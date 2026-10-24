#include "revkit/debug/crash_target.hh"

#include "revkit/emu/emulator.hh"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <set>

namespace revkit::debug {

namespace {

std::string lower(std::string_view s) {
  std::string out(s);
  for (char &c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

std::string proc_of(const std::string &language) { return language.substr(0, language.find(':')); }

std::uint64_t value_of(const std::vector<std::uint8_t> &v) {
  std::uint64_t x = 0;
  for (std::size_t i = 0; i < v.size() && i < 8; ++i) x |= static_cast<std::uint64_t>(v[i]) << (8 * i);
  return x;
}

}  // namespace

Stop crash_stop(const crash::CrashDump &d) {
  Stop s;
  s.kind = StopKind::signal;
  s.signal = d.format == crash::Format::elf_core ? d.signal : 0;
  s.detail = d.reason;
  if (d.fault_address) s.address = d.fault_address;
  else if (d.exception_address) s.address = d.exception_address;
  if (d.crashed_thread < d.threads.size()) {
    const crash::Thread &t = d.threads[d.crashed_thread];
    s.thread = std::to_string(t.id);
    for (const crash::Register &r : t.registers)
      if (r.name == "rip" || r.name == "eip" || r.name == "pc") s.pc = value_of(r.value);
  }
  return s;
}

CrashTarget::CrashTarget(std::shared_ptr<const void> keep, std::span<const std::byte> bytes, crash::CrashDump dump,
                         CrashTargetOptions options)
    : keep_(std::move(keep)), bytes_(bytes), dump_(std::move(dump)), options_(std::move(options)) {
  if (dump_.threads.empty()) throw DebugError("the crash dump has no threads");
  current_ = std::min(dump_.crashed_thread, dump_.threads.size() - 1);
  // Registers: the union of every thread's, in the crashed thread's order.
  std::vector<const crash::Register *> seen;
  std::set<std::string> names;
  for (std::size_t k = 0; k < dump_.threads.size(); ++k) {
    const crash::Thread &t = dump_.threads[(current_ + k) % dump_.threads.size()];
    for (const crash::Register &r : t.registers)
      if (names.insert(r.name).second) seen.push_back(&r);
  }
  if (seen.empty()) throw DebugError("the crash dump's threads have no registers (" + dump_.arch + ")");
  std::set<std::string> used;
  for (const crash::Register *r : seen) {
    RegisterDesc d;
    d.target_name = r->name;
    d.size = static_cast<std::uint32_t>(r->value.size());
    d.group = r->group;
    d.sleigh = map_register_name(options_.language, d.target_name, d.size, options_.sleigh_registers);
    d.name = !d.sleigh.empty() && !used.count(lower(d.sleigh)) ? d.sleigh : d.target_name;
    used.insert(lower(d.name));
    regs_.push_back(std::move(d));
  }
  // Flag bits shown as registers, as the emulator shows them.
  const std::string proc = proc_of(options_.language);
  auto derive = [&](const std::string &parent, std::initializer_list<std::pair<const char *, int>> bits) {
    auto p = std::find_if(regs_.begin(), regs_.end(), [&](const RegisterDesc &d) { return d.target_name == parent; });
    if (p == regs_.end()) return;
    const std::string parent_name = p->name;
    for (auto [name, bit] : bits) {
      if (used.count(lower(name))) continue;
      RegisterDesc d;
      d.name = d.target_name = name;
      d.size = 1;
      d.group = "flags";
      d.parent = parent_name;
      d.bit = bit;
      for (const SleighRegister &s : options_.sleigh_registers)
        if (s.name == name) d.sleigh = name;
      regs_.push_back(std::move(d));
      used.insert(lower(name));
    }
  };
  if (proc == "x86") derive("eflags", {{"CF", 0}, {"PF", 2}, {"AF", 4}, {"ZF", 6}, {"SF", 7}, {"IF", 9}, {"DF", 10}, {"OF", 11}});
  else if (proc == "AARCH64") derive("cpsr", {{"NG", 31}, {"ZR", 30}, {"CY", 29}, {"OV", 28}});
  else if (proc == "ARM") derive("cpsr", {{"NG", 31}, {"ZR", 30}, {"CY", 29}, {"OV", 28}, {"TB", 5}});
  const std::vector<std::string> curated = emu::display_register_names(options_.language, dump_.pointer_size);
  bool any = false;
  for (const std::string &c : curated)
    for (RegisterDesc &d : regs_)
      if (lower(d.name) == lower(c)) {
        d.display = true;
        any = true;
      }
  if (!any)
    for (RegisterDesc &d : regs_)
      if (d.group == "general" || d.group == "flags") d.display = true;
  auto pick = [&](std::string &out, std::initializer_list<const char *> want) {
    for (const char *w : want)
      for (const RegisterDesc &d : regs_)
        if (d.target_name == w) {
          out = d.name;
          return;
        }
  };
  pick(pc_, {"rip", "eip", "pc"});
  pick(sp_, {"rsp", "esp", "sp"});
  if (pc_.empty()) throw DebugError("the crash dump's registers have no program counter");
  last_ = crash_stop(dump_);
  // Modules, with an ELF's load bias from its first page when the dump has it.
  for (const crash::Module &m : dump_.modules) {
    ModuleInfo mi;
    mi.name = m.name;
    mi.path = m.path;
    mi.base = m.base;
    mi.size = m.size;
    mi.main = m.main;
    // An ELF's bias is worked out below; a PE module moves by its base (load_bias unused).
    mi.load_bias = dump_.format == crash::Format::elf_core ? m.base : 0;
    std::uint8_t h[64] = {};
    std::vector<ByteRange> miss;
    if (dump_.format == crash::Format::elf_core && read_dumped(m.base, h, &miss) == sizeof h &&
        std::memcmp(h, "\x7f" "ELF", 4) == 0) {
      const bool wide = h[4] == 2;
      auto rd = [&](std::uint64_t at, unsigned n) {
        std::uint8_t b[8] = {};
        std::vector<ByteRange> mm;
        read_dumped(at, std::span<std::uint8_t>(b, n), &mm);
        std::uint64_t v = 0;
        for (unsigned i = 0; i < n; ++i) v |= static_cast<std::uint64_t>(b[i]) << (8 * i);
        return mm.empty() ? std::optional<std::uint64_t>(v) : std::nullopt;
      };
      const auto phoff = rd(m.base + (wide ? 32 : 28), wide ? 8 : 4);
      const auto phent = rd(m.base + (wide ? 54 : 42), 2), phnum = rd(m.base + (wide ? 56 : 44), 2);
      if (phoff && phent && phnum && *phnum < 256 && *phent >= (wide ? 56u : 32u)) {
        std::optional<std::uint64_t> lowest;
        for (std::uint64_t i = 0; i < *phnum; ++i) {
          const std::uint64_t p = m.base + *phoff + i * *phent;
          const auto type = rd(p, 4), vaddr = rd(p + (wide ? 16 : 8), wide ? 8 : 4);
          if (type && *type == 1 && vaddr) lowest = lowest ? std::min(*lowest, *vaddr) : *vaddr;
        }
        if (lowest) mi.load_bias = m.base - (*lowest & ~std::uint64_t{0xfff});
      }
    }
    modules_.push_back(std::move(mi));
  }
}

void CrashTarget::refuse() { throw DebugError("a crash dump can be read, not run or changed"); }

const crash::Register *CrashTarget::raw(const crash::Thread &t, std::string_view target_name) const {
  for (const crash::Register &r : t.registers)
    if (r.name == target_name) return &r;
  return nullptr;
}

std::vector<std::uint8_t> CrashTarget::read_register(std::string_view name) {
  const RegisterDesc *d = find_register(name);
  if (d == nullptr) throw DebugError("no register " + std::string(name));
  const crash::Thread &t = dump_.threads[current_];
  if (!d->parent.empty()) {
    const RegisterDesc *p = find_register(d->parent);
    const crash::Register *r = p ? raw(t, p->target_name) : nullptr;
    if (r == nullptr) throw DebugError("register " + d->parent + " isn't in the dump");
    return {static_cast<std::uint8_t>((value_of(r->value) >> d->bit) & 1)};
  }
  const crash::Register *r = raw(t, d->target_name);
  if (r == nullptr) throw DebugError("thread " + std::to_string(t.id) + " has no " + d->target_name + " in the dump");
  std::vector<std::uint8_t> v = r->value;
  v.resize(d->size, 0);
  return v;
}

std::size_t CrashTarget::read_dumped(std::uint64_t address, std::span<std::uint8_t> out, std::vector<ByteRange> *missing) const {
  std::vector<std::pair<std::uint32_t, std::uint32_t>> m;
  const std::size_t got = dump_.read(bytes_, address, out, &m);
  if (missing != nullptr)
    for (auto [o, n] : m) missing->push_back({o, n});
  return got;
}

std::size_t CrashTarget::read_memory(std::uint64_t address, std::span<std::uint8_t> out, std::vector<ByteRange> *unreadable) {
  std::vector<ByteRange> missing;
  std::size_t got = read_dumped(address, out, &missing);
  for (const ByteRange &m : missing) {
    std::size_t filled = 0;
    if (options_.backing) {
      try {
        filled = std::min<std::size_t>(m.length, options_.backing(address + m.offset, out.subspan(m.offset, m.length)));
      } catch (const std::exception &) {
        filled = 0;
      }
    }
    got += filled;
    if (filled < m.length && unreadable != nullptr)
      unreadable->push_back({static_cast<std::uint32_t>(m.offset + filled), static_cast<std::uint32_t>(m.length - filled)});
    if (filled < m.length) std::fill(out.begin() + m.offset + filled, out.begin() + m.offset + m.length, 0);
  }
  return got;
}

std::vector<ThreadInfo> CrashTarget::threads() {
  std::vector<ThreadInfo> out;
  for (std::size_t i = 0; i < dump_.threads.size(); ++i) {
    const crash::Thread &t = dump_.threads[i];
    ThreadInfo ti;
    ti.id = std::to_string(t.id);
    ti.name = t.name.empty() ? (i == dump_.crashed_thread ? "crashed" : "") : t.name;
    ti.current = i == current_;
    for (const crash::Register &r : t.registers)
      if (r.name == "rip" || r.name == "eip" || r.name == "pc") ti.pc = value_of(r.value);
    out.push_back(std::move(ti));
  }
  return out;
}

void CrashTarget::select_thread(const std::string &id) {
  for (std::size_t i = 0; i < dump_.threads.size(); ++i)
    if (std::to_string(dump_.threads[i].id) == id) {
      current_ = i;
      return;
    }
  throw DebugError("no thread " + id + " in the dump");
}

std::string CrashTarget::current_thread() const { return std::to_string(dump_.threads[current_].id); }

std::vector<MapRegion> CrashTarget::memory_map() {
  std::vector<MapRegion> out;
  std::uint64_t sp = 0;
  try {
    sp = to_u64(read_register(sp_));
  } catch (const DebugError &) {
  }
  for (const crash::Segment &s : dump_.memory) {
    MapRegion r;
    r.start = s.address;
    r.size = s.size;
    r.perms = s.perms;
    r.kind = "anon";
    for (const crash::MappedFile &f : dump_.files)
      if (s.address >= f.start && s.address < f.end) {
        r.name = f.path;
        r.offset = f.file_offset + (s.address - f.start);
        r.kind = "file";
        break;
      }
    if (r.name.empty())
      if (const crash::Module *m = dump_.module_at(s.address)) {
        r.name = m->path.empty() ? m->name : m->path;
        r.kind = "image";
      }
    if (r.name.empty() && sp >= s.address && sp - s.address < s.size) r.name = "[stack]";
    out.push_back(std::move(r));
  }
  return out;
}

std::optional<std::int64_t> CrashTarget::process_id() const {
  if (dump_.pid != 0) return dump_.pid;
  return std::nullopt;
}

bool CrashTarget::thumb() {
  if (proc_of(options_.language) != "ARM") return false;
  if (const crash::Register *r = raw(dump_.threads[current_], "cpsr")) return (value_of(r->value) >> 5) & 1;
  return false;
}

}  // namespace revkit::debug
