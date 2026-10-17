// The machine around the CPU: its description (parse_machine), memory,
// peripherals and their interrupt wiring, the clock and scheduler, idle
// skipping, and exception delivery as recorded steps.
#include "machine_impl.hh"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <thread>

namespace revkit::emu {

using detail::Fault;
using detail::MachineRuntime;
using detail::Pending;
using detail::Wide;

namespace detail {

namespace {

std::string hexs(std::uint64_t v) {
  std::ostringstream o;
  o << "0x" << std::hex << v;
  return o.str();
}

[[noreturn]] void bad(const json::Value &at, const std::string &what) {
  throw MachineError(json::where(at) + ": " + what);
}

// "0x1000", "4096", "64K", "8M", "1_000_000", or a JSON integer.
std::optional<std::uint64_t> parse_text_number(std::string s) {
  s.erase(std::remove(s.begin(), s.end(), '_'), s.end());
  if (s.empty()) return std::nullopt;
  std::uint64_t mult = 1;
  auto ends = [&](const char *suffix) {
    const std::string x = suffix;
    if (s.size() > x.size() && s.compare(s.size() - x.size(), x.size(), x) == 0) {
      s.resize(s.size() - x.size());
      return true;
    }
    return false;
  };
  if (ends("KiB") || ends("K") || ends("k")) mult = 1ull << 10;
  else if (ends("MiB") || ends("M")) mult = 1ull << 20;
  else if (ends("GiB") || ends("G")) mult = 1ull << 30;
  errno = 0;
  char *end = nullptr;
  const std::uint64_t v = std::strtoull(s.c_str(), &end, 0);
  if (errno != 0 || end != s.c_str() + s.size()) return std::nullopt;
  return v * mult;
}

loader::Perms parse_perms(const json::Value &v, const std::string &what) {
  if (!v.is_string()) bad(v, what + " must be a string like \"rw-\"");
  loader::Perms p{false, false, false};
  for (char c : v.as_string()) {
    if (c == 'r') p.read = true;
    else if (c == 'w') p.write = true;
    else if (c == 'x') p.exec = true;
    else if (c != '-') bad(v, what + ": \"" + v.as_string() + "\" is not r, w, x or -");
  }
  return p;
}

void allow_keys(const json::Value &obj, std::initializer_list<const char *> keys, const std::string &what) {
  for (const auto &[k, v] : obj.members()) {
    if (k == "note" || k == "comment" || (!k.empty() && k[0] == '_')) continue;
    bool ok = false;
    for (const char *x : keys) ok = ok || k == x;
    if (!ok) bad(v, what + " has no field \"" + k + "\"");
  }
}

}  // namespace

std::uint64_t num(const json::Value &v, const std::string &what) {
  if (v.is_integer()) {
    if (v.negative()) bad(v, what + " must not be negative");
    return v.as_u64();
  }
  if (v.is_string()) {
    if (auto n = parse_text_number(v.as_string())) return *n;
    bad(v, what + ": \"" + v.as_string() + "\" is not a number");
  }
  bad(v, what + " must be a number (or a string such as \"0x1000\")");
}

std::optional<std::uint64_t> opt_num(const json::Value &obj, std::string_view key) {
  const json::Value *v = obj.find(key);
  if (v == nullptr || v->is_null()) return std::nullopt;
  return num(*v, std::string(key));
}

std::uint64_t num_or(const json::Value &obj, std::string_view key, std::uint64_t def) {
  return opt_num(obj, key).value_or(def);
}

bool bool_or(const json::Value &obj, std::string_view key, bool def) {
  const json::Value *v = obj.find(key);
  if (v == nullptr || v->is_null()) return def;
  if (!v->is_bool()) bad(*v, std::string(key) + " must be true or false");
  return v->as_bool();
}

std::string str_or(const json::Value &obj, std::string_view key, std::string def) {
  const json::Value *v = obj.find(key);
  if (v == nullptr || v->is_null()) return def;
  if (!v->is_string()) bad(*v, std::string(key) + " must be a string");
  return v->as_string();
}

std::string default_cpu_model(const std::string &language) {
  const std::string proc = language.substr(0, language.find(':'));
  if (proc == "ARM") {
    if (language.find(":Cortex") != std::string::npos || language.find(":v8m") != std::string::npos ||
        language.find(":v8-m") != std::string::npos)
      return "cortex-m";
    return "arm";
  }
  if (proc == "MIPS") return "mips";
  return "";
}

std::uint64_t semihosting_call(Emulator::Impl &m, std::uint32_t op, std::uint64_t arg) {
  auto word = [&](std::uint64_t at) {
    std::uint8_t b[4];
    m.mem_read(at, b, 4);
    return m.word(b, 4);
  };
  switch (op) {
    case 0x03: {  // SYS_WRITEC
      std::uint8_t c = 0;
      m.mem_read(arg, &c, 1);
      m.out.push_back(static_cast<char>(c));
      return 0;
    }
    case 0x04: {  // SYS_WRITE0
      for (std::uint64_t at = arg; at < arg + 65536; ++at) {
        std::uint8_t c = 0;
        m.mem_read(at, &c, 1);
        if (c == 0) break;
        m.out.push_back(static_cast<char>(c));
      }
      return 0;
    }
    case 0x05: {  // SYS_WRITE: {fd, buffer, length}
      const std::uint64_t fd = word(arg), buf = word(arg + 4), len = std::min<std::uint64_t>(word(arg + 8), 1 << 20);
      std::string bytes(len, '\0');
      for (std::uint64_t i = 0; i < len; ++i) {
        std::uint8_t c = 0;
        m.mem_read(buf + i, &c, 1);
        bytes[i] = static_cast<char>(c);
      }
      (fd == 2 ? m.err : m.out) += bytes;
      return 0;
    }
    case 0x10:  // SYS_CLOCK: centiseconds
      return m.machine ? m.machine->now() * 100 / std::max<std::uint64_t>(m.machine->spec().clock.hz, 1) : 0;
    case 0x11:  // SYS_TIME
      return m.machine ? m.machine->now() / std::max<std::uint64_t>(m.machine->spec().clock.hz, 1) : 0;
    case 0x13: return 0;  // SYS_ERRNO
    case 0x18:            // SYS_EXIT: ADP_Stopped_ApplicationExit (0x20026) is success
      m.pending_exit = arg == 0x20026 ? 0 : static_cast<std::int64_t>(arg == 0x20023 ? 1 : arg);
      return 0;
    case 0x20:  // SYS_EXIT_EXTENDED: {reason, code}
      m.pending_exit = static_cast<std::int64_t>(static_cast<std::int32_t>(word(arg + 4)));
      return 0;
    default: return ~std::uint64_t{0};  // -1: not supported
  }
}

std::uint32_t CpuModel::load32(std::uint64_t addr) {
  std::uint8_t b[4];
  m.mem_read(addr, b, 4);
  return static_cast<std::uint32_t>(m.word(b, 4));
}

void CpuModel::store32(std::uint64_t addr, std::uint32_t v) {
  std::uint8_t b[4];
  m.put_word(b, 4, v);
  m.mem_write(addr, b, 4);
}

std::uint32_t CpuModel::peek32(std::uint64_t addr) const {
  std::uint8_t b[4] = {};
  if (!m.mapped(addr, 4)) return 0;
  m.ram_read(addr, b, 4);
  return static_cast<std::uint32_t>(m.word(b, 4));
}

// --- The runtime ---------------------------------------------------------

struct MachineRuntime::Context final : PeripheralContext {
  MachineRuntime &rt;
  int index;
  Context(MachineRuntime &r, int i) : rt(r), index(i) {}
  std::uint64_t now() const override { return rt.now_; }
  std::uint64_t hz() const override { return rt.spec_.clock.hz; }
  void schedule(std::uint64_t at) override { rt.schedule(index, at); }
  void cancel_schedule() override { rt.cancel(index); }
  void set_irq(unsigned line, bool level) override { rt.drive(index, line, level); }
  void output(std::string_view bytes) override { rt.m_.out.append(bytes); }
  bool read_memory(std::uint64_t address, std::span<std::uint8_t> out) override {
    return rt.m_.self->read_memory(address, out);
  }
  bool write_memory(std::uint64_t address, std::span<const std::uint8_t> bytes) override {
    try {
      return rt.m_.self->write_memory(address, bytes);
    } catch (const EmuError &) {
      return false;
    }
  }
  void log(std::string_view line) override;
  void request_stop(std::string reason) override { rt.request_stop(std::move(reason)); }
};

struct MachineRuntime::Device {
  PeripheralSpec spec;
  std::unique_ptr<Peripheral> p;
  std::unique_ptr<Context> ctx;
  std::uint64_t base = 0, size = 0;
  bool mapped = false;  // has registers
  std::optional<std::uint64_t> deadline;
};

void MachineRuntime::Context::log(std::string_view line) {
  rt.log(rt.devices_[static_cast<std::size_t>(index)]->spec.name + ": " + std::string(line));
}

MachineRuntime::MachineRuntime(Emulator::Impl &m, MachineSpec spec, MachineOptions options)
    : m_(m), spec_(std::move(spec)), options_(std::move(options)) {
  wall_start_ = std::chrono::steady_clock::now();
  break_on_ = spec_.break_on;
}

MachineRuntime::~MachineRuntime() = default;

void MachineRuntime::log(std::string line) {
  log_.push_back(std::move(line));
  while (log_.size() > 200) log_.pop_front();
}

void MachineRuntime::map_memory() {
  // The machine's memory where the program doesn't already have some; MMIO
  // the program maps as ordinary memory becomes MMIO.
  for (const MemorySpec &ms : spec_.memory) {
    const std::uint64_t last = ms.start + (ms.size - 1);
    if (ms.kind == MemorySpec::Kind::mmio) {
      std::vector<std::pair<std::uint64_t, std::uint64_t>> convert;
      for (const auto &[start, r] : m_.regions) {
        if (r.last() < ms.start || r.info.start > last || r.info.kind == RegionInfo::Kind::mmio) continue;
        if (r.info.kind == RegionInfo::Kind::image && m_.image->memory.is_mapped(std::max(ms.start, r.info.start)) &&
            r.info.kind != RegionInfo::Kind::mmio) {
          // Loaded bytes stay memory.
          bool loaded = false;
          for (const loader::Block &b : m_.image->blocks)
            if (b.start <= last && b.start + b.size - 1 >= ms.start && b.initialized && !b.is_volatile) loaded = true;
          if (loaded) continue;
        }
        convert.emplace_back(std::max(ms.start, r.info.start), std::min(last, r.last()));
      }
      for (const auto &[a, b] : convert) {
        m_.self->unmap(a, b - a + 1);
        log("memory " + ms.name + ": " + hexs(a) + "-" + hexs(b) + " is MMIO");
      }
    }
    // The gaps.
    std::uint64_t at = ms.start;
    while (true) {
      const detail::Region *r = m_.region_at(at);
      if (r != nullptr) {
        if (r->last() >= last) break;
        at = r->last() + 1;
        continue;
      }
      std::uint64_t end = last;  // inclusive
      auto it = m_.regions.upper_bound(at);
      if (it != m_.regions.end() && it->second.info.start <= last) end = it->second.info.start - 1;
      RegionInfo info;
      info.name = ms.name;
      info.start = at;
      info.size = end - at + 1;
      info.perms = ms.perms;
      info.kind = ms.kind == MemorySpec::Kind::mmio ? RegionInfo::Kind::mmio : RegionInfo::Kind::ram;
      m_.map_region(info);
      if (end >= last) break;
      at = end + 1;
    }
  }
}

MachineRuntime::Target MachineRuntime::resolve(const std::string &where, const std::string &who) {
  std::string dev = where, in;
  if (auto dot = where.find('.'); dot != std::string::npos) {
    dev = where.substr(0, dot);
    in = where.substr(dot + 1);
  }
  const bool cortex = cpu && cpu->name() == "cortex-m";
  if (dev == "cpu" || (cortex && (dev == "nvic" || dev == "scs"))) {
    if (!cpu) throw MachineError(who + ": goes to " + where + ", but this machine's CPU has no interrupt model");
    if (in.empty()) in = cortex ? "" : "irq";
    const int i = cpu->input(in);
    if (i < 0) throw MachineError(who + ": the " + cpu->name() + " CPU has no interrupt input \"" + in + "\"");
    return {-1, i};
  }
  for (std::size_t k = 0; k < devices_.size(); ++k) {
    if (devices_[k]->spec.name != dev) continue;
    if (!devices_[k]->p->has_inputs())
      throw MachineError(who + ": goes to " + where + ", but " + dev + " is not an interrupt controller");
    if (in.empty() || in.find_first_not_of("0123456789") != std::string::npos)
      throw MachineError(who + ": " + where + " needs an input number (" + dev + ".N)");
    return {static_cast<int>(k), static_cast<int>(std::stoul(in))};
  }
  throw MachineError(who + ": goes to " + where + ", but there is no peripheral named " + dev);
}

void MachineRuntime::build() {
  const std::string model = spec_.cpu.model.empty() ? default_cpu_model(m_.language) : spec_.cpu.model;
  if (model == "arm") cpu = make_arm_model(m_, spec_.cpu);
  else if (model == "cortex-m") cpu = make_cortexm_model(m_, spec_.cpu);
  else if (model == "mips") cpu = make_mips_model(m_, spec_.cpu);
  else if (!model.empty() && model != "none") throw MachineError("unknown cpu model \"" + model + "\" (arm, cortex-m, mips)");
  if (cpu) cpu->machine = this;

  map_memory();

  // The CPU's own devices, then the description's.
  if (cpu) {
    for (auto &[ps, p] : cpu->builtin_devices()) {
      auto d = std::make_unique<Device>();
      d->spec = ps;
      d->p = std::move(p);
      devices_.push_back(std::move(d));
    }
  }
  std::set<std::string> names;
  for (const auto &d : devices_) names.insert(d->spec.name);
  // auto-ack registers at absolute addresses: one small device per register.
  std::vector<PeripheralSpec> specs;
  for (const PeripheralSpec &ps : spec_.peripherals) {
    const json::Value *regs = ps.config.find("registers");
    if (ps.kind != "auto-ack" || ps.base || regs == nullptr || !regs->is_array()) {
      specs.push_back(ps);
      continue;
    }
    if (!names.insert(ps.name).second) throw MachineError("two peripherals are named " + ps.name);
    std::size_t i = 0;
    for (const json::Value &r : regs->items()) {
      const std::optional<std::uint64_t> addr = opt_num(r, "address");
      if (!addr) throw MachineError("peripheral " + ps.name + ": each register needs an address (or give the block a base)");
      PeripheralSpec one;
      one.name = ps.name + "." + std::to_string(i++);
      one.kind = "auto-ack";
      one.base = *addr;
      one.size = num_or(r, "size", 4);
      one.config = json::Value::object();
      json::Value list = json::Value::array();
      json::Value rule = r;
      rule.set("address", json::Value::string(hexs(*addr)));
      list.push(rule);
      one.config.set("registers", list);
      specs.push_back(std::move(one));
    }
  }
  for (const PeripheralSpec &ps : specs) {
    if (!names.insert(ps.name).second) throw MachineError("two peripherals are named " + ps.name);
    std::string error;
    std::unique_ptr<Peripheral> p = make_builtin_peripheral(ps, error);
    if (!p && error.empty() && options_.factory) p = options_.factory(ps, error);
    if (!p) {
      if (error.empty()) {
        error = "unknown kind \"" + ps.kind + "\"";
        if (ps.kind.rfind("plugin:", 0) == 0) error = "no peripheral plugin " + ps.kind.substr(7) + " is loaded";
      }
      throw MachineError("peripheral " + ps.name + ": " + error);
    }
    auto d = std::make_unique<Device>();
    d->spec = ps;
    d->p = std::move(p);
    devices_.push_back(std::move(d));
  }
  for (std::size_t k = 0; k < devices_.size(); ++k) {
    Device &d = *devices_[k];
    d.ctx = std::make_unique<Context>(*this, static_cast<int>(k));
    d.p->bind(d.ctx.get());
    if (d.spec.base) {
      d.mapped = true;
      d.base = *d.spec.base;
      d.size = d.spec.size;
      if (d.spec.config.find("size") == nullptr)
        if (auto size = d.p->default_size()) d.size = *size;
      if (d.size == 0) throw MachineError("peripheral " + d.spec.name + " has size 0");
      // An editor's machine (or a plugin's default size): past the top of
      // the address space it wrapped, and the device mapped nothing.
      if (d.size - 1 > UINT64_MAX - d.base)
        throw MachineError("peripheral " + d.spec.name + " at " + hexs(d.base) + " runs past the end of memory");
      // Its registers are MMIO.
      const std::uint64_t last = d.base + d.size - 1;
      bool covered = true;
      for (std::uint64_t at = d.base; at <= last;) {
        const detail::Region *r = m_.region_at(at);
        if (r == nullptr) {
          covered = false;
          break;
        }
        if (r->info.kind != RegionInfo::Kind::mmio) {
          bool loaded = false;
          for (const loader::Block &b : m_.image->blocks)
            if (b.start <= last && b.start + b.size - 1 >= d.base && b.initialized && !b.is_volatile) loaded = true;
          if (loaded)
            throw MachineError("peripheral " + d.spec.name + " at " + hexs(d.base) + " overlaps the loaded image (" +
                               r->info.name + ")");
          m_.self->unmap(d.base, d.size);
          covered = false;
          break;
        }
        if (r->last() >= last) break;
        at = r->last() + 1;
      }
      if (!covered) {
        // Map what isn't mapped as MMIO named after the device.
        std::uint64_t at = d.base;
        while (at <= last) {
          const detail::Region *r = m_.region_at(at);
          if (r != nullptr) {
            if (r->last() >= last) break;
            at = r->last() + 1;
            continue;
          }
          std::uint64_t end = last;
          auto it = m_.regions.upper_bound(at);
          if (it != m_.regions.end() && it->second.info.start <= last) end = it->second.info.start - 1;
          RegionInfo info;
          info.name = d.spec.name;
          info.start = at;
          info.size = end - at + 1;
          info.perms = {true, true, false};
          info.kind = RegionInfo::Kind::mmio;
          m_.map_region(info);
          if (end >= last) break;
          at = end + 1;
        }
      }
    }
  }
  // Address lookup, and no two devices on one address.
  for (std::size_t k = 0; k < devices_.size(); ++k)
    if (devices_[k]->mapped) by_address_.push_back(static_cast<int>(k));
  std::sort(by_address_.begin(), by_address_.end(), [&](int a, int b) {
    return devices_[static_cast<std::size_t>(a)]->base < devices_[static_cast<std::size_t>(b)]->base;
  });
  for (std::size_t k = 1; k < by_address_.size(); ++k) {
    const Device &a = *devices_[static_cast<std::size_t>(by_address_[k - 1])];
    const Device &b = *devices_[static_cast<std::size_t>(by_address_[k])];
    if (a.base + a.size > b.base)
      throw MachineError("peripherals " + a.spec.name + " and " + b.spec.name + " overlap at " + hexs(b.base));
  }

  // Wiring. A controller's unwired outputs go to the CPU's inputs of the same name.
  for (std::size_t k = 0; k < devices_.size(); ++k) {
    Device &d = *devices_[k];
    const std::vector<std::string> outs = d.p->outputs();
    std::set<std::string> wired;
    for (const auto &[out, to] : d.spec.irqs) {
      unsigned line = 0;
      bool found = false;
      for (std::size_t o = 0; o < outs.size(); ++o)
        if (outs[o] == out) line = static_cast<unsigned>(o), found = true;
      if (!found && !out.empty() && out.find_first_not_of("0123456789") == std::string::npos) {
        line = static_cast<unsigned>(std::stoul(out));
        found = line < outs.size() || outs.empty();
      }
      if (!found)
        throw MachineError("peripheral " + d.spec.name + " has no interrupt output \"" + out + "\"" +
                           (outs.empty() ? "" : " (it has " + [&] {
                             std::string s;
                             for (const auto &o : outs) s += (s.empty() ? "" : ", ") + o;
                             return s;
                           }() + ")"));
      wires_[{static_cast<int>(k), line}].push_back(resolve(to, "peripheral " + d.spec.name + " " + out));
      wired.insert(out);
    }
    if (d.p->has_inputs() && cpu) {
      for (std::size_t o = 0; o < outs.size(); ++o) {
        if (wired.count(outs[o]) != 0 || wired.count(std::to_string(o)) != 0) continue;
        const int i = cpu->input(outs[o]);
        if (i >= 0) wires_[{static_cast<int>(k), static_cast<unsigned>(o)}].push_back({-1, i});
      }
    }
  }

  // The console UART.
  for (std::size_t k = 0; k < devices_.size(); ++k) {
    const Device &d = *devices_[k];
    if (spec_.console.empty() ? (console_ < 0 && d.p->is_uart()) : d.spec.name == spec_.console) console_ = static_cast<int>(k);
  }
  if (!spec_.console.empty() && console_ < 0) throw MachineError("console: there is no peripheral named " + spec_.console);

  // The display registers the CPU model adds.
  if (cpu)
    for (const std::string &n : cpu->display_extra())
      if (auto i = m_.find_reg(n); i && std::find(m_.display.begin(), m_.display.end(), m_.registers[*i].name) == m_.display.end())
        m_.display.push_back(m_.registers[*i].name);
}

void MachineRuntime::reset(std::optional<std::uint64_t> entry) {
  for (auto &d : devices_) d->p->reset();
  if (cpu) {
    cpu->reset(entry);
  } else {
    if (!entry) throw MachineError("this machine's CPU has no reset vector: give an entry");
    m_.pc = *entry & m_.code_mask;
    m_.apply_isa(m_.pc);
  }
  for (const auto &[name, value] : spec_.registers) {
    if (!m_.find_reg(name)) throw MachineError("registers: no register " + name + " in " + m_.language);
    m_.set_reg(m_.reg(name), Wide::of(m_.reg(name).size, value));
    if (m_.pc_reg.name == m_.reg(name).name) m_.pc = value & m_.code_mask;
  }
  if (!m_.pc_reg.name.empty()) m_.set_reg(m_.pc_reg, Wide::of(m_.pc_reg.size, m_.pc));
  if (!m_.options.stdin_data.empty() && console_ >= 0)
    devices_[static_cast<std::size_t>(console_)]->p->input(m_.options.stdin_data);
}

bool MachineRuntime::input(std::string_view peripheral, std::string_view bytes) {
  int k = console_;
  if (!peripheral.empty()) {
    k = -1;
    for (std::size_t i = 0; i < devices_.size(); ++i)
      if (devices_[i]->spec.name == peripheral) k = static_cast<int>(i);
  }
  if (k < 0) return false;
  devices_[static_cast<std::size_t>(k)]->p->input(bytes);
  return true;
}

bool MachineRuntime::mmio_read(std::uint64_t addr, std::uint32_t size, std::uint64_t &value) {
  int k = -1;
  if (last_hit_ >= 0) {
    const Device &d = *devices_[static_cast<std::size_t>(last_hit_)];
    if (addr >= d.base && addr - d.base < d.size) k = last_hit_;
  }
  if (k < 0) {
    auto it = std::upper_bound(by_address_.begin(), by_address_.end(), addr,
                               [&](std::uint64_t a, int i) { return a < devices_[static_cast<std::size_t>(i)]->base; });
    if (it == by_address_.begin()) return false;
    const int i = *std::prev(it);
    const Device &d = *devices_[static_cast<std::size_t>(i)];
    if (addr - d.base >= d.size) return false;
    k = last_hit_ = i;
  }
  Device &d = *devices_[static_cast<std::size_t>(k)];
  value = d.p->read(addr - d.base, size);
  return true;
}

bool MachineRuntime::mmio_write(std::uint64_t addr, std::uint32_t size, std::uint64_t value) {
  std::uint64_t ignored = 0;
  (void)ignored;
  int k = -1;
  if (last_hit_ >= 0) {
    const Device &d = *devices_[static_cast<std::size_t>(last_hit_)];
    if (addr >= d.base && addr - d.base < d.size) k = last_hit_;
  }
  if (k < 0) {
    auto it = std::upper_bound(by_address_.begin(), by_address_.end(), addr,
                               [&](std::uint64_t a, int i) { return a < devices_[static_cast<std::size_t>(i)]->base; });
    if (it == by_address_.begin()) return false;
    const int i = *std::prev(it);
    const Device &d = *devices_[static_cast<std::size_t>(i)];
    if (addr - d.base >= d.size) return false;
    k = last_hit_ = i;
  }
  Device &d = *devices_[static_cast<std::size_t>(k)];
  d.p->write(addr - d.base, size, value);
  return true;
}

void MachineRuntime::drive(int device, unsigned line, bool level) {
  auto it = wires_.find({device, line});
  if (it == wires_.end()) return;
  for (const Target &t : it->second) {
    auto &sources = asserted_[{t.device, t.input}];
    const bool before = !sources.empty();
    if (level) sources.insert({device, line});
    else sources.erase({device, line});
    const bool after = !sources.empty();
    if (before == after && !(after && t.device < 0)) continue;
    if (t.device < 0) {
      if (cpu) cpu->set_line(t.input, after);
    } else {
      devices_[static_cast<std::size_t>(t.device)]->p->irq_in(static_cast<unsigned>(t.input), after);
    }
  }
}

void MachineRuntime::schedule(int device, std::uint64_t at) { devices_[static_cast<std::size_t>(device)]->deadline = at; }

void MachineRuntime::cancel(int device) { devices_[static_cast<std::size_t>(device)]->deadline.reset(); }

std::uint64_t MachineRuntime::next_event() const {
  std::uint64_t best = ~std::uint64_t{0};
  for (const auto &d : devices_)
    if (d->deadline) best = std::min(best, *d->deadline);
  return best;
}

void MachineRuntime::fire_due() {
  for (int guard = 0; guard < 100000; ++guard) {
    int best = -1;
    for (std::size_t k = 0; k < devices_.size(); ++k) {
      const auto &dl = devices_[k]->deadline;
      if (!dl || *dl > now_) continue;
      if (best < 0 || *dl < *devices_[static_cast<std::size_t>(best)]->deadline) best = static_cast<int>(k);
    }
    if (best < 0) return;
    Device &d = *devices_[static_cast<std::size_t>(best)];
    const std::uint64_t at = *d.deadline;
    d.deadline.reset();
    d.p->tick(at);
  }
  log("the scheduler fired 100000 events at tick " + std::to_string(now_) + "; a peripheral keeps scheduling the past");
}

void MachineRuntime::advance(std::uint64_t ticks) {
  if (spec_.clock.wall) {
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - wall_start_).count();
    const std::uint64_t t = static_cast<std::uint64_t>(us) * spec_.clock.hz / 1000000 + idle_skipped_;
    now_ = std::max(now_ + (ticks != 0 ? 0 : 0), t);
  } else {
    now_ += ticks;
  }
  if (cpu) cpu->tick(now_);
}

bool MachineRuntime::can_idle() const { return cpu != nullptr && cpu->interruptible(); }

bool MachineRuntime::breaks_on(const std::string &kind, std::int32_t number) const {
  for (const std::string &b : break_on_) {
    if (b == "any" && kind != "return") return true;
    if (b == kind) return true;
    if (number >= 0 && b == kind + ":" + std::to_string(number)) return true;
  }
  return false;
}

void MachineRuntime::record_event(ExceptionEvent e) {
  ++event_count_;
  events_.push_back(std::move(e));
  while (events_.size() > options_.event_capacity) events_.pop_front();
}

namespace {

std::string label(const Pending &p) {
  std::string s = p.kind;
  if (p.number >= 0 && (p.kind == "irq" || p.kind == "interrupt" || p.kind == "external")) s += " " + std::to_string(p.number);
  if ((p.kind == "swi" || p.kind == "svc") && p.arg != 0 && p.kind == "swi") s += " " + hexs(p.arg);
  return s;
}

}  // namespace

std::uint64_t MachineRuntime::take_now(const Pending &p, std::uint64_t return_pc) {
  const std::uint64_t handler = cpu->enter(p, return_pc);
  ExceptionEvent e;
  e.step = m_.steps;
  e.tick = now_;
  e.kind = p.kind;
  e.number = p.number;
  e.pc = return_pc;
  e.handler = handler;
  e.source = p.source;
  if (p.kind == "data_abort" || p.kind == "prefetch_abort") e.detail = "address " + hexs(p.arg);
  if (m_.recording) {
    m_.entry.exception = p.kind;
    m_.entry.exception_number = p.number;
  }
  const std::string what = label(p) + " -> " + hexs(handler);
  m_.step_event = m_.step_event.empty() ? what : m_.step_event + "; " + what;
  m_.trace.count_exception();
  if (breaks_on(p.kind, p.number))
    pending_break = Stop{StopKind::exception, 0, std::nullopt, "took " + label(p) + " (handler " + hexs(handler) + ")", 0, 0};
  record_event(std::move(e));
  return handler;
}

std::optional<Stop> MachineRuntime::deliver(const Pending &pin) {
  Pending p = pin;
  if (p.source.empty() && cpu) {
    // The devices driving the CPU's line.
    for (const auto &[target, sources] : asserted_) {
      if (target.first != -1 || sources.empty()) continue;
      const int in = cpu->input(p.kind);
      if (in >= 0 && target.second != in) continue;
      for (const auto &[dev, line] : sources) {
        (void)line;
        p.source += (p.source.empty() ? "" : ",") + devices_[static_cast<std::size_t>(dev)]->spec.name;
      }
    }
  }
  struct InStep {
    bool &flag;
    explicit InStep(bool &f) : flag(f) { flag = true; }
    ~InStep() { flag = false; }
  } guard(m_.in_step);
  m_.undo.clear();
  m_.watch_hit.reset();
  m_.step_event.clear();
  m_.step_reads = m_.step_writes = 0;
  m_.recording = m_.trace.capacity() > 0;
  if (m_.recording) {
    m_.entry = TraceEntry{};
    m_.entry.index = m_.steps;
    m_.entry.pc = m_.pc;
    m_.entry.thumb = m_.thumb;
  }
  std::uint64_t handler = 0;
  try {
    handler = take_now(p, m_.pc);
  } catch (Fault &f) {
    m_.undo_all();
    Stop s = m_.make_stop(f.kind, "taking " + label(p) + ": " + f.detail);
    if (f.has_address) s.address = f.address;
    return s;
  }
  m_.pc = handler & m_.code_mask;
  if (m_.has_thumb && m_.tb_register)
    m_.thumb = m_.tb_register->offset < m_.regs.size() && m_.regs[m_.tb_register->offset] != 0;
  if (!m_.pc_reg.name.empty()) m_.set_reg(m_.pc_reg, Wide::of(m_.pc_reg.size, m_.pc));
  ++m_.steps;
  if (m_.recording) m_.entry.text = "<" + label(p) + ">";
  m_.entry.event = m_.step_event;
  m_.finish_entry(nullptr, m_.recording);
  waiting_ = false;
  if (pending_break) {
    Stop s = *pending_break;
    pending_break.reset();
    s.pc = m_.pc;
    return s;
  }
  return std::nullopt;
}

std::optional<Stop> MachineRuntime::resume_check(const RunOptions &o) {
  if (waiting_) {
    if (auto s = idle(o)) return s;
  }
  if (cpu)
    if (auto p = cpu->pending()) return deliver(*p);
  return std::nullopt;
}

std::optional<Stop> MachineRuntime::idle(const RunOptions &o) {
  for (int rounds = 0;; ++rounds) {
    if (cpu && cpu->wake()) {
      waiting_ = false;
      return std::nullopt;
    }
    const std::uint64_t ne = next_event();
    if (ne == ~std::uint64_t{0}) {
      return m_.make_stop(StopKind::idle, "waiting for an interrupt; nothing is scheduled to raise one");
    }
    if ((rounds & 63) == 63) {
      if (std::chrono::steady_clock::now() >= o.deadline) return m_.make_stop(StopKind::time_limit, "the call's time limit");
      if (o.cancelled && o.cancelled()) return m_.make_stop(StopKind::cancelled, "cancelled");
    }
    if (spec_.clock.wall) {
      // Real time: sleep toward the event (bounded, so the run's deadline holds).
      if (ne > now_) {
        const std::uint64_t ticks = ne - now_;
        const auto us = std::chrono::microseconds(std::min<std::uint64_t>(ticks * 1000000 / std::max<std::uint64_t>(spec_.clock.hz, 1) + 1, 10000));
        if (std::chrono::steady_clock::now() + us >= o.deadline) return m_.make_stop(StopKind::time_limit, "the call's time limit");
        std::this_thread::sleep_for(us);
        advance(0);
      }
    } else {
      idle_skipped_ += ne - now_;
      now_ = ne;
      if (cpu) cpu->tick(now_);
    }
    fire_due();
    if (stop_request_) {
      Stop s = m_.make_stop(StopKind::hook, *stop_request_);
      stop_request_.reset();
      return s;
    }
  }
}

std::optional<Stop> MachineRuntime::after_step(const RunOptions &o) {
  advance(spec_.clock.ticks_per_step);
  fire_due();
  if (stop_request_) {
    Stop s = m_.make_stop(StopKind::hook, *stop_request_);
    stop_request_.reset();
    return s;
  }
  if (cpu && cpu->returned) {
    ExceptionEvent e = *cpu->returned;
    cpu->returned.reset();
    e.step = m_.steps;
    e.tick = now_;
    const bool brk = breaks_on("return", -1);
    record_event(std::move(e));
    if (brk) return m_.make_stop(StopKind::exception, "returned from an exception");
  }
  if (pending_break) {
    Stop s = *pending_break;
    pending_break.reset();
    s.pc = m_.pc;
    return s;
  }
  if (waiting_) {
    if (auto s = idle(o)) return s;
  }
  if (cpu)
    if (auto p = cpu->pending()) return deliver(*p);
  return std::nullopt;
}

MachineState MachineRuntime::state() const {
  MachineState s;
  if (cpu) cpu->state(s);
  s.tick = now_;
  s.hz = spec_.clock.hz;
  s.waiting = waiting_;
  s.interrupts = event_count_;
  for (const auto &d : devices_) {
    MachineState::Device x;
    x.name = d->spec.name;
    x.kind = d->spec.kind;
    x.base = d->base;
    x.size = d->mapped ? d->size : 0;
    x.state = d->p->state();
    x.next_tick = d->deadline;
    s.devices.push_back(std::move(x));
  }
  for (const auto &[target, sources] : asserted_) {
    if (sources.empty()) continue;
    std::string who;
    for (const auto &[dev, line] : sources)
      who += (who.empty() ? "" : ",") + devices_[static_cast<std::size_t>(dev)]->spec.name;
    const std::string to = target.first < 0 ? "cpu." + std::to_string(target.second)
                                            : devices_[static_cast<std::size_t>(target.first)]->spec.name + "." +
                                                  std::to_string(target.second);
    s.pending.push_back(to + " <- " + who);
  }
  s.log.assign(log_.begin(), log_.end());
  return s;
}

}  // namespace detail

// --- The description -------------------------------------------------------

namespace {

using detail::bad;
using detail::num;

MemorySpec::Kind memory_kind(const json::Value &v) {
  if (!v.is_string()) bad(v, "kind must be \"ram\", \"rom\" or \"mmio\"");
  const std::string &k = v.as_string();
  if (k == "ram") return MemorySpec::Kind::ram;
  if (k == "rom" || k == "flash") return MemorySpec::Kind::rom;
  if (k == "mmio" || k == "io" || k == "volatile") return MemorySpec::Kind::mmio;
  bad(v, "kind \"" + k + "\" is not ram, rom or mmio");
}

}  // namespace

MachineSpec parse_machine(std::string_view text) {
  json::Value doc;
  try {
    doc = json::Value::parse(text);
  } catch (const json::Error &e) {
    throw MachineError(std::string("not valid JSON: ") + e.what());
  }
  if (!doc.is_object()) throw MachineError("a machine description is a JSON object");
  detail::allow_keys(doc, {"machine", "name", "description", "language", "cpu", "clock", "memory", "image", "entry",
                           "registers", "peripherals", "break_on", "console"},
                     "a machine");
  MachineSpec s;
  s.source = doc;
  if (const json::Value *v = doc.find("machine"); v && num(*v, "machine") != 1)
    bad(*v, "this revkit reads machine descriptions of version 1");
  s.name = detail::str_or(doc, "name", "");
  s.description = detail::str_or(doc, "description", "");
  s.language = detail::str_or(doc, "language", "");
  if (const json::Value *c = doc.find("cpu")) {
    if (c->is_string()) {
      s.cpu.model = c->as_string();
    } else if (c->is_object()) {
      detail::allow_keys(*c, {"model", "vector_base", "aborts", "undefined", "nvic_irqs", "priority_bits", "semihosting"}, "cpu");
      s.cpu.semihosting = detail::bool_or(*c, "semihosting", false);
      s.cpu.model = detail::str_or(*c, "model", "");
      s.cpu.vector_base = detail::opt_num(*c, "vector_base");
      s.cpu.aborts = detail::bool_or(*c, "aborts", false);
      s.cpu.undefined = detail::bool_or(*c, "undefined", false);
      s.cpu.nvic_irqs = static_cast<std::uint32_t>(detail::num_or(*c, "nvic_irqs", 64));
      s.cpu.priority_bits = static_cast<std::uint32_t>(detail::num_or(*c, "priority_bits", 8));
    } else {
      bad(*c, "cpu is a model name or an object");
    }
    if (!s.cpu.model.empty() && s.cpu.model != "arm" && s.cpu.model != "cortex-m" && s.cpu.model != "mips" && s.cpu.model != "none")
      bad(*c, "cpu model \"" + s.cpu.model + "\" is not arm, cortex-m, mips or none");
  }
  if (const json::Value *c = doc.find("clock")) {
    if (!c->is_object()) bad(*c, "clock is an object");
    detail::allow_keys(*c, {"mode", "hz", "ticks_per_step"}, "clock");
    const std::string mode = detail::str_or(*c, "mode", "instructions");
    if (mode != "instructions" && mode != "wall") bad(*c, "clock mode is \"instructions\" (deterministic) or \"wall\"");
    s.clock.wall = mode == "wall";
    s.clock.hz = detail::num_or(*c, "hz", 1000000);
    s.clock.ticks_per_step = static_cast<std::uint32_t>(detail::num_or(*c, "ticks_per_step", 1));
    if (s.clock.hz == 0) bad(*c, "clock hz must not be 0");
  }
  if (const json::Value *mem = doc.find("memory")) {
    if (!mem->is_array()) bad(*mem, "memory is a list of regions");
    for (const json::Value &r : mem->items()) {
      if (!r.is_object()) bad(r, "a memory region is an object");
      detail::allow_keys(r, {"name", "start", "size", "end", "kind", "perms"}, "a memory region");
      MemorySpec ms;
      ms.name = detail::str_or(r, "name", "");
      const json::Value *start = r.find("start");
      if (!start) bad(r, "a memory region needs start");
      ms.start = num(*start, "start");
      if (auto size = detail::opt_num(r, "size")) ms.size = *size;
      else if (auto end = detail::opt_num(r, "end")) ms.size = *end - ms.start;
      else bad(r, "memory region " + ms.name + " needs a size (or end)");
      if (ms.size == 0) bad(r, "memory region " + ms.name + " is empty");
      if (ms.start + (ms.size - 1) < ms.start) bad(r, "memory region " + ms.name + " wraps around");
      if (const json::Value *k = r.find("kind")) ms.kind = memory_kind(*k);
      ms.perms = ms.kind == MemorySpec::Kind::rom    ? loader::Perms{true, false, true}
                 : ms.kind == MemorySpec::Kind::mmio ? loader::Perms{true, true, false}
                                                     : loader::Perms{true, true, true};
      if (const json::Value *p = r.find("perms")) ms.perms = detail::parse_perms(*p, "perms");
      if (ms.name.empty()) ms.name = std::string(ms.kind == MemorySpec::Kind::mmio ? "mmio" : ms.kind == MemorySpec::Kind::rom ? "rom" : "ram") + "_" + detail::hexs(ms.start).substr(2);
      s.memory.push_back(std::move(ms));
    }
    for (std::size_t i = 0; i < s.memory.size(); ++i)
      for (std::size_t j = i + 1; j < s.memory.size(); ++j) {
        const MemorySpec &a = s.memory[i], &b = s.memory[j];
        if (a.start <= b.start + (b.size - 1) && b.start <= a.start + (a.size - 1))
          throw MachineError("memory regions " + a.name + " and " + b.name + " overlap");
      }
  }
  if (const json::Value *im = doc.find("image")) {
    if (!im->is_object()) bad(*im, "image is an object");
    detail::allow_keys(*im, {"load", "offset", "header", "length", "perms", "name"}, "image");
    ImageSpec is;
    is.load = detail::num_or(*im, "load", 0);
    is.offset = detail::num_or(*im, "offset", detail::num_or(*im, "header", 0));
    is.length = detail::opt_num(*im, "length");
    if (const json::Value *p = im->find("perms")) is.perms = detail::parse_perms(*p, "image perms");
    is.name = detail::str_or(*im, "name", "image");
    s.image = is;
  }
  if (const json::Value *e = doc.find("entry")) {
    if (e->is_string() && (e->as_string() == "reset" || e->as_string() == "reset_vector")) s.entry.reset();
    else s.entry = num(*e, "entry");
  }
  if (const json::Value *r = doc.find("registers")) {
    if (!r->is_object()) bad(*r, "registers maps names to values");
    for (const auto &[k, v] : r->members()) s.registers.emplace_back(k, num(v, "register " + k));
  }
  if (const json::Value *ps = doc.find("peripherals")) {
    if (!ps->is_array()) bad(*ps, "peripherals is a list");
    for (const json::Value &p : ps->items()) {
      if (!p.is_object()) bad(p, "a peripheral is an object");
      PeripheralSpec x;
      x.config = p;
      x.name = detail::str_or(p, "name", "");
      x.kind = detail::str_or(p, "kind", "");
      if (x.kind.empty()) bad(p, "peripheral " + x.name + " needs a kind");
      if (x.name.empty()) x.name = x.kind + std::to_string(s.peripherals.size());
      for (char c : x.name)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-'))
          bad(p, "peripheral name \"" + x.name + "\": letters, digits, - and _ only");
      x.base = detail::opt_num(p, "base");
      x.size = detail::num_or(p, "size", 0x1000);
      if (const json::Value *irq = p.find("irq")) {
        if (irq->is_string()) x.irqs.emplace_back("irq", irq->as_string());
        else if (irq->is_object())
          for (const auto &[k, v] : irq->members()) {
            if (!v.is_string()) bad(v, "irq " + k + " goes to a \"device.input\" string");
            x.irqs.emplace_back(k, v.as_string());
          }
        else bad(*irq, "irq is \"device.input\" or {output: \"device.input\"}");
      }
      s.peripherals.push_back(std::move(x));
    }
  }
  if (const json::Value *b = doc.find("break_on")) {
    if (b->is_string()) s.break_on.push_back(b->as_string());
    else if (b->is_array())
      for (const json::Value &x : b->items()) {
        if (!x.is_string()) bad(x, "break_on lists exception kinds");
        s.break_on.push_back(x.as_string());
      }
    else bad(*b, "break_on lists exception kinds");
  }
  s.console = detail::str_or(doc, "console", "");
  return s;
}

std::string machine_json(const MachineSpec &s) {
  using json::Value;
  auto hex = [](std::uint64_t v) { return Value::string(detail::hexs(v)); };
  auto perms = [](const loader::Perms &p) {
    return Value::string(std::string(p.read ? "r" : "-") + (p.write ? "w" : "-") + (p.exec ? "x" : "-"));
  };
  Value doc = Value::object();
  doc.set("machine", Value::integer(1));
  if (!s.name.empty()) doc.set("name", Value::string(s.name));
  if (!s.description.empty()) doc.set("description", Value::string(s.description));
  if (!s.language.empty()) doc.set("language", Value::string(s.language));
  Value cpu = Value::object();
  if (!s.cpu.model.empty()) cpu.set("model", Value::string(s.cpu.model));
  if (s.cpu.vector_base) cpu.set("vector_base", hex(*s.cpu.vector_base));
  if (s.cpu.aborts) cpu.set("aborts", Value::boolean(true));
  if (s.cpu.undefined) cpu.set("undefined", Value::boolean(true));
  if (s.cpu.semihosting) cpu.set("semihosting", Value::boolean(true));
  if (s.cpu.model == "cortex-m") {
    if (s.cpu.nvic_irqs != 64) cpu.set("nvic_irqs", Value::integer(s.cpu.nvic_irqs));
    if (s.cpu.priority_bits != 8) cpu.set("priority_bits", Value::integer(s.cpu.priority_bits));
  }
  if (!cpu.members().empty()) doc.set("cpu", cpu);
  if (s.clock.wall || s.clock.hz != 1000000 || s.clock.ticks_per_step != 1) {
    Value c = Value::object();
    c.set("mode", Value::string(s.clock.wall ? "wall" : "instructions"));
    c.set("hz", Value::unsigned_integer(s.clock.hz));
    if (s.clock.ticks_per_step != 1) c.set("ticks_per_step", Value::integer(s.clock.ticks_per_step));
    doc.set("clock", c);
  }
  if (s.image) {
    Value im = Value::object();
    im.set("load", hex(s.image->load));
    if (s.image->offset) im.set("offset", hex(s.image->offset));
    if (s.image->length) im.set("length", hex(*s.image->length));
    im.set("perms", perms(s.image->perms));
    if (s.image->name != "image") im.set("name", Value::string(s.image->name));
    doc.set("image", im);
  }
  doc.set("entry", s.entry ? hex(*s.entry) : Value::string("reset"));
  Value mem = Value::array();
  for (const MemorySpec &m : s.memory) {
    Value r = Value::object();
    r.set("name", Value::string(m.name));
    r.set("start", hex(m.start));
    r.set("size", hex(m.size));
    r.set("kind", Value::string(m.kind == MemorySpec::Kind::ram ? "ram" : m.kind == MemorySpec::Kind::rom ? "rom" : "mmio"));
    r.set("perms", perms(m.perms));
    mem.push(r);
  }
  doc.set("memory", mem);
  if (!s.registers.empty()) {
    Value r = Value::object();
    for (const auto &[k, v] : s.registers) r.set(k, hex(v));
    doc.set("registers", r);
  }
  Value ps = Value::array();
  for (const PeripheralSpec &p : s.peripherals) {
    Value o = p.config.is_object() ? p.config : Value::object();
    o.set("name", Value::string(p.name));
    o.set("kind", Value::string(p.kind));
    if (p.base) o.set("base", hex(*p.base));
    if (p.size != 0x1000 || (p.base && !o.find("size"))) o.set("size", hex(p.size));
    if (!p.irqs.empty()) {
      if (p.irqs.size() == 1 && p.irqs[0].first == "irq") {
        o.set("irq", Value::string(p.irqs[0].second));
      } else {
        Value w = Value::object();
        for (const auto &[k, v] : p.irqs) w.set(k, Value::string(v));
        o.set("irq", w);
      }
    }
    ps.push(o);
  }
  doc.set("peripherals", ps);
  if (!s.break_on.empty()) {
    Value b = Value::array();
    for (const std::string &x : s.break_on) b.push(Value::string(x));
    doc.set("break_on", b);
  }
  if (!s.console.empty()) doc.set("console", Value::string(s.console));
  return doc.dump() + "\n";
}

loader::RawOptions machine_raw_options(const MachineSpec &spec, std::uint64_t file_size) {
  loader::RawOptions o;
  o.language = spec.language;
  const ImageSpec im = spec.image.value_or(ImageSpec{});
  o.base = im.load;
  o.offset = im.offset;
  o.length = im.length;
  o.perms = im.perms;
  o.block_name = im.name;
  if (spec.entry) o.entry = spec.entry;
  if (im.offset > file_size) throw MachineError("image offset " + detail::hexs(im.offset) + " is past the end of the file");
  const std::uint64_t len = std::min(im.length.value_or(file_size - im.offset), file_size - im.offset);
  const std::uint64_t first = im.load, last = len == 0 ? im.load : im.load + len - 1;
  for (const MemorySpec &m : spec.memory) {
    const std::uint64_t mlast = m.start + (m.size - 1);
    auto add = [&](std::uint64_t a, std::uint64_t b, const std::string &suffix) {
      if (b < a) return;
      loader::RawRegion r;
      r.name = m.name + suffix;
      r.start = a;
      r.size = b - a + 1;
      r.perms = m.perms;
      r.initialized = false;
      r.is_volatile = m.kind == MemorySpec::Kind::mmio;
      o.regions.push_back(r);
    };
    if (len == 0 || mlast < first || m.start > last) {
      add(m.start, mlast, "");
      continue;
    }
    if (m.kind == MemorySpec::Kind::mmio)
      throw MachineError("the image (" + detail::hexs(first) + "-" + detail::hexs(last) + ") overlaps MMIO region " + m.name);
    if (m.start < first) add(m.start, first - 1, "");
    if (mlast > last) add(last + 1, mlast, m.start < first ? "_high" : "");
  }
  return o;
}

std::vector<std::pair<std::string, std::string>> builtin_peripheral_kinds() {
  return {
      {"timer", "a generic down/up counting timer: load, value, control (enable, periodic, interrupt), status; registers and bits configurable"},
      {"sp804", "ARM SP804 dual timer (as on Versatile and RealView boards)"},
      {"uart", "a generic UART: data and status registers at configurable offsets; transmits to the session's output"},
      {"pl011", "ARM PL011 UART"},
      {"intc", "a generic interrupt controller: status, raw, enable/mask, clear and pending-number registers, configurable"},
      {"vic", "ARM PL190 vectored interrupt controller (VIC)"},
      {"gic", "a GIC-lite: distributor and CPU interface for one CPU (enable, pending, priority, acknowledge, end of interrupt)"},
      {"rtc", "ARM PL031 real-time clock (seconds from the machine clock)"},
      {"auto-ack", "registers that read back a ready bit (address, mask, value; fixed, toggling or counting) to get past polling loops"},
      {"ram-device", "a block of registers that read back what was written (MMIO without side effects)"},
  };
}

// --- The emulator's side ---------------------------------------------------

Emulator::Impl::~Impl() = default;

Machine &Emulator::attach_machine(const MachineSpec &spec, const MachineOptions &options) {
  Impl &m = *impl_;
  if (m.machine) throw MachineError("a machine is already attached");
  if (!spec.language.empty()) {
    auto base = [](const std::string &l) {
      return std::count(l.begin(), l.end(), ':') >= 4 ? l.substr(0, l.rfind(':')) : l;
    };
    if (base(spec.language) != base(m.language))
      throw MachineError("the machine is for " + spec.language + ", the program is " + m.language);
  }
  auto rt = std::make_unique<MachineRuntime>(m, spec, options);
  MachineRuntime &r = *rt;
  m.machine = std::move(rt);
  try {
    r.build();
    r.reset(spec.entry);
  } catch (const Fault &f) {
    m.machine.reset();
    throw MachineError(f.detail);
  } catch (...) {
    m.machine.reset();
    throw;
  }
  m.decoded.clear();
  m.decoded_thumb.clear();
  m.code_pages.clear();
  return r;
}

Machine *Emulator::machine() { return impl_->machine.get(); }
const Machine *Emulator::machine() const { return impl_->machine.get(); }

}  // namespace revkit::emu
