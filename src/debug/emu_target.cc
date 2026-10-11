#include "revkit/debug/emu_target.hh"

#include <algorithm>
#include <cstdlib>

namespace revkit::debug {

Stop from_emu(const emu::Stop &s) {
  Stop out;
  if (s.kind == emu::StopKind::exception) out.kind = StopKind::exception;
  else if (s.kind == emu::StopKind::idle) out.kind = StopKind::idle;
  else out.kind = static_cast<StopKind>(static_cast<std::uint8_t>(s.kind));  // the same order up to cancelled (target.hh)
  out.pc = s.pc;
  out.address = s.address;
  out.detail = s.detail;
  out.exit_code = s.exit_code;
  out.steps = s.steps;
  out.thread = "1";
  return out;
}

EmulatorTarget::EmulatorTarget(std::unique_ptr<emu::Emulator> emu, std::string program_name)
    : emu_(std::move(emu)), program_name_(std::move(program_name)) {
  const auto &display = emu_->display_registers();
  for (const emu::RegisterInfo &r : emu_->registers()) {
    RegisterDesc d;
    d.name = d.target_name = d.sleigh = r.name;
    d.size = r.size;
    d.display = std::find(display.begin(), display.end(), r.name) != display.end();
    d.group = d.display ? (r.size == 1 ? "flags" : "general") : "other";
    regs_.push_back(d);
  }
  // Display registers first, in the emulator's order.
  std::stable_sort(regs_.begin(), regs_.end(), [&](const RegisterDesc &a, const RegisterDesc &b) {
    auto rank = [&](const RegisterDesc &d) {
      auto it = std::find(display.begin(), display.end(), d.name);
      return it == display.end() ? display.size() : static_cast<std::size_t>(it - display.begin());
    };
    return rank(a) < rank(b);
  });
  last_ = from_emu(emu_->last_stop());
  last_.pc = emu_->pc();
}

std::string EmulatorTarget::description() const { return "revkit p-code emulator (" + emu_->language() + ")"; }

bool EmulatorTarget::complete_recording() const {
  return emu_->trace().capacity() > 0 && emu_->options().trace_memory;
}

TargetState EmulatorTarget::state() const {
  if (detached_) return TargetState::detached;
  if (last_.kind == StopKind::exited) return TargetState::exited;
  return TargetState::stopped;
}

std::vector<std::uint8_t> EmulatorTarget::read_register(std::string_view name) {
  try {
    return emu_->read_register_bytes(name);
  } catch (const emu::EmuError &e) {
    throw DebugError(e.what());
  }
}

void EmulatorTarget::write_register(std::string_view name, std::span<const std::uint8_t> value) {
  try {
    auto r = emu_->find_register(name);
    if (!r) throw DebugError("no register " + std::string(name));
    std::vector<std::uint8_t> v(value.begin(), value.end());
    v.resize(r->size, 0);
    emu_->write_register_bytes(name, v);
  } catch (const emu::EmuError &e) {
    throw DebugError(e.what());
  }
}

std::size_t EmulatorTarget::read_memory(std::uint64_t address, std::span<std::uint8_t> out, std::vector<ByteRange> *unreadable) {
  std::fill(out.begin(), out.end(), 0);
  const auto regions = emu_->regions();
  std::size_t at = 0, read = 0;
  while (at < out.size()) {
    const std::uint64_t addr = address + at;
    const emu::RegionInfo *r = nullptr;
    for (const emu::RegionInfo &x : regions)
      if (addr >= x.start && addr - x.start < x.size) r = &x;
    std::size_t n = 0;
    if (r != nullptr) {
      n = static_cast<std::size_t>(std::min<std::uint64_t>(out.size() - at, r->start + r->size - addr));
      if (n == 0) n = out.size() - at;
      emu_->read_memory(addr, out.subspan(at, n));
      read += n;
    } else {
      std::uint64_t next = ~std::uint64_t{0};
      for (const emu::RegionInfo &x : regions)
        if (x.start > addr) next = std::min(next, x.start);
      n = static_cast<std::size_t>(std::min<std::uint64_t>(out.size() - at, next - addr));
      if (unreadable != nullptr) unreadable->push_back({static_cast<std::uint32_t>(at), static_cast<std::uint32_t>(n)});
    }
    at += n;
  }
  return read;
}

bool EmulatorTarget::write_memory(std::uint64_t address, std::span<const std::uint8_t> bytes) {
  try {
    return emu_->write_memory(address, bytes);
  } catch (const emu::EmuError &e) {
    throw DebugError(e.what());
  }
}

std::map<std::string, std::vector<std::uint8_t>> EmulatorTarget::display_values() const {
  std::map<std::string, std::vector<std::uint8_t>> out;
  for (const std::string &n : emu_->display_registers()) out[n] = emu_->read_register_bytes(n);
  return out;
}

Stop EmulatorTarget::resume(const ResumeOptions &options) {
  if (detached_) throw DebugError("the emulator session is closed");
  steps_at_resume_ = emu_->steps();
  display_at_resume_ = display_values();
  interrupted_ = false;
  emu::RunOptions o;
  o.max_steps = options.max_steps;
  o.until = options.until;
  o.deadline = options.deadline;
  auto cancelled = options.cancelled;
  o.cancelled = [this, cancelled] { return interrupted_.load() || (cancelled && cancelled()); };
  emu::Stop s;
  switch (options.mode) {
    case RunMode::step_into: s = emu_->step(); break;
    case RunMode::step_over: s = emu_->step_over(o); break;
    case RunMode::step_out: s = emu_->step_out(o); break;
    case RunMode::run: s = emu_->run(o); break;
  }
  last_ = from_emu(s);
  if (last_.kind == StopKind::cancelled && interrupted_) {
    last_.kind = StopKind::interrupted;
    last_.detail = "interrupted";
  }
  return last_;
}

void EmulatorTarget::checkpoint(std::uint64_t snapshot) {
  if (!rewindable()) return;
  checkpoints_[snapshot] = emu_->checkpoint();
  // Bounded: thin the oldest half when there are many.
  if (checkpoints_.size() > 1024) {
    std::size_t i = 0;
    for (auto it = checkpoints_.begin(); it != checkpoints_.end() && i < 512; ++i)
      it = (i % 2 == 1) ? checkpoints_.erase(it) : std::next(it);
  }
}

void EmulatorTarget::forget_checkpoints_before(std::uint64_t first) {
  auto keep = checkpoints_.upper_bound(first);
  if (keep == checkpoints_.begin()) return;
  --keep;  // the last one at or before `first` stays
  checkpoints_.erase(checkpoints_.begin(), keep);
}

void EmulatorTarget::rewind(std::uint64_t snapshot, std::uint64_t steps) {
  if (!rewindable()) throw DebugError("an emulator with a machine can't go back (its peripherals aren't checkpointed)");
  auto it = checkpoints_.upper_bound(snapshot);
  if (it == checkpoints_.begin()) throw DebugError("no checkpoint at or before snapshot " + std::to_string(snapshot));
  --it;
  if (it->second.steps() > steps) throw DebugError("snapshot " + std::to_string(snapshot) + " is before its checkpoint");
  emu_->restore(it->second);
  // The steps between, again.
  while (emu_->steps() < steps) {
    const emu::Stop s = emu_->step();
    if (s.kind != emu::StopKind::stepped && s.kind != emu::StopKind::breakpoint && s.kind != emu::StopKind::watchpoint &&
        emu_->steps() < steps)
      throw DebugError("replaying to snapshot " + std::to_string(snapshot) + " stopped: " + s.detail);
  }
  checkpoints_.erase(checkpoints_.upper_bound(snapshot), checkpoints_.end());
  steps_at_resume_ = emu_->steps();
  stdout_at_ = emu_->stdout_data().size();
  stderr_at_ = emu_->stderr_data().size();
  display_at_resume_ = display_values();
}

void EmulatorTarget::insert_breakpoint(BreakKind kind, std::uint64_t address, std::uint32_t size) {
  switch (kind) {
    case BreakKind::software:
    case BreakKind::hardware: emu_->add_breakpoint(address); return;
    default: break;
  }
  const bool r = kind == BreakKind::watch_read || kind == BreakKind::watch_access;
  const bool w = kind == BreakKind::watch_write || kind == BreakKind::watch_access;
  const auto key = std::make_tuple(static_cast<int>(kind), address, size == 0 ? 1u : size);
  if (watches_.count(key)) return;
  watches_[key] = emu_->add_watchpoint(address, size == 0 ? 1 : size, r, w);
}

void EmulatorTarget::remove_breakpoint(BreakKind kind, std::uint64_t address, std::uint32_t size) {
  switch (kind) {
    case BreakKind::software:
    case BreakKind::hardware: emu_->remove_breakpoint(address); return;
    default: break;
  }
  const auto key = std::make_tuple(static_cast<int>(kind), address, size == 0 ? 1u : size);
  if (auto it = watches_.find(key); it != watches_.end()) {
    emu_->remove_watchpoint(it->second);
    watches_.erase(it);
  }
}

std::vector<ThreadInfo> EmulatorTarget::threads() {
  ThreadInfo t;
  t.id = "1";
  t.name = "emulated";
  t.current = true;
  t.pc = emu_->pc();
  return {t};
}

void EmulatorTarget::select_thread(const std::string &id) {
  if (id != "1") throw DebugError("the emulator has one thread, 1");
}

std::vector<ModuleInfo> EmulatorTarget::modules() {
  ModuleInfo m;
  m.name = m.path = program_name_;
  m.main = true;
  const loader::Image &img = emu_->image();
  std::uint64_t lo = ~std::uint64_t{0}, hi = 0;
  for (const loader::Region &r : img.memory.regions()) {
    lo = std::min(lo, r.start);
    hi = std::max(hi, r.start + r.size);
  }
  if (hi > lo) {
    m.base = lo;
    m.size = hi - lo;
  }
  m.load_bias = img.image_base - img.file_base;
  return {m};
}

std::vector<MapRegion> EmulatorTarget::memory_map() {
  std::vector<MapRegion> out;
  for (const emu::RegionInfo &r : emu_->regions()) {
    MapRegion m;
    m.start = r.start;
    m.size = r.size;
    m.perms = r.perms.str();
    m.name = r.name;
    switch (r.kind) {
      case emu::RegionInfo::Kind::image: m.kind = "image"; break;
      case emu::RegionInfo::Kind::ram: m.kind = "ram"; break;
      case emu::RegionInfo::Kind::mmio: m.kind = "mmio"; break;
      case emu::RegionInfo::Kind::stub: m.kind = "stub"; break;
    }
    out.push_back(m);
  }
  return out;
}

std::string EmulatorTarget::take_output() {
  std::string out;
  const std::string &so = emu_->stdout_data(), &se = emu_->stderr_data();
  if (stdout_at_ < so.size()) out += so.substr(stdout_at_);
  if (stderr_at_ < se.size()) out += se.substr(stderr_at_);
  stdout_at_ = so.size();
  stderr_at_ = se.size();
  return out;
}

namespace {

// A trace write's register storage: by name, or "register:0x<offset>:<size>".
std::optional<std::pair<std::uint64_t, std::uint32_t>> storage(const emu::Emulator &e, const std::string &name) {
  if (auto r = e.find_register(name)) return std::make_pair(r->offset, r->size);
  if (name.rfind("register:", 0) == 0) {
    const auto colon = name.find(':', 9);
    if (colon == std::string::npos) return std::nullopt;
    const std::uint64_t off = std::strtoull(name.c_str() + 9, nullptr, 0);
    const std::uint32_t size = static_cast<std::uint32_t>(std::strtoul(name.c_str() + colon + 1, nullptr, 0));
    return std::make_pair(off, size);
  }
  return std::nullopt;
}

}  // namespace

std::vector<StepRecord> EmulatorTarget::take_steps() {
  std::vector<StepRecord> out;
  const auto entries = emu_->trace().since(steps_at_resume_);
  if (entries.empty()) return out;
  // Display registers as they evolve, by storage overlap.
  struct Shown {
    std::string name;
    std::uint64_t offset;
    std::uint32_t size;
  };
  std::vector<Shown> shown;
  for (const std::string &n : emu_->display_registers())
    if (auto r = emu_->find_register(n)) shown.push_back({r->name, r->offset, r->size});
  auto values = display_at_resume_;
  const std::string pc_name = emu_->pc_register();
  const auto pc_reg = emu_->find_register(pc_name);
  for (std::size_t k = 0; k < entries.size(); ++k) {
    const emu::TraceEntry &e = entries[k];
    StepRecord rec;
    rec.index = e.index;
    rec.pc = e.pc;
    rec.text = e.text;
    rec.event = e.event;
    rec.exception = e.exception;
    rec.exception_number = e.exception_number;
    std::map<std::string, bool> touched;
    for (const emu::RegisterWrite &w : e.registers) {
      auto st = storage(*emu_, w.name);
      if (!st) continue;
      for (const Shown &s : shown) {
        const std::uint64_t lo = std::max(s.offset, st->first);
        const std::uint64_t hi = std::min(s.offset + s.size, st->first + std::min<std::uint64_t>(st->second, w.value.size()));
        if (lo >= hi) continue;
        auto &v = values[s.name];
        v.resize(s.size, 0);
        // Bytes are least significant first; register-space offsets on a
        // big-endian language count from the most significant byte.
        for (std::uint64_t at = lo; at < hi; ++at) {
          const std::uint64_t src = at - st->first, dst = at - s.offset;
          if (emu_->big_endian()) v[s.size - 1 - dst] = w.value[w.value.size() - 1 - src];
          else v[dst] = w.value[src];
        }
        touched[s.name] = true;
      }
    }
    // The pc moves without a recorded write: it is where the next step runs.
    if (pc_reg && values.count(pc_reg->name)) {
      const std::uint64_t next = k + 1 < entries.size() ? entries[k + 1].pc : emu_->pc();
      auto v = from_u64(next, pc_reg->size);
      if (values[pc_reg->name] != v) {
        values[pc_reg->name] = v;
        touched[pc_reg->name] = true;
      }
    }
    for (const auto &[name, _] : touched) rec.registers.emplace_back(name, values[name]);
    for (const emu::MemoryAccess &a : e.reads)
      if (a.space.empty()) rec.memory.push_back({a.address, a.bytes, {}, false});
    for (const emu::MemoryAccess &a : e.writes)
      if (a.space.empty()) rec.memory.push_back({a.address, a.bytes, a.before, true});
    out.push_back(std::move(rec));
  }
  steps_at_resume_ = emu_->steps();
  display_at_resume_ = display_values();
  return out;
}

}  // namespace revkit::debug
