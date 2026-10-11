#include "emulator.h"

#include "revkit/emu/emulator.hh"
#include "revkit/infer/library.h"
#include "revkit/lift/lifter.hh"

#include <algorithm>
#include <random>
#include <set>
#include <sstream>

namespace revkit::backend {

using api::Error;
using api::Status;
using api::StatusCode;

struct EmulatorSessions::Session {
  std::string id, program_id, client;
  std::string owner;  // CallContext.caller of Create ("anonymous" without authentication)
  std::shared_ptr<const Program> program;  // keeps the image alive
  std::unique_ptr<emu::Emulator> emu;
  pb::EmulatorLimits limits;
  std::mutex mu;  // one call at a time
  std::chrono::steady_clock::time_point last_used = std::chrono::steady_clock::now();
  std::uint64_t steps = 0;
  bool session_limit = false;  // the last run hit max_total_steps
  // Register values before the last RunEmulator call, for `changed`.
  std::map<std::string, std::vector<std::uint8_t>> before;
  std::set<std::string> shown;  // registers the last state reported
};

namespace {

std::string NewId() {
  static std::mutex mu;
  static std::random_device rd;
  std::lock_guard lock(mu);
  std::ostringstream o;
  o << "emu-" << std::hex;
  for (int i = 0; i < 4; ++i) o << std::uniform_int_distribution<std::uint32_t>()(rd);
  return o.str();
}

std::uint64_t Pick(std::uint64_t asked, std::uint64_t def, std::uint64_t cap) {
  return std::min(asked == 0 ? def : asked, cap);
}

pb::EmulatorStopKind ToPb(emu::StopKind k) {
  using K = emu::StopKind;
  switch (k) {
    case K::none: return pb::EMULATOR_STOP_KIND_NONE;
    case K::stepped: return pb::EMULATOR_STOP_KIND_STEPPED;
    case K::step_limit: return pb::EMULATOR_STOP_KIND_STEP_LIMIT;
    case K::breakpoint: return pb::EMULATOR_STOP_KIND_BREAKPOINT;
    case K::until: return pb::EMULATOR_STOP_KIND_UNTIL;
    case K::returned: return pb::EMULATOR_STOP_KIND_RETURNED;
    case K::exited: return pb::EMULATOR_STOP_KIND_EXITED;
    case K::halted: return pb::EMULATOR_STOP_KIND_HALTED;
    case K::unmapped: return pb::EMULATOR_STOP_KIND_UNMAPPED;
    case K::protection: return pb::EMULATOR_STOP_KIND_PROTECTION;
    case K::decode: return pb::EMULATOR_STOP_KIND_DECODE;
    case K::unimplemented: return pb::EMULATOR_STOP_KIND_UNIMPLEMENTED;
    case K::userop: return pb::EMULATOR_STOP_KIND_USEROP;
    case K::syscall: return pb::EMULATOR_STOP_KIND_SYSCALL;
    case K::watchpoint: return pb::EMULATOR_STOP_KIND_WATCHPOINT;
    case K::hook: return pb::EMULATOR_STOP_KIND_HOOK;
    case K::divide_by_zero: return pb::EMULATOR_STOP_KIND_DIVIDE_BY_ZERO;
    case K::memory_limit: return pb::EMULATOR_STOP_KIND_MEMORY_LIMIT;
    case K::time_limit: return pb::EMULATOR_STOP_KIND_TIME_LIMIT;
    case K::cancelled: return pb::EMULATOR_STOP_KIND_CANCELLED;
    case K::exception: return pb::EMULATOR_STOP_KIND_EXCEPTION;
    case K::idle: return pb::EMULATOR_STOP_KIND_IDLE;
  }
  return pb::EMULATOR_STOP_KIND_UNSPECIFIED;
}

void FillStop(const emu::Stop &s, pb::EmulatorStop *out) {
  out->set_kind(ToPb(s.kind));
  out->mutable_pc()->set_offset(s.pc);
  if (s.address) out->mutable_address()->set_offset(*s.address);
  out->set_detail(s.detail);
  out->set_exit_code(s.exit_code);
  out->set_steps(s.steps);
}

bool DefaultSpace(const pb::Address &a) { return a.space().empty() || a.space() == "ram"; }

std::string Perms(const loader::Perms &p) {
  return std::string(p.read ? "r" : "-") + (p.write ? "w" : "-") + (p.exec ? "x" : "-");
}

const char *KindName(emu::RegionInfo::Kind k) {
  switch (k) {
    case emu::RegionInfo::Kind::image: return "image";
    case emu::RegionInfo::Kind::ram: return "ram";
    case emu::RegionInfo::Kind::mmio: return "mmio";
    case emu::RegionInfo::Kind::stub: return "stub";
  }
  return "";
}

Status WriteRegisters(emu::Emulator &e, const google::protobuf::RepeatedPtrField<pb::EmulatorRegisterWrite> &writes) {
  for (const pb::EmulatorRegisterWrite &w : writes) {
    if (!e.find_register(w.name())) return Error(StatusCode::kInvalidArgument, "unknown register " + w.name());
    try {
      if (!w.bytes().empty()) {
        e.write_register_bytes(w.name(), std::span<const std::uint8_t>(
                                             reinterpret_cast<const std::uint8_t *>(w.bytes().data()), w.bytes().size()));
      } else {
        e.write_register(w.name(), w.value());
      }
    } catch (const emu::EmuError &err) {
      return Error(StatusCode::kInvalidArgument, err.what());
    }
  }
  return Status::Ok();
}

Status WriteMemory(emu::Emulator &e, const pb::Address &at, const std::string &data) {
  if (!DefaultSpace(at)) return Error(StatusCode::kInvalidArgument, "only the default space is writable");
  if (data.size() > (16u << 20)) return Error(StatusCode::kInvalidArgument, "more than 16 MiB");
  try {
    if (!e.write_memory(at.offset(),
                        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(data.data()), data.size())))
      return Error(StatusCode::kInvalidArgument, "memory at " + emu::hex(at.offset()) + " is not mapped");
  } catch (const emu::EmuError &err) {
    return Error(StatusCode::kResourceExhausted, err.what());
  }
  return Status::Ok();
}

void FillRegister(emu::Emulator &e, const std::string &name, const std::vector<std::uint8_t> *before,
                  pb::EmulatorRegisterValue *out) {
  const std::vector<std::uint8_t> v = e.read_register_bytes(name);
  out->set_name(name);
  out->set_size(static_cast<std::uint32_t>(v.size()));
  std::uint64_t lo = 0;
  for (std::size_t i = 0; i < v.size() && i < 8; ++i) lo |= std::uint64_t{v[i]} << (8 * i);
  out->set_value(lo);
  out->set_bytes(std::string(v.begin(), v.end()));
  out->set_changed(before != nullptr && *before != v);
}

}  // namespace

pb::EmulatorLimits ResolveLimits(const pb::EmulatorLimits &l, const EmulatorBounds &bounds) {
  pb::EmulatorLimits out;
  out.set_max_steps_per_call(Pick(l.max_steps_per_call(), bounds.steps_per_call, bounds.max_steps_per_call));
  out.set_max_total_steps(Pick(l.max_total_steps(), bounds.total_steps, bounds.max_total_steps));
  out.set_max_memory_bytes(Pick(l.max_memory_bytes(), bounds.memory, bounds.max_memory));
  out.set_trace_capacity(static_cast<std::uint32_t>(Pick(l.trace_capacity(), bounds.trace_capacity, bounds.max_trace_capacity)));
  out.set_time_limit_ms(static_cast<std::uint32_t>(Pick(l.time_limit_ms(), bounds.time_ms, bounds.max_time_ms)));
  return out;
}

Status BuildEmulator(const pb::CreateEmulatorSessionRequest &req, const std::shared_ptr<const Program> &program,
                     const pb::EmulatorLimits &limits, std::unique_ptr<emu::Emulator> &out,
                     const facts::PatchList &patches, const MachineSupport *machines) {
  if (!req.entry().space().empty() && !DefaultSpace(req.entry()))
    return Error(StatusCode::kInvalidArgument, "the entry must be in the default space");
  const loader::Image &image = program->image();
  emu::Options o;
  o.language = program->language().id();
  o.patches = patches;  // the program as patched (docs/patching.md)
  o.max_memory = limits.max_memory_bytes();
  o.trace_capacity = limits.trace_capacity();
  o.import_return = req.import_return();
  o.library_stubs = !req.no_library_stubs();
  o.stdin_data = req.stdin();
  o.argv = {image.format == loader::Format::raw ? "firmware" : req.program_id().substr(req.program_id().find('/') + 1)};
  const auto image_ptr = program->image_ptr();
  const bool pe32 = image.format == loader::Format::pe && image.bits == 32;
  o.prototypes = [image_ptr, pe32](std::string_view name) -> std::optional<emu::ImportPrototype> {
    auto p = infer::library_prototype(*image_ptr, name);
    if (!p) return std::nullopt;
    emu::ImportPrototype ip;
    ip.returns_value = !p->ret.is_void();
    ip.parameters = static_cast<std::uint32_t>(p->params.size());
    ip.varargs = p->varargs;
    ip.callee_pops = pe32 && !p->varargs;
    return ip;
  };
  // A machine (docs/firmware-emulation.md): its description, or a saved one.
  std::optional<emu::MachineSpec> spec;
  if (!req.machine().empty() || !req.machine_name().empty()) {
    if (!req.machine().empty() && !req.machine_name().empty())
      return Error(StatusCode::kInvalidArgument, "give machine or machine_name, not both");
    std::string text = req.machine();
    if (!req.machine_name().empty()) {
      std::optional<std::string> saved;
      if (machines && machines->load) saved = machines->load(req.program_id(), req.machine_name());
      if (!saved) return Error(StatusCode::kNotFound, "no machine " + req.machine_name() + " for " + req.program_id());
      text = *saved;
    }
    if (text.size() > (4u << 20)) return Error(StatusCode::kInvalidArgument, "a machine description is at most 4 MiB");
    try {
      spec = emu::parse_machine(text);
    } catch (const emu::MachineError &e) {
      return Error(StatusCode::kInvalidArgument, std::string("machine: ") + e.what());
    }
    if (req.has_entry()) spec->entry = req.entry().offset();
  }
  std::uint64_t entry = 0;
  if (req.has_entry()) entry = req.entry().offset();
  else if (image.entry) entry = *image.entry;
  else if (!spec) return Error(StatusCode::kInvalidArgument, "the program has no entry point; give one");
  emu::StartMode mode = emu::StartMode::automatic;
  switch (req.mode()) {
    case pb::EMULATOR_START_MODE_PROCESS: mode = emu::StartMode::process; break;
    case pb::EMULATOR_START_MODE_CALL: mode = emu::StartMode::call; break;
    case pb::EMULATOR_START_MODE_BARE: mode = emu::StartMode::bare; break;
    default: break;
  }
  try {
    out = std::make_unique<emu::Emulator>(image_ptr, o);
    if (spec) {
      emu::MachineOptions mo;
      if (machines) mo.factory = machines->factory;
      out->attach_machine(*spec, mo);
    } else {
      const std::vector<std::uint64_t> args(req.arguments().begin(), req.arguments().end());
      out->start(entry, mode, args);
    }
  } catch (const emu::MachineError &e) {
    return Error(StatusCode::kInvalidArgument, std::string("machine: ") + e.what());
  } catch (const emu::EmuError &e) {
    return Error(StatusCode::kInvalidArgument, e.what());
  } catch (const lift::LiftError &e) {
    return Error(StatusCode::kFailedPrecondition, e.what());
  }
  if (auto st = backend::WriteRegisters(*out, req.registers()); !st.ok()) return st;
  for (const pb::EmulatorMemoryWrite &w : req.memory())
    if (auto st = backend::WriteMemory(*out, w.address(), w.data()); !st.ok()) return st;
  for (const pb::Address &b : req.breakpoints()) out->add_breakpoint(b.offset());
  return Status::Ok();
}

EmulatorSessions::EmulatorSessions(EmulatorBounds bounds) : bounds_(bounds) {}
EmulatorSessions::~EmulatorSessions() = default;

namespace {

void FillState(EmulatorSessions::Session &s, const pb::EmulatorStateOptions &o, pb::EmulatorState *out);

}  // namespace

void EmulatorSessions::Reap() {
  const auto now = std::chrono::steady_clock::now();
  for (auto it = sessions_.begin(); it != sessions_.end();) {
    std::unique_lock lock(it->second->mu, std::try_to_lock);
    if (lock.owns_lock() && now - it->second->last_used > bounds_.idle) {
      lock.unlock();
      it = sessions_.erase(it);
    } else {
      ++it;
    }
  }
}

namespace {
// Whether `ctx`'s caller may use a session made by `owner`. Another
// caller's session reads as missing, so ids don't leak.
bool MayUse(const api::CallContext &ctx, const std::string &owner) { return ctx.caller_admin || ctx.caller == owner; }
}  // namespace

Status EmulatorSessions::Acquire(const api::CallContext &ctx, const std::string &id, std::shared_ptr<Session> &out,
                                 std::unique_lock<std::mutex> &lock) {
  {
    std::lock_guard g(mu_);
    auto it = sessions_.find(id);
    if (it == sessions_.end() || !MayUse(ctx, it->second->owner))
      return Error(StatusCode::kNotFound, "no emulator session " + id);
    out = it->second;
  }
  lock = std::unique_lock(out->mu);
  out->last_used = std::chrono::steady_clock::now();
  return Status::Ok();
}

Status EmulatorSessions::Create(const api::CallContext &ctx, const pb::CreateEmulatorSessionRequest &req,
                                std::shared_ptr<const Program> program, pb::CreateEmulatorSessionResponse &resp,
                                const facts::PatchList &patches) {
  const std::string client = req.client().empty() ? ctx.peer : req.client();
  {
    std::lock_guard g(mu_);
    Reap();
    if (sessions_.size() >= bounds_.sessions)
      return Error(StatusCode::kResourceExhausted, "the server runs " + std::to_string(sessions_.size()) +
                                                       " emulator sessions, its most; close one");
    // Authenticated, the bound is per identity, whatever `client` says.
    const bool authed = ctx.caller != "anonymous";
    const auto mine = std::count_if(sessions_.begin(), sessions_.end(), [&](const auto &kv) {
      return authed ? kv.second->owner == ctx.caller : kv.second->client == client;
    });
    if (static_cast<unsigned>(mine) >= bounds_.sessions_per_client)
      return Error(StatusCode::kResourceExhausted,
                   (authed ? ctx.caller : "client " + client) + " has " + std::to_string(mine) + " emulator sessions, its most; close one");
  }
  if (!req.entry().space().empty() && !DefaultSpace(req.entry()))
    return Error(StatusCode::kInvalidArgument, "the entry must be in the default space");

  auto s = std::make_shared<Session>();
  s->id = NewId();
  s->program_id = req.program_id();
  s->client = client;
  s->owner = ctx.caller;
  s->program = program;
  s->limits = ResolveLimits(req.limits(), bounds_);
  if (auto st = BuildEmulator(req, program, s->limits, s->emu, patches, &machines_); !st.ok()) return st;
  emu::Emulator &e = *s->emu;
  if (const emu::Machine *m = e.machine()) FillMachineInfo(*m, resp.mutable_machine());
  resp.set_session_id(s->id);
  resp.set_language(e.language());
  const std::set<std::string> display(e.display_registers().begin(), e.display_registers().end());
  for (const emu::RegisterInfo &r : e.registers()) {
    pb::EmulatorRegisterInfo *ri = resp.add_registers();
    ri->set_name(r.name);
    ri->set_size(r.size);
    ri->set_display(display.count(r.name) != 0);
  }
  resp.set_pc_register(e.pc_register());
  resp.set_sp_register(e.sp_register());
  *resp.mutable_limits() = s->limits;
  FillState(*s, {}, resp.mutable_state());
  std::lock_guard g(mu_);
  sessions_[s->id] = s;
  return Status::Ok();
}

Status EmulatorSessions::Close(const api::CallContext &ctx, const pb::CloseEmulatorSessionRequest &req) {
  std::shared_ptr<Session> s;
  {
    std::lock_guard g(mu_);
    auto it = sessions_.find(req.session_id());
    if (it == sessions_.end() || !MayUse(ctx, it->second->owner)) return Error(StatusCode::kNotFound, "no emulator session " + req.session_id());
    s = it->second;
    sessions_.erase(it);
  }
  std::lock_guard wait(s->mu);  // a running call finishes first
  return Status::Ok();
}

Status EmulatorSessions::List(const api::CallContext &ctx, const pb::ListEmulatorSessionsRequest &req,
                              pb::ListEmulatorSessionsResponse &resp) {
  const std::string client = req.client().empty() ? ctx.peer : req.client();
  std::vector<std::shared_ptr<Session>> mine;
  {
    std::lock_guard g(mu_);
    Reap();
    // Without a client filter, an authenticated caller lists all its own
    // sessions (whichever client made them); others' stay invisible unless
    // the caller is an admin naming their client.
    for (const auto &[id, s] : sessions_) {
      if (!MayUse(ctx, s->owner)) continue;
      const bool own = ctx.caller != "anonymous" && s->owner == ctx.caller;
      if (s->client == client || (req.client().empty() && own)) mine.push_back(s);
    }
  }
  const auto now = std::chrono::steady_clock::now();
  for (const auto &s : mine) {
    std::unique_lock lock(s->mu, std::try_to_lock);
    pb::EmulatorSessionInfo *info = resp.add_sessions();
    info->set_session_id(s->id);
    info->set_program_id(s->program_id);
    info->set_client(s->client);
    info->set_idle_ms(static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now - s->last_used).count()));
    if (lock.owns_lock()) {
      info->set_steps(s->emu->steps());
      FillStop(s->emu->last_stop(), info->mutable_last_stop());
    }
  }
  return Status::Ok();
}

namespace {

void FillState(EmulatorSessions::Session &s, const pb::EmulatorStateOptions &o, pb::EmulatorState *out) {
  emu::Emulator &e = *s.emu;
  out->mutable_pc()->set_offset(e.pc());
  out->set_thumb(e.thumb());
  out->set_steps(e.steps());
  FillStop(e.last_stop(), out->mutable_last_stop());
  if (s.session_limit) out->mutable_last_stop()->set_kind(pb::EMULATOR_STOP_KIND_SESSION_LIMIT);
  std::vector<std::string> names;
  if (o.all_registers()) {
    for (const emu::RegisterInfo &r : e.registers())
      if (r.size <= 64) names.push_back(r.name);
  } else if (!o.registers().empty()) {
    for (const std::string &n : o.registers())
      if (auto r = e.find_register(n)) names.push_back(r->name);
  } else {
    names = e.display_registers();
  }
  s.shown.clear();
  for (const std::string &n : names) {
    auto it = s.before.find(n);
    FillRegister(e, n, it == s.before.end() ? nullptr : &it->second, out->add_registers());
    s.shown.insert(n);
  }
  for (std::uint64_t b : e.breakpoints()) out->add_breakpoints()->set_offset(b);
  out->set_memory_used(e.memory_used());
  constexpr std::uint64_t kMaxOutput = 64 << 10;
  const std::string &so = e.stdout_data(), &se = e.stderr_data();
  if (o.stdout_offset() < so.size()) out->set_stdout(so.substr(o.stdout_offset(), kMaxOutput));
  if (o.stderr_offset() < se.size()) out->set_stderr(se.substr(o.stderr_offset(), kMaxOutput));
  out->set_stdout_size(so.size());
  out->set_stderr_size(se.size());
  if (const emu::Machine *m = e.machine()) {
    out->set_machine(true);
    out->set_tick(m->now());
    out->set_waiting(m->state().waiting);
  }
  if (o.include_regions()) {
    for (const emu::RegionInfo &r : e.regions()) {
      pb::EmulatorRegion *pr = out->add_regions();
      pr->set_name(r.name);
      pr->mutable_range()->mutable_first()->set_offset(r.start);
      pr->mutable_range()->mutable_last()->set_offset(r.start + (r.size - 1));
      pr->set_permissions(Perms(r.perms));
      pr->set_kind(KindName(r.kind));
    }
  }
}

}  // namespace

Status EmulatorSessions::Run(const api::CallContext &ctx, const pb::RunEmulatorRequest &req, pb::RunEmulatorResponse &resp) {
  std::shared_ptr<Session> s;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), s, lock); !st.ok()) return st;
  emu::Emulator &e = *s->emu;

  // What `changed` compares against: the registers as they are now.
  s->before.clear();
  for (const std::string &n : e.display_registers()) s->before[n] = e.read_register_bytes(n);
  for (const std::string &n : s->shown) s->before[n] = e.read_register_bytes(n);
  for (const std::string &n : req.state().registers())
    if (auto r = e.find_register(n)) s->before[r->name] = e.read_register_bytes(r->name);

  const std::uint64_t used = e.steps();
  const std::uint64_t left = used >= s->limits.max_total_steps() ? 0 : s->limits.max_total_steps() - used;
  s->session_limit = false;
  emu::Stop stop;
  if (left == 0) {
    s->session_limit = true;
    stop.kind = emu::StopKind::step_limit;
    stop.pc = e.pc();
    stop.detail = "the session's " + std::to_string(s->limits.max_total_steps()) + " steps are spent";
  } else {
    emu::RunOptions o;
    o.max_steps = std::min({req.max_steps() == 0 ? s->limits.max_steps_per_call() : req.max_steps(),
                            s->limits.max_steps_per_call(), left});
    const std::uint32_t ms = req.time_limit_ms() == 0 ? s->limits.time_limit_ms()
                                                       : std::min(req.time_limit_ms(), s->limits.time_limit_ms());
    o.deadline = std::min(ctx.deadline, std::chrono::steady_clock::now() + std::chrono::milliseconds(ms));
    o.cancelled = ctx.cancelled;
    if (req.has_until()) o.until = req.until().offset();
    switch (req.mode()) {
      case pb::EMULATOR_RUN_MODE_STEP_INTO: stop = e.step(); break;
      case pb::EMULATOR_RUN_MODE_STEP_OVER: stop = e.step_over(o); break;
      case pb::EMULATOR_RUN_MODE_STEP_OUT: stop = e.step_out(o); break;
      default: stop = e.run(o); break;
    }
    if (stop.kind == emu::StopKind::step_limit && e.steps() >= s->limits.max_total_steps()) s->session_limit = true;
  }
  FillStop(stop, resp.mutable_stop());
  if (s->session_limit) resp.mutable_stop()->set_kind(pb::EMULATOR_STOP_KIND_SESSION_LIMIT);
  FillState(*s, req.state(), resp.mutable_state());
  return Status::Ok();
}

Status EmulatorSessions::GetState(const api::CallContext &ctx, const pb::GetEmulatorStateRequest &req, pb::GetEmulatorStateResponse &resp) {
  std::shared_ptr<Session> s;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), s, lock); !st.ok()) return st;
  FillState(*s, req.state(), resp.mutable_state());
  return Status::Ok();
}

Status EmulatorSessions::WriteRegisters(const api::CallContext &ctx, const pb::WriteEmulatorRegistersRequest &req,
                                        pb::WriteEmulatorRegistersResponse &resp) {
  std::shared_ptr<Session> s;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), s, lock); !st.ok()) return st;
  if (auto st = backend::WriteRegisters(*s->emu, req.registers()); !st.ok()) return st;
  FillState(*s, req.state(), resp.mutable_state());
  return Status::Ok();
}

Status EmulatorSessions::ReadMemory(const api::CallContext &ctx, const pb::ReadEmulatorMemoryRequest &req, pb::ReadEmulatorMemoryResponse &resp) {
  if (req.length() > (1u << 20)) return Error(StatusCode::kInvalidArgument, "length exceeds 1 MiB");
  if (!DefaultSpace(req.address())) return Error(StatusCode::kInvalidArgument, "only the default space is readable");
  std::shared_ptr<Session> s;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), s, lock); !st.ok()) return st;
  emu::Emulator &e = *s->emu;
  const std::uint64_t start = req.address().offset();
  std::string data(req.length(), '\0');
  // Mapped runs, from the regions; the rest stays zero and is reported.
  std::uint32_t at = 0;
  const auto regions = e.regions();
  while (at < req.length()) {
    const std::uint64_t addr = start + at;
    const emu::RegionInfo *r = nullptr;
    for (const emu::RegionInfo &x : regions)
      if (addr >= x.start && addr - x.start < x.size) r = &x;
    std::uint32_t n = 0;
    if (r != nullptr) {
      n = static_cast<std::uint32_t>(std::min<std::uint64_t>(req.length() - at, r->start + r->size - addr));
      if (n == 0) n = req.length() - at;  // a region reaching the top of the space
      e.read_memory(addr, std::span<std::uint8_t>(reinterpret_cast<std::uint8_t *>(data.data() + at), n));
    } else {
      // Up to the next region.
      std::uint64_t next = ~std::uint64_t{0};
      for (const emu::RegionInfo &x : regions)
        if (x.start > addr) next = std::min(next, x.start);
      n = static_cast<std::uint32_t>(std::min<std::uint64_t>(req.length() - at, next - addr));
      pb::EmulatorByteRange *u = resp.add_unmapped();
      u->set_offset(at);
      u->set_length(n);
    }
    at += n;
  }
  *resp.mutable_address() = req.address();
  resp.set_data(std::move(data));
  return Status::Ok();
}

Status EmulatorSessions::WriteMemory(const api::CallContext &ctx, const pb::WriteEmulatorMemoryRequest &req, pb::WriteEmulatorMemoryResponse &) {
  std::shared_ptr<Session> s;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), s, lock); !st.ok()) return st;
  return backend::WriteMemory(*s->emu, req.address(), req.data());
}

Status EmulatorSessions::SetBreakpoints(const api::CallContext &ctx, const pb::SetEmulatorBreakpointsRequest &req,
                                        pb::SetEmulatorBreakpointsResponse &resp) {
  std::shared_ptr<Session> s;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), s, lock); !st.ok()) return st;
  emu::Emulator &e = *s->emu;
  if (req.clear()) e.clear_breakpoints();
  for (const pb::Address &a : req.remove()) e.remove_breakpoint(a.offset());
  for (const pb::Address &a : req.add()) {
    if (!DefaultSpace(a)) return Error(StatusCode::kInvalidArgument, "breakpoints are in the default space");
    e.add_breakpoint(a.offset());
  }
  for (std::uint64_t b : e.breakpoints()) resp.add_breakpoints()->set_offset(b);
  if (req.set_exception_breaks()) {
    emu::Machine *m = e.machine();
    if (!m) return Error(StatusCode::kFailedPrecondition, "exception breakpoints need a machine (CreateEmulatorSessionRequest.machine)");
    m->set_break_on({req.exception_breaks().begin(), req.exception_breaks().end()});
  }
  if (const emu::Machine *m = e.machine())
    for (const std::string &k : m->break_on()) resp.add_exception_breaks(k);
  return Status::Ok();
}

Status EmulatorSessions::GetTrace(const api::CallContext &ctx, const pb::GetEmulatorTraceRequest &req, pb::GetEmulatorTraceResponse &resp) {
  std::shared_ptr<Session> s;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), s, lock); !st.ok()) return st;
  emu::Emulator &e = *s->emu;
  const emu::TraceSummary &t = e.trace().summary();
  pb::EmulatorTraceSummary *sum = resp.mutable_summary();
  sum->set_steps(t.steps);
  sum->set_recorded(t.recorded);
  sum->set_dropped(t.dropped);
  sum->set_unique_pcs(t.unique_pcs);
  sum->set_memory_reads(t.memory_reads);
  sum->set_memory_writes(t.memory_writes);
  sum->set_mmio_reads(t.mmio_reads);
  sum->set_mmio_writes(t.mmio_writes);
  sum->set_syscalls(t.syscalls);
  sum->set_stub_calls(t.stub_calls);
  sum->set_userops(t.userops);
  sum->set_exceptions(t.exceptions);
  if (req.json()) {
    resp.set_json(emu::trace_json(e));
    return Status::Ok();
  }
  const std::size_t limit = req.limit() == 0 ? 1000 : std::min<std::uint32_t>(req.limit(), 10000);
  for (const emu::TraceEntry &x : e.trace().since(req.from_index(), limit)) {
    pb::EmulatorTraceEntry *pe = resp.add_entries();
    pe->set_index(x.index);
    pe->mutable_pc()->set_offset(x.pc);
    pe->set_thumb(x.thumb);
    pe->set_bytes(std::string(x.bytes.begin(), x.bytes.end()));
    pe->set_text(x.text);
    for (const emu::RegisterWrite &w : x.registers) {
      pb::EmulatorRegisterValue *v = pe->add_registers();
      v->set_name(w.name);
      v->set_size(static_cast<std::uint32_t>(w.value.size()));
      std::uint64_t lo = 0;
      for (std::size_t i = 0; i < w.value.size() && i < 8; ++i) lo |= std::uint64_t{w.value[i]} << (8 * i);
      v->set_value(lo);
      v->set_bytes(std::string(w.value.begin(), w.value.end()));
    }
    auto access = [](const emu::MemoryAccess &a, pb::EmulatorMemoryAccess *m) {
      m->mutable_address()->set_offset(a.address);
      m->mutable_address()->set_space(a.space);
      m->set_data(std::string(a.bytes.begin(), a.bytes.end()));
      m->set_mmio(a.mmio);
    };
    for (const emu::MemoryAccess &a : x.reads) access(a, pe->add_reads());
    for (const emu::MemoryAccess &a : x.writes) access(a, pe->add_writes());
    pe->set_event(x.event);
    pe->set_exception(x.exception);
    pe->set_exception_number(x.exception.empty() ? -1 : x.exception_number);
  }
  return Status::Ok();
}

Status EmulatorSessions::WriteInput(const api::CallContext &ctx, const pb::WriteEmulatorInputRequest &req) {
  if (req.data().size() > (1u << 20)) return Error(StatusCode::kInvalidArgument, "input is at most 1 MiB per call");
  std::shared_ptr<Session> s;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), s, lock); !st.ok()) return st;
  emu::Machine *m = s->emu->machine();
  if (!m) return Error(StatusCode::kFailedPrecondition, "the session has no machine to take input");
  if (!m->input(req.peripheral(), req.data()))
    return Error(StatusCode::kNotFound, req.peripheral().empty() ? "the machine has no UART for console input"
                                                                 : "the machine has no peripheral " + req.peripheral());
  return Status::Ok();
}

Status EmulatorSessions::GetMachine(const api::CallContext &ctx, const pb::GetEmulatorMachineRequest &req,
                                    pb::GetEmulatorMachineResponse &resp) {
  std::shared_ptr<Session> s;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), s, lock); !st.ok()) return st;
  const emu::Machine *m = s->emu->machine();
  if (!m) return Error(StatusCode::kFailedPrecondition, "the session has no machine");
  FillMachineState(*s->emu, resp.mutable_state());
  std::uint64_t first = 0, count = 0;
  FillMachineEvents(*m, req.from_event(), req.limit(), resp.mutable_events(), first, count);
  resp.set_first_event(first);
  resp.set_event_count(count);
  return Status::Ok();
}

namespace {

void FillDevice(const emu::MachineState::Device &d, pb::EmulatorDevice *out) {
  out->set_name(d.name);
  out->set_kind(d.kind);
  out->set_base(d.base);
  out->set_size(d.size);
  out->set_state(d.state);
  if (d.next_tick) out->set_next_tick(*d.next_tick);
}

}  // namespace

void FillMachineInfo(const emu::Machine &m, pb::EmulatorMachineInfo *out) {
  out->set_name(m.spec().name);
  out->set_cpu(m.cpu_model());
  out->set_hz(m.spec().clock.hz);
  out->set_wall_clock(m.spec().clock.wall);
  for (const auto &d : m.state().devices) FillDevice(d, out->add_devices());
}

void FillMachineState(const emu::Emulator &e, pb::EmulatorMachineState *out) {
  const emu::Machine *m = e.machine();
  if (!m) return;
  const emu::MachineState s = m->state();
  out->set_cpu(s.cpu);
  out->set_mode(s.mode);
  out->set_tick(s.tick);
  out->set_hz(s.hz);
  out->set_waiting(s.waiting);
  out->set_exceptions_taken(s.interrupts);
  for (const auto &[name, value] : s.registers) {
    pb::EmulatorRegisterValue *r = out->add_registers();
    r->set_name(name);
    r->set_size(4);
    r->set_value(value);
    std::string bytes(8, '\0');
    for (int i = 0; i < 8; ++i) bytes[static_cast<std::size_t>(i)] = static_cast<char>(value >> (8 * i));
    bytes.resize(value > 0xffffffffu ? 8 : 4);
    r->set_size(static_cast<std::uint32_t>(bytes.size()));
    r->set_bytes(bytes);
  }
  for (const auto &d : s.devices) FillDevice(d, out->add_devices());
  for (const std::string &p : s.pending) out->add_pending(p);
  for (const std::string &l : s.log) out->add_log(l);
  for (const std::string &b : m->break_on()) out->add_exception_breaks(b);
}

void FillMachineEvents(const emu::Machine &m, std::uint64_t from, std::uint32_t limit,
                       google::protobuf::RepeatedPtrField<pb::EmulatorException> *out, std::uint64_t &first,
                       std::uint64_t &count) {
  const auto &events = m.events();
  count = m.event_count();
  first = count - events.size();
  const std::uint32_t n = limit == 0 ? 1000 : std::min<std::uint32_t>(limit, 10000);
  for (std::uint64_t i = std::max(from, first); i < count && static_cast<std::uint32_t>(out->size()) < n; ++i) {
    const emu::ExceptionEvent &ev = events[static_cast<std::size_t>(i - first)];
    pb::EmulatorException *x = out->Add();
    x->set_step(ev.step);
    x->set_tick(ev.tick);
    x->set_kind(ev.kind);
    x->set_number(ev.number);
    x->mutable_pc()->set_offset(ev.pc);
    x->mutable_handler()->set_offset(ev.handler);
    x->set_source(ev.source);
    x->set_detail(ev.detail);
  }
}

}  // namespace revkit::backend
