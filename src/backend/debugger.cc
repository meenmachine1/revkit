#include "debugger.h"

#include "open_beneath.h"

#include "revkit/debug/crash_target.hh"
#include "revkit/debug/emu_target.hh"
#include "revkit/debug/expr.hh"
#include "revkit/debug/gdb_remote.hh"
#include "revkit/debug/trace_target.hh"
#include "revkit/lift/lifter.hh"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <random>
#include <set>
#include <sstream>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace revkit::backend {

using api::Error;
using api::Status;
using api::StatusCode;
namespace fs = std::filesystem;

struct DebugSessions::Entry {
  std::string id, client;
  std::string owner;  // CallContext.caller of Create ("anonymous" without authentication)
  DebugProgram program;
  std::unique_ptr<debug::Session> session;
  bool emulator = false;
  pb::EmulatorLimits emu_limits;
  pb::DebugTimelineLimits limits;
  fs::path launch_dir;  // the program's copy a launch ran; removed at close
  std::mutex mu;        // one call at a time
  std::chrono::steady_clock::time_point last_used = std::chrono::steady_clock::now();
  // Breakpoint conditions, parsed once (docs/debugger.md "Breakpoints").
  std::map<std::string, std::shared_ptr<const debug::expr::Expression>> conditions;
  // Runtime modules that are other project programs, by module name
  // (DebugProgram::library); null: the module is none.
  std::map<std::string, std::shared_ptr<const DebugProgram>> libraries;
  // Their call-frame information, read once each, by program id.
  std::map<std::string, std::shared_ptr<const debug::CfiTable>> library_cfi;
  // A crash dump target (api_minor 102): the target, and its modules that
  // are files under --browse-root rather than project programs, loaded once
  // each by path (null: not found or not loadable).
  debug::CrashTarget *crash = nullptr;
  struct HostModule {
    std::shared_ptr<const loader::Image> image;
    std::int64_t slide = 0;
    std::shared_ptr<const debug::CfiTable> cfi;
    struct Function {
      std::uint64_t start = 0, size = 0;  // static; size 0: unknown
      std::string name;
      bool operator<(const Function &o) const { return start < o.start; }
    };
    std::vector<Function> functions;  // sorted by start
  };
  std::map<std::string, std::shared_ptr<const HostModule>> host_modules;
  // Hooks the client answers (SetDebugHooks; docs/debugger.md "Hooks").
  struct Hook {
    int id = 0;
    pb::DebugHookSpec spec;
    std::uint64_t address = 0;  // FUNCTION: the entry; MMIO: the first byte (runtime)
    std::uint64_t size = 1;     // MMIO
    std::uint64_t hits = 0;
  };
  std::vector<Hook> hooks;
  int next_hook = 1;
  bool hooks_installed = false;
  emu::Emulator::SyscallHandler base_syscall;
  emu::Emulator::MmioHandler base_mmio;
  // The hook that stopped the last run, waiting for its answer.
  std::optional<pb::DebugHookEvent> hook_hit;
  // An answer to apply when its hook triggers again (the instruction runs again).
  struct Answer {
    int hook = 0;
    bool proceed = true;
    std::uint64_t value = 0;
  };
  std::optional<Answer> answer;
  ~Entry() {
    session.reset();
    if (!launch_dir.empty()) {
      std::error_code ec;
      fs::remove_all(launch_dir, ec);
    }
  }
};

namespace {

bool SameName(std::string_view a, std::string_view b);  // case-insensitive (below)

// A backtrace's frames as the API gives them (GetDebugBacktrace, the crash
// summary), and a crash dump session's summary (below).
void FillFrames(DebugSessions::Entry &e, const std::vector<debug::Frame> &frames,
                google::protobuf::RepeatedPtrField<pb::DebugFrame> *out);
void FillCrash(DebugSessions::Entry &e, std::uint32_t max_frames, pb::DebugCrash *out);

// Defined with the evaluation, below: a condition at a stop (true: stop;
// an error stops too), and a condition's parse error ("" when it parses).
bool CheckCondition(DebugSessions::Entry &e, const DebugEvalEnv &env, const std::string &text, std::string &error);
std::string ConditionError(debug::Session &s, const DebugEvalEnv &env, const std::string &text);

// A spec's condition, ignore count and enabled state onto its breakpoint.
void ApplySpec(debug::Session &s, const debug::Breakpoint &b, const pb::DebugBreakpointSpec &spec) {
  if (!spec.condition().empty() || spec.ignore_count() != 0 || spec.disabled())
    s.update_breakpoint(b.id, spec.condition(), spec.ignore_count(), spec.disabled());
}

// Lets the session's runs pass over breakpoints by their conditions, for one call.
struct ConditionScope {
  debug::Session &s;
  ConditionScope(debug::Session &session, DebugSessions::Entry &e, const DebugEvalEnv *env) : s(session) {
    if (env)
      s.set_condition_check([&e, env](const debug::Breakpoint &b, std::string &error) { return CheckCondition(e, *env, b.condition, error); });
  }
  ~ConditionScope() { s.set_condition_check(nullptr); }
};

std::string NewId() {
  static std::mutex mu;
  static std::random_device rd;
  std::lock_guard lock(mu);
  std::ostringstream o;
  o << "dbg-" << std::hex;
  for (int i = 0; i < 4; ++i) o << std::uniform_int_distribution<std::uint32_t>()(rd);
  return o.str();
}

template <typename T>
T Pick(T asked, T def, T cap) {
  return std::min(asked == 0 ? def : asked, cap);
}

pb::DebugStopKind ToPb(debug::StopKind k) {
  const auto i = static_cast<int>(k);
  // NONE..CANCELLED are 1..20; SESSION_LIMIT (21) is the backend's own;
  // SIGNAL.. follow from 22.
  if (k <= debug::StopKind::cancelled) return static_cast<pb::DebugStopKind>(i + 1);
  return static_cast<pb::DebugStopKind>(i + 2);
}

pb::DebugTargetState ToPb(debug::TargetState s) {
  switch (s) {
    case debug::TargetState::stopped: return pb::DEBUG_TARGET_STATE_STOPPED;
    case debug::TargetState::running: return pb::DEBUG_TARGET_STATE_RUNNING;
    case debug::TargetState::exited: return pb::DEBUG_TARGET_STATE_EXITED;
    case debug::TargetState::detached: return pb::DEBUG_TARGET_STATE_DETACHED;
    case debug::TargetState::disconnected: return pb::DEBUG_TARGET_STATE_DISCONNECTED;
    case debug::TargetState::replay: return pb::DEBUG_TARGET_STATE_REPLAY;
  }
  return pb::DEBUG_TARGET_STATE_UNSPECIFIED;
}

debug::BreakKind FromPb(pb::DebugBreakpointKind k) {
  switch (k) {
    case pb::DEBUG_BREAKPOINT_KIND_HARDWARE: return debug::BreakKind::hardware;
    case pb::DEBUG_BREAKPOINT_KIND_WATCH_WRITE: return debug::BreakKind::watch_write;
    case pb::DEBUG_BREAKPOINT_KIND_WATCH_READ: return debug::BreakKind::watch_read;
    case pb::DEBUG_BREAKPOINT_KIND_WATCH_ACCESS: return debug::BreakKind::watch_access;
    default: return debug::BreakKind::software;
  }
}

pb::DebugBreakpointKind ToPb(debug::BreakKind k) {
  switch (k) {
    case debug::BreakKind::software: return pb::DEBUG_BREAKPOINT_KIND_SOFTWARE;
    case debug::BreakKind::hardware: return pb::DEBUG_BREAKPOINT_KIND_HARDWARE;
    case debug::BreakKind::watch_write: return pb::DEBUG_BREAKPOINT_KIND_WATCH_WRITE;
    case debug::BreakKind::watch_read: return pb::DEBUG_BREAKPOINT_KIND_WATCH_READ;
    case debug::BreakKind::watch_access: return pb::DEBUG_BREAKPOINT_KIND_WATCH_ACCESS;
  }
  return pb::DEBUG_BREAKPOINT_KIND_UNSPECIFIED;
}

pb::DebugSnapshotKind ToPb(debug::Snapshot::Kind k) {
  switch (k) {
    case debug::Snapshot::Kind::stop: return pb::DEBUG_SNAPSHOT_KIND_STOP;
    case debug::Snapshot::Kind::step: return pb::DEBUG_SNAPSHOT_KIND_STEP;
    case debug::Snapshot::Kind::edit: return pb::DEBUG_SNAPSHOT_KIND_EDIT;
  }
  return pb::DEBUG_SNAPSHOT_KIND_UNSPECIFIED;
}

std::string ProgramName(const std::string &program_id) { return program_id.substr(program_id.find('/') + 1); }

bool ValidTraceName(const std::string &n) {
  if (n.empty() || n.size() > 64 || n[0] == '.') return false;
  return std::all_of(n.begin(), n.end(), [](char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-';
  });
}

// The runtime address a request names.
Status Runtime(debug::Session &s, const pb::DebugAddress &a, std::uint64_t &out) {
  if (!a.program()) {
    out = a.offset();
    return Status::Ok();
  }
  if (!s.mapping().known)
    return Error(StatusCode::kFailedPrecondition,
                 "the program isn't mapped in the target yet (" + s.mapping().how + "): give a runtime address or a slide");
  out = s.to_runtime(a.offset());
  return Status::Ok();
}

void FillLocation(debug::Session &s, std::uint64_t runtime, const std::string &program_id, pb::DebugLocation *out) {
  out->mutable_address()->set_offset(runtime);
  if (auto p = s.to_program(runtime)) {
    out->mutable_program_address()->set_offset(*p);
    out->set_module(ProgramName(program_id));
    const loader::Image *img = s.options().image.get();
    if (img != nullptr) out->set_module_offset(*p - img->image_base);
    return;
  }
  if (s.target().state() != debug::TargetState::stopped) return;
  try {
    if (auto m = s.module_at(runtime)) {
      out->set_module(m->first.name);
      out->set_module_offset(m->second);
    }
  } catch (const debug::DebugError &) {
  }
}

// A runtime address in a module that is another project program: that
// program, the address in its image and the function there.
struct LibraryHit {
  std::shared_ptr<const DebugProgram> program;
  std::int64_t slide = 0;
  std::uint64_t address = 0;  // in the library's image
  std::optional<std::pair<std::uint64_t, std::string>> function;
};

// The project program a module is (cached per session), with its slide.
std::shared_ptr<const DebugProgram> LibraryOf(DebugSessions::Entry &e, const debug::ModuleInfo &m, std::int64_t &slide) {
  if (m.main || m.name.empty() || m.name == ProgramName(e.program.program_id) || !e.program.library) return nullptr;
  auto it = e.libraries.find(m.name);
  if (it == e.libraries.end()) {
    std::shared_ptr<const DebugProgram> lib;
    try {
      if (auto dp = e.program.library(m.name); dp && dp->program) lib = std::make_shared<const DebugProgram>(std::move(*dp));
    } catch (const std::exception &) {
    }
    it = e.libraries.emplace(m.name, std::move(lib)).first;
  }
  if (!it->second) return nullptr;
  const loader::Image &img = it->second->program->image();
  // As the session maps its own program (session.cc): an ELF shared object
  // moves by its link map's l_addr; a PE by where its image starts.
  slide = img.format == loader::Format::pe
              ? static_cast<std::int64_t>(m.base - img.image_base)
              : static_cast<std::int64_t>(m.load_bias - (img.image_base - img.file_base));
  return it->second;
}

std::optional<LibraryHit> LibraryAt(DebugSessions::Entry &e, std::uint64_t runtime) {
  debug::Session &s = *e.session;
  if (!e.program.library || s.to_program(runtime) || s.target().state() != debug::TargetState::stopped) return std::nullopt;
  std::optional<std::pair<debug::ModuleInfo, std::uint64_t>> m;
  try {
    m = s.module_at(runtime);
  } catch (const debug::DebugError &) {
    return std::nullopt;
  }
  if (!m) return std::nullopt;
  LibraryHit hit;
  hit.program = LibraryOf(e, m->first, hit.slide);
  if (!hit.program) return std::nullopt;
  hit.address = runtime - static_cast<std::uint64_t>(hit.slide);
  if (!hit.program->program->image().memory.find(hit.address)) return std::nullopt;
  if (hit.program->function_at) hit.function = hit.program->function_at(hit.address);
  return hit;
}

// A crash dump's module that is no project program, from its file under
// --browse-root (an admin's session only): its image, slide, CFI and
// function symbols. The address in its image, when it is one.
struct HostHit {
  std::shared_ptr<const DebugSessions::Entry::HostModule> module;
  std::uint64_t address = 0;
  std::optional<std::pair<std::uint64_t, std::string>> function;
};

std::shared_ptr<const DebugSessions::Entry::HostModule> LoadHostModule(const DebugSessions::Entry &e, const debug::ModuleInfo &m) {
  if (!e.program.crash || e.program.crash->host_roots.empty() || m.path.empty() || m.path.front() != '/') return nullptr;
  const fs::path want = fs::path(m.path).lexically_normal();
  for (const std::string &r : e.program.crash->host_roots) {
    std::error_code ec;
    const fs::path root = fs::canonical(r, ec);
    if (ec) continue;
    const fs::path rel = want.lexically_relative(root);
    if (rel.empty() || rel.native().starts_with("..")) continue;
    // O_NONBLOCK: a FIFO at the path a dump names doesn't block the
    // session; it isn't a regular file, so it is refused below.
    const int fd = OpenBeneath(root, rel, O_RDONLY | O_NONBLOCK);
    if (fd < 0) continue;
    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > (512ll << 20)) {
      ::close(fd);
      continue;
    }
    auto bytes = std::make_shared<loader::Bytes>(static_cast<std::size_t>(st.st_size));
    std::size_t got = 0;
    while (got < bytes->size()) {
      const ssize_t n = ::pread(fd, bytes->data() + got, bytes->size() - got, static_cast<off_t>(got));
      if (n <= 0) break;
      got += static_cast<std::size_t>(n);
    }
    ::close(fd);
    if (got != bytes->size()) continue;
    try {
      auto img = std::make_shared<const loader::Image>(loader::parse(bytes));
      auto out = std::make_shared<DebugSessions::Entry::HostModule>();
      out->slide = img->format == loader::Format::pe ? static_cast<std::int64_t>(m.base - img->image_base)
                                                     : static_cast<std::int64_t>(m.load_bias - (img->image_base - img->file_base));
      out->cfi = debug::CfiTable::from_image(*img);
      for (const loader::Symbol &s : img->symbols)
        if (s.defined && s.type == loader::SymbolType::func && s.value != 0 && !s.name.empty())
          out->functions.push_back({s.value, s.size, s.name});
      std::sort(out->functions.begin(), out->functions.end());
      out->image = std::move(img);
      return out;
    } catch (const std::exception &) {
    }
  }
  return nullptr;
}

std::optional<HostHit> HostModuleAt(DebugSessions::Entry &e, std::uint64_t runtime) {
  if (e.crash == nullptr) return std::nullopt;
  debug::Session &s = *e.session;
  if (s.to_program(runtime)) return std::nullopt;
  std::optional<std::pair<debug::ModuleInfo, std::uint64_t>> m;
  try {
    m = s.module_at(runtime);
  } catch (const debug::DebugError &) {
    return std::nullopt;
  }
  if (!m || m->first.main) return std::nullopt;
  std::int64_t slide = 0;
  if (LibraryOf(e, m->first, slide)) return std::nullopt;  // a project program: LibraryAt's
  auto it = e.host_modules.find(m->first.path);
  if (it == e.host_modules.end()) it = e.host_modules.emplace(m->first.path, LoadHostModule(e, m->first)).first;
  if (!it->second) return std::nullopt;
  HostHit h;
  h.module = it->second;
  h.address = runtime - static_cast<std::uint64_t>(h.module->slide);
  if (!h.module->image->memory.find(h.address)) return std::nullopt;
  const auto &fns = h.module->functions;
  auto f = std::upper_bound(fns.begin(), fns.end(), h.address,
                            [](std::uint64_t a, const DebugSessions::Entry::HostModule::Function &x) { return a < x.start; });
  // The symbol that covers it (an internal function between two exported
  // ones is no symbol's: the module and offset name it then).
  if (f != fns.begin()) {
    --f;
    if (f->size != 0 ? h.address - f->start < f->size : h.address - f->start < 0x1000) h.function = std::make_pair(f->start, f->name);
  }
  return h;
}

// Bytes a crash dump doesn't hold, from the session's program, a library
// program, or a host module's file: as many from the start of `out` as one
// of them maps contiguously.
std::size_t CrashBacking(DebugSessions::Entry &e, std::uint64_t runtime, std::span<std::uint8_t> out) {
  auto from = [&](const loader::Image &img, std::uint64_t at) -> std::size_t {
    std::size_t done = 0;
    while (done < out.size()) {
      const loader::Region *r = img.memory.find(at + done);
      if (r == nullptr) break;
      const std::uint64_t left = r->start + r->size - (at + done);
      const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(left, out.size() - done));
      img.memory.read(at + done, std::as_writable_bytes(out.subspan(done, n)));
      done += n;
    }
    return done;
  };
  debug::Session &s = *e.session;
  if (auto p = s.to_program(runtime)) return from(e.program.program->image(), *p);
  if (auto h = LibraryAt(e, runtime)) return from(h->program->program->image(), h->address);
  if (auto h = HostModuleAt(e, runtime)) return from(*h->module->image, h->address);
  return 0;
}

// Unwinding through libraries that are project programs: their own CFI
// (.eh_frame, .debug_frame; read once per session) and function entries,
// by the library's image.
void LibraryUnwinding(DebugSessions::Entry &e, debug::Session::BacktraceOptions &o) {
  if (!e.program.library && e.crash == nullptr) return;
  o.library_cfi = [&e](std::uint64_t runtime) -> std::optional<debug::CfiRow> {
    auto h = LibraryAt(e, runtime);
    if (!h) {
      // A crash dump's module from its file on the host.
      if (auto m = HostModuleAt(e, runtime)) return m->module->cfi->row_at(m->address);
      return std::nullopt;
    }
    auto &t = e.library_cfi[h->program->program_id];
    if (!t) t = debug::CfiTable::from_image(h->program->program->image());
    return t->row_at(h->address);
  };
  o.library_entry = [&e](std::uint64_t runtime) {
    auto h = LibraryAt(e, runtime);
    if (!h) {
      auto m = HostModuleAt(e, runtime);
      return m && m->function && m->function->first == m->address;
    }
    return h && h->function && h->function->first == h->address;
  };
}

std::string HitText(const LibraryHit &h, std::uint64_t at) {
  if (!h.function) return {};
  const std::uint64_t off = at - h.function->first;
  char buf[24];
  std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(off));
  return off ? h.function->second + "+0x" + buf : h.function->second;
}

// FillLocation, with a library module's program, address and function.
void FillLocation(DebugSessions::Entry &e, std::uint64_t runtime, pb::DebugLocation *out) {
  FillLocation(*e.session, runtime, e.program.program_id, out);
  if (out->has_program_address()) return;
  if (auto h = LibraryAt(e, runtime)) {
    out->set_library_program_id(h->program->program_id);
    out->mutable_library_address()->set_offset(h->address);
    out->set_library_function(HitText(*h, h->address));
  }
}

void FillStop(debug::Session &s, const debug::Stop &st, const std::string &program_id, pb::DebugStop *out) {
  out->set_kind(ToPb(st.kind));
  FillLocation(s, st.pc, program_id, out->mutable_pc());
  if (st.address) out->mutable_address()->set_offset(*st.address);
  out->set_detail(st.detail);
  out->set_exit_code(st.exit_code);
  out->set_steps(st.steps);
  out->set_signal(st.signal);
  out->set_thread(st.thread);
}

// FillStop, with a library module's program for the pc.
void FillStop(DebugSessions::Entry &e, const debug::Stop &st, pb::DebugStop *out) {
  FillStop(*e.session, st, e.program.program_id, out);
  if (!out->pc().has_program_address()) FillLocation(e, st.pc, out->mutable_pc());
}

void FillBreakpoint(debug::Session &s, const debug::Breakpoint &b, const std::string &program_id, pb::DebugBreakpoint *out) {
  out->set_id(b.id);
  out->set_kind(ToPb(b.kind));
  if (b.pending) {
    if (b.program_address) out->mutable_location()->mutable_program_address()->set_offset(*b.program_address);
  } else {
    FillLocation(s, b.address, program_id, out->mutable_location());
    if (b.program_address && !out->location().has_program_address())
      out->mutable_location()->mutable_program_address()->set_offset(*b.program_address);
  }
  out->set_size(b.size);
  out->set_inserted(b.inserted);
  out->set_pending(b.pending);
  out->set_error(b.error);
  out->set_hits(b.hits);
  out->set_condition(b.condition);
  out->set_ignore_count(b.ignore_count);
  out->set_disabled(b.disabled);
  out->set_condition_error(b.condition_error);
}

void FillValue(const std::string &name, const std::vector<std::uint8_t> &v, bool changed, pb::DebugRegisterValue *out) {
  out->set_name(name);
  out->set_size(static_cast<std::uint32_t>(v.size()));
  out->set_value(debug::to_u64(v));
  out->set_bytes(std::string(v.begin(), v.end()));
  out->set_changed(changed);
}

std::vector<pb::DebugByteRange> Ranges(const std::vector<bool> &mark) {
  std::vector<pb::DebugByteRange> out;
  for (std::size_t i = 0; i < mark.size(); ++i) {
    if (!mark[i]) continue;
    if (!out.empty() && out.back().offset() + out.back().length() == i) {
      out.back().set_length(out.back().length() + 1);
    } else {
      pb::DebugByteRange r;
      r.set_offset(static_cast<std::uint32_t>(i));
      r.set_length(1);
      out.push_back(r);
    }
  }
  return out;
}

Status FillState(DebugSessions::Entry &e, const pb::DebugStateOptions &o, std::optional<std::uint64_t> snapshot,
                 pb::DebugState *out) {
  debug::Session &s = *e.session;
  debug::Target &t = s.target();
  const debug::Timeline &tl = s.timeline();
  const std::uint64_t last = tl.last();
  const std::uint64_t snap = snapshot.value_or(last);
  const debug::Snapshot *at = tl.find(snap);
  if (at == nullptr)
    return Error(StatusCode::kOutOfRange, "snapshot " + std::to_string(snap) + " is not recorded (the timeline holds " +
                                              std::to_string(tl.first()) + " to " + std::to_string(last) + ")");
  const bool live = t.state() == debug::TargetState::stopped && snap == last;
  out->set_target_state(ToPb(t.state()));
  out->set_snapshot(snap);
  out->set_historical(snap != last);
  out->set_last_snapshot(last);
  const std::uint64_t pc = live ? t.pc() : at->pc;
  FillLocation(e, pc, out->mutable_pc());
  if (snap == last && t.state() != debug::TargetState::replay) {
    FillStop(e, s.last_stop(), out->mutable_last_stop());
  } else {
    debug::Stop st;
    st.kind = at->kind == debug::Snapshot::Kind::stop ? at->stop : debug::StopKind::stepped;
    st.pc = at->pc;
    st.detail = at->detail;
    st.thread = at->thread;
    FillStop(e, st, out->mutable_last_stop());
  }
  out->set_thread(live ? t.current_thread() : at->thread);
  out->set_steps(live ? t.steps() : at->steps);
  // Registers: now from the target, else as recorded.
  // Changed: since the previous stop (what a step or a run changed).
  const auto prev = tl.previous(snap);
  const auto changed_list = prev ? tl.changed_between(*prev, snap) : std::vector<std::string>{};
  const std::set<std::string> changed(changed_list.begin(), changed_list.end());
  std::vector<std::string> names;
  if (!o.registers().empty()) {
    for (const std::string &n : o.registers())
      if (const debug::RegisterDesc *d = t.find_register(n)) names.push_back(d->name);
  } else {
    for (const debug::RegisterDesc &d : t.registers())
      if (d.display || (o.all_registers() && d.size <= 64)) names.push_back(d.name);
  }
  std::map<std::string, std::vector<std::uint8_t>> recorded;
  if (!live) recorded = tl.registers_at(snap);
  for (const std::string &n : names) {
    std::vector<std::uint8_t> v;
    if (live) {
      try {
        v = t.read_register(n);
      } catch (const debug::DebugError &) {
        continue;
      }
    } else {
      auto it = recorded.find(n);
      if (it == recorded.end()) continue;
      v = it->second;
    }
    FillValue(n, v, changed.count(n) != 0, out->add_registers());
  }
  if (live) {
    out->set_thumb(t.thumb());
  } else if (auto it = recorded.find("TB"); it != recorded.end()) {
    out->set_thumb(debug::to_u64(it->second) != 0);
  }
  for (const debug::Breakpoint &b : s.breakpoints()) FillBreakpoint(s, b, e.program.program_id, out->add_breakpoints());
  // Output: offsets count every byte the program wrote; the last MiB is kept.
  constexpr std::uint64_t kMaxOutput = 64 << 10;
  const std::string &output = s.output();
  const std::uint64_t total = s.output_size(), kept_from = total - output.size();
  const std::uint64_t from = std::max<std::uint64_t>(o.output_offset(), kept_from);
  if (from < total) out->set_output(output.substr(static_cast<std::size_t>(from - kept_from), kMaxOutput));
  out->set_output_size(total);
  pb::DebugAddressMapping *m = out->mutable_mapping();
  if (auto *et = dynamic_cast<debug::EmulatorTarget *>(&t); et && live)
    if (const emu::Machine *mc = et->emulator().machine()) {
      out->set_machine(true);
      out->set_tick(mc->now());
      out->set_waiting(mc->state().waiting);
    }
  m->set_known(s.mapping().known);
  m->set_slide(s.mapping().slide);
  m->set_how(s.mapping().how);
  out->set_rewindable(s.can_rewind());
  if (o.include_threads() && t.state() == debug::TargetState::stopped) {
    try {
      for (const debug::ThreadInfo &ti : t.threads()) {
        pb::DebugThread *th = out->add_threads();
        th->set_id(ti.id);
        th->set_name(ti.name);
        th->set_current(ti.current);
        th->set_core(ti.core);
        if (ti.pc) FillLocation(e, *ti.pc, th->mutable_pc());
      }
    } catch (const debug::DebugError &) {
    }
  }
  return Status::Ok();
}

// Whether `ctx`'s caller may use a session `owner` made. Another caller's
// session reads as missing, so ids don't leak.
bool MayUse(const api::CallContext &ctx, const std::string &owner) { return ctx.caller_admin || ctx.caller == owner; }

Status DebugFailure(const debug::DebugError &e) { return Error(StatusCode::kFailedPrecondition, e.what()); }

void FillTraceInfo(const debug::TraceHeader &h, std::uint64_t snapshots, std::uint64_t bytes, bool persisted,
                   pb::DebugTraceInfo *out) {
  out->set_name(h.name);
  out->set_program_id(h.program_id);
  out->set_created_unix(h.created_unix);
  out->set_snapshots(snapshots);
  out->set_bytes(bytes);
  out->set_target_kind(h.target_kind);
  out->set_description(h.target_description);
  out->set_persisted(persisted);
}

}  // namespace

DebugSessions::DebugSessions(DebugBounds bounds) : bounds_(bounds) {}

DebugSessions::~DebugSessions() {
  // Running targets are stopped first so their sessions can close.
  std::lock_guard g(mu_);
  for (auto &[id, e] : sessions_) e->session->interrupt();
  sessions_.clear();
}

void DebugSessions::Reap() {
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

Status DebugSessions::Acquire(const api::CallContext &ctx, const std::string &id, std::shared_ptr<Entry> &out,
                              std::unique_lock<std::mutex> &lock) {
  {
    std::lock_guard g(mu_);
    auto it = sessions_.find(id);
    if (it == sessions_.end() || !MayUse(ctx, it->second->owner)) return Error(StatusCode::kNotFound, "no debug session " + id);
    out = it->second;
  }
  lock = std::unique_lock(out->mu);
  out->last_used = std::chrono::steady_clock::now();
  return Status::Ok();
}

Status DebugSessions::Create(const api::CallContext &ctx, const pb::CreateDebugSessionRequest &req, DebugProgram program,
                             pb::CreateDebugSessionResponse &resp) {
  const std::string client = req.client().empty() ? ctx.peer : req.client();
  {
    std::lock_guard g(mu_);
    Reap();
    if (sessions_.size() >= bounds_.sessions)
      return Error(StatusCode::kResourceExhausted,
                   "the server runs " + std::to_string(sessions_.size()) + " debug sessions, its most; close one");
    // Authenticated, the bound is per identity, whatever `client` says.
    const bool authed = ctx.caller != "anonymous";
    const auto mine = std::count_if(sessions_.begin(), sessions_.end(), [&](const auto &kv) {
      return authed ? kv.second->owner == ctx.caller : kv.second->client == client;
    });
    if (static_cast<unsigned>(mine) >= bounds_.sessions_per_client)
      return Error(StatusCode::kResourceExhausted, (authed ? ctx.caller : "client " + client) + " has " +
                                                       std::to_string(mine) + " debug sessions, its most; close one");
  }
  const bool live_target = req.target_case() == pb::CreateDebugSessionRequest::kRemote ||
                           req.target_case() == pb::CreateDebugSessionRequest::kLaunch;
  if (live_target && !bounds_.live)
    return Error(StatusCode::kPermissionDenied,
                 "live debugging is off on this daemon: start rk-daemon with --debug-live to debug processes and boards");

  auto e = std::make_shared<Entry>();
  e->id = NewId();
  e->client = client;
  e->owner = ctx.caller;
  e->program = std::move(program);
  const Program &prog = *e->program.program;
  const loader::Image &image = prog.image();

  const pb::DebugTimelineLimits &tl = req.timeline();
  e->limits.set_max_snapshots(static_cast<std::uint32_t>(
      Pick<std::size_t>(tl.max_snapshots(), bounds_.snapshots, bounds_.max_snapshots)));
  e->limits.set_max_bytes(Pick<std::uint64_t>(tl.max_bytes(), bounds_.timeline_bytes, bounds_.max_timeline_bytes));
  e->limits.set_stops_only(tl.stops_only());
  e->limits.set_stack_bytes(std::min<std::uint32_t>(tl.stack_bytes() == 0 ? 256 : tl.stack_bytes(), 1u << 16));

  debug::SessionOptions so;
  so.image = prog.image_ptr();
  so.program_name = ProgramName(e->program.program_id);
  so.language = prog.language().id();
  so.timeline = {e->limits.max_snapshots(), e->limits.max_bytes()};
  so.record_steps = !tl.stops_only();
  so.stack_bytes = e->limits.stack_bytes();
  if (req.has_slide()) so.slide = req.slide();
  so.function_entry = e->program.function_entry;

  const bool crash_target = req.target_case() == pb::CreateDebugSessionRequest::kCrash;
  std::vector<debug::SleighRegister> sleigh;
  if (live_target || crash_target) {
    auto lifter = prog.lifter();
    for (const lift::RegisterDef &r : lifter->registers()) sleigh.push_back({r.name, r.size});
  }
  auto remote_options = [&] {
    debug::GdbRemoteOptions o;
    o.language = prog.language().id();
    o.sleigh_registers = sleigh;
    o.pointer_size = image.bits / 8;
    o.big_endian = image.endian == loader::Endian::big;
    return o;
  };

  std::unique_ptr<debug::Target> target;
  debug::TraceTarget *trace_target = nullptr;
  try {
    switch (req.target_case()) {
      case pb::CreateDebugSessionRequest::kRemote: {
        const pb::DebugRemoteTarget &r = req.remote();
        if (r.address().empty()) return Error(StatusCode::kInvalidArgument, "remote.address is required (host:port)");
        const auto timeout = std::chrono::milliseconds(r.timeout_ms() == 0 ? 5000 : std::min(r.timeout_ms(), 60000u));
        auto transport = debug::connect_url(r.address(), timeout);
        debug::GdbRemoteOptions o = remote_options();
        o.timeout = timeout;
        o.description = "gdb remote " + r.address();
        if (r.attach_pid() != 0) o.attach_pid = r.attach_pid();
        target = std::make_unique<debug::GdbRemoteTarget>(std::move(transport), o);
        break;
      }
      case pb::CreateDebugSessionRequest::kLaunch: {
        const pb::DebugLaunchTarget &l = req.launch();
        if (image.format == loader::Format::raw && l.attach_pid() == 0)
          return Error(StatusCode::kInvalidArgument,
                       "a raw image has no operating system to launch it on: run it under qemu-system or on a board, "
                       "and connect to its gdbstub");
        debug::LaunchOptions lo;
        for (const std::string &a : l.arguments()) lo.args.push_back(a);
        for (const std::string &v : l.environment()) lo.env.push_back(v);
        lo.qemu = l.qemu();
        if (l.attach_pid() != 0) {
          lo.attach_pid = l.attach_pid();
        } else {
          // The program's own bytes, in a private directory.
          std::string tmpl = (fs::temp_directory_path() / "rk-launch-XXXXXX").string();
          if (::mkdtemp(tmpl.data()) == nullptr) return Error(StatusCode::kInternal, "mkdtemp failed");
          e->launch_dir = tmpl;
          lo.program = e->launch_dir / so.program_name;
          {
            std::ofstream f(lo.program, std::ios::binary);
            f.write(reinterpret_cast<const char *>(image.file->data()), static_cast<std::streamsize>(image.file->size()));
            if (!f) return Error(StatusCode::kInternal, "can't write the program to " + lo.program.string());
          }
          ::chmod(lo.program.c_str(), 0700);
          lo.working_dir = e->launch_dir;
        }
        debug::Launched launched = debug::launch(lo);
        debug::GdbRemoteOptions o = remote_options();
        o.child = launched.child;
        o.description = launched.description;
        if (l.attach_pid() != 0) o.attach_pid = std::nullopt;  // gdbserver --attach did it
        try {
          target = std::make_unique<debug::GdbRemoteTarget>(std::move(launched.transport), o);
        } catch (const debug::DebugError &err) {
          std::string out = launched.child ? launched.child->drain() : "";
          while (!out.empty() && (out.back() == '\n' || out.back() == ' ')) out.pop_back();
          std::string msg = std::string(err.what()) + (out.empty() ? "" : " (" + launched.description + ": " + out + ")");
          if (l.attach_pid() != 0 && !debug::attach_hint().empty()) msg += "; " + debug::attach_hint();
          return Error(StatusCode::kFailedPrecondition, msg);
        }
        break;
      }
      case pb::CreateDebugSessionRequest::kTrace: {
        auto data = LoadTrace(e->program, req.trace().name());
        if (!data) return Error(StatusCode::kNotFound, "no trace " + req.trace().name() + " for " + e->program.program_id);
        debug::TraceHeader h;
        debug::Timeline recorded = debug::Timeline::deserialize(*data, h);
        so.recorded = std::move(recorded);
        so.slide = h.slide;
        so.record_steps = true;
        auto t = std::make_unique<debug::TraceTarget>(h);
        trace_target = t.get();
        target = std::move(t);
        break;
      }
      case pb::CreateDebugSessionRequest::kCrash: {
        // A crash dump (docs/crash-dumps.md): its bytes resolved by the backend.
        const auto &src = e->program.crash;
        if (!src) return Error(StatusCode::kInvalidArgument, "crash: give a dump_program_id, host_path or upload_id");
        crash::CrashDump dump;
        try {
          dump = crash::parse(src->bytes);
        } catch (const crash::Error &err) {
          return Error(StatusCode::kInvalidArgument, src->name + ": " + err.what());
        }
        debug::CrashTargetOptions co;
        co.language = prog.language().id();
        co.sleigh_registers = sleigh;
        std::string who = dump.command.empty() ? (dump.modules.empty() ? src->name : dump.modules.front().name) : dump.command;
        for (const crash::Module &m : dump.modules)
          if (m.main) who = m.name;
        co.description = std::string(dump.format == crash::Format::elf_core ? "core" : "minidump") + " of " + who +
                         (dump.pid != 0 ? " (pid " + std::to_string(dump.pid) + ")" : "") + ": " + dump.reason;
        so.stack_bytes = std::max<std::uint32_t>(so.stack_bytes, 4096);
        so.record_steps = false;
        auto t = std::make_unique<debug::CrashTarget>(src->keep, src->bytes, std::move(dump), std::move(co));
        e->crash = t.get();
        target = std::move(t);
        break;
      }
      case pb::CreateDebugSessionRequest::kEmulator:
      case pb::CreateDebugSessionRequest::TARGET_NOT_SET: {
        const pb::DebugEmulatorTarget &em = req.emulator();
        if (!em.from_session().empty()) {
          // From another session's state (docs/debugger.md "Emulating from a stop").
          e->emu_limits = ResolveLimits(em.limits(), bounds_.emulator);
          std::unique_ptr<emu::Emulator> emulator;
          if (auto st = EmulatorFromSession(ctx, em, *e, so, emulator); !st.ok()) return st;
          target = std::make_unique<debug::EmulatorTarget>(std::move(emulator), so.program_name);
          e->emulator = true;
          break;
        }
        pb::CreateEmulatorSessionRequest er;
        er.set_program_id(e->program.program_id);
        if (em.has_entry()) *er.mutable_entry() = em.entry();
        er.set_mode(em.mode());
        *er.mutable_arguments() = em.arguments();
        *er.mutable_registers() = em.registers();
        *er.mutable_memory() = em.memory();
        er.set_import_return(em.import_return());
        er.set_no_library_stubs(em.no_library_stubs());
        er.set_stdin(em.stdin());
        er.set_machine(em.machine());
        er.set_machine_name(em.machine_name());
        e->emu_limits = ResolveLimits(em.limits(), bounds_.emulator);
        std::unique_ptr<emu::Emulator> emulator;
        if (auto st = BuildEmulator(er, e->program.program, e->emu_limits, emulator, e->program.patches, &machines_);
            !st.ok())
          return st;
        if (const emu::Machine *m = emulator->machine()) FillMachineInfo(*m, resp.mutable_machine());
        target = std::make_unique<debug::EmulatorTarget>(std::move(emulator), so.program_name);
        e->emulator = true;
        break;
      }
    }
    // A crash dump's missing bytes come from the programs it ran; set
    // before the session records its first stop (the code at the pc).
    if (e->crash != nullptr)
      e->crash->set_backing([ep = e.get()](std::uint64_t at, std::span<std::uint8_t> out) -> std::size_t {
        return ep->session ? CrashBacking(*ep, at, out) : 0;
      });
    e->session = std::make_unique<debug::Session>(std::move(target), std::move(so));
    if (trace_target != nullptr) trace_target->attach(&e->session->timeline());
  } catch (const debug::DebugError &err) {
    return Error(StatusCode::kFailedPrecondition, err.what());
  }
  debug::Session &s = *e->session;
  for (const pb::DebugBreakpointSpec &b : req.breakpoints()) {
    try {
      ApplySpec(s, s.add_breakpoint(FromPb(b.kind()), b.address().offset(), b.address().program(), b.size()), b);
    } catch (const debug::DebugError &err) {
      return Error(StatusCode::kInvalidArgument, err.what());
    }
  }
  resp.set_session_id(e->id);
  resp.set_target_kind(s.target().kind());
  resp.set_description(s.target().description());
  resp.set_language(s.options().language);
  for (const debug::RegisterDesc &r : s.target().registers()) {
    pb::DebugRegisterInfo *ri = resp.add_registers();
    ri->set_name(r.name);
    ri->set_target_name(r.target_name);
    ri->set_size(r.size);
    ri->set_display(r.display);
    ri->set_group(r.group);
    ri->set_sleigh(r.sleigh);
  }
  resp.set_pc_register(s.target().pc_register());
  resp.set_sp_register(s.target().sp_register());
  *resp.mutable_timeline() = e->limits;
  if (auto st = FillState(*e, {}, std::nullopt, resp.mutable_state()); !st.ok()) return st;
  if (e->crash != nullptr) FillCrash(*e, 64, resp.mutable_crash());
  std::lock_guard g(mu_);
  sessions_[e->id] = e;
  return Status::Ok();
}

// An emulator at another session's stop or recorded snapshot: its registers,
// its memory map, and its memory read lazily (a page when first touched,
// then copied on write). The source stays as it is.
Status DebugSessions::EmulatorFromSession(const api::CallContext &ctx, const pb::DebugEmulatorTarget &em, Entry &e,
                                          debug::SessionOptions &so, std::unique_ptr<emu::Emulator> &out) {
  std::shared_ptr<Entry> src;
  {
    std::lock_guard g(mu_);
    auto it = sessions_.find(em.from_session());
    if (it == sessions_.end() || !MayUse(ctx, it->second->owner)) return Error(StatusCode::kNotFound, "no debug session " + em.from_session());
    src = it->second;
  }
  if (src->program.program_id != e.program.program_id)
    return Error(StatusCode::kInvalidArgument, "session " + em.from_session() + " debugs another program");
  std::map<std::string, std::vector<std::uint8_t>> regs;
  std::vector<emu::RegionInfo> regions;
  std::optional<std::uint64_t> snap;
  bool thumb = false;
  {
    std::lock_guard lock(src->mu);
    debug::Session &s = *src->session;
    const std::uint64_t last = s.timeline().last();
    const bool stopped = s.target().state() == debug::TargetState::stopped;
    if (em.has_from_snapshot()) {
      if (s.timeline().find(em.from_snapshot()) == nullptr)
        return Error(StatusCode::kOutOfRange, "snapshot " + std::to_string(em.from_snapshot()) + " is not recorded");
      if (em.from_snapshot() != last || !stopped) snap = em.from_snapshot();
    } else if (!stopped) {
      if (s.target().state() == debug::TargetState::running)
        return Error(StatusCode::kFailedPrecondition, "the session's target is running: interrupt it, or give a snapshot");
      snap = last;  // gone (exited, a trace): as last recorded
    }
    try {
      if (snap) {
        regs = s.timeline().registers_at(*snap);
        if (auto it = regs.find("TB"); it != regs.end()) thumb = debug::to_u64(it->second) != 0;
      } else {
        for (const debug::RegisterDesc &d : s.target().registers()) {
          if (d.size > 64) continue;
          try {
            regs[d.name] = s.read_register(d.name);
          } catch (const debug::DebugError &) {
          }
        }
        thumb = s.target().thumb();
      }
      std::vector<debug::MapRegion> map;
      try {
        map = s.memory_map();
      } catch (const debug::DebugError &) {
      }
      for (const debug::MapRegion &r : map) {
        if (r.size == 0) continue;
        emu::RegionInfo ri;
        ri.name = r.name.empty() ? "region" : r.name;
        ri.start = r.start;
        ri.size = r.size;
        ri.perms = {r.perms.find('r') != std::string::npos, r.perms.find('w') != std::string::npos, r.perms.find('x') != std::string::npos};
        ri.kind = emu::RegionInfo::Kind::ram;
        regions.push_back(std::move(ri));
      }
    } catch (const debug::DebugError &err) {
      return DebugFailure(err);
    }
    so.slide = s.mapping().known ? std::optional<std::int64_t>(s.mapping().slide) : std::nullopt;
  }
  const unsigned bits = e.program.program->image().bits;
  // A recording: its memory map now (if any) isn't the one at the snapshot.
  if (snap) regions.clear();
  if (regions.empty()) {
    // No map (a recording): the whole space, read from the recording, else the image.
    emu::RegionInfo all;
    all.name = "process";
    all.start = 0x1000;
    all.size = (bits >= 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << bits) - 1) - 0xfff;
    all.perms = {true, true, true};
    all.kind = emu::RegionInfo::Kind::ram;
    regions.push_back(all);
  }
  // Overlapping entries (a map with duplicates) would be refused: keep the first.
  std::sort(regions.begin(), regions.end(), [](const auto &a, const auto &b) { return a.start < b.start; });
  std::vector<emu::RegionInfo> kept;
  for (auto &r : regions)
    if (kept.empty() || kept.back().start + kept.back().size <= r.start) kept.push_back(std::move(r));
  emu::Options o;
  o.language = e.program.program->language().id();
  o.max_memory = e.emu_limits.max_memory_bytes();
  o.trace_capacity = e.emu_limits.trace_capacity();
  o.import_return = em.import_return();
  o.stdin_data = em.stdin();
  emu::Options::Backing backing;
  backing.regions = std::move(kept);
  // Bytes the source doesn't have (code a recording never saw written) come
  // from the program's image, where the address is the program's.
  const std::shared_ptr<const Program> program = e.program.program;
  const std::int64_t slide = so.slide.value_or(0);
  backing.read = [src, snap, program, slide](std::uint64_t address, std::span<std::uint8_t> buf) -> std::size_t {
    std::vector<bool> known(buf.size(), false);
    {
      std::lock_guard lock(src->mu);
      if (src->session) {
        debug::Session &s = *src->session;
        try {
          if (snap) {
            std::vector<debug::Timeline::ByteState> state;
            s.memory_at(*snap, address, buf, state);
            for (std::size_t i = 0; i < state.size() && i < buf.size(); ++i)
              known[i] = state[i] != debug::Timeline::ByteState::unknown;
          } else if (s.target().state() == debug::TargetState::stopped) {
            std::vector<debug::ByteRange> holes;
            s.read_memory(address, buf, &holes);
            std::fill(known.begin(), known.end(), true);
            for (const debug::ByteRange &h : holes)
              for (std::uint32_t i = 0; i < h.length && h.offset + i < known.size(); ++i) known[h.offset + i] = false;
          }
        } catch (const debug::DebugError &) {
        }
      }
    }
    std::size_t n = 0;
    for (std::size_t i = 0; i < buf.size(); ++i) {
      if (!known[i]) {
        std::byte b{};
        const std::uint64_t at = address + i - static_cast<std::uint64_t>(slide);
        if (program->image().memory.read(at, std::span<std::byte>(&b, 1)) == 1 && program->image().memory.find(at) != nullptr) {
          buf[i] = static_cast<std::uint8_t>(b);
          known[i] = true;
        } else {
          buf[i] = 0;
        }
      }
      if (known[i] && n == i) ++n;
    }
    return n;
  };
  o.backing = std::move(backing);
  try {
    out = std::make_unique<emu::Emulator>(e.program.program->image_ptr(), o);
    const std::string pcname = out->pc_register();
    std::uint64_t pc = 0;
    for (const auto &[name, value] : regs)
      if (SameName(name, pcname)) pc = debug::to_u64(value);
    out->start(pc, emu::StartMode::bare);
    if (out->find_register("TB")) out->set_thumb(thumb);
    for (const auto &[name, value] : regs) {
      auto r = out->find_register(name);
      if (!r || value.empty()) continue;
      std::vector<std::uint8_t> v = value;
      v.resize(r->size, 0);
      try {
        out->write_register_bytes(name, v);
      } catch (const std::exception &) {
      }
    }
    out->set_pc(pc);
  } catch (const std::exception &err) {
    return Error(StatusCode::kFailedPrecondition, std::string("can't emulate from that state: ") + err.what());
  }
  // Writes the request asked for, over the source's state.
  for (const pb::EmulatorRegisterWrite &w : em.registers()) {
    if (!out->find_register(w.name())) return Error(StatusCode::kInvalidArgument, "unknown register " + w.name());
    out->write_register(w.name(), w.value());
  }
  return Status::Ok();
}

Status DebugSessions::Close(const api::CallContext &ctx, const pb::CloseDebugSessionRequest &req) {
  std::shared_ptr<Entry> e;
  {
    std::lock_guard g(mu_);
    auto it = sessions_.find(req.session_id());
    if (it == sessions_.end() || !MayUse(ctx, it->second->owner)) return Error(StatusCode::kNotFound, "no debug session " + req.session_id());
    e = it->second;
    sessions_.erase(it);
  }
  e->session->interrupt();  // a call waiting on a running target returns
  std::lock_guard wait(e->mu);
  if (req.kill()) {
    try {
      e->session->target().kill();
    } catch (const debug::DebugError &) {
    }
  }
  e->session.reset();
  return Status::Ok();
}

Status DebugSessions::List(const api::CallContext &ctx, const pb::ListDebugSessionsRequest &req,
                           pb::ListDebugSessionsResponse &resp) {
  const std::string client = req.client().empty() ? ctx.peer : req.client();
  std::vector<std::shared_ptr<Entry>> mine;
  {
    std::lock_guard g(mu_);
    Reap();
    // Without a client filter, an authenticated caller lists all its own
    // sessions; others' stay invisible unless the caller is an admin.
    for (const auto &[id, e] : sessions_) {
      if (!MayUse(ctx, e->owner)) continue;
      const bool own = ctx.caller != "anonymous" && e->owner == ctx.caller;
      if (e->client == client || (req.client().empty() && own)) mine.push_back(e);
    }
  }
  const auto now = std::chrono::steady_clock::now();
  for (const auto &e : mine) {
    std::unique_lock lock(e->mu, std::try_to_lock);
    pb::DebugSessionInfo *info = resp.add_sessions();
    info->set_session_id(e->id);
    info->set_program_id(e->program.program_id);
    info->set_client(e->client);
    info->set_idle_ms(static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now - e->last_used).count()));
    if (lock.owns_lock()) {
      debug::Session &s = *e->session;
      info->set_target_kind(s.target().kind());
      info->set_description(s.target().description());
      info->set_target_state(ToPb(s.target().state()));
      FillStop(*e, s.last_stop(), info->mutable_last_stop());
      info->set_snapshots(s.timeline().size());
    } else {
      info->set_target_state(pb::DEBUG_TARGET_STATE_RUNNING);
    }
  }
  return Status::Ok();
}

Status DebugSessions::Resume(const api::CallContext &ctx, const pb::ResumeDebugSessionRequest &req,
                             pb::ResumeDebugSessionResponse &resp, const DebugEvalEnv *env) {
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  debug::Session &s = *e->session;
  debug::RunMode mode = debug::RunMode::run;
  switch (req.mode()) {
    case pb::DEBUG_RUN_MODE_STEP_INTO: mode = debug::RunMode::step_into; break;
    case pb::DEBUG_RUN_MODE_STEP_OVER: mode = debug::RunMode::step_over; break;
    case pb::DEBUG_RUN_MODE_STEP_OUT: mode = debug::RunMode::step_out; break;
    default: break;
  }
  debug::ResumeOptions o;
  std::uint32_t ms = req.time_limit_ms();
  if (e->emulator) {
    const std::uint64_t used = s.target().steps();
    const std::uint64_t left = used >= e->emu_limits.max_total_steps() ? 0 : e->emu_limits.max_total_steps() - used;
    if (left == 0) {
      pb::DebugStop *stop = resp.mutable_stop();
      stop->set_kind(pb::DEBUG_STOP_KIND_SESSION_LIMIT);
      stop->set_detail("the session's " + std::to_string(e->emu_limits.max_total_steps()) + " steps are spent");
      FillLocation(*e, s.target().pc(), stop->mutable_pc());
      return FillState(*e, req.state(), std::nullopt, resp.mutable_state());
    }
    o.max_steps = std::min({req.max_steps() == 0 ? e->emu_limits.max_steps_per_call() : req.max_steps(),
                            e->emu_limits.max_steps_per_call(), left});
    ms = ms == 0 ? e->emu_limits.time_limit_ms() : std::min(ms, e->emu_limits.time_limit_ms());
  } else {
    ms = ms == 0 ? bounds_.time_ms : std::min(ms, bounds_.max_time_ms);
  }
  o.deadline = std::min(ctx.deadline, std::chrono::steady_clock::now() + std::chrono::milliseconds(ms));
  o.cancelled = ctx.cancelled;
  if (req.has_until()) {
    std::uint64_t until = 0;
    if (auto st = Runtime(s, req.until(), until); !st.ok()) return st;
    o.until = until;
  }
  debug::Stop stop;
  ConditionScope conditions(s, *e, env);
  // A hook left unanswered: its default (the function runs, the call is the built-in one).
  if (e->hook_hit && !e->answer && e->hook_hit->kind() != pb::DEBUG_HOOK_KIND_FUNCTION)
    e->answer = Entry::Answer{e->hook_hit->hook_id(), true, 0};
  e->hook_hit.reset();
  try {
    stop = s.resume(mode, o);
  } catch (const debug::DebugError &err) {
    return DebugFailure(err);
  }
  FillStop(*e, stop, resp.mutable_stop());
  // A function hook: the run stopped at its entry.
  if (!e->hook_hit && stop.kind == debug::StopKind::breakpoint)
    for (auto &h : e->hooks)
      if (h.spec.kind() == pb::DEBUG_HOOK_KIND_FUNCTION && h.address == stop.pc) {
        ++h.hits;
        pb::DebugHookEvent ev;
        ev.set_hook_id(h.id);
        ev.set_kind(h.spec.kind());
        ev.set_pc(stop.pc);
        ev.set_name(h.spec.name());
        if (auto *et = dynamic_cast<debug::EmulatorTarget *>(&s.target()))
          for (unsigned i = 0; i < 6; ++i) {
            try {
              ev.add_args(et->emulator().arg(i));
            } catch (const std::exception &) {
              break;
            }
          }
        e->hook_hit = ev;
        break;
      }
  if (e->hook_hit) {
    resp.mutable_stop()->set_kind(pb::DEBUG_STOP_KIND_HOOK);
    *resp.mutable_stop()->mutable_hook() = *e->hook_hit;
  }
  return FillState(*e, req.state(), std::nullopt, resp.mutable_state());
}

Status DebugSessions::Wait(const api::CallContext &ctx, const pb::WaitDebugSessionRequest &req, pb::WaitDebugSessionResponse &resp,
                           const DebugEvalEnv *env) {
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  debug::Session &s = *e->session;
  const std::uint32_t ms = req.wait_ms() == 0 ? 1000 : std::min(req.wait_ms(), bounds_.max_time_ms);
  debug::Stop stop;
  ConditionScope conditions(s, *e, env);
  try {
    stop = s.wait(std::min(ctx.deadline, std::chrono::steady_clock::now() + std::chrono::milliseconds(ms)));
  } catch (const debug::DebugError &err) {
    return DebugFailure(err);
  }
  FillStop(*e, stop, resp.mutable_stop());
  return FillState(*e, req.state(), std::nullopt, resp.mutable_state());
}

Status DebugSessions::Interrupt(const api::CallContext &ctx, const pb::InterruptDebugSessionRequest &req) {
  std::shared_ptr<Entry> e;
  {
    std::lock_guard g(mu_);
    auto it = sessions_.find(req.session_id());
    if (it == sessions_.end() || !MayUse(ctx, it->second->owner)) return Error(StatusCode::kNotFound, "no debug session " + req.session_id());
    e = it->second;
  }
  // Without the session's lock: a Resume or Wait holding it is what this stops.
  e->session->interrupt();
  return Status::Ok();
}

Status DebugSessions::GetState(const api::CallContext &ctx, const pb::GetDebugStateRequest &req, pb::GetDebugStateResponse &resp) {
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  std::optional<std::uint64_t> snap;
  if (req.has_snapshot()) snap = req.snapshot();
  try {
    return FillState(*e, req.state(), snap, resp.mutable_state());
  } catch (const debug::DebugError &err) {
    return DebugFailure(err);
  }
}

Status DebugSessions::GetBacktrace(const api::CallContext &ctx, const pb::GetDebugBacktraceRequest &req,
                                   pb::GetDebugBacktraceResponse &resp) {
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  debug::Session &s = *e->session;
  if (s.target().state() == debug::TargetState::running && !req.has_snapshot())
    return Error(StatusCode::kFailedPrecondition, "the target is running: interrupt it, or ask for a snapshot");
  debug::Session::BacktraceOptions o;
  o.max_frames = req.max_frames() == 0 ? 64 : std::min<std::uint32_t>(req.max_frames(), 256);
  if (req.has_snapshot()) o.snapshot = req.snapshot();
  LibraryUnwinding(*e, o);
  resp.set_snapshot(o.snapshot.value_or(s.current_snapshot()));
  if (!debug::UnwindArch::for_language(s.options().language)) {
    resp.set_unsupported("no call-stack unwinding for " + s.options().language +
                         " (x86, x86-64, AArch64, ARM and RISC-V are covered)");
    return Status::Ok();
  }
  std::vector<debug::Frame> frames;
  try {
    frames = s.backtrace(o);
  } catch (const debug::DebugError &err) {
    return DebugFailure(err);
  }
  FillFrames(*e, frames, resp.mutable_frames());
  return Status::Ok();
}

namespace {

void FillFrames(DebugSessions::Entry &ent, const std::vector<debug::Frame> &frames,
                google::protobuf::RepeatedPtrField<pb::DebugFrame> *outs) {
  DebugSessions::Entry *e = &ent;
  debug::Session &s = *e->session;
  for (std::size_t i = 0; i < frames.size(); ++i) {
    const debug::Frame &f = frames[i];
    pb::DebugFrame *out = outs->Add();
    out->set_level(static_cast<std::uint32_t>(i));
    FillLocation(*e, f.pc, out->mutable_pc());
    out->set_sp(f.sp);
    out->set_cfa(f.cfa);
    out->set_how(f.how);
    if (auto p = s.to_program(f.pc); p && e->program.function_at) {
      if (auto fn = e->program.function_at(i == 0 ? *p : *p - 1)) {
        out->set_function(fn->second);
        out->mutable_function_entry()->set_offset(fn->first);
        out->set_function_offset(*p - fn->first);
      }
    } else if (auto h = LibraryAt(*e, i == 0 ? f.pc : f.pc - 1); h && h->function) {
      // In a library that is a project program: its function, by the
      // library's analysis (a return address looks up the call before it).
      const std::uint64_t at = f.pc - static_cast<std::uint64_t>(h->slide);
      out->set_function(h->function->second);
      out->mutable_function_entry()->set_offset(h->function->first);
      out->set_function_offset(at - h->function->first);
    } else if (auto m = HostModuleAt(*e, i == 0 ? f.pc : f.pc - 1); m && m->function) {
      // A crash dump's module read from its file: the nearest function symbol.
      const std::uint64_t at = f.pc - static_cast<std::uint64_t>(m->module->slide);
      out->set_function(m->function->second);
      out->mutable_function_entry()->set_offset(m->function->first);
      out->set_function_offset(at - m->function->first);
    }
    const unsigned size = s.options().image ? s.options().image->bits / 8 : 8;
    for (const debug::FrameRegister &r : f.registers) {
      std::vector<std::uint8_t> bytes(size);
      for (unsigned k = 0; k < size; ++k) bytes[k] = static_cast<std::uint8_t>(r.value >> (8 * k));
      FillValue(r.name, bytes, false, out->add_registers());
    }
  }
}

// Where a runtime address is, as text: "lib_store+0x4", "main",
// "libc.so.6+0x98e51", "0x7f…".
std::string WhereText(DebugSessions::Entry &e, std::uint64_t runtime, bool return_address) {
  debug::Session &s = *e.session;
  const std::uint64_t look = return_address ? runtime - 1 : runtime;
  auto with = [](const std::string &name, std::uint64_t off) {
    char b[24];
    std::snprintf(b, sizeof b, "+0x%llx", static_cast<unsigned long long>(off));
    return off ? name + b : name;
  };
  if (auto p = s.to_program(runtime); p && e.program.function_at)
    if (auto fn = e.program.function_at(return_address ? *p - 1 : *p)) return with(fn->second, *p - fn->first);
  if (auto h = LibraryAt(e, look); h && h->function)
    return with(h->function->second, runtime - static_cast<std::uint64_t>(h->slide) - h->function->first);
  if (auto h = HostModuleAt(e, look); h && h->function)
    return with(h->function->second, runtime - static_cast<std::uint64_t>(h->module->slide) - h->function->first);
  try {
    if (auto m = s.module_at(runtime)) return with(m->first.name, m->second);
  } catch (const debug::DebugError &) {
  }
  char b[24];
  std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(runtime));
  return b;
}

void FillCrash(DebugSessions::Entry &e, std::uint32_t max_frames, pb::DebugCrash *out) {
  debug::Session &s = *e.session;
  const crash::CrashDump &d = e.crash->dump();
  out->set_format(std::string(crash::to_string(d.format)));
  out->set_arch(d.arch);
  out->set_reason(d.reason);
  out->set_signal(d.signal);
  out->set_signal_name(d.signal_name);
  out->set_signal_code(d.signal_code);
  out->set_code_name(d.code_name);
  out->set_exception_code(d.exception_code);
  out->set_exception_name(d.exception_name);
  out->set_access(d.access);
  if (d.fault_address) out->set_fault_address(*d.fault_address);
  out->set_pid(d.pid);
  out->set_command(d.command);
  out->set_args(d.args);
  out->set_os(d.os.empty() && d.format == crash::Format::elf_core ? "Linux" : d.os);
  out->set_cpu(d.cpu);
  std::uint64_t dumped = 0;
  for (const crash::Segment &g : d.memory) dumped += g.file_size;
  out->set_segments(static_cast<std::uint32_t>(d.memory.size()));
  out->set_dumped_bytes(dumped);
  for (const std::string &c : d.comments) out->add_comments(c);
  for (const std::string &w : d.warnings) out->add_warnings(w);
  // The crashed thread, whatever thread the session shows now.
  const std::string shown = s.target().current_thread();
  const std::string crashed = d.crashed_thread < d.threads.size() ? std::to_string(d.threads[d.crashed_thread].id) : shown;
  out->set_crashed_thread(crashed);
  try {
    if (shown != crashed) e.crash->select_thread(crashed);
  } catch (const debug::DebugError &) {
  }
  std::uint64_t pc = 0;
  try {
    pc = s.target().pc();
  } catch (const debug::DebugError &) {
  }
  FillLocation(e, pc, out->mutable_pc());
  out->set_module(out->pc().module());
  out->set_module_offset(out->pc().module_offset());
  out->set_function(WhereText(e, pc, false));
  // The faulting instruction: its bytes from the dump or the programs.
  std::vector<std::uint8_t> code(16);
  std::vector<debug::ByteRange> missing;
  const std::size_t got = s.target().read_memory(pc, code, &missing);
  std::size_t have = code.size();
  for (const debug::ByteRange &m : missing) have = std::min<std::size_t>(have, m.offset);
  if (got != 0 && have != 0) {
    code.resize(have);
    try {
      if (auto insn = s.disassemble(pc, code)) {
        out->set_instruction(insn->text);
        out->set_instruction_bytes(std::string(reinterpret_cast<const char *>(code.data()), std::min<std::size_t>(insn->length, code.size())));
      }
    } catch (const std::exception &) {
    }
  }
  // The backtrace.
  std::vector<debug::Frame> frames;
  if (debug::UnwindArch::for_language(s.options().language)) {
    debug::Session::BacktraceOptions o;
    o.max_frames = max_frames;
    LibraryUnwinding(e, o);
    try {
      frames = s.backtrace(o);
    } catch (const debug::DebugError &err) {
      out->add_warnings(std::string("the backtrace: ") + err.what());
    }
  } else {
    out->add_warnings("no call-stack unwinding for " + s.options().language);
  }
  FillFrames(e, frames, out->mutable_backtrace());
  // The threads, each at its own pc.
  const std::string sp_name = s.target().sp_register();
  const debug::RegisterDesc *spd = s.target().find_register(sp_name);
  for (const crash::Thread &t : d.threads) {
    pb::DebugCrashThread *x = out->add_threads();
    x->set_id(std::to_string(t.id));
    x->set_name(t.name);
    x->set_crashed(x->id() == crashed);
    std::uint64_t tpc = 0, tsp = 0;
    for (const crash::Register &r : t.registers) {
      std::uint64_t v = 0;
      for (std::size_t i = 0; i < r.value.size() && i < 8; ++i) v |= std::uint64_t(r.value[i]) << (8 * i);
      if (r.name == "rip" || r.name == "eip" || r.name == "pc") tpc = v;
      if (spd != nullptr && r.name == spd->target_name) tsp = v;
    }
    FillLocation(e, tpc, x->mutable_pc());
    x->set_sp(tsp);
    x->set_where(WhereText(e, tpc, false));
  }
  // The modules, and which project programs they are.
  for (const crash::Module &m : d.modules) {
    pb::DebugCrashModule *x = out->add_modules();
    x->set_name(m.name);
    x->set_path(m.path);
    x->set_base(m.base);
    x->set_size(m.size);
    x->set_main(m.main);
    x->set_version(m.version);
    x->set_timestamp(m.timestamp);
    x->set_pdb_name(m.pdb_name);
    x->set_pdb_guid(m.pdb_guid);
    x->set_build_id(m.build_id);
    if (SameName(m.name, ProgramName(e.program.program_id))) {
      x->set_program_id(e.program.program_id);
    } else if (e.program.library) {
      try {
        if (auto dp = e.program.library(m.name); dp && dp->program) {
          x->set_program_id(dp->program_id);
          if (m.main) out->set_main_program_id(dp->program_id);
        }
      } catch (const std::exception &) {
      }
    }
  }
  // The report as text.
  std::string text = d.reason + "\n";
  char line[512];
  std::snprintf(line, sizeof line, "at 0x%llx in %s", static_cast<unsigned long long>(pc), out->function().c_str());
  text += line;
  if (!out->module().empty() && out->function().rfind(out->module(), 0) != 0) {
    std::snprintf(line, sizeof line, " (%s+0x%llx)", out->module().c_str(), static_cast<unsigned long long>(out->module_offset()));
    text += line;
  }
  text += ", thread " + crashed;
  if (!out->instruction().empty()) text += ": " + out->instruction();
  text += "\n";
  for (const pb::DebugFrame &f : out->backtrace()) {
    std::string fn = f.function().empty() ? WhereText(e, f.pc().address().offset(), f.level() != 0)
                                          : (f.function_offset() ? f.function() + "+0x" + [&] {
                                              char b[24];
                                              std::snprintf(b, sizeof b, "%llx", static_cast<unsigned long long>(f.function_offset()));
                                              return std::string(b);
                                            }()
                                                                 : f.function());
    std::snprintf(line, sizeof line, "#%u  0x%llx  %s", f.level(), static_cast<unsigned long long>(f.pc().address().offset()), fn.c_str());
    text += line;
    if (!f.pc().module().empty()) {
      std::snprintf(line, sizeof line, "  [%s+0x%llx]", f.pc().module().c_str(), static_cast<unsigned long long>(f.pc().module_offset()));
      text += line;
    }
    text += "  (" + f.how() + ")\n";
  }
  if (d.threads.size() > 1) {
    text += std::to_string(d.threads.size()) + " threads:";
    for (const pb::DebugCrashThread &t : out->threads()) text += " " + t.id() + (t.crashed() ? " (crashed)" : "") + " in " + t.where() + ";";
    text.back() = '\n';
  }
  if (d.pid != 0 || !d.command.empty()) {
    text += "process " + std::to_string(d.pid);
    if (!d.args.empty()) text += " \"" + d.args + "\"";
    else if (!d.command.empty()) text += " " + d.command;
    text += "\n";
  }
  if (!out->main_program_id().empty() && out->main_program_id() != e.program.program_id)
    text += "the executable is program " + out->main_program_id() + ": open the dump from it for its code and names\n";
  out->set_summary(text);
  try {
    if (shown != crashed && !shown.empty()) e.crash->select_thread(shown);
  } catch (const debug::DebugError &) {
  }
}

}  // namespace

Status DebugSessions::GetCrash(const api::CallContext &ctx, const pb::GetDebugCrashRequest &req, pb::GetDebugCrashResponse &resp) {
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  if (e->crash == nullptr) return Error(StatusCode::kFailedPrecondition, "the session isn't a crash dump's");
  FillCrash(*e, req.max_frames() == 0 ? 64 : std::min<std::uint32_t>(req.max_frames(), 256), resp.mutable_crash());
  return Status::Ok();
}

Status DebugSessions::WriteRegisters(const api::CallContext &ctx, const pb::WriteDebugRegistersRequest &req, pb::WriteDebugRegistersResponse &resp) {
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  debug::Session &s = *e->session;
  for (const pb::DebugRegisterWrite &w : req.registers()) {
    const debug::RegisterDesc *d = s.target().find_register(w.name());
    if (d == nullptr) return Error(StatusCode::kInvalidArgument, "unknown register " + w.name());
    std::vector<std::uint8_t> v = w.bytes().empty() ? debug::from_u64(w.value(), d->size)
                                                    : std::vector<std::uint8_t>(w.bytes().begin(), w.bytes().end());
    v.resize(d->size, 0);
    try {
      s.write_register(d->name, v);
    } catch (const debug::DebugError &err) {
      return DebugFailure(err);
    }
  }
  return FillState(*e, req.state(), std::nullopt, resp.mutable_state());
}

Status DebugSessions::ReadMemory(const api::CallContext &ctx, const pb::ReadDebugMemoryRequest &req, pb::ReadDebugMemoryResponse &resp) {
  if (req.length() > (1u << 20)) return Error(StatusCode::kInvalidArgument, "length exceeds 1 MiB");
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  debug::Session &s = *e->session;
  std::uint64_t at = 0;
  if (auto st = Runtime(s, req.address(), at); !st.ok()) return st;
  if (req.length() > 0 && at + (req.length() - 1) < at) return Error(StatusCode::kInvalidArgument, "the range wraps");
  const std::uint64_t last = s.timeline().last();
  const std::uint64_t snap = req.has_snapshot() ? req.snapshot() : last;
  if (s.timeline().find(snap) == nullptr) return Error(StatusCode::kOutOfRange, "snapshot " + std::to_string(snap) + " is not recorded");
  std::string data(req.length(), '\0');
  auto bytes = std::span<std::uint8_t>(reinterpret_cast<std::uint8_t *>(data.data()), data.size());
  std::vector<bool> unavailable(req.length(), false), stale(req.length(), false);
  try {
    if (snap == last && s.target().state() == debug::TargetState::stopped) {
      std::vector<debug::ByteRange> holes;
      s.read_memory(at, bytes, &holes);
      for (const debug::ByteRange &h : holes)
        for (std::uint32_t i = 0; i < h.length && h.offset + i < unavailable.size(); ++i) unavailable[h.offset + i] = true;
    } else {
      std::vector<debug::Timeline::ByteState> state;
      s.memory_at(snap, at, bytes, state);
      for (std::size_t i = 0; i < state.size(); ++i) {
        unavailable[i] = state[i] == debug::Timeline::ByteState::unknown;
        stale[i] = state[i] == debug::Timeline::ByteState::stale;
      }
    }
  } catch (const debug::DebugError &err) {
    return DebugFailure(err);
  }
  resp.set_address(at);
  resp.set_data(std::move(data));
  for (auto &r : Ranges(unavailable)) *resp.add_unavailable() = r;
  for (auto &r : Ranges(stale)) *resp.add_stale() = r;
  resp.set_snapshot(snap);
  return Status::Ok();
}

Status DebugSessions::WriteMemory(const api::CallContext &ctx, const pb::WriteDebugMemoryRequest &req) {
  if (req.data().size() > (16u << 20)) return Error(StatusCode::kInvalidArgument, "more than 16 MiB");
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  debug::Session &s = *e->session;
  std::uint64_t at = 0;
  if (auto st = Runtime(s, req.address(), at); !st.ok()) return st;
  try {
    if (!s.write_memory(at, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(req.data().data()),
                                                          req.data().size())))
      return Error(StatusCode::kInvalidArgument, "memory at " + debug::hex(at) + " can't be written");
  } catch (const debug::DebugError &err) {
    return DebugFailure(err);
  }
  return Status::Ok();
}

Status DebugSessions::SetBreakpoints(const api::CallContext &ctx, const pb::SetDebugBreakpointsRequest &req, pb::SetDebugBreakpointsResponse &resp,
                                     const DebugEvalEnv *env) {
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  debug::Session &s = *e->session;
  try {
    if (req.clear()) s.clear_breakpoints();
    for (std::int32_t id : req.remove_ids()) s.remove_breakpoint(id);
    for (const pb::DebugAddress &a : req.remove()) s.remove_breakpoint_at(a.offset(), a.program());
    for (const pb::DebugBreakpointSpec &b : req.add()) {
      if (s.target().state() == debug::TargetState::replay)
        return Error(StatusCode::kFailedPrecondition, "a recorded trace has no breakpoints");
      if (env && !b.condition().empty())
        if (std::string why = ConditionError(s, *env, b.condition()); !why.empty())
          return Error(StatusCode::kInvalidArgument, "condition " + b.condition() + ": " + why);
      ApplySpec(s, s.add_breakpoint(FromPb(b.kind()), b.address().offset(), b.address().program(), b.size()), b);
    }
    for (const pb::DebugBreakpointUpdate &u : req.update()) {
      if (env && u.has_condition() && !u.condition().empty())
        if (std::string why = ConditionError(s, *env, u.condition()); !why.empty())
          return Error(StatusCode::kInvalidArgument, "condition " + u.condition() + ": " + why);
      if (!s.update_breakpoint(u.id(), u.has_condition() ? std::optional<std::string>(u.condition()) : std::nullopt,
                               u.has_ignore_count() ? std::optional<std::uint64_t>(u.ignore_count()) : std::nullopt,
                               u.has_disabled() ? std::optional<bool>(u.disabled()) : std::nullopt))
        return Error(StatusCode::kNotFound, "no breakpoint " + std::to_string(u.id()));
    }
  } catch (const debug::DebugError &err) {
    return DebugFailure(err);
  }
  for (const debug::Breakpoint &b : s.breakpoints()) FillBreakpoint(s, b, e->program.program_id, resp.add_breakpoints());
  emu::Machine *m = nullptr;
  if (auto *t = dynamic_cast<debug::EmulatorTarget *>(&s.target())) m = t->emulator().machine();
  if (req.set_exception_breaks()) {
    if (!m) return Error(StatusCode::kFailedPrecondition, "exception breakpoints need an emulator target with a machine");
    m->set_break_on({req.exception_breaks().begin(), req.exception_breaks().end()});
  }
  if (m)
    for (const std::string &k : m->break_on()) resp.add_exception_breaks(k);
  return Status::Ok();
}

Status DebugSessions::WriteInput(const api::CallContext &ctx, const pb::WriteDebugInputRequest &req) {
  if (req.data().size() > (1u << 20)) return Error(StatusCode::kInvalidArgument, "input is at most 1 MiB per call");
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  auto *t = dynamic_cast<debug::EmulatorTarget *>(&e->session->target());
  emu::Machine *m = t ? t->emulator().machine() : nullptr;
  if (!m) return Error(StatusCode::kFailedPrecondition, "the session has no machine to take input");
  if (!m->input(req.peripheral(), req.data()))
    return Error(StatusCode::kNotFound, req.peripheral().empty() ? "the machine has no UART for console input"
                                                                 : "the machine has no peripheral " + req.peripheral());
  return Status::Ok();
}

Status DebugSessions::GetMachine(const api::CallContext &ctx, const pb::GetDebugMachineRequest &req,
                                 pb::GetDebugMachineResponse &resp) {
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  auto *t = dynamic_cast<debug::EmulatorTarget *>(&e->session->target());
  const emu::Machine *m = t ? t->emulator().machine() : nullptr;
  if (!m) return Error(StatusCode::kFailedPrecondition, "the session has no machine");
  FillMachineState(t->emulator(), resp.mutable_state());
  std::uint64_t first = 0, count = 0;
  FillMachineEvents(*m, req.from_event(), req.limit(), resp.mutable_events(), first, count);
  resp.set_first_event(first);
  resp.set_event_count(count);
  return Status::Ok();
}

Status DebugSessions::SelectThread(const api::CallContext &ctx, const pb::SelectDebugThreadRequest &req, pb::SelectDebugThreadResponse &resp) {
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  try {
    e->session->select_thread(req.thread_id());
  } catch (const debug::DebugError &err) {
    return Error(StatusCode::kInvalidArgument, err.what());
  }
  return FillState(*e, req.state(), std::nullopt, resp.mutable_state());
}

Status DebugSessions::ListModules(const api::CallContext &ctx, const pb::ListDebugModulesRequest &req, pb::ListDebugModulesResponse &resp) {
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  debug::Session &s = *e->session;
  const std::string name = ProgramName(e->program.program_id);
  try {
    for (const debug::ModuleInfo &m : s.modules()) {
      pb::DebugModule *pm = resp.add_modules();
      pm->set_name(m.name);
      pm->set_path(m.path);
      pm->set_base(m.base);
      pm->set_size(m.size);
      pm->set_load_bias(m.load_bias);
      pm->set_main(m.main);
      pm->set_program(m.name == name || (m.main && s.mapping().known && s.mapping().how != "not loaded yet" &&
                                         s.to_program(m.base).has_value()));
      std::int64_t slide = 0;
      if (!pm->program())
        if (auto lib = LibraryOf(*e, m, slide)) {
          pm->set_program_id(lib->program_id);
          pm->set_library_slide(slide);
        }
    }
    for (const debug::MapRegion &r : s.memory_map()) {
      pb::DebugMemoryRegion *pr = resp.add_regions();
      pr->set_start(r.start);
      pr->set_size(r.size);
      pr->set_permissions(r.perms);
      pr->set_name(r.name);
      pr->set_kind(r.kind);
      pr->set_offset(r.offset);
    }
  } catch (const debug::DebugError &err) {
    return DebugFailure(err);
  }
  pb::DebugAddressMapping *m = resp.mutable_mapping();
  m->set_known(s.mapping().known);
  m->set_slide(s.mapping().slide);
  m->set_how(s.mapping().how);
  return Status::Ok();
}

Status DebugSessions::GetTimeline(const api::CallContext &ctx, const pb::GetDebugTimelineRequest &req, pb::GetDebugTimelineResponse &resp) {
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  debug::Session &s = *e->session;
  const debug::Timeline &tl = s.timeline();
  const std::size_t limit = req.limit() == 0 ? 1000 : std::min<std::uint32_t>(req.limit(), 10000);
  std::size_t n = 0;
  for (const debug::Snapshot &snap : tl.snapshots()) {
    if (snap.index < req.from_snapshot()) continue;
    if (req.stops_only() && snap.kind != debug::Snapshot::Kind::stop) continue;
    if (req.events_only() && snap.event.empty()) continue;
    if (n++ >= limit) break;
    pb::DebugSnapshot *ps = resp.add_snapshots();
    ps->set_index(snap.index);
    ps->set_kind(ToPb(snap.kind));
    ps->mutable_pc()->mutable_address()->set_offset(snap.pc);
    if (snap.program_pc) {
      ps->mutable_pc()->mutable_program_address()->set_offset(*snap.program_pc);
      ps->mutable_pc()->set_module(ProgramName(e->program.program_id));
    }
    ps->set_thread(snap.thread);
    ps->set_steps(snap.steps);
    if (snap.kind == debug::Snapshot::Kind::stop) ps->set_stop(ToPb(snap.stop));
    ps->set_detail(snap.detail);
    ps->set_text(snap.text);
    for (const std::string &c : tl.changed_at(snap.index)) ps->add_changed(c);
    ps->set_time_us(snap.time_us);
    ps->set_gap(snap.gap);
    ps->set_event(snap.event);
    ps->set_event_number(snap.event.empty() ? -1 : snap.event_number);
  }
  resp.set_first(tl.first());
  resp.set_last(tl.last());
  resp.set_count(tl.size());
  resp.set_dropped(tl.dropped());
  resp.set_bytes(tl.bytes());
  resp.set_complete(s.target().complete_recording() && s.options().record_steps);
  *resp.mutable_limits() = e->limits;
  return Status::Ok();
}

Status DebugSessions::SaveTrace(const api::CallContext &ctx, const pb::SaveDebugTraceRequest &req, pb::SaveDebugTraceResponse &resp) {
  if (!ValidTraceName(req.name()))
    return Error(StatusCode::kInvalidArgument, "a trace name is 1 to 64 of A-Z a-z 0-9 . _ - (not starting with .)");
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  return SaveTraceLocked(*e, req.name(), resp.mutable_trace());
}

Status DebugSessions::SaveTraceLocked(Entry &entry, const std::string &name, pb::DebugTraceInfo *info) {
  Entry *e = &entry;
  debug::Session &s = *e->session;
  debug::TraceHeader h = s.header(name, e->program.program_id);
  try {
    h.modules = s.modules();
  } catch (const debug::DebugError &) {
  }
  const std::string data = s.timeline().serialize(h);
  if (data.size() > bounds_.max_trace_bytes)
    return Error(StatusCode::kResourceExhausted, "the trace is " + std::to_string(data.size()) + " bytes, more than " +
                                                     std::to_string(bounds_.max_trace_bytes));
  const DebugProgram &p = e->program;
  bool persisted = false;
  if (!p.trace_dir.empty()) {
    std::error_code ec;
    fs::create_directories(p.trace_dir, ec);
    std::size_t count = 0;
    for (const auto &f : fs::directory_iterator(p.trace_dir, ec))
      if (f.path().extension() == ".rktrace" && f.path().stem() != name) ++count;
    if (count >= bounds_.traces_per_program)
      return Error(StatusCode::kResourceExhausted, "the program has " + std::to_string(count) + " traces, its most; delete one");
    const fs::path file = p.trace_dir / (name + ".rktrace");
    const fs::path tmp = p.trace_dir / ("." + name + ".tmp");
    {
      std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
      out.write(data.data(), static_cast<std::streamsize>(data.size()));
      if (!out) return Error(StatusCode::kInternal, "can't write " + tmp.string());
    }
    fs::rename(tmp, file, ec);
    if (ec) return Error(StatusCode::kInternal, "can't save " + file.string() + ": " + ec.message());
    persisted = true;
  } else {
    std::lock_guard g(traces_mu_);
    auto &mine = traces_[p.program_id];
    if (mine.size() >= bounds_.traces_per_program && !mine.count(name))
      return Error(StatusCode::kResourceExhausted, "the program has " + std::to_string(mine.size()) + " traces, its most; delete one");
    mine[name] = data;
  }
  FillTraceInfo(h, s.timeline().size(), data.size(), persisted, info);
  return Status::Ok();
}

// --- Rewinding (RewindDebugSession; docs/debugger.md "Rewind") ---

Status DebugSessions::Rewind(const api::CallContext &ctx, const pb::RewindDebugSessionRequest &req,
                             pb::RewindDebugSessionResponse &resp) {
  if (!req.save_branch_as().empty() && !ValidTraceName(req.save_branch_as()))
    return Error(StatusCode::kInvalidArgument, "a trace name is 1 to 64 of A-Z a-z 0-9 . _ - (not starting with .)");
  if (req.has_snapshot() == req.step_back()) return Error(StatusCode::kInvalidArgument, "give a snapshot or step_back");
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  debug::Session &s = *e->session;
  if (!s.can_rewind())
    return Error(StatusCode::kFailedPrecondition,
                 s.target().kind() == "emulator" ? "an emulator session on a machine can't go back (its peripherals aren't checkpointed)"
                                                 : "only the emulator can go back: a live target's or a trace's past is a recording to look at");
  const std::uint64_t last = s.timeline().last();
  const std::uint64_t to = req.step_back() ? (last == s.timeline().first() ? last : last - 1) : req.snapshot();
  if (req.step_back() && to == last) return Error(StatusCode::kOutOfRange, "at the first recorded snapshot: nothing to go back to");
  if (s.timeline().find(to) == nullptr) return Error(StatusCode::kOutOfRange, "snapshot " + std::to_string(to) + " is not recorded");
  if (!req.save_branch_as().empty() && to < last)
    if (auto st = SaveTraceLocked(*e, req.save_branch_as(), resp.mutable_saved()); !st.ok()) return st;
  debug::Stop stop;
  try {
    stop = s.rewind(to);
  } catch (const debug::DebugError &err) {
    return DebugFailure(err);
  }
  resp.set_discarded(last - to);
  FillStop(*e, stop, resp.mutable_stop());
  return FillState(*e, req.state(), std::nullopt, resp.mutable_state());
}

std::optional<std::string> DebugSessions::LoadTrace(const DebugProgram &p, const std::string &name) {
  if (!ValidTraceName(name)) return std::nullopt;
  if (!p.trace_dir.empty()) {
    std::ifstream in(p.trace_dir / (name + ".rktrace"), std::ios::binary);
    if (in) {
      std::ostringstream o;
      o << in.rdbuf();
      return o.str();
    }
  }
  std::lock_guard g(traces_mu_);
  auto it = traces_.find(p.program_id);
  if (it == traces_.end()) return std::nullopt;
  auto t = it->second.find(name);
  if (t == it->second.end()) return std::nullopt;
  return t->second;
}

Status DebugSessions::ListTraces(const DebugProgram &p, pb::ListDebugTracesResponse &resp) {
  if (!p.trace_dir.empty()) {
    std::error_code ec;
    std::vector<fs::path> files;
    for (const auto &f : fs::directory_iterator(p.trace_dir, ec))
      if (f.path().extension() == ".rktrace") files.push_back(f.path());
    std::sort(files.begin(), files.end());
    for (const fs::path &f : files) {
      std::ifstream in(f, std::ios::binary);
      std::string head(1u << 20, '\0');
      in.read(head.data(), static_cast<std::streamsize>(head.size()));
      head.resize(static_cast<std::size_t>(in.gcount()));
      try {
        std::uint64_t n = 0;
        debug::TraceHeader h = debug::Timeline::peek(head, &n);
        h.name = f.stem().string();
        FillTraceInfo(h, n, fs::file_size(f, ec), true, resp.add_traces());
      } catch (const debug::DebugError &) {
      }
    }
  }
  std::lock_guard g(traces_mu_);
  if (auto it = traces_.find(p.program_id); it != traces_.end())
    for (const auto &[name, data] : it->second) {
      std::uint64_t n = 0;
      debug::TraceHeader h = debug::Timeline::peek(data, &n);
      FillTraceInfo(h, n, data.size(), false, resp.add_traces());
    }
  return Status::Ok();
}

Status DebugSessions::DeleteTrace(const DebugProgram &p, const std::string &name) {
  if (!ValidTraceName(name)) return Error(StatusCode::kInvalidArgument, "bad trace name");
  bool found = false;
  if (!p.trace_dir.empty()) {
    std::error_code ec;
    found = fs::remove(p.trace_dir / (name + ".rktrace"), ec);
  }
  {
    std::lock_guard g(traces_mu_);
    if (auto it = traces_.find(p.program_id); it != traces_.end()) found = it->second.erase(name) > 0 || found;
  }
  if (!found) return Error(StatusCode::kNotFound, "no trace " + name + " for " + p.program_id);
  return Status::Ok();
}

// --- Values (EvaluateDebug; docs/debugger.md "Expressions") ---

namespace {

namespace ex = debug::expr;

std::string HexOf(std::uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

bool SameName(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i)
    if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) return false;
  return true;
}

// The program's types for expressions, described on demand.
class ProgramTypes : public ex::TypeSource {
 public:
  ProgramTypes(const DebugEvalEnv &env, unsigned pointer_size) : env_(env), ps_(pointer_size) {}
  ex::TypeP by_hash(const std::string &hash) override {
    if (hash.empty()) return nullptr;
    if (auto it = cache_.find(hash); it != cache_.end()) return it->second;
    if (!env_.describe || ++described_ > 4096) return nullptr;
    std::optional<pb::TypeDefinition> d = env_.describe(hash);
    if (!d) return nullptr;
    auto t = std::make_shared<ex::Type>();
    cache_[hash] = t;  // before the parts: a struct's pointers to itself
    Convert(*d, *t);
    return t;
  }
  ex::TypeP by_name(const std::string &name) override {
    if (!env_.type_named) return nullptr;
    auto h = env_.type_named(name);
    return h ? by_hash(*h) : nullptr;
  }

 private:
  void Convert(const pb::TypeDefinition &d, ex::Type &t) {
    using K = ex::Type::Kind;
    t.size = d.size();
    t.name = d.display().empty() ? d.name() : d.display();
    switch (d.kind()) {
      case pb::TYPE_KIND_VOID: t.kind = K::void_; break;
      case pb::TYPE_KIND_BOOL: t.kind = K::bool_; break;
      case pb::TYPE_KIND_INT: t.kind = K::int_; break;
      case pb::TYPE_KIND_UINT: t.kind = K::uint_; break;
      case pb::TYPE_KIND_CHAR: t.kind = K::char_; break;
      case pb::TYPE_KIND_FLOAT: t.kind = K::float_; break;
      case pb::TYPE_KIND_POINTER:
        t.kind = K::pointer;
        t.target_hash = d.pointer().target_hash();
        if (t.size == 0) t.size = ps_;
        break;
      case pb::TYPE_KIND_ARRAY:
        t.kind = K::array;
        t.target_hash = d.array().element_hash();
        t.count = d.array().count();
        break;
      case pb::TYPE_KIND_STRUCT:
      case pb::TYPE_KIND_UNION:
        t.kind = d.kind() == pb::TYPE_KIND_STRUCT ? K::struct_ : K::union_;
        for (const pb::Field &f : d.composite().fields())
          t.fields.push_back({f.name(), f.offset(), f.bit_offset(), f.bit_size(), f.type_hash(), nullptr});
        break;
      case pb::TYPE_KIND_ENUM:
        t.kind = K::enum_;
        for (const pb::EnumValue &v : d.enumeration().values()) t.enumerators.emplace_back(v.value(), v.name());
        break;
      case pb::TYPE_KIND_FUNCTION: t.kind = K::function; break;
      case pb::TYPE_KIND_TYPEDEF:
      case pb::TYPE_KIND_QUALIFIED: {
        const std::string &target = d.kind() == pb::TYPE_KIND_TYPEDEF ? d.typedef_type().target_hash() : d.qualified().target_hash();
        if (ex::TypeP to = target == d.hash() ? nullptr : by_hash(target)) {
          const std::string name = t.name;
          t = *to;
          t.name = name;
        } else {
          t.kind = K::undefined;
        }
        break;
      }
      default: t.kind = K::undefined;
    }
  }

  const DebugEvalEnv &env_;
  unsigned ps_;
  std::map<std::string, std::shared_ptr<ex::Type>> cache_;
  int described_ = 0;
};

// One evaluation: a session at a snapshot (or now), in a frame.
class Evaluation {
 public:
  Evaluation(debug::Session &s, const DebugProgram &program, const DebugEvalEnv &env, std::uint64_t snap, bool live)
      : s_(s), program_(program), env_(env), snap_(snap), live_(live),
        ps_(s.options().image ? std::max(1u, s.options().image->bits / 8) : 8),
        big_(s.options().language.find(":BE:") != std::string::npos), types_(env, ps_) {
    if (!live_) recorded_ = s_.timeline().registers_at(snap_);
  }

  unsigned pointer_size() const { return ps_; }
  bool big_endian() const { return big_; }
  // Unwind through the session's libraries too (LibraryUnwinding).
  void unwind_libraries(DebugSessions::Entry &e) { entry_ = &e; }

  const std::vector<debug::Frame> &frames() {
    if (!frames_) {
      frames_.emplace();
      if (debug::UnwindArch::for_language(s_.options().language)) {
        debug::Session::BacktraceOptions o;
        if (!live_) o.snapshot = snap_;
        if (entry_) LibraryUnwinding(*entry_, o);
        try {
          *frames_ = s_.backtrace(o);
        } catch (const debug::DebugError &) {
        }
      }
    }
    return *frames_;
  }

  // The function (entry, name) of frame `level`.
  std::optional<std::pair<std::uint64_t, std::string>> function_of(std::uint32_t level) {
    const auto &f = frames();
    if (level >= f.size() || !program_.function_at) return std::nullopt;
    auto p = s_.to_program(f[level].pc);
    if (!p) return std::nullopt;
    return program_.function_at(level == 0 ? *p : *p - 1);
  }

  // The innermost frame in the function at `entry`.
  std::optional<std::uint32_t> frame_in(std::uint64_t entry) {
    for (std::uint32_t i = 0; i < frames().size(); ++i)
      if (auto fn = function_of(i); fn && fn->first == entry) return i;
    return std::nullopt;
  }

  std::size_t read(std::uint64_t address, std::span<std::uint8_t> out) {
    if (out.empty()) return 0;
    try {
      if (live_) {
        std::vector<debug::ByteRange> holes;
        s_.read_memory(address, out, &holes);
        std::size_t n = out.size();
        for (const debug::ByteRange &h : holes) n = std::min<std::size_t>(n, h.offset);
        return n;
      }
      std::vector<debug::Timeline::ByteState> state;
      s_.memory_at(snap_, address, out, state);
      for (std::size_t i = 0; i < state.size() && i < out.size(); ++i)
        if (state[i] == debug::Timeline::ByteState::unknown) return i;
      return out.size();
    } catch (const debug::DebugError &) {
      return 0;
    }
  }

  // A register's bytes (target order) in frame `level`; sub-registers
  // ("EAX", "w0") from the register holding them.
  std::optional<std::vector<std::uint8_t>> reg(const std::string &name, std::uint32_t level, std::string *canonical) {
    // Now, at the stop: the target's register by its name, without reading the rest.
    if (level == 0 && live_)
      if (const debug::RegisterDesc *d = s_.target().find_register(name)) {
        try {
          auto v = s_.read_register(d->name);
          if (canonical) *canonical = d->name;
          return v;
        } catch (const debug::DebugError &) {
        }
      }
    auto known = known_registers(level);
    for (const auto &[n, v] : known)
      if (SameName(n, name)) {
        if (canonical) *canonical = n;
        return v;
      }
    // A part of a known one.
    std::optional<std::pair<std::uint64_t, std::uint32_t>> want;
    for (const std::string &n : {name, Upper(name), Lower(name)})
      if ((want = s_.register_storage(n))) {
        if (canonical) *canonical = n;
        break;
      }
    if (!want) return std::nullopt;
    for (const auto &[n, v] : known) {
      auto has = s_.register_storage(n);
      if (!has || want->first < has->first || want->first + want->second > has->first + has->second) continue;
      const std::size_t at = static_cast<std::size_t>(want->first - has->first);
      if (at + want->second > v.size()) continue;
      return std::vector<std::uint8_t>(v.begin() + static_cast<std::ptrdiff_t>(at),
                                       v.begin() + static_cast<std::ptrdiff_t>(at + want->second));
    }
    return std::nullopt;
  }

  // Whether `name` is any register of the language (so a caller frame can say it wasn't recovered).
  bool is_register(const std::string &name) {
    for (const std::string &n : {name, Upper(name), Lower(name)})
      if (s_.register_storage(n)) return true;
    return false;
  }

  // Frame `level`'s registers by name, as uint64 values (the memory_accesses input).
  std::map<std::string, std::uint64_t> register_values(std::uint32_t level) {
    std::map<std::string, std::uint64_t> out;
    for (const auto &[n, v] : known_registers(level))
      if (v.size() <= 8) out[n] = debug::to_u64(v);
    return out;
  }

  // The stack pointer at the entry of frame `level`'s function: where its
  // stack variables' offsets count from.
  std::optional<std::uint64_t> entry_sp(std::uint32_t level) {
    const auto &f = frames();
    if (level >= f.size()) return std::nullopt;
    auto arch = debug::UnwindArch::for_language(s_.options().language);
    if (!arch) return std::nullopt;
    // A call pushes the return address on x86; elsewhere it goes to a register.
    const std::uint64_t push = s_.options().language.rfind("x86:", 0) == 0 ? arch->address_size : 0;
    if (f[level].cfa != 0) return f[level].cfa - push;
    if (level + 1 < f.size()) return f[level + 1].sp - push;
    return std::nullopt;
  }

  // A decompiler variable through its storage, in frame `level` (nullopt: no frame).
  ex::Value variable(const pb::DebugVariable &v, std::optional<std::uint32_t> level, std::string &location) {
    ex::Value out;
    std::vector<std::vector<std::uint8_t>> pieces;
    std::uint64_t total = 0;
    for (const pb::Varnode &vn : v.storage()) total += vn.size();
    out.type = Resolve(v.type(), total);
    if (v.storage().empty()) {
      if (v.has_address()) {
        out.address = s_.to_runtime(v.address().offset());
        location = HexOf(*out.address);
        return Load(out);
      }
      out.unknown = "the variable has no storage";
      return out;
    }
    for (const pb::Varnode &vn : v.storage()) {
      std::vector<std::uint8_t> bytes(vn.size());
      if (vn.space() == "register") {
        std::string name = vn.register_name().empty() ? s_.register_at(vn.offset(), vn.size()) : vn.register_name();
        if (!level) return Unknown(out, "not in a frame on the stack");
        std::string canon;
        auto r = name.empty() ? std::nullopt : reg(name, *level, &canon);
        if (!r) return Unknown(out, (name.empty() ? "register " + HexOf(vn.offset()) : name) +
                                        (*level == 0 ? " is not known" : " is not recovered in frame #" + std::to_string(*level)));
        r->resize(vn.size());
        bytes = *r;
        location += (location.empty() ? "" : ":") + (canon.empty() ? name : canon);
        if (v.storage_size() == 1) out.reg = canon.empty() ? name : canon;
      } else if (vn.space() == "stack") {
        if (!level) return Unknown(out, "not in a frame on the stack");
        auto base = entry_sp(*level);
        if (!base) return Unknown(out, "the frame's stack pointer at entry is not known");
        const std::int64_t off = SignExtend(vn.offset(), ps_);
        const std::uint64_t at = *base + static_cast<std::uint64_t>(off);
        location += (location.empty() ? "" : ":") + std::string("stack ") + (off < 0 ? "-" : "") +
                    HexOf(static_cast<std::uint64_t>(off < 0 ? -off : off)) + " (" + HexOf(at) + ")";
        if (v.storage_size() == 1) {
          out.address = at;
          return Load(out);
        }
        if (read(at, bytes) < bytes.size()) return Unknown(out, "memory at " + HexOf(at) + " is not readable");
      } else if (vn.space() == "unique") {
        return Unknown(out, "a decompiler temporary: no location at runtime");
      } else if (vn.space() == "const") {
        bytes = debug::from_u64(vn.offset(), vn.size());
      } else {
        const std::uint64_t at = s_.to_runtime(vn.offset());
        location += (location.empty() ? "" : ":") + HexOf(at);
        if (v.storage_size() == 1) {
          out.address = at;
          return Load(out);
        }
        if (read(at, bytes) < bytes.size()) return Unknown(out, "memory at " + HexOf(at) + " is not readable");
      }
      if (big_ && vn.space() == "const") std::reverse(bytes.begin(), bytes.end());
      pieces.push_back(std::move(bytes));
    }
    // Most significant piece first: little-endian bytes start with the last.
    if (!big_) std::reverse(pieces.begin(), pieces.end());
    for (auto &p : pieces) out.bytes.insert(out.bytes.end(), p.begin(), p.end());
    if (out.type->size != 0 && out.type->size != out.bytes.size()) {
      if (big_ && out.type->size < out.bytes.size())
        out.bytes.erase(out.bytes.begin(), out.bytes.end() - static_cast<std::ptrdiff_t>(out.type->size));
      else
        out.bytes.resize(static_cast<std::size_t>(out.type->size), 0);
    }
    return out;
  }

  // Names in frame `level`: its function's variables, registers, symbols.
  ex::Context context(std::optional<std::uint32_t> level) {
    ex::Context c;
    c.types = &types_;
    c.pointer_size = ps_;
    c.big_endian = big_;
    c.read = [this](std::uint64_t a, std::span<std::uint8_t> out) { return read(a, out); };
    c.symbolize = [this](std::uint64_t a) -> std::string {
      auto p = s_.to_program(a);
      return p && env_.symbol_at ? env_.symbol_at(*p) : std::string();
    };
    c.lookup = [this, level](const std::string &name, bool register_only) -> std::optional<ex::Value> {
      if (!register_only && level && env_.variables) {
        if (auto fn = function_of(*level)) {
          for (const pb::Variable &var : Variables(fn->first)) {
            if (var.name() != name) continue;
            pb::DebugVariable dv;
            dv.mutable_function()->set_offset(fn->first);
            *dv.mutable_storage() = var.storage();
            *dv.mutable_type() = var.type();
            if (var.has_address()) *dv.mutable_address() = var.address();
            std::string where;
            return variable(dv, level, where);
          }
        }
      }
      std::string canon;
      if (auto r = reg(name, level.value_or(0), &canon)) {
        ex::Value v;
        v.type = ex::undefined(r->size());
        v.bytes = std::move(*r);
        v.reg = canon;
        return v;
      }
      if (is_register(name)) {
        ex::Value v;
        v.type = ex::undefined(ps_);
        v.reg = name;
        v.unknown = name + " is not recovered in frame #" + std::to_string(level.value_or(0));
        return v;
      }
      if (register_only || !env_.symbol) return std::nullopt;
      auto at = env_.symbol(name);
      if (!at) return std::nullopt;
      ex::Value v;
      const std::uint64_t runtime = s_.to_runtime(*at);
      if (env_.data_type)
        if (auto h = env_.data_type(*at))
          if (ex::TypeP t = types_.by_hash(*h)) {
            v.type = t;
            v.address = runtime;
            return v;
          }
      // No type: the symbol's address, as Go To reads it.
      v.type = ex::undefined(ps_);
      v.bytes = debug::from_u64(runtime, ps_);
      if (big_) std::reverse(v.bytes.begin(), v.bytes.end());
      return v;
    };
    return c;
  }

  ex::TypeSource &types() { return types_; }

 private:
  static std::string Upper(std::string s) {
    for (char &c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
  }
  static std::string Lower(std::string s) {
    for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
  }
  static std::int64_t SignExtend(std::uint64_t v, unsigned size) {
    if (size >= 8) return static_cast<std::int64_t>(v);
    const std::uint64_t m = 1ull << (size * 8 - 1);
    v &= (1ull << (size * 8)) - 1;
    return static_cast<std::int64_t>((v ^ m) - m);
  }
  ex::Value Unknown(ex::Value v, std::string why) {
    v.unknown = std::move(why);
    v.bytes.clear();
    return v;
  }
  ex::Value Load(ex::Value v) {
    std::uint64_t size = std::min<std::uint64_t>(v.type->size, 4096);
    if (size == 0) return v;
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(size));
    const std::size_t n = read(*v.address, buf);
    if (n < buf.size()) return Unknown(v, "memory at " + HexOf(*v.address + n) + " is not " + (live_ ? "readable" : "recorded at this snapshot"));
    v.bytes = std::move(buf);
    v.truncated = size < v.type->size;
    return v;
  }
  ex::TypeP Resolve(const pb::TypeRef &t, std::uint64_t size) {
    if (ex::TypeP r = types_.by_hash(t.hash())) return r;
    if (!t.display().empty()) {
      ex::Context c;
      c.types = &types_;
      c.pointer_size = ps_;
      std::string name = t.display();
      int stars = 0;
      while (!name.empty() && (name.back() == '*' || name.back() == ' ')) {
        if (name.back() == '*') ++stars;
        name.pop_back();
      }
      if (ex::TypeP r = ex::resolve_type_name(name, c)) {
        for (int i = 0; i < stars; ++i) r = ex::pointer_to(r, ps_);
        return r;
      }
    }
    return ex::undefined(size == 0 ? 1 : size);
  }
  const std::vector<pb::Variable> &Variables(std::uint64_t entry) {
    auto it = variables_.find(entry);
    if (it == variables_.end()) it = variables_.emplace(entry, env_.variables(entry)).first;
    return it->second;
  }
  // Registers known in frame `level`: all the target's at the stop, the unwound ones above it.
  std::vector<std::pair<std::string, std::vector<std::uint8_t>>> known_registers(std::uint32_t level) {
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>> out;
    if (level == 0) {
      if (live_) {
        for (const debug::RegisterDesc &d : s_.target().registers()) {
          if (d.size > 64) continue;
          try {
            out.emplace_back(d.name, s_.read_register(d.name));
          } catch (const debug::DebugError &) {
          }
        }
      } else {
        for (const auto &[n, v] : recorded_) out.emplace_back(n, v);
      }
      return out;
    }
    const auto &f = frames();
    if (level >= f.size()) return out;
    for (const debug::FrameRegister &r : f[level].registers) {
      auto bytes = debug::from_u64(r.value, ps_);
      if (big_) std::reverse(bytes.begin(), bytes.end());
      out.emplace_back(r.name, std::move(bytes));
    }
    return out;
  }

  debug::Session &s_;
  const DebugProgram &program_;
  const DebugEvalEnv &env_;
  std::uint64_t snap_;
  bool live_;
  unsigned ps_;
  bool big_;
  ProgramTypes types_;
  std::map<std::string, std::vector<std::uint8_t>> recorded_;
  std::optional<std::vector<debug::Frame>> frames_;
  DebugSessions::Entry *entry_ = nullptr;
  std::map<std::uint64_t, std::vector<pb::Variable>> variables_;
};

std::shared_ptr<const ex::Expression> ParseCondition(DebugSessions::Entry &e, Evaluation &ev, const std::string &text) {
  auto it = e.conditions.find(text);
  if (it != e.conditions.end()) return it->second;
  auto x = std::make_shared<const ex::Expression>(ex::Expression::parse(text, [&](const std::string &n) {
    return ev.types().by_name(n) != nullptr || ex::builtin(n, ev.pointer_size()) != nullptr;
  }));
  if (e.conditions.size() > 256) e.conditions.clear();
  e.conditions.emplace(text, x);
  return x;
}

bool CheckCondition(DebugSessions::Entry &e, const DebugEvalEnv &env, const std::string &text, std::string &error) {
  debug::Session &s = *e.session;
  Evaluation ev(s, e.program, env, s.timeline().last(), true);
  ev.unwind_libraries(e);
  try {
    auto x = ParseCondition(e, ev, text);
    ex::Context c = ev.context(0u);
    return ex::truthy(x->evaluate(c), ev.big_endian());
  } catch (const ex::ExprError &err) {
    error = err.what();
  } catch (const debug::DebugError &err) {
    error = err.what();
  }
  return true;
}

std::string ConditionError(debug::Session &s, const DebugEvalEnv &env, const std::string &text) {
  ProgramTypes types(env, s.options().image ? std::max(1u, s.options().image->bits / 8) : 8);
  try {
    ex::Expression::parse(text, [&](const std::string &n) { return types.by_name(n) != nullptr || ex::builtin(n, 8) != nullptr; });
  } catch (const ex::ExprError &err) {
    return err.what();
  }
  return {};
}

void FillDebugValue(debug::Session &s, Evaluation &ev, ex::Context &c, const ex::Value &v, int depth, pb::DebugValue *out) {
  if (v.type) out->set_type(v.type->name);
  if (v.address) {
    out->set_address(*v.address);
    if (auto p = s.to_program(*v.address)) out->set_program_address(*p);
  }
  out->set_register_name(v.reg);
  if (!v.unknown.empty()) {
    out->set_error(v.unknown);
    out->set_text("??");
    return;
  }
  ex::Formatted f = ex::format(v, c, depth);
  out->set_text(f.text);
  out->set_hex(f.hex);
  out->set_bytes(std::string(v.bytes.begin(), v.bytes.end()));
  for (const auto &ch : f.children) {
    pb::DebugValueChild *o = out->add_children();
    o->set_name(ch.name);
    o->set_text(ch.text);
    o->set_type(ch.type);
    if (ch.address) o->set_address(*ch.address);
  }
  (void)ev;
}

}  // namespace

Status DebugSessions::ProgramOf(const api::CallContext &ctx, const std::string &session_id, std::string &program_id) {
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, session_id, e, lock); !st.ok()) return st;
  program_id = e->program.program_id;
  return Status::Ok();
}

Status DebugSessions::Evaluate(const api::CallContext &ctx, const pb::EvaluateDebugRequest &req, const DebugEvalEnv &env,
                               pb::EvaluateDebugResponse &resp) {
  if (req.items_size() > 256) return Error(StatusCode::kInvalidArgument, "at most 256 items");
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  debug::Session &s = *e->session;
  const std::uint64_t last = s.timeline().last();
  const bool running = s.target().state() == debug::TargetState::running;
  if (running && !req.has_snapshot())
    return Error(StatusCode::kFailedPrecondition, "the target is running: interrupt it, or ask for a snapshot");
  const std::uint64_t snap = req.has_snapshot() ? req.snapshot() : last;
  if (s.timeline().find(snap) == nullptr) return Error(StatusCode::kOutOfRange, "snapshot " + std::to_string(snap) + " is not recorded");
  if (req.has_compare_snapshot() && s.timeline().find(req.compare_snapshot()) == nullptr)
    return Error(StatusCode::kOutOfRange, "snapshot " + std::to_string(req.compare_snapshot()) + " is not recorded");
  const bool live = snap == last && s.target().state() == debug::TargetState::stopped;
  const int depth = req.depth() == 0 ? 2 : static_cast<int>(std::min<std::uint32_t>(req.depth(), 8));
  resp.set_snapshot(snap);

  Evaluation now(s, e->program, env, snap, live);
  std::optional<Evaluation> then;
  if (req.has_compare_snapshot()) then.emplace(s, e->program, env, req.compare_snapshot(), false);

  // Parsed once: `is_type` sees the program's types.
  auto parse = [&](const std::string &text) {
    return ex::Expression::parse(text, [&](const std::string &n) { return now.types().by_name(n) != nullptr || ex::builtin(n, now.pointer_size()) != nullptr; });
  };
  // The frame for an item: the request's, else the innermost in its function.
  auto frame_for = [&](Evaluation &ev, std::optional<std::uint64_t> entry) -> std::optional<std::uint32_t> {
    if (req.has_frame()) {
      if (req.frame() == 0 || req.frame() < ev.frames().size()) return req.frame();
      return std::nullopt;
    }
    if (entry) return ev.frame_in(*entry);
    return 0u;
  };
  // One item in one evaluation; `location` and `name` for the caption.
  auto one = [&](Evaluation &ev, const pb::DebugEvalItem &item, std::string &location, std::string &name,
                 std::optional<std::uint32_t> &used, ex::Context &c) -> ex::Value {
    switch (item.what_case()) {
      case pb::DebugEvalItem::kExpression: {
        if (item.has_frame_function()) {
          used = ev.frame_in(item.frame_function().offset());
          if (!used) throw ex::ExprError("the function at 0x" + HexOf(item.frame_function().offset()).substr(2) + " is not on the stack");
        } else {
          used = frame_for(ev, std::nullopt);
        }
        c = ev.context(used);
        ex::Expression x = parse(item.expression());
        ex::Value v = x.evaluate(c);
        if (v.address) location = HexOf(*v.address);
        else if (!v.reg.empty()) location = v.reg;
        return v;
      }
      case pb::DebugEvalItem::kVariable: {
        const pb::DebugVariable &var = item.variable();
        name = var.name();
        const bool global = var.storage().empty() ||
                            std::all_of(var.storage().begin(), var.storage().end(), [](const pb::Varnode &vn) {
                              return vn.space() != "register" && vn.space() != "stack" && vn.space() != "unique";
                            });
        used = frame_for(ev, var.has_function() ? std::optional<std::uint64_t>(var.function().offset()) : std::nullopt);
        if (!used && global) used = 0u;
        c = ev.context(used);
        return ev.variable(var, used, location);
      }
      case pb::DebugEvalItem::kOperand: {
        const pb::DebugOperand &op = item.operand();
        std::optional<std::uint64_t> entry;
        if (e->program.function_at)
          if (auto fn = e->program.function_at(op.address().offset())) entry = fn->first;
        used = frame_for(ev, entry);
        if (!used) used = 0u;
        c = ev.context(used);
        const std::uint64_t runtime = s.to_runtime(op.address().offset());
        std::vector<std::uint8_t> bytes(32, 0);
        std::size_t n = 0;
        if (s.options().image) {
          n = s.options().image->memory.read(op.address().offset(),
                                             std::span<std::byte>(reinterpret_cast<std::byte *>(bytes.data()), bytes.size()));
        }
        if (n == 0) n = ev.read(runtime, bytes);
        if (n == 0) throw ex::ExprError("the instruction's bytes are not readable");
        bytes.resize(n);
        auto reader = [&](std::uint64_t a, unsigned size) -> std::optional<std::uint64_t> {
          std::vector<std::uint8_t> b(size);
          if (ev.read(a, b) < size) return std::nullopt;
          if (now.big_endian()) std::reverse(b.begin(), b.end());
          return debug::to_u64(b);
        };
        auto accesses = s.memory_accesses(runtime, bytes, ev.register_values(*used), reader, op.operand());
        if (accesses.empty()) throw ex::ExprError("the operand's address is not known (its registers are not, in this frame)");
        const debug::Session::MemoryAccess &a = accesses.front();
        ex::Value v;
        v.type = ex::undefined(a.size);
        v.address = a.address;
        location = HexOf(a.address);
        if (auto p = s.to_program(a.address); p && env.symbol_at) {
          const std::string sym = env.symbol_at(*p);
          if (!sym.empty()) location += " " + sym;
        }
        // Typed through the decompiler's variables: one at this stack slot or address.
        if (auto fn = ev.function_of(*used); fn && env.variables) {
          auto base = ev.entry_sp(*used);
          for (const pb::Variable &var : env.variables(fn->first)) {
            if (var.storage_size() != 1) continue;
            const pb::Varnode &vn = var.storage(0);
            std::optional<std::uint64_t> at;
            if (vn.space() == "stack" && base) {
              std::int64_t off = static_cast<std::int64_t>(vn.offset());
              if (now.pointer_size() < 8) off = static_cast<std::int32_t>(vn.offset());
              at = *base + static_cast<std::uint64_t>(off);
            } else if (vn.space() != "register" && vn.space() != "unique" && vn.space() != "const" && vn.space() != "stack") {
              at = s.to_runtime(vn.offset());
            }
            if (at && *at == a.address) {
              pb::DebugVariable dv;
              dv.mutable_function()->set_offset(fn->first);
              *dv.mutable_storage() = var.storage();
              *dv.mutable_type() = var.type();
              name = var.name();
              std::string where;
              return ev.variable(dv, used, where);
            }
          }
        }
        std::vector<std::uint8_t> b(a.size);
        if (ev.read(a.address, b) < b.size()) {
          v.unknown = "memory at " + HexOf(a.address) + " is not " + (live ? "readable" : "recorded at this snapshot");
          return v;
        }
        v.bytes = std::move(b);
        if (a.size > 8) v.type = ex::undefined(a.size);
        return v;
      }
      case pb::DebugEvalItem::WHAT_NOT_SET: break;
    }
    throw ex::ExprError("an item needs an expression, a variable or an operand");
  };

  std::optional<std::uint32_t> first_frame;
  for (const pb::DebugEvalItem &item : req.items()) {
    pb::DebugValue *out = resp.add_values();
    std::string location, name;
    std::optional<std::uint32_t> used;
    ex::Context c;
    ex::Value v;
    try {
      v = one(now, item, location, name, used, c);
      FillDebugValue(s, now, c, v, depth, out);
    } catch (const ex::ExprError &err) {
      out->set_error(err.what());
      out->set_text("??");
    } catch (const debug::DebugError &err) {
      out->set_error(err.what());
      out->set_text("??");
    }
    out->set_location(location);
    out->set_name(name);
    if (!first_frame && used) first_frame = used;
    if (then && out->error().empty()) {
      std::string l2, n2;
      std::optional<std::uint32_t> u2;
      ex::Context c2;
      try {
        ex::Value w = one(*then, item, l2, n2, u2, c2);
        out->set_changed(!w.unknown.empty() || w.bytes != v.bytes);
      } catch (const std::exception &) {
        out->set_changed(true);
      }
    }
  }
  resp.set_frame(first_frame.value_or(req.has_frame() ? req.frame() : 0));
  if (auto fn = now.function_of(resp.frame())) {
    resp.set_function(fn->second);
    resp.mutable_function_entry()->set_offset(fn->first);
  }
  return Status::Ok();
}

// --- Runtime disassembly (DisassembleDebugMemory; docs/debugger.md "Runtime disassembly") ---

Status DebugSessions::Disassemble(const api::CallContext &ctx, const pb::DisassembleDebugMemoryRequest &req,
                                  const DebugEvalEnv &env, pb::DisassembleDebugMemoryResponse &resp) {
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  debug::Session &s = *e->session;
  const std::uint64_t last = s.timeline().last();
  if (s.target().state() == debug::TargetState::running && !req.has_snapshot())
    return Error(StatusCode::kFailedPrecondition, "the target is running: interrupt it, or ask for a snapshot");
  const std::uint64_t snap = req.has_snapshot() ? req.snapshot() : last;
  const debug::Snapshot *at_snap = s.timeline().find(snap);
  if (at_snap == nullptr) return Error(StatusCode::kOutOfRange, "snapshot " + std::to_string(snap) + " is not recorded");
  const bool live = snap == last && s.target().state() == debug::TargetState::stopped;
  std::uint64_t at = 0;
  if (req.has_address()) {
    if (auto st = Runtime(s, req.address(), at); !st.ok()) return st;
  } else {
    at = live ? s.target().pc() : at_snap->pc;
  }
  const std::uint64_t pc = live ? s.target().pc() : at_snap->pc;
  Evaluation ev(s, e->program, env, snap, live);
  ev.unwind_libraries(*e);
  const std::uint32_t count = req.count() == 0 ? 32 : std::min<std::uint32_t>(req.count(), 512);
  auto arch = debug::UnwindArch::for_language(s.options().language);
  const std::uint32_t align = arch ? arch->insn_align : 1;
  // The bytes and the instruction at `a`.
  auto decode = [&](std::uint64_t a, std::vector<std::uint8_t> &bytes) -> std::optional<lift::Instruction> {
    bytes.assign(32, 0);
    const std::size_t n = ev.read(a, bytes);
    bytes.resize(n);
    if (n == 0) return std::nullopt;
    return s.disassemble(a, bytes);
  };
  // Start `before` instructions earlier: fixed-width ISAs step back; on
  // variable-length ones, the nearest start whose decoding lands on `at`.
  const std::uint32_t before = std::min<std::uint32_t>(req.before(), align > 1 ? 256 : 16);
  std::uint64_t start = at;
  if (before > 0) {
    if (align > 1) {
      start = at >= before * align ? at - before * align : 0;
    } else {
      std::optional<std::pair<std::uint32_t, std::uint64_t>> best;  // (instructions, start)
      std::vector<std::uint8_t> bytes;
      for (std::uint64_t d = 1; d <= before * 15ull && d <= at; ++d) {
        std::uint64_t a = at - d;
        std::uint32_t n = 0;
        while (a < at && n <= before) {
          auto insn = decode(a, bytes);
          if (!insn) break;
          a += insn->length + insn->delay_slot;
          ++n;
        }
        if (a != at || n > before) continue;
        if (!best || n > best->first) best = std::make_pair(n, at - d);
        if (n == before) break;
      }
      if (best) start = best->second;
    }
  }
  std::set<std::uint64_t> breaks;
  for (const debug::Breakpoint &b : s.breakpoints())
    if (!b.pending) breaks.insert(b.address);
  auto symbolize = [&](std::uint64_t runtime, pb::DebugLocation &loc) -> std::string {
    if (loc.has_program_address() && env.symbol_at) {
      std::string sym = env.symbol_at(loc.program_address().offset());
      if (!sym.empty()) return sym;
    }
    // A library that is a project program: "libc.so.6!strlen+0x10".
    if (!loc.library_function().empty()) return loc.module() + "!" + loc.library_function();
    if (!loc.module().empty()) return loc.module() + "+0x" + HexOf(loc.module_offset()).substr(2);
    (void)runtime;
    return {};
  };
  std::uint64_t a = start;
  std::vector<std::uint8_t> bytes;
  for (std::uint32_t i = 0; i < count; ++i) {
    pb::DebugInstruction *out = resp.add_instructions();
    FillLocation(*e, a, out->mutable_location());
    out->set_symbol(symbolize(a, *out->mutable_location()));
    out->set_pc(a == pc);
    out->set_breakpoint(breaks.count(a) != 0);
    auto insn = decode(a, bytes);
    if (!insn) {
      const std::size_t n = std::min<std::size_t>(std::max<std::uint32_t>(align, 1), bytes.size());
      if (bytes.empty()) {
        out->set_error(live ? "memory is not readable" : "memory is not recorded at this snapshot");
        resp.mutable_instructions()->RemoveLast();
        if (i == 0) resp.set_unreadable(true);
        break;
      }
      out->set_bytes(std::string(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(n)));
      out->set_mnemonic("??");
      out->set_error("does not decode");
      a += n;
      continue;
    }
    const std::uint32_t len = insn->length + insn->delay_slot;
    out->set_bytes(std::string(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(std::min<std::size_t>(len, bytes.size()))));
    out->set_mnemonic(insn->mnemonic);
    std::string ops = insn->text;
    if (ops.rfind(insn->mnemonic, 0) == 0) ops = ops.substr(insn->mnemonic.size());
    while (!ops.empty() && ops.front() == ' ') ops.erase(ops.begin());
    out->set_operands(ops);
    for (const lift::PcodeOp &op : insn->pcode) {
      const bool flow = op.opcode == "CALL" || op.opcode == "BRANCH" || op.opcode == "CBRANCH";
      if (op.opcode == "CALL" || op.opcode == "CALLIND") out->set_call(true);
      if (op.opcode == "RETURN") out->set_ret(true);
      if (op.opcode == "BRANCH" || op.opcode == "CBRANCH" || op.opcode == "BRANCHIND") out->set_branch(true);
      if (flow && !op.inputs.empty() && op.inputs[0].space != "const" && !out->has_target()) {
        out->set_target(op.inputs[0].offset);
        pb::DebugLocation tl;
        FillLocation(*e, op.inputs[0].offset, &tl);
        out->set_target_symbol(symbolize(op.inputs[0].offset, tl));
      }
    }
    a += len;
  }
  resp.set_snapshot(snap);
  resp.set_next(a);
  return Status::Ok();
}

// --- Copying runtime memory (CopyDebugMemory; docs/debugger.md "Copying runtime memory") ---

Status DebugSessions::ReadForCopy(const api::CallContext &ctx, const pb::CopyDebugMemoryRequest &req, DebugCopySource &out) {
  constexpr std::uint64_t kMax = 64ull << 20;
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  debug::Session &s = *e->session;
  out.program_id = e->program.program_id;
  const std::uint64_t last = s.timeline().last();
  if (s.target().state() == debug::TargetState::running && !req.has_snapshot())
    return Error(StatusCode::kFailedPrecondition, "the target is running: interrupt it, or ask for a snapshot");
  const std::uint64_t snap = req.has_snapshot() ? req.snapshot() : last;
  if (s.timeline().find(snap) == nullptr) return Error(StatusCode::kOutOfRange, "snapshot " + std::to_string(snap) + " is not recorded");
  const bool live = snap == last && s.target().state() == debug::TargetState::stopped;
  std::uint64_t at = 0;
  if (auto st = Runtime(s, req.address(), at); !st.ok()) return st;
  std::uint64_t length = req.length();
  // The target region holding it: its permissions, name and (with `region`) extent.
  std::vector<debug::MapRegion> map;
  if (live || req.region()) {
    try {
      map = s.memory_map();
    } catch (const debug::DebugError &) {
    }
  }
  for (const debug::MapRegion &r : map) {
    if (at < r.start || at - r.start >= r.size) continue;
    out.perms = r.perms;
    out.region_name = r.name;
    if (req.region()) {
      at = r.start;
      length = r.size;
    }
    break;
  }
  if (req.region() && out.perms.empty() && out.region_name.empty())
    return Error(StatusCode::kNotFound, "no region of the target's memory map holds 0x" + HexOf(at).substr(2));
  if (length == 0) return Error(StatusCode::kInvalidArgument, "length is required (or region)");
  if (length > kMax) return Error(StatusCode::kInvalidArgument, "more than 64 MiB: copy a smaller range");
  if (at + (length - 1) < at) return Error(StatusCode::kInvalidArgument, "the range wraps");
  out.runtime = at;
  out.program_address = s.to_program(at);
  out.bytes.assign(static_cast<std::size_t>(length), '\0');
  std::vector<bool> bad(static_cast<std::size_t>(length), false);
  constexpr std::size_t kChunk = 64 << 10;
  try {
    for (std::uint64_t done = 0; done < length; done += kChunk) {
      const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(kChunk, length - done));
      auto span = std::span<std::uint8_t>(reinterpret_cast<std::uint8_t *>(out.bytes.data()) + done, n);
      if (live) {
        std::vector<debug::ByteRange> holes;
        s.read_memory(at + done, span, &holes);
        for (const debug::ByteRange &h : holes)
          for (std::uint32_t i = 0; i < h.length && h.offset + i < n; ++i) bad[done + h.offset + i] = true;
      } else {
        std::vector<debug::Timeline::ByteState> state;
        s.memory_at(snap, at + done, span, state);
        for (std::size_t i = 0; i < state.size() && i < n; ++i)
          if (state[i] == debug::Timeline::ByteState::unknown) bad[done + i] = true;
      }
      if (ctx.cancelled()) return Error(StatusCode::kCancelled, "cancelled");
    }
  } catch (const debug::DebugError &err) {
    return DebugFailure(err);
  }
  for (std::size_t i = 0; i < bad.size();) {
    if (!bad[i]) {
      ++i;
      continue;
    }
    std::size_t j = i;
    while (j < bad.size() && bad[j]) ++j;
    out.unreadable.emplace_back(i, j - i);
    i = j;
  }
  return Status::Ok();
}

// --- Hooks (SetDebugHooks, AnswerDebugHook; docs/debugger.md "Hooks") ---

namespace {

DebugSessions::Entry::Hook *FindHook(DebugSessions::Entry &e, pb::DebugHookKind kind, const std::function<bool(const DebugSessions::Entry::Hook &)> &match) {
  for (auto &h : e.hooks)
    if (h.spec.kind() == kind && match(h)) return &h;
  return nullptr;
}

pb::DebugHookEvent HitOf(const DebugSessions::Entry::Hook &h, std::uint64_t pc) {
  pb::DebugHookEvent ev;
  ev.set_hook_id(h.id);
  ev.set_kind(h.spec.kind());
  ev.set_pc(pc);
  ev.set_name(h.spec.name());
  return ev;
}

// The answer waiting for this hook, taken.
std::optional<DebugSessions::Entry::Answer> TakeAnswer(DebugSessions::Entry &e, int hook) {
  if (!e.answer || e.answer->hook != hook) return std::nullopt;
  auto a = e.answer;
  e.answer.reset();
  return a;
}

void InstallHookHandlers(DebugSessions::Entry &e, emu::Emulator &em) {
  if (e.hooks_installed) return;
  e.hooks_installed = true;
  DebugSessions::Entry *ep = &e;
  e.base_syscall = em.syscall_hook();
  e.base_mmio = em.mmio_hook();
  em.on_syscall([ep](emu::Emulator &m, emu::Syscall &sc) -> emu::HookAction {
    auto *h = FindHook(*ep, pb::DEBUG_HOOK_KIND_SYSCALL, [&](const auto &x) {
      return x.spec.number() < 0 || static_cast<std::uint64_t>(x.spec.number()) == sc.number;
    });
    auto base = [&]() -> emu::HookAction {
      if (ep->base_syscall) return ep->base_syscall(m, sc);
      sc.note = "system call " + std::to_string(sc.number) + " with no handler";
      return emu::HookAction::stop;
    };
    if (h == nullptr) return base();
    if (auto a = TakeAnswer(*ep, h->id)) {
      if (a->proceed) return base();
      sc.result = a->value;
      sc.note = "system call " + std::to_string(sc.number) + " = " + std::to_string(a->value) + " (hook " + std::to_string(h->id) + ")";
      return emu::HookAction::proceed;
    }
    ++h->hits;
    pb::DebugHookEvent ev = HitOf(*h, m.pc());
    ev.set_number(static_cast<std::int64_t>(sc.number));
    for (std::uint64_t arg : sc.args) ev.add_args(arg);
    ep->hook_hit = ev;
    sc.note = "hook " + std::to_string(h->id) + ": system call " + std::to_string(sc.number);
    return emu::HookAction::stop;
  });
  em.on_mmio([ep](emu::Emulator &m, emu::MmioAccess &a) {
    auto *h = FindHook(*ep, pb::DEBUG_HOOK_KIND_MMIO, [&](const auto &x) {
      return a.address < x.address + x.size && x.address < a.address + a.size && (a.write ? x.spec.write() : x.spec.read());
    });
    if (h == nullptr) {
      if (ep->base_mmio) ep->base_mmio(m, a);
      return;
    }
    if (auto ans = TakeAnswer(*ep, h->id)) {
      if (!ans->proceed && !a.write) a.value = ans->value;
      else if (ep->base_mmio) ep->base_mmio(m, a);
      return;
    }
    ++h->hits;
    pb::DebugHookEvent ev = HitOf(*h, a.pc);
    ev.set_address(a.address);
    ev.set_size(a.size);
    ev.set_write(a.write);
    ev.set_value(a.value);
    ep->hook_hit = ev;
    a.stop = true;
    a.note = "hook " + std::to_string(h->id) + ": " + (a.write ? "write of " : "read of ") + std::to_string(a.size) + " bytes at 0x" + HexOf(a.address).substr(2);
  });
}

}  // namespace

Status DebugSessions::SetHooks(const api::CallContext &ctx, const pb::SetDebugHooksRequest &req, const DebugEvalEnv *env,
                               pb::SetDebugHooksResponse &resp) {
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  debug::Session &s = *e->session;
  auto *et = dynamic_cast<debug::EmulatorTarget *>(&s.target());
  if (et == nullptr) return Error(StatusCode::kFailedPrecondition, "hooks are for emulator sessions: a live target runs its own code");
  emu::Emulator &em = et->emulator();
  if (e->hooks.size() + static_cast<std::size_t>(req.add_size()) > 256) return Error(StatusCode::kResourceExhausted, "at most 256 hooks");
  auto drop = [&](const Entry::Hook &h) {
    switch (h.spec.kind()) {
      case pb::DEBUG_HOOK_KIND_FUNCTION: {
        bool user = false;
        for (const debug::Breakpoint &b : s.breakpoints())
          if (!b.pending && b.address == h.address && (b.kind == debug::BreakKind::software || b.kind == debug::BreakKind::hardware)) user = true;
        if (!user) em.remove_breakpoint(h.address);
        break;
      }
      case pb::DEBUG_HOOK_KIND_USEROP: em.remove_userop(h.spec.name()); break;
      default: break;
    }
  };
  if (req.clear()) {
    for (const auto &h : e->hooks) drop(h);
    e->hooks.clear();
    e->hook_hit.reset();
    e->answer.reset();
  }
  for (std::int32_t id : req.remove()) {
    auto it = std::find_if(e->hooks.begin(), e->hooks.end(), [&](const auto &h) { return h.id == id; });
    if (it == e->hooks.end()) return Error(StatusCode::kNotFound, "no hook " + std::to_string(id));
    drop(*it);
    e->hooks.erase(it);
  }
  for (const pb::DebugHookSpec &spec : req.add()) {
    Entry::Hook h;
    h.spec = spec;
    switch (spec.kind()) {
      case pb::DEBUG_HOOK_KIND_FUNCTION: {
        std::optional<std::uint64_t> at;
        if (spec.has_address()) {
          std::uint64_t a = 0;
          if (auto st = Runtime(s, spec.address(), a); !st.ok()) return st;
          at = a;
        } else if (!spec.name().empty()) {
          at = em.import_address(spec.name());
          if (!at && env && env->symbol)
            if (auto p = env->symbol(spec.name())) at = s.to_runtime(*p);
        }
        if (!at) return Error(StatusCode::kNotFound, spec.name().empty() ? "a function hook needs an address or a name" : "no import or function named " + spec.name());
        h.address = *at;
        if (h.spec.name().empty() && env && env->symbol_at)
          if (auto p = s.to_program(*at)) h.spec.set_name(env->symbol_at(*p));
        em.add_breakpoint(h.address);
        break;
      }
      case pb::DEBUG_HOOK_KIND_SYSCALL: break;
      case pb::DEBUG_HOOK_KIND_MMIO: {
        if (!spec.has_address()) return Error(StatusCode::kInvalidArgument, "an MMIO hook needs an address");
        std::uint64_t a = 0;
        if (auto st = Runtime(s, spec.address(), a); !st.ok()) return st;
        h.address = a;
        h.size = spec.size() == 0 ? 1 : spec.size();
        if (!spec.read() && !spec.write()) {
          h.spec.set_read(true);
          h.spec.set_write(true);
        }
        if (!em.mark_mmio(h.address, h.size))
          return Error(StatusCode::kFailedPrecondition, "no mapped memory at 0x" + HexOf(a).substr(2) + " for an MMIO hook");
        break;
      }
      case pb::DEBUG_HOOK_KIND_USEROP: {
        if (spec.name().empty()) return Error(StatusCode::kInvalidArgument, "a user-op hook needs the CALLOTHER's name");
        Entry *ep = e.get();
        const int id = e->next_hook;
        em.on_userop(spec.name(), [ep, id](emu::Emulator &m, emu::UseropCall &call) -> emu::HookAction {
          auto it = std::find_if(ep->hooks.begin(), ep->hooks.end(), [&](const auto &x) { return x.id == id; });
          if (it == ep->hooks.end()) return emu::HookAction::proceed;
          if (auto a = TakeAnswer(*ep, id)) {
            if (!a->proceed) call.output = a->value;
            call.note = call.name + " (hook " + std::to_string(id) + ")";
            return emu::HookAction::proceed;
          }
          ++it->hits;
          pb::DebugHookEvent ev = HitOf(*it, m.pc());
          for (std::uint64_t in : call.inputs) ev.add_args(in);
          ev.set_size(call.output_size);
          ep->hook_hit = ev;
          call.note = "hook " + std::to_string(id) + ": " + call.name;
          return emu::HookAction::stop;
        });
        break;
      }
      default: return Error(StatusCode::kInvalidArgument, "a hook needs a kind");
    }
    h.id = e->next_hook++;
    *h.spec.mutable_address() = spec.address();
    e->hooks.push_back(std::move(h));
  }
  InstallHookHandlers(*e, em);
  for (const auto &h : e->hooks) {
    pb::DebugHook *o = resp.add_hooks();
    o->set_id(h.id);
    *o->mutable_spec() = h.spec;
    o->set_address(h.address);
    o->set_hits(h.hits);
  }
  return Status::Ok();
}

Status DebugSessions::AnswerHook(const api::CallContext &ctx, const pb::AnswerDebugHookRequest &req, pb::AnswerDebugHookResponse &resp) {
  std::shared_ptr<Entry> e;
  std::unique_lock<std::mutex> lock;
  if (auto st = Acquire(ctx, req.session_id(), e, lock); !st.ok()) return st;
  if (!e->hook_hit || e->hook_hit->hook_id() != req.hook_id())
    return Error(StatusCode::kFailedPrecondition, "hook " + std::to_string(req.hook_id()) + " isn't waiting for an answer");
  const pb::DebugHookEvent hit = *e->hook_hit;
  e->hook_hit.reset();
  debug::Session &s = *e->session;
  auto *et = dynamic_cast<debug::EmulatorTarget *>(&s.target());
  if (et == nullptr) return Error(StatusCode::kFailedPrecondition, "not an emulator session");
  if (hit.kind() == pb::DEBUG_HOOK_KIND_FUNCTION) {
    if (req.has_value()) {
      try {
        et->emulator().return_from_call(req.value());
      } catch (const std::exception &err) {
        return Error(StatusCode::kFailedPrecondition, std::string("can't return from ") + hit.name() + ": " + err.what());
      }
      s.note_edit((hit.name().empty() ? "hook " + std::to_string(hit.hook_id()) : hit.name()) + " returned " + std::to_string(req.value()));
    }
    // Else the function runs: the next run starts on its first instruction.
  } else {
    e->answer = Entry::Answer{hit.hook_id(), !req.has_value(), req.value()};
  }
  return FillState(*e, req.state(), std::nullopt, resp.mutable_state());
}

}  // namespace revkit::backend
