// DebugService on the image backend: emulator sessions with time travel,
// saving and replaying traces (in memory and in a project directory), and
// live sessions (gdbserver launched by the daemon, and one it connects to)
// with breakpoints at the program's static addresses of a PIE.
#include "builders.hh"

#include "revkit/backend/image_backend.h"
#include "revkit/debug/gdb_remote.hh"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <thread>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

constexpr const char *kProgram = R"(
#include <stdio.h>
__attribute__((noinline)) int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
int counter;
// For hooks: a system call, a user op (RDTSC), a global read and written.
__attribute__((noinline)) long raw_getpid(void) {
  long r;
  __asm__ volatile("syscall" : "=a"(r) : "a"(39L) : "rcx", "r11", "memory");
  return r;
}
__attribute__((noinline)) unsigned long long ticks(void) { return __builtin_ia32_rdtsc(); }
__attribute__((noinline)) int peek(void) { return counter; }
__attribute__((noinline)) void poke(int v) { counter = v; }
int main(int argc, char **argv) {
  if (argc > 99) {
    poke((int)raw_getpid() + (int)ticks());
    counter += peek();
  }
  counter = fib(argc + 9);
  printf("fib %d\n", counter);
  return counter == 89 ? 0 : 1;
}
)";

class DebuggerApi : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("debugger-api");
    exe_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O1 -fno-inline -pie -fPIE", exe_);
  }
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!compiled_) GTEST_SKIP() << "no C compiler";
  }
  void Open(bool live, const std::string &project_dir = "") {
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.debug_live = live;
    o.project_dir = project_dir;
    backend_ = MakeImageBackend(o);
    pb::ListProgramsRequest lp;
    lp.set_project_id("default");
    pb::ListProgramsResponse lpr;
    if (backend_->ListPrograms(ctx_, lp, lpr).ok() && lpr.programs_size() > 0) {
      program_ = lpr.programs(0).program_id();
    } else {
      pb::ImportProgramRequest req;
      req.set_project_id("default");
      req.set_path(exe_.string());
      pb::ImportProgramResponse resp;
      auto st = backend_->ImportProgram(ctx_, req, resp);
      ASSERT_TRUE(st.ok()) << st.message;
      program_ = resp.program().program_id();
    }
    pb::ListFunctionsRequest lf;
    lf.set_program_id(program_);
    lf.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse lr;
    ASSERT_TRUE(backend_->ListFunctions(ctx_, lf, lr).ok());
    for (const auto &f : lr.functions()) functions_[f.name()] = f.entry().offset();
    ASSERT_TRUE(functions_.count("fib"));
    ASSERT_TRUE(functions_.count("main"));
  }
  pb::ResumeDebugSessionResponse Resume(const std::string &id, pb::DebugRunMode mode) {
    pb::ResumeDebugSessionRequest req;
    req.set_session_id(id);
    req.set_mode(mode);
    req.set_time_limit_ms(20000);
    pb::ResumeDebugSessionResponse resp;
    auto st = backend_->ResumeDebugSession(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }
  pb::DebugState State(const std::string &id, std::optional<std::uint64_t> snapshot = std::nullopt) {
    pb::GetDebugStateRequest req;
    req.set_session_id(id);
    if (snapshot) req.set_snapshot(*snapshot);
    pb::GetDebugStateResponse resp;
    auto st = backend_->GetDebugState(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.state();
  }
  static std::uint64_t Reg(const pb::DebugState &s, const std::string &name) {
    for (const auto &r : s.registers())
      if (r.name() == name) return r.value();
    ADD_FAILURE() << "no register " << name;
    return 0;
  }
  void Break(const std::string &id, std::uint64_t program_address) {
    pb::SetDebugBreakpointsRequest req;
    req.set_session_id(id);
    auto *b = req.add_add();
    b->mutable_address()->set_offset(program_address);
    b->mutable_address()->set_program(true);
    pb::SetDebugBreakpointsResponse resp;
    auto st = backend_->SetDebugBreakpoints(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    for (const auto &bp : resp.breakpoints()) {
      if (bp.location().program_address().offset() == program_address) {
        EXPECT_TRUE(bp.inserted()) << bp.error();
      }
    }
  }

  static inline std::filesystem::path exe_;
  static inline bool compiled_ = false;
  std::unique_ptr<api::Backend> backend_;
  CallContext ctx_;
  std::string program_;
  std::map<std::string, std::uint64_t> functions_;
};

TEST_F(DebuggerApi, EmulatorTimeTravelAndTraces) {
  Open(false);
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_GE(info.api_minor(), 14u);
  auto has = [&](const char *f) { return std::find(info.features().begin(), info.features().end(), f) != info.features().end(); };
  EXPECT_TRUE(has("debugger"));
  EXPECT_FALSE(has("debugger-live"));

  // Live targets are off without --debug-live.
  {
    pb::CreateDebugSessionRequest req;
    req.set_program_id(program_);
    req.mutable_launch();
    pb::CreateDebugSessionResponse resp;
    EXPECT_EQ(backend_->CreateDebugSession(ctx_, req, resp).code, StatusCode::kPermissionDenied);
  }

  pb::CreateDebugSessionRequest req;
  req.set_program_id(program_);
  req.mutable_emulator()->mutable_entry()->set_offset(functions_["fib"]);
  req.mutable_emulator()->set_mode(pb::EMULATOR_START_MODE_CALL);
  req.mutable_emulator()->add_arguments(6);
  req.set_client("test");
  pb::CreateDebugSessionResponse created;
  auto st = backend_->CreateDebugSession(ctx_, req, created);
  ASSERT_TRUE(st.ok()) << st.message;
  const std::string id = created.session_id();
  EXPECT_EQ(created.target_kind(), "emulator");
  EXPECT_EQ(created.pc_register(), "RIP");
  EXPECT_EQ(created.state().pc().program_address().offset(), functions_["fib"]);
  EXPECT_EQ(created.state().mapping().how(), "emulator");
  EXPECT_EQ(Reg(created.state(), "RDI"), 6u);

  Break(id, functions_["fib"]);
  auto r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT) << r.stop().detail();
  EXPECT_EQ(Reg(r.state(), "RDI"), 5u);  // fib(5), from fib(6)
  bool changed = false;
  for (const auto &reg : r.state().registers())
    if (reg.name() == "RDI") changed = reg.changed();
  EXPECT_TRUE(changed);

  // The timeline: the first instruction's snapshot, then each instruction.
  pb::GetDebugTimelineRequest tr;
  tr.set_session_id(id);
  pb::GetDebugTimelineResponse timeline;
  ASSERT_TRUE(backend_->GetDebugTimeline(ctx_, tr, timeline).ok());
  EXPECT_TRUE(timeline.complete());
  ASSERT_GT(timeline.count(), 3u);
  EXPECT_EQ(timeline.snapshots(0).kind(), pb::DEBUG_SNAPSHOT_KIND_STOP);
  EXPECT_EQ(timeline.snapshots(1).kind(), pb::DEBUG_SNAPSHOT_KIND_STEP);
  EXPECT_EQ(timeline.snapshots(timeline.snapshots_size() - 1).stop(), pb::DEBUG_STOP_KIND_BREAKPOINT);
  // Back to the start: fib(6) again.
  const auto then = State(id, timeline.first());
  EXPECT_TRUE(then.historical());
  EXPECT_EQ(Reg(then, "RDI"), 6u);
  EXPECT_EQ(then.pc().program_address().offset(), functions_["fib"]);
  // Memory at the start, where the recursive call later pushed its return
  // address: what was there before, exactly, though first written later.
  const std::uint64_t sp_now = Reg(r.state(), "RSP");
  pb::ReadDebugMemoryRequest mr;
  mr.set_session_id(id);
  mr.mutable_address()->set_offset(sp_now);
  mr.set_length(8);
  mr.set_snapshot(timeline.first());
  pb::ReadDebugMemoryResponse mem_then;
  ASSERT_TRUE(backend_->ReadDebugMemory(ctx_, mr, mem_then).ok());
  EXPECT_EQ(mem_then.unavailable_size(), 0);
  EXPECT_EQ(mem_then.stale_size(), 0);
  mr.clear_snapshot();
  pb::ReadDebugMemoryResponse mem_now;
  ASSERT_TRUE(backend_->ReadDebugMemory(ctx_, mr, mem_now).ok());
  std::uint64_t ret = 0;
  std::memcpy(&ret, mem_now.data().data(), 8);
  EXPECT_GT(ret, functions_["fib"]);  // a return address inside fib
  EXPECT_LT(ret, functions_["fib"] + 0x100);
  EXPECT_NE(mem_then.data(), mem_now.data());

  // Save, list, replay, delete.
  pb::SaveDebugTraceRequest sr;
  sr.set_session_id(id);
  sr.set_name("fib-run");
  pb::SaveDebugTraceResponse saved;
  st = backend_->SaveDebugTrace(ctx_, sr, saved);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_FALSE(saved.trace().persisted());
  EXPECT_EQ(saved.trace().snapshots(), timeline.count());
  sr.set_name("../bad");
  EXPECT_EQ(backend_->SaveDebugTrace(ctx_, sr, saved).code, StatusCode::kInvalidArgument);
  pb::ListDebugTracesRequest lt;
  lt.set_program_id(program_);
  pb::ListDebugTracesResponse traces;
  ASSERT_TRUE(backend_->ListDebugTraces(ctx_, lt, traces).ok());
  ASSERT_EQ(traces.traces_size(), 1);
  EXPECT_EQ(traces.traces(0).name(), "fib-run");
  EXPECT_EQ(traces.traces(0).target_kind(), "emulator");

  pb::CreateDebugSessionRequest open;
  open.set_program_id(program_);
  open.mutable_trace()->set_name("fib-run");
  pb::CreateDebugSessionResponse replay;
  st = backend_->CreateDebugSession(ctx_, open, replay);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(replay.target_kind(), "trace");
  EXPECT_EQ(replay.state().target_state(), pb::DEBUG_TARGET_STATE_REPLAY);
  EXPECT_EQ(Reg(replay.state(), "RDI"), 5u);
  EXPECT_EQ(Reg(State(replay.session_id(), timeline.first()), "RDI"), 6u);
  pb::ReadDebugMemoryResponse mem_replay;
  mr.set_session_id(replay.session_id());
  mr.set_snapshot(timeline.first());
  ASSERT_TRUE(backend_->ReadDebugMemory(ctx_, mr, mem_replay).ok());
  EXPECT_EQ(mem_replay.data(), mem_then.data());
  pb::ResumeDebugSessionRequest rr;
  rr.set_session_id(replay.session_id());
  pb::ResumeDebugSessionResponse rresp;
  EXPECT_EQ(backend_->ResumeDebugSession(ctx_, rr, rresp).code, StatusCode::kFailedPrecondition);

  pb::DeleteDebugTraceRequest dr;
  dr.set_program_id(program_);
  dr.set_name("fib-run");
  pb::DeleteDebugTraceResponse dresp;
  EXPECT_TRUE(backend_->DeleteDebugTrace(ctx_, dr, dresp).ok());
  EXPECT_EQ(backend_->DeleteDebugTrace(ctx_, dr, dresp).code, StatusCode::kNotFound);

  // Sessions are their owner's: another (authenticated, non-admin) caller
  // finds nothing there.
  {
    CallContext bob;
    bob.caller = "user:bob";
    bob.caller_admin = false;
    pb::GetDebugStateRequest gs;
    gs.set_session_id(id);
    pb::GetDebugStateResponse gr;
    EXPECT_EQ(backend_->GetDebugState(bob, gs, gr).code, StatusCode::kNotFound);
    pb::CloseDebugSessionRequest cr;
    cr.set_session_id(id);
    pb::CloseDebugSessionResponse cresp;
    EXPECT_EQ(backend_->CloseDebugSession(bob, cr, cresp).code, StatusCode::kNotFound);
    pb::ListDebugSessionsResponse theirs;
    ASSERT_TRUE(backend_->ListDebugSessions(bob, {}, theirs).ok());
    EXPECT_EQ(theirs.sessions_size(), 0);
  }

  pb::ListDebugSessionsRequest ls;
  ls.set_client("test");
  pb::ListDebugSessionsResponse sessions;
  ASSERT_TRUE(backend_->ListDebugSessions(ctx_, ls, sessions).ok());
  EXPECT_EQ(sessions.sessions_size(), 1);
  pb::CloseDebugSessionRequest close;
  close.set_session_id(id);
  pb::CloseDebugSessionResponse closed;
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
  EXPECT_EQ(backend_->CloseDebugSession(ctx_, close, closed).code, StatusCode::kNotFound);
}

// The call stack (api_minor 59, feature "debugger-stack"): in the emulator,
// fib's recursion with function names, and at a recorded snapshot; under
// gdbserver, fib called from main.
TEST_F(DebuggerApi, Backtrace) {
  Open(true);
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "debugger-stack"), info.features().end());
  auto bt = [&](const std::string &id, std::optional<std::uint64_t> snapshot = std::nullopt) {
    pb::GetDebugBacktraceRequest req;
    req.set_session_id(id);
    if (snapshot) req.set_snapshot(*snapshot);
    pb::GetDebugBacktraceResponse resp;
    auto st = backend_->GetDebugBacktrace(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  };
  {
    pb::CreateDebugSessionRequest req;
    req.set_program_id(program_);
    req.mutable_emulator()->mutable_entry()->set_offset(functions_["fib"]);
    req.mutable_emulator()->set_mode(pb::EMULATOR_START_MODE_CALL);
    req.mutable_emulator()->add_arguments(6);
    pb::CreateDebugSessionResponse created;
    ASSERT_TRUE(backend_->CreateDebugSession(ctx_, req, created).ok());
    const std::string id = created.session_id();
    Break(id, functions_["fib"]);
    // fib(6) at its entry; then fib(5) and fib(4) inside it.
    auto r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT) << r.stop().detail();
    const std::uint64_t second = r.state().snapshot();
    r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT) << r.stop().detail();
    auto frames = bt(id);
    EXPECT_TRUE(frames.unsupported().empty()) << frames.unsupported();
    ASSERT_GE(frames.frames_size(), 3) << frames.DebugString();
    for (int i = 0; i < 3; ++i) {
      EXPECT_EQ(frames.frames(i).function(), "fib") << i << frames.DebugString();
      EXPECT_EQ(frames.frames(i).function_entry().offset(), functions_["fib"]);
      EXPECT_EQ(frames.frames(i).level(), static_cast<std::uint32_t>(i));
    }
    EXPECT_EQ(frames.frames(0).function_offset(), 0u);
    EXPECT_GT(frames.frames(1).function_offset(), 0u);
    EXPECT_NE(frames.frames(1).how(), "registers");
    bool has_sp = false;
    for (const auto &rv : frames.frames(1).registers()) has_sp = has_sp || (rv.name() == "RSP" && rv.value() == frames.frames(1).sp());
    EXPECT_TRUE(has_sp);
    // At the earlier stop: one frame fewer of fib.
    auto then = bt(id, second);
    ASSERT_GE(then.frames_size(), 2);
    EXPECT_EQ(then.frames(0).function(), "fib");
    EXPECT_EQ(then.frames(1).function(), "fib");
    EXPECT_LT(then.frames_size(), frames.frames_size());
    pb::CloseDebugSessionRequest close;
    close.set_session_id(id);
    pb::CloseDebugSessionResponse closed;
    EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
  }
  if (debug::find_program("gdbserver").empty()) GTEST_SKIP() << "gdbserver is not installed";
  pb::CreateDebugSessionRequest req;
  req.set_program_id(program_);
  req.mutable_launch();
  auto *b = req.add_breakpoints();
  b->mutable_address()->set_offset(functions_["fib"]);
  b->mutable_address()->set_program(true);
  pb::CreateDebugSessionResponse created;
  ASSERT_TRUE(backend_->CreateDebugSession(ctx_, req, created).ok());
  const std::string id = created.session_id();
  auto r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT) << r.stop().detail();
  auto frames = bt(id);
  ASSERT_GE(frames.frames_size(), 2) << frames.DebugString();
  EXPECT_EQ(frames.frames(0).function(), "fib");
  EXPECT_EQ(frames.frames(1).function(), "main") << frames.DebugString();
  EXPECT_TRUE(frames.frames(1).pc().has_program_address());
  pb::CloseDebugSessionRequest close;
  close.set_session_id(id);
  pb::CloseDebugSessionResponse closed;
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
}

// Values (api_minor 60, feature "debugger-values"): expressions over
// registers and symbols, a decompiler variable through its storage, a
// listing operand's memory, changed marks against an earlier stop.
TEST_F(DebuggerApi, Values) {
  Open(true);
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "debugger-values"), info.features().end());
  // fib's parameter, as the decompiler has it.
  pb::DecompileRequest dr;
  dr.set_program_id(program_);
  dr.mutable_function()->set_offset(functions_["fib"]);
  pb::DecompileResponse dresp;
  ASSERT_TRUE(backend_->Decompile(ctx_, dr, dresp).ok());
  const pb::Variable *param = nullptr;
  for (const auto &v : dresp.function().variables())
    if (v.kind() == pb::VARIABLE_KIND_PARAMETER) param = &v;
  ASSERT_NE(param, nullptr) << dresp.function().DebugString();
  auto variable = [&](pb::DebugEvalItem *item) {
    auto *v = item->mutable_variable();
    v->mutable_function()->set_offset(functions_["fib"]);
    *v->mutable_storage() = param->storage();
    *v->mutable_type() = param->type();
    v->set_name(param->name());
  };
  auto eval = [&](const std::string &id, const std::vector<std::string> &exprs, std::optional<std::uint64_t> compare = std::nullopt,
                  bool with_variable = false, std::optional<std::uint32_t> frame = std::nullopt) {
    pb::EvaluateDebugRequest req;
    req.set_session_id(id);
    for (const auto &x : exprs) req.add_items()->set_expression(x);
    if (with_variable) variable(req.add_items());
    if (compare) req.set_compare_snapshot(*compare);
    if (frame) req.set_frame(*frame);
    pb::EvaluateDebugResponse resp;
    auto st = backend_->EvaluateDebug(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  };

  pb::CreateDebugSessionRequest req;
  req.set_program_id(program_);
  req.mutable_emulator()->mutable_entry()->set_offset(functions_["fib"]);
  req.mutable_emulator()->set_mode(pb::EMULATOR_START_MODE_CALL);
  req.mutable_emulator()->add_arguments(6);
  pb::CreateDebugSessionResponse created;
  ASSERT_TRUE(backend_->CreateDebugSession(ctx_, req, created).ok());
  const std::string id = created.session_id();
  Break(id, functions_["fib"]);
  auto r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT);
  const std::uint64_t first = r.state().snapshot();
  r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT);
  // fib(4) called from fib(5) (the run from fib(6)'s entry stopped in fib(5) first).
  auto v = eval(id, {"$RDI", "RDI + 1", "EDI", "$rdi * 2 == 8 && 1", "*(int *)counter", "counter", "nosuch", "1 +", param->name() + " - 1",
                     "(char)0x41", "sizeof(int)"},
                first, true);
  ASSERT_EQ(v.values_size(), 12);
  EXPECT_EQ(v.values(0).text(), "0x4");
  EXPECT_EQ(v.values(0).register_name(), "RDI");
  EXPECT_TRUE(v.values(0).changed());  // 5 at the first stop
  EXPECT_EQ(v.values(1).text(), "5");
  EXPECT_EQ(v.values(2).text(), "0x4");
  EXPECT_EQ(v.values(3).text(), "1");
  EXPECT_EQ(v.values(4).text(), "0") << v.values(4).error();
  EXPECT_FALSE(v.values(4).changed());
  EXPECT_EQ(v.values(5).hex(), v.values(5).text());  // an untyped symbol: its address
  EXPECT_NE(v.values(6).error().find("nosuch"), std::string::npos);
  EXPECT_FALSE(v.values(7).error().empty());
  EXPECT_EQ(v.values(8).text(), "3") << v.values(8).error();
  EXPECT_EQ(v.values(9).text(), "65 'A'");
  EXPECT_EQ(v.values(10).text(), "4");
  EXPECT_EQ(v.values(11).text(), "4") << v.values(11).error() << " " << param->DebugString();
  EXPECT_EQ(v.values(11).name(), param->name());
  EXPECT_FALSE(v.values(11).location().empty());
  EXPECT_EQ(v.frame(), 0u);
  EXPECT_EQ(v.function(), "fib");
  // At the first stop (a snapshot): fib(5).
  {
    pb::EvaluateDebugRequest at;
    at.set_session_id(id);
    at.set_snapshot(first);
    at.add_items()->set_expression("$RDI");
    variable(at.add_items());
    pb::EvaluateDebugResponse resp;
    ASSERT_TRUE(backend_->EvaluateDebug(ctx_, at, resp).ok());
    EXPECT_EQ(resp.values(0).text(), "0x5");
    EXPECT_EQ(resp.values(1).text(), "5") << resp.values(1).error();
  }
  // A watch on a function's variable (api_minor 61): in its innermost frame, whatever the request's frame.
  {
    pb::EvaluateDebugRequest at;
    at.set_session_id(id);
    at.set_frame(1);
    auto *in_fib = at.add_items();
    in_fib->set_expression(param->name());
    in_fib->mutable_frame_function()->set_offset(functions_["fib"]);
    auto *in_main = at.add_items();
    in_main->set_expression("1");
    in_main->mutable_frame_function()->set_offset(functions_["main"]);
    pb::EvaluateDebugResponse resp;
    ASSERT_TRUE(backend_->EvaluateDebug(ctx_, at, resp).ok());
    EXPECT_EQ(resp.values(0).text(), "4") << resp.values(0).error();
    EXPECT_NE(resp.values(1).error().find("not on the stack"), std::string::npos) << resp.values(1).DebugString();
  }
  // The first push's memory: the stack slot below RSP (after an endbr64, if the compiler put one first).
  {
    pb::EvaluateDebugRequest at;
    at.set_session_id(id);
    for (std::uint64_t off : {0, 4}) {
      auto *op = at.add_items()->mutable_operand();
      op->mutable_address()->set_offset(functions_["fib"] + off);
      op->set_operand(-1);
    }
    pb::EvaluateDebugResponse resp;
    ASSERT_TRUE(backend_->EvaluateDebug(ctx_, at, resp).ok());
    if (!resp.values(0).error().empty()) resp.mutable_values()->SwapElements(0, 1);
    ASSERT_TRUE(resp.values(0).error().empty()) << resp.DebugString();
    EXPECT_EQ(resp.values(0).address(), Reg(r.state(), "RSP") - 8);
    EXPECT_EQ(resp.values(0).type(), "undefined8");
  }
  pb::CloseDebugSessionRequest close;
  close.set_session_id(id);
  pb::CloseDebugSessionResponse closed;
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());

  // Live, under gdbserver: fib(10) from main.
  if (debug::find_program("gdbserver").empty()) GTEST_SKIP() << "gdbserver is not installed";
  pb::CreateDebugSessionRequest lr;
  lr.set_program_id(program_);
  lr.mutable_launch();
  auto *b = lr.add_breakpoints();
  b->mutable_address()->set_offset(functions_["fib"]);
  b->mutable_address()->set_program(true);
  pb::CreateDebugSessionResponse lc;
  ASSERT_TRUE(backend_->CreateDebugSession(ctx_, lr, lc).ok());
  r = Resume(lc.session_id(), pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT);
  v = eval(lc.session_id(), {"$RDI", "*(int *)counter"}, std::nullopt, true);
  EXPECT_EQ(v.values(0).text(), "0xa");
  EXPECT_EQ(v.values(1).text(), "0") << v.values(1).error();
  EXPECT_EQ(v.values(2).text(), "10") << v.values(2).error();
  close.set_session_id(lc.session_id());
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
}

// Runtime disassembly (api_minor 62, feature "debugger-disassembly"): at
// the pc with context before it, at a static address, and in a library
// the program doesn't contain.
TEST_F(DebuggerApi, Disassembly) {
  Open(true);
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "debugger-disassembly"), info.features().end());
  if (debug::find_program("gdbserver").empty()) GTEST_SKIP() << "gdbserver is not installed";
  pb::CreateDebugSessionRequest lr;
  lr.set_program_id(program_);
  lr.mutable_launch();
  auto *b = lr.add_breakpoints();
  b->mutable_address()->set_offset(functions_["fib"]);
  b->mutable_address()->set_program(true);
  pb::CreateDebugSessionResponse lc;
  ASSERT_TRUE(backend_->CreateDebugSession(ctx_, lr, lc).ok());
  const std::string id = lc.session_id();
  auto r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT);
  auto disas = [&](std::optional<pb::DebugAddress> at, std::uint32_t count, std::uint32_t before) {
    pb::DisassembleDebugMemoryRequest req;
    req.set_session_id(id);
    if (at) *req.mutable_address() = *at;
    req.set_count(count);
    req.set_before(before);
    pb::DisassembleDebugMemoryResponse resp;
    auto st = backend_->DisassembleDebugMemory(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  };
  // At the pc, with three instructions before it.
  auto d = disas(std::nullopt, 8, 3);
  ASSERT_GE(d.instructions_size(), 4);
  int at_pc = -1;
  for (int i = 0; i < d.instructions_size(); ++i)
    if (d.instructions(i).pc()) at_pc = i;
  ASSERT_GE(at_pc, 1) << d.DebugString();
  EXPECT_EQ(d.instructions(at_pc).location().program_address().offset(), functions_["fib"]);
  EXPECT_EQ(d.instructions(at_pc).symbol(), "fib");
  EXPECT_TRUE(d.instructions(at_pc).breakpoint());
  EXPECT_FALSE(d.instructions(at_pc).mnemonic().empty());
  // Contiguous: each starts where the one before ended.
  for (int i = 1; i < d.instructions_size(); ++i)
    EXPECT_EQ(d.instructions(i).location().address().offset(),
              d.instructions(i - 1).location().address().offset() + d.instructions(i - 1).bytes().size());
  EXPECT_EQ(d.next(), d.instructions(d.instructions_size() - 1).location().address().offset() +
                          d.instructions(d.instructions_size() - 1).bytes().size());
  // main by its static address: its call to fib names it.
  pb::DebugAddress main_at;
  main_at.set_offset(functions_["main"]);
  main_at.set_program(true);
  d = disas(main_at, 40, 0);
  bool calls_fib = false;
  for (const auto &ins : d.instructions())
    if (ins.call() && ins.target_symbol() == "fib") calls_fib = true;
  EXPECT_TRUE(calls_fib) << d.DebugString();
  // In the C library: the frame that called main.
  pb::GetDebugBacktraceRequest br;
  br.set_session_id(id);
  pb::GetDebugBacktraceResponse bt;
  ASSERT_TRUE(backend_->GetDebugBacktrace(ctx_, br, bt).ok());
  for (const auto &f : bt.frames()) {
    if (f.pc().has_program_address()) continue;
    pb::DebugAddress lib;
    lib.set_offset(f.pc().address().offset());
    d = disas(lib, 4, 0);
    ASSERT_GE(d.instructions_size(), 1);
    EXPECT_FALSE(d.instructions(0).location().has_program_address());
    EXPECT_FALSE(d.instructions(0).mnemonic().empty());
    EXPECT_TRUE(d.instructions(0).error().empty());
    break;
  }
  // Unreadable memory.
  pb::DebugAddress nowhere;
  nowhere.set_offset(8);
  d = disas(nowhere, 4, 0);
  EXPECT_TRUE(d.unreadable());
  EXPECT_EQ(d.instructions_size(), 0);
  pb::CloseDebugSessionRequest close;
  close.set_session_id(id);
  pb::CloseDebugSessionResponse closed;
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
}

// Copying runtime memory (api_minor 63, feature "debugger-copy"): changed
// code back into the program as patches (only what differs, one
// revision), the stack as a new block at its runtime address, the C
// library as a new program.
TEST_F(DebuggerApi, CopyMemory) {
  Open(true);
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "debugger-copy"), info.features().end());
  if (debug::find_program("gdbserver").empty()) GTEST_SKIP() << "gdbserver is not installed";
  pb::CreateDebugSessionRequest lr;
  lr.set_program_id(program_);
  lr.mutable_launch();
  auto *bp = lr.add_breakpoints();
  bp->mutable_address()->set_offset(functions_["fib"]);
  bp->mutable_address()->set_program(true);
  pb::CreateDebugSessionResponse lc;
  ASSERT_TRUE(backend_->CreateDebugSession(ctx_, lr, lc).ok());
  const std::string id = lc.session_id();
  auto r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT);
  auto copy = [&](pb::DebugAddress at, std::uint64_t length, bool region, pb::DebugCopyMode mode, pb::CopyDebugMemoryResponse &resp) {
    pb::CopyDebugMemoryRequest req;
    req.set_session_id(id);
    *req.mutable_address() = at;
    req.set_length(length);
    req.set_region(region);
    req.set_mode(mode);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("test");
    return backend_->CopyDebugMemory(ctx_, req, resp);
  };
  pb::DebugAddress main_at;
  main_at.set_offset(functions_["main"] + 4);
  main_at.set_program(true);
  // The same bytes as the program: nothing to patch.
  {
    pb::CopyDebugMemoryResponse resp;
    auto st = copy(main_at, 16, false, pb::DEBUG_COPY_MODE_PATCH, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    EXPECT_EQ(resp.changed(), 0u);
    EXPECT_EQ(resp.seqs_size(), 0);
    EXPECT_EQ(resp.program_address(), functions_["main"] + 4);
  }
  // Two bytes changed in the process: two bytes patched, in one revision.
  {
    pb::WriteDebugMemoryRequest wr;
    wr.set_session_id(id);
    pb::DebugAddress at = main_at;
    at.set_offset(at.offset() + 5);
    *wr.mutable_address() = at;
    wr.set_data(std::string("\x90\x90", 2));
    ASSERT_TRUE(backend_->WriteDebugMemory(ctx_, wr, *std::make_unique<pb::WriteDebugMemoryResponse>()).ok());
    pb::CopyDebugMemoryResponse resp;
    auto st = copy(main_at, 16, false, pb::DEBUG_COPY_MODE_PATCH, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    EXPECT_GE(resp.changed(), 1u);
    EXPECT_LE(resp.changed(), 2u);  // one of them may have been 0x90 already
    EXPECT_GE(resp.seqs_size(), 1);
    pb::ListPatchesRequest lp;
    lp.set_program_id(program_);
    pb::ListPatchesResponse patches;
    ASSERT_TRUE(backend_->ListPatches(ctx_, lp, patches).ok());
    bool found = false;
    for (const auto &p : patches.patches())
      if (p.address().offset() <= functions_["main"] + 9 && p.address().offset() + p.bytes().size() > functions_["main"] + 9) found = true;
    EXPECT_TRUE(found) << patches.DebugString();
  }
  // The stack: a new block at its runtime address; inside the program a block is refused.
  {
    pb::DebugAddress sp;
    sp.set_offset(Reg(r.state(), "RSP"));
    pb::CopyDebugMemoryResponse resp;
    auto st = copy(sp, 0, true, pb::DEBUG_COPY_MODE_BLOCK, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    EXPECT_LE(resp.address(), sp.offset());
    EXPECT_GT(resp.address() + resp.length(), sp.offset());
    EXPECT_FALSE(resp.region_id().empty());
    EXPECT_EQ(resp.block().range().first().offset(), resp.address());
    EXPECT_NE(resp.block().name().find("stack"), std::string::npos) << resp.block().name();
    EXPECT_EQ(resp.seqs_size(), 1);
    pb::CopyDebugMemoryResponse again;
    st = copy(main_at, 16, false, pb::DEBUG_COPY_MODE_BLOCK, again);
    EXPECT_FALSE(st.ok());
    EXPECT_NE(st.message.find("patches"), std::string::npos) << st.message;
  }
  // The C library's code, where the program's caller runs: a new program based there.
  {
    pb::GetDebugBacktraceRequest br;
    br.set_session_id(id);
    pb::GetDebugBacktraceResponse bt;
    ASSERT_TRUE(backend_->GetDebugBacktrace(ctx_, br, bt).ok());
    std::optional<std::uint64_t> lib;
    for (const auto &f : bt.frames())
      if (!f.pc().has_program_address()) {
        lib = f.pc().address().offset();
        break;
      }
    ASSERT_TRUE(lib.has_value());
    pb::DebugAddress at;
    at.set_offset(*lib);
    pb::CopyDebugMemoryResponse resp;
    auto st = copy(at, 4096, false, pb::DEBUG_COPY_MODE_NEW_PROGRAM, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    EXPECT_FALSE(resp.program().program_id().empty());
    EXPECT_EQ(resp.program_address(), *lib);
    pb::GetMemoryMapRequest mr;
    mr.set_program_id(resp.program().program_id());
    pb::GetMemoryMapResponse map;
    ASSERT_TRUE(backend_->GetMemoryMap(ctx_, mr, map).ok());
    ASSERT_GE(map.blocks_size(), 1);
    EXPECT_EQ(map.blocks(0).range().first().offset(), *lib);
    EXPECT_TRUE(map.blocks(0).execute());
  }
  pb::CloseDebugSessionRequest close;
  close.set_session_id(id);
  pb::CloseDebugSessionResponse closed;
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
}

// Conditional breakpoints (api_minor 64, feature "debugger-conditions"): a
// condition over registers, an ignore count, a disabled breakpoint, a
// condition that can't be evaluated stopping with its error; live, the
// passed-over stops are not recorded.
TEST_F(DebuggerApi, ConditionalBreakpoints) {
  Open(true);
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "debugger-conditions"), info.features().end());
  auto set = [&](const std::string &id, std::function<void(pb::SetDebugBreakpointsRequest &)> fill) {
    pb::SetDebugBreakpointsRequest req;
    req.set_session_id(id);
    fill(req);
    pb::SetDebugBreakpointsResponse resp;
    auto st = backend_->SetDebugBreakpoints(ctx_, req, resp);
    return std::make_pair(st, resp);
  };
  pb::CreateDebugSessionRequest req;
  req.set_program_id(program_);
  req.mutable_emulator()->mutable_entry()->set_offset(functions_["fib"]);
  req.mutable_emulator()->set_mode(pb::EMULATOR_START_MODE_CALL);
  req.mutable_emulator()->add_arguments(6);
  pb::CreateDebugSessionResponse created;
  ASSERT_TRUE(backend_->CreateDebugSession(ctx_, req, created).ok());
  const std::string id = created.session_id();
  // A condition that doesn't parse is refused.
  auto [bad, bad_resp] = set(id, [&](auto &r) {
    auto *b = r.add_add();
    b->mutable_address()->set_offset(functions_["fib"]);
    b->mutable_address()->set_program(true);
    b->set_condition("$RDI ==");
  });
  EXPECT_EQ(bad.code, StatusCode::kInvalidArgument);
  auto [st, bps] = set(id, [&](auto &r) {
    auto *b = r.add_add();
    b->mutable_address()->set_offset(functions_["fib"]);
    b->mutable_address()->set_program(true);
    b->set_condition("$RDI == 2");
  });
  ASSERT_TRUE(st.ok()) << st.message;
  ASSERT_EQ(bps.breakpoints_size(), 1);
  const int bp = bps.breakpoints(0).id();
  EXPECT_EQ(bps.breakpoints(0).condition(), "$RDI == 2");
  auto r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT) << r.stop().detail();
  EXPECT_EQ(Reg(r.state(), "RDI"), 2u);
  ASSERT_EQ(r.state().breakpoints_size(), 1);
  EXPECT_EQ(r.state().breakpoints(0).hits(), 4u);  // fib(5), fib(4), fib(3), then fib(2)
  // Without the condition, after three more hits.
  auto [st2, bps2] = set(id, [&](auto &r) {
    auto *u = r.add_update();
    u->set_id(bp);
    u->set_condition("");
    u->set_ignore_count(7);  // hits counted so far: 4
  });
  ASSERT_TRUE(st2.ok()) << st2.message;
  r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT);
  EXPECT_EQ(r.state().breakpoints(0).hits(), 8u);
  // A condition naming nothing: it stops, saying why.
  set(id, [&](auto &r) {
    auto *u = r.add_update();
    u->set_id(bp);
    u->set_condition("nosuch > 1");
  });
  r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT);
  EXPECT_NE(r.state().breakpoints(0).condition_error().find("nosuch"), std::string::npos) << r.state().breakpoints(0).DebugString();
  // Disabled: the run returns from fib(6).
  auto [st3, bps3] = set(id, [&](auto &r) {
    auto *u = r.add_update();
    u->set_id(bp);
    u->set_disabled(true);
  });
  ASSERT_TRUE(st3.ok());
  EXPECT_TRUE(bps3.breakpoints(0).disabled());
  EXPECT_FALSE(bps3.breakpoints(0).inserted());
  r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  EXPECT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_RETURNED) << r.stop().detail();
  pb::CloseDebugSessionRequest close;
  close.set_session_id(id);
  pb::CloseDebugSessionResponse closed;
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());

  // Live: fib(10)'s recursion, stopping where n is 3; one stop recorded.
  if (debug::find_program("gdbserver").empty()) GTEST_SKIP() << "gdbserver is not installed";
  pb::CreateDebugSessionRequest lr;
  lr.set_program_id(program_);
  lr.mutable_launch();
  auto *b = lr.add_breakpoints();
  b->mutable_address()->set_offset(functions_["fib"]);
  b->mutable_address()->set_program(true);
  b->set_condition("(int)$RDI == 3");
  b->set_ignore_count(2);
  pb::CreateDebugSessionResponse lc;
  ASSERT_TRUE(backend_->CreateDebugSession(ctx_, lr, lc).ok());
  const std::uint64_t before = lc.state().last_snapshot();
  r = Resume(lc.session_id(), pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT) << r.stop().detail();
  EXPECT_EQ(Reg(r.state(), "RDI"), 3u);
  EXPECT_GT(r.state().breakpoints(0).hits(), 3u);
  EXPECT_EQ(r.state().last_snapshot(), before + 1);
  close.set_session_id(lc.session_id());
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
}

// Rewinding (api_minor 65, feature "debugger-rewind"): back to an earlier
// stop, the later snapshots saved as a trace first; step back; live
// sessions refuse.
TEST_F(DebuggerApi, Rewind) {
  Open(true);
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "debugger-rewind"), info.features().end());
  pb::CreateDebugSessionRequest req;
  req.set_program_id(program_);
  req.mutable_emulator()->mutable_entry()->set_offset(functions_["fib"]);
  req.mutable_emulator()->set_mode(pb::EMULATOR_START_MODE_CALL);
  req.mutable_emulator()->add_arguments(6);
  pb::CreateDebugSessionResponse created;
  ASSERT_TRUE(backend_->CreateDebugSession(ctx_, req, created).ok());
  const std::string id = created.session_id();
  EXPECT_TRUE(created.state().rewindable());
  Break(id, functions_["fib"]);
  auto r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT);
  const std::uint64_t first = r.state().last_snapshot();  // fib(5)
  r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(Reg(r.state(), "RDI"), 3u);
  const std::uint64_t last = r.state().last_snapshot();
  pb::RewindDebugSessionRequest rw;
  rw.set_session_id(id);
  rw.set_snapshot(first);
  rw.set_save_branch_as("before-rewind");
  pb::RewindDebugSessionResponse back;
  auto st = backend_->RewindDebugSession(ctx_, rw, back);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(back.discarded(), last - first);
  EXPECT_EQ(back.saved().name(), "before-rewind");
  EXPECT_EQ(back.state().last_snapshot(), first);
  EXPECT_EQ(Reg(back.state(), "RDI"), 5u);
  // On again: the same next stop, at the next index.
  r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT);
  EXPECT_EQ(Reg(r.state(), "RDI"), 4u);
  // Step back: one instruction.
  pb::RewindDebugSessionRequest sb;
  sb.set_session_id(id);
  sb.set_step_back(true);
  pb::RewindDebugSessionResponse one;
  ASSERT_TRUE(backend_->RewindDebugSession(ctx_, sb, one).ok());
  EXPECT_EQ(one.discarded(), 1u);
  EXPECT_EQ(one.state().last_snapshot(), r.state().last_snapshot() - 1);
  EXPECT_NE(one.state().pc().program_address().offset(), functions_["fib"]);
  // The branch that was: a trace, replayable.
  pb::ListDebugTracesRequest lt;
  lt.set_program_id(program_);
  pb::ListDebugTracesResponse traces;
  ASSERT_TRUE(backend_->ListDebugTraces(ctx_, lt, traces).ok());
  bool saved = false;
  for (const auto &t : traces.traces()) saved = saved || t.name() == "before-rewind";
  EXPECT_TRUE(saved);
  pb::CloseDebugSessionRequest close;
  close.set_session_id(id);
  pb::CloseDebugSessionResponse closed;
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
  // A trace session can't go back.
  pb::CreateDebugSessionRequest tr;
  tr.set_program_id(program_);
  tr.mutable_trace()->set_name("before-rewind");
  pb::CreateDebugSessionResponse tc;
  ASSERT_TRUE(backend_->CreateDebugSession(ctx_, tr, tc).ok());
  EXPECT_FALSE(tc.state().rewindable());
  rw.set_session_id(tc.session_id());
  rw.set_snapshot(0);
  rw.clear_save_branch_as();
  EXPECT_EQ(backend_->RewindDebugSession(ctx_, rw, back).code, StatusCode::kFailedPrecondition);
  close.set_session_id(tc.session_id());
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
}

// Emulating from a live stop (api_minor 66, feature "debugger-emulate-from"):
// the emulator takes the process's registers and reads its memory when
// first touched; it runs fib(10) to its end on that state, writes its own
// copy of the global, and the process is as it was.
TEST_F(DebuggerApi, EmulateFromALiveStop) {
  Open(true);
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "debugger-emulate-from"), info.features().end());
  if (debug::find_program("gdbserver").empty()) GTEST_SKIP() << "gdbserver is not installed";
  pb::CreateDebugSessionRequest lr;
  lr.set_program_id(program_);
  lr.mutable_launch();
  auto *b = lr.add_breakpoints();
  b->mutable_address()->set_offset(functions_["fib"]);
  b->mutable_address()->set_program(true);
  pb::CreateDebugSessionResponse lc;
  ASSERT_TRUE(backend_->CreateDebugSession(ctx_, lr, lc).ok());
  const std::string live = lc.session_id();
  auto r = Resume(live, pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT);
  const std::uint64_t live_rsp = Reg(r.state(), "RSP");
  ASSERT_EQ(Reg(r.state(), "RDI"), 10u);

  pb::CreateDebugSessionRequest er;
  er.set_program_id(program_);
  er.mutable_emulator()->set_from_session(live);
  pb::CreateDebugSessionResponse ec;
  auto st = backend_->CreateDebugSession(ctx_, er, ec);
  ASSERT_TRUE(st.ok()) << st.message;
  const std::string emu = ec.session_id();
  EXPECT_EQ(ec.target_kind(), "emulator");
  EXPECT_EQ(ec.state().pc().program_address().offset(), functions_["fib"]);
  EXPECT_EQ(Reg(ec.state(), "RDI"), 10u);
  EXPECT_EQ(Reg(ec.state(), "RSP"), live_rsp);
  // fib(10) to its return, in the emulator, on the process's stack and code.
  auto out = Resume(emu, pb::DEBUG_RUN_MODE_STEP_OUT);
  ASSERT_NE(out.stop().kind(), pb::DEBUG_STOP_KIND_UNMAPPED) << out.stop().detail();
  EXPECT_EQ(Reg(out.state(), "RAX") & 0xffffffff, 55u) << out.stop().DebugString();
  EXPECT_GE(out.state().pc().program_address().offset(), functions_["main"]);
  // On a little: main stores the result into counter, in the emulator's memory only.
  for (int i = 0; i < 4; ++i) Resume(emu, pb::DEBUG_RUN_MODE_STEP_INTO);
  // The process: where it was, as it was.
  pb::GetDebugStateRequest gs;
  gs.set_session_id(live);
  pb::GetDebugStateResponse now;
  ASSERT_TRUE(backend_->GetDebugState(ctx_, gs, now).ok());
  EXPECT_EQ(now.state().pc().program_address().offset(), functions_["fib"]);
  EXPECT_EQ(Reg(now.state(), "RDI"), 10u);
  pb::CloseDebugSessionRequest close;
  close.set_session_id(emu);
  pb::CloseDebugSessionResponse closed;
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
  // And the process runs on to its end.
  r = Resume(live, pb::DEBUG_RUN_MODE_RUN);
  close.set_session_id(live);
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
}

// Hooks (api_minor 68, feature "debugger-hooks"): a function answered with
// its return value (not run), a system call's result, a user op's output,
// a global's reads and writes made MMIO; unanswered, a run goes on as if
// not hooked.
TEST_F(DebuggerApi, Hooks) {
  Open(true);
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "debugger-hooks"), info.features().end());
  auto start = [&](std::optional<std::string> call) {
    pb::CreateDebugSessionRequest req;
    req.set_program_id(program_);
    if (call) {
      req.mutable_emulator()->mutable_entry()->set_offset(functions_[*call]);
      req.mutable_emulator()->set_mode(pb::EMULATOR_START_MODE_CALL);
    } else {
      req.mutable_emulator();
    }
    pb::CreateDebugSessionResponse created;
    auto st = backend_->CreateDebugSession(ctx_, req, created);
    EXPECT_TRUE(st.ok()) << st.message;
    return created.session_id();
  };
  auto hook = [&](const std::string &id, pb::DebugHookSpec spec) {
    pb::SetDebugHooksRequest req;
    req.set_session_id(id);
    *req.add_add() = spec;
    pb::SetDebugHooksResponse resp;
    auto st = backend_->SetDebugHooks(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.hooks_size() ? resp.hooks(resp.hooks_size() - 1).id() : 0;
  };
  auto answer = [&](const std::string &id, int hook_id, std::optional<std::uint64_t> value) {
    pb::AnswerDebugHookRequest req;
    req.set_session_id(id);
    req.set_hook_id(hook_id);
    if (value) req.set_value(*value);
    pb::AnswerDebugHookResponse resp;
    auto st = backend_->AnswerDebugHook(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
  };
  auto close = [&](const std::string &id) {
    pb::CloseDebugSessionRequest req;
    req.set_session_id(id);
    pb::CloseDebugSessionResponse resp;
    EXPECT_TRUE(backend_->CloseDebugSession(ctx_, req, resp).ok());
  };

  // fib by name, from the whole program: it returns 89 without running, so main exits 0.
  {
    const std::string id = start(std::nullopt);
    pb::DebugHookSpec spec;
    spec.set_kind(pb::DEBUG_HOOK_KIND_FUNCTION);
    spec.set_name("fib");
    const int h = hook(id, spec);
    auto r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_HOOK) << r.stop().DebugString();
    EXPECT_EQ(r.stop().hook().hook_id(), h);
    EXPECT_EQ(r.stop().hook().name(), "fib");
    ASSERT_GE(r.stop().hook().args_size(), 1);
    EXPECT_EQ(r.stop().hook().args(0) & 0xffffffff, 10u);  // argc 1, + 9
    answer(id, h, 89);
    r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_EXITED) << r.stop().DebugString();
    EXPECT_EQ(r.stop().exit_code(), 0);
    EXPECT_NE(r.state().output().find("fib 89"), std::string::npos) << r.state().output();
    close(id);
  }
  // The same unanswered: fib runs (55), main exits 1.
  {
    const std::string id = start(std::nullopt);
    pb::DebugHookSpec spec;
    spec.set_kind(pb::DEBUG_HOOK_KIND_FUNCTION);
    spec.set_name("fib");
    hook(id, spec);
    auto r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_HOOK);
    // Every recursive call stops too: remove the hook, then run on.
    pb::SetDebugHooksRequest clear;
    clear.set_session_id(id);
    clear.set_clear(true);
    pb::SetDebugHooksResponse cleared;
    ASSERT_TRUE(backend_->SetDebugHooks(ctx_, clear, cleared).ok());
    r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_EXITED) << r.stop().DebugString();
    EXPECT_EQ(r.stop().exit_code(), 1);
    close(id);
  }
  // getpid (39) through the syscall instruction: the hook's result.
  {
    const std::string id = start("raw_getpid");
    pb::DebugHookSpec spec;
    spec.set_kind(pb::DEBUG_HOOK_KIND_SYSCALL);
    spec.set_number(39);
    const int h = hook(id, spec);
    auto r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_HOOK) << r.stop().DebugString();
    EXPECT_EQ(r.stop().hook().number(), 39);
    answer(id, h, 4242);
    r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_RETURNED) << r.stop().DebugString();
    EXPECT_EQ(r.stop().exit_code(), 4242);
    close(id);
  }
  // RDTSC's user op: its output.
  {
    const std::string id = start("ticks");
    pb::DebugHookSpec spec;
    spec.set_kind(pb::DEBUG_HOOK_KIND_USEROP);
    spec.set_name("rdtsc");
    const int h = hook(id, spec);
    auto r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_HOOK) << r.stop().DebugString();
    EXPECT_EQ(r.stop().hook().name(), "rdtsc");
    answer(id, h, 0x1234567890ull);
    r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_RETURNED) << r.stop().DebugString();
    EXPECT_EQ(static_cast<std::uint64_t>(r.stop().exit_code()), 0x1234567890ull);
    close(id);
  }
  // counter's reads and writes: a read answered, a write seen.
  {
    pb::ListSymbolsRequest ls;
    ls.set_program_id(program_);
    ls.set_name_equals("counter");
    pb::ListSymbolsResponse syms;
    ASSERT_TRUE(backend_->ListSymbols(ctx_, ls, syms).ok());
    ASSERT_EQ(syms.symbols_size(), 1);
    const std::uint64_t counter = syms.symbols(0).address().offset();
    pb::DebugHookSpec spec;
    spec.set_kind(pb::DEBUG_HOOK_KIND_MMIO);
    spec.mutable_address()->set_offset(counter);
    spec.mutable_address()->set_program(true);
    spec.set_size(4);
    std::string id = start("peek");
    int h = hook(id, spec);
    auto r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_HOOK) << r.stop().DebugString();
    EXPECT_FALSE(r.stop().hook().write());
    EXPECT_EQ(r.stop().hook().size(), 4u);
    answer(id, h, 77);
    r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_RETURNED) << r.stop().DebugString();
    EXPECT_EQ(r.stop().exit_code(), 77);
    close(id);
    pb::CreateDebugSessionRequest req;
    req.set_program_id(program_);
    req.mutable_emulator()->mutable_entry()->set_offset(functions_["poke"]);
    req.mutable_emulator()->set_mode(pb::EMULATOR_START_MODE_CALL);
    req.mutable_emulator()->add_arguments(5);
    pb::CreateDebugSessionResponse created;
    ASSERT_TRUE(backend_->CreateDebugSession(ctx_, req, created).ok());
    id = created.session_id();
    h = hook(id, spec);
    r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_HOOK) << r.stop().DebugString();
    EXPECT_TRUE(r.stop().hook().write());
    EXPECT_EQ(r.stop().hook().value(), 5u);
    r = Resume(id, pb::DEBUG_RUN_MODE_RUN);  // unanswered: the write goes on
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_RETURNED) << r.stop().DebugString();
    close(id);
  }
  // A live session has no hooks.
  if (debug::find_program("gdbserver").empty()) return;
  pb::CreateDebugSessionRequest lr;
  lr.set_program_id(program_);
  lr.mutable_launch();
  pb::CreateDebugSessionResponse lc;
  ASSERT_TRUE(backend_->CreateDebugSession(ctx_, lr, lc).ok());
  pb::SetDebugHooksRequest req;
  req.set_session_id(lc.session_id());
  auto *spec = req.add_add();
  spec->set_kind(pb::DEBUG_HOOK_KIND_FUNCTION);
  spec->set_name("fib");
  pb::SetDebugHooksResponse resp;
  EXPECT_EQ(backend_->SetDebugHooks(ctx_, req, resp).code, StatusCode::kFailedPrecondition);
  close(lc.session_id());
}

// Emulating from a saved trace's snapshot (the trace control mode): the
// recording's registers and memory (an emulator's recording is complete),
// run on to fib's next call.
TEST_F(DebuggerApi, EmulateFromATraceSnapshot) {
  Open(false);
  pb::CreateDebugSessionRequest req;
  req.set_program_id(program_);
  req.mutable_emulator()->mutable_entry()->set_offset(functions_["fib"]);
  req.mutable_emulator()->set_mode(pb::EMULATOR_START_MODE_CALL);
  req.mutable_emulator()->add_arguments(6);
  pb::CreateDebugSessionResponse created;
  ASSERT_TRUE(backend_->CreateDebugSession(ctx_, req, created).ok());
  Break(created.session_id(), functions_["fib"]);
  auto r = Resume(created.session_id(), pb::DEBUG_RUN_MODE_RUN);  // fib(5)
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT);
  const std::uint64_t at5 = r.state().last_snapshot();
  Resume(created.session_id(), pb::DEBUG_RUN_MODE_RUN);  // fib(4)
  pb::SaveDebugTraceRequest save;
  save.set_session_id(created.session_id());
  save.set_name("fib6");
  pb::SaveDebugTraceResponse saved;
  ASSERT_TRUE(backend_->SaveDebugTrace(ctx_, save, saved).ok());
  pb::CloseDebugSessionRequest close;
  close.set_session_id(created.session_id());
  pb::CloseDebugSessionResponse closed;
  ASSERT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());

  pb::CreateDebugSessionRequest tr;
  tr.set_program_id(program_);
  tr.mutable_trace()->set_name("fib6");
  pb::CreateDebugSessionResponse tc;
  ASSERT_TRUE(backend_->CreateDebugSession(ctx_, tr, tc).ok());
  pb::CreateDebugSessionRequest er;
  er.set_program_id(program_);
  er.mutable_emulator()->set_from_session(tc.session_id());
  er.mutable_emulator()->set_from_snapshot(at5);
  pb::CreateDebugSessionResponse ec;
  auto st = backend_->CreateDebugSession(ctx_, er, ec);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(Reg(ec.state(), "RDI"), 5u);
  EXPECT_EQ(ec.state().pc().program_address().offset(), functions_["fib"]);
  Break(ec.session_id(), functions_["fib"]);
  r = Resume(ec.session_id(), pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT) << r.stop().DebugString();
  EXPECT_EQ(Reg(r.state(), "RDI"), 4u);
  close.set_session_id(ec.session_id());
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
  close.set_session_id(tc.session_id());
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
}

TEST_F(DebuggerApi, TracesPersistWithTheProject) {
  const auto dir = testing::scratch_dir("debugger-api-project");
  Open(false, dir.string());
  pb::CreateDebugSessionRequest req;
  req.set_program_id(program_);
  req.mutable_emulator()->mutable_entry()->set_offset(functions_["fib"]);
  req.mutable_emulator()->set_mode(pb::EMULATOR_START_MODE_CALL);
  req.mutable_emulator()->add_arguments(3);
  pb::CreateDebugSessionResponse created;
  ASSERT_TRUE(backend_->CreateDebugSession(ctx_, req, created).ok());
  Resume(created.session_id(), pb::DEBUG_RUN_MODE_RUN);
  pb::SaveDebugTraceRequest sr;
  sr.set_session_id(created.session_id());
  sr.set_name("kept");
  pb::SaveDebugTraceResponse saved;
  ASSERT_TRUE(backend_->SaveDebugTrace(ctx_, sr, saved).ok());
  EXPECT_TRUE(saved.trace().persisted());
  backend_.reset();
  functions_.clear();
  Open(false, dir.string());  // reopened from the directory
  pb::ListDebugTracesRequest lt;
  lt.set_program_id(program_);
  pb::ListDebugTracesResponse traces;
  ASSERT_TRUE(backend_->ListDebugTraces(ctx_, lt, traces).ok());
  ASSERT_EQ(traces.traces_size(), 1);
  EXPECT_EQ(traces.traces(0).name(), "kept");
  EXPECT_TRUE(traces.traces(0).persisted());
  pb::CreateDebugSessionRequest open;
  open.set_program_id(program_);
  open.mutable_trace()->set_name("kept");
  pb::CreateDebugSessionResponse replay;
  auto st = backend_->CreateDebugSession(ctx_, open, replay);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(replay.state().last_stop().kind(), pb::DEBUG_STOP_KIND_RETURNED);
  std::filesystem::remove_all(dir);
}

TEST_F(DebuggerApi, LaunchedPieUnderGdbserver) {
  if (debug::find_program("gdbserver").empty()) GTEST_SKIP() << "gdbserver is not installed";
  Open(true);
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "debugger-live"), info.features().end());

  pb::CreateDebugSessionRequest req;
  req.set_program_id(program_);
  req.mutable_launch()->add_arguments("x");
  auto *bp = req.add_breakpoints();
  bp->mutable_address()->set_offset(functions_["main"]);
  bp->mutable_address()->set_program(true);
  pb::CreateDebugSessionResponse created;
  auto st = backend_->CreateDebugSession(ctx_, req, created);
  ASSERT_TRUE(st.ok()) << st.message;
  const std::string id = created.session_id();
  EXPECT_EQ(created.target_kind(), "gdb-remote");
  EXPECT_TRUE(created.state().mapping().known());
  EXPECT_NE(created.state().mapping().slide(), 0);
  ASSERT_EQ(created.state().breakpoints_size(), 1);
  EXPECT_TRUE(created.state().breakpoints(0).inserted()) << created.state().breakpoints(0).error();

  auto r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT) << r.stop().detail();
  EXPECT_EQ(r.state().pc().program_address().offset(), functions_["main"]);
  EXPECT_EQ(r.state().pc().address().offset(),
            functions_["main"] + static_cast<std::uint64_t>(created.state().mapping().slide()));
  EXPECT_EQ(Reg(r.state(), "RDI"), 2u);  // argc: prog x

  // Modules: the program, with its slide.
  pb::ListDebugModulesRequest mr;
  mr.set_session_id(id);
  pb::ListDebugModulesResponse mods;
  ASSERT_TRUE(backend_->ListDebugModules(ctx_, mr, mods).ok());
  bool program = false;
  for (const auto &m : mods.modules())
    if (m.program()) program = m.name() == "prog";
  EXPECT_TRUE(program);
  EXPECT_GT(mods.regions_size(), 3);

  // Out of main's call to fib (step over), and the global by its static address.
  for (int i = 0; i < 20; ++i) {
    r = Resume(id, pb::DEBUG_RUN_MODE_STEP_OVER);
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_STEPPED) << r.stop().detail();
    if ((Reg(r.state(), "RAX") & 0xffffffff) == 89) break;
  }
  EXPECT_EQ(Reg(r.state(), "RAX") & 0xffffffff, 89u);
  EXPECT_GE(r.state().pc().program_address().offset(), functions_["main"]);

  // Threads in the state.
  pb::GetDebugStateRequest gs;
  gs.set_session_id(id);
  gs.mutable_state()->set_include_threads(true);
  pb::GetDebugStateResponse withthreads;
  ASSERT_TRUE(backend_->GetDebugState(ctx_, gs, withthreads).ok());
  ASSERT_EQ(withthreads.state().threads_size(), 1);
  EXPECT_TRUE(withthreads.state().threads(0).current());

  r = Resume(id, pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_EXITED) << r.stop().detail();
  EXPECT_EQ(r.stop().exit_code(), 0);
  EXPECT_EQ(r.state().target_state(), pb::DEBUG_TARGET_STATE_EXITED);
  EXPECT_NE(r.state().output().find("fib 89"), std::string::npos) << r.state().output();
  // The recording stays readable after the process is gone.
  const auto at_main = State(id, 1);
  EXPECT_EQ(Reg(at_main, "RDI"), 2u);
  pb::CloseDebugSessionRequest close;
  close.set_session_id(id);
  pb::CloseDebugSessionResponse closed;
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
}

TEST_F(DebuggerApi, ConnectsToAGdbserver) {
  if (debug::find_program("gdbserver").empty()) GTEST_SKIP() << "gdbserver is not installed";
  Open(true);
  // A gdbserver of our own, on a free port.
  const std::string cmd = "gdbserver --once 127.0.0.1:0 " + exe_.string() + " 2>&1";
  FILE *p = ::popen(cmd.c_str(), "r");
  ASSERT_NE(p, nullptr);
  int port = 0;
  char line[512];
  while (port == 0 && std::fgets(line, sizeof line, p) != nullptr)
    if (std::sscanf(line, "Listening on port %d", &port) == 1) break;
  ASSERT_GT(port, 0);
  std::thread drain([p] {
    char buf[512];
    while (std::fgets(buf, sizeof buf, p) != nullptr) {
    }
  });
  pb::CreateDebugSessionRequest req;
  req.set_program_id(program_);
  req.mutable_remote()->set_address("127.0.0.1:" + std::to_string(port));
  pb::CreateDebugSessionResponse created;
  auto st = backend_->CreateDebugSession(ctx_, req, created);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_NE(created.description().find("gdb remote 127.0.0.1"), std::string::npos);
  Break(created.session_id(), functions_["fib"]);
  auto r = Resume(created.session_id(), pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT) << r.stop().detail();
  EXPECT_EQ(r.state().pc().program_address().offset(), functions_["fib"]);
  EXPECT_EQ(Reg(r.state(), "RDI"), 10u);
  // Closing detaches: the program runs to its end on its own.
  pb::CloseDebugSessionRequest close;
  close.set_session_id(created.session_id());
  pb::CloseDebugSessionResponse closed;
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
  drain.join();
  EXPECT_EQ(::pclose(p), 0);
}

}  // namespace
}  // namespace revkit::backend
