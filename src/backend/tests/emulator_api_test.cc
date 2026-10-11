// EmulatorService on the image backend: a session over an imported program,
// stepping, breakpoints, registers that changed, memory, the trace, and the
// bounds (per client, steps, time).
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <map>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

constexpr const char *kProgram = R"(
__attribute__((noinline)) int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
__attribute__((noinline)) int spin(void) { volatile int x = 0; for (;;) x++; }
int counter;
int main(int argc, char **argv) { counter = fib(argc + 9); return counter > 0 ? 0 : spin(); }
)";

class EmulatorApi : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("emulator-api");
    exe_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O1 -fno-inline", exe_);
  }
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!compiled_) GTEST_SKIP() << "no C compiler";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(exe_.string());
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    program_ = resp.program().program_id();
    pb::ListFunctionsRequest lf;
    lf.set_program_id(program_);
    lf.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse lr;
    ASSERT_TRUE(backend_->ListFunctions(ctx_, lf, lr).ok());
    for (const auto &f : lr.functions()) functions_[f.name()] = f.entry().offset();
    ASSERT_TRUE(functions_.count("fib"));
  }

  pb::CreateEmulatorSessionResponse Create(std::uint64_t entry, std::vector<std::uint64_t> args,
                                           const std::string &client = "test") {
    pb::CreateEmulatorSessionRequest req;
    req.set_program_id(program_);
    req.mutable_entry()->set_offset(entry);
    req.set_mode(pb::EMULATOR_START_MODE_CALL);
    for (auto a : args) req.add_arguments(a);
    req.set_client(client);
    pb::CreateEmulatorSessionResponse resp;
    auto st = backend_->CreateEmulatorSession(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }
  pb::RunEmulatorResponse Run(const std::string &id, pb::EmulatorRunMode mode, std::uint64_t max_steps = 0) {
    pb::RunEmulatorRequest req;
    req.set_session_id(id);
    req.set_mode(mode);
    req.set_max_steps(max_steps);
    pb::RunEmulatorResponse resp;
    auto st = backend_->RunEmulator(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  static inline std::filesystem::path exe_;
  static inline bool compiled_ = false;
  std::unique_ptr<api::Backend> backend_;
  CallContext ctx_;
  std::string program_;
  std::map<std::string, std::uint64_t> functions_;
};

TEST_F(EmulatorApi, CallStepBreakpointAndRegisters) {
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_GE(info.api_minor(), 12u);
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "emulator"), info.features().end());

  const std::uint64_t fib = functions_["fib"];
  auto created = Create(fib, {10});
  const std::string id = created.session_id();
  ASSERT_FALSE(id.empty());
  EXPECT_EQ(created.language(), "x86:LE:64:default:gcc");
  EXPECT_EQ(created.pc_register(), "RIP");
  EXPECT_EQ(created.state().pc().offset(), fib);
  EXPECT_EQ(created.state().last_stop().kind(), pb::EMULATOR_STOP_KIND_NONE);
  bool rdi_shown = false;
  for (const auto &r : created.state().registers())
    if (r.name() == "RDI") rdi_shown = r.value() == 10;
  EXPECT_TRUE(rdi_shown);

  // One step: the registers it wrote are flagged as changed.
  auto step = Run(id, pb::EMULATOR_RUN_MODE_STEP_INTO);
  EXPECT_EQ(step.stop().kind(), pb::EMULATOR_STOP_KIND_STEPPED);
  EXPECT_EQ(step.state().steps(), 1u);
  int changed = 0;
  for (const auto &r : step.state().registers()) {
    if (r.name() == "RIP") EXPECT_TRUE(r.changed());
    if (r.name() == "R15") EXPECT_FALSE(r.changed());
    changed += r.changed();
  }
  EXPECT_GE(changed, 1);

  // A breakpoint at the recursive call's return path: fib's own entry.
  pb::SetEmulatorBreakpointsRequest bp;
  bp.set_session_id(id);
  bp.add_add()->set_offset(fib);
  pb::SetEmulatorBreakpointsResponse bpr;
  ASSERT_TRUE(backend_->SetEmulatorBreakpoints(ctx_, bp, bpr).ok());
  ASSERT_EQ(bpr.breakpoints_size(), 1);
  auto hit = Run(id, pb::EMULATOR_RUN_MODE_RUN);
  EXPECT_EQ(hit.stop().kind(), pb::EMULATOR_STOP_KIND_BREAKPOINT);
  EXPECT_EQ(hit.state().pc().offset(), fib);

  // Clear it and run to the end: fib(10) returns 55 to the return trap.
  bp.Clear();
  bp.set_session_id(id);
  bp.set_clear(true);
  pb::SetEmulatorBreakpointsResponse cleared;
  ASSERT_TRUE(backend_->SetEmulatorBreakpoints(ctx_, bp, cleared).ok());
  EXPECT_EQ(cleared.breakpoints_size(), 0);
  auto done = Run(id, pb::EMULATOR_RUN_MODE_RUN);
  EXPECT_EQ(done.stop().kind(), pb::EMULATOR_STOP_KIND_RETURNED) << done.stop().detail();
  EXPECT_EQ(done.stop().exit_code(), 55);

  // Registers written, then read back by name.
  pb::WriteEmulatorRegistersRequest wr;
  wr.set_session_id(id);
  auto *w = wr.add_registers();
  w->set_name("rbx");
  w->set_value(0x1234);
  wr.mutable_state()->add_registers("RBX");
  pb::WriteEmulatorRegistersResponse wresp;
  ASSERT_TRUE(backend_->WriteEmulatorRegisters(ctx_, wr, wresp).ok());
  ASSERT_EQ(wresp.state().registers_size(), 1);
  EXPECT_EQ(wresp.state().registers(0).value(), 0x1234u);
  w->set_name("NOPE");
  EXPECT_EQ(backend_->WriteEmulatorRegisters(ctx_, wr, wresp).code, StatusCode::kInvalidArgument);

  // The trace: entries with registers and memory, and the summary.
  pb::GetEmulatorTraceRequest tr;
  tr.set_session_id(id);
  tr.set_limit(5);
  pb::GetEmulatorTraceResponse trace;
  ASSERT_TRUE(backend_->GetEmulatorTrace(ctx_, tr, trace).ok());
  EXPECT_EQ(trace.entries_size(), 5);
  EXPECT_EQ(trace.entries(0).pc().offset(), fib);
  EXPECT_GT(trace.summary().steps(), 100u);
  EXPECT_GT(trace.summary().memory_writes(), 0u);
  tr.set_json(true);
  ASSERT_TRUE(backend_->GetEmulatorTrace(ctx_, tr, trace).ok());
  EXPECT_NE(trace.json().find("\"returned\""), std::string::npos);

  pb::CloseEmulatorSessionRequest close;
  close.set_session_id(id);
  pb::CloseEmulatorSessionResponse closed;
  EXPECT_TRUE(backend_->CloseEmulatorSession(ctx_, close, closed).ok());
  EXPECT_EQ(backend_->CloseEmulatorSession(ctx_, close, closed).code, StatusCode::kNotFound);
}

TEST_F(EmulatorApi, MemoryAndProcessStart) {
  // main as a process from the entry point: the counter global is written.
  pb::CreateEmulatorSessionRequest req;
  req.set_program_id(program_);
  req.set_client("test");
  req.set_stdin("ignored");
  pb::CreateEmulatorSessionResponse created;
  ASSERT_TRUE(backend_->CreateEmulatorSession(ctx_, req, created).ok());
  pb::RunEmulatorRequest run;
  run.set_session_id(created.session_id());
  run.mutable_state()->set_include_regions(true);
  pb::RunEmulatorResponse ran;
  ASSERT_TRUE(backend_->RunEmulator(ctx_, run, ran).ok());
  EXPECT_EQ(ran.stop().kind(), pb::EMULATOR_STOP_KIND_EXITED) << ran.stop().detail();
  EXPECT_EQ(ran.stop().exit_code(), 0);
  bool stack = false, stubs = false;
  for (const auto &r : ran.state().regions()) {
    stack = stack || r.name() == "stack";
    stubs = stubs || r.kind() == "stub";
  }
  EXPECT_TRUE(stack);
  EXPECT_TRUE(stubs);

  // Read across mapped and unmapped bytes; write and read back.
  std::uint64_t stack_last = 0;
  for (const auto &r : ran.state().regions())
    if (r.name() == "stack") stack_last = r.range().last().offset();
  pb::ReadEmulatorMemoryRequest rm;
  rm.set_session_id(created.session_id());
  rm.mutable_address()->set_offset(stack_last - 7);
  rm.set_length(32);
  pb::ReadEmulatorMemoryResponse mem;
  pb::WriteEmulatorMemoryRequest wm;
  wm.set_session_id(created.session_id());
  wm.mutable_address()->set_offset(stack_last - 3);
  wm.set_data("ABCD");
  pb::WriteEmulatorMemoryResponse wmr;
  ASSERT_TRUE(backend_->WriteEmulatorMemory(ctx_, wm, wmr).ok());
  ASSERT_TRUE(backend_->ReadEmulatorMemory(ctx_, rm, mem).ok());
  ASSERT_EQ(mem.data().size(), 32u);
  EXPECT_EQ(mem.data().substr(4, 4), "ABCD");
  ASSERT_GE(mem.unmapped_size(), 1);
  EXPECT_EQ(mem.unmapped(0).offset(), 8u);
  wm.mutable_address()->set_offset(stack_last + 0x100000);
  EXPECT_EQ(backend_->WriteEmulatorMemory(ctx_, wm, wmr).code, StatusCode::kInvalidArgument);
}

// An image block's permission edit reaches the emulator for an ELF section
// inside a segment too (docs/memory-map.md): its piece of the segment is a
// region of its own with the block's permissions; the rest keeps the
// segment's.
TEST_F(EmulatorApi, AnEditedSectionsPermissionsReachTheEmulator) {
  pb::GetMemoryMapRequest mr;
  mr.set_program_id(program_);
  pb::GetMemoryMapResponse map;
  ASSERT_TRUE(backend_->GetMemoryMap(ctx_, mr, map).ok());
  const pb::MemoryBlock *rodata = nullptr;
  for (const auto &b : map.blocks())
    if (b.name() == ".rodata") rodata = &b;
  ASSERT_NE(rodata, nullptr);
  ASSERT_FALSE(rodata->write());
  const std::uint64_t first = rodata->range().first().offset(), last = rodata->range().last().offset();

  auto regions = [&] {
    pb::CreateEmulatorSessionRequest req;
    req.set_program_id(program_);
    req.set_client("test");
    pb::CreateEmulatorSessionResponse created;
    EXPECT_TRUE(backend_->CreateEmulatorSession(ctx_, req, created).ok());
    pb::RunEmulatorRequest run;
    run.set_session_id(created.session_id());
    run.set_mode(pb::EMULATOR_RUN_MODE_STEP_INTO);
    run.mutable_state()->set_include_regions(true);
    pb::RunEmulatorResponse ran;
    EXPECT_TRUE(backend_->RunEmulator(ctx_, run, ran).ok());
    return std::vector<pb::EmulatorRegion>(ran.state().regions().begin(), ran.state().regions().end());
  };
  // Before: the segment holding .rodata is read-only throughout.
  for (const auto &r : regions())
    if (r.range().first().offset() <= first && last <= r.range().last().offset()) EXPECT_EQ(r.permissions()[1], '-');

  pb::UpdateMemoryRegionRequest up;
  up.set_program_id(program_);
  up.mutable_block_start()->set_offset(first);
  up.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  up.mutable_provenance()->set_id("alice");
  pb::MemoryRegion *r = up.mutable_region();
  r->set_name(".rodata");
  r->set_start(first);
  r->set_size(last - first + 1);
  r->set_read(true);
  r->set_write(true);
  r->set_initialized(rodata->initialized());
  pb::UpdateMemoryRegionResponse updated;
  auto st = backend_->UpdateMemoryRegion(ctx_, up, updated);
  ASSERT_TRUE(st.ok()) << st.message;

  bool section = false;
  for (const auto &e : regions()) {
    const std::uint64_t a = e.range().first().offset(), b = e.range().last().offset();
    if (a == first && b == last) {
      section = true;
      EXPECT_EQ(e.permissions(), "rw-");
      EXPECT_EQ(e.name(), ".rodata");
    } else {
      // Nothing else of the segment became writable.
      EXPECT_TRUE(b < first || a > last) << e.name() << " " << std::hex << a << "-" << b;
    }
  }
  EXPECT_TRUE(section);

  // The program still runs to its end.
  pb::CreateEmulatorSessionRequest req;
  req.set_program_id(program_);
  req.set_client("test");
  pb::CreateEmulatorSessionResponse created;
  ASSERT_TRUE(backend_->CreateEmulatorSession(ctx_, req, created).ok());
  auto ran = Run(created.session_id(), pb::EMULATOR_RUN_MODE_RUN);
  EXPECT_EQ(ran.stop().kind(), pb::EMULATOR_STOP_KIND_EXITED) << ran.stop().detail();
}

TEST_F(EmulatorApi, Bounds) {
  // Per client.
  std::vector<std::string> ids;
  for (int i = 0; i < 8; ++i) ids.push_back(Create(functions_["fib"], {3}, "greedy").session_id());
  pb::CreateEmulatorSessionRequest req;
  req.set_program_id(program_);
  req.set_client("greedy");
  pb::CreateEmulatorSessionResponse resp;
  EXPECT_EQ(backend_->CreateEmulatorSession(ctx_, req, resp).code, StatusCode::kResourceExhausted);
  pb::ListEmulatorSessionsRequest list;
  list.set_client("greedy");
  pb::ListEmulatorSessionsResponse listed;
  ASSERT_TRUE(backend_->ListEmulatorSessions(ctx_, list, listed).ok());
  EXPECT_EQ(listed.sessions_size(), 8);
  list.set_client("someone else");
  pb::ListEmulatorSessionsResponse others;
  ASSERT_TRUE(backend_->ListEmulatorSessions(ctx_, list, others).ok());
  EXPECT_EQ(others.sessions_size(), 0);

  // Steps per session, and time per call, on a function that never returns.
  pb::CreateEmulatorSessionRequest spin;
  spin.set_program_id(program_);
  spin.set_client("bounded");
  spin.mutable_entry()->set_offset(functions_["spin"]);
  spin.set_mode(pb::EMULATOR_START_MODE_CALL);
  spin.mutable_limits()->set_max_total_steps(1000);
  pb::CreateEmulatorSessionResponse s;
  ASSERT_TRUE(backend_->CreateEmulatorSession(ctx_, spin, s).ok());
  EXPECT_EQ(s.limits().max_total_steps(), 1000u);
  auto r = Run(s.session_id(), pb::EMULATOR_RUN_MODE_RUN);
  EXPECT_EQ(r.stop().kind(), pb::EMULATOR_STOP_KIND_SESSION_LIMIT);
  EXPECT_EQ(r.state().steps(), 1000u);
  r = Run(s.session_id(), pb::EMULATOR_RUN_MODE_RUN);
  EXPECT_EQ(r.stop().kind(), pb::EMULATOR_STOP_KIND_SESSION_LIMIT);
  EXPECT_EQ(r.state().steps(), 1000u);

  spin.mutable_limits()->set_max_total_steps(0);
  spin.mutable_limits()->set_time_limit_ms(200);
  ASSERT_TRUE(backend_->CreateEmulatorSession(ctx_, spin, s).ok());
  const auto t0 = std::chrono::steady_clock::now();
  r = Run(s.session_id(), pb::EMULATOR_RUN_MODE_RUN, 1000000000);
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
  EXPECT_TRUE(r.stop().kind() == pb::EMULATOR_STOP_KIND_TIME_LIMIT || r.stop().kind() == pb::EMULATOR_STOP_KIND_STEP_LIMIT)
      << r.stop().kind();
  EXPECT_LT(ms, 5000);

  pb::RunEmulatorRequest bad;
  bad.set_session_id("emu-nope");
  pb::RunEmulatorResponse br;
  EXPECT_EQ(backend_->RunEmulator(ctx_, bad, br).code, StatusCode::kNotFound);
}


// With authentication (docs/security.md), a session belongs to the
// identity that made it: another caller sees "not found" on every call and
// doesn't list it; an admin reaches it.
TEST_F(EmulatorApi, SessionsBelongToTheirCaller) {
  api::CallContext alice, bob, root;
  alice.caller = "user:alice", alice.caller_admin = false;
  bob.caller = "user:bob", bob.caller_admin = false;
  root.caller = "user:root", root.caller_admin = true;
  pb::CreateEmulatorSessionRequest req;
  req.set_program_id(program_);
  req.mutable_entry()->set_offset(functions_["fib"]);
  req.set_mode(pb::EMULATOR_START_MODE_CALL);
  req.add_arguments(5);
  pb::CreateEmulatorSessionResponse created;
  ASSERT_TRUE(backend_->CreateEmulatorSession(alice, req, created).ok());
  const std::string id = created.session_id();

  pb::GetEmulatorStateRequest gs;
  gs.set_session_id(id);
  pb::GetEmulatorStateResponse state;
  EXPECT_TRUE(backend_->GetEmulatorState(alice, gs, state).ok());
  EXPECT_EQ(backend_->GetEmulatorState(bob, gs, state).code, StatusCode::kNotFound);
  pb::RunEmulatorRequest run;
  run.set_session_id(id);
  run.set_mode(pb::EMULATOR_RUN_MODE_STEP_INTO);
  pb::RunEmulatorResponse ran;
  EXPECT_EQ(backend_->RunEmulator(bob, run, ran).code, StatusCode::kNotFound);
  pb::ReadEmulatorMemoryRequest rm;
  rm.set_session_id(id);
  rm.set_length(4);
  pb::ReadEmulatorMemoryResponse mem;
  EXPECT_EQ(backend_->ReadEmulatorMemory(bob, rm, mem).code, StatusCode::kNotFound);
  pb::GetEmulatorTraceRequest tr;
  tr.set_session_id(id);
  pb::GetEmulatorTraceResponse trace;
  EXPECT_EQ(backend_->GetEmulatorTrace(bob, tr, trace).code, StatusCode::kNotFound);
  pb::CloseEmulatorSessionRequest close;
  close.set_session_id(id);
  pb::CloseEmulatorSessionResponse closed;
  EXPECT_EQ(backend_->CloseEmulatorSession(bob, close, closed).code, StatusCode::kNotFound);

  // Listing: alice sees hers whatever client made it; bob sees none, even
  // naming alice's client.
  pb::ListEmulatorSessionsRequest list;
  pb::ListEmulatorSessionsResponse a, b;
  ASSERT_TRUE(backend_->ListEmulatorSessions(alice, list, a).ok());
  EXPECT_EQ(a.sessions_size(), 1);
  list.set_client(a.sessions(0).client());
  ASSERT_TRUE(backend_->ListEmulatorSessions(bob, list, b).ok());
  EXPECT_EQ(b.sessions_size(), 0);

  // The session bound is per identity, whatever `client` says.
  for (int i = 0; i < 7; ++i) {
    req.set_client("c" + std::to_string(i));
    ASSERT_TRUE(backend_->CreateEmulatorSession(alice, req, created).ok());
  }
  req.set_client("one-more");
  EXPECT_EQ(backend_->CreateEmulatorSession(alice, req, created).code, StatusCode::kResourceExhausted);

  // An admin reaches it, and closes it.
  EXPECT_TRUE(backend_->RunEmulator(root, run, ran).ok());
  EXPECT_TRUE(backend_->CloseEmulatorSession(root, close, closed).ok());
  EXPECT_EQ(backend_->GetEmulatorState(alice, gs, state).code, StatusCode::kNotFound);
}

}  // namespace

}  // namespace revkit::backend
