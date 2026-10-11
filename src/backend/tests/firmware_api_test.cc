// Firmware emulation through the API (api_minor 20, feature
// "firmware-emulation"; docs/firmware-emulation.md): emulator and debugger
// sessions on a machine, UART input, the machine's state and exception
// events, exception breakpoints, the timeline's events, machines saved with
// a program, and a derived starter machine.
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <optional>
#include <vector>
#include <fstream>
#include <sstream>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;
namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

std::string ReadText(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  std::stringstream s;
  s << in.rdbuf();
  return s.str();
}

class FirmwareApi : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty() || std::string(REVKIT_TEST_CLANG).empty() ||
        std::string(REVKIT_TEST_LLD).empty() || std::string(REVKIT_TEST_OBJCOPY).empty())
      return;
    dir_ = testing::scratch_dir("firmware-api");
    std::string cmd = std::string("sh ") + REVKIT_FWEMU_DIR + "/build.sh " + REVKIT_TEST_CLANG + " " + REVKIT_TEST_LLD + " " +
                      REVKIT_TEST_OBJCOPY + " " + (dir_ / "fwemu").string() + " >/dev/null 2>&1";
    if (std::system(cmd.c_str()) != 0) return;
    cmd = std::string("sh ") + REVKIT_ARMFW_DIR + "/build.sh " + REVKIT_TEST_CLANG + " " + REVKIT_TEST_LLD + " " +
          REVKIT_TEST_OBJCOPY + " " + (dir_ / "armfw").string() + " >/dev/null 2>&1";
    built_ = std::system(cmd.c_str()) == 0;
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!built_) GTEST_SKIP() << "no clang, ld.lld and llvm-objcopy";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.project_dir = project_dir_;
    backend_ = MakeImageBackend(o);
  }

  // A raw ARMv4T program at 0, as the user would import firmware.
  std::string Import(const fs::path &bin, const std::string &name, bool sysctrl = false) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(bin.string());
    req.set_name(name);
    pb::ImportOptions *o = req.mutable_options();
    o->set_format("raw");
    o->set_language_id("ARM:LE:32:v4t");
    o->set_compiler_spec_id("default");
    if (sysctrl) {
      pb::MemoryRegion *r = o->add_regions();
      r->set_name("sysctrl");
      r->set_start(0xd0000000);
      r->set_size(0x1000);
      r->set_read(true);
      r->set_write(true);
      r->set_is_volatile(true);
    }
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  std::string Board(const std::string &file) { return ReadText(fs::path(REVKIT_FWEMU_DIR) / file); }

  static inline fs::path dir_;
  static inline bool built_ = false;
  std::string project_dir_;
  std::unique_ptr<api::Backend> backend_;
  CallContext ctx_;
};

TEST_F(FirmwareApi, EmulatorSessionOnAMachine) {
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_GE(info.api_minor(), 20u);
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "firmware-emulation"), info.features().end());

  const std::string id = Import(dir_ / "fwemu" / "arm_uart.bin", "arm_uart");
  pb::CreateEmulatorSessionRequest req;
  req.set_program_id(id);
  req.set_machine(Board("versatilepb.json"));
  pb::CreateEmulatorSessionResponse created;
  auto st = backend_->CreateEmulatorSession(ctx_, req, created);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(created.machine().cpu(), "arm");
  EXPECT_EQ(created.machine().name(), "versatilepb");
  EXPECT_TRUE(created.state().machine());
  bool vic = false;
  for (const auto &d : created.machine().devices()) vic = vic || (d.name() == "vic" && d.base() == 0x10140000u);
  EXPECT_TRUE(vic);
  bool cpsr = false;
  for (const auto &r : created.registers()) cpsr = cpsr || (r.name() == "cpsr" && r.display());
  EXPECT_TRUE(cpsr);

  auto run = [&] {
    pb::RunEmulatorRequest r;
    r.set_session_id(created.session_id());
    pb::RunEmulatorResponse resp;
    auto s = backend_->RunEmulator(ctx_, r, resp);
    EXPECT_TRUE(s.ok()) << s.message;
    return resp;
  };
  // No input yet: the program waits for an interrupt with nothing scheduled.
  pb::RunEmulatorResponse r = run();
  EXPECT_EQ(r.stop().kind(), pb::EMULATOR_STOP_KIND_IDLE) << r.stop().detail();
  EXPECT_TRUE(r.state().waiting());
  pb::WriteEmulatorInputRequest in;
  in.set_session_id(created.session_id());
  in.set_data("hello\nquit\n");
  pb::WriteEmulatorInputResponse ignored;
  ASSERT_TRUE(backend_->WriteEmulatorInput(ctx_, in, ignored).ok());
  r = run();
  EXPECT_EQ(r.stop().kind(), pb::EMULATOR_STOP_KIND_EXITED) << r.stop().detail();
  EXPECT_EQ(r.state().stdout(), "uart echo test\necho: HELLO\necho: QUIT\nlines 2\ndone\n");

  pb::GetEmulatorMachineRequest mreq;
  mreq.set_session_id(created.session_id());
  pb::GetEmulatorMachineResponse m;
  ASSERT_TRUE(backend_->GetEmulatorMachine(ctx_, mreq, m).ok());
  EXPECT_EQ(m.state().cpu(), "arm");
  EXPECT_GT(m.event_count(), 0u);
  bool irq = false;
  for (const auto &ev : m.events()) irq = irq || (ev.kind() == "irq" && ev.handler().offset() == 0x18 && ev.source() == "vic");
  EXPECT_TRUE(irq);
  bool banked = false;
  for (const auto &reg : m.state().registers()) banked = banked || reg.name() == "sp_irq";
  EXPECT_TRUE(banked);

  // A session without a machine has none.
  pb::WriteEmulatorInputRequest bad = in;
  bad.set_session_id("nope");
  EXPECT_EQ(backend_->WriteEmulatorInput(ctx_, bad, ignored).code, StatusCode::kNotFound);
  // A bad description says where.
  req.set_machine("{\"memory\": [{\"start\": 0}]}");
  pb::CreateEmulatorSessionResponse failed;
  st = backend_->CreateEmulatorSession(ctx_, req, failed);
  EXPECT_EQ(st.code, StatusCode::kInvalidArgument);
  EXPECT_NE(st.message.find("1:"), std::string::npos) << st.message;
}

TEST_F(FirmwareApi, DebuggerTimelineShowsInterrupts) {
  const std::string id = Import(dir_ / "fwemu" / "arm_timer.bin", "arm_timer");
  // Saved with the program, then used by name.
  pb::SaveMachineRequest save;
  save.set_program_id(id);
  save.set_name("versatilepb");
  save.set_machine(Board("versatilepb.json"));
  pb::SaveMachineResponse saved;
  auto st = backend_->SaveMachine(ctx_, save, saved);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(saved.info().name(), "versatilepb");
  pb::ListMachinesRequest list;
  list.set_program_id(id);
  pb::ListMachinesResponse listed;
  ASSERT_TRUE(backend_->ListMachines(ctx_, list, listed).ok());
  ASSERT_EQ(listed.machines_size(), 1);
  save.set_machine("{nope");
  EXPECT_EQ(backend_->SaveMachine(ctx_, save, saved).code, StatusCode::kInvalidArgument);

  pb::CreateDebugSessionRequest req;
  req.set_program_id(id);
  req.mutable_emulator()->set_machine_name("versatilepb");
  pb::CreateDebugSessionResponse created;
  st = backend_->CreateDebugSession(ctx_, req, created);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(created.machine().cpu(), "arm");

  // Break on the first IRQ.
  pb::SetDebugBreakpointsRequest br;
  br.set_session_id(created.session_id());
  br.add_exception_breaks("irq");
  br.set_set_exception_breaks(true);
  pb::SetDebugBreakpointsResponse brr;
  ASSERT_TRUE(backend_->SetDebugBreakpoints(ctx_, br, brr).ok());
  ASSERT_EQ(brr.exception_breaks_size(), 1);
  pb::ResumeDebugSessionRequest rr;
  rr.set_session_id(created.session_id());
  pb::ResumeDebugSessionResponse resumed;
  ASSERT_TRUE(backend_->ResumeDebugSession(ctx_, rr, resumed).ok());
  EXPECT_EQ(resumed.stop().kind(), pb::DEBUG_STOP_KIND_EXCEPTION) << resumed.stop().detail();
  EXPECT_EQ(resumed.state().pc().address().offset(), 0x18u);
  EXPECT_TRUE(resumed.state().machine());

  // Run to the end; the timeline has the interrupts as events.
  br.clear_exception_breaks();
  ASSERT_TRUE(backend_->SetDebugBreakpoints(ctx_, br, brr).ok());
  ASSERT_TRUE(backend_->ResumeDebugSession(ctx_, rr, resumed).ok());
  EXPECT_EQ(resumed.stop().kind(), pb::DEBUG_STOP_KIND_EXITED) << resumed.stop().detail();
  EXPECT_EQ(resumed.state().output(), "timer irq test\nticks 10 fiq 2 r8 kept\ndone\n");
  pb::GetDebugTimelineRequest tr;
  tr.set_session_id(created.session_id());
  tr.set_events_only(true);
  tr.set_limit(10000);
  pb::GetDebugTimelineResponse tl;
  ASSERT_TRUE(backend_->GetDebugTimeline(ctx_, tr, tl).ok());
  int irqs = 0, fiqs = 0, returns = 0;
  for (const auto &s : tl.snapshots()) {
    irqs += s.event() == "irq";
    fiqs += s.event() == "fiq";
    returns += s.event() == "return";
    EXPECT_FALSE(s.event().empty());
  }
  EXPECT_EQ(irqs, 10);
  EXPECT_EQ(fiqs, 2);
  EXPECT_GE(returns, 12);

  pb::GetDebugMachineRequest mreq;
  mreq.set_session_id(created.session_id());
  pb::GetDebugMachineResponse m;
  ASSERT_TRUE(backend_->GetDebugMachine(ctx_, mreq, m).ok());
  EXPECT_GE(m.state().tick(), 100000u);

  // A trace saved and replayed keeps its events.
  pb::SaveDebugTraceRequest sr;
  sr.set_session_id(created.session_id());
  sr.set_name("irqs");
  pb::SaveDebugTraceResponse srr;
  ASSERT_TRUE(backend_->SaveDebugTrace(ctx_, sr, srr).ok());
  pb::CreateDebugSessionRequest replay;
  replay.set_program_id(id);
  replay.mutable_trace()->set_name("irqs");
  pb::CreateDebugSessionResponse rc;
  ASSERT_TRUE(backend_->CreateDebugSession(ctx_, replay, rc).ok());
  tr.set_session_id(rc.session_id());
  pb::GetDebugTimelineResponse tl2;
  ASSERT_TRUE(backend_->GetDebugTimeline(ctx_, tr, tl2).ok());
  int replayed = 0;
  for (const auto &s : tl2.snapshots()) replayed += s.event() == "irq";
  EXPECT_EQ(replayed, 10);

  pb::DeleteMachineRequest del;
  del.set_program_id(id);
  del.set_name("versatilepb");
  pb::DeleteMachineResponse deleted;
  EXPECT_TRUE(backend_->DeleteMachine(ctx_, del, deleted).ok());
  EXPECT_EQ(backend_->DeleteMachine(ctx_, del, deleted).code, StatusCode::kNotFound);
}

// Hooks on firmware (api_minor 68, feature "debugger-hooks"): the synthetic
// firmware's device registers modeled from the client, with no machine:
// its two configuration writes seen, the ready bit it polls answered, and
// the run past the loop.
TEST_F(FirmwareApi, MmioHooksModelTheDevice) {
  const std::string id = Import(dir_ / "armfw" / "fw.bin", "armfw-hooks", true);
  // RAM for the reset handler's stack (0x20008000 down).
  pb::AddMemoryRegionRequest ram;
  ram.set_program_id(id);
  ram.mutable_region()->set_name("ram");
  ram.mutable_region()->set_start(0x20000000);
  ram.mutable_region()->set_size(0x8000);
  ram.mutable_region()->set_read(true);
  ram.mutable_region()->set_write(true);
  ram.mutable_region()->set_initialized(true);
  ram.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  ram.mutable_provenance()->set_id("test");
  pb::AddMemoryRegionResponse added;
  auto rst = backend_->AddMemoryRegion(ctx_, ram, added);
  ASSERT_TRUE(rst.ok()) << rst.message;
  pb::CreateDebugSessionRequest req;
  req.set_program_id(id);
  req.mutable_emulator()->mutable_entry()->set_offset(0);  // the reset vector
  req.mutable_emulator()->set_mode(pb::EMULATOR_START_MODE_BARE);
  pb::CreateDebugSessionResponse created;
  auto st = backend_->CreateDebugSession(ctx_, req, created);
  ASSERT_TRUE(st.ok()) << st.message;
  const std::string sid = created.session_id();
  pb::SetDebugHooksRequest hr;
  hr.set_session_id(sid);
  auto *spec = hr.add_add();
  spec->set_kind(pb::DEBUG_HOOK_KIND_MMIO);
  spec->mutable_address()->set_offset(0xd0000010);
  spec->set_size(12);
  pb::SetDebugHooksResponse hooks;
  st = backend_->SetDebugHooks(ctx_, hr, hooks);
  ASSERT_TRUE(st.ok()) << st.message;
  const int hook = hooks.hooks(0).id();
  auto resume = [&] {
    pb::ResumeDebugSessionRequest rr;
    rr.set_session_id(sid);
    rr.set_mode(pb::DEBUG_RUN_MODE_RUN);
    rr.set_max_steps(200000);
    pb::ResumeDebugSessionResponse r;
    auto s = backend_->ResumeDebugSession(ctx_, rr, r);
    EXPECT_TRUE(s.ok()) << s.message;
    return r;
  };
  std::vector<std::pair<std::uint64_t, std::uint64_t>> writes;
  std::optional<std::uint64_t> polled_at;
  for (int i = 0; i < 6; ++i) {
    auto r = resume();
    if (r.stop().kind() != pb::DEBUG_STOP_KIND_HOOK) {
      // Past the loop: on to the firmware's bad pointer slot, as with a machine.
      EXPECT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_UNMAPPED) << r.stop().DebugString();
      break;
    }
    const auto &ev = r.stop().hook();
    EXPECT_EQ(ev.hook_id(), hook);
    if (ev.write()) {
      writes.emplace_back(ev.address(), ev.value());
      continue;  // unanswered: the write goes on
    }
    EXPECT_EQ(ev.address(), 0xd0000018u);
    EXPECT_FALSE(polled_at.has_value()) << "the ready bit was read twice";
    polled_at = ev.pc();
    pb::AnswerDebugHookRequest ar;
    ar.set_session_id(sid);
    ar.set_hook_id(hook);
    ar.set_value(1);
    pb::AnswerDebugHookResponse ans;
    ASSERT_TRUE(backend_->AnswerDebugHook(ctx_, ar, ans).ok());
  }
  ASSERT_EQ(writes.size(), 2u);
  EXPECT_EQ(writes[0], std::make_pair(std::uint64_t{0xd0000010}, std::uint64_t{1}));
  EXPECT_EQ(writes[1], std::make_pair(std::uint64_t{0xd0000014}, std::uint64_t{0x200}));
  EXPECT_TRUE(polled_at.has_value());
  pb::CloseDebugSessionRequest close;
  close.set_session_id(sid);
  pb::CloseDebugSessionResponse closed;
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
}

// The synthetic firmware: its import declares the status register's region;
// the starter machine finds the polling loop on it and answers it.
TEST_F(FirmwareApi, DerivesAStarterMachine) {
  const std::string id = Import(dir_ / "armfw" / "fw.bin", "armfw", true);
  pb::DeriveMachineRequest req;
  req.set_program_id(id);
  req.set_trial_steps(500000);
  pb::DeriveMachineResponse resp;
  auto st = backend_->DeriveMachine(ctx_, req, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_GE(resp.mmio_registers(), 3u);  // 0xd0000010, 0x14, 0x18
  EXPECT_EQ(resp.polling_loops(), 1u);
  EXPECT_NE(resp.machine().find("0xd0000018"), std::string::npos) << resp.machine();
  // It runs as derived: past the loop, on to the bad pointer slot.
  pb::CreateEmulatorSessionRequest create;
  create.set_program_id(id);
  create.set_machine(resp.machine());
  pb::CreateEmulatorSessionResponse created;
  st = backend_->CreateEmulatorSession(ctx_, create, created);
  ASSERT_TRUE(st.ok()) << st.message;
  pb::RunEmulatorRequest run;
  run.set_session_id(created.session_id());
  pb::RunEmulatorResponse ran;
  ASSERT_TRUE(backend_->RunEmulator(ctx_, run, ran).ok());
  EXPECT_EQ(ran.stop().kind(), pb::EMULATOR_STOP_KIND_UNMAPPED) << ran.stop().detail();
  EXPECT_EQ(ran.stop().address().offset(), 0xffffffffu);

  pb::ListPeripheralKindsResponse kinds;
  ASSERT_TRUE(backend_->ListPeripheralKinds(ctx_, {}, kinds).ok());
  bool pl011 = false;
  for (const auto &k : kinds.kinds()) pl011 = pl011 || k.kind() == "pl011";
  EXPECT_TRUE(pl011);
}

}  // namespace
}  // namespace revkit::backend
