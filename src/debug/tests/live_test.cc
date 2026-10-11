// Live processes: the debuggee (programs/debuggee.c) under gdbserver on
// x86-64 (a PIE, so its addresses slide) and under qemu-aarch64's gdbstub
// (static and static-pie). Breakpoints set at the program's static
// addresses, stepping into, over and out of calls (with recursion), register
// and memory reads, a watchpoint, threads, modules and the memory map, the
// exit, and the recorded timeline. Skipped without gdbserver or qemu.
#include "util.hh"

#include <csignal>
#include <fstream>
#include <thread>

namespace revkit::debug {
namespace {

namespace fs = std::filesystem;

using testing::Program;
using testing::reg;
using testing::within;

class LiveX86 : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    const auto out = testing::out_dir() / "debuggee";
    built_ = testing::compile("cc -O0 -g0 -fno-inline -pie -fPIE -pthread -o {out} " REVKIT_DEBUG_TEST_SRC
                              "/programs/debuggee.c", out);
  }
  void SetUp() override {
    if (!testing::ghidra_ready()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (host_machine() != 62) GTEST_SKIP() << "not an x86-64 host";
    if (find_program("gdbserver").empty()) GTEST_SKIP() << "gdbserver is not installed (apt install gdbserver)";
    if (!built_) GTEST_SKIP() << "no C compiler";
    prog_ = Program::load(testing::out_dir() / "debuggee");
  }
  static inline bool built_ = false;
  Program prog_;
};

TEST_F(LiveX86, BreakStepReadPie) {
  auto s = launch_session(prog_);
  Target &t = s->target();
  EXPECT_EQ(t.kind(), "gdb-remote");
  EXPECT_EQ(t.state(), TargetState::stopped);
  EXPECT_EQ(t.pc_register(), "RIP");
  ASSERT_NE(t.find_register("RAX"), nullptr);
  EXPECT_EQ(t.find_register("eflags")->name, "rflags");

  // The PIE slid: revkit loads it at 0x100000 (Ghidra's base), the kernel elsewhere.
  ASSERT_TRUE(s->mapping().known) << s->mapping().how;
  EXPECT_EQ(s->mapping().how, "auxv AT_ENTRY");
  const std::uint64_t main_static = prog_.symbol("main");
  EXPECT_GE(main_static, 0x100000u);
  EXPECT_LT(main_static, 0x200000u);
  EXPECT_NE(s->mapping().slide, 0);
  EXPECT_EQ(static_cast<std::uint64_t>(s->mapping().slide) & 0xfff, 0u);
  const std::uint64_t main_rt = s->to_runtime(main_static);
  EXPECT_EQ(s->to_program(main_rt), main_static);

  // A breakpoint in program addresses lands on the runtime main.
  const Breakpoint &bp = s->add_breakpoint(BreakKind::software, main_static, true);
  EXPECT_TRUE(bp.inserted) << bp.error;
  EXPECT_EQ(bp.address, main_rt);
  Stop st = s->resume(RunMode::run, within(20));
  ASSERT_EQ(st.kind, StopKind::breakpoint) << st.detail;
  EXPECT_EQ(st.pc, main_rt);
  EXPECT_EQ(reg(*s, "RIP"), main_rt);
  EXPECT_EQ(reg(*s, "RDI"), 1u);  // argc
  EXPECT_EQ(s->breakpoints()[0].hits, 1u);
  const Snapshot *at_main = s->timeline().find(s->current_snapshot());
  ASSERT_NE(at_main, nullptr);
  EXPECT_EQ(at_main->program_pc, main_static);

  // Memory: the string, by its static address.
  const std::uint64_t msg = s->to_runtime(prog_.symbol("message"));
  std::vector<std::uint8_t> buf(15);
  ASSERT_EQ(s->read_memory(msg, buf), 15u);
  EXPECT_EQ(std::string(buf.begin(), buf.end()), "hello, debugger");
  const std::uint64_t main_snap = s->current_snapshot();

  // Into middle; step over its call to leaf without entering it.
  s->add_breakpoint(BreakKind::software, prog_.symbol("middle"), true);
  st = s->resume(RunMode::run, within(20));
  ASSERT_EQ(st.kind, StopKind::breakpoint) << st.detail;
  EXPECT_EQ(s->to_program(st.pc), prog_.symbol("middle"));
  const std::uint64_t mid_lo = prog_.symbol("middle"), mid_hi = mid_lo + prog_.symbol_size("middle");
  bool saw_six = false;
  for (int i = 0; i < 30 && !saw_six; ++i) {
    st = s->resume(RunMode::step_over, within(20));
    ASSERT_EQ(st.kind, StopKind::stepped) << st.detail;
    auto p = s->to_program(st.pc);
    ASSERT_TRUE(p && *p >= mid_lo && *p < mid_hi) << "stepped out of middle to " << hex(st.pc);
    saw_six = (reg(*s, "RAX") & 0xffffffff) == 6;  // leaf(2) returned
    if (std::getenv("RK_DEBUG_TEST_VERBOSE")) std::fprintf(stderr, "step over -> %s rax %llx\n", hex(*p).c_str(), (unsigned long long)reg(*s, "RAX"));
  }
  EXPECT_TRUE(saw_six);
  // Out of middle: back in main with its result.
  st = s->resume(RunMode::step_out, within(20));
  ASSERT_EQ(st.kind, StopKind::stepped) << st.detail;
  auto back = s->to_program(st.pc);
  ASSERT_TRUE(back);
  EXPECT_GE(*back, main_static);
  EXPECT_LT(*back, main_static + prog_.symbol_size("main"));
  EXPECT_EQ(reg(*s, "RAX") & 0xffffffff, 7u);

  // Recursion: out of fact(4) returns to fact(5), not main.
  const auto &fbp = s->add_breakpoint(BreakKind::software, prog_.symbol("fact"), true);
  const int fact_bp = fbp.id;
  st = s->resume(RunMode::run, within(20));  // fact(5)
  ASSERT_EQ(st.kind, StopKind::breakpoint);
  EXPECT_EQ(reg(*s, "RDI") & 0xffffffff, 5u);
  st = s->resume(RunMode::run, within(20));  // fact(4)
  ASSERT_EQ(st.kind, StopKind::breakpoint);
  EXPECT_EQ(reg(*s, "RDI") & 0xffffffff, 4u);
  s->remove_breakpoint(fact_bp);
  st = s->resume(RunMode::step_out, within(20));
  ASSERT_EQ(st.kind, StopKind::stepped) << st.detail;
  auto in_fact = s->to_program(st.pc);
  ASSERT_TRUE(in_fact);
  EXPECT_GE(*in_fact, prog_.symbol("fact"));
  EXPECT_LT(*in_fact, prog_.symbol("fact") + prog_.symbol_size("fact"));
  EXPECT_EQ(reg(*s, "RAX") & 0xffffffff, 24u);  // fact(4)
  st = s->resume(RunMode::step_out, within(20));
  EXPECT_EQ(reg(*s, "RAX") & 0xffffffff, 120u);  // fact(5), back in main

  // The store to message[0], seen by reading again; the old value stays at
  // the snapshot at main.
  st = s->resume(RunMode::step_over, within(20));
  for (int i = 0; i < 20; ++i) {
    s->read_memory(msg, buf);
    if (buf[0] == 'H') break;
    s->resume(RunMode::step_into, within(20));
  }
  EXPECT_EQ(buf[0], 'H');
  std::vector<std::uint8_t> then(15);
  std::vector<Timeline::ByteState> state;
  s->memory_at(main_snap, msg, then, state);
  EXPECT_EQ(then[0], 'h');
  EXPECT_EQ(state[0], Timeline::ByteState::exact);
  s->memory_at(s->current_snapshot(), msg, then, state);
  EXPECT_EQ(then[0], 'H');
  // Registers at the breakpoint at main, from the recording.
  EXPECT_EQ(to_u64(s->timeline().registers_at(main_snap)["RIP"]), main_rt);
  EXPECT_EQ(to_u64(s->timeline().registers_at(main_snap)["RDI"]), 1u);

  // Modules and the memory map.
  bool main_mod = false, libc = false;
  for (const ModuleInfo &m : s->modules()) {
    if (m.main) {
      main_mod = true;
      EXPECT_EQ(m.name, "debuggee");
      EXPECT_EQ(m.base, s->to_runtime(prog_.image->image_base));
    }
    if (m.name.rfind("libc.so", 0) == 0) libc = true;
  }
  EXPECT_TRUE(main_mod);
  EXPECT_TRUE(libc);
  bool mapped = false;
  for (const MapRegion &r : s->memory_map())
    if (r.name.find("debuggee") != std::string::npos && r.perms == "r-x") mapped = true;
  EXPECT_TRUE(mapped);
  auto mod = s->module_at(main_rt);
  ASSERT_TRUE(mod);
  EXPECT_EQ(mod->first.name, "debuggee");

  // To the end.
  s->clear_breakpoints();
  st = s->resume(RunMode::run, within(20));
  ASSERT_EQ(st.kind, StopKind::exited) << st.detail;
  EXPECT_EQ(st.exit_code, 0);
  EXPECT_EQ(t.state(), TargetState::exited);
  EXPECT_NE(s->output().find("Hello, debugger 7 120"), std::string::npos) << s->output();
  // The timeline survives the process.
  EXPECT_GT(s->timeline().size(), 10u);
  EXPECT_EQ(s->timeline().find(s->current_snapshot())->stop, StopKind::exited);
}

// The call stack (docs/debugger.md, "Call stack"): at leaf, called from
// middle from main, the frames by the program's CFI, then by frame pointers
// alone; in fact's recursion, one frame per call; at a recorded snapshot.
TEST_F(LiveX86, Backtrace) {
  auto s = launch_session(prog_);
  auto in = [&](const Frame &f, const char *fn) {
    auto p = s->to_program(f.pc);
    if (!p) return false;
    const std::uint64_t at = prog_.symbol(fn), size = prog_.symbol_size(fn);
    return *p >= at && *p < at + (size ? size : 0x100);
  };
  s->add_breakpoint(BreakKind::software, prog_.symbol("leaf"), true);
  Stop st = s->resume(RunMode::run, within(20));
  ASSERT_EQ(st.kind, StopKind::breakpoint) << st.detail;

  auto frames = s->backtrace({});
  ASSERT_GE(frames.size(), 3u);
  EXPECT_TRUE(in(frames[0], "leaf"));
  EXPECT_EQ(frames[0].how, "registers");
  EXPECT_TRUE(in(frames[1], "middle")) << std::hex << frames[1].pc;
  EXPECT_EQ(frames[1].how, "cfi");
  EXPECT_TRUE(in(frames[2], "main")) << std::hex << frames[2].pc;
  EXPECT_EQ(frames[2].how, "cfi");
  // A caller's pc is a return address: just after its call.
  EXPECT_TRUE(s->after_call(frames[1].pc));
  EXPECT_GT(frames[1].sp, frames[0].sp);
  EXPECT_GT(frames[2].sp, frames[1].sp);
  // The frames carry their registers: pc, sp and the frame pointer.
  auto reg_of = [](const Frame &f, const std::string &n) -> std::optional<std::uint64_t> {
    for (const FrameRegister &r : f.registers)
      if (r.name == n) return r.value;
    return std::nullopt;
  };
  EXPECT_EQ(reg_of(frames[1], "RIP"), frames[1].pc);
  EXPECT_EQ(reg_of(frames[1], "RSP"), frames[1].sp);
  EXPECT_TRUE(reg_of(frames[1], "RBP").has_value());

  // Without CFI: the frame-pointer chain (-O0 keeps rbp) finds the same.
  Session::BacktraceOptions nocfi;
  nocfi.cfi = false;
  auto fp = s->backtrace(nocfi);
  ASSERT_GE(fp.size(), 3u);
  EXPECT_TRUE(in(fp[1], "middle")) << std::hex << fp[1].pc;
  EXPECT_TRUE(in(fp[2], "main")) << std::hex << fp[2].pc;
  EXPECT_EQ(fp[1].how, "entry");
  EXPECT_EQ(fp[2].how, "frame pointer");

  // A recorded snapshot: what was recorded of the stack at that stop.
  const std::uint64_t at_leaf = s->current_snapshot();

  // Recursion: fact(1) under four more fact frames, then main.
  s->clear_breakpoints();
  const std::uint64_t fact = prog_.symbol("fact");
  s->add_breakpoint(BreakKind::software, fact, true);
  for (int i = 0; i < 5; ++i) {
    st = s->resume(RunMode::run, within(20));
    ASSERT_EQ(st.kind, StopKind::breakpoint) << st.detail;
  }
  frames = s->backtrace({});
  ASSERT_GE(frames.size(), 6u);
  for (int i = 0; i < 5; ++i) EXPECT_TRUE(in(frames[static_cast<std::size_t>(i)], "fact")) << i;
  EXPECT_TRUE(in(frames[5], "main"));
  Session::BacktraceOptions limited;
  limited.max_frames = 2;
  EXPECT_EQ(s->backtrace(limited).size(), 2u);

  Session::BacktraceOptions past;
  past.snapshot = at_leaf;
  auto then = s->backtrace(past);
  ASSERT_GE(then.size(), 2u);
  EXPECT_TRUE(in(then[0], "leaf"));
  EXPECT_TRUE(in(then[1], "middle"));
  s->target().kill();
}

TEST_F(LiveX86, WatchpointThreadsAndRegisters) {
  auto s = launch_session(prog_, {"threads"});
  const std::uint64_t counter = prog_.symbol("counter");
  const Breakpoint &w = s->add_breakpoint(BreakKind::watch_write, counter, true, 4);
  ASSERT_TRUE(w.inserted) << w.error;
  Stop st = s->resume(RunMode::run, within(20));
  ASSERT_EQ(st.kind, StopKind::watchpoint) << st.detail;
  EXPECT_EQ(st.address, s->to_runtime(counter));
  auto in_leaf = s->to_program(st.pc);
  ASSERT_TRUE(in_leaf);
  EXPECT_GE(*in_leaf, prog_.symbol("leaf"));
  EXPECT_LT(*in_leaf, prog_.symbol("leaf") + prog_.symbol_size("leaf"));
  std::vector<std::uint8_t> v(4);
  s->read_memory(s->to_runtime(counter), v);
  EXPECT_EQ(to_u64(v), 3u);  // leaf(argc + 1), argc 2
  s->clear_breakpoints();

  // Writing registers: the flag registers derived from rflags write it.
  const std::uint64_t rbx = reg(*s, "RBX");
  s->write_register("RBX", from_u64(0x1234567890abcdefull, 8));
  EXPECT_EQ(reg(*s, "RBX"), 0x1234567890abcdefull);
  s->write_register("RBX", from_u64(rbx, 8));
  const std::uint64_t cf = reg(*s, "CF");
  s->write_register("CF", std::vector<std::uint8_t>{static_cast<std::uint8_t>(cf ^ 1)});
  EXPECT_EQ((reg(*s, "rflags") & 1), cf ^ 1);
  s->write_register("CF", std::vector<std::uint8_t>{static_cast<std::uint8_t>(cf)});

  // The worker thread: a second thread while it runs.
  s->add_breakpoint(BreakKind::software, prog_.symbol("leaf"), true);
  bool two = false;
  for (int i = 0; i < 6 && !two; ++i) {
    st = s->resume(RunMode::run, within(20));
    ASSERT_EQ(st.kind, StopKind::breakpoint) << st.detail;
    const auto threads = s->target().threads();
    two = threads.size() >= 2;
    if (two) {
      int current = 0;
      for (const ThreadInfo &t : threads) current += t.current ? 1 : 0;
      EXPECT_EQ(current, 1);
      // Selecting the other thread shows its registers.
      for (const ThreadInfo &t : threads)
        if (!t.current) {
          s->select_thread(t.id);
          EXPECT_EQ(s->target().current_thread(), t.id);
          EXPECT_NE(reg(*s, "RIP"), st.pc);
        }
    }
  }
  EXPECT_TRUE(two);
  s->clear_breakpoints();
  st = s->resume(RunMode::run, within(20));
  EXPECT_EQ(st.kind, StopKind::exited) << st.detail;
}

TEST_F(LiveX86, InterruptAndKill) {
  // A program that never stops on its own.
  const auto src = testing::out_dir() / "spin.c";
  if (!fs::exists(src)) {
    const auto tmp = src.string() + std::to_string(::getpid());
    std::ofstream(tmp) << "volatile unsigned long n; int main(void) { for (;;) n++; }\n";
    fs::rename(tmp, src);
  }
  const auto exe = testing::out_dir() / "spin";
  ASSERT_TRUE(testing::compile("cc -O1 -o {out} " + src.string(), exe));
  Program p = Program::load(exe);
  auto s = launch_session(p);
  ResumeOptions o;
  o.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(300);
  Stop st = s->resume(RunMode::run, o);
  ASSERT_EQ(st.kind, StopKind::running);
  EXPECT_TRUE(s->running());
  EXPECT_THROW(s->resume(RunMode::run, o), DebugError);
  s->interrupt();
  st = s->wait(std::chrono::steady_clock::now() + std::chrono::seconds(5));
  EXPECT_EQ(st.kind, StopKind::interrupted) << st.detail;
  EXPECT_EQ(s->target().state(), TargetState::stopped);
  s->target().kill();
  EXPECT_EQ(s->target().state(), TargetState::exited);
}

TEST_F(LiveX86, AttachAndDetach) {
  // A process that lets any process of its user trace it (PR_SET_PTRACER),
  // so attaching works whatever kernel.yama.ptrace_scope is (up to 2).
  const auto src = testing::out_dir() / "attachee.c";
  if (!fs::exists(src)) {
    const auto tmp = src.string() + std::to_string(::getpid());
    std::ofstream(tmp) << "#include <sys/prctl.h>\n#include <unistd.h>\nvolatile unsigned long n;\n"
                          "int main(void) { prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY); for (;;) { n++; usleep(1000); } }\n";
    fs::rename(tmp, src);
  }
  const auto exe = testing::out_dir() / "attachee";
  ASSERT_TRUE(testing::compile("cc -O1 -o {out} " + src.string(), exe));
  if (ptrace_scope() >= 3) GTEST_SKIP() << "ptrace_scope 3: attaching is disabled";
  const pid_t pid = ::fork();
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    ::execl(exe.c_str(), exe.c_str(), nullptr);
    ::_exit(127);
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(200));  // past the prctl
  Program p = Program::load(exe);
  LaunchOptions lo;
  lo.attach_pid = pid;
  Launched l = launch(lo);
  GdbRemoteOptions o = p.remote_options();
  o.child = l.child;
  {
    Session s(std::make_unique<GdbRemoteTarget>(std::move(l.transport), o), p.session_options());
    EXPECT_EQ(s.target().state(), TargetState::stopped);
    EXPECT_EQ(s.target().process_id(), pid);
    ASSERT_TRUE(s.mapping().known) << s.mapping().how;
    std::vector<std::uint8_t> v(8);
    s.read_memory(s.to_runtime(p.symbol("n")), v);
    const std::uint64_t n0 = to_u64(v);
    EXPECT_GT(n0, 0u);
    s.target().detach();  // it keeps running
    EXPECT_EQ(s.target().state(), TargetState::detached);
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  int status = 0;
  EXPECT_EQ(::waitpid(pid, &status, WNOHANG), 0);  // still running
  ::kill(pid, SIGKILL);
  ::waitpid(pid, &status, 0);
}

TEST(Launch, MissingToolsAreExplained) {
  LaunchOptions o;
  o.program = "/bin/true";
  o.gdbserver = "rk-no-such-gdbserver";
  try {
    launch(o);
    FAIL();
  } catch (const DebugError &e) {
    EXPECT_NE(std::string(e.what()).find("apt install gdbserver"), std::string::npos);
  }
  EXPECT_GE(ptrace_scope(), -1);
}

// --- AArch64 under qemu-user ---

class LiveAarch64 : public ::testing::TestWithParam<const char *> {
 protected:
  void SetUp() override {
    if (!testing::ghidra_ready()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (find_program("qemu-aarch64").empty()) GTEST_SKIP() << "qemu-aarch64 is not installed (apt install qemu-user)";
    if (find_program("aarch64-linux-gnu-gcc").empty()) GTEST_SKIP() << "no aarch64-linux-gnu-gcc";
    const std::string flavor = GetParam();
    const auto out = testing::out_dir() / ("debuggee-aarch64-" + flavor);
    if (!testing::compile("aarch64-linux-gnu-gcc -O0 -g0 -fno-inline -" + flavor + " -pthread -o {out} " +
                              REVKIT_DEBUG_TEST_SRC "/programs/debuggee.c", out))
      GTEST_SKIP() << "aarch64-linux-gnu-gcc can't link -" << flavor;
    prog_ = Program::load(out);
  }
  Program prog_;
};

TEST_P(LiveAarch64, BreakStepRead) {
  auto s = launch_session(prog_);
  EXPECT_NE(s->target().description().find("qemu-aarch64"), std::string::npos);
  EXPECT_EQ(s->target().pc_register(), "pc");
  ASSERT_TRUE(s->mapping().known) << s->mapping().how;
  const std::uint64_t main_static = prog_.symbol("main");
  const Breakpoint &bp = s->add_breakpoint(BreakKind::software, main_static, true);
  ASSERT_TRUE(bp.inserted) << bp.error;
  Stop st = s->resume(RunMode::run, within(30));
  ASSERT_EQ(st.kind, StopKind::breakpoint) << st.detail;
  EXPECT_EQ(s->to_program(st.pc), main_static);
  EXPECT_EQ(reg(*s, "x0"), 1u);  // argc
  std::vector<std::uint8_t> buf(15);
  s->read_memory(s->to_runtime(prog_.symbol("message")), buf);
  EXPECT_EQ(std::string(buf.begin(), buf.end()), "hello, debugger");
  // Over a call and out of one: AArch64's bl and ret.
  s->add_breakpoint(BreakKind::software, prog_.symbol("middle"), true);
  st = s->resume(RunMode::run, within(30));
  ASSERT_EQ(st.kind, StopKind::breakpoint) << st.detail;
  {
    // The call stack at middle's entry: main above it (the CFI, the link register).
    auto frames = s->backtrace({});
    std::string regs;
    for (const FrameRegister &r : frames[0].registers) regs += r.name + "=" + std::to_string(r.value) + " ";
    ASSERT_GE(frames.size(), 2u) << regs;
    EXPECT_EQ(s->to_program(frames[0].pc), prog_.symbol("middle"));
    auto caller = s->to_program(frames[1].pc);
    ASSERT_TRUE(caller.has_value()) << std::hex << frames[1].pc;
    EXPECT_GE(*caller, main_static);
    EXPECT_LT(*caller, main_static + 0x200);
    EXPECT_TRUE(s->after_call(frames[1].pc));
  }
  st = s->resume(RunMode::step_out, within(30));
  ASSERT_EQ(st.kind, StopKind::stepped) << st.detail;
  EXPECT_EQ(reg(*s, "x0") & 0xffffffff, 7u);
  const std::uint64_t pc0 = st.pc;
  st = s->resume(RunMode::step_into, within(30));
  EXPECT_EQ(st.kind, StopKind::stepped);
  EXPECT_EQ(st.pc, pc0 + 4);
  // Flags derived from cpsr, named as the emulator names them.
  ASSERT_NE(s->target().find_register("ZR"), nullptr);
  EXPECT_TRUE(s->target().find_register("ZR")->display);
  s->clear_breakpoints();
  st = s->resume(RunMode::run, within(30));
  ASSERT_EQ(st.kind, StopKind::exited) << st.detail;
  EXPECT_EQ(st.exit_code, 0);
  EXPECT_NE(s->output().find("Hello, debugger 7 120"), std::string::npos) << s->output();
}

INSTANTIATE_TEST_SUITE_P(Linkage, LiveAarch64, ::testing::Values("static", "static-pie"));

}  // namespace
}  // namespace revkit::debug
