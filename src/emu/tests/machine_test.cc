// Firmware emulation (docs/firmware-emulation.md): bare-metal programs
// (fixtures/fwemu) on machine descriptions, with timer, UART and software
// interrupts on ARMv4T (qemu's versatilepb) and Cortex-M3 (lm3s6965evb),
// and a made-up SoC described with the configurable built-ins. Their UART
// output is checked against hand-written expectations and, where
// qemu-system-arm is installed, against qemu running the same ELF.
#include "util.hh"

#include "revkit/emu/machine.hh"

#include <cstdlib>
#include <filesystem>
#include <sys/wait.h>
#include <unistd.h>
#include <fstream>
#include <regex>
#include <sstream>

namespace revkit::emu {
namespace {

namespace fs = std::filesystem;

std::string read_file(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  std::stringstream s;
  s << in.rdbuf();
  return s.str();
}

struct Outcome {
  std::string out;
  Stop stop;
  std::uint64_t steps = 0;
  std::uint64_t tick = 0;
  std::vector<ExceptionEvent> events;
  std::string trace;
};

class FirmwareMachine : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    out_ = testing::build_fixtures(REVKIT_FWEMU_DIR, REVKIT_FWEMU_OUT, REVKIT_CLANG, REVKIT_LLD, REVKIT_OBJCOPY);
    built_ = !out_.empty();
  }
  void SetUp() override {
    if (!testing::ghidra_ready()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!built_) GTEST_SKIP() << "no clang, ld.lld and llvm-objcopy for armv4t and thumbv7m";
  }

  static MachineSpec board(const std::string &name) {
    return parse_machine(read_file(fs::path(REVKIT_FWEMU_DIR) / name));
  }

  // Runs a fixture's raw image on a board until it exits (or `steps`).
  static Outcome run(const std::string &board_file, const std::string &program, const std::string &input = "",
                 std::uint64_t steps = 2000000, std::size_t trace = 0, std::vector<std::string> break_on = {}) {
    MachineSpec spec = board(board_file);
    spec.break_on = std::move(break_on);
    const fs::path bin = out_ / (program + ".bin");
    loader::RawOptions raw = machine_raw_options(spec, fs::file_size(bin));
    auto image = std::make_shared<const loader::Image>(loader::load_raw_file(bin, raw));
    Options o;
    o.language = spec.language;
    o.trace_capacity = trace;
    o.stdin_data = input;
    Emulator e(image, o);
    e.attach_machine(spec, {});
    RunOptions ro;
    ro.max_steps = steps;
    Outcome r;
    r.stop = e.run(ro);
    r.out = e.stdout_data();
    r.steps = e.steps();
    r.tick = e.machine()->now();
    r.events.assign(e.machine()->events().begin(), e.machine()->events().end());
    if (trace) r.trace = trace_json(e);
    return r;
  }

  static int count(const Outcome &r, const std::string &kind) {
    int n = 0;
    for (const ExceptionEvent &e : r.events) n += e.kind == kind;
    return n;
  }

  // The fixture under qemu-system-arm (stdout only), or nullopt without it.
  // Input goes in once the program's first line is out: qemu loses bytes
  // that arrive before the guest has set its UART up.
  static std::optional<std::string> qemu(const std::string &machine, const std::string &program, const std::string &input) {
    int status = 0;
    if (testing::run_command("command -v qemu-system-arm >/dev/null 2>&1 && echo yes", status).find("yes") == std::string::npos)
      return std::nullopt;
    const fs::path elf = out_ / (program + ".elf");
    const std::string cmd = "exec timeout 60 qemu-system-arm -M " + machine +
                            (machine == "versatilepb" ? " -cpu arm926 -m 128M" : "") +
                            " -nographic -monitor none -serial stdio -semihosting -kernel " + elf.string() + " 2>/dev/null";
    int in[2], out[2];
    if (pipe(in) != 0 || pipe(out) != 0) return std::nullopt;
    const pid_t pid = fork();
    if (pid == 0) {
      dup2(in[0], 0);
      dup2(out[1], 1);
      close(in[0]);
      close(in[1]);
      close(out[0]);
      close(out[1]);
      execl("/bin/sh", "sh", "-c", cmd.c_str(), static_cast<char *>(nullptr));
      _exit(127);
    }
    close(in[0]);
    close(out[1]);
    std::string text;
    bool sent = false;
    char buf[4096];
    for (;;) {
      const ssize_t n = read(out[0], buf, sizeof buf);
      if (n <= 0) break;
      text.append(buf, static_cast<std::size_t>(n));
      if (!sent && text.find('\n') != std::string::npos) {
        // Kept open: qemu may drop what it hasn't read yet at end of file.
        if (!input.empty() && write(in[1], input.data(), input.size()) != static_cast<ssize_t>(input.size())) break;
        sent = true;
      }
    }
    close(in[1]);
    close(out[0]);
    int rc = 0;
    waitpid(pid, &rc, 0);
    EXPECT_TRUE(WIFEXITED(rc) && WEXITSTATUS(rc) == 0) << cmd;
    return text;
  }

  static inline bool built_ = false;
  static inline fs::path out_;  // this process's copy of the fixtures
};

TEST_F(FirmwareMachine, ArmTimerIrqAndFiq) {
  const Outcome r = run("versatilepb.json", "arm_timer");
  EXPECT_EQ(r.stop.kind, StopKind::exited) << r.stop.detail;
  EXPECT_EQ(r.out, "timer irq test\nticks 10 fiq 2 r8 kept\ndone\n");
  EXPECT_EQ(count(r, "irq"), 10);
  EXPECT_EQ(count(r, "fiq"), 2);
  EXPECT_GE(count(r, "return"), 22);  // every IRQ, FIQ and SWI returned
  // Idle skipping: 100 ms of machine time in under a thousand instructions.
  EXPECT_GE(r.tick, 100000u);
  EXPECT_LT(r.steps, 2000u);
  for (const ExceptionEvent &e : r.events)
    if (e.kind == "irq") {
      EXPECT_EQ(e.handler, 0x18u);
      EXPECT_EQ(e.source, "vic");
    }
}

TEST_F(FirmwareMachine, ArmUartEchoesInput) {
  const Outcome r = run("versatilepb.json", "arm_uart", "hello\nquit\n");
  EXPECT_EQ(r.stop.kind, StopKind::exited) << r.stop.detail;
  EXPECT_EQ(r.out, "uart echo test\necho: HELLO\necho: QUIT\nlines 2\ndone\n");
  EXPECT_GE(count(r, "irq"), 1);
}

TEST_F(FirmwareMachine, ArmSwiModesAndUndefined) {
  const Outcome r = run("versatilepb.json", "arm_swi");
  EXPECT_EQ(r.stop.kind, StopKind::exited) << r.stop.detail;
  // SWI from user mode runs in supervisor mode with IRQs masked (0x93),
  // SPSR holds the user mode (0x10); SP is banked; the undefined
  // instruction traps once and resumes.
  EXPECT_EQ(r.out, "swi test\nadd 42\nmul 42\nmodes 93 10\nstacks banked\ntraps 1\ndone\n");
  EXPECT_EQ(count(r, "undefined"), 1);
}

TEST_F(FirmwareMachine, CortexSysTickPendSvOnTheProcessStack) {
  const Outcome r = run("lm3s6965.json", "cm_timer");
  EXPECT_EQ(r.stop.kind, StopKind::exited) << r.stop.detail;
  EXPECT_EQ(r.out, "systick test\nticks 10 pendsv 2 psp\ndone\n");
  EXPECT_EQ(count(r, "systick"), 10);
  EXPECT_EQ(count(r, "pendsv"), 2);
}

TEST_F(FirmwareMachine, CortexUartEchoesInput) {
  const Outcome r = run("lm3s6965.json", "cm_uart", "hello\nquit\n");
  EXPECT_EQ(r.stop.kind, StopKind::exited) << r.stop.detail;
  EXPECT_EQ(r.out, "uart echo test\necho: HELLO\necho: QUIT\nlines 2\ndone\n");
}

TEST_F(FirmwareMachine, CortexSvcFramesAndItBlocks) {
  const Outcome r = run("lm3s6965.json", "cm_svc");
  EXPECT_EQ(r.stop.kind, StopKind::exited) << r.stop.detail;
  EXPECT_EQ(r.out, "svc test\nadd 42\nmul 42\nipsr 11\nframes on msp then psp\nmax 9\ndone\n");
  EXPECT_EQ(count(r, "svc"), 5);
}

TEST_F(FirmwareMachine, ConfigurableBuiltinsOnAMadeUpSoc) {
  const Outcome r = run("custom_soc.json", "custom");
  EXPECT_EQ(r.stop.kind, StopKind::exited) << r.stop.detail;
  // Timer 0 (IRQ 45) fires every 1000 counts; timer 1's IRQ 40 stays masked.
  EXPECT_EQ(r.out, "custom soc test\nticks 5 irq 45 others 0\ndone\n");
  EXPECT_GE(r.tick, 5000u);
  EXPECT_LT(r.tick, 6000u);
}

// MIPS: hand-checked (no qemu-system-mips here). Count/Compare interrupts
// every 1000 counts (2000 ticks), five times while main waits; a SYSCALL's
// handler doubles a0 into v0 and returns past the instruction.
TEST_F(FirmwareMachine, MipsTimerAndSyscall) {
  if (!fs::exists(out_ / "mips.bin")) GTEST_SKIP() << "clang has no MIPS target";
  const Outcome r = run("mips.json", "mips");
  EXPECT_EQ(r.stop.kind, StopKind::halted) << r.stop.detail;  // interrupts off, then a branch to itself
  EXPECT_EQ(r.out, "mips test\nticks 5\nsyscall 42\ndone\n");
  EXPECT_EQ(count(r, "interrupt"), 5);
  EXPECT_EQ(count(r, "syscall"), 1);
  EXPECT_EQ(count(r, "return"), 6);
  for (const ExceptionEvent &e : r.events)
    if (e.kind == "interrupt") {
      EXPECT_EQ(e.number, 7);
      EXPECT_EQ(e.handler, 0x80000180u);
    }
  EXPECT_GE(r.tick, 10000u);
}

// qemu's timers run on the host's clock (revkit's on instructions): on a
// loaded host one more tick can land before the program reads its count. The
// outputs must match except a "ticks N" count off by one.
bool SameAsQemu(const std::string &ours, const std::string &qemus) {
  if (ours == qemus) return true;
  static const std::regex ticks(R"(ticks (\d+))");
  auto numbers = [](const std::string &s) {
    std::vector<long> out;
    for (std::sregex_iterator it(s.begin(), s.end(), ticks), end; it != end; ++it) out.push_back(std::stol((*it)[1]));
    return out;
  };
  if (std::regex_replace(ours, ticks, "ticks N") != std::regex_replace(qemus, ticks, "ticks N")) return false;
  const auto a = numbers(ours), b = numbers(qemus);
  for (std::size_t i = 0; i < a.size(); ++i)
    if (std::abs(a[i] - b[i]) > 1) return false;
  return true;
}

TEST(FirmwareMachineQemu, TickCountsMayDifferByOne) {
  EXPECT_TRUE(SameAsQemu("ticks 10 pendsv 2\ndone\n", "ticks 11 pendsv 2\ndone\n"));
  EXPECT_FALSE(SameAsQemu("ticks 10 pendsv 2\ndone\n", "ticks 12 pendsv 2\ndone\n"));
  EXPECT_FALSE(SameAsQemu("ticks 10 pendsv 2\ndone\n", "ticks 10 pendsv 3\ndone\n"));
}

TEST_F(FirmwareMachine, SameOutputAsQemu) {
  struct Case {
    const char *qemu_machine, *board, *program, *input;
  };
  const Case cases[] = {
      {"versatilepb", "versatilepb.json", "arm_timer", ""},
      {"versatilepb", "versatilepb.json", "arm_uart", "hello\nquit\n"},
      {"versatilepb", "versatilepb.json", "arm_swi", ""},
      {"lm3s6965evb", "lm3s6965.json", "cm_timer", ""},
      {"lm3s6965evb", "lm3s6965.json", "cm_uart", "hello\nquit\n"},
      {"lm3s6965evb", "lm3s6965.json", "cm_svc", ""},
  };
  for (const Case &c : cases) {
    auto q = qemu(c.qemu_machine, c.program, c.input);
    if (!q) GTEST_SKIP() << "qemu-system-arm is not installed (apt install qemu-system-arm)";
    const Outcome r = run(c.board, c.program, c.input);
    EXPECT_TRUE(SameAsQemu(r.out, *q)) << c.program << ": revkit\n" << r.out << "qemu\n" << *q;
    EXPECT_FALSE(q->empty()) << c.program;
  }
}

TEST_F(FirmwareMachine, TracesAreDeterministic) {
  const Outcome a = run("versatilepb.json", "arm_timer", "", 2000000, 1 << 16);
  const Outcome b = run("versatilepb.json", "arm_timer", "", 2000000, 1 << 16);
  EXPECT_EQ(a.trace, b.trace);
  EXPECT_NE(a.trace.find("\"exception\":\"irq\""), std::string::npos);
  EXPECT_NE(a.trace.find("\"machine\":{\"cpu\":\"arm\""), std::string::npos);
  const Outcome c = run("lm3s6965.json", "cm_uart", "hello\nquit\n", 2000000, 1 << 16);
  const Outcome d = run("lm3s6965.json", "cm_uart", "hello\nquit\n", 2000000, 1 << 16);
  EXPECT_EQ(c.trace, d.trace);
}

TEST_F(FirmwareMachine, BreaksOnIrqEntry) {
  MachineSpec spec = board("versatilepb.json");
  const fs::path bin = out_ / "arm_timer.bin";
  auto image = std::make_shared<const loader::Image>(loader::load_raw_file(bin, machine_raw_options(spec, fs::file_size(bin))));
  Options o;
  o.language = spec.language;
  o.trace_capacity = 64;
  Emulator e(image, o);
  Machine &m = e.attach_machine(spec, {});
  m.set_break_on({"irq"});
  Stop s = e.run({});
  ASSERT_EQ(s.kind, StopKind::exception) << s.detail;
  EXPECT_EQ(s.pc, 0x18u);
  EXPECT_EQ(e.pc(), 0x18u);
  EXPECT_EQ(m.state().mode, "irq");
  EXPECT_EQ(e.read_register("cpsr") & 0x1f, 0x12u);
  EXPECT_EQ(e.read_register("spsr") & 0x1f, 0x10u);  // from user mode
  // The entry is a recorded step, with what it wrote.
  ASSERT_FALSE(e.trace().entries().empty());
  const TraceEntry &t = e.trace().entries().back();
  EXPECT_EQ(t.exception, "irq");
  EXPECT_EQ(t.text, "<irq>");
  bool lr = false;
  for (const RegisterWrite &w : t.registers) lr = lr || w.name == "lr";
  EXPECT_TRUE(lr);
  // Continue: the next one stops too; only FIQ when asked.
  s = e.run({});
  EXPECT_EQ(s.kind, StopKind::exception);
  m.set_break_on({"fiq"});
  s = e.run({});
  EXPECT_EQ(s.kind, StopKind::exception);
  EXPECT_EQ(e.pc(), 0x1cu);
  EXPECT_EQ(m.state().mode, "fiq");
  m.set_break_on({});
  s = e.run({});
  EXPECT_EQ(s.kind, StopKind::exited) << s.detail;
  EXPECT_EQ(e.stdout_data(), "timer irq test\nticks 10 fiq 2 r8 kept\ndone\n");
}

TEST_F(FirmwareMachine, IdleWithNothingScheduledStops) {
  // The echo program waits for input that never comes.
  const Outcome r = run("versatilepb.json", "arm_uart", "");
  EXPECT_EQ(r.stop.kind, StopKind::idle) << r.stop.detail;
  EXPECT_EQ(r.out, "uart echo test\n");
}

TEST_F(FirmwareMachine, InputArrivingLaterWakesTheCpu) {
  MachineSpec spec = board("lm3s6965.json");
  const fs::path bin = out_ / "cm_uart.bin";
  auto image = std::make_shared<const loader::Image>(loader::load_raw_file(bin, machine_raw_options(spec, fs::file_size(bin))));
  Options o;
  o.language = spec.language;
  Emulator e(image, o);
  Machine &m = e.attach_machine(spec, {});
  EXPECT_EQ(e.run({}).kind, StopKind::idle);
  EXPECT_TRUE(m.state().waiting);
  EXPECT_TRUE(m.input("", "abc\n"));
  EXPECT_EQ(e.run({}).kind, StopKind::idle);
  EXPECT_TRUE(m.input("uart0", "quit\n"));
  EXPECT_EQ(e.run({}).kind, StopKind::exited);
  EXPECT_EQ(e.stdout_data(), "uart echo test\necho: ABC\necho: QUIT\nlines 2\ndone\n");
}

// The synthetic firmware (src/analysis/tests/fixtures/armfw) polls a status
// register at 0xd0000018 for its ready bit: an auto-ack register answers.
TEST_F(FirmwareMachine, AutoAckGetsPastAPollingLoop) {
  const fs::path armfw =
      testing::build_fixtures(REVKIT_ARMFW_DIR, REVKIT_ARMFW_OUT, REVKIT_CLANG, REVKIT_LLD, REVKIT_OBJCOPY);
  ASSERT_FALSE(armfw.empty());
  const std::string text = R"({
    "language": "ARM:LE:32:v4t",
    "memory": [{"name": "sram", "start": "0x20000000", "size": "0x10000"},
               {"name": "sysctrl", "start": "0xd0000000", "size": "0x1000", "kind": "mmio"}],
    "peripherals": [{"name": "ack", "kind": "auto-ack",
                     "registers": [{"address": "0xd0000018", "mask": "0x31", "value": "0x31"}]}]
  })";
  MachineSpec spec = parse_machine(text);
  const fs::path bin = armfw / "fw.bin";
  auto image = std::make_shared<const loader::Image>(loader::load_raw_file(bin, machine_raw_options(spec, fs::file_size(bin))));
  Options o;
  o.language = "ARM:LE:32:v4t:default";
  Emulator e(image, o);
  e.attach_machine(spec, {});
  const Stop s = e.run({});
  // As with a hook answering the register: on to the store through the bad slot.
  EXPECT_EQ(s.kind, StopKind::unmapped) << s.detail;
  EXPECT_TRUE(s.address && *s.address == 0xffffffffu);
}

// A peripheral whose range runs past the top of memory wrapped: the
// device mapped nothing and its range check passed (docs/bug-scrub.md).
TEST_F(FirmwareMachine, APeripheralPastTheEndOfMemoryIsRefused) {
  const fs::path armfw =
      testing::build_fixtures(REVKIT_ARMFW_DIR, REVKIT_ARMFW_OUT, REVKIT_CLANG, REVKIT_LLD, REVKIT_OBJCOPY);
  ASSERT_FALSE(armfw.empty());
  const std::string text = R"({
    "language": "ARM:LE:32:v4t",
    "memory": [{"name": "sram", "start": "0x20000000", "size": "0x10000"}],
    "peripherals": [{"name": "t", "kind": "timer", "base": "0xfffffffffffffff0", "size": "0x100", "irq": "cpu.irq"}]
  })";
  MachineSpec spec = parse_machine(text);
  const fs::path bin = armfw / "fw.bin";
  auto image = std::make_shared<const loader::Image>(loader::load_raw_file(bin, machine_raw_options(spec, fs::file_size(bin))));
  Options o;
  o.language = "ARM:LE:32:v4t:default";
  Emulator e(image, o);
  try {
    e.attach_machine(spec, {});
    ADD_FAILURE() << "attached";
  } catch (const MachineError &err) {
    EXPECT_NE(std::string(err.what()).find("past the end of memory"), std::string::npos) << err.what();
  }
}

TEST(Machine, ParseErrorsSayWhere) {
  try {
    parse_machine("{\n  \"memory\": [{\"start\": \"0x10\", \"size\": \"lots\"}]\n}");
    FAIL() << "accepted";
  } catch (const MachineError &e) {
    EXPECT_NE(std::string(e.what()).find("2:"), std::string::npos) << e.what();
    EXPECT_NE(std::string(e.what()).find("lots"), std::string::npos) << e.what();
  }
  EXPECT_THROW(parse_machine("{\"memroy\": []}"), MachineError);
  EXPECT_THROW(parse_machine("{\"cpu\": \"z80\"}"), MachineError);
  EXPECT_THROW(parse_machine("{\"memory\": [{\"start\": 0, \"size\": 16}, {\"start\": 8, \"size\": 16}]}"), MachineError);
  // Comments, trailing commas, sizes with units.
  const MachineSpec s = parse_machine(R"({
    // a board
    "memory": [{"name": "ram", "start": "0x0", "size": "8M",},],
    "peripherals": [{"name": "t", "kind": "timer", "base": "0xc000", "irq": "cpu.irq"}],
  })");
  ASSERT_EQ(s.memory.size(), 1u);
  EXPECT_EQ(s.memory[0].size, 8u << 20);
  ASSERT_EQ(s.peripherals.size(), 1u);
  EXPECT_EQ(s.peripherals[0].irqs.at(0).second, "cpu.irq");
  // What machine_json writes reads back the same.
  const MachineSpec again = parse_machine(machine_json(s));
  EXPECT_EQ(again.memory[0].size, s.memory[0].size);
  EXPECT_EQ(again.peripherals[0].kind, "timer");
  EXPECT_EQ(again.peripherals[0].base, s.peripherals[0].base);
}

TEST(Machine, RawOptionsLoadTheImageInsideItsMemory) {
  const MachineSpec s = parse_machine(R"({
    "language": "ARM:LE:32:v4t",
    "memory": [{"name": "ram", "start": "0x0", "size": "8M"},
               {"name": "io", "start": "0xa0000000", "size": "0x1000", "kind": "mmio"}],
    "image": {"load": "0x0", "offset": "0x40"}
  })");
  const loader::RawOptions o = machine_raw_options(s, 0x40 + 0x1000);
  EXPECT_EQ(o.offset, 0x40u);
  EXPECT_EQ(o.base, 0u);
  ASSERT_EQ(o.regions.size(), 2u);
  EXPECT_EQ(o.regions[0].name, "ram");
  EXPECT_EQ(o.regions[0].start, 0x1000u);  // the rest of the RAM after the image
  EXPECT_EQ(o.regions[0].size, (8u << 20) - 0x1000u);
  EXPECT_TRUE(o.regions[1].is_volatile);
}

}  // namespace
}  // namespace revkit::emu
