// Bare-metal firmware: the synthetic ARM firmware
// (src/analysis/tests/fixtures/armfw) as a raw image, run by qemu-system-arm
// (an ARM926 on QEMU's empty machine, RAM from 0 over the firmware's SRAM and
// device addresses) and debugged through its gdbstub. The debugger plays the
// device the firmware waits for, follows ARM/Thumb interworking, and the
// live machine agrees with revkit's emulator about the same code.
#include "util.hh"

namespace revkit::debug {
namespace {

using testing::Program;
using testing::reg;
using testing::within;

class Firmware : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_CLANG).empty() || std::string(REVKIT_LLD).empty() || std::string(REVKIT_OBJCOPY).empty())
      return;
    // Built in a directory of this process's, then moved into place.
    const auto tmp = testing::out_dir() / ("armfw.tmp" + std::to_string(::getpid()));
    const std::string cmd = std::string("sh ") + REVKIT_ARMFW_DIR + "/build.sh " + REVKIT_CLANG + " " + REVKIT_LLD + " " +
                            REVKIT_OBJCOPY + " " + tmp.string() + " >/dev/null 2>&1";
    built_ = testing::run(cmd) == 0;
    const auto dir = testing::out_dir() / "armfw";
    std::filesystem::create_directories(dir);
    for (const char *f : {"fw.elf", "fw.bin"})
      if (built_) std::filesystem::rename(tmp / f, dir / f);
    std::filesystem::remove_all(tmp);
  }
  void SetUp() override {
    if (!testing::ghidra_ready()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!built_) GTEST_SKIP() << "no clang, ld.lld and llvm-objcopy for armv4t";
    if (find_program("qemu-system-arm").empty())
      GTEST_SKIP() << "qemu-system-arm is not installed (apt install qemu-system-arm)";
    const auto dir = testing::out_dir() / "armfw";
    loader::RawOptions o;
    o.language = "ARM:LE:32:v4t:default";
    loader::RawRegion mmio;
    mmio.name = "sysctrl";
    mmio.start = 0xd0000000;
    mmio.size = 0x1000;
    mmio.is_volatile = true;
    loader::RawRegion ram;
    ram.name = "sram";
    ram.start = 0x20000000;
    ram.size = 0x10000;
    o.regions = {mmio, ram};
    prog_ = Program::raw(dir / "fw.bin", o);
    elf_ = std::make_shared<const loader::Image>(loader::load_file(dir / "fw.elf", {std::nullopt, false}));
  }
  std::uint64_t sym(const std::string &name) const {
    for (const loader::Symbol &s : elf_->symbols)
      if (s.name == name) return s.value;
    throw std::runtime_error("no symbol " + name);
  }
  SessionOptions options() const {
    SessionOptions so = prog_.session_options();
    auto elf = elf_;
    so.program_name = "fw.bin";
    so.function_entry = [elf](std::uint64_t a) -> std::optional<std::uint64_t> {
      std::optional<std::uint64_t> best;
      for (const loader::Symbol &s : elf->symbols)
        if (s.type == loader::SymbolType::func && (s.value & ~1ull) <= a && (!best || (s.value & ~1ull) > *best))
          best = s.value & ~1ull;
      return best;
    };
    return so;
  }
  std::unique_ptr<Session> boot() {
    const auto bin = (testing::out_dir() / "armfw" / "fw.bin").string();
    Launched l = launch_qemu_system("qemu-system-arm", {"-M", "none", "-cpu", "arm926", "-m", "3584M", "-device",
                                                        "loader,file=" + bin + ",addr=0,force-raw=on"});
    GdbRemoteOptions o = prog_.remote_options();
    o.child = l.child;
    o.description = l.description;
    return std::make_unique<Session>(std::make_unique<GdbRemoteTarget>(std::move(l.transport), o), options());
  }
  static inline bool built_ = false;
  Program prog_;
  std::shared_ptr<const loader::Image> elf_;
};

TEST_F(Firmware, DebugUnderQemuSystem) {
  auto s = boot();
  EXPECT_TRUE(s->mapping().known);
  EXPECT_EQ(s->mapping().slide, 0);
  EXPECT_EQ(s->target().pc(), 0u);  // the reset vector
  EXPECT_EQ(s->target().pc_register(), "pc");
  ASSERT_NE(s->target().find_register("r0"), nullptr);
  EXPECT_EQ(reg(*s, "TB"), 0u);
  // A board without a module list: the program is the module.
  auto mods = s->modules();
  ASSERT_EQ(mods.size(), 1u);
  EXPECT_EQ(mods[0].name, "fw.bin");

  // To main through the reset handler.
  s->add_breakpoint(BreakKind::software, sym("main"), true);
  Stop st = s->resume(RunMode::run, within(20));
  ASSERT_EQ(st.kind, StopKind::breakpoint) << st.detail;
  EXPECT_EQ(st.pc, sym("main"));
  EXPECT_EQ(reg(*s, "sp"), 0x20008000u);

  // mmio_init waits for the device's ready bit: it spins.
  ResumeOptions brief;
  brief.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(300);
  st = s->resume(RunMode::run, brief);
  ASSERT_EQ(st.kind, StopKind::running);
  s->interrupt();
  st = s->wait(std::chrono::steady_clock::now() + std::chrono::seconds(5));
  ASSERT_EQ(st.kind, StopKind::interrupted) << st.detail;
  EXPECT_GE(st.pc, sym("mmio_init"));
  EXPECT_LT(st.pc, sym("mmio_status"));
  std::vector<std::uint8_t> regs(8);
  s->read_memory(0xd0000010, regs);
  EXPECT_EQ(to_u64(std::span(regs).subspan(0, 4)), 1u);  // written by mmio_init
  EXPECT_EQ(to_u64(std::span(regs).subspan(4, 4)), 0x200u);
  // Be the device: set the ready bit.
  const std::vector<std::uint8_t> ready{1, 0, 0, 0};
  ASSERT_TRUE(s->write_memory(0xd0000018, ready));

  // The first handler's store to `sink`, by a watchpoint.
  const int watch = s->add_breakpoint(BreakKind::watch_write, sym("sink"), true, 4).id;
  ASSERT_TRUE(s->breakpoints().back().inserted) << s->breakpoints().back().error;
  st = s->resume(RunMode::run, within(20));
  ASSERT_EQ(st.kind, StopKind::watchpoint) << st.detail;
  EXPECT_GE(st.pc, sym("h0"));
  EXPECT_LT(st.pc, sym("h1"));
  // QEMU stops before the access (gdbserver on x86, after): one more step.
  s->remove_breakpoint(watch);
  s->resume(RunMode::step_into, within(20));
  std::vector<std::uint8_t> sink(4);
  s->read_memory(sym("sink"), sink);
  EXPECT_EQ(to_u64(sink), 10u);  // h0

  // Into Thumb code.
  s->add_breakpoint(BreakKind::software, sym("thumb_sum"), true);  // odd: a Thumb function
  st = s->resume(RunMode::run, within(20));
  ASSERT_EQ(st.kind, StopKind::breakpoint) << st.detail;
  EXPECT_EQ(st.pc, sym("thumb_sum") & ~1ull);
  EXPECT_EQ(reg(*s, "TB"), 1u);
  // dispatch's case 5 calls it first: thumb_sum(v, 5).
  const std::uint64_t acc = reg(*s, "r0"), count = reg(*s, "r1");
  EXPECT_EQ(count, 5u);

  // The emulator agrees: the same firmware with a device that is ready.
  {
    emu::Options eo;
    eo.language = prog_.language;
    emu::Emulator e(prog_.image, eo);
    e.on_mmio([](emu::Emulator &, emu::MmioAccess &a) {
      if (!a.write && a.address == 0xd0000018) a.value = 1;
    });
    e.start(0, emu::StartMode::bare);
    e.add_breakpoint(sym("thumb_sum") & ~1ull);
    emu::RunOptions ro;
    ro.max_steps = 1000000;
    const emu::Stop es = e.run(ro);
    ASSERT_EQ(es.kind, emu::StopKind::breakpoint) << es.detail;
    EXPECT_EQ(e.read_register("r0"), acc);
  }

  // Out of Thumb, back to ARM main, with thumb_sum's result.
  s->clear_breakpoints();
  st = s->resume(RunMode::step_out, within(20));
  ASSERT_EQ(st.kind, StopKind::stepped) << st.detail << "; output: " << s->output();
  EXPECT_EQ(reg(*s, "TB"), 0u);
  EXPECT_GE(st.pc, sym("main"));
  const std::uint64_t sum = reg(*s, "r0");
  std::uint64_t want = 0;
  for (std::uint64_t i = 0; i < count; ++i) want += (acc + i) * 5 + 1;
  EXPECT_EQ(sum & 0xffffffff, want & 0xffffffff);

  // poke_bad_slot stores through 0xffffffff (which this QEMU can't take):
  // return from it at once by setting pc to its return address.
  s->add_breakpoint(BreakKind::software, sym("poke_bad_slot"), true);
  st = s->resume(RunMode::run, within(20));
  ASSERT_EQ(st.kind, StopKind::breakpoint) << st.detail;
  const std::uint64_t final_acc = reg(*s, "r0");
  s->write_register("pc", s->read_register("lr"));
  EXPECT_EQ(s->target().pc(), reg(*s, "lr"));
  s->clear_breakpoints();
  // Then main's endless `sink = acc`.
  s->add_breakpoint(BreakKind::watch_write, sym("sink"), true, 4);
  st = s->resume(RunMode::run, within(20));
  ASSERT_EQ(st.kind, StopKind::watchpoint) << st.detail;
  s->clear_breakpoints();
  s->resume(RunMode::step_into, within(20));
  s->read_memory(sym("sink"), sink);
  EXPECT_EQ(to_u64(sink), final_acc & 0xffffffff);

  // The timeline has every stop, with program addresses.
  bool saw_thumb = false;
  for (const Snapshot &snap : s->timeline().snapshots())
    if (snap.program_pc == (sym("thumb_sum") & ~1ull)) saw_thumb = true;
  EXPECT_TRUE(saw_thumb);
}

}  // namespace
}  // namespace revkit::debug
