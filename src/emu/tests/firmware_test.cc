// The synthetic ARM firmware (src/analysis/tests/fixtures/armfw) as a raw
// image from its reset vector: MMIO recorded or answered by a hook, ARM and
// Thumb code, and the store through a 0xffffffff pointer slot that ends it.
#include "util.hh"

#include <filesystem>

namespace revkit::emu {
namespace {

namespace fs = std::filesystem;

class Firmware : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    dir_ = testing::build_fixtures(REVKIT_ARMFW_DIR, REVKIT_ARMFW_OUT, REVKIT_CLANG, REVKIT_LLD, REVKIT_OBJCOPY);
    built_ = !dir_.empty();
  }
  void SetUp() override {
    if (!testing::ghidra_ready()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!built_) GTEST_SKIP() << "no clang, ld.lld and llvm-objcopy for armv4t";
  }
  static std::shared_ptr<const loader::Image> image() {
    loader::RawOptions o;
    o.language = "ARM:LE:32:v4t";
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
    return std::make_shared<const loader::Image>(loader::load_raw_file(dir_ / "fw.bin", o));
  }
  static std::uint64_t symbol(const std::string &name) {
    static const loader::Image elf = loader::load_file(dir_ / "fw.elf", {std::nullopt, false});
    for (const loader::Symbol &s : elf.symbols)
      if (s.name == name) return s.value;
    return 0;
  }
  static inline bool built_ = false;
  static inline fs::path dir_;  // this process's copy of the fixtures
};

TEST_F(Firmware, ResetHandlerSpinsOnRecordedMmio) {
  Options opts;
  opts.language = "ARM:LE:32:v4t:default";
  Emulator e(image(), opts);
  EXPECT_EQ(e.language(), "ARM:LE:32:v4t:default");
  e.start(0);  // the reset vector; a raw image starts bare
  RunOptions o;
  o.max_steps = 3000;
  Stop s = e.run(o);
  // Nothing answers the status register, so mmio_init waits forever.
  EXPECT_EQ(s.kind, StopKind::step_limit);
  EXPECT_EQ(e.read_register("sp") & 0xffff0000u, 0x20000000u);
  const auto &log = e.mmio_log();
  ASSERT_GE(log.size(), 3u);
  EXPECT_TRUE(log[0].write);
  EXPECT_EQ(log[0].address, 0xd0000010u);
  EXPECT_EQ(log[0].value, 1u);
  EXPECT_EQ(log[1].address, 0xd0000014u);
  EXPECT_EQ(log[1].value, 0x200u);
  EXPECT_FALSE(log[2].write);
  EXPECT_EQ(log[2].address, 0xd0000018u);
  EXPECT_GT(e.trace().summary().mmio_reads, 500u);
  EXPECT_EQ(e.trace().summary().mmio_writes, 2u);
}

TEST_F(Firmware, RunsArmAndThumbUntilTheBadSlot) {
  auto run = [&](std::uint64_t &acc, bool &thumb_seen) {
    Options opts;
    opts.trace_capacity = 1 << 16;
    opts.language = "ARM:LE:32:v4t:default";
    Emulator e(image(), opts);
    e.on_mmio([](Emulator &, MmioAccess &a) {
      if (!a.write && a.address == 0xd0000018) a.value = 0x31;  // ready, status 3
    });
    e.start(0);
    const std::uint64_t thumb_sum = symbol("thumb_sum");
    EXPECT_EQ(thumb_sum & 1, 1u);  // a Thumb function
    e.add_breakpoint(thumb_sum & ~std::uint64_t{1});
    Stop s = e.run({});
    EXPECT_EQ(s.kind, StopKind::breakpoint) << s.detail;
    EXPECT_TRUE(e.thumb());
    e.clear_breakpoints();  // thumb_sum runs twice
    s = e.run({});
    // poke_bad_slot stores through a pointer slot holding 0xffffffff.
    EXPECT_EQ(s.kind, StopKind::unmapped) << s.detail;
    EXPECT_TRUE(s.address && *s.address == 0xffffffffu);
    const std::uint64_t poke = symbol("poke_bad_slot");
    EXPECT_GE(s.pc, poke);
    EXPECT_LT(s.pc, poke + 0x20);
    EXPECT_FALSE(e.thumb());
    acc = e.read_register("r0");  // the value main stores
    thumb_seen = false;
    for (const TraceEntry &t : e.trace().entries()) thumb_seen = thumb_seen || t.thumb;
    return e.trace().summary().steps;
  };
  std::uint64_t acc1 = 0, acc2 = 0;
  bool t1 = false, t2 = false;
  const auto steps1 = run(acc1, t1), steps2 = run(acc2, t2);
  EXPECT_TRUE(t1);
  EXPECT_EQ(acc1, acc2);
  EXPECT_EQ(steps1, steps2);
  EXPECT_GT(steps1, 200u);
}

}  // namespace
}  // namespace revkit::emu
