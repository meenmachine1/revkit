// The emulator on hand-assembled x86-64: stepping, breakpoints, step over
// and out, faults that leave the machine between instructions, hooks,
// watchpoints, wide values, bounds and determinism.
#include "util.hh"

#include <set>

namespace revkit::emu {
namespace {

using testing::raw_image;

constexpr const char *kX64 = "x86:LE:64:default:gcc";

// 0x1000  mov rax,5
// 0x1007  add rax,3
// 0x100b  call 0x1020
// 0x1010  mov rcx,rax
// 0x1013  mov [0x50000000],rax   (unmapped)
// 0x101b  ud2                    (a CALLOTHER without a handler)
// 0x101d  jmp $                  (a halt)
// 0x1020  add rax,1
// 0x1024  mov [0x100000],rax     (RAM, watched in one test)
// 0x102c  ret
std::vector<std::uint8_t> program() {
  std::vector<std::uint8_t> c(0x40, 0x90);
  const std::vector<std::uint8_t> main = {0x48, 0xc7, 0xc0, 0x05, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc0, 0x03,
                                          0xe8, 0x10, 0x00, 0x00, 0x00, 0x48, 0x89, 0xc1, 0x48, 0x89, 0x04,
                                          0x25, 0x00, 0x00, 0x00, 0x50, 0x0f, 0x0b, 0xeb, 0xfe};
  const std::vector<std::uint8_t> callee = {0x48, 0x83, 0xc0, 0x01, 0x48, 0x89, 0x04, 0x25,
                                            0x00, 0x00, 0x10, 0x00, 0xc3};
  std::copy(main.begin(), main.end(), c.begin());
  std::copy(callee.begin(), callee.end(), c.begin() + 0x20);
  return c;
}

class Emu : public ::testing::Test {
 protected:
  void SetUp() override {
    if (!testing::ghidra_ready()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    loader::RawRegion ram;
    ram.name = "ram";
    ram.start = 0x100000;
    ram.size = 0x1000;
    image_ = raw_image(program(), 0x1000, kX64, {ram});
  }
  std::unique_ptr<Emulator> make(Options o = {}) {
    o.language = kX64;
    auto e = std::make_unique<Emulator>(image_, o);
    e->start(0x1000, StartMode::call);
    return e;
  }
  std::shared_ptr<const loader::Image> image_;
};

TEST_F(Emu, StepsRecordRegistersAndTheTrace) {
  auto e = make();
  EXPECT_EQ(e->pc(), 0x1000u);
  Stop s = e->step();
  EXPECT_EQ(s.kind, StopKind::stepped);
  EXPECT_EQ(e->read_register("RAX"), 5u);
  EXPECT_EQ(e->read_register("RIP"), 0x1007u);
  s = e->step();
  EXPECT_EQ(e->read_register("rax"), 8u);  // names are case-insensitive
  ASSERT_EQ(e->trace().entries().size(), 2u);
  const TraceEntry &t = e->trace().entries().back();
  EXPECT_EQ(t.pc, 0x1007u);
  EXPECT_EQ(t.text, "ADD RAX,0x3");
  std::set<std::string> written;
  for (const RegisterWrite &w : t.registers) written.insert(w.name);
  EXPECT_TRUE(written.count("RAX"));
  EXPECT_TRUE(written.count("CF"));
  EXPECT_EQ(e->trace().summary().steps, 2u);
}

TEST_F(Emu, BreakpointsStepOverAndOut) {
  auto e = make();
  e->add_breakpoint(0x100b);
  Stop s = e->run({});
  EXPECT_EQ(s.kind, StopKind::breakpoint);
  EXPECT_EQ(s.pc, 0x100bu);
  EXPECT_EQ(s.steps, 2u);
  // Over the call: back at the fall-through with the callee's effect.
  s = e->step_over();
  EXPECT_EQ(s.kind, StopKind::stepped);
  EXPECT_EQ(e->pc(), 0x1010u);
  EXPECT_EQ(e->read_register("RAX"), 9u);
  std::uint8_t word[8];
  ASSERT_TRUE(e->read_memory(0x100000, word));
  EXPECT_EQ(word[0], 9);

  // Into the call, then out of it.
  auto f = make();
  f->add_breakpoint(0x1020);
  EXPECT_EQ(f->run({}).kind, StopKind::breakpoint);
  s = f->step_out();
  EXPECT_EQ(s.kind, StopKind::stepped);
  EXPECT_EQ(f->pc(), 0x1010u);
  // Running from a breakpoint executes it first, rather than stopping again.
  f->add_breakpoint(0x1010);
  EXPECT_EQ(f->run({}).kind, StopKind::unmapped);
}

TEST_F(Emu, UnmappedAccessStopsBetweenInstructions) {
  auto e = make();
  e->add_breakpoint(0x1013);
  ASSERT_EQ(e->run({}).kind, StopKind::breakpoint);
  const auto rax = e->read_register("RAX");
  Stop s = e->run({});
  EXPECT_EQ(s.kind, StopKind::unmapped);
  ASSERT_TRUE(s.address);
  EXPECT_EQ(*s.address, 0x50000000u);
  EXPECT_EQ(s.pc, 0x1013u);  // the faulting instruction didn't happen
  EXPECT_EQ(e->pc(), 0x1013u);
  EXPECT_EQ(e->read_register("RAX"), rax);
  // Map it and go on: the store happens, then ud2's CALLOTHER has no handler.
  e->map("io", 0x50000000, 0x1000, {true, true, false});
  s = e->run({});
  EXPECT_EQ(s.kind, StopKind::userop);
  EXPECT_EQ(s.pc, 0x101bu);
  EXPECT_NE(s.detail.find("invalidInstructionException"), std::string::npos) << s.detail;
  std::uint8_t io[8];
  ASSERT_TRUE(e->read_memory(0x50000000, io));
  EXPECT_EQ(io[0], 9);
  // A handler makes it go (its output is where ud2 jumps): the halt (jmp $)
  // stops the run.
  e->on_userop("invalidInstructionException", [](Emulator &, UseropCall &call) {
    call.output = 0x101d;
    return HookAction::proceed;
  });
  s = e->run({});
  EXPECT_EQ(s.kind, StopKind::halted);
  EXPECT_EQ(e->pc(), 0x101du);
}

TEST_F(Emu, WatchpointsAndLimits) {
  auto e = make();
  e->add_watchpoint(0x100000, 8, false, true);
  Stop s = e->run({});
  EXPECT_EQ(s.kind, StopKind::watchpoint);
  EXPECT_EQ(e->pc(), 0x102cu);  // after the store
  ASSERT_TRUE(s.address);
  EXPECT_EQ(*s.address, 0x100000u);

  auto f = make();
  RunOptions o;
  o.max_steps = 3;
  s = f->run(o);
  EXPECT_EQ(s.kind, StopKind::step_limit);
  EXPECT_EQ(s.steps, 3u);
  EXPECT_EQ(f->pc(), 0x1020u);
}

TEST_F(Emu, ReturnTrapEndsACall) {
  // From the callee: it returns to the trap start() pushed.
  auto e = make();
  e->set_pc(0x1020);
  Stop s = e->run({});
  EXPECT_EQ(s.kind, StopKind::returned);
  EXPECT_EQ(s.exit_code, 1);
}

TEST_F(Emu, WideValues) {
  // mov rax,-1; mov rdx,1; mov rcx,3; div rcx; mul rcx;
  // movq xmm0,rax; movq xmm1,rdx; paddq xmm0,xmm1; jmp $
  const std::vector<std::uint8_t> code = {0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x48, 0xc7, 0xc2, 0x01, 0x00,
                                          0x00, 0x00, 0x48, 0xc7, 0xc1, 0x03, 0x00, 0x00, 0x00, 0x48, 0xf7, 0xf1,
                                          0x48, 0xf7, 0xe1, 0x66, 0x48, 0x0f, 0x6e, 0xc0, 0x66, 0x48, 0x0f, 0x6e,
                                          0xca, 0x66, 0x0f, 0xd4, 0xc1, 0xeb, 0xfe};
  Options o;
  o.language = kX64;
  Emulator e(raw_image(code, 0x2000, kX64), o);
  e.start(0x2000, StartMode::bare);
  RunOptions ro;
  ro.until = 0x2018;  // after div
  EXPECT_EQ(e.run(ro).kind, StopKind::until);
  EXPECT_EQ(e.read_register("RAX"), 0xaaaaaaaaaaaaaaaaull);
  EXPECT_EQ(e.read_register("RDX"), 1u);
  EXPECT_EQ(e.run({}).kind, StopKind::halted);
  EXPECT_EQ(e.read_register("RDX"), 1u);
  const auto xmm0 = e.read_register_bytes("XMM0");
  ASSERT_EQ(xmm0.size(), 16u);
  for (int i = 0; i < 8; ++i) EXPECT_EQ(xmm0[i], 0xff);
  for (int i = 8; i < 16; ++i) EXPECT_EQ(xmm0[i], 0);
}

TEST_F(Emu, MemoryBound) {
  // rep stosq over 64 KiB of a mapping, with a 32 KiB bound.
  // mov rdi,0x200000; mov rcx,0x2000; rep stosq; jmp $
  const std::vector<std::uint8_t> code = {0x48, 0xc7, 0xc7, 0x00, 0x00, 0x20, 0x00, 0x48, 0xc7, 0xc1,
                                          0x00, 0x20, 0x00, 0x00, 0xf3, 0x48, 0xab, 0xeb, 0xfe};
  Options o;
  o.language = kX64;
  o.max_memory = 32 << 10;
  loader::RawRegion big;
  big.name = "big";
  big.start = 0x200000;
  big.size = 0x10000;
  Emulator e(raw_image(code, 0x3000, kX64, {big}), o);
  e.start(0x3000, StartMode::bare);
  Stop s = e.run({});
  EXPECT_EQ(s.kind, StopKind::memory_limit) << s.detail;
  EXPECT_LE(e.memory_used(), o.max_memory);
}

TEST_F(Emu, SameInputsSameTrace) {
  auto run = [&] {
    auto e = make();
    e->on_userop("invalidInstructionException", [](Emulator &, UseropCall &call) {
      call.output = 0x101d;
      return HookAction::proceed;
    });
    e->map("io", 0x50000000, 0x1000, {true, true, false});
    e->run({});
    return trace_json(*e);
  };
  const std::string a = run(), b = run();
  EXPECT_EQ(a, b);
  EXPECT_NE(a.find("\"kind\":\"halted\""), std::string::npos);
}

// Checkpoints (docs/emulator.md "Checkpoints"): rewinding gives back the
// registers, memory, step count and trace, and running again from there
// does what it did the first time; a checkpoint is cheap (shared pages).
TEST_F(Emu, CheckpointsRewind) {
  auto e = make();
  e->step();  // rax = 5
  e->step();  // rax = 8
  const Checkpoint at2 = e->checkpoint();
  EXPECT_EQ(at2.steps(), 2u);
  EXPECT_EQ(at2.pc(), 0x100bu);
  const std::vector<std::uint8_t> before(8, 0);
  std::vector<std::uint8_t> ram(8);
  ASSERT_TRUE(e->read_memory(0x100000, ram));
  EXPECT_EQ(ram, before);
  // Into the callee and its store.
  for (int i = 0; i < 3; ++i) e->step();
  ASSERT_TRUE(e->read_memory(0x100000, ram));
  EXPECT_EQ(ram[0], 9u);
  EXPECT_EQ(e->read_register("RAX"), 9u);
  const std::uint64_t entries = e->trace().entries().size();
  e->restore(at2);
  EXPECT_EQ(e->steps(), 2u);
  EXPECT_EQ(e->pc(), 0x100bu);
  EXPECT_EQ(e->read_register("RAX"), 8u);
  ASSERT_TRUE(e->read_memory(0x100000, ram));
  EXPECT_EQ(ram, before);
  EXPECT_EQ(e->trace().entries().size(), 2u);
  EXPECT_LT(e->trace().entries().size(), entries);
  // Again: the same steps.
  for (int i = 0; i < 3; ++i) e->step();
  ASSERT_TRUE(e->read_memory(0x100000, ram));
  EXPECT_EQ(ram[0], 9u);
  EXPECT_EQ(e->trace().entries().size(), entries);
  // A different future from the same point: a register changed after rewinding.
  e->restore(at2);
  e->write_register("RAX", 100);
  for (int i = 0; i < 3; ++i) e->step();
  ASSERT_TRUE(e->read_memory(0x100000, ram));
  EXPECT_EQ(ram[0], 101u);
  // Another emulator's checkpoint is refused.
  auto other = make();
  EXPECT_THROW(other->restore(at2), std::logic_error);
}

TEST_F(Emu, DisassemblesWithPcode) {
  auto e = make();
  const std::string d = e->disassemble(0x1007, true);
  EXPECT_NE(d.find("ADD RAX,0x3"), std::string::npos);
  EXPECT_NE(d.find("INT_ADD"), std::string::npos);
  EXPECT_TRUE(e->disassemble(0x90000000).empty());
}

}  // namespace
}  // namespace revkit::emu
