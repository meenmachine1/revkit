// Recording and time travel: the Timeline on its own (keyframes, bounds,
// what memory is known when), and a Session over the emulator, whose every
// instruction becomes a snapshot that reproduces the machine exactly.
#include "util.hh"

#include <cstring>

namespace revkit::debug {
namespace {

using testing::Program;

std::vector<std::uint8_t> le(std::uint64_t v, std::size_t n = 8) { return from_u64(v, n); }

TEST(Timeline, RegistersAndKeyframes) {
  Timeline t(Timeline::Limits{100, 1 << 20});
  Snapshot s0;
  s0.keyframe = true;
  s0.registers = {{"A", le(1)}, {"B", le(2)}};
  t.add(s0);
  for (int i = 1; i <= 600; ++i) {
    Snapshot s;
    s.kind = Snapshot::Kind::step;
    s.registers = {{"A", le(static_cast<std::uint64_t>(i + 1))}};
    t.add(s);
  }
  // Bounded: the oldest dropped, the new oldest made whole.
  EXPECT_EQ(t.size(), 100u);
  EXPECT_EQ(t.dropped(), 501u);
  EXPECT_EQ(t.first(), 501u);
  EXPECT_TRUE(t.snapshots().front().keyframe);
  EXPECT_EQ(to_u64(t.registers_at(501)["A"]), 502u);
  EXPECT_EQ(to_u64(t.registers_at(501)["B"]), 2u);
  EXPECT_EQ(to_u64(t.registers_at(600)["A"]), 601u);
  EXPECT_EQ(t.changed_at(600), std::vector<std::string>{"A"});
  EXPECT_EQ(t.find(500), nullptr);
}

TEST(Timeline, MemoryKnownAndStale) {
  Timeline t;
  Snapshot a;
  a.keyframe = true;
  a.memory.push_back({0x1000, {1, 2, 3, 4}, {}, MemoryRecord::Kind::observed});
  t.add(a);  // 0
  Snapshot b;
  b.memory.push_back({0x1002, {9}, {3}, MemoryRecord::Kind::write});
  t.add(b);  // 1
  Snapshot c;
  t.add(c);  // 2
  std::vector<std::uint8_t> out(6);
  std::vector<Timeline::ByteState> st;
  // A live target: only what was seen, older values marked stale.
  t.memory_at(0, 0xfff, out, st, false);
  EXPECT_EQ(out, (std::vector<std::uint8_t>{0, 1, 2, 3, 4, 0}));
  EXPECT_EQ(st[0], Timeline::ByteState::unknown);
  EXPECT_EQ(st[1], Timeline::ByteState::exact);
  t.memory_at(2, 0xfff, out, st, false);
  EXPECT_EQ(out[3], 9);
  EXPECT_EQ(st[3], Timeline::ByteState::stale);
  // Complete recording (the emulator): exact, and the value now fills the rest.
  t.memory_at(2, 0xfff, out, st, true, [](std::uint64_t at, std::span<std::uint8_t> buf, std::vector<bool> &ok) {
    for (std::size_t i = 0; i < buf.size(); ++i) {
      buf[i] = static_cast<std::uint8_t>(0xa0 + ((at + i) & 0xf));
      ok[i] = true;
    }
  });
  EXPECT_EQ(st[3], Timeline::ByteState::exact);
  EXPECT_EQ(out[0], 0xaf);
  EXPECT_EQ(st[0], Timeline::ByteState::exact);
  // A byte written later reads as its value before the write.
  Timeline u;
  u.add(Snapshot{});
  Snapshot w;
  w.memory.push_back({0x2000, {7}, {5}, MemoryRecord::Kind::write});
  u.add(w);
  std::vector<std::uint8_t> one(1);
  u.memory_at(0, 0x2000, one, st, true);
  EXPECT_EQ(one[0], 5);
  EXPECT_EQ(st[0], Timeline::ByteState::exact);
  u.memory_at(1, 0x2000, one, st, true);
  EXPECT_EQ(one[0], 7);
}

TEST(Timeline, SaveAndLoad) {
  Timeline t;
  Snapshot a;
  a.keyframe = true;
  a.pc = 0x401000;
  a.program_pc = 0x101000;
  a.thread = "p1.1";
  a.stop = StopKind::breakpoint;
  a.detail = "bp";
  a.registers = {{"RAX", le(0x1234)}};
  a.memory.push_back({0x5000, {1, 2}, {}, MemoryRecord::Kind::observed});
  t.add(a);
  Snapshot b;
  b.kind = Snapshot::Kind::step;
  b.registers = {{"RAX", le(0x99)}};
  b.memory.push_back({0x5000, {3}, {1}, MemoryRecord::Kind::write});
  b.gap = true;
  t.add(b);
  TraceHeader h;
  h.name = "t1";
  h.program_id = "default/prog";
  h.language = "x86:LE:64:default:gcc";
  h.slide = -0x1000;
  h.modules.push_back({"prog", "/x/prog", 0x400000, 0, 0x2000, true});
  RegisterDesc rd;
  rd.name = "RAX";
  rd.size = 8;
  rd.display = true;
  h.registers.push_back(rd);
  const std::string data = t.serialize(h);
  TraceHeader h2;
  Timeline t2 = Timeline::deserialize(data, h2);
  EXPECT_EQ(h2.name, "t1");
  EXPECT_EQ(h2.slide, -0x1000);
  ASSERT_EQ(h2.modules.size(), 1u);
  EXPECT_EQ(h2.modules[0].size, 0x2000u);
  ASSERT_EQ(t2.size(), 2u);
  EXPECT_EQ(*t2.find(0)->program_pc, 0x101000u);
  EXPECT_EQ(t2.find(0)->stop, StopKind::breakpoint);
  EXPECT_TRUE(t2.find(1)->gap);
  EXPECT_EQ(to_u64(t2.registers_at(1)["RAX"]), 0x99u);
  EXPECT_EQ(t2.serialize(h2), data);
  // Damage is an error, not a crash.
  for (std::size_t cut : {std::size_t{0}, std::size_t{5}, data.size() / 2, data.size() - 1})
    EXPECT_THROW(Timeline::deserialize(std::string_view(data).substr(0, cut), h2), DebugError) << cut;
  std::string flipped = data;
  flipped[20] = static_cast<char>(0xff);
  try {
    Timeline::deserialize(flipped, h2);
  } catch (const DebugError &) {
  }
  EXPECT_NE(t.to_json(h).find("\"program_pc\":\"0x101000\""), std::string::npos);
}

// --- The emulator as a target ---

class EmulatorSession : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    const auto out = testing::out_dir() / "debuggee-x86_64";
    built_ = testing::compile("cc -O0 -g0 -fno-inline -pie -fPIE -pthread -o {out} " REVKIT_DEBUG_TEST_SRC
                              "/programs/debuggee.c", out);
  }
  void SetUp() override {
    if (!testing::ghidra_ready()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!built_) GTEST_SKIP() << "no C compiler";
    prog_ = Program::load(testing::out_dir() / "debuggee-x86_64");
  }
  std::unique_ptr<Session> start(std::uint64_t entry, std::vector<std::uint64_t> args) {
    emu::Options o;
    o.language = prog_.language;
    auto e = std::make_unique<emu::Emulator>(prog_.image, o);
    e->start(entry, emu::StartMode::call, args);
    return std::make_unique<Session>(std::make_unique<EmulatorTarget>(std::move(e), "debuggee-x86_64"),
                                     prog_.session_options());
  }
  static inline bool built_ = false;
  Program prog_;
};

TEST_F(EmulatorSession, EveryInstructionIsASnapshot) {
  auto s = start(prog_.symbol("middle"), {4});
  EXPECT_EQ(s->mapping().slide, 0);
  EXPECT_EQ(s->mapping().how, "emulator");
  const std::uint64_t counter = prog_.symbol("counter");
  s->add_breakpoint(BreakKind::software, prog_.symbol("leaf"), true);
  Stop st = s->resume(RunMode::run, testing::within(10));
  ASSERT_EQ(st.kind, StopKind::breakpoint) << st.detail;
  const std::uint64_t at_leaf = s->current_snapshot();
  st = s->resume(RunMode::run, testing::within(10));
  ASSERT_EQ(st.kind, StopKind::returned) << st.detail;
  EXPECT_EQ(st.exit_code, 16);  // leaf(5) * 3 + 1

  // Replay the same run one instruction at a time, independently, and
  // compare every snapshot's pc and registers with it.
  emu::Options o;
  o.language = prog_.language;
  emu::Emulator ref(prog_.image, o);
  ref.start(prog_.symbol("middle"), emu::StartMode::call, std::vector<std::uint64_t>{4});
  const Timeline &t = s->timeline();
  ASSERT_GT(t.size(), 10u);
  std::size_t compared = 0;
  bool wrote_counter = false;
  for (const Snapshot &snap : t.snapshots()) {
    if (snap.kind == Snapshot::Kind::edit) continue;
    while (ref.steps() < snap.steps) ref.step();
    ASSERT_EQ(snap.pc, ref.pc()) << "snapshot " << snap.index;
    const auto regs = t.registers_at(snap.index);
    for (const std::string &n : ref.display_registers()) {
      auto it = regs.find(n);
      ASSERT_NE(it, regs.end()) << n;
      ASSERT_EQ(it->second, ref.read_register_bytes(n)) << n << " at snapshot " << snap.index;
    }
    // Memory at that moment: the global the run increments.
    std::vector<std::uint8_t> m(4);
    std::vector<Timeline::ByteState> state;
    s->memory_at(snap.index, counter, m, state);
    std::vector<std::uint8_t> want(4);
    ref.read_memory(counter, want);
    ASSERT_EQ(m, want) << "counter at snapshot " << snap.index;
    EXPECT_EQ(state[0], Timeline::ByteState::exact);
    if (to_u64(want) == 5) wrote_counter = true;
    ++compared;
  }
  EXPECT_TRUE(wrote_counter);
  EXPECT_GT(compared, 10u);
  // The snapshot at the breakpoint shows the pc of leaf, statically too.
  EXPECT_EQ(t.find(at_leaf)->pc, prog_.symbol("leaf"));
  EXPECT_EQ(*t.find(at_leaf)->program_pc, prog_.symbol("leaf"));
  EXPECT_EQ(t.find(at_leaf)->stop, StopKind::breakpoint);
}

// Rewinding (docs/debugger.md "Rewind"): back to an instruction in the
// middle of a run, the registers and memory are as recorded there, later
// snapshots are gone, and running on gives the same end; a register
// changed after going back gives a different one. Step back undoes one
// instruction.
TEST_F(EmulatorSession, Rewind) {
  auto s = start(prog_.symbol("middle"), {4});
  ASSERT_TRUE(s->can_rewind());
  const std::uint64_t counter = prog_.symbol("counter");
  s->add_breakpoint(BreakKind::software, prog_.symbol("leaf"), true);
  Stop st = s->resume(RunMode::run, testing::within(10));
  ASSERT_EQ(st.kind, StopKind::breakpoint) << st.detail;
  const std::uint64_t at_leaf = s->current_snapshot();
  st = s->resume(RunMode::run, testing::within(10));
  ASSERT_EQ(st.kind, StopKind::returned) << st.detail;
  EXPECT_EQ(st.exit_code, 16);
  const std::uint64_t end = s->current_snapshot();
  ASSERT_GT(end, at_leaf + 3);

  // Back to an instruction inside leaf, after its first.
  const std::uint64_t mid = at_leaf + 2;
  const auto want = s->timeline().registers_at(mid);
  st = s->rewind(mid);
  EXPECT_EQ(s->current_snapshot(), mid);
  EXPECT_EQ(s->timeline().last(), mid);
  EXPECT_EQ(s->timeline().next_index(), mid + 1);
  for (const auto &[name, value] : want) EXPECT_EQ(s->read_register(name), value) << name;
  std::uint8_t c[4] = {};
  s->read_memory(counter, c);
  std::vector<Timeline::ByteState> state;
  std::uint8_t then[4] = {};
  s->memory_at(mid, counter, then, state);
  EXPECT_EQ(std::memcmp(c, then, 4), 0);
  // On to the same end.
  st = s->resume(RunMode::run, testing::within(10));
  ASSERT_EQ(st.kind, StopKind::returned) << st.detail;
  EXPECT_EQ(st.exit_code, 16);
  EXPECT_EQ(s->current_snapshot(), end);

  // Back to leaf's entry, with x changed: a different end.
  s->rewind(at_leaf);
  s->write_register("RDI", from_u64(10, 8));
  st = s->resume(RunMode::run, testing::within(10));
  ASSERT_EQ(st.kind, StopKind::returned) << st.detail;
  EXPECT_EQ(st.exit_code, 31);  // leaf(10) * 3 + 1

  // Step back: one instruction at a time.
  const std::uint64_t end2 = s->current_snapshot();
  const std::uint64_t pc_before = s->timeline().find(end2 - 1)->pc;
  s->step_back();
  EXPECT_EQ(s->target().pc(), pc_before);
  EXPECT_EQ(s->current_snapshot(), end2 - 1);
  s->step_back();
  EXPECT_EQ(s->current_snapshot(), end2 - 2);
}

TEST_F(EmulatorSession, EditsAndWatchpoints) {
  auto s = start(prog_.symbol("middle"), {1});
  const std::uint64_t counter = prog_.symbol("counter");
  s->add_breakpoint(BreakKind::watch_write, counter, true, 4);
  Stop st = s->resume(RunMode::run, testing::within(10));
  ASSERT_EQ(st.kind, StopKind::watchpoint) << st.detail;
  EXPECT_EQ(s->breakpoints()[0].hits, 1u);
  const std::uint64_t before_edit = s->current_snapshot();
  const std::vector<std::uint8_t> v{0x44, 0x33, 0x22, 0x11};
  ASSERT_TRUE(s->write_memory(counter, v));
  s->write_register("RAX", from_u64(0x77, 8));
  EXPECT_EQ(s->timeline().find(s->current_snapshot())->kind, Snapshot::Kind::edit);
  std::vector<std::uint8_t> m(4);
  std::vector<Timeline::ByteState> state;
  s->memory_at(before_edit, counter, m, state);
  EXPECT_EQ(to_u64(m), 2u);
  s->memory_at(s->current_snapshot(), counter, m, state);
  EXPECT_EQ(to_u64(m), 0x11223344u);
  EXPECT_EQ(to_u64(s->timeline().registers_at(s->current_snapshot())["RAX"]), 0x77u);
  EXPECT_NE(to_u64(s->timeline().registers_at(before_edit)["RAX"]), 0x77u);
  // Step over and out are the emulator's own.
  st = s->resume(RunMode::step_out, testing::within(10));
  EXPECT_EQ(st.kind, StopKind::stepped);
}

}  // namespace
}  // namespace revkit::debug
