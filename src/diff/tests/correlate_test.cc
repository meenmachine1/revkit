// Block and instruction correlation inside a matched pair (correlate.h):
// hand-built functions for each kind of change, then real code: two
// compiled versions of a program (code moved, cases added, calls
// inserted) and an in-place patch of the ARM firmware (one instruction
// turned into a call to new code).

#include "revkit/diff/correlate.h"

#include <gtest/gtest.h>

#include <map>

namespace revkit::diff {
namespace {

// A function from blocks of (exact, kind) tokens; every block falls into
// the next unless `succ` says otherwise.
struct Spec {
  std::vector<std::vector<std::pair<std::uint64_t, std::uint64_t>>> blocks;
  std::map<std::uint32_t, std::vector<CodeEdge>> succ;
  std::uint64_t base = 0x1000;
  std::map<std::uint64_t, std::uint64_t> calls;  // exact token -> callee
};

FunctionCode Build(const Spec &s) {
  FunctionCode f;
  f.entry = s.base;
  std::uint64_t at = s.base;
  for (std::uint32_t b = 0; b < s.blocks.size(); ++b) {
    CodeBlock bl;
    bl.first = static_cast<std::uint32_t>(f.insns.size());
    for (const auto &[exact, kind] : s.blocks[b]) {
      CodeInsn i;
      i.address = at;
      i.length = 4;
      i.block = b;
      i.exact = exact;
      i.kind = kind;
      if (auto c = s.calls.find(exact); c != s.calls.end()) i.refs.push_back({CodeRef::Kind::call, c->second, 0});
      f.insns.push_back(i);
      at += 4;
    }
    bl.last = static_cast<std::uint32_t>(f.insns.size() - 1);
    if (auto it = s.succ.find(b); it != s.succ.end()) bl.succ = it->second;
    else if (b + 1 < s.blocks.size()) bl.succ = {{b + 1, EdgeKind::fall}};
    f.blocks.push_back(bl);
  }
  return f;
}

// Tokens: exact = 100 * kind + variant.
std::pair<std::uint64_t, std::uint64_t> T(std::uint64_t kind, std::uint64_t variant = 0) { return {kind * 100 + variant, kind}; }

std::vector<std::pair<std::uint64_t, std::uint64_t>> Seq(std::uint64_t from, std::uint64_t n) {
  std::vector<std::pair<std::uint64_t, std::uint64_t>> v;
  for (std::uint64_t k = 0; k < n; ++k) v.push_back(T(from + k));
  return v;
}

std::vector<std::uint64_t> With(const Correlation &c, const FunctionCode &f, bool side_a, InsnStatus s) {
  std::vector<std::uint64_t> out;
  const auto &st = side_a ? c.status_a : c.status_b;
  for (std::size_t i = 0; i < st.size(); ++i)
    if (st[i] == s) out.push_back(f.insns[i].address);
  return out;
}

TEST(Correlate, IdenticalFunctionsAreEqualEverywhere) {
  Spec s{{Seq(1, 5), Seq(10, 3), Seq(20, 4)}, {{0, {{1, EdgeKind::fall}, {2, EdgeKind::taken}}}}};
  const FunctionCode a = Build(s);
  s.base = 0x8000;  // moved: addresses don't matter
  const FunctionCode b = Build(s);
  const Correlation c = correlate(a, b);
  EXPECT_EQ(c.equal, 12u);
  EXPECT_EQ(c.changed + c.inserted + c.deleted, 0u);
  for (BlockStatus st : c.block_status_a) EXPECT_EQ(st, BlockStatus::unchanged);
  for (std::size_t x = 0; x < c.block_a.size(); ++x) EXPECT_EQ(c.block_a[x], static_cast<std::int32_t>(x));
  EXPECT_EQ(c.lines.size(), 12u);
  EXPECT_TRUE(c.hunks().empty());
}

TEST(Correlate, AnImmediateChangeIsOneChangedInstruction) {
  Spec s{{Seq(1, 6), Seq(10, 4)}};
  const FunctionCode a = Build(s);
  s.blocks[1][2] = T(12, 7);  // same kind, other operand
  const FunctionCode b = Build(s);
  const Correlation c = correlate(a, b);
  EXPECT_EQ(With(c, a, true, InsnStatus::changed), (std::vector<std::uint64_t>{a.insns[8].address}));
  EXPECT_EQ(c.equal, 9u);
  EXPECT_EQ(c.inserted + c.deleted, 0u);
  EXPECT_EQ(c.block_status_a[0], BlockStatus::unchanged);
  EXPECT_EQ(c.block_status_a[1], BlockStatus::modified);
  EXPECT_EQ(c.block_status_b[1], BlockStatus::modified);
  ASSERT_EQ(c.hunks().size(), 1u);
  EXPECT_EQ(c.lines[c.hunks()[0]], std::make_pair(8, 8));
}

TEST(Correlate, AReplacedInstructionIsChangedInPlace) {
  // sub r0,r0,#0x7 -> bl new: another kind of instruction at the same place.
  Spec s{{Seq(1, 9)}};
  const FunctionCode a = Build(s);
  s.blocks[0][4] = T(77);
  s.calls[7700] = 0x9000;
  const FunctionCode b = Build(s);
  Correlation c = correlate(a, b);
  EXPECT_EQ(With(c, b, false, InsnStatus::changed), (std::vector<std::uint64_t>{b.insns[4].address}));
  EXPECT_EQ(c.equal, 8u);
  retarget(c, a, b, [](std::uint64_t) { return std::nullopt; });
  EXPECT_EQ(c.changed, 1u);
  const auto refs = reference_diff(c, a, b, {});
  ASSERT_EQ(refs.size(), 1u);
  EXPECT_TRUE(refs[0].in_b);
  EXPECT_EQ(refs[0].ref.to, 0x9000u);
  EXPECT_EQ(refs[0].insn, 4u);
}

TEST(Correlate, AnInsertedCallIsOneInsertedInstruction) {
  Spec s{{Seq(1, 5), Seq(10, 5)}};
  const FunctionCode a = Build(s);
  s.blocks[1].insert(s.blocks[1].begin() + 2, T(50));
  s.calls[5000] = 0x4000;
  const FunctionCode b = Build(s);
  const Correlation c = correlate(a, b);
  EXPECT_EQ(With(c, b, false, InsnStatus::inserted), (std::vector<std::uint64_t>{b.insns[7].address}));
  EXPECT_EQ(c.equal, 10u);
  EXPECT_EQ(c.changed + c.deleted, 0u);
  EXPECT_EQ(c.lines.size(), 11u);
  EXPECT_EQ(c.lines[7], std::make_pair(-1, 7));
  const auto refs = reference_diff(c, a, b, {});
  ASSERT_EQ(refs.size(), 1u);
  EXPECT_EQ(refs[0].ref.to, 0x4000u);
}

TEST(Correlate, AMovedBlockStillCorrespondsAndIsMarkedMoved) {
  // A: entry, X, Y, exit. B: entry, Y, X, exit (X and Y swapped in memory).
  Spec sa{{Seq(1, 4), Seq(10, 5), Seq(20, 6), Seq(30, 3)},
          {{0, {{1, EdgeKind::fall}, {2, EdgeKind::taken}}}, {1, {{3, EdgeKind::jump}}}, {2, {{3, EdgeKind::fall}}}}};
  Spec sb{{Seq(1, 4), Seq(20, 6), Seq(10, 5), Seq(30, 3)},
          {{0, {{2, EdgeKind::fall}, {1, EdgeKind::taken}}}, {1, {{3, EdgeKind::jump}}}, {2, {{3, EdgeKind::jump}}}}};
  sb.base = 0x5000;
  const FunctionCode a = Build(sa), b = Build(sb);
  const Correlation c = correlate(a, b);
  EXPECT_EQ(c.equal, 18u);
  EXPECT_EQ(c.changed + c.inserted + c.deleted, 0u);
  EXPECT_EQ(c.block_a, (std::vector<std::int32_t>{0, 2, 1, 3}));
  for (BlockStatus st : c.block_status_b) EXPECT_EQ(st, BlockStatus::unchanged);
  std::size_t moved = 0;
  for (bool m : c.moved_a) moved += m;
  EXPECT_EQ(moved, 5u);  // the smaller of the two swapped blocks gets lines of its own
  EXPECT_EQ(c.lines.size(), 18u + 5u);
}

TEST(Correlate, ASplitBlockAlignsAcrossBothHalves) {
  // B inserts a branch target in the middle of A's second block.
  Spec sa{{Seq(1, 3), Seq(10, 8)}};
  Spec sb{{Seq(1, 3), Seq(10, 4), Seq(14, 4)}};
  const FunctionCode a = Build(sa), b = Build(sb);
  const Correlation c = correlate(a, b);
  EXPECT_EQ(c.equal, 11u);
  EXPECT_EQ(c.changed + c.inserted + c.deleted, 0u);
  EXPECT_EQ(c.block_status_b[2], BlockStatus::modified);  // only half of A's block
}

TEST(Correlate, ARemovedAndAnAddedBlock) {
  Spec sa{{Seq(1, 3), Seq(40, 4), Seq(30, 3)}};
  Spec sb{{Seq(1, 3), Seq(60, 5), Seq(30, 3)}};
  const FunctionCode a = Build(sa), b = Build(sb);
  const Correlation c = correlate(a, b);
  EXPECT_EQ(c.block_status_a[1], BlockStatus::removed);
  EXPECT_EQ(c.block_status_b[1], BlockStatus::added);
  EXPECT_EQ(c.deleted, 4u);
  EXPECT_EQ(c.inserted, 5u);
  EXPECT_EQ(c.equal, 6u);
}

TEST(Correlate, RetargetedCallsChangeUnlessTheTargetsMatch) {
  Spec s{{Seq(1, 4)}};
  s.calls[200] = 0x7000;
  const FunctionCode a = Build(s);
  s.calls[200] = 0x7100;  // the same masked bytes, another callee
  const FunctionCode b = Build(s);
  Correlation c = correlate(a, b);
  EXPECT_EQ(c.equal, 4u);
  Correlation unmatched = c;
  retarget(unmatched, a, b, [](std::uint64_t) { return std::nullopt; });
  EXPECT_EQ(unmatched.changed, 1u);
  EXPECT_EQ(unmatched.block_status_a[0], BlockStatus::modified);
  EXPECT_EQ(reference_diff(unmatched, a, b, {}).size(), 2u);  // lost 0x7000, gained 0x7100
  Correlation matched = c;
  retarget(matched, a, b, [](std::uint64_t x) { return x == 0x7000 ? std::optional<std::uint64_t>(0x7100) : std::nullopt; });
  EXPECT_EQ(matched.changed, 0u);
  EXPECT_EQ(matched.block_status_a[0], BlockStatus::unchanged);
}

TEST(Correlate, IdenticalTwinBlocksPairInOrder) {
  // A switch over cases whose code is the same: nothing unique tells them
  // apart, so they pair through the switch and in address order.
  auto spec = [](std::uint64_t middle) {
    Spec s{{Seq(1, 4), {T(5), T(6), T(7)}, {T(5), T(6, middle), T(7)}, {T(5), T(6), T(7)}, Seq(30, 3)},
           {{0, {{1, EdgeKind::switch_case}, {2, EdgeKind::switch_case}, {3, EdgeKind::switch_case}}},
            {1, {{4, EdgeKind::jump}}},
            {2, {{4, EdgeKind::jump}}},
            {3, {{4, EdgeKind::fall}}}}};
    return s;
  };
  const FunctionCode a = Build(spec(0)), b = Build(spec(1));
  const Correlation c = correlate(a, b);
  EXPECT_EQ(With(c, b, false, InsnStatus::changed), (std::vector<std::uint64_t>{b.insns[8].address}));
  EXPECT_EQ(c.inserted + c.deleted, 0u);
  EXPECT_EQ(c.block_a, (std::vector<std::int32_t>{0, 1, 2, 3, 4}));
}

TEST(Correlate, IsDeterministicAndRoundTrips) {
  Spec sa{{Seq(1, 7), {T(3), T(3), T(3), T(4)}, Seq(30, 6), {T(3), T(3), T(5)}},
          {{0, {{1, EdgeKind::fall}, {3, EdgeKind::taken}}}, {1, {{2, EdgeKind::fall}}}, {2, {{0, EdgeKind::jump}}}}};
  Spec sb = sa;
  sb.blocks[2][3] = T(33, 1);
  sb.blocks[1].push_back(T(3));
  sb.blocks[3].insert(sb.blocks[3].begin(), T(9));
  const FunctionCode a = Build(sa), b = Build(sb);
  const Correlation c1 = correlate(a, b), c2 = correlate(a, b);
  EXPECT_EQ(c1, c2);
  facts::Encoder e;
  c1.encode(e);
  const std::string bytes = e.str();
  facts::Decoder d(bytes);
  EXPECT_EQ(Correlation::decode(d), c1);
  facts::Encoder ef;
  a.encode(ef);
  const std::string fb = ef.str();
  facts::Decoder df(fb);
  EXPECT_EQ(FunctionCode::decode(df), a);
}

}  // namespace
}  // namespace revkit::diff
