#include "revkit/diff/residue.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <cstdint>
#include <random>
#include <vector>

namespace revkit::diff {
namespace {

const WeightTable &weights() { return WeightTable::builtin(Weights::w64); }

// A vector of `n` distinct hashes from `seed`, plus `shared` taken from `base`.
std::vector<std::uint32_t> features(std::uint32_t seed, std::size_t n, const std::vector<std::uint32_t> &base = {},
                                    std::size_t shared = 0) {
  std::mt19937 rng(seed);
  std::vector<std::uint32_t> f(base.begin(), base.begin() + static_cast<std::ptrdiff_t>(std::min(shared, base.size())));
  for (std::size_t k = 0; k < n; ++k) f.push_back(rng());
  std::sort(f.begin(), f.end());
  return f;
}

struct Side {
  std::vector<std::vector<std::uint32_t>> vecs;
  std::vector<std::uint64_t> entries;
  std::vector<ResidueFunction> fns() const {
    std::vector<ResidueFunction> out;
    for (std::size_t k = 0; k < vecs.size(); ++k) out.push_back({entries[k], vecs[k]});
    return out;
  }
};

TEST(Residue, IdenticalFunctionsAreMutualBest) {
  Side a, b;
  for (std::uint32_t k = 0; k < 20; ++k) {
    a.vecs.push_back(features(k, 30));
    a.entries.push_back(0x1000 + 0x10 * k);
    b.vecs.push_back(a.vecs.back());
    b.entries.push_back(0x9000 + 0x10 * (19 - k));
  }
  auto fa = a.fns(), fb = b.fns();
  ResidueResult r = match_residue(fa, fb, nullptr, {}, weights());
  ASSERT_EQ(r.matches.size(), 20u);
  for (std::size_t k = 0; k < 20; ++k) {
    EXPECT_EQ(r.matches[k].a, 0x1000 + 0x10 * k);
    EXPECT_EQ(r.matches[k].b, 0x9000 + 0x10 * (19 - k));
    EXPECT_NEAR(r.matches[k].cosine, 1.0, 1e-12);
    EXPECT_GT(r.matches[k].significance, 10);
    EXPECT_TRUE(r.matches[k].mutual_best);
    EXPECT_FALSE(r.matches[k].hinted);
  }
}

TEST(Residue, TiesAreNotBrokenExceptByAHint) {
  Side a, b;
  a.vecs = {features(1, 30)};
  a.entries = {0x100};
  b.vecs = {a.vecs[0], a.vecs[0]};  // two identical candidates
  b.entries = {0x200, 0x300};
  auto fa = a.fns(), fb = b.fns();
  ResidueResult r = match_residue(fa, fb, nullptr, {}, weights());
  EXPECT_TRUE(r.matches.empty());
  ASSERT_EQ(r.scored.size(), 2u);  // both shown as candidates
  EXPECT_EQ(r.scored[0].b, 0x200u);
  EXPECT_EQ(r.scored[0].next_a, r.scored[0].cosine);  // zero margin
  std::vector<ResidueHint> hints{{0x100, 0x300, "callee"}};
  r = match_residue(fa, fb, nullptr, hints, weights());
  ASSERT_EQ(r.matches.size(), 1u);
  EXPECT_EQ(r.matches[0].b, 0x300u);
  EXPECT_TRUE(r.matches[0].hinted);
  EXPECT_EQ(r.matches[0].hints, std::vector<std::string>{"callee"});
}

TEST(Residue, WeakPairsNeedAHint) {
  // About a third of the features in common: cosine below 0.35.
  std::vector<std::uint32_t> base = features(7, 30);
  Side a, b;
  a.vecs = {base};
  a.entries = {0x100};
  b.vecs = {features(8, 50, base, 10)};
  b.entries = {0x200};
  auto fa = a.fns(), fb = b.fns();
  ResidueResult r = match_residue(fa, fb, nullptr, {}, weights());
  ASSERT_EQ(r.scored.size(), 1u);
  const double c = r.scored[0].cosine;
  EXPECT_GT(c, 0.2);
  EXPECT_LT(c, 0.35);
  EXPECT_TRUE(r.scored[0].mutual_best);
  EXPECT_TRUE(r.matches.empty());
  std::vector<ResidueHint> hints{{0x100, 0x200, "caller"}};
  r = match_residue(fa, fb, nullptr, hints, weights());
  ASSERT_EQ(r.matches.size(), 1u);
  EXPECT_TRUE(r.matches[0].hinted);
  ResidueOptions strict;
  strict.hinted_min_cosine = 0.5;
  EXPECT_TRUE(match_residue(fa, fb, nullptr, hints, weights(), strict).matches.empty());
}

TEST(Residue, MutualBestIsRequired) {
  // A0 resembles B0 a little; A1 is B0 exactly. B0 chooses A1, so A0 has no match.
  std::vector<std::uint32_t> base = features(3, 40);
  Side a, b;
  a.vecs = {features(4, 20, base, 30), base};
  a.entries = {0x100, 0x110};
  b.vecs = {base};
  b.entries = {0x200};
  auto fa = a.fns(), fb = b.fns();
  ResidueResult r = match_residue(fa, fb, nullptr, {}, weights());
  ASSERT_EQ(r.matches.size(), 1u);
  EXPECT_EQ(r.matches[0].a, 0x110u);
  // A0's pair is scored, not mutual: B0's best other is A1's 1.0.
  auto it = std::find_if(r.scored.begin(), r.scored.end(), [](const ResiduePair &p) { return p.a == 0x100; });
  ASSERT_NE(it, r.scored.end());
  EXPECT_FALSE(it->mutual_best);
  EXPECT_DOUBLE_EQ(it->next_b, 1.0);
}

TEST(Residue, CandidatesRestrictWhatIsScored) {
  Side a, b;
  a.vecs = {features(1, 30)};
  a.entries = {0x100};
  b.vecs = {a.vecs[0], features(2, 30, a.vecs[0], 25)};
  b.entries = {0x200, 0x300};
  auto fa = a.fns(), fb = b.fns();
  std::vector<std::vector<std::uint64_t>> cands{{0x300, 0x999}};  // the exact twin not listed; unknown entries ignored
  ResidueResult r = match_residue(fa, fb, &cands, {}, weights());
  ASSERT_EQ(r.matches.size(), 1u);
  EXPECT_EQ(r.matches[0].b, 0x300u);
  EXPECT_EQ(r.matches[0].scored_a, 1u);
  // A hint brings an unlisted pair in.
  std::vector<ResidueHint> hints{{0x100, 0x200, "string"}};
  r = match_residue(fa, fb, &cands, hints, weights());
  ASSERT_EQ(r.matches.size(), 1u);
  EXPECT_EQ(r.matches[0].b, 0x200u);
}

TEST(Residue, EmptyVectorsNeverMatch) {
  Side a, b;
  a.vecs = {{}};
  a.entries = {0x100};
  b.vecs = {{}};
  b.entries = {0x200};
  auto fa = a.fns(), fb = b.fns();
  std::vector<std::vector<std::uint64_t>> cands{{0x200}};
  std::vector<ResidueHint> hints{{0x100, 0x200, "callee"}};
  ResidueResult r = match_residue(fa, fb, &cands, hints, weights());
  EXPECT_TRUE(r.matches.empty());
}

TEST(Residue, OrderOfInputsDoesNotMatter) {
  Side a, b;
  std::mt19937 rng(5);
  for (std::uint32_t k = 0; k < 40; ++k) {
    std::vector<std::uint32_t> base = features(100 + k, 10 + k % 7);
    a.vecs.push_back(features(200 + k, 3, base, base.size()));
    a.entries.push_back(0x1000 + 8 * k);
    b.vecs.push_back(features(300 + k, k % 4, base, base.size() - 1));
    b.entries.push_back(0x8000 + 8 * k);
  }
  auto fa = a.fns(), fb = b.fns();
  ResidueResult r1 = match_residue(fa, fb, nullptr, {}, weights());
  std::shuffle(fa.begin(), fa.end(), rng);
  std::shuffle(fb.begin(), fb.end(), rng);
  ResidueResult r2 = match_residue(fa, fb, nullptr, {}, weights());
  EXPECT_EQ(r1.matches, r2.matches);
  EXPECT_GT(r1.matches.size(), 30u);
}

}  // namespace
}  // namespace revkit::diff

namespace revkit::diff {
namespace {

FunctionFeatures fn(std::uint64_t entry, std::vector<std::uint64_t> calls = {}) {
  FunctionFeatures f;
  f.entry = entry;
  f.calls = std::move(calls);
  return f;
}

TEST(ResidueTier, CallerHintsNeedOneCallerEachSide) {
  // Matched pair (0x10, 0x20); A's 0x11 and B's 0x21 are its only unmatched
  // callers; 0x12 and 0x22, 0x23 call (0x30, 0x40): two on B's side.
  FunctionFeatures a1 = fn(0x11, {0x10, 0x10}), a2 = fn(0x12, {0x30});
  FunctionFeatures b1 = fn(0x21, {0x20}), b2 = fn(0x22, {0x40}), b3 = fn(0x23, {0x40});
  ResidueRequest req;
  req.unmatched_a = {&a1, &a2};
  req.unmatched_b = {&b1, &b2, &b3};
  req.matched = {{0x10, 0x20, 1.0f}, {0x30, 0x40, 1.0f}};
  std::vector<ResidueHint> hints = call_graph_hints(req);
  ASSERT_EQ(hints.size(), 1u);
  EXPECT_EQ(hints[0].a, 0x11u);
  EXPECT_EQ(hints[0].b, 0x21u);
  EXPECT_EQ(hints[0].kind, "caller");
}

TEST(ResidueTier, ScoresTheRequestWithFetchedVectors) {
  FunctionFeatures a1 = fn(0x11), a2 = fn(0x12), b1 = fn(0x21), b2 = fn(0x22);
  ResidueRequest req;
  req.unmatched_a = {&a1, &a2};
  req.unmatched_b = {&b1, &b2};
  const std::vector<std::uint32_t> x = features(1, 40), y = features(2, 40);
  std::size_t fetched = 0;
  auto fetch = [&](bool side_b, const std::vector<std::uint64_t> &entries) {
    fetched += entries.size();
    std::vector<std::vector<std::uint32_t>> out;
    for (std::uint64_t e : entries) out.push_back((e & 0xf) == 1 ? (side_b ? y : x) : (side_b ? x : y));
    return out;
  };
  std::vector<ScoredPair> scored = score_residue(req, fetch, weights());
  EXPECT_EQ(fetched, 4u);
  std::map<std::pair<std::uint64_t, std::uint64_t>, ScoredPair> accepted;
  for (const ScoredPair &p : scored)
    if (p.accept) accepted[{p.a, p.b}] = p;
  ASSERT_EQ(accepted.size(), 2u);
  EXPECT_TRUE(accepted.contains({0x11, 0x22}));
  EXPECT_TRUE(accepted.contains({0x12, 0x21}));
  const ScoredPair &p = accepted[std::make_pair(std::uint64_t{0x11}, std::uint64_t{0x22})];
  EXPECT_FLOAT_EQ(p.similarity, 1.0f);
  EXPECT_GT(p.confidence, 0.9f);
  EXPECT_LT(p.confidence, 0.95f);  // F5 alone is never auto-applied
}

}  // namespace
}  // namespace revkit::diff
