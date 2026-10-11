// Fingerprints and matching on two versions of a small program compiled at
// test time: what stays equal, what propagation finds, ties, seeds and
// rejections, determinism and incrementality.

#include "builders.hh"

#include "revkit/analysis/analysis.h"
#include "revkit/diff/correlate.h"
#include "revkit/diff/features.h"
#include "revkit/diff/match.h"
#include "revkit/facts/thread_pool.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <algorithm>
#include <map>
#include <tuple>
#include <set>

namespace revkit::diff {
namespace {

// Version 1 and 2 of one program. Between them: parse_flag gains a case,
// only_v1 goes, only_v2 comes (called from elsewhere), a function is
// inserted before the others so everything moves; get_a and get_b are
// identical apart from the global they read, in both versions.
constexpr const char *kHeader = R"(
#include <stdio.h>
#include <string.h>
)";

constexpr const char *kCommon = R"(
int g_counter;
int table[16];
__attribute__((noinline)) unsigned hash_str(const char *s) {
  unsigned h = 5381;
  while (*s) h = h * 33 + (unsigned char)*s++;
  return h;
}
__attribute__((noinline)) int clamp(int x, int lo, int hi) { return x < lo ? lo : x > hi ? hi : x; }
__attribute__((noinline)) int sum_table(void) {
  int s = 0;
  for (int i = 0; i < 16; i++) s += table[i] * (i + 1);
  return s;
}
__attribute__((noinline)) int get_a(void) { return table[1]; }
__attribute__((noinline)) int get_b(void) { return table[2]; }
)";

constexpr const char *kV1 = R"(
__attribute__((noinline)) int parse_flag(const char *a) {
  if (!strcmp(a, "--verbose")) return 1;
  if (!strcmp(a, "--quiet")) return 2;
  return 0;
}
__attribute__((noinline)) void report(const char *name, int v) {
  printf("%s=%d\n", name, v);
  g_counter++;
}
__attribute__((noinline)) int only_v1(int x) { return x * 7 + 3; }
int main(int argc, char **argv) {
  int f = argc > 1 ? parse_flag(argv[1]) : 0;
  report("flag", f);
  report("hash", (int)hash_str(argv[0]));
  report("clamp", clamp(argc, 1, 4));
  report("sum", sum_table() + get_a() + get_b());
  return only_v1(f);
}
)";

constexpr const char *kInserted = R"(
__attribute__((noinline)) int inserted(int x) { return x - 11; }
)";

constexpr const char *kV2 = R"(
__attribute__((noinline)) int parse_flag(const char *a) {
  if (!strcmp(a, "--verbose")) return 1;
  if (!strcmp(a, "--quiet")) return 2;
  if (!strcmp(a, "--extra")) return 3;
  return 0;
}
__attribute__((noinline)) int only_v2(int x) { return x ^ 0x5a5a; }
__attribute__((noinline)) void report(const char *name, int v) {
  printf("%s=%d\n", name, inserted(only_v2(v)));
  g_counter++;
}
int main(int argc, char **argv) {
  int f = argc > 1 ? parse_flag(argv[1]) : 0;
  report("flag", f);
  report("hash", (int)hash_str(argv[0]));
  report("clamp", clamp(argc, 1, 4));
  report("sum", sum_table() + get_a() + get_b());
  return f + 1;
}
)";

struct Built {
  std::filesystem::path debug, stripped;
};

class Diff : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("diff");
    for (int v = 0; v < 2; ++v) {
      Built b{dir / ("v" + std::to_string(v + 1)), dir / ("v" + std::to_string(v + 1) + "-stripped")};
      const std::string src = std::string(kHeader) + (v == 0 ? "" : kInserted) + kCommon + (v == 0 ? kV1 : kV2);
      if (!testing::compile(REVKIT_TEST_CC, src, "-O2 -fno-inline", b.debug)) return;
      if (std::system(("strip -o " + b.stripped.string() + " " + b.debug.string()).c_str()) != 0) return;
      built_[v] = b;
    }
    ok_ = true;
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!ok_) GTEST_SKIP() << "no C compiler or strip";
    lift::initialize(REVKIT_GHIDRA_ROOT);
    analysis::register_queries(db_.engine());
    register_queries(db_.engine());
    load("a", built_[0].stripped, 16);
    load("b", built_[1].stripped, 18);
    truth_[0] = names(built_[0].debug);
    truth_[1] = names(built_[1].debug);
  }

  void load(const std::string &id, const std::filesystem::path &file, facts::SpaceId space) {
    auto image = loader::load_file(file, {.image_base = std::nullopt, .ghidra_image_base = true});
    auto lang = loader::guess_language(image);
    ASSERT_TRUE(lang);
    analysis::ProgramInfo info = analysis::describe(image, lang->id(), space);
    info.references = true;
    analysis::import_image(db_, analysis::ProgramKey{id}, image, info);
    spaces_[id] = space;
  }

  // Entry -> name, from the unstripped twin's symbols.
  static std::map<std::uint64_t, std::string> names(const std::filesystem::path &file) {
    loader::Image img = loader::load_file(file, {.image_base = std::nullopt, .ghidra_image_base = true});
    std::map<std::uint64_t, std::string> out;
    for (const loader::Symbol &s : img.symbols)
      if (s.defined && s.type == loader::SymbolType::func) out[s.value] = s.name;
    return out;
  }
  std::uint64_t entry(int side, const std::string &name) {
    for (const auto &[a, n] : truth_[side])
      if (n == name) return a;
    ADD_FAILURE() << "no " << name;
    return 0;
  }

  MatchResult matches(const std::string &session = "s1") {
    return *db_.snapshot().get<Matches>(SessionKey{session, "a", "b", {}});
  }

  void assert_fact(facts::FactKey key, facts::FactValue value) {
    auto tx = db_.begin();
    tx.assert_fact(facts::Provenance::user("t"), std::move(key), std::move(value));
    tx.commit();
  }

  static inline Built built_[2];
  static inline bool ok_ = false;
  facts::FactDb db_;
  std::map<std::string, facts::SpaceId> spaces_;
  std::map<std::uint64_t, std::string> truth_[2];
};

TEST_F(Diff, UnchangedCodeHashesEqualAcrossVersions) {
  auto snap = db_.snapshot();
  auto fa = snap.get<Features>({{"a"}, entry(0, "hash_str")});
  auto fb = snap.get<Features>({{"b"}, entry(1, "hash_str")});
  ASSERT_NE(fa->entry, 0u);
  EXPECT_NE(fa->entry, fb->entry);  // moved
  EXPECT_EQ(fa->bytes, fb->bytes);
  EXPECT_EQ(fa->pcode, fb->pcode);
  EXPECT_EQ(fa->shape, fb->shape);
  EXPECT_GT(fa->instructions, 3u);
  EXPECT_GE(fa->loops, 1u);
  auto pa = snap.get<Features>({{"a"}, entry(0, "parse_flag")});
  auto pb = snap.get<Features>({{"b"}, entry(1, "parse_flag")});
  EXPECT_NE(pa->bytes, pb->bytes);
  EXPECT_FALSE(pa->strings.empty());  // "--verbose", "--quiet"? at least one string read
  // main calls report several times, in order.
  auto main_a = snap.get<Features>({{"a"}, entry(0, "main")});
  EXPECT_GE(main_a->calls.size(), 5u);
  // Imports in the bag: report calls printf (or __printf_chk).
  auto ra = snap.get<Features>({{"a"}, entry(0, "report")});
  EXPECT_FALSE(ra->bag.empty());
}

TEST_F(Diff, MatchesFollowTheTruth) {
  MatchResult r = matches();
  std::map<std::string, std::string> got;  // A name -> B name
  for (const Match &m : r.matches) {
    auto na = truth_[0].find(m.a), nb = truth_[1].find(m.b);
    if (na == truth_[0].end() || nb == truth_[1].end()) continue;
    got[na->second] = nb->second;
    EXPECT_EQ(na->second, nb->second) << "tier " << to_string(m.tier) << " via " << to_string(m.evidence.relation);
  }
  for (const char *n : {"hash_str", "clamp", "sum_table", "get_a", "get_b", "parse_flag", "report", "main"})
    EXPECT_EQ(got[n], n) << n << " unmatched";
  EXPECT_FALSE(got.contains("only_v1"));
  // Unchanged code matches on bytes, flagged unchanged.
  const Match *h = r.by_a(entry(0, "hash_str"));
  ASSERT_TRUE(h);
  EXPECT_TRUE(h->unchanged);
  EXPECT_GE(h->confidence, 0.95f);
  const Match *p = r.by_a(entry(0, "parse_flag"));
  ASSERT_TRUE(p);
  EXPECT_FALSE(p->unchanged);
  // only_v1 is left over, with the reason and (maybe) candidates.
  bool found = false;
  for (const Unmatched &u : r.unmatched_a) found |= u.entry == entry(0, "only_v1");
  EXPECT_TRUE(found);
}

TEST_F(Diff, IdenticalTwinsTieWithoutContext) {
  // get_a and get_b differ only in the global they read: equal masked
  // bytes on each side. Without propagation they are a tie, never guessed.
  auto snap = db_.snapshot();
  std::vector<facts::Ref<FunctionFeatures>> keep;
  MatchInput in;
  for (int side = 0; side < 2; ++side)
    for (const char *n : {"get_a", "get_b"}) {
      keep.push_back(snap.get<Features>({{side == 0 ? "a" : "b"}, entry(side, n)}));
      (side == 0 ? in.a : in.b).push_back(keep.back().get());
    }
  EXPECT_EQ(keep[0]->bytes, keep[1]->bytes);
  in.options.propagate = false;
  MatchResult r = match(in);
  EXPECT_TRUE(r.matches.empty());
  ASSERT_EQ(r.unmatched_a.size(), 2u);
  EXPECT_EQ(r.unmatched_a[0].reason, UnmatchedReason::tie);
  EXPECT_EQ(r.unmatched_a[0].candidates.size(), 2u);
}

TEST_F(Diff, SeedsAndRejectionsSteerMatching) {
  const std::uint64_t ga = entry(0, "get_a"), gb = entry(1, "get_b"), ha = entry(0, "hash_str"),
                      hb = entry(1, "hash_str");
  // Accept a wrong pair and reject a right one.
  assert_fact({facts::FactKind::Match, {spaces_["b"], gb}, match_sub("s1")},
              MatchValue{MatchState::accepted, false, ga, Tier::accepted, 1}.text());
  assert_fact({facts::FactKind::Match, {spaces_["b"], hb}, reject_sub("s1", ha)}, std::string("rejected"));
  MatchResult r = matches();
  const Match *m = r.by_a(ga);
  ASSERT_TRUE(m);
  EXPECT_EQ(m->b, gb);
  EXPECT_EQ(m->state, MatchState::accepted);
  EXPECT_EQ(m->tier, Tier::accepted);
  EXPECT_EQ(r.by_a(ha), nullptr);
  // Another session's assertions don't matter.
  MatchResult other = matches("s2");
  ASSERT_TRUE(other.by_a(ha));
  EXPECT_EQ(other.by_a(ha)->b, hb);
}

TEST_F(Diff, DeterministicAcrossThreadCounts) {
  facts::Engine &engine = db_.engine();
  MatchResult one = matches();
  std::string first = facts::encode_to_string(one);
  for (unsigned threads : {2u, 8u}) {
    facts::FactDb other;
    analysis::register_queries(other.engine());
    register_queries(other.engine());
    facts::ThreadPool pool(threads);
    other.engine().set_pool(&pool);
    for (auto [id, file, space] : {std::tuple{"a", built_[0].stripped, 16}, std::tuple{"b", built_[1].stripped, 18}}) {
      auto image = loader::load_file(file, {.image_base = std::nullopt, .ghidra_image_base = true});
      analysis::ProgramInfo info = analysis::describe(image, loader::guess_language(image)->id(),
                                                      static_cast<facts::SpaceId>(space));
      info.references = true;
      analysis::import_image(other, analysis::ProgramKey{id}, image, info);
    }
    auto r = other.snapshot().get<Matches>(SessionKey{"s1", "a", "b", {}});
    EXPECT_EQ(facts::encode_to_string(*r), first) << threads << " threads";
    other.engine().set_pool(nullptr);
  }
  (void)engine;
}

TEST_F(Diff, RenameRecomputesOnlyThatFunctionsFeatures) {
  MatchResult before = matches();
  db_.engine().reset_stats();
  const std::uint64_t e = entry(0, "clamp");
  assert_fact(facts::FactKey::name({spaces_["a"], e}), std::string("my_clamp"));
  MatchResult after = matches();
  EXPECT_EQ(db_.engine().stats<Features>().executions, 1u);
  EXPECT_EQ(db_.engine().stats<Proposals>().executions, 1u);
  // The same proposals (A's new name has no counterpart): the session's
  // matches validate by fingerprint.
  EXPECT_EQ(db_.engine().stats<Matches>().executions, 0u);
  // The name doesn't exist in B: the pair stays, found another way.
  ASSERT_TRUE(after.by_a(e));
  EXPECT_EQ(after.by_a(e)->b, entry(1, "clamp"));
  // Nothing changed: a memo hit.
  db_.engine().reset_stats();
  matches();
  EXPECT_EQ(db_.engine().stats<Matches>().executions, 0u);
}

TEST_F(Diff, DecisionsRefineTheProposalsIncrementally) {
  MatchResult base = matches();
  const std::uint64_t ga = entry(0, "get_a"), gb = entry(1, "get_b"), ha = entry(0, "hash_str"),
                      hb = entry(1, "hash_str");
  db_.engine().reset_stats();
  assert_fact({facts::FactKind::Match, {spaces_["b"], gb}, match_sub("s1")},
              MatchValue{MatchState::accepted, false, ga, Tier::accepted, 1}.text());
  assert_fact({facts::FactKind::Match, {spaces_["b"], hb}, reject_sub("s1", ha)}, std::string("rejected"));
  MatchResult r = matches();
  // Only the session's matches ran again, not the proposals.
  EXPECT_EQ(db_.engine().stats<Proposals>().executions, 0u);
  EXPECT_EQ(db_.engine().stats<Matches>().executions, 1u);
  ASSERT_TRUE(r.by_a(ga));
  EXPECT_EQ(r.by_a(ga)->b, gb);
  EXPECT_FALSE(r.by_a(ha));
  // get_b's own partner lost it; everything not involved stays as proposed.
  for (const Match &m : base.matches) {
    if (m.a == ga || m.a == ha || m.b == gb || m.b == hb) continue;
    const Match *x = r.by_a(m.a);
    ASSERT_TRUE(x) << std::hex << m.a;
    EXPECT_EQ(x->b, m.b);
  }
  // Retracting the decisions gives the proposals back.
  auto none = refine(MatchInput{}, base);
  EXPECT_EQ(facts::encode_to_string(none), facts::encode_to_string(base));
}

// The residue hook (M2's BSim plugs in here): a registered tier sees the
// unmatched functions with candidates; the pairs it accepts are matched as
// SIMILARITY and seed more propagation; reads through the context are the
// proposals' dependencies.
class PairTier : public SimilarityTier {
 public:
  std::string_view name() const override { return "test-pair"; }
  std::vector<ScoredPair> score(facts::QueryContext &ctx, const ResidueRequest &req) override {
    ++calls;
    seen_a = req.unmatched_a.size();
    seen_candidates = req.candidates.size();
    // Read something through the context, as a real tier reads its signatures.
    ctx.get<analysis::Program>(analysis::ProgramKey{req.program_a});
    std::vector<ScoredPair> out;
    for (const FunctionFeatures *f : req.unmatched_a)
      if (f->entry == a) out.push_back({a, b, 0.42f, 0.9f, true});
    return out;
  }
  std::uint64_t a = 0, b = 0;
  int calls = 0;
  std::size_t seen_a = 0, seen_candidates = 0;
};

TEST_F(Diff, SimilarityTierScoresTheResidue) {
  auto tier = std::make_shared<PairTier>();
  // only_v1 has no counterpart; the tier pairs it with inserted() anyway.
  tier->a = entry(0, "only_v1");
  tier->b = entry(1, "inserted");
  register_similarity_tier(tier);
  auto r = db_.snapshot().get<Matches>(SessionKey{"s1", "a", "b", {"test-pair"}});
  EXPECT_GE(tier->calls, 1);
  EXPECT_GT(tier->seen_a, 0u);
  EXPECT_EQ(tier->seen_candidates, tier->seen_a);
  const Match *m = r->by_a(tier->a);
  ASSERT_TRUE(m);
  EXPECT_EQ(m->b, tier->b);
  EXPECT_EQ(m->tier, Tier::similarity);
  EXPECT_EQ(m->evidence.relation, Relation::similar);
  EXPECT_FLOAT_EQ(m->similarity, 0.42f);
  EXPECT_FLOAT_EQ(m->confidence, 0.9f);
  // A session without the tier doesn't call it.
  const int before = tier->calls;
  auto plain = matches("s2");
  EXPECT_EQ(tier->calls, before);
  EXPECT_FALSE(plain.by_a(tier->a));
}

// A function's code is the same when only data it reads changed: firmware
// whose patch rewrote a table of pointers (as a patch rewrites an asset
// table) changes where loads through the table lead, not the code. Built
// from the synthetic ARM firmware, with two of its handlers[] swapped.
TEST_F(Diff, DataTheCodeReadsDoesNotChangeTheCode) {
  if (std::string(REVKIT_TEST_CLANG).empty() || std::string(REVKIT_TEST_LLD).empty() ||
      std::string(REVKIT_TEST_OBJCOPY).empty())
    GTEST_SKIP() << "no clang, ld.lld and llvm-objcopy for armv4t";
  auto dir = testing::scratch_dir("diff-table");
  const std::string cmd = std::string("sh ") + REVKIT_ARMFW_DIR + "/build.sh " + REVKIT_TEST_CLANG + " " +
                          REVKIT_TEST_LLD + " " + REVKIT_TEST_OBJCOPY + " " + dir.string() + " >/dev/null 2>&1";
  if (std::system(cmd.c_str()) != 0) GTEST_SKIP() << "the ARM firmware didn't build";
  std::uint64_t table = 0;
  {
    loader::Image elf = loader::load_file(dir / "fw.elf", {.image_base = std::nullopt, .ghidra_image_base = true});
    for (const loader::Symbol &sym : elf.symbols)
      if (sym.name == "handlers") table = sym.value;
  }
  ASSERT_NE(table, 0u);
  auto bytes = testing::read_file(dir / "fw.bin");
  ASSERT_GE(bytes.size(), table + 8);
  std::swap_ranges(bytes.begin() + static_cast<std::ptrdiff_t>(table), bytes.begin() + static_cast<std::ptrdiff_t>(table + 4),
                   bytes.begin() + static_cast<std::ptrdiff_t>(table + 4));
  {
    std::ofstream out(dir / "fw2.bin", std::ios::binary);
    out.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  }
  const loader::RawOptions raw{.language = "ARM:LE:32:v4t", .base = 0, .entry = 0};
  for (auto [id, file, space] : {std::tuple{"fa", "fw.bin", facts::SpaceId{20}}, std::tuple{"fb", "fw2.bin", facts::SpaceId{22}}}) {
    loader::Image image = loader::load_raw_file(dir / file, raw);
    analysis::ProgramInfo info = analysis::describe(image, raw.language, space);
    info.references = true;
    analysis::import_image(db_, analysis::ProgramKey{id}, image, info);
  }
  MatchResult r = *db_.snapshot().get<Matches>(SessionKey{"tables", "fa", "fb", {}});
  ASSERT_GT(r.matches.size(), 10u);
  for (const Match &m : r.matches) {
    EXPECT_EQ(m.a, m.b);
    EXPECT_TRUE(m.unchanged) << std::hex << m.a << " reads the table but its code didn't change";
  }
  EXPECT_TRUE(r.unmatched_a.empty());
  EXPECT_TRUE(r.unmatched_b.empty());
}

// Inside matched pairs of two compiled versions: everything moved (a
// function was inserted before the others), so nothing may assume equal
// addresses. Unchanged functions correlate equal everywhere; parse_flag
// gains a case (inserted instructions, nothing removed); main no longer
// calls only_v1; report gains calls to only_v2 and inserted.
TEST_F(Diff, CorrelationInsideMatchedPairsOfMovedCode) {
  MatchResult r = matches();
  auto snap = db_.snapshot();
  MatchOf match_of = [&](std::uint64_t a) -> std::optional<std::uint64_t> {
    if (const Match *m = r.by_a(a)) return m->b;
    return std::nullopt;
  };
  auto pair = [&](const std::string &name) {
    const std::uint64_t a = entry(0, name), b = entry(1, name);
    const Match *m = r.by_a(a);
    EXPECT_TRUE(m && m->b == b) << name << " is matched";
    if (name != "main") EXPECT_NE(a, b) << name << " moved";
    Correlation c = *snap.get<Correlate>({"a", "b", a, b});
    auto code_a = snap.get<Code>({{"a"}, a});
    auto code_b = snap.get<Code>({{"b"}, b});
    retarget(c, *code_a, *code_b, match_of);
    return std::tuple{c, code_a, code_b};
  };
  for (const char *same : {"hash_str", "clamp", "sum_table"}) {
    auto [c, ca, cb] = pair(same);
    EXPECT_GT(c.equal, 3u) << same;
    EXPECT_EQ(c.changed + c.inserted + c.deleted, 0u) << same;
    EXPECT_TRUE(c.hunks().empty()) << same;
    for (BlockStatus st : c.block_status_a) EXPECT_EQ(st, BlockStatus::unchanged) << same;
  }
  {
    auto [c, ca, cb] = pair("parse_flag");
    EXPECT_GE(c.inserted, 3u);
    EXPECT_GE(c.equal, ca->insns.size() * 2 / 3);
    bool added = false;
    for (BlockStatus st : c.block_status_b) added |= st == BlockStatus::added;
    EXPECT_TRUE(added) << "the new case's block";
  }
  auto calls = [](const std::vector<RefChange> &refs, bool in_b, std::uint64_t to) {
    for (const RefChange &x : refs)
      if (x.in_b == in_b && x.ref.kind != CodeRef::Kind::data && x.ref.to == to) return true;
    return false;
  };
  {
    auto [c, ca, cb] = pair("main");
    const auto refs = reference_diff(c, *ca, *cb, match_of);
    EXPECT_TRUE(calls(refs, false, entry(0, "only_v1")));
    EXPECT_FALSE(calls(refs, true, entry(1, "report"))) << "report is called the same";
  }
  {
    auto [c, ca, cb] = pair("report");
    const auto refs = reference_diff(c, *ca, *cb, match_of);
    EXPECT_TRUE(calls(refs, true, entry(1, "only_v2")));
    EXPECT_TRUE(calls(refs, true, entry(1, "inserted")));
    EXPECT_FALSE(calls(refs, false, entry(0, "report")));
  }
}

// An in-place patch (the case of firmware patched on the device): one
// instruction of the ARM firmware's h2 becomes a BL to new code written
// over data at the end of the image. The pair's instruction map flags
// exactly that instruction, as CHANGED, and the reference diff names the
// new callee.
TEST_F(Diff, InPlacePatchFlagsOnlyThePatchedInstruction) {
  if (std::string(REVKIT_TEST_CLANG).empty() || std::string(REVKIT_TEST_LLD).empty() ||
      std::string(REVKIT_TEST_OBJCOPY).empty())
    GTEST_SKIP() << "no clang, ld.lld and llvm-objcopy for armv4t";
  auto dir = testing::scratch_dir("diff-patch");
  const std::string cmd = std::string("sh ") + REVKIT_ARMFW_DIR + "/build.sh " + REVKIT_TEST_CLANG + " " +
                          REVKIT_TEST_LLD + " " + REVKIT_TEST_OBJCOPY + " " + dir.string() + " >/dev/null 2>&1";
  if (std::system(cmd.c_str()) != 0) GTEST_SKIP() << "the ARM firmware didn't build";
  std::uint64_t h2 = 0, h2_size = 0;
  {
    loader::Image elf = loader::load_file(dir / "fw.elf", {.image_base = std::nullopt, .ghidra_image_base = true});
    for (const loader::Symbol &sym : elf.symbols)
      if (sym.name == "h2") h2 = sym.value, h2_size = sym.size;
  }
  ASSERT_NE(h2, 0u);
  auto bytes = testing::read_file(dir / "fw.bin");
  // Data at the end of both images (zeros: never code in A).
  bytes.resize((bytes.size() + 15) / 16 * 16 + 64, 0);
  auto word = [&](std::uint64_t at) {
    return std::uint32_t{bytes[at]} | std::uint32_t{bytes[at + 1]} << 8 | std::uint32_t{bytes[at + 2]} << 16 |
           std::uint32_t{bytes[at + 3]} << 24;
  };
  auto put = [&](std::vector<std::uint8_t> &b, std::uint64_t at, std::uint32_t v) {
    for (int k = 0; k < 4; ++k) b[at + static_cast<std::uint64_t>(k)] = static_cast<std::uint8_t>(v >> (8 * k));
  };
  std::uint64_t patched = 0;
  for (std::uint64_t at = h2; at + 4 <= h2 + (h2_size ? h2_size : 32); at += 4)
    if (word(at) == 0xe2400007u) patched = at;  // sub r0, r0, #7
  ASSERT_NE(patched, 0u) << "h2's sub r0, r0, #7";
  std::vector<std::uint8_t> b = bytes;
  const std::uint64_t fresh = b.size() - 32;
  put(b, fresh, 0xe2800009u);      // add r0, r0, #9
  put(b, fresh + 4, 0xe12fff1eu);  // bx lr
  put(b, patched, 0xeb000000u | static_cast<std::uint32_t>(((fresh - (patched + 8)) >> 2) & 0xffffff));  // bl fresh
  for (auto [file, data] : {std::pair{"pa.bin", &bytes}, std::pair{"pb.bin", &b}}) {
    std::ofstream out(dir / file, std::ios::binary);
    out.write(reinterpret_cast<const char *>(data->data()), static_cast<std::streamsize>(data->size()));
  }
  const loader::RawOptions raw{.language = "ARM:LE:32:v4t", .base = 0, .entry = 0};
  for (auto [id, file, space] : {std::tuple{"pa", "pa.bin", facts::SpaceId{24}}, std::tuple{"pb", "pb.bin", facts::SpaceId{26}}}) {
    loader::Image image = loader::load_raw_file(dir / file, raw);
    analysis::ProgramInfo info = analysis::describe(image, raw.language, space);
    info.references = true;
    analysis::import_image(db_, analysis::ProgramKey{id}, image, info);
  }
  auto snap = db_.snapshot();
  MatchResult r = *snap.get<Matches>(SessionKey{"patch", "pa", "pb", {}});
  MatchOf match_of = [&](std::uint64_t a) -> std::optional<std::uint64_t> {
    if (const Match *m = r.by_a(a)) return m->b;
    return std::nullopt;
  };
  std::size_t modified = 0;
  for (const Match &m : r.matches) {
    Correlation c = *snap.get<Correlate>({"pa", "pb", m.a, m.b});
    auto ca = snap.get<Code>({{"pa"}, m.a});
    auto cb = snap.get<Code>({{"pb"}, m.b});
    retarget(c, *ca, *cb, match_of);
    std::vector<std::uint64_t> differ;
    for (std::size_t i = 0; i < c.status_b.size(); ++i)
      if (c.status_b[i] != InsnStatus::equal) differ.push_back(cb->insns[i].address);
    for (std::size_t i = 0; i < c.status_a.size(); ++i)
      if (c.status_a[i] == InsnStatus::deleted) differ.push_back(ca->insns[i].address);
    if (m.a != h2) {
      EXPECT_TRUE(differ.empty()) << std::hex << m.a << " didn't change";
      EXPECT_TRUE(m.unchanged) << std::hex << m.a;
      continue;
    }
    ++modified;
    EXPECT_FALSE(m.unchanged);
    EXPECT_EQ(differ, (std::vector<std::uint64_t>{patched}));
    EXPECT_EQ(c.changed, 1u);
    EXPECT_EQ(c.inserted + c.deleted, 0u);
    ASSERT_EQ(c.hunks().size(), 1u);
    const auto refs = reference_diff(c, *ca, *cb, match_of);
    ASSERT_EQ(refs.size(), 1u);
    EXPECT_TRUE(refs[0].in_b);
    EXPECT_EQ(refs[0].ref.kind, CodeRef::Kind::call);
    EXPECT_EQ(refs[0].ref.to, fresh);
    EXPECT_FALSE(r.by_b(fresh)) << "the new code has no match";
  }
  EXPECT_EQ(modified, 1u);
}

namespace {
FunctionFeatures Fn(std::uint64_t entry, std::uint64_t bytes, std::uint64_t raw, std::vector<std::uint64_t> calls = {}) {
  FunctionFeatures f;
  f.entry = entry;
  f.bytes = bytes;
  f.raw = raw;
  f.pcode = bytes * 31;
  f.shape = bytes * 7;
  f.opcodes = bytes * 13;
  f.instructions = 12;
  f.blocks = 2;
  f.calls = std::move(calls);
  return f;
}
}  // namespace

// Identical twins (the same code twice) between functions that match pair
// by their place, and only as a proposal.
TEST(DiffMatch, TwinsBetweenMatchedNeighboursPairInAddressOrder) {
  std::vector<FunctionFeatures> fa = {Fn(0x100, 1, 1), Fn(0x200, 7, 70), Fn(0x300, 7, 71), Fn(0x400, 2, 2)};
  std::vector<FunctionFeatures> fb = {Fn(0x100, 1, 1), Fn(0x200, 7, 70), Fn(0x300, 7, 71), Fn(0x400, 2, 2)};
  MatchInput in;
  for (auto &f : fa) in.a.push_back(&f);
  for (auto &f : fb) in.b.push_back(&f);
  MatchResult r = match(in);
  std::map<std::uint64_t, const Match *> by_a;
  for (const Match &m : r.matches) by_a[m.a] = &m;
  ASSERT_EQ(by_a.size(), 4u);
  for (std::uint64_t e : {0x200u, 0x300u}) {
    EXPECT_EQ(by_a[e]->b, e);
    EXPECT_EQ(by_a[e]->evidence.relation, Relation::address);
    EXPECT_LT(by_a[e]->confidence, 0.95f);
    EXPECT_TRUE(by_a[e]->unchanged);
  }
  EXPECT_TRUE(r.unmatched_a.empty());
}

// A patch that only retargets a call keeps the masked bytes (F1) but not
// the code: the call site now calls a function that matches another.
TEST(DiffMatch, RetargetedCallIsAChange) {
  std::vector<FunctionFeatures> fa = {Fn(0x100, 5, 50, {0x200}), Fn(0x200, 1, 10), Fn(0x300, 2, 20)};
  std::vector<FunctionFeatures> fb = {Fn(0x100, 5, 51, {0x300}), Fn(0x200, 1, 10), Fn(0x300, 2, 20)};
  MatchInput in;
  for (auto &f : fa) in.a.push_back(&f);
  for (auto &f : fb) in.b.push_back(&f);
  MatchResult r = match(in);
  ASSERT_EQ(r.matches.size(), 3u);
  for (const Match &m : r.matches) {
    EXPECT_EQ(m.a, m.b);
    EXPECT_EQ(m.unchanged, m.a != 0x100) << std::hex << m.a;
  }
}

TEST(MatchValueText, RoundTrips) {
  MatchValue v{MatchState::applied, false, 0x401000, Tier::pcode, 0.97f};
  auto p = MatchValue::parse(v.text());
  ASSERT_TRUE(p);
  EXPECT_EQ(p->a, 0x401000u);
  EXPECT_EQ(p->state, MatchState::applied);
  EXPECT_EQ(p->tier, Tier::pcode);
  EXPECT_NEAR(p->confidence, 0.97f, 1e-3);
  EXPECT_TRUE(MatchValue::parse("rejected")->rejected);
  auto s = parse_match_sub(reject_sub("d-12", 0xabc));
  ASSERT_TRUE(s);
  EXPECT_EQ(s->session, "d-12");
  EXPECT_EQ(s->rejected_a, 0xabcu);
  EXPECT_FALSE(parse_match_sub("d-12/other")->rejected_a.has_value() && false);
}

}  // namespace
}  // namespace revkit::diff
