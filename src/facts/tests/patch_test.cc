// Byte patches as assertions (FactKind::Patch) and the bytes.effective
// query (docs/patching.md): undo and redo, precedence between overlapping
// patches, revert by provenance, replication in either order, persistence,
// and invalidation that stops at the patched page.
#include "revkit/facts/fact_db.h"
#include "revkit/facts/storage.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>

namespace revkit::facts {
namespace {

constexpr SpaceId kSpace = 16;
const Provenance kAlice = Provenance::user("alice");
const Provenance kBob = Provenance::user("bob");
const Provenance kAgent = Provenance::agent("model", "1");

std::string page_of(char fill) { return std::string(kPageSize, fill); }

struct Db {
  explicit Db(ReplicaId replica = 0, std::unique_ptr<Storage> storage = nullptr) {
    FactDbOptions o;
    o.replica = replica;
    o.storage = std::move(storage);
    std::int64_t t = 1'000'000'000'000;
    o.clock = [t]() mutable { return t += 1'000'000; };
    db = std::make_unique<FactDb>(std::move(o));
  }
  void load() {
    auto tx = db->begin();
    tx.write_bytes(Address{kSpace, 0}, page_of('a') + page_of('b') + page_of('c'));
    tx.commit();
  }
  Seq patch(const Provenance &who, std::uint64_t at, std::string bytes) {
    auto tx = db->begin();
    Seq s = tx.assert_fact(who, FactKey::patch(Address{kSpace, at}), std::move(bytes));
    tx.commit();
    return s;
  }
  Seq retract(const Provenance &who, Seq target) {
    auto tx = db->begin();
    Seq s = tx.retract(who, target);
    tx.commit();
    return s;
  }
  std::string read(std::uint64_t at, std::size_t n) {
    auto snap = db->snapshot();
    std::string out;
    for (std::uint64_t a = at; a < at + n; ++a) {
      auto page = snap.get<EffectivePage>(PageKey{kSpace, a / kPageSize});
      out += a % kPageSize < page->size() ? (*page)[a % kPageSize] : '?';
    }
    return out;
  }
  std::unique_ptr<FactDb> db;
};

TEST(PatchTest, EffectiveBytesFollowUndoAndRedo) {
  Db d;
  d.load();
  EXPECT_EQ(d.read(0x10, 4), "aaaa");
  const Seq p = d.patch(kAlice, 0x10, "XY");
  EXPECT_EQ(d.read(0xf, 4), "aXYa");
  const Seq undo = d.retract(kAlice, p);
  EXPECT_EQ(d.read(0xf, 4), "aaaa");
  d.retract(kAlice, undo);  // redo
  EXPECT_EQ(d.read(0xf, 4), "aXYa");
  // The original bytes are untouched.
  auto snap = d.db->snapshot();
  EXPECT_EQ((*snap.get<MemoryPage>(PageKey{kSpace, 0}))[0x10], 'a');
}

TEST(PatchTest, APatchAcrossAPageBoundaryReachesBoth) {
  Db d;
  d.load();
  d.patch(kAlice, kPageSize - 2, "1234");
  EXPECT_EQ(d.read(kPageSize - 3, 6), "a1234b");
}

TEST(PatchTest, OverlapsComposeByPrecedenceThenRecency) {
  Db d;
  d.load();
  // A user's patch outranks a later agent's where they overlap.
  d.patch(kAlice, 0x100, "UUUU");
  d.patch(kAgent, 0x102, "GGGG");
  EXPECT_EQ(d.read(0x100, 6), "UUUUGG");
  // Between equals, the later one wins its bytes.
  d.patch(kBob, 0x101, "B");
  EXPECT_EQ(d.read(0x100, 6), "UBUUGG");
  d.patch(kAlice, 0x100, "uuuu");  // same key, alice again: replaces her value
  EXPECT_EQ(d.read(0x100, 6), "uuuuGG");
  // Re-asserting the same value later makes it the most recent of its rank.
  d.patch(kBob, 0x101, "B");
  EXPECT_EQ(d.read(0x100, 6), "uBuuGG");
}

TEST(PatchTest, RevertByProvenanceRemovesOnlyThatAuthorsPatches) {
  Db d;
  d.load();
  d.patch(kAlice, 0x200, "AA");
  d.patch(kAgent, 0x300, "MM");
  d.patch(kAgent, 0x201, "mm");
  EXPECT_EQ(d.read(0x200, 3), "AAm");
  {
    auto tx = d.db->begin();
    tx.revert(kAlice, Provenance::agent("model"));
    tx.commit();
  }
  EXPECT_EQ(d.read(0x200, 3), "AAa");
  EXPECT_EQ(d.read(0x300, 2), "aa");
}

TEST(PatchTest, ReplicasConvergeInEitherOrder) {
  Db a(1), b(2), c(3);
  a.load();
  b.load();
  c.load();
  a.patch(kAlice, 0x40, "aaaaZZ");
  b.patch(kBob, 0x42, "YYYY");
  auto ops_a = a.db->ops_since({});
  auto ops_b = b.db->ops_since({});
  auto merge = [](Db &into, const std::vector<Op> &ops) {
    auto tx = into.db->begin();
    tx.merge(ops);
    tx.commit();
  };
  merge(a, ops_b);
  merge(b, ops_a);
  merge(c, ops_b);
  merge(c, ops_a);
  const std::string want = a.read(0x40, 8);
  EXPECT_EQ(b.read(0x40, 8), want);
  EXPECT_EQ(c.read(0x40, 8), want);
}

TEST(PatchTest, PatchesPersistAndReplay) {
  const auto dir = std::filesystem::temp_directory_path() / ("revkit-patch-test-" + std::to_string(::getpid()));
  std::filesystem::remove_all(dir);
  {
    Db d(0, open_lmdb_storage(dir));
    d.load();
    d.patch(kAlice, 0x10, "PQ");
    d.patch(kAgent, 0x11, "rs");
  }
  {
    Db d(0, open_lmdb_storage(dir));
    EXPECT_EQ(d.read(0x10, 4), "PQsa");
  }
  std::filesystem::remove_all(dir);
}

TEST(PatchTest, APatchInvalidatesOnlyItsPage) {
  Db d;
  d.load();
  {
    auto snap = d.db->snapshot();
    for (std::uint64_t i = 0; i < 3; ++i) snap.get<EffectivePage>(PageKey{kSpace, i});
  }
  d.db->engine().reset_stats();
  d.patch(kAlice, kPageSize + 0x20, "!");
  auto snap = d.db->snapshot();
  for (std::uint64_t i = 0; i < 3; ++i) snap.get<EffectivePage>(PageKey{kSpace, i});
  EXPECT_EQ(d.db->engine().stats<EffectivePage>().executions, 1u);
  EXPECT_EQ((*snap.get<EffectivePage>(PageKey{kSpace, 1}))[0x20], '!');
  // A note doesn't revalidate the bytes at all (its own partition).
  d.db->engine().reset_stats();
  {
    auto tx = d.db->begin();
    tx.assert_fact(kAlice, FactKey::note(Address{kSpace, 0x20}, "x"), std::string("hello"));
    tx.commit();
  }
  auto snap2 = d.db->snapshot();
  for (std::uint64_t i = 0; i < 3; ++i) snap2.get<EffectivePage>(PageKey{kSpace, i});
  EXPECT_EQ(d.db->engine().stats<EffectivePage>().executions, 0u);
}

// Pages with no patch near them read their patch.page gate and no span; a
// patch opens the gates of the pages it can reach only.
TEST(PatchTest, PagesWithoutPatchesReadNoSpans) {
  Db d;
  d.load();
  auto read_all = [&] {
    auto snap = d.db->snapshot();
    for (std::uint64_t i = 0; i < 3; ++i) snap.get<EffectivePage>(PageKey{kSpace, i});
  };
  read_all();
  Engine &engine = d.db->engine();
  EXPECT_EQ(engine.stats<PatchSpan>().executions, 0u);
  EXPECT_EQ(engine.stats<PatchedPage>().executions, 3u);
  auto inputs = d.db->snapshot().fact<EffectivePage>(PageKey{kSpace, 1}).inputs;
  auto reads = [&](std::string_view rule) {
    return std::count_if(inputs.begin(), inputs.end(), [&](const std::string &i) { return i.starts_with(rule); });
  };
  EXPECT_EQ(reads("patch.span("), 0);
  EXPECT_EQ(reads("patch.page("), 1);

  // Within the last 255 bytes of page 1: it can reach page 2, not page 0.
  engine.reset_stats();
  d.patch(kAlice, 2 * kPageSize - 0x10, "!");
  read_all();
  EXPECT_EQ(engine.stats<EffectivePage>().executions, 2u);
  {
    auto snap = d.db->snapshot();
    EXPECT_FALSE(*snap.get<PatchedPage>(PageKey{kSpace, 0}));
    EXPECT_TRUE(*snap.get<PatchedPage>(PageKey{kSpace, 1}));
    EXPECT_TRUE(*snap.get<PatchedPage>(PageKey{kSpace, 2}));
  }
  EXPECT_EQ(d.read(2 * kPageSize - 0x11, 3), "b!b");
}

TEST(PatchTest, PatchesOverUnmappedBytesAreIgnored) {
  Db d;
  d.load();
  d.patch(kAlice, 3 * kPageSize + 8, "zz");
  auto snap = d.db->snapshot();
  EXPECT_TRUE(snap.get<EffectivePage>(PageKey{kSpace, 3})->empty());
}

}  // namespace
}  // namespace revkit::facts
