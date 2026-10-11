// Rebase (docs/memory-map.md, "Rebase: setting the image base"): a space's
// keys stored image-relative and read moved by its live Rebase value.
#include "revkit/facts/fact_db.h"
#include "revkit/facts/storage.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <random>

namespace revkit::facts {
namespace {

constexpr SpaceId kSpace = 16;
const Provenance kAlice = Provenance::user("alice");
const Provenance kBob = Provenance::user("bob");

FactKey Name(std::uint64_t a) { return FactKey::name({kSpace, a}); }
FactKey RebaseKey() { return {FactKind::Rebase, {kSpace, 0}, {}}; }

std::string ValueAt(FactDb &db, const FactKey &k) {
  FactValue v = *db.snapshot().get<AssertedFact>(k);
  const auto *s = std::get_if<std::string>(&v);
  return s ? *s : std::string();
}

// The addresses the key index has for `kind` in the space.
std::vector<std::uint64_t> asserted_keys_at(FactDb &db, FactKind kind) {
  Snapshot snap = db.snapshot();
  std::vector<std::uint64_t> out;
  for (std::uint64_t b : *snap.get<AssertedBuckets>({kind, kSpace}))
    for (const auto &[offset, sub] : *snap.get<AssertedKeys>(BucketKey{kind, kSpace, b})) out.push_back(offset);
  return out;
}

Seq Put(FactDb &db, const Provenance &who, const FactKey &k, FactValue v) {
  auto tx = db.begin();
  Seq s = tx.assert_fact(who, k, std::move(v));
  tx.commit();
  return s;
}

Seq Rebase(FactDb &db, std::uint64_t delta, unsigned bits = 32) {
  return Put(db, kAlice, RebaseKey(), Shift{delta, bits}.str());
}

void Retract(FactDb &db, Seq s) {
  auto tx = db.begin();
  tx.retract(kAlice, s);
  tx.commit();
}

TEST(Rebase, ShiftText) {
  Shift s{0x10000, 32};
  EXPECT_EQ(s.str(), "0x10000/32");
  EXPECT_EQ(Shift::parse("0x10000/32"), s);
  EXPECT_EQ(s.apply(0x1000), 0x11000u);
  EXPECT_EQ(s.apply(0xffff8000), 0x8000u);  // wraps in 32 bits
  EXPECT_EQ(s.apply(std::uint64_t{1} << 40), std::uint64_t{1} << 40);  // another memory space doesn't move
  EXPECT_EQ(s.inverse().apply(s.apply(0x1234)), 0x1234u);
  EXPECT_FALSE(Shift::parse("10000/32"));
  EXPECT_FALSE(Shift::parse("0x10000/65"));
  EXPECT_FALSE(Shift::parse(""));
}

TEST(Rebase, KeysReadMovedAndAreStoredImageRelative) {
  FactDb db;
  Put(db, kAlice, Name(0x1000), std::string("main"));
  Put(db, kAlice, FactKey::function({kSpace, 0x1000}), AddressSet(AddressRange{{kSpace, 0x1000}, {kSpace, 0x10ff}}));
  Put(db, kAlice, FactKey::type_def("struct point"), std::string("record"));
  const Seq rebase = Rebase(db, 0x10000);
  EXPECT_EQ(ValueAt(db, Name(0x11000)), "main");
  EXPECT_EQ(ValueAt(db, Name(0x1000)), "");
  // The index (what range reads use) has the moved key only.
  auto keys = asserted_keys_at(db, FactKind::Name);
  EXPECT_EQ(keys, (std::vector<std::uint64_t>{0x11000}));
  // An AddressSet value moves too; a type definition (no address) doesn't.
  FactValue body = *db.snapshot().get<AssertedFact>(FactKey::function({kSpace, 0x11000}));
  ASSERT_TRUE(std::holds_alternative<AddressSet>(body));
  EXPECT_EQ(std::get<AddressSet>(body).ranges().front().first.offset, 0x11000u);
  EXPECT_EQ(ValueAt(db, FactKey::type_def("struct point")), "record");

  // A key asserted now (at its moved address) is stored image-relative.
  const Seq later = Put(db, kBob, Name(0x12000), std::string("helper"));
  EXPECT_EQ(db.log().op(later)->key.addr.offset, 0x2000u);
  EXPECT_EQ(ValueAt(db, Name(0x12000)), "helper");

  // Undoing the rebase moves everything back, the later key included.
  Retract(db, rebase);
  EXPECT_EQ(ValueAt(db, Name(0x1000)), "main");
  EXPECT_EQ(ValueAt(db, Name(0x2000)), "helper");
  EXPECT_EQ(ValueAt(db, Name(0x11000)), "");
  EXPECT_EQ(ValueAt(db, Name(0x12000)), "");
  EXPECT_EQ(asserted_keys_at(db, FactKind::Name), (std::vector<std::uint64_t>{0x1000, 0x2000}));
}

TEST(Rebase, ALaterRebaseReplacesAndUndoReturnsToTheOneBefore) {
  FactDb db;
  Put(db, kAlice, Name(0x1000), std::string("main"));
  Rebase(db, 0x10000);
  const Seq second = Rebase(db, 0x20000);
  EXPECT_EQ(ValueAt(db, Name(0x21000)), "main");
  Retract(db, second);
  EXPECT_EQ(ValueAt(db, Name(0x11000)), "main");
  EXPECT_EQ(ValueAt(db, Name(0x21000)), "");
  // Back to the import base by asserting a zero shift.
  Rebase(db, 0);
  EXPECT_EQ(ValueAt(db, Name(0x1000)), "main");
}

TEST(Rebase, KeysLandingWhereOthersLeft) {
  // 0x1000 moves to 0x2000, where another key was: both are right after.
  FactDb db;
  Put(db, kAlice, Name(0x1000), std::string("a"));
  Put(db, kAlice, Name(0x2000), std::string("b"));
  std::vector<FactKey> changed;
  {
    auto tx = db.begin();
    tx.assert_fact(kAlice, RebaseKey(), Shift{0x1000, 64}.str());
    tx.commit(&changed);
  }
  EXPECT_EQ(ValueAt(db, Name(0x2000)), "a");
  EXPECT_EQ(ValueAt(db, Name(0x3000)), "b");
  EXPECT_EQ(ValueAt(db, Name(0x1000)), "");
  // The commit reports the old and new places.
  auto has = [&](std::uint64_t a) {
    return std::find(changed.begin(), changed.end(), Name(a)) != changed.end();
  };
  EXPECT_TRUE(has(0x1000) && has(0x2000) && has(0x3000));
}

TEST(Rebase, TheCallbackStagesInTheSameCommit) {
  std::vector<std::pair<Shift, Shift>> calls;
  FactDbOptions o;
  o.on_rebase = [&](FactDbTransaction &tx, SpaceId space, const Shift &before, const Shift &after) {
    EXPECT_EQ(space, kSpace);
    calls.emplace_back(before, after);
    tx.write_bytes({kSpace, after.apply(0x1000)}, "\x90\xc3");
  };
  FactDb db(std::move(o));
  const auto rev0 = db.engine().revision();
  const Seq rebase = Rebase(db, 0x10000);
  EXPECT_EQ(db.engine().revision(), rev0 + 1);
  ASSERT_EQ(calls.size(), 1u);
  EXPECT_EQ(calls[0].second, (Shift{0x10000, 32}));
  EXPECT_EQ(db.snapshot().get<MemoryPage>(PageKey{kSpace, 0x11000 / kPageSize})->substr(0, 2), "\x90\xc3");
  // Undo, redo and an equal rebase call it as the shift changes.
  Retract(db, rebase);
  ASSERT_EQ(calls.size(), 2u);
  EXPECT_TRUE(calls[1].second.identity());
  Put(db, kAlice, Name(0x1000), std::string("x"));
  EXPECT_EQ(calls.size(), 2u);
}

TEST(Rebase, ReplicasAndReopenAgree) {
  // Ops travel image-relative: a peer merging a rebase and the edits made
  // after it reads them where the author does.
  FactDbOptions oa, ob;
  oa.replica = 1;
  ob.replica = 2;
  FactDb a(std::move(oa)), b(std::move(ob));
  Put(a, kAlice, Name(0x1000), std::string("main"));
  Rebase(a, 0x10000);
  Put(a, kAlice, Name(0x12000), std::string("helper"));
  {
    auto tx = b.begin();
    tx.merge(a.ops_since({}));
    tx.commit();
  }
  EXPECT_EQ(ValueAt(b, Name(0x11000)), "main");
  EXPECT_EQ(ValueAt(b, Name(0x12000)), "helper");
  // A peer's edit made before it saw the rebase (at the old base) lands
  // with the image too.
  FactDbOptions oc;
  oc.replica = 3;
  FactDb c(std::move(oc));
  {
    auto tx = c.begin();
    tx.merge(a.ops_since({}, 1));  // "main" only, not the rebase
    tx.commit();
  }
  EXPECT_EQ(ValueAt(c, Name(0x1000)), "main");
  Put(c, kBob, Name(0x3000), std::string("from_c"));
  {
    auto tx = a.begin();
    tx.merge(c.ops_since(a.version_vector()));
    tx.commit();
  }
  EXPECT_EQ(ValueAt(a, Name(0x13000)), "from_c");

  // Reopened from storage: indexed with the shift its log gives.
  const auto dir = std::filesystem::temp_directory_path() / ("rk-rebase-" + std::to_string(std::random_device{}()));
  {
    FactDbOptions o;
    o.storage = open_lmdb_storage(dir);
    FactDb d(std::move(o));
    auto tx = d.begin();
    tx.merge(a.ops_since({}));
    tx.commit();
  }
  {
    FactDbOptions o;
    o.storage = open_lmdb_storage(dir);
    FactDb d(std::move(o));
    EXPECT_EQ(d.shift(kSpace), (Shift{0x10000, 32}));
    EXPECT_EQ(ValueAt(d, Name(0x11000)), "main");
    EXPECT_EQ(ValueAt(d, Name(0x13000)), "from_c");
    EXPECT_EQ(ValueAt(d, Name(0x1000)), "");
  }
  std::filesystem::remove_all(dir);
}

}  // namespace
}  // namespace revkit::facts
