#include "toy_program.h"

#include "revkit/facts/storage.h"
#include "revkit/facts/thread_pool.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <thread>
#include <unistd.h>

namespace revkit::facts {
namespace {

namespace fs = std::filesystem;
using namespace toy;

const Provenance kAlice = Provenance::user("alice");

// A fresh directory under the build tree's temp area, removed afterwards.
class TempDir {
 public:
  TempDir() {
    const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
    path_ = fs::temp_directory_path() /
            ("revkit-facts-" + std::to_string(::getpid()) + "-" + info->name());
    fs::remove_all(path_);
  }
  ~TempDir() { fs::remove_all(path_); }
  const fs::path &path() const { return path_; }

 private:
  fs::path path_;
};

class BackendTest : public ::testing::TestWithParam<bool> {
 protected:
  std::unique_ptr<Storage> open() {
    return GetParam() ? open_lmdb_storage(dir_.path()) : make_memory_storage();
  }
  TempDir dir_;
};

TEST_P(BackendTest, GetPutScanDelete) {
  auto s = open();
  EXPECT_FALSE(s->get(Table::Meta, "x"));
  WriteBatch b;
  b.put(Table::Meta, "x", "1");
  b.put(Table::Log, "a1", "first");
  b.put(Table::Log, "a2", "second");
  b.put(Table::Log, "b1", "other");
  b.put(Table::Derived, "a1", "not a log entry");
  s->write(b);
  EXPECT_EQ(s->get(Table::Meta, "x"), "1");
  EXPECT_FALSE(s->get(Table::Log, "x"));

  std::vector<std::string> seen;
  s->scan(Table::Log, "a", [&](std::string_view k, std::string_view v) {
    seen.push_back(std::string(k) + "=" + std::string(v));
    return true;
  });
  EXPECT_EQ(seen, (std::vector<std::string>{"a1=first", "a2=second"}));
  seen.clear();
  s->scan(Table::Log, "", [&](std::string_view k, std::string_view) {
    seen.emplace_back(k);
    return seen.size() < 2;  // stop early
  });
  EXPECT_EQ(seen.size(), 2u);

  WriteBatch d;
  d.erase(Table::Log, "a1");
  d.erase(Table::Log, "nope");
  d.put(Table::Meta, "x", "2");
  s->write(d);
  EXPECT_FALSE(s->get(Table::Log, "a1"));
  EXPECT_EQ(s->get(Table::Meta, "x"), "2");
  StorageStats st = s->stats();
  EXPECT_EQ(st.entries[static_cast<int>(Table::Log)], 2u);
  // Binary keys and values survive.
  std::string bin("\0\x01\xff", 3);
  WriteBatch e;
  e.put(Table::Bytes, bin, bin + bin);
  s->write(e);
  EXPECT_EQ(s->get(Table::Bytes, bin), bin + bin);
}

TEST_P(BackendTest, ConcurrentWritersAndReaders) {
  auto s = open();
  std::vector<std::thread> threads;
  for (int t = 0; t < 4; ++t) {
    threads.emplace_back([&, t] {
      for (int i = 0; i < 200; ++i) {
        WriteBatch b;
        b.put(Table::Derived, std::to_string(t) + ":" + std::to_string(i), std::string(64, 'x'));
        s->write(b);
        s->get(Table::Derived, std::to_string((t + 1) % 4) + ":" + std::to_string(i));
      }
    });
  }
  for (auto &t : threads) t.join();
  EXPECT_EQ(s->stats().entries[static_cast<int>(Table::Derived)], 800u);
}

INSTANTIATE_TEST_SUITE_P(Backends, BackendTest, ::testing::Values(false, true),
                         [](const auto &info) { return info.param ? "Lmdb" : "Memory"; });

TEST(LmdbStorage, PersistsAcrossReopen) {
  TempDir dir;
  {
    auto s = open_lmdb_storage(dir.path());
    WriteBatch b;
    b.put(Table::Meta, "k", "v");
    s->write(b);
  }
  auto s = open_lmdb_storage(dir.path());
  EXPECT_EQ(s->get(Table::Meta, "k"), "v");
  EXPECT_GT(s->stats().file_bytes, 0u);
}

ProgramSpec spec() {
  ProgramSpec p;
  p.functions = 300;
  p.insns_per_function = 30;
  p.globals = 32;
  p.structs = 5;
  p.seed = 11;
  p.functions_per_commit = 100;
  return p;
}

std::unique_ptr<FactDb> open_db(const fs::path &dir, std::size_t budget = SIZE_MAX) {
  FactDbOptions o;
  o.storage = open_lmdb_storage(dir);
  o.memo_budget = budget;
  auto db = std::make_unique<FactDb>(std::move(o));
  register_queries(db->engine());
  return db;
}

TEST(FactDbOnDisk, RoundTripsLogBytesAndDerivedFacts) {
  TempDir dir;
  Program prog;
  std::vector<std::string> summaries;
  Blame blame_before;
  Revision rev_before = 0;
  FactKey renamed = FactKey::name(Address{1, 0x400000});
  {
    auto db = open_db(dir.path());
    prog = generate(*db, spec());
    auto tx = db->begin();
    Seq a = tx.assert_fact(kAlice, renamed, "main");
    tx.assert_fact(Provenance::agent("m", "1"), renamed, "entry");
    tx.retract(kAlice, a);
    tx.assert_fact(kAlice, renamed, "real_main");
    tx.commit();
    blame_before = db->log().blame(renamed);
    for (auto &s : db->snapshot().get_all<FunctionSummary>(prog.functions, nullptr))
      summaries.push_back(*s);
    db->engine().flush();
    rev_before = db->engine().revision();
  }

  auto db = open_db(dir.path());
  EXPECT_GT(db->engine().revision(), rev_before);
  EXPECT_EQ(db->log().size(), prog.assertions + 4);
  Blame b = db->log().blame(renamed);
  EXPECT_EQ(b.value, FactValue("real_main"));
  ASSERT_EQ(b.candidates.size(), blame_before.candidates.size());
  for (std::size_t i = 0; i < b.candidates.size(); ++i) {
    EXPECT_EQ(b.candidates[i].op, blame_before.candidates[i].op);
    EXPECT_EQ(b.candidates[i].status, blame_before.candidates[i].status);
  }

  // Derived facts come back from disk and are re-validated against the
  // reopened inputs by fingerprint instead of being recomputed.
  auto again = db->snapshot().get_all<FunctionSummary>(prog.functions, nullptr);
  for (std::size_t i = 0; i < again.size(); ++i) EXPECT_EQ(*again[i], summaries[i]);
  QueryStats st = db->engine().stats<FunctionSummary>();
  EXPECT_EQ(st.executions, 0u);
  EXPECT_EQ(st.loads, prog.functions.size());
  EXPECT_EQ(db->engine().stats<DecodeFunction>().executions, 0u);

  // And they still invalidate correctly after the reload.
  {
    auto tx = db->begin();
    tx.assert_fact(kAlice, FactKey::name(prog.functions[1]), "renamed_after_reopen");
    tx.commit();
  }
  db->engine().reset_stats();
  auto third = db->snapshot().get_all<FunctionSummary>(prog.functions, nullptr);
  EXPECT_GT(db->engine().stats<FunctionSummary>().executions, 0u);
  EXPECT_LT(db->engine().stats<FunctionSummary>().executions, 20u);
  EXPECT_NE(third[1]->find("renamed_after_reopen"), std::string::npos);
}

TEST(FactDbOnDisk, MetaAndKeyIndexSurviveReopen) {
  TempDir dir;
  const FactKey c1 = FactKey::comment(Address{1, 0x401000}), c2 = FactKey::comment(Address{1, 0x401008});
  Revision before = 0;
  {
    auto db = open_db(dir.path());
    auto tx = db->begin();
    tx.assert_fact(kAlice, c1, "one", 0, "meta one");
    Seq two = tx.assert_fact(kAlice, c2, "two");
    tx.retract(kAlice, two, "undo");
    before = tx.commit();
  }
  auto db = open_db(dir.path());
  EXPECT_GT(db->engine().revision(), before);
  EXPECT_EQ(db->log().op(1)->meta, "meta one");
  EXPECT_EQ(db->log().op(3)->meta, "undo");
  using Entry = std::pair<std::uint64_t, std::string>;
  EXPECT_EQ(*db->snapshot().get<AssertedKeys>(BucketKey{FactKind::Comment, 1, 0x401000 >> kBucketShift}),
            (std::vector<Entry>{{0x401000, "eol"}}));
  EXPECT_EQ(*db->snapshot().get<LogLength>(0), 3u);
}

TEST(FactDbOnDisk, EqualValueRecomputationIsPersistedWithNewDeps) {
  TempDir dir;
  Program prog;
  {
    auto db = open_db(dir.path());
    prog = generate(*db, spec());
    db->snapshot().get<StructLayout>("S2");
    db->engine().flush();
    // Same layout, new text: the layout reruns with an equal value but a
    // different dependency fingerprint, which must reach disk.
    auto tx = db->begin();
    tx.assert_fact(kAlice, FactKey::type_def("S2"), "f0 : int; f1 : int; f2 : int; f3 : int");
    tx.commit();
    db->snapshot().get<StructLayout>("S2");
    EXPECT_EQ(db->engine().stats<StructLayout>().executions, 2u);
    db->engine().flush();
  }
  auto db = open_db(dir.path());
  db->snapshot().get<StructLayout>("S2");
  EXPECT_EQ(db->engine().stats<StructLayout>().executions, 0u);
  EXPECT_EQ(db->engine().stats<StructLayout>().validations, 1u);
}

struct ReadAll {
  static constexpr std::string_view name = "t.readall";
  static constexpr std::uint32_t version = 1;
  using Key = std::pair<Address, std::uint64_t>;
  using Value = std::string;
  static Value compute(QueryContext &ctx, const Key &k) {
    return read_bytes(ctx, k.first, static_cast<std::size_t>(k.second));
  }
};

TEST(FactDbOnDisk, BytesSurviveReopenAcrossChunkBoundaries) {
  TempDir dir;
  std::string blob(3 * kPageSize * 16 + 123, '\0');
  for (std::size_t i = 0; i < blob.size(); ++i) blob[i] = static_cast<char>(i * 7 + 3);
  const Address at{1, 0x10000 - 100};
  {
    auto db = open_db(dir.path());
    auto tx = db->begin();
    tx.write_bytes(at, blob);
    tx.commit();
    auto tx2 = db->begin();
    tx2.write_bytes(Address{1, 0x10000 + 5}, "patched");
    tx2.commit();
  }
  blob.replace(105, 7, "patched");
  auto db = open_db(dir.path());
  db->engine().add_query<ReadAll>();
  EXPECT_EQ(*db->snapshot().get<ReadAll>({at, blob.size()}), blob);
  // Unmapped memory before the write reads as absent.
  EXPECT_EQ(*db->snapshot().get<ReadAll>({Address{1, 0}, 16}), "");
}

TEST(FactDbOnDisk, SmallMemoBudgetSpillsAndStaysCorrect) {
  TempDir ref_dir, dir;
  std::vector<std::string> expected;
  {
    FactDb ref;
    register_queries(ref.engine());
    Program p = generate(ref, spec());
    for (auto &s : ref.snapshot().get_all<FunctionSummary>(p.functions, nullptr)) expected.push_back(*s);
  }
  auto db = open_db(dir.path(), 64 << 10);
  Program prog = generate(*db, spec());
  ThreadPool pool(4);
  for (int round = 0; round < 2; ++round) {
    auto got = db->snapshot().get_all<FunctionSummary>(prog.functions, &pool);
    for (std::size_t i = 0; i < got.size(); ++i) ASSERT_EQ(*got[i], expected[i]) << i;
  }
  EXPECT_GT(db->engine().stats<DecodeFunction>().evictions, 0u);
  EXPECT_GT(db->engine().stats<FunctionSummary>().loads, 0u);
  EXPECT_LE(db->engine().resident_bytes(), std::size_t{64 << 10} + (32 << 10));
  EXPECT_GT(db->storage().stats().entries[static_cast<int>(Table::Derived)], 0u);
}

// Same name as DecodeFunction, new version: persisted memos must be ignored.
struct DecodeFunctionV2 {
  static constexpr std::string_view name = DecodeFunction::name;
  static constexpr std::uint32_t version = DecodeFunction::version + 1;
  using Key = Address;
  using Value = InsnList;
  static Value compute(QueryContext &ctx, const Key &k) { return DecodeFunction::compute(ctx, k); }
};

TEST(FactDbOnDisk, RuleVersionChangeDiscardsPersistedMemos) {
  TempDir dir;
  Program prog;
  {
    auto db = open_db(dir.path());
    prog = generate(*db, spec());
    db->snapshot().get_all<DecodeFunction>(prog.functions, nullptr);
    db->engine().flush();
  }
  FactDbOptions o;
  o.storage = open_lmdb_storage(dir.path());
  FactDb db(std::move(o));
  db.engine().add_query<DecodeFunctionV2>();
  db.snapshot().get_all<DecodeFunctionV2>(prog.functions, nullptr);
  EXPECT_EQ(db.engine().stats<DecodeFunctionV2>().executions, prog.functions.size());
}

// A rule whose values can't be stored (persistent = false): computed again
// in each process, never written or read back; its dependents still load.
struct DecodeFunctionHere {
  static constexpr std::string_view name = "toy.decode.here";
  static constexpr std::uint32_t version = 1;
  static constexpr bool persistent = false;
  using Key = Address;
  using Value = InsnList;
  static Value compute(QueryContext &ctx, const Key &k) { return DecodeFunction::compute(ctx, k); }
};

TEST(FactDbOnDisk, NonPersistentRulesAreComputedInEachProcess) {
  TempDir dir;
  Program prog;
  std::uint64_t derived = 0;
  {
    auto db = open_db(dir.path());
    db->engine().add_query<DecodeFunctionHere>();
    prog = generate(*db, spec());
    db->snapshot().get_all<DecodeFunctionHere>(prog.functions, nullptr);
    db->snapshot().get_all<DecodeFunction>(prog.functions, nullptr);
    db->engine().flush();
    derived = db->storage().stats().entries[static_cast<int>(Table::Derived)];
  }
  auto db = open_db(dir.path());
  db->engine().add_query<DecodeFunctionHere>();
  generate(*db, spec());
  db->snapshot().get_all<DecodeFunctionHere>(prog.functions, nullptr);
  db->snapshot().get_all<DecodeFunction>(prog.functions, nullptr);
  EXPECT_EQ(db->engine().stats<DecodeFunctionHere>().executions, prog.functions.size());
  EXPECT_EQ(db->engine().stats<DecodeFunctionHere>().loads, 0u);
  EXPECT_EQ(db->engine().stats<DecodeFunction>().loads, prog.functions.size());
  db->engine().flush();
  EXPECT_EQ(db->storage().stats().entries[static_cast<int>(Table::Derived)], derived);
}

TEST(FactDbOnDisk, CorruptMemoRecordIsRecomputed) {
  TempDir dir;
  Program prog;
  {
    auto db = open_db(dir.path());
    prog = generate(*db, spec());
    db->snapshot().get_all<FunctionSummary>(prog.functions, nullptr);
    db->engine().flush();
    // Truncate every derived record.
    WriteBatch b;
    db->storage().scan(Table::Derived, "", [&](std::string_view k, std::string_view v) {
      b.put(Table::Derived, std::string(k), std::string(v.substr(0, v.size() / 2)));
      return true;
    });
    db->storage().write(b);
  }
  auto db = open_db(dir.path());
  auto got = db->snapshot().get_all<FunctionSummary>(prog.functions, nullptr);
  EXPECT_EQ(db->engine().stats<FunctionSummary>().executions, prog.functions.size());
  EXPECT_NE(got[0]->find("() {"), std::string::npos);
}

}  // namespace
}  // namespace revkit::facts
