#include "revkit/facts/engine.h"
#include "revkit/facts/thread_pool.h"

#include <gtest/gtest.h>

#include <chrono>
#include <thread>

namespace revkit::facts {
namespace {

struct Num {
  static constexpr std::string_view name = "t.num";
  using Key = std::string;
  using Value = std::int64_t;
};

struct Double {
  static constexpr std::string_view name = "t.double";
  static constexpr std::uint32_t version = 1;
  using Key = std::string;
  using Value = std::int64_t;
  static Value compute(QueryContext &ctx, const Key &k) { return 2 * *ctx.get<Num>(k); }
};

struct Parity {
  static constexpr std::string_view name = "t.parity";
  static constexpr std::uint32_t version = 1;
  using Key = std::string;
  using Value = std::int64_t;
  static Value compute(QueryContext &ctx, const Key &k) { return *ctx.get<Num>(k) & 1; }
};

struct Label {
  static constexpr std::string_view name = "t.label";
  static constexpr std::uint32_t version = 3;
  using Key = std::string;
  using Value = std::string;
  static Value compute(QueryContext &ctx, const Key &k) {
    if (*ctx.get<Parity>(k)) {
      ctx.set_confidence(Confidence::Likely);
      return "odd";
    }
    return "even";
  }
};

// Sum of Num over a comma-separated key list.
struct Sum {
  static constexpr std::string_view name = "t.sum";
  static constexpr std::uint32_t version = 1;
  using Key = std::string;
  using Value = std::int64_t;
  static Value compute(QueryContext &ctx, const Key &keys) {
    std::int64_t total = 0;
    std::size_t start = 0;
    while (start <= keys.size()) {
      std::size_t comma = keys.find(',', start);
      if (comma == std::string::npos) comma = keys.size();
      total += *ctx.get<Num>(keys.substr(start, comma - start));
      start = comma + 1;
    }
    return total;
  }
};

// Ring of n queries, each reading the next.
struct Ring {
  static constexpr std::string_view name = "t.ring";
  static constexpr std::uint32_t version = 1;
  using Key = std::pair<std::uint32_t, std::uint32_t>;  // (i, n)
  using Value = std::int64_t;
  static Value compute(QueryContext &ctx, const Key &k) {
    return 1 + *ctx.get<Ring>({(k.first + 1) % k.second, k.second});
  }
};

// Recovers from a cycle with a provisional value: the fixpoint hook.
struct Guarded {
  static constexpr std::string_view name = "t.guarded";
  static constexpr std::uint32_t version = 1;
  using Key = std::uint32_t;
  using Value = std::int64_t;
  static Value compute(QueryContext &ctx, const Key &k);
};
struct GuardedPeer {
  static constexpr std::string_view name = "t.guarded_peer";
  static constexpr std::uint32_t version = 1;
  using Key = std::uint32_t;
  using Value = std::int64_t;
  static Value compute(QueryContext &ctx, const Key &k) { return 10 + *ctx.get<Guarded>(k); }
};
Guarded::Value Guarded::compute(QueryContext &ctx, const Key &k) {
  try {
    return 1 + *ctx.get<GuardedPeer>(k);
  } catch (const CycleError &) {
    return -1;
  }
}

// Two queries that read each other, each first waiting until both threads
// are inside a computation, to force the cross-thread cycle.
std::atomic<int> g_entered{0};
struct Ping {
  static constexpr std::string_view name = "t.ping";
  static constexpr std::uint32_t version = 1;
  using Key = std::uint32_t;
  using Value = std::int64_t;
  static Value compute(QueryContext &ctx, const Key &k) {
    g_entered.fetch_add(1);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (g_entered.load() < 2 && std::chrono::steady_clock::now() < deadline)
      std::this_thread::yield();
    return *ctx.get<Ping>(1 - k);
  }
};

class EngineTest : public ::testing::Test {
 protected:
  EngineTest() {
    e_.add_input<Num>();
    e_.add_query<Double>();
    e_.add_query<Parity>();
    e_.add_query<Label>();
    e_.add_query<Sum>();
    e_.add_query<Ring>();
    e_.add_query<Guarded>();
    e_.add_query<GuardedPeer>();
    e_.add_query<Ping>();
  }
  Revision set(std::initializer_list<std::pair<std::string, std::int64_t>> kv) {
    auto w = e_.begin_write();
    for (const auto &[k, v] : kv) w.set<Num>(k, v);
    return w.commit();
  }
  Engine e_;
};

TEST_F(EngineTest, Memoizes) {
  set({{"a", 21}});
  auto s = e_.snapshot();
  EXPECT_EQ(*s.get<Double>("a"), 42);
  EXPECT_EQ(*s.get<Double>("a"), 42);
  EXPECT_EQ(*e_.snapshot().get<Double>("a"), 42);
  QueryStats st = e_.stats<Double>();
  EXPECT_EQ(st.executions, 1u);
  EXPECT_EQ(st.hits, 2u);
  // Unset inputs read as their default.
  EXPECT_EQ(*s.get<Double>("missing"), 0);
}

TEST_F(EngineTest, InvalidatesOnlyWhatReadTheChangedInput) {
  set({{"a", 1}, {"b", 2}});
  e_.snapshot().get<Double>("a");
  e_.snapshot().get<Double>("b");
  e_.snapshot().get<Sum>("a,b");
  e_.reset_stats();

  set({{"a", 5}});
  auto s = e_.snapshot();
  EXPECT_EQ(*s.get<Double>("a"), 10);
  EXPECT_EQ(*s.get<Double>("b"), 4);
  EXPECT_EQ(*s.get<Sum>("a,b"), 7);
  EXPECT_EQ(e_.stats<Double>().executions, 1u);   // a
  EXPECT_EQ(e_.stats<Double>().validations, 1u);  // b: checked, not rerun
  EXPECT_EQ(e_.stats<Sum>().executions, 1u);
}

TEST_F(EngineTest, EarlyCutoffStopsAtUnchangedValues) {
  set({{"a", 2}});
  EXPECT_EQ(*e_.snapshot().get<Label>("a"), "even");
  e_.reset_stats();

  set({{"a", 4}});  // parity is still even
  EXPECT_EQ(*e_.snapshot().get<Label>("a"), "even");
  EXPECT_EQ(e_.stats<Parity>().executions, 1u);
  EXPECT_EQ(e_.stats<Label>().executions, 0u);
  EXPECT_EQ(e_.stats<Label>().validations, 1u);

  set({{"a", 7}});
  EXPECT_EQ(*e_.snapshot().get<Label>("a"), "odd");
  EXPECT_EQ(e_.stats<Label>().executions, 1u);
}

TEST_F(EngineTest, SettingAnEqualValueDoesNotAdvanceTheRevision) {
  Revision r = set({{"a", 3}});
  EXPECT_EQ(set({{"a", 3}}), r);
  EXPECT_EQ(set({{"a", 4}}), r + 1);
}

TEST_F(EngineTest, DerivedFactsCarryRuleVersionInputsAndConfidence) {
  set({{"a", 3}});
  auto f = e_.snapshot().fact<Label>("a");
  EXPECT_EQ(*f.value, "odd");
  EXPECT_EQ(f.rule, "t.label");
  EXPECT_EQ(f.rule_version, 3u);
  EXPECT_EQ(f.confidence, Confidence::Likely);
  EXPECT_EQ(f.inputs, std::vector<std::string>{"t.parity(a)"});
  EXPECT_EQ(e_.snapshot().fact<Parity>("a").inputs, std::vector<std::string>{"t.num(a)"});
}

TEST_F(EngineTest, DetectsCycles) {
  try {
    e_.snapshot().get<Ring>({0, 3});
    FAIL() << "expected a cycle";
  } catch (const CycleError &err) {
    EXPECT_EQ(err.path.size(), 4u);
    EXPECT_EQ(err.path.front(), err.path.back());
  }
  EXPECT_THROW(e_.snapshot().get<Ring>({0, 1}), CycleError);  // self-loop
  // Nothing is left claimed: the same keys fail the same way again.
  EXPECT_THROW(e_.snapshot().get<Ring>({1, 3}), CycleError);
}

TEST_F(EngineTest, CycleRecoveryIsProvisionalAndNotMemoized) {
  // Guarded -> GuardedPeer -> Guarded: the inner read fails, the error
  // unwinds through GuardedPeer, and the outer Guarded falls back.
  auto f = e_.snapshot().fact<Guarded>(7);
  EXPECT_EQ(*f.value, -1);
  EXPECT_EQ(f.confidence, Confidence::Uncertain);
  EXPECT_EQ(*e_.snapshot().get<Guarded>(7), -1);
  EXPECT_EQ(e_.stats<Guarded>().executions, 2u);  // recomputed, not memoized
  EXPECT_EQ(e_.stats<Guarded>().hits, 0u);
}

TEST_F(EngineTest, DetectsCyclesAcrossThreads) {
  g_entered = 0;
  std::atomic<int> cycles{0};
  auto run = [&](std::uint32_t k) {
    try {
      e_.snapshot().get<Ping>(k);
    } catch (const CycleError &) {
      cycles.fetch_add(1);
    }
  };
  std::thread a(run, 0), b(run, 1);
  a.join();
  b.join();
  EXPECT_EQ(cycles.load(), 2);
}

TEST_F(EngineTest, SnapshotsAreIsolatedFromLaterRevisions) {
  set({{"a", 1}, {"b", 1}});
  Snapshot s1 = e_.snapshot();
  EXPECT_EQ(*s1.get<Double>("a"), 2);

  Revision r2;
  {
    auto w = e_.begin_write();
    w.set<Num>("a", 50);
    // Staged changes are invisible until commit, to old and new snapshots.
    EXPECT_EQ(*e_.snapshot().get<Double>("a"), 2);
    EXPECT_EQ(*w.latest<Num>("a"), 50);
    r2 = w.commit();
  }

  Snapshot s2 = e_.snapshot();
  EXPECT_EQ(s2.revision(), r2);
  EXPECT_EQ(*s2.get<Double>("a"), 100);
  EXPECT_EQ(*s1.get<Double>("a"), 2);
  // A first read of a query on the old snapshot, after the commit, sees
  // the old inputs too.
  EXPECT_EQ(*s1.get<Sum>("a,b"), 2);
  EXPECT_EQ(*s2.get<Sum>("a,b"), 51);

  // Many commits and a GC later the pinned snapshot still reads its revision.
  for (int i = 0; i < 20; ++i) {
    auto w2 = e_.begin_write();
    w2.set<Num>("a", 1000 + i);
    w2.set<Num>("b", -i);
    w2.commit();
    e_.collect_garbage();
  }
  EXPECT_EQ(*s1.get<Sum>("a,b"), 2);
  EXPECT_EQ(*s1.get<Label>("b"), "odd");
  EXPECT_EQ(*s2.get<Label>("b"), "odd");
  EXPECT_EQ(*e_.snapshot().get<Sum>("a,b"), 1019 - 19);
}

TEST_F(EngineTest, ReadersSeeConsistentRevisionsWhileWriterCommits) {
  set({{"a", 0}, {"b", 100}});
  std::atomic<bool> stop{false};
  std::atomic<int> bad{0}, reads{0};
  std::vector<std::thread> readers;
  for (int t = 0; t < 4; ++t) {
    readers.emplace_back([&] {
      while (!stop.load()) {
        Snapshot s = e_.snapshot();
        if (*s.get<Sum>("a,b") != 100) bad.fetch_add(1);
        if (*s.get<Num>("a") + *s.get<Num>("b") != 100) bad.fetch_add(1);
        if (*s.get<Double>("a") != 2 * *s.get<Num>("a")) bad.fetch_add(1);
        reads.fetch_add(1);
      }
    });
  }
  for (int i = 1; i <= 300; ++i) {
    set({{"a", i}, {"b", 100 - i}});
    if (i % 50 == 0) e_.collect_garbage();
  }
  while (reads.load() < 100) std::this_thread::yield();
  stop = true;
  for (auto &t : readers) t.join();
  EXPECT_EQ(bad.load(), 0);
  EXPECT_GT(reads.load(), 0);
}

TEST_F(EngineTest, ParallelEvaluationIsDeterministic) {
  {
    auto w = e_.begin_write();
    for (int i = 0; i < 500; ++i) w.set<Num>("k" + std::to_string(i), i * 7919 % 1009);
    w.commit();
  }
  std::vector<std::string> keys;
  for (int i = 0; i < 500; ++i) keys.push_back("k" + std::to_string(i) + ",k" + std::to_string((i * 31) % 500));

  auto reference = e_.snapshot().get_all<Sum>(keys, nullptr);
  for (unsigned threads : {1u, 2u, 4u, 8u}) {
    Engine fresh;
    fresh.add_input<Num>();
    fresh.add_query<Sum>();
    {
      auto w = fresh.begin_write();
      for (int i = 0; i < 500; ++i) w.set<Num>("k" + std::to_string(i), i * 7919 % 1009);
      w.commit();
    }
    ThreadPool pool(threads);
    auto got = fresh.snapshot().get_all<Sum>(keys, &pool);
    ASSERT_EQ(got.size(), reference.size());
    for (std::size_t i = 0; i < got.size(); ++i) EXPECT_EQ(*got[i], *reference[i]) << i;
  }
}

TEST_F(EngineTest, ThreadPoolPropagatesTheLowestIndexError) {
  ThreadPool pool(4);
  std::atomic<int> ran{0};
  try {
    pool.parallel_for(100, [&](std::size_t i) {
      ran.fetch_add(1);
      if (i == 17 || i == 60) throw std::runtime_error(std::to_string(i));
    });
    FAIL();
  } catch (const std::runtime_error &e) {
    EXPECT_STREQ(e.what(), "17");
  }
  EXPECT_EQ(ran.load(), 100);
}

// Sum of Double over k0..k(n-1), read with QueryContext::get_all.
struct SumAll {
  static constexpr std::string_view name = "t.sum_all";
  static constexpr std::uint32_t version = 1;
  using Key = std::uint32_t;
  using Value = std::int64_t;
  static Value compute(QueryContext &ctx, const Key &n) {
    std::vector<std::string> keys;
    for (std::uint32_t i = 0; i < n; ++i) keys.push_back("k" + std::to_string(i));
    std::int64_t total = 0;
    for (const auto &v : ctx.get_all<Double>(keys)) total += *v;
    // Work on values already read may be split too.
    std::vector<std::int64_t> parts(4, 0);
    ctx.parallel_for(parts.size(), [&](std::size_t i) { parts[i] = static_cast<std::int64_t>(i); });
    return total + parts[3];
  }
};

TEST_F(EngineTest, GetAllInsideAQueryRecordsEveryKeyInOrder) {
  for (unsigned threads : {0u, 1u, 3u, 8u}) {
    Engine e;
    e.add_input<Num>();
    e.add_query<Double>();
    e.add_query<SumAll>();
    ThreadPool pool(threads == 0 ? 1 : threads);
    if (threads != 0) e.set_pool(&pool);
    {
      auto w = e.begin_write();
      for (int i = 0; i < 200; ++i) w.set<Num>("k" + std::to_string(i), i);
      w.commit();
    }
    auto f = e.snapshot().fact<SumAll>(200);
    EXPECT_EQ(*f.value, 2 * (199 * 200 / 2) + 3);
    ASSERT_EQ(f.inputs.size(), 200u);
    for (int i = 0; i < 200; ++i) EXPECT_EQ(f.inputs[i], "t.double(k" + std::to_string(i) + ")");
    // A change to one key re-runs the sum and only that Double.
    e.reset_stats();
    {
      auto w = e.begin_write();
      w.set<Num>("k57", 1000);
      w.commit();
    }
    EXPECT_EQ(*e.snapshot().get<SumAll>(200), 2 * (199 * 200 / 2 - 57 + 1000) + 3);
    EXPECT_EQ(e.stats<Double>().executions, 1u);
    EXPECT_EQ(e.stats<SumAll>().executions, 1u);
    e.set_pool(nullptr);
  }
}

TEST_F(EngineTest, NestedParallelForOnOnePoolCompletes) {
  // Every worker runs an outer item that splits its own work on the same
  // pool; helpers queued behind busy workers must not be waited for.
  ThreadPool pool(4);
  std::atomic<int> inner{0};
  for (int round = 0; round < 50; ++round)
    pool.parallel_for(8, [&](std::size_t) {
      pool.parallel_for(16, [&](std::size_t) { inner.fetch_add(1); });
    });
  EXPECT_EQ(inner.load(), 50 * 8 * 16);
}

// Reads through a Snapshot instead of its context, bypassing tracking.
struct Sneaky {
  static constexpr std::string_view name = "t.sneaky";
  static constexpr std::uint32_t version = 1;
  using Key = std::uint32_t;
  using Value = std::int64_t;
  static inline Engine *engine = nullptr;
  static Value compute(QueryContext &, const Key &) { return *engine->snapshot().get<Num>("a"); }
};

TEST_F(EngineTest, SnapshotReadsInsideQueriesAreRejected) {
  Sneaky::engine = &e_;
  e_.add_query<Sneaky>();
  EXPECT_THROW(e_.snapshot().get<Sneaky>(1), std::logic_error);
}

TEST_F(EngineTest, EvictionWithoutStorageRecomputesCorrectly) {
  Engine small(EngineOptions{nullptr, 4096, 0});
  small.add_input<Num>();
  small.add_query<Double>();
  {
    auto w = small.begin_write();
    for (int i = 0; i < 200; ++i) w.set<Num>(std::to_string(i), i);
    w.commit();
  }
  for (int round = 0; round < 2; ++round)
    for (int i = 0; i < 200; ++i) EXPECT_EQ(*small.snapshot().get<Double>(std::to_string(i)), 2 * i);
  EXPECT_GT(small.stats<Double>().evictions, 0u);
  EXPECT_LE(small.resident_bytes(), 4096u + 1024u);
}

}  // namespace
}  // namespace revkit::facts
