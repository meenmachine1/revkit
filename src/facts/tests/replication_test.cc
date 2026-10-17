// Replication of the assertion log (docs/collab.md): op identity, merging
// in any order, and convergence of effective values, blame and history.
//
// The property tests run random histories on several replicas with skewed
// clocks: assertions (single and batched, some depending on others),
// retractions of anything, reverts by provenance, and partial exchanges of
// random subsets in random orders with duplicates. Once every replica has
// every op, all of them (and fresh replicas fed the same ops in other
// orders) must report identical effective values, blame and history.
#include "revkit/facts/fact_db.h"
#include "revkit/facts/storage.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <random>
#include <set>
#include <sstream>

namespace revkit::facts {
namespace {

const Address kA{1, 0x1000}, kB{1, 0x2000};
const Provenance kAlice = Provenance::user("alice");
const Provenance kBob = Provenance::user("bob");
const Provenance kDwarf = Provenance::import("dwarf");
const Provenance kModel1 = Provenance::agent("model", "1");
const Provenance kModel2 = Provenance::agent("model", "2");
const Provenance kAuto = Provenance::analysis("auto");

// A replica with its own (skewable) clock.
struct Replica {
  Replica(ReplicaId id, std::int64_t skew_ns = 0) : clock(std::make_shared<std::int64_t>(1'000'000'000'000 + skew_ns)) {
    FactDbOptions o;
    o.replica = id;
    o.clock = [c = clock] { return *c += 1'000'000; };  // 1 ms per reading
    db = std::make_unique<FactDb>(std::move(o));
  }
  std::shared_ptr<std::int64_t> clock;
  std::unique_ptr<FactDb> db;

  Seq put(const Provenance &who, const FactKey &k, FactValue v, Seq dep = 0) {
    auto tx = db->begin();
    Seq s = tx.assert_fact(who, k, std::move(v), dep);
    tx.commit();
    return s;
  }
  Seq retract(const Provenance &who, Seq target) {
    auto tx = db->begin();
    Seq s = tx.retract(who, target);
    tx.commit();
    return s;
  }
  MergeResult merge(std::span<const Op> ops) {
    auto tx = db->begin();
    MergeResult r = tx.merge(ops);
    tx.commit();
    return r;
  }
  // Everything `from` has that this replica lacks.
  void pull(const Replica &from) { merge(from.db->ops_since(db->version_vector())); }
  FactValue eff(const FactKey &k) const { return db->log().effective(k); }
  OpId id(Seq s) const { return db->log().op(s)->id; }
};

std::string text(const FactValue &v) {
  std::ostringstream os;
  std::visit(
      [&](const auto &x) {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, std::monostate>) os << "-";
        else if constexpr (std::is_same_v<T, std::int64_t>) os << x;
        else if constexpr (std::is_same_v<T, std::string>) os << '"' << x << '"';
        else if constexpr (std::is_same_v<T, Address>) os << x.space << ":" << x.offset;
        else
          for (const AddressRange &r : x.ranges()) os << "[" << r.first.offset << "," << r.last.offset << "]";
      },
      v);
  return os.str();
}

// Everything a replica reports about its keys, in terms every replica
// shares: op ids, never local seqs. Also checks the engine agrees with the
// log.
std::string dump(const FactDb &db_const, const std::set<FactKey> &keys) {
  FactDb &db = const_cast<FactDb &>(db_const);
  const AssertionLog &log = db.log();
  auto id = [&](Seq s) { return log.op(s)->id.str(); };
  Snapshot snap = db.snapshot();
  std::ostringstream os;
  for (const FactKey &k : keys) {
    const FactValue eff = log.effective(k);
    EXPECT_EQ(*snap.get<AssertedFact>(k), eff) << AssertedFact::describe(k);
    Blame b = log.blame(k);
    os << AssertedFact::describe(k) << " = " << text(eff) << "\n";
    os << "  winner " << (b.winner ? b.winner->id.str() : "-") << "\n";
    for (const BlameEntry &e : b.candidates) {
      os << "  " << e.op.id.str() << " " << e.op.prov.str() << " " << text(e.op.value) << " " << to_string(e.status);
      for (Seq r : e.retracted_by) os << " by:" << id(r);
      os << " sup:" << (e.op.supersedes ? e.op.supersedes.str() : "-") << "\n";
    }
    for (Seq s : b.concurrent) os << "  concurrent " << id(s) << "\n";
    os << "  history";
    for (const Op &op : log.history(k)) os << " " << op.id.str();
    os << "\n";
  }
  return os.str();
}

std::set<FactKey> all_keys(const std::vector<const FactDb *> &dbs) {
  std::set<FactKey> keys;
  for (const FactDb *db : dbs)
    for (const FactKey &k : db->log().keys()) keys.insert(k);
  return keys;
}

// --- Deterministic cases --------------------------------------------------

TEST(Replication, OpsCarryGlobalIdsAndStamps) {
  Replica a(0xa);
  Seq s1 = a.put(kAlice, FactKey::name(kA), "x");
  auto tx = a.db->begin();
  Seq s2 = tx.assert_fact(kAlice, FactKey::name(kB), "y");
  Seq s3 = tx.assert_fact(kBob, FactKey::comment(kB), "z", s2);
  tx.commit();
  Seq s4 = a.retract(kBob, s1);
  const AssertionLog &log = a.db->log();
  EXPECT_EQ(log.op(s1)->id, (OpId{0xa, 1}));
  EXPECT_EQ(log.op(s3)->id, (OpId{0xa, 3}));
  EXPECT_EQ(log.op(s3)->depends_on_id, (OpId{0xa, 2}));
  EXPECT_EQ(log.op(s4)->target_id, (OpId{0xa, 1}));
  // One stamp per transaction, increasing across transactions.
  EXPECT_EQ(log.op(s2)->stamp, log.op(s3)->stamp);
  EXPECT_LT(log.op(s1)->stamp, log.op(s2)->stamp);
  EXPECT_LT(log.op(s3)->stamp, log.op(s4)->stamp);
  EXPECT_EQ(a.db->version_vector(), (VersionVector{{0xa, 4}}));
  EXPECT_EQ(OpId::parse(log.op(s3)->id.str()), log.op(s3)->id);
  EXPECT_EQ(log.op(s3)->id.str(), "000000000000000a.3");
}

TEST(Replication, EncodingRoundTripsReplicationFields) {
  Replica a(0x1234);
  Seq s1 = a.put(kAlice, FactKey::name(kA), "x");
  Seq s2 = a.retract(kBob, s1);
  for (Seq s : {s1, s2}) {
    Op op = *a.db->log().op(s);
    EXPECT_EQ(decode_from_string<Op>(encode_to_string(op)), op);
  }
}

TEST(Replication, MergeIsIdempotentAndOrderFree) {
  Replica a(1), b(2), c(3);
  Seq x = a.put(kAlice, FactKey::name(kA), "a1");
  a.put(kModel1, FactKey::name(kA), "agent");
  Seq r = a.retract(kAlice, x);
  auto ops = a.db->ops_since({});
  // b: in order, twice. c: reversed, so everything waits for the first op.
  b.merge(ops);
  EXPECT_EQ(b.merge(ops).duplicate, ops.size());
  std::vector<Op> reversed(ops.rbegin(), ops.rend());
  MergeResult partial = c.merge(std::span(reversed).first(2));
  EXPECT_EQ(partial.staged, 0u);
  EXPECT_EQ(c.db->waiting(), 2u);
  EXPECT_EQ(c.merge(std::span(reversed).subspan(2)).staged, 3u);
  EXPECT_EQ(c.db->waiting(), 0u);
  for (Replica *p : {&b, &c}) {
    EXPECT_EQ(p->eff(FactKey::name(kA)), FactValue("agent"));
    EXPECT_TRUE(p->db->log().retracted(*p->db->log().find(a.id(x))));
    EXPECT_EQ(p->db->log().op(*p->db->log().find(a.id(r)))->target, *p->db->log().find(a.id(x)));
  }
  EXPECT_EQ(dump(*b.db, all_keys({b.db.get()})), dump(*c.db, all_keys({c.db.get()})));
  EXPECT_EQ(dump(*a.db, all_keys({a.db.get()})), dump(*c.db, all_keys({c.db.get()})));
}

TEST(Replication, ConcurrentEqualStampsBreakTiesByReplica) {
  // Same physical clock: equal stamps, so the replica id decides, alike
  // on both sides.
  Replica a(0x10), b(0x20);
  a.put(kAlice, FactKey::name(kA), "from-a");
  b.put(kBob, FactKey::name(kA), "from-b");
  ASSERT_EQ(a.db->log().op(1)->stamp, b.db->log().op(1)->stamp);
  a.pull(b);
  b.pull(a);
  EXPECT_EQ(a.eff(FactKey::name(kA)), FactValue("from-b"));
  EXPECT_EQ(b.eff(FactKey::name(kA)), FactValue("from-b"));
  // The loser stays, shadowed, and is reported as concurrent.
  Blame bl = a.db->log().blame(FactKey::name(kA));
  ASSERT_EQ(bl.candidates.size(), 2u);
  EXPECT_EQ(bl.candidates[1].status, OpStatus::Shadowed);
  ASSERT_EQ(bl.concurrent.size(), 1u);
  EXPECT_EQ(a.db->log().op(bl.concurrent[0])->value, FactValue("from-a"));
}

TEST(Replication, RankBeatsRecencyAcrossReplicas) {
  Replica a(1), b(2, 3'600'000'000'000);  // b's clock is an hour ahead
  a.put(kAlice, FactKey::name(kA), "user");
  b.put(kModel1, FactKey::name(kA), "agent");
  a.pull(b);
  b.pull(a);
  EXPECT_EQ(a.eff(FactKey::name(kA)), FactValue("user"));
  EXPECT_EQ(b.eff(FactKey::name(kA)), FactValue("user"));
}

TEST(Replication, PluginsRankWithAgentsAcrossReplicas) {
  // A command plugin's edit (docs/plugins.md) replicates with its kind and
  // competes with agents on recency; users still win and analysis loses.
  const Provenance plugin{ProvenanceKind::Plugin, "rename-regex", "1.0.0"};
  Replica a(1), b(2, 3'600'000'000'000);  // b's clock is an hour ahead
  a.put(kModel1, FactKey::name(kA), "agent");
  b.put(plugin, FactKey::name(kA), "plugin");
  a.put(kAuto, FactKey::name(kB), "auto");
  b.put(plugin, FactKey::name(kB), "plugin");
  a.pull(b);
  b.pull(a);
  for (const Replica *r : {&a, &b}) {
    EXPECT_EQ(r->eff(FactKey::name(kA)), FactValue("plugin"));  // same rank, later stamp
    EXPECT_EQ(r->eff(FactKey::name(kB)), FactValue("plugin"));  // outranks analysis
  }
  EXPECT_EQ(a.db->log().blame(FactKey::name(kA)).winner->prov, plugin);
  // The agent, causally later, takes it back; a user beats both.
  a.put(kModel2, FactKey::name(kA), "agent again");
  b.pull(a);
  EXPECT_EQ(b.eff(FactKey::name(kA)), FactValue("agent again"));
  b.put(kAlice, FactKey::name(kB), "user");
  a.put(plugin, FactKey::name(kB), "plugin again");
  a.pull(b);
  b.pull(a);
  EXPECT_EQ(a.eff(FactKey::name(kB)), FactValue("user"));
  EXPECT_EQ(b.eff(FactKey::name(kB)), FactValue("user"));
}

TEST(Replication, CausallyLaterEditWinsDespiteASlowClock) {
  Replica fast(1, 3'600'000'000'000), slow(2);
  fast.put(kAlice, FactKey::name(kA), "first");
  slow.pull(fast);
  // slow saw "first", so its edit is stamped after it, even though its
  // wall clock is an hour behind.
  slow.put(kBob, FactKey::name(kA), "second");
  fast.pull(slow);
  EXPECT_EQ(fast.eff(FactKey::name(kA)), FactValue("second"));
  EXPECT_EQ(slow.eff(FactKey::name(kA)), FactValue("second"));
  // Sequential, not concurrent: bob saw alice's value.
  EXPECT_TRUE(fast.db->log().blame(FactKey::name(kA)).concurrent.empty());
}

// An op stamped UINT64_MAX (a crafted archive or a broken peer) wrapped
// the hybrid clock to 0: every later local edit sorted before it and lost.
// The clock saturates instead, so an edit made after it still wins.
TEST(Replication, TheClockSaturatesInsteadOfWrapping) {
  Replica a(1), b(2);
  a.put(kAlice, FactKey::name(kA), "first");
  auto ops = a.db->ops_since(b.db->version_vector());
  ASSERT_EQ(ops.size(), 1u);
  ops[0].stamp = UINT64_MAX;
  ASSERT_EQ(b.merge(ops).staged, 1u);
  b.put(kAlice, FactKey::name(kA), "later");
  EXPECT_EQ(b.eff(FactKey::name(kA)), FactValue("later"));
}

TEST(Replication, TransactionsWinOrLoseAsAUnit) {
  // Two concurrent batches touching the same keys at the same rank: one
  // batch wins every key, so a multi-key edit is never torn.
  for (int run = 0; run < 2; ++run) {
    Replica a(run ? 1 : 2), b(run ? 2 : 1);
    for (Replica *r : {&a, &b}) {
      auto tx = r->db->begin();
      std::string tag = r == &a ? "a" : "b";
      tx.assert_fact(kAlice, FactKey::type(kA), "h:" + tag);
      tx.assert_fact(kAlice, FactKey::type(kB), "h:" + tag);
      tx.assert_fact(kAlice, FactKey::type_def("s"), tag);
      tx.commit();
    }
    a.pull(b);
    b.pull(a);
    for (Replica *r : {&a, &b}) {
      FactValue first = r->eff(FactKey::type(kA));
      EXPECT_EQ(r->eff(FactKey::type(kB)), first);
      EXPECT_EQ(r->eff(FactKey::type_def("s")), FactValue(std::get<std::string>(first).substr(2)));
    }
  }
}

TEST(Replication, RetractionArrivingBeforeItsTargetWaits) {
  Replica a(1), b(2), c(3);
  Seq x = a.put(kAlice, FactKey::name(kA), "x");
  b.pull(a);
  Seq bx = *b.db->log().find(a.id(x));
  b.retract(kBob, bx);
  // c hears from b first: the retraction waits for its target.
  auto from_b = b.db->ops_since(a.db->version_vector());
  ASSERT_EQ(from_b.size(), 1u);
  EXPECT_EQ(c.merge(from_b).staged, 0u);
  EXPECT_EQ(c.db->waiting(), 1u);
  EXPECT_EQ(c.eff(FactKey::name(kA)), FactValue{});
  c.pull(a);
  EXPECT_EQ(c.db->waiting(), 0u);
  EXPECT_EQ(c.eff(FactKey::name(kA)), FactValue{});
  EXPECT_EQ(c.db->log().size(), 2u);
}

TEST(Replication, RevertRetractsTheAuthorsRetractionsOnEveryReplica) {
  Replica a(1), b(2);
  Seq user = a.put(kAlice, FactKey::name(kA), "alices");
  b.pull(a);
  // The agent, on b, removes alice's name and names another function.
  b.retract(kModel1, *b.db->log().find(a.id(user)));
  b.put(kModel1, FactKey::name(kB), "agents");
  a.pull(b);
  EXPECT_EQ(a.eff(FactKey::name(kA)), FactValue{});
  // A reviewer on a reverts the agent: its retraction is retracted too,
  // so alice's name comes back, everywhere.
  {
    auto tx = a.db->begin();
    EXPECT_EQ(tx.revert(kAlice, Provenance::agent("model")).size(), 2u);
    tx.commit();
  }
  b.pull(a);
  for (Replica *r : {&a, &b}) {
    EXPECT_EQ(r->eff(FactKey::name(kA)), FactValue("alices"));
    EXPECT_EQ(r->eff(FactKey::name(kB)), FactValue{});
  }
  EXPECT_EQ(dump(*a.db, all_keys({a.db.get()})), dump(*b.db, all_keys({b.db.get()})));
}

TEST(Replication, RevertCoversWhatTheRevertingReplicaHeld) {
  // Documented semantics: a revert retracts the author's ops its replica
  // held; an op the author made concurrently elsewhere survives it.
  Replica a(1), b(2);
  a.put(kModel1, FactKey::name(kA), "seen");
  b.pull(a);
  b.put(kModel1, FactKey::name(kB), "concurrent");
  {
    auto tx = a.db->begin();
    tx.revert(kAlice, Provenance::agent("model"));
    tx.commit();
  }
  a.pull(b);
  b.pull(a);
  for (Replica *r : {&a, &b}) {
    EXPECT_EQ(r->eff(FactKey::name(kA)), FactValue{});
    EXPECT_EQ(r->eff(FactKey::name(kB)), FactValue("concurrent"));
  }
}

TEST(Replication, DependentsFollowTheirDependencyAcrossReplicas) {
  Replica a(1), b(2);
  Seq bounds = a.put(kAlice, FactKey::function(kA), AddressSet{});
  a.put(kAlice, FactKey::name(Address{1, 0x1004}), "local", bounds);
  b.pull(a);
  b.retract(kBob, *b.db->log().find(a.id(bounds)));
  a.pull(b);
  for (Replica *r : {&a, &b}) {
    EXPECT_EQ(r->eff(FactKey::name(Address{1, 0x1004})), FactValue{});
    EXPECT_EQ(r->db->log().blame(FactKey::name(Address{1, 0x1004})).candidates[0].status, OpStatus::DependencyDead);
  }
}

TEST(Replication, MalformedOpsAreRejected) {
  Replica a(1), b(2);
  a.put(kAlice, FactKey::name(kA), "x");
  Op op = a.db->ops_since({})[0];
  Op no_id = op;
  no_id.id = {};
  Op wrong_key = *a.db->log().op(1);
  wrong_key.kind = OpKind::Retract;
  wrong_key.id = {1, 2};
  wrong_key.target_id = op.id;
  wrong_key.key = FactKey::name(kB);
  wrong_key.value = {};
  MergeResult r = b.merge(std::vector<Op>{no_id, op, wrong_key});
  EXPECT_EQ(r.staged, 1u);
  EXPECT_EQ(r.rejected, 2u);
  EXPECT_EQ(b.eff(FactKey::name(kA)), FactValue("x"));
}

TEST(Replication, ReplicaIdAndLegacyOpsSurviveReopen) {
  const auto dir = std::filesystem::temp_directory_path() / ("rk-replication-" + std::to_string(::getpid()));
  std::filesystem::remove_all(dir);
  // A log written before replication: ops without ids.
  {
    auto storage = open_lmdb_storage(dir);
    WriteBatch batch;
    for (Seq s = 1; s <= 2; ++s) {
      Op op;
      op.seq = s;
      op.prov = kAlice;
      op.key = FactKey::name(kA);
      op.value = std::string("v") + std::to_string(s);
      Encoder e;
      e.u64be(s);
      batch.put(Table::Log, std::move(e).str(), encode_to_string(op));
    }
    storage->write(batch);
  }
  ReplicaId replica = 0;
  OpId third;
  {
    FactDbOptions o;
    o.storage = open_lmdb_storage(dir);
    FactDb db(std::move(o));
    replica = db.replica();
    EXPECT_NE(replica, 0u);
    EXPECT_EQ(db.log().op(2)->id, (OpId{replica, 2}));
    EXPECT_EQ(db.log().effective(FactKey::name(kA)), FactValue("v2"));
    auto tx = db.begin();
    tx.assert_fact(kBob, FactKey::name(kA), "v3");
    tx.commit();
    third = db.log().op(3)->id;
    EXPECT_EQ(third, (OpId{replica, 3}));
    EXPECT_GT(db.log().op(3)->stamp, db.log().op(2)->stamp);
  }
  {
    FactDbOptions o;
    o.storage = open_lmdb_storage(dir);
    FactDb db(std::move(o));
    EXPECT_EQ(db.replica(), replica);
    EXPECT_EQ(db.log().op(3)->id, third);
    EXPECT_EQ(db.log().effective(FactKey::name(kA)), FactValue("v3"));
    EXPECT_EQ(db.version_vector(), (VersionVector{{replica, 3}}));
  }
  std::filesystem::remove_all(dir);
}

// --- Property: convergence -----------------------------------------------

class Convergence : public ::testing::TestWithParam<int> {};

// One random history; returns the replicas after a full exchange.
void RunHistory(std::uint64_t seed) {
  std::mt19937_64 rng(seed);
  auto pick = [&](std::size_t n) { return static_cast<std::size_t>(rng() % n); };
  auto chance = [&](int percent) { return static_cast<int>(rng() % 100) < percent; };

  const std::size_t n = 2 + pick(3);
  std::vector<std::unique_ptr<Replica>> rs;
  for (std::size_t i = 0; i < n; ++i) {
    // Skews up to an hour either way; some replicas share a clock exactly.
    std::int64_t skew = chance(30) ? 0 : static_cast<std::int64_t>(pick(7200)) * 1'000'000'000 - 3'600'000'000'000;
    rs.push_back(std::make_unique<Replica>(rng() | 1, skew));
  }
  const std::vector<Provenance> provs{kAlice, kBob, kDwarf, kModel1, kModel2, kAuto};
  const std::vector<FactKey> keys{FactKey::name(kA),     FactKey::name(kB),          FactKey::comment(kA),
                                  FactKey::function(kA), FactKey::comment(kA, "pre"), FactKey::type_def("s")};
  auto value = [&](const FactKey &k) -> FactValue {
    if (k.kind == FactKind::FunctionBounds) {
      if (chance(20)) return std::int64_t{0};
      AddressSet s;
      s.add(AddressRange{kA, Address{1, kA.offset + pick(4) * 16}});
      return s;
    }
    static const char *names[] = {"a", "b", "c", "d"};
    return std::string(names[pick(4)]);
  };

  // Delivers a random subset of `from`'s ops to `to`, shuffled, with
  // duplicates, in one or more transactions.
  auto exchange = [&](Replica &from, Replica &to, bool everything) {
    std::vector<Op> ops = from.db->ops_since(everything || chance(50) ? VersionVector{} : to.db->version_vector());
    std::vector<Op> batch;
    for (const Op &op : ops)
      if (everything || chance(70)) batch.push_back(op);
    for (std::size_t i = 0, dups = pick(4); i < dups && !ops.empty(); ++i) batch.push_back(ops[pick(ops.size())]);
    std::shuffle(batch.begin(), batch.end(), rng);
    std::size_t at = 0;
    while (at < batch.size()) {
      std::size_t take = 1 + pick(batch.size() - at);
      to.merge(std::span(batch).subspan(at, take));
      at += take;
    }
  };

  const int steps = 40 + static_cast<int>(pick(60));
  for (int step = 0; step < steps; ++step) {
    Replica &r = *rs[pick(n)];
    *r.clock += static_cast<std::int64_t>(pick(5)) * 1'000'000;
    const std::size_t size = r.db->log().size();
    const int action = static_cast<int>(pick(100));
    if (action < 40 || size == 0) {
      // A batch of one to three assertions, some depending on earlier ones.
      auto tx = r.db->begin();
      const Provenance &who = provs[pick(provs.size())];
      for (std::size_t i = 0, m = 1 + (chance(30) ? pick(3) : 0); i < m; ++i) {
        const FactKey &k = keys[pick(keys.size())];
        Seq dep = 0;
        if (size && chance(15)) {
          Seq cand = 1 + pick(size);
          if (r.db->log().op(cand)->kind == OpKind::Assert) dep = cand;
        }
        tx.assert_fact(who, k, value(k), dep);
      }
      tx.commit();
    } else if (action < 65) {
      r.retract(provs[pick(provs.size())], 1 + pick(size));  // anything, retractions too
    } else if (action < 72) {
      auto tx = r.db->begin();
      Provenance whose = provs[pick(provs.size())];
      if (whose.kind == ProvenanceKind::Agent && chance(50)) whose.version.clear();  // every version
      tx.revert(provs[pick(provs.size())], whose);
      tx.commit();
    } else {
      // A partial, possibly stale exchange between two replicas.
      Replica &to = *rs[pick(n)];
      if (&to != &r) exchange(r, to, false);
    }
  }

  // Heal: everyone gets everything, in random orders, until nothing moves.
  for (int round = 0; round < 4; ++round)
    for (auto &from : rs)
      for (auto &to : rs)
        if (from != to) exchange(*from, *to, true);
  std::vector<const FactDb *> dbs;
  for (auto &r : rs) dbs.push_back(r->db.get());
  const std::set<FactKey> all = all_keys(dbs);
  const std::string expected = dump(*rs[0]->db, all);
  for (auto &r : rs) {
    EXPECT_EQ(r->db->waiting(), 0u);
    EXPECT_EQ(r->db->version_vector(), rs[0]->db->version_vector());
    EXPECT_EQ(r->db->log().size(), rs[0]->db->log().size());
    EXPECT_EQ(dump(*r->db, all), expected);
  }

  // Fresh replicas fed the union in other orders: shuffled with
  // duplicates in random batches, and reversed in one batch.
  std::vector<Op> ops = rs[0]->db->ops_since({});
  Replica shuffled(7), reversed(8);
  {
    std::vector<Op> batch = ops;
    for (std::size_t i = 0; i < ops.size() / 4; ++i) batch.push_back(ops[pick(ops.size())]);
    std::shuffle(batch.begin(), batch.end(), rng);
    for (std::size_t at = 0; at < batch.size();) {
      std::size_t take = 1 + pick(std::min<std::size_t>(batch.size() - at, 16));
      shuffled.merge(std::span(batch).subspan(at, take));
      at += take;
    }
  }
  reversed.merge(std::vector<Op>(ops.rbegin(), ops.rend()));
  for (Replica *r : {&shuffled, &reversed}) {
    EXPECT_EQ(r->db->waiting(), 0u);
    EXPECT_EQ(dump(*r->db, all), expected);
  }
}

TEST_P(Convergence, RandomHistoriesConverge) {
  for (int i = 0; i < 25; ++i) {
    const std::uint64_t seed = static_cast<std::uint64_t>(GetParam()) * 1000 + static_cast<std::uint64_t>(i);
    SCOPED_TRACE("seed " + std::to_string(seed));
    RunHistory(seed);
    if (HasFailure()) return;
  }
}

INSTANTIATE_TEST_SUITE_P(Seeds, Convergence, ::testing::Range(0, 8));

}  // namespace
}  // namespace revkit::facts
