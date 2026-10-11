#include "revkit/facts/fact_db.h"

#include <gtest/gtest.h>

namespace revkit::facts {
namespace {

const Address kFn{1, 0x401000};
const Provenance kAlice = Provenance::user("alice");
const Provenance kBob = Provenance::user("bob");
const Provenance kDwarf = Provenance::import("dwarf");
const Provenance kModel1 = Provenance::agent("model", "1");
const Provenance kModel2 = Provenance::agent("model", "2");
const Provenance kAuto = Provenance::analysis("auto-name");

class LogTest : public ::testing::Test {
 protected:
  LogTest() : db_(options()) {}

  static FactDbOptions options() {
    FactDbOptions o;
    o.clock = [] {
      static std::int64_t t = 1000;
      return t += 10;
    };
    return o;
  }

  Seq put(const Provenance &who, const FactKey &k, FactValue v, Seq dep = 0) {
    auto tx = db_.begin();
    Seq s = tx.assert_fact(who, k, std::move(v), dep);
    tx.commit();
    return s;
  }
  Seq retract(const Provenance &who, Seq target) {
    auto tx = db_.begin();
    Seq s = tx.retract(who, target);
    tx.commit();
    return s;
  }
  FactValue eff(const FactKey &k) { return db_.log().effective(k); }
  // The engine's view must always agree with the log's.
  FactValue engine_view(const FactKey &k) { return *db_.snapshot().get<AssertedFact>(k); }

  FactDb db_;
};

TEST_F(LogTest, SequenceNumbersAndTimestampsAreMonotonic) {
  Seq a = put(kAlice, FactKey::name(kFn), "a");
  Seq b = put(kBob, FactKey::comment(kFn), "b");
  auto tx = db_.begin();
  Seq c = tx.assert_fact(kAlice, FactKey::note(kFn), "c");
  Seq d = tx.assert_fact(kAlice, FactKey::note(kFn, "x"), "d");
  tx.commit();
  EXPECT_EQ(a, 1u);
  EXPECT_EQ(b, 2u);
  EXPECT_EQ(c, 3u);
  EXPECT_EQ(d, 4u);
  EXPECT_LT(db_.log().op(a)->time_ns, db_.log().op(b)->time_ns);
  EXPECT_EQ(db_.log().next_seq(), 5u);
}

TEST_F(LogTest, AbortedTransactionLeavesNoTrace) {
  {
    auto tx = db_.begin();
    tx.assert_fact(kAlice, FactKey::name(kFn), "never");
  }
  EXPECT_EQ(db_.log().size(), 0u);
  EXPECT_EQ(eff(FactKey::name(kFn)), FactValue{});
  EXPECT_EQ(put(kAlice, FactKey::name(kFn), "real"), 1u);
}

TEST_F(LogTest, ConflictsRankByProvenanceThenRecency) {
  FactKey k = FactKey::name(kFn);
  put(kAuto, k, "FUN_401000");
  EXPECT_EQ(eff(k), FactValue("FUN_401000"));
  put(kModel1, k, "parse_header");
  EXPECT_EQ(eff(k), FactValue("parse_header"));
  put(kDwarf, k, "read_hdr");
  EXPECT_EQ(eff(k), FactValue("read_hdr"));
  // A later agent assertion does not beat an earlier import.
  put(kModel2, k, "parse_hdr_v2");
  EXPECT_EQ(eff(k), FactValue("read_hdr"));
  put(kAlice, k, "alice_name");
  EXPECT_EQ(eff(k), FactValue("alice_name"));
  // Same rank: the most recent wins.
  put(kBob, k, "bob_name");
  EXPECT_EQ(eff(k), FactValue("bob_name"));
  EXPECT_EQ(engine_view(k), FactValue("bob_name"));

  // Nothing is deleted: every loser is still in history.
  EXPECT_EQ(db_.log().history(k).size(), 6u);
}

TEST_F(LogTest, RetractionUndoAndRedo) {
  FactKey k = FactKey::type(kFn);
  put(kDwarf, k, "int (*)(char *)");
  Seq mine = put(kAlice, k, "int (*)(const char *)");
  EXPECT_EQ(eff(k), FactValue("int (*)(const char *)"));

  Seq undo = retract(kAlice, mine);
  EXPECT_EQ(eff(k), FactValue("int (*)(char *)"));
  EXPECT_EQ(engine_view(k), FactValue("int (*)(char *)"));
  EXPECT_TRUE(db_.log().retracted(mine));
  EXPECT_FALSE(db_.log().live(mine));

  Seq redo = retract(kAlice, undo);
  EXPECT_EQ(eff(k), FactValue("int (*)(const char *)"));
  EXPECT_FALSE(db_.log().retracted(mine));

  // Undo the redo: chains of any length resolve.
  retract(kAlice, redo);
  EXPECT_EQ(eff(k), FactValue("int (*)(char *)"));

  auto h = db_.log().history(k);
  ASSERT_EQ(h.size(), 5u);
  EXPECT_EQ(h[2].kind, OpKind::Retract);
  EXPECT_EQ(h[2].target, mine);
  EXPECT_EQ(h[4].target, redo);
}

TEST_F(LogTest, LongUndoRedoChainDoesNotRecurse) {
  FactKey k = FactKey::comment(kFn);
  Seq last = put(kAlice, k, "x");
  for (int i = 0; i < 5000; ++i) last = retract(kAlice, last);
  // An even number of retractions on top of the assertion: it is live.
  EXPECT_EQ(eff(k), FactValue("x"));
  retract(kAlice, last);
  EXPECT_EQ(eff(k), FactValue{});
}

TEST_F(LogTest, DependentAssertionsFollowTheirDependency) {
  Seq fn = put(kAlice, FactKey::function(kFn), AddressSet(*AddressRange::sized(kFn, 0x40)));
  Address local{3, 0x10};  // a stack slot of that function
  Seq var = put(kModel1, FactKey::name(local), "counter", fn);
  EXPECT_EQ(eff(FactKey::name(local)), FactValue("counter"));

  Seq undo = retract(kAlice, fn);
  EXPECT_EQ(eff(FactKey::name(local)), FactValue{});
  EXPECT_FALSE(db_.log().live(var));
  EXPECT_FALSE(db_.log().retracted(var));
  auto b = db_.log().blame(FactKey::name(local));
  ASSERT_EQ(b.candidates.size(), 1u);
  EXPECT_EQ(b.candidates[0].status, OpStatus::DependencyDead);

  retract(kAlice, undo);
  EXPECT_EQ(eff(FactKey::name(local)), FactValue("counter"));
  EXPECT_EQ(engine_view(FactKey::name(local)), FactValue("counter"));
}

TEST_F(LogTest, BlameExplainsTheWinner) {
  FactKey k = FactKey::name(kFn);
  Seq imp = put(kDwarf, k, "imported");
  Seq ag = put(kModel1, k, "guessed");
  Seq us = put(kAlice, k, "chosen");
  Seq bad = put(kBob, k, "typo");
  Seq undo = retract(kBob, bad);

  Blame b = db_.log().blame(k);
  ASSERT_TRUE(b.winner);
  EXPECT_EQ(b.winner->seq, us);
  EXPECT_EQ(b.winner->prov, kAlice);
  EXPECT_EQ(b.value, FactValue("chosen"));
  ASSERT_EQ(b.candidates.size(), 4u);
  EXPECT_EQ(b.candidates[0].op.seq, us);
  EXPECT_EQ(b.candidates[0].status, OpStatus::Effective);
  EXPECT_EQ(b.candidates[1].op.seq, imp);
  EXPECT_EQ(b.candidates[1].status, OpStatus::Shadowed);
  EXPECT_EQ(b.candidates[2].op.seq, ag);
  EXPECT_EQ(b.candidates[3].op.seq, bad);
  EXPECT_EQ(b.candidates[3].status, OpStatus::Retracted);
  EXPECT_EQ(b.candidates[3].retracted_by, std::vector<Seq>{undo});
}

TEST_F(LogTest, BulkRevertByProvenance) {
  FactKey name = FactKey::name(kFn);
  FactKey cmt = FactKey::comment(kFn);
  FactKey ty = FactKey::type(kFn);
  put(kDwarf, name, "imported");
  put(kAlice, cmt, "alice's comment");
  put(kModel1, name, "agent_name");
  put(kModel1, ty, "void (void)");
  Seq agent_cmt = put(kModel1, cmt, "agent comment");
  // The agent also undid alice's comment and its own type...
  Seq alice_cmt = 0;
  for (const auto &c : db_.log().blame(cmt).candidates)
    if (c.op.prov == kAlice) alice_cmt = c.op.seq;
  retract(kModel1, alice_cmt);
  Seq ty2 = put(kModel1, ty, "int (void)");
  // ...and a different version of the agent made one change.
  put(kModel2, FactKey::note(kFn), "v2 note");
  // Alice later built on the agent's comment; that is hers and stays.
  put(kAlice, FactKey::note(kFn, "alice"), "see agent comment");

  EXPECT_EQ(eff(cmt), FactValue("agent comment"));
  EXPECT_EQ(eff(ty), FactValue("int (void)"));

  Revision before = db_.engine().revision();
  std::vector<Seq> reverted;
  Revision after;
  {
    auto tx = db_.begin();
    reverted = tx.revert(kAlice, kModel1);
    after = tx.commit();
  }
  EXPECT_EQ(after, before + 1);  // one revision for the whole revert
  EXPECT_EQ(reverted.size(), 5u);  // 4 assertions and 1 retraction

  EXPECT_EQ(eff(name), FactValue("imported"));
  EXPECT_EQ(eff(cmt), FactValue("alice's comment"));  // restored
  EXPECT_EQ(eff(ty), FactValue{});
  EXPECT_EQ(eff(FactKey::note(kFn)), FactValue("v2 note"));
  EXPECT_EQ(eff(FactKey::note(kFn, "alice")), FactValue("see agent comment"));
  EXPECT_EQ(engine_view(cmt), FactValue("alice's comment"));
  EXPECT_TRUE(db_.log().retracted(agent_cmt));
  EXPECT_TRUE(db_.log().retracted(ty2));

  // The revert is itself undoable: retract its retractions.
  {
    auto tx3 = db_.begin();
    for (Seq s : reverted) tx3.retract(kAlice, s);
    tx3.commit();
  }
  EXPECT_EQ(eff(cmt), FactValue("agent comment"));
  EXPECT_EQ(eff(ty), FactValue("int (void)"));

  // "agent:model" without a version covers every version.
  {
    auto tx2 = db_.begin();
    tx2.revert(kAlice, Provenance::agent("model"));
    tx2.commit();
    EXPECT_THROW(tx2.assert_fact(kAlice, name, "late"), std::logic_error);  // committed
    auto open = db_.begin();  // commit released the writer
    EXPECT_THROW(db_.begin(), std::logic_error);  // same thread: would deadlock
  }
  EXPECT_EQ(eff(FactKey::note(kFn)), FactValue{});
  EXPECT_EQ(eff(cmt), FactValue("alice's comment"));
  EXPECT_EQ(eff(name), FactValue("imported"));
}

TEST_F(LogTest, RevertSinceOnlyTouchesLaterOps) {
  FactKey a = FactKey::name(kFn);
  FactKey b = FactKey::name(Address{1, 0x402000});
  put(kModel1, a, "early");
  Seq mark = db_.log().next_seq();
  put(kModel1, b, "late");
  auto tx = db_.begin();
  tx.revert(kAlice, kModel1, mark);
  tx.commit();
  EXPECT_EQ(eff(a), FactValue("early"));
  EXPECT_EQ(eff(b), FactValue{});
}

TEST_F(LogTest, InvalidOpsAreRejected) {
  auto tx = db_.begin();
  EXPECT_THROW(tx.retract(kAlice, 42), std::invalid_argument);
  Seq s = tx.assert_fact(kAlice, FactKey::name(kFn), "x");
  Seq r = tx.retract(kAlice, s);  // retracting a staged op is fine
  EXPECT_THROW(tx.assert_fact(kAlice, FactKey::name(kFn), "y", r), std::invalid_argument);
  EXPECT_THROW(tx.assert_fact(kAlice, FactKey::name(kFn), "y", 99), std::invalid_argument);
  tx.commit();
  EXPECT_EQ(db_.log().size(), 2u);
  EXPECT_EQ(eff(FactKey::name(kFn)), FactValue{});
}

// Every commit that appends ops publishes a revision, so a client can name
// the revision its edit landed in; an equal value still changes no key.
TEST_F(LogTest, EqualValuesAdvanceTheRevisionButChangeNoKey) {
  FactKey k = FactKey::name(kFn);
  Revision r1 = [&] {
    auto tx = db_.begin();
    tx.assert_fact(kDwarf, k, "same");
    return tx.commit();
  }();
  auto tx = db_.begin();
  tx.assert_fact(kAlice, k, "same");  // different op, same effective value
  EXPECT_EQ(tx.next_revision(), r1 + 1);
  std::vector<FactKey> changed{k};
  EXPECT_EQ(tx.commit(&changed), r1 + 1);
  EXPECT_TRUE(changed.empty());
  EXPECT_EQ(db_.log().blame(k).winner->prov, kAlice);
  EXPECT_EQ(*db_.snapshot().get<LogLength>(0), 2u);
  // A transaction that stages nothing publishes nothing.
  EXPECT_EQ(db_.begin().commit(), r1 + 1);
}

TEST_F(LogTest, CommitReportsChangedKeys) {
  FactKey a = FactKey::name(kFn), b = FactKey::comment(kFn);
  auto tx = db_.begin();
  Seq sa = tx.assert_fact(kAlice, a, "a");
  tx.assert_fact(kAlice, b, "b", sa);
  std::vector<FactKey> changed;
  tx.commit(&changed);
  EXPECT_EQ(changed, (std::vector<FactKey>{a, b}));
  auto tx2 = db_.begin();
  tx2.assert_fact(kModel1, a, "shadowed");  // outranked: nothing changes
  tx2.commit(&changed);
  EXPECT_TRUE(changed.empty());
  auto tx3 = db_.begin();
  tx3.retract(kAlice, sa);  // b depended on a
  tx3.commit(&changed);
  EXPECT_EQ(changed, (std::vector<FactKey>{a, b}));
  EXPECT_EQ(eff(a), FactValue("shadowed"));
}

TEST_F(LogTest, MetaIsKeptWithTheOp) {
  auto tx = db_.begin();
  Seq a = tx.assert_fact(kAlice, FactKey::name(kFn), "x", 0, "request body");
  Seq r = tx.retract(kAlice, a, std::string("\0why", 4));
  tx.commit();
  EXPECT_EQ(db_.log().op(a)->meta, "request body");
  EXPECT_EQ(db_.log().op(r)->meta, std::string("\0why", 4));
  // Encoded ops without meta decode as before; with it, round-trip.
  for (Seq s : {a, r}) EXPECT_EQ(decode_from_string<Op>(encode_to_string(*db_.log().op(s))), *db_.log().op(s));
  Op plain = *db_.log().op(a);
  plain.meta.clear();
  EXPECT_EQ(decode_from_string<Op>(encode_to_string(plain)), plain);
}

// Blame, history and statuses as a reader pinned to an earlier revision
// sees them, while later ops retract, redo and outrank.
TEST_F(LogTest, BlameAndStatusAsOfAnEarlierSeq) {
  FactKey k = FactKey::name(kFn), dep = FactKey::comment(kFn);
  Seq imp = put(kDwarf, k, "imported");  // 1
  Seq mine = put(kAlice, k, "mine");     // 2
  Seq c = put(kAlice, dep, "under mine", mine);  // 3
  Seq undo = retract(kAlice, mine);      // 4
  Seq redo = retract(kAlice, undo);      // 5
  Seq undo2 = retract(kBob, mine);       // 6

  struct Expect {
    Seq upto;
    FactValue value;
    OpStatus mine, imp, c;
  };
  for (const Expect &e : {Expect{2, "mine", OpStatus::Effective, OpStatus::Shadowed, OpStatus::Shadowed},
                          Expect{3, "mine", OpStatus::Effective, OpStatus::Shadowed, OpStatus::Effective},
                          Expect{4, "imported", OpStatus::Retracted, OpStatus::Effective, OpStatus::DependencyDead},
                          Expect{5, "mine", OpStatus::Effective, OpStatus::Shadowed, OpStatus::Effective},
                          Expect{6, "imported", OpStatus::Retracted, OpStatus::Effective, OpStatus::DependencyDead}}) {
    SCOPED_TRACE(e.upto);
    Blame b = db_.log().blame(k, e.upto);
    EXPECT_EQ(b.value, e.value);
    EXPECT_EQ(db_.log().status(mine, e.upto), e.mine);
    EXPECT_EQ(db_.log().status(imp, e.upto), e.imp);
    if (e.upto >= c) {
      EXPECT_EQ(db_.log().status(c, e.upto), e.c);
    }
  }
  EXPECT_EQ(db_.log().status(undo, 4), OpStatus::Effective);
  EXPECT_EQ(db_.log().status(undo, 5), OpStatus::Retracted);
  EXPECT_EQ(db_.log().retracted_by(mine, 5), std::vector<Seq>{});
  EXPECT_EQ(db_.log().retracted_by(mine, 6), std::vector<Seq>{undo2});
  EXPECT_EQ(db_.log().history(k, 4).size(), 3u);  // two assertions, one retraction
  EXPECT_EQ(db_.log().history(k).size(), 5u);
  // The current state agrees with the incremental one.
  Blame now = db_.log().blame(k), at = db_.log().blame(k, 100);
  ASSERT_EQ(now.candidates.size(), at.candidates.size());
  for (std::size_t i = 0; i < now.candidates.size(); ++i) EXPECT_EQ(now.candidates[i].status, at.candidates[i].status);
  EXPECT_EQ(redo, 5u);
}

struct CommentsIn {
  static constexpr std::string_view name = "t.comments_in";
  static constexpr std::uint32_t version = 1;
  using Key = std::pair<std::uint64_t, std::uint64_t>;
  using Value = std::vector<std::string>;
  static Value compute(QueryContext &ctx, const Key &k) {
    Value out;
    for (const FactKey &key : asserted_keys(ctx, FactKind::Comment, Address{1, k.first}, Address{1, k.second}))
      out.push_back(std::get<std::string>(*ctx.get<AssertedFact>(key)));
    return out;
  }
};

TEST_F(LogTest, AssertedKeyIndexFindsKeysByRange) {
  db_.engine().add_query<CommentsIn>();
  put(kAlice, FactKey::comment({1, 0x401000}), "a");
  put(kAlice, FactKey::comment({1, 0x401010}, "plate"), "b");
  Seq far = put(kAlice, FactKey::comment({1, 0x900000}), "far");
  put(kAlice, FactKey::name({1, 0x401004}), "not a comment");
  auto in = [&](std::uint64_t lo, std::uint64_t hi) { return *db_.snapshot().get<CommentsIn>({lo, hi}); };
  EXPECT_EQ(in(0x401000, 0x4010ff), (std::vector<std::string>{"a", "b"}));
  EXPECT_EQ(in(0, ~std::uint64_t{0}), (std::vector<std::string>{"a", "b", "far"}));  // via the directory
  EXPECT_EQ(*db_.snapshot().get<AssertedBuckets>({FactKind::Comment, 1}),
            (std::vector<std::uint64_t>{0x401000 >> kBucketShift, 0x900000 >> kBucketShift}));

  // A comment in another bucket leaves the narrow query alone.
  db_.engine().reset_stats();
  retract(kAlice, far);
  EXPECT_EQ(in(0x401000, 0x4010ff), (std::vector<std::string>{"a", "b"}));
  EXPECT_EQ(db_.engine().stats<CommentsIn>().executions, 0u);
  EXPECT_EQ(in(0, ~std::uint64_t{0}), (std::vector<std::string>{"a", "b"}));
  EXPECT_EQ(*db_.snapshot().get<AssertedBuckets>({FactKind::Comment, 1}),
            (std::vector<std::uint64_t>{0x401000 >> kBucketShift}));
}

// The comment at one address, found through its span.
struct CommentAt {
  static constexpr std::string_view name = "t.comment_at";
  static constexpr std::uint32_t version = 1;
  using Key = std::uint64_t;
  using Value = std::vector<std::string>;
  static Value compute(QueryContext &ctx, const Key &a) {
    Value out;
    for (const FactKey &key : asserted_at(ctx, FactKind::Comment, Address{1, a}))
      out.push_back(key.sub + "=" + std::get<std::string>(*ctx.get<AssertedFact>(key)));
    return out;
  }
};

// Narrow reads depend on 256-byte spans, not on the 64 KiB bucket: a key
// elsewhere in the bucket re-runs the span filter, which cuts off, and no
// rule that read another span.
TEST_F(LogTest, AssertedSpansNarrowTheIndex) {
  db_.engine().add_query<CommentsIn>();
  db_.engine().add_query<CommentAt>();
  put(kAlice, FactKey::comment({1, 0x401000}), "a");
  put(kAlice, FactKey::comment({1, 0x401000}, "plate"), "p");
  put(kAlice, FactKey::comment({1, 0x4010ff}), "edge");
  auto at = [&](std::uint64_t a) { return *db_.snapshot().get<CommentAt>(a); };
  EXPECT_EQ(at(0x401000), (std::vector<std::string>{"eol=a", "plate=p"}));
  EXPECT_EQ(at(0x401001), std::vector<std::string>{});
  EXPECT_EQ(*db_.snapshot().get<CommentsIn>({0x401000, 0x4010ff}), (std::vector<std::string>{"a", "p", "edge"}));
  EXPECT_EQ(db_.snapshot().get<AssertedSpan>(BucketKey{FactKind::Comment, 1, 0x401000 >> kSpanShift})->size(), 3u);

  // Same bucket, next span: only the span filter re-runs, and it cuts off.
  db_.engine().reset_stats();
  Seq next = put(kAlice, FactKey::comment({1, 0x401100}), "next");
  EXPECT_EQ(at(0x401000), (std::vector<std::string>{"eol=a", "plate=p"}));
  EXPECT_EQ(*db_.snapshot().get<CommentsIn>({0x401000, 0x4010ff}), (std::vector<std::string>{"a", "p", "edge"}));
  EXPECT_EQ(db_.engine().stats<CommentAt>().executions, 0u);
  EXPECT_EQ(db_.engine().stats<CommentsIn>().executions, 0u);
  EXPECT_EQ(db_.engine().stats<AssertedSpan>().executions, 1u);
  EXPECT_EQ(at(0x401100), std::vector<std::string>{"eol=next"});

  // A key in the span re-runs its readers; a changed value only the
  // reader of that address.
  db_.engine().reset_stats();
  put(kAlice, FactKey::comment({1, 0x401001}), "b");
  EXPECT_EQ(at(0x401001), std::vector<std::string>{"eol=b"});
  EXPECT_EQ(at(0x401000), (std::vector<std::string>{"eol=a", "plate=p"}));
  EXPECT_EQ(db_.engine().stats<CommentAt>().executions, 2u);
  db_.engine().reset_stats();
  put(kAlice, FactKey::comment({1, 0x401001}), "c");
  EXPECT_EQ(at(0x401001), std::vector<std::string>{"eol=c"});
  EXPECT_EQ(at(0x401000), (std::vector<std::string>{"eol=a", "plate=p"}));
  EXPECT_EQ(db_.engine().stats<CommentAt>().executions, 1u);
  retract(kAlice, next);
  EXPECT_EQ(at(0x401100), std::vector<std::string>{});
}

TEST(AssertionLogDirect, AppendReturnsAffectedKeys) {
  AssertionLog log;
  FactKey k1 = FactKey::name(kFn), k2 = FactKey::comment(kFn);
  auto make = [](Seq seq, OpKind kind, FactKey key, FactValue value, Seq target, Seq dep) {
    Op op;
    op.seq = seq;
    op.prov = kAlice;
    op.kind = kind;
    op.key = std::move(key);
    op.value = std::move(value);
    op.target = target;
    op.depends_on = dep;
    return op;
  };
  Op a = make(1, OpKind::Assert, k1, std::string("a"), 0, 0);
  Op b = make(2, OpKind::Assert, k2, std::string("b"), 0, 1);
  EXPECT_EQ(log.append(std::vector<Op>{a, b}), (std::vector<FactKey>{k1, k2}));
  Op r = make(3, OpKind::Retract, k1, {}, 1, 0);
  // Retracting a also kills b (it depends on a): both keys are affected.
  EXPECT_EQ(log.append(std::vector<Op>{r}), (std::vector<FactKey>{k1, k2}));
  EXPECT_EQ(log.effective(k2), FactValue{});
  Op bad = make(5, OpKind::Assert, k1, std::string("x"), 0, 0);
  EXPECT_THROW(log.append(std::vector<Op>{bad}), std::invalid_argument);
  EXPECT_EQ(log.size(), 3u);
  // Ops appended without ids are the local replica's, numbered in order.
  EXPECT_EQ(log.op(3)->id, (OpId{0, 3}));
  EXPECT_EQ(log.op(3)->target_id, (OpId{0, 1}));
  EXPECT_EQ(log.version_vector(), (VersionVector{{0, 3}}));
}

}  // namespace
}  // namespace revkit::facts
