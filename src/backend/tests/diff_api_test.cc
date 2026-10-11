// DiffService on the image backend (docs/diff.md): a session over two
// versions of a program compiled here, A with debug info and B stripped;
// runs, the match table, decisions, porting markup and undoing it.
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <chrono>
#include <map>
#include <set>
#include <mutex>
#include <thread>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

constexpr const char *kV1 = R"(
#include <stdio.h>
#include <string.h>
struct point { int x, y; };
int table[16];
__attribute__((noinline)) unsigned hash_str(const char *s) {
  unsigned h = 5381;
  while (*s) h = h * 33 + (unsigned char)*s++;
  return h;
}
__attribute__((noinline)) int point_sum(struct point *p) { return p->x * 3 + p->y; }
__attribute__((noinline)) int sum_table(void) {
  int s = 0;
  for (int i = 0; i < 16; i++) s += table[i] * (i + 1);
  return s;
}
__attribute__((noinline)) int parse_flag(const char *a) {
  if (!strcmp(a, "--verbose")) return 1;
  if (!strcmp(a, "--quiet")) return 2;
  return 0;
}
__attribute__((noinline)) int only_v1(int x) { return x * 7 + 3; }
int main(int argc, char **argv) {
  struct point p = {argc, 2};
  int f = argc > 1 ? parse_flag(argv[1]) : 0;
  printf("%u %d %d %d\n", hash_str(argv[0]), point_sum(&p), sum_table(), f);
  return only_v1(f);
}
)";

// Version 2: something new first (everything moves, nothing calls it),
// parse_flag grows a case, only_v1 is gone.
constexpr const char *kV2 = R"(
#include <stdio.h>
#include <string.h>
struct point { int x, y; };
int table[16];
__attribute__((noinline)) int fresh(int x) { return x - 11; }
__attribute__((noinline)) unsigned hash_str(const char *s) {
  unsigned h = 5381;
  while (*s) h = h * 33 + (unsigned char)*s++;
  return h;
}
__attribute__((noinline)) int point_sum(struct point *p) { return p->x * 3 + p->y; }
__attribute__((noinline)) int sum_table(void) {
  int s = 0;
  for (int i = 0; i < 16; i++) s += table[i] * (i + 1);
  return s;
}
__attribute__((noinline)) int parse_flag(const char *a) {
  if (!strcmp(a, "--verbose")) return 1;
  if (!strcmp(a, "--quiet")) return 2;
  if (!strcmp(a, "--extra")) return 3;
  return 0;
}
int main(int argc, char **argv) {
  struct point p = {argc, 2};
  int f = argc > 1 ? parse_flag(argv[1]) : 0;
  printf("%u %d %d %d\n", hash_str(argv[0]), point_sum(&p), sum_table(), f);
  return f;
}
)";

class Sink : public api::EventSink {
 public:
  void Send(pb::SubscribeResponse event) override {
    std::lock_guard lock(mu_);
    if (event.has_revision()) events_.push_back(event.revision());
  }
  void End(api::Status) override {}
  std::vector<pb::RevisionEvent> events() {
    std::lock_guard lock(mu_);
    return events_;
  }

 private:
  std::mutex mu_;
  std::vector<pb::RevisionEvent> events_;
};

class DiffApi : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("diff-api");
    v1_ = dir / "v1";
    v2_ = dir / "v2";
    const auto v2_debug = dir / "v2-debug";
    ok_ = testing::compile(REVKIT_TEST_CC, kV1, "-g -O2 -fno-inline", v1_) &&
          testing::compile(REVKIT_TEST_CC, kV2, "-g -O2 -fno-inline", v2_debug) &&
          std::system(("strip -o " + v2_.string() + " " + v2_debug.string()).c_str()) == 0;
    // B's truth, for checking ported names.
    if (ok_) truth_b_ = Symbols(v2_debug);
  }

  static std::map<std::string, std::uint64_t> Symbols(const std::filesystem::path &file) {
    std::map<std::string, std::uint64_t> out;
    // Through a throwaway backend: ListFunctions of the debug build.
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    auto b = MakeImageBackend(o);
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(file.string());
    pb::ImportProgramResponse resp;
    if (!b->ImportProgram({}, req, resp).ok()) return out;
    pb::ListFunctionsRequest lf;
    lf.set_program_id(resp.program().program_id());
    lf.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse fr;
    b->ListFunctions({}, lf, fr);
    for (const auto &f : fr.functions()) out[f.name()] = f.entry().offset();
    return out;
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!ok_) GTEST_SKIP() << "no C compiler or strip";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
    a_ = Import(v1_, "v1");
    b_ = Import(v2_, "v2");
  }

  std::string Import(const std::filesystem::path &path, const std::string &name) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(path.string());
    req.set_name(name);
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  std::map<std::string, std::uint64_t> Functions(const std::string &program) {
    pb::ListFunctionsRequest req;
    req.set_program_id(program);
    req.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(backend_->ListFunctions(ctx_, req, resp).ok());
    std::map<std::string, std::uint64_t> out;
    for (const auto &f : resp.functions()) out[f.name()] = f.entry().offset();
    return out;
  }
  std::string NameAt(const std::string &program, std::uint64_t entry) {
    for (const auto &[n, e] : Functions(program))
      if (e == entry) return n;
    return {};
  }

  static pb::Provenance User(const std::string &id = "alice") {
    pb::Provenance p;
    p.set_kind(pb::PROVENANCE_KIND_USER);
    p.set_id(id);
    return p;
  }

  std::string Session(bool run = true) {
    pb::CreateDiffSessionRequest req;
    req.set_project_id("default");
    req.set_program_a(a_);
    req.set_program_b(b_);
    *req.mutable_provenance() = User();
    req.set_run(run);
    pb::CreateDiffSessionResponse resp;
    auto st = backend_->CreateDiffSession(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.session().session_id();
  }

  pb::GetDiffStatusResponse Wait(const std::string &session) {
    pb::GetDiffStatusRequest req;
    req.set_project_id("default");
    req.set_session_id(session);
    pb::GetDiffStatusResponse resp;
    for (int i = 0; i < 600; ++i) {
      EXPECT_TRUE(backend_->GetDiffStatus(ctx_, req, resp).ok());
      if (resp.session().run().state() != pb::DIFF_RUN_STATE_RUNNING) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return resp;
  }

  pb::ListMatchesResponse Matches(const std::string &session, pb::DiffMatchFilter filter = {}, std::uint32_t page = 0) {
    pb::ListMatchesRequest req;
    req.set_project_id("default");
    req.set_session_id(session);
    *req.mutable_filter() = filter;
    req.mutable_page()->set_page_size(page);
    pb::ListMatchesResponse resp;
    auto st = backend_->ListMatches(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }
  const pb::DiffMatch *ByNameA(const pb::ListMatchesResponse &r, const std::string &name) {
    for (const auto &m : r.matches())
      if (m.a().name() == name) return &m;
    return nullptr;
  }

  pb::ApplyMarkupResponse Apply(const std::string &session, pb::ApplyMarkupRequest req = {}) {
    req.set_project_id("default");
    req.set_session_id(session);
    *req.mutable_provenance() = User();
    pb::ApplyMarkupResponse resp;
    auto st = backend_->ApplyMarkup(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  static inline std::filesystem::path v1_, v2_;
  static inline bool ok_ = false;
  static inline std::map<std::string, std::uint64_t> truth_b_;
  std::unique_ptr<api::Backend> backend_;
  CallContext ctx_;
  std::string a_, b_;
};

TEST_F(DiffApi, RunListAndCounts) {
  const std::string s = Session();
  ASSERT_FALSE(s.empty());
  auto status = Wait(s);
  EXPECT_EQ(status.session().run().state(), pb::DIFF_RUN_STATE_SUCCEEDED) << status.session().run().message();
  EXPECT_GT(status.counts().matched(), 5u);
  EXPECT_GT(status.counts().auto_matches(), 3u);
  EXPECT_GE(status.counts().unmatched_a(), 1u);  // only_v1

  auto all = Matches(s);
  for (const char *n : {"hash_str", "point_sum", "sum_table", "parse_flag", "main"}) {
    const pb::DiffMatch *m = ByNameA(all, n);
    ASSERT_TRUE(m) << n;
    EXPECT_EQ(m->b().entry().offset(), truth_b_.at(n)) << n;
    EXPECT_TRUE(m->b().default_name()) << n;  // stripped
    EXPECT_FALSE(m->evidence().detail().empty());
  }
  EXPECT_EQ(ByNameA(all, "hash_str")->change_kind(), pb::DIFF_CHANGE_KIND_UNCHANGED);
  EXPECT_EQ(ByNameA(all, "parse_flag")->change_kind(), pb::DIFF_CHANGE_KIND_MODIFIED);
  EXPECT_EQ(ByNameA(all, "hash_str")->status(), pb::DIFF_MATCH_STATUS_PROPOSED);

  // Filters, sorting and paging.
  pb::DiffMatchFilter f;
  f.add_change_kinds(pb::DIFF_CHANGE_KIND_MODIFIED);
  const auto modified = Matches(s, f);
  EXPECT_GT(modified.matches_size(), 0);
  for (const auto &m : modified.matches()) EXPECT_EQ(m.change_kind(), pb::DIFF_CHANGE_KIND_MODIFIED);
  f.Clear();
  f.set_name_contains("HASH");
  ASSERT_EQ(Matches(s, f).matches_size(), 1);
  pb::ListMatchesRequest req;
  req.set_project_id("default");
  req.set_session_id(s);
  req.set_sort(pb::DIFF_SORT_CONFIDENCE);
  req.mutable_page()->set_page_size(2);
  pb::ListMatchesResponse page1;
  ASSERT_TRUE(backend_->ListMatches(ctx_, req, page1).ok());
  ASSERT_EQ(page1.matches_size(), 2);
  EXPECT_LE(page1.matches(0).confidence(), page1.matches(1).confidence());
  ASSERT_FALSE(page1.page().next_page_token().empty());
  req.mutable_page()->set_page_token(page1.page().next_page_token());
  pb::ListMatchesResponse page2;
  ASSERT_TRUE(backend_->ListMatches(ctx_, req, page2).ok());
  EXPECT_GE(page2.matches(0).confidence(), page1.matches(1).confidence());

  // only_v1 is unmatched in A.
  pb::ListUnmatchedRequest u;
  u.set_project_id("default");
  u.set_session_id(s);
  u.set_side(pb::DIFF_SIDE_A);
  pb::ListUnmatchedResponse ur;
  ASSERT_TRUE(backend_->ListUnmatched(ctx_, u, ur).ok());
  bool found = false;
  for (const auto &x : ur.functions()) found |= x.function().name() == "only_v1";
  EXPECT_TRUE(found);

  // One function's diff.
  pb::GetFunctionDiffRequest g;
  g.set_project_id("default");
  g.set_session_id(s);
  g.mutable_entry_a()->set_offset(Functions(a_).at("main"));
  pb::GetFunctionDiffResponse gr;
  ASSERT_TRUE(backend_->GetFunctionDiff(ctx_, g, gr).ok());
  EXPECT_EQ(gr.match().b().entry().offset(), truth_b_.at("main"));
  EXPECT_GE(gr.a().callees_size(), 3);
  EXPECT_FALSE(gr.b().bytes_hash().empty());

  // Sessions are listed, with their run.
  pb::ListDiffSessionsRequest ls;
  ls.set_project_id("default");
  pb::ListDiffSessionsResponse lr;
  ASSERT_TRUE(backend_->ListDiffSessions(ctx_, ls, lr).ok());
  ASSERT_EQ(lr.sessions_size(), 1);
  EXPECT_EQ(lr.sessions(0).run().state(), pb::DIFF_RUN_STATE_SUCCEEDED);
  EXPECT_EQ(lr.sessions(0).created_by().id(), "alice");
}

// Inside a pair (api_minor 17): parse_flag gains a case; hash_str only
// moved. The detail aligns both listings, flags only what changed, and
// the summaries say it in a line.
TEST_F(DiffApi, FunctionDiffDetailAlignsAndSummarizes) {
  const std::string s = Session();
  Wait(s);
  auto detail = [&](const std::string &name) {
    pb::GetFunctionDiffRequest g;
    g.set_project_id("default");
    g.set_session_id(s);
    g.mutable_entry_a()->set_offset(Functions(a_).at(name));
    g.set_detail(true);
    pb::GetFunctionDiffResponse gr;
    EXPECT_TRUE(backend_->GetFunctionDiff(ctx_, g, gr).ok());
    return gr;
  };
  {
    const auto gr = detail("hash_str");
    const pb::DiffDetail &d = gr.detail();
    ASSERT_GT(d.rows_a_size(), 5);
    EXPECT_EQ(d.rows_a_size(), d.rows_b_size());
    EXPECT_EQ(d.lines_size(), d.rows_a_size());
    EXPECT_EQ(d.hunks_size(), 0);
    for (const auto &r : d.rows_a()) EXPECT_EQ(r.status(), pb::DIFF_LINE_STATUS_EQUAL) << r.text();
    for (const auto &b : d.blocks_b()) EXPECT_EQ(b.status(), pb::DIFF_BLOCK_STATUS_UNCHANGED);
    EXPECT_EQ(d.summary().text(), "no instruction changed");
    EXPECT_FALSE(d.rows_a(0).text().empty());
    EXPECT_GT(d.rows_a(0).tokens_size(), 0);
  }
  const auto gr = detail("parse_flag");
  const pb::DiffDetail &d = gr.detail();
  EXPECT_GE(d.summary().inserted(), 3u);
  EXPECT_GE(d.hunks_size(), 1);
  EXPECT_GE(d.summary().blocks_added(), 1u);
  EXPECT_FALSE(d.summary().text().empty());
  // Lines: every row once, partners on the same line.
  std::set<int> seen_a, seen_b;
  for (const auto &l : d.lines()) {
    if (l.a() >= 0) EXPECT_TRUE(seen_a.insert(l.a()).second);
    if (l.b() >= 0) EXPECT_TRUE(seen_b.insert(l.b()).second);
    if (l.a() >= 0 && l.b() >= 0) {
      EXPECT_EQ(d.rows_a(l.a()).partner(), l.b());
      EXPECT_EQ(d.rows_b(l.b()).partner(), l.a());
    }
  }
  EXPECT_EQ(static_cast<int>(seen_a.size()), d.rows_a_size());
  EXPECT_EQ(static_cast<int>(seen_b.size()), d.rows_b_size());
  for (int k : d.hunks()) EXPECT_TRUE(d.lines(k).a() < 0 || d.lines(k).b() < 0 ||
                                      d.rows_a(d.lines(k).a()).status() != pb::DIFF_LINE_STATUS_EQUAL ||
                                      d.rows_a(d.lines(k).a()).moved());
  // Each block's partner is one to one.
  for (int x = 0; x < d.blocks_a_size(); ++x)
    if (d.blocks_a(x).partner() >= 0) EXPECT_EQ(d.blocks_b(d.blocks_a(x).partner()).partner(), x);

  // The table's summaries, in request order.
  pb::SummarizeFunctionDiffsRequest sr;
  sr.set_project_id("default");
  sr.set_session_id(s);
  for (const char *name : {"parse_flag", "hash_str", "main"}) {
    auto *p = sr.add_pairs();
    p->mutable_entry_a()->set_offset(Functions(a_).at(name));
    p->mutable_entry_b()->set_offset(truth_b_.at(name));
  }
  pb::SummarizeFunctionDiffsResponse sresp;
  ASSERT_TRUE(backend_->SummarizeFunctionDiffs(ctx_, sr, sresp).ok());
  ASSERT_EQ(sresp.summaries_size(), 3);
  EXPECT_EQ(sresp.summaries(0).text(), d.summary().text());
  EXPECT_EQ(sresp.summaries(0).inserted(), d.summary().inserted());
  EXPECT_EQ(sresp.summaries(1).text(), "no instruction changed");
  EXPECT_NE(sresp.summaries(2).text().find("only_v1"), std::string::npos) << sresp.summaries(2).text();
  EXPECT_EQ(sresp.summaries(2).entry_b().offset(), truth_b_.at("main"));
}

TEST_F(DiffApi, ApplyPortsNamesCommentsAndPrototypesAndRevertUndoesIt) {
  const std::string s = Session();
  Wait(s);
  const std::uint64_t hash_a = Functions(a_).at("hash_str");
  const std::uint64_t hash_b = truth_b_.at("hash_str");
  // Comments in A: a plate at the entry, an end-of-line one inside.
  pb::AppendAssertionsRequest add;
  add.set_program_id(a_);
  *add.mutable_provenance() = User();
  auto *c1 = add.add_assertions()->mutable_body()->mutable_comment();
  c1->mutable_address()->set_offset(hash_a);
  c1->set_kind(pb::COMMENT_KIND_PLATE);
  c1->set_text("djb2");
  auto *c2 = add.add_assertions()->mutable_body()->mutable_comment();
  c2->mutable_address()->set_offset(hash_a + 4);
  c2->set_kind(pb::COMMENT_KIND_EOL);
  c2->set_text("inside");
  pb::AppendAssertionsResponse added;
  ASSERT_TRUE(backend_->AppendAssertions(ctx_, add, added).ok());

  // A dry run commits nothing.
  pb::ApplyMarkupRequest dry;
  dry.set_dry_run(true);
  auto d = Apply(s, dry);
  EXPECT_GT(d.names(), 3u);
  EXPECT_TRUE(d.run_id().empty());
  EXPECT_TRUE(NameAt(b_, hash_b).starts_with("FUN_"));

  auto r = Apply(s);
  ASSERT_FALSE(r.run_id().empty());
  EXPECT_EQ(r.names(), d.names());
  EXPECT_GE(r.comments(), 2u);
  EXPECT_GE(r.prototypes(), 3u);  // DWARF prototypes of A
  EXPECT_GT(r.types(), 0u);       // struct point, at least
  EXPECT_GE(r.matches_recorded(), r.pairs());
  // Ported names are right.
  for (const char *n : {"hash_str", "point_sum", "sum_table"}) EXPECT_EQ(NameAt(b_, truth_b_.at(n)), n);

  // Blame: migration diff, ported from A.
  pb::BlameRequest bl;
  bl.mutable_key()->set_program_id(b_);
  bl.mutable_key()->set_kind(pb::FACT_KIND_NAME);
  bl.mutable_key()->mutable_address()->set_offset(hash_b);
  pb::BlameResponse blr;
  ASSERT_TRUE(backend_->Blame(ctx_, bl, blr).ok());
  ASSERT_GE(blr.candidates_size(), 1);
  const pb::Assertion &w = blr.candidates(0);
  EXPECT_EQ(w.provenance().kind(), pb::PROVENANCE_KIND_MIGRATION);
  EXPECT_EQ(w.provenance().id(), "diff");
  EXPECT_EQ(w.provenance().version(), s);
  EXPECT_EQ(w.provenance().session(), r.run_id());
  EXPECT_NE(w.provenance().reason().find("from " + a_), std::string::npos);
  EXPECT_EQ(w.ported_from().program_id(), a_);
  EXPECT_EQ(w.ported_from().function().offset(), hash_a);
  EXPECT_NE(w.ported_from().source_seq(), 0u);  // DWARF's import assertion
  EXPECT_NE(w.ported_from().match_seq(), 0u);
  EXPECT_EQ(w.depends_on_seq(), w.ported_from().match_seq());
  // The comments landed at the same offsets (the bytes are equal).
  bl.mutable_key()->set_kind(pb::FACT_KIND_COMMENT);
  bl.mutable_key()->set_sub("eol");
  bl.mutable_key()->mutable_address()->set_offset(hash_b + 4);
  ASSERT_TRUE(backend_->Blame(ctx_, bl, blr).ok());
  EXPECT_EQ(blr.value_text(), "inside");
  // The prototype, by hash.
  bl.mutable_key()->set_kind(pb::FACT_KIND_TYPE);
  bl.mutable_key()->set_sub("");
  bl.mutable_key()->mutable_address()->set_offset(truth_b_.at("point_sum"));
  ASSERT_TRUE(backend_->Blame(ctx_, bl, blr).ok());
  EXPECT_NE(blr.value_text().find("point"), std::string::npos) << blr.value_text();

  // Applied pairs show as such.
  auto all = Matches(s);
  EXPECT_EQ(ByNameA(all, "hash_str")->status(), pb::DIFF_MATCH_STATUS_APPLIED);
  EXPECT_NE(ByNameA(all, "hash_str")->match_seq(), 0u);

  // Applying again ports nothing new.
  auto again = Apply(s);
  EXPECT_EQ(again.names(), 0u);
  EXPECT_TRUE(again.run_id().empty());

  // Revert the run: B is as before.
  pb::RevertApplyRequest rv;
  rv.set_project_id("default");
  rv.set_session_id(s);
  rv.set_run_id(r.run_id());
  *rv.mutable_provenance() = User();
  pb::RevertApplyResponse rvr;
  ASSERT_TRUE(backend_->RevertApply(ctx_, rv, rvr).ok());
  EXPECT_GT(rvr.retracted_seqs_size(), 0);
  EXPECT_TRUE(NameAt(b_, hash_b).starts_with("FUN_"));
  EXPECT_EQ(ByNameA(Matches(s), "hash_str")->status(), pb::DIFF_MATCH_STATUS_PROPOSED);
}

TEST_F(DiffApi, RetractingAMatchRemovesWhatWasPortedThroughIt) {
  const std::string s = Session();
  Wait(s);
  pb::ApplyMarkupRequest only;
  auto *pair = only.add_pairs();
  pair->mutable_entry_a()->set_offset(Functions(a_).at("sum_table"));
  pair->mutable_entry_b()->set_offset(truth_b_.at("sum_table"));
  only.add_items(pb::DIFF_MARKUP_ITEM_NAMES);
  auto r = Apply(s, only);
  EXPECT_EQ(r.names(), 1u);
  EXPECT_EQ(r.pairs(), 1u);
  EXPECT_EQ(NameAt(b_, truth_b_.at("sum_table")), "sum_table");
  const auto table = Matches(s);
  const auto m = ByNameA(table, "sum_table");
  ASSERT_TRUE(m);
  ASSERT_NE(m->match_seq(), 0u);
  pb::RetractAssertionsRequest rt;
  rt.set_program_id(b_);
  rt.add_seqs(m->match_seq());
  *rt.mutable_provenance() = User();
  pb::RetractAssertionsResponse rtr;
  ASSERT_TRUE(backend_->RetractAssertions(ctx_, rt, rtr).ok());
  EXPECT_TRUE(NameAt(b_, truth_b_.at("sum_table")).starts_with("FUN_"));
  // Undo of the retraction brings both back.
  pb::RetractAssertionsRequest undo;
  undo.set_program_id(b_);
  undo.add_seqs(rtr.retractions(0).seq());
  *undo.mutable_provenance() = User();
  ASSERT_TRUE(backend_->RetractAssertions(ctx_, undo, rtr).ok());
  EXPECT_EQ(NameAt(b_, truth_b_.at("sum_table")), "sum_table");
}

TEST_F(DiffApi, AcceptRejectAndSetMatch) {
  const std::string s = Session(false);
  // Without a run, reads compute the matches.
  auto all = Matches(s);
  const pb::DiffMatch *h = ByNameA(all, "hash_str");
  ASSERT_TRUE(h);
  const std::uint64_t ha = h->a().entry().offset(), hb = h->b().entry().offset();
  const std::uint64_t pa = Functions(a_).at("point_sum"), pbe = truth_b_.at("point_sum");

  pb::AcceptMatchesRequest acc;
  acc.set_project_id("default");
  acc.set_session_id(s);
  *acc.mutable_provenance() = User();
  auto *p = acc.add_pairs();
  p->mutable_entry_a()->set_offset(ha);
  p->mutable_entry_b()->set_offset(hb);
  pb::AcceptMatchesResponse ar;
  ASSERT_TRUE(backend_->AcceptMatches(ctx_, acc, ar).ok());
  ASSERT_EQ(ar.match_seqs_size(), 1);
  EXPECT_NE(ar.match_seqs(0), 0u);
  EXPECT_EQ(ByNameA(Matches(s), "hash_str")->status(), pb::DIFF_MATCH_STATUS_ACCEPTED);

  // Accepting a conflicting pair is refused; SetMatch replaces.
  p->mutable_entry_b()->set_offset(pbe);
  auto st = backend_->AcceptMatches(ctx_, acc, ar);
  EXPECT_EQ(st.code, StatusCode::kFailedPrecondition) << st.message;
  pb::SetMatchRequest set;
  set.set_project_id("default");
  set.set_session_id(s);
  set.mutable_entry_a()->set_offset(ha);
  set.mutable_entry_b()->set_offset(pbe);
  *set.mutable_provenance() = User();
  pb::SetMatchResponse sr;
  ASSERT_TRUE(backend_->SetMatch(ctx_, set, sr).ok());
  EXPECT_EQ(sr.retracted_seqs_size(), 1);
  auto now = Matches(s);
  const pb::DiffMatch *x = ByNameA(now, "hash_str");
  ASSERT_TRUE(x);
  EXPECT_EQ(x->b().entry().offset(), pbe);
  EXPECT_EQ(x->status(), pb::DIFF_MATCH_STATUS_ACCEPTED);
  EXPECT_EQ(x->tier(), pb::DIFF_TIER_ACCEPTED);
  // point_sum lost its partner to the manual match; it isn't matched to it.
  const pb::DiffMatch *y = ByNameA(now, "point_sum");
  EXPECT_TRUE(!y || y->b().entry().offset() != pbe);
  (void)pa;

  // Reject: the right pair is never proposed again, and the accepted one is retracted.
  pb::RejectMatchesRequest rej;
  rej.set_project_id("default");
  rej.set_session_id(s);
  *rej.mutable_provenance() = User();
  auto *rp = rej.add_pairs();
  rp->mutable_entry_a()->set_offset(ha);
  rp->mutable_entry_b()->set_offset(pbe);
  pb::RejectMatchesResponse rr;
  ASSERT_TRUE(backend_->RejectMatches(ctx_, rej, rr).ok());
  EXPECT_EQ(rr.retracted_seqs_size(), 1);
  auto after = Matches(s);
  const pb::DiffMatch *z = ByNameA(after, "hash_str");
  ASSERT_TRUE(z);
  EXPECT_EQ(z->b().entry().offset(), hb);  // the real partner again
  EXPECT_EQ(z->status(), pb::DIFF_MATCH_STATUS_PROPOSED);
}

TEST_F(DiffApi, EditsInvalidateTheSession) {
  const std::string s = Session();
  Wait(s);
  auto sink = std::make_shared<Sink>();
  std::unique_ptr<api::Subscription> sub;
  pb::SubscribeRequest sreq;
  sreq.set_project_id("default");
  ASSERT_TRUE(backend_->Subscribe(ctx_, sreq, sink, sub).ok());
  pb::AppendAssertionsRequest ren;
  ren.set_program_id(b_);
  *ren.mutable_provenance() = User();
  auto *rn = ren.add_assertions()->mutable_body()->mutable_rename();
  rn->mutable_target()->mutable_address()->set_offset(truth_b_.at("main"));
  rn->set_name("entry_main");
  pb::AppendAssertionsResponse rr;
  ASSERT_TRUE(backend_->AppendAssertions(ctx_, ren, rr).ok());
  bool invalidated = false;
  for (const auto &ev : sink->events())
    for (const auto &q : ev.invalidated())
      invalidated |= q.kind() == pb::QUERY_KIND_DIFF_SESSION && q.diff_session_id() == s;
  EXPECT_TRUE(invalidated);
  // The rename shows in the table (B's name), the match stays.
  const auto table = Matches(s);
  const pb::DiffMatch *m = ByNameA(table, "main");
  ASSERT_TRUE(m);
  EXPECT_EQ(m->b().name(), "entry_main");
}

TEST_F(DiffApi, ErrorsAndServerInfo) {
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_GE(info.api_minor(), 16u);
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "diff"), info.features().end());
  pb::ListMatchesRequest req;
  req.set_project_id("default");
  req.set_session_id("d000000000000");
  pb::ListMatchesResponse resp;
  EXPECT_EQ(backend_->ListMatches(ctx_, req, resp).code, StatusCode::kNotFound);
  pb::CreateDiffSessionRequest bad;
  bad.set_project_id("default");
  bad.set_program_a(a_);
  bad.set_program_b(a_);
  pb::CreateDiffSessionResponse br;
  EXPECT_EQ(backend_->CreateDiffSession(ctx_, bad, br).code, StatusCode::kInvalidArgument);
  // Match assertions are DiffService's.
  pb::AppendAssertionsRequest app;
  app.set_program_id(b_);
  *app.mutable_provenance() = User();
  app.add_assertions()->mutable_body()->mutable_diff_match()->set_session_id("x");
  pb::AppendAssertionsResponse ar;
  EXPECT_EQ(backend_->AppendAssertions(ctx_, app, ar).code, StatusCode::kInvalidArgument);
}


// --- Comparing any two functions (api_minor 54, feature "function-compare") ---

// A row of A with an EQUAL partner, not the entry: (A's, B's) addresses;
// one at another offset from its entry than its partner when there is one.
static std::pair<std::uint64_t, std::uint64_t> EqualPair(const pb::DiffDetail &d, std::uint64_t entry_a,
                                                         std::uint64_t entry_b = 0) {
  std::pair<std::uint64_t, std::uint64_t> first{0, 0};
  for (const auto &r : d.rows_a()) {
    if (r.status() != pb::DIFF_LINE_STATUS_EQUAL || r.partner() < 0 || r.address().offset() == entry_a) continue;
    const std::pair<std::uint64_t, std::uint64_t> x{r.address().offset(), d.rows_b(r.partner()).address().offset()};
    if (entry_b && x.first - entry_a != x.second - entry_b) return x;
    if (!first.first) first = x;
  }
  return first;
}

TEST_F(DiffApi, CompareAnyTwoFunctions) {
  const auto fa = Functions(a_);
  const std::uint64_t pa = fa.at("parse_flag"), pbe = truth_b_.at("parse_flag");
  auto compare = [&](const std::string &prog_a, std::uint64_t ea, const std::string &prog_b, std::uint64_t eb,
                     const std::string &session = "", bool markup = true) {
    pb::CompareFunctionsRequest req;
    req.set_project_id("default");
    req.set_program_a(prog_a);
    req.set_program_b(prog_b);
    req.mutable_entry_a()->set_offset(ea);
    req.mutable_entry_b()->set_offset(eb);
    req.set_session_id(session);
    req.set_markup(markup);
    pb::CompareFunctionsResponse resp;
    auto st = backend_->CompareFunctions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  };
  // Two programs, no session: parse_flag gained a case.
  auto r = compare(a_, pa, b_, pbe);
  EXPECT_EQ(r.a().function().name(), "parse_flag");
  EXPECT_TRUE(r.b().function().default_name());
  ASSERT_GT(r.detail().lines_size(), 3);
  EXPECT_GT(r.detail().hunks_size(), 0);
  EXPECT_GT(r.detail().summary().equal(), 0u);
  EXPECT_GT(r.detail().summary().inserted() + r.detail().summary().changed(), 0u);
  EXPECT_FALSE(r.detail().summary().text().empty());
  // strcmp is called on both sides: the calls correspond by name (B's
  // extra call is gained, to a function A calls too).
  for (const auto &ref : r.detail().references())
    if (ref.name() == "strcmp") {
      EXPECT_FALSE(ref.unmatched());
      EXPECT_EQ(ref.partner().name(), "strcmp");
    }
  // Markup: the signatures, the parameter paired by position.
  const pb::CompareMarkup &m = r.markup();
  EXPECT_TRUE(m.error_a().empty()) << m.error_a();
  EXPECT_TRUE(m.error_b().empty()) << m.error_b();
  EXPECT_NE(m.signature_a().find("parse_flag"), std::string::npos) << m.signature_a();
  EXPECT_TRUE(m.signature_set_a());
  EXPECT_FALSE(m.signature_set_b()) << m.signature_b();
  bool param = false;
  for (const auto &v : m.variables())
    if (v.has_a() && v.has_b() && v.a().kind() == pb::VARIABLE_KIND_PARAMETER) {
      param = true;
      EXPECT_EQ(v.evidence(), "parameter 1");
      EXPECT_EQ(v.a().parameter_index(), v.b().parameter_index());
      EXPECT_TRUE(v.a().named()) << v.a().name();
      EXPECT_FALSE(v.b().named()) << v.b().name();
    }
  EXPECT_TRUE(param);
  // In one program: two different functions, and a function with itself.
  auto two = compare(a_, fa.at("point_sum"), a_, fa.at("sum_table"), "", false);
  EXPECT_GT(two.detail().hunks_size(), 0);
  EXPECT_FALSE(two.has_markup());
  auto self = compare(a_, fa.at("hash_str"), a_, fa.at("hash_str"));
  EXPECT_EQ(self.detail().hunks_size(), 0);
  for (const auto &v : self.markup().variables()) {
    EXPECT_TRUE(v.has_a() && v.has_b()) << v.a().name() << " / " << v.b().name();
    EXPECT_EQ(v.a().storage_key(), v.b().storage_key());
  }
  // With a session: its matches, and the pair's match.
  const std::string s = Session();
  Wait(s);
  auto withs = compare("", pa, "", pbe, s, false);
  EXPECT_EQ(withs.match().b().entry().offset(), pbe);
  EXPECT_EQ(withs.detail().hunks_size(), r.detail().hunks_size());
  // Errors.
  pb::CompareFunctionsRequest bad;
  bad.set_project_id("default");
  bad.set_program_a(a_);
  bad.set_program_b(b_);
  bad.mutable_entry_a()->set_offset(pa);
  pb::CompareFunctionsResponse br;
  EXPECT_EQ(backend_->CompareFunctions(ctx_, bad, br).code, StatusCode::kInvalidArgument);
  bad.mutable_entry_b()->set_offset(pa + 1);
  EXPECT_EQ(backend_->CompareFunctions(ctx_, bad, br).code, StatusCode::kNotFound);
  bad.mutable_entry_b()->set_offset(pbe);
  bad.set_session_id(s);
  bad.set_program_b(a_);
  EXPECT_EQ(backend_->CompareFunctions(ctx_, bad, br).code, StatusCode::kInvalidArgument);
}

TEST_F(DiffApi, PortFunctionMarkupItemsAndEverything) {
  const std::uint64_t pa = Functions(a_).at("parse_flag"), pbe = truth_b_.at("parse_flag");
  auto port = [&](const std::string &from_prog, std::uint64_t from, const std::string &to_prog, std::uint64_t to,
                  std::vector<pb::FunctionMarkupItem> items, bool overwrite = false, bool dry = false) {
    pb::PortFunctionMarkupRequest req;
    req.set_project_id("default");
    req.set_from_program(from_prog);
    req.mutable_from_entry()->set_offset(from);
    req.set_to_program(to_prog);
    req.mutable_to_entry()->set_offset(to);
    for (auto &i : items) *req.add_items() = i;
    req.set_overwrite(overwrite);
    req.set_dry_run(dry);
    *req.mutable_provenance() = User();
    pb::PortFunctionMarkupResponse resp;
    auto st = backend_->PortFunctionMarkup(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  };
  auto item = [](pb::FunctionMarkupKind k, const std::string &var = "") {
    pb::FunctionMarkupItem i;
    i.set_kind(k);
    i.set_variable(var);
    return i;
  };
  // An instruction comment in A's parse_flag, at an instruction that has a partner in B.
  pb::CompareFunctionsRequest cr;
  cr.set_project_id("default");
  cr.set_program_a(a_);
  cr.set_program_b(b_);
  cr.mutable_entry_a()->set_offset(pa);
  cr.mutable_entry_b()->set_offset(pbe);
  pb::CompareFunctionsResponse before;
  ASSERT_TRUE(backend_->CompareFunctions(ctx_, cr, before).ok());
  const auto [ia, ib] = EqualPair(before.detail(), pa);
  ASSERT_NE(ia, 0u);
  pb::AppendAssertionsRequest com;
  com.set_program_id(a_);
  *com.mutable_provenance() = User();
  auto *c = com.add_assertions()->mutable_body()->mutable_comment();
  c->mutable_address()->set_offset(ia);
  c->set_kind(pb::COMMENT_KIND_EOL);
  c->set_text("the first flag");
  pb::AppendAssertionsResponse comr;
  ASSERT_TRUE(backend_->AppendAssertions(ctx_, com, comr).ok());

  // A dry run says what everything would be, and commits nothing.
  auto dry = port(a_, pa, b_, pbe, {}, false, true);
  EXPECT_EQ(dry.names(), 1u);
  EXPECT_EQ(dry.signatures(), 1u);
  EXPECT_EQ(dry.comments(), 1u);
  EXPECT_GE(dry.variable_names(), 1u);
  EXPECT_TRUE(dry.seqs().empty());
  EXPECT_NE(NameAt(b_, pbe), "parse_flag");

  // Everything: one revision, undone by retracting its seqs.
  auto all = port(a_, pa, b_, pbe, {});
  ASSERT_FALSE(all.seqs().empty());
  EXPECT_EQ(NameAt(b_, pbe), "parse_flag");
  bool named = false, commented = false;
  for (const auto &x : all.ported()) {
    named |= x.kind() == pb::FUNCTION_MARKUP_KIND_NAME && x.after() == "parse_flag";
    commented |= x.kind() == pb::FUNCTION_MARKUP_KIND_COMMENT && x.address().offset() == ib && x.comment_kind() == "eol";
  }
  EXPECT_TRUE(named && commented);
  pb::CompareFunctionsResponse after;
  cr.set_markup(true);
  ASSERT_TRUE(backend_->CompareFunctions(ctx_, cr, after).ok());
  bool comment_b = false;
  for (const auto &x : after.markup().comments())
    comment_b |= x.address_b().offset() == ib && x.text_b() == "the first flag" && x.text_a() == "the first flag";
  EXPECT_TRUE(comment_b);
  for (const auto &v : after.markup().variables())
    if (v.has_a() && v.has_b() && v.a().named()) EXPECT_EQ(v.a().name(), v.b().name());
  // Who and from where: the user, ported_from A's function.
  pb::BlameRequest bl;
  *bl.mutable_key() = [&] {
    pb::FactKey k;
    k.set_program_id(b_);
    k.set_kind(pb::FACT_KIND_NAME);
    k.mutable_address()->set_offset(pbe);
    return k;
  }();
  pb::BlameResponse blr;
  ASSERT_TRUE(backend_->Blame(ctx_, bl, blr).ok());
  ASSERT_GT(blr.candidates_size(), 0);
  EXPECT_EQ(blr.candidates(0).provenance().kind(), pb::PROVENANCE_KIND_USER);
  EXPECT_EQ(blr.candidates(0).ported_from().program_id(), a_);
  EXPECT_EQ(blr.candidates(0).ported_from().function().offset(), pa);
  // Again: nothing left to port.
  auto again = port(a_, pa, b_, pbe, {}, false, true);
  EXPECT_EQ(again.names() + again.signatures() + again.comments() + again.variable_names(), 0u);
  pb::RetractAssertionsRequest undo;
  undo.set_program_id(b_);
  for (auto q : all.seqs()) undo.add_seqs(q);
  *undo.mutable_provenance() = User();
  pb::RetractAssertionsResponse ur;
  ASSERT_TRUE(backend_->RetractAssertions(ctx_, undo, ur).ok());
  EXPECT_NE(NameAt(b_, pbe), "parse_flag");

  // Single items: only the name.
  auto name = port(a_, pa, b_, pbe, {item(pb::FUNCTION_MARKUP_KIND_NAME)});
  EXPECT_EQ(name.names(), 1u);
  EXPECT_EQ(name.signatures() + name.comments() + name.variable_names(), 0u);
  EXPECT_EQ(name.seqs_size(), 1);
  // The other way, B to A: A's name isn't a default one; only with overwrite.
  pb::AppendAssertionsRequest ren;
  ren.set_program_id(b_);
  *ren.mutable_provenance() = User();
  auto *rn = ren.add_assertions()->mutable_body()->mutable_rename();
  rn->mutable_target()->mutable_address()->set_offset(pbe);
  rn->set_name("flag_of");
  pb::AppendAssertionsResponse rr;
  ASSERT_TRUE(backend_->AppendAssertions(ctx_, ren, rr).ok());
  auto back = port(b_, pbe, a_, pa, {item(pb::FUNCTION_MARKUP_KIND_NAME)});
  EXPECT_EQ(back.names(), 0u);
  EXPECT_EQ(back.skipped(), 1u);
  back = port(b_, pbe, a_, pa, {item(pb::FUNCTION_MARKUP_KIND_NAME)}, true);
  EXPECT_EQ(back.names(), 1u);
  EXPECT_EQ(NameAt(a_, pa), "flag_of");
  // A variable by its storage key; a default name isn't ported.
  std::string named_key, default_key;
  for (const auto &v : after.markup().variables()) {
    if (!v.has_a() || !v.has_b()) continue;
    if (v.a().named() && named_key.empty()) named_key = v.a().storage_key();
  }
  if (!named_key.empty()) {
    auto one = port(a_, pa, b_, pbe, {item(pb::FUNCTION_MARKUP_KIND_VARIABLE_NAME, named_key)});
    EXPECT_EQ(one.variable_names(), 1u);
    EXPECT_EQ(one.ported_size(), 1);
  }
  auto none = port(a_, pa, b_, pbe, {item(pb::FUNCTION_MARKUP_KIND_VARIABLE_NAME, "stack:-0x9999")});
  EXPECT_EQ(none.variable_names(), 0u);
  EXPECT_FALSE(none.warnings().empty());
  // Errors.
  pb::PortFunctionMarkupRequest bad;
  bad.set_project_id("default");
  bad.set_from_program(a_);
  bad.set_to_program(a_);
  bad.mutable_from_entry()->set_offset(pa);
  bad.mutable_to_entry()->set_offset(pa);
  pb::PortFunctionMarkupResponse badr;
  EXPECT_EQ(backend_->PortFunctionMarkup(ctx_, bad, badr).code, StatusCode::kInvalidArgument);
}

// ApplyMarkup ports instruction comments of a pair whose code changed by
// the instruction map (api_minor 54); before, only equal bytes did.
// Globals and callees (api_minor 71): what the aligned instructions
// reference gets A's names and types: sum_table's table, main's callees
// and their signatures; Apply all carries them too, one undo step.
TEST_F(DiffApi, PortFunctionMarkupGlobalsAndCallees) {
  auto port = [&](std::uint64_t from, std::uint64_t to, std::vector<pb::FunctionMarkupItem> items, bool dry = false,
                  bool overwrite = false) {
    pb::PortFunctionMarkupRequest req;
    req.set_project_id("default");
    req.set_from_program(a_);
    req.mutable_from_entry()->set_offset(from);
    req.set_to_program(b_);
    req.mutable_to_entry()->set_offset(to);
    for (auto &i : items) *req.add_items() = i;
    req.set_dry_run(dry);
    req.set_overwrite(overwrite);
    *req.mutable_provenance() = User();
    pb::PortFunctionMarkupResponse resp;
    auto st = backend_->PortFunctionMarkup(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  };
  auto item = [](pb::FunctionMarkupKind k) {
    pb::FunctionMarkupItem i;
    i.set_kind(k);
    return i;
  };
  auto symbol = [&](const std::string &program, const std::string &name) -> std::optional<std::uint64_t> {
    pb::ListSymbolsRequest ls;
    ls.set_program_id(program);
    ls.set_name_equals(name);
    pb::ListSymbolsResponse r;
    EXPECT_TRUE(backend_->ListSymbols(ctx_, ls, r).ok());
    if (r.symbols_size() == 0) return std::nullopt;
    return r.symbols(0).address().offset();
  };
  const auto fa = Functions(a_);
  // sum_table's global: table, by name and type (over whatever the stripped
  // build's dynamic symbols call that spot: overwrite).
  ASSERT_FALSE(symbol(b_, "table").has_value());
  auto g = port(fa.at("sum_table"), truth_b_.at("sum_table"),
                {item(pb::FUNCTION_MARKUP_KIND_GLOBAL_NAME), item(pb::FUNCTION_MARKUP_KIND_GLOBAL_TYPE)}, false, true);
  EXPECT_GE(g.globals(), 1u) << g.DebugString();
  auto at = symbol(b_, "table");
  ASSERT_TRUE(at.has_value()) << g.DebugString();
  bool typed = false;
  for (const auto &x : g.ported())
    if (x.kind() == pb::FUNCTION_MARKUP_KIND_GLOBAL_TYPE && x.address().offset() == *at) typed = x.after().find("int") != std::string::npos;
  EXPECT_TRUE(typed) << g.DebugString();
  // main's callees: a dry run of everything counts them; then their names and signatures.
  const std::uint64_t ma = fa.at("main"), mb = truth_b_.at("main");
  auto dry = port(ma, mb, {}, true);
  EXPECT_GE(dry.callees(), 3u) << dry.DebugString();
  // One item: a callee by its address.
  pb::FunctionMarkupItem one = item(pb::FUNCTION_MARKUP_KIND_CALLEE_NAME);
  one.mutable_address()->set_offset(fa.at("parse_flag"));
  auto single = port(ma, mb, {one}, true);
  ASSERT_EQ(single.ported_size(), 1) << single.DebugString();
  EXPECT_EQ(single.ported(0).address().offset(), truth_b_.at("parse_flag"));
  EXPECT_EQ(single.ported(0).after(), "parse_flag");
  auto c = port(ma, mb, {item(pb::FUNCTION_MARKUP_KIND_CALLEE_NAME), item(pb::FUNCTION_MARKUP_KIND_CALLEE_SIGNATURE)});
  ASSERT_FALSE(c.seqs().empty()) << c.DebugString();
  EXPECT_EQ(NameAt(b_, truth_b_.at("hash_str")), "hash_str");
  EXPECT_EQ(NameAt(b_, truth_b_.at("point_sum")), "point_sum");
  bool signed_up = false;
  for (const auto &x : c.ported())
    if (x.kind() == pb::FUNCTION_MARKUP_KIND_CALLEE_SIGNATURE && x.address().offset() == truth_b_.at("point_sum"))
      signed_up = x.after().find("point") != std::string::npos;
  EXPECT_TRUE(signed_up) << c.DebugString();
}

TEST_F(DiffApi, ApplyPortsInstructionCommentsByAlignedInstruction) {
  const std::string s = Session();
  Wait(s);
  const std::uint64_t pa = Functions(a_).at("parse_flag"), pbe = truth_b_.at("parse_flag");
  pb::GetFunctionDiffRequest g;
  g.set_project_id("default");
  g.set_session_id(s);
  g.mutable_entry_a()->set_offset(pa);
  g.set_detail(true);
  pb::GetFunctionDiffResponse gr;
  ASSERT_TRUE(backend_->GetFunctionDiff(ctx_, g, gr).ok());
  ASSERT_EQ(gr.match().change_kind(), pb::DIFF_CHANGE_KIND_MODIFIED);
  // Before api_minor 54 only function-level comments of a modified pair went.
  const auto [ia, ib] = EqualPair(gr.detail(), pa, pbe);
  ASSERT_NE(ia, 0u);
  pb::AppendAssertionsRequest com;
  com.set_program_id(a_);
  *com.mutable_provenance() = User();
  auto *c = com.add_assertions()->mutable_body()->mutable_comment();
  c->mutable_address()->set_offset(ia);
  c->set_kind(pb::COMMENT_KIND_PRE);
  c->set_text("checks --verbose");
  pb::AppendAssertionsResponse comr;
  ASSERT_TRUE(backend_->AppendAssertions(ctx_, com, comr).ok());
  pb::ApplyMarkupRequest req;
  auto *pair = req.add_pairs();
  pair->mutable_entry_a()->set_offset(pa);
  pair->mutable_entry_b()->set_offset(pbe);
  req.add_items(pb::DIFF_MARKUP_ITEM_COMMENTS);
  auto r = Apply(s, req);
  EXPECT_EQ(r.comments(), 1u);
  ASSERT_TRUE(backend_->GetFunctionDiff(ctx_, g, gr).ok());
  bool found = false;
  for (const auto &row : gr.detail().rows_b())
    if (row.address().offset() == ib) found = row.comment().find("checks --verbose") != std::string::npos;
  EXPECT_TRUE(found);
}

TEST_F(DiffApi, UnmatchAndUndoingDecisions) {
  const std::string s = Session(false);
  auto all = Matches(s);
  const pb::DiffMatch *h = ByNameA(all, "hash_str");
  ASSERT_TRUE(h);
  const std::uint64_t ha = h->a().entry().offset(), hb = h->b().entry().offset();
  const std::uint64_t pbe = truth_b_.at("point_sum");
  auto pairs = [](std::uint64_t a, std::uint64_t b, auto *req) {
    auto *p = req->add_pairs();
    p->mutable_entry_a()->set_offset(a);
    p->mutable_entry_b()->set_offset(b);
  };
  auto retract = [&](const auto &seqs) {
    pb::RetractAssertionsRequest u;
    u.set_program_id(b_);
    for (auto q : seqs) u.add_seqs(q);
    *u.mutable_provenance() = User();
    pb::RetractAssertionsResponse ur;
    auto st = backend_->RetractAssertions(ctx_, u, ur);
    EXPECT_TRUE(st.ok()) << st.message;
  };
  auto status = [&] { return ByNameA(Matches(s), "hash_str")->status(); };
  // Accept, and undo it by retracting the decision's ops.
  pb::AcceptMatchesRequest acc;
  acc.set_project_id("default");
  acc.set_session_id(s);
  *acc.mutable_provenance() = User();
  pairs(ha, hb, &acc);
  pb::AcceptMatchesResponse ar;
  ASSERT_TRUE(backend_->AcceptMatches(ctx_, acc, ar).ok());
  ASSERT_EQ(ar.seqs_size(), 1);
  EXPECT_EQ(status(), pb::DIFF_MATCH_STATUS_ACCEPTED);
  retract(ar.seqs());
  EXPECT_EQ(status(), pb::DIFF_MATCH_STATUS_PROPOSED);
  // Unmatch an accepted match: proposed again; undoing the unmatch brings it back.
  ASSERT_TRUE(backend_->AcceptMatches(ctx_, acc, ar).ok());
  pb::UnmatchRequest un;
  un.set_project_id("default");
  un.set_session_id(s);
  *un.mutable_provenance() = User();
  pairs(ha, hb, &un);
  pb::UnmatchResponse unr;
  ASSERT_TRUE(backend_->Unmatch(ctx_, un, unr).ok());
  EXPECT_EQ(unr.retracted_seqs_size(), 1);
  EXPECT_EQ(unr.seqs_size(), 1);
  EXPECT_EQ(status(), pb::DIFF_MATCH_STATUS_PROPOSED);
  retract(unr.seqs());
  EXPECT_EQ(status(), pb::DIFF_MATCH_STATUS_ACCEPTED);
  // A manual match replaces it (a retraction and an assertion, one step);
  // unmatching it gives hash_str its own partner back.
  pb::SetMatchRequest set;
  set.set_project_id("default");
  set.set_session_id(s);
  set.mutable_entry_a()->set_offset(ha);
  set.mutable_entry_b()->set_offset(pbe);
  *set.mutable_provenance() = User();
  pb::SetMatchResponse sr;
  ASSERT_TRUE(backend_->SetMatch(ctx_, set, sr).ok());
  EXPECT_EQ(sr.seqs_size(), 2);
  EXPECT_EQ(ByNameA(Matches(s), "hash_str")->b().entry().offset(), pbe);
  pb::UnmatchRequest un2 = un;
  un2.clear_pairs();
  pairs(ha, pbe, &un2);
  ASSERT_TRUE(backend_->Unmatch(ctx_, un2, unr).ok());
  EXPECT_EQ(ByNameA(Matches(s), "hash_str")->b().entry().offset(), hb);
  EXPECT_EQ(status(), pb::DIFF_MATCH_STATUS_PROPOSED);
  // A rejection is a decision too: unmatching the pair lifts it.
  pb::RejectMatchesRequest rej;
  rej.set_project_id("default");
  rej.set_session_id(s);
  *rej.mutable_provenance() = User();
  pairs(ha, hb, &rej);
  pb::RejectMatchesResponse rr;
  ASSERT_TRUE(backend_->RejectMatches(ctx_, rej, rr).ok());
  EXPECT_GE(rr.seqs_size(), 1);
  const pb::DiffMatch *gone = ByNameA(Matches(s), "hash_str");
  EXPECT_TRUE(!gone || gone->b().entry().offset() != hb);
  ASSERT_TRUE(backend_->Unmatch(ctx_, un, unr).ok());
  EXPECT_EQ(ByNameA(Matches(s), "hash_str")->b().entry().offset(), hb);
  // Nothing to undo.
  EXPECT_EQ(backend_->Unmatch(ctx_, un, unr).code, StatusCode::kFailedPrecondition);
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "function-compare"), info.features().end());
}

}  // namespace
}  // namespace revkit::backend
