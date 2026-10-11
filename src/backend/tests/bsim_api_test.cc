// BSimService through the image backend (docs/bsim.md): a database created
// at a path and attached, a program ingested (its functions signed under
// the database's settings, with names, prototypes and sizes), listed,
// ingested again (replaced), its categories changed, deleted; a second
// build of the same source ingested beside it finds its counterparts by
// similarity; the errors a caller can make.
#include "builders.hh"

#include "revkit/backend/image_backend.h"
#include "revkit/bsim/store.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <map>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;
namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

constexpr const char *kSource = R"(
#include <stddef.h>
volatile int sink;
__attribute__((noinline)) unsigned checksum(const unsigned char *p, size_t n) {
  unsigned h = 2166136261u;
  for (size_t i = 0; i < n; ++i) h = (h ^ p[i]) * 16777619u;
  return h;
}
__attribute__((noinline)) void reverse(char *s, size_t n) {
  for (size_t i = 0, j = n ? n - 1 : 0; i < j; ++i, --j) { char t = s[i]; s[i] = s[j]; s[j] = t; }
}
__attribute__((noinline)) int classify(int c) {
  switch (c) {
    case 0: return 10; case 1: return 22; case 2: return 37; case 3: return 41;
    case 4: return 58; case 5: return 63; case 6: return 79; default: return -1;
  }
}
__attribute__((noinline)) long fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
__attribute__((noinline)) int count_bits(unsigned long x) { int n = 0; while (x) { x &= x - 1; ++n; } return n; }
__attribute__((noinline)) int find_max(const int *a, int n) {
  int m = a[0];
  for (int i = 1; i < n; ++i) if (a[i] > m) m = a[i];
  return m;
}
int main(int argc, char **argv) {
  char buf[16] = "hello";
  int a[4] = {argc, 3, 9, 1};
  reverse(buf, 5);
  sink = (int)checksum((const unsigned char *)argv[0], 4) + classify(argc) + (int)fib(argc + 5) +
         count_bits((unsigned long)argc) + find_max(a, 4);
  return buf[0];
}
)";

class BsimApi : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    dir_ = testing::scratch_dir("bsim-api");
    built_ = testing::compile(REVKIT_TEST_CC, kSource, "-O1 -g", dir_ / "a.out") &&
             testing::compile(REVKIT_TEST_CC, kSource, "-O2 -fno-inline", dir_ / "b.out");
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!built_) GTEST_SKIP() << "no C compiler";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    b_ = MakeImageBackend(o);
    db_ = (dir_ / ("db-" + std::string(::testing::UnitTest::GetInstance()->current_test_info()->name()) + ".rkbsim")).string();
    fs::remove_all(db_);
  }

  std::string Import(const fs::path &path, const std::string &name) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(path.string());
    req.set_name(name);
    pb::ImportProgramResponse resp;
    auto st = b_->ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  pb::BSimDatabase Create() {
    pb::CreateBSimDatabaseRequest req;
    req.set_project_id("default");
    req.set_path(db_);
    req.set_name("test");
    req.set_description("bsim api test");
    pb::CreateBSimDatabaseResponse resp;
    auto st = b_->CreateBSimDatabase(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.database();
  }

  pb::IngestBSimResponse Ingest(const std::vector<std::string> &programs, std::map<std::string, std::string> cats = {}) {
    pb::IngestBSimRequest req;
    req.set_project_id("default");
    req.set_database(db_);
    for (const auto &p : programs) req.add_program_ids(p);
    for (const auto &[k, v] : cats) (*req.mutable_categories())[k] = v;
    req.set_threads(2);
    pb::IngestBSimResponse resp;
    auto st = b_->IngestBSim(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  std::vector<pb::BSimExecutable> Executables() {
    pb::ListBSimExecutablesRequest req;
    req.set_project_id("default");
    req.set_database(db_);
    pb::ListBSimExecutablesResponse resp;
    EXPECT_TRUE(b_->ListBSimExecutables(ctx_, req, resp).ok());
    return {resp.executables().begin(), resp.executables().end()};
  }

  pb::ListBSimFunctionsResponse Functions(const std::string &exe, const std::string &name = {}) {
    pb::ListBSimFunctionsRequest req;
    req.set_project_id("default");
    req.set_database(db_);
    req.set_executable(exe);
    req.set_name_contains(name);
    pb::ListBSimFunctionsResponse resp;
    auto st = b_->ListBSimFunctions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  static inline fs::path dir_;
  static inline bool built_ = false;
  std::shared_ptr<api::Backend> b_;
  std::string db_;
  CallContext ctx_;
};

TEST_F(BsimApi, CreateIngestListReplaceDelete) {
  const pb::BSimDatabase d = Create();
  EXPECT_EQ(d.id(), db_);
  EXPECT_EQ(d.template_(), pb::BSIM_TEMPLATE_64);
  EXPECT_EQ(d.settings(), 0x49u);
  EXPECT_EQ(d.executables(), 0u);

  pb::ListBSimDatabasesRequest lreq;
  lreq.set_project_id("default");
  pb::ListBSimDatabasesResponse lresp;
  ASSERT_TRUE(b_->ListBSimDatabases(ctx_, lreq, lresp).ok());
  ASSERT_EQ(lresp.databases_size(), 1);
  EXPECT_EQ(lresp.databases(0).name(), "test");
  EXPECT_TRUE(lresp.databases(0).error().empty());

  const std::string a = Import(dir_ / "a.out", "prog-O1");
  auto ing = Ingest({a}, {{"build", "O1"}});
  ASSERT_EQ(ing.programs_size(), 1);
  const pb::BSimIngested &r = ing.programs(0);
  EXPECT_FALSE(r.replaced());
  EXPECT_GE(r.functions(), 7u);
  EXPECT_TRUE(r.warning().empty()) << r.warning();
  EXPECT_EQ(r.executable().name(), "prog-O1");
  EXPECT_EQ(r.executable().id().size(), 64u);
  EXPECT_EQ(r.executable().language().substr(0, 9), "x86:LE:64");
  EXPECT_EQ(r.executable().source(), "daemon:" + a);
  EXPECT_EQ(r.executable().categories().at("build"), "O1");
  EXPECT_EQ(r.executable().function_count(), r.functions());

  auto exes = Executables();
  ASSERT_EQ(exes.size(), 1u);
  const std::string id = exes[0].id();
  auto fns = Functions(id, "checksum");
  ASSERT_EQ(fns.functions_size(), 1);
  EXPECT_EQ(fns.functions(0).name(), "checksum");
  EXPECT_GT(fns.functions(0).size(), 0u);
  EXPECT_GT(fns.functions(0).feature_count(), 5u);
  EXPECT_FALSE(fns.functions(0).default_name());
  EXPECT_NE(fns.functions(0).prototype().find("checksum("), std::string::npos) << fns.functions(0).prototype();
  EXPECT_EQ(Functions("prog-O1").total(), r.functions());  // by name too
  EXPECT_EQ(Functions(id.substr(0, 8)).total(), r.functions());  // and id prefix

  // Ingested again: replaced, still one executable.
  auto again = Ingest({a});
  EXPECT_TRUE(again.programs(0).replaced());
  EXPECT_EQ(Executables().size(), 1u);
  EXPECT_TRUE(Executables()[0].categories().empty());

  pb::UpdateBSimExecutableRequest u;
  u.set_project_id("default");
  u.set_database(db_);
  u.set_executable(id);
  u.set_name("renamed");
  (*u.mutable_categories())["vendor"] = "me";
  u.set_set_categories(true);
  pb::UpdateBSimExecutableResponse ur;
  ASSERT_TRUE(b_->UpdateBSimExecutable(ctx_, u, ur).ok());
  EXPECT_EQ(ur.executable().name(), "renamed");
  EXPECT_EQ(ur.executable().categories().at("vendor"), "me");

  // The files are the database: another reader sees it all.
  bsim::Database direct = bsim::Database::open(db_);
  ASSERT_NE(direct.executable(id), nullptr);
  EXPECT_EQ(direct.executable(id)->name, "renamed");

  pb::DeleteBSimExecutablesRequest del;
  del.set_project_id("default");
  del.set_database(db_);
  del.add_executables(id);
  del.add_executables("nonesuch");
  pb::DeleteBSimExecutablesResponse dr;
  ASSERT_TRUE(b_->DeleteBSimExecutables(ctx_, del, dr).ok());
  EXPECT_EQ(dr.deleted(), 1u);
  ASSERT_EQ(dr.missing_size(), 1);
  EXPECT_TRUE(Executables().empty());
}

// Two builds (-O1 with debug info, -O2): each of B's named functions finds
// A's counterpart first among A's functions, scoring every function (gcc
// -O2 turns fib's recursion into a loop: cosine 0.19, still the best); LSH
// alone finds those above 0.7.
TEST_F(BsimApi, ASecondBuildFindsItsCounterparts) {
  Create();
  const std::string a = Import(dir_ / "a.out", "prog-O1");
  const std::string b = Import(dir_ / "b.out", "prog-O2");
  auto ing = Ingest({a, b});
  ASSERT_EQ(ing.programs_size(), 2);
  const std::string ida = ing.programs(0).executable().id(), idb = ing.programs(1).executable().id();
  ASSERT_NE(ida, idb);
  bsim::Database db = bsim::Database::open(db_);
  int named = 0, found = 0, high = 0;
  for (const char *name : {"checksum", "reverse", "classify", "fib", "count_bits", "find_max"}) {
    const bsim::FunctionRecord *q = nullptr;
    for (const auto &f : db.functions(idb))
      if (f.name == name) q = &f;
    if (!q) continue;
    ++named;
    bsim::SearchOptions o;
    o.executables = {ida};
    o.min_similarity = 0;
    auto m = db.search(q->features, o);
    ASSERT_FALSE(m.empty()) << name;
    if (m[0].function->name == name) ++found;
    else ADD_FAILURE() << name << ": " << m[0].function->name << " " << m[0].similarity;
    if (m[0].similarity >= 0.7) {
      ++high;
      bsim::SearchOptions lsh = o;
      lsh.exhaustive_below = 0;
      lsh.min_similarity = 0.7;
      auto l = db.search(q->features, lsh);
      ASSERT_FALSE(l.empty()) << name << " at " << m[0].similarity;
      EXPECT_EQ(l[0].function, m[0].function) << name;
    }
  }
  EXPECT_GE(named, 5);
  EXPECT_EQ(found, named);
  EXPECT_GE(high, 2);
}

// SearchBSim (api_minor 72): B's functions against a database holding A;
// the hit names A's program (in this project); the query's own file is left
// out unless include_self; an overview counts without matches; filters.
TEST_F(BsimApi, SearchFindsCounterpartsAndCounts) {
  Create();
  const std::string a = Import(dir_ / "a.out", "prog-O1");
  const std::string b = Import(dir_ / "b.out", "prog-O2");
  Ingest({a});
  auto search = [&](pb::SearchBSimRequest req) {
    req.set_project_id("default");
    req.set_database(db_);
    req.set_program_id(b);
    req.set_threads(2);
    pb::SearchBSimResponse resp;
    auto st = b_->SearchBSim(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  };
  std::map<std::string, std::uint64_t> entries;
  {
    pb::ListFunctionsRequest l;
    l.set_program_id(b);
    pb::ListFunctionsResponse lr;
    ASSERT_TRUE(b_->ListFunctions(ctx_, l, lr).ok());
    for (const auto &f : lr.functions()) entries[f.name()] = f.entry().offset();
  }
  ASSERT_TRUE(entries.contains("checksum") && entries.contains("classify"));

  pb::SearchBSimRequest one;
  one.add_functions()->set_offset(entries["checksum"]);
  one.add_functions()->set_offset(entries["classify"] + 1);  // inside it: the function containing
  one.set_min_similarity(0);
  one.set_max_matches(3);
  auto r = search(one);
  ASSERT_EQ(r.results_size(), 2);
  for (const auto &q : r.results()) {
    ASSERT_GT(q.matches_size(), 0) << q.name();
    EXPECT_EQ(q.matches(0).function().name(), q.name());
    EXPECT_EQ(q.matches(0).program_id(), a);
    EXPECT_EQ(q.matches(0).executable().name(), "prog-O1");
    EXPECT_GT(q.feature_count(), 0u);
    EXPECT_GT(q.self_significance(), 0);
    EXPECT_LE(q.matches_size(), 3);
    EXPECT_GE(q.hit_count(), static_cast<std::uint32_t>(q.matches_size()));
  }
  EXPECT_GT(r.total(), 0u);

  // Every function; an overview has counts and no matches.
  pb::SearchBSimRequest all;
  all.set_all_functions(true);
  all.set_overview(true);
  all.set_min_similarity(0.5);
  r = search(all);
  EXPECT_GE(r.results_size(), 7);
  int with_hits = 0;
  for (const auto &q : r.results()) {
    EXPECT_EQ(q.matches_size(), 0);
    if (q.hit_count() > 0) ++with_hits;
  }
  EXPECT_GE(with_hits, 3);

  // The query's own file: left out unless include_self.
  Ingest({b});
  one.clear_functions();
  one.add_functions()->set_offset(entries["checksum"]);
  one.set_min_similarity(0.999);
  r = search(one);
  for (const auto &m : r.results(0).matches()) EXPECT_NE(m.executable().name(), "prog-O2");
  one.set_include_self(true);
  r = search(one);
  bool self = false;
  for (const auto &m : r.results(0).matches())
    if (m.executable().name() == "prog-O2" && m.similarity() > 0.9999) self = true;
  std::string seen;
  for (const auto &m : r.results(0).matches())
    seen += m.executable().name() + ":" + m.function().name() + "@" + std::to_string(m.similarity()) + " ";
  EXPECT_TRUE(self) << "its own function, at 1.0: " << seen << " hits " << r.results(0).hit_count();
  // Filters: an executable that isn't there, a name.
  one.add_executables("nonesuch");
  EXPECT_EQ(search(one).results(0).matches_size(), 0);
  one.clear_executables();
  one.set_min_similarity(0);
  one.set_name_contains("CLASSIFY");
  const pb::SearchBSimResponse named = search(one);
  for (const auto &m : named.results(0).matches()) EXPECT_EQ(m.function().name(), "classify");

  // Errors: nothing asked; no function there.
  pb::SearchBSimRequest none;
  pb::SearchBSimResponse nr;
  none.set_project_id("default");
  none.set_database(db_);
  none.set_program_id(b);
  EXPECT_EQ(b_->SearchBSim(ctx_, none, nr).code, StatusCode::kInvalidArgument);
  none.add_functions()->set_offset(1);
  EXPECT_EQ(b_->SearchBSim(ctx_, none, nr).code, StatusCode::kNotFound);
}

TEST_F(BsimApi, Errors) {
  // Not attached.
  pb::ListBSimExecutablesRequest l;
  l.set_project_id("default");
  l.set_database("/nonexistent/x.rkbsim");
  pb::ListBSimExecutablesResponse lr;
  EXPECT_EQ(b_->ListBSimExecutables(ctx_, l, lr).code, StatusCode::kNotFound);
  // A relative path; by name in an in-memory project.
  pb::CreateBSimDatabaseRequest c;
  c.set_project_id("default");
  c.set_path("relative.rkbsim");
  pb::CreateBSimDatabaseResponse cr;
  EXPECT_EQ(b_->CreateBSimDatabase(ctx_, c, cr).code, StatusCode::kInvalidArgument);
  c.clear_path();
  c.set_name("x");
  EXPECT_EQ(b_->CreateBSimDatabase(ctx_, c, cr).code, StatusCode::kFailedPrecondition);
  // Created twice.
  Create();
  c.set_path(db_);
  EXPECT_EQ(b_->CreateBSimDatabase(ctx_, c, cr).code, StatusCode::kAlreadyExists);
  // Attaching something that isn't a database.
  pb::AttachBSimDatabaseRequest at;
  at.set_project_id("default");
  at.set_path(dir_.string());
  pb::AttachBSimDatabaseResponse ar;
  EXPECT_EQ(b_->AttachBSimDatabase(ctx_, at, ar).code, StatusCode::kInvalidArgument);
  // Detached: gone from the list; attached again by path.
  pb::DetachBSimDatabaseRequest d;
  d.set_project_id("default");
  d.set_database(db_);
  pb::DetachBSimDatabaseResponse dr;
  ASSERT_TRUE(b_->DetachBSimDatabase(ctx_, d, dr).ok());
  EXPECT_EQ(b_->DetachBSimDatabase(ctx_, d, dr).code, StatusCode::kNotFound);
  at.set_path(db_);
  ASSERT_TRUE(b_->AttachBSimDatabase(ctx_, at, ar).ok());
  EXPECT_EQ(ar.database().name(), "test");
  // No programs; an unknown program.
  pb::IngestBSimRequest in;
  in.set_project_id("default");
  in.set_database(db_);
  pb::IngestBSimResponse inr;
  EXPECT_EQ(b_->IngestBSim(ctx_, in, inr).code, StatusCode::kInvalidArgument);
  in.add_program_ids("nope");
  EXPECT_EQ(b_->IngestBSim(ctx_, in, inr).code, StatusCode::kNotFound);
  // An unknown executable.
  pb::ListBSimFunctionsRequest f;
  f.set_project_id("default");
  f.set_database(db_);
  f.set_executable("nope");
  pb::ListBSimFunctionsResponse fr;
  EXPECT_EQ(b_->ListBSimFunctions(ctx_, f, fr).code, StatusCode::kNotFound);
}

}  // namespace
}  // namespace revkit::backend
