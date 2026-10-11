// BSim signatures in the image backend (signatures.h): diff.signature as a
// memoized query, the same as rk-lift's batch, untouched by renames and
// retypes, the same whatever the threads, and cancellable in the
// background.
#include "builders.hh"
#include "signatures.h"

#include "revkit/backend/image_backend.h"
#include "revkit/decompd/signature.h"
#include "revkit/facts/engine.h"
#include "revkit/inputs/inputs.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <filesystem>
#include <map>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;
namespace pb = ::revkit::v1;
using api::CallContext;

constexpr const char *kProgram = R"(
#include <stdio.h>
#include <string.h>
long counter;
__attribute__((noinline)) long leaf(long a, long b) { counter++; return a * b + counter; }
__attribute__((noinline)) long wrap(long a, long b) { return leaf(a, 1) + leaf(b, 2) + 1; }
__attribute__((noinline)) int loop(const char *s) { int n = 0; while (*s) n += *s++ == 'a'; return n; }
int main(int argc, char **argv) {
  printf("%ld %d %zu\n", wrap(argc, 2), loop(argv[0]), strlen(argv[0]));
  return 0;
}
)";

class SignatureQueries : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("signatures");
    plain_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O2 -g", plain_);
  }
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  }

  static std::unique_ptr<api::Backend> Make(unsigned workers = 4) {
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.param_id = inputs::ParamIdMode::off;
    o.decompile_workers = workers;
    o.decompilers_per_program = workers;
    return MakeImageBackend(o);
  }

  std::string Import(api::Backend &b, const fs::path &path) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(path.string());
    pb::ImportProgramResponse resp;
    auto st = b.ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  std::map<std::string, std::uint64_t> Functions(api::Backend &b, const std::string &program) {
    pb::ListFunctionsRequest req;
    req.set_program_id(program);
    req.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(b.ListFunctions(ctx_, req, resp).ok());
    std::map<std::string, std::uint64_t> out;
    for (const auto &f : resp.functions()) out[f.name()] = f.entry().offset();
    return out;
  }

  static std::vector<std::uint64_t> Entries(const std::map<std::string, std::uint64_t> &fns) {
    std::vector<std::uint64_t> out;
    for (const auto &[n, e] : fns) out.push_back(e);
    return out;
  }

  static std::map<std::uint64_t, decompd::FunctionSignature> Sign(api::Backend &b, const std::string &program,
                                                                 const std::vector<std::uint64_t> &entries,
                                                                 unsigned threads) {
    SignatureJob job(ProjectEngine(b, "default").snapshot(), program, entries, {threads, 0});
    return job.wait();
  }

  static inline fs::path plain_;
  static inline bool compiled_ = false;
  CallContext ctx_;
};

TEST_F(SignatureQueries, SignsEveryFunctionAndMemoizes) {
  if (!compiled_) GTEST_SKIP() << "no C compiler";
  auto b = Make();
  const std::string id = Import(*b, plain_);
  auto fns = Functions(*b, id);
  ASSERT_TRUE(fns.contains("wrap"));
  auto sigs = Sign(*b, id, Entries(fns), 4);
  ASSERT_EQ(sigs.size(), fns.size());
  for (const char *name : {"leaf", "wrap", "loop", "main"}) {
    const decompd::FunctionSignature &s = sigs.at(fns.at(name));
    EXPECT_TRUE(s.ok()) << name << ": " << s.detail;
    EXPECT_FALSE(s.features.empty()) << name;
    EXPECT_EQ(s.settings, decompd::kSignatureSettings);
  }
  // An import's stub is skipped.
  if (fns.contains("printf")) EXPECT_EQ(sigs.at(fns.at("printf")).status, decompd::FunctionSignature::Status::skipped);
  // Asked again: memo hits, nothing recomputed.
  ResetQueryCounters(*b, "default");
  auto again = Sign(*b, id, Entries(fns), 2);
  EXPECT_EQ(again, sigs);
  EXPECT_EQ(QueryCounters(*b, "default")["diff.signature"].executions, 0u);
}

// The same vectors as rk-lift's batch (decompd::signature_functions over
// revkit::inputs' assembly), and the same whatever the threads.
TEST_F(SignatureQueries, SameAsTheBatchAndForAnyThreadCount) {
  if (!compiled_) GTEST_SKIP() << "no C compiler";
  auto one = Make(1), eight = Make(8);
  const std::string a = Import(*one, plain_), c = Import(*eight, plain_);
  auto fns = Functions(*one, a);
  auto s1 = Sign(*one, a, Entries(fns), 1);
  auto s8 = Sign(*eight, c, Entries(fns), 8);
  EXPECT_EQ(s1, s8);

  lift::initialize(REVKIT_GHIDRA_ROOT);
  loader::LoadOptions lo;
  lo.ghidra_image_base = true;  // as rk-lift and the backend load it
  auto image = std::make_shared<const loader::Image>(loader::load_file(plain_.string(), lo));
  const std::string lang = loader::guess_language(*image)->id();
  auto analysis = inputs::analyze(*image, lang, 2);
  inputs::Program program{image, lang, analysis.get(), inputs::read_debug_info(*image, plain_)};
  lift::DecompileConfig config;
  config.image = image;
  config.language_id = lang;
  config.inputs = std::make_shared<lift::DecompilerInputs>(inputs::assemble(program));
  config.default_labels = false;
  config.threads = 4;
  decompd::SignatureBatchOptions o;
  o.no_return = std::make_shared<const std::vector<std::uint64_t>>(
      inputs::ghidra_no_return(analysis->functions(), analysis->no_return_evidence()));
  auto batch = decompd::signature_functions(config, Entries(fns), o);
  for (const auto &[name, entry] : fns) {
    SCOPED_TRACE(name);
    EXPECT_EQ(batch.at(entry).status, s1.at(entry).status);
    EXPECT_EQ(batch.at(entry).features, s1.at(entry).features);
  }
}

// Renaming and retyping functions recomputes no signature.
TEST_F(SignatureQueries, RenamesAndRetypesDontTouchSignatures) {
  if (!compiled_) GTEST_SKIP() << "no C compiler";
  auto b = Make();
  const std::string id = Import(*b, plain_);
  auto fns = Functions(*b, id);
  auto before = Sign(*b, id, Entries(fns), 4);
  pb::AppendAssertionsRequest req;
  req.set_program_id(id);
  req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  req.mutable_provenance()->set_id("alice");
  auto *rename = req.add_assertions()->mutable_body()->mutable_rename();
  rename->mutable_target()->mutable_address()->set_offset(fns.at("leaf"));
  rename->set_name("renamed_leaf");
  auto *comment = req.add_assertions()->mutable_body()->mutable_comment();
  comment->mutable_address()->set_offset(fns.at("wrap"));
  comment->set_kind(pb::COMMENT_KIND_PRE);
  comment->set_text("a comment");
  pb::AppendAssertionsResponse resp;
  auto st = b->AppendAssertions(ctx_, req, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  // leaf retyped: long leaf(long, long) as a type the decompiler is told.
  pb::AppendAssertionsRequest types;
  types.set_program_id(id);
  *types.mutable_provenance() = req.provenance();
  pb::TypeNode *i64 = types.add_assertions()->mutable_body()->mutable_define_type()->mutable_type();
  i64->set_kind(pb::TYPE_KIND_INT);
  i64->set_size(8);
  i64->set_rank(pb::INTEGER_RANK_LONG);
  pb::TypeNode *fn = types.add_assertions()->mutable_body()->mutable_define_type()->mutable_type();
  fn->set_kind(pb::TYPE_KIND_FUNCTION);
  fn->mutable_target()->set_assertion_index(0);
  for (const char *name : {"a", "b"}) {
    auto *param = fn->add_params();
    param->set_name(name);
    param->mutable_type()->set_assertion_index(0);
  }
  types.set_validate_only(true);
  pb::AppendAssertionsResponse checked;
  st = b->AppendAssertions(ctx_, types, checked);
  ASSERT_TRUE(st.ok()) << st.message;
  types.set_validate_only(false);
  auto *retype = types.add_assertions()->mutable_body()->mutable_retype();
  retype->mutable_target()->mutable_address()->set_offset(fns.at("leaf"));
  retype->mutable_type()->set_type_hash(checked.assertions(1).key().sub());
  pb::AppendAssertionsResponse appended;
  st = b->AppendAssertions(ctx_, types, appended);
  ASSERT_TRUE(st.ok()) << st.message;
  ResetQueryCounters(*b, "default");
  auto after = Sign(*b, id, Entries(fns), 4);
  EXPECT_EQ(after, before);
  const auto counters = QueryCounters(*b, "default");
  EXPECT_EQ(counters.at("diff.signature").executions, 0u);
}

TEST_F(SignatureQueries, CancelledJobsMemoizeNothingPartial) {
  const fs::path lua = fs::path(REVKIT_CORPUS) / "elf-x86_64/gcc-O2/debug/lua";
  if (!fs::exists(lua)) GTEST_SKIP() << "corpus not built";
  auto b = Make(2);
  const std::string id = Import(*b, lua);
  auto fns = Functions(*b, id);
  std::vector<std::uint64_t> entries = Entries(fns);
  {
    SignatureJob job(ProjectEngine(*b, "default").snapshot(), id, entries, {2, 0});
    while (job.done() < 5) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    job.cancel();
    auto partial = job.wait();
    EXPECT_LT(partial.size(), entries.size());
    for (const auto &[e, s] : partial) EXPECT_NE(s.detail, "cancelled");
  }
  SignatureJob full(ProjectEngine(*b, "default").snapshot(), id, entries, {4, 0});
  auto all = full.wait();
  EXPECT_EQ(all.size(), entries.size());
  std::size_t ok = 0;
  for (const auto &[e, s] : all) ok += s.ok();
  EXPECT_GT(ok, 600u);
}

// DiffService with the "bsim" tier: A at -O0 with debug info, B at -O2
// stripped; what the exact tiers and propagation leave, F5 pairs, right.
TEST_F(SignatureQueries, DiffSessionsRunTheBsimTier) {
  if (!compiled_) GTEST_SKIP() << "no C compiler";
  auto dir = testing::scratch_dir("signatures-diff");
  const fs::path a = dir / "a", b_debug = dir / "b-debug", b = dir / "b";
  ASSERT_TRUE(testing::compile(REVKIT_TEST_CC, kProgram, "-O0 -g", a));
  ASSERT_TRUE(testing::compile(REVKIT_TEST_CC, kProgram, "-O2 -g", b_debug));
  ASSERT_EQ(std::system(("strip -o " + b.string() + " " + b_debug.string()).c_str()), 0);
  auto backend = Make();
  const std::string ia = Import(*backend, a), ib = Import(*backend, b), itruth = Import(*backend, b_debug);
  std::map<std::uint64_t, std::string> truth_b;
  for (const auto &[n, e] : Functions(*backend, itruth)) truth_b[e] = n;
  std::map<std::uint64_t, std::string> names_a;
  for (const auto &[n, e] : Functions(*backend, ia)) names_a[e] = n;

  auto run = [&](bool bsim) {
    pb::CreateDiffSessionRequest req;
    req.set_project_id("default");
    req.set_program_a(ia);
    req.set_program_b(ib);
    req.set_run(true);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    if (bsim) req.mutable_options()->add_similarity_tiers("bsim");
    pb::CreateDiffSessionResponse resp;
    auto st = backend->CreateDiffSession(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    pb::GetDiffStatusRequest sreq;
    sreq.set_project_id("default");
    sreq.set_session_id(resp.session().session_id());
    pb::GetDiffStatusResponse sresp;
    for (int i = 0; i < 3000; ++i) {
      EXPECT_TRUE(backend->GetDiffStatus(ctx_, sreq, sresp).ok());
      if (sresp.session().run().state() != pb::DIFF_RUN_STATE_RUNNING) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    EXPECT_EQ(sresp.session().run().state(), pb::DIFF_RUN_STATE_SUCCEEDED) << sresp.session().run().message();
    pb::ListMatchesRequest lreq;
    lreq.set_project_id("default");
    lreq.set_session_id(resp.session().session_id());
    pb::ListMatchesResponse lresp;
    EXPECT_TRUE(backend->ListMatches(ctx_, lreq, lresp).ok());
    return lresp;
  };
  const pb::ListMatchesResponse plain = run(false), with = run(true);
  EXPECT_GE(with.matches_size(), plain.matches_size());
  int similar = 0;
  for (const auto &m : with.matches()) {
    if (m.tier() != pb::DIFF_TIER_SIMILARITY) continue;
    ++similar;
    EXPECT_EQ(names_a[m.a().entry().offset()], truth_b[m.b().entry().offset()]);
    EXPECT_GT(m.similarity(), 0.2f);
    EXPECT_LT(m.confidence(), 0.95f);
  }
  EXPECT_GE(similar, 1);
  for (const auto &m : plain.matches()) EXPECT_NE(m.tier(), pb::DIFF_TIER_SIMILARITY);
  std::fprintf(stderr, "matches without bsim %d, with %d (%d by similarity)\n", plain.matches_size(),
               with.matches_size(), similar);
}

}  // namespace
}  // namespace revkit::backend
