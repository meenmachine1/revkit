// Ghidra's Decompiler Parameter ID in the image backend (param_id.h): the
// signatures it commits reach decompilations in the background, the same
// whatever the threads, and an edit recomputes only what it affects.
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <map>
#include <set>
#include <thread>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;
namespace pb = ::revkit::v1;
using api::CallContext;

// main -> wrap -> leaf: wrap passes its arguments through to leaf, so the
// registers it doesn't touch become its parameters only once leaf's are
// committed (cJSON_Print in Ghidra's corpus export).
constexpr const char *kProgram = R"(
#include <stdio.h>
long counter;
__attribute__((noinline)) long leaf(long a, long b, long c, long d) { counter++; return a * b + c - d; }
__attribute__((noinline)) long wrap(long a, long b, long c, long d) { return leaf(a, 1, c, d) + 1; }
__attribute__((noinline)) long other(long x) { return x * 3 + counter; }
int main(int argc, char **argv) {
  printf("%ld %ld\n", wrap(argc, 2, (long)argv, 4), other(argc));
  return 0;
}
)";

std::string Text(const pb::DecompiledFunction &f) {
  std::string out;
  for (const auto &line : f.lines()) {
    for (const auto &t : line.tokens()) out += t.text();
    out += '\n';
  }
  return out;
}

class ParamIdTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("param-id");
    plain_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O2 -fno-optimize-sibling-calls", plain_);
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  }

  static std::unique_ptr<api::Backend> Make(inputs::ParamIdMode mode, unsigned workers = 3) {
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.param_id = mode;
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

  // Until the analyzer has nothing queued or running for the program.
  pb::GetAnalysisStatusResponse Settle(api::Backend &b, const std::string &program) {
    pb::GetAnalysisStatusRequest req;
    req.set_program_id(program);
    pb::GetAnalysisStatusResponse resp;
    const auto until = std::chrono::steady_clock::now() + std::chrono::minutes(3);
    do {
      resp.Clear();
      EXPECT_TRUE(b.GetAnalysisStatus(ctx_, req, resp).ok());
      if (resp.idle()) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    } while (std::chrono::steady_clock::now() < until);
    EXPECT_TRUE(resp.idle());
    return resp;
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

  pb::DecompiledFunction Decompile(api::Backend &b, const std::string &program, std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(program);
    req.mutable_function()->set_offset(entry);
    pb::DecompileResponse resp;
    auto st = b.Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.function();
  }

  void Append(api::Backend &b, const std::string &program, const pb::AssertionBody &body) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(program);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    *req.add_assertions()->mutable_body() = body;
    pb::AppendAssertionsResponse resp;
    auto st = b.AppendAssertions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
  }

  static inline fs::path plain_;
  static inline bool compiled_ = false;
  CallContext ctx_;
};

TEST_F(ParamIdTest, CommittedSignaturesReachCallers) {
  if (!compiled_) GTEST_SKIP() << "no C compiler";
  auto off = Make(inputs::ParamIdMode::off);
  auto on = Make(inputs::ParamIdMode::on);
  const std::string a = Import(*off, plain_), b = Import(*on, plain_);
  pb::GetAnalysisStatusResponse status = Settle(*on, b);
  bool ran = false;
  for (const auto &job : status.jobs())
    for (const auto &name : job.analyzers()) ran |= name == "decompiler_parameter_id";
  EXPECT_TRUE(ran);
  auto fns = Functions(*on, b);
  // leaf's own signature is the decompiler's either way; wrap, decompiled
  // with leaf's committed, passes c and d through as parameters, and its
  // callers then pass them.
  const std::string wrap_off = Text(Decompile(*off, a, fns.at("wrap")));
  const std::string wrap_on = Text(Decompile(*on, b, fns.at("wrap")));
  EXPECT_NE(wrap_off, wrap_on);
  EXPECT_NE(wrap_on.find("param_4"), std::string::npos) << wrap_on;
  EXPECT_EQ(wrap_on.find("in_RCX"), std::string::npos) << wrap_on;
  EXPECT_EQ(Settle(*off, a).jobs_size(), 0);
}

TEST_F(ParamIdTest, SameSignaturesWhateverTheThreads) {
  if (!compiled_) GTEST_SKIP() << "no C compiler";
  auto one = Make(inputs::ParamIdMode::on, 1);
  auto four = Make(inputs::ParamIdMode::on, 4);
  const std::string a = Import(*one, plain_), b = Import(*four, plain_);
  Settle(*one, a);
  Settle(*four, b);
  auto fns = Functions(*one, a);
  ASSERT_EQ(fns, Functions(*four, b));
  for (const auto &[name, entry] : fns)
    EXPECT_EQ(Text(Decompile(*one, a, entry)), Text(Decompile(*four, b, entry))) << name;
}

// The corpus's stripped cJSON for Windows: Ghidra runs the analyzer on it
// by default, and its cJSON_Print takes four parameters, not one and two
// unexplained registers.
TEST_F(ParamIdTest, GhidraDefaultOnSmallPe) {
  const fs::path bin = fs::path(REVKIT_CORPUS) / "pe-x86_64/clang-O2/stripped/cjson.exe";
  if (!fs::exists(bin)) GTEST_SKIP() << "corpus not built";
  auto b = Make(inputs::ParamIdMode::automatic);
  const std::string id = Import(*b, bin);
  Settle(*b, id);
  auto fns = Functions(*b, id);
  ASSERT_TRUE(fns.contains("cJSON_Print"));
  const std::string text = Text(Decompile(*b, id, fns.at("cJSON_Print")));
  EXPECT_NE(text.find("cJSON_Print(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)"),
            std::string::npos)
      << text;
  EXPECT_EQ(text.find("in_R8"), std::string::npos) << text;
}

// A prototype the user asserts outranks the analyzer's, and reaches the
// callers' commits: the analysis runs again after the edit, recomputing
// only the functions whose decompilation looked the edited one up.
TEST_F(ParamIdTest, UserPrototypesOutrankAndRecomputeOnlyWhatTheyReach) {
  if (!compiled_) GTEST_SKIP() << "no C compiler";
  auto b = Make(inputs::ParamIdMode::on);
  const std::string id = Import(*b, plain_);
  Settle(*b, id);
  auto fns = Functions(*b, id);
  const std::size_t functions = fns.size();
  ResetQueryCounters(*b, "default");
  // long leaf(long a, long b), as a type the decompiler is told.
  pb::AppendAssertionsRequest req;
  req.set_program_id(id);
  req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  req.mutable_provenance()->set_id("alice");
  pb::TypeNode *i64 = req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type();
  i64->set_kind(pb::TYPE_KIND_INT);
  i64->set_size(8);
  i64->set_rank(pb::INTEGER_RANK_LONG);
  pb::TypeNode *fn = req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type();
  fn->set_kind(pb::TYPE_KIND_FUNCTION);
  fn->mutable_target()->set_assertion_index(0);
  for (const char *name : {"a", "b"}) {
    auto *param = fn->add_params();
    param->set_name(name);
    param->mutable_type()->set_assertion_index(0);
  }
  req.set_validate_only(true);
  pb::AppendAssertionsResponse checked;
  auto st = b->AppendAssertions(ctx_, req, checked);
  ASSERT_TRUE(st.ok()) << st.message;
  req.set_validate_only(false);
  auto *retype = req.add_assertions()->mutable_body()->mutable_retype();
  retype->mutable_target()->mutable_address()->set_offset(fns.at("leaf"));
  retype->mutable_type()->set_type_hash(checked.assertions(1).key().sub());
  pb::AppendAssertionsResponse appended;
  st = b->AppendAssertions(ctx_, req, appended);
  ASSERT_TRUE(st.ok()) << st.message;
  Settle(*b, id);
  const auto counters = QueryCounters(*b, "default");
  // leaf itself (now user-defined: skipped), wrap, which calls it, and
  // main, which calls wrap, whose commit changed.
  EXPECT_LE(counters.at("analysis.param_id").executions, 3u);
  EXPECT_LT(counters.at("analysis.param_id").executions, functions);
  const std::string wrap = Text(Decompile(*b, id, fns.at("wrap")));
  EXPECT_NE(wrap.find("leaf("), std::string::npos) << wrap;
  EXPECT_EQ(wrap.find("param_4"), std::string::npos) << wrap;
}

}  // namespace
}  // namespace revkit::backend
