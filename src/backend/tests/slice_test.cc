// Def-use chains and data-flow slices in a decompilation
// (QueryService.SliceDecompiled, api_minor 57, feature "decompile-slices";
// docs/api.md "Slices") on a function whose slices are known:
//
//   int f(int a, int b) { g = b + 7; return a * 3 + 1; }
//
// the backward slice of the return value is a, 3 and 1, never b, 7 or g;
// the forward slice of b reaches g and not the return; def-use of a is its
// prints; the instruction slices mark instructions; the graph only comes
// with Decompile when asked for.
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <set>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;

constexpr const char *kProgram = R"(
int g;
__attribute__((noinline)) int f(int a, int b) {
  g = b + 7;
  return a * 3 + 1;
}
int main(int argc, char **argv) { (void)argv; return f(argc, argc + 1); }
)";

class SliceTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("slice");
    exe_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O1 -g -fno-inline", exe_);
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!compiled_) GTEST_SKIP() << "no C compiler";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(exe_.string());
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    id_ = resp.program().program_id();
    pb::ListSymbolsRequest sreq;
    sreq.set_program_id(id_);
    sreq.set_name_equals("f");
    pb::ListSymbolsResponse sresp;
    ASSERT_TRUE(backend_->ListSymbols(ctx_, sreq, sresp).ok());
    ASSERT_GE(sresp.symbols_size(), 1);
    f_ = sresp.symbols(0).address().offset();
    fn_ = Decompile(false);
  }

  pb::DecompiledFunction Decompile(bool dataflow) {
    pb::DecompileRequest req;
    req.set_program_id(id_);
    req.mutable_function()->set_offset(f_);
    req.mutable_options()->set_timeout_ms(10000);
    req.mutable_options()->set_include_dataflow(dataflow);
    pb::DecompileResponse resp;
    auto st = backend_->Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    EXPECT_FALSE(resp.has_failure());
    return resp.function();
  }

  // The first token with this text after the prototype line (the body).
  pb::TokenPosition Token(const std::string &text, int skip = 0) {
    for (int l = 1; l < fn_.lines_size(); ++l)
      for (int i = 0; i < fn_.lines(l).tokens_size(); ++i)
        if (fn_.lines(l).tokens(i).text() == text && skip-- == 0) {
          pb::TokenPosition p;
          p.set_line(static_cast<std::uint32_t>(l));
          p.set_token(static_cast<std::uint32_t>(i));
          return p;
        }
    ADD_FAILURE() << "no token " << text << " in\n" << Text();
    return {};
  }

  std::string Text() const {
    std::string s;
    for (const auto &line : fn_.lines()) {
      for (const auto &t : line.tokens()) s += t.text();
      s += "\n";
    }
    return s;
  }

  api::Status Slice(pb::SliceKind kind, const pb::TokenPosition &at, pb::SliceDecompiledResponse &resp) {
    pb::SliceDecompiledRequest req;
    req.set_program_id(id_);
    req.mutable_function()->set_offset(f_);
    req.set_kind(kind);
    *req.mutable_token() = at;
    return backend_->SliceDecompiled(ctx_, req, resp);
  }

  // The texts of the slice's tokens.
  std::multiset<std::string> Texts(pb::SliceKind kind, const pb::TokenPosition &at) {
    pb::SliceDecompiledResponse resp;
    auto st = Slice(kind, at, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    std::multiset<std::string> out;
    for (const auto &p : resp.tokens()) out.insert(fn_.lines(static_cast<int>(p.line())).tokens(static_cast<int>(p.token())).text());
    return out;
  }

  static inline std::filesystem::path exe_;
  static inline bool compiled_ = false;
  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
  std::string id_;
  std::uint64_t f_ = 0;
  pb::DecompiledFunction fn_;
};

TEST_F(SliceTest, TheGraphComesOnlyWhenAskedFor) {
  EXPECT_FALSE(fn_.has_dataflow()) << "a plain Decompile carries the graph";
  for (const auto &line : fn_.lines())
    for (const auto &t : line.tokens()) EXPECT_FALSE(t.has_op_index()) << t.text();
  pb::DecompiledFunction full = Decompile(true);
  ASSERT_TRUE(full.has_dataflow());
  EXPECT_GE(full.dataflow().nodes_size(), full.varnodes_size());
  EXPECT_GT(full.dataflow().ops_size(), 0);
  bool any = false;
  for (const auto &line : full.lines())
    for (const auto &t : line.tokens()) any = any || t.has_op_index();
  EXPECT_TRUE(any);
  // The same tokens, the same lines.
  ASSERT_EQ(full.lines_size(), fn_.lines_size());
  for (int l = 0; l < fn_.lines_size(); ++l) EXPECT_EQ(full.lines(l).tokens_size(), fn_.lines(l).tokens_size());
}

TEST_F(SliceTest, BackwardSliceOfTheReturnValueIsItsOperands) {
  // From `return`: the values it reads, back to a and the constants.
  auto back = Texts(pb::SLICE_KIND_BACKWARD, Token("return"));
  EXPECT_TRUE(back.count("a")) << Text();
  EXPECT_TRUE(back.count("3") || back.count("1")) << Text();
  EXPECT_FALSE(back.count("b")) << Text();
  EXPECT_FALSE(back.count("g")) << Text();
  EXPECT_FALSE(back.count("7")) << Text();
}

TEST_F(SliceTest, ForwardSliceOfBReachesGNotTheReturn) {
  auto fwd = Texts(pb::SLICE_KIND_FORWARD, Token("b"));
  EXPECT_TRUE(fwd.count("b")) << Text();
  EXPECT_TRUE(fwd.count("g")) << Text();
  EXPECT_FALSE(fwd.count("a")) << Text();
}

TEST_F(SliceTest, DefUseOfAIsItsPrints) {
  auto du = Texts(pb::SLICE_KIND_DEF_USE, Token("a"));
  EXPECT_GE(du.count("a"), 1u);
  for (const std::string &t : du) EXPECT_EQ(t, "a");
}

TEST_F(SliceTest, InstructionSlicesMarkInstructions) {
  pb::SliceDecompiledResponse resp;
  ASSERT_TRUE(Slice(pb::SLICE_KIND_BACKWARD_OPS, Token("return"), resp).ok());
  EXPECT_GT(resp.tokens_size(), 0);
  ASSERT_GT(resp.addresses_size(), 0);
  for (const auto &a : resp.addresses()) EXPECT_GE(a.offset(), f_);
  EXPECT_EQ(resp.start(), "return");
  pb::SliceDecompiledResponse fwd;
  ASSERT_TRUE(Slice(pb::SLICE_KIND_FORWARD_OPS, Token("b"), fwd).ok());
  EXPECT_GT(fwd.addresses_size(), 0);
}

TEST_F(SliceTest, SaysWhatItCantSliceFrom) {
  pb::SliceDecompiledResponse resp;
  EXPECT_EQ(Slice(pb::SLICE_KIND_FORWARD, Token(";"), resp).code, api::StatusCode::kInvalidArgument);
  pb::TokenPosition far;
  far.set_line(9999);
  EXPECT_EQ(Slice(pb::SLICE_KIND_FORWARD, far, resp).code, api::StatusCode::kInvalidArgument);
  EXPECT_EQ(Slice(pb::SLICE_KIND_UNSPECIFIED, Token("a"), resp).code, api::StatusCode::kInvalidArgument);
  // A variable: every varnode of it.
  pb::SliceDecompiledRequest req;
  req.set_program_id(id_);
  req.mutable_function()->set_offset(f_);
  req.set_kind(pb::SLICE_KIND_FORWARD);
  std::uint32_t b = 0;
  for (const auto &v : fn_.variables())
    if (v.name() == "b") b = v.index();
  req.set_variable_index(b);
  pb::SliceDecompiledResponse byvar;
  ASSERT_TRUE(backend_->SliceDecompiled(ctx_, req, byvar).ok());
  EXPECT_EQ(byvar.start(), "b");
  EXPECT_GT(byvar.tokens_size(), 0);
}

}  // namespace
}  // namespace revkit::backend
