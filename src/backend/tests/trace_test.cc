// Value tracing across calls (QueryService.TraceValue, api_minor 89,
// feature "value-trace"; docs/api.md "Tracing a value across calls") on a
// program whose flows are known:
//
//   scale(v) = v * 3 + 1          pick(a, b) = a > b ? a : b
//   combine(x, y) = pick(scale(x), y)
//   main: r = combine(argc, strlen(argv[0])); sink(&r) through a pointer;
//         return r
//
// Backward from main's return value the trace goes into combine, pick and
// scale (returns, then parameters), stops at strlen (an import) and at
// main's own parameter (nothing calls main directly). Forward from scale's
// parameter it comes back out only through the call it came in by (scale's
// caller combine, then main), not into every caller. Budgets stop it and
// say so; an indirect call is listed, not followed.
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <set>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;

constexpr const char *kProgram = R"(
#include <string.h>
__attribute__((noinline)) int scale(int v) { return v * 3 + 1; }
__attribute__((noinline)) int pick(int a, int b) { return a > b ? a : b; }
__attribute__((noinline)) int combine(int x, int y) { int s = scale(x); return pick(s, y); }
__attribute__((noinline)) int other(int q) { return scale(q + 5); }
int (*volatile hook)(int) = other;
int main(int argc, char **argv) {
  int r = combine(argc, (int)strlen(argv[0]));
  r += hook(r);
  return r + other(argc);
}
)";

class TraceTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("trace");
    exe_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O1 -g -fno-inline -fno-optimize-sibling-calls -fno-pie -no-pie", exe_);
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
  }

  std::uint64_t Fn(const std::string &name) {
    pb::ListSymbolsRequest sreq;
    sreq.set_program_id(id_);
    sreq.set_name_equals(name);
    pb::ListSymbolsResponse sresp;
    EXPECT_TRUE(backend_->ListSymbols(ctx_, sreq, sresp).ok());
    EXPECT_GE(sresp.symbols_size(), 1) << name;
    return sresp.symbols_size() ? sresp.symbols(0).address().offset() : 0;
  }

  pb::DecompiledFunction Decompile(std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(id_);
    req.mutable_function()->set_offset(entry);
    req.mutable_options()->set_timeout_ms(20000);
    pb::DecompileResponse resp;
    auto st = backend_->Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.function();
  }

  static std::string Text(const pb::DecompiledFunction &f) {
    std::string s;
    for (const auto &line : f.lines()) {
      for (const auto &t : line.tokens()) s += t.text();
      s += "\n";
    }
    return s;
  }

  // The last token with this text in a function (the return's, for "return").
  static pb::TokenPosition Last(const pb::DecompiledFunction &f, const std::string &text) {
    pb::TokenPosition p;
    bool found = false;
    for (int l = 1; l < f.lines_size(); ++l)
      for (int i = 0; i < f.lines(l).tokens_size(); ++i)
        if (f.lines(l).tokens(i).text() == text) {
          p.set_line(static_cast<std::uint32_t>(l));
          p.set_token(static_cast<std::uint32_t>(i));
          found = true;
        }
    EXPECT_TRUE(found) << "no token " << text << " in\n" << Text(f);
    return p;
  }

  api::Status Trace(std::uint64_t entry, pb::TraceDirection dir, const pb::TraceValueRequest &extra,
                    pb::TraceValueResponse &resp) {
    pb::TraceValueRequest req = extra;
    req.set_program_id(id_);
    req.mutable_function()->set_offset(entry);
    req.set_direction(dir);
    return backend_->TraceValue(ctx_, req, resp);
  }

  static std::set<std::string> Functions(const pb::TraceValueResponse &r) {
    std::set<std::string> out;
    for (const auto &f : r.functions()) out.insert(f.name());
    return out;
  }
  static bool Unknown(const pb::TraceValueResponse &r, pb::TraceUnknownKind kind, const std::string &detail) {
    for (const auto &u : r.unknowns())
      if (u.kind() == kind && u.detail().find(detail) != std::string::npos) return true;
    return false;
  }
  static void MaybeDump(const pb::TraceValueResponse &r) {
    if (std::getenv("RK_TRACE_DUMP")) std::fprintf(stderr, "%s\n", Dump(r).c_str());
  }
  static std::string Dump(const pb::TraceValueResponse &r) {
    std::string s = "start " + r.start() + "\n";
    for (const auto &f : r.functions()) {
      s += "fn " + f.name() + " depth " + std::to_string(f.depth()) + "\n";
      for (const auto &l : f.lines()) s += "  " + l.text() + "\n";
    }
    for (const auto &u : r.unknowns()) s += "unknown " + std::to_string(u.kind()) + " " + u.detail() + "\n";
    return s;
  }

  static inline std::filesystem::path exe_;
  static inline bool compiled_ = false;
  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
  std::string id_;
};

TEST_F(TraceTest, BackwardThroughReturnsAndParameters) {
  const std::uint64_t combine = Fn("combine");
  pb::DecompiledFunction f = Decompile(combine);
  pb::TraceValueResponse r;
  // combine's returned value: pick's return, its parameters a and b, then
  // combine's x (through scale) and y, then main's arguments.
  auto st = Trace(combine, pb::TRACE_DIRECTION_BACKWARD, [&] {
    pb::TraceValueRequest q;
    *q.mutable_token() = Last(f, "return");
    return q;
  }(), r);
  ASSERT_TRUE(st.ok()) << st.message;
  MaybeDump(r);
  const auto fns = Functions(r);
  EXPECT_TRUE(fns.count("pick") && fns.count("scale") && fns.count("main")) << Dump(r);
  EXPECT_EQ(r.functions(0).name(), "combine");
  // strlen is outside the program; main's argc comes from nothing that calls main directly.
  EXPECT_TRUE(Unknown(r, pb::TRACE_UNKNOWN_KIND_EXTERNAL_CALL, "strlen")) << Dump(r);
  EXPECT_TRUE(Unknown(r, pb::TRACE_UNKNOWN_KIND_NO_CALLERS, "main")) << Dump(r);
  // Edges: a RETURN from pick into combine, ARGUMENTs from main into combine.
  bool ret = false, arg = false;
  for (const auto &e : r.edges()) {
    const auto &from = r.nodes(static_cast<int>(e.from())), &to = r.nodes(static_cast<int>(e.to()));
    const std::string a = r.functions(static_cast<int>(from.function())).name(), b = r.functions(static_cast<int>(to.function())).name();
    ret = ret || (e.kind() == pb::TRACE_EDGE_KIND_RETURN && a == "pick" && b == "combine");
    arg = arg || (e.kind() == pb::TRACE_EDGE_KIND_ARGUMENT && a == "main" && b == "combine");
  }
  EXPECT_TRUE(ret && arg) << Dump(r);
  // Depths: pick is a callee (+1), main a caller (-1).
  for (const auto &fn : r.functions()) {
    if (fn.name() == "pick") EXPECT_EQ(fn.depth(), 1);
    if (fn.name() == "main") EXPECT_EQ(fn.depth(), -1);
  }
  EXPECT_FALSE(r.truncated()) << Dump(r);
  // Lines: combine's return line is among its lines.
  EXPECT_FALSE(r.functions(0).lines().empty());
}

TEST_F(TraceTest, ForwardComesBackOutThroughTheCallItEnteredBy) {
  // From combine's call of scale forward: into scale (its parameter), out
  // through its return to combine only (not other, scale's other caller),
  // into pick, back to combine and on to main.
  const std::uint64_t combine = Fn("combine");
  pb::DecompiledFunction f = Decompile(combine);
  pb::TraceValueRequest q;
  // x, the parameter: forward.
  q.set_variable_index(0);
  ASSERT_GT(f.variables_size(), 0);
  ASSERT_TRUE(f.variables(0).has_parameter_index()) << Text(f);
  pb::TraceValueResponse r;
  auto st = Trace(combine, pb::TRACE_DIRECTION_FORWARD, q, r);
  ASSERT_TRUE(st.ok()) << st.message;
  MaybeDump(r);
  const auto fns = Functions(r);
  EXPECT_TRUE(fns.count("scale") && fns.count("pick") && fns.count("main")) << Dump(r);
  EXPECT_FALSE(fns.count("other")) << "scale's return went to every caller\n" << Dump(r);
  // main's r goes to an indirect call (hook) and out of main, which nothing calls.
  EXPECT_TRUE(Unknown(r, pb::TRACE_UNKNOWN_KIND_INDIRECT_CALL, "indirect")) << Dump(r);
  EXPECT_TRUE(Unknown(r, pb::TRACE_UNKNOWN_KIND_NO_CALLERS, "main")) << Dump(r);
}

TEST_F(TraceTest, FromAFunctionNothingCallsGoesToEveryCaller) {
  // scale's returned value, traced forward from scale itself: both callers.
  const std::uint64_t scale = Fn("scale");
  pb::DecompiledFunction f = Decompile(scale);
  pb::TraceValueRequest q;
  *q.mutable_token() = Last(f, "return");
  pb::TraceValueResponse r;
  auto st = Trace(scale, pb::TRACE_DIRECTION_FORWARD, q, r);
  ASSERT_TRUE(st.ok()) << st.message;
  MaybeDump(r);
  const auto fns = Functions(r);
  EXPECT_TRUE(fns.count("combine") && fns.count("other")) << Dump(r);
}

TEST_F(TraceTest, BudgetsStopItAndSaySo) {
  const std::uint64_t combine = Fn("combine");
  pb::DecompiledFunction f = Decompile(combine);
  pb::TraceValueRequest q;
  *q.mutable_token() = Last(f, "return");
  q.set_max_depth(1);
  q.set_max_functions(2);
  pb::TraceValueResponse r;
  ASSERT_TRUE(Trace(combine, pb::TRACE_DIRECTION_BACKWARD, q, r).ok());
  EXPECT_TRUE(r.truncated()) << Dump(r);
  EXPECT_LE(r.functions_size(), 2) << Dump(r);
  EXPECT_TRUE(Unknown(r, pb::TRACE_UNKNOWN_KIND_BUDGET, "")) << Dump(r);
  q.set_max_functions(0);
  q.set_max_nodes(3);
  pb::TraceValueResponse small;
  ASSERT_TRUE(Trace(combine, pb::TRACE_DIRECTION_BACKWARD, q, small).ok());
  EXPECT_LE(small.nodes_size(), 3);
  EXPECT_TRUE(small.truncated());
}

TEST_F(TraceTest, Refusals) {
  const std::uint64_t combine = Fn("combine");
  pb::TraceValueRequest q;
  pb::TraceValueResponse r;
  q.set_variable_index(0);
  EXPECT_EQ(Trace(combine, pb::TRACE_DIRECTION_UNSPECIFIED, q, r).code, api::StatusCode::kInvalidArgument);
  q.set_variable_index(9999);
  EXPECT_EQ(Trace(combine, pb::TRACE_DIRECTION_FORWARD, q, r).code, api::StatusCode::kInvalidArgument);
  pb::TraceValueRequest none;
  EXPECT_EQ(Trace(combine, pb::TRACE_DIRECTION_FORWARD, none, r).code, api::StatusCode::kInvalidArgument);
  q.set_variable_index(0);
  EXPECT_EQ(Trace(combine + 1, pb::TRACE_DIRECTION_FORWARD, q, r).code, api::StatusCode::kNotFound);
}

// Result evidence (api_minor 97, feature "result-evidence"; docs/api.md
// "Result evidence"): main's call through `hook` is an unknown of GetFunction
// and of its decompilation; scale's calls are all known. Names say their
// tier: DWARF's (-g) are debug information, the decompiler's are guesses.
TEST_F(TraceTest, ResultsSayWhatTheyLeaveUnknown) {
  const std::uint64_t main_fn = Fn("main"), scale = Fn("scale");
  auto indirect = [](const auto &unknowns) {
    int n = 0;
    for (const pb::Unknown &u : unknowns) n += u.kind() == pb::UNKNOWN_KIND_INDIRECT_CALL && u.has_address();
    return n;
  };
  pb::GetFunctionRequest req;
  req.set_program_id(id_);
  req.mutable_address()->set_offset(main_fn);
  pb::GetFunctionResponse resp;
  ASSERT_TRUE(backend_->GetFunction(ctx_, req, resp).ok());
  EXPECT_EQ(indirect(resp.function().unknowns()), 1);
  EXPECT_EQ(resp.function().name_origin().tier(), pb::SOURCE_TIER_DEBUG_INFO)
      << resp.function().name_origin().DebugString();
  const pb::DecompiledFunction dec = Decompile(main_fn);
  EXPECT_EQ(indirect(dec.unknowns()), 1) << Text(dec);
  EXPECT_EQ(indirect(Decompile(scale).unknowns()), 0);
  bool guessed = false;
  for (const pb::Variable &v : dec.variables())
    if (v.kind() == pb::VARIABLE_KIND_LOCAL && v.name_origin().has_derived())
      guessed |= v.name_origin().tier() == pb::SOURCE_TIER_GUESSED;
  EXPECT_TRUE(guessed) << "the decompiler's local names are guesses";
}

}  // namespace
}  // namespace revkit::backend
