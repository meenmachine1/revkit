// Call-site signature overrides and finding uses of a type or field
// (docs/api.md, "Call-site signature overrides" and "Find uses of a type or
// field"): an override reaches the decompiler for its call alone (a varargs
// call's arguments, a computed call's), shows in the listing and on the
// decompiler's token, is undone by a retraction and by Remove, and what is
// refused; FindTypeUses finds a struct's fields with their access and the
// struct named in prototypes, and one field alone, through the api::Backend
// interface on a program compiled at test time.
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <set>
#include <tuple>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;

constexpr const char *kProgram = R"(
#include <stdarg.h>
struct pt { int x; int y; long tag; };
struct pt g_pt;
int (*volatile hook)(int, int, int);
__attribute__((noinline)) int sum(int n, ...) {
  va_list ap; va_start(ap, n); int s = 0;
  for (int i = 0; i < n; i++) s += va_arg(ap, int);
  va_end(ap); return s;
}
__attribute__((noinline)) int add3(int a, int b, int c) { return a + b * 2 + c * 3; }
__attribute__((noinline)) void setx(struct pt *p, int v) { p->x = v; p->tag += 1; }
__attribute__((noinline)) int gety(struct pt *p) { return p->y; }
__attribute__((noinline)) int *addr_y(struct pt *p) { return &p->y; }
__attribute__((noinline)) int calls(int a) { return sum(3, a, a + 1, a + 2) + hook(a, 2, 3); }
int main(int argc, char **argv) {
  (void)argv;
  hook = add3;
  setx(&g_pt, argc);
  return calls(argc) + gety(&g_pt) + *addr_y(&g_pt);
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

// The decompiled line calling `callee`, trimmed.
std::string CallLine(const std::string &text, const std::string &callee) {
  std::size_t at = text.find(callee + "(");
  if (at == std::string::npos) return {};
  std::size_t first = text.rfind('\n', at);
  first = first == std::string::npos ? 0 : first + 1;
  std::size_t last = text.find('\n', at);
  std::string line = text.substr(first, last - first);
  line.erase(0, line.find_first_not_of(' '));
  return line;
}

class CallsiteTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("callsite");
    exe_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O1 -g -fno-pie -no-pie", exe_);
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

  std::uint64_t Symbol(const std::string &name) {
    pb::ListSymbolsRequest req;
    req.set_program_id(id_);
    req.set_name_equals(name);
    pb::ListSymbolsResponse resp;
    EXPECT_TRUE(backend_->ListSymbols(ctx_, req, resp).ok());
    EXPECT_EQ(resp.symbols_size(), 1) << name;
    return resp.symbols_size() ? resp.symbols(0).address().offset() : 0;
  }

  pb::DecompiledFunction Decompiled(std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(id_);
    req.mutable_function()->set_offset(entry);
    pb::DecompileResponse resp;
    auto st = backend_->Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.function();
  }

  // A function's call rows (direct and computed), in address order.
  std::vector<pb::ListingRow> Calls(std::uint64_t entry) {
    pb::GetListingRequest req;
    req.set_program_id(id_);
    req.mutable_addresses()->mutable_start()->set_offset(entry);
    req.mutable_addresses()->set_max_rows(80);
    pb::GetListingResponse resp;
    EXPECT_TRUE(backend_->GetListing(ctx_, req, resp).ok());
    std::vector<pb::ListingRow> out;
    for (const auto &r : resp.rows())
      if (r.kind() == pb::LISTING_ROW_KIND_INSTRUCTION && r.function().offset() == entry &&
          (r.flow() == pb::FLOW_KIND_CALL || r.flow() == pb::FLOW_KIND_INDIRECT_CALL))
        out.push_back(r);
    return out;
  }
  pb::ListingRow Row(std::uint64_t a) {
    pb::GetListingRequest req;
    req.set_program_id(id_);
    req.mutable_addresses()->mutable_start()->set_offset(a);
    req.mutable_addresses()->set_max_rows(1);
    pb::GetListingResponse resp;
    EXPECT_TRUE(backend_->GetListing(ctx_, req, resp).ok());
    return resp.rows_size() ? resp.rows(0) : pb::ListingRow{};
  }

  api::Status Edit(const pb::AssertionBody &body, pb::AppendAssertionsResponse *out = nullptr) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(id_);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    *req.add_assertions()->mutable_body() = body;
    pb::AppendAssertionsResponse resp;
    auto st = backend_->AppendAssertions(ctx_, req, resp);
    if (out) *out = resp;
    return st;
  }
  void Undo(const pb::AppendAssertionsResponse &done) {
    pb::RetractAssertionsRequest req;
    req.set_program_id(id_);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    for (const auto &a : done.assertions()) req.add_seqs(a.seq());
    pb::RetractAssertionsResponse resp;
    auto st = backend_->RetractAssertions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
  }
  static pb::AssertionBody Override(std::uint64_t call, const std::string &c) {
    pb::AssertionBody b;
    b.mutable_call_signature()->mutable_call()->set_offset(call);
    if (!c.empty()) b.mutable_call_signature()->mutable_signature()->set_c_declaration(c);
    return b;
  }

  std::string StructHash(const std::string &name) {
    pb::FindTypesRequest req;
    req.set_program_id(id_);
    req.set_name_prefix(name);
    req.add_kinds(pb::TYPE_KIND_STRUCT);
    req.mutable_page()->set_page_size(5000);
    pb::FindTypesResponse resp;
    EXPECT_TRUE(backend_->FindTypes(ctx_, req, resp).ok());
    for (const auto &t : resp.types())
      if (t.name() == name && t.kind() == pb::TYPE_KIND_STRUCT) return t.hash();
    ADD_FAILURE() << "no struct " << name;
    return {};
  }

  api::Status Uses(pb::FindTypeUsesRequest req, std::vector<pb::TypeUse> &out, pb::FindTypeUsesResponse *last = nullptr) {
    req.set_program_id(id_);
    out.clear();
    return backend_->FindTypeUses(ctx_, req, [&](const pb::FindTypeUsesResponse &m) {
      for (const auto &u : m.uses()) out.push_back(u);
      if (last) *last = m;
      return true;
    });
  }

  static inline std::filesystem::path exe_;
  static inline bool compiled_ = false;
  std::unique_ptr<api::Backend> backend_;
  CallContext ctx_;
  std::string id_;
};

TEST_F(CallsiteTest, OverrideReachesTheDecompilerForThatCallAlone) {
  const std::uint64_t calls = Symbol("calls");
  std::vector<pb::ListingRow> rows = Calls(calls);
  ASSERT_EQ(rows.size(), 2u);
  const std::uint64_t direct = rows[0].address().offset(), computed = rows[1].address().offset();
  ASSERT_EQ(rows[1].flow(), pb::FLOW_KIND_INDIRECT_CALL);
  const std::string before = Text(Decompiled(calls));
  EXPECT_NE(CallLine(before, "sum").find("(ulong)"), std::string::npos) << before;
  EXPECT_NE(before.find("(*hook)(a,2,3)"), std::string::npos) << before;

  pb::AppendAssertionsResponse r1, r2;
  ASSERT_TRUE(Edit(Override(direct, "int sum(int n, int a, int b, int c)"), &r1).ok());
  EXPECT_EQ(r1.assertions(0).key().kind(), pb::FACT_KIND_CALL_SIGNATURE);
  ASSERT_TRUE(Edit(Override(computed, "int f(int a)"), &r2).ok());
  pb::DecompiledFunction after = Decompiled(calls);
  const std::string text = Text(after);
  EXPECT_EQ(CallLine(text, "sum"), "iVar1 = sum(3,a,a + 1,a + 2);") << text;
  EXPECT_NE(text.find("(*hook)(a);"), std::string::npos) << text;
  // Shown in the listing (with who set it) and on the call's token.
  EXPECT_EQ(Row(direct).call_signature(), "int sum(int n, int a, int b, int c)");
  EXPECT_EQ(Row(direct).call_signature_origin().asserted().provenance().id(), "alice");
  EXPECT_EQ(Row(computed).call_signature(), "int (int a)");
  int tokens = 0;
  for (const auto &line : after.lines())
    for (const auto &t : line.tokens())
      if (!t.call_signature().empty()) {
        ++tokens;
        EXPECT_EQ(t.text(), "sum");
        EXPECT_EQ(t.call_signature(), "int sum(int n, int a, int b, int c)");
      }
  EXPECT_EQ(tokens, 1);
  // Other functions' calls to sum are untouched: main calls calls, not sum.
  // Undo the computed call's, Remove the direct call's.
  Undo(r2);
  EXPECT_NE(Text(Decompiled(calls)).find("(*hook)(a,2,3)"), std::string::npos);
  EXPECT_EQ(Row(computed).call_signature(), "");
  ASSERT_TRUE(Edit(Override(direct, "")).ok());
  EXPECT_NE(CallLine(Text(Decompiled(calls)), "sum").find("(ulong)"), std::string::npos);
  EXPECT_EQ(Row(direct).call_signature(), "");
}

TEST_F(CallsiteTest, OverridesRefused) {
  const std::uint64_t calls = Symbol("calls");
  const std::uint64_t direct = Calls(calls).at(0).address().offset();
  auto st = Edit(Override(calls, "int f(int a)"));
  EXPECT_EQ(st.code, api::StatusCode::kInvalidArgument);
  EXPECT_NE(st.message.find("not a call"), std::string::npos) << st.message;
  st = Edit(Override(direct, "int f(struct nosuch a"));
  EXPECT_EQ(st.code, api::StatusCode::kInvalidArgument);
  EXPECT_NE(st.message.find("parse"), std::string::npos) << st.message;
  st = Edit(Override(direct, "int x"));  // a variable, not a prototype
  EXPECT_EQ(st.code, api::StatusCode::kInvalidArgument);
  pb::AssertionBody b = Override(direct, "");
  b.mutable_call_signature()->mutable_signature()->set_type_hash(StructHash("pt"));
  st = Edit(b);
  EXPECT_EQ(st.code, api::StatusCode::kInvalidArgument);
  EXPECT_NE(st.message.find("not a function type"), std::string::npos) << st.message;
  b.mutable_call_signature()->mutable_signature()->set_type_hash("00112233445566778899aabbccddeeff");
  EXPECT_EQ(Edit(b).code, api::StatusCode::kInvalidArgument);
}

TEST_F(CallsiteTest, FindTypeUses) {
  const std::string pt = StructHash("pt");
  ASSERT_FALSE(pt.empty());
  pb::FindTypeUsesRequest req;
  req.set_type_hash(pt);
  std::vector<pb::TypeUse> uses;
  pb::FindTypeUsesResponse last;
  ASSERT_TRUE(Uses(req, uses, &last).ok());
  EXPECT_TRUE(last.done());
  EXPECT_FALSE(last.truncated());
  EXPECT_GT(last.functions_total(), 0u);
  EXPECT_EQ(last.functions_done(), last.functions_total());
  std::multiset<std::tuple<std::string, std::string, int>> fields;
  std::set<std::string> typed;
  for (const auto &u : uses) {
    EXPECT_EQ(u.text().substr(u.match_start(), u.match_length()), u.kind() == pb::TYPE_USE_KIND_FIELD ? u.field_name() : "pt")
        << u.text();
    if (u.kind() == pb::TYPE_USE_KIND_FIELD) fields.insert({u.function_name(), u.field_name(), u.access()});
    else typed.insert(u.function_name());
  }
  const std::multiset<std::tuple<std::string, std::string, int>> want{
      {"setx", "x", pb::FIELD_ACCESS_WRITE},  {"setx", "tag", pb::FIELD_ACCESS_WRITE}, {"setx", "tag", pb::FIELD_ACCESS_READ},
      {"gety", "y", pb::FIELD_ACCESS_READ},   {"addr_y", "y", pb::FIELD_ACCESS_ADDRESS}};
  EXPECT_EQ(fields, want);
  EXPECT_EQ(typed, (std::set<std::string>{"setx", "gety", "addr_y"}));

  // One field: y at offset 4.
  req.set_field_offset(4);
  ASSERT_TRUE(Uses(req, uses).ok());
  std::set<std::string> fns;
  for (const auto &u : uses) {
    fns.insert(u.function_name());
    EXPECT_EQ(u.field_offset(), 4u);
  }
  EXPECT_EQ(fns, (std::set<std::string>{"gety", "addr_y"}));
  // One function only.
  *req.add_functions() = Row(Symbol("gety")).address();
  ASSERT_TRUE(Uses(req, uses).ok());
  ASSERT_EQ(uses.size(), 1u);
  EXPECT_EQ(uses[0].function_name(), "gety");

  // Unknown types and a field name without an offset are refused.
  pb::FindTypeUsesRequest bad;
  bad.set_type_hash("00112233445566778899aabbccddeeff");
  EXPECT_EQ(Uses(bad, uses).code, api::StatusCode::kNotFound);
  bad.set_type_hash(pt);
  bad.set_field_name("y");
  EXPECT_EQ(Uses(bad, uses).code, api::StatusCode::kInvalidArgument);
}

TEST_F(CallsiteTest, TypeTokensNameTheirStruct) {
  const std::string pt = StructHash("pt");
  pb::DecompiledFunction f = Decompiled(Symbol("gety"));
  int named = 0;
  for (const auto &line : f.lines())
    for (const auto &t : line.tokens())
      if (t.kind() == pb::CODE_TOKEN_KIND_TYPE && t.text() == "pt") {
        EXPECT_EQ(t.type_hash(), pt);
        ++named;
      }
  EXPECT_GE(named, 1);
}

}  // namespace
}  // namespace revkit::backend
