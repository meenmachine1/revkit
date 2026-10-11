// What the UI's hover cards read (docs/ui.md "Hover cards", feature
// "hover"): no RPC of their own, so this pins the contract of the reads
// they make on a program with debug info: a callee's prototype and first
// lines of C, a struct global's data row naming its type by hash and that
// type's layout, a struct parameter's type found by its C spelling (the
// decompiler's TypeRef has no hash) and a field token naming its struct and
// offset, and a scalar's symbol and block by an exact address range.
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;

constexpr const char *kProgram = R"(
struct pair { int first; int second; };
struct pair g_pair = {1, 2};
int counter;
__attribute__((noinline)) int second(struct pair *p) { return p->second; }
__attribute__((noinline)) int twice(int x) {
  counter += x;
  return x * 2 + 0x41;
}
int main(int argc, char **argv) { return twice(argc) + second(&g_pair); }
)";

std::vector<std::string> Lines(const pb::DecompiledFunction &f) {
  std::vector<std::string> out;
  for (const auto &line : f.lines()) {
    std::string s(2 * line.indent(), ' ');
    for (const auto &t : line.tokens()) s += t.text();
    out.push_back(s);
  }
  return out;
}

class HoverTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("hover");
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
  }

  std::uint64_t Symbol(const std::string &name) {
    pb::ListSymbolsRequest req;
    req.set_program_id(id_);
    req.set_name_equals(name);
    pb::ListSymbolsResponse resp;
    EXPECT_TRUE(backend_->ListSymbols(ctx_, req, resp).ok());
    EXPECT_GE(resp.symbols_size(), 1) << name;
    return resp.symbols_size() ? resp.symbols(0).address().offset() : 0;
  }

  pb::DecompiledFunction Decompile(std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(id_);
    req.mutable_function()->set_offset(entry);
    req.mutable_options()->set_timeout_ms(5000);
    pb::DecompileResponse resp;
    auto st = backend_->Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    EXPECT_FALSE(resp.has_failure());
    return resp.function();
  }

  pb::GetTypesResponse Types(const std::string &hash) {
    pb::GetTypesRequest req;
    req.set_program_id(id_);
    req.add_hashes(hash);
    req.set_include_dependencies(true);
    pb::GetTypesResponse resp;
    EXPECT_TRUE(backend_->GetTypes(ctx_, req, resp).ok());
    return resp;
  }

  // The struct's members as the card's layout lists them: "+0x<offset> <type> <name>".
  std::vector<std::string> Layout(const std::string &hash) {
    auto resp = Types(hash);
    std::map<std::string, const pb::TypeDefinition *> by;
    for (const auto &t : resp.types()) by[t.hash()] = &t;
    const pb::TypeDefinition *t = by.count(hash) ? by[hash] : nullptr;
    std::vector<std::string> out;
    if (!t) return out;
    for (const auto &f : t->composite().fields()) {
      char off[32];
      std::snprintf(off, sizeof off, "+0x%llx", static_cast<unsigned long long>(f.offset()));
      out.push_back(std::string(off) + " " + (by.count(f.type_hash()) ? by[f.type_hash()]->display() : "?") + " " + f.name());
    }
    return out;
  }

  static inline std::filesystem::path exe_;
  static inline bool compiled_ = false;
  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
  std::string id_;
};

const std::vector<std::string> kPairLayout = {"+0x0 int first", "+0x4 int second"};

TEST_F(HoverTest, TheDaemonSaysSo) {
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_GE(info.api_minor(), 47u);
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "hover"), info.features().end());
}

TEST_F(HoverTest, ACalleePreviewsItsSignatureAndFirstLines) {
  const std::uint64_t twice = Symbol("twice");
  pb::GetFunctionRequest req;
  req.set_program_id(id_);
  req.mutable_address()->set_offset(twice);
  pb::GetFunctionResponse fn;
  ASSERT_TRUE(backend_->GetFunction(ctx_, req, fn).ok());
  EXPECT_NE(fn.function().prototype().find("twice(int x)"), std::string::npos) << fn.function().prototype();
  auto lines = Lines(Decompile(twice));
  ASSERT_GE(lines.size(), 4u);
  EXPECT_NE(lines[0].find("twice(int x)"), std::string::npos) << lines[0];
  EXPECT_NE(std::find(lines.begin(), lines.end(), "{"), lines.end());
}

TEST_F(HoverTest, AStructGlobalsRowNamesItsTypeAndTheTypeItsLayout) {
  const std::uint64_t g = Symbol("g_pair");
  pb::GetListingRequest req;
  req.set_program_id(id_);
  req.mutable_addresses()->mutable_start()->set_offset(g);
  req.mutable_addresses()->set_max_rows(8);
  pb::GetListingResponse resp;
  ASSERT_TRUE(backend_->GetListing(ctx_, req, resp).ok());
  const pb::ListingRow *row = nullptr;
  for (const auto &r : resp.rows())
    // (A global debug info types but no listing edit defines shows as
    // undefined bytes with the asserted type: data_type, data_type_hash.)
    if (r.address().offset() == g && r.kind() != pb::LISTING_ROW_KIND_HEADER) row = &r;
  ASSERT_NE(row, nullptr);
  ASSERT_FALSE(row->data_type_hash().empty()) << row->data_type();
  EXPECT_EQ(Layout(row->data_type_hash()), kPairLayout);
}

TEST_F(HoverTest, AStructParameterAndItsFieldLeadToTheLayout) {
  auto fn = Decompile(Symbol("second"));
  const pb::Variable *p = nullptr;
  for (const auto &v : fn.variables())
    if (v.kind() == pb::VARIABLE_KIND_PARAMETER) p = &v;
  ASSERT_NE(p, nullptr);
  EXPECT_NE(p->type().display().find("pair"), std::string::npos) << p->type().display();
  // The card finds a TypeRef without a hash by its spelling.
  std::string hash = p->type().hash();
  if (hash.empty()) {
    pb::FindTypesRequest req;
    req.set_program_id(id_);
    req.set_name_contains("pair");
    pb::FindTypesResponse found;
    ASSERT_TRUE(backend_->FindTypes(ctx_, req, found).ok());
    for (const auto &t : found.types())
      if (t.name() == "pair" && !t.superseded()) hash = t.hash();
  } else {
    auto resp = Types(hash);
    for (const auto &t : resp.types())
      if (t.hash() == hash && t.kind() == pb::TYPE_KIND_POINTER) hash = t.pointer().target_hash();
  }
  ASSERT_FALSE(hash.empty());
  EXPECT_EQ(Layout(hash), kPairLayout);
  // p->second: the field token names its struct and the member's offset.
  bool seen = false;
  for (const auto &line : fn.lines())
    for (const auto &t : line.tokens())
      if (t.kind() == pb::CODE_TOKEN_KIND_FIELD && t.text() == "second") {
        seen = true;
        EXPECT_EQ(t.parent_type_hash(), hash);
        EXPECT_EQ(t.field_offset(), 4u);
      }
  EXPECT_TRUE(seen);
}

TEST_F(HoverTest, AScalarThatIsAnAddressNamesItsSymbolAndBlock) {
  const std::uint64_t counter = Symbol("counter");
  pb::ListSymbolsRequest req;
  req.set_program_id(id_);
  req.mutable_range()->mutable_first()->set_offset(counter);
  req.mutable_range()->mutable_last()->set_offset(counter);
  pb::ListSymbolsResponse syms;
  ASSERT_TRUE(backend_->ListSymbols(ctx_, req, syms).ok());
  ASSERT_GE(syms.symbols_size(), 1);
  EXPECT_EQ(syms.symbols(0).name(), "counter");
  pb::GetMemoryMapRequest mreq;
  mreq.set_program_id(id_);
  pb::GetMemoryMapResponse map;
  ASSERT_TRUE(backend_->GetMemoryMap(ctx_, mreq, map).ok());
  bool in = false;
  for (const auto &b : map.blocks())
    if (b.range().first().offset() <= counter && counter <= b.range().last().offset()) in = true;
  EXPECT_TRUE(in);
  // The constant 0x41 in twice's C, as the card spells it.
  bool constant = false;
  const pb::DecompiledFunction twice = Decompile(Symbol("twice"));
  for (const auto &line : twice.lines())
    for (const auto &t : line.tokens())
      if (t.kind() == pb::CODE_TOKEN_KIND_CONSTANT && t.has_value() && t.value() == 0x41) constant = true;
  EXPECT_TRUE(constant);
}

}  // namespace
}  // namespace revkit::backend
