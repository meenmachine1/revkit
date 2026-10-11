// Editing what bytes are from the listing (docs/listing-edit.md): Clear,
// Disassemble here, Define data and constant ranges as assertions, on a
// program compiled at test time, through the api::Backend interface.
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <set>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

constexpr const char *kProgram = R"(
#include <string.h>
struct conf { int magic; short port; short flags; const char *name; };
struct conf config = {0x1234, 80, 3, "server"};
const char banner[] = "hello listing";
int threshold = 0x12345678;
unsigned slots[4];
const char *greeting = "greetings, listing";
__attribute__((noinline)) int get_port(void) { return config.port + config.flags; }
__attribute__((noinline)) int helper(int x) { return x * 3 + threshold; }
__attribute__((noinline)) const char *get_banner(void) { return banner; }
__attribute__((noinline)) const char *get_greeting(void) { return greeting; }
int main(int argc, char **argv) {
  (void)argv;
  slots[argc & 3]++;
  return get_port() + helper(argc) + (int)strlen(get_banner()) + (int)strlen(get_greeting());
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

class ListingEditTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("listing-edit");
    exe_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O1 -fno-pie -no-pie", exe_);
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

  std::map<std::string, std::uint64_t> Functions() {
    pb::ListFunctionsRequest req;
    req.set_program_id(id_);
    req.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(backend_->ListFunctions(ctx_, req, resp).ok());
    std::map<std::string, std::uint64_t> out;
    for (const auto &f : resp.functions()) out[f.name()] = f.entry().offset();
    return out;
  }

  std::string Decompile(std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(id_);
    req.mutable_function()->set_offset(entry);
    req.mutable_options()->set_include_text(true);
    pb::DecompileResponse resp;
    auto st = backend_->Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return Text(resp.function());
  }

  // The rows from `a` on (no header rows).
  std::vector<pb::ListingRow> Rows(std::uint64_t a, std::uint32_t n = 8) {
    pb::GetListingRequest req;
    req.set_program_id(id_);
    req.mutable_addresses()->mutable_start()->set_offset(a);
    req.mutable_addresses()->set_max_rows(n);
    pb::GetListingResponse resp;
    EXPECT_TRUE(backend_->GetListing(ctx_, req, resp).ok());
    return {resp.rows().begin(), resp.rows().end()};
  }
  pb::ListingRow Row(std::uint64_t a) {
    for (const auto &r : Rows(a))
      if (r.address().offset() == a && !r.has_data_parent()) return r;
    return {};
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
  pb::AppendAssertionsResponse MustEdit(const pb::AssertionBody &body) {
    pb::AppendAssertionsResponse resp;
    auto st = Edit(body, &resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
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

  static pb::AssertionBody Data(std::uint64_t a, const std::string &type, std::uint64_t count = 0) {
    pb::AssertionBody b;
    b.mutable_listing_edit()->mutable_address()->set_offset(a);
    b.mutable_listing_edit()->mutable_data()->mutable_type()->set_c_declaration(type);
    b.mutable_listing_edit()->mutable_data()->set_count(count);
    return b;
  }
  static pb::AssertionBody String(std::uint64_t a) {
    pb::AssertionBody b;
    b.mutable_listing_edit()->mutable_address()->set_offset(a);
    b.mutable_listing_edit()->mutable_data()->set_string(pb::STRING_ENCODING_UTF8);
    return b;
  }
  static pb::AssertionBody Clear(std::uint64_t a, std::uint64_t n) {
    pb::AssertionBody b;
    b.mutable_listing_edit()->mutable_address()->set_offset(a);
    b.mutable_listing_edit()->mutable_clear()->set_length(n);
    return b;
  }
  static pb::AssertionBody Disassemble(std::uint64_t a, bool function = false) {
    pb::AssertionBody b;
    b.mutable_listing_edit()->mutable_address()->set_offset(a);
    b.mutable_listing_edit()->mutable_disassemble()->set_function(function);
    return b;
  }
  static pb::AssertionBody Mutability(std::uint64_t a, std::uint64_t n, pb::Mutability m) {
    pb::AssertionBody b;
    b.mutable_mutability()->mutable_address()->set_offset(a);
    b.mutable_mutability()->set_length(n);
    b.mutable_mutability()->set_mutability(m);
    return b;
  }

  static inline std::filesystem::path exe_;
  static inline bool compiled_ = false;
  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
  std::string id_;
};

TEST_F(ListingEditTest, AStructOverAGlobalTypesTheDecompilerAndTheListing) {
  const std::uint64_t config = Symbol("config");
  const std::uint64_t get_port = Functions().at("get_port");
  const std::string before = Decompile(get_port);
  EXPECT_EQ(before.find("config.port"), std::string::npos) << before;

  auto done = MustEdit(Data(config, "struct conf { int magic; short port; short flags; const char *name; }"));
  ASSERT_GE(done.assertions_size(), 1);
  const pb::DefineData &stored = done.assertions(0).body().listing_edit().data();
  EXPECT_EQ(stored.size(), 16u);
  EXPECT_EQ(stored.type_name(), "struct conf");
  EXPECT_EQ(done.assertions(0).key().kind(), pb::FACT_KIND_CODE_UNIT);
  EXPECT_EQ(done.assertions(0).key().sub(), "data");

  // The decompiler sees the global's type, live.
  const std::string after = Decompile(get_port);
  EXPECT_NE(after.find("config.port"), std::string::npos) << after;
  EXPECT_NE(after.find("config.flags"), std::string::npos) << after;

  // The listing: the item, then a row per field (a struct is expanded).
  std::vector<pb::ListingRow> rows = Rows(config, 6);
  ASSERT_GE(rows.size(), 5u);
  EXPECT_EQ(rows[0].kind(), pb::LISTING_ROW_KIND_DATA);
  EXPECT_EQ(rows[0].data_type(), "struct conf");
  EXPECT_EQ(rows[0].data_components(), 4u);
  EXPECT_TRUE(rows[0].has_unit_origin());
  EXPECT_EQ(rows[0].unit_origin().asserted().provenance().id(), "alice");
  const char *fields[] = {"magic", "port", "flags", "name"};
  const std::uint64_t offsets[] = {0, 4, 6, 8};
  for (int i = 0; i < 4; ++i) {
    const pb::ListingRow &f = rows[static_cast<std::size_t>(i) + 1];
    EXPECT_EQ(f.data_field(), fields[i]);
    EXPECT_EQ(f.address().offset(), config + offsets[i]);
    EXPECT_EQ(f.data_parent().offset(), config);
    EXPECT_EQ(f.data_depth(), 1u);
  }
  std::string port;
  for (const auto &t : rows[2].tokens()) port += t.text();
  EXPECT_NE(port.find("50h"), std::string::npos) << port;  // 80

  // The pointer field refers to "server": a reference from data.
  std::uint64_t server = 0;
  for (const auto &t : rows[4].tokens())
    if (t.has_target()) server = t.target().offset();
  ASSERT_NE(server, 0u);
  pb::GetXrefsRequest xr;
  xr.set_program_id(id_);
  xr.mutable_address()->set_offset(server);
  pb::GetXrefsResponse xs;
  ASSERT_TRUE(backend_->GetXrefs(ctx_, xr, xs).ok());
  bool from_field = false;
  for (const auto &x : xs.xrefs())
    from_field |= x.from_address().offset() == config + 8 && x.kind() == pb::XREF_KIND_DATA_POINTER;
  EXPECT_TRUE(from_field);

  // Collapsing it is the same definition, asserted again.
  pb::AssertionBody collapsed = Data(config, "struct conf { int magic; short port; short flags; const char *name; }");
  collapsed.mutable_listing_edit()->mutable_data()->set_collapsed(true);
  auto folded = MustEdit(collapsed);
  rows = Rows(config, 2);
  EXPECT_TRUE(rows[0].data_collapsed());
  EXPECT_FALSE(rows[1].has_data_parent());

  // Undo, twice: the decompilation is the one from before.
  Undo(folded);
  Undo(done);
  EXPECT_EQ(Decompile(get_port), before);
  EXPECT_FALSE(Row(config).has_unit_origin());
}

TEST_F(ListingEditTest, ClearRemovesAFunctionAndDisassembleBringsItBack) {
  auto functions = Functions();
  ASSERT_TRUE(functions.contains("helper"));
  const std::uint64_t helper = functions.at("helper");
  pb::GetFunctionRequest fr;
  fr.set_program_id(id_);
  fr.mutable_address()->set_offset(helper);
  pb::GetFunctionResponse f;
  ASSERT_TRUE(backend_->GetFunction(ctx_, fr, f).ok());
  std::uint64_t last = helper;
  for (const auto &r : f.function().body()) last = std::max(last, r.last().offset());

  auto cleared = MustEdit(Clear(helper, last - helper + 1));
  EXPECT_EQ(cleared.assertions(0).key().sub(), "clear:" + [&] {
    char buf[24];
    std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(last - helper + 1));
    return std::string(buf);
  }());
  // Gone, though main still calls it; its bytes are undefined.
  EXPECT_FALSE(Functions().contains("helper"));
  pb::ListingRow row = Row(helper);
  EXPECT_EQ(row.kind(), pb::LISTING_ROW_KIND_UNDEFINED);
  EXPECT_TRUE(row.has_unit_origin());

  // Disassemble here: code again, and a function since main calls it.
  auto code = MustEdit(Disassemble(helper));
  EXPECT_TRUE(Functions().contains("helper"));
  EXPECT_EQ(Row(helper).kind(), pb::LISTING_ROW_KIND_INSTRUCTION);
  EXPECT_NE(Decompile(helper).find("threshold"), std::string::npos);

  // Undoing it clears the bytes again; undoing the Clear brings it back.
  Undo(code);
  EXPECT_FALSE(Functions().contains("helper"));
  Undo(cleared);
  EXPECT_TRUE(Functions().contains("helper"));
  EXPECT_FALSE(Row(helper).has_unit_origin());
}

TEST_F(ListingEditTest, DisassembleHereMakesCodeAFunctionWhenAsked) {
  const std::uint64_t helper = Functions().at("helper");
  auto cleared = MustEdit(Clear(helper, 4));
  EXPECT_FALSE(Functions().contains("helper"));
  MustEdit(Disassemble(helper, true));
  pb::GetFunctionRequest fr;
  fr.set_program_id(id_);
  fr.mutable_address()->set_offset(helper);
  pb::GetFunctionResponse f;
  EXPECT_TRUE(backend_->GetFunction(ctx_, fr, f).ok());
}

TEST_F(ListingEditTest, AStringShowsInTheListingWithItsReferences) {
  const std::uint64_t banner = Symbol("banner");
  auto done = MustEdit(String(banner));
  EXPECT_EQ(done.assertions(0).body().listing_edit().data().size(), 14u);
  pb::ListingRow row = Row(banner);
  EXPECT_EQ(row.kind(), pb::LISTING_ROW_KIND_DATA);
  EXPECT_EQ(row.data_type(), "char[14]");
  std::string text;
  for (const auto &t : row.tokens()) text += t.text();
  EXPECT_NE(text.find("\"hello listing\""), std::string::npos) << text;
  EXPECT_GE(row.xref_to_count(), 1u);  // get_banner

  // Its defined data, by category.
  pb::ListDataRequest req;
  req.set_program_id(id_);
  req.add_categories(pb::DATA_CATEGORY_STRING);
  req.set_text_contains("hello listing");
  pb::ListDataResponse resp;
  ASSERT_TRUE(backend_->ListData(ctx_, req, resp).ok());
  ASSERT_EQ(resp.data_size(), 1);
  EXPECT_EQ(resp.data(0).data_type(), "char[14]");
  EXPECT_TRUE(resp.data(0).origin().has_asserted());

  // A dword over part of it removes it: its bytes are undefined.
  auto dword = MustEdit(Data(banner + 4, "dword"));
  EXPECT_NE(Row(banner).kind(), pb::LISTING_ROW_KIND_DATA);
  EXPECT_EQ(Row(banner + 4).data_type(), "uint32_t");
  Undo(dword);
  EXPECT_EQ(Row(banner).data_type(), "char[14]");
}

TEST_F(ListingEditTest, ConstantAndVolatileRanges) {
  const std::uint64_t threshold = Symbol("threshold");
  const std::uint64_t helper = Functions().at("helper");
  const std::string before = Decompile(helper);
  EXPECT_EQ(before.find("0x12345678"), std::string::npos) << before;

  auto constant = MustEdit(Mutability(threshold, 4, pb::MUTABILITY_CONSTANT));
  EXPECT_EQ(constant.assertions(0).key().kind(), pb::FACT_KIND_MUTABILITY);
  EXPECT_EQ(constant.assertions(0).key().sub(), "4");
  EXPECT_NE(Decompile(helper).find("0x12345678"), std::string::npos);
  EXPECT_EQ(Row(threshold).mutability(), pb::MUTABILITY_CONSTANT);

  // Volatile over it wins (the newer edit); undoing it folds again.
  auto vol = MustEdit(Mutability(threshold, 4, pb::MUTABILITY_VOLATILE));
  EXPECT_EQ(Decompile(helper).find("0x12345678"), std::string::npos);
  Undo(vol);
  EXPECT_NE(Decompile(helper).find("0x12345678"), std::string::npos);
  Undo(constant);
  EXPECT_EQ(Decompile(helper), before);
}

TEST_F(ListingEditTest, DataInUninitializedMemory) {
  const std::uint64_t slots = Symbol("slots");
  auto done = MustEdit(Data(slots, "dword", 4));
  pb::ListingRow row = Row(slots);
  EXPECT_EQ(row.data_type(), "uint32_t[4]");
  std::string text;
  for (const auto &t : row.tokens()) text += t.text();
  EXPECT_NE(text.find("??"), std::string::npos) << text;
  EXPECT_EQ(Edit(String(slots)).code, StatusCode::kInvalidArgument);  // no bytes to find its end in
}

// References to `to` from data (DATA_POINTER), by their from address.
std::set<std::uint64_t> DataPointersTo(api::Backend &backend, CallContext &ctx, const std::string &id, std::uint64_t to) {
  pb::GetXrefsRequest req;
  req.set_program_id(id);
  req.mutable_address()->set_offset(to);
  pb::GetXrefsResponse resp;
  EXPECT_TRUE(backend.GetXrefs(ctx, req, resp).ok());
  std::set<std::uint64_t> out;
  for (const auto &x : resp.xrefs())
    if (x.kind() == pb::XREF_KIND_DATA_POINTER) out.insert(x.from_address().offset());
  return out;
}

TEST_F(ListingEditTest, FieldRowsFollowTheBoundDefinitionOfTheirStruct) {
  const std::uint64_t config = Symbol("config");
  MustEdit(Data(config, "struct conf { int magic; short port; short flags; const char *name; }"));
  std::vector<pb::ListingRow> rows = Rows(config, 6);
  ASSERT_GE(rows.size(), 5u);
  EXPECT_EQ(rows[0].data_components(), 4u);
  std::uint64_t server = 0;
  for (const auto &t : rows[4].tokens())
    if (t.has_target()) server = t.target().offset();
  ASSERT_NE(server, 0u);
  EXPECT_TRUE(DataPointersTo(*backend_, ctx_, id_, server).contains(config + 8));

  // Another definition of struct conf, bound to the name (Edit in C, a
  // header import): the rows show its fields, and its third field is no
  // pointer, so the reference from it goes.
  pb::ParseCRequest parse;
  parse.set_program_id(id_);
  parse.add_sources()->set_text("struct conf { int magic; int port_flags; long long name_bits; };");
  pb::ParseCResponse parsed;
  ASSERT_TRUE(backend_->ParseC(ctx_, parse, parsed).ok());
  pb::AppendAssertionsRequest req;
  req.set_program_id(id_);
  req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  req.mutable_provenance()->set_id("alice");
  for (const auto &n : parsed.nodes()) *req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type() = n;
  for (const auto &n : parsed.named())
    req.add_assertions()->mutable_body()->mutable_bind_type_name()->mutable_type()->set_assertion_index(n.index());
  pb::AppendAssertionsResponse bound;
  auto st = backend_->AppendAssertions(ctx_, req, bound);
  ASSERT_TRUE(st.ok()) << st.message;

  rows = Rows(config, 6);
  ASSERT_GE(rows.size(), 4u);
  EXPECT_EQ(rows[0].data_type(), "struct conf");
  EXPECT_EQ(rows[0].data_components(), 3u);
  const char *fields[] = {"magic", "port_flags", "name_bits"};
  const std::uint64_t offsets[] = {0, 4, 8};
  for (int i = 0; i < 3; ++i) {
    const pb::ListingRow &f = rows[static_cast<std::size_t>(i) + 1];
    EXPECT_EQ(f.data_field(), fields[i]);
    EXPECT_EQ(f.address().offset(), config + offsets[i]);
    EXPECT_EQ(f.data_parent().offset(), config);
  }
  EXPECT_FALSE(DataPointersTo(*backend_, ctx_, id_, server).contains(config + 8));

  // Undoing the binding gives the fields and the reference back.
  Undo(bound);
  rows = Rows(config, 6);
  ASSERT_GE(rows.size(), 5u);
  EXPECT_EQ(rows[0].data_components(), 4u);
  EXPECT_EQ(rows[4].data_field(), "name");
  EXPECT_TRUE(DataPointersTo(*backend_, ctx_, id_, server).contains(config + 8));
}

TEST_F(ListingEditTest, AnalysisPointersAreReferences) {
  // `greeting` holds a pointer to its string; analysis lays a pointer there
  // (get_greeting reads it), which refers to the string as Ghidra's does.
  const std::uint64_t greeting = Symbol("greeting");
  pb::ListingRow row = Row(greeting);
  ASSERT_EQ(row.kind(), pb::LISTING_ROW_KIND_DATA);
  std::uint64_t text = 0;
  for (const auto &t : row.tokens())
    if (t.has_target()) text = t.target().offset();
  ASSERT_NE(text, 0u);
  EXPECT_TRUE(DataPointersTo(*backend_, ctx_, id_, text).contains(greeting));
  EXPECT_GE(Row(text).xref_to_count(), 1u);
}

TEST_F(ListingEditTest, BadEditsAreRefused) {
  const std::uint64_t config = Symbol("config");
  EXPECT_EQ(Edit(Data(config, "struct no_such_type")).code, StatusCode::kInvalidArgument);
  EXPECT_EQ(Edit(Data(config, "int (void)")).code, StatusCode::kInvalidArgument);
  EXPECT_EQ(Edit(Clear(config, 0)).code, StatusCode::kInvalidArgument);
  EXPECT_EQ(Edit(Clear(0x10, 4)).code, StatusCode::kInvalidArgument);  // not in memory
  EXPECT_EQ(Edit(Mutability(config, 4, pb::MUTABILITY_UNSPECIFIED)).code, StatusCode::kInvalidArgument);
  pb::AssertionBody thumb = Disassemble(config);
  thumb.mutable_listing_edit()->mutable_disassemble()->set_instruction_set(pb::INSTRUCTION_SET_THUMB);
  EXPECT_EQ(Edit(thumb).code, StatusCode::kInvalidArgument);  // x86 has one instruction set
}

}  // namespace
}  // namespace revkit::backend
