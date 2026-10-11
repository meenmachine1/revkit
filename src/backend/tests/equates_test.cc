// Equates and user references (docs/api.md, "Equates and user
// references"): how a scalar shows (Convert, Set Equate, an enum member)
// in the listing and the decompiler, and references the user adds or
// deletes, as discovery, xrefs, the listing and the decompiler follow them,
// on the corpus's features program and on one compiled at test time,
// through the api::Backend interface.
#include "builders.hh"

#include "revkit/analysis/user_refs.h"
#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <set>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;

constexpr const char *kProgram = R"(
#include <stdint.h>
int table_g[4] = {1, 2, 3, 4};
__attribute__((noinline)) int is_a(int c) { return c == 'A' ? 3 : 5; }
__attribute__((noinline)) int weigh(int x) { return x * 0x1234 + table_g[x & 3]; }
__attribute__((noinline)) int sevens(int x) { return (x + 7) * 7; }
__attribute__((noinline)) int add7(int x) { return x + 7; }
#if defined(__x86_64__)
__asm__(".text\n.p2align 4\n.globl anchor_fn\n.type anchor_fn,@function\nanchor_fn:\n  ret\n"
        ".p2align 4\n.Lhidden_target:\n  leal 3(%rdi,%rdi,4), %eax\n  ret\n");
extern int hidden_target(int) __asm__(".Lhidden_target");
__asm__(".text\n.p2align 4\n.globl jumper\n.type jumper,@function\njumper:\n"
        "  leaq .Lcase(%rip), %rax\n  addq bias(%rip), %rax\n  jmp *%rax\n.Lcase:\n  movl $5, %eax\n  ret\n");
extern int jumper(void);
#else
__attribute__((noinline)) int jumper(void) { return 5; }
__attribute__((noinline)) int hidden_target(int x) { return x * 5 + 3; }
#endif
volatile long bias;
__attribute__((noinline)) int call_through(int x) {
  int (*f)(int) = (int (*)(int))((char *)hidden_target + bias);
  return f(x) + 1;
}
int main(int argc, char **argv) {
  (void)argv;
  return is_a(argc) + weigh(argc) + sevens(argc) + add7(argc) + call_through(argc) + jumper();
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

std::string RowText(const pb::ListingRow &r) {
  std::string out;
  for (const auto &t : r.tokens()) out += t.text();
  return out;
}

class EquatesTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("equates");
    exe_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O1 -fno-pie -no-pie", exe_);
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
  }

  void Import(const std::filesystem::path &path) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(path.string());
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    id_ = resp.program().program_id();
  }
  void ImportCompiled() {
    if (!compiled_) GTEST_SKIP() << "no C compiler";
    Import(exe_);
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
  bool FunctionAt(std::uint64_t entry) {
    for (const auto &[name, e] : Functions())
      if (e == entry) return true;
    return false;
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
  std::string Decompile(std::uint64_t entry) { return Text(Decompiled(entry)); }

  // A function's instruction rows.
  std::vector<pb::ListingRow> Rows(std::uint64_t entry) {
    pb::GetListingRequest req;
    req.set_program_id(id_);
    req.mutable_addresses()->mutable_start()->set_offset(entry);
    req.mutable_addresses()->set_max_rows(400);
    pb::GetListingResponse resp;
    EXPECT_TRUE(backend_->GetListing(ctx_, req, resp).ok());
    std::vector<pb::ListingRow> out;
    for (const auto &r : resp.rows())
      if (r.kind() == pb::LISTING_ROW_KIND_INSTRUCTION && r.function().offset() == entry) out.push_back(r);
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
  // The first instruction of a function with a scalar of `value` (and the
  // mnemonic, if given): its address and the scalar's operand.
  std::pair<std::uint64_t, std::uint32_t> ScalarIn(std::uint64_t entry, std::int64_t value, const std::string &mnemonic = "") {
    for (const auto &r : Rows(entry)) {
      if (!mnemonic.empty() && (r.tokens().empty() || r.tokens(0).text() != mnemonic)) continue;
      for (const auto &t : r.tokens())
        if (t.kind() == pb::LISTING_TOKEN_KIND_SCALAR && t.value() == value) return {r.address().offset(), t.operand_index()};
    }
    ADD_FAILURE() << "no scalar " << value << " in the function at 0x" << std::hex << entry;
    return {0, 0};
  }
  const pb::ListingToken *Operand(const pb::ListingRow &r, std::uint32_t operand) {
    for (const auto &t : r.tokens())
      if (t.has_operand_index() && t.operand_index() == operand &&
          (t.kind() == pb::LISTING_TOKEN_KIND_SCALAR || t.kind() == pb::LISTING_TOKEN_KIND_SYMBOL ||
           t.kind() == pb::LISTING_TOKEN_KIND_ADDRESS))
        return &t;
    return nullptr;
  }

  api::Status Edit(const std::vector<pb::AssertionBody> &bodies, pb::AppendAssertionsResponse *out = nullptr) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(id_);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    for (const auto &b : bodies) *req.add_assertions()->mutable_body() = b;
    pb::AppendAssertionsResponse resp;
    auto st = backend_->AppendAssertions(ctx_, req, resp);
    if (out) *out = resp;
    return st;
  }
  pb::AppendAssertionsResponse MustEdit(const pb::AssertionBody &body) {
    pb::AppendAssertionsResponse resp;
    auto st = Edit({body}, &resp);
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

  static pb::AssertionBody Format(std::uint64_t a, std::uint64_t value, pb::ScalarFormat f) {
    pb::AssertionBody b;
    b.mutable_operand_display()->mutable_address()->set_offset(a);
    b.mutable_operand_display()->set_value(value);
    b.mutable_operand_display()->set_format(f);
    return b;
  }
  static pb::AssertionBody Equate(std::uint64_t a, std::uint64_t value, const std::string &name) {
    pb::AssertionBody b;
    b.mutable_operand_display()->mutable_address()->set_offset(a);
    b.mutable_operand_display()->set_value(value);
    b.mutable_operand_display()->mutable_equate()->set_name(name);
    return b;
  }
  static pb::AssertionBody Member(std::uint64_t a, std::uint64_t value, const std::string &hash, const std::string &member) {
    pb::AssertionBody b;
    b.mutable_operand_display()->mutable_address()->set_offset(a);
    b.mutable_operand_display()->set_value(value);
    b.mutable_operand_display()->mutable_equate()->set_enum_type_hash(hash);
    b.mutable_operand_display()->mutable_equate()->set_member(member);
    return b;
  }
  static pb::AssertionBody Reference(std::uint64_t from, std::optional<std::uint32_t> operand, std::uint64_t to,
                                     pb::ReferenceType type, bool primary = false, bool remove = false) {
    pb::AssertionBody b;
    pb::UserReference &r = *b.mutable_reference();
    r.mutable_from()->set_offset(from);
    if (operand) r.set_operand_index(*operand);
    r.mutable_to()->set_offset(to);
    r.set_type(type);
    r.set_primary(primary);
    r.set_remove(remove);
    return b;
  }

  // An enum the user defines (as in Ghidra's data type manager).
  std::string DefineEnum(const std::string &name, const std::vector<std::pair<std::string, std::int64_t>> &members) {
    pb::AssertionBody b;
    pb::TypeNode &t = *b.mutable_define_type()->mutable_type();
    t.set_kind(pb::TYPE_KIND_ENUM);
    t.set_name(name);
    t.set_size(4);
    for (const auto &[n, v] : members) {
      auto *e = t.add_enumerators();
      e->set_name(n);
      e->set_value(v);
    }
    return MustEdit(b).assertions(0).key().sub();
  }

  std::vector<pb::Xref> Xrefs(std::uint64_t a, pb::XrefDirection dir) {
    pb::GetXrefsRequest req;
    req.set_program_id(id_);
    req.mutable_address()->set_offset(a);
    req.set_direction(dir);
    pb::GetXrefsResponse resp;
    EXPECT_TRUE(backend_->GetXrefs(ctx_, req, resp).ok());
    return {resp.xrefs().begin(), resp.xrefs().end()};
  }

  static inline std::filesystem::path exe_;
  static inline bool compiled_ = false;
  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
  std::string id_;
};

TEST(ScalarDisplay, FormatsAsGhidrasConvertDoes) {
  using analysis::format_scalar;
  using F = analysis::ScalarFormat;
  EXPECT_EQ(format_scalar(0x41, 32, F::chr), "'A'");
  EXPECT_EQ(format_scalar(0x4142, 32, F::chr), "'AB'");
  EXPECT_EQ(format_scalar(0x0a, 8, F::chr), "'\\n'");
  EXPECT_EQ(format_scalar(0x01, 8, F::chr), "'\\x01'");
  EXPECT_EQ(format_scalar(~std::uint64_t{0xf}, 32, F::hex), "0xfffffff0");
  EXPECT_EQ(format_scalar(~std::uint64_t{0xf}, 32, F::signed_dec), "-16");
  EXPECT_EQ(format_scalar(~std::uint64_t{0xf}, 32, F::unsigned_dec), "4294967280");
  EXPECT_EQ(format_scalar(0x41, 32, F::octal), "101o");
  EXPECT_EQ(format_scalar(0x41, 32, F::binary), "1000001b");
  EXPECT_EQ(format_scalar(0, 32, F::binary), "0b");
  EXPECT_EQ(format_scalar(0x3fc00000, 32, F::flt), "1.5");
  EXPECT_EQ(format_scalar(0x4000000000000000ULL, 64, F::flt), "2.0");
  EXPECT_EQ(format_scalar(0x41, 16, F::flt), "");
  EXPECT_TRUE(analysis::scalar_matches(~std::uint64_t{0xf}, 0xfffffff0, 32));
  EXPECT_FALSE(analysis::scalar_matches(0x1f0, 0xf0, 8));
  auto d = analysis::parse_operand_display("m:abc:RED");
  ASSERT_TRUE(d);
  EXPECT_EQ(d->name, "RED");
  EXPECT_EQ(analysis::encode_operand_display(*d), "m:abc:RED");
  auto r = analysis::parse_user_ref("i:401000", "6p");
  ASSERT_TRUE(r);
  EXPECT_EQ(r->operand, -1);
  EXPECT_EQ(r->to, 0x401000u);
  EXPECT_TRUE(r->primary);
  EXPECT_TRUE(r->is_call());
  EXPECT_FALSE(analysis::parse_user_ref("0:401000", "9"));
}

// On the corpus's features program: an enum member in place of a constant
// in the listing and the decompiler (an enum the user defines, found by
// value), Convert to char, and undo.
TEST_F(EquatesTest, CorpusFeaturesEnumMemberAndChar) {
  const std::filesystem::path bin = std::filesystem::path(REVKIT_CORPUS) / "elf-x86_64/gcc-O2/debug/features";
  if (!std::filesystem::exists(bin)) GTEST_SKIP() << "corpus not built";
  Import(bin);
  auto fns = Functions();

  // run_switches compares i % (NCOLORS + 1) with NCOLORS (color_weight's
  // default, inlined).
  const std::string color = DefineEnum("color", {{"RED", 0}, {"ORANGE", 1}, {"YELLOW", 2}, {"GREEN", 3}, {"BLUE", 4},
                                                 {"INDIGO", 5}, {"VIOLET", 6}, {"BLACK", 7}, {"WHITE", 8}, {"GREY", 9},
                                                 {"NCOLORS", 10}});
  {
    pb::FindTypesRequest req;
    req.set_program_id(id_);
    req.set_enum_value(10);
    req.add_sources(pb::TYPE_SOURCE_PROGRAM);
    pb::FindTypesResponse resp;
    ASSERT_TRUE(backend_->FindTypes(ctx_, req, resp).ok());
    ASSERT_EQ(resp.types_size(), 1);
    EXPECT_EQ(resp.types(0).hash(), color);
    req.set_enum_value(11);
    resp.Clear();
    ASSERT_TRUE(backend_->FindTypes(ctx_, req, resp).ok());
    EXPECT_EQ(resp.types_size(), 0);
  }
  const std::uint64_t rs = fns.at("run_switches");
  const auto [cmp, operand] = ScalarIn(rs, 10, "CMP");
  ASSERT_NE(cmp, 0u);
  EXPECT_NE(Decompile(rs).find("== 10)"), std::string::npos);

  auto done = MustEdit(Member(cmp, 10, color, "NCOLORS"));
  ASSERT_EQ(done.assertions_size(), 1);
  EXPECT_EQ(done.assertions(0).key().kind(), pb::FACT_KIND_EQUATE);
  EXPECT_EQ(done.assertions(0).key().sub(), std::to_string(operand) + ":a");
  EXPECT_EQ(done.assertions(0).body().operand_display().equate().name(), "NCOLORS");
  const pb::ListingRow row = Row(cmp);
  const pb::ListingToken *t = Operand(row, operand);
  ASSERT_NE(t, nullptr) << RowText(row);
  EXPECT_EQ(t->text(), "NCOLORS");
  EXPECT_EQ(t->value(), 10);
  EXPECT_EQ(t->display_origin().asserted().seq(), done.assertions(0).seq());
  const pb::DecompiledFunction f = Decompiled(rs);
  EXPECT_NE(Text(f).find("== NCOLORS)"), std::string::npos) << Text(f);
  bool token = false;
  for (const auto &line : f.lines())
    for (const auto &k : line.tokens())
      if (k.text() == "NCOLORS") {
        token = true;
        EXPECT_EQ(k.kind(), pb::CODE_TOKEN_KIND_CONSTANT);
        EXPECT_EQ(k.value(), 10u);
        EXPECT_TRUE(k.display_set());
      }
  EXPECT_TRUE(token);
  // A member of another value is refused.
  pb::AppendAssertionsResponse refused;
  EXPECT_FALSE(Edit({Member(cmp, 10, color, "GREY")}, &refused).ok());

  // Undo gives the number back in both.
  Undo(done);
  EXPECT_EQ(Operand(Row(cmp), operand)->text(), "0xa");
  EXPECT_FALSE(Operand(Row(cmp), operand)->has_display_origin());
  EXPECT_NE(Decompile(rs).find("== 10)"), std::string::npos);

  // Convert to char: run_varargs's 'A' + n % 26 in the listing; main's
  // '0' (argv[1][0] - '0') in the listing and the decompiler.
  const auto [lea, lea_operand] = ScalarIn(fns.at("run_varargs"), 0x41);
  ASSERT_NE(lea, 0u);
  auto chr = MustEdit(Format(lea, 0x41, pb::SCALAR_FORMAT_CHAR));
  EXPECT_EQ(Operand(Row(lea), lea_operand)->text(), "'A'");
  Undo(chr);
  EXPECT_EQ(Operand(Row(lea), lea_operand)->text(), "0x41");
  const std::uint64_t main = fns.at("main");
  const auto [sub, sub_operand] = ScalarIn(main, 0x30, "SUB");
  ASSERT_NE(sub, 0u);
  EXPECT_NE(Decompile(main).find("0x30"), std::string::npos);
  auto zero = MustEdit(Format(sub, 0x30, pb::SCALAR_FORMAT_CHAR));
  EXPECT_EQ(Operand(Row(sub), sub_operand)->text(), "'0'");
  const std::string converted = Decompile(main);
  EXPECT_NE(converted.find("'0'"), std::string::npos) << converted;
  EXPECT_EQ(converted.find("0x30"), std::string::npos) << converted;
  Undo(zero);
  EXPECT_NE(Decompile(main).find("0x30"), std::string::npos);
}

// On a program compiled here: Convert in each format, an equate and an
// equate applied to every matching scalar in the function, one name for one
// value, and a display cleared.
TEST_F(EquatesTest, ConvertAndSetEquate) {
  ImportCompiled();
  auto fns = Functions();
  const std::uint64_t is_a = fns.at("is_a");
  const auto [cmp, operand] = ScalarIn(is_a, 0x41);
  ASSERT_NE(cmp, 0u);

  // Convert to char: 'A' in both views.
  auto chr = MustEdit(Format(cmp, 0x41, pb::SCALAR_FORMAT_CHAR));
  EXPECT_EQ(Operand(Row(cmp), operand)->text(), "'A'");
  EXPECT_NE(Decompile(is_a).find("'A'"), std::string::npos) << Decompile(is_a);
  // Each format, in the listing and (except float) the decompiler.
  for (auto [format, text] : std::vector<std::pair<pb::ScalarFormat, std::string>>{
           {pb::SCALAR_FORMAT_HEX, "0x41"},
           {pb::SCALAR_FORMAT_UNSIGNED_DECIMAL, "65"},
           {pb::SCALAR_FORMAT_OCTAL, "101o"},
           {pb::SCALAR_FORMAT_BINARY, "1000001b"}}) {
    MustEdit(Format(cmp, 0x41, format));
    EXPECT_EQ(Operand(Row(cmp), operand)->text(), text) << format;
  }
  MustEdit(Format(cmp, 0x41, pb::SCALAR_FORMAT_UNSIGNED_DECIMAL));
  EXPECT_NE(Decompile(is_a).find("= 65"), std::string::npos) << Decompile(is_a);
  // A display cleared shows the disassembler's text.
  MustEdit(Format(cmp, 0x41, pb::SCALAR_FORMAT_UNSPECIFIED));
  EXPECT_EQ(Operand(Row(cmp), operand)->text(), "0x41");
  EXPECT_FALSE(Operand(Row(cmp), operand)->has_display_origin());

  // An equate, in both views.
  MustEdit(Equate(cmp, 0x41, "LETTER_A"));
  EXPECT_EQ(Operand(Row(cmp), operand)->text(), "LETTER_A");
  EXPECT_NE(Decompile(is_a).find("= LETTER_A"), std::string::npos) << Decompile(is_a);
  // One name has one value.
  const std::uint64_t sevens = fns.at("sevens");
  const auto [seven, seven_operand] = ScalarIn(sevens, 7);
  ASSERT_NE(seven, 0u);
  pb::AppendAssertionsResponse refused;
  auto st = Edit({Equate(seven, 7, "LETTER_A")}, &refused);
  EXPECT_FALSE(st.ok());
  EXPECT_NE(st.message.find("already has the value"), std::string::npos) << st.message;
  // No operand holds the value: refused.
  EXPECT_FALSE(Edit({Equate(seven, 0x99, "NINETY")}).ok());
  // Every 7 in the function, then in the program.
  pb::AssertionBody all = Equate(seven, 7, "SEVEN");
  all.mutable_operand_display()->set_apply_to(pb::EQUATE_SCOPE_FUNCTION);
  auto in_function = MustEdit(all);
  const std::uint64_t add7 = fns.at("add7");
  auto count = [&](std::uint64_t entry) {
    int shown = 0;
    for (const auto &r : Rows(entry))
      for (const auto &t : r.tokens())
        if (t.text() == "SEVEN") ++shown;
        else if (t.kind() == pb::LISTING_TOKEN_KIND_SCALAR && t.value() == 7) --shown;
    return shown;
  };
  EXPECT_GE(count(sevens), 1);
  EXPECT_LE(count(add7), 0);
  all.mutable_operand_display()->set_apply_to(pb::EQUATE_SCOPE_PROGRAM);
  auto applied = MustEdit(all);
  EXPECT_GE(applied.assertions_size(), 2);
  EXPECT_GE(count(sevens), 1);
  EXPECT_GE(count(add7), 1);
  EXPECT_NE(Decompile(add7).find("SEVEN"), std::string::npos) << Decompile(add7);
  // One undo takes them all back.
  Undo(applied);
  Undo(in_function);
  EXPECT_LE(count(sevens), 0);
  EXPECT_LE(count(add7), 0);
}

// User references: a computed call's target becomes a function the
// decompiler calls; a deleted analysis reference leaves xrefs; a primary
// reference shows its target in the operand.
TEST_F(EquatesTest, UserReferences) {
  ImportCompiled();
#if !defined(__x86_64__)
  GTEST_SKIP() << "the hidden target is x86-64 code";
#endif
  auto fns = Functions();
  const std::uint64_t hidden = Symbol("anchor_fn") + 16;
  ASSERT_FALSE(FunctionAt(hidden));
  const std::uint64_t ct = fns.at("call_through");
  std::uint64_t call = 0;
  for (const auto &r : Rows(ct))
    if (r.flow() == pb::FLOW_KIND_INDIRECT_CALL) call = r.address().offset();
  ASSERT_NE(call, 0u);
  const std::string before = Decompile(ct);
  EXPECT_NE(before.find("(*"), std::string::npos) << before;

  auto ref = MustEdit(Reference(call, std::nullopt, hidden, pb::REFERENCE_TYPE_COMPUTED_CALL, true));
  EXPECT_EQ(ref.assertions(0).key().kind(), pb::FACT_KIND_REFERENCE);
  EXPECT_TRUE(FunctionAt(hidden));
  char name[32];
  std::snprintf(name, sizeof name, "FUN_%08llx", static_cast<unsigned long long>(hidden));
  const std::string after = Decompile(ct);
  EXPECT_NE(after.find(std::string(name) + "("), std::string::npos) << after;
  EXPECT_EQ(after.find("(*"), std::string::npos) << after;
  // xrefs list it with the user's provenance.
  bool listed = false;
  for (const auto &x : Xrefs(hidden, pb::XREF_DIRECTION_TO))
    if (x.from_address().offset() == call) {
      listed = true;
      EXPECT_EQ(x.kind(), pb::XREF_KIND_INDIRECT_CALL);
      EXPECT_TRUE(x.primary());
      EXPECT_EQ(x.origin().asserted().seq(), ref.assertions(0).seq());
      EXPECT_FALSE(x.has_operand_index());
    }
  EXPECT_TRUE(listed);
  Undo(ref);
  EXPECT_FALSE(FunctionAt(hidden));
  EXPECT_NE(Decompile(ct).find("(*"), std::string::npos);

  // A computed jump's target: the flow goes on there, and the decompiler
  // takes it as the jump's table.
  const std::uint64_t jumper = fns.at("jumper");
  std::uint64_t jmp = 0, jmp_end = 0;
  for (const auto &r : Rows(jumper))
    if (r.flow() == pb::FLOW_KIND_INDIRECT_BRANCH) {
      jmp = r.address().offset();
      jmp_end = jmp + r.length();
    }
  ASSERT_NE(jmp, 0u);
  EXPECT_NE(Row(jmp_end).kind(), pb::LISTING_ROW_KIND_INSTRUCTION);
  EXPECT_EQ(Decompile(jumper).find("return 5"), std::string::npos);
  auto jump = MustEdit(Reference(jmp, std::nullopt, jmp_end, pb::REFERENCE_TYPE_COMPUTED_JUMP));
  const pb::ListingRow target = Row(jmp_end);
  EXPECT_EQ(target.kind(), pb::LISTING_ROW_KIND_INSTRUCTION);
  EXPECT_EQ(target.function().offset(), jumper);
  bool flows = false;
  const pb::ListingRow jmp_row = Row(jmp);
  for (const auto &t : jmp_row.flow_targets()) flows |= t.offset() == jmp_end;
  EXPECT_TRUE(flows);
  EXPECT_NE(Decompile(jumper).find("return 5"), std::string::npos) << Decompile(jumper);
  Undo(jump);
  EXPECT_NE(Row(jmp_end).kind(), pb::LISTING_ROW_KIND_INSTRUCTION);

  // main's call of is_a: deleted, then back with undo.
  const std::uint64_t main = fns.at("main"), is_a = fns.at("is_a");
  std::uint64_t from = 0;
  for (const auto &x : Xrefs(is_a, pb::XREF_DIRECTION_TO))
    if (x.from_function().offset() == main) from = x.from_address().offset();
  ASSERT_NE(from, 0u);
  auto removed = MustEdit(Reference(from, 0, is_a, pb::REFERENCE_TYPE_UNSPECIFIED, false, true));
  for (const auto &x : Xrefs(is_a, pb::XREF_DIRECTION_TO)) EXPECT_NE(x.from_address().offset(), from);
  EXPECT_TRUE(FunctionAt(is_a));  // discovery keeps what it found
  Undo(removed);
  bool back = false;
  for (const auto &x : Xrefs(is_a, pb::XREF_DIRECTION_TO)) back |= x.from_address().offset() == from;
  EXPECT_TRUE(back);

  // A primary data reference on weigh's 0x1234 shows table_g there.
  const std::uint64_t table = Symbol("table_g");
  const auto [imul, operand] = ScalarIn(fns.at("weigh"), 0x1234);
  ASSERT_NE(imul, 0u);
  auto data = MustEdit(Reference(imul, operand, table, pb::REFERENCE_TYPE_DATA_READ, true));
  const pb::ListingRow imul_row = Row(imul);
  const pb::ListingToken *t = Operand(imul_row, operand);
  ASSERT_NE(t, nullptr) << RowText(imul_row);
  EXPECT_EQ(t->text(), "table_g");
  EXPECT_EQ(t->target().offset(), table);
  EXPECT_EQ(t->reference_origin().asserted().seq(), data.assertions(0).seq());
  bool from_weigh = false;
  for (const auto &x : Xrefs(table, pb::XREF_DIRECTION_TO))
    if (x.from_address().offset() == imul) {
      from_weigh = true;
      EXPECT_EQ(x.kind(), pb::XREF_KIND_DATA_READ);
      EXPECT_EQ(x.operand_index(), operand);
    }
  EXPECT_TRUE(from_weigh);
  // A second primary reference on the operand: the first stops being
  // primary in the same revision.
  auto second = MustEdit(Reference(imul, operand, table + 4, pb::REFERENCE_TYPE_DATA_READ, true));
  EXPECT_EQ(second.assertions_size(), 2);
  int primaries = 0;
  for (const auto &x : Xrefs(imul, pb::XREF_DIRECTION_FROM))
    if (x.primary()) {
      ++primaries;
      EXPECT_EQ(x.to_address().offset(), table + 4);
    }
  EXPECT_EQ(primaries, 1);
  Undo(second);
  for (const auto &x : Xrefs(imul, pb::XREF_DIRECTION_FROM))
    if (x.primary()) EXPECT_EQ(x.to_address().offset(), table);
  // Refused: no instruction, no type.
  EXPECT_FALSE(Edit({Reference(table, std::nullopt, hidden, pb::REFERENCE_TYPE_CALL)}).ok());
  EXPECT_FALSE(Edit({Reference(imul, operand, table, pb::REFERENCE_TYPE_UNSPECIFIED)}).ok());
}

}  // namespace
}  // namespace revkit::backend
