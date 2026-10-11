// TypeService.ParseC, C-declaration retypes and bound types reaching
// debug-info variables, on the corpus's cJSON (docs/cparse.md).
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
namespace fs = std::filesystem;
using api::CallContext;
using api::StatusCode;

class ParseCTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    // cJSON.h from the corpus's cached tarball (scripts/build-corpus.sh).
    dir_ = testing::scratch_dir("parse-c");
    const fs::path tarball = fs::path(REVKIT_CORPUS).parent_path() / "cache" / "v1.7.18.tar.gz";
    if (!fs::exists(tarball)) return;
    const std::string cmd = "tar -xzf '" + tarball.string() + "' -C '" + dir_.string() + "' cJSON-1.7.18/cJSON.h";
    if (std::system(cmd.c_str()) != 0) return;
    header_ = dir_ / "cJSON-1.7.18" / "cJSON.h";
    std::ifstream in(header_);
    header_text_.assign(std::istreambuf_iterator<char>(in), {});
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    stripped_ = fs::path(REVKIT_CORPUS) / "elf-x86_64/gcc-O2/stripped/cjson";
    debug_ = fs::path(REVKIT_CORPUS) / "elf-x86_64/gcc-O2/debug/cjson";
    if (!fs::exists(stripped_) || !fs::exists(debug_) || header_text_.empty()) GTEST_SKIP() << "corpus not built";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.browse_roots = {dir_.string()};
    backend_ = MakeImageBackend(o);
  }

  std::string Import(const fs::path &path, const std::string &name) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(path.string());
    req.set_name(name);
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  std::uint64_t Entry(const std::string &program, const std::string &name) {
    pb::ListFunctionsRequest req;
    req.set_program_id(program);
    req.set_name_contains(name);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(backend_->ListFunctions(ctx_, req, resp).ok());
    for (const auto &f : resp.functions())
      if (f.name() == name) return f.entry().offset();
    ADD_FAILURE() << "no function " << name;
    return 0;
  }

  std::string Decompile(const std::string &program, std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(program);
    req.mutable_function()->set_offset(entry);
    req.mutable_options()->set_include_text(true);
    pb::DecompileResponse resp;
    auto st = backend_->Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.function().text();
  }

  pb::ParseCResponse Parse(const std::string &program, const std::string &text, bool prototypes = false,
                           api::Status *status = nullptr) {
    pb::ParseCRequest req;
    req.set_program_id(program);
    auto *s = req.add_sources();
    s->set_text(text);
    s->set_name("cJSON.h");
    req.mutable_options()->set_prototypes(prototypes);
    pb::ParseCResponse resp;
    api::Status st = backend_->ParseC(ctx_, req, resp);
    if (status) *status = st;
    else EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  // The header import as an SDK's import_header composes it: every node,
  // then a binding for every named type, in one request (one revision).
  pb::AppendAssertionsResponse ImportHeader(const std::string &program, const pb::ParseCResponse &parsed,
                                            const std::string &session, bool validate_only = false) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(program);
    req.set_validate_only(validate_only);
    auto *prov = req.mutable_provenance();
    prov->set_kind(pb::PROVENANCE_KIND_IMPORT);
    prov->set_id("header");
    prov->set_version("cJSON.h");
    prov->set_session(session);
    for (const auto &n : parsed.nodes()) *req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type() = n;
    for (const auto &n : parsed.named())
      req.add_assertions()->mutable_body()->mutable_bind_type_name()->mutable_type()->set_assertion_index(n.index());
    pb::AppendAssertionsResponse resp;
    auto st = backend_->AppendAssertions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  api::Status Retype(const std::string &program, std::uint64_t entry, const std::string &decl,
                     const std::string &session, pb::AppendAssertionsResponse *out = nullptr) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(program);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    req.mutable_provenance()->set_session(session);
    auto *r = req.add_assertions()->mutable_body()->mutable_retype();
    r->mutable_target()->mutable_address()->set_offset(entry);
    r->mutable_type()->set_c_declaration(decl);
    pb::AppendAssertionsResponse resp;
    auto st = backend_->AppendAssertions(ctx_, req, resp);
    if (out) *out = resp;
    return st;
  }

  void Revert(const std::string &program, pb::ProvenanceKind kind, const std::string &id, const std::string &session) {
    pb::RevertByProvenanceRequest req;
    req.set_program_id(program);
    req.mutable_filter()->set_kind(kind);
    req.mutable_filter()->set_id(id);
    req.mutable_filter()->set_session(session);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    pb::RevertByProvenanceResponse resp;
    auto st = backend_->RevertByProvenance(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
  }

  static inline fs::path dir_, header_;
  static inline std::string header_text_;
  fs::path stripped_, debug_;
  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
};

// The design's acceptance test: cJSON.h into stripped cjson, a parameter
// retyped to cJSON *, ->valuestring in the C; undo removes it all.
TEST_F(ParseCTest, HeaderImportRetypeAndUndo) {
  const std::string prog = Import(stripped_, "cjson");
  const std::string debug = Import(debug_, "cjson-debug");
  const std::uint64_t entry = Entry(debug, "cJSON_GetStringValue");  // the same address in both builds
  const std::string before = Decompile(prog, entry);
  EXPECT_EQ(before.find("->valuestring"), std::string::npos) << before;

  pb::ParseCResponse parsed = Parse(prog, header_text_, true);
  EXPECT_EQ(parsed.errors(), 0u);
  EXPECT_EQ(parsed.profile(), "x86_64-linux-gnu");
  std::set<std::string> keys;
  for (const auto &n : parsed.named()) keys.insert(n.key());
  for (const char *k : {"struct cJSON", "typedef cJSON", "struct cJSON_Hooks", "typedef cJSON_bool"})
    EXPECT_TRUE(keys.contains(k)) << k;
  EXPECT_GT(parsed.prototypes_size(), 60);
  EXPECT_GE(parsed.constants_size(), 10);

  const pb::AppendAssertionsResponse imported = ImportHeader(prog, parsed, "import-1");
  const std::uint64_t import_revision = imported.snapshot().revision();
  pb::AppendAssertionsResponse retyped;
  ASSERT_TRUE(Retype(prog, entry, "char *cJSON_GetStringValue(const cJSON * const item)", "edit-1", &retyped).ok());
  EXPECT_EQ(retyped.snapshot().revision(), import_revision + 1);
  // The retype is a hashed type, defined with it.
  ASSERT_GE(retyped.assertions_size(), 1);
  const std::string after = Decompile(prog, entry);
  EXPECT_NE(after.find("->valuestring"), std::string::npos) << after;
  EXPECT_NE(after.find("cJSON *item"), std::string::npos) << after;

  Revert(prog, pb::PROVENANCE_KIND_USER, "alice", "edit-1");
  Revert(prog, pb::PROVENANCE_KIND_IMPORT, "header", "import-1");
  EXPECT_EQ(Decompile(prog, entry), before);
  pb::FindTypesRequest find;
  find.set_program_id(prog);
  find.set_name_contains("cJSON");
  pb::FindTypesResponse found;
  ASSERT_TRUE(backend_->FindTypes(ctx_, find, found).ok());
  for (const auto &t : found.types()) EXPECT_FALSE(t.bound()) << t.name();
}

// The nodes intern, through DefineType, to the hashes ParseC computed; the
// debug build's own (DWARF) types are the very same types.
TEST_F(ParseCTest, NodesAreDefineTypeReadyAndMatchTheDebugInfo) {
  const std::string prog = Import(stripped_, "cjson");
  const std::string debug = Import(debug_, "cjson-debug");
  pb::ParseCResponse parsed = Parse(prog, header_text_, true);
  pb::AppendAssertionsResponse validated = ImportHeader(prog, parsed, "v", true);
  ASSERT_EQ(validated.assertions_size(), parsed.nodes_size() + parsed.named_size());
  for (int i = 0; i < parsed.nodes_size(); ++i)
    EXPECT_EQ(validated.assertions(i).key().sub(), parsed.hashes(i)) << "nodes[" << i << "]";
  for (const auto &n : parsed.named()) EXPECT_TRUE(n.existing_hash().empty()) << n.key();

  pb::ParseCResponse on_debug = Parse(debug, header_text_);
  EXPECT_EQ(on_debug.conflicts_size(), 0);
  for (const auto &n : on_debug.named()) EXPECT_EQ(n.existing_hash(), n.hash()) << n.key();

  // An edit of struct cJSON: a renamed member is a conflict with the same
  // layout; an added one changes it.
  std::string renamed = header_text_;
  renamed.replace(renamed.find("char *valuestring;"), 18, "char *str_value;");
  pb::ParseCResponse r1 = Parse(debug, renamed);
  bool seen = false;
  for (const auto &c : r1.conflicts())
    if (c.named_key() == "struct cJSON") {
      seen = true;
      EXPECT_TRUE(c.same_layout());
    }
  EXPECT_TRUE(seen);
  std::string grown = header_text_;
  grown.replace(grown.find("char *valuestring;"), 18, "char *valuestring; int extra;");
  pb::ParseCResponse r2 = Parse(debug, grown);
  for (const auto &c : r2.conflicts())
    if (c.named_key() == "struct cJSON") EXPECT_FALSE(c.same_layout());
}

TEST_F(ParseCTest, DiagnosticsAndHostFiles) {
  const std::string prog = Import(stripped_, "cjson");
  pb::ParseCResponse bad = Parse(prog, "struct ok { int a; };\nstruct bad { mystery_t x; };\n#include \"../../../../etc/passwd\"\n");
  EXPECT_GT(bad.errors(), 0u);
  ASSERT_GE(bad.diagnostics_size(), 1);
  EXPECT_EQ(bad.diagnostics(0).line(), 2u);
  EXPECT_EQ(bad.diagnostics(0).source_line(), "struct bad { mystery_t x; };");
  EXPECT_EQ(bad.diagnostics(0).severity(), pb::PARSE_C_SEVERITY_ERROR);
  bool ok = false;
  for (const auto &n : bad.named()) ok |= n.key() == "struct ok";
  EXPECT_TRUE(ok);

  // A file under the browse root, with an include beside it.
  pb::ParseCRequest req;
  req.set_program_id(prog);
  req.add_sources()->set_path(header_.string());
  pb::ParseCResponse resp;
  ASSERT_TRUE(backend_->ParseC(ctx_, req, resp).ok());
  EXPECT_EQ(resp.errors(), 0u);
  ASSERT_EQ(resp.files_size(), 1);
  // Outside the roots: refused, and so is an include directory there.
  pb::ParseCRequest out = req;
  out.mutable_sources(0)->set_path("/etc/hostname");
  EXPECT_EQ(backend_->ParseC(ctx_, out, resp).code, StatusCode::kNotFound);
  pb::ParseCRequest inc;
  inc.set_program_id(prog);
  inc.add_sources()->set_text("#include <x.h>\n");
  inc.add_include_dirs("/usr/include");
  EXPECT_EQ(backend_->ParseC(ctx_, inc, resp).code, StatusCode::kPermissionDenied);
  // Without --browse-root no host file is read.
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  auto closed = MakeImageBackend(o);
  pb::ImportProgramRequest imp;
  imp.set_project_id("default");
  imp.set_path(stripped_.string());
  pb::ImportProgramResponse ir;
  ASSERT_TRUE(closed->ImportProgram(ctx_, imp, ir).ok());
  req.set_program_id(ir.program().program_id());
  EXPECT_EQ(closed->ParseC(ctx_, req, resp).code, StatusCode::kFailedPrecondition);
}

// "__revkit_type_<hash>" is the program's type with that hash itself, and
// an anonymous struct or union by hash is an anonymous member: a struct
// written with its fields' types by hash is the same struct (what the type
// editor does with the fields an edit didn't change).
TEST_F(ParseCTest, TypesByHash) {
  const std::string prog = Import(stripped_, "cjson");
  pb::ParseCResponse first = Parse(prog, "struct outer { union { int i; float f; }; int *next; unsigned tail : 3; };\n");
  ASSERT_EQ(first.errors(), 0u);
  ASSERT_EQ(first.named_size(), 1);
  const std::string outer = first.named(0).hash();
  // Each node's C spelling, and the named type's definition, for previews.
  ASSERT_EQ(first.displays_size(), first.nodes_size());
  EXPECT_EQ(first.displays(first.named(0).index()), "struct outer");
  EXPECT_NE(first.named(0).c_definition().find("int *next;"), std::string::npos) << first.named(0).c_definition();
  ImportHeader(prog, first, "outer");
  pb::GetTypesRequest get;
  get.set_program_id(prog);
  get.add_hashes(outer);
  pb::GetTypesResponse got;
  ASSERT_TRUE(backend_->GetTypes(ctx_, get, got).ok());
  ASSERT_EQ(got.types_size(), 1);
  const auto &fields = got.types(0).composite().fields();
  ASSERT_EQ(fields.size(), 3);
  EXPECT_EQ(fields[0].name(), "");
  const std::string text = "struct outer {\n  __revkit_type_" + fields[0].type_hash() + ";\n  __revkit_type_" +
                           fields[1].type_hash() + " next;\n  __revkit_type_" + fields[2].type_hash() +
                           " tail : 3;\n};\n";
  pb::ParseCResponse again = Parse(prog, text);
  EXPECT_EQ(again.errors(), 0u) << (again.diagnostics_size() ? again.diagnostics(0).text() : "");
  ASSERT_EQ(again.named_size(), 1);
  EXPECT_EQ(again.named(0).hash(), outer);
  EXPECT_EQ(again.named(0).existing_hash(), outer);
  // The anonymous member refers to the program's union by its hash.
  const pb::TypeNode &node = again.nodes(again.named(0).index());
  ASSERT_EQ(node.fields_size(), 3);
  EXPECT_EQ(node.fields(0).name(), "");
  EXPECT_EQ(node.fields(0).type().hash(), fields[0].type_hash());
  // A hash the program doesn't have is an unknown type name.
  pb::ParseCResponse unknown = Parse(prog, "struct x { __revkit_type_00112233 a; };\n");
  EXPECT_GT(unknown.errors(), 0u);
}

// Programs of the address-space languages (word-addressed AVR, 8051's
// banks; 16- and 24-bit pointers) get their compilers' data model: a
// header parses to the sizes avr-gcc and SDCC give, and the response says
// which defaults it used.
TEST(ParseCTargets, MicrocontrollerPrograms) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  auto backend = MakeImageBackend(o);
  CallContext ctx;
  struct Case {
    const char *language, *compiler;
    std::uint64_t pointer;
  };
  for (const Case &c : {Case{"avr8:LE:16:atmega256", "gcc", 2}, Case{"8051:BE:16:default", "default", 2}}) {
    pb::ImportProgramRequest imp;
    imp.set_project_id("default");
    imp.set_content(std::string(256, '\0'));
    imp.set_name(std::string("fw-") + c.language[0]);
    imp.mutable_options()->set_format("raw");
    imp.mutable_options()->set_language_id(c.language);
    imp.mutable_options()->set_compiler_spec_id(c.compiler);
    pb::ImportProgramResponse ir;
    auto st = backend->ImportProgram(ctx, imp, ir);
    ASSERT_TRUE(st.ok()) << c.language << ": " << st.message;
    pb::ParseCRequest req;
    req.set_program_id(ir.program().program_id());
    auto *src = req.add_sources();
    src->set_name("dev.h");
    src->set_text("#include <stdint.h>\nstruct dev { uint8_t flags; uint16_t count; void *buf; void (*cb)(int); long total; int n; };\n");
    pb::ParseCResponse resp;
    ASSERT_TRUE(backend->ParseC(ctx, req, resp).ok()) << c.language;
    EXPECT_EQ(resp.errors(), 0u) << c.language;
    bool noted = false;
    for (const auto &n : resp.profile_notes()) noted |= n.find("microcontrollers") != std::string::npos;
    EXPECT_TRUE(noted) << c.language;
    const pb::TypeNode *dev = nullptr;
    for (const auto &n : resp.named())
      if (n.key() == "struct dev") dev = &resp.nodes(n.index());
    ASSERT_NE(dev, nullptr) << c.language;
    // flags, count (no alignment), a 2-byte data and code pointer, long 4, int 2.
    EXPECT_EQ(dev->size(), 13u) << c.language;
    ASSERT_EQ(dev->fields_size(), 6);
    EXPECT_EQ(dev->fields(1).offset(), 1u) << c.language;
    EXPECT_EQ(dev->fields(3).offset(), 3u + c.pointer) << c.language;
    EXPECT_EQ(dev->fields(5).offset(), 11u) << c.language;
  }
}

// A declaration the parser can't read stays text, as before it existed.
TEST_F(ParseCTest, UnparsableRetypesStayText) {
  const std::string prog = Import(stripped_, "cjson");
  const std::string debug = Import(debug_, "cjson-debug");
  const std::uint64_t entry = Entry(debug, "cJSON_GetStringValue");
  ASSERT_TRUE(Retype(prog, entry, "this is not C (", "t").ok());
  pb::DecompileRequest req;
  req.set_program_id(prog);
  req.mutable_function()->set_offset(entry);
  pb::DecompileResponse resp;
  ASSERT_TRUE(backend_->Decompile(ctx_, req, resp).ok());
  EXPECT_EQ(resp.function().prototype().c_declaration(), "this is not C (");
}

// A bound name reaches debug-info globals and locals in the decompiler
// (types.resolved), not only prototypes.
TEST_F(ParseCTest, BindingsReachDebugInfoVariables) {
  const std::string debug = Import(debug_, "cjson-debug");
  const std::uint64_t init = Entry(debug, "cJSON_InitHooks");
  const std::uint64_t parse = Entry(debug, "cJSON_ParseWithLengthOpts");
  EXPECT_NE(Decompile(debug, init).find("global_hooks.allocate"), std::string::npos);
  EXPECT_NE(Decompile(debug, parse).find("buffer.length"), std::string::npos);
  const std::string edit = R"(#include <stddef.h>
typedef struct internal_hooks {
  void *(*alloc_fn)(size_t); void (*free_fn2)(void *); void *(*realloc_fn)(void *, size_t);
} internal_hooks;
typedef struct { const unsigned char *data; size_t len; size_t pos; size_t nesting; internal_hooks hooks; } parse_buffer;
)";
  pb::ParseCResponse parsed = Parse(debug, edit);
  EXPECT_EQ(parsed.errors(), 0u);
  EXPECT_EQ(parsed.conflicts_size(), 3);
  ImportHeader(debug, parsed, "rebind");
  const std::string hooks = Decompile(debug, init);
  EXPECT_NE(hooks.find("global_hooks.alloc_fn"), std::string::npos) << hooks;  // a global
  const std::string buffer = Decompile(debug, parse);
  EXPECT_NE(buffer.find("buffer.len"), std::string::npos) << buffer;  // a local
  EXPECT_EQ(buffer.find("buffer.length"), std::string::npos);
}

}  // namespace
}  // namespace revkit::backend
