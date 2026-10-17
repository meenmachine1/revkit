// Type archives and categories (TypeService.ExportTypeArchive, ParseC with
// a sidecar, SetTypeCategory; docs/types.md#type-archives) on the corpus's
// cJSON and Lua: the debug build's types exported, imported into the
// stripped twin, and exported again byte for byte.
#include "builders.hh"

#include "revkit/backend/image_backend.h"
#include "revkit/cparse/cparse.h"
#include "type_archive.h"

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
namespace fs = std::filesystem;
using api::CallContext;
using api::StatusCode;

class TypeArchiveTest : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
    dir_ = testing::scratch_dir("type-archive");
  }

  bool Have(const std::string &rel) const { return fs::exists(fs::path(REVKIT_CORPUS) / rel); }

  std::string Import(const std::string &rel, const std::string &name) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path((fs::path(REVKIT_CORPUS) / rel).string());
    req.set_name(name);
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  pb::ExportTypeArchiveResponse Export(const std::string &program, pb::TypeArchiveScope scope,
                                       const std::string &name = "", const std::string &category = "",
                                       api::Status *status = nullptr) {
    pb::ExportTypeArchiveRequest req;
    req.set_program_id(program);
    req.set_scope(scope);
    req.set_name(name);
    req.set_category(category);
    pb::ExportTypeArchiveResponse resp;
    api::Status st = backend_->ExportTypeArchive(ctx_, req, resp);
    if (status) *status = st;
    else EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  pb::ParseCResponse ParseArchive(const std::string &program, const std::string &header, const std::string &sidecar,
                                  const std::string &name) {
    pb::ParseCRequest req;
    req.set_program_id(program);
    auto *s = req.add_sources();
    s->set_text(header);
    s->set_name(name);
    req.set_archive_sidecar(sidecar);
    pb::ParseCResponse resp;
    auto st = backend_->ParseC(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  // What the SDKs' import_type_archive sends (headerImportPlan with the
  // archive's options): the nodes the chosen names need, a binding for
  // each name the program doesn't already define as the archive does (a
  // library archive's definition counts as none), and the archive's
  // categories, as one request with import:archive provenance whose
  // version is the archive's origin. Returns the number of assertions (0:
  // nothing to do, nothing sent).
  int ImportArchive(const std::string &program, const pb::ParseCResponse &parsed, const std::string &session) {
    std::vector<const pb::ParseCNamedType *> chosen;
    for (const auto &n : parsed.named())
      if (!n.system() && (n.existing_hash() != n.hash() || n.existing_library())) chosen.push_back(&n);
    std::set<std::uint32_t> need;
    std::vector<std::uint32_t> stack;
    for (const auto *n : chosen) stack.push_back(n->index());
    while (!stack.empty()) {
      const std::uint32_t i = stack.back();
      stack.pop_back();
      if (!need.insert(i).second) continue;
      const pb::TypeNode &node = parsed.nodes(static_cast<int>(i));
      auto ref = [&](const pb::TypeNodeRef &r) {
        if (r.kind_case() == pb::TypeNodeRef::kAssertionIndex) stack.push_back(r.assertion_index());
      };
      if (node.has_target()) ref(node.target());
      for (const auto &f : node.fields()) ref(f.type());
      for (const auto &p : node.params()) ref(p.type());
    }
    std::map<std::uint32_t, std::uint32_t> renumber;
    for (std::uint32_t old : need) renumber.emplace(old, static_cast<std::uint32_t>(renumber.size()));
    pb::AppendAssertionsRequest req;
    req.set_program_id(program);
    auto *prov = req.mutable_provenance();
    prov->set_kind(pb::PROVENANCE_KIND_IMPORT);
    prov->set_id("archive");
    prov->set_version(parsed.archive().origin());
    prov->set_session(session);
    for (std::uint32_t old : need) {
      pb::TypeNode node = parsed.nodes(static_cast<int>(old));
      auto fix = [&](pb::TypeNodeRef *r) {
        if (r->kind_case() == pb::TypeNodeRef::kAssertionIndex) r->set_assertion_index(renumber.at(r->assertion_index()));
      };
      if (node.has_target()) fix(node.mutable_target());
      for (auto &f : *node.mutable_fields()) fix(f.mutable_type());
      for (auto &p : *node.mutable_params()) fix(p.mutable_type());
      *req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type() = node;
    }
    for (const auto *n : chosen)
      req.add_assertions()->mutable_body()->mutable_bind_type_name()->mutable_type()->set_assertion_index(
          renumber.at(n->index()));
    for (const auto &n : parsed.named())
      if (!n.category().empty() && n.category() != n.existing_category()) {
        auto *c = req.add_assertions()->mutable_body()->mutable_type_category();
        c->set_named_key(n.key());
        c->set_path(n.category());
      }
    if (req.assertions().empty()) return 0;
    pb::AppendAssertionsResponse resp;
    auto st = backend_->AppendAssertions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return req.assertions_size();
  }

  // Every named type of a program, key -> hashes (bound and own).
  std::map<std::string, std::vector<std::string>> Names(const std::string &program,
                                                        std::map<std::string, std::string> *categories = nullptr) {
    pb::FindTypesRequest req;
    req.set_program_id(program);
    req.mutable_page()->set_page_size(5000);
    req.add_sources(pb::TYPE_SOURCE_PROGRAM);
    pb::FindTypesResponse resp;
    EXPECT_TRUE(backend_->FindTypes(ctx_, req, resp).ok());
    std::map<std::string, std::vector<std::string>> out;
    for (const auto &t : resp.types()) {
      std::string kind = t.kind() == pb::TYPE_KIND_STRUCT ? "struct " : t.kind() == pb::TYPE_KIND_UNION ? "union "
                         : t.kind() == pb::TYPE_KIND_ENUM ? "enum " : "typedef ";
      out[kind + t.name()].push_back(t.hash());
      if (categories && !t.category().empty()) (*categories)[kind + t.name()] = t.category();
    }
    return out;
  }

  // A real compiler for the data model accepts the header, its
  // _Static_asserts included.
  void ExpectCompiles(const std::string &header, const std::string &target) {
    const fs::path file = dir_ / ("check-" + target + ".h");
    std::ofstream(file) << header;
    std::string cc = REVKIT_TEST_CLANG;
    std::string cmd;
    if (!cc.empty()) cmd = cc + " --target=" + target + " -fsyntax-only -x c '" + file.string() + "'";
    else if (target == "x86_64-linux-gnu") cmd = std::string(REVKIT_TEST_CC) + " -fsyntax-only -x c '" + file.string() + "'";
    else GTEST_SKIP() << "no compiler for " << target;
    EXPECT_EQ(std::system(cmd.c_str()), 0) << cmd;
  }

  // The gate for one program: debug export, stripped import, export again.
  void RoundTrip(const std::string &debug_rel, const std::string &stripped_rel, const std::string &name,
                 const std::string &target) {
    if (!Have(debug_rel) || !Have(stripped_rel)) GTEST_SKIP() << "corpus not built";
    const std::string debug = Import(debug_rel, name + "-debug");
    const std::string stripped = Import(stripped_rel, name);
    const pb::ExportTypeArchiveResponse a = Export(debug, pb::TYPE_ARCHIVE_SCOPE_ALL);
    ASSERT_FALSE(a.header().empty());
    EXPECT_EQ(a.mismatches(), 0u);
    for (const auto &n : a.notes()) ADD_FAILURE() << n;
    // The name defaults to the origin: the program first exported from.
    EXPECT_EQ(a.header_name(), name + "-debug.h");
    EXPECT_EQ(a.sidecar_name(), name + "-debug.json");
    EXPECT_EQ(a.archive().provenance().origin(), name + "-debug");
    EXPECT_EQ(a.archive().data_model().profile(), target);
    EXPECT_GT(a.archive().types_size(), 10);
    ExpectCompiles(a.header(), target);

    const pb::ParseCResponse parsed = ParseArchive(stripped, a.header(), a.sidecar(), a.header_name());
    EXPECT_EQ(parsed.errors(), 0u);
    EXPECT_EQ(parsed.archive().types(), static_cast<std::uint32_t>(a.archive().types_size()));
    EXPECT_EQ(parsed.archive().verified(), parsed.archive().types());
    EXPECT_FALSE(parsed.archive().header_changed());
    EXPECT_EQ(parsed.archive().origin(), name + "-debug");
    ASSERT_GT(ImportArchive(stripped, parsed, "archive-1"), 0);

    // The stripped twin now has the debug build's types: same keys, same
    // hashes (so the same layouts, members and member types).
    std::map<std::string, std::string> debug_categories, stripped_categories;
    auto debug_names = Names(debug, &debug_categories);
    auto stripped_names = Names(stripped, &stripped_categories);
    for (const auto &t : a.archive().types()) {
      ASSERT_TRUE(stripped_names.contains(t.key())) << t.key();
      const auto &hashes = stripped_names.at(t.key());
      EXPECT_NE(std::find(hashes.begin(), hashes.end(), t.hash()), hashes.end()) << t.key();
      const auto &theirs = debug_names.at(t.key());
      EXPECT_NE(std::find(theirs.begin(), theirs.end(), t.hash()), theirs.end()) << t.key();
      EXPECT_EQ(stripped_categories[t.key()], t.category()) << t.key();
    }

    // Byte-identical: the stripped program's export of what it imported.
    const pb::ExportTypeArchiveResponse b = Export(stripped, pb::TYPE_ARCHIVE_SCOPE_ALL);
    EXPECT_EQ(b.header_name(), a.header_name());  // the name defaults to the origin, which the import kept
    EXPECT_EQ(b.header(), a.header());
    EXPECT_EQ(b.sidecar(), a.sidecar());
    // Named alike, the two programs' exports are the same too.
    EXPECT_EQ(Export(stripped, pb::TYPE_ARCHIVE_SCOPE_ALL, name).sidecar(),
              Export(debug, pb::TYPE_ARCHIVE_SCOPE_ALL, name).sidecar());

    // Idempotent: importing it again finds every type identical and every
    // category set, so there is nothing to send, and no name doubles.
    const pb::ParseCResponse again = ParseArchive(stripped, a.header(), a.sidecar(), a.header_name());
    for (const auto &n : again.named()) {
      EXPECT_EQ(n.existing_hash(), n.hash()) << n.key();
      EXPECT_FALSE(n.existing_library()) << n.key();
    }
    EXPECT_EQ(ImportArchive(stripped, again, "archive-2"), 0);
    for (const auto &[key, hashes] : Names(stripped)) EXPECT_EQ(hashes.size(), stripped_names.at(key).size()) << key;
  }

  fs::path dir_;
  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
};

TEST_F(TypeArchiveTest, CjsonRoundTrip) {
  RoundTrip("elf-x86_64/gcc-O2/debug/cjson", "elf-x86_64/gcc-O2/stripped/cjson", "cjson", "x86_64-linux-gnu");
}

TEST_F(TypeArchiveTest, LuaRoundTrip) {
  RoundTrip("elf-x86_64/gcc-O2/debug/lua", "elf-x86_64/gcc-O2/stripped/lua", "lua", "x86_64-linux-gnu");
}

TEST_F(TypeArchiveTest, AArch64RoundTrip) {
  RoundTrip("elf-aarch64/clang-O2/debug/zlib", "elf-aarch64/clang-O2/stripped/zlib", "zlib", "aarch64-linux-gnu");
}

// The sidecar's hashes catch a header edited after the export.
TEST_F(TypeArchiveTest, ImportChecksTheHashes) {
  if (!Have("elf-x86_64/gcc-O2/debug/cjson") || !Have("elf-x86_64/gcc-O2/stripped/cjson")) GTEST_SKIP();
  const std::string debug = Import("elf-x86_64/gcc-O2/debug/cjson", "cjson-debug");
  const std::string stripped = Import("elf-x86_64/gcc-O2/stripped/cjson", "cjson");
  const pb::ExportTypeArchiveResponse a = Export(debug, pb::TYPE_ARCHIVE_SCOPE_ALL, "cjson");
  std::string header = a.header();
  const auto at = header.find("int valueint;");
  ASSERT_NE(at, std::string::npos) << header;
  header.replace(at, 3, "long");
  const pb::ParseCResponse parsed = ParseArchive(stripped, header, a.sidecar(), "cjson.h");
  EXPECT_TRUE(parsed.archive().header_changed());
  EXPECT_LT(parsed.archive().verified(), parsed.archive().types());
  std::set<std::string> bad;
  for (const auto &m : parsed.archive().mismatches()) bad.insert(m.key());
  EXPECT_TRUE(bad.contains("struct cJSON")) << parsed.archive().DebugString();

  pb::ParseCRequest req;
  req.set_program_id(stripped);
  req.add_sources()->set_text(a.header());
  req.set_archive_sidecar("{\"format\": \"something else\"}");
  pb::ParseCResponse resp;
  EXPECT_EQ(backend_->ParseC(ctx_, req, resp).code, StatusCode::kInvalidArgument);
}

// Categories: set, filtered, listed as folders, exported by category; the
// debug info files its types under their headers; a header import under
// the header's name.
TEST_F(TypeArchiveTest, Categories) {
  if (!Have("elf-x86_64/gcc-O2/debug/cjson")) GTEST_SKIP();
  const std::string debug = Import("elf-x86_64/gcc-O2/debug/cjson", "cjson-debug");
  std::map<std::string, std::string> cats;
  Names(debug, &cats);
  EXPECT_EQ(cats["struct cJSON"], "/cJSON.h");
  EXPECT_EQ(cats["typedef cJSON"], "/cJSON.h");
  EXPECT_EQ(cats["typedef size_t"], "/stddef.h");

  auto set = [&](const std::string &key, const std::string &path) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(debug);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    auto *c = req.add_assertions()->mutable_body()->mutable_type_category();
    c->set_named_key(key);
    c->set_path(path);
    pb::AppendAssertionsResponse resp;
    return backend_->AppendAssertions(ctx_, req, resp);
  };
  ASSERT_TRUE(set("struct cJSON", "/json/core/").ok());
  ASSERT_TRUE(set("struct cJSON_Hooks", "/json").ok());
  EXPECT_EQ(set("struct cJSON", "json").code, StatusCode::kInvalidArgument);
  EXPECT_EQ(set("struct cJSON", "/a/../b").code, StatusCode::kInvalidArgument);
  EXPECT_EQ(set("cJSON", "/a").code, StatusCode::kInvalidArgument);

  pb::FindTypesRequest find;
  find.set_program_id(debug);
  find.set_category("/json");
  find.set_include_categories(true);
  pb::FindTypesResponse found;
  ASSERT_TRUE(backend_->FindTypes(ctx_, find, found).ok());
  std::set<std::string> names;
  for (const auto &t : found.types()) names.insert(t.name() + "@" + t.category());
  EXPECT_EQ(names, (std::set<std::string>{"cJSON@/json/core", "cJSON_Hooks@/json"}));
  std::map<std::string, std::uint32_t> folders;
  for (const auto &f : found.categories()) folders[f.path()] = f.types();
  EXPECT_EQ(folders["/json"], 1u);
  EXPECT_EQ(folders["/json/core"], 1u);
  EXPECT_GT(folders["/cJSON.h"], 0u);
  find.set_category_exact(true);
  pb::FindTypesResponse exact;
  ASSERT_TRUE(backend_->FindTypes(ctx_, find, exact).ok());
  ASSERT_EQ(exact.types_size(), 1);
  EXPECT_EQ(exact.types(0).name(), "cJSON_Hooks");
  // Search still finds every category.
  pb::FindTypesRequest search;
  search.set_program_id(debug);
  search.set_name_contains("cjson");
  pb::FindTypesResponse searched;
  ASSERT_TRUE(backend_->FindTypes(ctx_, search, searched).ok());
  std::set<std::string> where;
  for (const auto &t : searched.types()) where.insert(t.category());
  EXPECT_TRUE(where.contains("/json/core"));
  EXPECT_TRUE(where.contains("/cJSON.h"));

  // Export by category: the category's types and what they reach.
  const pb::ExportTypeArchiveResponse a = Export(debug, pb::TYPE_ARCHIVE_SCOPE_CATEGORY, "", "/json");
  std::set<std::string> keys;
  for (const auto &t : a.archive().types()) keys.insert(t.key());
  EXPECT_TRUE(keys.contains("struct cJSON"));
  EXPECT_TRUE(keys.contains("struct cJSON_Hooks"));
  EXPECT_FALSE(keys.contains("struct printbuffer"));
  api::Status st;
  Export(debug, pb::TYPE_ARCHIVE_SCOPE_CATEGORY, "", "/nothing", &st);
  EXPECT_EQ(st.code, StatusCode::kFailedPrecondition);
  // Nothing bound yet: the default scope (types made in revkit) is empty.
  Export(debug, pb::TYPE_ARCHIVE_SCOPE_UNSPECIFIED, "", "", &st);
  EXPECT_EQ(st.code, StatusCode::kFailedPrecondition);

  // A header's types are filed under its name.
  pb::ParseCRequest req;
  req.set_program_id(debug);
  auto *s = req.add_sources();
  s->set_text("struct widget { int w; };\n");
  s->set_name("include/widget.h");
  pb::ParseCResponse parsed;
  ASSERT_TRUE(backend_->ParseC(ctx_, req, parsed).ok());
  ASSERT_EQ(parsed.named_size(), 1);
  EXPECT_EQ(parsed.named(0).category(), "/widget.h");
  EXPECT_EQ(parsed.named(0).existing_category(), "");
}

// A PDB files its types under the header its LF_UDT_SRC_LINE names.
TEST_F(TypeArchiveTest, PdbCategories) {
  if (!Have("pe-x86_64/clang-O2/debug/cjson.exe")) GTEST_SKIP();
  const std::string pe = Import("pe-x86_64/clang-O2/debug/cjson.exe", "cjson-pe");
  std::map<std::string, std::string> cats;
  Names(pe, &cats);
  EXPECT_EQ(cats["struct cJSON"], "/cJSON.h");
  EXPECT_EQ(cats["struct cJSON_Hooks"], "/cJSON.h");
  const pb::ExportTypeArchiveResponse a = Export(pe, pb::TYPE_ARCHIVE_SCOPE_CATEGORY, "", "/cJSON.h");
  EXPECT_EQ(a.mismatches(), 0u);
  EXPECT_EQ(a.archive().data_model().profile(), "x86_64-pc-windows-msvc");
  ExpectCompiles(a.header(), "x86_64-pc-windows-msvc");
}

// One type selected: it and what it reaches; an unknown key is NOT_FOUND.
TEST_F(TypeArchiveTest, SelectedTypes) {
  if (!Have("elf-x86_64/gcc-O2/debug/lua")) GTEST_SKIP();
  const std::string debug = Import("elf-x86_64/gcc-O2/debug/lua", "lua-debug");
  pb::ExportTypeArchiveRequest req;
  req.set_program_id(debug);
  req.add_keys("struct lua_State");
  pb::ExportTypeArchiveResponse resp;
  ASSERT_TRUE(backend_->ExportTypeArchive(ctx_, req, resp).ok());
  EXPECT_EQ(resp.mismatches(), 0u);
  std::set<std::string> keys;
  for (const auto &t : resp.archive().types()) keys.insert(t.key());
  EXPECT_TRUE(keys.contains("struct lua_State"));
  EXPECT_TRUE(keys.contains("struct CallInfo"));
  EXPECT_FALSE(keys.contains("struct LoadF"));
  EXPECT_EQ(resp.header_name(), "lua-debug.h");
  req.add_keys("struct no_such_thing");
  EXPECT_EQ(backend_->ExportTypeArchive(ctx_, req, resp).code, StatusCode::kNotFound);
}

// A sidecar's data model is anyone's file: sizes and alignments outside
// 1-64 keep the profile's, as the spec path's do.
TEST(TypeArchiveSidecar, HostileDataModelKeepsSaneLayouts) {
  pb::TypeArchiveDataModel m;
  m.set_profile("x86_64-linux-gnu");
  m.set_pointer_size(0xffffffffu);
  m.set_int_size(4096);
  m.set_long_size(8);
  m.set_max_alignment(1u << 30);
  m.add_size_alignment("4294967300:8");
  m.add_size_alignment("8:0");
  m.add_size_alignment("16:16");
  m.add_size_alignment("garbage");
  const cparse::Profile p = ProfileOf(m);
  const cparse::Profile base = *cparse::profile_named("x86_64-linux-gnu");
  EXPECT_EQ(p.rules.pointer_size, base.rules.pointer_size);
  EXPECT_EQ(p.rules.int_size, base.rules.int_size);
  EXPECT_EQ(p.rules.long_size, 8u);
  EXPECT_EQ(p.rules.max_alignment, base.rules.max_alignment);
  ASSERT_EQ(p.rules.size_alignment.size(), 1u);
  EXPECT_EQ(p.rules.size_alignment[0], (std::pair<std::uint32_t, std::uint32_t>{16, 16}));
}

}  // namespace
}  // namespace revkit::backend
