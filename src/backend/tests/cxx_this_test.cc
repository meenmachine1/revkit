// C++ classes from an imported header as the type of `this` (docs/types.md,
// "C++ classes as `this`"): the 32-bit ARM fixture's ELF (tests/data/arm32,
// mangled symbols, no debug info used) with its shapes.h parsed as C++ and
// imported; member functions then print `this->w`, not `this + 0x14`.
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

class CxxThisTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_TEST_CLANG).empty() || std::string(REVKIT_TEST_LLD).empty() ||
        std::string(REVKIT_NDS_PYTHON).empty())
      return;
    dir_ = testing::scratch_dir("cxx-this");
    const std::string cmd = std::string(REVKIT_NDS_PYTHON) + " " + REVKIT_ARM32_FIXTURE + "/make_fixture.py --clang " +
                            REVKIT_TEST_CLANG + " --lld " + REVKIT_TEST_LLD + " --opt O2 --out " + dir_.string() +
                            " > " + (dir_ / "make.log").string() + " 2>&1";
    if (std::system(cmd.c_str()) != 0) return;
    // Without its DWARF: the classes come from the header alone.
    const fs::path elf = dir_ / "arm" / "arm32-O2.elf";
    if (std::system(("llvm-objcopy --strip-debug '" + elf.string() + "' '" + (dir_ / "shapes.elf").string() + "' 2>/dev/null")
                        .c_str()) != 0)
      return;
    std::ifstream in(fs::path(REVKIT_ARM32_FIXTURE) / "shapes.h");
    header_.assign(std::istreambuf_iterator<char>(in), {});
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (header_.empty() || !fs::exists(dir_ / "shapes.elf")) GTEST_SKIP() << "no clang, ld.lld or llvm-objcopy for the fixture";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.browse_roots = {dir_.string()};
    backend_ = MakeImageBackend(o);
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path((dir_ / "shapes.elf").string());
    req.set_name("shapes");
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    program_ = resp.program().program_id();
  }

  std::uint64_t Entry(const std::string &name) {
    pb::ListFunctionsRequest req;
    req.set_program_id(program_);
    req.set_name_contains(name);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(backend_->ListFunctions(ctx_, req, resp).ok());
    std::string seen;
    for (const auto &f : resp.functions()) {
      if (f.name() == name) return f.entry().offset();
      seen += " " + f.name();
    }
    ADD_FAILURE() << "no function " << name << ":" << seen;
    return 0;
  }

  std::string Decompile(std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(program_);
    req.mutable_function()->set_offset(entry);
    req.mutable_options()->set_include_text(true);
    pb::DecompileResponse resp;
    auto st = backend_->Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.function().text();
  }

  // The header as an SDK's import_header imports it: every node, then a
  // binding for every named type, in one request.
  void ImportHeader() {
    pb::ParseCRequest parse;
    parse.set_program_id(program_);
    auto *s = parse.add_sources();
    s->set_text(header_);
    s->set_name("shapes.h");
    parse.mutable_options()->set_cplusplus(true);
    pb::ParseCResponse parsed;
    auto st = backend_->ParseC(ctx_, parse, parsed);
    ASSERT_TRUE(st.ok()) << st.message;
    pb::AppendAssertionsRequest req;
    req.set_program_id(program_);
    auto *prov = req.mutable_provenance();
    prov->set_kind(pb::PROVENANCE_KIND_IMPORT);
    prov->set_id("header");
    prov->set_version("shapes.h");
    for (const auto &n : parsed.nodes()) *req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type() = n;
    for (const auto &n : parsed.named())
      req.add_assertions()->mutable_body()->mutable_bind_type_name()->mutable_type()->set_assertion_index(n.index());
    pb::AppendAssertionsResponse resp;
    st = backend_->AppendAssertions(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
  }

  static inline fs::path dir_;
  static inline std::string header_;
  std::unique_ptr<api::Backend> backend_;
  CallContext ctx_;
  std::string program_;
};

TEST_F(CxxThisTest, ImportedClassesTypeThis) {
  const std::uint64_t move = Entry("Shape::move");
  ASSERT_NE(move, 0u);
  // The demangler's `this` alone: an empty class.
  const std::string before = Decompile(move);
  EXPECT_EQ(before.find("this->x"), std::string::npos) << before;
  ImportHeader();
  const std::string after = Decompile(move);
  EXPECT_NE(after.find("this->x"), std::string::npos) << after;
  EXPECT_NE(after.find("this->flags"), std::string::npos) << after;
  // Another class, and a pointer parameter of a class type: the same
  // binding (the demangler's Shape * in Scene::add is the header's).
  const std::string add = Decompile(Entry("Scene::add"));
  EXPECT_NE(add.find("this->count"), std::string::npos) << add;
  EXPECT_NE(add.find("this->items"), std::string::npos) << add;
}

}  // namespace
}  // namespace revkit::backend
