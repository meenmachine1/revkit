// Raw imports (ImportOptions format "raw") through the backend: the
// synthetic ARM firmware (src/analysis/tests/fixtures/armfw) behind a
// header, with an MMIO region, persisted and reopened identically.
#include "builders.hh"

#include "revkit/backend/image_backend.h"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <map>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;
namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

class RawImport : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty() || std::string(REVKIT_TEST_CLANG).empty() ||
        std::string(REVKIT_TEST_LLD).empty() || std::string(REVKIT_TEST_OBJCOPY).empty())
      return;
    dir_ = testing::scratch_dir("raw-import");
    const std::string cmd = std::string("sh ") + REVKIT_ARMFW_DIR + "/build.sh " + REVKIT_TEST_CLANG + " " +
                            REVKIT_TEST_LLD + " " + REVKIT_TEST_OBJCOPY + " " + dir_.string() + " >/dev/null 2>&1";
    if (std::system(cmd.c_str()) != 0) return;
    // The image behind a 0x40-byte header, as firmware files often have.
    auto image = testing::read_file(dir_ / "fw.bin");
    std::ofstream out(dir_ / "fw-with-header.bin", std::ios::binary);
    std::string header(0x40, 'H');
    out.write(header.data(), static_cast<std::streamsize>(header.size()));
    out.write(reinterpret_cast<const char *>(image.data()), static_cast<std::streamsize>(image.size()));
    built_ = out.good();
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!built_) GTEST_SKIP() << "no clang, ld.lld and llvm-objcopy for armv4t";
  }

  static std::unique_ptr<api::Backend> Make(const std::string &project_dir = {}) {
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.project_dir = project_dir;
    return MakeImageBackend(o);
  }

  static pb::ImportProgramRequest Request() {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path((dir_ / "fw-with-header.bin").string());
    pb::ImportOptions *o = req.mutable_options();
    o->set_format("raw");
    o->set_language_id("ARM:LE:32:v4t");
    o->set_compiler_spec_id("default");
    o->set_raw_offset(0x40);
    pb::MemoryRegion *r = o->add_regions();
    r->set_name("sysctrl");
    r->set_start(0xd0000000);
    r->set_size(0x1000);
    r->set_read(true);
    r->set_write(true);
    r->set_is_volatile(true);
    return req;
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

  std::string Memory(api::Backend &b, const std::string &program) {
    pb::GetMemoryMapRequest req;
    req.set_program_id(program);
    pb::GetMemoryMapResponse resp;
    EXPECT_TRUE(b.GetMemoryMap(ctx_, req, resp).ok());
    std::string out;
    for (const auto &m : resp.blocks())
      out += m.name() + ":" + std::to_string(m.range().first().offset()) + "-" + std::to_string(m.range().last().offset()) +
             (m.read() ? "r" : "-") + (m.write() ? "w" : "-") + (m.execute() ? "x" : "-") + (m.initialized() ? "i" : "u") +
             " ";
    return out;
  }

  static inline fs::path dir_;
  static inline bool built_ = false;
  CallContext ctx_;
};

// Removing a Thumb function sticks. The user removes it at the address the
// listing shows; discovery keys Thumb entries with the Thumb bit, and used
// to miss the removal and find the function again.
TEST_F(RawImport, RemovingAThumbFunctionSticks) {
  std::uint64_t thumb = 0;
  {
    loader::Image elf = loader::load_file(dir_ / "fw.elf", {.image_base = std::nullopt, .ghidra_image_base = true});
    for (const loader::Symbol &sym : elf.symbols)
      if (sym.name == "thumb_scale") thumb = sym.value & ~std::uint64_t{1};
  }
  ASSERT_NE(thumb, 0u);
  auto b = Make();
  pb::ImportProgramResponse resp;
  ASSERT_TRUE(b->ImportProgram(ctx_, Request(), resp).ok());
  const std::string id = resp.program().program_id();
  auto has = [&] {
    for (const auto &[name, entry] : Functions(*b, id))
      if (entry == thumb) return true;
    return false;
  };
  ASSERT_TRUE(has()) << "discovery finds the Thumb function";

  pb::AppendAssertionsRequest req;
  req.set_program_id(id);
  req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  req.mutable_provenance()->set_id("tester");
  pb::SetFunctionBounds *fb = req.add_assertions()->mutable_body()->mutable_function_bounds();
  fb->mutable_entry()->set_offset(thumb);
  fb->set_remove(true);
  pb::AppendAssertionsResponse ar;
  ASSERT_TRUE(b->AppendAssertions(ctx_, req, ar).ok());
  EXPECT_FALSE(has()) << "the removal applies to the Thumb entry";
}

// A Thumb function in a raw image (no $t symbols to say so) decompiles as
// Thumb through the daemon, as rk-lift does: its decoding context is painted
// over its body, which the daemon's per-address facts used to drop.
TEST_F(RawImport, ThumbFunctionsDecompileAsThumb) {
  std::uint64_t thumb = 0;
  {
    loader::Image elf = loader::load_file(dir_ / "fw.elf", {.image_base = std::nullopt, .ghidra_image_base = true});
    for (const loader::Symbol &sym : elf.symbols)
      if (sym.name == "thumb_scale") thumb = sym.value & ~std::uint64_t{1};
  }
  ASSERT_NE(thumb, 0u);
  auto b = Make();
  pb::ImportProgramResponse resp;
  ASSERT_TRUE(b->ImportProgram(ctx_, Request(), resp).ok());
  pb::DecompileRequest req;
  req.set_program_id(resp.program().program_id());
  req.mutable_function()->set_offset(thumb);
  req.mutable_options()->set_include_text(true);
  pb::DecompileResponse d;
  ASSERT_TRUE(b->Decompile(ctx_, req, d).ok());
  EXPECT_EQ(d.function().text().find("halt_baddata"), std::string::npos) << d.function().text();
  EXPECT_EQ(d.function().text().find("bad instruction"), std::string::npos) << d.function().text();
}

TEST_F(RawImport, ImportsReopensAndDecompiles) {
  fs::path dir = dir_ / "project";
  fs::remove_all(dir);
  std::string id, memory, text;
  std::map<std::string, std::uint64_t> fns;
  {
    auto b = Make(dir.string());
    pb::GetServerInfoResponse info;
    ASSERT_TRUE(b->GetServerInfo(ctx_, {}, info).ok());
    EXPECT_GE(info.api_minor(), 9u);
    EXPECT_NE(std::find(info.features().begin(), info.features().end(), "raw-import"), info.features().end());

    pb::ImportProgramResponse resp;
    auto st = b->ImportProgram(ctx_, Request(), resp);
    ASSERT_TRUE(st.ok()) << st.message;
    id = resp.program().program_id();
    EXPECT_EQ(resp.program().format(), "raw");
    EXPECT_EQ(resp.program().language_id(), "ARM:LE:32:v4t");
    memory = Memory(*b, id);
    // The image (after the header) at 0, read/write/execute, and the region.
    EXPECT_NE(memory.find("ram:0-"), std::string::npos) << memory;
    EXPECT_NE(memory.find("rwxi"), std::string::npos) << memory;
    EXPECT_NE(memory.find("sysctrl:3489660928-3489665023rw-u"), std::string::npos) << memory;
    fns = Functions(*b, id);
    // The exception vectors, and what discovery reaches from them.
    EXPECT_EQ(fns.at("Reset"), 0u);
    EXPECT_GE(fns.size(), 20u);

    pb::DecompileRequest req;
    req.set_program_id(id);
    req.mutable_function()->set_offset(0);
    req.mutable_options()->set_include_text(true);
    pb::DecompileResponse d;
    ASSERT_TRUE(b->Decompile(ctx_, req, d).ok());
    text = d.function().text();
    EXPECT_FALSE(text.empty());
  }
  // Reopened: the same layout, functions and decompilation.
  auto b = Make(dir.string());
  EXPECT_EQ(Memory(*b, id), memory);
  EXPECT_EQ(Functions(*b, id), fns);
  pb::DecompileRequest req;
  req.set_program_id(id);
  req.mutable_function()->set_offset(0);
  req.mutable_options()->set_include_text(true);
  pb::DecompileResponse d;
  ASSERT_TRUE(b->Decompile(ctx_, req, d).ok());
  EXPECT_EQ(d.function().text(), text);
}

TEST_F(RawImport, RejectsBadOptions) {
  auto b = Make();
  pb::ImportProgramResponse resp;
  auto req = Request();
  req.mutable_options()->clear_language_id();
  EXPECT_EQ(b->ImportProgram(ctx_, req, resp).code, StatusCode::kInvalidArgument);
  req = Request();
  req.mutable_options()->set_raw_permissions("rwz");
  EXPECT_EQ(b->ImportProgram(ctx_, req, resp).code, StatusCode::kInvalidArgument);
  req = Request();
  req.mutable_options()->set_raw_offset(1 << 30);  // past the end of the file
  EXPECT_EQ(b->ImportProgram(ctx_, req, resp).code, StatusCode::kInvalidArgument);
  req = Request();
  req.mutable_options()->set_format("elf");  // raw options without raw
  EXPECT_EQ(b->ImportProgram(ctx_, req, resp).code, StatusCode::kInvalidArgument);
  // The failed imports left no program behind.
  pb::ListProgramsRequest lr;
  lr.set_project_id("default");
  pb::ListProgramsResponse programs;
  ASSERT_TRUE(b->ListPrograms(ctx_, lr, programs).ok());
  EXPECT_EQ(programs.programs_size(), 0);
}

// Every language in the install is offered for a raw import, not a short list.
TEST(Languages, ListsTheInstallsLanguages) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  auto backend = MakeImageBackend(o);
  pb::ListLanguagesResponse resp;
  ASSERT_TRUE(backend->ListLanguages(CallContext{}, {}, resp).ok());
  std::map<std::string, const pb::AvailableLanguage *> by_id;
  for (const auto &l : resp.languages()) by_id[l.language_id()] = &l;
  EXPECT_GT(by_id.size(), 100u);
  for (const char *id : {"ARM:LE:32:v4t", "68000:BE:32:default", "SuperH4:LE:32:default", "Xtensa:LE:32:default",
                         "8051:BE:16:default", "tricore:LE:32:default"})
    EXPECT_TRUE(by_id.count(id)) << id;
  const pb::AvailableLanguage &arm = *by_id.at("ARM:BE:32:v7");
  EXPECT_EQ(arm.processor(), "ARM");
  EXPECT_EQ(arm.endianness(), pb::ENDIANNESS_BIG);
  EXPECT_EQ(arm.address_size(), 32u);
  EXPECT_FALSE(arm.description().empty());
  EXPECT_FALSE(arm.compiler_spec_ids().empty());
  for (const auto &l : resp.languages()) EXPECT_FALSE(l.deprecated()) << l.language_id();
  pb::ListLanguagesRequest all;
  all.set_include_deprecated(true);
  pb::ListLanguagesResponse with_deprecated;
  ASSERT_TRUE(backend->ListLanguages(CallContext{}, all, with_deprecated).ok());
  EXPECT_GE(with_deprecated.languages_size(), resp.languages_size());
}

}  // namespace
}  // namespace revkit::backend
