// Export C's header for decompiled C (api_minor 112, feature "c-dialect";
// docs/api.md "Export C"): the 32-bit ARM fixture (tests/data/arm32) as a
// raw image with inference on, exported with its header at one revision,
// and every function compiled with the header as an old compiler would
// (clang -std=c89 -pedantic-errors --target=armv5te-none-eabi), the way a
// matching decompilation compiles revkit's C with Metrowerks CodeWarrior.
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <thread>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
namespace fs = std::filesystem;
using api::CallContext;

class ExportCTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_TEST_CLANG).empty() || std::string(REVKIT_TEST_LLD).empty() ||
        std::string(REVKIT_NDS_PYTHON).empty())
      return;
    dir_ = testing::scratch_dir("export-c-c89");
    const std::string cmd = std::string(REVKIT_NDS_PYTHON) + " " + REVKIT_ARM32_FIXTURE + "/make_fixture.py --clang " +
                            REVKIT_TEST_CLANG + " --lld " + REVKIT_TEST_LLD + " --opt O2 --out " + dir_.string() +
                            " > " + (dir_ / "make.log").string() + " 2>&1";
    built_ = std::system(cmd.c_str()) == 0 && fs::exists(dir_ / "arm" / "arm32-O2.bin");
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!built_) GTEST_SKIP() << "no clang, ld.lld or python3 for the fixture";
  }

  // The raw image as firmware_score.py loads it, with inference on (the
  // daemon's default for a raw ARM image).
  std::string Import(api::Backend &b) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path((dir_ / "arm" / "arm32-O2.bin").string());
    req.set_name("arm32");
    auto *o = req.mutable_options();
    o->set_format("raw");
    o->set_language_id("ARM:LE:32:v5t");
    o->set_has_image_base(true);
    o->set_image_base(0x02000000);
    o->set_has_entry_point(true);
    o->set_entry_point(0x02000000);
    for (auto [name, start, size] : {std::tuple{"ram", 0x2200000u, 0x10000u}, std::tuple{"stack", 0x23e0000u, 0x20000u}}) {
      auto *r = o->add_regions();
      r->set_name(name);
      r->set_start(start);
      r->set_size(size);
      r->set_read(true);
      r->set_write(true);
    }
    pb::ImportProgramResponse resp;
    auto st = b.ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    if (!st.ok()) return {};
    // Until the import's analysis and the background inference are done.
    pb::GetAnalysisStatusRequest sr;
    sr.set_program_id(resp.program().program_id());
    pb::GetAnalysisStatusResponse status;
    const auto until = std::chrono::steady_clock::now() + std::chrono::minutes(10);
    do {
      status.Clear();
      if (!b.GetAnalysisStatus(ctx_, sr, status).ok()) break;
      if (status.idle()) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } while (std::chrono::steady_clock::now() < until);
    EXPECT_TRUE(status.idle());
    return resp.program().program_id();
  }

  // compilable_c (docs/decompiler-inputs.md "Source shape"): what a
  // matching run sets for C it compiles.
  void Compilable(api::Backend &b, const std::string &program) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(program);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    req.add_assertions()->mutable_body()->mutable_decompiler_settings()->mutable_settings()->set_compilable_c(true);
    pb::AppendAssertionsResponse resp;
    auto st = b.AppendAssertions(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
  }

  struct Export {
    pb::ExportCResponse head;
    std::vector<pb::ExportedCFunction> functions;
    std::string source;
    std::uint64_t revision = 0;
  };
  Export Run(api::Backend &b, const std::string &program, pb::CDialect dialect, bool per_function) {
    pb::ExportCRequest req;
    req.set_program_id(program);
    req.set_all(true);
    req.set_header(true);
    req.set_name("arm32");
    req.set_dialect(dialect);
    req.set_per_function(per_function);
    Export out;
    auto st = b.ExportC(ctx_, req, [&](const pb::ExportCResponse &m) {
      if (!m.header_name().empty()) out.head = m;
      for (const auto &f : m.function_sources()) out.functions.push_back(f);
      out.source += m.source_part();
      out.revision = m.snapshot().revision();
      return true;
    });
    EXPECT_TRUE(st.ok()) << st.message;
    return out;
  }

  // clang as an old C compiler for the DS's processor: "" when it accepts
  // `text`, else its errors.
  static std::string Compile(const std::string &name, const std::string &text) {
    const fs::path c = dir_ / (name + ".c"), log = dir_ / (name + ".log");
    std::ofstream(c) << text;
    const std::string cmd = std::string(REVKIT_TEST_CLANG) +
                            " -std=c89 -pedantic-errors --target=armv5te-none-eabi -c -o /dev/null -I" +
                            dir_.string() + " " + c.string() + " 2>" + log.string();
    const int rc = std::system(cmd.c_str());
    std::ifstream in(log);
    std::string errors;
    for (std::string line; std::getline(in, line);)
      if (line.find("error:") != std::string::npos) errors += line + "\n";
    return rc == 0 ? std::string() : errors.empty() ? std::string("failed\n") : errors;
  }

  static inline fs::path dir_;
  static inline bool built_ = false;
  CallContext ctx_;
};

// The header of the fixture, inference on, in C89: nothing C89 lacks, and
// Ghidra's built-in names defined once (an inferred structure's undefined4
// fields clashed with the archive's own undefined4).
TEST_F(ExportCTest, HeaderCompilesAsC89) {
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  o.infer_prototypes = InferMode::automatic;
  auto b = MakeImageBackend(o);
  const std::string id = Import(*b);
  ASSERT_FALSE(id.empty());
  Compilable(*b, id);
  Export ex = Run(*b, id, pb::C_DIALECT_C89, false);
  const std::string &h = ex.head.header();
  ASSERT_FALSE(h.empty());
  EXPECT_NE(h.find("struct astruct_"), std::string::npos) << h;
  for (const char *c11 : {"_Static_assert", "<stdbool.h>", "_Bool", "typedef void code;", "unsigned long long :"})
    EXPECT_EQ(h.find(c11), std::string::npos) << c11;
  EXPECT_EQ(h.find("typedef unsigned char undefined4[4];"), std::string::npos) << h;
  std::ofstream(dir_ / "arm32.h") << h;
  EXPECT_EQ(Compile("header", "#include \"arm32.h\"\nint revkit_check;\n"), "") << h;
  // The default dialect is C11.
  Export c11 = Run(*b, id, pb::C_DIALECT_UNSPECIFIED, false);
  EXPECT_NE(c11.head.header().find("#include <stdbool.h>"), std::string::npos);
  EXPECT_NE(c11.source.find("#include \"arm32.h\""), std::string::npos);
}

// Every function of the fixture, inference on, compiles with the C89
// header: the inferred structures' fields and gaps (field_0x10), the
// function types the C names, its globals, Ghidra's names once.
TEST_F(ExportCTest, EveryFunctionCompilesAsC89) {
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  o.infer_prototypes = InferMode::automatic;
  auto b = MakeImageBackend(o);
  const std::string id = Import(*b);
  ASSERT_FALSE(id.empty());
  Compilable(*b, id);
  Export ex = Run(*b, id, pb::C_DIALECT_C89, true);
  const std::string &h = ex.head.header();
  ASSERT_FALSE(h.empty());
  ASSERT_GT(ex.functions.size(), 40u);
  EXPECT_TRUE(ex.source.empty());  // per function: no .c
  // Inference's structures are there, and nothing C89 lacks.
  EXPECT_NE(h.find("struct astruct_"), std::string::npos) << h;
  EXPECT_NE(h.find("typedef struct astruct_"), std::string::npos) << h;
  EXPECT_NE(h.find("/* Globals */"), std::string::npos) << h;
  for (const char *c11 : {"_Static_assert", "<stdbool.h>", "_Bool", "typedef void code;"})
    EXPECT_EQ(h.find(c11), std::string::npos) << c11;
  std::ofstream(dir_ / "arm32.h") << h;
  EXPECT_EQ(Compile("header", "#include \"arm32.h\"\nint revkit_check;\n"), "") << h;
  std::size_t compiled = 0, failed = 0;
  std::string why;
  for (const pb::ExportedCFunction &f : ex.functions) {
    if (f.source().empty()) continue;  // the decompiler failed (none should)
    const std::string errors = Compile("f_" + f.name(), "#include \"arm32.h\"\n\n" + f.source());
    if (errors.empty()) {
      ++compiled;
    } else {
      ++failed;
      if (why.size() < 4000) why += f.name() + ":\n" + errors + f.source() + "\n";
    }
  }
  EXPECT_EQ(failed, 0u) << why;
  EXPECT_EQ(compiled, ex.functions.size());
  // The header declares each function (but a second of one name: a thunk's).
  std::map<std::string, int> names;
  for (const pb::ExportedCFunction &f : ex.functions) ++names[f.name()];
  for (const pb::ExportedCFunction &f : ex.functions)
    if (!f.source().empty() && names[f.name()] == 1) EXPECT_FALSE(f.prototype().empty()) << f.name();
}

// The default dialect (C11) of the same export: the same types, its own
// built-ins; and one source file whose functions follow the header.
TEST_F(ExportCTest, DefaultDialectIsC11) {
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  o.infer_prototypes = InferMode::automatic;
  auto b = MakeImageBackend(o);
  const std::string id = Import(*b);
  ASSERT_FALSE(id.empty());
  Export ex = Run(*b, id, pb::C_DIALECT_UNSPECIFIED, false);
  const std::string &h = ex.head.header();
  EXPECT_NE(h.find("#include <stdbool.h>"), std::string::npos);
  EXPECT_NE(h.find("struct astruct_"), std::string::npos);
  EXPECT_TRUE(ex.functions.empty());
  EXPECT_NE(ex.source.find("#include \"arm32.h\""), std::string::npos);
  // A structure's gap is a byte the C can name.
  EXPECT_NE(h.find("unsigned char field_0x"), std::string::npos) << h;
}

// A scratch (ExportDecompScratch) in C89 for a function an inferred
// structure's pointer reaches: its context and C compile together.
TEST_F(ExportCTest, ScratchCompilesAsC89) {
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  o.infer_prototypes = InferMode::automatic;
  auto b = MakeImageBackend(o);
  const std::string id = Import(*b);
  ASSERT_FALSE(id.empty());
  Compilable(*b, id);
  Export ex = Run(*b, id, pb::C_DIALECT_C89, true);
  std::size_t tried = 0;
  std::string why;
  for (const pb::ExportedCFunction &f : ex.functions) {
    if (f.source().find("astruct_") == std::string::npos) continue;
    pb::ExportDecompScratchRequest req;
    req.set_program_id(id);
    *req.mutable_function() = f.entry();
    req.mutable_read()->set_revision(ex.revision);  // the export's revision
    req.set_dialect(pb::C_DIALECT_C89);
    pb::ExportDecompScratchResponse resp;
    ASSERT_TRUE(b->ExportDecompScratch(ctx_, req, resp).ok());
    EXPECT_EQ(resp.snapshot().revision(), ex.revision);
    EXPECT_GT(resp.types(), 0u) << f.name();
    // The PROBE line is the probe format's `//` comment (mwcc takes it).
    ASSERT_EQ(resp.text().rfind("// PROBE: ", 0), 0u);
    const std::string errors = Compile("scratch_" + f.name(), resp.text().substr(resp.text().find('\n') + 1));
    if (!errors.empty()) why += f.name() + ":\n" + errors + resp.text() + "\n";
    if (++tried == 6) break;
  }
  EXPECT_GT(tried, 0u);
  EXPECT_EQ(why, "");
}

}  // namespace
}  // namespace revkit::backend
