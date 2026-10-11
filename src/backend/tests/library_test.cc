// Library prototypes (docs/types.md#library-prototypes): revkit's own type
// archives, built from the host's headers by rk-typeinfo, give imports
// their prototypes by name, and a printf-like call whose format is a
// constant string passes the arguments the format names.
#include "builders.hh"

#include "revkit/backend/image_backend.h"
#include "revkit/inputs/library.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <map>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
namespace fs = std::filesystem;
using api::CallContext;

std::string Text(const pb::DecompiledFunction &f) {
  std::string out;
  for (const auto &line : f.lines()) {
    for (const auto &t : line.tokens()) out += t.text();
    out += '\n';
  }
  return out;
}

class LibraryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!inputs::read_library_archive("libc-lp64")) GTEST_SKIP() << "no libc-lp64 archive (no glibc headers at build time)";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
  }

  std::string Import(const std::string &rel) {
    const fs::path path = fs::path(REVKIT_CORPUS) / rel;
    if (!fs::exists(path)) return {};
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(path.string());
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  std::map<std::string, std::uint64_t> Functions(const std::string &id) {
    pb::ListFunctionsRequest req;
    req.set_program_id(id);
    req.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(backend_->ListFunctions(ctx_, req, resp).ok());
    std::map<std::string, std::uint64_t> out;
    for (const auto &f : resp.functions()) out[f.name()] = f.entry().offset();
    return out;
  }

  pb::Function Function(const std::string &id, std::uint64_t entry) {
    pb::GetFunctionRequest req;
    req.set_program_id(id);
    req.mutable_address()->set_offset(entry);
    pb::GetFunctionResponse resp;
    EXPECT_TRUE(backend_->GetFunction(ctx_, req, resp).ok());
    return resp.function();
  }

  std::string Decompile(const std::string &id, std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(id);
    req.mutable_function()->set_offset(entry);
    pb::DecompileResponse resp;
    auto st = backend_->Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return Text(resp.function());
  }

  std::unique_ptr<api::Backend> backend_;
  CallContext ctx_;
};

// The stripped x86-64 features program's imports: printf's stub has the
// archive's prototype at library rank, exit is no-return, and the C of a
// function passing a constant format to snprintf passes exactly what the
// format names.
TEST_F(LibraryTest, ImportsGetTheArchivesPrototypesAndFormatsTheirArguments) {
  const std::string id = Import("elf-x86_64/gcc-O2/stripped/features");
  if (id.empty()) GTEST_SKIP() << "no corpus";
  const auto fns = Functions(id);
  ASSERT_TRUE(fns.contains("printf"));
  const pb::Function printf = Function(id, fns.at("printf"));
  EXPECT_EQ(printf.prototype_origin().derived().rule(), "library:libc-lp64");
  EXPECT_NE(printf.prototype().find("printf(const char *restrict __format, ...)"), std::string::npos)
      << printf.prototype();

  // "%s/%d/%c": a string, an int and a character after the format.
  bool seen = false;
  for (const auto &[name, entry] : fns) {
    if (!name.starts_with("FUN_")) continue;
    const std::string c = Decompile(id, entry);
    const auto at = c.find("\"%s/%d/%c\"");
    if (at == std::string::npos) continue;
    seen = true;
    const std::string call = c.substr(at, c.find(';', at) - at);
    EXPECT_EQ(std::count(call.begin(), call.end(), ','), 3) << call;
    EXPECT_EQ(call.find("(ulong)"), std::string::npos) << call;  // an int, as %d says
  }
  EXPECT_TRUE(seen);
}

// A PE gets the Windows archives of its data model: the C runtime's and
// kernel32's types and prototypes.
TEST_F(LibraryTest, APeGetsTheWindowsArchives) {
  if (!inputs::read_library_archive("kernel32-llp64")) GTEST_SKIP() << "no mingw-w64 headers at build time";
  const std::string id = Import("pe-x86_64/clang-O2/stripped/features.exe");
  if (id.empty()) GTEST_SKIP() << "no corpus";
  pb::FindTypesRequest req;
  req.set_program_id(id);
  req.set_name_contains("FILETIME");
  req.add_sources(pb::TYPE_SOURCE_LIBRARY);
  pb::FindTypesResponse resp;
  ASSERT_TRUE(backend_->FindTypes(ctx_, req, resp).ok());
  bool found = false;
  for (const auto &t : resp.types())
    if (t.name() == "_FILETIME") {
      found = true;
      EXPECT_EQ(t.size(), 8u);
      EXPECT_EQ(t.origin().derived().rule().rfind("library:", 0), 0u) << t.origin().derived().rule();
    }
  EXPECT_TRUE(found);
}

}  // namespace
}  // namespace revkit::backend
