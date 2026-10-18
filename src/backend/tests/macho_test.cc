// Mach-O through the API (docs/macho.md), on tests/data/macho's fixtures
// built at test time: functions named by their symbols and their stubs by
// what they import, the decompiler calling them by name, ProgramSummary's
// Mach-O facts, a universal file's slices (the default, another one by
// program_file, a missing one), the relocation table, and a dylib linked
// by @rpath.
#include "macho_fixture.h"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <map>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;
using loader::macho_testing::Fixtures;

std::string Text(const pb::DecompiledFunction &f) {
  std::string out;
  for (const auto &line : f.lines()) {
    for (const auto &t : line.tokens()) out += t.text();
    out += '\n';
  }
  return out;
}

class MachoApi : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    const auto &f = loader::macho_testing::fixtures(REVKIT_TEST_CLANG, REVKIT_TEST_LD64, REVKIT_TEST_LIPO,
                                                    REVKIT_TEST_NM, REVKIT_TEST_OBJDUMP, REVKIT_MACHO_FIXTURE);
    if (!f) GTEST_SKIP() << "clang, ld64.lld or llvm tools missing, or the fixtures didn't build";
    fx_ = &*f;
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
  }

  pb::ImportProgramResponse Import(const std::string &name, const std::string &slice = {}, bool libraries = false) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(fx_->path(name).string());
    req.mutable_options()->set_macho_slice(slice);
    if (libraries) {
      req.mutable_options()->set_import_libraries(true);
      req.mutable_options()->add_library_search_paths(fx_->dir.string());
    }
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  std::map<std::string, pb::Function> Functions(const std::string &id) {
    pb::ListFunctionsRequest req;
    req.set_program_id(id);
    req.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(backend_->ListFunctions(ctx_, req, resp).ok());
    std::map<std::string, pb::Function> out;
    for (const auto &f : resp.functions()) out[f.name()] = f;
    return out;
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

  pb::ProgramSummary Summary(const std::string &id) {
    pb::GetProgramSummaryRequest req;
    req.set_program_id(id);
    pb::GetProgramSummaryResponse resp;
    EXPECT_TRUE(backend_->GetProgramSummary(ctx_, req, resp).ok());
    return resp.summary();
  }

  const Fixtures *fx_ = nullptr;
  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
};

TEST_F(MachoApi, NamesFunctionsAndStubsAndDecompilesCalls) {
  for (const char *name : {"hello-arm64", "hello-arm64-chained", "hello-x86_64", "hello-x86_64-chained"}) {
    SCOPED_TRACE(name);
    const pb::ImportProgramResponse imp = Import(name);
    const std::string id = imp.program().program_id();
    EXPECT_EQ(imp.program().format(), "macho");
    const auto syms = fx_->symbols(name);
    auto fns = Functions(id);
    for (const char *f : {"_main", "_add", "_twice"}) {
      ASSERT_TRUE(fns.contains(f)) << f;
      EXPECT_EQ(fns.at(f).entry().offset(), syms.at(f)) << f;
    }
    EXPECT_FALSE(fns.contains("__mh_execute_header"));  // the header is no function
    // The stubs: thunks named as Ghidra names them, after their import.
    for (const char *f : {"_printf", "_puts"}) {
      ASSERT_TRUE(fns.contains(f)) << f;
      EXPECT_TRUE(fns.at(f).thunk()) << f;
    }
    const std::string c = Decompile(id, syms.at("_main"));
    EXPECT_NE(c.find("_printf("), std::string::npos) << c;
    EXPECT_NE(c.find("_puts("), std::string::npos) << c;
  }
}

TEST_F(MachoApi, SummarizesTheHeaderAndLoadCommands) {
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_GE(info.api_minor(), 90u);
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "macho"), info.features().end());

  const std::string id = Import("hello-arm64-chained").program().program_id();
  const pb::ProgramSummary s = Summary(id);
  EXPECT_EQ(s.info().format(), "macho");
  EXPECT_EQ(s.language().language_id(), "AARCH64:LE:64:AppleSilicon");
  ASSERT_TRUE(s.has_macho());
  const pb::MachoSummary &m = s.macho();
  EXPECT_EQ(m.arch(), "arm64");
  EXPECT_EQ(m.file_type(), "execute");
  EXPECT_EQ(m.platform(), "macos");
  EXPECT_EQ(m.min_os(), "13.0");
  EXPECT_EQ(m.uuid().size(), 36u);
  EXPECT_EQ(s.build_id().size(), 32u);
  EXPECT_TRUE(m.code_signed());
  EXPECT_FALSE(m.encrypted());
  EXPECT_EQ(m.fixups(), "chained");
  EXPECT_EQ(m.dylinker(), "/usr/lib/dyld");
  ASSERT_EQ(m.dylibs_size(), 1);
  EXPECT_EQ(m.dylibs(0).name(), "/usr/lib/libSystem.B.dylib");
  EXPECT_EQ(m.dylibs(0).kind(), "load");
  EXPECT_NE(std::find(m.flags().begin(), m.flags().end(), "PIE"), m.flags().end());
  EXPECT_EQ(s.image_base().offset(), 0x100000000u);

  // The fixups, by Mach-O's names.
  pb::ListRelocationsRequest lr;
  lr.set_program_id(id);
  pb::ListRelocationsResponse rel;
  ASSERT_TRUE(backend_->ListRelocations(ctx_, lr, rel).ok());
  EXPECT_EQ(rel.format(), "macho");
  ASSERT_GT(rel.relocations_size(), 0);
  bool printf_bind = false;
  for (const auto &r : rel.relocations()) printf_bind |= r.symbol() == "_printf" && r.type_name() == "DYLD_CHAINED_PTR_64";
  EXPECT_TRUE(printf_bind);
}

TEST_F(MachoApi, ImportsUniversalSlices) {
  const pb::ImportProgramResponse fat = Import("hello-fat");
  EXPECT_EQ(fat.program().macho_slice(), "arm64");
  EXPECT_EQ(std::vector<std::string>(fat.program().macho_slices().begin(), fat.program().macho_slices().end()),
            (std::vector<std::string>{"x86_64", "arm64"}));
  EXPECT_EQ(fat.program().language_id(), "AARCH64:LE:64:AppleSilicon");
  const pb::ProgramSummary s = Summary(fat.program().program_id());
  ASSERT_EQ(s.macho().slices_size(), 2);
  EXPECT_EQ(s.macho().slice_index(), 1u);

  // The other slice, from the same stored file.
  pb::ImportProgramRequest again;
  again.set_project_id("default");
  again.set_program_file(fat.program().program_id());
  again.mutable_options()->set_macho_slice("x86_64");
  pb::ImportProgramResponse x86;
  auto st = backend_->ImportProgram(ctx_, again, x86);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(x86.program().name(), "hello-fat-x86_64");
  EXPECT_EQ(x86.program().macho_slice(), "x86_64");
  EXPECT_EQ(x86.program().language_id(), "x86:LE:64:default");
  EXPECT_EQ(x86.program().sha256(), fat.program().sha256());
  EXPECT_TRUE(Functions(x86.program().program_id()).contains("_main"));

  // A slice the file doesn't have.
  again.mutable_options()->set_macho_slice("ppc");
  pb::ImportProgramResponse none;
  st = backend_->ImportProgram(ctx_, again, none);
  EXPECT_EQ(st.code, api::StatusCode::kInvalidArgument);
  EXPECT_NE(st.message.find("x86_64, arm64"), std::string::npos) << st.message;
  again.set_program_file("default/nothing");
  EXPECT_EQ(backend_->ImportProgram(ctx_, again, none).code, api::StatusCode::kNotFound);
}

TEST_F(MachoApi, LinksADylibByRpath) {
  const pb::ImportProgramResponse imp = Import("uses-greet", {}, /*libraries=*/true);
  const std::string prog = imp.program().program_id();
  ASSERT_EQ(imp.libraries_size(), 1);
  EXPECT_EQ(imp.libraries(0).name(), "libgreet.dylib");
  bool system_missing = false;
  for (const auto &m : imp.libraries_not_found()) system_missing |= m.name() == "/usr/lib/libSystem.B.dylib";
  EXPECT_TRUE(system_missing);

  pb::ListProgramLibrariesRequest req;
  req.set_program_id(prog);
  req.set_include_imports(true);
  pb::ListProgramLibrariesResponse libs;
  ASSERT_TRUE(backend_->ListProgramLibraries(ctx_, req, libs).ok());
  const pb::ProgramLibrary *greet = nullptr;
  for (const auto &l : libs.libraries())
    if (l.name() == "@rpath/libgreet.dylib") greet = &l;
  ASSERT_NE(greet, nullptr);
  EXPECT_EQ(greet->resolution(), pb::LIBRARY_RESOLUTION_NAME);
  EXPECT_EQ(greet->program_id(), imp.libraries(0).program_id());
  EXPECT_GE(greet->imports_resolved(), 2u);  // _greet and _greet_count

  const auto lib_syms = fx_->symbols("libgreet.dylib");
  const pb::ResolvedImport *call = nullptr;
  for (const auto &i : libs.imports())
    if (i.name() == "_greet") call = &i;
  ASSERT_NE(call, nullptr);
  EXPECT_TRUE(call->resolved());
  EXPECT_EQ(call->library(), "@rpath/libgreet.dylib");
  EXPECT_EQ(call->address().offset(), lib_syms.at("_greet"));
  EXPECT_EQ(call->function_name(), "_greet");

  pb::ListProgramLibrariesRequest own;
  own.set_program_id(imp.libraries(0).program_id());
  pb::ListProgramLibrariesResponse lib;
  ASSERT_TRUE(backend_->ListProgramLibraries(ctx_, own, lib).ok());
  EXPECT_EQ(lib.soname(), "@rpath/libgreet.dylib");
}

TEST_F(MachoApi, ObjectiveCMetadataNamesTypesAndListsMethods) {
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_GE(info.api_minor(), 91u);
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "objc"), info.features().end());
  if (!std::filesystem::exists(fx_->path("objc-stripped"))) GTEST_SKIP() << "no llvm-strip";
  // Stripped of its local symbols: the methods' names come from the metadata.
  const pb::ImportProgramResponse imp = Import("objc-stripped");
  const std::string id = imp.program().program_id();
  bool counted = false;
  std::string warnings;
  for (const std::string &w : imp.warnings()) {
    counted |= w.find("analysis:objc: 1 objc categories, 2 objc classes") != std::string::npos;
    warnings += w + "\n";
  }
  EXPECT_TRUE(counted) << warnings;
  const auto syms = fx_->symbols("objc-arm64");
  auto fns = Functions(id);
  for (const char *m : {"-[Point sum]", "-[Point setX:]", "+[Base alloc]", "-[Point(Extra) diff]"}) {
    ASSERT_TRUE(fns.contains(m)) << m;
    EXPECT_EQ(fns.at(m).entry().offset(), syms.at(m)) << m;
  }
  // The type encoding's prototype (import:objc), self the class's struct.
  EXPECT_NE(fns.at("-[Point setX:]").prototype().find("Point *self"), std::string::npos) << fns.at("-[Point setX:]").prototype();
  EXPECT_NE(fns.at("-[Point setX:]").prototype().find("SEL _cmd"), std::string::npos);
  // The ivar is a field; the selectors read as their strings.
  const std::string sum = Decompile(id, syms.at("-[Point sum]"));
  EXPECT_NE(sum.find("self->y"), std::string::npos) << sum;
  EXPECT_NE(sum.find("\"x\""), std::string::npos) << sum;
  const std::string main = Decompile(id, syms.at("_main"));
  EXPECT_NE(main.find("\"sum\""), std::string::npos) << main;

  pb::ListObjcClassesRequest req;
  req.set_program_id(id);
  pb::ListObjcClassesResponse resp;
  ASSERT_TRUE(backend_->ListObjcClasses(ctx_, req, resp).ok());
  ASSERT_EQ(resp.classes_size(), 2);
  const pb::ObjcClass &point = resp.classes(1);
  EXPECT_EQ(point.name(), "Point");
  EXPECT_EQ(point.superclass(), "Base");
  EXPECT_EQ(point.address().offset(), syms.at("_OBJC_CLASS_$_Point"));
  ASSERT_EQ(point.methods_size(), 5);  // four of its own and the category's
  EXPECT_EQ(point.methods(4).selector(), "diff");
  EXPECT_EQ(point.methods(4).category(), "Extra");
  EXPECT_EQ(point.methods(4).function_name(), "-[Point(Extra) diff]");
  EXPECT_EQ(point.categories(0), "Extra");
  ASSERT_EQ(point.ivars_size(), 2);
  EXPECT_EQ(point.ivars(0).name(), "y");
  EXPECT_EQ(point.ivars(0).offset(), 8u);
  ASSERT_EQ(resp.protocols_size(), 1);
  EXPECT_EQ(resp.protocols(0).name(), "Named");
  req.set_name_contains("base");
  pb::ListObjcClassesResponse base;
  ASSERT_TRUE(backend_->ListObjcClasses(ctx_, req, base).ok());
  ASSERT_EQ(base.classes_size(), 1);
  EXPECT_TRUE(base.classes(0).root());
  EXPECT_EQ(base.protocols_size(), 0);
}

}  // namespace
}  // namespace revkit::backend
