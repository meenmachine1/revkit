// Shared libraries (api_minor 70, docs/api.md "Libraries"): a program built
// here against a tiny shared library built here. The loader's needed list,
// soname and build ID; importing the library with the program (and the libc
// it can't find, listed as missing); its imports resolved to the library's
// functions; links; and the debugger naming a frame in the library from the
// library program.
#include "builders.hh"

#include "libraries.h"
#include "revkit/backend/image_backend.h"
#include "revkit/debug/gdb_remote.hh"
#include "revkit/loader/load.hh"

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

constexpr const char *kLibrary = R"(
__attribute__((noinline)) int lib_add(int a, int b) { return a + b + 1000; }
int lib_twice(int a) { return lib_add(a, a); }
// A frame of its own (no frame pointer at -O1) around a call: unwinding out
// of it needs the library's CFI.
__attribute__((noinline)) int lib_leaf(int a) { return a * 3 + 1; }
__attribute__((noinline)) int lib_deep(int a) {
  volatile int buf[16];
  for (int i = 0; i < 16; ++i) buf[i] = a + i;
  int r = lib_leaf(buf[a & 15]);
  return r + buf[0] + buf[15];
}
)";

constexpr const char *kProgram = R"(
int lib_add(int a, int b);
int lib_twice(int a);
int lib_deep(int a);
int main(int argc, char **argv) {
  (void)argv;
  int r = lib_add(argc, 2) + lib_twice(argc);
  return (r + lib_deep(argc)) & 0x7f;
}
)";

class Libraries : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty() || std::string(REVKIT_TEST_CC).empty()) return;
    dir_ = testing::scratch_dir("libraries");
    lib_ = dir_ / "libmylib.so";
    exe_ = dir_ / "prog";
    {
      std::ofstream(dir_ / "mylib.c") << kLibrary;
      std::ofstream(dir_ / "prog.c") << kProgram;
    }
    const std::string cc = REVKIT_TEST_CC;
    const std::string lib = cc + " -O1 -fno-inline -shared -fPIC -Wl,-soname,libmylib.so -Wl,--build-id " +
                            (dir_ / "mylib.c").string() + " -o " + lib_.string() + " 2>/dev/null";
    const std::string exe = cc + " -O1 -pie -fPIE " + (dir_ / "prog.c").string() + " -o " + exe_.string() +
                            " -Wl,--no-as-needed -L" + dir_.string() + " -lmylib -Wl,-rpath," + dir_.string() + " 2>/dev/null";
    built_ = std::system(lib.c_str()) == 0 && std::system(exe.c_str()) == 0 && fs::exists(exe_);
  }
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!built_) GTEST_SKIP() << "no C compiler that builds a shared library";
  }
  void Open(bool live = false, std::vector<std::string> browse_roots = {}) {
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.debug_live = live;
    o.browse_roots = std::move(browse_roots);
    backend_ = MakeImageBackend(o);
  }
  // An extracted root file system under <dir>/fw/rootfs: the program in
  // /usr/bin, the library in /opt/vendor/lib (named by /etc/ld.so.conf's
  // include) as libmylib.so.1, with libmylib.so an absolute symlink to it
  // (resolved inside the root, not on the host), and a link that tries to
  // climb out.
  static fs::path MakeRootFs() {
    const fs::path root = dir_ / "fw" / "rootfs";
    fs::remove_all(dir_ / "fw");
    for (const char *d : {"usr/bin", "lib", "etc/ld.so.conf.d", "opt/vendor/lib"}) fs::create_directories(root / d);
    fs::copy_file(exe_, root / "usr/bin/prog");
    fs::copy_file(lib_, root / "opt/vendor/lib/libmylib.so.1");
    fs::create_symlink("/opt/vendor/lib/libmylib.so.1", root / "opt/vendor/lib/libmylib.so");
    fs::create_symlink("../../../../../../../../../../etc/passwd", root / "lib/escape");
    std::ofstream(root / "etc/ld.so.conf") << "# comment\ninclude /etc/ld.so.conf.d/*.conf\n";
    std::ofstream(root / "etc/ld.so.conf.d/vendor.conf") << "/opt/vendor/lib\n";
    return root;
  }
  // The program, uploaded (so the host's own libraries aren't searched),
  // with the libraries found beside it.
  pb::ImportProgramResponse ImportWithLibraries(const std::string &folder = "") {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    const auto bytes = testing::read_file(exe_);
    req.set_content(std::string(bytes.begin(), bytes.end()));
    req.set_name("prog");
    req.set_folder_id(folder);
    req.mutable_options()->set_import_libraries(true);
    req.mutable_options()->add_library_search_paths(dir_.string());
    req.mutable_options()->set_library_depth(1);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("test");
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }
  std::map<std::string, std::uint64_t> Functions(const std::string &program) {
    pb::ListFunctionsRequest lf;
    lf.set_program_id(program);
    lf.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse lr;
    EXPECT_TRUE(backend_->ListFunctions(ctx_, lf, lr).ok());
    std::map<std::string, std::uint64_t> out;
    for (const auto &f : lr.functions()) out[f.name()] = f.entry().offset();
    return out;
  }
  pb::ListProgramLibrariesResponse Libs(const std::string &program) {
    pb::ListProgramLibrariesRequest req;
    req.set_program_id(program);
    req.set_include_imports(true);
    pb::ListProgramLibrariesResponse resp;
    auto st = backend_->ListProgramLibraries(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }
  static const pb::ProgramLibrary *Find(const pb::ListProgramLibrariesResponse &r, const std::string &name) {
    for (const auto &l : r.libraries())
      if (l.name() == name) return &l;
    return nullptr;
  }

  static inline fs::path dir_, lib_, exe_;
  static inline bool built_ = false;
  std::unique_ptr<api::Backend> backend_;
  CallContext ctx_;
};

TEST_F(Libraries, TheLoaderReadsNeededSonameRunpathAndBuildId) {
  const loader::Image exe = loader::load_file(exe_);
  EXPECT_NE(std::find(exe.needed.begin(), exe.needed.end(), "libmylib.so"), exe.needed.end());
  EXPECT_NE(std::find(exe.needed.begin(), exe.needed.end(), "libc.so.6"), exe.needed.end());
  ASSERT_FALSE(exe.runpath.empty());
  EXPECT_EQ(exe.runpath.front(), dir_.string());
  const loader::Image lib = loader::load_file(lib_);
  EXPECT_EQ(lib.soname, "libmylib.so");
  EXPECT_GE(lib.build_id.size(), 16u);
  EXPECT_EQ(lib.build_id.find_first_not_of("0123456789abcdef"), std::string::npos) << lib.build_id;
}

TEST_F(Libraries, ImportedWithTheProgramAndItsImportsResolved) {
  Open();
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_GE(info.api_minor(), 70u);
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "program-libraries"), info.features().end());

  // A folder for both.
  pb::CreateFolderRequest cf;
  cf.set_project_id("default");
  cf.set_name("app");
  cf.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  pb::CreateFolderResponse folder;
  ASSERT_TRUE(backend_->CreateFolder(ctx_, cf, folder).ok());

  const pb::ImportProgramResponse imported = ImportWithLibraries(folder.folder().folder_id());
  const std::string prog = imported.program().program_id();
  EXPECT_EQ(imported.program().folder_path(), "/app");
  ASSERT_EQ(imported.libraries_size(), 1);
  const std::string lib = imported.libraries(0).program_id();
  EXPECT_EQ(imported.libraries(0).name(), "libmylib.so");
  EXPECT_EQ(imported.libraries(0).folder_path(), "/app");
  // libc isn't beside it, and an upload's host directories aren't searched.
  bool libc_missing = false;
  for (const auto &m : imported.libraries_not_found()) libc_missing |= m.name() == "libc.so.6" && m.needed_by() == "prog";
  EXPECT_TRUE(libc_missing);

  // Its libraries: libmylib resolved by name, libc not in the project.
  auto libs = Libs(prog);
  const pb::ProgramLibrary *my = Find(libs, "libmylib.so");
  ASSERT_NE(my, nullptr);
  EXPECT_EQ(my->resolution(), pb::LIBRARY_RESOLUTION_NAME);
  EXPECT_EQ(my->program_id(), lib);
  EXPECT_EQ(my->depth(), 0u);
  EXPECT_GE(my->imports_resolved(), 2u);
  const pb::ProgramLibrary *libc = Find(libs, "libc.so.6");
  ASSERT_NE(libc, nullptr);
  EXPECT_EQ(libc->resolution(), pb::LIBRARY_RESOLUTION_NONE);
  // The library's own name and build ID.
  auto own = Libs(lib);
  EXPECT_EQ(own.soname(), "libmylib.so");
  EXPECT_FALSE(own.build_id().empty());

  // lib_add: its thunk in prog, the function in the library.
  const auto lib_functions = Functions(lib);
  ASSERT_TRUE(lib_functions.count("lib_add"));
  const pb::ResolvedImport *add = nullptr;
  for (const auto &i : libs.imports())
    if (i.name() == "lib_add") add = &i;
  ASSERT_NE(add, nullptr);
  EXPECT_TRUE(add->resolved());
  EXPECT_EQ(add->library(), "libmylib.so");
  EXPECT_EQ(add->program_id(), lib);
  EXPECT_EQ(add->address().offset(), lib_functions.at("lib_add"));
  EXPECT_EQ(add->function_name(), "lib_add");
  ASSERT_TRUE(add->has_thunk());

  // ResolveImport, by name and by the thunk.
  pb::ResolveImportRequest rr;
  rr.set_program_id(prog);
  rr.set_name("lib_twice");
  pb::ResolveImportResponse resolved;
  ASSERT_TRUE(backend_->ResolveImport(ctx_, rr, resolved).ok());
  EXPECT_TRUE(resolved.resolved().resolved());
  EXPECT_EQ(resolved.resolved().address().offset(), lib_functions.at("lib_twice"));
  rr.mutable_address()->set_offset(add->thunk().offset());
  ASSERT_TRUE(backend_->ResolveImport(ctx_, rr, resolved).ok());
  EXPECT_EQ(resolved.resolved().name(), "lib_add");
  rr.set_name("no_such_import");
  EXPECT_EQ(backend_->ResolveImport(ctx_, rr, resolved).code, api::StatusCode::kNotFound);

  // References back from the library: prog imports lib_add, main calls it.
  EXPECT_GE(info.api_minor(), 81u);
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "library-importers"), info.features().end());
  pb::ListLibraryImportersRequest li;
  li.set_program_id(lib);
  li.mutable_address()->set_offset(lib_functions.at("lib_add") + 1);  // inside it: the function
  li.set_include_references(true);
  pb::ListLibraryImportersResponse back;
  auto bst = backend_->ListLibraryImporters(ctx_, li, back);
  ASSERT_TRUE(bst.ok()) << bst.message;
  ASSERT_EQ(back.importers_size(), 1);
  EXPECT_EQ(back.importers(0).program_id(), prog);
  EXPECT_EQ(back.importers(0).program_name(), "prog");
  EXPECT_EQ(back.importers(0).library(), "libmylib.so");
  EXPECT_EQ(back.importers(0).resolved().name(), "lib_add");
  EXPECT_EQ(back.importers(0).resolved().thunk().offset(), add->thunk().offset());
  bool from_main = false;
  for (const auto &x : back.importers(0).references()) {
    from_main |= x.from_function_name() == "main" && x.kind() == pb::XREF_KIND_CALL;
    EXPECT_NE(x.from_function().offset(), add->thunk().offset()) << "the thunk's own jump is left out";
  }
  EXPECT_TRUE(from_main);
  // Every import of it: lib_add and lib_twice; by name; none from prog itself.
  li.clear_address();
  li.set_include_references(false);
  back.Clear();
  ASSERT_TRUE(backend_->ListLibraryImporters(ctx_, li, back).ok());
  std::set<std::string> names;
  for (const auto &u : back.importers()) names.insert(u.resolved().name());
  EXPECT_TRUE(names.count("lib_add") && names.count("lib_twice"));
  EXPECT_EQ(back.importers(0).references_size(), 0);
  li.set_name("lib_twice");
  back.Clear();
  ASSERT_TRUE(backend_->ListLibraryImporters(ctx_, li, back).ok());
  ASSERT_EQ(back.importers_size(), 1);
  EXPECT_EQ(back.importers(0).resolved().address().offset(), lib_functions.at("lib_twice"));
  li.set_program_id(prog);
  back.Clear();
  ASSERT_TRUE(backend_->ListLibraryImporters(ctx_, li, back).ok());
  EXPECT_EQ(back.importers_size(), 0);

  // A link: libc.so.6 is (say) the library program; then found by name again.
  pb::LinkProgramLibraryRequest link;
  link.set_program_id(prog);
  link.set_library("libc.so.6");
  link.set_target_program_id(lib);
  link.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  link.mutable_provenance()->set_id("test");
  pb::LinkProgramLibraryResponse linked;
  auto st = backend_->LinkProgramLibrary(ctx_, link, linked);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(linked.library().resolution(), pb::LIBRARY_RESOLUTION_LINKED);
  EXPECT_EQ(linked.library().program_id(), lib);
  EXPECT_TRUE(linked.library().origin().has_asserted());
  EXPECT_EQ(Find(Libs(prog), "libc.so.6")->resolution(), pb::LIBRARY_RESOLUTION_LINKED);
  link.set_target_program_id("");
  ASSERT_TRUE(backend_->LinkProgramLibrary(ctx_, link, linked).ok());
  EXPECT_EQ(linked.library().resolution(), pb::LIBRARY_RESOLUTION_NONE);
  link.set_target_program_id(prog);
  EXPECT_EQ(backend_->LinkProgramLibrary(ctx_, link, linked).code, api::StatusCode::kInvalidArgument);
}

TEST_F(Libraries, ARootFileSystemIsSearchedInsideItself) {
  const fs::path root = fs::canonical(MakeRootFs());
  // Found from the program, below the browse root, not above it.
  EXPECT_EQ(libs::FindRootFileSystem(root / "usr/bin/prog", dir_ / "fw"), root);
  EXPECT_EQ(libs::FindRootFileSystem(root / "usr/bin/prog", root / "usr"), std::nullopt);
  auto r = libs::HostRoot(root);
  // An absolute link is from the root; one climbing out stops at it.
  EXPECT_EQ(r->file("/opt/vendor/lib/libmylib.so"), (root / "opt/vendor/lib/libmylib.so.1").string());
  EXPECT_EQ(r->file("/lib/escape"), std::nullopt);
  EXPECT_EQ(r->file("/../../../../etc/passwd"), std::nullopt);
  EXPECT_EQ(r->origin((root / "usr/bin/prog").string()), "/usr/bin");
  const loader::Image exe = loader::load_file(exe_);
  const auto dirs = libs::RootSearchDirs(*r, {}, "/usr/bin", exe);
  EXPECT_EQ(dirs.front(), "/usr/bin");
  EXPECT_NE(std::find(dirs.begin(), dirs.end(), "/opt/vendor/lib"), dirs.end());
  EXPECT_NE(std::find(dirs.begin(), dirs.end(), "/usr/lib"), dirs.end());
  EXPECT_EQ(libs::FindLibraryIn(*r, "libmylib.so", dirs, exe), (root / "opt/vendor/lib/libmylib.so.1").string());
  EXPECT_EQ(libs::FindLibraryIn(*r, "libc.so.6", dirs, exe), std::nullopt);
}

TEST_F(Libraries, ImportedFromTheProgramsRootFileSystem) {
  const fs::path root = fs::canonical(MakeRootFs());
  Open(false, {(dir_ / "fw").string()});
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_GE(info.api_minor(), 79u);
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "library-roots"), info.features().end());

  pb::ImportProgramRequest req;
  req.set_project_id("default");
  req.set_path((root / "usr/bin/prog").string());
  req.mutable_options()->set_import_libraries(true);
  req.mutable_options()->set_library_depth(1);
  req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  pb::ImportProgramResponse resp;
  auto st = backend_->ImportProgram(ctx_, req, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(resp.library_root(), root.string());
  ASSERT_EQ(resp.libraries_size(), 1);
  EXPECT_EQ(resp.libraries(0).name(), "libmylib.so");
  // libc isn't in the root, and the host's isn't looked at instead.
  bool libc_missing = false;
  for (const auto &m : resp.libraries_not_found()) libc_missing |= m.name() == "libc.so.6";
  EXPECT_TRUE(libc_missing);
  const auto libs = Libs(resp.program().program_id());
  const pb::ProgramLibrary *my = Find(libs, "libmylib.so");
  ASSERT_NE(my, nullptr);
  EXPECT_EQ(my->program_id(), resp.libraries(0).program_id());

  // library_root must be under a --browse-root.
  pb::ImportProgramRequest bad = req;
  bad.mutable_options()->set_library_root(dir_.string());
  pb::ImportProgramResponse bad_resp;
  EXPECT_EQ(backend_->ImportProgram(ctx_, bad, bad_resp).code, api::StatusCode::kPermissionDenied);
  Open();
  EXPECT_EQ(backend_->ImportProgram(ctx_, bad, bad_resp).code, api::StatusCode::kFailedPrecondition);
}

TEST_F(Libraries, ImportedFromTheSameContainer) {
  const fs::path root = MakeRootFs();
  const fs::path tar = dir_ / "rootfs.tar";
  fs::remove(tar);
  if (std::system(("tar -C " + root.string() + " -cf " + tar.string() + " . 2>/dev/null").c_str()) != 0)
    GTEST_SKIP() << "no tar";
  Open();
  pb::OpenFileSystemRequest open;
  open.set_project_id("default");
  open.set_host_path(tar.string());
  pb::OpenFileSystemResponse opened;
  auto st = backend_->OpenFileSystem(ctx_, open, opened);
  ASSERT_TRUE(st.ok()) << st.message;

  pb::ImportFromFileSystemRequest req;
  req.set_session_id(opened.session_id());
  req.set_project_id("default");
  req.add_paths("/usr/bin/prog");
  req.mutable_options()->set_import_libraries(true);
  req.mutable_options()->set_library_depth(1);
  req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  pb::ImportFromFileSystemResponse resp;
  st = backend_->ImportFromFileSystem(ctx_, req, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  ASSERT_EQ(resp.items_size(), 2);
  EXPECT_EQ(resp.imported(), 2u);
  const pb::FileSystemImport &prog = resp.items(0), &lib = resp.items(1);
  EXPECT_EQ(prog.action(), "imported");
  EXPECT_EQ(lib.action(), "imported");
  EXPECT_EQ(lib.library_of(), "prog");
  EXPECT_EQ(lib.path(), "/opt/vendor/lib/libmylib.so.1");
  EXPECT_EQ(lib.container_path(), "tar://rootfs.tar!/opt/vendor/lib/libmylib.so.1");
  EXPECT_EQ(lib.program().name(), "libmylib.so");
  EXPECT_EQ(lib.program().container_path(), lib.container_path());
  bool libc_missing = false;
  for (const auto &m : resp.libraries_not_found()) libc_missing |= m.name() == "libc.so.6" && m.needed_by() == "prog";
  EXPECT_TRUE(libc_missing);
  const auto libs = Libs(prog.program().program_id());
  const pb::ProgramLibrary *my = Find(libs, "libmylib.so");
  ASSERT_NE(my, nullptr);
  EXPECT_EQ(my->program_id(), lib.program().program_id());
  EXPECT_GE(my->imports_resolved(), 2u);
}

TEST_F(Libraries, TheDebuggerNamesALibraryFrameFromTheLibraryProgram) {
  if (debug::find_program("gdbserver").empty()) GTEST_SKIP() << "gdbserver is not installed";
  Open(true);
  const pb::ImportProgramResponse imported = ImportWithLibraries();
  const std::string prog = imported.program().program_id();
  ASSERT_EQ(imported.libraries_size(), 1);
  const std::string lib = imported.libraries(0).program_id();
  const auto prog_functions = Functions(prog);
  const auto lib_functions = Functions(lib);
  ASSERT_TRUE(prog_functions.count("main"));
  ASSERT_TRUE(lib_functions.count("lib_add"));

  pb::CreateDebugSessionRequest req;
  req.set_program_id(prog);
  req.mutable_launch()->add_arguments("x");  // under gdbserver
  auto *bp = req.add_breakpoints();
  bp->mutable_address()->set_offset(prog_functions.at("main"));
  bp->mutable_address()->set_program(true);
  pb::CreateDebugSessionResponse created;
  auto st = backend_->CreateDebugSession(ctx_, req, created);
  ASSERT_TRUE(st.ok()) << st.message;
  const std::string id = created.session_id();
  auto resume = [&](pb::DebugRunMode mode) {
    pb::ResumeDebugSessionRequest r;
    r.set_session_id(id);
    r.set_mode(mode);
    r.set_time_limit_ms(20000);
    pb::ResumeDebugSessionResponse out;
    auto s = backend_->ResumeDebugSession(ctx_, r, out);
    EXPECT_TRUE(s.ok()) << s.message;
    return out;
  };
  auto r = resume(pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT) << r.stop().detail();

  // The library's module is the library program, with its slide.
  pb::ListDebugModulesRequest mr;
  mr.set_session_id(id);
  pb::ListDebugModulesResponse mods;
  ASSERT_TRUE(backend_->ListDebugModules(ctx_, mr, mods).ok());
  const pb::DebugModule *mine = nullptr;
  std::string listed;
  for (const auto &m : mods.modules()) {
    listed += m.name() + " (" + m.path() + ") ";
    if (m.name() == "libmylib.so") mine = &m;
  }
  ASSERT_NE(mine, nullptr) << listed;
  EXPECT_EQ(mine->program_id(), lib);
  const std::uint64_t runtime = lib_functions.at("lib_add") + static_cast<std::uint64_t>(mine->library_slide());

  // A breakpoint in lib_add at its runtime address; the stop is named from the library.
  pb::SetDebugBreakpointsRequest sb;
  sb.set_session_id(id);
  sb.add_add()->mutable_address()->set_offset(runtime);
  pb::SetDebugBreakpointsResponse sbr;
  ASSERT_TRUE(backend_->SetDebugBreakpoints(ctx_, sb, sbr).ok());
  r = resume(pb::DEBUG_RUN_MODE_RUN);
  ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT) << r.stop().detail();
  EXPECT_EQ(r.state().pc().address().offset(), runtime);
  EXPECT_FALSE(r.state().pc().has_program_address());
  EXPECT_EQ(r.state().pc().library_program_id(), lib);
  EXPECT_EQ(r.state().pc().library_address().offset(), lib_functions.at("lib_add"));
  EXPECT_EQ(r.state().pc().library_function(), "lib_add");

  // The stack: lib_add (the library's), then main (the program's).
  pb::GetDebugBacktraceRequest bt;
  bt.set_session_id(id);
  pb::GetDebugBacktraceResponse frames;
  ASSERT_TRUE(backend_->GetDebugBacktrace(ctx_, bt, frames).ok());
  ASSERT_GE(frames.frames_size(), 2);
  EXPECT_EQ(frames.frames(0).function(), "lib_add");
  EXPECT_EQ(frames.frames(0).function_entry().offset(), lib_functions.at("lib_add"));
  EXPECT_EQ(frames.frames(0).pc().library_program_id(), lib);
  bool main_found = false;
  for (const auto &f : frames.frames()) main_found |= f.function() == "main" && f.pc().has_program_address();
  EXPECT_TRUE(main_found);

  // Out of lib_deep, whose frame has no frame pointer: the library's own CFI
  // unwinds lib_leaf and lib_deep, back to main.
  ASSERT_TRUE(lib_functions.count("lib_leaf"));
  sb.clear_add();
  sb.add_add()->mutable_address()->set_offset(lib_functions.at("lib_leaf") + static_cast<std::uint64_t>(mine->library_slide()));
  ASSERT_TRUE(backend_->SetDebugBreakpoints(ctx_, sb, sbr).ok());
  pb::GetDebugBacktraceResponse deep;
  for (int i = 0; i < 4; ++i) {  // past lib_add's other hits
    r = resume(pb::DEBUG_RUN_MODE_RUN);
    ASSERT_EQ(r.stop().kind(), pb::DEBUG_STOP_KIND_BREAKPOINT) << r.stop().detail();
    if (r.state().pc().library_function() == "lib_leaf") break;
  }
  ASSERT_EQ(r.state().pc().library_function(), "lib_leaf");
  deep.Clear();
  ASSERT_TRUE(backend_->GetDebugBacktrace(ctx_, bt, deep).ok());
  std::string stack;
  for (const auto &f : deep.frames()) stack += f.function() + " (" + f.how() + ") ";
  ASSERT_GE(deep.frames_size(), 3) << stack;
  EXPECT_EQ(deep.frames(0).function(), "lib_leaf") << stack;
  EXPECT_EQ(deep.frames(1).function(), "lib_deep") << stack;
  EXPECT_EQ(deep.frames(1).how(), "cfi") << stack;
  EXPECT_EQ(deep.frames(2).function(), "main") << stack;
  EXPECT_EQ(deep.frames(2).how(), "cfi") << stack;
  EXPECT_TRUE(deep.frames(2).pc().has_program_address()) << stack;

  // Its disassembly names it "libmylib.so!lib_add".
  pb::DisassembleDebugMemoryRequest dr;
  dr.set_session_id(id);
  dr.mutable_address()->set_offset(runtime);
  dr.set_count(2);
  pb::DisassembleDebugMemoryResponse dis;
  st = backend_->DisassembleDebugMemory(ctx_, dr, dis);
  ASSERT_TRUE(st.ok()) << st.message;
  ASSERT_GE(dis.instructions_size(), 1);
  EXPECT_EQ(dis.instructions(0).symbol(), "libmylib.so!lib_add");

  pb::CloseDebugSessionRequest close;
  close.set_session_id(id);
  pb::CloseDebugSessionResponse closed;
  EXPECT_TRUE(backend_->CloseDebugSession(ctx_, close, closed).ok());
}

}  // namespace
}  // namespace revkit::backend
