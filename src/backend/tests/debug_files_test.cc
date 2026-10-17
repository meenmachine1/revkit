// Separate debug files for ELF (docs/backend.md "External debug files"):
// .gnu_debuglink and build-ID lookups in local trees made here, LoadDebugFile
// by path and by search, the cache the decompiler reads at the next load,
// and debuginfod from a fake server on a loopback port: never contacted
// while off, https only unless http is allowed, no redirect to another
// host, a size limit, another build's file refused. No test reaches the
// internet.
#include "builders.hh"
#include "debug_files.h"

#include "revkit/backend/image_backend.h"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>
#include <httplib.h>

#include <cstdlib>
#include <chrono>
#include <filesystem>
#include <functional>
#include <fstream>
#include <mutex>
#include <thread>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;
namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

constexpr const char *kProgram = R"(
struct point { int x; int y; };
struct point grid[4] = {{1, 2}, {3, 4}, {5, 6}, {7, 8}};
__attribute__((noinline)) int sum_points(struct point *pts, int n) {
  int total_sum = 0;
  for (int i = 0; i < n; i++) total_sum += pts[i].x * pts[i].y;
  return total_sum;
}
int main(int argc, char **argv) { (void)argv; return sum_points(grid, argc & 3); }
)";

std::string ReadAll(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

bool Shell(const std::string &cmd) { return std::system((cmd + " >/dev/null 2>&1").c_str()) == 0; }

// The build ID of an ELF, as the loader reads it.
std::string BuildId(const fs::path &p) { return loader::load_file(p).build_id; }

class DebugFilesTest : public ::testing::Test {
 protected:
  // prog.full (with DWARF), prog.debug (objcopy --only-keep-debug), prog
  // (every symbol stripped, a .gnu_debuglink to prog.debug), and other.debug
  // (another build's: the same program with a different constant).
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    dir_ = testing::scratch_dir("debug-files");
    const fs::path full = dir_ / "build" / "prog.full";
    fs::create_directories(full.parent_path());
    const std::string flags = "-g -O0 -fno-pie -no-pie -Wl,--build-id=sha1";
    if (!testing::compile(REVKIT_TEST_CC, kProgram, flags, full)) return;
    std::string other_src = kProgram;
    other_src.replace(other_src.find("{7, 8}"), 6, "{7, 9}");
    const fs::path other = dir_ / "build" / "other.full";
    if (!testing::compile(REVKIT_TEST_CC, other_src, flags, other)) return;
    const fs::path b = dir_ / "build";
    ok_ = Shell("objcopy --only-keep-debug " + full.string() + " " + (b / "prog.debug").string()) &&
          Shell("objcopy --strip-all " + full.string() + " " + (b / "prog").string()) &&
          Shell("cd " + b.string() + " && objcopy --add-gnu-debuglink=prog.debug prog") &&
          Shell("objcopy --only-keep-debug " + other.string() + " " + (b / "other.debug").string());
    if (ok_) build_id_ = BuildId(b / "prog");
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!ok_ || build_id_.empty()) GTEST_SKIP() << "no C compiler or objcopy, or no build ID";
    unsetenv("DEBUGINFOD_URLS");
  }

  static fs::path Build(const std::string &name) { return dir_ / "build" / name; }

  // The stripped binary alone (or with its debug file beside it) in a
  // directory of its own.
  fs::path Place(const std::string &name, bool with_debug) {
    const fs::path d = dir_ / name;
    fs::remove_all(d);
    fs::create_directories(d);
    fs::copy_file(Build("prog"), d / "prog");
    if (with_debug) fs::copy_file(Build("prog.debug"), d / "prog.debug");
    return d / "prog";
  }

  std::unique_ptr<api::Backend> Make(const fs::path &project_dir) {
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.project_dir = project_dir.string();
    o.param_id = inputs::ParamIdMode::off;
    return MakeImageBackend(o);
  }

  std::string Import(api::Backend &b, const fs::path &file, const std::string &name = "prog") {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(file.string());
    req.set_name(name);
    pb::ImportProgramResponse resp;
    auto st = b.ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  std::uint64_t Symbol(api::Backend &b, const std::string &id, const std::string &name) {
    pb::ListSymbolsRequest req;
    req.set_program_id(id);
    req.set_name_equals(name);
    pb::ListSymbolsResponse resp;
    EXPECT_TRUE(b.ListSymbols(ctx_, req, resp).ok());
    return resp.symbols_size() ? resp.symbols(0).address().offset() : 0;
  }

  std::string Decompiled(api::Backend &b, const std::string &id, std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(id);
    req.mutable_function()->set_offset(entry);
    req.mutable_options()->set_include_text(true);
    pb::DecompileResponse resp;
    auto st = b.Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.function().text();
  }

  pb::ProgramSummary Summary(api::Backend &b, const std::string &id) {
    pb::GetProgramSummaryRequest req;
    req.set_program_id(id);
    pb::GetProgramSummaryResponse resp;
    EXPECT_TRUE(b.GetProgramSummary(ctx_, req, resp).ok());
    return resp.summary();
  }

  api::Status Load(api::Backend &b, const std::string &id, pb::LoadDebugFileRequest req, pb::LoadDebugFileResponse &resp) {
    req.set_program_id(id);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    return b.LoadDebugFile(ctx_, req, resp);
  }
  static pb::LoadDebugFileRequest ByPath(const fs::path &p, bool force = false) {
    pb::LoadDebugFileRequest r;
    r.set_path(p.string());
    r.set_force(force);
    return r;
  }
  static pb::LoadDebugFileRequest BySearch() {
    pb::LoadDebugFileRequest r;
    r.set_search(true);
    return r;
  }

  api::Status Settings(api::Backend &b, const std::function<void(pb::SymbolSettings &)> &edit) {
    pb::GetSymbolSettingsResponse now;
    EXPECT_TRUE(b.GetSymbolSettings(ctx_, {}, now).ok());
    pb::SetSymbolSettingsRequest req;
    *req.mutable_settings() = now.settings();
    edit(*req.mutable_settings());
    pb::SetSymbolSettingsResponse resp;
    return b.SetSymbolSettings(ctx_, req, resp);
  }

  static inline fs::path dir_;
  static inline bool ok_ = false;
  static inline std::string build_id_;
  CallContext ctx_;
};

TEST_F(DebugFilesTest, ReadsTheDebuglinkAndChecksItsCrc) {
  const loader::Image image = loader::load_file(Build("prog"));
  auto link = ReadDebugLink(image);
  ASSERT_TRUE(link);
  EXPECT_EQ(link->name, "prog.debug");
  const std::string debug = ReadAll(Build("prog.debug"));
  EXPECT_EQ(link->crc, DebugLinkCrc(std::as_bytes(std::span(debug.data(), debug.size()))));
  EXPECT_FALSE(ReadDebugLink(loader::load_file(Build("prog.full"))));

  DebugFileQuery q;
  q.link = link;
  q.binary = Build("prog");
  auto bytes = ReadDebugFileBytes(Build("prog.debug"), 1u << 30);
  ASSERT_TRUE(bytes);
  EXPECT_EQ(CheckDebugFile(bytes, q), "");  // by CRC (no build ID asked)
  q.build_id = build_id_;
  EXPECT_EQ(CheckDebugFile(bytes, q), "");
  EXPECT_NE(CheckDebugFile(ReadDebugFileBytes(Build("other.debug"), 1u << 30), q).find("another build"), std::string::npos);
  EXPECT_NE(CheckDebugFile(ReadDebugFileBytes(Build("prog"), 1u << 30), q).find(".debug_info"), std::string::npos);

  // Found beside the binary, in .debug/, in a build-ID tree, under
  // <dir>/<the binary's directory>; nothing found says where it looked.
  DebugFileSettings s;
  std::vector<std::string> log;
  auto f = FindDebugFile(s, q, false, false, log);
  ASSERT_TRUE(f) << ::testing::PrintToString(log);
  EXPECT_EQ(f->source, "beside the binary");
  const fs::path alone = Place("alone", false);
  q.binary = alone;
  log.clear();
  EXPECT_FALSE(FindDebugFile(s, q, false, false, log));
  EXPECT_FALSE(log.empty());
  fs::create_directories(alone.parent_path() / ".debug");
  fs::copy_file(Build("prog.debug"), alone.parent_path() / ".debug" / "prog.debug");
  f = FindDebugFile(s, q, false, false, log);
  ASSERT_TRUE(f);
  EXPECT_EQ(f->file, alone.parent_path() / ".debug" / "prog.debug");
  fs::remove_all(alone.parent_path() / ".debug");
  const fs::path tree = dir_ / "tree";
  fs::create_directories(tree / ".build-id" / build_id_.substr(0, 2));
  fs::copy_file(Build("prog.debug"), tree / ".build-id" / build_id_.substr(0, 2) / (build_id_.substr(2) + ".debug"),
                fs::copy_options::overwrite_existing);
  s.dirs = {tree.string()};
  f = FindDebugFile(s, q, false, false, log);
  ASSERT_TRUE(f);
  EXPECT_EQ(f->source, "directory " + tree.string());
  const fs::path mirror = dir_ / "mirror";
  fs::create_directories(mirror / alone.parent_path().relative_path());
  fs::copy_file(Build("prog.debug"), mirror / alone.parent_path().relative_path() / "prog.debug",
                fs::copy_options::overwrite_existing);
  s.dirs = {mirror.string()};
  f = FindDebugFile(s, q, false, false, log);
  ASSERT_TRUE(f);
  EXPECT_EQ(f->source, "directory " + mirror.string());
  // A damaged copy beside the binary: its CRC doesn't match, and it is said.
  {
    std::string damaged = debug;
    damaged[damaged.size() / 2] ^= 0x55;
    std::ofstream(alone.parent_path() / "prog.debug", std::ios::binary) << damaged;
  }
  q.build_id.clear();
  log.clear();
  s.dirs.clear();
  EXPECT_FALSE(FindDebugFile(s, q, false, false, log));
  EXPECT_NE(::testing::PrintToString(log).find("CRC-32"), std::string::npos) << ::testing::PrintToString(log);
}

TEST_F(DebugFilesTest, ImportReadsTheFileBesideTheBinaryAsItsOwnDwarf) {
  auto b = Make(dir_ / "projects-beside");
  const std::string id = Import(*b, Place("beside", true));
  const std::uint64_t sum = Symbol(*b, id, "sum_points");
  ASSERT_NE(sum, 0u) << "the debug file's names";
  const pb::ProgramSummary s = Summary(*b, id);
  EXPECT_EQ(s.build_id(), build_id_);
  EXPECT_EQ(s.debuglink(), "prog.debug");
  EXPECT_EQ(fs::path(s.debug_file()).filename(), "prog.debug");
  const std::string c = Decompiled(*b, id, sum);
  EXPECT_NE(c.find("total_sum"), std::string::npos) << c;  // a local the DWARF names

  // Without it, nothing of the sort.
  auto plain = Make(dir_ / "projects-plain");
  const std::string alone = Import(*plain, Place("alone2", false));
  EXPECT_EQ(Symbol(*plain, alone, "sum_points"), 0u);
  EXPECT_EQ(Summary(*plain, alone).debug_file(), "");
}

TEST_F(DebugFilesTest, LoadDebugFileByPathThenTheNextLoadReadsItFromTheCache) {
  const fs::path projects = dir_ / "projects-load";
  fs::remove_all(projects);
  std::string id;
  std::uint64_t sum = 0;
  {
    auto b = Make(projects);
    id = Import(*b, Place("load", false));
    ASSERT_EQ(Symbol(*b, id, "sum_points"), 0u);
    // Another build's file: refused, then forced with a warning.
    pb::LoadDebugFileResponse r;
    auto st = Load(*b, id, ByPath(Build("other.debug")), r);
    EXPECT_EQ(st.code, StatusCode::kFailedPrecondition) << st.message;
    EXPECT_NE(st.message.find("another build"), std::string::npos) << st.message;
    // Not an ELF with DWARF at all: refused even forced.
    EXPECT_EQ(Load(*b, id, ByPath(Build("prog"), true), r).code, StatusCode::kFailedPrecondition);
    // The right one.
    pb::LoadDebugFileResponse loaded;
    st = Load(*b, id, ByPath(Build("prog.debug")), loaded);
    ASSERT_TRUE(st.ok()) << st.message;
    EXPECT_TRUE(loaded.exact());
    EXPECT_TRUE(loaded.cached());
    EXPECT_EQ(loaded.build_id(), build_id_);
    EXPECT_GE(loaded.functions(), 2u);
    EXPECT_GE(loaded.variables(), 1u);
    EXPECT_FALSE(loaded.assertion_seqs().empty());
    sum = Symbol(*b, id, "sum_points");
    ASSERT_NE(sum, 0u);
    EXPECT_NE(Symbol(*b, id, "grid"), 0u);
    EXPECT_TRUE(fs::exists(projects / ".revkit" / "debuginfod" / build_id_ / "debuginfo"));
    // Undo takes the names back.
    pb::RetractAssertionsRequest undo;
    undo.set_program_id(id);
    undo.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    for (auto s : loaded.assertion_seqs()) undo.add_seqs(s);
    pb::RetractAssertionsResponse undone;
    ASSERT_TRUE(b->RetractAssertions(ctx_, undo, undone).ok());
    EXPECT_EQ(Symbol(*b, id, "sum_points"), 0u);
    ASSERT_TRUE(Load(*b, id, ByPath(Build("prog.debug")), loaded).ok());
  }
  // Reopened: the program reads the cached file at load, so the decompiler
  // has its variables too.
  auto b = Make(projects);
  EXPECT_EQ(Symbol(*b, id, "sum_points"), sum);
  EXPECT_EQ(fs::path(Summary(*b, id).debug_file()).filename(), "debuginfo");
  const std::string c = Decompiled(*b, id, sum);
  EXPECT_NE(c.find("total_sum"), std::string::npos) << c;
}

TEST_F(DebugFilesTest, DebuginfodOnlyWhenOnHttpsOnlyAndNoRedirectToAnotherHost) {
  const std::string debug = ReadAll(Build("prog.debug"));
  const std::string other = ReadAll(Build("other.debug"));
  httplib::Server server, elsewhere;
  std::mutex mu;
  std::vector<std::string> asked;
  std::string mode = "serve";
  int other_port = 0;
  server.Get(R"(/(.*))", [&](const httplib::Request &req, httplib::Response &res) {
    std::lock_guard lock(mu);
    asked.push_back(req.path);
    if (req.path == "/moved/buildid/" + build_id_ + "/debuginfo") {
      res.set_content(debug, "application/octet-stream");
    } else if (req.path == "/buildid/" + build_id_ + "/debuginfo") {
      if (mode == "serve") res.set_content(debug, "application/octet-stream");
      else if (mode == "wrong") res.set_content(other, "application/octet-stream");
      else if (mode == "same-host") res.set_redirect("/moved/buildid/" + build_id_ + "/debuginfo");
      else res.set_redirect("http://127.0.0.1:" + std::to_string(other_port) + "/buildid/" + build_id_ + "/debuginfo");
    } else {
      res.status = 404;
    }
  });
  bool elsewhere_asked = false;
  elsewhere.Get(R"(/(.*))", [&](const httplib::Request &, httplib::Response &res) {
    std::lock_guard lock(mu);
    elsewhere_asked = true;
    res.set_content(debug, "application/octet-stream");
  });
  const int port = server.bind_to_any_port("127.0.0.1");
  other_port = elsewhere.bind_to_any_port("127.0.0.1");
  ASSERT_GT(port, 0);
  ASSERT_GT(other_port, 0);
  std::thread t([&] { server.listen_after_bind(); });
  std::thread t2([&] { elsewhere.listen_after_bind(); });
  const std::string url = "http://127.0.0.1:" + std::to_string(port);

  setenv("DEBUGINFOD_URLS", (url + " https://debuginfod.invalid").c_str(), 1);
  const fs::path projects = dir_ / "projects-debuginfod";
  fs::remove_all(projects);
  auto b = Make(projects);
  const std::string id = Import(*b, Place("fetch", false));
  auto count = [&] {
    std::lock_guard lock(mu);
    return asked.size();
  };
  // DEBUGINFOD_URLS is a suggestion only: off by default, nothing asked.
  pb::GetSymbolSettingsResponse got;
  ASSERT_TRUE(b->GetSymbolSettings(ctx_, {}, got).ok());
  EXPECT_FALSE(got.settings().debuginfod());
  EXPECT_EQ(got.settings().debuginfod_urls_size(), 0);
  ASSERT_EQ(got.suggested_debuginfod_urls_size(), 2);
  EXPECT_EQ(got.suggested_debuginfod_urls(0), url);
  EXPECT_EQ(got.settings().debug_cache_dir(), (projects / ".revkit" / "debuginfod").string());
  pb::LoadDebugFileResponse r;
  EXPECT_EQ(Load(*b, id, BySearch(), r).code, StatusCode::kNotFound);
  EXPECT_EQ(count(), 0u);
  // An http server is refused unless http is allowed.
  auto st = Settings(*b, [&](pb::SymbolSettings &s) {
    s.set_debuginfod(true);
    s.add_debuginfod_urls(url);
  });
  EXPECT_EQ(st.code, StatusCode::kInvalidArgument) << st.message;
  // Listed but off: still nothing asked.
  ASSERT_TRUE(Settings(*b, [&](pb::SymbolSettings &s) {
                s.add_debuginfod_urls(url);
                s.set_debuginfod_allow_http(true);
              }).ok());
  EXPECT_EQ(Load(*b, id, BySearch(), r).code, StatusCode::kNotFound);
  EXPECT_EQ(count(), 0u);
  ASSERT_TRUE(Settings(*b, [&](pb::SymbolSettings &s) { s.set_debuginfod(true); }).ok());

  // Another build's file is refused and not kept.
  mode = "wrong";
  st = Load(*b, id, BySearch(), r);
  EXPECT_EQ(st.code, StatusCode::kNotFound) << st.message;
  EXPECT_NE(st.message.find("another build"), std::string::npos) << st.message;
  EXPECT_FALSE(fs::exists(projects / ".revkit" / "debuginfod" / build_id_));
  // A redirect to another host isn't followed.
  mode = "elsewhere";
  st = Load(*b, id, BySearch(), r);
  EXPECT_EQ(st.code, StatusCode::kNotFound);
  EXPECT_NE(st.message.find("another host"), std::string::npos) << st.message;
  EXPECT_FALSE(elsewhere_asked);
  // Larger than allowed.
  mode = "serve";
  ASSERT_TRUE(Settings(*b, [&](pb::SymbolSettings &s) { s.set_debug_file_max_bytes(1024); }).ok());
  st = Load(*b, id, BySearch(), r);
  EXPECT_NE(st.message.find("larger than allowed"), std::string::npos) << st.message;
  ASSERT_TRUE(Settings(*b, [&](pb::SymbolSettings &s) { s.set_debug_file_max_bytes(0); }).ok());
  // The same host's redirect is followed; the file is kept by build ID.
  mode = "same-host";
  pb::LoadDebugFileResponse fetched;
  st = Load(*b, id, BySearch(), fetched);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_TRUE(fetched.exact());
  EXPECT_EQ(fetched.source(), "debuginfod " + url);
  EXPECT_EQ(fetched.debug_file(), (projects / ".revkit" / "debuginfod" / build_id_ / "debuginfo").string());
  EXPECT_NE(Symbol(*b, id, "sum_points"), 0u);
  // Again: from the cache, without asking.
  const std::size_t before = count();
  pb::LoadDebugFileResponse again;
  ASSERT_TRUE(Load(*b, id, BySearch(), again).ok());
  EXPECT_EQ(again.source(), "cache");
  EXPECT_EQ(count(), before);

  server.stop();
  elsewhere.stop();
  t.join();
  t2.join();
  unsetenv("DEBUGINFOD_URLS");
}

TEST_F(DebugFilesTest, TheCacheKeepsToItsSize) {
  DebugFileSettings s;
  s.cache_dir = (dir_ / "cache-trim").string();
  const std::string debug = ReadAll(Build("prog.debug"));
  const loader::Bytes bytes(reinterpret_cast<const std::byte *>(debug.data()),
                            reinterpret_cast<const std::byte *>(debug.data()) + debug.size());
  s.cache_max_bytes = bytes.size() * 2 + 10;
  std::string error;
  ASSERT_TRUE(CacheDebugFile(s, "aa01", bytes, &error)) << error;
  ASSERT_TRUE(CacheDebugFile(s, "aa02", bytes, &error)) << error;
  const auto now = fs::file_time_type::clock::now();
  fs::last_write_time(fs::path(s.cache_dir) / "aa01" / "debuginfo", now - std::chrono::hours(2));
  fs::last_write_time(fs::path(s.cache_dir) / "aa02" / "debuginfo", now - std::chrono::hours(1));
  ASSERT_TRUE(CacheDebugFile(s, "aa03", bytes, &error)) << error;  // the oldest goes
  EXPECT_FALSE(fs::exists(fs::path(s.cache_dir) / "aa01" / "debuginfo"));
  EXPECT_TRUE(fs::exists(fs::path(s.cache_dir) / "aa02" / "debuginfo"));
  EXPECT_TRUE(fs::exists(fs::path(s.cache_dir) / "aa03" / "debuginfo"));
  EXPECT_FALSE(CacheDebugFile(s, "../x", bytes, &error));
  s.cache_max_bytes = 10;
  EXPECT_FALSE(CacheDebugFile(s, "aa04", bytes, &error));
  EXPECT_EQ(CheckDebuginfodUrl("https://debuginfod.example.org/x", false), "");
  EXPECT_NE(CheckDebuginfodUrl("http://debuginfod.example.org", false), "");
  EXPECT_EQ(CheckDebuginfodUrl("http://debuginfod.example.org", true), "");
  EXPECT_NE(CheckDebuginfodUrl("https://user:pw@host", false), "");
  EXPECT_NE(CheckDebuginfodUrl("ftp://host", true), "");
}

}  // namespace
}  // namespace revkit::backend
