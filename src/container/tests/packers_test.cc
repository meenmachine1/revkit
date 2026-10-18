// The packers' containers (docs/filesystems.md, "Packed executables"):
// Electron asar, PyInstaller's CArchive and PYZ, Node SEA, pkg, nexe, Bun,
// a zip appended to an executable, Lua chunks carved out of firmware.
// Real files where the tool is here (PyInstaller in revkit's bytecode
// venv, node --experimental-sea-config, lupa's interpreters), and the
// formats as tests/data/bytecode/make_packed.py writes them otherwise.
#include "../bytecode.hh"
#include "fixtures.hh"

#include <cstdlib>
#include <map>

namespace revkit::container {
namespace {

using namespace testing;

std::string bytecode_python() {
  if (const char *p = std::getenv("RK_BYTECODE_PYTHON"); p && *p) return p;
  const char *home = std::getenv("HOME");
  const std::string venv = std::string(home ? home : "") + "/.cache/revkit/bytecode-venv/bin/python";
  return fs::exists(venv) ? venv : "";
}

std::shared_ptr<Session> open_file(const fs::path &p) {
  return Session::open(open_host_file(p.string()), p.filename().string(), Limits{});
}

// The synthetic fixtures, made once.
const fs::path &packed() {
  static TempDir dir;
  static bool made = [] {
    const std::string blob = (dir / "sea-prep.blob").string();
    bool sea = false;
    if (have_tool("node")) {
      std::ofstream(dir / "main.js") << "console.log(require('node:sea').getAsset('a.txt', 'utf8'))\n";
      std::ofstream(dir / "a.txt") << "asset text\n";
      std::ofstream(dir / "sea.json") << R"({"main":"main.js","output":"sea-prep.blob","useCodeCache":true,)"
                                         R"("assets":{"a.txt":"a.txt"},"execArgv":["--no-warnings"]})";
      sea = sh("cd " + dir.path().string() + " && node --experimental-sea-config sea.json");
    }
    return sh("python3 -I " REVKIT_SOURCE_DIR "/tests/data/bytecode/make_packed.py /bin/true " + dir.path().string() +
              (sea ? " --sea-blob " + blob : std::string()));
  }();
  EXPECT_TRUE(made);
  return dir.path();
}

std::string read(Session &s, const std::string &path) { return read_all(*s.open_file(path)); }

TEST(ContainerPackers, AsarWithUnpackedFiles) {
  TempDir t;
  // An asar as @electron/asar writes it: the size pickle, the header
  // pickle with its JSON, then the files.
  const std::string json =
      R"({"files":{"main.js":{"size":12,"offset":"0"},"lib":{"files":{"data.bin":{"size":3,"offset":"12",)"
      R"("executable":true},"native.node":{"size":5,"unpacked":true},"alias.js":{"link":"main.js"}}}}})";
  std::string pickle;
  auto u32 = [](std::uint32_t v) { return std::string(reinterpret_cast<const char *>(&v), 4); };
  std::string padded = json + std::string((4 - json.size() % 4) % 4, '\0');
  pickle = u32(static_cast<std::uint32_t>(4 + padded.size())) + u32(static_cast<std::uint32_t>(json.size())) + padded;
  const std::string asar = u32(4) + u32(static_cast<std::uint32_t>(pickle.size())) + pickle + "console.log;abc";
  fs::create_directories(t / "resources/app.asar.unpacked/lib");
  std::ofstream(t / "resources/app.asar", std::ios::binary) << asar;
  std::ofstream(t / "resources/app.asar.unpacked/lib/native.node") << "ELF!!";
  auto s = open_file(t / "resources/app.asar");
  EXPECT_EQ(s->root_format(), "asar");
  EXPECT_EQ(s->root()->description(), "Electron asar archive, 3 files (1 unpacked), 1 link");
  EXPECT_EQ(read(*s, "/main.js"), "console.log;");
  EXPECT_EQ(read(*s, "/lib/data.bin"), "abc");
  auto main = s->locate("/main.js", false);
  EXPECT_EQ(main.fs->entry(main.entry).content_kind, "js-source");
  EXPECT_EQ(read(*s, "/lib/alias.js"), "console.log;");  // links are from the archive's root
  EXPECT_THROW(s->open_file("/lib/native.node"), Error);  // the folder beside it isn't in this session
  // Opened from the folder holding both, the unpacked file reads.
  auto d = Session::open_directory((t / "resources").string(), Limits{});
  EXPECT_EQ(read(*d, "/app.asar!/lib/native.node"), "ELF!!");
  EXPECT_EQ(read(*d, "/app.asar!/main.js"), "console.log;");
  // Broken headers are refused, not misread.
  std::string bad = asar;
  bad[8] = 'x';
  std::ofstream(t / "bad.asar", std::ios::binary) << bad;
  EXPECT_THROW(open_file(t / "bad.asar"), Error);
}

TEST(ContainerPackers, PyInstallerFromItsFormat) {
  auto s = open_file(packed() / "pyinstaller-appended");
  EXPECT_EQ(s->root_format(), "pyinstaller");
  EXPECT_NE(s->root()->description().find("PyInstaller archive, Python 3."), std::string::npos)
      << s->root()->description();
  // Scripts and modules come out as .pyc files: this Python's magic and a
  // 16-byte header in front of the code, which marshal reads back.
  for (const char *p : {"/main.pyc", "/pyiboot01_bootstrap.pyc", "/oldmod.pyc", "/PYZ.pyz!/pkg/util.pyc",
                        "/PYZ.pyz!/pkg/__init__.pyc", "/PYZ.pyz!/json_helper.pyc"}) {
    const std::string pyc = read(*s, p);
    std::vector<std::byte> b(pyc.size());
    std::memcpy(b.data(), pyc.data(), pyc.size());
    Guess g = guess(b, b.size());
    EXPECT_EQ(g.format, "pyc") << p << ": " << g.description;
    TempDir t;
    std::ofstream(t / "x.pyc", std::ios::binary) << pyc;
    EXPECT_TRUE(sh("python3 -I -c \"import marshal, importlib.util as u; d = open('" + (t / "x.pyc").string() +
                   "', 'rb').read(); assert d[:4] == u.MAGIC_NUMBER; marshal.loads(d[16:])\""))
        << p;
    auto n = s->locate(p, false);
    EXPECT_EQ(n.fs->entry(n.entry).content_kind.substr(0, 4), "pyc:") << p;
  }
  // The module that kept its own header isn't given a second one.
  EXPECT_EQ(read(*s, "/oldmod.pyc").size(), s->locate("/oldmod.pyc", false).fs->entry(
                                                 s->locate("/oldmod.pyc", false).entry).size);
  EXPECT_EQ(read(*s, "/data/conf.txt"), "conf\n");
  auto link = s->locate("/libbar.so", false);
  EXPECT_EQ(link.fs->entry(link.entry).kind, Kind::symlink);
  EXPECT_EQ(s->open_file("/libbar.so")->size(), 4096u);
  // The bootloader stays a program: its guess is ELF, with the payload.
  TempDir t;
  fs::copy_file(packed() / "pyinstaller-appended", t / "app");
  auto d = Session::open_directory(t.path().string(), Limits{});
  Guess g = d->describe(d->locate("/app", false), {}, Session::Payloads::cheap);
  EXPECT_EQ(g.kind, "elf");
  EXPECT_EQ(g.payload, "pyinstaller");
  EXPECT_EQ(d->container_format(d->locate("/app", false)), "");  // a batch import still imports it
}

TEST(ContainerPackers, PyInstallerReal) {
  const std::string python = bytecode_python();
  if (python.empty()) GTEST_SKIP() << "no bytecode venv (~/.cache/revkit/bytecode-venv with pyinstaller)";
  const fs::path pyi = fs::path(python).parent_path() / "pyinstaller";
  if (!fs::exists(pyi)) GTEST_SKIP() << "no pyinstaller in " << python;
  TempDir t;
  std::ofstream(t / "hello.py") << "import json\ndef add(a, b):\n    return a + b\nprint(json.dumps(add(1, 2)))\n";
  ASSERT_TRUE(sh("cd " + t.path().string() + " && " + pyi.string() +
                 " --onefile --noconfirm --log-level ERROR --distpath dist --workpath build --specpath . hello.py"));
  auto s = open_file(t / "dist/hello");
  EXPECT_EQ(s->root_format(), "pyinstaller");
  const std::string pyc = read(*s, "/hello.pyc");
  std::ofstream(t / "hello.pyc", std::ios::binary) << pyc;
  // The script runs as extracted, under the interpreter that built it.
  FILE *f = popen((python + " -I " + (t / "hello.pyc").string()).c_str(), "r");
  char buf[64] = {};
  ASSERT_TRUE(f && fgets(buf, sizeof buf, f));
  pclose(f);
  EXPECT_EQ(std::string(buf), "3\n");
  // Its modules, in the PYZ.
  auto json = s->locate("/PYZ.pyz!/json/__init__.pyc", false);
  EXPECT_EQ(json.fs->entry(json.entry).content_kind.substr(0, 4), "pyc:");
}

TEST(ContainerPackers, NodeSea) {
  if (!fs::exists(packed() / "sea-note.bin")) GTEST_SKIP() << "no node with --experimental-sea-config";
  if (!have_tool("objcopy")) GTEST_SKIP() << "no objcopy";
  TempDir t;
  // The blob as postject injects it into an ELF: a NODE_SEA_BLOB note.
  ASSERT_TRUE(sh("objcopy --add-section .note.node.sea=" + (packed() / "sea-note.bin").string() + " /bin/true " +
                 (t / "app").string()));
  auto s = open_file(t / "app");
  EXPECT_EQ(s->root_format(), "node-sea");
  EXPECT_NE(s->root()->description().find("main main.js"), std::string::npos) << s->root()->description();
  EXPECT_NE(s->root()->description().find("execArgv --no-warnings"), std::string::npos);
  EXPECT_EQ(read(*s, "/main.js"), "console.log(require('node:sea').getAsset('a.txt', 'utf8'))\n");
  EXPECT_EQ(read(*s, "/assets/a.txt"), "asset text\n");
  auto cache = s->locate("/main.js.cache", false);
  EXPECT_EQ(cache.fs->entry(cache.entry).content_kind, "v8-cache");
}

TEST(ContainerPackers, PkgNexeBunAndAppendedZip) {
  {
    for (const char *name : {"pkg", "pkg-gzip"}) {
      auto s = open_file(packed() / name);
      EXPECT_EQ(s->root_format(), "pkg") << name;
      EXPECT_EQ(read(*s, "/snapshot/app/index.js"), "console.log('pkg main')\n") << name;
      auto blob = s->locate("/snapshot/app/lib.js.jsc", false);
      EXPECT_EQ(blob.fs->entry(blob.entry).content_kind, "v8-cache");
      EXPECT_NE(s->root()->description().find("entry /snapshot/app/index.js"), std::string::npos);
    }
  }
  {
    auto s = open_file(packed() / "nexe4");
    EXPECT_EQ(s->root_format(), "nexe");
    EXPECT_EQ(read(*s, "/resources/index.js"), "console.log('nexe4')\n");
    EXPECT_EQ(read(*s, "/resources/data/a.txt"), "text\n");
    auto v5 = open_file(packed() / "nexe5");
    EXPECT_EQ(read(*v5, "/resources.zip!/snapshot/app/index.js"), "console.log('nexe5')\n");
  }
  {
    auto s = open_file(packed() / "bun");
    EXPECT_EQ(s->root_format(), "bun");
    EXPECT_EQ(read(*s, "/app.js"), "console.log('bun')\n");
    EXPECT_EQ(read(*s, "/asset.txt"), "asset\n");
    EXPECT_NE(s->root()->description().find("entry app.js"), std::string::npos);
  }
  {
    auto s = open_file(packed() / "zip-appended");
    EXPECT_EQ(s->root_format(), "zip");
    EXPECT_EQ(read(*s, "/readme.txt"), "py2exe-style library\n");
  }
  // A plain executable carries nothing.
  EXPECT_EQ(identify(*open_host_file("/bin/true")), "");
}

TEST(ContainerPackers, LuaChunksInFirmware) {
  auto s = open_file(packed() / "lua-firmware");
  EXPECT_EQ(s->root_format(), "lua-chunks");
  // The decoys ("\x1bLuaT" and "\x1bLJ" with no chunk after them) are skipped.
  ASSERT_EQ(s->root()->entries().size(), 2u);
  const Entry &e = s->root()->entry(1);
  EXPECT_EQ(e.content_kind, "lua:5.4");
  std::ifstream index(packed() / "index.jsonl");
  std::string line, want;
  while (std::getline(index, line))
    if (line.find("lua-firmware") != std::string::npos) want = line;
  char name[64];
  std::snprintf(name, sizeof name, "lua-5.4@0x%llx.luac", static_cast<unsigned long long>(e.loc0));
  EXPECT_EQ(e.name, name);
  EXPECT_NE(want.find("\"offset\": " + std::to_string(e.loc0)), std::string::npos) << want;
  EXPECT_NE(want.find("\"size\": " + std::to_string(e.size)), std::string::npos) << want;
  // A chunk by itself is bytecode, not a container of one.
  auto chunk = s->open_file("/" + e.name);
  EXPECT_EQ(identify(*chunk), "");
}

TEST(ContainerPackers, LuaChunksFromLupaCarved) {
  const std::string python = bytecode_python();
  if (python.empty()) GTEST_SKIP() << "no Python with lupa";
  TempDir t;
  const int rc = std::system((python + " -I " REVKIT_SOURCE_DIR "/tests/data/bytecode/make_lua_chunks.py " +
                              t.path().string() + " >/dev/null 2>&1")
                                 .c_str());
  if (WIFEXITED(rc) && WEXITSTATUS(rc) == 77) GTEST_SKIP() << "lupa is not installed";
  ASSERT_EQ(rc, 0);
  // Every chunk between noise, at known offsets.
  std::string blob(3000, '\x5a');
  std::map<std::uint64_t, std::pair<std::string, std::uint64_t>> want;
  for (const auto &f : fs::directory_iterator(t.path())) {
    if (f.path().extension() != ".luac" || f.path().filename().string().find("lua-5.5") == 0) continue;
    const std::string c = text(read_file(f.path()));
    want[blob.size()] = {f.path().stem().string(), c.size()};
    blob += c + std::string(777, '\x1b');
  }
  std::ofstream(t / "fw.bin", std::ios::binary) << blob;
  auto s = open_file(t / "fw.bin");
  ASSERT_EQ(s->root_format(), "lua-chunks");
  std::map<std::uint64_t, std::uint64_t> got;
  for (const Entry &e : s->root()->entries())
    if (e.kind == Kind::file) got[e.loc0] = e.size;
  ASSERT_EQ(got.size(), want.size());
  for (const auto &[off, w] : want) EXPECT_EQ(got[off], w.second) << w.first << " at " << off;
}

TEST(ContainerPackers, HostileInputs) {
  // Each fixture cut short and with bytes flipped: errors or fewer
  // entries, never a crash or a read outside the file.
  for (const char *name : {"pyinstaller-appended", "pkg", "nexe4", "bun", "lua-firmware"}) {
    const auto whole = read_file(packed() / name);
    for (std::size_t cut : {whole.size() - 1, whole.size() - 40, whole.size() - 200, whole.size() / 2}) {
      std::vector<std::byte> b(whole.begin(), whole.begin() + static_cast<std::ptrdiff_t>(cut));
      try {
        auto s = Session::open(memory_source(b), name, Limits{});
        for (std::uint32_t i = 0; i < s->root()->entries().size(); ++i)
          if (s->root()->entry(i).kind == Kind::file) try {
              (void)s->open_file(s->root()->path_of(i));
            } catch (const Error &) {
            }
      } catch (const Error &) {
      }
    }
    std::srand(7);
    for (int round = 0; round < 100; ++round) {
      auto b = whole;
      for (int k = 0; k < 8; ++k) b[static_cast<std::size_t>(std::rand()) % b.size()] = static_cast<std::byte>(std::rand());
      try {
        auto s = Session::open(memory_source(b), name, Limits{});
        for (std::uint32_t i = 0; i < s->root()->entries().size(); ++i)
          if (s->root()->entry(i).kind == Kind::file) try {
              (void)s->open_file(s->root()->path_of(i));
            } catch (const Error &) {
            }
      } catch (const Error &) {
      }
    }
  }
}

}  // namespace
}  // namespace revkit::container
