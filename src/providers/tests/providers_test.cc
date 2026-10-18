// External decompiler providers (docs/providers.md): the mechanism with a
// fake provider (tests/fake_provider.sh): its results, the cache, the
// limits (time, output, files), crashes and failures, a missing tool, and
// what the sandbox refuses; input detection; then each real tool that is
// installed, on fixtures built at test time (dotnet, javac, py_compile),
// or skipped with a message.
#include "revkit/providers/providers.h"

#include <gtest/gtest.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <thread>

namespace revkit::providers {
namespace {

namespace fs = std::filesystem;

const fs::path kFake = fs::path(REVKIT_SOURCE_DIR) / "src" / "providers" / "tests" / "fake_provider.sh";

std::vector<std::byte> bytes_of(std::string_view s) {
  std::vector<std::byte> b(s.size());
  std::memcpy(b.data(), s.data(), s.size());
  return b;
}

std::vector<std::byte> read_all(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return bytes_of(s);
}

std::string read_text(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

int sh(const std::string &cmd) { return std::system(cmd.c_str()); }

class TempDir {
 public:
  TempDir() {
    std::string t = (fs::temp_directory_path() / "rk-providers-test-XXXXXX").string();
    path = ::mkdtemp(t.data());
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path, ec);
  }
  fs::path path;
};

Definition fake_definition(Shape shape = Shape::tree) {
  Definition d = make_definition("fake", "Fake decompiler", "fake_provider.sh", "AGPL-3.0", "", {"fake"}, Runtime::native, shape, "java");
  d.path_names = {"fake_provider.sh"};
  d.command = {"{tool}", "{in}", "{out}"};
  d.version_command = {"{tool}", "--version"};
  d.stdout_extension = ".py";
  return d;
}

const InputKind kFakeKind{"fake", "", "fake bytecode"};

Settings fake_settings(Shape shape = Shape::tree) {
  Settings s;
  s.extra = {fake_definition(shape)};
  s.providers = {{"fake", kFake.string(), false}};
  s.limits.timeout = std::chrono::seconds(20);
  s.limits.memory_bytes = 1ull << 30;
  return s;
}

class ProvidersTest : public ::testing::Test {
 protected:
  void SetUp() override {
    if (find_helper().empty()) GTEST_SKIP() << "rk-sandbox isn't built";
    const SandboxSupport sup = probe_support();
    if (sup.landlock_abi == 0) GTEST_SKIP() << "this kernel has no Landlock: " << sup.describe();
  }
  TempDir tmp;
};

TEST_F(ProvidersTest, AToolsVersionAndATreeOfFiles) {
  Service svc(fake_settings(), tmp.path / "cache");
  const ToolStatus t = svc.tool("fake");
  ASSERT_TRUE(t.available) << t.reason;
  EXPECT_EQ(t.version, "1.2.3");
  EXPECT_EQ(t.found_by, "configured");
  const auto in = bytes_of("mode=ok\n");
  const Result r = svc.decompile(in, "Tiny.class", kFakeKind, "", false);
  ASSERT_EQ(r.status, RunStatus::ok) << r.detail << "\n" << r.stderr_tail;
  EXPECT_FALSE(r.cached);
  ASSERT_EQ(r.files.size(), 2u);
  EXPECT_EQ(r.files[0].path, "notes.txt");
  EXPECT_EQ(r.files[1].path, "pkg/A.java");
  EXPECT_EQ(r.files[1].language, "java");
  EXPECT_EQ(r.main_file, "pkg/A.java");
  EXPECT_EQ(r.sha256, sha256_hex(in));
  EXPECT_NE(r.stderr_tail.find("decompiled"), std::string::npos);
  EXPECT_NE(r.sandbox.find("Landlock"), std::string::npos) << r.sandbox;
  std::uint64_t size = 0;
  EXPECT_EQ(svc.read_file(r, "pkg/A.java", 0, 1 << 20, size), "class A { int f() { return 1; } }\n");
  EXPECT_EQ(size, 34u);
  EXPECT_EQ(svc.read_file(r, "pkg/A.java", 6, 1, size), "A");
  EXPECT_THROW(svc.read_file(r, "../result", 0, 10, size), Error);
  EXPECT_THROW(svc.read_file(r, "pkg/B.java", 0, 10, size), Error);
}

TEST_F(ProvidersTest, TheCacheAnswersTheSameInputAgain) {
  Service svc(fake_settings(), tmp.path / "cache");
  const auto in = bytes_of("mode=ok\nfirst\n");
  const Result a = svc.decompile(in, "x.class", kFakeKind, "fake", false);
  ASSERT_EQ(a.status, RunStatus::ok) << a.detail;
  const Result b = svc.decompile(in, "x.class", kFakeKind, "fake", false);
  EXPECT_TRUE(b.cached);
  EXPECT_EQ(b.files.size(), a.files.size());
  EXPECT_EQ(b.dir, a.dir);
  // cached() finds it without running; another daemon over the same
  // directory too.
  ASSERT_TRUE(svc.cached(a.sha256, kFakeKind, "fake"));
  Service other(fake_settings(), tmp.path / "cache");
  auto c = other.cached(a.sha256, kFakeKind, "");
  ASSERT_TRUE(c);
  EXPECT_EQ(c->main_file, "pkg/A.java");
  // refresh runs it again; other bytes are another entry.
  const Result d = svc.decompile(in, "x.class", kFakeKind, "fake", true);
  EXPECT_FALSE(d.cached);
  EXPECT_FALSE(svc.cached(sha256_hex(bytes_of("mode=ok\nsecond\n")), kFakeKind, "fake"));
  // A failure is kept too (the same tool fails the same way).
  const Result f1 = svc.decompile(bytes_of("mode=fail\n"), "y", kFakeKind, "fake", false);
  EXPECT_EQ(f1.status, RunStatus::failed);
  const Result f2 = svc.decompile(bytes_of("mode=fail\n"), "y", kFakeKind, "fake", false);
  EXPECT_TRUE(f2.cached);
  EXPECT_EQ(f2.status, RunStatus::failed);
  EXPECT_NE(f2.stderr_tail.find("cannot decompile this"), std::string::npos);
}

TEST_F(ProvidersTest, OneFileFromStdout) {
  Service svc(fake_settings(Shape::file), tmp.path / "cache");
  const Result r = svc.decompile(bytes_of("mode=stdout\n"), "mod.pyc", kFakeKind, "fake", false);
  ASSERT_EQ(r.status, RunStatus::ok) << r.detail;
  ASSERT_EQ(r.files.size(), 1u);
  EXPECT_EQ(r.files[0].path, "mod.py");
  EXPECT_EQ(r.files[0].language, "python");
  std::uint64_t size = 0;
  EXPECT_EQ(svc.read_file(r, "mod.py", 0, 100, size), "def f(): return 1\n");
}

TEST_F(ProvidersTest, TheDeadlineKillsIt) {
  Settings s = fake_settings();
  s.limits.timeout = std::chrono::seconds(2);
  Service svc(s, tmp.path / "cache");
  const auto start = std::chrono::steady_clock::now();
  const Result r = svc.decompile(bytes_of("mode=sleep\n"), "x", kFakeKind, "fake", false);
  const double took = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
  EXPECT_EQ(r.status, RunStatus::timeout) << r.detail;
  EXPECT_LT(took, 10.0);
  EXPECT_NE(r.detail.find("killed after 2 s"), std::string::npos) << r.detail;
  // Not cached: a longer deadline may finish.
  EXPECT_FALSE(svc.cached(sha256_hex(bytes_of("mode=sleep\n")), kFakeKind, "fake"));
}

TEST_F(ProvidersTest, TheOutputCapStopsIt) {
  Settings s = fake_settings();
  s.limits.output_bytes = 1 << 20;
  Service svc(s, tmp.path / "cache");
  const Result r = svc.decompile(bytes_of("mode=big\n"), "x", kFakeKind, "fake", false);
  EXPECT_EQ(r.status, RunStatus::output_limit) << r.detail;
  EXPECT_TRUE(r.files.empty());
  Service svc_file(fake_settings(Shape::file), tmp.path / "cache2");
  Settings s2 = fake_settings(Shape::file);
  s2.limits.output_bytes = 1 << 20;
  svc_file.set_settings(s2);
  const Result r2 = svc_file.decompile(bytes_of("mode=bigstdout\n"), "x", kFakeKind, "fake", false);
  EXPECT_EQ(r2.status, RunStatus::output_limit) << r2.detail;
  // Too many files.
  Settings s3 = fake_settings();
  s3.limits.output_files = 100;
  Service svc_many(s3, tmp.path / "cache3");
  const Result r3 = svc_many.decompile(bytes_of("mode=many\n"), "x", kFakeKind, "fake", false);
  EXPECT_EQ(r3.status, RunStatus::output_limit) << r3.detail;
}

TEST_F(ProvidersTest, ACrashAFailureAndRunningOutOfMemory) {
  Service svc(fake_settings(), tmp.path / "cache");
  const Result c = svc.decompile(bytes_of("mode=crash\n"), "x", kFakeKind, "fake", false);
  EXPECT_EQ(c.status, RunStatus::crashed) << c.detail;
  EXPECT_EQ(c.detail, "SIGSEGV");
  const Result f = svc.decompile(bytes_of("mode=fail\n"), "x", kFakeKind, "fake", false);
  EXPECT_EQ(f.status, RunStatus::failed);
  EXPECT_EQ(f.detail, "exit status 3");
  const Result m = svc.decompile(bytes_of("mode=oom\n"), "x", kFakeKind, "fake", false);
  EXPECT_EQ(m.status, RunStatus::out_of_memory) << m.detail;
}

TEST_F(ProvidersTest, AMissingToolAndATurnedOffOne) {
  Settings s = fake_settings();
  Definition missing = fake_definition();
  missing.name = "missing";
  missing.path_names = {"no-such-decompiler-revkit"};
  missing.known = {"~/no/such/place/*/tool"};
  s.extra.push_back(missing);
  s.providers.push_back({"missing", "", false});
  Service svc(s, tmp.path / "cache");
  const ToolStatus t = svc.tool("missing");
  EXPECT_FALSE(t.available);
  EXPECT_NE(t.reason.find("not found"), std::string::npos) << t.reason;
  try {
    svc.decompile(bytes_of("mode=ok\n"), "x", kFakeKind, "missing", false);
    FAIL() << "expected an error";
  } catch (const Error &e) {
    EXPECT_EQ(e.code, Error::Code::failed_precondition);
  }
  // The default for the kind is the one that is there.
  EXPECT_EQ(svc.default_provider("fake"), "fake");
  // A configured path that isn't there.
  s.providers = {{"fake", "/no/such/fake_provider.sh", false}};
  svc.set_settings(s);
  EXPECT_FALSE(svc.tool("fake").available);
  // Turned off.
  s.providers = {{"fake", kFake.string(), true}};
  svc.set_settings(s);
  EXPECT_TRUE(svc.tool("fake").disabled);
  EXPECT_FALSE(svc.tool("fake").available);
  s.providers = {{"fake", kFake.string(), false}};
  s.enabled = false;
  svc.set_settings(s);
  EXPECT_FALSE(svc.tool("fake").available);
  EXPECT_THROW(svc.decompile(bytes_of("mode=ok\n"), "x", kFakeKind, "ilspy", false), Error);  // ILSpy doesn't take "fake"
}

TEST_F(ProvidersTest, TheSandboxRefuses) {
  TempDir outside;
  const fs::path secret = outside.path / "secret.txt";
  std::ofstream(secret) << "secret\n";
  Service svc(fake_settings(), tmp.path / "cache");
  const Result r = svc.decompile(bytes_of("mode=escape\n" + secret.string() + "\n"), "x", kFakeKind, "fake", false);
  ASSERT_EQ(r.status, RunStatus::ok) << r.detail << r.stderr_tail;
  std::uint64_t size = 0;
  const std::string report = svc.read_file(r, "report.txt", 0, 4096, size);
  for (const char *line : {"read-outside no", "list-outside no", "write-outside no", "write-input no", "read-etc yes",
                           "signal no"})
    EXPECT_NE(report.find(line), std::string::npos) << line << "\n" << report;
  if (report.find("tcp ") != std::string::npos) {
    EXPECT_NE(report.find("tcp no"), std::string::npos) << report;
    EXPECT_NE(report.find("unix no"), std::string::npos) << report;
  }
  EXPECT_FALSE(fs::exists(outside.path / "planted"));
  // The link and the pipe it made aren't part of the output.
  for (const OutputFile &f : r.files) EXPECT_TRUE(f.path == "report.txt") << f.path;
}

TEST_F(ProvidersTest, NothingOutlivesTheRun) {
  Service svc(fake_settings(), tmp.path / "cache");
  const Result r = svc.decompile(bytes_of("mode=linger\n"), "x", kFakeKind, "fake", false);
  ASSERT_EQ(r.status, RunStatus::ok) << r.detail;
  std::uint64_t size = 0;
  const int pid = std::atoi(svc.read_file(r, "child.pid", 0, 64, size).c_str());
  ASSERT_GT(pid, 0);
  bool gone = false;
  for (int i = 0; i < 100 && !gone; ++i) {
    const std::string cmd = read_text("/proc/" + std::to_string(pid) + "/cmdline");
    gone = cmd.find("sleep") == std::string::npos;
    if (!gone) std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  EXPECT_TRUE(gone) << "the run's child " << pid << " is still running";
}

TEST_F(ProvidersTest, ConcurrentRunsOfOneInputRunOnce) {
  Service svc(fake_settings(), tmp.path / "cache");
  const auto in = bytes_of("mode=ok\nconcurrent\n");
  std::vector<std::thread> threads;
  std::vector<Result> results(4);
  for (int i = 0; i < 4; ++i)
    threads.emplace_back([&, i] { results[i] = svc.decompile(in, "x", kFakeKind, "fake", false); });
  for (auto &t : threads) t.join();
  int ran = 0;
  for (const Result &r : results) {
    EXPECT_EQ(r.status, RunStatus::ok);
    ran += r.cached ? 0 : 1;
  }
  // The first ran; the others waited for it (or found it cached).
  EXPECT_GE(ran, 1);
  EXPECT_EQ(results[0].dir, results[3].dir);
}

TEST_F(ProvidersTest, TheCacheIsTrimmed) {
  Settings s = fake_settings();
  s.cache_max_bytes = 60;  // two results of the ok mode (40 bytes each) don't fit
  Service svc(s, tmp.path / "cache");
  const Result a = svc.decompile(bytes_of("mode=ok\na\n"), "x", kFakeKind, "fake", false);
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  const Result b = svc.decompile(bytes_of("mode=ok\nb\n"), "x", kFakeKind, "fake", false);
  EXPECT_FALSE(fs::exists(a.dir));
  EXPECT_TRUE(fs::exists(b.dir));
}

// --- detection -------------------------------------------------------------

TEST(ProviderKinds, MagicNumbers) {
  // From the container detector's content kinds (docs/filesystems.md):
  // whole headers, as the files have them.
  auto k = [](std::string_view b, std::string_view name = "x") { return detect_kind(bytes_of(b), name); };
  EXPECT_EQ(k(std::string_view("dex\n035\0", 8)).kind, "dex");
  EXPECT_EQ(k(std::string_view("dex\n035\0", 8)).version, "035");
  // A class file (Java 8): the constant pool's count after the version.
  EXPECT_EQ(k(std::string_view("\xca\xfe\xba\xbe\x00\x00\x00\x34\x00\x10", 10)).kind, "class");
  EXPECT_EQ(k(std::string_view("\xca\xfe\xba\xbe\x00\x00\x00\x34\x00\x10", 10)).version, "8");
  // Lua 5.4 (64-bit sizes, LUAC_INT and LUAC_NUM) and 5.1, as luac writes them.
  EXPECT_EQ(k(std::string_view("\x1bLua\x54\x00\x19\x93\r\n\x1a\n\x04\x08\x08\x78\x56\0\0\0\0\0\0"
                               "\0\0\0\0\0\x28\x77\x40\x01", 32)).version, "5.4");
  EXPECT_EQ(k(std::string_view("\x1bLua\x51\x00\x01\x04\x08\x04\x08\x00", 12)).version, "5.1");
  EXPECT_EQ(k(std::string_view("\x1bLJ\x02\x0a", 5)).kind, "luajit");
  EXPECT_EQ(k(std::string_view("\0asm\x01\0\0\0", 8)).kind, "wasm");
  // Python 3.12 (3531) and 3.8 (3413): the 16-byte header and a code object.
  EXPECT_EQ(k(std::string_view("\xcb\x0d\r\n\0\0\0\0\0\0\0\0\0\0\0\0\xe3", 17)).version, "3.12");
  EXPECT_EQ(k(std::string_view("\x55\x0d\r\n\0\0\0\0\0\0\0\0\0\0\0\0\xe3", 17)).version, "3.8");
  EXPECT_EQ(k("function f(){return 1}\n", "app.js").kind, "js");
  EXPECT_EQ(k("#!/usr/bin/env node\nconsole.log(1)\n", "cli").kind, "js");
  EXPECT_EQ(k("function f(){return 1}\n", "app.txt").kind, "");
  EXPECT_EQ(k("\x7f" "ELF\x02\x01\x01").kind, "");
  EXPECT_EQ(k("").kind, "");
  // The container detector's content kinds.
  EXPECT_EQ(kind_from_format("pyc:3.12").version, "3.12");
  EXPECT_EQ(kind_from_format("lua:5.4").kind, "lua");
  EXPECT_EQ(kind_from_format("luajit:2.1").kind, "luajit");
  EXPECT_EQ(kind_from_format("dotnet").kind, "dotnet");
  EXPECT_EQ(kind_from_format("dotnet:il").kind, "dotnet");
  EXPECT_EQ(kind_from_format("dotnet:mixed").kind, "dotnet");
  EXPECT_EQ(kind_from_format("java-class:21").kind, "class");
  EXPECT_EQ(kind_from_format("java-class:21").version, "21");
  EXPECT_EQ(kind_from_format("dex:035").version, "035");
  EXPECT_EQ(kind_from_format("js-source").kind, "js");
  EXPECT_EQ(kind_from_format("apk").kind, "apk");
  EXPECT_EQ(kind_from_format("jar").kind, "jar");
  EXPECT_EQ(kind_from_format("squashfs").kind, "");
  EXPECT_EQ(kind_from_format("v8-cache").kind, "");  // no provider takes it yet
}

TEST(ProviderKinds, ZipsAreJarsOrApks) {
  TempDir t;
  if (sh("command -v python3 >/dev/null") != 0) GTEST_SKIP() << "no python3";
  const std::string py = "import zipfile,sys\n"
                         "with zipfile.ZipFile(sys.argv[1]+'/a.jar','w') as z: z.writestr('META-INF/MANIFEST.MF','Manifest-Version: 1.0\\n'); z.writestr('p/A.class', b'\\xca\\xfe\\xba\\xbe')\n"
                         "with zipfile.ZipFile(sys.argv[1]+'/a.apk','w') as z: z.writestr('AndroidManifest.xml','x'); z.writestr('classes.dex', b'dex\\n035\\0')\n"
                         "with zipfile.ZipFile(sys.argv[1]+'/a.zip','w') as z: z.writestr('readme.txt','hi')\n";
  std::ofstream(t.path / "mk.py") << py;
  ASSERT_EQ(sh("python3 -I " + (t.path / "mk.py").string() + " " + t.path.string()), 0);
  EXPECT_EQ(detect_kind(read_all(t.path / "a.jar"), "a.jar").kind, "jar");
  EXPECT_EQ(detect_kind(read_all(t.path / "a.apk"), "a.apk").kind, "apk");
  EXPECT_EQ(detect_kind(read_all(t.path / "a.zip"), "a.zip").kind, "");
}

TEST(ProviderKinds, Languages) {
  EXPECT_EQ(language_of("a/B.cs"), "csharp");
  EXPECT_EQ(language_of("Tiny.csproj"), "xml");
  EXPECT_EQ(language_of("x.dcmp"), "wasm");
  EXPECT_EQ(language_of("Makefile"), "text");
  EXPECT_EQ(language_of("dir.d/file"), "text");
}

// --- the real tools, where installed -----------------------------------------

class RealTools : public ProvidersTest {
 protected:
  // The tool's status, or skips the test.
  bool need(Service &svc, const std::string &name) {
    const ToolStatus t = svc.tool(name);
    if (!t.available) {
      std::cout << "[  SKIPPED ] " << name << ": " << t.reason << "\n";
      return false;
    }
    return true;
  }
  std::string text_of(Service &svc, const Result &r, const std::string &path) {
    std::uint64_t size = 0;
    return svc.read_file(r, path, 0, 1 << 20, size);
  }
  std::string all_text(Service &svc, const Result &r, const std::string &language) {
    std::string out;
    for (const OutputFile &f : r.files)
      if (f.language == language) out += text_of(svc, r, f.path);
    return out;
  }
};

TEST_F(RealTools, IlspyOnADotnetClassLibrary) {
  Service svc(Settings{}, tmp.path / "cache");
  if (!need(svc, "ilspy")) GTEST_SKIP() << "ilspycmd isn't installed";
  if (sh("command -v dotnet >/dev/null") != 0) GTEST_SKIP() << "no .NET SDK to build the fixture";
  const fs::path proj = tmp.path / "Tiny";
  const std::string cmd = "cd " + tmp.path.string() +
                          " && DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 dotnet new classlib -n Tiny -o Tiny --force >/dev/null 2>&1";
  ASSERT_EQ(sh(cmd), 0);
  std::ofstream(proj / "Class1.cs") << "namespace Tiny;\npublic class Calc {\n  public int f;\n"
                                       "  public static int Add(int a, int b) { int c = a + b; if (c > 10) c -= 3; return c * 2; }\n"
                                       "  public static string Hello(string n) => \"hi \" + n.Length;\n}\n";
  ASSERT_EQ(sh("cd " + proj.string() + " && DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 dotnet build -c Release -o out >/dev/null 2>&1"), 0);
  const auto dll = read_all(proj / "out" / "Tiny.dll");
  const InputKind k = detect_kind(dll, "Tiny.dll");
  ASSERT_EQ(k.kind, "dotnet");
  EXPECT_EQ(svc.default_provider("dotnet"), "ilspy");
  const Result r = svc.decompile(dll, "Tiny.dll", k, "", false);
  ASSERT_EQ(r.status, RunStatus::ok) << r.detail << "\n" << r.stderr_tail;
  const std::string cs = all_text(svc, r, "csharp");
  EXPECT_NE(cs.find("public static int Add(int a, int b)"), std::string::npos) << cs;
  EXPECT_NE(cs.find("return \"hi \" + n.Length;"), std::string::npos) << cs;
  EXPECT_EQ(r.language, "csharp");
  EXPECT_EQ(fs::path(r.main_file).filename(), "Calc.cs") << r.main_file;  // not AssemblyInfo.cs
  std::cout << "ilspy " << r.version << ": " << r.files.size() << " files in " << r.seconds << " s\n";
}

class JavaFixture : public RealTools {
 protected:
  void SetUp() override {
    RealTools::SetUp();
    if (IsSkipped()) return;
    if (sh("command -v javac >/dev/null && command -v jar >/dev/null") != 0) GTEST_SKIP() << "no JDK for the fixture";
    fs::create_directories(tmp.path / "src" / "tiny");
    std::ofstream(tmp.path / "src" / "tiny" / "Tiny.java")
        << "package tiny;\npublic class Tiny {\n  int f;\n"
           "  public static int add(int a, int b) { int c = a + b; if (c > 10) c -= 3; return c * 2; }\n"
           "  public static String hello(String n) { return \"hi \" + n.length(); }\n}\n";
    const std::string d = tmp.path.string();
    ASSERT_EQ(sh("javac --release 8 -nowarn -d " + d + "/classes " + d + "/src/tiny/Tiny.java 2>/dev/null"), 0);
    ASSERT_EQ(sh("cd " + d + "/classes && jar cf " + d + "/tiny.jar tiny/Tiny.class"), 0);
    jar = read_all(tmp.path / "tiny.jar");
    cls = read_all(tmp.path / "classes" / "tiny" / "Tiny.class");
  }
  void check(const std::string &provider, bool class_too) {
    Service svc(Settings{}, tmp.path / "cache");
    if (!need(svc, provider)) GTEST_SKIP() << provider << " isn't installed";
    const InputKind kj = detect_kind(jar, "tiny.jar");
    ASSERT_EQ(kj.kind, "jar");
    const Result r = svc.decompile(jar, "tiny.jar", kj, provider, false);
    ASSERT_EQ(r.status, RunStatus::ok) << r.detail << "\n" << r.stderr_tail;
    const std::string java = all_text(svc, r, "java");
    EXPECT_NE(java.find("add(int"), std::string::npos) << java;
    EXPECT_NE(java.find("hi "), std::string::npos) << java;
    std::cout << provider << " " << r.version << ": jar in " << r.seconds << " s\n";
    if (class_too) {
      const InputKind kc = detect_kind(cls, "Tiny.class");
      ASSERT_EQ(kc.kind, "class");
      const Result c = svc.decompile(cls, "Tiny.class", kc, provider, false);
      ASSERT_EQ(c.status, RunStatus::ok) << c.detail << "\n" << c.stderr_tail;
      EXPECT_NE(all_text(svc, c, "java").find("add(int"), std::string::npos);
    }
  }
  std::vector<std::byte> jar, cls;
};

TEST_F(JavaFixture, Jadx) { check("jadx", true); }
TEST_F(JavaFixture, Vineflower) { check("vineflower", true); }
TEST_F(JavaFixture, Cfr) { check("cfr", true); }

TEST_F(RealTools, PycdcOnPythonBytecode) {
  Service svc(Settings{}, tmp.path / "cache");
  if (!need(svc, "pycdc")) GTEST_SKIP() << "pycdc isn't installed";
  if (sh("command -v python3 >/dev/null") != 0) GTEST_SKIP() << "no python3 for the fixture";
  std::ofstream(tmp.path / "mod.py") << "def add(a, b):\n    c = a + b\n    if c > 10:\n        c -= 3\n    return c * 2\n";
  ASSERT_EQ(sh("python3 -I -c \"import py_compile,sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)\" " +
               (tmp.path / "mod.py").string() + " " + (tmp.path / "mod.pyc").string()),
            0);
  const auto pyc = read_all(tmp.path / "mod.pyc");
  const InputKind k = detect_kind(pyc, "mod.pyc");
  ASSERT_EQ(k.kind, "pyc");
  const Result r = svc.decompile(pyc, "mod.pyc", k, "", false);
  ASSERT_EQ(r.status, RunStatus::ok) << r.detail << "\n" << r.stderr_tail;
  ASSERT_EQ(r.files.size(), 1u);
  EXPECT_EQ(r.files[0].path, "mod.py");
  EXPECT_NE(text_of(svc, r, "mod.py").find("def add(a, b)"), std::string::npos) << text_of(svc, r, "mod.py");
}

TEST_F(RealTools, WasmDecompileOnAModule) {
  Service svc(Settings{}, tmp.path / "cache");
  if (!need(svc, "wasm-decompile")) GTEST_SKIP() << "wasm-decompile isn't installed";
  // (module (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add))
  const std::string_view mod(
      "\0asm\x01\0\0\0"
      "\x01\x07\x01\x60\x02\x7f\x7f\x01\x7f"
      "\x03\x02\x01\x00"
      "\x07\x07\x01\x03" "add" "\x00\x00"
      "\x0a\x09\x01\x07\x00\x20\x00\x20\x01\x6a\x0b",
      41);
  const auto b = bytes_of(mod);
  const InputKind k = detect_kind(b, "m.wasm");
  ASSERT_EQ(k.kind, "wasm");
  const Result r = svc.decompile(b, "m.wasm", k, "", false);
  ASSERT_EQ(r.status, RunStatus::ok) << r.detail << "\n" << r.stderr_tail;
  ASSERT_EQ(r.files.size(), 1u);
  EXPECT_NE(text_of(svc, r, r.files[0].path).find("export function add"), std::string::npos)
      << text_of(svc, r, r.files[0].path);
}

TEST_F(RealTools, WebcrackOnABundle) {
  Service svc(Settings{}, tmp.path / "cache");
  if (!need(svc, "webcrack")) GTEST_SKIP() << "webcrack isn't installed";
  const std::string js = "var a=function(){return!0},b=void 0;if(a()){console.log(\"hi\")}\n";
  const auto b = bytes_of(js);
  const InputKind k = detect_kind(b, "app.min.js");
  ASSERT_EQ(k.kind, "js");
  const Result r = svc.decompile(b, "app.min.js", k, "", false);
  ASSERT_EQ(r.status, RunStatus::ok) << r.detail << "\n" << r.stderr_tail;
  const std::string out = all_text(svc, r, "javascript");
  EXPECT_NE(out.find("console.log(\"hi\")"), std::string::npos) << out;
  EXPECT_NE(out.find("true"), std::string::npos) << out;  // !0 unminified
}

TEST_F(RealTools, UnluacOnALuaChunk) {
  Service svc(Settings{}, tmp.path / "cache");
  if (!need(svc, "unluac")) GTEST_SKIP() << "unluac isn't installed";
  // A chunk compiled by luac, when there is one (none on most hosts; the
  // revkit-tools build is run in the sandbox, as every downloaded tool is).
  const char *home = std::getenv("HOME");
  fs::path luac = home ? fs::path(home) / ".local/share/revkit-tools/lua/luac" : fs::path();
  if (luac.empty() || ::access(luac.c_str(), X_OK) != 0) GTEST_SKIP() << "no luac to make the fixture";
  std::ofstream(tmp.path / "f.lua") << "local function f(n) local s = 0 for i = 1, n do s = s + i end return s end\nreturn f(10)\n";
  fs::create_directories(tmp.path / "luaout");
  SandboxSpec spec;
  spec.argv = {luac.string(), "-o", (tmp.path / "luaout" / "f.luac").string(), (tmp.path / "f.lua").string()};
  spec.env = {"PATH=/usr/bin:/bin"};
  spec.read_paths = {"/usr", "/lib", "/lib64", "/etc", luac, tmp.path / "f.lua"};
  spec.write_paths = {tmp.path / "luaout"};
  spec.limits.timeout = std::chrono::seconds(20);
  ASSERT_EQ(run_sandboxed(spec).status, RunStatus::ok);
  const auto chunk = read_all(tmp.path / "luaout" / "f.luac");
  const InputKind k = detect_kind(chunk, "f.luac");
  ASSERT_EQ(k.kind, "lua");
  const Result r = svc.decompile(chunk, "f.luac", k, "", false);
  ASSERT_EQ(r.status, RunStatus::ok) << r.detail << "\n" << r.stderr_tail;
  EXPECT_NE(text_of(svc, r, r.files.at(0).path).find("for "), std::string::npos) << text_of(svc, r, r.files.at(0).path);
}

}  // namespace
}  // namespace revkit::providers
