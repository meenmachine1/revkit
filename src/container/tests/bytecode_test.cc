// Bytecode and script formats by their headers (docs/filesystems.md,
// "Content kinds"): real files where the toolchain is here (python3's
// py_compile, javac, node's code cache, Lua and LuaJIT through lupa:
// tests/data/bytecode/make_lua_chunks.py), headers written here otherwise.
#include "../bytecode.hh"
#include "fixtures.hh"

#include <cstdlib>

namespace revkit::container {
namespace {

using namespace testing;

std::vector<std::byte> bytes(std::initializer_list<int> v, std::size_t pad = 64) {
  std::vector<std::byte> out;
  for (int x : v) out.push_back(static_cast<std::byte>(x));
  if (out.size() < pad) out.resize(pad);
  return out;
}

std::vector<std::byte> str(std::string_view s, std::size_t pad = 64) {
  std::vector<std::byte> out(s.size());
  std::memcpy(out.data(), s.data(), s.size());
  if (out.size() < pad) out.resize(pad);
  return out;
}

Guess guess_of(const std::vector<std::byte> &b) { return guess(b, b.size()); }

// A Python with lupa and PyInstaller (docs/development.md): $RK_BYTECODE_PYTHON,
// else revkit's cache venv.
std::string bytecode_python() {
  if (const char *p = std::getenv("RK_BYTECODE_PYTHON"); p && *p) return p;
  const char *home = std::getenv("HOME");
  const std::string venv = std::string(home ? home : "") + "/.cache/revkit/bytecode-venv/bin/python";
  return fs::exists(venv) ? venv : "";
}

TEST(ContainerBytecode, PycFromPyCompile) {
  if (!have_tool("python3")) GTEST_SKIP() << "no python3";
  TempDir t;
  std::ofstream(t / "m.py") << "def add(a, b):\n    return a + b\n";
  ASSERT_TRUE(sh("cd " + t.path().string() + " && python3 -I -c \"import py_compile; py_compile.compile('m.py', cfile='m.pyc')\""));
  std::string want;
  {
    FILE *f = popen("python3 -I -c \"import sys; print('%d.%d' % sys.version_info[:2])\"", "r");
    char buf[32] = {};
    if (f && fgets(buf, sizeof buf, f)) want = buf;
    if (f) pclose(f);
    while (!want.empty() && (want.back() == '\n' || want.back() == '\r')) want.pop_back();
  }
  const auto b = read_file(t / "m.pyc");
  Guess g = guess_of(b);
  EXPECT_EQ(g.kind, "bytecode");
  EXPECT_EQ(g.format, "pyc");
  EXPECT_EQ(g.content_kind, "pyc:" + want);
  EXPECT_NE(g.description.find("Python " + want + " bytecode"), std::string::npos) << g.description;
}

TEST(ContainerBytecode, PycMagicTable) {
  struct Case {
    unsigned magic;
    const char *version;
    std::size_t header;
  };
  for (const Case &c : {Case{62211, "2.7", 8}, Case{3131, "3.0", 8}, Case{3180, "3.2", 8}, Case{3230, "3.3", 12},
                        Case{3310, "3.4", 12}, Case{3351, "3.5", 12}, Case{3379, "3.6", 12}, Case{3394, "3.7", 16},
                        Case{3413, "3.8", 16}, Case{3425, "3.9", 16}, Case{3439, "3.10", 16},
                        Case{3495, "3.11", 16}, Case{3531, "3.12", 16}, Case{3571, "3.13", 16},
                        Case{3627, "3.14", 16}, Case{3655, "3.15", 16}}) {
    auto b = bytes({static_cast<int>(c.magic & 0xff), static_cast<int>(c.magic >> 8), '\r', '\n'});
    b[c.header] = std::byte{0xe3};  // TYPE_CODE | FLAG_REF
    Guess g = guess_of(b);
    EXPECT_EQ(g.content_kind, std::string("pyc:") + c.version) << c.magic;
    auto v = detail::pyc_version(static_cast<std::uint16_t>(c.magic));
    ASSERT_TRUE(v) << c.magic;
    EXPECT_EQ(detail::pyc_header_size(*v), c.header) << c.magic;
    // Not followed by a code object: not a .pyc.
    b[c.header] = std::byte{0x41};
    EXPECT_NE(guess_of(b).format, "pyc") << c.magic;
  }
  EXPECT_FALSE(detail::pyc_version(1234));
  EXPECT_EQ(detail::pyc_release_magic({3, 12}), 3531);
  const auto h = detail::pyc_header(3531);
  ASSERT_EQ(h.size(), 16u);
  EXPECT_EQ(static_cast<int>(h[0]), 3531 & 0xff);
  EXPECT_EQ(static_cast<int>(h[1]), 3531 >> 8);
}

// Real chunks of every Lua and LuaJIT version lupa bundles: named by their
// headers, and walked to their exact length (what the firmware carver
// cuts by).
TEST(ContainerBytecode, LuaChunksFromLupa) {
  const std::string python = bytecode_python();
  if (python.empty()) GTEST_SKIP() << "no Python with lupa (RK_BYTECODE_PYTHON, ~/.cache/revkit/bytecode-venv)";
  TempDir t;
  const int rc = std::system((python + " -I " REVKIT_SOURCE_DIR "/tests/data/bytecode/make_lua_chunks.py " +
                              t.path().string() + " >/dev/null 2>&1")
                                 .c_str());
  if (WIFEXITED(rc) && WEXITSTATUS(rc) == 77) GTEST_SKIP() << "lupa is not installed in " << python;
  ASSERT_EQ(rc, 0);
  std::ifstream index(t / "index.txt");
  std::string name;
  std::uint64_t size = 0;
  int seen = 0;
  while (index >> name >> size) {
    ++seen;
    const auto b = read_file(t / (name + ".luac"));
    ASSERT_EQ(b.size(), size);
    Guess g = guess_of(b);
    std::string want = name.substr(0, name.find("-stripped"));
    want = want.starts_with("luajit-") ? "luajit:" + want.substr(7) : "lua:" + want.substr(4);
    EXPECT_EQ(g.kind, "bytecode") << name;
    EXPECT_EQ(g.content_kind, want) << name << ": " << g.description;
    auto h = detail::lua_header(b);
    ASSERT_TRUE(h) << name;
    if (want == "lua:5.5") continue;  // named, not walked (docs/filesystems.md)
    auto len = detail::lua_chunk_length(b, 0, *h);
    ASSERT_TRUE(len) << name;
    EXPECT_EQ(*len, b.size()) << name;
    // Truncated anywhere inside: no length.
    for (std::size_t cut : {b.size() - 1, b.size() / 2, h->size + 1}) {
      std::vector<std::byte> c(b.begin(), b.begin() + static_cast<std::ptrdiff_t>(cut));
      EXPECT_FALSE(detail::lua_chunk_length(c, 0, *h)) << name << " cut at " << cut;
    }
  }
  EXPECT_GE(seen, 8);
}

TEST(ContainerBytecode, LuaHeaders) {
  // 5.1, 32-bit build with float numbers, big-endian.
  auto b51 = bytes({0x1b, 'L', 'u', 'a', 0x51, 0, 0, 4, 4, 4, 4, 0});
  Guess g = guess_of(b51);
  EXPECT_EQ(g.content_kind, "lua:5.1");
  EXPECT_EQ(g.description, "Lua 5.1 chunk (32-bit float numbers, big-endian)");
  // A modified format byte, a bad size: not a chunk this reader accepts.
  auto bad = b51;
  bad[5] = std::byte{1};
  EXPECT_NE(guess_of(bad).format, "lua");
  bad = b51;
  bad[9] = std::byte{3};
  EXPECT_NE(guess_of(bad).format, "lua");
  // 5.4 with 32-bit integers and floats (an embedded build).
  auto b54 = bytes({0x1b, 'L', 'u', 'a', 0x54, 0, 0x19, 0x93, '\r', '\n', 0x1a, '\n', 4, 4, 4, 0x78, 0x56, 0, 0,
                    0, 0, 0xb9, 0x43, 1});
  g = guess_of(b54);
  EXPECT_EQ(g.content_kind, "lua:5.4");
  EXPECT_EQ(g.description, "Lua 5.4 chunk (32-bit integers, 32-bit floats)");
  auto lj = bytes({0x1b, 'L', 'J', 2, 0x0a});
  g = guess_of(lj);
  EXPECT_EQ(g.content_kind, "luajit:2.1");
  EXPECT_NE(g.description.find("stripped"), std::string::npos);
  lj[4] = std::byte{0x7f};  // flags past BITOP
  EXPECT_NE(guess_of(lj).format, "luajit");
}

TEST(ContainerBytecode, JavaClassFromJavac) {
  if (!have_tool("javac")) GTEST_SKIP() << "no javac";
  TempDir t;
  std::ofstream(t / "A.java") << "class A { int f(int x) { return x + 1; } }\n";
  ASSERT_TRUE(sh("cd " + t.path().string() + " && javac --release 8 A.java"));
  Guess g = guess_of(read_file(t / "A.class"));
  EXPECT_EQ(g.kind, "bytecode");
  EXPECT_EQ(g.content_kind, "java-class:8");
  EXPECT_EQ(g.description, "Java class (Java 8, class file 52.0)");
  // And the jar of it.
  if (have_tool("jar")) {
    ASSERT_TRUE(sh("cd " + t.path().string() + " && jar cf a.jar A.class"));
    g = guess(read_file(t / "a.jar"), fs::file_size(t / "a.jar"), "zip");
    EXPECT_EQ(g.content_kind, "jar");
    EXPECT_EQ(g.description, "zip archive (Java archive)");
  }
}

TEST(ContainerBytecode, ClassesDexWasmAndOthers) {
  // A universal Mach-O stays one; a class file with the same magic is a class.
  EXPECT_EQ(guess_of(bytes({0xca, 0xfe, 0xba, 0xbe, 0, 3, 0, 45, 0, 9})).content_kind, "java-class:1.1");
  EXPECT_EQ(guess_of(bytes({0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65, 0, 9})).content_kind, "java-class:21");
  EXPECT_EQ(guess_of(bytes({0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65, 0, 0})).kind, "raw");  // empty constant pool
  Guess g = guess_of(str(std::string_view("dex\n039\0", 8)));
  EXPECT_EQ(g.content_kind, "dex:039");
  EXPECT_EQ(g.description, "Android DEX 039");
  EXPECT_EQ(guess_of(str(std::string_view("dex\n03x\0", 8))).format, "data");
  g = guess_of(str(std::string_view("\0asm\1\0\0\0", 8)));
  EXPECT_EQ(g.content_kind, "wasm");
  EXPECT_EQ(g.kind, "bytecode");
  EXPECT_EQ(guess_of(str(std::string_view("\0asm\x0d\0\1\0", 8))).content_kind, "wasm-component");
  g = guess_of(bytes({0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f, 96, 0, 0, 0}));
  EXPECT_EQ(g.content_kind, "hermes:96");
  EXPECT_EQ(g.description, "Hermes bytecode (version 96)");
  g = guess_of(str(std::string_view("YARB\3\0\0\0\4\0\0\0", 12)));
  EXPECT_EQ(g.content_kind, "yarb:3.4");
  EXPECT_EQ(guess_of(str(std::string_view("FOR1\0\0\0\x10" "BEAM", 12))).content_kind, "beam");
  EXPECT_EQ(guess_of(str(std::string_view("OPCACHE\0", 8))).content_kind, "php-opcache");
  // EVM bytecode as solc writes it, binary or hex text (docs/evm.md).
  g = guess_of(bytes({0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15}));
  EXPECT_EQ(g.content_kind, "evm");
  EXPECT_EQ(g.description, "EVM bytecode (solc)");
  g = guess_of(str("0x6080604052348015610010575f80fd5b50\n"));
  EXPECT_EQ(g.content_kind, "evm");
  EXPECT_EQ(g.description, "EVM bytecode as hex text (solc)");
  EXPECT_NE(guess_of(str("6080604")).content_kind, "evm");
}

TEST(ContainerBytecode, V8CodeCacheFromNode) {
  if (!have_tool("node")) GTEST_SKIP() << "no node";
  TempDir t;
  ASSERT_TRUE(sh("node -e 'const vm=require(\"vm\");const s=new vm.Script(\"function f(a){return a+1} f(2)\");"
                 "s.runInThisContext();require(\"fs\").writeFileSync(process.argv[1],s.createCachedData())' " +
                 (t / "c.jsc").string()));
  const auto b = read_file(t / "c.jsc");
  Guess g = guess_of(b);
  EXPECT_EQ(g.content_kind, "v8-cache") << g.description;
  EXPECT_EQ(g.kind, "bytecode");
  // Its length must fill the file: one byte more is data.
  auto longer = b;
  longer.push_back(std::byte{0});
  EXPECT_NE(guess_of(longer).content_kind, "v8-cache");
}

TEST(ContainerBytecode, ScriptsByTheirInterpreter) {
  EXPECT_EQ(guess_of(str("#!/usr/bin/env node\nconsole.log(1)\n", 0)).content_kind, "js-source");
  EXPECT_EQ(guess_of(str("#!/usr/bin/python3.12 -I\nprint(1)\n", 0)).content_kind, "python-source");
  EXPECT_EQ(guess_of(str("#!/usr/bin/lua5.4\nprint(1)\n", 0)).content_kind, "lua-source");
  EXPECT_EQ(guess_of(str("#!/bin/sh\necho nodes\n", 0)).content_kind, "");
}

TEST(ContainerBytecode, ApkByItsFirstMembers) {
  if (!have_tool("zip")) GTEST_SKIP() << "no zip";
  TempDir t;
  std::ofstream(t / "AndroidManifest.xml") << "x";
  std::ofstream(t / "classes.dex") << "dex\n035";
  ASSERT_TRUE(sh("cd " + t.path().string() + " && zip -q a.apk AndroidManifest.xml classes.dex"));
  const auto b = read_file(t / "a.apk");
  Guess g = guess(b, b.size(), identify_head(b, b.size()));
  EXPECT_EQ(g.content_kind, "apk");
  EXPECT_EQ(g.description, "zip archive (Android package)");
}

}  // namespace
}  // namespace revkit::container

namespace revkit::container {
namespace {

using namespace testing;

// A .NET class library built by the dotnet SDK, when it is here: a PE
// whose CLR header says IL-only.
TEST(ContainerBytecode, DotNetAssemblyFromDotnet) {
  if (!have_tool("dotnet")) GTEST_SKIP() << "no dotnet SDK";
  TempDir t;
  std::ofstream(t / "lib.csproj") << "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>"
                                     "net10.0</TargetFramework></PropertyGroup></Project>\n";
  std::ofstream(t / "A.cs") << "public class A { public int Add(int a, int b) => a + b; }\n";
  const std::string env = "DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 ";
  if (!sh("cd " + t.path().string() + " && " + env +
          "dotnet build -c Release -o out --disable-build-servers -nodeReuse:false -p:UseSharedCompilation=false"))
    GTEST_SKIP() << "dotnet build failed (no net10.0 targeting pack?)";
  const auto b = read_file(t / "out/lib.dll");
  Guess g = guess_of(b);
  EXPECT_EQ(g.kind, "pe");
  EXPECT_EQ(g.content_kind, "dotnet:il");
  EXPECT_EQ(g.description, "PE x86 DLL, .NET assembly (IL-only, metadata v4.0.30319)");
}

}  // namespace
}  // namespace revkit::container
