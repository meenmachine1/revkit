// Go build info and cargo-auditable dependency lists (buildinfo.hh):
// synthetic images for each format and every refusal, then real binaries
// built at test time when Go or cargo-auditable is installed (they skip
// otherwise). The toolchains: REVKIT_TEST_GO (configure-time `go`, or
// $RK_GO), $RK_GO_OLD (a Go before 1.18, for the pointer format; e.g.
// go1.17.13 from https://go.dev/dl/), REVKIT_TEST_CARGO (or $RK_CARGO)
// with cargo-auditable installed (`cargo install cargo-auditable`).

#include "builders.hh"

#include "revkit/loader/buildinfo.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>
#include <zlib.h>

#include <cstdlib>
#include <fstream>

namespace revkit::loader {
namespace {

using testing::ElfBuilder;
using testing::ElfSpec;
using testing::scratch_dir;
using testing::to_bytes;

constexpr std::uint32_t kPfR = 4, kPfW = 2, kPfX = 1;

const std::string kSentinelStart("\x30\x77\xaf\x0c\x92\x74\x08\x02\x41\xe1\xc1\x07\xe6\xd6\x18\xe6", 16);
const std::string kSentinelEnd("\xf9\x32\x43\x31\x86\x18\x20\x72\x00\x82\x42\x10\x41\x16\xd8\xf2", 16);

const char kModuleText[] =
    "path\texample.com/hello\n"
    "mod\texample.com/hello\tv1.2.3\th1:abc=\n"
    "dep\tgolang.org/x/text\tv0.14.0\th1:def=\n"
    "dep\texample.com/dep\tv0.1.0\n"
    "=>\t./dep\t\t\n"
    "build\t-buildmode=exe\n"
    "build\t-ldflags=\"-s -w -X main.v=1\"\n"
    "build\tCGO_ENABLED=0\n"
    "build\tGOOS=linux\n"
    "build\tvcs.revision=0123456789abcdef\n"
    "build\t\"odd key\"=`raw value`\n"
    "weird\tline\n";

std::string Framed(std::string_view text) { return kSentinelStart + std::string(text) + kSentinelEnd; }

void PutVarint(std::vector<std::uint8_t> &out, std::uint64_t v) {
  while (v >= 0x80) {
    out.push_back(static_cast<std::uint8_t>(v | 0x80));
    v >>= 7;
  }
  out.push_back(static_cast<std::uint8_t>(v));
}

std::vector<std::uint8_t> Header(std::uint8_t ptr, std::uint8_t flags) {
  std::vector<std::uint8_t> h = {0xff, ' ', 'G', 'o', ' ', 'b', 'u', 'i', 'l', 'd', 'i', 'n', 'f', ':', ptr, flags};
  h.resize(32, 0);
  return h;
}

// Go 1.18's layout: the header, then the two strings, uvarint-prefixed.
std::vector<std::uint8_t> InlineBlob(std::string_view version, std::string_view mod) {
  auto b = Header(8, 2);
  PutVarint(b, version.size());
  b.insert(b.end(), version.begin(), version.end());
  PutVarint(b, mod.size());
  b.insert(b.end(), mod.begin(), mod.end());
  return b;
}

// Go 1.13-1.17's: pointers to Go string headers (pointer, length) and
// their bytes, all in the blob at `base`.
std::vector<std::uint8_t> PointerBlob(std::uint64_t base, unsigned ptr, bool big, std::string_view version,
                                      std::string_view mod) {
  testing::ByteWriter w(big);
  for (std::uint8_t c : Header(static_cast<std::uint8_t>(ptr), big ? 1 : 0)) w.put(c, 1);
  const std::uint64_t vhdr = 32 + 2 * ptr, mhdr = vhdr + 2 * ptr, vdata = mhdr + 2 * ptr,
                      mdata = vdata + version.size();
  w.put_at(16, base + vhdr, ptr);
  w.put_at(16 + ptr, mod.empty() ? 0 : base + mhdr, ptr);
  w.put_at(vhdr, base + vdata, ptr);
  w.put_at(vhdr + ptr, version.size(), ptr);
  w.put_at(mhdr, base + mdata, ptr);
  w.put_at(mhdr + ptr, mod.size(), ptr);
  w.bytes_at(vdata, std::vector<std::uint8_t>(version.begin(), version.end()));
  w.bytes_at(mdata, std::vector<std::uint8_t>(mod.begin(), mod.end()));
  return w.data();
}

Image ElfWith(const std::string &name, std::vector<std::uint8_t> data, ElfSpec spec = {}, std::uint64_t at = 0x500000) {
  ElfBuilder b(spec);
  b.add_load(".text", 0x401000, std::vector<std::uint8_t>(16, 0xc3), kPfR | kPfX);
  b.add_load(name, at, std::move(data), kPfR | kPfW);
  return parse_elf(to_bytes(b.build()));
}

void ExpectModules(const GoBuildInfo &g) {
  EXPECT_EQ(g.path, "example.com/hello");
  ASSERT_TRUE(g.main);
  EXPECT_EQ(g.main->path, "example.com/hello");
  EXPECT_EQ(g.main->version, "v1.2.3");
  EXPECT_EQ(g.main->sum, "h1:abc=");
  ASSERT_EQ(g.deps.size(), 2u);
  EXPECT_EQ(g.deps[0].path, "golang.org/x/text");
  EXPECT_FALSE(g.deps[0].replacement);
  EXPECT_EQ(g.deps[1].path, "example.com/dep");
  EXPECT_EQ(g.deps[1].sum, "");
  ASSERT_TRUE(g.deps[1].replacement);
  EXPECT_EQ(g.deps[1].replacement->path, "./dep");
  EXPECT_EQ(g.deps[1].replacement->version, "");
}

TEST(GoModuleText, ParsesEveryLineKind) {
  GoBuildInfo g;
  parse_go_module_text(kModuleText, g);
  ExpectModules(g);
  ASSERT_EQ(g.settings.size(), 6u);
  EXPECT_EQ(*g.setting("-ldflags"), "-s -w -X main.v=1");
  EXPECT_EQ(*g.setting("CGO_ENABLED"), "0");
  EXPECT_EQ(*g.setting("odd key"), "raw value");
  EXPECT_EQ(g.setting("GOARCH"), nullptr);
  ASSERT_EQ(g.unparsed.size(), 1u);
  EXPECT_EQ(g.unparsed[0], "weird\tline");
}

TEST(GoModuleText, KeepsWhatItCantTake) {
  GoBuildInfo g;
  parse_go_module_text(
      "=>\tno\tmodule\tbefore\n"         // a replacement with nothing to replace
      "mod\tonly-one-field\n"            // a module line needs 2 or 3 fields
      "build\tkey with space=1\n"        // an unquoted key can't hold a space
      "build\t-tags=\"a\\x41\\u00e9\\101\"\n"  // Go escapes
      "build\tbad=\"unterminated\n"
      "build\tnoequals\n"
      "dep\tlast\tv1\n"
      "=>\ttwo\tfields\n"                // a replacement needs 3
      "mod\tlate\tv9\n"                  // a second mod after a dep is still the first main
      "dep\tunterminated\tv1",
      g);
  EXPECT_EQ(*g.setting("-tags"), "aA\xc3\xa9" "A");
  ASSERT_EQ(g.deps.size(), 1u);
  EXPECT_FALSE(g.deps[0].replacement);
  ASSERT_TRUE(g.main);
  EXPECT_EQ(g.main->path, "late");
  EXPECT_EQ(g.unparsed.size(), 7u);
}

TEST(GoBuildInfo, InlineFormatInGoBuildinfoSection) {
  Image img = ElfWith(".go.buildinfo", InlineBlob("go1.22.3", Framed(kModuleText)));
  std::string error;
  auto g = read_go_buildinfo(img, &error);
  ASSERT_TRUE(g) << error;
  EXPECT_TRUE(error.empty());
  EXPECT_EQ(g->go_version, "go1.22.3");
  EXPECT_TRUE(g->inline_strings);
  EXPECT_EQ(g->address, 0x500000u);
  EXPECT_EQ(g->module_text, kModuleText);
  ExpectModules(*g);
  EXPECT_EQ(*g->setting("GOOS"), "linux");
}

TEST(GoBuildInfo, PointerFormat64LittleAnd32Big) {
  {
    Image img = ElfWith(".go.buildinfo", PointerBlob(0x500000, 8, false, "go1.17.13", Framed(kModuleText)));
    std::string error;
    auto g = read_go_buildinfo(img, &error);
    ASSERT_TRUE(g) << error;
    EXPECT_FALSE(g->inline_strings);
    EXPECT_EQ(g->pointer_size, 8u);
    EXPECT_EQ(g->go_version, "go1.17.13");
    ExpectModules(*g);
  }
  {
    ElfSpec spec;
    spec.wide = false;
    spec.big = true;
    spec.machine = 8;  // MIPS
    Image img = ElfWith(".go.buildinfo", PointerBlob(0x500000, 4, true, "go1.16", ""), spec);
    std::string error;
    auto g = read_go_buildinfo(img, &error);
    ASSERT_TRUE(g) << error;
    EXPECT_EQ(g->pointer_size, 4u);
    EXPECT_EQ(g->go_version, "go1.16");
    EXPECT_TRUE(g->module_text.empty());
    EXPECT_FALSE(g->main);
  }
}

TEST(GoBuildInfo, RebasedImageMovesThePointers) {
  ElfBuilder b(ElfSpec{});
  b.add_load(".text", 0x401000, std::vector<std::uint8_t>(16, 0xc3), kPfR | kPfX);
  b.add_load(".go.buildinfo", 0x500000, PointerBlob(0x500000, 8, false, "go1.15", Framed(kModuleText)), kPfR | kPfW);
  LoadOptions o;
  o.image_base = 0x10400000;
  Image img = parse_elf(to_bytes(b.build()), o);
  std::string error;
  auto g = read_go_buildinfo(img, &error);
  ASSERT_TRUE(g) << error;
  EXPECT_EQ(g->go_version, "go1.15");
  EXPECT_EQ(g->address, 0x10500000u - 0x1000u);
  ExpectModules(*g);
}

TEST(GoBuildInfo, WritableSegmentWithoutTheSectionName) {
  // A stripped section name: Go looks in the first writable PT_LOAD, and
  // only at 16-byte aligned addresses.
  std::vector<std::uint8_t> data(8, 0);
  auto misaligned = InlineBlob("go1.0-bad", "");
  data.insert(data.end(), misaligned.begin(), misaligned.end());
  data.resize(64, 0);
  auto good = InlineBlob("go1.21.0", "");
  data.insert(data.end(), good.begin(), good.end());
  Image img = ElfWith(".data", data);
  std::string error;
  auto g = read_go_buildinfo(img, &error);
  ASSERT_TRUE(g) << error;
  EXPECT_EQ(g->go_version, "go1.21.0");
  EXPECT_EQ(g->address, 0x500040u);
}

TEST(GoBuildInfo, Refusals) {
  auto expect_error = [](std::vector<std::uint8_t> blob, const std::string &what) {
    Image img = ElfWith(".go.buildinfo", std::move(blob));
    std::string error;
    EXPECT_FALSE(read_go_buildinfo(img, &error)) << what;
    EXPECT_NE(error.find(what), std::string::npos) << error;
  };
  expect_error(InlineBlob("", ""), "no Go version");
  auto truncated = InlineBlob("go1.22", "");
  truncated.resize(20);
  expect_error(truncated, "truncated header");
  auto long_len = Header(8, 2);
  PutVarint(long_len, 2u << 20);
  expect_error(long_len, "longer than 1 MiB");
  auto past = Header(8, 2);
  PutVarint(past, 100);
  expect_error(past, "truncated string");
  auto overflow = Header(8, 2);
  for (int i = 0; i < 9; ++i) overflow.push_back(0xff);
  overflow.push_back(0x7f);
  expect_error(overflow, "past 64 bits");
  auto bad_ptr = Header(3, 0);
  expect_error(bad_ptr, "pointer size of 3");
  auto wild = Header(8, 0);
  wild[16] = 0x10;  // a pointer to nowhere
  expect_error(wild, "outside memory");
  // No header at all: absent, not an error.
  Image none = ElfWith(".go.buildinfo", std::vector<std::uint8_t>(64, 0));
  std::string error = "stale";
  EXPECT_FALSE(read_go_buildinfo(none, &error));
  EXPECT_TRUE(error.empty());
  // Module text without its sentinels is kept out, and said.
  Image unframed = ElfWith(".go.buildinfo", InlineBlob("go1.22", "path\tx\n"));
  auto g = read_go_buildinfo(unframed, &error);
  ASSERT_TRUE(g) << error;
  EXPECT_TRUE(g->module_text.empty());
  ASSERT_EQ(g->unparsed.size(), 1u);
}

TEST(GoBuildInfo, InvalidUtf8IsReplaced) {
  Image img = ElfWith(".go.buildinfo", InlineBlob("go1.\xff\xfe", Framed("path\t\xc3(\n")));
  auto g = read_go_buildinfo(img, nullptr);
  ASSERT_TRUE(g);
  EXPECT_EQ(g->go_version, "go1.\xef\xbf\xbd\xef\xbf\xbd");
  EXPECT_EQ(g->path, "\xef\xbf\xbd(");
}

// --- Rust ------------------------------------------------------------------

std::vector<std::uint8_t> Zlib(std::string_view s) {
  uLongf n = compressBound(static_cast<uLong>(s.size()));
  std::vector<std::uint8_t> out(n);
  EXPECT_EQ(compress2(out.data(), &n, reinterpret_cast<const Bytef *>(s.data()), static_cast<uLong>(s.size()), 9), Z_OK);
  out.resize(n);
  return out;
}

std::span<const std::byte> Span(const std::vector<std::uint8_t> &v) {
  return {reinterpret_cast<const std::byte *>(v.data()), v.size()};
}

const char kAudit[] =
    R"({"packages":[{"name":"dep","version":"1.2.3","source":"local"},)"
    R"({"name":"cc","version":"1.0.83","source":"crates.io","kind":"build","future":{"x":[1,2,{"y":null}]}},)"
    R"({"name":"hello","version":"0.3.1","source":"local","dependencies":[0,1],"root":true}],"format":1})";

TEST(RustAudit, ParsesTheDependencyList) {
  auto blob = Zlib(kAudit);
  Image img = ElfWith(".dep-v0", blob);
  std::string error;
  auto r = read_rust_audit(img, &error);
  ASSERT_TRUE(r) << error;
  EXPECT_EQ(r->format, 1u);
  ASSERT_EQ(r->packages.size(), 3u);
  EXPECT_EQ(r->packages[1].name, "cc");
  EXPECT_EQ(r->packages[1].kind, "build");
  EXPECT_EQ(r->packages[1].source, "crates.io");
  EXPECT_EQ(r->packages[0].kind, "");
  ASSERT_TRUE(r->root);
  EXPECT_EQ(*r->root, 2u);
  EXPECT_EQ(r->packages[2].dependencies, (std::vector<std::uint32_t>{0, 1}));
  EXPECT_EQ(r->compressed_size, blob.size());
  EXPECT_EQ(r->uncompressed_size, std::string_view(kAudit).size());
  // Section padding (a PE's file alignment) after the stream is fine.
  blob.resize(blob.size() + 100, 0);
  EXPECT_TRUE(parse_rust_audit(Span(blob), &error)) << error;
  // Escapes, surrogate pairs and a lone surrogate.
  auto esc = parse_rust_audit(
      Span(Zlib(R"({"packages":[{"name":"aé😀\ud800","version":"1\/2","source":"x"}]})")), &error);
  ASSERT_TRUE(esc) << error;
  EXPECT_EQ(esc->packages[0].name, "a\xc3\xa9\xf0\x9f\x98\x80\xef\xbf\xbd");
  EXPECT_EQ(esc->packages[0].version, "1/2");
  EXPECT_EQ(esc->format, 0u);
  EXPECT_FALSE(esc->root);
}

TEST(RustAudit, Refusals) {
  auto expect_error = [](std::vector<std::uint8_t> bytes, const std::string &what) {
    std::string error;
    EXPECT_FALSE(parse_rust_audit(Span(bytes), &error)) << what;
    EXPECT_NE(error.find(what), std::string::npos) << error;
  };
  auto json = [&](std::string_view s, const std::string &what) { expect_error(Zlib(s), what); };
  expect_error({}, "empty");
  expect_error({1, 2, 3, 4}, "zlib");
  auto trailing = Zlib(kAudit);
  trailing.push_back(7);
  expect_error(trailing, "after the dependency section's zlib stream");
  auto cut = Zlib(kAudit);
  cut.resize(cut.size() / 2);
  expect_error(cut, "complete zlib stream");
  // 1 MiB of spaces inflate past 64x their compressed size.
  expect_error(Zlib(std::string(1 << 20, ' ')), "larger than");
  json("[]", "expected an object");
  json(R"({"packages":[{"name":"a","version":"1"}]})", "no name, version or source");
  json(R"({"packages":[{"name":"","version":"1","source":"x"}]})", "no name, version or source");
  json(R"({"packages":[{"name":"a","version":"1","source":"x","kind":"dev"}]})", "kind");
  json(R"({"packages":[{"name":"a","version":"1","source":"x","dependencies":[1]}]})", "outside the list");
  json(R"({"packages":[{"name":"a","version":"1","source":"x","dependencies":[-1]}]})", "non-negative");
  json(R"({"packages":[{"name":"a","version":"1","source":"x","dependencies":[0.5]}]})", "integer");
  json(R"({"packages":[{"name":"a","version":"1","source":"x","root":true},{"name":"b","version":"1","source":"x","root":true}]})",
       "more than one root");
  json(R"({"packages":[]} x)", "after the JSON");
  json(R"({"packages":[{"name":"a\x","version":"1","source":"x"}]})", "bad escape");
  json(R"({"format":99999999999,"packages":[]})", "32 bits");
  json(std::string(R"({"x":)") + std::string(40, '[') + std::string(40, ']') + "}", "deeper than 32");
  json(R"({"packages":[{"name":"a","version":"1","source":"x"})", "expected");
}

TEST(RustAudit, TwoSectionsAndBuildMetadata) {
  ElfBuilder b(ElfSpec{});
  b.add_load(".text", 0x401000, std::vector<std::uint8_t>(16, 0xc3), kPfR | kPfX);
  std::string ro = "panicked at /rustc/0123456789abcdef0123456789abcdef01234567/library/core/src/x.rs"
                   "\0/rustc/0123456789abcdef0123456789abcdef01234567/again\0/rustc/nothex/\0";
  b.add_load(".rodata", 0x402000, std::vector<std::uint8_t>(ro.begin(), ro.end()), kPfR);
  b.add_load(".dep-v0", 0x403000, Zlib(kAudit), kPfR);
  Image img = parse_elf(to_bytes(b.build()));
  BuildMetadata m = read_build_metadata(img);
  EXPECT_FALSE(m.go);
  ASSERT_TRUE(m.rust);
  EXPECT_EQ(m.rust->packages.size(), 3u);
  EXPECT_EQ(m.rustc_commits, (std::vector<std::string>{"0123456789abcdef0123456789abcdef01234567"}));
  EXPECT_TRUE(m.warnings.empty());
  EXPECT_FALSE(m.empty());

  ElfBuilder two(ElfSpec{});
  two.add_load(".dep-v0", 0x403000, Zlib(kAudit), kPfR);
  two.add_load(".dep-v0", 0x404000, Zlib(kAudit), kPfR);
  BuildMetadata m2 = read_build_metadata(parse_elf(to_bytes(two.build())));
  EXPECT_FALSE(m2.rust);
  ASSERT_EQ(m2.warnings.size(), 1u);
  EXPECT_NE(m2.warnings[0].find("two"), std::string::npos);

  ElfBuilder plain(ElfSpec{});
  plain.add_load(".text", 0x401000, std::vector<std::uint8_t>(16, 0xc3), kPfR | kPfX);
  EXPECT_TRUE(read_build_metadata(parse_elf(to_bytes(plain.build()))).empty());
}

// --- real toolchains ------------------------------------------------------------

std::string Env(const char *name, const char *fallback) {
  const char *v = std::getenv(name);
  return v && *v ? v : fallback;
}

void WriteFile(const std::filesystem::path &p, std::string_view s) {
  std::filesystem::create_directories(p.parent_path());
  std::ofstream(p) << s;
}

bool RunQuiet(const std::string &cmd) { return std::system((cmd + " >/dev/null 2>&1").c_str()) == 0; }

// A module with a dependency replaced by a local directory (no network),
// in a git repository so the build stamps vcs settings.
std::filesystem::path GoModule(const std::string &name, const std::string &go_line) {
  auto dir = scratch_dir(name);
  WriteFile(dir / "go.mod", "module example.com/hello\n\ngo " + go_line +
                                "\n\nrequire example.com/dep v0.1.0\n\nreplace example.com/dep => ./dep\n");
  WriteFile(dir / "dep/go.mod", "module example.com/dep\n\ngo " + go_line + "\n");
  WriteFile(dir / "dep/dep.go", "package dep\n\nfunc Greeting() string { return \"hello from dep\" }\n");
  WriteFile(dir / "main.go",
            "package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/dep\"\n)\n\nfunc main() { fmt.Println(dep.Greeting()) }\n");
  RunQuiet("cd " + dir.string() + " && git init -q . && git add -A && git -c user.email=t@example.com -c user.name=t commit -qm init");
  return dir;
}

std::optional<GoBuildInfo> GoBuild(const std::string &go, const std::filesystem::path &dir, const std::string &env,
                                   const std::string &flags, const std::string &out, std::string *error) {
  // GOFLAGS=-p=2: two compiles at a time; the user's build cache is reused.
  const std::string cmd = "cd " + dir.string() + " && env GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-p=2 GOWORK=off " + env +
                          " " + go + " build " + flags + " -o " + out + " .";
  if (!RunQuiet(cmd)) {
    *error = "go build failed: " + cmd;
    return std::nullopt;
  }
  Image img = load_file(dir / out);
  return read_go_buildinfo(img, error);
}

TEST(GoBuildInfoReal, CurrentGo) {
  const std::string go = Env("RK_GO", REVKIT_TEST_GO);
  if (go.empty()) GTEST_SKIP() << "no Go toolchain (set RK_GO)";
  auto dir = GoModule("go-new", "1.21");
  std::string error;
  auto g = GoBuild(go, dir, "CGO_ENABLED=0", "-ldflags=\"-s -w -X main.v=1\"", "hello", &error);
  ASSERT_TRUE(g) << error;
  EXPECT_TRUE(g->inline_strings);
  EXPECT_TRUE(g->go_version.starts_with("go1.")) << g->go_version;
  EXPECT_EQ(g->path, "example.com/hello");
  ASSERT_TRUE(g->main);
  EXPECT_EQ(g->main->path, "example.com/hello");
  ASSERT_EQ(g->deps.size(), 1u);
  EXPECT_EQ(g->deps[0].path, "example.com/dep");
  EXPECT_EQ(g->deps[0].version, "v0.1.0");
  ASSERT_TRUE(g->deps[0].replacement);
  EXPECT_EQ(g->deps[0].replacement->path, "./dep");
  ASSERT_TRUE(g->setting("-ldflags"));
  EXPECT_EQ(*g->setting("-ldflags"), "-s -w -X main.v=1");
  EXPECT_EQ(*g->setting("CGO_ENABLED"), "0");
  EXPECT_EQ(*g->setting("GOOS"), "linux");
  // (-trimpath would leave -ldflags out: they may hold paths.)
  ASSERT_TRUE(g->setting("vcs.revision"));
  EXPECT_EQ(g->setting("vcs.revision")->size(), 40u);
  EXPECT_TRUE(g->setting("vcs.time"));
  EXPECT_TRUE(g->unparsed.empty()) << g->unparsed[0];

  // The same module as a Windows PE: found in .data.
  auto pe = GoBuild(go, dir, "CGO_ENABLED=0 GOOS=windows GOARCH=amd64", "", "hello.exe", &error);
  ASSERT_TRUE(pe) << error;
  EXPECT_EQ(*pe->setting("GOOS"), "windows");
  EXPECT_EQ(pe->deps.size(), 1u);
}

TEST(GoBuildInfoReal, GoBefore118PointerFormat) {
  const std::string go = Env("RK_GO_OLD", "");
  if (go.empty()) GTEST_SKIP() << "no Go before 1.18 (set RK_GO_OLD to its go binary)";
  auto dir = GoModule("go-old", "1.17");
  std::string error;
  for (const auto &[env, flags, out] : std::vector<std::tuple<std::string, std::string, std::string>>{
           {"CGO_ENABLED=0", "", "hello"},
           {"CGO_ENABLED=0", "-buildmode=pie", "hello-pie"},  // pointers with RELATIVE relocations
           {"CGO_ENABLED=0 GOOS=windows", "", "hello.exe"},
       }) {
    auto g = GoBuild(go, dir, env, flags, out, &error);
    ASSERT_TRUE(g) << out << ": " << error;
    EXPECT_FALSE(g->inline_strings) << out;
    EXPECT_EQ(g->pointer_size, 8u);
    EXPECT_TRUE(g->go_version.starts_with("go1.1")) << g->go_version;
    EXPECT_EQ(g->path, "example.com/hello") << out;
    ASSERT_EQ(g->deps.size(), 1u) << out;
    ASSERT_TRUE(g->deps[0].replacement) << out;
    EXPECT_EQ(g->deps[0].replacement->path, "./dep");
  }
}

TEST(RustAuditReal, CargoAuditable) {
  const std::string cargo = Env("RK_CARGO", REVKIT_TEST_CARGO);
  if (cargo.empty()) GTEST_SKIP() << "no cargo (set RK_CARGO)";
  const auto bin = std::filesystem::path(cargo).parent_path();
  if (!std::filesystem::exists(bin / "cargo-auditable")) GTEST_SKIP() << "no cargo-auditable beside cargo";
  auto dir = scratch_dir("rust-audit");
  WriteFile(dir / "Cargo.toml",
            "[package]\nname = \"hello\"\nversion = \"0.3.1\"\nedition = \"2021\"\n\n[dependencies]\n"
            "dep = { path = \"dep\" }\n");
  WriteFile(dir / "dep/Cargo.toml", "[package]\nname = \"dep\"\nversion = \"1.2.3\"\nedition = \"2021\"\n");
  WriteFile(dir / "dep/src/lib.rs", "pub fn greeting() -> &'static str { \"hi\" }\n");
  WriteFile(dir / "src/main.rs", "fn main() { println!(\"{}\", dep::greeting()); }\n");
  const std::string cmd = "cd " + dir.string() + " && env PATH=" + bin.string() + ":$PATH CARGO_TARGET_DIR=" +
                          (dir / "target").string() + " " + cargo + " auditable build --offline -j2";
  ASSERT_TRUE(RunQuiet(cmd)) << cmd;
  Image img = load_file(dir / "target/debug/hello");
  BuildMetadata m = read_build_metadata(img);
  ASSERT_TRUE(m.rust) << (m.warnings.empty() ? "" : m.warnings[0]);
  ASSERT_EQ(m.rust->packages.size(), 2u);
  ASSERT_TRUE(m.rust->root);
  const RustPackage &root = m.rust->packages[*m.rust->root];
  EXPECT_EQ(root.name, "hello");
  EXPECT_EQ(root.version, "0.3.1");
  EXPECT_EQ(root.source, "local");
  ASSERT_EQ(root.dependencies.size(), 1u);
  EXPECT_EQ(m.rust->packages[root.dependencies[0]].name, "dep");
  EXPECT_TRUE(m.rustc_version.starts_with("rustc version 1.")) << m.rustc_version;
  EXPECT_FALSE(m.rustc_commits.empty());
  EXPECT_FALSE(m.go);
}

}  // namespace
}  // namespace revkit::loader
