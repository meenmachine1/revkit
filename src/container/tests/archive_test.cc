// The framework (paths, the tree, links, limits, sessions and nesting) and
// the archive formats: zip, tar and single-file compression.
#include "fixtures.hh"
#include "revkit/container/decompress.hh"

namespace revkit::container {
namespace {

using namespace testing;

std::shared_ptr<Session> open_path(const fs::path &p, Limits limits = {}) {
  return Session::open(open_host_file(p.string()), p.filename().string(), limits);
}

TEST(ContainerPaths, EncodeAndDecode) {
  EXPECT_EQ(encode_component("a b.txt"), "a b.txt");
  EXPECT_EQ(encode_component("x!y%z/w"), "x%21y%25z%2Fw");
  EXPECT_EQ(encode_component(std::string("\x01\xff", 2)), "%01%FF");
  EXPECT_EQ(encode_component("caf\xc3\xa9"), "caf\xc3\xa9");
  EXPECT_EQ(decode_component("x%21y%25z%2Fw"), "x!y%z/w");
  EXPECT_THROW(decode_component("%G1"), Error);
  EXPECT_THROW(decode_component("%4"), Error);
  EXPECT_EQ(split_path("/a//./b%21/"), (std::vector<std::string>{"a", "b!"}));
  EXPECT_EQ(join_path({"a", "b!"}), "/a/b%21");
  // Display: invalid UTF-8, controls and bidirectional overrides are U+FFFD.
  EXPECT_EQ(display_name("ok\xff"), "ok\xEF\xBF\xBD");
  EXPECT_EQ(display_name("a\nb"), "a\xEF\xBF\xBD" "b");
  EXPECT_EQ(display_name("evil\xE2\x80\xAEtxt.exe"), "evil\xEF\xBF\xBDtxt.exe");
}

class TestFs : public FileSystem {
 public:
  std::shared_ptr<Source> open(std::uint32_t, const Context &) const override { throw Error("no"); }
  FileSystem &self() { return *this; }
};

TEST(ContainerTree, NormalizesNamesAndClashes) {
  TestFs fs;
  Limits limits;
  TreeBuilder t(fs, limits);
  Entry f;
  f.kind = Kind::file;
  t.add_path("../../etc/passwd", f);
  t.add_path("/abs/x", f);
  t.add_path("./a/./b", f);
  t.add_path("a/b", f);  // the same file again: replaces
  t.add_path("a/b/c", f);  // a directory where a file is: renamed
  t.finish();
  auto p = fs.find({"etc", "passwd"}, false);
  ASSERT_TRUE(p);
  EXPECT_TRUE(fs.entry(*p).renamed);
  EXPECT_NE(fs.entry(*p).note.find("../../etc/passwd"), std::string::npos);
  EXPECT_TRUE(fs.find({"abs", "x"}, false));
  EXPECT_TRUE(fs.find({"a", "b"}, false));
  EXPECT_TRUE(fs.find({"a", "b~2", "c"}, false));
  EXPECT_EQ(fs.path_of(*fs.find({"a", "b~2", "c"}, false)), "/a/b~2/c");
}

TEST(ContainerTree, EntryLimit) {
  TestFs fs;
  Limits limits;
  limits.max_entries = 10;
  TreeBuilder t(fs, limits);
  Entry f;
  f.kind = Kind::file;
  EXPECT_THROW(
      {
        for (int i = 0; i < 20; ++i) t.add_path("f" + std::to_string(i), f);
      },
      LimitError);
}

TEST(ContainerTree, SymlinksStayInside) {
  TestFs fs;
  Limits limits;
  TreeBuilder t(fs, limits);
  Entry f;
  f.kind = Kind::file;
  t.add_path("etc/passwd", f);
  Entry l;
  l.kind = Kind::symlink;
  l.link_target = "../../../../etc/passwd";  // escapes: stops at the root
  t.add_path("x/up", l);
  l.link_target = "/etc/passwd";  // absolute: from the container's root
  t.add_path("x/abs", l);
  l.link_target = "loop2";
  t.add_path("loop1", l);
  l.link_target = "loop1";
  t.add_path("loop2", l);
  l.link_target = "self/x";
  t.add_path("self", l);
  t.finish();
  const auto passwd = fs.find({"etc", "passwd"}, false);
  EXPECT_EQ(fs.find({"x", "up"}, true), passwd);
  EXPECT_EQ(fs.find({"x", "abs"}, true), passwd);
  EXPECT_THROW(fs.find({"loop1"}, true), LimitError);
  EXPECT_THROW(fs.find({"self"}, true), LimitError);
  EXPECT_TRUE(fs.find({"loop1"}, false));  // the link itself is listable
}

TEST(ContainerDecompress, Lz4AndLzoBlocks) {
  // LZ4: "abcabcabcabcabc" as literals "abc" then a match of 12 at offset 3.
  const std::vector<std::byte> lz4 = {std::byte{0x38}, std::byte{'a'}, std::byte{'b'}, std::byte{'c'},
                                      std::byte{3},    std::byte{0},   std::byte{0x30}, std::byte{'x'},
                                      std::byte{'y'},  std::byte{'z'}};
  std::vector<std::byte> out;
  lz4_decode_block(lz4, out, 100);
  EXPECT_EQ(text(out), "abcabcabcabcabcxyz");
  out.clear();
  EXPECT_THROW(lz4_decode_block(lz4, out, 10), Error);
  // A match before the start.
  const std::vector<std::byte> bad = {std::byte{0x10}, std::byte{'a'}, std::byte{9}, std::byte{0}};
  out.clear();
  EXPECT_THROW(lz4_decode_block(bad, out, 100), Error);
  // LZO1X: 4 literals "abcd" (first byte 17 + 4), then the end marker.
  const std::vector<std::byte> lzo = {std::byte{21}, std::byte{'a'}, std::byte{'b'}, std::byte{'c'},
                                      std::byte{'d'}, std::byte{0x11}, std::byte{0},   std::byte{0}};
  out.clear();
  lzo1x_decode(lzo, out, 100);
  EXPECT_EQ(text(out), "abcd");
  out.clear();
  EXPECT_THROW(lzo1x_decode(std::span(lzo).first(4), out, 100), Error);
}

TEST(ContainerZip, ListsAndReads) {
  if (!have_tool("zip")) GTEST_SKIP() << "zip is not installed";
  TempDir d;
  make_tree(d / "src");
  ASSERT_TRUE(sh("cd " + (d / "src").string() + " && zip -qry ../t.zip ."));
  auto s = open_path(d / "t.zip");
  EXPECT_EQ(s->root_format(), "zip");
  expect_tree(*s);
  EXPECT_EQ(s->container_path("/bin/true"), "zip://t.zip!/bin/true");
  EXPECT_NE(s->root()->description().find("zip archive"), std::string::npos);
}

TEST(ContainerZip, Python_Zip64AndMethods) {
  TempDir d;
  const std::string script = R"(
import sys, zipfile
p = sys.argv[1]
with zipfile.ZipFile(p, 'w') as z:
    z.writestr('stored.txt', 'stored data', compress_type=zipfile.ZIP_STORED)
    z.writestr('deflated.txt', 'deflated ' * 100, compress_type=zipfile.ZIP_DEFLATED)
    z.writestr('bz.txt', 'bzip2 ' * 100, compress_type=zipfile.ZIP_BZIP2)
    z.writestr('lz.txt', 'lzma ' * 100, compress_type=zipfile.ZIP_LZMA)
    with z.open('big64.bin', 'w', force_zip64=True) as f:
        f.write(b'z' * 1000)
)";
  std::ofstream(d / "mk.py") << script;
  ASSERT_TRUE(sh(py() + " " + (d / "mk.py").string() + " " + (d / "m.zip").string()));
  auto s = open_path(d / "m.zip");
  EXPECT_EQ(read_all(*s->open_file("/stored.txt")), "stored data");
  EXPECT_EQ(s->open_file("/deflated.txt")->size(), 900u);
  EXPECT_EQ(s->open_file("/bz.txt")->size(), 600u);
  EXPECT_EQ(s->open_file("/big64.bin")->size(), 1000u);
  // Zip's own LZMA (method 14) is listed with the reason it can't be read.
  auto lz = s->locate("/lz.txt", false);
  EXPECT_NE(lz.fs->entry(lz.entry).note.find("method 14"), std::string::npos);
  EXPECT_THROW(s->open_file("/lz.txt"), Error);
}

TEST(ContainerTar, ListsAndReads) {
  if (!have_tool("tar")) GTEST_SKIP() << "tar is not installed";
  TempDir d;
  make_tree(d / "src");
  ASSERT_TRUE(sh("tar -C " + (d / "src").string() + " -cf " + (d / "t.tar").string() + " ."));
  ASSERT_TRUE(sh("tar -C " + (d / "src").string() + " --format=posix -cf " + (d / "p.tar").string() + " ."));
  for (const char *name : {"t.tar", "p.tar"}) {
    auto s = open_path(d / name);
    EXPECT_EQ(s->root_format(), "tar");
    expect_tree(*s);
  }
}

TEST(ContainerTar, LongNamesAndHardLinks) {
  TempDir d;
  const std::string script = R"(
import io, sys, tarfile
p = sys.argv[1]
long = 'x' * 150 + '/' + 'y' * 120
with tarfile.open(p, 'w', format=tarfile.GNU_FORMAT) as t:
    data = b'long name data'
    i = tarfile.TarInfo(long); i.size = len(data); t.addfile(i, io.BytesIO(data))
    h = tarfile.TarInfo('hard'); h.type = tarfile.LNKTYPE; h.linkname = long; t.addfile(h)
)";
  std::ofstream(d / "mk.py") << script;
  ASSERT_TRUE(sh(py() + " " + (d / "mk.py").string() + " " + (d / "l.tar").string()));
  auto s = open_path(d / "l.tar");
  const std::string long_path = "/" + std::string(150, 'x') + "/" + std::string(120, 'y');
  EXPECT_EQ(read_all(*s->open_file(long_path)), "long name data");
  EXPECT_EQ(read_all(*s->open_file("/hard")), "long name data");
}

TEST(ContainerCompressed, EveryCodec) {
  TempDir d;
  make_tree(d / "src");
  struct Tool {
    const char *tool, *cmd, *file, *format;
  };
  const Tool tools[] = {
      {"gzip", "gzip -kc", "x.gz", "gzip"}, {"bzip2", "bzip2 -kc", "x.bz2", "bzip2"},
      {"xz", "xz -kc", "x.xz", "xz"},       {"zstd", "zstd -qc", "x.zst", "zstd"},
      {"lzma", "lzma -kc", "x.lzma", "lzma"}, {"lz4", "lz4 -qc", "x.lz4", "lz4"},
  };
  const std::string input = (d / "src/bin/true").string();
  for (const Tool &t : tools) {
    if (!have_tool(t.tool)) {
      std::printf("[  SKIP    ] %s is not installed\n", t.tool);
      continue;
    }
    ASSERT_TRUE(sh(std::string(t.cmd) + " " + input + " > " + (d / t.file).string())) << t.tool;
    auto s = open_path(d / t.file);
    EXPECT_EQ(s->root_format(), t.format);
    ASSERT_EQ(s->root()->entries().size(), 2u);
    const std::string inner = "/" + s->root()->entry(1).name;
    EXPECT_EQ(s->open_file(inner)->size(), fs::file_size(input)) << t.tool;
    EXPECT_EQ(s->describe(s->locate(inner, false)).kind, "elf") << t.tool;
  }
  // gzip keeps the original name.
  ASSERT_TRUE(sh("gzip -c " + input + " > " + (d / "renamed.bin").string()));
  auto s = open_path(d / "renamed.bin");
  EXPECT_EQ(s->root()->entry(1).name, "true");
}

TEST(ContainerCompressed, Python_Lz4Frame) {
  // No lz4 tool here: a frame written by hand (uncompressed and compressed
  // blocks, linked), as the format describes it.
  TempDir d;
  const std::string script = R"(
import struct, sys
def block_lit(data):  # one LZ4 block: all literals
    n = len(data); out = bytearray()
    if n >= 15:
        out.append(0xF0); k = n - 15
        while k >= 255: out.append(255); k -= 255
        out.append(k)
    else:
        out.append(n << 4)
    return bytes(out) + data
frame = struct.pack('<I', 0x184D2204) + bytes([0x40 | 0x20, 0x40, 0])  # independent blocks, 64 KiB
b1 = b'hello ' * 10
frame += struct.pack('<I', len(b1) | 0x80000000) + b1           # stored
b2 = block_lit(b'world ' * 10)
frame += struct.pack('<I', len(b2)) + b2                         # compressed
frame += struct.pack('<I', 0)
open(sys.argv[1], 'wb').write(frame)
)";
  std::ofstream(d / "mk.py") << script;
  ASSERT_TRUE(sh(py() + " " + (d / "mk.py").string() + " " + (d / "x.lz4").string()));
  auto s = open_path(d / "x.lz4");
  EXPECT_EQ(s->root_format(), "lz4");
  EXPECT_EQ(read_all(*s->open_file("/x")), std::string("hello hello hello hello hello hello hello hello hello hello ") +
                                               "world world world world world world world world world world ");
}

// An .ipk-like nesting, by magic only: outer.zip holds mid.tgz (gzip) holding
// mid.tar holding inner.dat (a zip, named so its extension says nothing)
// holding bin/true.
TEST(ContainerNesting, ThreeDeep) {
  if (!have_tool("zip") || !have_tool("tar")) GTEST_SKIP() << "zip or tar is not installed";
  TempDir d;
  make_tree(d / "src");
  ASSERT_TRUE(sh("cd " + (d / "src").string() + " && zip -qry ../inner.dat ."));
  fs::create_directories(d / "mid");
  fs::rename(d / "inner.dat", d / "mid/inner.dat");
  ASSERT_TRUE(sh("tar -C " + (d / "mid").string() + " -czf " + (d / "mid.tgz").string() + " ."));
  ASSERT_TRUE(sh("cd " + d.path().string() + " && zip -q outer.zip mid.tgz"));
  auto s = open_path(d / "outer.zip");
  const std::string prefix = "/mid.tgz!/mid.tar!/inner.dat!";
  expect_tree(*s, prefix);
  EXPECT_EQ(s->container_path(prefix + "/bin/true"), "zip://outer.zip!/mid.tgz!/mid.tar!/inner.dat!/bin/true");
  auto n = s->locate(prefix + "/bin/true", false);
  EXPECT_EQ(n.depth, 4u);
  // Too deep for a smaller limit.
  Limits shallow;
  shallow.max_depth = 3;
  auto s2 = open_path(d / "outer.zip", shallow);
  EXPECT_THROW(s2->locate(prefix + "/bin/true", false), LimitError);
  // Not a container where a layer is expected.
  EXPECT_THROW(s->locate(prefix + "/bin/true!/x", false), Error);
}

// ---- hostile input -------------------------------------------------------------------

TEST(ContainerHostile, ZipBomb) {
  TempDir d;
  const std::string script = R"(
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('zeros.bin', bytes(48 << 20))
)";
  std::ofstream(d / "mk.py") << script;
  ASSERT_TRUE(sh(py() + " " + (d / "mk.py").string() + " " + (d / "bomb.zip").string()));
  // Per-file size.
  Limits small;
  small.max_file_bytes = 16 << 20;
  EXPECT_THROW(open_path(d / "bomb.zip", small)->open_file("/zeros.bin"), LimitError);
  // Ratio (48 MiB from ~48 KiB is 1000:1).
  Limits ratio;
  ratio.ratio_floor = 4 << 20;
  ratio.max_ratio = 100;
  EXPECT_THROW(open_path(d / "bomb.zip", ratio)->open_file("/zeros.bin"), LimitError);
  // The session's budget.
  Limits budget;
  budget.max_total_bytes = 8 << 20;
  EXPECT_THROW(open_path(d / "bomb.zip", budget)->open_file("/zeros.bin"), LimitError);
  // The head (for the listing's guess) is cheap and allowed.
  auto s = open_path(d / "bomb.zip", small);
  EXPECT_EQ(s->describe(s->locate("/zeros.bin", false)).kind, "raw");
}

TEST(ContainerHostile, OverlappingZip) {
  // Two central directory entries sharing one member's data (Fifield's
  // "better zip bomb" construction): the second is refused.
  TempDir d;
  const std::string script = R"(
import struct, sys, zlib
data = zlib.compress(bytes(1 << 20))[2:-4]
crc = zlib.crc32(bytes(1 << 20))
name = b'a'
local = struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, 0, 8, 0, 0, crc, len(data), 1 << 20, len(name), 0) + name + data
cd = b''
for n in (b'a', b'b'):
    cd += struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, 0, 8, 0, 0, crc, len(data), 1 << 20, len(n), 0, 0, 0, 0, 0, 0) + n
eocd = struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, 2, 2, len(cd), len(local), 0)
open(sys.argv[1], 'wb').write(local + cd + eocd)
)";
  std::ofstream(d / "mk.py") << script;
  ASSERT_TRUE(sh(py() + " " + (d / "mk.py").string() + " " + (d / "o.zip").string()));
  auto s = open_path(d / "o.zip");
  EXPECT_EQ(s->open_file("/a")->size(), 1u << 20);
  EXPECT_THROW(s->open_file("/b"), Error);
  EXPECT_FALSE(s->root()->warnings().empty());
}

TEST(ContainerHostile, TraversalNamesAndLinks) {
  TempDir d;
  const std::string script = R"(
import io, sys, tarfile
with tarfile.open(sys.argv[1], 'w') as t:
    for name in ('../../evil.txt', '/etc/shadow', 'a/../../../b.txt', 'ok/../c.txt'):
        data = name.encode()
        i = tarfile.TarInfo(name); i.size = len(data); t.addfile(i, io.BytesIO(data))
    for name, target in (('loop1', 'loop2'), ('loop2', 'loop1'), ('self', 'self/x'),
                         ('escape', '../../../../../etc/shadow'), ('abs', '/etc/shadow'),
                         ('dangling', '../nowhere')):
        l = tarfile.TarInfo(name); l.type = tarfile.SYMTYPE; l.linkname = target; t.addfile(l)
    nul = tarfile.TarInfo('ctrl\x01name\xff'.encode('latin-1').decode('utf-8', 'surrogateescape'))
    nul.size = 1; t.addfile(nul, io.BytesIO(b'x'))
)";
  std::ofstream(d / "mk.py") << script;
  ASSERT_TRUE(sh(py() + " " + (d / "mk.py").string() + " " + (d / "h.tar").string()));
  auto s = open_path(d / "h.tar");
  // Names are normalized inside the container, never outside it.
  EXPECT_EQ(read_all(*s->open_file("/evil.txt")), "../../evil.txt");
  EXPECT_EQ(read_all(*s->open_file("/etc/shadow")), "/etc/shadow");
  EXPECT_EQ(read_all(*s->open_file("/b.txt")), "a/../../../b.txt");
  EXPECT_EQ(read_all(*s->open_file("/c.txt")), "ok/../c.txt");
  auto evil = s->locate("/evil.txt", false);
  EXPECT_TRUE(evil.fs->entry(evil.entry).renamed);
  // Links resolve inside the container: escaping ones land on its root.
  EXPECT_EQ(read_all(*s->open_file("/escape")), "/etc/shadow");
  EXPECT_EQ(read_all(*s->open_file("/abs")), "/etc/shadow");
  EXPECT_THROW(s->open_file("/loop1"), LimitError);
  EXPECT_THROW(s->open_file("/self"), LimitError);
  EXPECT_THROW(s->open_file("/dangling"), Error);
  // A name with control bytes and invalid UTF-8: encoded for the API.
  bool found = false;
  for (std::uint32_t c : s->root()->entry(0).children) {
    const std::string p = s->root()->path_of(c);
    if (p.find("ctrl") != std::string::npos) {
      EXPECT_EQ(p, "/ctrl%01name%FF");
      EXPECT_EQ(read_all(*s->open_file(p)), "x");
      found = true;
    }
  }
  EXPECT_TRUE(found);
}

TEST(ContainerHostile, TruncatedAndGarbage) {
  TempDir d;
  if (!have_tool("zip")) GTEST_SKIP() << "zip is not installed";
  make_tree(d / "src");
  ASSERT_TRUE(sh("cd " + (d / "src").string() + " && zip -qry ../t.zip . && tar -cf ../t.tar . && gzip -c ../t.tar > ../t.tgz"));
  for (const char *name : {"t.zip", "t.tar", "t.tgz"}) {
    auto bytes = read_file(d / name);
    // Every prefix and a few corruptions: errors, never crashes.
    for (std::size_t cut : {std::size_t{0}, std::size_t{10}, bytes.size() / 3, bytes.size() / 2, bytes.size() - 1}) {
      std::vector<std::byte> part(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(cut));
      try {
        auto s = Session::open(memory_source(part), name, Limits{});
        for (std::uint32_t i = 0; i < s->root()->entries().size(); ++i) {
          try {
            auto n = s->locate(s->root()->path_of(i), false);
            if (n.fs->entry(n.entry).kind == Kind::file) s->open_file(s->root()->path_of(i));
          } catch (const Error &) {
          }
        }
      } catch (const Error &) {
      }
    }
    for (std::size_t k = 0; k < 64; ++k) {
      auto copy = bytes;
      copy[(k * 7919) % copy.size()] ^= std::byte{0x5a};
      try {
        auto s = Session::open(memory_source(copy), name, Limits{});
        for (std::uint32_t i = 1; i < s->root()->entries().size(); ++i) try {
            s->open_file(s->root()->path_of(i));
          } catch (const Error &) {
          }
      } catch (const Error &) {
      }
    }
  }
}

// A zero-length read: read_exact of 0 bytes passed memcpy a null buffer,
// undefined even for 0 bytes (UBSan, extract_fuzzer: a zip whose header
// named an empty extra field). The asan preset runs UBSan fatal.
TEST(ContainerHostile, ZeroLengthReads) {
  auto src = memory_source({std::byte{1}, std::byte{2}});
  EXPECT_TRUE(src->read_exact(0, 0, "nothing").empty());
  EXPECT_TRUE(src->read_exact(2, 0, "nothing at the end").empty());
  std::vector<std::byte> none;
  EXPECT_EQ(src->read(0, none), 0u);
}

TEST(ContainerHostile, TarSizeWrapsToItsOwnHeader) {
  // A global header whose base-256 size is 2^64 - 512: the next header's
  // offset wrapped around to this one, and the parser looped forever.
  std::vector<std::byte> b(1024);
  auto put = [&](std::size_t off, std::string_view s) {
    for (std::size_t i = 0; i < s.size(); ++i) b[off + i] = static_cast<std::byte>(s[i]);
  };
  put(0, "g");
  put(257, std::string_view("ustar\0" "00", 8));
  b[156] = std::byte{'g'};
  b[124] = std::byte{0x80};
  for (std::size_t i = 128; i < 135; ++i) b[i] = std::byte{0xff};
  b[134] = std::byte{0xfe};
  unsigned sum = 0;
  for (std::size_t i = 0; i < 512; ++i) sum += (i >= 148 && i < 156) ? ' ' : std::to_integer<unsigned>(b[i]);
  char ck[8];
  std::snprintf(ck, sizeof ck, "%06o", sum);
  put(148, std::string_view(ck, 7));
  Context ctx;
  int polls = 0;
  ctx.cancelled = [&] { return ++polls > 10000; };
  try {
    open_format("tar", memory_source(b), "x.tar", ctx);
    ADD_FAILURE() << "opened";
  } catch (const Error &e) {
    EXPECT_NE(std::string(e.what()).find("overflows"), std::string::npos) << e.what();
  }
  EXPECT_LT(polls, 10);
}

TEST(ContainerDir, HostDirectoryDoesNotFollowLinksOut) {
  TempDir d;
  make_tree(d / "root");
  std::ofstream(d / "outside.txt") << "outside";
  fs::create_symlink(d / "outside.txt", d / "root/out-abs");
  fs::create_symlink("../outside.txt", d / "root/out-rel");
  auto s = Session::open_directory((d / "root").string(), Limits{});
  expect_tree(*s);
  EXPECT_THROW(s->open_file("/out-abs"), Error);
  EXPECT_THROW(s->open_file("/out-rel"), Error);
  EXPECT_EQ(s->container_path("/bin/true"), "file://" + (d / "root").string() + "/bin/true");
}

}  // namespace
}  // namespace revkit::container
