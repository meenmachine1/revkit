// The file system formats: cpio, ar, ISO 9660, squashfs (every
// compressor), ext2/3/4, cramfs (both byte orders), FAT12/16/32, uImage,
// Android boot images, UF2 and partition tables, from fixtures made with
// the standard tools (or Python where none is installed); nesting through
// them; and their hostile cases.
#include "fixtures.hh"

#include <chrono>

namespace revkit::container {
namespace {

using namespace testing;

std::shared_ptr<Session> open_path(const fs::path &p, Limits limits = {}) {
  return Session::open(open_host_file(p.string()), p.filename().string(), limits);
}

TEST(ContainerCpio, NewcOdcAndBinary) {
  if (!have_tool("cpio")) GTEST_SKIP() << "cpio is not installed";
  TempDir d;
  make_tree(d / "src");
  // A hard link: newc keeps the data with the last name.
  fs::create_hard_link(d / "src/etc/config.txt", d / "src/etc/hard.txt");
  for (const char *format : {"newc", "odc", "bin"}) {
    const fs::path out = d / (std::string(format) + ".cpio");
    ASSERT_TRUE(sh("cd " + (d / "src").string() + " && find . | sort | cpio -o -H " + format + " > " + out.string()));
    auto s = open_path(out);
    EXPECT_EQ(s->root_format(), "cpio") << format;
    if (std::string(format) == "bin") {
      // The old binary format keeps 16-bit sizes and modes: a smaller check.
      EXPECT_EQ(read_all(*s->open_file("/etc/config.txt")), "hello config\n");
      continue;
    }
    expect_tree(*s);
    EXPECT_EQ(read_all(*s->open_file("/etc/hard.txt")), "hello config\n") << format;
  }
  // An initramfs: gzip around newc.
  ASSERT_TRUE(sh("cd " + (d / "src").string() + " && find . | cpio -o -H newc | gzip > " + (d / "initrd.img").string()));
  auto s = open_path(d / "initrd.img");
  expect_tree(*s, "/initrd.img.out!");
}

TEST(ContainerAr, StaticLibraryAndDeb) {
  if (!have_tool("ar") || !have_tool("tar")) GTEST_SKIP() << "ar or tar is not installed";
  TempDir d;
  make_tree(d / "src");
  std::ofstream(d / "a_member_with_a_long_name_past_sixteen.o") << "long";
  std::ofstream(d / "short.o") << "short";
  ASSERT_TRUE(sh("cd " + d.path().string() + " && ar rc lib.a a_member_with_a_long_name_past_sixteen.o short.o"));
  auto lib = open_path(d / "lib.a");
  EXPECT_EQ(lib->root_format(), "ar");
  EXPECT_EQ(read_all(*lib->open_file("/a_member_with_a_long_name_past_sixteen.o")), "long");
  EXPECT_EQ(read_all(*lib->open_file("/short.o")), "short");
  // A .deb (or a new-style .ipk): ar of debian-binary, control.tar.gz, data.tar.xz.
  std::ofstream(d / "debian-binary") << "2.0\n";
  ASSERT_TRUE(sh("cd " + d.path().string() + " && tar -C src -czf control.tar.gz ./etc && tar -C src -cJf data.tar.xz . && "
                 "ar rc pkg.deb debian-binary control.tar.gz data.tar.xz"));
  auto deb = open_path(d / "pkg.deb");
  EXPECT_EQ(read_all(*deb->open_file("/debian-binary")), "2.0\n");
  expect_tree(*deb, "/data.tar.xz!/data.tar!");
}

TEST(ContainerIso, RockRidgeJolietAndPlain) {
  if (!have_tool("xorriso")) GTEST_SKIP() << "xorriso is not installed";
  TempDir d;
  make_tree(d / "src");
  std::ofstream(d / "src/Mixed Case Long Name.txt") << "long";
  ASSERT_TRUE(sh("xorriso -as mkisofs -quiet -R -J -o " + (d / "rr.iso").string() + " " + (d / "src").string()));
  ASSERT_TRUE(sh("xorriso -as mkisofs -quiet --norock -J -o " + (d / "joliet.iso").string() + " " + (d / "src").string()));
  ASSERT_TRUE(sh("xorriso -as mkisofs -quiet --norock -o " + (d / "plain.iso").string() + " " + (d / "src").string()));
  auto rr = open_path(d / "rr.iso");
  EXPECT_EQ(rr->root_format(), "iso9660");
  EXPECT_NE(rr->root()->description().find("Rock Ridge"), std::string::npos);
  expect_tree(*rr);
  EXPECT_EQ(read_all(*rr->open_file("/Mixed Case Long Name.txt")), "long");
  auto jo = open_path(d / "joliet.iso");
  EXPECT_NE(jo->root()->description().find("Joliet"), std::string::npos);
  EXPECT_EQ(read_all(*jo->open_file("/Mixed Case Long Name.txt")), "long");
  EXPECT_EQ(read_all(*jo->open_file("/etc/config.txt")), "hello config\n");
  auto plain = open_path(d / "plain.iso");
  // ISO level 1 names: upper case 8.3, version numbers dropped.
  EXPECT_EQ(read_all(*plain->open_file("/ETC/CONFIG.TXT")), "hello config\n");
}

TEST(ContainerSquashfs, EveryCompressor) {
  if (!have_tool("mksquashfs")) GTEST_SKIP() << "mksquashfs is not installed";
  TempDir d;
  make_tree(d / "src");
  // Larger than a block, a sparse stretch, and a fragment tail.
  {
    std::string big(300000, '\0');
    for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<char>((i * 7) % 251);
    std::fill(big.begin() + 140000, big.begin() + 270000, '\0');
    std::ofstream(d / "src/big.bin", std::ios::binary) << big;
  }
  const std::string want_big = text(read_file(d / "src/big.bin"));
  for (const char *comp : {"gzip", "xz", "zstd", "lzo", "lz4", "lzma"}) {
    const fs::path img = d / (std::string(comp) + ".sqfs");
    if (!sh(tool_path("mksquashfs") + " " + (d / "src").string() + " " + img.string() + " -comp " + comp + " -noappend -no-xattrs")) {
      std::printf("[  SKIP    ] mksquashfs can't write %s here\n", comp);
      continue;
    }
    auto s = open_path(img);
    EXPECT_EQ(s->root_format(), "squashfs") << comp;
    EXPECT_NE(s->root()->description().find(comp), std::string::npos) << s->root()->description();
    expect_tree(*s);
    EXPECT_EQ(read_all(*s->open_file("/big.bin")), want_big) << comp;
  }
  // No fragments, and every file in fragments.
  for (const char *opt : {"-no-fragments", "-always-use-fragments"}) {
    const fs::path img = d / "opt.sqfs";
    ASSERT_TRUE(sh(tool_path("mksquashfs") + " " + (d / "src").string() + " " + img.string() + " -noappend " + opt));
    auto s = open_path(img);
    expect_tree(*s);
    EXPECT_EQ(read_all(*s->open_file("/big.bin")), want_big) << opt;
  }
}

TEST(ContainerExt, Ext2Ext3Ext4AndInlineData) {
  if (!have_tool("mke2fs")) GTEST_SKIP() << "mke2fs is not installed";
  TempDir d;
  make_tree(d / "src");
  {
    // Past the 12 direct blocks of a 1 KiB-block ext2: indirect blocks.
    std::string big(200000, 'x');
    for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<char>('a' + i % 26);
    std::ofstream(d / "src/big.txt") << big;
    fs::create_directories(d / "src/many");
    for (int i = 0; i < 300; ++i) std::ofstream(d / "src/many" / ("f" + std::to_string(i))) << i;
  }
  const std::string want_big = text(read_file(d / "src/big.txt"));
  struct Case {
    const char *type, *opts, *name;
  };
  const Case cases[] = {
      {"ext2", "-b 1024", "ext2"},
      {"ext3", "-b 1024", "ext3"},
      {"ext4", "", "ext4"},
      {"ext4", "-O inline_data", "ext4 inline"},
      {"ext4", "-O 64bit,meta_bg,^resize_inode -b 1024", "ext4 64bit meta_bg"},
  };
  for (const Case &c : cases) {
    const fs::path img = d / "fs.img";
    fs::remove(img);
    if (!sh(tool_path("mke2fs") + " -q -F -t " + c.type + " " + c.opts + " -d " + (d / "src").string() + " " +
            img.string() + " 16M")) {
      std::printf("[  SKIP    ] mke2fs can't make %s here\n", c.name);
      continue;
    }
    auto s = open_path(img);
    EXPECT_EQ(s->root_format(), "ext") << c.name;
    EXPECT_NE(s->root()->description().find(c.type), std::string::npos) << s->root()->description();
    expect_tree(*s);
    EXPECT_EQ(read_all(*s->open_file("/big.txt")), want_big) << c.name;
    EXPECT_EQ(read_all(*s->open_file("/many/f299")), "299") << c.name;
    EXPECT_EQ(s->locate("/many", false).fs->entry(s->locate("/many", false).entry).children.size(), 300u);
  }
}

TEST(ContainerHostile, ExtSparseDirectoriesAndBlockMaps) {
  if (!have_tool("mke2fs") || !have_tool("debugfs")) GTEST_SKIP() << "mke2fs or debugfs is not installed";
  TempDir d;
  // Directories made 64 MiB of holes: each zero block was one warning
  // (65536 per directory), and each was held while its subdirectories were
  // read. One warning each now; past 1 GiB of directories in all, a limit.
  for (int count : {4, 20}) {
    fs::remove_all(d / "src");
    for (int i = 0; i < count; ++i) fs::create_directories(d / "src" / ("d" + std::to_string(i)));
    const fs::path img = d / "dirs.img";
    fs::remove(img);
    ASSERT_TRUE(sh(tool_path("mke2fs") + " -q -F -t ext2 -b 1024 -d " + (d / "src").string() + " " + img.string() + " 4M"));
    for (int i = 0; i < count; ++i)
      ASSERT_TRUE(sh(tool_path("debugfs") + " -w -R 'sif /d" + std::to_string(i) + " size 67108864' " + img.string()));
    if (count == 4) {
      auto s = open_path(img);
      EXPECT_LE(s->root()->warnings().size(), 4u);
    } else {
      EXPECT_THROW(open_path(img), LimitError);
    }
  }
  // A triple-indirect block naming one double-indirect block five times,
  // whose 1024 pointers name one block of 1024 copies of block 5: a run per
  // block, 5M of them (2^36 at full size). Over 4M is a limit, as for
  // extents.
  fs::remove_all(d / "src");
  fs::create_directories(d / "src");
  std::ofstream(d / "src/f") << "x";
  const fs::path img = d / "map.img";
  ASSERT_TRUE(sh(tool_path("mke2fs") + " -q -F -t ext2 -b 4096 -d " + (d / "src").string() + " " + img.string() + " 4M"));
  std::ofstream(d / "patch.py") << R"(
import re, struct, subprocess, sys
img, debugfs = sys.argv[1], sys.argv[2]
out = subprocess.run([debugfs, '-R', 'imap /f', img], capture_output=True, text=True).stdout
m = re.search(r'located at block (\d+), offset (0x[0-9a-f]+)', out)
bs = 4096
ino = int(m.group(1)) * bs + int(m.group(2), 16)
with open(img, 'r+b') as f:
    def put(at, data):
        f.seek(at)
        f.write(data)
    put(ino + 0x04, struct.pack('<I', 0))       # size 2^45
    put(ino + 0x6c, struct.pack('<I', 0x2000))
    put(ino + 0x60, struct.pack('<I', 1000))    # triple indirect
    put(1000 * bs, struct.pack('<5I', *[1001] * 5))
    put(1001 * bs, struct.pack('<1024I', *[1002] * 1024))
    put(1002 * bs, struct.pack('<1024I', *[5] * 1024))
)";
  ASSERT_TRUE(sh(py() + " " + (d / "patch.py").string() + " " + img.string() + " " + tool_path("debugfs")));
  auto s = open_path(img);
  // A file's blocks are distinct blocks of the image: this 4 MiB image has
  // 1,024, so the map stops there, in milliseconds instead of the seconds
  // 4M runs took (docs/bug-scrub.md, "ext CPU").
  const auto start = std::chrono::steady_clock::now();
  try {
    (void)s->open_file("/f");
    ADD_FAILURE() << "opened";
  } catch (const LimitError &e) {
    EXPECT_NE(std::string(e.what()).find("more blocks than the image has"), std::string::npos) << e.what();
  }
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(2));
}

TEST(ContainerHostile, SquashfsHardLinksShareTheirBlockList) {
  // Each directory entry of one inode copied its block list (64 MiB at
  // most); hard links now share one.
  if (!have_tool("mksquashfs")) GTEST_SKIP() << "mksquashfs is not installed";
  TempDir d;
  fs::create_directories(d / "src");
  std::ofstream(d / "src/a") << std::string(300000, 'q');
  fs::create_hard_link(d / "src/a", d / "src/b");
  const fs::path img = d / "l.sqfs";
  ASSERT_TRUE(sh(tool_path("mksquashfs") + " " + (d / "src").string() + " " + img.string() + " -noappend -b 4096"));
  auto s = open_path(img);
  auto a = s->locate("/a", false), b = s->locate("/b", false);
  EXPECT_EQ(a.fs->entry(a.entry).loc0, b.fs->entry(b.entry).loc0);
  EXPECT_EQ(read_all(*s->open_file("/b")), std::string(300000, 'q'));
}

// FAT directories whose chains share their clusters: 400 subdirectories
// of the root each start one cluster further along one 1000-cluster chain,
// so each reads up to 4 MiB of the same clusters again. With the root's
// 512 entries and 262,144 entries in all that is a terabyte to read from
// a 17 MB image; the directories read are now capped at 1 GiB in all.
TEST(ContainerHostile, FatDirectoriesSharingTheirChains) {
  const std::uint32_t bps = 512, spc = 8, reserved = 1, root_entries = 512, clusters = 4100;
  const std::uint32_t fat_sectors = (2 * (clusters + 2) + bps - 1) / bps;
  const std::uint32_t root_sectors = root_entries * 32 / bps;
  const std::uint32_t total = reserved + fat_sectors + root_sectors + clusters * spc;
  std::vector<std::byte> img(static_cast<std::size_t>(total) * bps);
  auto put8 = [&](std::size_t at, std::uint8_t v) { img[at] = std::byte{v}; };
  auto put16 = [&](std::size_t at, std::uint16_t v) {
    put8(at, static_cast<std::uint8_t>(v));
    put8(at + 1, static_cast<std::uint8_t>(v >> 8));
  };
  auto put32 = [&](std::size_t at, std::uint32_t v) {
    put16(at, static_cast<std::uint16_t>(v));
    put16(at + 2, static_cast<std::uint16_t>(v >> 16));
  };
  put8(0, 0xeb);
  put8(1, 0x3c);
  put8(2, 0x90);
  put16(11, bps);
  put8(13, spc);
  put16(14, reserved);
  put8(16, 1);
  put16(17, root_entries);
  put16(19, 0);
  put32(32, total);
  put8(21, 0xf8);
  put16(22, fat_sectors);
  for (std::size_t i = 0; i < 8; ++i) put8(54 + i, static_cast<std::uint8_t>("FAT16   "[i]));
  put8(510, 0x55);
  put8(511, 0xaa);
  // The FAT: clusters 3..1002 one chain.
  const std::size_t fat = reserved * bps;
  put16(fat, 0xfff8);
  put16(fat + 2, 0xffff);
  for (std::uint32_t c = 3; c < 1002; ++c) put16(fat + 2 * c, static_cast<std::uint16_t>(c + 1));
  put16(fat + 2 * 1002, 0xffff);
  // The root: 400 directories, the i-th starting at cluster 3 + i.
  const std::size_t root = (reserved + fat_sectors) * bps;
  for (std::uint32_t i = 0; i < 400; ++i) {
    char name[12];
    std::snprintf(name, sizeof name, "D%07u   ", i);
    const std::size_t e = root + 32 * i;
    for (int k = 0; k < 11; ++k) put8(e + k, static_cast<std::uint8_t>(name[k]));
    put8(e + 11, 0x10);
    put16(e + 26, static_cast<std::uint16_t>(3 + i));
  }
  Context ctx;
  ctx.budget = std::make_shared<Budget>(ctx.limits.max_total_bytes);
  try {
    auto opened = open_format("fat", memory_source(std::move(img)), "shared.img", ctx);
    ADD_FAILURE() << "opened: " << opened->description();
  } catch (const Error &e) {
    EXPECT_NE(std::string(e.what()).find("over 1 GiB of FAT directories"), std::string::npos) << e.what();
  }
}

TEST(ContainerCramfs, BothByteOrders) {
  if (!have_tool("mkfs.cramfs")) GTEST_SKIP() << "mkfs.cramfs is not installed";
  TempDir d;
  make_tree(d / "src");
  for (const char *endian : {"little", "big"}) {
    const fs::path img = d / (std::string(endian) + ".cramfs");
    ASSERT_TRUE(sh(tool_path("mkfs.cramfs") + " -N " + endian + " " + (d / "src").string() + " " + img.string()));
    auto s = open_path(img);
    EXPECT_EQ(s->root_format(), "cramfs");
    EXPECT_NE(s->root()->description().find(endian), std::string::npos) << s->root()->description();
    // cramfs keeps no times and 8-bit gids; modes it keeps.
    expect_tree(*s);
  }
}

// mkfs.fat formats; with no mtools here, Python writes the files (long
// names, subdirectories, cluster chains) into the formatted volume.
const char *kFatPopulate = R"(
import os, struct, sys
img, src = sys.argv[1], sys.argv[2]
data = bytearray(open(img, 'rb').read())
bps, spc, res, nf, rootent = struct.unpack_from('<HBHBH', data, 11)
ts16, = struct.unpack_from('<H', data, 19); fs16, = struct.unpack_from('<H', data, 22)
ts32, fs32 = struct.unpack_from('<II', data, 32)
fatsz, total = fs16 or fs32, ts16 or ts32
rootsec = (rootent * 32 + bps - 1) // bps
first = res + nf * fatsz + rootsec
clusters = (total - first) // spc
bits = 12 if clusters < 4085 else 16 if clusters < 65525 else 32
csize = bps * spc
EOC = {12: 0xFFF, 16: 0xFFFF, 32: 0x0FFFFFFF}[bits]
def set_fat(c, v):
    for k in range(nf):
        base = (res + k * fatsz) * bps
        if bits == 12:
            o = base + c + c // 2
            cur, = struct.unpack_from('<H', data, o)
            cur = (cur & 0x000F) | (v << 4) if c & 1 else (cur & 0xF000) | (v & 0xFFF)
            struct.pack_into('<H', data, o, cur & 0xFFFF)
        elif bits == 16:
            struct.pack_into('<H', data, base + 2 * c, v & 0xFFFF)
        else:
            struct.pack_into('<I', data, base + 4 * c, v & 0x0FFFFFFF)
free = [3 if bits == 32 else 2]
def alloc(n):
    start = free[0]; free[0] += n
    for i in range(n): set_fat(start + i, start + i + 1 if i < n - 1 else EOC)
    return start
def coff(c): return (first + (c - 2) * spc) * bps
count = [0]
def lfn(name, short):
    s = 0
    for b in short: s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
    u = name.encode('utf-16-le') + b'\0\0'
    if len(u) % 26: u += b'\xff' * (26 - len(u) % 26)
    parts = [u[i:i + 26] for i in range(0, len(u), 26)]
    out = []
    for i, ch in enumerate(parts):
        o = (i + 1) | (0x40 if i == len(parts) - 1 else 0)
        out.append(bytes([o]) + ch[0:10] + bytes([0x0F, 0, s]) + ch[10:22] + b'\0\0' + ch[22:26])
    return b''.join(reversed(out))
def entry(name, attr, cluster, size):
    count[0] += 1
    short = ('F%07d' % count[0]).encode() + b'BIN'
    e = short + bytes([attr, 0, 0]) + struct.pack('<HHHHHHHI', 0, 0x5021, 0x5021, cluster >> 16, 0x6000, 0x5021, cluster & 0xFFFF, size)
    return lfn(name, short) + e
def put(c, blob):
    data[coff(c):coff(c) + len(blob)] = blob
def children(path):
    return sorted(n for n in os.listdir(path) if not os.path.islink(os.path.join(path, n)))
def fill(path, me, parent):
    ents = b''
    if me:
        ents += b'.          ' + bytes([0x10, 0, 0]) + struct.pack('<HHHHHHHI', 0, 0, 0, me >> 16, 0, 0, me & 0xFFFF, 0)
        ents += b'..         ' + bytes([0x10, 0, 0]) + struct.pack('<HHHHHHHI', 0, 0, 0, parent >> 16, 0, 0, parent & 0xFFFF, 0)
    for n in children(path):
        p = os.path.join(path, n)
        if os.path.isdir(p):
            sub = make_dir(p, me)
            ents += entry(n, 0x10, sub, 0)
        else:
            blob = open(p, 'rb').read()
            c = alloc(max(1, (len(blob) + csize - 1) // csize)) if blob else 0
            if blob:
                for i in range(0, len(blob), csize): put(c + i // csize, blob[i:i + csize])
            ents += entry(n, 0x20, c, len(blob))
    return ents
def make_dir(path, parent):
    need = 64 + sum(32 * (2 + (len(n) * 2 + 2 + 25) // 26) for n in children(path))
    me = alloc((need + csize - 1) // csize)
    put(me, fill(path, me, parent))
    return me
if bits == 32:
    root, = struct.unpack_from('<I', data, 44)
    ents = fill(src, 0, 0)
    assert len(ents) <= csize, 'root too big for one cluster'
    put(root, ents)
else:
    ents = fill(src, 0, 0)
    off = (res + nf * fatsz) * bps
    assert len(ents) <= rootent * 32
    data[off:off + len(ents)] = ents
open(img, 'wb').write(data)
)";

TEST(ContainerFat, Fat12Fat16Fat32) {
  if (!have_tool("mkfs.fat")) GTEST_SKIP() << "mkfs.fat is not installed";
  TempDir d;
  fs::create_directories(d / "src/dir/sub");
  std::ofstream(d / "src/A Long File Name.txt") << "long name";
  std::ofstream(d / "src/dir/sub/deep.bin") << std::string(5000, 'z');
  fs::copy_file("/bin/true", d / "src/dir/true");
  std::ofstream(d / "pop.py") << kFatPopulate;
  struct Case {
    const char *bits, *size;
  };
  for (const Case c : {Case{"12", "2048"}, Case{"16", "20480"}, Case{"32", "40960"}}) {
    const fs::path img = d / ("fat" + std::string(c.bits) + ".img");
    ASSERT_TRUE(sh(tool_path("mkfs.fat") + " -F " + c.bits + " -s 1 -C " + img.string() + " " + c.size));
    ASSERT_TRUE(sh(py() + " " + (d / "pop.py").string() + " " + img.string() + " " + (d / "src").string())) << c.bits;
    auto s = open_path(img);
    EXPECT_EQ(s->root_format(), "fat") << c.bits;
    EXPECT_NE(s->root()->description().find("FAT" + std::string(c.bits)), std::string::npos) << s->root()->description();
    EXPECT_EQ(read_all(*s->open_file("/A Long File Name.txt")), "long name");
    EXPECT_EQ(read_all(*s->open_file("/dir/sub/deep.bin")), std::string(5000, 'z'));
    auto t = s->locate("/dir/true", false);
    EXPECT_EQ(s->describe(t).kind, "elf");
    EXPECT_EQ(s->open_file("/dir/true")->size(), fs::file_size("/bin/true"));
  }
}

// uImage, Android boot, UF2 and partition tables, written by hand.
const char *kFirmware = R"(
import gzip, io, os, struct, sys, zlib, tarfile
out = sys.argv[1]
code = bytes(range(256)) * 64
# uImage: a gzip-compressed ARM kernel loading at 0x80008000.
payload = gzip.compress(code)
def uimage(payload, arch, typ, comp, name, bad_data=False):
    dcrc = zlib.crc32(payload) ^ (1 if bad_data else 0)
    h = struct.pack('>IIIIIIIBBBB32s', 0x27051956, 0, 0, len(payload), 0x80008000, 0x80008000, dcrc, 5, arch, typ, comp, name)
    h = h[:4] + struct.pack('>I', zlib.crc32(h)) + h[8:]
    return h + payload
open(os.path.join(out, 'kernel.uimg'), 'wb').write(uimage(payload, 2, 2, 1, b'Linux-6.1'))
open(os.path.join(out, 'raw.uimg'), 'wb').write(uimage(code, 22, 5, 0, b'firmware', bad_data=True))
# Android boot v0: kernel, and a ramdisk that is a gzip'd newc cpio.
cpio = b''
def newc(name, data, mode):
    global cpio
    n = name.encode() + b'\0'
    hdr = '070701' + ''.join('%08x' % v for v in (1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(n), 0))
    rec = hdr.encode() + n
    rec += b'\0' * ((4 - len(rec) % 4) % 4) + data
    rec += b'\0' * ((4 - len(rec) % 4) % 4)
    cpio += rec
newc('init', b'#!/bin/sh\necho hi\n', 0o100755)
newc('TRAILER!!!', b'', 0)
ramdisk = gzip.compress(cpio)
page = 2048
hdr = struct.pack('<8sIIIIIIIIII16s512s', b'ANDROID!', len(code), 0x10008000, len(ramdisk), 0x11000000, 0, 0, 0x10000100, page, 0, 0, b'test', b'console=ttyS0')
pad = lambda b: b + b'\0' * ((page - len(b) % page) % page)
open(os.path.join(out, 'boot.img'), 'wb').write(pad(hdr) + pad(code) + pad(ramdisk))
# UF2: an RP2040 image at 0x10000000 in two runs, 256-byte payloads.
blocks = []
def uf2(addr, data, fam=0xe48bff56):
    blocks.append(struct.pack('<IIIIIIII', 0x0A324655, 0x9E5D5157, 0x2000, addr, len(data), len(blocks), 0, fam) + data + b'\0' * (476 - len(data)) + struct.pack('<I', 0x0AB16F30))
for i in range(8): uf2(0x10000000 + 256 * i, code[256 * i:256 * i + 256])
for i in range(4): uf2(0x10100000 + 256 * i, code[:256])
open(os.path.join(out, 'fw.uf2'), 'wb').write(b''.join(blocks))
# An MBR disk: a tar at sector 2048 and a zip-less raw blob at 4096.
tarb = io.BytesIO()
with tarfile.open(fileobj=tarb, mode='w') as t:
    i = tarfile.TarInfo('inside.txt'); i.size = 6; t.addfile(i, io.BytesIO(b'inside'))
disk = bytearray(6000 * 512)
disk[2048 * 512:2048 * 512 + len(tarb.getvalue())] = tarb.getvalue()
disk[4096 * 512:4096 * 512 + len(code)] = code
def part(i, typ, lba, count):
    struct.pack_into('<B3sB3sII', disk, 446 + 16 * i, 0, b'\0\0\0', typ, b'\0\0\0', lba, count)
part(0, 0x83, 2048, 1024)
part(1, 0x0c, 4096, 64)
disk[510:512] = b'\x55\xaa'
open(os.path.join(out, 'disk.img'), 'wb').write(disk)
# The same as GPT, with a protective MBR.
gpt = bytearray(6000 * 512)
gpt[2048 * 512:2048 * 512 + len(tarb.getvalue())] = tarb.getvalue()
struct.pack_into('<B3sB3sII', gpt, 446, 0, b'\0\0\0', 0xEE, b'\0\0\0', 1, 5999)
gpt[510:512] = b'\x55\xaa'
hdr = b'EFI PART' + struct.pack('<IIIIQQQQ16sQIII', 0x10000, 92, 0, 0, 1, 5999, 34, 5966, b'\1' * 16, 2, 128, 128, 0)
gpt[512:512 + len(hdr)] = hdr
ent = b'\xaf' * 16 + b'\2' * 16 + struct.pack('<QQQ', 2048, 3071, 0) + 'rootfs'.encode('utf-16-le').ljust(72, b'\0')
gpt[1024:1024 + 128] = ent
open(os.path.join(out, 'gpt.img'), 'wb').write(gpt)
open(os.path.join(out, 'code.bin'), 'wb').write(code)
)";

TEST(ContainerFirmware, UImageBootUf2AndPartitions) {
  TempDir d;
  std::ofstream(d / "mk.py") << kFirmware;
  ASSERT_TRUE(sh(py() + " " + (d / "mk.py").string() + " " + d.path().string()));
  const std::string code = text(read_file(d / "code.bin"));
  // uImage: the gzip payload decompressed, with the header's processor and load address.
  {
    auto s = open_path(d / "kernel.uimg");
    EXPECT_EQ(s->root_format(), "uimage");
    EXPECT_NE(s->root()->description().find("ARM"), std::string::npos);
    auto n = s->locate("/Linux-6.1", false);
    const Entry &e = n.fs->entry(n.entry);
    EXPECT_EQ(e.language, "ARM:LE:32:v8");
    ASSERT_TRUE(e.load_address);
    EXPECT_EQ(*e.load_address, 0x80008000u);
    EXPECT_EQ(read_all(*s->open_file("/Linux-6.1")), code);
    auto raw = open_path(d / "raw.uimg");
    EXPECT_EQ(read_all(*raw->open_file("/firmware")), code);
    EXPECT_FALSE(raw->root()->warnings().empty());  // the data checksum
  }
  // Android boot: the kernel and the ramdisk's cpio, nested.
  {
    auto s = open_path(d / "boot.img");
    EXPECT_EQ(s->root_format(), "android-boot");
    EXPECT_EQ(read_all(*s->open_file("/kernel")), code);
    EXPECT_EQ(read_all(*s->open_file("/ramdisk!/ramdisk.out!/init")), "#!/bin/sh\necho hi\n");
    auto k = s->locate("/kernel", false);
    EXPECT_EQ(*k.fs->entry(k.entry).load_address, 0x10008000u);
  }
  // UF2: one image per contiguous range, with the family's language.
  {
    auto s = open_path(d / "fw.uf2");
    EXPECT_EQ(s->root_format(), "uf2");
    auto a = s->locate("/rp2040@0x10000000.bin", false);
    EXPECT_EQ(a.fs->entry(a.entry).language, "ARM:LE:32:Cortex");
    EXPECT_EQ(read_all(*s->open_file("/rp2040@0x10000000.bin")), code.substr(0, 2048));
    EXPECT_EQ(s->open_file("/rp2040@0x10100000.bin")->size(), 1024u);
  }
  // Partitions: the tar inside the first, by magic.
  for (const char *img : {"disk.img", "gpt.img"}) {
    auto s = open_path(d / img);
    EXPECT_EQ(s->root_format(), "partitions") << img;
    const std::string first = std::string(img) == "gpt.img" ? "/p1-rootfs.img" : "/p1.img";
    EXPECT_EQ(read_all(*s->open_file(first + "!/inside.txt")), "inside") << img;
  }
}

// The nesting the task names: an .ipk (tar.gz flavour) holding a
// data.tar.gz holding a squashfs.
TEST(ContainerNesting, IpkDataTarSquashfs) {
  if (!have_tool("mksquashfs") || !have_tool("tar")) GTEST_SKIP() << "mksquashfs or tar is not installed";
  TempDir d;
  make_tree(d / "src");
  fs::create_directories(d / "data");
  ASSERT_TRUE(sh(tool_path("mksquashfs") + " " + (d / "src").string() + " " + (d / "data/rootfs.sqfs").string() + " -noappend -comp xz"));
  fs::create_directories(d / "ipk");
  std::ofstream(d / "ipk/debian-binary") << "2.0\n";
  ASSERT_TRUE(sh("tar -C " + (d / "data").string() + " -czf " + (d / "ipk/data.tar.gz").string() + " ./rootfs.sqfs && "
                 "tar -C " + (d / "ipk").string() + " -czf " + (d / "pkg.ipk").string() + " ./debian-binary ./data.tar.gz"));
  auto s = open_path(d / "pkg.ipk");
  // tar's gzip keeps no name: the member is the outer name plus ".out".
  ASSERT_EQ(s->root()->entry(1).name, "pkg.ipk.out");
  const std::string prefix = "/pkg.ipk.out!/data.tar.gz!/data.tar!/rootfs.sqfs!";
  expect_tree(*s, prefix);
  EXPECT_EQ(s->container_path(prefix + "/bin/true"), "gzip://pkg.ipk!/pkg.ipk.out!/data.tar.gz!/data.tar!/rootfs.sqfs!/bin/true");
  EXPECT_EQ(s->locate(prefix + "/bin/true", false).depth, 5u);
}

// ---- hostile images -----------------------------------------------------------------

TEST(ContainerHostile, CorruptedImages) {
  // Every format's fixture, truncated and with bytes flipped: errors, never crashes.
  TempDir d;
  make_tree(d / "src");
  std::vector<fs::path> images;
  if (have_tool("mksquashfs") && sh(tool_path("mksquashfs") + " " + (d / "src").string() + " " + (d / "a.sqfs").string() + " -noappend"))
    images.push_back(d / "a.sqfs");
  if (have_tool("mke2fs") && sh(tool_path("mke2fs") + " -q -F -t ext4 -d " + (d / "src").string() + " " + (d / "a.ext4").string() + " 4M"))
    images.push_back(d / "a.ext4");
  if (have_tool("mkfs.cramfs") && sh(tool_path("mkfs.cramfs") + " " + (d / "src").string() + " " + (d / "a.cramfs").string()))
    images.push_back(d / "a.cramfs");
  if (have_tool("xorriso") && sh("xorriso -as mkisofs -quiet -R -J -o " + (d / "a.iso").string() + " " + (d / "src").string()))
    images.push_back(d / "a.iso");
  if (have_tool("cpio") && sh("cd " + (d / "src").string() + " && find . | cpio -o -H newc > " + (d / "a.cpio").string()))
    images.push_back(d / "a.cpio");
  if (images.empty()) GTEST_SKIP() << "no image tools installed";
  Limits small;
  small.max_file_bytes = 8 << 20;
  for (const fs::path &img : images) {
    const auto bytes = read_file(img);
    auto exercise = [&](std::vector<std::byte> b) {
      try {
        auto s = Session::open(memory_source(std::move(b)), img.filename().string(), small);
        for (std::uint32_t i = 1; i < s->root()->entries().size(); ++i) try {
            s->open_file(s->root()->path_of(i));
          } catch (const Error &) {
          }
      } catch (const Error &) {
      }
    };
    for (std::size_t cut : {bytes.size() / 2, bytes.size() / 8, std::size_t{2000}}) exercise({bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(std::min(cut, bytes.size()))});
    for (std::size_t k = 0; k < 200; ++k) {
      auto copy = bytes;
      // Flip bytes in the first 64 KiB, where the metadata is.
      const std::size_t at = (k * 7919 + 13) % std::min<std::size_t>(copy.size(), 65536);
      copy[at] ^= std::byte{static_cast<unsigned char>(0x5a + k)};
      exercise(std::move(copy));
    }
  }
}

TEST(ContainerFirmwareCorpus, RealFirmwareInContainers) {
  // The firmware corpus (public U-Boot builds and fwkit images) wrapped as
  // a vendor would ship them: a uImage of U-Boot in a tar.gz, and an ELF in
  // a squashfs in a zip. RK_FIRMWARE_CORPUS or out/firmware-corpus.
  const char *env = std::getenv("RK_FIRMWARE_CORPUS");
  const fs::path corpus = env ? fs::path(env) : fs::path(REVKIT_SOURCE_DIR) / "out/firmware-corpus";
  const fs::path uboot = corpus / "mips/uboot-maltael.bin", elf = corpus / "cortexm/fwkit-cortexm3-O2.elf";
  if (!fs::exists(uboot) || !fs::exists(elf)) GTEST_SKIP() << "no firmware corpus at " << corpus;
  if (!have_tool("mksquashfs") || !have_tool("zip")) GTEST_SKIP() << "mksquashfs or zip is not installed";
  TempDir d;
  const std::string script = R"(
import struct, sys, tarfile, zlib, io, gzip
data = open(sys.argv[1], 'rb').read()
h = struct.pack('>IIIIIIIBBBB32s', 0x27051956, 0, 0, len(data), 0x80100000, 0x80100000, zlib.crc32(data), 5, 5, 5, 0, b'u-boot malta')
h = h[:4] + struct.pack('>I', zlib.crc32(h)) + h[8:]
with tarfile.open(sys.argv[2], 'w:gz') as t:
    i = tarfile.TarInfo('boot/u-boot.uimg'); i.size = len(h) + len(data); t.addfile(i, io.BytesIO(h + data))
)";
  std::ofstream(d / "mk.py") << script;
  ASSERT_TRUE(sh(py() + " " + (d / "mk.py").string() + " " + uboot.string() + " " + (d / "fw.tgz").string()));
  fs::create_directories(d / "root/usr/bin");
  fs::copy_file(elf, d / "root/usr/bin/app");
  ASSERT_TRUE(sh(tool_path("mksquashfs") + " " + (d / "root").string() + " " + (d / "root.sqfs").string() + " -noappend -comp xz"));
  ASSERT_TRUE(sh("cd " + d.path().string() + " && zip -q bundle.zip root.sqfs fw.tgz"));
  auto s = open_path(d / "bundle.zip");
  auto app = s->locate("/root.sqfs!/usr/bin/app", false);
  const Guess g = s->describe(app);
  EXPECT_EQ(g.kind, "elf");
  EXPECT_EQ(g.processor, "ARM:LE:32");
  EXPECT_EQ(s->open_file("/root.sqfs!/usr/bin/app")->size(), fs::file_size(elf));
  // Python's gzip keeps the file's own name ("fw.tgz") in its header.
  const std::string tar = "/fw.tgz!/" + s->locate("/fw.tgz!/", false).fs->entry(1).name + "!";
  auto ub = s->locate(tar + "/boot/u-boot.uimg!/u-boot malta", false);
  EXPECT_EQ(s->open_file(ub.path)->size(), fs::file_size(uboot));
  EXPECT_EQ(s->container_format(s->locate(tar + "/boot/u-boot.uimg", false)), "uimage");
}

}  // namespace
}  // namespace revkit::container
