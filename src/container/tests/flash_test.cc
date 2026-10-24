// Flash file systems and firmware wrappers: JFFS2 (both byte orders, every
// compressor mkfs.jffs2 has, newer nodes over older), UBI images and the
// UBIFS in their volumes (LZO, zlib, zstd, none), from fixtures made with
// mtd-utils where it's installed, and Python (tests/data/firmware/
// make_flash.py) for what no tool here writes; their hostile cases.
#include "fixtures.hh"

#include "../formats.hh"

namespace revkit::container {
namespace {

using namespace testing;

std::shared_ptr<Session> open_path(const fs::path &p, Limits limits = {}) {
  return Session::open(open_host_file(p.string()), p.filename().string(), limits);
}

std::string make_flash() { return py() + " " + std::string(REVKIT_SOURCE_DIR) + "/tests/data/firmware/make_flash.py"; }

// A compressible file of a few nodes and one that isn't.
void add_big_files(const fs::path &root) {
  std::string text;
  for (int i = 0; i < 3000; ++i) text += "line " + std::to_string(i) + " of a compressible file\n";
  std::ofstream(root / "etc/big.txt") << text;
  std::string noise(20000, '\0');
  std::uint32_t x = 12345;
  for (char &c : noise) {
    x = x * 1103515245 + 12345;
    c = static_cast<char>(x >> 16);
  }
  std::ofstream(root / "etc/noise.bin", std::ios::binary) << noise;
}

void expect_big_files(Session &s, const fs::path &root, const std::string &prefix = "") {
  EXPECT_EQ(read_all(*s.open_file(prefix + "/etc/big.txt")), text(read_file(root / "etc/big.txt")));
  EXPECT_EQ(read_all(*s.open_file(prefix + "/etc/noise.bin")), text(read_file(root / "etc/noise.bin")));
}

// ---- JFFS2 --------------------------------------------------------------------------

TEST(ContainerJffs2, BothByteOrdersAndEveryCompressor) {
  if (!have_tool("mkfs.jffs2")) GTEST_SKIP() << "mkfs.jffs2 (mtd-utils) is not installed";
  TempDir d;
  make_tree(d / "src");
  add_big_files(d / "src");
  struct Case {
    const char *name, *flags, *compr;
  };
  const Case cases[] = {
      {"zlib", "", "zlib"},
      {"rtime", "-x zlib", "rtime"},
      {"lzo", "-X lzo -x zlib -x rtime", "lzo"},
      {"none", "-x zlib -x rtime", ""},
  };
  for (const char *order : {"-l", "-b"}) {
    for (const Case &c : cases) {
      const fs::path img = d / (std::string(c.name) + order + ".jffs2");
      ASSERT_TRUE(sh(tool_path("mkfs.jffs2") + " " + order + " " + c.flags + " -e 0x10000 -p -r " +
                     (d / "src").string() + " -o " + img.string()))
          << c.name;
      auto s = open_path(img);
      ASSERT_EQ(s->root_format(), "jffs2") << c.name;
      const std::string desc = s->root()->description();
      EXPECT_NE(desc.find(std::string(order) == "-b" ? "big-endian" : "little-endian"), std::string::npos) << desc;
      if (*c.compr) {
        EXPECT_NE(desc.find(c.compr), std::string::npos) << desc;
      }
      expect_tree(*s);
      expect_big_files(*s, d / "src");
    }
  }
}

TEST(ContainerJffs2, NewestVersionWins) {
  if (!have_tool("mkfs.jffs2")) GTEST_SKIP() << "mkfs.jffs2 (mtd-utils) is not installed";
  TempDir d;
  fs::create_directories(d / "src");
  std::ofstream(d / "src/a.txt") << std::string(10000, 'a');
  std::ofstream(d / "src/b.txt") << "bee\n";
  std::ofstream(d / "src/c.txt") << "cee cee cee\n";
  for (const char *order : {"le", "be"}) {
    const fs::path img = d / (std::string(order) + ".jffs2");
    ASSERT_TRUE(sh(tool_path("mkfs.jffs2") + (std::string(order) == "le" ? " -l" : " -b") + " -n -r " +
                   (d / "src").string() + " -o " + img.string()));
    ASSERT_TRUE(sh(make_flash() + " jffs2-update " + img.string() + " " + order));
    auto s = open_path(img);
    std::string a(10000, 'a');
    a.replace(100, 10, "XXXXXXXXXX");
    EXPECT_EQ(read_all(*s->open_file("/a.txt")), a) << order;
    EXPECT_THROW(s->locate("/b.txt", false), Error) << "a deleted name stays deleted";
    EXPECT_EQ(read_all(*s->open_file("/c.txt")), "cee") << "truncated, and the corrupt newer node ignored";
    EXPECT_EQ(read_all(*s->open_file("/d.txt")), "dee\n");
    bool crc_warned = false;
    for (const auto &w : s->root()->warnings()) crc_warned = crc_warned || w.find("CRC") != std::string::npos;
    EXPECT_TRUE(crc_warned);
  }
}

TEST(ContainerJffs2, Hostile) {
  if (!have_tool("mkfs.jffs2")) GTEST_SKIP() << "mkfs.jffs2 (mtd-utils) is not installed";
  TempDir d;
  make_tree(d / "src");
  add_big_files(d / "src");
  const fs::path img = d / "fs.jffs2";
  ASSERT_TRUE(sh(tool_path("mkfs.jffs2") + " -l -r " + (d / "src").string() + " -o " + img.string()));
  const auto good = read_file(img);
  // Truncations and flipped bytes: no crash, no hang; Error at worst.
  for (std::size_t cut : {good.size() / 3, good.size() / 2, good.size() - 7}) {
    std::vector<std::byte> b(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(cut));
    try {
      auto s = Session::open(memory_source(b), "cut.jffs2", Limits{});
      for (std::uint32_t i = 0; i < s->root()->entries().size(); ++i)
        if (s->root()->entry(i).kind == Kind::file) {
          try {
            (void)s->root()->open(i, s->context({}));
          } catch (const Error &) {
          }
        }
    } catch (const Error &) {
    }
  }
  std::uint32_t x = 7;
  for (int k = 0; k < 200; ++k) {
    auto b = good;
    x = x * 1103515245 + 12345;
    b[(x >> 8) % b.size()] ^= static_cast<std::byte>(1 + (x & 0x7f));
    try {
      auto s = Session::open(memory_source(b), "flip.jffs2", Limits{});
      for (std::uint32_t i = 0; i < s->root()->entries().size(); ++i)
        if (s->root()->entry(i).kind == Kind::file) {
          try {
            (void)s->root()->open(i, s->context({}));
          } catch (const Error &) {
          }
        }
    } catch (const Error &) {
    }
  }
}

// ---- UBI and UBIFS ------------------------------------------------------------------

TEST(ContainerUbi, VolumesAndUbifsWithEveryCompressor) {
  if (!have_tool("mkfs.ubifs") || !have_tool("ubinize")) GTEST_SKIP() << "mkfs.ubifs or ubinize (mtd-utils) is not installed";
  TempDir d;
  make_tree(d / "src");
  add_big_files(d / "src");
  // A raw kernel-like blob for a static volume.
  std::string kernel(70000, '\0');
  for (std::size_t i = 0; i < kernel.size(); ++i) kernel[i] = static_cast<char>(i * 7 + 3);
  std::ofstream(d / "kernel.bin", std::ios::binary) << kernel;
  for (const char *compr : {"lzo", "zlib", "zstd", "none"}) {
    const fs::path ubifs = d / (std::string(compr) + ".ubifs");
    ASSERT_TRUE(sh(tool_path("mkfs.ubifs") + " -q -r " + (d / "src").string() + " -m 2048 -e 126976 -c 64 -x " + compr +
                   " -o " + ubifs.string()))
        << compr;
    // The UBIFS image by itself.
    {
      auto s = open_path(ubifs);
      ASSERT_EQ(s->root_format(), "ubifs") << compr;
      EXPECT_NE(s->root()->description().find(compr), std::string::npos) << s->root()->description();
      expect_tree(*s);
      expect_big_files(*s, d / "src");
    }
    // In a UBI image, beside a static volume.
    std::ofstream(d / "ubinize.cfg") << "[rootfs]\nmode=ubi\nimage=" << ubifs.string()
                                     << "\nvol_id=0\nvol_type=dynamic\nvol_name=rootfs\nvol_flags=autoresize\n"
                                     << "[kernel]\nmode=ubi\nimage=" << (d / "kernel.bin").string()
                                     << "\nvol_id=1\nvol_type=static\nvol_name=kernel\n";
    const fs::path ubi = d / (std::string(compr) + ".ubi");
    ASSERT_TRUE(sh(tool_path("ubinize") + " -o " + ubi.string() + " -m 2048 -p 128KiB -s 512 " +
                   (d / "ubinize.cfg").string()));
    auto s = open_path(ubi);
    ASSERT_EQ(s->root_format(), "ubi");
    EXPECT_NE(s->root()->description().find("2 volumes"), std::string::npos) << s->root()->description();
    EXPECT_EQ(read_all(*s->open_file("/kernel")), kernel);
    auto rootfs = s->locate("/rootfs", false);
    EXPECT_NE(rootfs.fs->entry(rootfs.entry).note.find("dynamic volume 0"), std::string::npos);
    EXPECT_EQ(s->container_format(rootfs), "ubifs");
    expect_tree(*s, "/rootfs!");
    expect_big_files(*s, d / "src", "/rootfs!");
  }
}

TEST(ContainerUbi, Hostile) {
  if (!have_tool("mkfs.ubifs") || !have_tool("ubinize")) GTEST_SKIP() << "mkfs.ubifs or ubinize (mtd-utils) is not installed";
  TempDir d;
  make_tree(d / "src");
  const fs::path ubifs = d / "fs.ubifs";
  ASSERT_TRUE(sh(tool_path("mkfs.ubifs") + " -q -r " + (d / "src").string() + " -m 2048 -e 126976 -c 32 -o " +
                 ubifs.string()));
  std::ofstream(d / "ubinize.cfg") << "[rootfs]\nmode=ubi\nimage=" << ubifs.string()
                                   << "\nvol_id=0\nvol_type=dynamic\nvol_name=rootfs\n";
  const fs::path ubi = d / "fs.ubi";
  ASSERT_TRUE(sh(tool_path("ubinize") + " -o " + ubi.string() + " -m 2048 -p 128KiB " + (d / "ubinize.cfg").string()));
  for (const fs::path &p : {ubifs, ubi}) {
    const auto good = read_file(p);
    std::uint32_t x = 99;
    for (int k = 0; k < 200; ++k) {
      auto b = good;
      if (k < 8) {
        b.resize(good.size() * (k + 1) / 9);
      } else {
        // Most of an image is erased space: flip bytes in the parts in use.
        x = x * 1103515245 + 12345;
        const std::size_t span = std::min<std::size_t>(b.size(), 4 * 131072);
        b[(x >> 8) % span] ^= static_cast<std::byte>(1 + (x & 0x7f));
      }
      try {
        auto s = Session::open(memory_source(b), p.filename().string(), Limits{});
        std::function<void(const std::string &, const std::shared_ptr<FileSystem> &, int)> walk =
            [&](const std::string &prefix, const std::shared_ptr<FileSystem> &f, int depth) {
              for (std::uint32_t i = 0; i < f->entries().size(); ++i) {
                if (f->entry(i).kind != Kind::file) continue;
                try {
                  Session::Node n{f, i, prefix + f->path_of(i), prefix, static_cast<std::uint32_t>(depth)};
                  (void)s->open_file(n.path);
                  if (depth < 2)
                    if (auto sub = s->mount(n)) walk(n.path + "!", sub, depth + 1);
                } catch (const Error &) {
                }
              }
            };
        walk("", s->root(), 1);
      } catch (const Error &) {
      }
    }
  }
}

// Bug scrub part 3: an index whose branches all point at one leaf (here a
// directory entry, but a large inode or a long name the same) reads it
// once, not once a branch.
TEST(ContainerUbi, BranchesToOneLeafReadItOnce) {
  if (!have_tool("mkfs.ubifs")) GTEST_SKIP() << "mkfs.ubifs (mtd-utils) is not installed";
  TempDir d;
  fs::create_directories(d / "src");
  for (int i = 0; i < 40; ++i) std::ofstream(d / "src" / ("file" + std::to_string(i))) << i << "\n";
  const fs::path ubifs = d / "fs.ubifs";
  constexpr std::uint64_t kLeb = 126976;
  ASSERT_TRUE(sh(tool_path("mkfs.ubifs") + " -q -r " + (d / "src").string() + " -m 2048 -e 126976 -c 32 -o " +
                 ubifs.string()));
  std::vector<std::byte> b = read_file(ubifs);
  auto u8 = [&](std::size_t o) { return std::to_integer<std::uint32_t>(b[o]); };
  auto le16 = [&](std::size_t o) { return u8(o) | u8(o + 1) << 8; };
  auto le32 = [&](std::size_t o) { return le16(o) | le16(o + 2) << 16; };
  auto put32 = [&](std::size_t o, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b[o + i] = std::byte(v >> (8 * i) & 0xff);
  };
  std::string name;
  for (std::size_t off = 0; off + 28 <= b.size() && name.empty(); off += 8) {
    if (le32(off) != 0x06101831 || u8(off + 20) != 9 || le16(off + 26) != 0) continue;
    const std::uint32_t len = le32(off + 16), count = le16(off + 24);
    if (count < 2 || off + len > b.size()) continue;
    for (std::uint32_t i = 0; i < count; ++i) {
      const std::size_t br = off + 28 + 20 * i;
      const std::uint64_t pos = le32(br) * kLeb + le32(br + 4);
      if (pos + 56 > b.size() || u8(pos + 20) != 2) continue;
      name.assign(reinterpret_cast<const char *>(b.data() + pos + 56), le16(pos + 50));
      for (std::uint32_t k = 0; k < count; ++k)  // every branch to this one
        for (int w = 0; w < 3; ++w) put32(off + 28 + 20 * k + 4 * w, le32(br + 4 * w));
      put32(off + 4, detail::crc32_ieee(std::span<const std::byte>(b).subspan(off + 8, len - 8), 0) ^ 0xffffffffu);
      break;
    }
  }
  ASSERT_FALSE(name.empty()) << "no level-0 index node with a directory entry";
  auto s = Session::open(memory_source(b), "fs.ubifs", Limits{});
  std::size_t seen = 0;
  for (std::uint32_t i = 0; i < s->root()->entries().size(); ++i)
    if (s->root()->path_of(i) == "/" + name) ++seen;
  EXPECT_EQ(seen, 1u) << name;
}

// ---- YAFFS2 -------------------------------------------------------------------------

TEST(ContainerYaffs2, GeometriesGuessed) {
  TempDir d;
  make_tree(d / "src");
  add_big_files(d / "src");
  fs::create_hard_link(d / "src/etc/config.txt", d / "src/etc/hard.txt");
  struct Case {
    int page, spare;
    const char *order, *where, *expect;
  };
  const Case cases[] = {
      {2048, 64, "le", "0", "2048-byte pages + 64-byte spare (tags at 0)"},
      {4096, 128, "be", "2", "4096-byte pages + 128-byte spare (tags at 2), big-endian"},
      {4096, 224, "le", "0", "4096-byte pages + 224-byte spare"},
      {8192, 448, "le", "2", "8192-byte pages + 448-byte spare (tags at 2)"},
      {2048, 0, "le", "inband", "2048-byte pages with inband tags"},
      {16384, 1280, "be", "0", "16384-byte pages + 1280-byte spare"},
  };
  for (const Case &c : cases) {
    const fs::path img = d / ("y" + std::to_string(c.page) + "-" + c.where + ".img");
    ASSERT_TRUE(sh(make_flash() + " yaffs2 " + (d / "src").string() + " " + img.string() + " " + std::to_string(c.page) +
                   " " + std::to_string(c.spare) + " " + c.order + " " + c.where));
    auto s = open_path(img);
    ASSERT_EQ(s->root_format(), "yaffs2") << c.expect;
    EXPECT_NE(s->root()->description().find(c.expect), std::string::npos) << s->root()->description();
    expect_tree(*s);
    expect_big_files(*s, d / "src");
    EXPECT_EQ(read_all(*s->open_file("/etc/hard.txt")), "hello config\n");
  }
}

TEST(ContainerYaffs2, NewestChunkWins) {
  TempDir d;
  make_tree(d / "src");
  const fs::path img = d / "y.img";
  ASSERT_TRUE(sh(make_flash() + " yaffs2 " + (d / "src").string() + " " + img.string() +
                 " 2048 64 le 0 etc/config.txt 'a newer and longer config'"));
  auto s = open_path(img);
  EXPECT_EQ(read_all(*s->open_file("/etc/config.txt")), "a newer and longer config");
  EXPECT_EQ(read_all(*s->open_file("/deep/a/b/c/d.txt")), "deep\n");
}

TEST(ContainerYaffs2, Hostile) {
  TempDir d;
  make_tree(d / "src");
  add_big_files(d / "src");
  const fs::path img = d / "y.img";
  ASSERT_TRUE(sh(make_flash() + " yaffs2 " + (d / "src").string() + " " + img.string() + " 2048 64 le 0"));
  const auto good = read_file(img);
  std::uint32_t x = 5;
  for (int k = 0; k < 200; ++k) {
    auto b = good;
    if (k < 6) {
      b.resize(good.size() * (k + 1) / 7);
    } else {
      x = x * 1103515245 + 12345;
      b[(x >> 8) % b.size()] ^= static_cast<std::byte>(1 + (x & 0x7f));
    }
    try {
      auto s = Session::open(memory_source(b), "y.img", Limits{});
      for (std::uint32_t i = 0; i < s->root()->entries().size(); ++i)
        if (s->root()->entry(i).kind == Kind::file) {
          try {
            (void)s->root()->open(i, s->context({}));
          } catch (const Error &) {
          }
        }
    } catch (const Error &) {
    }
  }
  // Random data and text are not YAFFS2.
  std::vector<std::byte> noise(65536);
  for (auto &c : noise) {
    x = x * 1103515245 + 12345;
    c = static_cast<std::byte>(x >> 16);
  }
  EXPECT_EQ(identify_head(noise, noise.size()), "");
}

// ---- firmware wrappers ------------------------------------------------------------

// Every entry listed and every file read, for the hostile cases.
void read_everything(const std::vector<std::byte> &b, const std::string &name) {
  try {
    auto s = Session::open(memory_source(b), name, Limits{});
    for (std::uint32_t i = 0; i < s->root()->entries().size(); ++i)
      if (s->root()->entry(i).kind == Kind::file) {
        try {
          (void)read_all(*s->root()->open(i, s->context({})));
        } catch (const Error &) {
        }
      }
  } catch (const Error &) {
  }
}

void mangle(const fs::path &p) {
  const auto good = read_file(p);
  std::uint32_t x = 11;
  for (int k = 0; k < 120; ++k) {
    auto b = good;
    if (k < 6) {
      b.resize(good.size() * (k + 1) / 7);
    } else {
      x = x * 1103515245 + 12345;
      b[(x >> 8) % std::min<std::size_t>(b.size(), 4096)] ^= static_cast<std::byte>(1 + (x & 0x7f));
    }
    read_everything(b, p.filename().string());
  }
}

std::string bytes_of(std::size_t n, unsigned seed) {
  std::string s(n, '\0');
  for (std::size_t i = 0; i < n; ++i) s[i] = static_cast<char>((i * seed + 7) >> 3);
  return s;
}

TEST(ContainerTrx, PartitionsByOffset) {
  TempDir d;
  make_tree(d / "src");
  std::ofstream(d / "loader.bin", std::ios::binary) << bytes_of(3001, 13);
  ASSERT_TRUE(sh("gzip -c /bin/true > " + (d / "kernel.gz").string()));
  ASSERT_TRUE(sh("tar -C " + (d / "src").string() + " -cf " + (d / "root.tar").string() + " ."));
  ASSERT_TRUE(sh(make_flash() + " trx " + (d / "three.trx").string() + " 1 " + (d / "loader.bin").string() + " " +
                 (d / "kernel.gz").string() + " " + (d / "root.tar").string()));
  auto s = open_path(d / "three.trx");
  ASSERT_EQ(s->root_format(), "trx");
  EXPECT_TRUE(s->root()->warnings().empty());
  EXPECT_EQ(read_all(*s->open_file("/loader")), bytes_of(3001, 13) + std::string(3, '\0'));
  EXPECT_EQ(s->open_file("/linux!/true")->size(), fs::file_size("/bin/true"));
  expect_tree(*s, "/rootfs!");
  // Two parts, v2: no loader.
  ASSERT_TRUE(sh(make_flash() + " trx " + (d / "two.trx").string() + " 2 " + (d / "kernel.gz").string() + " " +
                 (d / "root.tar").string()));
  auto two = open_path(d / "two.trx");
  EXPECT_NE(two->root()->description().find("TRX v2"), std::string::npos);
  expect_tree(*two, "/rootfs!");
  // A changed byte: the CRC says so.
  auto b = read_file(d / "two.trx");
  b[b.size() - 1] ^= std::byte{1};
  auto bad = Session::open(memory_source(b), "bad.trx", Limits{});
  ASSERT_EQ(bad->root()->warnings().size(), 1u);
  EXPECT_NE(bad->root()->warnings()[0].find("CRC"), std::string::npos);
  mangle(d / "three.trx");
}

TEST(ContainerAndroidSparse, ExpandsToTheRawImage) {
  TempDir d;
  // Raw blocks, zeros, a repeated word and an ext4 at the end.
  std::string raw = bytes_of(10000, 7) + std::string(5 * 4096, '\0');
  for (int i = 0; i < 3 * 1024; ++i) raw += "\xde\xad\xbe\xef";
  raw += bytes_of(4096, 3);
  raw.resize((raw.size() + 4095) / 4096 * 4096, '\0');
  std::ofstream(d / "system.img", std::ios::binary) << raw;
  ASSERT_TRUE(sh(make_flash() + " sparse " + (d / "system.img").string() + " " + (d / "system.simg").string()));
  auto s = open_path(d / "system.simg");
  ASSERT_EQ(s->root_format(), "android-sparse");
  EXPECT_NE(s->root()->description().find("1 fill"), std::string::npos) << s->root()->description();
  EXPECT_EQ(read_all(*s->open_file("/system.raw.img")), raw);
  // A file system inside one, by magic.
  if (have_tool("mke2fs")) {
    make_tree(d / "src");
    ASSERT_TRUE(sh(tool_path("mke2fs") + " -q -t ext4 -d " + (d / "src").string() + " " + (d / "fs.img").string() + " 2M"));
    ASSERT_TRUE(sh(make_flash() + " sparse " + (d / "fs.img").string() + " " + (d / "fs.simg").string()));
    auto e = open_path(d / "fs.simg");
    expect_tree(*e, "/fs.raw.img!");
  }
  mangle(d / "system.simg");
}

TEST(ContainerAndroidBoot, VendorBootImages) {
  TempDir d;
  std::ofstream(d / "platform.cpio", std::ios::binary) << bytes_of(5000, 3);
  std::ofstream(d / "dlkm.cpio", std::ios::binary) << bytes_of(7000, 5);
  std::ofstream(d / "board.dtb", std::ios::binary) << bytes_of(900, 9);
  ASSERT_TRUE(sh(make_flash() + " vendor-boot " + (d / "v4.img").string() + " 4 " + (d / "board.dtb").string() + " " +
                 (d / "platform.cpio").string() + " " + (d / "dlkm.cpio").string()));
  auto s = open_path(d / "v4.img");
  ASSERT_EQ(s->root_format(), "android-boot");
  EXPECT_NE(s->root()->description().find("vendor boot image v4 \"revkit-board\""), std::string::npos)
      << s->root()->description();
  EXPECT_EQ(read_all(*s->open_file("/vendor_ramdisk-platform.cpio")), bytes_of(5000, 3));
  EXPECT_EQ(read_all(*s->open_file("/vendor_ramdisk-dlkm.cpio")), bytes_of(7000, 5));
  EXPECT_EQ(read_all(*s->open_file("/dtb")), bytes_of(900, 9));
  EXPECT_EQ(read_all(*s->open_file("/bootconfig")), "androidboot.hardware=revkit\n");
  auto dtb = s->locate("/dtb", false);
  ASSERT_TRUE(dtb.fs->entry(dtb.entry).load_address);
  EXPECT_EQ(*dtb.fs->entry(dtb.entry).load_address, 0x11f00000u);
  ASSERT_TRUE(sh(make_flash() + " vendor-boot " + (d / "v3.img").string() + " 3 " + (d / "board.dtb").string() + " " +
                 (d / "platform.cpio").string()));
  auto v3 = open_path(d / "v3.img");
  EXPECT_EQ(read_all(*v3->open_file("/vendor_ramdisk")), bytes_of(5000, 3));
  EXPECT_EQ(read_all(*v3->open_file("/dtb")), bytes_of(900, 9));
  mangle(d / "v4.img");
}

TEST(ContainerDeviceTree, TreeSourceAndFit) {
  if (!have_tool("dtc")) GTEST_SKIP() << "dtc is not installed";
  TempDir d;
  std::ofstream(d / "board.dts") << R"(/dts-v1/;
/ {
    model = "revkit test board";
    compatible = "revkit,test", "revkit,base";
    #address-cells = <1>;
    #size-cells = <1>;
    memory@80000000 { device_type = "memory"; reg = <0x80000000 0x10000000>; };
    soc {
        #address-cells = <1>;
        #size-cells = <1>;
        uart@1000 { compatible = "ns16550a"; reg = <0x1000 0x100>; status = "okay"; blob = [01 02 03]; empty; };
    };
};
)";
  ASSERT_TRUE(sh("dtc -q -I dts -O dtb -o " + (d / "board.dtb").string() + " " + (d / "board.dts").string()));
  auto s = open_path(d / "board.dtb");
  ASSERT_EQ(s->root_format(), "dtb");
  EXPECT_EQ(read_all(*s->open_file("/model")), std::string("revkit test board\0", 18));
  EXPECT_EQ(read_all(*s->open_file("/soc/uart@1000/blob")), "\x01\x02\x03");
  EXPECT_EQ(s->open_file("/soc/uart@1000/empty")->size(), 0u);
  auto compat = s->locate("/compatible", false);
  EXPECT_EQ(compat.fs->entry(compat.entry).note, "revkit,test, revkit,base");
  // The source revkit writes compiles back to the same blob.
  std::ofstream(d / "back.dts") << read_all(*s->open_file("/devicetree.dts"));
  ASSERT_TRUE(sh("dtc -q -I dts -O dtb -o " + (d / "back.dtb").string() + " " + (d / "back.dts").string()));
  EXPECT_EQ(read_file(d / "back.dtb"), read_file(d / "board.dtb"));
  // A FIT image: its images as files, the uncompressed kernel at its load address.
  ASSERT_TRUE(sh("head -c 3000 /bin/true > " + (d / "k.bin").string() + " && gzip -c /bin/true > " + (d / "k.gz").string()));
  std::ofstream(d / "fit.its") << R"(/dts-v1/;
/ {
    description = "revkit FIT";
    #address-cells = <1>;
    images {
        kernel-1 { data = /incbin/("k.bin"); type = "kernel"; arch = "arm"; os = "linux"; compression = "none";
                   load = <0x80008000>; entry = <0x80008000>; };
        kernel-2 { data = /incbin/("k.gz"); type = "kernel"; arch = "arm64"; compression = "gzip"; load = <0x80000>; };
        fdt-1 { data = /incbin/("board.dtb"); type = "flat_dt"; arch = "arm"; compression = "none"; };
    };
    configurations { default = "conf-1"; conf-1 { kernel = "kernel-1"; fdt = "fdt-1"; }; };
};
)";
  ASSERT_TRUE(sh("cd " + d.path().string() + " && dtc -q -I dts -O dtb -o fit.itb fit.its"));
  auto fit = open_path(d / "fit.itb");
  EXPECT_NE(fit->root()->description().find("FIT image"), std::string::npos) << fit->root()->description();
  auto k1 = fit->locate("/images/kernel-1/data", false);
  EXPECT_EQ(k1.fs->entry(k1.entry).language, "ARM:LE:32:v8");
  ASSERT_TRUE(k1.fs->entry(k1.entry).load_address);
  EXPECT_EQ(*k1.fs->entry(k1.entry).load_address, 0x80008000u);
  EXPECT_EQ(read_all(*fit->open_file("/images/kernel-1/data")), text(read_file(d / "k.bin")));
  auto k2 = fit->locate("/images/kernel-2/data", false);
  EXPECT_FALSE(k2.fs->entry(k2.entry).load_address) << "a compressed image's address is the decompressed data's";
  EXPECT_EQ(fit->open_file("/images/kernel-2/data!/true")->size(), fs::file_size("/bin/true"));
  EXPECT_EQ(read_all(*fit->open_file("/images/fdt-1/data!/model")), std::string("revkit test board\0", 18));
  // External data (mkimage -E): data-offset past the blob, 4-byte aligned.
  std::ofstream(d / "ext.its") << R"(/dts-v1/;
/ {
    images { kernel-1 { data-offset = <0>; data-size = <3000>; type = "kernel"; arch = "arm"; compression = "none";
                        load = <0x1000>; }; };
};
)";
  ASSERT_TRUE(sh("cd " + d.path().string() + " && dtc -q -I dts -O dtb -o ext.itb ext.its && "
                 "python3 -I -c \"import os; n=os.path.getsize('ext.itb'); open('ext.itb','ab').write(b'\\0'*(-n%4)+open('k.bin','rb').read())\""));
  auto ext = open_path(d / "ext.itb");
  EXPECT_EQ(read_all(*ext->open_file("/images/kernel-1/data")), text(read_file(d / "k.bin")));
  mangle(d / "board.dtb");
  mangle(d / "fit.itb");
}

TEST(ContainerHexImages, IntelHexAndSRecordsByAddressRange) {
  if (!have_tool("objcopy")) GTEST_SKIP() << "objcopy is not installed";
  TempDir d;
  std::ofstream(d / "a.bin", std::ios::binary) << bytes_of(3000, 5);
  std::ofstream(d / "b.bin", std::ios::binary) << bytes_of(1000, 11);
  std::ofstream(d / "c.bin", std::ios::binary) << bytes_of(500, 17);
  for (const char *f : {"ihex", "srec"}) {
    const std::string ext = std::string(".") + f;
    // a at 0x08000000, b 4 KiB after it (one image, the gap erased), c at 0x20000000.
    ASSERT_TRUE(sh("cd " + d.path().string() + " && objcopy -I binary -O " + f + " --change-addresses 0x08000000 a.bin a" +
                   ext + " && objcopy -I binary -O " + f + " --change-addresses 0x08001000 b.bin b" + ext +
                   " && objcopy -I binary -O " + f + " --change-addresses 0x20000000 c.bin c" + ext));
    // One file: every record but the end records of the first two.
    const std::string end = std::string(f) == "ihex" ? "^:00000001FF" : "^S[789]";
    ASSERT_TRUE(sh("cd " + d.path().string() + " && { grep -v '" + end + "' a" + ext + "; grep -v '" + end + "' b" + ext +
                   " | grep -v '^S0'; grep -v '^S0' c" + ext + "; } > fw" + ext));
    auto s = open_path(d / ("fw" + ext));
    ASSERT_EQ(s->root_format(), f);
    EXPECT_NE(s->root()->description().find("2 images"), std::string::npos) << s->root()->description();
    const std::string first = read_all(*s->open_file("/fw@0x8000000.bin"));
    ASSERT_EQ(first.size(), 0x1000u + 1000u);
    EXPECT_EQ(first.substr(0, 3000), bytes_of(3000, 5));
    EXPECT_EQ(first.substr(3000, 0x1000 - 3000), std::string(0x1000 - 3000, '\xff'));
    EXPECT_EQ(first.substr(0x1000), bytes_of(1000, 11));
    auto c = s->locate("/fw@0x20000000.bin", false);
    ASSERT_TRUE(c.fs->entry(c.entry).load_address);
    EXPECT_EQ(*c.fs->entry(c.entry).load_address, 0x20000000u);
    EXPECT_EQ(read_all(*s->open_file("/fw@0x20000000.bin")), bytes_of(500, 17));
    // Still a raw program to import as a listing describes it, and a container.
    auto g = s->describe(s->locate("/fw@0x20000000.bin", false));
    EXPECT_EQ(g.kind, "raw");
    mangle(d / ("fw" + ext));
  }
}

}  // namespace
}  // namespace revkit::container
