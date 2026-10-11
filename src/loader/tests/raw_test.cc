// Raw images: a flat binary at a base, with a header skipped and extra
// regions for RAM and memory-mapped I/O.

#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <array>
#include <string>

namespace revkit::loader {
namespace {

std::shared_ptr<const Bytes> file_of(std::size_t n) {
  auto b = std::make_shared<Bytes>(n);
  for (std::size_t i = 0; i < n; ++i) (*b)[i] = static_cast<std::byte>(i & 0xff);
  return b;
}

TEST(Raw, LoadsTheSliceAtTheBaseReadWriteExecute) {
  RawOptions o;
  o.language = "ARM:LE:32:v4t";
  o.base = 0x1000;
  o.offset = 0x10;
  Image img = parse_raw(file_of(0x40), o);
  EXPECT_EQ(img.format, Format::raw);
  EXPECT_EQ(img.bits, 32u);
  EXPECT_EQ(img.endian, Endian::little);
  ASSERT_EQ(img.blocks.size(), 1u);
  EXPECT_EQ(img.blocks[0].start, 0x1000u);
  EXPECT_EQ(img.blocks[0].size, 0x30u);
  EXPECT_EQ(img.blocks[0].perms.str(), "rwx");
  EXPECT_TRUE(img.blocks[0].initialized);
  std::array<std::byte, 2> b{};
  ASSERT_EQ(img.memory.read(0x1000, b), 2u);
  EXPECT_EQ(b[0], std::byte{0x10});  // the header's 16 bytes were skipped
  EXPECT_EQ(img.image_base, 0x1000u);
  EXPECT_FALSE(img.entry);
}

TEST(Raw, LengthPermsEntryAndRegions) {
  RawOptions o;
  o.language = "ARM:BE:32:v8:default";
  o.length = 0x20;
  o.perms = {true, false, true};
  o.entry = 0x4;
  o.regions.push_back(parse_raw_region("periph:c0000000:1000"));
  o.regions.push_back(parse_raw_region("sram:0x20000000:0x8000:rwx:init"));
  o.regions.push_back(parse_raw_region("uart:e0001000:100:rw-:volatile"));
  Image img = parse_raw(file_of(0x40), o);
  EXPECT_EQ(img.endian, Endian::big);
  ASSERT_EQ(img.blocks.size(), 4u);
  EXPECT_EQ(img.blocks[0].size, 0x20u);
  EXPECT_EQ(img.blocks[0].perms.str(), "r-x");
  EXPECT_EQ(img.blocks[1].name, "sram");
  EXPECT_TRUE(img.blocks[1].initialized);
  EXPECT_EQ(img.blocks[1].perms.str(), "rwx");
  EXPECT_EQ(img.blocks[2].name, "periph");
  EXPECT_FALSE(img.blocks[2].initialized);
  EXPECT_EQ(img.blocks[2].perms.str(), "rw-");
  EXPECT_FALSE(img.blocks[2].is_volatile);
  EXPECT_TRUE(img.blocks[3].is_volatile);
  EXPECT_EQ(img.entry, 0x4u);
  EXPECT_TRUE(img.memory.is_mapped(0xc0000fff));
  EXPECT_FALSE(img.memory.is_mapped(0xc0001000));
}

TEST(Raw, RejectsWhatDoesntFit) {
  RawOptions o;
  o.language = "ARM:LE:32:v4t";
  EXPECT_THROW(parse_raw(file_of(0x10), {.language = "nonsense"}), LoadError);
  o.offset = 0x20;
  EXPECT_THROW(parse_raw(file_of(0x10), o), LoadError);  // past the end
  o.offset = 0;
  o.length = 0x11;
  EXPECT_THROW(parse_raw(file_of(0x10), o), LoadError);
  o.length.reset();
  o.regions = {parse_raw_region("a:8:10")};
  EXPECT_THROW(parse_raw(file_of(0x10), o), LoadError);  // overlaps the image
  o.regions = {parse_raw_region("a:fffffff0:20")};
  EXPECT_THROW(parse_raw(file_of(0x10), o), LoadError);  // past 32 bits
  EXPECT_THROW(parse_raw_region("a:10"), LoadError);
  EXPECT_THROW(parse_raw_region("a:10:zz"), LoadError);
  EXPECT_THROW(parse_raw_region("a:10:10:rwq"), LoadError);
  EXPECT_THROW(parse_raw_region(":10:10"), LoadError);
}

// An overlap names both blocks and their ranges (the Open dialog's user saw
// "memory region at 0x0 overlaps region at 0x0" for a region over the image).
TEST(Raw, OverlapsNameBothBlocks) {
  RawOptions o;
  o.language = "6502:LE:16:default";
  o.regions = {parse_raw_region("mmio:0:10000:rw-:volatile")};
  auto message = [&](std::size_t size) {
    try {
      parse_raw(file_of(size), o);
    } catch (const LoadError &e) {
      return std::string(e.what());
    }
    return std::string("(loaded)");
  };
  EXPECT_EQ(message(0x1a4a), "region mmio (0x0–0xffff) overlaps the image block ram (0x0–0x1a49)");
  o.base = 0x8000;
  o.regions = {parse_raw_region("ram:0:200"), parse_raw_region("io:100:10")};
  EXPECT_EQ(message(0x100), "region io (0x100–0x10f) overlaps region ram (0x0–0x1ff)");
  // The region after the image, overlapping its end.
  o.regions = {parse_raw_region("tail:80ff:10")};
  EXPECT_EQ(message(0x100), "region tail (0x80ff–0x810e) overlaps the image block ram (0x8000–0x80ff)");
  // In another space: the offsets as given, and the space.
  o.base = 0;
  o.regions = {parse_raw_region("x:0:10:space=EXTMEM"), parse_raw_region("y:8:10:space=EXTMEM")};
  EXPECT_EQ(message(0x10), "region y (0x8–0x17 in EXTMEM) overlaps region x (0x0–0xf in EXTMEM)");
}

// Memory itself, which doesn't know names, gives both ranges.
TEST(Raw, MemoryOverlapGivesBothRanges) {
  Memory m;
  m.add({0, 0x1a4a, 0, 0, {}});
  try {
    m.add({0, 0x10000, 0, 0, {}});
    FAIL() << "added an overlapping region";
  } catch (const LoadError &e) {
    EXPECT_STREQ(e.what(), "memory region 0x0–0xffff overlaps region 0x0–0x1a49");
  }
}

// Permissions over part of a region (an ELF section inside its segment,
// docs/memory-map.md): the region splits there, each piece keeping its
// bytes; regions the range doesn't reach, or that already have them, stay.
TEST(Raw, PermissionsOverPartOfARegionSplitIt) {
  Memory m(file_of(0x100));
  const Perms rx{true, false, true}, r{true, false, false}, rw{true, true, false};
  m.add({0x1000, 0x200, 0x0, 0x100, rx});  // 0x100 bytes from the file, 0x100 zeros
  m.add({0x3000, 0x10, 0x0, 0x10, r});
  m.set_perms(0x1080, 0x100, rw);
  ASSERT_EQ(m.regions().size(), 4u);
  const Region &a = m.regions()[0], &b = m.regions()[1], &c = m.regions()[2];
  EXPECT_EQ(a.start, 0x1000u);
  EXPECT_EQ(a.size, 0x80u);
  EXPECT_EQ(a.file_size, 0x80u);
  EXPECT_EQ(a.perms, rx);
  EXPECT_EQ(b.start, 0x1080u);
  EXPECT_EQ(b.size, 0x100u);
  EXPECT_EQ(b.file_offset, 0x80u);
  EXPECT_EQ(b.file_size, 0x80u);  // the file's last 0x80 bytes, then zeros
  EXPECT_EQ(b.perms, rw);
  EXPECT_EQ(c.start, 0x1180u);
  EXPECT_EQ(c.size, 0x80u);
  EXPECT_EQ(c.file_size, 0u);
  EXPECT_EQ(c.perms, rx);
  EXPECT_EQ(m.regions()[3].perms, r);
  // The bytes are where they were.
  std::array<std::byte, 4> got{};
  EXPECT_EQ(m.read(0x107e, got), 4u);
  EXPECT_EQ(std::to_integer<int>(got[0]), 0x7e);
  EXPECT_EQ(std::to_integer<int>(got[2]), 0x80);
  EXPECT_EQ(m.read(0x10fe, got), 4u);
  EXPECT_EQ(std::to_integer<int>(got[1]), 0xff);
  EXPECT_EQ(std::to_integer<int>(got[2]), 0);
  // The same permissions again change nothing; a whole region just changes.
  m.set_perms(0x1080, 0x100, rw);
  EXPECT_EQ(m.regions().size(), 4u);
  m.set_perms(0x3000, 0x10, rw);
  EXPECT_EQ(m.regions().size(), 4u);
  EXPECT_EQ(m.regions()[3].perms, rw);
}

std::shared_ptr<const Bytes> text_of(std::string_view s) {
  auto b = std::make_shared<Bytes>();
  for (char c : s) b->push_back(static_cast<std::byte>(c));
  return b;
}

std::uint8_t byte_at(const Image &img, std::uint64_t a) {
  std::array<std::byte, 1> b{};
  EXPECT_EQ(img.memory.read(a, b), 1u) << std::hex << a;
  return std::to_integer<std::uint8_t>(b[0]);
}

// Intel HEX: data records at their addresses (extended linear and segment
// addresses), contiguous runs merged into a block, the start address as
// the entry point.
TEST(RawHex, IntelHexBlocksAndEntry) {
  const std::string hex =
      ":10000000000102030405060708090A0B0C0D0E0F78\n"
      ":0400100010111213A6\r\n"
      ":02000004000AF0\n"            // upper 16 bits: 0x000a
      ":03200000AABBCCAC\n"          // 0xa2000
      ":020000021000EC\n"            // segment 0x1000 -> base 0x10000
      ":0100050077830\n";            // bad: odd digits
  RawOptions o;
  o.language = "avr8:LE:16:default";
  EXPECT_EQ(detect_raw_container(*text_of(hex)), RawContainer::binary);  // not HEX throughout
  const std::string good =
      ":10000000000102030405060708090A0B0C0D0E0F78\n"
      ":0400100010111213A6\r\n"
      ":02000004000AF0\n"
      ":03200000AABBCCAC\n"
      ":0400000500000010E7\n"
      ":00000001FF\n";
  EXPECT_EQ(detect_raw_container(*text_of(good)), RawContainer::ihex);
  Image img = parse_raw(text_of(good), o);
  ASSERT_EQ(img.blocks.size(), 2u);
  EXPECT_EQ(img.blocks[0].start, 0u);
  EXPECT_EQ(img.blocks[0].size, 0x14u);
  EXPECT_EQ(img.blocks[1].start, 0xa2000u);
  EXPECT_EQ(img.blocks[1].size, 3u);
  EXPECT_EQ(img.blocks[1].name, "ram_1");
  EXPECT_EQ(byte_at(img, 0x0f), 0x0f);
  EXPECT_EQ(byte_at(img, 0x13), 0x13);
  EXPECT_EQ(byte_at(img, 0xa2002), 0xcc);
  EXPECT_FALSE(img.memory.is_mapped(0x14));
  EXPECT_EQ(img.entry, 0x10u);
  // A bad checksum, and data after the end record.
  EXPECT_THROW(parse_raw(text_of(":0400100010111213A7\n"), {.language = "avr8:LE:16:default", .container = RawContainer::ihex}),
               LoadError);
  EXPECT_THROW(parse_raw(text_of(":00000001FF\n:0400100010111213A6\n"),
                         {.language = "avr8:LE:16:default", .container = RawContainer::ihex}),
               LoadError);
  // Overlapping records.
  EXPECT_THROW(parse_raw(text_of(":0400100010111213A6\n:0400120010111213A4\n"),
                         {.language = "avr8:LE:16:default", .container = RawContainer::ihex}),
               LoadError);
}

// Motorola S-records: S1/S2/S3 data with 16/24/32-bit addresses, S9/S8/S7
// entries, the header and count records skipped.
TEST(RawHex, SRecords) {
  const std::string srec =
      "S00F000068656C6C6F202020202000003C\n"
      "S11F00007C0802A6900100049421FFF07C6C1B787C8C23783C6000003863000026\n"
      "S20801000041424344EC\n"
      "S5030002FA\n"
      "S9030000FC\n";
  EXPECT_EQ(detect_raw_container(*text_of(srec)), RawContainer::srec);
  RawOptions o;
  o.language = "68000:BE:32:default";
  Image img = parse_raw(text_of(srec), o);
  ASSERT_EQ(img.blocks.size(), 2u);
  EXPECT_EQ(img.blocks[0].start, 0u);
  EXPECT_EQ(img.blocks[0].size, 0x1cu);
  EXPECT_EQ(img.blocks[1].start, 0x10000u);
  EXPECT_EQ(byte_at(img, 0), 0x7c);
  EXPECT_EQ(byte_at(img, 0x10003), 0x44);
  EXPECT_EQ(img.entry, 0u);
  // Not S-records throughout: a binary file.
  EXPECT_EQ(detect_raw_container(*text_of("S9030000FC\nhello\n")), RawContainer::binary);
  EXPECT_THROW(parse_raw(text_of("S1030000FD\n"), {.language = "68000:BE:32:default", .container = RawContainer::srec}),
               LoadError);  // checksum
}

// Without a language memory provider (no SLEIGH here), a named space gets
// the next free base; keys split back to (space, offset).
TEST(RawSpaces, RegionsInOtherSpacesAreKeyed) {
  RawOptions o;
  o.language = "8051:BE:16:default";
  o.regions.push_back(parse_raw_region("xram:0:ff00:rw-:space=EXTMEM"));
  o.regions.push_back(parse_raw_region("xio:ff00:100:rw-:volatile:space=EXTMEM"));
  Image img = parse_raw(file_of(0x100), o);
  ASSERT_EQ(img.spaces.size(), 1u);
  const std::uint64_t base = img.spaces[0].base;
  EXPECT_EQ(base & ((std::uint64_t{1} << kSpaceKeyShift) - 1), 0u);
  EXPECT_NE(base, 0u);
  ASSERT_EQ(img.blocks.size(), 3u);
  EXPECT_EQ(img.blocks[0].start, 0u);
  EXPECT_EQ(img.blocks[1].start, base);
  EXPECT_EQ(img.blocks[2].start, base + 0xff00);
  EXPECT_TRUE(img.blocks[2].is_volatile);
  EXPECT_EQ(space_key(img, "EXTMEM", 0x10), base + 0x10);
  EXPECT_EQ(space_key(img, "", 0x10), 0x10u);
  EXPECT_FALSE(space_key(img, "SFR", 0x10));
  SpaceOffset so = split_key(img, base + 0xff01);
  ASSERT_NE(so.space, nullptr);
  EXPECT_EQ(so.space->name, "EXTMEM");
  EXPECT_EQ(so.offset, 0xff01u);
  EXPECT_EQ(split_key(img, 0x20).space, nullptr);
  EXPECT_EQ(parse_raw_region("a:1:2:space=mem").space, "mem");
  // A 64-bit language keeps one space.
  EXPECT_THROW(parse_raw(file_of(0x10), {.language = "x86:LE:64:default", .regions = {parse_raw_region("a:0:10:space=io")}}),
               LoadError);
}

TEST(RawSpaces, NameAddressCountsWords) {
  Image img;
  img.bits = 16;
  img.default_space = {"code", 0, false, 2, 4};
  EXPECT_EQ(name_address(img, 0x74), "00000074");  // no other spaces: the legacy form
  const AddressSpace &mem = add_space(img, "mem");
  for (AddressSpace &s : img.spaces) s.digits = 4;
  EXPECT_EQ(name_address(img, 0x74), "code_003a");
  EXPECT_EQ(name_address(img, mem.base + 0x100), "mem_0100");
  Image flat;
  EXPECT_EQ(name_address(flat, 0x101000, "ram_"), "ram_00101000");
}

}  // namespace
}  // namespace revkit::loader
