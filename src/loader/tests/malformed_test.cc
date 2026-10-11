// Malformed input must produce LoadError or a warning, never a crash or UB
// (run under the asan preset to make that meaningful).

#include "builders.hh"

#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <random>

namespace revkit::loader {
namespace {

using testing::build_pe;
using testing::ElfBuilder;
using testing::to_bytes;

std::vector<std::uint8_t> sample_elf64() {
  ElfBuilder b({.wide = true, .big = false, .machine = 62, .type = 2, .flags = 0, .entry = 0x401000});
  b.add_load(".text", 0x401000, {0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3}, 5);
  b.add_load(".data", 0x402000, {1, 2, 3, 4}, 6);
  b.add_symbol("f", 0x401000, 6, 2, 1, 1);
  b.add_symbol("d", 0x402000, 4, 1, 1, 2);
  return b.build();
}

void put_le(std::vector<std::uint8_t> &v, std::size_t off, std::uint64_t value, unsigned n) {
  for (unsigned i = 0; i < n; ++i) v.at(off + i) = static_cast<std::uint8_t>(value >> (8 * i));
}

// Parses, accepting either outcome; the point is no crash.
void parse_anything(const std::vector<std::uint8_t> &bytes) {
  try {
    Image img = parse(to_bytes(bytes));
    // Exercise the memory image too.
    std::array<std::byte, 32> buf{};
    for (const Region &r : img.memory.regions()) img.memory.read(r.start, buf);
    for (const Block &b : img.blocks) img.memory.read(b.start, buf);
  } catch (const LoadError &) {
  }
}

constexpr std::size_t kPhoff = 32, kShoff = 40, kPhentsize = 54, kPhnum = 56, kShnum = 60, kShstrndx = 62;
constexpr std::size_t kPhdr0 = 64, kPhdr1 = 64 + 56;

TEST(MalformedElf, SampleIsValid) {
  Image img = parse(to_bytes(sample_elf64()));
  EXPECT_TRUE(img.warnings.empty());
  EXPECT_EQ(img.symbols.size(), 2u);
}

TEST(MalformedElf, EmptyAndGarbage) {
  EXPECT_THROW(parse(to_bytes({})), LoadError);
  EXPECT_THROW(parse(to_bytes({0x7f, 'E', 'L', 'F'})), LoadError);
  EXPECT_THROW(parse(to_bytes({1, 2, 3, 4, 5, 6, 7, 8})), LoadError);
}

TEST(MalformedElf, TruncatedHeaderThrows) {
  auto elf = sample_elf64();
  for (std::size_t n = 0; n < 64; ++n) {
    std::vector<std::uint8_t> cut(elf.begin(), elf.begin() + static_cast<std::ptrdiff_t>(n));
    EXPECT_THROW(parse(to_bytes(cut)), LoadError) << "prefix " << n;
  }
}

TEST(MalformedElf, EveryTruncationIsSafe) {
  auto elf = sample_elf64();
  for (std::size_t n = 0; n <= elf.size(); ++n)
    parse_anything(std::vector<std::uint8_t>(elf.begin(), elf.begin() + static_cast<std::ptrdiff_t>(n)));
}

TEST(MalformedElf, BadIdent) {
  auto elf = sample_elf64();
  elf[4] = 3;  // class
  EXPECT_THROW(parse(to_bytes(elf)), LoadError);
  elf = sample_elf64();
  elf[5] = 0;  // data encoding
  EXPECT_THROW(parse(to_bytes(elf)), LoadError);
}

TEST(MalformedElf, AbsurdProgramHeaderCount) {
  auto elf = sample_elf64();
  put_le(elf, kPhnum, 0xfffe, 2);
  EXPECT_THROW(parse(to_bytes(elf)), LoadError);
}

TEST(MalformedElf, ProgramHeaderOffsetOverflow) {
  auto elf = sample_elf64();
  put_le(elf, kPhoff, 0xffffffffffffff00ULL, 8);
  EXPECT_THROW(parse(to_bytes(elf)), LoadError);
}

TEST(MalformedElf, ProgramHeaderEntryTooSmall) {
  auto elf = sample_elf64();
  put_le(elf, kPhentsize, 8, 2);
  EXPECT_THROW(parse(to_bytes(elf)), LoadError);
}

TEST(MalformedElf, OverlappingSegmentsThrow) {
  auto elf = sample_elf64();
  put_le(elf, kPhdr1 + 16, 0x401004, 8);  // .data segment vaddr inside .text
  try {
    parse(to_bytes(elf));
    FAIL() << "expected LoadError";
  } catch (const LoadError &e) {
    EXPECT_NE(std::string(e.what()).find("overlaps"), std::string::npos) << e.what();
  }
}

TEST(MalformedElf, SegmentWrappingAddressSpaceThrows) {
  auto elf = sample_elf64();
  put_le(elf, kPhdr1 + 16, 0xfffffffffffff000ULL, 8);
  put_le(elf, kPhdr1 + 40, 0x2000, 8);
  EXPECT_THROW(parse(to_bytes(elf)), LoadError);
}

TEST(MalformedElf, Elf32SegmentPast4GiBThrows) {
  ElfBuilder b({.wide = false, .big = false, .machine = 3, .type = 2, .flags = 0, .entry = 0});
  b.add_load(".bss", 0xfffff000, {}, 6, 0x2000, true);
  EXPECT_THROW(parse(to_bytes(b.build())), LoadError);
}

TEST(MalformedElf, SegmentDataPastEndOfFileIsTruncated) {
  auto elf = sample_elf64();
  put_le(elf, kPhdr0 + 8, 0x7fffffff, 8);  // .text p_offset far past EOF
  Image img = parse(to_bytes(elf));
  EXPECT_FALSE(img.warnings.empty());
  const Region *r = img.memory.find(0x401000);
  ASSERT_NE(r, nullptr);
  EXPECT_EQ(r->file_size, 0u);
}

TEST(MalformedElf, HugeFileSizeIsTruncated) {
  auto elf = sample_elf64();
  put_le(elf, kPhdr0 + 32, 0xffffffffffffULL, 8);  // p_filesz, clipped to p_memsz then to EOF
  put_le(elf, kPhdr0 + 40, 0x800, 8);               // p_memsz, still below .data
  Image img = parse(to_bytes(elf));
  EXPECT_FALSE(img.warnings.empty());
}

TEST(MalformedElf, AbsurdSectionCountIsIgnored) {
  auto elf = sample_elf64();
  put_le(elf, kShnum, 0xfff0, 2);
  Image img = parse(to_bytes(elf));
  EXPECT_TRUE(img.sections.empty());
  EXPECT_FALSE(img.warnings.empty());
  EXPECT_TRUE(img.memory.is_mapped(0x401000));
  // Without sections, blocks fall back to segments.
  ASSERT_EQ(img.blocks.size(), 2u);
  EXPECT_EQ(img.blocks[0].name, "segment_0");
  EXPECT_EQ(img.blocks[0].perms.str(), "r-x");
}

TEST(MalformedElf, SectionTableOffsetOverflow) {
  auto elf = sample_elf64();
  put_le(elf, kShoff, 0xfffffffffffffff0ULL, 8);
  Image img = parse(to_bytes(elf));
  EXPECT_TRUE(img.sections.empty());
}

TEST(MalformedElf, ExtendedSectionCountMustFit) {
  auto elf = sample_elf64();
  put_le(elf, kShnum, 0, 2);  // real count in section 0's sh_size, which we make absurd
  std::uint64_t shoff = 0;
  for (unsigned i = 0; i < 8; ++i) shoff |= std::uint64_t{elf[kShoff + i]} << (8 * i);
  put_le(elf, shoff + 32, 0xffffffffffffULL, 8);
  Image img = parse(to_bytes(elf));
  EXPECT_TRUE(img.sections.empty());
}

TEST(MalformedElf, BadSectionNameIndex) {
  auto elf = sample_elf64();
  put_le(elf, kShstrndx, 0x7777, 2);
  Image img = parse(to_bytes(elf));
  EXPECT_FALSE(img.warnings.empty());
  for (const Section &s : img.sections) EXPECT_TRUE(s.name.empty());
}

TEST(MalformedElf, SymbolTablesWithBadGeometry) {
  auto elf = sample_elf64();
  std::uint64_t shoff = 0;
  for (unsigned i = 0; i < 8; ++i) shoff |= std::uint64_t{elf[kShoff + i]} << (8 * i);
  const std::size_t symtab = shoff + 3 * 64;  // null, .text, .data, .symtab

  auto bad = elf;
  put_le(bad, symtab + 56, 3, 8);  // sh_entsize too small
  EXPECT_TRUE(parse(to_bytes(bad)).symbols.empty());

  bad = elf;
  put_le(bad, symtab + 32, 0xffffffffffffULL, 8);  // sh_size huge
  EXPECT_TRUE(parse(to_bytes(bad)).symbols.empty());

  bad = elf;
  put_le(bad, symtab + 40, 0xffff, 4);  // sh_link to nowhere: symbols without names
  Image img = parse(to_bytes(bad));
  ASSERT_EQ(img.symbols.size(), 2u);
  EXPECT_TRUE(img.symbols[0].name.empty());
}

TEST(MalformedElf, SymbolNameOffsetsOutOfRange) {
  auto elf = sample_elf64();
  std::uint64_t shoff = 0;
  for (unsigned i = 0; i < 8; ++i) shoff |= std::uint64_t{elf[kShoff + i]} << (8 * i);
  std::uint64_t symoff = 0;
  for (unsigned i = 0; i < 8; ++i) symoff |= std::uint64_t{elf[shoff + 3 * 64 + 24 + i]} << (8 * i);
  put_le(elf, symoff + 24, 0xfffffff0, 4);  // first real symbol's st_name
  Image img = parse(to_bytes(elf));
  ASSERT_EQ(img.symbols.size(), 2u);
  EXPECT_TRUE(img.symbols[0].name.empty());
  EXPECT_EQ(img.symbols[1].name, "d");
}

TEST(MalformedElf, BrokenEhFrameIsIgnored) {
  auto build = [](std::vector<std::uint8_t> eh) {
    ElfBuilder b({.wide = true, .big = false, .machine = 62, .type = 2, .flags = 0, .entry = 0x401000});
    b.add_load(".text", 0x401000, {0xc3}, 5);
    b.add_load(".eh_frame", 0x402000, std::move(eh), 4);
    return parse(to_bytes(b.build()));
  };
  // Record length past the section.
  Image img = build({0xf0, 0xff, 0xff, 0x7f, 0, 0, 0, 0});
  EXPECT_TRUE(img.function_ranges.empty());
  EXPECT_FALSE(img.warnings.empty());
  // An FDE whose CIE pointer leads nowhere.
  img = build({0x0c, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_TRUE(img.function_ranges.empty());
  // 64-bit extended length that overflows.
  img = build({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
  EXPECT_TRUE(img.function_ranges.empty());
  // A valid CIE ("zR", pcrel sdata4) and an FDE covering .text.
  std::vector<std::uint8_t> eh = {
      0x10, 0, 0, 0, 0, 0, 0, 0, 1, 'z', 'R', 0, 1, 0x78, 0x10, 1, 0x1b, 0, 0, 0,  // CIE
      0x10, 0, 0, 0, 0x18, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,             // FDE
      0, 0, 0, 0};
  // pc_begin is pc-relative to its own field at 0x402000 + 28: 0x401000 - 0x40201c.
  std::uint32_t rel = static_cast<std::uint32_t>(0x401000 - 0x40201c);
  for (int i = 0; i < 4; ++i) eh[28 + i] = static_cast<std::uint8_t>(rel >> (8 * i));
  img = build(eh);
  ASSERT_EQ(img.function_ranges.size(), 1u) << (img.warnings.empty() ? "" : img.warnings.front());
  EXPECT_EQ(img.function_ranges[0].start, 0x401000u);
  EXPECT_EQ(img.function_ranges[0].end, 0x401001u);
}

TEST(MalformedPe, EmptyAndTruncated) {
  auto pe = build_pe().bytes;
  for (std::size_t n = 0; n < 0x40; ++n)
    EXPECT_THROW(parse(to_bytes(std::vector<std::uint8_t>(pe.begin(), pe.begin() + static_cast<std::ptrdiff_t>(n)))),
                 LoadError);
  for (std::size_t n = 0; n <= pe.size(); n += 7)
    parse_anything(std::vector<std::uint8_t>(pe.begin(), pe.begin() + static_cast<std::ptrdiff_t>(n)));
}

TEST(MalformedPe, BadHeaderFields) {
  testing::PeImage pe = build_pe();
  auto bad = pe.bytes;
  put_le(bad, 0x3c, 0xfffffff0, 4);  // e_lfanew past EOF
  EXPECT_THROW(parse(to_bytes(bad)), LoadError);

  bad = pe.bytes;
  bad[pe.lfanew] = 'X';  // signature
  EXPECT_THROW(parse(to_bytes(bad)), LoadError);

  bad = pe.bytes;
  put_le(bad, pe.opt, 0x1234, 2);  // optional header magic
  EXPECT_THROW(parse(to_bytes(bad)), LoadError);

  bad = pe.bytes;
  put_le(bad, pe.lfanew + 4 + 16, 16, 2);  // SizeOfOptionalHeader too small
  EXPECT_THROW(parse(to_bytes(bad)), LoadError);

  bad = pe.bytes;
  put_le(bad, pe.lfanew + 4 + 2, 0xffff, 2);  // NumberOfSections
  EXPECT_THROW(parse(to_bytes(bad)), LoadError);

  bad = pe.bytes;
  put_le(bad, pe.opt + 108, 0xffffffff, 4);  // NumberOfRvaAndSizes: clamped
  EXPECT_NO_THROW(parse(to_bytes(bad)));
}

TEST(MalformedPe, OverlappingSectionsThrow) {
  testing::PeImage pe = build_pe();
  put_le(pe.bytes, pe.section_table + 40 + 12, 0x1010, 4);  // .rdata VA inside .text
  EXPECT_THROW(parse(to_bytes(pe.bytes)), LoadError);
}

TEST(MalformedPe, SectionDataPastEndOfFile) {
  testing::PeImage pe = build_pe();
  put_le(pe.bytes, pe.section_table + 2 * 40 + 20, 0x7ffffff0, 4);  // .pdata PointerToRawData
  Image img = parse(to_bytes(pe.bytes));
  EXPECT_FALSE(img.warnings.empty());
  EXPECT_TRUE(img.function_ranges.empty());
  EXPECT_EQ(img.exports.size(), 2u);  // other directories still load
}

TEST(MalformedPe, AbsurdExportCounts) {
  testing::PeImage pe = build_pe();
  put_le(pe.bytes, pe.export_dir_off + 20, 0xffffffff, 4);
  Image img = parse(to_bytes(pe.bytes));
  EXPECT_TRUE(img.exports.empty());
  EXPECT_FALSE(img.warnings.empty());
  EXPECT_EQ(img.imports.size(), 2u);

  pe = build_pe();
  put_le(pe.bytes, pe.export_dir_off + 20, 0x00100000, 4);  // big, under the cap: table runs off the end
  img = parse(to_bytes(pe.bytes));
  EXPECT_TRUE(img.exports.empty());
}

TEST(MalformedPe, BogusImportRvas) {
  testing::PeImage pe = build_pe();
  put_le(pe.bytes, pe.import_dir_off + 12, 0x7fff0000, 4);  // library name RVA
  Image img = parse(to_bytes(pe.bytes));
  EXPECT_TRUE(img.imports.empty());
  EXPECT_FALSE(img.warnings.empty());

  pe = build_pe();
  put_le(pe.bytes, pe.import_dir_off, 0x7fff0000, 4);  // ILT RVA
  img = parse(to_bytes(pe.bytes));
  EXPECT_TRUE(img.imports.empty());
}

TEST(MalformedPe, SharedImportTablesStayBounded) {
  // Twenty descriptors share one 65536-entry lookup table: 1.3M imports
  // from 600 KB (4096 of them made 268M). The walk stops at 1M in all.
  testing::PeImage pe = build_pe();
  const std::size_t pdata = pe.section_table + 2 * 40;
  put_le(pe.bytes, pdata + 8, 0x90000, 4);    // .pdata virtual size
  put_le(pe.bytes, pdata + 16, 0x90000, 4);   // raw size
  put_le(pe.bytes, pe.opt + 56, 0x93000, 4);  // size of image
  pe.bytes.resize(0xa00 + 0x90000);
  const std::size_t dirs = pe.opt + 112;
  put_le(pe.bytes, dirs + 8, 0x3100, 4);  // import directory
  put_le(pe.bytes, dirs + 12, 21 * 20, 4);
  for (std::size_t i = 0; i < 20; ++i) {
    const std::size_t d = 0xb00 + i * 20;
    put_le(pe.bytes, d, 0x4000, 4);
    put_le(pe.bytes, d + 12, 0x2180, 4);
    put_le(pe.bytes, d + 16, 0x4000, 4);
  }
  for (std::size_t j = 0; j < 65536; ++j) put_le(pe.bytes, 0x1a00 + 8 * j, 0x21a0, 8);
  Image img = parse(to_bytes(pe.bytes));
  EXPECT_EQ(img.imports.size(), std::size_t{1} << 20);
  bool warned = false;
  for (const auto &w : img.warnings) warned |= w.find("imports") != std::string::npos;
  EXPECT_TRUE(warned);
}

// Random byte mutations of valid images; nothing may crash.
TEST(Malformed, MutationSmoke) {
  std::mt19937 rng(12345);
  const std::vector<std::vector<std::uint8_t>> seeds = {sample_elf64(), build_pe().bytes, build_pe(false).bytes};
  for (const auto &seed : seeds) {
    for (int iter = 0; iter < 3000; ++iter) {
      auto m = seed;
      int flips = 1 + static_cast<int>(rng() % 8);
      for (int k = 0; k < flips; ++k) {
        std::size_t at = rng() % m.size();
        switch (rng() % 3) {
          case 0: m[at] = static_cast<std::uint8_t>(rng()); break;
          case 1: m[at] = 0xff; break;
          default: m[at] = 0; break;
        }
      }
      parse_anything(m);
    }
  }
}

// Mutations confined to a real binary's relocation sections and dynamic
// table, which the synthetic sample doesn't have: relocations, init arrays
// and PLT layout must cope with any contents.
TEST(MalformedElf, MutatedRelocationsAndDynamicTable) {
  auto dir = testing::scratch_dir("malformed-reloc");
  auto exe = dir / "prog";
  if (!testing::compile(REVKIT_TEST_CC, "int f(void) { return 1; }\nint (*p)(void) = f;\nint main(void) { return p(); }\n",
                        "-O1 -pie -fPIE", exe))
    GTEST_SKIP() << "no host C compiler";
  const auto seed = testing::read_file(exe);
  const Image clean = parse(to_bytes(seed));
  ASSERT_FALSE(clean.relocations.empty());
  std::vector<std::pair<std::uint64_t, std::uint64_t>> spans;  // file ranges to mutate
  for (const Section &s : clean.sections)
    if (s.type == 4 || s.type == 9 || s.type == 19 || s.type == 6) spans.emplace_back(s.offset, s.file_size);
  ASSERT_FALSE(spans.empty());

  std::mt19937 rng(777);
  for (int iter = 0; iter < 2000; ++iter) {
    auto m = seed;
    for (int k = 0; k < 1 + static_cast<int>(rng() % 6); ++k) {
      const auto &[off, size] = spans[rng() % spans.size()];
      if (size == 0) continue;
      m[off + rng() % size] = static_cast<std::uint8_t>(rng() % 3 == 0 ? 0xff : rng());
    }
    parse_anything(m);
  }
}

}  // namespace
}  // namespace revkit::loader
