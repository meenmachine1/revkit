#include "builders.hh"

#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <algorithm>

namespace revkit::loader {
namespace {

using testing::build_pe;
using testing::to_bytes;

TEST(Pe, ParsesHeadersSectionsAndDirectories) {
  Image img = parse(to_bytes(build_pe().bytes));
  EXPECT_EQ(img.format, Format::pe);
  EXPECT_EQ(img.bits, 64u);
  EXPECT_EQ(img.machine, 0x8664u);
  EXPECT_EQ(img.image_base, 0x140000000u);
  ASSERT_TRUE(img.entry);
  EXPECT_EQ(*img.entry, 0x140001000u);
  EXPECT_TRUE(img.warnings.empty()) << img.warnings.front();

  ASSERT_EQ(img.sections.size(), 3u);
  EXPECT_EQ(img.sections[0].name, ".text");
  EXPECT_EQ(img.sections[0].addr, 0x140001000u);
  EXPECT_EQ(img.sections[0].perms.str(), "r-x");
  EXPECT_EQ(img.sections[1].perms.str(), "r--");

  // Blocks: the headers, then each section sized by its virtual size.
  ASSERT_EQ(img.blocks.size(), 4u);
  EXPECT_EQ(img.blocks[0].name, "Headers");
  EXPECT_EQ(img.blocks[0].start, 0x140000000u);
  EXPECT_EQ(img.blocks[1].name, ".text");
  EXPECT_EQ(img.blocks[1].size, 0x200u);  // max(virtual 0x20, raw 0x200), like Ghidra

  // Code bytes are readable at their virtual address.
  std::array<std::byte, 6> code{};
  EXPECT_EQ(img.memory.read(0x140001000, code), 6u);
  EXPECT_EQ(code[0], std::byte{0xb8});
  EXPECT_EQ(code[5], std::byte{0xc3});

  ASSERT_EQ(img.exports.size(), 2u);
  EXPECT_EQ(img.exports[0].name, "one");
  EXPECT_EQ(img.exports[0].ordinal, 1u);
  EXPECT_EQ(img.exports[0].address, 0x140001000u);
  EXPECT_EQ(img.exports[1].name, "two");
  EXPECT_EQ(img.exports[1].address, 0x140001010u);
  auto one = std::find_if(img.symbols.begin(), img.symbols.end(), [](const Symbol &s) { return s.name == "one"; });
  ASSERT_NE(one, img.symbols.end());
  EXPECT_EQ(one->type, SymbolType::func);
  EXPECT_EQ(one->source, SymbolSource::pe_export);

  ASSERT_EQ(img.imports.size(), 2u);
  EXPECT_EQ(img.imports[0].library, "KERNEL32.dll");
  EXPECT_EQ(img.imports[0].name, "ExitProcess");
  EXPECT_EQ(img.imports[0].iat_address, 0x140002160u);
  EXPECT_FALSE(img.imports[1].ordinal.value_or(0) == 0);
  EXPECT_EQ(*img.imports[1].ordinal, 7);
  EXPECT_EQ(img.imports[1].iat_address, 0x140002168u);

  EXPECT_EQ(img.pdb_path, "C:\\build\\test.pdb");
  ASSERT_TRUE(img.codeview);
  EXPECT_TRUE(img.codeview->rsds);
  EXPECT_EQ(img.codeview->pdb_path, img.pdb_path);
  EXPECT_EQ(img.codeview->age, 3u);
  EXPECT_EQ(img.codeview->guid[0], 0x10);
  EXPECT_EQ(img.codeview->guid[15], 0x1f);

  // Section contents stop at VirtualSize, without file-alignment padding.
  const Section *text = find_section(img, ".text");
  ASSERT_NE(text, nullptr);
  EXPECT_EQ(section_bytes(img, *text).size(), std::min(text->virtual_size, text->file_size));
  EXPECT_EQ(section_contents(img, *text).size(), section_bytes(img, *text).size());
  EXPECT_EQ(find_section(img, ".nope"), nullptr);

  ASSERT_EQ(img.function_ranges.size(), 2u);
  EXPECT_EQ(img.function_ranges[0].start, 0x140001000u);
  EXPECT_EQ(img.function_ranges[0].end, 0x140001006u);
  EXPECT_EQ(img.function_ranges[1].start, 0x140001010u);

  EXPECT_EQ(guess_language(img)->id(), "x86:LE:64:default:windows");
}

TEST(Pe, Pe32) {
  Image img = parse(to_bytes(build_pe(false).bytes));
  EXPECT_EQ(img.bits, 32u);
  EXPECT_EQ(img.image_base, 0x10000000u);
  ASSERT_EQ(img.imports.size(), 2u);
  EXPECT_EQ(img.imports[0].iat_address, 0x10002160u);
  EXPECT_EQ(img.imports[1].iat_address, 0x10002164u);
  EXPECT_EQ(*img.imports[1].ordinal, 7);
  EXPECT_EQ(guess_language(img)->id(), "x86:LE:32:default:windows");
}

TEST(Pe, Rebase) {
  Image img = parse(to_bytes(build_pe().bytes), {.image_base = 0x10000, .ghidra_image_base = false});
  EXPECT_EQ(img.image_base, 0x10000u);
  EXPECT_EQ(*img.entry, 0x11000u);
  EXPECT_EQ(img.exports[0].address, 0x11000u);
}

TEST(Pe, LongSectionNamesFromCoffStringTable) {
  testing::PeImage pe = build_pe();
  // Point the file header at a string table and name .pdata "/4".
  const std::size_t coff = pe.lfanew + 4;
  std::size_t strtab = pe.bytes.size();
  pe.bytes.resize(strtab + 32, 0);
  pe.bytes[coff + 8] = static_cast<std::uint8_t>(strtab);  // PointerToSymbolTable
  pe.bytes[coff + 9] = static_cast<std::uint8_t>(strtab >> 8);
  const char *name = ".debug_info";
  std::copy(name, name + 11, pe.bytes.begin() + static_cast<std::ptrdiff_t>(strtab + 4));
  std::size_t s = pe.section_table + 2 * 40;
  std::fill(pe.bytes.begin() + static_cast<std::ptrdiff_t>(s), pe.bytes.begin() + static_cast<std::ptrdiff_t>(s + 8), 0);
  pe.bytes[s] = '/';
  pe.bytes[s + 1] = '4';
  Image img = parse(to_bytes(pe.bytes));
  EXPECT_EQ(img.sections[2].name, ".debug_info");
}

TEST(Pe, RealMinGwIfAvailable) {
  if (std::string(REVKIT_TEST_MINGW_CC).empty()) GTEST_SKIP() << "no mingw cross compiler";
  auto dir = testing::scratch_dir("pe-mingw");
  auto exe = dir / "prog.exe";
  ASSERT_TRUE(testing::compile(REVKIT_TEST_MINGW_CC,
                               "__declspec(dllexport) int add(int a, int b) { return a + b; }\n"
                               "int main(void) { return add(1, 2); }\n",
                               "-O1", exe));
  Image img = load_file(exe);
  EXPECT_EQ(img.format, Format::pe);
  EXPECT_TRUE(std::any_of(img.exports.begin(), img.exports.end(), [](const Export &e) { return e.name == "add"; }));
  EXPECT_FALSE(img.imports.empty());
  EXPECT_FALSE(img.function_ranges.empty());
}

// A chained RUNTIME_FUNCTION (UNWIND_INFO flags UNW_FLAG_CHAININFO, or
// unwind data that is another RUNTIME_FUNCTION) is a fragment of a
// function another entry starts, not a function: MSVC's shrink-wrapped and
// separated code. Only the first entry stays.
TEST(Pe, ChainedUnwindEntriesAreNotFunctions) {
  for (std::uint32_t unwind : {0x23f1u /* indirect: low bit set */, 0x23f0u /* CHAININFO */}) {
    testing::PeImage pe = build_pe();
    // .rdata 0x2000 is at file offset 0x600: UNWIND_INFO version 1, flags 4.
    pe.bytes[0x600 + 0x3f0] = 0x01 | (4 << 3);
    // The second RUNTIME_FUNCTION (at .pdata 0x300c, file 0xa0c) points at it.
    for (int i = 0; i < 4; ++i) pe.bytes[0xa0c + 8 + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(unwind >> (8 * i));
    Image img = parse(to_bytes(pe.bytes));
    ASSERT_EQ(img.function_ranges.size(), 1u) << std::hex << unwind;
    EXPECT_EQ(img.function_ranges[0].start, 0x140001000u);
  }
}

}  // namespace
}  // namespace revkit::loader
