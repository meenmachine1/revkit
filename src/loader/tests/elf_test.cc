#include "builders.hh"

#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <algorithm>

namespace revkit::loader {
namespace {

using testing::compile;
using testing::ElfBuilder;
using testing::ElfSpec;
using testing::scratch_dir;
using testing::to_bytes;

constexpr const char *kProgram = R"(
int add(int a, int b) { return a + b; }
int counter = 3;
int scratch[64];
int main(void) { return add(counter, scratch[1]); }
)";

const Symbol *find_symbol(const Image &img, const std::string &name) {
  auto it = std::find_if(img.symbols.begin(), img.symbols.end(), [&](const Symbol &s) { return s.name == name; });
  return it == img.symbols.end() ? nullptr : &*it;
}

const Block *find_block(const Image &img, const std::string &name) {
  auto it = std::find_if(img.blocks.begin(), img.blocks.end(), [&](const Block &b) { return b.name == name; });
  return it == img.blocks.end() ? nullptr : &*it;
}

// Checks the parts every real Linux executable has.
void expect_linux_executable(const Image &img) {
  EXPECT_EQ(img.format, Format::elf);
  ASSERT_TRUE(img.entry.has_value());

  const Symbol *main_sym = find_symbol(img, "main");
  const Symbol *add_sym = find_symbol(img, "add");
  ASSERT_NE(main_sym, nullptr);
  ASSERT_NE(add_sym, nullptr);
  EXPECT_EQ(main_sym->type, SymbolType::func);
  EXPECT_TRUE(main_sym->defined);
  EXPECT_GT(main_sym->size, 0u);
  EXPECT_GT(add_sym->size, 0u);
  const Symbol *counter = find_symbol(img, "counter");
  ASSERT_NE(counter, nullptr);
  EXPECT_EQ(counter->type, SymbolType::object);
  EXPECT_EQ(counter->size, 4u);

  // Imports appear as undefined dynamic symbols.
  auto libc_start = std::find_if(img.symbols.begin(), img.symbols.end(), [](const Symbol &s) {
    return s.name == "__libc_start_main" && s.source == SymbolSource::dynsym;
  });
  ASSERT_NE(libc_start, img.symbols.end());
  EXPECT_FALSE(libc_start->defined);

  // Code is mapped executable, and main's bytes are readable.
  const Region *code = img.memory.find(main_sym->value);
  ASSERT_NE(code, nullptr);
  EXPECT_TRUE(code->perms.exec);
  EXPECT_FALSE(code->perms.write);
  std::vector<std::byte> buf(main_sym->size);
  EXPECT_EQ(img.memory.read(main_sym->value, buf), buf.size());

  const Block *text = find_block(img, ".text");
  ASSERT_NE(text, nullptr);
  EXPECT_EQ(text->perms.str(), "r-x");
  EXPECT_LE(text->start, main_sym->value);
  const Block *data = find_block(img, ".data");
  ASSERT_NE(data, nullptr);
  EXPECT_EQ(data->perms.str(), "rw-");
  const Block *bss = find_block(img, ".bss");
  ASSERT_NE(bss, nullptr);
  EXPECT_FALSE(bss->initialized);
  // .bss reads as zeros.
  const Symbol *scratch = find_symbol(img, "scratch");
  ASSERT_NE(scratch, nullptr);
  std::vector<std::byte> zeros(16, std::byte{0xff});
  EXPECT_EQ(img.memory.read(scratch->value, zeros), zeros.size());
  EXPECT_TRUE(std::all_of(zeros.begin(), zeros.end(), [](std::byte b) { return b == std::byte{0}; }));

  // Blocks are sorted and disjoint.
  for (std::size_t i = 1; i < img.blocks.size(); ++i)
    EXPECT_LT(img.blocks[i - 1].start + img.blocks[i - 1].size - 1, img.blocks[i].start);

  EXPECT_TRUE(std::any_of(img.segments.begin(), img.segments.end(), [](const Segment &s) { return s.type == 1; }));

  // .eh_frame gives every compiled function's extent, symbols or not.
  auto fde = std::find_if(img.function_ranges.begin(), img.function_ranges.end(),
                          [&](const FunctionRange &r) { return r.start == main_sym->value; });
  ASSERT_NE(fde, img.function_ranges.end());
  EXPECT_EQ(fde->end, main_sym->value + main_sym->size);
  EXPECT_TRUE(std::is_sorted(img.function_ranges.begin(), img.function_ranges.end(),
                             [](const FunctionRange &a, const FunctionRange &b) { return a.start < b.start; }));
}

TEST(ElfReal, HostX86_64Pie) {
  auto dir = scratch_dir("elf-x86-64");
  auto exe = dir / "prog";
  if (!compile(REVKIT_TEST_CC, kProgram, "-O1 -pie -fPIE", exe)) GTEST_SKIP() << "no host C compiler";

  Image img = load_file(exe);
  expect_linux_executable(img);
  EXPECT_EQ(img.bits, 64u);
  EXPECT_EQ(img.endian, Endian::little);
  EXPECT_EQ(img.machine, 62u);
  EXPECT_EQ(img.elf_type, 3);  // ET_DYN
  EXPECT_EQ(img.image_base, 0u);
  auto lang = guess_language(img);
  ASSERT_TRUE(lang);
  EXPECT_EQ(lang->id(), "x86:LE:64:default:gcc");

  // Ghidra's default base moves a PIE to 0x100000, and everything with it.
  Image rebased = load_file(exe, {.image_base = std::nullopt, .ghidra_image_base = true});
  EXPECT_EQ(rebased.image_base, 0x100000u);
  EXPECT_EQ(*rebased.entry, *img.entry + 0x100000);
  EXPECT_EQ(find_symbol(rebased, "main")->value, find_symbol(img, "main")->value + 0x100000);
  EXPECT_EQ(find_block(rebased, ".text")->start, find_block(img, ".text")->start + 0x100000);
  // The ELF header is the first loaded segment's uncovered part.
  ASSERT_FALSE(rebased.blocks.empty());
  EXPECT_EQ(rebased.blocks.front().start, 0x100000u);
  EXPECT_EQ(rebased.blocks.front().name.rfind("segment_", 0), 0u);

  // An explicit base wins.
  Image at = load_file(exe, {.image_base = 0x7000000, .ghidra_image_base = true});
  EXPECT_EQ(at.image_base, 0x7000000u);
}

TEST(ElfReal, HostX86_64NonPieKeepsBase) {
  auto dir = scratch_dir("elf-x86-64-nopie");
  auto exe = dir / "prog";
  if (!compile(REVKIT_TEST_CC, kProgram, "-O1 -no-pie", exe)) GTEST_SKIP() << "no host C compiler";
  Image img = load_file(exe, {.image_base = std::nullopt, .ghidra_image_base = true});
  expect_linux_executable(img);
  EXPECT_EQ(img.elf_type, 2);  // ET_EXEC
  EXPECT_EQ(img.image_base, 0x400000u);
}

// Compressed debug sections inflate to the same bytes as uncompressed ones.
TEST(ElfReal, CompressedDebugSections) {
  auto dir = scratch_dir("elf-gz");
  auto plain = dir / "plain", gz = dir / "gz";
  if (!compile(REVKIT_TEST_CC, kProgram, "-g -O1", plain)) GTEST_SKIP() << "no host C compiler";
  std::string cmd = "objcopy --compress-debug-sections=zlib " + plain.string() + " " + gz.string() +
                    " 2>/dev/null";
  if (std::system(cmd.c_str()) != 0) GTEST_SKIP() << "no objcopy";
  Image a = load_file(plain), b = load_file(gz);
  const Section *sa = find_section(a, ".debug_info"), *sb = find_section(b, ".debug_info");
  ASSERT_NE(sa, nullptr);
  ASSERT_NE(sb, nullptr);
  if (!(sb->flags & 0x800)) GTEST_SKIP() << "compiler did not compress .debug_info";
  EXPECT_NE(section_bytes(b, *sb).size(), section_bytes(a, *sa).size());
  Bytes inflated = section_contents(b, *sb);
  EXPECT_EQ(inflated, section_contents(a, *sa));

  // A corrupt stream or an absurd claimed size is an error, not a crash.
  auto bytes = std::make_shared<Bytes>(*b.file);
  for (std::uint64_t i = 24; i < sb->file_size; ++i) (*bytes)[sb->offset + i] = std::byte{0xff};
  Image bad = parse(bytes);
  EXPECT_THROW(section_contents(bad, *find_section(bad, ".debug_info")), LoadError);
  bytes = std::make_shared<Bytes>(*b.file);
  (*bytes)[sb->offset + 15] = std::byte{0x7f};  // ch_size's high byte
  bad = parse(bytes);
  EXPECT_THROW(section_contents(bad, *find_section(bad, ".debug_info")), LoadError);
}

TEST(ElfReal, CrossAArch64) {
  auto dir = scratch_dir("elf-aarch64");
  auto exe = dir / "prog";
  if (!compile(REVKIT_TEST_AARCH64_CC, kProgram, "-O1", exe)) GTEST_SKIP() << "no aarch64 cross compiler";
  Image img = load_file(exe);
  expect_linux_executable(img);
  EXPECT_EQ(img.machine, 183u);
  auto lang = guess_language(img);
  ASSERT_TRUE(lang);
  EXPECT_EQ(lang->id(), "AARCH64:LE:64:v8A:default");
  // AArch64 instructions are 4 bytes; function sizes reflect that.
  EXPECT_EQ(find_symbol(img, "add")->size % 4, 0u);
}

// Imports through the PLT, a pointer table in .data.rel.ro, and a
// constructor in .init_array.
constexpr const char *kDynamicProgram = R"(
#include <stdio.h>
#include <stdlib.h>
static int ctor_ran;
__attribute__((constructor)) static void ctor(void) { ctor_ran = 1; }
int one(int x) { return x + 1; }
int two(int x) { return x * 2; }
int (*const table[])(int) = {one, two};
int main(int argc, char **argv) {
  puts(argv[0]);
  if (argc > 5) exit(3);
  return table[argc & 1](argc) + ctor_ran;
}
)";

const Relocation *find_relocation(const Image &img, const std::string &symbol, RelocationKind kind) {
  for (const Relocation &r : img.relocations)
    if (r.symbol == symbol && r.kind == kind) return &r;
  return nullptr;
}

const Block *block_at(const Image &img, std::uint64_t addr) {
  for (const Block &b : img.blocks)
    if (addr >= b.start && addr - b.start < b.size) return &b;
  return nullptr;
}

// Relocations, PLT layout and init arrays of a dynamically linked program,
// loaded at Ghidra's base so every address must have moved with it.
void expect_dynamic_metadata(const Image &img, std::uint64_t plt_header) {
  ASSERT_FALSE(img.relocations.empty());
  EXPECT_TRUE(std::is_sorted(img.relocations.begin(), img.relocations.end(),
                             [](const Relocation &a, const Relocation &b) { return a.address < b.address; }));

  // puts is called through a PLT stub whose GOT slot has a JUMP_SLOT.
  const Relocation *puts = find_relocation(img, "puts", RelocationKind::jump_slot);
  ASSERT_NE(puts, nullptr);
  const Block *got = block_at(img, puts->address);
  ASSERT_NE(got, nullptr);
  EXPECT_EQ(got->name.rfind(".got", 0), 0u) << got->name;
  EXPECT_FALSE(puts->target.has_value());

  // table[] holds pointers to one() and two(): relative relocations whose
  // targets are the functions at this load address.
  const Symbol *table = find_symbol(img, "table");
  const Symbol *one = find_symbol(img, "one");
  const Symbol *two = find_symbol(img, "two");
  ASSERT_TRUE(table && one && two);
  std::vector<std::uint64_t> targets;
  for (const Relocation &r : img.relocations)
    if (r.address >= table->value && r.address < table->value + table->size) {
      EXPECT_EQ(r.kind, RelocationKind::relative);
      ASSERT_TRUE(r.target.has_value());
      targets.push_back(*r.target);
    }
  EXPECT_EQ(targets, (std::vector<std::uint64_t>{one->value, two->value}));

  // The constructor runs from .init_array.
  const Symbol *ctor = find_symbol(img, "ctor");
  ASSERT_NE(ctor, nullptr);
  EXPECT_NE(std::find(img.init_fini.init_array.begin(), img.init_fini.init_array.end(), ctor->value),
            img.init_fini.init_array.end());
  EXPECT_FALSE(img.init_fini.fini_array.empty());
  ASSERT_TRUE(img.init_fini.init.has_value());
  const Block *init = block_at(img, *img.init_fini.init);
  ASSERT_NE(init, nullptr);
  EXPECT_EQ(init->name, ".init");

  // The lazy-binding .plt has the machine's header and stub sizes.
  auto plt = std::find_if(img.plt_sections.begin(), img.plt_sections.end(),
                          [](const PltSection &p) { return p.name == ".plt"; });
  ASSERT_NE(plt, img.plt_sections.end());
  EXPECT_EQ(plt->start, find_block(img, ".plt")->start);
  EXPECT_EQ(plt->header_size, plt_header);
  EXPECT_EQ(plt->entry_size, 16u);
  for (const PltSection &p : img.plt_sections) {
    const Block *b = find_block(img, p.name);
    ASSERT_NE(b, nullptr);
    EXPECT_TRUE(b->perms.exec);
  }
}

TEST(ElfReal, HostX86_64RelocationsPltAndInitArrays) {
  auto dir = scratch_dir("elf-x86-64-dyn");
  auto exe = dir / "prog";
  if (!compile(REVKIT_TEST_CC, kDynamicProgram, "-O1 -pie -fPIE", exe)) GTEST_SKIP() << "no host C compiler";
  Image img = load_file(exe, {.image_base = std::nullopt, .ghidra_image_base = true});
  EXPECT_EQ(img.image_base, 0x100000u);
  expect_dynamic_metadata(img, 16);
  // Rebasing moves relocation addresses and relative targets together.
  Image linked = load_file(exe);
  ASSERT_EQ(linked.relocations.size(), img.relocations.size());
  for (std::size_t i = 0; i < img.relocations.size(); ++i) {
    EXPECT_EQ(img.relocations[i].address, linked.relocations[i].address + 0x100000);
    if (img.relocations[i].target) {
      EXPECT_EQ(*img.relocations[i].target, *linked.relocations[i].target + 0x100000);
    }
  }
}

TEST(ElfReal, CrossAArch64RelocationsPltAndInitArrays) {
  auto dir = scratch_dir("elf-aarch64-dyn");
  auto exe = dir / "prog";
  if (!compile(REVKIT_TEST_AARCH64_CC, kDynamicProgram, "-O1 -pie -fPIE", exe))
    GTEST_SKIP() << "no aarch64 cross compiler";
  Image img = load_file(exe, {.image_base = std::nullopt, .ghidra_image_base = true});
  expect_dynamic_metadata(img, 32);
  EXPECT_NE(find_relocation(img, "puts", RelocationKind::jump_slot)->type, 0u);
}

TEST(ElfReal, ObjectFileRelocationsAreStatic) {
  auto dir = scratch_dir("elf-x86-64-obj-rel");
  auto obj = dir / "prog.o";
  if (!compile(REVKIT_TEST_CC, kDynamicProgram, "-O1 -c", obj)) GTEST_SKIP() << "no host C compiler";
  Image img = load_file(obj);
  // Object files have the calls' static relocations (R_X86_64_PLT32 is
  // "other"), placed inside the section they patch: main's.
  auto puts = std::find_if(img.relocations.begin(), img.relocations.end(),
                           [](const Relocation &r) { return r.symbol == "puts"; });
  ASSERT_NE(puts, img.relocations.end());
  EXPECT_EQ(puts->kind, RelocationKind::other);
  const Symbol *main_sym = find_symbol(img, "main");
  ASSERT_NE(main_sym, nullptr);
  EXPECT_GE(puts->address, main_sym->value);
  EXPECT_LT(puts->address, main_sym->value + main_sym->size);
  EXPECT_TRUE(img.plt_sections.empty());
}

TEST(ElfReal, X86ObjectFileSectionsArePacked) {
  auto dir = scratch_dir("elf-i386-obj");
  auto obj = dir / "prog.o";
  if (!compile(REVKIT_TEST_CC, kProgram, "-m32 -O1 -c", obj)) GTEST_SKIP() << "no -m32 support";
  Image img = load_file(obj, {.image_base = std::nullopt, .ghidra_image_base = true});
  EXPECT_EQ(img.bits, 32u);
  EXPECT_EQ(img.elf_type, 1);  // ET_REL
  EXPECT_FALSE(img.entry.has_value());
  auto lang = guess_language(img);
  ASSERT_TRUE(lang);
  EXPECT_EQ(lang->id(), "x86:LE:32:default:gcc");
  EXPECT_EQ(img.image_base, 0x10000u);

  // Sections get addresses from the base, symbols move with their section.
  const Block *text = find_block(img, ".text");
  ASSERT_NE(text, nullptr);
  EXPECT_GE(text->start, 0x10000u);
  const Symbol *add = find_symbol(img, "add");
  ASSERT_NE(add, nullptr);
  EXPECT_GE(add->value, text->start);
  EXPECT_LT(add->value, text->start + text->size);
  EXPECT_TRUE(img.memory.find(add->value)->perms.exec);
}

TEST(ElfSynthetic, BigEndian32BitPowerPC) {
  ElfBuilder b({.wide = false, .big = true, .machine = 20, .type = 2, .flags = 0, .entry = 0x10000100});
  b.add_load(".text", 0x10000100, {0x38, 0x60, 0x00, 0x01, 0x4e, 0x80, 0x00, 0x20}, 5);  // li r3,1; blr
  b.add_load(".data", 0x10010000, {0xde, 0xad, 0xbe, 0xef}, 6);
  b.add_symbol("f", 0x10000100, 8, 2, 1, 1);
  b.add_symbol("word", 0x10010000, 4, 1, 1, 2);
  Image img = parse(to_bytes(b.build()));

  EXPECT_EQ(img.bits, 32u);
  EXPECT_EQ(img.endian, Endian::big);
  EXPECT_EQ(*img.entry, 0x10000100u);
  EXPECT_EQ(img.image_base, 0x10000100u);
  ASSERT_EQ(img.segments.size(), 2u);
  EXPECT_EQ(img.segments[1].vaddr, 0x10010000u);
  ASSERT_EQ(img.symbols.size(), 2u);
  EXPECT_EQ(img.symbols[0].name, "f");
  EXPECT_EQ(img.symbols[0].size, 8u);
  EXPECT_EQ(img.symbols[1].type, SymbolType::object);
  std::array<std::byte, 4> word{};
  EXPECT_EQ(img.memory.read(0x10010000, word), 4u);
  EXPECT_EQ(word[0], std::byte{0xde});
  EXPECT_EQ(guess_language(img)->id(), "PowerPC:BE:32:default:default");
  ASSERT_EQ(img.blocks.size(), 2u);
  EXPECT_EQ(img.blocks[0].name, ".text");
  EXPECT_EQ(img.blocks[0].perms.str(), "r-x");
  EXPECT_EQ(img.blocks[1].perms.str(), "rw-");
}

TEST(ElfSynthetic, BssSegmentIsZeroFilledWithoutAllocating) {
  ElfBuilder b({.wide = true, .big = false, .machine = 62, .type = 2, .flags = 0, .entry = 0x400000});
  b.add_load(".text", 0x400000, {0xc3}, 5);
  // A huge .bss must not allocate memory proportional to its size.
  b.add_load(".bss", 0x10000000, {}, 6, 0x100000000ULL, true);
  Image img = parse(to_bytes(b.build()));
  const Region *bss = img.memory.find(0x10000000 + 0xfffffff0ULL);
  ASSERT_NE(bss, nullptr);
  EXPECT_EQ(bss->file_size, 0u);
  std::array<std::byte, 8> buf{};
  buf.fill(std::byte{1});
  EXPECT_EQ(img.memory.read(0x10000000 + 0xfffffff0ULL, buf), 8u);
  EXPECT_EQ(buf[0], std::byte{0});
}

struct LangCase {
  std::uint16_t machine;
  bool wide;
  bool big;
  std::uint32_t flags;
  const char *expected;
};

class ElfLanguage : public ::testing::TestWithParam<LangCase> {};

TEST_P(ElfLanguage, MapsMachineToGhidraLanguage) {
  const LangCase &c = GetParam();
  ElfBuilder b({.wide = c.wide, .big = c.big, .machine = c.machine, .type = 2, .flags = c.flags, .entry = 0x1000});
  b.add_load(".text", 0x1000, {0, 0, 0, 0}, 5);
  Image img = parse(to_bytes(b.build()));
  auto lang = guess_language(img);
  ASSERT_TRUE(lang);
  EXPECT_EQ(lang->id(), c.expected);
}

INSTANTIATE_TEST_SUITE_P(
    Machines, ElfLanguage,
    ::testing::Values(LangCase{62, true, false, 0, "x86:LE:64:default:gcc"},
                      LangCase{3, false, false, 0, "x86:LE:32:default:gcc"},
                      LangCase{183, true, false, 0, "AARCH64:LE:64:v8A:default"},
                      LangCase{183, true, true, 0, "AARCH64:BE:64:v8A:default"},
                      LangCase{40, false, false, 0x05000000, "ARM:LE:32:v8:default"},
                      LangCase{40, false, true, 0x05000000, "ARM:BE:32:v8:default"},
                      LangCase{40, false, true, 0x05800000, "ARM:LEBE:32:v8LEInstruction:default"},
                      LangCase{243, true, false, 0x5, "RISCV:LE:64:default:gcc"},
                      LangCase{243, false, false, 0x5, "RISCV:LE:32:default:gcc"},
                      LangCase{8, false, true, 0x70001007, "MIPS:BE:32:default:default"},
                      LangCase{8, false, false, 0x70001007, "MIPS:LE:32:default:default"},
                      LangCase{8, false, true, 0x80000027, "MIPS:BE:64:64-32addr:n32"},
                      LangCase{8, false, true, 0x90001407, "MIPS:BE:32:R6:default"},
                      LangCase{8, false, false, 0x72001007, "MIPS:LE:32:micro:default"},
                      LangCase{8, true, true, 0x80000007, "MIPS:BE:64:default:default"},
                      LangCase{20, false, true, 0, "PowerPC:BE:32:default:default"},
                      LangCase{21, true, true, 1, "PowerPC:BE:64:default:default"},
                      LangCase{21, true, false, 2, "PowerPC:LE:64:default:default"}));

TEST(ElfLanguage, UnknownMachine) {
  ElfBuilder b({.wide = true, .big = false, .machine = 0x1234, .type = 2, .flags = 0, .entry = 0x1000});
  b.add_load(".text", 0x1000, {0}, 5);
  EXPECT_FALSE(guess_language(parse(to_bytes(b.build()))).has_value());
}

// The relocation table's type names (relocations.cc): per ELF machine, PE
// base relocation types by machine, a number for the rest.
TEST(Relocations, TypeNames) {
  Image img;
  img.format = Format::elf;
  img.machine = 62;  // EM_X86_64
  EXPECT_EQ(relocation_type_name(img, 7), "R_X86_64_JUMP_SLOT");
  EXPECT_EQ(relocation_type_name(img, 8), "R_X86_64_RELATIVE");
  EXPECT_EQ(relocation_type_name(img, 999), "type 999");
  img.machine = 183;  // EM_AARCH64
  EXPECT_EQ(relocation_type_name(img, 1027), "R_AARCH64_RELATIVE");
  img.machine = 243;  // EM_RISCV
  EXPECT_EQ(relocation_type_name(img, 5), "R_RISCV_JUMP_SLOT");
  img.machine = 0x9999;
  EXPECT_EQ(relocation_type_name(img, 5), "type 5");
  EXPECT_TRUE(pe_base_relocations(img).empty());
  img.format = Format::pe;
  img.machine = 0x8664;
  EXPECT_EQ(relocation_type_name(img, 10), "IMAGE_REL_BASED_DIR64");
  EXPECT_EQ(relocation_type_name(img, 3), "IMAGE_REL_BASED_HIGHLOW");
  EXPECT_EQ(relocation_type_name(img, 7), "IMAGE_REL_BASED_7");
  img.machine = 0x1c4;  // ARMNT
  EXPECT_EQ(relocation_type_name(img, 7), "IMAGE_REL_BASED_THUMB_MOV32");
}

}  // namespace
}  // namespace revkit::loader
