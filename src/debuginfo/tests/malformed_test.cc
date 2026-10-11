// Malformed input: the reader must never crash, hang or read out of
// bounds, and should say what it skipped.

#include "revkit/debuginfo/dwarf.h"
#include "revkit/debuginfo/image.h"
#include "revkit/loader/load.hh"
#include "revkit/types/print.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <random>

namespace revkit::debuginfo {
namespace {

using Bytes = std::vector<std::uint8_t>;

// Imports and prints everything, the way rk-dwarf would.
DebugInfo exercise(const Sections &sec) {
  types::TypeStore store;
  DebugInfo info = import_dwarf(sec, store);
  for (const Function &f : info.functions) {
    (void)types::prototype(store, f.prototype, f.name);
    (void)types::prototype(store, f.prototype, f.name, {types::Style::Ghidra});
  }
  for (types::TypeId id : info.types) (void)types::definition(store, id);
  return info;
}

struct Owned {
  std::map<std::string, Bytes> data;
  Sections view() const {
    Sections s;
    for (const auto &[name, bytes] : data) s.by_name.emplace(name, bytes);
    return s;
  }
};

// A DWARF 4 unit: header, then `dies`; abbreviations in `abbrev`.
Owned unit4(const Bytes &abbrev, const Bytes &dies) {
  Bytes info;
  std::uint32_t len = std::uint32_t(2 + 4 + 1 + dies.size());
  for (int i = 0; i < 4; ++i) info.push_back(std::uint8_t(len >> (8 * i)));
  info.insert(info.end(), {4, 0, 0, 0, 0, 0, 8});
  info.insert(info.end(), dies.begin(), dies.end());
  Owned o;
  o.data[".debug_info"] = info;
  o.data[".debug_abbrev"] = abbrev;
  return o;
}

// Abbreviations: 1 = compile unit (children), 2 = pointer type (ref4
// type, data1 byte_size), 3 = base type (string name, data1 size, data1
// encoding).
const Bytes kAbbrev = {1, 0x11, 1, 0, 0,
                       2, 0x0f, 0, 0x49, 0x13, 0x0b, 0x0b, 0, 0,
                       3, 0x24, 0, 0x03, 0x08, 0x0b, 0x0b, 0x3e, 0x0b, 0, 0,
                       0};

TEST(Malformed, EmptyInput) {
  Sections none;
  DebugInfo info = exercise(none);
  EXPECT_TRUE(info.functions.empty());
  EXPECT_TRUE(info.diagnostics.empty());
}

TEST(Malformed, PointerToItself) {
  // DIE at unit offset 12 is a pointer whose target is itself.
  Owned o = unit4(kAbbrev, {1, 2, 12, 0, 0, 0, 8, 0, 0});
  DebugInfo info = exercise(o.view());
  EXPECT_FALSE(info.types.empty());
  ASSERT_FALSE(info.diagnostics.empty());
  EXPECT_NE(info.diagnostics.back().message.find("cycle"), std::string::npos);
}

TEST(Malformed, DanglingReference) {
  Owned o = unit4(kAbbrev, {1, 2, 0xff, 0xff, 0, 0, 8, 0, 0});
  DebugInfo info = exercise(o.view());
  EXPECT_FALSE(info.types.empty());
}

TEST(Malformed, UnitLengthPastEnd) {
  Owned o = unit4(kAbbrev, {1, 3, 'i', 'n', 't', 0, 4, 5, 0});
  o.data[".debug_info"][0] = 0xf0;
  DebugInfo info = exercise(o.view());
  ASSERT_EQ(info.diagnostics.size(), 1u);
  EXPECT_NE(info.diagnostics[0].message.find("past end"), std::string::npos);
}

TEST(Malformed, BadVersionAndAddressSize) {
  Owned o = unit4(kAbbrev, {1, 0});
  o.data[".debug_info"][4] = 9;
  EXPECT_EQ(exercise(o.view()).diagnostics.size(), 1u);
  Owned p = unit4(kAbbrev, {1, 0});
  p.data[".debug_info"][10] = 3;
  EXPECT_EQ(exercise(p.view()).diagnostics.size(), 1u);
}

TEST(Malformed, UnknownFormAndAbbrev) {
  Bytes abbrev = {1, 0x11, 1, 0x03, 0x7e, 0, 0, 0};  // form 0x7e does not exist
  EXPECT_FALSE(exercise(unit4(abbrev, {1, 0}).view()).diagnostics.empty());
  EXPECT_FALSE(exercise(unit4(kAbbrev, {9, 0}).view()).diagnostics.empty());
}

TEST(Malformed, IndirectFormLoop) {
  Bytes abbrev = {1, 0x11, 1, 0x03, 0x16, 0, 0, 0};  // DW_AT_name, DW_FORM_indirect
  Bytes dies = {1};
  for (int i = 0; i < 20; ++i) dies.push_back(0x16);
  EXPECT_FALSE(exercise(unit4(abbrev, dies).view()).diagnostics.empty());
}

TEST(Malformed, UnterminatedStringAndAbbrevTable) {
  EXPECT_FALSE(exercise(unit4(kAbbrev, {1, 3, 'i', 'n', 't'}).view()).diagnostics.empty());
  EXPECT_FALSE(exercise(unit4({1, 0x11}, {1, 0}).view()).diagnostics.empty());
}

std::optional<loader::Image> fixture() {
  std::string path = std::string(REVKIT_FIXTURE_DIR) + "/gcc-dwarf5";
  if (!std::filesystem::exists(path)) return std::nullopt;
  return loader::load_file(path);
}

Owned copy_debug(const loader::Image &image) {
  Owned o;
  ImageSections secs = dwarf_sections(image);
  for (const auto &[name, span] : secs.sections.by_name)
    o.data[name] = Bytes(span.begin(), span.end());
  return o;
}

TEST(Malformed, TruncatedSections) {
  auto elf = fixture();
  if (!elf) GTEST_SKIP();
  Owned base = copy_debug(*elf);
  for (const char *name : {".debug_info", ".debug_abbrev", ".debug_str", ".debug_line_str",
                           ".debug_rnglists"}) {
    if (!base.data.count(name)) continue;
    const std::size_t full = base.data[name].size();
    for (std::size_t cut = 0; cut < full; cut += std::max<std::size_t>(1, full / 97)) {
      Owned o = base;
      o.data[name].resize(cut);
      exercise(o.view());
    }
  }
}

TEST(Malformed, RandomMutations) {
  auto elf = fixture();
  if (!elf) GTEST_SKIP();
  Owned base = copy_debug(*elf);
  std::vector<std::string> names;
  for (const auto &[n, b] : base.data)
    if (!b.empty()) names.push_back(n);
  std::mt19937 rng(1234);
  for (int iter = 0; iter < 1500; ++iter) {
    Owned o = base;
    int flips = 1 + int(rng() % 8);
    for (int k = 0; k < flips; ++k) {
      Bytes &b = o.data[names[rng() % names.size()]];
      b[rng() % b.size()] = std::uint8_t(rng());
    }
    exercise(o.view());
  }
}

}  // namespace
}  // namespace revkit::debuginfo
