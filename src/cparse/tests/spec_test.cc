// Profiles from Ghidra's own compiler specs agree with the named targets
// (needs the Ghidra install the build was configured with).

#include "revkit/cparse/cparse.h"
#include "revkit/cparse/spec.h"
#include "revkit/lift/lifter.hh"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>

namespace {

using namespace revkit;

class CParseSpec : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::filesystem::exists(REVKIT_GHIDRA_ROOT)) lift::initialize(REVKIT_GHIDRA_ROOT);
  }
  void SetUp() override {
    if (!lift::ghidra_root()) GTEST_SKIP() << "no Ghidra install at " << REVKIT_GHIDRA_ROOT;
  }
};

TEST_F(CParseSpec, CompilerSpecsGiveTheNamedTargets) {
  struct Case {
    const char *language, *compiler, *format, *target;
  };
  for (const Case &c : {Case{"x86:LE:64:default", "gcc", "elf", "x86_64-linux-gnu"},
                        Case{"AARCH64:LE:64:v8A", "default", "elf", "aarch64-linux-gnu"},
                        Case{"RISCV:LE:64:RV64GC", "gcc", "elf", "riscv64-linux-gnu"},
                        Case{"x86:LE:64:default", "windows", "pe", "x86_64-pc-windows-msvc"},
                        Case{"x86:LE:32:default", "gcc", "elf", "i386-linux-gnu"},
                        Case{"x86:LE:32:default", "windows", "pe", "i386-pc-windows-msvc"},
                        Case{"ARM:LE:32:v8", "default", "elf", "arm-linux-gnueabihf"}}) {
    std::vector<std::string> notes;
    cparse::Profile p = cparse::profile_for_language(c.language, c.compiler, c.format, &notes);
    cparse::Profile want = *cparse::profile_named(c.target);
    EXPECT_EQ(p.name, want.name) << c.language;
    EXPECT_EQ(p.rules.pointer_size, want.rules.pointer_size) << c.language;
    EXPECT_EQ(p.rules.long_size, want.rules.long_size) << c.language;
    EXPECT_EQ(p.rules.long_double_size, want.rules.long_double_size) << c.language;
    EXPECT_EQ(p.rules.wchar_size, want.rules.wchar_size) << c.language;
    EXPECT_EQ(p.rules.char_signed, want.rules.char_signed) << c.language;
    EXPECT_EQ(p.rules.bitfields, want.rules.bitfields) << c.language;
    for (std::uint32_t size : {1u, 2u, 4u, 8u, 16u})
      EXPECT_EQ(p.rules.scalar_align(size), want.rules.scalar_align(size)) << c.language << " size " << size;
  }
}

// The address-space languages (8- and 16-bit microcontrollers, 16- and
// 24-bit pointers): the sizes their compilers use (avr-gcc, SDCC, Keil,
// msp430-gcc), from the spec where it has them, else the microcontroller
// defaults, and a note saying so.
TEST_F(CParseSpec, MicrocontrollerTargets) {
  static const std::string kHeader =
      "#include <stdint.h>\n"
      "struct dev { uint8_t flags; uint16_t count; void *buf; void (*cb)(int); long total; int n; unsigned mode : 3; };\n";
  struct Case {
    const char *language, *compiler;
    std::uint32_t pointer, int_size;
    std::uint64_t size, count_at;
    bool spec_profile;  // the spec gives the data model
  };
  for (const Case &c : {Case{"avr8:LE:16:atmega256", "gcc", 2, 2, 14, 1, false},
                        Case{"8051:BE:16:default", "default", 2, 2, 14, 1, false},
                        Case{"80390:BE:24:default", "default", 3, 2, 16, 1, false},
                        Case{"z80:LE:16:default", "default", 2, 2, 14, 1, false},
                        Case{"TI_MSP430:LE:16:default", "default", 2, 2, 16, 2, false}}) {
    std::vector<std::string> notes;
    cparse::Options o;
    o.profile = cparse::profile_for_language(c.language, c.compiler, "raw", &notes);
    EXPECT_EQ(o.profile.rules.pointer_size, c.pointer) << c.language;
    EXPECT_EQ(o.profile.rules.int_size, c.int_size) << c.language;
    EXPECT_EQ(o.profile.rules.long_size, 4u) << c.language;
    bool noted = false;
    for (const std::string &n : notes) noted |= n.find("microcontrollers") != std::string::npos;
    EXPECT_TRUE(noted || c.spec_profile) << c.language;
    types::TypeStore store;
    const cparse::Source src{"dev.h", kHeader, false};
    cparse::Result r = cparse::parse(store, std::span(&src, 1), o);
    EXPECT_EQ(r.errors, 0u) << c.language << (r.diagnostics.empty() ? "" : ": " + r.diagnostics[0].text);
    auto dev = std::find_if(r.named.begin(), r.named.end(), [](const cparse::NamedType &n) { return n.key == "struct dev"; });
    ASSERT_NE(dev, r.named.end()) << c.language;
    EXPECT_EQ(store.size_of(dev->id), c.size) << c.language;
    const auto *agg = store.get(dev->id).as<types::AggregateType>();
    ASSERT_NE(agg, nullptr);
    EXPECT_EQ(agg->fields.at(1).bit_offset, c.count_at * 8) << c.language;
  }
}

}  // namespace
