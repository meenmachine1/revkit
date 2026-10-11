// The assembler on real specs: encodings checked against the
// architectures' manuals (and by the disassembler, which every candidate
// already passes), ranking, context, prefixes, completion and errors.

#include "revkit/asm/assembler.hh"
#include "revkit/lift/lifter.hh"

#include <gtest/gtest.h>

#include <algorithm>
#include <memory>

namespace {

using revkit::assembler::Assembler;
using revkit::assembler::Options;
using Bytes = std::vector<std::uint8_t>;

class AssemblerTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() { revkit::lift::initialize(REVKIT_GHIDRA_ROOT); }

  static Assembler &arm() {
    static Assembler a("ARM:LE:32:v4t");
    return a;
  }
  static Assembler &x86() {
    static Assembler a("x86:LE:64:default");
    return a;
  }

  static bool has(const revkit::assembler::Result &r, const Bytes &b) {
    return std::any_of(r.candidates.begin(), r.candidates.end(), [&](const auto &c) { return c.bytes == b; });
  }
};

TEST_F(AssemblerTest, ArmImmediateAndBranch) {
  auto ctx = arm().default_context();
  auto r = arm().assemble(0x20040, "add r0,r0,#0x5f", ctx);
  ASSERT_FALSE(r.candidates.empty()) << r.error;
  EXPECT_EQ(r.candidates[0].bytes, (Bytes{0x5f, 0x00, 0x80, 0xe2}));  // e280005f
  EXPECT_EQ(r.candidates[0].text, "add r0,r0,#0x5f");

  // bl: (target - (pc + 8)) / 4 in 24 bits.
  r = arm().assemble(0x20040, "bl 0xa0000", ctx);
  ASSERT_FALSE(r.candidates.empty()) << r.error;
  EXPECT_EQ(r.candidates[0].bytes, (Bytes{0xee, 0xff, 0x01, 0xeb}));  // eb01ffee
  // Spelled as the listing prints it, zero-padded, or in decimal.
  EXPECT_FALSE(arm().assemble(0x20040, "bl 0x000a0000", ctx).candidates.empty());
  EXPECT_FALSE(arm().assemble(0x20040, "BL 655360", ctx).candidates.empty());
  // Out of reach of a 24-bit word offset: no encoding, and a reason.
  r = arm().assemble(0x0, "bl 0x10000000", ctx);
  EXPECT_TRUE(r.candidates.empty());
  EXPECT_FALSE(r.error.empty());
}

TEST_F(AssemblerTest, RankingKeepsTheToolchainsRotation) {
  auto ctx = arm().default_context();
  // 0x800 has four encodings: 0x02 ror 22 (canonical), 0x08 ror 24, 0x20
  // ror 26, 0x80 ror 28. With the non-canonical one at the address, it
  // comes first: an edit elsewhere keeps the toolchain's choice.
  const Bytes rot24{0x08, 0x1c, 0xa0, 0xe3};  // e3a01c08 mov r1,#0x800
  Options o;
  o.current = rot24;
  o.current_text = "mov r1,#0x800";
  auto r = arm().assemble(0x1000, "mov r1,#0x800", ctx, o);
  ASSERT_GE(r.candidates.size(), 4u) << r.error;
  EXPECT_EQ(r.candidates[0].bytes, rot24);
  EXPECT_TRUE(r.candidates[0].current);
  EXPECT_EQ(r.candidates[0].hamming, 0u);
  EXPECT_TRUE(has(r, Bytes{0x02, 0x1b, 0xa0, 0xe3}));  // e3a01b02

  // Changing the immediate keeps every other bit where it can.
  r = arm().assemble(0x1000, "mov r1,#0x900", ctx, o);
  ASSERT_FALSE(r.candidates.empty()) << r.error;
  EXPECT_EQ(r.candidates[0].bytes, (Bytes{0x09, 0x1c, 0xa0, 0xe3}));
  EXPECT_EQ(r.candidates[0].hamming, 1u);
}

TEST_F(AssemblerTest, CanonicalStaysCanonical) {
  // cmp r0,#0x4 encoded canonically (rotation 0): the new immediate is
  // canonical too (e3500009), though 0x24 ror 2 (e3500124) is one bit nearer.
  auto ctx = arm().default_context();
  const Bytes cur{0x04, 0x00, 0x50, 0xe3};
  Options o;
  o.current = cur;
  o.current_text = "cmp r0,#0x4";
  auto r = arm().assemble(0x8010, "cmp r0,#0x9", ctx, o);
  ASSERT_GE(r.candidates.size(), 2u) << r.error;
  EXPECT_EQ(r.candidates[0].bytes, (Bytes{0x09, 0x00, 0x50, 0xe3}));
  // Without the text there is nothing to tell: nearest first.
  o.current_text = {};
  r = arm().assemble(0x8010, "cmp r0,#0x9", ctx, o);
  EXPECT_EQ(r.candidates[0].bytes, (Bytes{0x24, 0x01, 0x50, 0xe3}));
}

TEST_F(AssemblerTest, ThumbFollowsTheContext) {
  auto ctx = arm().default_context();
  ASSERT_TRUE(arm().set_context(ctx, "TMode", 1));
  auto r = arm().assemble(0x2000, "mov r0,#0x1", ctx);
  ASSERT_FALSE(r.candidates.empty()) << r.error;
  EXPECT_EQ(r.candidates[0].bytes, (Bytes{0x01, 0x20}));  // movs r0,#1 (Ghidra prints mov in v4t Thumb)
  // The same text in ARM mode is four bytes.
  auto a = arm().assemble(0x2000, "mov r0,#0x1", arm().default_context());
  ASSERT_FALSE(a.candidates.empty());
  EXPECT_EQ(a.candidates[0].bytes.size(), 4u);
  // Thumb bl is two halfwords with the offset split between them.
  r = arm().assemble(0x2000, "bl 0x3000", ctx);
  ASSERT_FALSE(r.candidates.empty()) << r.error;
  EXPECT_EQ(r.candidates[0].bytes.size(), 4u);
  auto d = arm().disassemble(0x2000, r.candidates[0].bytes, ctx);
  ASSERT_TRUE(d);
  EXPECT_TRUE(Assembler::same_text(d->text, "bl 0x3000"));
}

TEST_F(AssemblerTest, LabelsResolveThroughTheCallback) {
  Options o;
  o.symbols = [](std::string_view name) -> std::optional<std::uint64_t> {
    if (name == "patch_cave") return 0xa0000;
    return std::nullopt;
  };
  auto r = arm().assemble(0x20040, "bl patch_cave", arm().default_context(), o);
  ASSERT_FALSE(r.candidates.empty()) << r.error;
  EXPECT_EQ(r.candidates[0].bytes, (Bytes{0xee, 0xff, 0x01, 0xeb}));
  r = arm().assemble(0x20040, "bl nowhere", arm().default_context(), o);
  EXPECT_TRUE(r.candidates.empty());
  EXPECT_GE(r.error_column, 3);
}

TEST_F(AssemblerTest, ErrorsSayWhereAndWhatWasExpected) {
  auto r = arm().assemble(0, "add r0,r0,", arm().default_context());
  EXPECT_TRUE(r.candidates.empty());
  EXPECT_EQ(r.error, "incomplete instruction");
  EXPECT_FALSE(r.expected.empty());
  EXPECT_NE(std::find(r.expected.begin(), r.expected.end(), "#"), r.expected.end());

  r = arm().assemble(0, "add r0,q9,#1", arm().default_context());
  EXPECT_TRUE(r.candidates.empty());
  EXPECT_EQ(r.error_column, 7);
  EXPECT_NE(std::find(r.expected.begin(), r.expected.end(), "r1"), r.expected.end());

  // An immediate no rotation can make.
  r = arm().assemble(0, "mov r0,#0x101", arm().default_context());
  EXPECT_TRUE(r.candidates.empty());
  EXPECT_FALSE(r.error.empty());
}

TEST_F(AssemblerTest, CompletionOffersMnemonicsAndRegisters) {
  auto c = arm().complete(0, "ad", 2, arm().default_context());
  EXPECT_EQ(c.from, 0u);
  EXPECT_NE(std::find(c.items.begin(), c.items.end(), "add"), c.items.end());
  EXPECT_EQ(std::find(c.items.begin(), c.items.end(), "mov"), c.items.end());
  c = arm().complete(0, "add r0,r", 8, arm().default_context());
  EXPECT_EQ(c.from, 7u);
  EXPECT_NE(std::find(c.items.begin(), c.items.end(), "r12"), c.items.end());
  c = arm().complete(0, "add r0,r1,", 10, arm().default_context());
  EXPECT_NE(std::find(c.items.begin(), c.items.end(), "#"), c.items.end());
}

TEST_F(AssemblerTest, X86PrefixesComeFromContext) {
  auto ctx = x86().default_context();
  auto r = x86().assemble(0x401000, "MOV EAX,0x1", ctx);
  ASSERT_FALSE(r.candidates.empty()) << r.error;
  EXPECT_EQ(r.candidates[0].bytes, (Bytes{0xb8, 0x01, 0x00, 0x00, 0x00}));
  // A 16-bit operand needs the 0x66 prefix: Ghidra's root recursion.
  r = x86().assemble(0x401000, "MOV AX,0x1", ctx);
  ASSERT_FALSE(r.candidates.empty()) << r.error;
  EXPECT_EQ(r.candidates[0].bytes, (Bytes{0x66, 0xb8, 0x01, 0x00}));
  // REX.W, solved backwards from the operand size through the prefix's
  // context operation.
  r = x86().assemble(0x401000, "MOV RAX,0x1", ctx);
  ASSERT_FALSE(r.candidates.empty()) << r.error;
  EXPECT_EQ(r.candidates[0].bytes.size(), 7u);  // 48 c7 c0 01 00 00 00
  EXPECT_EQ(r.candidates[0].bytes[0], 0x48);
  // RIP-relative: inst_next is backfilled once the length is known.
  r = x86().assemble(0x401000, "CALL 0x401234", ctx);
  ASSERT_FALSE(r.candidates.empty()) << r.error;
  EXPECT_EQ(r.candidates[0].bytes, (Bytes{0xe8, 0x2f, 0x02, 0x00, 0x00}));
}

TEST_F(AssemblerTest, AArch64) {
  Assembler a("AARCH64:LE:64:v8A");
  auto r = a.assemble(0x100000, "add x0,x1,#0x10", a.default_context());
  ASSERT_FALSE(r.candidates.empty()) << r.error;
  EXPECT_EQ(r.candidates[0].bytes, (Bytes{0x20, 0x40, 0x00, 0x91}));  // 91004020
  r = a.assemble(0x100000, "bl 0x100100", a.default_context());
  ASSERT_FALSE(r.candidates.empty()) << r.error;
  EXPECT_EQ(r.candidates[0].bytes, (Bytes{0x40, 0x00, 0x00, 0x94}));  // 94000040
}

TEST_F(AssemblerTest, SameTextComparesNumbersByValue) {
  EXPECT_TRUE(Assembler::same_text("bl 0x000a0000", "BL 0xa0000"));
  EXPECT_TRUE(Assembler::same_text("add r0, r0, #95", "add r0,r0,#0x5f"));
  EXPECT_TRUE(Assembler::same_text("cmp r0,#-0x1", "cmp r0,#0xffffffff"));
  EXPECT_FALSE(Assembler::same_text("add r0,r0,#0x5f", "add r0,r0,#0x5e"));
  EXPECT_FALSE(Assembler::same_text("add r0,r1", "add r0,r1,r2"));
}

TEST_F(AssemblerTest, GrammarsAreSharedAndQuickToReuse) {
  Assembler again("ARM:LE:32:v4t");
  EXPECT_EQ(again.stats().constructors, arm().stats().constructors);
  EXPECT_GT(arm().stats().productions, 500u);
}

}  // namespace
