#include "builders.hh"

#include "revkit/lift/context.hh"
#include "revkit/lift/functions.hh"
#include "revkit/lift/image_arch.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <chrono>

#include "funcdata.hh"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace revkit::lift {

// Readable gtest failure messages.
void PrintTo(const Varnode &v, std::ostream *os) {
  *os << "(" << v.space << ", 0x" << std::hex << v.offset << std::dec << ", " << v.size
      << (v.referenced_space.empty() ? "" : ", " + v.referenced_space) << ")";
}

namespace {

using loader::Image;
using testing::ElfBuilder;
using testing::to_bytes;

class Lift : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    initialize(REVKIT_GHIDRA_ROOT);
  }

  // A one-segment executable holding `code` at `addr`.
  static std::shared_ptr<const Image> code_image(std::uint16_t machine, bool wide, std::uint64_t addr,
                                                 std::vector<std::uint8_t> code) {
    ElfBuilder b({.wide = wide, .big = false, .machine = machine, .type = 2, .flags = 0, .entry = addr});
    b.add_load(".text", addr, std::move(code), 5);
    return std::make_shared<const Image>(loader::parse(to_bytes(b.build())));
  }

  static const PcodeOp *find_op(const Instruction &insn, const std::string &opcode) {
    auto it = std::find_if(insn.pcode.begin(), insn.pcode.end(),
                           [&](const PcodeOp &op) { return op.opcode == opcode; });
    return it == insn.pcode.end() ? nullptr : &*it;
  }
};

TEST_F(Lift, EveryMappedLanguageExistsInGhidra) {
  for (const loader::LanguageSpec &spec : loader::all_language_specs())
    EXPECT_TRUE(language_exists(spec.id())) << spec.id();
  EXPECT_FALSE(language_exists("x86:LE:64:nonsense"));
  EXPECT_FALSE(language_exists("x86:LE:64:default:nonsense"));
}

TEST_F(Lift, X86_64AddRegisters) {
  auto img = code_image(62, true, 0x401000, {0x48, 0x01, 0xd8});  // add rax, rbx
  Lifter lifter(img, "x86:LE:64:default:gcc");
  EXPECT_EQ(lifter.language(), "x86:LE:64:default");
  auto insn = lifter.lift(0x401000);
  ASSERT_TRUE(insn);
  EXPECT_EQ(insn->length, 3u);
  EXPECT_EQ(insn->mnemonic, "ADD");
  EXPECT_EQ(insn->text, "ADD RAX,RBX");

  // RAX is register 0x0 and RBX 0x18 in x86-64.sla.
  const PcodeOp *add = find_op(*insn, "INT_ADD");
  ASSERT_NE(add, nullptr);
  ASSERT_TRUE(add->output);
  EXPECT_EQ(*add->output, (Varnode{"register", 0x0, 8, {}}));
  ASSERT_EQ(add->inputs.size(), 2u);
  EXPECT_EQ(add->inputs[0], (Varnode{"register", 0x0, 8, {}}));
  EXPECT_EQ(add->inputs[1], (Varnode{"register", 0x18, 8, {}}));
  // Flags are computed too.
  EXPECT_NE(find_op(*insn, "INT_CARRY"), nullptr);
  EXPECT_NE(find_op(*insn, "INT_SCARRY"), nullptr);

  // Lifting is repeatable.
  auto again = lifter.lift(0x401000);
  ASSERT_TRUE(again);
  ASSERT_EQ(again->pcode.size(), insn->pcode.size());
}

TEST_F(Lift, LoadNamesItsAddressSpace) {
  auto img = code_image(62, true, 0x401000, {0x48, 0x8b, 0x03});  // mov rax, [rbx]
  Lifter lifter(img, "x86:LE:64:default");
  auto insn = lifter.lift(0x401000);
  ASSERT_TRUE(insn);
  const PcodeOp *load = find_op(*insn, "LOAD");
  ASSERT_NE(load, nullptr);
  ASSERT_EQ(load->inputs.size(), 2u);
  EXPECT_EQ(load->inputs[0].space, "space");
  EXPECT_EQ(load->inputs[0].referenced_space, "ram");
  EXPECT_EQ(load->inputs[1], (Varnode{"register", 0x18, 8, {}}));
}

TEST_F(Lift, AArch64Add) {
  auto img = code_image(183, true, 0x400000, {0x20, 0x00, 0x02, 0x8b});  // add x0, x1, x2
  Lifter lifter(img, "AARCH64:LE:64:v8A");
  auto insn = lifter.lift(0x400000);
  ASSERT_TRUE(insn);
  EXPECT_EQ(insn->length, 4u);
  EXPECT_EQ(insn->text, "add x0,x1,x2");  // Java strips spaces between operands
  const PcodeOp *add = find_op(*insn, "INT_ADD");
  ASSERT_NE(add, nullptr);
  // x0..x2 are consecutive 8-byte registers at 0x4000 in AARCH64.sla. The
  // spec routes x2 and the sum through temporaries:
  //   u1 = COPY x2; u2 = INT_ADD x1, u1; ...flags...; x0 = COPY u2
  ASSERT_GE(insn->pcode.size(), 3u);
  const PcodeOp &first = insn->pcode.front();
  const PcodeOp &last = insn->pcode.back();
  EXPECT_EQ(first.opcode, "COPY");
  EXPECT_EQ(first.inputs[0], (Varnode{"register", 0x4010, 8, {}}));
  EXPECT_EQ(add->inputs[0], (Varnode{"register", 0x4008, 8, {}}));
  EXPECT_EQ(add->inputs[1], *first.output);
  EXPECT_EQ(last.opcode, "COPY");
  EXPECT_EQ(*last.output, (Varnode{"register", 0x4000, 8, {}}));
  EXPECT_EQ(last.inputs[0], *add->output);
}

TEST_F(Lift, ArmAndThumbFromContext) {
  // ARM code at 0x8000, Thumb code at 0x8010, marked by mapping symbols.
  ElfBuilder b({.wide = false, .big = false, .machine = 40, .type = 2, .flags = 0x05000000, .entry = 0x8000});
  std::vector<std::uint8_t> code = {0x00, 0x00, 0xa0, 0xe3,   // mov r0, #0
                                    0x1e, 0xff, 0x2f, 0xe1,   // bx lr
                                    0, 0, 0, 0, 0, 0, 0, 0,  //
                                    0x00, 0x20,               // movs r0, #0
                                    0x70, 0x47};              // bx lr
  b.add_load(".text", 0x8000, code, 5);
  b.add_symbol("$a", 0x8000, 0, 0, 0, 1);
  b.add_symbol("$d", 0x8008, 0, 0, 0, 1);
  b.add_symbol("$t", 0x8010, 0, 0, 0, 1);
  b.add_symbol("arm_fn", 0x8000, 8, 2, 1, 1);
  b.add_symbol("thumb_fn", 0x8011, 4, 2, 1, 1);
  auto img = std::make_shared<const Image>(loader::parse(to_bytes(b.build())));
  EXPECT_EQ(loader::guess_language(*img)->id(), "ARM:LE:32:v8:default");

  // Without image context the .pspec default (TMode=0, ARM) applies everywhere.
  Lifter plain(img, "ARM:LE:32:v8");
  auto arm = plain.lift(0x8000);
  ASSERT_TRUE(arm);
  EXPECT_EQ(arm->length, 4u);
  EXPECT_EQ(arm->mnemonic, "mov");
  auto wrong = plain.lift(0x8010);
  ASSERT_TRUE(wrong);
  EXPECT_EQ(wrong->length, 4u);

  auto ctx = image_context(*img);
  ASSERT_FALSE(ctx.empty());
  EXPECT_EQ(ctx.front().name, "TMode");
  EXPECT_EQ(ctx.front().start, 0x8010u);

  Lifter lifter(img, "ARM:LE:32:v8");
  for (const ContextRegion &c : ctx) lifter.set_context(c.name, c.value, c.start, c.end);
  auto thumb = lifter.lift(0x8010);
  ASSERT_TRUE(thumb);
  EXPECT_EQ(thumb->length, 2u);
  EXPECT_EQ(thumb->mnemonic, "movs");
  auto bx = lifter.lift(0x8012);
  ASSERT_TRUE(bx);
  EXPECT_EQ(bx->length, 2u);
  EXPECT_NE(find_op(*bx, "RETURN"), nullptr);
  // ARM code outside the region is unaffected, even after a rebuild.
  EXPECT_EQ(lifter.lift(0x8000)->length, 4u);

  EXPECT_THROW(lifter.set_context("NoSuchVariable", 1, 0x8000), LiftError);

  // Many settings before a decode cost one rebuild, not one each (rk-lift
  // paints every Thumb function's body: thousands on a firmware image).
  // A rebuild is tens of milliseconds, so 400 of them would take seconds.
  Lifter many(img, "ARM:LE:32:v8");
  const auto started = std::chrono::steady_clock::now();
  for (std::uint64_t a = 0x100000; a < 0x100000 + 400 * 0x10; a += 0x10) many.set_context("TMode", 1, a, a + 8);
  many.set_context("TMode", 1, 0x8010, 0x8014);
  EXPECT_THROW(many.set_context("NoSuchVariable", 1, 0x8000), LiftError);  // still checked while stale
  EXPECT_EQ(many.lift(0x8010)->length, 2u);
  EXPECT_EQ(many.lift(0x8000)->length, 4u);
  EXPECT_LT(std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count(), 2.0);

  // Data between the functions is marked, and the Thumb bit is dropped from
  // function entries.
  auto data = embedded_data(*img);
  ASSERT_EQ(data.size(), 1u);
  EXPECT_EQ(data[0], (AddressRange{0x8008, 0x800f}));
  auto fns = function_symbols(*img);
  ASSERT_EQ(fns.size(), 2u);
  EXPECT_EQ(fns[1].name, "thumb_fn");
  EXPECT_EQ(fns[1].entry, 0x8010u);
}

// Bytes that are not code can decode through a constructor tree deeper than
// SLEIGH's fixed parser state; that is bad data, not a crash (patch 0005).
TEST_F(Lift, ArmBytesNestingTooDeepAreBadData) {
  auto img = code_image(40, false, 0x1000, {0x3e, 0x6a, 0x6d, 0x0d, 0, 0, 0, 0});
  Lifter lifter(img, "ARM:LE:32:v7");
  auto insn = lifter.lift(0x1000);
  EXPECT_FALSE(insn && insn->length == 4 && insn->mnemonic == "vldr") << "decoded";
  // The lifter stays usable afterwards.
  EXPECT_TRUE(lifter.lift(0x1004));
}

// A branch whose delay slot holds an instruction the language has no
// semantics for: SLEIGH's error handler read a walker that was gone (patch
// 0009). The branch is unimplemented, and nothing crashes.
TEST_F(Lift, UnimplementedDelaySlotIsUnimplemented) {
  auto img = code_image(2, false, 0x3a10, {0x38, 0xb5, 0x10, 0xb3, 0xa1, 0xb1, 0x14, 0x4c, 0x62, 0x68, 0x23, 0x46});
  Lifter lifter(img, "sparc:BE:32:default");
  auto insn = lifter.lift_pcode(0x3a10);
  ASSERT_TRUE(insn);
  EXPECT_TRUE(insn->unimplemented);
  EXPECT_TRUE(insn->pcode.empty());
}

// microMIPS bc2f uses its condition operand's value, but that operand's
// constructors export nothing: SLEIGH read a handle that was never set
// (patch 0010). The branch is unimplemented, and nothing crashes; the
// lifter stays usable.
TEST_F(Lift, OperandThatExportsNothingIsUnimplemented) {
  auto img = code_image(8, false, 0x1000, {0x8c, 0x42, 0x00, 0xa0, 0x22, 0x4f, 0x43, 0x60});
  Lifter lifter(img, "MIPS:LE:32:micro");
  lifter.set_context("ISA_MODE", 1, 0);
  auto insn = lifter.lift(0x1000);
  ASSERT_TRUE(insn);
  EXPECT_EQ(insn->mnemonic, "bc2f");
  EXPECT_TRUE(insn->unimplemented);
  EXPECT_TRUE(insn->pcode.empty());
  EXPECT_TRUE(lifter.lift(0x1004));
}

// Text follows Ghidra's Java Instruction.toString(), not C++ printAssembly.
TEST_F(Lift, TextMatchesGhidraJavaFormatting) {
  // jmp +2: branch targets are addresses, zero-padded to 8 digits.
  auto x86 = code_image(62, true, 0x1000, {0xeb, 0x02, 0x48, 0x8b, 0x45, 0xf0});  // jmp; mov rax,[rbp-0x10]
  Lifter x(x86, "x86:LE:64:default");
  EXPECT_EQ(x.lift(0x1000)->text, "JMP 0x00001004");
  EXPECT_EQ(x.lift(0x1002)->text, "MOV RAX,qword ptr [RBP + -0x10]");

  // Spaces after commas go between operands, but stay inside one.
  auto a64 = code_image(183, true, 0x400000, {0xe1, 0x0f, 0x40, 0xb9});  // ldr w1, [sp, #0xc]
  Lifter a(a64, "AARCH64:LE:64:v8A");
  EXPECT_EQ(a.lift(0x400000)->text, "ldr w1,[sp, #0xc]");
}

TEST_F(Lift, TypedTokens) {
  // mov rax,qword ptr [rbp + -0x10]; call 0x1010; lea rdi,[rip+0x10]
  auto img = code_image(62, true, 0x1000,
                        {0x48, 0x8b, 0x45, 0xf0, 0xe8, 0x07, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x3d, 0x10, 0x00, 0x00, 0x00});
  Lifter lifter(img, "x86:LE:64:default");
  auto mov = lifter.lift(0x1000);
  ASSERT_TRUE(mov);
  std::string joined;
  for (const Token &t : mov->tokens) joined += t.text;
  EXPECT_EQ(joined, mov->text);
  using K = Token::Kind;
  ASSERT_GE(mov->tokens.size(), 4u);
  EXPECT_EQ(mov->tokens[0].kind, K::mnemonic);
  EXPECT_EQ(mov->tokens[0].operand, -1);
  auto find = [](const Instruction &i, const std::string &text) {
    auto it = std::find_if(i.tokens.begin(), i.tokens.end(), [&](const Token &t) { return t.text == text; });
    return it == i.tokens.end() ? nullptr : &*it;
  };
  const Token *rax = find(*mov, "RAX");
  ASSERT_NE(rax, nullptr);
  EXPECT_EQ(rax->kind, K::reg);
  EXPECT_EQ(rax->operand, 0);
  EXPECT_EQ(rax->reg, (Varnode{"register", 0x0, 8, {}}));
  const Token *rbp = find(*mov, "RBP");
  ASSERT_NE(rbp, nullptr);
  EXPECT_EQ(rbp->operand, 1);
  const Token *disp = find(*mov, "-0x10");
  ASSERT_NE(disp, nullptr);
  EXPECT_EQ(disp->kind, K::scalar);
  EXPECT_EQ(static_cast<std::int64_t>(disp->value), -0x10);
  EXPECT_EQ(find(*mov, "qword")->kind, K::separator);
  EXPECT_EQ(find(*mov, ",")->operand, -1);  // between operands

  auto call = lifter.lift(0x1004);
  ASSERT_TRUE(call);
  const Token *target = find(*call, "0x00001010");
  ASSERT_NE(target, nullptr);
  EXPECT_EQ(target->kind, K::address);
  EXPECT_EQ(target->value, 0x1010u);

  auto lea = lifter.lift(0x1009);
  ASSERT_TRUE(lea);
  // RIP-relative operands print as scalars (no zero padding), as in Java.
  const Token *rel = find(*lea, "0x1020");  // next (0x1010) + 0x10
  ASSERT_NE(rel, nullptr);
  EXPECT_EQ(rel->kind, K::scalar);
  EXPECT_EQ(rel->value, 0x1020u);
}

// Each ImageArchitecture has its own translator: a second instance of the
// same language must not re-point the first at its own image.
TEST_F(Lift, ArchitecturesOfOneLanguageAreIndependent) {
  auto decompile = [](ImageArchitecture &arch, std::uint64_t addr) {
    ghidra::AddrSpace *code = arch.getDefaultCodeSpace();
    ghidra::Address entry(code, addr);
    ghidra::Funcdata *fd = arch.symboltab->getGlobalScope()->queryFunction(entry);
    if (fd == nullptr) fd = arch.symboltab->getGlobalScope()->addFunction(entry, "f")->getFunction();
    fd->followFlow(ghidra::Address(code, 0), ghidra::Address(code, code->getHighest()));
    ghidra::Action *pipeline = arch.allacts.getCurrent();
    pipeline->reset(*fd);
    pipeline->perform(*fd);
    std::ostringstream out;
    arch.print->setOutputStream(&out);
    arch.print->docFunction(fd);
    fd->clear();
    return out.str();
  };
  auto one = code_image(62, true, 0x1000, {0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3});  // mov eax,1; ret
  auto two = code_image(62, true, 0x1000, {0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3});  // mov eax,2; ret
  ImageArchitecture a(one, "one", "x86:LE:64:default:gcc", &std::cerr);
  a.init_image();
  ImageArchitecture b(two, "two", "x86:LE:64:default:gcc", &std::cerr);
  b.init_image();
  EXPECT_NE(decompile(a, 0x1000).find("return 1;"), std::string::npos);
  EXPECT_NE(decompile(b, 0x1000).find("return 2;"), std::string::npos);
  EXPECT_NE(decompile(a, 0x1000).find("return 1;"), std::string::npos);
}

TEST_F(Lift, MipsDelaySlot) {
  ElfBuilder b({.wide = false, .big = true, .machine = 8, .type = 2, .flags = 0x70001007, .entry = 0x400000});
  b.add_load(".text", 0x400000, {0x03, 0xe0, 0x00, 0x08, 0x24, 0x02, 0x00, 0x01}, 5);  // jr ra; li v0,1
  auto img = std::make_shared<const Image>(loader::parse(to_bytes(b.build())));
  EXPECT_EQ(loader::guess_language(*img)->id(), "MIPS:BE:32:default:default");
  Lifter lifter(img, "MIPS:BE:32:default");
  auto insns = lifter.lift_range(0x400000, 0x400008);
  ASSERT_EQ(insns.size(), 2u);
  EXPECT_EQ(insns[0].text, "jr ra");
  EXPECT_EQ(insns[0].delay_slot, 4u);
  // The branch's p-code includes its delay slot, which comes before the return.
  EXPECT_EQ(insns[0].pcode.back().opcode, "RETURN");
  EXPECT_GT(insns[0].pcode.size(), 1u);
  // Ghidra marks the delay-slot instruction with a leading underscore.
  EXPECT_EQ(insns[1].mnemonic, "_li");
  EXPECT_EQ(insns[1].text, "_li v0,0x1");
}

std::vector<std::byte> as_bytes(std::vector<std::uint8_t> v) {
  std::vector<std::byte> out;
  for (std::uint8_t b : v) out.push_back(std::byte{b});
  return out;
}

TEST_F(Lift, DecodesSuppliedBytesWithoutTouchingTheImage) {
  auto img = code_image(62, true, 0x1000, {0x48, 0x01, 0xd8, 0xc3});  // add rax, rbx; ret
  Lifter lifter(img, "x86:LE:64:default");
  // Same bytes, same instruction.
  auto same = lifter.lift(0x1000, as_bytes({0x48, 0x01, 0xd8, 0xc3}));
  ASSERT_TRUE(same);
  EXPECT_EQ(same->text, "ADD RAX,RBX");
  // Other bytes at the same address (a patch, or another program) win, and
  // neither decode leaks into the other through SLEIGH's parse cache.
  auto image_first = lifter.lift(0x1000);
  auto patched = lifter.lift(0x1000, as_bytes({0x31, 0xc0}));  // xor eax, eax
  ASSERT_TRUE(image_first && patched);
  EXPECT_EQ(patched->text, "XOR EAX,EAX");
  EXPECT_EQ(patched->length, 2u);
  EXPECT_EQ(lifter.lift(0x1000)->text, "ADD RAX,RBX");
  EXPECT_EQ(lifter.lift(0x1000, as_bytes({0x90}))->text, "NOP");
  // Addresses the image doesn't map decode fine from supplied bytes.
  auto elsewhere = lifter.lift(0x7000, as_bytes({0xc3}));
  ASSERT_TRUE(elsewhere);
  EXPECT_EQ(elsewhere->pcode.back().opcode, "RETURN");
  // A truncated instruction sees zeros past the span, as at the end of a
  // segment; an empty span decodes nothing.
  auto cut = lifter.lift(0x1000, as_bytes({0x48, 0x01}));
  auto zero_padded = lifter.lift(0x1000, as_bytes({0x48, 0x01, 0x00}));
  ASSERT_TRUE(cut && zero_padded);
  EXPECT_EQ(cut->text, zero_padded->text);
  EXPECT_FALSE(lifter.lift(0x1000, std::span<const std::byte>()));
}

TEST_F(Lift, SuppliedBytesCoverDelaySlots) {
  ElfBuilder b({.wide = false, .big = true, .machine = 8, .type = 2, .flags = 0x70001007, .entry = 0x400000});
  b.add_load(".text", 0x400000, {0x00, 0x00, 0x00, 0x00}, 5);
  auto img = std::make_shared<const Image>(loader::parse(to_bytes(b.build())));
  Lifter lifter(img, "MIPS:BE:32:default");
  auto jr = lifter.lift(0x400000, as_bytes({0x03, 0xe0, 0x00, 0x08, 0x24, 0x02, 0x00, 0x01}));  // jr ra; li v0,1
  ASSERT_TRUE(jr);
  EXPECT_EQ(jr->text, "jr ra");
  EXPECT_EQ(jr->delay_slot, 4u);
  EXPECT_EQ(jr->pcode.back().opcode, "RETURN");
  EXPECT_EQ(lifter.lift(0x400000)->text, "nop");
}

TEST_F(Lift, MemorySpaces) {
  auto img = code_image(62, true, 0x1000, {0xc3});
  EXPECT_EQ(Lifter(img, "x86:LE:64:default").memory_spaces(), (std::vector<std::string>{"ram"}));
  auto rv = code_image(243, true, 0x1000, {0x82, 0x80});
  EXPECT_EQ(Lifter(rv, "RISCV:LE:64:RV64GC").memory_spaces(), (std::vector<std::string>{"ram", "csreg"}));
}

TEST_F(Lift, FlowBodySkipsDataAfterJump) {
  // jmp +2; int3; int3; xor eax,eax; ret
  auto img = code_image(62, true, 0x1000, {0xeb, 0x02, 0xcc, 0xcc, 0x31, 0xc0, 0xc3});
  Lifter lifter(img, "x86:LE:64:default");
  auto body = lifter.flow_body(0x1000);
  ASSERT_EQ(body.size(), 2u);
  EXPECT_EQ(body[0], (AddressRange{0x1000, 0x1001}));
  EXPECT_EQ(body[1], (AddressRange{0x1004, 0x1006}));
  EXPECT_TRUE(lifter.flow_body(0x9999).empty());  // unmapped
}

TEST_F(Lift, UnmappedAndUndecodable) {
  auto img = code_image(62, true, 0x1000, {0x0f, 0xff});  // ud0 needs a ModRM byte: runs off the end
  Lifter lifter(img, "x86:LE:64:default");
  EXPECT_FALSE(lifter.lift(0x5000));
  EXPECT_FALSE(lifter.lift(0xffffffffffffffffULL));
  auto swept = lifter.lift_range(0x1000, 0x1002);  // must terminate whatever decodes
  EXPECT_LE(swept.size(), 2u);
}

TEST_F(Lift, RejectsUnknownLanguage) {
  auto img = code_image(62, true, 0x1000, {0xc3});
  EXPECT_THROW(Lifter(img, "NoSuch:LE:64:default"), LiftError);
}

constexpr const char *kProgram = R"(
int add(int a, int b) { return a + b; }
int main(int argc, char **argv) { return add(argc, argv[0][0]); }
)";

// Lifts a real compiled function end to end and checks the sweep is gapless.
void check_real_function(const std::string &compiler, const std::string &flags, const std::string &name) {
  auto dir = testing::scratch_dir(name);
  auto exe = dir / "prog";
  if (!testing::compile(compiler, kProgram, flags, exe)) GTEST_SKIP() << "compiler unavailable: " << compiler;

  auto img = std::make_shared<const Image>(
      loader::load_file(exe, {.image_base = std::nullopt, .ghidra_image_base = true}));
  auto lang = loader::guess_language(*img);
  ASSERT_TRUE(lang);
  Lifter lifter(img, lang->language);
  auto functions = seed_functions(*img, lifter);
  auto add = std::find_if(functions.begin(), functions.end(), [](const Function &f) { return f.name == "add"; });
  auto main_fn = std::find_if(functions.begin(), functions.end(), [](const Function &f) { return f.name == "main"; });
  ASSERT_NE(add, functions.end());
  ASSERT_NE(main_fn, functions.end());
  ASSERT_EQ(add->body.size(), 1u);
  EXPECT_GE(add->entry, 0x100000u);

  auto insns = lifter.lift_range(add->body[0].first, add->body[0].second + 1);
  ASSERT_FALSE(insns.empty());
  std::uint64_t covered = 0;
  for (const Instruction &i : insns) {
    EXPECT_FALSE(i.unimplemented) << i.text;
    EXPECT_FALSE(i.mnemonic.empty());
    covered += i.length;
  }
  EXPECT_EQ(covered, add->body[0].second - add->body[0].first + 1);
  ASSERT_FALSE(insns.back().pcode.empty());
  EXPECT_EQ(insns.back().pcode.back().opcode, "RETURN");

  // main calls add directly.
  auto main_insns = lifter.lift_range(main_fn->body[0].first, main_fn->body[0].second + 1);
  bool calls_add = std::any_of(main_insns.begin(), main_insns.end(), [&](const Instruction &i) {
    return std::any_of(i.pcode.begin(), i.pcode.end(), [&](const PcodeOp &op) {
      return op.opcode == "CALL" && op.inputs[0].space == "ram" && op.inputs[0].offset == add->entry;
    });
  });
  EXPECT_TRUE(calls_add);
}

TEST_F(Lift, RealX86_64Binary) { check_real_function(REVKIT_TEST_CC, "-O1 -fno-inline", "lift-x86-64"); }

TEST_F(Lift, RealAArch64Binary) { check_real_function(REVKIT_TEST_AARCH64_CC, "-O1 -fno-inline", "lift-aarch64"); }

TEST_F(Lift, RealRiscV64Binary) { check_real_function(REVKIT_TEST_RISCV64_CC, "-O1 -fno-inline", "lift-riscv64"); }

// Small processors' specs say which of their memory is I/O registers.
TEST_F(Lift, ProcessorVolatileRanges) {
  const std::vector<VolatileRange> avr = processor_volatile_ranges("avr8:LE:16:default");
  ASSERT_FALSE(avr.empty());
  EXPECT_EQ(avr.front(), (VolatileRange{"mem", 0x20, 0x57}));
  EXPECT_TRUE(processor_volatile_ranges("x86:LE:64:default").empty());
  EXPECT_TRUE(processor_volatile_ranges("nonsense:LE:1:none").empty());
}

}  // namespace
}  // namespace revkit::lift
