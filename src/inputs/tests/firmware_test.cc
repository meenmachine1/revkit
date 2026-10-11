// A synthetic ARM firmware (src/analysis/tests/fixtures/armfw), built at
// test time with clang and ld.lld and loaded as a raw image: discovery
// finds its functions from the exception vectors alone (literal pools,
// interworking, jump tables, pointer tables, start patterns), and its
// functions decompile from revkit's own inputs, read-only image included.

#include "builders.hh"

#include "revkit/analysis/analysis.h"
#include "revkit/inputs/inputs.h"
#include "revkit/lift/decompile.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <array>
#include <cstdio>
#include <map>
#include <memory>
#include <sstream>

namespace revkit::inputs {
namespace {

namespace an = revkit::analysis;

constexpr const char *kLanguage = "ARM:LE:32:v4t:default";

class Firmware : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty() || std::string(REVKIT_TEST_CLANG).empty() ||
        std::string(REVKIT_TEST_LLD).empty() || std::string(REVKIT_TEST_OBJCOPY).empty())
      return;
    dir_ = testing::scratch_dir("armfw");
    const std::string cmd = std::string("sh ") + REVKIT_ARMFW_DIR + "/build.sh " + REVKIT_TEST_CLANG + " " +
                            REVKIT_TEST_LLD + " " + REVKIT_TEST_OBJCOPY + " " + dir_.string() + " >/dev/null 2>&1";
    if (std::system(cmd.c_str()) != 0) return;
    // The ground truth: the ELF's function symbols.
    auto elf = loader::load_file(dir_ / "fw.elf");
    for (const loader::Symbol &s : elf.symbols)
      if (s.type == loader::SymbolType::func) symbols_[s.value & ~std::uint64_t{1}] = s.name;
    built_ = !symbols_.empty();
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!built_) GTEST_SKIP() << "no clang, ld.lld and llvm-objcopy for armv4t";
    lift::initialize(REVKIT_GHIDRA_ROOT);
  }

  static std::shared_ptr<const loader::Image> Load(loader::Perms perms = {true, true, true}) {
    loader::RawOptions o;
    o.language = kLanguage;
    o.perms = perms;
    o.regions.push_back(loader::parse_raw_region("sysctrl:d0000000:1000"));
    return std::make_shared<const loader::Image>(loader::load_raw_file(dir_ / "fw.bin", o));
  }

  std::uint64_t Address(const std::string &name) const {
    for (const auto &[a, n] : symbols_)
      if (n == name) return a;
    ADD_FAILURE() << "no symbol " << name;
    return 0;
  }

  static inline std::filesystem::path dir_;
  static inline bool built_ = false;
  static inline std::map<std::uint64_t, std::string> symbols_;
};

TEST_F(Firmware, DiscoveryFindsTheFunctionsFromTheVectorsAlone) {
  auto image = Load();
  auto analysis = analyze(*image, kLanguage);
  const an::ProgramInfo &info = analysis->info();
  EXPECT_TRUE(info.search);
  EXPECT_FALSE(info.patterns.empty());
  EXPECT_EQ(info.isa_context, "TMode");
  ASSERT_TRUE(info.link_register);

  std::map<std::uint64_t, const an::FunctionInfo *> found;
  for (const an::FunctionInfo &f : analysis->functions().functions) found[f.entry.offset] = &f;
  // Every function symbol, except the veneer h3 tail-jumps into (it is
  // part of h3, as Ghidra's flow makes it).
  for (const auto &[a, name] : symbols_) {
    if (name == "__ARMv4ABSLongBXThunk_thumb_scale") continue;
    EXPECT_TRUE(found.contains(a)) << name << " at 0x" << std::hex << a;
  }
  // Nothing else but the processor's exception vectors.
  for (const auto &[a, f] : found)
    EXPECT_TRUE(symbols_.contains(a) || (f->seed & an::kSeedProcessor)) << f->name << " at 0x" << std::hex << a;
  EXPECT_EQ(found.at(0)->name, "Reset");

  // Thumb code is Thumb.
  for (const char *name : {"thumb_scale", "thumb_helper", "thumb_sum"}) {
    const an::FunctionInfo *f = found[Address(name)];
    ASSERT_NE(f, nullptr) << name;
    EXPECT_TRUE(f->flags & an::kFunctionThumb) << name;
    EXPECT_EQ(f->flow_key(), f->entry.offset | 1) << name;
  }
  EXPECT_FALSE(found[Address("main")]->flags & an::kFunctionThumb);
  // Only the start patterns find what nothing refers to.
  EXPECT_TRUE(found[Address("unreferenced")]->flags & an::kFunctionSearched);

  // main calls through the table with mov lr, pc; bx rN: those calls return.
  const an::FlowGraph &main = analysis->flow(Address("main"));
  bool calls_dispatch = false;
  for (const an::FlowInsn &i : main.insns)
    for (std::uint64_t t : i.targets) calls_dispatch = calls_dispatch || t == Address("dispatch");
  EXPECT_TRUE(calls_dispatch);

  // dispatch's switch: an ARM jump table (ldr pc, [rN, rM, lsl #2]) of
  // eight cases, its words data inside code.
  const an::FlowGraph &dispatch = analysis->flow(Address("dispatch"));
  const an::FlowInsn *table = nullptr;
  for (const an::FlowInsn &i : dispatch.insns)
    if (i.kind == an::FlowKind::jump_indirect) table = &i;
  ASSERT_NE(table, nullptr);
  EXPECT_EQ(table->targets.size(), 8u);
  bool table_is_data = false;
  for (const an::Range &r : dispatch.literals) table_is_data = table_is_data || r.contains(table->address + 4);
  EXPECT_TRUE(table_is_data);
  for (const an::FlowInsn &i : dispatch.insns) EXPECT_FALSE(i.address >= table->address + 4 && i.address < table->address + 36);

  // The same result on any number of threads.
  auto again = analyze(*image, kLanguage, 4);
  EXPECT_EQ(facts::encode_to_string(again->functions()), facts::encode_to_string(analysis->functions()));
}

TEST_F(Firmware, DecompilesFromOwnInputsWithTheImageReadOnly) {
  // Read-only, the decompiler folds bad_slot's 0xffffffff: storing through
  // it must not fail the function (patch 0004).
  for (bool writable : {true, false}) {
    auto image = Load({true, writable, true});
    auto analysis = analyze(*image, kLanguage);
    Program program{image, kLanguage, analysis.get(), nullptr};
    lift::DecompileConfig config;
    config.image = image;
    config.language_id = kLanguage;
    config.inputs = std::make_shared<const lift::DecompilerInputs>(assemble(program));
    config.default_labels = false;
    lift::InputDecompiler d(config);
    std::map<std::string, std::string> c;
    for (const char *name : {"poke_bad_slot", "thumb_sum", "mmio_init", "dispatch"}) {
      lift::DecompileResult r = d.decompile(Address(name));
      EXPECT_TRUE(r.ok) << name << (writable ? " (rwx)" : " (r-x)") << ": " << r.error;
      c[name] = r.c;
    }
    if (!writable) EXPECT_NE(c["poke_bad_slot"].find("0xffffffff"), std::string::npos) << c["poke_bad_slot"];
    // Thumb decodes as Thumb: a loop calling thumb_helper.
    EXPECT_NE(c["thumb_sum"].find("FUN_" + [&] {
      char buf[16];
      std::snprintf(buf, sizeof buf, "%08llx", static_cast<unsigned long long>(Address("thumb_helper")));
      return std::string(buf);
    }()), std::string::npos) << c["thumb_sum"];
    // MMIO is read again on every iteration (never folded): a loop.
    EXPECT_NE(c["mmio_init"].find("while"), std::string::npos) << c["mmio_init"];
    EXPECT_NE(c["dispatch"].find("switch"), std::string::npos) << c["dispatch"];
  }
}

// In the read/write/execute image (Ghidra's raw default), a literal-pool
// word no code writes is a constant where it holds a function's address
// (the reset handler's ldr r0, =main): the decompiler folds it. One
// holding a global's address in the image (sink, which h0 writes) stays a
// memory read: folded, a store there would be forwarded to later loads as
// if no interrupt or device could change it.
TEST_F(Firmware, LiteralPoolsHoldingCodeAreConstantsInAWritableImage) {
  auto image = Load();
  auto analysis = analyze(*image, kLanguage);
  Program program{image, kLanguage, analysis.get(), nullptr};
  lift::DecompilerInputs in = assemble(program);
  std::uint64_t sink = 0;  // a global variable (.data), not a function
  for (const loader::Symbol &s : loader::load_file(dir_ / "fw.elf").symbols)
    if (s.name == "sink") sink = s.value;
  ASSERT_NE(sink, 0u);
  auto word_at = [&](std::uint64_t a) {
    std::array<std::byte, 4> b{};
    image->memory.read(a, b);
    return std::uint64_t(b[0]) | std::uint64_t(b[1]) << 8 | std::uint64_t(b[2]) << 16 | std::uint64_t(b[3]) << 24;
  };
  int to_code = 0, to_sink = 0;
  for (const an::DataItem &d : analysis->data()->items) {
    if (!d.literal || d.written || d.length != 4) continue;
    const lift::DataFacts *f = nullptr;
    for (const lift::DataFacts &x : in.data)
      if (x.addr == d.address && x.space.empty()) f = &x;
    ASSERT_NE(f, nullptr);
    const std::uint64_t v = word_at(d.address);
    if (v == Address("main") || v == (Address("thumb_sum") | 1)) {
      ++to_code;
      EXPECT_EQ(f->mutability, lift::Mutability::constant) << f->name;
    }
    if (v == sink) {
      ++to_sink;
      EXPECT_EQ(f->mutability, lift::Mutability::normal) << f->name;
    }
  }
  EXPECT_GT(to_code, 0);
  EXPECT_GT(to_sink, 0);
}

// An ARMv7 raw image written out by hand, ARM and Thumb code side by side:
// each function decompiles in its own instruction set, whatever was
// decompiled before it, and Thumb code that runs on into another function's
// body is read as Thumb there too.
TEST(FirmwareContext, EachFunctionDecodesInItsOwnInstructionSet) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  constexpr const char *kV7 = "ARM:LE:32:v7:default";
  auto bytes = std::make_shared<loader::Bytes>(0x100);
  auto arm = [&](std::size_t at, std::initializer_list<std::uint32_t> words) {
    for (std::uint32_t w : words)
      for (int i = 0; i < 4; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  auto thumb = [&](std::size_t at, std::initializer_list<std::uint16_t> words) {
    for (std::uint16_t w : words)
      for (int i = 0; i < 2; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  auto bl = [&](std::size_t at, std::size_t target) {  // Thumb bl
    const auto off = static_cast<std::uint32_t>(target - (at + 4));
    thumb(at, {static_cast<std::uint16_t>(0xf000 | ((off >> 12) & 0x7ff)),
               static_cast<std::uint16_t>(0xf800 | ((off >> 1) & 0x7ff))});
  };
  for (std::size_t v = 4; v < 0x20; v += 4) arm(v, {0xeafffffe});  // b .
  arm(0x00, {0xea000006});                                         // b 0x20
  // reset (ARM): bl arm_add; ldr r0, =main + 1; bx r0
  arm(0x20, {0xeb000016, 0xe59f0000, 0xe12fff10, 0x00000041});
  // main (Thumb) at 0x40: push {lr}; bl f; bl shared; bl wrong; bl pick; pop {pc}
  thumb(0x40, {0xb500});
  bl(0x42, 0x60);
  bl(0x46, 0x66);
  bl(0x4a, 0x70);
  bl(0x4e, 0xa0);
  thumb(0x52, {0xbd00});
  // f (Thumb) at 0x60: cmp r0, #0; beq shared; adds r0, #1, and on into
  // shared at 0x66 (a function of its own: main calls it): adds r0, #2; bx lr
  thumb(0x60, {0x2800, 0xd000, 0x3001, 0x3002, 0x4770});
  // wrong (Thumb) at 0x70: a Thumb bl to ARM code (what data read as code
  // does): push {lr}; bl arm_add; pop {pc}
  thumb(0x70, {0xb500});
  bl(0x72, 0x80);
  thumb(0x76, {0xbd00});
  // arm_add (ARM) at 0x80: add r0, r0, #7; bx lr
  arm(0x80, {0xe2800007, 0xe12fff1e});
  // pick (Thumb-2) at 0xa0, an IT block, whose state SLEIGH carries from
  // one instruction to the next as context: cmp r0, #0; ite eq;
  // moveq r0, #5; movne r0, #9; bx lr
  thumb(0xa0, {0x2800, 0xbf0c, 0x2005, 0x2009, 0x4770});

  loader::RawOptions o;
  o.language = kV7;
  auto image = std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
  auto analysis = analyze(*image, kV7);
  std::map<std::uint64_t, const an::FunctionInfo *> found;
  for (const an::FunctionInfo &f : analysis->functions().functions) found[f.entry.offset] = &f;
  for (std::uint64_t a : {0x40u, 0x60u, 0x66u, 0x70u, 0x80u, 0xa0u}) ASSERT_TRUE(found.contains(a)) << std::hex << a;
  EXPECT_TRUE(found[0x60]->flags & an::kFunctionThumb);
  EXPECT_FALSE(found[0x80]->flags & an::kFunctionThumb);
  // f's flow runs on into shared's body.
  EXPECT_TRUE(found[0x60]->reach.contains(facts::Address{found[0x60]->entry.space, 0x66}));
  EXPECT_FALSE(found[0x60]->body.contains(facts::Address{found[0x60]->entry.space, 0x66}));

  Program program{image, kV7, analysis.get(), nullptr};
  lift::DecompileConfig config;
  config.image = image;
  config.language_id = kV7;
  config.inputs = std::make_shared<const lift::DecompilerInputs>(assemble(program));
  config.default_labels = false;
  lift::InputDecompiler d(config);
  auto c = [&](std::uint64_t entry) {
    lift::DecompileResult r = d.decompile(entry);
    EXPECT_TRUE(r.ok) << std::hex << entry << ": " << r.error;
    EXPECT_EQ(r.c.find("halt_baddata"), std::string::npos) << r.c;
    return r.c;
  };
  // Thumb past the body: f ends in shared.s add of 2.
  const std::string f = c(0x60);
  EXPECT_NE(f.find("+ 2"), std::string::npos) << f;
  // After a Thumb function whose bl "calls" it, arm_add is still ARM; and
  // the same again in the other order.
  c(0x70);
  const std::string add = c(0x80);
  EXPECT_NE(add.find("+ 7"), std::string::npos) << add;
  c(0x70);
  EXPECT_EQ(c(0x80), add);
  EXPECT_EQ(c(0x60), f);
  // Both arms of the IT block, each under its condition; and again.
  const std::string pick = c(0xa0);
  EXPECT_NE(pick.find("5;"), std::string::npos) << pick;
  EXPECT_NE(pick.find("9;"), std::string::npos) << pick;
  EXPECT_NE(pick.find("if"), std::string::npos) << pick;
  c(0x40);
  EXPECT_EQ(c(0xa0), pick);
}

// A Thumb-1 switch as gcc compiles it: a call to __gnu_thumb1_case_uqi,
// which reads a table of byte offsets at its return address and goes on at
// the case the index picks. Written out by hand, the helper byte for byte
// as libgcc has it.
TEST(FirmwareSwitchHelper, ACallToACaseHelperIsASwitch) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  constexpr const char *kV7 = "ARM:LE:32:v7:default";
  auto bytes = std::make_shared<loader::Bytes>(0x100);
  auto arm = [&](std::size_t at, std::initializer_list<std::uint32_t> words) {
    for (std::uint32_t w : words)
      for (int i = 0; i < 4; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  auto thumb = [&](std::size_t at, std::initializer_list<std::uint16_t> words) {
    for (std::uint16_t w : words)
      for (int i = 0; i < 2; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  auto bl = [&](std::size_t at, std::size_t target) {  // Thumb bl
    const auto off = static_cast<std::uint32_t>(target - (at + 4));
    thumb(at, {static_cast<std::uint16_t>(0xf000 | ((off >> 12) & 0x7ff)),
               static_cast<std::uint16_t>(0xf800 | ((off >> 1) & 0x7ff))});
  };
  for (std::size_t v = 4; v < 0x20; v += 4) arm(v, {0xeafffffe});  // b .
  arm(0x00, {0xea000006});                                         // b 0x20
  // reset (ARM): ldr r0, =main + 1; bx r0
  arm(0x20, {0xe59f0000, 0xe12fff10, 0x00000041});
  // main (Thumb) at 0x40: push {lr}; bl pick; pop {pc}
  thumb(0x40, {0xb500});
  bl(0x42, 0x60);
  thumb(0x46, {0xbd00});
  // pick (Thumb) at 0x60: push {r4, lr}; cmp r0, #3; bhi default;
  // bl __gnu_thumb1_case_uqi; the table (offsets from it, halved); the
  // cases, each movs r0, #n; b out; default: movs r0, #0; out: pop {r4, pc}
  thumb(0x60, {0xb510, 0x2803, 0xd80b});
  bl(0x66, 0xa0);
  for (std::size_t k = 0; k < 4; ++k) (*bytes)[0x6a + k] = static_cast<std::byte>(2 + 2 * k);
  thumb(0x6e, {0x200a, 0xe006, 0x2014, 0xe004, 0x201e, 0xe002, 0x2028, 0xe000, 0x2000, 0xbd10});
  // __gnu_thumb1_case_uqi at 0xa0: push {r1}; mov r1, lr; lsrs r1, r1, #1;
  // lsls r1, r1, #1; ldrb r1, [r1, r0]; lsls r1, r1, #1; add lr, r1;
  // pop {r1}; bx lr
  thumb(0xa0, {0xb402, 0x4671, 0x0849, 0x0049, 0x5c09, 0x0049, 0x448e, 0xbc02, 0x4770});

  loader::RawOptions o;
  o.language = kV7;
  auto image = std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
  auto analysis = analyze(*image, kV7);
  std::map<std::uint64_t, const an::FunctionInfo *> found;
  for (const an::FunctionInfo &f : analysis->functions().functions) found[f.entry.offset] = &f;
  for (std::uint64_t a : {0x40u, 0x60u, 0xa0u}) ASSERT_TRUE(found.contains(a)) << std::hex << a;
  // The helper has the name Ghidra's pattern gives it; the cases are part
  // of pick, not functions, and the table is not code.
  EXPECT_EQ(found[0xa0]->name, "__gnu_thumb1_case_uqi");
  EXPECT_EQ(found.size(), 8u + 1 + 3) << "the vectors, reset, main, pick and the helper";
  const facts::SpaceId space = found[0x60]->entry.space;
  for (std::uint64_t a : {0x6eu, 0x72u, 0x76u, 0x7au, 0x7eu, 0x80u})
    EXPECT_TRUE(found[0x60]->body.contains(facts::Address{space, a})) << std::hex << a;
  for (std::uint64_t a : {0x6au, 0x6cu}) EXPECT_FALSE(found[0x60]->body.contains(facts::Address{space, a})) << std::hex << a;
  const an::FlowGraph &pick = analysis->flow(found[0x60]->flow_key());
  const an::FlowInsn *call = pick.at(0x66);
  ASSERT_NE(call, nullptr);
  EXPECT_EQ(call->kind, an::FlowKind::jump_indirect);
  EXPECT_FALSE(call->falls_through);
  EXPECT_EQ(call->targets, (std::vector<std::uint64_t>{0x6e, 0x72, 0x76, 0x7a}));
  ASSERT_EQ(pick.case_calls.size(), 1u);
  EXPECT_EQ(pick.case_calls[0].first, 0x66u);
  EXPECT_EQ(pick.case_calls[0].second, found[0xa0]->flow_key());
  bool table_is_data = false;
  for (const an::Range &r : pick.literals) table_is_data = table_is_data || (r.first <= 0x6a && r.last >= 0x6d);
  EXPECT_TRUE(table_is_data);

  // The decompiler replaces the call by the compiler spec's call fixup
  // (the helper's name selects it) and shows the switch.
  Program program{image, kV7, analysis.get(), nullptr};
  const lift::DecompilerInputs inputs = assemble(program);
  for (const lift::FunctionFacts &f : inputs.functions)
    EXPECT_EQ(f.call_fixup, f.entry == 0xa0 ? "switch8_r0" : "") << std::hex << f.entry;
  lift::DecompileConfig config;
  config.image = image;
  config.language_id = kV7;
  config.inputs = std::make_shared<const lift::DecompilerInputs>(inputs);
  config.default_labels = false;
  lift::InputDecompiler d(config);
  lift::DecompileResult r = d.decompile(0x60);
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_NE(r.c.find("switch"), std::string::npos) << r.c;
  for (const char *value : {"10;", "0x14;", "0x1e;", "0x28;"}) EXPECT_NE(r.c.find(value), std::string::npos) << value << r.c;
  EXPECT_EQ(r.c.find("halt_baddata"), std::string::npos) << r.c;
  EXPECT_EQ(r.c.find("bad instruction"), std::string::npos) << r.c;
}

// A switch through `add pc, rN` whose guard isn't on the first path flow
// takes to the jump: an out-of-range index is clamped to case 0 on the way
// in (cmp r0, #3; bls 1f; movs r0, #0; 1: lsls r0, #1; add pc, r0), so the
// first path reaches the jump with the index a constant. The path through
// the guard finds the table, and the jump is the switch, not a jump to
// case 0.
TEST(FirmwareSwitch, AnAddPcSwitchWhoseGuardIsOnAnotherPath) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  constexpr const char *kV7 = "ARM:LE:32:v7:default";
  auto bytes = std::make_shared<loader::Bytes>(0x100);
  auto arm = [&](std::size_t at, std::initializer_list<std::uint32_t> words) {
    for (std::uint32_t w : words)
      for (int i = 0; i < 4; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  auto thumb = [&](std::size_t at, std::initializer_list<std::uint16_t> words) {
    for (std::uint16_t w : words)
      for (int i = 0; i < 2; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  auto bl = [&](std::size_t at, std::size_t target) {  // Thumb bl
    const auto off = static_cast<std::uint32_t>(target - (at + 4));
    thumb(at, {static_cast<std::uint16_t>(0xf000 | ((off >> 12) & 0x7ff)),
               static_cast<std::uint16_t>(0xf800 | ((off >> 1) & 0x7ff))});
  };
  for (std::size_t v = 4; v < 0x20; v += 4) arm(v, {0xeafffffe});  // b .
  arm(0x00, {0xea000006});                                         // b 0x20
  // reset (ARM): ldr r0, =main + 1; bx r0
  arm(0x20, {0xe59f0000, 0xe12fff10, 0x00000041});
  // main (Thumb) at 0x40: push {lr}; bl pick; pop {pc}
  thumb(0x40, {0xb500});
  bl(0x42, 0x60);
  thumb(0x46, {0xbd00});
  // pick (Thumb) at 0x60: push {r4, lr}; cmp r0, #3; bls 0x68; movs r0, #0;
  // 0x68: lsls r0, r0, #1; add pc, r0; (0x6c) nop; the table at 0x6e,
  // b case0..case3; the cases at 0x76, 0x7a, 0x7e, 0x82: movs r0, #n;
  // b out; out at 0x84: pop {r4, pc}
  thumb(0x60, {0xb510, 0x2803, 0xd900, 0x2000, 0x0040, 0x4487, 0xbf00});
  thumb(0x6e, {0xe002, 0xe003, 0xe004, 0xe005});
  thumb(0x76, {0x200a, 0xe004, 0x2014, 0xe002, 0x201e, 0xe000, 0x2028, 0xbd10});

  loader::RawOptions o;
  o.language = kV7;
  auto image = std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
  auto analysis = analyze(*image, kV7);
  std::map<std::uint64_t, const an::FunctionInfo *> found;
  for (const an::FunctionInfo &f : analysis->functions().functions) found[f.entry.offset] = &f;
  for (std::uint64_t a : {0x40u, 0x60u}) ASSERT_TRUE(found.contains(a)) << std::hex << a;
  const an::FlowGraph &pick = analysis->flow(found[0x60]->flow_key());
  const an::FlowInsn *jump = pick.at(0x6a);
  ASSERT_NE(jump, nullptr);
  EXPECT_EQ(jump->kind, an::FlowKind::jump_indirect);
  EXPECT_FALSE(jump->resolved);
  EXPECT_EQ(jump->targets, (std::vector<std::uint64_t>{0x6e, 0x70, 0x72, 0x74}));
  // Every case is pick's, none a function of its own.
  const facts::SpaceId space = found[0x60]->entry.space;
  for (std::uint64_t a : {0x76u, 0x7au, 0x7eu, 0x82u, 0x84u})
    EXPECT_TRUE(found[0x60]->body.contains(facts::Address{space, a})) << std::hex << a;
  for (std::uint64_t a : {0x76u, 0x7au, 0x7eu, 0x82u}) EXPECT_FALSE(found.contains(a)) << std::hex << a;

  // The decompiler shows every case's value.
  Program program{image, kV7, analysis.get(), nullptr};
  const lift::DecompilerInputs inputs = assemble(program);
  lift::DecompileConfig config;
  config.image = image;
  config.language_id = kV7;
  config.inputs = std::make_shared<const lift::DecompilerInputs>(inputs);
  config.default_labels = false;
  lift::InputDecompiler d(config);
  lift::DecompileResult r = d.decompile(0x60);
  ASSERT_TRUE(r.ok) << r.error;
  for (const char *value : {"10;", "0x14;", "0x1e;", "0x28;"}) EXPECT_NE(r.c.find(value), std::string::npos) << value << r.c;
  EXPECT_EQ(r.c.find("halt_baddata"), std::string::npos) << r.c;
}

// Code that returns from a stack frame it didn't make is the rest of a
// function, not a function: gcc's Thumb-1 far jump (a `bl` used as a
// branch, where a branch doesn't reach) goes to such code, and a pointer
// into the middle of a function points at such code. And a function that
// nothing calls is found by its prologue, further into a gap than where
// the gap starts.
TEST(FirmwareFragments, CodeThatReturnsFromAnothersFrameIsNoFunction) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  constexpr const char *kV7 = "ARM:LE:32:v7:default";
  auto bytes = std::make_shared<loader::Bytes>(0x100);
  auto arm = [&](std::size_t at, std::initializer_list<std::uint32_t> words) {
    for (std::uint32_t w : words)
      for (int i = 0; i < 4; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  auto thumb = [&](std::size_t at, std::initializer_list<std::uint16_t> words) {
    for (std::uint16_t w : words)
      for (int i = 0; i < 2; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  auto bl = [&](std::size_t at, std::size_t target) {  // Thumb bl
    const auto off = static_cast<std::uint32_t>(target - (at + 4));
    thumb(at, {static_cast<std::uint16_t>(0xf000 | ((off >> 12) & 0x7ff)),
               static_cast<std::uint16_t>(0xf800 | ((off >> 1) & 0x7ff))});
  };
  for (std::size_t v = 4; v < 0x20; v += 4) arm(v, {0xeafffffe});  // b .
  arm(0x00, {0xea000006});                                         // b 0x20
  // reset (ARM): ldr r0, =main + 1; bx r0
  arm(0x20, {0xe59f0000, 0xe12fff10, 0x00000041});
  // main (Thumb) at 0x40: push {lr}; bl f; ldr r3, =(0xc4 + 1); pop {pc};
  // the literal points into the middle of the function at 0xc0.
  thumb(0x40, {0xb500});
  bl(0x42, 0x60);
  thumb(0x46, {0x4b01, 0xbd00});
  arm(0x4c, {0x000000c5});
  // f (Thumb) at 0x60: push {r4, lr}; cmp r0, #0; beq 0x6a; bl 0x90 (a far
  // jump to its own tail); 0x6a: adds r0, #1; bl g; b 0x90;
  // 0x90: adds r0, #2; pop {r4, pc}
  thumb(0x60, {0xb510, 0x2800, 0xd001});
  bl(0x66, 0x90);
  thumb(0x6a, {0x3001});
  bl(0x6c, 0xb0);
  thumb(0x70, {0xe00e});
  thumb(0x90, {0x3002, 0xbd10});
  // g (Thumb) at 0xb0: adds r0, #7; bx lr
  thumb(0xb0, {0x3007, 0x4770});
  // Nothing calls the function at 0xc0, and zeroed padding lies before it:
  // push {r4, lr}; movs r4, #1; 0xc4: adds r0, r0, r4; bl g; pop {r4, pc}
  thumb(0xc0, {0xb510, 0x2401, 0x1900});
  bl(0xc6, 0xb0);
  thumb(0xca, {0xbd10});

  loader::RawOptions o;
  o.language = kV7;
  auto image = std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
  auto analysis = analyze(*image, kV7);
  std::map<std::uint64_t, const an::FunctionInfo *> found;
  for (const an::FunctionInfo &f : analysis->functions().functions) found[f.entry.offset] = &f;
  for (std::uint64_t a : {0x40u, 0x60u, 0xb0u, 0xc0u}) ASSERT_TRUE(found.contains(a)) << std::hex << a;
  // Neither f's tail nor the place the literal points at is a function.
  EXPECT_FALSE(found.contains(0x90));
  EXPECT_FALSE(found.contains(0xc4));
  EXPECT_EQ(found.size(), 8u + 1 + 4) << "the vectors, reset, main, f, g and the function at 0xc0";
  EXPECT_TRUE(found[0xc0]->flags & an::kFunctionSearched);
  const facts::SpaceId space = found[0x60]->entry.space;
  EXPECT_TRUE(found[0x60]->body.contains(facts::Address{space, 0x90}));
  EXPECT_TRUE(found[0xc0]->body.contains(facts::Address{space, 0xc4}));
  // The far jump is a jump, and the call to g a call.
  const an::FlowGraph &f = analysis->flow(found[0x60]->flow_key());
  ASSERT_NE(f.at(0x66), nullptr);
  EXPECT_EQ(f.at(0x66)->kind, an::FlowKind::jump);
  EXPECT_EQ(f.at(0x66)->targets, (std::vector<std::uint64_t>{0x90}));
  EXPECT_FALSE(f.at(0x66)->falls_through);
  EXPECT_EQ(f.far_jumps, (std::vector<std::uint64_t>{0x66}));
  ASSERT_NE(f.at(0x6c), nullptr);
  EXPECT_EQ(f.at(0x6c)->kind, an::FlowKind::call);

  // The decompiler is told (a BRANCH override): f calls g only.
  Program program{image, kV7, analysis.get(), nullptr};
  lift::DecompileConfig config;
  config.image = image;
  config.language_id = kV7;
  config.inputs = std::make_shared<const lift::DecompilerInputs>(assemble(program));
  config.default_labels = false;
  lift::InputDecompiler d(config);
  lift::DecompileResult r = d.decompile(0x60);
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_EQ(r.c.find("00000090"), std::string::npos) << r.c;
  EXPECT_NE(r.c.find("FUN_000000b0"), std::string::npos) << r.c;
  EXPECT_NE(r.c.find("+ 2"), std::string::npos) << r.c;
  EXPECT_EQ(r.c.find("halt_baddata"), std::string::npos) << r.c;
}

// A shrink-wrapped function starts with its early exit, before the
// prologue a start pattern or the code finder sees: cbz r0, out; push
// {r4, lr}; ... A function nothing calls is found where its first
// instruction is, not at the push.
TEST(FirmwareFragments, AShrinkWrappedFunctionStartsAtItsEarlyExit) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  constexpr const char *kV7 = "ARM:LE:32:v7:default";
  auto bytes = std::make_shared<loader::Bytes>(0x100);
  auto arm = [&](std::size_t at, std::initializer_list<std::uint32_t> words) {
    for (std::uint32_t w : words)
      for (int i = 0; i < 4; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  auto thumb = [&](std::size_t at, std::initializer_list<std::uint16_t> words) {
    for (std::uint16_t w : words)
      for (int i = 0; i < 2; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  auto bl = [&](std::size_t at, std::size_t target) {  // Thumb bl
    const auto off = static_cast<std::uint32_t>(target - (at + 4));
    thumb(at, {static_cast<std::uint16_t>(0xf000 | ((off >> 12) & 0x7ff)),
               static_cast<std::uint16_t>(0xf800 | ((off >> 1) & 0x7ff))});
  };
  for (std::size_t v = 4; v < 0x20; v += 4) arm(v, {0xeafffffe});  // b .
  arm(0x00, {0xea000006});                                         // b 0x20
  // reset (ARM): ldr r0, =main + 1; bx r0
  arm(0x20, {0xe59f0000, 0xe12fff10, 0x00000041});
  // main (Thumb) at 0x40: push {lr}; bl g; pop {pc}
  thumb(0x40, {0xb500});
  bl(0x42, 0x5c);
  thumb(0x46, {0xbd00});
  // g (Thumb) at 0x5c: adds r0, #7; bx lr
  thumb(0x5c, {0x3007, 0x4770});
  // Nothing calls the function right after it: cbz r0, 0x6a; push {r4, lr};
  // bl g; pop {r4, pc}; 0x6a: bx lr
  thumb(0x60, {0xb118, 0xb510});
  bl(0x64, 0x5c);
  thumb(0x68, {0xbd10, 0x4770});

  loader::RawOptions o;
  o.language = kV7;
  auto image = std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
  auto analysis = analyze(*image, kV7);
  std::map<std::uint64_t, const an::FunctionInfo *> found;
  for (const an::FunctionInfo &f : analysis->functions().functions) found[f.entry.offset] = &f;
  for (std::uint64_t a : {0x40u, 0x5cu}) ASSERT_TRUE(found.contains(a)) << std::hex << a;
  ASSERT_TRUE(found.contains(0x60)) << "the shrink-wrapped function, from its early exit";
  EXPECT_FALSE(found.contains(0x62));
  const facts::SpaceId space = found[0x60]->entry.space;
  EXPECT_TRUE(found[0x60]->body.contains(facts::Address{space, 0x6a}));
}

// A literal pool word the code finder took for code before it found the
// code that loads it is data: what it found there goes, and the function
// after the pool starts where it does.
TEST(FirmwareFragments, CodeFoundInALiteralPoolIsData) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  constexpr const char *kV7 = "ARM:LE:32:v7:default";
  auto bytes = std::make_shared<loader::Bytes>(0x100);
  auto arm = [&](std::size_t at, std::initializer_list<std::uint32_t> words) {
    for (std::uint32_t w : words)
      for (int i = 0; i < 4; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  auto thumb = [&](std::size_t at, std::initializer_list<std::uint16_t> words) {
    for (std::uint16_t w : words)
      for (int i = 0; i < 2; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  auto bl = [&](std::size_t at, std::size_t target) {  // Thumb bl
    const auto off = static_cast<std::uint32_t>(target - (at + 4));
    thumb(at, {static_cast<std::uint16_t>(0xf000 | ((off >> 12) & 0x7ff)),
               static_cast<std::uint16_t>(0xf800 | ((off >> 1) & 0x7ff))});
  };
  for (std::size_t v = 4; v < 0x20; v += 4) arm(v, {0xeafffffe});  // b .
  arm(0x00, {0xea000006});                                         // b 0x20
  // reset (ARM): ldr r0, =main + 1; bx r0
  arm(0x20, {0xe59f0000, 0xe12fff10, 0x00000041});
  // main (Thumb) at 0x40: push {lr}; bl g; pop {pc}; g at 0x5c: adds r0, #7; bx lr
  thumb(0x40, {0xb500});
  bl(0x42, 0x5c);
  thumb(0x46, {0xbd00});
  thumb(0x5c, {0x3007, 0x4770});
  // a at 0x60: ldr r0, [pc, #4] (the word at 0x68); bx lr. The word reads
  // as asrs r4, r6, #8; lsls r0, r0, #1, which runs into b's prologue.
  thumb(0x60, {0x4801, 0x4770});
  arm(0x68, {0x00401234});
  // b at 0x6c, which nothing calls: push {r4, lr}; bl a; bl g; pop {r4, pc}
  thumb(0x6c, {0xb510});
  bl(0x6e, 0x60);
  bl(0x72, 0x5c);
  thumb(0x76, {0xbd10});

  loader::RawOptions o;
  o.language = kV7;
  auto image = std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
  auto analysis = analyze(*image, kV7);
  std::map<std::uint64_t, const an::FunctionInfo *> found;
  for (const an::FunctionInfo &f : analysis->functions().functions) found[f.entry.offset] = &f;
  for (std::uint64_t a : {0x40u, 0x5cu, 0x60u}) EXPECT_TRUE(found.contains(a)) << std::hex << a;
  EXPECT_TRUE(found.contains(0x6c)) << "the function after the pool";
  EXPECT_FALSE(found.contains(0x68));
  EXPECT_FALSE(found.contains(0x6a));
}

// Far jumps in a chain: the code a far jump goes to (a default case) far
// jumps on to the function's epilogue, so it returns from the function's
// frame too and is no function.
TEST(FirmwareFragments, AFarJumpToAFarJumpIsAJump) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  constexpr const char *kV7 = "ARM:LE:32:v7:default";
  auto bytes = std::make_shared<loader::Bytes>(0x100);
  auto arm = [&](std::size_t at, std::initializer_list<std::uint32_t> words) {
    for (std::uint32_t w : words)
      for (int i = 0; i < 4; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  auto thumb = [&](std::size_t at, std::initializer_list<std::uint16_t> words) {
    for (std::uint16_t w : words)
      for (int i = 0; i < 2; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  auto bl = [&](std::size_t at, std::size_t target) {  // Thumb bl
    const auto off = static_cast<std::uint32_t>(target - (at + 4));
    thumb(at, {static_cast<std::uint16_t>(0xf000 | ((off >> 12) & 0x7ff)),
               static_cast<std::uint16_t>(0xf800 | ((off >> 1) & 0x7ff))});
  };
  for (std::size_t v = 4; v < 0x20; v += 4) arm(v, {0xeafffffe});  // b .
  arm(0x00, {0xea000006});                                         // b 0x20
  // reset (ARM): ldr r0, =main + 1; bx r0
  arm(0x20, {0xe59f0000, 0xe12fff10, 0x00000041});
  // main (Thumb) at 0x40: push {lr}; bl f; pop {pc}
  thumb(0x40, {0xb500});
  bl(0x42, 0x60);
  thumb(0x46, {0xbd00});
  // f at 0x60: push {r4, lr}; cmp r0, #0; beq 0x6e; bl 0x90 (far jump to
  // the default case); 0x6e: bl g; adds r0, #1; bl 0xa0 (far jump to the
  // epilogue)
  thumb(0x60, {0xb510, 0x2800, 0xd003});
  bl(0x66, 0x90);
  bl(0x6e, 0xb0);
  thumb(0x72, {0x3001});
  bl(0x74, 0xa0);
  // 0x90, the default case: movs r0, #2; bl 0xa0 (far jump to the epilogue)
  thumb(0x90, {0x2002});
  bl(0x92, 0xa0);
  // 0xa0, the epilogue: pop {r4, pc}
  thumb(0xa0, {0xbd10});
  // g at 0xb0: adds r0, #7; bx lr
  thumb(0xb0, {0x3007, 0x4770});

  loader::RawOptions o;
  o.language = kV7;
  auto image = std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
  auto analysis = analyze(*image, kV7);
  std::map<std::uint64_t, const an::FunctionInfo *> found;
  for (const an::FunctionInfo &f : analysis->functions().functions) found[f.entry.offset] = &f;
  for (std::uint64_t a : {0x40u, 0x60u, 0xb0u}) ASSERT_TRUE(found.contains(a)) << std::hex << a;
  EXPECT_FALSE(found.contains(0x90));
  EXPECT_FALSE(found.contains(0xa0));
  const facts::SpaceId space = found[0x60]->entry.space;
  EXPECT_TRUE(found[0x60]->body.contains(facts::Address{space, 0x90}));
  EXPECT_TRUE(found[0x60]->body.contains(facts::Address{space, 0xa0}));
  const an::FlowGraph &f = analysis->flow(found[0x60]->flow_key());
  EXPECT_EQ(f.far_jumps, (std::vector<std::uint64_t>{0x66, 0x74, 0x92}));
}

// A second program in the image (an application after its boot loader)
// with ARM exception vectors of its own: its reset code, and what that
// calls, are functions.
TEST(FirmwareFragments, AnEmbeddedVectorTableGivesItsResetCode) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  constexpr const char *kV7 = "ARM:LE:32:v7:default";
  auto bytes = std::make_shared<loader::Bytes>(0x200);
  auto arm = [&](std::size_t at, std::initializer_list<std::uint32_t> words) {
    for (std::uint32_t w : words)
      for (int i = 0; i < 4; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  for (std::size_t v = 4; v < 0x20; v += 4) arm(v, {0xeafffffe});  // b .
  arm(0x00, {0xea000006});                                         // b 0x20
  arm(0x20, {0xeafffffe});                                         // reset: b .
  // The application's vectors at 0x100: b 0x140; ldr pc, [pc, #0x14] x 7;
  // the handlers' addresses (where it is linked, not here).
  arm(0x100, {0xea00000e});
  for (std::size_t v = 0x104; v < 0x120; v += 4) arm(v, {0xe59ff014});
  for (std::size_t v = 0x120; v < 0x13c; v += 4) arm(v, {0x80001000u + static_cast<std::uint32_t>(v)});
  // 0x140 (ARM): mrs r0, cpsr; bl 0x160; b .
  arm(0x140, {0xe10f0000, 0xeb000005, 0xeafffffe});
  // 0x160 (ARM): mov r0, #1; bx lr
  arm(0x160, {0xe3a00001, 0xe12fff1e});
  // Eight branches in a row at 0x180 (a switch's branch table nothing
  // reached) aren't vectors: no function at 0x1c0.
  for (std::size_t v = 0x180; v < 0x1a0; v += 4)
    arm(v, {0xea000000u | static_cast<std::uint32_t>(((0x1c0 - (v + 8)) / 4) & 0xffffff)});
  arm(0x1c0, {0xe3a00002, 0xe12fff1e});

  loader::RawOptions o;
  o.language = kV7;
  auto image = std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
  auto analysis = analyze(*image, kV7);
  std::map<std::uint64_t, const an::FunctionInfo *> found;
  for (const an::FunctionInfo &f : analysis->functions().functions) found[f.entry.offset] = &f;
  ASSERT_TRUE(found.contains(0x140)) << "the application's reset code";
  EXPECT_FALSE(found[0x140]->flags & an::kFunctionThumb);
  EXPECT_TRUE(found.contains(0x160));
  for (std::uint64_t a = 0x100; a < 0x140; a += 4) EXPECT_FALSE(found.contains(a)) << std::hex << a;
  EXPECT_FALSE(found.contains(0x1c0));
}

// A conditional branch to a function elsewhere is a tail call (ARM's beq
// other_function), not a sign that the function it reaches starts inside
// the one that branches: a start found by a pattern stays a function.
TEST(FirmwareFragments, AConditionalTailCallLeavesItsTargetAFunction) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  constexpr const char *kV4t = "ARM:LE:32:v4t:default";
  auto bytes = std::make_shared<loader::Bytes>(0x100);
  auto arm = [&](std::size_t at, std::initializer_list<std::uint32_t> words) {
    for (std::uint32_t w : words)
      for (int i = 0; i < 4; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  for (std::size_t v = 4; v < 0x20; v += 4) arm(v, {0xeafffffe});  // b .
  arm(0x00, {0xea000006});                                         // b 0x20
  // reset at 0x20: bl 0x40; b .   0x40: mov r0, #0; bx lr
  arm(0x20, {0xeb000006, 0xeafffffe});
  arm(0x40, {0xe3a00000, 0xe12fff1e});
  // Two functions nothing calls, found by their prologues. f at 0x48:
  // stmdb sp!, {r4, lr}; mov r4, r0; bl g; add r0, r0, r4; ldmia sp!, {r4, pc}
  arm(0x48, {0xe92d4010, 0xe1a04000, 0xeb00001a, 0xe0800004, 0xe8bd8010});
  // the dispatcher at 0x5c: stmdb sp!, {r4, lr}; cmp r0, #0;
  // ldmeqia sp!, {r4, lr}; beq f; bl g; ldmia sp!, {r4, pc}
  arm(0x5c, {0xe92d4010, 0xe3500000, 0x08bd4010, 0x0afffff6, 0xeb000013, 0xe8bd8010});
  // g at 0xc0: mov r0, #2; bx lr
  arm(0xc0, {0xe3a00002, 0xe12fff1e});

  loader::RawOptions o;
  o.language = kV4t;
  auto image = std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
  auto analysis = analyze(*image, kV4t);
  std::map<std::uint64_t, const an::FunctionInfo *> found;
  for (const an::FunctionInfo &f : analysis->functions().functions) found[f.entry.offset] = &f;
  for (std::uint64_t a : {0x20u, 0x5cu, 0xc0u}) ASSERT_TRUE(found.contains(a)) << std::hex << a;
  EXPECT_TRUE(found.contains(0x48)) << "the function the dispatcher tail-calls";
  const facts::SpaceId space = found[0x5c]->entry.space;
  EXPECT_FALSE(found[0x5c]->body.contains(facts::Address{space, 0x48}));
}

// A stripped dynamic ARM program (fixtures/armelf, built with clang and
// ld.lld): no symbols to seed from but the entry point and the PLT, so it
// is searched as a raw image is. The PLT's stubs are functions one per
// import (lld's: a 32-byte header, 16-byte stubs; not one per word), and
// the commands only a table of pointers in .data reaches are found.
TEST(StrippedElf, PltStubsAndFunctionsATableInDataReaches) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  if (std::string(REVKIT_TEST_CLANG).empty() || std::string(REVKIT_TEST_LLD).empty()) GTEST_SKIP() << "no clang, ld.lld";
  const auto dir = testing::scratch_dir("armelf");
  const std::string cmd = std::string("sh ") + REVKIT_ARMELF_DIR + "/build.sh " + REVKIT_TEST_CLANG + " " +
                          REVKIT_TEST_LLD + " " + dir.string() + " >/dev/null 2>&1";
  if (std::system(cmd.c_str()) != 0) GTEST_SKIP() << "no clang, ld.lld for armv7a";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  std::map<std::string, std::uint64_t> truth;
  for (const loader::Symbol &s : loader::load_file(dir / "prog.sym").symbols)
    if (s.defined && s.type == loader::SymbolType::func) truth[s.name] = s.value & ~std::uint64_t{1};
  for (const char *name : {"cmd_a", "cmd_b", "cmd_c", "cmd_d", "_start"}) ASSERT_TRUE(truth.contains(name)) << name;

  auto image = std::make_shared<const loader::Image>(loader::load_file(dir / "prog"));
  ASSERT_EQ(image->plt_sections.size(), 1u);
  const loader::PltSection &plt = image->plt_sections[0];
  EXPECT_EQ(plt.header_size, 32u);
  EXPECT_EQ(plt.entry_size, 16u);
  const auto lang = loader::guess_language(*image);
  ASSERT_TRUE(lang);
  auto analysis = analyze(*image, lang->id());
  std::map<std::uint64_t, const an::FunctionInfo *> found;
  for (const an::FunctionInfo &f : analysis->functions().functions) found[f.entry.offset] = &f;
  for (const char *name : {"cmd_a", "cmd_b", "cmd_c", "cmd_d", "_start"})
    EXPECT_TRUE(found.contains(truth[name])) << name;
  for (std::uint64_t a = plt.start + plt.header_size; a < plt.start + plt.size; a += 4)
    EXPECT_EQ(found.contains(a), (a - plt.start - plt.header_size) % plt.entry_size == 0) << std::hex << a;
}

// An ARM function's stack locals don't depend on what the lifter decoded
// before: an ARM blx to it (as data read as code has it) commits Thumb
// mode at its entry (SLEIGH's globalset), which a shared lifter keeps; the
// stack walk decodes without commits, so it still reads ARM there.
TEST(FirmwareFragments, StackLocalsDontDependOnEarlierDecoding) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  constexpr const char *kV7 = "ARM:LE:32:v7:default";
  auto bytes = std::make_shared<loader::Bytes>(0x300);
  auto arm = [&](std::size_t at, std::initializer_list<std::uint32_t> words) {
    for (std::uint32_t w : words)
      for (int i = 0; i < 4; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  auto thumb = [&](std::size_t at, std::initializer_list<std::uint16_t> words) {
    for (std::uint16_t w : words)
      for (int i = 0; i < 2; ++i) (*bytes)[at++] = static_cast<std::byte>(w >> (8 * i));
  };
  for (std::size_t v = 4; v < 0x20; v += 4) arm(v, {0xeafffffe});  // b .
  arm(0x00, {0xea000006});                                         // b 0x20
  // reset at 0x20: bl 0x100; b .
  arm(0x20, {0xeb000036, 0xeafffffe});
  // f (ARM) at 0x100: push {r4, lr}; sub sp, sp, #8; str r0, [sp, #4];
  // ldr r0, [sp, #4]; add sp, sp, #8; pop {r4, pc}
  arm(0x100, {0xe92d4010, 0xe24dd008, 0xe58d0004, 0xe59d0004, 0xe28dd008, 0xe8bd8010});
  // 0x200 (ARM): blx 0x100, which makes its target Thumb
  arm(0x200, {0xfaffffbe});

  loader::RawOptions o;
  o.language = kV7;
  auto image = std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
  auto analysis = analyze(*image, kV7);
  const an::FunctionInfo *f = nullptr;
  for (const an::FunctionInfo &fi : analysis->functions().functions)
    if (fi.entry.offset == 0x100) f = &fi;
  ASSERT_NE(f, nullptr);
  const an::FlowGraph &g = analysis->flow(f->flow_key());
  Program program{image, kV7, analysis.get(), nullptr};
  const FunctionSets sets = function_sets(analysis->functions(), nullptr);
  lift::Lifter fresh(image, kV7);
  const auto expected = assemble_function(program, {}, sets, *f, g, {}, fresh).locals;
  ASSERT_FALSE(expected.empty());
  lift::Lifter used(image, kV7);
  ASSERT_TRUE(used.lift(0x200));  // commits TMode = 1 at 0x100
  ASSERT_TRUE(used.context_changed());
  const auto after = assemble_function(program, {}, sets, *f, g, {}, used).locals;
  ASSERT_EQ(after.size(), expected.size());
  for (std::size_t i = 0; i < after.size(); ++i) EXPECT_EQ(after[i].name, expected[i].name);
}

}  // namespace
}  // namespace revkit::inputs
