// revkit::evm on hand-made code and on OpenZeppelin's compiled ERC-20 and
// ERC-721 (tests/data/evm, MIT): detection, the runtime inside creation
// code, the dispatcher's selectors, and how many jumps the stack analysis
// resolves (docs/evm.md).
#include "revkit/evm/evm.h"

#include <gtest/gtest.h>

#include <fstream>
#include <iterator>
#include <string>

namespace revkit::evm {
namespace {

Bytes bytes_of(const std::string &s) {
  Bytes out;
  for (char c : s) out.push_back(static_cast<std::byte>(c));
  return out;
}

Bytes file(const std::string &name) {
  std::ifstream in(std::string(REVKIT_EVM_DATA) + "/" + name, std::ios::binary);
  std::string text((std::istreambuf_iterator<char>(in)), {});
  EXPECT_FALSE(text.empty()) << name;
  return bytes_of(text);
}

Bytes code(const std::string &name) {
  std::optional<Bytes> b = bytecode_of(file(name));
  EXPECT_TRUE(b) << name << " isn't EVM bytecode";
  return b.value_or(Bytes{});
}

Bytes hex(std::initializer_list<int> v) {
  Bytes out;
  for (int x : v) out.push_back(static_cast<std::byte>(x));
  return out;
}

TEST(Evm, DetectsBinaryAndHexText) {
  const Bytes bin = hex({0x60, 0x80, 0x60, 0x40, 0x52, 0x00});
  EXPECT_TRUE(is_bytecode(bin));
  EXPECT_EQ(bytecode_of(bin), bin);
  EXPECT_EQ(bytecode_of(bytes_of("0x608060405200\n")), bin);
  EXPECT_EQ(bytecode_of(bytes_of("608060405200")), bin);
  EXPECT_EQ(bytecode_of(bytes_of("0x6080604052zz")), std::nullopt);
  EXPECT_EQ(bytecode_of(bytes_of("\x7f" "ELF")), std::nullopt);
  EXPECT_EQ(bytecode_of(hex({0x60, 0x01, 0x60, 0x02, 0x01})), std::nullopt);  // EVM, but not solc's prologue
}

TEST(Evm, DisassemblesPushData) {
  // PUSH2 0x5b5b (JUMPDEST bytes as data); JUMPDEST; PUSH32 cut short.
  const Bytes c = hex({0x61, 0x5b, 0x5b, 0x5b, 0x7f, 0x01});
  const std::vector<Insn> v = disassemble(c);
  ASSERT_EQ(v.size(), 3u);
  EXPECT_EQ(mnemonic(v[0].op), "PUSH2");
  EXPECT_EQ(v[0].value, 0x5b5bu);
  EXPECT_EQ(v[1].pc, 3u);
  EXPECT_EQ(mnemonic(v[1].op), "JUMPDEST");
  EXPECT_EQ(v[2].push, 1u);
  EXPECT_EQ(v[2].value, std::nullopt);
  EXPECT_EQ(analyze(c).jumpdests, std::set<std::uint32_t>{3});
}

TEST(Evm, ResolvesAReturnAddressThroughTheStack) {
  // 0: PUSH1 0x0a (return address); PUSH1 0x07; JUMP     (folded: direct)
  // 5: STOP; 6: STOP
  // 7: JUMPDEST; 8: JUMP (computed: to the 0x0a pushed first)
  // a: JUMPDEST; b: STOP
  const Bytes c = hex({0x60, 0x0a, 0x60, 0x07, 0x56, 0x00, 0x00, 0x5b, 0x56, 0x00, 0x5b, 0x00});
  const Analysis a = analyze(c);
  EXPECT_EQ(a.jumps, 2u);
  EXPECT_EQ(a.direct, (std::map<std::uint32_t, std::uint32_t>{{2, 7}}));
  ASSERT_TRUE(a.computed.contains(8));
  EXPECT_EQ(a.computed.at(8), std::set<std::uint32_t>{0x0a});
  EXPECT_TRUE(a.unresolved.empty());
  EXPECT_EQ(a.resolved(), 2u);
}

TEST(Evm, AnUnknownTargetIsUnresolved) {
  // CALLDATALOAD(0) JUMP: the target is the caller's.
  const Bytes c = hex({0x60, 0x00, 0x35, 0x56, 0x5b, 0x00});
  const Analysis a = analyze(c);
  EXPECT_EQ(a.unresolved, std::set<std::uint32_t>{3});
  EXPECT_EQ(a.resolved(), 0u);
}

// Empty code, and an entry that isn't an instruction (inside a PUSH's
// data, past the end), are analyzed as nothing reached (evm_fuzzer, bug
// scrub part 3: insns[0] of an empty list).
TEST(Evm, NoCodeOrAnEntryOffAnInstruction) {
  const Analysis empty = analyze(Bytes{});
  EXPECT_TRUE(empty.insns.empty());
  EXPECT_EQ(empty.jumps, 0u);
  const Bytes c = hex({0x60, 0x08, 0x56, 0x5b, 0x00});  // PUSH1 8 JUMP JUMPDEST STOP
  EXPECT_TRUE(analyze(c, 1).computed.empty());          // inside PUSH1's data
  EXPECT_TRUE(analyze(c, 100).computed.empty());        // past the end
}

TEST(Evm, FindsTheRuntimeInCreationCode) {
  const Bytes creation = code("erc20.creation.hex"), runtime = code("erc20.runtime.hex");
  const Layout l = layout(creation);
  ASSERT_TRUE(l.creation);
  ASSERT_EQ(l.runtime_size, runtime.size());
  EXPECT_TRUE(std::equal(runtime.begin(), runtime.end(), creation.begin() + l.runtime_offset));
  EXPECT_FALSE(layout(runtime).creation);
}

TEST(Evm, NamesTheDispatchersSelectors) {
  const Bytes runtime = code("erc20.runtime.hex");
  const Analysis a = analyze(runtime);
  const std::vector<Selector> s = dispatcher(a.insns);
  std::set<std::string> names;
  for (const Selector &x : s) {
    const KnownSignature *k = known_signature(x.selector);
    ASSERT_NE(k, nullptr) << selector_name(x.selector);
    names.insert(signature_name(k->signature));
    EXPECT_TRUE(a.jumpdests.contains(x.entry)) << selector_name(x.selector);
  }
  EXPECT_EQ(names, (std::set<std::string>{"allowance", "approve", "balanceOf", "decimals", "decreaseAllowance",
                                          "increaseAllowance", "name", "symbol", "totalSupply", "transfer",
                                          "transferFrom"}));
  EXPECT_EQ(selector_name(0xa9059cbb), "func_0xa9059cbb");
  ASSERT_TRUE(a.meta);
  EXPECT_EQ(a.meta->offset + a.meta->size, runtime.size());
}

TEST(Evm, ResolvesNearlyEveryJumpOfRealContracts) {
  for (const char *name : {"erc20.runtime.hex", "erc721.runtime.hex"}) {
    const Analysis a = analyze(code(name));
    EXPECT_FALSE(a.budget) << name;
    EXPECT_GT(a.jumps, 50u) << name;
    // Nearly every jump has a known target (ERC-20: all 98; ERC-721: 194
    // of 195, one returns through a value the stack analysis doesn't track).
    EXPECT_LE(a.unresolved.size(), 1u) << name;
    EXPECT_GE(a.resolved() * 100, a.jumps * 99u) << name;
    std::printf("%s: %u jumps, %zu direct, %u resolved, %zu unresolved, %zu unreached\n", name, a.jumps,
                a.direct.size(), a.resolved(), a.unresolved.size(), a.unreached.size());
  }
}

}  // namespace
}  // namespace revkit::evm
