#include "revkit/evm/evm.h"

#include "revkit/loader/load.hh"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <deque>
#include <unordered_set>

namespace revkit::evm {

namespace {

std::uint8_t at(std::span<const std::byte> b, std::size_t i) { return static_cast<std::uint8_t>(b[i]); }

constexpr std::uint8_t kJump = 0x56, kJumpi = 0x57, kJumpdest = 0x5b, kPush0 = 0x5f, kPush1 = 0x60,
                       kPush4 = 0x63, kPush32 = 0x7f, kDup1 = 0x80, kDup16 = 0x8f, kSwap1 = 0x90,
                       kSwap16 = 0x9f, kEq = 0x14;

struct OpInfo {
  const char *name;
  std::uint8_t pops, pushes;
};

// Every assigned opcode's mnemonic and stack effect (Cancun); PUSH, DUP and
// SWAP are handled apart.
const OpInfo *info(std::uint8_t op) {
  static const std::map<std::uint8_t, OpInfo> table = {
      {0x00, {"STOP", 0, 0}},           {0x01, {"ADD", 2, 1}},          {0x02, {"MUL", 2, 1}},
      {0x03, {"SUB", 2, 1}},            {0x04, {"DIV", 2, 1}},          {0x05, {"SDIV", 2, 1}},
      {0x06, {"MOD", 2, 1}},            {0x07, {"SMOD", 2, 1}},         {0x08, {"ADDMOD", 3, 1}},
      {0x09, {"MULMOD", 3, 1}},         {0x0a, {"EXP", 2, 1}},          {0x0b, {"SIGNEXTEND", 2, 1}},
      {0x10, {"LT", 2, 1}},             {0x11, {"GT", 2, 1}},           {0x12, {"SLT", 2, 1}},
      {0x13, {"SGT", 2, 1}},            {0x14, {"EQ", 2, 1}},           {0x15, {"ISZERO", 1, 1}},
      {0x16, {"AND", 2, 1}},            {0x17, {"OR", 2, 1}},           {0x18, {"XOR", 2, 1}},
      {0x19, {"NOT", 1, 1}},            {0x1a, {"BYTE", 2, 1}},         {0x1b, {"SHL", 2, 1}},
      {0x1c, {"SHR", 2, 1}},            {0x1d, {"SAR", 2, 1}},          {0x20, {"KECCAK256", 2, 1}},
      {0x30, {"ADDRESS", 0, 1}},        {0x31, {"BALANCE", 1, 1}},      {0x32, {"ORIGIN", 0, 1}},
      {0x33, {"CALLER", 0, 1}},         {0x34, {"CALLVALUE", 0, 1}},    {0x35, {"CALLDATALOAD", 1, 1}},
      {0x36, {"CALLDATASIZE", 0, 1}},   {0x37, {"CALLDATACOPY", 3, 0}}, {0x38, {"CODESIZE", 0, 1}},
      {0x39, {"CODECOPY", 3, 0}},       {0x3a, {"GASPRICE", 0, 1}},     {0x3b, {"EXTCODESIZE", 1, 1}},
      {0x3c, {"EXTCODECOPY", 4, 0}},    {0x3d, {"RETURNDATASIZE", 0, 1}}, {0x3e, {"RETURNDATACOPY", 3, 0}},
      {0x3f, {"EXTCODEHASH", 1, 1}},    {0x40, {"BLOCKHASH", 1, 1}},    {0x41, {"COINBASE", 0, 1}},
      {0x42, {"TIMESTAMP", 0, 1}},      {0x43, {"NUMBER", 0, 1}},       {0x44, {"PREVRANDAO", 0, 1}},
      {0x45, {"GASLIMIT", 0, 1}},       {0x46, {"CHAINID", 0, 1}},      {0x47, {"SELFBALANCE", 0, 1}},
      {0x48, {"BASEFEE", 0, 1}},        {0x49, {"BLOBHASH", 1, 1}},     {0x4a, {"BLOBBASEFEE", 0, 1}},
      {0x50, {"POP", 1, 0}},            {0x51, {"MLOAD", 1, 1}},        {0x52, {"MSTORE", 2, 0}},
      {0x53, {"MSTORE8", 2, 0}},        {0x54, {"SLOAD", 1, 1}},        {0x55, {"SSTORE", 2, 0}},
      {0x56, {"JUMP", 1, 0}},           {0x57, {"JUMPI", 2, 0}},        {0x58, {"PC", 0, 1}},
      {0x59, {"MSIZE", 0, 1}},          {0x5a, {"GAS", 0, 1}},          {0x5b, {"JUMPDEST", 0, 0}},
      {0x5c, {"TLOAD", 1, 1}},          {0x5d, {"TSTORE", 2, 0}},       {0x5e, {"MCOPY", 3, 0}},
      {0x5f, {"PUSH0", 0, 1}},          {0xa0, {"LOG0", 2, 0}},         {0xa1, {"LOG1", 3, 0}},
      {0xa2, {"LOG2", 4, 0}},           {0xa3, {"LOG3", 5, 0}},         {0xa4, {"LOG4", 6, 0}},
      {0xf0, {"CREATE", 3, 1}},         {0xf1, {"CALL", 7, 1}},         {0xf2, {"CALLCODE", 7, 1}},
      {0xf3, {"RETURN", 2, 0}},         {0xf4, {"DELEGATECALL", 6, 1}}, {0xf5, {"CREATE2", 4, 1}},
      {0xfa, {"STATICCALL", 6, 1}},     {0xfd, {"REVERT", 2, 0}},       {0xfe, {"INVALID", 0, 0}},
      {0xff, {"SELFDESTRUCT", 1, 0}},
  };
  auto it = table.find(op);
  return it == table.end() ? nullptr : &it->second;
}

bool halts(std::uint8_t op) {
  return op == 0x00 || op == 0xf3 || op == 0xfd || op == 0xfe || op == 0xff ||
         (info(op) == nullptr && !(op >= kPush1 && op <= kSwap16));
}

bool is_jump(std::uint8_t op) { return op == kJump || op == kJumpi; }

using Value = std::optional<std::uint64_t>;

// One path's stack (top at the back) at an instruction.
struct State {
  std::uint32_t pc = 0;
  std::vector<Value> stack;
};

std::size_t hash_stack(const std::vector<Value> &s) {
  std::size_t h = s.size() * 0x9e3779b97f4a7c15ull;
  for (const Value &v : s) h = (h ^ (v ? *v + 0x51ed27 : 0x2545f491)) * 0x100000001b3ull;
  return h;
}

}  // namespace

std::string mnemonic(std::uint8_t op) {
  if (op >= kPush1 && op <= kPush32) return "PUSH" + std::to_string(op - kPush0);
  if (op >= kDup1 && op <= kDup16) return "DUP" + std::to_string(op - kDup1 + 1);
  if (op >= kSwap1 && op <= kSwap16) return "SWAP" + std::to_string(op - kSwap1 + 1);
  const OpInfo *i = info(op);
  return i ? i->name : "INVALID";
}

std::vector<Insn> disassemble(std::span<const std::byte> code) {
  std::vector<Insn> out;
  out.reserve(code.size());
  for (std::size_t pc = 0; pc < code.size();) {
    Insn i;
    i.pc = static_cast<std::uint32_t>(pc);
    i.op = at(code, pc);
    if (i.op >= kPush1 && i.op <= kPush32) {
      const std::size_t n = i.op - kPush0;
      const std::size_t have = std::min(n, code.size() - pc - 1);
      i.push = static_cast<std::uint8_t>(have);
      std::uint64_t v = 0;
      bool fits = true;
      for (std::size_t k = 0; k < have; ++k) {
        if (v >> 56) fits = false;
        v = v << 8 | at(code, pc + 1 + k);
      }
      if (fits && have == n) i.value = v;
    } else if (i.op == kPush0) {
      i.value = 0;
    }
    out.push_back(i);
    pc += i.length();
  }
  return out;
}

bool is_bytecode(std::span<const std::byte> b) {
  if (b.size() < 5) return false;
  const std::uint8_t a = at(b, 0), x = at(b, 1), c = at(b, 2), d = at(b, 3), e = at(b, 4);
  return a == 0x60 && (x == 0x80 || x == 0x60) && c == 0x60 && d == 0x40 && e == 0x52;
}

std::optional<Bytes> bytecode_of(std::span<const std::byte> file) {
  if (is_bytecode(file)) return Bytes(file.begin(), file.end());
  // Hex text: look at its start before decoding all of it.
  std::size_t i = 0;
  while (i < file.size() && (at(file, i) == ' ' || at(file, i) == '\n' || at(file, i) == '\r' || at(file, i) == '\t')) ++i;
  if (i + 1 < file.size() && at(file, i) == '0' && (at(file, i + 1) == 'x' || at(file, i + 1) == 'X')) i += 2;
  static constexpr std::string_view kStarts[] = {"6080604052", "6060604052"};
  std::string head;
  for (std::size_t k = i; k < file.size() && head.size() < 10; ++k) head.push_back(static_cast<char>(std::tolower(at(file, k))));
  if (std::find(std::begin(kStarts), std::end(kStarts), head) == std::end(kStarts)) return std::nullopt;
  std::optional<Bytes> bytes = loader::decode_hex_text(file);
  if (!bytes || !is_bytecode(*bytes)) return std::nullopt;
  return bytes;
}

std::optional<Metadata> metadata(std::span<const std::byte> code) {
  if (code.size() < 4) return std::nullopt;
  const std::uint32_t len = static_cast<std::uint32_t>(at(code, code.size() - 2)) << 8 | at(code, code.size() - 1);
  if (len == 0 || len + 2 > code.size()) return std::nullopt;
  const std::size_t start = code.size() - 2 - len;
  // A CBOR map of one to eight entries whose first key is a text string:
  // "ipfs", "bzzr0", "bzzr1", "solc", "experimental".
  const std::uint8_t m = at(code, start);
  if (m < 0xa1 || m > 0xa8) return std::nullopt;
  const std::uint8_t key = at(code, start + 1);
  if (key < 0x61 || key > 0x77) return std::nullopt;
  return Metadata{static_cast<std::uint32_t>(start), len + 2};
}

std::uint32_t Analysis::resolved() const {
  std::uint32_t n = static_cast<std::uint32_t>(direct.size());
  for (const auto &[pc, targets] : computed)
    if (!unresolved.contains(pc) && !targets.empty()) ++n;
  return n;
}

Analysis analyze(std::span<const std::byte> code, std::uint32_t entry) {
  Analysis a;
  a.meta = metadata(code);
  const std::uint32_t end = a.meta ? a.meta->offset : static_cast<std::uint32_t>(code.size());
  a.insns = disassemble(code.first(end));
  std::map<std::uint32_t, std::size_t> index;  // pc -> insns index
  for (std::size_t i = 0; i < a.insns.size(); ++i) {
    const Insn &x = a.insns[i];
    index[x.pc] = i;
    if (x.op == kJumpdest) a.jumpdests.insert(x.pc);
    if (is_jump(x.op)) ++a.jumps;
    // The processor's folded PUSH1..PUSH4 tag; JUMP(I).
    if (x.op >= kPush1 && x.op <= kPush4 && x.value && i + 1 < a.insns.size() && is_jump(a.insns[i + 1].op))
      a.direct[x.pc] = static_cast<std::uint32_t>(*x.value);
  }
  std::set<std::uint32_t> folded;  // the JUMP(I)s the processor folds into their PUSH
  for (const auto &[pc, tag] : a.direct) folded.insert(pc + a.insns[index[pc]].length());

  constexpr std::size_t kMaxStates = 200000, kStatesPerInsn = 64, kMaxDepth = 1024;
  std::map<std::uint32_t, std::unordered_set<std::size_t>> seen;
  std::set<std::uint32_t> reached_jumps;
  std::deque<State> work;
  // Only from an instruction: empty code, or an entry inside a PUSH's data
  // or past the end, read insns[0] of nothing (evm_fuzzer, bug scrub part 3).
  if (index.contains(entry)) work.push_back({entry, {}});
  std::size_t states = 0;
  // The stacks waiting in the queue, in slots: 200,000 states of 1,024-deep
  // stacks were 3 GiB (bug scrub part 3); 16M slots are 256 MiB.
  constexpr std::size_t kMaxQueuedSlots = 1u << 24;
  std::size_t queued = 0;
  auto enqueue = [&](std::uint32_t pc, const std::vector<Value> &stack) {
    if (!index.contains(pc)) return;
    auto &s = seen[pc];
    const std::size_t h = hash_stack(stack);
    if (s.contains(h)) return;
    if (s.size() >= kStatesPerInsn || ++states > kMaxStates || queued + stack.size() > kMaxQueuedSlots) {
      a.budget = true;
      return;
    }
    s.insert(h);
    queued += stack.size();
    work.push_back({pc, stack});
  };
  if (index.contains(entry)) seen[entry].insert(hash_stack({}));
  while (!work.empty()) {
    State st = std::move(work.front());
    work.pop_front();
    queued -= st.stack.size();
    std::vector<Value> &s = st.stack;
    std::size_t i = index[st.pc];
    for (;;) {
      const Insn &x = a.insns[i];
      auto pop = [&]() -> Value {
        if (s.empty()) return std::nullopt;
        Value v = s.back();
        s.pop_back();
        return v;
      };
      const std::uint8_t op = x.op;
      bool stop = false;
      if (op >= kPush0 && op <= kPush32) {
        s.push_back(x.value);
      } else if (op >= kDup1 && op <= kDup16) {
        const std::size_t n = op - kDup1 + 1;
        s.push_back(s.size() >= n ? s[s.size() - n] : Value());
      } else if (op >= kSwap1 && op <= kSwap16) {
        const std::size_t n = op - kSwap1 + 1;
        while (s.size() < n + 1) s.insert(s.begin(), Value());
        std::swap(s.back(), s[s.size() - 1 - n]);
      } else if (op == 0x58) {  // PC
        s.push_back(x.pc);
      } else if (op == 0x39) {  // CODECOPY(dst, offset, size)
        const Value d = pop(), o = pop(), n = pop();
        if (d && o && n) a.codecopies.push_back({*d, *o, *n});
      } else if (op == 0xf3) {  // RETURN(offset, size)
        const Value o = pop(), n = pop();
        if (o && n) a.returns.push_back({*o, *n});
        stop = true;
      } else if (op == kJump || op == kJumpi) {
        reached_jumps.insert(x.pc);
        const Value d = pop();
        if (op == kJumpi) pop();
        auto go = [&](std::uint32_t to) { enqueue(to, s); };
        if (folded.contains(x.pc)) {
          // The PUSH before gave the tag: a direct branch.
          const std::uint32_t tag = a.direct.at(a.insns[i - 1].pc);
          if (a.jumpdests.contains(tag)) go(tag);
        } else if (d && *d <= 0xffffffffu && a.jumpdests.contains(static_cast<std::uint32_t>(*d))) {
          a.computed[x.pc].insert(static_cast<std::uint32_t>(*d));
          go(static_cast<std::uint32_t>(*d));
        } else {
          a.computed[x.pc];
          if (!d) a.unresolved.insert(x.pc);
        }
        if (op == kJumpi && i + 1 < a.insns.size()) go(a.insns[i + 1].pc);
        stop = true;
      } else if (halts(op)) {
        stop = true;
      } else if (const OpInfo *in = info(op)) {
        for (int k = 0; k < in->pops; ++k) pop();
        for (int k = 0; k < in->pushes; ++k) s.push_back(std::nullopt);
      }
      if (s.size() > kMaxDepth) stop = true;  // a stack overflow: the EVM stops there
      if (stop || ++i >= a.insns.size()) break;
      // A JUMPDEST starts a block: one state per distinct stack there.
      if (a.insns[i].op == kJumpdest) {
        enqueue(a.insns[i].pc, s);
        break;
      }
    }
  }
  for (const Insn &x : a.insns)
    if (is_jump(x.op) && !reached_jumps.contains(x.pc)) a.unreached.insert(x.pc);
  return a;
}

Layout layout(std::span<const std::byte> file) {
  Layout out;
  out.runtime_size = static_cast<std::uint32_t>(file.size());
  const Analysis a = analyze(file);
  std::uint64_t best = 0;
  for (const auto &[dst, off, size] : a.codecopies) {
    if (off == 0 || size == 0 || off > file.size() || size > file.size() - off) continue;
    bool returned = false;
    for (const auto &[roff, rsize] : a.returns) returned |= roff == dst && rsize == size;
    if (!returned || size <= best) continue;
    best = size;
    out.creation = true;
    out.runtime_offset = static_cast<std::uint32_t>(off);
    out.runtime_size = static_cast<std::uint32_t>(size);
  }
  return out;
}

std::vector<Selector> dispatcher(const std::vector<Insn> &insns) {
  std::vector<Selector> out;
  std::set<std::uint32_t> seen;
  for (std::size_t i = 0; i + 3 < insns.size(); ++i) {
    const Insn &p = insns[i];
    if (p.op != kPush4 || !p.value) continue;
    std::size_t j = i + 1;
    if (insns[j].op == kDup1 + 1) ++j;  // PUSH4 sel DUP2 EQ (solc's via-IR order)
    if (j >= insns.size() || insns[j].op != kEq) continue;
    ++j;
    if (j + 1 >= insns.size()) continue;
    const Insn &tag = insns[j];
    if (tag.op < kPush1 || tag.op > kPush4 || !tag.value || insns[j + 1].op != kJumpi) continue;
    const std::uint32_t sel = static_cast<std::uint32_t>(*p.value);
    if (!seen.insert(sel).second) continue;
    out.push_back({sel, static_cast<std::uint32_t>(*tag.value), p.pc});
  }
  return out;
}

std::span<const KnownSignature> known_signatures() {
  // Selectors checked against keccak256 of the signature (tests/test_evm.py).
  static constexpr KnownSignature kTable[] = {
      {0x06fdde03, "name()", "ERC-20"},
      {0x95d89b41, "symbol()", "ERC-20"},
      {0x313ce567, "decimals()", "ERC-20"},
      {0x18160ddd, "totalSupply()", "ERC-20"},
      {0x70a08231, "balanceOf(address)", "ERC-20"},
      {0xa9059cbb, "transfer(address,uint256)", "ERC-20"},
      {0x23b872dd, "transferFrom(address,address,uint256)", "ERC-20"},
      {0x095ea7b3, "approve(address,uint256)", "ERC-20"},
      {0xdd62ed3e, "allowance(address,address)", "ERC-20"},
      {0x39509351, "increaseAllowance(address,uint256)", "OpenZeppelin ERC-20"},
      {0xa457c2d7, "decreaseAllowance(address,uint256)", "OpenZeppelin ERC-20"},
      {0x40c10f19, "mint(address,uint256)", "ERC-20 extension"},
      {0x42966c68, "burn(uint256)", "ERC-20 extension"},
      {0x79cc6790, "burnFrom(address,uint256)", "ERC-20 extension"},
      {0xd505accf, "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", "ERC-2612"},
      {0x7ecebe00, "nonces(address)", "ERC-2612"},
      {0x3644e515, "DOMAIN_SEPARATOR()", "ERC-2612"},
      {0x6352211e, "ownerOf(uint256)", "ERC-721"},
      {0x42842e0e, "safeTransferFrom(address,address,uint256)", "ERC-721"},
      {0xb88d4fde, "safeTransferFrom(address,address,uint256,bytes)", "ERC-721"},
      {0xa22cb465, "setApprovalForAll(address,bool)", "ERC-721"},
      {0x081812fc, "getApproved(uint256)", "ERC-721"},
      {0xe985e9c5, "isApprovedForAll(address,address)", "ERC-721"},
      {0xc87b56dd, "tokenURI(uint256)", "ERC-721"},
      {0x4f6ccce7, "tokenByIndex(uint256)", "ERC-721"},
      {0x2f745c59, "tokenOfOwnerByIndex(address,uint256)", "ERC-721"},
      {0x01ffc9a7, "supportsInterface(bytes4)", "ERC-165"},
      {0x8da5cb5b, "owner()", "Ownable"},
      {0xf2fde38b, "transferOwnership(address)", "Ownable"},
      {0x715018a6, "renounceOwnership()", "Ownable"},
      {0x8456cb59, "pause()", "Pausable"},
      {0x3f4ba83a, "unpause()", "Pausable"},
      {0x5c975abb, "paused()", "Pausable"},
  };
  return kTable;
}

const KnownSignature *known_signature(std::uint32_t selector) {
  for (const KnownSignature &k : known_signatures())
    if (k.selector == selector) return &k;
  return nullptr;
}

std::string signature_name(const char *signature) {
  const std::string s(signature);
  return s.substr(0, s.find('('));
}

std::string selector_name(std::uint32_t selector) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "func_0x%08x", selector);
  return buf;
}

}  // namespace revkit::evm
