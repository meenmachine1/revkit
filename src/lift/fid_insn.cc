// What Ghidra's Function ID hashes read from an instruction, over the C++
// SLEIGH parse tree (docs/fid.md, "Hashing").
//
// Ghidra's MessageDigestFidHasher reads, for each instruction, the masks
// its prototype reports and its operands' objects and types. The masks come
// from SleighDebugLogger (MASKS_ONLY), which re-resolves the instruction
// and records, for every constructor in the tree:
//
//   - each decision node's instruction field on the way to it, as
//     PatternBlock(0, mask, value) (DecisionNode.debugInstructionBitsDecision).
//     Normalizing that block moves its leading zero bytes into an offset
//     that InstructionBitPattern then ignores, so a field that doesn't start
//     in the node's first byte lands in it: a quirk the hashes depend on,
//     kept here;
//   - the instruction bits of the pattern that matched (InstructionPattern,
//     or a CombinePattern's instruction part), at its offset.
//
// The instruction mask is all of that; each operand's mask is the token
// fields its value comes from (combineOperandMask), or failing that what
// was recorded while resolving the root constructor's operand of the same
// name; operand masks are cleared from the instruction mask. Context
// decisions record nothing (addContextPattern is a no-op in Java).
//
// This is a port of the Java (Ghidra 12.1.4, Apache 2.0) over the public C++
// API and patch 0011's DecisionNode accessors.

#include "ghidra_text.hh"

#include "slghsymbol.hh"

namespace revkit::lift::detail {

namespace {

void merge(std::vector<std::uint8_t> &into, const std::vector<std::uint8_t> &from) {
  for (std::size_t i = 0; i < into.size() && i < from.size(); ++i) into[i] |= from[i];
}

// DecisionNode.debugInstructionBitsDecision: the field as
// PatternBlock(0, (-1 << (32 - bitsize)) >>> startbit, val), normalized
// (leading zero bytes dropped), then laid at the node's offset.
void record_decision(std::vector<std::uint8_t> &group, std::uint32_t offset, int startbit, int bitsize) {
  std::uint32_t mask = 0xffffffffu << ((32 - bitsize) & 31);  // Java shifts count mod 32
  mask >>= (startbit & 31);
  if (mask == 0) return;
  int bytes = 0;
  for (std::uint32_t t = mask; t != 0; t >>= 8) ++bytes;
  mask <<= 8 * (4 - bytes);
  for (int k = 0; k < 4; ++k) {
    const std::size_t at = static_cast<std::size_t>(offset) + static_cast<std::size_t>(k);
    if (at < group.size()) group[at] |= static_cast<std::uint8_t>(mask >> (24 - 8 * k));
  }
}

// An instruction pattern that matched: its mask bytes at the node's offset.
void record_pattern(std::vector<std::uint8_t> &group, std::uint32_t offset, const ghidra::DisjointPattern &pat) {
  const int len = pat.getLength(false);
  for (int b = 0; b < len; ++b) {
    const std::size_t at = static_cast<std::size_t>(offset) + static_cast<std::size_t>(b);
    if (at >= group.size()) break;
    group[at] |= static_cast<std::uint8_t>(pat.getMask(b * 8, 8, false));
  }
}

constexpr int kMaxDepth = 64;

bool is_register_space(const ghidra::AddrSpace *spc) {
  return spc->getType() == ghidra::IPTR_PROCESSOR && spc->getName() == "register";
}

// SleighInstructionPrototype flow flags (walkTemplates, convertFlowFlags).
enum : int {
  kReturn = 0x01,
  kCallIndirect = 0x02,
  kBranchIndirect = 0x04,
  kCall = 0x08,
  kJumpOut = 0x10,
  kNoFallthru = 0x20,
  kBranchToEnd = 0x40,
  kCrossBuild = 0x80,
  kLabel = 0x100,
};

void flow_flags(const ghidra::ConstructState *state, int &flags, int depth) {
  if (state == nullptr || state->ct == nullptr || depth > kMaxDepth) return;
  const ghidra::ConstructTpl *tpl = state->ct->getTempl();
  if (tpl == nullptr) return;
  for (const ghidra::OpTpl *op : tpl->getOpvec()) {
    int f = -1;
    switch (op->getOpcode()) {
      case ghidra::CPUI_MULTIEQUAL: {  // build directive
        const auto idx = static_cast<std::size_t>(op->getIn(0)->getOffset().getReal());
        if (idx < state->resolve.size()) flow_flags(state->resolve[idx], flags, depth + 1);
        continue;
      }
      case ghidra::CPUI_PTRSUB: f = kCrossBuild; break;
      case ghidra::CPUI_BRANCHIND: f = kBranchIndirect | kNoFallthru; break;
      case ghidra::CPUI_BRANCH: {
        const auto t = op->getIn(0)->getOffset().getType();
        if (t == ghidra::ConstTpl::j_next) f = kBranchToEnd;
        else if (t == ghidra::ConstTpl::j_start || t == ghidra::ConstTpl::j_relative) f = kNoFallthru;
        else f = kJumpOut | kNoFallthru;
        break;
      }
      case ghidra::CPUI_CBRANCH: {
        const auto t = op->getIn(0)->getOffset().getType();
        if (t == ghidra::ConstTpl::j_next) f = kBranchToEnd;
        else if (t == ghidra::ConstTpl::j_next2) f = kJumpOut;
        else if (t != ghidra::ConstTpl::j_start && t != ghidra::ConstTpl::j_relative) f = kJumpOut;
        else f = 0;
        break;
      }
      case ghidra::CPUI_CALL: f = kCall; break;
      case ghidra::CPUI_CALLIND: f = kCallIndirect; break;
      case ghidra::CPUI_RETURN: f = kReturn | kNoFallthru; break;
      case ghidra::CPUI_PTRADD: f = kLabel; break;
      default: break;
    }
    if (f < 0) continue;
    flags &= ~(kNoFallthru | kCrossBuild | kLabel);
    flags |= f;
  }
}

// convertFlowFlags, then FlowType.isCall().
bool is_call(int flags) {
  if (flags & kLabel) flags |= kBranchToEnd;
  flags &= ~(kCrossBuild | kLabel);
  switch (flags) {
    case kCall:                                             // UNCONDITIONAL_CALL
    case kCall | kNoFallthru | kReturn:                     // CALL_TERMINATOR
    case kCallIndirect | kNoFallthru | kReturn:             // COMPUTED_CALL_TERMINATOR
    case kCall | kBranchToEnd:                              // CONDITIONAL_CALL
    case kCall | kNoFallthru | kBranchToEnd | kReturn:      // UNCONDITIONAL_CALL
    case kCallIndirect:                                     // COMPUTED_CALL
    case kCallIndirect | kBranchToEnd:                      // CONDITIONAL_COMPUTED_CALL
    case kCallIndirect | kNoFallthru | kBranchToEnd:        // CONDITIONAL_COMPUTED_CALL
      return true;
    default:
      return false;
  }
}

}  // namespace

struct GhidraText::FidMasks {
  std::size_t length = 0;
  std::map<std::string, std::vector<std::uint8_t>> root_groups;  // mainSubGroups, by operand symbol name
  bool ok = true;
  int depth = 0;
};

void GhidraText::fid_replay(ghidra::ParserWalkerChange &walker, FidMasks &m, std::vector<std::uint8_t> &group,
                            bool root) {
  ghidra::ConstructState *st = walker.getPoint();
  if (st == nullptr || st->ct == nullptr || m.depth > kMaxDepth) {
    m.ok = false;
    return;
  }
  const ghidra::Constructor *ct = st->ct;
  const ghidra::SubtableSymbol *table = ct->getParent();
  const ghidra::DecisionNode *node = table ? table->getDecisionNode() : nullptr;
  if (node == nullptr) {
    m.ok = false;
    return;
  }
  for (int guard = 0; node->getBitSize() != 0; ++guard) {
    const int start = node->getStartBit(), size = node->getBitSize();
    std::uint32_t val;
    if (node->isContextDecision()) {
      val = walker.getContextBits(start, size);
    } else {
      val = walker.getInstructionBits(start, size);
      record_decision(group, walker.getOffset(-1), start, size);
    }
    const auto &children = node->getChildren();
    if (val >= children.size() || guard > 64) {
      m.ok = false;
      return;
    }
    node = children[val];
  }
  const ghidra::DisjointPattern *matched = nullptr;
  const ghidra::Constructor *chosen = nullptr;
  for (const auto &[pat, c] : node->getPairs()) {
    if (pat->isMatch(walker)) {
      matched = pat;
      chosen = c;
      break;
    }
  }
  if (chosen != ct) {  // not the resolve the tree came from
    m.ok = false;
    return;
  }
  record_pattern(group, walker.getOffset(-1), *matched);
  ct->applyContext(walker);
  for (int i = 0; i < ct->getNumOperands(); ++i) {
    const ghidra::OperandSymbol *sym = ct->getOperand(i);
    const ghidra::TripleSymbol *tsym = sym->getDefiningSymbol();
    if (tsym == nullptr) continue;
    if (tsym->getType() != ghidra::SleighSymbol::subtable_symbol) {
      if (root) m.root_groups[sym->getName()] = std::vector<std::uint8_t>(m.length, 0);
      continue;
    }
    std::vector<std::uint8_t> sub(m.length, 0);
    walker.pushOperand(i);
    ++m.depth;
    fid_replay(walker, m, sub, false);
    --m.depth;
    walker.popOperand();
    if (!m.ok) return;
    merge(group, sub);
    if (root) m.root_groups[sym->getName()] = std::move(sub);
  }
}

// SleighDebugLogger.combineOperandMask.
void GhidraText::fid_operand_mask(const ghidra::ConstructState *state, const ghidra::OperandSymbol *sym,
                                  std::vector<std::uint8_t> &mask, int depth) {
  if (state == nullptr || sym == nullptr || depth > kMaxDepth) return;
  const ghidra::PatternExpression *pe = nullptr;
  const auto hand = static_cast<std::size_t>(sym->getIndex());
  const ghidra::ConstructState *sub = hand < state->resolve.size() ? state->resolve[hand] : nullptr;
  if (const ghidra::TripleSymbol *triple = sym->getDefiningSymbol()) {
    if (triple->getType() == ghidra::SleighSymbol::subtable_symbol) {
      // combineSymbolMask: the operands the sub-constructor prints.
      if (sub != nullptr && sub->ct != nullptr) {
        const ConstructorInfo &ci = info(sub->ct);
        for (const Piece &p : ci.pieces)
          if (p.operand && p.index >= 0 && p.index < sub->ct->getNumOperands())
            fid_operand_mask(sub, sub->ct->getOperand(p.index), mask, depth + 1);
      }
    } else {
      try {
        pe = triple->getPatternExpression();
      } catch (const ghidra::LowlevelError &) {
        pe = nullptr;
      }
    }
  } else {
    pe = sym->getDefiningExpression();
  }
  if (pe == nullptr) return;
  if (sym->getOffsetBase() < 0) fid_pattern_mask(state, pe, state->offset + sym->getRelativeOffset(), mask, depth + 1);
  else if (sub != nullptr) fid_pattern_mask(sub, pe, sub->offset, mask, depth + 1);
}

// SleighDebugLogger.combinePatternMask.
void GhidraText::fid_pattern_mask(const ghidra::ConstructState *state, const ghidra::PatternExpression *pe,
                                  std::uint32_t offset, std::vector<std::uint8_t> &mask, int depth) {
  if (pe == nullptr || depth > kMaxDepth) return;
  if (const auto *u = dynamic_cast<const ghidra::UnaryExpression *>(pe)) {
    fid_pattern_mask(state, u->getUnary(), offset, mask, depth + 1);
  } else if (const auto *b = dynamic_cast<const ghidra::BinaryExpression *>(pe)) {
    fid_pattern_mask(state, b->getLeft(), offset, mask, depth + 1);
    fid_pattern_mask(state, b->getRight(), offset, mask, depth + 1);
  } else if (const auto *ov = dynamic_cast<const ghidra::OperandValue *>(pe)) {
    const ghidra::Constructor *c = ov->getConstructor();
    if (c != nullptr && ov->getIndex() >= 0 && ov->getIndex() < c->getNumOperands())
      fid_operand_mask(state, c->getOperand(ov->getIndex()), mask, depth + 1);
  } else if (const auto *tf = dynamic_cast<const ghidra::TokenField *>(pe)) {
    const int start_byte = tf->getByteStart();
    const int end_byte = tf->getByteEnd();
    const int start_bit = tf->getBitStart() % 8;
    const int end_bit = tf->getBitEnd() % 8;
    const bool big = trans_.isBigEndian();  // the memory buffer's order, as Java reads it
    for (int i = start_byte; i <= end_byte; ++i) {
      int first = 0, last = 7;
      if (i == end_byte) {
        if (big) first = start_bit;
        else last = end_bit;
      }
      if (i == start_byte) {
        if (big) last = end_bit;
        else first = start_bit;
      }
      const int shift = 7 - last + first;
      const std::uint8_t byte_mask =
          shift < 0 || shift > 31 ? 0 : static_cast<std::uint8_t>((0xff >> shift) << first);
      const std::int64_t at = static_cast<std::int64_t>(offset) + i;
      if (at >= 0 && static_cast<std::size_t>(at) < mask.size()) mask[static_cast<std::size_t>(at)] |= byte_mask;
    }
  }
}

// SleighInstructionPrototype.addHandleObject, as the hash sees the objects.
bool GhidraText::fid_object(const ghidra::FixedHandle &h, FidObject &out) const {
  if (h.space == nullptr) return false;
  auto reg = [&](const ghidra::AddrSpace *space, std::uint64_t offset, std::uint32_t size) {
    const std::string *name = find_register(space, offset, size);
    if (name == nullptr) return false;
    auto it = by_name_.find(*name);
    if (it == by_name_.end()) return false;
    out.kind = FidObject::Kind::reg;
    out.value = static_cast<std::int64_t>(it->second.offset);
    return true;
  };
  if (is_register_space(h.space)) return reg(h.space, h.offset_offset, h.size);
  if (h.space->getType() == ghidra::IPTR_CONSTANT) {
    std::uint32_t size = h.size;
    if (size == 0) size = h.offset_size;
    if (size == 0) size = trans_.getDefaultCodeSpace()->getAddrSize();
    const int bits = size >= 1 && size <= 8 ? static_cast<int>(size * 8) : 64;
    const int unused = 64 - bits;
    out.kind = FidObject::Kind::scalar;
    out.bits = static_cast<std::uint8_t>(bits);
    out.value = static_cast<std::int64_t>(h.offset_offset << unused) >> unused;
    return true;
  }
  if (h.space->getType() != ghidra::IPTR_PROCESSOR) return false;
  if (h.offset_space == nullptr) {
    const std::uint64_t addr = h.offset_offset & h.space->getHighest();
    if (has_registers_.contains(h.space) && reg(h.space, addr, h.size)) return true;
    out.kind = FidObject::Kind::address;
    out.value = static_cast<std::int64_t>(addr);
    return true;
  }
  if (is_register_space(h.offset_space)) return reg(h.offset_space, h.offset_offset, h.offset_size);
  return false;
}

void GhidraText::fid(ghidra::ParserContext &context, FidInstruction &out) {
  out.length = static_cast<std::uint32_t>(context.getLength());
  out.masks = false;
  out.mask.clear();
  out.operands.clear();

  ghidra::ConstructState *root = nullptr;
  {
    ghidra::ParserWalkerChange w(&context);
    w.baseState();
    root = w.getPoint();
  }
  int flags = 0;
  flow_flags(root, flags, 0);
  out.call = is_call(flags);

  // The mnemonic's constructor (cacheMnemonicState) and its operands in
  // display order (Constructor.getOpsPrintOrder).
  const ghidra::ConstructState *mnem = root;
  for (int guard = 0; mnem != nullptr && mnem->ct != nullptr && guard <= kMaxDepth; ++guard) {
    const ConstructorInfo &ci = info(mnem->ct);
    if (ci.flowthru < 0 || static_cast<std::size_t>(ci.flowthru) >= mnem->resolve.size()) break;
    mnem = mnem->resolve[static_cast<std::size_t>(ci.flowthru)];
  }
  if (mnem == nullptr || mnem->ct == nullptr) return;
  const ghidra::Constructor *mct = mnem->ct;
  const ConstructorInfo &mci = info(mct);
  std::vector<int> order;
  if (mci.first_whitespace >= 0)
    for (std::size_t i = static_cast<std::size_t>(mci.first_whitespace) + 1; i < mci.pieces.size(); ++i)
      if (mci.pieces[i].operand) order.push_back(mci.pieces[i].index);

  // Operands' objects and types; the walker sits at the mnemonic's state.
  auto to_mnemonic = [&](Walker &w) {
    w.baseState();
    for (int guard = 0; guard <= kMaxDepth; ++guard) {
      const ConstructorInfo &ci = info(w.getConstructor());
      if (ci.flowthru < 0) break;
      w.pushOperand(ci.flowthru);
    }
  };
  out.operands.resize(order.size());
  for (std::size_t i = 0; i < order.size(); ++i) {
    FidOperand &op = out.operands[i];
    const ghidra::OperandSymbol *sym = mct->getOperand(order[i]);
    std::vector<Item> list;
    try {
      Walker w(&context);
      to_mnemonic(w);
      operand_list(w, sym, list);
    } catch (const ghidra::LowlevelError &) {
      list.clear();
    }
    for (const Item &it : list) {
      if (it.is_char) continue;
      FidObject obj;
      if (fid_object(it.handle, obj)) op.objects.push_back(obj);
    }
    // getOpType: the operand state's own handle.
    const auto idx = static_cast<std::size_t>(order[i]);
    const ghidra::ConstructState *os = idx < mnem->resolve.size() ? mnem->resolve[idx] : nullptr;
    if (os != nullptr && os->hand.space != nullptr && os->hand.offset_space == nullptr) {
      const ghidra::AddrSpace *spc = os->hand.space;
      if (spc->getType() == ghidra::IPTR_CONSTANT) op.scalar = true;
      else if (!is_register_space(spc) && (sym->isCodeAddress() || spc->getType() == ghidra::IPTR_PROCESSOR))
        op.address = true;
    }
  }

  // The masks, replaying the resolve.
  FidMasks m;
  m.length = out.length;
  std::vector<std::uint8_t> main(out.length, 0);
  try {
    context.loadContext();
    ghidra::ParserWalkerChange walker(&context);
    walker.baseState();
    fid_replay(walker, m, main, true);
  } catch (const ghidra::LowlevelError &) {
    m.ok = false;
  }
  if (!m.ok) return;
  for (std::size_t i = 0; i < order.size(); ++i) {
    std::vector<std::uint8_t> mask(out.length, 0);
    const ghidra::OperandSymbol *sym = mct->getOperand(order[i]);
    try {
      fid_operand_mask(mnem, sym, mask, 0);
    } catch (const ghidra::LowlevelError &) {
      return;
    }
    bool empty = true;
    for (std::uint8_t b : mask) empty = empty && b == 0;
    if (empty) {
      auto g = m.root_groups.find(sym->getName());
      if (g != m.root_groups.end()) mask = g->second;
    }
    for (std::size_t k = 0; k < main.size(); ++k) main[k] &= static_cast<std::uint8_t>(~mask[k]);
    out.operands[i].mask = std::move(mask);
  }
  out.mask = std::move(main);
  out.masks = true;
}

}  // namespace revkit::lift::detail
