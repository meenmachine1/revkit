#include "ghidra_text.hh"

#include "slaformat.hh"
#include "slghsymbol.hh"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace revkit::lift::detail {

namespace {

// Captures a Constructor's print pieces from its .sla encoding: the C++
// class keeps them private, but encode() is public and writes them out.
class PieceCapture : public ghidra::Encoder {
 public:
  std::vector<std::pair<bool, std::string>> pieces;  // (is operand, text or index)
  int first_whitespace = -1;

  void openElement(const ghidra::ElementId &id) override { stack_.push_back(id.getId()); }
  void closeElement(const ghidra::ElementId &) override {
    if (!stack_.empty()) stack_.pop_back();
  }
  void writeBool(const ghidra::AttributeId &, bool) override {}
  void writeSignedInteger(const ghidra::AttributeId &attr, ghidra::intb val) override {
    if (stack_.empty()) return;
    if (stack_.back() == ghidra::sla::ELEM_CONSTRUCTOR.getId() && stack_.size() == 1 &&
        attr.getId() == ghidra::sla::ATTRIB_FIRST.getId())
      first_whitespace = static_cast<int>(val);
    else if (stack_.back() == ghidra::sla::ELEM_OPPRINT.getId() && attr.getId() == ghidra::sla::ATTRIB_ID.getId())
      pieces.emplace_back(true, std::to_string(val));
  }
  void writeUnsignedInteger(const ghidra::AttributeId &, ghidra::uintb) override {}
  void writeString(const ghidra::AttributeId &attr, const std::string &val) override {
    if (!stack_.empty() && stack_.back() == ghidra::sla::ELEM_PRINT.getId() &&
        attr.getId() == ghidra::sla::ATTRIB_PIECE.getId())
      pieces.emplace_back(false, val);
  }
  void writeStringIndexed(const ghidra::AttributeId &, ghidra::uint4, const std::string &) override {}
  void writeSpace(const ghidra::AttributeId &, const ghidra::AddrSpace *) override {}
  void writeOpcode(const ghidra::AttributeId &, ghidra::OpCode) override {}

 private:
  std::vector<ghidra::uint4> stack_;
};

std::string hex_digits(std::uint64_t v) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string s;
  do {
    s.insert(s.begin(), digits[v & 0xf]);
    v >>= 4;
  } while (v != 0);
  return s;
}

// Java Scalar(bits, value, signed).toString(): "0x1f", "-0x10".
std::string scalar_text(int bits, std::uint64_t raw, bool is_signed) {
  if (bits < 1 || bits > 64) bits = 64;
  const int unused = 64 - bits;
  const std::uint64_t value = (raw << unused) >> unused;
  if (is_signed) {
    auto sval = static_cast<std::int64_t>(value << unused) >> unused;
    if (sval < 0) return "-0x" + hex_digits(std::uint64_t{0} - static_cast<std::uint64_t>(sval));
    return "0x" + hex_digits(static_cast<std::uint64_t>(sval));
  }
  return "0x" + hex_digits(value);
}

bool is_register_space(const ghidra::AddrSpace *spc) {
  return spc->getType() == ghidra::IPTR_PROCESSOR && spc->getName() == "register";
}

}  // namespace

GhidraText::GhidraText(const ghidra::Translate &trans) : trans_(trans) {
  // Java's RegisterManager: registers largest first, each claiming
  // (address, n) for n up to its size, so a lookup finds the smallest
  // register at that address at least n bytes wide. Big-endian registers
  // align on their last byte.
  std::map<ghidra::VarnodeData, std::string> all;
  trans_.getAllRegisters(all);
  std::vector<std::pair<ghidra::VarnodeData, std::string>> regs(all.begin(), all.end());
  std::stable_sort(regs.begin(), regs.end(), [](const auto &a, const auto &b) { return a.first.size > b.first.size; });
  const bool big = trans_.isBigEndian();
  for (const auto &[vn, name] : regs) {
    if (name == "contextreg") continue;  // processor context, not a register
    has_registers_[vn.space] = true;
    by_name_.emplace(name, vn);
    for (std::uint32_t i = 1; i <= vn.size; ++i) {
      std::uint64_t at = big ? vn.offset + (vn.size - i) : vn.offset;
      registers_[{vn.space, at, i}] = name;
    }
  }
}

const GhidraText::ConstructorInfo &GhidraText::info(const ghidra::Constructor *ct) {
  auto it = infos_.find(ct);
  if (it != infos_.end()) return it->second;
  PieceCapture capture;
  ct->encode(capture);
  ConstructorInfo ci;
  ci.first_whitespace = capture.first_whitespace;
  for (auto &[is_operand, text] : capture.pieces) {
    Piece p;
    p.operand = is_operand;
    if (is_operand) p.index = std::stoi(text);
    else p.text = std::move(text);
    ci.pieces.push_back(std::move(p));
  }
  if (ci.pieces.size() == 1 && ci.pieces[0].operand) ci.flowthru = ci.pieces[0].index;
  return infos_.emplace(ct, std::move(ci)).first->second;
}

void GhidraText::operand_list(Walker &walker, const ghidra::OperandSymbol *sym, std::vector<Item> &list) {
  walker.pushOperand(sym->getIndex());
  ghidra::TripleSymbol *triple = sym->getDefiningSymbol();
  if (triple != nullptr) {
    if (triple->getType() == ghidra::SleighSymbol::subtable_symbol) {
      constructor_list(walker, list);
    } else if (triple->getType() == ghidra::SleighSymbol::name_symbol) {
      std::ostringstream s;
      triple->print(s, walker);
      for (char c : s.str()) list.push_back({true, c, {}, true});
    } else {
      Item it;
      it.handle = walker.getParentHandle();
      if (it.handle.offset_space == nullptr) it.handle.offset_size = 0;  // C++ leaves it stale
      list.push_back(it);
    }
  } else {
    Item it;
    it.handle = walker.getParentHandle();
    it.handle.offset_size = static_cast<ghidra::uint4>(walker.current_length());
    list.push_back(it);
  }
  walker.popOperand();
}

void GhidraText::constructor_list(Walker &walker, std::vector<Item> &list) {
  const ghidra::Constructor *ct = walker.getConstructor();
  const ConstructorInfo &ci = info(ct);
  int operands_printed = 0;
  std::ptrdiff_t last_handle = -1;
  int last_handle_index = -1;
  for (const Piece &p : ci.pieces) {
    std::size_t before = list.size();
    if (p.operand) {
      operand_list(walker, ct->getOperand(p.index), list);
      if (before != list.size() && ++operands_printed == 1) {
        for (std::size_t n = before; n < list.size(); ++n) {
          if (list[n].is_char) continue;
          if (last_handle != -1) {  // can't fix multiple handles
            last_handle = -1;
            break;
          }
          last_handle = static_cast<std::ptrdiff_t>(n);
          last_handle_index = p.index;
        }
      }
    } else {
      for (char c : p.text) list.push_back({true, c, {}, true});
    }
  }

  // A constant operand exported as an address prints as that address
  // (HandleTpl.fixPrintPiece).
  if (operands_printed != 1 || last_handle == -1 || ct->getTempl() == nullptr) return;
  Item &item = list[static_cast<std::size_t>(last_handle)];
  const ghidra::HandleTpl *res = ct->getTempl()->getResult();
  if (!item.fixable || res == nullptr) return;
  if (item.handle.space->getType() != ghidra::IPTR_CONSTANT) {
    item.fixable = false;
    return;
  }
  if (res->getSpace().getType() == ghidra::ConstTpl::spaceid && res->getSpace().isUniqueSpace()) {
    item.fixable = false;
    return;
  }
  const ghidra::ConstTpl &ptroffset = res->getPtrOffset();
  if (ptroffset.getType() == ghidra::ConstTpl::handle && ptroffset.getHandleIndex() == last_handle_index) {
    item.handle.space = res->getSpace().fixSpace(walker);
    item.handle.offset_offset = item.handle.space->getWordSize() * item.handle.offset_offset;
    item.handle.size = static_cast<ghidra::uint4>(res->getSize().fix(walker));
  } else {
    item.fixable = false;
  }
}

const std::string *GhidraText::find_register(const ghidra::AddrSpace *space, std::uint64_t offset,
                                             std::uint32_t size) const {
  if (size == 0) {
    // Java's size-0 key maps to the largest register at the address.
    const std::string *best = nullptr;
    for (auto it = registers_.lower_bound({space, offset, 1});
         it != registers_.end() && std::get<0>(it->first) == space && std::get<1>(it->first) == offset; ++it)
      best = &it->second;
    return best;
  }
  auto it = registers_.find({space, offset, size});
  return it == registers_.end() ? nullptr : &it->second;
}

Varnode GhidraText::register_varnode(const ghidra::AddrSpace *space, std::uint64_t offset,
                                     std::uint32_t size) const {
  return {space->getName(), offset, size, {}};
}

// SleighInstructionPrototype.addHandleObject, rendered to a token.
bool GhidraText::render_handle(const ghidra::FixedHandle &h, Token &out) const {
  if (h.space == nullptr) return false;
  if (is_register_space(h.space)) {
    if (const std::string *r = find_register(h.space, h.offset_offset, h.size)) {
      out.kind = Token::Kind::reg;
      out.text = *r;
      out.reg = register_varnode(h.space, h.offset_offset, h.size);
    } else {
      out.kind = Token::Kind::separator;
      out.text = "<BAD_register_" + std::to_string(static_cast<std::int64_t>(h.offset_offset)) + ":" +
                 std::to_string(h.size) + ">";
    }
    return true;
  }
  if (h.space->getType() == ghidra::IPTR_CONSTANT) {
    std::uint32_t size = h.size;
    if (size == 0) size = h.offset_size;
    if (size == 0) size = trans_.getDefaultCodeSpace()->getAddrSize();
    const int bits = size >= 1 && size <= 8 ? static_cast<int>(size * 8) : 64;
    const bool is_signed = static_cast<std::int64_t>(h.offset_offset) < 0;
    out.kind = Token::Kind::scalar;
    out.bits = static_cast<std::uint8_t>(bits);
    out.text = scalar_text(bits, h.offset_offset, is_signed);
    const int unused = 64 - bits;
    std::uint64_t v = (h.offset_offset << unused) >> unused;
    if (is_signed) v = static_cast<std::uint64_t>(static_cast<std::int64_t>(v << unused) >> unused);
    out.value = v;
    return true;
  }
  if (h.space->getType() != ghidra::IPTR_PROCESSOR) return false;
  if (h.offset_space == nullptr) {
    std::uint64_t addr = h.offset_offset & h.space->getHighest();
    if (has_registers_.contains(h.space)) {
      if (const std::string *r = find_register(h.space, addr, h.size)) {
        out.kind = Token::Kind::reg;
        out.text = *r;
        out.reg = register_varnode(h.space, addr, h.size);
        return true;
      }
    }
    // GenericAddress.toString(false): at least 8 digits, at most the space's.
    std::string digits = hex_digits(addr);
    std::size_t max_digits = (h.space->getAddrSize() * 8 - 1) / 4 + 1;
    std::size_t pad = std::min<std::size_t>(8, max_digits);
    if (digits.size() < pad) digits.insert(0, pad - digits.size(), '0');
    out.kind = Token::Kind::address;
    out.text = "0x" + digits;
    out.value = addr;
    return true;
  }
  if (is_register_space(h.offset_space)) {
    if (const std::string *r = find_register(h.offset_space, h.offset_offset, h.offset_size)) {
      out.kind = Token::Kind::reg;
      out.text = *r;
      out.reg = register_varnode(h.offset_space, h.offset_offset, h.offset_size);
    } else {
      out.kind = Token::Kind::separator;
      out.text = "null";
    }
    return true;
  }
  return false;
}

void GhidraText::literal(const std::string &text, int operand, std::vector<Token> &out) const {
  auto word_char = [](char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.'; };
  for (std::size_t i = 0; i < text.size();) {
    Token t;
    t.operand = operand;
    std::size_t j = i + 1;
    if (std::isspace(static_cast<unsigned char>(text[i]))) {
      while (j < text.size() && std::isspace(static_cast<unsigned char>(text[j]))) ++j;
      t.kind = Token::Kind::whitespace;
    } else if (word_char(text[i])) {
      while (j < text.size() && word_char(text[j])) ++j;
      t.kind = Token::Kind::separator;
    } else {
      t.kind = Token::Kind::separator;
    }
    t.text = text.substr(i, j - i);
    // Some specs spell a register out as literal text.
    if (auto it = by_name_.find(t.text); it != by_name_.end()) {
      t.kind = Token::Kind::reg;
      t.reg = register_varnode(it->second.space, it->second.offset, it->second.size);
    }
    out.push_back(std::move(t));
    i = j;
  }
}

void GhidraText::render(const std::vector<Item> &list, int operand, std::vector<Token> &out) const {
  std::string chars;
  for (const Item &it : list) {
    if (it.is_char) {
      chars.push_back(it.c);
      continue;
    }
    Token t;
    t.operand = operand;
    if (!render_handle(it.handle, t)) continue;
    literal(chars, operand, out);
    chars.clear();
    out.push_back(std::move(t));
  }
  literal(chars, operand, out);
}

// Constructor.printSeparator: literal text before operand `index`, after the
// mnemonic, with ",<whitespace>" collapsed to ",".
std::string GhidraText::separator(const ConstructorInfo &ci, int index, int num_operands) const {
  if (index < 0 || index > num_operands) return {};
  std::size_t pos = 0;
  while (pos < ci.pieces.size() &&
         (ci.pieces[pos].operand || ci.pieces[pos].text.empty() || ci.pieces[pos].text[0] != ' '))
    ++pos;
  ++pos;
  int op = 0;
  std::string buf;
  for (std::size_t i = pos; i < ci.pieces.size() && op <= index; ++i) {
    const Piece &p = ci.pieces[i];
    if (p.operand) {
      if (op == index) break;
      ++op;
    } else if (!p.text.empty() && op == index) {
      buf += p.text;
    }
  }
  std::string out;
  for (std::size_t i = 0; i < buf.size(); ++i) {
    out.push_back(buf[i]);
    if (buf[i] == ',')
      while (i + 1 < buf.size() && std::isspace(static_cast<unsigned char>(buf[i + 1]))) ++i;
  }
  return out;
}

std::vector<Token> GhidraText::tokens(const ghidra::ParserContext &context, const std::string &mnemonic) {
  // Java's mnemonicState: follow flow-through constructors from the root to
  // the one that prints the mnemonic.
  auto to_mnemonic = [&](Walker &w) {
    w.baseState();
    for (;;) {
      const ConstructorInfo &ci = info(w.getConstructor());
      if (ci.flowthru < 0) break;
      w.pushOperand(ci.flowthru);
    }
  };
  Walker walker(&context);
  to_mnemonic(walker);
  const ghidra::Constructor *ct = walker.getConstructor();
  const ConstructorInfo &ci = info(ct);

  std::vector<int> order;  // Constructor.getOpsPrintOrder
  if (ci.first_whitespace >= 0)
    for (std::size_t i = static_cast<std::size_t>(ci.first_whitespace) + 1; i < ci.pieces.size(); ++i)
      if (ci.pieces[i].operand) order.push_back(ci.pieces[i].index);

  const int num_operands = ct->getNumOperands();
  std::vector<Token> out;
  out.push_back({Token::Kind::mnemonic, mnemonic, -1, 0, 0, {}});
  std::string sep = separator(ci, 0, num_operands);
  if (!sep.empty() || !order.empty()) out.push_back({Token::Kind::whitespace, " ", -1, 0, 0, {}});
  literal(sep, -1, out);
  for (std::size_t i = 0; i < order.size(); ++i) {
    std::vector<Item> list;
    try {
      Walker w(&context);
      to_mnemonic(w);
      operand_list(w, ct->getOperand(order[i]), list);
    } catch (const ghidra::LowlevelError &) {
      list.clear();  // Java treats a failing operand as having no representation
    }
    render(list, static_cast<int>(i), out);
    literal(separator(ci, static_cast<int>(i) + 1, num_operands), -1, out);
  }
  return out;
}

std::string GhidraText::text(const ghidra::ParserContext &context, const std::string &mnemonic) {
  std::string out;
  for (const Token &t : tokens(context, mnemonic)) out += t.text;
  return out;
}

}  // namespace revkit::lift::detail
