// Grammar construction from a loaded SLEIGH spec.

#include "grammar.hh"

#include "revkit/lift/sleigh_decoder.hh"

#include "sleigh.hh"
#include "slghsymbol.hh"

#include <algorithm>
#include <cctype>
#include <functional>
#include <set>
#include <sstream>
#include <stdexcept>

namespace revkit::assembler::detail {

namespace g = ghidra;

std::string Block::str() const {
  std::string s;
  static const char *hex = "0123456789abcdef";
  for (int i = 0; i < len; ++i) {
    if (i) s += ':';
    for (int b = 7; b >= 0; --b) {
      const std::uint8_t bit = static_cast<std::uint8_t>(1u << b);
      s += (mask[i] & bit) ? ((val[i] & bit) ? '1' : '0') : 'x';
    }
    (void)hex;
  }
  return s;
}

std::vector<std::string> Terminal::suggestions() const {
  switch (kind) {
    case Literal:
    case Register: return {text};
    case Space: return {" "};
    case Names: {
      std::vector<std::string> out;
      for (const auto &[n, _] : names)
        if (!n.empty()) out.push_back(n);
      return out;
    }
    case Number:
    case Values: return {address ? "<address>" : "<number>"};
  }
  return {};
}

int Grammar::add_expr(const Expr &e) {
  std::string key(reinterpret_cast<const char *>(&e.op), 1);
  for (std::int64_t v : {e.value, std::int64_t{e.big_endian}, std::int64_t{e.sign}, std::int64_t{e.bit_start},
                         std::int64_t{e.bit_end}, std::int64_t{e.byte_start}, std::int64_t{e.byte_end},
                         std::int64_t{e.shift}, std::int64_t{e.cons}, std::int64_t{e.index}, std::int64_t{e.l},
                         std::int64_t{e.r}})
    key.append(reinterpret_cast<const char *>(&v), sizeof v);
  auto [it, fresh] = expr_ids.try_emplace(std::move(key), static_cast<int>(exprs.size()));
  if (fresh) exprs.push_back(e);
  return it->second;
}

std::string Grammar::describe(int c) const {
  const Constructor &k = cons[c];
  std::ostringstream s;
  s << nt_names[k.nt] << ":" << k.line;
  return s.str();
}

std::string Grammar::describe_production(int p) const {
  const Production &prod = productions[p];
  std::string s = nt_names[prod.lhs] + " ->";
  for (const Sym &sym : prod.rhs) {
    s += ' ';
    if (sym.nt) {
      s += nt_names[sym.id];
      continue;
    }
    const Terminal &t = terminals[sym.id];
    switch (t.kind) {
      case Terminal::Literal: s += "'" + t.text + "'"; break;
      case Terminal::Space: s += "_"; break;
      case Terminal::Number: s += "[num" + std::to_string(t.bits) + "]"; break;
      case Terminal::Names: s += "[names:" + t.key + "]"; break;
      case Terminal::Values: s += "[values:" + t.key + "]"; break;
      case Terminal::Register: s += "[reg:" + t.text + "]"; break;
    }
  }
  return s;
}

namespace {

std::string lower(std::string s) {
  for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

bool word_char(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; }

class Builder {
 public:
  Builder(const lift::SleighDecoder &dec, Grammar &g) : dec_(dec), g_(g), sleigh_(dec.sleigh()) {}

  void build() {
    g_.language = dec_.language();
    g_.big_endian = dec_.big_endian();
    g_.alignment = std::max(1u, dec_.alignment());
    g_.word_size = std::max(1u, dec_.word_size());
    g_.address_size = dec_.address_size();
    g_.context_words = static_cast<int>(dec_.default_context().size());
    if (g_.context_words * 4 > kMaxBytes) throw std::runtime_error("context too large for the assembler");

    auto *root = dynamic_cast<g::SubtableSymbol *>(sleigh_.findSymbol("instruction"));
    if (root == nullptr) throw std::runtime_error("no instruction table");
    // Every subtable reachable from the root, and their constructors.
    std::vector<g::SubtableSymbol *> work{root};
    while (!work.empty()) {
      g::SubtableSymbol *t = work.back();
      work.pop_back();
      if (nt_of_.contains(t)) continue;
      nt_of_[t] = static_cast<int>(g_.nt_names.size());
      g_.nt_names.push_back(t->getName());
      tables_.push_back(t);
      for (int i = 0; i < t->getNumConstructors(); ++i) {
        g::Constructor *ct = t->getConstructor(i);
        for (int k = 0; k < ct->getNumOperands(); ++k) {
          g::TripleSymbol *ts = ct->getOperand(k)->getDefiningSymbol();
          if (ts != nullptr && ts->getType() == g::SleighSymbol::subtable_symbol)
            work.push_back(static_cast<g::SubtableSymbol *>(ts));
        }
      }
    }
    g_.start = nt_of_.at(root);
    g_.nt_productions.resize(g_.nt_names.size());
    g_.nt_cons.resize(g_.nt_names.size());
    // Index every constructor first: OperandValue expressions refer to them.
    for (std::size_t n = 0; n < tables_.size(); ++n)
      for (int i = 0; i < tables_[n]->getNumConstructors(); ++i) {
        g::Constructor *ct = tables_[n]->getConstructor(i);
        g_.cons_index[ct] = static_cast<int>(g_.cons.size());
        Constructor c;
        c.ct = ct;
        c.nt = static_cast<int>(n);
        c.min_length = ct->getMinimumLength();
        c.line = ct->getLineno();
        g_.cons.push_back(std::move(c));
        g_.nt_cons[n].push_back(static_cast<int>(g_.cons.size() - 1));
      }
    for (std::size_t n = 0; n < tables_.size(); ++n) collect_patterns(tables_[n]->getDecisionNode());
    for (std::size_t c = 0; c < g_.cons.size(); ++c) convert(static_cast<int>(c));
    for (std::size_t c = 0; c < g_.cons.size(); ++c) add_production(static_cast<int>(c));
    nullable();
  }

 private:
  void collect_patterns(const g::DecisionNode *node) {
    if (node == nullptr) return;
    for (const auto &[pat, ct] : node->getPairs()) {
      auto it = g_.cons_index.find(ct);
      if (it == g_.cons_index.end()) continue;
      Pattern p;
      if (!block_of(pat, false, p.ins) || !block_of(pat, true, p.ctx)) continue;
      auto &pats = g_.cons[it->second].patterns;
      bool dup = false;
      for (const Pattern &q : pats) dup = dup || (q.ins == p.ins && q.ctx == p.ctx);
      if (!dup) pats.push_back(p);
    }
    for (const g::DecisionNode *child : node->getChildren()) collect_patterns(child);
  }

  static bool block_of(const g::DisjointPattern *pat, bool context, Block &out) {
    const int n = pat->getLength(context);
    if (n < 0) return false;  // always false
    if (n > kMaxBytes) throw std::runtime_error("pattern longer than the assembler supports");
    out = Block{};
    out.len = static_cast<std::uint8_t>(n);
    for (int i = 0; i < n; ++i) {
      out.mask[i] = static_cast<std::uint8_t>(pat->getMask(8 * i, 8, context));
      out.val[i] = static_cast<std::uint8_t>(pat->getValue(8 * i, 8, context) & out.mask[i]);
    }
    return true;
  }

  int expr(const g::PatternExpression *e) {
    if (e == nullptr) return -1;
    Expr x;
    if (auto *c = dynamic_cast<const g::ConstantValue *>(e)) {
      x.op = Expr::Const;
      x.value = c->minValue();
    } else if (auto *t = dynamic_cast<const g::TokenField *>(e)) {
      x.op = Expr::Token;
      x.big_endian = t->isBigEndian();
      x.sign = t->hasSignbit();
      x.bit_start = t->getBitStart();
      x.bit_end = t->getBitEnd();
      x.byte_start = t->getByteStart();
      x.byte_end = t->getByteEnd();
      x.shift = t->getShift();
    } else if (auto *f = dynamic_cast<const g::ContextField *>(e)) {
      x.op = Expr::Context;
      x.sign = f->getSignBit();
      x.bit_start = f->getStartBit();
      x.bit_end = f->getEndBit();
      x.byte_start = f->getStartByte();
      x.byte_end = f->getEndByte();
      x.shift = f->getShift();
    } else if (auto *o = dynamic_cast<const g::OperandValue *>(e)) {
      x.op = Expr::Operand;
      auto it = g_.cons_index.find(o->getConstructor());
      if (it == g_.cons_index.end()) throw std::runtime_error("operand value of an unknown constructor");
      x.cons = it->second;
      x.index = o->getIndex();
    } else if (dynamic_cast<const g::StartInstructionValue *>(e)) {
      x.op = Expr::Start;
    } else if (dynamic_cast<const g::EndInstructionValue *>(e)) {
      x.op = Expr::End;
    } else if (dynamic_cast<const g::Next2InstructionValue *>(e)) {
      x.op = Expr::Next2;
    } else if (auto *b = dynamic_cast<const g::BinaryExpression *>(e)) {
      if (dynamic_cast<const g::PlusExpression *>(e)) x.op = Expr::Plus;
      else if (dynamic_cast<const g::SubExpression *>(e)) x.op = Expr::Sub;
      else if (dynamic_cast<const g::MultExpression *>(e)) x.op = Expr::Mult;
      else if (dynamic_cast<const g::LeftShiftExpression *>(e)) x.op = Expr::Shl;
      else if (dynamic_cast<const g::RightShiftExpression *>(e)) x.op = Expr::Shr;
      else if (dynamic_cast<const g::AndExpression *>(e)) x.op = Expr::And;
      else if (dynamic_cast<const g::OrExpression *>(e)) x.op = Expr::Or;
      else if (dynamic_cast<const g::XorExpression *>(e)) x.op = Expr::Xor;
      else if (dynamic_cast<const g::DivExpression *>(e)) x.op = Expr::Div;
      else throw std::runtime_error("unknown binary pattern expression");
      x.l = expr(b->getLeft());
      x.r = expr(b->getRight());
    } else if (auto *u = dynamic_cast<const g::UnaryExpression *>(e)) {
      if (dynamic_cast<const g::MinusExpression *>(e)) x.op = Expr::Neg;
      else if (dynamic_cast<const g::NotExpression *>(e)) x.op = Expr::Not;
      else throw std::runtime_error("unknown unary pattern expression");
      x.l = expr(u->getUnary());
    } else {
      throw std::runtime_error("unknown pattern expression");
    }
    return g_.add_expr(x);
  }

  void convert(int ci) {
    Constructor &c = g_.cons[ci];
    const g::Constructor *ct = c.ct;
    for (int k = 0; k < ct->getNumOperands(); ++k) {
      const g::OperandSymbol *sym = ct->getOperand(k);
      Operand op;
      op.name = sym->getName();
      op.offset_base = sym->getOffsetBase();
      op.rel_offset = static_cast<int>(sym->getRelativeOffset());
      op.min_length = sym->getMinimumLength();
      g::TripleSymbol *ts = sym->getDefiningSymbol();
      if (ts == nullptr) {
        op.kind = Operand::Value;
        op.expr = expr(sym->getDefiningExpression());
      } else {
        switch (ts->getType()) {
          case g::SleighSymbol::subtable_symbol:
            op.kind = Operand::Subtable;
            op.nt = nt_of_.at(static_cast<g::SubtableSymbol *>(ts));
            break;
          case g::SleighSymbol::varnodelist_symbol:
            op.kind = Operand::Registers;
            op.expr = expr(ts->getPatternExpression());
            break;
          case g::SleighSymbol::name_symbol:
            op.kind = Operand::Names;
            op.expr = expr(ts->getPatternExpression());
            break;
          case g::SleighSymbol::valuemap_symbol:
            op.kind = Operand::Values;
            op.expr = expr(ts->getPatternExpression());
            break;
          case g::SleighSymbol::varnode_symbol:
            op.kind = Operand::Fixed;
            break;
          default:
            try {
              op.kind = Operand::Value;
              op.expr = expr(ts->getPatternExpression());
            } catch (const g::SleighError &) {
              op.kind = Operand::Other;
            }
            break;
        }
      }
      c.ops.push_back(std::move(op));
    }
    for (const g::ContextChange *cc : ct->getContextChanges()) {
      if (auto *o = dynamic_cast<const g::ContextOp *>(cc)) {
        ContextOp x{expr(o->getPatternExpression()), o->getWordIndex(), static_cast<std::uint32_t>(o->getMask()),
                    o->getShift()};
        c.ctx_ops.push_back(x);
        for (int b = 0; b < 4; ++b) {
          const auto m = static_cast<std::uint8_t>(x.mask >> (24 - 8 * b));
          if (m) c.writes.set_bits(4 * x.word + b, m, 0);
        }
      }
      // ContextCommit (globalset) only reaches later addresses.
    }
  }

  int terminal(Terminal t) {
    auto it = term_of_.find(t.key);
    if (it != term_of_.end()) return it->second;
    g_.terminals.push_back(std::move(t));
    const int id = static_cast<int>(g_.terminals.size() - 1);
    term_of_[g_.terminals.back().key] = id;
    return id;
  }

  int literal(const std::string &text) {
    Terminal t;
    t.kind = Terminal::Literal;
    t.text = lower(text);
    t.key = "L" + t.text;
    return terminal(std::move(t));
  }

  int space() {
    Terminal t;
    t.kind = Terminal::Space;
    t.key = "_";
    return terminal(std::move(t));
  }

  // The terminal for a printed non-subtable operand.
  int operand_terminal(int ci, int k) {
    const Constructor &c = g_.cons[ci];
    const Operand &op = c.ops[k];
    const g::TripleSymbol *ts = c.ct->getOperand(k)->getDefiningSymbol();
    Terminal t;
    switch (op.kind) {
      case Operand::Registers: {
        t.kind = Terminal::Names;
        std::map<std::string, std::vector<int>> names;
        const auto &table = static_cast<const g::VarnodeListSymbol *>(ts)->getVarnodeTable();
        for (std::size_t i = 0; i < table.size(); ++i)
          if (table[i] != nullptr) names[lower(table[i]->getName())].push_back(static_cast<int>(i));
        t.names.assign(names.begin(), names.end());
        t.key = "R" + ts->getName();
        break;
      }
      case Operand::Names: {
        t.kind = Terminal::Names;
        std::map<std::string, std::vector<int>> names;
        const auto &table = static_cast<const g::NameSymbol *>(ts)->getNameTable();
        for (std::size_t i = 0; i < table.size(); ++i)
          if (table[i] != "_" && table[i] != "\t") names[lower(table[i])].push_back(static_cast<int>(i));
        t.names.assign(names.begin(), names.end());
        t.key = "N" + ts->getName();
        break;
      }
      case Operand::Values: {
        t.kind = Terminal::Values;
        const auto &table = static_cast<const g::ValueMapSymbol *>(ts)->getMap();
        for (std::size_t i = 0; i < table.size(); ++i)
          if (table[i] != static_cast<g::intb>(0xBADBEEF)) t.values[table[i]].push_back(static_cast<int>(i));
        t.key = "V" + ts->getName();
        break;
      }
      case Operand::Fixed:
        t.kind = Terminal::Register;
        t.text = lower(ts->getName());
        t.key = "F" + t.text;
        break;
      default: {
        t.kind = Terminal::Number;
        // The printed size: a constructor exporting this operand with a
        // size or into a space (Ghidra's getHandleTpl).
        const g::ConstructTpl *tpl = c.ct->getTempl();
        const g::HandleTpl *h = tpl != nullptr ? tpl->getResult() : nullptr;
        if (h != nullptr && h->getPtrOffset().getType() == g::ConstTpl::handle &&
            h->getPtrOffset().getHandleIndex() == k && h->getSpace().getType() == g::ConstTpl::spaceid) {
          const g::AddrSpace *sp = h->getSpace().getSpace();
          if (sp->getType() == g::IPTR_CONSTANT) {
            if (h->getSize().getType() == g::ConstTpl::real) t.bits = static_cast<int>(h->getSize().getReal() * 8);
          } else {
            t.bits = sp->getAddrSize() * 8;
            t.address = true;
            if (sp != sleigh_.getDefaultCodeSpace()) {
              // Its registers print by name.
              std::map<g::VarnodeData, std::string> regs;
              sleigh_.getAllRegisters(regs);
              for (const auto &[vn, name] : regs)
                if (vn.space == sp)
                  t.named.emplace_back(lower(name), static_cast<std::int64_t>(vn.offset / std::max<g::uint4>(1u, sp->getWordSize())));
              std::sort(t.named.begin(), t.named.end(),
                        [](const auto &a, const auto &b) { return a.first.size() > b.first.size(); });
              t.key = "#" + std::to_string(t.bits) + "a" + sp->getName();
            }
          }
        }
        if (t.key.empty()) t.key = "#" + std::to_string(t.bits) + (t.address ? "a" : "");
        break;
      }
    }
    // Longest names first, so the matcher prefers them.
    std::stable_sort(t.names.begin(), t.names.end(),
                     [](const auto &a, const auto &b) { return a.first.size() > b.first.size(); });
    return terminal(std::move(t));
  }

  // Ghidra's AssemblySentential.addSeparators, with punctuation split into
  // single characters so optional whitespace may sit between any of them.
  void separators(const std::string &s, std::vector<Sym> &rhs) {
    auto add_space = [&] {
      if (!rhs.empty() && !rhs.back().nt && g_.terminals[rhs.back().id].kind == Terminal::Space) return;
      rhs.push_back({false, space()});
    };
    std::string word;
    auto flush = [&] {
      if (!word.empty()) rhs.push_back({false, literal(word)});
      word.clear();
    };
    for (char ch : s) {
      if (std::isspace(static_cast<unsigned char>(ch))) {
        flush();
        add_space();
      } else if (word_char(ch)) {
        word += ch;
      } else {
        flush();
        add_space();
        rhs.push_back({false, literal(std::string(1, ch))});
        add_space();
      }
    }
    flush();
  }

  void add_production(int ci) {
    const Constructor &c = g_.cons[ci];
    Production p;
    p.lhs = c.nt;
    std::vector<int> indices;
    for (const std::string &piece : c.ct->getPrintPieces()) {
      if (piece.empty()) continue;
      if (piece[0] == '\n' && piece.size() >= 2) {
        const int k = piece[1] - 'A';
        if (k < 0 || k >= static_cast<int>(c.ops.size())) throw std::runtime_error("bad print piece");
        const Operand &op = c.ops[k];
        if (op.kind == Operand::Subtable) {
          p.rhs.push_back({true, op.nt});
          indices.push_back(k);
        } else if (op.kind == Operand::Other) {
          return;  // can't be assembled
        } else {
          p.rhs.push_back({false, operand_terminal(ci, k)});
          indices.push_back(k);
        }
      } else {
        separators(piece, p.rhs);
      }
    }
    p.pure_recursion = p.rhs.size() == 1 && p.rhs[0].nt && p.rhs[0].id == p.lhs;
    if (p.pure_recursion && c.nt == g_.start) {
      g_.recursive_cons.push_back(ci);
      g_.recursion_writes.merge(c.writes);
    }
    // Same layout as an existing production: another semantic of it.
    std::string key = std::to_string(p.lhs) + ":";
    for (const Sym &s : p.rhs) key += (s.nt ? "n" : "t") + std::to_string(s.id) + ",";
    auto it = prod_of_.find(key);
    if (it != prod_of_.end()) {
      Production &q = g_.productions[it->second];
      q.cons.push_back(ci);
      q.operand_index.push_back(std::move(indices));
      return;
    }
    p.cons.push_back(ci);
    p.operand_index.push_back(std::move(indices));
    g_.productions.push_back(std::move(p));
    const int id = static_cast<int>(g_.productions.size() - 1);
    prod_of_[key] = id;
    g_.nt_productions[c.nt].push_back(id);
  }

  void nullable() {
    g_.nt_nullable.assign(g_.nt_names.size(), false);
    auto term_nullable = [&](int t) {
      const Terminal &x = g_.terminals[t];
      if (x.kind == Terminal::Space) return true;
      if (x.kind == Terminal::Names)
        for (const auto &[n, _] : x.names)
          if (n.empty()) return true;
      return false;
    };
    for (bool changed = true; changed;) {
      changed = false;
      for (const Production &p : g_.productions) {
        if (g_.nt_nullable[p.lhs] || p.pure_recursion) continue;
        bool all = true;
        for (const Sym &s : p.rhs) all = all && (s.nt ? g_.nt_nullable[s.id] : term_nullable(s.id));
        if (all) {
          g_.nt_nullable[p.lhs] = true;
          changed = true;
        }
      }
    }
  }

  const lift::SleighDecoder &dec_;
  Grammar &g_;
  const g::SleighBase &sleigh_;
  std::vector<g::SubtableSymbol *> tables_;
  std::map<const g::SubtableSymbol *, int> nt_of_;
  std::unordered_map<std::string, int> term_of_;
  std::unordered_map<std::string, int> prod_of_;
};

}  // namespace

std::shared_ptr<const Grammar> build_grammar(const lift::SleighDecoder &decoder) {
  auto g = std::make_shared<Grammar>();
  Builder(decoder, *g).build();
  return g;
}

}  // namespace revkit::assembler::detail
