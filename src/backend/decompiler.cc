#include "decompiler.h"

#include "revkit/decompd/batch.h"
#include "revkit/decompd/param_id.h"
#include "revkit/decompd/lift_mode.h"
#include "revkit/decompd/runner.h"
#include "revkit/infer/accesses.h"
#include "revkit/lift/image_arch.hh"

#include "dynamic.hh"
#include "funcdata.hh"
#include "marshal.hh"
#include "printc.hh"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <exception>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>
#include <thread>
#include <utility>

namespace revkit::backend {
namespace {

std::string Hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

// The varnode's high-level variable, or null: annotation varnodes (and a
// few others the printer still names) have none, and getHigh() throws.
ghidra::HighVariable *HighOf(const ghidra::Varnode *vn) {
  if (vn == nullptr || vn->isAnnotation()) return nullptr;
  try {
    return vn->getHigh();
  } catch (const ghidra::LowlevelError &) {
    return nullptr;
  }
}

// A token as the printer emitted it, still holding decompiler pointers. They
// are resolved into table indexes once printing is done and before the
// function's analysis is cleared.
struct RawToken {
  pb::CodeTokenKind kind = pb::CODE_TOKEN_KIND_UNSPECIFIED;
  std::string text;
  const ghidra::Varnode *vn = nullptr;
  const ghidra::PcodeOp *op = nullptr;          // the op it was printed from (slices)
  const ghidra::Symbol *symbol = nullptr;       // the variable, for variable tokens
  const ghidra::HighVariable *high = nullptr;   // when the variable has no symbol
  bool variable = false;
  std::optional<std::uint64_t> address, target, value;
  bool prototype = false;
  const ghidra::Symbol *declaration = nullptr;  // declaration this token belongs to
  // FIELD tokens: the struct or union's type id (the decompiler's, which
  // GhidraTypes derives from revkit's hash) and the field's byte offset.
  // TYPE tokens: the struct or union named (parent_id only).
  std::optional<std::uint64_t> parent_id, field_offset;
  // CONSTANT tokens: shown as an EquateSymbol says (an equate or a
  // conversion the user set).
  bool display_set = false;
};

struct RawLine {
  std::uint32_t indent = 0;
  std::vector<RawToken> tokens;
};

// Receives the C printer's output as tagged tokens instead of text. It does
// no line breaking (Ghidra's EmitPrettyPrint would wrap at 100 columns);
// lines end where the printer starts a new statement or declaration.
class TokenEmitter : public ghidra::Emit {
 public:
  std::vector<RawLine> lines;

  void Reset() {
    lines.clear();
    prototype_depth_ = 0;
    declarations_.clear();
    comment_depth_ = 0;
    comment_open_ = false;
    clear();
  }

  int beginDocument() override { return 0; }
  void endDocument(int) override {}
  int beginFunction(const ghidra::Funcdata *) override { return 0; }
  void endFunction(int) override {}
  int beginBlock(const ghidra::FlowBlock *) override { return 0; }
  void endBlock(int) override {}
  void tagLine() override {
    emitPending();
    lines.push_back({static_cast<std::uint32_t>(std::max(0, indentlevel) / std::max(1, indentincrement)), {}});
    comment_open_ = false;
  }
  // Comment lines ask for a column; keep them at the code's nesting.
  void tagLine(int) override { tagLine(); }
  int beginReturnType(const ghidra::Varnode *) override { return 0; }
  void endReturnType(int) override {}
  int beginVarDecl(const ghidra::Symbol *sym) override {
    declarations_.push_back(sym);
    return 0;
  }
  void endVarDecl(int) override {
    if (!declarations_.empty()) declarations_.pop_back();
  }
  int beginStatement(const ghidra::PcodeOp *) override { return 0; }
  void endStatement(int) override {}
  int beginFuncProto() override {
    ++prototype_depth_;
    return 0;
  }
  void endFuncProto(int) override { --prototype_depth_; }

  void tagVariable(const std::string &name, syntax_highlight hl, const ghidra::Varnode *vn,
                   const ghidra::PcodeOp *op) override {
    RawToken &t = Add(KindFor(hl, name), name);
    t.vn = vn;
    SetOpAddress(t, op);
    if (!t.address && vn != nullptr && vn->getDef() != nullptr) t.address = vn->getDef()->getAddr().getOffset();
    if (hl == const_color) {
      if (vn != nullptr && vn->isConstant()) {
        t.value = vn->getOffset();
        if (ghidra::HighVariable *high = HighOf(vn))
          if (const ghidra::Symbol *sym = high->getSymbol(); sym != nullptr && sym->getCategory() == ghidra::Symbol::equate)
            t.display_set = true;
      }
      return;
    }
    t.variable = true;
    if (ghidra::HighVariable *high = HighOf(vn)) {
      t.symbol = high->getSymbol();
      if (t.symbol == nullptr) t.high = high;
    } else if (!declarations_.empty()) {
      t.symbol = declarations_.back();
    }
  }
  void tagOp(const std::string &name, syntax_highlight hl, const ghidra::PcodeOp *op) override {
    RawToken &t = Add(hl == keyword_color ? pb::CODE_TOKEN_KIND_KEYWORD : pb::CODE_TOKEN_KIND_OPERATOR, name);
    SetOpAddress(t, op);
  }
  void tagFuncName(const std::string &name, syntax_highlight, const ghidra::Funcdata *fd,
                   const ghidra::PcodeOp *op) override {
    RawToken &t = Add(pb::CODE_TOKEN_KIND_FUNCTION_NAME, name);
    SetOpAddress(t, op);
    if (fd != nullptr) {
      t.target = fd->getAddress().getOffset();
      if (!t.address && prototype_depth_ > 0) t.address = t.target;
    } else if (op != nullptr && op->numInput() > 0) {
      // Direct calls name their callee through a call-spec reference.
      const ghidra::Varnode *callpoint = op->getIn(0);
      if (callpoint->getSpace()->getType() == ghidra::IPTR_FSPEC) {
        const ghidra::FuncCallSpecs *fc = ghidra::FuncCallSpecs::getFspecFromConst(callpoint->getAddr());
        if (fc != nullptr && !fc->getEntryAddress().isInvalid()) t.target = fc->getEntryAddress().getOffset();
      } else if (callpoint->getSpace()->getType() == ghidra::IPTR_PROCESSOR) {
        t.target = callpoint->getOffset();
      }
    }
  }
  void tagType(const std::string &name, syntax_highlight, const ghidra::Datatype *ct) override {
    RawToken &t = Add(pb::CODE_TOKEN_KIND_TYPE, name);
    // A struct or union named (a typedef of one too): its id, which the
    // program's types name back (CodeToken.type_hash; feature "type-uses").
    for (int i = 0; i < 16 && ct != nullptr && ct->getTypedef() != nullptr; ++i) ct = ct->getTypedef();
    if (ct != nullptr && (ct->getMetatype() == ghidra::TYPE_STRUCT || ct->getMetatype() == ghidra::TYPE_UNION))
      t.parent_id = ct->getUnsizedId();
  }
  void tagField(const std::string &name, syntax_highlight, const ghidra::Datatype *ct, int ident,
                const ghidra::PcodeOp *op) override {
    RawToken &t = Add(pb::CODE_TOKEN_KIND_FIELD, name);
    SetOpAddress(t, op);
    SetField(t, ct, ident);
  }
  void tagBitField(const std::string &name, syntax_highlight, const ghidra::Datatype *, int,
                   const ghidra::PcodeOp *op) override {
    SetOpAddress(Add(pb::CODE_TOKEN_KIND_FIELD, name), op);
  }
  void tagComment(const std::string &name, syntax_highlight, const ghidra::AddrSpace *, ghidra::uintb off) override {
    RawToken &t = Add(pb::CODE_TOKEN_KIND_COMMENT, name);
    t.address = off;
  }
  void tagLabel(const std::string &name, syntax_highlight, const ghidra::AddrSpace *, ghidra::uintb off) override {
    RawToken &t = Add(pb::CODE_TOKEN_KIND_LABEL, name);
    t.address = off;
    t.target = off;
  }
  void tagCaseLabel(const std::string &name, syntax_highlight, const ghidra::PcodeOp *op, ghidra::uintb value) override {
    RawToken &t = Add(pb::CODE_TOKEN_KIND_CONSTANT, name);
    SetOpAddress(t, op);
    t.value = value;
  }
  void print(const std::string &data, syntax_highlight hl = no_color) override { Add(KindFor(hl, data), data); }
  int openParen(const std::string &paren, int id = 0) override {
    Add(pb::CODE_TOKEN_KIND_PUNCTUATION, paren);
    ++parenlevel;
    return id;
  }
  void closeParen(const std::string &paren, int) override {
    Add(pb::CODE_TOKEN_KIND_PUNCTUATION, paren);
    --parenlevel;
  }
  int startComment() override {
    ++comment_depth_;
    comment_open_ = false;
    return 0;
  }
  void stopComment(int) override {
    --comment_depth_;
    comment_open_ = false;
  }
  void setOutputStream(std::ostream *s) override { stream_ = s; }
  std::ostream *getOutputStream() const override { return stream_; }
  bool emitsMarkup() const override { return false; }

 private:
  static pb::CodeTokenKind KindFor(syntax_highlight hl, const std::string &text) {
    switch (hl) {
      case keyword_color: return pb::CODE_TOKEN_KIND_KEYWORD;
      case comment_color: return pb::CODE_TOKEN_KIND_COMMENT;
      case type_color: return pb::CODE_TOKEN_KIND_TYPE;
      case funcname_color: return pb::CODE_TOKEN_KIND_FUNCTION_NAME;
      case var_color: return pb::CODE_TOKEN_KIND_LOCAL_VARIABLE;
      case param_color: return pb::CODE_TOKEN_KIND_PARAMETER;
      case global_color: return pb::CODE_TOKEN_KIND_GLOBAL_VARIABLE;
      case error_color: return pb::CODE_TOKEN_KIND_ERROR;
      case const_color:
        return !text.empty() && (text[0] == '"' || text.starts_with("L\"") || text.starts_with("u\"") ||
                                 text.starts_with("U\"") || text.starts_with("u8\""))
                   ? pb::CODE_TOKEN_KIND_STRING
                   : pb::CODE_TOKEN_KIND_CONSTANT;
      default:
        return std::all_of(text.begin(), text.end(), [](char c) { return c == ' '; }) ? pb::CODE_TOKEN_KIND_WHITESPACE
                                                                                      : pb::CODE_TOKEN_KIND_PUNCTUATION;
    }
  }

  static void SetOpAddress(RawToken &t, const ghidra::PcodeOp *op) {
    if (op != nullptr) {
      t.address = op->getAddr().getOffset();
      t.op = op;
    }
  }

  // The field's parent and offset. The printer names a struct's field by
  // its ident (the offset, unless the type says otherwise) or, for a gap no
  // field covers (`field_0x10`), by the offset itself; a union's by its
  // ordinal, at offset 0.
  static void SetField(RawToken &t, const ghidra::Datatype *ct, int ident) {
    if (ct == nullptr) return;
    // A typedef of a struct is a copy of it under the typedef's id: the
    // struct is what it names.
    for (int i = 0; i < 16 && ct->getTypedef() != nullptr; ++i) ct = ct->getTypedef();
    if (ct->getMetatype() == ghidra::TYPE_STRUCT) {
      const auto *st = static_cast<const ghidra::TypeStruct *>(ct);
      std::optional<std::uint64_t> off;
      for (auto it = st->beginField(); it != st->endField(); ++it)
        if (it->ident == ident) off = static_cast<std::uint64_t>(it->offset);
      if (!off && ident >= 0) off = static_cast<std::uint64_t>(ident);
      if (!off) return;
      t.field_offset = off;
    } else if (ct->getMetatype() == ghidra::TYPE_UNION) {
      t.field_offset = 0;
    } else {
      return;
    }
    t.parent_id = ct->getUnsizedId();
  }

  RawToken &Add(pb::CodeTokenKind kind, const std::string &text) {
    if (lines.empty()) lines.push_back({0, {}});
    RawLine &line = lines.back();
    // Everything between startComment and stopComment is one COMMENT token
    // per line, delimiters and spacing included.
    if (comment_depth_ > 0) {
      if (comment_open_ && !line.tokens.empty()) {
        RawToken &last = line.tokens.back();
        last.text += text;
        return last;
      }
      kind = pb::CODE_TOKEN_KIND_COMMENT;
      comment_open_ = true;
    }
    RawToken &t = line.tokens.emplace_back();
    t.kind = kind;
    t.text = text;
    t.prototype = prototype_depth_ > 0;
    if (!declarations_.empty()) t.declaration = declarations_.back();
    return t;
  }

  int prototype_depth_ = 0;
  std::vector<const ghidra::Symbol *> declarations_;
  int comment_depth_ = 0;
  bool comment_open_ = false;
  std::ostream *stream_ = nullptr;
};

// The stock C printer with its emitter replaced by a TokenEmitter.
class CapturePrintC : public ghidra::PrintC {
 public:
  explicit CapturePrintC(ghidra::Architecture *arch) : ghidra::PrintC(arch, "c-language") {
    delete emit;  // PrintLanguage owns `emit` and deletes it in its destructor
    tokens_ = new TokenEmitter();
    emit = tokens_;
  }
  TokenEmitter &tokens() { return *tokens_; }

 private:
  TokenEmitter *tokens_;
};

std::string TypeName(const ghidra::Datatype *t) {
  if (t == nullptr) return "undefined";
  std::ostringstream s;
  t->printRaw(s);
  return s.str();
}

std::int64_t SignedOffset(const ghidra::Address &a) {
  const int bits = a.getSpace()->getAddrSize() * 8;
  std::uint64_t v = a.getOffset();
  if (bits < 64 && ((v >> (bits - 1)) & 1)) v |= ~std::uint64_t{0} << bits;
  return static_cast<std::int64_t>(v);
}

std::string SignedHex(std::int64_t v) { return v < 0 ? "-" + Hex(0 - static_cast<std::uint64_t>(v)) : Hex(static_cast<std::uint64_t>(v)); }

// Storage location as text: "stack:-0x14", "register:EAX@0x40104b".
std::string StorageText(const ghidra::Architecture &arch, const ghidra::Address &addr, int size,
                        std::optional<std::uint64_t> pc) {
  const ghidra::AddrSpace *spc = addr.getSpace();
  std::string s;
  if (spc->getType() == ghidra::IPTR_SPACEBASE) {
    s = spc->getName() + ":" + SignedHex(SignedOffset(addr));
  } else {
    std::string reg = arch.translate->getRegisterName(addr.getSpace(), addr.getOffset(), size);
    s = spc->getName() + ":" + (reg.empty() ? Hex(addr.getOffset()) : reg);
  }
  if (pc) s += "@" + Hex(*pc);
  return s;
}

void SetVarnode(const ghidra::Architecture &arch, const ghidra::Address &addr, int size, pb::Varnode *out) {
  out->set_space(addr.getSpace()->getName());
  out->set_offset(addr.getOffset());
  out->set_size(static_cast<std::uint32_t>(size));
  if (addr.getSpace()->getType() == ghidra::IPTR_PROCESSOR && addr.getSpace() != arch.getDefaultCodeSpace() &&
      addr.getSpace() != arch.getDefaultDataSpace())
    out->set_register_name(arch.translate->getExactRegisterName(addr.getSpace(), addr.getOffset(), size));
}

// Turns the emitter's raw tokens into a DecompiledFunction with variable and
// varnode tables. Runs while the function's analysis is still alive.
class Converter {
 public:
  Converter(const ghidra::Architecture &arch, const ghidra::Funcdata &fd, DecompileOutput &out)
      : arch_(arch), fd_(fd), out_(out), f_(out.function) {}

  void Run(const std::vector<RawLine> &lines) {
    const ghidra::FuncProto &proto = fd_.getFuncProto();
    // Parameters first, in order, whether or not the body uses them.
    for (int i = 0; i < proto.numParams(); ++i) {
      ghidra::ProtoParameter *param = proto.getParam(i);
      if (const ghidra::Symbol *sym = param->getSymbol()) {
        std::uint32_t index = VariableFor(sym, nullptr, nullptr, {});
        f_.mutable_prototype()->add_parameter_indices(index);
        f_.mutable_variables(static_cast<int>(index))->set_parameter_index(static_cast<std::uint32_t>(i));
      }
    }

    bool started = false;
    for (const RawLine &raw : lines) {
      // Drop the blank line the printer opens with.
      if (!started && raw.tokens.empty()) continue;
      started = true;
      auto *line = f_.add_lines();
      line->set_indent(raw.indent);
      std::optional<std::uint64_t> lowest;
      for (const RawToken &rt : raw.tokens) {
        if (rt.text.empty()) continue;
        DecompileOutput::TokenRef ref{f_.lines_size() - 1, line->tokens_size()};
        auto *t = line->add_tokens();
        t->set_kind(rt.kind);
        t->set_text(rt.text);
        if (rt.address) {
          t->mutable_address()->set_offset(*rt.address);
          if (!lowest || *rt.address < *lowest) lowest = rt.address;
        }
        if (rt.value) t->set_value(*rt.value);
        if (rt.display_set) t->set_display_set(true);
        if (rt.kind == pb::CODE_TOKEN_KIND_CONSTANT && rt.vn != nullptr && rt.vn->isConstant() && rt.address) {
          // Its dynamic hash, which names it in an OperandDisplay where no
          // operand of the instruction holds it (feature "equates").
          ghidra::DynamicHash dh;
          dh.uniqueHash(rt.vn, const_cast<ghidra::Funcdata *>(&fd_));
          if (dh.getHash() != 0 && dh.getAddress().getOffset() == *rt.address) t->set_constant_hash(dh.getHash());
        }
        if (rt.field_offset) t->set_field_offset(*rt.field_offset);
        if (rt.parent_id) out_.field_parents.emplace_back(ref, *rt.parent_id);
        if (rt.target) {
          t->mutable_target()->set_offset(*rt.target);
          out_.references.push_back(*rt.target);
        }
        if (rt.vn != nullptr) t->add_varnode_indices(VarnodeIndex(rt.vn));
        if (rt.op != nullptr) t->set_op_index(OpIndex(rt.op));
        if (rt.variable && (rt.symbol != nullptr || rt.high != nullptr)) {
          std::uint32_t index = VariableFor(rt.symbol, rt.high, rt.vn, rt.text);
          t->set_variable_index(index);
          const pb::Variable &v = f_.variables(static_cast<int>(index));
          if (v.kind() == pb::VARIABLE_KIND_GLOBAL) {
            t->set_kind(pb::CODE_TOKEN_KIND_GLOBAL_VARIABLE);
            if (v.has_address() && !rt.target) {
              *t->mutable_target() = v.address();
              out_.references.push_back(v.address().offset());
            }
          } else if (t->kind() != pb::CODE_TOKEN_KIND_PARAMETER && t->kind() != pb::CODE_TOKEN_KIND_LOCAL_VARIABLE) {
            t->set_kind(v.kind() == pb::VARIABLE_KIND_PARAMETER ? pb::CODE_TOKEN_KIND_PARAMETER
                                                                 : pb::CODE_TOKEN_KIND_LOCAL_VARIABLE);
          }
        }
        if (rt.prototype) out_.prototype.push_back(ref);
        if (rt.declaration != nullptr && rt.kind == pb::CODE_TOKEN_KIND_TYPE) {
          auto it = variable_index_.find(rt.declaration);
          std::uint32_t index = it != variable_index_.end() ? it->second : VariableFor(rt.declaration, nullptr, nullptr, {});
          out_.declaration_types.emplace_back(ref, index);
        }
      }
      if (lowest) line->mutable_address()->set_offset(*lowest);
    }
    // Trailing blank lines carry nothing.
    while (f_.lines_size() > 0 && f_.lines(f_.lines_size() - 1).tokens().empty()) f_.mutable_lines()->RemoveLast();

    Reorder();
    Accesses();
    Dynamic();
    DataFlow();
  }

 private:
  // A p-code op's index in DataFlow.ops (tokens name theirs first; the
  // graph adds the rest).
  std::uint32_t OpIndex(const ghidra::PcodeOp *op) {
    auto [it, inserted] = op_index_.try_emplace(op, static_cast<std::uint32_t>(ops_.size()));
    if (inserted) ops_.push_back(op);
    return it->second;
  }

  // The function's data-flow graph (DecompiledFunction.dataflow; feature
  // "decompile-slices"): every live op and every varnode they read or
  // write. Nodes below varnodes_size are the varnodes table's; the others
  // follow it. QueryService.SliceDecompiled walks it.
  void DataFlow() {
    for (auto it = fd_.beginOpAlive(); it != fd_.endOpAlive(); ++it) OpIndex(*it);
    const auto mapped = static_cast<std::uint32_t>(f_.varnodes_size());
    std::unordered_map<const ghidra::Varnode *, std::uint32_t> extra;
    std::vector<const ghidra::Varnode *> extra_of;
    auto node = [&](const ghidra::Varnode *vn) -> std::uint32_t {
      if (auto it = varnode_index_.find(vn); it != varnode_index_.end()) return it->second;
      auto [it, inserted] = extra.try_emplace(vn, mapped + static_cast<std::uint32_t>(extra_of.size()));
      if (inserted) extra_of.push_back(vn);
      return it->second;
    };
    pb::DataFlow *df = f_.mutable_dataflow();
    // Ops first (they name the nodes); a node's defining op afterwards.
    for (std::size_t i = 0; i < ops_.size(); ++i) {
      const ghidra::PcodeOp *op = ops_[i];
      pb::DataFlowOp *o = df->add_ops();
      o->mutable_address()->set_offset(op->getAddr().getOffset());
      o->set_opcode(ghidra::get_opname(op->code()));
      if (const ghidra::Varnode *out = op->getOut()) o->set_output(node(out));
      for (int k = 0; k < op->numInput(); ++k)
        if (const ghidra::Varnode *in = op->getIn(k); in != nullptr && !in->isAnnotation()) o->add_inputs(node(in));
    }
    const std::uint32_t total = mapped + static_cast<std::uint32_t>(extra_of.size());
    for (std::uint32_t n = 0; n < total; ++n) {
      const ghidra::Varnode *vn = n < mapped ? varnode_of_[n] : extra_of[n - mapped];
      pb::DataFlowNode *d = df->add_nodes();
      if (const ghidra::PcodeOp *def = vn->getDef(); def != nullptr)
        if (auto it = op_index_.find(def); it != op_index_.end()) d->set_def(it->second);
      if (vn->isConstant()) d->set_constant(true);
      if (n >= mapped) SetVarnode(arch_, vn->getAddr(), vn->getSize(), d->mutable_varnode());
    }
  }

  std::unordered_map<const ghidra::PcodeOp *, std::uint32_t> op_index_;
  std::vector<const ghidra::PcodeOp *> ops_;

  std::uint32_t VarnodeIndex(const ghidra::Varnode *vn) {
    auto [it, inserted] = varnode_index_.try_emplace(vn, static_cast<std::uint32_t>(f_.varnodes_size()));
    if (inserted) {
      auto *m = f_.add_varnodes();
      SetVarnode(arch_, vn->getAddr(), vn->getSize(), m->mutable_varnode());
      if (vn->getDef() != nullptr) m->mutable_defined_at()->set_offset(vn->getDef()->getAddr().getOffset());
      varnode_of_.push_back(vn);
    }
    return it->second;
  }

  std::uint32_t VariableFor(const ghidra::Symbol *sym, const ghidra::HighVariable *high, const ghidra::Varnode *vn,
                            const std::string &printed_name) {
    const void *key = sym != nullptr ? static_cast<const void *>(sym) : static_cast<const void *>(high);
    auto [it, inserted] = variable_index_.try_emplace(key, static_cast<std::uint32_t>(f_.variables_size()));
    if (!inserted) return it->second;

    auto *v = f_.add_variables();
    v->set_index(it->second);
    const ghidra::SymbolEntry *entry = sym != nullptr ? sym->getFirstWholeMap() : nullptr;
    const bool global = sym != nullptr ? sym->getScope()->isGlobal()
                                       : vn != nullptr && vn->isPersist();
    if (global) v->set_kind(pb::VARIABLE_KIND_GLOBAL);
    else if (sym != nullptr && sym->getCategory() == ghidra::Symbol::function_parameter) v->set_kind(pb::VARIABLE_KIND_PARAMETER);
    else v->set_kind(pb::VARIABLE_KIND_LOCAL);

    if (sym != nullptr) {
      v->set_name(sym->getDisplayName());
      v->mutable_type()->set_display(TypeName(sym->getType()));
    } else {
      v->set_name(printed_name);
      v->mutable_type()->set_display(TypeName(high->getType()));
    }

    // Storage: the symbol's mapping, or for dynamic (hash-mapped) symbols
    // and symbol-less highs, the varnode that names the variable.
    ghidra::Address addr;
    int size = 0;
    std::optional<std::uint64_t> pc;
    auto use_point = [&](const ghidra::Address &a) {
      if (!a.isInvalid()) pc = a.getOffset();
    };
    if (entry != nullptr && !entry->isDynamic()) {
      addr = entry->getAddr();
      size = entry->getSize();
      use_point(entry->getFirstUseAddress());
    } else {
      const ghidra::HighVariable *h = high;
      if (h == nullptr) h = HighOf(vn);
      // A symbol mapped by hash (a temporary's committed type), named
      // without a varnode (its declaration): the variable it names.
      if (h == nullptr && sym != nullptr && entry != nullptr && entry->isDynamic())
        for (auto it = fd_.beginLoc(); it != fd_.endLoc() && h == nullptr; ++it)
          if (const ghidra::HighVariable *x = HighOf(*it); x != nullptr && x->getSymbol() == sym) h = x;
      const ghidra::Varnode *rep = h != nullptr ? h->getNameRepresentative() : nullptr;
      if (rep != nullptr) {
        addr = rep->getAddr();
        size = rep->getSize();
        if (rep->getDef() != nullptr) use_point(rep->getDef()->getAddr());
        else if (entry != nullptr) use_point(entry->getFirstUseAddress());
      }
    }
    if (!addr.isInvalid()) SetVarnode(arch_, addr, size, v->add_storage());

    std::string key_text;
    if (v->kind() == pb::VARIABLE_KIND_PARAMETER) key_text = "param:" + std::to_string(sym->getCategoryIndex());
    else if (global && !addr.isInvalid()) key_text = "global:" + Hex(addr.getOffset());
    else if (!addr.isInvalid()) key_text = StorageText(arch_, addr, size, pc);
    else key_text = "name:" + v->name();
    // Keys must identify one variable; disambiguate the rare collision.
    std::string unique = key_text;
    for (int n = 2; !storage_keys_.insert(unique).second; ++n) unique = key_text + "#" + std::to_string(n);
    v->set_storage_key(unique);
    if (global && !addr.isInvalid()) v->mutable_address()->set_offset(addr.getOffset());
    return it->second;
  }

  // Parameters (in order), then locals, then globals, each by first use.
  void Reorder() {
    const int n = f_.variables_size();
    std::vector<int> order(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) order[static_cast<std::size_t>(i)] = i;
    auto rank = [&](int i) {
      const pb::Variable &v = f_.variables(i);
      switch (v.kind()) {
        case pb::VARIABLE_KIND_PARAMETER: return 0;
        case pb::VARIABLE_KIND_LOCAL: return 1;
        default: return 2;
      }
    };
    std::stable_sort(order.begin(), order.end(), [&](int a, int b) {
      if (rank(a) != rank(b)) return rank(a) < rank(b);
      const pb::Variable &va = f_.variables(a), &vb = f_.variables(b);
      if (rank(a) == 0) return va.parameter_index() < vb.parameter_index();
      return a < b;
    });
    std::vector<std::uint32_t> new_index(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) new_index[static_cast<std::size_t>(order[static_cast<std::size_t>(i)])] = static_cast<std::uint32_t>(i);

    google::protobuf::RepeatedPtrField<pb::Variable> vars;
    for (int i : order) {
      pb::Variable v = f_.variables(i);
      v.set_index(new_index[static_cast<std::size_t>(i)]);
      *vars.Add() = std::move(v);
    }
    f_.mutable_variables()->Swap(&vars);
    for (auto &line : *f_.mutable_lines())
      for (auto &t : *line.mutable_tokens())
        if (t.has_variable_index()) t.set_variable_index(new_index[t.variable_index()]);
    for (auto &idx : *f_.mutable_prototype()->mutable_parameter_indices()) idx = new_index[idx];
    for (auto &[ref, idx] : out_.declaration_types) idx = new_index[idx];
    for (auto &[key, idx] : variable_index_) idx = new_index[idx];

    // Varnodes point at the variable their high belongs to, when listed.
    for (int i = 0; i < f_.varnodes_size(); ++i) {
      const ghidra::Varnode *vn = varnode_of_[static_cast<std::size_t>(i)];
      const ghidra::HighVariable *h = HighOf(vn);
      if (h == nullptr) continue;
      const ghidra::Symbol *sym = h->getSymbol();
      auto it = variable_index_.find(sym != nullptr ? static_cast<const void *>(sym) : static_cast<const void *>(h));
      if (it != variable_index_.end()) f_.mutable_varnodes(i)->set_variable_index(it->second);
    }
  }

  // What each pointer-sized parameter or local is used for, by storage key
  // (infer::pointer_accesses): what auto-created structures are made of.
  void Accesses() {
    const int pointer = arch_.types->getSizeOfPointer();
    std::map<std::string, std::vector<infer::PointerAccess>> by_key;
    std::set<const ghidra::HighVariable *> seen;
    for (auto it = fd_.beginLoc(); it != fd_.endLoc(); ++it) {
      const ghidra::HighVariable *h = HighOf(*it);
      if (h == nullptr || h->numInstances() == 0 || h->getInstance(0)->getSize() != pointer || !seen.insert(h).second) continue;
      const ghidra::Symbol *sym = h->getSymbol();
      auto vi = variable_index_.find(sym != nullptr ? static_cast<const void *>(sym) : static_cast<const void *>(h));
      if (vi == variable_index_.end()) continue;
      const pb::Variable &var = f_.variables(static_cast<int>(vi->second));
      if (var.kind() == pb::VARIABLE_KIND_GLOBAL) continue;
      std::vector<infer::PointerAccess> found;
      std::vector<infer::LoadedValue> loads;
      try {
        found = infer::pointer_accesses(fd_, *h, &loads);
      } catch (const ghidra::LowlevelError &) {
        continue;
      }
      if (found.empty()) continue;
      auto &list = by_key[var.storage_key()];
      list.insert(list.end(), found.begin(), found.end());
      Chained(var.storage_key(), loads, pointer, 1, by_key);
    }
    for (auto &[key, list] : by_key) out_.accesses.emplace_back(key, std::move(list));
  }

  // The accesses through pointer-sized values loaded through a pointer, by
  // path key ("param:0->0x20", "param:0->0x20->0x8"; at most 3 levels):
  // what a structure's field points to, for chained auto-created structures.
  void Chained(const std::string &key, const std::vector<infer::LoadedValue> &loads, int pointer, int level,
               std::map<std::string, std::vector<infer::PointerAccess>> &by_key) {
    if (level > 3 || by_key.size() > 4096) return;
    std::map<std::int64_t, std::vector<const ghidra::Varnode *>> by_offset;
    for (const auto &l : loads)
      if (l.value != nullptr && l.value->getSize() == pointer) by_offset[l.offset].push_back(l.value);
    for (const auto &[off, roots] : by_offset) {
      std::vector<infer::LoadedValue> inner;
      std::vector<infer::PointerAccess> found;
      try {
        found = infer::pointer_accesses(fd_, roots, &inner);
      } catch (const ghidra::LowlevelError &) {
        continue;
      }
      if (found.empty()) continue;
      char buf[24];
      std::snprintf(buf, sizeof buf, "->0x%llx", static_cast<unsigned long long>(off));
      const std::string path = key + buf;
      auto &list = by_key[path];
      list.insert(list.end(), found.begin(), found.end());
      Chained(path, inner, pointer, level + 1, by_key);
    }
  }

  // Each temporary's (unique-space local's) hash: Ghidra's DynamicHash of
  // its representative, what a committed type maps it by (Java's dynamic
  // storage).
  void Dynamic() {
    std::set<const ghidra::HighVariable *> seen;
    for (auto it = fd_.beginLoc(); it != fd_.endLoc(); ++it) {
      const ghidra::HighVariable *h = HighOf(*it);
      if (h == nullptr || h->numInstances() == 0 || !seen.insert(h).second) continue;
      const ghidra::Symbol *sym = h->getSymbol();
      auto vi = variable_index_.find(sym != nullptr ? static_cast<const void *>(sym) : static_cast<const void *>(h));
      if (vi == variable_index_.end()) continue;
      const pb::Variable &var = f_.variables(static_cast<int>(vi->second));
      if (var.kind() != pb::VARIABLE_KIND_LOCAL || !var.storage_key().starts_with("unique:")) continue;
      ghidra::DynamicHash hash;
      try {
        hash.uniqueHash(h->getNameRepresentative(), const_cast<ghidra::Funcdata *>(&fd_));
      } catch (const ghidra::LowlevelError &) {
        continue;
      }
      if (hash.getHash() == 0 || hash.getAddress().isInvalid()) continue;
      out_.dynamic.emplace_back(var.storage_key(), std::pair{hash.getHash(), hash.getAddress().getOffset()});
    }
  }

  const ghidra::Architecture &arch_;
  const ghidra::Funcdata &fd_;
  DecompileOutput &out_;
  pb::DecompiledFunction &f_;
  std::unordered_map<const void *, std::uint32_t> variable_index_;
  std::unordered_map<const ghidra::Varnode *, std::uint32_t> varnode_index_;
  std::vector<const ghidra::Varnode *> varnode_of_;
  std::set<std::string> storage_keys_;
};

}  // namespace

namespace {

const char *OverrideName(int kind) {
  switch (kind) {
    case pb::FLOW_OVERRIDE_KIND_BRANCH: return "BRANCH";
    case pb::FLOW_OVERRIDE_KIND_CALL: return "CALL";
    case pb::FLOW_OVERRIDE_KIND_CALL_RETURN: return "CALL_RETURN";
    case pb::FLOW_OVERRIDE_KIND_RETURN: return "RETURN";
    default: return nullptr;
  }
}

// Where the token session's printer is kept: a base constructed before
// LiftSession, whose constructor builds the printer.
struct PrinterSlot {
  CapturePrintC *printer = nullptr;
};

// The worker side of mode tokens: decompiles with the token printer and
// returns an encoded DecompileOutput (touched left to the parent).
class TokenSession final : private PrinterSlot, public decompd::LiftSession {
 public:
  explicit TokenSession(const decompd::Bundle &b)
      : PrinterSlot(), decompd::LiftSession(b, [slot = static_cast<PrinterSlot *>(this)](ghidra::Architecture *arch) {
          slot->printer = new CapturePrintC(arch);
          return slot->printer;
        }) {}

 protected:
  void prepare(const decompd::Bundle &, lift::RunHooks &hooks) override {
    out_ = DecompileOutput{};
    ghidra::Architecture &arch = decompiler().architecture();
    hooks.print = [this, &arch](ghidra::Funcdata &fd) {
      pb::DecompiledFunction &f = out_.function;
      TokenEmitter &emitter = printer->tokens();
      emitter.Reset();
      try {
        printer->docFunction(&fd);
      } catch (...) {
        emitter.Reset();
        throw;
      }
      f.set_name(fd.getName());
      const ghidra::FuncProto &proto = fd.getFuncProto();
      auto *p = f.mutable_prototype();
      p->mutable_return_type()->set_display(TypeName(proto.getOutputType()));
      p->set_calling_convention(proto.getModelName());
      p->set_varargs(proto.isDotdotdot());
      p->set_no_return(proto.isNoReturn());
      Converter(arch, fd, out_).Run(emitter.lines);
      emitter.Reset();
      std::string decl;
      for (const auto &ref : out_.prototype) decl += f.lines(ref.line).tokens(ref.token).text();
      p->set_c_declaration(decl);
      const ghidra::Address entry = fd.getAddress();
      for (auto it = arch.commentdb->beginComment(entry); it != arch.commentdb->endComment(entry); ++it)
        if ((*it)->getType() & (ghidra::Comment::warning | ghidra::Comment::warningheader))
          f.add_warnings((*it)->getText());
    };
  }

  std::string payload(const decompd::Bundle &b, lift::DecompileResult &r) override {
    DecompileOutput out = std::move(out_);
    out_ = DecompileOutput{};
    out.function.mutable_entry()->set_offset(b.entry);
    if (r.stopped != lift::DecompileStop::none) {
      out = DecompileOutput{};
      out.function.mutable_entry()->set_offset(b.entry);
    } else if (!r.ok) {
      Fail(out.function, r.error);
    }
    if (out.function.name().empty()) {
      // The function's name as the lookup gives it, else Ghidra's default.
      char buf[32];
      std::snprintf(buf, sizeof buf, "FUN_%08llx", static_cast<unsigned long long>(b.entry));
      std::string name = buf;
      if (auto it = b.lift.addresses.find({std::string(), b.entry}); it != b.lift.addresses.end() && it->second.starts >= 0)
        if (const std::string &n = b.lift.functions[static_cast<std::size_t>(it->second.starts)].name; !n.empty()) name = n;
      out.function.set_name(name);
    }
    std::sort(out.references.begin(), out.references.end());
    out.references.erase(std::unique(out.references.begin(), out.references.end()), out.references.end());
    out.milliseconds = r.milliseconds;
    return facts::encode_to_string(out);
  }

 public:
  static void Fail(pb::DecompiledFunction &f, const std::string &message) {
    f.clear_lines();
    f.clear_variables();
    f.clear_varnodes();
    f.clear_prototype();
    f.add_warnings("decompilation failed: " + message);
    auto *line = f.add_lines();
    auto *t = line->add_tokens();
    t->set_kind(pb::CODE_TOKEN_KIND_ERROR);
    t->set_text("/* decompilation failed: " + message + " */");
    t->mutable_address()->set_offset(f.entry().offset());
    line->mutable_address()->set_offset(f.entry().offset());
  }

 private:
  DecompileOutput out_;
};

thread_local const lift::DecompileLimits *t_limits = nullptr;

std::vector<std::pair<std::uint64_t, std::uint64_t>> BodyOf(const DecompileInputs &inputs) {
  std::vector<std::pair<std::uint64_t, std::uint64_t>> body;
  for (const Range &r : inputs.body) body.emplace_back(r.first, r.second);
  if (body.empty()) body.emplace_back(inputs.entry, inputs.entry);
  return body;
}

// The decompiler's patches and synthesized memory as an architecture lays them.
lift::ArchitectureOptions::Patches PatchesOf(const ImageInputs &image) {
  lift::ArchitectureOptions::Patches out(image.patches.begin(), image.patches.end());
  out.insert(out.end(), image.synthesized_memory.begin(), image.synthesized_memory.end());
  return out;
}

// RunLookup as a lift::FactLookup that stops at a failed lookup: a builder
// reading it must not carry on with answers the fact store couldn't give.
class Checked final : public lift::FactLookup {
 public:
  explicit Checked(RunLookup &to) : to_(to) {}
  const lift::FunctionFacts *function_at(std::uint64_t e) override { return check(to_.function_at(e)); }
  std::optional<Body> body_containing(std::uint64_t a) override { return check(to_.body_containing(a)); }
  const lift::DataFacts *data_containing(const std::string &s, std::uint64_t a) override {
    return check(to_.data_containing(s, a));
  }
  const lift::ExternalRefFacts *external_at(const std::string &s, std::uint64_t a) override {
    return check(to_.external_at(s, a));
  }
  const lift::LabelFacts *label_at(const std::string &s, std::uint64_t a) override { return check(to_.label_at(s, a)); }
  std::optional<std::string> code_label_at(const std::string &s, std::uint64_t a) override {
    return check(to_.code_label_at(s, a));
  }
  std::optional<lift::Mutability> block_at(const std::string &s, std::uint64_t a) override {
    return check(to_.block_at(s, a));
  }
  const lift::DecompElement *type(std::uint64_t id) override { return check(to_.type(id)); }
  std::vector<const lift::CommentFacts *> comments(std::uint64_t e) override { return check(to_.comments(e)); }
  std::vector<std::pair<std::uint64_t, std::string>> flow_overrides(std::uint64_t e) override {
    return check(to_.flow_overrides(e));
  }
  std::vector<lift::TrackedFacts> tracked(std::uint64_t e) override { return check(to_.tracked(e)); }

 private:
  template <class T>
  T check(T v) {
    if (to_.failure) std::rethrow_exception(to_.failure);
    return v;
  }
  RunLookup &to_;
};

}  // namespace

void RegisterDecompdModes() {
  decompd::register_mode(
      decompd::Mode::tokens, [](const decompd::Bundle &b) { return std::make_unique<TokenSession>(b); },
      [](std::string_view payload, bool &ok) {
        DecompileOutput out = facts::decode_from_string<DecompileOutput>(payload);
        ok = true;
        std::string text;
        for (const pb::CodeLine &line : out.function.lines()) {
          text.append(2 * line.indent(), ' ');
          for (const pb::CodeToken &t : line.tokens()) {
            text += t.text();
            if (t.kind() == pb::CODE_TOKEN_KIND_ERROR) ok = false;
          }
          text += '\n';
        }
        return text;
      });
}

DecompilerPool::DecompilerPool(Config config)
    : config_(std::move(config)), lifters_(config_.image, config_.language_id) {
  if (config_.max_instances == 0) config_.max_instances = 1;
  workers_ = config_.workers;
  if (!workers_) {
    decompd::PoolOptions o = decompd::default_pool_options();
    o.workers = config_.max_instances;
    workers_ = std::make_shared<decompd::WorkerPool>(o);
  }
  if (workers_->options().in_process) RegisterDecompdModes();
  param_id_stopped_ = config_.param_id_stopped ? config_.param_id_stopped : std::make_shared<std::atomic<bool>>(false);
}

DecompilerPool::Config DecompilerPool::SharedConfig(std::shared_ptr<const loader::Image> image) const {
  Config c = config_;
  c.image = std::move(image);
  c.workers = workers_;
  c.param_id_stopped = param_id_stopped_;
  return c;
}

DecompilerPool::~DecompilerPool() = default;

unsigned DecompilerPool::instances_created() const {
  return static_cast<unsigned>(workers_->stats().spawned);
}

DecompileLimitsScope::DecompileLimitsScope(lift::DecompileLimits limits) : limits_(std::move(limits)), outer_(t_limits) {
  t_limits = &limits_;
}
DecompileLimitsScope::~DecompileLimitsScope() { t_limits = outer_; }
const lift::DecompileLimits *DecompileLimitsScope::current() { return t_limits; }

std::shared_ptr<const decompd::ProgramImage> DecompilerPool::ProgramFor(const ImageInputs &image) {
  std::lock_guard lock(mu_);
  if (!program_ || !program_key_ || !(*program_key_ == image)) {
    program_ = std::make_shared<const decompd::ProgramImage>(config_.image, config_.language_id, PatchesOf(image));
    program_key_ = image;
  }
  return program_;
}

void DecompilerPool::Warm(const ImageInputs &image) {
  auto program = ProgramFor(image);
  // The SLEIGH engine that predicts what a bundle needs (tens of
  // milliseconds to build), beside the worker's architecture.
  std::thread predictor([&] {
    try {
      decompd::LifterPool::Lease l = lifters_.take();
    } catch (const std::exception &) {
    }
  });
  decompd::Bundle b = program->bundle(decompd::Mode::tokens, 0);
  b.lift.default_labels = false;
  b.lift.address_prefix = image.address_prefix;
  workers_->warm(decompd::encode_bundle(b));
  predictor.join();
}

DecompileOutput DecompilerPool::Decompile(const DecompileInputs &inputs, const ImageInputs &image,
                                          RunLookup &lookup) {
  const auto started = std::chrono::steady_clock::now();
  auto program = ProgramFor(image);
  const double program_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
  decompd::Prediction prediction;
  double predicted_ms = 0;
  {
    // The function's decoding context (a Thumb function), as the worker
    // will paint it.
    decompd::LifterPool::Context context;
    if (const lift::FunctionFacts *f = lookup.function_at(inputs.entry)) context = f->context;
    if (lookup.failure) std::rethrow_exception(lookup.failure);
    decompd::LifterPool::Lease lifter = lifters_.take(context);
    const auto t0 = std::chrono::steady_clock::now();
    prediction = decompd::predict(*lifter, *program, inputs.entry, BodyOf(inputs), image.memory,
                                  decompd::tracked_seeds(*lifter, lookup.tracked(inputs.entry)));
    predicted_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
  }
  Checked checked(lookup);
  decompd::LiftBundleBuilder builder(*program, decompd::Mode::tokens, inputs.entry, checked, image.memory,
                                     image.address_prefix);
  builder.set_chunk_hook([&lookup](std::uint64_t i, std::string b) { return lookup.chunk(i, std::move(b)); });
  // revkit::inputs lists the code labels Ghidra would have.
  builder.set_naming(true, false, true);
  // Call-site prototypes from constant printf/scanf formats (revkit's own
  // inputs: docs/types.md#format-strings).
  builder.set_format_strings(true);
  std::vector<std::pair<std::uint64_t, std::string>> overrides;
  for (const auto &[addr, kind] : inputs.flow_overrides)
    if (const char *name = OverrideName(kind)) overrides.emplace_back(addr, name);
  std::vector<lift::CommentFacts> comments;
  for (const auto &c : inputs.comments)
    comments.push_back(
        {c.address, c.kind == pb::COMMENT_KIND_PLATE ? lift::CommentFacts::plate : lift::CommentFacts::pre, c.text});
  builder.set_hooks(inputs.jump_tables, std::move(overrides), std::move(comments));
  builder.set_user_hooks(inputs.equates, inputs.call_targets, inputs.forced_tables);
  if (!inputs.call_signatures.empty()) {
    // Calls' signature overrides, as prototypes (their types the lookup's).
    std::map<std::uint64_t, lift::FunctionFacts> protos;
    for (const auto &[call, hash] : inputs.call_signatures)
      if (std::optional<lift::FunctionFacts> f = lookup.call_prototype(hash)) protos.emplace(call, std::move(*f));
    if (lookup.failure) std::rethrow_exception(lookup.failure);
    builder.set_call_protos(std::move(protos));
  }
  const double pre_add_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
  builder.add(prediction);
  const double built_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();

  const lift::DecompileLimits *scoped = DecompileLimitsScope::current();
  const lift::DecompileLimits &limits = scoped != nullptr ? *scoped : config_.limits;
  decompd::LiftSource source(builder);
  decompd::BundledRun run =
      decompd::run_bundled(*workers_, source, {limits.timeout_seconds, limits.max_varnodes}, inputs.entry, 4,
                           limits.cancelled);
  if (lookup.failure) std::rethrow_exception(lookup.failure);
  if (run.outcome.cancelled) throw DecompileStoppedError(lift::DecompileStop::cancelled, "decompilation cancelled");
  static const bool timing = std::getenv("REVKIT_TIMING") != nullptr;
  if (timing) {
    const double total = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    const double worker = run.outcome.result ? run.outcome.result->milliseconds : 0;
    std::fprintf(stderr,
                 "revkit: decompile 0x%llx %.1f ms: program %.1f, before answers %.1f, bundle %.1f ms (predicted %.1f), worker %.1f ms, round trips %.1f ms; "
                 "%u run(s), %zu bytes\n",
                 static_cast<unsigned long long>(inputs.entry), total, program_ms, pre_add_ms, built_ms, predicted_ms, worker,
                 run.outcome.round_trip_ms, run.runs, run.bundle.size());
  }
  DecompileOutput out = Finish(inputs.entry, run, &lookup);
  out.milliseconds = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
  return out;
}

lift::CommittedSignature DecompilerPool::ParamId(const DecompileInputs &inputs, const ImageInputs &image,
                                                 RunLookup &lookup, double timeout_seconds) {
  auto program = ProgramFor(image);
  decompd::Prediction prediction;
  {
    decompd::LifterPool::Context context;
    if (const lift::FunctionFacts *f = lookup.function_at(inputs.entry)) context = f->context;
    if (lookup.failure) std::rethrow_exception(lookup.failure);
    decompd::LifterPool::Lease lifter = lifters_.take(context);
    prediction = decompd::predict(*lifter, *program, inputs.entry, BodyOf(inputs), image.memory,
                                  decompd::tracked_seeds(*lifter, lookup.tracked(inputs.entry)));
  }
  Checked checked(lookup);
  decompd::LiftBundleBuilder builder(*program, decompd::Mode::param_id, inputs.entry, checked, image.memory,
                                     image.address_prefix);
  builder.set_chunk_hook([&lookup](std::uint64_t i, std::string b) { return lookup.chunk(i, std::move(b)); });
  builder.set_naming(true, false, true);
  std::vector<std::pair<std::uint64_t, std::string>> overrides;
  for (const auto &[addr, kind] : inputs.flow_overrides)
    if (const char *name = OverrideName(kind)) overrides.emplace_back(addr, name);
  builder.set_hooks(inputs.jump_tables, std::move(overrides), {});
  builder.add(prediction);
  const double timeout = timeout_seconds > 0 ? timeout_seconds : decompd::kParamIdTimeoutSeconds;
  decompd::LiftSource source(builder);
  decompd::BundledRun run = decompd::run_bundled(*workers_, source, {timeout, config_.limits.max_varnodes},
                                                 inputs.entry, 4, [this] { return param_id_stopped_->load(); });
  if (lookup.failure) std::rethrow_exception(lookup.failure);
  if (run.outcome.cancelled) throw DecompileStoppedError(lift::DecompileStop::cancelled, "parameter ID cancelled");
  return decompd::signature_of(run);
}

decompd::FunctionSignature DecompilerPool::Signature(const SignatureRequest &req, const ImageInputs &image,
                                                     RunLookup &lookup) {
  auto program = ProgramFor(image);
  decompd::Prediction prediction;
  {
    decompd::LifterPool::Context context;
    if (const lift::FunctionFacts *f = lookup.function_at(req.entry)) context = f->context;
    if (lookup.failure) std::rethrow_exception(lookup.failure);
    decompd::LifterPool::Lease lifter = lifters_.take(context);
    prediction = decompd::predict(*lifter, *program, req.entry, req.body, image.memory,
                                  decompd::tracked_seeds(*lifter, lookup.tracked(req.entry)));
  }
  Checked checked(lookup);
  decompd::LiftBundleBuilder builder(*program, decompd::Mode::signature, req.entry, checked, image.memory,
                                     image.address_prefix);
  builder.set_chunk_hook([&lookup](std::uint64_t i, std::string b) { return lookup.chunk(i, std::move(b)); });
  builder.set_naming(true, false, true);
  builder.set_hooks({}, req.flow_overrides, {});
  builder.set_extra(facts::encode_to_string(req.options));
  builder.add(prediction);
  const lift::DecompileLimits *scoped = DecompileLimitsScope::current();
  const lift::DecompileLimits &limits = scoped != nullptr ? *scoped : config_.limits;
  // Ghidra's GenSignatures uses the program's decompiler timeout (30 s).
  const double timeout = limits.timeout_seconds > 0 ? limits.timeout_seconds : 30;
  decompd::LiftSource source(builder);
  decompd::BundledRun run = decompd::run_bundled(*workers_, source, {timeout, limits.max_varnodes}, req.entry, 8,
                                                 limits.cancelled);
  if (lookup.failure) std::rethrow_exception(lookup.failure);
  if (run.outcome.cancelled) throw DecompileStoppedError(lift::DecompileStop::cancelled, "signature cancelled");
  decompd::FunctionSignature s = decompd::function_signature_of(run);
  if (!s.failure && !s.ok() && run.outcome.result && run.outcome.result->stopped == lift::DecompileStop::cancelled)
    throw DecompileStoppedError(lift::DecompileStop::cancelled, "signature cancelled");
  return s;
}

DecompileOutput DecompilerPool::Finish(std::uint64_t entry, decompd::BundledRun &run, RunLookup *lookup) {
  DecompileOutput out;
  out.function.mutable_entry()->set_offset(entry);
  if (run.outcome.result && run.outcome.result->ran && !run.failure) {
    try {
      out = facts::decode_from_string<DecompileOutput>(run.outcome.result->payload);
    } catch (const std::exception &e) {
      Fail(out.function, std::string("bad result from the decompiler worker: ") + e.what());
    }
  } else if (run.outcome.result && !run.outcome.result->ran) {
    Fail(out.function, "decompiler worker: " + run.outcome.result->error);
  }
  if (run.failure) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "FUN_%08llx", static_cast<unsigned long long>(entry));
    const lift::FunctionFacts *self = lookup != nullptr ? lookup->function_at(entry) : nullptr;
    out.function.set_name(self != nullptr && !self->name.empty() ? self->name : buf);
    Fail(out.function, decompd::describe(*run.failure));
    out.failure = *run.failure;
    out.failure_bundle = run.bundle;
  }
  // The addresses the decompiler looked up: its symbol dependencies.
  if (run.outcome.result)
    for (const auto &[space, a] : run.outcome.result->asked)
      if (space.empty()) out.touched.push_back(a);
  return out;
}

DecompileOutput DecompilerPool::Escalate(const DecompileOutput &failed, double timeout_seconds) {
  struct Fixed final : decompd::BundleSource {
    decompd::Bundle b;
    decompd::Bundle bundle() override { return b; }
    bool fill(const std::vector<decompd::Miss> &) override { return false; }
  } fixed;
  fixed.b = decompd::decode_bundle(failed.failure_bundle);
  const lift::DecompileLimits *scoped = DecompileLimitsScope::current();
  const lift::DecompileLimits &limits = scoped != nullptr ? *scoped : config_.limits;
  decompd::BundledRun run = decompd::run_bundled(*workers_, fixed, {timeout_seconds, limits.max_varnodes},
                                                 fixed.b.entry, 1, limits.cancelled);
  if (run.outcome.cancelled) throw DecompileStoppedError(lift::DecompileStop::cancelled, "decompilation cancelled");
  DecompileOutput out = Finish(fixed.b.entry, run, nullptr);
  if (out.failure) out.failure->escalated = true;
  if (!out.failure) out.function.set_name(failed.function.name().empty() ? out.function.name() : out.function.name());
  return out;
}

void DecompilerPool::Fail(pb::DecompiledFunction &f, const std::string &message) { TokenSession::Fail(f, message); }

}  // namespace revkit::backend
