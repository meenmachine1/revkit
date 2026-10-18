#include "revkit/infer/decompiler.h"
#include "revkit/lift/budget.hh"
#include "revkit/infer/ghidra_types.h"

#include "revkit/lift/decomp_inputs.hh"
#include "revkit/lift/image_arch.hh"
#include "revkit/lift/lifter.hh"

#include "funcdata.hh"
#include "printc.hh"
#include "xml.hh"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <map>
#include <set>
#include <sstream>

namespace revkit::infer {

// ---- codecs ----

void Slot::encode(facts::Encoder &e) const {
  e.bytes(reg);
  e.svarint(stack);
  e.u8(size);
  type.encode(e);
  e.u8(used);
  e.u8(narrowest);
  facts::encode(e, constants);
  facts::encode(e, data_address);
  facts::encode(e, code_address);
  e.svarint(from_param);
  facts::encode(e, passed_only);
}

Slot Slot::decode(facts::Decoder &d) {
  Slot s;
  s.reg = std::string(d.bytes());
  s.stack = d.svarint();
  s.size = d.u8();
  s.type = VType::decode(d);
  s.used = d.u8();
  s.narrowest = d.u8();
  s.constants = facts::decode<std::vector<std::uint64_t>>(d);
  s.data_address = facts::decode<bool>(d);
  s.code_address = facts::decode<bool>(d);
  s.from_param = static_cast<std::int32_t>(d.svarint());
  s.passed_only = facts::decode<bool>(d);
  return s;
}

void CallSite::encode(facts::Encoder &e) const {
  e.varint(address);
  e.varint(target);
  facts::encode(e, locked);
  facts::encode(e, args);
  facts::encode(e, ret_used);
  ret_type.encode(e);
}

CallSite CallSite::decode(facts::Decoder &d) {
  CallSite c;
  c.address = d.varint();
  c.target = d.varint();
  c.locked = facts::decode<bool>(d);
  c.args = facts::decode<std::vector<Slot>>(d);
  c.ret_used = facts::decode<bool>(d);
  c.ret_type = VType::decode(d);
  return c;
}

void PointerUse::Field::encode(facts::Encoder &e) const {
  e.svarint(offset);
  facts::encode(e, accesses);
  facts::encode(e, self);
  facts::encode(e, returned);
}

PointerUse::Field PointerUse::Field::decode(facts::Decoder &d) {
  Field f;
  f.offset = d.svarint();
  f.accesses = facts::decode<std::vector<PointerAccess>>(d);
  f.self = facts::decode<std::vector<std::int64_t>>(d);
  f.returned = facts::decode<bool>(d);
  return f;
}

void PointerUse::encode(facts::Encoder &e) const {
  e.svarint(param);
  e.varint(call);
  facts::encode(e, accesses);
  facts::encode(e, self);
  facts::encode(e, returned);
  facts::encode(e, fields);
}

PointerUse PointerUse::decode(facts::Decoder &d) {
  PointerUse u;
  u.param = static_cast<std::int32_t>(d.svarint());
  u.call = d.varint();
  u.accesses = facts::decode<std::vector<PointerAccess>>(d);
  u.self = facts::decode<std::vector<std::int64_t>>(d);
  u.returned = facts::decode<bool>(d);
  u.fields = facts::decode<std::vector<Field>>(d);
  return u;
}

void Observation::encode(facts::Encoder &e) const {
  facts::encode(e, ok);
  e.bytes(error);
  facts::encode(e, params);
  facts::encode(e, ret);
  e.u8(ret_natural);
  facts::encode(e, ret_address);
  facts::encode(e, ret_code);
  facts::encode(e, ret_loaded);
  facts::encode(e, extra_inputs);
  facts::encode(e, spilled_only);
  facts::encode(e, spills);
  facts::encode(e, reads_al);
  facts::encode(e, calls);
  facts::encode(e, pointer_uses);
  facts::encode(e, results);
  facts::encode(e, consulted);
  e.bytes(c);
  facts::encode(e, same_as);
  facts::encode(e, too_large);
}

Observation Observation::decode(facts::Decoder &d) {
  Observation o;
  o.ok = facts::decode<bool>(d);
  o.error = std::string(d.bytes());
  o.params = facts::decode<std::vector<Slot>>(d);
  o.ret = facts::decode<std::optional<Slot>>(d);
  o.ret_natural = d.u8();
  o.ret_address = facts::decode<bool>(d);
  o.ret_code = facts::decode<std::vector<std::uint64_t>>(d);
  o.ret_loaded = facts::decode<std::vector<std::uint64_t>>(d);
  o.extra_inputs = facts::decode<std::vector<Slot>>(d);
  o.spilled_only = facts::decode<std::vector<std::string>>(d);
  o.spills = facts::decode<std::vector<std::string>>(d);
  o.reads_al = facts::decode<bool>(d);
  o.calls = facts::decode<std::vector<CallSite>>(d);
  o.pointer_uses = facts::decode<std::vector<PointerUse>>(d);
  o.results = facts::decode<std::vector<PointerUse>>(d);
  o.consulted = facts::decode<std::vector<std::uint64_t>>(d);
  o.c = std::string(d.bytes());
  o.same_as = facts::decode<std::optional<std::uint32_t>>(d);
  o.too_large = facts::decode<bool>(d);
  return o;
}

// ---- Ghidra types for inferred ones ----

namespace {

ghidra::Datatype *to_ghidra(ghidra::Architecture &arch, const VType &t, int depth = 0) {
  ghidra::TypeFactory &tf = *arch.types;
  const int ptr = tf.getSizeOfPointer();
  switch (t.meta) {
    case Meta::void_: return tf.getTypeVoid();
    case Meta::bool_: return tf.getBase(1, ghidra::TYPE_BOOL);
    case Meta::char_: return tf.getTypeChar(1);
    case Meta::int_:
      if (t.size == 0 || t.size > 16) return tf.getBase(ptr, ghidra::TYPE_UNKNOWN);
      return tf.getBase(t.size, t.sign == Sign::is_unsigned ? ghidra::TYPE_UINT : ghidra::TYPE_INT);
    case Meta::float_:
      if (t.size == 4 || t.size == 8 || t.size == 10 || t.size == 16) return tf.getBase(t.size, ghidra::TYPE_FLOAT);
      return tf.getBase(8, ghidra::TYPE_FLOAT);
    case Meta::code:
      if (!t.pointee.empty() && depth < 3) {
        ghidra::PrototypePieces pc;
        pc.model = arch.defaultfp;
        pc.outtype = t.pointee[0].is_void() ? tf.getTypeVoid() : value_type(arch, t.pointee[0]);
        for (std::size_t i = 1; i < t.pointee.size(); ++i) {
          pc.intypes.push_back(value_type(arch, t.pointee[i]));
          pc.innames.emplace_back();
        }
        pc.firstVarArgSlot = t.name == "..." ? static_cast<int>(pc.intypes.size()) : -1;
        try {
          return tf.getTypeCode(pc);
        } catch (const ghidra::LowlevelError &) {
        }
      }
      return tf.getTypeCode();
    case Meta::struct_: return tf.getTypeStruct(t.name.empty() ? std::string("anon_struct") : t.name);
    case Meta::pointer: {
      ghidra::Datatype *target =
          t.pointee.empty() || depth > 4 ? tf.getBase(1, ghidra::TYPE_UNKNOWN) : to_ghidra(arch, t.target(), depth + 1);
      return tf.getTypePointer(ptr, target, 1);
    }
    case Meta::unknown:
      break;
  }
  const int n = t.size == 0 ? 1 : t.size;
  return tf.getBase(n, ghidra::TYPE_UNKNOWN);
}

}  // namespace

bool decompiler_safe(const ghidra::Datatype &t) {
  const ghidra::Datatype *d = &t;
  for (int depth = 0; depth < 16; ++depth) {
    switch (d->getMetatype()) {
      case ghidra::TYPE_VOID:
      case ghidra::TYPE_CODE:
      case ghidra::TYPE_STRUCT:
      case ghidra::TYPE_UNION:
        // Size 0 here is an incomplete aggregate, which the decompiler
        // makes itself for a forward declaration (TypeFactory::
        // getTypeStruct); the fork guards where it divided by that size.
        return true;
      case ghidra::TYPE_PTR:
        d = static_cast<const ghidra::TypePointer *>(d)->getPtrTo();
        continue;
      case ghidra::TYPE_ARRAY: {
        const auto *a = static_cast<const ghidra::TypeArray *>(d);
        if (a->numElements() <= 0 || a->getBase()->getSize() <= 0) return false;
        d = a->getBase();
        continue;
      }
      default:
        return d->getSize() > 0;
    }
  }
  return true;
}

ghidra::Datatype *value_type(ghidra::Architecture &arch, const VType &t) {
  ghidra::TypeFactory &tf = *arch.types;
  // Structs by value and bare functions are opaque bytes.
  if (t.meta == Meta::struct_ || t.meta == Meta::code) return tf.getBase(tf.getSizeOfPointer(), ghidra::TYPE_UNKNOWN);
  ghidra::Datatype *d = to_ghidra(arch, t);
  // A degenerate type would reach the decompiler locked: give it bytes.
  if (!decompiler_safe(*d)) return tf.getBase(t.size != 0 ? t.size : tf.getSizeOfPointer(), ghidra::TYPE_UNKNOWN);
  return d;
}

ghidra::PrototypePieces prototype_pieces(ghidra::Architecture &arch, const Prototype &p) {
  ghidra::PrototypePieces out;
  out.model = arch.defaultfp;
  out.outtype = p.ret.is_void() ? arch.types->getTypeVoid() : value_type(arch, p.ret);
  for (const VType &t : p.params) {
    out.intypes.push_back(value_type(arch, t));
    out.innames.emplace_back();
  }
  out.firstVarArgSlot = p.varargs ? static_cast<int>(p.params.size()) : -1;
  return out;
}

// ---- the decompiler ----

namespace {

std::string hex8(std::uint64_t a) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "%08llx", static_cast<unsigned long long>(a));
  return buf;
}

std::int64_t signed_offset(const ghidra::Address &a) {
  const int bits = static_cast<int>(a.getSpace()->getAddrSize()) * 8;
  std::uint64_t v = a.getOffset();
  if (bits < 64 && (v >> (bits - 1)) & 1) v |= ~std::uint64_t{0} << bits;
  return static_cast<std::int64_t>(v);
}

}  // namespace

struct Decompiler::Impl {
  std::shared_ptr<const loader::Image> image;
  std::string language;  // without the compiler
  std::shared_ptr<Prologues> prologues;
  std::ostringstream errors;  // the architecture writes to it until destroyed
  std::unique_ptr<lift::ImageArchitecture> arch;
  DataOrg org;
  SymbolEnv *env = nullptr;
  std::uint64_t current = 0;
  std::exception_ptr failure;
  std::map<std::uint64_t, FunctionSymbol> imports;  // slots resolved this run
  lift::DecompileBudget budget;
  bool spoiled = false;  // a run was stopped mid-analysis: rebuild before the next
  lift::DecompileStop last_stop = lift::DecompileStop::none;

  Impl(std::shared_ptr<const loader::Image> img, const std::string &language_id, std::shared_ptr<Prologues> shared,
       std::shared_ptr<lift::MemorySource> memory, std::optional<std::vector<lift::ContextRegion>> context)
      : image(std::move(img)) {
    language = std::count(language_id.begin(), language_id.end(), ':') >= 4
                   ? language_id.substr(0, language_id.rfind(':'))
                   : language_id;
    prologues = shared ? std::move(shared) : std::make_shared<Prologues>(image, language);
    lift::ArchitectureOptions opts;
    opts.image_symbols = false;
    opts.java_strings = true;
    opts.readonly.emplace();  // mutability comes with each answer, as from Java
    opts.memory = std::move(memory);
    opts.context = std::move(context);
    {
      auto globals = lift::lock_ghidra_globals();
      arch = std::make_unique<lift::ImageArchitecture>(image, "image", language_id, &errors, std::move(opts));
    }
    arch->init_image();
    arch->resetDefaults();
    arch->readonlypropagate = true;
    arch->allacts.setCurrent("decompile");
    budget.install(*arch);
    org.pointer_size = static_cast<std::uint8_t>(arch->types->getSizeOfPointer());
    org.long_size = image->format == loader::Format::pe ? 4 : org.pointer_size;
    lift::ImageScope &scope = arch->global_scope();
    scope.reset();
    scope.snapshot_properties();
    if (lift::JavaStringManager *strings = arch->java_strings())
      strings->set_defined([](const ghidra::Address &) { return std::optional<std::string>(); });
    scope.set_resolvers([this](const ghidra::Address &a, lift::ImageScope::Hole &hole) { return resolve(a, hole); },
                        [this](const ghidra::Address &a) { return label(a); },
                        [this](const ghidra::Address &a) { return external(a); });
  }

  // Calls the environment; a failure there stops the run (as a decompiler
  // error) and is rethrown once the decompiler is back in a clean state.
  template <class F>
  auto ask(F &&f) -> decltype(f()) {
    if (failure) throw ghidra::LowlevelError("symbol lookup failed");
    try {
      return f();
    } catch (const ghidra::LowlevelError &) {
      throw;
    } catch (...) {
      failure = std::current_exception();
      throw ghidra::LowlevelError("symbol lookup failed");
    }
  }

  const loader::Block *block_at(std::uint64_t a) const {
    for (const loader::Block &b : image->blocks)
      if (a >= b.start && a - b.start < b.size) return &b;
    return nullptr;
  }

  ghidra::Datatype *value_type(const VType &t) { return infer::value_type(*arch, t); }

  VType from_ghidra(ghidra::Datatype *t, int depth = 0) const {
    if (t == nullptr) return VType::unknown(0);
    const auto size = static_cast<std::uint8_t>(t->getSize() > 255 ? 0 : t->getSize());
    switch (t->getMetatype()) {
      case ghidra::TYPE_VOID: return VType::void_type();
      case ghidra::TYPE_INT:
      case ghidra::TYPE_ENUM_INT:
        if (size == 1 && t->isCharPrint()) return VType::character();
        return VType::integer(size, Sign::is_signed, t->getName() == "longlong");
      case ghidra::TYPE_UINT:
      case ghidra::TYPE_ENUM_UINT:
        if (size == 1 && t->isCharPrint()) return VType::character();
        return VType::integer(size, Sign::is_unsigned, t->getName() == "ulonglong");
      case ghidra::TYPE_BOOL: return VType::boolean();
      case ghidra::TYPE_FLOAT: return VType::floating(size);
      case ghidra::TYPE_CODE: {
        VType code = VType::code_type();
        const ghidra::FuncProto *fp = static_cast<ghidra::TypeCode *>(t)->getPrototype();
        if (fp != nullptr && depth < 3 && fp->isInputLocked()) {
          code.pointee.push_back(from_ghidra(fp->getOutputType(), depth + 1));
          for (int i = 0; i < fp->numParams(); ++i) code.pointee.push_back(from_ghidra(fp->getParam(i)->getType(), depth + 1));
          if (fp->isDotdotdot()) code.name = "...";
        }
        return code;
      }
      case ghidra::TYPE_PTR:
      case ghidra::TYPE_PTRREL: {
        auto *p = static_cast<ghidra::TypePointer *>(t);
        if (depth > 4 || t->getMetatype() == ghidra::TYPE_PTRREL) return VType::pointer_to(VType::unknown(1), size);
        return VType::pointer_to(from_ghidra(p->getPtrTo(), depth + 1), size);
      }
      case ghidra::TYPE_STRUCT:
      case ghidra::TYPE_UNION: return VType::structure(t->getName());
      default: return VType::unknown(size);
    }
  }

  std::string reg_name(const ghidra::Address &a) const {
    for (int size : {16, 8, 4}) {
      std::string n = arch->translate->getRegisterName(a.getSpace(), a.getOffset(), size);
      if (!n.empty()) return n;
    }
    return arch->translate->getRegisterName(a.getSpace(), a.getOffset(), 1);
  }

  Slot slot(const ghidra::Address &a, int size, ghidra::Datatype *type) const {
    Slot s;
    s.size = static_cast<std::uint8_t>(size > 255 ? 255 : size);
    if (a.getSpace()->getType() == ghidra::IPTR_PROCESSOR && a.getSpace() != arch->getDefaultCodeSpace() &&
        a.getSpace()->getName() == "register") {
      s.reg = reg_name(a);
      if (s.reg.empty()) s.reg = "reg_" + hex8(a.getOffset());
    } else if (a.getSpace()->getType() == ghidra::IPTR_SPACEBASE) {
      s.stack = signed_offset(a);
    } else {
      s.reg = a.getSpace()->getName() + "_" + hex8(a.getOffset());
    }
    s.type = from_ghidra(type);
    return s;
  }

  ghidra::PrototypePieces pieces(const Prototype &p) { return prototype_pieces(*arch, p); }

  void apply(ghidra::Funcdata *fd, const FunctionSymbol &f) {
    if (fd == nullptr) return;
    if (f.proto) {
      try {
        fd->getFuncProto().setPieces(pieces(*f.proto));
      } catch (const ghidra::LowlevelError &) {
      }
    }
    fd->getFuncProto().setNoReturn(f.no_return);
  }

  ghidra::Symbol *add(const lift::DecompElement &e) {
    std::unique_ptr<ghidra::Element> root(lift::to_element(e));
    return arch->global_scope().add_mapsym(*root);
  }

  ghidra::Symbol *resolve(const ghidra::Address &addr, lift::ImageScope::Hole &hole) {
    const std::uint64_t a = addr.getOffset();
    if (addr.getSpace() != arch->getDefaultCodeSpace() && addr.getSpace() != arch->getDefaultDataSpace()) return nullptr;
    if (auto imp = ask([&] { return env->import_slot(a); })) {
      imports[a] = *imp;
      return add(lift::encode_external_ref(a, imp->name));
    }
    if (auto f = ask([&] { return env->function(a); })) {
      auto *sym = dynamic_cast<ghidra::FunctionSymbol *>(add(lift::encode_function_symbol(facts_for(f->name, a), a, a == current, 1)));
      if (sym != nullptr) apply(sym->getFunction(), *f);
      return sym;
    }
    const loader::Block *b = block_at(a);
    if (b == nullptr) return nullptr;
    if (b->perms.exec) {
      hole = {a, a, true, false};
      return nullptr;
    }
    const lift::Mutability m = b->perms.write ? lift::Mutability::normal : lift::Mutability::constant;
    return add(lift::encode_undefined_symbol(a, "DAT_" + hex8(a), m));
  }

  std::string label(const ghidra::Address &addr) {
    const std::uint64_t a = addr.getOffset();
    if (addr.getSpace() != arch->getDefaultCodeSpace()) return {};
    const loader::Block *b = block_at(a);
    if (b == nullptr || !b->perms.exec) return {};
    return "LAB_" + hex8(a);
  }

  // A function without a signature, as Ghidra's Java side describes one
  // (convention "unknown", the default stack purge): the decompiler then
  // recovers its parameters, and what calls to it pass.
  lift::FunctionFacts facts_for(const std::string &name, std::uint64_t entry) const {
    lift::FunctionFacts f;
    f.entry = entry;
    f.name = name;
    f.convention = "unknown";
    f.ret.type = lift::DecompElement{"void", {}, {}};
    f.ret.storage = std::vector<lift::StorageVarnode>{};
    f.ret.void_storage = true;
    if (arch->defaultfp != nullptr) f.extrapop = arch->defaultfp->getExtraPop();
    f.body.emplace_back(entry, entry);
    return f;
  }

  ghidra::Funcdata *external(const ghidra::Address &slot) {
    auto it = imports.find(slot.getOffset());
    if (it == imports.end()) return nullptr;
    lift::FunctionFacts f = facts_for(it->second.name, 0);
    f.body.clear();
    auto *sym = dynamic_cast<ghidra::FunctionSymbol *>(add(lift::encode_function_symbol(f, slot.getOffset(), false, 2)));
    if (sym == nullptr) return nullptr;
    apply(sym->getFunction(), it->second);
    return sym->getFunction();
  }

  // The low bytes of an input every use of it truncates to (an int passed
  // in a 64-bit register), or its size; 0 if the input isn't there.
  static void used_bytes(ghidra::Funcdata *fd, const ghidra::Address &addr, int size, Slot &s) {
    ghidra::Varnode *vn = fd->findVarnodeInput(size, addr);
    if (vn == nullptr) return;
    int used = 0, narrowest = 0;
    bool whole = false;
    for (auto it = vn->beginDescend(); it != vn->endDescend(); ++it) {
      const ghidra::PcodeOp *op = *it;
      if (op->code() == ghidra::CPUI_SUBPIECE && op->getIn(1)->getOffset() == 0 && op->getOut() != nullptr) {
        const int n = op->getOut()->getSize();
        used = std::max(used, n);
        narrowest = narrowest == 0 ? n : std::min(narrowest, n);
      } else {
        whole = true;
      }
    }
    s.used = static_cast<std::uint8_t>(whole || used == 0 ? size : used);
    s.narrowest = static_cast<std::uint8_t>(narrowest);
  }

  // Whether every read of a parameter (through copies, casts and joins)
  // passes it to a call as an argument.
  static bool passed_only(ghidra::Funcdata *fd, const ghidra::Address &addr, int size) {
    ghidra::Varnode *start = fd->findVarnodeInput(size, addr);
    if (start == nullptr) return false;
    std::vector<const ghidra::Varnode *> work{start}, seen;
    bool passed = false;
    while (!work.empty()) {
      const ghidra::Varnode *vn = work.back();
      work.pop_back();
      if (std::find(seen.begin(), seen.end(), vn) != seen.end()) continue;
      seen.push_back(vn);
      if (seen.size() > 256) return false;
      for (auto it = vn->beginDescend(); it != vn->endDescend(); ++it) {
        const ghidra::PcodeOp *op = *it;
        switch (op->code()) {
          case ghidra::CPUI_CALL:
          case ghidra::CPUI_CALLIND:
            if (op->getSlot(vn) == 0) return false;
            passed = true;
            break;
          case ghidra::CPUI_COPY:
          case ghidra::CPUI_CAST:
          case ghidra::CPUI_MULTIEQUAL:
          case ghidra::CPUI_INDIRECT:
            if (op->getOut() != nullptr) work.push_back(op->getOut());
            break;
          default:
            return false;
        }
      }
    }
    return passed;
  }

  // The constants the j-th argument of a call can be: through copies,
  // casts and joins of control flow (a conditional choice of two
  // callbacks), and as the decompiler shows `&FUN_x` (PTRSUB of 0).
  static std::vector<std::uint64_t> constants_of(ghidra::PcodeOp *op, int j) {
    if (j + 1 >= op->numInput()) return {};
    return value_constants(op->getIn(j + 1));
  }

  static std::vector<std::uint64_t> value_constants(const ghidra::Varnode *start) {
    std::vector<std::uint64_t> out;
    std::vector<std::pair<const ghidra::Varnode *, int>> work{{start, 0}};
    std::vector<const ghidra::Varnode *> seen;
    while (!work.empty() && out.size() < 8) {
      auto [vn, depth] = work.back();
      work.pop_back();
      if (vn == nullptr || depth > 6 || std::find(seen.begin(), seen.end(), vn) != seen.end()) continue;
      seen.push_back(vn);
      if (vn->isConstant()) {
        out.push_back(vn->getOffset());
        continue;
      }
      if (!vn->isWritten()) continue;
      const ghidra::PcodeOp *def = vn->getDef();
      switch (def->code()) {
        case ghidra::CPUI_COPY:
        case ghidra::CPUI_CAST:
          work.emplace_back(def->getIn(0), depth + 1);
          break;
        case ghidra::CPUI_MULTIEQUAL:
          for (int i = 0; i < def->numInput(); ++i) work.emplace_back(def->getIn(i), depth + 1);
          break;
        case ghidra::CPUI_PTRSUB:
          if (def->getIn(0)->isConstant() && def->getIn(0)->getOffset() == 0 && def->getIn(1)->isConstant())
            out.push_back(def->getIn(1)->getOffset());
          break;
        default:
          break;
      }
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
  }

  // Data addresses a value is loaded from: the constant base of the
  // address of a LOAD it comes from (through copies, casts and joins).
  std::vector<std::uint64_t> loaded_from(const ghidra::Varnode *start) const {
    std::vector<std::uint64_t> out;
    std::vector<std::pair<const ghidra::Varnode *, int>> work{{start, 0}};
    std::vector<const ghidra::Varnode *> seen;
    while (!work.empty() && out.size() < 4) {
      auto [vn, depth] = work.back();
      work.pop_back();
      if (vn == nullptr || depth > 6 || !vn->isWritten() || std::find(seen.begin(), seen.end(), vn) != seen.end())
        continue;
      seen.push_back(vn);
      const ghidra::PcodeOp *def = vn->getDef();
      switch (def->code()) {
        case ghidra::CPUI_COPY:
        case ghidra::CPUI_CAST:
          work.emplace_back(def->getIn(0), depth + 1);
          break;
        case ghidra::CPUI_MULTIEQUAL:
          for (int i = 0; i < def->numInput(); ++i) work.emplace_back(def->getIn(i), depth + 1);
          break;
        case ghidra::CPUI_LOAD:
          for (std::uint64_t c : value_constants_deep(def->getIn(1)))
            if (const loader::Block *b = block_at(c); b != nullptr && !b->perms.exec && c >= 0x1000) out.push_back(c);
          break;
        default:
          break;
      }
    }
    return out;
  }

  // Constants an address expression is built from (base plus index).
  static std::vector<std::uint64_t> value_constants_deep(const ghidra::Varnode *start) {
    std::vector<std::uint64_t> out;
    std::vector<std::pair<const ghidra::Varnode *, int>> work{{start, 0}};
    while (!work.empty() && out.size() < 4) {
      auto [vn, depth] = work.back();
      work.pop_back();
      if (vn == nullptr || depth > 4) continue;
      if (vn->isConstant()) {
        out.push_back(vn->getOffset());
        continue;
      }
      if (!vn->isWritten()) continue;
      const ghidra::PcodeOp *def = vn->getDef();
      switch (def->code()) {
        case ghidra::CPUI_COPY:
        case ghidra::CPUI_CAST:
        case ghidra::CPUI_INT_ADD:
        case ghidra::CPUI_PTRADD:
        case ghidra::CPUI_PTRSUB:
          for (int i = 0; i < def->numInput() && i < 2; ++i) work.emplace_back(def->getIn(i), depth + 1);
          break;
        default:
          break;
      }
    }
    return out;
  }

  void classify_constants(Slot &s) const {
    if (s.size != arch->types->getSizeOfPointer()) return;
    for (std::uint64_t c : s.constants) {
      if (c < 0x1000) continue;
      if (const loader::Block *b = block_at(c)) (b->perms.exec ? s.code_address : s.data_address) = true;
    }
  }

  // Whether a value reaches a RETURN unchanged (through copies, casts and
  // joins of control flow).
  static bool returned(const std::vector<const ghidra::Varnode *> &roots) {
    std::vector<const ghidra::Varnode *> work(roots.begin(), roots.end()), seen;
    while (!work.empty() && seen.size() < 64) {
      const ghidra::Varnode *vn = work.back();
      work.pop_back();
      if (vn == nullptr || std::find(seen.begin(), seen.end(), vn) != seen.end()) continue;
      seen.push_back(vn);
      for (auto it = vn->beginDescend(); it != vn->endDescend(); ++it) {
        const ghidra::PcodeOp *op = *it;
        if (op->isDead()) continue;
        switch (op->code()) {
          case ghidra::CPUI_RETURN:
            if (op->getSlot(vn) == 1) return true;
            break;
          case ghidra::CPUI_COPY:
          case ghidra::CPUI_CAST:
          case ghidra::CPUI_MULTIEQUAL:
            if (op->getOut() != nullptr) work.push_back(op->getOut());
            break;
          case ghidra::CPUI_INDIRECT:
            if (op->getSlot(vn) == 0 && op->getOut() != nullptr) work.push_back(op->getOut());
            break;
          default:
            break;
        }
      }
    }
    return false;
  }

  // How a pointer is used, for structure inference (PointerUse): the
  // accesses through it and through the values loaded through it, trimmed
  // to what it composes from. Empty when nothing uses it as a pointer.
  PointerUse use_of(const ghidra::Funcdata &fd, const std::vector<const ghidra::Varnode *> &roots) const {
    constexpr std::size_t kMaxPerRoot = 512, kMaxPerField = 128, kMaxFields = 64;
    constexpr std::int64_t kMinOffset = -0x1000, kMaxOffset = 0x10000;
    auto trim = [&](std::vector<PointerAccess> in, std::size_t cap) {
      std::vector<PointerAccess> out;
      for (PointerAccess &a : in) {
        if (out.size() >= cap) break;
        if (a.offset < kMinOffset || a.offset > kMaxOffset) continue;
        a.storage.clear();
        if (a.kind != AccessKind::passed) a.address = 0;
        out.push_back(std::move(a));
      }
      return out;
    };
    const int ptr = arch->types->getSizeOfPointer();
    PointerUse u;
    std::vector<LoadedValue> loads;
    u.accesses = trim(pointer_accesses(fd, roots, &loads, &u.self), kMaxPerRoot);
    u.returned = returned(roots);
    std::map<std::int64_t, std::vector<const ghidra::Varnode *>> by_offset;
    for (const LoadedValue &l : loads)
      if (l.value != nullptr && l.value->getSize() == ptr && l.offset <= kMaxOffset &&
          (by_offset.contains(l.offset) || by_offset.size() < kMaxFields))
        by_offset[l.offset].push_back(l.value);
    for (const auto &[off, values] : by_offset) {
      PointerUse::Field f;
      f.offset = off;
      f.accesses = trim(pointer_accesses(fd, values, nullptr, &f.self), kMaxPerField);
      f.returned = returned(values);
      if (!f.accesses.empty() || f.returned || !f.self.empty()) u.fields.push_back(std::move(f));
    }
    if (u.accesses.empty() && !u.returned) return {};
    return u;
  }

  // What structure inference reads (Observation::pointer_uses, results):
  // the uses of each pointer-sized parameter and of each pointer-sized
  // result of a call.
  void pointer_uses(const ghidra::Funcdata &fd, const std::vector<const ghidra::HighVariable *> &highs,
                    Observation &o) const {
    const int ptr = arch->types->getSizeOfPointer();
    for (std::size_t i = 0; i < highs.size(); ++i) {
      const ghidra::HighVariable *h = highs[i];
      if (h == nullptr || i >= o.params.size() || o.params[i].size != ptr) continue;
      try {
        std::vector<const ghidra::Varnode *> roots;
        for (int k = 0; k < h->numInstances(); ++k) roots.push_back(h->getInstance(k));
        PointerUse u = use_of(fd, roots);
        u.param = static_cast<std::int32_t>(i);
        if (!u.accesses.empty() || u.returned) o.pointer_uses.push_back(std::move(u));
      } catch (const ghidra::LowlevelError &) {
      }
    }
    for (int i = 0; i < fd.numCalls(); ++i) {
      const ghidra::FuncCallSpecs *fc = fd.getCallSpecs(i);
      const ghidra::PcodeOp *op = fc->getOp();
      if (op == nullptr || op->isDead()) continue;
      const ghidra::Varnode *out = op->getOut();
      if (out == nullptr || out->getSize() != ptr || out->hasNoDescend()) continue;
      try {
        PointerUse u = use_of(fd, {out});
        u.call = op->getAddr().getOffset();
        if (!u.accesses.empty() || u.returned) o.results.push_back(std::move(u));
      } catch (const ghidra::LowlevelError &) {
      }
    }
  }

  void observe(ghidra::Funcdata *fd, Observation &o) {
    ghidra::FuncProto &proto = fd->getFuncProto();
    for (int i = 0; i < proto.numParams(); ++i) {
      ghidra::ProtoParameter *p = proto.getParam(i);
      Slot s = slot(p->getAddress(), p->getSize(), p->getType());
      used_bytes(fd, p->getAddress(), p->getSize(), s);
      s.passed_only = passed_only(fd, p->getAddress(), p->getSize());
      o.params.push_back(std::move(s));
    }
    ghidra::ProtoParameter *out = proto.getOutput();
    if (out != nullptr && out->getType() != nullptr && out->getType()->getMetatype() != ghidra::TYPE_VOID &&
        !out->getAddress().isInvalid())
      o.ret = slot(out->getAddress(), out->getSize(), out->getType());
    if (o.ret) {
      int natural = 0;
      bool known = true;
      for (auto it = fd->beginOp(ghidra::CPUI_RETURN); it != fd->endOp(ghidra::CPUI_RETURN) && known; ++it) {
        ghidra::PcodeOp *ret = *it;
        if (ret->isDead() || ret->numInput() < 2) continue;
        const ghidra::Varnode *vn = ret->getIn(1);
        int w = vn->getSize();
        if (vn->isConstant()) {
          const std::uint64_t v = vn->getOffset();
          if (vn->getSize() == arch->types->getSizeOfPointer())
            if (const loader::Block *b = block_at(v); b != nullptr && !b->perms.exec && v >= 0x1000) o.ret_address = true;
          const int bits = vn->getSize() * 8;
          const std::uint64_t mask = bits >= 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << bits) - 1;
          const std::uint64_t sext = (v & (std::uint64_t{1} << (bits - 1))) ? (v | ~mask) : v;
          const auto sv = static_cast<std::int64_t>(sext);
          w = (sv >= INT32_MIN && sv <= INT32_MAX) || v <= 0xffffffffULL ? std::min(4, vn->getSize()) : vn->getSize();
        } else if (vn->isWritten()) {
          const ghidra::PcodeOp *def = vn->getDef();
          if (def->code() == ghidra::CPUI_INT_ZEXT || def->code() == ghidra::CPUI_INT_SEXT) w = def->getIn(0)->getSize();
          if (def->code() == ghidra::CPUI_PTRSUB && def->getIn(0)->isConstant() && def->getIn(0)->getOffset() == 0 &&
              def->getIn(1)->isConstant())
            if (const loader::Block *b = block_at(def->getIn(1)->getOffset()); b != nullptr && !b->perms.exec)
              o.ret_address = true;
        }
        natural = std::max(natural, w);
        if (vn->getSize() == arch->types->getSizeOfPointer())
          for (std::uint64_t c : loaded_from(vn))
            if (std::find(o.ret_loaded.begin(), o.ret_loaded.end(), c) == o.ret_loaded.end()) o.ret_loaded.push_back(c);
        if (vn->getSize() == arch->types->getSizeOfPointer())
          for (std::uint64_t c : value_constants(vn))
            if (const loader::Block *b = block_at(c); b != nullptr && c >= 0x1000) {
              if (!b->perms.exec) o.ret_address = true;
              else if (std::find(o.ret_code.begin(), o.ret_code.end(), c) == o.ret_code.end()) o.ret_code.push_back(c);
            }
      }
      o.ret_natural = static_cast<std::uint8_t>(known ? natural : 0);
    }
    // Register inputs that aren't parameters.
    for (auto it = fd->beginDef(ghidra::Varnode::input); it != fd->endDef(ghidra::Varnode::input); ++it) {
      ghidra::Varnode *vn = *it;
      if (vn->getSpace()->getName() != "register") continue;
      bool is_param = false;
      for (int i = 0; i < proto.numParams(); ++i)
        if (proto.getParam(i)->getAddress() == vn->getAddr()) is_param = true;
      if (is_param) continue;
      Slot s = slot(vn->getAddr(), vn->getSize(), nullptr);
      s.type = VType::unknown(s.size);
      o.extra_inputs.push_back(std::move(s));
    }
    // The parameters' variables, to tell a call argument that is one of
    // them passed on unchanged (Slot::from_param).
    std::vector<const ghidra::HighVariable *> param_highs;
    for (int i = 0; i < proto.numParams(); ++i) {
      const ghidra::HighVariable *h = nullptr;
      try {
        ghidra::ProtoParameter *p = proto.getParam(i);
        if (ghidra::Varnode *in = fd->findVarnodeInput(p->getSize(), p->getAddress()); in != nullptr)
          h = in->getHigh();
      } catch (const ghidra::LowlevelError &) {
      }
      param_highs.push_back(h);
    }
    pointer_uses(*fd, param_highs, o);
    for (int i = 0; i < fd->numCalls(); ++i) {
      ghidra::FuncCallSpecs *fc = fd->getCallSpecs(i);
      ghidra::PcodeOp *op = fc->getOp();
      if (op == nullptr || op->isDead()) continue;
      auto from_param = [&](int j) -> std::int32_t {
        if (j + 1 >= op->numInput()) return -1;
        const ghidra::Varnode *vn = op->getIn(j + 1);
        while (vn != nullptr && vn->isWritten() && vn->getDef()->code() == ghidra::CPUI_CAST) vn = vn->getDef()->getIn(0);
        if (vn == nullptr) return -1;
        try {
          const ghidra::HighVariable *h = vn->getHigh();
          for (std::size_t k = 0; k < param_highs.size(); ++k)
            if (h != nullptr && param_highs[k] == h) return static_cast<std::int32_t>(k);
        } catch (const ghidra::LowlevelError &) {
        }
        return -1;
      };
      CallSite c;
      c.address = op->getAddr().getOffset();
      if (!fc->getEntryAddress().isInvalid()) c.target = fc->getEntryAddress().getOffset();
      c.locked = fc->isInputLocked();
      auto value_type = [&](int j, ghidra::Datatype *fallback) {
        if (j + 1 < op->numInput()) {
          ghidra::Varnode *vn = op->getIn(j + 1);
          try {
            if (vn != nullptr && vn->getHigh() != nullptr) {
              ghidra::Datatype *t = vn->getHigh()->getType();
              // A locked callee's integer parameter makes the decompiler
              // cast a pointer the caller passes ((ulong)param_1): that the
              // caller has a pointer there is evidence the cast hides. (A
              // pointer cast to another pointer type stays the parameter's:
              // what the caller's pointer points to is its own guess.)
              if (vn->isWritten() && vn->getDef()->code() == ghidra::CPUI_CAST && t != nullptr &&
                  t->getMetatype() != ghidra::TYPE_PTR) {
                ghidra::Varnode *in = vn->getDef()->getIn(0);
                ghidra::Datatype *from = in->getHigh() != nullptr ? in->getHigh()->getType() : nullptr;
                if (from != nullptr && from->getMetatype() == ghidra::TYPE_PTR && from->getSize() == t->getSize())
                  return from;
              }
              return t;
            }
          } catch (const ghidra::LowlevelError &) {
          }
        }
        return fallback;
      };
      ghidra::ParamActive *active = fc->getActiveInput();
      if (!c.locked && active != nullptr && active->getNumTrials() == op->numInput() - 1) {
        // Recovered at the call: the trials it kept, in input order.
        for (int j = 0; j < active->getNumTrials(); ++j) {
          const ghidra::ParamTrial &t = active->getTrial(j);
          c.args.push_back(slot(t.getAddress(), t.getSize(), value_type(j, nullptr)));
          c.args.back().from_param = from_param(j);
          c.args.back().constants = constants_of(op, j);
          classify_constants(c.args.back());
        }
      } else {
        for (int j = 0; j < fc->numParams(); ++j) {
          ghidra::ProtoParameter *p = fc->getParam(j);
          c.args.push_back(slot(p->getAddress(), p->getSize(), value_type(j, p->getType())));
          c.args.back().from_param = from_param(j);
          c.args.back().constants = constants_of(op, j);
          classify_constants(c.args.back());
        }
      }
      if (ghidra::Varnode *vn = op->getOut(); vn != nullptr && !vn->hasNoDescend()) {
        c.ret_used = true;
        try {
          c.ret_type = from_ghidra(vn->getHigh()->getType());
        } catch (const ghidra::LowlevelError &) {
          c.ret_type = VType::unknown(static_cast<std::uint8_t>(vn->getSize()));
        }
      }
      o.calls.push_back(std::move(c));
    }
  }

  // Registers the first straight-line instructions store before writing
  // them, and whether AL is read before RAX is written.
  void prologue(std::uint64_t entry, Observation &o) { prologues->fill(entry, o); }

  Observation run(std::uint64_t entry, SymbolEnv &e, const RunOptions &options) {
    Observation o;
    env = &e;
    current = entry;
    failure = nullptr;
    imports.clear();
    lift::ImageScope &scope = arch->global_scope();
    ghidra::AddrSpace *code = arch->getDefaultCodeSpace();
    try {
      if (entry > code->getHighest()) throw ghidra::LowlevelError("entry outside the code space");
      const ghidra::Address addr(code, entry);
      ghidra::Funcdata *fd = scope.queryFunction(addr);
      if (fd == nullptr) {
        // Not a function the environment knows: decompile it anyway.
        std::string name;
        arch->nameFunction(addr, name);
        auto *sym = dynamic_cast<ghidra::FunctionSymbol *>(add(lift::encode_function_symbol(facts_for(name, entry), entry, true, 1)));
        fd = sym != nullptr ? sym->getFunction() : nullptr;
      }
      if (fd == nullptr) throw ghidra::LowlevelError("no function at the entry");
      for (std::uint64_t a : options.call_returns)
        fd->getOverride().insertFlowOverride(ghidra::Address(code, a), ghidra::Override::CALL_RETURN);
      lift::DecompileLimits limits;
      limits.max_varnodes = options.max_varnodes;
      limits.timeout_seconds = options.timeout_seconds;
      budget.start(limits);
      ghidra::Action *act = arch->allacts.getCurrent();
      act->reset(*fd);
      act->perform(*fd);
      if (budget.stopped() != lift::DecompileStop::none) throw lift::DecompileStopped(budget.stopped(), budget.message());
      if (!fd->isProcComplete()) throw ghidra::LowlevelError("decompilation did not complete");
      observe(fd, o);
      if (options.prologue) prologue(entry, o);
      if (options.want_c) {
        std::ostringstream out;
        auto globals = lift::lock_ghidra_globals();
        arch->print->setOutputStream(&out);
        arch->print->docFunction(fd);
        arch->print->setOutputStream(nullptr);
        o.c = out.str();
      }
      o.ok = true;
    } catch (const ghidra::LowlevelError &err) {
      o.error = err.explain;
    } catch (const ghidra::DecoderError &err) {
      o.error = err.explain;
    } catch (const std::exception &err) {
      o.error = err.what();
    }
    last_stop = budget.stopped();
    if (budget.stopped() != lift::DecompileStop::none) {
      o = Observation{};
      o.too_large = budget.stopped() == lift::DecompileStop::too_large;
      o.error = budget.message();
      spoiled = true;
    }
    try {
      scope.reset();
      arch->commentdb->clear();
      arch->stringManager->clear();
    } catch (const ghidra::LowlevelError &err) {
      if (o.ok) o.error = "cleanup: " + err.explain;
      o.ok = false;
    }
    env = nullptr;
    if (failure) std::rethrow_exception(std::exchange(failure, nullptr));
    return o;
  }
};

struct Prologues::Impl {
  std::shared_ptr<const loader::Image> image;
  std::string language;
  std::mutex mu;
  std::unique_ptr<lift::Lifter> lifter;  // built on first use
  std::map<std::uint64_t, std::pair<std::vector<std::string>, bool>> done;
};

Prologues::Prologues(std::shared_ptr<const loader::Image> image, std::string language)
    : impl_(std::make_unique<Impl>()) {
  impl_->image = std::move(image);
  impl_->language = std::move(language);
}

Prologues::~Prologues() = default;

void Prologues::fill(std::uint64_t entry, Observation &o) {
  std::lock_guard lock(impl_->mu);
  if (auto it = impl_->done.find(entry); it != impl_->done.end()) {
    o.spills = it->second.first;
    o.reads_al = it->second.second;
    return;
  }
  std::unique_ptr<lift::Lifter> &lifter = impl_->lifter;
  const auto &image = impl_->image;
  const auto &language = impl_->language;
  if (!lifter) {
    try {
      lifter = std::make_unique<lift::Lifter>(image, language);
    } catch (const std::exception &) {
      return;
    }
  }
  o.spills.clear();
  o.reads_al = false;
  std::set<std::uint64_t> written;  // register offsets written (by byte)
  auto was_written = [&](const lift::Varnode &v) {
    for (std::uint32_t i = 0; i < v.size; ++i)
      if (written.contains(v.offset + i)) return true;
    return false;
  };
  std::uint64_t at = entry;
  for (int n = 0; n < 48; ++n) {
    auto insn = lifter->lift(at);
    if (!insn || insn->length == 0) break;
    bool stop = false;
    std::map<std::uint64_t, lift::Varnode> copies;  // unique -> register it copies (push)
    for (const lift::PcodeOp &op : insn->pcode) {
      if (op.opcode == "COPY" && op.output && op.output->space == "unique" && op.inputs.size() == 1 &&
          op.inputs[0].space == "register")
        copies[op.output->offset] = op.inputs[0];
      if (op.opcode == "STORE" && op.inputs.size() >= 2) {
        lift::Varnode v = op.inputs.back();
        if (v.space == "unique")
          if (auto it = copies.find(v.offset); it != copies.end()) v = it->second;
        if (v.space == "register" && !was_written(v)) {
          std::string name = lifter->register_name(v.offset, 8);
          if (name.empty()) name = lifter->register_name(v.offset, v.size);
          if (!name.empty() && std::find(o.spills.begin(), o.spills.end(), name) == o.spills.end())
            o.spills.push_back(name);
        }
      }
      for (const lift::Varnode &v : op.inputs)
        if (v.space == "register" && v.size == 1 && !was_written(v) && lifter->register_name(v.offset, 1) == "AL")
          o.reads_al = true;
      if (op.output && op.output->space == "register")
        for (std::uint32_t i = 0; i < op.output->size; ++i) written.insert(op.output->offset + i);
      if (op.opcode == "RETURN" || op.opcode == "BRANCHIND" || op.opcode == "CALLIND" || op.opcode == "CALL" ||
          op.opcode == "BRANCH")
        stop = true;
    }
    if (stop) break;
    at += insn->length;
  }
  impl_->done.emplace(entry, std::make_pair(o.spills, o.reads_al));
}

Decompiler::Decompiler(std::shared_ptr<const loader::Image> image, const std::string &language_id,
                       std::shared_ptr<Prologues> prologues, std::shared_ptr<lift::MemorySource> memory,
                       std::optional<std::vector<lift::ContextRegion>> context)
    : impl_(std::make_unique<Impl>(std::move(image), language_id, std::move(prologues), std::move(memory),
                                   std::move(context))) {}

Decompiler::~Decompiler() = default;

Observation Decompiler::run(std::uint64_t entry, SymbolEnv &env, const RunOptions &options) {
  return impl_->run(entry, env, options);
}

const DataOrg &Decompiler::data_org() const { return impl_->org; }

bool Decompiler::spoiled() const { return impl_->spoiled; }

lift::DecompileStop Decompiler::last_stop() const { return impl_->last_stop; }

lift::ImageArchitecture &Decompiler::architecture() { return *impl_->arch; }

}  // namespace revkit::infer
