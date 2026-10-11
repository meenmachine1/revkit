#include "revkit/lift/param_id.hh"

#include "revkit/lift/decompile.hh"

#include "funcdata.hh"
#include "type.hh"

#include <algorithm>

namespace revkit::lift {

namespace {

using Attrs = std::vector<std::pair<std::string, DecompElement::Value>>;

DecompElement el(std::string tag, Attrs attrs = {}, std::vector<DecompElement> kids = {}) {
  return DecompElement{std::move(tag), std::move(attrs), std::move(kids)};
}

std::string metatype_name(ghidra::type_metatype m) {
  std::string s;
  ghidra::metatype2string(m, s);
  return s;
}

// A storage location as Java's VariableStorage holds it: join space
// pieces expanded to their registers.
std::vector<StorageVarnode> storage_of(ghidra::Architecture &arch, const ghidra::Address &addr, int size) {
  std::vector<StorageVarnode> out;
  if (addr.isInvalid()) return out;
  ghidra::AddrSpace *spc = addr.getSpace();
  if (spc->getType() == ghidra::IPTR_JOIN) {
    ghidra::JoinRecord *join = arch.findJoin(addr.getOffset());
    for (int i = 0; i < static_cast<int>(join->numPieces()); ++i) {
      const ghidra::VarnodeData &v = join->getPiece(i);
      out.push_back({v.space->getName(), v.offset, static_cast<int>(v.size)});
    }
    return out;
  }
  out.push_back({spc->getName(), addr.getOffset(), size});
  return out;
}

// Ghidra's DEFAULT data type ("undefined", DataType.DEFAULT).
constexpr std::uint64_t kDefaultTypeId = 0xc000000000000000ULL;
DecompElement default_type() {
  return el("typeref", {{"id", kDefaultTypeId}, {"name", std::string("undefined")}});
}

}  // namespace

DecompElement type_reference(const ghidra::Datatype *t, ghidra::TypeFactory *types) {
  if (t == nullptr || t->getMetatype() == ghidra::TYPE_VOID) return el("void");
  const std::string &name = t->getName();
  const bool named = !name.empty() && t->getId() != 0;
  // Java decodes the decompiler's core "code" type to its DEFAULT data
  // type (PcodeDataTypeManager.generateCoreTypes).
  if (t->isCoreType() && t->getMetatype() == ghidra::TYPE_CODE) return default_type();
  if (t->isCoreType() && named) {
    // Built-in types (PcodeDataTypeManager's core list, ids included):
    // undefinedN by reference, the others inline.
    if (t->getMetatype() == ghidra::TYPE_UNKNOWN) return el("typeref", {{"id", t->getId()}, {"name", name}});
    Attrs a;
    if (dynamic_cast<const ghidra::TypeChar *>(t) != nullptr && dynamic_cast<const ghidra::TypeUnicode *>(t) == nullptr)
      a.emplace_back("char", true);
    a.emplace_back("id", t->getId());
    a.emplace_back("metatype", metatype_name(t->getMetatype()));
    a.emplace_back("name", name);
    a.emplace_back("size", std::int64_t{t->getSize()});
    if (dynamic_cast<const ghidra::TypeUnicode *>(t) != nullptr) a.emplace_back("utf", true);
    return el("type", std::move(a));
  }
  if (named) {
    // Typedefs, structures, enums, function definitions: by reference to
    // the program's type of that id (Java writes a function definition's
    // reference with size 1).
    Attrs a{{"id", t->getId()}, {"name", name}};
    if (t->getMetatype() == ghidra::TYPE_CODE) a.emplace_back("size", std::int64_t{1});
    return el("typeref", std::move(a));
  }
  if (t->getMetatype() == ghidra::TYPE_PTR && dynamic_cast<const ghidra::TypePointerRel *>(t) == nullptr) {
    const auto *p = static_cast<const ghidra::TypePointer *>(t);
    Attrs a{{"metatype", std::string("ptr")}, {"name", std::string()}, {"size", std::int64_t{t->getSize()}}};
    if (p->getWordSize() != 1) a.emplace_back("wordsize", std::int64_t{p->getWordSize()});
    return el("type", std::move(a), {type_reference(p->getPtrTo(), types)});
  }
  if (t->getMetatype() == ghidra::TYPE_ARRAY) {
    const auto *arr = static_cast<const ghidra::TypeArray *>(t);
    return el("type",
              {{"arraysize", std::int64_t{arr->numElements()}},
               {"metatype", std::string("array")},
               {"name", std::string()},
               {"size", std::int64_t{t->getSize()}}},
              {type_reference(arr->getBase(), types)});
  }
  // Something only the decompiler has, written without a name: what
  // PcodeDataTypeManager.decodeDataType makes of it. Integers and floats
  // are Java's of that size, the whole stack void, anything else (an
  // invented structure, a relative pointer, unknown bytes of an odd size)
  // Undefined.getUndefinedDataType: undefinedN up to 8 bytes, else an
  // array of undefined1.
  const int size = t->getSize();
  switch (t->getMetatype()) {
    case ghidra::TYPE_SPACEBASE: return el("void");
    case ghidra::TYPE_INT:
    case ghidra::TYPE_UINT:
    case ghidra::TYPE_FLOAT:
    case ghidra::TYPE_PARTIALENUM:
      if (types != nullptr && size > 0) {
        const ghidra::type_metatype m =
            t->getMetatype() == ghidra::TYPE_PARTIALENUM ? ghidra::TYPE_UINT : t->getMetatype();
        if (ghidra::Datatype *b = types->getBase(size, m); b != nullptr && b != t && b->isCoreType())
          return type_reference(b, nullptr);
      }
      break;
    default: break;
  }
  if (size < 1 || types == nullptr) return default_type();
  if (size <= 8)
    if (ghidra::Datatype *u = types->getBase(size, ghidra::TYPE_UNKNOWN); u != nullptr && u->isCoreType())
      return type_reference(u, nullptr);
  ghidra::Datatype *byte = types->getBase(1, ghidra::TYPE_UNKNOWN);
  return el("type",
            {{"arraysize", std::int64_t{size}},
             {"metatype", std::string("array")},
             {"name", std::string()},
             {"size", std::int64_t{size}}},
            {type_reference(byte, nullptr)});
}

CommittedSignature commit_signature(InputDecompiler &decompiler, ghidra::Funcdata &fd, const FunctionFacts &facts) {
  CommittedSignature out;
  out.status = CommittedSignature::Status::committed;
  ghidra::Architecture &arch = *fd.getArch();
  const ghidra::FuncProto &proto = fd.getFuncProto();

  // HighFunctionDBUtil.getPrototypeModelForCommit.
  ghidra::ProtoModel *model = nullptr;
  if (!proto.isModelUnknown() && proto.getModelName() != "unknown") model = arch.getModel(proto.getModelName());
  if (model == nullptr) model = arch.defaultfp;
  out.convention = model != nullptr ? model->getName() : std::string("unknown");
  out.varargs = proto.isDotdotdot();

  // getReturnParameter with COMMIT_NO_VOID: void keeps what the function
  // had; anything else is committed with the decompiler's storage.
  const ghidra::ProtoParameter *output = proto.getOutput();
  ghidra::Datatype *rtype = output != nullptr ? output->getType() : nullptr;
  if (rtype != nullptr && rtype->getMetatype() != ghidra::TYPE_VOID) {
    out.return_committed = true;
    out.ret.type = type_reference(rtype, arch.types);
    // A type Java decodes to its DEFAULT data type ("undefined", "code").
    const DecompElement::Value *id = out.ret.type.attr("id");
    out.ret.is_default = out.ret.type.tag == "typeref" && id != nullptr &&
                         std::holds_alternative<std::uint64_t>(*id) && std::get<std::uint64_t>(*id) == kDefaultTypeId;
    out.ret.storage = storage_of(arch, output->getAddress(), output->getSize());
    out.ret.size = rtype->getSize();
  }

  // getParameters: the local symbol map's parameter symbols, in order.
  const ghidra::ScopeLocal *scope = fd.getScopeLocal();
  const int n = scope->getCategorySize(ghidra::Symbol::function_parameter);
  for (int i = 0; i < n; ++i) {
    ghidra::Symbol *sym = scope->getCategorySymbol(ghidra::Symbol::function_parameter, i);
    if (sym == nullptr) continue;
    ParamFacts p;
    p.name = sym->getName();
    p.type = type_reference(sym->getType(), arch.types);
    if (ghidra::SymbolEntry *e = sym->getFirstWholeMap(); e != nullptr && !e->isDynamic())
      p.storage = storage_of(arch, e->getAddr(), e->getSize());
    p.valid = !p.storage.empty();
    p.stack = p.valid && p.storage[0].space == arch.getStackSpace()->getName();
    out.params.push_back(std::move(p));
  }

  // updateFunction(DYNAMIC_STORAGE_ALL_PARAMS), then CUSTOM_STORAGE if the
  // convention's storage for these types isn't the decompiler's.
  FunctionFacts dynamic = facts;
  dynamic.convention = out.convention;
  dynamic.varargs = out.varargs;
  dynamic.params = out.params;
  if (out.return_committed) {
    dynamic.ret = out.ret;
  } else {
    dynamic.ret = FunctionFacts::Return{};
    dynamic.ret.type = el("void");
  }
  dynamic.dynamic_storage = true;
  std::optional<FunctionFacts> assigned = decompiler.assign_storage(dynamic);
  bool matches = assigned.has_value() && assigned->params.size() == out.params.size();
  for (std::size_t i = 0; matches && i < out.params.size(); ++i)
    matches = assigned->params[i].storage == out.params[i].storage;
  if (matches && out.return_committed) matches = assigned->ret.storage && *assigned->ret.storage == *out.ret.storage;
  out.custom_storage = !matches;
  for (const ParamFacts &p : out.params)
    if (!p.valid) out.custom_storage = true;
  return out;
}

}  // namespace revkit::lift
