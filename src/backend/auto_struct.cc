#include "auto_struct.h"

#include "define_type.h"

#include "revkit/types/packing.h"
#include "revkit/types/print.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <deque>
#include <map>
#include <set>
#include <tuple>

namespace revkit::backend {

using api::Error;
using api::Status;
using api::StatusCode;
using types::TypeId;

namespace q {

void PointerAccessList::encode(facts::Encoder &e) const {
  facts::encode(e, found);
  facts::encode(e, accesses);
}

PointerAccessList PointerAccessList::decode(facts::Decoder &d) {
  PointerAccessList l;
  l.found = facts::decode<bool>(d);
  l.accesses = facts::decode<std::vector<infer::PointerAccess>>(d);
  return l;
}

PointerAccesses::Value PointerAccesses::compute(facts::QueryContext &ctx, const Key &key) {
  auto out = ctx.get<Decompile>(key.first);
  Value v;
  for (const auto &var : out->function.variables())
    if (var.kind() != pb::VARIABLE_KIND_GLOBAL && var.storage_key() == key.second) v.found = true;
  for (const auto &[k, list] : out->accesses)
    if (k == key.second) v.accesses = list;
  return v;
}

}  // namespace q

void RegisterAutoStructQueries(facts::Engine &engine) { engine.add_query<q::PointerAccesses>(); }

namespace {

constexpr std::uint32_t kDefaultDepth = 1;  // Ghidra's FillOutStructureHelper.maxCallDepth
constexpr std::uint32_t kMaxDepth = 4;
constexpr std::size_t kMaxFunctions = 64;
constexpr std::size_t kMaxReported = 10000;
constexpr std::uint64_t kMaxRange = 1u << 20;

std::string Hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

pb::PointerValueKind ValueOf(infer::ValueKind k) {
  switch (k) {
    case infer::ValueKind::pointer: return pb::POINTER_VALUE_KIND_POINTER;
    case infer::ValueKind::signed_int: return pb::POINTER_VALUE_KIND_SIGNED;
    case infer::ValueKind::unsigned_int: return pb::POINTER_VALUE_KIND_UNSIGNED;
    case infer::ValueKind::floating: return pb::POINTER_VALUE_KIND_FLOAT;
    case infer::ValueKind::boolean: return pb::POINTER_VALUE_KIND_BOOL;
    default: return pb::POINTER_VALUE_KIND_UNSPECIFIED;
  }
}

pb::PointerAccessKind KindOf(infer::AccessKind k) {
  switch (k) {
    case infer::AccessKind::load: return pb::POINTER_ACCESS_KIND_LOAD;
    case infer::AccessKind::store: return pb::POINTER_ACCESS_KIND_STORE;
    case infer::AccessKind::passed: return pb::POINTER_ACCESS_KIND_PASSED;
  }
  return pb::POINTER_ACCESS_KIND_UNSPECIFIED;
}

// The program's own name for a struct is taken (by a definition or a binding).
bool NameTaken(const NamedTypes &names, const std::string &key) {
  if (names.bound(key)) return true;
  return std::any_of(names.types.begin(), names.types.end(), [&](const auto &e) { return e.key == key; });
}

std::string UniqueName(const NamedTypes &names, const std::string &base) {
  if (!NameTaken(names, "struct " + base)) return base;
  for (int i = 1;; ++i) {
    std::string n = base + "_" + std::to_string(i);
    if (!NameTaken(names, "struct " + n)) return n;
  }
}

bool ValidName(const std::string &n) {
  if (n.empty() || n.size() > 256 || std::isdigit(static_cast<unsigned char>(n[0]))) return false;
  return std::all_of(n.begin(), n.end(), [](char ch) {
    return std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' || ch == ':';
  });
}

bool CName(const std::string &n) {
  if (n.empty() || n.size() > 256 || std::isdigit(static_cast<unsigned char>(n[0]))) return false;
  return std::all_of(n.begin(), n.end(), [](char ch) { return std::isalnum(static_cast<unsigned char>(ch)) || ch == '_'; });
}

// The client's edits (AutoStructureRequest.edits) on the composed fields:
// removes, then renames and retypes, then adds, each checked against the
// fields as they are then (a name used twice, a type that runs into the
// next field) and left out with a field error when it doesn't fit. Grows
// the structure when its last field grows past the end. Returns the
// offsets of the fields an edit made or changed.
std::set<std::uint64_t> ApplyEdits(types::AggregateType &agg, const pb::AutoStructureRequest &req, types::TypeStore &store,
                                   ProgramTypes &program, const cparse::Profile &profile, pb::AutoStructureResponse &resp) {
  std::set<std::uint64_t> edited;
  if (req.edits().empty()) return edited;
  auto fail = [&](std::uint64_t off, std::string msg) {
    auto *e = resp.add_field_errors();
    e->set_offset(off);
    e->set_message(std::move(msg));
  };
  auto byte_size = [&](const types::Field &f) -> std::uint64_t {
    return f.bit_size != 0 ? (f.bit_offset % 8 + f.bit_size + 7) / 8 : store.size_of(f.type);
  };
  auto at = [&](std::uint64_t off) -> types::Field * {
    for (auto &f : agg.fields)
      if (f.bit_offset / 8 == off && f.bit_size == 0) return &f;
    return nullptr;
  };
  // Does a field of `size` bytes at `off` (other than `self`) fit?
  auto check_room = [&](std::uint64_t off, std::uint64_t size, const types::Field *self, const std::string &what) -> std::string {
    for (const auto &f : agg.fields) {
      if (&f == self) continue;
      const std::uint64_t fo = f.bit_offset / 8, fe = fo + std::max<std::uint64_t>(byte_size(f), 1);
      if (fo < off + size && off < fe)
        return what + " is " + std::to_string(size) + " byte" + (size == 1 ? "" : "s") + ": it runs into " + f.name + " at " +
               Hex(fo);
    }
    return "";
  };
  auto name_taken = [&](const std::string &n, const types::Field *self) {
    return std::any_of(agg.fields.begin(), agg.fields.end(), [&](const types::Field &f) { return &f != self && f.name == n; });
  };
  // The edit's type, or an error.
  auto type_of = [&](const pb::AutoStructureFieldEdit &e, std::string &declared, std::string &err) -> std::optional<TypeId> {
    std::optional<TypeId> t;
    if (e.type_case() == pb::AutoStructureFieldEdit::kTypeHash) {
      t = program.intern(e.type_hash());
      if (!t) err = "no type " + e.type_hash() + " in the program";
    } else {
      cparse::Options o;
      o.profile = profile;
      o.lookup = [&](std::string_view key) { return program.lookup(key); };
      o.limits.wall_time = std::chrono::milliseconds(2000);
      cparse::Result r;
      std::optional<cparse::Declaration> d = e.type_c().size() <= 4096 ? cparse::parse_declaration(store, e.type_c(), o, &r) : std::nullopt;
      if (!d) {
        err = "not a C type: " + e.type_c();
        for (const auto &dg : r.diagnostics)
          if (dg.severity == cparse::Severity::Error) {
            err += " (" + dg.text + ")";
            break;
          }
      } else if (d->function) {
        err = "a function isn't a field; use a pointer to one";
      } else {
        t = d->type;
        declared = d->name;
      }
    }
    if (t && store.size_of(*t) == 0) {
      err = types::type_name(store, *t) + " has no size";
      t.reset();
    }
    return t;
  };
  // Removes.
  for (const auto &e : req.edits()) {
    if (!e.remove()) continue;
    auto it = std::find_if(agg.fields.begin(), agg.fields.end(), [&](const types::Field &f) { return f.bit_offset / 8 == e.offset() && f.bit_size == 0; });
    if (it == agg.fields.end()) {
      fail(e.offset(), "no field at " + Hex(e.offset()) + " to remove");
      continue;
    }
    agg.fields.erase(it);
    edited.insert(e.offset());
  }
  // Renames and retypes, then adds.
  for (int pass = 0; pass < 2; ++pass) {
    for (const auto &e : req.edits()) {
      if (e.remove() || e.add() != (pass == 1)) continue;
      const std::uint64_t off = e.offset();
      std::string declared, err;
      std::optional<TypeId> t;
      if (e.type_case() != pb::AutoStructureFieldEdit::TYPE_NOT_SET) {
        t = type_of(e, declared, err);
        if (!t) {
          fail(off, err);
          continue;
        }
      }
      std::string name = !e.name().empty() ? e.name() : declared;
      if (!name.empty() && !CName(name)) {
        fail(off, "not a C name: " + name);
        continue;
      }
      if (e.add()) {
        if (!t) {
          fail(off, "a new field needs a type");
          continue;
        }
        if (off >= agg.size) {
          fail(off, "past the end of the structure (" + Hex(agg.size) + " bytes)");
          continue;
        }
        if (name.empty()) name = infer::field_name(off);
        const std::uint64_t size = store.size_of(*t);
        if (std::string room = check_room(off, size, nullptr, types::type_name(store, *t)); !room.empty()) {
          fail(off, at(off) ? "there is a field at " + Hex(off) + " already" : room);
          continue;
        }
        if (name_taken(name, nullptr)) {
          fail(off, "another field is named " + name);
          continue;
        }
        agg.fields.push_back({name, *t, off * 8, 0});
        agg.size = std::max<std::uint64_t>(agg.size, off + size);
        edited.insert(off);
        continue;
      }
      types::Field *f = at(off);
      if (f == nullptr) {
        fail(off, "no field at " + Hex(off));
        continue;
      }
      if (t) {
        const std::uint64_t size = store.size_of(*t);
        if (std::string room = check_room(off, size, f, types::type_name(store, *t)); !room.empty()) {
          fail(off, room);
          continue;
        }
      }
      if (!name.empty() && name_taken(name, f)) {
        fail(off, "another field is named " + name);
        continue;
      }
      if (t) {
        f->type = *t;
        agg.size = std::max<std::uint64_t>(agg.size, off + store.size_of(*t));
      }
      if (!name.empty()) f->name = name;
      edited.insert(off);
    }
  }
  return edited;
}

// The parameter of `callee`'s decompilation a call passes the pointer as:
// the one in the storage the call's prototype gives, else by position.
const pb::Variable *ParameterFor(const pb::DecompiledFunction &callee, const infer::PointerAccess &a) {
  const pb::Variable *by_index = nullptr;
  for (const auto &var : callee.variables()) {
    if (var.kind() != pb::VARIABLE_KIND_PARAMETER) continue;
    if (a.storage.starts_with("register:") && var.storage_size() > 0 &&
        var.storage(0).register_name() == a.storage.substr(9))
      return &var;
    if (a.parameter >= 0 && var.has_parameter_index() && var.parameter_index() == static_cast<std::uint32_t>(a.parameter))
      by_index = &var;
  }
  return by_index;
}

// Where everything a request makes goes: the struct and its pointer, and
// the nodes and hashes that describe them.
struct Built {
  TypeId struct_id, pointer_id;
  std::optional<TypeId> outer_id;  // a field target's outer structure, retyped
};

void EmitNodes(types::TypeStore &store, ProgramTypes &program, const ProgramTypes::Closure &closure, const Built &b,
               pb::AutoStructureResponse &resp) {
  // Every type the program lacks is a node; the rest go by hash.
  std::map<TypeId, bool> known;
  auto program_has = [&](TypeId id) {
    if (program.recorded(id)) return true;
    auto it = known.find(id);
    if (it != known.end()) return it->second;
    const bool has = !closure(store.hash(id).hex()).empty();
    known.emplace(id, has);
    return has;
  };
  std::vector<TypeId> roots{b.struct_id, b.pointer_id};
  if (b.outer_id) roots.push_back(*b.outer_id);
  std::map<TypeId, std::uint32_t> index;
  std::vector<TypeId> order;
  std::vector<TypeId> stack(roots.rbegin(), roots.rend());
  while (!stack.empty()) {
    TypeId id = stack.back();
    stack.pop_back();
    const bool root = std::find(roots.begin(), roots.end(), id) != roots.end();
    if (index.contains(id) || (!root && program_has(id))) continue;
    index.emplace(id, static_cast<std::uint32_t>(order.size()));
    order.push_back(id);
    types::Type t = store.get(id);
    std::vector<TypeId> refs;
    types::for_each_ref(t, [&](TypeId &x, types::EdgeKind) { refs.push_back(x); });
    for (auto it = refs.rbegin(); it != refs.rend(); ++it) stack.push_back(*it);
  }
  auto ref = [&](TypeId id) {
    pb::TypeNodeRef out;
    if (auto it = index.find(id); it != index.end()) out.set_assertion_index(it->second);
    else out.set_hash(store.hash(id).hex());
    return out;
  };
  for (TypeId id : order) {
    *resp.add_nodes() = TypeNodeOf(store, id, ref);
    resp.add_hashes(store.hash(id).hex());
  }
  resp.set_struct_index(index.at(b.struct_id));
  resp.set_pointer_index(index.at(b.pointer_id));
  resp.set_struct_hash(store.hash(b.struct_id).hex());
  resp.set_pointer_hash(store.hash(b.pointer_id).hex());
  resp.set_c_definition(types::definition(store, b.struct_id));
  if (b.outer_id) {
    resp.set_outer_index(index.at(*b.outer_id));
    resp.set_outer_hash(store.hash(*b.outer_id).hex());
  }
}

// A struct of `fields` (sorted, store ids), packed or not as the
// importers' rule says, and a pointer to it.
Built MakeStruct(types::TypeStore &store, types::AggregateType agg, std::uint32_t pointer_size) {
  std::sort(agg.fields.begin(), agg.fields.end(),
            [](const types::Field &a, const types::Field &b) { return a.bit_offset < b.bit_offset; });
  agg.packed = false;
  types::TypeGraph g;
  const TypeId local = g.add(types::Type(std::move(agg)));
  types::infer_packing(g, store, {{local, pointer_size}});
  Built b;
  b.struct_id = store.intern(g).at(0);
  b.pointer_id = store.pointer_to(b.struct_id, pointer_size);
  return b;
}

// The type of a field made from accesses.
TypeId FieldType(types::TypeStore &store, const cparse::LayoutRules &rules, const infer::PlannedField &f) {
  switch (f.value) {
    case infer::ValueKind::pointer: return store.pointer_to(store.undefined(1), rules.pointer_size);
    case infer::ValueKind::floating:
      if (f.size == 4) return store.float_type(4, types::FloatKind::Float);
      if (f.size == 8) return store.float_type(8, types::FloatKind::Double);
      if (f.size == rules.long_double_size || f.size == 10) return store.float_type(f.size, types::FloatKind::LongDouble);
      break;
    case infer::ValueKind::signed_int:
    case infer::ValueKind::unsigned_int: {
      const bool s = f.value == infer::ValueKind::signed_int;
      types::IntRank rank = types::IntRank::Fixed;
      if (f.size == 1) rank = types::IntRank::Char;
      else if (f.size == rules.short_size) rank = types::IntRank::Short;
      else if (f.size == rules.int_size) rank = types::IntRank::Int;
      else if (f.size == rules.long_size) rank = types::IntRank::Long;
      else if (f.size == rules.long_long_size) rank = types::IntRank::LongLong;
      return store.int_type(f.size, s, rank);
    }
    case infer::ValueKind::boolean: return store.bool_type(1);
    default: break;
  }
  return store.undefined(f.size);
}

void AddField(pb::AutoStructureResponse &resp, const types::TypeStore &store, const types::Field &f,
              pb::AutoStructureFieldSource source, std::uint32_t accesses, bool truncated, bool edited = false) {
  auto *out = resp.add_fields();
  out->set_edited(edited);
  out->set_offset(f.bit_offset / 8);
  out->set_size(store.size_of(f.type));
  out->set_name(f.name);
  out->set_type_display(types::type_name(store, f.type));
  out->set_type_hash(store.hash(f.type).hex());
  out->set_source(source);
  out->set_accesses(accesses);
  out->set_truncated(truncated);
}

// The struct a FILL fills: the variable's asserted type, else the type
// its decompilation prints, if either is a pointer to a struct.
std::optional<TypeId> ExistingStruct(types::TypeStore &store, ProgramTypes &program, const std::string &asserted,
                                     const std::string &display) {
  auto as_struct = [&](TypeId id) -> std::optional<TypeId> {
    id = store.strip_typedefs(id);
    if (const auto *p = store.get(id).as<types::PointerType>()) id = store.strip_typedefs(p->target);
    const auto *a = store.get(id).as<types::AggregateType>();
    if (a == nullptr || a->kind == types::AggregateKind::Union) return std::nullopt;
    return id;
  };
  if (!asserted.empty())
    if (auto id = program.intern(asserted)) return as_struct(*id);
  std::string base = display;
  while (!base.empty() && (base.back() == '*' || base.back() == ' ')) base.pop_back();
  if (base.empty() || base == display) return std::nullopt;  // not a pointer
  if (base.starts_with("struct ")) base = base.substr(7);
  for (const std::string key : {"struct " + base, "class " + base, "typedef " + base})
    if (auto id = program.lookup(key)) return as_struct(*id);
  return std::nullopt;
}

Status FromVariable(const AutoStructContext &c, const pb::AutoStructureRequest &req, pb::AutoStructureResponse &resp,
                    types::TypeStore &store, ProgramTypes &program, const cparse::Profile &profile) {
  const cparse::LayoutRules &rules = profile.rules;
  const bool field_target = req.source_case() == pb::AutoStructureRequest::kField;
  const pb::Address &fn_addr = field_target ? req.field().function() : req.variable().function();
  const std::uint64_t entry = fn_addr.offset();
  if (!fn_addr.space().empty() || !c.function(entry) || *c.function(entry) != entry)
    return Error(StatusCode::kNotFound, "no function at " + Hex(entry));
  const std::uint32_t depth = req.has_call_depth() ? req.call_depth() : kDefaultDepth;
  if (depth > kMaxDepth) return Error(StatusCode::kInvalidArgument, "call_depth is at most " + std::to_string(kMaxDepth));

  auto root = c.decompile(entry);
  auto variable = [&](const std::string &k) -> const pb::Variable * {
    const std::string base = k.substr(0, k.find("->"));
    for (const auto &v : root->function.variables())
      if (v.kind() != pb::VARIABLE_KIND_GLOBAL && v.storage_key() == base) return &v;
    return nullptr;
  };
  // The keys whose accesses make the structure: the variable, or a field
  // target's path keys ("param:0->0x20", one per pointer to the outer
  // structure the field is read through).
  std::vector<std::string> keys;
  const pb::Variable *var = nullptr;
  std::string what;  // "param_1", "param_1->field_0x20"
  // A field target: the outer structure and its field.
  std::optional<TypeId> outer;
  std::optional<types::Field> outer_field;  // copies: the store grows
  std::string outer_key;                    // "struct item"
  if (field_target) {
    const pb::AutoStructureFieldTarget &ft = req.field();
    outer = program.intern(ft.struct_hash());
    const auto *agg = outer ? store.get(*outer).as<types::AggregateType>() : nullptr;
    if (agg == nullptr) return Error(StatusCode::kNotFound, "no structure " + ft.struct_hash() + " in the program");
    for (const auto &f : agg->fields)
      if (f.bit_offset == ft.offset() * 8 && f.bit_size == 0) outer_field = f;
    if (!outer_field) return Error(StatusCode::kNotFound, "struct " + agg->name + " has no field at " + Hex(ft.offset()));
    if (agg->name.empty())
      return Error(StatusCode::kFailedPrecondition, "the structure has no name of its own (an anonymous member or a typedef's); name it first");
    outer_key = (agg->kind == types::AggregateKind::Class ? "class " : agg->kind == types::AggregateKind::Union ? "union " : "struct ") + agg->name;
    if (store.size_of(outer_field->type) < rules.pointer_size)
      return Error(StatusCode::kFailedPrecondition, agg->name + "." + outer_field->name + " is " + std::to_string(store.size_of(outer_field->type)) +
                                                        " bytes: too small for a pointer (" + std::to_string(rules.pointer_size) + ")");
    char suffix[24];
    std::snprintf(suffix, sizeof suffix, "->0x%llx", static_cast<unsigned long long>(ft.offset()));
    if (!ft.base_storage_key().empty()) {
      keys.push_back(ft.base_storage_key() + suffix);
    } else {
      // Every variable that points to the structure.
      const std::string outer_name = outer_key.substr(outer_key.find(' ') + 1);
      for (const auto &v : root->function.variables()) {
        if (v.kind() == pb::VARIABLE_KIND_GLOBAL) continue;
        // As printed ("chain_a *", "struct item *"): one level of pointer to the structure's name.
        std::string base = v.type().display();
        while (!base.empty() && base.back() == ' ') base.pop_back();
        if (base.ends_with("*") && !base.ends_with("**")) {
          base.pop_back();
          while (!base.empty() && base.back() == ' ') base.pop_back();
          if (base.starts_with("struct ") || base.starts_with("class ") || base.starts_with("union ")) base = base.substr(base.find(' ') + 1);
          if (base == outer_name) {
            keys.push_back(v.storage_key() + suffix);
            continue;
          }
        }
        if (v.type().hash().empty()) continue;
        auto t = program.intern(v.type().hash());
        if (!t) continue;
        const auto *p = store.get(store.strip_typedefs(*t)).as<types::PointerType>();
        if (p == nullptr) continue;
        // The structure, or another version of it (by its name).
        const TypeId target = store.strip_typedefs(p->target);
        const auto *ta = store.get(target).as<types::AggregateType>();
        const bool same = store.hash(target).hex() == ft.struct_hash() ||
                          (ta != nullptr && !ta->name.empty() &&
                           (ta->kind == types::AggregateKind::Class ? "class " : ta->kind == types::AggregateKind::Union ? "union " : "struct ") + ta->name == outer_key);
        if (same) keys.push_back(v.storage_key() + suffix);
      }
      if (keys.empty())
        return Error(StatusCode::kFailedPrecondition, "nothing in the function points to " + outer_key + "; name the pointer (base_storage_key)");
    }
    var = variable(keys[0]);
    if (var == nullptr) return Error(StatusCode::kNotFound, "no variable " + keys[0] + " in the function at " + Hex(entry));
    what = var->name() + "->" + outer_field->name;
  } else {
    const std::string &key = req.variable().storage_key();
    if (key.empty()) return Error(StatusCode::kInvalidArgument, "variable.storage_key is required");
    keys.push_back(key);
    var = variable(key);
    if (var == nullptr) return Error(StatusCode::kNotFound, "no variable " + key + " in the function at " + Hex(entry));
    what = var->name();
  }

  // Accesses through the variable, then through the parameters of the
  // functions it is passed to (offset + delta), breadth first.
  struct Item {
    std::uint64_t entry;
    std::string key;
    std::int64_t delta;
    std::uint32_t depth;
  };
  std::deque<Item> todo;
  std::set<std::tuple<std::uint64_t, std::string, std::int64_t>> seen;
  for (const auto &k : keys)
    if (seen.insert({entry, k, 0}).second) todo.push_back({entry, k, 0, 0});
  std::set<std::uint64_t> functions;
  std::vector<infer::PointerAccess> all;
  bool capped = false;
  while (!todo.empty()) {
    if (c.cancelled && c.cancelled()) return Error(StatusCode::kCancelled, "cancelled");
    Item it = todo.front();
    todo.pop_front();
    if (functions.insert(it.entry).second) resp.add_functions()->set_offset(it.entry);
    q::PointerAccessList list;
    if (it.key.find("->") == std::string::npos) {
      list = c.accesses(it.entry, it.key);
    } else {
      // A field's value (a path key): straight from the decompilation.
      facts::Ref<DecompileOutput> out = c.decompile(it.entry);
      for (const auto &[k, l] : out->accesses)
        if (k == it.key) list.accesses = l;
    }
    for (const infer::PointerAccess &a : list.accesses) {
      infer::PointerAccess shifted = a;
      shifted.offset += it.delta;
      all.push_back(shifted);
      if (resp.accesses_size() < static_cast<int>(kMaxReported)) {
        auto *out = resp.add_accesses();
        out->mutable_function()->set_offset(it.entry);
        out->set_storage_key(it.key);
        out->set_offset(shifted.offset);
        out->set_size(a.size);
        out->set_kind(KindOf(a.kind));
        out->set_value(ValueOf(a.value));
        out->mutable_address()->set_offset(a.address);
        if (a.callee != 0) out->mutable_callee()->set_offset(a.callee);
        if (a.parameter >= 0) out->set_parameter_index(static_cast<std::uint32_t>(a.parameter));
        out->set_depth(it.depth);
      }
      if (a.kind != infer::AccessKind::passed || it.depth >= depth || a.callee == 0 || shifted.offset < 0) continue;
      const std::optional<std::uint64_t> target = c.function(a.callee);
      if (!target) continue;  // an import, or no function there
      if (functions.size() >= kMaxFunctions && !functions.contains(*target)) {
        capped = true;
        continue;
      }
      facts::Ref<DecompileOutput> callee = c.decompile(*target);
      if (callee->failure) {
        resp.add_notes(callee->function.name() + " failed to decompile");
        continue;
      }
      const pb::Variable *param = ParameterFor(callee->function, a);
      if (param == nullptr) continue;
      if (seen.insert({*target, param->storage_key(), shifted.offset}).second)
        todo.push_back({*target, param->storage_key(), shifted.offset, it.depth + 1});
    }
  }
  if (capped) resp.add_notes("followed the pointer into the first " + std::to_string(kMaxFunctions) + " functions only");

  infer::ComposeOptions o;
  o.pointer_size = rules.pointer_size;
  std::optional<TypeId> existing;
  types::AggregateType agg;
  std::vector<infer::ExistingField> old;
  if (req.mode() == pb::AUTO_STRUCTURE_MODE_FILL) {
    if (field_target) {
      // The structure the field points to.
      TypeId t = store.strip_typedefs(outer_field->type);
      if (const auto *p = store.get(t).as<types::PointerType>()) {
        t = store.strip_typedefs(p->target);
        if (const auto *a = store.get(t).as<types::AggregateType>(); a != nullptr && a->kind != types::AggregateKind::Union) existing = t;
      }
    } else {
      existing = ExistingStruct(store, program, keys[0].find("->") == std::string::npos ? c.local_type(entry, keys[0]) : "", var->type().display());
    }
    if (!existing)
      return Error(StatusCode::kFailedPrecondition,
                   field_target ? what + " isn't a pointer to a structure (" + types::type_name(store, outer_field->type) + "); create one instead"
                                : "the variable isn't a pointer to a structure (" + var->type().display() + "); create one instead");
    agg = *store.get(*existing).as<types::AggregateType>();
    for (const types::Field &f : agg.fields)
      old.push_back({f.bit_offset / 8, static_cast<std::uint32_t>(f.bit_size != 0 ? (f.bit_size + f.bit_offset % 8 + 7) / 8
                                                                                   : store.size_of(f.type)),
                     f.name});
    resp.set_existing_hash(store.hash(*existing).hex());
  }
  const infer::StructurePlan plan = infer::compose_structure(all, o, old, existing ? agg.size : 0);
  if (plan.size == 0) {
    if (field_target)
      return Error(StatusCode::kFailedPrecondition,
                   what + " isn't used as a pointer here: nothing is read or written through the value it holds");
    resp.set_unchanged(true);
    resp.add_notes("no accesses through " + what);
    return Status::Ok();
  }
  types::AggregateType made = agg;
  made.kind = existing ? agg.kind : types::AggregateKind::Struct;
  made.complete = true;
  made.size = plan.size;
  bool added = false;
  for (const infer::PlannedField &p : plan.fields) {
    if (p.existing) continue;
    made.fields.push_back({p.name, FieldType(store, rules, p), p.offset * 8, 0});
    added = true;
  }
  if (existing) {
    if (!added && plan.size == agg.size) resp.set_unchanged(true);
    resp.set_name(agg.name);
  } else {
    std::string name = req.name().empty() ? UniqueName(c.names, "astruct") : req.name();
    if (!ValidName(name)) return Error(StatusCode::kInvalidArgument, "not a C name: " + name);
    if (!req.name().empty() && NameTaken(c.names, "struct " + name))
      return Error(StatusCode::kAlreadyExists, "struct " + name + " exists; fill it in, or choose another name");
    made.name = name;
    resp.set_name(name);
  }
  if (!made.name.empty()) resp.set_named_key((made.kind == types::AggregateKind::Class ? "class " : "struct ") + made.name);
  std::set<std::uint64_t> made_here;  // the offsets of the fields from accesses
  for (const infer::PlannedField &p : plan.fields)
    if (!p.existing) made_here.insert(p.offset);
  const std::set<std::uint64_t> edited = ApplyEdits(made, req, store, program, profile, resp);
  if (!edited.empty()) resp.set_unchanged(false);
  Built b = MakeStruct(store, made, rules.pointer_size);
  if (field_target) {
    // The outer structure's next version: the field points to the new one.
    types::AggregateType next = *store.get(*outer).as<types::AggregateType>();
    for (auto &f : next.fields)
      if (f.bit_offset == outer_field->bit_offset && f.bit_size == 0) f.type = b.pointer_id;
    types::TypeGraph g;
    g.add(types::Type(std::move(next)));
    b.outer_id = store.intern(g).at(0);
    resp.set_outer_named_key(outer_key);
  }
  EmitNodes(store, program, c.closure, b, resp);
  const auto &done = *store.get(b.struct_id).as<types::AggregateType>();
  std::map<std::uint64_t, const infer::PlannedField *> planned;
  for (const auto &p : plan.fields) planned.emplace(p.offset, &p);
  for (const types::Field &f : done.fields) {
    const std::uint64_t off = f.bit_offset / 8;
    auto it = planned.find(off);
    const bool is_new = it != planned.end() && !it->second->existing && f.bit_size == 0 && made_here.contains(off);
    const bool was_edited = edited.contains(off) && f.bit_size == 0;
    AddField(resp, store, f, is_new || (was_edited && !existing) ? pb::AUTO_STRUCTURE_FIELD_SOURCE_ACCESS : pb::AUTO_STRUCTURE_FIELD_SOURCE_EXISTING,
             it != planned.end() ? it->second->accesses : 0, is_new && !was_edited && it->second->truncated, was_edited);
  }
  resp.set_size(done.size);
  return Status::Ok();
}

Status FromRange(const AutoStructContext &c, const pb::AutoStructureRequest &req, pb::AutoStructureResponse &resp,
                 types::TypeStore &store, ProgramTypes &program, const cparse::Profile &profile) {
  const cparse::LayoutRules &rules = profile.rules;
  const pb::AddressRange &r = req.range();
  if (!r.first().space().empty() || !r.last().space().empty())
    return Error(StatusCode::kInvalidArgument, "the range must be in the program's default space");
  const std::uint64_t first = r.first().offset(), last = r.last().offset();
  if (last < first) return Error(StatusCode::kInvalidArgument, "range.last is before range.first");
  if (last - first >= kMaxRange) return Error(StatusCode::kInvalidArgument, "the range is larger than 1 MiB");
  if (req.mode() == pb::AUTO_STRUCTURE_MODE_FILL)
    return Error(StatusCode::kInvalidArgument, "FILL applies to a variable; a range creates a structure");
  if (!c.program.block_containing(first) || !c.program.block_containing(last))
    return Error(StatusCode::kInvalidArgument, "the range is outside the program's memory");

  types::AggregateType agg;
  agg.kind = types::AggregateKind::Struct;
  agg.size = last - first + 1;
  const std::string name = req.name().empty() ? UniqueName(c.names, "astruct") : req.name();
  if (!ValidName(name)) return Error(StatusCode::kInvalidArgument, "not a C name: " + name);
  if (!req.name().empty() && NameTaken(c.names, "struct " + name))
    return Error(StatusCode::kAlreadyExists, "struct " + name + " exists; choose another name");
  agg.name = name;
  const TypeId plain_char = store.int_type(1, rules.char_signed, types::IntRank::PlainChar);
  const analysis::DataList &data = c.data();
  auto it = std::lower_bound(data.items.begin(), data.items.end(), first,
                             [](const analysis::DataItem &d, std::uint64_t a) { return d.address < a; });
  if (it != data.items.begin() && std::prev(it)->last() >= first) --it;
  for (; it != data.items.end() && it->address <= last; ++it) {
    const analysis::DataItem &d = *it;
    if (d.address < first || d.last() > last || d.length == 0) continue;  // not wholly inside: filler
    std::optional<TypeId> type;
    if (d.origin == analysis::kDataUser && !d.spec.item_type.empty()) type = program.intern(d.spec.item_type);
    if (!type) {
      switch (d.kind) {
        case analysis::DataKind::string: type = store.array_of(plain_char, d.length); break;
        case analysis::DataKind::unicode:
          type = store.array_of(store.int_type(2, false, types::IntRank::Char16), d.length / 2);
          break;
        case analysis::DataKind::unicode32:
          type = store.array_of(store.int_type(4, false, types::IntRank::Char32), d.length / 4);
          break;
        case analysis::DataKind::pointer:
          if (d.length == rules.pointer_size) type = store.pointer_to(store.undefined(1), rules.pointer_size);
          break;
        default:
          break;  // undefined bytes and labels: filler
      }
    }
    if (!type || store.size_of(*type) == 0 || store.size_of(*type) > d.length) continue;
    agg.fields.push_back({infer::field_name(d.address - first), *type, (d.address - first) * 8, 0});
  }
  if (agg.fields.empty() && req.edits().empty()) resp.add_notes("no data is defined in the range: the structure is undefined bytes");
  resp.set_name(name);
  resp.set_named_key("struct " + name);
  const std::set<std::uint64_t> edited = ApplyEdits(agg, req, store, program, profile, resp);
  const Built b = MakeStruct(store, agg, rules.pointer_size);
  EmitNodes(store, program, c.closure, b, resp);
  const auto &done = *store.get(b.struct_id).as<types::AggregateType>();
  for (const types::Field &f : done.fields)
    AddField(resp, store, f, pb::AUTO_STRUCTURE_FIELD_SOURCE_DATA, 0, false, f.bit_size == 0 && edited.contains(f.bit_offset / 8));
  resp.set_size(done.size);
  return Status::Ok();
}

}  // namespace

Status AutoStructure(const AutoStructContext &c, const pb::AutoStructureRequest &req, pb::AutoStructureResponse &resp) {
  types::TypeStore store;
  ProgramTypes program(c.names, c.closure, store);
  const cparse::Profile profile = ProgramProfile(c.program);
  if (req.edits_size() > 4096) return Error(StatusCode::kInvalidArgument, "at most 4096 edits");
  switch (req.source_case()) {
    case pb::AutoStructureRequest::kVariable:
    case pb::AutoStructureRequest::kField: return FromVariable(c, req, resp, store, program, profile);
    case pb::AutoStructureRequest::kRange: return FromRange(c, req, resp, store, program, profile);
    default: return Error(StatusCode::kInvalidArgument, "a variable or a range is required");
  }
}

}  // namespace revkit::backend
