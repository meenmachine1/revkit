#include "revkit/types/transform.h"

#include "revkit/types/describe.h"

#include <unordered_map>

namespace revkit::types {

std::vector<TypeId> without_typedefs(TypeStore &store, std::span<const TypeId> roots,
                                     const WithoutTypedefsOptions &options) {
  // Everything reachable, in DFS preorder.
  std::vector<TypeId> order;
  std::unordered_map<TypeId, std::uint32_t> seen;
  std::vector<TypeId> stack(roots.rbegin(), roots.rend());
  while (!stack.empty()) {
    TypeId id = stack.back();
    stack.pop_back();
    if (!seen.emplace(id, std::uint32_t(order.size())).second) continue;
    order.push_back(id);
    Type t = store.get(id);
    std::vector<TypeId> refs;
    for_each_ref(t, [&](TypeId &r, EdgeKind) { refs.push_back(r); });
    for (auto it = refs.rbegin(); it != refs.rend(); ++it) stack.push_back(*it);
  }

  // A typedef, or a qualifier node with no bits once merged, stands for
  // the type below it. Chains are bounded by the store's size (the store
  // rejects cycles of typedefs and qualifiers).
  auto merged = [&](TypeId id, std::uint8_t &quals) {
    quals = 0;
    for (std::size_t k = 0; k <= store.size(); ++k) {
      const Type &t = store.get(id);
      if (auto *d = t.as<TypedefType>()) id = d->target;
      else if (auto *q = t.as<QualifiedType>()) {
        quals |= q->quals;
        id = q->target;
      } else break;
    }
    return id;
  };
  auto resolve = [&](TypeId id) {
    for (std::size_t k = 0; k <= store.size(); ++k) {
      const Type &t = store.get(id);
      if (auto *d = t.as<TypedefType>()) {
        id = d->target;
        continue;
      }
      if (t.as<QualifiedType>()) {
        std::uint8_t q;
        TypeId base = merged(id, q);
        if (q == 0) {
          id = base;
          continue;
        }
      }
      break;
    }
    return id;
  };

  TypeGraph g;
  std::unordered_map<TypeId, TypeId> local;
  for (TypeId id : order)
    if (resolve(id) == id) local.emplace(id, g.reserve());
  auto map = [&](TypeId id) { return local.at(resolve(id)); };

  std::unordered_map<TypeId, std::string> names;  // anonymous tag -> typedef name
  if (options.name_anonymous_tags) {
    for (TypeId id : order) {
      const auto *d = store.get(id).as<TypedefType>();
      if (!d) continue;
      const Type &target = store.get(d->target);
      const auto *a = target.as<AggregateType>();
      if (a && a->name.empty()) names.emplace(d->target, d->name);
    }
  }

  for (auto &[id, l] : local) {
    Type t = store.get(id);
    if (t.as<QualifiedType>()) {
      std::uint8_t q;
      TypeId base = merged(id, q);
      g.set(l, QualifiedType{local.at(base), q});
      continue;
    }
    for_each_ref(t, [&](TypeId &r, EdgeKind) { r = map(r); });
    if (auto it = names.find(id); it != names.end()) t.as<AggregateType>()->name = it->second;
    g.set(l, std::move(t));
  }
  std::vector<TypeId> ids = store.intern(g);
  std::vector<TypeId> out;
  out.reserve(roots.size());
  for (TypeId r : roots) out.push_back(ids[map(r).index()]);
  return out;
}

TypeId without_typedefs(TypeStore &store, TypeId root, const WithoutTypedefsOptions &options) {
  return without_typedefs(store, std::span<const TypeId>(&root, 1), options)[0];
}

std::vector<TypeId> resolve_declarations(TypeStore &store, std::span<const TypeId> roots,
                                         const std::map<std::string, TypeId> &definitions) {
  auto substitute = [&](TypeId id) {
    const Type &t = store.get(id);
    bool incomplete = false;
    if (const auto *a = t.as<AggregateType>()) incomplete = !a->complete && !a->name.empty();
    else if (const auto *e = t.as<EnumType>()) incomplete = !e->complete && !e->name.empty();
    if (!incomplete) return id;
    auto it = definitions.find(named_key(store, id));
    return it == definitions.end() ? id : it->second;
  };
  std::vector<TypeId> order;
  std::unordered_map<TypeId, std::uint32_t> seen;
  std::vector<TypeId> stack;
  for (auto it = roots.rbegin(); it != roots.rend(); ++it) stack.push_back(substitute(*it));
  while (!stack.empty()) {
    TypeId id = stack.back();
    stack.pop_back();
    if (!seen.emplace(id, std::uint32_t(order.size())).second) continue;
    order.push_back(id);
    Type t = store.get(id);
    for_each_ref(t, [&](TypeId &r, EdgeKind) { stack.push_back(substitute(r)); });
  }
  TypeGraph g;
  std::unordered_map<TypeId, TypeId> local;
  for (TypeId id : order) local.emplace(id, g.reserve());
  for (TypeId id : order) {
    Type t = store.get(id);
    for_each_ref(t, [&](TypeId &r, EdgeKind) { r = local.at(substitute(r)); });
    g.set(local.at(id), std::move(t));
  }
  std::vector<TypeId> ids = store.intern(g);
  std::vector<TypeId> out;
  out.reserve(roots.size());
  for (TypeId r : roots) out.push_back(ids[local.at(substitute(r)).index()]);
  return out;
}

}  // namespace revkit::types
