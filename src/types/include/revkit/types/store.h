// TypeStore: program-independent, content-hashed, interned types.
//
// Types are immutable once interned. Acyclic types can be interned one at a
// time; types that refer to each other (struct node { struct node *next; })
// are built in a TypeGraph with graph-local ids and interned as a batch,
// which minimizes the graph and hashes each strongly connected component
// canonically, so equal types get equal hashes whatever graph they came from.
#pragma once

#include "revkit/types/hash.h"
#include "revkit/types/type.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace revkit::types {

class TypeStore;

// A batch of types under construction. Nodes may reference each other by
// the local ids this hands out, and may reference store types directly.
class TypeGraph {
 public:
  TypeId add(Type t);
  TypeId reserve();  // a node to fill in later with set()
  void set(TypeId local, Type t);
  Type &at(TypeId local);
  const Type &at(TypeId local) const;
  bool is_set(TypeId local) const;
  std::size_t size() const { return nodes_.size(); }

  // Breaks cycles a TypeStore would reject (a cycle that passes through no
  // struct or union, or a struct that contains itself by value) by pointing
  // the offending edges at an undefined type. Real compilers never produce
  // these; malformed debug info can. Returns the number of edges changed.
  std::size_t break_invalid_cycles();

  // Natural alignment of a local or store type.
  std::uint32_t align_of(TypeId id, const TypeStore &store) const;

 private:
  std::vector<std::optional<Type>> nodes_;
  mutable std::vector<std::uint32_t> align_cache_;  // cleared on any change
};

class TypeStore {
 public:
  TypeStore();

  // Interns every node of `graph` and returns the store id for each local
  // node, by local index. Throws std::invalid_argument if a node is unset,
  // a reference is out of range, or the graph has a cycle that
  // TypeGraph::break_invalid_cycles() would break.
  std::vector<TypeId> intern(const TypeGraph &graph);

  // Interns one type whose references are all store ids.
  TypeId intern(Type t);

  // Shorthands.
  TypeId void_type();
  TypeId bool_type(std::uint32_t size = 1);
  TypeId int_type(std::uint32_t size, bool is_signed, IntRank rank = IntRank::Fixed);
  TypeId float_type(std::uint32_t size, FloatKind kind);
  TypeId pointer_to(TypeId target, std::uint32_t size = 8, PointerKind kind = PointerKind::Pointer);
  TypeId array_of(TypeId element, std::uint64_t count);
  TypeId typedef_of(std::string name, TypeId target);
  TypeId qualified(TypeId target, std::uint8_t quals);
  TypeId undefined(std::uint32_t size);
  TypeId function(FunctionType f);

  std::size_t size() const { return types_.size(); }
  const Type &get(TypeId id) const;
  Kind kind(TypeId id) const { return get(id).kind(); }
  const Hash &hash(TypeId id) const;
  std::optional<TypeId> find(const Hash &h) const;
  // Named aggregates, enums and typedefs with this name, in interning order.
  std::vector<TypeId> lookup(std::string_view name) const;

  // Size in bytes (0 for void, functions and unknown-bound arrays).
  std::uint64_t size_of(TypeId id) const;
  std::uint32_t align_of(TypeId id) const;
  // Follows typedefs (and qualifiers, if asked) to the underlying type.
  TypeId strip_typedefs(TypeId id, bool qualifiers = true) const;

  // Members of id's strongly connected component if id is part of a cycle,
  // else empty.
  std::span<const TypeId> cycle_of(TypeId id) const;

 private:
  const Type &checked(TypeId id) const;

  std::vector<Type> types_;
  std::vector<Hash> hashes_;
  std::vector<std::uint32_t> scc_;  // per type: index into sccs_, or kNoScc
  std::vector<std::vector<TypeId>> sccs_;
  std::unordered_map<Hash, TypeId> by_hash_;
  std::unordered_multimap<std::string, TypeId> by_name_;
  mutable std::vector<std::uint32_t> align_cache_;
};

}  // namespace revkit::types
