// Types as the fact store holds them: one TYPE_DEF assertion per type, its
// key's sub the type's content hash (revkit::types), its value this record.
// A record names the types it references by hash, so a hash in a prototype
// pins every type it reaches and records never change once written.
#pragma once

#include "revkit/types/store.h"

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::backend {

struct TypeRecord {
  // References inside `type` are TypeId::local(i), meaning refs[i].
  types::Type type;
  std::vector<std::string> refs;  // hex hashes, in for_each_ref order
};

std::string EncodeTypeRecord(const types::TypeStore &store, types::TypeId id);
// Throws facts::DecodeError on malformed input.
TypeRecord DecodeTypeRecord(std::string_view bytes);

// "struct foo", "class c", "union u", "enum e" or "typedef t" for a named
// struct, class, union, enum or typedef; "" for anything else, anonymous
// ones included. What a BindTypeName binds (its key's sub is "name:" + it).
std::string NamedTypeKey(const types::Type &t);
inline std::string TypeNameSub(const std::string &named) { return "name:" + named; }
inline bool IsTypeNameSub(const std::string &sub) { return sub.starts_with("name:"); }

// SetTypeCategory: TYPE_DEF "category:<named key>" = the category path.
inline constexpr std::string_view kTypeCategorySub = "category:";
inline std::string TypeCategorySub(const std::string &named) { return std::string(kTypeCategorySub) + named; }
inline bool IsTypeCategorySub(const std::string &sub) { return sub.starts_with(kTypeCategorySub); }

// A category path as stored: '/'-separated and absolute, without empty,
// "." or ".." parts or a trailing '/', at most 1024 bytes and 32 levels;
// "" (or "/") is the top. nullopt (and `error`) for anything else.
std::optional<std::string> NormalizeTypeCategory(std::string_view path, std::string *error = nullptr);

// Whether `key` is a named type key: "struct x", "union x", "class x",
// "enum x" or "typedef x".
bool IsNamedTypeKey(std::string_view key);

// The type a record's reference `id` names.
inline const std::string &RefHash(const TypeRecord &r, types::TypeId id) { return r.refs.at(id.index()); }

// Interns records (hash -> encoded record, closed under references) into
// `store` and returns the store id of each hash. A record that references
// a hash not in `records` makes that reference an undefined type.
std::map<std::string, types::TypeId> InternRecords(const std::map<std::string, std::string> &records,
                                                   types::TypeStore &store);

}  // namespace revkit::backend
