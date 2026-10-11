// Whole-type rewrites that produce new interned types.
#pragma once

#include "revkit/types/store.h"

#include <map>
#include <span>
#include <string>
#include <vector>

namespace revkit::types {

struct WithoutTypedefsOptions {
  // Give an anonymous struct or union the name of a typedef that names it
  // directly (typedef struct { ... } point;), as C++ does for linkage and
  // clang's CodeView does even for C. (It leaves anonymous enums unnamed.)
  bool name_anonymous_tags = false;
};

// The types with every typedef replaced by its target, everywhere inside
// them (fields, elements, pointees, parameters, return types), and runs of
// qualifiers the typedefs separated merged into one. This is the view of a
// type that CodeView records, which has no typedefs: a DWARF type passed
// through this hashes like the PDB's type for the same C declaration.
std::vector<TypeId> without_typedefs(TypeStore &store, std::span<const TypeId> roots,
                                     const WithoutTypedefsOptions &options = {});
TypeId without_typedefs(TypeStore &store, TypeId root, const WithoutTypedefsOptions &options = {});

// The types with every reference to an incomplete struct, union or enum
// that `definitions` (keyed as describe.h's named_key: "struct foo") has a
// definition for replaced by that definition, everywhere inside them and
// inside the definitions. This is what the DWARF importer does with a
// declaration whose binary has exactly one definition: a translation unit
// that only declares `struct lua_State` uses the one another unit defines.
std::vector<TypeId> resolve_declarations(TypeStore &store, std::span<const TypeId> roots,
                                         const std::map<std::string, TypeId> &definitions);

}  // namespace revkit::types
