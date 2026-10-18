// Inferred prototypes as revkit::types function types, so front ends that
// encode debug-info and asserted prototypes for the decompiler
// (inputs::GhidraTypes) can encode inferred ones the same way.
#pragma once

#include "revkit/infer/vtype.h"
#include "revkit/types/store.h"

#include <map>
#include <string>
#include <vector>

namespace revkit::infer {

// Inferred structures' ids in a store, by name.
using StructureIds = std::map<std::string, types::TypeId>;

// The type of `t` in `store`: integers get the C rank of their size
// (long on LP64, long long on LLP64), unknowns are undefined of their
// size, named structs are incomplete aggregates (or, for a name in
// `structures`, that inferred structure), functions with a signature are
// function types.
types::TypeId to_type(const VType &t, types::TypeStore &store, const DataOrg &org,
                      const StructureIds *structures = nullptr);

// The function type of `p` (parameters unnamed).
types::TypeId to_type(const Prototype &p, types::TypeStore &store, const DataOrg &org,
                      const StructureIds *structures = nullptr);

// Inferred structures as complete structs in `store` (one graph: they may
// point to each other and to themselves), fields named field_0x<offset>,
// packing classified by the importers' rule.
StructureIds to_types(const std::vector<InferredStructure> &structures, types::TypeStore &store, const DataOrg &org);

}  // namespace revkit::infer
