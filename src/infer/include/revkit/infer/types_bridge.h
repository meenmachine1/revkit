// Inferred prototypes as revkit::types function types, so front ends that
// encode debug-info and asserted prototypes for the decompiler
// (inputs::GhidraTypes) can encode inferred ones the same way.
#pragma once

#include "revkit/infer/vtype.h"
#include "revkit/types/store.h"

namespace revkit::infer {

// The type of `t` in `store`: integers get the C rank of their size
// (long on LP64, long long on LLP64), unknowns are undefined of their
// size, named structs are incomplete aggregates, functions with a
// signature are function types.
types::TypeId to_type(const VType &t, types::TypeStore &store, const DataOrg &org);

// The function type of `p` (parameters unnamed).
types::TypeId to_type(const Prototype &p, types::TypeStore &store, const DataOrg &org);

}  // namespace revkit::infer
