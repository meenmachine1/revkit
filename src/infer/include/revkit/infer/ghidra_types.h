// Inferred types as Ghidra decompiler types, for front ends that run the
// decompiler themselves (the image backend locks callees' prototypes with
// these, as it does debug-info prototypes).
#pragma once

#include "revkit/infer/vtype.h"

#include "architecture.hh"
#include "fspec.hh"

namespace revkit::infer {

// Whether the decompiler can take `t`: no zero-size type, array of none or
// array of zero-size elements, at any pointer depth (it divides by sizes).
// A pointer to an incomplete struct or union (size 0) is fine: that is the
// decompiler's own forward declaration, as for `_IO_FILE *`.
bool decompiler_safe(const ghidra::Datatype &t);

// A value's type as a parameter or return type (structs by value and bare
// functions become opaque bytes, as does any type decompiler_safe rejects).
ghidra::Datatype *value_type(ghidra::Architecture &arch, const VType &t);

// The pieces of a locked prototype (FuncProto::setPieces), in the
// architecture's default model.
ghidra::PrototypePieces prototype_pieces(ghidra::Architecture &arch, const Prototype &p);

}  // namespace revkit::infer
