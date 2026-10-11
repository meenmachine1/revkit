// Def-use chains and data-flow slices over a decompilation's data-flow
// graph (QueryService.SliceDecompiled, api_minor 57, feature
// "decompile-slices"; docs/api.md "Slices"): Ghidra's Highlight Def-use,
// Forward and Backward Slice, and Forward and Backward Inst Slice, as the
// tokens they mark and the instructions their ops belong to.
#pragma once

#include "revkit/api/backend.h"
#include "revkit/v1/query.pb.h"

namespace revkit::backend {

namespace pb = ::revkit::v1;

// Walks `fn`'s DecompiledFunction.dataflow (with each token's op_index)
// from what `req` names; fills `resp` but its snapshot. INVALID_ARGUMENT
// for a token, varnode or variable the function hasn't, or one that prints
// no value; FAILED_PRECONDITION when `fn` has no data-flow graph.
api::Status SliceFunction(const pb::DecompiledFunction &fn, const pb::SliceDecompiledRequest &req,
                          pb::SliceDecompiledResponse &resp);

}  // namespace revkit::backend
