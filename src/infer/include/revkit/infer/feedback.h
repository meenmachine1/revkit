// Inferred prototypes back into the decompiler.
//
// The decompiler takes a locked prototype for every function it sees (the
// one it decompiles and the ones that function calls) the way debug-info
// prototypes reach it in the image backend: parameter and return types,
// varargs, and no-return. prototype_for() (infer.h) is the interface for
// other decompiler front ends; decompile_all() is the stand-alone one used
// to measure what inference does to decompiled C.
#pragma once

#include "revkit/infer/infer.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace revkit::infer {

// Decompiles `entries` with every function's inferred prototype locked
// (feedback), or only the library prototypes of imports (without), on
// `pool` (null: the calling thread). Entry -> C, or "/* error */".
std::map<std::uint64_t, std::string> decompile_all(const facts::Snapshot &snapshot, const ProgramKey &program,
                                                   const std::vector<std::uint64_t> &entries, bool feedback,
                                                   facts::ThreadPool *pool);

}  // namespace revkit::infer
