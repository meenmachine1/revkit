// Debug info into decompiler inputs (debug.cc).
#pragma once

#include "revkit/inputs/debug_info.h"
#include "revkit/inputs/inputs.h"
#include "revkit/types/store.h"

#include <optional>
#include <string>

namespace revkit::inputs {


// Adds functions' signatures, locals and namespaces, global variables and
// the types they use to `in`.
void apply_debug_info(const DebugInfo &debug, const loader::Image &image, lift::DecompilerInputs &in,
                      const Options &options);

}  // namespace revkit::inputs
