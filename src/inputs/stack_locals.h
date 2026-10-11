// Ghidra's stack variables for one function (stack_locals.cc).
#pragma once

#include "revkit/analysis/analysis.h"
#include "revkit/lift/decomp_inputs.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/image.hh"

#include <string>
#include <vector>

namespace revkit::inputs {

// The local_<offset> variables Ghidra's Stack analyzer makes for `f`
// (undefined types of the sizes its instructions access), leaving out any
// that overlap `protected_locals` (debug info's). Instructions are decoded
// from `image`'s bytes without their context commits, so the result
// doesn't depend on what `lifter` decoded before.
std::vector<lift::LocalFacts> stack_locals(lift::Lifter &lifter, const loader::Image &image,
                                           const std::string &language_id, bool pe,
                                           const analysis::FunctionInfo &f, const analysis::FlowGraph &g,
                                           const std::vector<lift::LocalFacts> &protected_locals);

}  // namespace revkit::inputs
