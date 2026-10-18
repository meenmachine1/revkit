// Go's function table as analysis-rank assertions (docs/go.md): the
// pclntab (revkit/loader/gopclntab.hh) of a Go program, staged with the
// import as analysis:go, as the PE and Objective-C passes are
// (msvc_import.h):
//
//   FUNCTION_BOUNDS  a function at every entry (a seed; flow finds the body)
//   NAME             Go's name for it, where neither the file's symbols nor
//                    the debug info name the address
//   COMMENT          a plate comment with its source file and line (and
//                    Go's own spelling when the name had to change)
//   NO_RETURN        Go's runtime functions that never return
//
// Analysis ranks below every other provenance, so a user's names, the
// debug info's and an agent's all win, and reverting analysis:go takes
// the whole pass back.
#pragma once

#include "msvc_import.h"

#include <optional>
#include <string>
#include <vector>

namespace revkit::backend {

class Program;

// The assertions for `program`'s Go functions; nullopt for a program with
// no pclntab. A table that is there but doesn't decode gives no assertions
// and the reason in `warnings`.
std::optional<AnalysisFacts> CollectGoAnalysis(const Program &program, const std::vector<DebugFacts> &debug);

}  // namespace revkit::backend
