// Ghidra's evidence for functions that don't return, as a query.
//
//   analysis.no_return_evidence()  the entries Ghidra's "Non-Returning
//                                  Functions - Discovered" analyzer
//                                  (FindNoReturnFunctionsAnalyzer) marks
//
// Discovery's own no-return functions (FunctionInfo::no_return) are the
// known names plus those no path from the entry returns from, which stops
// bodies where Ghidra's would. The decompiler is told what Ghidra's
// database holds instead: the known names, and the functions this
// evidence finds. A call is evidence when what follows it isn't code that
// returns there: the next function starts in its fallthrough, the
// fallthrough doesn't decode, an instruction there overlaps a function's
// entry, or (x86) it is an INT3. A target with at least three such calls
// is non-returning; with fewer, it is if every path through it ends in a
// call to a non-returning function. Run twice, as Ghidra does when some
// targets were suspicious, so later passes see earlier results. Only
// targets in the program's code are judged: a call to an address no block
// maps (another DS module, ROM a firmware image lacks) returns. A target
// the user said returns (SetNoReturn false) is never marked.
//
// Reads analysis.functions, every function's analysis.flow, the bytes
// after calls (INT3) and the NoReturn assertions, so a change to discovery
// recomputes it.
#pragma once

#include "revkit/analysis/analysis.h"

#include <cstdint>
#include <string_view>
#include <vector>

namespace revkit::analysis {

struct NoReturnEvidence {
  static constexpr std::string_view name = "analysis.no_return_evidence";
  static constexpr std::uint32_t version = 5;  // 2: literal pools after a call are data; 3: patches
                                               // through patch.page; 4: fallthrough overrides; 5: only
                                               // targets in the program's code, and never one the
                                               // user said returns
  using Key = ProgramKey;
  using Value = std::vector<std::uint64_t>;  // sorted entries
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return k.id; }
};

}  // namespace revkit::analysis
