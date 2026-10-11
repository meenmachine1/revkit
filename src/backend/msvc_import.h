// Microsoft-specific analysis as analysis-rank assertions (docs/pe.md):
// revkit::msvc's markup of a PE (RTTI and vftables, the PE headers and
// directories, exception data) as the assertions a user's edits would
// make, with provenance analysis:<pass>, staged with the import:
//
//   TYPE_DEF      the structures' types, the class structs and vftables
//   CODE_UNIT     typed data (a "data" mark, as Define data makes one)
//   NAME          the structures, vftables, virtual functions, labels
//   FUNCTION_BOUNDS  functions to make (a seed: vftable entries, exception
//                    handlers, TLS callbacks, guarded call targets)
//   TYPE          a virtual method's prototype carrying its `this` type,
//                 which at analysis rank types `this` only (own_inputs.cc)
//
// Analysis ranks below every other provenance: a user's edit, the debug
// info (import:pdb, import:dwarf) and an agent's all win, and a revert of
// analysis:<pass> takes the whole pass back.
#pragma once

#include "debug_import.h"

#include "revkit/facts/fact.h"
#include "revkit/msvc/msvc.h"
#include "revkit/v1/assertion.pb.h"

#include <cstdint>
#include <map>
#include <string>
#include <variant>
#include <vector>

namespace revkit::backend {

namespace pb = ::revkit::v1;
class Program;

struct AnalysisAssertion {
  facts::FactKind kind = facts::FactKind::Name;
  std::uint64_t address = 0;  // TYPE_DEF: unused
  std::string sub;
  facts::FactValue value;
  pb::AssertionBody body;  // what the API shows (empty for a TYPE_DEF)
};

struct AnalysisFacts {
  std::string source;  // the provenance id: "msvc"
  std::vector<AnalysisAssertion> assertions;
  std::map<std::string, std::size_t> counts;  // msvc::Markup::counts
  std::vector<std::string> warnings;
};

// The markup of `program`'s image as assertions, one AnalysisFacts per
// pass ("pe": headers, directories, exception tables; "msvc": RTTI,
// vftables, C++ exception data), where the program is a PE. Names the
// loader's symbols or `debug` give an address are kept; a class the PDB
// defines is `this`'s type as the PDB has it.
std::vector<AnalysisFacts> CollectPeAnalysis(const Program &program, const std::vector<DebugFacts> &debug);

}  // namespace revkit::backend
