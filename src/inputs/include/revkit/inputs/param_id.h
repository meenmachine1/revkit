// Ghidra's Decompiler Parameter ID analyzer (DecompilerFunctionAnalyzer,
// DecompilerParameterIdCmd): every function is decompiled, callees before
// callers, and the parameters, return and calling convention the
// decompiler finds are committed to the program with source ANALYSIS, so
// callers decompile with them. docs/param-id.md has the behaviour in full.
//
// This part is what doesn't need the decompiler: whether Ghidra runs the
// analyzer on a program, the order it decompiles in (AcyclicCallGraphBuilder),
// which functions it skips, and how a committed signature lands in a
// function's facts. The decompiling is decompd::param_id_functions (rk-lift)
// and the backend's analysis.param_id query.
#pragma once

#include "revkit/analysis/analysis.h"
#include "revkit/lift/decomp_inputs.hh"
#include "revkit/lift/param_id.hh"
#include "revkit/loader/image.hh"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace revkit::inputs {

// Whether the analyzer runs: `automatic` is Ghidra's default enablement
// (DecompilerFunctionAnalyzer.getDefaultEnablement: a PE whose memory has
// fewer than 2 MiB of addresses); on and off force it.
enum class ParamIdMode { automatic, on, off };
std::optional<ParamIdMode> parse_param_id_mode(const std::string &s);
const char *param_id_mode_name(ParamIdMode m);

// Ghidra's default enablement for a program with these memory blocks
// (Memory.getNumAddresses: every block's size).
bool param_id_default(const loader::Image &image, const std::vector<lift::BlockFacts> &memory);
bool param_id_enabled(ParamIdMode mode, const loader::Image &image, const std::vector<lift::BlockFacts> &memory);

// A function as AcyclicCallGraphBuilder sees it.
struct CallGraphNode {
  std::uint64_t entry = 0;
  // A thunk: the function it finally thunks (getThunkedFunction(true)),
  // nullopt when that is external (an import).
  bool thunk = false;
  std::optional<std::uint64_t> thunk_target;
  // A thunk of an import: the external function's offset in Ghidra's
  // EXTERNAL space (only the walk's start order depends on it).
  std::optional<std::uint64_t> external;
  // An external entry point reference (the program's entry, exports,
  // processor vectors) makes it a start of the depth-first walk.
  bool entry_point = false;
  // Its body's call references in address order of the calling instruction
  // (computed calls discovery resolved and CALL_RETURN jumps included).
  std::vector<std::uint64_t> calls;
};

// Discovery's functions as call graph nodes. `flow` gives a function's
// flow by FunctionInfo::flow_key(); `info` the seeds.
std::vector<CallGraphNode> call_graph_nodes(const analysis::FunctionList &functions, const analysis::ProgramInfo &info,
                                            const std::function<const analysis::FlowGraph &(std::uint64_t key)> &flow);

// The analyzer's dependency graph: AcyclicCallGraphBuilder(program, set,
// killThunks = true). Thunks are replaced by the functions they thunk;
// a node depends on the functions it calls, except a call back to a
// function on the depth-first walk's stack (recursion), which is dropped,
// so the callee in a cycle is decompiled first, with its caller still
// uncommitted. The walk starts at entry points and functions nothing
// calls, in the order Java's HashSet of their addresses iterates, then at
// the lowest address left.
struct ParamIdPlan {
  std::vector<std::uint64_t> nodes;  // sorted
  // Each node's dependencies (sorted, unique): the callees committed
  // before it is decompiled, the only functions it sees committed.
  std::map<std::uint64_t, std::vector<std::uint64_t>> dependencies;
  // Thunks and the functions they finally thunk (for reading a thunk's
  // signature from its target's).
  std::map<std::uint64_t, std::optional<std::uint64_t>> thunks;

  const std::vector<std::uint64_t> &dependencies_of(std::uint64_t node) const;
  // Nodes in rounds: each round's dependencies are in earlier rounds.
  std::vector<std::vector<std::uint64_t>> rounds() const;
  void encode(facts::Encoder &e) const;
  static ParamIdPlan decode(facts::Decoder &d);
  friend bool operator==(const ParamIdPlan &, const ParamIdPlan &) = default;
};
// `space`: the name of the address space function entries are in.
ParamIdPlan param_id_plan(const std::vector<CallGraphNode> &nodes, const std::string &space = "ram");

// The order a java.util.HashSet<Address> holding these addresses of
// `space` (inserted in this order) iterates them in (for tests).
std::vector<std::uint64_t> java_address_set_order(const std::vector<std::uint64_t> &keys,
                                                  const std::string &space = "ram");

// Why DecompilerParameterIdCmd.analyzeFunction leaves a function alone,
// or nullopt if it decompiles it: a thunk; a signature with a source other
// than DEFAULT (debug info, a type archive, the user: those outrank the
// analyzer; ANALYSIS ones it first resets); in a block of external glue
// (EXTERNAL, .plt, __stub_helper).
std::optional<std::string> param_id_skip(const lift::FunctionFacts &f, bool thunk,
                                         const std::vector<lift::BlockFacts> &memory);

// The function's facts with the committed signature over them
// (commitParamsToDatabase with source ANALYSIS); nothing changes unless
// it was committed.
void apply_param_id(lift::FunctionFacts &f, const lift::CommittedSignature &s);

// Every function's committed signature over the inputs: functions and
// thunks of them (a thunk shows its target's signature), as Ghidra's
// database has them after the analyzer.
void apply_param_id(lift::DecompilerInputs &inputs, const ParamIdPlan &plan,
                    const std::map<std::uint64_t, lift::CommittedSignature> &results);

}  // namespace revkit::inputs
