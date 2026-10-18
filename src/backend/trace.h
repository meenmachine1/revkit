// Value tracing across calls (QueryService.TraceValue, api_minor 89, feature
// "value-trace"; docs/api.md "Tracing a value across calls"): the slices'
// def-use walk (slice.cc) carried through direct calls. Going backward, a
// call's output continues at the callee's returned values and a parameter
// at each caller's argument; going forward, an argument continues at the
// callee's parameter and a returned value at the calls' outputs. Calls are
// matched: a walk that entered a callee from one call goes back out to that
// call only; a walk that leaves the function it started in goes to every
// caller. Budgets bound it (call depth, functions decompiled, nodes,
// edges), and what it can't follow is listed, not guessed: indirect calls,
// callees outside the program, values through memory, parameters of
// functions nothing calls, decompilations that failed.
#pragma once

#include "revkit/api/backend.h"
#include "revkit/v1/query.pb.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace revkit::backend {

namespace pb = ::revkit::v1;

struct TraceHooks {
  // A function's decompilation with its data-flow graph, or null with
  // *error saying why (the decompiler failed, no function there). The
  // pointer stays valid for the trace.
  std::function<const pb::DecompiledFunction *(std::uint64_t entry, std::string *error)> decompile;
  // The function a direct call instruction goes to, through thunks;
  // nullopt when it goes nowhere in the program (an import, no target).
  // `what` names it then ("strlen (import)").
  std::function<std::optional<std::uint64_t>(std::uint64_t call, std::string *what)> callee;
  // The direct calls of a function (through its thunks): each call
  // instruction and the function containing it.
  std::function<std::vector<std::pair<std::uint64_t, std::uint64_t>>(std::uint64_t entry)> callers;
  // A function's name, for captions.
  std::function<std::string(std::uint64_t entry)> name;
};

// Traces from `req`'s start in the function at `entry`, filling `resp`
// (all but the snapshot).
api::Status TraceValue(const TraceHooks &hooks, std::uint64_t entry, const pb::TraceValueRequest &req,
                       pb::TraceValueResponse &resp);

}  // namespace revkit::backend
