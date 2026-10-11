// Ghidra's Decompiler Parameter ID in the image backend (docs/param-id.md),
// as fact-store queries, computed in the background after import and after
// every edit, and published to decompilations as they arrive.
//
//   param_id.mode           (input) auto, on or off, staged at import
//   analysis.param_id_plan  where the analyzer runs, and its dependency     <- param_id.mode, inputs.static,
//                           graph (inputs::param_id_plan)                       analysis.functions, every flow
//   analysis.param_id_deps  one function's slice of the plan                <- analysis.param_id_plan
//   analysis.param_id       what the analyzer commits for one function:     <- analysis.param_id_deps, the
//                           its decompilation (mode param_id) with exactly       dependencies' param_id, and
//                           its dependencies' commits, the user's prototypes    what its decompilation looks
//                           and the debug info's over everything else            up (QueryLookup)
//   param_id.published      (input) the committed signature decompilations
//                           see, set by the backend's background analysis
//                           (ImageBackend: ParamIdAnalysis) once computed
//
// analysis.param_id is a pure function of the revision, so its results are
// the same whatever computes them and however many threads do. Decompilations
// (decompile.ghidra) read only param_id.published, one key per function
// they look up: a function's published signature changing re-decompiles it
// and the functions that call it, nothing else, and a decompilation never
// waits for the analysis (a program's first decompilation is as fast as
// without it, then is redone when its callees' signatures arrive).
#pragma once

#include "revkit/facts/engine.h"
#include "revkit/inputs/codec.h"
#include "revkit/inputs/param_id.h"
#include "revkit/lift/param_id.hh"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace revkit::backend {

struct ParamIdPlanValue {
  bool enabled = false;
  inputs::ParamIdPlan plan;

  void encode(facts::Encoder &e) const;
  static ParamIdPlanValue decode(facts::Decoder &d);
  friend bool operator==(const ParamIdPlanValue &, const ParamIdPlanValue &) = default;
};

struct ParamIdSlice {
  bool node = false;                 // the analyzer decompiles it
  std::vector<std::uint64_t> deps;   // what it sees committed

  void encode(facts::Encoder &e) const;
  static ParamIdSlice decode(facts::Decoder &d);
  friend bool operator==(const ParamIdSlice &, const ParamIdSlice &) = default;
};

namespace q {

struct ParamIdModeInput {
  static constexpr std::string_view name = "param_id.mode";
  using Key = std::string;      // program id
  using Value = std::uint8_t;  // inputs::ParamIdMode; unset: automatic
};

struct ParamIdPublished {
  static constexpr std::string_view name = "param_id.published";
  using Key = std::pair<std::string, std::uint64_t>;  // (program, entry: a function or a thunk of one)
  using Value = std::optional<lift::CommittedSignature>;
};

struct ParamIdPlan {
  static constexpr std::string_view name = "analysis.param_id_plan";
  static constexpr std::uint32_t version = 1;
  using Key = std::string;
  using Value = ParamIdPlanValue;
  static Value compute(facts::QueryContext &ctx, const Key &program);
  static std::size_t weight(const Value &v);
};

struct ParamIdDeps {
  static constexpr std::string_view name = "analysis.param_id_deps";
  static constexpr std::uint32_t version = 1;
  using Key = std::pair<std::string, std::uint64_t>;
  using Value = ParamIdSlice;
  static Value compute(facts::QueryContext &ctx, const Key &key);
};

struct ParamId {
  static constexpr std::string_view name = "analysis.param_id";
  static constexpr std::uint32_t version = 2;  // 2: patched bytes through patch.page
  using Key = std::pair<std::string, std::uint64_t>;
  using Value = lift::CommittedSignature;
  static Value compute(facts::QueryContext &ctx, const Key &key);
};

}  // namespace q

void RegisterParamIdQueries(facts::Engine &engine);

// The function a thunk finally thunks (analysis.function's thunk targets
// followed), or `entry` itself if it isn't a thunk; nullopt for a thunk of
// an import.
std::optional<std::uint64_t> ThunkedFunction(facts::QueryContext &ctx, const std::string &program, std::uint64_t entry);

}  // namespace revkit::backend
