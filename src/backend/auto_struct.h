// Structures from pointer use and from a listing selection
// (TypeService.AutoStructure; docs/types.md, "Structures from pointer
// use"): Ghidra's Auto Create Structure, Auto Fill in Structure and
// Create Structure from a selection, as DefineType-ready nodes the client
// asserts with a binding of the name and a retype (or a data definition)
// in one request.
#pragma once

#include "model.h"
#include "parse_c.h"
#include "queries.h"

#include "revkit/analysis/data.h"
#include "revkit/api/backend.h"
#include "revkit/facts/engine.h"
#include "revkit/infer/accesses.h"
#include "revkit/v1/types.pb.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace revkit::backend {

namespace q {

struct PointerAccessList {
  bool found = false;  // the function's decompilation has the variable
  std::vector<infer::PointerAccess> accesses;

  friend bool operator==(const PointerAccessList &, const PointerAccessList &) = default;
  void encode(facts::Encoder &e) const;
  static PointerAccessList decode(facts::Decoder &d);
};

// The accesses through one variable of a function (by its decompilation's
// storage key), as its decompilation's p-code shows them
// (infer::pointer_accesses, collected by the decompiler worker).
struct PointerAccesses {
  static constexpr std::string_view name = "infer.pointer_accesses";
  static constexpr std::uint32_t version = 1;
  using Key = std::pair<AddressKey, std::string>;  // ((program id, function entry), storage key)
  using Value = PointerAccessList;
  static Value compute(facts::QueryContext &ctx, const Key &key);
};

}  // namespace q

void RegisterAutoStructQueries(facts::Engine &engine);

// What AutoStructure reads, from the request's snapshot.
struct AutoStructContext {
  const Program &program;
  const NamedTypes &names;
  ProgramTypes::Closure closure;
  // A function's decompilation (decompile.ghidra); throws
  // DecompileStoppedError when cancelled.
  std::function<facts::Ref<DecompileOutput>(std::uint64_t entry)> decompile;
  // infer.pointer_accesses.
  std::function<q::PointerAccessList(std::uint64_t entry, const std::string &key)> accesses;
  // The function to decompile for a call to `entry` (a direct thunk's
  // target), or nullopt when there is none to follow into (an import).
  std::function<std::optional<std::uint64_t>(std::uint64_t entry)> function;
  // A variable's asserted type, by hash ("" when none, or text).
  std::function<std::string(std::uint64_t entry, const std::string &key)> local_type;
  // The program's data items (analysis.data).
  std::function<const analysis::DataList &()> data;
  std::function<bool()> cancelled;
};

api::Status AutoStructure(const AutoStructContext &c, const pb::AutoStructureRequest &req,
                          pb::AutoStructureResponse &resp);

}  // namespace revkit::backend
