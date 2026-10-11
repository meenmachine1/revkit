// What Ghidra's Decompiler Parameter ID analyzer commits for one function
// (DecompilerParameterIdCmd.analyzeFunction with its default options:
// HighFunctionDBUtil.commitParamsToDatabase(hfunc, useDataTypes = true,
// COMMIT_NO_VOID, ANALYSIS)), read from the decompiler's own model of the
// function after a "decompile" run with unreachable-code elimination off.
// docs/param-id.md has the whole behaviour; inputs::apply_param_id lays a
// result over a function's facts.
#pragma once

#include "revkit/lift/decomp_inputs.hh"

#include <cstdint>
#include <string>
#include <vector>

namespace ghidra {
class Datatype;
class Funcdata;
class TypeFactory;
}  // namespace ghidra

namespace revkit::lift {

class InputDecompiler;

struct CommittedSignature {
  enum class Status : std::uint8_t {
    committed = 0,  // the decompilation completed: the signature below is committed
    failed = 1,     // it didn't (an error, a timeout, a crash): nothing is committed
    skipped = 2,    // the analyzer doesn't decompile it (see inputs::param_id_plan)
  };
  Status status = Status::skipped;
  std::string detail;  // why not committed

  // getPrototypeModelForCommit: the decompiler's model, the compiler
  // spec's default where it was "unknown".
  std::string convention;
  bool varargs = false;
  // updateFunction(DYNAMIC_STORAGE_ALL_PARAMS) assigns storage from the
  // convention; where that differs from the decompiler's, CUSTOM_STORAGE.
  bool custom_storage = false;
  // COMMIT_NO_VOID: a void return keeps the function's return as it was.
  bool return_committed = false;
  FunctionFacts::Return ret;
  // LocalSymbolMap's parameter symbols in order: name, type, storage.
  std::vector<ParamFacts> params;
};

// A use of a decompiler data type as Ghidra's Java side writes it back
// (PcodeDataTypeManager.encodeTypeRef after decoding it): integers,
// pointers and arrays inline, other named types by reference. Null types
// are void. A type only the decompiler has becomes undefined bytes of its
// size from `types`.
DecompElement type_reference(const ghidra::Datatype *t, ghidra::TypeFactory *types = nullptr);

// The signature commitParamsToDatabase would commit from `fd`, which
// `decompiler` has just decompiled (the function at `entry`, described by
// `facts`, its facts as the decompiler was told them).
CommittedSignature commit_signature(InputDecompiler &decompiler, ghidra::Funcdata &fd, const FunctionFacts &facts);

}  // namespace revkit::lift
