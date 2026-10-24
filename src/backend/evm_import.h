// An Ethereum Virtual Machine contract (docs/evm.md) as revkit imports it:
// a raw image of revkit's EVM processor (processors/EVM), laid out by
// EvmRawOptions, and the markup revkit::evm finds, staged with the import
// as analysis:evm assertions (as the Go and PE passes are, msvc_import.h):
//
//   FUNCTION_BOUNDS  the runtime's entry ("dispatcher"), the constructor's
//                    and a function at each selector the dispatcher tests
//   NAME             each one's: the well-known signature's ("transfer"),
//                    else func_0x<selector>; tag_<offset> on JUMPDESTs
//   COMMENT          a plate comment with the selector and its signature
//   CODE_UNIT        a code mark (Disassemble here) on every JUMPDEST, so
//                    discovery decodes all the code and data analysis takes
//                    no PUSH32 immediate for a string
//   REFERENCE        computed jumps' targets the stack analysis found, as
//                    computed-jump references, which flow and the
//                    decompiler follow
//
// Analysis ranks below every other provenance; reverting analysis:evm takes
// the whole pass back.
#pragma once

#include "msvc_import.h"

#include "revkit/loader/image.hh"
#include "revkit/v1/project.pb.h"

#include <optional>
#include <span>

namespace revkit::backend {

class Program;

// The raw options an EVM file loads with: language EVM, its bytes (binary
// or hex text) as one block "runtime" at 0, or for creation code a block
// "init" at evm::kCreationBase and the runtime it returns at 0. nullopt
// when the file isn't EVM bytecode.
std::optional<loader::RawOptions> EvmRawOptions(std::span<const std::byte> file);

// Whether a program is of revkit's EVM language.
bool IsEvm(const Program &program);

// The analysis:evm assertions for an EVM program; nullopt for others.
std::optional<AnalysisFacts> CollectEvmAnalysis(const Program &program);

// ProgramSummary.evm (api_minor 99).
void FillEvmSummary(const Program &program, pb::EvmSummary *out);

}  // namespace revkit::backend
