// A program's functions as Function ID sees them: each one's hash and its
// callers and callees (docs/fid.md), computed from revkit's discovery.
#pragma once

#include "revkit/analysis/analysis.h"
#include "revkit/fid/db.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace revkit::fid {

struct ProgramFunction {
  std::uint64_t entry = 0;
  std::string name;  // discovery's (or the caller's) name
  bool thunk = false;
  std::optional<HashQuad> hash;
  // Callees (FidProgramSeeker.getChildren: call targets in the body, thunks
  // followed) and callers (getParents: functions calling the entry or a
  // thunk of it), as indexes into ProgramHashes::functions, in Ghidra's
  // order (callees by call instruction, callers by calling instruction).
  std::vector<std::size_t> callees, callers;
  // Callees that are no function of the program (imports, an unrelocated
  // object file's external calls): the symbol named, for creating databases.
  std::vector<std::string> external_callees;
  bool has_terminator = false;  // a return or other terminal flow (FunctionRecord's HAS_TERMINATOR)
  // Instructions hashed (Function ID needs 4), and the calls in the body:
  // (call instruction, target address), by instruction.
  std::uint32_t instructions = 0;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> calls;
};

struct ProgramHashes {
  std::string language;  // without the compiler: "x86:LE:64:default"
  std::vector<ProgramFunction> functions;  // by entry
  const ProgramFunction *find(std::uint64_t entry) const;
};

// What hashing a program reads.
struct ProgramSource {
  std::string language;  // "x86:LE:64:default" (a trailing ":compiler" is ignored)
  const analysis::ProgramInfo *info = nullptr;
  const analysis::FunctionList *functions = nullptr;
  // The flow of a function by FunctionInfo::flow_key().
  std::function<std::shared_ptr<const analysis::FlowGraph>(std::uint64_t key)> flow;
  // The program's bytes (as patched); returns how many it read.
  std::function<std::size_t(std::uint64_t address, std::span<std::byte> out)> read;
  // Relocation addresses, sorted (the loader's: an object file's static
  // relocations, a PE's base relocations, an ELF's dynamic ones).
  std::vector<std::uint64_t> relocations;
  // Symbols at relocated call operands (object files): address -> name.
  std::map<std::uint64_t, std::string> relocation_symbols;
  // The functions Ghidra holds non-returning (inputs::ghidra_no_return:
  // the known names and its evidence), sorted: bodies end after calls to
  // them, as Ghidra's do, rather than after calls to every function
  // discovery infers never returns.
  std::vector<std::uint64_t> no_return;
  // Whether Ghidra's "Scalar Operand References" analyzer runs on the
  // program (every format but ELF): scalars that are addresses in memory
  // get references, which make whole-scalar operands addresses.
  bool scalar_references = false;
  // Names to use instead of discovery's (debug info), by entry.
  std::map<std::uint64_t, std::string> names;
  const std::atomic<bool> *cancel = nullptr;
  std::function<void(std::size_t done, std::size_t total)> progress;
  // HashOptions::min_code_units: Function ID's 4 unless a caller wants
  // shorter functions hashed too.
  int min_code_units = 4;
};

// Hashes every function. Throws FidError when cancelled.
ProgramHashes hash_program(const ProgramSource &source);

// Relocations a loaded image has, as ProgramSource wants them.
void image_relocations(const loader::Image &image, ProgramSource &source);

}  // namespace revkit::fid
