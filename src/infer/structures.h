// Structures for classes of passed-on pointers (infer.h, InferredStructure;
// docs/infer.md, "Structures").
#pragma once

#include "abi.h"
#include "revkit/infer/infer.h"

#include <functional>
#include <optional>
#include <utility>
#include <vector>

namespace revkit::infer {

struct StructureOptions {
  // A class makes a structure with at least this many distinct field
  // offsets and this many reads and writes through its members.
  std::uint32_t min_offsets = 2;
  std::uint32_t min_accesses = 3;
  // Accesses past this offset are dropped (64 KiB: zlib's deflate_state
  // is 5.9 KB; a structure smaller than its accesses would make the
  // decompiler index an array of them, `param_1[1].field_0xb6c`).
  std::uint64_t max_offset = 0x10000;
};

// Infers structures from the functions' last-round observations (by entry;
// a null one is skipped) for r.prototypes' pointer parameters and returns,
// adds them to r.structures and points the parameters and returns of each
// class that has one to it. `library` gives an import's library prototype
// by call target (an import stub or slot), for the parameters that say a
// pointer is a string. Deterministic: the result doesn't depend on the
// observations' order (classes are numbered by their first member).
void infer_structures(const std::vector<std::pair<std::uint64_t, const Observation *>> &observations,
                      FixpointResult &r, const Abi &abi, const DataOrg &org,
                      const std::function<std::optional<Prototype>(std::uint64_t)> &library,
                      const StructureOptions &options = {});

}  // namespace revkit::infer
