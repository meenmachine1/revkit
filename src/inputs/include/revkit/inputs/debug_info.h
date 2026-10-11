// One image's debug info as revkit::inputs reads it (read_debug_info): the
// image backend's debug-info import assertions come from it too.
#pragma once

#include "revkit/debuginfo/dwarf.h"
#include "revkit/debuginfo/pdb.h"
#include "revkit/types/store.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace revkit::inputs {

// DWARF and, for a PE, its PDB, in one type store. Addresses are the
// readers' (DWARF's link-time ones: add dwarf_delta for the image's).
struct DebugInfo {
  types::TypeStore store;
  std::optional<debuginfo::DebugInfo> dwarf;
  std::uint64_t dwarf_delta = 0;  // add to DWARF addresses (a rebased image)
  std::optional<debuginfo::PdbDebugInfo> pdb;
  std::string pdb_file;
  std::vector<std::string> warnings;  // reading the DWARF sections
};

}  // namespace revkit::inputs
