// Rebasing a position-independent ELF moves its code but not the pointers
// stored in its data: those are R_*_RELATIVE relocations, applied by the
// dynamic linker (and by Ghidra's importer). revkit::loader rebases without
// applying relocations, so pointer tables (vtables, computed-goto and
// function-pointer tables in .data.rel.ro) would still hold link-time
// addresses. This applies the RELATIVE ones to a copy of the file.
#pragma once

#include "revkit/loader/image.hh"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace revkit::backend {

// `linked` is the image parsed at the file's own addresses. Returns the file
// with every RELATIVE relocation (RELA, REL and RELR) rewritten for a load
// `delta` bytes higher, or null when there is nothing to do (not ELF, no
// delta, no relocations, or a machine whose RELATIVE type isn't known).
std::shared_ptr<const loader::Bytes> RelocateRelative(const loader::Image &linked, std::uint64_t delta,
                                                      std::vector<std::string> &warnings);

}  // namespace revkit::backend
