// The packing rule every producer of aggregate types shares: the DWARF and
// PDB importers (which can't read packing from the debug info) and the C
// parser (revkit::cparse, which knows it but must hash like them).
#pragma once

#include "revkit/types/store.h"

#include <cstdint>
#include <utility>
#include <vector>

namespace revkit::types {

// Neither DWARF nor CodeView reliably says a struct is packed, so infer it:
// a struct is packed if a member sits below its natural alignment or the
// size isn't a multiple of it. Alignment is capped at the address size
// (`second`), which is what i386-style ABIs give 8-byte scalars. Every
// producer uses this one rule so the same struct hashes the same from
// any source. `aggs` lists graph-local aggregate nodes.
void infer_packing(TypeGraph &g, const TypeStore &store, std::vector<std::pair<TypeId, std::uint32_t>> aggs);

}  // namespace revkit::types
