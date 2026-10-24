// Named types' layouts as JSON, for comparing what different producers
// (the C parser, the DWARF and PDB importers) make of one type.
#pragma once

#include "revkit/types/store.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::types {

// A JSON string literal (ASCII; others as \u escapes of their UTF-8 bytes).
std::string json_quote(std::string_view s);

// The key a named type is compared under: "struct point", "union u",
// "class c", "enum e", "typedef t"; empty for anything else (anonymous
// aggregates, pointers, ...).
std::string named_key(const TypeStore &store, TypeId id);

// One named type as a JSON object: key, kind, size, alignment, packed,
// complete, the aggregate's own tag (for a typedef of one), its hash and its hash with every typedef resolved and anonymous
// tags named after their typedefs ("flat_hash", the identity DWARF and PDB
// are compared by), and its fields (name, bit_offset, bit_size, type) or
// enumerators. `store` gains the typedef-free types.
std::string layout_json(TypeStore &store, TypeId id);

}  // namespace revkit::types

namespace revkit::types {

// Every node a type reaches, one per line with its fields spelled out and
// references by visit number: for finding where two types that should be
// equal differ (rk-cparse --dump, rk-debuginfo --dump).
std::string deep_dump(const TypeStore &store, TypeId id);

}  // namespace revkit::types

namespace revkit::types {

// A field of an aggregate as Ghidra's decompiler is told it
// (inputs::GhidraTypes), and so as its C names it: `index` into
// AggregateType::fields, `name` (an unnamed member is field_<ordinal>).
// The decompiler drops what it can't lay out: a field overlapping the one
// before, a non-bitfield not at a byte, one of size 0 or past the end, and
// an unnamed, non-integral or out-of-order bitfield; what it drops is a gap
// to it, which its C names by offset (`field_0x10`).
struct DecompilerField {
  std::size_t index = 0;
  std::string name;
};
std::vector<DecompilerField> decompiler_fields(const TypeStore &store, const AggregateType &a);

// The decompiler's name for the bytes at `offset` that no field covers.
std::string gap_field_name(std::uint64_t offset);

}  // namespace revkit::types
