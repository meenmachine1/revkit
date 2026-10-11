// The listing's edits (docs/listing-edit.md): a ListingEdit or SetMutability
// body as the CODE_UNIT or MUTABILITY assertion it makes, with a data
// definition's type resolved against the program's types and laid out.
#pragma once

#include "parse_c.h"
#include "program.h"

#include "revkit/analysis/units.h"
#include "revkit/types/store.h"
#include "revkit/v1/assertion.pb.h"

#include <cstdint>
#include <functional>
#include <map>
#include <string>

namespace revkit::backend {

struct ListingEditKey {
  std::uint64_t address = 0;
  std::string sub;
  std::string value;          // the encoded mark (analysis::UnitMark, ::MutabilityMark)
  pb::AssertionBody stored;   // as stored: a DefineData's size, type_hash and type_name filled
  // Types the definition reaches that aren't the program's records: to
  // define with it (the caller drops those the program or library has).
  std::map<std::string, ParsedRetype::Def> types;
};

// The program's bytes (as patched) at an address; fewer where memory ends.
using EditBytes = std::function<std::string(std::uint64_t address, std::size_t n)>;

inline constexpr std::uint64_t kMaxDataBytes = 16u << 20;
inline constexpr std::uint64_t kMaxStringScan = 1u << 16;

// Validates a ListingEdit at its address and computes its key and value;
// returns an error, or "".
std::string ResolveListingEdit(const ParseCContext &c, const pb::ListingEdit &e, const EditBytes &read,
                               ListingEditKey &out);
std::string ResolveMutability(const Program &p, const pb::SetMutability &m, ListingEditKey &out);

// A data definition's element as the listing and analysis see it: the
// spec's format, fields (depth first) and pointer offsets, from `elem`.
void LayOutElement(const types::TypeStore &store, types::TypeId elem, analysis::DataSpec &spec);
// Its C spelling as the listing shows it ("uint32_t[4]", not "uint32_t [4]").
std::string ElementName(const types::TypeStore &store, types::TypeId elem);

// What the listing shows for a data definition: Ghidra's mnemonic for a
// scalar ("dword", "char", "float", "addr", "ds"), else its C type.
std::string DataMnemonic(const analysis::DataSpec &s);
// A value of `format` read from `bytes` (size 1..8 for numbers), as the
// listing shows it ("2Ah", "-3", "1.5", "'A'", "true").
std::string FormatValue(analysis::ValueFormat format, std::string_view bytes, bool big_endian);

}  // namespace revkit::backend
