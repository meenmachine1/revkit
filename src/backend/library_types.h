// The library type archive Ghidra applies to a program's imports (a .gdt
// of the Ghidra install: generic_clib for ELF, windows_vs12 for PE; see
// revkit/inputs/ghidra_archive.h), its named structs, unions, enums and
// typedefs as revkit types: records keyed by content hash like TYPE_DEF
// assertions', so they can be browsed (FindTypes), described (GetTypes),
// referenced by DefineType and applied by hash like any program type.
#pragma once

#include "revkit/facts/codec.h"
#include "revkit/inputs/ghidra_archive.h"
#include "revkit/inputs/library.h"

#include <string>
#include <utility>
#include <vector>

namespace revkit::backend {

struct LibraryTypes {
  std::string archive;  // e.g. "generic_clib_64"; empty: none
  std::vector<std::pair<std::string, std::string>> records;  // hash -> record, by hash
  std::vector<std::pair<std::string, std::string>> named;    // NamedTypeKey -> hash, by key
  // hash -> the archive it came from (the first that reaches it), by hash;
  // empty: every record is `archive`'s.
  std::vector<std::pair<std::string, std::string>> sources;

  // The archive a record came from.
  std::string archive_of(const std::string &hash) const;

  const std::string *record(const std::string &hash) const;
  void encode(facts::Encoder &e) const;
  static LibraryTypes decode(facts::Decoder &d);
};

// The archive's named types in revkit's type model, sized by the program's
// data organization; `char_signed` is plain char's signedness on the target.
LibraryTypes ConvertArchive(const inputs::GhidraArchive &archive, const std::string &name, const inputs::DataOrg &org,
                            bool char_signed);

// revkit's library archives' named types (and every type their named
// types and prototypes reach), parsed for the program (inputs/library.h).
LibraryTypes ConvertLibrary(const inputs::LibraryPrototypes &lib);

// `extra`'s named types whose keys `into` lacks, with their records.
void MergeLibraryTypes(LibraryTypes &into, const LibraryTypes &extra);

}  // namespace revkit::backend
