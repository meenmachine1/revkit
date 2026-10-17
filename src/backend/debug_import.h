// Debug info as import assertions: DWARF (any image) as import:dwarf, a
// PE's PDB as import:pdb. Function and global names, prototypes and
// variable types as type hashes, and the type records those hashes reach
// (type_record.h).
#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace revkit::backend {

class Program;

struct DebugFacts {
  std::string source;  // "dwarf" or "pdb": the provenance id
  std::string file;    // the PDB read, for messages
  // Function entries and global variables, at loaded addresses.
  std::map<std::uint64_t, std::string> names;
  // Address -> "h:<hash>": a function's prototype, a variable's type.
  std::map<std::uint64_t, std::string> types;
  // Hash -> type record, closed under references.
  std::map<std::string, std::string> records;
  // Named type key -> category ("/cJSON.h"): the header that declared it,
  // where the debug info says.
  std::map<std::string, std::string> categories;
  std::vector<std::string> diagnostics;
  std::size_t functions = 0;
  std::size_t variables = 0;
};

// The image's DWARF, if it has .debug_info: from the debug info the
// program read at load (inputs::read_debug_info, which the decompiler's
// inputs come from too).
std::optional<DebugFacts> ReadDwarf(const Program &program);

// A PE's PDB, as the program found it at load: the debug directory's path
// as written, then its file name beside the binary, then <stem>.pdb beside
// it, matching the image's CodeView GUID and age.
std::optional<DebugFacts> ReadPdb(const Program &program);

// An ELF's separate debug file (docs/backend.md "External debug files"):
// its DWARF, read as the image's own .debug_info is, at the program's
// addresses. Throws std::exception for a file the loader can't read.
DebugFacts ReadDwarfFile(const Program &program, std::shared_ptr<const std::vector<std::byte>> bytes,
                         const std::string &file);

// A PDB's bytes, read for `program` whatever build it is ("Load PDB…",
// docs/pdb.md): its facts at the image's addresses. Throws
// debuginfo::PdbError for a file that isn't an MSF 7.00 PDB.
DebugFacts ReadPdbBytes(const Program &program, std::span<const std::uint8_t> bytes, const std::string &file);

}  // namespace revkit::backend
