// Type archives: a set of types as one self-contained C header
// (docs/types.md#type-archives).
//
// write_archive() writes every named type the roots reach (structs,
// unions, enums, typedefs) as C definitions in dependency order, with
// forward declarations where a type is used before it is defined,
// `#pragma pack` around the structs C's natural rules wouldn't lay out as
// they are, and a `_Static_assert(sizeof(...))` per sized type, so a real
// compiler for the data model checks the sizes. It then parses its own
// header with the same profile and keeps the forms that reproduce each
// type: natural, `#pragma pack(N)`, or explicit offsets (a packed struct
// whose gaps are unnamed bitfields). What the header can't reproduce is
// listed in `notes`, and each entry's `hash` is what the header parses to,
// so an import of it is checked against these hashes.
#pragma once

#include "revkit/cparse/cparse.h"
#include "revkit/types/store.h"

#include <cstdint>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::cparse {

// A function prototype an archive declares (a library's: the prototypes
// revkit applies to imports by name, docs/types.md#library-prototypes).
struct ArchiveFunction {
  std::string name;
  types::TypeId type;  // a FunctionType with parameter names
  bool noreturn = false;
};

// The C a header is written in.
enum class Dialect : std::uint8_t {
  C11,  // the default: _Bool, _Static_assert, long long, any bitfield width
  // For old compilers (Metrowerks CodeWarrior, a strict C89 mode): no
  // <stdbool.h> or _Bool (bool is a typedef of unsigned char), sizes
  // checked by arrays of negative size instead of _Static_assert, `long
  // long` only under __extension__ (defined away for compilers without it),
  // padding bitfields of the target's int, never wider, enumerators within
  // int's range, and no typedef written twice.
  C89,
};

struct ArchiveOptions {
  // The archive's name: the header's comment and include guard.
  std::string name = "types";
  // The data model the types are laid out for (the program's).
  Profile profile;
  // Prototypes declared after the types, by name; the named types they
  // reach are written too.
  std::vector<ArchiveFunction> functions;
  Dialect dialect = Dialect::C11;
  // Aggregates as the decompiler sees them (types::decompiler_fields), for
  // a header decompiled C includes (ExportC, ExportDecompScratch): the
  // fields it drops left out, unnamed ones named as it names them
  // (field_<ordinal>), and every byte no field covers a one-byte member
  // named as its C names such bytes (field_0x10), so `&p->field_0x10` and
  // `p->field_0x12` compile and lay out where the decompiler meant. Such a
  // header isn't an archive to import back: the members it adds are its
  // own. Entries are checked by layout only.
  bool decompiler_view = false;
  // Type names the file including the header defines itself (Ghidra's
  // built-in names: uint, undefined4, code): a typedef of one is never
  // written, nor Ghidra's undefined types, so nothing is defined twice.
  std::set<std::string> provided;
};

struct ArchiveEntry {
  std::string key;          // "struct cJSON", "typedef cJSON", "enum color"
  types::TypeId id;         // the type exported (the caller's store)
  std::string hash;         // what the header parses to under the profile
  std::string source_hash;  // the exported type's own hash (equal when reproduced)
  std::uint64_t size = 0;
  std::uint32_t line = 0;   // of its definition in the header
  // "natural", "pack(N)", "explicit" (aggregates and enums), "typedef",
  // "declaration" (a struct or union with no definition), "prototype"
  // (key "function <name>").
  std::string form;
  bool noreturn = false;  // a prototype's
};

struct Archive {
  std::string header;
  std::vector<ArchiveEntry> entries;  // in header order
  std::vector<std::string> notes;     // what the header doesn't reproduce, and why
  std::size_t mismatches = 0;         // entries whose hash isn't their source_hash
};

// The named types `roots` reach, roots first where two definitions share a
// name (only one definition of a name fits in one header; uses of the
// others are written by name, so they then parse to the chosen one).
Archive write_archive(const types::TypeStore &store, std::span<const types::TypeId> roots,
                      const ArchiveOptions &options);

// `name` as a file stem: letters, digits, '_', '-' and '.', else '_'.
std::string archive_stem(std::string_view name);

// The profile as one line ("x86_64-linux-gnu: pointer 8, long 8, ...").
std::string describe_profile(const Profile &profile);

}  // namespace revkit::cparse
