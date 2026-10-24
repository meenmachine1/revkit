// Library prototypes: revkit's type archives of the C library and the
// Windows API (tools/rk-typeinfo builds them from the host's headers at
// build time; docs/types.md#library-prototypes), parsed for a program's
// target, whose prototypes are applied to imported and external functions
// by name, as Ghidra's "Apply Data Archives" analyzer applies its .gdt
// archives. They rank below debug info, PDBs, demangled names and the user,
// above inference.
#pragma once

#include "revkit/cparse/cparse.h"
#include "revkit/loader/image.hh"
#include "revkit/types/store.h"

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::inputs {

// One archive's header, as shipped or as attached to a project.
struct LibraryArchiveText {
  std::string name;    // "libc-lp64", "kernel32-llp64", or an attached archive's
  std::string header;  // the C header
};

struct LibraryFunction {
  types::TypeId type;  // a FunctionType with parameter names
  bool noreturn = false;
  std::string archive;  // the archive it came from
};

// Archives parsed for one target: their prototypes by name (the first
// archive that declares a name wins) and named types.
struct LibraryPrototypes {
  types::TypeStore store;
  std::vector<std::string> archives;  // in priority order
  std::map<std::string, LibraryFunction, std::less<>> functions;
  std::vector<cparse::NamedType> named;  // every archive's, the first of a key
  // Errors parsing a header (an attached archive written for another
  // compiler), with the archive's name.
  std::vector<std::string> diagnostics;
  // Identifies the archives and the profile: equal identities, equal contents.
  std::string identity;

  // A function by the name a binary gives it: exactly, else as the symbol
  // `_name` names `name` (and an x86 stdcall `_name@N`), else without a
  // symbol version (`printf@GLIBC_2.2.5`). Null if no archive declares it.
  // Without `underscore`, `_name` is not `name`: a raw image's symbols
  // (a DS module's: CodeWarrior's soft-float `_fmul` is not C23's
  // `fmul(double, double)`, docs/nds.md).
  const LibraryFunction *find(std::string_view name, bool underscore = true) const;
  // Whether `_name` may name `name` for this image (not a raw image's symbols).
  static bool underscore_names(const loader::Image &image) { return image.format != loader::Format::raw; }
};

// The C runtime's start-up and tear-down code a program defines itself
// (_init, _fini, _start, frame_dummy, __libc_csu_init, ...): it never takes
// an archive's prototype by name (Ghidra's generic_clib names an OpenSSL
// engine's _init: int _init(EVP_PKEY_CTX *ctx)).
bool crt_function(std::string_view name);

// The shipped archives that apply to an image, by name, in priority order:
// libc-lp64 or libc-ilp32 for ELF (and raw images with symbols); for PE
// the Windows DLLs' and the C runtime's of its data model.
std::vector<std::string> default_library_archives(const loader::Image &image);
// Every shipped archive's name (the typeinfo directory's *.h), sorted.
std::vector<std::string> shipped_library_archives();
// A shipped archive's header, from runtime::typeinfo_dir(); nullopt if absent.
std::optional<std::string> read_library_archive(const std::string &name);

// Parses the archives for `profile` (each header alone, in order). Cached
// by identity, so every program of a target shares one parse.
std::shared_ptr<const LibraryPrototypes> parse_library(std::span<const LibraryArchiveText> archives,
                                                       const cparse::Profile &profile);

// The default archives for an image, read and parsed for `profile`; null
// when none is installed.
std::shared_ptr<const LibraryPrototypes> default_library(const loader::Image &image, const cparse::Profile &profile);

}  // namespace revkit::inputs
