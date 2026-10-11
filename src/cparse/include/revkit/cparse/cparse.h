// revkit::cparse: C (and a C++ subset) header parsing into revkit types.
//
// A hand-written preprocessor and declaration parser (docs/cparse.md). It
// reads headers, or whole source files with function bodies skipped, and
// produces the structs, unions, enums, typedefs, function prototypes and
// integer #define constants they declare, laid out by a target's data
// model (`Profile`, usually from the program's compiler spec), with
// line-numbered diagnostics. It never needs a system include tree: the
// freestanding headers (stddef.h, stdint.h, stdbool.h, stdarg.h, limits.h,
// float.h, ...) are built in and sized from the profile. Output of
// `clang -E -dD` or `cl /E` is accepted as is (its #defines are kept for
// constants, its text isn't expanded again).
//
// The parser is meant for untrusted input: every resource is bounded
// (`Limits`), recursion is bounded, and files are read only through a
// `FileSystem`, which decides what an #include may reach.
#pragma once

#include "revkit/types/store.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace revkit::cparse {

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

// How consecutive bitfields share storage: GCC's (System V, AAPCS: a field
// goes where the last one ended unless it would straddle a unit of its
// type's alignment) or Microsoft's (a run of same-sized types shares one
// unit; a different size starts a new one).
enum class BitfieldModel : std::uint8_t { Gcc, Msvc };

// Which compiler's dialect the predefined macros and keywords follow.
enum class Compiler : std::uint8_t { Gcc, Clang, Msvc };

enum class Os : std::uint8_t { None, Linux, Windows, Darwin };

// Sizes and alignments of C's types on a target: a compiler spec's
// <data_organization> (lift::read_data_organization), with what the spec
// doesn't say (or says wrong for the platform ABI) from the target.
struct LayoutRules {
  std::uint32_t pointer_size = 8;
  std::uint32_t short_size = 2;
  std::uint32_t int_size = 4;
  std::uint32_t long_size = 8;
  std::uint32_t long_long_size = 8;
  std::uint32_t float_size = 4;
  std::uint32_t double_size = 8;
  std::uint32_t long_double_size = 16;  // sizeof(long double): storage, e.g. 16 for x87 on x86-64
  std::uint32_t long_double_align = 16;
  std::uint32_t wchar_size = 4;
  bool wchar_signed = true;
  bool char_signed = true;
  bool big_endian = false;
  bool has_int128 = true;
  // Alignment of an n-byte scalar (the spec's size_alignment_map); a size
  // it doesn't list takes the alignment of the largest listed size below.
  std::vector<std::pair<std::uint32_t, std::uint32_t>> size_alignment = {{1, 1}, {2, 2}, {4, 4}, {8, 8}, {16, 16}};
  std::uint32_t max_alignment = 0;  // absolute_max_alignment; 0: none
  BitfieldModel bitfields = BitfieldModel::Gcc;
  // MSVC's enums are int whatever their values; GCC's are unsigned int
  // unless a value is negative, and 8 bytes when a value needs it.
  bool msvc_enums = false;
  // AAPCS (ARM and AArch64): an unnamed zero-width bitfield's type counts
  // toward the struct's alignment, as it doesn't on x86.
  bool zero_width_bitfield_aligns = false;
  // __attribute__((aligned)) with no argument: __BIGGEST_ALIGNMENT__.
  std::uint32_t biggest_alignment = 16;
  // GCC vectors are aligned to their size, up to this (ARM's ABI: 8).
  std::uint32_t max_vector_alignment = 16;

  std::uint32_t scalar_align(std::uint64_t size) const;
  friend bool operator==(const LayoutRules &, const LayoutRules &) = default;
};

// A target: its layout rules, compiler dialect and predefined macros.
struct Profile {
  std::string name;  // "x86_64-linux-gnu"
  std::string arch;  // "x86_64", "aarch64", "riscv64", "i386", "arm", ...
  Os os = Os::Linux;
  Compiler compiler = Compiler::Gcc;
  LayoutRules rules;
  // Macros the compiler predefines for the target (__x86_64__, __LP64__,
  // __GNUC__, _MSC_VER, __CHAR_UNSIGNED__, __SIZEOF_LONG__, ...), as
  // NAME -> body.
  std::vector<std::pair<std::string, std::string>> predefined() const;
};

// The named targets: x86_64-linux-gnu, aarch64-linux-gnu,
// riscv64-linux-gnu, x86_64-w64-mingw32 (LLP64, Microsoft bitfields, 16-byte
// long double), x86_64-pc-windows-msvc, i386-linux-gnu, i686-w64-mingw32,
// i386-pc-windows-msvc, arm-linux-gnueabihf, riscv32-linux-gnu,
// powerpc-linux-gnu, mips-linux-gnu, mipsel-linux-gnu.
std::optional<Profile> profile_named(std::string_view name);
std::vector<std::string> profile_names();

// A compiler spec's <data_organization>, as written (all optional).
struct DataOrganization {
  std::optional<std::uint32_t> absolute_max_alignment, machine_alignment, default_alignment,
      default_pointer_alignment, pointer_size, wchar_size, short_size, integer_size, long_size, long_long_size,
      float_size, double_size, long_double_size;
  std::optional<bool> char_signed;  // <char_type signed="...">
  std::vector<std::pair<std::uint32_t, std::uint32_t>> size_alignment;
  bool ms_bitfields = false;  // <bitfield_packing><use_MS_convention value="true"/>
};

// What a program says about its target.
struct ProfileInputs {
  std::string language_id;  // "x86:LE:64:default"
  std::string compiler_id;  // "gcc", "windows", "default", ... (the cspec's id)
  std::string format;       // "elf", "pe", "macho", "raw", ...
  std::optional<DataOrganization> data_org;  // the cspec's; nullopt: the target's defaults
};

// The profile for a program: the target named by its processor, size,
// format and compiler, with the spec's data organization laid over it.
// Where Ghidra's specs disagree with the platform's ABI (AArch64 and
// RISC-V Linux's 16-byte long double and unsigned char, which the specs
// leave at 8 bytes and signed) the ABI wins, and `notes` says so.
Profile profile_for(const ProfileInputs &in, std::vector<std::string> *notes = nullptr);

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

struct Limits {
  std::size_t max_bytes = 64u << 20;  // all source text, includes too
  std::size_t max_files = 4096;
  std::uint32_t max_include_depth = 64;
  std::size_t max_expansion_tokens = 20'000'000;  // tokens macro expansion may produce
  std::size_t max_tokens = 50'000'000;            // tokens the parser may read
  std::uint32_t max_nesting = 200;  // declarators, expressions, braces, #if, macro arguments
  std::size_t max_types = 2'000'000;
  std::size_t max_diagnostics = 1000;
  std::chrono::milliseconds wall_time{20'000};
};

// Where sources and #includes are read. resolve() turns a path into the
// canonical path of a readable regular file it may read, or nullopt (no such
// file, or not allowed); read() reads a resolved path, at most `max` bytes
// (nullopt: unreadable or longer).
class FileSystem {
 public:
  virtual ~FileSystem() = default;
  virtual std::optional<std::string> resolve(const std::string &path) = 0;
  virtual std::optional<std::string> read(const std::string &canonical, std::size_t max) = 0;
};

// The host's files. With `roots`, only files whose canonical path is under
// one of them (symlinks and ".." resolved first, so neither leaves a root).
std::unique_ptr<FileSystem> host_file_system(std::vector<std::string> roots = {});

struct Source {
  std::string name;  // shown in diagnostics; for a path, the path
  std::string text;  // the text, or empty with `path` set
  bool path = false; // read `name` through the FileSystem
};

struct Options {
  Profile profile;
  std::vector<std::string> include_dirs;         // -I: searched for "..." and <...>
  std::vector<std::string> system_include_dirs;  // -isystem: after the built-in headers
  std::vector<std::pair<std::string, std::string>> defines;  // -D NAME[=VALUE] (VALUE "1" if empty)
  std::vector<std::string> undefines;                         // -U, after the predefined macros
  // C++ (namespaces, classes, enum class, references); otherwise decided
  // per source by its extension (.hpp, .hh, .hxx, .cpp, .cc, .cxx).
  bool cplusplus = false;
  bool builtin_headers = true;
  // Group the constants of each file into one enum type
  // ("<file>_constants"), as Ghidra's "parse defines as enums" does.
  bool defines_as_enums = false;
  // Keep the prototypes system headers declare (a library's type archive
  // is made of them); by default only the sources' own are listed.
  bool system_prototypes = false;
  Limits limits;
  FileSystem *fs = nullptr;  // nullptr: no file access (inline sources; #include fails)
  // Types already defined elsewhere (a program's), by key: "struct cJSON",
  // "union u", "enum e", "typedef cJSON". A name the sources use but don't
  // declare is looked up here (TypeIds of the store passed to parse()).
  std::function<std::optional<types::TypeId>(std::string_view key)> lookup;
};

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

enum class Severity : std::uint8_t { Note, Warning, Error };

struct Diagnostic {
  std::string file;
  std::uint32_t line = 0;
  std::uint32_t col = 0;
  Severity severity = Severity::Error;
  std::string text;
};

struct Location {
  std::string file;
  std::uint32_t line = 0;
  bool system = false;  // a built-in header or one found in a system include dir
};

// A struct, union, enum or typedef the sources defined (or declared, for a
// struct only ever declared: complete = false in its type).
struct NamedType {
  std::string key;  // "struct point", "union number", "enum color", "typedef size_t"
  types::TypeId id;
  Location where;
};

struct Constant {
  std::string name;
  std::int64_t value = 0;
  bool is_unsigned = false;
  Location where;
};

struct Prototype {
  std::string name;  // qualified for C++ ("ns::f")
  types::TypeId type;  // a FunctionType with parameter names
  Location where;
  bool defined = false;  // it had a body (skipped)
  // The name it links as when an asm label renames it (glibc's
  // `sscanf` -> "__isoc99_sscanf"); empty: its own name.
  std::string asm_label;
  bool noreturn = false;  // __attribute__((noreturn)), __declspec(noreturn), _Noreturn
};

struct Result {
  std::vector<NamedType> named;
  std::vector<Constant> constants;
  std::vector<Prototype> prototypes;
  // Options::defines_as_enums: one enum per file with constants.
  std::vector<NamedType> constant_enums;
  // Types the sources used from Options::lookup, by key.
  std::vector<std::pair<std::string, types::TypeId>> used_existing;
  std::vector<Diagnostic> diagnostics;
  std::size_t errors = 0;
  std::size_t warnings = 0;
  std::size_t suppressed_diagnostics = 0;  // beyond Limits::max_diagnostics
  bool limit_hit = false;                  // a Limits bound stopped the parse early
  std::vector<std::string> files;          // every file read, in order
};

// Parses `sources` in order as one translation unit (macros and types
// carry over from one to the next) into `store`.
Result parse(types::TypeStore &store, std::span<const Source> sources, const Options &options);

// One declaration as a type: a type name ("cJSON *", "struct point"), a
// declaration ("cJSON *item", "int (*cb)(int)") or a prototype
// ("int f(const char *s)"), with or without a trailing ';'. A prototype
// keeps its parameter names. nullopt unless the text is exactly one
// declaration and parsed without errors (`result`, if given, has the
// diagnostics).
struct Declaration {
  types::TypeId type;
  std::string name;  // the declared name; empty for a type name
  bool function = false;
};
std::optional<Declaration> parse_declaration(types::TypeStore &store, std::string_view text, const Options &options,
                                             Result *result = nullptr);

// Links translation units parsed into one store, as a linker sees a
// program: a struct, union or enum a unit only declares becomes the
// definition the other units give it, when they agree on one (the DWARF
// importer resolves declarations the same way for a whole binary). Rewrites
// each unit's named types and prototypes; returns the names left ambiguous
// (defined differently by different units), which stay as they were.
std::vector<std::string> link(types::TypeStore &store, std::span<Result> units);

}  // namespace revkit::cparse
