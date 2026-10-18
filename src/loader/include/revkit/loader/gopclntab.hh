// Go's function table (pclntab): every Go function's entry, extent, name,
// source file and line, which a Go binary keeps however it was stripped
// (the runtime needs it for stack traces). docs/go.md.
//
// The four layouts Go has written are read, in both byte orders and both
// pointer sizes: Go 1.2 to 1.15 (magic 0xfffffffb), 1.16 and 1.17
// (0xfffffffa), 1.18 and 1.19 (0xfffffff0), 1.20 and later (0xfffffff1).
// The format is Go's: runtime/symtab.go and debug/gosym (BSD-3-Clause), which
// this follows without copying code. Everything is bounded: a table that
// doesn't decode is an error, a function that doesn't is skipped with a
// warning.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "revkit/loader/image.hh"

namespace revkit::loader {

enum class GoPclntabVersion : std::uint8_t { go12, go116, go118, go120 };

// "1.2", "1.16", "1.18", "1.20": the first Go version that wrote the layout.
std::string_view to_string(GoPclntabVersion v);

// _func.flag (Go 1.19 and later; 0 before).
inline constexpr std::uint8_t kGoFuncFlagTopFrame = 1;
inline constexpr std::uint8_t kGoFuncFlagSpWrite = 2;
inline constexpr std::uint8_t kGoFuncFlagAsm = 4;

struct GoFunction {
  std::uint64_t entry = 0;
  std::uint64_t end = 0;  // the next function's entry (exclusive)
  std::string name;       // as Go spells it: "main.(*T).Method", "fmt.Fprintf"
  // The source file of the entry and the function's line: its `func`
  // line (_func.startLine, Go 1.20 and later), else the entry's line.
  // Empty and 0 when the table has none (assembly the linker made).
  std::string file;
  std::int32_t line = 0;
  std::uint8_t func_id = 0;  // _func.funcID (runtime.goexit, morestack, ...); 0 for most
  std::uint8_t flag = 0;     // kGoFuncFlag*
};

struct GoPclntab {
  GoPclntabVersion version = GoPclntabVersion::go120;
  std::uint64_t address = 0;  // the header's
  std::uint32_t pointer_size = 8;
  std::uint32_t quantum = 1;  // the instruction size unit (1 x86, 4 ARM and the RISCs)
  Endian endian = Endian::little;
  // Where the entries' offsets count from (Go 1.18 and later: the header's
  // textStart, else the moduledata's text); 0 for older layouts, whose
  // entries are addresses.
  std::uint64_t text_start = 0;
  std::uint64_t function_count = 0;  // nfunctab, as the header says
  std::uint64_t file_count = 0;      // nfiletab
  // runtime.firstmoduledata (or the module's moduledata) when it was found:
  // the data that points to this table.
  std::optional<std::uint64_t> moduledata;
  // How the table was found: "section" (.gopclntab, __gopclntab),
  // "symbol" (runtime.pclntab), "scan" (its magic in read-only data).
  std::string found_by;
  std::vector<GoFunction> functions;  // by entry
  // Functions that didn't decode (skipped) and other oddities.
  std::vector<std::string> warnings;
};

// A pointer the file stores at `at` (`raw` is the word read there): its
// target after relocations and a rebase. Identity when unset.
using GoPointerFn = std::function<std::uint64_t(std::uint64_t at, std::uint64_t raw)>;

struct GoPclntabOptions {
  // Decode each function's file and line (the pcfile and pcln tables).
  bool lines = true;
  // Go 1.18 and later: the text start to use instead of the header's
  // (the moduledata's text, when the header's doesn't hold up).
  std::optional<std::uint64_t> text_start;
  // At most this many functions are read (a header claiming more is refused).
  std::uint64_t max_functions = 4u << 20;
};

// Decodes the table whose header is at data[0] (loaded at `address`;
// `data` runs to the end of what's mapped after it). nullopt with *error
// set when it isn't a pclntab or doesn't decode: a bad magic, header, or a
// function table outside the data, unsorted or empty.
std::optional<GoPclntab> parse_go_pclntab(std::span<const std::byte> data, std::uint64_t address,
                                          const GoPointerFn &pointer, const GoPclntabOptions &options,
                                          std::string *error);

// The table of a Go image: the .gopclntab section (ELF; .data.rel.ro.gopclntab
// in a PIE before Go 1.18), __gopclntab (Mach-O), the runtime.pclntab
// symbol, else a scan for its magic in read-only data (a PE, an ELF without
// section headers), checked against the moduledata that points to it and
// the executable memory its entries must be in. nullopt with *error empty:
// no table (not Go, or a Go too old); *error set: one that doesn't decode.
std::optional<GoPclntab> read_go_pclntab(const Image &image, std::string *error, const GoPclntabOptions &options = {});

// The name revkit gives a Go function: Go's own spelling ("fmt.Fprintf",
// "main.(*T).Method", "example.com/dep.Greeting", "slices.Sort[...]") as
// one token of at most 256 bytes: an old toolchain's middle dot and
// division slash as '.' and '/', whitespace and control characters as '_'
// (Ghidra's SymbolUtilities.replaceInvalidChars), and in a name still too
// long, each generic argument list as "[...]" (Go 1.21's own short form),
// then the rest cut.
std::string go_display_name(std::string_view name);

// Whether a function's name is one of Go's no-return runtime functions
// (runtime.throw, runtime.goPanicIndex, ...): Ghidra's
// GolangFunctionsThatDoNotReturn list.
bool go_function_no_return(std::string_view name);

}  // namespace revkit::loader
