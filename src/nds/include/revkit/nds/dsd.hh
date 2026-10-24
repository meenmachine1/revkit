// ds-decomp ("dsd") project files: the config.yaml that lists a game's
// modules, and each module's symbols.txt, relocs.txt and delinks.txt
// (docs/nds.md). dsd (https://github.com/AetiasHax/ds-decomp, MIT) splits a
// Nintendo DS ROM into its ARM9 main module, the ITCM and DTCM autoloads
// and the overlays; these are its text formats, read and written here
// without its code.
//
// symbols.txt  `<name> kind:<kind> addr:0x<addr> [local|weak] [ambiguous] [// comment]`
//              kinds: function(arm|thumb,size=0x..[,unknown]...), data(any),
//              data(byte|short|word[N]), data(byte[]), bss[(size=0x..)],
//              label(arm|thumb)
// relocs.txt   `from:0x.. kind:<kind> to:0x.. [add:0x..] module:<module>`
//              kinds arm_call, thumb_call, arm_call_thumb, thumb_call_arm,
//              arm_branch, load, overlay_id, link_time_const(NAME);
//              modules none, main, itcm, dtcm, overlay(N),
//              overlays(N,M,...), autoload(N)
// delinks.txt  the module's sections (`.text start:0x.. end:0x.. kind:code
//              align:32`), then translation units: a `path:` line with
//              indented `complete`, `categories: a,b` and sections
//              (start and end only; kind and align come from the module)
//
// `//` starts a comment anywhere; blank lines and comment lines are kept
// by the writer, which changes only the lines it must. Every parser is
// bounded and reports a bad line with its number instead of failing the
// file.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::nds {

// ---- A YAML subset (block maps and sequences, scalars, comments, tags) --

struct YamlEntry;

struct YamlNode {
  enum class Kind : std::uint8_t { scalar, map, seq };
  Kind kind = Kind::scalar;
  std::string scalar;  // the text, unquoted
  std::string tag;     // `!Unknown 3` keeps "Unknown"
  // A map's keys and values in order. Not std::pair<std::string, YamlNode>:
  // pair's constructors ask whether YamlNode is constructible while it is
  // still incomplete, which clang refuses (the fuzz build, bug scrub part 3).
  std::vector<YamlEntry> map;
  std::vector<YamlNode> seq;

  const YamlNode *get(std::string_view key) const;
  // The scalar at `key`, or "" when absent or not a scalar.
  std::string str(std::string_view key) const;
  std::optional<std::uint64_t> num(std::string_view key) const;
  bool flag(std::string_view key) const;  // "true"/"yes"/"1"
};

struct YamlEntry {
  std::string first;  // the key
  YamlNode second;    // its value
};

// Parses a block-style YAML document (what serde writes): nested maps and
// sequences by indentation, `- ` items, plain, single- and double-quoted
// scalars, `#` comments, empty `[]`/`{}`, and a leading `!Tag`. Anchors,
// multi-line scalars and flow collections with content are rejected.
std::optional<YamlNode> parse_yaml(std::string_view text, std::string *error);

std::optional<std::uint64_t> parse_number(std::string_view s);  // 0x.., decimal, -0x.. not accepted

// ---- config.yaml -------------------------------------------------------

enum class DsdModuleKind : std::uint8_t { main, itcm, dtcm, autoload, overlay };
std::string_view to_string(DsdModuleKind k);

struct DsdModuleConfig {
  DsdModuleKind kind = DsdModuleKind::main;
  std::string name;         // "main", "itcm", "ov006", as config.yaml names it
  int overlay_id = -1;      // overlays only
  std::uint32_t autoload_index = 0;  // `kind: !Unknown N` autoloads
  bool signed_overlay = false;
  std::string object;       // the built binary dsd writes (relative to config.yaml)
  std::string hash;
  std::string delinks, symbols, relocations;  // relative to config.yaml
};

struct DsdConfig {
  std::string rom_config;   // the extract's config.yaml (ds-rom), relative to config.yaml
  std::string build_path, delinks_path;
  std::vector<DsdModuleConfig> modules;  // main, the autoloads, the overlays
  const DsdModuleConfig *find(std::string_view module_name) const;
  const DsdModuleConfig *overlay(int id) const;
  const DsdModuleConfig *by_kind(DsdModuleKind kind) const;  // main, itcm or dtcm
};

std::optional<DsdConfig> parse_dsd_config(std::string_view yaml, std::string *error);

// ds-rom's extract config (`rom_config`): the extracted binaries and their
// load addresses. Paths are relative to that file.
struct RomExtractModule {
  std::string name;    // "main", "itcm", "dtcm", "autoload_N", "ov006", "arm7", "arm7_ov000"
  std::string bin;     // path of the binary (decompressed)
  std::uint32_t base_address = 0;
  std::uint32_t code_size = 0;  // 0: the file's size
  std::uint32_t bss_size = 0;
  std::uint32_t entry = 0;      // main and arm7
  int overlay_id = -1;
  bool arm7 = false;
  bool known_address = false;   // the address came from a file, not a guess
};

struct RomExtract {
  std::vector<RomExtractModule> modules;
  std::vector<std::string> warnings;
};

// Reads the extract config and the YAML files it names through `read`
// (a path relative to the extract config's directory; nullopt when it is
// missing). The binaries themselves are not read.
using ReadText = std::optional<std::string> (*)(void *ctx, const std::string &relative_path);
std::optional<RomExtract> parse_rom_extract(std::string_view config_yaml, ReadText read, void *ctx,
                                            std::string *error);

// ---- symbols.txt --------------------------------------------------------

enum class DsdSymbolKind : std::uint8_t { function, data, bss, label };
enum class DsdMode : std::uint8_t { arm, thumb };
enum class DsdDataKind : std::uint8_t { any, byte, short_, word };
enum class DsdScope : std::uint8_t { global, local, weak };

struct DsdSymbol {
  std::string name;
  DsdSymbolKind kind = DsdSymbolKind::function;
  std::string kind_text;  // as written, after `kind:`
  std::uint32_t addr = 0;
  DsdScope scope = DsdScope::global;
  bool ambiguous = false;
  // function, label
  DsdMode mode = DsdMode::arm;
  std::uint32_t size = 0;       // function(size=), bss(size=); 0 when absent
  bool has_size = false;
  bool unknown = false;         // function(...,unknown)
  // data
  DsdDataKind data = DsdDataKind::any;
  std::optional<std::uint32_t> count = 1;  // data(word[4]): 4; data(byte[]): nullopt
  std::string comment;          // after `//` on the line, trimmed
  std::size_t line = 0;         // 1-based

  // The size the kind implies (function and bss size, data element size
  // times count); 0 when unknown.
  std::uint32_t byte_size() const;
};

struct DsdLineError {
  std::size_t line = 0;
  std::string message;
};

struct DsdSymbols {
  std::vector<DsdSymbol> symbols;
  std::vector<DsdLineError> errors;  // lines skipped
};

DsdSymbols parse_dsd_symbols(std::string_view text);
// One symbol line in dsd's exact syntax (no newline), as dsd writes it:
// `name kind:function(arm,size=0x7c) addr:0x02219440 local`.
std::string format_dsd_symbol(const DsdSymbol &s);
std::string format_dsd_kind(const DsdSymbol &s);
// A name dsd can read back as one word: no whitespace, no `//`, no
// unbalanced parentheses, nonempty, at most 4096 bytes.
bool dsd_name_ok(std::string_view name);

// ---- relocs.txt ---------------------------------------------------------

enum class DsdRelocKind : std::uint8_t {
  arm_call, thumb_call, arm_call_thumb, thumb_call_arm, arm_branch, load, overlay_id, link_time_const
};
std::string_view to_string(DsdRelocKind k);

struct DsdRelocModule {
  enum class Kind : std::uint8_t { none, main, itcm, dtcm, overlay, overlays, autoload };
  Kind kind = Kind::none;
  std::vector<std::uint16_t> ids;  // overlay: one; overlays: two or more
  std::uint32_t index = 0;         // autoload(N)
};

struct DsdReloc {
  std::uint32_t from = 0, to = 0;
  std::int64_t addend = 0;
  DsdRelocKind kind = DsdRelocKind::load;
  std::string constant;  // link_time_const(NAME)
  DsdRelocModule module;
  std::size_t line = 0;
  bool call() const;     // a call or branch kind
};

struct DsdRelocs {
  std::vector<DsdReloc> relocs;
  std::vector<DsdLineError> errors;
};

DsdRelocs parse_dsd_relocs(std::string_view text);

// ---- delinks.txt --------------------------------------------------------

struct DsdSection {
  std::string name;   // ".text", ".rodata", ".ctor", ".data", ".bss", ...
  std::uint32_t start = 0, end = 0;
  std::string kind;   // code, data, rodata, bss ("" in a file entry: the module's)
  std::uint32_t align = 0;
  std::size_t line = 0;
};

struct DsdDelinkFile {
  std::string name;   // "src/06_GameOver/Scene/GameOverScene.cpp"
  bool complete = false;
  std::vector<std::string> categories;
  std::vector<DsdSection> sections;
  std::size_t line = 0;
};

struct DsdDelinks {
  std::vector<DsdSection> sections;
  std::vector<std::string> categories;
  std::vector<DsdDelinkFile> files;
  std::vector<DsdLineError> errors;
  const DsdSection *section(std::string_view name) const;
  // The module's extent: the lowest start and the highest end of its
  // sections; {0, 0} without sections.
  std::pair<std::uint32_t, std::uint32_t> extent() const;
};

DsdDelinks parse_dsd_delinks(std::string_view text);

// ---- Writing symbols.txt back -------------------------------------------

// What revkit knows at one address of a module, for the export.
struct ExportSymbol {
  std::uint32_t addr = 0;
  std::string name;               // revkit's current name (what the user typed, or the import's)
  DsdSymbolKind kind = DsdSymbolKind::function;
  DsdMode mode = DsdMode::arm;
  std::uint32_t size = 0;         // functions: the body's size; data: the defined size; 0 unknown
  DsdDataKind data = DsdDataKind::any;
  std::optional<std::uint32_t> count = 1;
  bool in_bss = false;            // data in a bss section: written as kind:bss
};

struct SymbolChange {
  enum class Kind : std::uint8_t { renamed, added, skipped };
  Kind kind = Kind::renamed;
  std::uint32_t addr = 0;
  std::string old_name, new_name;
  std::size_t line = 0;   // in the old file (renamed); 0 for added
  std::string reason;     // skipped: why
};

struct SymbolsExport {
  std::string text;                    // the new symbols.txt
  std::vector<SymbolChange> changes;
  std::size_t renamed = 0, added = 0, skipped = 0;
};

// How a revkit name relates to a dsd name: `same(dsd_name, revkit_name)` is
// true when revkit's name stands for the dsd one unchanged (equal, or its
// demangled display form). The export keeps the dsd spelling then.
using SameName = bool (*)(void *ctx, std::string_view dsd_name, std::string_view revkit_name);

struct ExportOptions {
  bool add_new = true;        // write functions and data dsd doesn't list
  bool rename = true;         // write renames of listed symbols
  // Names revkit invents (FUN_0200abcd, DAT_..., LAB_...) are never written.
};

// The old file's text with each listed symbol whose revkit name differs
// renamed in place (the rest of the line kept: kind, address, scope,
// comment), and each new symbol inserted in address order (appended when
// the file isn't sorted). `symbols` is what revkit has; addresses dsd
// lists that revkit has no name for keep their line.
SymbolsExport export_dsd_symbols(std::string_view old_text, const std::vector<ExportSymbol> &symbols,
                                 SameName same, void *ctx, const ExportOptions &options = {});

// A unified diff (3 lines of context) between two texts, with the given
// file labels; "" when they are equal.
std::string unified_diff(std::string_view a, std::string_view b, std::string_view label_a,
                         std::string_view label_b);

// True for names revkit invents for unnamed things (FUN_, DAT_, LAB_,
// SUB_, PTR_, s_, u_, thunk_FUN_, switchD_, caseD_...) and dsd's own
// placeholders (func_0200abcd, func_ov006_0221a000, data_..., ...).
bool generated_name(std::string_view name);

}  // namespace revkit::nds
