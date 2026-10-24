// Nintendo DS games as revkit programs (docs/nds.md): a ds-decomp project
// (its config.yaml, each module's symbols.txt, relocs.txt and delinks.txt,
// and the extracted module binaries) or a .nds ROM image becomes one raw
// program per module at its load address, all in one folder:
//
//   main, the ITCM and DTCM (and other) autoloads, the ARM9 overlays
//   ARM:LE:32:v5t; the ARM7 and its overlays ARM:LE:32:v4t
//
// A module's sections (delinks.txt) are its memory blocks, its symbols
// (symbols.txt) the image's symbol table (loader::RawOptions::symbols:
// function symbols seed and name functions, Thumb ones odd, mangled names
// demangled as an ELF's are; data and bss symbols label data), and each
// translation unit delinks.txt lists a plate comment at its start
// (import:dsd). Each program records which modules it is linked to (the
// dsd record, kDsdSub): the decompiler and the listing name what a module
// calls or reads in another module from that program (own_inputs.cc).
//
// The overlays share addresses, so each is its own program rather than an
// overlay space; a module links the overlays its relocs.txt names alone
// (module:overlay(N)), never those an ambiguous reference names
// (module:overlays(...)).
#pragma once

#include "msvc_import.h"

#include "revkit/loader/image.hh"
#include "revkit/nds/dsd.hh"
#include "revkit/nds/rom.hh"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace revkit::backend {

// The NOTE sub on a module program's record: "revkit:program.dsd". Its
// value, one `key value` per line:
//   source dsd|nds
//   config <absolute path of config.yaml>   (dsd)
//   rom <absolute path of the .nds>         (nds)
//   module <name>                           ("main", "ov006", "arm7")
//   symbols <absolute path of symbols.txt>  (dsd)
//   cpu arm9|arm7
//   link <module name> <program id>         (one per linked module)
inline constexpr std::string_view kDsdSub = "revkit:program.dsd";
// A NOTE at a function's address: the symbol as the linker spells it
// (mangled), where its name is the demangled form (the decomp knowledge
// base's names, docs/decomp-kb.md). ExportDsdSymbols writes this spelling.
inline constexpr std::string_view kDsdSymbolSub = "revkit:dsd.symbol";

struct DsdRecord {
  std::string source, config, rom, module, symbols, cpu;
  std::vector<std::pair<std::string, std::string>> links;  // module name, program id
  std::string encode() const;
  static DsdRecord decode(std::string_view text);
};

struct NdsModulePlan {
  std::string name;   // "main", "itcm", "ov006", "arm7", "arm7_ov000"
  std::string kind;   // main, itcm, dtcm, autoload, overlay, arm7, arm7_overlay
  int overlay_id = -1;
  bool arm7 = false;
  std::string language;  // "ARM:LE:32:v5t" or "ARM:LE:32:v4t"
  std::string binary_path;  // host path of the bytes (dsd); empty for a ROM's module
  std::shared_ptr<loader::Bytes> bytes;
  loader::RawOptions raw;   // base, regions, symbols, entry
  std::uint32_t base = 0, size = 0, bss = 0;
  AnalysisFacts facts;      // import:dsd (translation units)
  std::vector<std::string> warnings;
  std::string symbols_path;  // dsd: the module's symbols.txt (host path)
  std::set<std::string> links;  // the module names it is linked to
  std::size_t symbols = 0, functions = 0, thumb_functions = 0, data = 0, relocs = 0, cross_relocs = 0,
              ambiguous_relocs = 0, sections = 0, units = 0;
};

struct NdsProjectPlan {
  std::string source;       // "dsd" or "nds"
  std::string path;         // the config.yaml or the .nds (absolute)
  std::string game;         // a folder name: the ROM's title and code, or the project's directory
  std::vector<NdsModulePlan> modules;
  std::vector<std::string> warnings;
};

struct NdsPlanOptions {
  bool arm7 = true;                  // the ARM7 and its overlays, when the extract or ROM has them
  std::set<std::string> only;        // module names to plan; empty: all
  std::uint64_t max_file = 256u << 20;  // a module binary or text file
  // Whether a file (its canonical path) may be read: under a --browse-root.
  std::function<bool(const std::string &)> allowed;
  // The --browse-root directories the files are opened below (ReadRegularFile).
  std::vector<std::string> roots;
};

// Whether `canonical` is a --browse-root or below one.
bool UnderBrowseRoot(const std::string &canonical, const std::vector<std::string> &roots);

// From a ds-decomp config.yaml on the host. Paths in it are relative to
// its directory; the module binaries come from the extract its
// rom_config names (ds-rom's layout, decompressed), else from each
// module's `object` (the built binary) at its delinks.txt's lowest
// address. nullopt with `error` when the config can't be read.
std::optional<NdsProjectPlan> PlanDsdProject(const std::string &config_path, const NdsPlanOptions &options,
                                             std::string *error);

// From a .nds ROM image (nds::parse_nds): the same modules, with no
// symbols (the ROM has none) and one block per module (code and its .bss).
std::optional<NdsProjectPlan> PlanNdsRom(const std::string &path, std::shared_ptr<const loader::Bytes> rom,
                                         const NdsPlanOptions &options, std::string *error);

// The links each module gets (NdsModulePlan::links already holds what its
// relocations say): every ARM9 module is linked to main and the
// autoloads, and the ARM7's modules to the ARM7.
void CompleteLinks(NdsProjectPlan &plan);

}  // namespace revkit::backend
