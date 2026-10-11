// Decompiler inputs from revkit's own components.
//
// Ghidra's decompiler is told about a program by Ghidra's Java side: what
// its loader, its auto-analysis and its debug-info import put in the
// program database (docs/decompiler-inputs.md). revkit::lift::InputDecompiler
// answers the decompiler the same way from a lift::DecompilerInputs. This
// library fills a DecompilerInputs from revkit alone, as Ghidra's Java side
// would have filled its database:
//
//   loader     memory blocks, the ELF EXTERNAL block Ghidra's loader lays
//              out for imported symbols, relocated pointer slots (GOT and
//              RELATIVE) as they read after loading, PE import slots as
//              external references, the PE thread block, tracked register
//              values (RISC-V gp, PE GS_OFFSET)
//   analysis   functions (revkit::analysis discovery: names, bodies,
//              thunks, no-return), CALL_RETURN on import-stub jumps, code
//              labels where something refers to them
//   debug info DWARF and PDB names, prototypes, locals, globals, types and
//              namespaces (revkit::debuginfo into the type store, encoded
//              as Ghidra's own DWARF and PDB importers name things)
//
// Every piece is a pure function of the image, discovery's results and the
// debug info, and is shared by rk-lift --analyze --decompile and the image
// backend (src/backend), so both decompile under the same inputs.
#pragma once

#include "revkit/analysis/analysis.h"
#include "revkit/analysis/data.h"
#include "revkit/analysis/no_return.h"
#include "revkit/facts/codec.h"
#include "revkit/lift/decomp_inputs.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/image.hh"

#include <cstdint>
#include <functional>
#include <span>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace revkit::types {
class TypeStore;
}
namespace revkit::inputs {
struct LibraryPrototypes;
}

namespace revkit::inputs {

// Which kinds of facts to assemble. All on by default; turning one off is
// how the parity measurement attributes the output to each.
struct Options {
  bool relocations = true;    // EXTERNAL block, GOT and RELATIVE slots as relocated
  bool plt_overrides = true;  // CALL_RETURN on import-stub jumps
  bool no_return = true;      // discovery's no-return functions
  bool imports = true;        // PE import slots as external references
  bool tracked = true;        // RISC-V gp, PE GS_OFFSET and the thread block
  bool labels = true;         // LAB_ only where code is referred to
  bool debug_info = true;     // DWARF and PDB
  bool data = true;           // loader data symbols (pointer slots, imported data)
  // Library prototypes for imported (and external, and like-named local)
  // functions by name (library.h): revkit's archives, then Ghidra's type
  // archive in the Ghidra install (generic_clib_64, windows_vs12_64) for
  // names they don't declare.
  bool library_signatures = true;
  // The archives to apply; null: the shipped ones for the image
  // (default_library). The image backend passes the project's choice.
  std::shared_ptr<const LibraryPrototypes> library;
  // Ghidra's .gdt archive after revkit's (for names they lack).
  bool ghidra_library = true;
  // The demangler analysis (demangled.h, docs/demangle.md): functions,
  // labels and data named by mangled symbols get the demangled names, and
  // functions with no better signature the mangled one's prototype.
  bool demangle = true;
  bool stack_locals = true;  // Ghidra's Stack analyzer: local_<offset> variables
  // Data analysis (analysis::Data): strings, pointers and accessed data
  // where Ghidra's analyzers define them.
  bool data_analysis = true;
  // PDB prototypes. ghidra: as Ghidra's PDB applicator gives them (a
  // near-C procedure's convention __cdecl, unknown without parameters, and
  // parameters param_N: it doesn't apply the PDB's names), which is what
  // the parity measurement compares; full: the PDB's own names and the
  // default convention (the daemon, which shows users what the PDB says).
  // Scoped to that step only.
  enum class PdbSignatures { ghidra, full } pdb_signatures = PdbSignatures::ghidra;
  // Ghidra's Decompiler Parameter ID (param_id.h): signatures the
  // decompiler finds for the program's own functions, bottom-up, where
  // Ghidra runs the analyzer (a PE below 2 MiB of addresses). Applied after
  // assembly (it decompiles), by whoever runs it: rk-lift's
  // decompd::param_id_functions, the backend's analysis.param_id.
  bool param_id = true;
};

// ---- loader ----

// One imported symbol Ghidra's ELF loader places in its EXTERNAL block.
struct ExternalSymbol {
  std::string name;
  std::uint64_t address = 0;
  std::uint64_t size = 0;
  bool data = false;  // an STT_OBJECT symbol (a label), else a function
};

// The EXTERNAL block (ElfProgramBuilder.allocateExternalSymbol): undefined
// symbols of every symbol table in section order, each at the next free
// slot (pointer-sized, or a data symbol's size rounded up to it) of a block
// that starts at the first 4 KiB boundary past the image's last block.
// Duplicates and versioned names (free@GLIBC_2.2.5) share their first slot.
struct ExternalBlock {
  std::uint64_t start = 0;
  std::uint64_t end = 0;  // inclusive; start > end when empty
  std::vector<ExternalSymbol> symbols;  // by address

  bool empty() const { return symbols.empty(); }
  const ExternalSymbol *find(const std::string &name) const;
  const ExternalSymbol *at(std::uint64_t address) const;
};
ExternalBlock external_block(const loader::Image &image);

using Patch = std::pair<std::uint64_t, std::vector<std::uint8_t>>;

// Pointer slots as Ghidra's ELF loader leaves them: RELATIVE relocations
// (base + addend), and JUMP_SLOT, GLOB_DAT and absolute relocations against
// imported symbols pointing at the symbol's EXTERNAL slot (+ addend).
std::vector<Patch> relocation_patches(const loader::Image &image, const ExternalBlock &external);

// Tracked register values Ghidra's analysis sets at every function entry:
// RISC-V gp from __global_pointer$ (RISCVAddressAnalyzer); on x86-64 PE,
// GS_OFFSET at the thread block (the loader's ThreadEnvironmentBlock).
// The language's pspec tracked_set (x86 DF) the decompiler reads itself.
struct TrackedRegister {
  std::string name;  // register name, resolved to storage by the decompiler's language
  std::uint64_t value = 0;
};
std::vector<TrackedRegister> tracked_registers(const loader::Image &image, const std::string &language_id);

// ---- debug info ----

struct DebugInfo;  // debug.cc

// The image's DWARF and, for a PE, the PDB that matches it, looked up as
// rk-debuginfo does (the debug directory's path, its file name beside
// `binary`, then <stem>.pdb). Null if there is neither.
std::shared_ptr<const DebugInfo> read_debug_info(const loader::Image &image, const std::filesystem::path &binary);

// ---- analysis ----

// What assembly reads from function discovery.
class Analysis {
 public:
  virtual ~Analysis() = default;
  virtual const analysis::ProgramInfo &info() = 0;
  virtual const analysis::FunctionList &functions() = 0;
  // The flow of a function by its FunctionInfo::flow_key().
  virtual const analysis::FlowGraph &flow(std::uint64_t entry) = 0;
  // The same, held only by the caller, from any thread when the analysis
  // allows it (concurrent() is true); the default keeps it like flow().
  virtual std::shared_ptr<const analysis::FlowGraph> flow_shared(std::uint64_t entry) {
    return std::shared_ptr<const analysis::FlowGraph>(std::shared_ptr<void>(), &flow(entry));
  }
  virtual bool concurrent() const { return false; }
  // Data analysis's results (analysis::Data), or null if there are none.
  virtual const analysis::DataList *data() { return nullptr; }
  // The functions Ghidra's evidence finds non-returning
  // (analysis::NoReturnEvidence), or null if not known.
  virtual const std::vector<std::uint64_t> *no_return_evidence() { return nullptr; }
};

// Discovery over an in-memory fact store, as rk-lift --analyze runs it.
// `jobs` > 1 decodes the seeds in parallel first. Past `memo_budget` bytes
// the store drops what it memoized (flow graphs are read again by
// decoding), so after discovery it doesn't hold every flow.
std::unique_ptr<Analysis> analyze(const loader::Image &image, const std::string &language_id, unsigned jobs = 1,
                                  std::size_t memo_budget = SIZE_MAX);

// ---- assembly ----

struct Program {
  std::shared_ptr<const loader::Image> image;
  std::string language_id;  // with compiler: "x86:LE:64:default:gcc"
  Analysis *analysis = nullptr;
  std::shared_ptr<const DebugInfo> debug;  // may be null
  // The image's bytes as patched (docs/patching.md), where the inputs read
  // contents; null: the image's own.
  std::function<void(std::uint64_t addr, std::span<std::byte> out)> read = {};
};

// Everything: the program's facts with every function's merged in (each
// function's on `threads` threads; the result is the same).
lift::DecompilerInputs assemble(const Program &program, const Options &options = {}, unsigned threads = 1);

// The program-wide facts that don't depend on discovery: memory (with
// the EXTERNAL and thread blocks), relocation patches, EXTERNAL functions
// and data, PE import references, the thread block's data and types, the
// loader's non-function symbols, and the relocated pointer slots' values.
// A change to the function list leaves them as they are, so the image
// backend computes them once (inputs.static) and only the part that does
// depend on discovery again (inputs.program).
struct StaticInputs {
  std::vector<lift::BlockFacts> memory;
  std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>> patches;
  lift::DecompilerInputs external;  // EXTERNAL functions and data
  lift::DecompilerInputs imports;   // PE import references and their slots as data
  lift::DecompilerInputs thread;    // the thread block: memory, synthesized bytes, data, types
  // The best non-function symbol at each address (before functions
  // claim some): data when it is an object in mapped memory, else a label.
  struct Symbol {
    std::uint64_t address = 0;
    std::string name;
    std::uint64_t size = 0;
    bool data = false;
    lift::Mutability mutability = lift::Mutability::normal;
    friend bool operator==(const Symbol &, const Symbol &) = default;
  };
  std::vector<Symbol> symbols;  // by address
  // Relocated pointer slots: address, the pointer it holds, mutability.
  struct Slot {
    std::uint64_t address = 0;
    std::uint64_t value = 0;
    lift::Mutability mutability = lift::Mutability::normal;
    bool mapped = false;  // the value is a mapped address
    friend bool operator==(const Slot &, const Slot &) = default;
  };
  std::vector<Slot> slots;  // by address
  // EXTERNAL symbols' names by address, in the block's order (later ones
  // at an address win).
  std::vector<std::pair<std::uint64_t, std::string>> external_names;

  void encode(facts::Encoder &e) const;
  static StaticInputs decode(facts::Decoder &d);
};
// Reads the image and the analysis's ProgramInfo, never its functions.
StaticInputs assemble_static(const Program &program, const Options &options = {});

// What naming a pointer takes: the labels of functions, symbols, EXTERNAL
// entries and analyzed data by address, every function body (merged), and
// every pointer to mapped memory laid out (relocated slots and analyzed
// pointers) with the address it holds, for PTR_<target>_<address>.
// Decompiler inputs speak (space, offset); revkit keys addresses in other
// memory spaces (loader::AddressSpace). These move a keyed address (with
// an empty space) to its space and offset there; every address of the
// program's inputs (data, labels, blocks, external references).
void unkey(const loader::Image &image, std::string &space, std::uint64_t &addr);
void unkey(lift::DecompilerInputs &in, const loader::Image &image);

struct SlotNames {
  std::unordered_map<std::uint64_t, std::string> names;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> bodies;  // merged, sorted
  std::string prefix;  // the address prefix of default names
  unsigned word = 8;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> pointers;  // (address, value), sorted
  // The image, for addresses in other memory spaces (loader::name_address).
  const loader::Image *image = nullptr;

  bool in_body(std::uint64_t a) const;
  const std::uint64_t *pointer_at(std::uint64_t a) const;
};

// The name Ghidra's database gives pointer data at `at` holding `value`
// (PointerDataType.getLabelString, then the address): PTR_ and the
// target's label (a default label without its address: PTR_FUN_, PTR_s_hi_,
// PTR_DAT_), PTR_PTR_ past two levels, PTR_LOOP_ for a cycle, PTR_ alone
// for an unmapped value.
std::string pointer_name(std::uint64_t at, std::uint64_t value, bool mapped, const SlotNames &names);

// The program-wide facts: memory, relocations, functions with signatures
// and debug-info locals, data, labels, imports, types. Reads discovery's
// function list, not its flows; with `static_inputs`, takes what doesn't
// depend on it from there (assemble_static of the same program). With
// `slots`, relocated pointer slots are left out of `data` (a large program
// has hundreds of thousands) and what naming them takes goes to `slots`:
// pointer_slot() makes one when it is looked up.
lift::DecompilerInputs assemble_program(const Program &program, const Options &options = {},
                                        const StaticInputs *static_inputs = nullptr, SlotNames *slots = nullptr);

// The pointer slot assemble_program would have laid out at `slot` (one of
// static_inputs.slots) when `slots` was given, unless data it laid out
// starts there.
lift::DataFacts pointer_slot(const StaticInputs::Slot &slot, const SlotNames &names);

// Which addresses start functions and which of those never return: what a
// function's flow overrides depend on besides its own flow.
struct FunctionSets {
  std::vector<std::uint64_t> entries;    // sorted
  std::vector<std::uint64_t> no_return;  // sorted
  bool is_entry(std::uint64_t a) const;
  bool is_no_return(std::uint64_t a) const;
  void encode(facts::Encoder &e) const;
  static FunctionSets decode(facts::Decoder &d);
  friend bool operator==(const FunctionSets &, const FunctionSets &) = default;
};
// No-return: the functions on the known list, and those `evidence` (Ghidra's,
// analysis::NoReturnEvidence) holds; discovery's own inference stops its
// bodies but isn't what Ghidra tells the decompiler.
FunctionSets function_sets(const analysis::FunctionList &list, const std::vector<std::uint64_t> *evidence = nullptr);
// Those no-return functions, sorted: the known names, the evidence, and
// thunks of either.
std::vector<std::uint64_t> ghidra_no_return(const analysis::FunctionList &list, const std::vector<std::uint64_t> *evidence);

// One function's facts from its own flow.
struct FunctionInputs {
  std::vector<lift::LocalFacts> locals;  // Ghidra's stack variables (the debug info's are the program's)
  std::vector<std::pair<std::uint64_t, std::string>> flow_overrides;  // in its body
  std::vector<lift::LabelFacts> code_labels;                          // LAB_ at targets in its body
};
// `debug_locals`: the function's locals from the debug info, which stack
// variables must not overlap. `lifter` decodes the image's instructions.
FunctionInputs assemble_function(const Program &program, const Options &options, const FunctionSets &sets,
                                 const analysis::FunctionInfo &function, const analysis::FlowGraph &flow,
                                 const std::vector<lift::LocalFacts> &debug_locals, lift::Lifter &lifter);

}  // namespace revkit::inputs
