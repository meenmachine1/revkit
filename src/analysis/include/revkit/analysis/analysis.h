// Function discovery and code coverage as queries over the fact engine.
//
// Inputs: the program's bytes (facts::MemoryPage) and ProgramInfo, what the
// loader knows (code ranges, seeds, import slots), set once at import; and
// the user's assertions about functions and flow (see "Assertions" below).
// Every query is keyed by program (ProgramKey, or a Location in one), so
// one engine holds any number of programs, each in its own code space.
//
//   analysis.stub(addr)      (internal) is the code at addr a jump stub:
//                            a PLT/IAT import stub or a jump to code
//   analysis.thunk(addr)     a stub, or a function whose first instruction
//                            calls a function that never returns
//   analysis.flow(entry)     recursive-descent disassembly from one entry:
//                            every instruction reachable through branches,
//                            fallthrough and jump tables, plus call targets
//   analysis.functions()     the discovery fixpoint over the whole program:
//                            entries (seeds and call targets), no-return
//                            functions, bodies and default names
//   analysis.function(entry) one function's slice of that, so readers keyed
//                            by function only change when that function does
//
// Purity. Every query is a pure function of what it reads through its
// QueryContext. Bytes come from the store, never from the loader::Image:
// queries read pages and decode exactly those bytes with
// lift::Lifter::lift(address, bytes), using SLEIGH engines leased from a
// process-wide pool (keyed by language and context). A patched byte
// re-runs only the flows and stubs that read its page, then `functions`,
// which re-validates every other flow by fingerprint.
//
// No-return. Known by name (Ghidra's ELF and PE lists, compared without
// leading underscores, plus err/errx, quick_exit, __cxa_rethrow,
// __chk_fail; minus "cexit"/"c_exit", since msvcrt's _cexit returns), or
// inferred: no path from the entry reaches a return, an unresolved
// computed jump, a dead end, or a returning function it jumps or falls
// into, once flow stops after calls to no-return functions. That is the
// least fixed point from the named set, computed in `functions` over the
// flow graphs, so it is deterministic and has no query cycles; `flow`
// itself only uses names.
//
// Assertions. Discovery reads two kinds of facts::FactDb assertions in the
// program's code space (ProgramInfo::space), as the API stores them:
//   FUNCTION_BOUNDS@entry  an AddressSet: a function starts at entry (a
//                          seed), with that body if it isn't empty; the
//                          integer kNotAFunction: nothing starts there
//                          (not a seed, not a call target, and flows go on
//                          through it)
//   FLOW_OVERRIDE@addr     a FlowOverride: the instruction's flow changed
//                          as Ghidra's flow overrides change it
//   REFERENCE@addr         a user reference (user_refs.h): a call type
//                          makes its target a function (FlowGraph::
//                          ref_calls), a jump type from a computed jump
//                          adds a target the flow goes on at
//   FALLTHROUGH@addr       a FallthroughOverride (SetFallthrough): the
//                          instruction's fallthrough goes there instead of
//                          to the next instruction, or nowhere
// Flow reads the overrides on the instructions it decodes and the bounds
// at the seeds it reaches, each through its 256-byte span of the key index
// (facts::AssertedSpan), so an edit re-runs only the flows that saw it.
// Functions reads every FUNCTION_BOUNDS key. An asserted body wins over the
// discovered ones: it is taken out of every other function's body. Where
// asserted bodies overlap (concurrent edits, docs/collab.md), an address
// goes to the claiming entry closest at or before it.
//
// Bodies are what flow reaches from the entry without crossing another
// entry or the fallthrough of a no-return call, so alignment padding is
// never in a body. Code several functions reach goes to the closest entry
// at or before it, which is where Ghidra's CreateFunctionCmd ends up.
//
// Jump tables are recovered by probing the p-code on the path to the
// computed jump (jump_tables.cc), not with the decompiler: the decompiler
// reads bytes through its own LoadImage, which would make the query
// impure, and costs a full decompile per switch.
//
// Data and code. Only executable, initialized memory outside $d ranges is
// decoded; seeds and call targets must decode and may not start inside an
// instruction a function already has. There is no linear sweep, so
// constants and padding never become functions. Words code loads from
// constant addresses in code (literal pools) are data (FlowGraph::literals).
//
// Computed jumps and calls. A flow resolves what the instructions before a
// BRANCHIND or CALLIND fix (jump_tables.cc, resolve_computed): a target
// loaded from a literal pool or computed from the program counter, a jump
// to the unchanged link register (a return: ARM's mov pc, lr), and a
// link register just set to the return address (a call: ARM's mov lr, pc
// before a jump). FlowInsn::resolved marks them, for the decompiler.
//
// ARM interworking (ProgramInfo::isa_context). A Flow key with the low bit
// set is Thumb code at the address without it (ProgramInfo::code_key):
// decoded with a Thumb engine, its calls and BX/BLX targets keyed by the
// instruction set the TB register says. FunctionInfo::entry is the plain
// address; kFunctionThumb and flow_key() say how to read its flow.
//
// Firmware search (ProgramInfo::search, raw images: nothing to seed from
// but the processor's vectors). Once calls find nothing new, the language's
// Ghidra function-start patterns are matched in code nothing reached
// (search.cc, search_starts), with the conditions Ghidra's Function Start
// Search applies (what comes before, how many instructions decode); code
// pointers from literal pools and pointer tables count as the data
// references those conditions accept. When they find nothing new either,
// code that isn't a function is looked for at gap starts, as Ghidra's ARM
// Aggressive Instruction Finder does (find_code): its calls make functions,
// it never becomes one. A start only a "possible" pattern made, that
// another function's code falls into, is dropped. docs/firmware.md.
//
// To use: lift::initialize(), register_queries(engine), write the bytes
// and ProgramInfo (import_image does both for a loaded image), then read
// Functions or Function from a snapshot.
#pragma once

#include "revkit/facts/engine.h"
#include "revkit/facts/fact_db.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/image.hh"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::analysis {

// An inclusive [first, last] range in the code space.
struct Range {
  std::uint64_t first = 0;
  std::uint64_t last = 0;

  bool contains(std::uint64_t a) const { return a >= first && a <= last; }
  void encode(facts::Encoder &e) const;
  static Range decode(facts::Decoder &d);
  friend auto operator<=>(const Range &, const Range &) = default;
};

// Why an address is known to start a function before any analysis.
enum SeedFlags : std::uint16_t {
  kSeedEntry = 1 << 0,     // the image's entry point
  kSeedSymbol = 1 << 1,    // a defined function symbol
  kSeedExport = 1 << 2,    // a PE export
  kSeedUnwind = 1 << 3,    // an unwind-table entry (.eh_frame FDE, PE .pdata)
  kSeedInit = 1 << 4,      // DT_INIT/DT_FINI or a (pre)init/fini array entry
  kSeedPlt = 1 << 5,       // a PLT stub or the PLT header
  kSeedProcessor = 1 << 6, // an entry point the processor spec names (ARM's exception vectors)
  kSeedFunctionStarts = 1 << 7,  // a Mach-O LC_FUNCTION_STARTS entry
};

struct Seed {
  std::uint64_t address = 0;
  std::uint16_t flags = 0;  // SeedFlags
  // The name the file gives it: a symbol or export, else a conventional one
  // ("entry", "_INIT_0", "_DT_FINI"); empty when it has none.
  std::string name;
  // Whether `name` came from a symbol or export (it then beats thunk names).
  bool named_by_symbol = false;

  void encode(facts::Encoder &e) const;
  static Seed decode(facts::Decoder &d);
  friend bool operator==(const Seed &, const Seed &) = default;
};

// A memory slot the program loads an imported symbol's address from: an
// ELF GOT entry (JUMP_SLOT, GLOB_DAT, or an absolute relocation against an
// undefined symbol) or a PE IAT entry.
struct ImportSlot {
  std::uint64_t address = 0;
  std::string name;

  void encode(facts::Encoder &e) const;
  static ImportSlot decode(facts::Decoder &d);
  friend bool operator==(const ImportSlot &, const ImportSlot &) = default;
};

// A context variable painted over part of the code space (ARM "TMode").
struct ContextSetting {
  std::string name;
  std::uint32_t value = 0;
  Range range;

  void encode(facts::Encoder &e) const;
  static ContextSetting decode(facts::Decoder &d);
  friend bool operator==(const ContextSetting &, const ContextSetting &) = default;
};

// A function-start pattern from the language's Ghidra pattern files
// (Ghidra/Processors/<proc>/data/patterns, Apache 2.0, read from the
// install): bytes before and at a function start, with the conditions
// Ghidra's Function Start Search applies to a match.
struct StartPattern {
  enum class Kind : std::uint8_t { function, possible };  // funcstart, possiblefuncstart
  // What must come right before the start ("after" attribute).
  enum class After : std::uint8_t { any, defined, function, instruction, data, pointer };

  std::vector<std::uint8_t> value, mask;  // the pre-pattern's bytes, then the post-pattern's
  std::uint32_t pre = 0;    // bytes of `value` before the start
  std::uint32_t align = 1;  // the start is a multiple of this
  std::int32_t isa = -1;    // the instruction-set context value it sets (Thumb 1, ARM 0), or -1
  Kind kind = Kind::function;
  After after = After::any;
  std::uint16_t valid_min = 0;  // instructions that must decode from the start
  std::uint16_t valid_max = 0;  // checked at most (0: valid_min)
  bool contiguous = true;       // straight-line instructions only

  void encode(facts::Encoder &e) const;
  static StartPattern decode(facts::Decoder &d);
  friend bool operator==(const StartPattern &, const StartPattern &) = default;
};

// The language's function-start patterns, as Ghidra's patternconstraints.xml
// selects them by language id; empty if it has none. lift::initialize()
// must have been called. Throws lift::LiftError on a malformed file.
std::vector<StartPattern> load_start_patterns(const std::string &language, const std::string &compiler);

// A pattern that names the function it starts (funcstart label="..."), as
// Ghidra's Function Start Pre Search and Function Start Search label what
// they find: compiler helpers with side effects that the compiler spec
// has call fixups for (ARM's __gnu_thumb1_case_uqi, x86's
// __i686.get_pc_thunk.bx).
struct LabelPattern {
  StartPattern pattern;
  std::string label;
};
// Those of the language's pattern files (prepatternconstraints.xml and
// patternconstraints.xml), read once per language and compiler; empty if
// it has none or they can't be read. lift::initialize() must have been
// called.
const std::vector<LabelPattern> &label_patterns(const std::string &language, const std::string &compiler);

// A register as (offset, size) in the register space.
using RegisterSlot = std::pair<std::uint64_t, std::uint32_t>;

// A memory space as the program's addresses key it (loader::AddressSpace):
// the default code space at base 0, and each other space the image has
// blocks in at its base. Offsets are bytes; `wordsize` is bytes per
// addressable unit (AVR's code space: 2), what a pointer into the space
// counts in and what display divides by.
struct SpaceInfo {
  std::string name;
  std::uint64_t base = 0;
  std::uint32_t wordsize = 1;
  // Hex digits of default names' offsets: Ghidra pads an offset to its
  // space's size, at most 8 (FUN_code_003a on AVR, FUN_00101000 on x86-64).
  std::uint32_t digits = 8;
  bool alias = false;  // a byte-mapped view of the default space (AVR's codebyte)

  void encode(facts::Encoder &e) const;
  static SpaceInfo decode(facts::Decoder &d);
  friend bool operator==(const SpaceInfo &, const SpaceInfo &) = default;
};

// A register value analysis assumes over a range from what the loader
// knows (docs/api.md, "Register values"): MIPS gp from _gp, PowerPC 64 r2
// at the TOC base, PowerPC 32 r13 and r2 at _SDA_BASE_ and _SDA2_BASE_.
// The user's values (FactKind::RegisterValue) paint over these
// (analysis.register_values, register_values.h).
struct RegisterDefault {
  std::string name;  // the register, as the language spells it ("gp", "r2")
  RegisterSlot slot;
  Range range;
  std::uint64_t value = 0;
  std::string origin;  // which rule: "mips-gp", "ppc64-toc", "ppc64-opd", "ppc64-entry", "ppc-sda", "ppc-sda2"

  void encode(facts::Encoder &e) const;
  static RegisterDefault decode(facts::Decoder &d);
  friend bool operator==(const RegisterDefault &, const RegisterDefault &) = default;
};

// What the loader knows about the program, as the analysis input.
struct ProgramInfo {
  std::string language;  // SLEIGH language id, "x86:LE:64:default"
  std::string compiler;  // compiler spec id, "gcc"
  facts::SpaceId space = 1;  // the code space's id in the fact store
  std::string code_space = "ram";  // its SLEIGH name, as p-code varnodes spell it
  // Default names carry the space when the language has several memory
  // spaces, as Ghidra's do: FUN_ram_00101000.
  bool qualify_names = false;
  bool big_endian = false;
  std::uint8_t pointer_size = 8;
  std::vector<Range> code;          // executable, initialized memory; sorted, disjoint
  std::vector<Range> data_in_code;  // data marked inside code ($d mapping symbols); sorted
  std::vector<Range> plt;           // PLT sections; sorted
  std::vector<ContextSetting> context;
  std::vector<Seed> seeds;          // sorted by address, one per address
  std::vector<ImportSlot> imports;  // sorted by address, one per address
  // Whether Flow records each instruction's references (FlowGraph::refs;
  // the backend's xrefs, off by default), and the memory they may point
  // into: every mapped range, sorted and merged (describe() fills it).
  bool references = false;
  std::vector<Range> mapped;
  // ARM interworking (ARM languages): the context variable that decodes
  // Thumb ("TMode"), the register an instruction sets to the instruction
  // set it branches to (ISAModeSwitch: 1 = Thumb) and the link register.
  // With isa_context set, a flow's key with the low bit set is Thumb code
  // at the address without it (see Flow).
  std::string isa_context;
  std::optional<RegisterSlot> isa_register;
  std::optional<RegisterSlot> link_register;
  // The registers a call preserves (the compiler spec's <unaffected>
  // list): constants carried along a flow for data references live on in
  // them across a call, and only in them. Empty: every register is
  // forgotten at a call.
  std::vector<RegisterSlot> call_preserved;
  // Firmware search (raw images: no symbols, exports or unwind tables to
  // seed from): functions are also looked for in code nothing reached yet,
  // by the language's start patterns, which code pointers in literal pools
  // and data tables strengthen (see Functions).
  bool search = false;
  std::vector<StartPattern> patterns;
  // A Mach-O: no-return names are its list's (is_known_no_return).
  bool macho = false;
  // Memory the user added to the map (analysis.memory, memory.h) whose
  // bytes aren't the program's own pages: zero-filled regions (space 0)
  // and a file's bytes staged in another space at `offset`. Sorted,
  // disjoint. Readers of the program's bytes lay them over its pages.
  struct SourceRange {
    Range range;
    facts::SpaceId space = 0;  // 0: zeros
    std::uint64_t offset = 0;  // of range.first in `space`

    friend bool operator==(const SourceRange &, const SourceRange &) = default;
  };
  std::vector<SourceRange> sources;
  // The memory spaces (see SpaceInfo): the default one first. Empty in
  // records from before spaces, which mean one byte-addressed space.
  std::vector<SpaceInfo> spaces;
  // Registers a processor maps into memory (AVR's R0-R31 at mem:0x00), as
  // keys: their varnodes are read as registers (at their keys in the
  // register space) rather than memory. Sorted, merged.
  std::vector<Range> register_memory;
  // Register values from the loader's symbols and sections (see
  // RegisterDefault), by register name then range; empty for most
  // programs.
  std::vector<RegisterDefault> register_defaults;

  // Bytes per addressable unit of the code space (1 but on word-addressed
  // code: AVR, PIC).
  std::uint32_t code_wordsize() const { return spaces.empty() ? 1 : spaces.front().wordsize; }
  // The key of a pointer's target: `value` counts in `space`'s units
  // ("" or the code space: code), so it is scaled by its word size and
  // moved to the space's base; nullopt for a space the program has no
  // memory in.
  std::optional<std::uint64_t> pointer_key(std::string_view space, std::uint64_t value) const;
  // The key of a byte offset in a space; nullopt for a space without memory.
  std::optional<std::uint64_t> space_key(std::string_view space, std::uint64_t offset) const;
  // The space a key is in (the default one for keys below every base).
  const SpaceInfo *space_of(std::uint64_t key) const;

  bool is_mapped(std::uint64_t a) const;
  // Interworking: the code address a flow key or tagged pointer names, and
  // whether it is Thumb code (tagged, or painted Thumb by `context`).
  std::uint64_t code_address(std::uint64_t key) const { return isa_context.empty() ? key : key & ~std::uint64_t{1}; }
  bool thumb(std::uint64_t key) const;
  // The key of code at `address` in the given instruction set: tagged when
  // it is Thumb and `context` doesn't already paint it so.
  std::uint64_t code_key(std::uint64_t address, bool thumb) const;

  bool is_code(std::uint64_t a) const;  // in `code` and not in `data_in_code`
  const Seed *seed_at(std::uint64_t a) const;
  const ImportSlot *import_at(std::uint64_t slot) const;

  void encode(facts::Encoder &e) const;
  static ProgramInfo decode(facts::Decoder &d);
  friend bool operator==(const ProgramInfo &, const ProgramInfo &) = default;
};

// Whether code that isn't marked Thumb (a tagged key, the image's context)
// is ARM code: the language has two instruction sets and decodes ARM where
// nothing says otherwise. (On Cortex-M everything is Thumb, marked or not.)
// lift::initialize() must have been called.
bool two_instruction_sets(const ProgramInfo &info);

// Which program: inputs and whole-program queries are keyed by its id
// (the backend's program id; any string, empty included, for a lone one).
struct ProgramKey {
  std::string id;

  void encode(facts::Encoder &e) const { e.bytes(id); }
  static ProgramKey decode(facts::Decoder &d) { return {std::string(d.bytes())}; }
  friend auto operator<=>(const ProgramKey &, const ProgramKey &) = default;
};

// An address in one program's code space: the key of per-address queries.
struct Location {
  ProgramKey program;
  std::uint64_t address = 0;

  void encode(facts::Encoder &e) const {
    program.encode(e);
    e.varint(address);
  }
  static Location decode(facts::Decoder &d) {
    Location l;
    l.program = ProgramKey::decode(d);
    l.address = d.varint();
    return l;
  }
  friend auto operator<=>(const Location &, const Location &) = default;
};
// "id:0x401000", for diagnostics (DerivedFact::inputs).
std::string describe(const Location &l);

// ---- assertions ----

// FLOW_OVERRIDE values: the API's FlowOverrideKind numbers.
enum class FlowOverride : std::int64_t { none = 1, branch = 2, call = 3, call_return = 4, ret = 5 };
// FUNCTION_BOUNDS value meaning "no function starts here".
inline constexpr std::int64_t kNotAFunction = 0;

// A FALLTHROUGH value (SetFallthrough): an Address, where control goes on
// after the instruction; kNoFallthrough, it doesn't go on; kDefaultFallthrough
// (or nothing), the next instruction (the override cleared).
inline constexpr std::int64_t kDefaultFallthrough = 0;
inline constexpr std::int64_t kNoFallthrough = 1;
struct FallthroughOverride {
  bool falls = true;     // false: no fallthrough
  std::uint64_t to = 0;  // where it goes on, if it falls
  friend bool operator==(const FallthroughOverride &, const FallthroughOverride &) = default;
};
// The override a FALLTHROUGH value says, if any (nullopt: the default).
std::optional<FallthroughOverride> fallthrough_override(const facts::FactValue &v);

// Input: what the loader says (describe()), set by the importer
// (stage_image). Queries read Program, which lays the memory map's edits
// over it (memory.h).
struct LoadedProgram {
  static constexpr std::string_view name = "analysis.program.loaded";
  using Key = ProgramKey;
  using Value = ProgramInfo;
  static std::string describe(const Key &k) { return k.id; }
};

// The program as every query sees it: LoadedProgram, unchanged unless the
// memory map is edited; then its mapped ranges, code and byte sources
// follow the effective map (analysis.memory). Named as the input it
// replaced, so memos that read that input validate against it.
struct Program {
  static constexpr std::string_view name = "analysis.program";
  static constexpr std::uint32_t version = 1;
  using Key = ProgramKey;
  using Value = ProgramInfo;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return k.id; }
};

// ---- thunks ----

enum class ThunkKind : std::uint8_t {
  none,
  import,  // jumps through an import slot: a PLT or IAT stub
  direct,  // jumps straight to another address
};

struct ThunkInfo {
  ThunkKind kind = ThunkKind::none;
  std::uint64_t target = 0;  // direct: the destination; import: the slot
  std::string import;        // import: the imported symbol
  Range body;                // the stub's instructions, through the jump

  void encode(facts::Encoder &e) const;
  static ThunkInfo decode(facts::Decoder &d);
  friend bool operator==(const ThunkInfo &, const ThunkInfo &) = default;
};

// Whether the code at an address is a thunk: after instructions with no
// p-code (ENDBR64), at most a few that only compute registers (AArch64 and
// RISC-V PLT stubs load the slot address with adrp/auipc), ending in an
// unconditional jump.
struct Thunk {
  static constexpr std::string_view name = "analysis.thunk";
  static constexpr std::uint32_t version = 6;  // 4: patches through patch.page; 5: the user's no-return marks;
                                               // 6: fallthrough overrides
  using Key = Location;
  using Value = ThunkInfo;
  static Value compute(facts::QueryContext &ctx, const Key &addr);
  static std::string describe(const Key &k) { return analysis::describe(k); }
};

// ---- flow ----

enum class FlowKind : std::uint8_t {
  fall,           // no control transfer
  jump,           // unconditional direct jump; `targets` holds it
  branch,         // conditional direct jump; `targets` holds it
  call,           // direct call; `targets` holds the callee
  call_indirect,  // call through a register or memory
  jump_indirect,  // computed jump; `targets` holds jump-table destinations, if recovered
  ret,            // return (a conditional one, under a RETURN override, falls through)
};

struct FlowInsn {
  std::uint64_t address = 0;
  std::uint32_t length = 0;  // including delay-slot instructions
  FlowKind kind = FlowKind::fall;
  // False for jumps, returns, calls to known no-return functions, and
  // instructions after which decoding failed.
  bool falls_through = true;
  // A computed call or jump through an import slot whose import is known
  // never to return (call/jmp [exit@GOT]): control ends here.
  bool no_return = false;
  std::vector<std::uint64_t> targets;
  // A call that returns from this function too (a CALL_RETURN override).
  bool tail_call = false;
  // Bytes of `length` that are delay-slot instructions.
  std::uint32_t delay = 0;
  // A computed jump or call (BRANCHIND, CALLIND in its p-code) whose kind
  // discovery decided from the code before it: a return to the incoming
  // link register, a call (mov lr, pc), or a jump or call to a known
  // address. The decompiler is told with a flow override.
  bool resolved = false;
  // The instruction only runs under a condition (ARM's conditional
  // execution: blhi, ldrls pc, movne pc, lr): when it doesn't, control
  // falls through, whatever its kind says.
  bool conditional = false;
  // The user's fallthrough override (FactKind::Fallthrough, SetFallthrough;
  // Ghidra's Set Fallthrough): control goes on at `fall_to` when it falls
  // through, or, with falls_through false, doesn't go on at all, instead of
  // the next instruction.
  bool fall_override = false;
  std::uint64_t fall_to = 0;

  // Where control goes on when the instruction falls through: the next
  // instruction, or the override's address.
  std::uint64_t fallthrough() const { return fall_override ? fall_to : address + length; }

  void encode(facts::Encoder &e) const;
  static FlowInsn decode(facts::Decoder &d);
  friend bool operator==(const FlowInsn &, const FlowInsn &) = default;
};

// A reference an instruction's p-code makes, as the backend's xrefs list
// them: direct flow targets, and constants (or constants copied to a
// temporary) that are mapped addresses, other than the instruction's own
// flow targets and fallthrough.
// `fallthrough`: a fallthrough override's address (Ghidra's FALL_THROUGH
// reference).
enum class RefKind : std::uint8_t { call, jump, conditional_jump, data_pointer, data_read, data_write, fallthrough };

struct FlowRef {
  std::uint32_t insn = 0;   // index in FlowGraph::insns
  RefKind kind = RefKind::data_pointer;
  bool delay_slot = false;  // from the instruction's delay slot (decoded on its own)
  std::uint64_t to = 0;

  // The referring instruction's address.
  std::uint64_t from(const struct FlowGraph &g) const;
  friend bool operator==(const FlowRef &, const FlowRef &) = default;
};

// A data access or address the code makes, as Ghidra's constant
// propagation (SymbolicPropogator) finds it: a load or store at a constant
// address with its size, or an address computed into a register or
// stored. Data analysis (data.h) lays data down from them.
enum class DataAccess : std::uint8_t { read, write, address };

struct DataRef {
  std::uint64_t from = 0;  // the instruction
  std::uint64_t to = 0;
  std::uint32_t size = 0;  // read/write: the access size; address: 0
  DataAccess access = DataAccess::address;

  friend auto operator<=>(const DataRef &, const DataRef &) = default;
};

struct FlowGraph {
  std::uint64_t entry = 0;
  std::vector<FlowInsn> insns;  // sorted by address
  bool truncated = false;       // hit the instruction limit
  // With ProgramInfo::references: each instruction's references, by
  // instruction, then delay slot, then (to, kind); one per (to, kind).
  std::vector<FlowRef> refs;
  // Words the code loads from constant addresses in code (literal pools)
  // whose value is a code address: possible function entries, as keys
  // (Thumb tagged). Sorted, unique.
  std::vector<std::uint64_t> code_pointers;
  // Where those loads read: data inside code, never decoded. Sorted, merged.
  std::vector<Range> literals;
  // The data references of these instructions, with values carried along
  // the flow depth first from the entry (fallthrough first, branch targets
  // with the values at the branch, cleared at calls), each instruction
  // with the values of the first path that reaches it. Sorted, unique.
  std::vector<DataRef> data_refs;
  // Calls to switch helpers (instruction, the helper's key), sorted: code
  // that is called and goes on at one of the places a table after the
  // call names (gcc's __gnu_thumb1_case_uqi). The instruction is a
  // computed jump here (jump_indirect, `targets` the table's
  // destinations); this keeps whom it calls.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> case_calls;
  // Call instructions that are jumps within the function (gcc's Thumb-1
  // far jump: a `bl` where a branch doesn't reach), sorted: the code
  // called returns from this function's frame. Each is a `jump` here.
  std::vector<std::uint64_t> far_jumps;
  // User call references (REFERENCE keys of a call type, user_refs.h) from
  // these instructions: (instruction, the callee's key), sorted, unique.
  // Their targets are functions, as the calls' are; a computed jump's
  // user jump references are among its `targets`.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> ref_calls;

  const FlowInsn *at(std::uint64_t address) const;
  void encode(facts::Encoder &e) const;
  static FlowGraph decode(facts::Decoder &d);
  friend bool operator==(const FlowGraph &, const FlowGraph &) = default;
};

// Recursive descent from `entry`: follows fallthrough, branches and jump
// tables, not calls (their targets are recorded). Calls fall through unless
// the callee is no-return by name (an import or symbol on the known list).
// Stops where flow reaches another seed (unless an assertion says no
// function starts there), leaves code, overlaps an instruction already
// decoded, or doesn't decode. Flow overrides change instructions' kinds.
struct Flow {
  static constexpr std::string_view name = "analysis.flow";
  static constexpr std::uint32_t version = 21;  // 5: interworking, computed targets, literals; 6: data refs;
                                                // 7: computed targets on raw images, big-endian data refs;
                                                // 8: fill (runs of one repeated byte) is not code;
                                                // 9: calls to switch helpers; 10: far jumps; 11: shifts out;
                                                // 12: far jumps to far jumps; 13: keyed memory spaces,
                                                // word-addressed targets, settled conditional returns
                                                // after calls (SPARC); 14: patches through patch.page;
                                                // 15: the listing's edits (units.h); 16: a jump
                                                // resolved by a constant index is a table when
                                                // another path's probe finds one; 17: user
                                                // references (user_refs.h); 18: the user's
                                                // no-return marks (FactKind::NoReturn); 19: direct
                                                // memory varnodes as data references (x86-64's
                                                // read-modify-write [rip+x]); 20: the user's
                                                // fallthrough overrides (FactKind::Fallthrough);
                                                // 21: register values over ranges
                                                // (register_values.h)
  using Key = Location;
  using Value = FlowGraph;
  static Value compute(facts::QueryContext &ctx, const Key &entry);
  static std::string describe(const Key &k) { return analysis::describe(k); }
  static std::size_t weight(const Value &v) {
    return sizeof(Value) + v.insns.capacity() * (sizeof(FlowInsn) + 8) + v.refs.capacity() * sizeof(FlowRef) +
           v.code_pointers.capacity() * 8 + v.literals.capacity() * sizeof(Range) +
           v.data_refs.capacity() * sizeof(DataRef) + v.case_calls.capacity() * 16 + v.far_jumps.capacity() * 8;
  }
};

// ---- functions ----

enum FunctionFlags : std::uint16_t {
  kFunctionNoReturn = 1 << 0,  // never returns to its caller
  kFunctionThunk = 1 << 1,     // a thunk (see Thunk); its name follows the target
  kFunctionDiscovered = 1 << 2,  // found as a call or thunk target, not a seed
  kFunctionAssertedEntry = 1 << 3,  // a FUNCTION_BOUNDS assertion starts it
  kFunctionAssertedBody = 1 << 4,   // and gives its body
  kFunctionThumb = 1 << 5,          // Thumb code (ARM interworking)
  kFunctionSearched = 1 << 6,       // found by the firmware search (a start pattern)
  kFunctionTagged = 1 << 7,         // its Flow key is the entry with the low bit set (see flow_key)
};

enum class NoReturnReason : std::uint8_t {
  none,
  named,     // on the known list (exit, abort, __stack_chk_fail, ...)
  inferred,  // no path from its entry reaches a return
  user,      // the user said so (FactKind::NoReturn)
};

struct FunctionInfo {
  facts::Address entry;
  std::string name;
  facts::AddressSet body;  // the instructions reachable from the entry (see Functions)
  std::uint16_t flags = 0;  // FunctionFlags
  std::uint16_t seed = 0;   // SeedFlags of the entry, 0 if discovered
  NoReturnReason no_return = NoReturnReason::none;
  std::uint64_t thunk_target = 0;  // for thunks: the destination (import slot for imports)
  std::string import;              // for import thunks: the imported symbol
  // Where the language has instruction sets (ARM and Thumb): the code its
  // flow reaches outside its body (another function's, which it runs or
  // jumps into), decoded in its instruction set like the body. What reads
  // the function on from its entry (the decompiler) must read that so too.
  facts::AddressSet reach;

  // The key of its Flow (and Thunk): the entry, tagged with the low bit for
  // Thumb code the program's context doesn't paint Thumb (interworking).
  std::uint64_t flow_key() const { return entry.offset | ((flags & kFunctionTagged) ? 1 : 0); }

  void encode(facts::Encoder &e) const;
  static FunctionInfo decode(facts::Decoder &d);
  friend bool operator==(const FunctionInfo &, const FunctionInfo &) = default;
};

// An instruction some function's flow reaches, as the listing shows it.
struct CodeUnit {
  std::uint64_t address = 0;
  std::uint32_t length = 0;  // including delay-slot instructions
  std::uint32_t delay = 0;   // bytes of those
  bool thumb = false;        // decoded as Thumb (interworking; see ProgramInfo::thumb)

  friend bool operator==(const CodeUnit &, const CodeUnit &) = default;
};

struct FunctionList {
  std::vector<FunctionInfo> functions;  // sorted by entry
  // Every instruction in some function's walk (whether or not an asserted
  // body took it), sorted by address: the program's known code. Flow past
  // the fallthrough of a no-return call and alignment padding aren't in it.
  std::vector<CodeUnit> code;

  const FunctionInfo *find(std::uint64_t entry) const;
  void encode(facts::Encoder &e) const;
  static FunctionList decode(facts::Decoder &d);
  friend bool operator==(const FunctionList &, const FunctionList &) = default;
};

// The discovery fixpoint. Entries are the seeds plus, repeatedly, the call
// targets (and thunk destinations) in code reachable from known entries.
// No-return functions are the named ones plus those from whose entry no
// return is reachable once calls to no-return functions stop flow; this is
// the least such set, so recursion that may return counts as returning.
// A body is what Flow reaches from the entry, without crossing another
// entry or the fallthrough of a no-return call; trailing alignment padding
// is unreachable and so excluded. Code reachable from several functions
// goes to the closest entry at or before it, as Ghidra resolves overlaps.
// Asserted entries are seeds, asserted non-functions are neither seeds nor
// call targets, and asserted bodies win (see "Assertions" above).
struct Functions {
  static constexpr std::string_view name = "analysis.functions";
  static constexpr std::uint32_t version = 22;  // 6: removals match Thumb entries; 7: on raw images, unproven
                                               // candidates must be credible code (not text, fill, random bytes);
                                               // 8: reach; 9: of ARM functions too; 10: switch helpers,
                                               // names from labelled patterns; 11: prologues in gaps, code
                                               // that returns from a frame it didn't make is no function;
                                               // 12: shrink-wrapped prologues start at their early exit;
                                               // 13: search finds in literal pools are data; 14: far
                                               // jumps to far jumps; 15: embedded ARM vector tables;
                                               // 16: conditional tail calls; 17: pointer tables in
                                               // data, search finds inside instructions dropped;
                                               // 18: patches through patch.page; 19: the listing's edits;
                                               // 20: shrink-wrapped guards count no delay slots (MIPS); 21: the user's no-return marks
                                               // (FactKind::NoReturn); 22: fallthrough overrides
  using Key = ProgramKey;
  using Value = FunctionList;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::size_t weight(const Value &v);
  static std::string describe(const Key &k) { return k.id; }
};

// One function from Functions; Uncertain and empty (no name) if there is no
// function at the address.
struct Function {
  static constexpr std::string_view name = "analysis.function";
  static constexpr std::uint32_t version = 2;
  using Key = Location;
  using Value = FunctionInfo;
  static Value compute(facts::QueryContext &ctx, const Key &entry);
  static std::string describe(const Key &k) { return analysis::describe(k); }
};

void register_queries(facts::Engine &engine);

// ---- progress ----

// How far one program's discovery has got, for an import's progress report
// (rk-daemon's GetImportProgress). Flow and Functions write it as they run,
// relaxed atomics only, and anyone may read it at any time. It never
// changes what discovery computes: a memoized discovery reports nothing.
struct DiscoveryProgress {
  enum class Stage : std::uint8_t {
    none,
    flows,        // decoding from the seeds (the caller's own get_all)
    walking,      // the fixpoint: decoding entries, following calls
    search,       // firmware search: start patterns in code nothing reached
    search_code,  // firmware search: code nothing reached that makes calls
    bodies,       // assigning code to functions
  };
  std::atomic<Stage> stage{Stage::none};
  // Bytes of instructions the flows computed so far decoded (code two
  // flows reach counts twice), against ProgramInfo::code's size.
  std::atomic<std::uint64_t> decoded_bytes{0};
  // Flows computed that decoded something.
  std::atomic<std::uint64_t> flows{0};
  // Entries the fixpoint knows (set at each round).
  std::atomic<std::uint64_t> functions{0};
  std::atomic<std::uint32_t> rounds{0};
};

// Reports `program`'s discovery to `progress` while it lives (one watch per
// program at a time; a second replaces the first).
class WatchDiscovery {
 public:
  WatchDiscovery(ProgramKey program, std::shared_ptr<DiscoveryProgress> progress);
  ~WatchDiscovery();
  WatchDiscovery(const WatchDiscovery &) = delete;
  WatchDiscovery &operator=(const WatchDiscovery &) = delete;

 private:
  ProgramKey program_;
};

// The progress watching `program`'s discovery, or null.
std::shared_ptr<DiscoveryProgress> watched_discovery(const ProgramKey &program);

// Bytes of instructions in a flow (FlowInsn::length summed).
std::uint64_t decoded_bytes(const FlowGraph &g);

// ---- import ----

// ProgramInfo for a loaded image: code ranges and data in code, seeds
// (entry, function symbols, exports, unwind entries, init/fini code, PLT
// stubs), import slots, ARM context. `language` is
// "proc:endian:size:variant[:compiler]"; the language's spaces come from
// SLEIGH, so lift::initialize() must have been called. `space` is the code
// space's id in the fact store. `bytes` reads the image's bytes (default:
// its memory); the image backend passes the bytes as patched
// (bytes.effective, docs/patching.md) when it describes a patched program.
using ByteSource = std::function<std::size_t(std::uint64_t addr, std::span<std::byte> out)>;
ProgramInfo describe(const loader::Image &image, const std::string &language, facts::SpaceId space = 1,
                     const ByteSource &bytes = {});
// What describe() needs from SLEIGH about `language`, read now (it builds
// an engine, tens of milliseconds, once per language and process): for a
// loader to overlap with its own work. Throws what describe() would.
void prepare_language(const std::string &language);

// Stages the image's initialized bytes in `info.space`, with relative
// relocations applied as the dynamic linker (and Ghidra's importer) would,
// and `info` and describe_data(image) as the program's inputs
// (LoadedProgram, LoadedDataProgram), in the caller's transaction.
void stage_image(facts::FactDb::Transaction &tx, const ProgramKey &program, const loader::Image &image,
                 const ProgramInfo &info);
// The same in a transaction of its own; returns the revision it commits.
facts::Revision import_image(facts::FactDb &db, const ProgramKey &program, const loader::Image &image,
                             const ProgramInfo &info);

// Names Ghidra gives functions it has no symbol for: FUN_00101000, or
// FUN_ram_00101000 when `info.qualify_names`; in a word-addressed space
// the offset is in words (AVR's FUN_code_003a is byte 0x74).
std::string default_name(const ProgramInfo &info, std::uint64_t address);
// The same for any prefix and key, in whatever space the key is in:
// address_name(info, "DAT_", key) is "DAT_mem_0100" for AVR's SRAM.
std::string address_name(const ProgramInfo &info, std::string_view prefix, std::uint64_t key);

// Frees the SLEIGH engines queries keep between decodes (one per thread
// that decoded, about 35 MB each); later decodes build them again. With a
// pool, they are torn down in parallel on it (each takes about 10 ms, and
// an import holds a dozen or more).
void release_idle_decoders(facts::ThreadPool *pool = nullptr);
// Builds the engines a discovery on `pool` decodes with (one per thread
// and the caller's), in parallel on it, so that its first decodes don't
// wait for them: for a loader to overlap with its own work once it knows
// the language. They go with the next release_idle_decoders().
void prepare_decoders(const std::string &language, facts::ThreadPool &pool);
// Parks the idle decoders' SLEIGH engines (lift::Lifter::park; docs/memory.md
// "SLEIGH engines") once no decoder has been taken or returned for
// `idle_for`. How many parked.
std::size_t park_decoders(std::chrono::steady_clock::duration idle_for = {});

// Reads a program's code through a query context, so the bytes read become
// the query's dependencies, decoding with a SLEIGH engine leased from
// discovery's pool for the reader's lifetime: for clients that hash
// functions (src/diff). One thread at a time.
class CodeReader {
 public:
  CodeReader(facts::QueryContext &ctx, const ProgramInfo &info);
  ~CodeReader();
  CodeReader(const CodeReader &) = delete;
  CodeReader &operator=(const CodeReader &) = delete;

  // The instruction at a code address, with p-code and no display text;
  // `tagged`: Thumb code at a tagged flow key (FunctionInfo::flow_key).
  std::optional<lift::Instruction> decode(std::uint64_t address, bool tagged = false);
  // Up to n bytes at an address, stopping at unmapped memory. Valid until
  // the next call.
  std::span<const std::byte> bytes(std::uint64_t address, std::size_t n);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Imported or local functions known never to return, by name. Leading
// underscores are ignored, as Ghidra ignores them (_exit, __exit). A
// Mach-O's list (`macho`) adds MachOFunctionsThatDoNotReturn's names
// (objc_exception_throw, Swift's fatal errors, __clang_call_terminate).
bool is_known_no_return(std::string_view name, bool macho = false);

}  // namespace revkit::analysis
