// Shared by the analysis queries: reading bytes through a query context,
// decoding them with a pooled SLEIGH engine, and reading control flow and
// values out of raw p-code.
#pragma once

#include "revkit/analysis/analysis.h"
#include "revkit/analysis/units.h"
#include "revkit/analysis/user_refs.h"
#include "revkit/facts/fact_db.h"
#include "revkit/lift/lifter.hh"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace revkit::analysis::detail {

// The progress watching `program`'s discovery (WatchDiscovery), or null:
// for Flow::compute, once per flow. Lock-free unless the watches changed
// since this thread last asked (each thread caches its answer).
DiscoveryProgress *discovery_progress(const ProgramKey &program);

// Program bytes read through a query, so each page becomes a dependency.
// A page is fetched from the engine once per reader.
// Memory the user added to the map (ProgramInfo::sources) is laid over the
// program's pages: zeros, or a file's bytes from the space they are staged in.
class ByteReader {
 public:
  ByteReader(facts::QueryContext &ctx, const ProgramInfo &info)
      : ctx_(ctx), space_(info.space), sources_(info.sources) {}
  ByteReader(const ByteReader &) = delete;  // last_ points into pages_
  ByteReader &operator=(const ByteReader &) = delete;

  // Up to `n` bytes at `addr`, stopping at unmapped memory or the top of
  // the space, as patched. Valid until the next call. Reads depend on the
  // loader's pages and their patch.page gates and, where a gate says a
  // patch may be near, on the patches of the 256-byte spans read, not of
  // the whole page: a patch re-runs the flows that decode near it only
  // (the first one near a page, that page's).
  std::span<const std::byte> read(std::uint64_t addr, std::size_t n);
  // An unsigned integer of `size` bytes (1..8) at `addr`, if mapped.
  std::optional<std::uint64_t> uint(std::uint64_t addr, unsigned size, bool big_endian);

 private:
  struct Page {
    facts::Ref<std::string> bytes;
    const std::string *data = nullptr;  // `bytes`, or with sources laid over them (composed_)
    bool patched = false;  // patch.page: a patch may overlap it (mapped pages only)
  };
  const Page &page(std::uint64_t index);
  const facts::PatchSpan::Value &span(std::uint64_t index);

  facts::QueryContext &ctx_;
  facts::SpaceId space_;
  std::vector<ProgramInfo::SourceRange> sources_;
  std::map<std::uint64_t, Page> pages_;
  // The page read last (most reads are near the one before).
  std::uint64_t last_index_ = 0;
  const Page *last_ = nullptr;
  std::map<std::uint64_t, facts::Ref<facts::PatchSpan::Value>> spans_;
  std::map<std::uint64_t, std::string> composed_;  // pages with sources laid over them
  std::vector<std::byte> buf_;
};

// Drops the pool's idle engines (release_idle_decoders()), destroying
// them on `threads` when given.
void pool_clear(facts::ThreadPool *threads = nullptr);
// Parks the idle engines once the pool has been unused for `idle_for` (park_decoders()).
std::size_t pool_park(std::chrono::steady_clock::duration idle_for);
// Builds `n` engines for `language` (without its compiler) on `threads`
// (prepare_decoders()).
void pool_prepare(const std::string &language, unsigned n, facts::ThreadPool &threads);

// A SLEIGH engine for the program's language and context, leased from a
// process-wide pool for the lifetime of this object. Decodes only bytes it
// is handed (Lifter::lift with a span), so results depend on nothing but
// the inputs. lift::initialize() must have been called.
//
// A Decoder made while another for the same engine is alive on the same
// thread (a query a flow asks while it decodes: analysis.jump_stub, a
// thunk) shares that one's engine instead of building another (tens of
// milliseconds, ~35 MB): the outer one is suspended until the inner one is
// gone. So Decoders must be scoped (destroyed on their thread, innermost
// first), as locals and the members of locals are.
class Decoder {
 public:
  explicit Decoder(const ProgramInfo &info);
  ~Decoder();
  Decoder(const Decoder &) = delete;
  Decoder &operator=(const Decoder &) = delete;

  // The instruction at `addr`, which must be code (ProgramInfo::is_code).
  // Bytes past the end of its code range are not offered to SLEIGH, so an
  // instruction can't straddle into non-code.
  // With `thumb` (interworking only), as Thumb code wherever it is.
  std::optional<lift::Instruction> decode(std::uint64_t addr, ByteReader &bytes, bool thumb = false);

  // Whether a tagged key decodes differently from a plain one: the
  // language has two instruction sets and its default isn't Thumb (on
  // Cortex-M everything is Thumb, tagged or not).
  bool two_instruction_sets();

  // How far apart instructions can start, in bytes: the language's
  // instruction alignment (SLEIGH's `alignment`; 2 on AVR, whose code
  // space counts words). 1 on byte-coded processors (6502, Z80, 8051,
  // x86, Xtensa).
  std::uint64_t step();

 private:
  const ProgramInfo &info_;
  std::string key_;
  std::unique_ptr<lift::Lifter> owned_;  // leased from the pool, or null when shared
  lift::Lifter *lifter_ = nullptr;       // owned_, or an outer Decoder's
  std::unique_ptr<lift::Lifter> thumb_;  // leased on first Thumb decode
};

// The stack pointer of the program's language and compiler (the compiler
// spec's <stackpointer>), found once per language; nullopt if the specs
// don't name one. lift::initialize() must have been called.
std::optional<RegisterSlot> stack_register(const ProgramInfo &info);

// Fill, not code: the instruction of `length` bytes at `a` starts a run of
// more than kMaxRepeatedByteInstructions instructions that are all one
// repeated byte (zeroed or erased memory, padding). Ghidra's disassembler
// stops such a run too (its "maximum run of repeated byte instructions",
// also 16), after disassembling the first 16; here none of it is code.
constexpr unsigned kMaxRepeatedByteInstructions = 16;
bool starts_fill(std::uint64_t a, std::uint32_t length, ByteReader &bytes);

// An instruction's references (FlowGraph::refs), appended to `out`.
void references(const lift::Instruction &insn, const ProgramInfo &info, std::uint32_t index, bool delay_slot,
                std::vector<FlowRef> &out);

// Control flow of one instruction, from its p-code.
struct InsnFlow {
  FlowKind kind = FlowKind::fall;
  bool falls_through = true;
  std::vector<std::uint64_t> targets;  // direct targets in the code space
  bool tail_call = false;  // a call that returns from the caller too
};
InsnFlow classify(const lift::Instruction &insn, const std::string &code_space);

// Rewrites varnodes in the program's other memory spaces (AVR's "mem",
// the 8051's INTMEM, aliases like AVR's "codebyte") as code-space
// varnodes at their keys (ProgramInfo::spaces), so everything that reads
// memory operands sees one keyed space. Decoder::decode applies it.
void key_spaces(lift::Instruction &insn, const ProgramInfo &info);

// A value in the evaluator: unknown, a constant, (when memory isn't read)
// the contents of a constant address, or a register's unknown incoming
// value plus a constant, which is enough to follow stack spills.
struct Sym {
  enum class Kind : std::uint8_t { unknown, constant, loaded, relative };
  Kind kind = Kind::unknown;
  std::uint64_t value = 0;  // constant: the value; loaded: the address read; relative: the offset
  std::uint32_t base = 0;   // relative: which incoming value

  static Sym constant(std::uint64_t v) { return {Kind::constant, v, 0}; }
  static Sym loaded(std::uint64_t addr) { return {Kind::loaded, addr, 0}; }
  static Sym relative(std::uint32_t base, std::uint64_t offset) { return {Kind::relative, offset, base}; }
  bool known() const { return kind == Kind::constant; }
};

// A small map kept as a sorted vector: what the evaluator holds is a few
// dozen entries, and jump-table probing copies an evaluator per probe, which
// for a node-based map is an allocation per entry.
template <class K, class V>
class FlatMap {
 public:
  using value_type = std::pair<K, V>;
  using iterator = typename std::vector<value_type>::iterator;
  using const_iterator = typename std::vector<value_type>::const_iterator;

  iterator begin() { return v_.begin(); }
  iterator end() { return v_.end(); }
  const_iterator begin() const { return v_.begin(); }
  const_iterator end() const { return v_.end(); }
  iterator lower_bound(const K &k) {
    return std::lower_bound(v_.begin(), v_.end(), k, [](const value_type &e, const K &x) { return e.first < x; });
  }
  const_iterator lower_bound(const K &k) const {
    return std::lower_bound(v_.begin(), v_.end(), k, [](const value_type &e, const K &x) { return e.first < x; });
  }
  iterator upper_bound(const K &k) {
    return std::upper_bound(v_.begin(), v_.end(), k, [](const K &x, const value_type &e) { return x < e.first; });
  }
  iterator find(const K &k) {
    auto it = lower_bound(k);
    return it != v_.end() && it->first == k ? it : v_.end();
  }
  const_iterator find(const K &k) const {
    auto it = lower_bound(k);
    return it != v_.end() && it->first == k ? it : v_.end();
  }
  std::pair<iterator, bool> emplace(const K &k, V value) {
    auto it = lower_bound(k);
    if (it != v_.end() && it->first == k) return {it, false};
    return {v_.insert(it, value_type(k, std::move(value))), true};
  }
  V &operator[](const K &k) { return emplace(k, V{}).first->second; }
  iterator erase(iterator it) { return v_.erase(it); }
  void clear() { v_.clear(); }

 private:
  std::vector<value_type> v_;
};

// Interprets the raw p-code of straight-line instructions over registers,
// temporaries and the memory it stores to. With a ByteReader, loads from
// constant addresses not stored to read the program's bytes; without one
// they become Sym::loaded, which is how thunks find the slot they jump
// through.
class Evaluator {
 public:
  Evaluator(const ProgramInfo &info, ByteReader *memory) : info_(&info), memory_(memory) {}

  // Runs one instruction. Returns false if it does something a thunk may
  // not (store, call, user-defined op); values stay usable either way.
  bool step(const lift::Instruction &insn);

  // After step(): where the instruction's BRANCHIND, CALLIND or RETURN
  // goes, and the condition of its CBRANCH into the code space (1 = taken).
  const std::optional<Sym> &indirect_target() const { return indirect_; }
  const std::optional<Sym> &branch_condition() const { return condition_; }

  // Registers (offset, size) read before this evaluator wrote them.
  const std::vector<std::pair<std::uint64_t, std::uint32_t>> &free_registers() const { return free_; }
  // Every register read, written or not.
  const std::vector<std::pair<std::uint64_t, std::uint32_t>> &reads() const { return reads_; }
  // Memory read before this evaluator stored to it, addressed by an
  // incoming register plus a displacement (a local spilled to the stack).
  struct FreeMemory {
    std::uint64_t reg;
    std::uint64_t disp;
    std::uint32_t size;
  };
  const std::vector<FreeMemory> &free_memory() const { return free_memory_; }
  // A copy with the same state but none of the history (free registers,
  // reads, free memory), for a probe that only steps and asks where the
  // jump goes: much cheaper to make.
  Evaluator fork() const;
  // Gives a register a value, as a probe; without one, makes it unknown
  // (what the code after it computes whatever the register holds).
  void set_register(std::uint64_t offset, std::uint32_t size, std::optional<std::uint64_t> value);
  // Stores a value (or an unknown one) at register + displacement, as a
  // probe. False if the register's value isn't a known or relative address.
  bool set_memory(const FreeMemory &slot, std::optional<std::uint64_t> value);
  // Whether the register currently holds a known constant.
  bool register_known(std::uint64_t offset, std::uint32_t size) const;
  // The register `s` is the unchanged incoming value of, if it is one.
  std::optional<std::uint64_t> incoming_register(const Sym &s) const;
  // The register's value, if it is a known constant.
  std::optional<std::uint64_t> register_value(std::uint64_t offset, std::uint32_t size) const;
  // Memory reads go only to code (literal pools), not import slots; other
  // loads stay unknown, as without memory.
  void restrict_loads_to_code() { code_only_ = true; }
  // Past a call, memory stored to and the link register are unknown (the
  // callee's), not what this code stored or set before it.
  void forget_at_calls() { calls_clobber_ = true; }
  // Stores through an unknown pointer leave what is known at constant and
  // register-relative addresses (saved registers on the stack) alone.
  void keep_slots() { keep_slots_ = true; }
  // After step(): whether every op ran with its internal branches decided
  // (a conditional instruction whose condition is known), so a BRANCHIND
  // or CALLIND that didn't set indirect_target() was skipped.
  bool decided() const { return completed_; }
  // Constant addresses memory was read from, with sizes, in order.
  const std::vector<std::pair<std::uint64_t, std::uint32_t>> &loads() const { return loads_; }
  // Whether some slot addressed through an incoming register (the stack)
  // holds the register's value as it came in: a prologue saved it.
  bool saved(std::uint64_t reg) const;
  // How far above where `stack` (a register that still points into the
  // frame it came in with) now points the slot holding `reg`'s incoming
  // value lies: after a prologue, from the stack pointer up to the saved
  // return address.
  std::optional<std::int64_t> saved_above(std::uint64_t reg, std::uint64_t stack) const;
  // How far a register has moved from the value it came in with (the
  // stack pointer after pushes: -8); nullopt if it no longer holds that
  // value plus a constant.
  std::optional<std::int64_t> moved(std::uint64_t reg) const;

 private:
  struct Slot {
    std::uint32_t size;
    Sym value;
  };
  Sym read(const lift::Varnode &v);
  void write(const lift::Varnode &v, Sym s);
  Sym load(std::uint64_t addr, std::uint32_t size);
  Sym apply(const lift::PcodeOp &op);
  void clobber_at_call();
  void store(const Sym &addr, std::uint32_t size, Sym value);

  const ProgramInfo *info_;
  ByteReader *memory_;
  // (space is register or unique, offset) -> what was last written there.
  FlatMap<std::pair<bool, std::uint64_t>, Slot> state_;
  std::vector<std::pair<std::uint64_t, std::uint32_t>> free_;
  std::vector<std::pair<std::uint64_t, std::uint32_t>> reads_;
  std::optional<Sym> indirect_;
  std::optional<Sym> condition_;
  // Stores to known addresses: (base, offset) -> (size, value); base 0 is
  // a constant address, else a relative one's incoming value.
  FlatMap<std::pair<std::uint32_t, std::uint64_t>, Slot> memory_writes_;
  std::uint32_t next_base_ = 1;
  FlatMap<std::uint32_t, std::uint64_t> incoming_;  // relative base -> register offset
  std::vector<FreeMemory> free_memory_;
  bool code_only_ = false;
  bool calls_clobber_ = false;
  bool keep_slots_ = false;
  bool completed_ = false;
  std::vector<std::pair<std::uint64_t, std::uint32_t>> loads_;
};

// The jump-only part of analysis.thunk: an import stub or a jump to code.
// Separate so that thunks found through calls (Thunk) can ask about their
// callee without thunks ever depending on each other in a cycle.
struct JumpStub {
  static constexpr std::string_view name = "analysis.stub";
  static constexpr std::uint32_t version = 5;  // 4: patches through patch.page; 5: fallthrough overrides
  using Key = Location;
  using Value = ThunkInfo;
  static Value compute(facts::QueryContext &ctx, const Key &addr);
  static std::string describe(const Key &k) { return analysis::describe(k); }
};

// A switch helper: code that is called, and instead of returning goes to a
// place it reads from a table at its return address, indexed by a
// register (gcc's __gnu_thumb1_case_uqi and its kin for Thumb-1, ARM's
// switch8 helpers). Here, by its shape alone: the number of straight-line
// instructions from the key that end in a computed jump to something made
// from the link register it was called with (not that register as it came
// in, which is a return), or 0. A call site then proves it by recovering
// the table through the helper's code (Flow). Only where the program has a
// link register (ProgramInfo::link_register).
struct CaseHelper {
  static constexpr std::string_view name = "analysis.case_helper";
  static constexpr std::uint32_t version = 2;  // 2: patches through patch.page
  using Key = Location;
  using Value = std::uint32_t;
  static Value compute(facts::QueryContext &ctx, const Key &addr);
  static std::string describe(const Key &k) { return analysis::describe(k); }
};

// Whether the code at `key` returns from a stack frame it didn't make:
// the first path from it to a return (fallthrough at conditional branches,
// through direct jumps and past calls) returns to an address it takes off
// the stack as it found it. Such code is the rest of a function whose
// start pushed that address, not a function: a pointer, jump or call into
// the middle of one. The result is how far above the stack pointer it
// came in with that address lies; nullopt when it makes its own frame or
// the path can't be followed (also past a call `stops` names: one known
// not to return). Only where calls leave the return address in a register
// (ProgramInfo::link_register).
// A call on the way to code that returns from the frame the callee came
// in with (a far jump: see FrameFragment) counts as a jump there: such
// calls are followed three deep, past the first only for a short tail (an
// epilogue, a default case: 24 instructions).
std::optional<std::int64_t> pops_callers_frame(facts::QueryContext &ctx, const ProgramKey &program,
                                               const ProgramInfo &info, std::uint64_t key, ByteReader &bytes,
                                               Decoder &decoder,
                                               const std::function<bool(std::uint64_t)> &stops = {},
                                               int depth = 0);

// pops_callers_frame as a query (-1: it doesn't), for Flow: gcc's Thumb-1
// far jump is a `bl` to a place in the same function (a branch reaches
// only 2 KiB). A call from a function to code after its entry that returns
// from exactly the frame the function's prologue made is such a jump.
struct FrameFragment {
  static constexpr std::string_view name = "analysis.frame_fragment";
  static constexpr std::uint32_t version = 3;  // 2: through far jumps; 3: patches through patch.page
  using Key = Location;
  using Value = std::int64_t;
  static Value compute(facts::QueryContext &ctx, const Key &addr);
  static std::string describe(const Key &k) { return analysis::describe(k); }
};

// How far above the stack pointer the return address lies once the code at
// `key` has made its frame: after its leading straight-line instructions
// (push {r4, lr}; sub sp, #8), if they save the link register. nullopt
// otherwise, and where the program has no link register.
std::optional<std::int64_t> prologue_frame(const ProgramInfo &info, std::uint64_t key, ByteReader &bytes,
                                           Decoder &decoder);

// Whether a call to `target` never returns, by name: a symbol, or an
// import reached through jump stubs, on the known list.
bool named_no_return(facts::QueryContext &ctx, const ProgramKey &program, const ProgramInfo &info,
                     std::uint64_t target);

// The asserted FUNCTION_BOUNDS, FLOW_OVERRIDE and FALLTHROUGH values at one address in
// the program's code space, read through the key index's spans so a query
// depends on the assertions near what it looked at.
class Assertions {
 public:
  Assertions(facts::QueryContext &ctx, facts::SpaceId space) : ctx_(ctx), space_(space) {}

  // FUNCTION_BOUNDS at `a`: absent, an AddressSet, or kNotAFunction.
  facts::FactValue bounds(std::uint64_t a) { return value(facts::FactKind::FunctionBounds, a); }
  FlowOverride flow_override(std::uint64_t a);
  // FALLTHROUGH at `a`: the user's fallthrough override, if any.
  std::optional<FallthroughOverride> fallthrough(std::uint64_t a);
  // The live REFERENCE keys at `a` (user references, user_refs.h).
  std::vector<UserRef> references(std::uint64_t a);

 private:
  facts::FactValue value(facts::FactKind kind, std::uint64_t a);

  facts::QueryContext &ctx_;
  facts::SpaceId space_;
  std::map<std::pair<facts::FactKind, std::uint64_t>, facts::Ref<facts::AssertedSpan::Value>> spans_;
  std::pair<facts::FactKind, std::uint64_t> last_key_{};
  facts::Ref<facts::AssertedSpan::Value> *last_ = nullptr;  // spans_[last_key_]
};

// Applies a flow override to one instruction's flow, as Ghidra's
// FlowOverride.getModifiedFlowType changes its flow type.
void apply_override(FlowInsn &insn, FlowOverride o);

// Jump-table recovery (jump_tables.cc). `path` holds the instructions that
// lead to the computed jump, oldest first, the jump last. Returns the
// table's destinations, or nothing if the pattern isn't recognised.
// With `table`, the code addresses the table's entries were read from are
// added to it (data inside code: an inline ARM table).
std::vector<std::uint64_t> recover_jump_table(const std::vector<const lift::Instruction *> &path,
                                              const ProgramInfo &info, ByteReader &bytes,
                                              std::vector<Range> *table = nullptr);

// A computed jump or call (the last of `path`) whose destination the path
// fixes: values loaded from code (literal pools) and computed from the
// program counter, as Ghidra's constant propagation finds them.
struct Computed {
  std::optional<std::uint64_t> target;  // the destination, if known
  std::optional<bool> thumb;            // its instruction set, if the instruction sets it (interworking)
  bool links = false;                   // the link register holds the return address: a call
  bool returns = false;                 // it jumps to the incoming link register: a return
};
Computed resolve_computed(const std::vector<const lift::Instruction *> &path, const ProgramInfo &info,
                          ByteReader &bytes);

// Sorted, disjoint inclusive ranges.
class Ranges {
 public:
  Ranges() = default;
  explicit Ranges(std::vector<Range> v) {
    std::sort(v.begin(), v.end());
    for (const Range &r : v) {
      if (!r_.empty() && (r_.back().last == ~std::uint64_t{0} || r.first <= r_.back().last + 1))
        r_.back().last = std::max(r_.back().last, r.last);
      else
        r_.push_back(r);
    }
  }
  const Range *find(std::uint64_t a) const {
    auto it = std::upper_bound(r_.begin(), r_.end(), a, [](std::uint64_t x, const Range &r) { return x < r.first; });
    if (it == r_.begin()) return nullptr;
    --it;
    return it->contains(a) ? &*it : nullptr;
  }
  bool contains(std::uint64_t a) const { return find(a) != nullptr; }
  // The first address at or after `a` that some range covers, if any.
  std::optional<std::uint64_t> next(std::uint64_t a) const {
    if (find(a)) return a;
    auto it = std::upper_bound(r_.begin(), r_.end(), a, [](std::uint64_t x, const Range &r) { return x < r.first; });
    if (it == r_.end()) return std::nullopt;
    return it->first;
  }
  bool intersects(std::uint64_t first, std::uint64_t last) const {
    auto it = std::upper_bound(r_.begin(), r_.end(), last, [](std::uint64_t x, const Range &r) { return x < r.first; });
    return it != r_.begin() && std::prev(it)->last >= first;
  }
  const std::vector<Range> &ranges() const { return r_; }

 private:
  std::vector<Range> r_;
};

// What the firmware search knows: the instructions walks reached, data
// inside code (literal pools, inline tables) and the code pointers flows
// loaded (keys).
struct SearchInput {
  struct Insn {
    std::uint64_t address;
    std::uint32_t length;
    bool thumb;  // decoded as Thumb (ARM interworking)
  };
  std::vector<Insn> code;  // sorted by address, one per address
  std::vector<Range> data;
  std::vector<std::uint64_t> pointers;
};

// The same, indexed: what a candidate is checked against.
struct Known {
  explicit Known(const SearchInput &in);
  Ranges code;  // every known instruction's bytes
  Ranges data;
  // The known instruction at `a`, or the one whose bytes cover it.
  const SearchInput::Insn *at(std::uint64_t a) const;
  const SearchInput::Insn *covering(std::uint64_t a) const;
  // The instruction set of the nearest known code before `a`, if any.
  std::optional<bool> thumb_before(std::uint64_t a) const;

 private:
  const std::vector<SearchInput::Insn> *insns_;
};

// Bytes that aren't code, whatever they decode to (plausible.cc).
//
// Text: how many of the bytes [first, last] lie in C strings (four or more
// printable characters up to a NUL, the NUL too), and the longest run of
// such bytes there.
struct TextBytes {
  std::size_t total = 0;
  std::size_t longest = 0;
};
TextBytes text_bytes(ByteReader &bytes, std::uint64_t first, std::uint64_t last);
// A run of text this long inside what decodes as code means it is text:
// machine code has such runs by chance up to a dozen bytes or so, about
// three dozen where opcodes are letters (68000, SuperH).
constexpr std::size_t kTextRun = 64;
// Whether the code that would start at `a` is text: its first bytes all
// are, and most of the 32 from there. (A short function before a string
// table has text close behind it.)
bool starts_in_text(ByteReader &bytes, std::uint64_t a);
// Whether the 256 bytes from `a` are as random as compressed or encrypted
// data (their byte entropy is above anything machine code has).
bool high_entropy(ByteReader &bytes, std::uint64_t a);
// An instruction of zero bytes that does something (ARM's andeq r0, r0, r0,
// Thumb's movs r0, r0, x86's add [rax], al): compilers don't emit it, and
// zeroed words in data decode to it. (MIPS's nop is all zeros and does
// nothing.)
bool zero_instruction(const lift::Instruction &insn, ByteReader &bytes);

// Whether `start` is a valid subroutine: Ghidra's
// PseudoDisassembler.checkValidSubroutine, as its Reference analyzer
// (OperandReferenceAnalyzer) runs it on a constant an instruction loads
// that points into code, before making a function there (without
// existing code: allowExistingInstructions false). From
// `start` every flow decodes (no undecodable or unimplemented
// instruction, no run of more than four identical instructions, no
// jump to the next instruction or into one, no running into code
// already known), and some path reaches a return or a computed jump,
// or jumps to known code (a tail call); more than one instruction.
// `flow`, if given, gets its instructions (address -> length, delay slots
// included) when it is one.
bool valid_subroutine(const ProgramInfo &info, const Known &known, std::uint64_t start, bool thumb, ByteReader &bytes,
                      Decoder &decoder, std::map<std::uint64_t, std::uint32_t> *flow = nullptr);

// Code (not functions) in what nothing reached, as Ghidra's ARM Aggressive
// Instruction Finder finds it: where a gap starts, instructions that decode
// as a plausible subroutine and add something known (a call to a known
// function or to new code). Keys of where it starts (search.cc).
// The instruction set tried first is that of the code before the gap, as
// the AIF takes it; the other one needs a call to a known function.
// Where a gap's start gives nothing (data nothing known loads, a function
// that calls nothing), the first place further into it where code begins
// by saving the return address and calls or jumps to a known function.
// `fallback`: discovery found nothing to start from (find_called), and
// the rules for 8- and 16-bit code apply too: on a byte-coded processor
// every byte is a possible start and pieces of one instruction are
// allowed (a lone rts a branch reaches); on an 8- or 16-bit one a first
// instruction that stores a byte register is not filler, a call to where
// no code is adds nothing, and running into a known function's entry
// (a table before it, decoded) is not plausible. Without it, the rules
// are the ARM AIF's alone, as before.
std::set<std::uint64_t> find_code(const ProgramInfo &info, const SearchInput &in, const std::set<std::uint64_t> &functions,
                                  ByteReader &bytes, Decoder &decoder, bool fallback = false);

// Routines that code nothing reached calls from more than one place, for
// an image where discovery found nothing at all (no vectors, entry,
// symbols or start patterns, and nothing the other searches find: a 6502
// or Z80 blob). Every place an instruction can start in
// what isn't known code or data is decoded; a target is kept where two or
// more calls to it, not overlapping and not in one repeated pattern (a
// table of records), each sit in code (not text, fill or random bytes,
// and their flow on from the call decodes as a valid subroutine's does),
// and the target is a valid subroutine itself (valid_subroutine) and not
// text, fill or random bytes. Of two that disagree (one starts inside an
// instruction of the other) the one called more often stays. Processors
// with one instruction set; keys of the targets.
std::set<std::uint64_t> find_called(const ProgramInfo &info, const SearchInput &in, ByteReader &bytes,
                                    Decoder &decoder);

// A shrink-wrapped prologue: a function that starts with an early exit
// (cbz r0, out; cmpwi r3, 0; beqlr) and saves registers only after it,
// where a start pattern or the code finder sees a prologue. Whether the
// instructions from `from` fall through to `prologue`, at most
// kGuardBytes of them before it (delay slots not counted: MIPS's early
// exits are a branch and its slot each, so several of them reach further
// into a function; at most kGuardSpan bytes in all), one of them a
// conditional branch or return forward past it and none a call or an
// unconditional transfer: then the function starts at `from`.
constexpr std::uint64_t kGuardBytes = 16;
constexpr std::uint64_t kGuardSpan = 32;
bool guards_prologue(const ProgramInfo &info, std::uint64_t from, std::uint64_t prologue, bool thumb, ByteReader &bytes,
                     Decoder &decoder);

// Whether the code at `key` begins by saving the return address (the link
// register) to the stack, in its first two instructions: a function's
// prologue (push {r4, lr}; one instruction may come before it). False
// where the program has no link register.
bool saves_return_address(const ProgramInfo &info, std::uint64_t key, ByteReader &bytes, Decoder &decoder);

// Function starts (keys) in code nothing reached (search.cc): by the
// program's start patterns, or (`pointers`) where constants that code
// loads point. Each with whether only "possible" patterns
// (possiblefuncstart) or a pointer found it.
std::map<std::uint64_t, bool> search_starts(const ProgramInfo &info, const SearchInput &in, ByteReader &bytes,
                                            Decoder &decoder, bool pointers);

}  // namespace revkit::analysis::detail
