// Inter-procedural prototype and type inference (revkit::infer).
//
// Every function's prototype (parameters, their types, the return type,
// varargs) is inferred from what Ghidra's decompiler concludes about it
// (decompiler.h: storage the .cspec prototype model counts as parameters
// and return values, typed by the decompiler's own propagation), and then
// improved across the call graph, to a fixpoint:
//
//   callee -> caller  the functions a function calls are decompiled with
//                     their current prototypes locked, so argument counts
//                     and parameter types (a library's `char *`, an inferred
//                     `int`) flow into the caller's variables and from there
//                     into the caller's own parameters and return value;
//   caller -> callee  what call sites pass (storage and the types the
//                     caller's variables have) and whether they read the
//                     return value refine the callee's parameters and
//                     return type.
//
// Imports are matched by name against a signature database generated from
// system headers (sigdb.h). Types live in a lattice (vtype.h) joined
// monotonically; a function whose prototype keeps changing is widened, and
// rounds are capped, so the iteration always terminates.
//
// Everything is a fact-engine query keyed by program (analysis::ProgramKey)
// or by (Location, round). Rounds are explicit in the keys: round k of a
// function reads round k-1 of its neighbours, so there are no query cycles
// and the result is the same whatever the thread schedule (facts.md notes
// that recovering from a cycle through the engine's hook depends on which
// thread detects it). `infer.fixpoint` iterates rounds until nothing
// changes; `run()` computes the same rounds in parallel first.
#pragma once

#include "revkit/analysis/analysis.h"
#include "revkit/facts/engine.h"
#include "revkit/facts/fact_db.h"
#include "revkit/infer/decompiler.h"
#include "revkit/infer/vtype.h"
#include "revkit/loader/image.hh"

#include <cstdint>
#include <functional>
#include <stdexcept>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::infer {

using analysis::Location;
using analysis::ProgramKey;

struct Options {
  std::uint32_t max_rounds = 16;    // rounds after the local one (round 0)
  std::uint32_t change_budget = 3;  // changes to one prototype before it is widened
  bool interprocedural = true;      // false: round 0 only, the decompiler's own guesses
  bool library = true;              // use the signature database for imports
  bool defaults = true;             // spell undefinedN as the commonest C type of its size
  // With defaults, an unknown return keeps its register's width (the
  // commonest return of exactly that size) rather than the commonest that
  // fits (int in RAX): what a decompiler is told, so callers reading the
  // whole register don't see a truncated value (CONCAT44(extraout_var, x)).
  bool keep_return_width = false;
  // Structures for the classes of pointer parameters a value passes
  // through unchanged, composed from their accesses (InferredStructure):
  // the parameters point to them instead of to their first word.
  bool structures = true;
  // How the decompiler types a loaded value, as the final C's decompiler
  // is set (rk-lift's --source-shape; the daemon's are revkit's defaults;
  // off, Ghidra's use-based types, for rk-infer and its gate): else a
  // value loaded with ldrh and typed from its uses locks `short *` where
  // that C says `ushort *`. With `all`, defaults don't spell a byte
  // pointee `char` over its loads (finalize).
  lift::SourceShape::Extension load_extension = lift::SourceShape::Extension::off;
  // Functions whose decompilation grows past this many varnodes (about
  // 1 KB each) aren't observed, only seen from their callers: the corpus's
  // largest has 29K; cmake has a handful of 100K-500K that each took 15 to
  // 70 s and were decompiled again in most rounds. 0: unbounded.
  std::uint32_t max_varnodes = 100000;
  // A decompilation past this many seconds fails (its worker is killed
  // past the hard deadline, decompd); the function is then only seen from
  // its callers. Not part of the encoding: it bounds the run, as a machine
  // does. 0: none.
  double timeout_seconds = 30;

  friend bool operator==(const Options &, const Options &) = default;
  void encode(facts::Encoder &e) const;
  static Options decode(facts::Decoder &d);
};

// What the decompiler reads besides the fact store's bytes: the loaded
// image. Only `identity`, `language_id` and `options` are encoded, so the
// fingerprint covers the file (by hash) rather than the in-memory image,
// as the backend's program source does.
struct ImageRef {
  std::string identity;     // e.g. the file's sha256
  std::string language_id;  // with compiler: "x86:LE:64:default:gcc"
  Options options;
  std::shared_ptr<const loader::Image> image;
  std::shared_ptr<DecompilerPool> pool;

  void encode(facts::Encoder &e) const;
  static ImageRef decode(facts::Decoder &d);
};

// Input: per program, set by stage_image().
struct ImageInput {
  static constexpr std::string_view name = "infer.image";
  using Key = ProgramKey;
  using Value = ImageRef;
};

// The image as the memory map lays it out (analysis.memory,
// docs/memory-map.md): ImageInput unchanged for a program without
// memory-map edits (the same value, so nothing that read it recomputes);
// otherwise the image with the map laid over it
// (analysis::image_with_memory: added regions with their bytes, blocks'
// permissions) and a decompiler pool over it, its identity naming the map.
// Every inference rule reads the image through this.
struct EffectiveImage {
  static constexpr std::string_view name = "infer.image.effective";
  static constexpr std::uint32_t version = 1;
  // Its value holds the image and a decompiler pool: computed in each
  // process, never read back from a project's storage (where it would
  // come back without them, and inference would fail after a reopen).
  static constexpr bool persistent = false;
  using Key = ProgramKey;
  using Value = ImageRef;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

// The call graph over discovery's functions.
struct CallNode {
  std::uint64_t entry = 0;
  std::string name;
  std::string import;  // the imported function an import stub jumps to
  std::uint64_t thunk_target = 0;  // a thunk's internal target
  bool no_return = false;
  bool from_data = false;  // not discovered: found in a table of function pointers
  // Unconditional jumps in its body to another function's entry, which the
  // decompiler takes as tail calls (Ghidra's CALL_RETURN overrides from
  // SharedReturnAnalysisCmd, as inputs::assemble_function gives them).
  std::vector<std::uint64_t> call_returns;
  std::vector<std::uint64_t> callees;  // direct calls and tail calls, sorted, unique
  std::vector<std::uint64_t> callers;  // sorted, unique

  void encode(facts::Encoder &e) const;
  static CallNode decode(facts::Decoder &d);
};

struct CallGraph {
  std::vector<CallNode> nodes;  // by entry
  std::vector<std::pair<std::uint64_t, std::string>> slots;  // import slots (IAT, GOT), by address
  // ARM interworking (analysis::ProgramInfo::isa_context): a code pointer
  // with the low bit set is Thumb code at the address without it.
  bool interworking = false;

  // The node at `entry`; with interworking, also at a Thumb pointer's
  // address (a function pointer passed, returned or in a table).
  const CallNode *find(std::uint64_t entry) const;
  const std::string *slot(std::uint64_t address) const;
  void encode(facts::Encoder &e) const;
  static CallGraph decode(facts::Decoder &d);
};

struct CallGraphQuery {
  static constexpr std::string_view name = "infer.callgraph";
  // 2: no-return evidence (analysis.no_return_evidence); 3: jumps to
  // other functions' entries are tail calls (CallNode::call_returns); 4:
  // Thumb code pointers (CallGraph::interworking)
  static constexpr std::uint32_t version = 4;
  using Key = ProgramKey;
  using Value = CallGraph;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

// The order rounds work in: the call graph's strongly connected
// components, with the members of each function-pointer table family
// joined into one, ranked callees first. In round k a function is
// decompiled with the round-k prototypes of callees ranked below it
// (already final for the round) and the round-(k-1) ones of the rest, so
// what a callee learns reaches its callers' callers in the same round
// instead of one call edge per round; its callers ranked above it are seen
// as of round k-1. Same-rank functions read each other at k-1, so no query
// waits on itself.
struct Order {
  std::vector<std::pair<std::uint64_t, std::uint32_t>> rank;  // by entry
  std::uint32_t components = 0;

  std::uint32_t rank_of(std::uint64_t entry) const;  // UINT32_MAX for an unknown entry
  void encode(facts::Encoder &e) const;
  static Order decode(facts::Decoder &d);
};

struct OrderQuery {
  static constexpr std::string_view name = "infer.order";
  static constexpr std::uint32_t version = 1;
  using Key = ProgramKey;
  using Value = Order;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

struct RoundKey {
  Location at;
  std::uint32_t round = 0;

  friend bool operator==(const RoundKey &, const RoundKey &) = default;
  void encode(facts::Encoder &e) const;
  static RoundKey decode(facts::Decoder &d);
};

// One function decompiled with its callees' prototypes locked: round 0
// only library prototypes; round k each callee's as of round k when it
// ranks below the function (Order), else as of round k-1.
struct Observe {
  static constexpr std::string_view name = "infer.observe";
  // 2: rounds in call-graph order; 3: a pointer a locked call casts to an
  // integer parameter is seen as the caller's pointer; 4: arguments that
  // are the caller's parameters passed on (Slot::from_param); 5: jumps to
  // other functions are tail calls (RunOptions::call_returns); 6: pointer
  // parameters' accesses (Observation::pointer_uses); 7: decoded in the
  // function's instruction set (RunOptions::context: ARM's Thumb); 8:
  // loads typed as the final C's decompiler types them
  // (Options::load_extension)
  static constexpr std::uint32_t version = 8;
  using Key = RoundKey;
  using Value = Observation;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k);
};

// Functions whose addresses sit in the same function-pointer table in the
// program's data (an array of pointers, or a field at a fixed stride in an
// array of structs): C gives them one type, so they share a prototype.
struct FamilyTable {
  std::vector<std::vector<std::uint64_t>> families;     // members by entry
  std::vector<std::pair<std::uint64_t, std::uint32_t>> index;  // entry -> family, by entry
  // The tables: first and last slot address, family, by first address.
  struct Table {
    std::uint64_t first = 0, last = 0;
    std::uint32_t family = 0;
    friend bool operator==(const Table &, const Table &) = default;
    void encode(facts::Encoder &e) const;
    static Table decode(facts::Decoder &d);
  };
  std::vector<Table> tables;

  const std::vector<std::uint64_t> *find(std::uint64_t entry) const;
  // The family of the table holding `address`.
  const std::vector<std::uint64_t> *table_at(std::uint64_t address) const;
  void encode(facts::Encoder &e) const;
  static FamilyTable decode(facts::Decoder &d);
};

struct Families {
  static constexpr std::string_view name = "infer.families";
  // 2: Thumb code pointers name their function
  static constexpr std::uint32_t version = 2;
  using Key = ProgramKey;
  using Value = FamilyTable;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

// Functions passed to a library function's function-pointer parameter
// (qsort's comparator, __libc_start_main's main): the prototype the
// library calls them with, from the signature database.
struct Callbacks {
  static constexpr std::string_view name = "infer.callbacks";
  static constexpr std::uint32_t version = 1;
  using Key = ProgramKey;
  using Value = std::vector<std::pair<std::uint64_t, Prototype>>;  // by entry
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

// A function's observation at a round, with a repeated round's content
// (Observation::same_as) looked up.
facts::Ref<Observation> observation(facts::QueryContext &ctx, const RoundKey &key);
facts::Ref<Observation> observation(const facts::Snapshot &snapshot, const RoundKey &key);

// A prototype with its history in the iteration.
struct Inferred {
  bool known = false;   // there is a prototype (a function, decompiled or with callers)
  Prototype proto;
  std::uint32_t changes = 0;  // rounds in which it changed
  bool widened = false;

  friend bool operator==(const Inferred &, const Inferred &) = default;
  void encode(facts::Encoder &e) const;
  static Inferred decode(facts::Decoder &d);
};

// Round k's prototype of one function from its own evidence: its
// observations and what its callers' observations say about it.
struct Own {
  static constexpr std::string_view name = "infer.own";
  // 3: parameters it only passes on to callees that read them; 4: what a
  // tail call returns, and imports' parameters passed on
  static constexpr std::uint32_t version = 4;
  using Key = RoundKey;
  using Value = Inferred;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k);
};

// Round k's prototype of one function: its own evidence (Own), a library
// callback type or its table family's consensus, and its round k-1 value.
struct Round {
  static constexpr std::string_view name = "infer.round";
  // 3: a thunk has its target's prototype
  static constexpr std::uint32_t version = 3;
  using Key = RoundKey;
  using Value = Inferred;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k);
};

struct FixpointResult {
  std::uint32_t rounds = 0;      // the last round computed
  bool converged = false;        // the last round changed nothing
  std::vector<std::uint32_t> changed;  // prototypes changed per round (round 0: inferred)
  std::uint32_t widened = 0;
  std::vector<std::pair<std::uint64_t, Prototype>> prototypes;  // by entry
  std::vector<InferredStructure> structures;  // what the prototypes' astruct_<n> are

  const Prototype *find(std::uint64_t entry) const;
  const InferredStructure *structure(std::string_view name) const;
  void encode(facts::Encoder &e) const;
  static FixpointResult decode(facts::Decoder &d);
};

struct Fixpoint {
  static constexpr std::string_view name = "infer.fixpoint";
  // 3: pointers passed on unchanged take one target (unify_passed_pointers);
  // 4: structures for classes of passed-on pointers (InferredStructure)
  static constexpr std::uint32_t version = 4;
  using Key = ProgramKey;
  using Value = FixpointResult;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

// The final prototype of the function at a location.
struct PrototypeQuery {
  static constexpr std::string_view name = "infer.prototype";
  static constexpr std::uint32_t version = 1;
  using Key = Location;
  using Value = std::optional<Prototype>;
  static Value compute(facts::QueryContext &ctx, const Key &at);
  static std::string describe(const Key &k) { return analysis::describe(k); }
};

// Registers infer's input and queries (analysis's must be registered too).
void register_queries(facts::Engine &engine);

// Stages the image the decompiler reads for `program` (whose bytes and
// analysis.program input analysis::stage_image stages).
void stage_image(facts::FactDb::Transaction &tx, const ProgramKey &program,
                 std::shared_ptr<const loader::Image> image, const std::string &language_id,
                 const std::string &identity, const Options &options = {});

// The inferred prototype of the function at `at`, if it is one.
std::optional<Prototype> prototype_for(const facts::Snapshot &snapshot, const Location &at);

// What one round of run() cost (diagnostics; not part of any fact).
struct RoundStats {
  std::uint32_t round = 0;
  double seconds = 0;              // wall
  std::uint64_t decompiled = 0;    // observations that ran the decompiler
  double decompile_seconds = 0;    // their time, summed over threads
  double slowest_seconds = 0;      // the slowest one
  std::uint64_t slowest = 0;       // its entry
  std::uint32_t changed = 0;       // prototypes that changed
  std::vector<std::uint64_t> changed_entries;  // which (up to 64)
};

// Following and stopping a run() (the backend's background inference).
struct RunControl {
  // Asked before each function's observation; true stops the run, which
  // then throws Cancelled. What was computed stays memoized.
  std::function<bool()> cancelled;
  // After each function of a round: the round, functions done in it and
  // their number, and the round cap (rounds 0..max_rounds; a run usually
  // converges well before it).
  std::function<void(std::uint32_t round, std::size_t done, std::size_t total, std::uint32_t max_rounds)> progress;
};

struct Cancelled : std::runtime_error {
  Cancelled() : std::runtime_error("inference cancelled") {}
};

// Computes every round in parallel on `pool` (null: the calling thread),
// then returns the fixpoint, which then reads memoized rounds. With
// `stats`, what each round cost.
FixpointResult run(const facts::Snapshot &snapshot, const ProgramKey &program, facts::ThreadPool *pool,
                   std::vector<RoundStats> *stats = nullptr, const RunControl *control = nullptr);

// Whether inference knows the calling convention of `language_id`'s default
// prototype for `image` (System V and Windows x86-64, AAPCS64, RISC-V
// LP64D; on 32-bit processors AAPCS for ARM and Thumb, MIPS o32 and
// PowerPC SysV, measured against the source in docs/decomp-quality.md):
// elsewhere a prototype is only the decompiler's own view of the
// function. (RISC-V rv32 and x86-32 have tables abi_for gives rk-infer,
// unmeasured.)
bool supports(const std::string &language_id, const loader::Image &image);

// The target's C data organization (pointer and long sizes).
DataOrg data_org(const loader::Image &image);

}  // namespace revkit::infer
