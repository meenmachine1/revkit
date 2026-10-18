// Ghidra's decompiler as an observer for prototype inference.
//
// Decompiling one function with given prototypes for the functions it
// calls yields what the decompiler concluded about it, from the language's
// .cspec prototype model: its parameters (storage read before written) and
// return value (storage live at its returns), with the types its own type
// propagation gave them, and, at each call it makes, what is passed and
// whether the result is used. Inference combines these across the call
// graph (infer.h).
//
// Symbols are not loaded up front: the global scope asks a SymbolEnv the
// first time the decompiler looks an address up, so a caller backed by the
// fact store records exactly the callees a decompilation consulted.
#pragma once

#include "revkit/decompd/builder.h"
#include "revkit/decompd/pool.h"
#include "revkit/infer/accesses.h"
#include "revkit/infer/vtype.h"
#include "revkit/lift/context.hh"
#include "revkit/lift/image_arch.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/image.hh"

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace revkit::infer {

// Where a value lives: a register (by its canonical name: RDI, XMM0, x0,
// a0, fa0) or a stack offset at the function's entry.
struct Slot {
  std::string reg;  // empty: on the stack
  std::int64_t stack = 0;
  std::uint8_t size = 0;
  VType type;
  // Parameters: how many low bytes the function uses (an int passed in a
  // 64-bit register is only ever truncated), 0 if unknown. Call
  // arguments: 0.
  std::uint8_t used = 0;
  // Parameters: the narrowest low part any use takes (a 32-bit operation
  // on a register RISC-V passes sign-extended), 0 if none truncates it.
  std::uint8_t narrowest = 0;
  // Call arguments: the constants the value can be (a function pointer,
  // or either of two chosen by a condition).
  std::vector<std::uint64_t> constants;
  // Call arguments: some constant is an address in the image's data
  // (static data) or code (a function).
  bool data_address = false;
  bool code_address = false;
  // Call arguments: the caller's parameter (its index in the caller's
  // Observation::params) passed on unchanged, -1 for any other value.
  std::int32_t from_param = -1;
  // Parameters: every read of it passes it on to a call unchanged (so the
  // function doesn't use it itself).
  bool passed_only = false;

  friend bool operator==(const Slot &, const Slot &) = default;
  void encode(facts::Encoder &e) const;
  static Slot decode(facts::Decoder &d);
};

struct CallSite {
  std::uint64_t address = 0;  // the call instruction
  std::uint64_t target = 0;   // the callee's entry, or the import slot; 0 if unknown
  bool locked = false;        // the callee's prototype was given to the decompiler
  std::vector<Slot> args;     // what the call passes, in the model's order
  bool ret_used = false;      // the return value is read after the call
  VType ret_type;             // its type there

  friend bool operator==(const CallSite &, const CallSite &) = default;
  void encode(facts::Encoder &e) const;
  static CallSite decode(facts::Decoder &d);
};

// How a pointer-sized parameter is used as a pointer: what
// infer::pointer_accesses finds through it (loads and stores at constant
// offsets, and the calls it is passed to; trimmed to offset, size, kind,
// value, and for a passed one the call's address, callee and argument
// index), and through each value loaded through it, by offset (one level:
// `param_1->field_0x18->...`). What structure inference composes after the
// fixpoint (infer.h, InferredStructure).
struct PointerUse {
  std::int32_t param = -1;  // index in Observation::params (-1: a call's result)
  std::uint64_t call = 0;   // a call's result: the call's address
  std::vector<PointerAccess> accesses;
  // Offsets whose loaded value flows back into the variable (`p =
  // p->next`): fields pointing to the same kind of thing.
  std::vector<std::int64_t> self;
  bool returned = false;  // the function returns the value unchanged
  struct Field {
    std::int64_t offset = 0;
    std::vector<PointerAccess> accesses;
    std::vector<std::int64_t> self;  // as PointerUse::self, for the loaded value
    bool returned = false;           // the function returns the loaded value
    friend bool operator==(const Field &, const Field &) = default;
    void encode(facts::Encoder &e) const;
    static Field decode(facts::Decoder &d);
  };
  std::vector<Field> fields;  // by offset

  friend bool operator==(const PointerUse &, const PointerUse &) = default;
  void encode(facts::Encoder &e) const;
  static PointerUse decode(facts::Decoder &d);
};

struct Observation {
  bool ok = false;
  std::string error;
  std::vector<Slot> params;
  std::optional<Slot> ret;  // nullopt: returns nothing
  // The width the returned values have before any extension to the return
  // register (a 4-byte int zero-extended into RAX): the widest over all
  // returns, constants counted by the bytes they need. 0 if unknown.
  std::uint8_t ret_natural = 0;
  // Some return is a constant address in the image's data (a static
  // buffer or string).
  bool ret_address = false;
  // Constant code addresses returned (a function pointer).
  std::vector<std::uint64_t> ret_code;
  // Data addresses some returned value is loaded from (an element of a
  // static table).
  std::vector<std::uint64_t> ret_loaded;
  // Inputs read that the model doesn't count as parameters (in_AL on
  // x86-64, which carries the vector-register count of a variadic call).
  std::vector<Slot> extra_inputs;
  // Integer argument registers stored to the stack and otherwise unused,
  // as a variadic function's register save area does (AArch64, RISC-V).
  std::vector<std::string> spilled_only;
  // The prologue, decoded before any analysis: argument registers stored
  // to memory before anything writes them (a register save area), in the
  // order stored, and whether AL is read first (System V's vector count).
  std::vector<std::string> spills;
  bool reads_al = false;
  std::vector<CallSite> calls;
  // The pointer-sized parameters' uses as pointers (those with any), and
  // the pointer-sized results of calls (`param` -1, `call` the call).
  std::vector<PointerUse> pointer_uses;
  std::vector<PointerUse> results;
  // Function entries the decompiler looked up (callees, function pointers):
  // what this observation depends on besides the function itself.
  std::vector<std::uint64_t> consulted;
  std::string c;  // decompiled C, when asked for
  // A later round's observation that would repeat an earlier one (nothing
  // it consulted changed) holds only the round whose content it repeats,
  // so rounds cost memory only where something changed. See
  // infer::observation() in infer.h.
  std::optional<std::uint32_t> same_as;
  // The decompilation was stopped over its varnode bound (RunOptions):
  // the function is too large to observe (`ok` is false).
  bool too_large = false;

  friend bool operator==(const Observation &, const Observation &) = default;
  void encode(facts::Encoder &e) const;
  static Observation decode(facts::Decoder &d);
};

// What the decompiler is told about a function at an address.
struct FunctionSymbol {
  std::string name;
  bool no_return = false;
  std::optional<Prototype> proto;  // locked when set
};

class SymbolEnv {
 public:
  virtual ~SymbolEnv() = default;
  // A function starting at `entry`, or nullopt.
  virtual std::optional<FunctionSymbol> function(std::uint64_t entry) = 0;
  // The imported function an external-reference slot (PE IAT, ELF GOT)
  // holds, or nullopt.
  virtual std::optional<FunctionSymbol> import_slot(std::uint64_t slot) = 0;
};

struct RunOptions {
  bool want_c = false;
  // The varnodes the function may grow to (0: unbounded): a function past
  // it isn't observed (Observation::too_large). Deterministic, unlike a
  // timeout, so inference gives the same answer on any machine.
  std::size_t max_varnodes = 0;
  // A deadline for the run (0: none); past it the observation fails.
  double timeout_seconds = 0;
  // The function's body (inclusive ranges), when known: what its
  // decompiler bundle is predicted from (revkit::decompd). Empty: the flow
  // from the entry.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> body;
  // Fill Observation::spills and reads_al. A worker leaves it to the
  // process that has the image's bytes.
  bool prologue = true;
  // Jumps the decompiler takes as tail calls (CALL_RETURN flow overrides).
  std::vector<std::uint64_t> call_returns;
};

// One Ghidra architecture over an image. Not thread-safe: one thread at a
// time. lift::initialize() must have been called.
// The prologue facts of each function (Observation::spills, reads_al),
// decoded once per entry with one SLEIGH engine that every decompiler of a
// pool shares (an engine is about 35 MB; the decode takes microseconds).
class Prologues {
 public:
  Prologues(std::shared_ptr<const loader::Image> image, std::string language);
  ~Prologues();
  // Sets o.spills and o.reads_al for the function at `entry`.
  void fill(std::uint64_t entry, Observation &o);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

class Decompiler {
 public:
  // `prologues`: shared with other decompilers of the image (null: its own).
  // `memory` and `context`: where the decompiler reads bytes and its
  // decoding context instead of the image (a worker's bundle).
  Decompiler(std::shared_ptr<const loader::Image> image, const std::string &language_id,
             std::shared_ptr<Prologues> prologues = nullptr, std::shared_ptr<lift::MemorySource> memory = nullptr,
             std::optional<std::vector<lift::ContextRegion>> context = std::nullopt);
  ~Decompiler();
  Decompiler(const Decompiler &) = delete;
  Decompiler &operator=(const Decompiler &) = delete;

  // Decompiles the function at `entry`. Its own prototype is the one
  // env.function(entry) gives (locked), or recovered by the decompiler.
  // Exceptions thrown by `env` propagate (after the decompiler is reset).
  Observation run(std::uint64_t entry, SymbolEnv &env, const RunOptions &options = {});

  const DataOrg &data_org() const;
  // A run was stopped over its bound: the architecture may be left
  // mid-analysis, so the pool builds another rather than reuse it.
  bool spoiled() const;
  // Why the last run stopped short (lift::DecompileStop::none if it didn't).
  lift::DecompileStop last_stop() const;
  lift::ImageArchitecture &architecture();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Decompiles one image's functions in decompiler worker processes
// (revkit::decompd, mode observe): each run's bundle holds the image's bytes
// the decompiler reads and the SymbolEnv's answers to what it will ask
// (predicted from the function's body, completed with what the worker
// missed), so the env's lookups stay the observation's dependencies. A
// worker that crashes or hangs costs one observation (not ok, the failure
// in its error), and the failure is kept for failures().
class DecompilerPool {
 public:
  DecompilerPool(std::shared_ptr<const loader::Image> image, std::string language_id);
  ~DecompilerPool();

  // What callers lease, as they leased a decompiler: run() and data_org().
  class Lease {
   public:
    explicit Lease(DecompilerPool &pool) : pool_(&pool) {}
    DecompilerPool &operator*() const { return *pool_; }
    DecompilerPool *operator->() const { return pool_; }

   private:
    DecompilerPool *pool_;
  };
  Lease acquire() { return Lease(*this); }

  // Decompiles the function at `entry` as Decompiler::run would, in a
  // worker. Exceptions thrown by `env` propagate.
  Observation run(std::uint64_t entry, SymbolEnv &env, const RunOptions &options = {});
  DataOrg data_org();
  // Every decompilation that failed so far (crash, hang, out of memory).
  std::vector<decompd::Failure> failures() const;
  // Frees what the pool keeps between decompilations: its lifters (a SLEIGH
  // engine each, one per thread that used it), the program image and the
  // prologue reader. The next run makes them again. A daemon keeps a pool
  // per program, so after a run (ImageBackend's inference) this is what
  // keeps ~200 MB per program from staying behind.
  void trim();
  // Lifters kept between runs (for tests).
  std::size_t idle_lifters() const;

  // The workers every DecompilerPool decompiles in (default: one of the
  // process's own, with up to eight workers).
  static void set_workers(std::shared_ptr<decompd::WorkerPool> workers);
  static std::shared_ptr<decompd::WorkerPool> workers();

 private:
  std::shared_ptr<const decompd::ProgramImage> program();
  std::unique_ptr<lift::Lifter> take_lifter();

  std::shared_ptr<const loader::Image> image_;
  std::string language_id_;
  mutable std::mutex mu_;
  std::shared_ptr<const decompd::ProgramImage> program_;
  std::vector<std::unique_ptr<lift::Lifter>> lifters_;
  std::shared_ptr<Prologues> prologues_;
  std::vector<decompd::Failure> failures_;
};

// Registers mode observe with revkit::decompd (rk-decompd, and the
// in-process debugging mode).
void register_decompd_mode();

}  // namespace revkit::infer
