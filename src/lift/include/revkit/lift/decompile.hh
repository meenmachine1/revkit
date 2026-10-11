// Decompiling a program's functions under given inputs (decomp_inputs.hh),
// in parallel, the way Ghidra's DecompInterface decompiles a program: each
// function starts from the same symbol table, with the options Ghidra sends
// (DecompileOptions.grabFromProgram, simplification style "decompile").
#pragma once

#include "revkit/lift/budget.hh"
#include "revkit/lift/decomp_inputs.hh"
#include "revkit/lift/image_arch.hh"
#include "revkit/loader/image.hh"

#include <cstdint>
#include <functional>
#include <iosfwd>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace ghidra {
class PrintLanguage;
struct PrototypePieces;
}

namespace revkit::lift {

// Java's IllegalCharCppTransformer: characters that can't appear in a C++
// identifier become '_' ("main.cold" -> "main_cold"), as Ghidra's
// DecompileResults applies to function, variable, type, field and label
// names.
std::string legal_cpp_name(const std::string &name);

// The facts InputDecompiler answers the decompiler's queries from, looked
// up by address the way Ghidra's Java side looks them up in its program
// database (DecompileCallback). Spaces are by name, "" for the default
// space. Returned pointers stay valid until reset().
//
// lookup_inputs() indexes a DecompilerInputs; the image backend looks facts
// up through fact-store queries, so a decompilation depends on exactly
// those it read.
class FactLookup {
 public:
  virtual ~FactLookup() = default;
  struct Body {
    std::uint64_t first = 0, last = 0;  // the range of the body containing the address
    const FunctionFacts *function = nullptr;
  };
  virtual const FunctionFacts *function_at(std::uint64_t entry) = 0;
  virtual std::optional<Body> body_containing(std::uint64_t a) = 0;
  virtual const DataFacts *data_containing(const std::string &space, std::uint64_t a) = 0;
  virtual const ExternalRefFacts *external_at(const std::string &space, std::uint64_t a) = 0;
  virtual const LabelFacts *label_at(const std::string &space, std::uint64_t a) = 0;
  virtual std::optional<std::string> code_label_at(const std::string &space, std::uint64_t a) = 0;
  // The mutability of the memory block holding the address; nullopt
  // outside every block.
  virtual std::optional<Mutability> block_at(const std::string &space, std::uint64_t a) = 0;
  virtual const DecompElement *type(std::uint64_t id) = 0;
  // Every type id, when decoding them all up front is cheap and allowed
  // (see InputDecompiler::install_types); empty to always fetch lazily.
  virtual std::vector<std::uint64_t> all_types() { return {}; }
  // The function being decompiled: the comments it shows, flow overrides,
  // tracked register values at its entry.
  virtual std::vector<const CommentFacts *> comments(std::uint64_t entry) = 0;
  virtual std::vector<std::pair<std::uint64_t, std::string>> flow_overrides(std::uint64_t entry) = 0;
  virtual std::vector<TrackedFacts> tracked(std::uint64_t entry) = 0;
  // Whether returned pointers outlive reset() (an index over fixed inputs).
  virtual bool stable() const { return false; }
  // A run is over: what it looked up may be released.
  virtual void reset() {}
};

// A lookup over fixed inputs. Without memory blocks in them, `image`'s
// blocks (if given) say which memory is constant: not writable.
std::unique_ptr<FactLookup> lookup_inputs(std::shared_ptr<const DecompilerInputs> inputs,
                                          const loader::Image *image = nullptr);

struct DecompileConfig {
  std::shared_ptr<const loader::Image> image;
  std::string language_id;  // with compiler: "x86:LE:64:default:gcc"
  std::shared_ptr<const DecompilerInputs> inputs;
  // Where facts are looked up; null: an index over `inputs`. With a lookup,
  // `inputs` supplies only what an architecture is built with (memory
  // blocks, patches, synthesized memory, the address prefix).
  std::shared_ptr<FactLookup> lookup;
  // The inputs' patches and synthesized memory, when instances share them
  // (decompile_functions does); otherwise each architecture copies them.
  std::shared_ptr<const ArchitectureOptions::Patches> patches;
  // Bytes from here instead of the image and the patches (a decompiler
  // worker reads a bundle's), and decoding context instead of the image's.
  std::shared_ptr<MemorySource> memory;
  std::optional<std::vector<ContextRegion>> context;
  // Synthesize Ghidra's default names (LAB_, DAT_) where the inputs have no
  // symbol. Off when the inputs are a full export of Ghidra's symbols.
  bool default_names = true;
  // Synthesize LAB_ for any address in a function body the decompiler asks
  // a label for (with default_names). Off when the inputs list the code
  // labels Ghidra would have (revkit's own references); then the cases of
  // the function's recovered jump tables are also named as Ghidra's switch
  // analysis names them (switchD_<jump>_caseD_<value>).
  bool default_labels = true;
  // Fill a function's unknown extrapop from the default calling convention
  // (what Ghidra does for a function whose stack purge is unknown).
  bool default_extrapop = true;
  unsigned threads = 0;  // 0: one per hardware thread
  // Decompile in the order given (default: largest functions first, which
  // finishes sooner). With one thread and entries in address order, the
  // decompiler sees functions in the sequence DecompInterface does.
  bool in_order = false;
  // Bounds on each function's run (none by default); RunHooks::limits
  // overrides them for one run.
  DecompileLimits limits;
  // The decompiler's "unreachable" action (DecompileOptions'
  // eliminateUnreachable). Ghidra's Decompiler Parameter ID turns it off
  // (param_id.hh).
  bool eliminate_unreachable = true;
  // The root action the decompiler runs: "decompile" (DecompInterface's
  // simplification style), or "normalize", the group BSim's signatures run
  // (SignaturesAt: no type recovery, structuring or merging; decompd mode
  // signature). Under "normalize" a run is analysed, not printed: a print
  // hook (RunHooks::print) reads the function.
  std::string action = "decompile";
  // decompile_functions: resident memory (bytes) to stay within; 0 is
  // unbounded. Functions start only while their estimated working sets fit
  // beside the ones running (largest first, smaller ones filling in), and
  // unless limits.max_varnodes is set, no function may grow past what the
  // budget leaves for one (it stops as too large).
  std::size_t memory_budget = 0;
  // Calls to a varargs function with a format parameter (printf, scanf and
  // their kin, by the parameter's name) whose format is a constant string
  // get a call-site prototype with the arguments the format names
  // (format_string.hh), and the function is analysed again: Ghidra's
  // "Variadic Function Signature Override" analysis. revkit's own inputs
  // only (rk-lift --analyze, the daemon); off for Ghidra's exported ones.
  bool format_strings = false;
};

struct DecompileResult {
  std::uint64_t entry = 0;
  bool ok = false;
  std::string c;      // the printer's C text
  std::string error;  // why there is no C
  // Inputs the decompiler asked for that could not be used (a type that
  // didn't decode, a symbol it rejected).
  std::vector<std::string> input_errors;
  double milliseconds = 0;
  // Why the run stopped short (`error` says so too): over its limits.
  DecompileStop stopped = DecompileStop::none;
  std::size_t varnodes = 0;  // the most the function had (sampled)
};

// What a caller adds to one run, and how it prints.
struct RunHooks {
  // Jump tables recovered elsewhere (computed jump -> destinations), given
  // to the decompiler as overrides where it can't recover a table itself:
  // it warns that it treats the jump as a call or a return, and the
  // function is analysed again with the table installed.
  std::map<std::uint64_t, std::vector<std::uint64_t>> jump_tables;
  // Flow overrides and comments besides the lookup's.
  std::vector<std::pair<std::uint64_t, std::string>> flow_overrides;
  std::vector<CommentFacts> comments;
  // The user's (docs/api.md, "Equates and user references"): equates and
  // conversions of constants in the function; computed calls made direct
  // calls to a target (a call override: Override::insertIndirectOverride);
  // computed jumps whose `jump_tables` entry is installed whether or not
  // the decompiler recovers a table itself.
  std::vector<EquateFacts> equates;
  std::map<std::uint64_t, std::uint64_t> call_targets;
  std::set<std::uint64_t> forced_tables;
  // Calls' signature overrides (docs/api.md, "Call-site signature
  // overrides"): call address -> the prototype the decompiler takes for
  // that call alone (Override::insertProtoOverride), in place of its
  // callee's; its convention, return, parameters and varargs are read,
  // the storage assigned by the convention. Over a format string's.
  std::map<std::uint64_t, FunctionFacts> call_protos;
  // Prints the analysed function in place of the C printer (which then
  // leaves DecompileResult::c empty); called while it is alive. Printing
  // runs under share_ghidra_globals() instead of the exclusive lock.
  std::function<void(ghidra::Funcdata &)> print;
  // Called with true before printing and false after.
  std::function<void(bool)> printing;
  // This run's bounds instead of DecompileConfig::limits.
  const DecompileLimits *limits = nullptr;
};

// One architecture with the inputs installed. Not thread-safe: one thread
// at a time (use one per thread).
class InputDecompiler {
 public:
  explicit InputDecompiler(const DecompileConfig &config);
  // With a printer of the caller's instead of the C printer: made by
  // `make_printer` (under lock_ghidra_globals(), before the architecture's
  // init configures it) and owned by the architecture.
  InputDecompiler(const DecompileConfig &config,
                  const std::function<ghidra::PrintLanguage *(ghidra::Architecture *)> &make_printer);
  ~InputDecompiler();
  InputDecompiler(const InputDecompiler &) = delete;
  InputDecompiler &operator=(const InputDecompiler &) = delete;

  DecompileResult decompile(std::uint64_t entry, const RunHooks *hooks = nullptr);

  // A run was stopped over its limits (DecompileResult::stopped): the
  // architecture may be left mid-analysis, so the caller should build a
  // new instance rather than decompile with this one again.
  bool spoiled() const { return spoiled_; }

  // What installing the inputs could not use (types that didn't decode,
  // symbols the decompiler rejected), one line each.
  const std::vector<std::string> &warnings() const { return warnings_; }

  ImageArchitecture &architecture() { return *arch_; }

  // The inputs as installed: functions with dynamic storage have it
  // assigned (for dumping what the decompiler is told).
  DecompilerInputs resolved_inputs();

  // `f` with its parameters' and return value's storage assigned by its
  // calling convention, as Java's dynamic storage assigns it; nullopt if
  // the convention can't (no model, a type that doesn't decode).
  std::optional<FunctionFacts> assign_storage(const FunctionFacts &f);

 private:
  struct State;
  void install();
  void install_types();
  ghidra::Datatype *fetch_type(const std::string &name, std::uint64_t id);
  ghidra::Scope *scope_for(const NamespacePath &ns);
  ghidra::Symbol *add_symbol(const DecompElement &e, const NamespacePath &ns, const std::string &what);
  ghidra::Symbol *resolve(const ghidra::Address &addr, ImageScope::Hole &hole);
  void place_equates(const std::vector<EquateFacts> &equates);
  std::string code_label(const ghidra::Address &addr);
  std::optional<std::string> switch_label(std::uint64_t a);
  std::optional<std::string> defined_string(const ghidra::Address &addr);
  std::map<std::uint64_t, ghidra::PrototypePieces> format_overrides(ghidra::Funcdata &fd);
  // A call-site prototype from a signature override (RunHooks::call_protos);
  // nullopt if a type doesn't decode.
  std::optional<ghidra::PrototypePieces> call_pieces(const FunctionFacts &f);
  ghidra::Funcdata *external_function(const ghidra::Address &slot);
  const FunctionFacts *with_storage(const FunctionFacts &f);
  const FunctionFacts *prepared(const FunctionFacts *f);
  std::optional<FactLookup::Body> body_containing(std::uint64_t a);
  std::string space_name(const ghidra::Address &addr) const;
  void set_tracked(std::uint64_t entry);
  // The function's context variables (FunctionFacts::context) over its body.
  void set_context(std::uint64_t entry);
  std::string end_run();

  DecompileConfig config_;
  std::unique_ptr<std::ostringstream> errors_;
  std::unique_ptr<ImageArchitecture> arch_;
  std::unique_ptr<State> state_;
  std::vector<std::string> warnings_;
  DecompileBudget budget_;
  bool spoiled_ = false;
};

struct DecompileStats {
  double setup_seconds = 0;   // building architectures and installing inputs (wall)
  double total_seconds = 0;   // everything (wall)
  unsigned threads = 0;
  std::vector<std::string> warnings;  // from the first instance
  std::size_t stopped = 0;    // runs stopped over their limits
  std::size_t rebuilt = 0;    // instances built again after a stopped run
  std::size_t peak_rss = 0;   // bytes, sampled while decompiling (with a memory budget)
  std::size_t max_varnodes = 0;  // the per-function bound in force (0: none)
};

// Decompiles `entries` with config.threads InputDecompilers, each used by
// one thread. Results are in the order of `entries`. With `on_result`,
// each result is handed to it as soon as it is made (from the worker
// thread, one call at a time), and the returned vector keeps everything
// but the C text, so a whole program's text needn't be held in memory.
std::vector<DecompileResult> decompile_functions(
    const DecompileConfig &config, const std::vector<std::uint64_t> &entries, DecompileStats *stats = nullptr,
    const std::function<void(std::size_t index, DecompileResult &result)> &on_result = {});

}  // namespace revkit::lift
