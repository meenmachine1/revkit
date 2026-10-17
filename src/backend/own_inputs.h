// The decompiler's inputs in the image backend: revkit::inputs' assembly,
// the same rk-lift --analyze --decompile uses (src/inputs), computed and
// sliced by fact-store queries so that a decompilation depends on exactly
// the facts it reads, with the project's assertions laid over them.
//
//   inputs.static    what of those the image alone decides: relocations, <- the image, analysis.program
//                    pointer slots, imports, EXTERNAL and thread blocks,
//                    the loader's symbols (inputs::assemble_static)
//   inputs.program   the program-wide facts (inputs::assemble_program)   <- inputs.static, discovery's
//                                                                           functions, debug info
//   inputs.image     what a decompiler instance is built with: relocated <- inputs.static
//                    bytes, synthesized memory, the address prefix
//   inputs.sets      function entries and no-return functions           <- analysis.functions
//   inputs.function  one function's stack variables, flow overrides     <- analysis.function/flow,
//                    and code labels (inputs::assemble_function)            inputs.sets, inputs.address
//   inputs.address   what the decompiler is told about one address:     <- inputs.program
//                    the function there or around it, data, label,
//                    external reference, block, tracked registers and
//                    comments of a function starting there
//   inputs.type      one data type definition by id                     <- inputs.program
//
// Slices are recomputed when the program's facts change, but their values
// usually don't, so the decompilations that read them validate.
#pragma once

#include "decompiler.h"
#include "model.h"

#include "revkit/infer/vtype.h"
#include "revkit/facts/engine.h"
#include "revkit/inputs/ghidra_types.h"
#include "revkit/inputs/inputs.h"
#include "revkit/lift/decompile.hh"
#include "revkit/lift/param_id.hh"

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace revkit::backend {

struct ProgramInputs {
  // Without the relocated pointer slots, which inputs.address makes when
  // looked up (inputs::pointer_slot), named from `slots`.
  std::shared_ptr<const lift::DecompilerInputs> inputs;
  std::shared_ptr<lift::FactLookup> index;  // over `inputs`; not encoded
  std::shared_ptr<const inputs::SlotNames> slots;

  void encode(facts::Encoder &e) const;
  static ProgramInputs decode(facts::Decoder &d);
};


struct AddressFacts {
  std::optional<lift::FunctionFacts> starts;    // the function whose entry it is
  std::optional<lift::FunctionFacts> contains;  // the function whose body holds it
  std::uint64_t body_first = 0, body_last = 0;  // the range of that body holding it
  std::optional<lift::DataFacts> data;           // data containing it
  std::optional<lift::ExternalRefFacts> external;
  std::optional<lift::LabelFacts> label;
  std::optional<lift::Mutability> block;
  std::vector<lift::TrackedFacts> tracked;   // at a function's entry
  std::vector<lift::CommentFacts> comments;  // in the body of the function starting here (debug info's)

  bool empty() const;
  void encode(facts::Encoder &e) const;
  static AddressFacts decode(facts::Decoder &d);
};


namespace q {

// revkit::infer's prototype of a function (or an import stub's library
// prototype) as decompilations see it: set by the backend's background
// inference (ImageBackend: InferLoop) once it reaches its fixpoint, one key
// per function, so a decompilation never waits for inference and is redone
// only where a prototype it looked up arrives or changes. Unset: none.
struct InferPublished {
  static constexpr std::string_view name = "infer.published";
  using Key = std::pair<std::string, std::uint64_t>;  // (program, entry)
  using Value = std::optional<infer::Prototype>;
};

using ProgramKey = std::string;
using AddressKey = std::pair<std::string, std::uint64_t>;

// What the program's inputs take from the image alone (relocations,
// pointer slots, imports, the EXTERNAL and thread blocks, symbols): a
// change to the function list doesn't recompute it.
struct InputsStatic {
  static constexpr std::string_view name = "inputs.static";
  static constexpr std::uint32_t version = 6;  // 2: functions' context; 3: locals' source types; 4: the memory map (docs/memory-map.md);
                                               // 5: demangled (docs/demangle.md); 6: a separate debug file (program.debug_file)
  using Key = ProgramKey;
  using Value = inputs::StaticInputs;
  static Value compute(facts::QueryContext &ctx, const Key &program);
  static std::size_t weight(const Value &v);
};

struct InputsProgram {
  static constexpr std::string_view name = "inputs.program";
  static constexpr std::uint32_t version = 15;  // 2: from inputs.static; 3: pointer slots looked up; 4: context; 5: data analysis; 6: no-return;
                                                // 7: context_reach; 8: ARM functions' context; 9: call fixups by name; 10: locals' source types
                                                // 11: a raw image's patches through patch.page; 12: the memory map;
                                                // 13: demangled names and prototypes (docs/demangle.md)
                                                // 14: revkit's library archives (library.prototypes)
                                                // 15: a separate debug file (program.debug_file)
  using Key = ProgramKey;
  using Value = ProgramInputs;
  static Value compute(facts::QueryContext &ctx, const Key &program);
  static std::size_t weight(const Value &v);
};

struct InputsImage {
  static constexpr std::string_view name = "inputs.image";
  static constexpr std::uint32_t version = 2;  // 2: from inputs.static
  using Key = ProgramKey;
  using Value = ImageInputs;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

struct InputsSets {
  static constexpr std::string_view name = "inputs.sets";
  static constexpr std::uint32_t version = 3;  // 2: Ghidra's no-return (names and evidence); 3: and the user's
  using Key = ProgramKey;
  using Value = inputs::FunctionSets;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

struct InputsFunction {
  static constexpr std::string_view name = "inputs.function";
  static constexpr std::uint32_t version = 8;  // 2: CALL_RETURN on calls to switch helpers; 3: BRANCH on far jumps;
                                               // 4: stack walked with a lifter of its own; 5: locals' source types; 6: the memory map;
                                               // 7: demangled functions (docs/demangle.md); 8: a separate debug file (program.debug_file)
  using Key = AddressKey;
  using Value = inputs::FunctionInputs;
  static Value compute(facts::QueryContext &ctx, const Key &key);
};

struct InputsAddress {
  static constexpr std::string_view name = "inputs.address";
  static constexpr std::uint32_t version = 11;  // 3: functions' context; 4: not inside debug-info variables; 5: Thumb bodies kept;
                                                // 6: context_reach; 7: ARM functions' context; 8: call fixups by name; 9: locals' source types;
                                                // 10: mutability edits; 11: demangled functions (docs/demangle.md)
  using Key = AddressKey;
  using Value = AddressFacts;
  static Value compute(facts::QueryContext &ctx, const Key &key);
};

// The mutability the listing's edits give one address (MUTABILITY,
// docs/listing-edit.md): nullopt where none does (the memory map decides).
struct MutabilityAt {
  static constexpr std::string_view name = "inputs.mutability";
  static constexpr std::uint32_t version = 1;
  using Key = AddressKey;
  using Value = std::optional<lift::Mutability>;
  static Value compute(facts::QueryContext &ctx, const Key &key);
};

struct InputsType {
  static constexpr std::string_view name = "inputs.type";
  static constexpr std::uint32_t version = 1;
  using Key = std::pair<std::string, std::uint64_t>;  // (program, type id)
  using Value = std::optional<lift::DecompElement>;
  static Value compute(facts::QueryContext &ctx, const Key &key);
};

}  // namespace q

void RegisterInputQueries(facts::Engine &engine);

// The decompiler's lookups for one program, through the query context of
// the decompilation they serve, so each becomes a dependency; assertions
// are laid over the program's facts (renames, and asserted types other than
// the debug info's own).
class QueryLookup final : public RunLookup {
 public:
  // For decompiling the function at `entry` of `program`: functions with
  // the signature Ghidra's Decompiler Parameter ID committed for them, as
  // far as it is published (param_id.h). With `param_id_deps`, for the
  // analyzer's own decompilation of `entry` instead: only those functions
  // (and thunks of them) have their commits, computed (analysis.param_id).
  QueryLookup(facts::QueryContext &ctx, std::string program, std::uint64_t entry,
              const std::vector<std::uint64_t> *param_id_deps = nullptr);

  // What the inputs could not give the decompiler as asserted (a calling
  // convention the compiler spec has no prototype model for), for the
  // function's warnings.
  const std::set<std::string> &warnings() const { return warnings_; }

  // What a variable's type needs from the function's own decompilation
  // before it can be committed: the parameters it found, where a parameter
  // is typed but nothing locked the prototype (Ghidra's
  // commitParamsToDatabase before updateDBVariable); the hash a temporary
  // is mapped by. needs_found() after a run: run again with commit_found().
  struct Found {
    std::optional<std::vector<lift::ParamFacts>> params;
    std::map<std::string, std::pair<std::uint64_t, std::uint64_t>> hashes;  // storage key -> (hash, address)
  };
  bool needs_found() const { return needs_found_; }
  void commit_found(Found found) { found_ = std::move(found); }

  void freeze(bool frozen) override { frozen_ = frozen; }
  std::vector<std::uint64_t> take_late() override { return std::exchange(late_, {}); }
  bool says_anything(std::uint64_t a) override;
  void prefetch(std::uint64_t a) override { eager_.insert(a); }
  std::vector<std::uint64_t> touched() const override { return {touched_.begin(), touched_.end()}; }

  const lift::FunctionFacts *function_at(std::uint64_t entry) override;
  std::optional<Body> body_containing(std::uint64_t a) override;
  const lift::DataFacts *data_containing(const std::string &space, std::uint64_t a) override;
  const lift::ExternalRefFacts *external_at(const std::string &space, std::uint64_t a) override;
  const lift::LabelFacts *label_at(const std::string &space, std::uint64_t a) override;
  std::optional<std::string> code_label_at(const std::string &space, std::uint64_t a) override;
  std::optional<lift::Mutability> block_at(const std::string &space, std::uint64_t a) override;
  const lift::DecompElement *type(std::uint64_t id) override;
  std::vector<const lift::CommentFacts *> comments(std::uint64_t entry) override;
  std::vector<std::pair<std::uint64_t, std::string>> flow_overrides(std::uint64_t entry) override;
  std::vector<lift::TrackedFacts> tracked(std::uint64_t entry) override;
  void reset() override;
  std::string chunk(std::uint64_t index, std::string bytes) override;
  std::optional<lift::FunctionFacts> call_prototype(const std::string &hash) override;

 private:
  const AddressFacts *address(std::uint64_t a);
  const inputs::FunctionInputs *function_slice(std::uint64_t entry);
  const SymbolInfo *symbol(std::uint64_t a);
  const lift::FunctionFacts *with_overlay(const lift::FunctionFacts &f);
  void commit_variable_types(lift::FunctionFacts &out);
  // The type an asserted hash names, encoded for the decompiler; its
  // definitions join the run's overlay types. Null if it isn't known.
  struct Asserted {
    types::TypeStore store;
    types::TypeId id;
  };
  std::unique_ptr<Asserted> asserted_type(const std::string &hash);
  bool prototype_from(const Asserted &t, lift::FunctionFacts &out, bool warn);
  // An analysis-rank prototype (a virtual method's, docs/pe.md): it types
  // `this` alone, in the prototype's calling convention, and leaves the
  // other parameters to whatever else gives them (inference, Decompiler
  // Parameter ID, the decompiler).
  void apply_this(lift::FunctionFacts &out, const Asserted &t);
  // Whether a parameter is in the register `this` is passed in (RCX, ECX
  // under __thiscall, x0).
  bool in_this_register(const lift::ParamFacts &p);
  // Whether a BindTypeName changes what `hash` reaches (types.resolved
  // differs from types.closure).
  bool rebound(const std::string &hash);
  const inputs::DataOrg &data_org();
  // revkit::infer's prototype for a function, if the program has one staged.
  std::optional<infer::Prototype> inferred(std::uint64_t entry);
  // The signature Ghidra's Decompiler Parameter ID commits for a function
  // as this lookup sees it (published, or a dependency's), if any.
  std::optional<lift::CommittedSignature> param_id(std::uint64_t entry);
  infer::DataOrg InferOrg();

  // Runs `get` through the context; a failure is kept and stops the run.
  template <class F>
  auto query(F &&get) -> decltype(get());
  bool blocked(std::uint64_t a);  // frozen and not prefetched: recorded late

  facts::QueryContext *ctx_;
  std::string program_;
  std::uint64_t entry_;
  const std::vector<std::uint64_t> *param_id_deps_ = nullptr;
  bool frozen_ = false;
  std::set<std::uint64_t> eager_;
  std::vector<std::uint64_t> late_;
  std::set<std::uint64_t> touched_;
  // This run's answers (the Refs keep the values alive).
  std::map<std::uint64_t, facts::Ref<AddressFacts>> addresses_;
  std::map<std::uint64_t, facts::Ref<inputs::FunctionInputs>> functions_;
  std::map<std::uint64_t, facts::Ref<SymbolInfo>> symbols_;
  std::map<std::uint64_t, facts::Ref<std::optional<lift::DecompElement>>> types_;
  std::map<const void *, const lift::FunctionFacts *> overlaid_;
  std::deque<lift::FunctionFacts> owned_functions_;
  std::deque<lift::DataFacts> owned_data_;
  std::deque<lift::LabelFacts> owned_labels_;
  std::map<std::uint64_t, lift::DecompElement> overlay_types_;  // types asserted types reach
  std::optional<inputs::DataOrg> org_;
  bool needs_found_ = false;
  std::optional<Found> found_;
  // The compiler spec's prototype model names (lift::prototype_models,
  // read before any run: reading a spec takes Ghidra's globals).
  const std::set<std::string> *models_ = nullptr;
  std::set<std::string> warnings_;
  std::optional<std::pair<std::uint64_t, int>> this_register_;  // offset, size; size 0: none
};

}  // namespace revkit::backend
