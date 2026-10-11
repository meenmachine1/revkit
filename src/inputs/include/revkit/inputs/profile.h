// Input-assembly profiles: how much of a program's facts a decompilation is
// told.
//
//   full       everything (inputs.h): names, prototypes, types, locals,
//              comments, data, labels, from the loader, analysis, debug
//              info and the user. What decompilations for reading run under.
//   signature  only what shapes the data flow BSim hashes (docs/diff.md):
//              function starts and bodies, no-return, call fixups and
//              decoding context; import and external functions by name,
//              with their library prototypes (optional); flow overrides;
//              tracked registers; memory blocks and their mutability (the
//              read-only ranges the decompiler folds loads from).
//              No user or debug-info names, prototypes, types, locals,
//              comments, data symbols or labels.
//
// Signatures (decompd mode signature) run under `signature`, so that
// renaming or retyping a function changes no other function's signature
// (nor its own), a program with debug info and its stripped twin get the
// same vectors, and the bundles, and so their cache keys, don't change
// with any of those facts. The profile's id is part of every signature
// bundle (decompd/signature.h).
#pragma once

#include "revkit/lift/decompile.hh"

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace revkit::inputs {

enum class Profile : std::uint8_t { full = 0, signature = 1 };

struct SignatureProfile {
  // Import and external functions keep their library prototypes (Ghidra's
  // type archive, assembled by inputs::Options::library_signatures): a pure
  // function of the import's name, so it never churns, and what Ghidra's
  // analysis gives a stripped program too. With them, revkit's vectors are
  // Ghidra's for 98% of functions (x86-64, AArch64; docs/diff.md); without,
  // 89%.
  bool import_prototypes = true;

  // Bumped whenever what the profile keeps changes.
  static constexpr std::uint32_t kVersion = 1;
  // "signature/1/-" or "signature/1/import-prototypes": hashed into bundles.
  std::string id() const;
  friend bool operator==(const SignatureProfile &, const SignatureProfile &) = default;
};

// A function as the signature profile tells it: entry, body, no-return,
// call fixup, inline, context; imports (a code label of their own, as
// "<EXTERNAL>_name", or no entry: a PE import) keep their name and label
// (and with import_prototypes, their prototype); every other function is
// named by its address and has an unknown prototype. With `no_return`
// (sorted entries: what analysis finds, FunctionSets::no_return), a
// function other than an import is no-return exactly when listed: debug
// info's DW_AT_noreturn, which a stripped twin lacks, doesn't count.
lift::FunctionFacts strip_function(const lift::FunctionFacts &f, const SignatureProfile &profile,
                                   const std::vector<std::uint64_t> *no_return = nullptr);
// Whether `f` is an import or external function as strip_function sees it.
bool is_import(const lift::FunctionFacts &f);

// `base` under the signature profile. Owns what it strips until reset().
class SignatureLookup final : public lift::FactLookup {
 public:
  SignatureLookup(lift::FactLookup &base, SignatureProfile profile,
                  std::shared_ptr<const std::vector<std::uint64_t>> no_return = nullptr)
      : base_(base), profile_(profile), no_return_(std::move(no_return)) {}

  const lift::FunctionFacts *function_at(std::uint64_t entry) override;
  std::optional<Body> body_containing(std::uint64_t a) override;
  const lift::DataFacts *data_containing(const std::string &, std::uint64_t) override { return nullptr; }
  const lift::ExternalRefFacts *external_at(const std::string &space, std::uint64_t a) override;
  const lift::LabelFacts *label_at(const std::string &, std::uint64_t) override { return nullptr; }
  std::optional<std::string> code_label_at(const std::string &, std::uint64_t) override { return std::nullopt; }
  std::optional<lift::Mutability> block_at(const std::string &space, std::uint64_t a) override {
    return base_.block_at(space, a);
  }
  // Import prototypes may name types (with import_prototypes).
  const lift::DecompElement *type(std::uint64_t id) override {
    return profile_.import_prototypes ? base_.type(id) : nullptr;
  }
  std::vector<const lift::CommentFacts *> comments(std::uint64_t) override { return {}; }
  std::vector<std::pair<std::uint64_t, std::string>> flow_overrides(std::uint64_t entry) override {
    return base_.flow_overrides(entry);
  }
  std::vector<lift::TrackedFacts> tracked(std::uint64_t entry) override { return base_.tracked(entry); }
  bool stable() const override { return base_.stable(); }
  void reset() override;

 private:
  const lift::FunctionFacts *strip(const lift::FunctionFacts *f);

  lift::FactLookup &base_;
  SignatureProfile profile_;
  std::shared_ptr<const std::vector<std::uint64_t>> no_return_;
  std::map<const lift::FunctionFacts *, const lift::FunctionFacts *> done_;
  std::deque<lift::FunctionFacts> owned_;
  std::map<const lift::ExternalRefFacts *, const lift::ExternalRefFacts *> done_refs_;
  std::deque<lift::ExternalRefFacts> owned_refs_;
};

}  // namespace revkit::inputs
