// Ghidra's Decompiler Parameter ID in decompiler workers: mode param_id
// (a session decompiling as DecompilerParameterIdCmd's DecompInterface
// does, returning the lift::CommittedSignature), the lookup a function of
// the plan decompiles under (its dependencies' signatures committed,
// nothing else), and rk-lift's driver over a whole program
// (param_id_functions). The image backend runs the same mode per function
// from its analysis.param_id query.
#pragma once

#include "revkit/decompd/batch.h"
#include "revkit/decompd/lift_mode.h"
#include "revkit/inputs/param_id.h"
#include "revkit/lift/param_id.hh"

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace revkit::decompd {

// The decompiler timeout DecompilerFunctionAnalyzer uses by default
// ("Analysis Decompiler Timeout (sec)").
inline constexpr double kParamIdTimeoutSeconds = 60;

// Mode param_id's session, and its payload.
std::unique_ptr<Session> make_param_id_session(const Bundle &b);
std::string encode_signature(const lift::CommittedSignature &s);
lift::CommittedSignature decode_signature(std::string_view bytes);
// The payload as text (rk-decompd --bundle).
std::string print_signature(std::string_view payload, bool &ok);
// A finished run's signature: the payload's, or failed with why.
lift::CommittedSignature signature_of(const BundledRun &run, const std::string &unavailable = {});

// `base` with committed signatures over the functions in `committed` (by
// entry) and the thunks of them: what a function of the plan sees while
// it is decompiled. Each run's facts are its own.
class CommittedLookup final : public lift::FactLookup {
 public:
  CommittedLookup(lift::FactLookup &base, const std::map<std::uint64_t, lift::CommittedSignature> &committed,
                  const std::map<std::uint64_t, std::optional<std::uint64_t>> &thunks)
      : base_(base), committed_(committed), thunks_(thunks) {}

  const lift::FunctionFacts *function_at(std::uint64_t entry) override;
  std::optional<Body> body_containing(std::uint64_t a) override;
  const lift::DataFacts *data_containing(const std::string &space, std::uint64_t a) override {
    return base_.data_containing(space, a);
  }
  const lift::ExternalRefFacts *external_at(const std::string &space, std::uint64_t a) override {
    return base_.external_at(space, a);
  }
  const lift::LabelFacts *label_at(const std::string &space, std::uint64_t a) override {
    return base_.label_at(space, a);
  }
  std::optional<std::string> code_label_at(const std::string &space, std::uint64_t a) override {
    return base_.code_label_at(space, a);
  }
  std::optional<lift::Mutability> block_at(const std::string &space, std::uint64_t a) override {
    return base_.block_at(space, a);
  }
  const lift::DecompElement *type(std::uint64_t id) override { return base_.type(id); }
  std::vector<std::uint64_t> all_types() override { return base_.all_types(); }
  std::vector<const lift::CommentFacts *> comments(std::uint64_t entry) override { return base_.comments(entry); }
  std::vector<std::pair<std::uint64_t, std::string>> flow_overrides(std::uint64_t entry) override {
    return base_.flow_overrides(entry);
  }
  std::vector<lift::TrackedFacts> tracked(std::uint64_t entry) override { return base_.tracked(entry); }
  void reset() override { base_.reset(); }

 private:
  const lift::FunctionFacts *overlay(const lift::FunctionFacts *f);

  lift::FactLookup &base_;
  const std::map<std::uint64_t, lift::CommittedSignature> &committed_;
  const std::map<std::uint64_t, std::optional<std::uint64_t>> &thunks_;
  std::map<const lift::FunctionFacts *, const lift::FunctionFacts *> done_;
  std::deque<lift::FunctionFacts> owned_;
};

struct ParamIdStats {
  std::size_t functions = 0;  // the plan's nodes
  std::size_t decompiled = 0, committed = 0, failed = 0, skipped = 0;
  std::size_t rounds = 0;     // the dependency graph's depth
  double seconds = 0;         // wall
  double run_ms = 0;          // the workers' runs, summed
  std::vector<Failure> failures;
};

struct ParamIdOptions {
  double timeout_seconds = kParamIdTimeoutSeconds;
  std::uint64_t max_varnodes = 0;
};

// Decompiles every node of `plan` in workers, dependencies first and in
// parallel (config.threads), each under `config`'s facts with its
// dependencies' committed signatures, and returns every node's signature.
// Deterministic for any thread count: a node sees exactly its
// dependencies' results (save for decompilations that time out).
std::map<std::uint64_t, lift::CommittedSignature> param_id_functions(const lift::DecompileConfig &config,
                                                                     const inputs::ParamIdPlan &plan,
                                                                     const ParamIdOptions &options = {},
                                                                     ParamIdStats *stats = nullptr,
                                                                     PoolOptions pool_options = default_pool_options());

}  // namespace revkit::decompd
