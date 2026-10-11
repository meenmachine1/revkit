// Decompiling through workers: one function (run_bundled: build, run, add
// what the worker missed, run again if an answer it guessed was wrong),
// and a whole program (decompile_functions, rk-lift's decompilation: the
// memory-aware scheduler of lift::decompile_functions, with workers'
// memory counted).
#pragma once

#include "revkit/decompd/builder.h"
#include "revkit/decompd/pool.h"
#include "revkit/lift/decompile.hh"

#include <array>
#include <atomic>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace revkit::decompd {

// Where run_bundled gets bundles from: a builder over the parent's facts.
class BundleSource {
 public:
  virtual ~BundleSource() = default;
  virtual Bundle bundle() = 0;
  // Adds the answers to `misses`; true if any differs from what the
  // worker assumed (the run must be repeated).
  virtual bool fill(const std::vector<Miss> &misses) = 0;
};

struct BundledRun {
  Outcome outcome;             // the last run
  std::optional<Failure> failure;  // failure_of(outcome), completed
  std::string bundle;          // the bundle the last run decompiled (encoded)
  std::string hash;            // its hash
  std::string arch_key;
  unsigned runs = 0;           // decompilations (1 + reruns after misses)
  std::size_t misses = 0;      // queries missed, over all runs
  bool unresolved = false;     // still missing answers after the last run allowed
  std::array<std::size_t, 8> miss_kinds{};  // by Miss::Kind, over all runs
};

// Runs `source`'s bundle on `pool` until the worker's guesses for what the
// bundle lacked were right (at most `max_runs` times).
BundledRun run_bundled(WorkerPool &pool, BundleSource &source, const Limits &limits, std::uint64_t function,
                       unsigned max_runs = 4, const std::function<bool()> &cancelled = {});

// LiftBundleBuilder as a BundleSource.
class LiftSource final : public BundleSource {
 public:
  explicit LiftSource(LiftBundleBuilder &b) : b_(b) {}
  Bundle bundle() override { return b_.bundle(); }
  bool fill(const std::vector<Miss> &m) override { return b_.fill(m); }

 private:
  LiftBundleBuilder &b_;
};

struct BatchStats : lift::DecompileStats {
  std::size_t bundles = 0;       // functions decompiled through bundles
  std::size_t reruns = 0;        // runs repeated after misses
  std::size_t missed = 0;        // functions whose first bundle missed something
  std::size_t miss_queries = 0;  // queries missed, in all
  std::size_t miss_changed = 0;  // functions where a missed answer differed (rerun needed)
  std::size_t unresolved = 0;
  std::vector<std::uint64_t> unresolved_functions;
  std::array<std::size_t, 8> miss_kinds{};  // queries missed, by Miss::Kind
  std::size_t bundle_bytes = 0;  // encoded, summed
  double build_ms = 0;           // assembling bundles (parent CPU, summed over threads)
  double ipc_ms = 0;             // round trips minus the workers' run time
  double run_ms = 0;             // the workers' runs
  PoolStats pool;
  std::vector<Failure> failures;
  std::map<std::string, std::string> failed_bundles;  // by hash: the bundles failures were observed on
  std::size_t peak_workers_rss = 0;  // workers' anonymous memory, sampled
  std::size_t peak_total_rss = 0;    // the parent's and the workers', sampled every 100 ms (with a budget)
  std::size_t evicted = 0;           // runs stopped to stay within the budget, then run alone
};

// What rk-lift decompiles a program with: config as for
// lift::decompile_functions (inputs, lookup, naming, limits, threads,
// in_order, memory budget), each function decompiled in a worker. With
// in_order and one thread, functions run in address order with the join
// records chained from one to the next, as one in-process decompiler
// would have them (Ghidra's sequence).
std::vector<lift::DecompileResult> decompile_functions(
    const lift::DecompileConfig &config, const std::vector<std::uint64_t> &entries, BatchStats *stats = nullptr,
    const std::function<void(std::size_t index, lift::DecompileResult &result)> &on_result = {},
    PoolOptions pool_options = default_pool_options());

// The block list InputsLookup answers block_at from: the inputs' memory,
// else the image's blocks.
std::vector<lift::BlockFacts> lookup_blocks(const lift::DecompilerInputs &inputs, const loader::Image &image);

// The spaces a program's inputs name (the default space "" first).
std::vector<std::string> input_spaces(const lift::DecompilerInputs &inputs);

// "decompiler crashed (SIGSEGV)", "decompiler timed out", ... for a failure.
std::string describe(const Failure &f);

// Failures by kind, one line per function, for a batch tool's summary.
std::string failure_summary(const std::vector<Failure> &failures);

}  // namespace revkit::decompd
