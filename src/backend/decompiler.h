// Ghidra's decompiler producing revkit.v1 token streams, in decompiler
// worker processes (revkit::decompd).
//
// A decompilation is assembled into a self-contained bundle in the daemon:
// everything the decompiler will ask (revkit::inputs' facts, as rk-lift
// --analyze --decompile tells them, read through a RunLookup the caller
// backs with fact-store queries, QueryLookup in own_inputs.h), the bytes it
// reads, the function's hooks. A worker (rk-decompd) decompiles it with a
// lift::InputDecompiler whose printer records typed tokens (mode tokens,
// registered by RegisterDecompdModes) and sends back a DecompileOutput.
// What the worker missed is looked up and the run repeated if it mattered
// (decompd/bundle.h), so the lookups made are the decompilation's
// dependencies and its output is the caller's revision's.
//
// A worker that crashes, runs past its hard deadline or out of memory
// costs that decompilation only: it comes back as a DecompileOutput with a
// failure, memoized like any output (retried when the bundle or the
// decompiler build changes, or once with a longer deadline: Escalate).
#pragma once

#include "model.h"

#include "revkit/decompd/batch.h"
#include "revkit/decompd/builder.h"
#include "revkit/decompd/pool.h"
#include "revkit/decompd/signature.h"
#include "revkit/inputs/inputs.h"
#include "revkit/lift/decompile.hh"
#include "revkit/lift/param_id.hh"
#include "revkit/loader/image.hh"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace revkit::backend {

// A program's decompiler settings (AssertionBody.decompiler_settings): a
// NOTE at address 0 with this sub, its value the serialized
// pb::DecompilerSettings.
inline constexpr std::string_view kDecompilerSettingsTag = "revkit:decompiler-settings";
// The source-shape options they ask for (lift::SourceShape::own() but
// where they say otherwise).
lift::SourceShape ShapeFromSettings(const pb::DecompilerSettings &s);

// What an instance's architecture is built with (inputs.image).
struct ImageInputs {
  std::string address_prefix;
  std::vector<inputs::Patch> patches;
  std::vector<inputs::Patch> synthesized_memory;
  std::vector<lift::BlockFacts> memory;

  void encode(facts::Encoder &e) const;
  static ImageInputs decode(facts::Decoder &d);
  friend bool operator==(const ImageInputs &, const ImageInputs &) = default;
};

// The facts one run reads. Lookups made while printing happen under
// Ghidra's shared global lock and must not build a SLEIGH engine: a lookup
// frozen for printing answers what it was asked before, records anything
// new (take_late()) and the pool checks those after the run, running again
// with them prefetched when they say something.
class RunLookup : public lift::FactLookup {
 public:
  virtual void freeze(bool frozen) = 0;
  virtual std::vector<std::uint64_t> take_late() = 0;
  // Whether the facts at `a` say anything (unfrozen).
  virtual bool says_anything(std::uint64_t a) = 0;
  // Makes `a` answerable while frozen.
  virtual void prefetch(std::uint64_t a) = 0;
  // Every address looked up, sorted.
  virtual std::vector<std::uint64_t> touched() const = 0;
  // The bytes of one decompd::kChunk-sized chunk as the run reads them:
  // `bytes` are the program's; the image backend lays the program's
  // patches over them (docs/patching.md).
  virtual std::string chunk(std::uint64_t /*index*/, std::string bytes) { return bytes; }
  // The prototype a call's signature override names by a function type's
  // hash (DecompileInputs::call_signatures), for the decompiler; nullopt
  // if the type isn't known or isn't a function's.
  virtual std::optional<lift::FunctionFacts> call_prototype(const std::string & /*hash*/) { return std::nullopt; }
  // A lookup that failed (not a decompiler failure: a cancelled query, say).
  // The run stops and the pool rethrows it.
  std::exception_ptr failure;
};

// A run the caller cancelled (lift::DecompileLimits::cancelled, a client
// that went away). Thrown out of the decompile query so it is never
// memoized. Runs over their timeout or varnode bound are failures
// (DecompileOutput::failure) instead.
struct DecompileStoppedError : std::runtime_error {
  lift::DecompileStop reason;
  DecompileStoppedError(lift::DecompileStop r, const std::string &why) : std::runtime_error(why), reason(r) {}
};

// One function's BSim signature request (signatures.h): its body and the
// user's flow overrides in it, the rest from the signature lookup.
struct SignatureRequest {
  std::uint64_t entry = 0;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> body;  // inclusive
  std::vector<std::pair<std::uint64_t, std::string>> flow_overrides;
  decompd::SignatureOptions options;
};

// The limits decompilations on this thread run under while it is alive
// (the request being served), instead of the pool's defaults.
class DecompileLimitsScope {
 public:
  explicit DecompileLimitsScope(lift::DecompileLimits limits);
  ~DecompileLimitsScope();
  DecompileLimitsScope(const DecompileLimitsScope &) = delete;
  DecompileLimitsScope &operator=(const DecompileLimitsScope &) = delete;
  static const lift::DecompileLimits *current();

 private:
  lift::DecompileLimits limits_;
  const lift::DecompileLimits *outer_;
};

class DecompilerPool {
 public:
  struct Config {
    std::shared_ptr<const loader::Image> image;
    std::string language_id;  // with compiler: "x86:LE:64:default:gcc"
    // Workers to decompile in, shared by every program of a backend; null:
    // a pool of the pool's own with `max_instances` workers.
    std::shared_ptr<decompd::WorkerPool> workers;
    unsigned max_instances = 2;
    // Bounds on a run when the thread has no DecompileLimitsScope.
    lift::DecompileLimits limits;
    // StopParamId's flag, shared with other pools of one program (its
    // memory-map variants); null: the pool's own.
    std::shared_ptr<std::atomic<bool>> param_id_stopped;
  };

  explicit DecompilerPool(Config config);
  ~DecompilerPool();
  DecompilerPool(const DecompilerPool &) = delete;
  DecompilerPool &operator=(const DecompilerPool &) = delete;

  // Decompiles in a worker. Never throws for decompiler failures: an error
  // the decompiler reports comes back as a function whose body is an error
  // comment, with the message in `warnings`; a worker that died, timed out
  // or ran out of memory, likewise, with DecompileOutput::failure set. A
  // failed lookup is rethrown; a cancelled run throws DecompileStoppedError.
  // `image` is what the program's architecture is built with.
  DecompileOutput Decompile(const DecompileInputs &inputs, const ImageInputs &image, RunLookup &lookup,
                            const lift::SourceShape &shape = lift::SourceShape::own());

  // Decompiles as Ghidra's Decompiler Parameter ID does (worker mode
  // param_id) and returns what it would commit (param_id.h). Failures are
  // values (nothing committed); a failed lookup is rethrown, a cancelled
  // run (`cancelled`) throws DecompileStoppedError. The timeout is the
  // analyzer's (60 s) unless `timeout_seconds` says otherwise.
  lift::CommittedSignature ParamId(const DecompileInputs &inputs, const ImageInputs &image, RunLookup &lookup,
                                   double timeout_seconds = 0);
  // BSim's features of a function (worker mode signature) from `lookup`,
  // which answers under the signature profile. Failures are values; a
  // failed lookup is rethrown; a run the thread's DecompileLimitsScope
  // cancels throws DecompileStoppedError. Its limits (or the pool's) bound
  // the run.
  decompd::FunctionSignature Signature(const SignatureRequest &request, const ImageInputs &image, RunLookup &lookup);

  // Stops param-id runs in flight and to come (ImageBackend's shutdown).
  void StopParamId() { param_id_stopped_->store(true); }
  // What a pool for another image of the same program shares with this one
  // (a memory-map variant, Program::WithMemory): its workers and stop flag.
  Config SharedConfig(std::shared_ptr<const loader::Image> image) const;
  // Parks the prediction engines once they have been unused for `idle_for`
  // (docs/memory.md "SLEIGH engines").
  std::size_t ParkIdleEngines(std::chrono::steady_clock::duration idle_for) { return lifters_.park_idle(idle_for); }

  // Decompiles a timed-out run's bundle again with a longer timeout (the
  // one escalation a timeout allows). The result's failure, if any, is
  // marked escalated.
  DecompileOutput Escalate(const DecompileOutput &failed, double timeout_seconds);

  // Starts a worker and builds the architecture `image` needs ahead of the
  // first Decompile (best effort).
  void Warm(const ImageInputs &image);

  // Workers started so far (for tests and benchmarks).
  unsigned instances_created() const;

 private:
  std::shared_ptr<const decompd::ProgramImage> ProgramFor(const ImageInputs &image);
  DecompileOutput Finish(std::uint64_t entry, decompd::BundledRun &run, RunLookup *lookup);
  static void Fail(pb::DecompiledFunction &f, const std::string &message);

  Config config_;
  std::shared_ptr<decompd::WorkerPool> workers_;
  mutable std::mutex mu_;
  std::optional<ImageInputs> program_key_;
  std::shared_ptr<const decompd::ProgramImage> program_;
  decompd::LifterPool lifters_;  // for prediction
  std::shared_ptr<std::atomic<bool>> param_id_stopped_;
};

// Registers the token printer's worker mode (decompd::Mode::tokens) with
// revkit::decompd; rk-decompd and the in-process debugging mode call it.
void RegisterDecompdModes();

}  // namespace revkit::backend
