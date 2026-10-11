// BSim signatures in decompiler workers: mode signature (docs/decompd.md,
// docs/diff.md).
//
// A worker runs the function through the decompiler's "normalize" action
// group with no printer, then BSim's GraphSigManager over the result, as
// Ghidra's SignaturesAt does (signature_ghidra.cc): the payload is the
// function's feature vector (sorted 32-bit hashes, simpleSignature's
// <sig> values) and, on request, the features rooted in each basic block
// (what debugSignature describes), for block correlation.
//
// Signature bundles are assembled under the inputs' signature profile
// (inputs/profile.h): no names, types, prototypes or comments beyond
// imports, so a user's edits never change them. The profile's id and the
// signature settings travel in the bundle (SignatureOptions, Bundle::extra),
// so they are part of its hash.
//
// GraphSigManager reads its settings from a process-wide static
// (SigManager::settings) in its constructor and nowhere else: a session
// sets it and constructs its manager under one mutex, so workers (and
// in-process sessions on several threads) can serve bundles with different
// settings.
#pragma once

#include "revkit/decompd/batch.h"
#include "revkit/decompd/runner.h"
#include "revkit/facts/codec.h"
#include "revkit/inputs/profile.h"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace revkit::decompd {

// BSim's settings words (third_party/bsim): the 64- and 32-bit weight
// tables are for 0x49 (SIG_COLLAPSE_INDNOISE | SIG_DONOTUSE_CONST), the
// size-independent one for 0x4d (also SIG_COLLAPSE_SIZE).
inline constexpr std::uint32_t kSignatureSettings = 0x49;
inline constexpr std::uint32_t kSignatureSettingsNoSize = 0x4d;

// What a signature run is asked for: part of the bundle.
struct SignatureOptions {
  std::uint32_t settings = kSignatureSettings;
  bool blocks = false;  // also the features of each basic block
  inputs::SignatureProfile profile;

  void encode(facts::Encoder &e) const;
  static SignatureOptions decode(facts::Decoder &d);
  friend bool operator==(const SignatureOptions &, const SignatureOptions &) = default;
};

// The features rooted in one basic block: its control-flow features
// (BlockSignature), stand-alone copies (CopySignature), and the data-flow
// features (VarnodeSignature) of values its operations define.
struct BlockFeatures {
  std::int32_t index = 0;   // the block's index in the normalized function
  std::uint64_t start = 0;  // its first instruction
  std::vector<std::uint32_t> features;  // sorted
  friend bool operator==(const BlockFeatures &, const BlockFeatures &) = default;
};

// A function's signature (the mode's payload, and diff.signature's value).
struct FunctionSignature {
  enum class Status : std::uint8_t {
    ok = 0,
    failed = 1,   // the decompiler failed or stopped (detail says why; with a worker failure, `failure`)
    skipped = 2,  // nothing to sign (no function, an import, no body)
  };
  Status status = Status::failed;
  std::string detail;
  std::vector<std::uint32_t> features;  // sorted ascending, repeats kept
  std::vector<BlockFeatures> blocks;    // with SignatureOptions::blocks, by index
  bool unimplemented = false;           // the function has unimplemented instructions
  bool bad_data = false;                // flow ran into bad data
  std::uint32_t settings = 0;
  std::optional<FailureKind> failure;   // a worker failure (crash, deadline, memory)
  std::string bundle_hash;              // the bundle it was computed from (set by the parent)

  bool ok() const { return status == Status::ok; }
  void encode(facts::Encoder &e) const;
  static FunctionSignature decode(facts::Decoder &d);
  friend bool operator==(const FunctionSignature &, const FunctionSignature &) = default;
};

std::unique_ptr<Session> make_signature_session(const Bundle &b);
std::string encode_function_signature(const FunctionSignature &s);
FunctionSignature decode_function_signature(std::string_view bytes);
// The payload as text (rk-decompd --bundle): one hash per line, blocks after.
std::string print_function_signature(std::string_view payload, bool &ok);
// A finished run's signature: the payload's, or failed with why.
FunctionSignature function_signature_of(const BundledRun &run, const std::string &unavailable = {});

// The settings Ghidra signs a program of `language` with when comparing it
// with itself or a program of the same pointer size (the weights file's).
std::uint32_t default_signature_settings(const std::string &language_id);

// Assembles the signature bundle for `entry` from `facts` (the caller's
// lookup, which signature_bundle wraps in the signature profile) and runs
// it on `pool`, adding what the worker missed. Thread-safe as far as
// `facts` is (a lookup over fixed inputs is).
struct SignatureContext {
  const ProgramImage *program = nullptr;
  std::vector<lift::BlockFacts> blocks;
  std::vector<std::string> spaces;
  std::string address_prefix;
  bool default_names = true, default_labels = true, default_extrapop = true;
  LifterPool *lifters = nullptr;
  std::shared_ptr<TypeCache> type_cache;  // over a stable lookup only
  // Analysis's no-return functions (sorted), for the profile
  // (inputs::strip_function); null: the lookup's.
  std::shared_ptr<const std::vector<std::uint64_t>> no_return;
};
FunctionSignature sign_function(WorkerPool &pool, const SignatureContext &ctx, lift::FactLookup &facts,
                                std::uint64_t entry, const SignatureOptions &options, const Limits &limits,
                                BundledRun *run = nullptr, const std::function<bool()> &cancelled = {});

struct SignatureStats {
  std::size_t functions = 0, signed_ok = 0, failed = 0, skipped = 0;
  double seconds = 0;  // wall
  double run_ms = 0;   // the workers' runs, summed
  double build_ms = 0; // assembling bundles, summed
  std::size_t features = 0;  // over the signed functions
  std::vector<Failure> failures;
};

struct SignatureBatchOptions {
  SignatureOptions signature;
  double timeout_seconds = 30;
  std::uint64_t max_varnodes = 0;
  std::shared_ptr<const std::vector<std::uint64_t>> no_return;  // SignatureContext::no_return
};

// Signs `entries` of a program (config: image, language, inputs or lookup,
// naming, threads) in workers, largest first on config.threads threads.
// Results by entry; the same for any thread count.
std::map<std::uint64_t, FunctionSignature> signature_functions(const lift::DecompileConfig &config,
                                                               const std::vector<std::uint64_t> &entries,
                                                               const SignatureBatchOptions &options = {},
                                                               SignatureStats *stats = nullptr,
                                                               PoolOptions pool_options = default_pool_options());

}  // namespace revkit::decompd
