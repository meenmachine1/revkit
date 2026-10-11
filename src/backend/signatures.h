// BSim signatures (F5) of the image backend's programs, for binary diffing
// (docs/diff.md): fact-store queries computed lazily (when a diff's residue
// asks) or in the background (SignatureJob), memoized per function.
//
//   diff.signature_inputs  what a signature bundle is told about one       <- inputs.address, inputs.sets
//                          address: inputs.address under the signature
//                          profile (inputs/profile.h: no names, types,
//                          prototypes or comments beyond imports;
//                          analysis's no-return set)
//   diff.signature         one function's BSim feature vector (decompd      <- analysis.function, FLOW_OVERRIDE
//                          mode signature, in a worker): FunctionSignature,    keys in its body, inputs.image,
//                          failures included                                  decompiler.options, and
//                                                                              diff.signature_inputs for every
//                                                                              address the decompiler asked
//
// Neither reads names, types, prototypes or comments the user asserted, nor
// the debug info's: renaming or retyping anything recomputes no signature
// (the slices it reads validate by fingerprint), and a program with debug
// info signs as its stripped twin does. A computation the caller cancels
// (DecompileLimitsScope's `cancelled`) throws DecompileStoppedError and is
// never memoized; a decompiler failure (crash, deadline, varnode bound) is
// the memoized value, retried when the bundle's facts or the decompiler
// build change.
#pragma once

#include "decompiler.h"
#include "model.h"

#include "revkit/decompd/signature.h"
#include "revkit/facts/engine.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace revkit::backend {

// One address as a signature bundle sees it (AddressFacts under the profile).
struct SignatureAddress {
  std::optional<lift::FunctionFacts> starts;    // stripped
  std::optional<lift::FunctionFacts> contains;  // stripped
  std::uint64_t body_first = 0, body_last = 0;
  std::optional<lift::ExternalRefFacts> external;  // its function stripped
  std::optional<lift::Mutability> block;
  std::vector<lift::TrackedFacts> tracked;

  void encode(facts::Encoder &e) const;
  static SignatureAddress decode(facts::Decoder &d);
};

// diff.signature's key: settings 0 is the program's own
// (decompd::default_signature_settings: 0x49 for 32- and 64-bit
// languages); a diff of programs of different pointer sizes asks for
// 0x4d on both (lshweights_nosize.xml).
struct SignatureKey {
  std::string program;
  std::uint64_t entry = 0;
  std::uint32_t settings = 0;

  void encode(facts::Encoder &e) const;
  static SignatureKey decode(facts::Decoder &d);
  friend auto operator<=>(const SignatureKey &, const SignatureKey &) = default;
};

namespace q {

struct SignatureInputs {
  static constexpr std::string_view name = "diff.signature_inputs";
  static constexpr std::uint32_t version = 1;
  using Key = std::pair<std::string, std::uint64_t>;
  using Value = SignatureAddress;
  static Value compute(facts::QueryContext &ctx, const Key &key);
};

struct DiffSignature {
  static constexpr std::string_view name = "diff.signature";
  static constexpr std::uint32_t version = 2;  // 2: patched bytes through patch.page
  using Key = SignatureKey;
  using Value = decompd::FunctionSignature;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::size_t weight(const Value &v);
};

}  // namespace q

void RegisterSignatureQueries(facts::Engine &engine);

// Signs functions of one program at a snapshot in the background, on its
// own threads (each run in a decompiler worker of the program's pool), as
// diff.signature memos: a later diff, or another job, reads them. Results
// are the same whatever the thread count. cancel() stops the runs in flight
// (their workers are stopped; nothing partial is memoized) and the rest.
class SignatureJob {
 public:
  struct Options {
    unsigned threads = 4;
    std::uint32_t settings = 0;
  };
  SignatureJob(facts::Snapshot snapshot, std::string program, std::vector<std::uint64_t> entries, Options options);
  ~SignatureJob();  // cancels and joins
  SignatureJob(const SignatureJob &) = delete;
  SignatureJob &operator=(const SignatureJob &) = delete;

  void cancel();
  bool cancelled() const { return cancelled_.load(); }
  // Functions finished (signed, failed or skipped), and in all.
  std::size_t done() const { return done_.load(); }
  std::size_t total() const { return entries_.size(); }
  // Blocks until every function is done or the job was cancelled; returns
  // what was computed, by entry. Rethrows a lookup failure (not a
  // decompiler failure: those are values).
  std::map<std::uint64_t, decompd::FunctionSignature> wait();

 private:
  void work();

  facts::Snapshot snapshot_;
  std::string program_;
  std::vector<std::uint64_t> entries_;
  Options options_;
  std::atomic<bool> cancelled_{false};
  std::atomic<std::size_t> next_{0}, done_{0};
  std::mutex mu_;
  std::map<std::uint64_t, decompd::FunctionSignature> results_;
  std::exception_ptr error_;
  std::vector<std::thread> threads_;
};

}  // namespace revkit::backend
