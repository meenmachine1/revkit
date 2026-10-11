// Decompiling bundles: what a decompiler worker process runs (rk-decompd
// --worker), and what the in-process debugging mode and the repro tool
// (rk-decompd --bundle) run in the calling process.
//
// A Runner keeps a few sessions: one decompiler architecture per arch key
// (Bundle::arch_key: mode, language, image shape, naming options), reused
// across bundles. Each mode registers a session factory; lift's c_text is
// built in, the image backend registers tokens and revkit::infer observe.
#pragma once

#include "revkit/decompd/bundle.h"

#include <functional>
#include <list>
#include <memory>
#include <string>

namespace revkit::decompd {

// One decompiler architecture serving bundles of one arch key.
class Session {
 public:
  virtual ~Session() = default;
  // Decompiles `b` (whose arch key is this session's) into `out`: payload,
  // stopped, misses, asked, varnodes. The runner handles joins and timing.
  virtual void run(const Bundle &b, const Limits &limits, RunResult &out) = 0;
  // The architecture may be left mid-analysis (a stopped run): rebuild.
  virtual bool spoiled() const = 0;
  virtual lift::ImageArchitecture &architecture() = 0;
};

using SessionFactory = std::function<std::unique_ptr<Session>(const Bundle &)>;
// A mode's payload as text, for rk-decompd --bundle; sets `ok` to whether
// the decompiler produced output.
using PayloadPrinter = std::function<std::string(std::string_view payload, bool &ok)>;
// Registers a mode (replacing any). Thread-safe.
void register_mode(Mode mode, SessionFactory factory, PayloadPrinter printer = {});
bool mode_registered(Mode mode);
std::string print_payload(Mode mode, std::string_view payload, bool &ok);

// A synthetic loader::Image for a bundle: format, pointer size and blocks,
// no bytes (they come from BundleMemory).
std::shared_ptr<const loader::Image> bundle_image(const Bundle &b);

// A bundle's bytes as an ImageArchitecture reads them, recording chunks it
// doesn't have as misses. Point it at the bundle being decompiled.
class BundleMemory final : public lift::MemorySource {
 public:
  void set(const Bundle *b) {
    bundle_ = b;
    missed_.clear();
  }
  std::size_t read(std::uint64_t addr, std::span<std::uint8_t> out) override;
  const std::set<std::uint64_t> &missed() const { return missed_; }

 private:
  const Bundle *bundle_ = nullptr;
  std::set<std::uint64_t> missed_;
};

class Runner {
 public:
  // Decodes and decompiles one bundle. Never throws for a bad bundle or a
  // decompiler error (RunResult::ran / error say so).
  RunResult run(std::string_view bundle_bytes, const Limits &limits);
  RunResult run(const Bundle &b, const Limits &limits);
  // Builds the session `b` needs ahead of the first run.
  void warm(const Bundle &b);

 private:
  struct Entry {
    std::string key;
    std::unique_ptr<Session> session;
    std::vector<lift::JoinFacts> joins;  // records made since the session was built
    std::uint64_t next_join = 0;         // join-space offset of the next record
  };
  Entry &session_for(const Bundle &b);
  Entry build(const Bundle &b);
  std::list<Entry> sessions_;  // most recently used first
};

// The worker's resident memory: total and anonymous (not file-backed), bytes.
std::pair<std::uint64_t, std::uint64_t> resident_memory();

}  // namespace revkit::decompd
