// Decompiler worker processes.
//
// Ghidra's decompiler runs in rk-decompd worker processes, never in the
// process that owns the facts (rk-daemon, rk-lift, rk-infer): a crash, a
// step that never returns or memory a stopped run leaves behind costs one
// function, not the process. A WorkerPool starts workers on demand (up to
// PoolOptions::workers), hands each request to one, and:
//
// - kills a worker with SIGKILL when a run is past its hard deadline (the
//   cooperative timeout plus a grace period; the cooperative stop inside
//   the decompiler is the graceful path), which covers loops no check in
//   the decompiler reaches;
// - starts workers under an address-space limit (RLIMIT_AS), and replaces
//   one after `recycle_after` functions, when its anonymous memory passes
//   `recycle_rss`, or after a stopped run (malloc keeps what such runs
//   free; a new process gives it back);
// - replaces a worker that died, and reports the run it died in as a
//   Failure (segv, fpe, abort, timeout, oom) with the tail of its stderr.
//
// Transport: one AF_UNIX stream socketpair per worker, length-prefixed
// frames (a request: limits and an encoded bundle; a reply: RunResult),
// and a pipe for its stderr. A bundle is tens of kilobytes and a
// decompilation milliseconds to seconds, so copying through the kernel
// costs microseconds; a socket gives end-of-file when the worker dies and
// poll()s with the deadline, and nothing the worker shares can be left
// half-written or locked by a crash, as shared memory could.
#pragma once

#include "revkit/decompd/bundle.h"

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace revkit::decompd {

// What identifies the decompiler: Ghidra's version and a hash of the
// vendored sources and patches it is built from (third_party/ghidra).
// A failure is retried when this changes.
const std::string &decompiler_build();

enum class FailureKind : std::uint8_t { segv = 1, fpe = 2, abort = 3, timeout = 4, oom = 5 };
const char *failure_kind_name(FailureKind k);

// A decompilation that produced nothing, as a fact: negative-cached by
// (bundle_hash, decompiler_build).
struct Failure {
  std::uint64_t function = 0;
  std::string bundle_hash;
  std::string decompiler_build;
  FailureKind kind = FailureKind::abort;
  double deadline_seconds = 0;  // the deadline in force (0: none)
  std::string stderr_tail;
  std::string detail;  // "SIGSEGV", "killed at the 37.5 s deadline", the cooperative stop's message
  bool escalated = false;  // the one longer-deadline retry a timeout allows was this run

  friend bool operator==(const Failure &, const Failure &) = default;
  void encode(facts::Encoder &e) const;
  static Failure decode(facts::Decoder &d);
};

struct PoolOptions {
  unsigned workers = 4;
  // rk-decompd; empty: $REVKIT_DECOMPD, beside this executable, or the build's.
  std::string worker_path;
  // RLIMIT_AS for each worker, bytes (0: none; ignored in sanitizer builds).
  std::uint64_t memory_limit = std::uint64_t{4} << 30;
  // Replace a worker whose anonymous memory is past this after a run (0: never).
  std::uint64_t recycle_rss = std::uint64_t{768} << 20;
  unsigned recycle_after = 5000;  // functions; 0: never
  // Hard deadline: the cooperative timeout times `grace_factor` plus
  // `grace_seconds`. Runs without a timeout get `no_timeout_deadline` (0: none).
  double grace_factor = 1.25;
  double grace_seconds = 2;
  double no_timeout_deadline = 0;
  // Debugging only: decompile in the calling thread (under gdb), no workers.
  bool in_process = false;
};

// The pool's defaults, with REVKIT_DECOMPILE_IN_PROCESS=1 turning on
// in_process (for gdb) and REVKIT_DECOMPD naming the worker.
PoolOptions default_pool_options();

struct Outcome {
  std::optional<RunResult> result;  // the worker answered (its run may have stopped cooperatively)
  std::optional<Failure> failure;   // it died or was killed: kind, deadline, stderr (failure_of() completes it)
  bool cancelled = false;           // the caller cancelled: the worker was stopped
  bool evicted = false;             // stopped to stay within memory (evict_largest): run it again
  double round_trip_ms = 0;         // sending, waiting and receiving
};

struct PoolStats {
  std::uint64_t runs = 0, spawned = 0, recycled = 0, crashed = 0, killed = 0, evicted = 0;
  double ipc_ms = 0;  // round trips minus the workers' own run time
};

class WorkerPool {
 public:
  explicit WorkerPool(PoolOptions options = default_pool_options());
  ~WorkerPool();
  WorkerPool(const WorkerPool &) = delete;
  WorkerPool &operator=(const WorkerPool &) = delete;

  // Decompiles one encoded bundle; blocks until it is done or failed. Safe
  // from several threads (at most `workers` run at once). `affinity`
  // prefers a worker that last ran the same key (Bundle::arch_key), whose
  // architecture is built. Throws only if no worker can be started.
  // `cancelled`, if given, is polled while the worker runs; true stops it
  // (Outcome::cancelled).
  Outcome run(const std::string &bundle, const Limits &limits, const std::string &affinity = {},
              const std::function<bool()> &cancelled = {});

  // Starts a worker and builds the architecture `bundle` needs, ahead of
  // the first run (synchronous; best effort).
  void warm(const std::string &bundle);

  // Resident anonymous memory of the live workers (bytes), as they last
  // reported it; and how many are alive.
  std::uint64_t workers_rss() const;
  // The live workers' anonymous memory now (read from /proc), in-flight
  // runs included.
  std::uint64_t live_rss() const;
  // Kills the busy worker holding the most memory, unless it is the only
  // one busy; its run() returns Outcome::evicted. False if nothing was.
  bool evict_largest();
  unsigned live_workers() const;
  PoolStats stats() const;
  const PoolOptions &options() const { return options_; }

  // The hard deadline for a cooperative timeout (0: none).
  double hard_deadline(double timeout_seconds) const;

 private:
  struct Worker;
  std::unique_ptr<Worker> acquire(const std::string &affinity);
  void release(std::unique_ptr<Worker> w, bool keep);
  void forget(const Worker &w);
  std::unique_ptr<Worker> spawn();
  Outcome run_in_process(const std::string &bundle, const Limits &limits);

  PoolOptions options_;
  mutable std::mutex mu_;
  std::condition_variable cv_;
  std::vector<std::unique_ptr<Worker>> idle_;
  unsigned live_ = 0;
  PoolStats stats_;
  std::map<int, std::uint64_t> rss_;
  std::set<int> busy_, evicted_;  // worker pids running a request; those killed for memory  // by worker pid: anonymous memory after its last run
  struct InProcess;
  std::unique_ptr<InProcess> local_;
  std::string missing_worker_;  // why no worker binary was found
};

// A run's failure, whether the worker died (Outcome::failure) or the
// decompiler stopped itself over its limits (timeout; too many varnodes as
// oom). Cancellation is not a failure (nullopt).
std::optional<Failure> failure_of(const Outcome &o, std::uint64_t function, const std::string &bundle_hash,
                                  const Limits &limits);

// The worker side: serves requests on `fd` until it closes (rk-decompd --worker).
int serve(int fd);

}  // namespace revkit::decompd
