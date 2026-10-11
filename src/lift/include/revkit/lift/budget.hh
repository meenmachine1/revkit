// Bounds on one run of Ghidra's decompiler: a deadline, a size bound and
// cancellation, checked cooperatively from inside the decompiler.
//
// Ghidra's Java side bounds a decompilation by killing the decompiler
// process after a timeout (30 s by default, DecompileOptions). revkit links
// the decompiler in process, so it stops a run instead: DecompileBudget
// adds a check to every rule pool and action group of the architecture's
// root action (no change to the decompiler itself), and the check throws
// DecompileStopped once the run is over its limits. The check runs between
// rule applications and actions, so a run stops within one action of its
// deadline. An architecture a run was stopped in is left mid-analysis and
// should be discarded (InputDecompiler::spoiled()).
#pragma once

#include "error.hh"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace ghidra {
class Architecture;
class Funcdata;
}  // namespace ghidra

namespace revkit::lift {

struct DecompileLimits {
  // Wall time for the run; 0: none.
  double timeout_seconds = 0;
  // Varnodes the function under analysis may have, a stand-in for its
  // memory (about 1 KB each with ops, covers and heritage); 0: none.
  // Unlike the timeout, it gives the same answer on any machine.
  std::size_t max_varnodes = 0;
  // Polled every few milliseconds: true stops the run.
  std::function<bool()> cancelled;

  bool any() const { return timeout_seconds > 0 || max_varnodes != 0 || cancelled; }
};

enum class DecompileStop : std::uint8_t { none, timeout, too_large, cancelled };

// What a stopped run throws (a LowlevelError, so the decompiler unwinds as
// from any of its own errors).
struct DecompileStopped : ghidra::LowlevelError {
  DecompileStop reason;
  DecompileStopped(DecompileStop r, const std::string &why) : ghidra::LowlevelError(why), reason(r) {}
};

class DecompileBudget {
 public:
  // Adds the checks to `arch`'s current root action (call after
  // allacts.setCurrent). The budget must outlive the architecture's use.
  void install(ghidra::Architecture &arch);
  // Starts a run under `limits`.
  void start(const DecompileLimits &limits);
  // Why the run stopped, if it did.
  DecompileStop stopped() const { return stopped_; }
  // The most varnodes the function had when checked (a sample, every 64
  // checks): how big the run got.
  std::size_t peak_varnodes() const { return peak_; }
  std::string message() const;
  // Throws DecompileStopped once the run is over its limits.
  void check(const ghidra::Funcdata &fd);

 private:
  using Clock = std::chrono::steady_clock;
  [[noreturn]] void stop(DecompileStop why);

  DecompileLimits limits_;
  Clock::time_point started_{};
  Clock::time_point deadline_ = Clock::time_point::max();
  Clock::time_point next_poll_{};
  std::uint32_t tick_ = 0;
  std::size_t peak_ = 0;
  DecompileStop stopped_ = DecompileStop::none;
};

// "decompilation timed out after 30 s" and the like.
std::string describe(DecompileStop why);

}  // namespace revkit::lift
