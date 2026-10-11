// Raw layout detection behind ProjectService.DetectRawLayout (api_minor 23,
// feature "raw-detect"; docs/api.md, "Raw layout detection"): what
// revkit::detect says of a file with no header, as raw import options with
// a confidence and the evidence for each answer.
//
// DetectRawLayout is one blocking call of a few seconds that reads a whole
// file and decodes samples of it as every language, on several threads. So:
//  - a client that sends a detect_id can poll how far it has got
//    (GetRawDetectProgress) and stop it (CancelRawDetect), as an import is
//    followed (import_progress.h): per caller, kept a while after it ends;
//  - the daemon runs at most DetectRegistry::kMaxRunning at a time; more
//    wait (phase QUEUED), and beyond kMaxWaiting are refused.
//
// Concurrency: a job's phase changes under its mutex (a handful of times);
// the detector's threads only touch its relaxed atomics (candidates done,
// the stop flag); readers take the mutex and read those atomics.
#pragma once

#include "revkit/api/backend.h"
#include "revkit/detect/detect.hh"
#include "revkit/v1/project.pb.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace revkit::backend {

namespace pb = ::revkit::v1;

// One detection: its progress, and the flag that stops it.
class DetectJob {
 public:
  using Clock = std::chrono::steady_clock;

  DetectJob(std::string caller, std::string project, std::string id);

  // Ends the current phase and starts `phase` (never an earlier one).
  void Enter(pb::RawDetectPhase phase, std::string message);
  // Candidate languages decoded, of how many. From any thread.
  void Candidates(std::size_t done, std::size_t total);
  // Asks the detection to stop; it does at the next candidate.
  void Cancel() { cancel_.store(true, std::memory_order_relaxed); }
  bool cancel_requested() const { return cancel_.load(std::memory_order_relaxed); }
  // How it ended: answered, failed, or stopped because it was cancelled.
  void Finish(std::string message);
  void Fail(std::string error);
  void Stopped();

  void Fill(pb::GetRawDetectProgressResponse &out);
  bool done() const;
  Clock::time_point finished_at() const;
  double elapsed_seconds() const;
  const std::string &project() const { return project_; }

 private:
  double FractionLocked(Clock::time_point now) const;
  std::string MessageLocked() const;
  void EndLocked(Clock::time_point now);

  const std::string caller_, project_, id_;
  const Clock::time_point start_;
  mutable std::mutex mu_;
  pb::RawDetectPhase phase_ = pb::RAW_DETECT_PHASE_UNSPECIFIED;
  std::string message_;
  Clock::time_point phase_start_;
  double last_ = 0;  // the largest fraction reported
  bool done_ = false;
  bool stopped_ = false;
  std::string error_;
  Clock::time_point finished_at_;
  std::atomic<std::uint64_t> candidates_done_{0}, candidates_total_{0};
  std::atomic<bool> cancel_{false};
};

// Every caller's detections with an id, until a while after they end, and
// the slots that bound how many run at once.
class DetectRegistry {
 public:
  // Starts following a detection. An empty id is followed by nobody (the
  // job is the caller's alone); ALREADY_EXISTS when this caller has one
  // running under `id`, INVALID_ARGUMENT for an unusable id.
  api::Status Start(const std::string &caller, const std::string &project, const std::string &id,
                    std::shared_ptr<DetectJob> &out);
  // NOT_FOUND unless `caller` started a detection under the request's id
  // for its project.
  api::Status Get(const std::string &caller, const pb::GetRawDetectProgressRequest &req,
                  pb::GetRawDetectProgressResponse &resp);
  api::Status Cancel(const std::string &caller, const pb::CancelRawDetectRequest &req);

  // A slot to run in, held until the returned guard goes. Waits (phase
  // QUEUED) while kMaxRunning others run; CANCELLED once the job is
  // cancelled or `gone` says its caller left; RESOURCE_EXHAUSTED when
  // kMaxWaiting are waiting already.
  class Slot {
   public:
    Slot() = default;
    explicit Slot(DetectRegistry *r) : registry_(r) {}
    Slot(Slot &&o) noexcept : registry_(std::exchange(o.registry_, nullptr)) {}
    Slot &operator=(Slot &&o) noexcept {
      Release();
      registry_ = std::exchange(o.registry_, nullptr);
      return *this;
    }
    ~Slot() { Release(); }

   private:
    void Release();
    DetectRegistry *registry_ = nullptr;
  };
  api::Status Acquire(DetectJob &job, const std::function<bool()> &gone, Slot &out);

  static constexpr std::chrono::minutes kKeep{5};    // after the detection ends
  static constexpr std::size_t kMaxPerCaller = 64;   // ended ones beyond this go first
  static constexpr unsigned kMaxRunning = 2;         // each on up to 8 threads
  static constexpr unsigned kMaxWaiting = 8;

 private:
  void PruneLocked(DetectJob::Clock::time_point now);

  std::mutex mu_;
  std::map<std::pair<std::string, std::string>, std::shared_ptr<DetectJob>> entries_;  // (caller, id)
  std::mutex slots_mu_;
  std::condition_variable slot_free_;
  unsigned running_ = 0, waiting_ = 0;
};

// The largest file DetectRawLayout reads by path: it is held in memory
// while it is looked at.
constexpr std::uint64_t kMaxDetectBytes = std::uint64_t{1} << 30;

// The request's hints as the detector's options: `processors` (language
// ids' first fields) and, for a language hint, `language` (its first four
// fields) and `compiler` (its fifth, if given). INVALID_ARGUMENT for a
// language or processor the install doesn't have.
struct DetectHints {
  std::vector<std::string> processors;
  std::string language;
  std::string compiler;
};
api::Status ResolveDetectHints(const pb::RawDetectHints &hints, DetectHints &out);

// The detector's report as the response: each suggestion as raw import
// options. With a language hint, the suggestion whose language or tie group
// covers it names it and comes first (language_pinned).
void FillDetectResponse(const detect::Report &report, const DetectHints &hints, pb::DetectRawLayoutResponse &resp);

// Runs the detector on `file` for `job`, on `threads` threads, and fills
// `resp`. `gone` is asked from the calling thread only (the transport's
// "has the client left"). CANCELLED when it was stopped.
api::Status RunRawDetect(std::span<const std::byte> file, const DetectHints &hints, unsigned threads, DetectJob &job,
                         const std::function<bool()> &gone, pb::DetectRawLayoutResponse &resp);

// One line saying what a detection found, for its last progress message.
std::string DescribeDetection(const pb::DetectRawLayoutResponse &resp);

}  // namespace revkit::backend
