// An import's progress (ProjectService.GetImportProgress, api_minor 22,
// feature "import-progress"; docs/api.md, "Import progress").
//
// ImportProgram is one blocking call. A client that sends an import_id can
// poll how far it has got: the phase, a line saying what it is doing and an
// estimated fraction. The fraction weights the phases by what each is
// expected to cost for this file (ImportCosts, from sizes measured on real
// binaries), re-planned as more becomes known (the code's and the debug
// info's size once the file is parsed), and moves inside a phase by real
// work where that is cheap to count (function discovery: bytes decoded,
// functions found) and by elapsed time against the estimate elsewhere.
//
// Concurrency: the importing thread changes phase under the progress's
// mutex (a handful of times per import); discovery's threads only touch
// analysis::DiscoveryProgress's relaxed atomics; readers take the mutex and
// read those atomics. Nothing locks in a hot loop.
#pragma once

#include "revkit/analysis/analysis.h"
#include "revkit/api/backend.h"
#include "revkit/loader/image.hh"
#include "revkit/v1/project.pb.h"

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

namespace revkit::backend {

namespace pb = ::revkit::v1;

// What is known about the file being imported, as the import learns it.
struct ImportFacts {
  std::uint64_t file_bytes = 0;
  // Executable, initialized bytes (ProgramInfo::code); 0 until parsed.
  std::uint64_t code_bytes = 0;
  // DWARF sections' bytes; a PE that names a PDB counts as some.
  std::uint64_t debug_bytes = 0;
  bool parsed = false;      // the fields below and above are known
  bool raw = false;         // a raw image: discovery searches for starts
  bool pdb = false;         // a PE naming a PDB
  bool parallel = false;    // discovery runs on the analysis pool
  bool persistent = false;  // the project is saved to disk at the end
  bool prototypes = false;  // rk-daemon --infer-prototypes
};

// Expected seconds per phase (0: the import skips it).
struct ImportCosts {
  double reading = 0, loading = 0, debug_info = 0, functions = 0, data = 0, prototypes = 0, saving = 0;
  double of(pb::ImportPhase phase) const;
  static ImportCosts estimate(const ImportFacts &f);
};

// The share of the code bytes discovery is expected to have decoded when
// it ends: what the decoded-bytes measure is held against.
double ExpectedCoverage(bool raw);

// "3,120".
std::string Thousands(std::uint64_t n);

class ImportProgress {
 public:
  using Clock = std::chrono::steady_clock;

  ImportProgress(std::string caller, std::string project, std::string id);

  // The costs of the phases still to come (and of the current one, for its
  // elapsed-time estimate). Shares already handed out don't change, so the
  // fraction never goes back.
  void Plan(const ImportCosts &costs);
  // Ends the current phase (its whole share counts as done) and starts
  // `phase`, whose share of what is left is its cost over the cost of it
  // and every phase after it.
  void Enter(pb::ImportPhase phase, std::string message);
  // Within the current phase: from here on `message`, and at least `floor`
  // of the phase is done; the rest moves with elapsed time against
  // `seconds`.
  void Step(double floor, std::string message, double seconds);
  // Function discovery in the current phase: the fraction follows its
  // decoded bytes against `code_bytes` × ExpectedCoverage (up to `until`
  // of the phase), the message its stage and functions found.
  void Track(std::shared_ptr<const analysis::DiscoveryProgress> discovery, std::uint64_t code_bytes, bool raw,
             double until);
  void SetProgram(std::string program_id);
  // The current phase's estimated seconds.
  double Estimate() const;
  // The functions discovery found, once it has.
  void SetFunctions(std::uint64_t n);
  std::uint64_t functions() const;
  void Finish(std::string message);
  void Fail(std::string error);

  void Fill(pb::GetImportProgressResponse &out);
  bool done() const;
  Clock::time_point finished_at() const;
  const std::string &project() const { return project_; }

 private:
  double SubLocked(Clock::time_point now) const;
  std::string MessageLocked() const;
  void LogLocked(Clock::time_point now);

  const std::string caller_, project_, id_;
  const Clock::time_point start_;
  const bool timing_;
  mutable std::mutex mu_;
  pb::ImportPhase phase_ = pb::IMPORT_PHASE_UNSPECIFIED;
  std::string message_;
  ImportCosts costs_;
  double done_share_ = 0;  // phases ended
  double share_ = 0;       // the current phase's
  Clock::time_point phase_start_, step_start_;
  double floor_ = 0;          // of the current phase, from Step
  double step_seconds_ = 0;   // Step's estimate; 0: the phase's
  bool stepped_ = false;
  std::shared_ptr<const analysis::DiscoveryProgress> discovery_;
  double discovery_bytes_ = 0;  // code bytes × coverage
  double discovery_until_ = 0;
  bool raw_ = false;
  double last_ = 0;  // the largest fraction reported
  std::string program_id_;
  std::uint64_t functions_ = 0;
  bool done_ = false;
  std::string error_;
  Clock::time_point finished_at_;
};

// Every caller's imports with an id, until a while after they end.
class ImportProgressRegistry {
 public:
  // Starts following an import; ALREADY_EXISTS when this caller has one
  // running under `id`, INVALID_ARGUMENT for an unusable id.
  api::Status Start(const std::string &caller, const std::string &project, const std::string &id,
                    std::shared_ptr<ImportProgress> &out);
  // NOT_FOUND unless `caller` started an import under the request's id
  // into its project.
  api::Status Get(const std::string &caller, const pb::GetImportProgressRequest &req,
                  pb::GetImportProgressResponse &resp);

  static constexpr std::chrono::minutes kKeep{5};  // after the import ends
  static constexpr std::size_t kMaxPerCaller = 64;  // ended ones beyond this go first

 private:
  void PruneLocked(ImportProgress::Clock::time_point now);

  std::mutex mu_;
  std::map<std::pair<std::string, std::string>, std::shared_ptr<ImportProgress>> entries_;  // (caller, id)
};

}  // namespace revkit::backend
