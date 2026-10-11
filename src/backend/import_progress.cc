#include "import_progress.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <iterator>

namespace revkit::backend {
namespace {

using api::Error;
using api::Status;
using api::StatusCode;

constexpr double kMB = 1 << 20;

const char *PhaseName(pb::ImportPhase p) {
  switch (p) {
    case pb::IMPORT_PHASE_READING: return "reading";
    case pb::IMPORT_PHASE_LOADING: return "loading";
    case pb::IMPORT_PHASE_DEBUG_INFO: return "debug info";
    case pb::IMPORT_PHASE_FUNCTIONS: return "functions";
    case pb::IMPORT_PHASE_DATA: return "data";
    case pb::IMPORT_PHASE_PROTOTYPES: return "prototypes";
    case pb::IMPORT_PHASE_SAVING: return "saving";
    case pb::IMPORT_PHASE_DONE: return "done";
    default: return "starting";
  }
}

constexpr pb::ImportPhase kOrder[] = {pb::IMPORT_PHASE_READING,   pb::IMPORT_PHASE_LOADING,
                                      pb::IMPORT_PHASE_DEBUG_INFO, pb::IMPORT_PHASE_FUNCTIONS,
                                      pb::IMPORT_PHASE_DATA,      pb::IMPORT_PHASE_PROTOTYPES,
                                      pb::IMPORT_PHASE_SAVING};

// Elapsed time against an estimate, as a fraction of the work: in step with
// the estimate up to 85%, then creeping towards 95% however long it runs
// over, so a slow phase never looks finished.
double ByTime(double elapsed, double estimate) {
  if (estimate <= 0) return 0.5;
  const double t = elapsed / estimate;
  return t < 1 ? 0.85 * t : 0.85 + 0.10 * (1 - std::exp(-(t - 1)));
}

}  // namespace

// Seconds, from imports measured with REVKIT_TIMING on a 32-core host (8
// analysis threads), RelWithDebInfo; docs/api.md, "Import progress", has
// the table. Only the ratios between phases matter.
ImportCosts ImportCosts::estimate(const ImportFacts &f) {
  ImportCosts c;
  const double file = static_cast<double>(f.file_bytes) / kMB;
  // Before parsing, a guess at the code from the file's size.
  const double code = f.parsed ? static_cast<double>(f.code_bytes) / kMB : file * (f.raw ? 1.0 : 0.7);
  c.reading = 0.002 + 0.003 * file;
  c.loading = f.raw ? 0.02 + 0.015 * file : 0.08 + 0.006 * file;
  if (f.parsed) {
    c.debug_info = f.debug_bytes ? 0.01 + 0.02 * static_cast<double>(f.debug_bytes) / kMB : 0;
    if (f.pdb) c.debug_info += 0.2;
  }
  // Discovery: decoding from the seeds, the fixpoint and references. Raw
  // images search for function starts round after round: 0.7-40 s per MB
  // on the firmware corpus, about 3 the median; half that, because the
  // bar's time term (t / (t + estimate)) is only half way at the estimate.
  if (f.raw) c.functions = 0.05 + 1.5 * code;
  else if (f.parallel) c.functions = 0.1 + 0.1 * code;
  else c.functions = 0.02 + 0.9 * code;
  c.data = 0.1 + 0.035 * code;
  c.prototypes = f.prototypes ? 0.1 + 0.5 * code : 0;
  c.saving = f.persistent ? std::min(0.8, 0.1 + 0.25 * code) : 0;
  return c;
}

double ImportCosts::of(pb::ImportPhase phase) const {
  switch (phase) {
    case pb::IMPORT_PHASE_READING: return reading;
    case pb::IMPORT_PHASE_LOADING: return loading;
    case pb::IMPORT_PHASE_DEBUG_INFO: return debug_info;
    case pb::IMPORT_PHASE_FUNCTIONS: return functions;
    case pb::IMPORT_PHASE_DATA: return data;
    case pb::IMPORT_PHASE_PROTOTYPES: return prototypes;
    case pb::IMPORT_PHASE_SAVING: return saving;
    default: return 0;
  }
}

double ExpectedCoverage(bool raw) {
  // Instruction bytes over code bytes once discovery ends: about 0.9 for
  // compiled ELF and PE text; 0.45-0.87 on raw firmware, whose image holds
  // its data too.
  return raw ? 0.7 : 0.9;
}

std::string Thousands(std::uint64_t n) {
  std::string s = std::to_string(n);
  for (int i = static_cast<int>(s.size()) - 3; i > 0; i -= 3) s.insert(static_cast<std::size_t>(i), ",");
  return s;
}

ImportProgress::ImportProgress(std::string caller, std::string project, std::string id)
    : caller_(std::move(caller)),
      project_(std::move(project)),
      id_(std::move(id)),
      start_(Clock::now()),
      timing_(std::getenv("REVKIT_TIMING") != nullptr),
      phase_start_(start_),
      step_start_(start_) {}

void ImportProgress::Plan(const ImportCosts &costs) {
  std::lock_guard lock(mu_);
  costs_ = costs;
}

void ImportProgress::LogLocked(Clock::time_point now) {
  if (!timing_ || phase_ == pb::IMPORT_PHASE_UNSPECIFIED) return;
  std::fprintf(stderr, "revkit: import %s: %s %.1f ms (estimated %.1f ms, %.1f%% of the bar)\n", id_.c_str(),
               PhaseName(phase_), std::chrono::duration<double, std::milli>(now - phase_start_).count(),
               costs_.of(phase_) * 1000, share_ * 100);
}

void ImportProgress::Enter(pb::ImportPhase phase, std::string message) {
  std::lock_guard lock(mu_);
  if (done_ || phase <= phase_) {
    message_ = std::move(message);
    return;
  }
  const auto now = Clock::now();
  LogLocked(now);
  done_share_ = std::min(1.0, done_share_ + share_);
  last_ = std::max(last_, done_share_);
  double rest = 0;
  for (pb::ImportPhase p : kOrder)
    if (p >= phase) rest += costs_.of(p);
  share_ = rest > 0 ? (1 - done_share_) * costs_.of(phase) / rest : 0;
  phase_ = phase;
  message_ = std::move(message);
  phase_start_ = step_start_ = now;
  floor_ = 0;
  step_seconds_ = 0;
  stepped_ = false;
  discovery_.reset();
}

void ImportProgress::Step(double floor, std::string message, double seconds) {
  std::lock_guard lock(mu_);
  if (done_) return;
  const auto now = Clock::now();
  floor_ = std::clamp(std::max(floor, SubLocked(now)), 0.0, 1.0);
  if (discovery_) functions_ = std::max(functions_, discovery_->functions.load(std::memory_order_relaxed));
  message_ = std::move(message);
  step_start_ = now;
  step_seconds_ = seconds;
  stepped_ = true;
}

void ImportProgress::Track(std::shared_ptr<const analysis::DiscoveryProgress> discovery, std::uint64_t code_bytes,
                           bool raw, double until) {
  std::lock_guard lock(mu_);
  discovery_ = std::move(discovery);
  raw_ = raw;
  discovery_bytes_ = std::max(1.0, static_cast<double>(code_bytes) * ExpectedCoverage(raw));
  discovery_until_ = until;
}

void ImportProgress::SetProgram(std::string program_id) {
  std::lock_guard lock(mu_);
  program_id_ = std::move(program_id);
}

double ImportProgress::Estimate() const {
  std::lock_guard lock(mu_);
  return costs_.of(phase_);
}

void ImportProgress::SetFunctions(std::uint64_t n) {
  std::lock_guard lock(mu_);
  functions_ = n;
}

std::uint64_t ImportProgress::functions() const {
  std::lock_guard lock(mu_);
  return functions_;
}

void ImportProgress::Finish(std::string message) {
  std::lock_guard lock(mu_);
  if (done_) return;
  const auto now = Clock::now();
  LogLocked(now);
  if (timing_)
    std::fprintf(stderr, "revkit: import %s: total %.1f ms\n", id_.c_str(),
                 std::chrono::duration<double, std::milli>(now - start_).count());
  if (discovery_) functions_ = std::max(functions_, discovery_->functions.load(std::memory_order_relaxed));
  discovery_.reset();
  phase_ = pb::IMPORT_PHASE_DONE;
  message_ = std::move(message);
  done_share_ = last_ = 1;
  share_ = 0;
  done_ = true;
  finished_at_ = now;
}

void ImportProgress::Fail(std::string error) {
  std::lock_guard lock(mu_);
  if (done_) return;
  const auto now = Clock::now();
  last_ = std::max(last_, done_share_ + share_ * SubLocked(now));
  discovery_.reset();
  message_ = "Import failed: " + error;
  error_ = std::move(error);
  done_ = true;
  finished_at_ = now;
}

double ImportProgress::SubLocked(Clock::time_point now) const {
  const double since_step = std::chrono::duration<double>(now - step_start_).count();
  if (discovery_ && !stepped_) {
    // Decoded bytes against what discovery is expected to decode, and time
    // against the estimate (t / (t + estimate): half at the estimate, 90%
    // at nine times it, so a long search slows the bar but never stops
    // it). Compiled code is mostly decoding from the seeds; raw firmware
    // mostly searching, round after round, after the decoding is done.
    const double bytes = std::min(
        1.0, static_cast<double>(discovery_->decoded_bytes.load(std::memory_order_relaxed)) / discovery_bytes_);
    const double t = std::chrono::duration<double>(now - phase_start_).count();
    const double estimate = std::max(0.05, costs_.of(phase_));
    const double by_time = t / (t + estimate);
    const double s = raw_ ? 1 - (1 - 0.5 * bytes) * (1 - by_time) : std::max(std::min(0.97, bytes), by_time);
    return discovery_until_ * std::min(0.99, s);
  }
  const double seconds = step_seconds_ > 0 ? step_seconds_ : costs_.of(phase_);
  return floor_ + (1 - floor_) * ByTime(since_step, seconds);
}

std::string ImportProgress::MessageLocked() const {
  if (!discovery_ || stepped_) return message_;
  using Stage = analysis::DiscoveryProgress::Stage;
  const std::string found = Thousands(discovery_->functions.load(std::memory_order_relaxed));
  switch (discovery_->stage.load(std::memory_order_relaxed)) {
    case Stage::flows:
      return "Disassembling: " + Thousands(discovery_->flows.load(std::memory_order_relaxed)) + " functions";
    case Stage::walking: return "Finding functions: " + found + " found";
    case Stage::search: return "Searching for function starts: " + found + " found";
    case Stage::search_code: return "Searching for code nothing calls: " + found + " functions";
    case Stage::bodies: return "Assigning code to " + found + " functions";
    default: return message_;
  }
}

void ImportProgress::Fill(pb::GetImportProgressResponse &out) {
  std::lock_guard lock(mu_);
  const auto now = Clock::now();
  out.set_phase(phase_);
  out.set_message(MessageLocked());
  if (phase_ == pb::IMPORT_PHASE_UNSPECIFIED && !done_) {
    out.set_progress(-1);
  } else {
    if (!done_) last_ = std::max(last_, std::min(1.0, done_share_ + share_ * SubLocked(now)));
    out.set_progress(static_cast<float>(last_));
  }
  out.set_done(done_);
  out.set_error(error_);
  out.set_program_id(program_id_);
  std::uint64_t functions = functions_;
  if (discovery_) {
    functions = std::max(functions, discovery_->functions.load(std::memory_order_relaxed));
    if (discovery_->stage.load(std::memory_order_relaxed) == analysis::DiscoveryProgress::Stage::flows)
      functions = std::max(functions, discovery_->flows.load(std::memory_order_relaxed));
  }
  out.set_functions_found(functions);
  out.set_elapsed_seconds(std::chrono::duration<double>((done_ ? finished_at_ : now) - start_).count());
}

bool ImportProgress::done() const {
  std::lock_guard lock(mu_);
  return done_;
}

ImportProgress::Clock::time_point ImportProgress::finished_at() const {
  std::lock_guard lock(mu_);
  return finished_at_;
}

Status ImportProgressRegistry::Start(const std::string &caller, const std::string &project, const std::string &id,
                                     std::shared_ptr<ImportProgress> &out) {
  if (id.size() > 128) return Error(StatusCode::kInvalidArgument, "import_id is longer than 128 characters");
  for (unsigned char c : id)
    if (c < 0x20 || c == 0x7f) return Error(StatusCode::kInvalidArgument, "import_id may not contain control characters");
  std::lock_guard lock(mu_);
  PruneLocked(ImportProgress::Clock::now());
  auto &slot = entries_[{caller, id}];
  if (slot && !slot->done())
    return Error(StatusCode::kAlreadyExists, "an import with id " + id + " is already running");
  slot = std::make_shared<ImportProgress>(caller, project, id);
  out = slot;
  return Status::Ok();
}

Status ImportProgressRegistry::Get(const std::string &caller, const pb::GetImportProgressRequest &req,
                                   pb::GetImportProgressResponse &resp) {
  std::shared_ptr<ImportProgress> p;
  {
    std::lock_guard lock(mu_);
    PruneLocked(ImportProgress::Clock::now());
    auto it = entries_.find({caller, req.import_id()});
    if (it != entries_.end() && it->second->project() == req.project_id()) p = it->second;
  }
  // Someone else's import reads as one that doesn't exist (yet).
  if (!p) return Error(StatusCode::kNotFound, "no import " + req.import_id() + " in project " + req.project_id());
  p->Fill(resp);
  return Status::Ok();
}

void ImportProgressRegistry::PruneLocked(ImportProgress::Clock::time_point now) {
  std::map<std::string, std::vector<std::pair<ImportProgress::Clock::time_point, decltype(entries_)::iterator>>> ended;
  for (auto it = entries_.begin(); it != entries_.end();) {
    if (!it->second || (it->second->done() && now - it->second->finished_at() > kKeep)) {
      it = entries_.erase(it);
      continue;
    }
    if (it->second->done()) ended[it->first.first].emplace_back(it->second->finished_at(), it);
    ++it;
  }
  for (auto &[caller, list] : ended) {
    if (list.size() <= kMaxPerCaller) continue;
    std::sort(list.begin(), list.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
    for (std::size_t i = 0; i + kMaxPerCaller < list.size(); ++i) entries_.erase(list[i].second);
  }
}

}  // namespace revkit::backend
