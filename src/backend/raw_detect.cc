#include "raw_detect.h"

#include "import_progress.h"  // Thousands

#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <iterator>
#include <thread>

namespace revkit::backend {
namespace {

using api::Error;
using api::Status;
using api::StatusCode;

// The bar's share per phase. Decoding every candidate is nearly all of the
// time (and counted); the rest moves with elapsed time.
constexpr double kReading = 0.02, kSegments = 0.03, kProcessor = 0.80;
constexpr double kBeforeProcessor = kReading + kSegments, kBeforeLayout = kBeforeProcessor + kProcessor;

// Elapsed time as a fraction of work of unknown length: half at `estimate`,
// never whole.
double ByTime(double elapsed, double estimate) { return std::min(0.95, elapsed / (elapsed + estimate)); }

std::string Lower(std::string s) {
  for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

std::vector<std::string> Split(const std::string &s, char sep) {
  std::vector<std::string> out(1);
  for (char c : s) {
    if (c == sep) out.emplace_back();
    else out.back().push_back(c);
  }
  return out;
}

// "ARM:LE:32:v8:default" -> ("ARM:LE:32:v8", "default").
std::pair<std::string, std::string> SplitCompiler(const std::string &language) {
  std::size_t at = 0;
  for (int i = 0; i < 4 && at != std::string::npos; ++i) at = language.find(':', at + (i ? 1 : 0));
  if (at == std::string::npos) return {language, ""};
  return {language.substr(0, at), language.substr(at + 1)};
}

std::string Hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

pb::DetectConfidence ToPb(detect::Confidence c) {
  switch (c) {
    case detect::Confidence::high: return pb::DETECT_CONFIDENCE_HIGH;
    case detect::Confidence::medium: return pb::DETECT_CONFIDENCE_MEDIUM;
    case detect::Confidence::low: return pb::DETECT_CONFIDENCE_LOW;
  }
  return pb::DETECT_CONFIDENCE_LOW;
}

pb::RawSegmentKind ToPb(detect::Segment::Kind k) {
  switch (k) {
    case detect::Segment::Kind::padding: return pb::RAW_SEGMENT_KIND_PADDING;
    case detect::Segment::Kind::high_entropy: return pb::RAW_SEGMENT_KIND_HIGH_ENTROPY;
    case detect::Segment::Kind::text: return pb::RAW_SEGMENT_KIND_TEXT;
    case detect::Segment::Kind::code: return pb::RAW_SEGMENT_KIND_CODE;
  }
  return pb::RAW_SEGMENT_KIND_UNSPECIFIED;
}

const char *ConfidenceText(pb::DetectConfidence c) {
  switch (c) {
    case pb::DETECT_CONFIDENCE_HIGH: return "high";
    case pb::DETECT_CONFIDENCE_MEDIUM: return "medium";
    default: return "low";
  }
}

}  // namespace

// --- DetectJob -----------------------------------------------------------------

DetectJob::DetectJob(std::string caller, std::string project, std::string id)
    : caller_(std::move(caller)), project_(std::move(project)), id_(std::move(id)), start_(Clock::now()), phase_start_(start_) {}

void DetectJob::Enter(pb::RawDetectPhase phase, std::string message) {
  std::lock_guard lock(mu_);
  if (done_) return;
  if (phase <= phase_) {
    message_ = std::move(message);
    return;
  }
  const auto now = Clock::now();
  last_ = std::max(last_, FractionLocked(now));
  phase_ = phase;
  message_ = std::move(message);
  phase_start_ = now;
}

void DetectJob::Candidates(std::size_t done, std::size_t total) {
  candidates_total_.store(total, std::memory_order_relaxed);
  // Threads report as they finish, not in order: keep the largest.
  std::uint64_t seen = candidates_done_.load(std::memory_order_relaxed);
  while (seen < done && !candidates_done_.compare_exchange_weak(seen, done, std::memory_order_relaxed)) {
  }
}

void DetectJob::EndLocked(Clock::time_point now) {
  phase_ = pb::RAW_DETECT_PHASE_DONE;
  done_ = true;
  finished_at_ = now;
}

void DetectJob::Finish(std::string message) {
  std::lock_guard lock(mu_);
  if (done_) return;
  message_ = std::move(message);
  last_ = 1;
  EndLocked(Clock::now());
}

void DetectJob::Fail(std::string error) {
  std::lock_guard lock(mu_);
  if (done_) return;
  const auto now = Clock::now();
  last_ = std::max(last_, FractionLocked(now));
  message_ = "Detection failed: " + error;
  error_ = std::move(error);
  EndLocked(now);
}

void DetectJob::Stopped() {
  std::lock_guard lock(mu_);
  if (done_) return;
  const auto now = Clock::now();
  last_ = std::max(last_, FractionLocked(now));
  message_ = "Detection cancelled";
  stopped_ = true;
  EndLocked(now);
}

double DetectJob::FractionLocked(Clock::time_point now) const {
  const double t = std::chrono::duration<double>(now - phase_start_).count();
  switch (phase_) {
    case pb::RAW_DETECT_PHASE_READING: return kReading * ByTime(t, 0.05);
    case pb::RAW_DETECT_PHASE_SEGMENTS: return kReading + kSegments * ByTime(t, 0.05);
    case pb::RAW_DETECT_PHASE_PROCESSOR: {
      const double total = static_cast<double>(candidates_total_.load(std::memory_order_relaxed));
      const double done = static_cast<double>(candidates_done_.load(std::memory_order_relaxed));
      return kBeforeProcessor + kProcessor * (total > 0 ? std::min(1.0, done / total) : ByTime(t, 2));
    }
    case pb::RAW_DETECT_PHASE_LAYOUT: return kBeforeLayout + (1 - kBeforeLayout) * ByTime(t, 0.4);
    default: return last_;
  }
}

std::string DetectJob::MessageLocked() const {
  if (phase_ != pb::RAW_DETECT_PHASE_PROCESSOR) return message_;
  const std::uint64_t total = candidates_total_.load(std::memory_order_relaxed);
  if (total == 0) return message_;
  return "Trying " + Thousands(total) + (total == 1 ? " language: " : " languages: ") +
         Thousands(std::min(total, candidates_done_.load(std::memory_order_relaxed))) + " done";
}

void DetectJob::Fill(pb::GetRawDetectProgressResponse &out) {
  std::lock_guard lock(mu_);
  const auto now = Clock::now();
  out.set_phase(phase_);
  out.set_message(MessageLocked());
  if (!done_ && phase_ <= pb::RAW_DETECT_PHASE_QUEUED) {
    out.set_progress(-1);
  } else {
    if (!done_) last_ = std::max(last_, std::min(1.0, FractionLocked(now)));
    out.set_progress(static_cast<float>(last_));
  }
  out.set_done(done_);
  out.set_error(error_);
  out.set_cancelled(stopped_);
  const std::uint64_t total = candidates_total_.load(std::memory_order_relaxed);
  out.set_candidates_total(static_cast<std::uint32_t>(total));
  out.set_candidates_done(static_cast<std::uint32_t>(std::min(total, candidates_done_.load(std::memory_order_relaxed))));
  out.set_elapsed_seconds(std::chrono::duration<double>((done_ ? finished_at_ : now) - start_).count());
}

bool DetectJob::done() const {
  std::lock_guard lock(mu_);
  return done_;
}

DetectJob::Clock::time_point DetectJob::finished_at() const {
  std::lock_guard lock(mu_);
  return finished_at_;
}

double DetectJob::elapsed_seconds() const {
  std::lock_guard lock(mu_);
  return std::chrono::duration<double>((done_ ? finished_at_ : Clock::now()) - start_).count();
}

// --- DetectRegistry ------------------------------------------------------------

Status DetectRegistry::Start(const std::string &caller, const std::string &project, const std::string &id,
                             std::shared_ptr<DetectJob> &out) {
  if (id.empty()) {
    out = std::make_shared<DetectJob>(caller, project, id);
    return Status::Ok();
  }
  if (id.size() > 128) return Error(StatusCode::kInvalidArgument, "detect_id is longer than 128 characters");
  for (unsigned char c : id)
    if (c < 0x20 || c == 0x7f) return Error(StatusCode::kInvalidArgument, "detect_id may not contain control characters");
  std::lock_guard lock(mu_);
  PruneLocked(DetectJob::Clock::now());
  auto &slot = entries_[{caller, id}];
  if (slot && !slot->done())
    return Error(StatusCode::kAlreadyExists, "a detection with id " + id + " is already running");
  slot = std::make_shared<DetectJob>(caller, project, id);
  out = slot;
  return Status::Ok();
}

Status DetectRegistry::Get(const std::string &caller, const pb::GetRawDetectProgressRequest &req,
                           pb::GetRawDetectProgressResponse &resp) {
  std::shared_ptr<DetectJob> job;
  {
    std::lock_guard lock(mu_);
    PruneLocked(DetectJob::Clock::now());
    auto it = entries_.find({caller, req.detect_id()});
    if (it != entries_.end() && it->second->project() == req.project_id()) job = it->second;
  }
  // Someone else's detection reads as one that doesn't exist (yet).
  if (!job) return Error(StatusCode::kNotFound, "no detection " + req.detect_id() + " in project " + req.project_id());
  job->Fill(resp);
  return Status::Ok();
}

Status DetectRegistry::Cancel(const std::string &caller, const pb::CancelRawDetectRequest &req) {
  std::shared_ptr<DetectJob> job;
  {
    std::lock_guard lock(mu_);
    auto it = entries_.find({caller, req.detect_id()});
    if (it != entries_.end() && it->second->project() == req.project_id()) job = it->second;
  }
  if (!job) return Error(StatusCode::kNotFound, "no detection " + req.detect_id() + " in project " + req.project_id());
  job->Cancel();
  slot_free_.notify_all();  // one that waits for a slot stops waiting
  return Status::Ok();
}

Status DetectRegistry::Acquire(DetectJob &job, const std::function<bool()> &gone, Slot &out) {
  std::unique_lock lock(slots_mu_);
  if (running_ >= kMaxRunning) {
    if (waiting_ >= kMaxWaiting)
      return Error(StatusCode::kResourceExhausted,
                   "too many detections are waiting already (" + std::to_string(kMaxWaiting) + "); try again in a moment");
    job.Enter(pb::RAW_DETECT_PHASE_QUEUED, "Waiting for another detection to finish");
    ++waiting_;
    while (running_ >= kMaxRunning) {
      if (job.cancel_requested() || (gone && gone())) {
        --waiting_;
        return Error(StatusCode::kCancelled, "detection cancelled");
      }
      slot_free_.wait_for(lock, std::chrono::milliseconds(50));
    }
    --waiting_;
  }
  ++running_;
  out = Slot(this);
  return Status::Ok();
}

void DetectRegistry::Slot::Release() {
  if (!registry_) return;
  {
    std::lock_guard lock(registry_->slots_mu_);
    --registry_->running_;
  }
  registry_->slot_free_.notify_all();
  registry_ = nullptr;
}

void DetectRegistry::PruneLocked(DetectJob::Clock::time_point now) {
  std::map<std::string, std::vector<std::pair<DetectJob::Clock::time_point, decltype(entries_)::iterator>>> ended;
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

// --- hints, the response ---------------------------------------------------------

Status ResolveDetectHints(const pb::RawDetectHints &hints, DetectHints &out) {
  out = {};
  if (!hints.language_id().empty()) {
    const std::vector<std::string> parts = Split(hints.language_id(), ':');
    if (parts.size() < 4 || parts.size() > 5)
      return Error(StatusCode::kInvalidArgument,
                   "hints.language_id \"" + hints.language_id() + "\" is not proc:endian:size:variant[:compiler]");
    out.language = parts[0] + ":" + parts[1] + ":" + parts[2] + ":" + parts[3];
    const std::vector<lift::LanguageSummary> all = lift::list_languages();
    const auto it = std::find_if(all.begin(), all.end(), [&](const auto &l) { return l.id == out.language; });
    if (it == all.end())
      return Error(StatusCode::kInvalidArgument, "hints.language_id: the daemon has no language " + out.language);
    if (parts.size() == 5) {
      if (std::find(it->compilers.begin(), it->compilers.end(), parts[4]) == it->compilers.end())
        return Error(StatusCode::kInvalidArgument,
                     "hints.language_id: " + out.language + " has no compiler \"" + parts[4] + "\"");
      out.compiler = parts[4];
    }
    out.processors = {parts[0]};
    return Status::Ok();
  }
  if (!hints.processor().empty()) {
    const std::string want = Lower(hints.processor());
    for (const lift::LanguageSummary &l : lift::list_languages()) {
      const std::string first = l.id.substr(0, l.id.find(':'));
      if (Lower(first) != want && Lower(l.processor) != want) continue;
      if (std::find(out.processors.begin(), out.processors.end(), first) == out.processors.end())
        out.processors.push_back(first);
    }
    if (out.processors.empty())
      return Error(StatusCode::kInvalidArgument,
                   "hints.processor: the daemon has no language for processor \"" + hints.processor() + "\"");
  }
  return Status::Ok();
}

void FillDetectResponse(const detect::Report &report, const DetectHints &hints, pb::DetectRawLayoutResponse &resp) {
  if (report.refusal) {
    resp.mutable_refusal()->set_reason(report.refusal->reason);
    resp.mutable_refusal()->set_detail(report.refusal->detail);
  }
  for (const detect::Segment &s : report.segments) {
    pb::RawFileSegment *out = resp.add_segments();
    out->set_offset(s.offset);
    out->set_size(s.size);
    out->set_kind(ToPb(s.kind));
  }
  int pinned = -1;
  for (const detect::Suggestion &s : report.suggestions) {
    pb::RawLayoutSuggestion *out = resp.add_suggestions();
    pb::ImportOptions *o = out->mutable_options();
    auto [language, compiler] = SplitCompiler(s.language);
    std::vector<std::string> ties = s.tie_group;
    // The language the user chose, where this suggestion's evidence covers
    // it: it takes the suggestion's place, which joins the tie group.
    if (pinned < 0 && !hints.language.empty()) {
      bool covers = language == hints.language;
      for (auto it = ties.begin(); !covers && it != ties.end(); ++it) {
        auto [tie, tie_compiler] = SplitCompiler(*it);
        if (tie != hints.language) continue;
        covers = true;
        ties.erase(it);
        ties.insert(ties.begin(), s.language);
        language = tie;
        compiler = tie_compiler;
        break;
      }
      if (covers) {
        if (!hints.compiler.empty()) compiler = hints.compiler;
        out->set_language_pinned(true);
        pinned = resp.suggestions_size() - 1;
      }
    }
    o->set_format("raw");
    o->set_language_id(language);
    o->set_compiler_spec_id(compiler);
    if (s.base) {
      o->set_has_image_base(true);
      o->set_image_base(*s.base);
    }
    o->set_raw_offset(s.offset);
    // A region as an import takes it; false for what the raw loader wouldn't take either.
    auto region = [](const std::string &spec, pb::MemoryRegion &m) {
      loader::RawRegion r;
      try {
        r = loader::parse_raw_region(spec);
      } catch (const loader::LoadError &) {
        return false;
      }
      if (r.name.empty() || r.size == 0) return false;
      m.set_name(r.name);
      m.set_start(r.start);
      m.set_size(r.size);
      m.set_read(r.perms.read);
      m.set_write(r.perms.write);
      m.set_execute(r.perms.exec);
      m.set_initialized(r.initialized);
      m.set_is_volatile(r.is_volatile);
      return true;
    };
    for (const std::string &spec : s.regions) {
      pb::MemoryRegion m;
      if (region(spec, m)) *o->add_regions() = std::move(m);
    }
    for (const detect::RegionSuggestion &g : s.region_details) {
      pb::RawRegionSuggestion d;
      if (!region(g.spec, *d.mutable_region())) continue;
      using K = detect::RegionSuggestion::Kind;
      d.set_kind(g.kind == K::ram    ? pb::RAW_REGION_KIND_RAM
                 : g.kind == K::mmio ? pb::RAW_REGION_KIND_MMIO
                                     : pb::RAW_REGION_KIND_UNKNOWN);
      d.set_spec(g.spec);
      d.set_confidence(ToPb(g.confidence));
      for (const std::string &e : g.evidence) d.add_evidence(e);
      *out->add_region_details() = std::move(d);
    }
    out->set_processor_confidence(ToPb(s.processor));
    out->set_variant_confidence(ToPb(s.variant));
    out->set_base_confidence(ToPb(s.base_confidence));
    out->set_offset_confidence(ToPb(s.offset_confidence));
    for (const detect::Evidence &e : s.evidence) {
      pb::DetectEvidence *ev = out->add_evidence();
      ev->set_about(e.about);
      ev->set_text(e.text);
    }
    for (const std::string &t : ties) out->add_tie_group(t);
    out->set_score(s.score);
  }
  // What the user chose comes first.
  for (int i = pinned; i > 0; --i) resp.mutable_suggestions()->SwapElements(i, i - 1);
}

Status RunRawDetect(std::span<const std::byte> file, const DetectHints &hints, unsigned threads, DetectJob &job,
                    const std::function<bool()> &gone, pb::DetectRawLayoutResponse &resp) {
  detect::Options options;
  options.threads = std::max(1u, threads);
  options.processors = hints.processors;
  options.progress = [&job](const detect::Progress &p) {
    switch (p.stage) {
      case detect::Progress::Stage::segments:
        job.Enter(pb::RAW_DETECT_PHASE_SEGMENTS, "Mapping the file: padding, compressed data, text, code");
        break;
      case detect::Progress::Stage::sweep:
        job.Candidates(p.done, p.total);
        if (p.done == 0) job.Enter(pb::RAW_DETECT_PHASE_PROCESSOR, "Decoding samples as every candidate language");
        break;
      case detect::Progress::Stage::layout:
        job.Enter(pb::RAW_DETECT_PHASE_LAYOUT, "Working out the load address, where the image starts in the file and the variant");
        break;
    }
  };
  // The detector asks from every thread it runs; the transport is asked
  // from this one only (it does its share of the work, so often enough).
  const std::thread::id here = std::this_thread::get_id();
  options.cancel = [&job, &gone, here] {
    if (gone && std::this_thread::get_id() == here && gone()) job.Cancel();
    return job.cancel_requested();
  };
  const detect::Report report = detect::detect(file, options);
  if (options.cancel()) return Error(StatusCode::kCancelled, "detection cancelled");
  FillDetectResponse(report, hints, resp);
  resp.set_file_size(file.size());
  return Status::Ok();
}

std::string DescribeDetection(const pb::DetectRawLayoutResponse &resp) {
  if (resp.has_refusal()) return "No answer (" + resp.refusal().reason() + "): " + resp.refusal().detail();
  if (resp.suggestions().empty()) return "No answer";
  const pb::RawLayoutSuggestion &s = resp.suggestions(0);
  std::string out = "Detected " + s.options().language_id();
  out += s.options().has_image_base() ? " at " + Hex(s.options().image_base()) : ", load address undetermined";
  if (s.options().raw_offset()) out += ", image at file offset " + Hex(s.options().raw_offset());
  out += std::string(" (") + ConfidenceText(s.processor_confidence()) + " confidence)";
  return out;
}

}  // namespace revkit::backend
