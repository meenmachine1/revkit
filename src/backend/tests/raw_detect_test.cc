// Raw layout detection (api_minor 23, feature "raw-detect"; raw_detect.h):
// a detection's phases and fraction, who may read and stop it, how many run
// at once, the detector's report as raw import options, hints, and on the
// image backend DetectRawLayout on this test's own code (a blob with no
// header) while another thread polls, stopped half way, and imported with
// the options it suggested.
#include "builders.hh"
#include "raw_detect.h"

#include "revkit/backend/image_backend.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;
using api::CallContext;
using api::StatusCode;

pb::GetRawDetectProgressResponse Read(DetectJob &job) {
  pb::GetRawDetectProgressResponse r;
  job.Fill(r);
  return r;
}

TEST(DetectJobUnit, PhasesAdvanceInOrderAndTheFractionEndsAtOne) {
  DetectJob job("user:alice", "default", "d1");
  EXPECT_EQ(Read(job).progress(), -1);  // nothing started: unknown
  job.Enter(pb::RAW_DETECT_PHASE_QUEUED, "Waiting");
  EXPECT_EQ(Read(job).progress(), -1);  // waiting for a slot: unknown too
  std::vector<pb::GetRawDetectProgressResponse> seen;
  auto sample = [&] {
    seen.push_back(Read(job));
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    seen.push_back(Read(job));
  };
  job.Enter(pb::RAW_DETECT_PHASE_READING, "Reading fw.bin (1.3 MB)");
  sample();
  job.Enter(pb::RAW_DETECT_PHASE_SEGMENTS, "Mapping the file");
  sample();
  job.Enter(pb::RAW_DETECT_PHASE_PROCESSOR, "Decoding");
  for (std::size_t done : {0u, 40u, 20u, 152u}) {  // threads report out of order
    job.Candidates(done, 152);
    sample();
  }
  EXPECT_EQ(seen.back().message(), "Trying 152 languages: 152 done");
  EXPECT_EQ(seen.back().candidates_done(), 152u);
  EXPECT_EQ(seen.back().candidates_total(), 152u);
  EXPECT_NEAR(seen.back().progress(), 0.85, 0.001);
  job.Enter(pb::RAW_DETECT_PHASE_LAYOUT, "Working out the load address");
  sample();
  EXPECT_LT(seen.back().progress(), 1);
  job.Finish("Detected ARM:LE:32:v8 at 0x8000000 (high confidence)");
  seen.push_back(Read(job));

  for (std::size_t i = 1; i < seen.size(); ++i) {
    EXPECT_GE(seen[i].phase(), seen[i - 1].phase()) << i;
    EXPECT_GE(seen[i].progress(), seen[i - 1].progress()) << i << ": " << seen[i].message();
    EXPECT_GE(seen[i].progress(), 0);
    EXPECT_LE(seen[i].progress(), 1);
  }
  const auto &last = seen.back();
  EXPECT_TRUE(last.done());
  EXPECT_FALSE(last.cancelled());
  EXPECT_EQ(last.phase(), pb::RAW_DETECT_PHASE_DONE);
  EXPECT_EQ(last.progress(), 1);
  EXPECT_TRUE(last.error().empty());
  EXPECT_EQ(last.message(), "Detected ARM:LE:32:v8 at 0x8000000 (high confidence)");
  // Nothing moves it once it has ended.
  job.Enter(pb::RAW_DETECT_PHASE_READING, "again");
  job.Fail("too late");
  EXPECT_EQ(Read(job).phase(), pb::RAW_DETECT_PHASE_DONE);
  EXPECT_TRUE(Read(job).error().empty());
}

TEST(DetectJobUnit, AFailureAndAStopKeepTheFractionAndSayWhich) {
  DetectJob failed("anonymous", "default", "a");
  failed.Enter(pb::RAW_DETECT_PHASE_PROCESSOR, "");
  failed.Candidates(10, 100);
  const float before = Read(failed).progress();
  failed.Fail("cannot read /x");
  auto r = Read(failed);
  EXPECT_TRUE(r.done());
  EXPECT_EQ(r.error(), "cannot read /x");
  EXPECT_FALSE(r.cancelled());
  EXPECT_GE(r.progress(), before);
  EXPECT_LT(r.progress(), 1);

  DetectJob stopped("anonymous", "default", "b");
  stopped.Enter(pb::RAW_DETECT_PHASE_PROCESSOR, "");
  stopped.Candidates(50, 100);
  EXPECT_FALSE(stopped.cancel_requested());
  stopped.Cancel();
  EXPECT_TRUE(stopped.cancel_requested());
  EXPECT_FALSE(Read(stopped).done());  // asked to stop, not stopped yet
  stopped.Stopped();
  r = Read(stopped);
  EXPECT_TRUE(r.done());
  EXPECT_TRUE(r.cancelled());
  EXPECT_TRUE(r.error().empty());
  EXPECT_EQ(r.message(), "Detection cancelled");
  EXPECT_LT(r.progress(), 1);
}

// The detector's threads report while readers poll: no data race (the tsan
// preset), and the fraction never goes back.
TEST(DetectJobUnit, ReadersAndDetectorThreadsRunConcurrently) {
  DetectJob job("anonymous", "default", "id");
  job.Enter(pb::RAW_DETECT_PHASE_PROCESSOR, "");
  std::atomic<std::size_t> next{0};
  std::vector<std::thread> writers;
  for (int t = 0; t < 4; ++t)
    writers.emplace_back([&] {
      for (std::size_t i; (i = next.fetch_add(1)) < 4000;) job.Candidates(i + 1, 4000);
    });
  std::atomic<int> backwards{0};
  std::vector<std::thread> readers;
  for (int t = 0; t < 3; ++t)
    readers.emplace_back([&] {
      float last = 0;
      for (int i = 0; i < 2000; ++i) {
        auto r = Read(job);
        if (r.progress() < last) ++backwards;
        last = r.progress();
        if (i % 500 == 0) (void)job.cancel_requested();
      }
    });
  for (auto &t : writers) t.join();
  for (auto &t : readers) t.join();
  EXPECT_EQ(backwards.load(), 0);
  EXPECT_EQ(Read(job).candidates_done(), 4000u);
  job.Finish("done");
  EXPECT_EQ(Read(job).progress(), 1);
}

TEST(DetectRegistryUnit, OnlyTheCallerThatStartedADetectionCanReadOrStopIt) {
  DetectRegistry reg;
  std::shared_ptr<DetectJob> job;
  ASSERT_TRUE(reg.Start("user:alice", "default", "abc", job).ok());
  job->Enter(pb::RAW_DETECT_PHASE_READING, "Reading");
  pb::GetRawDetectProgressRequest req;
  req.set_project_id("default");
  req.set_detect_id("abc");
  pb::GetRawDetectProgressResponse resp;
  EXPECT_TRUE(reg.Get("user:alice", req, resp).ok());
  EXPECT_EQ(resp.message(), "Reading");
  // Anyone else, admins included, sees nothing; nor does another project.
  EXPECT_EQ(reg.Get("user:bob", req, resp).code, StatusCode::kNotFound);
  EXPECT_EQ(reg.Get("anonymous", req, resp).code, StatusCode::kNotFound);
  req.set_project_id("other");
  EXPECT_EQ(reg.Get("user:alice", req, resp).code, StatusCode::kNotFound);
  // Stopping it is the caller's too.
  pb::CancelRawDetectRequest cancel;
  cancel.set_project_id("default");
  cancel.set_detect_id("abc");
  EXPECT_EQ(reg.Cancel("user:bob", cancel).code, StatusCode::kNotFound);
  EXPECT_FALSE(job->cancel_requested());
  cancel.set_project_id("other");
  EXPECT_EQ(reg.Cancel("user:alice", cancel).code, StatusCode::kNotFound);
  EXPECT_FALSE(job->cancel_requested());
  cancel.set_project_id("default");
  EXPECT_TRUE(reg.Cancel("user:alice", cancel).ok());
  EXPECT_TRUE(job->cancel_requested());
  // One running detection per (caller, id); another caller may use the id.
  std::shared_ptr<DetectJob> other;
  EXPECT_EQ(reg.Start("user:alice", "default", "abc", other).code, StatusCode::kAlreadyExists);
  EXPECT_TRUE(reg.Start("user:bob", "default", "abc", other).ok());
  // Once it has ended it is kept to be read, stopping it changes nothing,
  // and the id can be used again.
  job->Stopped();
  req.set_project_id("default");
  ASSERT_TRUE(reg.Get("user:alice", req, resp).ok());
  EXPECT_TRUE(resp.done());
  EXPECT_TRUE(resp.cancelled());
  EXPECT_TRUE(reg.Cancel("user:alice", cancel).ok());
  EXPECT_TRUE(reg.Start("user:alice", "default", "abc", job).ok());
  EXPECT_EQ(reg.Start("user:alice", "default", std::string(129, 'x'), job).code, StatusCode::kInvalidArgument);
  EXPECT_EQ(reg.Start("user:alice", "default", "a\nb", job).code, StatusCode::kInvalidArgument);
  // Without an id nobody can follow it: nothing is recorded.
  ASSERT_TRUE(reg.Start("user:alice", "default", "", job).ok());
  ASSERT_TRUE(job);
  req.set_detect_id("");
  EXPECT_EQ(reg.Get("user:alice", req, resp).code, StatusCode::kNotFound);
}

TEST(DetectRegistryUnit, EndedDetectionsBeyondTheBoundAreDropped) {
  DetectRegistry reg;
  for (std::size_t i = 0; i < DetectRegistry::kMaxPerCaller + 5; ++i) {
    std::shared_ptr<DetectJob> job;
    ASSERT_TRUE(reg.Start("user:alice", "default", "id" + std::to_string(i), job).ok());
    job->Finish("done");
  }
  std::shared_ptr<DetectJob> job;
  ASSERT_TRUE(reg.Start("user:alice", "default", "last", job).ok());
  pb::GetRawDetectProgressRequest req;
  req.set_project_id("default");
  pb::GetRawDetectProgressResponse resp;
  req.set_detect_id("id0");
  EXPECT_EQ(reg.Get("user:alice", req, resp).code, StatusCode::kNotFound);
  req.set_detect_id("id" + std::to_string(DetectRegistry::kMaxPerCaller + 4));
  EXPECT_TRUE(reg.Get("user:alice", req, resp).ok());
}

TEST(DetectRegistryUnit, AFewRunAtOnceMoreWaitAndTooManyAreRefused) {
  DetectRegistry reg;
  std::vector<DetectRegistry::Slot> running(DetectRegistry::kMaxRunning);
  DetectJob first("anonymous", "default", "");
  for (auto &slot : running) ASSERT_TRUE(reg.Acquire(first, {}, slot).ok());
  EXPECT_EQ(Read(first).phase(), pb::RAW_DETECT_PHASE_UNSPECIFIED);  // it never waited

  // The next ones wait, each saying so.
  constexpr unsigned kWaiters = DetectRegistry::kMaxWaiting;
  std::vector<std::unique_ptr<DetectJob>> jobs;
  std::vector<api::Status> status(kWaiters);
  std::vector<DetectRegistry::Slot> slots(kWaiters);
  std::vector<std::atomic<int>> state(kWaiters);  // 0: waiting, 1: got a slot, 2: refused
  std::vector<std::thread> waiters;
  for (unsigned i = 0; i < kWaiters; ++i) jobs.push_back(std::make_unique<DetectJob>("anonymous", "default", ""));
  for (unsigned i = 0; i < kWaiters; ++i)
    waiters.emplace_back([&, i] {
      status[i] = reg.Acquire(*jobs[i], {}, slots[i]);
      state[i] = status[i].ok() ? 1 : 2;
    });
  auto until = [](auto &&pred) {
    for (int i = 0; i < 10000 && !pred(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    return pred();
  };
  ASSERT_TRUE(until([&] {
    return std::all_of(jobs.begin(), jobs.end(), [](auto &j) { return Read(*j).phase() == pb::RAW_DETECT_PHASE_QUEUED; });
  }));
  EXPECT_EQ(Read(*jobs[0]).message(), "Waiting for another detection to finish");
  EXPECT_EQ(Read(*jobs[0]).progress(), -1);
  // One more than may wait is refused at once.
  DetectJob extra("anonymous", "default", "");
  DetectRegistry::Slot none;
  EXPECT_EQ(reg.Acquire(extra, {}, none).code, StatusCode::kResourceExhausted);
  // One that is cancelled, and one whose caller left, stop waiting.
  jobs[0]->Cancel();
  waiters[0].join();
  EXPECT_EQ(status[0].code, StatusCode::kCancelled);
  std::atomic<bool> left{false};
  DetectJob leaver("anonymous", "default", "");
  api::Status leaver_status;
  std::thread leaving([&] {
    DetectRegistry::Slot slot;
    leaver_status = reg.Acquire(leaver, [&] { return left.load(); }, slot);
  });
  left = true;
  leaving.join();
  EXPECT_EQ(leaver_status.code, StatusCode::kCancelled);
  // As the running ones end, waiting ones run: never more than kMaxRunning
  // at a time, and each that ends lets the next one in.
  auto with_slot = [&] { return static_cast<unsigned>(std::count_if(state.begin(), state.end(), [](auto &s) { return s == 1; })); };
  running.clear();
  ASSERT_TRUE(until([&] { return with_slot() == DetectRegistry::kMaxRunning; }));
  std::this_thread::sleep_for(std::chrono::milliseconds(120));  // more than a waiter's poll
  EXPECT_EQ(with_slot(), DetectRegistry::kMaxRunning);
  std::vector<bool> released(kWaiters, false);
  for (unsigned ended = 0; ended < kWaiters - 1;) {
    unsigned i = 0;
    ASSERT_TRUE(until([&] {
      for (i = 1; i < kWaiters; ++i)
        if (state[i] == 1 && !released[i]) return true;
      return false;
    }));
    slots[i] = DetectRegistry::Slot();
    released[i] = true;
    ++ended;
  }
  for (auto &t : waiters)
    if (t.joinable()) t.join();
  for (unsigned i = 1; i < kWaiters; ++i) EXPECT_TRUE(status[i].ok()) << i << ": " << status[i].message;
}

detect::Report SomeReport() {
  detect::Report r;
  r.segments = {{0, 0x200, detect::Segment::Kind::text},
                {0x200, 0x40000, detect::Segment::Kind::code},
                {0x40200, 0x1000, detect::Segment::Kind::high_entropy},
                {0x41200, 0xe00, detect::Segment::Kind::padding}};
  detect::Suggestion arm;
  arm.language = "ARM:LE:32:v8:default";
  arm.tie_group = {"ARM:LE:32:Cortex:default", "ARM:LE:32:v7:default"};
  arm.base = 0x08000000;
  arm.offset = 0x200;
  arm.regions = {"ram:20000000:40000", "periph:0x40000000:0x1000:rw-:volatile", "rom:0:100:r-x:init", "nonsense", "empty:10:0"};
  using K = detect::RegionSuggestion::Kind;
  arm.region_details = {
      {K::ram, 0x20000000, 0x40000, "ram:20000000:40000", detect::Confidence::high, {"the stack pointer starts at its top"}},
      {K::mmio, 0x40000000, 0x1000, "mmio:40000000:1000:rw-:volatile", detect::Confidence::medium,
       {"52 of 60 stores write constants", "loads wait in a loop"}},
      {K::unknown, 0x60000000, 0x100, "mem:60000000:100", detect::Confidence::low, {"accessed, but nothing says which"}},
      {K::ram, 0x70000000, 0, "bad", detect::Confidence::low, {}},
  };
  arm.processor = detect::Confidence::high;
  arm.variant = detect::Confidence::low;
  arm.base_confidence = detect::Confidence::medium;
  arm.offset_confidence = detect::Confidence::high;
  arm.score = 0.4;
  arm.evidence = {{"processor", "1,220 instructions decode"}, {"base", "140 pointers land on string starts at base 0x8000000"}};
  detect::Suggestion mips;
  mips.language = "MIPS:BE:32:default:default";
  mips.tie_group = {"MIPS:BE:32:R6:default"};
  mips.score = 0.02;
  mips.evidence = {{"processor", "900 instructions decode"}};
  r.suggestions = {arm, mips};
  return r;
}

TEST(DetectResponseUnit, ASuggestionIsRawImportOptionsWithConfidenceEvidenceAndItsTieGroup) {
  pb::DetectRawLayoutResponse resp;
  FillDetectResponse(SomeReport(), {}, resp);
  EXPECT_FALSE(resp.has_refusal());
  ASSERT_EQ(resp.suggestions_size(), 2);
  const pb::RawLayoutSuggestion &s = resp.suggestions(0);
  const pb::ImportOptions &o = s.options();
  EXPECT_EQ(o.format(), "raw");
  EXPECT_EQ(o.language_id(), "ARM:LE:32:v8");
  EXPECT_EQ(o.compiler_spec_id(), "default");
  EXPECT_TRUE(o.has_image_base());
  EXPECT_EQ(o.image_base(), 0x08000000u);
  EXPECT_EQ(o.raw_offset(), 0x200u);
  EXPECT_EQ(o.raw_length(), 0u);
  EXPECT_FALSE(o.has_entry_point());
  // Regions as the raw loader reads them; what it wouldn't take is left out.
  ASSERT_EQ(o.regions_size(), 3);
  EXPECT_EQ(o.regions(0).name(), "ram");
  EXPECT_EQ(o.regions(0).start(), 0x20000000u);
  EXPECT_EQ(o.regions(0).size(), 0x40000u);
  EXPECT_TRUE(o.regions(0).read() && o.regions(0).write() && !o.regions(0).execute());
  EXPECT_FALSE(o.regions(0).initialized());
  EXPECT_EQ(o.regions(1).name(), "periph");
  EXPECT_TRUE(o.regions(1).is_volatile());
  EXPECT_EQ(o.regions(2).name(), "rom");
  EXPECT_TRUE(o.regions(2).execute() && o.regions(2).initialized() && !o.regions(2).write());
  // Each region with its kind, confidence and evidence, unknown ones too;
  // one the raw loader wouldn't take is left out.
  ASSERT_EQ(s.region_details_size(), 3);
  EXPECT_EQ(s.region_details(0).kind(), pb::RAW_REGION_KIND_RAM);
  EXPECT_EQ(s.region_details(0).spec(), "ram:20000000:40000");
  EXPECT_EQ(s.region_details(0).region().start(), 0x20000000u);
  EXPECT_EQ(s.region_details(0).region().size(), 0x40000u);
  EXPECT_EQ(s.region_details(0).confidence(), pb::DETECT_CONFIDENCE_HIGH);
  ASSERT_EQ(s.region_details(0).evidence_size(), 1);
  EXPECT_EQ(s.region_details(1).kind(), pb::RAW_REGION_KIND_MMIO);
  EXPECT_TRUE(s.region_details(1).region().is_volatile());
  EXPECT_EQ(s.region_details(1).region().name(), "mmio");
  EXPECT_EQ(s.region_details(1).evidence_size(), 2);
  EXPECT_EQ(s.region_details(2).kind(), pb::RAW_REGION_KIND_UNKNOWN);
  EXPECT_EQ(s.region_details(2).confidence(), pb::DETECT_CONFIDENCE_LOW);
  EXPECT_EQ(resp.suggestions(1).region_details_size(), 0);
  EXPECT_EQ(s.processor_confidence(), pb::DETECT_CONFIDENCE_HIGH);
  EXPECT_EQ(s.variant_confidence(), pb::DETECT_CONFIDENCE_LOW);
  EXPECT_EQ(s.base_confidence(), pb::DETECT_CONFIDENCE_MEDIUM);
  EXPECT_EQ(s.offset_confidence(), pb::DETECT_CONFIDENCE_HIGH);
  ASSERT_EQ(s.evidence_size(), 2);
  EXPECT_EQ(s.evidence(1).about(), "base");
  EXPECT_EQ(s.evidence(1).text(), "140 pointers land on string starts at base 0x8000000");
  ASSERT_EQ(s.tie_group_size(), 2);
  EXPECT_EQ(s.tie_group(0), "ARM:LE:32:Cortex:default");
  EXPECT_FALSE(s.language_pinned());
  EXPECT_DOUBLE_EQ(s.score(), 0.4);
  // An undetermined base is no base, at low confidence.
  const pb::RawLayoutSuggestion &m = resp.suggestions(1);
  EXPECT_EQ(m.options().language_id(), "MIPS:BE:32:default");
  EXPECT_FALSE(m.options().has_image_base());
  EXPECT_EQ(m.base_confidence(), pb::DETECT_CONFIDENCE_LOW);
  ASSERT_EQ(resp.segments_size(), 4);
  EXPECT_EQ(resp.segments(0).kind(), pb::RAW_SEGMENT_KIND_TEXT);
  EXPECT_EQ(resp.segments(1).kind(), pb::RAW_SEGMENT_KIND_CODE);
  EXPECT_EQ(resp.segments(1).offset(), 0x200u);
  EXPECT_EQ(resp.segments(1).size(), 0x40000u);
  EXPECT_EQ(resp.segments(2).kind(), pb::RAW_SEGMENT_KIND_HIGH_ENTROPY);
  EXPECT_EQ(resp.segments(3).kind(), pb::RAW_SEGMENT_KIND_PADDING);
  EXPECT_EQ(DescribeDetection(resp), "Detected ARM:LE:32:v8 at 0x8000000, image at file offset 0x200 (high confidence)");
}

TEST(DetectResponseUnit, ARefusalKeepsItsGuesses) {
  detect::Report r = SomeReport();
  r.refusal = detect::Refusal{"unknown-processor", "no language decodes this as code"};
  pb::DetectRawLayoutResponse resp;
  FillDetectResponse(r, {}, resp);
  ASSERT_TRUE(resp.has_refusal());
  EXPECT_EQ(resp.refusal().reason(), "unknown-processor");
  EXPECT_EQ(resp.refusal().detail(), "no language decodes this as code");
  EXPECT_EQ(resp.suggestions_size(), 2);
  EXPECT_EQ(DescribeDetection(resp), "No answer (unknown-processor): no language decodes this as code");
}

TEST(DetectResponseUnit, ALanguageTheUserChoseIsNamedWhereTheEvidenceCoversIt) {
  // In the best suggestion's tie group: it takes its place.
  DetectHints hints;
  hints.language = "ARM:LE:32:v7";
  hints.processors = {"ARM"};
  pb::DetectRawLayoutResponse resp;
  FillDetectResponse(SomeReport(), hints, resp);
  ASSERT_EQ(resp.suggestions_size(), 2);
  EXPECT_TRUE(resp.suggestions(0).language_pinned());
  EXPECT_EQ(resp.suggestions(0).options().language_id(), "ARM:LE:32:v7");
  EXPECT_EQ(resp.suggestions(0).options().compiler_spec_id(), "default");
  EXPECT_EQ(resp.suggestions(0).options().image_base(), 0x08000000u);
  ASSERT_EQ(resp.suggestions(0).tie_group_size(), 2);
  EXPECT_EQ(resp.suggestions(0).tie_group(0), "ARM:LE:32:v8:default");
  EXPECT_EQ(resp.suggestions(0).tie_group(1), "ARM:LE:32:Cortex:default");
  EXPECT_FALSE(resp.suggestions(1).language_pinned());

  // The best suggestion's own language, with the user's compiler.
  hints.language = "ARM:LE:32:v8";
  hints.compiler = "windows";
  resp.Clear();
  FillDetectResponse(SomeReport(), hints, resp);
  EXPECT_TRUE(resp.suggestions(0).language_pinned());
  EXPECT_EQ(resp.suggestions(0).options().language_id(), "ARM:LE:32:v8");
  EXPECT_EQ(resp.suggestions(0).options().compiler_spec_id(), "windows");
  EXPECT_EQ(resp.suggestions(0).tie_group_size(), 2);

  // Covered by a later suggestion: that one comes first.
  hints = {};
  hints.language = "MIPS:BE:32:R6";
  resp.Clear();
  FillDetectResponse(SomeReport(), hints, resp);
  ASSERT_EQ(resp.suggestions_size(), 2);
  EXPECT_TRUE(resp.suggestions(0).language_pinned());
  EXPECT_EQ(resp.suggestions(0).options().language_id(), "MIPS:BE:32:R6");
  EXPECT_FALSE(resp.suggestions(0).options().has_image_base());
  EXPECT_EQ(resp.suggestions(1).options().language_id(), "ARM:LE:32:v8");
  EXPECT_FALSE(resp.suggestions(1).language_pinned());

  // Not what the bytes decode as: the suggestions as they are, none pinned.
  hints.language = "ARM:BE:32:v7";
  resp.Clear();
  FillDetectResponse(SomeReport(), hints, resp);
  EXPECT_EQ(resp.suggestions(0).options().language_id(), "ARM:LE:32:v8");
  EXPECT_FALSE(resp.suggestions(0).language_pinned());
  EXPECT_FALSE(resp.suggestions(1).language_pinned());
}

std::vector<std::byte> Noise(std::size_t n) {
  std::mt19937 gen(7);
  std::vector<std::byte> out(n);
  for (std::byte &b : out) b = static_cast<std::byte>(gen() & 0xff);
  return out;
}

// This program's own code, as a blob with no header: 128 KB from the middle
// of what the compiler made for the machine the tests run on.
std::vector<std::byte> OwnCode() {
  const loader::Image image = loader::load_file("/proc/self/exe");
  const loader::Section *text = loader::find_section(image, ".text");
  if (text == nullptr) return {};
  const std::span<const std::byte> bytes = loader::section_bytes(image, *text);
  constexpr std::size_t kTake = 128 << 10;
  if (bytes.size() < 2 * kTake) return {};
  const std::size_t at = (bytes.size() / 2) & ~std::size_t{0xfff};
  return {bytes.begin() + static_cast<std::ptrdiff_t>(at), bytes.begin() + static_cast<std::ptrdiff_t>(at + kTake)};
}

#if defined(__x86_64__)
constexpr const char *kOwnLanguage = "x86:LE:64:";
constexpr const char *kOwnProcessor = "x86";
#elif defined(__aarch64__)
constexpr const char *kOwnLanguage = "AARCH64:LE:64:";
constexpr const char *kOwnProcessor = "AARCH64";
#else
constexpr const char *kOwnLanguage = "";
constexpr const char *kOwnProcessor = "";
#endif

class DetectLibrary : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    lift::initialize(REVKIT_GHIDRA_ROOT);
  }
};

TEST_F(DetectLibrary, HintsNarrowTheSearchAndUnknownOnesAreRefused) {
  pb::RawDetectHints h;
  DetectHints out;
  ASSERT_TRUE(ResolveDetectHints(h, out).ok());
  EXPECT_TRUE(out.processors.empty());
  EXPECT_TRUE(out.language.empty());

  h.set_language_id("ARM:LE:32:v4t");
  ASSERT_TRUE(ResolveDetectHints(h, out).ok());
  EXPECT_EQ(out.language, "ARM:LE:32:v4t");
  EXPECT_EQ(out.compiler, "");
  EXPECT_EQ(out.processors, std::vector<std::string>{"ARM"});
  h.set_language_id("ARM:LE:32:v4t:default");
  ASSERT_TRUE(ResolveDetectHints(h, out).ok());
  EXPECT_EQ(out.language, "ARM:LE:32:v4t");
  EXPECT_EQ(out.compiler, "default");
  // The language wins over a processor given beside it.
  h.set_processor("MIPS");
  ASSERT_TRUE(ResolveDetectHints(h, out).ok());
  EXPECT_EQ(out.processors, std::vector<std::string>{"ARM"});
  for (const char *bad : {"ARM", "ARM:LE:32", "NOPE:LE:32:x", "ARM:LE:32:v4t:nocompiler", "ARM:LE:32:v4t:default:more"}) {
    h.set_language_id(bad);
    EXPECT_EQ(ResolveDetectHints(h, out).code, StatusCode::kInvalidArgument) << bad;
  }

  h.Clear();
  h.set_processor("arm");  // case is ignored
  ASSERT_TRUE(ResolveDetectHints(h, out).ok());
  EXPECT_EQ(out.processors, std::vector<std::string>{"ARM"});
  EXPECT_TRUE(out.language.empty());
  h.set_processor("no such processor");
  EXPECT_EQ(ResolveDetectHints(h, out).code, StatusCode::kInvalidArgument);
}

// The detector's hooks (detect::Options::progress and cancel), which the
// RPC's progress and CancelRawDetect stand on.
TEST_F(DetectLibrary, TheDetectorReportsEachStageAndStopsWhenAsked) {
  const std::vector<std::byte> code = OwnCode();
  if (std::string(kOwnProcessor).empty() || code.empty()) GTEST_SKIP() << "no code of a known processor to read";
  detect::Options options;
  options.threads = 4;
  options.processors = {kOwnProcessor, "ARM", "MIPS", "PowerPC"};
  std::mutex mu;
  std::vector<detect::Progress> seen;
  options.progress = [&](const detect::Progress &p) {
    std::lock_guard lock(mu);
    seen.push_back(p);
  };
  const detect::Report whole = detect::detect(code, options);
  ASSERT_FALSE(whole.suggestions.empty());
  EXPECT_TRUE(whole.suggestions.front().language.starts_with(kOwnLanguage)) << whole.suggestions.front().language;
  ASSERT_GE(seen.size(), 3u);
  EXPECT_EQ(seen.front().stage, detect::Progress::Stage::segments);
  std::size_t total = 0, most = 0, sweeps = 0;
  for (const detect::Progress &p : seen) {
    if (p.stage != detect::Progress::Stage::sweep) continue;
    ++sweeps;
    total = p.total;
    most = std::max(most, p.done);
    EXPECT_LE(p.done, p.total);
  }
  EXPECT_GT(total, 3u);
  EXPECT_EQ(most, total);          // every candidate was reported
  EXPECT_EQ(sweeps, total + 1);    // once at the start, once each
  EXPECT_EQ(whole.sweeps.size(), total);

  // Stopped after the first few candidates: it returns early, and what it
  // returns is not an answer.
  seen.clear();
  std::atomic<int> asked{0};
  options.cancel = [&] { return asked.fetch_add(1) >= 6; };
  const detect::Report stopped = detect::detect(code, options);
  EXPECT_TRUE(stopped.suggestions.empty());
  EXPECT_FALSE(stopped.refusal);
  std::size_t done = 0;
  for (const detect::Progress &p : seen)
    if (p.stage == detect::Progress::Stage::sweep) done = std::max(done, p.done);
  EXPECT_LT(done, total);
  // Asked before it starts: nothing is decoded at all.
  seen.clear();
  options.cancel = [] { return true; };
  EXPECT_TRUE(detect::detect(code, options).suggestions.empty());
  for (const detect::Progress &p : seen) EXPECT_EQ(p.stage, detect::Progress::Stage::segments);
}

class RawDetectApi : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.analysis_threads = 4;
    backend_ = MakeImageBackend(o);
    alice_.caller = "user:alice";
    bob_.caller = "user:bob";
  }

  static pb::DetectRawLayoutRequest Request(const std::vector<std::byte> &content, const std::string &id = "") {
    pb::DetectRawLayoutRequest req;
    req.set_project_id("default");
    req.set_content(std::string(reinterpret_cast<const char *>(content.data()), content.size()));
    req.set_detect_id(id);
    return req;
  }

  api::Status Poll(const CallContext &who, const std::string &id, pb::GetRawDetectProgressResponse &resp) {
    pb::GetRawDetectProgressRequest req;
    req.set_project_id("default");
    req.set_detect_id(id);
    resp.Clear();
    return backend_->GetRawDetectProgress(who, req, resp);
  }

  std::shared_ptr<api::Backend> backend_;
  CallContext alice_, bob_;
};

TEST_F(RawDetectApi, RefusesWhatIsNoProgramWithTheReason) {
  pb::GetServerInfoResponse si;
  ASSERT_TRUE(backend_->GetServerInfo(alice_, {}, si).ok());
  EXPECT_GE(si.api_minor(), 23u);
  EXPECT_NE(std::find(si.features().begin(), si.features().end(), "raw-detect"), si.features().end());

  pb::DetectRawLayoutResponse resp;
  ASSERT_TRUE(backend_->DetectRawLayout(alice_, Request(Noise(1 << 16), "noise"), resp).ok());
  ASSERT_TRUE(resp.has_refusal());
  EXPECT_EQ(resp.refusal().reason(), "high-entropy");
  EXPECT_FALSE(resp.refusal().detail().empty());
  EXPECT_EQ(resp.suggestions_size(), 0);
  ASSERT_EQ(resp.segments_size(), 1);
  EXPECT_EQ(resp.segments(0).kind(), pb::RAW_SEGMENT_KIND_HIGH_ENTROPY);
  EXPECT_EQ(resp.segments(0).size(), 1u << 16);
  EXPECT_EQ(resp.file_size(), 1u << 16);
  // Its progress ends done, whole, and says what was found.
  pb::GetRawDetectProgressResponse p;
  ASSERT_TRUE(Poll(alice_, "noise", p).ok());
  EXPECT_TRUE(p.done());
  EXPECT_EQ(p.progress(), 1);
  EXPECT_TRUE(p.error().empty());
  EXPECT_NE(p.message().find("high-entropy"), std::string::npos) << p.message();

  resp.Clear();
  ASSERT_TRUE(backend_->DetectRawLayout(alice_, Request(std::vector<std::byte>(1 << 16, std::byte{0xff})), resp).ok());
  EXPECT_EQ(resp.refusal().reason(), "not-code");
  resp.Clear();
  ASSERT_TRUE(backend_->DetectRawLayout(alice_, Request(std::vector<std::byte>(16, std::byte{0x12})), resp).ok());
  EXPECT_EQ(resp.refusal().reason(), "too-small");
}

TEST_F(RawDetectApi, NamesAFileAsAnImportDoesAndChecksItFirst) {
  const fs::path dir = testing::scratch_dir("raw-detect");
  const fs::path file = dir / "noise.bin";
  const std::vector<std::byte> noise = Noise(1 << 14);
  std::ofstream(file, std::ios::binary).write(reinterpret_cast<const char *>(noise.data()), static_cast<std::streamsize>(noise.size()));

  // By path, as an import reads one.
  pb::DetectRawLayoutRequest req;
  req.set_project_id("default");
  req.set_path(file.string());
  req.set_detect_id("by-path");
  pb::DetectRawLayoutResponse resp;
  ASSERT_TRUE(backend_->DetectRawLayout(alice_, req, resp).ok());
  EXPECT_EQ(resp.refusal().reason(), "high-entropy");
  EXPECT_EQ(resp.file_size(), noise.size());
  // Nothing was imported.
  pb::ListProgramsRequest list;
  list.set_project_id("default");
  pb::ListProgramsResponse programs;
  ASSERT_TRUE(backend_->ListPrograms(alice_, list, programs).ok());
  EXPECT_EQ(programs.programs_size(), 0);

  auto code = [&](const pb::DetectRawLayoutRequest &r) {
    pb::DetectRawLayoutResponse out;
    return backend_->DetectRawLayout(alice_, r, out).code;
  };
  req.set_detect_id("");
  req.set_path((dir / "no such file").string());
  EXPECT_EQ(code(req), StatusCode::kNotFound);
  req.set_path(dir.string());  // a directory is no file
  EXPECT_EQ(code(req), StatusCode::kNotFound);
  req.clear_source();
  EXPECT_EQ(code(req), StatusCode::kInvalidArgument);
  req.set_path(file.string());
  req.set_project_id("no-such-project");
  EXPECT_EQ(code(req), StatusCode::kNotFound);
  req.set_project_id("default");
  req.mutable_hints()->set_language_id("NOPE:LE:32:x");
  EXPECT_EQ(code(req), StatusCode::kInvalidArgument);
  req.mutable_hints()->Clear();
  req.mutable_hints()->set_processor("no such processor");
  EXPECT_EQ(code(req), StatusCode::kInvalidArgument);
  req.mutable_hints()->Clear();
  req.set_detect_id(std::string(129, 'x'));
  EXPECT_EQ(code(req), StatusCode::kInvalidArgument);
  // A failure is recorded for whoever follows it.
  req.set_detect_id("missing");
  req.set_path((dir / "no such file").string());
  EXPECT_EQ(code(req), StatusCode::kNotFound);
  pb::GetRawDetectProgressResponse p;
  ASSERT_TRUE(Poll(alice_, "missing", p).ok());
  EXPECT_TRUE(p.done());
  EXPECT_NE(p.error().find("cannot read"), std::string::npos) << p.error();
  EXPECT_FALSE(p.cancelled());
}

TEST_F(RawDetectApi, SuggestsThisProgramsOwnCodeWhilePolledAndTheSuggestionImports) {
  const std::vector<std::byte> code = OwnCode();
  if (std::string(kOwnProcessor).empty() || code.empty()) GTEST_SKIP() << "no code of a known processor to read";
  pb::DetectRawLayoutRequest req = Request(code, "own");
  req.mutable_hints()->set_processor(kOwnProcessor);  // quick under the sanitizers
  pb::DetectRawLayoutResponse resp;
  api::Status status;
  std::atomic<bool> finished{false};
  std::thread detector([&] {
    status = backend_->DetectRawLayout(alice_, req, resp);
    finished = true;
  });
  std::vector<pb::GetRawDetectProgressResponse> seen;
  int bob_saw = 0;
  while (!finished) {
    pb::GetRawDetectProgressResponse r;
    if (Poll(alice_, "own", r).ok()) seen.push_back(r);
    if (Poll(bob_, "own", r).ok()) ++bob_saw;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  detector.join();
  ASSERT_TRUE(status.ok()) << status.message;
  pb::GetRawDetectProgressResponse last;
  ASSERT_TRUE(Poll(alice_, "own", last).ok());
  seen.push_back(last);
  EXPECT_EQ(bob_saw, 0);
  EXPECT_EQ(Poll(bob_, "own", last).code, StatusCode::kNotFound);

  bool swept = false;
  for (std::size_t i = 0; i < seen.size(); ++i) {
    swept |= seen[i].phase() == pb::RAW_DETECT_PHASE_PROCESSOR && seen[i].candidates_total() > 0;
    if (i == 0) continue;
    EXPECT_GE(seen[i].phase(), seen[i - 1].phase()) << seen[i].message();
    EXPECT_GE(seen[i].progress(), seen[i - 1].progress()) << seen[i].message();
    EXPECT_GE(seen[i].candidates_done(), seen[i - 1].candidates_done());
  }
  EXPECT_TRUE(swept) << seen.size() << " polls never saw the candidates being decoded";
  last = seen.back();
  EXPECT_TRUE(last.done());
  EXPECT_TRUE(last.error().empty());
  EXPECT_FALSE(last.cancelled());
  EXPECT_EQ(last.phase(), pb::RAW_DETECT_PHASE_DONE);
  EXPECT_EQ(last.progress(), 1);
  EXPECT_EQ(last.candidates_done(), last.candidates_total());
  EXPECT_NE(last.message().find("Detected "), std::string::npos) << last.message();

  EXPECT_FALSE(resp.has_refusal()) << resp.refusal().reason();
  ASSERT_GE(resp.suggestions_size(), 1);
  const pb::RawLayoutSuggestion &top = resp.suggestions(0);
  EXPECT_EQ(top.options().format(), "raw");
  EXPECT_TRUE((top.options().language_id() + ":").starts_with(kOwnLanguage)) << top.options().language_id();
  EXPECT_FALSE(top.options().compiler_spec_id().empty());
  EXPECT_NE(top.processor_confidence(), pb::DETECT_CONFIDENCE_UNSPECIFIED);
  EXPECT_NE(top.base_confidence(), pb::DETECT_CONFIDENCE_UNSPECIFIED);
  ASSERT_GE(top.evidence_size(), 1);
  EXPECT_EQ(top.evidence(0).about(), "processor");
  EXPECT_NE(top.evidence(0).text().find("instructions decode"), std::string::npos) << top.evidence(0).text();
  EXPECT_GT(top.score(), 0);
  EXPECT_EQ(resp.file_size(), code.size());
  EXPECT_GT(resp.elapsed_seconds(), 0);
  std::uint64_t covered = 0;
  for (const pb::RawFileSegment &s : resp.segments()) {
    EXPECT_EQ(s.offset(), covered);
    covered += s.size();
  }
  EXPECT_EQ(covered, code.size());

  // The options are ready for a raw import as they are; nothing was
  // imported until now.
  pb::ListProgramsRequest list;
  list.set_project_id("default");
  pb::ListProgramsResponse programs;
  ASSERT_TRUE(backend_->ListPrograms(alice_, list, programs).ok());
  EXPECT_EQ(programs.programs_size(), 0);
  pb::ImportProgramRequest import;
  import.set_project_id("default");
  import.set_content(req.content().substr(0, 16 << 10));  // a piece: discovery on all of it takes a while
  import.set_name("own-code");
  *import.mutable_options() = top.options();
  pb::ImportProgramResponse imported;
  const api::Status st = backend_->ImportProgram(alice_, import, imported);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(imported.program().format(), "raw");
  EXPECT_EQ(imported.program().language_id(), top.options().language_id());
}

TEST_F(RawDetectApi, IsStoppedByItsCallerOrWhenTheCallerLeaves) {
  const std::vector<std::byte> code = OwnCode();
  if (code.empty()) GTEST_SKIP() << "no code to read";
  // Every language is tried: long enough to stop it half way.
  pb::DetectRawLayoutResponse resp;
  api::Status status;
  std::thread detector([&] { status = backend_->DetectRawLayout(alice_, Request(code, "stop-me"), resp); });
  pb::GetRawDetectProgressResponse p;
  for (int i = 0; i < 60000; ++i) {
    if (Poll(alice_, "stop-me", p).ok() && (p.candidates_done() >= 1 || p.done())) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  ASSERT_GE(p.candidates_done(), 1u);
  ASSERT_FALSE(p.done()) << "it ended before it could be stopped";
  pb::CancelRawDetectRequest cancel;
  cancel.set_project_id("default");
  cancel.set_detect_id("stop-me");
  pb::CancelRawDetectResponse cancelled;
  // Not by someone else.
  EXPECT_EQ(backend_->CancelRawDetect(bob_, cancel, cancelled).code, StatusCode::kNotFound);
  ASSERT_TRUE(backend_->CancelRawDetect(alice_, cancel, cancelled).ok());
  detector.join();
  EXPECT_EQ(status.code, StatusCode::kCancelled);
  EXPECT_EQ(resp.suggestions_size(), 0);
  ASSERT_TRUE(Poll(alice_, "stop-me", p).ok());
  EXPECT_TRUE(p.done());
  EXPECT_TRUE(p.cancelled());
  EXPECT_TRUE(p.error().empty());
  EXPECT_LT(p.progress(), 1);
  EXPECT_LT(p.candidates_done(), p.candidates_total());
  // Stopping what has ended, or what never was, changes nothing.
  EXPECT_TRUE(backend_->CancelRawDetect(alice_, cancel, cancelled).ok());
  cancel.set_detect_id("never");
  EXPECT_EQ(backend_->CancelRawDetect(alice_, cancel, cancelled).code, StatusCode::kNotFound);

  // A caller that goes away (the transport says so) stops it too, with or
  // without an id.
  std::atomic<int> asked{0};
  CallContext leaving = alice_;
  leaving.cancelled = [&] { return asked.fetch_add(1) >= 3; };
  resp.Clear();
  EXPECT_EQ(backend_->DetectRawLayout(leaving, Request(code), resp).code, StatusCode::kCancelled);
  EXPECT_EQ(resp.suggestions_size(), 0);
}

}  // namespace
}  // namespace revkit::backend
