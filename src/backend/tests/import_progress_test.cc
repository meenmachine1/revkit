// An import's progress (api_minor 22, feature "import-progress";
// import_progress.h): phases in order, a fraction that never goes back and
// ends at 1, only for the caller that started it; and on the image backend,
// a raw firmware import followed by GetImportProgress from another thread.
#include "builders.hh"
#include "import_progress.h"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <thread>
#include <vector>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;
using api::CallContext;
using api::StatusCode;

ImportCosts SomeCosts() {
  ImportFacts f;
  f.file_bytes = 4 << 20;
  f.code_bytes = 3 << 20;
  f.debug_bytes = 1 << 20;
  f.parsed = true;
  f.parallel = true;
  f.persistent = true;
  return ImportCosts::estimate(f);
}

pb::GetImportProgressResponse Read(ImportProgress &p) {
  pb::GetImportProgressResponse r;
  p.Fill(r);
  return r;
}

TEST(ImportProgressUnit, PhasesAdvanceInOrderAndTheFractionEndsAtOne) {
  ImportProgress p("user:alice", "default", "id1");
  EXPECT_EQ(Read(p).progress(), -1);  // nothing started: unknown
  p.Plan(SomeCosts());
  std::vector<pb::GetImportProgressResponse> seen;
  auto sample = [&] {
    seen.push_back(Read(p));
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    seen.push_back(Read(p));
  };
  p.Enter(pb::IMPORT_PHASE_READING, "Reading");
  sample();
  p.Enter(pb::IMPORT_PHASE_LOADING, "Loading");
  sample();
  p.Enter(pb::IMPORT_PHASE_DEBUG_INFO, "Reading DWARF debug info");
  sample();
  auto discovery = std::make_shared<analysis::DiscoveryProgress>();
  p.Enter(pb::IMPORT_PHASE_FUNCTIONS, "Disassembling");
  p.Track(discovery, 3 << 20, false, 0.93);
  for (int i = 1; i <= 4; ++i) {
    discovery->stage = analysis::DiscoveryProgress::Stage::walking;
    discovery->functions = 1000u * static_cast<unsigned>(i);
    discovery->decoded_bytes.store(static_cast<std::uint64_t>(i) << 19);
    sample();
  }
  EXPECT_EQ(seen.back().message(), "Finding functions: 4,000 found");
  EXPECT_EQ(seen.back().functions_found(), 4000u);
  p.SetFunctions(4000);
  p.Step(0.93, "Following references", 0.01);
  sample();
  p.Enter(pb::IMPORT_PHASE_DATA, "Finding strings and pointers");
  sample();
  p.Enter(pb::IMPORT_PHASE_SAVING, "Saving to the project");
  sample();
  p.Finish("Imported: 4,000 functions");
  seen.push_back(Read(p));

  for (std::size_t i = 1; i < seen.size(); ++i) {
    EXPECT_GE(seen[i].phase(), seen[i - 1].phase()) << i;
    EXPECT_GE(seen[i].progress(), seen[i - 1].progress()) << i << ": " << seen[i].message();
    EXPECT_GE(seen[i].progress(), 0);
    EXPECT_LE(seen[i].progress(), 1);
  }
  EXPECT_LT(seen[seen.size() - 2].progress(), 1);
  const auto &last = seen.back();
  EXPECT_TRUE(last.done());
  EXPECT_EQ(last.phase(), pb::IMPORT_PHASE_DONE);
  EXPECT_EQ(last.progress(), 1);
  EXPECT_TRUE(last.error().empty());
  EXPECT_EQ(last.functions_found(), 4000u);
  // Phases out of order are ignored (the phase never goes back).
  p.Enter(pb::IMPORT_PHASE_READING, "again");
  EXPECT_EQ(Read(p).phase(), pb::IMPORT_PHASE_DONE);
}

TEST(ImportProgressUnit, SharesFollowTheCostsAndSkippedPhasesGetNone) {
  ImportCosts c;
  c.reading = 1;
  c.loading = 1;
  c.functions = 6;
  c.data = 2;  // no debug info, nothing to save
  ImportProgress p("anonymous", "default", "id");
  p.Plan(c);
  p.Enter(pb::IMPORT_PHASE_READING, "");
  p.Enter(pb::IMPORT_PHASE_LOADING, "");
  EXPECT_NEAR(Read(p).progress(), 0.1, 0.01);
  p.Enter(pb::IMPORT_PHASE_FUNCTIONS, "");
  EXPECT_NEAR(Read(p).progress(), 0.2, 0.01);
  p.Enter(pb::IMPORT_PHASE_DATA, "");
  EXPECT_NEAR(Read(p).progress(), 0.8, 0.01);
  // A re-plan changes only what is still to come.
  c.data = 100;
  p.Plan(c);
  EXPECT_GE(Read(p).progress(), 0.8);
}

TEST(ImportProgressUnit, ElapsedTimeMovesAPhaseButNeverFinishesIt) {
  ImportCosts c;
  c.loading = 0.001;  // far shorter than it will take
  c.functions = 1;
  ImportProgress p("anonymous", "default", "id");
  p.Plan(c);
  p.Enter(pb::IMPORT_PHASE_LOADING, "");
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  const float share = static_cast<float>(0.001 / 1.001);
  EXPECT_GT(Read(p).progress(), 0.8 * share);
  EXPECT_LT(Read(p).progress(), share);
}

TEST(ImportProgressUnit, AFailureKeepsTheFractionAndSaysWhy) {
  ImportProgress p("anonymous", "default", "id");
  p.Plan(SomeCosts());
  p.Enter(pb::IMPORT_PHASE_READING, "");
  p.Enter(pb::IMPORT_PHASE_LOADING, "");
  const float before = Read(p).progress();
  p.Fail("cannot load: not ELF");
  auto r = Read(p);
  EXPECT_TRUE(r.done());
  EXPECT_EQ(r.error(), "cannot load: not ELF");
  EXPECT_EQ(r.phase(), pb::IMPORT_PHASE_LOADING);
  EXPECT_GE(r.progress(), before);
  EXPECT_LT(r.progress(), 1);
  p.Finish("too late");
  EXPECT_FALSE(Read(p).error().empty());
}

TEST(ImportProgressUnit, OnlyTheCallerThatStartedAnImportCanReadIt) {
  ImportProgressRegistry reg;
  std::shared_ptr<ImportProgress> p;
  ASSERT_TRUE(reg.Start("user:alice", "default", "abc", p).ok());
  p->Plan(SomeCosts());
  p->Enter(pb::IMPORT_PHASE_READING, "Reading");
  pb::GetImportProgressRequest req;
  req.set_project_id("default");
  req.set_import_id("abc");
  pb::GetImportProgressResponse resp;
  EXPECT_TRUE(reg.Get("user:alice", req, resp).ok());
  EXPECT_EQ(resp.phase(), pb::IMPORT_PHASE_READING);
  EXPECT_EQ(resp.message(), "Reading");
  // Anyone else, admins included, sees nothing; nor does another project.
  EXPECT_EQ(reg.Get("user:bob", req, resp).code, StatusCode::kNotFound);
  EXPECT_EQ(reg.Get("anonymous", req, resp).code, StatusCode::kNotFound);
  req.set_project_id("other");
  EXPECT_EQ(reg.Get("user:alice", req, resp).code, StatusCode::kNotFound);
  req.set_project_id("default");
  // One running import per (caller, id); another caller may use the id.
  std::shared_ptr<ImportProgress> q;
  EXPECT_EQ(reg.Start("user:alice", "default", "abc", q).code, StatusCode::kAlreadyExists);
  ASSERT_TRUE(reg.Start("user:bob", "default", "abc", q).ok());
  q->Plan(SomeCosts());
  q->Enter(pb::IMPORT_PHASE_LOADING, "Bob's");
  ASSERT_TRUE(reg.Get("user:alice", req, resp).ok());
  EXPECT_EQ(resp.message(), "Reading");
  // Once it has ended, it is kept to be read, and the id can be used again.
  p->Finish("done");
  ASSERT_TRUE(reg.Get("user:alice", req, resp).ok());
  EXPECT_TRUE(resp.done());
  EXPECT_TRUE(reg.Start("user:alice", "default", "abc", p).ok());
  EXPECT_EQ(reg.Start("user:alice", "default", std::string(129, 'x'), p).code, StatusCode::kInvalidArgument);
  EXPECT_EQ(reg.Start("user:alice", "default", "a\nb", p).code, StatusCode::kInvalidArgument);
}

TEST(ImportProgressUnit, EndedImportsBeyondTheBoundAreDropped) {
  ImportProgressRegistry reg;
  for (std::size_t i = 0; i < ImportProgressRegistry::kMaxPerCaller + 5; ++i) {
    std::shared_ptr<ImportProgress> p;
    ASSERT_TRUE(reg.Start("user:alice", "default", "id" + std::to_string(i), p).ok());
    p->Finish("done");
  }
  std::shared_ptr<ImportProgress> p;
  ASSERT_TRUE(reg.Start("user:alice", "default", "last", p).ok());
  pb::GetImportProgressRequest req;
  req.set_project_id("default");
  pb::GetImportProgressResponse resp;
  req.set_import_id("id0");
  EXPECT_EQ(reg.Get("user:alice", req, resp).code, StatusCode::kNotFound);
  req.set_import_id("id" + std::to_string(ImportProgressRegistry::kMaxPerCaller + 4));
  EXPECT_TRUE(reg.Get("user:alice", req, resp).ok());
}

// Discovery's threads write the atomics while readers poll: no data race
// (the tsan preset), and the fraction still never goes back.
TEST(ImportProgressUnit, ReadersAndDiscoveryThreadsRunConcurrently) {
  ImportProgress p("anonymous", "default", "id");
  ImportCosts c;
  c.functions = 0.01;
  c.data = 0.01;
  p.Plan(c);
  auto discovery = std::make_shared<analysis::DiscoveryProgress>();
  p.Enter(pb::IMPORT_PHASE_FUNCTIONS, "");
  p.Track(discovery, 1 << 20, true, 0.93);
  std::atomic<bool> stop{false};
  std::vector<std::thread> writers;
  for (int t = 0; t < 4; ++t)
    writers.emplace_back([&] {
      for (std::uint64_t i = 0; !stop; ++i) {
        discovery->decoded_bytes.fetch_add(64, std::memory_order_relaxed);
        discovery->flows.fetch_add(1, std::memory_order_relaxed);
        discovery->functions.store(i, std::memory_order_relaxed);
        using Stage = analysis::DiscoveryProgress::Stage;
        discovery->stage.store(i % 3 == 0 ? Stage::flows : i % 2 ? Stage::search : Stage::walking,
                               std::memory_order_relaxed);
      }
    });
  std::vector<std::thread> readers;
  std::atomic<int> backwards{0};
  for (int t = 0; t < 3; ++t)
    readers.emplace_back([&] {
      float last = 0;
      for (int i = 0; i < 2000; ++i) {
        auto r = Read(p);
        if (r.progress() < last) ++backwards;
        last = r.progress();
      }
    });
  for (auto &t : readers) t.join();
  p.Step(0.93, "references", 0.001);
  p.Enter(pb::IMPORT_PHASE_DATA, "");
  stop = true;
  for (auto &t : writers) t.join();
  p.Finish("done");
  EXPECT_EQ(backwards.load(), 0);
  EXPECT_EQ(Read(p).progress(), 1);
}

TEST(ImportProgressUnit, RawFirmwareIsMostlyDiscovery) {
  ImportFacts raw;
  raw.file_bytes = raw.code_bytes = 1300 << 10;
  raw.parsed = raw.raw = true;
  const ImportCosts r = ImportCosts::estimate(raw);
  EXPECT_GT(r.functions, 5 * (r.reading + r.loading + r.data));
  EXPECT_EQ(r.debug_info, 0);
  EXPECT_EQ(r.saving, 0);
  EXPECT_EQ(Thousands(3120), "3,120");
  EXPECT_EQ(Thousands(999), "999");
  EXPECT_EQ(Thousands(1234567), "1,234,567");
}

// On the image backend: a raw ARM image scaled up with bulk functions
// (armfw's build.sh), imported in one thread while another polls.
class ImportProgressApi : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty() || std::string(REVKIT_TEST_CLANG).empty() ||
        std::string(REVKIT_TEST_LLD).empty() || std::string(REVKIT_TEST_OBJCOPY).empty())
      return;
    dir_ = testing::scratch_dir("import-progress");
    const std::string cmd = std::string("sh ") + REVKIT_ARMFW_DIR + "/build.sh " + REVKIT_TEST_CLANG + " " +
                            REVKIT_TEST_LLD + " " + REVKIT_TEST_OBJCOPY + " " + (dir_ / "fw").string() +
                            " -O2 1500 >/dev/null 2>&1";
    built_ = std::system(cmd.c_str()) == 0;
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!built_) GTEST_SKIP() << "no clang, ld.lld, llvm-objcopy and python3";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.project_dir = (dir_ / ("projects-" + std::to_string(++run_))).string();
    backend_ = MakeImageBackend(o);
  }

  static pb::ImportProgramRequest Request(const std::string &id) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path((dir_ / "fw" / "fw.bin").string());
    req.set_name("fw");
    req.set_import_id(id);
    req.mutable_options()->set_format("raw");
    req.mutable_options()->set_language_id("ARM:LE:32:v4t");
    return req;
  }

  api::Status Poll(const CallContext &who, const std::string &id, pb::GetImportProgressResponse &resp) {
    pb::GetImportProgressRequest req;
    req.set_project_id("default");
    req.set_import_id(id);
    resp.Clear();
    return backend_->GetImportProgress(who, req, resp);
  }

  static inline fs::path dir_;
  static inline bool built_ = false;
  static inline int run_ = 0;
  std::shared_ptr<api::Backend> backend_;
};

TEST_F(ImportProgressApi, PhasesAdvanceInOrderWhileItImports) {
  CallContext alice, bob;
  alice.caller = "user:alice";
  bob.caller = "user:bob";
  pb::GetServerInfoResponse si;
  ASSERT_TRUE(backend_->GetServerInfo(alice, {}, si).ok());
  EXPECT_GE(si.api_minor(), 22u);
  EXPECT_NE(std::find(si.features().begin(), si.features().end(), "import-progress"), si.features().end());

  pb::ImportProgramResponse imported;
  api::Status status;
  std::atomic<bool> finished{false};
  std::thread importer([&] {
    status = backend_->ImportProgram(alice, Request("fw-1"), imported);
    finished = true;
  });
  std::vector<pb::GetImportProgressResponse> seen;
  int bob_saw = 0;
  while (!finished) {
    pb::GetImportProgressResponse r;
    if (Poll(alice, "fw-1", r).ok()) seen.push_back(r);
    if (Poll(bob, "fw-1", r).ok()) ++bob_saw;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  importer.join();
  ASSERT_TRUE(status.ok()) << status.message;
  pb::GetImportProgressResponse last;
  ASSERT_TRUE(Poll(alice, "fw-1", last).ok());
  seen.push_back(last);
  EXPECT_EQ(bob_saw, 0);
  EXPECT_EQ(Poll(bob, "fw-1", last).code, StatusCode::kNotFound);

  bool functions = false;
  for (std::size_t i = 0; i < seen.size(); ++i) {
    functions |= seen[i].phase() == pb::IMPORT_PHASE_FUNCTIONS;
    if (i == 0) continue;
    EXPECT_GE(seen[i].phase(), seen[i - 1].phase()) << seen[i].message();
    EXPECT_GE(seen[i].progress(), seen[i - 1].progress()) << seen[i].message();
  }
  EXPECT_TRUE(functions) << seen.size() << " polls never saw function discovery";
  last = seen.back();
  EXPECT_TRUE(last.done());
  EXPECT_TRUE(last.error().empty());
  EXPECT_EQ(last.phase(), pb::IMPORT_PHASE_DONE);
  EXPECT_EQ(last.progress(), 1);
  EXPECT_EQ(last.program_id(), imported.program().program_id());
  EXPECT_GT(last.functions_found(), 1000u);
  EXPECT_NE(last.message().find("functions"), std::string::npos) << last.message();
}

TEST_F(ImportProgressApi, AFailedImportSaysWhy) {
  CallContext alice;
  alice.caller = "user:alice";
  auto req = Request("broken");
  req.set_path((dir_ / "no such file").string());
  pb::ImportProgramResponse resp;
  EXPECT_EQ(backend_->ImportProgram(alice, req, resp).code, StatusCode::kNotFound);
  pb::GetImportProgressResponse r;
  ASSERT_TRUE(Poll(alice, "broken", r).ok());
  EXPECT_TRUE(r.done());
  EXPECT_NE(r.error().find("cannot read"), std::string::npos) << r.error();
  // Without an id nothing is recorded, and the import works as before.
  req = Request("");
  ASSERT_TRUE(backend_->ImportProgram(alice, req, resp).ok());
  EXPECT_EQ(Poll(alice, "", r).code, StatusCode::kNotFound);
}

}  // namespace
}  // namespace revkit::backend
