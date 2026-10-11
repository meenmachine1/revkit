// api_minor 19 on the image backend: renaming and (softly) deleting
// programs, the function list's filters and sorts, FindTypes for a category
// tree, and function graphs of code with delay slots (MIPS).
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <thread>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

constexpr const char *kProgram = R"(
#include <stdio.h>
int counter;
struct pair { int a, b; };
__attribute__((noinline)) unsigned checksum(const unsigned char *p, int n) {
  unsigned h = 0x811c9dc5;
  for (int i = 0; i < n; i++) h = (h ^ p[i]) * 0x1000193;
  counter++;
  return h;
}
__attribute__((noinline)) int twice(int x) { return checksum((const unsigned char *)&x, 4) * 2; }
__attribute__((noinline)) int sum(struct pair *p) { return p->a + p->b; }
int main(int argc, char **argv) {
  struct pair q = {argc, 2};
  unsigned r = checksum((const unsigned char *)argv[0], argc);
  printf("%u %d %d\n", r, twice(argc), sum(&q));
  return (int)r;
}
)";

class Sink : public api::EventSink {
 public:
  void Send(pb::SubscribeResponse event) override {
    std::lock_guard lock(mu_);
    if (event.has_revision()) events_.push_back(event.revision());
  }
  void End(api::Status) override {}
  std::vector<pb::RevisionEvent> revisions() {
    std::lock_guard lock(mu_);
    return events_;
  }

 private:
  std::mutex mu_;
  std::vector<pb::RevisionEvent> events_;
};

class ProgramManagementTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("program-management");
    exe_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O1 -g", exe_);
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!compiled_) GTEST_SKIP() << "no C compiler";
    Make({});
  }

  void Make(const std::filesystem::path &project_dir) {
    backend_.reset();
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.project_dir = project_dir.string();
    backend_ = MakeImageBackend(o);
  }

  std::string Import(const std::string &name) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(exe_.string());
    req.set_name(name);
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  std::vector<pb::ProgramInfo> Programs(bool include_deleted = false) {
    pb::ListProgramsRequest req;
    req.set_project_id("default");
    req.set_include_deleted(include_deleted);
    pb::ListProgramsResponse resp;
    EXPECT_TRUE(backend_->ListPrograms(ctx_, req, resp).ok());
    return {resp.programs().begin(), resp.programs().end()};
  }

  static pb::Provenance User(const std::string &who) {
    pb::Provenance p;
    p.set_kind(pb::PROVENANCE_KIND_USER);
    p.set_id(who);
    return p;
  }

  api::Status Retract(const std::string &program, std::uint64_t seq) {
    pb::RetractAssertionsRequest req;
    req.set_program_id(program);
    req.add_seqs(seq);
    *req.mutable_provenance() = User("alice");
    pb::RetractAssertionsResponse resp;
    return backend_->RetractAssertions(ctx_, req, resp);
  }

  std::vector<pb::Function> Functions(const std::string &program, pb::ListFunctionsRequest req = {}) {
    req.set_program_id(program);
    req.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse resp;
    auto st = backend_->ListFunctions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return {resp.functions().begin(), resp.functions().end()};
  }

  static inline std::filesystem::path exe_;
  static inline bool compiled_ = false;
  std::unique_ptr<api::Backend> backend_;
  CallContext ctx_;
};

TEST_F(ProgramManagementTest, ServerInfoListsTheFeatures) {
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_GE(info.api_minor(), 19u);
  for (const char *f : {"program-management", "function-list-filters", "find-types-tree"})
    EXPECT_NE(std::find(info.features().begin(), info.features().end(), f), info.features().end()) << f;
}

TEST_F(ProgramManagementTest, RenameIsAnUndoableAssertion) {
  const std::string id = Import("prog");
  auto sink = std::make_shared<Sink>();
  pb::SubscribeRequest sub;
  sub.set_project_id("default");
  std::unique_ptr<api::Subscription> subscription;
  ASSERT_TRUE(backend_->Subscribe(ctx_, sub, sink, subscription).ok());

  pb::RenameProgramRequest req;
  req.set_program_id(id);
  req.set_name("server v2");
  *req.mutable_provenance() = User("alice");
  pb::RenameProgramResponse resp;
  ASSERT_TRUE(backend_->RenameProgram(ctx_, req, resp).ok());
  EXPECT_EQ(resp.program().program_id(), id);  // ids never change
  EXPECT_EQ(resp.program().name(), "server v2");
  EXPECT_EQ(resp.program().name_origin().asserted().provenance().id(), "alice");
  EXPECT_EQ(resp.assertion().key().program_id(), id);
  EXPECT_EQ(resp.assertion().key().sub(), "revkit:program.name");
  ASSERT_EQ(Programs().size(), 1u);
  EXPECT_EQ(Programs()[0].name(), "server v2");

  // Reads pinned before the rename still see the old name.
  pb::ListProgramsRequest old;
  old.set_project_id("default");
  old.mutable_read()->set_revision(resp.snapshot().revision() - 1);
  pb::ListProgramsResponse old_resp;
  ASSERT_TRUE(backend_->ListPrograms(ctx_, old, old_resp).ok());
  EXPECT_EQ(old_resp.programs(0).name(), "prog");

  // Subscribers hear of it as a PROGRAM invalidation.
  bool heard = false;
  for (const auto &ev : sink->revisions())
    for (const auto &q : ev.invalidated()) heard |= q.kind() == pb::QUERY_KIND_PROGRAM && q.program_id() == id;
  EXPECT_TRUE(heard);

  // Blame by the API's key.
  pb::BlameRequest blame;
  *blame.mutable_key() = resp.assertion().key();
  blame.mutable_key()->set_program_id(id);
  pb::BlameResponse blamed;
  ASSERT_TRUE(backend_->Blame(ctx_, blame, blamed).ok());
  ASSERT_GE(blamed.candidates_size(), 1);
  EXPECT_EQ(blamed.candidates(0).body().note().text(), "server v2");

  // Undo is a retraction.
  ASSERT_TRUE(Retract(id, resp.assertion().seq()).ok());
  EXPECT_EQ(Programs()[0].name(), "prog");

  // Bad names.
  for (const char *bad : {"a/b", "tab\there"}) {
    req.set_name(bad);
    EXPECT_EQ(backend_->RenameProgram(ctx_, req, resp).code, StatusCode::kInvalidArgument) << bad;
  }
  // The reserved note tags.
  pb::AppendAssertionsRequest note;
  note.set_program_id(id);
  *note.mutable_provenance() = User("alice");
  note.add_assertions()->mutable_body()->mutable_note()->set_tag("revkit:program.deleted");
  pb::AppendAssertionsResponse noted;
  EXPECT_EQ(backend_->AppendAssertions(ctx_, note, noted).code, StatusCode::kInvalidArgument);
}

TEST_F(ProgramManagementTest, DeleteHidesTheProgramAndARetractionRestoresIt) {
  const std::string keep = Import("keep");
  const std::string gone = Import("leftover");
  ASSERT_EQ(Programs().size(), 2u);

  pb::DeleteProgramRequest del;
  del.set_program_id(gone);
  pb::DeleteProgramResponse deleted;
  EXPECT_EQ(backend_->DeleteProgram(ctx_, del, deleted).code, StatusCode::kInvalidArgument);  // no provenance
  *del.mutable_provenance() = User("alice");
  ASSERT_TRUE(backend_->DeleteProgram(ctx_, del, deleted).ok());
  EXPECT_EQ(backend_->DeleteProgram(ctx_, del, deleted).code, StatusCode::kFailedPrecondition);

  auto listed = Programs();
  ASSERT_EQ(listed.size(), 1u);
  EXPECT_EQ(listed[0].program_id(), keep);
  auto all = Programs(true);
  ASSERT_EQ(all.size(), 2u);
  const auto &trash = all[0].program_id() == gone ? all[0] : all[1];
  EXPECT_TRUE(trash.deleted());
  EXPECT_EQ(trash.deleted_origin().asserted().seq(), deleted.assertion().seq());

  pb::ListProjectsResponse projects;
  ASSERT_TRUE(backend_->ListProjects(ctx_, {}, projects).ok());
  EXPECT_EQ(projects.projects(0).program_count(), 1u);

  // Its data is kept: the id still answers reads.
  EXPECT_FALSE(Functions(gone).empty());
  // A deleted program can't be renamed.
  pb::RenameProgramRequest ren;
  ren.set_program_id(gone);
  ren.set_name("x");
  *ren.mutable_provenance() = User("alice");
  pb::RenameProgramResponse renamed;
  EXPECT_EQ(backend_->RenameProgram(ctx_, ren, renamed).code, StatusCode::kFailedPrecondition);

  ASSERT_TRUE(Retract(gone, deleted.assertion().seq()).ok());
  EXPECT_EQ(Programs().size(), 2u);
}

TEST_F(ProgramManagementTest, RenameAndDeleteSurviveAReopen) {
  auto dir = testing::scratch_dir("program-management-persist");
  Make(dir);
  const std::string a = Import("a");
  const std::string b = Import("b");
  pb::RenameProgramRequest ren;
  ren.set_program_id(a);
  ren.set_name("renamed");
  *ren.mutable_provenance() = User("alice");
  pb::RenameProgramResponse renamed;
  ASSERT_TRUE(backend_->RenameProgram(ctx_, ren, renamed).ok());
  pb::DeleteProgramRequest del;
  del.set_program_id(b);
  *del.mutable_provenance() = User("alice");
  pb::DeleteProgramResponse deleted;
  ASSERT_TRUE(backend_->DeleteProgram(ctx_, del, deleted).ok());

  Make(dir);
  auto listed = Programs();
  ASSERT_EQ(listed.size(), 1u);
  EXPECT_EQ(listed[0].program_id(), a);
  EXPECT_EQ(listed[0].name(), "renamed");
  EXPECT_EQ(Programs(true).size(), 2u);
  backend_.reset();
  std::filesystem::remove_all(dir);
}

TEST_F(ProgramManagementTest, FunctionListSortsAndFilters) {
  const std::string id = Import("prog");
  auto all = Functions(id);
  ASSERT_GT(all.size(), 4u);
  std::map<std::string, pb::Function> by_name;
  for (const auto &f : all) by_name[f.name()] = f;
  ASSERT_TRUE(by_name.contains("checksum"));
  const pb::Function &cs = by_name["checksum"];
  EXPECT_GT(cs.size(), 0u);
  EXPECT_GE(cs.xref_count(), 2u);  // main and twice call it
  EXPECT_GE(cs.xref_count(), cs.caller_count());
  // Debug info's prototype.
  EXPECT_NE(cs.prototype().find("checksum("), std::string::npos) << cs.prototype();

  pb::ListFunctionsRequest req;
  req.set_sort(pb::FUNCTION_SORT_SIZE);
  req.set_descending(true);
  auto sized = Functions(id, req);
  ASSERT_EQ(sized.size(), all.size());
  for (std::size_t i = 1; i < sized.size(); ++i) EXPECT_GE(sized[i - 1].size(), sized[i].size());

  req.set_sort(pb::FUNCTION_SORT_XREFS);
  auto refs = Functions(id, req);
  for (std::size_t i = 1; i < refs.size(); ++i) EXPECT_GE(refs[i - 1].xref_count(), refs[i].xref_count());
  req.set_descending(false);
  refs = Functions(id, req);
  for (std::size_t i = 1; i < refs.size(); ++i) {
    EXPECT_LE(refs[i - 1].xref_count(), refs[i].xref_count());
    if (refs[i - 1].xref_count() == refs[i].xref_count()) {  // ties in address order
      EXPECT_LT(refs[i - 1].entry().offset(), refs[i].entry().offset());
    }
  }

  pb::ListFunctionsRequest named;
  named.set_named(pb::FUNCTION_NAME_FILTER_UNNAMED);
  for (const auto &f : Functions(id, named)) EXPECT_TRUE(f.name().starts_with("FUN_")) << f.name();
  named.set_named(pb::FUNCTION_NAME_FILTER_NAMED);
  auto named_fns = Functions(id, named);
  EXPECT_FALSE(named_fns.empty());
  for (const auto &f : named_fns) EXPECT_FALSE(f.name().starts_with("FUN_")) << f.name();

  pb::ListFunctionsRequest thunks;
  thunks.set_thunks(pb::FUNCTION_THUNK_FILTER_ONLY);
  auto only = Functions(id, thunks);
  for (const auto &f : only) EXPECT_TRUE(f.thunk()) << f.name();
  thunks.set_thunks(pb::FUNCTION_THUNK_FILTER_EXCLUDE);
  auto without = Functions(id, thunks);
  for (const auto &f : without) EXPECT_FALSE(f.thunk()) << f.name();
  EXPECT_EQ(only.size() + without.size(), all.size());

  pb::ListFunctionsRequest failed;
  failed.set_decompile_failed(true);
  EXPECT_TRUE(Functions(id, failed).empty());

  pb::ListFunctionsRequest backwards;
  backwards.set_descending(true);
  auto rev = Functions(id, backwards);
  ASSERT_EQ(rev.size(), all.size());
  EXPECT_EQ(rev.front().entry().offset(), all.back().entry().offset());
}

TEST_F(ProgramManagementTest, FindTypesByPrefixAndSummaries) {
  const std::string id = Import("prog");
  pb::FindTypesRequest req;
  req.set_program_id(id);
  req.set_name_prefix("PA");
  req.add_sources(pb::TYPE_SOURCE_PROGRAM);
  pb::FindTypesResponse resp;
  ASSERT_TRUE(backend_->FindTypes(ctx_, req, resp).ok());
  ASSERT_GE(resp.types_size(), 1);
  bool pair = false;
  for (const auto &t : resp.types()) {
    EXPECT_TRUE(t.name().starts_with("pa") || t.name().starts_with("Pa") || t.name().starts_with("PA")) << t.name();
    if (t.name() == "pair") {
      pair = true;
      EXPECT_TRUE(t.has_composite());
    }
  }
  EXPECT_TRUE(pair);
  req.set_summary_only(true);
  ASSERT_TRUE(backend_->FindTypes(ctx_, req, resp).ok());
  for (const auto &t : resp.types()) {
    EXPECT_FALSE(t.has_composite()) << t.name();
    EXPECT_TRUE(t.c_definition().empty());
    EXPECT_FALSE(t.hash().empty());
    EXPECT_FALSE(t.display().empty());
  }
}

// Without debug info, the list shows what parameter ID committed.
TEST_F(ProgramManagementTest, FunctionListShowsParameterIdSignatures) {
  auto dir = testing::scratch_dir("program-management-paramid");
  const auto exe = dir / "nodebug";
  if (!testing::compile(REVKIT_TEST_CC, kProgram, "-O1 -g0", exe)) GTEST_SKIP() << "no C compiler";
  backend_.reset();
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  o.param_id = inputs::ParamIdMode::on;
  backend_ = MakeImageBackend(o);
  pb::ImportProgramRequest imp;
  imp.set_project_id("default");
  imp.set_path(exe.string());
  pb::ImportProgramResponse imported;
  ASSERT_TRUE(backend_->ImportProgram(ctx_, imp, imported).ok());
  const std::string id = imported.program().program_id();
  pb::GetAnalysisStatusRequest status;
  status.set_program_id(id);
  const auto until = std::chrono::steady_clock::now() + std::chrono::minutes(3);
  for (;;) {
    pb::GetAnalysisStatusResponse st;
    ASSERT_TRUE(backend_->GetAnalysisStatus(ctx_, status, st).ok());
    if (st.idle() || std::chrono::steady_clock::now() > until) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  bool seen = false;
  for (const auto &f : Functions(id))
    if (f.name() == "checksum") {
      seen = true;
      EXPECT_EQ(f.prototype_origin().derived().rule(), "analysis.param_id");
      EXPECT_NE(f.prototype().find(" checksum("), std::string::npos) << f.prototype();
    }
  EXPECT_TRUE(seen);
  std::filesystem::remove_all(dir);
}

// MIPS: a branch's delay slot belongs to the branch's block, and the
// branch's fallthrough continues after the slot.
TEST_F(ProgramManagementTest, GraphKeepsDelaySlotsInTheirBranchsBlock) {
  if (std::string(REVKIT_TEST_CLANG).empty() || std::string(REVKIT_TEST_LLD).empty())
    GTEST_SKIP() << "no clang and ld.lld for MIPS";
  auto dir = testing::scratch_dir("program-management-mips");
  const auto src = dir / "m.c", obj = dir / "m.o", exe = dir / "m.elf";
  {
    std::ofstream s(src);
    s << R"(
int g;
__attribute__((noinline)) int h(int x) { return x ^ g; }
__attribute__((noinline)) int f(const int *p, int n) {
  int s = 0;
  for (int i = 0; i < n; i++) s += h(p[i]);
  return s;
}
void __start(void) { g = f(&g, g); for (;;); }
)";
  }
  const std::string cc = std::string(REVKIT_TEST_CLANG) + " --target=mipsel-linux-gnu -O1 -fno-pic -mno-abicalls -c " +
                         src.string() + " -o " + obj.string() + " 2>/dev/null";
  const std::string ld = std::string(REVKIT_TEST_LLD) + " -e __start -o " + exe.string() + " " + obj.string() + " 2>/dev/null";
  if (std::system(cc.c_str()) != 0 || std::system(ld.c_str()) != 0) GTEST_SKIP() << "can't build a MIPS binary";

  pb::ImportProgramRequest imp;
  imp.set_project_id("default");
  imp.set_path(exe.string());
  pb::ImportProgramResponse imported;
  auto st = backend_->ImportProgram(ctx_, imp, imported);
  if (!st.ok()) GTEST_SKIP() << "no MIPS language: " << st.message;
  const std::string id = imported.program().program_id();
  std::uint64_t f = 0;
  for (const auto &fn : Functions(id))
    if (fn.name() == "f") f = fn.entry().offset();
  ASSERT_NE(f, 0u);

  pb::GetFunctionGraphRequest req;
  req.set_program_id(id);
  req.mutable_function()->set_offset(f);
  pb::GetFunctionGraphResponse g;
  ASSERT_TRUE(backend_->GetFunctionGraph(ctx_, req, g).ok());
  ASSERT_GE(g.blocks_size(), 4);
  // No block starts with a delay slot ("_"-prefixed mnemonics, Ghidra's).
  for (const auto &b : g.blocks()) {
    std::string first;
    for (const auto &t : b.rows(0).tokens()) first += t.text();
    EXPECT_FALSE(first.starts_with("_")) << "a block starts at the delay slot " << first;
  }
  // The loop's block ends with its bnez's delay slot and branches back to
  // itself; its fallthrough goes to the instruction after the slot.
  int loops = 0;
  for (const auto &e : g.edges()) {
    const auto &from = g.blocks(static_cast<int>(e.from_block()));
    if (e.from_block() != e.to_block()) continue;
    ++loops;
    EXPECT_EQ(e.kind(), pb::FLOW_EDGE_KIND_CONDITIONAL_TRUE);
    std::string last;
    for (const auto &t : from.rows(from.rows_size() - 1).tokens()) last += t.text();
    EXPECT_TRUE(last.starts_with("_")) << last;
    for (const auto &e2 : g.edges())
      if (e2.from_block() == e.from_block() && e2.kind() == pb::FLOW_EDGE_KIND_CONDITIONAL_FALSE) {
        EXPECT_EQ(g.blocks(static_cast<int>(e2.to_block())).range().first().offset(), from.range().last().offset() + 1);
      }
  }
  EXPECT_EQ(loops, 1);
  std::filesystem::remove_all(dir);
}

}  // namespace
}  // namespace revkit::backend
