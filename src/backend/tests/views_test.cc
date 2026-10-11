// What the UI's types, graph and data views read from the image backend:
// FindTypes over debug-info and defined types, BindTypeName reaching the
// uses of a type (decompiler, displays, events) and undo, GetFunctionGraph's
// blocks and edges, and ListData.
#include "builders.hh"

#include "revkit/backend/image_backend.h"
#include "revkit/inputs/library.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <mutex>
#include <set>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

constexpr const char *kProgram = R"(
#include <stdio.h>
struct point { int x; int y; };
struct point origin = {1, 2};
const char *greeting = "hello from the data view";
__attribute__((noinline)) int gety(struct point *p) { return p->y; }
__attribute__((noinline)) unsigned checksum(const unsigned char *p, int n) {
  unsigned h = 0x811c9dc5;
  for (int i = 0; i < n; i++) h = (h ^ p[i]) * 0x1000193;
  return h;
}
__attribute__((noinline)) int pick(int x) {
  switch (x) { case 0: return 3; case 1: return 7; case 2: return 9; case 3: return 11; case 4: return 13; case 5: return 2; default: return -1; }
}
int main(int argc, char **argv) {
  printf("%u %d %d %s\n", checksum((const unsigned char *)argv[0], argc), gety(&origin), pick(argc), greeting);
  return 0;
}
)";

class Sink : public api::EventSink {
 public:
  void Send(pb::SubscribeResponse event) override {
    std::lock_guard lock(mu_);
    if (event.has_revision()) revisions_.push_back(event.revision());
  }
  void End(api::Status) override {}
  std::vector<pb::RevisionEvent> revisions() {
    std::lock_guard lock(mu_);
    return revisions_;
  }

 private:
  std::mutex mu_;
  std::vector<pb::RevisionEvent> revisions_;
};

std::string Text(const pb::DecompiledFunction &f) {
  std::string out;
  for (const auto &line : f.lines()) {
    for (const auto &t : line.tokens()) out += t.text();
    out += '\n';
  }
  return out;
}

class ViewsTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("views");
    exe_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O1 -g -fno-inline", exe_);
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!compiled_) GTEST_SKIP() << "no C compiler";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(exe_.string());
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    id_ = resp.program().program_id();
  }

  std::uint64_t Fn(const std::string &name) {
    pb::ListSymbolsRequest req;
    req.set_program_id(id_);
    req.set_name_equals(name);
    pb::ListSymbolsResponse resp;
    EXPECT_TRUE(backend_->ListSymbols(ctx_, req, resp).ok());
    EXPECT_EQ(resp.symbols_size(), 1) << name;
    return resp.symbols_size() ? resp.symbols(0).address().offset() : 0;
  }

  pb::FindTypesResponse Find(const std::string &needle, bool superseded = false) {
    pb::FindTypesRequest req;
    req.set_program_id(id_);
    req.set_name_contains(needle);
    req.set_include_superseded(superseded);
    req.add_sources(pb::TYPE_SOURCE_PROGRAM);
    pb::FindTypesResponse resp;
    auto st = backend_->FindTypes(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  std::string Decompiled(std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(id_);
    req.mutable_function()->set_offset(entry);
    pb::DecompileResponse resp;
    auto st = backend_->Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return Text(resp.function());
  }

  pb::GetFunctionGraphResponse Graph(std::uint64_t entry) {
    pb::GetFunctionGraphRequest req;
    req.set_program_id(id_);
    req.mutable_function()->set_offset(entry);
    req.set_omit_bytes(true);
    pb::GetFunctionGraphResponse resp;
    auto st = backend_->GetFunctionGraph(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  static inline std::filesystem::path exe_;
  static inline bool compiled_ = false;
  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
  std::string id_;
};

TEST_F(ViewsTest, FindTypesListsNamedTypes) {
  pb::FindTypesResponse all = Find("");
  std::set<std::string> names;
  for (const auto &t : all.types()) names.insert(t.name());
  EXPECT_TRUE(names.contains("point"));
  EXPECT_EQ(all.page().total_count(), all.types_size());
  for (const auto &t : all.types()) EXPECT_FALSE(t.name().empty());  // named types only

  pb::FindTypesResponse found = Find("POI");  // case-insensitive
  ASSERT_EQ(found.types_size(), 1);
  const pb::TypeDefinition &point = found.types(0);
  EXPECT_EQ(point.kind(), pb::TYPE_KIND_STRUCT);
  EXPECT_EQ(point.composite().fields_size(), 2);
  EXPECT_EQ(point.origin().asserted().provenance().kind(), pb::PROVENANCE_KIND_IMPORT);
  EXPECT_FALSE(point.bound());

  pb::FindTypesRequest by_kind;
  by_kind.set_program_id(id_);
  by_kind.add_kinds(pb::TYPE_KIND_ENUM);
  by_kind.add_sources(pb::TYPE_SOURCE_PROGRAM);
  pb::FindTypesResponse none;
  ASSERT_TRUE(backend_->FindTypes(ctx_, by_kind, none).ok());
  EXPECT_EQ(none.types_size(), 0);
}

// The library archives applied to imports (revkit's libc-lp64, built from
// the host's glibc headers, then Ghidra's generic_clib_64): their named
// types are found, described and usable by hash, never asserted.
TEST_F(ViewsTest, LibraryArchiveTypesAreFoundAndUsable) {
  pb::FindTypesRequest req;
  req.set_program_id(id_);
  req.set_name_contains("stat");
  req.add_sources(pb::TYPE_SOURCE_LIBRARY);
  pb::FindTypesResponse resp;
  ASSERT_TRUE(backend_->FindTypes(ctx_, req, resp).ok());
  const pb::TypeDefinition *stat = nullptr;
  for (const auto &t : resp.types())
    if (t.name() == "stat" && t.kind() == pb::TYPE_KIND_STRUCT) stat = &t;
  if (!stat) GTEST_SKIP() << "no library archive (libc-lp64 or Ghidra's generic_clib_64)";
  EXPECT_EQ(stat->origin().derived().rule(),
            inputs::read_library_archive("libc-lp64") ? "library:libc-lp64" : "library:generic_clib_64");
  EXPECT_EQ(stat->size(), 144u);  // x86-64 glibc
  EXPECT_NE(stat->c_definition().find("st_size"), std::string::npos) << stat->c_definition();
  // Program types only: point, none of the library's.
  pb::FindTypesRequest prog;
  prog.set_program_id(id_);
  prog.add_sources(pb::TYPE_SOURCE_PROGRAM);
  pb::FindTypesResponse own;
  ASSERT_TRUE(backend_->FindTypes(ctx_, prog, own).ok());
  for (const auto &t : own.types()) EXPECT_TRUE(t.origin().has_asserted()) << t.name();

  // A global retyped to a pointer to it, by hash: listed with its C spelling.
  pb::AppendAssertionsRequest app;
  app.set_program_id(id_);
  app.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  pb::TypeNode *ptr = app.add_assertions()->mutable_body()->mutable_define_type()->mutable_type();
  ptr->set_kind(pb::TYPE_KIND_POINTER);
  ptr->mutable_target()->set_hash(stat->hash());
  app.set_validate_only(true);
  pb::AppendAssertionsResponse checked;
  auto st = backend_->AppendAssertions(ctx_, app, checked);
  ASSERT_TRUE(st.ok()) << st.message;
  app.set_validate_only(false);
  auto *rt = app.add_assertions()->mutable_body()->mutable_retype();
  rt->mutable_target()->mutable_address()->set_offset(Fn("greeting"));
  rt->mutable_type()->set_type_hash(checked.assertions(0).key().sub());
  pb::AppendAssertionsResponse done;
  st = backend_->AppendAssertions(ctx_, app, done);
  ASSERT_TRUE(st.ok()) << st.message;
  pb::BlameRequest breq;
  *breq.mutable_key() = done.assertions(1).key();
  pb::BlameResponse blame;
  ASSERT_TRUE(backend_->Blame(ctx_, breq, blame).ok());
  EXPECT_EQ(blame.value_text(), "struct stat *");
}

// Editing struct point (a new definition bound to its name) reaches the
// decompilation that pinned the old one through its DWARF prototype, is
// announced to subscribers, and undoes by retraction.
TEST_F(ViewsTest, ABoundTypeNameReachesItsUsesAndUndoes) {
  const std::uint64_t gety = Fn("gety");
  const std::string before = Decompiled(gety);
  ASSERT_NE(before.find("->y"), std::string::npos) << before;
  const pb::TypeDefinition old = Find("point").types(0);
  const std::string int_hash = old.composite().fields(0).type_hash();

  auto sink = std::make_shared<Sink>();
  std::unique_ptr<api::Subscription> sub;
  pb::SubscribeRequest sreq;
  sreq.set_project_id("default");
  ASSERT_TRUE(backend_->Subscribe(ctx_, sreq, sink, sub).ok());

  pb::AppendAssertionsRequest req;
  req.set_program_id(id_);
  req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  req.mutable_provenance()->set_id("alice");
  pb::TypeNode *t = req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type();
  t->set_kind(pb::TYPE_KIND_STRUCT);
  t->set_name("point");
  t->set_size(8);
  for (const char *name : {"px", "py"}) {
    auto *f = t->add_fields();
    f->set_name(name);
    f->set_offset(t->fields_size() == 1 ? 0 : 4);
    f->mutable_type()->set_hash(int_hash);
  }
  req.add_assertions()->mutable_body()->mutable_bind_type_name()->mutable_type()->set_assertion_index(0);
  pb::AppendAssertionsResponse appended;
  auto st = backend_->AppendAssertions(ctx_, req, appended);
  ASSERT_TRUE(st.ok()) << st.message;
  ASSERT_EQ(appended.assertions_size(), 2);
  const std::string new_hash = appended.assertions(0).key().sub();
  EXPECT_EQ(appended.assertions(1).key().sub(), "name:struct point");
  EXPECT_EQ(appended.assertions(1).body().bind_type_name().type().hash(), new_hash);

  // FindTypes shows the bound definition; the old one is superseded.
  pb::FindTypesResponse now = Find("point");
  ASSERT_EQ(now.types_size(), 1);
  EXPECT_EQ(now.types(0).hash(), new_hash);
  EXPECT_TRUE(now.types(0).bound());
  pb::FindTypesResponse history = Find("point", true);
  ASSERT_EQ(history.types_size(), 2);
  for (const auto &x : history.types()) EXPECT_EQ(x.superseded(), x.hash() == old.hash());

  // The decompilation that used the old definition uses the new one.
  const std::string after = Decompiled(gety);
  EXPECT_NE(after.find("->py"), std::string::npos) << after;
  // GetTypes still describes the old hash as it was.
  pb::GetTypesRequest treq;
  treq.set_program_id(id_);
  treq.add_hashes(old.hash());
  pb::GetTypesResponse types;
  ASSERT_TRUE(backend_->GetTypes(ctx_, treq, types).ok());
  ASSERT_EQ(types.types_size(), 1);
  EXPECT_EQ(types.types(0).composite().fields(1).name(), "y");
  EXPECT_TRUE(types.types(0).superseded());

  // Subscribers are told: types, and the decompilation served before.
  auto events = sink->revisions();
  ASSERT_FALSE(events.empty());
  bool types_kind = false, decompile = false;
  for (const auto &q : events.back().invalidated()) {
    types_kind |= q.kind() == pb::QUERY_KIND_TYPES;
    decompile |= q.kind() == pb::QUERY_KIND_DECOMPILE && q.address().offset() == gety;
  }
  EXPECT_TRUE(types_kind && decompile);

  // Binding needs a named type the program knows.
  pb::AppendAssertionsRequest bad;
  bad.set_program_id(id_);
  bad.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  bad.add_assertions()->mutable_body()->mutable_bind_type_name()->mutable_type()->set_hash(int_hash);
  pb::AppendAssertionsResponse rejected;
  EXPECT_EQ(backend_->AppendAssertions(ctx_, bad, rejected).code, StatusCode::kInvalidArgument);
  bad.mutable_assertions(0)->mutable_body()->mutable_bind_type_name()->mutable_type()->set_hash(std::string(32, '0'));
  EXPECT_EQ(backend_->AppendAssertions(ctx_, bad, rejected).code, StatusCode::kInvalidArgument);

  // Undo: retracting both restores the old definition everywhere.
  pb::RetractAssertionsRequest undo;
  undo.set_program_id(id_);
  undo.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  undo.mutable_provenance()->set_id("alice");
  for (const auto &a : appended.assertions()) undo.add_seqs(a.seq());
  pb::RetractAssertionsResponse undone;
  ASSERT_TRUE(backend_->RetractAssertions(ctx_, undo, undone).ok());
  EXPECT_NE(Decompiled(gety).find("->y"), std::string::npos);
  pb::FindTypesResponse restored = Find("point");
  ASSERT_EQ(restored.types_size(), 1);
  EXPECT_EQ(restored.types(0).hash(), old.hash());
}

TEST_F(ViewsTest, FunctionGraphHasBlocksAndTypedEdges) {
  // A loop: a conditional back edge, its fallthrough, an exit block.
  pb::GetFunctionGraphResponse loop = Graph(Fn("checksum"));
  ASSERT_GE(loop.blocks_size(), 2);
  EXPECT_EQ(loop.function().name(), "checksum");
  const pb::BasicBlock &entry = loop.blocks(static_cast<int>(loop.entry_block()));
  EXPECT_EQ(entry.range().first().offset(), Fn("checksum"));
  std::set<pb::FlowEdgeKind> kinds;
  bool back = false;
  for (const auto &e : loop.edges()) {
    kinds.insert(e.kind());
    ASSERT_LT(e.from_block(), static_cast<std::uint32_t>(loop.blocks_size()));
    ASSERT_LT(e.to_block(), static_cast<std::uint32_t>(loop.blocks_size()));
    back |= e.to_block() <= e.from_block() && e.kind() == pb::FLOW_EDGE_KIND_CONDITIONAL_TRUE;
  }
  EXPECT_TRUE(kinds.contains(pb::FLOW_EDGE_KIND_CONDITIONAL_TRUE));
  EXPECT_TRUE(kinds.contains(pb::FLOW_EDGE_KIND_CONDITIONAL_FALSE));
  EXPECT_TRUE(back) << "the loop's backward branch";
  int exits = 0, rows = 0;
  for (const auto &b : loop.blocks()) {
    exits += b.exit();
    rows += b.rows_size();
    for (int i = 0; i < b.rows_size(); ++i) {
      EXPECT_EQ(b.rows(i).kind(), pb::LISTING_ROW_KIND_INSTRUCTION);
      EXPECT_EQ(b.rows(i).row(), i);
      EXPECT_FALSE(b.rows(i).tokens().empty());
    }
    // A conditional branch ends its block.
    for (int i = 0; i + 1 < b.rows_size(); ++i) EXPECT_NE(b.rows(i).flow(), pb::FLOW_KIND_CONDITIONAL_BRANCH);
  }
  EXPECT_GE(exits, 1);
  EXPECT_EQ(static_cast<std::uint32_t>(rows), loop.function().instruction_count());

  // A switch: a computed jump with an edge per recovered case.
  pb::GetFunctionGraphResponse sw = Graph(Fn("pick"));
  int cases = 0;
  for (const auto &e : sw.edges()) cases += e.kind() == pb::FLOW_EDGE_KIND_SWITCH;
  EXPECT_GE(cases, 6);

  // Any address in the body finds its function with `containing`.
  pb::GetFunctionGraphRequest req;
  req.set_program_id(id_);
  req.mutable_function()->set_offset(loop.blocks(loop.blocks_size() - 1).range().first().offset());
  pb::GetFunctionGraphResponse resp;
  EXPECT_EQ(backend_->GetFunctionGraph(ctx_, req, resp).code, StatusCode::kNotFound);
  req.set_containing(true);
  ASSERT_TRUE(backend_->GetFunctionGraph(ctx_, req, resp).ok());
  EXPECT_EQ(resp.function().name(), "checksum");
}

TEST_F(ViewsTest, ListDataShowsStringsPointersAndTypedGlobals) {
  pb::ListDataRequest req;
  req.set_program_id(id_);
  req.add_categories(pb::DATA_CATEGORY_STRING);
  req.set_text_contains("data view");
  pb::ListDataResponse resp;
  auto st = backend_->ListData(ctx_, req, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  ASSERT_EQ(resp.data_size(), 1);
  const pb::DefinedData &s = resp.data(0);
  EXPECT_EQ(s.value(), "hello from the data view");
  EXPECT_EQ(s.data_type(), "string");
  EXPECT_EQ(s.length(), s.value().size() + 1);
  EXPECT_EQ(s.origin().derived().rule(), "analysis.data");

  // Every category, in address order, paged by offset.
  pb::ListDataRequest all;
  all.set_program_id(id_);
  pb::ListDataResponse everything;
  ASSERT_TRUE(backend_->ListData(ctx_, all, everything).ok());
  std::set<pb::DataCategory> cats;
  for (int i = 0; i < everything.data_size(); ++i) {
    cats.insert(everything.data(i).category());
    if (i) EXPECT_LE(everything.data(i - 1).address().offset(), everything.data(i).address().offset());
  }
  EXPECT_TRUE(cats.contains(pb::DATA_CATEGORY_STRING));
  EXPECT_TRUE(cats.contains(pb::DATA_CATEGORY_TYPED));  // DWARF types origin and greeting
  all.set_offset(1);
  all.mutable_page()->set_page_size(1);
  pb::ListDataResponse second;
  ASSERT_TRUE(backend_->ListData(ctx_, all, second).ok());
  ASSERT_EQ(second.data_size(), 1);
  EXPECT_EQ(second.data(0).address().offset(), everything.data(1).address().offset());
  EXPECT_EQ(second.page().total_count(), everything.data_size());

  pb::ListDataRequest typed;
  typed.set_program_id(id_);
  typed.add_categories(pb::DATA_CATEGORY_TYPED);
  typed.set_text_contains("origin");
  pb::ListDataResponse t;
  ASSERT_TRUE(backend_->ListData(ctx_, typed, t).ok());
  ASSERT_EQ(t.data_size(), 1);
  EXPECT_EQ(t.data(0).data_type(), "struct point");
  EXPECT_EQ(t.data(0).origin().asserted().provenance().kind(), pb::PROVENANCE_KIND_IMPORT);
}

}  // namespace
}  // namespace revkit::backend
