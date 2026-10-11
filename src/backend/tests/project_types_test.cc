// Project-wide types (docs/types.md#project-types): two programs of one
// project share a struct defined at project scope, and editing it there
// changes both programs' decompiled C; Copy to program gives one of them
// its own copy; type archives attach to the project and switch off.
#include "builders.hh"

#include "revkit/backend/image_backend.h"
#include "revkit/inputs/library.h"

#include <gtest/gtest.h>

#include <filesystem>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
namespace fs = std::filesystem;
using api::CallContext;
using api::StatusCode;

constexpr const char *kFirst = R"(
struct point { int x; int y; };
struct point origin = {1, 2};
__attribute__((noinline)) int gety(struct point *p) { return p->y; }
int main(void) { return gety(&origin); }
)";

constexpr const char *kSecond = R"(
struct point { int x; int y; };
struct point corner = {3, 4};
__attribute__((noinline)) int sumxy(struct point *p) { return p->x + p->y * 3; }
int main(void) { return sumxy(&corner); }
)";

std::string Text(const pb::DecompiledFunction &f) {
  std::string out;
  for (const auto &line : f.lines()) {
    for (const auto &t : line.tokens()) out += t.text();
    out += '\n';
  }
  return out;
}

class ProjectTypesTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("project-types");
    first_ = dir / "first";
    second_ = dir / "second";
    compiled_ = testing::compile(REVKIT_TEST_CC, kFirst, "-O1 -g -fno-inline", first_) &&
                testing::compile(REVKIT_TEST_CC, kSecond, "-O1 -g -fno-inline", second_);
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!compiled_) GTEST_SKIP() << "no C compiler";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
    a_ = Import(first_);
    b_ = Import(second_);
  }

  std::string Import(const fs::path &path) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(path.string());
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  std::uint64_t Fn(const std::string &program, const std::string &name) {
    pb::ListSymbolsRequest req;
    req.set_program_id(program);
    req.set_name_equals(name);
    pb::ListSymbolsResponse resp;
    EXPECT_TRUE(backend_->ListSymbols(ctx_, req, resp).ok());
    return resp.symbols_size() ? resp.symbols(0).address().offset() : 0;
  }

  std::string Decompiled(const std::string &program, const std::string &fn) {
    pb::DecompileRequest req;
    req.set_program_id(program);
    req.mutable_function()->set_offset(Fn(program, fn));
    pb::DecompileResponse resp;
    auto st = backend_->Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return Text(resp.function());
  }

  pb::FindTypesResponse Find(const std::string &program, const std::string &needle,
                             pb::TypeSource source = pb::TYPE_SOURCE_UNSPECIFIED) {
    pb::FindTypesRequest req;
    req.set_program_id(program);
    req.set_name_contains(needle);
    if (source != pb::TYPE_SOURCE_UNSPECIFIED) req.add_sources(source);
    pb::FindTypesResponse resp;
    auto st = backend_->FindTypes(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  // struct point as a new definition with the field names given, bound to
  // the name: at project scope, or in the program.
  std::string Edit(const std::string &program, const std::string &x, const std::string &y, bool project) {
    pb::TypeDefinition old;
    const pb::FindTypesResponse found = Find(program, "point");
    for (const auto &t : found.types())
      if (t.name() == "point" && t.kind() == pb::TYPE_KIND_STRUCT && t.composite().fields_size() == 2) old = t;
    EXPECT_FALSE(old.hash().empty());
    if (old.hash().empty()) return {};
    pb::AppendAssertionsRequest req;
    req.set_program_id(program);
    req.set_project_scope(project);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    pb::TypeNode *t = req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type();
    t->set_kind(pb::TYPE_KIND_STRUCT);
    t->set_name("point");
    t->set_size(8);
    for (const std::string &name : {x, y}) {
      auto *f = t->add_fields();
      f->set_name(name);
      f->set_offset(t->fields_size() == 1 ? 0 : 4);
      f->mutable_type()->set_hash(old.composite().fields(0).type_hash());
    }
    req.add_assertions()->mutable_body()->mutable_bind_type_name()->mutable_type()->set_assertion_index(0);
    pb::AppendAssertionsResponse resp;
    auto st = backend_->AppendAssertions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    if (resp.assertions_size() != 2) return {};
    EXPECT_EQ(resp.assertions(0).key().project(), project);
    return resp.assertions(0).key().sub();
  }

  pb::CopyTypesResponse Copy(const std::string &program, pb::CopyTypesMode mode, api::Status *status = nullptr) {
    pb::CopyTypesRequest req;
    req.set_program_id(program);
    req.add_keys("struct point");
    req.set_mode(mode);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    pb::CopyTypesResponse resp;
    api::Status st = backend_->CopyTypes(ctx_, req, resp);
    if (status) *status = st;
    else EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  static inline fs::path first_, second_;
  static inline bool compiled_ = false;
  std::unique_ptr<api::Backend> backend_;
  CallContext ctx_;
  std::string a_, b_;
};

TEST_F(ProjectTypesTest, TwoProgramsShareAStructAndAnEditReachesBoth) {
  ASSERT_NE(Decompiled(a_, "gety").find("p->y"), std::string::npos);
  ASSERT_NE(Decompiled(b_, "sumxy").find("p->x"), std::string::npos);

  // Move to project: the first program's struct point is the project's.
  pb::CopyTypesResponse moved = Copy(a_, pb::COPY_TYPES_MODE_MOVE_TO_PROJECT);
  ASSERT_EQ(moved.types_size(), 1);
  EXPECT_GE(moved.records(), 1u);
  EXPECT_GE(moved.retracted(), 1u);  // the program's own definition (DWARF's)
  pb::FindTypesResponse in_a = Find(a_, "point", pb::TYPE_SOURCE_PROJECT);
  ASSERT_EQ(in_a.types_size(), 1);
  EXPECT_EQ(in_a.types(0).name(), "point");
  EXPECT_TRUE(in_a.types(0).project());
  const pb::FindTypesResponse own_a = Find(a_, "point", pb::TYPE_SOURCE_PROGRAM);
  for (const auto &t : own_a.types()) EXPECT_NE(t.name(), "point");
  // The decompilation is the same: one type, now the project's.
  EXPECT_NE(Decompiled(a_, "gety").find("p->y"), std::string::npos);

  // An edit at project scope reaches both programs, the second through its
  // own (identical) DWARF definition of the name.
  const std::string edited = Edit(a_, "px", "py", true);
  ASSERT_FALSE(edited.empty());
  const std::string ca = Decompiled(a_, "gety"), cb = Decompiled(b_, "sumxy");
  EXPECT_NE(ca.find("->py"), std::string::npos) << ca;
  EXPECT_NE(cb.find("->px"), std::string::npos) << cb;
  EXPECT_NE(cb.find("->py"), std::string::npos) << cb;
  pb::FindTypesResponse in_b = Find(b_, "point");
  bool bound_project = false;
  for (const auto &t : in_b.types()) bound_project |= t.hash() == edited && t.bound() && t.project();
  EXPECT_TRUE(bound_project);

  // Copy to program: the second gets its own copy, which a later project
  // edit no longer reaches.
  pb::CopyTypesResponse copied = Copy(b_, pb::COPY_TYPES_MODE_COPY_TO_PROGRAM);
  ASSERT_EQ(copied.types_size(), 1);
  EXPECT_EQ(copied.types(0).hash(), edited);
  Edit(a_, "qx", "qy", true);
  EXPECT_NE(Decompiled(a_, "gety").find("->qy"), std::string::npos);
  const std::string cb2 = Decompiled(b_, "sumxy");
  EXPECT_NE(cb2.find("->py"), std::string::npos) << cb2;
  EXPECT_EQ(cb2.find("->qy"), std::string::npos) << cb2;

  // Exported in a .rkproj and imported as a new project: the project's
  // types come along, and the first program's copy uses them.
  pb::ExportProjectRequest ex;
  ex.set_project_id("default");
  std::string bytes;
  bool first = true;
  auto est = backend_->ExportProject(ctx_, ex, [&](const pb::ExportProjectResponse &r) {
    if (!first) bytes += r.data();
    first = false;
    return true;
  });
  ASSERT_TRUE(est.ok()) << est.message;
  pb::ImportProjectArchiveRequest imp;
  imp.mutable_archive()->set_content(bytes);
  imp.set_new_project_name("copied");
  imp.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  pb::ImportProjectArchiveResponse imported;
  auto ist = backend_->ImportProjectArchive(ctx_, imp, imported);
  ASSERT_TRUE(ist.ok()) << ist.message;
  std::string copy_a;
  for (const auto &ip : imported.programs())
    if (ip.program().name() == "first") copy_a = ip.program().program_id();
  ASSERT_FALSE(copy_a.empty());
  const pb::FindTypesResponse in_copy = Find(copy_a, "point", pb::TYPE_SOURCE_PROJECT);
  bool found_q = false;
  for (const auto &t : in_copy.types())
    if (t.name() == "point" && t.bound() && t.composite().fields_size() == 2) found_q = t.composite().fields(1).name() == "qy";
  EXPECT_TRUE(found_q);
  EXPECT_NE(Decompiled(copy_a, "gety").find("->qy"), std::string::npos);

  // project_scope takes only type bodies.
  pb::AppendAssertionsRequest bad;
  bad.set_program_id(a_);
  bad.set_project_scope(true);
  bad.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  auto *rn = bad.add_assertions()->mutable_body()->mutable_rename();
  rn->mutable_target()->mutable_address()->set_offset(Fn(a_, "gety"));
  rn->set_name("nope");
  pb::AppendAssertionsResponse rejected;
  EXPECT_EQ(backend_->AppendAssertions(ctx_, bad, rejected).code, StatusCode::kInvalidArgument);
  // Moving a name the program doesn't define.
  api::Status st;
  Copy(a_, pb::COPY_TYPES_MODE_MOVE_TO_PROJECT, &st);
  EXPECT_EQ(st.code, StatusCode::kNotFound);
}

// Archives: listed per program; a shipped one switched off stops giving
// prototypes; an attached archive's prototypes apply to every program.
TEST_F(ProjectTypesTest, ArchivesAttachAndSwitchOff) {
  if (!inputs::read_library_archive("libc-lp64")) GTEST_SKIP() << "no libc-lp64 archive";
  auto list = [&]() {
    pb::ListTypeArchivesRequest req;
    req.set_program_id(a_);
    pb::ListTypeArchivesResponse resp;
    EXPECT_TRUE(backend_->ListTypeArchives(ctx_, req, resp).ok());
    return resp;
  };
  auto find = [](const pb::ListTypeArchivesResponse &r, const std::string &name) -> const pb::TypeArchiveInfo * {
    for (const auto &a : r.archives())
      if (a.name() == name) return &a;
    return nullptr;
  };
  pb::ListTypeArchivesResponse before = list();
  const pb::TypeArchiveInfo *libc = find(before, "libc-lp64");
  ASSERT_NE(libc, nullptr);
  EXPECT_TRUE(libc->enabled());
  EXPECT_TRUE(libc->applies());
  EXPECT_GT(libc->functions(), 1000u);
  EXPECT_NE(libc->origin().find("glibc"), std::string::npos) << libc->origin();
  const pb::TypeArchiveInfo *k32 = find(before, "kernel32-llp64");
  if (k32) EXPECT_FALSE(k32->applies());
  ASSERT_NE(find(before, "ghidra"), nullptr);

  auto set = [&](const pb::TypeArchiveSetting &s) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(a_);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    *req.add_assertions()->mutable_body()->mutable_type_archive() = s;
    pb::AppendAssertionsResponse resp;
    auto st = backend_->AppendAssertions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    if (resp.assertions_size() == 1) EXPECT_TRUE(resp.assertions(0).key().project());
  };
  // Attach a small archive declaring gety's prototype by name: it applies
  // to both programs' functions of that name (the first program's).
  pb::TypeArchiveSetting mine;
  mine.set_name("mylib");
  mine.set_enabled(true);
  mine.set_header("struct widget { int a; };\nint gety(struct widget *w);\n");
  set(mine);
  pb::ListTypeArchivesResponse after = list();
  const pb::TypeArchiveInfo *attached = find(after, "mylib");
  ASSERT_NE(attached, nullptr);
  EXPECT_EQ(attached->kind(), pb::TYPE_ARCHIVE_KIND_ATTACHED);
  EXPECT_EQ(attached->functions(), 1u);
  EXPECT_EQ(attached->types(), 1u);
  pb::FindTypesResponse widget = Find(b_, "widget", pb::TYPE_SOURCE_LIBRARY);
  ASSERT_EQ(widget.types_size(), 1);
  EXPECT_EQ(widget.types(0).origin().derived().rule(), "library:mylib");

  // Switched off and on again without its header: the header is kept.
  pb::TypeArchiveSetting mine_off;
  mine_off.set_name("mylib");
  mine_off.set_enabled(false);
  set(mine_off);
  EXPECT_FALSE(find(list(), "mylib")->enabled());
  mine_off.set_enabled(true);
  set(mine_off);
  EXPECT_EQ(find(list(), "mylib")->functions(), 1u);

  // Switch libc off: its types go from the program's library types.
  pb::TypeArchiveSetting off;
  off.set_name("libc-lp64");
  off.set_enabled(false);
  set(off);
  EXPECT_FALSE(find(list(), "libc-lp64")->enabled());
  pb::FindTypesResponse files = Find(a_, "_IO_FILE", pb::TYPE_SOURCE_LIBRARY);
  for (const auto &t : files.types()) EXPECT_NE(t.origin().derived().rule(), "library:libc-lp64");

  // Detach.
  pb::TypeArchiveSetting gone;
  gone.set_name("mylib");
  gone.set_detach(true);
  set(gone);
  EXPECT_EQ(find(list(), "mylib"), nullptr);
}

}  // namespace
}  // namespace revkit::backend
