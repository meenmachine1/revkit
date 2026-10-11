// Microsoft-specific analysis through the API (docs/pe.md): RTTI classes,
// vftables, virtual methods' `this`, the class hierarchy, on
// tests/data/msvc/classes.cc built at test time for x86_64 and i686
// (clang in cl mode, lld-link; skipped without them).
#include "../../msvc/tests/msvc_fixture.h"

#include "revkit/backend/image_backend.h"
#include "revkit/loader/load.hh"
#include "revkit/debuginfo/pdb.h"
#include "symbol_server.h"

#include <gtest/gtest.h>

#include <fstream>
#include <map>
#include <set>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
namespace fs = std::filesystem;
using api::CallContext;

std::string Text(const pb::DecompiledFunction &f) {
  std::string out;
  for (const auto &line : f.lines()) {
    for (const auto &t : line.tokens()) out += t.text();
    out += '\n';
  }
  return out;
}

class MsvcApiTest : public ::testing::TestWithParam<std::string> {
 protected:
  static std::map<std::string, std::optional<msvc::testing::Fixture>> &fixtures() {
    static std::map<std::string, std::optional<msvc::testing::Fixture>> f;
    return f;
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    auto &f = fixtures();
    if (!f.contains(GetParam()))
      f[GetParam()] = msvc::testing::build_fixture(REVKIT_TEST_CLANG, REVKIT_TEST_LLD_LINK, REVKIT_MSVC_FIXTURE, GetParam());
    if (!f[GetParam()]) GTEST_SKIP() << "clang or lld-link missing, or the fixture didn't build";
    fx_ = &*f[GetParam()];
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
  }

  std::string Import(const std::filesystem::path &path) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(path.string());
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    for (const auto &w : resp.warnings()) warnings_.push_back(w);
    return resp.program().program_id();
  }

  std::vector<pb::Function> Functions(const std::string &id) {
    pb::ListFunctionsRequest req;
    req.set_program_id(id);
    req.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(backend_->ListFunctions(ctx_, req, resp).ok());
    return {resp.functions().begin(), resp.functions().end()};
  }

  std::optional<pb::Function> FunctionAt(const std::string &id, std::uint64_t entry) {
    for (const pb::Function &f : Functions(id))
      if (f.entry().offset() == entry) return f;
    return std::nullopt;
  }

  std::string Decompile(const std::string &id, std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(id);
    req.mutable_function()->set_offset(entry);
    pb::DecompileResponse resp;
    auto st = backend_->Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return Text(resp.function());
  }

  const msvc::testing::Fixture *fx_ = nullptr;
  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
  std::vector<std::string> warnings_;
};

// The symbol whose mangled name starts with `prefix` (x86_64 and i686 mangle
// pointers differently: match the part before them).
std::uint64_t Mangled(const msvc::testing::Fixture &fx, const std::string &prefix) {
  for (const auto &[name, a] : fx.symbols)
    if (name.starts_with(prefix)) return a;
  ADD_FAILURE() << "no symbol " << prefix;
  return 0;
}

TEST_P(MsvcApiTest, StrippedClassesGetNamesFunctionsAndThis) {
  const std::string id = Import(fx_->stripped);
  bool summary = false;
  for (const auto &w : warnings_)
    summary = summary || (w.starts_with("analysis:msvc:") && w.find(" 8 rtti classes") != std::string::npos);
  EXPECT_TRUE(summary) << ::testing::PrintToString(warnings_);
  // Every function in a vftable is a function, named after its class and
  // slot, with `this` typed.
  const std::uint64_t area = Mangled(*fx_, "?area@Rect@geo@@");
  std::optional<pb::Function> f = FunctionAt(id, area);
  ASSERT_TRUE(f);
  EXPECT_EQ(f->name(), "geo::Rect::vfunc1");
  EXPECT_EQ(f->name_origin().asserted().provenance().kind(), pb::PROVENANCE_KIND_ANALYSIS);
  EXPECT_EQ(f->name_origin().asserted().provenance().id(), "msvc");
  EXPECT_NE(f->prototype().find("(struct geo::Rect *this, ...)"), std::string::npos) << f->prototype();
  // Shape::scale is in Rect's and Box<int>'s tables: named after their
  // common base, which has no table of its own.
  std::optional<pb::Function> scale = FunctionAt(id, Mangled(*fx_, "?scale@Shape@geo@@"));
  ASSERT_TRUE(scale);
  EXPECT_EQ(scale->name(), "geo::Shape::vfunc2");
  // Rect's override of Named::name takes the Named subobject.
  std::optional<pb::Function> name = FunctionAt(id, Mangled(*fx_, "?name@Rect@geo@@"));
  ASSERT_TRUE(name);
  EXPECT_EQ(name->name(), "geo::Rect::Named_vfunc0");
  EXPECT_NE(name->prototype().find("struct geo::Named *this"), std::string::npos) << name->prototype();
}

TEST_P(MsvcApiTest, DecompiledMethodsUseTheClassStruct) {
  const std::string id = Import(fx_->stripped);
  const bool x64 = GetParam() == "x86_64";
  // `this` is the class struct, as large as its methods reach: fields
  // past the vftable pointer read as the struct's own.
  const std::string area = Decompile(id, Mangled(*fx_, "?area@Rect@geo@@"));
  EXPECT_NE(area.find("geo::Rect::vfunc1(Rect *this)"), std::string::npos) << area;
  EXPECT_NE(area.find(x64 ? "this->field_0x18" : "this->field_0xc"), std::string::npos) << area;
  EXPECT_EQ(area.find("this["), std::string::npos) << area;
  if (!x64) EXPECT_NE(area.find("__thiscall"), std::string::npos) << area;
  // A virtual call through `this`: the vftable's field, called with `this`.
  const std::string scale = Decompile(id, Mangled(*fx_, "?scale@Shape@geo@@"));
  EXPECT_NE(scale.find("(*this->vftable->vfunc1)(this)"), std::string::npos) << scale;
}

TEST_P(MsvcApiTest, RttiStructuresAreTypedData) {
  const std::string id = Import(fx_->stripped);
  pb::ListDataRequest req;
  req.set_program_id(id);
  req.mutable_page()->set_page_size(5000);
  pb::ListDataResponse resp;
  ASSERT_TRUE(backend_->ListData(ctx_, req, resp).ok());
  std::map<std::uint64_t, const pb::DefinedData *> at;
  for (const pb::DefinedData &d : resp.data()) at[d.address().offset()] = &d;
  struct Want {
    const char *symbol, *label, *type;
  };
  for (const Want &w : {Want{"??_R0?AURect@geo@@@8", "geo::Rect::RTTI_Type_Descriptor", "TypeDescriptor"},
                        Want{"??_R4Rect@geo@@6BShape@1@@", "geo::Rect::RTTI_Complete_Object_Locator",
                             "RTTICompleteObjectLocator"},
                        Want{"??_R3Rect@geo@@8", "geo::Rect::RTTI_Class_Hierarchy_Descriptor", "RTTIClassHierarchyDescriptor"},
                        Want{"??_7Rect@geo@@6BShape@1@@", "geo::Rect::vftable", "geo::Rect_vftable"},
                        Want{"??_7Rect@geo@@6BNamed@1@@", "geo::Rect::vftable_for_Named", "geo::Rect_vftable_for_Named"}}) {
    const std::uint64_t a = fx_->at(w.symbol);
    ASSERT_TRUE(at.contains(a)) << w.symbol;
    EXPECT_EQ(at[a]->label(), w.label) << w.symbol;
    EXPECT_NE(at[a]->data_type().find(w.type), std::string::npos) << at[a]->data_type();
    EXPECT_EQ(at[a]->origin().asserted().provenance().id(), "msvc");
  }
}

TEST_P(MsvcApiTest, ClassHierarchy) {
  const std::string id = Import(fx_->stripped);
  pb::GetClassHierarchyRequest req;
  req.set_program_id(id);
  pb::GetClassHierarchyResponse resp;
  ASSERT_TRUE(backend_->GetClassHierarchy(ctx_, req, resp).ok());
  std::map<std::string, const pb::RttiClass *> by;
  for (const pb::RttiClass &c : resp.classes()) by[c.name()] = &c;
  ASSERT_TRUE(by.contains("geo::Square"));
  const pb::RttiClass &sq = *by["geo::Square"];
  ASSERT_EQ(sq.bases_size(), 3);
  EXPECT_EQ(sq.bases(0).name(), "geo::Rect");
  EXPECT_TRUE(sq.bases(0).direct());
  EXPECT_FALSE(sq.bases(1).direct());
  EXPECT_EQ(sq.bases(2).name(), "geo::Named");
  EXPECT_EQ(sq.bases(2).offset(), GetParam() == "x86_64" ? 16 : 8);
  EXPECT_EQ(sq.type_name(), "struct geo::Square");
  EXPECT_FALSE(sq.type_hash().empty());
  ASSERT_EQ(sq.vftables_size(), 2);
  EXPECT_EQ(sq.vftables(0).name(), "geo::Square::vftable");
  EXPECT_EQ(sq.vftables(0).functions(1).name(), "geo::Square::vfunc1");
  EXPECT_EQ(sq.vftables(1).subobject(), "geo::Named");
  ASSERT_TRUE(by.contains("geo::Rect"));
  EXPECT_EQ(std::vector<std::string>(by["geo::Rect"]->derived().begin(), by["geo::Rect"]->derived().end()),
            std::vector<std::string>{"geo::Square"});
  ASSERT_TRUE(by.contains("geo::Left"));
  ASSERT_EQ(by["geo::Left"]->bases_size(), 1);
  EXPECT_TRUE(by["geo::Left"]->bases(0).is_virtual());
  // The filter.
  req.set_name_contains("box");
  resp.Clear();
  ASSERT_TRUE(backend_->GetClassHierarchy(ctx_, req, resp).ok());
  ASSERT_EQ(resp.classes_size(), 1);
  EXPECT_EQ(resp.classes(0).name(), "geo::Box<int>");
}

TEST_P(MsvcApiTest, UsersAndDebugInfoOutrankTheAnalysis) {
  const std::string id = Import(fx_->stripped);
  const std::uint64_t area = Mangled(*fx_, "?area@Rect@geo@@");
  // A user's rename and prototype win.
  pb::AppendAssertionsRequest req;
  req.set_program_id(id);
  req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  req.mutable_provenance()->set_id("alice");
  auto *rn = req.add_assertions()->mutable_body()->mutable_rename();
  rn->mutable_target()->mutable_address()->set_offset(area);
  rn->set_name("Rect_area");
  auto *rt = req.add_assertions()->mutable_body()->mutable_retype();
  rt->mutable_target()->mutable_address()->set_offset(area);
  rt->mutable_type()->set_c_declaration("int Rect_area(void *self)");
  pb::AppendAssertionsResponse resp;
  ASSERT_TRUE(backend_->AppendAssertions(ctx_, req, resp).ok());
  std::optional<pb::Function> f = FunctionAt(id, area);
  ASSERT_TRUE(f);
  EXPECT_EQ(f->name(), "Rect_area");
  const std::string c = Decompile(id, area);
  EXPECT_NE(c.find("Rect_area(void *self)"), std::string::npos) << c;
  // Reverting the analysis takes back what it made: the functions only a
  // vftable reaches are gone again (discovery doesn't follow data
  // pointers), names and all.
  pb::RevertByProvenanceRequest rv;
  rv.set_program_id(id);
  rv.mutable_filter()->set_kind(pb::PROVENANCE_KIND_ANALYSIS);
  rv.mutable_filter()->set_id("msvc");
  rv.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  rv.mutable_provenance()->set_id("alice");
  pb::RevertByProvenanceResponse rvr;
  ASSERT_TRUE(backend_->RevertByProvenance(ctx_, rv, rvr).ok());
  EXPECT_GT(rvr.retracted_seqs_size(), 20);
  EXPECT_FALSE(FunctionAt(id, area));
  EXPECT_FALSE(FunctionAt(id, Mangled(*fx_, "?area@Square@geo@@")));

  // With the PDB, its names and prototypes win; the classes are still
  // found and the vftables typed.
  const std::string dbg = Import(fx_->exe);
  std::optional<pb::Function> g = FunctionAt(dbg, area);
  ASSERT_TRUE(g);
  EXPECT_EQ(g->name(), "geo::Rect::area");
  EXPECT_EQ(g->prototype_origin().asserted().provenance().id(), "pdb");
  pb::GetClassHierarchyRequest h;
  h.set_program_id(dbg);
  pb::GetClassHierarchyResponse hr;
  ASSERT_TRUE(backend_->GetClassHierarchy(ctx_, h, hr).ok());
  bool rect = false;
  for (const pb::RttiClass &k : hr.classes())
    if (k.name() == "geo::Rect") {
      rect = true;
      ASSERT_GE(k.vftables_size(), 1);
      EXPECT_EQ(k.vftables(0).functions(1).name(), "geo::Rect::area");
    }
  EXPECT_TRUE(rect);
}

TEST_P(MsvcApiTest, PeStructuresExceptionDataAndTls) {
  const std::string id = Import(fx_->stripped);
  const bool x64 = GetParam() == "x86_64";
  bool summary = false;
  for (const auto &w : warnings_) summary = summary || w.starts_with("analysis:pe:");
  EXPECT_TRUE(summary) << ::testing::PrintToString(warnings_);
  const loader::Image image = loader::load_file(fx_->stripped);
  // The headers are typed data, an analysis:pe assertion.
  pb::ListDataRequest req;
  req.set_program_id(id);
  req.mutable_page()->set_page_size(5000);
  pb::ListDataResponse resp;
  ASSERT_TRUE(backend_->ListData(ctx_, req, resp).ok());
  bool dos = false;
  for (const pb::DefinedData &d : resp.data())
    if (d.address().offset() == image.image_base) {
      dos = d.data_type().find("IMAGE_DOS_HEADER") != std::string::npos &&
            d.origin().asserted().provenance().id() == "pe";
    }
  EXPECT_TRUE(dos);
  // __security_cookie, named from the load config, shows in a /GS check.
  const std::string cookie = Decompile(id, Mangled(*fx_, "?cookie_user@@"));
  EXPECT_NE(cookie.find("__security_cookie"), std::string::npos) << cookie;
  // The TLS callback and the catch handlers are functions.
  std::map<std::string, std::uint64_t> names;
  for (const pb::Function &f : Functions(id)) names[f.name()] = f.entry().offset();
  EXPECT_EQ(names["tls_callback_0"], fx_->at(x64 ? "rk_tls_callback" : "_rk_tls_callback@12"));
  int catches = 0;
  for (const auto &[n, a] : names) catches += n.starts_with("Catch@") || n.starts_with("Catch_All@");
  EXPECT_EQ(catches, 2);
  // x64: every .pdata entry starts a function.
  if (x64) {
    ASSERT_FALSE(image.function_ranges.empty());
    std::set<std::uint64_t> entries;
    for (const pb::Function &f : Functions(id)) entries.insert(f.entry().offset());
    for (const loader::FunctionRange &r : image.function_ranges) EXPECT_TRUE(entries.contains(r.start)) << std::hex << r.start;
  }
}

api::Status LoadPdb(api::Backend &b, const std::string &id, pb::LoadPdbRequest req, pb::LoadPdbResponse &resp) {
  CallContext ctx;
  req.set_program_id(id);
  req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  req.mutable_provenance()->set_id("alice");
  return b.LoadPdb(ctx, req, resp);
}

TEST_P(MsvcApiTest, LoadPdbOnAnOpenProgram) {
  const std::uint64_t area = Mangled(*fx_, "?area@Rect@geo@@");
  // The debug build without its PDB beside it: imported without debug info.
  const fs::path dir = fx_->exe.parent_path() / "moved";
  fs::create_directories(dir);
  fs::copy_file(fx_->exe, dir / fx_->exe.filename(), fs::copy_options::overwrite_existing);
  const std::string id = Import(dir / fx_->exe.filename());
  EXPECT_EQ(FunctionAt(id, area)->name(), "geo::Rect::vfunc1");
  // Its own PDB, by path: exact; names and prototypes are the PDB's.
  pb::LoadPdbRequest req;
  req.set_path(fx_->pdb.string());
  pb::LoadPdbResponse resp;
  ASSERT_TRUE(LoadPdb(*backend_, id, req, resp).ok());
  EXPECT_TRUE(resp.exact());
  EXPECT_GT(resp.functions(), 10u);
  EXPECT_GT(resp.types(), 10u);
  std::optional<pb::Function> f = FunctionAt(id, area);
  ASSERT_TRUE(f);
  EXPECT_EQ(f->name(), "geo::Rect::area");
  EXPECT_EQ(f->prototype_origin().asserted().provenance().id(), "pdb");
  // The PDB's classes have their vftable pointers (LF_VFUNCTAB), to
  // structs of the virtual functions they introduce: a virtual call reads
  // as one. (Shape has no definition in this PDB: clang emits a class's
  // only where its vftable is.)
  const std::string call = Decompile(id, Mangled(*fx_, "?call_base@@"));
  EXPECT_NE(call.find("b->vftable->get"), std::string::npos) << call;

  // The stripped build has no CodeView record: only forced.
  const std::string stripped = Import(fx_->stripped);
  pb::LoadPdbResponse r2;
  api::Status st = LoadPdb(*backend_, stripped, req, r2);
  EXPECT_EQ(st.code, api::StatusCode::kFailedPrecondition);
  EXPECT_NE(st.message.find("force"), std::string::npos) << st.message;
  req.set_force(true);
  ASSERT_TRUE(LoadPdb(*backend_, stripped, req, r2).ok());
  EXPECT_FALSE(r2.exact());
  ASSERT_GE(r2.warnings_size(), 1);
  EXPECT_NE(r2.warnings(0).find("another build"), std::string::npos);
  EXPECT_EQ(FunctionAt(stripped, area)->name(), "geo::Rect::area");

  // From the symbol path: a local store holding it under its key.
  const fs::path store = fx_->exe.parent_path() / "store";
  const auto bytes = [&] {
    std::ifstream in(fx_->pdb, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  }();
  const auto pid = debuginfo::read_pdb_identity(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(bytes.data()), bytes.size()));
  const fs::path in_store = store / fx_->pdb.filename() / SymbolKey(pid.guid, pid.age) / fx_->pdb.filename();
  fs::create_directories(in_store.parent_path());
  fs::copy_file(fx_->pdb, in_store, fs::copy_options::overwrite_existing);
  pb::SetSymbolSettingsRequest set;
  set.mutable_settings()->set_symbol_path("srv*" + store.string());
  pb::SetSymbolSettingsResponse set_resp;
  ASSERT_TRUE(backend_->SetSymbolSettings(ctx_, set, set_resp).ok());
  EXPECT_FALSE(set_resp.settings().downloads());
  const std::string again = Import(dir / fx_->exe.filename());
  pb::LoadPdbRequest sym;
  sym.set_symbol_path(true);
  pb::LoadPdbResponse r3;
  ASSERT_TRUE(LoadPdb(*backend_, again, sym, r3).ok());
  EXPECT_TRUE(r3.exact());
  EXPECT_EQ(fs::path(r3.pdb_file()), in_store);
  EXPECT_EQ(FunctionAt(again, area)->name(), "geo::Rect::area");
  // Not a PDB: refused.
  pb::LoadPdbRequest bad;
  bad.set_path(fx_->exe.string());
  bad.set_force(true);
  EXPECT_EQ(LoadPdb(*backend_, again, bad, r3).code, api::StatusCode::kInvalidArgument);
}

INSTANTIATE_TEST_SUITE_P(Arch, MsvcApiTest, ::testing::Values("x86_64", "i686"));

}  // namespace
}  // namespace revkit::backend
