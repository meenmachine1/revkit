// Nintendo DS games through the backend (docs/nds.md): the synthetic
// ds-decomp project and ROM (tests/data/nds/make_fixture.py) imported as
// module programs, the names across modules, persisted and reopened, the
// export back to symbols.txt, and the refusals.
#include "decomp_kb.h"
#include "nds_fixture.h"

#include "nds_import.h"
#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <sys/stat.h>

#include <atomic>
#include <chrono>
#include <ctime>
#include <thread>
#include <filesystem>
#include <map>
#include <set>
#include <sstream>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;
namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

class Nds : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    fixture_ = nds::testing::nds_fixture(REVKIT_NDS_PYTHON, REVKIT_TEST_CLANG, REVKIT_TEST_LLD, REVKIT_NDS_FIXTURE);
    if (!fixture_) GTEST_SKIP() << "no clang, ld.lld or python3 for the DS fixture";
  }

  std::unique_ptr<api::Backend> Make(const std::string &project_dir = {}, bool roots = true) {
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.project_dir = project_dir;
    if (roots) o.browse_roots = {fixture_->string()};
    return MakeImageBackend(o);
  }

  static pb::Provenance User() {
    pb::Provenance p;
    p.set_kind(pb::PROVENANCE_KIND_USER);
    p.set_id("test");
    return p;
  }

  pb::ImportDsdProjectRequest Dsd() const {
    pb::ImportDsdProjectRequest req;
    req.set_project_id("default");
    req.set_config_path((*fixture_ / "dsd/config/arm9/config.yaml").string());
    *req.mutable_provenance() = User();
    return req;
  }

  std::string Decompile(api::Backend &b, const std::string &id, std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(id);
    req.mutable_function()->set_offset(entry);
    req.mutable_options()->set_include_text(true);
    pb::DecompileResponse d;
    auto st = b.Decompile(ctx_, req, d);
    EXPECT_TRUE(st.ok()) << st.message;
    return d.function().text();
  }

  std::map<std::uint64_t, std::string> Functions(api::Backend &b, const std::string &id) {
    pb::ListFunctionsRequest req;
    req.set_program_id(id);
    req.mutable_page()->set_page_size(10000);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(b.ListFunctions(ctx_, req, resp).ok());
    std::map<std::uint64_t, std::string> out;
    for (const pb::Function &f : resp.functions()) out[f.entry().offset()] = f.name();
    return out;
  }

  std::optional<fs::path> fixture_;
  CallContext ctx_;
};

TEST_F(Nds, DsdProjectImportsReopensAndExports) {
  const fs::path dir = *fixture_ / "project";
  fs::remove_all(dir);
  std::string main_id, ov_id, text;
  std::map<std::uint64_t, std::string> fns;
  std::uint64_t update = 0, draw = 0;
  {
    auto b = Make(dir.string());
    pb::ImportDsdProjectResponse resp;
    auto st = b->ImportDsdProject(ctx_, Dsd(), resp);
    ASSERT_TRUE(st.ok()) << st.message;
    ASSERT_EQ(resp.imported(), 6u);
    for (const pb::NdsModuleImport &m : resp.modules()) {
      if (m.module() == "main") main_id = m.program().program_id();
      if (m.module() == "ov000") ov_id = m.program().program_id();
      EXPECT_TRUE(m.error().empty()) << m.module() << ": " << m.error();
    }
    fns = Functions(*b, main_id);
    for (const auto &[a, n] : fns) {
      if (n == "SceneBase::Update") update = a;
      if (n == "SceneBase::Draw") draw = a;
    }
    ASSERT_NE(update, 0u);
    ASSERT_NE(draw, 0u);
    std::uint64_t ov_update = 0;
    for (const auto &[a, n] : Functions(*b, ov_id))
      if (n == "GameOverScene::Update") ov_update = a;
    ASSERT_NE(ov_update, 0u);
    text = Decompile(*b, ov_id, ov_update);
    EXPECT_NE(text.find("SceneBase::Update((SceneBase *)this)"), std::string::npos) << text;
    EXPECT_EQ(text.find("func_0x02"), std::string::npos) << text;
  }
  // Reopened: the symbols (kept in the raw image's record) and the links.
  auto b = Make(dir.string());
  EXPECT_EQ(Functions(*b, main_id), fns);
  std::uint64_t ov_update = 0;
  for (const auto &[a, n] : Functions(*b, ov_id))
    if (n == "GameOverScene::Update") ov_update = a;
  EXPECT_EQ(Decompile(*b, ov_id, ov_update), text);
  // A rename in main reaches the overlay's decompilation.
  pb::AppendAssertionsRequest ren;
  ren.set_program_id(main_id);
  *ren.mutable_provenance() = User();
  auto *r = ren.add_assertions()->mutable_body()->mutable_rename();
  r->mutable_target()->mutable_address()->set_offset(update);
  r->set_name("BaseTick");
  pb::AppendAssertionsResponse rr;
  ASSERT_TRUE(b->AppendAssertions(ctx_, ren, rr).ok());
  EXPECT_NE(Decompile(*b, ov_id, ov_update).find("BaseTick("), std::string::npos);
  // The export: the rename as a change to symbols.txt, nothing written.
  pb::ExportDsdSymbolsRequest ex;
  ex.set_project_id("default");
  ex.add_program_ids(main_id);
  pb::ExportDsdSymbolsResponse er;
  auto st = b->ExportDsdSymbols(ctx_, ex, er);
  ASSERT_TRUE(st.ok()) << st.message;
  ASSERT_EQ(er.modules_size(), 1);
  EXPECT_EQ(er.renamed(), 1u);
  EXPECT_NE(er.patch().find("-_ZN9SceneBase6UpdateEv kind:function(arm,"), std::string::npos) << er.patch();
  EXPECT_NE(er.patch().find("+BaseTick kind:function(arm,"), std::string::npos) << er.patch();
  EXPECT_FALSE(er.modules(0).written());
  // A program that isn't a dsd module.
  ex.clear_program_ids();
  ex.add_program_ids("default/nothing");
  EXPECT_FALSE(b->ExportDsdSymbols(ctx_, ex, er).ok());
}

// Cross-module invalidation under concurrency (bug scrub part 3, for
// TSan): two threads decompile the overlay while a third renames the main
// module's function it calls; the last name is the one shown after.
TEST_F(Nds, OverlayReadsWhileMainIsRenamed) {
  auto b = Make();
  pb::ImportDsdProjectRequest req = Dsd();
  req.add_modules("main");
  req.add_modules("ov000");
  pb::ImportDsdProjectResponse resp;
  ASSERT_TRUE(b->ImportDsdProject(ctx_, req, resp).ok());
  std::string main_id, ov_id;
  for (const pb::NdsModuleImport &m : resp.modules()) {
    if (m.module() == "main") main_id = m.program().program_id();
    if (m.module() == "ov000") ov_id = m.program().program_id();
  }
  ASSERT_FALSE(main_id.empty() || ov_id.empty());
  std::uint64_t update = 0, ov_update = 0;
  for (const auto &[a, n] : Functions(*b, main_id))
    if (n == "SceneBase::Update") update = a;
  for (const auto &[a, n] : Functions(*b, ov_id))
    if (n == "GameOverScene::Update") ov_update = a;
  ASSERT_NE(update, 0u);
  ASSERT_NE(ov_update, 0u);
  std::atomic<bool> stop{false};
  std::vector<std::thread> readers;
  for (int k = 0; k < 2; ++k)
    readers.emplace_back([&] {
      CallContext ctx;
      while (!stop) {
        pb::DecompileRequest d;
        d.set_program_id(ov_id);
        d.mutable_function()->set_offset(ov_update);
        d.mutable_options()->set_include_text(true);
        pb::DecompileResponse dr;
        EXPECT_TRUE(b->Decompile(ctx, d, dr).ok());
      }
    });
  std::string last;
  for (int i = 0; i < 12; ++i) {
    last = "Tick" + std::to_string(i);
    pb::AppendAssertionsRequest ren;
    ren.set_program_id(main_id);
    *ren.mutable_provenance() = User();
    auto *r = ren.add_assertions()->mutable_body()->mutable_rename();
    r->mutable_target()->mutable_address()->set_offset(update);
    r->set_name(last);
    pb::AppendAssertionsResponse rr;
    if (!b->AppendAssertions(ctx_, ren, rr).ok()) {
      ADD_FAILURE() << "rename " << i;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
  }
  stop = true;
  for (std::thread &t : readers) t.join();
  EXPECT_NE(Decompile(*b, ov_id, ov_update).find(last + "("), std::string::npos);
}

TEST_F(Nds, RomImport) {
  auto b = Make();
  pb::ImportNdsRomRequest req;
  req.set_project_id("default");
  req.set_content(nds::testing::read_text(*fixture_ / "game.nds"));
  *req.mutable_provenance() = User();
  req.set_skip_arm7(true);
  pb::ImportNdsRomResponse resp;
  auto st = b->ImportNdsRom(ctx_, req, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  std::map<std::string, const pb::NdsModuleImport *> mods;
  for (const pb::NdsModuleImport &m : resp.modules()) mods[m.module()] = &m;
  EXPECT_EQ(mods.size(), 5u);
  EXPECT_FALSE(mods.contains("arm7"));
  ASSERT_TRUE(mods.contains("main"));
  EXPECT_TRUE(mods["main"]->compressed());
  EXPECT_EQ(mods["main"]->address(), 0x02000000u);
  EXPECT_EQ(mods["itcm"]->address(), 0x01ff8000u);
  // Overlays are linked to main: a call into main is named by address.
  EXPECT_EQ(std::vector<std::string>(mods["ov000"]->links().begin(), mods["ov000"]->links().end()),
            (std::vector<std::string>{"dtcm", "itcm", "main"}));
  // Not a ROM.
  req.set_content(std::string(4096, 'x'));
  EXPECT_EQ(b->ImportNdsRom(ctx_, req, resp).code, StatusCode::kInvalidArgument);
}

TEST_F(Nds, Refusals) {
  {
    auto b = Make({}, false);
    pb::ImportDsdProjectResponse resp;
    EXPECT_EQ(b->ImportDsdProject(ctx_, Dsd(), resp).code, StatusCode::kFailedPrecondition);
  }
  auto b = Make();
  pb::ImportDsdProjectResponse resp;
  pb::ImportDsdProjectRequest req = Dsd();
  req.set_config_path("/etc/hostname");
  EXPECT_EQ(b->ImportDsdProject(ctx_, req, resp).code, StatusCode::kPermissionDenied);
  req.set_config_path((*fixture_ / "expect.json").string());
  EXPECT_EQ(b->ImportDsdProject(ctx_, req, resp).code, StatusCode::kInvalidArgument);
  req = Dsd();
  req.clear_provenance();
  EXPECT_EQ(b->ImportDsdProject(ctx_, req, resp).code, StatusCode::kInvalidArgument);
  // Only some modules.
  req = Dsd();
  req.add_modules("main");
  req.add_modules("ov001");
  ASSERT_TRUE(b->ImportDsdProject(ctx_, req, resp).ok());
  EXPECT_EQ(resp.imported(), 2u);
}


// Bug scrub part 3: a record's fields can't be forged by a line break in a
// name, and the export reads and writes only below the browse root: never a
// link out of it, a FIFO, or a link planted at its backup's or temporary
// file's name.
TEST(NdsRecord, LineBreaksDontForgeFields) {
  DsdRecord r;
  r.source = "dsd";
  r.module = "x\nsymbols /etc/passwd";
  r.symbols = "/root/symbols.txt";
  r.links.emplace_back("main\nsymbols /etc/shadow", "default/1");
  const DsdRecord d = DsdRecord::decode(r.encode());
  EXPECT_EQ(d.symbols, "/root/symbols.txt");
  EXPECT_TRUE(d.module.empty());
  EXPECT_TRUE(d.links.empty());
}

TEST_F(Nds, ExportStaysBelowTheRoot) {
  const fs::path copy = *fixture_ / "hostile";
  fs::remove_all(copy);
  fs::create_directories(copy);
  fs::copy(*fixture_ / "dsd", copy / "dsd", fs::copy_options::recursive);
  const fs::path symbols = copy / "dsd/config/arm9/symbols.txt";
  const fs::path victim = *fixture_ / "victim.txt";
  { std::ofstream(victim) << "untouched\n"; }
  auto b = Make();
  pb::ImportDsdProjectRequest req = Dsd();
  req.set_config_path((copy / "dsd/config/arm9/config.yaml").string());
  req.add_modules("main");
  pb::ImportDsdProjectResponse resp;
  ASSERT_TRUE(b->ImportDsdProject(ctx_, req, resp).ok());
  ASSERT_EQ(resp.imported(), 1u);
  const std::string id = resp.modules(0).program().program_id();
  // A rename to export.
  std::uint64_t at = 0;
  for (const auto &[a, n] : Functions(*b, id))
    if (n == "SceneBase::Update") at = a;
  ASSERT_NE(at, 0u);
  pb::AppendAssertionsRequest ren;
  ren.set_program_id(id);
  *ren.mutable_provenance() = User();
  auto *r = ren.add_assertions()->mutable_body()->mutable_rename();
  r->mutable_target()->mutable_address()->set_offset(at);
  r->set_name("BaseTick");
  pb::AppendAssertionsResponse rr;
  ASSERT_TRUE(b->AppendAssertions(ctx_, ren, rr).ok());
  // Links at the backup's and the temporary file's names for the next
  // seconds, to a file the export must not write.
  std::vector<fs::path> planted;
  for (int i = 0; i < 6; ++i) {
    const std::time_t t = std::time(nullptr) + i;
    std::tm tm{};
    gmtime_r(&t, &tm);
    char stamp[32];
    std::strftime(stamp, sizeof stamp, "%Y%m%dT%H%M%SZ", &tm);
    for (const char *suffix : {".bak-", ".tmp-"}) {
      planted.push_back(fs::path(symbols.string() + suffix + stamp));
      fs::create_symlink(victim, planted.back());
    }
  }
  pb::ExportDsdSymbolsRequest ex;
  ex.set_project_id("default");
  ex.add_program_ids(id);
  ex.set_write(true);
  pb::ExportDsdSymbolsResponse er;
  auto st = b->ExportDsdSymbols(ctx_, ex, er);
  ASSERT_TRUE(st.ok()) << st.message;
  ASSERT_EQ(er.modules_size(), 1);
  EXPECT_TRUE(er.modules(0).written()) << (er.modules(0).warnings().empty() ? "" : er.modules(0).warnings(0));
  EXPECT_EQ(nds::testing::read_text(victim), "untouched\n");
  EXPECT_NE(nds::testing::read_text(symbols).find("BaseTick"), std::string::npos);
  const fs::path backup = er.modules(0).backup_path();
  EXPECT_FALSE(fs::is_symlink(backup)) << backup;
  EXPECT_EQ(nds::testing::read_text(backup).find("BaseTick"), std::string::npos);
  for (const fs::path &p : planted) EXPECT_TRUE(fs::is_symlink(p)) << p;
  // symbols.txt swapped for a link out of the root, then for a FIFO: a
  // viewer's export reads neither (and doesn't block on the FIFO).
  ex.set_write(false);
  ex.set_include_text(true);
  fs::remove(symbols);
  fs::create_symlink("/etc/passwd", symbols);
  er.Clear();
  ASSERT_TRUE(b->ExportDsdSymbols(ctx_, ex, er).ok());
  ASSERT_EQ(er.modules_size(), 1);
  EXPECT_EQ(er.modules(0).text().find("root:"), std::string::npos);
  EXPECT_FALSE(er.modules(0).warnings().empty());
  fs::remove(symbols);
  ASSERT_EQ(::mkfifo(symbols.c_str(), 0600), 0);
  er.Clear();
  ASSERT_TRUE(b->ExportDsdSymbols(ctx_, ex, er).ok());
  ASSERT_EQ(er.modules_size(), 1);
  EXPECT_FALSE(er.modules(0).warnings().empty());
  EXPECT_TRUE(er.modules(0).text().empty());
  fs::remove_all(copy);
  fs::remove(victim);
}

TEST(DecompKbText, FindsDefinitions) {
  const std::string src = R"(#include "game.h"

// A comment with Clamp(1, 2) { not code }
int Clamp(int v, int lo, int hi);  // a declaration first
int Clamp(int v, int lo, int hi) { return v < lo ? lo : v > hi ? hi : v; }

GameOverScene::GameOverScene() : cursor{0, 0}, fade(1.0f) {}
GameOverScene::~GameOverScene() { gScene = nullptr; /* } in a comment */ }

void GameOverScene::Update() {
  const char *s = "}";
  if (frame > 60) { ShowRetryWindow(1); }
}

__attribute__((target("thumb"), noinline)) int ThumbChecksum(const unsigned char *p, int n) {
  return n;
}

class Inline {
 public:
  int Get() const { return value; }
  int value;
};
)";
  EXPECT_EQ(ExtractFunctionText(src, "Clamp"), "int Clamp(int v, int lo, int hi) { return v < lo ? lo : v > hi ? hi : v; }");
  EXPECT_EQ(ExtractFunctionText(src, "GameOverScene::GameOverScene"),
            "GameOverScene::GameOverScene() : cursor{0, 0}, fade(1.0f) {}");
  EXPECT_EQ(ExtractFunctionText(src, "GameOverScene::~GameOverScene"),
            "GameOverScene::~GameOverScene() { gScene = nullptr; /* } in a comment */ }");
  auto upd = ExtractFunctionText(src, "GameOverScene::Update");
  ASSERT_TRUE(upd);
  EXPECT_TRUE(upd->starts_with("void GameOverScene::Update() {")) << *upd;
  EXPECT_TRUE(upd->ends_with("ShowRetryWindow(1); }\n}")) << *upd;
  auto thumb = ExtractFunctionText(src, "ThumbChecksum");
  ASSERT_TRUE(thumb);
  EXPECT_TRUE(thumb->starts_with("__attribute__((target(\"thumb\"), noinline)) int ThumbChecksum(")) << *thumb;
  EXPECT_EQ(ExtractFunctionText(src, "Inline::Get"), "  int Get() const { return value; }");
  EXPECT_FALSE(ExtractFunctionText(src, "Missing"));
  EXPECT_FALSE(ExtractFunctionText("int f(int);", "f"));
  EXPECT_FALSE(ExtractFunctionText("int f( { {", "f"));
}

TEST(DecompKbText, Manifest) {
  std::size_t bad = 0;
  auto m = ReadManifest(R"({"module": "ov006", "address": "0x02219604", "size": 948, "compiler": "mwcc", "flags": "-O4,p"}
{"module": "main", "address": 33554432, "status": "matching"}
not json
{"module": "main"}
)",
                        &bad);
  EXPECT_EQ(bad, 2u);
  ASSERT_EQ(m.size(), 2u);
  EXPECT_EQ(m.at({"ov006", 0x02219604}).compiler, "mwcc");
  EXPECT_EQ(m.at({"ov006", 0x02219604}).size, 948u);
  EXPECT_EQ(m.at({"main", 0x02000000}).status, "matching");
  // A matching pipeline's fields.
  bad = 0;
  auto p = ReadManifest(R"({"address": "0x02000100", "compiler": "mwcc-ds/1.2/sp2", "flags": "-O4,p -proc arm946e", "fuzzy": 87.5, "isa": "Thumb", "library": "NitroSDK", "masked_sha256": "ab12", "module": "ov004", "name": "func_02000100", "object": "build/ov004/a.o", "relocations": [{"offset": 4}, {"offset": 12}, {"offset": 20}], "size": 64, "source": "src/ov004/a.c", "status": "fuzzy", "variant": "permute"}
{"address": "0x02000200", "module": "ov004", "status": "exact", "flags": ["-O4,p", "-interworking"], "relocations": 2}
{"address": -5, "module": "ov004"}
)",
                        &bad);
  EXPECT_EQ(bad, 1u);
  ASSERT_EQ(p.size(), 2u);
  const ManifestEntry &e = p.at({"ov004", 0x02000100});
  EXPECT_EQ(e.symbol, "func_02000100");
  EXPECT_EQ(e.mode, "thumb");
  EXPECT_EQ(e.masked_hash, "ab12");
  EXPECT_EQ(e.library, "NitroSDK");
  EXPECT_EQ(e.object, "build/ov004/a.o");
  EXPECT_EQ(e.variant, "permute");
  EXPECT_EQ(e.relocations, 3u);
  EXPECT_EQ(e.status, "nonmatching");
  EXPECT_DOUBLE_EQ(e.fuzzy, 87.5);
  EXPECT_EQ(e.source, "src/ov004/a.c");
  EXPECT_EQ(p.at({"ov004", 0x02000200}).status, "matching");
  EXPECT_EQ(p.at({"ov004", 0x02000200}).flags, "-O4,p -interworking");
  EXPECT_EQ(p.at({"ov004", 0x02000200}).relocations, 2u);
}

TEST(DecompKbText, InstructionDiff) {
  EXPECT_EQ(InstructionDiff({"push {lr}", "bl <addr>", "pop {pc}"}, {"push {lr}", "bl <addr>", "pop {pc}"}),
            " push {lr}\n bl <addr>\n pop {pc}\n");
  EXPECT_EQ(InstructionDiff({"push {lr}", "mov r0,#0x3", "bl <addr>", "pop {pc}"},
                            {"push {lr}", "mov r0,#0x4", "bl <addr>", "add r0,r0,#0x1", "pop {pc}"}),
            " push {lr}\n-mov r0,#0x3\n+mov r0,#0x4\n bl <addr>\n+add r0,r0,#0x1\n pop {pc}\n");
  EXPECT_EQ(InstructionDiff({}, {"bx lr"}), "+bx lr\n");
  EXPECT_EQ(InstructionDiff({"a", "b", "c"}, {"a", "b", "c"}, 2), " a\n b\n...\n");
}

TEST_F(Nds, RomAsAFileSystem) {
  auto b = Make();
  pb::OpenFileSystemRequest open;
  open.set_project_id("default");
  open.set_content(nds::testing::read_text(*fixture_ / "game.nds"));
  open.set_name("game.nds");
  pb::OpenFileSystemResponse opened;
  auto st = b->OpenFileSystem(ctx_, open, opened);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(opened.root().format(), "nds");
  pb::ListFileSystemRequest ls;
  ls.set_session_id(opened.session_id());
  ls.set_path("/");
  ls.set_recursive(true);
  pb::ListFileSystemResponse list;
  ASSERT_TRUE(b->ListFileSystem(ctx_, ls, list).ok());
  std::map<std::string, pb::FileSystemEntry> by;
  for (const pb::FileSystemEntry &e : list.entries()) by[e.path()] = e;
  for (const char *p : {"/arm9.bin", "/arm7.bin", "/header.bin", "/y9.bin", "/overlay/overlay_0000.bin",
                        "/overlay/overlay_0001.bin", "/files/data/msg.lz", "/files/data/pack.narc", "/files/data/sub/tiles.lz11"})
    EXPECT_TRUE(by.contains(p)) << p;
  // The ARM9 decompressed, with its language and address; an LZ10 file decompressed.
  EXPECT_EQ(by["/arm9.bin"].language_id(), "ARM:LE:32:v5t");
  auto read = [&](const std::string &path) {
    pb::ReadFileSystemFileRequest rr;
    rr.set_session_id(opened.session_id());
    rr.set_path(path);
    rr.set_length(1 << 20);
    pb::ReadFileSystemFileResponse rd;
    auto rs = b->ReadFileSystemFile(ctx_, rr, rd);
    EXPECT_TRUE(rs.ok()) << path << ": " << rs.message;
    return rd.data();
  };
  EXPECT_EQ(read("/files/data/msg.lz"), nds::testing::read_text(*fixture_ / "plain/msg.lz"));
  EXPECT_EQ(read("/arm9.bin"), nds::testing::read_text(*fixture_ / "plain/arm9.bin"));
  EXPECT_EQ(read("/overlay/overlay_0000.bin"), nds::testing::read_text(*fixture_ / "plain/ov000.bin"));
  // The NARC inside, by its names.
  ls.set_path("/files/data/pack.narc!/");
  pb::ListFileSystemResponse inner;
  ASSERT_TRUE(b->ListFileSystem(ctx_, ls, inner).ok());
  std::set<std::string> names;
  for (const pb::FileSystemEntry &e : inner.entries()) names.insert(e.name());
  EXPECT_TRUE(names.contains("readme.txt") && names.contains("pal.bin")) << inner.DebugString();
  EXPECT_EQ(read("/files/data/pack.narc!/readme.txt"), "inside a NARC\n");
}

}  // namespace
}  // namespace revkit::backend

// ---- What a matching-decompilation run on a DS game hit (docs/known-issues.md) ----

namespace revkit::backend {
namespace {

class NdsFixes : public Nds {
 protected:
  // Imports the dsd project; its module programs by name.
  std::map<std::string, std::string> Import(api::Backend &b, pb::NameConflict conflict = pb::NAME_CONFLICT_UNSPECIFIED,
                                            pb::ImportDsdProjectResponse *out = nullptr) {
    pb::ImportDsdProjectRequest req = Dsd();
    req.set_on_conflict(conflict);
    pb::ImportDsdProjectResponse resp;
    auto st = b.ImportDsdProject(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    std::map<std::string, std::string> ids;
    for (const pb::NdsModuleImport &m : resp.modules()) ids[m.module()] = m.program().program_id();
    if (out) *out = resp;
    return ids;
  }
  std::uint64_t Named(api::Backend &b, const std::string &id, const std::string &name) {
    for (const auto &[a, n] : Functions(b, id))
      if (n == name) return a;
    return 0;
  }
  api::Status Append(api::Backend &b, const std::string &id, std::vector<pb::AssertionBody> bodies,
                     pb::AppendAssertionsResponse &resp, bool skip_invalid = false) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(id);
    *req.mutable_provenance() = User();
    req.set_skip_invalid(skip_invalid);
    for (pb::AssertionBody &body : bodies) *req.add_assertions()->mutable_body() = std::move(body);
    return b.AppendAssertions(ctx_, req, resp);
  }
  std::uint32_t InsnLength(api::Backend &b, const std::string &id, std::uint64_t at) {
    pb::GetInstructionRequest req;
    req.set_program_id(id);
    req.mutable_address()->set_offset(at);
    pb::GetInstructionResponse resp;
    if (!b.GetInstruction(ctx_, req, resp).ok()) return 0;
    return resp.instruction().length();
  }
};

pb::AssertionBody Bounds(std::uint64_t entry, pb::InstructionSet isa = pb::INSTRUCTION_SET_UNSPECIFIED) {
  pb::AssertionBody b;
  b.mutable_function_bounds()->mutable_entry()->set_offset(entry);
  b.mutable_function_bounds()->set_instruction_set(isa);
  return b;
}

pb::AssertionBody Rename(std::uint64_t at, const std::string &name) {
  pb::AssertionBody b;
  b.mutable_rename()->mutable_target()->mutable_address()->set_offset(at);
  b.mutable_rename()->set_name(name);
  return b;
}

// The DS's I/O, shared WRAM and main memory's shared area are volatile
// blocks of every module (cut around the modules), so a poll reads the
// hardware each time round its loop.
TEST_F(NdsFixes, IoIsVolatile) {
  auto b = Make();
  auto ids = Import(*b);
  pb::GetMemoryMapRequest mr;
  mr.set_program_id(ids.at("ov000"));
  pb::GetMemoryMapResponse map;
  ASSERT_TRUE(b->GetMemoryMap(ctx_, mr, map).ok());
  std::map<std::string, pb::MemoryBlock> blocks;
  for (const pb::MemoryBlock &m : map.blocks()) blocks[m.name()] = m;
  ASSERT_TRUE(blocks.contains("io")) << map.DebugString();
  EXPECT_EQ(blocks["io"].range().first().offset(), 0x04000000u);
  EXPECT_EQ(blocks["io"].range().last().offset(), 0x04FFFFFFu);
  EXPECT_TRUE(blocks["io"].is_volatile());
  EXPECT_FALSE(blocks["io"].execute());
  EXPECT_TRUE(blocks["shared_wram"].is_volatile());
  EXPECT_TRUE(blocks["main_shared"].is_volatile());
  EXPECT_EQ(blocks["main_shared"].range().first().offset(), 0x027FF000u);
  // The ARM7's map: its shared WRAM window ends where its own WRAM starts.
  mr.set_program_id(ids.at("arm7"));
  map.Clear();
  ASSERT_TRUE(b->GetMemoryMap(ctx_, mr, map).ok());
  bool shared = false;
  for (const pb::MemoryBlock &m : map.blocks())
    if (m.name() == "shared_wram") {
      shared = true;
      EXPECT_LE(m.range().last().offset(), 0x037FFFFFu);
    }
  EXPECT_TRUE(shared);
  const std::uint64_t wait = Named(*b, ids.at("ov000"), "WaitFrames");
  ASSERT_NE(wait, 0u);
  const std::string text = Decompile(*b, ids.at("ov000"), wait);
  // Both polls survive as loops that read again, and the IME save is kept.
  EXPECT_EQ(text.find("while( true )"), std::string::npos) << text;
  EXPECT_NE(text.find("4000006"), std::string::npos) << text;
  EXPECT_NE(text.find("27ffc3c"), std::string::npos) << text;
  EXPECT_NE(text.find("4000208"), std::string::npos) << text;
}

// A function's instruction set stays its own when bounds are asserted
// without one: the untagged entry of a Thumb function is that Thumb
// function, not an ARM one over its bytes. As a run sends them: main
// imported raw, its symbols' bounds asserted through the SDK.
TEST_F(NdsFixes, ThumbBoundsKeepTheirMode) {
  auto b = Make();
  auto ids = Import(*b);
  const std::uint64_t thumb = Named(*b, ids.at("main"), "ThumbChecksum");
  ASSERT_NE(thumb, 0u);
  pb::ImportProgramRequest in;
  in.set_project_id("default");
  in.set_name("raw-main");
  in.set_path((*fixture_ / "dsd/extract/arm9/arm9.bin").string());
  in.mutable_options()->set_format("raw");
  in.mutable_options()->set_language_id("ARM:LE:32:v5t");
  in.mutable_options()->set_has_image_base(true);
  in.mutable_options()->set_image_base(0x02000000);
  *in.mutable_provenance() = User();
  pb::ImportProgramResponse ir;
  ASSERT_TRUE(b->ImportProgram(ctx_, in, ir).ok());
  const std::string main = ir.program().program_id();
  // Tagged: decoded and checked as Thumb (it was checked as ARM, and
  // refused where the bytes aren't an ARM instruction).
  pb::AppendAssertionsResponse r;
  auto st = Append(*b, main, {Bounds(thumb | 1)}, r);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(r.assertions(0).key().address().offset(), thumb | 1);
  ASSERT_EQ(InsnLength(*b, main, thumb), 2u);
  // Untagged: the function's own instruction set, keyed at its tagged entry.
  r.Clear();
  ASSERT_TRUE(Append(*b, main, {Bounds(thumb)}, r).ok());
  EXPECT_EQ(r.assertions(0).key().address().offset(), thumb | 1) << "keyed at the tagged entry";
  EXPECT_EQ(InsnLength(*b, main, thumb), 2u);
  EXPECT_NE(Decompile(*b, main, thumb).find("<< 1"), std::string::npos);
  // Tagged and asked as ARM: refused, saying why.
  r.Clear();
  st = Append(*b, main, {Bounds(thumb | 1, pb::INSTRUCTION_SET_ARM)}, r);
  EXPECT_EQ(st.code, StatusCode::kInvalidArgument);
  EXPECT_NE(st.message.find("bit 0"), std::string::npos) << st.message;
  // Cleared, then disassembled as Thumb and bounded in the same request.
  pb::AssertionBody clear;
  clear.mutable_listing_edit()->mutable_address()->set_offset(thumb);
  clear.mutable_listing_edit()->mutable_clear()->set_length(2);
  r.Clear();
  ASSERT_TRUE(Append(*b, main, {clear}, r).ok());
  pb::AssertionBody dis;
  dis.mutable_listing_edit()->mutable_address()->set_offset(thumb);
  dis.mutable_listing_edit()->mutable_disassemble()->set_instruction_set(pb::INSTRUCTION_SET_THUMB);
  r.Clear();
  st = Append(*b, main, {dis, Bounds(thumb)}, r);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(r.assertions(1).key().address().offset(), thumb | 1);
  EXPECT_EQ(InsnLength(*b, main, thumb), 2u);
  // And asked for after the Disassemble has landed, in a request of its own.
  r.Clear();
  ASSERT_TRUE(Append(*b, main, {Bounds(thumb)}, r).ok());
  EXPECT_EQ(r.assertions(0).key().address().offset(), thumb | 1);
}

// A batch names every body it refuses; skip_invalid commits the others.
TEST_F(NdsFixes, AssertionBatchRefusals) {
  auto b = Make();
  auto ids = Import(*b);
  const std::string main = ids.at("main");
  const std::uint64_t update = Named(*b, main, "SceneBase::Update"), draw = Named(*b, main, "SceneBase::Draw");
  ASSERT_NE(update, 0u);
  pb::AssertionBody outside = Rename(0x09000000, "nowhere");
  std::vector<pb::AssertionBody> bodies = {Rename(update, "Tick"), Rename(update, "has space"), outside,
                                           Rename(draw, "Paint"), Bounds(0x09000000)};
  pb::AppendAssertionsResponse r;
  auto st = Append(*b, main, bodies, r);
  ASSERT_EQ(st.code, StatusCode::kInvalidArgument);
  EXPECT_NE(st.message.find("assertions[1]: name contains whitespace"), std::string::npos) << st.message;
  EXPECT_NE(st.message.find("assertions[2]: address 0x9000000 is not in memory"), std::string::npos) << st.message;
  EXPECT_NE(st.message.find("assertions[4]"), std::string::npos) << st.message;
  EXPECT_NE(Named(*b, main, "SceneBase::Update"), 0u) << "nothing landed";
  r.Clear();
  ASSERT_TRUE(Append(*b, main, bodies, r, true).ok());
  ASSERT_EQ(r.refused_size(), 3);
  EXPECT_EQ(r.refused(0).index(), 1u);
  EXPECT_EQ(r.refused(1).index(), 2u);
  EXPECT_EQ(r.refused(2).index(), 4u);
  EXPECT_EQ(r.assertions_size(), 2);
  EXPECT_EQ(Named(*b, main, "Tick"), update);
  EXPECT_EQ(Named(*b, main, "Paint"), draw);
  // Nothing valid: no revision, only the refusals.
  const std::uint64_t head = r.snapshot().revision();
  r.Clear();
  ASSERT_TRUE(Append(*b, main, {outside}, r, true).ok());
  EXPECT_EQ(r.refused_size(), 1);
  EXPECT_EQ(r.assertions_size(), 0);
  EXPECT_EQ(r.snapshot().revision(), head);
}

// A game imported again: refused, replaced in its folder, or beside it.
TEST_F(NdsFixes, ImportNameConflicts) {
  auto b = Make();
  pb::ImportDsdProjectResponse first, again;
  auto ids = Import(*b, pb::NAME_CONFLICT_UNSPECIFIED, &first);
  pb::ImportDsdProjectRequest req = Dsd();
  req.set_on_conflict(pb::NAME_CONFLICT_REFUSE);
  auto st = b->ImportDsdProject(ctx_, req, again);
  EXPECT_EQ(st.code, StatusCode::kAlreadyExists) << st.message;
  auto replaced = Import(*b, pb::NAME_CONFLICT_REPLACE, &again);
  EXPECT_EQ(again.folder().folder_id(), first.folder().folder_id());
  EXPECT_EQ(again.folder_taken_by(), first.folder().folder_id());
  EXPECT_EQ(again.replaced_program_ids_size(), first.modules_size());
  pb::ListProgramsRequest lr;
  lr.set_project_id("default");
  pb::ListProgramsResponse lp;
  ASSERT_TRUE(b->ListPrograms(ctx_, lr, lp).ok());
  std::set<std::string> live;
  for (const pb::ProgramInfo &p : lp.programs()) {
    EXPECT_EQ(p.folder_id(), first.folder().folder_id());
    live.insert(p.name());
  }
  EXPECT_EQ(lp.programs_size(), first.modules_size());
  EXPECT_TRUE(live.contains("main") && live.contains("ov000")) << lp.DebugString();
  EXPECT_NE(replaced.at("main"), ids.at("main"));
  // The links follow the new programs.
  const std::uint64_t ov_update = Named(*b, replaced.at("ov000"), "GameOverScene::Update");
  EXPECT_NE(Decompile(*b, replaced.at("ov000"), ov_update).find("SceneBase::Update("), std::string::npos);
  // Keep both: a folder beside it, saying whose name it was.
  Import(*b, pb::NAME_CONFLICT_KEEP_BOTH, &again);
  EXPECT_NE(again.folder().folder_id(), first.folder().folder_id());
  EXPECT_EQ(again.folder_taken_by(), first.folder().folder_id());

  // One program: refused, kept beside (said), replaced.
  pb::ImportProgramRequest in;
  in.set_project_id("default");
  in.set_name("ov");
  in.set_path((*fixture_ / "plain/ov000.bin").string());
  in.mutable_options()->set_format("raw");
  in.mutable_options()->set_language_id("ARM:LE:32:v5t");
  in.mutable_options()->set_has_image_base(true);
  in.mutable_options()->set_image_base(0x02100000);
  in.mutable_options()->set_memory_preset("nds-arm9");
  *in.mutable_provenance() = User();
  pb::ImportProgramResponse ir;
  ASSERT_TRUE(b->ImportProgram(ctx_, in, ir).ok());
  EXPECT_TRUE(ir.name_taken_by().empty());
  const std::string ov = ir.program().program_id();
  in.set_on_conflict(pb::NAME_CONFLICT_REFUSE);
  EXPECT_EQ(b->ImportProgram(ctx_, in, ir).code, StatusCode::kAlreadyExists);
  in.set_on_conflict(pb::NAME_CONFLICT_KEEP_BOTH);
  ASSERT_TRUE(b->ImportProgram(ctx_, in, ir).ok());
  EXPECT_EQ(ir.name_taken_by(), ov);
  EXPECT_EQ(ir.program().program_id(), "default/ov-2");
  in.set_on_conflict(pb::NAME_CONFLICT_REPLACE);
  ASSERT_TRUE(b->ImportProgram(ctx_, in, ir).ok());
  EXPECT_EQ(ir.replaced_program_id(), ov);
  EXPECT_EQ(ir.program().name(), "ov");
  // The preset on a raw import: the I/O is volatile there too.
  pb::GetMemoryMapRequest mr;
  mr.set_program_id(ir.program().program_id());
  pb::GetMemoryMapResponse map;
  ASSERT_TRUE(b->GetMemoryMap(ctx_, mr, map).ok());
  bool io = false;
  for (const pb::MemoryBlock &m : map.blocks()) io = io || (m.name() == "io" && m.is_volatile());
  EXPECT_TRUE(io);
  in.mutable_options()->set_memory_preset("gameboy");
  EXPECT_EQ(b->ImportProgram(ctx_, in, ir).code, StatusCode::kInvalidArgument);
}

// A closed project's store is compacted: stale and dropped memos go, the
// file shrinks, and the project reopens with its programs.
TEST_F(NdsFixes, CompactShrinksTheStore) {
  const fs::path dir = *fixture_ / "compact";
  fs::remove_all(dir);
  std::map<std::string, std::string> ids;
  std::string before_text;
  std::uint64_t ov_update = 0;
  {
    auto b = Make(dir.string());
    ids = Import(*b);
    for (const auto &[module, id] : ids)
      for (const auto &[a, n] : Functions(*b, id)) Decompile(*b, id, a);
    ov_update = Named(*b, ids.at("ov000"), "GameOverScene::Update");
    before_text = Decompile(*b, ids.at("ov000"), ov_update);
    pb::CompactProjectRequest cr;
    cr.set_project_id("default");
    pb::CompactProjectResponse resp;
    EXPECT_EQ(b->CompactProject(ctx_, cr, resp).code, StatusCode::kFailedPrecondition) << "open";
    pb::CloseProjectRequest close;
    close.set_project_id("default");
    pb::CloseProjectResponse closed;
    ASSERT_TRUE(b->CloseProject(ctx_, close, closed).ok());
    cr.set_dry_run(true);
    auto st = b->CompactProject(ctx_, cr, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    EXPECT_GT(resp.memo_records(), 0u);
    EXPECT_GT(resp.log_records(), 0u);
    EXPECT_EQ(resp.file_bytes_after(), resp.file_bytes_before());
    bool decompile = false;
    for (const pb::CompactRule &r : resp.rules()) decompile = decompile || (r.name() == "decompile.ghidra" && r.records());
    EXPECT_TRUE(decompile);
    cr.set_dry_run(false);
    cr.set_drop_caches(true);
    st = b->CompactProject(ctx_, cr, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    EXPECT_EQ(resp.dropped_records(), resp.memo_records());
    EXPECT_LT(resp.file_bytes_after(), resp.file_bytes_before());
    pb::OpenProjectRequest open;
    open.set_project_id("default");
    pb::OpenProjectResponse opened;
    ASSERT_TRUE(b->OpenProject(ctx_, open, opened).ok());
    EXPECT_EQ(Decompile(*b, ids.at("ov000"), ov_update), before_text);
  }
  // Reopened by a new daemon: the log and the bytes are whole.
  auto b = Make(dir.string());
  EXPECT_EQ(Decompile(*b, ids.at("ov000"), ov_update), before_text);
  // The CLI's function on a stopped daemon's directory.
  b.reset();
  std::ostringstream out;
  StoreCompaction o;
  o.cache_limit = 1;
  EXPECT_EQ(CompactProjectDir(dir.string(), "", o, out), 1);
  EXPECT_NE(out.str().find("file "), std::string::npos) << out.str();
}

}  // namespace
}  // namespace revkit::backend
