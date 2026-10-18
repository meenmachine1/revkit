// Go programs through the API (docs/go.md), on binaries built at test time
// when Go is installed (REVKIT_TEST_GO, or $RK_GO; skipped otherwise): a
// stripped ELF's functions named from the pclntab as analysis:go, with
// their source lines as plate comments and Go's no-return functions; the
// golang compiler spec and the decompiler's register arguments; the user's
// names and the symbol table's winning; the symbol tree's package
// namespaces; GetBuildInfo's table summary; a stripped PE (the table found
// by its magic); and a C program untouched.
#include "revkit/backend/image_backend.h"

#include "builders.hh"

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;

std::string Env(const char *name, const char *fallback) {
  const char *v = std::getenv(name);
  return v && *v ? v : fallback;
}

bool RunQuiet(const std::string &cmd) { return std::system((cmd + " >/dev/null 2>&1").c_str()) == 0; }

std::string Text(const pb::DecompiledFunction &f) {
  std::string out;
  for (const auto &line : f.lines()) {
    for (const auto &t : line.tokens()) out += t.text();
    out += '\n';
  }
  return out;
}

// A module with a method, a closure, a dependency and a panic path.
struct GoFixture {
  std::filesystem::path dir;
  bool ok = false;
};

const GoFixture &Fixture() {
  static const GoFixture f = [] {
    GoFixture out;
    const std::string go = Env("RK_GO", REVKIT_TEST_GO);
    if (go.empty()) return out;
    out.dir = testing::scratch_dir("go-api");
    auto write = [&](const std::string &file, const std::string &text) {
      std::filesystem::create_directories((out.dir / file).parent_path());
      std::ofstream(out.dir / file) << text;
    };
    write("go.mod", "module example.com/hello\n\ngo 1.21\n\nrequire example.com/dep v0.1.0\n\nreplace example.com/dep => ./dep\n");
    write("dep/go.mod", "module example.com/dep\n\ngo 1.21\n");
    write("dep/dep.go", "package dep\n\n//go:noinline\nfunc Greeting(n int) string {\n\tif n > 2 {\n\t\treturn \"many\"\n\t}\n\treturn \"few\"\n}\n");
    write("main.go",
          "package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n\n\t\"example.com/dep\"\n)\n\n"
          "type T struct{ n []int }\n\n"
          "//go:noinline\nfunc (t *T) Method(i, j int) int { return t.n[i] + j }\n\n"
          "func main() {\n\tt := &T{n: []int{3, 1, 2}}\n\tfmt.Println(dep.Greeting(len(os.Args)), t.Method(len(os.Args), 7))\n}\n");
    const std::string base = "cd " + out.dir.string() + " && env GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-p=2 GOWORK=off CGO_ENABLED=0 ";
    out.ok = RunQuiet(base + go + " build -ldflags=\"-s -w\" -o hello-s .") && RunQuiet(base + go + " build -o hello .") &&
             RunQuiet(base + "GOOS=windows GOARCH=amd64 " + go + " build -ldflags=\"-s -w\" -o hello-s.exe .");
    return out;
  }();
  return f;
}

class GoApi : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (Env("RK_GO", REVKIT_TEST_GO).empty()) GTEST_SKIP() << "no Go toolchain (set RK_GO)";
    if (!Fixture().ok) GTEST_SKIP() << "go build failed";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
  }

  pb::ImportProgramResponse Import(const std::filesystem::path &path, const std::string &name) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(path.string());
    req.set_name(name);
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  std::map<std::string, pb::Function> Functions(const std::string &id) {
    std::map<std::string, pb::Function> out;
    pb::ListFunctionsRequest req;
    req.set_program_id(id);
    req.mutable_page()->set_page_size(5000);
    for (;;) {
      pb::ListFunctionsResponse resp;
      EXPECT_TRUE(backend_->ListFunctions(ctx_, req, resp).ok());
      for (const auto &f : resp.functions()) out[f.name()] = f;
      if (resp.page().next_page_token().empty()) break;
      req.mutable_page()->set_page_token(resp.page().next_page_token());
    }
    return out;
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

  std::vector<pb::ProgramComment> Plates(const std::string &id, const std::string &text) {
    pb::ListCommentsRequest req;
    req.set_program_id(id);
    req.add_kinds(pb::COMMENT_KIND_PLATE);
    req.set_text_contains(text);
    pb::ListCommentsResponse resp;
    EXPECT_TRUE(backend_->ListComments(ctx_, req, resp).ok());
    return {resp.comments().begin(), resp.comments().end()};
  }

  std::vector<pb::SymbolTreeNode> Tree(const std::string &id, std::vector<std::string> path) {
    pb::ListSymbolTreeRequest req;
    req.set_program_id(id);
    for (auto &p : path) req.add_path(p);
    pb::ListSymbolTreeResponse resp;
    EXPECT_TRUE(backend_->ListSymbolTree(ctx_, req, resp).ok());
    return {resp.nodes().begin(), resp.nodes().end()};
  }

  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
};

TEST_F(GoApi, StrippedElfNamedFromThePclntab) {
  const pb::ImportProgramResponse imp = Import(Fixture().dir / "hello-s", "hello-s");
  const std::string id = imp.program().program_id();
  bool summary = false;
  for (const auto &w : imp.warnings())
    summary |= w.starts_with("analysis:go: ") && w.find(" names") != std::string::npos && w.find("pclntab 1.20") != std::string::npos;
  EXPECT_TRUE(summary);
  auto fns = Functions(id);
  for (const char *f : {"main.main", "main.(*T).Method", "example.com/dep.Greeting", "fmt.Fprintln", "runtime.throw"})
    ASSERT_TRUE(fns.contains(f)) << f;
  const pb::Function &m = fns.at("main.main");
  EXPECT_EQ(m.name_origin().asserted().provenance().kind(), pb::PROVENANCE_KIND_ANALYSIS);
  EXPECT_EQ(m.name_origin().asserted().provenance().id(), "go");
  EXPECT_TRUE(fns.at("runtime.throw").no_return());
  std::size_t unnamed = 0;
  for (const auto &[name, f] : fns) unnamed += name.starts_with("FUN_");
  EXPECT_LT(unnamed * 50, fns.size()) << unnamed << " of " << fns.size();  // a few call targets inside duffzero and the like

  // Its file and line as a plate comment.
  auto plates = Plates(id, "main.go:15");
  ASSERT_EQ(plates.size(), 1u);
  EXPECT_EQ(plates[0].address().offset(), m.entry().offset());
  EXPECT_TRUE(plates[0].text().starts_with("Go source: ")) << plates[0].text();

  // The golang spec: the method's receiver and arguments are registers.
  pb::GetProgramSummaryRequest sreq;
  sreq.set_program_id(id);
  pb::GetProgramSummaryResponse sresp;
  ASSERT_TRUE(backend_->GetProgramSummary(ctx_, sreq, sresp).ok());
  EXPECT_EQ(sresp.summary().language().compiler_spec_id(), "golang");
  const std::string method = Decompile(id, fns.at("main.(*T).Method").entry().offset());
  EXPECT_NE(method.find("main.(*T).Method("), std::string::npos) << method;
  EXPECT_NE(method.find("param_3"), std::string::npos) << method;  // t, i, j in RAX, RBX, RCX
  EXPECT_EQ(method.find("decompilation failed"), std::string::npos) << method;
  const std::string c = Decompile(id, m.entry().offset());
  EXPECT_NE(c.find("example.com/dep.Greeting("), std::string::npos) << c;
  EXPECT_NE(c.find("main.(*T).Method("), std::string::npos) << c;

  // The symbol tree: packages as namespaces.
  bool dep = false;
  for (const auto &n : Tree(id, {"Namespaces"})) dep |= n.name() == "example.com/dep";
  EXPECT_TRUE(dep);
  bool greeting = false;
  for (const auto &n : Tree(id, {"Namespaces", "example.com/dep"}))
    greeting |= n.name() == "Greeting" && n.full_name() == "example.com/dep.Greeting";
  EXPECT_TRUE(greeting);

  // GetBuildInfo's summary of the table.
  pb::GetBuildInfoRequest breq;
  breq.set_program_id(id);
  pb::GetBuildInfoResponse bresp;
  ASSERT_TRUE(backend_->GetBuildInfo(ctx_, breq, bresp).ok());
  ASSERT_TRUE(bresp.has_go_pclntab());
  EXPECT_EQ(bresp.go_pclntab().layout(), "1.20");
  EXPECT_EQ(bresp.go_pclntab().found_by(), "section");
  EXPECT_TRUE(bresp.go_pclntab().has_moduledata());
  EXPECT_TRUE(bresp.go_pclntab().has_text_start());
  EXPECT_GE(bresp.go_pclntab().functions_read(), fns.size() * 9 / 10);
}

TEST_F(GoApi, UsersAndSymbolsOutrankTheAnalysis) {
  const std::string id = Import(Fixture().dir / "hello-s", "hello-s").program().program_id();
  const std::uint64_t entry = Functions(id).at("main.main").entry().offset();
  pb::AppendAssertionsRequest req;
  req.set_program_id(id);
  req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  req.mutable_provenance()->set_id("alice");
  auto *rn = req.add_assertions()->mutable_body()->mutable_rename();
  rn->mutable_target()->mutable_address()->set_offset(entry);
  rn->set_name("entry_point");
  pb::AppendAssertionsResponse resp;
  ASSERT_TRUE(backend_->AppendAssertions(ctx_, req, resp).ok());
  auto fns = Functions(id);
  ASSERT_TRUE(fns.contains("entry_point"));
  EXPECT_EQ(fns.at("entry_point").entry().offset(), entry);

  // With symbols the file's names stand: analysis:go names none of them
  // (the summary has no "names"), and the functions are the same.
  const pb::ImportProgramResponse full = Import(Fixture().dir / "hello", "hello");
  for (const auto &w : full.warnings())
    if (w.starts_with("analysis:go: ")) EXPECT_EQ(w.find(" names"), std::string::npos) << w;
  auto named = Functions(full.program().program_id());
  ASSERT_TRUE(named.contains("main.main"));
  EXPECT_NE(named.at("main.main").name_origin().asserted().provenance().id(), "go");
}

TEST_F(GoApi, StrippedPeFoundByItsMagic) {
  const std::string id = Import(Fixture().dir / "hello-s.exe", "hello-s.exe").program().program_id();
  auto fns = Functions(id);
  ASSERT_TRUE(fns.contains("main.main"));
  ASSERT_TRUE(fns.contains("example.com/dep.Greeting"));
  pb::GetBuildInfoRequest breq;
  breq.set_program_id(id);
  pb::GetBuildInfoResponse bresp;
  ASSERT_TRUE(backend_->GetBuildInfo(ctx_, breq, bresp).ok());
  ASSERT_TRUE(bresp.has_go_pclntab());
  EXPECT_EQ(bresp.go_pclntab().found_by(), "scan");
}

TEST_F(GoApi, CProgramUntouched) {
  auto dir = testing::scratch_dir("go-api-c");
  ASSERT_TRUE(testing::compile(REVKIT_TEST_CC, "int main(void) { return 0; }\n", "-O0", dir / "c"));
  const pb::ImportProgramResponse imp = Import(dir / "c", "c");
  for (const auto &w : imp.warnings()) EXPECT_FALSE(w.starts_with("analysis:go")) << w;
  pb::GetProgramSummaryRequest sreq;
  sreq.set_program_id(imp.program().program_id());
  pb::GetProgramSummaryResponse sresp;
  ASSERT_TRUE(backend_->GetProgramSummary(ctx_, sreq, sresp).ok());
  EXPECT_EQ(sresp.summary().language().compiler_spec_id(), "gcc");
  pb::GetBuildInfoRequest breq;
  breq.set_program_id(imp.program().program_id());
  pb::GetBuildInfoResponse bresp;
  ASSERT_TRUE(backend_->GetBuildInfo(ctx_, breq, bresp).ok());
  EXPECT_FALSE(bresp.has_go_pclntab());
}

}  // namespace
}  // namespace revkit::backend
