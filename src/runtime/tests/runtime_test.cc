#include "revkit/runtime/runtime.h"

#include <gtest/gtest.h>

#include <fstream>
#include <random>

namespace fs = std::filesystem;
using revkit::runtime::FindOptions;
using revkit::runtime::GhidraNotFound;
using revkit::runtime::locate_ghidra;

namespace {

class TempDir {
 public:
  TempDir() {
    std::random_device rd;
    path_ = fs::temp_directory_path() / ("rk-runtime-test-" + std::to_string(rd()));
    fs::create_directories(path_);
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
  }
  const fs::path &path() const { return path_; }

 private:
  fs::path path_;
};

void touch(const fs::path &p, const std::string &content = "") {
  fs::create_directories(p.parent_path());
  std::ofstream(p) << content;
}

// A minimal Ghidra layout: one processor with an .ldefs and a .sla.
fs::path fake_ghidra(const fs::path &root, const std::string &version = "12.1.4", bool sla = true) {
  touch(root / "Ghidra/Processors/x86/data/languages/x86.ldefs");
  if (sla) touch(root / "Ghidra/Processors/x86/data/languages/x86-64.sla");
  else touch(root / "Ghidra/Processors/x86/data/languages/x86-64.slaspec");
  touch(root / "Ghidra/application.properties", "application.name=Ghidra\napplication.version=" + version + "\n");
  return root;
}

// Nothing from the real environment.
FindOptions isolated() {
  FindOptions o;
  o.env = "";
  o.config_files = std::vector<fs::path>{};
  o.bundled = fs::path("/nonexistent/revkit-bundle");
  o.build_default = "";
  o.common = std::vector<fs::path>{};
  return o;
}

}  // namespace

TEST(Runtime, VersionString) {
  EXPECT_FALSE(revkit::runtime::version().empty());
  const std::string s = revkit::runtime::version_string("rk-test");
  EXPECT_EQ(s.rfind("rk-test " + std::string(revkit::runtime::version()) + " (git ", 0), 0u) << s;
}

TEST(Runtime, PrintVersionIfAsked) {
  char a0[] = "rk-test", a1[] = "--ghidra", a2[] = "x", a3[] = "--version";
  char *with[] = {a0, a1, a2, a3};
  char *without[] = {a0, a1, a2};
  char a4[] = "--";
  char *after_dashes[] = {a0, a4, a3};
  EXPECT_FALSE(revkit::runtime::print_version_if_asked(3, after_dashes, "rk-test"));
  testing::internal::CaptureStdout();
  EXPECT_TRUE(revkit::runtime::print_version_if_asked(4, with, "rk-test"));
  EXPECT_NE(testing::internal::GetCapturedStdout().find("rk-test "), std::string::npos);
  EXPECT_FALSE(revkit::runtime::print_version_if_asked(3, without, "rk-test"));
}

TEST(Runtime, CheckGhidraRoot) {
  TempDir t;
  EXPECT_NE(revkit::runtime::check_ghidra_root(t.path() / "missing"), "");
  EXPECT_NE(revkit::runtime::check_ghidra_root(t.path()), "");
  EXPECT_EQ(revkit::runtime::check_ghidra_root(fake_ghidra(t.path() / "g")), "");
  const std::string why = revkit::runtime::check_ghidra_root(fake_ghidra(t.path() / "src", "12.1.4", false));
  EXPECT_NE(why.find("source checkout"), std::string::npos) << why;
}

TEST(Runtime, FlagWins) {
  TempDir t;
  FindOptions o = isolated();
  o.env = fake_ghidra(t.path() / "env").string();
  auto s = locate_ghidra(fake_ghidra(t.path() / "flag").string(), o);
  EXPECT_EQ(s.root.filename(), "flag");
  EXPECT_EQ(s.source, "--ghidra");
  EXPECT_EQ(s.version, "12.1.4");
  EXPECT_EQ(s.warning, "");
}

TEST(Runtime, EnvThenConfigThenBundled) {
  TempDir t;
  FindOptions o = isolated();
  const fs::path conf = t.path() / "revkit.conf";
  touch(conf, "# revkit\nother = 1\nghidra = \"" + fake_ghidra(t.path() / "conf").string() + "\"  # comment\n");
  o.config_files = std::vector<fs::path>{t.path() / "absent.conf", conf};
  o.bundled = fake_ghidra(t.path() / "bundled");
  o.env = fake_ghidra(t.path() / "env").string();
  EXPECT_EQ(locate_ghidra("", o).source, "$GHIDRA_INSTALL_DIR");
  o.env = "";
  auto s = locate_ghidra("", o);
  EXPECT_EQ(s.root.filename(), "conf");
  EXPECT_EQ(s.source, conf.string());
  o.config_files = std::vector<fs::path>{};
  EXPECT_EQ(locate_ghidra("", o).source, "bundled");
}

TEST(Runtime, BuildDefaultThenCommon) {
  TempDir t;
  FindOptions o = isolated();
  o.common = std::vector<fs::path>{t.path() / "nope", fake_ghidra(t.path() / "common")};
  EXPECT_EQ(locate_ghidra("", o).source, "common path");
  o.build_default = fake_ghidra(t.path() / "build").string();
  EXPECT_EQ(locate_ghidra("", o).source, "build default");
}

TEST(Runtime, ExplicitBadChoiceIsAnError) {
  TempDir t;
  FindOptions o = isolated();
  o.bundled = fake_ghidra(t.path() / "bundled");
  try {
    locate_ghidra((t.path() / "typo").string(), o);
    FAIL() << "expected GhidraNotFound";
  } catch (const GhidraNotFound &e) {
    EXPECT_NE(std::string(e.what()).find("--ghidra"), std::string::npos) << e.what();
  }
  o.env = (t.path() / "typo").string();
  EXPECT_THROW(locate_ghidra("", o), GhidraNotFound);
}

TEST(Runtime, NothingFoundSaysWhatWasTried) {
  try {
    locate_ghidra("", isolated());
    FAIL() << "expected GhidraNotFound";
  } catch (const GhidraNotFound &e) {
    const std::string m = e.what();
    for (const char *s : {"GHIDRA_INSTALL_DIR", "--ghidra", "revkit.conf", "bundled", "Tried"})
      EXPECT_NE(m.find(s), std::string::npos) << s << " missing from:\n" << m;
  }
}

TEST(Runtime, OtherMajorVersionWarns) {
  TempDir t;
  auto s = locate_ghidra(fake_ghidra(t.path() / "old", "11.4.2").string(), isolated());
  EXPECT_NE(s.warning.find("11.4.2"), std::string::npos) << s.warning;
}
