// ScriptService's parts that need no Python (src/api/script_service.h):
// metadata parsing as revkit/script/meta.py does it, who the daemon runs
// scripts for (off by default beyond loopback), the trust pins, and the
// auth store's run tokens. The service end to end is in
// sdk/python/tests/test_script_service.py.
#include "../script_service.h"

#include "revkit/auth/store.h"

#include <gtest/gtest.h>
#include <unistd.h>
#include <cstdlib>

#include <filesystem>
#include <fstream>

namespace revkit::api {
namespace {

namespace fs = std::filesystem;

TEST(ScriptMetadata, ReadsTheHeaderOnly) {
  const char *src =
      "#!/usr/bin/env python3\n"
      "# @category Analysis/Naming\n"
      "# @description Names things\n"
      "# @description over two lines\n"
      "# @menupath Analysis.Name things\n"
      "# @keybinding ctrl shift N\n"
      "# @context function\n"
      "# @arg limit:int=8 Largest size\n"
      "# @arg mode[fast|slow]=fast How\n"
      "# @arg out:file Where\n"
      "# @arg bad:widget=1 Unknown type\n"
      "\n"
      "import os\n"
      "# @category Not/This\n";
  ScriptMeta m = ParseScriptMetadata(src, "name_things");
  EXPECT_EQ(m.name, "name_things");
  EXPECT_EQ(m.category, "Analysis/Naming");
  EXPECT_EQ(m.description, "Names things over two lines");
  EXPECT_EQ(m.menupath, "Analysis.Name things");
  EXPECT_EQ(m.keybinding, "ctrl shift N");
  EXPECT_EQ(m.context, "function");
  ASSERT_EQ(m.args.size(), 4u);
  EXPECT_EQ(m.args[0].type, "int");
  EXPECT_EQ(m.args[0].default_value.value_or(""), "8");
  EXPECT_EQ(m.args[0].description, "Largest size");
  EXPECT_EQ(m.args[1].type, "choice");
  EXPECT_EQ(m.args[1].choices, (std::vector<std::string>{"fast", "slow"}));
  EXPECT_FALSE(m.args[2].default_value.has_value());
  EXPECT_EQ(m.args[3].type, "str");
  ASSERT_EQ(m.errors.size(), 1u);
  EXPECT_NE(m.errors[0].find("widget"), std::string::npos);

  ScriptMeta named = ParseScriptMetadata("# @name fixer\n# @context nowhere\nx = 1\n", "file");
  EXPECT_EQ(named.name, "fixer");
  EXPECT_EQ(named.context, "program");
  EXPECT_EQ(named.errors.size(), 1u);
  // Ghidra's conventions: a licence block, "@category: X", the untagged
  // comment lines as the description.
  ScriptMeta ghidra = ParseScriptMetadata(
      "## ###\n# IP: GHIDRA\n#\n# Licensed under the Apache License\n##\n"
      "#Given a function, find all strings\n# used by its callees.\n# @category: Functions\n#\n"
      "# @runtime Jython\nimport ghidra\n",
      "RecursiveStringFinder");
  EXPECT_EQ(ghidra.category, "Functions");
  EXPECT_EQ(ghidra.description, "Given a function, find all strings used by its callees.");
  // A huge comment line is skipped, not fed to the regex.
  EXPECT_EQ(ParseScriptMetadata("# " + std::string(1 << 20, 'x') + "\n# @category A\n", "s").category, "A");
}

TEST(ScriptHost, OffBeyondLoopbackByDefault) {
  std::string why;
  EXPECT_EQ(ScriptHostRole("", true, why), auth::Role::kEditor);
  EXPECT_EQ(ScriptHostRole("", false, why), std::nullopt);
  EXPECT_NE(why.find("--scripts-host-role"), std::string::npos);
  EXPECT_EQ(ScriptHostRole("editor", false, why), auth::Role::kEditor);
  EXPECT_EQ(ScriptHostRole("admin", false, why), auth::Role::kAdmin);
  EXPECT_EQ(ScriptHostRole("off", true, why), std::nullopt);
  // "viewer" opens scripts and consoles to viewers too (their run tokens
  // can't edit); only when asked for, never by default.
  EXPECT_EQ(ScriptHostRole("viewer", false, why), auth::Role::kViewer);
  EXPECT_NE(why.find("can't edit"), std::string::npos);
  EXPECT_EQ(ScriptHostRole("bogus", true, why), std::nullopt);
  EXPECT_NE(why.find("viewer, editor or admin"), std::string::npos);
}

TEST(ScriptHost, NoPythonSaysHowToSetOneUp) {
  std::string problem;
  EXPECT_FALSE(FindScriptPython("/nonexistent/python", "", problem));
  EXPECT_NE(problem.find("/nonexistent/python"), std::string::npos);
  EXPECT_NE(problem.find("rk-script setup"), std::string::npos);
}

// An SDK older than the daemon (no SCRIPT_API stamp, no console, or a lower
// stamp) is passed over and named, with how to update it; a current one is
// taken. A real python3 imports a stand-in revkit package from PYTHONPATH.
TEST(ScriptHost, AnOlderSdkSaysToUpdateIt) {
  if (std::system("python3 -c 'import sys' >/dev/null 2>&1") != 0) GTEST_SKIP() << "no python3";
  const fs::path dir = fs::temp_directory_path() / ("rk-stale-sdk-" + std::to_string(::getpid()));
  fs::remove_all(dir);
  fs::create_directories(dir / "revkit" / "script");
  std::ofstream(dir / "revkit" / "__init__.py") << "";
  std::ofstream(dir / "revkit" / "script" / "worker.py") << "";
  // As the user's ~/.local/share/revkit/pyenv had it: 0.1.0 without the console.
  std::ofstream(dir / "revkit" / "script" / "__init__.py") << "";
  std::string problem;
  EXPECT_FALSE(FindScriptPython("python3", dir.string(), problem));
  EXPECT_NE(problem.find("the revkit SDK in python3 is older than this daemon"), std::string::npos) << problem;
  EXPECT_NE(problem.find("Set up Python (or run `rk-script setup`) to update it"), std::string::npos) << problem;
  // The console, but a lower stamp.
  std::ofstream(dir / "revkit" / "script" / "console.py") << "";
  std::ofstream(dir / "revkit" / "script" / "__init__.py") << "SCRIPT_API = 0\n";
  problem.clear();
  EXPECT_FALSE(FindScriptPython("python3", dir.string(), problem));
  EXPECT_NE(problem.find("older than this daemon"), std::string::npos) << problem;
  // Current.
  std::ofstream(dir / "revkit" / "script" / "__init__.py") << "SCRIPT_API = 999\n";
  problem.clear();
  auto py = FindScriptPython("python3", dir.string(), problem);
  ASSERT_TRUE(py) << problem;
  EXPECT_EQ(py->python, "python3");
  EXPECT_EQ(py->pythonpath.rfind(dir.string(), 0), 0u) << py->pythonpath;
  fs::remove_all(dir);
}

// What "Set up Python" installs: the newest shipped wheel of the first
// directory that has one, else an SDK source tree.
TEST(ScriptHost, SetupInstallsTheShippedWheelElseTheSourceTree) {
  const fs::path dir = fs::temp_directory_path() / ("rk-sdk-" + std::to_string(::getpid()));
  fs::remove_all(dir);
  fs::create_directories(dir / "python");
  fs::create_directories(dir / "sdk");
  fs::create_directories(dir / "src" / "revkit");
  std::ofstream(dir / "src" / "pyproject.toml") << "[project]\n";
  const std::vector<std::string> sources = {(dir / "python").string(), (dir / "sdk").string(), (dir / "src").string()};
  EXPECT_EQ(FindScriptSdk(sources), (dir / "src").string());
  std::ofstream(dir / "sdk" / "revkit-0.1.0-py3-none-any.whl") << "old";
  EXPECT_EQ(FindScriptSdk(sources), (dir / "sdk" / "revkit-0.1.0-py3-none-any.whl").string());
  std::ofstream(dir / "python" / "revkit-0.1.0.dev20261007-py3-none-any.whl") << "a";
  std::ofstream(dir / "python" / "revkit-0.1.0.dev20261008-py3-none-any.whl") << "b";
  std::ofstream(dir / "python" / "other-1.0-py3-none-any.whl") << "c";
  EXPECT_EQ(FindScriptSdk(sources), (dir / "python" / "revkit-0.1.0.dev20261008-py3-none-any.whl").string());
  EXPECT_EQ(FindScriptSdk({(dir / "nowhere").string()}), "");
  fs::remove_all(dir);
}

TEST(ScriptTrustPins, PerCallerAndScript) {
  const fs::path dir = fs::temp_directory_path() / ("rk-trust-" + std::to_string(::getpid()));
  fs::remove_all(dir);
  ScriptTrust t(dir / "trusted-scripts");
  EXPECT_EQ(t.Pinned("user:alice", "user/a.py"), "");
  t.Pin("user:alice", "user/a.py", "aaa");
  t.Pin("user:bob", "user/a.py", "bbb");
  t.Pin("user:alice", "user/a.py", "ccc");  // replaces alice's
  ScriptTrust again(dir / "trusted-scripts");
  EXPECT_EQ(again.Pinned("user:alice", "user/a.py"), "ccc");
  EXPECT_EQ(again.Pinned("user:bob", "user/a.py"), "bbb");
  EXPECT_EQ(again.Pinned("user:alice", "user/b.py"), "");
  EXPECT_EQ(fs::status(dir / "trusted-scripts").permissions() & fs::perms::others_read, fs::perms::none);
  fs::remove_all(dir);
}

TEST(RunTokens, ActAsTheCallerUntilRevoked) {
  const fs::path dir = fs::temp_directory_path() / ("rk-runtok-" + std::to_string(::getpid()));
  fs::remove_all(dir);
  fs::create_directories(dir);
  auth::StoreOptions so;
  so.path = (dir / "auth.db").string();
  so.scrypt = {10, 8, 1};
  auth::Store store(so);
  store.add_user("alice", auth::Role::kEditor, "alice-password-1", {"fw"});
  auto session = store.login("alice", "alice-password-1");
  ASSERT_TRUE(session);
  std::string id;
  const std::string secret = store.mint_run_token(session->principal, 3600, id);
  ASSERT_TRUE(secret.starts_with("rkr_"));
  auto p = store.authenticate(secret);
  ASSERT_TRUE(p);
  EXPECT_EQ(p->display(), "user:alice");
  EXPECT_EQ(p->role, auth::Role::kEditor);
  EXPECT_EQ(p->projects, std::vector<std::string>{"fw"});
  EXPECT_EQ(p->token_id, "run:" + id);
  // Never in the file.
  std::ifstream in(so.path);
  std::string text((std::istreambuf_iterator<char>(in)), {});
  EXPECT_EQ(text.find(id), std::string::npos);
  // A lowered role applies at once; a deleted account ends it.
  store.update_user("alice", auth::Role::kViewer, std::nullopt, std::nullopt);
  EXPECT_EQ(store.authenticate(secret)->role, auth::Role::kViewer);
  EXPECT_FALSE(store.authenticate(secret.substr(0, secret.size() - 1) + "x"));
  store.revoke_run_token(id);
  EXPECT_FALSE(store.authenticate(secret));
  EXPECT_EQ(store.run_token_count(), 0u);

  // An agent's: ends with the agent's token.
  auto agent = store.create_token("ci-bot", auth::Role::kEditor);
  auto ap = store.authenticate(agent.secret);
  ASSERT_TRUE(ap);
  const std::string s2 = store.mint_run_token(*ap, 0, id);
  EXPECT_EQ(store.authenticate(s2)->display(), "agent:ci-bot");
  store.revoke_token("ci-bot");
  EXPECT_FALSE(store.authenticate(s2));
  auth::Principal anon;
  EXPECT_THROW(store.mint_run_token(anon, 0, id), auth::AuthError);
  fs::remove_all(dir);
}

}  // namespace
}  // namespace revkit::api
