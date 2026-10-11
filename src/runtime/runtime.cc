#include "revkit/runtime/runtime.h"

#include "revkit/runtime/build_info.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <system_error>

#ifndef REVKIT_DEFAULT_TYPEINFO_DIR
#define REVKIT_DEFAULT_TYPEINFO_DIR ""
#endif

#ifndef REVKIT_DEFAULT_GHIDRA_ROOT
#define REVKIT_DEFAULT_GHIDRA_ROOT ""
#endif

namespace revkit::runtime {

namespace fs = std::filesystem;

std::string_view version() { return REVKIT_VERSION; }
std::string_view git_sha() { return REVKIT_GIT_SHA; }

std::string version_string(std::string_view tool) {
  std::string s(tool);
  s += ' ';
  s += version();
  s += " (git ";
  s += git_sha();
  s += ')';
  return s;
}

bool print_version_if_asked(int argc, char **argv, std::string_view tool) {
  for (int i = 1; i < argc; ++i) {
    if (std::string_view(argv[i]) == "--") break;  // the rest is someone else's (rk-dbg -- prog args)
    if (std::string_view(argv[i]) == "--version") {
      std::cout << version_string(tool) << "\n";
      return true;
    }
  }
  return false;
}

fs::path executable_dir() {
  std::error_code ec;
  const fs::path exe = fs::read_symlink("/proc/self/exe", ec);
  if (ec) return {};
  return exe.parent_path();
}

std::optional<fs::path> share_dir() {
  const fs::path dir = executable_dir();
  if (dir.empty()) return std::nullopt;
  std::error_code ec;
  fs::path share = fs::weakly_canonical(dir / ".." / "share" / "revkit", ec);
  if (ec || !fs::is_directory(share, ec)) return std::nullopt;
  return share;
}

std::optional<fs::path> typeinfo_dir() {
  std::error_code ec;
  if (const char *env = std::getenv("REVKIT_TYPEINFO_DIR"); env != nullptr && *env)
    return fs::is_directory(env, ec) ? std::optional<fs::path>(env) : std::nullopt;
  if (auto share = share_dir())
    if (fs::is_directory(*share / "typeinfo", ec)) return *share / "typeinfo";
  const fs::path build = REVKIT_DEFAULT_TYPEINFO_DIR;
  if (!build.empty() && fs::is_directory(build, ec)) return build;
  return std::nullopt;
}

namespace {

std::string trim(std::string s) {
  const auto ws = " \t\r\n";
  s.erase(0, s.find_first_not_of(ws));
  const auto end = s.find_last_not_of(ws);
  s.erase(end == std::string::npos ? 0 : end + 1);
  return s;
}

std::string home() {
  const char *h = std::getenv("HOME");
  return h != nullptr ? h : "";
}

fs::path expand_home(const std::string &p) {
  if (p == "~") return home();
  if (p.starts_with("~/")) return fs::path(home()) / p.substr(2);
  return p;
}

std::vector<fs::path> default_config_files();

// `ghidra = DIR` from a revkit.conf; nullopt when the file or key is absent.
std::optional<std::string> config_ghidra(const fs::path &file) {
  auto v = config_values(file, "ghidra");
  if (v.empty()) return std::nullopt;
  return v.front();
}

}  // namespace

std::vector<std::string> config_values(const fs::path &file, std::string_view key) {
  std::vector<std::string> out;
  std::ifstream in(file);
  if (!in) return out;
  std::string line;
  while (std::getline(in, line)) {
    if (auto hash = line.find('#'); hash != std::string::npos) line.erase(hash);
    const auto eq = line.find('=');
    if (eq == std::string::npos || trim(line.substr(0, eq)) != key) continue;
    std::string v = trim(line.substr(eq + 1));
    if (v.size() >= 2 && (v.front() == '"' || v.front() == '\'') && v.back() == v.front()) v = v.substr(1, v.size() - 2);
    out.push_back(std::move(v));
  }
  return out;
}

std::vector<fs::path> config_files() { return default_config_files(); }

namespace {

std::vector<fs::path> default_config_files() {
  std::vector<fs::path> out;
  if (const char *x = std::getenv("XDG_CONFIG_HOME"); x != nullptr && *x != 0)
    out.push_back(fs::path(x) / "revkit" / "revkit.conf");
  else if (!home().empty())
    out.push_back(fs::path(home()) / ".config" / "revkit" / "revkit.conf");
  out.emplace_back("/etc/revkit/revkit.conf");
  return out;
}

// Directories under parent whose name starts with prefix, newest version
// first (names sort descending: ghidra_12.1.4_PUBLIC before ghidra_11.4).
void add_matching(std::vector<fs::path> &out, const fs::path &parent, std::string_view prefix) {
  std::error_code ec;
  if (!fs::is_directory(parent, ec)) return;
  std::vector<fs::path> found;
  for (const auto &e : fs::directory_iterator(parent, ec)) {
    const std::string name = e.path().filename().string();
    if (name.starts_with(prefix) && e.is_directory(ec)) found.push_back(e.path());
  }
  std::sort(found.begin(), found.end(), [](const fs::path &a, const fs::path &b) { return a.filename() > b.filename(); });
  out.insert(out.end(), found.begin(), found.end());
}

std::vector<fs::path> default_common_paths() {
  std::vector<fs::path> out;
  const std::string h = home();
  if (!h.empty()) {
    add_matching(out, fs::path(h) / "ghidra", "ghidra_");
    add_matching(out, h, "ghidra");
  }
  add_matching(out, "/opt/ghidra", "ghidra_");
  add_matching(out, "/opt", "ghidra");
  out.emplace_back("/usr/share/ghidra");
  out.emplace_back("/usr/lib/ghidra");
  return out;
}

std::string ghidra_version(const fs::path &root) {
  std::ifstream in(root / "Ghidra" / "application.properties");
  std::string line;
  while (std::getline(in, line)) {
    if (line.starts_with("application.version=")) return trim(line.substr(20));
  }
  return "";
}

}  // namespace

std::string check_ghidra_root(const fs::path &root) {
  std::error_code ec;
  if (!fs::exists(root, ec)) return "does not exist";
  if (!fs::is_directory(root, ec)) return "is not a directory";
  const fs::path procs = root / "Ghidra" / "Processors";
  if (!fs::is_directory(procs, ec)) return "has no Ghidra/Processors (not a Ghidra install root)";
  bool ldefs = false, sla = false, slaspec = false;
  for (const auto &proc : fs::directory_iterator(procs, ec)) {
    const fs::path langs = proc.path() / "data" / "languages";
    if (!fs::is_directory(langs, ec)) continue;
    for (const auto &f : fs::recursive_directory_iterator(langs, ec)) {
      const auto ext = f.path().extension();
      ldefs |= ext == ".ldefs";
      sla |= ext == ".sla";
      slaspec |= ext == ".slaspec";
    }
    if (ldefs && sla) return "";
  }
  if (!ldefs) return "has no Ghidra/Processors/*/data/languages/*.ldefs";
  if (slaspec) return "has SLEIGH sources (.slaspec) but no compiled .sla files: a source checkout; use a Ghidra release";
  return "has no compiled .sla files";
}

GhidraSpecs locate_ghidra(std::string_view flag, const FindOptions &options) {
  std::vector<std::string> tried;
  auto accept = [](const fs::path &root, std::string source) {
    GhidraSpecs s;
    std::error_code ec;
    s.root = fs::weakly_canonical(root, ec);
    if (ec) s.root = root;
    s.source = std::move(source);
    s.version = ghidra_version(s.root);
    if (!s.version.empty()) {
      const int major = std::atoi(s.version.c_str());
      if (major != kGhidraMajor)
        s.warning = "Ghidra " + s.version + " at " + s.root.string() + " (" + s.source + "): revkit is built from Ghidra " +
                    std::to_string(kGhidraMajor) + ".x and may not read other versions' .sla files";
    }
    return s;
  };
  // An explicit choice that is wrong is an error, not a reason to look elsewhere.
  auto explicit_choice = [&](const fs::path &root, const std::string &source) {
    const std::string why = check_ghidra_root(root);
    if (why.empty()) return accept(root, source);
    throw GhidraNotFound("Ghidra processor specs: " + root.string() + " (from " + source + ") " + why +
                         ".\nPoint it at a Ghidra " + std::to_string(kGhidraMajor) +
                         ".x install (the directory holding Ghidra/Processors), or at a revkit bundle's "
                         "share/revkit/ghidra.");
  };

  if (!flag.empty()) return explicit_choice(expand_home(std::string(flag)), "--ghidra");

  std::optional<std::string> env = options.env;
  if (!options.env) {
    if (const char *e = std::getenv("GHIDRA_INSTALL_DIR")) env = e;
  }
  if (env && !env->empty()) return explicit_choice(expand_home(*env), "$GHIDRA_INSTALL_DIR");
  tried.push_back("--ghidra: not given");
  tried.push_back("$GHIDRA_INSTALL_DIR: not set");

  for (const fs::path &file : options.config_files ? *options.config_files : default_config_files()) {
    if (auto v = config_ghidra(file); v && !v->empty()) return explicit_choice(expand_home(*v), file.string());
    tried.push_back(file.string() + ": no `ghidra = DIR` line");
  }

  auto candidate = [&](const fs::path &root, const std::string &source) -> std::optional<GhidraSpecs> {
    const std::string why = check_ghidra_root(root);
    if (why.empty()) return accept(root, source);
    tried.push_back(source + " " + root.string() + ": " + why);
    return std::nullopt;
  };

  std::optional<fs::path> bundled = options.bundled;
  if (!bundled) {
    if (auto share = share_dir()) bundled = *share / "ghidra";
  }
  if (bundled) {
    if (auto s = candidate(*bundled, "bundled")) return *s;
  } else {
    tried.push_back("bundled <executable>/../share/revkit/ghidra: not present");
  }

  const std::string build_default = options.build_default ? *options.build_default : REVKIT_DEFAULT_GHIDRA_ROOT;
  if (!build_default.empty()) {
    if (auto s = candidate(build_default, "build default")) return *s;
  }

  const std::vector<fs::path> common = options.common ? *options.common : default_common_paths();
  std::size_t common_missing = 0;
  for (const fs::path &root : common) {
    std::error_code ec;
    if (!fs::exists(root, ec)) {
      ++common_missing;
      continue;
    }
    if (auto s = candidate(root, "common path")) return *s;
  }
  if (common_missing > 0 || common.empty())
    tried.push_back("common paths (~/ghidra*, ~/ghidra/ghidra_*, /opt/ghidra*, /usr/share/ghidra, /usr/lib/ghidra): none found");

  std::ostringstream msg;
  msg << "cannot find Ghidra's processor specs (.sla, .ldefs, .pspec, .cspec).\n"
      << "revkit reads them at run time from a Ghidra " << kGhidraMajor
      << ".x install or from a revkit bundle's share/revkit/ghidra. Tried:\n";
  for (const std::string &t : tried) msg << "  - " << t << "\n";
  msg << "Fix one of:\n"
      << "  - pass --ghidra /path/to/ghidra_" << kGhidraMajor << ".x_PUBLIC\n"
      << "  - export GHIDRA_INSTALL_DIR=/path/to/ghidra_" << kGhidraMajor << ".x_PUBLIC\n"
      << "  - put `ghidra = /path/to/ghidra_" << kGhidraMajor << ".x_PUBLIC` in ~/.config/revkit/revkit.conf\n"
      << "  - use the revkit bundle, which carries the specs (docs/getting-started.md)\n"
      << "Ghidra releases: https://github.com/NationalSecurityAgency/ghidra/releases";
  throw GhidraNotFound(msg.str());
}

std::optional<fs::path> find_ghidra(std::string_view flag, std::string_view tool) {
  try {
    GhidraSpecs s = locate_ghidra(flag);
    if (!s.warning.empty()) std::cerr << tool << ": warning: " << s.warning << "\n";
    return s.root;
  } catch (const GhidraNotFound &e) {
    std::cerr << tool << ": " << e.what() << "\n";
    return std::nullopt;
  }
}

}  // namespace revkit::runtime
