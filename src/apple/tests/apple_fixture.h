// Builds tests/data/apple's fixtures once per process: the plists alone
// (python3 only), or the bundles too (build.sh: clang and ld64.lld for the
// Mach-O files, then make_bundle.py). Removed when the process exits.
#pragma once

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <unistd.h>
#include <vector>

namespace revkit::apple_testing {

inline std::filesystem::path scratch(const char *what) {
  const std::filesystem::path dir =
      std::filesystem::temp_directory_path() / ("revkit-apple-" + std::string(what) + "-" + std::to_string(::getpid()));
  std::filesystem::create_directories(dir);
  static std::vector<std::filesystem::path> made;
  if (made.empty())
    std::atexit([] {
      std::error_code ec;
      for (const auto &d : made) std::filesystem::remove_all(d, ec);
    });
  made.push_back(dir);
  return dir;
}

// The plists (make_bundle.py --plists-only); nullopt without python3.
inline const std::optional<std::filesystem::path> &plists(const std::string &fixture_dir) {
  static std::optional<std::filesystem::path> built;
  static bool tried = false;
  if (tried) return built;
  tried = true;
  const auto dir = scratch("plists");
  const std::string cmd = "python3 -I '" + fixture_dir + "/make_bundle.py' '" + dir.string() + "' --plists-only >'" +
                          (dir / "build.log").string() + "' 2>&1";
  if (std::system(cmd.c_str()) == 0) built = dir / "plists";
  return built;
}

// The bundles (build.sh); nullopt when clang or ld64.lld is missing.
inline const std::optional<std::filesystem::path> &bundles(const std::string &clang, const std::string &ld,
                                                            const std::string &fixture_dir) {
  static std::optional<std::filesystem::path> built;
  static bool tried = false;
  if (tried) return built;
  tried = true;
  if (clang.empty() || ld.empty()) return built;
  const auto dir = scratch("bundles");
  const std::string cmd = "sh '" + fixture_dir + "/build.sh' '" + clang + "' '" + ld + "' '" + dir.string() + "' >'" +
                          (dir / "build.log").string() + "' 2>&1";
  if (std::system(cmd.c_str()) == 0) built = dir;
  return built;
}

inline std::vector<std::byte> read_file(const std::filesystem::path &p) {
  std::ifstream in(p, std::ios::binary);
  std::vector<char> c((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  std::vector<std::byte> out(c.size());
  for (std::size_t i = 0; i < c.size(); ++i) out[i] = static_cast<std::byte>(c[i]);
  return out;
}

}  // namespace revkit::apple_testing
