// Builds tests/data/msvc/classes.cc for an MSVC target once per process
// (tests/data/msvc/build.sh) and reads its linker map.
#pragma once

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace revkit::msvc::testing {

struct Fixture {
  std::filesystem::path exe, stripped, pdb, map;
  std::map<std::string, std::uint64_t> symbols;  // the map's symbols by name
  std::uint64_t at(const std::string &name) const {
    auto it = symbols.find(name);
    return it == symbols.end() ? 0 : it->second;
  }
};

// nullopt when clang or lld-link is missing or the build fails.
inline std::optional<Fixture> build_fixture(const std::string &clang, const std::string &lld_link,
                                            const std::string &fixture_dir, const std::string &arch) {
  if (clang.empty() || lld_link.empty()) return std::nullopt;
  const std::filesystem::path dir = std::filesystem::temp_directory_path() /
                                    ("revkit-msvc-" + std::to_string(::getpid()) + "-" + arch);
  std::filesystem::create_directories(dir);
  // Gone when the test process exits.
  static std::vector<std::filesystem::path> made;
  if (made.empty())
    std::atexit([] {
      std::error_code ec;
      for (const auto &d : made) std::filesystem::remove_all(d, ec);
    });
  made.push_back(dir);
  const std::string cmd = "sh '" + fixture_dir + "/build.sh' '" + clang + "' '" + lld_link + "' '" + dir.string() +
                          "' " + arch + " >'" + (dir / "build.log").string() + "' 2>&1";
  if (std::system(cmd.c_str()) != 0) return std::nullopt;
  Fixture f;
  f.exe = dir / ("classes-" + arch + ".exe");
  f.stripped = dir / ("classes-" + arch + "-stripped.exe");
  f.pdb = dir / ("classes-" + arch + ".pdb");
  f.map = dir / ("classes-" + arch + ".map");
  // " 0002:00000128       ??_7Rect@geo@@6BShape@1@@  0000000140002128     obj"
  std::ifstream in(f.map);
  for (std::string line; std::getline(in, line);) {
    std::istringstream s(line);
    std::string sec, name, addr;
    if (!(s >> sec >> name >> addr) || sec.find(':') == std::string::npos || addr.size() < 8) continue;
    char *end = nullptr;
    const std::uint64_t a = std::strtoull(addr.c_str(), &end, 16);
    if (end && *end == 0) f.symbols.emplace(name, a);
  }
  return f;
}

}  // namespace revkit::msvc::testing
