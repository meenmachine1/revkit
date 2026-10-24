// Builds the synthetic DS fixtures (tests/data/nds/make_fixture.py) once per
// test process: a .nds image, a ds-decomp project and the objects. nullopt
// when clang, ld.lld or python3 is missing or the build fails (the callers
// skip). docs/nds.md, "Test fixtures".
#pragma once

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <unistd.h>
#include <vector>

namespace revkit::nds::testing {

inline std::optional<std::filesystem::path> nds_fixture(const std::string &python, const std::string &clang,
                                                        const std::string &lld, const std::string &fixture_dir) {
  static std::optional<std::filesystem::path> built;
  static bool tried = false;
  if (tried) return built;
  tried = true;
  if (python.empty() || clang.empty() || lld.empty()) return std::nullopt;
  const std::filesystem::path dir =
      std::filesystem::temp_directory_path() / ("revkit-nds-" + std::to_string(::getpid()));
  std::filesystem::remove_all(dir);
  std::filesystem::create_directories(dir);
  static std::filesystem::path made;
  made = dir;
  std::atexit([] {
    std::error_code ec;
    std::filesystem::remove_all(made, ec);
  });
  const std::string cmd = "'" + python + "' -I '" + fixture_dir + "/make_fixture.py' --clang '" + clang +
                          "' --lld '" + lld + "' --out '" + dir.string() + "' >'" + (dir / "build.log").string() +
                          "' 2>&1";
  if (std::system(cmd.c_str()) != 0) return std::nullopt;
  built = dir;
  return built;
}

inline std::vector<std::uint8_t> read_bytes(const std::filesystem::path &p) {
  std::ifstream in(p, std::ios::binary);
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

inline std::string read_text(const std::filesystem::path &p) {
  std::ifstream in(p, std::ios::binary);
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

}  // namespace revkit::nds::testing
