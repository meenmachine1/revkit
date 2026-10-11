#pragma once

#include "revkit/emu/emulator.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

namespace revkit::emu::testing {

inline bool ghidra_ready() {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) return false;
  lift::initialize(REVKIT_GHIDRA_ROOT);
  return true;
}

// A raw image of `code` at `base` (rwx), plus any regions.
inline std::shared_ptr<const loader::Image> raw_image(const std::vector<std::uint8_t> &code, std::uint64_t base,
                                                      const std::string &language,
                                                      std::vector<loader::RawRegion> regions = {}) {
  auto bytes = std::make_shared<loader::Bytes>(code.size());
  for (std::size_t i = 0; i < code.size(); ++i) (*bytes)[i] = static_cast<std::byte>(code[i]);
  loader::RawOptions o;
  o.language = language;
  o.base = base;
  o.regions = std::move(regions);
  return std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
}

// Runs a command, returning its stdout and exit status.
inline std::string run_command(const std::string &cmd, int &status) {
  std::string out;
  FILE *p = popen(cmd.c_str(), "r");
  if (p == nullptr) {
    status = -1;
    return out;
  }
  char buf[4096];
  std::size_t n;
  while ((n = std::fread(buf, 1, sizeof buf, p)) > 0) out.append(buf, n);
  const int rc = pclose(p);
  status = WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
  return out;
}

// Builds a fixture set (`<source>/build.sh <clang> <ld.lld> <llvm-objcopy>
// <out>`) into a directory of this process's own under `out`, removed when
// the process exits, and returns it; empty when a tool is missing or the
// build fails. ctest runs every test in a process of its own, several at
// once: a directory they shared would have one of them linking or reading
// files another is rewriting (a failed build, so a skipped test, or a
// truncated image).
inline std::filesystem::path build_fixtures(const std::string &source, const std::string &out, const std::string &clang,
                                            const std::string &lld, const std::string &objcopy) {
  namespace fs = std::filesystem;
  if (clang.empty() || lld.empty() || objcopy.empty()) return {};
  struct Dirs {
    std::vector<fs::path> made;
    ~Dirs() {
      std::error_code ec;
      for (const fs::path &d : made) fs::remove_all(d, ec);
    }
  };
  static Dirs dirs;
  const fs::path dir = out + "." + std::to_string(::getpid());
  dirs.made.push_back(dir);
  const std::string cmd =
      "sh " + source + "/build.sh " + clang + " " + lld + " " + objcopy + " " + dir.string() + " >/dev/null 2>&1";
  if (std::system(cmd.c_str()) != 0) return {};
  return dir;
}

}  // namespace revkit::emu::testing
