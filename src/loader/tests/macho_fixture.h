// Builds tests/data/macho's fixtures once per process (build.sh: clang,
// ld64.lld, llvm-lipo) and reads what llvm-nm and llvm-objdump say about
// them, the independent account the tests check the loader against.
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

namespace revkit::loader::macho_testing {

// One fixup llvm-objdump lists.
struct Fixup {
  std::string kind;  // "rebase", "bind", "lazy", "weak"
  std::string section;
  std::uint64_t address = 0;
  std::string symbol;  // binds
  std::string dylib;   // binds: the library's short name ("libSystem")
  std::uint64_t target = 0;  // chained rebases
};

struct Fixtures {
  std::filesystem::path dir;
  std::filesystem::path path(const std::string &name) const { return dir / name; }

  // llvm-nm's defined symbols of a linked fixture: name -> address.
  std::map<std::string, std::uint64_t> symbols(const std::string &name) const {
    std::map<std::string, std::uint64_t> out;
    std::ifstream in(dir / (name + ".nm"));
    for (std::string line; std::getline(in, line);) {
      // "0000000100000598 t -[Point sum]": the name is the rest of the line.
      std::istringstream s(line);
      std::string addr, type, sym;
      if (!(s >> addr >> type) || addr == "U") continue;
      std::getline(s >> std::ws, sym);
      if (!sym.empty()) out.emplace(sym, std::strtoull(addr.c_str(), nullptr, 16));
    }
    return out;
  }
  // llvm-nm's undefined symbols.
  std::vector<std::string> undefined(const std::string &name) const {
    std::vector<std::string> out;
    std::ifstream in(dir / (name + ".nm"));
    for (std::string line; std::getline(in, line);) {
      std::istringstream s(line);
      std::string type, sym;
      if ((s >> type >> sym) && type == "U") out.push_back(sym);
    }
    return out;
  }

  std::vector<Fixup> fixups(const std::string &name) const {
    std::vector<Fixup> out;
    std::ifstream in(dir / (name + ".fixups"));
    std::string table;
    for (std::string line; std::getline(in, line);) {
      if (line.starts_with("dyld information:")) table = "chained";
      else if (line.starts_with("Rebase table:")) table = "rebase";
      else if (line.starts_with("Bind table:")) table = "bind";
      else if (line.starts_with("Lazy bind table:")) table = "lazy";
      else if (line.starts_with("Weak bind table:")) table = "weak";
      std::istringstream s(line);
      std::vector<std::string> w;
      for (std::string x; s >> x;) w.push_back(x);
      if (w.size() < 3 || !w[2].starts_with("0x")) continue;
      Fixup f;
      f.section = w[1];
      f.address = std::strtoull(w[2].c_str(), nullptr, 16);
      if (table == "chained" && w.size() >= 6) {
        f.kind = w[4];
        if (f.kind == "rebase") f.target = std::strtoull(w[5].c_str(), nullptr, 16);
        else if (w.size() >= 8) f.dylib = w[6], f.symbol = w[7];
      } else if (table == "rebase") {
        f.kind = "rebase";
      } else if (table == "bind" && w.size() >= 7) {
        f.kind = "bind", f.dylib = w[5], f.symbol = w[6];
      } else if (table == "lazy" && w.size() >= 5) {
        f.kind = "lazy", f.dylib = w[3], f.symbol = w[4];
      } else if (table == "weak" && w.size() >= 6) {
        f.kind = "weak", f.symbol = w[5];
      } else {
        continue;
      }
      out.push_back(std::move(f));
    }
    return out;
  }
};

// The fixtures, built on first use; nullopt when a tool is missing or the
// build fails (the tests skip). Removed when the process exits.
inline const std::optional<Fixtures> &fixtures(const std::string &clang, const std::string &ld, const std::string &lipo,
                                                const std::string &nm, const std::string &objdump,
                                                const std::string &fixture_dir) {
  static std::optional<Fixtures> built;
  static bool tried = false;
  if (tried) return built;
  tried = true;
  if (clang.empty() || ld.empty() || lipo.empty() || nm.empty() || objdump.empty()) return built;
  const std::filesystem::path dir =
      std::filesystem::temp_directory_path() / ("revkit-macho-" + std::to_string(::getpid()));
  std::filesystem::create_directories(dir);
  static std::filesystem::path made;
  made = dir;
  std::atexit([] {
    std::error_code ec;
    std::filesystem::remove_all(made, ec);
  });
  const std::string cmd = "sh '" + fixture_dir + "/build.sh' '" + clang + "' '" + ld + "' '" + lipo + "' '" + nm +
                          "' '" + objdump + "' '" + dir.string() + "' >'" + (dir / "build.log").string() + "' 2>&1";
  if (std::system(cmd.c_str()) != 0) return built;
  built = Fixtures{dir};
  return built;
}

}  // namespace revkit::loader::macho_testing
