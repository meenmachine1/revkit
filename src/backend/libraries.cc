#include "libraries.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <set>
#include <system_error>

namespace revkit::backend::libs {

namespace fs = std::filesystem;

std::string StripVersion(std::string_view name) {
  return std::string(name.substr(0, name.find('@')));
}

static std::string Lower(std::string_view s) {
  std::string out(s);
  for (char &c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

bool SameLibrary(std::string_view a, std::string_view b, bool pe) {
  return pe ? Lower(a) == Lower(b) : a == b;
}

std::map<std::string, std::uint64_t> Exports(const loader::Image &img) {
  std::map<std::string, std::uint64_t> out;
  if (img.format == loader::Format::pe) {
    for (const loader::Export &e : img.exports)
      if (!e.name.empty() && e.forwarder.empty() && e.address != 0) out.emplace(e.name, e.address);
    return out;
  }
  const bool dynsym = std::any_of(img.symbols.begin(), img.symbols.end(),
                                  [](const loader::Symbol &s) { return s.source == loader::SymbolSource::dynsym; });
  for (const loader::Symbol &s : img.symbols) {
    if (!s.defined || s.value == 0 || s.name.empty()) continue;
    if (dynsym && s.source != loader::SymbolSource::dynsym) continue;
    if (s.bind != loader::SymbolBind::global && s.bind != loader::SymbolBind::weak) continue;
    if (s.type != loader::SymbolType::func && s.type != loader::SymbolType::ifunc && s.type != loader::SymbolType::object)
      continue;
    std::string name = StripVersion(s.name);
    // A global definition wins over a weak one of the same name.
    auto [it, fresh] = out.emplace(name, s.value);
    if (!fresh && s.bind == loader::SymbolBind::global) it->second = s.value;
  }
  return out;
}

std::optional<FileArch> PeekArch(const fs::path &file) {
  std::ifstream in(file, std::ios::binary);
  if (!in) return std::nullopt;
  std::array<unsigned char, 64> h{};
  in.read(reinterpret_cast<char *>(h.data()), h.size());
  if (in.gcount() < 20) return std::nullopt;
  FileArch a;
  if (h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F') {
    a.format = loader::Format::elf;
    a.bits = h[4] == 2 ? 64 : 32;
    a.endian = h[5] == 2 ? loader::Endian::big : loader::Endian::little;
    a.machine = a.endian == loader::Endian::little ? (h[18] | (h[19] << 8)) : ((h[18] << 8) | h[19]);
    return a;
  }
  if (h[0] == 'M' && h[1] == 'Z') {
    const std::uint32_t pe = h[0x3c] | (h[0x3d] << 8) | (h[0x3e] << 16) | (static_cast<std::uint32_t>(h[0x3f]) << 24);
    if (pe > (1u << 20)) return std::nullopt;
    std::array<unsigned char, 26> p{};
    in.clear();
    in.seekg(pe);
    in.read(reinterpret_cast<char *>(p.data()), p.size());
    if (in.gcount() < 26 || p[0] != 'P' || p[1] != 'E' || p[2] != 0 || p[3] != 0) return std::nullopt;
    a.format = loader::Format::pe;
    a.machine = p[4] | (p[5] << 8);
    const unsigned magic = p[24] | (p[25] << 8);
    a.bits = magic == 0x20b ? 64 : 32;
    return a;
  }
  return std::nullopt;
}

bool Compatible(const FileArch &a, const loader::Image &img) {
  return a.format == img.format && a.bits == img.bits && a.machine == img.machine &&
         (a.format == loader::Format::pe || a.endian == img.endian);
}

// The Debian/Ubuntu multiarch directory name for an ELF machine.
static std::string Triplet(const loader::Image &img) {
  switch (img.machine) {
    case 62: return "x86_64-linux-gnu";
    case 3: return "i386-linux-gnu";
    case 183: return "aarch64-linux-gnu";
    case 40: return "arm-linux-gnueabihf";
    case 243: return img.bits == 64 ? "riscv64-linux-gnu" : "";
    case 8: return img.endian == loader::Endian::big ? "mips-linux-gnu" : "mipsel-linux-gnu";
    case 21: return "powerpc64le-linux-gnu";
    default: return "";
  }
}

std::vector<fs::path> SearchDirs(const std::vector<std::string> &user, const std::string &source_path,
                                 const loader::Image &img, bool host) {
  std::vector<fs::path> out;
  std::set<std::string> seen;
  auto add = [&](const fs::path &d) {
    std::error_code ec;
    if (!d.is_absolute() || !fs::is_directory(d, ec)) return;
    const std::string key = d.lexically_normal().string();
    if (seen.insert(key).second) out.push_back(d.lexically_normal());
  };
  for (const std::string &u : user) add(fs::path(u));
  if (!source_path.empty()) {
    const fs::path origin = fs::path(source_path).parent_path();
    add(origin);
    for (std::string r : img.runpath) {
      for (std::string_view o : {"${ORIGIN}", "$ORIGIN"})
        for (std::size_t at; (at = r.find(o)) != std::string::npos;) r.replace(at, o.size(), origin.string());
      add(fs::path(r));
    }
  }
  if (host && img.format == loader::Format::elf) {
    const std::string t = Triplet(img);
    for (const char *d : {"/lib", "/usr/lib"}) {
      if (!t.empty()) add(fs::path(d) / t);
      if (img.bits == 64) add(fs::path(std::string(d) + "64"));
      else add(fs::path(std::string(d) + "32"));
      add(fs::path(d));
    }
    add("/usr/local/lib");
  }
  return out;
}

std::optional<fs::path> FindLibrary(const std::string &name, const std::vector<fs::path> &dirs, const loader::Image &img) {
  if (name.empty() || name.find('/') != std::string::npos || name == "." || name == "..") return std::nullopt;
  const bool pe = img.format == loader::Format::pe;
  auto fits = [&](const fs::path &f) {
    std::error_code ec;
    if (!fs::is_regular_file(f, ec)) return false;
    auto a = PeekArch(f);
    return a && Compatible(*a, img);
  };
  for (const fs::path &d : dirs) {
    if (fits(d / name)) return d / name;
    if (!pe) continue;
    // Windows names are case-insensitive: KERNEL32.dll is kernel32.dll.
    std::error_code ec;
    for (fs::directory_iterator it(d, ec), end; !ec && it != end; it.increment(ec))
      if (SameLibrary(it->path().filename().string(), name, true) && fits(it->path())) return it->path();
  }
  return std::nullopt;
}

}  // namespace revkit::backend::libs
