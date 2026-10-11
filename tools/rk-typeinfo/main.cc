// rk-typeinfo: builds a library type archive (a C header plus its JSON
// sidecar, docs/types.md#library-prototypes) from a system's headers with
// revkit's own C parser. The build runs it for the C libraries and the
// Windows API (src/typeinfo/CMakeLists.txt); revkit applies the archives'
// prototypes to imported functions by name.
//
//   rk-typeinfo --name NAME --target PROFILE --out DIR --headers FILE
//               [-isystem DIR]... [-I DIR]... [-D NAME[=VALUE]]... [--include FILE]...
//               [--exports LIB.a]... [--source TEXT] [--min-functions N]
//
// --headers lists the headers to include, one per line ('#' comments).
// --include adds a file of declarations of our own (runtime entry points
// the headers don't declare). With --exports, only the functions the
// import libraries export are kept (a Windows DLL's archive); their
// `__imp_` symbols name them, decorations stripped.

#include "revkit/cparse/archive.h"
#include "revkit/cparse/cparse.h"
#include "revkit/runtime/runtime.h"
#include "revkit/types/hash.h"
#include "revkit/types/store.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

namespace cp = revkit::cparse;
namespace types = revkit::types;
namespace fs = std::filesystem;

struct Args {
  std::string name, target, out, headers, source;
  std::vector<std::string> includes, exports;
  std::size_t min_functions = 1;
  cp::Options parse;
};

void usage() {
  std::cerr << "usage: rk-typeinfo --name NAME --target PROFILE --out DIR --headers FILE [-isystem DIR] [-I DIR]\n"
               "                   [-D NAME[=VALUE]] [--include FILE] [--exports LIB.a] [--source TEXT]\n"
               "                   [--min-functions N]\n";
}

std::optional<std::string> read_file(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return std::nullopt;
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

// The names an import library's archive symbol table gives its `__imp_`
// symbols: what the DLL exports, by the name a PE imports it by (x86's
// leading '_' and stdcall's "@N" stripped).
bool library_exports(const std::string &path, bool x86, std::set<std::string> &names) {
  std::optional<std::string> data = read_file(path);
  if (!data || !data->starts_with("!<arch>\n")) return false;
  const std::string &d = *data;
  std::size_t pos = 8;
  bool found = false;
  // The first member named "/" is the System V symbol table (big-endian
  // count, offsets, then NUL-terminated names).
  while (pos + 60 <= d.size()) {
    const std::string name = d.substr(pos, 16);
    const std::size_t size = std::strtoull(d.substr(pos + 48, 10).c_str(), nullptr, 10);
    const std::size_t body = pos + 60;
    if (body + size > d.size()) break;
    if (name.starts_with("/ ") || name.starts_with("/               ")) {
      if (size < 4) break;
      auto u32 = [&](std::size_t at) {
        return (std::uint32_t(std::uint8_t(d[at])) << 24) | (std::uint32_t(std::uint8_t(d[at + 1])) << 16) |
               (std::uint32_t(std::uint8_t(d[at + 2])) << 8) | std::uint32_t(std::uint8_t(d[at + 3]));
      };
      const std::uint32_t count = u32(body);
      std::size_t at = body + 4 + std::size_t(count) * 4;
      for (std::uint32_t i = 0; i < count && at < body + size; ++i) {
        const std::size_t end = d.find('\0', at);
        if (end == std::string::npos || end > body + size) break;
        std::string sym = d.substr(at, end - at);
        at = end + 1;
        if (!sym.starts_with("__imp_")) continue;
        sym = sym.substr(6);
        // x86 decorates every C name with a leading '_'.
        if (x86) {
          if (!sym.starts_with("_")) continue;
          sym = sym.substr(1);
        }
        if (const auto atsign = sym.rfind('@'); atsign != std::string::npos && atsign > 0 &&
                                                  sym.find_first_not_of("0123456789", atsign + 1) == std::string::npos)
          sym = sym.substr(0, atsign);
        names.insert(sym);
        found = true;
      }
      break;
    }
    pos = body + size + (size & 1);
  }
  return found;
}

std::string json_string(const std::string &s) {
  std::string out = "\"";
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", c);
          out += buf;
        } else {
          out += char(c);
        }
    }
  }
  return out + "\"";
}

const char *os_name(cp::Os os) {
  switch (os) {
    case cp::Os::Linux: return "linux";
    case cp::Os::Windows: return "windows";
    case cp::Os::Darwin: return "darwin";
    case cp::Os::None: break;
  }
  return "none";
}

const char *compiler_name(cp::Compiler c) {
  switch (c) {
    case cp::Compiler::Gcc: return "gcc";
    case cp::Compiler::Clang: return "clang";
    case cp::Compiler::Msvc: return "msvc";
  }
  return "gcc";
}

// The sidecar, as TypeService.ExportTypeArchive writes it
// (TypeArchiveSidecar as protobuf JSON with the proto's field names).
std::string sidecar(const Args &a, const cp::Profile &p, const cp::Archive &ar, const std::string &header_sha) {
  const cp::LayoutRules &r = p.rules;
  std::ostringstream o;
  auto num = [&](const char *k, std::uint64_t v, bool comma = true) {
    if (v) o << "  " << json_string(k) << ": " << v << (comma ? ",\n" : "\n");
  };
  auto flag = [&](const char *k, bool v) {
    if (v) o << "  " << json_string(k) << ": true,\n";
  };
  o << "{\n \"format\": \"revkit-type-archive\",\n \"version\": 1,\n \"name\": " << json_string(a.name)
    << ",\n \"header\": " << json_string(a.name + ".h") << ",\n \"header_sha256\": " << json_string(header_sha)
    << ",\n \"data_model\": {\n";
  o << "  \"profile\": " << json_string(p.name) << ",\n  \"arch\": " << json_string(p.arch) << ",\n  \"os\": "
    << json_string(os_name(p.os)) << ",\n  \"compiler\": " << json_string(compiler_name(p.compiler)) << ",\n";
  num("pointer_size", r.pointer_size);
  num("short_size", r.short_size);
  num("int_size", r.int_size);
  num("long_size", r.long_size);
  num("long_long_size", r.long_long_size);
  num("float_size", r.float_size);
  num("double_size", r.double_size);
  num("long_double_size", r.long_double_size);
  num("long_double_align", r.long_double_align);
  num("wchar_size", r.wchar_size);
  flag("wchar_signed", r.wchar_signed);
  flag("char_signed", r.char_signed);
  flag("big_endian", r.big_endian);
  flag("has_int128", r.has_int128);
  o << "  \"size_alignment\": [";
  for (std::size_t i = 0; i < r.size_alignment.size(); ++i)
    o << (i ? ", " : "") << json_string(std::to_string(r.size_alignment[i].first) + ":" +
                                        std::to_string(r.size_alignment[i].second));
  o << "],\n";
  num("max_alignment", r.max_alignment);
  o << "  \"bitfields\": " << json_string(r.bitfields == cp::BitfieldModel::Msvc ? "msvc" : "gcc") << ",\n";
  flag("msvc_enums", r.msvc_enums);
  flag("zero_width_bitfield_aligns", r.zero_width_bitfield_aligns);
  num("biggest_alignment", r.biggest_alignment);
  num("max_vector_alignment", r.max_vector_alignment);
  o << "  \"description\": " << json_string(cp::describe_profile(p)) << "\n },\n";
  o << " \"provenance\": {\n  \"generator\": \"revkit\",\n  \"origin\": " << json_string(a.source) << "\n },\n";
  o << " \"types\": [";
  for (std::size_t i = 0; i < ar.entries.size(); ++i) {
    const cp::ArchiveEntry &e = ar.entries[i];
    o << (i ? ",\n" : "\n") << "  {\"key\": " << json_string(e.key) << ", \"hash\": " << json_string(e.hash);
    if (e.size) o << ", \"size\": \"" << e.size << "\"";
    if (e.line) o << ", \"line\": " << e.line;
    o << ", \"form\": " << json_string(e.form);
    if (e.noreturn) o << ", \"noreturn\": true";
    if (e.source_hash != e.hash) o << ", \"source_hash\": " << json_string(e.source_hash);
    o << "}";
  }
  o << "\n ]\n}\n";
  return o.str();
}

}  // namespace

int main(int argc, char **argv) {
  if (revkit::runtime::print_version_if_asked(argc, argv, "rk-typeinfo")) return 0;
  Args a;
  for (int i = 1; i < argc; ++i) {
    const std::string s = argv[i];
    auto value = [&]() -> std::string {
      if (i + 1 >= argc) {
        usage();
        std::exit(2);
      }
      return argv[++i];
    };
    if (s == "--name") a.name = value();
    else if (s == "--target") a.target = value();
    else if (s == "--out") a.out = value();
    else if (s == "--headers") a.headers = value();
    else if (s == "--include") a.includes.push_back(value());
    else if (s == "--exports") a.exports.push_back(value());
    else if (s == "--source") a.source = value();
    else if (s == "--min-functions") a.min_functions = std::stoul(value());
    else if (s == "-isystem") a.parse.system_include_dirs.push_back(value());
    else if (s == "-I") a.parse.include_dirs.push_back(value());
    else if (s == "-D") {
      const std::string d = value();
      const auto eq = d.find('=');
      a.parse.defines.emplace_back(d.substr(0, eq), eq == std::string::npos ? "1" : d.substr(eq + 1));
    } else {
      usage();
      return 2;
    }
  }
  if (a.name.empty() || a.target.empty() || a.out.empty() || a.headers.empty()) {
    usage();
    return 2;
  }
  std::optional<cp::Profile> profile = cp::profile_named(a.target);
  if (!profile) {
    std::cerr << "rk-typeinfo: unknown target " << a.target << "\n";
    return 2;
  }
  std::optional<std::string> list = read_file(a.headers);
  if (!list) {
    std::cerr << "rk-typeinfo: can't read " << a.headers << "\n";
    return 1;
  }
  std::string unit = "/* " + a.name + " */\n";
  std::istringstream lines(*list);
  for (std::string line; std::getline(lines, line);) {
    if (const auto hash = line.find('#'); hash != std::string::npos) line.erase(hash);
    std::istringstream words(line);
    for (std::string h; words >> h;) unit += "#include <" + h + ">\n";
  }
  std::vector<cp::Source> sources{{a.name + ".c", unit, false}};
  for (const std::string &inc : a.includes) sources.push_back({inc, {}, true});

  std::set<std::string> exported;
  for (const std::string &lib : a.exports)
    if (!library_exports(lib, profile->rules.pointer_size == 4, exported)) {
      std::cerr << "rk-typeinfo: no exports read from " << lib << "\n";
      return 1;
    }

  types::TypeStore store;
  auto fs = cp::host_file_system();
  a.parse.profile = *profile;
  a.parse.fs = fs.get();
  a.parse.system_prototypes = true;
  a.parse.limits.wall_time = std::chrono::milliseconds(600'000);
  a.parse.limits.max_bytes = 256u << 20;
  a.parse.limits.max_diagnostics = 100'000;
  cp::Result r = cp::parse(store, sources, a.parse);
  std::size_t errors = 0;
  for (const cp::Diagnostic &d : r.diagnostics)
    if (d.severity == cp::Severity::Error && ++errors <= 20)
      std::cerr << "rk-typeinfo: " << a.name << ": " << d.file << ":" << d.line << ": " << d.text << "\n";
  if (r.limit_hit) {
    std::cerr << "rk-typeinfo: " << a.name << ": a parser limit stopped the parse\n";
    return 1;
  }

  // The functions, by the name a binary imports them by: the asm label's
  // where glibc renames one (sscanf links as __isoc99_sscanf), and the C
  // name too (older binaries import that).
  std::map<std::string, cp::ArchiveFunction> functions;
  auto add = [&](const std::string &name, const cp::Prototype &p) {
    if (name.empty() || name.find("::") != std::string::npos || name.starts_with("__builtin")) return;
    if (!exported.empty() && !exported.contains(name)) return;
    const auto *fn = store.get(p.type).as<types::FunctionType>();
    if (fn == nullptr) return;
    auto [it, fresh] = functions.try_emplace(name, cp::ArchiveFunction{name, p.type, p.noreturn});
    if (!fresh) it->second.noreturn = it->second.noreturn || p.noreturn;
  };
  for (const cp::Prototype &p : r.prototypes) {
    if (!p.asm_label.empty()) add(p.asm_label, p);
    add(p.name, p);
  }
  if (functions.size() < a.min_functions) {
    std::cerr << "rk-typeinfo: " << a.name << ": only " << functions.size() << " functions (expected at least "
              << a.min_functions << "); " << errors << " errors\n";
    return 1;
  }

  cp::ArchiveOptions ao;
  ao.name = a.name;
  ao.profile = *profile;
  for (auto &[name, f] : functions) ao.functions.push_back(f);
  cp::Archive ar = cp::write_archive(store, {}, ao);
  std::size_t prototypes = 0;
  for (const cp::ArchiveEntry &e : ar.entries) prototypes += e.form == "prototype";

  std::error_code ec;
  fs::create_directories(a.out, ec);
  const fs::path header = fs::path(a.out) / (a.name + ".h");
  const fs::path json = fs::path(a.out) / (a.name + ".json");
  types::Sha256 h;
  h.update(ar.header);
  const std::string sha = types::to_hex(h.finish());
  auto write = [](const fs::path &p, const std::string &text) {
    const fs::path tmp = p.string() + ".tmp";
    {
      std::ofstream out(tmp, std::ios::binary);
      out << text;
      if (!out) return false;
    }
    std::error_code e;
    fs::rename(tmp, p, e);
    return !e;
  };
  if (!write(header, ar.header) || !write(json, sidecar(a, *profile, ar, sha))) {
    std::cerr << "rk-typeinfo: can't write " << header << "\n";
    return 1;
  }
  std::cerr << "rk-typeinfo: " << a.name << ": " << prototypes << " functions, " << ar.entries.size() - prototypes
            << " types, " << ar.mismatches << " not reproduced, " << errors << " parse errors in the headers\n";
  if (const char *v = std::getenv("RK_TYPEINFO_VERBOSE"); v && *v)
    for (const std::string &n : ar.notes) std::cerr << "  " << n << "\n";
  return 0;
}
