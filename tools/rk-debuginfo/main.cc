// rk-debuginfo: dump a binary's debug-info ground truth (functions, their
// bodies and prototypes) in the reference format (docs/reference-format.md).
//
//   rk-debuginfo [options] <binary>
//
// ELF: DWARF. PE: the CodeView PDB the image was linked with, found through
// the debug directory's path or next to the binary and checked against its
// GUID and age, plus any DWARF the image carries (mingw runtimes). Where
// both describe a function, the PDB wins.
//
// Addresses are rebased the way Ghidra loads the file (position-independent
// ELF images at 0x100000; PE at its ImageBase) so the output lines up with
// Ghidra's export. Also installed as rk-dwarf, its old name.

#include "revkit/debuginfo/dwarf.h"
#include "revkit/debuginfo/image.h"
#include "revkit/debuginfo/pdb.h"
#include "revkit/loader/load.hh"
#include "revkit/runtime/runtime.h"
#include "revkit/cparse/archive.h"
#include "revkit/types/describe.h"
#include "revkit/types/hash.h"
#include "revkit/types/print.h"
#include "revkit/types/transform.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace types = revkit::types;
namespace dbg = revkit::debuginfo;
namespace loader = revkit::loader;
namespace fs = std::filesystem;

std::string g_prog = "rk-debuginfo";

struct Options {
  std::string file;
  std::string path;  // binary.path; defaults to `file`
  types::Style style = types::Style::Ghidra;
  bool resolve_typedefs = false;
  bool file_base = false;
  std::optional<std::uint64_t> image_base;
  bool c_dump = false;
  bool types_json = false;
  std::string archive;               // --archive NAME
  std::string target = "x86_64-linux-gnu";  // its data model
  std::string dump;
  std::string pdb;  // explicit PDB
  bool use_pdb = true;
  bool use_dwarf = true;
};

void usage(std::ostream &os) {
  os << "usage: " << g_prog << " [options] <binary>\n"
        "  --path <p>          binary.path to record (default: the file argument)\n"
        "  --style ghidra|c    prototype notation (default ghidra, as the format requires)\n"
        "  --resolve-typedefs  print typedefs as their underlying types\n"
        "  --file-base         keep the file's addresses (default: rebase like Ghidra)\n"
        "  --image-base <hex>  rebase to this image base\n"
        "  --pdb <file>        PE: read this PDB (default: the debug directory's, or\n"
        "                      <name>.pdb beside the binary, if its GUID and age match)\n"
        "  --no-pdb            PE: ignore the PDB\n"
        "  --no-dwarf          ignore DWARF (for a PE: PDB functions only)\n"
        "  --c                 print a C dump of types, globals and prototypes instead\n"
        "  --types-json        print every named struct, union, enum and typedef's layout as JSON\n"
        "                      (one object per line; the C parser's round-trip truth)\n"
        "  --archive <name>    print every named type as a type archive header (notes on stderr)\n"
        "    --target <t>      ... laid out for this cparse target (default x86_64-linux-gnu)\n";
}

std::optional<Options> parse_args(int argc, char **argv) {
  Options opt;
  for (int i = 1; i < argc; ++i) {
    std::string_view arg = argv[i];
    auto value = [&]() -> const char * { return i + 1 < argc ? argv[++i] : nullptr; };
    const char *v = nullptr;
    if (arg == "--help" || arg == "-h") return std::nullopt;
    if (arg == "--path" && (v = value())) opt.path = v;
    else if (arg == "--style" && (v = value()) && (v == std::string_view("c") || v == std::string_view("ghidra")))
      opt.style = v == std::string_view("c") ? types::Style::C : types::Style::Ghidra;
    else if (arg == "--resolve-typedefs") opt.resolve_typedefs = true;
    else if (arg == "--file-base") opt.file_base = true;
    else if (arg == "--image-base" && (v = value())) opt.image_base = std::stoull(v, nullptr, 16);
    else if (arg == "--pdb" && (v = value())) opt.pdb = v;
    else if (arg == "--no-pdb") opt.use_pdb = false;
    else if (arg == "--no-dwarf") opt.use_dwarf = false;
    else if (arg == "--c") opt.c_dump = true;
    else if (arg == "--types-json") opt.types_json = true;
    else if (arg == "--archive" && (v = value())) opt.archive = v;
    else if (arg == "--target" && (v = value())) opt.target = v;
    else if (arg == "--dump" && (v = value())) opt.dump = v;
    else if (!arg.starts_with("-") && opt.file.empty()) opt.file = arg;
    else {
      std::cerr << g_prog << ": bad argument: " << arg << "\n";
      return std::nullopt;
    }
  }
  if (opt.file.empty()) return std::nullopt;
  if (opt.path.empty()) opt.path = opt.file;
  return opt;
}

// JSON string as Python's json.dumps(ensure_ascii=True) writes it, so the
// output matches refformat.dumps() byte for byte.
std::string json_string(std::string_view s) {
  std::string out = "\"";
  char buf[16];
  auto u16 = [&](unsigned v) {
    std::snprintf(buf, sizeof buf, "\\u%04x", v);
    out += buf;
  };
  for (std::size_t i = 0; i < s.size();) {
    auto c = static_cast<unsigned char>(s[i]);
    if (c < 0x80) {
      switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        default:
          if (c < 0x20) u16(c);
          else out += char(c);
      }
      ++i;
      continue;
    }
    // Decode UTF-8; invalid bytes become U+FFFD.
    unsigned len = c >= 0xf0 ? 4 : c >= 0xe0 ? 3 : c >= 0xc0 ? 2 : 0;
    unsigned cp = len == 4 ? c & 7 : len == 3 ? c & 15 : c & 31;
    bool ok = len != 0 && i + len <= s.size();
    for (unsigned k = 1; ok && k < len; ++k) {
      auto cc = static_cast<unsigned char>(s[i + k]);
      if ((cc & 0xc0) != 0x80) ok = false;
      cp = cp << 6 | (cc & 0x3f);
    }
    if (!ok || cp > 0x10ffff) {
      u16(0xfffd);
      ++i;
      continue;
    }
    if (cp >= 0x10000) {
      cp -= 0x10000;
      u16(0xd800 + (cp >> 10));
      u16(0xdc00 + (cp & 0x3ff));
    } else {
      u16(cp);
    }
    i += len;
  }
  return out + "\"";
}

std::string hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "\"0x%llx\"", static_cast<unsigned long long>(v));
  return buf;
}

std::string bare_hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::uint64_t rebase_target(const loader::Image &image, const Options &opt) {
  if (opt.image_base) return *opt.image_base;
  if (opt.file_base) return image.image_base;
  // Ghidra loads position-independent ELF images that start at 0 here.
  constexpr std::uint16_t kEtDyn = 3;
  if (image.format == loader::Format::elf && image.elf_type == kEtDyn && image.image_base == 0)
    return image.bits == 64 ? 0x100000 : 0x10000;
  return image.image_base;
}

std::optional<std::vector<std::uint8_t>> read_file(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) return std::nullopt;
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void warn(const std::string &msg) { std::cerr << g_prog << ": warning: " << msg << "\n"; }

// The PDB for a PE image: --pdb, else the debug directory's path (as
// written, then its file name beside the binary), else <stem>.pdb beside
// the binary. Automatic candidates must match the image's GUID and age.
std::optional<std::pair<fs::path, std::vector<std::uint8_t>>> find_pdb(const loader::Image &image,
                                                                      const Options &opt) {
  const auto &cv = image.codeview;
  auto check = [&](const fs::path &p, bool explicit_path) -> std::optional<std::vector<std::uint8_t>> {
    std::error_code ec;
    if (!fs::is_regular_file(p, ec)) {
      if (explicit_path) warn("cannot read PDB " + p.string());
      return std::nullopt;
    }
    auto bytes = read_file(p);
    if (!bytes) return std::nullopt;
    try {
      dbg::PdbIdentity id = dbg::read_pdb_identity(*bytes);
      bool match = !cv ? false
                   : cv->rsds ? id.matches(cv->guid, cv->age)
                              : id.signature == cv->signature && id.age == cv->age;
      if (!match) {
        std::string why = cv ? "doesn't match the image (PDB " + dbg::guid_string(id.guid) + " age " +
                                   std::to_string(id.age) + ")"
                             : "can't be checked: the image has no CodeView record";
        if (!explicit_path) {
          warn("skipping " + p.string() + ": " + why);
          return std::nullopt;
        }
        warn(p.string() + " " + why);
      }
    } catch (const dbg::PdbError &e) {
      warn(p.string() + ": " + e.what());
      return std::nullopt;
    }
    return bytes;
  };
  if (!opt.pdb.empty()) {
    if (auto b = check(opt.pdb, true)) return std::make_pair(fs::path(opt.pdb), std::move(*b));
    return std::nullopt;
  }
  std::vector<fs::path> candidates;
  fs::path dir = fs::path(opt.file).parent_path();
  if (cv && !cv->pdb_path.empty()) {
    std::string p = cv->pdb_path;
    candidates.push_back(p);
    std::replace(p.begin(), p.end(), '\\', '/');
    fs::path name = fs::path(p).filename();
    if (!name.empty()) candidates.push_back(dir / name);
  }
  candidates.push_back(dir / (fs::path(opt.file).stem().string() + ".pdb"));
  for (const fs::path &p : candidates)
    if (auto b = check(p, false)) return std::make_pair(p, std::move(*b));
  return std::nullopt;
}

void c_dump(const types::TypeStore &store, const dbg::DebugInfo &info) {
  for (types::TypeId id : info.types) {
    const types::Type &t = store.get(id);
    bool named = false;
    if (auto *a = t.as<types::AggregateType>()) named = !a->name.empty();
    else if (auto *e = t.as<types::EnumType>()) named = !e->name.empty();
    else named = t.kind() == types::Kind::Typedef;
    if (named) std::cout << types::definition(store, id) << "\n";
  }
  for (const auto &v : info.variables)
    std::printf("%s; /* 0x%llx */\n", types::declaration(store, v.type, v.qualified_name).c_str(),
                static_cast<unsigned long long>(v.address));
  std::cout << "\n";
  for (const auto &f : info.functions) {
    if (!f.prototype.valid()) continue;
    std::printf("%s; /* 0x%llx%s */\n",
                types::prototype(store, f.prototype, f.qualified_name).c_str(),
                static_cast<unsigned long long>(f.entry), f.abi_changed ? ", nocall" : "");
  }
}

int run(const Options &opt) {
  // File addresses; DWARF and the PDB use link-time addresses, rebased below.
  loader::Image image = loader::load_file(opt.file);
  types::TypeStore store;

  std::optional<dbg::PdbDebugInfo> pdb;
  if (image.format == loader::Format::pe && opt.use_pdb) {
    if (auto found = find_pdb(image, opt)) {
      dbg::PdbOptions popt;
      popt.image_base = image.image_base;
      pdb = dbg::read_pdb(found->second, store, popt);
      for (const auto &d : pdb->diagnostics)
        warn(found->first.string() + ": " + bare_hex(d.offset) + ": " + d.message);
    } else {
      warn("no PDB found for " + opt.file);
    }
  }
  dbg::DebugInfo info;
  dbg::ImageSections sections;
  if (opt.use_dwarf) {
    sections = dbg::dwarf_sections(image);
    for (const auto &w : sections.warnings) warn(w);
    info = dbg::import_dwarf(sections.sections, store);
    for (const auto &d : info.diagnostics) warn(bare_hex(d.offset) + ": " + d.message);
  }

  if (!opt.dump.empty()) {
    std::vector<types::TypeId> ids = pdb ? pdb->types : std::vector<types::TypeId>{};
    ids.insert(ids.end(), info.types.begin(), info.types.end());
    for (types::TypeId id : ids)
      if (types::named_key(store, id) == opt.dump) {
        types::WithoutTypedefsOptions w;
        w.name_anonymous_tags = true;
        std::cout << types::deep_dump(store, types::without_typedefs(store, id, w)) << "\n";
      }
    return 0;
  }
  if (!opt.archive.empty()) {
    auto profile = revkit::cparse::profile_named(opt.target);
    if (!profile) {
      std::cerr << g_prog << ": unknown target " << opt.target << "\n";
      return 2;
    }
    std::vector<types::TypeId> ids;
    if (pdb) ids = pdb->types;
    ids.insert(ids.end(), info.types.begin(), info.types.end());
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    std::vector<types::TypeId> named;
    for (types::TypeId id : ids)
      if (!types::named_key(store, id).empty()) named.push_back(id);
    revkit::cparse::ArchiveOptions ao;
    ao.name = opt.archive;
    ao.profile = *profile;
    revkit::cparse::Archive a = revkit::cparse::write_archive(store, named, ao);
    std::cout << a.header;
    for (const std::string &n : a.notes) std::cerr << g_prog << ": archive: " << n << "\n";
    std::cerr << g_prog << ": archive: " << a.entries.size() << " types, " << a.mismatches << " not reproduced\n";
    return a.mismatches ? 1 : 0;
  }
  if (opt.types_json) {
    std::vector<types::TypeId> ids;
    if (pdb) ids = pdb->types;
    ids.insert(ids.end(), info.types.begin(), info.types.end());
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    // layout_json adds typedef-free types to the store: name them first.
    std::vector<types::TypeId> named;
    for (types::TypeId id : ids)
      if (!types::named_key(store, id).empty()) named.push_back(id);
    for (types::TypeId id : named) std::cout << types::layout_json(store, id) << "\n";
    return 0;
  }

  if (opt.c_dump) {
    dbg::DebugInfo all = pdb ? dbg::DebugInfo(*pdb) : dbg::DebugInfo();
    all.types.insert(all.types.end(), info.types.begin(), info.types.end());
    std::sort(all.types.begin(), all.types.end());
    all.types.erase(std::unique(all.types.begin(), all.types.end()), all.types.end());
    all.variables.insert(all.variables.end(), info.variables.begin(), info.variables.end());
    all.functions.insert(all.functions.end(), info.functions.begin(), info.functions.end());
    c_dump(store, all);
    return 0;
  }

  // PDB functions first: one entry per address, the first description wins.
  std::vector<const dbg::Function *> functions;
  if (pdb)
    for (const auto &f : pdb->functions) functions.push_back(&f);
  for (const auto &f : info.functions) functions.push_back(&f);

  const std::uint64_t base = rebase_target(image, opt);
  const std::uint64_t delta = base - image.image_base;
  types::PrintOptions popt{opt.style, opt.resolve_typedefs};

  std::map<std::uint64_t, std::string> lines;
  for (const dbg::Function *fp : functions) {
    const dbg::Function &f = *fp;
    if (f.ranges.empty() || !dbg::is_code(image, f.entry) || lines.count(f.entry + delta)) continue;
    std::vector<dbg::AddressRange> merged;
    for (const auto &r : f.ranges) {
      if (!merged.empty() && r.begin <= merged.back().end) merged.back().end = std::max(merged.back().end, r.end);
      else merged.push_back(r);
    }
    std::string body;
    for (const auto &r : merged)
      body += std::string(body.empty() ? "" : ",") + "[" + hex(r.begin + delta) + "," +
              hex(r.end - 1 + delta) + "]";
    std::string name = f.name.empty() ? f.linkage_name : f.name;
    std::string line = "{\"body\":[" + body + "],\"entry\":" + hex(f.entry + delta);
    if (!name.empty()) line += ",\"name\":" + json_string(name);
    // A prototype the compiler didn't keep (DW_CC_nocall) isn't ground truth.
    if (!f.abi_changed && !name.empty() && f.prototype.valid())
      line += ",\"prototype\":" + json_string(types::prototype(store, f.prototype, name, popt));
    lines.emplace(f.entry + delta, line + "}");
  }

  types::Sha256 sha;
  sha.update({reinterpret_cast<const std::uint8_t *>(image.file->data()), image.file->size()});
  std::string binary = "{";
  auto lang = loader::guess_language(image);
  if (lang && pdb) {
    // The compiler spec Ghidra picks for a clang-built PE.
    for (const auto &m : pdb->modules)
      if (m.compiler.find("clang") != std::string::npos) lang->compiler = "clangwindows";
  }
  if (lang) binary += "\"compiler\":" + json_string(lang->compiler) + ",";
  binary += "\"image_base\":" + hex(base) + ",";
  if (lang) binary += "\"language\":" + json_string(lang->language) + ",";
  binary += "\"path\":" + json_string(opt.path) + ",\"sha256\":\"" + types::to_hex(sha.finish()) + "\"}";

  std::string out = "{\n\"binary\":" + binary + ",\n\"format_version\":1,\n";
  if (lines.empty()) {
    out += "\"functions\":[],\n";
  } else {
    out += "\"functions\":[\n";
    std::size_t i = 0;
    for (const auto &[addr, line] : lines) out += line + (++i < lines.size() ? ",\n" : "\n");
    out += "],\n";
  }
  out += "\"producer\":\"revkit-" + std::string(revkit::runtime::git_sha()) + "\"\n}\n";
  std::fwrite(out.data(), 1, out.size(), stdout);
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc > 0) {
    std::string self = fs::path(argv[0]).filename().string();
    if (!self.empty()) g_prog = self;
  }
  if (revkit::runtime::print_version_if_asked(argc, argv, g_prog)) return 0;
  auto opt = parse_args(argc, argv);
  if (!opt) {
    usage(std::cerr);
    return 2;
  }
  try {
    return run(*opt);
  } catch (const std::exception &e) {
    std::cerr << g_prog << ": " << e.what() << "\n";
    return 1;
  }
}
