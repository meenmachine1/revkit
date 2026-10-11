// rk-cparse: parse C headers (or whole sources, bodies skipped) into
// revkit types and print them as C or JSON (docs/cparse.md).
//
//   rk-cparse [options] FILE...   (one translation unit; "-" reads stdin)

#include "revkit/cparse/archive.h"
#include "revkit/cparse/cparse.h"
#include "revkit/cparse/spec.h"
#include "revkit/lift/lifter.hh"
#include "revkit/runtime/runtime.h"
#include "revkit/types/describe.h"
#include "revkit/types/print.h"
#include "revkit/types/transform.h"

#include <cstdio>
#include <iostream>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace cp = revkit::cparse;
namespace types = revkit::types;

struct Options {
  std::vector<std::string> files;
  std::string target = "x86_64-linux-gnu";
  std::string language, compiler, format = "elf";
  std::string ghidra;
  std::vector<std::string> roots;
  cp::Options parse;
  bool json = false;
  bool system = false;
  bool quiet = false;
  bool list = false;
  bool units = false;
  std::string dump;
  std::string archive;
};

void usage(std::ostream &os) {
  os << "usage: rk-cparse [options] FILE...    (\"-\" reads stdin; the files are one translation unit)\n"
        "  --target NAME          a named target (default x86_64-linux-gnu); --list-targets lists them\n"
        "  --language ID          the target of a Ghidra language, from its compiler spec\n"
        "    --compiler ID        ... and compiler spec id (default: the language's first)\n"
        "    --format elf|pe|raw  ... and executable format (default elf)\n"
        "    --ghidra DIR         Ghidra install with the specs (default: found as the other tools do)\n"
        "  -I DIR, -isystem DIR   include directories (-isystem: after the built-in headers)\n"
        "  -D NAME[=VALUE], -U NAME\n"
        "  -x c++, --cplusplus    parse as C++ (default: by file extension)\n"
        "  --no-builtin-headers   no built-in stddef.h, stdint.h, ...\n"
        "  --root DIR             read files only under DIR (repeatable)\n"
        "  --units                each FILE is its own translation unit; then link them: a struct one\n"
        "                         only declares is the definition the others agree on\n"
        "  --defines-as-enums     group each file's integer #defines into an enum\n"
        "  --json                 named types (layouts, hashes), prototypes, constants and diagnostics as JSON\n"
        "  --system               also print types from system and built-in headers\n"
        "  --archive NAME         print the named types as a type archive header (NAME.h; notes on stderr)\n"
        "  -q                     don't print diagnostics (still counted in the exit status)\n"
        "exit status: 0, 1 when a source had errors (or a limit stopped the parse), 2 for usage errors\n";
}

std::optional<Options> parse_args(int argc, char **argv) {
  Options o;
  for (int i = 1; i < argc; ++i) {
    std::string_view a = argv[i];
    auto value = [&]() -> const char * { return i + 1 < argc ? argv[++i] : nullptr; };
    auto joined = [&](std::string_view flag) -> std::optional<std::string> {
      if (a == flag) {
        const char *v = value();
        if (!v) return std::nullopt;
        return std::string(v);
      }
      if (a.starts_with(flag)) return std::string(a.substr(flag.size()));
      return std::nullopt;
    };
    const char *v = nullptr;
    if (a == "--help" || a == "-h") return std::nullopt;
    if (a == "--target" && (v = value())) o.target = v;
    else if (a == "--language" && (v = value())) o.language = v;
    else if (a == "--compiler" && (v = value())) o.compiler = v;
    else if (a == "--format" && (v = value())) o.format = v;
    else if (a == "--ghidra" && (v = value())) o.ghidra = v;
    else if (a == "--root" && (v = value())) o.roots.push_back(v);
    else if (a == "--list-targets") o.list = true;
    else if (a == "--units") o.units = true;
    else if (a == "--dump" && (v = value())) o.dump = v;
    else if (a == "--archive" && (v = value())) o.archive = v;
    else if (a == "--json") o.json = true;
    else if (a == "--system") o.system = true;
    else if (a == "-q") o.quiet = true;
    else if (a == "--cplusplus" || a == "-xc++" || (a == "-x" && i + 1 < argc && std::string_view(argv[i + 1]) == "c++" && ++i)) o.parse.cplusplus = true;
    else if (a == "-xc" || (a == "-x" && i + 1 < argc && std::string_view(argv[i + 1]) == "c" && ++i)) o.parse.cplusplus = false;
    else if (a == "--no-builtin-headers") o.parse.builtin_headers = false;
    else if (a == "--defines-as-enums") o.parse.defines_as_enums = true;
    else if (a == "-isystem" && (v = value())) o.parse.system_include_dirs.push_back(v);
    else if (a.starts_with("-I")) {
      auto d = joined("-I");
      if (!d) return std::nullopt;
      o.parse.include_dirs.push_back(*d);
    } else if (a.starts_with("-D")) {
      auto d = joined("-D");
      if (!d) return std::nullopt;
      auto eq = d->find('=');
      if (eq == std::string::npos) o.parse.defines.emplace_back(*d, "1");
      else o.parse.defines.emplace_back(d->substr(0, eq), d->substr(eq + 1));
    } else if (a.starts_with("-U")) {
      auto d = joined("-U");
      if (!d) return std::nullopt;
      o.parse.undefines.push_back(*d);
    } else if (a == "-" || !a.starts_with("-")) o.files.emplace_back(a);
    else return std::nullopt;
  }
  if (o.files.empty() && !o.list) return std::nullopt;
  return o;
}

const char *severity(cp::Severity s) {
  switch (s) {
    case cp::Severity::Note: return "note";
    case cp::Severity::Warning: return "warning";
    case cp::Severity::Error: return "error";
  }
  return "error";
}

std::string location_json(const cp::Location &l) {
  return "\"file\":" + types::json_quote(l.file) + ",\"line\":" + std::to_string(l.line) +
         ",\"system\":" + (l.system ? "true" : "false");
}

}  // namespace

int main(int argc, char **argv) {
  if (revkit::runtime::print_version_if_asked(argc, argv, "rk-cparse")) return 0;
  auto opt = parse_args(argc, argv);
  if (!opt) {
    usage(std::cerr);
    return 2;
  }
  if (opt->list) {
    for (const std::string &n : cp::profile_names()) std::cout << n << "\n";
    return 0;
  }
  std::vector<std::string> notes;
  if (!opt->language.empty()) {
    auto ghidra = revkit::runtime::find_ghidra(opt->ghidra, "rk-cparse");
    if (!ghidra) return 1;
    try {
      revkit::lift::initialize(*ghidra);
      opt->parse.profile = cp::profile_for_language(opt->language, opt->compiler, opt->format, &notes);
    } catch (const std::exception &e) {
      std::cerr << "rk-cparse: " << e.what() << "\n";
      return 1;
    }
  } else {
    auto p = cp::profile_named(opt->target);
    if (!p) {
      std::cerr << "rk-cparse: unknown target " << opt->target << " (--list-targets lists them)\n";
      return 2;
    }
    opt->parse.profile = *p;
  }
  auto fs = cp::host_file_system(opt->roots);
  opt->parse.fs = fs.get();
  std::vector<cp::Source> sources;
  for (const std::string &f : opt->files) {
    if (f == "-") {
      std::string text(std::istreambuf_iterator<char>(std::cin), {});
      sources.push_back({"<stdin>", std::move(text), false});
    } else {
      sources.push_back({f, {}, true});
    }
  }
  types::TypeStore store;
  cp::Result r;
  if (opt->units) {
    std::vector<cp::Result> units;
    for (const cp::Source &s : sources) units.push_back(cp::parse(store, std::span(&s, 1), opt->parse));
    for (const std::string &k : cp::link(store, units))
      if (!opt->quiet && !opt->json) std::cerr << "rk-cparse: note: " << k << " is defined differently by different units\n";
    // One result: each key once per distinct definition.
    std::set<std::pair<std::string, std::uint32_t>> seen;
    for (cp::Result &u : units) {
      for (cp::NamedType &n : u.named)
        if (seen.emplace(n.key, n.id.raw()).second) r.named.push_back(std::move(n));
      for (cp::Prototype &p : u.prototypes) r.prototypes.push_back(std::move(p));
      for (cp::Constant &c : u.constants) r.constants.push_back(std::move(c));
      for (cp::Diagnostic &d : u.diagnostics) r.diagnostics.push_back(std::move(d));
      r.errors += u.errors;
      r.warnings += u.warnings;
      r.limit_hit = r.limit_hit || u.limit_hit;
      r.suppressed_diagnostics += u.suppressed_diagnostics;
    }
  } else {
    r = cp::parse(store, sources, opt->parse);
  }
  if (!opt->quiet && !opt->json) {
    for (const std::string &n : notes) std::cerr << "rk-cparse: note: " << n << "\n";
    for (const cp::Diagnostic &d : r.diagnostics)
      std::cerr << (d.file.empty() ? "<input>" : d.file) << ":" << d.line << ":" << d.col << ": " << severity(d.severity)
                << ": " << d.text << "\n";
    if (r.suppressed_diagnostics) std::cerr << "rk-cparse: " << r.suppressed_diagnostics << " more diagnostics\n";
  }
  if (!opt->dump.empty()) {
    for (const cp::NamedType &n : r.named)
      if (n.key == opt->dump) {
        revkit::types::WithoutTypedefsOptions w;
        w.name_anonymous_tags = true;
        std::cout << types::deep_dump(store, revkit::types::without_typedefs(store, n.id, w));
      }
    return 0;
  }
  if (!opt->archive.empty()) {
    std::vector<types::TypeId> roots;
    for (const cp::NamedType &n : r.named)
      if (!n.where.system || opt->system) roots.push_back(n.id);
    cp::ArchiveOptions ao;
    ao.name = opt->archive;
    ao.profile = opt->parse.profile;
    cp::Archive a = cp::write_archive(store, roots, ao);
    std::cout << a.header;
    for (const std::string &n : a.notes) std::cerr << "rk-cparse: archive: " << n << "\n";
    std::cerr << "rk-cparse: archive: " << a.entries.size() << " types, " << a.mismatches << " not reproduced\n";
    return a.mismatches || r.errors ? 1 : 0;
  }
  if (opt->json) {
    std::string out = "{\"profile\":" + types::json_quote(opt->parse.profile.name) + ",\n\"named\":[";
    bool first = true;
    for (const cp::NamedType &n : r.named) {
      if (n.where.system && !opt->system) continue;
      std::string j = types::layout_json(store, n.id);
      j.pop_back();
      out += std::string(first ? "\n" : ",\n") + j + "," + location_json(n.where) + "}";
      first = false;
    }
    out += "],\n\"constant_enums\":[";
    first = true;
    for (const cp::NamedType &n : r.constant_enums) {
      out += std::string(first ? "\n" : ",\n") + types::layout_json(store, n.id);
      first = false;
    }
    out += "],\n\"prototypes\":[";
    first = true;
    for (const cp::Prototype &p : r.prototypes) {
      out += std::string(first ? "\n" : ",\n") + "{\"name\":" + types::json_quote(p.name) +
             ",\"declaration\":" + types::json_quote(types::prototype(store, p.type, p.name)) + ",\"hash\":\"" +
             store.hash(p.type).hex() + "\",\"defined\":" + (p.defined ? "true" : "false") + "," +
             location_json(p.where) + "}";
      first = false;
    }
    out += "],\n\"constants\":[";
    first = true;
    for (const cp::Constant &c : r.constants) {
      out += std::string(first ? "\n" : ",\n") + "{\"name\":" + types::json_quote(c.name) +
             ",\"value\":" + (c.is_unsigned ? std::to_string(std::uint64_t(c.value)) : std::to_string(c.value)) +
             ",\"unsigned\":" + (c.is_unsigned ? "true" : "false") + "," + location_json(c.where) + "}";
      first = false;
    }
    out += "],\n\"diagnostics\":[";
    first = true;
    for (const cp::Diagnostic &d : r.diagnostics) {
      out += std::string(first ? "\n" : ",\n") + "{\"file\":" + types::json_quote(d.file) +
             ",\"line\":" + std::to_string(d.line) + ",\"col\":" + std::to_string(d.col) + ",\"severity\":\"" +
             severity(d.severity) + "\",\"text\":" + types::json_quote(d.text) + "}";
      first = false;
    }
    out += "],\n\"notes\":[";
    for (std::size_t i = 0; i < notes.size(); ++i) out += (i ? "," : "") + types::json_quote(notes[i]);
    out += "],\n\"errors\":" + std::to_string(r.errors) + ",\"warnings\":" + std::to_string(r.warnings) +
           ",\"limit_hit\":" + (r.limit_hit ? "true" : "false") + "}\n";
    std::cout << out;
  } else {
    for (const cp::NamedType &n : r.named) {
      if (n.where.system && !opt->system) continue;
      std::cout << types::definition(store, n.id) << "\n";
    }
    for (const cp::NamedType &n : r.constant_enums) std::cout << types::definition(store, n.id) << "\n";
    for (const cp::Prototype &p : r.prototypes) std::cout << types::prototype(store, p.type, p.name) << ";\n";
    for (const cp::Constant &c : r.constants)
      std::cout << "#define " << c.name << " "
                << (c.is_unsigned ? std::to_string(std::uint64_t(c.value)) + "U" : std::to_string(c.value)) << "\n";
  }
  return r.errors || r.limit_hit ? 1 : 0;
}
