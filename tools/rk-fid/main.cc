// rk-fid: Function ID from the command line (docs/fid.md).
//
//   rk-fid hash <binary> [--json]
//       Every function's FID hash quad (Ghidra's, bit for bit).
//   rk-fid detail <binary> <entry>
//       One function's instructions: bytes, masks, operand objects (JSON),
//       to compare with tools/ghidra-export/ghidra_fid.py --detail.
//   rk-fid info <db.fidbf|db.rkfid>
//       A database's libraries and sizes.
//   rk-fid names <db>
//       Every function name in a database (JSON).
//   rk-fid match <binary> --db <file> [--db <file>...] [--json] [--threshold N]
//       The functions the databases name, with scores.
//   rk-fid create --name <family> [--version V] [--variant V] [--lang <id>]
//                 [--common <symbols.txt>] -o <out.rkfid> <program>...
//       A database from programs with symbols (or debug info).
//
// Common options: --ghidra <root> (default $REVKIT_GHIDRA_ROOT, then the
// build's), -j <threads> for discovery.
#include "json.hh"

#include "revkit/fid/create.h"
#include "revkit/fid/db.h"
#include "revkit/fid/hash.h"
#include "revkit/fid/match.h"
#include "revkit/fid/program.h"
#include "revkit/inputs/debug_info.h"
#include "revkit/inputs/inputs.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>

namespace {

using rklift::Json;
namespace fid = revkit::fid;

struct Loaded {
  std::shared_ptr<const revkit::loader::Image> image;
  std::string language, compiler;
  std::unique_ptr<revkit::inputs::Analysis> analysis;
  fid::ProgramHashes hashes;
  std::vector<std::uint64_t> no_return;
};

std::string hex(std::uint64_t v) {
  char b[24];
  std::snprintf(b, sizeof b, "%llx", static_cast<unsigned long long>(v));
  return b;
}
std::string hex16(std::uint64_t v) {
  char b[24];
  std::snprintf(b, sizeof b, "%016llx", static_cast<unsigned long long>(v));
  return b;
}

bool is_default_name(const std::string &n) {
  for (const char *p : {"FUN_", "thunk_FUN_", "LAB_", "SUB_", "entry"})
    if (n.starts_with(p) && (std::string_view(p) != "entry" || n == "entry")) return true;
  return n.empty();
}

// Names from debug info (mangled where there is a linkage name), by entry.
std::map<std::uint64_t, std::string> debug_names(const revkit::loader::Image &image, const std::string &path) {
  std::map<std::uint64_t, std::string> out;
  auto dbg = revkit::inputs::read_debug_info(image, path);
  if (!dbg) return out;
  if (dbg->pdb) {
    for (const auto &p : dbg->pdb->publics)
      if (p.function && p.address != 0) out.emplace(p.address, p.name);
    for (const auto &f : dbg->pdb->functions)
      out.emplace(f.entry, f.linkage_name.empty() ? f.name : f.linkage_name);
  }
  if (dbg->dwarf)
    for (const auto &f : dbg->dwarf->functions)
      if (!f.name.empty()) out.emplace(f.entry + dbg->dwarf_delta, f.linkage_name.empty() ? f.name : f.linkage_name);
  return out;
}

Loaded load(const std::string &path, unsigned jobs, bool names) {
  Loaded l;
  revkit::loader::LoadOptions opts;
  opts.ghidra_image_base = true;  // Ghidra's addresses (PIE at 0x100000)
  l.image = std::make_shared<const revkit::loader::Image>(revkit::loader::load_file(path, opts));
  auto guess = revkit::loader::guess_language(*l.image);
  if (!guess) throw std::runtime_error("no Ghidra language for " + path);
  l.language = guess->language;
  l.compiler = guess->compiler;
  l.analysis = revkit::inputs::analyze(*l.image, l.language + ":" + l.compiler, jobs);
  fid::ProgramSource src;
  src.language = l.language;
  src.info = &l.analysis->info();
  src.functions = &l.analysis->functions();
  revkit::inputs::Analysis *an = l.analysis.get();
  src.flow = [an](std::uint64_t key) { return an->flow_shared(key); };
  const revkit::loader::Image *img = l.image.get();
  src.read = [img](std::uint64_t a, std::span<std::byte> out) { return img->memory.read(a, out); };
  fid::image_relocations(*l.image, src);
  src.scalar_references = l.image->format != revkit::loader::Format::elf;
  src.no_return = revkit::inputs::ghidra_no_return(l.analysis->functions(), std::getenv("RK_FID_NAMES_ONLY") ? nullptr : l.analysis->no_return_evidence());
  l.no_return = src.no_return;
  if (names) src.names = debug_names(*l.image, path);
  l.hashes = fid::hash_program(src);
  return l;
}

std::string read_file(const std::string &p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) throw std::runtime_error("cannot read " + p);
  std::ostringstream s;
  s << in.rdbuf();
  return s.str();
}

Json hash_json(const fid::HashQuad &q) {
  Json::Object o;
  o["units"] = Json(static_cast<std::int64_t>(q.code_units));
  o["full"] = Json(hex16(q.full));
  o["specific_extra"] = Json(static_cast<std::int64_t>(q.specific_extra));
  o["specific"] = Json(hex16(q.specific));
  return Json(o);
}

int usage() {
  std::cerr << "usage: rk-fid hash|detail|info|match|create ... (see the header of tools/rk-fid/main.cc)\n";
  return 2;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 2) return usage();
  const std::string cmd = argv[1];
  std::vector<std::string> pos, dbs;
  std::string out, name, version, variant, lang, common, ghidra;
  bool json = false;
  unsigned jobs = 4;
  float threshold = fid::kScoreThreshold;
  for (int i = 2; i < argc; ++i) {
    std::string a = argv[i];
    auto next = [&]() -> std::string {
      if (i + 1 >= argc) throw std::runtime_error(a + " needs a value");
      return argv[++i];
    };
    try {
      if (a == "--json") json = true;
      else if (a == "--db") dbs.push_back(next());
      else if (a == "-o") out = next();
      else if (a == "--name") name = next();
      else if (a == "--version") version = next();
      else if (a == "--variant") variant = next();
      else if (a == "--lang") lang = next();
      else if (a == "--common") common = next();
      else if (a == "--ghidra") ghidra = next();
      else if (a == "--threshold") threshold = std::stof(next());
      else if (a == "-j") jobs = static_cast<unsigned>(std::stoul(next()));
      else if (a.starts_with("-")) return usage();
      else pos.push_back(a);
    } catch (const std::exception &e) {
      std::cerr << "rk-fid: " << e.what() << "\n";
      return 2;
    }
  }
  if (ghidra.empty())
    if (const char *g = std::getenv("REVKIT_GHIDRA_ROOT")) ghidra = g;
#ifdef REVKIT_DEFAULT_GHIDRA_ROOT
  if (ghidra.empty()) ghidra = REVKIT_DEFAULT_GHIDRA_ROOT;
#endif
  try {
    if (cmd == "names") {  // every function name in a database, as JSON
      if (pos.size() != 1) return usage();
      fid::Database db = fid::Database::open(pos[0]);
      std::set<std::string> names;
      for (const fid::Function &f : db.functions()) names.insert(f.name);
      Json::Array a;
      for (const std::string &n : names) a.push_back(Json(n));
      std::cout << Json(a).compact() << "\n";
      return 0;
    }
    if (cmd == "dump") {  // a small database whole, relations as (caller, callee) names
      if (pos.size() != 1) return usage();
      fid::Database db = fid::Database::open(pos[0]);
      if (db.functions().size() > 20000) throw std::runtime_error("too large to dump");
      Json::Array fns, rel;
      for (const fid::Function &f : db.functions()) {
        Json::Object o;
        o["name"] = Json(f.name);
        o["hash"] = hash_json(f.hash);
        o["flags"] = Json(static_cast<std::int64_t>(f.flags));
        fns.push_back(Json(o));
      }
      for (const fid::Function &a : db.functions())
        for (const fid::Function &b : db.functions()) {
          const bool sup = db.superior(a.id, b.hash.full), inf = db.inferior(a.hash.full, b.id);
          if (!sup && !inf) continue;
          Json::Array e;
          e.push_back(Json(a.name));
          e.push_back(Json(b.name));
          e.push_back(Json(sup ? (inf ? "both" : "superior") : "inferior"));
          rel.push_back(Json(e));
        }
      Json::Object d;
      d["functions"] = Json(fns);
      d["relations"] = Json(rel);
      std::cout << Json(d).compact() << "\n";
      return 0;
    }
    if (cmd == "info") {
      if (pos.size() != 1) return usage();
      fid::Database db = fid::Database::open(pos[0]);
      Json::Object o;
      o["name"] = Json(db.name());
      o["format"] = Json(db.format() == fid::Database::Format::fidbf ? "fidbf" : "rkfid");
      o["functions"] = Json(static_cast<std::uint64_t>(db.functions().size()));
      o["superior"] = Json(static_cast<std::uint64_t>(db.superior_count()));
      o["inferior"] = Json(static_cast<std::uint64_t>(db.inferior_count()));
      Json::Array libs;
      for (const fid::Library &l : db.libraries()) {
        Json::Object lo;
        lo["family"] = Json(l.family);
        lo["version"] = Json(l.version);
        lo["variant"] = Json(l.variant);
        lo["language"] = Json(l.language);
        lo["compiler"] = Json(l.compiler);
        lo["ghidra_version"] = Json(l.ghidra_version);
        libs.push_back(Json(lo));
      }
      o["libraries"] = Json(libs);
      std::cout << Json(o).compact() << "\n";
      return 0;
    }
    revkit::lift::initialize(ghidra);
    if (cmd == "hash") {
      if (pos.size() != 1) return usage();
      Loaded l = load(pos[0], jobs, false);
      Json::Array fns;
      for (const fid::ProgramFunction &f : l.hashes.functions) {
        if (!json) {
          if (f.hash)
            std::cout << hex(f.entry) << " " << f.name << " " << f.hash->code_units << " " << hex16(f.hash->full) << " "
                      << int(f.hash->specific_extra) << " " << hex16(f.hash->specific) << "\n";
          continue;
        }
        Json::Object o;
        o["entry"] = Json(hex(f.entry));
        o["name"] = Json(f.name);
        o["thunk"] = Json(f.thunk);
        if (f.hash) o["hash"] = hash_json(*f.hash);
        fns.push_back(Json(o));
      }
      if (json) {
        Json::Object d;
        d["language"] = Json(l.language);
        d["functions"] = Json(fns);
        Json::Array nr;
        for (std::uint64_t e : l.no_return) nr.push_back(Json(hex(e)));
        d["no_return"] = Json(nr);
        std::cout << Json(d).compact() << "\n";
      }
      return 0;
    }
    if (cmd == "detail") {
      if (pos.size() != 2) return usage();
      Loaded l = load(pos[0], jobs, false);
      const std::uint64_t entry = std::stoull(pos[1], nullptr, 16);
      const revkit::analysis::FunctionInfo *fi = l.analysis->functions().find(entry);
      if (!fi) throw std::runtime_error("no function at " + pos[1]);
      revkit::lift::SleighDecoder dec(l.language);
      Json::Array insns;
      for (const auto &cu : l.analysis->functions().code) {
        if (!fi->body.contains({fi->entry.space, cu.address})) continue;
        std::vector<std::byte> raw(32);
        const std::size_t got = l.image->memory.read(cu.address, raw);
        auto d = dec.fid(cu.address, std::span(raw.data(), got), dec.default_context());
        if (!d) continue;
        auto hexbytes = [](std::span<const std::uint8_t> b) {
          std::string s;
          for (std::uint8_t c : b) {
            char t[3];
            std::snprintf(t, sizeof t, "%02x", c);
            s += t;
          }
          return s;
        };
        std::vector<std::uint8_t> bytes(d->length);
        for (std::size_t k = 0; k < d->length; ++k) bytes[k] = std::to_integer<std::uint8_t>(raw[k]);
        Json::Object o;
        o["addr"] = Json(hex(cu.address));
        o["bytes"] = Json(hexbytes(bytes));
        o["mask"] = d->masks ? Json(hexbytes(d->mask)) : Json();
        o["call"] = Json(d->call);
        Json::Array ops;
        for (const auto &op : d->operands) {
          Json::Object oo;
          oo["mask"] = Json(hexbytes(op.mask));
          oo["scalar"] = Json(op.scalar);
          oo["address"] = Json(op.address);
          Json::Array objs;
          for (const auto &ob : op.objects) {
            Json::Array e;
            e.push_back(Json(ob.kind == revkit::lift::FidObject::Kind::scalar ? "s"
                             : ob.kind == revkit::lift::FidObject::Kind::reg  ? "r"
                                                                               : "a"));
            e.push_back(Json(ob.value));
            objs.push_back(Json(e));
          }
          oo["objs"] = Json(objs);
          ops.push_back(Json(oo));
        }
        o["ops"] = Json(ops);
        insns.push_back(Json(o));
      }
      std::cout << Json(insns).compact() << "\n";
      return 0;
    }
    if (cmd == "match") {
      if (pos.size() != 1 || dbs.empty()) return usage();
      std::vector<fid::Database> loaded;
      loaded.reserve(dbs.size());
      for (const std::string &p : dbs) loaded.push_back(fid::Database::open(p));
      Loaded l = load(pos[0], jobs, false);
      std::vector<const fid::Database *> ptrs;
      for (const fid::Database &d : loaded) ptrs.push_back(&d);
      ptrs = fid::for_language(ptrs, l.language);
      fid::SearchOptions so;
      so.threshold = threshold;
      std::vector<fid::Match> ms = fid::search(l.hashes, ptrs, so);
      Json::Array arr;
      for (const fid::Match &m : ms) {
        const fid::ProgramFunction &f = l.hashes.functions[m.function];
        if (!json) {
          std::cout << hex(m.entry) << " " << f.name << " -> " << (m.name.empty() ? "(not named)" : m.name) << " "
                    << m.score() << " [" << m.candidates.size() << "]\n";
          continue;
        }
        Json::Object o;
        o["entry"] = Json(hex(m.entry));
        o["was"] = Json(f.name);
        o["name"] = Json(m.name);
        o["score"] = Json(static_cast<double>(m.score()));
        o["verdict"] = Json(static_cast<std::int64_t>(m.verdict));
        Json::Array names;
        for (const std::string &n : m.names) names.push_back(Json(n));
        o["names"] = Json(names);
        Json::Array libs;
        for (const std::string &n : m.libraries) libs.push_back(Json(n));
        o["libraries"] = Json(libs);
        arr.push_back(Json(o));
      }
      if (json) std::cout << Json(arr).compact() << "\n";
      return 0;
    }
    if (cmd == "create") {
      if (pos.empty() || name.empty() || out.empty()) return usage();
      std::set<std::string> common_syms;
      if (!common.empty()) {
        std::istringstream in(read_file(common));
        for (std::string line; std::getline(in, line);) {
          while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
          if (!line.empty()) common_syms.insert(line);
        }
      }
      fid::Database db;
      std::optional<fid::LibraryBuilder> builder;
      std::string established;
      for (const std::string &p : pos) {
        Loaded l = load(p, jobs, true);
        if (!lang.empty() && l.language != lang) {
          std::cerr << "rk-fid: skipping " << p << " (" << l.language << ", not " << lang << ")\n";
          continue;
        }
        if (!builder) {
          fid::LibraryInfo li{name, version, variant, l.language, l.compiler};
          builder.emplace(db, li, common_syms);
          established = l.language;
        } else if (l.language != established) {
          std::cerr << "rk-fid: skipping " << p << " (" << l.language << ", not " << established << ")\n";
          continue;
        }
        builder->add_program(l.hashes, p, is_default_name);
      }
      if (!builder) throw std::runtime_error("no program in the library's language");
      fid::IngestReport r = builder->finish();
      db.write(out);
      std::cerr << "rk-fid: " << db.functions().size() << " functions";
      for (const auto &[d, n] : r.counts) std::cerr << ", " << static_cast<int>(d) << ":" << n;
      std::cerr << "; " << r.unresolved.size() << " callee names unresolved\n";
      return 0;
    }
  } catch (const std::exception &e) {
    std::cerr << "rk-fid: " << e.what() << "\n";
    return 1;
  }
  return usage();
}
