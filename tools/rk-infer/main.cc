// rk-infer: infer every function's prototype in a binary (revkit::infer)
// and write them in the reference format (docs/reference-format.md), so
// tools/rk-debuginfo/protonorm.py can score them against debug info.
//
//   rk-infer [-j N] [--local] [--no-library] [--no-defaults] [--no-structures] [--rounds N]
//            [--decompile] [--stats FILE] [--memo-budget MB] [--store DIR]
//            [--max-varnodes N] [-o OUT.json] BINARY

#include "revkit/analysis/analysis.h"
#include "revkit/runtime/runtime.h"
#include "revkit/decompd/batch.h"
#include "revkit/facts/fact_db.h"
#include "revkit/facts/storage.h"
#include "revkit/facts/thread_pool.h"
#include "revkit/infer/feedback.h"
#include "revkit/infer/infer.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <sys/resource.h>
#ifdef __GLIBC__
#include <malloc.h>
#endif
#include <unistd.h>

namespace an = revkit::analysis;
namespace fs = std::filesystem;
namespace infer = revkit::infer;

namespace {

struct Options {
  std::string file;
  std::string out;
  std::string stats;
  std::string ghidra_root;
  unsigned threads = 0;
  bool in_process = false;  // decompile in this process (debugging under gdb)
  bool decompile = false;
  bool feedback = true;  // with --decompile: lock the inferred prototypes
  std::vector<std::uint64_t> trace;  // functions whose rounds to print
  std::string evidence;              // dump every function's evidence as JSON lines
  bool families = false;             // print function-pointer table families
  std::size_t memo_budget_mb = 256;   // resident memos; 0: unbounded, in memory
  std::string store;                  // where memos spill (default: a temporary directory)
  infer::Options infer;
};

void usage() {
  std::cerr << "usage: rk-infer [options] <binary>\n"
               "  -o <file>        output (default: stdout)\n"
               "  -j <n>           threads, and decompiler worker processes (default: hardware threads)\n"
               "  --decompile-in-process  decompile in this process, not in workers (debugging under gdb only)\n"
               "  --local          round 0 only: the decompiler's own view of each function\n"
               "  --no-library     no library signatures for imports\n"
               "  --no-defaults    leave undefinedN types as they are\n"
               "  --no-structures  no structures for classes of passed-on pointers (the output's \"structures\")\n"
               "  --rounds <n>     at most n inter-procedural rounds (default 16)\n"
               "  --decompile      add decompiled_c, every prototype locked to the inferred one\n"
               "  --no-feedback    with --decompile: decompile without the inferred prototypes\n"
               "  --stats <file>   write timing and convergence as JSON\n"
               "  --trace <hex>    print a function's observations and prototype in every round\n"
               "  --memo-budget <MB>  resident memos before they spill to an LMDB store (default 256; 0: no store)\n"
               "  --store <dir>    the store (default: a temporary directory, removed at exit)\n"
               "  --max-varnodes <n>  don't observe functions whose decompilation grows past n varnodes\n"
               "                   (default 100000; 0: no bound)\n"
               "  --ghidra <dir>   Ghidra install (default: $GHIDRA_INSTALL_DIR, ~/.config/revkit/revkit.conf,\n"
               "                   the bundled specs, ~/ghidra*, /opt/ghidra*; docs/getting-started.md)\n"
               "  --version        print the version and exit\n";
}

std::optional<Options> parse(int argc, char **argv) {
  Options o;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto value = [&]() -> std::string {
      if (i + 1 >= argc) throw std::runtime_error(a + " needs a value");
      return argv[++i];
    };
    if (a == "-o") o.out = value();
    else if (a == "-j") o.threads = static_cast<unsigned>(std::stoul(value()));
    else if (a == "--decompile-in-process") o.in_process = true;
    else if (a == "--local") o.infer.interprocedural = false;
    else if (a == "--no-library") o.infer.library = false;
    else if (a == "--no-defaults") o.infer.defaults = false;
    else if (a == "--no-structures") o.infer.structures = false;
    else if (a == "--rounds") o.infer.max_rounds = static_cast<std::uint32_t>(std::stoul(value()));
    else if (a == "--decompile") o.decompile = true;
    else if (a == "--no-feedback") o.feedback = false;
    else if (a == "--stats") o.stats = value();
    else if (a == "--trace") o.trace.push_back(std::stoull(value(), nullptr, 16));
    else if (a == "--evidence") o.evidence = value();
    else if (a == "--families") o.families = true;
    else if (a == "--ghidra") o.ghidra_root = value();
    else if (a == "--memo-budget") o.memo_budget_mb = std::stoull(value());
    else if (a == "--store") o.store = value();
    else if (a == "--max-varnodes") o.infer.max_varnodes = static_cast<std::uint32_t>(std::stoul(value()));
    else if (a == "-h" || a == "--help") return std::nullopt;
    else if (!a.empty() && a[0] == '-') throw std::runtime_error("unknown option " + a);
    else o.file = a;
  }
  if (o.file.empty()) return std::nullopt;
  return o;
}

std::string json_string(const std::string &s) {
  std::string out = "\"";
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20 || c >= 0x7f) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", c);
          out += buf;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out + "\"";
}

std::string hex(std::uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

double seconds_since(std::chrono::steady_clock::time_point t) {
  return std::chrono::duration<double>(std::chrono::steady_clock::now() - t).count();
}

std::string slot_text(const infer::Slot &s, const infer::DataOrg &org) {
  std::string where = s.reg.empty() ? "stack" + std::to_string(s.stack) : s.reg;
  return where + ":" + std::to_string(s.size) + " " + infer::print(s.type, org);
}

void trace(const revkit::facts::Snapshot &snap, const an::ProgramKey &prog, std::uint64_t entry, std::uint32_t rounds,
           const infer::DataOrg &org) {
  auto cg = snap.get<infer::CallGraphQuery>(prog);
  const infer::CallNode *n = cg->find(entry);
  std::cerr << "== " << hex(entry) << " " << (n ? n->name : "?") << "\n";
  if (n == nullptr) return;
  std::cerr << "   callers:";
  for (auto c : n->callers) std::cerr << " " << hex(c);
  std::cerr << "\n   callees:";
  for (auto c : n->callees) std::cerr << " " << hex(c);
  if (!n->call_returns.empty()) {
    std::cerr << "\n   tail calls at:";
    for (auto c : n->call_returns) std::cerr << " " << hex(c);
  }
  std::cerr << "\n";
  for (std::uint32_t k = 0; k <= rounds; ++k) {
    auto o = infer::observation(snap, infer::RoundKey{{prog, entry}, k});
    auto r = snap.get<infer::Round>(infer::RoundKey{{prog, entry}, k});
    std::cerr << "  round " << k << (o->ok ? "" : " FAILED " + o->error) << "\n    params:";
    for (const auto &s : o->params) std::cerr << " [" << slot_text(s, org) << "]";
    std::cerr << "\n    ret: " << (o->ret ? slot_text(*o->ret, org) : "none") << "\n    extra:";
    for (const auto &s : o->extra_inputs) std::cerr << " [" << slot_text(s, org) << "]";
    std::cerr << "\n    prologue:" << (o->reads_al ? " reads AL;" : "");
    for (const auto &r : o->spills) std::cerr << " " << r;
    std::cerr << "\n";
    for (const auto &c : o->calls) {
      std::cerr << "    call " << hex(c.address) << " -> " << hex(c.target) << (c.locked ? " locked" : "") << ":";
      for (const auto &s : c.args) std::cerr << " [" << slot_text(s, org) << "]";
      if (c.ret_used) std::cerr << " => " << infer::print(c.ret_type, org);
      std::cerr << "\n";
    }
    // Calls to it from callers in this round.
    for (auto c : n->callers) {
      auto oc = infer::observation(snap, infer::RoundKey{{prog, c}, k});
      for (const auto &s : oc->calls) {
        if (s.target != entry) continue;
        std::cerr << "    from " << hex(c) << (s.locked ? " locked" : "") << ":";
        for (const auto &a : s.args) std::cerr << " [" << slot_text(a, org) << "]";
        if (s.ret_used) std::cerr << " => " << infer::print(s.ret_type, org);
        std::cerr << "\n";
      }
    }
    auto own = snap.get<infer::Own>(infer::RoundKey{{prog, entry}, k});
    std::cerr << "    own " << (own->known ? own->proto.print("f", org) : "unknown") << "\n";
    std::cerr << "    => " << (r->known ? r->proto.print("f", org) : "unknown") << " changes=" << r->changes
              << (r->widened ? " widened" : "") << "\n";
  }
  // Its table family's members, as their own evidence has them in the last
  // round (Round votes over these).
  auto families = snap.get<infer::Families>(prog);
  if (const std::vector<std::uint64_t> *family = families->find(entry)) {
    std::cerr << "   family of " << family->size() << ":\n";
    for (std::uint64_t m : *family) {
      auto o = snap.get<infer::Own>(infer::RoundKey{{prog, m}, rounds});
      std::cerr << "    " << hex(m) << " " << (o->known ? o->proto.print("f", org) : "unknown") << "\n";
    }
  }
}

std::string slot_json(const infer::Slot &s, const infer::DataOrg &org) {
  std::ostringstream o;
  o << "{\"reg\":" << json_string(s.reg) << ",\"stack\":" << s.stack << ",\"size\":" << int(s.size)
    << ",\"used\":" << int(s.used) << ",\"narrowest\":" << int(s.narrowest) << ",\"type\":" << json_string(infer::print(s.type, org));
  if (!s.constants.empty()) o << ",\"const\":" << s.constants.front();
  o << "}";
  return o.str();
}

std::string obs_json(const infer::Observation &ob, const infer::DataOrg &org) {
  std::ostringstream o;
  o << "{\"ok\":" << (ob.ok ? "true" : "false") << ",\"params\":[";
  for (std::size_t i = 0; i < ob.params.size(); ++i) o << (i ? "," : "") << slot_json(ob.params[i], org);
  o << "],\"ret\":" << (ob.ret ? slot_json(*ob.ret, org) : "null") << ",\"ret_natural\":" << int(ob.ret_natural)
    << ",\"extra\":[";
  for (std::size_t i = 0; i < ob.extra_inputs.size(); ++i) o << (i ? "," : "") << slot_json(ob.extra_inputs[i], org);
  o << "],\"reads_al\":" << (ob.reads_al ? "true" : "false") << ",\"spills\":[";
  for (std::size_t i = 0; i < ob.spills.size(); ++i) o << (i ? "," : "") << json_string(ob.spills[i]);
  o << "]}";
  return o.str();
}

std::string site_json(const infer::CallSite &c, const infer::DataOrg &org) {
  std::ostringstream o;
  o << "{\"at\":" << c.address << ",\"locked\":" << (c.locked ? "true" : "false") << ",\"args\":[";
  for (std::size_t i = 0; i < c.args.size(); ++i) o << (i ? "," : "") << slot_json(c.args[i], org);
  o << "],\"ret_used\":" << (c.ret_used ? "true" : "false") << ",\"ret_type\":" << json_string(infer::print(c.ret_type, org))
    << ",\"ret_size\":" << int(c.ret_type.size) << "}";
  return o.str();
}

// One JSON object per function: its observations in round 0 and the last
// round, and the calls to it in its callers' round-0 and last-round
// observations.
void dump_evidence(const revkit::facts::Snapshot &snap, const an::ProgramKey &prog, std::uint32_t rounds,
                   const infer::DataOrg &org, const std::string &path) {
  auto cg = snap.get<infer::CallGraphQuery>(prog);
  std::ofstream f(path);
  for (const infer::CallNode &n : cg->nodes) {
    if (!n.import.empty()) continue;
    auto o0 = infer::observation(snap, infer::RoundKey{{prog, n.entry}, 0});
    auto ok = infer::observation(snap, infer::RoundKey{{prog, n.entry}, rounds});
    f << "{\"entry\":" << json_string(hex(n.entry)) << ",\"self0\":" << obs_json(*o0, org)
      << ",\"self\":" << obs_json(*ok, org) << ",\"callers\":" << n.callers.size() << ",\"sites0\":[";
    bool first = true;
    for (auto c : n.callers) {
      auto oc = infer::observation(snap, infer::RoundKey{{prog, c}, 0});
      for (const auto &s : oc->calls)
        if (s.target == n.entry) {
          f << (first ? "" : ",") << site_json(s, org);
          first = false;
        }
    }
    f << "],\"sites\":[";
    first = true;
    for (auto c : n.callers) {
      auto oc = infer::observation(snap, infer::RoundKey{{prog, c}, rounds});
      for (const auto &s : oc->calls)
        if (s.target == n.entry) {
          f << (first ? "" : ",") << site_json(s, org);
          first = false;
        }
    }
    f << "]}\n";
  }
}

int run(const Options &opt) {
  const auto t0 = std::chrono::steady_clock::now();
#ifdef __GLIBC__
  // Each decompiling thread would get a malloc arena of its own, and glibc
  // keeps what a round's decompilations free in every one of them: on
  // cmake about a gigabyte more at the peak than with four shared arenas,
  // at no measurable cost in time.
  if (std::getenv("MALLOC_ARENA_MAX") == nullptr) mallopt(M_ARENA_MAX, 4);
#endif
  revkit::loader::LoadOptions load;
  load.ghidra_image_base = true;
  auto image = std::make_shared<const revkit::loader::Image>(revkit::loader::load_file(opt.file, load));
  auto lang = revkit::loader::guess_language(*image);
  if (!lang) {
    std::cerr << "rk-infer: no language for " << opt.file << "\n";
    return 1;
  }
  revkit::lift::initialize(opt.ghidra_root);

  // Memos beyond the budget go to an LMDB store in a scratch directory
  // (every round's observations of a large program don't fit in memory).
  revkit::facts::FactDbOptions dbo;
  std::optional<fs::path> scratch;
  if (opt.memo_budget_mb != 0) {
    scratch = opt.store.empty() ? fs::temp_directory_path() / ("rk-infer-" + std::to_string(getpid())) : fs::path(opt.store);
    fs::create_directories(*scratch);
    revkit::facts::LmdbOptions lo;
    lo.no_sync = true;
    dbo.storage = revkit::facts::open_lmdb_storage(*scratch, lo);
    dbo.memo_budget = opt.memo_budget_mb << 20;
  }
  struct Cleanup {
    std::optional<fs::path> dir;
    bool keep;
    ~Cleanup() {
      std::error_code ec;
      if (dir && !keep) fs::remove_all(*dir, ec);
    }
  } cleanup{scratch, !opt.store.empty()};
  revkit::facts::FactDb db(std::move(dbo));
  an::register_queries(db.engine());
  infer::register_queries(db.engine());
  const an::ProgramKey prog{"p"};
  const an::ProgramInfo info = an::describe(*image, lang->id());
  {
    auto tx = db.begin();
    an::stage_image(tx, prog, *image, info);
    std::error_code ec;
    const std::string identity = fs::absolute(opt.file).string() + ":" + std::to_string(fs::file_size(opt.file, ec));
    infer::stage_image(tx, prog, image, lang->id(), identity, opt.infer);
    tx.commit();
  }
  const unsigned threads = opt.threads ? opt.threads : std::max(1u, std::thread::hardware_concurrency());
  revkit::facts::ThreadPool pool(threads);
  {
    // One decompiler worker per thread: a decompilation that crashes or
    // hangs costs that function's observation, not the run.
    revkit::decompd::PoolOptions po = revkit::decompd::default_pool_options();
    po.workers = threads;
    if (opt.in_process) po.in_process = true;
    infer::DecompilerPool::set_workers(std::make_shared<revkit::decompd::WorkerPool>(po));
  }
  revkit::facts::Snapshot snap = db.snapshot();
  const double load_s = seconds_since(t0);

  const auto t1 = std::chrono::steady_clock::now();
  {
    std::vector<an::Location> seeds;
    for (const an::Seed &s : info.seeds) seeds.push_back({prog, s.address});
    snap.get_all<an::Flow>(seeds, &pool);
  }
  auto functions = snap.get<an::Functions>(prog);
  snap.get<infer::CallGraphQuery>(prog);  // reads every flow; then discovery's engines can go
  an::release_idle_decoders();
  const double discover_s = seconds_since(t1);

  const auto t2 = std::chrono::steady_clock::now();
  std::vector<infer::RoundStats> round_stats;
  infer::FixpointResult result = infer::run(snap, prog, &pool, &round_stats);
  const double infer_s = seconds_since(t2);

  const infer::DataOrg org = infer::data_org(*image);
  for (std::uint64_t e : opt.trace) trace(snap, prog, e, result.rounds, org);
  if (!opt.evidence.empty()) dump_evidence(snap, prog, result.rounds, org, opt.evidence);
  if (opt.families) {
    auto fam = snap.get<infer::Families>(prog);
    auto cbs = snap.get<infer::Callbacks>(prog);
    for (const auto &f : fam->families) {
      std::cerr << "family:";
      for (auto m : f) std::cerr << " " << hex(m);
      std::cerr << "\n";
    }
    for (const auto &[e, p] : *cbs) std::cerr << "callback " << hex(e) << ": " << p.print("f", org) << "\n";
  }
  std::map<std::uint64_t, std::string> decompiled;
  double decompile_s = 0;
  if (opt.decompile) {
    const auto t3 = std::chrono::steady_clock::now();
    std::vector<std::uint64_t> entries;
    for (const infer::CallNode &n : snap.get<infer::CallGraphQuery>(prog)->nodes)
      if (n.import.empty()) entries.push_back(n.entry);
    decompiled = infer::decompile_all(snap, prog, entries, opt.feedback, &pool);
    decompile_s = seconds_since(t3);
  }

  // Decompilations that failed, once per function and bundle.
  std::vector<revkit::decompd::Failure> failures;
  {
    std::set<std::pair<std::uint64_t, std::string>> seen;
    for (const revkit::decompd::Failure &f : snap.get<infer::ImageInput>(prog)->pool->failures())
      if (seen.insert({f.function, f.bundle_hash}).second) failures.push_back(f);
    std::sort(failures.begin(), failures.end(),
              [](const auto &a, const auto &b) { return a.function < b.function; });
  }
  std::cerr << "rk-infer: " << revkit::decompd::failure_summary(failures);

  std::ostringstream out;
  out << "{\n\"binary\":{\"path\":" << json_string(opt.file) << ",\"language\":" << json_string(lang->id()) << "},\n";
  out << "\"format_version\":1,\n\"functions\":[\n";
  bool first = true;
  // Discovery's functions, and those inference found in tables of
  // function pointers.
  for (const infer::CallNode &n : snap.get<infer::CallGraphQuery>(prog)->nodes) {
    if (!n.import.empty()) continue;
    const infer::Prototype *p = result.find(n.entry);
    if (!first) out << ",\n";
    first = false;
    out << "{\"entry\":" << json_string(hex(n.entry)) << ",\"name\":" << json_string(n.name);
    if (n.from_data) out << ",\"from_data\":true";
    if (p != nullptr) out << ",\"prototype\":" << json_string(p->print(n.name, org));
    if (auto it = decompiled.find(n.entry); it != decompiled.end())
      out << ",\"decompiled_c\":" << json_string(it->second);
    out << "}";
  }
  out << "\n],\n\"structures\":[";
  first = true;
  for (const infer::InferredStructure &s : result.structures) {
    out << (first ? "\n" : ",\n");
    first = false;
    out << "{\"name\":" << json_string(s.name) << ",\"size\":" << s.size << ",\"functions\":" << s.functions
        << ",\"accesses\":" << s.accesses << ",\"parameters\":" << s.parameters << ",\"returns\":" << s.returns << ",\"fields\":[";
    for (std::size_t i = 0; i < s.fields.size(); ++i) {
      const infer::InferredField &f = s.fields[i];
      out << (i ? "," : "") << "{\"offset\":" << f.offset << ",\"size\":" << f.size << ",\"type\":"
          << json_string(infer::print(f.type, org)) << ",\"accesses\":" << f.accesses << "}";
    }
    out << "]}";
  }
  out << "\n],\n\"producer\":{\"name\":\"rk-infer\"}\n}\n";
  if (opt.out.empty()) {
    std::cout << out.str();
  } else {
    std::ofstream f(opt.out);
    f << out.str();
  }

  struct rusage ru{};
  getrusage(RUSAGE_SELF, &ru);
  std::ostringstream st;
  st << "{\"file\":" << json_string(opt.file) << ",\"functions\":" << functions->functions.size()
     << ",\"inferred\":" << result.prototypes.size() << ",\"rounds\":" << result.rounds
     << ",\"converged\":" << (result.converged ? "true" : "false") << ",\"widened\":" << result.widened
     << ",\"changed\":[";
  for (std::size_t i = 0; i < result.changed.size(); ++i) st << (i ? "," : "") << result.changed[i];
  st << "],\"threads\":" << threads << ",\"load_s\":" << load_s << ",\"discover_s\":" << discover_s
     << ",\"infer_s\":" << infer_s << ",\"decompile_s\":" << decompile_s
     << ",\"max_rss_mb\":" << ru.ru_maxrss / 1024 << ",\"decompile_failures\":" << failures.size()
     << ",\"round_stats\":[";
  for (std::size_t i = 0; i < round_stats.size(); ++i) {
    const infer::RoundStats &r = round_stats[i];
    st << (i ? "," : "") << "{\"round\":" << r.round << ",\"s\":" << r.seconds << ",\"decompiled\":" << r.decompiled
       << ",\"decompile_s\":" << r.decompile_seconds << ",\"slowest_s\":" << r.slowest_seconds
       << ",\"slowest\":" << json_string(hex(r.slowest)) << ",\"changed\":" << r.changed << ",\"changed_entries\":[";
    for (std::size_t j = 0; j < r.changed_entries.size(); ++j) st << (j ? "," : "") << json_string(hex(r.changed_entries[j]));
    st << "]}";
  }
  st << "]}\n";
  if (!opt.stats.empty()) {
    std::ofstream f(opt.stats);
    f << st.str();
  } else {
    std::cerr << st.str();
  }
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (revkit::runtime::print_version_if_asked(argc, argv, "rk-infer")) return 0;
  try {
    auto opt = parse(argc, argv);
    if (!opt) {
      usage();
      return 2;
    }
    auto ghidra = revkit::runtime::find_ghidra(opt->ghidra_root, "rk-infer");
    if (!ghidra) return 1;
    opt->ghidra_root = ghidra->string();
    return run(*opt);
  } catch (const std::exception &e) {
    std::cerr << "rk-infer: " << e.what() << "\n";
    return 1;
  }
}
