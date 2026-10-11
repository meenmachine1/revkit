// rk-factbench: load a synthetic program into the fact store on LMDB and
// measure size, memory and incremental recomputation.
//
//   rk-factbench [--functions N] [--insns N] [--threads N] [--budget-mb N]
//                [--dir PATH] [--keep]
//
// Defaults model a ~100 MB binary: 250k functions averaging 100 toy
// instructions (~4.3 bytes each), i.e. ~25M instruction facts.

#include "toy_program.h"

#include "revkit/facts/fact_db.h"
#include "revkit/facts/thread_pool.h"

#include <malloc.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

namespace {

using namespace revkit::facts;
namespace fs = std::filesystem;

struct Options {
  std::uint64_t functions = 250000;
  std::uint32_t insns = 100;
  std::uint32_t globals = 20000;
  std::uint32_t structs = 500;
  unsigned threads = std::thread::hardware_concurrency();
  std::size_t budget_mb = 1024;
  std::string dir;
  bool keep = false;
};

void usage(std::ostream &os) {
  os << "usage: rk-factbench [--functions N] [--insns N] [--globals N] [--structs N]\n"
        "                    [--threads N] [--budget-mb N] [--dir PATH] [--keep]\n"
        "  --functions  functions to synthesize (default 250000)\n"
        "  --insns      average instructions per function (default 100)\n"
        "  --threads    query threads (default: all cores)\n"
        "  --budget-mb  resident memo budget before spilling to LMDB (default 1024)\n"
        "  --dir        LMDB directory (default: a temp dir, removed unless --keep)\n";
}

std::optional<Options> parse_args(int argc, char **argv) {
  Options opt;
  for (int i = 1; i < argc; ++i) {
    std::string_view arg = argv[i];
    auto value = [&]() -> const char * { return i + 1 < argc ? argv[++i] : nullptr; };
    const char *v = nullptr;
    try {
      if (arg == "--help" || arg == "-h") return std::nullopt;
      if (arg == "--functions" && (v = value())) opt.functions = std::stoull(v);
      else if (arg == "--insns" && (v = value())) opt.insns = static_cast<std::uint32_t>(std::stoul(v));
      else if (arg == "--globals" && (v = value())) opt.globals = static_cast<std::uint32_t>(std::stoul(v));
      else if (arg == "--structs" && (v = value())) opt.structs = static_cast<std::uint32_t>(std::stoul(v));
      else if (arg == "--threads" && (v = value())) opt.threads = static_cast<unsigned>(std::stoul(v));
      else if (arg == "--budget-mb" && (v = value())) opt.budget_mb = std::stoull(v);
      else if (arg == "--dir" && (v = value())) opt.dir = v;
      else if (arg == "--keep") opt.keep = true;
      else {
        std::cerr << "rk-factbench: bad argument: " << arg << "\n";
        return std::nullopt;
      }
    } catch (const std::exception &) {
      std::cerr << "rk-factbench: bad number for " << arg << "\n";
      return std::nullopt;
    }
  }
  if (opt.functions == 0 || opt.insns == 0 || opt.threads == 0) return std::nullopt;
  return opt;
}

// Fields of /proc/self/status, in bytes.
std::map<std::string, std::uint64_t> proc_status() {
  std::map<std::string, std::uint64_t> out;
  std::ifstream in("/proc/self/status");
  std::string line;
  while (std::getline(in, line)) {
    auto colon = line.find(':');
    if (colon == std::string::npos || line.find("kB") == std::string::npos) continue;
    try {
      out[line.substr(0, colon)] = std::stoull(line.substr(colon + 1)) * 1024;
    } catch (const std::exception &) {
    }
  }
  return out;
}

// Samples anonymous RSS, which unlike VmHWM excludes LMDB's file-backed,
// reclaimable mmap pages.
class PeakSampler {
 public:
  PeakSampler() : thread_([this](std::stop_token st) {
    while (!st.stop_requested()) {
      sample();
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  }) {}
  void sample() {
    raise(peak_, proc_status()["RssAnon"]);
    struct mallinfo2 mi = mallinfo2();
    raise(peak_live_, mi.uordblks + mi.hblkhd);
    if (Engine *e = engine_.load()) raise(peak_cache_, e->resident_bytes());
  }
  std::uint64_t peak_live() { return peak_live_.load(); }
  std::uint64_t peak_cache() { return peak_cache_.load(); }
  void watch(Engine *e) { engine_.store(e); }
  std::uint64_t peak_anon() {
    sample();
    return peak_.load();
  }

 private:
  static void raise(std::atomic<std::uint64_t> &a, std::uint64_t v) {
    std::uint64_t cur = a.load();
    while (v > cur && !a.compare_exchange_weak(cur, v)) {
    }
  }
  std::atomic<std::uint64_t> peak_{0};
  std::atomic<std::uint64_t> peak_live_{0};
  std::atomic<std::uint64_t> peak_cache_{0};
  std::atomic<Engine *> engine_{nullptr};
  std::jthread thread_;
};

double mb(std::uint64_t b) { return static_cast<double>(b) / (1024.0 * 1024.0); }

class Timer {
 public:
  double seconds() const {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - start_).count();
  }

 private:
  std::chrono::steady_clock::time_point start_ = std::chrono::steady_clock::now();
};

void memory_line(const char *phase, PeakSampler &peak, Engine &engine) {
  auto st = proc_status();
  struct mallinfo2 mi = mallinfo2();
  std::printf("  memory after %s:\n    RssAnon %.1f MB, RssFile %.1f MB, VmHWM %.1f MB, peak anon %.1f MB\n"
              "    live heap %.1f MB (memo cache estimate %.1f MB), free heap retained by malloc %.1f MB, peak live heap %.1f MB, peak memo cache %.1f MB\n",
              phase, mb(st["RssAnon"]), mb(st["RssFile"]), mb(st["VmHWM"]), mb(peak.peak_anon()),
              mb(mi.uordblks + mi.hblkhd), mb(engine.resident_bytes()), mb(mi.fordblks),
              mb(peak.peak_live()), mb(peak.peak_cache()));
}

void print_stats(Engine &engine) {
  auto line = [](const char *name, QueryStats s) {
    std::printf("    %-13s executions %9llu  validations %9llu  hits %9llu  loads %9llu  "
                "evictions %9llu\n",
                name, static_cast<unsigned long long>(s.executions),
                static_cast<unsigned long long>(s.validations),
                static_cast<unsigned long long>(s.hits), static_cast<unsigned long long>(s.loads),
                static_cast<unsigned long long>(s.evictions));
  };
  line("decode", engine.stats<toy::DecodeFunction>());
  line("xrefs", engine.stats<toy::FunctionXrefs>());
  line("layout", engine.stats<toy::StructLayout>());
  line("summary", engine.stats<toy::FunctionSummary>());
}

std::unique_ptr<FactDb> open_db(const fs::path &dir, std::size_t budget) {
  FactDbOptions o;
  // Derived facts are recomputable and the benchmark is throwaway, so skip
  // fsync; the log write path is otherwise identical.
  o.storage = open_lmdb_storage(dir, LmdbOptions{std::uint64_t{256} << 30, true});
  o.memo_budget = budget;
  auto db = std::make_unique<FactDb>(std::move(o));
  toy::register_queries(db->engine());
  return db;
}

struct Change {
  const char *what;
  std::function<void(FactDb::Transaction &)> apply;
  Address probe;  // a function whose view a user would be looking at
};

void measure_change(FactDb &db, const toy::Program &prog, ThreadPool &pool, const Change &c) {
  db.engine().reset_stats();
  Timer t_commit;
  {
    auto tx = db.begin();
    c.apply(tx);
    tx.commit();
  }
  double commit_s = t_commit.seconds();
  Timer t_one;
  db.snapshot().get<toy::FunctionSummary>(c.probe);
  double one_s = t_one.seconds();
  Timer t_all;
  db.snapshot().get_all<toy::FunctionSummary>(prog.functions, &pool);
  double all_s = t_all.seconds();
  std::printf("  %s:\n    commit %.3f ms, one affected view %.3f ms, "
              "re-validate all %zu summaries %.3f s\n",
              c.what, commit_s * 1e3, one_s * 1e3, prog.functions.size(), all_s);
  print_stats(db.engine());
}

int run(const Options &opt) {
  fs::path dir = opt.dir.empty()
                     ? fs::temp_directory_path() / ("rk-factbench-" + std::to_string(::getpid()))
                     : fs::path(opt.dir);
  fs::remove_all(dir);
  const std::size_t budget = opt.budget_mb << 20;
  PeakSampler peak;
  ThreadPool pool(opt.threads);

  toy::ProgramSpec spec;
  spec.functions = opt.functions;
  spec.insns_per_function = opt.insns;
  spec.globals = opt.globals;
  spec.structs = opt.structs;
  spec.seed = 42;
  spec.functions_per_commit = 8192;

  std::printf("rk-factbench: %llu functions x ~%u insns, %u threads, memo budget %zu MB, LMDB at %s\n",
              static_cast<unsigned long long>(opt.functions), opt.insns, opt.threads,
              opt.budget_mb, dir.c_str());

  auto db = open_db(dir, budget);
  peak.watch(&db->engine());
  Timer t_load;
  toy::Program prog = toy::generate(*db, spec);
  double load_s = t_load.seconds();
  std::printf("\nload (bytes + %llu import assertions, durable in LMDB): %.2f s\n",
              static_cast<unsigned long long>(prog.assertions), load_s);
  std::printf("  program: %.1f MB of code, %llu instructions, %zu functions\n", mb(prog.text_bytes),
              static_cast<unsigned long long>(prog.instructions), prog.functions.size());
  memory_line("load", peak, db->engine());

  Timer t_analyze;
  db->snapshot().get_all<toy::FunctionSummary>(prog.functions, &pool);
  double analyze_s = t_analyze.seconds();
  Timer t_flush;
  db->engine().flush();
  double flush_s = t_flush.seconds();
  std::printf("\nanalyze (decode, xrefs, summaries for every function): %.2f s, flush %.2f s\n",
              analyze_s, flush_s);
  std::printf("  %.2f M instructions/s\n", static_cast<double>(prog.instructions) / analyze_s / 1e6);
  print_stats(db->engine());
  memory_line("analyze", peak, db->engine());

  // Size of what is on disk, per derived rule.
  std::map<QueryId, std::pair<std::uint64_t, std::uint64_t>> per_rule;  // count, bytes
  db->storage().scan(Table::Derived, "", [&](std::string_view k, std::string_view v) {
    if (k.size() < 4) return true;
    Decoder d(k);
    auto &e = per_rule[d.u32be()];
    e.first += 1;
    e.second += k.size() + v.size();
    return true;
  });
  StorageStats ss = db->storage().stats();
  auto decode_bytes = per_rule[query_id(toy::DecodeFunction::name)].second;
  auto ninsn = static_cast<double>(prog.instructions);
  std::printf("\nstorage (LMDB file %.1f MB):\n", mb(ss.file_bytes));
  const char *tables[] = {"meta", "log", "bytes", "derived"};
  for (int i = 0; i < kTableCount; ++i)
    std::printf("  %-8s %10llu entries %9.1f MB in pages\n", tables[i],
                static_cast<unsigned long long>(ss.entries[i]), mb(ss.bytes[i]));
  for (auto [name, id] : {std::pair{"decode", query_id(toy::DecodeFunction::name)},
                          std::pair{"xrefs", query_id(toy::FunctionXrefs::name)},
                          std::pair{"summary", query_id(toy::FunctionSummary::name)}})
    std::printf("  derived %-8s %9llu records %9.1f MB encoded\n", name,
                static_cast<unsigned long long>(per_rule[id].first), mb(per_rule[id].second));
  std::uint64_t derived_encoded = 0;
  for (const auto &[id, e] : per_rule) derived_encoded += e.second;
  double page_factor = derived_encoded ? static_cast<double>(ss.bytes[3]) / derived_encoded : 1.0;
  std::printf("  bytes per instruction fact:\n"
              "    %.2f encoded (decode records incl. key and deps)\n"
              "    %.2f on disk (x%.2f LMDB page overhead measured over all derived records)\n"
              "    %zu in memory when resident (sizeof(Insn))\n"
              "    %.2f whole database / instructions (log, bytes, decode, xrefs, summaries)\n",
              static_cast<double>(decode_bytes) / ninsn,
              static_cast<double>(decode_bytes) / ninsn * page_factor, page_factor,
              sizeof(toy::Insn), static_cast<double>(ss.file_bytes) / ninsn);

  std::printf("\nincremental (single assertion, then every summary re-read):\n");
  std::uint32_t target_struct = 7;
  Address struct_user = prog.functions.front();
  {
    auto snap = db->snapshot();
    for (Address f : prog.functions) {
      bool found = false;
      for (const auto &x : *snap.get<toy::FunctionXrefs>(f))
        if (x.kind == toy::XrefKind::Field &&
            prog.global_struct[(x.to.offset - spec.data_base) / 16] == target_struct)
          found = true;
      if (found) {
        struct_user = f;
        break;
      }
    }
  }
  const Provenance user = Provenance::user("bench");
  measure_change(*db, prog, pool,
                 {"retype struct S7 (field offsets move)",
                  [&](FactDb::Transaction &tx) {
                    tx.assert_fact(user, FactKey::type_def(toy::struct_name(target_struct)),
                                   "f0:long;f1:char;f2:ptr;f3:int;f4:int;f5:short;f6:int");
                  },
                  struct_user});
  measure_change(*db, prog, pool,
                 {"rename one function",
                  [&](FactDb::Transaction &tx) {
                    tx.assert_fact(user, FactKey::name(prog.functions[1234 % prog.functions.size()]),
                                   "renamed_by_bench");
                  },
                  prog.functions[1234 % prog.functions.size()]});
  measure_change(*db, prog, pool, {"no-op re-read (nothing changed)", [](FactDb::Transaction &) {}, struct_user});
  memory_line("incremental", peak, db->engine());

  db->engine().flush();
  peak.watch(nullptr);
  db.reset();
  Timer t_open;
  db = open_db(dir, budget);
  peak.watch(&db->engine());
  double open_s = t_open.seconds();
  db->engine().reset_stats();
  Timer t_warm;
  db->snapshot().get_all<toy::FunctionSummary>(prog.functions, &pool);
  double warm_s = t_warm.seconds();
  std::printf("\nreopen: open (replay log, load bytes) %.2f s, re-validate every summary from disk %.2f s\n",
              open_s, warm_s);
  print_stats(db->engine());
  memory_line("reopen", peak, db->engine());

  std::uint64_t peak_anon = peak.peak_anon();
  std::uint64_t hwm = proc_status()["VmHWM"];
  const std::uint64_t gate = std::uint64_t{4} << 30;
  bool big_enough = prog.text_bytes >= 100'000'000;
  std::printf("\ngate: %.1f MB binary, %.2f M instruction facts within 4096 MB\n", mb(prog.text_bytes),
              ninsn / 1e6);
  std::printf("  peak anonymous RSS %.1f MB, peak total RSS (incl. LMDB page cache mappings) %.1f MB\n",
              mb(peak_anon), mb(hwm));
  if (!big_enough)
    std::printf("  NOTE: program is below 100 MB; the gate result is only indicative\n");
  if (hwm <= gate)
    std::printf("  GATE MET: %.1f MB of headroom on total RSS\n", mb(gate - hwm));
  else if (peak_anon <= gate)
    std::printf("  GATE MET on anonymous memory (%.1f MB headroom); total RSS exceeds by %.1f MB "
                "of reclaimable LMDB pages\n", mb(gate - peak_anon), mb(hwm - gate));
  else
    std::printf("  GATE MISSED by %.1f MB (anonymous)\n", mb(peak_anon - gate));

  peak.watch(nullptr);
  db.reset();
  if (!opt.keep) fs::remove_all(dir);
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  auto opt = parse_args(argc, argv);
  if (!opt) {
    usage(std::cerr);
    return 2;
  }
  try {
    return run(*opt);
  } catch (const std::exception &e) {
    std::cerr << "rk-factbench: " << e.what() << "\n";
    return 1;
  }
}
