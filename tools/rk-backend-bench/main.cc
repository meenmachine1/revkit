// rk-backend-bench: latency of the image backend's listing and decompile
// paths on one binary, through the same api::Backend calls rk-daemon serves.
//
//   rk-backend-bench <elf|pe> [--ghidra dir] [--threads n] [--max-functions n] [--no-debug-info]
//                    [--analysis-threads n] [--project-dir dir]   (projects in LMDB; also times a reopen)
//                    [--cold-start [name]] (only: import, first listing page, first decompile of
//                                           `name`, else main, else the entry point's function)
//                    [--edit-functions]    (with --cold-start: then remove a function and decompile
//                                           the same one again)
//                    [--param-id auto|on|off] [--decompilers n]
//                                          (with --cold-start: then wait for Ghidra's Decompiler
//                                           Parameter ID to finish in the background, and decompile
//                                           the same function again)
//                    [--infer-prototypes auto|on|off]  (revkit::infer in the background after
//                                           import; default auto, as rk-daemon)

#include "revkit/backend/image_backend.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <sys/resource.h>

namespace {

namespace pb = ::revkit::v1;
using Clock = std::chrono::steady_clock;

double Ms(Clock::time_point since) { return std::chrono::duration<double, std::milli>(Clock::now() - since).count(); }

// The process's CPU time so far (every thread; not the decompiler workers'),
// which a busy machine inflates far less than wall time.
double CpuMs() {
  rusage u{};
  getrusage(RUSAGE_SELF, &u);
  auto ms = [](const timeval &t) { return static_cast<double>(t.tv_sec) * 1e3 + static_cast<double>(t.tv_usec) / 1e3; };
  return ms(u.ru_utime) + ms(u.ru_stime);
}

struct Stats {
  std::vector<double> ms;
  double pct(double p) {
    if (ms.empty()) return 0;
    std::sort(ms.begin(), ms.end());
    return ms[std::min(ms.size() - 1, static_cast<std::size_t>(p * static_cast<double>(ms.size())))];
  }
  double total() const {
    double t = 0;
    for (double m : ms) t += m;
    return t;
  }
};

void Row(const std::string &what, Stats s) {
  std::cout << "| " << std::left << std::setw(46) << what << " | " << std::right << std::setw(6) << s.ms.size()
            << " | " << std::fixed << std::setprecision(2) << std::setw(8) << s.pct(0.5) << " | " << std::setw(8)
            << s.pct(0.95) << " | " << std::setw(8) << s.pct(1.0) << " |\n";
}

void Check(const revkit::api::Status &st, const char *what) {
  if (!st.ok()) {
    std::cerr << "rk-backend-bench: " << what << ": " << st.message << "\n";
    std::exit(1);
  }
}

struct Loaded {
  std::unique_ptr<revkit::api::Backend> backend;
  std::string id;
  double import_ms = 0;
};

bool g_dwarf = true;
std::string g_project_dir;  // empty: in memory
unsigned g_analysis_threads = 0;  // 0: the backend's default
revkit::inputs::ParamIdMode g_param_id = revkit::inputs::ParamIdMode::automatic;
unsigned g_decompilers = 2;
revkit::backend::InferMode g_infer = revkit::backend::InferMode::automatic;

Loaded Load(const std::string &ghidra, const std::string &file, unsigned decompilers) {
  revkit::backend::ImageBackendOptions o;
  o.ghidra_root = ghidra;
  o.import_debug_info = g_dwarf;
  if (!g_project_dir.empty()) {
    // Each backend gets its own directory, so the runs below don't reopen
    // one another's projects.
    static int n = 0;
    o.project_dir = g_project_dir + "/" + std::to_string(n++);
    std::filesystem::remove_all(o.project_dir);
  }
  o.decompilers_per_program = decompilers;
  o.decompile_workers = decompilers;
  o.analysis_threads = g_analysis_threads;
  o.param_id = g_param_id;
  o.infer_prototypes = g_infer;
  Loaded l;
  l.backend = revkit::backend::MakeImageBackend(o);
  revkit::api::CallContext ctx;
  pb::ImportProgramRequest req;
  req.set_project_id("default");
  req.set_path(file);
  pb::ImportProgramResponse resp;
  auto t = Clock::now();
  Check(l.backend->ImportProgram(ctx, req, resp), "import");
  l.import_ms = Ms(t);
  l.id = resp.program().program_id();
  return l;
}

}  // namespace

int main(int argc, char **argv) {
  std::string file, ghidra = std::getenv("GHIDRA_INSTALL_DIR") ? std::getenv("GHIDRA_INSTALL_DIR") : REVKIT_DEFAULT_GHIDRA_ROOT;
  unsigned threads = std::max(2u, std::min(8u, std::thread::hardware_concurrency()));
  std::size_t max_functions = SIZE_MAX;
  bool cold_start = false;
  bool edit_functions = false;
  std::string cold_name = "main";
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--ghidra" && i + 1 < argc) ghidra = argv[++i];
    else if (a == "--threads" && i + 1 < argc) threads = static_cast<unsigned>(std::stoul(argv[++i]));
    else if (a == "--max-functions" && i + 1 < argc) max_functions = std::stoul(argv[++i]);
    else if (a == "--no-debug-info") g_dwarf = false;
    else if (a == "--analysis-threads" && i + 1 < argc) g_analysis_threads = static_cast<unsigned>(std::stoul(argv[++i]));
    else if (a == "--cold-start") {
      cold_start = true;
      if (i + 1 < argc && argv[i + 1][0] != '-' && !file.empty()) cold_name = argv[++i];
    }
    else if (a == "--project-dir" && i + 1 < argc) g_project_dir = argv[++i];
    else if (a == "--edit-functions") edit_functions = true;
    else if (a == "--decompilers" && i + 1 < argc) g_decompilers = static_cast<unsigned>(std::stoul(argv[++i]));
    else if (a == "--param-id" && i + 1 < argc) {
      auto m = revkit::inputs::parse_param_id_mode(argv[++i]);
      if (!m) {
        std::cerr << "rk-backend-bench: --param-id takes auto, on or off\n";
        return 2;
      }
      g_param_id = *m;
    }
    else if (a == "--infer-prototypes" && i + 1 < argc) {
      const std::string m = argv[++i];
      if (m == "auto") g_infer = revkit::backend::InferMode::automatic;
      else if (m == "on") g_infer = revkit::backend::InferMode::on;
      else if (m == "off") g_infer = revkit::backend::InferMode::off;
      else {
        std::cerr << "rk-backend-bench: --infer-prototypes takes auto, on or off\n";
        return 2;
      }
    }
    else if (file.empty() && a[0] != '-') file = a;
    else {
      std::cerr << "usage: rk-backend-bench <elf|pe> [--ghidra dir] [--threads n] [--max-functions n] [--no-debug-info] [--analysis-threads n] [--project-dir dir] [--cold-start [name]]\n";
      return 2;
    }
  }
  if (file.empty()) {
    std::cerr << "usage: rk-backend-bench <elf|pe> [--ghidra dir] [--threads n] [--max-functions n] [--no-debug-info] [--analysis-threads n] [--project-dir dir] [--cold-start [name]]\n";
    return 2;
  }

  const auto process_start = Clock::now();
  Loaded l = Load(ghidra, file, g_decompilers);
  revkit::api::CallContext ctx;
  auto &b = *l.backend;

  if (cold_start) {
    // What a user waits for after opening a binary: the import, the first
    // listing page, then one decompiled function.
    pb::GetListingRequest req;
    req.set_program_id(l.id);
    req.mutable_rows()->set_first_row(0);
    req.mutable_rows()->set_row_count(100);
    pb::GetListingResponse resp;
    auto t = Clock::now();
    Check(b.GetListing(ctx, req, resp), "listing");
    const double listing_ms = Ms(t);
    std::optional<std::uint64_t> target;
    std::string target_name;
    pb::ListFunctionsRequest fr;
    fr.set_program_id(l.id);
    fr.set_name_contains(cold_name);
    fr.mutable_page()->set_page_size(100);
    pb::ListFunctionsResponse fresp;
    t = Clock::now();
    Check(b.ListFunctions(ctx, fr, fresp), "functions");
    const double find_ms = Ms(t);
    for (const auto &f : fresp.functions())
      if (f.name() == cold_name) target = f.entry().offset(), target_name = f.name();
    if (!target) {
      pb::GetProgramSummaryRequest sr;
      sr.set_program_id(l.id);
      pb::GetProgramSummaryResponse sresp;
      Check(b.GetProgramSummary(ctx, sr, sresp), "summary");
      for (const auto &e : sresp.summary().entry_points()) {
        pb::GetFunctionRequest gr;
        gr.set_program_id(l.id);
        gr.mutable_address()->set_offset(e.address().offset());
        gr.set_containing(true);
        pb::GetFunctionResponse gresp;
        if (b.GetFunction(ctx, gr, gresp).ok()) {
          target = gresp.function().entry().offset(), target_name = gresp.function().name();
          break;
        }
      }
    }
    if (!target) {
      // As scripts/bench-coldstart.py: else the first function.
      pb::ListFunctionsRequest first;
      first.set_program_id(l.id);
      first.mutable_page()->set_page_size(1);
      pb::ListFunctionsResponse r;
      Check(b.ListFunctions(ctx, first, r), "functions");
      if (r.functions_size() > 0) target = r.functions(0).entry().offset(), target_name = r.functions(0).name();
    }
    double decompile_ms = 0;
    if (target) {
      pb::DecompileRequest dr;
      dr.set_program_id(l.id);
      dr.mutable_function()->set_offset(*target);
      pb::DecompileResponse dresp;
      t = Clock::now();
      Check(b.Decompile(ctx, dr, dresp), "decompile");
      decompile_ms = Ms(t);
    }
    std::cout << std::fixed << std::setprecision(1) << "import " << l.import_ms << " ms, first listing page "
              << listing_ms << " ms, find " << find_ms << " ms, decompile " << target_name << " " << decompile_ms
              << " ms; " << Ms(process_start) << " ms in all, " << CpuMs() << " ms CPU\n";
    {
      // Ghidra's Decompiler Parameter ID, in the background since the import.
      pb::GetAnalysisStatusRequest sr;
      sr.set_program_id(l.id);
      // Inference (minutes on cmake) isn't waited for: stopped once seen.
      std::set<std::string> cancelled;
      for (;;) {
        pb::GetAnalysisStatusResponse st;
        Check(b.GetAnalysisStatus(ctx, sr, st), "analysis status");
        for (const auto &job : st.jobs())
          if (job.state() == pb::ANALYSIS_STATE_RUNNING && !job.analyzers().empty() &&
              job.analyzers(0) == "infer.prototypes" && cancelled.insert(job.job_id()).second) {
            pb::CancelAnalysisRequest cr;
            cr.set_job_id(job.job_id());
            pb::CancelAnalysisResponse cresp;
            Check(b.CancelAnalysis(ctx, cr, cresp), "cancel inference");
          }
        if (st.idle()) {
          for (const auto &job : st.jobs())
            for (const auto &a : job.analyzers())
              if (a == "decompiler_parameter_id") {
                const double ran =
                    static_cast<double>((job.finished_at().seconds() - job.started_at().seconds()) * 1000) +
                    static_cast<double>(job.finished_at().nanos() - job.started_at().nanos()) / 1e6;
                std::cout << "parameter ID: " << job.phase() << " after " << Ms(process_start) << " ms in all ("
                          << ran << " ms in the background), revisions " << job.first_revision() << ".."
                          << job.last_revision() << "\n";
              }
          break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
      if (target && g_param_id != revkit::inputs::ParamIdMode::off) {
        pb::DecompileRequest dr;
        dr.set_program_id(l.id);
        dr.mutable_function()->set_offset(*target);
        pb::DecompileResponse dresp;
        t = Clock::now();
        Check(b.Decompile(ctx, dr, dresp), "decompile");
        std::cout << "decompile " << target_name << " again: " << Ms(t) << " ms\n";
      }
    }
    if (edit_functions && target) {
      // A change to the function list: remove the last function, then
      // decompile the same function again (discovery, the decompiler's
      // inputs and every lookup the decompilation made revalidate).
      pb::ListFunctionsRequest all;
      all.set_program_id(l.id);
      all.mutable_page()->set_page_size(5000);
      std::uint64_t last = 0;
      for (;;) {
        pb::ListFunctionsResponse r;
        Check(b.ListFunctions(ctx, all, r), "functions");
        for (const auto &f : r.functions())
          if (f.entry().offset() != *target) last = f.entry().offset();
        if (r.page().next_page_token().empty()) break;
        all.mutable_page()->set_page_token(r.page().next_page_token());
      }
      pb::AppendAssertionsRequest ar;
      ar.set_program_id(l.id);
      ar.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
      ar.mutable_provenance()->set_id("bench");
      auto *bounds = ar.add_assertions()->mutable_body()->mutable_function_bounds();
      bounds->mutable_entry()->set_offset(last);
      bounds->set_remove(true);
      pb::AppendAssertionsResponse aresp;
      t = Clock::now();
      Check(b.AppendAssertions(ctx, ar, aresp), "assert");
      const double commit_ms = Ms(t);
      pb::DecompileRequest dr;
      dr.set_program_id(l.id);
      dr.mutable_function()->set_offset(*target);
      pb::DecompileResponse dresp;
      t = Clock::now();
      Check(b.Decompile(ctx, dr, dresp), "decompile");
      std::cout << "remove function 0x" << std::hex << last << std::dec << ": commit " << commit_ms
                << " ms, decompile " << target_name << " again " << Ms(t) << " ms\n";
    }
    return 0;
  }

  pb::GetListingRequest lr;
  lr.set_program_id(l.id);
  lr.mutable_rows()->set_first_row(0);
  lr.mutable_rows()->set_row_count(1);
  pb::GetListingResponse lresp;
  Check(b.GetListing(ctx, lr, lresp), "listing");
  const std::int64_t total = lresp.total_rows();

  pb::ListFunctionsRequest fr;
  fr.set_program_id(l.id);
  fr.mutable_page()->set_page_size(5000);
  std::vector<std::uint64_t> functions;
  for (;;) {
    pb::ListFunctionsResponse resp;
    Check(b.ListFunctions(ctx, fr, resp), "functions");
    for (const auto &f : resp.functions()) functions.push_back(f.entry().offset());
    if (resp.page().next_page_token().empty()) break;
    fr.mutable_page()->set_page_token(resp.page().next_page_token());
  }
  if (functions.size() > max_functions) functions.resize(max_functions);

  std::cout << "file: " << file << "\nimport: " << std::fixed << std::setprecision(1) << l.import_ms << " ms, "
            << total << " listing rows, " << functions.size() << " functions\n\n";
  std::cout << "| operation                                      |      n |  p50 ms  |  p95 ms  |  max ms  |\n"
               "| ---------------------------------------------- | ------ | -------- | -------- | -------- |\n";

  // Listing: scroll the whole program in 100-row windows, as a virtual
  // list does; the first pass builds every page, the second hits the cache.
  for (const char *pass : {"listing 100 rows, scroll (cold pages)", "listing 100 rows, scroll (warm)"}) {
    Stats s;
    for (std::int64_t row = 0; row < total; row += 100) {
      pb::GetListingRequest req;
      req.set_program_id(l.id);
      req.mutable_rows()->set_first_row(row);
      req.mutable_rows()->set_row_count(100);
      pb::GetListingResponse resp;
      auto t = Clock::now();
      Check(b.GetListing(ctx, req, resp), "listing");
      s.ms.push_back(Ms(t));
    }
    Row(pass, s);
  }
  {
    // Jumps to random function entries, centred (a fresh backend: cold).
    Loaded fresh = Load(ghidra, file, 2);
    std::mt19937 rng(1);
    Stats cold;
    for (int i = 0; i < 500; ++i) {
      pb::GetListingRequest req;
      req.set_program_id(fresh.id);
      req.mutable_addresses()->mutable_start()->set_offset(functions[rng() % functions.size()]);
      req.mutable_addresses()->set_rows_before(50);
      req.mutable_addresses()->set_max_rows(100);
      pb::GetListingResponse resp;
      auto t = Clock::now();
      Check(fresh.backend->GetListing(ctx, req, resp), "listing");
      cold.ms.push_back(Ms(t));
    }
    Row("listing 100 rows, jump to function (mixed)", cold);
  }

  // Decompile every function once (cold), then again (cache).
  Stats cold, warm;
  std::size_t failed = 0;
  for (std::uint64_t entry : functions) {
    pb::DecompileRequest req;
    req.set_program_id(l.id);
    req.mutable_function()->set_offset(entry);
    pb::DecompileResponse resp;
    auto t = Clock::now();
    Check(b.Decompile(ctx, req, resp), "decompile");
    cold.ms.push_back(Ms(t));
    for (const auto &w : resp.function().warnings())
      if (w.starts_with("decompilation failed") && ++failed <= 5)
        std::cerr << "rk-backend-bench: " << resp.function().name() << ": " << w << "\n";
  }
  for (std::uint64_t entry : functions) {
    pb::DecompileRequest req;
    req.set_program_id(l.id);
    req.mutable_function()->set_offset(entry);
    pb::DecompileResponse resp;
    auto t = Clock::now();
    Check(b.Decompile(ctx, req, resp), "decompile");
    warm.ms.push_back(Ms(t));
  }
  const double cold_total = cold.total();
  Row("decompile, every function (cold)", cold);
  Row("decompile, every function (cached)", warm);

  // A rename of the most-called function, then its callers re-decompiled.
  {
    pb::GetXrefsRequest xr;
    xr.set_program_id(l.id);
    std::uint64_t best = functions.front();
    std::vector<std::uint64_t> callers;
    for (std::uint64_t entry : functions) {
      xr.mutable_address()->set_offset(entry);
      xr.mutable_page()->set_page_size(5000);
      pb::GetXrefsResponse resp;
      Check(b.GetXrefs(ctx, xr, resp), "xrefs");
      std::vector<std::uint64_t> c;
      for (const auto &x : resp.xrefs())
        if (x.kind() == pb::XREF_KIND_CALL && x.has_from_function()) c.push_back(x.from_function().offset());
      std::sort(c.begin(), c.end());
      c.erase(std::unique(c.begin(), c.end()), c.end());
      if (c.size() > callers.size()) {
        callers = c;
        best = entry;
      }
    }
    pb::AppendAssertionsRequest ar;
    ar.set_program_id(l.id);
    ar.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    ar.mutable_provenance()->set_id("bench");
    auto *rn = ar.add_assertions()->mutable_body()->mutable_rename();
    rn->mutable_target()->mutable_address()->set_offset(best);
    rn->set_name("renamed_by_bench");
    pb::AppendAssertionsResponse aresp;
    auto t = Clock::now();
    Check(b.AppendAssertions(ctx, ar, aresp), "rename");
    Stats commit;
    commit.ms.push_back(Ms(t));
    Row("rename (commit + invalidation)", commit);
    Stats again;
    for (std::uint64_t entry : callers) {
      pb::DecompileRequest req;
      req.set_program_id(l.id);
      req.mutable_function()->set_offset(entry);
      pb::DecompileResponse resp;
      auto t2 = Clock::now();
      Check(b.Decompile(ctx, req, resp), "decompile");
      again.ms.push_back(Ms(t2));
    }
    Row("decompile callers after rename (" + std::to_string(callers.size()) + ")", again);
  }

  // Reopen: a new backend on the same project directory, reading the
  // assertions and the cached derived facts back.
  if (!g_project_dir.empty()) {
    const std::string dir = g_project_dir + "/0";
    l.backend.reset();
    auto t0 = Clock::now();
    revkit::backend::ImageBackendOptions o;
    o.ghidra_root = ghidra;
    o.project_dir = dir;
    auto reopened = revkit::backend::MakeImageBackend(o);
    const double open_ms = Ms(t0);
    pb::GetListingRequest req;
    req.set_program_id(l.id);
    req.mutable_rows()->set_row_count(100);
    pb::GetListingResponse resp;
    t0 = Clock::now();
    Check(reopened->GetListing(ctx, req, resp), "listing");
    const double first_listing_ms = Ms(t0);
    Stats cached;
    for (std::uint64_t entry : functions) {
      pb::DecompileRequest dr;
      dr.set_program_id(l.id);
      dr.mutable_function()->set_offset(entry);
      pb::DecompileResponse dresp;
      auto t2 = Clock::now();
      Check(reopened->Decompile(ctx, dr, dresp), "decompile");
      cached.ms.push_back(Ms(t2));
    }
    auto c = revkit::backend::QueryCounters(*reopened, "default");
    std::uintmax_t bytes = 0;
    for (const auto &e : std::filesystem::recursive_directory_iterator(dir))
      if (e.is_regular_file()) bytes += e.file_size();
    std::cout << "\nreopen: " << std::setprecision(1) << open_ms << " ms to open, first listing " << first_listing_ms
              << " ms; project directory " << bytes / 1024 << " KiB\n";
    Row("decompile after reopen (from disk)", cached);
    std::cout << "recomputed after reopen: decompile.ghidra " << c["decompile.ghidra"].executions << ", analysis.functions "
              << c["analysis.functions"].executions << "; loaded: decompile.ghidra " << c["decompile.ghidra"].loads << "\n";
  }

  // Throughput with several decompiler instances (fresh caches).
  Loaded par = Load(ghidra, file, threads);
  std::atomic<std::size_t> next = 0;
  auto t = Clock::now();
  std::vector<std::thread> pool;
  for (unsigned i = 0; i < threads; ++i)
    pool.emplace_back([&] {
      revkit::api::CallContext c;
      for (std::size_t k; (k = next++) < functions.size();) {
        pb::DecompileRequest req;
        req.set_program_id(par.id);
        req.mutable_function()->set_offset(functions[k]);
        pb::DecompileResponse resp;
        Check(par.backend->Decompile(c, req, resp), "decompile");
      }
    });
  for (auto &th : pool) th.join();
  const double par_ms = Ms(t);
  std::cout << "\ndecompile all " << functions.size() << " functions: " << std::setprecision(0) << cold_total
            << " ms on 1 thread, " << par_ms << " ms on " << threads << " threads (" << std::setprecision(1)
            << cold_total / par_ms << "x); " << failed << " failed\n";
  return 0;
}
