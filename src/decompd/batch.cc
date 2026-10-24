#include "revkit/decompd/batch.h"

#include "revkit/decompd/lift_mode.h"
#include "revkit/lift/context.hh"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <unordered_map>

#include <malloc.h>
#include <unistd.h>

namespace revkit::decompd {

namespace {

using Clock = std::chrono::steady_clock;

double ms_since(Clock::time_point t) { return std::chrono::duration<double, std::milli>(Clock::now() - t).count(); }

std::size_t resident_bytes() {
  std::ifstream statm("/proc/self/statm");
  std::size_t pages = 0, resident = 0;
  statm >> pages >> resident;
  return resident * static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
}

// As lift::decompile_functions estimates a run's peak (decompile.cc):
// varnodes per byte of code at kBytesPerVarnode each, at least kMinRun.
constexpr std::size_t kBytesPerVarnode = 1024;
constexpr std::size_t kVarnodesPerByte = 24;
constexpr std::size_t kMinRun = std::size_t{4} << 20;
// What an idle worker holds besides a run (its architecture, SLEIGH
// tables): counted in the baseline for each worker.
constexpr std::size_t kWorkerBase = std::size_t{96} << 20;

std::size_t estimate(std::uint64_t body_bytes) {
  const std::uint64_t per_byte = std::min<std::uint64_t>(kVarnodesPerByte, 2 + body_bytes / 1024);
  return std::max<std::size_t>(kMinRun, static_cast<std::size_t>(body_bytes * per_byte) * kBytesPerVarnode);
}

// lift::decompile_functions' scheduler: largest first while the estimates
// of those running fit in the budget beside the baseline; the smallest
// fill in; measured memory (the parent's and its workers') over the
// budget admits only tiny functions.
class Scheduler {
 public:
  Scheduler(std::vector<std::size_t> order, std::vector<std::size_t> cost, std::size_t budget)
      : order_(std::move(order)), cost_(std::move(cost)), budget_(budget), back_(order_.size()) {}

  void set_baseline(std::size_t bytes) {
    std::lock_guard lock(mu_);
    baseline_ = bytes;
  }
  void cap(std::size_t bytes) {
    std::lock_guard lock(mu_);
    for (std::size_t &c : cost_) c = std::min(c, bytes);
  }
  std::size_t peak() const { return peak_.load(); }

  std::optional<std::size_t> take() {
    std::unique_lock lock(mu_);
    for (;;) {
      if (front_ >= back_) return std::nullopt;
      if (solo_ > 0) {  // a function evicted for memory runs alone first
        cv_.wait(lock);
        continue;
      }
      if (budget_ == 0) return start(order_[front_++]);
      const std::size_t room = budget_ > baseline_ + reserved_ ? budget_ - baseline_ - reserved_ : 0;
      if (running_ == 0) return start(order_[front_++]);
      if (!over_ && cost_[order_[front_]] <= room) return start(order_[front_++]);
      if (cost_[order_[back_ - 1]] <= (over_ ? kMinRun : room)) return start(order_[--back_]);
      cv_.wait(lock);
    }
  }

  // Run `k`, which was evicted from a worker to stay within the budget,
  // with nothing else running (it was started, and done() follows).
  template <class F>
  void alone(std::size_t k, F &&run) {
    std::lock_guard one(alone_mu_);
    {
      std::unique_lock lock(mu_);
      reserved_ -= cost_[k];
      --running_;
      ++solo_;
      cv_.notify_all();
      cv_.wait(lock, [&] { return running_ == 0; });
      ++running_;
      reserved_ += cost_[k];
    }
    run();
    std::lock_guard lock(mu_);
    --solo_;
    cv_.notify_all();
  }
  void set_over(bool over) {
    std::lock_guard lock(mu_);
    if (budget_ != 0) over_ = over_ || over;
  }

  // `measured`: the parent's resident memory plus the workers'.
  void done(std::size_t k, std::size_t measured) {
    peak_.store(std::max(peak_.load(), measured));
    std::lock_guard lock(mu_);
    reserved_ -= cost_[k];
    --running_;
    if (budget_ != 0) over_ = measured > budget_;
    cv_.notify_all();
  }

 private:
  std::size_t start(std::size_t k) {
    reserved_ += cost_[k];
    ++running_;
    return k;
  }
  std::vector<std::size_t> order_, cost_;
  const std::size_t budget_;
  std::size_t front_ = 0, back_;
  std::size_t baseline_ = 0, reserved_ = 0, running_ = 0, solo_ = 0;
  bool over_ = false;
  std::mutex alone_mu_;
  std::atomic<std::size_t> peak_{0};
  std::mutex mu_;
  std::condition_variable cv_;
};


}  // namespace

BundledRun run_bundled(WorkerPool &pool, BundleSource &source, const Limits &limits, std::uint64_t function,
                       unsigned max_runs, const std::function<bool()> &cancelled) {
  BundledRun out;
  for (;;) {
    Bundle b = source.bundle();
    out.bundle = encode_bundle(b);
    out.hash = bundle_hash(out.bundle);
    out.arch_key = b.arch_key();
    out.outcome = pool.run(out.bundle, limits, out.arch_key, cancelled);
    ++out.runs;
    if (out.outcome.cancelled || out.outcome.evicted) return out;
    out.failure = failure_of(out.outcome, function, out.hash, limits);
    if (out.failure || !out.outcome.result || !out.outcome.result->ran || out.outcome.result->misses.empty()) return out;
    out.misses += out.outcome.result->misses.size();
    for (const Miss &m : out.outcome.result->misses) ++out.miss_kinds[m.kind];
    static const bool trace = std::getenv("REVKIT_DECOMPD_TRACE_MISSES") != nullptr;
    if (trace)
      for (const Miss &m : out.outcome.result->misses)
        std::fprintf(stderr, "miss %llx kind %d %s %llx\n", static_cast<unsigned long long>(function), m.kind,
                     m.space.c_str(), static_cast<unsigned long long>(m.value));
    if (!source.fill(out.outcome.result->misses)) {
      // Every missed answer was what the worker assumed: the run is the
      // run of the bundle with them added.
      Bundle complete = source.bundle();
      out.bundle = encode_bundle(complete);
      out.hash = bundle_hash(out.bundle);
      out.outcome.result->misses.clear();
      return out;
    }
    if (out.runs >= max_runs) {
      out.unresolved = true;
      return out;
    }
  }
}

std::vector<lift::BlockFacts> lookup_blocks(const lift::DecompilerInputs &inputs, const loader::Image &image) {
  if (!inputs.memory.empty()) return inputs.memory;
  std::vector<lift::BlockFacts> out;
  for (const loader::Block &b : image.blocks) {
    lift::BlockFacts f;
    f.name = b.name;
    f.start = b.start;
    f.end = b.start + (b.size - 1);
    f.write = b.perms.write;
    f.execute = b.perms.exec;
    f.initialized = b.initialized;
    f.is_volatile = b.is_volatile;
    out.push_back(std::move(f));
  }
  return out;
}

std::vector<std::string> input_spaces(const lift::DecompilerInputs &in) {
  std::set<std::string> s{std::string()};
  for (const lift::DataFacts &d : in.data) s.insert(d.space);
  for (const lift::ExternalRefFacts &x : in.external_refs) s.insert(x.space);
  for (const lift::LabelFacts &l : in.labels) s.insert(l.space);
  for (const lift::LabelFacts &l : in.code_labels) s.insert(l.space);
  for (const lift::BlockFacts &b : in.memory) s.insert(b.space);
  return {s.begin(), s.end()};
}

std::string describe(const Failure &f) {
  std::string what;
  switch (f.kind) {
    case FailureKind::timeout: what = "decompiler timed out"; break;
    case FailureKind::oom: what = "decompiler ran out of memory"; break;
    default: what = "decompiler crashed"; break;
  }
  return what + " (" + f.detail + ")";
}

std::string failure_summary(const std::vector<Failure> &failures) {
  if (failures.empty()) return "decompiler failures: none\n";
  std::map<FailureKind, std::vector<const Failure *>> by;
  for (const Failure &f : failures) by[f.kind].push_back(&f);
  std::string out = "decompiler failures: " + std::to_string(failures.size()) + " (";
  bool first = true;
  for (const auto &[kind, list] : by) {
    out += (first ? "" : ", ") + std::to_string(list.size()) + " " + failure_kind_name(kind);
    first = false;
  }
  out += ")\n";
  for (const auto &[kind, list] : by)
    for (const Failure *f : list) {
      char buf[64];
      std::snprintf(buf, sizeof buf, "  0x%llx  %-7s ", static_cast<unsigned long long>(f->function),
                    failure_kind_name(kind));
      out += buf + f->detail + "  bundle " + f->bundle_hash + "\n";
    }
  return out;
}

std::vector<lift::DecompileResult> decompile_functions(
    const lift::DecompileConfig &config, const std::vector<std::uint64_t> &entries, BatchStats *stats,
    const std::function<void(std::size_t, lift::DecompileResult &)> &on_result, PoolOptions pool_options) {
  const auto started = Clock::now();
  std::vector<lift::DecompileResult> results(entries.size());
  if (entries.empty()) return results;
  unsigned threads = config.threads != 0 ? config.threads : std::max(1u, std::thread::hardware_concurrency());
  threads = static_cast<unsigned>(std::min<std::size_t>(threads, entries.size()));
  const bool chain = config.in_order && threads == 1;

  auto inputs = config.inputs ? config.inputs : std::make_shared<lift::DecompilerInputs>();
  std::unordered_map<std::uint64_t, const lift::FunctionFacts *> by_entry;
  for (const lift::FunctionFacts &f : inputs->functions) by_entry.emplace(f.entry, &f);
  std::vector<std::size_t> order(entries.size());
  std::vector<std::uint64_t> bytes(entries.size(), 0);
  for (std::size_t i = 0; i < order.size(); ++i) {
    order[i] = i;
    if (auto it = by_entry.find(entries[i]); it != by_entry.end())
      for (const auto &[a, b] : it->second->body) bytes[i] += b - a + 1;
  }
  if (!config.in_order)
    std::stable_sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) { return bytes[a] > bytes[b]; });
  std::vector<std::size_t> cost(entries.size());
  for (std::size_t i = 0; i < entries.size(); ++i) cost[i] = estimate(bytes[i]);
  Scheduler schedule(order, std::move(cost), config.memory_budget);

  const auto setup_started = Clock::now();
  std::shared_ptr<lift::FactLookup> lookup =
      config.lookup ? config.lookup : std::shared_ptr<lift::FactLookup>(lift::lookup_inputs(inputs, config.image.get()));
  lift::ArchitectureOptions::Patches patches = inputs->patches;
  patches.insert(patches.end(), inputs->synthesized_memory.begin(), inputs->synthesized_memory.end());
  const ProgramImage program(config.image, config.language_id, patches);
  patches.clear();
  const std::vector<lift::BlockFacts> blocks = lookup_blocks(*inputs, *config.image);
  const std::vector<std::string> spaces = input_spaces(*inputs);
  // A lookup over fixed inputs answers the same every time: encode each
  // type once for the whole program.
  std::shared_ptr<TypeCache> type_cache = lookup->stable() ? std::make_shared<TypeCache>() : nullptr;
  // Prediction takes a few milliseconds of a run's tens: two engines
  // (35 MB each) keep up with any number of workers.
  LifterPool lifters(config.image, config.language_id, std::min(threads, 2u));

  lift::DecompileLimits limits = config.limits;
  if (config.memory_budget != 0) {
    if (limits.max_varnodes == 0)
      limits.max_varnodes = std::max<std::size_t>(config.memory_budget / 4 / kBytesPerVarnode, 1 << 16);
    schedule.cap(limits.max_varnodes * kBytesPerVarnode);
    // A worker may hold its baseline and one run at the bound, with room
    // for malloc's slack; past a share of the budget it is replaced.
    pool_options.memory_limit = std::max<std::uint64_t>(std::uint64_t{1} << 30, config.memory_budget / 2 + (512u << 20));
    pool_options.recycle_rss =
        std::max<std::uint64_t>(std::uint64_t{192} << 20, config.memory_budget / (2 * std::max(1u, threads)));
  }
  pool_options.workers = threads;
  WorkerPool pool(pool_options);
  if (config.memory_budget != 0) schedule.set_baseline(resident_bytes() + threads * kWorkerBase);
  const double setup_ms = ms_since(setup_started);

  std::mutex mu;
  BatchStats local;
  std::optional<std::vector<lift::JoinFacts>> joins;
  if (chain) joins.emplace();
  std::atomic<std::size_t> peak_workers{0};
  std::atomic<std::size_t> finished{0};
  static const bool trace = std::getenv("REVKIT_DECOMPILE_TRACE") != nullptr;
  const Limits run_limits{limits.timeout_seconds, limits.max_varnodes};

  auto work = [&] {
    while (std::optional<std::size_t> next = schedule.take()) {
      const std::size_t k = *next;
      const std::uint64_t entry = entries[k];
      const auto t0 = Clock::now();
      std::vector<std::pair<std::uint64_t, std::uint64_t>> body;
      LifterPool::Context context;
      if (auto it = by_entry.find(entry); it != by_entry.end()) {
        body = it->second->body;
        context = it->second->context;
      }
      if (body.empty()) body = {{entry, entry}};
      Prediction p;
      {
        LifterPool::Lease l = lifters.take(context);
        p = predict(*l, program, entry, body, blocks, tracked_seeds(*l, lookup->tracked(entry)));
      }
      LiftBundleBuilder builder(program, Mode::c_text, entry, *lookup, blocks, inputs->address_prefix);
      builder.set_naming(config.default_names, config.default_labels, config.default_extrapop);
      builder.set_format_strings(config.format_strings);
      builder.set_shape(config.shape);
      builder.set_spaces(spaces);
      if (type_cache) builder.set_type_cache(type_cache);
      if (chain) builder.set_joins(*joins);
      builder.add(p);
      LiftSource source(builder);
      const double build_ms = ms_since(t0);
      if (trace)
        std::fprintf(stderr, "start %llx %llu bytes\n", static_cast<unsigned long long>(entry),
                     static_cast<unsigned long long>(bytes[k]));
      BundledRun run;
      std::string unavailable;
      try {
        run = run_bundled(pool, source, run_limits, entry, 8);
        if (run.outcome.evicted) {
          // Stopped to keep the batch within its memory budget: the same
          // bundle again, alone (its output doesn't depend on that).
          schedule.alone(k, [&] { run = run_bundled(pool, source, run_limits, entry, 8); });
          std::lock_guard lock(mu);
          ++local.evicted;
        }
      } catch (const std::exception &e) {
        // No worker could be started (or spoken to): this function has no
        // output, and the next tries again.
        unavailable = e.what();
      }
      // Debugging: every function's final bundle, for rk-decompd --bundle.
      static const char *save = std::getenv("REVKIT_DECOMPD_SAVE_BUNDLES");
      if (save != nullptr && *save != 0) {
        char name[64];
        std::snprintf(name, sizeof name, "/0x%llx.bundle", static_cast<unsigned long long>(entry));
        std::ofstream(std::string(save) + name, std::ios::binary) << run.bundle;
      }
      lift::DecompileResult r;
      r.entry = entry;
      if (run.outcome.result && run.outcome.result->ran) {
        try {
          r = decode_result(run.outcome.result->payload);
        } catch (const std::exception &e) {
          r.ok = false;
          r.error = std::string("bad result from the decompiler worker: ") + e.what();
        }
      } else if (run.outcome.result) {
        r.error = "decompiler worker: " + run.outcome.result->error;
      } else if (!unavailable.empty()) {
        r.error = "decompiler worker unavailable: " + unavailable;
      }
      if (run.failure) {
        r.ok = false;
        r.c.clear();
        r.error = describe(*run.failure);
        if (run.failure->kind == FailureKind::timeout) r.stopped = lift::DecompileStop::timeout;
        else if (run.failure->kind == FailureKind::oom) r.stopped = lift::DecompileStop::too_large;
      }
      if (chain) {
        // As one in-process decompiler: a stopped run's instance is
        // replaced (no records); a crash keeps the records as they were.
        if (r.stopped != lift::DecompileStop::none) joins->clear();
        else if (!run.failure && run.outcome.result) joins->insert(joins->end(), run.outcome.result->joins_made.begin(),
                                                                    run.outcome.result->joins_made.end());
      }
      if (trace)
        std::fprintf(stderr, "done %llx %.0f ms %zu varnodes runs %u%s\n", static_cast<unsigned long long>(entry),
                     r.milliseconds, r.varnodes, run.runs, run.failure ? " FAILED" : "");
      {
        std::lock_guard lock(mu);
        ++local.bundles;
        local.reruns += run.runs - 1;
        if (run.misses != 0) ++local.missed;
        local.miss_queries += run.misses;
        for (std::size_t i = 0; i < run.miss_kinds.size(); ++i) local.miss_kinds[i] += run.miss_kinds[i];
        if (run.runs > 1) ++local.miss_changed;
        if (run.unresolved) {
          ++local.unresolved;
          local.unresolved_functions.push_back(entry);
        }
        local.bundle_bytes += run.bundle.size();
        local.build_ms += build_ms;
        if (run.outcome.result) local.run_ms += run.outcome.result->milliseconds;
        if (r.stopped != lift::DecompileStop::none) ++local.stopped;
        if (run.failure) {
          local.failures.push_back(*run.failure);
          local.failed_bundles[run.hash] = run.bundle;
        }
        if (on_result) {
          on_result(k, r);
          std::string().swap(r.c);
        }
        results[k] = std::move(r);
      }
      const std::size_t workers = pool.workers_rss();
      peak_workers.store(std::max(peak_workers.load(), workers));
      // What the parent freed (bundles, answers) back to the system now
      // and then: its arenas otherwise keep their high-water mark.
      if (++finished % 1024 == 0) ::malloc_trim(0);
      schedule.done(k, resident_bytes() + workers);
    }
  };
  // The budget holds for runs in flight too: when the parent and its
  // workers are over it, the largest running decompilation is stopped and
  // run again alone (above).
  std::atomic<bool> working{true};
  std::thread guard;
  std::atomic<std::size_t> peak_total{0};
  if (config.memory_budget != 0 && !pool_options.in_process)
    guard = std::thread([&] {
      while (working.load()) {
        const std::size_t total = resident_bytes() + pool.live_rss();
        peak_total.store(std::max(peak_total.load(), total));
        // At 95%: memory grows between samples.
        if (total > config.memory_budget / 20 * 19) {
          schedule.set_over(true);
          // Give the system a moment to take back what a killed worker held.
          if (pool.evict_largest()) std::this_thread::sleep_for(std::chrono::milliseconds(400));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    });
  std::vector<std::thread> threads_v;
  for (unsigned t = 1; t < threads; ++t) threads_v.emplace_back(work);
  work();
  for (std::thread &t : threads_v) t.join();
  working.store(false);
  if (guard.joinable()) guard.join();
  if (stats) {
    *stats = std::move(local);
    stats->threads = threads;
    stats->setup_seconds = setup_ms / 1000;
    stats->total_seconds = ms_since(started) / 1000;
    stats->peak_rss = schedule.peak();
    stats->max_varnodes = limits.max_varnodes;
    stats->pool = pool.stats();
    stats->ipc_ms = stats->pool.ipc_ms;
    stats->rebuilt = stats->pool.recycled;
    stats->peak_workers_rss = peak_workers.load();
    stats->peak_total_rss = peak_total.load();
    std::sort(stats->failures.begin(), stats->failures.end(),
              [](const Failure &a, const Failure &b) { return a.function < b.function; });
  }
  return results;
}

}  // namespace revkit::decompd
