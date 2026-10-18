// revkit::infer's decompilations in worker processes (decompd mode observe).
//
// Worker side: ObserveSession runs infer::Decompiler over a bundle, its
// SymbolEnv answering from the bundle (BundleEnv). Parent side:
// DecompilerPool::run predicts the lookups from the body, records the
// caller's SymbolEnv answers to them (ObserveSource), and fills what the
// worker missed.

#include "revkit/decompd/batch.h"
#include "revkit/decompd/runner.h"
#include "revkit/infer/decompd_mode.h"
#include "revkit/infer/decompiler.h"
#include "revkit/infer/infer.h"

#include <algorithm>
#include <map>
#include <set>
#include <thread>

namespace revkit::infer {

namespace {

void encode_symbol(facts::Encoder &e, const FunctionSymbol &f) {
  e.bytes(f.name);
  facts::encode(e, f.no_return);
  facts::encode(e, f.proto);
}

FunctionSymbol decode_symbol(facts::Decoder &d) {
  FunctionSymbol f;
  f.name = std::string(d.bytes());
  f.no_return = facts::decode<bool>(d);
  f.proto = facts::decode<std::optional<Prototype>>(d);
  return f;
}

using Answers = std::map<std::uint64_t, std::optional<FunctionSymbol>>;

void encode_answers(facts::Encoder &e, const Answers &a) {
  e.varint(a.size());
  for (const auto &[k, v] : a) {
    e.varint(k);
    e.u8(v ? 1 : 0);
    if (v) encode_symbol(e, *v);
  }
}

Answers decode_answers(facts::Decoder &d) {
  Answers a;
  const std::size_t n = d.count();
  for (std::size_t i = 0; i < n; ++i) {
    const std::uint64_t k = d.varint();
    if (d.u8() != 0) a.emplace(k, decode_symbol(d));
    else a.emplace(k, std::nullopt);
  }
  return a;
}

// What a mode observe bundle holds besides bytes: the SymbolEnv's answers.
struct ObserveFacts {
  bool want_c = false;
  Answers functions;  // SymbolEnv::function
  Answers imports;    // SymbolEnv::import_slot
  std::vector<std::uint64_t> call_returns;  // RunOptions::call_returns

  std::string encode() const {
    facts::Encoder e;
    facts::encode(e, want_c);
    encode_answers(e, functions);
    encode_answers(e, imports);
    facts::encode(e, call_returns);
    return std::move(e).str();
  }
  static ObserveFacts decode(std::string_view bytes) {
    facts::Decoder d(bytes);
    ObserveFacts f;
    f.want_c = facts::decode<bool>(d);
    f.functions = decode_answers(d);
    f.imports = decode_answers(d);
    f.call_returns = facts::decode<std::vector<std::uint64_t>>(d);
    d.expect_done();
    return f;
  }
};

// The worker's SymbolEnv: the bundle's answers; anything else is a miss,
// answered as nothing.
class BundleEnv final : public SymbolEnv {
 public:
  explicit BundleEnv(const ObserveFacts &f) : f_(f) {}
  std::optional<FunctionSymbol> function(std::uint64_t entry) override {
    asked.insert(entry);
    auto it = f_.functions.find(entry);
    if (it != f_.functions.end()) return it->second;
    misses.push_back({decompd::Miss::function, {}, entry});
    return std::nullopt;
  }
  std::optional<FunctionSymbol> import_slot(std::uint64_t slot) override {
    auto it = f_.imports.find(slot);
    if (it != f_.imports.end()) return it->second;
    misses.push_back({decompd::Miss::import, {}, slot});
    return std::nullopt;
  }
  std::set<std::uint64_t> asked;
  std::vector<decompd::Miss> misses;

 private:
  const ObserveFacts &f_;
};

class ObserveSession final : public decompd::Session {
 public:
  explicit ObserveSession(const decompd::Bundle &b)
      : memory_(std::make_shared<decompd::BundleMemory>()),
        dec_(std::make_unique<Decompiler>(decompd::bundle_image(b), b.language_id, nullptr, memory_, b.context)) {}

  void run(const decompd::Bundle &b, const decompd::Limits &limits, decompd::RunResult &out) override {
    const ObserveFacts facts = ObserveFacts::decode(b.extra);
    BundleEnv env(facts);
    memory_->set(&b);
    RunOptions o;
    o.want_c = facts.want_c;
    o.call_returns = facts.call_returns;
    o.max_varnodes = limits.max_varnodes;
    o.timeout_seconds = limits.timeout_seconds;
    o.prologue = false;
    Observation obs = dec_->run(b.entry, env, o);
    out.stopped = dec_->last_stop();
    out.payload = facts::encode_to_string(obs);
    out.misses = std::move(env.misses);
    for (std::uint64_t c : memory_->missed()) out.misses.push_back({decompd::Miss::chunk, {}, c});
    out.asked_functions.assign(env.asked.begin(), env.asked.end());
    memory_->set(nullptr);
  }
  bool spoiled() const override { return dec_->spoiled(); }
  lift::ImageArchitecture &architecture() override { return dec_->architecture(); }

 private:
  std::shared_ptr<decompd::BundleMemory> memory_;
  std::unique_ptr<Decompiler> dec_;
};

// The parent's side: the caller's SymbolEnv answers, recorded as the
// decompiler would ask them (an import slot first, then a function).
class ObserveSource final : public decompd::BundleSource {
 public:
  ObserveSource(const decompd::ProgramImage &program, std::uint64_t entry, SymbolEnv &env, bool want_c,
                std::vector<std::uint64_t> call_returns)
      : program_(program), entry_(entry), env_(env) {
    facts_.want_c = want_c;
    facts_.call_returns = std::move(call_returns);
  }

  void add(const decompd::Prediction &p) {
    import_slot(entry_);
    function(entry_);
    for (const auto &[space, a] : p.addresses) {
      if (!space.empty()) continue;
      // Lookups are cheap where the address is no import slot nor a call
      // target: those are only recorded when the decompiler asks.
      if (import_slot(a)) continue;
      if (p.calls.contains(a)) function(a);
    }
    for (std::uint64_t c : p.chunks) chunks_.emplace(c, program_.chunk(c));
  }

  decompd::Bundle bundle() override {
    decompd::Bundle b = program_.bundle(decompd::Mode::observe, entry_);
    b.chunks = chunks_;
    b.extra = facts_.encode();
    return b;
  }

  bool fill(const std::vector<decompd::Miss> &misses) override {
    bool changed = false;
    for (const decompd::Miss &m : misses) {
      switch (m.kind) {
        case decompd::Miss::function: changed |= function(m.value).has_value(); break;
        case decompd::Miss::import: changed |= import_slot(m.value).has_value(); break;
        case decompd::Miss::chunk:
          if (!chunks_.contains(m.value)) {
            chunks_.emplace(m.value, program_.chunk(m.value));
            changed = true;
          }
          break;
        default: break;
      }
    }
    return changed;
  }

  // Whether the env knows a function at `entry` (what QueryEnv counts as consulted).
  bool known_function(std::uint64_t entry) const {
    auto it = facts_.functions.find(entry);
    return it != facts_.functions.end() && it->second.has_value();
  }

 private:
  const std::optional<FunctionSymbol> &function(std::uint64_t a) {
    auto it = facts_.functions.find(a);
    if (it == facts_.functions.end()) it = facts_.functions.emplace(a, env_.function(a)).first;
    return it->second;
  }
  const std::optional<FunctionSymbol> &import_slot(std::uint64_t a) {
    auto it = facts_.imports.find(a);
    if (it == facts_.imports.end()) it = facts_.imports.emplace(a, env_.import_slot(a)).first;
    return it->second;
  }

  const decompd::ProgramImage &program_;
  std::uint64_t entry_;
  SymbolEnv &env_;
  ObserveFacts facts_;
  std::map<std::uint64_t, std::string> chunks_;
};

std::mutex &workers_mu() {
  static std::mutex m;
  return m;
}
std::shared_ptr<decompd::WorkerPool> &shared_workers() {
  static std::shared_ptr<decompd::WorkerPool> w;
  return w;
}

}  // namespace

void register_decompd_mode() {
  decompd::register_mode(
      decompd::Mode::observe, [](const decompd::Bundle &b) { return std::make_unique<ObserveSession>(b); },
      [](std::string_view payload, bool &ok) {
        Observation o = facts::decode_from_string<Observation>(payload);
        ok = o.ok;
        std::string out = o.ok ? "observed: " + std::to_string(o.params.size()) + " parameters, " +
                                     std::to_string(o.calls.size()) + " calls" + (o.ret ? ", a return value" : "") + "\n"
                               : "observation failed: " + o.error + "\n";
        return out + o.c;
      });
}

void DecompilerPool::set_workers(std::shared_ptr<decompd::WorkerPool> workers) {
  std::lock_guard lock(workers_mu());
  shared_workers() = std::move(workers);
}

std::shared_ptr<decompd::WorkerPool> DecompilerPool::workers() {
  std::lock_guard lock(workers_mu());
  if (!shared_workers()) {
    decompd::PoolOptions o = decompd::default_pool_options();
    o.workers = std::clamp(std::thread::hardware_concurrency(), 2u, 8u);
    shared_workers() = std::make_shared<decompd::WorkerPool>(o);
  }
  return shared_workers();
}

DecompilerPool::DecompilerPool(std::shared_ptr<const loader::Image> image, std::string language_id)
    : image_(std::move(image)), language_id_(std::move(language_id)) {
  if (workers()->options().in_process) register_decompd_mode();
}

DecompilerPool::~DecompilerPool() = default;

DataOrg DecompilerPool::data_org() { return infer::data_org(*image_); }

std::vector<decompd::Failure> DecompilerPool::failures() const {
  std::lock_guard lock(mu_);
  return failures_;
}

void DecompilerPool::trim() {
  std::vector<std::unique_ptr<lift::Lifter>> lifters;
  std::shared_ptr<const decompd::ProgramImage> program;
  std::shared_ptr<Prologues> prologues;
  {
    std::lock_guard lock(mu_);
    lifters.swap(lifters_);
    program.swap(program_);
    prologues.swap(prologues_);
  }
  // Destroyed here, outside the lock; a run holding its own references
  // keeps them alive until it ends.
}

std::size_t DecompilerPool::idle_lifters() const {
  std::lock_guard lock(mu_);
  return lifters_.size();
}

std::shared_ptr<const decompd::ProgramImage> DecompilerPool::program() {
  std::lock_guard lock(mu_);
  // The decompiler reads the image's own bytes here (no relocations laid
  // over them), as infer::Decompiler does.
  if (!program_) program_ = std::make_shared<const decompd::ProgramImage>(image_, language_id_, lift::ArchitectureOptions::Patches{});
  return program_;
}

std::unique_ptr<lift::Lifter> DecompilerPool::take_lifter() {
  {
    std::lock_guard lock(mu_);
    if (!lifters_.empty()) {
      auto l = std::move(lifters_.back());
      lifters_.pop_back();
      return l;
    }
  }
  const std::string language = std::count(language_id_.begin(), language_id_.end(), ':') >= 4
                                   ? language_id_.substr(0, language_id_.rfind(':'))
                                   : language_id_;
  auto l = std::make_unique<lift::Lifter>(image_, language);
  for (const lift::ContextRegion &c : lift::image_context(*image_)) l->set_context(c.name, c.value, c.start, c.end);
  return l;
}

Observation DecompilerPool::run(std::uint64_t entry, SymbolEnv &env, const RunOptions &options) {
  auto program = this->program();
  decompd::Prediction p;
  {
    std::unique_ptr<lift::Lifter> lifter = take_lifter();
    p = decompd::predict(*lifter, *program, entry, options.body);
    std::lock_guard lock(mu_);
    lifters_.push_back(std::move(lifter));
  }
  ObserveSource source(*program, entry, env, options.want_c, options.call_returns);
  source.add(p);
  const decompd::Limits limits{options.timeout_seconds, options.max_varnodes};
  decompd::BundledRun run = decompd::run_bundled(*workers(), source, limits, entry);
  Observation o;
  if (run.outcome.result && run.outcome.result->ran) {
    try {
      o = facts::decode_from_string<Observation>(run.outcome.result->payload);
    } catch (const std::exception &e) {
      o = Observation{};
      o.error = std::string("bad result from the decompiler worker: ") + e.what();
    }
  } else if (run.outcome.result) {
    o.error = "decompiler worker: " + run.outcome.result->error;
  }
  if (run.failure) {
    if (!(run.outcome.result && run.outcome.result->ran)) {
      o = Observation{};
      o.error = decompd::describe(*run.failure);
    }
    std::lock_guard lock(mu_);
    failures_.push_back(*run.failure);
  }
  // What the decompiler consulted: the entries it asked the env about that
  // the env knows (QueryEnv counts those).
  o.consulted.clear();
  if (run.outcome.result)
    for (std::uint64_t e : run.outcome.result->asked_functions)
      if (source.known_function(e)) o.consulted.push_back(e);
  if (o.ok && options.prologue) {
    std::shared_ptr<Prologues> prologues;  // its own reference: trim() may drop the pool's
    {
      std::lock_guard lock(mu_);
      if (!prologues_) {
        const std::string language = std::count(language_id_.begin(), language_id_.end(), ':') >= 4
                                         ? language_id_.substr(0, language_id_.rfind(':'))
                                         : language_id_;
        prologues_ = std::make_shared<Prologues>(image_, language);
      }
      prologues = prologues_;
    }
    prologues->fill(entry, o);
  }
  return o;
}

}  // namespace revkit::infer
