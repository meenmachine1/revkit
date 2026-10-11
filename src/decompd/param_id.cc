#include "revkit/decompd/param_id.h"

#include "revkit/inputs/codec.h"
#include "revkit/lift/context.hh"

#include "error.hh"
#include "funcdata.hh"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>

namespace revkit::decompd {

namespace {

using Clock = std::chrono::steady_clock;

class ParamIdSession final : public LiftSession {
 public:
  explicit ParamIdSession(const Bundle &b) : LiftSession(b) {}

 protected:
  void prepare(const Bundle &b, lift::RunHooks &hooks) override {
    captured_.reset();
    // DecompInterface.toggleCCode(false): nothing is printed; the
    // decompiler's model of the function is read instead.
    hooks.print = [this, entry = b.entry](ghidra::Funcdata &fd) {
      lift::FunctionFacts facts;
      if (const lift::FunctionFacts *f = lookup().function_at(entry)) facts = *f;
      facts.entry = entry;
      try {
        captured_ = lift::commit_signature(decompiler(), fd, facts);
      } catch (const ghidra::LowlevelError &e) {
        captured_ = lift::CommittedSignature{};
        captured_->status = lift::CommittedSignature::Status::failed;
        captured_->detail = "reading the signature: " + e.explain;
      }
    };
  }

  std::string payload(const Bundle &, lift::DecompileResult &r) override {
    lift::CommittedSignature s;
    if (r.ok && captured_) {
      s = std::move(*captured_);
    } else {
      s.status = lift::CommittedSignature::Status::failed;
      s.detail = r.ok ? std::string("no signature") : r.error;
    }
    captured_.reset();
    return encode_signature(s);
  }

 private:
  std::optional<lift::CommittedSignature> captured_;
};

std::string storage_text(const std::vector<lift::StorageVarnode> &s) {
  std::string out;
  for (const lift::StorageVarnode &v : s) {
    char buf[96];
    std::snprintf(buf, sizeof buf, "%s%s:0x%llx:%d", out.empty() ? "" : "+", v.space.c_str(),
                  static_cast<unsigned long long>(v.offset), v.size);
    out += buf;
  }
  return out;
}

std::string type_text(const lift::DecompElement &t) {
  if (t.tag == "void") return "void";
  if (const auto *n = t.attr("name"); n != nullptr && std::holds_alternative<std::string>(*n) &&
                                      !std::get<std::string>(*n).empty())
    return std::get<std::string>(*n);
  if (!t.children.empty()) return type_text(t.children[0]) + (t.tag == "type" ? " *" : "");
  return "?";
}

}  // namespace

std::unique_ptr<Session> make_param_id_session(const Bundle &b) { return std::make_unique<ParamIdSession>(b); }

std::string encode_signature(const lift::CommittedSignature &s) { return facts::encode_to_string(s); }

lift::CommittedSignature decode_signature(std::string_view bytes) {
  return facts::decode_from_string<lift::CommittedSignature>(bytes);
}

// rk-decompd --bundle's text for the mode.
std::string print_signature(std::string_view payload, bool &ok) {
  lift::CommittedSignature s = decode_signature(payload);
  ok = s.status == lift::CommittedSignature::Status::committed;
  if (!ok) return "/* not committed: " + s.detail + " */\n";
  std::string out = s.convention + (s.custom_storage ? " (custom storage)" : "") + "\n";
  out += "return: " + (s.return_committed ? type_text(s.ret.type) + " @" + storage_text(*s.ret.storage) : "(kept)") +
         "\n";
  for (const lift::ParamFacts &p : s.params)
    out += "  " + type_text(p.type) + " " + p.name + " @" + storage_text(p.storage) + "\n";
  if (s.varargs) out += "  ...\n";
  return out;
}

lift::CommittedSignature signature_of(const BundledRun &run, const std::string &unavailable) {
  lift::CommittedSignature s;
  s.status = lift::CommittedSignature::Status::failed;
  if (run.failure) {
    s.detail = describe(*run.failure);
  } else if (run.outcome.result && run.outcome.result->ran) {
    try {
      return decode_signature(run.outcome.result->payload);
    } catch (const std::exception &e) {
      s.detail = std::string("bad result from the decompiler worker: ") + e.what();
    }
  } else if (run.outcome.result) {
    s.detail = "decompiler worker: " + run.outcome.result->error;
  } else if (!unavailable.empty()) {
    s.detail = "decompiler worker unavailable: " + unavailable;
  } else {
    s.detail = "not run";
  }
  return s;
}

// ---- CommittedLookup ------------------------------------------------------------

const lift::FunctionFacts *CommittedLookup::overlay(const lift::FunctionFacts *f) {
  if (f == nullptr) return nullptr;
  if (auto it = done_.find(f); it != done_.end()) return it->second;
  std::uint64_t at = f->entry;
  if (auto t = thunks_.find(f->entry); t != thunks_.end()) {
    if (!t->second || f->signature_source != lift::SignatureSource::default_) return done_[f] = f;
    at = *t->second;
  }
  auto it = committed_.find(at);
  if (it == committed_.end() || it->second.status != lift::CommittedSignature::Status::committed) return done_[f] = f;
  lift::FunctionFacts &copy = owned_.emplace_back(*f);
  inputs::apply_param_id(copy, it->second);
  return done_[f] = &copy;
}

const lift::FunctionFacts *CommittedLookup::function_at(std::uint64_t entry) {
  return overlay(base_.function_at(entry));
}

std::optional<lift::FactLookup::Body> CommittedLookup::body_containing(std::uint64_t a) {
  std::optional<Body> b = base_.body_containing(a);
  if (b) b->function = overlay(b->function);
  return b;
}

// ---- the driver -----------------------------------------------------------------

std::map<std::uint64_t, lift::CommittedSignature> param_id_functions(const lift::DecompileConfig &config,
                                                                     const inputs::ParamIdPlan &plan,
                                                                     const ParamIdOptions &options,
                                                                     ParamIdStats *stats, PoolOptions pool_options) {
  const auto started = Clock::now();
  std::map<std::uint64_t, lift::CommittedSignature> results;
  ParamIdStats local;
  local.functions = plan.nodes.size();
  if (plan.nodes.empty()) {
    if (stats) *stats = local;
    return results;
  }
  auto inputs = config.inputs ? config.inputs : std::make_shared<lift::DecompilerInputs>();
  std::shared_ptr<lift::FactLookup> base =
      config.lookup ? config.lookup : std::shared_ptr<lift::FactLookup>(lift::lookup_inputs(inputs, config.image.get()));
  lift::ArchitectureOptions::Patches patches = inputs->patches;
  patches.insert(patches.end(), inputs->synthesized_memory.begin(), inputs->synthesized_memory.end());
  const ProgramImage program(config.image, config.language_id, patches);
  patches.clear();
  const std::vector<lift::BlockFacts> blocks = lookup_blocks(*inputs, *config.image);
  const std::vector<std::string> spaces = input_spaces(*inputs);
  std::shared_ptr<TypeCache> type_cache = base->stable() ? std::make_shared<TypeCache>() : nullptr;
  unsigned threads = config.threads != 0 ? config.threads : std::max(1u, std::thread::hardware_concurrency());
  threads = static_cast<unsigned>(std::min<std::size_t>(threads, plan.nodes.size()));
  LifterPool lifters(config.image, config.language_id, std::min(threads, 2u));
  pool_options.workers = threads;
  WorkerPool pool(pool_options);
  const Limits limits{options.timeout_seconds, options.max_varnodes ? options.max_varnodes : config.limits.max_varnodes};

  // Dependents and what each node still waits for.
  std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> dependents;
  std::unordered_map<std::uint64_t, std::size_t> waiting;
  for (std::uint64_t n : plan.nodes) {
    const std::vector<std::uint64_t> &d = plan.dependencies_of(n);
    waiting[n] = d.size();
    for (std::uint64_t c : d) dependents[c].push_back(n);
  }
  // Ready nodes, largest first among those ready (they finish last).
  std::unordered_map<std::uint64_t, std::uint64_t> bytes;
  for (const lift::FunctionFacts &f : inputs->functions) {
    std::uint64_t b = 0;
    for (const auto &[x, y] : f.body) b += y - x + 1;
    bytes[f.entry] = b;
  }
  auto size_of = [&](std::uint64_t n) {
    auto it = bytes.find(n);
    return it != bytes.end() ? it->second : 0;
  };
  std::vector<std::uint64_t> ready;
  for (std::uint64_t n : plan.nodes)
    if (waiting[n] == 0) ready.push_back(n);
  std::mutex mu;
  std::condition_variable cv;
  std::size_t remaining = plan.nodes.size();
  std::mutex base_mu;  // the base lookup answers one thread at a time unless it is stable
  const bool shared_base = base->stable();

  auto take = [&]() -> std::optional<std::uint64_t> {
    std::unique_lock lock(mu);
    cv.wait(lock, [&] { return !ready.empty() || remaining == 0; });
    if (ready.empty()) return std::nullopt;
    auto best = std::max_element(ready.begin(), ready.end(), [&](std::uint64_t a, std::uint64_t b) {
      return size_of(a) != size_of(b) ? size_of(a) < size_of(b) : a > b;
    });
    const std::uint64_t n = *best;
    ready.erase(best);
    return n;
  };

  auto work = [&] {
    while (std::optional<std::uint64_t> next = take()) {
      const std::uint64_t entry = *next;
      // What it sees committed: its dependencies' results, which are final.
      std::map<std::uint64_t, lift::CommittedSignature> visible;
      {
        std::lock_guard lock(mu);
        for (std::uint64_t d : plan.dependencies_of(entry))
          if (auto it = results.find(d); it != results.end()) visible.emplace(d, it->second);
      }
      lift::CommittedSignature sig;
      std::optional<Failure> failure;
      double run_ms = 0;
      bool decompiled = false;
      {
        std::unique_lock<std::mutex> base_lock(base_mu, std::defer_lock);
        if (!shared_base) base_lock.lock();
        CommittedLookup lookup(*base, visible, plan.thunks);
        const lift::FunctionFacts *facts = base->function_at(entry);
        std::optional<std::string> skip =
            facts == nullptr ? std::optional<std::string>("no function") : inputs::param_id_skip(*facts, false, blocks);
        if (skip) {
          sig.status = lift::CommittedSignature::Status::skipped;
          sig.detail = *skip;
        } else {
          std::vector<std::pair<std::uint64_t, std::uint64_t>> body = facts->body;
          if (body.empty()) body = {{entry, entry}};
          Prediction p;
          {
            LifterPool::Lease l = lifters.take(facts->context);
            p = predict(*l, program, entry, body, blocks, tracked_seeds(*l, lookup.tracked(entry)));
          }
          LiftBundleBuilder builder(program, Mode::param_id, entry, lookup, blocks, inputs->address_prefix);
          builder.set_naming(config.default_names, config.default_labels, config.default_extrapop);
          builder.set_spaces(spaces);
          if (type_cache) builder.set_type_cache(type_cache);
          builder.add(p);
          LiftSource source(builder);
          BundledRun run;
          std::string unavailable;
          try {
            run = run_bundled(pool, source, limits, entry, 8);
          } catch (const std::exception &e) {
            unavailable = e.what();
          }
          sig = signature_of(run, unavailable);
          failure = run.failure;
          if (run.outcome.result) run_ms = run.outcome.result->milliseconds;
          decompiled = true;
        }
      }
      std::lock_guard lock(mu);
      if (decompiled) ++local.decompiled;
      switch (sig.status) {
        case lift::CommittedSignature::Status::committed: ++local.committed; break;
        case lift::CommittedSignature::Status::failed: ++local.failed; break;
        case lift::CommittedSignature::Status::skipped: ++local.skipped; break;
      }
      if (failure) local.failures.push_back(*failure);
      local.run_ms += run_ms;
      results[entry] = std::move(sig);
      for (std::uint64_t parent : dependents[entry])
        if (--waiting[parent] == 0) ready.push_back(parent);
      --remaining;
      cv.notify_all();
    }
  };
  std::vector<std::thread> threads_v;
  for (unsigned t = 1; t < threads; ++t) threads_v.emplace_back(work);
  work();
  for (std::thread &t : threads_v) t.join();
  local.rounds = plan.rounds().size();
  local.seconds = std::chrono::duration<double>(Clock::now() - started).count();
  std::sort(local.failures.begin(), local.failures.end(),
            [](const Failure &a, const Failure &b) { return a.function < b.function; });
  if (stats) *stats = std::move(local);
  return results;
}

}  // namespace revkit::decompd
