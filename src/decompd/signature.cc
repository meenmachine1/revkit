#include "revkit/decompd/signature.h"

#include "revkit/decompd/lift_mode.h"

#include "block.hh"
#include "error.hh"
#include "funcdata.hh"
#include "signature.hh"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace revkit::decompd {

namespace {

using Clock = std::chrono::steady_clock;

double ms_since(Clock::time_point t) { return std::chrono::duration<double, std::milli>(Clock::now() - t).count(); }

// SigManager::settings is process-wide and read only by GraphSigManager's
// constructor: set and construct under this lock.
std::mutex &settings_mu() {
  static std::mutex m;
  return m;
}

// Records which block each feature is rooted in, from the managers'
// own encoding of their features (SigManager::encode): a VarnodeSignature
// names its defining op (whose sequence number gives its block), block and
// copy signatures their block's index.
class FeatureBlocks final : public ghidra::Encoder {
 public:
  struct Feature {
    std::uint32_t hash = 0;
    std::int32_t block = -1;
  };
  explicit FeatureBlocks(const std::unordered_map<ghidra::uintm, std::int32_t> &op_blocks) : op_blocks_(op_blocks) {}
  std::vector<Feature> features;

  void openElement(const ghidra::ElementId &id) override {
    ++depth_;
    if (depth_ == 2) {
      features.emplace_back();
      var_ = id.getId() == ghidra::ELEM_VARSIG.getId();
      seen_seq_ = false;
    }
    in_seq_ = id.getId() == ghidra::ELEM_SEQNUM.getId();
  }
  void closeElement(const ghidra::ElementId &) override {
    --depth_;
    in_seq_ = false;
  }
  void writeBool(const ghidra::AttributeId &, bool) override {}
  void writeSignedInteger(const ghidra::AttributeId &a, ghidra::intb v) override {
    if (depth_ == 2 && a.getId() == ghidra::ATTRIB_INDEX.getId()) features.back().block = static_cast<std::int32_t>(v);
  }
  void writeUnsignedInteger(const ghidra::AttributeId &a, ghidra::uintb v) override {
    if (depth_ == 2 && a.getId() == ghidra::ATTRIB_HASH.getId()) {
      features.back().hash = static_cast<std::uint32_t>(v);
    } else if (var_ && in_seq_ && !seen_seq_ && a.getId() == ghidra::ATTRIB_UNIQ.getId()) {
      // The first sequence number inside a VARSIG is its defining op's.
      seen_seq_ = true;
      if (auto it = op_blocks_.find(static_cast<ghidra::uintm>(v)); it != op_blocks_.end())
        features.back().block = it->second;
    }
  }
  void writeString(const ghidra::AttributeId &, const std::string &) override {}
  void writeStringIndexed(const ghidra::AttributeId &, ghidra::uint4, const std::string &) override {}
  void writeSpace(const ghidra::AttributeId &, const ghidra::AddrSpace *) override {}
  void writeOpcode(const ghidra::AttributeId &, ghidra::OpCode) override {}

 private:
  const std::unordered_map<ghidra::uintm, std::int32_t> &op_blocks_;
  int depth_ = 0;
  bool var_ = false, in_seq_ = false, seen_seq_ = false;
};

// GraphSigManager over a normalized function: simpleSignature's features,
// and with `blocks` debugSignature's attribution of them to blocks.
void sign(ghidra::Funcdata &fd, const SignatureOptions &options, std::uint64_t max_varnodes, FunctionSignature &out) {
  std::unique_ptr<ghidra::GraphSigManager> manager;
  {
    std::lock_guard lock(settings_mu());
    ghidra::SigManager::setSettings(options.settings);
    manager = std::make_unique<ghidra::GraphSigManager>();
  }
  if (max_varnodes != 0)
    manager->setMaxVarnode(static_cast<ghidra::int4>(std::min<std::uint64_t>(max_varnodes, 0x7fffffff)));
  manager->setCurrentFunction(&fd);
  manager->generate();
  std::vector<ghidra::uint4> features;
  manager->getSignatureVector(features);  // sorted
  out.features.assign(features.begin(), features.end());
  out.unimplemented = fd.hasUnimplemented();
  out.bad_data = fd.hasBadData();
  out.settings = options.settings;
  if (!options.blocks) return;
  const ghidra::BlockGraph &graph = fd.getBasicBlocks();
  std::unordered_map<ghidra::uintm, std::int32_t> op_blocks;
  std::map<std::int32_t, BlockFeatures> by_block;
  for (ghidra::int4 i = 0; i < graph.getSize(); ++i) {
    auto *bl = static_cast<ghidra::BlockBasic *>(graph.getBlock(i));
    BlockFeatures &bf = by_block[bl->getIndex()];
    bf.index = bl->getIndex();
    bf.start = bl->getStart().getOffset();
    for (auto it = bl->beginOp(); it != bl->endOp(); ++it) op_blocks[(*it)->getSeqNum().getTime()] = bl->getIndex();
  }
  FeatureBlocks capture(op_blocks);
  manager->encode(capture);
  for (const FeatureBlocks::Feature &f : capture.features) {
    BlockFeatures &bf = by_block[f.block];
    if (f.block < 0) {
      bf.index = -1;  // rooted in no block (an input): the function's
      bf.start = fd.getAddress().getOffset();
    }
    bf.features.push_back(f.hash);
  }
  for (auto &[index, bf] : by_block) {
    std::sort(bf.features.begin(), bf.features.end());
    out.blocks.push_back(std::move(bf));
  }
}

class SignatureSession final : public LiftSession {
 public:
  explicit SignatureSession(const Bundle &b) : LiftSession(b) {}

 protected:
  void prepare(const Bundle &b, lift::RunHooks &hooks) override {
    captured_.reset();
    SignatureOptions options;
    try {
      options = facts::decode_from_string<SignatureOptions>(b.extra);
    } catch (const facts::DecodeError &e) {
      bad_options_ = std::string("bad signature options: ") + e.what();
      return;
    }
    bad_options_.clear();
    if (!ghidra::GraphSigManager::testSettings(options.settings)) {
      char buf[64];
      std::snprintf(buf, sizeof buf, "bad signature settings 0x%x", options.settings);
      bad_options_ = buf;
      return;
    }
    const std::uint64_t max_varnodes = hooks.limits != nullptr ? hooks.limits->max_varnodes : 0;
    // Nothing is printed: the normalized function is signed instead.
    hooks.print = [this, options, max_varnodes](ghidra::Funcdata &fd) {
      FunctionSignature s;
      try {
        sign(fd, options, max_varnodes, s);
        s.status = FunctionSignature::Status::ok;
      } catch (const ghidra::LowlevelError &e) {
        s = FunctionSignature{};
        s.status = FunctionSignature::Status::failed;
        s.detail = "signing: " + e.explain;
      }
      captured_ = std::move(s);
    };
  }

  std::string payload(const Bundle &, lift::DecompileResult &r) override {
    FunctionSignature s;
    if (!bad_options_.empty()) {
      s.detail = bad_options_;
    } else if (r.ok && captured_) {
      s = std::move(*captured_);
    } else {
      s.status = FunctionSignature::Status::failed;
      s.detail = r.ok ? std::string("no signature") : r.error;
    }
    captured_.reset();
    return encode_function_signature(s);
  }

 private:
  std::optional<FunctionSignature> captured_;
  std::string bad_options_;
};

}  // namespace

// ---- encodings --------------------------------------------------------------------

void SignatureOptions::encode(facts::Encoder &e) const {
  e.varint(settings);
  facts::encode(e, blocks);
  e.bytes(profile.id());
  facts::encode(e, profile.import_prototypes);
}

SignatureOptions SignatureOptions::decode(facts::Decoder &d) {
  SignatureOptions o;
  o.settings = static_cast<std::uint32_t>(d.varint());
  o.blocks = facts::decode<bool>(d);
  const std::string id(d.bytes());
  o.profile.import_prototypes = facts::decode<bool>(d);
  if (id != o.profile.id()) throw facts::DecodeError("signature profile " + id + ", expected " + o.profile.id());
  return o;
}

void FunctionSignature::encode(facts::Encoder &e) const {
  e.u8(static_cast<std::uint8_t>(status));
  e.bytes(detail);
  e.varint(features.size());
  std::uint32_t last = 0;
  for (std::uint32_t f : features) {  // sorted: deltas
    e.varint(f - last);
    last = f;
  }
  e.varint(blocks.size());
  for (const BlockFeatures &b : blocks) {
    e.svarint(b.index);
    e.varint(b.start);
    facts::encode(e, b.features);
  }
  e.u8(static_cast<std::uint8_t>((unimplemented ? 1 : 0) | (bad_data ? 2 : 0)));
  e.varint(settings);
  e.u8(failure ? static_cast<std::uint8_t>(*failure) : 0);
  e.bytes(bundle_hash);
}

FunctionSignature FunctionSignature::decode(facts::Decoder &d) {
  FunctionSignature s;
  const std::uint8_t st = d.u8();
  if (st > 2) throw facts::DecodeError("bad signature status");
  s.status = static_cast<Status>(st);
  s.detail = std::string(d.bytes());
  const std::size_t n = d.count();
  s.features.reserve(n);
  std::uint32_t last = 0;
  for (std::size_t i = 0; i < n; ++i) {
    last += static_cast<std::uint32_t>(d.varint());
    s.features.push_back(last);
  }
  const std::size_t nb = d.count();
  for (std::size_t i = 0; i < nb; ++i) {
    BlockFeatures b;
    b.index = static_cast<std::int32_t>(d.svarint());
    b.start = d.varint();
    b.features = facts::decode<std::vector<std::uint32_t>>(d);
    s.blocks.push_back(std::move(b));
  }
  const std::uint8_t flags = d.u8();
  s.unimplemented = flags & 1;
  s.bad_data = flags & 2;
  s.settings = static_cast<std::uint32_t>(d.varint());
  if (const std::uint8_t f = d.u8(); f != 0) {
    if (f > static_cast<std::uint8_t>(FailureKind::oom)) throw facts::DecodeError("bad failure kind");
    s.failure = static_cast<FailureKind>(f);
  }
  s.bundle_hash = std::string(d.bytes());
  return s;
}

std::unique_ptr<Session> make_signature_session(const Bundle &b) { return std::make_unique<SignatureSession>(b); }

std::string encode_function_signature(const FunctionSignature &s) { return facts::encode_to_string(s); }

FunctionSignature decode_function_signature(std::string_view bytes) {
  return facts::decode_from_string<FunctionSignature>(bytes);
}

std::string print_function_signature(std::string_view payload, bool &ok) {
  FunctionSignature s = decode_function_signature(payload);
  ok = s.ok();
  if (!ok) return "/* no signature: " + s.detail + " */\n";
  std::string out;
  char buf[96];
  std::snprintf(buf, sizeof buf, "# settings 0x%x, %zu features%s%s\n", s.settings, s.features.size(),
                s.unimplemented ? ", unimplemented instructions" : "", s.bad_data ? ", bad data" : "");
  out += buf;
  for (std::uint32_t f : s.features) {
    std::snprintf(buf, sizeof buf, "%08x\n", f);
    out += buf;
  }
  for (const BlockFeatures &b : s.blocks) {
    std::snprintf(buf, sizeof buf, "# block %d at 0x%llx:", b.index, static_cast<unsigned long long>(b.start));
    out += buf;
    for (std::uint32_t f : b.features) {
      std::snprintf(buf, sizeof buf, " %08x", f);
      out += buf;
    }
    out += "\n";
  }
  return out;
}

FunctionSignature function_signature_of(const BundledRun &run, const std::string &unavailable) {
  FunctionSignature s;
  s.status = FunctionSignature::Status::failed;
  s.bundle_hash = run.hash;
  if (run.failure) {
    s.detail = describe(*run.failure);
    s.failure = run.failure->kind;
  } else if (run.outcome.result && run.outcome.result->ran) {
    try {
      s = decode_function_signature(run.outcome.result->payload);
      s.bundle_hash = run.hash;
      if (run.outcome.result->stopped != lift::DecompileStop::none && !s.ok()) {
        // A cooperative stop over the run's limits is a failure fact.
        if (run.outcome.result->stopped == lift::DecompileStop::too_large) s.failure = FailureKind::oom;
        else if (run.outcome.result->stopped == lift::DecompileStop::timeout) s.failure = FailureKind::timeout;
      }
      return s;
    } catch (const std::exception &e) {
      s.detail = std::string("bad result from the decompiler worker: ") + e.what();
    }
  } else if (run.outcome.result) {
    s.detail = "decompiler worker: " + run.outcome.result->error;
  } else if (run.outcome.cancelled) {
    s.detail = "cancelled";
  } else if (!unavailable.empty()) {
    s.detail = "decompiler worker unavailable: " + unavailable;
  } else {
    s.detail = "not run";
  }
  return s;
}

std::uint32_t default_signature_settings(const std::string &language_id) {
  // GenSignatures.getWeightsFile(id, id): lshweights_32/64(_32).xml (0x49)
  // for 32- and 64-bit languages, lshweights_nosize.xml (0x4d) otherwise.
  // (revkit::diff::weights_for is the same choice, for the comparison.)
  std::size_t a = language_id.find(':');
  std::size_t b = a == std::string::npos ? a : language_id.find(':', a + 1);
  std::size_t c = b == std::string::npos ? b : language_id.find(':', b + 1);
  if (b == std::string::npos) return kSignatureSettingsNoSize;
  const std::string size = language_id.substr(b + 1, c == std::string::npos ? std::string::npos : c - b - 1);
  return size == "32" || size == "64" ? kSignatureSettings : kSignatureSettingsNoSize;
}

// ---- assembling and running one ----------------------------------------------------

FunctionSignature sign_function(WorkerPool &pool, const SignatureContext &ctx, lift::FactLookup &facts,
                                std::uint64_t entry, const SignatureOptions &options, const Limits &limits,
                                BundledRun *run_out, const std::function<bool()> &cancelled) {
  inputs::SignatureLookup lookup(facts, options.profile, ctx.no_return);
  FunctionSignature s;
  const lift::FunctionFacts *f = lookup.function_at(entry);
  if (f == nullptr) {
    s.status = FunctionSignature::Status::skipped;
    s.detail = "no function";
    return s;
  }
  if (inputs::is_import(*f)) {
    s.status = FunctionSignature::Status::skipped;
    s.detail = "import";
    return s;
  }
  std::vector<std::pair<std::uint64_t, std::uint64_t>> body = f->body;
  if (body.empty()) body = {{entry, entry}};
  Prediction p;
  {
    LifterPool::Lease l = ctx.lifters->take(f->context);
    p = predict(*l, *ctx.program, entry, body, ctx.blocks, tracked_seeds(*l, lookup.tracked(entry)));
  }
  LiftBundleBuilder builder(*ctx.program, Mode::signature, entry, lookup, ctx.blocks, ctx.address_prefix);
  builder.set_naming(ctx.default_names, ctx.default_labels, ctx.default_extrapop);
  builder.set_spaces(ctx.spaces);
  if (ctx.type_cache && facts.stable()) builder.set_type_cache(ctx.type_cache);
  builder.set_extra(facts::encode_to_string(options));
  builder.add(p);
  LiftSource source(builder);
  BundledRun run;
  std::string unavailable;
  try {
    run = run_bundled(pool, source, limits, entry, 8, cancelled);
  } catch (const std::exception &e) {
    unavailable = e.what();
  }
  s = function_signature_of(run, unavailable);
  if (run_out != nullptr) *run_out = std::move(run);
  return s;
}

// ---- a whole program ---------------------------------------------------------------

std::map<std::uint64_t, FunctionSignature> signature_functions(const lift::DecompileConfig &config,
                                                               const std::vector<std::uint64_t> &entries,
                                                               const SignatureBatchOptions &options,
                                                               SignatureStats *stats, PoolOptions pool_options) {
  const auto started = Clock::now();
  std::map<std::uint64_t, FunctionSignature> results;
  SignatureStats local;
  local.functions = entries.size();
  if (entries.empty()) {
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
  unsigned threads = config.threads != 0 ? config.threads : std::max(1u, std::thread::hardware_concurrency());
  threads = static_cast<unsigned>(std::min<std::size_t>(threads, entries.size()));
  LifterPool lifters(config.image, config.language_id, std::min(threads, 2u));
  SignatureContext ctx;
  ctx.program = &program;
  ctx.blocks = lookup_blocks(*inputs, *config.image);
  ctx.spaces = input_spaces(*inputs);
  ctx.address_prefix = inputs->address_prefix;
  ctx.default_names = config.default_names;
  ctx.default_labels = config.default_labels;
  ctx.default_extrapop = config.default_extrapop;
  ctx.lifters = &lifters;
  ctx.no_return = options.no_return;
  if (base->stable()) ctx.type_cache = std::make_shared<TypeCache>();
  pool_options.workers = threads;
  WorkerPool pool(pool_options);
  const Limits limits{options.timeout_seconds, options.max_varnodes ? options.max_varnodes : config.limits.max_varnodes};

  // Largest first: they finish last.
  std::unordered_map<std::uint64_t, std::uint64_t> bytes;
  for (const lift::FunctionFacts &f : inputs->functions) {
    std::uint64_t b = 0;
    for (const auto &[x, y] : f.body) b += y - x + 1;
    bytes[f.entry] = b;
  }
  std::vector<std::uint64_t> order(entries);
  std::sort(order.begin(), order.end());
  order.erase(std::unique(order.begin(), order.end()), order.end());
  std::stable_sort(order.begin(), order.end(), [&](std::uint64_t a, std::uint64_t b) {
    auto sa = bytes.find(a), sb = bytes.find(b);
    return (sa != bytes.end() ? sa->second : 0) > (sb != bytes.end() ? sb->second : 0);
  });
  std::atomic<std::size_t> next{0};
  std::mutex mu, base_mu;
  const bool shared_base = base->stable();
  auto work = [&] {
    for (;;) {
      const std::size_t k = next.fetch_add(1);
      if (k >= order.size()) return;
      const std::uint64_t entry = order[k];
      const auto t0 = Clock::now();
      BundledRun run;
      FunctionSignature s;
      {
        std::unique_lock<std::mutex> lock(base_mu, std::defer_lock);
        if (!shared_base) lock.lock();
        s = sign_function(pool, ctx, *base, entry, options.signature, limits, &run);
      }
      const double total_ms = ms_since(t0);
      std::lock_guard lock(mu);
      const double run_ms = run.outcome.result ? run.outcome.result->milliseconds : 0;
      local.run_ms += run_ms;
      local.build_ms += std::max(0.0, total_ms - run.outcome.round_trip_ms);
      switch (s.status) {
        case FunctionSignature::Status::ok:
          ++local.signed_ok;
          local.features += s.features.size();
          break;
        case FunctionSignature::Status::failed: ++local.failed; break;
        case FunctionSignature::Status::skipped: ++local.skipped; break;
      }
      if (run.failure) local.failures.push_back(*run.failure);
      results[entry] = std::move(s);
    }
  };
  std::vector<std::thread> pool_threads;
  for (unsigned t = 1; t < threads; ++t) pool_threads.emplace_back(work);
  work();
  for (std::thread &t : pool_threads) t.join();
  local.seconds = std::chrono::duration<double>(Clock::now() - started).count();
  std::sort(local.failures.begin(), local.failures.end(),
            [](const Failure &a, const Failure &b) { return a.function < b.function; });
  if (stats) *stats = std::move(local);
  return results;
}

}  // namespace revkit::decompd
