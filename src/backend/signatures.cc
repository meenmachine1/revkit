#include "signatures.h"

#include "own_inputs.h"
#include "program.h"
#include "queries.h"

#include "revkit/diff/lsh.h"
#include "revkit/diff/match.h"
#include "revkit/diff/residue.h"
#include "revkit/inputs/codec.h"
#include "revkit/inputs/profile.h"

#include "error.hh"

#include <algorithm>
#include <stdexcept>

namespace revkit::backend {

namespace an = analysis;
using facts::QueryContext;

// ---- values ------------------------------------------------------------------

void SignatureAddress::encode(facts::Encoder &e) const {
  facts::encode(e, starts);
  facts::encode(e, contains);
  e.varint(body_first);
  e.varint(body_last);
  facts::encode(e, external);
  e.u8(block ? static_cast<std::uint8_t>(*block) + 1 : 0);
  facts::encode(e, tracked);
}

SignatureAddress SignatureAddress::decode(facts::Decoder &d) {
  SignatureAddress v;
  v.starts = facts::decode<std::optional<lift::FunctionFacts>>(d);
  v.contains = facts::decode<std::optional<lift::FunctionFacts>>(d);
  v.body_first = d.varint();
  v.body_last = d.varint();
  v.external = facts::decode<std::optional<lift::ExternalRefFacts>>(d);
  if (const std::uint8_t b = d.u8(); b != 0) {
    if (b > 3) throw facts::DecodeError("bad mutability");
    v.block = static_cast<lift::Mutability>(b - 1);
  }
  v.tracked = facts::decode<std::vector<lift::TrackedFacts>>(d);
  return v;
}

void SignatureKey::encode(facts::Encoder &e) const {
  e.bytes(program);
  e.varint(entry);
  e.varint(settings);
}

SignatureKey SignatureKey::decode(facts::Decoder &d) {
  SignatureKey k;
  k.program = std::string(d.bytes());
  k.entry = d.varint();
  k.settings = static_cast<std::uint32_t>(d.varint());
  return k;
}

namespace {

// A signature run's lookup: diff.signature_inputs through the query
// context, so each address the decompiler asks is a dependency; nothing
// else (no assertions, no types beyond import prototypes).
class SignatureRunLookup final : public RunLookup {
 public:
  SignatureRunLookup(QueryContext &ctx, std::string program) : ctx_(&ctx), program_(std::move(program)) {}

  void freeze(bool) override {}
  std::vector<std::uint64_t> take_late() override { return {}; }
  bool says_anything(std::uint64_t a) override {
    const SignatureAddress *s = at(a);
    return s->starts || s->contains || s->external;
  }
  void prefetch(std::uint64_t) override {}
  std::vector<std::uint64_t> touched() const override {
    std::vector<std::uint64_t> out;
    for (const auto &[a, r] : addresses_) out.push_back(a);
    return out;
  }

  const lift::FunctionFacts *function_at(std::uint64_t entry) override {
    const SignatureAddress *s = at(entry);
    return s->starts ? &*s->starts : nullptr;
  }
  std::optional<Body> body_containing(std::uint64_t a) override {
    const SignatureAddress *s = at(a);
    if (!s->contains) return std::nullopt;
    return Body{s->body_first, s->body_last, &*s->contains};
  }
  const lift::DataFacts *data_containing(const std::string &, std::uint64_t) override { return nullptr; }
  const lift::ExternalRefFacts *external_at(const std::string &space, std::uint64_t a) override {
    if (!space.empty()) return nullptr;
    const SignatureAddress *s = at(a);
    return s->external ? &*s->external : nullptr;
  }
  const lift::LabelFacts *label_at(const std::string &, std::uint64_t) override { return nullptr; }
  std::optional<std::string> code_label_at(const std::string &, std::uint64_t) override { return std::nullopt; }
  std::optional<lift::Mutability> block_at(const std::string &space, std::uint64_t a) override {
    if (!space.empty()) return std::nullopt;
    return at(a)->block;
  }
  const lift::DecompElement *type(std::uint64_t id) override {
    // Import prototypes' types.
    if (auto it = types_.find(id); it != types_.end()) return *it->second ? &**it->second : nullptr;
    auto ref = query([&] { return ctx_->get<q::InputsType>({program_, id}); });
    auto &slot = types_.emplace(id, std::move(ref)).first->second;
    return *slot ? &**slot : nullptr;
  }
  std::vector<const lift::CommentFacts *> comments(std::uint64_t) override { return {}; }
  std::vector<std::pair<std::uint64_t, std::string>> flow_overrides(std::uint64_t entry) override {
    if (auto it = functions_.find(entry); it != functions_.end()) return it->second->flow_overrides;
    auto ref = query([&] { return ctx_->get<q::InputsFunction>({program_, entry}); });
    return functions_.emplace(entry, std::move(ref)).first->second->flow_overrides;
  }
  std::vector<lift::TrackedFacts> tracked(std::uint64_t entry) override { return at(entry)->tracked; }

 private:
  template <class F>
  auto query(F &&get) -> decltype(get()) {
    if (failure) throw ghidra::LowlevelError("lookup failed");
    try {
      return get();
    } catch (...) {
      failure = std::current_exception();
      throw ghidra::LowlevelError("lookup failed");
    }
  }
  const SignatureAddress *at(std::uint64_t a) {
    if (auto it = addresses_.find(a); it != addresses_.end()) return &*it->second;
    auto ref = query([&] { return ctx_->get<q::SignatureInputs>({program_, a}); });
    return &*addresses_.emplace(a, std::move(ref)).first->second;
  }

  QueryContext *ctx_;
  std::string program_;
  std::map<std::uint64_t, facts::Ref<SignatureAddress>> addresses_;
  std::map<std::uint64_t, facts::Ref<inputs::FunctionInputs>> functions_;
  std::map<std::uint64_t, facts::Ref<std::optional<lift::DecompElement>>> types_;
};

const char *OverrideKindName(int kind) {
  switch (kind) {
    case pb::FLOW_OVERRIDE_KIND_BRANCH: return "BRANCH";
    case pb::FLOW_OVERRIDE_KIND_CALL: return "CALL";
    case pb::FLOW_OVERRIDE_KIND_CALL_RETURN: return "CALL_RETURN";
    case pb::FLOW_OVERRIDE_KIND_RETURN: return "RETURN";
    default: return nullptr;
  }
}

}  // namespace

namespace q {

SignatureInputs::Value SignatureInputs::compute(QueryContext &ctx, const Key &key) {
  auto facts = ctx.get<InputsAddress>(key);
  auto sets = ctx.get<InputsSets>(key.first);
  const inputs::SignatureProfile profile;
  SignatureAddress out;
  if (facts->starts) out.starts = inputs::strip_function(*facts->starts, profile, &sets->no_return);
  if (facts->contains) {
    out.contains = inputs::strip_function(*facts->contains, profile, &sets->no_return);
    out.body_first = facts->body_first;
    out.body_last = facts->body_last;
  }
  if (facts->external) {
    out.external = *facts->external;
    if (out.external->function) out.external->function = inputs::strip_function(*out.external->function, profile);
  }
  out.block = facts->block;
  out.tracked = facts->tracked;
  return out;
}

DiffSignature::Value DiffSignature::compute(QueryContext &ctx, const Key &key) {
  auto src = ctx.get<Source>(key.program);
  if (!src->program) throw std::logic_error("program " + key.program + " is not loaded");
  ctx.get<DecompilerOptions>(key.program);  // the decompiler build
  const an::Location at{AnalysisKey(key.program), key.entry};
  auto f = ctx.get<an::Function>(at);
  decompd::FunctionSignature out;
  out.status = decompd::FunctionSignature::Status::skipped;
  if (f->name.empty()) {
    out.detail = "no function";
    return out;
  }
  SignatureRunLookup lookup(ctx, key.program);
  const lift::FunctionFacts *self = lookup.function_at(key.entry);
  if (lookup.failure) std::rethrow_exception(lookup.failure);
  if (self == nullptr || inputs::is_import(*self)) {
    out.detail = self == nullptr ? "no function" : "import";
    return out;
  }
  SignatureRequest req;
  req.entry = key.entry;
  for (const facts::AddressRange &r : f->body.ranges()) req.body.emplace_back(r.first.offset, r.last.offset);
  if (req.body.empty()) req.body.emplace_back(key.entry, key.entry);
  // The user's flow overrides in the body: flow, not naming.
  const facts::SpaceId space = src->ram_space;
  for (const auto &[first, last] : req.body)
    for (const facts::FactKey &k : facts::asserted_keys(ctx, facts::FactKind::FlowOverride, {space, first}, {space, last})) {
      auto v = ctx.get<facts::AssertedFact>(k);
      if (const auto *kind = std::get_if<std::int64_t>(&*v))
        if (const char *name = OverrideKindName(static_cast<int>(*kind))) req.flow_overrides.emplace_back(k.addr.offset, name);
    }
  req.options.settings =
      key.settings != 0 ? key.settings : decompd::default_signature_settings(src->program->language().language);
  auto image = ctx.get<InputsImage>(key.program);
  return EffectiveProgram(ctx, key.program)->decompiler().Signature(req, *image, lookup);
}

std::size_t DiffSignature::weight(const Value &v) {
  std::size_t blocks = 0;
  for (const decompd::BlockFeatures &b : v.blocks) blocks += sizeof(b) + b.features.capacity() * 4;
  return sizeof(Value) + v.features.capacity() * 4 + blocks + v.detail.capacity() + v.bundle_hash.capacity();
}

}  // namespace q

namespace {

// The matcher's "bsim" tier (diff.matches with SessionKey::similarity
// naming it): the residue's signatures through diff.signature (in
// parallel on the engine's pool, as dependencies of the matches), scored
// by diff::score_residue. Programs of different pointer sizes are signed
// with the size-free settings and table.
class BsimTier final : public diff::SimilarityTier {
 public:
  std::string_view name() const override { return "bsim"; }
  std::vector<diff::ScoredPair> score(QueryContext &ctx, const diff::ResidueRequest &req) override {
    auto sa = ctx.get<q::Source>(req.program_a);
    auto sb = ctx.get<q::Source>(req.program_b);
    if (!sa->program || !sb->program) return {};
    const diff::Weights w =
        diff::weights_for(sa->program->language().language, sb->program->language().language)
            .value_or(diff::Weights::nosize);
    const diff::WeightTable &table = diff::WeightTable::builtin(w);
    const std::uint32_t settings = w == diff::Weights::nosize ? decompd::kSignatureSettingsNoSize : 0;
    auto fetch = [&](bool side_b, const std::vector<std::uint64_t> &entries) {
      std::vector<SignatureKey> keys;
      for (std::uint64_t e : entries) keys.push_back({side_b ? req.program_b : req.program_a, e, settings});
      auto sigs = ctx.get_all<q::DiffSignature>(keys);
      std::vector<std::vector<std::uint32_t>> out;
      for (const auto &s : sigs) out.push_back(s->ok() ? s->features : std::vector<std::uint32_t>{});
      return out;
    };
    return diff::score_residue(req, fetch, table);
  }
};

}  // namespace

void RegisterSignatureQueries(facts::Engine &engine) {
  engine.add_query<q::SignatureInputs>();
  engine.add_query<q::DiffSignature>();
  static const bool registered = [] {
    diff::register_similarity_tier(std::make_shared<BsimTier>());
    return true;
  }();
  (void)registered;
}

// ---- SignatureJob --------------------------------------------------------------

SignatureJob::SignatureJob(facts::Snapshot snapshot, std::string program, std::vector<std::uint64_t> entries,
                           Options options)
    : snapshot_(std::move(snapshot)), program_(std::move(program)), entries_(std::move(entries)), options_(options) {
  std::sort(entries_.begin(), entries_.end());
  entries_.erase(std::unique(entries_.begin(), entries_.end()), entries_.end());
  const unsigned n = std::max(1u, std::min<unsigned>(options_.threads, static_cast<unsigned>(entries_.size())));
  for (unsigned t = 0; t < n && !entries_.empty(); ++t) threads_.emplace_back([this] { work(); });
}

SignatureJob::~SignatureJob() {
  cancel();
  for (std::thread &t : threads_)
    if (t.joinable()) t.join();
}

void SignatureJob::cancel() { cancelled_.store(true); }

void SignatureJob::work() {
  // Runs in flight see the cancellation at their next poll (their worker is
  // stopped); a cancelled computation throws and is not memoized.
  lift::DecompileLimits limits;
  if (const lift::DecompileLimits *outer = DecompileLimitsScope::current()) limits = *outer;
  limits.cancelled = [this] { return cancelled_.load(); };
  DecompileLimitsScope scope(limits);
  for (;;) {
    if (cancelled_.load()) return;
    const std::size_t k = next_.fetch_add(1);
    if (k >= entries_.size()) return;
    try {
      auto sig = snapshot_.get<q::DiffSignature>(SignatureKey{program_, entries_[k], options_.settings});
      std::lock_guard lock(mu_);
      results_[entries_[k]] = *sig;
    } catch (const DecompileStoppedError &) {
      return;  // cancelled
    } catch (...) {
      std::lock_guard lock(mu_);
      if (!error_) error_ = std::current_exception();
      cancelled_.store(true);
      return;
    }
    done_.fetch_add(1);
  }
}

std::map<std::uint64_t, decompd::FunctionSignature> SignatureJob::wait() {
  for (std::thread &t : threads_)
    if (t.joinable()) t.join();
  std::lock_guard lock(mu_);
  if (error_) std::rethrow_exception(error_);
  return results_;
}

}  // namespace revkit::backend
