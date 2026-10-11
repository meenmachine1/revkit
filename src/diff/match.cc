// The matcher (match.h): unique matching over global buckets, propagation
// through neighbourhoods to a fixpoint, the residue hook, candidates.

#include "revkit/diff/match.h"

#include "revkit/diff/correlate.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace revkit::diff {

using namespace std::string_view_literals;

std::string_view to_string(Tier t) {
  switch (t) {
    case Tier::none: return "none";
    case Tier::accepted: return "accepted";
    case Tier::name: return "name";
    case Tier::bytes: return "bytes";
    case Tier::pcode: return "pcode";
    case Tier::shape_refs: return "shape_refs";
    case Tier::shape: return "shape";
    case Tier::refs: return "refs";
    case Tier::call_order: return "call_order";
    case Tier::lone: return "lone";
    case Tier::similarity: return "similarity";
    case Tier::neighbour: return "neighbour";
  }
  return "none";
}

std::optional<Tier> tier_from_string(std::string_view s) {
  for (int i = 0; i <= static_cast<int>(Tier::neighbour); ++i)
    if (to_string(static_cast<Tier>(i)) == s) return static_cast<Tier>(i);
  return std::nullopt;
}

std::string_view to_string(Relation r) {
  switch (r) {
    case Relation::global: return "global";
    case Relation::residue: return "residue";
    case Relation::callee: return "callee";
    case Relation::caller: return "caller";
    case Relation::string: return "string";
    case Relation::data: return "data";
    case Relation::seed: return "seed";
    case Relation::similar: return "similar";
    case Relation::address: return "address";
  }
  return "?";
}

// ---- encodings ----

namespace {
void put_float(facts::Encoder &e, float f) {
  std::uint32_t u = 0;
  static_assert(sizeof u == sizeof f);
  std::memcpy(&u, &f, 4);
  e.u32be(u);
}
float get_float(facts::Decoder &d) {
  std::uint32_t u = d.u32be();
  float f = 0;
  std::memcpy(&f, &u, 4);
  return f;
}
}  // namespace

void Evidence::encode(facts::Encoder &e) const {
  facts::encode(e, tier);
  facts::encode(e, relation);
  e.varint(parent_a);
  e.varint(parent_b);
  e.varint(round);
  e.varint(group);
}
Evidence Evidence::decode(facts::Decoder &d) {
  Evidence v;
  v.tier = facts::decode<Tier>(d);
  v.relation = facts::decode<Relation>(d);
  v.parent_a = d.varint();
  v.parent_b = d.varint();
  v.round = static_cast<std::uint32_t>(d.varint());
  v.group = static_cast<std::uint32_t>(d.varint());
  return v;
}

void Match::encode(facts::Encoder &e) const {
  e.varint(a);
  e.varint(b);
  facts::encode(e, tier);
  put_float(e, confidence);
  put_float(e, similarity);
  facts::encode(e, state);
  facts::encode(e, unchanged);
  evidence.encode(e);
}
Match Match::decode(facts::Decoder &d) {
  Match m;
  m.a = d.varint();
  m.b = d.varint();
  m.tier = facts::decode<Tier>(d);
  m.confidence = get_float(d);
  m.similarity = get_float(d);
  m.state = facts::decode<MatchState>(d);
  m.unchanged = facts::decode<bool>(d);
  m.evidence = Evidence::decode(d);
  return m;
}

void Candidate::encode(facts::Encoder &e) const {
  e.varint(entry);
  facts::encode(e, tier);
  put_float(e, score);
}
Candidate Candidate::decode(facts::Decoder &d) {
  Candidate c;
  c.entry = d.varint();
  c.tier = facts::decode<Tier>(d);
  c.score = get_float(d);
  return c;
}

void Unmatched::encode(facts::Encoder &e) const {
  e.varint(entry);
  facts::encode(e, reason);
  facts::encode(e, candidates);
}
Unmatched Unmatched::decode(facts::Decoder &d) {
  Unmatched u;
  u.entry = d.varint();
  u.reason = facts::decode<UnmatchedReason>(d);
  u.candidates = facts::decode<std::vector<Candidate>>(d);
  return u;
}

const Match *MatchResult::by_a(std::uint64_t a) const {
  auto it = std::lower_bound(matches.begin(), matches.end(), a, [](const Match &m, std::uint64_t x) { return m.a < x; });
  return it != matches.end() && it->a == a ? &*it : nullptr;
}

const Match *MatchResult::by_b(std::uint64_t b) const {
  for (const Match &m : matches)
    if (m.b == b) return &m;
  return nullptr;
}

void MatchResult::encode(facts::Encoder &e) const {
  facts::encode(e, matches);
  facts::encode(e, unmatched_a);
  facts::encode(e, unmatched_b);
  e.varint(functions_a);
  e.varint(functions_b);
  e.varint(rounds);
  facts::encode(e, conflicting_seeds);
}
MatchResult MatchResult::decode(facts::Decoder &d) {
  MatchResult r;
  r.matches = facts::decode<std::vector<Match>>(d);
  r.unmatched_a = facts::decode<std::vector<Unmatched>>(d);
  r.unmatched_b = facts::decode<std::vector<Unmatched>>(d);
  r.functions_a = static_cast<std::uint32_t>(d.varint());
  r.functions_b = static_cast<std::uint32_t>(d.varint());
  r.rounds = static_cast<std::uint32_t>(d.varint());
  r.conflicting_seeds = facts::decode<std::vector<std::pair<std::uint64_t, std::uint64_t>>>(d);
  return r;
}

void SessionKey::encode(facts::Encoder &e) const {
  e.bytes(session);
  e.bytes(program_a);
  e.bytes(program_b);
  facts::encode(e, similarity);
}
SessionKey SessionKey::decode(facts::Decoder &d) {
  SessionKey k;
  k.session = std::string(d.bytes());
  k.program_a = std::string(d.bytes());
  k.program_b = std::string(d.bytes());
  k.similarity = facts::decode<std::vector<std::string>>(d);
  return k;
}

void ProposalKey::encode(facts::Encoder &e) const {
  e.bytes(program_a);
  e.bytes(program_b);
  facts::encode(e, similarity);
}
ProposalKey ProposalKey::decode(facts::Decoder &d) {
  ProposalKey k;
  k.program_a = std::string(d.bytes());
  k.program_b = std::string(d.bytes());
  k.similarity = facts::decode<std::vector<std::string>>(d);
  return k;
}

// ---- Match assertions ----

namespace {
std::string Hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}
std::optional<std::uint64_t> ParseHex(std::string_view s) {
  if (!s.starts_with("0x")) return std::nullopt;
  s.remove_prefix(2);
  std::uint64_t v = 0;
  auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v, 16);
  if (ec != std::errc() || p != s.data() + s.size() || s.empty()) return std::nullopt;
  return v;
}
std::vector<std::string_view> Words(std::string_view s) {
  std::vector<std::string_view> out;
  while (!s.empty()) {
    auto sp = s.find(' ');
    if (sp != 0) out.push_back(s.substr(0, sp));
    if (sp == std::string_view::npos) break;
    s.remove_prefix(sp + 1);
  }
  return out;
}
}  // namespace

std::string MatchValue::text() const {
  if (rejected) return "rejected";
  char conf[16];
  std::snprintf(conf, sizeof conf, "%.3f", static_cast<double>(confidence));
  return Hex(a) + (state == MatchState::applied ? " applied " : " accepted ") + std::string(to_string(tier)) + " " +
         conf;
}

std::optional<MatchValue> MatchValue::parse(std::string_view text) {
  MatchValue v;
  if (text == "rejected") {
    v.rejected = true;
    return v;
  }
  auto w = Words(text);
  if (w.size() < 2) return std::nullopt;
  auto a = ParseHex(w[0]);
  if (!a) return std::nullopt;
  v.a = *a;
  if (w[1] == "accepted") v.state = MatchState::accepted;
  else if (w[1] == "applied") v.state = MatchState::applied;
  else return std::nullopt;
  if (w.size() >= 3)
    if (auto t = tier_from_string(w[2])) v.tier = *t;
  if (w.size() >= 4) v.confidence = std::strtof(std::string(w[3]).c_str(), nullptr);
  return v;
}

std::string reject_sub(std::string_view session, std::uint64_t a) {
  return std::string(session) + "/reject/" + Hex(a);
}

std::optional<MatchSub> parse_match_sub(std::string_view sub) {
  MatchSub s;
  auto slash = sub.find('/');
  if (slash == std::string_view::npos) {
    if (sub.empty()) return std::nullopt;
    s.session = std::string(sub);
    return s;
  }
  s.session = std::string(sub.substr(0, slash));
  std::string_view rest = sub.substr(slash + 1);
  if (!rest.starts_with("reject/")) return std::nullopt;
  auto a = ParseHex(rest.substr(7));
  if (!a) return std::nullopt;
  s.rejected_a = *a;
  return s;
}

// ---- similarity tier registry ----

namespace {
std::mutex &RegistryMutex() {
  static std::mutex mu;
  return mu;
}
std::map<std::string, std::shared_ptr<SimilarityTier>, std::less<>> &Registry() {
  static auto *r = new std::map<std::string, std::shared_ptr<SimilarityTier>, std::less<>>;
  return *r;
}
}  // namespace

void register_similarity_tier(std::shared_ptr<SimilarityTier> tier) {
  std::lock_guard lock(RegistryMutex());
  Registry()[std::string(tier->name())] = std::move(tier);
}

std::shared_ptr<SimilarityTier> similarity_tier(std::string_view name) {
  std::lock_guard lock(RegistryMutex());
  auto it = Registry().find(name);
  return it == Registry().end() ? nullptr : it->second;
}

// ---- scores ----

namespace {
float Ratio(std::uint32_t x, std::uint32_t y) {
  if (x == 0 && y == 0) return 1;
  return static_cast<float>(std::min(x, y)) / static_cast<float>(std::max(x, y));
}
float Jaccard(const std::vector<std::uint32_t> &x, const std::vector<std::uint32_t> &y) {
  if (x.empty() && y.empty()) return 1;
  std::size_t i = 0, j = 0, both = 0;
  while (i < x.size() && j < y.size()) {
    if (x[i] == y[j]) {
      ++both;
      ++i;
      ++j;
    } else if (x[i] < y[j]) {
      ++i;
    } else {
      ++j;
    }
  }
  return static_cast<float>(both) / static_cast<float>(x.size() + y.size() - both);
}
}  // namespace

float similarity(const FunctionFeatures &a, const FunctionFeatures &b) {
  if (a.bytes == b.bytes || a.pcode == b.pcode) return 1;
  float s = 0.30f * Ratio(a.instructions, b.instructions) + 0.15f * Ratio(a.blocks, b.blocks) +
            0.10f * Ratio(a.edges, b.edges) + 0.10f * Ratio(a.pcode_ops, b.pcode_ops) +
            0.05f * (a.opcodes == b.opcodes ? 1.f : 0.f) + 0.05f * (a.shape == b.shape ? 1.f : 0.f) +
            0.25f * Jaccard(a.bag, b.bag);
  return std::min(s, 0.999f);
}

float confidence(Tier tier, Relation relation, float parent, float sim) {
  // Precision observed per tier, relation and similarity band on the
  // tuning corpus's version-diff families ((a) and (e), docs/diff.md
  // "Calibration"), rounded down.
  const bool caller = relation == Relation::caller;
  const bool neighbourhood = relation == Relation::callee || caller || relation == Relation::string ||
                             relation == Relation::data;
  const int band = sim >= 0.9f ? 2 : sim >= 0.8f ? 1 : sim >= 0.7f ? 0 : -1;
  auto pick = [&](float hi, float mid, float lo, float low) {
    return band == 2 ? hi : band == 1 ? mid : band == 0 ? lo : low;
  };
  float base = 0;
  switch (tier) {
    case Tier::accepted: return 1;
    case Tier::name: return 1;
    case Tier::bytes: base = neighbourhood || relation == Relation::residue ? 0.985f : 0.99f; break;
    case Tier::pcode: base = neighbourhood ? 0.975f : 0.98f; break;
    case Tier::shape_refs: base = pick(0.96f, 0.93f, 0.85f, 0.8f); break;
    case Tier::shape:
      base = caller ? pick(0.9f, 0.85f, 0.7f, 0.6f) : pick(0.95f, 0.92f, 0.8f, 0.7f);
      break;
    case Tier::refs:
      base = caller ? pick(0.88f, 0.85f, 0.7f, 0.6f)
             : neighbourhood ? pick(0.93f, 0.9f, 0.75f, 0.65f)
                             : pick(0.95f, 0.93f, 0.8f, 0.7f);
      break;
    case Tier::call_order: base = pick(0.96f, 0.96f, 0.92f, 0.85f); break;
    case Tier::lone: base = pick(0.93f, 0.93f, 0.8f, 0.7f); break;
    case Tier::neighbour: base = pick(0.92f, 0.9f, 0.8f, 0.6f); break;
    case Tier::similarity: base = 0.7f; break;
    case Tier::none: return 0;
  }
  if (neighbourhood) base *= 0.97f + 0.03f * std::clamp(parent, 0.f, 1.f);
  return base;
}

// ---- the matcher ----

namespace {

constexpr std::int32_t kNone = -1;
// The neighbour tier: least similarity, and margin over the runner-up.
constexpr float kNeighbourMin = 0.7f;
constexpr float kNeighbourMargin = 0.15f;
// Global matches needing the call graph's agreement to be applied
// automatically: exact ones of fewer instructions, and structural ones.
constexpr std::uint32_t kTinyInstructions = 5;
constexpr float kUncorroborated = 0.93f;
// Twins told apart only by where they are: proposed, never applied unasked.
constexpr float kAddressOrder = 0.9f;

struct Side {
  std::vector<const FunctionFeatures *> f;
  std::unordered_map<std::uint64_t, std::uint32_t> index;
  std::vector<std::vector<std::uint32_t>> callees;  // unique, first-call order
  std::vector<std::vector<std::uint32_t>> sites;    // every call site, in order
  std::vector<std::vector<std::uint32_t>> callers;  // unique, by entry
  std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> by_string;
  std::unordered_map<std::uint64_t, std::vector<std::uint32_t>> by_global;
  std::vector<std::int32_t> partner;

  void build(const std::vector<const FunctionFeatures *> &in) {
    for (const FunctionFeatures *x : in)
      if (x && x->entry != 0) f.push_back(x);
    std::sort(f.begin(), f.end(), [](auto *x, auto *y) { return x->entry < y->entry; });
    f.erase(std::unique(f.begin(), f.end(), [](auto *x, auto *y) { return x->entry == y->entry; }), f.end());
    index.reserve(f.size());
    for (std::uint32_t i = 0; i < f.size(); ++i) index.emplace(f[i]->entry, i);
    callees.resize(f.size());
    sites.resize(f.size());
    callers.resize(f.size());
    partner.assign(f.size(), kNone);
    for (std::uint32_t i = 0; i < f.size(); ++i) {
      for (std::uint64_t c : f[i]->calls) {
        auto it = index.find(c);
        if (it == index.end() || it->second == i) continue;
        sites[i].push_back(it->second);
        if (std::find(callees[i].begin(), callees[i].end(), it->second) == callees[i].end())
          callees[i].push_back(it->second);
      }
      for (std::uint32_t c : callees[i]) callers[c].push_back(i);
      for (std::uint32_t s : f[i]->strings) by_string[s].push_back(i);
      for (std::uint64_t g : f[i]->globals) by_global[g].push_back(i);
    }
  }
  bool free(std::uint32_t i) const { return partner[i] == kNone; }
};

// A fingerprint a tier compares, for global buckets or neighbourhoods.
struct Probe {
  Tier tier;
  std::optional<std::uint64_t> (*key)(const FunctionFeatures &, const MatchOptions &);
};

std::optional<std::uint64_t> KeyName(const FunctionFeatures &f, const MatchOptions &) {
  if (f.name.empty()) return std::nullopt;
  return Hasher().u64(1).str(f.name).done();
}
std::optional<std::uint64_t> KeyBytes(const FunctionFeatures &f, const MatchOptions &) {
  if (f.instructions == 0) return std::nullopt;
  return f.bytes;
}
std::optional<std::uint64_t> KeyPcode(const FunctionFeatures &f, const MatchOptions &) {
  if (f.instructions == 0) return std::nullopt;
  return f.pcode;
}
std::optional<std::uint64_t> KeyShapeRefs(const FunctionFeatures &f, const MatchOptions &) {
  if (f.instructions == 0) return std::nullopt;
  return Hasher().u64(f.shape).u64(f.opcodes).u64(f.refs).done();
}
std::optional<std::uint64_t> KeyBigShape(const FunctionFeatures &f, const MatchOptions &o) {
  if (f.blocks < o.min_shape_blocks) return std::nullopt;
  return f.shape;
}
std::optional<std::uint64_t> KeyRichRefs(const FunctionFeatures &f, const MatchOptions &o) {
  if (f.bag.size() < o.min_refs) return std::nullopt;
  return f.refs;
}
std::optional<std::uint64_t> KeyShapeOpcodes(const FunctionFeatures &f, const MatchOptions &) {
  if (f.instructions == 0) return std::nullopt;
  return Hasher().u64(f.shape).u64(f.opcodes).done();
}
std::optional<std::uint64_t> KeyRefs(const FunctionFeatures &f, const MatchOptions &) {
  if (f.refs == 0) return std::nullopt;
  return f.refs;
}
std::optional<std::uint64_t> KeyShape(const FunctionFeatures &f, const MatchOptions &) {
  if (f.blocks < 3) return std::nullopt;
  return f.shape;
}

constexpr Probe kGlobal[] = {
    {Tier::name, KeyName},          {Tier::bytes, KeyBytes},     {Tier::pcode, KeyPcode},
    {Tier::shape_refs, KeyShapeRefs}, {Tier::shape, KeyBigShape}, {Tier::refs, KeyRichRefs},
};
constexpr Probe kLocal[] = {
    {Tier::bytes, KeyBytes},          {Tier::pcode, KeyPcode}, {Tier::shape_refs, KeyShapeRefs},
    {Tier::shape, KeyShapeOpcodes},   {Tier::refs, KeyRefs},   {Tier::shape, KeyShape},
};
// Candidates for an unmatched function: the exact probes, then the looser ones.
constexpr Probe kCandidates[] = {
    {Tier::bytes, KeyBytes}, {Tier::pcode, KeyPcode}, {Tier::shape_refs, KeyShapeRefs},
    {Tier::shape, KeyShapeOpcodes}, {Tier::refs, KeyRefs}, {Tier::shape, KeyShape},
};

bool LooselySimilar(const FunctionFeatures &a, const FunctionFeatures &b) {
  if (a.thunk != b.thunk) return false;
  if (Ratio(a.instructions, b.instructions) < 0.5f) return false;
  if (std::max(a.blocks, b.blocks) > 3 && Ratio(a.blocks, b.blocks) < 0.5f) return false;
  return true;
}

struct Proposal {
  std::uint32_t a, b;
  Tier tier;
  Relation relation;
  float confidence;
  std::uint64_t parent_a, parent_b;
  std::uint32_t group;
};

// Better proposal first: higher confidence, then the better tier.
bool Better(const Proposal &x, const Proposal &y) {
  if (x.confidence != y.confidence) return x.confidence > y.confidence;
  return x.tier < y.tier;
}

class Matcher {
 public:
  Matcher(const MatchInput &in, const ResidueFn &residue) : in_(in), residue_(residue) {
    A_.build(in.a);
    B_.build(in.b);
    out_.functions_a = static_cast<std::uint32_t>(A_.f.size());
    out_.functions_b = static_cast<std::uint32_t>(B_.f.size());
  }

  MatchResult run() {
    seeds();
    global(Relation::global);
    loop(1);
    finish();
    return std::move(out_);
  }

  // The proposals of an earlier run without decisions, with the session's
  // decisions applied: accepted pairs replace the proposals they conflict
  // with, rejected pairs are dropped, and propagation runs again from what
  // changed only (the functions freed or newly matched, and their
  // neighbourhoods), so a decision costs milliseconds, not a re-match.
  MatchResult refine(const MatchResult &base) {
    dirty_mode_ = true;
    dirty_a_.assign(A_.f.size(), 0);
    dirty_b_.assign(B_.f.size(), 0);
    seeds();
    for (const Match &m : base.matches) {
      auto ia = A_.index.find(m.a);
      auto ib = B_.index.find(m.b);
      if (ia == A_.index.end() || ib == B_.index.end()) continue;
      const std::uint32_t a = ia->second, b = ib->second;
      if (!A_.free(a) || !B_.free(b) || blocked(a, b)) {
        if (A_.free(a)) dirty_a_[a] = 1;
        if (B_.free(b)) dirty_b_[b] = 1;
        continue;
      }
      A_.partner[a] = static_cast<std::int32_t>(b);
      B_.partner[b] = static_cast<std::int32_t>(a);
      matched_.push_back(m);
    }
    loop(base.rounds + 1);
    finish(&base);
    return std::move(out_);
  }

 private:
  void loop(std::uint32_t first_round) {
    int residue_calls = 0;
    const std::uint32_t max_rounds = first_round + std::max<std::uint32_t>(1, in_.options.max_rounds) - 1;
    for (round_ = first_round; round_ <= max_rounds; ++round_) {
      std::size_t added = 0;
      if (in_.options.propagate) added += resolve(propagate());
      if (dirty_mode_) {
        // What this round matched is what the next one starts from.
        dirty_a_.swap(next_a_);
        dirty_b_.swap(next_b_);
        next_a_.assign(A_.f.size(), 0);
        next_b_.assign(B_.f.size(), 0);
      }
      added += global(Relation::residue);
      if (added == 0 && residue_ && residue_calls < 2) {
        ++residue_calls;
        added += similar();
      }
      if (added == 0 && in_.options.propagate) added += address_order();
      if (added == 0) break;
    }
    out_.rounds = std::min(round_, max_rounds);
  }

  // In refine: whether a matched pair's neighbourhoods can have changed,
  // i.e. it or a function it calls, is called by or shares a global with
  // changed since the last round.
  bool active(std::uint32_t a, std::uint32_t b) const {
    if (!dirty_mode_) return true;
    auto touched = [](const Side &s, const std::vector<char> &dirty, std::uint32_t x) {
      if (dirty[x]) return true;
      for (std::uint32_t y : s.callees[x])
        if (dirty[y]) return true;
      for (std::uint32_t y : s.callers[x])
        if (dirty[y]) return true;
      for (std::uint64_t g : s.f[x]->globals)
        if (auto it = s.by_global.find(g); it != s.by_global.end() && it->second.size() <= 64)
          for (std::uint32_t y : it->second)
            if (dirty[y]) return true;
      return false;
    };
    return touched(A_, dirty_a_, a) || touched(B_, dirty_b_, b);
  }

 private:
  bool blocked(std::uint32_t a, std::uint32_t b) const {
    return !in_.blocked.empty() && in_.blocked.contains({A_.f[a]->entry, B_.f[b]->entry});
  }

  void add(std::uint32_t a, std::uint32_t b, Tier tier, Relation relation, float conf, std::uint64_t pa,
           std::uint64_t pb, std::uint32_t group, MatchState state = MatchState::proposed) {
    A_.partner[a] = static_cast<std::int32_t>(b);
    B_.partner[b] = static_cast<std::int32_t>(a);
    if (dirty_mode_) {
      // Seeds are this round's news; propagation's finds are the next's.
      auto &da = state == MatchState::proposed ? next_a_ : dirty_a_;
      auto &db = state == MatchState::proposed ? next_b_ : dirty_b_;
      if (da.size() < A_.f.size()) da.resize(A_.f.size(), 0);
      if (db.size() < B_.f.size()) db.resize(B_.f.size(), 0);
      da[a] = 1;
      db[b] = 1;
    }
    Match m;
    m.a = A_.f[a]->entry;
    m.b = B_.f[b]->entry;
    m.tier = tier;
    m.state = state;
    m.unchanged = A_.f[a]->bytes == B_.f[b]->bytes && A_.f[a]->instructions > 0;
    m.similarity = similarity(*A_.f[a], *B_.f[b]);
    m.confidence = conf;
    m.evidence = {tier, relation, pa, pb, round_, group};
    matched_.push_back(std::move(m));
  }

  void seeds() {
    std::vector<Seed> s = in_.seeds;
    std::sort(s.begin(), s.end(), [](const Seed &x, const Seed &y) { return std::pair(x.a, x.b) < std::pair(y.a, y.b); });
    for (const Seed &seed : s) {
      auto ia = A_.index.find(seed.a);
      auto ib = B_.index.find(seed.b);
      if (ia == A_.index.end() || ib == B_.index.end() || !A_.free(ia->second) || !B_.free(ib->second)) {
        out_.conflicting_seeds.emplace_back(seed.a, seed.b);
        continue;
      }
      const Tier tier = seed.state == MatchState::applied ? seed.tier : Tier::accepted;
      const float conf = seed.state == MatchState::applied ? seed.confidence : 1.f;
      add(ia->second, ib->second, tier, Relation::seed, conf, 0, 0, 1, seed.state);
    }
  }

  // Unique buckets over every unmatched function, tier by tier.
  std::size_t global(Relation relation) {
    std::size_t added = 0;
    for (const Probe &p : kGlobal) {
      std::unordered_map<std::uint64_t, std::pair<std::uint32_t, std::uint32_t>> ka, kb;  // key -> (count, index)
      for (std::uint32_t i = 0; i < A_.f.size(); ++i)
        if (A_.free(i))
          if (auto k = p.key(*A_.f[i], in_.options)) {
            auto &e = ka[*k];
            if (e.first++ == 0) e.second = i;
          }
      if (ka.empty()) continue;
      for (std::uint32_t j = 0; j < B_.f.size(); ++j)
        if (B_.free(j))
          if (auto k = p.key(*B_.f[j], in_.options)) {
            auto &e = kb[*k];
            if (e.first++ == 0) e.second = j;
          }
      std::vector<std::pair<std::uint32_t, std::uint32_t>> pairs;
      for (const auto &[k, ea] : ka) {
        if (ea.first != 1) continue;
        auto it = kb.find(k);
        if (it == kb.end() || it->second.first != 1) continue;
        pairs.emplace_back(ea.second, it->second.second);
      }
      std::sort(pairs.begin(), pairs.end());
      for (auto [a, b] : pairs) {
        if (blocked(a, b)) continue;
        add(a, b, p.tier, relation, confidence(p.tier, relation, 1, similarity(*A_.f[a], *B_.f[b])), 0, 0, 1);
        ++added;
      }
    }
    return added;
  }

  // Unique fingerprints within one neighbourhood, then (callees) call-site
  // order, then a lone pair.
  void neighbourhood(std::vector<std::uint32_t> na, std::vector<std::uint32_t> nb, Relation relation, float parent,
                     std::uint64_t pa, std::uint64_t pb, std::vector<Proposal> &out) {
    if (na.empty() || nb.empty()) return;
    const std::uint32_t group = static_cast<std::uint32_t>(std::max(na.size(), nb.size()));
    for (const Probe &p : kLocal) {
      if (na.empty() || nb.empty()) break;
      std::unordered_map<std::uint64_t, std::pair<std::uint32_t, std::uint32_t>> ka, kb;
      for (std::uint32_t i : na)
        if (auto k = p.key(*A_.f[i], in_.options)) {
          auto &e = ka[*k];
          if (e.first++ == 0) e.second = i;
        }
      if (ka.empty()) continue;
      for (std::uint32_t j : nb)
        if (auto k = p.key(*B_.f[j], in_.options)) {
          auto &e = kb[*k];
          if (e.first++ == 0) e.second = j;
        }
      std::vector<std::pair<std::uint32_t, std::uint32_t>> pairs;
      for (const auto &[k, ea] : ka) {
        if (ea.first != 1) continue;
        auto it = kb.find(k);
        if (it == kb.end() || it->second.first != 1) continue;
        if (blocked(ea.second, it->second.second)) continue;
        pairs.emplace_back(ea.second, it->second.second);
      }
      for (auto [a, b] : pairs) {
        out.push_back({a, b, p.tier, relation,
                       confidence(p.tier, relation, parent, similarity(*A_.f[a], *B_.f[b])), pa, pb, group});
        std::erase(na, a);
        std::erase(nb, b);
      }
    }
    // The most similar functions of the two sides, each the other's best by
    // a margin.
    if (!na.empty() && !nb.empty() && na.size() <= 48 && nb.size() <= 48) {
      std::vector<std::vector<float>> sim(na.size(), std::vector<float>(nb.size()));
      for (std::size_t i = 0; i < na.size(); ++i)
        for (std::size_t j = 0; j < nb.size(); ++j)
          sim[i][j] = LooselySimilar(*A_.f[na[i]], *B_.f[nb[j]]) ? similarity(*A_.f[na[i]], *B_.f[nb[j]]) : 0.f;
      auto best = [](const std::vector<float> &row, std::size_t &at) {
        float b1 = -1, b2 = -1;
        for (std::size_t k = 0; k < row.size(); ++k) {
          if (row[k] > b1) {
            b2 = b1;
            b1 = row[k];
            at = k;
          } else if (row[k] > b2) {
            b2 = row[k];
          }
        }
        return b1 - std::max(b2, 0.f);
      };
      std::vector<std::pair<std::uint32_t, std::uint32_t>> found;
      for (std::size_t i = 0; i < na.size(); ++i) {
        std::size_t j = 0;
        const float margin = best(sim[i], j);
        if (sim[i][j] < kNeighbourMin || margin < kNeighbourMargin) continue;
        std::vector<float> col(na.size());
        for (std::size_t k = 0; k < na.size(); ++k) col[k] = sim[k][j];
        std::size_t back = 0;
        const float margin_b = best(col, back);
        if (back != i || margin_b < kNeighbourMargin || blocked(na[i], nb[j])) continue;
        found.emplace_back(na[i], nb[j]);
        out.push_back({na[i], nb[j], Tier::neighbour, relation, confidence(Tier::neighbour, relation, parent, sim[i][j]),
                       pa, pb, group});
      }
      for (auto [x, y] : found) {
        std::erase(na, x);
        std::erase(nb, y);
      }
    }
    if (na.size() == 1 && nb.size() == 1 && group <= 16 && LooselySimilar(*A_.f[na[0]], *B_.f[nb[0]]) &&
        !blocked(na[0], nb[0]) && (relation == Relation::callee || relation == Relation::caller))
      out.push_back({na[0], nb[0], Tier::lone, relation,
                     confidence(Tier::lone, relation, parent, similarity(*A_.f[na[0]], *B_.f[nb[0]])), pa, pb, group});
  }

  std::vector<std::uint32_t> Free(const Side &s, const std::vector<std::uint32_t> &list) {
    std::vector<std::uint32_t> out;
    for (std::uint32_t i : list)
      if (s.free(i)) out.push_back(i);
    return out;
  }

  std::vector<Proposal> propagate() {
    std::vector<Proposal> out;
    for (const Match &m : matched_) {
      const std::uint32_t a = A_.index.at(m.a), b = B_.index.at(m.b);
      if (!active(a, b)) continue;
      const float parent = m.confidence;
      // Callees: call-site order first, where both sides' sites line up.
      {
        const auto &sa = A_.sites[a], &sb = B_.sites[b];
        if (!sa.empty() && sa.size() == sb.size() && sa.size() <= 256) {
          bool aligned = true;
          std::vector<std::pair<std::uint32_t, std::uint32_t>> pairs;
          for (std::size_t k = 0; k < sa.size() && aligned; ++k) {
            const bool fa = A_.free(sa[k]), fb = B_.free(sb[k]);
            if (!fa && !fb) aligned = A_.partner[sa[k]] == static_cast<std::int32_t>(sb[k]);
            else if (fa && fb) pairs.emplace_back(sa[k], sb[k]);
            else aligned = false;
          }
          if (aligned && !pairs.empty()) {
            std::sort(pairs.begin(), pairs.end());
            pairs.erase(std::unique(pairs.begin(), pairs.end()), pairs.end());
            // One A callee at two positions paired differently: not aligned.
            bool consistent = true;
            for (std::size_t k = 1; k < pairs.size(); ++k)
              if (pairs[k].first == pairs[k - 1].first) consistent = false;
            std::vector<std::uint32_t> bs;
            for (auto &p : pairs) bs.push_back(p.second);
            std::sort(bs.begin(), bs.end());
            if (std::adjacent_find(bs.begin(), bs.end()) != bs.end()) consistent = false;
            if (consistent)
              for (auto [x, y] : pairs)
                if (LooselySimilar(*A_.f[x], *B_.f[y]) && !blocked(x, y))
                  out.push_back({x, y, Tier::call_order, Relation::callee,
                                 confidence(Tier::call_order, Relation::callee, parent,
                                            similarity(*A_.f[x], *B_.f[y])),
                                 m.a, m.b,
                                 static_cast<std::uint32_t>(sa.size())});
          }
        }
      }
      neighbourhood(Free(A_, A_.callees[a]), Free(B_, B_.callees[b]), Relation::callee, parent, m.a, m.b, out);
      neighbourhood(Free(A_, A_.callers[a]), Free(B_, B_.callers[b]), Relation::caller, parent, m.a, m.b, out);
      // Globals the pair touches at the same position of its references.
      const auto &ga = A_.f[a]->globals, &gb = B_.f[b]->globals;
      if (ga.size() == gb.size())
        for (std::size_t k = 0; k < ga.size(); ++k) {
          auto xa = A_.by_global.find(ga[k]);
          auto xb = B_.by_global.find(gb[k]);
          if (xa == A_.by_global.end() || xb == B_.by_global.end()) continue;
          if (xa->second.size() > 64 || xb->second.size() > 64) continue;
          neighbourhood(Free(A_, xa->second), Free(B_, xb->second), Relation::data, parent, m.a, m.b, out);
        }
    }
    // Strings: every function reading one string, on each side.
    std::vector<std::uint32_t> strings;
    if (dirty_mode_) {
      // Only strings a changed function reads.
      std::set<std::uint32_t> touched;
      for (std::uint32_t i = 0; i < A_.f.size(); ++i)
        if (dirty_a_[i]) touched.insert(A_.f[i]->strings.begin(), A_.f[i]->strings.end());
      for (std::uint32_t j = 0; j < B_.f.size(); ++j)
        if (dirty_b_[j]) touched.insert(B_.f[j]->strings.begin(), B_.f[j]->strings.end());
      for (std::uint32_t s : touched)
        if (A_.by_string.contains(s) && B_.by_string.contains(s)) strings.push_back(s);
    } else {
      for (const auto &[s, users] : A_.by_string)
        if (B_.by_string.contains(s)) strings.push_back(s);
    }
    std::sort(strings.begin(), strings.end());
    for (std::uint32_t s : strings) {
      const auto &ua = A_.by_string.at(s), &ub = B_.by_string.at(s);
      if (ua.size() > 64 || ub.size() > 64) continue;
      neighbourhood(Free(A_, ua), Free(B_, ub), Relation::string, 1.f, 0, 0, out);
    }
    return out;
  }

  // Decides a round's proposals together: for each function the best
  // proposal (the same pair proposed twice counts once); a function with
  // two different best partners gets neither.
  std::size_t resolve(std::vector<Proposal> props) {
    if (props.empty()) return 0;
    std::unordered_map<std::uint32_t, std::size_t> best_a, best_b;
    std::unordered_set<std::uint32_t> tied_a, tied_b;
    auto pick = [&](std::unordered_map<std::uint32_t, std::size_t> &best, std::unordered_set<std::uint32_t> &tied,
                    std::uint32_t key, std::size_t i, bool side_a) {
      auto it = best.find(key);
      if (it == best.end()) {
        best.emplace(key, i);
        return;
      }
      const Proposal &cur = props[it->second], &x = props[i];
      const bool same = cur.a == x.a && cur.b == x.b;
      if (Better(x, cur)) {
        it->second = i;
        if (!same) tied.erase(key);
      } else if (!Better(cur, x) && !same) {
        tied.insert(key);
      }
      (void)side_a;
    };
    // Deterministic order: by (a, b, tier, relation, parent).
    std::sort(props.begin(), props.end(), [](const Proposal &x, const Proposal &y) {
      return std::tie(x.a, x.b, x.tier, x.relation, x.parent_a, x.parent_b) <
             std::tie(y.a, y.b, y.tier, y.relation, y.parent_a, y.parent_b);
    });
    for (std::size_t i = 0; i < props.size(); ++i) {
      pick(best_a, tied_a, props[i].a, i, true);
      pick(best_b, tied_b, props[i].b, i, false);
    }
    // A proposal outranked on one side by a different pair is dropped; a
    // tie at the top on either side drops the function's proposals.
    std::vector<std::size_t> chosen;
    for (const auto &[a, i] : best_a) {
      if (tied_a.contains(a)) continue;
      const Proposal &p = props[i];
      auto jb = best_b.find(p.b);
      if (jb == best_b.end() || tied_b.contains(p.b)) continue;
      const Proposal &q = props[jb->second];
      if (q.a != p.a || q.b != p.b) continue;
      chosen.push_back(i);
    }
    std::sort(chosen.begin(), chosen.end());
    std::size_t added = 0;
    for (std::size_t i : chosen) {
      const Proposal &p = props[i];
      if (!A_.free(p.a) || !B_.free(p.b)) continue;
      add(p.a, p.b, p.tier, p.relation, p.confidence, p.parent_a, p.parent_b, p.group);
      ++added;
    }
    return added;
  }

  // Candidates for each unmatched function on one side: shared buckets
  // among the other side's unmatched functions, then the unmatched
  // neighbours of its matched neighbours' partners; ranked by similarity.
  void candidates(const Side &mine, const Side &other, std::vector<Unmatched> &out,
                  std::vector<std::vector<std::uint64_t>> *lists, const std::vector<char> *only = nullptr) {
    std::vector<std::unordered_map<std::uint64_t, std::vector<std::uint32_t>>> buckets(std::size(kCandidates));
    for (std::size_t p = 0; p < std::size(kCandidates); ++p)
      for (std::uint32_t j = 0; j < other.f.size(); ++j)
        if (other.free(j))
          if (auto k = kCandidates[p].key(*other.f[j], in_.options)) buckets[p][*k].push_back(j);
    for (std::uint32_t i = 0; i < mine.f.size(); ++i) {
      if (!mine.free(i) || (only && !(*only)[i])) continue;
      Unmatched u;
      u.entry = mine.f[i]->entry;
      std::map<std::uint32_t, Tier> found;  // other index -> best tier
      bool tie = false;
      for (std::size_t p = 0; p < std::size(kCandidates) && found.size() < MatchResult::kMaxCandidates; ++p) {
        auto k = kCandidates[p].key(*mine.f[i], in_.options);
        if (!k) continue;
        auto it = buckets[p].find(*k);
        if (it == buckets[p].end()) continue;
        if (p < 3) tie = true;  // shares an exact fingerprint, yet unmatched: ambiguous
        for (std::uint32_t j : it->second) {
          found.emplace(j, kCandidates[p].tier);
          if (found.size() >= 2 * MatchResult::kMaxCandidates) break;
        }
      }
      // Neighbours of matched neighbours.
      auto near = [&](const std::vector<std::vector<std::uint32_t>> &mine_rel,
                      const std::vector<std::vector<std::uint32_t>> &other_rel) {
        for (std::uint32_t n : mine_rel[i]) {
          if (mine.free(n)) continue;
          const std::uint32_t m = static_cast<std::uint32_t>(mine.partner[n]);
          // The relation is symmetric: n calls i <=> i is n's callee.
          for (std::uint32_t c : other_rel[m])
            if (other.free(c) && found.size() < 2 * MatchResult::kMaxCandidates) found.emplace(c, Tier::none);
        }
      };
      near(mine.callers, other.callees);
      near(mine.callees, other.callers);
      std::vector<Candidate> cs;
      for (const auto &[j, tier] : found)
        cs.push_back({other.f[j]->entry, tier, similarity(*mine.f[i], *other.f[j])});
      std::sort(cs.begin(), cs.end(), [](const Candidate &x, const Candidate &y) {
        if (x.score != y.score) return x.score > y.score;
        return x.entry < y.entry;
      });
      if (cs.size() > MatchResult::kMaxCandidates) cs.resize(MatchResult::kMaxCandidates);
      u.reason = cs.empty() ? UnmatchedReason::no_candidate : tie ? UnmatchedReason::tie : UnmatchedReason::weak;
      if (lists) {
        std::vector<std::uint64_t> l;
        for (const Candidate &c : cs) l.push_back(c.entry);
        lists->push_back(std::move(l));
      }
      u.candidates = std::move(cs);
      out.push_back(std::move(u));
    }
  }

  // Identical code that nothing else tells apart (the same bytes or p-code
  // twice, as a template or a copy-pasted helper makes): between two
  // matched functions, unmatched functions that are the same on both sides,
  // in the same order and as many, pair in address order. BinDiff's
  // "address sequence".
  std::size_t address_order() {
    std::size_t added = 0;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> found;
    auto same = [&](std::uint32_t a, std::uint32_t b) {
      const FunctionFeatures &x = *A_.f[a], &y = *B_.f[b];
      return x.instructions > 0 && (x.bytes == y.bytes || x.pcode == y.pcode) && !blocked(a, b);
    };
    std::int64_t pa = -1, pb = -1;  // the last matched pair, in A's order
    auto gap = [&](std::int64_t from_a, std::int64_t to_a, std::int64_t from_b, std::int64_t to_b) {
      // Places mean nothing without a matched function to count from.
      if (from_a < 0 && to_a >= static_cast<std::int64_t>(A_.f.size())) return;
      std::vector<std::uint32_t> ga, gb;
      for (std::int64_t i = from_a + 1; i < to_a; ++i)
        if (A_.free(static_cast<std::uint32_t>(i))) ga.push_back(static_cast<std::uint32_t>(i));
      for (std::int64_t i = from_b + 1; i < to_b; ++i)
        if (B_.free(static_cast<std::uint32_t>(i))) gb.push_back(static_cast<std::uint32_t>(i));
      if (ga.empty() || ga.size() != gb.size()) return;
      for (std::size_t k = 0; k < ga.size(); ++k)
        if (!same(ga[k], gb[k])) return;
      for (std::size_t k = 0; k < ga.size(); ++k) found.emplace_back(ga[k], gb[k]);
    };
    for (std::uint32_t a = 0; a < A_.f.size(); ++a) {
      if (A_.free(a)) continue;
      const std::int64_t b = A_.partner[a];
      if (b > pb) gap(pa, a, pb, b);  // keep to pairs in the same order on both sides
      if (b > pb) pa = a, pb = b;
    }
    gap(pa, static_cast<std::int64_t>(A_.f.size()), pb, static_cast<std::int64_t>(B_.f.size()));
    for (auto [a, b] : found) {
      const Tier tier = A_.f[a]->bytes == B_.f[b]->bytes ? Tier::bytes : Tier::pcode;
      add(a, b, tier, Relation::address, kAddressOrder, 0, 0, 1);
      ++added;
    }
    return added;
  }

  std::size_t similar() {
    ResidueRequest req;
    for (std::uint32_t i = 0; i < A_.f.size(); ++i)
      if (A_.free(i)) req.unmatched_a.push_back(A_.f[i]);
    for (std::uint32_t j = 0; j < B_.f.size(); ++j)
      if (B_.free(j)) req.unmatched_b.push_back(B_.f[j]);
    if (req.unmatched_a.empty() || req.unmatched_b.empty()) return 0;
    std::vector<Unmatched> scratch;
    candidates(A_, B_, scratch, &req.candidates);
    for (const Match &m : matched_) req.matched.emplace_back(m.a, m.b, m.confidence);
    std::vector<ScoredPair> scored = residue_(req);
    std::vector<Proposal> props;
    std::map<std::pair<std::uint32_t, std::uint32_t>, float> sim;
    for (const ScoredPair &s : scored) {
      if (!s.accept) continue;
      auto ia = A_.index.find(s.a);
      auto ib = B_.index.find(s.b);
      if (ia == A_.index.end() || ib == B_.index.end()) continue;
      if (!A_.free(ia->second) || !B_.free(ib->second) || blocked(ia->second, ib->second)) continue;
      props.push_back({ia->second, ib->second, Tier::similarity, Relation::similar, s.confidence, 0, 0, 1});
      sim[{ia->second, ib->second}] = s.similarity;
    }
    const std::size_t before = matched_.size();
    const std::size_t added = resolve(std::move(props));
    for (std::size_t k = before; k < matched_.size(); ++k) {
      auto it = sim.find({A_.index.at(matched_[k].a), B_.index.at(matched_[k].b)});
      if (it != sim.end()) matched_[k].similarity = it->second;
    }
    return added;
  }

  // Whether a matched pair's call graph agrees: a caller (callee) of one
  // matched to a caller (callee) of the other.
  bool corroborated(std::uint32_t a, std::uint32_t b) const {
    auto agree = [&](const std::vector<std::uint32_t> &xa, const std::vector<std::uint32_t> &xb) {
      for (std::uint32_t c : xa) {
        if (A_.free(c)) continue;
        const auto p = static_cast<std::uint32_t>(A_.partner[c]);
        if (std::find(xb.begin(), xb.end(), p) != xb.end()) return true;
      }
      return false;
    };
    return agree(A_.callers[a], B_.callers[b]) || agree(A_.callees[a], B_.callees[b]);
  }

  // The unmatched functions with their candidates. In refine, those the
  // base had keep its candidates (less any matched since), and only the
  // functions the decisions freed are looked up afresh.
  void finish_unmatched(const MatchResult *base) {
    if (!base) {
      candidates(A_, B_, out_.unmatched_a, nullptr);
      candidates(B_, A_, out_.unmatched_b, nullptr);
      return;
    }
    auto side = [&](const Side &mine, const Side &other, const std::vector<Unmatched> &before, std::vector<Unmatched> &out) {
      std::vector<char> fresh(mine.f.size(), 1);
      for (const Unmatched &u : before) {
        auto it = mine.index.find(u.entry);
        if (it == mine.index.end() || !mine.free(it->second)) continue;
        fresh[it->second] = 0;
        Unmatched kept = u;
        std::erase_if(kept.candidates, [&](const Candidate &c) {
          auto o = other.index.find(c.entry);
          return o == other.index.end() || !other.free(o->second);
        });
        if (kept.candidates.empty()) kept.reason = UnmatchedReason::no_candidate;
        out.push_back(std::move(kept));
      }
      std::vector<Unmatched> more;
      candidates(mine, other, more, nullptr, &fresh);
      out.insert(out.end(), std::make_move_iterator(more.begin()), std::make_move_iterator(more.end()));
      std::sort(out.begin(), out.end(), [](const Unmatched &x, const Unmatched &y) { return x.entry < y.entry; });
    };
    side(A_, B_, base->unmatched_a, out_.unmatched_a);
    side(B_, A_, base->unmatched_b, out_.unmatched_b);
  }

  bool unchanged(std::uint32_t a, std::uint32_t b) const {
    const FunctionFeatures &x = *A_.f[a], &y = *B_.f[b];
    if (x.instructions == 0) return false;
    if (x.entry == y.entry && x.raw == y.raw) return true;
    if (x.bytes != y.bytes || x.calls.size() != y.calls.size()) return false;
    for (std::size_t k = 0; k < x.calls.size(); ++k) {
      auto ia = A_.index.find(x.calls[k]);
      auto ib = B_.index.find(y.calls[k]);
      if (ia != A_.index.end() && ib != B_.index.end() && A_.partner[ia->second] >= 0) {
        if (A_.partner[ia->second] != static_cast<std::int32_t>(ib->second)) return false;
      } else if (x.calls[k] - x.entry != y.calls[k] - y.entry) {
        return false;
      }
    }
    return true;
  }

  void finish(const MatchResult *base = nullptr) {
    // Uniqueness alone is weak evidence for tiny functions (stubs returning
    // a constant come and go between versions) and for the structural
    // tiers: without the call graph agreeing, they stay below the
    // auto-apply threshold.
    for (Match &m : matched_) {
      if (m.evidence.relation != Relation::global && m.evidence.relation != Relation::residue) continue;
      const std::uint32_t a = A_.index.at(m.a), b = B_.index.at(m.b);
      const bool exact = m.tier == Tier::bytes || m.tier == Tier::pcode;
      const bool structural = m.tier == Tier::shape_refs || m.tier == Tier::shape || m.tier == Tier::refs;
      const bool tiny = A_.f[a]->instructions < kTinyInstructions;
      if (((exact && tiny) || structural) && !corroborated(a, b)) m.confidence = std::min(m.confidence, kUncorroborated);
    }
    // Whether the code is the same: the same bytes at the same place, or the
    // same bytes but for addresses, each call site calling the functions
    // that match (a patch that only retargets a call changes the code).
    for (Match &m : matched_) {
      const std::uint32_t a = A_.index.at(m.a), b = B_.index.at(m.b);
      m.unchanged = unchanged(a, b);
    }
    std::sort(matched_.begin(), matched_.end(), [](const Match &x, const Match &y) { return x.a < y.a; });
    out_.matches = std::move(matched_);
    finish_unmatched(base);
  }

  const MatchInput &in_;
  const ResidueFn &residue_;
  Side A_, B_;
  std::vector<Match> matched_;
  MatchResult out_;
  // refine(): functions whose neighbourhoods may offer new matches this
  // round, and those matched this round (the next round's).
  bool dirty_mode_ = false;
  std::vector<char> dirty_a_, dirty_b_, next_a_, next_b_;
  std::uint32_t round_ = 0;
};

}  // namespace

MatchResult match(const MatchInput &in, const ResidueFn &residue) { return Matcher(in, residue).run(); }

MatchResult refine(const MatchInput &in, const MatchResult &base, const ResidueFn &residue) {
  if (in.seeds.empty() && in.blocked.empty()) return base;
  return Matcher(in, residue).refine(base);
}

// ---- diff.matches ----

std::size_t Matches::weight(const Value &v) {
  std::size_t w = sizeof(Value) + v.matches.capacity() * sizeof(Match);
  for (const auto *list : {&v.unmatched_a, &v.unmatched_b})
    for (const Unmatched &u : *list) w += sizeof(Unmatched) + u.candidates.capacity() * sizeof(Candidate);
  return w;
}

std::size_t Proposals::weight(const Value &v) { return Matches::weight(v); }

namespace {

std::vector<facts::Ref<FunctionFeatures>> ProgramFeatures(facts::QueryContext &ctx, const std::string &program) {
  auto functions = ctx.get<analysis::Functions>(analysis::ProgramKey{program});
  std::vector<analysis::Location> keys;
  keys.reserve(functions->functions.size());
  for (const analysis::FunctionInfo &f : functions->functions) keys.push_back({{program}, f.entry.offset});
  return ctx.get_all<Features>(keys);
}

// The registered tiers a key names, as the matcher's residue hook.
ResidueFn Residue(facts::QueryContext &ctx, const std::string &a, const std::string &b,
                  const std::vector<std::string> &names, std::vector<std::shared_ptr<SimilarityTier>> &tiers) {
  for (const std::string &name : names)
    if (auto t = similarity_tier(name)) tiers.push_back(std::move(t));
  if (tiers.empty()) return {};
  return [&ctx, a, b, &tiers](const ResidueRequest &req0) {
    ResidueRequest req = req0;
    req.program_a = a;
    req.program_b = b;
    std::vector<ScoredPair> all;
    for (const auto &t : tiers) {
      auto s = t->score(ctx, req);
      all.insert(all.end(), s.begin(), s.end());
    }
    return all;
  };
}

}  // namespace

MatchResult Proposals::compute(facts::QueryContext &ctx, const Key &key) {
  auto fa = ProgramFeatures(ctx, key.program_a);
  auto fb = ProgramFeatures(ctx, key.program_b);
  MatchInput in;
  for (const auto &f : fa) in.a.push_back(f.get());
  for (const auto &f : fb) in.b.push_back(f.get());
  std::vector<std::shared_ptr<SimilarityTier>> tiers;
  return match(in, Residue(ctx, key.program_a, key.program_b, key.similarity, tiers));
}

MatchResult Matches::compute(facts::QueryContext &ctx, const Key &key) {
  auto base = ctx.get<Proposals>(ProposalKey{key.program_a, key.program_b, key.similarity});
  // The session's Match assertions, in B's space.
  MatchInput in;
  auto info_b = ctx.get<analysis::Program>(analysis::ProgramKey{key.program_b});
  const facts::SpaceId space = info_b->space;
  auto buckets = ctx.get<facts::AssertedBuckets>({facts::FactKind::Match, space});
  for (std::uint64_t bucket : *buckets) {
    auto keys = ctx.get<facts::AssertedKeys>(facts::BucketKey{facts::FactKind::Match, space, bucket});
    for (const auto &[offset, sub] : *keys) {
      auto s = parse_match_sub(sub);
      if (!s || s->session != key.session) continue;
      auto value = ctx.get<facts::AssertedFact>(facts::FactKey{facts::FactKind::Match, {space, offset}, sub});
      const auto *text = std::get_if<std::string>(value.get());
      if (!text) continue;
      auto v = MatchValue::parse(*text);
      if (!v) continue;
      if (s->rejected_a) {
        if (v->rejected) in.blocked.emplace(*s->rejected_a, offset);
      } else if (!v->rejected) {
        in.seeds.push_back({v->a, offset, v->state, v->tier, v->confidence});
      }
    }
  }
  if (in.seeds.empty() && in.blocked.empty()) return *base;
  auto fa = ProgramFeatures(ctx, key.program_a);
  auto fb = ProgramFeatures(ctx, key.program_b);
  for (const auto &f : fa) in.a.push_back(f.get());
  for (const auto &f : fb) in.b.push_back(f.get());
  std::vector<std::shared_ptr<SimilarityTier>> tiers;
  return refine(in, *base, Residue(ctx, key.program_a, key.program_b, key.similarity, tiers));
}

void register_queries(facts::Engine &engine) {
  engine.add_query<Features>();
  engine.add_query<Proposals>();
  engine.add_query<Matches>();
  engine.add_query<Code>();
  engine.add_query<Correlate>();
}

}  // namespace revkit::diff
