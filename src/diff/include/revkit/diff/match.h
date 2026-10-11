// Matching the functions of two programs (docs/diff.md; design in
// docs/diff/design.md, section 1): BinDiff-style ordered unique matching
// over the fingerprints of features.h, then propagation through callers,
// callees and data references to a fixpoint, then (M2) a similarity tier
// over what is left.
//
//   1. Seeds: pairs a user accepted or an apply run recorded (Match
//      assertions). Rejected pairs are never proposed.
//   2. Global tiers, in order: name, bytes, p-code, shape+refs, shape (big
//      functions), refs (rich bags). A hash with exactly one unmatched
//      function on each side is a match; a bucket with several on either
//      side is left alone (a tie).
//   3. Propagation: from every matched pair, the unmatched functions each
//      side calls, the ones calling it, the ones reading the same strings
//      and the ones touching the globals the pair touches in the same
//      order form two neighbourhoods; the tiers run again within them
//      (bytes, p-code, shape+refs, shape+opcodes, refs, shape), then
//      call-site order and a lone remaining pair. Every round considers
//      every pair, proposals that conflict are dropped, the global tiers
//      run again over the residue, until nothing changes.
//   4. Residue: registered similarity tiers (SimilarityTier, M2's BSim F5)
//      score the functions still unmatched; pairs they accept become seeds
//      of another propagation.
//
// Everything is deterministic: tiers run in a fixed order, functions are
// visited by entry, a round's proposals are decided together and ties are
// never broken (they stay unmatched, with their candidates).
#pragma once

#include "revkit/diff/features.h"
#include "revkit/facts/engine.h"
#include "revkit/facts/fact_db.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace revkit::diff {

// The evidence class of a match, best first. Values are the API's DiffTier
// numbers.
enum class Tier : std::uint8_t {
  none = 0,
  accepted = 1,    // a Match assertion: accepted by someone, or by an apply run
  name = 2,        // F0
  bytes = 3,       // F1
  pcode = 4,       // F2
  shape_refs = 5,  // F3 + F4
  shape = 6,       // F3 alone (big functions globally; shape+opcodes or shape in a neighbourhood)
  refs = 7,        // F4 alone
  call_order = 8,  // the same position among a matched pair's call sites
  lone = 9,        // the one function left on each side of a neighbourhood
  similarity = 10, // a SimilarityTier (M2)
  neighbour = 11,  // the most similar pair in a neighbourhood, both ways, by a margin
};
std::string_view to_string(Tier t);
std::optional<Tier> tier_from_string(std::string_view s);

// Where a match was found. Values are the API's DiffRelation numbers.
enum class Relation : std::uint8_t {
  global = 1,   // unique over both programs
  residue = 2,  // unique over what was still unmatched after propagation
  callee = 3,   // among the functions a matched pair calls
  caller = 4,   // among the functions calling a matched pair
  string = 5,   // among the functions reading one string
  data = 6,     // among the functions touching a global a matched pair touches in the same place
  seed = 7,     // a Match assertion
  similar = 8,  // a similarity tier over the residue
  address = 9,  // identical twins between the same matched neighbours, paired in address order
};
std::string_view to_string(Relation r);

// A matched pair's standing. Values are the API's DiffMatchStatus numbers.
enum class MatchState : std::uint8_t {
  proposed = 1,  // derived only
  accepted = 2,  // a Match assertion by a user or an agent
  applied = 3,   // a Match assertion by an apply run (provenance migration)
};

struct Evidence {
  Tier tier = Tier::none;
  Relation relation = Relation::global;
  std::uint64_t parent_a = 0, parent_b = 0;  // the pair whose neighbourhood it was found in
  std::uint32_t round = 0;
  std::uint32_t group = 0;  // functions on each side where it was unique (the neighbourhood's or bucket's size)

  void encode(facts::Encoder &e) const;
  static Evidence decode(facts::Decoder &d);
  friend bool operator==(const Evidence &, const Evidence &) = default;
};

struct Match {
  std::uint64_t a = 0, b = 0;  // entries
  Tier tier = Tier::none;
  float confidence = 0;  // 0..1, calibrated on the tuning corpus (docs/diff.md)
  float similarity = 0;  // 1 for equal bytes or p-code, else the cheap structural score (M2: BSim cosine)
  MatchState state = MatchState::proposed;
  bool unchanged = false;  // the same code: equal bytes in place, or equal masked bytes calling matching functions
  Evidence evidence;

  void encode(facts::Encoder &e) const;
  static Match decode(facts::Decoder &d);
  friend bool operator==(const Match &, const Match &) = default;
};

enum class UnmatchedReason : std::uint8_t {
  no_candidate = 1,  // nothing on the other side resembles it
  tie = 2,           // it shares an exact fingerprint with several functions
  weak = 3,          // only structurally similar candidates
};

struct Candidate {
  std::uint64_t entry = 0;
  Tier tier = Tier::none;  // the fingerprint they share, or none (similar only)
  float score = 0;

  void encode(facts::Encoder &e) const;
  static Candidate decode(facts::Decoder &d);
  friend bool operator==(const Candidate &, const Candidate &) = default;
};

struct Unmatched {
  std::uint64_t entry = 0;
  UnmatchedReason reason = UnmatchedReason::no_candidate;
  std::vector<Candidate> candidates;  // best first, at most kMaxCandidates

  void encode(facts::Encoder &e) const;
  static Unmatched decode(facts::Decoder &d);
  friend bool operator==(const Unmatched &, const Unmatched &) = default;
};

struct MatchResult {
  std::vector<Match> matches;  // by a
  std::vector<Unmatched> unmatched_a, unmatched_b;  // by entry
  std::uint32_t functions_a = 0, functions_b = 0;
  std::uint32_t rounds = 0;
  // Seeds that conflicted with another seed (an entry accepted twice), ignored.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> conflicting_seeds;

  static constexpr std::size_t kMaxCandidates = 16;

  const Match *by_a(std::uint64_t a) const;
  const Match *by_b(std::uint64_t b) const;
  void encode(facts::Encoder &e) const;
  static MatchResult decode(facts::Decoder &d);
  friend bool operator==(const MatchResult &, const MatchResult &) = default;
};

// A Match assertion as the matcher reads it.
struct Seed {
  std::uint64_t a = 0, b = 0;
  MatchState state = MatchState::accepted;
  Tier tier = Tier::accepted;  // what an apply run recorded; accepted for a user's
  float confidence = 1;
};

// ---- the residue hook (M2: BSim's F5 plugs in here) ----

// What a similarity tier is asked: the functions still unmatched after the
// exact tiers and propagation, with the prefilter's candidates for each.
struct ResidueRequest {
  std::string program_a, program_b;  // analysis program keys, for the tier's own queries
  std::vector<const FunctionFeatures *> unmatched_a, unmatched_b;  // by entry
  // For unmatched_a[i]: entries of B functions worth scoring (shared
  // buckets, neighbours of matched neighbours, similar size), best first.
  // A tier may score other pairs too.
  std::vector<std::vector<std::uint64_t>> candidates;
  // Pairs already matched, for corroboration (a, b, confidence).
  std::vector<std::tuple<std::uint64_t, std::uint64_t, float>> matched;
};

struct ScoredPair {
  std::uint64_t a = 0, b = 0;
  float similarity = 0;   // the tier's own measure (BSim: cosine)
  float confidence = 0;   // calibrated
  bool accept = false;    // the tier vouches for it (mutual best above its thresholds)
};

// A similarity tier over the residue (design section 1, step 3). Called
// from inside diff.matches: what it reads through `ctx` (its signatures,
// memoized as queries of their own) becomes the matches' dependencies, so
// the result stays a pure, incremental function of both programs. It must
// be deterministic. Accepted pairs that conflict with each other are
// dropped; the rest seed another round of propagation, and its other
// scores rank candidates.
class SimilarityTier {
 public:
  virtual ~SimilarityTier() = default;
  virtual std::string_view name() const = 0;  // "bsim"
  virtual std::vector<ScoredPair> score(facts::QueryContext &ctx, const ResidueRequest &request) = 0;
};

// Process-wide registry, by name. Sessions name the tiers they run
// (SessionKey::similarity); a tier must be registered before a session
// naming it is matched, and before the memo is read in a later process.
void register_similarity_tier(std::shared_ptr<SimilarityTier> tier);
std::shared_ptr<SimilarityTier> similarity_tier(std::string_view name);

// ---- the matcher ----

struct MatchOptions {
  // Global shape-only tier: functions with at least this many blocks.
  std::uint32_t min_shape_blocks = 8;
  // Global refs-only tier: bags with at least this many elements.
  std::uint32_t min_refs = 3;
  std::uint32_t max_rounds = 64;
  bool propagate = true;
};

struct MatchInput {
  std::vector<const FunctionFeatures *> a, b;  // sorted by entry; entry 0 entries are skipped
  std::vector<Seed> seeds;
  std::set<std::pair<std::uint64_t, std::uint64_t>> blocked;  // rejected (a, b)
  MatchOptions options;
};

using ResidueFn = std::function<std::vector<ScoredPair>(const ResidueRequest &)>;

// The whole matching, a pure function of its input (and of what `residue`
// returns, called at most once per fixpoint).
MatchResult match(const MatchInput &in, const ResidueFn &residue = {});

// `base` (match() of the same features without seeds or rejections) with
// in.seeds and in.blocked applied: seeds replace the proposals they
// conflict with, rejected pairs go, and propagation runs again only from
// the functions that changed and their neighbourhoods. A pure function of
// (features, decisions), and fast: what makes an accept or a reject
// interactive. Proposals found through a pair that is later rejected stay.
MatchResult refine(const MatchInput &in, const MatchResult &base, const ResidueFn &residue = {});

// The cheap structural similarity M1 reports and ranks candidates by, 0..1.
float similarity(const FunctionFeatures &a, const FunctionFeatures &b);

// Confidence of a match found by `tier` through `relation`, its parent pair
// having `parent` confidence (1 for global tiers), the pair's similarity
// being `sim`. Calibrated on the tuning corpus (docs/diff.md,
// "Calibration").
float confidence(Tier tier, Relation relation, float parent = 1, float sim = 1);

// ---- the session query ----

// What diff.matches is keyed by: a session's programs and options.
struct SessionKey {
  std::string session;     // Match assertions' sub
  std::string program_a;   // analysis program keys (the backend's program ids)
  std::string program_b;
  std::vector<std::string> similarity;  // residue tiers to run, by name

  void encode(facts::Encoder &e) const;
  static SessionKey decode(facts::Decoder &d);
  friend auto operator<=>(const SessionKey &, const SessionKey &) = default;
};

// diff.proposals(programs): the matching of two programs' functions, with
// no decisions: shared by every session over the same programs and
// options. Reads both function lists and every function's features. A
// re-diff after an edit is incremental: unchanged functions' features
// validate by fingerprint and only the matching runs again.
struct ProposalKey {
  std::string program_a, program_b;
  std::vector<std::string> similarity;

  void encode(facts::Encoder &e) const;
  static ProposalKey decode(facts::Decoder &d);
  friend auto operator<=>(const ProposalKey &, const ProposalKey &) = default;
};

struct Proposals {
  static constexpr std::string_view name = "diff.proposals";
  static constexpr std::uint32_t version = 2;  // 2: unchanged is the code's; address-order twins
  using Key = ProposalKey;
  using Value = MatchResult;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return k.program_a + " -> " + k.program_b; }
  static std::size_t weight(const Value &v);
};

// diff.matches(session): the session's proposals with its decisions, the
// Match assertions in B's space (accepted and applied pairs are seeds,
// rejected ones are blocked), applied by refine(). A decision re-runs only
// this, from diff.proposals' memo.
struct Matches {
  static constexpr std::string_view name = "diff.matches";
  static constexpr std::uint32_t version = 3;  // 3: unchanged is the code's; address-order twins
  using Key = SessionKey;
  using Value = MatchResult;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return k.session; }
  static std::size_t weight(const Value &v);
};

void register_queries(facts::Engine &engine);

// ---- Match assertions ----

// The value of a Match assertion (FactKind::Match, key at B's entry):
//   "<0x entry in A> accepted <tier> <confidence>"  a user's or agent's acceptance
//   "<0x entry in A> applied <tier> <confidence>"   recorded by an apply run
//   "rejected"                                      under sub "<session>/reject/<0x entry in A>"
struct MatchValue {
  MatchState state = MatchState::accepted;
  bool rejected = false;
  std::uint64_t a = 0;
  Tier tier = Tier::accepted;
  float confidence = 1;

  std::string text() const;
  static std::optional<MatchValue> parse(std::string_view text);
};

// The sub of a session's accepted/applied match, and of a rejected pair.
inline std::string match_sub(std::string_view session) { return std::string(session); }
std::string reject_sub(std::string_view session, std::uint64_t a);
// The session and (rejections) the A entry a Match key's sub names.
struct MatchSub {
  std::string session;
  std::optional<std::uint64_t> rejected_a;
};
std::optional<MatchSub> parse_match_sub(std::string_view sub);

}  // namespace revkit::diff
