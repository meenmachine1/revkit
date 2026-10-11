// The similarity tier over the residue (design §1 step 3, docs/diff.md):
// pairing the functions the exact tiers and propagation left unmatched by
// their BSim vectors (F5, decompd mode signature).
//
// A pure function over feature vectors. For each function of A, its
// candidates in B (the caller's prefilter: top-K by shape and references;
// or every function of B) are scored with BSim's cosine and significance
// (lsh.h). A pair is accepted when it is the mutual best (A's best
// candidate is B, and among every A function scoring B, B's best is A,
// both strictly: a tie at the top is never broken by the score), and
//   cosine >= min_cosine and significance >= min_significance (0.35 and
//   10: BSim's own seed confidence), or
//   a corroborating hint names the pair (a propagation edge: it is the
//   callee at the same call site of a matched pair, ...) and cosine >=
//   hinted_min_cosine, significance >= hinted_min_significance. A hint
//   also breaks a tie at the top between the pairs it names.
// Hinted pairs are scored even when the prefilter didn't list them.
//
// Deterministic: inputs are processed by index, results ordered by A's
// entry; floating-point scores are BSim's, bit for bit.
#pragma once

#include "revkit/diff/lsh.h"
#include "revkit/diff/match.h"

#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace revkit::diff {

struct ResidueFunction {
  std::uint64_t entry = 0;
  std::span<const std::uint32_t> features;  // sorted (FunctionSignature::features); empty: no signature
};

// Evidence from elsewhere that `a` and `b` correspond.
struct ResidueHint {
  std::uint64_t a = 0, b = 0;
  std::string kind;  // "callee", "caller", "string", ... (reported back)
};

struct ResidueOptions {
  double min_cosine = 0.35;
  double min_significance = 10;
  double hinted_min_cosine = 0.2;
  double hinted_min_significance = 0;
  // Pairs reported per function of A in ResidueResult::scored (best first).
  std::size_t keep_scored = 16;
  // score_residue: residues of at most this many pairs (|A| x |B|) are
  // scored over every pair sharing a hash, not only the prefilter's
  // candidates (the inverted index keeps that cheap at that size).
  std::uint64_t all_pairs_limit = 25'000'000;
};

struct ResiduePair {
  std::uint64_t a = 0, b = 0;
  double cosine = 0;
  double significance = 0;
  bool mutual_best = false;  // strictly, or by a hint between tied pairs
  bool accepted = false;
  bool hinted = false;
  // The runner-up scores: A's best other candidate, and B's best other
  // scorer (-1: none). Their gap to `cosine` is the margin.
  double next_a = -1, next_b = -1;
  std::uint32_t scored_a = 0, scored_b = 0;  // pairs scored for A, for B
  std::vector<std::string> hints;            // kinds of the hints naming it
  friend bool operator==(const ResiduePair &, const ResiduePair &) = default;
};

struct ResidueResult {
  std::vector<ResiduePair> matches;  // accepted, by a's entry
  // Every function of A's best-scoring pairs (keep_scored of them, by
  // cosine descending, then b's entry), accepted or not: candidates to show.
  std::vector<ResiduePair> scored;
};

// `candidates`: for a[i], the entries in B to score; null scores every pair
// that shares at least one feature hash (others have cosine 0).
// `weights`: the table for the two programs' languages (weights_for).
ResidueResult match_residue(std::span<const ResidueFunction> a, std::span<const ResidueFunction> b,
                            const std::vector<std::vector<std::uint64_t>> *candidates,
                            std::span<const ResidueHint> hints, const WeightTable &weights,
                            const ResidueOptions &options = {});

// ---- the matcher's similarity tier (match.h's ResidueRequest) ----

// Corroborating hints from the call graph: for each matched pair, the
// unmatched functions calling it, when there is exactly one on each side
// ("caller").
std::vector<ResidueHint> call_graph_hints(const ResidueRequest &request);

// The confidence a pair accepted by match_residue is reported with:
// calibrated per cosine band on the tuning corpus (docs/diff.md), always
// below the auto-apply threshold (0.95).
float residue_confidence(const ResiduePair &p);

// Scores a residue with BSim (the "bsim" tier): fetches the feature
// vectors of the request's unmatched functions (`fetch(false, entries)` for
// A, `fetch(true, entries)` for B; a vector per entry, empty where there is
// no signature), runs match_residue over the request's candidates with
// call_graph_hints, and reports every accepted pair (accept = true) and
// each function's best-scored candidates (accept = false).
using SignatureFetch =
    std::function<std::vector<std::vector<std::uint32_t>>(bool side_b, const std::vector<std::uint64_t> &entries)>;
std::vector<ScoredPair> score_residue(const ResidueRequest &request, const SignatureFetch &fetch,
                                      const WeightTable &weights, const ResidueOptions &options = {});

}  // namespace revkit::diff
