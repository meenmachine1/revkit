#include "revkit/diff/residue.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <map>
#include <unordered_map>

namespace revkit::diff {

namespace {

struct Scored {
  std::uint32_t j = 0;
  double cosine = 0;
  double significance = 0;
  std::vector<std::string> hints;
};

// The best score among a function's pairs, how many pairs reach it, how many
// of those are hinted, and the best of the others.
struct Top {
  double best = -1;
  std::uint32_t at_best = 0;
  std::uint32_t hinted_at_best = 0;
  double second = -1;  // best below `best`, or `best` itself when tied
  std::uint32_t scored = 0;

  void add(double c, bool hinted) {
    ++scored;
    if (c > best) {
      second = best;
      best = c;
      at_best = 1;
      hinted_at_best = hinted ? 1 : 0;
    } else if (c == best) {
      ++at_best;
      if (hinted) ++hinted_at_best;
      second = best;
    } else if (c > second) {
      second = c;
    }
  }
  // Whether a pair scoring `c` is this side's choice: the strict best, or
  // the one hinted pair among those tied at the best.
  bool chooses(double c, bool hinted) const {
    if (c != best || c <= 0) return false;
    return at_best == 1 || (hinted && hinted_at_best == 1);
  }
  // The best score of the others, for a pair scoring `c`.
  double other(double c) const { return c == best ? (at_best > 1 ? best : second) : best; }
};

}  // namespace

ResidueResult match_residue(std::span<const ResidueFunction> a, std::span<const ResidueFunction> b,
                            const std::vector<std::vector<std::uint64_t>> *candidates,
                            std::span<const ResidueHint> hints, const WeightTable &weights,
                            const ResidueOptions &options) {
  ResidueResult out;
  std::vector<LshVector> va, vb;
  va.reserve(a.size());
  vb.reserve(b.size());
  for (const ResidueFunction &f : a) va.emplace_back(f.features, weights);
  for (const ResidueFunction &f : b) vb.emplace_back(f.features, weights);
  std::unordered_map<std::uint64_t, std::uint32_t> index_a, index_b;
  for (std::uint32_t i = 0; i < a.size(); ++i) index_a.emplace(a[i].entry, i);
  for (std::uint32_t j = 0; j < b.size(); ++j) index_b.emplace(b[j].entry, j);

  // The pairs to score, per function of A (sorted by j, unique).
  std::vector<std::vector<std::uint32_t>> pairs(a.size());
  if (candidates != nullptr) {
    for (std::size_t i = 0; i < a.size() && i < candidates->size(); ++i)
      for (std::uint64_t e : (*candidates)[i])
        if (auto it = index_b.find(e); it != index_b.end()) pairs[i].push_back(it->second);
  } else {
    // Every pair sharing a hash: the others score 0.
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> by_hash;
    for (std::uint32_t j = 0; j < vb.size(); ++j)
      for (const HashEntry &e : vb[j].entries()) by_hash[e.hash].push_back(j);
    std::vector<std::uint32_t> seen(b.size(), std::numeric_limits<std::uint32_t>::max());
    for (std::uint32_t i = 0; i < va.size(); ++i)
      for (const HashEntry &e : va[i].entries())
        if (auto it = by_hash.find(e.hash); it != by_hash.end())
          for (std::uint32_t j : it->second)
            if (seen[j] != i) {
              seen[j] = i;
              pairs[i].push_back(j);
            }
  }
  std::map<std::pair<std::uint32_t, std::uint32_t>, std::vector<std::string>> hinted;
  for (const ResidueHint &h : hints) {
    auto ia = index_a.find(h.a);
    auto jb = index_b.find(h.b);
    if (ia == index_a.end() || jb == index_b.end()) continue;
    hinted[{ia->second, jb->second}].push_back(h.kind);
    pairs[ia->second].push_back(jb->second);
  }
  for (std::vector<std::uint32_t> &p : pairs) {
    std::sort(p.begin(), p.end());
    p.erase(std::unique(p.begin(), p.end()), p.end());
  }

  // Score them.
  std::vector<std::vector<Scored>> scored(a.size());
  std::vector<Top> top_a(a.size()), top_b(b.size());
  for (std::uint32_t i = 0; i < a.size(); ++i) {
    for (std::uint32_t j : pairs[i]) {
      Scored s;
      s.j = j;
      VectorCompare d;
      s.cosine = compare(va[i], vb[j], &d);
      s.significance = significance(weights, d);
      if (std::isnan(s.significance)) s.significance = -std::numeric_limits<double>::infinity();
      if (auto h = hinted.find({i, j}); h != hinted.end()) s.hints = h->second;
      top_a[i].add(s.cosine, !s.hints.empty());
      top_b[j].add(s.cosine, !s.hints.empty());
      scored[i].push_back(std::move(s));
    }
  }

  for (std::uint32_t i = 0; i < a.size(); ++i) {
    std::vector<ResiduePair> mine;
    for (Scored &s : scored[i]) {
      ResiduePair p;
      p.a = a[i].entry;
      p.b = b[s.j].entry;
      p.cosine = s.cosine;
      p.significance = s.significance;
      p.hinted = !s.hints.empty();
      p.hints = std::move(s.hints);
      p.next_a = top_a[i].other(s.cosine);
      p.next_b = top_b[s.j].other(s.cosine);
      p.scored_a = top_a[i].scored;
      p.scored_b = top_b[s.j].scored;
      p.mutual_best = top_a[i].chooses(s.cosine, p.hinted) && top_b[s.j].chooses(s.cosine, p.hinted);
      const bool strong = p.cosine >= options.min_cosine && p.significance >= options.min_significance;
      const bool corroborated = p.hinted && p.cosine >= options.hinted_min_cosine &&
                                p.significance >= options.hinted_min_significance;
      p.accepted = p.mutual_best && (strong || corroborated);
      if (p.accepted) out.matches.push_back(p);
      mine.push_back(std::move(p));
    }
    std::sort(mine.begin(), mine.end(), [](const ResiduePair &x, const ResiduePair &y) {
      return x.cosine != y.cosine ? x.cosine > y.cosine : x.b < y.b;
    });
    if (mine.size() > options.keep_scored) mine.resize(options.keep_scored);
    for (ResiduePair &p : mine) out.scored.push_back(std::move(p));
  }
  auto by_a = [](const ResiduePair &x, const ResiduePair &y) { return x.a != y.a ? x.a < y.a : x.b < y.b; };
  std::sort(out.matches.begin(), out.matches.end(), by_a);
  std::stable_sort(out.scored.begin(), out.scored.end(),
                   [](const ResiduePair &x, const ResiduePair &y) { return x.a < y.a; });
  return out;
}

std::vector<ResidueHint> call_graph_hints(const ResidueRequest &request) {
  // Unmatched callers of each matched function, per side.
  std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> callers_a, callers_b;
  auto collect = [](const std::vector<const FunctionFeatures *> &side,
                    std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> &out) {
    for (const FunctionFeatures *f : side) {
      std::vector<std::uint64_t> callees(f->calls);
      std::sort(callees.begin(), callees.end());
      callees.erase(std::unique(callees.begin(), callees.end()), callees.end());
      for (std::uint64_t c : callees) out[c].push_back(f->entry);
    }
  };
  collect(request.unmatched_a, callers_a);
  collect(request.unmatched_b, callers_b);
  std::vector<ResidueHint> out;
  for (const auto &[a, b, conf] : request.matched) {
    auto ia = callers_a.find(a);
    auto ib = callers_b.find(b);
    if (ia == callers_a.end() || ib == callers_b.end()) continue;
    if (ia->second.size() == 1 && ib->second.size() == 1) out.push_back({ia->second[0], ib->second[0], "caller"});
  }
  std::sort(out.begin(), out.end(), [](const ResidueHint &x, const ResidueHint &y) {
    return x.a != y.a ? x.a < y.a : x.b < y.b;
  });
  out.erase(std::unique(out.begin(), out.end(),
                        [](const ResidueHint &x, const ResidueHint &y) { return x.a == y.a && x.b == y.b; }),
            out.end());
  return out;
}

float residue_confidence(const ResiduePair &p) {
  // Precision of the pairs the tier accepted over the residue of rk-diff's
  // families (scripts/diff_eval.py --similarity bsim, tuning corpus;
  // docs/diff.md), by cosine band: >= 0.95: 98-100%; 0.7-0.95: 88-100%;
  // 0.5-0.7: 82-100%; below: 72-100% (lowest across -O levels and Os/O2
  // firmware). Never at the auto-apply threshold (0.95): F5 alone asks for
  // acceptance.
  if (p.cosine >= 0.95) return 0.94f;
  if (p.cosine >= 0.7) return 0.9f;
  if (p.cosine >= 0.5) return 0.85f;
  if (p.cosine >= 0.35) return 0.75f;
  return 0.7f;  // a hinted pair below the plain thresholds
}

std::vector<ScoredPair> score_residue(const ResidueRequest &request, const SignatureFetch &fetch,
                                      const WeightTable &weights, const ResidueOptions &options) {
  std::vector<std::uint64_t> ea, eb;
  for (const FunctionFeatures *f : request.unmatched_a) ea.push_back(f->entry);
  for (const FunctionFeatures *f : request.unmatched_b) eb.push_back(f->entry);
  const std::vector<std::vector<std::uint32_t>> va = fetch(false, ea), vb = fetch(true, eb);
  std::vector<ResidueFunction> fa, fb;
  for (std::size_t i = 0; i < ea.size(); ++i) fa.push_back({ea[i], i < va.size() ? std::span(va[i]) : std::span<const std::uint32_t>()});
  for (std::size_t j = 0; j < eb.size(); ++j) fb.push_back({eb[j], j < vb.size() ? std::span(vb[j]) : std::span<const std::uint32_t>()});
  const std::vector<ResidueHint> hints = call_graph_hints(request);
  const bool all = request.candidates.empty() ||
                   static_cast<std::uint64_t>(fa.size()) * fb.size() <= options.all_pairs_limit;
  ResidueResult r = match_residue(fa, fb, all ? nullptr : &request.candidates, hints, weights, options);
  std::vector<ScoredPair> out;
  for (const ResiduePair &p : r.matches)
    out.push_back({p.a, p.b, static_cast<float>(p.cosine), residue_confidence(p), true});
  for (const ResiduePair &p : r.scored)
    if (!p.accepted) out.push_back({p.a, p.b, static_cast<float>(p.cosine), 0.0f, false});
  return out;
}

}  // namespace revkit::diff
