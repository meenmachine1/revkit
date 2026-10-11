// Block and instruction correlation inside a matched pair (correlate.h).

#include "revkit/diff/correlate.h"

#include "revkit/diff/features.h"
#include "revkit/facts/fact_db.h"

#include <algorithm>
#include <map>
#include <numeric>
#include <tuple>
#include <unordered_map>

namespace revkit::diff {

void Correlation::encode(facts::Encoder &e) const {
  facts::encode(e, insn_a);
  facts::encode(e, insn_b);
  facts::encode(e, status_a);
  facts::encode(e, status_b);
  facts::encode(e, block_a);
  facts::encode(e, block_b);
  facts::encode(e, block_status_a);
  facts::encode(e, block_status_b);
  facts::encode(e, lines);
  std::vector<std::uint8_t> ma(moved_a.begin(), moved_a.end()), mb(moved_b.begin(), moved_b.end());
  facts::encode(e, ma);
  facts::encode(e, mb);
  e.varint(equal);
  e.varint(changed);
  e.varint(inserted);
  e.varint(deleted);
}

Correlation Correlation::decode(facts::Decoder &d) {
  Correlation c;
  c.insn_a = facts::decode<std::vector<std::int32_t>>(d);
  c.insn_b = facts::decode<std::vector<std::int32_t>>(d);
  c.status_a = facts::decode<std::vector<InsnStatus>>(d);
  c.status_b = facts::decode<std::vector<InsnStatus>>(d);
  c.block_a = facts::decode<std::vector<std::int32_t>>(d);
  c.block_b = facts::decode<std::vector<std::int32_t>>(d);
  c.block_status_a = facts::decode<std::vector<BlockStatus>>(d);
  c.block_status_b = facts::decode<std::vector<BlockStatus>>(d);
  c.lines = facts::decode<std::vector<std::pair<std::int32_t, std::int32_t>>>(d);
  auto ma = facts::decode<std::vector<std::uint8_t>>(d);
  auto mb = facts::decode<std::vector<std::uint8_t>>(d);
  c.moved_a.assign(ma.begin(), ma.end());
  c.moved_b.assign(mb.begin(), mb.end());
  c.equal = static_cast<std::uint32_t>(d.varint());
  c.changed = static_cast<std::uint32_t>(d.varint());
  c.inserted = static_cast<std::uint32_t>(d.varint());
  c.deleted = static_cast<std::uint32_t>(d.varint());
  return c;
}

std::vector<std::uint32_t> Correlation::hunks() const {
  std::vector<std::uint32_t> out;
  bool in = false;
  for (std::size_t k = 0; k < lines.size(); ++k) {
    const auto [a, b] = lines[k];
    const bool same = a >= 0 && b >= 0 && status_a[static_cast<std::size_t>(a)] == InsnStatus::equal &&
                      !moved_a[static_cast<std::size_t>(a)];
    if (!same && !in) out.push_back(static_cast<std::uint32_t>(k));
    in = !same;
  }
  return out;
}

void CorrelationKey::encode(facts::Encoder &e) const {
  e.bytes(program_a);
  e.bytes(program_b);
  e.varint(a);
  e.varint(b);
}

CorrelationKey CorrelationKey::decode(facts::Decoder &d) {
  CorrelationKey k;
  k.program_a = std::string(d.bytes());
  k.program_b = std::string(d.bytes());
  k.a = d.varint();
  k.b = d.varint();
  return k;
}

std::string Correlate::describe(const Key &k) {
  char buf[64];
  std::snprintf(buf, sizeof buf, ":0x%llx -> ", static_cast<unsigned long long>(k.a));
  std::string s = k.program_a + buf + k.program_b;
  std::snprintf(buf, sizeof buf, ":0x%llx", static_cast<unsigned long long>(k.b));
  return s + buf;
}

Correlation Correlate::compute(facts::QueryContext &ctx, const Key &key) {
  auto a = ctx.get<Code>(analysis::Location{analysis::ProgramKey{key.program_a}, key.a});
  auto b = ctx.get<Code>(analysis::Location{analysis::ProgramKey{key.program_b}, key.b});
  return correlate(*a, *b);
}

namespace {

using Index = std::int32_t;
constexpr std::size_t kMaxGram = 16;
// The LCS table's size limit; beyond it a gap aligns by unique anchors.
constexpr std::size_t kMaxLcsCells = std::size_t{1} << 22;

struct Work {
  const FunctionCode &a, &b;
  std::vector<Index> pa, pb;  // instruction partners
};

std::uint64_t Tok(const CodeInsn &i, bool exact) { return exact ? i.exact : i.kind; }

// Unique n-grams within blocks, longest first: matches what is unique on
// both sides.
void Grams(Work &w, bool exact) {
  const auto &ia = w.a.insns, &ib = w.b.insns;
  std::size_t longest = 0;
  for (const CodeBlock &bl : w.a.blocks) longest = std::max<std::size_t>(longest, bl.last - bl.first + 1);
  std::size_t longest_b = 0;
  for (const CodeBlock &bl : w.b.blocks) longest_b = std::max<std::size_t>(longest_b, bl.last - bl.first + 1);
  const std::size_t top = std::min({kMaxGram, longest, longest_b});
  // Window hashes: hash[i * kMaxGram + n - 1] for the n instructions from i.
  auto windows = [&](const FunctionCode &f) {
    std::vector<std::uint64_t> h(f.insns.size() * top);
    for (std::size_t i = 0; i < f.insns.size(); ++i) {
      const std::uint32_t last = f.blocks[f.insns[i].block].last;
      Hasher x;
      for (std::size_t n = 1; n <= top && i + n - 1 <= last; ++n) {
        x.u64(Tok(f.insns[i + n - 1], exact));
        h[i * top + n - 1] = x.done();
      }
    }
    return h;
  };
  const auto ha = windows(w.a), hb = windows(w.b);
  // Free instructions from i to the end of its block.
  auto runs = [](const FunctionCode &f, const std::vector<Index> &p) {
    std::vector<std::uint32_t> r(f.insns.size(), 0);
    for (std::size_t i = f.insns.size(); i-- > 0;) {
      if (p[i] >= 0) continue;
      const bool next_same = i + 1 < f.insns.size() && f.insns[i + 1].block == f.insns[i].block;
      r[i] = 1 + (next_same ? r[i + 1] : 0);
    }
    return r;
  };
  for (std::size_t n = top; n >= 1; --n) {
    const auto ra = runs(w.a, w.pa), rb = runs(w.b, w.pb);
    struct Seen {
      std::uint32_t count = 0;
      Index at = -1;
    };
    std::unordered_map<std::uint64_t, Seen> sa, sb;
    for (std::size_t i = 0; i < ia.size(); ++i)
      if (ra[i] >= n) {
        Seen &s = sa[ha[i * top + n - 1]];
        if (s.count++ == 0) s.at = static_cast<Index>(i);
      }
    if (sa.empty()) continue;
    for (std::size_t j = 0; j < ib.size(); ++j)
      if (rb[j] >= n) {
        const std::uint64_t h = hb[j * top + n - 1];
        if (!sa.contains(h)) continue;
        Seen &s = sb[h];
        if (s.count++ == 0) s.at = static_cast<Index>(j);
      }
    for (std::size_t i = 0; i < ia.size(); ++i) {
      if (ra[i] < n) continue;
      const std::uint64_t h = ha[i * top + n - 1];
      const Seen &x = sa[h];
      auto it = sb.find(h);
      if (x.count != 1 || it == sb.end() || it->second.count != 1) continue;
      const auto j = static_cast<std::size_t>(it->second.at);
      bool free = true;  // an overlapping window may have matched in this round
      for (std::size_t k = 0; k < n && free; ++k) free = w.pa[i + k] < 0 && w.pb[j + k] < 0;
      if (!free) continue;
      for (std::size_t k = 0; k < n; ++k) {
        w.pa[i + k] = static_cast<Index>(j + k);
        w.pb[j + k] = static_cast<Index>(i + k);
      }
    }
  }
}

// Extends matches along their blocks while the tokens agree.
void Extend(Work &w, bool exact) {
  const auto &ia = w.a.insns, &ib = w.b.insns;
  for (bool again = true; again;) {
    again = false;
    for (std::size_t i = 0; i < ia.size(); ++i) {
      if (w.pa[i] < 0) continue;
      const auto j = static_cast<std::size_t>(w.pa[i]);
      for (std::size_t x = i + 1, y = j + 1; x < ia.size() && y < ib.size(); ++x, ++y) {
        if (ia[x].block != ia[i].block || ib[y].block != ib[j].block || w.pa[x] >= 0 || w.pb[y] >= 0) break;
        if (Tok(ia[x], exact) != Tok(ib[y], exact)) break;
        w.pa[x] = static_cast<Index>(y);
        w.pb[y] = static_cast<Index>(x);
        again = true;
      }
      for (std::size_t x = i, y = j; x > 0 && y > 0;) {
        --x, --y;
        if (ia[x].block != ia[i].block || ib[y].block != ib[j].block || w.pa[x] >= 0 || w.pb[y] >= 0) break;
        if (Tok(ia[x], exact) != Tok(ib[y], exact)) break;
        w.pa[x] = static_cast<Index>(y);
        w.pb[y] = static_cast<Index>(x);
        again = true;
      }
    }
  }
}

// Whether two blocks share enough to pair through their neighbours: a
// third of the smaller one's instructions by kind (or both are tiny).
bool Resemble(const FunctionCode &a, const CodeBlock &x, const FunctionCode &b, const CodeBlock &y) {
  const std::size_t nx = x.last - x.first + 1, ny = y.last - y.first + 1;
  std::vector<std::uint64_t> kx, ky;
  for (std::uint32_t i = x.first; i <= x.last; ++i) kx.push_back(a.insns[i].kind);
  for (std::uint32_t i = y.first; i <= y.last; ++i) ky.push_back(b.insns[i].kind);
  std::sort(kx.begin(), kx.end());
  std::sort(ky.begin(), ky.end());
  std::vector<std::uint64_t> common;
  std::set_intersection(kx.begin(), kx.end(), ky.begin(), ky.end(), std::back_inserter(common));
  if (nx <= 2 && ny <= 2) return true;
  return common.size() >= std::max<std::size_t>(1, std::min(nx, ny) / 3);
}

struct Preds {
  std::vector<std::vector<CodeEdge>> of;  // `to` is the predecessor
  explicit Preds(const FunctionCode &f) : of(f.blocks.size()) {
    for (std::uint32_t i = 0; i < f.blocks.size(); ++i)
      for (const CodeEdge &e : f.blocks[i].succ) of[e.to].push_back({i, e.kind});
  }
};

// Block pairs: by instruction votes, the entries, then neighbours.
void PairBlocks(const Work &w, std::vector<Index> &ba, std::vector<Index> &bb) {
  const FunctionCode &a = w.a, &b = w.b;
  ba.assign(a.blocks.size(), -1);
  bb.assign(b.blocks.size(), -1);
  std::map<std::pair<std::uint32_t, std::uint32_t>, std::uint32_t> votes;
  for (std::size_t i = 0; i < a.insns.size(); ++i)
    if (w.pa[i] >= 0) ++votes[{a.insns[i].block, b.insns[static_cast<std::size_t>(w.pa[i])].block}];
  std::vector<std::tuple<std::uint32_t, std::uint32_t, std::uint32_t>> order;  // (-votes as key), a, b
  for (const auto &[k, v] : votes) order.emplace_back(v, k.first, k.second);
  std::stable_sort(order.begin(), order.end(), [](const auto &x, const auto &y) { return std::get<0>(x) > std::get<0>(y); });
  for (const auto &[v, x, y] : order)
    if (ba[x] < 0 && bb[y] < 0) {
      ba[x] = static_cast<Index>(y);
      bb[y] = static_cast<Index>(x);
    }
  if (!a.blocks.empty() && !b.blocks.empty() && ba[a.entry_block] < 0 && bb[b.entry_block] < 0) {
    ba[a.entry_block] = static_cast<Index>(b.entry_block);
    bb[b.entry_block] = static_cast<Index>(a.entry_block);
  }
  // Blocks' contents, for telling twins apart from the rest.
  auto contents = [](const FunctionCode &f) {
    std::vector<std::uint64_t> h(f.blocks.size());
    for (std::size_t x = 0; x < f.blocks.size(); ++x) {
      Hasher k;
      for (std::uint32_t i = f.blocks[x].first; i <= f.blocks[x].last; ++i) k.u64(f.insns[i].exact);
      h[x] = k.done();
    }
    return h;
  };
  const auto ha = contents(a), hb = contents(b);
  auto link = [&](std::size_t x, std::size_t y) {
    ba[x] = static_cast<Index>(y);
    bb[y] = static_cast<Index>(x);
  };
  // Pairs unpaired blocks xs (of A) and ys (of B), both in address order:
  // contents unique among them first, then in order when as many are left
  // on each side and each pair resembles.
  auto pair_lists = [&](std::vector<std::uint32_t> xs, std::vector<std::uint32_t> ys) {
    bool any = false;
    if (xs.empty() || ys.empty()) return false;
    if (xs.size() > 1 || ys.size() > 1) {
      std::map<std::uint64_t, std::pair<std::vector<std::uint32_t>, std::vector<std::uint32_t>>> by;
      for (std::uint32_t x : xs) by[ha[x]].first.push_back(x);
      for (std::uint32_t y : ys) by[hb[y]].second.push_back(y);
      for (const auto &[h, g] : by)
        if (g.first.size() == 1 && g.second.size() == 1) {
          link(g.first[0], g.second[0]);
          any = true;
        }
      std::erase_if(xs, [&](std::uint32_t x) { return ba[x] >= 0; });
      std::erase_if(ys, [&](std::uint32_t y) { return bb[y] >= 0; });
    }
    if (xs.size() != ys.size()) return any;
    for (std::size_t k = 0; k < xs.size(); ++k)
      if (!Resemble(a, a.blocks[xs[k]], b, b.blocks[ys[k]])) return any;
    for (std::size_t k = 0; k < xs.size(); ++k) link(xs[k], ys[k]);
    return any || !xs.empty();
  };
  const Preds pra(a), prb(b);
  auto try_pair = [&](const std::vector<CodeEdge> &ea, const std::vector<CodeEdge> &eb) {
    bool any = false;
    for (EdgeKind k : {EdgeKind::fall, EdgeKind::taken, EdgeKind::jump, EdgeKind::switch_case}) {
      std::vector<std::uint32_t> xs, ys;
      for (const CodeEdge &e : ea)
        if (e.kind == k && ba[e.to] < 0 && (xs.empty() || xs.back() != e.to)) xs.push_back(e.to);
      for (const CodeEdge &e : eb)
        if (e.kind == k && bb[e.to] < 0 && (ys.empty() || ys.back() != e.to)) ys.push_back(e.to);
      std::sort(xs.begin(), xs.end());
      xs.erase(std::unique(xs.begin(), xs.end()), xs.end());
      std::sort(ys.begin(), ys.end());
      ys.erase(std::unique(ys.begin(), ys.end()), ys.end());
      any |= pair_lists(std::move(xs), std::move(ys));
    }
    return any;
  };
  for (bool again = true; again;) {
    again = false;
    for (std::size_t x = 0; x < a.blocks.size(); ++x) {
      if (ba[x] < 0) continue;
      const auto y = static_cast<std::size_t>(ba[x]);
      again |= try_pair(a.blocks[x].succ, b.blocks[y].succ);
      again |= try_pair(pra.of[x], prb.of[y]);
    }
    if (again) continue;
    // Identical twins nothing else tells apart: as many on each side, in
    // address order.
    std::map<std::uint64_t, std::pair<std::vector<std::uint32_t>, std::vector<std::uint32_t>>> twins;
    for (std::uint32_t x = 0; x < a.blocks.size(); ++x)
      if (ba[x] < 0) twins[ha[x]].first.push_back(x);
    for (std::uint32_t y = 0; y < b.blocks.size(); ++y)
      if (bb[y] < 0) twins[hb[y]].second.push_back(y);
    for (const auto &[h, g] : twins)
      if (g.first.size() == g.second.size() && !g.first.empty()) {
        for (std::size_t k = 0; k < g.first.size(); ++k) link(g.first[k], g.second[k]);
        again = true;
      }
  }
}

// Union-find over blocks of both sides (A's first).
struct Clusters {
  std::vector<std::uint32_t> up;
  explicit Clusters(std::size_t n) : up(n) { std::iota(up.begin(), up.end(), 0u); }
  std::uint32_t find(std::uint32_t x) {
    while (up[x] != x) x = up[x] = up[up[x]];
    return x;
  }
  void join(std::uint32_t x, std::uint32_t y) {
    x = find(x), y = find(y);
    if (x != y) up[std::max(x, y)] = std::min(x, y);
  }
};

// Aligns the instruction sequences sa and sb (indexes) into pairs.
class Aligner {
 public:
  Aligner(const FunctionCode &a, const FunctionCode &b, std::vector<Index> &pa, std::vector<Index> &pb)
      : a_(a), b_(b), pa_(pa), pb_(pb) {}

  void align(const std::vector<std::uint32_t> &sa, const std::vector<std::uint32_t> &sb) {
    level(sa, 0, sa.size(), sb, 0, sb.size(), 0);
  }

 private:
  // 0: exact tokens, 1: kinds, 2: in order.
  std::uint64_t key(bool side_a, std::uint32_t i, int lvl) const {
    const CodeInsn &x = side_a ? a_.insns[i] : b_.insns[i];
    return lvl == 0 ? x.exact : x.kind;
  }

  void pair(std::uint32_t i, std::uint32_t j) {
    pa_[i] = static_cast<Index>(j);
    pb_[j] = static_cast<Index>(i);
  }

  void level(const std::vector<std::uint32_t> &sa, std::size_t a0, std::size_t a1, const std::vector<std::uint32_t> &sb,
             std::size_t b0, std::size_t b1, int lvl) {
    if (a0 >= a1 || b0 >= b1) return;
    if (lvl == 2) {
      for (std::size_t k = 0; a0 + k < a1 && b0 + k < b1; ++k) pair(sa[a0 + k], sb[b0 + k]);
      return;
    }
    // Common prefix and suffix.
    while (a0 < a1 && b0 < b1 && key(true, sa[a0], lvl) == key(false, sb[b0], lvl)) pair(sa[a0++], sb[b0++]);
    while (a0 < a1 && b0 < b1 && key(true, sa[a1 - 1], lvl) == key(false, sb[b1 - 1], lvl)) pair(sa[--a1], sb[--b1]);
    if (a0 >= a1 || b0 >= b1) return;
    std::vector<std::pair<std::size_t, std::size_t>> anchors;
    const std::size_t n = a1 - a0, m = b1 - b0;
    if ((n + 1) * (m + 1) <= kMaxLcsCells) {
      std::vector<std::uint32_t> t((n + 1) * (m + 1), 0);
      auto at = [&](std::size_t x, std::size_t y) -> std::uint32_t & { return t[x * (m + 1) + y]; };
      for (std::size_t x = n; x-- > 0;)
        for (std::size_t y = m; y-- > 0;)
          at(x, y) = key(true, sa[a0 + x], lvl) == key(false, sb[b0 + y], lvl) ? at(x + 1, y + 1) + 1
                                                                               : std::max(at(x + 1, y), at(x, y + 1));
      for (std::size_t x = 0, y = 0; x < n && y < m;) {
        if (key(true, sa[a0 + x], lvl) == key(false, sb[b0 + y], lvl)) anchors.emplace_back(a0 + x++, b0 + y++);
        else if (at(x + 1, y) >= at(x, y + 1)) ++x;
        else ++y;
      }
    } else {
      anchors = Patience(sa, a0, a1, sb, b0, b1, lvl);
    }
    std::size_t pa = a0, pb = b0;
    for (const auto &[x, y] : anchors) {
      level(sa, pa, x, sb, pb, y, lvl + 1);
      pair(sa[x], sb[y]);
      pa = x + 1;
      pb = y + 1;
    }
    level(sa, pa, a1, sb, pb, b1, lvl + 1);
  }

  // Tokens unique on both sides of the gap, in an order both agree on (the
  // longest increasing run): anchors for a gap too big for the table.
  std::vector<std::pair<std::size_t, std::size_t>> Patience(const std::vector<std::uint32_t> &sa, std::size_t a0,
                                                            std::size_t a1, const std::vector<std::uint32_t> &sb,
                                                            std::size_t b0, std::size_t b1, int lvl) const {
    std::unordered_map<std::uint64_t, std::pair<std::int64_t, std::int64_t>> seen;  // key -> (index or -2 when repeated)
    for (std::size_t x = a0; x < a1; ++x) {
      auto [it, fresh] = seen.try_emplace(key(true, sa[x], lvl), std::pair<std::int64_t, std::int64_t>{static_cast<std::int64_t>(x), -1});
      if (!fresh) it->second.first = -2;
    }
    for (std::size_t y = b0; y < b1; ++y) {
      auto it = seen.find(key(false, sb[y], lvl));
      if (it == seen.end()) continue;
      it->second.second = it->second.second == -1 ? static_cast<std::int64_t>(y) : -2;
    }
    std::vector<std::pair<std::size_t, std::size_t>> cand;
    for (std::size_t x = a0; x < a1; ++x) {
      const auto &[ix, iy] = seen.at(key(true, sa[x], lvl));
      if (ix >= 0 && iy >= 0) cand.emplace_back(x, static_cast<std::size_t>(iy));
    }
    return LongestIncreasing(cand);
  }

 public:
  // The longest run of pairs increasing in both (pairs come sorted by first).
  static std::vector<std::pair<std::size_t, std::size_t>> LongestIncreasing(const std::vector<std::pair<std::size_t, std::size_t>> &p) {
    std::vector<std::size_t> tails, prev(p.size(), SIZE_MAX);
    for (std::size_t k = 0; k < p.size(); ++k) {
      auto it = std::lower_bound(tails.begin(), tails.end(), p[k].second,
                                 [&](std::size_t t, std::size_t v) { return p[t].second < v; });
      if (it != tails.begin()) prev[k] = *(it - 1);
      if (it == tails.end()) tails.push_back(k);
      else *it = k;
    }
    std::vector<std::pair<std::size_t, std::size_t>> out;
    for (std::size_t k = tails.empty() ? SIZE_MAX : tails.back(); k != SIZE_MAX; k = prev[k]) out.push_back(p[k]);
    std::reverse(out.begin(), out.end());
    return out;
  }

 private:
  const FunctionCode &a_, &b_;
  std::vector<Index> &pa_, &pb_;
};

// Statuses of blocks and the counts, from the instruction statuses.
void Finish(Correlation &c, const FunctionCode &a, const FunctionCode &b) {
  c.equal = c.changed = c.inserted = c.deleted = 0;
  for (InsnStatus s : c.status_a) {
    if (s == InsnStatus::equal) ++c.equal;
    else if (s == InsnStatus::changed) ++c.changed;
    else ++c.deleted;
  }
  for (InsnStatus s : c.status_b)
    if (s == InsnStatus::inserted) ++c.inserted;
  auto blocks = [](const FunctionCode &f, const FunctionCode &g, const std::vector<Index> &partner,
                   const std::vector<InsnStatus> &status, const std::vector<Index> &block_partner, bool side_a) {
    std::vector<BlockStatus> out(f.blocks.size());
    for (std::size_t x = 0; x < f.blocks.size(); ++x) {
      const CodeBlock &bl = f.blocks[x];
      bool any = false, all = block_partner[x] >= 0;
      for (std::uint32_t i = bl.first; i <= bl.last; ++i) {
        if (partner[i] >= 0) any = true;
        if (status[i] != InsnStatus::equal || partner[i] < 0 ||
            static_cast<Index>(g.insns[static_cast<std::size_t>(partner[i])].block) != block_partner[x])
          all = false;
      }
      if (all) {
        const CodeBlock &other = g.blocks[static_cast<std::size_t>(block_partner[x])];
        all = other.last - other.first == bl.last - bl.first;
      }
      out[x] = all ? BlockStatus::unchanged : any ? BlockStatus::modified : side_a ? BlockStatus::removed : BlockStatus::added;
    }
    return out;
  };
  c.block_status_a = blocks(a, b, c.insn_a, c.status_a, c.block_a, true);
  c.block_status_b = blocks(b, a, c.insn_b, c.status_b, c.block_b, false);
  // Both sides of a pair agree: a block is unchanged only if its partner is.
  for (std::size_t x = 0; x < c.block_a.size(); ++x) {
    if (c.block_a[x] < 0) continue;
    auto &other = c.block_status_b[static_cast<std::size_t>(c.block_a[x])];
    if (c.block_status_a[x] != other) {
      if (c.block_status_a[x] == BlockStatus::unchanged) c.block_status_a[x] = BlockStatus::modified;
      if (other == BlockStatus::unchanged) other = BlockStatus::modified;
    }
  }
}

}  // namespace

Correlation correlate(const FunctionCode &a, const FunctionCode &b) {
  Work w{a, b, std::vector<Index>(a.insns.size(), -1), std::vector<Index>(b.insns.size(), -1)};
  Correlation c;
  if (!a.insns.empty() && !b.insns.empty()) {
    for (bool exact : {true, false}) {
      Grams(w, exact);
      Extend(w, exact);
    }
    PairBlocks(w, c.block_a, c.block_b);
    // Clusters: paired blocks, and an unpaired block with the block its
    // instruction matches mostly lead to (a block split or merged).
    const std::size_t na = a.blocks.size(), nb = b.blocks.size();
    Clusters cl(na + nb);
    for (std::size_t x = 0; x < na; ++x)
      if (c.block_a[x] >= 0) cl.join(static_cast<std::uint32_t>(x), static_cast<std::uint32_t>(na + static_cast<std::size_t>(c.block_a[x])));
    auto lean = [&](const FunctionCode &f, const FunctionCode &g, const std::vector<Index> &p, const std::vector<Index> &bp,
                    std::size_t own, std::size_t other) {
      std::vector<std::map<std::uint32_t, std::uint32_t>> votes(f.blocks.size());
      for (std::size_t i = 0; i < f.insns.size(); ++i)
        if (p[i] >= 0 && bp[f.insns[i].block] < 0) ++votes[f.insns[i].block][g.insns[static_cast<std::size_t>(p[i])].block];
      for (std::size_t x = 0; x < f.blocks.size(); ++x) {
        std::uint32_t best = 0, at = 0;
        for (const auto &[y, v] : votes[x])
          if (v > best) best = v, at = y;
        if (best) cl.join(static_cast<std::uint32_t>(own + x), static_cast<std::uint32_t>(other + at));
      }
    };
    lean(a, b, w.pa, c.block_a, 0, na);
    lean(b, a, w.pb, c.block_b, na, 0);
    std::map<std::uint32_t, std::pair<std::vector<std::uint32_t>, std::vector<std::uint32_t>>> groups;
    for (std::size_t i = 0; i < a.insns.size(); ++i) groups[cl.find(a.insns[i].block)].first.push_back(static_cast<std::uint32_t>(i));
    for (std::size_t j = 0; j < b.insns.size(); ++j)
      groups[cl.find(static_cast<std::uint32_t>(na + b.insns[j].block))].second.push_back(static_cast<std::uint32_t>(j));
    std::vector<Index> pa(a.insns.size(), -1), pb(b.insns.size(), -1);
    Aligner al(a, b, pa, pb);
    for (const auto &[root, g] : groups)
      if (!g.first.empty() && !g.second.empty()) al.align(g.first, g.second);
    w.pa = std::move(pa);
    w.pb = std::move(pb);
  } else {
    c.block_a.assign(a.blocks.size(), -1);
    c.block_b.assign(b.blocks.size(), -1);
  }
  c.insn_a = w.pa;
  c.insn_b = w.pb;
  // Branches within the function are the same only if they lead to
  // instructions that correspond.
  auto same_local = [&](const CodeInsn &x, const CodeInsn &y) {
    if (x.local.size() != y.local.size()) return false;
    for (std::size_t k = 0; k < x.local.size(); ++k)
      if (c.insn_a[x.local[k]] != static_cast<Index>(y.local[k])) return false;
    return true;
  };
  c.status_a.resize(a.insns.size());
  c.status_b.resize(b.insns.size());
  for (std::size_t i = 0; i < a.insns.size(); ++i) {
    const Index j = c.insn_a[i];
    c.status_a[i] = j < 0 ? InsnStatus::deleted
                    : a.insns[i].exact == b.insns[static_cast<std::size_t>(j)].exact && same_local(a.insns[i], b.insns[static_cast<std::size_t>(j)])
                        ? InsnStatus::equal
                        : InsnStatus::changed;
  }
  for (std::size_t j = 0; j < b.insns.size(); ++j) {
    const Index i = c.insn_b[j];
    c.status_b[j] = i < 0 ? InsnStatus::inserted : c.status_a[static_cast<std::size_t>(i)];
  }

  // Lines: pairs in an order both sides agree on share a line; the others
  // (moved) and the unpaired get lines of their own.
  std::vector<std::pair<std::size_t, std::size_t>> pairs;
  for (std::size_t i = 0; i < a.insns.size(); ++i)
    if (c.insn_a[i] >= 0) pairs.emplace_back(i, static_cast<std::size_t>(c.insn_a[i]));
  const auto keep = Aligner::LongestIncreasing(pairs);
  c.moved_a.assign(a.insns.size(), false);
  c.moved_b.assign(b.insns.size(), false);
  for (const auto &[i, j] : pairs) c.moved_a[i] = c.moved_b[j] = true;
  for (const auto &[i, j] : keep) c.moved_a[i] = c.moved_b[j] = false;
  std::size_t x = 0, y = 0;
  for (const auto &[i, j] : keep) {
    for (; x < i; ++x) c.lines.emplace_back(static_cast<Index>(x), -1);
    for (; y < j; ++y) c.lines.emplace_back(-1, static_cast<Index>(y));
    c.lines.emplace_back(static_cast<Index>(x++), static_cast<Index>(y++));
  }
  for (; x < a.insns.size(); ++x) c.lines.emplace_back(static_cast<Index>(x), -1);
  for (; y < b.insns.size(); ++y) c.lines.emplace_back(-1, static_cast<Index>(y));
  Finish(c, a, b);
  return c;
}

namespace {

// Calls and jumps out, in order.
std::vector<std::uint64_t> Flows(const CodeInsn &i) {
  std::vector<std::uint64_t> out;
  for (const CodeRef &r : i.refs)
    if (r.kind != CodeRef::Kind::data) out.push_back(r.to);
  return out;
}

}  // namespace

void retarget(Correlation &c, const FunctionCode &a, const FunctionCode &b, const MatchOf &match_of) {
  for (std::size_t i = 0; i < a.insns.size(); ++i) {
    if (c.status_a[i] != InsnStatus::equal) continue;
    const auto j = static_cast<std::size_t>(c.insn_a[i]);
    const auto ta = Flows(a.insns[i]), tb = Flows(b.insns[j]);
    bool same = ta.size() == tb.size();
    for (std::size_t k = 0; same && k < ta.size(); ++k) {
      const auto m = match_of ? match_of(ta[k]) : std::nullopt;
      same = m ? *m == tb[k] : ta[k] == tb[k];
    }
    if (!same) c.status_a[i] = c.status_b[j] = InsnStatus::changed;
  }
  Finish(c, a, b);
}

std::vector<RefChange> reference_diff(const Correlation &c, const FunctionCode &a, const FunctionCode &b,
                                      const MatchOf &match_of) {
  // Key: what a reference is, comparable across the sides.
  using Key = std::tuple<int, std::uint64_t>;
  auto key = [&](const CodeRef &r, bool side_a) -> Key {
    if (r.kind == CodeRef::Kind::data) return r.string ? Key{2, r.string} : Key{3, r.to};
    std::uint64_t to = r.to;
    if (side_a && match_of)
      if (auto m = match_of(to)) to = *m;
    return {1, to};
  };
  std::map<Key, std::vector<RefChange>> lost, gained;
  for (std::size_t i = 0; i < a.insns.size(); ++i)
    if (c.status_a[i] != InsnStatus::equal)
      for (const CodeRef &r : a.insns[i].refs) lost[key(r, true)].push_back({false, r, static_cast<std::uint32_t>(i)});
  for (std::size_t j = 0; j < b.insns.size(); ++j)
    if (c.status_b[j] != InsnStatus::equal)
      for (const CodeRef &r : b.insns[j].refs) gained[key(r, false)].push_back({true, r, static_cast<std::uint32_t>(j)});
  std::vector<RefChange> out;
  for (auto &[k, v] : lost) {
    const std::size_t cancel = gained.contains(k) ? std::min(v.size(), gained[k].size()) : 0;
    out.insert(out.end(), v.begin() + static_cast<std::ptrdiff_t>(cancel), v.end());
  }
  for (auto &[k, v] : gained) {
    const std::size_t cancel = lost.contains(k) ? std::min(v.size(), lost[k].size()) : 0;
    out.insert(out.end(), v.begin() + static_cast<std::ptrdiff_t>(cancel), v.end());
  }
  std::stable_sort(out.begin(), out.end(), [](const RefChange &x, const RefChange &y) {
    return std::tie(x.in_b, x.insn) < std::tie(y.in_b, y.insn);
  });
  return out;
}

}  // namespace revkit::diff
