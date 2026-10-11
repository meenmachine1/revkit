// Expression solving over partially known values.

#include "solver.hh"

#include <bit>

namespace revkit::assembler::detail {

namespace {

constexpr std::uint64_t kAll = ~std::uint64_t{0};

std::uint64_t low_mask(int bits) { return bits >= 64 ? kAll : (std::uint64_t{1} << bits) - 1; }

std::vector<Solution> one(Solution s = {}) { return {std::move(s)}; }

// Every pairing of a and b that agrees.
std::vector<Solution> product(const std::vector<Solution> &a, const std::vector<Solution> &b) {
  std::vector<Solution> out;
  for (const Solution &x : a)
    for (const Solution &y : b) {
      auto ins = Block::combine(x.ins, y.ins);
      auto ctx = Block::combine(x.ctx, y.ctx);
      if (ins && ctx) out.push_back({*ins, *ctx});
    }
  return out;
}

// Modular inverse of an odd number mod 2^64.
std::uint64_t inverse(std::uint64_t a) {
  std::uint64_t x = a;
  for (int i = 0; i < 6; ++i) x *= 2 - a * x;
  return x;
}

}  // namespace

int operand_offset(const Grammar &g, int cons, int index) {
  const Operand &op = g.cons[cons].ops[index];
  int off = op.rel_offset;
  if (op.offset_base >= 0) {
    off += g.cons[cons].ops[op.offset_base].min_length;
    off += operand_offset(g, cons, op.offset_base);
  }
  return off;
}

Masked read_token(const Expr &x, int at, const Block *ins) {
  const int n = x.byte_end - x.byte_start + 1;
  std::uint64_t m = 0, v = 0;
  for (int i = 0; i < n; ++i) {
    const int b = at + x.byte_start + i;
    std::uint8_t bm = 0, bv = 0;
    if (ins && b < ins->len && b < kMaxBytes) {
      bm = ins->mask[b];
      bv = ins->val[b];
    }
    m = (m << 8) | bm;
    v = (v << 8) | bv;
  }
  if (!x.big_endian) {
    std::uint64_t sm = 0, sv = 0;
    for (int i = 0; i < n; ++i) {
      sm = (sm << 8) | ((m >> (8 * i)) & 0xff);
      sv = (sv << 8) | ((v >> (8 * i)) & 0xff);
    }
    m = sm;
    v = sv;
  }
  Masked r{m >> x.shift, v >> x.shift};
  const int w = x.bit_end - x.bit_start + 1;
  // Bits of the raw word above the field are not part of it.
  r.msk &= low_mask(w);
  r.val &= low_mask(w);
  Masked field = x.sign ? r.sext(static_cast<unsigned>(w)) : Masked{r.msk | ~low_mask(w), r.val};
  if (x.sign && !(r.msk >> (w - 1) & 1)) field.msk &= low_mask(w);  // sign unknown: high bits unknown
  return field;
}

bool write_token(const Expr &x, int at, const Masked &v, Block &ins) {
  const int w = x.bit_end - x.bit_start + 1;
  if (!v.fits(static_cast<unsigned>(w), x.sign)) return false;
  const int n = x.byte_end - x.byte_start + 1;
  if (at + x.byte_end >= kMaxBytes || n > 8) return false;
  std::uint64_t word = (v.val & low_mask(w)) << x.shift;
  std::uint64_t mask = (v.msk & low_mask(w)) << x.shift;
  for (int i = 0; i < n; ++i) {
    const int sh = x.big_endian ? 8 * (n - 1 - i) : 8 * i;
    const auto bm = static_cast<std::uint8_t>(mask >> sh);
    const auto bv = static_cast<std::uint8_t>(word >> sh);
    const int b = at + x.byte_start + i;
    if (!bm) continue;
    // Disagreement with bits already set in this solution can't happen
    // (one field); conflicts with other solutions are found by combine().
    ins.set_bits(b, bm, bv);
  }
  return true;
}

Masked read_context(const Expr &x, const Block *ctx) {
  const int n = x.byte_end - x.byte_start + 1;
  std::uint64_t m = 0, v = 0;
  for (int i = 0; i < n; ++i) {
    const int b = x.byte_start + i;
    std::uint8_t bm = 0, bv = 0;
    if (ctx && b < ctx->len) {
      bm = ctx->mask[b];
      bv = ctx->val[b];
    }
    m = (m << 8) | bm;
    v = (v << 8) | bv;
  }
  const int w = x.bit_end - x.bit_start + 1;
  Masked r{(m >> x.shift) & low_mask(w), (v >> x.shift) & low_mask(w)};
  if (x.sign) {
    Masked s = r.sext(static_cast<unsigned>(w));
    if (!(r.msk >> (w - 1) & 1)) s.msk &= low_mask(w);
    return s;
  }
  return Masked{r.msk | ~low_mask(w), r.val};
}

bool write_context(const Expr &x, const Masked &v, Block &ctx) {
  const int w = x.bit_end - x.bit_start + 1;
  if (!v.fits(static_cast<unsigned>(w), x.sign)) return false;
  const int n = x.byte_end - x.byte_start + 1;
  if (x.byte_end >= kMaxBytes || n > 8) return false;
  const std::uint64_t word = (v.val & low_mask(w)) << x.shift;
  const std::uint64_t mask = (v.msk & low_mask(w)) << x.shift;
  for (int i = 0; i < n; ++i) {
    const int sh = 8 * (n - 1 - i);
    const auto bm = static_cast<std::uint8_t>(mask >> sh);
    if (bm) ctx.set_bits(x.byte_start + i, bm, static_cast<std::uint8_t>(word >> sh));
  }
  return true;
}

Masked evaluate(const SolveEnv &env, int ei, int at, int cons_at) {
  const Expr &x = env.g.exprs[ei];
  auto ev = [&](int k) { return evaluate(env, k, at, cons_at); };
  switch (x.op) {
    case Expr::Const: return Masked::known(static_cast<std::uint64_t>(x.value));
    case Expr::Token: return read_token(x, at, env.ins);
    case Expr::Context: return read_context(x, env.ctx);
    case Expr::Operand: {
      const Operand &op = env.g.cons[x.cons].ops[x.index];
      if (op.expr < 0) return Masked::known(0);
      const int off = cons_at + operand_offset(env.g, x.cons, x.index);
      return evaluate(env, op.expr, off, cons_at);
    }
    case Expr::Start: return Masked::known(env.inst_start);
    case Expr::End:
    case Expr::Next2: return env.inst_next ? Masked::known(*env.inst_next) : Masked::unknown();
    case Expr::Plus: return ev(x.l).add(ev(x.r));
    case Expr::Sub: return ev(x.l).add(ev(x.r).neg());
    case Expr::Mult: return ev(x.l).mul(ev(x.r));
    case Expr::Shl: {
      Masked a = ev(x.l), b = ev(x.r);
      if (!b.full()) return a.none() ? Masked::unknown() : Masked::unknown();
      return a.shl(static_cast<unsigned>(b.val));
    }
    case Expr::Shr: {
      Masked a = ev(x.l), b = ev(x.r);
      if (!b.full()) return Masked::unknown();
      return a.shr_arith(static_cast<unsigned>(b.val));
    }
    case Expr::And: return ev(x.l).bit_and(ev(x.r));
    case Expr::Or: return ev(x.l).bit_or(ev(x.r));
    case Expr::Xor: return ev(x.l).bit_xor(ev(x.r));
    case Expr::Div: {
      Masked a = ev(x.l), b = ev(x.r);
      if (a.full() && b.full() && b.val != 0)
        return Masked::known(static_cast<std::uint64_t>(static_cast<std::int64_t>(a.val) / static_cast<std::int64_t>(b.val)));
      return Masked::unknown();
    }
    case Expr::Neg: return ev(x.l).neg();
    case Expr::Not: return ~ev(x.l);
  }
  return Masked::unknown();
}

namespace {

bool uses_end(const Grammar &g, int ei) {
  const Expr &x = g.exprs[ei];
  if (x.op == Expr::End || x.op == Expr::Next2) return true;
  if (x.op == Expr::Operand) {
    const Operand &op = g.cons[x.cons].ops[x.index];
    return op.expr >= 0 && uses_end(g, op.expr);
  }
  return (x.l >= 0 && uses_end(g, x.l)) || (x.r >= 0 && uses_end(g, x.r));
}

std::vector<Solution> solve_or(const SolveEnv &env, const Expr &x, int at, int cons_at, const Masked &goal);

}  // namespace

std::vector<Solution> solve(const SolveEnv &env, int ei, int at, int cons_at, const Masked &goal) {
  const Grammar &g = env.g;
  const Expr &x = g.exprs[ei];
  auto sub = [&](int k, const Masked &gl) { return solve(env, k, at, cons_at, gl); };
  switch (x.op) {
    case Expr::Const:
      return goal.agrees(Masked::known(static_cast<std::uint64_t>(x.value))) ? one() : std::vector<Solution>{};
    case Expr::Token: {
      Solution s;
      if (!write_token(x, at, goal, s.ins)) return {};
      return one(s);
    }
    case Expr::Context: {
      Solution s;
      if (!write_context(x, goal, s.ctx)) return {};
      return one(s);
    }
    case Expr::Operand: {
      const Operand &op = g.cons[x.cons].ops[x.index];
      if (op.expr < 0) return goal.agrees(Masked::known(0)) ? one() : std::vector<Solution>{};
      const int off = cons_at + operand_offset(g, x.cons, x.index);
      return solve(env, op.expr, off, cons_at, goal);
    }
    case Expr::Start:
      return goal.agrees(Masked::known(env.inst_start)) ? one() : std::vector<Solution>{};
    case Expr::End:
    case Expr::Next2:
      if (!env.inst_next) throw NeedsBackfill{};
      return goal.agrees(Masked::known(*env.inst_next)) ? one() : std::vector<Solution>{};
    case Expr::Neg: return sub(x.l, goal.neg());
    case Expr::Not: return sub(x.l, ~goal);
    default: break;
  }
  // Binary.
  const Masked lv = evaluate(env, x.l, at, cons_at), rv = evaluate(env, x.r, at, cons_at);
  const bool lk = lv.full(), rk = rv.full();
  if (lk && rk) {
    const Masked v = evaluate(env, ei, at, cons_at);
    return goal.agrees(v) ? one() : std::vector<Solution>{};
  }
  if (!lk && !rk && x.op != Expr::Or && uses_end(g, ei) && !env.inst_next) throw NeedsBackfill{};
  switch (x.op) {
    case Expr::Plus:
      if (lk) return sub(x.r, goal.add(lv.neg()));
      if (rk) return sub(x.l, goal.add(rv.neg()));
      return {};
    case Expr::Sub:
      if (lk) return sub(x.r, lv.add(goal.neg()));  // l - r = g  =>  r = l - g
      if (rk) return sub(x.l, goal.add(rv));
      return {};
    case Expr::Xor:
      if (lk) return sub(x.r, Masked{goal.msk, (goal.val ^ lv.val) & goal.msk});
      if (rk) return sub(x.l, Masked{goal.msk, (goal.val ^ rv.val) & goal.msk});
      return {};
    case Expr::And: {
      const Masked &c = lk ? lv : rv;
      const int other = lk ? x.r : x.l;
      // Where c is 0 the result is 0; elsewhere it is the other side.
      if ((goal.msk & ~c.val & goal.val) != 0) return {};
      return sub(other, Masked{goal.msk & c.val, goal.val & c.val});
    }
    case Expr::Or: return solve_or(env, x, at, cons_at, goal);
    case Expr::Mult: {
      if (!lk && !rk) return {};
      const std::uint64_t c = lk ? lv.val : rv.val;
      const int other = lk ? x.r : x.l;
      if (c == 0) return goal.agrees(Masked::known(0)) ? one() : std::vector<Solution>{};
      const int t = std::countr_zero(c);
      // The goal's known low bits, contiguous from bit 0.
      const int k = std::countr_one(goal.msk);
      if (k < t) return {};  // not enough known bits to say anything precise
      if ((goal.val & low_mask(t)) != 0) return {};
      const std::uint64_t odd = c >> t;
      const std::uint64_t q = ((goal.val >> t) * inverse(odd)) & low_mask(k - t);
      Masked xg{low_mask(k - t), q};
      if (k >= 64 && t == 0) xg = Masked::known(goal.val * inverse(odd));
      return sub(other, xg);
    }
    case Expr::Shl: {
      if (rk) {
        const unsigned n = static_cast<unsigned>(rv.val);
        if (n >= 64) return goal.agrees(Masked::known(0)) ? one() : std::vector<Solution>{};
        if ((goal.msk & goal.val & low_mask(static_cast<int>(n))) != 0) return {};
        return sub(x.l, goal.shr_positional(n));
      }
      // Unknown shift amount: try each.
      std::vector<Solution> out;
      for (unsigned n = 0; n < 64; ++n)
        if (lv.shl(n).agrees(goal)) {
          auto s = sub(x.r, Masked::known(n));
          out.insert(out.end(), s.begin(), s.end());
        }
      return out;
    }
    case Expr::Shr: {
      if (rk) {
        const unsigned n = static_cast<unsigned>(rv.val);
        if (n >= 64) return {};
        // l >> n (arithmetic) = g: l's bits above n are g's; the low n unknown.
        Masked lg{goal.msk << n, goal.val << n};
        return sub(x.l, lg);
      }
      std::vector<Solution> out;
      for (unsigned n = 0; n < 64; ++n)
        if (lv.shr_arith(n).agrees(goal)) {
          auto s = sub(x.r, Masked::known(n));
          out.insert(out.end(), s.begin(), s.end());
        }
      return out;
    }
    case Expr::Div: {
      if (!rk || rv.val == 0 || !goal.full()) return {};
      const std::int64_t c = static_cast<std::int64_t>(rv.val);
      const std::int64_t q = static_cast<std::int64_t>(goal.val);
      std::vector<Solution> out;
      const std::int64_t span = c > 0 ? c : -c;
      for (std::int64_t i = 0; i < std::min<std::int64_t>(span, 16); ++i) {
        auto s = sub(x.l, Masked::known(static_cast<std::uint64_t>(q * c + (q >= 0 ? i : -i))));
        out.insert(out.end(), s.begin(), s.end());
      }
      return out;
    }
    default: return {};
  }
}

namespace {

// Components of a catenation: expression at each constant bit shift.
bool collect(const SolveEnv &env, int ei, int shift, int at, int cons_at, std::map<int, int> &parts) {
  const Expr &x = env.g.exprs[ei];
  if (x.op == Expr::Or)
    return collect(env, x.l, shift, at, cons_at, parts) && collect(env, x.r, shift, at, cons_at, parts);
  if (x.op == Expr::Shl || x.op == Expr::Shr) {
    const Masked n = evaluate(env, x.r, at, cons_at);
    if (!n.full() || n.val >= 64) return false;
    const int s = x.op == Expr::Shl ? shift + static_cast<int>(n.val) : shift - static_cast<int>(n.val);
    return collect(env, x.l, s, at, cons_at, parts);
  }
  if (shift < 0 || shift >= 64) return false;
  return parts.emplace(shift, ei).second;
}

std::uint64_t rotl(std::uint64_t v, int n, int size) {
  const std::uint64_t m = low_mask(size);
  v &= m;
  n %= size;
  if (n == 0) return v;
  return ((v << n) | (v >> (size - n))) & m;
}

std::vector<Solution> solve_or(const SolveEnv &env, const Expr &x, int at, int cons_at, const Masked &goal) {
  const Grammar &g = env.g;
  const Masked lv = evaluate(env, x.l, at, cons_at), rv = evaluate(env, x.r, at, cons_at);
  if (lv.full() || rv.full()) {
    const Masked &c = lv.full() ? lv : rv;
    const int other = lv.full() ? x.r : x.l;
    // Where c is 1 the result is 1; elsewhere the other side.
    if ((goal.msk & c.val & ~goal.val) != 0) return {};
    return solve(env, other, at, cons_at, Masked{goal.msk & ~c.val, goal.val & ~c.val});
  }
  // A circular shift: (v << (size - s)) | (v >> s), either order.
  const Expr &a = g.exprs[x.l], &b = g.exprs[x.r];
  if ((a.op == Expr::Shl && b.op == Expr::Shr) || (a.op == Expr::Shr && b.op == Expr::Shl)) {
    const Expr &shl = a.op == Expr::Shl ? a : b, &shr = a.op == Expr::Shl ? b : a;
    if (shl.l == shr.l) {
      int size = -1, amount = -1;  // amount: the right-rotation expression
      const Expr &sl = g.exprs[shl.r], &sr = g.exprs[shr.r];
      if (sl.op == Expr::Sub && sl.r == shr.r) {
        const Masked c = evaluate(env, sl.l, at, cons_at);
        if (c.full()) size = static_cast<int>(c.val), amount = shr.r;
      } else if (sr.op == Expr::Sub && sr.r == shl.r) {
        const Masked c = evaluate(env, sr.l, at, cons_at);
        if (c.full()) size = static_cast<int>(c.val), amount = -shl.r - 2;  // left rotation by shl.r
      }
      if (size > 0 && size <= 64) {
        const bool right = amount >= 0;
        const int amt_expr = right ? amount : -(amount + 2);
        if (goal.msk & low_mask(size)) {
          std::vector<Solution> out;
          for (int s = 0; s < size; ++s) {
            // Value v with rot(v, s) = goal (within size bits).
            if ((goal.msk & low_mask(size)) != low_mask(size)) break;  // need the whole goal
            const std::uint64_t gv = goal.val & low_mask(size);
            const std::uint64_t v = right ? rotl(gv, s, size) : rotl(gv, size - s, size);
            std::vector<Solution> sv;
            try {
              sv = solve(env, shl.l, at, cons_at, Masked{low_mask(size), v});
            } catch (const NeedsBackfill &) {
              continue;
            }
            if (sv.empty()) continue;
            auto ss = solve(env, amt_expr, at, cons_at, Masked::known(static_cast<std::uint64_t>(s)));
            if (ss.empty()) continue;
            auto both = product(sv, ss);
            out.insert(out.end(), both.begin(), both.end());
          }
          if (!out.empty()) return out;
        }
      }
    }
  }
  // A catenation of fields at constant shifts.
  std::map<int, int> parts;
  if (collect(env, x.l, 0, at, cons_at, parts) && collect(env, x.r, 0, at, cons_at, parts)) {
    std::vector<std::pair<int, int>> list(parts.begin(), parts.end());
    if (list.front().first != 0) {
      // Bits below the lowest field are zero.
      const std::uint64_t m = low_mask(list.front().first);
      if (goal.msk & goal.val & m) return {};
    }
    // Part by part, each solved knowing what the earlier ones fixed (a
    // later part may only be a function of an earlier one's bits).
    std::vector<Solution> acc = one();
    for (std::size_t i = 0; i < list.size(); ++i) {
      const int lo = list[i].first;
      const int hi = i + 1 < list.size() ? list[i + 1].first : 64;
      Masked part = goal.shr_positional(static_cast<unsigned>(lo));
      if (hi < 64) {
        part.msk &= low_mask(hi - lo);
        part.val &= low_mask(hi - lo);
      }
      std::vector<Solution> next;
      for (const Solution &so : acc) {
        Block known = env.ins ? *env.ins : Block{};
        if (!known.merge(so.ins)) continue;
        SolveEnv e2 = env;
        e2.ins = &known;
        auto s = solve(e2, list[i].second, at, cons_at, part);
        auto both = product({so}, s);
        next.insert(next.end(), both.begin(), both.end());
      }
      acc = std::move(next);
      if (acc.empty()) return {};
    }
    return acc;
  }
  return {};
}

}  // namespace

}  // namespace revkit::assembler::detail
