// Resolution of parse trees into encodings, verification and ranking.

#include "revkit/asm/assembler.hh"

#include "grammar.hh"
#include "parser.hh"
#include "solver.hh"

#include "revkit/lift/sleigh_decoder.hh"

#include "slghsymbol.hh"

#include <algorithm>
#include <bit>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <mutex>
#include <set>

namespace revkit::assembler {

using namespace detail;

namespace {

// Grammars by language, built once per process. The decoder that built a
// grammar is kept with it: the grammar names its constructors.
struct CacheEntry {
  std::shared_ptr<lift::SleighDecoder> builder;
  std::shared_ptr<const Grammar> grammar;
  double build_ms = 0;
  std::map<std::pair<std::string, unsigned>, int> by_id;  // (table, constructor id) -> index
};

std::mutex g_cache_mu;
std::map<std::string, std::shared_ptr<CacheEntry>> g_cache;

std::shared_ptr<CacheEntry> grammar_for(const std::string &language) {
  std::lock_guard lock(g_cache_mu);
  auto it = g_cache.find(language);
  if (it != g_cache.end()) return it->second;
  auto e = std::make_shared<CacheEntry>();
  const auto t0 = std::chrono::steady_clock::now();
  e->builder = std::make_shared<lift::SleighDecoder>(language);
  e->grammar = build_grammar(*e->builder);
  e->build_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
  for (std::size_t i = 0; i < e->grammar->cons.size(); ++i) {
    const auto *ct = e->grammar->cons[i].ct;
    e->by_id[{ct->getParent()->getName(), static_cast<unsigned>(ct->getId())}] = static_cast<int>(i);
  }
  g_cache[language] = e;
  return e;
}

Block context_block(std::span<const std::uint32_t> words) {
  Block b;
  for (std::size_t w = 0; w < words.size() && 4 * w + 3 < kMaxBytes; ++w)
    for (int i = 0; i < 4; ++i) b.set_bits(static_cast<int>(4 * w + i), 0xff, static_cast<std::uint8_t>(words[w] >> (24 - 8 * i)));
  return b;
}

// Bits both blocks require agree.
bool consistent(const Block &a, const Block &b) {
  const int n = std::min(a.len, b.len);
  for (int i = 0; i < n; ++i) {
    const std::uint8_t both = a.mask[i] & b.mask[i];
    if ((a.val[i] & both) != (b.val[i] & both)) return false;
  }
  return true;
}

struct Event {
  bool write = false;
  Block req;      // requirement on the context at this point
  int cons = -1;  // write: the constructor and its context op
  int op = -1;
  int at = 0;     // the constructor's offset
};

struct Backfill {
  int expr = -1;
  int at = 0, cons_at = 0;
  Masked goal;
  bool context = false;  // the solution's context reads become a requirement at `event`
  std::size_t event = 0;
};

// A context write whose value wasn't known when it happened (it reads
// instruction bits solved later): the bits it still owns (no later write
// replaced them) are filled in once its value is known.
struct Pending {
  int cons = -1, op = -1, at = 0;
  Block owned;
};

struct State {
  Block ins;
  Block ctx;  // context known going forward (the address's, updated by writes)
  std::vector<Pending> pending;
  std::vector<Event> events;
  std::vector<Backfill> backfills;
  std::vector<int> tree;
};

using Cont = std::function<void(State &, int)>;

// Lexical comparison of two lines of assembly.
struct Lexeme {
  int kind;  // 0 word, 1 number, 2 punctuation
  std::string text;  // words in lower case
  std::int64_t value = 0;
  std::string raw;   // a word as written (labels are looked up so)
};

std::vector<Lexeme> lex(std::string_view s) {
  std::vector<Lexeme> out;
  std::size_t i = 0;
  auto word = [](char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' || c == '$'; };
  while (i < s.size()) {
    const char c = s[i];
    if (std::isspace(static_cast<unsigned char>(c))) {
      ++i;
      continue;
    }
    const bool sign = (c == '-' || c == '+') && i + 1 < s.size() && std::isdigit(static_cast<unsigned char>(s[i + 1])) &&
                      (out.empty() || out.back().kind == 2);
    if (std::isdigit(static_cast<unsigned char>(c)) || sign) {
      std::size_t j = i + (sign ? 1 : 0);
      int base = 10;
      if (j + 1 < s.size() && s[j] == '0' && (s[j + 1] == 'x' || s[j + 1] == 'X')) {
        base = 16;
        j += 2;
      }
      std::uint64_t v = 0;
      const std::size_t start = j;
      while (j < s.size() && std::isxdigit(static_cast<unsigned char>(s[j])) &&
             (base == 16 || std::isdigit(static_cast<unsigned char>(s[j])))) {
        const char d = static_cast<char>(std::tolower(static_cast<unsigned char>(s[j])));
        v = v * static_cast<std::uint64_t>(base) + static_cast<std::uint64_t>(d <= '9' ? d - '0' : d - 'a' + 10);
        ++j;
      }
      if (j > start && (j >= s.size() || !word(s[j]))) {
        std::int64_t sv = static_cast<std::int64_t>(v);
        if (c == '-') sv = -sv;
        out.push_back({1, {}, sv, {}});
        i = j;
        continue;
      }
    }
    if (word(c)) {
      std::size_t j = i;
      std::string w;
      while (j < s.size() && word(s[j])) w += static_cast<char>(std::tolower(static_cast<unsigned char>(s[j++])));
      out.push_back({0, std::move(w), 0, std::string(s.substr(i, j - i))});
      i = j;
      continue;
    }
    out.push_back({2, std::string(1, c), 0, {}});
    ++i;
  }
  return out;
}

bool same_number(std::int64_t a, std::int64_t b) {
  if (a == b) return true;
  for (int w : {32, 16, 8}) {
    const std::uint64_t m = (std::uint64_t{1} << w) - 1;
    auto narrow = [&](std::int64_t v) {
      const std::int64_t lo = -(std::int64_t{1} << (w - 1)), hi = static_cast<std::int64_t>(m);
      return v >= lo && v <= hi;
    };
    if (narrow(a) && narrow(b) && ((static_cast<std::uint64_t>(a) ^ static_cast<std::uint64_t>(b)) & m) == 0) return true;
  }
  return false;
}

}  // namespace

struct Assembler::Impl {
  std::shared_ptr<CacheEntry> entry;
  const Grammar *g = nullptr;
  std::shared_ptr<lift::SleighDecoder> decoder;  // this assembler's own

  // Per call.
  std::uint64_t address = 0;
  Block c0;  // the context at the address
  std::vector<std::uint32_t> context;
  const Options *opts = nullptr;
  std::string_view text;
  std::vector<Candidate> found;
  std::set<std::pair<std::vector<std::uint8_t>, std::vector<int>>> seen;  // (bytes, tree) verified
  std::string failure;
  std::size_t steps = 0;
  bool truncated = false;
  bool debug = std::getenv("REVKIT_ASM_DEBUG") != nullptr;
  static constexpr std::size_t kMaxSteps = 200000;
  Child recurse_marker;
  const Child *const kRecurse = &recurse_marker;

  SolveEnv env(const Block *ins, const Block *ctx) const {
    SolveEnv e{*g, 0, std::nullopt, nullptr, nullptr};
    e.inst_start = address / g->word_size;
    e.ins = ins;
    e.ctx = ctx;
    return e;
  }

  // Why nothing was found: the most telling reason seen. A pattern that
  // doesn't fit is routine while exploring; an operand that can't be
  // encoded is what the user needs to hear.
  int failure_rank = 0;
  void note(const char *why, int rank = 1) {
    if (rank > failure_rank) {
      failure = why;
      failure_rank = rank;
    }
  }

  // ---- forward generation ----

  bool reads_context(int e) const {
    const Expr &x = g->exprs[e];
    if (x.op == Expr::Context) return true;
    if (x.op == Expr::Operand) {
      const Operand &op = g->cons[x.cons].ops[x.index];
      return op.expr >= 0 && reads_context(op.expr);
    }
    return (x.l >= 0 && reads_context(x.l)) || (x.r >= 0 && reads_context(x.r));
  }

  // Pending writes whose values the instruction bits now decide.
  void refresh(State &s) const {
    for (std::size_t i = 0; i < s.pending.size();) {
      Pending &p = s.pending[i];
      const ContextOp &op = g->cons[p.cons].ctx_ops[p.op];
      SolveEnv e = env(&s.ins, nullptr);
      const Masked v = evaluate(e, op.expr, p.at, p.at);
      Block vals;
      write_forward(op, v, vals);
      bool all = true;
      for (int b = 0; b < p.owned.len; ++b) {
        const std::uint8_t want = p.owned.mask[b];
        if (!want) continue;
        const std::uint8_t have = b < vals.len ? vals.mask[b] & want : 0;
        if (have) {
          s.ctx.set_bits(b, have, vals.val[b]);
          p.owned.mask[b] &= static_cast<std::uint8_t>(~have);
        }
        if (p.owned.mask[b]) all = false;
      }
      if (all) {
        s.pending.erase(s.pending.begin() + static_cast<long>(i));
      } else {
        ++i;
      }
    }
  }

  void gen_tree(const Tree &t, int shift, State &s, int depth, const Cont &k) {
    const Production &p = g->productions[t.prod];
    for (std::size_t si = 0; si < p.cons.size(); ++si) {
      const int ci = p.cons[si];
      std::vector<const Child *> kids(g->cons[ci].ops.size(), nullptr);
      std::size_t n = 0;
      for (std::size_t pos = 0; pos < p.rhs.size(); ++pos) {
        const Sym &sym = p.rhs[pos];
        if (!sym.nt && !g->terminals[sym.id].takes_operand()) continue;
        kids[p.operand_index[si][n++]] = &t.kids[pos];
      }
      gen_cons(ci, shift, s, kids, depth, k);
    }
  }

  void gen_hidden(int nt, int shift, State &s, int depth, const Cont &k) {
    if (depth > 48) return;
    for (int ci : g->nt_cons[nt]) {
      std::vector<const Child *> kids(g->cons[ci].ops.size(), nullptr);
      gen_cons(ci, shift, s, kids, depth + 1, k);
    }
  }

  void write_forward(const ContextOp &op, const Masked &v, Block &ctx) const {
    const std::uint64_t vm = (v.msk << op.shift) & op.mask, vv = (v.val << op.shift) & op.mask;
    for (int b = 0; b < 4; ++b) {
      const int sh = 24 - 8 * b;
      const auto m = static_cast<std::uint8_t>(op.mask >> sh);
      if (!m) continue;
      const int byte = 4 * op.word + b;
      const auto km = static_cast<std::uint8_t>(vm >> sh);
      ctx.clear_bits(byte, static_cast<std::uint8_t>(m & ~km));
      if (km) ctx.set_bits(byte, km, static_cast<std::uint8_t>(vv >> sh));
    }
  }

  void gen_cons(int ci, int shift, State &st, const std::vector<const Child *> &kids, int depth, const Cont &k) {
    const Constructor &c = g->cons[ci];
    for (const Pattern &pat : c.patterns) {
      if (++steps > kMaxSteps) {
        truncated = true;
        return;
      }
      State s = st;
      Block pi = pat.ins;
      if (!pi.shift(shift) || !s.ins.merge(pi)) {
        if (debug) std::fprintf(stderr, "  pattern conflict %s at %d: have %s, pattern %s\n", g->describe(ci).c_str(), shift, s.ins.str().c_str(), pi.str().c_str());
        note("the operands need bits the instruction's pattern fixes otherwise");
        continue;
      }
      if (debug) std::fprintf(stderr, "  try %s at %d\n", g->describe(ci).c_str(), shift);
      refresh(s);
      if (!consistent(pat.ctx, s.ctx)) {
        if (debug) std::fprintf(stderr, "  context mismatch %s: have %s, pattern %s\n", g->describe(ci).c_str(), s.ctx.str().c_str(), pat.ctx.str().c_str());
        continue;
      }
      if (!pat.ctx.empty()) s.events.push_back(Event{false, pat.ctx});
      s.tree.push_back(ci);
      for (std::size_t j = 0; j < c.ctx_ops.size(); ++j) {
        const ContextOp &op = c.ctx_ops[j];
        SolveEnv e = env(&s.ins, &s.ctx);
        const Masked v = evaluate(e, op.expr, shift, shift);
        Block written;
        write_forward(op, Masked::known(~std::uint64_t{0}), written);
        for (Pending &p : s.pending)
          for (int b = 0; b < written.len; ++b) p.owned.clear_bits(b, written.mask[b]);
        Block before = s.ctx;
        write_forward(op, v, s.ctx);
        if (!reads_context(op.expr)) {
          Pending p{ci, static_cast<int>(j), shift, written};
          // Owned: the written bits whose value is still unknown.
          for (int b = 0; b < p.owned.len; ++b)
            p.owned.mask[b] &= static_cast<std::uint8_t>(~(b < s.ctx.len ? s.ctx.mask[b] : 0));
          if (!p.owned.empty()) s.pending.push_back(p);
        }
        (void)before;
        Event w;
        w.write = true;
        w.cons = ci;
        w.op = static_cast<int>(j);
        w.at = shift;
        s.events.push_back(w);
      }
      std::vector<int> offs(c.ops.size(), 0), lens(c.ops.size(), 0);
      gen_ops(ci, 0, shift, offs, lens, s, kids, depth, k);
    }
  }

  void gen_ops(int ci, std::size_t i, int shift, std::vector<int> offs, std::vector<int> lens, State &s,
               const std::vector<const Child *> &kids, int depth, const Cont &k) {
    const Constructor &c = g->cons[ci];
    if (i == c.ops.size()) {
      int end = shift + c.min_length;
      for (std::size_t j = 0; j < c.ops.size(); ++j) end = std::max(end, offs[j] + lens[j]);
      k(s, end - shift);
      return;
    }
    const Operand &op = c.ops[i];
    const int off = (op.offset_base < 0 ? shift : offs[op.offset_base] + lens[op.offset_base]) + op.rel_offset;
    const Child *kid = kids[i];
    Cont next = [&, i, off](State &s2, int len) {
      std::vector<int> o2 = offs, l2 = lens;
      o2[i] = off;
      l2[i] = len;
      gen_ops(ci, i + 1, shift, std::move(o2), std::move(l2), s2, kids, depth, k);
    };
    if (op.kind == Operand::Subtable) {
      if (kid == kRecurse) {
        gen_root(off, s, depth - 1, next);
      } else if (kid && kid->sub) {
        gen_tree(*kid->sub, off, s, depth, next);
      } else {
        gen_hidden(op.nt, off, s, depth, next);
      }
      return;
    }
    if (!kid || op.expr < 0) {
      next(s, op.min_length);
      return;
    }
    const Terminal &t = g->terminals[kid->tok.term];
    std::vector<Masked> goals;
    switch (t.kind) {
      case Terminal::Number: {
        const std::uint64_t m = t.bits > 0 && t.bits < 64 ? (std::uint64_t{1} << t.bits) - 1 : ~std::uint64_t{0};
        goals.push_back(Masked::of(m, static_cast<std::uint64_t>(kid->tok.number)));
        break;
      }
      case Terminal::Names:
      case Terminal::Values:
        if (kid->tok.entries)
          for (int idx : *kid->tok.entries) goals.push_back(Masked::known(static_cast<std::uint64_t>(idx)));
        break;
      default:
        next(s, op.min_length);
        return;
    }
    for (const Masked &goal : goals) {
      std::vector<Solution> sols;
      try {
        SolveEnv e = env(&s.ins, &s.ctx);
        sols = solve(e, op.expr, off, shift, goal);
      } catch (const NeedsBackfill &) {
        State s2 = s;
        Backfill b{op.expr, off, shift, goal, true, s2.events.size()};
        s2.events.push_back(Event{false, Block{}});  // placeholder for its context reads
        s2.backfills.push_back(b);
        next(s2, op.min_length);
        continue;
      }
      if (sols.empty()) note("an operand's value can't be encoded here (out of range or misaligned)", 3);
      for (const Solution &sol : sols) {
        State s2 = s;
        if (!s2.ins.merge(sol.ins)) {
          note("operand values conflict", 2);
          continue;
        }
        if (!sol.ctx.empty()) {
          refresh(s2);
          if (!consistent(sol.ctx, s2.ctx)) continue;
          s2.events.push_back(Event{false, sol.ctx});
        }
        next(s2, op.min_length);
      }
    }
  }

  // The instruction table's root: the parsed tree, or (depth > 0) a
  // recursive prefix constructor around it.
  const Tree *root_tree = nullptr;
  void gen_root(int shift, State &s, int depth, const Cont &k) {
    if (depth <= 0) {
      gen_tree(*root_tree, shift, s, 0, k);
      return;
    }
    for (int ci : g->recursive_cons) {
      std::vector<const Child *> kids(g->cons[ci].ops.size(), nullptr);
      for (std::size_t j = 0; j < kids.size(); ++j)
        if (g->cons[ci].ops[j].kind == Operand::Subtable && g->cons[ci].ops[j].nt == g->start) kids[j] = kRecurse;
      gen_cons(ci, shift, s, kids, depth, k);
    }
  }

  // ---- completion of one generated tree ----

  void finish(State &s, int length) {
    if (length <= 0 || length > kMaxBytes) return;
    std::vector<std::pair<Block, std::vector<Event>>> alts{{s.ins, s.events}};
    // Backfills: inst_next is known now.
    for (const Backfill &b : s.backfills) {
      std::vector<std::pair<Block, std::vector<Event>>> next;
      for (auto &[ins, events] : alts) {
        SolveEnv e = env(&ins, nullptr);
        e.inst_next = (address + static_cast<std::uint64_t>(length)) / g->word_size;
        std::vector<Solution> sols;
        try {
          sols = solve(e, b.expr, b.at, b.cons_at, b.goal);
        } catch (const NeedsBackfill &) {
        }
        if (sols.empty()) note("a relative operand can't reach its target (out of range or misaligned)", 3);
        for (const Solution &sol : sols) {
          auto merged = Block::combine(ins, sol.ins);
          if (!merged) continue;
          auto ev = events;
          ev[b.event].req = sol.ctx;
          next.emplace_back(*merged, std::move(ev));
        }
      }
      alts = std::move(next);
    }
    for (auto &[ins, events] : alts) backward(ins, events, events.size(), Block{}, s.tree, length);
  }

  // Context requirements solved backwards from the end of the walk to the
  // address's context.
  void backward(const Block &ins, const std::vector<Event> &events, std::size_t n, Block req,
                const std::vector<int> &tree, int length) {
    while (n > 0) {
      const Event &ev = events[--n];
      if (!ev.write) {
        if (!req.merge(ev.req)) {
          note("the operands need a different processor mode (context)");
          return;
        }
        continue;
      }
      const ContextOp &op = g->cons[ev.cons].ctx_ops[ev.op];
      // Required bits this op writes.
      std::uint32_t rmask = 0, rval = 0;
      for (int b = 0; b < 4; ++b) {
        const int byte = 4 * op.word + b;
        if (byte >= req.len) continue;
        rmask |= static_cast<std::uint32_t>(req.mask[byte]) << (24 - 8 * b);
        rval |= static_cast<std::uint32_t>(req.val[byte]) << (24 - 8 * b);
      }
      rmask &= op.mask;
      for (int b = 0; b < 4; ++b) {
        const auto m = static_cast<std::uint8_t>(op.mask >> (24 - 8 * b));
        if (m) req.clear_bits(4 * op.word + b, m);
      }
      if (!rmask) continue;
      const Masked goal{static_cast<std::uint64_t>(rmask >> op.shift), static_cast<std::uint64_t>((rval & rmask) >> op.shift)};
      SolveEnv e = env(&ins, nullptr);
      e.inst_next = (address + static_cast<std::uint64_t>(length)) / g->word_size;
      const Masked v = evaluate(e, op.expr, ev.at, ev.at);
      if (v.full() || (v.msk & goal.msk) == goal.msk) {
        if (!v.agrees(goal)) {
          note("the operands need a different processor mode (context)");
          return;
        }
        continue;
      }
      std::vector<Solution> sols;
      try {
        sols = solve(e, op.expr, ev.at, ev.at, goal);
      } catch (const NeedsBackfill &) {
      }
      for (const Solution &sol : sols) {
        auto ins2 = Block::combine(ins, sol.ins);
        auto req2 = Block::combine(req, sol.ctx);
        if (ins2 && req2) backward(*ins2, events, n, *req2, tree, length);
      }
      return;
    }
    if (!consistent(req, c0)) {
      note("the instruction needs a different processor mode (context) at this address", 2);
      return;
    }
    emit(ins, tree, length);
  }

  // ---- candidates ----

  void emit(const Block &ins, const std::vector<int> &tree, int length) {
    if (ins.last_masked() > length) return;
    std::vector<std::uint8_t> fills[2];
    for (int f = 0; f < 2; ++f) {
      std::vector<std::uint8_t> bytes(static_cast<std::size_t>(length));
      for (int i = 0; i < length; ++i) {
        const std::uint8_t base =
            f == 0 && static_cast<std::size_t>(i) < opts->current.size() ? opts->current[static_cast<std::size_t>(i)] : 0;
        const std::uint8_t m = i < ins.len ? ins.mask[i] : 0, v = i < ins.len ? ins.val[i] : 0;
        bytes[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>((base & ~m) | (v & m));
      }
      fills[f] = std::move(bytes);
    }
    for (int f = 0; f < 2; ++f) {
      if (f == 1 && fills[1] == fills[0]) break;
      if (seen.contains({fills[f], tree})) return;
      if (verify(fills[f], tree, length)) return;
    }
  }

  bool verify(const std::vector<std::uint8_t> &bytes, const std::vector<int> &tree, int length) {
    seen.insert({bytes, tree});
    for (const Candidate &c : found)
      if (c.bytes == bytes) return true;
    auto d = decoder->decode(address, std::as_bytes(std::span(bytes)), context);
    if (!d) {
      note("the encoding doesn't decode");
      return false;
    }
    if (d->insn.length != static_cast<std::uint32_t>(length)) {
      note("the encoding decodes as a different instruction");
      return false;
    }
    std::vector<int> got;
    for (const auto *ct : d->tree) {
      auto it = entry->by_id.find({ct->getParent()->getName(), static_cast<unsigned>(ct->getId())});
      got.push_back(it == entry->by_id.end() ? -1 : it->second);
    }
    if (debug) {
      std::fprintf(stderr, "  verify %s:", d->insn.text.c_str());
      for (int x : got) std::fprintf(stderr, " %s", x >= 0 ? g->describe(x).c_str() : "?");
      std::fprintf(stderr, " | want");
      for (int x : tree) std::fprintf(stderr, " %s", g->describe(x).c_str());
      std::fprintf(stderr, "\n");
    }
    if (got != tree) {
      note("the encoding decodes as a different instruction");
      return false;
    }
    if (!matches_input(d->insn.text)) {
      note("the encoding decodes to different operands", 2);
      return false;
    }
    Candidate c;
    c.bytes = bytes;
    c.text = d->insn.text;
    unsigned h = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i)
      h += i < opts->current.size() ? static_cast<unsigned>(std::popcount(static_cast<unsigned>(bytes[i] ^ opts->current[i]))) : 8u;
    c.hamming = h;
    c.current = opts->current.size() >= bytes.size() && std::equal(bytes.begin(), bytes.end(), opts->current.begin());
    found.push_back(std::move(c));
    return true;
  }

  bool matches_input(std::string_view decoded) const {
    std::vector<Lexeme> a = lex(text), b = lex(decoded);
    if (!b.empty() && b[0].kind == 0 && !b[0].text.empty() && b[0].text[0] == '_') b[0].text.erase(0, 1);
    if (!a.empty() && a[0].kind == 0 && !a[0].text.empty() && a[0].text[0] == '_') a[0].text.erase(0, 1);
    // Labels in the input are their addresses.
    if (opts->symbols)
      for (std::size_t i = 1; i < a.size(); ++i)
        if (a[i].kind == 0)
          if (auto v = opts->symbols(a[i].raw)) a[i] = Lexeme{1, {}, static_cast<std::int64_t>(*v), {}};
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
      if (a[i].kind != b[i].kind) return false;
      if (a[i].kind == 1 ? !same_number(a[i].value, b[i].value) : a[i].text != b[i].text) return false;
    }
    return true;
  }
};

Assembler::Assembler(const std::string &language) : impl_(std::make_unique<Impl>()) {
  impl_->entry = grammar_for(language);
  impl_->g = impl_->entry->grammar.get();
  impl_->decoder = std::make_shared<lift::SleighDecoder>(language);
}

Assembler::~Assembler() = default;

const std::string &Assembler::language() const { return impl_->g->language; }

GrammarStats Assembler::stats() const {
  GrammarStats s;
  s.constructors = impl_->g->cons.size();
  s.productions = impl_->g->productions.size();
  s.terminals = impl_->g->terminals.size();
  s.nonterminals = impl_->g->nt_names.size();
  s.build_ms = impl_->entry->build_ms;
  return s;
}

std::vector<std::uint32_t> Assembler::default_context() const { return impl_->decoder->default_context(); }

bool Assembler::set_context(std::vector<std::uint32_t> &words, const std::string &name, std::uint32_t value) const {
  return impl_->decoder->set_context(words, name, value);
}

std::optional<std::uint32_t> Assembler::get_context(std::span<const std::uint32_t> words, const std::string &name) const {
  return impl_->decoder->get_context(words, name);
}

std::optional<Assembler::Disassembly> Assembler::disassemble(std::uint64_t address, std::span<const std::uint8_t> bytes,
                                                             std::span<const std::uint32_t> context) {
  auto d = impl_->decoder->decode(address, std::as_bytes(bytes), context);
  if (!d) return std::nullopt;
  Disassembly out{d->insn.text, d->insn.length, {}};
  for (const auto *ct : d->tree) out.constructors.push_back(ct->getParent()->getName() + ":" + std::to_string(ct->getLineno()));
  return out;
}

std::vector<std::string> Assembler::debug_productions() const {
  std::vector<std::string> out;
  const Grammar &g = *impl_->g;
  for (std::size_t p = 0; p < g.productions.size(); ++p) {
    std::string s = g.describe_production(static_cast<int>(p)) + "   {";
    for (int c : g.productions[p].cons) s += " " + g.describe(c);
    out.push_back(s + " }");
  }
  return out;
}

bool Assembler::same_text(std::string_view a, std::string_view b) {
  std::vector<Lexeme> x = lex(a), y = lex(b);
  if (x.size() != y.size()) return false;
  for (std::size_t i = 0; i < x.size(); ++i) {
    if (x[i].kind != y[i].kind) return false;
    if (x[i].kind == 1 ? !same_number(x[i].value, y[i].value) : x[i].text != y[i].text) return false;
  }
  return true;
}

Result Assembler::assemble(std::uint64_t address, std::string_view text, std::span<const std::uint32_t> context,
                           const Options &options) {
  const auto t0 = std::chrono::steady_clock::now();
  Impl &m = *impl_;
  Result r;
  // A delay slot's "_" prefix is display only.
  std::string line(text);
  while (!line.empty() && std::isspace(static_cast<unsigned char>(line.back()))) line.pop_back();
  std::size_t lead = 0;
  while (lead < line.size() && std::isspace(static_cast<unsigned char>(line[lead]))) ++lead;
  line.erase(0, lead);
  if (!line.empty() && line[0] == '_') line.erase(0, 1);
  m.address = address;
  m.context.assign(context.begin(), context.end());
  if (m.context.empty()) m.context = m.decoder->default_context();
  m.c0 = context_block(m.context);
  m.opts = &options;
  m.text = line;
  m.found.clear();
  m.seen.clear();
  m.failure.clear();
  m.failure_rank = 0;
  m.steps = 0;
  m.truncated = false;

  ParseResult parsed = parse(*m.g, line, options.symbols);
  if (parsed.trees.empty()) {
    r.error_column = static_cast<int>(lead) + parsed.stop + (text.size() > lead && text[lead] == '_' ? 1 : 0);
    std::set<std::string> exp;
    for (int t : parsed.expected)
      for (const std::string &s : m.g->terminals[t].suggestions()) exp.insert(s);
    exp.erase(" ");
    r.expected.assign(exp.begin(), exp.end());
    r.error = line.empty() ? "empty instruction"
                           : (parsed.stop >= static_cast<int>(line.size()) ? "incomplete instruction"
                                                                           : "syntax error at column " +
                                                                                 std::to_string(r.error_column + 1));
  } else {
    r.truncated = parsed.truncated;
    for (int depth = 0; depth <= (m.g->recursive_cons.empty() ? 0 : options.max_prefix_depth); ++depth) {
      for (const auto &tree : parsed.trees) {
        m.root_tree = tree.get();
        if (m.debug) {
          std::function<void(const Tree &, int)> show = [&](const Tree &t, int ind) {
            std::fprintf(stderr, "%*s%s\n", ind, "", m.g->describe_production(t.prod).c_str());
            for (const Child &c : t.kids)
              if (c.sub) show(*c.sub, ind + 2);
          };
          std::fprintf(stderr, "tree (depth %d):\n", depth);
          show(*tree, 2);
        }
        State s;
        s.ctx = m.c0;
        Cont done = [&m](State &st, int len) { m.finish(st, len); };
        m.gen_root(0, s, depth, done);
      }
      if (!m.found.empty()) break;
    }
    r.truncated = r.truncated || m.truncated;
    if (m.found.empty()) r.error = m.failure.empty() ? "no encoding found" : m.failure;
  }
  for (std::size_t i = 0; i < m.found.size(); ++i) m.found[i].order = static_cast<unsigned>(i);
  // Is the instruction there now in its canonical encoding? Then so should
  // the new one be, where lengths tie.
  bool canonical = false;
  if (m.found.size() > 1 && !options.current.empty() && !options.current_text.empty()) {
    std::vector<Candidate> found = std::move(m.found);
    const std::string current_text(options.current_text);
    Options plain;
    plain.symbols = options.symbols;
    plain.max_candidates = 1;
    plain.max_prefix_depth = options.max_prefix_depth;
    Result cur = assemble(address, current_text, context, plain);
    canonical = !cur.candidates.empty() && cur.candidates[0].bytes.size() <= options.current.size() &&
                std::equal(cur.candidates[0].bytes.begin(), cur.candidates[0].bytes.end(), options.current.begin());
    m.found = std::move(found);
    m.text = line;
    m.opts = &options;
  }
  std::sort(m.found.begin(), m.found.end(), [canonical](const Candidate &a, const Candidate &b) {
    if (a.bytes.size() != b.bytes.size()) return a.bytes.size() < b.bytes.size();
    if (canonical && a.order != b.order) return a.order < b.order;
    if (a.hamming != b.hamming) return a.hamming < b.hamming;
    return a.order < b.order;
  });
  if (m.found.size() > options.max_candidates) {
    m.found.resize(options.max_candidates);
    r.truncated = true;
  }
  r.candidates = std::move(m.found);
  r.micros = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - t0).count();
  return r;
}

Completion Assembler::complete(std::uint64_t, std::string_view text, std::size_t cursor,
                               std::span<const std::uint32_t>, const Options &options) {
  Completion c;
  cursor = std::min(cursor, text.size());
  Expectation e = expect(*impl_->g, text.substr(0, cursor), options.symbols);
  c.from = static_cast<std::size_t>(e.at);
  c.valid_prefix = e.ok;
  std::string partial;
  for (char ch : e.partial) partial += static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  std::set<std::string> items;
  for (int t : e.terms)
    for (const std::string &s : impl_->g->terminals[t].suggestions()) {
      if (s == " ") continue;
      if (s.rfind(partial, 0) == 0 || (s[0] == '<' && partial.empty())) items.insert(s);
    }
  c.items.assign(items.begin(), items.end());
  return c;
}

}  // namespace revkit::assembler
