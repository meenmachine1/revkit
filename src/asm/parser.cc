// Earley parsing with span-matching terminals.

#include "parser.hh"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <unordered_map>
#include <unordered_set>

namespace revkit::assembler::detail {

namespace {

bool word_char(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; }

bool iequal_prefix(std::string_view text, std::size_t at, std::string_view lit) {
  if (text.size() - at < lit.size()) return false;
  for (std::size_t i = 0; i < lit.size(); ++i)
    if (std::tolower(static_cast<unsigned char>(text[at + i])) != static_cast<unsigned char>(lit[i])) return false;
  return true;
}

// [+-]? (0x hex | decimal); the end position and value, or nullopt.
std::optional<std::pair<int, std::int64_t>> number_at(std::string_view text, int at) {
  std::size_t i = static_cast<std::size_t>(at);
  bool neg = false;
  if (i < text.size() && (text[i] == '-' || text[i] == '+')) {
    neg = text[i] == '-';
    ++i;
  }
  if (i >= text.size() || !std::isdigit(static_cast<unsigned char>(text[i]))) return std::nullopt;
  std::uint64_t v = 0;
  std::size_t start = i;
  int base = 10;
  if (text[i] == '0' && i + 1 < text.size() && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
    base = 16;
    i += 2;
    start = i;
  }
  while (i < text.size()) {
    const char c = text[i];
    int d;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (base == 16 && c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else if (base == 16 && c >= 'A' && c <= 'F') d = c - 'A' + 10;
    else break;
    if (v > (~std::uint64_t{0} - static_cast<std::uint64_t>(d)) / static_cast<std::uint64_t>(base)) return std::nullopt;
    v = v * static_cast<std::uint64_t>(base) + static_cast<std::uint64_t>(d);
    ++i;
  }
  if (i == start) return std::nullopt;
  // A number runs into a word character: not a number ("0x12g").
  if (i < text.size() && word_char(text[i])) return std::nullopt;
  const std::int64_t s = static_cast<std::int64_t>(v);
  return std::pair{static_cast<int>(i), neg ? -s : s};
}

class Earley {
 public:
  Earley(const Grammar &g, std::string_view text, const SymbolLookup &symbols)
      : g_(g), text_(text), symbols_(symbols), sets_(text.size() + 1) {}

  struct Link {
    int pred = -1;       // item in set pred_set with dot-1 (-1 for dot 1 from a predicted item handled the same)
    int pred_set = -1;
    int child = -1;      // completed item index in set child_set, or -1
    int child_set = -1;
    int token = -1;      // token index, or -1
  };
  struct Item {
    int prod, dot, origin;
    std::vector<Link> links;
  };
  struct Set {
    std::vector<Item> items;
    std::unordered_map<std::uint64_t, int> index;
    std::unordered_map<int, std::vector<int>> waiting;  // nt -> items expecting it
    std::unordered_map<int, std::vector<int>> done;     // nt -> completed items with origin here
    std::unordered_set<int> predicted;
    std::vector<int> expected_terms;
  };

  void run() {
    add(0, {g_.start}, -1);
    for (std::size_t j = 0; j < sets_.size(); ++j) process(static_cast<int>(j));
  }

  // Index of an item, adding it if needed. `link` (if any) is attached.
  int add_item(int j, int prod, int dot, int origin, const Link *link) {
    Set &s = sets_[j];
    const std::uint64_t key = (static_cast<std::uint64_t>(prod) << 40) | (static_cast<std::uint64_t>(dot) << 24) |
                              static_cast<std::uint64_t>(origin);
    auto [it, fresh] = s.index.try_emplace(key, static_cast<int>(s.items.size()));
    if (fresh) s.items.push_back(Item{prod, dot, origin, {}});
    if (link) s.items[it->second].links.push_back(*link);
    return it->second;
  }

  void add(int j, std::initializer_list<int> nts, int) {
    for (int nt : nts) predict(j, nt);
  }

  void predict(int j, int nt) {
    if (!sets_[j].predicted.insert(nt).second) return;
    for (int p : g_.nt_productions[nt]) {
      if (g_.productions[p].pure_recursion) continue;
      add_item(j, p, 0, j, nullptr);
    }
  }

  void advance(int from_set, int from, int to_set, Link link) {
    const Item &it = sets_[from_set].items[from];
    link.pred = from;
    link.pred_set = from_set;
    add_item(to_set, it.prod, it.dot + 1, it.origin, &link);
  }

  void process(int j) {
    Set &s = sets_[j];
    for (std::size_t i = 0; i < s.items.size(); ++i) {
      const int prod = s.items[i].prod, dot = s.items[i].dot, origin = s.items[i].origin;
      const Production &p = g_.productions[prod];
      if (dot == static_cast<int>(p.rhs.size())) {
        // Complete: advance everything waiting for p.lhs at origin.
        Set &o = sets_[origin];
        if (origin == j) {
          auto &d = s.done[p.lhs];
          if (std::find(d.begin(), d.end(), static_cast<int>(i)) != d.end()) continue;
          d.push_back(static_cast<int>(i));
        }
        auto w = o.waiting.find(p.lhs);
        if (w == o.waiting.end()) continue;
        const std::vector<int> waiting = w->second;  // may grow while we add
        for (int k : waiting) advance(origin, k, j, Link{-1, -1, static_cast<int>(i), j, -1});
        continue;
      }
      const Sym sym = p.rhs[dot];
      if (sym.nt) {
        s.waiting[sym.id].push_back(static_cast<int>(i));
        predict(j, sym.id);
        // Nullable completions already made here.
        auto d = s.done.find(sym.id);
        if (d != s.done.end()) {
          const std::vector<int> done = d->second;
          for (int c : done) advance(j, static_cast<int>(i), j, Link{-1, -1, c, j, -1});
        }
        continue;
      }
      s.expected_terms.push_back(sym.id);
      for (int t : match(sym.id, j)) advance(j, static_cast<int>(i), tokens_[t].end, Link{-1, -1, -1, -1, t});
    }
  }

  // Tokens of terminal `term` starting at `at` (memoized).
  const std::vector<int> &match(int term, int at) {
    const std::uint64_t key = (static_cast<std::uint64_t>(term) << 32) | static_cast<std::uint32_t>(at);
    auto it = matched_.find(key);
    if (it != matched_.end()) return it->second;
    std::vector<int> &out = matched_[key];
    const Terminal &t = g_.terminals[term];
    auto emit = [&](int end, std::int64_t number = 0, const std::vector<int> *entries = nullptr) {
      tokens_.push_back(Token{term, at, end, number, entries});
      out.push_back(static_cast<int>(tokens_.size() - 1));
    };
    const std::size_t a = static_cast<std::size_t>(at);
    switch (t.kind) {
      case Terminal::Literal:
      case Terminal::Register:
        if (iequal_prefix(text_, a, t.text)) {
          // A word literal must not stop inside a word ("add" in "adds" is
          // fine: what follows is another terminal of the same word).
          emit(at + static_cast<int>(t.text.size()));
        }
        break;
      case Terminal::Space: {
        std::size_t b = a;
        while (b < text_.size() && std::isspace(static_cast<unsigned char>(text_[b]))) ++b;
        if (b == a && a > 0 && a < text_.size() && word_char(text_[a - 1]) && word_char(text_[a])) break;
        emit(static_cast<int>(b));
        break;
      }
      case Terminal::Number: {
        for (const auto &[name, value] : t.named)
          if (iequal_prefix(text_, a, name) && (a + name.size() >= text_.size() || !word_char(text_[a + name.size()])))
            emit(at + static_cast<int>(name.size()), value);
        if (auto n = number_at(text_, at)) {
          emit(n->first, n->second);
        } else if (a < text_.size() && (std::isalpha(static_cast<unsigned char>(text_[a])) || text_[a] == '_' ||
                                        text_[a] == '$' || text_[a] == '.')) {
          std::size_t b = a;
          while (b < text_.size() &&
                 (word_char(text_[b]) || text_[b] == '$' || text_[b] == '.' || text_[b] == '@'))
            ++b;
          if (symbols_)
            if (auto v = symbols_(text_.substr(a, b - a))) emit(static_cast<int>(b), static_cast<std::int64_t>(*v));
        }
        break;
      }
      case Terminal::Values:
        if (auto n = number_at(text_, at)) {
          auto v = t.values.find(n->second);
          if (v != t.values.end()) emit(n->first, n->second, &v->second);
        }
        break;
      case Terminal::Names:
        for (const auto &[name, entries] : t.names)
          if (iequal_prefix(text_, a, name)) emit(at + static_cast<int>(name.size()), 0, &entries);
        break;
    }
    return out;
  }

  // Trees of a completed item (memoized), capped.
  using Trees = std::vector<std::shared_ptr<const Tree>>;
  using Seqs = std::vector<std::vector<Child>>;

  const Seqs &sequences(int set, int item) {
    const std::uint64_t key = (static_cast<std::uint64_t>(set) << 32) | static_cast<std::uint32_t>(item);
    auto it = seq_memo_.find(key);
    if (it != seq_memo_.end()) return it->second;
    if (!active_.insert(key).second) {
      static const Seqs none;
      return none;  // a cycle: no finite trees through here
    }
    Seqs out;
    const Item &x = sets_[set].items[item];
    if (x.dot == 0) {
      out.push_back({});
    } else {
      for (const Link &l : x.links) {
        std::vector<Child> alts;
        if (l.token >= 0) {
          Child c;
          c.tok = tokens_[l.token];
          alts.push_back(std::move(c));
        } else {
          for (const auto &t : trees(l.child_set, l.child)) {
            Child c;
            c.sub = t;
            alts.push_back(std::move(c));
          }
        }
        if (alts.empty()) continue;
        const Seqs &prefix = sequences(l.pred_set, l.pred);
        for (const auto &pre : prefix)
          for (const Child &c : alts) {
            if (out.size() >= cap_) {
              truncated_ = true;
              break;
            }
            auto seq = pre;
            seq.push_back(c);
            out.push_back(std::move(seq));
          }
      }
    }
    active_.erase(key);
    return seq_memo_[key] = std::move(out);
  }

  const Trees &trees(int set, int item) {
    const std::uint64_t key = (static_cast<std::uint64_t>(set) << 32) | static_cast<std::uint32_t>(item);
    auto it = tree_memo_.find(key);
    if (it != tree_memo_.end()) return it->second;
    Trees out;
    const Item &x = sets_[set].items[item];
    for (auto &seq : sequences(set, item)) {
      auto t = std::make_shared<Tree>();
      t->prod = x.prod;
      t->start = x.origin;
      t->end = set;
      t->kids = seq;
      out.push_back(std::move(t));
    }
    return tree_memo_[key] = std::move(out);
  }

  ParseResult result(std::size_t cap) {
    cap_ = cap;
    ParseResult r;
    const int n = static_cast<int>(text_.size());
    const Set &last = sets_[n];
    for (std::size_t i = 0; i < last.items.size(); ++i) {
      const Item &x = last.items[i];
      const Production &p = g_.productions[x.prod];
      if (x.origin != 0 || p.lhs != g_.start || x.dot != static_cast<int>(p.rhs.size())) continue;
      for (const auto &t : trees(n, static_cast<int>(i))) {
        if (r.trees.size() >= cap) {
          r.truncated = true;
          break;
        }
        r.trees.push_back(t);
      }
    }
    r.truncated = r.truncated || truncated_;
    r.stop = furthest();
    r.expected = expected_at(r.stop);
    return r;
  }

  int furthest() const {
    for (int j = static_cast<int>(sets_.size()) - 1; j >= 0; --j)
      if (!sets_[j].items.empty()) return j;
    return 0;
  }

  std::vector<int> expected_at(int j) const {
    std::vector<int> out = sets_[j].expected_terms;
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
  }

 private:
  const Grammar &g_;
  std::string_view text_;
  const SymbolLookup &symbols_;
  std::vector<Set> sets_;
  std::vector<Token> tokens_;
  std::unordered_map<std::uint64_t, std::vector<int>> matched_;
  std::unordered_map<std::uint64_t, Seqs> seq_memo_;
  std::unordered_map<std::uint64_t, Trees> tree_memo_;
  std::unordered_set<std::uint64_t> active_;
  std::size_t cap_ = 4096;
  bool truncated_ = false;
};

}  // namespace

ParseResult parse(const Grammar &g, std::string_view text, const SymbolLookup &symbols, std::size_t max_trees) {
  Earley e(g, text, symbols);
  e.run();
  return e.result(max_trees);
}

Expectation expect(const Grammar &g, std::string_view prefix, const SymbolLookup &symbols) {
  Expectation out;
  // Back off over a partial word: suggestions complete it.
  std::size_t at = prefix.size();
  while (at > 0 && (word_char(prefix[at - 1]) || prefix[at - 1] == '.')) --at;
  Earley e(g, prefix.substr(0, at), symbols);
  e.run();
  const int stop = e.furthest();
  out.ok = stop == static_cast<int>(at);
  out.at = stop;
  out.partial = std::string(prefix.substr(static_cast<std::size_t>(stop)));
  out.terms = e.expected_at(stop);
  return out;
}

}  // namespace revkit::assembler::detail
