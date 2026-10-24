// Structures for classes of passed-on pointers (structures.h; docs/infer.md,
// "Structures").
//
// Nodes are values a function holds that point somewhere: a pointer
// parameter, a function's pointer return, a call's pointer result (in the
// caller), and the value loaded at one offset through any of those (a
// field). Each carries the reads and writes through it in its own function
// (Observation::pointer_uses and results). Union-find joins:
//   - a parameter passed on unchanged and the callee's parameter (the last
//     round's Slot::from_param edges);
//   - a parameter, field or result a function returns unchanged and its
//     return; a call's result and its callee's return; a result or a field
//     passed on unchanged and the callee's parameter;
//   - a field whose value flows back into its variable (p = p->next) and
//     the variable;
// and joining two classes joins their fields at each offset too
// (congruence: one structure's field has one type), so `L->l_G` of every
// function's lua_State is one node. An edge into a callee's node joins at
// once where the callee reads or writes through it itself (strong);
// otherwise (a wrapper passing it on, an allocator, a void * every caller
// passes its own to) only when every value reaching it is of one class
// (weak), else the node is generic and keeps its type. Classes whose
// accesses contradict (a pointer field read as a float or a narrower
// integer, or accessed inside, at two offsets or more) aren't joined.
//
// A class makes a structure when its accesses are mixed (not one scalar
// at its stride: an array; not bytes in runs: a buffer; not a string a
// library takes) at two or more offsets; repeating at a stride (with
// negative offsets, or every element alike) it is an array of one
// element structure. Fields are composed from all the class's accesses
// (compose_structure, keeping a wide field whole where splitting costs
// more); a field whose value has a structure of its own points to it.
#include "structures.h"

#include "sigdb.h"
#include "revkit/infer/accesses.h"

#include <algorithm>
#include <deque>
#include <map>
#include <set>

namespace revkit::infer {

namespace {

using VoteKey = std::pair<std::uint32_t, ValueKind>;  // size, kind
using Votes = std::map<VoteKey, std::uint32_t>;

struct Summary {
  std::map<std::int64_t, Votes> at;     // offset -> (size, kind) -> loads and stores
  std::map<std::int64_t, Votes> below;  // the same at negative offsets
  std::uint32_t accesses = 0;           // at offsets >= 0
  std::uint32_t negative = 0;
  bool string = false;   // passed to a library function's char * parameter
  bool library = false;  // a parameter something else typed (a library struct, a function)

  void add(const PointerAccess &a) {
    if (a.kind == AccessKind::passed || a.size == 0) return;
    if (a.offset < 0) {
      ++negative;
      ++below[a.offset][{a.size, a.value}];
      return;
    }
    ++at[a.offset][{a.size, a.value}];
    ++accesses;
  }
  void merge(const Summary &o) {
    for (const auto &[off, votes] : o.at) {
      Votes &mine = at[off];
      for (const auto &[k, n] : votes) mine[k] += n;
    }
    for (const auto &[off, votes] : o.below) {
      Votes &mine = below[off];
      for (const auto &[k, n] : votes) mine[k] += n;
    }
    accesses += o.accesses;
    negative += o.negative;
    string = string || o.string;
    library = library || o.library;
  }
};

// The size most accesses at an offset have (the wider on a tie), and the
// kind that most of those that say one say (a pointer if any does, as
// compose_structure types a field).
VoteKey dominant(const Votes &v) {
  std::map<std::uint32_t, std::uint32_t> sizes;
  for (const auto &[k, n] : v) sizes[k.first] += n;
  std::uint32_t size = 0, best_n = 0;
  for (const auto &[sz, n] : sizes)
    if (n >= best_n) size = sz, best_n = n;
  ValueKind kind = ValueKind::unknown;
  std::uint32_t kind_n = 0;
  for (const auto &[k, n] : v) {
    if (k.first != size || k.second == ValueKind::unknown) continue;
    if (k.second == ValueKind::pointer) return {size, ValueKind::pointer};
    if (n > kind_n) kind = k.second, kind_n = n;
  }
  return {size, kind};
}

bool is_int(ValueKind k) {
  return k == ValueKind::signed_int || k == ValueKind::unsigned_int || k == ValueKind::boolean;
}

// How much `b`'s accesses contradict the pointer fields of `a`: read as
// a float or a narrower integer where `a` holds a pointer, or starting
// inside it. The distinct offsets and `b`'s accesses there.
struct Conflict {
  std::uint32_t offsets = 0, accesses = 0;
};

std::uint32_t votes_of(const Votes &v) {
  std::uint32_t n = 0;
  for (const auto &[k, c] : v) n += c;
  return n;
}

void conflicts(const Summary &a, const Summary &b, std::uint32_t ptr, Conflict &out) {
  for (const auto &[off, votes] : a.at) {
    const VoteKey d = dominant(votes);
    if (d.first != ptr || d.second != ValueKind::pointer) continue;
    if (auto it = b.at.find(off); it != b.at.end()) {
      const VoteKey e = dominant(it->second);
      if (e.second == ValueKind::floating || (e.first < ptr && is_int(e.second))) {
        ++out.offsets;
        out.accesses += votes_of(it->second);
      }
    }
    for (auto it = b.at.upper_bound(off); it != b.at.end() && it->first < off + static_cast<std::int64_t>(ptr); ++it) {
      ++out.offsets;
      out.accesses += votes_of(it->second);
    }
  }
}

// Two classes are different things when their accesses contradict each
// other at two or more offsets, or in a quarter of the smaller one's
// accesses: a generic function's void * reached from two structures.
// One stray access (a compiler reading half a pointer, a union) isn't.
bool contradict(const Summary &a, const Summary &b, std::uint32_t ptr) {
  Conflict c;
  conflicts(a, b, ptr, c);
  conflicts(b, a, ptr, c);
  const std::uint32_t smaller = std::min(a.accesses, b.accesses);
  return c.offsets >= 2 || (c.accesses > 0 && c.accesses * 4 >= smaller);
}

struct Node {
  std::size_t parent = 0;
  std::uint64_t fn = 0;  // the function whose code it is
  Summary sum;           // a root's: its class's
  std::map<std::int64_t, std::size_t> children;  // a root's: field offset -> node
  // A parameter (proto, index), a function's return (proto), a call's
  // result (proto: the callee), or a loaded value (a field).
  enum class Kind : std::uint8_t { field, param, ret, result } kind = Kind::field;
  std::size_t proto = 0, index = 0;
  // Two different structures meet in it (a void * every caller passes
  // its own to, with few accesses of its own): it keeps the type it has.
  bool generic = false;
  std::uint32_t own = 0;  // its own reads and writes
};

class Classes {
 public:
  explicit Classes(std::uint32_t ptr) : ptr_(ptr) {}

  std::size_t add(std::uint64_t fn) {
    Node n;
    n.parent = nodes_.size();
    n.fn = fn;
    nodes_.push_back(std::move(n));
    return nodes_.size() - 1;
  }
  Node &at(std::size_t i) { return nodes_[i]; }
  std::size_t size() const { return nodes_.size(); }

  std::size_t find(std::size_t x) {
    while (nodes_[x].parent != x) x = nodes_[x].parent = nodes_[nodes_[x].parent].parent;
    return x;
  }

  // Whether these classes look like one structure: every two share two or
  // more offsets, half of the smaller's, with one size at each, and don't
  // contradict (values of one type that met nowhere else).
  bool alike(const std::set<std::size_t> &roots) {
    for (auto i = roots.begin(); i != roots.end(); ++i)
      for (auto j = std::next(i); j != roots.end(); ++j) {
        const Summary &a = nodes_[find(*i)].sum, &b = nodes_[find(*j)].sum;
        if (contradict(a, b, ptr_)) return false;
        std::uint32_t shared = 0;
        for (const auto &[off, votes] : a.at)
          if (auto it = b.at.find(off); it != b.at.end() && dominant(votes).first == dominant(it->second).first) ++shared;
        const std::size_t smaller = std::min(a.at.size(), b.at.size());
        if (shared < 2 || shared * 2 < smaller) return false;
      }
    return true;
  }

  // Joins the classes of a and b unless their accesses conflict (or their
  // fields' do, two levels down). Returns whether they are one class.
  bool unite(std::size_t a, std::size_t b) {
    if (!compatible(a, b, 0)) return false;
    merge(a, b);
    return true;
  }

 private:
  bool compatible(std::size_t a, std::size_t b, int depth) {
    a = find(a), b = find(b);
    if (a == b) return true;
    if (contradict(nodes_[a].sum, nodes_[b].sum, ptr_)) return false;
    if (depth >= 2) return true;
    for (const auto &[off, ca] : nodes_[a].children)
      if (auto it = nodes_[b].children.find(off); it != nodes_[b].children.end())
        if (!compatible(ca, it->second, depth + 1)) return false;
    return true;
  }

  // Joins without checking, and the fields at each offset with them.
  void merge(std::size_t x, std::size_t y) {
    std::vector<std::pair<std::size_t, std::size_t>> work{{x, y}};
    while (!work.empty()) {
      auto [p, q] = work.back();
      work.pop_back();
      p = find(p), q = find(q);
      if (p == q) continue;
      if (q < p) std::swap(p, q);
      nodes_[q].parent = p;
      nodes_[p].sum.merge(nodes_[q].sum);
      nodes_[q].sum = {};
      std::map<std::int64_t, std::size_t> kids = std::move(nodes_[q].children);
      nodes_[q].children.clear();
      for (const auto &[off, c] : kids) {
        auto [it, fresh] = nodes_[p].children.emplace(off, c);
        if (!fresh) work.emplace_back(it->second, c);
      }
    }
  }

  std::uint32_t ptr_;
  std::vector<Node> nodes_;
};

// What a class's accesses say its members point to.
struct Shape {
  bool structure = false;            // a structure: mixed accesses at two or more offsets
  std::uint64_t period = 0;          // an array of such structures, this long (0: one structure)
  std::optional<VType> element;      // otherwise, a uniform element type (an array of scalars)
};

// The element size of an array of structures, if the accesses repeat at
// one: folded at it (an offset's remainder), every remainder has accesses
// of one size that end within the element and overlap no other's, two or
// more remainders, the accesses fall in two or more elements, and there
// are negative offsets (a pointer to the end of an array: a stack's top)
// or, without them, every element has the same fields, of one kind each
// (a pointer, a float, an integer: a struct's fields rarely repeat so). The
// smallest such size (a multiple of 8, at most 256); 0 if none.
std::uint64_t period_of(const Summary &s, std::uint64_t max_offset) {
  struct Acc {
    std::int64_t offset;
    std::uint32_t size;  // dominant at it
    int group;           // -1 unknown, 0 integer, 1 pointer, 2 float
  };
  std::vector<Acc> acc;
  for (const auto *m : {&s.below, &s.at})
    for (const auto &[off, votes] : *m)
      if (off >= -static_cast<std::int64_t>(max_offset) && off <= static_cast<std::int64_t>(max_offset)) {
        const VoteKey d = dominant(votes);
        const int g = d.second == ValueKind::pointer ? 1 : d.second == ValueKind::floating ? 2
                      : d.second == ValueKind::unknown ? -1 : 0;
        acc.push_back({off, d.first, g});
      }
  if (acc.size() < 3) return 0;
  std::uint32_t widest = 0;
  for (const Acc &a : acc) widest = std::max(widest, a.size);
  for (std::int64_t p = 8; p <= 256; p += 8) {
    if (p < static_cast<std::int64_t>(widest)) continue;
    std::map<std::int64_t, std::uint32_t> folded;
    std::map<std::int64_t, int> kind;  // remainder -> its group, -2 when they disagree
    std::map<std::int64_t, std::set<std::int64_t>> elements;  // element -> its remainders
    bool ok = true;
    for (const Acc &a : acc) {
      const std::int64_t r = ((a.offset % p) + p) % p;
      elements[(a.offset - r) / p].insert(r);
      if (r + static_cast<std::int64_t>(a.size) > p) ok = false;
      auto [it, fresh] = folded.emplace(r, a.size);
      if (!fresh && it->second != a.size) ok = false;
      if (a.group >= 0) {
        auto [k, first] = kind.emplace(r, a.group);
        if (!first && k->second != a.group) k->second = -2;
      }
      if (!ok) break;
    }
    if (!ok || folded.size() < 2 || elements.size() < 2) continue;
    for (auto it = folded.begin(); ok && std::next(it) != folded.end(); ++it)
      if (it->first + static_cast<std::int64_t>(it->second) > std::next(it)->first) ok = false;
    if (!ok) continue;
    const bool same = std::all_of(elements.begin(), elements.end(),
                                  [&](const auto &e) { return e.second.size() == folded.size(); });
    const bool kinds = std::none_of(kind.begin(), kind.end(), [](const auto &k) { return k.second == -2; });
    if (s.below.empty() && !(same && kinds)) continue;
    return static_cast<std::uint64_t>(p);
  }
  return 0;
}

}  // namespace

void infer_structures(const std::vector<std::pair<std::uint64_t, const Observation *>> &unordered,
                      FixpointResult &r, const Abi &abi, const DataOrg &org,
                      const std::function<std::optional<Prototype>(std::uint64_t)> &library,
                      const StructureOptions &options) {
  // By entry: the joins (and so the result) don't depend on the order the
  // observations come in.
  std::vector<std::pair<std::uint64_t, const Observation *>> observations = unordered;
  std::sort(observations.begin(), observations.end(),
            [](const auto &a, const auto &b) { return a.first < b.first; });
  const std::uint32_t ptr = org.pointer_size;
  const Priors &pr = SigDb::priors(org);
  std::map<std::uint64_t, std::size_t> at;  // entry -> index in r.prototypes
  for (std::size_t i = 0; i < r.prototypes.size(); ++i) at.emplace(r.prototypes[i].first, i);
  auto int_index = [&](const Slot &s) { return infer::int_index(abi, s); };
  // Where ints and pointers are one size (32-bit targets), inference
  // types a word a pointer only on evidence from values (a static
  // address, a pointer passed in), and a struct pointer only ever used
  // with offsets is an integer to the decompiler (`*(int *)(param_1 +
  // 8)`). A word parameter its own code reads or writes through three or
  // more times at two or more offsets is a pointer here: it joins a class
  // like one, and gets the class's structure if the class makes one.
  std::set<std::pair<std::size_t, std::size_t>> word_pointers;  // (proto, param)
  if (ptr == 4)
    for (const auto &[entry, o] : observations) {
      auto fi = at.find(entry);
      if (o == nullptr || !o->ok || fi == at.end()) continue;
      const Prototype &proto = r.prototypes[fi->second].second;
      for (const PointerUse &u : o->pointer_uses) {
        if (u.param < 0 || static_cast<std::size_t>(u.param) >= o->params.size()) continue;
        const auto p = int_index(o->params[u.param]);
        if (!p || *p >= proto.params.size()) continue;
        const VType &t = proto.params[*p];
        if (t.size != ptr || (t.meta != Meta::int_ && t.meta != Meta::unknown)) continue;
        std::set<std::int64_t> offsets;
        std::size_t own = 0;
        for (const PointerAccess &a : u.accesses)
          if (a.kind != AccessKind::passed) {
            ++own;
            offsets.insert(a.offset);
          }
        if (own >= options.min_accesses && offsets.size() >= options.min_offsets) word_pointers.emplace(fi->second, *p);
      }
    }
  // A pointer parameter inference typed as a pointer of the target's size.
  auto pointer_param = [&](std::size_t f, std::size_t p) {
    const Prototype &proto = r.prototypes[f].second;
    if (word_pointers.contains({f, p})) return true;
    return p < proto.params.size() && proto.params[p].is_pointer() && proto.params[p].size == ptr;
  };

  // A pointer return inference typed as a pointer of the target's size.
  auto pointer_ret = [&](std::size_t f) {
    const VType &t = r.prototypes[f].second.ret;
    return t.is_pointer() && t.size == ptr;
  };

  Classes cls(ptr);
  std::map<std::pair<std::size_t, std::size_t>, std::size_t> pnodes;  // (proto, param) -> node
  std::map<std::size_t, std::size_t> rnodes;                          // proto -> its return's node
  std::map<std::pair<std::size_t, std::int64_t>, std::size_t> fnodes;  // (node, offset) -> F node
  // A library's type (a callback's prototype: main's argv), or a pointer
  // to a library struct or a function, is never replaced.
  auto typed_by_others = [&](std::size_t f, const VType &t) {
    const std::string &src = r.prototypes[f].second.source;
    return t.meta == Meta::struct_ || t.meta == Meta::code || src == "library" || src.starts_with("callback");
  };
  auto pnode = [&](std::size_t f, std::size_t p) {
    auto [it, fresh] = pnodes.emplace(std::pair{f, p}, 0);
    if (fresh) {
      it->second = cls.add(r.prototypes[f].first);
      Node &n = cls.at(it->second);
      n.kind = Node::Kind::param;
      n.proto = f;
      n.index = p;
      const VType &t = r.prototypes[f].second.params[p];
      if (t.is_pointer() && typed_by_others(f, t.target())) n.sum.library = true;
    }
    return it->second;
  };
  auto rnode = [&](std::size_t f) {
    auto [it, fresh] = rnodes.emplace(f, 0);
    if (fresh) {
      it->second = cls.add(r.prototypes[f].first);
      Node &n = cls.at(it->second);
      n.kind = Node::Kind::ret;
      n.proto = f;
      if (typed_by_others(f, r.prototypes[f].second.ret.target())) n.sum.library = true;
    }
    return it->second;
  };
  // A pointer passed to a library function's char * parameter is a string.
  auto to_string_param = [&](const Observation &o, const PointerAccess &a) {
    if (a.kind != AccessKind::passed || a.offset != 0 || a.parameter < 0) return false;
    std::vector<std::uint64_t> targets{a.callee};
    for (const CallSite &c : o.calls)
      if (c.address == a.address && c.target != 0) targets.push_back(c.target);
    for (std::uint64_t t : targets) {
      if (t == 0 || at.contains(t)) continue;
      const std::optional<Prototype> p = library(t);
      if (!p || static_cast<std::size_t>(a.parameter) >= p->params.size()) continue;
      const VType &v = p->params[a.parameter];
      if (v.is_pointer() && (v.target().meta == Meta::char_ || (v.target().meta == Meta::int_ && v.target().size == 1)))
        return true;
    }
    return false;
  };
  auto call_at = [](const Observation &o, std::uint64_t address) -> const CallSite * {
    for (const CallSite &c : o.calls)
      if (c.address == address) return &c;
    return nullptr;
  };
  // The callee's parameter a pointer passed (at offset 0) to a call
  // becomes, when the callee is one of the program's with a pointer there.
  auto passed_to = [&](const Observation &o, const PointerAccess &a) -> std::optional<std::size_t> {
    if (a.kind != AccessKind::passed || a.offset != 0 || a.parameter < 0) return std::nullopt;
    const CallSite *c = call_at(o, a.address);
    if (c == nullptr || c->target == 0 || static_cast<std::size_t>(a.parameter) >= c->args.size()) return std::nullopt;
    auto callee = at.find(c->target);
    if (callee == at.end()) return std::nullopt;
    const auto j = int_index(c->args[a.parameter]);
    if (!j || !pointer_param(callee->second, *j)) return std::nullopt;
    return pnode(callee->second, *j);
  };

  // The nodes and their own accesses: each pointer parameter's use and
  // each call result's, with the values loaded through them.
  struct Use {
    std::size_t node;
    std::size_t proto;  // the function whose code it is
    const PointerUse *use;
    const Observation *obs;
  };
  std::vector<Use> uses;
  std::map<std::size_t, const Observation *> seen;  // r.prototypes index -> its observation
  std::vector<std::pair<std::size_t, std::size_t>> selfs;  // (F node, its node): p = p->next
  auto add_use = [&](std::size_t node, std::size_t f, const PointerUse &u, const Observation &o) {
    for (const PointerAccess &a : u.accesses) {
      cls.at(node).sum.add(a);
      if (a.kind != AccessKind::passed) ++cls.at(node).own;
      if (to_string_param(o, a)) cls.at(node).sum.string = true;
    }
    for (const PointerUse::Field &fld : u.fields) {
      const std::size_t fnode = cls.add(r.prototypes[f].first);
      fnodes.emplace(std::pair{node, fld.offset}, fnode);
      cls.at(node).children.emplace(fld.offset, fnode);
      for (const PointerAccess &a : fld.accesses) {
        cls.at(fnode).sum.add(a);
        if (a.kind != AccessKind::passed) ++cls.at(fnode).own;
        if (to_string_param(o, a)) cls.at(fnode).sum.string = true;
      }
      // A field of the loaded value that flows back into it (a list
      // walked from the field) points to the same kind of thing.
      for (std::int64_t off : fld.self) cls.at(fnode).children.emplace(off, fnode);
    }
    for (std::int64_t off : u.self) {
      if (auto fn = fnodes.find({node, off}); fn != fnodes.end()) selfs.emplace_back(fn->second, node);
      else cls.at(node).children.emplace(off, node);
    }
    uses.push_back({node, f, &u, &o});
  };
  for (const auto &[entry, o] : observations) {
    auto fi = at.find(entry);
    if (o == nullptr || !o->ok || fi == at.end()) continue;
    seen.emplace(fi->second, o);
    for (const PointerUse &u : o->pointer_uses) {
      if (u.param < 0 || static_cast<std::size_t>(u.param) >= o->params.size()) continue;
      const auto p = int_index(o->params[u.param]);
      if (!p || !pointer_param(fi->second, *p)) continue;
      add_use(pnode(fi->second, *p), fi->second, u, *o);
    }
    for (const PointerUse &u : o->results) {
      const CallSite *c = call_at(*o, u.call);
      if (c == nullptr || c->target == 0) continue;
      auto callee = at.find(c->target);
      if (callee == at.end() || !pointer_ret(callee->second)) continue;
      const std::size_t q = cls.add(entry);
      cls.at(q).kind = Node::Kind::result;
      cls.at(q).proto = callee->second;
      add_use(q, fi->second, u, *o);
    }
  }
  // The joins. A value passed to a callee's parameter, or a call's result,
  // is what the callee takes or returns: an edge into that node. Where the
  // callee reads and writes through it itself (`own` accesses), its own
  // code says what it is, and the edge joins unless the accesses
  // contradict (a strong edge). Where it doesn't (a wrapper that passes
  // the pointer on, an allocator returning fresh memory, a void * every
  // caller passes its own to), the edges into it join only once the rest
  // is joined, and only when every value reaching it is of one class (or
  // its class has accesses of its own and theirs agree); else it is
  // generic and keeps its own type (weak edges).
  std::vector<std::pair<std::size_t, std::size_t>> strong;           // (from, to)
  std::map<std::size_t, std::vector<std::size_t>> weak;              // to -> from
  auto edge = [&](std::size_t from, std::size_t to) {
    if (cls.at(to).own >= options.min_accesses) strong.emplace_back(from, to);
    else weak[to].push_back(from);
  };
  // Fields that point back to their own variable's kind: one class.
  for (const auto &[f, n] : selfs) strong.emplace_back(f, n);
  // Parameters passed on unchanged.
  for (const auto &[f, obs] : seen) {
    const Observation &o = *obs;
    for (const CallSite &c : o.calls) {
      auto callee = at.find(c.target);
      if (c.target == 0 || callee == at.end()) continue;
      for (const Slot &a : c.args) {
        if (a.from_param < 0 || static_cast<std::size_t>(a.from_param) >= o.params.size()) continue;
        const auto i = int_index(o.params[a.from_param]);
        const auto j = int_index(a);
        if (!i || !j || (callee->second == f && *i == *j)) continue;
        if (!pointer_param(f, *i) || !pointer_param(callee->second, *j)) continue;
        edge(pnode(f, *i), pnode(callee->second, *j));
      }
    }
  }
  // Returns: a parameter, a field or a call's result the function returns
  // unchanged is its return (strong: its own code); a call's result is
  // its callee's return; a result passed on unchanged, the parameter.
  for (const Use &u : uses) {
    const Node &n = cls.at(u.node);
    if (u.use->returned && pointer_ret(u.proto)) strong.emplace_back(u.node, rnode(u.proto));
    if (n.kind != Node::Kind::result) continue;
    weak[rnode(n.proto)].push_back(u.node);
    for (const PointerAccess &a : u.use->accesses)
      if (auto p = passed_to(*u.obs, a)) edge(u.node, *p);
  }
  // Fields passed on unchanged or returned.
  for (const Use &u : uses)
    for (const PointerUse::Field &fld : u.use->fields) {
      auto fn = fnodes.find({u.node, fld.offset});
      if (fn == fnodes.end()) continue;
      if (fld.returned && pointer_ret(u.proto)) strong.emplace_back(fn->second, rnode(u.proto));
      for (const PointerAccess &a : fld.accesses)
        if (auto p = passed_to(*u.obs, a)) edge(fn->second, *p);
    }
  for (const auto &[from, to] : strong) cls.unite(from, to);
  // Weak edges, until nothing more joins; then what still has values of
  // two classes reaching it is generic.
  for (bool more = true, last = false;;) {
    more = false;
    for (const auto &[to, from] : weak) {
      if (cls.at(to).generic) continue;
      const std::size_t root = cls.find(to);
      std::set<std::size_t> sources;
      for (std::size_t f : from)
        if (const std::size_t x = cls.find(f); x != root) sources.insert(x);
      if (sources.empty()) continue;
      if (cls.at(root).sum.accesses >= options.min_accesses) {
        // Its class has accesses of its own: each value that agrees joins.
        for (std::size_t x : sources)
          if (cls.unite(x, root)) more = true;
          else if (last) cls.at(to).generic = true;
      } else if (sources.size() == 1 || cls.alike(sources)) {
        for (std::size_t x : sources) more = cls.unite(x, root) || more;
      } else if (last) {
        cls.at(to).generic = true;
      }
    }
    if (last) break;
    if (!more) last = true;
  }

  // Each class's shape.
  std::map<std::size_t, Shape> shapes;
  auto shape_of = [&](std::size_t root) -> const Shape & {
    auto [it, fresh] = shapes.emplace(root, Shape{});
    if (!fresh) return it->second;
    const Summary &s = cls.at(root).sum;
    Shape &out = it->second;
    if (s.string || s.library || s.accesses + s.negative == 0) return out;
    std::uint32_t offsets = 0, accesses = 0;
    std::set<std::uint32_t> sizes;
    std::set<int> groups;  // 0 int or unknown, 1 pointer, 2 float
    bool aligned = true;
    std::set<ValueKind> kinds;
    for (const auto &[off, votes] : s.below)
      for (const auto &[k, n] : votes) {
        sizes.insert(k.first);
        kinds.insert(k.second);
        if (k.second == ValueKind::pointer) groups.insert(1);
        else if (k.second == ValueKind::floating) groups.insert(2);
        else if (k.second != ValueKind::unknown) groups.insert(0);
        if (off % static_cast<std::int64_t>(k.first) != 0) aligned = false;
      }
    for (const auto &[off, votes] : s.at) {
      if (off > static_cast<std::int64_t>(options.max_offset)) continue;
      ++offsets;
      for (const auto &[k, n] : votes) {
        accesses += n;
        sizes.insert(k.first);
        kinds.insert(k.second);
        if (k.second == ValueKind::pointer) groups.insert(1);
        else if (k.second == ValueKind::floating) groups.insert(2);
        else if (k.second != ValueKind::unknown) groups.insert(0);
        if (off % static_cast<std::int64_t>(k.first) != 0) aligned = false;
      }
    }
    if (accesses + s.negative == 0) return out;
    // Where pointers are word-sized like ints (32-bit), a field whose
    // loaded value is read or written through is a pointer whatever the
    // decompiler typed the load: words of which some are dereferenced are
    // a structure (a queue's head, tail and items), not an array of ints.
    if (ptr == 4)
      for (const auto &[off, child] : cls.at(root).children) {
        const Summary &c = cls.at(cls.find(child)).sum;
        if (off >= 0 && c.accesses + c.negative > 0) groups.insert(1);
      }
    if (sizes.size() == 1 && groups.size() <= 1 && aligned) {
      // An array of scalars (bytes, ints, pointers): the pointer to its
      // element is the type, as the decompiler indexes it.
      const std::uint32_t size = *sizes.begin();
      const int g = groups.empty() ? 0 : *groups.begin();
      if (g == 1) out.element = VType::pointer_to(pr.pointee, static_cast<std::uint8_t>(ptr));
      else if (g == 2) out.element = VType::floating(static_cast<std::uint8_t>(size));
      else if (size == 1) out.element = pr.pointee.meta == Meta::char_ ? pr.pointee : VType::character();
      else if (size <= 8 && kinds.contains(ValueKind::signed_int) != kinds.contains(ValueKind::unsigned_int))
        out.element = VType::integer(static_cast<std::uint8_t>(size),
                                     kinds.contains(ValueKind::signed_int) ? Sign::is_signed : Sign::is_unsigned);
      else if (size <= 8) out.element = pr.unknown_param(static_cast<std::uint8_t>(size));
      return out;
    }
    // Bytes read one by one at consecutive offsets, eight or more in a
    // row, are a buffer (an unrolled checksum, a copy), whatever wider
    // words are read from it too: a buffer when they are most of it.
    std::uint32_t run = 0, in_runs = 0;
    std::int64_t last = -2;
    for (const auto &[off, votes] : s.at) {
      if (off > static_cast<std::int64_t>(options.max_offset)) break;
      const bool byte = std::any_of(votes.begin(), votes.end(), [](const auto &v) { return v.first.first == 1; });
      run = byte && off == last + 1 ? run + 1 : byte ? 1 : 0;
      last = off;
      if (run == 8) in_runs += 8;
      else if (run > 8) ++in_runs;
    }
    if (in_runs * 2 >= offsets) {
      out.element = pr.pointee.meta == Meta::char_ ? pr.pointee : VType::character();
      return out;
    }
    if (accesses + s.negative >= options.min_accesses)
      if (const std::uint64_t p = period_of(s, options.max_offset); p != 0) {
        out.structure = true;
        out.period = p;
        return out;
      }
    out.structure = offsets >= options.min_offsets && accesses >= options.min_accesses && s.negative * 4 <= accesses;
    return out;
  };

  // Members of each class.
  // root -> the parameters and returns it types, by (entry, position;
  // the return after the parameters)
  std::map<std::size_t, std::vector<std::size_t>> members;
  std::map<std::size_t, std::set<std::uint64_t>> functions;
  for (std::size_t i = 0; i < cls.size(); ++i) {
    const std::size_t root = cls.find(i);
    const Node &n = cls.at(i);
    if ((n.kind == Node::Kind::param || n.kind == Node::Kind::ret) && !n.generic) members[root].push_back(i);
    if (n.own > 0 || n.kind == Node::Kind::param) functions[root].insert(n.fn);
  }
  auto key = [&](std::size_t i) {
    const Node &n = cls.at(i);
    return std::pair{r.prototypes[n.proto].first, n.kind == Node::Kind::ret ? SIZE_MAX : n.index};
  };
  for (auto &[root, list] : members)
    std::sort(list.begin(), list.end(), [&](std::size_t a, std::size_t b) { return key(a) < key(b); });
  std::vector<std::size_t> firsts;  // classes with members that make structures, by first member
  for (const auto &[root, list] : members)
    if (shape_of(root).structure) firsts.push_back(root);
  std::sort(firsts.begin(), firsts.end(), [&](std::size_t a, std::size_t b) {
    return key(members[a].front()) < key(members[b].front());
  });

  // Structures, breadth first from the parameters' classes through the
  // fields that point to other classes' structures.
  std::map<std::size_t, std::string> names;
  std::deque<std::size_t> queue;
  auto name_of = [&](std::size_t root) -> const std::string & {
    auto [it, fresh] = names.emplace(root, std::string());
    if (fresh) {
      it->second = "astruct_" + std::to_string(names.size());
      queue.push_back(root);
    }
    return it->second;
  };
  for (std::size_t root : firsts) name_of(root);
  std::map<std::size_t, InferredStructure> made;
  while (!queue.empty()) {
    const std::size_t root = queue.front();
    queue.pop_front();
    const Summary &s = cls.at(root).sum;
    const std::uint64_t period = shape_of(root).period;
    // An array's accesses fold onto one element.
    auto fold = [&](std::int64_t off) {
      if (period == 0) return off;
      const auto p = static_cast<std::int64_t>(period);
      return ((off % p) + p) % p;
    };
    std::vector<PointerAccess> accesses;
    for (const auto *m : {&s.at, &s.below})
      for (const auto &[off, votes] : *m) {
        if (off < 0 && period == 0) continue;
        for (const auto &[k, n] : votes)
          for (std::uint32_t i = 0; i < n; ++i) {
            PointerAccess a;
            a.offset = fold(off);
            a.size = k.first;
            a.value = k.second;
            accesses.push_back(a);
          }
      }
    // A field's value, at the first element whose field has one.
    auto child_at = [&](std::uint64_t off) -> std::optional<std::size_t> {
      const auto &kids = cls.at(root).children;
      if (auto it = kids.find(static_cast<std::int64_t>(off)); it != kids.end()) return it->second;
      if (period != 0)
        for (const auto &[o, c] : kids)
          if (fold(o) == static_cast<std::int64_t>(off)) return c;
      return std::nullopt;
    };
    ComposeOptions co;
    co.max_offset = options.max_offset;
    co.pointer_size = ptr;
    co.keep_wide = true;
    const StructurePlan plan = compose_structure(accesses, co);
    InferredStructure st;
    st.name = names.at(root);
    st.size = plan.size;
    st.accesses = s.accesses;
    st.functions = static_cast<std::uint32_t>(functions[root].size());
    for (const PlannedField &p : plan.fields) {
      InferredField f;
      f.offset = p.offset;
      f.size = p.size;
      f.accesses = p.accesses;
      const std::optional<std::size_t> child = child_at(p.offset);
      const bool deref = child && cls.at(cls.find(*child)).sum.accesses + cls.at(cls.find(*child)).sum.negative > 0;
      if (p.size == ptr && !p.truncated && (p.value == ValueKind::pointer || deref)) {
        f.type = VType::pointer_to(pr.pointee, static_cast<std::uint8_t>(ptr));
        if (deref) {
          const std::size_t c = cls.find(*child);
          const Shape &sh = shape_of(c);
          if (sh.structure) f.type = VType::pointer_to(VType::structure(name_of(c)), static_cast<std::uint8_t>(ptr));
          else if (sh.element) f.type = VType::pointer_to(*sh.element, static_cast<std::uint8_t>(ptr));
        }
      } else {
        switch (p.value) {
          case ValueKind::floating: f.type = VType::floating(static_cast<std::uint8_t>(p.size)); break;
          case ValueKind::boolean: f.type = VType::boolean(); break;
          case ValueKind::signed_int:
            f.type = VType::integer(static_cast<std::uint8_t>(p.size), Sign::is_signed);
            break;
          case ValueKind::unsigned_int:
            f.type = VType::integer(static_cast<std::uint8_t>(p.size), Sign::is_unsigned);
            break;
          default:
            f.type = p.size == 1 || p.size == 2 || p.size == 4 || p.size == 8
                         ? pr.unknown_param(static_cast<std::uint8_t>(p.size))
                         : VType::unknown(static_cast<std::uint8_t>(std::min<std::uint32_t>(p.size, 255)));
            break;
        }
        if (f.type.meta == Meta::pointer || f.type.size != p.size) f.type = VType::unknown(static_cast<std::uint8_t>(std::min<std::uint32_t>(p.size, 255)));
      }
      st.fields.push_back(std::move(f));
    }
    // The size rounded up to the fields' alignment, as a compiler lays the
    // struct out (an array of them then indexes by its size), unless a
    // field sits below its own alignment.
    std::uint64_t align = 1;
    bool natural = true;
    for (const InferredField &f : st.fields) {
      std::uint64_t a = 1;
      if (f.type.meta != Meta::unknown && f.size <= ptr && (f.size & (f.size - 1)) == 0) a = f.size;
      if (f.offset % a != 0) natural = false;
      align = std::max(align, a);
    }
    if (natural) st.size = (st.size + align - 1) / align * align;
    if (period != 0) st.size = period;
    made.emplace(root, std::move(st));
  }
  // The parameters and returns point to their class's structure.
  for (auto &[root, st] : made) {
    auto m = members.find(root);
    if (m == members.end()) continue;
    for (std::size_t n : m->second) {
      const Node &node = cls.at(n);
      VType to = VType::pointer_to(VType::structure(st.name), static_cast<std::uint8_t>(ptr));
      if (node.kind == Node::Kind::ret) {
        r.prototypes[node.proto].second.ret = std::move(to);
        ++st.returns;
      } else {
        r.prototypes[node.proto].second.params[node.index] = std::move(to);
        ++st.parameters;
      }
    }
  }
  std::vector<InferredStructure> out;
  for (auto &[root, st] : made) out.push_back(std::move(st));
  std::sort(out.begin(), out.end(), [](const InferredStructure &a, const InferredStructure &b) {
    return std::stoul(a.name.substr(8)) < std::stoul(b.name.substr(8));
  });
  r.structures = std::move(out);
}

}  // namespace revkit::infer
