#include "revkit/types/store.h"

#include "graph_util.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace revkit::types {
namespace {

constexpr std::uint32_t kNoScc = 0xffffffffu;
constexpr std::string_view kDomain{"revkit-type-v1\0", 15};

// A type's canonical encoding with its references cut out: head, then for
// each reference the bytes that follow it. References are filled in
// differently for minimization (local refs anonymous) and for hashing
// (store refs by hash, cycle members inline or by back-reference).
struct Template {
  std::string head;
  std::vector<TypeId> refs;
  std::vector<std::string> tails;
};

class TemplateWriter {
 public:
  explicit TemplateWriter(Template &t) : t_(t) {}
  void u8(std::uint8_t v) { cur().push_back(char(v)); }
  void u32(std::uint32_t v) {
    for (int i = 0; i < 4; ++i) u8(std::uint8_t(v >> (8 * i)));
  }
  void u64(std::uint64_t v) {
    for (int i = 0; i < 8; ++i) u8(std::uint8_t(v >> (8 * i)));
  }
  void str(std::string_view s) {
    u32(std::uint32_t(s.size()));
    cur().append(s);
  }
  void ref(TypeId id) {
    t_.refs.push_back(id);
    t_.tails.emplace_back();
  }

 private:
  std::string &cur() { return t_.tails.empty() ? t_.head : t_.tails.back(); }
  Template &t_;
};

Template make_template(const Type &type) {
  Template t;
  TemplateWriter w(t);
  std::visit(
      [&](const auto &d) {
        using D = std::decay_t<decltype(d)>;
        if constexpr (std::is_same_v<D, VoidType>) {
          w.u8('v');
        } else if constexpr (std::is_same_v<D, BoolType>) {
          w.u8('b'); w.u32(d.size);
        } else if constexpr (std::is_same_v<D, IntType>) {
          w.u8('i'); w.u32(d.size); w.u8(d.is_signed); w.u8(std::uint8_t(d.rank));
        } else if constexpr (std::is_same_v<D, FloatType>) {
          w.u8('f'); w.u32(d.size); w.u8(std::uint8_t(d.kind)); w.u8(d.complex);
        } else if constexpr (std::is_same_v<D, PointerType>) {
          w.u8('p'); w.u32(d.size); w.u8(std::uint8_t(d.kind)); w.ref(d.target);
        } else if constexpr (std::is_same_v<D, ArrayType>) {
          w.u8('a'); w.u64(d.count); w.ref(d.element);
        } else if constexpr (std::is_same_v<D, AggregateType>) {
          w.u8('s'); w.u8(std::uint8_t(d.kind)); w.str(d.name); w.u64(d.size);
          w.u32(d.alignment); w.u8(d.packed); w.u8(d.complete);
          w.u32(std::uint32_t(d.fields.size()));
          for (const Field &f : d.fields) {
            w.str(f.name); w.u64(f.bit_offset); w.u32(f.bit_size); w.ref(f.type);
          }
        } else if constexpr (std::is_same_v<D, EnumType>) {
          w.u8('e'); w.str(d.name); w.u32(d.size); w.u8(d.is_signed); w.u8(d.complete);
          w.u32(std::uint32_t(d.values.size()));
          for (const Enumerator &e : d.values) {
            w.str(e.name); w.u64(std::uint64_t(e.value));
          }
        } else if constexpr (std::is_same_v<D, TypedefType>) {
          w.u8('t'); w.str(d.name); w.ref(d.target);
        } else if constexpr (std::is_same_v<D, QualifiedType>) {
          w.u8('q'); w.u8(d.quals); w.ref(d.target);
        } else if constexpr (std::is_same_v<D, FunctionType>) {
          w.u8('F'); w.u8(std::uint8_t(d.cc)); w.u8(d.varargs);
          w.u32(std::uint32_t(d.params.size())); w.ref(d.ret);
          for (const Param &p : d.params) {
            w.str(p.name); w.ref(p.type);
          }
        } else if constexpr (std::is_same_v<D, UndefinedType>) {
          w.u8('u'); w.u32(d.size);
        }
      },
      type.data);
  return t;
}

void put(Sha256 &h, char tag) {
  std::uint8_t b = std::uint8_t(tag);
  h.update({&b, 1});
}
void put(Sha256 &h, const Hash &x) { h.update(x.bytes); }
void put_u32(Sha256 &h, std::uint32_t v) {
  std::uint8_t b[4] = {std::uint8_t(v), std::uint8_t(v >> 8), std::uint8_t(v >> 16),
                       std::uint8_t(v >> 24)};
  h.update(b);
}

const char *named(const Type &t) {
  if (auto *a = t.as<AggregateType>()) return a->name.empty() ? nullptr : a->name.c_str();
  if (auto *e = t.as<EnumType>()) return e->name.empty() ? nullptr : e->name.c_str();
  if (auto *d = t.as<TypedefType>()) return d->name.c_str();
  return nullptr;
}

std::uint32_t scalar_align(std::uint64_t size) {
  std::uint32_t a = 1;
  while (a < 16 && std::uint64_t(a) * 2 <= size && size % (std::uint64_t(a) * 2) == 0) a *= 2;
  return a;
}

// Natural alignment over any id space. get(id) returns the Type, or nullptr
// to defer to `fallback(id)` (store ids seen from a graph).
template <class Get, class Fallback, class Cache>
std::uint32_t natural_align(TypeId id, Get &&get, Fallback &&fallback, Cache &&cache, int depth) {
  if (depth > 256) return 1;
  const Type *t = get(id);
  if (!t) return fallback(id);
  if (std::uint32_t *c = cache(id); c && *c) return *c;
  std::uint32_t a = 1;
  std::visit(
      [&](const auto &d) {
        using D = std::decay_t<decltype(d)>;
        if constexpr (std::is_same_v<D, BoolType> || std::is_same_v<D, IntType> ||
                      std::is_same_v<D, FloatType> || std::is_same_v<D, PointerType> ||
                      std::is_same_v<D, EnumType>)
          a = scalar_align(d.size);
        else if constexpr (std::is_same_v<D, ArrayType>)
          a = natural_align(d.element, get, fallback, cache, depth + 1);
        else if constexpr (std::is_same_v<D, TypedefType> || std::is_same_v<D, QualifiedType>)
          a = natural_align(d.target, get, fallback, cache, depth + 1);
        else if constexpr (std::is_same_v<D, AggregateType>) {
          if (d.alignment) a = d.alignment;
          else if (!d.packed)
            for (const Field &f : d.fields)
              a = std::max(a, natural_align(f.type, get, fallback, cache, depth + 1));
        }
      },
      t->data);
  if (std::uint32_t *c = cache(id)) *c = a;
  return a;
}

// Throws unless every cycle passes through an aggregate and through a
// pointer or signature edge (see TypeGraph::break_invalid_cycles).
void check_cycles(const std::vector<Type> &nodes) {
  const std::size_t n = nodes.size();
  detail::Adjacency loose(n), contains(n);
  for (std::size_t v = 0; v < n; ++v) {
    bool agg = nodes[v].kind() == Kind::Aggregate;
    for_each_ref(nodes[v], [&](const TypeId &r, EdgeKind k) {
      if (!r.is_local()) return;
      if (!agg && nodes[r.index()].kind() != Kind::Aggregate) loose[v].push_back(r.index());
      if (k == EdgeKind::Contains) contains[v].push_back(r.index());
    });
  }
  if (!detail::cyclic_nodes(loose).empty())
    throw std::invalid_argument("type cycle does not pass through a struct or union");
  if (!detail::cyclic_nodes(contains).empty())
    throw std::invalid_argument("type contains itself by value");
}

}  // namespace

// ---- TypeGraph ----

TypeId TypeGraph::add(Type t) {
  align_cache_.clear();
  nodes_.emplace_back(std::move(t));
  return TypeId::local(std::uint32_t(nodes_.size() - 1));
}

TypeId TypeGraph::reserve() {
  align_cache_.clear();
  nodes_.emplace_back();
  return TypeId::local(std::uint32_t(nodes_.size() - 1));
}

void TypeGraph::set(TypeId local, Type t) {
  if (!local.is_local() || local.index() >= nodes_.size())
    throw std::out_of_range("TypeGraph::set: not a node of this graph");
  align_cache_.clear();
  nodes_[local.index()] = std::move(t);
}

Type &TypeGraph::at(TypeId local) {
  if (!local.is_local() || local.index() >= nodes_.size() || !nodes_[local.index()])
    throw std::out_of_range("TypeGraph::at: not a set node of this graph");
  align_cache_.clear();
  return *nodes_[local.index()];
}

const Type &TypeGraph::at(TypeId local) const {
  if (!local.is_local() || local.index() >= nodes_.size() || !nodes_[local.index()])
    throw std::out_of_range("TypeGraph::at: not a set node of this graph");
  return *nodes_[local.index()];
}

bool TypeGraph::is_set(TypeId local) const {
  return local.is_local() && local.index() < nodes_.size() && nodes_[local.index()].has_value();
}

std::size_t TypeGraph::break_invalid_cycles() {
  align_cache_.clear();
  std::size_t changed = 0;
  TypeId undef;
  auto is_agg = [&](std::uint32_t v) {
    return nodes_[v] && nodes_[v]->kind() == Kind::Aggregate;
  };
  auto fix = [&](bool by_value) {
    const std::size_t n = nodes_.size();
    detail::Adjacency adj(n);
    for (std::size_t v = 0; v < n; ++v) {
      if (!nodes_[v]) continue;
      for_each_ref(*nodes_[v], [&](TypeId &r, EdgeKind k) {
        if (!r.is_local() || r.index() >= n) return;
        if (by_value ? k == EdgeKind::Contains : !is_agg(std::uint32_t(v)) && !is_agg(r.index()))
          adj[v].push_back(r.index());
      });
    }
    std::vector<std::uint32_t> comp = detail::cyclic_nodes(adj);
    if (comp.empty()) return;
    // comp[v] is the component id of v if v is on a cycle, else kNone.
    if (!undef.valid()) undef = add(UndefinedType{1});
    for (std::size_t v = 0; v < n; ++v) {
      if (comp[v] == detail::kNone || !nodes_[v]) continue;
      for_each_ref(*nodes_[v], [&](TypeId &r, EdgeKind k) {
        if (!r.is_local() || r.index() >= n || comp[r.index()] != comp[v]) return;
        if (by_value ? k == EdgeKind::Contains : !is_agg(std::uint32_t(v)) && !is_agg(r.index())) {
          r = undef;
          ++changed;
        }
      });
    }
  };
  fix(false);
  fix(true);
  return changed;
}

std::uint32_t TypeGraph::align_of(TypeId id, const TypeStore &store) const {
  align_cache_.resize(nodes_.size(), 0);
  return natural_align(
      id,
      [&](TypeId t) -> const Type * {
        return t.is_local() && t.index() < nodes_.size() && nodes_[t.index()] ? &*nodes_[t.index()]
                                                                             : nullptr;
      },
      [&](TypeId t) -> std::uint32_t {
        return !t.is_local() && t.index() < store.size() ? store.align_of(t) : 1;
      },
      [&](TypeId t) -> std::uint32_t * { return &align_cache_[t.index()]; }, 0);
}

// ---- TypeStore ----

TypeStore::TypeStore() = default;

const Type &TypeStore::checked(TypeId id) const {
  if (!id.valid() || id.is_local() || id.index() >= types_.size())
    throw std::out_of_range("TypeStore: bad type id");
  return types_[id.index()];
}

const Type &TypeStore::get(TypeId id) const { return checked(id); }

const Hash &TypeStore::hash(TypeId id) const {
  checked(id);
  return hashes_[id.index()];
}

std::optional<TypeId> TypeStore::find(const Hash &h) const {
  auto it = by_hash_.find(h);
  if (it == by_hash_.end()) return std::nullopt;
  return it->second;
}

std::vector<TypeId> TypeStore::lookup(std::string_view name) const {
  std::vector<TypeId> out;
  auto [b, e] = by_name_.equal_range(std::string(name));
  for (auto it = b; it != e; ++it) out.push_back(it->second);
  std::sort(out.begin(), out.end());
  return out;
}

std::span<const TypeId> TypeStore::cycle_of(TypeId id) const {
  checked(id);
  std::uint32_t s = scc_[id.index()];
  if (s == kNoScc) return {};
  return sccs_[s];
}

TypeId TypeStore::intern(Type t) {
  TypeGraph g;
  g.add(std::move(t));
  return intern(g).front();
}

std::vector<TypeId> TypeStore::intern(const TypeGraph &graph) {
  const std::size_t n0 = graph.size();
  std::vector<Type> nodes;
  nodes.reserve(n0);
  for (std::size_t i = 0; i < n0; ++i) {
    TypeId id = TypeId::local(std::uint32_t(i));
    if (!graph.is_set(id)) throw std::invalid_argument("TypeGraph node was reserved but never set");
    nodes.push_back(graph.at(id));
    for_each_ref(nodes.back(), [&](const TypeId &r, EdgeKind) {
      if (!r.valid() || (r.is_local() ? r.index() >= n0 : r.index() >= types_.size()))
        throw std::invalid_argument("TypeGraph node has a dangling reference");
    });
  }
  check_cycles(nodes);

  // A local type can be equal to a member of a stored cycle without the
  // graph containing that cycle (L -> S2 where L equals S3 in S2 <-> S3).
  // Copying referenced stored cycles in lets minimization see the equality.
  std::unordered_map<std::uint32_t, std::uint32_t> clone_base;  // scc -> first clone index
  for (std::size_t i = 0; i < n0; ++i)
    for_each_ref(nodes[i], [&](const TypeId &r, EdgeKind) {
      if (!r.is_local() && scc_[r.index()] != kNoScc) clone_base.try_emplace(scc_[r.index()], 0);
    });
  std::vector<std::uint32_t> cloned;
  for (auto &[s, base] : clone_base) cloned.push_back(s);
  std::sort(cloned.begin(), cloned.end());
  auto pos = [&](std::uint32_t s, TypeId m) -> std::uint32_t {
    const auto &members = sccs_[s];
    auto p = std::lower_bound(members.begin(), members.end(), m);
    return p == members.end() || *p != m ? kNoScc : std::uint32_t(p - members.begin());
  };
  for (std::uint32_t s : cloned) {
    std::uint32_t base = std::uint32_t(nodes.size());
    clone_base[s] = base;
    for (TypeId m : sccs_[s]) nodes.push_back(types_[m.index()]);
    for (std::size_t k = base; k < nodes.size(); ++k)
      for_each_ref(nodes[k], [&](TypeId &r, EdgeKind) {
        if (std::uint32_t p = pos(s, r); !r.is_local() && p != kNoScc) r = TypeId::local(base + p);
      });
  }
  for (std::size_t i = 0; i < n0; ++i)
    for_each_ref(nodes[i], [&](TypeId &r, EdgeKind) {
      if (r.is_local() || scc_[r.index()] == kNoScc) return;
      std::uint32_t s = scc_[r.index()];
      r = TypeId::local(clone_base[s] + pos(s, r));
    });
  const std::size_t n = nodes.size();

  std::vector<Template> tp;
  tp.reserve(n);
  for (const Type &t : nodes) tp.push_back(make_template(t));

  // Minimize (Moore partition refinement): afterwards two nodes share a
  // class iff they denote the same (possibly infinite) type tree.
  std::vector<std::uint32_t> cls(n);
  std::size_t nclasses = 0;
  {
    std::unordered_map<Hash, std::uint32_t> ids;
    for (std::size_t v = 0; v < n; ++v) {
      Sha256 h;
      h.update(tp[v].head);
      for (std::size_t k = 0; k < tp[v].refs.size(); ++k) {
        TypeId r = tp[v].refs[k];
        if (r.is_local()) put(h, 'L');
        else { put(h, 'H'); put(h, hashes_[r.index()]); }
        h.update(tp[v].tails[k]);
      }
      auto [it, _] = ids.try_emplace(Hash::from_digest(h.finish()), std::uint32_t(ids.size()));
      cls[v] = it->second;
    }
    nclasses = ids.size();
  }
  for (;;) {
    std::unordered_map<std::vector<std::uint32_t>, std::uint32_t, detail::VecHash> ids;
    std::vector<std::uint32_t> next(n);
    std::vector<std::uint32_t> sig;
    for (std::size_t v = 0; v < n; ++v) {
      sig.assign(1, cls[v]);
      for (TypeId r : tp[v].refs)
        if (r.is_local()) sig.push_back(cls[r.index()]);
      auto [it, _] = ids.try_emplace(sig, std::uint32_t(ids.size()));
      next[v] = it->second;
    }
    cls.swap(next);
    if (ids.size() == nclasses) break;
    nclasses = ids.size();
  }

  std::vector<std::uint32_t> rep(nclasses, kNoScc);
  for (std::size_t v = 0; v < n; ++v)
    if (rep[cls[v]] == kNoScc) rep[cls[v]] = std::uint32_t(v);
  detail::Adjacency adj(nclasses);
  for (std::size_t c = 0; c < nclasses; ++c)
    for (TypeId r : tp[rep[c]].refs)
      if (r.is_local()) adj[c].push_back(cls[r.index()]);
  detail::Components comps = detail::tarjan(adj);  // sinks first

  // Hash each class: a DFS from it over its own component, writing nodes
  // inline on first visit and as back-references after; everything outside
  // the component is written as its (already computed) hash.
  std::vector<Hash> chash(nclasses);
  std::vector<std::uint32_t> order(nclasses, kNoScc);
  struct Frame { std::uint32_t c; std::size_t next; };
  std::vector<Frame> stack;
  for (std::size_t ci = 0; ci < comps.members.size(); ++ci) {
    const auto &members = comps.members[ci];
    for (std::uint32_t root : members) {
      Sha256 h;
      h.update(kDomain);
      std::uint32_t visits = 0;
      auto enter = [&](std::uint32_t c) {
        order[c] = visits++;
        put(h, 'N');
        h.update(tp[rep[c]].head);
        stack.push_back({c, 0});
      };
      enter(root);
      while (!stack.empty()) {
        Frame &f = stack.back();
        const Template &t = tp[rep[f.c]];
        if (f.next == t.refs.size()) {
          stack.pop_back();
          if (!stack.empty()) h.update(tp[rep[stack.back().c]].tails[stack.back().next - 1]);
          continue;
        }
        std::size_t k = f.next++;
        TypeId r = t.refs[k];
        if (!r.is_local()) {
          put(h, 'H'); put(h, hashes_[r.index()]);
        } else if (std::uint32_t rc = cls[r.index()]; comps.comp[rc] != ci) {
          put(h, 'H'); put(h, chash[rc]);
        } else if (order[rc] != kNoScc) {
          put(h, 'B'); put_u32(h, order[rc]);
        } else {
          enter(rc);
          continue;  // this tail is written when the child's frame pops
        }
        h.update(t.tails[k]);
      }
      chash[root] = Hash::from_digest(h.finish());
      for (std::uint32_t m : members) order[m] = kNoScc;
    }
  }

  // Map classes to store ids, reusing existing types.
  std::vector<TypeId> cid(nclasses);
  std::vector<std::uint32_t> fresh;
  std::unordered_map<Hash, TypeId> batch;
  for (std::size_t c = 0; c < nclasses; ++c) {
    if (auto it = by_hash_.find(chash[c]); it != by_hash_.end()) {
      cid[c] = it->second;
    } else if (auto bt = batch.find(chash[c]); bt != batch.end()) {
      cid[c] = bt->second;  // only on a hash collision; keep one
    } else {
      cid[c] = TypeId::store(std::uint32_t(types_.size() + fresh.size()));
      batch.emplace(chash[c], cid[c]);
      fresh.push_back(std::uint32_t(c));
    }
  }
  for (std::uint32_t c : fresh) {
    Type t = nodes[rep[c]];
    for_each_ref(t, [&](TypeId &r, EdgeKind) {
      if (r.is_local()) r = cid[cls[r.index()]];
    });
    if (const char *name = named(t)) by_name_.emplace(name, cid[c]);
    types_.push_back(std::move(t));
    hashes_.push_back(chash[c]);
    scc_.push_back(kNoScc);
    by_hash_.emplace(chash[c], cid[c]);
  }
  for (std::size_t ci = 0; ci < comps.members.size(); ++ci) {
    const auto &members = comps.members[ci];
    bool cyclic = members.size() > 1 ||
                  std::find(adj[members[0]].begin(), adj[members[0]].end(), members[0]) !=
                      adj[members[0]].end();
    if (!cyclic) continue;
    std::vector<TypeId> ids;
    for (std::uint32_t m : members)
      if (scc_[cid[m].index()] == kNoScc) ids.push_back(cid[m]);
    if (ids.empty()) continue;
    std::sort(ids.begin(), ids.end());
    for (TypeId id : ids) scc_[id.index()] = std::uint32_t(sccs_.size());
    sccs_.push_back(std::move(ids));
  }

  std::vector<TypeId> out(n0);
  for (std::size_t i = 0; i < n0; ++i) out[i] = cid[cls[i]];
  return out;
}

TypeId TypeStore::void_type() { return intern(VoidType{}); }
TypeId TypeStore::bool_type(std::uint32_t size) { return intern(BoolType{size}); }
TypeId TypeStore::int_type(std::uint32_t size, bool is_signed, IntRank rank) {
  return intern(IntType{size, is_signed, rank});
}
TypeId TypeStore::float_type(std::uint32_t size, FloatKind kind) {
  return intern(FloatType{size, kind, false});
}
TypeId TypeStore::pointer_to(TypeId target, std::uint32_t size, PointerKind kind) {
  return intern(PointerType{target, size, kind});
}
TypeId TypeStore::array_of(TypeId element, std::uint64_t count) {
  return intern(ArrayType{element, count});
}
TypeId TypeStore::typedef_of(std::string name, TypeId target) {
  return intern(TypedefType{std::move(name), target});
}
TypeId TypeStore::qualified(TypeId target, std::uint8_t quals) {
  return intern(QualifiedType{target, quals});
}
TypeId TypeStore::undefined(std::uint32_t size) { return intern(UndefinedType{size}); }
TypeId TypeStore::function(FunctionType f) { return intern(std::move(f)); }

std::uint64_t TypeStore::size_of(TypeId id) const {
  constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
  std::uint64_t mult = 1;
  for (std::size_t guard = 0; guard <= types_.size(); ++guard) {
    const Type &t = checked(id);
    std::uint64_t base = 0;
    switch (t.kind()) {
      case Kind::Typedef: id = t.as<TypedefType>()->target; continue;
      case Kind::Qualified: id = t.as<QualifiedType>()->target; continue;
      case Kind::Array: {
        std::uint64_t count = t.as<ArrayType>()->count;
        if (count == 0) return 0;
        mult = mult > kMax / count ? kMax : mult * count;
        id = t.as<ArrayType>()->element;
        continue;
      }
      case Kind::Bool: base = t.as<BoolType>()->size; break;
      case Kind::Int: base = t.as<IntType>()->size; break;
      case Kind::Float: base = t.as<FloatType>()->size; break;
      case Kind::Pointer: base = t.as<PointerType>()->size; break;
      case Kind::Aggregate: base = t.as<AggregateType>()->size; break;
      case Kind::Enum: base = t.as<EnumType>()->size; break;
      case Kind::Undefined: base = t.as<UndefinedType>()->size; break;
      case Kind::Void:
      case Kind::Function: base = 0; break;
    }
    return base != 0 && mult > kMax / base ? kMax : mult * base;
  }
  return 0;  // unreachable for valid stores: by-value chains are acyclic
}

std::uint32_t TypeStore::align_of(TypeId id) const {
  checked(id);
  if (align_cache_.size() < types_.size()) align_cache_.resize(types_.size(), 0);
  return natural_align(
      id, [&](TypeId t) -> const Type * { return &checked(t); },
      [](TypeId) -> std::uint32_t { return 1; },
      [&](TypeId t) -> std::uint32_t * { return &align_cache_[t.index()]; }, 0);
}

TypeId TypeStore::strip_typedefs(TypeId id, bool qualifiers) const {
  for (std::size_t guard = 0; guard <= types_.size(); ++guard) {
    const Type &t = checked(id);
    if (auto *d = t.as<TypedefType>()) id = d->target;
    else if (auto *q = t.as<QualifiedType>(); q && qualifiers) id = q->target;
    else return id;
  }
  return id;
}

}  // namespace revkit::types
