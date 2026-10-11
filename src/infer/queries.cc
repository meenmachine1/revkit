// infer.callgraph, infer.observe, infer.round, infer.fixpoint and
// infer.prototype; the parallel driver.

#include "revkit/infer/infer.h"

#include "abi.h"
#include "merge.h"
#include "sigdb.h"

#include "revkit/analysis/memory.h"
#include "revkit/facts/thread_pool.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>

#ifdef __GLIBC__
#include <malloc.h>
#endif

namespace revkit::infer {

namespace an = analysis;

// ---- codecs ----

void Options::encode(facts::Encoder &e) const {
  e.varint(max_rounds);
  e.varint(change_budget);
  facts::encode(e, interprocedural);
  facts::encode(e, library);
  facts::encode(e, defaults);
  e.varint(max_varnodes);
  facts::encode(e, keep_return_width);
}

Options Options::decode(facts::Decoder &d) {
  Options o;
  o.max_rounds = facts::decode<std::uint32_t>(d);
  o.change_budget = facts::decode<std::uint32_t>(d);
  o.interprocedural = facts::decode<bool>(d);
  o.library = facts::decode<bool>(d);
  o.defaults = facts::decode<bool>(d);
  o.max_varnodes = facts::decode<std::uint32_t>(d);
  o.keep_return_width = facts::decode<bool>(d);
  return o;
}

void ImageRef::encode(facts::Encoder &e) const {
  e.bytes(identity);
  e.bytes(language_id);
  options.encode(e);
}

ImageRef ImageRef::decode(facts::Decoder &d) {
  ImageRef r;
  r.identity = std::string(d.bytes());
  r.language_id = std::string(d.bytes());
  r.options = Options::decode(d);
  return r;
}

void CallNode::encode(facts::Encoder &e) const {
  e.varint(entry);
  e.bytes(name);
  e.bytes(import);
  e.varint(thunk_target);
  facts::encode(e, no_return);
  facts::encode(e, from_data);
  facts::encode(e, callees);
  facts::encode(e, callers);
}

CallNode CallNode::decode(facts::Decoder &d) {
  CallNode n;
  n.entry = d.varint();
  n.name = std::string(d.bytes());
  n.import = std::string(d.bytes());
  n.thunk_target = d.varint();
  n.no_return = facts::decode<bool>(d);
  n.from_data = facts::decode<bool>(d);
  n.callees = facts::decode<std::vector<std::uint64_t>>(d);
  n.callers = facts::decode<std::vector<std::uint64_t>>(d);
  return n;
}

const CallNode *CallGraph::find(std::uint64_t entry) const {
  auto it = std::lower_bound(nodes.begin(), nodes.end(), entry,
                             [](const CallNode &n, std::uint64_t a) { return n.entry < a; });
  return it != nodes.end() && it->entry == entry ? &*it : nullptr;
}

const std::string *CallGraph::slot(std::uint64_t address) const {
  auto it = std::lower_bound(slots.begin(), slots.end(), address,
                             [](const auto &s, std::uint64_t a) { return s.first < a; });
  return it != slots.end() && it->first == address ? &it->second : nullptr;
}

void CallGraph::encode(facts::Encoder &e) const {
  facts::encode(e, nodes);
  facts::encode(e, slots);
}

CallGraph CallGraph::decode(facts::Decoder &d) {
  CallGraph g;
  g.nodes = facts::decode<std::vector<CallNode>>(d);
  g.slots = facts::decode<std::vector<std::pair<std::uint64_t, std::string>>>(d);
  return g;
}

void RoundKey::encode(facts::Encoder &e) const {
  facts::encode(e, at);
  e.varint(round);
}

RoundKey RoundKey::decode(facts::Decoder &d) {
  RoundKey k;
  k.at = facts::decode<Location>(d);
  k.round = facts::decode<std::uint32_t>(d);
  return k;
}

void Inferred::encode(facts::Encoder &e) const {
  facts::encode(e, known);
  proto.encode(e);
  e.varint(changes);
  facts::encode(e, widened);
}

Inferred Inferred::decode(facts::Decoder &d) {
  Inferred i;
  i.known = facts::decode<bool>(d);
  i.proto = Prototype::decode(d);
  i.changes = facts::decode<std::uint32_t>(d);
  i.widened = facts::decode<bool>(d);
  return i;
}

const Prototype *FixpointResult::find(std::uint64_t entry) const {
  auto it = std::lower_bound(prototypes.begin(), prototypes.end(), entry,
                             [](const auto &p, std::uint64_t a) { return p.first < a; });
  return it != prototypes.end() && it->first == entry ? &it->second : nullptr;
}

void FixpointResult::encode(facts::Encoder &e) const {
  e.varint(rounds);
  facts::encode(e, converged);
  facts::encode(e, changed);
  e.varint(widened);
  facts::encode(e, prototypes);
}

FixpointResult FixpointResult::decode(facts::Decoder &d) {
  FixpointResult r;
  r.rounds = facts::decode<std::uint32_t>(d);
  r.converged = facts::decode<bool>(d);
  r.changed = facts::decode<std::vector<std::uint32_t>>(d);
  r.widened = facts::decode<std::uint32_t>(d);
  r.prototypes = facts::decode<std::vector<std::pair<std::uint64_t, Prototype>>>(d);
  return r;
}

std::string Observe::describe(const Key &k) { return an::describe(k.at) + "@" + std::to_string(k.round); }
std::string Round::describe(const Key &k) { return an::describe(k.at) + "@" + std::to_string(k.round); }
std::string Own::describe(const Key &k) { return an::describe(k.at) + "@" + std::to_string(k.round); }

DataOrg data_org(const loader::Image &image) {
  DataOrg org;
  org.pointer_size = static_cast<std::uint8_t>(image.bits / 8);
  org.long_size = image.format == loader::Format::pe ? 4 : org.pointer_size;
  return org;
}

// ---- call graph ----

namespace {

void sort_unique(std::vector<std::uint64_t> &v) {
  std::sort(v.begin(), v.end());
  v.erase(std::unique(v.begin(), v.end()), v.end());
}

// Pointer-sized words in initialized, non-executable data whose value (or
// RELATIVE relocation target) is an address in executable memory.
struct CodeSlot {
  std::uint64_t address, target;
  std::size_t block;
};

std::vector<CodeSlot> code_pointer_slots(const loader::Image &image) {
  const unsigned ptr = image.bits / 8;
  const bool big = image.endian == loader::Endian::big;
  std::map<std::uint64_t, std::uint64_t> relocated;  // slot -> target
  for (const loader::Relocation &r : image.relocations)
    if (r.kind == loader::RelocationKind::relative && r.target) relocated[r.address] = *r.target;
  auto in_code = [&](std::uint64_t a) {
    for (const loader::Block &b : image.blocks)
      if (b.perms.exec && b.initialized && a >= b.start && a - b.start < b.size) return true;
    return false;
  };
  std::vector<CodeSlot> out;
  std::vector<std::byte> buf;
  for (std::size_t bi = 0; bi < image.blocks.size(); ++bi) {
    const loader::Block &b = image.blocks[bi];
    if (b.perms.exec || !b.initialized || b.size < ptr) continue;
    buf.resize(static_cast<std::size_t>(b.size));
    image.memory.read(b.start, buf);
    for (std::uint64_t off = (ptr - b.start % ptr) % ptr; off + ptr <= b.size; off += ptr) {
      const std::uint64_t at = b.start + off;
      std::uint64_t v = 0;
      if (auto it = relocated.find(at); it != relocated.end()) {
        v = it->second;
      } else {
        for (unsigned i = 0; i < ptr; ++i) {
          const auto byte = std::to_integer<std::uint64_t>(buf[static_cast<std::size_t>(off + (big ? i : ptr - 1 - i))]);
          v = (v << 8) | byte;
        }
      }
      if (v != 0 && in_code(v)) out.push_back({at, v, bi});
    }
  }
  return out;
}

// Runs of slots at one constant stride (at most 64 bytes) in one block:
// one table, or one field of an array of structs. Runs share no slots, so
// adjacent tables stay apart. Each run is [first, last] index into slots.
std::vector<std::pair<std::size_t, std::size_t>> slot_runs(const std::vector<CodeSlot> &slots) {
  std::vector<std::pair<std::size_t, std::size_t>> runs;
  for (std::size_t i = 0; i + 1 < slots.size();) {
    if (slots[i + 1].block != slots[i].block) {
      ++i;
      continue;
    }
    const std::uint64_t stride = slots[i + 1].address - slots[i].address;
    std::size_t j = i + 1;
    while (j + 1 < slots.size() && slots[j + 1].address - slots[j].address == stride && slots[j + 1].block == slots[i].block)
      ++j;
    if (stride <= 64) runs.emplace_back(i, j);
    i = j + 1;
  }
  return runs;
}

}  // namespace

CallGraph CallGraphQuery::compute(facts::QueryContext &ctx, const ProgramKey &program) {
  auto info = ctx.get<an::Program>(program);
  auto funcs = ctx.get<an::Functions>(program);
  CallGraph g;
  g.nodes.reserve(funcs->functions.size());
  for (const an::FunctionInfo &f : funcs->functions) {
    CallNode n;
    n.entry = f.entry.offset;
    n.name = f.import.empty() ? f.name : f.import;
    n.import = f.import;
    if ((f.flags & an::kFunctionThunk) && f.import.empty()) n.thunk_target = f.thunk_target;
    n.no_return = (f.flags & an::kFunctionNoReturn) != 0;
    if (f.import.empty() && !f.body.empty()) {
      auto flow = ctx.get<an::Flow>(Location{program, f.flow_key()});
      for (const an::FlowInsn &insn : flow->insns) {
        const bool call = insn.kind == an::FlowKind::call || (insn.kind == an::FlowKind::jump && insn.tail_call);
        if (!call) continue;
        if (!f.body.contains(facts::Address{f.entry.space, insn.address})) continue;
        for (std::uint64_t t : insn.targets)
          if (t != n.entry || insn.kind == an::FlowKind::call) n.callees.push_back(info->code_address(t));
      }
      sort_unique(n.callees);
    }
    g.nodes.push_back(std::move(n));
  }
  // Functions only data points to (callbacks in tables of function
  // pointers, without unwind info) aren't discovered: take the targets of
  // a table of at least two code pointers that are neither a function's
  // entry nor inside one's body.
  {
    const auto img_ref = ctx.get<EffectiveImage>(program);
    if (img_ref->image) {
      std::vector<std::pair<std::uint64_t, std::uint64_t>> bodies;
      for (const an::FunctionInfo &f : funcs->functions)
        for (const facts::AddressRange &r : f.body.ranges()) bodies.emplace_back(r.first.offset, r.last.offset);
      std::sort(bodies.begin(), bodies.end());
      auto covered = [&](std::uint64_t a) {
        auto it = std::upper_bound(bodies.begin(), bodies.end(), std::pair{a, ~std::uint64_t{0}});
        for (int k = 0; it != bodies.begin() && k < 64; ++k) {
          --it;
          if (it->first <= a && a <= it->second) return true;
        }
        return false;
      };
      const unsigned align = info->language.starts_with("x86") ? 1 : 2;
      const std::vector<CodeSlot> slots = code_pointer_slots(*img_ref->image);
      std::set<std::uint64_t> known;
      for (const CallNode &n : g.nodes) known.insert(n.entry);
      for (const auto &[i, j] : slot_runs(slots))
        for (std::size_t k = i; k <= j; ++k) {
          const std::uint64_t t = slots[k].target;
          if (t % align != 0 || known.contains(t) || covered(t)) continue;
          known.insert(t);
          CallNode n;
          n.entry = t;
          n.name = an::default_name(*info, t);
          n.from_data = true;
          g.nodes.push_back(std::move(n));
        }
    }
  }
  std::sort(g.nodes.begin(), g.nodes.end(), [](const CallNode &a, const CallNode &b) { return a.entry < b.entry; });
  for (const CallNode &n : g.nodes)
    for (std::uint64_t c : n.callees)
      if (auto *callee = const_cast<CallNode *>(g.find(c))) callee->callers.push_back(n.entry);
  for (CallNode &n : g.nodes) sort_unique(n.callers);
  for (const an::ImportSlot &s : info->imports) g.slots.emplace_back(s.address, s.name);
  std::sort(g.slots.begin(), g.slots.end());
  return g;
}

// ---- order ----

std::uint32_t Order::rank_of(std::uint64_t entry) const {
  auto it = std::lower_bound(rank.begin(), rank.end(), entry, [](const auto &p, std::uint64_t a) { return p.first < a; });
  return it != rank.end() && it->first == entry ? it->second : UINT32_MAX;
}

void Order::encode(facts::Encoder &e) const {
  facts::encode(e, rank);
  e.varint(components);
}

Order Order::decode(facts::Decoder &d) {
  Order o;
  o.rank = facts::decode<std::vector<std::pair<std::uint64_t, std::uint32_t>>>(d);
  o.components = facts::decode<std::uint32_t>(d);
  return o;
}

Order OrderQuery::compute(facts::QueryContext &ctx, const ProgramKey &program) {
  auto cg = ctx.get<CallGraphQuery>(program);
  auto families = ctx.get<Families>(program);
  const std::size_t n = cg->nodes.size();
  auto index_of = [&](std::uint64_t entry) -> std::size_t {
    const CallNode *node = cg->find(entry);
    return node == nullptr ? n : static_cast<std::size_t>(node - cg->nodes.data());
  };
  // Edges: calls, and a ring through each family's members (one component).
  std::vector<std::vector<std::uint32_t>> out(n);
  for (std::size_t i = 0; i < n; ++i)
    for (std::uint64_t c : cg->nodes[i].callees)
      if (std::size_t j = index_of(c); j < n) out[i].push_back(static_cast<std::uint32_t>(j));
  for (const std::vector<std::uint64_t> &family : families->families)
    for (std::size_t k = 0; k < family.size(); ++k) {
      const std::size_t a = index_of(family[k]), b = index_of(family[(k + 1) % family.size()]);
      if (a < n && b < n && a != b) out[a].push_back(static_cast<std::uint32_t>(b));
    }
  for (auto &v : out) {
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
  }
  // Tarjan's algorithm without recursion; components come out callees
  // first, which is the rank.
  constexpr std::uint32_t kNone = UINT32_MAX;
  std::vector<std::uint32_t> index(n, kNone), low(n, 0), comp(n, kNone);
  std::vector<std::uint32_t> stack;
  std::vector<char> on_stack(n, 0);
  std::uint32_t next = 0, components = 0;
  struct Frame {
    std::uint32_t v;
    std::size_t edge;
  };
  std::vector<Frame> frames;
  for (std::uint32_t root = 0; root < n; ++root) {
    if (index[root] != kNone) continue;
    frames.push_back({root, 0});
    index[root] = low[root] = next++;
    stack.push_back(root);
    on_stack[root] = 1;
    while (!frames.empty()) {
      Frame &f = frames.back();
      if (f.edge < out[f.v].size()) {
        const std::uint32_t w = out[f.v][f.edge++];
        if (index[w] == kNone) {
          index[w] = low[w] = next++;
          stack.push_back(w);
          on_stack[w] = 1;
          frames.push_back({w, 0});
        } else if (on_stack[w]) {
          low[f.v] = std::min(low[f.v], index[w]);
        }
        continue;
      }
      const std::uint32_t v = f.v;
      frames.pop_back();
      if (!frames.empty()) low[frames.back().v] = std::min(low[frames.back().v], low[v]);
      if (low[v] == index[v]) {
        for (;;) {
          const std::uint32_t w = stack.back();
          stack.pop_back();
          on_stack[w] = 0;
          comp[w] = components;
          if (w == v) break;
        }
        ++components;
      }
    }
  }
  Order o;
  o.components = components;
  o.rank.reserve(n);
  for (std::size_t i = 0; i < n; ++i) o.rank.emplace_back(cg->nodes[i].entry, comp[i]);
  return o;
}

// ---- observe ----

namespace {

// The round of `callee`'s prototype `self`'s round-k observation locks
// (k >= 1): this round's when it ranks below, else the previous round's.
std::uint32_t lock_round(const Order &order, std::uint64_t self, std::uint64_t callee, std::uint32_t k) {
  return order.rank_of(callee) < order.rank_of(self) ? k : k - 1;
}

// Answers the decompiler's symbol lookups from the call graph, the
// signature database and earlier rounds, through the query context.
class QueryEnv : public SymbolEnv {
 public:
  QueryEnv(facts::QueryContext &ctx, const RoundKey &key, const ImageRef &img, const CallGraph &cg, const Order &order)
      : ctx_(ctx), key_(key), img_(img), cg_(cg), order_(order), org_(data_org(*img.image)),
        db_(SigDb::for_image(*img.image)) {}

  std::optional<FunctionSymbol> function(std::uint64_t entry) override {
    const CallNode *n = cg_.find(entry);
    if (n == nullptr) return std::nullopt;
    consulted.push_back(entry);
    FunctionSymbol f;
    f.name = n->name;
    f.no_return = n->no_return;
    if (!n->import.empty()) {
      if (img_.options.library) f.proto = db_.find(n->import, org_);
    } else if (entry != key_.at.address && key_.round > 0 && img_.options.interprocedural) {
      auto r = ctx_.get<Round>(RoundKey{{key_.at.program, entry}, lock_round(order_, key_.at.address, entry, key_.round)});
      if (r->known) f.proto = r->proto;
    }
    return f;
  }

  std::optional<FunctionSymbol> import_slot(std::uint64_t slot) override {
    const std::string *name = cg_.slot(slot);
    if (name == nullptr) return std::nullopt;
    FunctionSymbol f;
    f.name = *name;
    f.no_return = an::is_known_no_return(*name);
    if (img_.options.library) f.proto = db_.find(*name, org_);
    return f;
  }

  std::vector<std::uint64_t> consulted;

 private:
  facts::QueryContext &ctx_;
  const RoundKey &key_;
  const ImageRef &img_;
  const CallGraph &cg_;
  const Order &order_;
  DataOrg org_;
  const SigDb &db_;
};

const ImageRef &image_of(const facts::Ref<ImageRef> &img) {
  if (!img->image || !img->pool) throw std::runtime_error("infer: no image staged for this program");
  return *img;
}

}  // namespace

namespace {

// Where Observe::compute reports its decompilations while run() collects
// stats (diagnostics only: nothing a query returns depends on it).
struct Collector {
  std::mutex mu;
  std::map<std::uint32_t, RoundStats> rounds;
  void add(std::uint32_t round, std::uint64_t entry, double seconds) {
    std::lock_guard lock(mu);
    RoundStats &r = rounds[round];
    ++r.decompiled;
    r.decompile_seconds += seconds;
    if (seconds > r.slowest_seconds) {
      r.slowest_seconds = seconds;
      r.slowest = entry;
    }
  }
};
std::atomic<Collector *> g_collector{nullptr};

}  // namespace

// Functions of at least this many bytes of code decompile at most
// kLargeRuns at a time, give or take (scheduling only: results don't
// depend on it).
constexpr std::uint64_t kLargeBody = 8192;
constexpr int kLargeRuns = 2;

class LargeRun {
 public:
  explicit LargeRun(bool large) : large_(large) {
    if (!large_) return;
    // Bounded wait: a run holding a slot may itself wait (in a lookup) on
    // a query this thread computes; then this one goes ahead.
    std::unique_lock lock(mu());
    cv().wait_for(lock, std::chrono::seconds(5), [] { return running() < kLargeRuns; });
    ++running();
  }
  ~LargeRun() {
    if (!large_) return;
    {
      std::lock_guard lock(mu());
      --running();
    }
    cv().notify_one();
  }
  LargeRun(const LargeRun &) = delete;
  LargeRun &operator=(const LargeRun &) = delete;

 private:
  static std::mutex &mu() {
    static std::mutex m;
    return m;
  }
  static std::condition_variable &cv() {
    static std::condition_variable c;
    return c;
  }
  static int &running() {
    static int n = 0;
    return n;
  }
  bool large_;
};

facts::Ref<Observation> observation(facts::QueryContext &ctx, const RoundKey &key) {
  auto o = ctx.get<Observe>(key);
  if (o->same_as) return ctx.get<Observe>(RoundKey{key.at, *o->same_as});
  return o;
}

facts::Ref<Observation> observation(const facts::Snapshot &snapshot, const RoundKey &key) {
  auto o = snapshot.get<Observe>(key);
  if (o->same_as) return snapshot.get<Observe>(RoundKey{key.at, *o->same_as});
  return o;
}

Observation Observe::compute(facts::QueryContext &ctx, const RoundKey &key) {
  const auto img_ref = ctx.get<EffectiveImage>(key.at.program);
  const ImageRef &img = image_of(img_ref);
  auto cg = ctx.get<CallGraphQuery>(key.at.program);
  auto order = ctx.get<OrderQuery>(key.at.program);
  // Round 1 of a function that consulted none of the program's own
  // functions in round 0 locks nothing new: the same decompilation.
  if (key.round == 1) {
    auto prev = ctx.get<Observe>(RoundKey{key.at, 0});
    const bool leaf = std::none_of(prev->consulted.begin(), prev->consulted.end(), [&](std::uint64_t e) {
      const CallNode *n = cg->find(e);
      return n != nullptr && n->import.empty() && e != key.at.address;
    });
    if (leaf || prev->too_large) {
      Observation marker;
      marker.ok = prev->ok;
      marker.too_large = prev->too_large;
      marker.same_as = 0;
      return marker;
    }
  }
  // A later round whose lookups all answer as in the previous one
  // decompiles the same: reuse it. So does one too large to observe.
  if (key.round >= 2) {
    auto prev = observation(ctx, RoundKey{key.at, key.round - 1});
    bool same = true;
    for (std::uint64_t e : prev->too_large ? std::vector<std::uint64_t>{} : prev->consulted) {
      const CallNode *n = cg->find(e);
      if (n == nullptr || !n->import.empty() || e == key.at.address) continue;
      auto a = ctx.get<Round>(RoundKey{{key.at.program, e}, lock_round(*order, key.at.address, e, key.round)});
      auto b = ctx.get<Round>(RoundKey{{key.at.program, e}, lock_round(*order, key.at.address, e, key.round - 1)});
      if (a->known != b->known || a->proto != b->proto) {
        same = false;
        break;
      }
    }
    if (same) {
      // Name the round that holds the content, never another marker.
      auto raw = ctx.get<Observe>(RoundKey{key.at, key.round - 1});
      Observation marker;
      marker.ok = prev->ok;
      marker.too_large = prev->too_large;
      marker.same_as = raw->same_as ? *raw->same_as : key.round - 1;
      return marker;
    }
  }
  // The callees' prototypes this round locks, read before a decompiler is
  // leased: those ranked below are computed now (round k), and computing
  // them leases decompilers of their own, which waiting inside this
  // decompilation would hold on to (one per level of the call graph).
  if (key.round > 0 && img.options.interprocedural)
    if (const CallNode *self = cg->find(key.at.address)) {
      std::vector<RoundKey> callees;
      for (std::uint64_t e : self->callees) {
        const CallNode *n = cg->find(e);
        if (n == nullptr || !n->import.empty() || e == key.at.address) continue;
        callees.push_back({{key.at.program, e}, lock_round(*order, key.at.address, e, key.round)});
      }
      ctx.get_all<Round>(callees);
    }
  // A large function's decompilation holds tens to hundreds of megabytes:
  // only a few run at once, whatever the thread count.
  std::uint64_t body = 0;
  for (const facts::AddressRange &r : ctx.get<an::Function>(key.at)->body.ranges())
    body += r.last.offset - r.first.offset + 1;
  LargeRun large(body >= kLargeBody);
  QueryEnv env(ctx, key, img, *cg, *order);
  Observation o;
  {
    const auto started = std::chrono::steady_clock::now();
    DecompilerPool::Lease d = img.pool->acquire();
    RunOptions run;
    run.max_varnodes = img.options.max_varnodes;
    run.timeout_seconds = img.options.timeout_seconds;
    for (const facts::AddressRange &r : ctx.get<an::Function>(key.at)->body.ranges())
      run.body.emplace_back(r.first.offset, r.last.offset);
    o = d->run(key.at.address, env, run);
    if (Collector *c = g_collector.load())
      c->add(key.round, key.at.address, std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count());
  }
#ifdef __GLIBC__
  // What the decompilations free stays in malloc's arenas unless handed
  // back now and then (a few milliseconds every few hundred).
  static std::atomic<std::uint32_t> runs{0};
  if (runs.fetch_add(1, std::memory_order_relaxed) % 256 == 255) malloc_trim(0);
#endif
  // What the decompiler consulted, as the run reports it (the env was
  // also asked what the bundle predicted the decompiler would ask).
  sort_unique(o.consulted);
  return o;
}

// ---- rounds ----

Inferred Own::compute(facts::QueryContext &ctx, const RoundKey &key) {
  const auto img_ref = ctx.get<EffectiveImage>(key.at.program);
  const ImageRef &img = image_of(img_ref);
  auto cg = ctx.get<CallGraphQuery>(key.at.program);
  auto order = ctx.get<OrderQuery>(key.at.program);
  const CallNode *node = cg->find(key.at.address);
  Inferred out;
  if (node == nullptr) return out;
  const DataOrg org = data_org(*img.image);
  if (!node->import.empty()) {
    if (img.options.library)
      if (auto p = SigDb::for_image(*img.image).find(node->import, org)) {
        out.known = true;
        out.proto = *p;
      }
    return out;
  }
  auto self = observation(ctx, key);
  facts::Ref<Observation> self0 = key.round == 0 ? self : observation(ctx, RoundKey{key.at, 0});
  Evidence ev;
  ev.self = self->ok ? self.get() : nullptr;
  ev.self0 = self0->ok ? self0.get() : nullptr;
  ev.interprocedural = img.options.interprocedural;
  std::vector<facts::Ref<Observation>> keep;
  if (img.options.interprocedural) {
    for (std::uint64_t c : node->callers) {
      // Recursive calls count too: the function is never locked in its own
      // decompilation, so they are unlocked call sites in every round.
      if (c == key.at.address) {
        for (const CallSite &s : self0->calls)
          if (s.target == key.at.address) ev.unlocked.push_back(&s);
        continue;
      }
      auto o0 = ctx.get<Observe>(RoundKey{{key.at.program, c}, 0});
      for (const CallSite &s : o0->calls)
        if (s.target == key.at.address) ev.unlocked.push_back(&s);
      keep.push_back(o0);
      if (key.round > 0) {
        // A caller ranked above is decompiled with this function's round-k
        // prototype, so it is seen as of round k-1 (Order).
        const std::uint32_t seen = order->rank_of(c) > order->rank_of(key.at.address) ? key.round - 1 : key.round;
        auto ok = observation(ctx, RoundKey{{key.at.program, c}, seen});
        for (const CallSite &s : ok->calls)
          if (s.target == key.at.address) ev.current.push_back(&s);
        keep.push_back(ok);
      }
    }
  }
  // Prototypes of the functions whose addresses it passes or returns: the
  // library's for imports, the previous round's for the program's own.
  const SigDb &db = SigDb::for_image(*img.image);
  auto families = ctx.get<Families>(key.at.program);
  ev.table_proto = [&](std::uint64_t address) -> std::optional<Prototype> {
    const std::vector<std::uint64_t> *family = families->table_at(address);
    if (family == nullptr || key.round == 0) return std::nullopt;
    for (std::uint64_t m : *family) {
      if (m == key.at.address) continue;
      auto r = ctx.get<Round>(RoundKey{{key.at.program, m}, key.round - 1});
      if (r->known) return r->proto;
    }
    return std::nullopt;
  };
  ev.proto_of = [&](std::uint64_t a) -> std::optional<Prototype> {
    const CallNode *n = cg->find(a);
    if (n == nullptr || a == key.at.address) return std::nullopt;
    if (!n->import.empty()) return img.options.library ? db.find(n->import, org) : std::nullopt;
    if (key.round == 0) return std::nullopt;
    auto r = ctx.get<Round>(RoundKey{{key.at.program, a}, key.round - 1});
    if (!r->known) return std::nullopt;
    return r->proto;
  };
  out.known = ev.self0 != nullptr || ev.self != nullptr || !ev.unlocked.empty();
  out.proto = merge(abi_for(img.language_id, img.image->format == loader::Format::pe), ev, org);
  return out;
}

Inferred Round::compute(facts::QueryContext &ctx, const RoundKey &key) {
  const auto img_ref = ctx.get<EffectiveImage>(key.at.program);
  const ImageRef &img = image_of(img_ref);
  facts::Ref<Inferred> prior;
  if (key.round > 0) {
    prior = ctx.get<Round>(RoundKey{key.at, key.round - 1});
    if (prior->widened) return *prior;
  }
  Inferred out = *ctx.get<Own>(key);
  if (out.proto.source == "library" || !img.options.interprocedural) return out;

  // A callback's type, from the library it is passed to, for it or for
  // any function in its table; else its table's consensus.
  auto callbacks = ctx.get<Callbacks>(key.at.program);
  auto families = ctx.get<Families>(key.at.program);
  const std::vector<std::uint64_t> *family = families->find(key.at.address);
  auto callback = [&](std::uint64_t e) -> const Prototype * {
    auto it = std::lower_bound(callbacks->begin(), callbacks->end(), e,
                               [](const auto &p, std::uint64_t a) { return p.first < a; });
    return it != callbacks->end() && it->first == e ? &it->second : nullptr;
  };
  const Prototype *cb = callback(key.at.address);
  if (cb == nullptr && family != nullptr)
    for (std::uint64_t m : *family)
      if ((cb = callback(m)) != nullptr) break;
  if (cb != nullptr) {
    // The library's type, cut to the function's own parameters where the
    // trailing ones are optional (main).
    const std::size_t own_params = out.proto.params.size();
    const bool had_own = out.known;
    out.known = true;
    Prototype p = *cb;
    if (p.source == "callback-optional" && had_own && own_params < p.params.size()) p.params.resize(own_params);
    out.proto = std::move(p);
  } else if (family != nullptr) {
    std::vector<Prototype> members;
    for (std::uint64_t m : *family) {
      auto o = ctx.get<Own>(RoundKey{{key.at.program, m}, key.round});
      if (o->known) members.push_back(o->proto);
    }
    if (auto v = family_vote(out.proto, members)) {
      out.known = true;
      out.proto = std::move(*v);
    }
  }

  if (prior) {
    out.proto = join(prior->proto, out.proto);
    out.changes = prior->changes;
    if (out.known != prior->known || out.proto != prior->proto) {
      ++out.changes;
      if (out.changes > img.options.change_budget) {
        // Widen: keep the shape, forget the types that keep moving.
        out.widened = true;
        Prototype w = prior->proto;
        if (w.params.size() == out.proto.params.size()) {
          for (std::size_t i = 0; i < w.params.size(); ++i)
            if (!(w.params[i] == out.proto.params[i])) w.params[i] = widen(join(w.params[i], out.proto.params[i]));
        } else {
          w = out.proto;
          for (VType &t : w.params) t = widen(t);
        }
        if (!(w.ret == out.proto.ret)) w.ret = w.ret.is_void() || out.proto.ret.is_void() ? out.proto.ret : widen(w.ret);
        w.source = "widened";
        out.proto = std::move(w);
      }
    }
  }
  return out;
}

// ---- families and callbacks ----

const std::vector<std::uint64_t> *FamilyTable::find(std::uint64_t entry) const {
  auto it = std::lower_bound(index.begin(), index.end(), entry, [](const auto &p, std::uint64_t a) { return p.first < a; });
  return it != index.end() && it->first == entry ? &families[it->second] : nullptr;
}

const std::vector<std::uint64_t> *FamilyTable::table_at(std::uint64_t address) const {
  for (const Table &t : tables)
    if (address >= t.first && address <= t.last) return &families[t.family];
  return nullptr;
}

void FamilyTable::Table::encode(facts::Encoder &e) const {
  e.varint(first);
  e.varint(last - first);
  e.varint(family);
}

FamilyTable::Table FamilyTable::Table::decode(facts::Decoder &d) {
  Table t;
  t.first = d.varint();
  t.last = t.first + d.varint();
  t.family = facts::decode<std::uint32_t>(d);
  return t;
}

void FamilyTable::encode(facts::Encoder &e) const {
  facts::encode(e, families);
  facts::encode(e, index);
  facts::encode(e, tables);
}

FamilyTable FamilyTable::decode(facts::Decoder &d) {
  FamilyTable t;
  t.families = facts::decode<std::vector<std::vector<std::uint64_t>>>(d);
  t.index = facts::decode<std::vector<std::pair<std::uint64_t, std::uint32_t>>>(d);
  t.tables = facts::decode<std::vector<Table>>(d);
  return t;
}

FamilyTable Families::compute(facts::QueryContext &ctx, const ProgramKey &program) {
  const auto img_ref = ctx.get<EffectiveImage>(program);
  const ImageRef &img = image_of(img_ref);
  auto cg = ctx.get<CallGraphQuery>(program);
  auto is_function = [&](std::uint64_t a) {
    const CallNode *n = cg->find(a);
    return n != nullptr && n->import.empty();
  };
  // Code pointers in data that hold a function's entry.
  std::vector<CodeSlot> slots;
  for (const CodeSlot &c : code_pointer_slots(*img.image))
    if (is_function(c.target)) slots.push_back(c);
  std::map<std::uint64_t, std::uint64_t> parent;
  std::function<std::uint64_t(std::uint64_t)> root = [&](std::uint64_t a) {
    auto it = parent.find(a);
    if (it == parent.end() || it->second == a) return a;
    return it->second = root(it->second);
  };
  auto unite = [&](std::uint64_t a, std::uint64_t b) {
    parent.try_emplace(a, a);
    parent.try_emplace(b, b);
    parent[root(a)] = root(b);
  };
  std::vector<std::pair<std::pair<std::uint64_t, std::uint64_t>, std::uint64_t>> runs;  // (first, last), a member
  for (const auto &[i, j] : slot_runs(slots)) {
    for (std::size_t k = i + 1; k <= j; ++k) unite(slots[i].target, slots[k].target);
    runs.push_back({{slots[i].address, slots[j].address}, slots[i].target});
  }
  std::map<std::uint64_t, std::vector<std::uint64_t>> groups;
  for (const auto &[a, p] : parent) groups[root(a)].push_back(a);
  FamilyTable t;
  for (auto &[r, members] : groups) {
    if (members.size() < 2) continue;
    std::sort(members.begin(), members.end());
    for (std::uint64_t m : members) t.index.emplace_back(m, static_cast<std::uint32_t>(t.families.size()));
    t.families.push_back(std::move(members));
  }
  std::sort(t.index.begin(), t.index.end());
  for (const auto &[range, member] : runs)
    if (auto it = std::lower_bound(t.index.begin(), t.index.end(), member,
                                   [](const auto &p, std::uint64_t a) { return p.first < a; });
        it != t.index.end() && it->first == member)
      t.tables.push_back({range.first, range.second, it->second});
  std::sort(t.tables.begin(), t.tables.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
  return t;
}

Callbacks::Value Callbacks::compute(facts::QueryContext &ctx, const ProgramKey &program) {
  const auto img_ref = ctx.get<EffectiveImage>(program);
  const ImageRef &img = image_of(img_ref);
  auto cg = ctx.get<CallGraphQuery>(program);
  const SigDb &db = SigDb::for_image(*img.image);
  const DataOrg org = data_org(*img.image);
  std::map<std::uint64_t, Prototype> found;
  for (const CallNode &n : cg->nodes) {
    if (!n.import.empty()) continue;
    auto o = ctx.get<Observe>(RoundKey{{program, n.entry}, 0});
    for (const CallSite &c : o->calls) {
      if (!c.locked || c.target == 0) continue;
      std::string callee;
      if (const CallNode *t = cg->find(c.target); t != nullptr && !t->import.empty()) callee = t->import;
      else if (const std::string *slot = cg->slot(c.target)) callee = *slot;
      if (callee.empty()) continue;
      for (std::size_t i = 0; i < c.args.size(); ++i) {
        for (std::uint64_t v : c.args[i].constants) {
          const CallNode *f = cg->find(v);
          if (f == nullptr || !f->import.empty()) continue;
          if (auto p = db.callback(callee, i, org)) found.emplace(f->entry, std::move(*p));
        }
      }
    }
  }
  return {found.begin(), found.end()};
}

// ---- fixpoint ----

namespace {

// Whether the rounds so far (`changed`: round 0's count first, then each
// round's changes) reached the fixpoint: two rounds in a row changed
// nothing. One isn't enough: a function's callers ranked above it are
// seen one round late, so the round after a change can still move it.
bool converged_at(const std::vector<std::uint32_t> &changed) {
  const std::size_t k = changed.size() - 1;
  return k >= 2 && changed[k] == 0 && changed[k - 1] == 0;
}

std::vector<std::uint64_t> inferable(const CallGraph &cg) {
  std::vector<std::uint64_t> out;
  for (const CallNode &n : cg.nodes)
    if (n.import.empty()) out.push_back(n.entry);
  return out;
}

}  // namespace

FixpointResult Fixpoint::compute(facts::QueryContext &ctx, const ProgramKey &program) {
  const auto img_ref = ctx.get<EffectiveImage>(program);
  const ImageRef &img = image_of(img_ref);
  auto cg = ctx.get<CallGraphQuery>(program);
  const std::vector<std::uint64_t> entries = inferable(*cg);
  const DataOrg org = data_org(*img.image);
  FixpointResult r;
  std::vector<facts::Ref<Inferred>> cur(entries.size());
  std::uint32_t known = 0;
  for (std::size_t i = 0; i < entries.size(); ++i) {
    cur[i] = ctx.get<Round>(RoundKey{{program, entries[i]}, 0});
    known += cur[i]->known;
  }
  r.changed.push_back(known);
  const std::uint32_t max_rounds = img.options.interprocedural ? img.options.max_rounds : 0;
  for (std::uint32_t k = 1; k <= max_rounds; ++k) {
    std::uint32_t changed = 0;
    std::vector<facts::Ref<Inferred>> next(entries.size());
    for (std::size_t i = 0; i < entries.size(); ++i) {
      next[i] = ctx.get<Round>(RoundKey{{program, entries[i]}, k});
      if (!(*next[i] == *cur[i]) && (next[i]->known != cur[i]->known || next[i]->proto != cur[i]->proto)) ++changed;
    }
    cur = std::move(next);
    r.rounds = k;
    r.changed.push_back(changed);
    if (converged_at(r.changed)) {
      r.converged = true;
      break;
    }
  }
  if (max_rounds == 0) r.converged = true;
  for (std::size_t i = 0; i < entries.size(); ++i) {
    if (cur[i]->widened) ++r.widened;
    if (!cur[i]->known) continue;
    r.prototypes.emplace_back(entries[i], img.options.defaults ? finalize(cur[i]->proto, org, img.options.keep_return_width) : cur[i]->proto);
  }
  // Imports with a library prototype.
  for (const CallNode &n : cg->nodes) {
    if (n.import.empty() || !img.options.library) continue;
    if (auto p = SigDb::for_image(*img.image).find(n.import, org)) r.prototypes.emplace_back(n.entry, *p);
  }
  std::sort(r.prototypes.begin(), r.prototypes.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
  return r;
}

std::optional<Prototype> PrototypeQuery::compute(facts::QueryContext &ctx, const Location &at) {
  auto r = ctx.get<Fixpoint>(at.program);
  if (const Prototype *p = r->find(at.address)) return *p;
  return std::nullopt;
}

ImageRef EffectiveImage::compute(facts::QueryContext &ctx, const ProgramKey &program) {
  auto in = ctx.get<ImageInput>(program);
  if (!in->image) return *in;
  auto map = ctx.get<an::MemoryMap>(program);
  if (!map->edited) return *in;
  ImageRef r = *in;
  r.image = an::image_with_memory(*in->image, *map, [&](const an::RegionBytes &b) { return an::region_bytes(ctx, b); });
  r.pool = std::make_shared<DecompilerPool>(r.image, r.language_id);
  // The map, by its encoding's fingerprint: what it changes recomputes.
  const std::string encoded = facts::encode_to_string(*map);
  r.identity += "+map:" + facts::Fingerprint::of(encoded).hex();
  return r;
}

void register_queries(facts::Engine &engine) {
  engine.add_input<ImageInput>();
  engine.add_query<EffectiveImage>();
  engine.add_query<CallGraphQuery>();
  engine.add_query<Observe>();
  engine.add_query<Own>();
  engine.add_query<Families>();
  engine.add_query<Callbacks>();
  engine.add_query<OrderQuery>();
  engine.add_query<Round>();
  engine.add_query<Fixpoint>();
  engine.add_query<PrototypeQuery>();
}

void stage_image(facts::FactDb::Transaction &tx, const ProgramKey &program, std::shared_ptr<const loader::Image> image,
                 const std::string &language_id, const std::string &identity, const Options &options) {
  ImageRef r;
  r.identity = identity;
  r.language_id = language_id;
  r.options = options;
  r.pool = std::make_shared<DecompilerPool>(image, language_id);
  r.image = std::move(image);
  tx.set<ImageInput>(program, std::move(r));
}

std::optional<Prototype> prototype_for(const facts::Snapshot &snapshot, const Location &at) {
  return *snapshot.get<PrototypeQuery>(at);
}

FixpointResult run(const facts::Snapshot &snapshot, const ProgramKey &program, facts::ThreadPool *pool,
                   std::vector<RoundStats> *stats, const RunControl *control) {
  auto img = snapshot.get<EffectiveImage>(program);
  auto cg = snapshot.get<CallGraphQuery>(program);
  const std::vector<std::uint64_t> entries = inferable(*cg);
  const std::uint32_t max_rounds = img->options.interprocedural ? img->options.max_rounds : 0;
  Collector collector;
  if (stats) g_collector.store(&collector);
  struct Reset {
    bool on;
    ~Reset() {
      if (on) g_collector.store(nullptr);
    }
  } reset{stats != nullptr};
  std::vector<facts::Ref<Inferred>> prev;
  std::vector<std::uint32_t> counts;  // as FixpointResult::changed, round 0's aside
  // Each round in call-graph order, callees first, so that a function's
  // lower-ranked callees are mostly done (or being done on another thread)
  // when it comes up; results are in entry order.
  auto order = snapshot.get<OrderQuery>(program);
  std::vector<std::size_t> by_rank(entries.size());
  for (std::size_t i = 0; i < by_rank.size(); ++i) by_rank[i] = i;
  std::stable_sort(by_rank.begin(), by_rank.end(),
                   [&](std::size_t a, std::size_t b) { return order->rank_of(entries[a]) < order->rank_of(entries[b]); });
  for (std::uint32_t k = 0; k <= max_rounds; ++k) {
    const auto started = std::chrono::steady_clock::now();
    std::vector<RoundKey> keys;
    keys.reserve(entries.size());
    for (std::size_t i : by_rank) keys.push_back({{program, entries[i]}, k});
    if (control == nullptr || (!control->cancelled && !control->progress)) {
      snapshot.get_all<Observe>(keys, pool);
    } else {
      // One function at a time, checking for a stop before each (a round
      // of a large program takes minutes) and reporting as they finish.
      std::atomic<std::size_t> done{0};
      std::atomic<bool> stopped{false};
      auto one = [&](std::size_t i) {
        if (stopped.load(std::memory_order_relaxed)) return;
        if (control->cancelled && control->cancelled()) {
          stopped.store(true, std::memory_order_relaxed);
          return;
        }
        snapshot.get<Observe>(keys[i]);
        const std::size_t n = done.fetch_add(1, std::memory_order_relaxed) + 1;
        if (control->progress) control->progress(k, n, keys.size(), max_rounds);
      };
      if (pool) pool->parallel_for(keys.size(), one);
      else
        for (std::size_t i = 0; i < keys.size(); ++i) one(i);
      if (stopped.load()) throw Cancelled();
    }
    auto ranked = snapshot.get_all<Round>(keys, pool);
    std::vector<facts::Ref<Inferred>> cur(entries.size());
    for (std::size_t j = 0; j < by_rank.size(); ++j) cur[by_rank[j]] = std::move(ranked[j]);
    RoundStats rs;
    for (std::size_t i = 0; k > 0 && i < cur.size(); ++i)
      if (cur[i]->known != prev[i]->known || cur[i]->proto != prev[i]->proto) {
        ++rs.changed;
        if (rs.changed_entries.size() < 64) rs.changed_entries.push_back(entries[i]);
      }
    if (stats) {
      std::lock_guard lock(collector.mu);
      RoundStats &c = collector.rounds[k];
      rs.round = k;
      rs.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
      rs.decompiled = c.decompiled;
      rs.decompile_seconds = c.decompile_seconds;
      rs.slowest_seconds = c.slowest_seconds;
      rs.slowest = c.slowest;
      stats->push_back(std::move(rs));
    }
    counts.push_back(rs.changed);
    if (k > 0 && converged_at(counts)) break;
    prev = std::move(cur);
#ifdef __GLIBC__
    // A round's decompilations free hundreds of megabytes across the
    // threads' malloc arenas, which glibc otherwise keeps.
    malloc_trim(0);
#endif
  }
  return *snapshot.get<Fixpoint>(program);
}

}  // namespace revkit::infer
