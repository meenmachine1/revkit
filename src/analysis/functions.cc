// analysis.functions: the discovery fixpoint, no-return inference, bodies
// and names; analysis.function: one function of it.

#include "internal.h"
#include "revkit/analysis/memory.h"
#include "revkit/analysis/data.h"
#include "revkit/analysis/register_values.h"

#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace revkit::analysis {

// ---- codecs ----

void FunctionInfo::encode(facts::Encoder &e) const {
  facts::encode(e, entry);
  e.bytes(name);
  facts::encode(e, body);
  e.varint(flags);
  e.varint(seed);
  facts::encode(e, no_return);
  e.varint(thunk_target);
  e.bytes(import);
  facts::encode(e, reach);
}

FunctionInfo FunctionInfo::decode(facts::Decoder &d) {
  FunctionInfo f;
  f.entry = facts::decode<facts::Address>(d);
  f.name = std::string(d.bytes());
  f.body = facts::decode<facts::AddressSet>(d);
  f.flags = facts::decode<std::uint16_t>(d);
  f.seed = facts::decode<std::uint16_t>(d);
  f.no_return = facts::decode<NoReturnReason>(d);
  if (f.no_return > NoReturnReason::user) throw facts::DecodeError("bad no-return reason");
  f.thunk_target = d.varint();
  f.import = std::string(d.bytes());
  f.reach = facts::decode<facts::AddressSet>(d);
  return f;
}

void FunctionList::encode(facts::Encoder &e) const {
  facts::encode(e, functions);
  e.varint(code.size());
  std::uint64_t at = 0;
  for (const CodeUnit &c : code) {
    e.varint(c.address - at);
    e.varint(c.length);
    e.varint(std::uint64_t{c.delay} << 1 | (c.thumb ? 1 : 0));
    at = c.address;
  }
}

FunctionList FunctionList::decode(facts::Decoder &d) {
  FunctionList l;
  l.functions = facts::decode<std::vector<FunctionInfo>>(d);
  const std::size_t n = d.count();
  l.code.reserve(n);
  std::uint64_t at = 0;
  for (std::size_t i = 0; i < n; ++i) {
    CodeUnit c;
    c.address = at += d.varint();
    c.length = facts::decode<std::uint32_t>(d);
    const std::uint64_t delay = d.varint();
    if (delay >> 33) throw facts::DecodeError("bad delay");
    c.delay = static_cast<std::uint32_t>(delay >> 1);
    c.thumb = (delay & 1) != 0;
    l.code.push_back(c);
  }
  return l;
}

const FunctionInfo *FunctionList::find(std::uint64_t entry) const {
  auto it = std::lower_bound(functions.begin(), functions.end(), entry,
                             [](const FunctionInfo &f, std::uint64_t a) { return f.entry.offset < a; });
  return it != functions.end() && it->entry.offset == entry ? &*it : nullptr;
}

std::size_t Functions::weight(const FunctionList &v) {
  std::size_t w = sizeof(FunctionList) + v.code.capacity() * sizeof(CodeUnit);
  for (const FunctionInfo &f : v.functions)
    w += sizeof(FunctionInfo) + f.name.capacity() +
         (f.body.ranges().size() + f.reach.ranges().size()) * sizeof(facts::AddressRange);
  return w;
}

// ---- discovery ----

namespace {

constexpr int kMaxRounds = 256;

// What one function's walk found.
struct Walk {
  std::vector<std::uint64_t> insns;  // addresses reached, in visiting order
  std::vector<std::uint32_t> index;  // each one's index in the flow graph
  std::vector<std::uint64_t> calls;  // direct call targets reached
  // Targets of unconditional jumps that soon jump indirectly: maybe a tail
  // call to an import stub.
  std::vector<std::uint64_t> stubs;
  std::vector<std::uint64_t> exits;  // other entries it jumps or falls into
  std::vector<std::uint64_t> merges;  // those of them it falls into
  // Those it falls into, or branches or jumps to with code of its own on
  // both sides: what an entry inside it looks like.
  std::vector<std::uint64_t> inner;
  bool returns = false;              // reaches a return, or somewhere it can't see past
};

// Whether a few straight-line instructions from `a` end in a computed jump,
// as an import stub does.
bool leads_to_indirect_jump(const FlowGraph &g, std::uint64_t a) {
  for (int n = 0; n < 5; ++n) {
    const FlowInsn *i = g.at(a);
    if (!i) return false;
    if (i->kind == FlowKind::jump_indirect) return true;
    if (i->kind != FlowKind::fall || !i->falls_through) return false;
    a = i->fallthrough();
  }
  return false;
}

// Sorts `v` by `less` (a strict total order: equal elements must be
// identical, so the result doesn't depend on the schedule), in sorted
// chunks on the context's pool merged pairwise.
template <class T, class Less>
void parallel_sort(facts::QueryContext &ctx, std::vector<T> &v, Less less) {
  constexpr std::size_t kMinChunk = 1 << 15;
  std::size_t chunks = 1;
  while (chunks < 16 && v.size() / (chunks * 2) >= kMinChunk) chunks *= 2;
  if (chunks == 1 || !ctx.parallel()) {
    std::sort(v.begin(), v.end(), less);
    return;
  }
  auto bound = [&](std::size_t c) { return v.size() * c / chunks; };
  ctx.parallel_for(chunks, [&](std::size_t c) {
    std::sort(v.begin() + static_cast<std::ptrdiff_t>(bound(c)), v.begin() + static_cast<std::ptrdiff_t>(bound(c + 1)), less);
  });
  std::vector<T> tmp(v.size());
  for (std::size_t width = 1; width < chunks; width *= 2) {
    const std::size_t pairs = chunks / (2 * width);
    ctx.parallel_for(pairs, [&](std::size_t k) {
      const std::size_t lo = bound(2 * k * width), mid = bound((2 * k + 1) * width), hi = bound((2 * k + 2) * width);
      std::merge(v.begin() + static_cast<std::ptrdiff_t>(lo), v.begin() + static_cast<std::ptrdiff_t>(mid),
                 v.begin() + static_cast<std::ptrdiff_t>(mid), v.begin() + static_cast<std::ptrdiff_t>(hi),
                 tmp.begin() + static_cast<std::ptrdiff_t>(lo), less);
    });
    v.swap(tmp);
  }
}

// The fixpoint runs its per-function work (walks, bodies) on the engine's
// pool when it has one. Flows and thunk checks are read through the
// context only between those parallel steps, in batches (get_all decodes
// the missing ones in parallel), and recorded in a fixed order, so the
// memo is the same whatever the schedule.
class Discovery {
 public:
  Discovery(facts::QueryContext &ctx, const ProgramKey &program, const ProgramInfo &info)
      : ctx_(ctx), program_(program), info_(info), progress_(watched_discovery(program)) {}

  FunctionList run();

 private:
  // Reads the flows (and thunk checks) of entries not read yet.
  void prefetch(const std::vector<std::uint64_t> &entries, bool flows, bool thunks) {
    std::vector<Location> f, t;
    for (std::uint64_t e : entries) {
      if (flows && !flows_.contains(e)) f.push_back(Location{program_, e});
      if (thunks && !thunks_.contains(e)) t.push_back(Location{program_, e});
    }
    // A few are decoded here: each thread decoding in parallel needs a
    // SLEIGH engine of its own, which costs more than a few flows.
    if (f.size() >= kParallelReads) {
      auto got = ctx_.get_all<Flow>(f);
      for (std::size_t i = 0; i < f.size(); ++i) flows_.emplace(f[i].address, std::move(got[i]));
    } else {
      for (const Location &l : f) flows_.emplace(l.address, ctx_.get<Flow>(l));
    }
    if (t.size() >= kParallelReads) {
      auto got = ctx_.get_all<Thunk>(t);
      for (std::size_t i = 0; i < t.size(); ++i) thunks_.emplace(t[i].address, std::move(got[i]));
    } else {
      for (const Location &l : t) thunks_.emplace(l.address, ctx_.get<Thunk>(l));
    }
  }
  static constexpr std::size_t kParallelReads = 512;
  // Read through the context when missing: only outside parallel steps.
  const FlowGraph &flow(std::uint64_t e) {
    auto it = flows_.find(e);
    if (it == flows_.end()) it = flows_.emplace(e, ctx_.get<Flow>(Location{program_, e})).first;
    return *it->second;
  }
  const ThunkInfo &thunk(std::uint64_t e) {
    auto it = thunks_.find(e);
    if (it == thunks_.end()) it = thunks_.emplace(e, ctx_.get<Thunk>(Location{program_, e})).first;
    return *it->second;
  }
  // Already read: safe in parallel steps.
  const FlowGraph &flow_of(std::uint64_t e) const { return *flows_.at(e); }
  const ThunkInfo &thunk_of(std::uint64_t e) const { return *thunks_.at(e); }

  // Interworking: entries are keys (Thumb ones tagged); instructions and
  // targets of jumps are plain addresses.
  std::uint64_t real(std::uint64_t key) const { return info_.code_address(key); }
  // Whether someone asserted that no function starts at `key`'s address. A
  // removal is asserted at the plain address (what the listing shows); a
  // Thumb entry's key carries the Thumb bit, so compare addresses.
  // So is anything in bytes the listing's edits cleared or made data
  // (units.h), unless a code mark there says otherwise.
  bool not_a_function(std::uint64_t key) const {
    return not_functions_.contains(key) || not_functions_.contains(real(key)) ||
           (units_ && units_->is_blocked(real(key)) && !marked_.contains(key));
  }
  // The entry starting at code address `a`, if any.
  // (Code the search found that isn't a function doesn't count: flows go
  // on through it.)
  std::optional<std::uint64_t> entry_at(std::uint64_t a) const {
    if (entries_.contains(a) && !orphans_.contains(a)) return a;
    if (!info_.isa_context.empty() && entries_.contains(a | 1) && !orphans_.contains(a | 1)) return a | 1;
    return std::nullopt;
  }
  // Firmware search: function starts in code no walk reached (search.cc),
  // then code that isn't a function.
  std::set<std::uint64_t> search(bool pointers);
  std::set<std::uint64_t> search_code();
  // Only when discovery has found nothing at all: see detail::find_called.
  std::set<std::uint64_t> search_called();
  // What the walks know (as of the last infer_no_return): every
  // instruction reached, literal pools, code pointers.
  const detail::SearchInput &known_input();
  // Entries that code reached from the program's own entry points calls
  // (transitively), and the search's definite pattern matches.
  void find_proven();
  // Whether a candidate nothing proven vouches for (the search found it, or
  // only such code calls it) can be code: see credible().
  bool credible(std::uint64_t e, detail::ByteReader &bytes, detail::Decoder &decoder);

  // Names the entries a labelled start pattern matches (compiler helpers:
  // __gnu_thumb1_case_uqi), as Ghidra's start searches label what they find.
  void find_labels();

  void read_assertions();
  void disjoin_asserted_bodies();
  bool named_no_return(std::uint64_t e) const;
  Walk walk(std::uint64_t e) const;
  void infer_no_return();
  std::string name_of(std::uint64_t e, int depth = 0) const;

  // Reports how far it has got to an import's progress (null: nobody asks).
  void report(DiscoveryProgress::Stage stage) {
    if (!progress_) return;
    progress_->stage.store(stage, std::memory_order_relaxed);
    progress_->functions.store(entries_.size(), std::memory_order_relaxed);
  }

  facts::QueryContext &ctx_;
  const ProgramKey &program_;
  const ProgramInfo &info_;
  std::shared_ptr<DiscoveryProgress> progress_;
  // FUNCTION_BOUNDS assertions: entries, their bodies, and non-functions.
  std::set<std::uint64_t> asserted_;
  std::map<std::uint64_t, facts::AddressSet> asserted_bodies_;
  std::set<std::uint64_t> not_functions_;
  // The listing's edits (units.h): code marks (flow keys), and the bytes
  // they leave cleared or make data.
  facts::Ref<UnitCodeInfo> units_;
  std::set<std::uint64_t> marked_;
  std::unordered_map<std::uint64_t, facts::Ref<FlowGraph>> flows_;
  std::unordered_map<std::uint64_t, facts::Ref<ThunkInfo>> thunks_;
  std::set<std::uint64_t> entries_;
  std::set<std::uint64_t> discovered_;  // entries that are not seeds
  std::set<std::uint64_t> searched_;    // of those, found by the firmware search
  // Code the search found that isn't a function: walked for its calls and
  // shown as code, but never a function and never a body's boundary.
  std::set<std::uint64_t> orphans_;
  std::set<std::uint64_t> demoted_;  // search finds that turned out to be inside a function
  std::set<std::uint64_t> possible_;  // search finds only "possible" patterns made
  std::set<std::uint64_t> proven_;   // see find_proven()
  std::set<std::uint64_t> rejected_;  // unproven candidates that aren't credible
  // Discovery found nothing at all, from any seed or search: the
  // fallback (search_called, find_code's rules for 8- and 16-bit code).
  bool fallback_ = false;
  std::optional<detail::SearchInput> known_input_;
  std::set<std::uint64_t> undecodable_;  // entries whose flow decoded nothing
  std::unordered_set<std::uint64_t> no_return_;
  // What the user said (FactKind::NoReturn): true, it doesn't return; false,
  // it does, whatever the known names or the walks say.
  std::unordered_map<std::uint64_t, bool> user_no_return_;
  std::unordered_set<std::uint64_t> named_;  // no-return by name
  // Names from the language's labelled start patterns (find_labels).
  std::unordered_map<std::uint64_t, std::string> labels_;
  std::vector<std::uint64_t> order_;  // entries_ in order, as of the last infer_no_return
  std::vector<Walk> walks_;           // one per order_
};

bool Discovery::named_no_return(std::uint64_t e) const {
  if (const Seed *s = info_.seed_at(real(e)); s && s->named_by_symbol) return is_known_no_return(s->name, info_.macho);
  const ThunkInfo &t = thunk_of(e);
  return t.kind == ThunkKind::import && is_known_no_return(t.import, info_.macho);
}

// Everything reachable from `e` within its function: through fallthrough,
// branches and jump tables, not into other entries, and not past calls to
// no-return functions.
Walk Discovery::walk(std::uint64_t e) const {
  Walk w;
  const FlowGraph &g = flow_of(e);
  // Visited marks by instruction index (the graph is sorted by address),
  // with a set for the few addresses outside the graph: much cheaper than
  // hashing every address.
  static constexpr std::size_t kOutside = ~std::size_t{0};
  std::vector<std::uint8_t> seen(g.insns.size());
  std::unordered_set<std::uint64_t> seen_outside;
  auto index_of = [&](std::uint64_t a, std::size_t hint) {
    if (hint < g.insns.size() && g.insns[hint].address == a) return hint;
    auto it = std::lower_bound(g.insns.begin(), g.insns.end(), a,
                               [](const FlowInsn &i, std::uint64_t x) { return i.address < x; });
    return it != g.insns.end() && it->address == a ? static_cast<std::size_t>(it - g.insns.begin()) : kOutside;
  };
  struct Item {
    std::uint64_t address;
    std::size_t index;
  };
  const std::uint64_t start = real(e);
  const bool thumb = info_.thumb(e);
  std::vector<Item> stack{{start, index_of(start, 0)}};  // the entry isn't marked: a loop back to it walks it again
  enum class By : std::uint8_t { fall, branch, jump };
  struct Jumped {
    std::uint64_t entry, address;
    bool conditional;
  };
  std::vector<Jumped> jumped;  // entries reached by a branch or jump
  auto go = [&](std::uint64_t a, std::size_t hint, By by = By::jump) {
    const bool fall = by == By::fall;
    if (a != start)
      if (auto other = entry_at(a)) {
        w.exits.push_back(*other);
        if (fall) w.merges.push_back(*other);
        // A branch (conditional or not) to an entry is inside only between
        // the function's own instructions, or (conditional) right after
        // them, as a shrink-wrapped prologue an early exit skips to is:
        // elsewhere it is a tail call (ARM's beq other_function).
        if (fall) w.inner.push_back(*other);
        else jumped.push_back({*other, a, by == By::branch});
        return;
      }
    const std::size_t i = index_of(a, hint);
    const bool fresh = i == kOutside ? seen_outside.insert(a).second : !std::exchange(seen[i], std::uint8_t{1});
    if (fresh) stack.push_back({a, i});
  };
  while (!stack.empty()) {
    const auto [a, index] = stack.back();
    stack.pop_back();
    const FlowInsn *insn = index == kOutside ? nullptr : &g.insns[index];
    if (!insn) {
      // Flow stopped here: undecodable, not code, or overlapping. We can't
      // tell where this path goes, so it may return.
      w.returns = true;
      continue;
    }
    w.insns.push_back(a);
    w.index.push_back(static_cast<std::uint32_t>(index));
    bool fall = insn->falls_through;
    switch (insn->kind) {
      case FlowKind::ret: w.returns = true; break;
      case FlowKind::call: {
        bool callee_returns = insn->targets.empty();
        for (std::uint64_t t : insn->targets) {
          w.calls.push_back(t);
          // (The user's fallthrough override says where it goes on.)
          if (no_return_.contains(t) && !insn->fall_override) fall = false;
          else callee_returns = true;
        }
        if (insn->tail_call && callee_returns) w.returns = true;  // returns with its callee
        break;
      }
      case FlowKind::call_indirect:
        if (insn->tail_call) w.returns = true;
        break;
      case FlowKind::jump_indirect:
        // A tail call through a pointer, or an unrecovered table, may return.
        if (insn->targets.empty() && !insn->no_return) w.returns = true;
        for (std::uint64_t t : insn->targets) go(t, kOutside);
        break;
      case FlowKind::jump:
        for (std::uint64_t t : insn->targets) {
          if (leads_to_indirect_jump(g, t)) w.stubs.push_back(info_.code_key(t, thumb));
          go(t, kOutside);
        }
        break;
      case FlowKind::branch:
        for (std::uint64_t t : insn->targets) go(t, kOutside, By::branch);
        break;
      case FlowKind::fall: break;
    }
    if (fall) {
      if (insn->fall_override) go(insn->fall_to, kOutside, By::fall);
      else go(a + insn->length, index + 1, By::fall);
    }
  }
  // A switch through a helper calls the helper.
  for (const auto &[from, helper] : g.case_calls) {
    const std::size_t i = index_of(from, kOutside);
    if (i != kOutside && (seen[i] || from == start)) w.calls.push_back(helper);
  }
  // User call references from the function's instructions (user_refs.h).
  for (const auto &[from, callee] : g.ref_calls) {
    const std::size_t i = index_of(from, kOutside);
    if (i != kOutside && (seen[i] || from == start)) w.calls.push_back(callee);
  }
  if (g.truncated) w.returns = true;
  if (!jumped.empty()) {
    // A branch or jump to an entry between this function's own instructions.
    const auto [lowest, highest] = std::minmax_element(w.insns.begin(), w.insns.end());
    constexpr std::uint64_t kAdjacent = 16;
    for (const auto &[entry, a, conditional] : jumped)
      if (start < a && ((*lowest < a && a < *highest) || (conditional && a > *highest && a - *highest <= kAdjacent)))
        w.inner.push_back(entry);
  }
  return w;
}

// The least set of no-return functions: start from the named ones, and add
// any function that can't reach a return (or a returning function it jumps
// into) once flow stops after calls to the set, until nothing changes.
// The operator is monotone, so the order entries are added in doesn't
// change the result.
void Discovery::infer_no_return() {
  known_input_.reset();
  order_.assign(entries_.begin(), entries_.end());
  prefetch(order_, true, true);
  named_.clear();
  for (std::uint64_t e : order_)
    if (named_no_return(e)) named_.insert(e);
  no_return_ = named_;
  // The user's word over the names and the walks.
  for (const auto &[e, nr] : user_no_return_) {
    if (nr) no_return_.insert(e);
    else no_return_.erase(e);
  }
  walks_.assign(order_.size(), Walk());
  ctx_.parallel_for(order_.size(), [&](std::size_t i) { walks_[i] = walk(order_[i]); });
  for (;;) {
    std::unordered_set<std::uint64_t> added;
    for (std::size_t i = 0; i < order_.size(); ++i) {
      const std::uint64_t e = order_[i];
      if (no_return_.contains(e)) continue;
      if (auto u = user_no_return_.find(e); u != user_no_return_.end() && !u->second) continue;  // it returns
      const Walk &w = walks_[i];
      bool returns = w.returns;
      for (std::uint64_t x : w.exits) returns = returns || !no_return_.contains(x);
      if (!returns) {
        no_return_.insert(e);
        added.insert(e);
      }
    }
    if (added.empty()) break;
    // A walk reads the no-return set only at the calls it reaches, so only
    // walks that reached a call to a function just added can change.
    std::vector<std::size_t> redo;
    for (std::size_t i = 0; i < order_.size(); ++i) {
      const Walk &w = walks_[i];
      if (std::any_of(w.calls.begin(), w.calls.end(), [&](std::uint64_t t) { return added.contains(t); }))
        redo.push_back(i);
    }
    ctx_.parallel_for(redo.size(), [&](std::size_t k) { walks_[redo[k]] = walk(order_[redo[k]]); });
  }
}

std::string Discovery::name_of(std::uint64_t e, int depth) const {
  // A symbol, then a name the loader gives (entry, _INIT_0), then the
  // thunk's target, then the default.
  const Seed *s = info_.seed_at(real(e));
  if (s && !s->name.empty()) return s->name;
  if (auto l = labels_.find(e); l != labels_.end()) return l->second;
  const ThunkInfo &t = thunk_of(e);
  if (t.kind == ThunkKind::import) return t.import;
  if (t.kind == ThunkKind::direct && depth < 8 && entries_.contains(t.target)) {
    // Ghidra: a thunk shows its target's name; "thunk_" marks a thunk of a
    // function that has only a default name and isn't a thunk itself.
    std::string target = name_of(t.target, depth + 1);
    bool target_default = target == default_name(info_, real(t.target));
    return target_default && thunk_of(t.target).kind == ThunkKind::none ? "thunk_" + target : target;
  }
  return default_name(info_, real(e));
}

const detail::SearchInput &Discovery::known_input() {
  if (known_input_) return *known_input_;
  detail::SearchInput in;
  std::size_t total = 0;
  for (const Walk &w : walks_) total += w.insns.size();
  in.code.reserve(total);
  for (std::size_t i = 0; i < order_.size(); ++i) {
    const Walk &w = walks_[i];
    const FlowGraph &g = flow_of(order_[i]);
    const bool thumb = info_.thumb(order_[i]);
    for (std::size_t k = 0; k < w.insns.size(); ++k) in.code.push_back({w.insns[k], g.insns[w.index[k]].length, thumb});
    in.data.insert(in.data.end(), g.literals.begin(), g.literals.end());
    in.pointers.insert(in.pointers.end(), g.code_pointers.begin(), g.code_pointers.end());
  }
  // One per address: the first walk's (by entry), as bodies take it.
  std::stable_sort(in.code.begin(), in.code.end(),
                   [](const detail::SearchInput::Insn &x, const detail::SearchInput::Insn &y) { return x.address < y.address; });
  in.code.erase(std::unique(in.code.begin(), in.code.end(),
                            [](const detail::SearchInput::Insn &x, const detail::SearchInput::Insn &y) {
                              return x.address == y.address;
                            }),
                in.code.end());
  std::sort(in.pointers.begin(), in.pointers.end());
  in.pointers.erase(std::unique(in.pointers.begin(), in.pointers.end()), in.pointers.end());
  known_input_ = std::move(in);
  return *known_input_;
}

std::set<std::uint64_t> Discovery::search(bool pointers) {
  const detail::SearchInput &in = known_input();
  detail::ByteReader bytes(ctx_, info_);
  detail::Decoder decoder(info_);
  std::set<std::uint64_t> found;
  for (const auto &[key, possible] : detail::search_starts(info_, in, bytes, decoder, pointers)) {
    if (entry_at(real(key))) continue;
    found.insert(key);
    if (possible) possible_.insert(key);
  }
  return found;
}

std::set<std::uint64_t> Discovery::search_code() {
  const detail::SearchInput &in = known_input();
  std::set<std::uint64_t> functions;
  for (std::uint64_t e : order_)
    if (!orphans_.contains(e)) functions.insert(e);
  detail::ByteReader bytes(ctx_, info_);
  detail::Decoder decoder(info_);
  std::set<std::uint64_t> found = detail::find_code(info_, in, functions, bytes, decoder, fallback_);
  for (auto it = found.begin(); it != found.end();)
    it = entries_.contains(*it) || entry_at(real(*it)) ? found.erase(it) : std::next(it);
  return found;
}

std::set<std::uint64_t> Discovery::search_called() {
  const detail::SearchInput &in = known_input();
  detail::ByteReader bytes(ctx_, info_);
  detail::Decoder decoder(info_);
  std::set<std::uint64_t> found = detail::find_called(info_, in, bytes, decoder);
  for (auto it = found.begin(); it != found.end();)
    it = entries_.contains(*it) || entry_at(real(*it)) ? found.erase(it) : std::next(it);
  return found;
}

void Discovery::find_proven() {
  proven_.clear();
  std::vector<std::uint64_t> work;
  auto add = [&](std::uint64_t e) {
    if (entries_.contains(e) && !orphans_.contains(e) && proven_.insert(e).second) work.push_back(e);
  };
  for (const Seed &s : info_.seeds) {
    add(s.address);
    if (!info_.isa_context.empty()) add(s.address | 1);
  }
  for (std::uint64_t e : asserted_) add(e);
  for (std::uint64_t e : searched_)
    if (!possible_.contains(e)) add(e);
  std::unordered_map<std::uint64_t, std::size_t> index;
  for (std::size_t i = 0; i < order_.size(); ++i) index.emplace(order_[i], i);
  while (!work.empty()) {
    const std::uint64_t e = work.back();
    work.pop_back();
    auto it = index.find(e);
    if (it == index.end()) continue;
    for (std::uint64_t t : walks_[it->second].calls) add(t);
    if (const ThunkInfo &t = thunk_of(e); t.kind == ThunkKind::direct) add(t.target);
  }
}

// A candidate that nothing proven vouches for must be code by its own
// bytes. Not credible: one that starts in text, in bytes as random as
// compressed data or in fill; whose first instructions (to the first
// transfer of control) include a zeroed word or something that doesn't
// decode; that runs through text; or that returns from a stack frame it
// didn't make. Nothing else here judges its control flow: real functions
// run into data after calls that never return, and through tables this
// analysis didn't recognise.
bool Discovery::credible(std::uint64_t e, detail::ByteReader &bytes, detail::Decoder &decoder) {
  const FlowGraph &g = flow(e);
  const std::uint64_t start = real(e);
  std::uint64_t at = start;
  auto no = [&](const char *why) {
    (void)why;
    return false;
  };
  if (g.insns.empty()) return no("nothing decodes");
  if (detail::starts_in_text(bytes, start)) return no("text");
  if (detail::high_entropy(bytes, start)) return no("random bytes");
  constexpr std::size_t kPrefix = 32;
  const bool tagged = start != e;
  std::vector<Range> body;
  for (std::size_t n = 0; n < kPrefix; ++n) {
    const FlowInsn *insn = g.at(at);
    if (!insn) return no("reaches what doesn't decode");
    {
      auto raw = bytes.read(at, insn->length);
      if (raw.size() == insn->length && std::all_of(raw.begin(), raw.end(), [](std::byte b) { return b == std::byte{0}; })) {
        auto decoded = decoder.decode(at, bytes, tagged);
        if (!decoded || detail::zero_instruction(*decoded, bytes)) return no("a zeroed word");
      }
    }
    if (insn->kind != FlowKind::fall || !insn->falls_through) break;
    at = insn->fallthrough();
  }
  // Everything it reaches without leaving through a call or another entry.
  at = start;
  for (const FlowInsn &i : g.insns) {
    if (!body.empty() && body.back().last + 1 == i.address) body.back().last = i.address + i.length - 1;
    else body.push_back({i.address, i.address + i.length - 1});
  }
  for (const Range &r : body)
    if (r.contains(start) && detail::text_bytes(bytes, r.first, r.last).longest >= detail::kTextRun) return no("runs through text");
  // Not the rest of a function whose start made the frame it returns from
  // (a pointer or a jump into the middle of one).
  if (detail::pops_callers_frame(ctx_, program_, info_, e, bytes, decoder,
                                 [&](std::uint64_t callee) { return no_return_.contains(callee); }))
    return no("returns from a frame it didn't make");
  return true;
}

void Discovery::find_labels() {
  const std::vector<LabelPattern> &patterns = label_patterns(info_.language, info_.compiler);
  if (patterns.empty()) return;
  detail::ByteReader bytes(ctx_, info_);
  for (std::uint64_t e : entries_) {
    const std::uint64_t start = real(e);
    if (const Seed *s = info_.seed_at(start); s && !s->name.empty()) continue;
    const bool thumb = info_.thumb(e);
    for (const LabelPattern &l : patterns) {
      const StartPattern &p = l.pattern;
      if (p.pre > start || start % p.align != 0) continue;
      if (!info_.isa_context.empty() && p.isa >= 0 && (p.isa != 0) != thumb) continue;
      const std::size_t n = p.value.size();
      auto b = bytes.read(start - p.pre, n);
      if (b.size() < n) continue;
      bool match = true;
      for (std::size_t i = 0; i < n && match; ++i) match = (std::to_integer<std::uint8_t>(b[i]) & p.mask[i]) == p.value[i];
      if (!match) continue;
      labels_.emplace(e, l.label);
      break;
    }
  }
}

void Discovery::read_assertions() {
  const facts::SpaceId space = info_.space;
  units_ = ctx_.get<UnitCode>(program_);
  // A code mark is an entry: a function when it says so, else code that
  // isn't one (an orphan: walked and shown, a function once called).
  for (const UnitCodeInfo::Entry &e : units_->entries) {
    marked_.insert(e.key);
    if (e.function) asserted_.insert(e.key);
    else orphans_.insert(e.key);
  }
  for (const facts::FactKey &k : facts::asserted_keys(ctx_, facts::FactKind::FunctionBounds, {space, 0},
                                                      {space, ~std::uint64_t{0}})) {
    if (!k.sub.empty()) continue;
    auto v = ctx_.get<facts::AssertedFact>(k);
    const std::uint64_t a = k.addr.offset;
    if (const auto *i = std::get_if<std::int64_t>(&*v); i && *i == kNotAFunction) {
      not_functions_.insert(a);
    } else if (const auto *body = std::get_if<facts::AddressSet>(&*v)) {
      if (units_->is_blocked(a)) continue;  // cleared since, or data
      asserted_.insert(a);
      orphans_.erase(a);
      if (!body->empty()) asserted_bodies_.emplace(a, *body);
    }
  }
  disjoin_asserted_bodies();
  for (const facts::FactKey &k : facts::asserted_keys(ctx_, facts::FactKind::NoReturn, {space, 0}, {space, ~std::uint64_t{0}})) {
    if (!k.sub.empty()) continue;
    auto v = ctx_.get<facts::AssertedFact>(k);
    if (const auto *i = std::get_if<std::int64_t>(&*v)) {
      // Keyed at the entry; a Thumb function's flow key is tagged.
      user_no_return_[k.addr.offset] = *i != 0;
      if (!info_.isa_context.empty()) user_no_return_[info_.code_key(k.addr.offset, true)] = *i != 0;
    }
  }
}

// Asserted bodies of different entries can overlap: two people (or
// daemons) set bounds concurrently (docs/collab.md, "Structural edits").
// Each contested address goes to the claiming entry closest at or before
// it, else the lowest claiming entry, as discovery assigns shared code; so
// bodies never overlap, and the result depends only on the effective
// values, never on which edit arrived first. An entry left with nothing
// falls back to the body discovery finds for it.
void Discovery::disjoin_asserted_bodies() {
  struct Piece {
    std::uint64_t first, last, entry;
  };
  std::vector<Piece> pieces;
  for (const auto &[e, body] : asserted_bodies_)
    for (const facts::AddressRange &r : body.ranges()) pieces.push_back({r.first.offset, r.last.offset, e});
  if (pieces.size() < 2) return;
  std::sort(pieces.begin(), pieces.end(), [](const Piece &x, const Piece &y) { return x.first < y.first; });
  auto resolve = [&](std::size_t lo, std::size_t hi) {  // a cluster of overlapping pieces
    std::vector<std::uint64_t> cuts;
    for (std::size_t i = lo; i < hi; ++i) {
      cuts.push_back(pieces[i].first);
      if (pieces[i].last != ~std::uint64_t{0}) cuts.push_back(pieces[i].last + 1);
      for (std::size_t j = lo; j < hi; ++j)
        if (pieces[j].entry > pieces[i].first && pieces[j].entry <= pieces[i].last) cuts.push_back(pieces[j].entry);
    }
    std::sort(cuts.begin(), cuts.end());
    cuts.erase(std::unique(cuts.begin(), cuts.end()), cuts.end());
    for (std::size_t c = 0; c < cuts.size(); ++c) {
      const std::uint64_t first = cuts[c];
      std::vector<std::uint64_t> claimants;
      std::uint64_t last = 0;
      for (std::size_t i = lo; i < hi; ++i)
        if (pieces[i].first <= first && first <= pieces[i].last) {
          claimants.push_back(pieces[i].entry);
          last = pieces[i].last;
        }
      if (claimants.size() < 2) continue;
      last = c + 1 < cuts.size() ? cuts[c + 1] - 1 : last;
      std::sort(claimants.begin(), claimants.end());
      auto at_or_before = std::upper_bound(claimants.begin(), claimants.end(), first);
      const std::uint64_t owner = at_or_before == claimants.begin() ? claimants.front() : *std::prev(at_or_before);
      for (std::uint64_t e : claimants)
        if (e != owner) asserted_bodies_[e].subtract(facts::AddressRange{{info_.space, first}, {info_.space, last}});
    }
  };
  std::size_t start = 0;
  std::uint64_t reach = pieces[0].last;
  for (std::size_t i = 1; i <= pieces.size(); ++i) {
    if (i < pieces.size() && pieces[i].first <= reach) {
      reach = std::max(reach, pieces[i].last);
      continue;
    }
    if (i - start > 1) resolve(start, i);
    if (i < pieces.size()) {
      start = i;
      reach = pieces[i].last;
    }
  }
  std::erase_if(asserted_bodies_, [](const auto &e) { return e.second.empty(); });
}

FunctionList Discovery::run() {
  read_assertions();
  for (const Seed &s : info_.seeds)
    if (!not_a_function(s.address)) entries_.insert(s.address);
  entries_.insert(asserted_.begin(), asserted_.end());
  entries_.insert(marked_.begin(), marked_.end());
  std::vector<std::uint64_t> fresh(entries_.begin(), entries_.end());
  for (int round = 0; round < kMaxRounds; ++round) {
    report(DiscoveryProgress::Stage::walking);
    if (progress_) progress_->rounds.store(round + 1, std::memory_order_relaxed);
    // An entry that doesn't decode isn't a function, unless asserted.
    prefetch(fresh, true, false);
    for (std::uint64_t e : fresh)
      if (flow(e).insns.empty() && !asserted_.contains(e)) {
        entries_.erase(e);
        undecodable_.insert(e);
      }
    infer_no_return();
    // A start only a "possible" pattern (or a pointer) found, that another
    // function's code falls or branches into and nothing calls, was part
    // of that function all along (Ghidra creates a possible start only
    // where no flow claims it).
    if (!possible_.empty()) {
      std::set<std::uint64_t> flowed, called;
      for (std::size_t i = 0; i < order_.size(); ++i) {
        const Walk &w = walks_[i];
        if (!orphans_.contains(order_[i]))
          for (std::uint64_t x : info_.search ? w.inner : w.merges)
            if (possible_.contains(x) && x != order_[i]) flowed.insert(x);
        for (std::uint64_t t : w.calls)
          if (possible_.contains(t)) called.insert(t);
      }
      std::vector<std::uint64_t> drop;
      for (std::uint64_t x : flowed)
        if (!called.contains(x) && !asserted_.contains(x) && !marked_.contains(x) && !info_.seed_at(real(x))) drop.push_back(x);
      if (!drop.empty()) {
        for (std::uint64_t x : drop) {
          entries_.erase(x);
          searched_.erase(x);
          possible_.erase(x);
          discovered_.erase(x);
          demoted_.insert(x);
        }
        fresh.clear();
        continue;  // walk again without them
      }
    }
    // What the search found where known code loads a constant (a literal
    // pool word that happened to decode, before the code that loads it
    // was found) is data, not code; and so is what it found inside an
    // instruction of code the search didn't find (a constant read as a
    // Thumb pointer into ARM code).
    if (info_.search && (!searched_.empty() || !orphans_.empty())) {
      std::vector<Range> pools;
      std::vector<std::pair<std::uint64_t, std::uint32_t>> trusted;  // instructions of non-search walks
      for (std::size_t i = 0; i < order_.size(); ++i) {
        const std::uint64_t e = order_[i];
        const FlowGraph &g = flow_of(e);
        pools.insert(pools.end(), g.literals.begin(), g.literals.end());
        if (searched_.contains(e) || orphans_.contains(e)) continue;
        const Walk &w = walks_[i];
        for (std::size_t k = 0; k < w.insns.size(); ++k) trusted.emplace_back(w.insns[k], g.insns[w.index[k]].length);
      }
      std::sort(trusted.begin(), trusted.end());
      auto offcut = [&](std::uint64_t a) {
        auto it = std::upper_bound(trusted.begin(), trusted.end(), std::make_pair(a, ~std::uint32_t{0}));
        if (it == trusted.begin()) return false;
        --it;
        return it->first < a && a - it->first < it->second;
      };
      const detail::Ranges literal(std::move(pools));
      std::vector<std::uint64_t> drop;
      for (const std::set<std::uint64_t> *from : {&searched_, &orphans_})
        for (std::uint64_t x : *from)
          if ((literal.contains(real(x)) || offcut(real(x))) && !asserted_.contains(x) && !marked_.contains(x) &&
              !info_.seed_at(real(x)))
            drop.push_back(x);
      if (!drop.empty()) {
        for (std::uint64_t x : drop) {
          entries_.erase(x);
          searched_.erase(x);
          possible_.erase(x);
          orphans_.erase(x);
          discovered_.erase(x);
          demoted_.insert(x);
        }
        fresh.clear();
        continue;  // walk again without them
      }
    }
    std::set<std::uint64_t> found;
    std::set<std::uint64_t> stubs;  // import stubs reached by a jump (a tail call), if they are stubs
    std::set<std::uint64_t> promoted;  // code the search found that something calls: a function after all
    // On a raw image, what only unproven code calls must be credible itself.
    std::set<std::uint64_t> vouched;  // found by proven code
    if (info_.search) find_proven();
    for (std::size_t i = 0; i < order_.size(); ++i) {
      const Walk &w = walks_[i];
      if (info_.search && proven_.contains(order_[i])) {
        for (std::uint64_t t : w.calls)
          if (!entries_.contains(t)) vouched.insert(t);
        if (const ThunkInfo &t = thunk_of(order_[i]); t.kind == ThunkKind::direct) vouched.insert(t.target);
      }
      for (std::uint64_t t : w.calls) {
        if (!entries_.contains(t) && info_.is_code(real(t))) found.insert(t);
        else if (orphans_.contains(t) && t != order_[i]) promoted.insert(t);
      }
      for (std::uint64_t t : w.stubs)
        if (!entries_.contains(t) && info_.is_code(real(t))) stubs.insert(t);
      const ThunkInfo &t = thunk_of(order_[i]);
      if (t.kind == ThunkKind::direct && !entries_.contains(t.target)) found.insert(t.target);
    }
    {
      std::vector<std::uint64_t> check;
      for (std::uint64_t t : stubs)
        if (!found.contains(t)) check.push_back(t);
      prefetch(check, false, true);
      for (std::uint64_t t : check)
        if (thunk(t).kind == ThunkKind::import) found.insert(t);
    }
    if (!promoted.empty()) {
      for (std::uint64_t t : promoted) orphans_.erase(t);
      fresh.clear();
      continue;  // walk again with them as functions (boundaries)
    }
    std::erase_if(found, [&](std::uint64_t k) { return not_a_function(k); });
    // (A target that didn't decode is found again by every round.)
    for (std::uint64_t a : undecodable_) found.erase(a);
    if (!found.empty()) {
      // A target inside an instruction some function already has is data
      // or a misdecode, not a function start (Ghidra refuses those too):
      // the closest decoded address at or before it, with the length the
      // first walk (by entry) that reached it decoded there.
      struct Decoded {
        std::uint64_t address;
        std::uint32_t walk;
        std::uint32_t length;
      };
      std::vector<std::size_t> offset(walks_.size() + 1, 0);
      for (std::size_t i = 0; i < walks_.size(); ++i) offset[i + 1] = offset[i] + walks_[i].insns.size();
      std::vector<Decoded> decoded(offset.back());
      ctx_.parallel_for(walks_.size(), [&](std::size_t i) {
        const Walk &w = walks_[i];
        const FlowGraph &g = flow_of(order_[i]);
        for (std::size_t k = 0; k < w.insns.size(); ++k)
          decoded[offset[i] + k] = {w.insns[k], static_cast<std::uint32_t>(i), g.insns[w.index[k]].length};
      });
      parallel_sort(ctx_, decoded, [](const Decoded &x, const Decoded &y) {
        return x.address != y.address ? x.address < y.address : x.walk < y.walk;
      });
      for (auto it = found.begin(); it != found.end();) {
        const std::uint64_t target = real(*it);
        auto d = std::upper_bound(decoded.begin(), decoded.end(), target,
                                  [](std::uint64_t x, const Decoded &p) { return x < p.address; });
        bool offcut = false;
        if (d != decoded.begin()) {
          const std::uint64_t at = std::prev(d)->address;
          // The first walk's decode at that address.
          auto first = std::lower_bound(decoded.begin(), d, at, [](const Decoded &p, std::uint64_t x) { return p.address < x; });
          offcut = at != target && target - at < first->length;
        }
        // One instruction set per address: an entry there already wins.
        if (!offcut && entry_at(target)) offcut = true;
        it = offcut ? found.erase(it) : std::next(it);
      }
    }
    // Checks candidates nothing proven vouches for; what isn't credible is
    // dropped (and not asked about again).
    auto keep_credible = [&](std::set<std::uint64_t> &candidates, const std::set<std::uint64_t> &trusted) {
      std::vector<std::uint64_t> check;
      for (auto it = candidates.begin(); it != candidates.end();) {
        if (trusted.contains(*it) || asserted_.contains(*it)) {
          ++it;
        } else if (rejected_.contains(*it)) {
          it = candidates.erase(it);
        } else {
          check.push_back(*it);
          ++it;
        }
      }
      if (check.empty()) return;
      prefetch(check, true, false);
      detail::ByteReader bytes(ctx_, info_);
      detail::Decoder decoder(info_);
      for (std::uint64_t t : check)
        if (!credible(t, bytes, decoder)) {
          rejected_.insert(t);
          candidates.erase(t);
        }
    };
    if (info_.search && !found.empty()) keep_credible(found, vouched);
    // Once calls find nothing new, the firmware search looks in the code
    // nothing reached; what it finds is walked like any other entry: by
    // the start patterns first, then (when they find nothing more) where
    // constants point, so a pointer into a function the patterns were
    // about to find isn't taken for a function's start.
    if (found.empty() && info_.search) {
      report(DiscoveryProgress::Stage::search);
      found = search(false);
      std::erase_if(found, [&](std::uint64_t k) { return not_a_function(k); });
      for (std::uint64_t a : demoted_) found.erase(a);
      keep_credible(found, {});
      if (found.empty()) {
        found = search(true);
        std::erase_if(found, [&](std::uint64_t k) { return not_a_function(k); });
        for (std::uint64_t a : demoted_) found.erase(a);
        keep_credible(found, {});
      }
      searched_.insert(found.begin(), found.end());
      // Nothing new looks like a function: code that adds a call.
      auto code_stage = [&] {
        report(DiscoveryProgress::Stage::search_code);
        found = search_code();
        std::erase_if(found, [&](std::uint64_t k) { return not_a_function(k); });
        for (std::uint64_t a : demoted_) found.erase(a);
        keep_credible(found, {});
        // Code that begins by saving its return address is a function (a
        // possible one: part of whatever function's code runs into it);
        // the rest is code that isn't one until something calls it. In the
        // fallback, on a processor whose calls push the return address,
        // code nothing calls is where the program starts: a possible
        // function too.
        const bool starts = fallback_ && !info_.link_register;
        detail::ByteReader bytes(ctx_, info_);
        detail::Decoder decoder(info_);
        for (std::uint64_t k : found) {
          if (starts || detail::saves_return_address(info_, k, bytes, decoder)) {
            searched_.insert(k);
            possible_.insert(k);
          } else {
            orphans_.insert(k);
          }
        }
      };
      if (found.empty()) code_stage();
      if (found.empty() && !fallback_ && entries_.empty()) {
        // Nothing found at all (no vectors, entry or start patterns, and
        // nothing the searches find): the fallback, once. Routines that
        // code calls from more than one place, as possible functions (as
        // pattern finds are); else, and in the rounds after, find_code
        // with its rules for 8- and 16-bit code.
        fallback_ = true;
        found = search_called();
        std::erase_if(found, [&](std::uint64_t k) { return not_a_function(k); });
        for (std::uint64_t a : demoted_) found.erase(a);
        keep_credible(found, {});
        searched_.insert(found.begin(), found.end());
        possible_.insert(found.begin(), found.end());
        if (found.empty()) code_stage();
      }
    }
    if (found.empty()) break;
    if (round + 1 == kMaxRounds) ctx_.set_confidence(facts::Confidence::Uncertain);
    fresh.assign(found.begin(), found.end());
    for (std::uint64_t t : found) {
      entries_.insert(t);
      discovered_.insert(t);
    }
  }

  // Out of rounds with entries just added: walk them too.
  if (!std::equal(entries_.begin(), entries_.end(), order_.begin(), order_.end())) {
    prefetch(fresh, true, false);
    for (std::uint64_t e : fresh)
      if (flow(e).insns.empty() && !asserted_.contains(e)) entries_.erase(e);
    infer_no_return();
  }

  report(DiscoveryProgress::Stage::bodies);
  find_labels();
  // Code several functions reach goes to the closest entry at or before it.
  // (address, owner, index in the owner's flow graph), sorted by address;
  // owners by their position in `entries`. 16 bytes an instruction: for a
  // large program these are the biggest structures discovery builds.
  const std::vector<std::uint64_t> entries(entries_.begin(), entries_.end());
  if (entries != order_) throw std::logic_error("discovery: walks out of date");
  struct Owned {
    std::uint64_t address;
    std::uint32_t entry;
    std::uint32_t index;
  };
  std::vector<Owned> owner;
  {
    std::vector<std::size_t> offset(walks_.size() + 1, 0);
    for (std::size_t i = 0; i < walks_.size(); ++i) offset[i + 1] = offset[i] + walks_[i].insns.size();
    owner.resize(offset.back());
    ctx_.parallel_for(walks_.size(), [&](std::size_t i) {
      Walk &w = walks_[i];
      for (std::size_t k = 0; k < w.insns.size(); ++k)
        owner[offset[i] + k] = {w.insns[k], static_cast<std::uint32_t>(i), w.index[k]};
      w = Walk();  // not needed any more
    });
  }
  walks_.clear();
  walks_.shrink_to_fit();
  parallel_sort(ctx_, owner, [](const Owned &x, const Owned &y) {
    return x.address != y.address ? x.address < y.address : x.entry < y.entry;
  });
  {
    // The closest entry at or before the address, else the nearest after it.
    std::size_t n = 0;
    for (std::size_t i = 0; i < owner.size();) {
      const std::uint64_t a = owner[i].address;
      Owned best = owner[i];
      for (; i < owner.size() && owner[i].address == a; ++i) {
        const std::uint64_t e = real(entries[owner[i].entry]), cur = real(entries[best.entry]);
        // A function's walk wins over code that isn't one.
        const bool orphan = orphans_.contains(entries[owner[i].entry]), cur_orphan = orphans_.contains(entries[best.entry]);
        if (orphan != cur_orphan) {
          if (cur_orphan) best = owner[i];
          continue;
        }
        if (e <= a ? (cur > a || e > cur) : (cur > a && e < cur)) best = owner[i];
      }
      owner[n++] = best;
    }
    owner.resize(n);
    owner.shrink_to_fit();
  }

  FunctionList out;
  out.code.resize(owner.size());
  ctx_.parallel_for((owner.size() + 65535) / 65536, [&](std::size_t c) {
    for (std::size_t k = c * 65536; k < std::min(owner.size(), (c + 1) * 65536); ++k) {
      const Owned &o = owner[k];
      const FlowInsn &insn = flow_of(entries[o.entry]).insns[o.index];
      out.code[k] = {o.address, insn.length, insn.delay, info_.thumb(entries[o.entry])};
    }
  });
  // Each function's instructions in address order: owner positions grouped
  // by owner (a stable counting sort).
  std::vector<std::uint32_t> first(entries.size() + 1, 0);
  for (const Owned &o : owner) ++first[o.entry + 1];
  for (std::size_t i = 1; i < first.size(); ++i) first[i] += first[i - 1];
  std::vector<std::uint32_t> by_owner(owner.size());
  {
    std::vector<std::uint32_t> next(first.begin(), first.end() - 1);
    for (std::size_t k = 0; k < owner.size(); ++k) by_owner[next[owner[k].entry]++] = static_cast<std::uint32_t>(k);
  }
  // Asserted bodies win: what they cover leaves every other body.
  facts::AddressSet claimed;
  for (const auto &[e, body] : asserted_bodies_)
    for (const facts::AddressRange &r : body.ranges()) claimed.add(r);
  out.functions.resize(entries.size());
  ctx_.parallel_for(entries.size(), [&](std::size_t ei) {
    const std::uint64_t e = entries[ei];
    const FlowGraph &g = flow_of(e);
    FunctionInfo &f = out.functions[ei];
    f.entry = facts::Address{info_.space, real(e)};
    if (info_.thumb(e)) f.flags |= kFunctionThumb;
    if (e != real(e)) f.flags |= kFunctionTagged;
    if (auto body = asserted_bodies_.find(e); body != asserted_bodies_.end()) {
      f.body = body->second;
      f.flags |= kFunctionAssertedBody;
    } else {
      // Contiguous instructions as one range: AddressSet merges adjacent
      // ranges, so this is the same set with fewer insertions.
      std::optional<facts::AddressRange> run;
      auto flush = [&] {
        if (run) f.body.add(*run);
        run.reset();
      };
      for (std::uint32_t k = first[ei]; k < first[ei + 1]; ++k) {
        const Owned &o = owner[by_owner[k]];
        auto r = facts::AddressRange::sized(facts::Address{info_.space, o.address}, g.insns[o.index].length);
        if (!r || (!claimed.empty() && claimed.intersects(*r))) continue;
        if (run && run->last.offset != ~std::uint64_t{0} && run->last.offset + 1 == r->first.offset) {
          run->last = r->last;
        } else {
          flush();
          run = *r;
        }
      }
      flush();
      if (f.body.empty() && asserted_.contains(e)) f.body.add(facts::AddressRange{f.entry, f.entry});
    }
    if (!info_.isa_context.empty()) {
      // What its flow decodes, in its instruction set, beyond its body.
      std::optional<facts::AddressRange> run;
      for (const FlowInsn &i : g.insns) {
        auto r = facts::AddressRange::sized(facts::Address{info_.space, i.address}, i.length);
        if (!r) continue;
        if (run && run->last.offset != ~std::uint64_t{0} && run->last.offset + 1 == r->first.offset) {
          run->last = r->last;
        } else {
          if (run) f.reach.add(*run);
          run = *r;
        }
      }
      if (run) f.reach.add(*run);
      for (const facts::AddressRange &r : f.body.ranges()) f.reach.subtract(r);
    }
    if (asserted_.contains(e)) f.flags |= kFunctionAssertedEntry;
    const ThunkInfo &t = thunk_of(e);
    if (t.kind != ThunkKind::none) {
      f.flags |= kFunctionThunk;
      f.thunk_target = t.kind == ThunkKind::direct ? real(t.target) : t.target;
      f.import = t.import;
    }
    if (no_return_.contains(e)) {
      f.flags |= kFunctionNoReturn;
      f.no_return = user_no_return_.contains(e) ? NoReturnReason::user
                    : named_.contains(e)        ? NoReturnReason::named
                                                : NoReturnReason::inferred;
    }
    if (discovered_.contains(e)) f.flags |= kFunctionDiscovered;
    if (searched_.contains(e)) f.flags |= kFunctionSearched;
    if (const Seed *s = info_.seed_at(real(e))) f.seed = s->flags;
    f.name = name_of(e);
  });
  // Code that isn't a function keeps its instructions in `code` only.
  if (!orphans_.empty()) {
    std::vector<FunctionInfo> kept;
    kept.reserve(out.functions.size());
    for (std::size_t ei = 0; ei < entries.size(); ++ei)
      if (!orphans_.contains(entries[ei])) kept.push_back(std::move(out.functions[ei]));
    out.functions = std::move(kept);
  }
  return out;
}

}  // namespace

// ---- progress ----

namespace {
std::mutex watch_mu;
std::map<std::string, std::shared_ptr<DiscoveryProgress>> &watches() {
  static std::map<std::string, std::shared_ptr<DiscoveryProgress>> w;
  return w;
}
// How many watches there are, and a count of changes to them, so a flow
// finds its program's progress without a lock (detail::discovery_progress).
std::atomic<std::size_t> watch_count{0};
std::atomic<std::uint64_t> watch_generation{1};
}  // namespace

WatchDiscovery::WatchDiscovery(ProgramKey program, std::shared_ptr<DiscoveryProgress> progress)
    : program_(std::move(program)) {
  std::lock_guard lock(watch_mu);
  watches()[program_.id] = std::move(progress);
  watch_count.store(watches().size(), std::memory_order_relaxed);
  watch_generation.fetch_add(1, std::memory_order_release);
}

WatchDiscovery::~WatchDiscovery() {
  std::lock_guard lock(watch_mu);
  watches().erase(program_.id);
  watch_count.store(watches().size(), std::memory_order_relaxed);
  watch_generation.fetch_add(1, std::memory_order_release);
}

DiscoveryProgress *detail::discovery_progress(const ProgramKey &program) {
  if (watch_count.load(std::memory_order_relaxed) == 0) return nullptr;
  struct Cached {
    std::uint64_t generation = 0;
    std::string program;
    std::shared_ptr<DiscoveryProgress> progress;
  };
  thread_local Cached cached;
  const std::uint64_t generation = watch_generation.load(std::memory_order_acquire);
  if (cached.generation != generation || cached.program != program.id) {
    cached.progress = watched_discovery(program);
    cached.program = program.id;
    cached.generation = generation;
  }
  return cached.progress.get();
}

std::shared_ptr<DiscoveryProgress> watched_discovery(const ProgramKey &program) {
  std::lock_guard lock(watch_mu);
  auto it = watches().find(program.id);
  return it == watches().end() ? nullptr : it->second;
}

std::uint64_t decoded_bytes(const FlowGraph &g) {
  std::uint64_t n = 0;
  for (const FlowInsn &i : g.insns) n += i.length;
  return n;
}

FunctionList Functions::compute(facts::QueryContext &ctx, const ProgramKey &program) {
  auto info = ctx.get<Program>(program);
  return Discovery(ctx, program, *info).run();
}

FunctionInfo Function::compute(facts::QueryContext &ctx, const Location &entry) {
  auto all = ctx.get<Functions>(entry.program);
  if (const FunctionInfo *f = all->find(entry.address)) return *f;
  ctx.set_confidence(facts::Confidence::Uncertain);
  FunctionInfo none;
  none.entry = facts::Address{ctx.get<Program>(entry.program)->space, entry.address};
  return none;
}

void register_queries(facts::Engine &engine) {
  engine.add_input<LoadedProgram>();
  register_memory_queries(engine);
  engine.add_query<detail::JumpStub>();
  engine.add_query<detail::CaseHelper>();
  engine.add_query<detail::FrameFragment>();
  engine.add_query<Thunk>();
  engine.add_query<Flow>();
  engine.add_query<Functions>();
  engine.add_query<Function>();
  register_unit_queries(engine);
  register_register_value_queries(engine);
  register_data_queries(engine);
}

}  // namespace revkit::analysis
