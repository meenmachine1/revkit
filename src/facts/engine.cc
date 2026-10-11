#include "revkit/facts/engine.h"

#include <algorithm>
#include <cctype>
#include <condition_variable>
#include <shared_mutex>

namespace revkit::facts {

namespace {

constexpr std::size_t kShards = 64;
// Bookkeeping per memo beyond its value: Memo, Slot, map node, deps vector.
constexpr std::size_t kMemoOverhead = 192;

std::atomic<std::uint64_t> g_next_task{1};

// Each thread is one task: it runs one top-level read at a time, and a
// computation never migrates between threads.
std::uint64_t this_task() {
  thread_local const std::uint64_t id = g_next_task.fetch_add(1, std::memory_order_relaxed);
  return id;
}

// The slots this thread currently owns, outermost first, for cycle reports
// and for rejecting Snapshot reads made from inside a computation.
struct Active {
  const detail::TableBase *table;
  std::string key;
};
thread_local std::vector<Active> t_active;

struct ActiveScope {
  ActiveScope(const detail::TableBase *t, std::string_view key) {
    t_active.push_back({t, std::string(key)});
  }
  ~ActiveScope() { t_active.pop_back(); }
  ActiveScope(const ActiveScope &) = delete;
  ActiveScope &operator=(const ActiveScope &) = delete;
};

struct StringHash {
  using is_transparent = void;
  std::size_t operator()(std::string_view s) const { return std::hash<std::string_view>{}(s); }
};

std::string join(const std::vector<std::string> &parts) {
  std::string s = "query cycle: ";
  for (std::size_t i = 0; i < parts.size(); ++i) s += (i ? " -> " : "") + parts[i];
  return s;
}

std::size_t shard_index(std::string_view key) { return StringHash{}(key) % kShards; }

void put_fp(Encoder &e, const Fingerprint &fp) {
  e.u64be(fp.lo);
  e.u64be(fp.hi);
}

Fingerprint get_fp(Decoder &d) {
  Fingerprint fp;
  fp.lo = d.u64be();
  fp.hi = d.u64be();
  return fp;
}

}  // namespace

CycleError::CycleError(std::vector<std::string> p) : std::runtime_error(join(p)), path(std::move(p)) {}

namespace detail {

std::string to_hex(std::uint64_t v) {
  static const char *digits = "0123456789abcdef";
  std::string s;
  do {
    s.insert(s.begin(), digits[v & 15]);
    v >>= 4;
  } while (v);
  return s;
}

// ---- TableBase ----

TableBase::TableBase(Engine &engine, std::string_view name, std::uint32_t version)
    : engine_(engine), id_(query_id(name)), name_(name), version_(version) {}

TableBase::~TableBase() = default;

std::string TableBase::describe_key(std::string_view key) const {
  bool printable = !key.empty() && std::all_of(key.begin(), key.end(), [](char c) {
    return std::isprint(static_cast<unsigned char>(c));
  });
  std::string out = name_ + "(";
  if (printable) {
    out += key;
  } else {
    static const char *hex = "0123456789abcdef";
    for (char c : key) {
      out += hex[(static_cast<unsigned char>(c) >> 4) & 15];
      out += hex[static_cast<unsigned char>(c) & 15];
    }
  }
  return out + ")";
}

QueryStats TableBase::stats() const {
  auto r = [](const std::atomic<std::uint64_t> &a) { return a.load(std::memory_order_relaxed); };
  return {r(counters_.executions), r(counters_.validations), r(counters_.hits),
          r(counters_.loads), r(counters_.evictions)};
}

void TableBase::reset_stats() {
  for (auto *a : {&counters_.executions, &counters_.validations, &counters_.hits,
                  &counters_.loads, &counters_.evictions})
    a->store(0, std::memory_order_relaxed);
}

void DepList::add(QueryId q, std::string_view key, const Fingerprint &fp) {
  enc_.u32be(q);
  enc_.bytes(key);
  put_fp(enc_, fp);
  ++count_;
}

std::vector<std::string> describe_deps(const Engine &engine, const Memo &memo) {
  std::vector<std::string> out;
  if (!memo.deps) return out;
  for_each_dep(*memo.deps, [&](const DepView &d) {
    try {
      out.push_back(engine.table(d.query).describe_key(d.key));
    } catch (const std::logic_error &) {
      out.push_back("?(unregistered)");
    }
    return true;
  });
  return out;
}

// ---- inputs ----

struct InputVersion {
  Revision rev;
  Fingerprint fp;
  std::shared_ptr<const void> value;
};

struct InputTableBase::Shard {
  mutable std::shared_mutex mu;
  std::unordered_map<std::string, std::vector<InputVersion>, StringHash, std::equal_to<>> map;
};

namespace {

// Keeps the newest version visible at `oldest` and everything after it.
void prune_versions(std::vector<InputVersion> &vs, Revision oldest) {
  std::size_t keep_from = 0;
  for (std::size_t i = 0; i < vs.size(); ++i)
    if (vs[i].rev <= oldest) keep_from = i;
  if (keep_from > 0) vs.erase(vs.begin(), vs.begin() + static_cast<std::ptrdiff_t>(keep_from));
}

}  // namespace

InputTableBase::InputTableBase(Engine &engine, std::string_view name)
    : TableBase(engine, name, 0), shards_(std::make_unique<Shard[]>(kShards)) {}

InputTableBase::~InputTableBase() = default;

InputTableBase::Shard &InputTableBase::shard_for(std::string_view key) const {
  return shards_[shard_index(key)];
}

std::uint64_t InputTableBase::partition_bit(std::string_view) const {
  return std::uint64_t{1} << (16 + id() % 48);
}

Probe InputTableBase::probe(std::string_view key, Revision rev) {
  counters_.hits.fetch_add(1, std::memory_order_relaxed);
  {
    Shard &sh = shard_for(key);
    std::shared_lock lock(sh.mu);
    if (auto it = sh.map.find(key); it != sh.map.end()) {
      const auto &vs = it->second;
      for (auto v = vs.rbegin(); v != vs.rend(); ++v)
        if (v->rev <= rev) return {v->fp, v->rev, v->value, nullptr, partition_bit(key)};
    }
  }
  Probe p = make_default(key);
  p.parts = partition_bit(key);
  return p;
}

bool InputTableBase::install(const std::string &key, Erased value, Revision rev,
                             Revision oldest) {
  Fingerprint fp = Fingerprint::of(value.bytes);
  Probe def = make_default(key);
  Shard &sh = shard_for(key);
  std::unique_lock lock(sh.mu);
  auto &vs = sh.map[key];
  Fingerprint current = vs.empty() ? def.fp : vs.back().fp;
  if (current == fp) {
    if (vs.empty()) sh.map.erase(key);
    return false;
  }
  vs.push_back({rev, fp, std::move(value.value)});
  prune_versions(vs, oldest);
  return true;
}

std::shared_ptr<const void> InputTableBase::latest(std::string_view key) {
  {
    Shard &sh = shard_for(key);
    std::shared_lock lock(sh.mu);
    if (auto it = sh.map.find(key); it != sh.map.end() && !it->second.empty())
      return it->second.back().value;
  }
  return make_default(key).value;
}

void InputTableBase::collect_garbage(Revision oldest) {
  for (std::size_t i = 0; i < kShards; ++i) {
    std::unique_lock lock(shards_[i].mu);
    for (auto &[k, vs] : shards_[i].map) prune_versions(vs, oldest);
  }
}

std::size_t InputTableBase::size() const {
  std::size_t n = 0;
  for (std::size_t i = 0; i < kShards; ++i) {
    std::shared_lock lock(shards_[i].mu);
    n += shards_[i].map.size();
  }
  return n;
}

// ---- derived queries ----

struct DerivedTableBase::Slot {
  std::vector<std::shared_ptr<const Memo>> memos;  // ascending by hi
  std::uint64_t owner = 0;       // task computing or validating, 0 if none
  std::uint64_t generation = 0;  // bumped on every release
  std::uint32_t waiters = 0;
  bool referenced = true;  // second-chance bit for eviction
  bool consulted_storage = false;
  // What storage holds for this key, so unchanged memos are not rewritten.
  // Deps are compared by identity: a re-validated memo shares its deps blob,
  // a recomputed one (even with an equal value) has new dependency
  // fingerprints that must reach disk.
  Fingerprint stored_fp;
  std::shared_ptr<const std::string> stored_deps;
  std::size_t weight = 0;
};

struct DerivedTableBase::Shard {
  std::mutex mu;
  std::condition_variable cv;
  std::unordered_map<std::string, std::unique_ptr<Slot>, StringHash, std::equal_to<>> map;
};

DerivedTableBase::DerivedTableBase(Engine &engine, std::string_view name, std::uint32_t version)
    : TableBase(engine, name, version), shards_(std::make_unique<Shard[]>(kShards)) {}

DerivedTableBase::~DerivedTableBase() {
  std::ptrdiff_t total = 0;
  for (std::size_t i = 0; i < kShards; ++i)
    for (auto &[k, s] : shards_[i].map) total += static_cast<std::ptrdiff_t>(s->weight);
  engine_.add_resident(-total);
}

DerivedTableBase::Shard &DerivedTableBase::shard_for(std::string_view key) const {
  return shards_[shard_index(key)];
}

Probe DerivedTableBase::probe(std::string_view key, Revision rev) {
  auto m = fetch(key, rev);
  return {m->fp, m->lo, m->value, m, m->parts};
}

void DerivedTableBase::prune(Slot &slot, Revision oldest) {
  auto &ms = slot.memos;
  if (ms.size() <= 1) return;
  std::size_t before = slot.weight;
  // The newest memo is the starting point for future validation; older ones
  // stay only while a pinned snapshot might still land in their interval.
  auto keep = [&](std::size_t i) { return i + 1 == ms.size() || ms[i]->hi >= oldest; };
  std::vector<std::shared_ptr<const Memo>> kept;
  slot.weight = 0;
  for (std::size_t i = 0; i < ms.size(); ++i) {
    if (!keep(i)) continue;
    slot.weight += ms[i]->weight;
    kept.push_back(std::move(ms[i]));
  }
  ms = std::move(kept);
  engine_.add_resident(static_cast<std::ptrdiff_t>(slot.weight) -
                       static_cast<std::ptrdiff_t>(before));
}

void DerivedTableBase::insert(Slot &slot, std::shared_ptr<const Memo> m) {
  slot.weight += m->weight;
  engine_.add_resident(static_cast<std::ptrdiff_t>(m->weight));
  auto pos = std::upper_bound(slot.memos.begin(), slot.memos.end(), m->hi,
                              [](Revision hi, const auto &x) { return hi < x->hi; });
  slot.memos.insert(pos, std::move(m));
  prune(slot, engine_.oldest_pinned());
}

void DerivedTableBase::wait_for(Shard &shard, std::unique_lock<std::mutex> &lock, Slot &slot,
                                std::string_view key) {
  const std::uint64_t me = this_task();
  const std::uint64_t gen = slot.generation;
  ++slot.waiters;
  try {
    engine_.wait_begin(me, &slot, slot.owner, describe_key(key));
  } catch (...) {
    --slot.waiters;
    throw;
  }
  shard.cv.wait(lock, [&] { return slot.generation != gen; });
  --slot.waiters;
  engine_.wait_end(me);
}

std::shared_ptr<const Memo> DerivedTableBase::fetch(std::string_view key, Revision rev) {
  const std::uint64_t me = this_task();
  Shard &sh = shard_for(key);
  std::unique_lock lock(sh.mu);
  Slot *slot = nullptr;
  for (;;) {
    auto it = sh.map.find(key);
    if (it == sh.map.end()) it = sh.map.emplace(std::string(key), std::make_unique<Slot>()).first;
    slot = it->second.get();
    slot->referenced = true;
    for (const auto &m : slot->memos) {
      if (m->lo <= rev && rev <= m->hi) {
        counters_.hits.fetch_add(1, std::memory_order_relaxed);
        return m;
      }
    }
    if (slot->owner == 0) break;
    if (slot->owner == me) {
      std::vector<std::string> path;
      bool on_path = false;
      for (const Active &a : t_active) {
        on_path = on_path || (a.table == this && a.key == key);
        if (on_path) path.push_back(a.table->describe_key(a.key));
      }
      path.push_back(describe_key(key));
      throw CycleError(std::move(path));
    }
    wait_for(sh, lock, *slot, key);
  }

  slot->owner = me;
  const bool consult = !slot->consulted_storage && engine_.storage();
  slot->consulted_storage = true;
  std::shared_ptr<const Memo> candidate = slot->memos.empty() ? nullptr : slot->memos.back();
  const bool candidate_in_slot = candidate != nullptr;
  lock.unlock();

  std::shared_ptr<const Memo> result;
  try {
    ActiveScope scope(this, key);
    if (!candidate && consult) {
      candidate = load(key);
      if (candidate) {
        counters_.loads.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard g(sh.mu);
        slot->stored_fp = candidate->fp;
        slot->stored_deps = candidate->deps;
      }
    }
    if (candidate) result = validate(candidate, rev);
    if (!result) result = execute(key, rev, candidate.get());
  } catch (...) {
    lock.lock();
    slot->owner = 0;
    ++slot->generation;
    if (slot->waiters) {
      engine_.release_waiters(slot);
      sh.cv.notify_all();
    }
    throw;
  }

  lock.lock();
  if (!result->provisional && !(candidate_in_slot && result == candidate)) insert(*slot, result);
  slot->owner = 0;
  ++slot->generation;
  if (slot->waiters) {
    engine_.release_waiters(slot);
    sh.cv.notify_all();
  }
  return result;
}

std::shared_ptr<const Memo> DerivedTableBase::validate(const std::shared_ptr<const Memo> &old,
                                                       Revision rev) {
  if (old->lo <= rev && rev <= old->hi) return old;
  if (!old->deps) return nullptr;
  if (rev > old->hi && !old->provisional && engine_.partitions_unchanged(old->parts, old->hi)) {
    // Nothing it read, however indirectly, changed since it was verified.
    counters_.validations.fetch_add(1, std::memory_order_relaxed);
    auto m = std::make_shared<Memo>(*old);
    m->hi = rev;
    return m;
  }
  Revision since = 0;
  std::uint64_t parts = 0;
  bool same = true;
  // In recorded order, stopping at the first change: later deps may not even
  // be read by a fresh computation.
  try {
    for_each_dep(*old->deps, [&](const DepView &d) {
      TableBase *t = nullptr;
      try {
        t = &engine_.table(d.query);
      } catch (const std::logic_error &) {
        return same = false;  // memo from a schema with a query we no longer have
      }
      Probe p = t->probe(d.key, rev);
      if (p.fp != d.fp || (p.memo && p.memo->provisional)) return same = false;
      since = std::max(since, p.since);
      parts |= p.parts;
      return true;
    });
  } catch (const DecodeError &) {
    return nullptr;
  }
  if (!same) return nullptr;
  counters_.validations.fetch_add(1, std::memory_order_relaxed);
  auto m = std::make_shared<Memo>(*old);
  m->parts = parts;
  if (rev > old->hi && since <= old->hi) {
    // Every input held still across (old->hi, rev], so the old interval
    // extends; otherwise we only know the value at rev and from `since`.
    m->hi = rev;
  } else {
    m->lo = since;
    m->hi = rev;
  }
  return m;
}

std::shared_ptr<const Memo> DerivedTableBase::execute(std::string_view key, Revision rev,
                                                      const Memo *old) {
  Frame frame{this, key, rev, {}};
  QueryContext ctx(engine_, frame);
  Computed c = compute(ctx, key);
  counters_.executions.fetch_add(1, std::memory_order_relaxed);

  auto m = std::make_shared<Memo>();
  m->fp = Fingerprint::of(c.bytes);
  m->lo = frame.since;
  m->hi = rev;
  // Early cutoff across the gap: same value and inputs still since old->hi.
  if (old && old->fp == m->fp && rev > old->hi && frame.since <= old->hi) m->lo = old->lo;
  m->value = std::move(c.value);
  {
    // The encoder grew by doubling; a memo keeps its dependencies for life.
    std::string deps = std::move(frame.deps).take();
    deps.shrink_to_fit();
    m->deps = std::make_shared<const std::string>(std::move(deps));
  }
  m->confidence = frame.confidence;
  m->parts = frame.parts;
  m->weight = c.weight + m->deps->capacity() + key.size() + kMemoOverhead;
  if (frame.cycle_tainted) {
    m->provisional = true;
    m->confidence = Confidence::Uncertain;
  }
  return m;
}

std::string DerivedTableBase::storage_key(std::string_view key) const {
  Encoder e;
  e.u32be(id());
  e.raw(key);
  return std::move(e).str();
}

std::string DerivedTableBase::encode_record(const Memo &m) const {
  Encoder e;
  e.varint(version());
  e.varint(m.lo);
  e.varint(m.hi);
  put_fp(e, m.fp);
  facts::encode(e, m.confidence);
  e.bytes(m.deps ? std::string_view(*m.deps) : std::string_view());
  e.raw(encode_value(m.value.get()));
  return std::move(e).str();
}

std::shared_ptr<const Memo> DerivedTableBase::load(std::string_view key) const {
  if (!persistent()) return nullptr;
  auto rec = engine_.storage()->get(Table::Derived, storage_key(key));
  if (!rec) return nullptr;
  try {
    Decoder d(*rec);
    if (d.varint() != version()) return nullptr;  // rule changed: recompute
    auto m = std::make_shared<Memo>();
    m->lo = d.varint();
    m->hi = d.varint();
    m->fp = get_fp(d);
    m->confidence = facts::decode<Confidence>(d);
    if (m->confidence > Confidence::Uncertain) throw DecodeError("bad confidence");
    auto deps = std::make_shared<const std::string>(d.bytes());
    for_each_dep(*deps, [](const DepView &) { return true; });  // reject malformed now
    m->deps = deps;
    std::size_t w = 0;
    m->value = decode_value(d.raw(d.remaining()), w);
    m->weight = w + deps->size() + key.size() + kMemoOverhead;
    return m;
  } catch (const DecodeError &) {
    return nullptr;  // a damaged record only costs a recomputation
  }
}

std::size_t DerivedTableBase::evict(std::size_t bytes, bool force) {
  Storage *storage = engine_.storage();
  std::size_t freed = 0;
  // Two sweeps so second-chance bits cleared on the first can be taken on
  // the second.
  for (std::size_t n = 0; n < 2 * kShards && freed < bytes; ++n) {
    Shard &sh = shards_[evict_cursor_.fetch_add(1, std::memory_order_relaxed) % kShards];
    std::lock_guard lock(sh.mu);
    WriteBatch batch;
    for (auto it = sh.map.begin(); it != sh.map.end() && freed < bytes;) {
      Slot &s = *it->second;
      if (s.owner || s.waiters) {
        ++it;
        continue;
      }
      if (s.referenced && !force) {
        s.referenced = false;
        ++it;
        continue;
      }
      if (storage && persistent() && !s.memos.empty()) {
        const Memo &m = *s.memos.back();
        if (s.stored_deps != m.deps || s.stored_fp != m.fp)
          batch.put(Table::Derived, storage_key(it->first), encode_record(m));
      }
      freed += s.weight;
      engine_.add_resident(-static_cast<std::ptrdiff_t>(s.weight));
      counters_.evictions.fetch_add(1, std::memory_order_relaxed);
      it = sh.map.erase(it);
    }
    // Written under the shard lock so nobody can miss in memory and in
    // storage at once and recompute for nothing.
    if (!batch.empty()) storage->write(batch);
  }
  return freed;
}

void DerivedTableBase::flush() {
  Storage *storage = engine_.storage();
  if (!storage || !persistent()) return;
  for (std::size_t i = 0; i < kShards; ++i) {
    std::lock_guard lock(shards_[i].mu);
    WriteBatch batch;
    for (auto &[k, s] : shards_[i].map) {
      if (s->memos.empty()) continue;
      const Memo &m = *s->memos.back();
      if (s->stored_deps == m.deps && s->stored_fp == m.fp) continue;
      batch.put(Table::Derived, storage_key(k), encode_record(m));
      s->stored_fp = m.fp;
      s->stored_deps = m.deps;
    }
    if (!batch.empty()) storage->write(batch);
  }
}

void DerivedTableBase::collect_garbage(Revision oldest) {
  for (std::size_t i = 0; i < kShards; ++i) {
    std::lock_guard lock(shards_[i].mu);
    for (auto &[k, s] : shards_[i].map)
      if (!s->owner) prune(*s, oldest);
  }
}

std::size_t DerivedTableBase::resident_slots() const {
  std::size_t n = 0;
  for (std::size_t i = 0; i < kShards; ++i) {
    std::lock_guard lock(shards_[i].mu);
    n += shards_[i].map.size();
  }
  return n;
}

}  // namespace detail

// ---- QueryContext / Snapshot ----

detail::Probe QueryContext::read(QueryId q, std::string key) {
  detail::Probe p;
  try {
    p = engine_.table(q).probe(key, frame_.rev);
  } catch (const CycleError &) {
    // If the rule catches this and returns anyway, its result is provisional.
    frame_.cycle_tainted = true;
    throw;
  }
  if (p.memo && p.memo->provisional) frame_.cycle_tainted = true;
  frame_.since = std::max(frame_.since, p.since);
  frame_.parts |= p.parts;
  frame_.deps.add(q, key, p.fp);
  return p;
}

std::vector<detail::Probe> QueryContext::read_all(QueryId q, std::vector<std::string> keys) {
  std::vector<detail::Probe> probes(keys.size());
  detail::TableBase &table = engine_.table(q);
  const Revision rev = frame_.rev;
  try {
    parallel_for(keys.size(), [&](std::size_t i) { probes[i] = table.probe(keys[i], rev); });
  } catch (const CycleError &) {
    frame_.cycle_tainted = true;
    throw;
  }
  // Recorded in key order: the memo doesn't depend on the schedule.
  for (std::size_t i = 0; i < keys.size(); ++i) {
    const detail::Probe &p = probes[i];
    if (p.memo && p.memo->provisional) frame_.cycle_tainted = true;
    frame_.since = std::max(frame_.since, p.since);
    frame_.parts |= p.parts;
    frame_.deps.add(q, keys[i], p.fp);
  }
  return probes;
}

void QueryContext::parallel_for(std::size_t n, const std::function<void(std::size_t)> &fn) {
  if (ThreadPool *pool = engine_.pool(); pool != nullptr && n > 1) {
    pool->parallel_for(n, fn);
  } else {
    for (std::size_t i = 0; i < n; ++i) fn(i);
  }
}

bool QueryContext::parallel() const { return engine_.pool() != nullptr && engine_.pool()->size() > 0; }

detail::Probe Snapshot::read(QueryId q, std::string key) const {
  if (!t_active.empty())
    throw std::logic_error("Snapshot read inside a query; use QueryContext so it is tracked");
  detail::Probe p = engine_->table(q).probe(key, rev_);
  engine_->maybe_evict();
  return p;
}

// ---- Engine ----

Engine::Engine(EngineOptions opt)
    : opt_(opt), revision_(opt.initial_revision), oldest_(opt.initial_revision) {}

Engine::~Engine() {
  // Tables reference resident_ from their destructors; destroy them first.
  derived_.clear();
  tables_.clear();
}

void Engine::add_table(std::unique_ptr<detail::TableBase> t) {
  QueryId id = t->id();
  if (auto it = tables_.find(id); it != tables_.end())
    throw std::logic_error("query id collision or duplicate registration: " + t->name() +
                           " vs " + it->second->name());
  if (auto *d = dynamic_cast<detail::DerivedTableBase *>(t.get())) derived_.push_back(d);
  tables_.emplace(id, std::move(t));
}

detail::TableBase &Engine::table(QueryId id) const {
  auto it = tables_.find(id);
  if (it == tables_.end()) throw std::logic_error("query not registered");
  return *it->second;
}

detail::InputTableBase &Engine::input_table(QueryId id) const {
  auto *t = dynamic_cast<detail::InputTableBase *>(&table(id));
  if (!t) throw std::logic_error(table(id).name() + " is not an input");
  return *t;
}

Revision Engine::revision() const { return revision_.load(std::memory_order_acquire); }

Snapshot Engine::snapshot() {
  std::lock_guard lock(pin_mu_);
  Revision rev = revision_.load(std::memory_order_acquire);
  ++pins_[rev];
  update_oldest();
  std::shared_ptr<void> pin(static_cast<void *>(this), [this, rev](void *) { unpin(rev); });
  return Snapshot(this, rev, std::move(pin));
}

void Engine::unpin(Revision rev) {
  std::lock_guard lock(pin_mu_);
  auto it = pins_.find(rev);
  if (it != pins_.end() && --it->second == 0) pins_.erase(it);
  update_oldest();
}

void Engine::update_oldest() {
  Revision cur = revision_.load(std::memory_order_acquire);
  oldest_.store(pins_.empty() ? cur : std::min(cur, pins_.begin()->first),
                std::memory_order_release);
}

Engine::Writer::Writer(Engine *engine) : engine_(engine) {
  if (engine->writer_thread_.load() == std::this_thread::get_id())
    throw std::logic_error("begin_write while this thread already holds the writer");
  lock_ = std::unique_lock(engine->write_mu_);
  engine->writer_thread_.store(std::this_thread::get_id());
}

Engine::Writer::Writer(Writer &&other) noexcept
    : engine_(other.engine_), lock_(std::move(other.lock_)), staged_(std::move(other.staged_)) {}

Engine::Writer::~Writer() {
  if (lock_.owns_lock()) engine_->writer_thread_.store(std::thread::id{});
}

Revision Engine::Writer::commit() {
  Revision next = engine_->revision() + 1;
  Revision oldest = engine_->oldest_pinned();
  bool changed = false;
  for (auto &[k, v] : staged_) {
    detail::InputTableBase &t = engine_->input_table(k.first);
    if (!t.install(k.second, std::move(v), next, oldest)) continue;
    changed = true;
    // Before the revision is published: a reader at `next` sees it.
    const std::uint64_t bits = t.partition_bit(k.second);
    for (unsigned b = 0; b < 64; ++b)
      if ((bits >> b) & 1) engine_->partition_changed_[b].store(next, std::memory_order_release);
  }
  staged_.clear();
  if (changed) {
    std::lock_guard lock(engine_->pin_mu_);
    engine_->revision_.store(next, std::memory_order_release);
    engine_->update_oldest();
  }
  return engine_->revision();
}

void Engine::reset_stats() {
  for (auto &[id, t] : tables_) t->reset_stats();
}

void Engine::collect_garbage() {
  Revision oldest = oldest_pinned();
  for (auto &[id, t] : tables_) t->collect_garbage(oldest);
}

void Engine::flush() {
  for (auto &[id, t] : tables_)
    if (auto *d = dynamic_cast<detail::DerivedTableBase *>(t.get())) d->flush();
}

void Engine::evict_all() {
  for (auto *d : derived_) d->evict(SIZE_MAX, true);
}

void Engine::add_resident(std::ptrdiff_t delta) {
  resident_.fetch_add(delta, std::memory_order_relaxed);
}

void Engine::maybe_evict() {
  if (opt_.memo_budget == SIZE_MAX || derived_.empty()) return;
  const auto budget = static_cast<std::ptrdiff_t>(opt_.memo_budget);
  // Backpressure: every reader that finds the cache over budget evicts a
  // slice itself before reading on. A single background evictor cannot keep
  // up with many producers, and evicting from different shards in parallel
  // overlaps the encoding work (storage writes still serialize).
  const std::size_t slice = opt_.memo_budget / 16 + 1;
  std::size_t idle = 0;
  while (resident_.load(std::memory_order_relaxed) > budget && idle < derived_.size()) {
    std::size_t n = evict_rr_.fetch_add(1, std::memory_order_relaxed);
    if (derived_[n % derived_.size()]->evict(slice) == 0) ++idle;
    else idle = 0;
  }
}

void Engine::wait_begin(std::uint64_t me, const void *slot, std::uint64_t owner,
                        const std::string &what) {
  std::lock_guard lock(wait_mu_);
  waits_[me] = {slot, owner};
  std::uint64_t t = owner;
  for (std::size_t steps = 0; steps <= waits_.size(); ++steps) {
    if (t == me) {
      waits_.erase(me);
      std::vector<std::string> path;
      for (const auto &a : t_active) path.push_back(a.table->describe_key(a.key));
      path.push_back(what + " [held by another thread]");
      throw CycleError(std::move(path));
    }
    auto it = waits_.find(t);
    if (it == waits_.end()) return;
    t = it->second.owner;
  }
}

void Engine::wait_end(std::uint64_t me) {
  std::lock_guard lock(wait_mu_);
  waits_.erase(me);
}

void Engine::release_waiters(const void *slot) {
  std::lock_guard lock(wait_mu_);
  std::erase_if(waits_, [&](const auto &kv) { return kv.second.slot == slot; });
}

}  // namespace revkit::facts
