// Incremental query engine in the style of salsa.
//
// Inputs are versioned values set by a single writer; each commit publishes a
// new Revision. Queries are pure functions of inputs and other queries; the
// engine memoizes each result together with the fingerprints of everything it
// read. A memo is valid on an interval of revisions [lo, hi]. Reading a key at
// revision S either hits a memo whose interval covers S, re-validates the
// newest memo by probing its dependencies at S (stopping at the first whose
// fingerprint differs), or recomputes. Comparing fingerprints rather than
// "changed at" revisions gives early cutoff, works for readers pinned to old
// revisions, and survives memos being spilled to disk and reloaded.
//
// Concurrency: any number of Snapshots read concurrently, each pinned to the
// revision current when it was taken, while one Writer stages the next
// revision. A key is computed by at most one thread at a time; others wait,
// and a wait-for graph turns cross-thread cycles into CycleError instead of
// deadlock.
#pragma once

#include "revkit/facts/codec.h"
#include "revkit/facts/fingerprint.h"
#include "revkit/facts/storage.h"

#include <array>
#include <atomic>
#include <concepts>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace revkit::facts {

using Revision = std::uint64_t;
using QueryId = std::uint32_t;

enum class Confidence : std::uint8_t { Certain, Likely, Uncertain };

struct CycleError : std::runtime_error {
  explicit CycleError(std::vector<std::string> path);
  std::vector<std::string> path;  // participants, outermost first
};

class Engine;
class QueryContext;
class Snapshot;
class ThreadPool;

// An input: `struct Bytes { static constexpr std::string_view name = "bytes";
// using Key = ...; using Value = ...; }`. Optionally
// `static Value default_value(const Key&)`; otherwise Value{} is the default.
template <class I>
concept InputType = requires {
  typename I::Key;
  typename I::Value;
  { I::name } -> std::convertible_to<std::string_view>;
} && Encodable<typename I::Key> && Encodable<typename I::Value>;

// A derived query: an input-like declaration plus
// `static constexpr std::uint32_t version` (bump when the rule changes) and
// `static Value compute(QueryContext&, const Key&)`. Optionally
// `static std::size_t weight(const Value&)` estimates resident bytes.
template <class Q>
concept QueryType = InputType<Q> && requires(QueryContext &ctx, const typename Q::Key &k) {
  { Q::version } -> std::convertible_to<std::uint32_t>;
  { Q::compute(ctx, k) } -> std::convertible_to<typename Q::Value>;
};

constexpr QueryId query_id(std::string_view name) {
  std::uint32_t h = 2166136261u;
  for (char c : name) h = (h ^ static_cast<unsigned char>(c)) * 16777619u;
  return h;
}

template <class V>
using Ref = std::shared_ptr<const V>;

// A derived value with the metadata the design asks every derived fact to
// carry: the rule that produced it, the rule's version, what it read, and
// how sure the rule is.
template <class V>
struct DerivedFact {
  Ref<V> value;
  std::string rule;
  std::uint32_t rule_version = 0;
  Confidence confidence = Confidence::Certain;
  std::vector<std::string> inputs;  // "query(key)" for each dependency read
  Fingerprint fingerprint;
  Revision valid_from = 0;
  Revision verified_at = 0;
};

struct QueryStats {
  std::uint64_t executions = 0;   // compute() ran
  std::uint64_t validations = 0;  // stale memo re-validated without running
  std::uint64_t hits = 0;         // memo already valid at the revision
  std::uint64_t loads = 0;        // memo read back from storage
  std::uint64_t evictions = 0;    // memo dropped from memory
};

struct EngineOptions {
  // Where evicted memos go. Null keeps everything in memory and drops evicted
  // memos outright.
  Storage *storage = nullptr;
  // Soft cap on resident memo bytes; beyond it, cold memos are spilled.
  std::size_t memo_budget = SIZE_MAX;
  // The first commit publishes initial_revision + 1. Persisted memos carry
  // revisions, so a reopened store must continue past what it saw before.
  Revision initial_revision = 0;
};

namespace detail {

std::string to_hex(std::uint64_t v);

// Dependencies are stored as one encoded blob per memo (u32be query id,
// length-prefixed key, 16-byte fingerprint per entry): about half the size of
// a vector of structs, and it is written to storage as-is.
class DepList {
 public:
  void add(QueryId q, std::string_view key, const Fingerprint &fp);
  std::size_t count() const { return count_; }
  const std::string &bytes() const { return enc_.str(); }
  std::string take() && { return std::move(enc_).str(); }

 private:
  Encoder enc_;
  std::size_t count_ = 0;
};

struct DepView {
  QueryId query;
  std::string_view key;
  Fingerprint fp;
};
// Calls fn(DepView) for each entry until it returns false. Throws
// DecodeError on a malformed blob.
template <class Fn>
void for_each_dep(std::string_view blob, Fn &&fn) {
  Decoder d(blob);
  while (!d.done()) {
    DepView v;
    v.query = d.u32be();
    v.key = d.bytes();
    v.fp.lo = d.u64be();
    v.fp.hi = d.u64be();
    if (!fn(v)) return;
  }
}

// One computed or validated result. Immutable once published; extending the
// verified interval publishes a new Memo sharing value and deps.
struct Memo {
  Revision lo = 0;  // value is known correct for every revision in [lo, hi]
  Revision hi = 0;
  Fingerprint fp;
  std::shared_ptr<const void> value;
  std::shared_ptr<const std::string> deps;  // DepList encoding
  Confidence confidence = Confidence::Certain;
  std::size_t weight = 0;
  // Computed while a cycle was being unwound: returned to the caller but
  // never memoized (the hook point for future fixpoint iteration).
  bool provisional = false;
  // The input partitions it read, transitively (a bit each, see
  // Engine::partition_changed); all ones when unknown (a memo loaded from
  // storage, until it is validated once).
  std::uint64_t parts = ~std::uint64_t{0};
};

struct Probe {
  Fingerprint fp;
  Revision since;  // the value has been constant on [since, rev]
  std::shared_ptr<const void> value;
  std::shared_ptr<const Memo> memo;  // null for inputs
  std::uint64_t parts = ~std::uint64_t{0};  // partitions the value depends on
};

class TableBase {
 public:
  TableBase(Engine &engine, std::string_view name, std::uint32_t version);
  virtual ~TableBase();
  TableBase(const TableBase &) = delete;
  TableBase &operator=(const TableBase &) = delete;

  // The value at rev, computing or validating it first if needed.
  virtual Probe probe(std::string_view key, Revision rev) = 0;
  virtual std::string describe_key(std::string_view key) const;
  virtual void collect_garbage(Revision oldest) = 0;

  QueryId id() const { return id_; }
  const std::string &name() const { return name_; }
  std::uint32_t version() const { return version_; }
  QueryStats stats() const;
  void reset_stats();

 protected:
  Engine &engine_;
  struct Counters {
    std::atomic<std::uint64_t> executions{0}, validations{0}, hits{0}, loads{0}, evictions{0};
  } counters_;

 private:
  QueryId id_;
  std::string name_;
  std::uint32_t version_;
};

struct Erased {
  std::shared_ptr<const void> value;
  std::string bytes;
};

class InputTableBase : public TableBase {
 public:
  InputTableBase(Engine &engine, std::string_view name);
  ~InputTableBase() override;

  Probe probe(std::string_view key, Revision rev) override;
  void collect_garbage(Revision oldest) override;
  // Writer side. Returns false (and installs nothing) if the value's
  // fingerprint equals the current one.
  bool install(const std::string &key, Erased value, Revision rev, Revision oldest);
  // The partition bit of a key (Engine::partition_changed): one of the 16
  // low bits when the input declares `partition(key)` (the assertion
  // index: by fact kind), else a high bit for the whole table.
  virtual std::uint64_t partition_bit(std::string_view key) const;
  std::shared_ptr<const void> latest(std::string_view key);
  std::size_t size() const;

 protected:
  virtual Probe make_default(std::string_view key) const = 0;

 private:
  struct Shard;
  std::unique_ptr<Shard[]> shards_;
  Shard &shard_for(std::string_view key) const;
};

class DerivedTableBase : public TableBase {
 public:
  DerivedTableBase(Engine &engine, std::string_view name, std::uint32_t version);
  ~DerivedTableBase() override;

  Probe probe(std::string_view key, Revision rev) override;
  std::shared_ptr<const Memo> fetch(std::string_view key, Revision rev);
  void collect_garbage(Revision oldest) override;

  // Spills memos (writing them to storage first if there is one) until about
  // `bytes` have been freed; returns what was freed.
  std::size_t evict(std::size_t bytes, bool force = false);
  void flush();  // persist every resident memo not yet in storage
  std::size_t resident_slots() const;
  // False for a rule whose values hold what an encoding can't (pointers to
  // live objects): never written to storage nor read back, so each process
  // computes it again. Its value's encoding is still its fingerprint, so
  // dependents validate against the recomputed value. A rule opts out with
  // `static constexpr bool persistent = false;`.
  virtual bool persistent() const { return true; }

 protected:
  struct Computed {
    std::shared_ptr<const void> value;
    std::string bytes;
    std::size_t weight;
  };
  virtual Computed compute(QueryContext &ctx, std::string_view key) = 0;
  virtual std::shared_ptr<const void> decode_value(std::string_view bytes,
                                                   std::size_t &weight) const = 0;
  virtual std::string encode_value(const void *value) const = 0;

 private:
  struct Slot;
  struct Shard;
  std::unique_ptr<Shard[]> shards_;
  std::atomic<std::size_t> evict_cursor_{0};

  Shard &shard_for(std::string_view key) const;
  std::shared_ptr<const Memo> validate(const std::shared_ptr<const Memo> &old, Revision rev);
  std::shared_ptr<const Memo> execute(std::string_view key, Revision rev, const Memo *old);
  std::shared_ptr<const Memo> load(std::string_view key) const;
  std::string storage_key(std::string_view key) const;
  std::string encode_record(const Memo &m) const;
  void wait_for(Shard &shard, std::unique_lock<std::mutex> &lock, Slot &slot,
                std::string_view key);
  void insert(Slot &slot, std::shared_ptr<const Memo> m);
  void prune(Slot &slot, Revision oldest);
};

// "name(key)" for diagnostics: Q::describe(key) if provided, else a
// readable form for common key types, else hex.
template <class Q>
std::string describe(const TableBase &t, std::string_view key) {
  using K = typename Q::Key;
  try {
    if constexpr (requires(const K &k) { { Q::describe(k) } -> std::convertible_to<std::string>; }) {
      return t.name() + "(" + Q::describe(decode_from_string<K>(key)) + ")";
    } else if constexpr (std::is_same_v<K, std::string>) {
      return t.name() + "(" + decode_from_string<K>(key) + ")";
    } else if constexpr (std::is_same_v<K, Address>) {
      auto a = decode_from_string<K>(key);
      return t.name() + "(" + std::to_string(a.space) + ":0x" + to_hex(a.offset) + ")";
    } else if constexpr (std::is_integral_v<K>) {
      return t.name() + "(" + std::to_string(decode_from_string<K>(key)) + ")";
    }
  } catch (const DecodeError &) {
  }
  return t.TableBase::describe_key(key);
}

template <class I>
class InputTable final : public InputTableBase {
 public:
  explicit InputTable(Engine &engine) : InputTableBase(engine, I::name) {}
  std::string describe_key(std::string_view key) const override { return describe<I>(*this, key); }
  std::uint64_t partition_bit(std::string_view key) const override {
    if constexpr (requires(const typename I::Key &k) { { I::partition(k) } -> std::convertible_to<unsigned>; }) {
      try {
        return std::uint64_t{1} << (static_cast<unsigned>(I::partition(decode_from_string<typename I::Key>(key))) % 16);
      } catch (const DecodeError &) {
        return ~std::uint64_t{0};
      }
    } else {
      return InputTableBase::partition_bit(key);
    }
  }

 protected:
  Probe make_default(std::string_view key) const override {
    using V = typename I::Value;
    if constexpr (requires(const typename I::Key &k) { I::default_value(k); }) {
      auto v = std::make_shared<const V>(
          I::default_value(decode_from_string<typename I::Key>(key)));
      return {Fingerprint::of(encode_to_string(*v)), 0, v, nullptr};
    } else {
      // Key-independent default: build it once.
      static const Probe fixed = [] {
        auto v = std::make_shared<const V>();
        return Probe{Fingerprint::of(encode_to_string(*v)), 0, v, nullptr};
      }();
      return fixed;
    }
  }
};

template <class Q>
class DerivedTable final : public DerivedTableBase {
 public:
  explicit DerivedTable(Engine &engine) : DerivedTableBase(engine, Q::name, Q::version) {}
  std::string describe_key(std::string_view key) const override { return describe<Q>(*this, key); }
  bool persistent() const override {
    if constexpr (requires { Q::persistent; }) return Q::persistent;
    else return true;
  }

 protected:
  using V = typename Q::Value;

  Computed compute(QueryContext &ctx, std::string_view key) override {
    auto k = decode_from_string<typename Q::Key>(key);
    auto v = std::make_shared<const V>(Q::compute(ctx, k));
    std::string bytes = encode_to_string(*v);
    std::size_t w = weigh(*v, bytes.size());
    return {std::move(v), std::move(bytes), w};
  }
  std::shared_ptr<const void> decode_value(std::string_view bytes,
                                           std::size_t &weight) const override {
    auto v = std::make_shared<const V>(decode_from_string<V>(bytes));
    weight = weigh(*v, bytes.size());
    return v;
  }
  std::string encode_value(const void *value) const override {
    return encode_to_string(*static_cast<const V *>(value));
  }

 private:
  static std::size_t weigh(const V &v, std::size_t encoded) {
    if constexpr (requires { Q::weight(v); }) return Q::weight(v);
    else return sizeof(V) + encoded;
  }
};

// Per-thread bookkeeping for the computation currently running.
struct Frame {
  DerivedTableBase *table;
  std::string_view key;
  Revision rev;
  DepList deps;
  Revision since = 0;
  Confidence confidence = Confidence::Certain;
  bool cycle_tainted = false;
  std::uint64_t parts = 0;  // input partitions read, transitively
};

}  // namespace detail

// Passed to Q::compute. Every read through it is recorded as a dependency.
class QueryContext {
 public:
  template <class Q>
  Ref<typename Q::Value> get(const typename Q::Key &key);
  template <QueryType Q>
  DerivedFact<typename Q::Value> fact(const typename Q::Key &key);

  // Reads every key, in parallel on the engine's pool when it has one
  // (Engine::set_pool), and records them as dependencies in key order, so
  // the memo is the same whatever the schedule. The keys' computations
  // must not read this query (a true cycle): a worker waiting on a key this
  // thread computes isn't seen as a cycle, and would wait forever.
  template <class Q>
  std::vector<Ref<typename Q::Value>> get_all(std::span<const typename Q::Key> keys);
  // Runs fn(0..n-1) on the engine's pool (on this thread without one), for
  // work on values already read. fn must not read through any context:
  // reads there would not be recorded.
  void parallel_for(std::size_t n, const std::function<void(std::size_t)> &fn);
  // Whether parallel_for can use more than this thread.
  bool parallel() const;

  // Marks this result as less than certain. Not propagated automatically:
  // a rule decides how its inputs' confidence affects its own.
  void set_confidence(Confidence c) { frame_.confidence = c; }
  Revision revision() const { return frame_.rev; }

 private:
  std::vector<detail::Probe> read_all(QueryId q, std::vector<std::string> keys);
  friend class detail::DerivedTableBase;
  QueryContext(Engine &engine, detail::Frame &frame) : engine_(engine), frame_(frame) {}
  detail::Probe read(QueryId q, std::string key);

  Engine &engine_;
  detail::Frame &frame_;
};

// A read-only view of one revision. Cheap to copy; keeps that revision's
// input versions and memos alive while held.
class Snapshot {
 public:
  Revision revision() const { return rev_; }

  template <class Q>
  Ref<typename Q::Value> get(const typename Q::Key &key) const;
  template <QueryType Q>
  DerivedFact<typename Q::Value> fact(const typename Q::Key &key) const;
  // Evaluates keys in parallel; results are in key order whatever the
  // schedule. A null pool runs on the calling thread.
  template <class Q>
  std::vector<Ref<typename Q::Value>> get_all(std::span<const typename Q::Key> keys,
                                              ThreadPool *pool) const;

 private:
  friend class Engine;
  Snapshot(Engine *engine, Revision rev, std::shared_ptr<void> pin)
      : engine_(engine), rev_(rev), pin_(std::move(pin)) {}
  detail::Probe read(QueryId q, std::string key) const;

  Engine *engine_;
  Revision rev_;
  std::shared_ptr<void> pin_;
};

class Engine {
 public:
  explicit Engine(EngineOptions opt = {});
  ~Engine();
  Engine(const Engine &) = delete;
  Engine &operator=(const Engine &) = delete;

  // Register every input and query before taking snapshots.
  template <InputType I>
  void add_input() {
    add_table(std::make_unique<detail::InputTable<I>>(*this));
  }
  template <QueryType Q>
  void add_query() {
    add_table(std::make_unique<detail::DerivedTable<Q>>(*this));
  }

  Revision revision() const;
  Snapshot snapshot();

  // Input partitions: every input key belongs to one of 64 (a bit), and the
  // engine records the last revision a key of each changed. A memo knows
  // the partitions it read transitively, so when none of them changed
  // since it was last verified, it is still valid without probing its
  // dependencies one by one: a Match assertion doesn't revalidate the
  // fingerprints of every function (salsa's "durability", by partition).
  bool partitions_unchanged(std::uint64_t parts, Revision since) const {
    for (unsigned b = 0; b < 64; ++b)
      if ((parts >> b) & 1)
        if (partition_changed_[b].load(std::memory_order_acquire) > since) return false;
    return true;
  }

  // A pool queries may use for work inside one computation
  // (QueryContext::get_all, parallel_for); not owned, null for none. Set it
  // before taking snapshots; it must outlive every computation.
  void set_pool(ThreadPool *pool) { pool_ = pool; }
  ThreadPool *pool() const { return pool_; }

  // Exclusive: a second begin_write() blocks until the first Writer is gone
  // (and throws std::logic_error if called from the thread holding it).
  class Writer {
   public:
    template <InputType I>
    void set(const typename I::Key &key, typename I::Value value) {
      auto v = std::make_shared<const typename I::Value>(std::move(value));
      std::string bytes = encode_to_string(*v);
      staged_.insert_or_assign({query_id(I::name), encode_to_string(key)},
                               detail::Erased{std::move(v), std::move(bytes)});
    }
    // The value as of this writer: staged if set, else latest committed.
    template <InputType I>
    Ref<typename I::Value> latest(const typename I::Key &key) const {
      std::pair<QueryId, std::string> k{query_id(I::name), encode_to_string(key)};
      if (auto it = staged_.find(k); it != staged_.end())
        return std::static_pointer_cast<const typename I::Value>(it->second.value);
      return std::static_pointer_cast<const typename I::Value>(
          engine_->input_table(k.first).latest(k.second));
    }
    // Publishes staged values as a new revision. Values equal to the current
    // ones are dropped; if nothing changes, the revision does not advance.
    Revision commit();
    bool empty() const { return staged_.empty(); }

    Writer(Writer &&other) noexcept;
    Writer &operator=(Writer &&) = delete;
    ~Writer();

   private:
    friend class Engine;
    explicit Writer(Engine *engine);
    Engine *engine_;
    std::unique_lock<std::mutex> lock_;
    std::map<std::pair<QueryId, std::string>, detail::Erased> staged_;
  };
  Writer begin_write() { return Writer(this); }

  template <class Q>
  QueryStats stats() const {
    return table(query_id(Q::name)).stats();
  }
  void reset_stats();

  // Drops input versions and memos no live snapshot can see.
  void collect_garbage();
  // Persists every resident memo (no-op without storage).
  void flush();
  // Spills every resident memo; later reads load from storage or recompute.
  void evict_all();
  std::size_t resident_bytes() const { return resident_.load(std::memory_order_relaxed); }
  Storage *storage() const { return opt_.storage; }

  // Internal: the table registered under id; throws std::logic_error.
  detail::TableBase &table(QueryId id) const;

 private:
  friend class Snapshot;
  friend class QueryContext;
  friend class detail::TableBase;
  friend class detail::InputTableBase;
  friend class detail::DerivedTableBase;

  void add_table(std::unique_ptr<detail::TableBase> t);
  detail::InputTableBase &input_table(QueryId id) const;
  Revision oldest_pinned() const { return oldest_.load(std::memory_order_acquire); }
  void unpin(Revision rev);
  void update_oldest();  // pin_mu_ held
  void add_resident(std::ptrdiff_t delta);
  void maybe_evict();

  // Cross-thread cycle detection: which task waits on which slot's owner.
  struct WaitEdge {
    const void *slot;
    std::uint64_t owner;
  };
  // Records that `me` waits on `owner` for `slot`; throws CycleError if that
  // closes a loop.
  void wait_begin(std::uint64_t me, const void *slot, std::uint64_t owner,
                  const std::string &what);
  void wait_end(std::uint64_t me);
  void release_waiters(const void *slot);

  EngineOptions opt_;
  std::unordered_map<QueryId, std::unique_ptr<detail::TableBase>> tables_;
  std::mutex write_mu_;
  std::atomic<std::thread::id> writer_thread_{};
  mutable std::mutex pin_mu_;
  std::map<Revision, std::size_t> pins_;
  std::atomic<Revision> revision_;
  std::atomic<Revision> oldest_;
  std::atomic<std::ptrdiff_t> resident_{0};
  std::vector<detail::DerivedTableBase *> derived_;  // registration order
  std::atomic<std::size_t> evict_rr_{0};
  std::mutex wait_mu_;
  std::unordered_map<std::uint64_t, WaitEdge> waits_;
  ThreadPool *pool_ = nullptr;
  std::array<std::atomic<Revision>, 64> partition_changed_{};
};

// ---- template implementations ----

template <class Q>
Ref<typename Q::Value> QueryContext::get(const typename Q::Key &key) {
  return std::static_pointer_cast<const typename Q::Value>(
      read(query_id(Q::name), encode_to_string(key)).value);
}

namespace detail {
std::vector<std::string> describe_deps(const Engine &engine, const Memo &memo);
}

template <class V>
DerivedFact<V> make_fact(const Engine &engine, const detail::DerivedTableBase &table,
                         const detail::Probe &p) {
  DerivedFact<V> f;
  f.value = std::static_pointer_cast<const V>(p.value);
  f.rule = table.name();
  f.rule_version = table.version();
  f.fingerprint = p.fp;
  if (p.memo) {
    f.confidence = p.memo->confidence;
    f.inputs = detail::describe_deps(engine, *p.memo);
    f.valid_from = p.memo->lo;
    f.verified_at = p.memo->hi;
  }
  return f;
}

template <QueryType Q>
DerivedFact<typename Q::Value> QueryContext::fact(const typename Q::Key &key) {
  QueryId id = query_id(Q::name);
  detail::Probe p = read(id, encode_to_string(key));
  return make_fact<typename Q::Value>(
      engine_, static_cast<const detail::DerivedTableBase &>(engine_.table(id)), p);
}

template <class Q>
Ref<typename Q::Value> Snapshot::get(const typename Q::Key &key) const {
  return std::static_pointer_cast<const typename Q::Value>(
      read(query_id(Q::name), encode_to_string(key)).value);
}

template <QueryType Q>
DerivedFact<typename Q::Value> Snapshot::fact(const typename Q::Key &key) const {
  QueryId id = query_id(Q::name);
  detail::Probe p = read(id, encode_to_string(key));
  return make_fact<typename Q::Value>(
      *engine_, static_cast<const detail::DerivedTableBase &>(engine_->table(id)), p);
}

}  // namespace revkit::facts

#include "revkit/facts/thread_pool.h"

namespace revkit::facts {

template <class Q>
std::vector<Ref<typename Q::Value>> QueryContext::get_all(std::span<const typename Q::Key> keys) {
  std::vector<std::string> encoded;
  encoded.reserve(keys.size());
  for (const auto &k : keys) encoded.push_back(encode_to_string(k));
  std::vector<detail::Probe> probes = read_all(query_id(Q::name), std::move(encoded));
  std::vector<Ref<typename Q::Value>> out;
  out.reserve(probes.size());
  for (detail::Probe &p : probes) out.push_back(std::static_pointer_cast<const typename Q::Value>(std::move(p.value)));
  return out;
}

template <class Q>
std::vector<Ref<typename Q::Value>> Snapshot::get_all(std::span<const typename Q::Key> keys,
                                                      ThreadPool *pool) const {
  std::vector<Ref<typename Q::Value>> out(keys.size());
  auto one = [&](std::size_t i) { out[i] = get<Q>(keys[i]); };
  if (pool) {
    pool->parallel_for(keys.size(), one);
    engine_->maybe_evict();  // workers may all have skipped a busy evictor
  } else {
    for (std::size_t i = 0; i < keys.size(); ++i) one(i);
  }
  return out;
}

}  // namespace revkit::facts
