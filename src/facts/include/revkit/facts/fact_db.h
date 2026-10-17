// FactDb: the assertion log, program bytes and the query engine over one
// storage backend. The log and bytes are the inputs; everything else is a
// query registered on engine().
//
// A Transaction is the single writer. On commit its ops are made durable,
// appended to the log, and the effective value of every key they touched is
// pushed into the engine as the AssertedFact input, publishing one revision.
#pragma once

#include "revkit/facts/assertion_log.h"
#include "revkit/facts/engine.h"
#include "revkit/facts/storage.h"

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <unordered_map>

namespace revkit::facts {

// Effective (winning) value of an asserted key, monostate if none is live.
struct AssertedFact {
  static constexpr std::string_view name = "fact";
  using Key = FactKey;
  using Value = FactValue;
  static std::string describe(const FactKey &k);  // "name@1:0x401000"
  // Partitioned by kind (Engine::partitions_unchanged): what read only
  // names isn't revalidated after a comment or a Match assertion.
  static unsigned partition(const FactKey &k) { return static_cast<unsigned>(k.kind); }
};

inline constexpr std::uint64_t kPageSize = 4096;

struct PageKey {
  SpaceId space = 0;
  std::uint64_t index = 0;  // offset / kPageSize

  void encode(Encoder &e) const {
    e.varint(space);
    e.varint(index);
  }
  static PageKey decode(Decoder &d) {
    PageKey k;
    k.space = facts::decode<SpaceId>(d);
    k.index = d.varint();
    return k;
  }
  friend auto operator<=>(const PageKey &, const PageKey &) = default;
};

// Program bytes, one page per key. Empty means unmapped; a mapped page is
// always kPageSize long.
struct MemoryPage {
  static constexpr std::string_view name = "page";
  using Key = PageKey;
  using Value = std::string;
};

// Reads up to n bytes at addr through the engine (so the pages become
// dependencies), stopping early at unmapped memory.
std::string read_bytes(QueryContext &ctx, Address addr, std::size_t n);

// Where the winning assertion of a key ranks among the winners of other
// keys: precedence (rank), then recency (stamp, replica, counter), as an
// order-preserving string; empty when nothing live asserts it. Kept for
// kinds whose keys compose (overlapping Patch keys), not for every kind.
struct AssertedOrder {
  static constexpr std::string_view name = "fact.order";
  using Key = FactKey;
  using Value = std::string;
  static std::string describe(const FactKey &k) { return AssertedFact::describe(k); }
  static unsigned partition(const FactKey &k) { return static_cast<unsigned>(k.kind); }
};

// Whether AssertedOrder is kept for keys of this kind: those that compose,
// and TYPE (whose winner's rank decides it against a derived, import-rank
// prototype: docs/demangle.md).
inline bool ordered_kind(FactKind k) {
  return k == FactKind::Patch || k == FactKind::CodeUnit || k == FactKind::Mutability || k == FactKind::Type ||
         k == FactKind::RegisterValue;
}

// The bytes as patched (docs/patching.md, "bytes.effective"): MemoryPage
// with every live Patch key overlapping the page laid over it, lower
// precedence first, so the winner of an overlap is the key with the
// higher (rank, stamp). Patches outside mapped memory are ignored (empty
// page). Every reader that decodes the program's bytes reads this.
struct EffectivePage {
  static constexpr std::string_view name = "bytes.effective";
  static constexpr std::uint32_t version = 2;  // 2: through patch.page
  using Key = PageKey;
  using Value = std::string;
  static Value compute(QueryContext &ctx, const Key &key);
};

// read_bytes() over EffectivePage.
std::string read_effective_bytes(QueryContext &ctx, Address addr, std::size_t n);

// The live patches starting in one 256-byte span of the key index:
// (AssertedOrder, (address, bytes)). What everything that lays patches
// over bytes reads where patch.page says there may be some, so it depends
// on the spans it covers only.
struct PatchSpan {
  static constexpr std::string_view name = "patch.span";
  static constexpr std::uint32_t version = 1;
  using Key = std::pair<SpaceId, std::uint64_t>;  // (space, offset >> kSpanShift)
  using Value = std::vector<std::pair<std::string, std::pair<std::uint64_t, std::string>>>;
  static Value compute(QueryContext &ctx, const Key &key);
};

// Whether a live Patch key may overlap one page: one starts in the page or
// in the kMaxPatchBytes - 1 bytes before it (from the key index, so true
// for any asserted Patch key there). The gate in front of patch.span: a
// reader checks the pages it reads and looks at their spans only where
// this is true, so a program without patches costs one of these per page
// read rather than two memos and a dependency per 256-byte span. The first
// patch near a page re-runs that page's readers once; from then on the
// gate holds still and a patch re-runs only the readers of its spans.
struct PatchedPage {
  static constexpr std::string_view name = "patch.page";
  static constexpr std::uint32_t version = 1;
  using Key = PageKey;
  using Value = bool;
  static Value compute(QueryContext &ctx, const Key &key);
};

// The live patches overlapping [first, last] of one space, in the order
// they apply (lowest precedence first): (address, bytes). From a query
// (the patch.page gates of the pages it covers, and the spans of those
// that may hold patches, become dependencies) or a snapshot.
using PatchList = std::vector<std::pair<std::uint64_t, std::string>>;
PatchList patches_overlapping(QueryContext &ctx, SpaceId space, std::uint64_t first, std::uint64_t last);
PatchList patches_overlapping(const Snapshot &snap, SpaceId space, std::uint64_t first, std::uint64_t last);
// Lays `patches` over `bytes`, which hold the bytes at `at`.
void apply_patches(const PatchList &patches, std::uint64_t at, std::string &bytes);

// Number of ops in the log. Every commit that appends ops changes it, so
// each such commit publishes exactly one new revision, even when no
// effective value changed (an equal or shadowed assertion).
struct LogLength {
  static constexpr std::string_view name = "log.length";
  using Key = std::uint8_t;  // always 0
  using Value = std::uint64_t;
};

// Where the asserted keys are, so a rule can find "every comment in this
// function" without reading every address: the keys of one kind in one
// space whose effective value is not monostate, grouped into buckets of
// 2^kBucketShift addresses and sorted by (offset, sub). A rule reading the
// buckets its range overlaps only reruns when a key in them comes or goes.
inline constexpr unsigned kBucketShift = 16;

struct BucketKey {
  FactKind kind = FactKind::Name;
  SpaceId space = 0;
  std::uint64_t index = 0;  // offset >> kBucketShift

  void encode(Encoder &e) const {
    facts::encode(e, kind);
    e.varint(space);
    e.varint(index);
  }
  static BucketKey decode(Decoder &d) {
    BucketKey k;
    k.kind = facts::decode<FactKind>(d);
    k.space = facts::decode<SpaceId>(d);
    k.index = d.varint();
    return k;
  }
  friend auto operator<=>(const BucketKey &, const BucketKey &) = default;
};

struct AssertedKeys {
  static constexpr std::string_view name = "fact.keys";
  using Key = BucketKey;
  using Value = std::vector<std::pair<std::uint64_t, std::string>>;  // (offset, sub)
  static unsigned partition(const BucketKey &k) { return static_cast<unsigned>(k.kind); }
};

// The non-empty buckets of one kind in one space, ascending: for rules that
// enumerate every key of a kind (all asserted function bounds).
struct AssertedBuckets {
  static constexpr std::string_view name = "fact.buckets";
  using Key = std::pair<FactKind, SpaceId>;
  using Value = std::vector<std::uint64_t>;
  static unsigned partition(const Key &k) { return static_cast<unsigned>(k.first); }
};

// The same index at a finer grain: the asserted keys of one kind in one
// space within 2^kSpanShift addresses, filtered out of their bucket. A
// rule that looks at many scattered addresses (every instruction a flow
// decodes) reads the spans they fall in, so a key that comes or goes
// elsewhere in the bucket re-runs only this filter, which cuts off.
inline constexpr unsigned kSpanShift = 8;

struct AssertedSpan {
  static constexpr std::string_view name = "fact.span";
  static constexpr std::uint32_t version = 1;
  using Key = BucketKey;  // index = offset >> kSpanShift
  using Value = AssertedKeys::Value;
  static Value compute(QueryContext &ctx, const Key &key);
};

// Asserted keys of `kind` in [first, last] (one space), read through the
// index so only the overlapping spans (narrow ranges) or buckets become
// dependencies.
std::vector<FactKey> asserted_keys(QueryContext &ctx, FactKind kind, Address first, Address last);

// Asserted keys of `kind` at exactly `at` (any sub), through its span.
std::vector<FactKey> asserted_at(QueryContext &ctx, FactKind kind, Address at);

class FactDb;
class FactDbTransaction;

// ---- Rebase (docs/memory-map.md, "Rebase: setting the image base") ----
//
// A program space's keys are stored image-relative: at the addresses their
// facts had when the program was imported. A live FactKind::Rebase key in
// the space (address 0) moves them: the store indexes every key (and its
// Address and AddressSet values) at its address plus the Shift's delta, so
// every query reads the moved addresses, and Transaction::assert_fact
// takes moved keys and stores them image-relative. The log, its persisted
// ops and what replicas exchange hold image-relative keys only.

// How a space's addresses move: by `delta`, in its default memory of
// `bits`-bit addresses (keys >= 2^bits, other memory spaces folded into
// the space's keys, don't move), wrapping there.
struct Shift {
  std::uint64_t delta = 0;
  unsigned bits = 64;

  bool identity() const { return delta == 0; }
  bool moves(std::uint64_t addr) const { return bits >= 64 || addr < (std::uint64_t{1} << bits); }
  std::uint64_t apply(std::uint64_t addr) const {
    if (!moves(addr)) return addr;
    const std::uint64_t v = addr + delta;
    return bits >= 64 ? v : v & ((std::uint64_t{1} << bits) - 1);
  }
  Shift inverse() const { return {~delta + 1, bits}; }
  // The Rebase value's text, "<delta hex>/<bits>"; parse() reads it back
  // (nullopt: not one, which reads as no shift).
  std::string str() const;
  static std::optional<Shift> parse(std::string_view text);
  friend bool operator==(const Shift &, const Shift &) = default;
};

// What the store can't move itself: addresses a kind spells in its sub or
// its string value (a user reference's target, a memory region's start),
// and which keys' own addresses are addresses at all (a memory-map edit's
// address 0 isn't). The image backend's (src/backend) knows its kinds.
class Relocator {
 public:
  virtual ~Relocator() = default;
  // Whether the key's address is a program address (moves with a Shift).
  virtual bool moves(const FactKey &key) const = 0;
  // The key's sub or string value with its addresses shifted; nullopt:
  // unchanged.
  virtual std::optional<std::string> sub(const FactKey &key, const Shift &shift) const = 0;
  virtual std::optional<std::string> value(const FactKey &key, std::string_view value, const Shift &shift) const = 0;
  // An op's meta (Op::meta, the client's own) with its addresses shifted.
  virtual std::optional<std::string> meta(const FactKey &, std::string_view, const Shift &) const { return std::nullopt; }
};

// A key and value as read with `shift` (stored -> moved), or, with the
// inverse, as stored. A null relocator moves addresses of every kind but
// TypeDef and Rebase, and no subs or string values.
FactKey shifted_key(const Relocator *r, const FactKey &k, const Shift &shift);
FactValue shifted_value(const Relocator *r, const FactKey &stored, const FactValue &v, const Shift &shift);

struct FactDbOptions {
  std::unique_ptr<Storage> storage;  // null: in-memory
  std::size_t memo_budget = SIZE_MAX;
  // Whether memos evicted over the budget go to the storage, to be read
  // back, or are dropped and recomputed when read again (an in-memory
  // store saves little by keeping their encodings).
  bool keep_evicted = true;
  std::function<std::int64_t()> clock;  // ns since epoch; default system clock
  // This replica's id (docs/collab.md). 0: the one the storage recorded,
  // else a new random id, recorded in the storage.
  ReplicaId replica = 0;
  // How keys move with a rebase (above); null: the default rules.
  std::shared_ptr<const Relocator> relocator;
  // Called inside a commit whose ops change a space's Shift (a rebase, its
  // undo or redo, a revert, a merged peer's op), before anything is
  // written: the client stages what follows the new base in the same
  // transaction (a program's bytes and inputs). It must not stage ops.
  std::function<void(FactDbTransaction &, SpaceId, const Shift &before, const Shift &after)> on_rebase;
  // Likewise for a program's language (FactKind::Language: a change, its
  // undo or redo, a revert, a peer's op): `before` and `after` are the
  // effective values ("" for the imported language). It must not stage ops.
  std::function<void(FactDbTransaction &, SpaceId, const std::string &before, const std::string &after)> on_language;
};

// What Transaction::merge did with a batch of another replica's ops.
struct MergeResult {
  std::size_t staged = 0;     // staged in this transaction (including ones that were waiting)
  std::size_t duplicate = 0;  // already held, staged or waiting
  std::size_t waiting = 0;    // held back until the ops they follow arrive (in total, after the batch)
  std::size_t rejected = 0;   // malformed: no id, or a reference that doesn't match
  std::vector<std::string> errors;
};

// The single writer of a FactDb (FactDb::Transaction).
class FactDbTransaction {
 public:
  // `meta` is stored with the op, uninterpreted (see Op::meta).
  Seq assert_fact(const Provenance &who, FactKey key, FactValue value, Seq depends_on = 0,
                  std::string meta = {});
  // Undo: retracting a retraction is redo.
  Seq retract(const Provenance &who, Seq target, std::string meta = {});
  // Retracts every op `whose` made (at or after `since`), including their
  // retractions, so the result is as if they had never acted. Returns the
  // new retraction seqs.
  std::vector<Seq> revert(const Provenance &who, const Provenance &whose, Seq since = 0);
  // Stages ops made by other replicas (Op::id set; references by id).
  // Merging is idempotent, commutative and associative: an op already
  // held is skipped, and one whose replica's previous op, target or
  // dependency is missing waits in the FactDb until it arrives, so any
  // delivery order ends in the same log contents. Staged ops get local
  // seqs; `on_stage` sees each just before it is staged (the backend
  // rewrites the op's meta there).
  MergeResult merge(std::span<const Op> ops, const std::function<void(Op &)> &on_stage = {});
  void write_bytes(Address at, std::string_view bytes);
  // Stages a client-defined input (registered with engine().add_input<Q>()).
  // Such inputs are not persisted; a client sets them again after reopening.
  template <class Q>
  void set(const typename Q::Key &key, typename Q::Value value) {
    writer().template set<Q>(key, std::move(value));
    inputs_ = true;
  }
  // The revision commit() publishes if it appends ops: the one ops staged
  // now are committed at.
  Revision next_revision() const;

  // Durably appends everything staged, publishes a revision and ends the
  // transaction, releasing the writer; further calls throw. `changed`
  // receives the keys whose effective value changed, sorted.
  Revision commit(std::vector<FactKey> *changed = nullptr);

 private:
  friend class FactDb;
  explicit FactDbTransaction(FactDb &db);
  Seq next_seq() const;
  std::string &page(PageKey k);
  Engine::Writer &writer();
  // This transaction's stamp (one for all its local ops) and next id.
  Stamp stamp();
  OpId next_local_id();
  bool known(const OpId &id) const;
  std::optional<Seq> seq_of(const OpId &id) const;
  void stage(Op op);

  FactDb *db_;
  std::optional<Engine::Writer> writer_;
  std::vector<Op> ops_;
  Stamp stamp_ = 0;
  std::map<ReplicaId, std::uint64_t> staged_vv_;
  std::unordered_map<OpId, Seq, OpIdHash> staged_ids_;
  std::map<PageKey, std::string> pages_;
  bool inputs_ = false;
};

class FactDb {
 public:
  explicit FactDb(FactDbOptions opt = {});
  ~FactDb();
  FactDb(const FactDb &) = delete;
  FactDb &operator=(const FactDb &) = delete;

  Engine &engine() { return *engine_; }
  const AssertionLog &log() const { return log_; }

  // --- Replication (docs/collab.md) ---
  ReplicaId replica() const { return replica_; }
  VersionVector version_vector() const { return log_.version_vector(); }
  // Ops a replica holding `theirs` lacks, in a causal order.
  std::vector<Op> ops_since(const VersionVector &theirs, std::size_t limit = SIZE_MAX) const {
    return log_.ops_since(theirs, limit);
  }
  // Other replicas' ops received but held back until the ops they follow
  // (their replica's previous op, their target, their dependency) arrive.
  // Not persisted: anti-entropy delivers them again.
  std::size_t waiting() const;
  Storage &storage() { return *storage_; }
  Snapshot snapshot() { return engine_->snapshot(); }

  using Transaction = FactDbTransaction;
  Transaction begin();

  // The space's Shift at head (identity when not rebased), and the rules
  // that move keys with it.
  Shift shift(SpaceId space) const;
  const Relocator *relocator() const { return opt_.relocator.get(); }


 private:
  // Stages AssertedKeys/AssertedBuckets changes for keys whose effective
  // value became (or stopped being) non-empty.
  class IndexUpdate;
  std::int64_t now() const;
  // A stamp above every stamp seen and at least the physical clock.
  Stamp tick();
  void observe(Stamp s);

  friend class FactDbTransaction;
  // Keys of `space` re-indexed for a new Shift (a rebase, in a commit).
  void reindex(Engine::Writer &w, IndexUpdate &index, SpaceId space, const Shift &before, const Shift &after,
               std::vector<FactKey> *changed);
  FactKey moved(const FactKey &stored) const;
  FactValue moved_value(const FactKey &stored, const FactValue &v) const;

  FactDbOptions opt_;
  std::unique_ptr<Storage> storage_;
  // The storage is our own in-memory one: nothing can reopen it, so the
  // bytes, which the engine holds as inputs anyway, aren't copied into it.
  bool private_storage_ = false;
  AssertionLog log_;
  std::unique_ptr<Engine> engine_;
  ReplicaId replica_ = 0;
  std::atomic<Stamp> clock_{0};
  // Ops waiting for an op they follow, and who waits on what.
  mutable std::mutex waiting_mu_;
  std::map<OpId, Op> waiting_;
  // Each rebased space's Shift at head (the live Rebase values).
  mutable std::mutex shift_mu_;
  std::map<SpaceId, Shift> shifts_;
  std::unordered_map<OpId, std::vector<OpId>, OpIdHash> waiting_on_;
};

}  // namespace revkit::facts
