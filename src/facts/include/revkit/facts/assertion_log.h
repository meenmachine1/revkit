// The append-only assertion log. Ops are never removed; undo appends a
// Retract, and an op's liveness is derived:
//
//   retracted(x) = some live Retract targets x
//   live(retract r) = !retracted(r)
//   live(assert a)  = !retracted(a) && (a.depends_on == 0 || live(a.depends_on))
//
// Liveness is maintained incrementally on append, so reading the effective
// value of a key costs one scan over that key's assertions.
//
// Replication (docs/collab.md): every op carries a global OpId and a stamp,
// and everything the log reports is a function of the *set* of ops it
// holds, never of their local order: the winner is the live assertion with
// the highest (rank, stamp, replica, counter), blame and history are
// ordered the same way, and liveness only follows retraction targets and
// dependencies. Two replicas holding the same ops therefore agree on every
// effective value, blame and history, whatever order the ops arrived in.
// Seq is an op's local position, which is a causal order (a retraction or
// dependent always comes after its target).
#pragma once

#include "revkit/facts/fact.h"

#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <span>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace revkit::facts {

enum class OpStatus : std::uint8_t {
  Effective,       // live and the winner for its key
  Shadowed,        // live but outranked by another assertion
  Retracted,       // a live retraction targets it
  DependencyDead,  // not retracted, but what it depends on is not live
};

std::string_view to_string(OpStatus s);

struct BlameEntry {
  Op op;
  OpStatus status;
  std::vector<Seq> retracted_by;  // live retractions targeting op
};

struct Blame {
  FactKey key;
  FactValue value;                 // effective value, monostate if none
  std::optional<Op> winner;
  std::vector<BlameEntry> candidates;  // every assertion on key, best first
  // Live candidates of the winner's rank made concurrently with it: not
  // in the winner's supersedes chain, so its author never saw them win.
  // The losing side of a concurrent edit, best first.
  std::vector<Seq> concurrent;
};

class AssertionLog {
 public:
  AssertionLog() = default;
  AssertionLog(const AssertionLog &) = delete;
  AssertionLog &operator=(const AssertionLog &) = delete;

  Seq next_seq() const;
  std::size_t size() const;

  // The replica that ops appended without an id are attributed to (ops
  // written before replication existed), with counters following its own.
  void set_local_replica(ReplicaId r);

  // Throws std::invalid_argument if op could not be appended after the log
  // plus `pending` (ops staged ahead of it, in seq order).
  void validate(const Op &op, std::span<const Op> pending = {}) const;

  // Appends ops (consecutive seqs starting at next_seq()). Returns the keys
  // whose effective value may have changed, sorted. An op with an id must
  // be the next counter of its replica; one without gets the local
  // replica's next id and a stamp above every stamp in the log.
  std::vector<FactKey> append(std::span<const Op> ops);

  // --- Replication ---
  // Highest counter held per replica.
  VersionVector version_vector() const;
  // The highest stamp in the log (0 if empty).
  Stamp max_stamp() const;
  // Local seq of an op by id, if held.
  std::optional<Seq> find(const OpId &id) const;
  // Whether the op is held: counters are contiguous, so this is a lookup
  // in the version vector.
  bool has(const OpId &id) const;
  // Ops the holder of `theirs` lacks, in seq order (a causal order), at
  // most `limit` of them.
  std::vector<Op> ops_since(const VersionVector &theirs, std::size_t limit = SIZE_MAX) const;
  // The live assertion on key of exactly this rank that wins among them
  // (what a new assertion of that rank supersedes).
  std::optional<OpId> top_of_rank(const FactKey &key, int rank) const;

  FactValue effective(const FactKey &key) const;
  std::optional<Op> winner(const FactKey &key) const;
  Blame blame(const FactKey &key) const;
  // Assertions on key plus every retraction (transitively) touching them,
  // in seq order.
  std::vector<Op> history(const FactKey &key) const;

  // The same, as the log stood after its first `upto` ops: what a reader
  // pinned to an earlier revision sees. upto >= size() is the current state.
  Blame blame(const FactKey &key, Seq upto) const;
  std::vector<Op> history(const FactKey &key, Seq upto) const;
  // An op's status as of `upto` (which must be >= seq). A retraction is
  // Effective while live, else Retracted.
  OpStatus status(Seq seq, Seq upto) const;
  // Live retractions targeting seq, as of `upto`.
  std::vector<Seq> retracted_by(Seq seq, Seq upto) const;

  std::optional<Op> op(Seq seq) const;
  bool live(Seq seq) const;
  bool retracted(Seq seq) const;

  // Ops whose provenance matches `who`: same kind and id, and same version
  // unless who.version is empty (so "agent:model" covers every version).
  std::vector<Seq> ops_by(const Provenance &who, Seq since = 0) const;
  // Every key that has ever been asserted, in no particular order.
  std::vector<FactKey> keys() const;

 private:
  using KeyId = std::uint32_t;
  using ProvId = std::uint32_t;

  struct Record {
    OpId id;
    Stamp stamp = 0;
    OpId supersedes;
    std::int64_t time_ns = 0;
    Seq target = 0;      // Retract only
    Seq depends_on = 0;  // Assert only
    FactValue value;
    std::string meta;
    KeyId key = 0;
    ProvId prov = 0;
    std::uint32_t live_retractions = 0;
    OpKind kind = OpKind::Assert;
    bool live = false;
  };
  class AsOf;

  const Record *find(Seq seq) const;
  // Precedence of an assertion against others on its key: higher wins.
  std::tuple<int, Stamp, ReplicaId, std::uint64_t> precedence(const Record &r) const {
    return {rank(provs_[r.prov].kind), r.stamp, r.id.replica, r.id.counter};
  }
  static OpOrder order(const Record &r) { return {r.stamp, r.id.replica, r.id.counter}; }
  void sort_by_order(std::vector<Seq> &seqs) const;
  Record &at(Seq seq) { return records_[seq - 1]; }
  Op to_op(Seq seq) const;
  KeyId intern(const FactKey &key);
  ProvId intern(const Provenance &prov);
  bool compute_live(const Record &r) const;
  void propagate(Seq changed, std::vector<KeyId> &affected);
  std::optional<Seq> winner_seq(KeyId key) const;
  static bool matches(const Provenance &who, const Provenance &p);
  static void validate_against(const Op &op, Seq next, const AssertionLog *log,
                               std::span<const Op> pending);

  mutable std::shared_mutex mu_;
  std::vector<Record> records_;  // records_[seq - 1]
  std::vector<FactKey> keys_;
  std::unordered_map<FactKey, KeyId, FactKeyHash> key_ids_;
  std::vector<std::vector<Seq>> asserts_by_key_;
  std::vector<Provenance> provs_;
  std::vector<std::vector<Seq>> ops_by_prov_;
  std::unordered_map<Seq, std::vector<Seq>> retractions_of_;
  std::unordered_map<Seq, std::vector<Seq>> dependents_of_;
  // Replication: id -> seq, the version vector, and legacy attribution.
  std::unordered_map<OpId, Seq, OpIdHash> by_id_;
  VersionVector vv_;
  std::map<ReplicaId, std::vector<Seq>> by_replica_;  // seqs in counter order
  ReplicaId local_ = 0;
  Stamp max_stamp_ = 0;
};

}  // namespace revkit::facts
