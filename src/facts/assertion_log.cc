#include "revkit/facts/assertion_log.h"

#include <algorithm>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <tuple>

namespace revkit::facts {

std::string_view to_string(OpStatus s) {
  switch (s) {
    case OpStatus::Effective: return "effective";
    case OpStatus::Shadowed: return "shadowed";
    case OpStatus::Retracted: return "retracted";
    case OpStatus::DependencyDead: return "dependency-dead";
  }
  return "?";
}

Seq AssertionLog::next_seq() const {
  std::shared_lock lock(mu_);
  return records_.size() + 1;
}

std::size_t AssertionLog::size() const {
  std::shared_lock lock(mu_);
  return records_.size();
}

void AssertionLog::set_local_replica(ReplicaId r) {
  std::unique_lock lock(mu_);
  local_ = r;
}

const AssertionLog::Record *AssertionLog::find(Seq seq) const {
  if (seq == 0 || seq > records_.size()) return nullptr;
  return &records_[seq - 1];
}

void AssertionLog::validate(const Op &op, std::span<const Op> pending) const {
  std::shared_lock lock(mu_);
  validate_against(op, records_.size() + 1, this, pending);
}

// `log` must be locked by the caller.
void AssertionLog::validate_against(const Op &op, Seq next, const AssertionLog *log,
                                    std::span<const Op> pending) {
  if (op.seq != next + pending.size())
    throw std::invalid_argument("op seq " + std::to_string(op.seq) + " out of order");
  // Kind and key of an earlier op, whether committed or pending.
  auto earlier = [&](Seq s) -> std::optional<std::pair<OpKind, FactKey>> {
    if (s == 0 || s >= op.seq) return std::nullopt;
    if (s < next) {
      const Record *r = log->find(s);
      if (!r) return std::nullopt;
      return std::pair{r->kind, log->keys_[r->key]};
    }
    const Op &p = pending[s - next];
    return std::pair{p.kind, p.key};
  };
  if (op.kind == OpKind::Retract) {
    auto t = earlier(op.target);
    if (!t) throw std::invalid_argument("retraction of unknown op " + std::to_string(op.target));
    if (t->second != op.key) throw std::invalid_argument("retraction key does not match target");
    if (op.depends_on != 0) throw std::invalid_argument("retractions cannot depend on ops");
  } else if (op.kind == OpKind::Assert) {
    if (op.target != 0) throw std::invalid_argument("assertion with a retraction target");
    if (op.depends_on != 0) {
      auto d = earlier(op.depends_on);
      if (!d || d->first != OpKind::Assert)
        throw std::invalid_argument("assertion depends on unknown or non-assert op");
    }
  } else {
    throw std::invalid_argument("bad op kind");
  }
}

AssertionLog::KeyId AssertionLog::intern(const FactKey &key) {
  auto [it, inserted] = key_ids_.try_emplace(key, static_cast<KeyId>(keys_.size()));
  if (inserted) {
    keys_.push_back(key);
    asserts_by_key_.emplace_back();
  }
  return it->second;
}

AssertionLog::ProvId AssertionLog::intern(const Provenance &prov) {
  for (ProvId i = 0; i < provs_.size(); ++i)
    if (provs_[i] == prov) return i;
  provs_.push_back(prov);
  ops_by_prov_.emplace_back();
  return static_cast<ProvId>(provs_.size() - 1);
}

bool AssertionLog::compute_live(const Record &r) const {
  if (r.live_retractions > 0) return false;
  if (r.kind == OpKind::Assert && r.depends_on != 0) return records_[r.depends_on - 1].live;
  return true;
}

// Re-derives liveness starting at `changed`, following retraction targets
// and dependents. Iterative so long undo/redo chains cannot overflow the stack.
void AssertionLog::propagate(Seq changed, std::vector<KeyId> &affected) {
  std::vector<Seq> work{changed};
  while (!work.empty()) {
    Seq s = work.back();
    work.pop_back();
    Record &r = at(s);
    bool now = compute_live(r);
    if (now == r.live) continue;
    r.live = now;
    if (r.kind == OpKind::Assert) {
      affected.push_back(r.key);
      if (auto it = dependents_of_.find(s); it != dependents_of_.end())
        work.insert(work.end(), it->second.begin(), it->second.end());
    } else {
      Record &t = at(r.target);
      if (now ? t.live_retractions++ == 0 : --t.live_retractions == 0) work.push_back(r.target);
    }
  }
}

std::vector<FactKey> AssertionLog::append(std::span<const Op> ops) {
  std::unique_lock lock(mu_);
  const Seq next = records_.size() + 1;
  for (std::size_t i = 0; i < ops.size(); ++i)
    validate_against(ops[i], next, this, ops.first(i));
  // Ids: each must be the next counter of its replica; ops without one are
  // the local replica's (written before replication existed).
  std::vector<OpId> ids(ops.size());
  {
    std::map<ReplicaId, std::uint64_t> counters;
    auto next_counter = [&](ReplicaId r) -> std::uint64_t & {
      auto [it, fresh] = counters.try_emplace(r, 0);
      if (fresh) it->second = vv_.contains(r) ? vv_.at(r) : 0;
      return it->second;
    };
    for (std::size_t i = 0; i < ops.size(); ++i) {
      const Op &op = ops[i];
      OpId id = op.id ? op.id : OpId{local_, next_counter(local_) + 1};
      std::uint64_t &c = next_counter(id.replica);
      if (id.counter != c + 1)
        throw std::invalid_argument("op " + id.str() + " is not the next op of its replica (have " +
                                    std::to_string(c) + ")");
      c = id.counter;
      ids[i] = id;
      // References by id, when given, must name the ops the seqs do.
      auto ref = [&](Seq s, const OpId &want) {
        if (!want) return;
        const OpId got = s < next ? records_[s - 1].id : ids[s - next];
        if (got != want) throw std::invalid_argument("op " + id.str() + " references " + want.str() + " by id but " + got.str() + " by seq");
      };
      if (op.kind == OpKind::Retract) ref(op.target, op.target_id);
      else if (op.depends_on) ref(op.depends_on, op.depends_on_id);
    }
  }

  std::vector<KeyId> affected;
  for (std::size_t i = 0; i < ops.size(); ++i) {
    const Op &op = ops[i];
    Record r;
    r.id = ids[i];
    r.stamp = op.id ? op.stamp : max_stamp_ + 1;
    r.supersedes = op.supersedes;
    r.time_ns = op.time_ns;
    r.target = op.target;
    r.depends_on = op.depends_on;
    r.value = op.value;
    r.meta = op.meta;
    r.key = intern(op.key);
    r.prov = intern(op.prov);
    r.kind = op.kind;
    max_stamp_ = std::max(max_stamp_, r.stamp);
    by_id_.emplace(r.id, op.seq);
    vv_[r.id.replica] = r.id.counter;
    by_replica_[r.id.replica].push_back(op.seq);
    records_.push_back(std::move(r));
    ops_by_prov_[records_.back().prov].push_back(op.seq);
    Record &rec = records_.back();
    if (op.kind == OpKind::Assert) {
      asserts_by_key_[rec.key].push_back(op.seq);
      if (op.depends_on) dependents_of_[op.depends_on].push_back(op.seq);
      rec.live = compute_live(rec);
      affected.push_back(rec.key);
    } else {
      retractions_of_[op.target].push_back(op.seq);
      rec.live = true;
      if (at(op.target).live_retractions++ == 0) propagate(op.target, affected);
    }
  }

  std::sort(affected.begin(), affected.end());
  affected.erase(std::unique(affected.begin(), affected.end()), affected.end());
  std::vector<FactKey> out;
  out.reserve(affected.size());
  for (KeyId k : affected) out.push_back(keys_[k]);
  std::sort(out.begin(), out.end());
  return out;
}

std::optional<Seq> AssertionLog::winner_seq(KeyId key) const {
  std::optional<Seq> best;
  for (Seq s : asserts_by_key_[key]) {
    const Record &r = records_[s - 1];
    if (!r.live) continue;
    if (!best || precedence(r) > precedence(records_[*best - 1])) best = s;
  }
  return best;
}

void AssertionLog::sort_by_order(std::vector<Seq> &seqs) const {
  std::sort(seqs.begin(), seqs.end(), [&](Seq a, Seq b) { return order(records_[a - 1]) < order(records_[b - 1]); });
}

Op AssertionLog::to_op(Seq seq) const {
  const Record &r = records_[seq - 1];
  Op op;
  op.seq = seq;
  op.time_ns = r.time_ns;
  op.prov = provs_[r.prov];
  op.kind = r.kind;
  op.key = keys_[r.key];
  op.value = r.value;
  op.target = r.target;
  op.depends_on = r.depends_on;
  op.meta = r.meta;
  op.id = r.id;
  op.stamp = r.stamp;
  if (r.target) op.target_id = records_[r.target - 1].id;
  if (r.depends_on) op.depends_on_id = records_[r.depends_on - 1].id;
  op.supersedes = r.supersedes;
  return op;
}

// Liveness as the log stood after its first `upto` ops, for readers pinned
// to an earlier revision. The current state is kept incrementally in the
// records; an earlier one is re-derived on demand from the same rules,
// memoized per instance. The caller holds mu_.
class AssertionLog::AsOf {
 public:
  AsOf(const AssertionLog &log, Seq upto)
      : log_(log), upto_(std::min<Seq>(upto, log.records_.size())), current_(upto_ == log.records_.size()) {}

  Seq upto() const { return upto_; }

  bool live(Seq s) {
    if (current_) return log_.records_[s - 1].live;
    // Iterative: undo/redo chains can be long. Prerequisites point either
    // at later retractions or at earlier dependencies, so there are no
    // cycles.
    std::vector<Seq> stack{s};
    while (!stack.empty()) {
      const Seq x = stack.back();
      if (memo_.contains(x)) {
        stack.pop_back();
        continue;
      }
      const Record &r = log_.records_[x - 1];
      const std::vector<Seq> *rs = retractions(x);
      bool ready = true;
      if (rs)
        for (Seq t : *rs)
          if (t <= upto_ && !memo_.contains(t)) {
            stack.push_back(t);
            ready = false;
          }
      if (r.kind == OpKind::Assert && r.depends_on && !memo_.contains(r.depends_on)) {
        stack.push_back(r.depends_on);
        ready = false;
      }
      if (!ready) continue;
      bool retracted = false;
      if (rs)
        for (Seq t : *rs) retracted = retracted || (t <= upto_ && memo_.at(t));
      memo_[x] = !retracted && (r.kind != OpKind::Assert || !r.depends_on || memo_.at(r.depends_on));
      stack.pop_back();
    }
    return memo_.at(s);
  }

  // Ordered by OpOrder, so every replica lists them alike.
  std::vector<Seq> retracted_by(Seq s) {
    std::vector<Seq> out;
    if (const std::vector<Seq> *rs = retractions(s))
      for (Seq t : *rs)
        if (t <= upto_ && live(t)) out.push_back(t);
    log_.sort_by_order(out);
    return out;
  }

  std::optional<Seq> winner(KeyId key) {
    if (current_) return log_.winner_seq(key);
    std::optional<Seq> best;
    for (Seq s : log_.asserts_by_key_[key]) {
      if (s > upto_ || !live(s)) continue;
      if (!best || log_.precedence(log_.records_[s - 1]) > log_.precedence(log_.records_[*best - 1])) best = s;
    }
    return best;
  }

  OpStatus status(Seq s) {
    const Record &r = log_.records_[s - 1];
    if (r.kind == OpKind::Retract) return live(s) ? OpStatus::Effective : OpStatus::Retracted;
    if (!retracted_by(s).empty()) return OpStatus::Retracted;
    if (!live(s)) return OpStatus::DependencyDead;
    return winner(r.key) == s ? OpStatus::Effective : OpStatus::Shadowed;
  }

 private:
  const std::vector<Seq> *retractions(Seq s) const {
    auto it = log_.retractions_of_.find(s);
    return it == log_.retractions_of_.end() ? nullptr : &it->second;
  }

  const AssertionLog &log_;
  const Seq upto_;
  const bool current_;
  std::unordered_map<Seq, bool> memo_;
};

FactValue AssertionLog::effective(const FactKey &key) const {
  std::shared_lock lock(mu_);
  auto it = key_ids_.find(key);
  if (it == key_ids_.end()) return {};
  auto w = winner_seq(it->second);
  return w ? records_[*w - 1].value : FactValue{};
}

std::optional<Op> AssertionLog::winner(const FactKey &key) const {
  std::shared_lock lock(mu_);
  auto it = key_ids_.find(key);
  if (it == key_ids_.end()) return std::nullopt;
  auto w = winner_seq(it->second);
  if (!w) return std::nullopt;
  return to_op(*w);
}

Blame AssertionLog::blame(const FactKey &key) const { return blame(key, ~Seq{0}); }

Blame AssertionLog::blame(const FactKey &key, Seq upto) const {
  std::shared_lock lock(mu_);
  AsOf at(*this, upto);
  Blame b;
  b.key = key;
  auto it = key_ids_.find(key);
  if (it == key_ids_.end()) return b;
  auto w = at.winner(it->second);
  if (w) {
    b.winner = to_op(*w);
    b.value = b.winner->value;
  }
  for (Seq s : asserts_by_key_[it->second]) {
    if (s > at.upto()) break;
    BlameEntry e{to_op(s), OpStatus::Shadowed, at.retracted_by(s)};
    if (w && s == *w) e.status = OpStatus::Effective;
    else if (!e.retracted_by.empty()) e.status = OpStatus::Retracted;
    else if (!at.live(s)) e.status = OpStatus::DependencyDead;
    b.candidates.push_back(std::move(e));
  }
  auto order = [&](const BlameEntry &e) {
    bool live = e.status == OpStatus::Effective || e.status == OpStatus::Shadowed;
    return std::tuple{live, live ? rank(e.op.prov.kind) : 0, e.op.order()};
  };
  std::sort(b.candidates.begin(), b.candidates.end(),
            [&](const BlameEntry &x, const BlameEntry &y) { return order(x) > order(y); });
  if (w) {
    // What the winner's author saw win before it, transitively.
    std::set<OpId> seen;
    for (OpId a = records_[*w - 1].supersedes; a && seen.insert(a).second;) {
      auto it = by_id_.find(a);
      if (it == by_id_.end()) break;
      a = records_[it->second - 1].supersedes;
    }
    const int top = rank(b.winner->prov.kind);
    for (const BlameEntry &e : b.candidates)
      if (e.status == OpStatus::Shadowed && rank(e.op.prov.kind) == top && !seen.contains(e.op.id))
        b.concurrent.push_back(e.op.seq);
  }
  return b;
}

std::vector<Op> AssertionLog::history(const FactKey &key) const { return history(key, ~Seq{0}); }

std::vector<Op> AssertionLog::history(const FactKey &key, Seq upto) const {
  std::shared_lock lock(mu_);
  auto it = key_ids_.find(key);
  if (it == key_ids_.end()) return {};
  std::vector<Seq> seqs;
  for (Seq s : asserts_by_key_[it->second])
    if (s <= upto) seqs.push_back(s);
  for (std::size_t i = 0; i < seqs.size(); ++i)
    if (auto rit = retractions_of_.find(seqs[i]); rit != retractions_of_.end())
      for (Seq r : rit->second)
        if (r <= upto) seqs.push_back(r);
  // By OpOrder, which every replica agrees on (and which, being a hybrid
  // logical clock, never puts a retraction before what it retracts).
  sort_by_order(seqs);
  std::vector<Op> out;
  out.reserve(seqs.size());
  for (Seq s : seqs) out.push_back(to_op(s));
  return out;
}

OpStatus AssertionLog::status(Seq seq, Seq upto) const {
  std::shared_lock lock(mu_);
  if (!find(seq) || seq > upto) throw std::invalid_argument("status of op " + std::to_string(seq) + " past upto");
  AsOf at(*this, upto);
  return at.status(seq);
}

std::vector<Seq> AssertionLog::retracted_by(Seq seq, Seq upto) const {
  std::shared_lock lock(mu_);
  if (!find(seq)) return {};
  AsOf at(*this, upto);
  return at.retracted_by(seq);
}

std::optional<Op> AssertionLog::op(Seq seq) const {
  std::shared_lock lock(mu_);
  if (!find(seq)) return std::nullopt;
  return to_op(seq);
}

bool AssertionLog::live(Seq seq) const {
  std::shared_lock lock(mu_);
  const Record *r = find(seq);
  return r && r->live;
}

bool AssertionLog::retracted(Seq seq) const {
  std::shared_lock lock(mu_);
  const Record *r = find(seq);
  return r && r->live_retractions > 0;
}

bool AssertionLog::matches(const Provenance &who, const Provenance &p) {
  return who.kind == p.kind && who.id == p.id && (who.version.empty() || who.version == p.version);
}

std::vector<Seq> AssertionLog::ops_by(const Provenance &who, Seq since) const {
  std::shared_lock lock(mu_);
  std::vector<Seq> out;
  for (ProvId i = 0; i < provs_.size(); ++i) {
    if (!matches(who, provs_[i])) continue;
    for (Seq s : ops_by_prov_[i])
      if (s >= since) out.push_back(s);
  }
  std::sort(out.begin(), out.end());
  return out;
}

std::vector<FactKey> AssertionLog::keys() const {
  std::shared_lock lock(mu_);
  return keys_;
}

VersionVector AssertionLog::version_vector() const {
  std::shared_lock lock(mu_);
  return vv_;
}

Stamp AssertionLog::max_stamp() const {
  std::shared_lock lock(mu_);
  return max_stamp_;
}

std::optional<Seq> AssertionLog::find(const OpId &id) const {
  std::shared_lock lock(mu_);
  auto it = by_id_.find(id);
  if (it == by_id_.end()) return std::nullopt;
  return it->second;
}

bool AssertionLog::has(const OpId &id) const {
  std::shared_lock lock(mu_);
  auto it = vv_.find(id.replica);
  return id && it != vv_.end() && id.counter <= it->second;
}

std::vector<Op> AssertionLog::ops_since(const VersionVector &theirs, std::size_t limit) const {
  std::shared_lock lock(mu_);
  std::vector<Seq> seqs;
  for (const auto &[replica, seqs_of] : by_replica_) {
    auto it = theirs.find(replica);
    const std::uint64_t have = it == theirs.end() ? 0 : it->second;
    // Counters are dense from 1, so the replica's ops they lack start at
    // index `have`.
    for (std::size_t i = have; i < seqs_of.size(); ++i) seqs.push_back(seqs_of[i]);
  }
  std::sort(seqs.begin(), seqs.end());
  if (seqs.size() > limit) seqs.resize(limit);
  std::vector<Op> out;
  out.reserve(seqs.size());
  for (Seq s : seqs) out.push_back(to_op(s));
  return out;
}

std::optional<OpId> AssertionLog::top_of_rank(const FactKey &key, int want) const {
  std::shared_lock lock(mu_);
  auto it = key_ids_.find(key);
  if (it == key_ids_.end()) return std::nullopt;
  const Record *best = nullptr;
  for (Seq s : asserts_by_key_[it->second]) {
    const Record &r = records_[s - 1];
    if (!r.live || rank(provs_[r.prov].kind) != want) continue;
    if (!best || precedence(r) > precedence(*best)) best = &r;
  }
  if (!best) return std::nullopt;
  return best->id;
}

}  // namespace revkit::facts
