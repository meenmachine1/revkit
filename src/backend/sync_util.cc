#include "sync_util.h"

#include <google/protobuf/util/time_util.h>

#include <algorithm>

namespace revkit::backend {

using google::protobuf::util::TimeUtil;

pb::OpId ToPbId(const facts::OpId &id) {
  pb::OpId out;
  out.set_replica(id.replica);
  out.set_counter(id.counter);
  return out;
}

pb::VersionVector ToPbVector(const facts::VersionVector &vv) {
  pb::VersionVector out;
  for (const auto &[replica, counter] : vv) {
    auto *e = out.add_entries();
    e->set_replica(replica);
    e->set_counter(counter);
  }
  return out;
}

facts::VersionVector FromPbVector(const pb::VersionVector &vv) {
  facts::VersionVector out;
  for (const auto &e : vv.entries())
    if (e.counter()) out[e.replica()] = std::max(out[e.replica()], e.counter());
  return out;
}

bool Covers(const facts::VersionVector &vv, const facts::OpId &id) {
  auto it = vv.find(id.replica);
  return it != vv.end() && id.counter <= it->second;
}

void Join(facts::VersionVector &into, const facts::VersionVector &other) {
  for (const auto &[replica, counter] : other) into[replica] = std::max(into[replica], counter);
}

void AddOp(const facts::Op &op, google::protobuf::RepeatedPtrField<pb::ReplicatedOp> *out) {
  auto *r = out->Add();
  *r->mutable_id() = ToPbId(op.id);
  r->set_encoded(facts::encode_to_string(op));
}

std::optional<facts::Op> DecodeOp(const pb::ReplicatedOp &in, std::string &error) {
  try {
    facts::Op op = facts::decode_from_string<facts::Op>(in.encoded());
    if (!op.id || op.id.replica != in.id().replica() || op.id.counter != in.id().counter()) {
      error = "op id does not match its encoding";
      return std::nullopt;
    }
    return op;
  } catch (const facts::DecodeError &e) {
    error = std::string("undecodable op: ") + e.what();
    return std::nullopt;
  }
}

void PresenceTable::Purge(Clock::time_point now) {
  const auto t = TimeUtil::TimeTToTimestamp(Clock::to_time_t(now));
  std::erase_if(entries_, [&](const auto &e) { return e.second.expires_at() < t; });
}

bool PresenceTable::Apply(const pb::Presence &p, Clock::time_point now) {
  Purge(now);
  auto it = entries_.find(p.client_id());
  if (it != entries_.end() && it->second.sequence() >= p.sequence()) return false;
  entries_[p.client_id()] = p;
  return true;
}

const pb::Presence *PresenceTable::Find(const std::string &client_id) const {
  auto it = entries_.find(client_id);
  return it == entries_.end() ? nullptr : &it->second;
}

std::vector<pb::Presence> PresenceTable::Live(Clock::time_point now, const std::string &program_id) const {
  const auto t = TimeUtil::TimeTToTimestamp(Clock::to_time_t(now));
  std::vector<pb::Presence> out;
  for (const auto &[id, p] : entries_)
    if (!p.left() && p.expires_at() >= t && (program_id.empty() || p.program_id() == program_id)) out.push_back(p);
  return out;
}

}  // namespace revkit::backend
