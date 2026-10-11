// Replication helpers for the image backend (docs/collab.md): the sync
// wire form of fact-store ops and version vectors, and the ephemeral
// presence table.
#pragma once

#include "revkit/facts/fact.h"
#include "revkit/v1/assertion.pb.h"
#include "revkit/v1/presence.pb.h"
#include "revkit/v1/sync.pb.h"

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace revkit::backend {

namespace pb = ::revkit::v1;

// The op encoding peers exchange (facts::Op's codec). Bumped when it
// changes incompatibly; peers with another format refuse to sync.
inline constexpr std::uint32_t kSyncFormat = 1;

pb::OpId ToPbId(const facts::OpId &id);
pb::VersionVector ToPbVector(const facts::VersionVector &vv);
facts::VersionVector FromPbVector(const pb::VersionVector &vv);

// Whether vv covers id (the holder of vv holds the op).
bool Covers(const facts::VersionVector &vv, const facts::OpId &id);
// Pointwise maximum.
void Join(facts::VersionVector &into, const facts::VersionVector &other);

void AddOp(const facts::Op &op, google::protobuf::RepeatedPtrField<pb::ReplicatedOp> *out);
// Decodes one op, or returns nullopt and sets `error`.
std::optional<facts::Op> DecodeOp(const pb::ReplicatedOp &in, std::string &error);

// Who is where, newest entry per client. Entries lapse at expires_at;
// one that left is kept (hidden) until then, so a stale update relayed
// late cannot bring it back.
class PresenceTable {
 public:
  using Clock = std::chrono::system_clock;

  // Stores `p` if it is newer than the client's entry (a higher
  // sequence). Returns whether it was stored.
  bool Apply(const pb::Presence &p, Clock::time_point now);
  // The stored entry for a client, expired or not.
  const pb::Presence *Find(const std::string &client_id) const;
  // Live entries (not left, not expired), optionally in one program.
  std::vector<pb::Presence> Live(Clock::time_point now, const std::string &program_id = {}) const;

 private:
  void Purge(Clock::time_point now);
  std::map<std::string, pb::Presence> entries_;
};

}  // namespace revkit::backend
