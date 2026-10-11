// DiffService's model on the image backend (docs/diff.md): sessions as
// project records, the queries that list them, and conversions between
// revkit::diff's values and the API's.
//
// A session is a NOTE assertion in the project's space (beside the program
// records), sub "diff-session", at an address derived from its id; its
// value is the encoded DiffSessionRecord. Its matches are the derived
// query diff.matches (src/diff), keyed by the record's programs and
// options; its decisions are Match assertions in program B's space.
#pragma once

#include "revkit/diff/match.h"
#include "revkit/facts/engine.h"
#include "revkit/v1/assertion.pb.h"
#include "revkit/v1/diff.pb.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::backend {

namespace pb = ::revkit::v1;

inline constexpr std::string_view kDiffSessionSub = "diff-session";

struct DiffSessionRecord {
  std::string id;
  std::string name;
  std::string program_a, program_b;
  std::vector<std::string> similarity;  // DiffOptions.similarity_tiers
  std::int64_t created_at = 0;          // unix seconds
  std::string created_by;               // provenance, "user:alice"

  diff::SessionKey key() const { return {id, program_a, program_b, similarity}; }
  void encode(facts::Encoder &e) const;
  static DiffSessionRecord decode(facts::Decoder &d);
  friend bool operator==(const DiffSessionRecord &, const DiffSessionRecord &) = default;
};

// Where a session's record lives in the project space: a 48-bit hash of its id.
std::uint64_t DiffSessionAddress(std::string_view id);
// A fresh session id, "d" and 12 hex digits, from what makes it unique.
std::string NewDiffSessionId(std::string_view program_a, std::string_view program_b, std::uint64_t replica,
                             std::uint64_t counter, std::int64_t time_ns);

namespace q {

// Every session of a project, newest first: the NOTE records in its space.
struct DiffSessions {
  static constexpr std::string_view name = "diff.sessions";
  static constexpr std::uint32_t version = 1;
  using Key = facts::SpaceId;  // the project space
  using Value = std::vector<DiffSessionRecord>;
  static Value compute(facts::QueryContext &ctx, const Key &space);
};

}  // namespace q

void RegisterDiffQueries(facts::Engine &engine);

// --- conversions -------------------------------------------------------------

pb::DiffTier ToApi(diff::Tier t);
diff::Tier FromApi(pb::DiffTier t);
pb::DiffRelation ToApi(diff::Relation r);
pb::DiffMatchStatus ToApi(diff::MatchState s);
pb::DiffUnmatchedReason ToApi(diff::UnmatchedReason r);

// An evidence's words: "unique masked bytes over both programs", "same
// p-code among the 4 callees of <a> / <b>".
std::string EvidenceText(const diff::Evidence &e, const std::string &parent_a, const std::string &parent_b);

// The comment kind a COMMENT key's sub names, UNSPECIFIED for an unknown one.
pb::CommentKind CommentKindOf(std::string_view sub);

}  // namespace revkit::backend
