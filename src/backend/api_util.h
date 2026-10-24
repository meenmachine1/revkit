// Helpers shared by the image backend's RPC handlers: provenance ranks and
// filters, fact origins, page tokens, pagination and per-subscriber event
// filtering.
#pragma once

#include "revkit/v1/assertion.pb.h"
#include "revkit/v1/common.pb.h"
#include "revkit/v1/subscription.pb.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace revkit::backend {

namespace pb = ::revkit::v1;

int Rank(pb::ProvenanceKind kind);
const char *CommentSub(pb::CommentKind kind);
bool MatchesProvenance(const pb::ProvenanceFilter &f, const pb::Provenance &p);

pb::FactOrigin Derived(const std::string &rule, std::uint64_t revision, float confidence = 1.0f);

// How far to trust a value, from who said it (FactOrigin.tier, api_minor 97;
// docs/api.md "Result evidence"): an assertion's provenance, or the rule and
// confidence of a derivation.
pb::SourceTier TierOf(const pb::Provenance &p);
pb::SourceTier TierOf(const std::string &rule, float confidence);
// Sets origin.tier from what the origin holds.
void SetTier(pb::FactOrigin &origin);
pb::FactOrigin Asserted(const pb::Assertion &a);

// Opaque page tokens "<revision>:<offset>", pinning later pages to the
// first page's revision.
std::string PageToken(std::uint64_t revision, std::size_t offset);
bool ParsePageToken(const std::string &token, std::uint64_t &revision, std::size_t &offset);

// Calls emit(i) for one page of `count` items and fills `info`.
template <class Fn>
void Paginate(std::size_t count, std::size_t offset, std::uint32_t page_size, std::uint32_t def, std::uint32_t max,
              std::uint64_t revision, pb::PageInfo *info, Fn &&emit) {
  std::size_t size = page_size == 0 ? def : std::min(page_size, max);
  std::size_t end = std::min(count, offset + size);
  for (std::size_t i = offset; i < end; ++i) emit(i);
  info->set_total_count(static_cast<std::int64_t>(count));
  if (end < count) info->set_next_page_token(PageToken(revision, end));
}

// A revision event as one subscriber sees it (program filter, assertions
// only on request).
pb::RevisionEvent FilterEvent(const pb::RevisionEvent &e, const std::set<std::string> &programs,
                              bool include_assertions);

}  // namespace revkit::backend
