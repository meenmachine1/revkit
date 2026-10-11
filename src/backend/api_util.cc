#include "api_util.h"

#include <cstdio>

namespace revkit::backend {

int Rank(pb::ProvenanceKind kind) {
  switch (kind) {
    case pb::PROVENANCE_KIND_USER: return 4;
    case pb::PROVENANCE_KIND_IMPORT:
    case pb::PROVENANCE_KIND_MIGRATION: return 3;
    case pb::PROVENANCE_KIND_AGENT:
    case pb::PROVENANCE_KIND_PLUGIN:
    case pb::PROVENANCE_KIND_SCRIPT: return 2;
    case pb::PROVENANCE_KIND_ANALYSIS: return 1;
    default: return 0;
  }
}

const char *CommentSub(pb::CommentKind kind) {
  switch (kind) {
    case pb::COMMENT_KIND_EOL: return "eol";
    case pb::COMMENT_KIND_PRE: return "pre";
    case pb::COMMENT_KIND_POST: return "post";
    case pb::COMMENT_KIND_PLATE: return "plate";
    case pb::COMMENT_KIND_REPEATABLE: return "repeatable";
    case pb::COMMENT_KIND_DECOMPILER: return "decompiler";
    default: return "";
  }
}

bool MatchesProvenance(const pb::ProvenanceFilter &f, const pb::Provenance &p) {
  if (f.kind() != pb::PROVENANCE_KIND_UNSPECIFIED && f.kind() != p.kind()) return false;
  if (!f.id().empty() && f.id() != p.id()) return false;
  if (!f.version().empty() && f.version() != p.version()) return false;
  if (!f.session().empty() && f.session() != p.session()) return false;
  if (!f.on_behalf_of().empty() && f.on_behalf_of() != p.on_behalf_of()) return false;
  return true;
}

pb::FactOrigin Derived(const std::string &rule, std::uint64_t revision, float confidence) {
  pb::FactOrigin o;
  o.mutable_derived()->set_rule(rule);
  o.mutable_derived()->set_confidence(confidence);
  o.mutable_derived()->set_computed_at_revision(revision);
  return o;
}

pb::FactOrigin Asserted(const pb::Assertion &a) {
  pb::FactOrigin o;
  o.mutable_asserted()->set_seq(a.seq());
  *o.mutable_asserted()->mutable_provenance() = a.provenance();
  return o;
}

std::string PageToken(std::uint64_t revision, std::size_t offset) {
  return std::to_string(revision) + ":" + std::to_string(offset);
}

bool ParsePageToken(const std::string &token, std::uint64_t &revision, std::size_t &offset) {
  auto colon = token.find(':');
  if (colon == std::string::npos) return false;
  try {
    revision = std::stoull(token.substr(0, colon));
    offset = std::stoull(token.substr(colon + 1));
  } catch (...) {
    return false;
  }
  return true;
}

pb::RevisionEvent FilterEvent(const pb::RevisionEvent &e, const std::set<std::string> &programs,
                              bool include_assertions) {
  pb::RevisionEvent out = e;
  if (!include_assertions) out.clear_assertions();
  if (programs.empty()) return out;
  // The project's own records (folders: program_id empty) reach everyone.
  auto keep = [&](const std::string &program) { return program.empty() || programs.count(program) > 0; };
  out.clear_changed_keys();
  for (const auto &k : e.changed_keys())
    if (keep(k.program_id())) *out.add_changed_keys() = k;
  out.clear_invalidated();
  for (const auto &q : e.invalidated())
    if (keep(q.program_id())) *out.add_invalidated() = q;
  out.clear_invalidate_all_programs();
  for (const auto &p : e.invalidate_all_programs())
    if (keep(p)) out.add_invalidate_all_programs(p);
  out.clear_assertions();
  if (include_assertions)
    for (const auto &a : e.assertions())
      if (keep(a.key().program_id())) *out.add_assertions() = a;
  return out;
}

}  // namespace revkit::backend
