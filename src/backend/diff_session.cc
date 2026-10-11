#include "diff_session.h"

#include "revkit/facts/fact_db.h"

#include <algorithm>
#include <cstdio>

namespace revkit::backend {

void DiffSessionRecord::encode(facts::Encoder &e) const {
  e.bytes(id);
  e.bytes(name);
  e.bytes(program_a);
  e.bytes(program_b);
  facts::encode(e, similarity);
  e.svarint(created_at);
  e.bytes(created_by);
}

DiffSessionRecord DiffSessionRecord::decode(facts::Decoder &d) {
  DiffSessionRecord r;
  r.id = std::string(d.bytes());
  r.name = std::string(d.bytes());
  r.program_a = std::string(d.bytes());
  r.program_b = std::string(d.bytes());
  r.similarity = facts::decode<std::vector<std::string>>(d);
  r.created_at = d.svarint();
  r.created_by = std::string(d.bytes());
  return r;
}

std::uint64_t DiffSessionAddress(std::string_view id) {
  std::uint64_t h = 1469598103934665603ULL;
  for (unsigned char c : id) h = (h ^ c) * 1099511628211ULL;
  return h & 0xffffffffffffULL;
}

std::string NewDiffSessionId(std::string_view program_a, std::string_view program_b, std::uint64_t replica,
                             std::uint64_t counter, std::int64_t time_ns) {
  diff::Hasher h;
  h.str(program_a).str(program_b).u64(replica).u64(counter).u64(static_cast<std::uint64_t>(time_ns));
  char buf[24];
  std::snprintf(buf, sizeof buf, "d%012llx", static_cast<unsigned long long>(h.done() & 0xffffffffffffULL));
  return buf;
}

q::DiffSessions::Value q::DiffSessions::compute(facts::QueryContext &ctx, const Key &space) {
  Value out;
  for (const facts::FactKey &k :
       facts::asserted_keys(ctx, facts::FactKind::Note, {space, 0}, {space, ~std::uint64_t{0}})) {
    if (k.sub != kDiffSessionSub) continue;
    auto v = ctx.get<facts::AssertedFact>(k);
    const auto *s = std::get_if<std::string>(v.get());
    if (!s) continue;
    try {
      out.push_back(facts::decode_from_string<DiffSessionRecord>(*s));
    } catch (const facts::DecodeError &) {
    }
  }
  std::sort(out.begin(), out.end(), [](const DiffSessionRecord &x, const DiffSessionRecord &y) {
    return x.created_at != y.created_at ? x.created_at > y.created_at : x.id < y.id;
  });
  return out;
}

void RegisterDiffQueries(facts::Engine &engine) {
  diff::register_queries(engine);
  engine.add_query<q::DiffSessions>();
}

pb::DiffTier ToApi(diff::Tier t) { return static_cast<pb::DiffTier>(static_cast<int>(t)); }
diff::Tier FromApi(pb::DiffTier t) { return static_cast<diff::Tier>(static_cast<int>(t)); }
pb::DiffRelation ToApi(diff::Relation r) { return static_cast<pb::DiffRelation>(static_cast<int>(r)); }
pb::DiffMatchStatus ToApi(diff::MatchState s) { return static_cast<pb::DiffMatchStatus>(static_cast<int>(s)); }
pb::DiffUnmatchedReason ToApi(diff::UnmatchedReason r) {
  return static_cast<pb::DiffUnmatchedReason>(static_cast<int>(r));
}

std::string EvidenceText(const diff::Evidence &e, const std::string &parent_a, const std::string &parent_b) {
  std::string what;
  switch (e.tier) {
    case diff::Tier::accepted: return "a Match assertion";
    case diff::Tier::name: what = "the same name"; break;
    case diff::Tier::bytes: what = "the same bytes (address fields masked)"; break;
    case diff::Tier::pcode: what = "the same p-code"; break;
    case diff::Tier::shape_refs: what = "the same control-flow shape, opcodes and references"; break;
    case diff::Tier::shape: what = "the same control-flow shape"; break;
    case diff::Tier::refs: what = "the same references"; break;
    case diff::Tier::call_order: what = "the same call site"; break;
    case diff::Tier::lone: what = "the only unmatched function on each side"; break;
    case diff::Tier::similarity: what = "a similarity tier"; break;
    case diff::Tier::neighbour: what = "the most similar pair, both ways"; break;
    case diff::Tier::none: return {};
  }
  const std::string group = e.group > 1 ? std::to_string(e.group) + " " : "";
  const std::string parents = parent_a + " / " + parent_b;
  switch (e.relation) {
    case diff::Relation::global: return what + ", unique over both programs";
    case diff::Relation::residue: return what + ", unique among the unmatched functions";
    case diff::Relation::callee: return what + " among the " + group + "callees of " + parents;
    case diff::Relation::caller: return what + " among the " + group + "callers of " + parents;
    case diff::Relation::string: return what + " among the " + group + "functions reading one string";
    case diff::Relation::data: return what + " among the " + group + "functions touching a global of " + parents;
    case diff::Relation::seed: return what;
    case diff::Relation::similar: return what + " over the residue";
    case diff::Relation::address:
      return what + ", a twin of other identical code, paired by its place between matched functions";
  }
  return what;
}

pb::CommentKind CommentKindOf(std::string_view sub) {
  if (sub == "eol") return pb::COMMENT_KIND_EOL;
  if (sub == "pre") return pb::COMMENT_KIND_PRE;
  if (sub == "post") return pb::COMMENT_KIND_POST;
  if (sub == "plate") return pb::COMMENT_KIND_PLATE;
  if (sub == "repeatable") return pb::COMMENT_KIND_REPEATABLE;
  if (sub == "decompiler") return pb::COMMENT_KIND_DECOMPILER;
  return pb::COMMENT_KIND_UNSPECIFIED;
}

}  // namespace revkit::backend
