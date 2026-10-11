#include "revkit/facts/fact.h"

#include <cstdio>

namespace revkit::facts {

std::string_view to_string(ProvenanceKind kind) {
  switch (kind) {
    case ProvenanceKind::User: return "user";
    case ProvenanceKind::Import: return "import";
    case ProvenanceKind::Agent: return "agent";
    case ProvenanceKind::Analysis: return "analysis";
    case ProvenanceKind::Migration: return "migration";
    case ProvenanceKind::Plugin: return "plugin";
    case ProvenanceKind::Script: return "script";
  }
  return "?";
}

int rank(ProvenanceKind kind) {
  switch (kind) {
    case ProvenanceKind::User: return 4;
    case ProvenanceKind::Import:
    case ProvenanceKind::Migration: return 3;
    case ProvenanceKind::Agent:
    case ProvenanceKind::Plugin:
    case ProvenanceKind::Script: return 2;
    case ProvenanceKind::Analysis: return 1;
  }
  return 0;
}

std::optional<Provenance> Provenance::parse(std::string_view text) {
  std::string_view kind = text, rest;
  if (auto colon = text.find(':'); colon != std::string_view::npos) {
    kind = text.substr(0, colon);
    rest = text.substr(colon + 1);
  }
  Provenance p;
  if (kind == "user") p.kind = ProvenanceKind::User;
  else if (kind == "import") p.kind = ProvenanceKind::Import;
  else if (kind == "agent") p.kind = ProvenanceKind::Agent;
  else if (kind == "analysis") p.kind = ProvenanceKind::Analysis;
  else if (kind == "migration") p.kind = ProvenanceKind::Migration;
  else if (kind == "plugin") p.kind = ProvenanceKind::Plugin;
  else if (kind == "script") p.kind = ProvenanceKind::Script;
  else return std::nullopt;
  if (auto at = rest.find('@'); at != std::string_view::npos) {
    p.version = rest.substr(at + 1);
    rest = rest.substr(0, at);
  }
  p.id = rest;
  return p;
}

std::string Provenance::str() const {
  std::string s(to_string(kind));
  if (!id.empty()) s += ":" + id;
  if (!version.empty()) s += "@" + version;
  return s;
}

void Provenance::encode(Encoder &e) const {
  facts::encode(e, kind);
  e.bytes(id);
  e.bytes(version);
}

Provenance Provenance::decode(Decoder &d) {
  Provenance p;
  p.kind = facts::decode<ProvenanceKind>(d);
  if (p.kind > ProvenanceKind::Script) throw DecodeError("bad provenance kind");
  p.id = d.bytes();
  p.version = d.bytes();
  return p;
}

std::string_view to_string(FactKind kind) {
  switch (kind) {
    case FactKind::Name: return "name";
    case FactKind::Type: return "type";
    case FactKind::Comment: return "comment";
    case FactKind::FunctionBounds: return "function";
    case FactKind::FlowOverride: return "flow-override";
    case FactKind::Note: return "note";
    case FactKind::TypeDef: return "typedef";
    case FactKind::Match: return "match";
    case FactKind::Patch: return "patch";
    case FactKind::MemoryRegion: return "memory-region";
    case FactKind::CodeUnit: return "code-unit";
    case FactKind::Mutability: return "mutability";
    case FactKind::Equate: return "equate";
    case FactKind::Reference: return "reference";
    case FactKind::Rebase: return "rebase";
    case FactKind::CallSignature: return "call-signature";
    case FactKind::NoReturn: return "no-return";
    case FactKind::Language: return "language";
  }
  return "?";
}

void FactKey::encode(Encoder &e) const {
  facts::encode(e, kind);
  facts::encode(e, addr);
  e.bytes(sub);
}

FactKey FactKey::decode(Decoder &d) {
  FactKey k;
  k.kind = facts::decode<FactKind>(d);
  k.addr = facts::decode<Address>(d);
  k.sub = d.bytes();
  return k;
}

std::size_t FactKeyHash::operator()(const FactKey &k) const {
  std::size_t h = std::hash<std::uint64_t>{}(k.addr.offset);
  h ^= (std::size_t{k.addr.space} << 20) ^ (static_cast<std::size_t>(k.kind) << 40);
  if (!k.sub.empty()) h ^= std::hash<std::string>{}(k.sub) * 0x9e3779b97f4a7c15ULL;
  return h;
}

std::string OpId::str() const {
  char buf[40];
  std::snprintf(buf, sizeof buf, "%016llx.%llu", static_cast<unsigned long long>(replica),
                static_cast<unsigned long long>(counter));
  return buf;
}

std::optional<OpId> OpId::parse(std::string_view text) {
  auto dot = text.find('.');
  if (dot != 16 || dot + 1 >= text.size()) return std::nullopt;
  OpId id;
  for (char c : text.substr(0, dot)) {
    int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
    if (v < 0) return std::nullopt;
    id.replica = id.replica << 4 | static_cast<unsigned>(v);
  }
  for (char c : text.substr(dot + 1)) {
    if (c < '0' || c > '9' || id.counter > (~std::uint64_t{0} - 9) / 10) return std::nullopt;
    id.counter = id.counter * 10 + static_cast<unsigned>(c - '0');
  }
  if (!id) return std::nullopt;
  return id;
}

namespace {
// Set on the encoded kind when meta follows, so records written before ops
// had meta still decode.
constexpr std::uint64_t kHasMeta = 0x80;
// Set when the replication fields (id, stamp, references by id) follow, at
// the end; records written before replication decode without them.
constexpr std::uint64_t kHasId = 0x40;
}  // namespace

void Op::encode(Encoder &e) const {
  e.varint(seq);
  e.svarint(time_ns);
  prov.encode(e);
  e.varint(static_cast<std::uint64_t>(kind) | (meta.empty() ? 0 : kHasMeta) | (id ? kHasId : 0));
  key.encode(e);
  if (kind == OpKind::Assert) {
    facts::encode(e, value);
    e.varint(depends_on);
  } else {
    e.varint(target);
  }
  if (!meta.empty()) e.bytes(meta);
  if (id) {
    id.encode(e);
    e.varint(stamp);
    if (kind == OpKind::Assert) {
      depends_on_id.encode(e);
      supersedes.encode(e);
    } else {
      target_id.encode(e);
    }
  }
}

Op Op::decode(Decoder &d) {
  Op op;
  op.seq = d.varint();
  op.time_ns = d.svarint();
  op.prov = Provenance::decode(d);
  const std::uint64_t kind = d.varint();
  const std::uint64_t base = kind & ~(kHasMeta | kHasId);
  if (base > static_cast<std::uint64_t>(OpKind::Retract)) throw DecodeError("bad op kind");
  op.kind = static_cast<OpKind>(base);
  op.key = FactKey::decode(d);
  if (op.kind == OpKind::Assert) {
    op.value = facts::decode<FactValue>(d);
    op.depends_on = d.varint();
  } else {
    op.target = d.varint();
  }
  if (kind & kHasMeta) op.meta = d.bytes();
  if (kind & kHasId) {
    op.id = OpId::decode(d);
    if (!op.id) throw DecodeError("op id with counter 0");
    op.stamp = d.varint();
    if (op.kind == OpKind::Assert) {
      op.depends_on_id = OpId::decode(d);
      op.supersedes = OpId::decode(d);
    } else {
      op.target_id = OpId::decode(d);
    }
  }
  return op;
}

}  // namespace revkit::facts
