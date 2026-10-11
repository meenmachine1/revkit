// The assertion vocabulary: who asserted something (Provenance), what it is
// about (FactKey), what they said (FactValue), and the log operation that
// records it (Op).
#pragma once

#include "revkit/facts/address.h"
#include "revkit/facts/codec.h"

#include <compare>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace revkit::facts {

// Ordered by precedence when assertions conflict; Migration sits with Import
// because it replays facts that were already accepted (see docs/facts.md).
// Plugin (a command plugin acting on its own, docs/plugins.md) ranks with
// Agent; it comes last so the persisted values of the others don't change.
enum class ProvenanceKind : std::uint8_t { User, Import, Agent, Analysis, Migration, Plugin, Script };

std::string_view to_string(ProvenanceKind kind);
// Higher wins: user > import = migration > agent = plugin = script > analysis-default.
int rank(ProvenanceKind kind);

struct Provenance {
  ProvenanceKind kind = ProvenanceKind::User;
  std::string id;       // "alice", "dwarf", "model"
  std::string version;  // optional; "agent:model@version"

  static Provenance user(std::string id) { return {ProvenanceKind::User, std::move(id), {}}; }
  static Provenance import(std::string id) { return {ProvenanceKind::Import, std::move(id), {}}; }
  static Provenance agent(std::string id, std::string version = {}) {
    return {ProvenanceKind::Agent, std::move(id), std::move(version)};
  }
  static Provenance analysis(std::string id) {
    return {ProvenanceKind::Analysis, std::move(id), {}};
  }
  static Provenance migration(std::string id = {}) {
    return {ProvenanceKind::Migration, std::move(id), {}};
  }
  // Accepts "user:alice", "import:dwarf", "agent:model@1.2", "migration",
  // "plugin:rename-regex@1.0.0".
  static std::optional<Provenance> parse(std::string_view text);
  std::string str() const;

  void encode(Encoder &e) const;
  static Provenance decode(Decoder &d);

  friend auto operator<=>(const Provenance &, const Provenance &) = default;
};

enum class FactKind : std::uint16_t {
  Name = 1,
  Type = 2,            // type applied at an address (data or function)
  Comment = 3,         // sub = "eol", "pre", "post", "plate"
  FunctionBounds = 4,  // value is the function body AddressSet
  FlowOverride = 5,    // value is an integer override code
  Note = 6,            // free-form annotation, sub distinguishes notes
  TypeDef = 7,         // data type definition; sub = type name, addr unused
  // A version-tracking match (docs/diff.md): addr = the function's entry in
  // program B, sub = the diff session (and, for a rejected pair,
  // "<session>/reject/<entry in A>"); value = the pair as text.
  Match = 8,
  // A byte patch (docs/patching.md): addr = its first byte in the program's
  // space, sub = ""; value = the new bytes as a string, at most
  // kMaxPatchBytes long (longer edits are several keys). Overlapping
  // patches compose by precedence, then recency (AssertedOrder).
  Patch = 9,
  // A memory-map edit (docs/memory-map.md): addr = 0 in the program's code
  // space, sub = "region:<id>" (a region the user added) or "block:<hex
  // start>" (an edit to one of the image's own blocks); value = the
  // encoded region or edit (analysis/memory.h), "" when removed.
  MemoryRegion = 10,
  // What bytes are, from the listing (docs/listing-edit.md): addr = the
  // first byte, sub = "clear:<hex length>", "code" or "data"; value = the
  // encoded analysis::UnitMark (analysis/units.h). Overlapping keys compose
  // by precedence, then recency (AssertedOrder).
  CodeUnit = 11,
  // Constant or volatile memory by range: addr = the first byte, sub = the
  // length in hex; value = the analysis::MutabilityMark (units.h), ordered
  // like CodeUnit.
  Mutability = 12,
  // How a scalar operand shows (docs/api.md, "Equates and user
  // references"): addr = the instruction, sub = "<operand>:<hex value>"
  // or "h<hex hash>:<hex value>"; value = the display as text
  // (analysis::OperandDisplay), "" for the disassembler's.
  Equate = 13,
  // A user reference: addr = the instruction it is from, sub =
  // "<operand>:<hex to>" or "i:<hex to>"; value = its type and flags as
  // text (analysis::UserRef), or "remove".
  Reference = 14,
  // A program's image base moved (docs/memory-map.md, "Rebase"): addr = 0
  // in the program's space, sub = ""; value = the Shift as text
  // ("<delta hex>/<bits>": the new base minus the import base, and the
  // default space's address size). The store presents the space's keys
  // moved by it (FactDb, Relocator); "" (or nothing live) is the import base.
  Rebase = 15,
  // A call-site signature override (docs/api.md, "Call-site signature
  // overrides"): addr = the call instruction, sub = ""; value = "h:<hash>"
  // of the function type the decompiler takes for that call, "" when
  // removed.
  CallSignature = 16,
  // Whether a function returns, as the user says (docs/api.md, "No
  // return"): addr = its entry, sub = ""; value 1 (doesn't return) or 0.
  NoReturn = 17,
  // The program's language, as the user set it after import (docs/api.md,
  // "Changing a program's language"): addr = 0 in the program's space, sub
  // = ""; value = "<language id>|<compiler spec id>", "" (or nothing live)
  // for the language it was imported with. The store calls on_language in
  // the commit that changes it, and the program reloads in that language.
  Language = 18,
};

// The longest Patch value: one 256-byte span of the key index
// (kSpanShift), so the patches overlapping a range are found in the spans
// it covers and the one before.
inline constexpr std::size_t kMaxPatchBytes = 256;

std::string_view to_string(FactKind kind);

struct FactKey {
  FactKind kind = FactKind::Name;
  Address addr;
  std::string sub;

  static FactKey name(Address a) { return {FactKind::Name, a, {}}; }
  static FactKey type(Address a) { return {FactKind::Type, a, {}}; }
  static FactKey comment(Address a, std::string which = "eol") {
    return {FactKind::Comment, a, std::move(which)};
  }
  static FactKey function(Address entry) { return {FactKind::FunctionBounds, entry, {}}; }
  static FactKey flow_override(Address a) { return {FactKind::FlowOverride, a, {}}; }
  static FactKey note(Address a, std::string tag = {}) { return {FactKind::Note, a, std::move(tag)}; }
  static FactKey type_def(std::string type_name) { return {FactKind::TypeDef, {}, std::move(type_name)}; }
  static FactKey patch(Address a) { return {FactKind::Patch, a, {}}; }

  void encode(Encoder &e) const;
  static FactKey decode(Decoder &d);

  friend auto operator<=>(const FactKey &, const FactKey &) = default;
};

struct FactKeyHash {
  std::size_t operator()(const FactKey &k) const;
};

// monostate means "no value": what a key reads as when nothing live asserts it.
using FactValue = std::variant<std::monostate, std::int64_t, std::string, Address, AddressSet>;

using Seq = std::uint64_t;  // log sequence numbers start at 1; 0 means none

// Replication (docs/collab.md). A replica is one copy of a project's log
// (one FactDb). Every op has a global identity, the replica that created it
// and that replica's counter (dense from 1, so a version vector summarises
// which ops a replica has), and a hybrid logical clock stamp. Seq stays
// the op's local position: its order of arrival in this replica's log.
using ReplicaId = std::uint64_t;

struct OpId {
  ReplicaId replica = 0;
  std::uint64_t counter = 0;  // 0: no id

  explicit operator bool() const { return counter != 0; }
  // "<replica as 16 hex digits>.<counter>"; parse() accepts the same.
  std::string str() const;
  static std::optional<OpId> parse(std::string_view text);

  void encode(Encoder &e) const {
    e.u64be(replica);
    e.varint(counter);
  }
  static OpId decode(Decoder &d) {
    OpId id;
    id.replica = d.u64be();
    id.counter = d.varint();
    return id;
  }
  friend auto operator<=>(const OpId &, const OpId &) = default;
};

struct OpIdHash {
  std::size_t operator()(const OpId &id) const {
    return std::hash<std::uint64_t>{}(id.replica * 0x9e3779b97f4a7c15ULL ^ id.counter);
  }
};

// Hybrid logical clock: physical milliseconds in the high bits, a logical
// counter in the low kStampLogicalBits. A replica stamps each transaction
// above every stamp it has seen, so an op always sorts after the ops its
// author could see; concurrent ops sort by (roughly) wall time.
using Stamp = std::uint64_t;
inline constexpr unsigned kStampLogicalBits = 16;

// What "more recent" means between two ops, on every replica: stamp, then
// replica id, then counter. All ops of one transaction share a stamp.
struct OpOrder {
  Stamp stamp = 0;
  ReplicaId replica = 0;
  std::uint64_t counter = 0;
  friend auto operator<=>(const OpOrder &, const OpOrder &) = default;
};

// Per replica, the highest counter held (counters are held contiguously).
using VersionVector = std::map<ReplicaId, std::uint64_t>;

enum class OpKind : std::uint8_t { Assert, Retract };

struct Op {
  Seq seq = 0;
  std::int64_t time_ns = 0;  // wall clock, informational; ordering uses seq
  Provenance prov;
  OpKind kind = OpKind::Assert;
  FactKey key;           // Assert: the fact; Retract: the target's key
  FactValue value;       // Assert only
  Seq target = 0;        // Retract only: the op being retracted
  Seq depends_on = 0;    // Assert only: live only while this op is live
  // Opaque to the store and persisted with the op: what a client needs to
  // render it again (for the API, its full provenance and request body).
  std::string meta;
  // Global identity and order (see OpId, Stamp). The *_id fields name
  // target and depends_on across replicas; a replica receiving an op
  // translates them to its own seqs.
  OpId id;
  Stamp stamp = 0;
  OpId target_id;
  OpId depends_on_id;
  // Assert only: the live assertion of the same rank on key that the
  // author's replica had as winner when this was made (none: default).
  // Blame uses the chain to tell sequential edits from concurrent ones.
  OpId supersedes;

  OpOrder order() const { return {stamp, id.replica, id.counter}; }

  void encode(Encoder &e) const;
  static Op decode(Decoder &d);

  friend bool operator==(const Op &, const Op &) = default;
};

}  // namespace revkit::facts
