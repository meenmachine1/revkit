// What bytes are, as the listing's edits say (docs/listing-edit.md): Clear,
// Disassemble here and Define data, and constant or volatile ranges, as
// queries over the assertions.
//
// Edits are assertions in the program's code space (ProgramInfo::space):
//
//   CODE_UNIT@start  sub "clear:<hex length>"  undefined bytes
//                    sub "code"                code starts here (UnitMark::isa,
//                                              ::function)
//                    sub "data"                a typed item (UnitMark::data)
//   MUTABILITY@start sub "<hex length>"        constant, volatile, normal or
//                                              as the memory map says
//
// Both kinds are ordered (facts::AssertedOrder): where edits overlap, each
// byte goes to the live edit of the highest precedence, then the most
// recent. A data item is alive only while it owns every one of its bytes;
// a later edit over part of it kills it, and its bytes are then cleared,
// as Ghidra clears conflicting data.
//
//   analysis.units           the painted map (every live mark, the pieces
//                            of the space each owns)
//   analysis.units.code      what discovery needs from it: the code marks
//                            (flow keys, functions) and the bytes nothing
//                            may start in, within code (Functions reads it)
//   analysis.units.bucket    the pieces overlapping one 64 KiB bucket of the
//                            key index (Flow reads the ones it decodes in)
//   analysis.mutability      the painted MUTABILITY map
//
// How they steer analysis:
//   - discovery: nothing starts in cleared or data bytes (no seed, call
//     target, search find or asserted entry), and flows stop where they
//     reach them; a code mark is an entry: code that isn't a function (an
//     orphan, as the firmware search's code finds are) unless its function
//     flag says so or something calls it. The flow from a code mark is
//     forced: it decodes outside executable memory and through cleared
//     bytes older than the mark, and stops at live data and newer marks;
//   - data analysis lays the live data items down first (kDataUser) and
//     never defines data in other marked bytes.
#pragma once

#include "revkit/analysis/analysis.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::analysis {

// ---- assertions ----

enum class UnitKind : std::uint8_t { clear = 1, code = 2, data = 3 };
// Which instruction set a code mark decodes in (ARM interworking).
enum class Isa : std::uint8_t { inherit = 0, arm = 1, thumb = 2 };
enum class StringKind : std::uint8_t { none = 0, utf8 = 1, utf16 = 2, utf32 = 3 };
enum class StringLayout : std::uint8_t { none = 0, terminated = 1, fixed = 2, pascal = 3, pascal16 = 4 };
// How a value's bytes read, for the listing.
enum class ValueFormat : std::uint8_t {
  hex,           // undefined bytes
  signed_int,
  unsigned_int,
  floating,
  character,     // char, wchar
  boolean,
  pointer,
  enumeration,   // an integer shown with the enum's type
  aggregate,     // a struct, union or array: its fields show it
  string,        // a char array (fields: its text)
};

// One field of a data item's element, depth first: a struct's fields and,
// under a field that is a struct or an array of at most kMaxShownElements,
// its own (depth 2, ...), up to kMaxFieldDepth.
struct DataField {
  std::uint64_t offset = 0;  // from the element's start
  std::uint64_t size = 0;
  std::string name;  // the field's own name ("magic"), or "[3]" for an array element
  std::string type;  // its C spelling
  ValueFormat format = ValueFormat::hex;
  std::uint32_t depth = 1;

  void encode(facts::Encoder &e) const;
  static DataField decode(facts::Decoder &d);
  friend bool operator==(const DataField &, const DataField &) = default;
};

inline constexpr std::uint32_t kMaxFieldDepth = 4;
inline constexpr std::uint64_t kMaxShownElements = 64;

// A typed data item, with what the listing and analysis need of its type
// (types by hash never change, so this is taken once, when it is defined).
struct DataSpec {
  std::string type;       // the element type's hash
  std::string type_name;  // its C spelling ("uint32_t", "struct hdr")
  std::string item_type;  // the whole item's type hash (the array, a string's char[n]); = type for one element
  std::string item_name;  // its C spelling ("char[6]", "struct hdr[4]")
  std::uint64_t element = 0;  // the element's size
  std::uint64_t count = 0;    // elements of an array; 0: one, not an array
  StringKind string = StringKind::none;
  StringLayout layout = StringLayout::none;
  ValueFormat format = ValueFormat::hex;  // of the element
  bool collapsed = false;                 // one row, not a row per field or element
  std::vector<DataField> fields;          // the element's (structs, unions), depth first
  std::vector<std::uint64_t> pointers;    // offsets of the element's pointers (any depth), sorted
  std::uint8_t pointer_size = 0;          // their size

  void encode(facts::Encoder &e) const;
  static DataSpec decode(facts::Decoder &d);
  friend bool operator==(const DataSpec &, const DataSpec &) = default;
};

struct UnitMark {
  UnitKind kind = UnitKind::clear;
  std::uint64_t length = 1;  // bytes covered (code: 1)
  Isa isa = Isa::inherit;    // code
  bool function = false;     // code: also a function
  DataSpec data;             // data

  void encode(facts::Encoder &e) const;
  static UnitMark decode(facts::Decoder &d);
  friend bool operator==(const UnitMark &, const UnitMark &) = default;
};

inline constexpr std::string_view kUnitClearPrefix = "clear:";
inline constexpr std::string_view kUnitCode = "code";
inline constexpr std::string_view kUnitData = "data";
// The CODE_UNIT sub of a mark ("clear:<hex length>", "code", "data").
std::string unit_sub(const UnitMark &m);
std::string hex_length(std::uint64_t n);  // "1f"

// MUTABILITY values: the API's Mutability numbers.
enum class MutabilityKind : std::uint8_t { as_map = 1, normal = 2, constant = 3, is_volatile = 4 };

struct MutabilityMark {
  std::uint64_t length = 1;
  MutabilityKind kind = MutabilityKind::as_map;

  void encode(facts::Encoder &e) const;
  static MutabilityMark decode(facts::Decoder &d);
  friend bool operator==(const MutabilityMark &, const MutabilityMark &) = default;
};

// ---- the painted maps ----

// Part of the space one mark owns.
struct UnitPiece {
  std::uint64_t first = 0, last = 0;
  std::uint32_t mark = 0;  // index into the map's marks

  friend bool operator==(const UnitPiece &, const UnitPiece &) = default;
};

struct UnitMap {
  struct Mark {
    std::uint64_t start = 0;
    std::string sub;
    std::string order;  // facts::AssertedOrder
    UnitMark mark;
    bool alive = true;      // data: owns all its bytes (others: always)
    std::uint64_t key = 0;  // code: its flow key (Thumb tagged, ProgramInfo::code_key)

    friend bool operator==(const Mark &, const Mark &) = default;
  };
  std::vector<Mark> marks;        // live, by order (lowest first)
  std::vector<UnitPiece> pieces;  // sorted, disjoint

  const UnitPiece *at(std::uint64_t a) const;
  // The mark owning `a`, or null.
  const Mark *owner(std::uint64_t a) const;
  // Pieces overlapping [first, last].
  std::vector<UnitPiece> overlapping(std::uint64_t first, std::uint64_t last) const;
  void encode(facts::Encoder &e) const;
  static UnitMap decode(facts::Decoder &d);
  friend bool operator==(const UnitMap &, const UnitMap &) = default;
};

struct Units {
  static constexpr std::string_view name = "analysis.units";
  static constexpr std::uint32_t version = 1;
  using Key = ProgramKey;
  using Value = UnitMap;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return k.id; }
};

// What a flow sees of the map at an address: who owns it.
enum class UnitState : std::uint8_t {
  code,     // a code mark's first byte
  cleared,  // a Clear, or a dead data item's byte
  data,     // a live data item's byte
};

struct UnitSpan {
  std::uint64_t first = 0, last = 0;
  UnitState state = UnitState::cleared;
  std::string order;
  std::uint64_t key = 0;  // code: the flow key

  void encode(facts::Encoder &e) const;
  static UnitSpan decode(facts::Decoder &d);
  friend bool operator==(const UnitSpan &, const UnitSpan &) = default;
};

// The pieces overlapping one bucket (address >> facts::kBucketShift).
struct UnitBucket {
  static constexpr std::string_view name = "analysis.units.bucket";
  static constexpr std::uint32_t version = 1;
  using Key = Location;  // address = the bucket index
  using Value = std::vector<UnitSpan>;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return analysis::describe(k); }
};

struct UnitCodeInfo {
  struct Entry {
    std::uint64_t key = 0;  // flow key
    bool function = false;
    friend bool operator==(const Entry &, const Entry &) = default;
  };
  std::vector<Entry> entries;   // by key
  std::vector<Range> blocked;   // cleared and data bytes within ProgramInfo::code; sorted, merged

  bool is_blocked(std::uint64_t a) const;
  void encode(facts::Encoder &e) const;
  static UnitCodeInfo decode(facts::Decoder &d);
  friend bool operator==(const UnitCodeInfo &, const UnitCodeInfo &) = default;
};

struct UnitCode {
  static constexpr std::string_view name = "analysis.units.code";
  static constexpr std::uint32_t version = 1;
  using Key = ProgramKey;
  using Value = UnitCodeInfo;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return k.id; }
};

// Reads the unit buckets a flow decodes in, once each.
class UnitReader {
 public:
  UnitReader(facts::QueryContext &ctx, const ProgramKey &program) : ctx_(ctx), program_(program) {}
  // The span holding `a`, or null when no mark owns it.
  const UnitSpan *at(std::uint64_t a);
  // The first span overlapping [first, last], or null.
  const UnitSpan *overlapping(std::uint64_t first, std::uint64_t last);

 private:
  const std::vector<UnitSpan> &bucket(std::uint64_t index);
  facts::QueryContext &ctx_;
  const ProgramKey &program_;
  std::vector<std::pair<std::uint64_t, facts::Ref<std::vector<UnitSpan>>>> buckets_;
};

struct MutabilityPiece {
  std::uint64_t first = 0, last = 0;
  MutabilityKind kind = MutabilityKind::as_map;
  std::uint64_t start = 0;  // the mark's key: address and sub
  std::string sub;

  void encode(facts::Encoder &e) const;
  static MutabilityPiece decode(facts::Decoder &d);
  friend bool operator==(const MutabilityPiece &, const MutabilityPiece &) = default;
};

struct MutabilityMap {
  static constexpr std::string_view name = "analysis.mutability";
  static constexpr std::uint32_t version = 1;
  using Key = ProgramKey;
  using Value = std::vector<MutabilityPiece>;  // sorted, disjoint; as_map pieces left out
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return k.id; }
};

const MutabilityPiece *mutability_at(const std::vector<MutabilityPiece> &map, std::uint64_t a);

void register_unit_queries(facts::Engine &engine);  // called by register_queries

}  // namespace revkit::analysis
