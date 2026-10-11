// Low-level DWARF model: units, abbreviations and a flat DIE tree with
// lazily-resolved attribute values (internal).
#pragma once

#include "cursor.h"
#include "revkit/debuginfo/dwarf.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace revkit::debuginfo {

constexpr std::uint32_t kNoDie = 0xffffffffu;

struct AttrSpec {
  std::uint16_t at;
  std::uint16_t form;
  std::int64_t implicit_const;
};

struct Abbrev {
  std::uint16_t tag = 0;
  bool has_children = false;
  std::vector<AttrSpec> attrs;
};

using AbbrevTable = std::unordered_map<std::uint64_t, Abbrev>;

struct Unit {
  std::uint64_t offset = 0;  // of the unit header in .debug_info
  std::uint64_t end = 0;     // one past the unit's last byte
  std::uint16_t version = 0;
  std::uint8_t unit_type = 0;
  std::uint8_t addr_size = 8;
  bool dwarf64 = false;
  std::uint64_t type_signature = 0;
  std::uint64_t type_offset = 0;  // absolute DIE offset, for type units
  const AbbrevTable *abbrevs = nullptr;

  // From the unit DIE.
  std::uint64_t base_address = 0;
  std::optional<std::uint64_t> str_offsets_base, addr_base, rnglists_base;
  std::uint16_t language = 0;

  std::uint32_t first_die = kNoDie;  // index into Dwarf::dies
  std::uint32_t die_count = 0;

  unsigned offset_size() const { return dwarf64 ? 8 : 4; }
  bool is_cxx() const;
};

// One attribute value as read: forms are resolved later, when the unit's
// bases (str_offsets_base, addr_base, ...) are known.
struct AttrValue {
  std::uint16_t at;
  std::uint16_t form;
  std::uint64_t u;          // integer, offset, index or absolute DIE offset
  std::string_view bytes;   // inline string, block or expression
};

struct Die {
  std::uint64_t offset = 0;
  std::uint32_t unit = 0;
  std::uint32_t parent = kNoDie;
  std::uint32_t first_child = kNoDie;
  std::uint32_t next_sibling = kNoDie;
  std::uint16_t tag = 0;
  std::uint32_t attr_begin = 0;
  std::uint16_t attr_count = 0;
};

class Dwarf {
 public:
  Dwarf(const Sections &sections, std::vector<Diagnostic> &diags);

  const std::vector<Unit> &units() const { return units_; }
  const std::vector<Die> &dies() const { return dies_; }
  const Die &die(std::uint32_t i) const { return dies_[i]; }
  const Unit &unit_of(std::uint32_t i) const { return units_[dies_[i].unit]; }
  std::span<const AttrValue> attrs(std::uint32_t i) const {
    const Die &d = dies_[i];
    return {attrs_.data() + d.attr_begin, d.attr_count};
  }
  const AttrValue *find(std::uint32_t die, std::uint16_t at) const;
  bool has(std::uint32_t die, std::uint16_t at) const { return find(die, at) != nullptr; }

  // Attribute accessors. Each returns nullopt if the attribute is absent,
  // has an unexpected form, or points outside its section.
  std::optional<std::string_view> string(std::uint32_t die, std::uint16_t at) const;
  std::optional<std::uint64_t> unsigned_value(std::uint32_t die, std::uint16_t at) const;
  std::optional<std::int64_t> signed_value(std::uint32_t die, std::uint16_t at) const;
  std::optional<std::uint64_t> address(std::uint32_t die, std::uint16_t at) const;
  bool flag(std::uint32_t die, std::uint16_t at) const;
  // A reference attribute, as a DIE index.
  std::uint32_t ref(std::uint32_t die, std::uint16_t at) const;
  std::uint32_t die_at(std::uint64_t offset) const;  // kNoDie if none

  // The DIE's code ranges from low_pc/high_pc or DW_AT_ranges (unsorted,
  // empty ranges dropped).
  std::vector<AddressRange> ranges(std::uint32_t die) const;
  // Entry of .debug_addr for this unit.
  std::optional<std::uint64_t> addr_index(const Unit &u, std::uint64_t index) const;
  // A location expression that is exactly one static address, if it is one.
  std::optional<std::uint64_t> static_address(std::uint32_t die) const;

  bool big_endian() const { return big_endian_; }

  // The file a DIE's DW_AT_decl_file names, from its unit's line table
  // header (.debug_line; DWARF 2-5) as written there (a path, or a name
  // relative to a directory); empty if unknown.
  std::string_view decl_file(std::uint32_t die) const;

 private:
  void parse_unit(Cursor &c, std::uint64_t unit_offset);
  const AbbrevTable *abbrevs_at(std::uint64_t offset);
  AttrValue read_attr(Cursor &c, const Unit &u, const AttrSpec &spec);
  void read_unit_bases(Unit &u);
  std::optional<std::string_view> str_at(std::span<const std::uint8_t> sec, std::uint64_t off) const;
  std::vector<AddressRange> rnglist(const Unit &u, std::uint64_t offset) const;
  std::vector<AddressRange> debug_ranges(const Unit &u, std::uint64_t offset) const;

  std::span<const std::uint8_t> info_, abbrev_, str_, line_str_, str_offsets_, addr_, rnglists_,
      ranges_, line_;
  // Per unit: its line table's file names (decl_file), read on first use.
  std::vector<std::string_view> file_names(const Unit &u) const;
  mutable std::unordered_map<std::uint32_t, std::vector<std::string_view>> files_;
  bool big_endian_;
  std::vector<Diagnostic> &diags_;
  std::unordered_map<std::uint64_t, AbbrevTable> abbrev_cache_;
  std::vector<Unit> units_;
  std::vector<Die> dies_;
  std::vector<AttrValue> attrs_;
  std::unordered_map<std::uint64_t, std::uint64_t> type_sigs_;  // signature -> DIE offset
};

}  // namespace revkit::debuginfo
