// Addresses modelled on Ghidra's scheme: an address is a space plus an
// offset, spaces are registered in a SpaceTable, and ranges are inclusive so
// that the last byte of a 64-bit space is representable.
#pragma once

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::facts {

using SpaceId = std::uint16_t;

enum class SpaceKind : std::uint8_t {
  Constant,  // offsets are values, not locations
  Ram,       // loaded memory (code and data)
  Register,
  Stack,     // offsets relative to a function's frame
  Unique,    // SLEIGH temporaries
  Overlay,   // shares offsets with a base space but is a distinct space
  Other,     // file-format metadata, etc.
};

std::string_view to_string(SpaceKind kind);

struct AddressSpace {
  SpaceId id = 0;
  std::string name;
  SpaceKind kind = SpaceKind::Ram;
  std::uint8_t size = 8;       // address size in bytes (1..8)
  std::uint8_t word_size = 1;  // bytes per addressable unit
  bool big_endian = false;
  std::optional<SpaceId> overlay_base;  // set only for SpaceKind::Overlay

  std::uint64_t max_offset() const {
    return size >= 8 ? ~std::uint64_t{0} : (std::uint64_t{1} << (8 * size)) - 1;
  }
};

struct Address {
  SpaceId space = 0;
  std::uint64_t offset = 0;

  friend auto operator<=>(const Address &, const Address &) = default;
};

// Inclusive range [first, last] within a single space.
struct AddressRange {
  Address first;
  Address last;

  static std::optional<AddressRange> make(Address first, Address last);
  // [start, start + length); nullopt if length is 0 or it wraps.
  static std::optional<AddressRange> sized(Address start, std::uint64_t length);

  bool contains(Address a) const {
    return a.space == first.space && a.offset >= first.offset && a.offset <= last.offset;
  }
  // Number of addresses minus one, so a full 64-bit space does not overflow.
  std::uint64_t span() const { return last.offset - first.offset; }

  friend auto operator<=>(const AddressRange &, const AddressRange &) = default;
};

// A normalized set of disjoint, non-adjacent ranges kept in address order.
class AddressSet {
 public:
  AddressSet() = default;
  explicit AddressSet(AddressRange r) { add(r); }

  void add(AddressRange r);
  void add(const AddressSet &other);
  void subtract(AddressRange r);
  AddressSet intersect(const AddressSet &other) const;

  bool contains(Address a) const;
  bool intersects(AddressRange r) const;
  bool empty() const { return ranges_.empty(); }
  const std::vector<AddressRange> &ranges() const { return ranges_; }
  std::optional<Address> min() const;
  std::optional<Address> max() const;

  friend bool operator==(const AddressSet &, const AddressSet &) = default;

 private:
  std::vector<AddressRange> ranges_;
};

// Registry of address spaces. Ids are dense and assigned in insertion order;
// they are persisted, so a table must be rebuilt in the same order on reopen.
class SpaceTable {
 public:
  // const, ram, register, stack, unique: the spaces every program has.
  static SpaceTable standard(std::uint8_t ram_size = 8);

  SpaceId add(std::string name, SpaceKind kind, std::uint8_t size,
              std::uint8_t word_size = 1, bool big_endian = false);
  SpaceId add_overlay(std::string name, SpaceId base);

  const AddressSpace *find(SpaceId id) const;
  const AddressSpace *find(std::string_view name) const;
  const std::vector<AddressSpace> &spaces() const { return spaces_; }

  // Checked arithmetic: nullopt when the result leaves the space.
  std::optional<Address> advance(Address a, std::uint64_t delta) const;
  // "ram:0x401000"
  std::string format(Address a) const;
  std::optional<Address> parse(std::string_view text) const;

 private:
  std::vector<AddressSpace> spaces_;
};

}  // namespace revkit::facts
