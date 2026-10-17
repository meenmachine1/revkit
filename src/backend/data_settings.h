// How a data item displays (Ghidra's Data > Settings and Default Settings;
// docs/listing-edit.md#data-settings): an integer's format, signedness,
// byte order and padding, a string's charset and termination, a pointer's
// kind (absolute, image-base offset, relative), mask and shift.
//
// Settings are NOTE keys with reserved tags, so a project that has them
// opens, and an archive of it imports, in a daemon from before them (which
// reads them as notes):
//
//   NOTE@item   tag "revkit:data-settings"            the item's own (its
//                                                     row, an array's elements)
//   NOTE@item   tag "revkit:data-settings:<field>"    a struct field's row
//                                                     ("hdr.magic")
//   NOTE@0      tag "revkit:data-type-settings:<type>" the type's defaults
//                                                     (every row of the type)
//
// Values are text ("format=decimal;sign=signed"; "" removes). Each setting
// a row's own settings leave unset falls back to its type's default, then
// to how the type shows without settings. Nothing is stored in the data
// definition itself (the CODE_UNIT mark): definitions made before this are
// read unchanged, and with no settings every row shows as before.
#pragma once

#include "revkit/v1/assertion.pb.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace revkit::backend {

namespace pb = ::revkit::v1;

inline constexpr std::string_view kDataSettingsTag = "revkit:data-settings";
inline constexpr std::string_view kDataFieldSettingsPrefix = "revkit:data-settings:";
inline constexpr std::string_view kDataTypeSettingsPrefix = "revkit:data-type-settings:";
inline constexpr std::size_t kMaxDataSettingsName = 512;  // a field path or type name

// A NOTE tag of data settings (the item's, a field's or a type's).
bool IsDataSettingsTag(std::string_view tag);
// The NOTE tag of an item's settings (field "") or of a struct field's.
std::string DataSettingsTag(std::string_view field);
// The NOTE tag of a type's default settings.
std::string DataTypeSettingsTag(std::string_view type);

struct DataSettings {
  enum class Format : std::uint8_t { unset, hex, decimal, octal, binary, character };
  enum class Sign : std::uint8_t { unset, is_signed, is_unsigned };
  enum class Endian : std::uint8_t { unset, little, big };
  enum class Padding : std::uint8_t { unset, padded, unpadded };
  enum class Termination : std::uint8_t { unset, nul, all };
  enum class Pointer : std::uint8_t { unset, absolute, image_base, relative };

  Format format = Format::unset;
  Sign sign = Sign::unset;
  Endian endian = Endian::unset;
  Padding padding = Padding::unset;
  std::string charset;  // canonical name (DataCharsets), "" unset
  Termination termination = Termination::unset;
  Pointer pointer = Pointer::unset;
  std::optional<std::uint64_t> mask;  // pointer: the bits of the stored value that hold it
  std::optional<std::int32_t> shift;  // pointer: then shifted left (negative: right)

  bool empty() const { return *this == DataSettings{}; }
  // Each setting of this one, else `under`'s.
  DataSettings over(const DataSettings &under) const;
  // The canonical text ("" when empty).
  std::string encode() const;
  // nullopt: not settings text. Unknown keys are skipped (a later daemon's).
  static std::optional<DataSettings> parse(std::string_view text);
  // Validates the API's message; nullopt with `err` set when it is out of range.
  static std::optional<DataSettings> from_proto(const pb::DataSettings &s, std::string *err);
  pb::DataSettings to_proto() const;

  friend bool operator==(const DataSettings &, const DataSettings &) = default;
};

// The charsets a string's setting may name, canonical spelling first.
const std::vector<std::string_view> &DataCharsets();
// The canonical name for `name` (any case, "latin1", "utf16le", ...), or nullopt.
std::optional<std::string> CanonicalCharset(std::string_view name);

// The settings one listing page reads: the items' and fields' in its
// address range, and every type's defaults.
struct DataSettingsMap {
  std::map<std::pair<std::uint64_t, std::string>, DataSettings> items;  // (item address, field; "" the item)
  std::map<std::string, DataSettings, std::less<>> types;

  bool empty() const { return items.empty() && types.empty(); }
  // What a row shows by: its item's (a struct field's: its own) over its type's.
  DataSettings at(std::uint64_t item, std::string_view field, std::string_view type) const;
};

// An integer of `bytes` (1..8, memory order) as the settings say:
// "2ah" (hex: padded to the width unless signed, by default), "42" or
// "-42" (decimal), "52o", "101010b", "'*'" (characters, most significant
// first).
std::string FormatInteger(std::string_view bytes, bool big_endian, bool is_signed, DataSettings::Format format,
                          DataSettings::Padding padding);
// Text of `bytes` in `charset` (canonical; "UTF-16" and "UTF-32" in
// `big_endian` order), as UTF-8 with control characters and invalid
// sequences escaped, quoted with `prefix` ("", "u", "U"): to the first NUL
// unless `all` (then NULs show as \0).
std::string QuoteChars(std::string_view bytes, std::string_view charset, bool big_endian, bool all,
                       std::string_view prefix);
// The length of the well-formed UTF-8 sequence at `s[i]` (1 for ASCII), or
// 0 when the bytes there aren't one.
std::size_t Utf8Sequence(std::string_view s, std::size_t i);

// The quoting prefix strings in `charset` take ("" for byte charsets, "u"
// for UTF-16, "U" for UTF-32).
std::string_view CharsetPrefix(std::string_view charset);

}  // namespace revkit::backend
