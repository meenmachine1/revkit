// A reader for CPython's marshal format (Python/marshal.c's documented
// type codes), enough for the packers' tables of contents: PyInstaller's
// PYZ index, a list of (name, (typecode, offset, length)). Written for
// hostile input: bounded depth and value count, back-references shared
// rather than copied (a reference can't make a table grow). Code objects
// are skipped by their version's layout, not read. Internal.
#pragma once

#include "revkit/container/container.hh"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace revkit::container::detail {

struct Marshal {
  enum class Type : std::uint8_t { none, boolean, integer, floating, bytes, str, tuple, list, dict, set, code, other };
  Type type = Type::none;
  bool b = false;
  std::int64_t i = 0;  // integers that fit; bigger ones are Type::other
  std::string s;       // bytes and str (UTF-8 as stored)
  std::vector<std::shared_ptr<const Marshal>> items;  // tuple, list, set; dict: key, value, key, value, ...
  bool is_text() const { return type == Type::bytes || type == Type::str; }
};

// Reads one value at `pos` (advanced past it). `major`/`minor`: the Python
// that wrote it, for code objects' layouts. Error on malformed data.
std::shared_ptr<const Marshal> read_marshal(std::span<const std::byte> data, std::size_t &pos, int major, int minor,
                                            std::uint32_t max_depth = 64, std::uint64_t max_values = 1u << 22);

}  // namespace revkit::container::detail
