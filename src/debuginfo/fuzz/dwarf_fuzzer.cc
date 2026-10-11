// libFuzzer target for the DWARF reader.
//
// Input: one flags byte (bit 0: big-endian, bit 1: 4-byte addresses), then
// sections as [u8 id][u32 little-endian length][bytes], ids indexing
// kSections. make_seeds.py turns real binaries into this format.
#include "revkit/debuginfo/dwarf.h"
#include "revkit/types/print.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace {

constexpr std::array<const char *, 8> kSections = {
    ".debug_info", ".debug_abbrev",  ".debug_str",    ".debug_line_str",
    ".debug_str_offsets", ".debug_addr", ".debug_rnglists", ".debug_ranges",
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit;
  if (size < 1) return 0;
  debuginfo::Sections sec;
  sec.byte_order = data[0] & 1 ? std::endian::big : std::endian::little;
  sec.address_size = data[0] & 2 ? 4 : 8;
  std::size_t pos = 1;
  while (pos + 5 <= size) {
    std::uint8_t id = data[pos];
    std::uint32_t len = std::uint32_t(data[pos + 1]) | std::uint32_t(data[pos + 2]) << 8 |
                        std::uint32_t(data[pos + 3]) << 16 | std::uint32_t(data[pos + 4]) << 24;
    pos += 5;
    if (len > size - pos) len = std::uint32_t(size - pos);
    sec.by_name.insert_or_assign(kSections[id % kSections.size()],
                                 std::span<const std::uint8_t>(data + pos, len));
    pos += len;
  }
  types::TypeStore store;
  debuginfo::DebugInfo info = debuginfo::import_dwarf(sec, store);
  for (const auto &f : info.functions) {
    (void)types::prototype(store, f.prototype, f.name);
    (void)types::prototype(store, f.prototype, f.name, {types::Style::Ghidra, true});
  }
  for (types::TypeId id : info.types) {
    (void)types::definition(store, id);
    (void)store.size_of(id);
    (void)store.align_of(id);
  }
  for (const auto &v : info.variables) (void)types::declaration(store, v.type, v.name);
  return 0;
}
