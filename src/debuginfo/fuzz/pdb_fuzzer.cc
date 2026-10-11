// libFuzzer target for the PDB reader.
//
// Two input forms. A file starting with the MSF 7.00 magic is a PDB, read
// as is: that exercises the container. Anything else is a list of streams,
// [u32 little-endian length][bytes] each, written into a fresh MSF first,
// so mutations reach the stream parsers instead of mostly breaking block
// maps. make_pdb_seeds.py writes both forms from real PDBs.
#include "../tests/pdb_builder.h"
#include "revkit/debuginfo/pdb.h"
#include "revkit/types/print.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace {

constexpr std::size_t kMaxStreams = 64;

void run(std::span<const std::uint8_t> pdb) {
  using namespace revkit;
  types::TypeStore store;
  debuginfo::PdbOptions opt;
  opt.image_base = 0x140000000;
  try {
    (void)debuginfo::read_pdb_identity(pdb);
    debuginfo::PdbDebugInfo info = debuginfo::read_pdb(pdb, store, opt);
    for (const auto &f : info.functions) {
      if (!f.prototype.valid()) continue;
      (void)types::prototype(store, f.prototype, f.name);
      (void)types::prototype(store, f.prototype, f.name, {types::Style::Ghidra, true});
    }
    for (types::TypeId id : info.types) {
      (void)types::definition(store, id);
      (void)store.size_of(id);
      (void)store.align_of(id);
    }
    for (const auto &v : info.variables) (void)types::declaration(store, v.type, v.name);
  } catch (const debuginfo::PdbError &) {
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  if (size >= 24 && std::memcmp(data, "Microsoft C/C++ MSF 7.00", 24) == 0) {
    run({data, size});
    return 0;
  }
  std::vector<std::vector<std::uint8_t>> streams;
  std::size_t pos = 0;
  while (pos + 4 <= size && streams.size() < kMaxStreams) {
    std::uint32_t len = std::uint32_t(data[pos]) | std::uint32_t(data[pos + 1]) << 8 |
                        std::uint32_t(data[pos + 2]) << 16 | std::uint32_t(data[pos + 3]) << 24;
    pos += 4;
    if (len > size - pos) len = std::uint32_t(size - pos);
    streams.emplace_back(data + pos, data + pos + len);
    pos += len;
  }
  run(revkit::debuginfo::testing::msf(streams));
  return 0;
}
