// The program's memory map as a query over the fact engine: the loader's
// blocks with the user's memory-map edits laid over them (docs/memory-map.md).
//
// Edits are MEMORY_REGION assertions in the program's code space, at
// address 0 (facts::FactKind::MemoryRegion):
//
//   sub "region:<id>"         a region the user added (RegionSpec): RAM,
//                             zero-filled memory, memory-mapped I/O, or
//                             bytes from another file, staged in the fact
//                             store's bytes at RegionBytes::space/offset
//   sub "block:<hex start>"   an edit to one of the image's own blocks
//                             (BlockEdit): its name, permissions and
//                             volatile flag, never its bytes
//
// A value of "" removes the region (or reverts the block's edit); undo is
// retracting the assertion, as for any edit.
//
//   analysis.memory   the effective map: the image's blocks, edited, and
//                     the user's regions that fit (sorted by start; a
//                     region that overlaps another block or wraps is
//                     rejected, with the reason, in a deterministic order:
//                     by start, then id)
//
// What reads it: analysis.program and analysis.data_program, which were the
// loader's view only, are queries over it (the loader's view is now the
// inputs analysis.program.loaded and analysis.data_program.loaded, which
// stage_image sets). A program without edits gets the loader's values
// unchanged, so their fingerprints, and every memo that read them, stay as
// they were. With edits, ProgramInfo maps the new regions, makes the
// executable, initialized ones code, and says where their bytes are
// (ProgramInfo::sources); DataProgramInfo's blocks are the effective map.
// The image backend builds the decompiler's, the listing's and the
// emulator's memory from the same value.
#pragma once

#include "revkit/analysis/analysis.h"
#include "revkit/analysis/data.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::analysis {

// ---- assertions ----

// Where a region's bytes are: a file's bytes staged in the fact store.
struct RegionBytes {
  facts::SpaceId space = 0;   // the fact-store space holding them
  std::uint64_t offset = 0;   // their first byte there
  std::uint64_t length = 0;   // how many (at most the region's size; the rest is zero)
  std::string sha256;         // of the bytes staged (what was taken from the file)
  std::string file;           // the file's name, for display
  std::uint64_t file_offset = 0;  // where they start in that file

  void encode(facts::Encoder &e) const;
  static RegionBytes decode(facts::Decoder &d);
  friend bool operator==(const RegionBytes &, const RegionBytes &) = default;
};

// A region the user added. `initialized` false: no contents (RAM before it
// is written, I/O); true: `bytes` if set, else zero-filled.
struct RegionSpec {
  std::string name;
  std::uint64_t start = 0;
  std::uint64_t size = 0;
  bool read = true, write = true, exec = false;
  bool initialized = false;
  bool is_volatile = false;
  std::optional<RegionBytes> bytes;

  std::uint64_t last() const { return start + (size - 1); }
  void encode(facts::Encoder &e) const;
  static RegionSpec decode(facts::Decoder &d);
  friend bool operator==(const RegionSpec &, const RegionSpec &) = default;
};

// An edit to one of the image's blocks: its new name, permissions and
// volatile flag (all of them; the block's own values where unchanged).
struct BlockEdit {
  std::string name;
  bool read = false, write = false, exec = false;
  bool is_volatile = false;

  void encode(facts::Encoder &e) const;
  static BlockEdit decode(facts::Decoder &d);
  friend bool operator==(const BlockEdit &, const BlockEdit &) = default;
};

inline constexpr std::string_view kRegionSubPrefix = "region:";
inline constexpr std::string_view kBlockSubPrefix = "block:";
std::string region_sub(std::string_view id);
std::string block_sub(std::uint64_t start);  // "block:0x1000"

// Assertion values ("" means removed); decoding a value that isn't one gives
// nullopt.
std::string encode_region(const RegionSpec &r);
std::optional<RegionSpec> decode_region(std::string_view value);
std::string encode_block_edit(const BlockEdit &e);
std::optional<BlockEdit> decode_block_edit(std::string_view value);

// ---- the effective map ----

enum class BlockOrigin : std::uint8_t { image, user };

struct MemoryBlock {
  std::string name;
  Range range;
  bool read = false, write = false, exec = false;
  bool initialized = true;
  bool is_volatile = false;
  BlockOrigin origin = BlockOrigin::image;
  std::string id;            // user: the region's id
  bool edited = false;       // image: a BlockEdit applies
  std::optional<RegionBytes> bytes;  // user: where its bytes are (when initialized from a file)
  // user, from a file: its bytes aren't in this store yet (a collaborator
  // added it and they are still on their way): uninitialized until they come.
  bool bytes_missing = false;
  std::string rejected;      // why it isn't mapped (MemoryMapInfo::rejected only)

  void encode(facts::Encoder &e) const;
  static MemoryBlock decode(facts::Decoder &d);
  friend bool operator==(const MemoryBlock &, const MemoryBlock &) = default;
};

struct MemoryMapInfo {
  std::vector<MemoryBlock> blocks;    // mapped, sorted by start, disjoint
  std::vector<MemoryBlock> rejected;  // user regions that don't fit, by start
  bool edited = false;                // any edit applies (else: the loader's map)
  std::uint8_t address_bits = 64;     // the code space's address size
  // The keys of the program's other memory spaces (ProgramInfo::spaces:
  // AVR's data memory, 8051's EXTMEM), each 2^loader::kSpaceKeyShift
  // long: a region there may not leave its space.
  std::vector<std::uint64_t> space_bases;

  const MemoryBlock *block(std::uint64_t a) const;
  const MemoryBlock *region(std::string_view id) const;  // mapped or rejected
  void encode(facts::Encoder &e) const;
  static MemoryMapInfo decode(facts::Decoder &d);
  friend bool operator==(const MemoryMapInfo &, const MemoryMapInfo &) = default;
};

struct MemoryMap {
  static constexpr std::string_view name = "analysis.memory";
  static constexpr std::uint32_t version = 1;
  using Key = ProgramKey;
  using Value = MemoryMapInfo;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return k.id; }
};

// Why `r` can't be added to `map` (or, with `replacing`, take the place of
// that region): empty if it can. The messages follow the raw loader's.
std::string check_region(const MemoryMapInfo &map, const RegionSpec &r, std::string_view replacing = {});

// "0x1000"
std::string hex_address(std::uint64_t a);

// ---- the map over a loaded image ----

// A region's staged bytes, read page by page from the fact store (through
// a query context, the pages become dependencies); null when they aren't
// all there yet. Bytes remembered by their sha256 (remember_region_bytes,
// while something still holds them) are taken from memory instead.
std::shared_ptr<const loader::Bytes> region_bytes(facts::QueryContext &ctx, const RegionBytes &b);
std::shared_ptr<const loader::Bytes> region_bytes(const facts::Snapshot &snap, const RegionBytes &b);
void remember_region_bytes(const std::string &sha256, std::shared_ptr<const loader::Bytes> bytes);

using RegionBytesReader = std::function<std::shared_ptr<const loader::Bytes>(const RegionBytes &)>;

// A copy of `image` with `map` laid over it, as everything that decodes or
// emulates the program's memory sees it (the image backend's
// Program::WithMemory, revkit::infer's effective image): the image's blocks
// renamed, with their permissions and volatile flags; their loaded regions
// split where an edited block's permissions differ from its region's (an
// ELF section inside a segment), so the region's permissions are the
// block's; the user's regions as blocks and memory regions with their
// bytes (from `bytes`; uninitialized, or bytes not there, have none).
std::shared_ptr<loader::Image> image_with_memory(const loader::Image &image, const MemoryMapInfo &map,
                                                 const RegionBytesReader &bytes);

void register_memory_queries(facts::Engine &engine);  // called by register_queries

}  // namespace revkit::analysis
