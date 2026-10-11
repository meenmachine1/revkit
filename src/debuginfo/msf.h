// MSF 7.00 ("big MSF") multi-stream container, the layer under a PDB
// (internal).
//
// The file is an array of fixed-size blocks. Block 0 is the superblock; a
// block map names the blocks holding the stream directory, and the
// directory gives each stream's size and blocks. Streams are read into
// contiguous buffers, so the parsers above never see block boundaries.
#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace revkit::debuginfo::pdb {

class Msf {
 public:
  static constexpr std::uint32_t kNilSize = 0xffffffffu;

  // Throws PdbError if the superblock, block map or directory is invalid.
  explicit Msf(std::span<const std::uint8_t> file);

  std::uint32_t block_size() const { return block_size_; }
  std::uint32_t block_count() const { return block_count_; }
  std::uint32_t stream_count() const { return std::uint32_t(sizes_.size()); }
  bool has_stream(std::uint32_t index) const {
    return index < sizes_.size() && sizes_[index] != kNilSize;
  }
  // 0 for a nil or missing stream.
  std::uint32_t stream_size(std::uint32_t index) const {
    return has_stream(index) ? sizes_[index] : 0;
  }

  // The stream's bytes. A nil or missing stream reads as empty; a block
  // past the end of the file throws FormatError.
  std::vector<std::uint8_t> read(std::uint32_t index) const;

 private:
  std::vector<std::uint8_t> gather(std::span<const std::uint32_t> blocks, std::uint64_t size) const;

  std::span<const std::uint8_t> file_;
  std::uint32_t block_size_ = 0;
  std::uint32_t block_count_ = 0;
  std::vector<std::uint32_t> sizes_;
  std::vector<std::vector<std::uint32_t>> blocks_;
};

}  // namespace revkit::debuginfo::pdb
