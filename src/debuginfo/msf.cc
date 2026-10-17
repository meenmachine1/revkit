#include "msf.h"

#include "cursor.h"
#include "revkit/debuginfo/pdb.h"

#include <cstring>
#include <string>

namespace revkit::debuginfo::pdb {
namespace {

constexpr char kMagic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0";
constexpr std::size_t kMagicSize = 32;
constexpr std::size_t kSuperBlockSize = kMagicSize + 6 * 4;

std::uint32_t le32(std::span<const std::uint8_t> b, std::size_t off) {
  return std::uint32_t(b[off]) | std::uint32_t(b[off + 1]) << 8 | std::uint32_t(b[off + 2]) << 16 |
         std::uint32_t(b[off + 3]) << 24;
}

}  // namespace

Msf::Msf(std::span<const std::uint8_t> file) : file_(file) {
  static_assert(sizeof kMagic - 1 == kMagicSize);
  if (file.size() < kSuperBlockSize || std::memcmp(file.data(), kMagic, kMagicSize) != 0) {
    if (file.size() >= 44 && std::memcmp(file.data(), "Microsoft C/C++ program database 2.00", 37) == 0)
      throw PdbError("PDB 2.00 (small MSF) files are not supported");
    throw PdbError("not an MSF 7.00 file");
  }
  budget_ = 4 * std::uint64_t(file.size()) + (std::uint64_t{64} << 20);
  block_size_ = le32(file, 32);
  block_count_ = le32(file, 40);
  const std::uint32_t dir_bytes = le32(file, 44);
  const std::uint32_t block_map = le32(file, 52);
  switch (block_size_) {
    case 512: case 1024: case 2048: case 4096: case 8192: case 16384: case 32768: break;
    default: throw PdbError("bad MSF block size " + std::to_string(block_size_));
  }
  const std::uint64_t whole_blocks = file.size() / block_size_;
  if (block_count_ == 0 || block_count_ > whole_blocks + 1)
    throw PdbError("MSF block count " + std::to_string(block_count_) + " doesn't fit a " +
                   std::to_string(file.size()) + "-byte file");

  // The block map is one block of directory block indices.
  const std::uint64_t dir_blocks = (std::uint64_t(dir_bytes) + block_size_ - 1) / block_size_;
  // The directory is at most the file: its blocks may repeat, and a 256 MB
  // directory of one repeated block listed 64M streams.
  if (dir_bytes < 4 || dir_blocks * 4 > block_size_ || dir_bytes > file.size())
    throw PdbError("bad MSF directory size " + std::to_string(dir_bytes));
  if (block_map >= block_count_ || std::uint64_t(block_map + 1) * block_size_ > file.size())
    throw PdbError("MSF block map is outside the file");
  std::vector<std::uint32_t> map(dir_blocks);
  for (std::size_t i = 0; i < dir_blocks; ++i)
    map[i] = le32(file, std::size_t(block_map) * block_size_ + 4 * i);
  std::vector<std::uint8_t> dir;
  try {
    dir = gather(map, dir_bytes);
  } catch (const FormatError &e) {
    throw PdbError(std::string("MSF stream directory: ") + e.what());
  }

  // Directory: stream count, sizes, then every stream's block list.
  Cursor c(dir, false);
  try {
    std::uint32_t n = c.u32();
    if (n > c.remaining() / 4) throw PdbError("MSF directory lists too many streams");
    sizes_.resize(n);
    for (auto &s : sizes_) s = c.u32();
    blocks_.resize(n);
    for (std::uint32_t i = 0; i < n; ++i) {
      if (sizes_[i] == kNilSize) continue;
      std::uint64_t count = (std::uint64_t(sizes_[i]) + block_size_ - 1) / block_size_;
      if (count > c.remaining() / 4 || count > block_count_)
        throw PdbError("MSF stream " + std::to_string(i) + " is larger than the file");
      blocks_[i].resize(count);
      for (auto &b : blocks_[i]) b = c.u32();
    }
  } catch (const FormatError &e) {
    throw PdbError(std::string("MSF stream directory: ") + e.what());
  }
}

std::vector<std::uint8_t> Msf::gather(std::span<const std::uint32_t> blocks, std::uint64_t size) const {
  std::vector<std::uint8_t> out;
  out.reserve(std::size_t(size));
  for (std::uint32_t b : blocks) {
    if (out.size() >= size) break;
    if (b >= block_count_ || std::uint64_t(b + 1ull) * block_size_ > file_.size())
      throw FormatError("MSF block " + std::to_string(b) + " is outside the file");
    std::size_t n = std::size_t(std::min<std::uint64_t>(block_size_, size - out.size()));
    auto src = file_.subspan(std::size_t(b) * block_size_, n);
    out.insert(out.end(), src.begin(), src.end());
  }
  if (out.size() != size) throw FormatError("MSF stream has too few blocks");
  return out;
}

std::vector<std::uint8_t> Msf::read(std::uint32_t index) const {
  if (!has_stream(index)) return {};
  if (gathered_.fetch_add(sizes_[index]) + sizes_[index] > budget_)
    throw PdbError("MSF streams read more than four times the file: their blocks are shared");
  return gather(blocks_[index], sizes_[index]);
}

}  // namespace revkit::debuginfo::pdb
