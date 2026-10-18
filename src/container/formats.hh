// The formats' entry points and the byte helpers they share (internal).
#pragma once

#include "revkit/container/container.hh"
#include "revkit/container/decompress.hh"

#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace revkit::container::detail {

using Opener = std::shared_ptr<FileSystem> (*)(std::shared_ptr<const Source>, std::string_view name, const Context &);

std::shared_ptr<FileSystem> open_zip(std::shared_ptr<const Source>, std::string_view, const Context &);
std::shared_ptr<FileSystem> open_tar(std::shared_ptr<const Source>, std::string_view, const Context &);
std::shared_ptr<FileSystem> open_cpio(std::shared_ptr<const Source>, std::string_view, const Context &);
std::shared_ptr<FileSystem> open_ar(std::shared_ptr<const Source>, std::string_view, const Context &);
std::shared_ptr<FileSystem> open_iso9660(std::shared_ptr<const Source>, std::string_view, const Context &);
std::shared_ptr<FileSystem> open_squashfs(std::shared_ptr<const Source>, std::string_view, const Context &);
std::shared_ptr<FileSystem> open_ext(std::shared_ptr<const Source>, std::string_view, const Context &);
std::shared_ptr<FileSystem> open_cramfs(std::shared_ptr<const Source>, std::string_view, const Context &);
std::shared_ptr<FileSystem> open_fat(std::shared_ptr<const Source>, std::string_view, const Context &);
std::shared_ptr<FileSystem> open_uimage(std::shared_ptr<const Source>, std::string_view, const Context &);
std::shared_ptr<FileSystem> open_android_boot(std::shared_ptr<const Source>, std::string_view, const Context &);
std::shared_ptr<FileSystem> open_uf2(std::shared_ptr<const Source>, std::string_view, const Context &);
std::shared_ptr<FileSystem> open_partitions(std::shared_ptr<const Source>, std::string_view, const Context &);
// gzip, bzip2, xz, lzma, zstd, lz4: one file, the decompressed data.
std::shared_ptr<FileSystem> open_compressed(Codec codec, std::shared_ptr<const Source>, std::string_view,
                                            const Context &);

// The file name without a compression suffix ("a.tar.gz" -> "a.tar"),
// or name + ".out" when there is none.
std::string strip_suffix(std::string_view name, std::initializer_list<std::string_view> suffixes);

inline std::uint16_t le16(const std::byte *p) {
  return static_cast<std::uint16_t>(static_cast<std::uint8_t>(p[0]) | static_cast<std::uint8_t>(p[1]) << 8);
}
inline std::uint32_t le32(const std::byte *p) {
  return static_cast<std::uint32_t>(p[0]) | static_cast<std::uint32_t>(p[1]) << 8 |
         static_cast<std::uint32_t>(p[2]) << 16 | static_cast<std::uint32_t>(p[3]) << 24;
}
inline std::uint64_t le64(const std::byte *p) { return le32(p) | static_cast<std::uint64_t>(le32(p + 4)) << 32; }
inline std::uint16_t be16(const std::byte *p) {
  return static_cast<std::uint16_t>(static_cast<std::uint8_t>(p[0]) << 8 | static_cast<std::uint8_t>(p[1]));
}
inline std::uint32_t be32(const std::byte *p) {
  return static_cast<std::uint32_t>(p[0]) << 24 | static_cast<std::uint32_t>(p[1]) << 16 |
         static_cast<std::uint32_t>(p[2]) << 8 | static_cast<std::uint32_t>(p[3]);
}

// Bounds-checked little/big-endian reads over a buffer: Error on overrun.
class Buf {
 public:
  explicit Buf(std::span<const std::byte> b, const char *what = "a header") : b_(b), what_(what) {}
  std::size_t size() const { return b_.size(); }
  const std::byte *at(std::size_t off, std::size_t n) const {
    if (off > b_.size() || n > b_.size() - off) throw Error(std::string("truncated ") + what_);
    return b_.data() + off;
  }
  std::uint8_t u8(std::size_t off) const { return static_cast<std::uint8_t>(*at(off, 1)); }
  std::uint16_t l16(std::size_t off) const { return le16(at(off, 2)); }
  std::uint32_t l32(std::size_t off) const { return le32(at(off, 4)); }
  std::uint64_t l64(std::size_t off) const { return le64(at(off, 8)); }
  std::uint16_t b16(std::size_t off) const { return be16(at(off, 2)); }
  std::uint32_t b32(std::size_t off) const { return be32(at(off, 4)); }
  std::string str(std::size_t off, std::size_t n) const {
    return std::string(reinterpret_cast<const char *>(at(off, n)), n);
  }
  // Up to the first NUL within n bytes.
  std::string cstr(std::size_t off, std::size_t n) const {
    const char *p = reinterpret_cast<const char *>(at(off, n));
    return std::string(p, strnlen(p, n));
  }
  std::span<const std::byte> span(std::size_t off, std::size_t n) const { return {at(off, n), n}; }

 private:
  std::span<const std::byte> b_;
  const char *what_;
};

// A file stored in pieces of its container (file system images): `runs`
// map the file's offsets to the container's; what no run covers, and runs
// marked `zero`, read as zeros. Runs must be sorted and not overlap.
struct Run {
  std::uint64_t logical = 0;
  std::uint64_t physical = 0;
  std::uint64_t length = 0;
  bool zero = false;
};
std::shared_ptr<Source> mapped_source(std::shared_ptr<const Source> base, std::vector<Run> runs, std::uint64_t size);

// Helpers every format's FileSystem uses.
std::string plural(std::uint64_t n, std::string_view one, std::string_view many);
std::string summary_counts(const FileSystem &fs);
std::uint32_t crc32_ieee(std::span<const std::byte> data, std::uint32_t crc = 0);

// A FileSystem whose files are slices of the container (loc0 offset,
// loc1 size), or stored compressed with one codec (loc2: 0 stored, else
// 1 + Codec), as archives keep them.
class SliceFileSystem : public FileSystem {
 public:
  explicit SliceFileSystem(std::shared_ptr<const Source> src) : src_(std::move(src)) {}
  std::shared_ptr<Source> open(std::uint32_t entry, const Context &ctx) const override;
  std::vector<std::byte> head(std::uint32_t entry, std::uint64_t n, const Context &ctx) const override;
  bool stored_plain(std::uint32_t entry) const override {
    return entry < entries_.size() && entries_[entry].loc2 == 0;
  }
  FileSystem &self() { return *this; }
  std::vector<std::string> &warnings_mut() { return warnings_; }
  void set_info(std::string format, std::string description) {
    format_ = std::move(format);
    description_ = std::move(description);
  }

 protected:
  std::uint32_t target_of(std::uint32_t entry) const;
  // The stored bytes of any entry, whatever its kind (a symlink's target).
  std::vector<std::byte> head_entry(const Entry &e, std::uint64_t n, const Context &ctx) const;
  std::shared_ptr<const Source> src_;
};

}  // namespace revkit::container::detail
