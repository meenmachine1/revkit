// Single-file compression (gzip, bzip2, xz, lzma, zstd, lz4): a container
// of one file, the decompressed data. Its name comes from the gzip header
// when there is one (display only), else the outer name without its suffix.
#include "formats.hh"

#include <zstd.h>

namespace revkit::container::detail {
namespace {

class Compressed final : public SliceFileSystem {
 public:
  Compressed(std::shared_ptr<const Source> src, Codec codec) : SliceFileSystem(std::move(src)), codec_(codec) {}

  void parse(std::string_view outer, const Context &ctx) {
    format_ = codec_ == Codec::lzma_alone ? "lzma" : codec_ == Codec::lz4_frame ? "lz4" : std::string(name(codec_));
    const std::uint64_t size = src_->size();
    const auto h = src_->head(4096);
    std::string inner;
    std::uint64_t usize = UINT64_MAX;
    switch (codec_) {
      case Codec::gzip: {
        Buf b(h, "the gzip header");
        const std::uint8_t flags = b.u8(3);
        std::size_t p = 10;
        if (flags & 0x04) p += 2u + b.l16(p);  // FEXTRA
        if (flags & 0x08) {                    // FNAME
          std::size_t e = p;
          while (e < h.size() && h[e] != std::byte{0} && e - p < 1024) ++e;
          if (e < h.size() && h[e] == std::byte{0}) inner.assign(reinterpret_cast<const char *>(h.data() + p), e - p);
        }
        // ISIZE: the size mod 2^32 of the last member; right for one
        // member under 4 GiB, which is nearly every .gz.
        if (size >= 18) usize = le32(src_->read_exact(size - 4, 4, "the gzip trailer").data());
        break;
      }
      case Codec::zstd: {
        const unsigned long long n = ZSTD_getFrameContentSize(h.data(), h.size());
        if (n != ZSTD_CONTENTSIZE_UNKNOWN && n != ZSTD_CONTENTSIZE_ERROR) usize = n;
        break;
      }
      case Codec::lzma_alone: {
        if (h.size() >= 13) {
          const std::uint64_t n = le64(h.data() + 5);
          if (n != UINT64_MAX) usize = n;
        }
        break;
      }
      case Codec::lz4_frame: {
        if (h.size() >= 14 && le32(h.data()) == 0x184d2204u && (static_cast<std::uint8_t>(h[4]) & 0x08))
          usize = le64(h.data() + 6);
        break;
      }
      default: break;
    }
    // Only a slash-free, non-empty name from inside is kept.
    if (inner.empty() || inner.find('/') != std::string::npos || inner == "." || inner == "..")
      inner = strip_suffix(outer, {".tgz", ".gz", ".z", ".tbz2", ".tbz", ".bz2", ".txz", ".xz", ".lzma",
                                   ".tzst", ".zst", ".zstd", ".lz4", ".cpgz"});
    if (inner.size() >= 7 && inner.ends_with(".tar.tar")) inner.resize(inner.size() - 4);
    TreeBuilder tree(*this, ctx.limits);
    Entry e;
    e.kind = Kind::file;
    e.size = usize;
    e.stored_size = size;
    e.loc0 = 0;
    e.loc1 = size;
    e.loc2 = 1 + static_cast<std::uint64_t>(codec_);
    if (usize == UINT64_MAX) e.note = "size known once read";
    e.name = inner;
    tree.add_child(0, std::move(e));
    tree.finish();
    description_ = format_ + " compressed";
  }

  std::shared_ptr<Source> open(std::uint32_t entry, const Context &ctx) const override {
    const Entry &e = entries_.at(target_of(entry));
    Sink sink(ctx);
    decompress(codec_, *src_, 0, src_->size(), sink, ctx);
    // gzip's size is a hint (mod 2^32, last member): don't insist on it.
    (void)e;
    return sink.finish();
  }

 private:
  Codec codec_;
};

}  // namespace

std::shared_ptr<FileSystem> open_compressed(Codec codec, std::shared_ptr<const Source> src, std::string_view name,
                                            const Context &ctx) {
  auto fs = std::make_shared<Compressed>(std::move(src), codec);
  fs->parse(name, ctx);
  return fs;
}

}  // namespace revkit::container::detail
