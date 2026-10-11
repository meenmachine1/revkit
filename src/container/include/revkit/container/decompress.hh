// Decompressors for the containers' codecs, bounded by a Sink (streams) or
// by the output buffer (blocks). zlib, liblzma, libzstd and libbz2 do the
// work where they can; LZ4 and LZO1X are decoded here (small formats, no
// library on the .deb's promise; docs/filesystems.md).
#pragma once

#include "revkit/container/container.hh"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace revkit::container {

enum class Codec : std::uint8_t {
  deflate,     // raw deflate (zip)
  zlib,        // zlib stream (squashfs gzip, cramfs)
  gzip,        // .gz, members concatenated
  bzip2,       // .bz2, streams concatenated
  xz,          // .xz, streams concatenated
  lzma_alone,  // .lzma (LZMA1 with the 13-byte header)
  zstd,        // .zst, frames concatenated
  lz4_frame,   // .lz4 (frame format, and the legacy format the kernel uses)
  lz4_block,   // one raw LZ4 block (squashfs)
  lzo1x,       // one raw LZO1X block (squashfs)
};
std::string_view name(Codec c);

// Decompresses [offset, offset + length) of `in` into `out`, stopping early
// once out.full(). Error on corrupt data; LimitError from the sink.
void decompress(Codec codec, const Source &in, std::uint64_t offset, std::uint64_t length, Sink &out,
                const Context &ctx);

// Decompresses one block whose output fits `out` (squashfs, cramfs: at most
// the block size). Returns the bytes written. Error on corrupt data or
// when the output doesn't fit.
std::size_t decompress_block(Codec codec, std::span<const std::byte> in, std::span<std::byte> out);

// The bare decoders, for tests and the fuzzers. `out` gets the output
// appended; `history` bytes already at its end may be referenced (LZ4's
// linked blocks). Error when the output would pass max_out.
void lz4_decode_block(std::span<const std::byte> in, std::vector<std::byte> &out, std::size_t max_out);
void lzo1x_decode(std::span<const std::byte> in, std::vector<std::byte> &out, std::size_t max_out);

}  // namespace revkit::container
