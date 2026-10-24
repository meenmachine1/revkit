// The Nintendo DS's compressions (docs/nds.md), as GBATEK documents them
// (problemkaputt.de/gbatek.htm, "BIOS Decompression Functions" and "DS
// Cartridge"): the BIOS's LZ77 (type 0x10, "LZ10"), its extended form
// (0x11, "LZ11"), Huffman (0x24 and 0x28) and run-length (0x30), all with
// a 4-byte header (type, 24-bit size, and for sizes past 16 MiB a 32-bit
// extension with LZ11), and the ARM9 binary's and overlays' backward LZ
// ("BLZ"), which decompresses in place from the end with an 8-byte footer.
//
// Every decoder is bounded: `max_out` caps the output (a header that
// claims more is an error), and malformed input is an error, never a read
// out of bounds.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace revkit::nds {

enum class Compression : std::uint8_t { none, lz10, lz11, huffman4, huffman8, rle };
const char *to_string(Compression c);

// What the 4-byte header says, without decoding: the type and the size it
// claims. nullopt for a header no BIOS decompressor takes.
struct CompressionHeader {
  Compression type = Compression::none;
  std::uint32_t size = 0;
  std::size_t header_size = 4;
};
std::optional<CompressionHeader> compression_header(std::span<const std::uint8_t> data);

// Decodes LZ10, LZ11, Huffman or RLE data by its header. `consumed` (when
// given) is how many input bytes the stream used.
std::optional<std::vector<std::uint8_t>> decompress(std::span<const std::uint8_t> data, std::size_t max_out,
                                                    std::string *error, std::size_t *consumed = nullptr);

// Whether `data` looks like a whole compressed file: the header is valid,
// the claimed size is plausible (more than the input, at most `max_out`,
// at most 64x the input) and the stream decodes, ending within the last
// 32 bytes of padding. The container layer mounts such files.
bool looks_compressed(std::span<const std::uint8_t> data, std::size_t max_out);

// Backward LZ: `data` is the whole module as stored (its compressed part
// ends the data and carries the footer). Returns the decompressed module.
std::optional<std::vector<std::uint8_t>> blz_decompress(std::span<const std::uint8_t> data, std::size_t max_out,
                                                        std::string *error);

// The footer's claims, for checking before decoding: the compressed
// part's length, the footer's length and how much longer the output is.
struct BlzFooter {
  std::uint32_t compressed_length = 0;
  std::uint32_t header_length = 0;
  std::uint32_t extra = 0;
};
std::optional<BlzFooter> blz_footer(std::span<const std::uint8_t> data);

}  // namespace revkit::nds
