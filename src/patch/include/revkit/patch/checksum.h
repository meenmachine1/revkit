// Checksums a firmware's loader or updater checks, and a detector that
// finds which rule a file obeys (docs/patching.md, "Export"): additive sums
// of bytes and of 16/32-bit words in either byte order, Fletcher/Adler,
// the CRC-16 and CRC-32 families, over natural ranges of the file, against
// its header words and values the caller supplies (a file name's hex
// suffix). The PE optional header's CheckSum is here too.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::patch {

// Values match revkit.v1.ChecksumAlgorithm.
enum class Algorithm : std::uint8_t {
  none = 0,
  sum8 = 1,
  sum16 = 2,
  sum32 = 3,
  sum16_words_le = 4,
  sum16_words_be = 5,
  sum32_words_le = 6,
  sum32_words_be = 7,
  sum8_neg = 8,
  sum32_neg = 9,
  xor8 = 10,
  fletcher16 = 11,
  fletcher32 = 12,
  adler32 = 13,
  crc16_ccitt_false = 14,
  crc16_xmodem = 15,
  crc16_kermit = 16,
  crc16_modbus = 17,
  crc16_arc = 18,
  crc32 = 19,
  crc32_bzip2 = 20,
  crc32_mpeg2 = 21,
  crc32_posix = 22,
  crc32_jamcrc = 23,
  crc32c = 24,
  pe = 25,
};

std::string_view name(Algorithm a);           // "sum32", "crc32", ...
std::optional<Algorithm> parse_algorithm(std::string_view name);
unsigned width_bits(Algorithm a);             // 8, 16 or 32
// Every algorithm the detector tries (not pe).
const std::vector<Algorithm> &all_algorithms();

// The checksum of `bytes`.
std::uint64_t compute(Algorithm a, std::span<const std::uint8_t> bytes);

// A rule: an algorithm over [start, end) of the file (end 0: the end;
// negative: back from it), skipping trailing 0xff/0x00 padding if asked,
// written to a field (excluded from the range: read as zeros) or to the
// file name.
struct Spec {
  Algorithm algorithm = Algorithm::none;
  std::uint64_t start = 0;
  std::int64_t end = 0;
  bool skip_padding = false;
  bool field = false;
  std::uint64_t field_offset = 0;
  unsigned field_width = 4;
  bool field_big_endian = false;
  bool name = false;

  friend bool operator==(const Spec &, const Spec &) = default;
};

// [start, end) of a file of `size` bytes as the spec means them; nullopt if
// outside the file.
std::optional<std::pair<std::uint64_t, std::uint64_t>> resolve_range(const Spec &s, std::span<const std::uint8_t> file);

// The spec's value over `file` (a field's own bytes count as zero).
std::optional<std::uint64_t> evaluate(const Spec &s, std::span<const std::uint8_t> file);

// Writes the value into the spec's field; false if it doesn't fit the file.
bool write_field(const Spec &s, std::uint64_t value, std::span<std::uint8_t> file);

// In words: "sum32 over 0..EOF", "crc32 over 0x200..EOF-padding into 0x1c (4 bytes, LE)".
std::string describe(const Spec &s);

// The PE optional header's CheckSum: its offset in the file and the value
// for these bytes (Microsoft's: 16-bit word sums with the field as zero,
// folded, plus the length). nullopt if not a PE.
std::optional<std::uint64_t> pe_checksum_offset(std::span<const std::uint8_t> file);
std::optional<std::uint32_t> pe_checksum(std::span<const std::uint8_t> file);

struct Hit {
  Spec spec;
  std::uint64_t value = 0;
  std::string evidence;  // "sum32 over 0..EOF = 0x1234ABCD, the expected value"
};

struct DetectOptions {
  // Values the rule should produce (a file name's suffix), and how to say
  // where each came from ("the file name's suffix").
  std::vector<std::pair<std::uint64_t, std::string>> expected;
  // Where the image starts in the file (a raw import's offset): ranges
  // from there are candidates too.
  std::uint64_t image_offset = 0;
  // Header words to try as stored checksums: the first this many bytes.
  std::uint64_t header_bytes = 0x200;
  std::size_t max_hits = 32;
};

struct DetectResult {
  std::vector<Hit> hits;   // name rules (expected values) first, then fields
  std::uint64_t tried = 0;  // (algorithm, range) pairs computed
};

DetectResult detect(std::span<const std::uint8_t> file, const DetectOptions &options);

// The hex runs of 4 or 8 digits in a file name, as expected values.
std::vector<std::pair<std::uint64_t, std::string>> values_in_name(std::string_view file_name);

}  // namespace revkit::patch
