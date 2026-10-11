// Section contents for consumers such as the DWARF reader.

#include "revkit/loader/load.hh"

#include "reader.hh"

#include <zlib.h>

#include <algorithm>
#include <limits>

namespace revkit::loader {

namespace {

constexpr std::uint64_t kShfCompressed = 0x800;
constexpr std::uint32_t kElfCompressZlib = 1;
constexpr std::uint64_t kMaxInflated = std::uint64_t(1) << 30;
// Deflate can't expand data more than about 1032:1.
constexpr std::uint64_t kMaxRatio = 1100;

}  // namespace

const Section *find_section(const Image &image, std::string_view name) {
  for (const Section &s : image.sections)
    if (s.name == name) return &s;
  return nullptr;
}

std::span<const std::byte> section_bytes(const Image &image, const Section &section) {
  if (!image.file || section.file_size == 0) return {};
  std::uint64_t len = section.file_size;
  if (image.format == Format::pe && section.virtual_size != 0) len = std::min(len, section.virtual_size);
  const Bytes &file = *image.file;
  if (section.offset > file.size() || len > file.size() - section.offset) return {};
  return std::span<const std::byte>(file).subspan(std::size_t(section.offset), std::size_t(len));
}

Bytes section_contents(const Image &image, const Section &section) {
  std::span<const std::byte> raw = section_bytes(image, section);
  if (image.format != Format::elf || !(section.flags & kShfCompressed) || raw.empty())
    return Bytes(raw.begin(), raw.end());

  // Elf32_Chdr / Elf64_Chdr: type, [reserved], size, addralign.
  detail::Reader r(raw, image.endian);
  const bool wide = image.bits == 64;
  const std::uint64_t header = wide ? 24 : 12;
  r.require(0, header, "ELF compression header of " + section.name);
  std::uint32_t type = r.u32(0);
  if (type != kElfCompressZlib)
    detail::fail("ELF: section " + section.name + " uses unsupported compression type " +
                 std::to_string(type));
  std::uint64_t out_size = r.word(wide ? 8 : 4, wide);
  std::uint64_t in_size = raw.size() - header;
  if (out_size > kMaxInflated || out_size > in_size * kMaxRatio + 4096)
    detail::fail("ELF: section " + section.name + " claims an implausible inflated size " +
                 detail::hex(out_size));
  Bytes out(static_cast<std::size_t>(out_size));
  uLongf len = static_cast<uLongf>(out_size);
  int rc = uncompress(reinterpret_cast<Bytef *>(out.data()), &len,
                      reinterpret_cast<const Bytef *>(raw.data() + header), static_cast<uLong>(in_size));
  if (rc != Z_OK) detail::fail("ELF: section " + section.name + " fails to inflate (zlib error " +
                               std::to_string(rc) + ")");
  out.resize(len);
  return out;
}

}  // namespace revkit::loader
