#include "revkit/debuginfo/image.h"

#include "revkit/loader/load.hh"

namespace revkit::debuginfo {

ImageSections dwarf_sections(const loader::Image &image) {
  ImageSections out;
  out.sections.byte_order =
      image.endian == loader::Endian::big ? std::endian::big : std::endian::little;
  out.sections.address_size = std::uint8_t(image.bits / 8);
  out.storage.reserve(image.sections.size());
  for (const loader::Section &s : image.sections) {
    if (!s.name.starts_with(".debug_") || out.sections.by_name.count(s.name)) continue;
    std::span<const std::byte> raw = loader::section_bytes(image, s);
    std::span<const std::uint8_t> data(reinterpret_cast<const std::uint8_t *>(raw.data()), raw.size());
    if (image.format == loader::Format::elf && (s.flags & 0x800 /* SHF_COMPRESSED */)) {
      try {
        out.storage.push_back(loader::section_contents(image, s));
      } catch (const loader::LoadError &e) {
        out.warnings.push_back(e.what());
        continue;
      }
      const loader::Bytes &b = out.storage.back();
      data = {reinterpret_cast<const std::uint8_t *>(b.data()), b.size()};
    }
    out.sections.by_name.emplace(s.name, data);
  }
  return out;
}

bool is_code(const loader::Image &image, std::uint64_t addr) {
  for (const loader::Section &s : image.sections)
    if (s.alloc && s.perms.exec && addr >= s.addr && addr - s.addr < s.size) return true;
  return false;
}

}  // namespace revkit::debuginfo
