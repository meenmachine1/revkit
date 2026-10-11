#include "relocate.h"

#include <cstring>
#include <optional>

namespace revkit::backend {
namespace {

constexpr std::uint32_t kShtRela = 4, kShtRel = 9, kShtRelr = 19;

// RELATIVE relocation type per ELF machine.
std::optional<std::uint32_t> RelativeType(std::uint32_t machine) {
  switch (machine) {
    case 3: return 8;      // EM_386: R_386_RELATIVE
    case 62: return 8;     // EM_X86_64: R_X86_64_RELATIVE
    case 40: return 23;    // EM_ARM: R_ARM_RELATIVE
    case 183: return 1027; // EM_AARCH64: R_AARCH64_RELATIVE
    case 243: return 3;    // EM_RISCV: R_RISCV_RELATIVE
    case 20:               // EM_PPC
    case 21: return 22;    // EM_PPC64: R_PPC*_RELATIVE
    default: return std::nullopt;
  }
}

class Patcher {
 public:
  Patcher(const loader::Image &image, loader::Bytes &bytes) : image_(image), bytes_(bytes) {}

  std::uint64_t Read(std::uint64_t off, unsigned size) const {
    std::uint64_t v = 0;
    for (unsigned i = 0; i < size; ++i) {
      unsigned shift = image_.endian == loader::Endian::little ? 8 * i : 8 * (size - 1 - i);
      v |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes_[off + i])) << shift;
    }
    return v;
  }
  void Write(std::uint64_t off, unsigned size, std::uint64_t v) {
    for (unsigned i = 0; i < size; ++i) {
      unsigned shift = image_.endian == loader::Endian::little ? 8 * i : 8 * (size - 1 - i);
      bytes_[off + i] = static_cast<std::byte>((v >> shift) & 0xff);
    }
  }
  // File offset of `size` bytes at link-time address `va`, if file-backed.
  std::optional<std::uint64_t> FileOffset(std::uint64_t va, unsigned size) const {
    for (const loader::Segment &s : image_.segments) {
      if (s.type != 1 || va < s.vaddr || va - s.vaddr + size > s.file_size) continue;  // PT_LOAD
      std::uint64_t off = s.offset + (va - s.vaddr);
      if (off + size <= bytes_.size()) return off;
    }
    return std::nullopt;
  }
  bool Relocate(std::uint64_t va, unsigned word, std::optional<std::uint64_t> addend, std::uint64_t delta) {
    auto off = FileOffset(va, word);
    if (!off) return false;
    std::uint64_t value = (addend ? *addend : Read(*off, word)) + delta;
    if (word == 4) value &= 0xffffffffu;
    Write(*off, word, value);
    return true;
  }
  bool InFile(std::uint64_t off, std::uint64_t size) const { return off <= bytes_.size() && size <= bytes_.size() - off; }

 private:
  const loader::Image &image_;
  loader::Bytes &bytes_;
};

}  // namespace

std::shared_ptr<const loader::Bytes> RelocateRelative(const loader::Image &linked, std::uint64_t delta,
                                                      std::vector<std::string> &warnings) {
  if (linked.format != loader::Format::elf || delta == 0 || !linked.file) return nullptr;
  const auto relative = RelativeType(linked.machine);
  if (!relative) return nullptr;
  const unsigned word = linked.bits == 64 ? 8 : 4;

  auto bytes = std::make_shared<loader::Bytes>(*linked.file);
  Patcher patch(linked, *bytes);
  std::size_t applied = 0, skipped = 0;
  for (const loader::Section &s : linked.sections) {
    if (s.type != kShtRela && s.type != kShtRel && s.type != kShtRelr) continue;
    if (!patch.InFile(s.offset, s.size)) continue;
    if (s.type == kShtRelr) {
      // Even entries are addresses; odd entries are bitmaps of the
      // following word-sized slots.
      std::uint64_t where = 0;
      for (std::uint64_t at = s.offset; at + word <= s.offset + s.size; at += word) {
        std::uint64_t entry = patch.Read(at, word);
        if ((entry & 1) == 0) {
          where = entry;
          (patch.Relocate(where, word, std::nullopt, delta) ? applied : skipped)++;
          where += word;
        } else {
          for (unsigned bit = 1; bit < 8 * word; ++bit)
            if ((entry >> bit) & 1) (patch.Relocate(where + (bit - 1) * word, word, std::nullopt, delta) ? applied : skipped)++;
          where += (8 * word - 1) * word;
        }
      }
      continue;
    }
    const bool rela = s.type == kShtRela;
    const std::uint64_t entsize = word * (rela ? 3 : 2);
    for (std::uint64_t at = s.offset; at + entsize <= s.offset + s.size; at += entsize) {
      std::uint64_t r_offset = patch.Read(at, word);
      std::uint64_t r_info = patch.Read(at + word, word);
      std::uint32_t type = word == 8 ? static_cast<std::uint32_t>(r_info & 0xffffffffu) : static_cast<std::uint32_t>(r_info & 0xff);
      if (type != *relative) continue;
      std::optional<std::uint64_t> addend;
      if (rela) {
        addend = patch.Read(at + 2 * word, word);
        if (word == 4) addend = static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(*addend)));
      }
      (patch.Relocate(r_offset, word, addend, delta) ? applied : skipped)++;
    }
  }
  if (applied == 0) return nullptr;
  if (skipped) warnings.push_back(std::to_string(skipped) + " RELATIVE relocations point outside the file's bytes");
  return bytes;
}

}  // namespace revkit::backend
