#include "revkit/lift/context.hh"

#include <algorithm>

namespace revkit::lift {

namespace {

constexpr std::uint32_t kElfMachineArm = 40;
constexpr std::uint32_t kMachoCpuArm = 12;

bool is_arm(const loader::Image &image) {
  return (image.format == loader::Format::elf && image.machine == kElfMachineArm) ||
         (image.format == loader::Format::macho && image.machine == kMachoCpuArm);
}

// A Mach-O's Thumb functions: symbols with N_ARM_THUMB_DEF (the loader
// sets bit 0) and odd LC_FUNCTION_STARTS entries, each to the next
// function start or its section's end (nlist has no sizes).
void macho_thumb(const loader::Image &image, std::vector<ContextRegion> &out) {
  std::vector<std::pair<std::uint64_t, bool>> starts;  // address, thumb
  for (const loader::Symbol &s : image.symbols)
    if (s.defined && s.type == loader::SymbolType::func) starts.emplace_back(s.value & ~std::uint64_t{1}, (s.value & 1) != 0);
  if (image.macho)
    for (std::uint64_t f : image.macho->function_starts) starts.emplace_back(f & ~std::uint64_t{1}, (f & 1) != 0);
  std::sort(starts.begin(), starts.end(), [](const auto &a, const auto &b) {
    return a.first != b.first ? a.first < b.first : a.second > b.second;  // Thumb first at an address
  });
  for (std::size_t i = 0; i < starts.size(); ++i) {
    if (!starts[i].second || (i > 0 && starts[i - 1].first == starts[i].first)) continue;
    const std::uint64_t start = starts[i].first;
    std::uint64_t end = start;
    for (const loader::Section &sec : image.sections)
      if (sec.perms.exec && start >= sec.addr && start - sec.addr < sec.size) end = sec.addr + sec.size;
    for (std::size_t j = i + 1; j < starts.size(); ++j)
      if (starts[j].first > start) {
        end = std::min(end, starts[j].first);
        break;
      }
    if (end > start) out.push_back({"TMode", 1, start, end});
  }
}

// Mapping symbol kind ('a', 't', 'x', 'd'), or 0. Names are "$a" or
// "$a.<anything>"; RISC-V also writes "$x<isa string>".
char mapping_kind(const loader::Symbol &s) {
  if (s.source != loader::SymbolSource::symtab || !s.defined || s.name.size() < 2 || s.name[0] != '$')
    return 0;
  char k = s.name[1];
  if (k != 'a' && k != 't' && k != 'x' && k != 'd') return 0;
  if (s.name.size() > 2 && s.name[2] != '.' && k != 'x') return 0;
  return k;
}

struct Mapping {
  std::uint64_t start;
  std::uint64_t end;  // exclusive
  char kind;
};

// Each mapping symbol governs from its address to the next mapping symbol in
// the same section, or the section's end.
std::vector<Mapping> mappings(const loader::Image &image) {
  struct Mark {
    std::uint32_t section;
    std::uint64_t addr;
    char kind;
  };
  std::vector<Mark> marks;
  for (const loader::Symbol &s : image.symbols) {
    char k = mapping_kind(s);
    if (k == 0 || s.section_index == 0 || s.section_index >= image.sections.size()) continue;
    const loader::Section &sec = image.sections[s.section_index];
    if (!sec.alloc || !sec.perms.exec) continue;  // only code sections matter
    marks.push_back({s.section_index, s.value, k});
  }
  std::sort(marks.begin(), marks.end(), [](const Mark &a, const Mark &b) {
    return a.section != b.section ? a.section < b.section : a.addr < b.addr;
  });

  std::vector<Mapping> out;
  for (std::size_t i = 0; i < marks.size(); ++i) {
    const loader::Section &sec = image.sections[marks[i].section];
    std::uint64_t end = sec.addr + sec.size;
    if (i + 1 < marks.size() && marks[i + 1].section == marks[i].section) end = marks[i + 1].addr;
    if (end > marks[i].addr) out.push_back({marks[i].addr, end, marks[i].kind});
  }
  return out;
}

}  // namespace

bool is_thumb_function(const loader::Image &image, const loader::Symbol &symbol) {
  // (Mach-O Thumb symbols have bit 0 set by the loader, as ELF's do.)
  return is_arm(image) && symbol.type == loader::SymbolType::func && (symbol.value & 1) != 0;
}

std::uint64_t function_address(const loader::Image &image, const loader::Symbol &symbol) {
  return is_thumb_function(image, symbol) ? symbol.value & ~std::uint64_t{1} : symbol.value;
}

std::vector<ContextRegion> image_context(const loader::Image &image) {
  std::vector<ContextRegion> out;
  if (!is_arm(image)) return out;
  if (image.format == loader::Format::macho) {
    macho_thumb(image, out);
    return out;
  }
  for (const Mapping &m : mappings(image))
    if (m.kind == 't') out.push_back({"TMode", 1, m.start, m.end});
  // Function symbols cover stripped-of-mapping-symbol binaries (.dynsym only).
  for (const loader::Symbol &s : image.symbols) {
    if (!s.defined || s.size == 0 || !is_thumb_function(image, s)) continue;
    std::uint64_t start = function_address(image, s);
    out.push_back({"TMode", 1, start, start + s.size});
  }
  std::sort(out.begin(), out.end(), [](const ContextRegion &a, const ContextRegion &b) {
    return a.start != b.start ? a.start < b.start : a.end < b.end;
  });
  return out;
}

std::vector<AddressRange> embedded_data(const loader::Image &image) {
  std::vector<AddressRange> out;
  // A Mach-O says where data is in code itself (LC_DATA_IN_CODE).
  if (image.format == loader::Format::macho) {
    if (image.macho)
      for (const auto &[start, end] : image.macho->data_in_code)
        if (end > start) out.emplace_back(start, end - 1);
    return out;
  }
  // ARM and AArch64 toolchains mark literal pools and inline tables with $d.
  // Elsewhere (RISC-V libgcc) $d can sit inside straight-line code, and
  // Ghidra disassembles through it, so we don't honour it.
  constexpr std::uint32_t kElfMachineAArch64 = 183;
  if (!is_arm(image) && !(image.format == loader::Format::elf && image.machine == kElfMachineAArch64)) return out;
  for (const Mapping &m : mappings(image))
    if (m.kind == 'd') out.emplace_back(m.start, m.end - 1);
  std::sort(out.begin(), out.end());
  return out;
}

}  // namespace revkit::lift
