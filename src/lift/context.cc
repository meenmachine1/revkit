#include "revkit/lift/context.hh"

#include <algorithm>

namespace revkit::lift {

namespace {

constexpr std::uint32_t kElfMachineArm = 40;

bool is_arm(const loader::Image &image) {
  return image.format == loader::Format::elf && image.machine == kElfMachineArm;
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
  return is_arm(image) && symbol.type == loader::SymbolType::func && (symbol.value & 1) != 0;
}

std::uint64_t function_address(const loader::Image &image, const loader::Symbol &symbol) {
  return is_thumb_function(image, symbol) ? symbol.value & ~std::uint64_t{1} : symbol.value;
}

std::vector<ContextRegion> image_context(const loader::Image &image) {
  std::vector<ContextRegion> out;
  if (!is_arm(image)) return out;
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
