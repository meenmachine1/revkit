// DataProgramInfo from a loaded image: what data analysis needs from the
// loader besides ProgramInfo.

#include "revkit/analysis/data.h"

#include <algorithm>
#include <cstring>

namespace revkit::analysis {

namespace {

// The bytes describe_data() reads (the image's, or describe_data's `bytes`).
thread_local const ByteSource *t_bytes = nullptr;

std::uint64_t read_le(const loader::Image &image, std::uint64_t addr, unsigned size, bool *ok = nullptr) {
  std::byte b[8]{};
  const std::span<std::byte> out(b, size);
  const std::size_t n = t_bytes && *t_bytes ? (*t_bytes)(addr, out) : image.memory.read(addr, out);
  if (ok) *ok = n == size;
  std::uint64_t v = 0;
  for (unsigned i = 0; i < size; ++i) v |= std::uint64_t{std::to_integer<std::uint8_t>(b[i])} << (8 * i);
  return v;
}

struct PeHeaders {
  std::uint64_t headers_end = 0;       // past the section table
  std::uint32_t reloc_rva = 0, reloc_size = 0;
  std::uint32_t exception_rva = 0, exception_size = 0;
};

std::optional<PeHeaders> pe_headers(const loader::Image &image) {
  const std::uint64_t base = image.image_base;
  bool ok = false;
  const std::uint64_t lfanew = read_le(image, base + 0x3c, 4, &ok);
  if (!ok || read_le(image, base + lfanew, 4) != 0x4550) return std::nullopt;
  const std::uint64_t coff = base + lfanew + 4;
  const std::uint64_t sections = read_le(image, coff + 2, 2);
  const std::uint64_t opt_size = read_le(image, coff + 16, 2);
  const std::uint64_t opt = coff + 20;
  const std::uint64_t magic = read_le(image, opt, 2);
  const bool plus = magic == 0x20b;
  if (!plus && magic != 0x10b) return std::nullopt;
  const std::uint64_t count = read_le(image, opt + (plus ? 108 : 92), 4);
  const std::uint64_t dirs = opt + (plus ? 112 : 96);
  PeHeaders h;
  h.headers_end = opt + opt_size + 40 * sections;
  auto dir = [&](unsigned i, std::uint32_t &rva, std::uint32_t &size) {
    if (i >= count) return;
    rva = static_cast<std::uint32_t>(read_le(image, dirs + 8 * i, 4));
    size = static_cast<std::uint32_t>(read_le(image, dirs + 8 * i + 4, 4));
  };
  dir(3, h.exception_rva, h.exception_size);
  dir(5, h.reloc_rva, h.reloc_size);
  return h;
}

void add_defined(std::vector<Range> &out, std::uint64_t first, std::uint64_t length) {
  if (length != 0 && first + length - 1 >= first) out.push_back({first, first + length - 1});
}

}  // namespace

DataProgramInfo describe_data(const loader::Image &image, const ByteSource &bytes) {
  struct Scope {
    explicit Scope(const ByteSource &b) { t_bytes = &b; }
    ~Scope() { t_bytes = nullptr; }
  } scope(bytes);
  DataProgramInfo out;
  out.present = true;
  out.pe = image.format == loader::Format::pe;
  // (A raw image has no loader markup: only its blocks.)
  const bool raw = image.format == loader::Format::raw;
  out.wide_char = out.pe ? 2 : 4;
  for (const loader::Block &b : image.blocks) {
    if (b.size == 0) continue;
    DataBlock d;
    d.name = b.name;
    d.range = {b.start, b.start + (b.size - 1)};
    d.read = b.perms.read;
    d.write = b.perms.write;
    d.exec = b.perms.exec;
    d.initialized = b.initialized;
    d.is_volatile = b.is_volatile;
    out.blocks.push_back(std::move(d));
  }
  std::sort(out.blocks.begin(), out.blocks.end(),
            [](const DataBlock &a, const DataBlock &b) { return a.range.first < b.range.first; });
  const unsigned word = image.bits / 8;

  if (out.pe) {
    if (auto h = pe_headers(image)) {
      // The headers through the section table (IMAGE_DOS_HEADER and its
      // stub, IMAGE_NT_HEADERS, the section headers).
      add_defined(out.defined, image.image_base, h->headers_end - image.image_base);
      // The exception table: one IMAGE_RUNTIME_FUNCTION_ENTRY per function.
      add_defined(out.defined, image.image_base + h->exception_rva, h->exception_size);
      // Base relocations: Ghidra's relocation table, which a pointer in
      // memory must be in.
      for (std::uint64_t at = image.image_base + h->reloc_rva, end = at + h->reloc_size;
           h->reloc_rva != 0 && at + 8 <= end;) {
        const std::uint64_t page = read_le(image, at, 4), size = read_le(image, at + 4, 4);
        if (size < 8 || size > end - at) break;  // a block past the directory: 2^31 reads
        for (std::uint64_t e = at + 8; e + 2 <= at + size; e += 2) {
          const std::uint64_t v = read_le(image, e, 2);
          const unsigned type = static_cast<unsigned>(v >> 12);
          if (type == 10 || type == 3) out.relocations.push_back(image.image_base + page + (v & 0xfff));
        }
        at += size;
      }
      out.relocatable = !out.relocations.empty();
    }
    // Import slots: pointers into the EXTERNAL space.
    for (const loader::Import &imp : image.imports)
      if (imp.iat_address != 0) add_defined(out.defined, imp.iat_address, word);
  } else if (!raw) {
    // ET_DYN, ET_REL; a Mach-O but an MH_EXECUTE (MachoProgramBuilder.setRelocatableProperty).
    out.relocatable = image.macho ? image.macho->filetype != 2 : image.elf_type == 3 || image.elf_type == 1;
    for (const loader::Relocation &r : image.relocations) {
      out.relocations.push_back(r.address);
      switch (r.kind) {
        case loader::RelocationKind::relative:
        case loader::RelocationKind::irelative:
        case loader::RelocationKind::jump_slot:
        case loader::RelocationKind::glob_dat:
        case loader::RelocationKind::absolute:
          add_defined(out.defined, r.address, word);
          if (r.kind == loader::RelocationKind::relative && r.target && image.memory.is_mapped(*r.target))
            out.pointers.emplace_back(r.address, *r.target);
          break;
        default: break;
      }
    }
    // Every entry of a .got section is a pointer (ElfDefaultGotPltMarkup);
    // the first one, the link-time address of _DYNAMIC, is rebased.
    std::uint64_t dynamic = 0;
    for (const loader::Section &sec : image.sections)
      if (sec.name == ".dynamic") dynamic = sec.addr;
    const std::uint64_t adjust = image.image_base - image.file_base;
    std::vector<std::uint64_t> relocated;
    for (const loader::Relocation &r : image.relocations) relocated.push_back(r.address);
    std::sort(relocated.begin(), relocated.end());
    // A Mach-O's pointer sections likewise (MachoProgramBuilder.markupSections:
    // S_LITERAL_POINTERS, S_NON_LAZY_SYMBOL_POINTERS, S_LAZY_SYMBOL_POINTERS).
    auto pointer_section = [&](const loader::Section &sec) {
      if (image.format == loader::Format::macho) return sec.type == 5 || sec.type == 6 || sec.type == 7;
      return sec.name.starts_with(".got");
    };
    for (const loader::Section &sec : image.sections) {
      if (!pointer_section(sec) || !sec.alloc || sec.file_size == 0 || sec.size < word) continue;
      for (std::uint64_t at = sec.addr; at + word <= sec.addr + sec.size; at += word) {
        bool ok = false;
        std::uint64_t v = word == 8 ? read_le(image, at, 8, &ok) : read_le(image, at, 4, &ok);
        if (!ok) break;
        if (at == sec.addr && adjust != 0 && dynamic != 0 && v + adjust == dynamic) v = dynamic;
        if (std::binary_search(relocated.begin(), relocated.end(), at)) continue;  // a relocated slot
        out.loader_pointers.emplace_back(at, v);
      }
    }
    // (Ghidra's Mach-O loader makes its symbols labels: they have no size.)
    for (const loader::Symbol &s : image.symbols)
      if (image.format != loader::Format::macho && s.defined && s.type == loader::SymbolType::object &&
          image.memory.is_mapped(s.value))
        out.symbols.emplace_back(s.value, s.size == 0 || s.size > 8 ? 1u : static_cast<std::uint32_t>(s.size));
  }
  std::sort(out.relocations.begin(), out.relocations.end());
  out.relocations.erase(std::unique(out.relocations.begin(), out.relocations.end()), out.relocations.end());
  // Disjoint: a later range that overlaps an earlier one is cut.
  std::sort(out.defined.begin(), out.defined.end());
  std::vector<Range> defined;
  for (Range r : out.defined) {
    if (!defined.empty() && r.first <= defined.back().last) {
      if (r.last <= defined.back().last) continue;
      r.first = defined.back().last + 1;
    }
    defined.push_back(r);
  }
  out.defined = std::move(defined);
  std::sort(out.pointers.begin(), out.pointers.end());
  out.pointers.erase(std::unique(out.pointers.begin(), out.pointers.end(),
                                 [](const auto &a, const auto &b) { return a.first == b.first; }),
                     out.pointers.end());
  std::sort(out.loader_pointers.begin(), out.loader_pointers.end());
  std::sort(out.symbols.begin(), out.symbols.end());
  out.symbols.erase(std::unique(out.symbols.begin(), out.symbols.end(),
                                [](const auto &a, const auto &b) { return a.first == b.first; }),
                    out.symbols.end());
  return out;
}

}  // namespace revkit::analysis
