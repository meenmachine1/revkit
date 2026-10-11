// ELF32/ELF64 parser, either endianness.
//
// Policy: anything needed to map the image (ELF header, program headers,
// PT_LOAD layout) must be valid or we throw. Metadata that only adds detail
// (section headers, symbol tables, string tables) is dropped with a warning
// when it is unreadable, so a stripped or damaged binary still loads.

#include "revkit/loader/load.hh"

#include "reader.hh"

#include <algorithm>
#include <array>
#include <limits>
#include <map>

namespace revkit::loader {

namespace {

using detail::checked_add;
using detail::checked_mul;
using detail::fail;
using detail::hex;
using detail::Reader;

constexpr std::uint16_t ET_REL = 1;
constexpr std::uint16_t ET_EXEC = 2;
constexpr std::uint16_t ET_DYN = 3;

constexpr std::uint32_t PT_LOAD = 1;
constexpr std::uint32_t PT_DYNAMIC = 2;
constexpr std::uint32_t PT_GNU_RELRO = 0x6474e552;
constexpr std::uint32_t PF_X = 1;
constexpr std::uint32_t PF_W = 2;
constexpr std::uint32_t PF_R = 4;

constexpr std::uint32_t SHT_NULL = 0;
constexpr std::uint32_t SHT_SYMTAB = 2;
constexpr std::uint32_t SHT_STRTAB = 3;
constexpr std::uint32_t SHT_NOBITS = 8;
constexpr std::uint32_t SHT_RELA = 4;
constexpr std::uint32_t SHT_DYNAMIC = 6;
constexpr std::uint32_t SHT_REL = 9;
constexpr std::uint32_t SHT_DYNSYM = 11;
constexpr std::uint32_t SHT_INIT_ARRAY = 14;
constexpr std::uint32_t SHT_FINI_ARRAY = 15;
constexpr std::uint32_t SHT_PREINIT_ARRAY = 16;
constexpr std::uint32_t SHT_RELR = 19;
constexpr std::uint64_t SHF_WRITE = 0x1;
constexpr std::uint64_t SHF_ALLOC = 0x2;
constexpr std::uint64_t SHF_EXECINSTR = 0x4;
constexpr std::uint64_t SHF_TLS = 0x400;

constexpr std::uint16_t SHN_UNDEF = 0;
constexpr std::uint16_t SHN_LORESERVE = 0xff00;
constexpr std::uint16_t SHN_XINDEX = 0xffff;
constexpr std::uint16_t PN_XNUM = 0xffff;

constexpr std::uint16_t EM_386 = 3;
constexpr std::uint16_t EM_PPC = 20;
constexpr std::uint16_t EM_PPC64 = 21;
constexpr std::uint16_t EM_ARM = 40;
constexpr std::uint16_t EM_X86_64 = 62;
constexpr std::uint16_t EM_AARCH64 = 183;
constexpr std::uint16_t EM_RISCV = 243;
constexpr std::uint16_t EM_AVR = 83;

constexpr std::int64_t DT_NULL = 0;
constexpr std::int64_t DT_NEEDED = 1;
constexpr std::int64_t DT_STRTAB = 5;
constexpr std::int64_t DT_STRSZ = 10;
constexpr std::int64_t DT_SONAME = 14;
constexpr std::int64_t DT_RPATH = 15;
constexpr std::int64_t DT_RUNPATH = 29;
constexpr std::uint32_t PT_NOTE = 4;
constexpr std::uint32_t SHT_NOTE = 7;
constexpr std::uint32_t NT_GNU_BUILD_ID = 3;
constexpr std::int64_t DT_INIT = 12;
constexpr std::int64_t DT_FINI = 13;
constexpr std::int64_t DT_INIT_ARRAY = 25;
constexpr std::int64_t DT_FINI_ARRAY = 26;
constexpr std::int64_t DT_INIT_ARRAYSZ = 27;
constexpr std::int64_t DT_FINI_ARRAYSZ = 28;
constexpr std::int64_t DT_PREINIT_ARRAY = 32;
constexpr std::int64_t DT_PREINIT_ARRAYSZ = 33;

// Relocation types per machine for the kinds RelocationKind names.
struct RelocationTypes {
  static constexpr std::uint32_t none = 0xffffffffu;
  std::uint32_t relative = none, irelative = none, jump_slot = none, glob_dat = none;
  std::uint32_t abs_word = none, abs_half = none;  // pointer-sized and 32-bit absolute
};

RelocationTypes relocation_types(std::uint16_t machine) {
  constexpr std::uint32_t none = RelocationTypes::none;
  switch (machine) {
    case EM_X86_64: return {8, 37, 7, 6, 1, 10};       // R_X86_64_64, R_X86_64_32
    case EM_386: return {8, 42, 7, 6, 1, none};        // R_386_32
    case EM_AARCH64: return {1027, 1032, 1026, 1025, 257, 258};  // ABS64, ABS32
    case EM_ARM: return {23, 160, 22, 21, 2, none};    // R_ARM_ABS32
    case EM_RISCV: return {3, 58, 5, none, 2, 1};      // R_RISCV_64, R_RISCV_32 (no GLOB_DAT)
    case EM_PPC: return {22, 248, 21, 20, 1, none};    // R_PPC_ADDR32
    case EM_PPC64: return {22, 248, 21, 20, 38, 1};    // R_PPC64_ADDR64, ADDR32
    default: return {};
  }
}

RelocationKind relocation_kind(const RelocationTypes &t, std::uint32_t type) {
  if (type == RelocationTypes::none) return RelocationKind::other;
  if (type == t.relative) return RelocationKind::relative;
  if (type == t.irelative) return RelocationKind::irelative;
  if (type == t.jump_slot) return RelocationKind::jump_slot;
  if (type == t.glob_dat) return RelocationKind::glob_dat;
  if (type == t.abs_word || type == t.abs_half) return RelocationKind::absolute;
  return RelocationKind::other;
}

// Ghidra only looks at this many program headers when choosing a base.
constexpr std::uint64_t kMaxHeadersForBase = 100;

struct Header {
  bool wide = false;  // ELFCLASS64
  std::uint16_t type = 0;
  std::uint16_t machine = 0;
  std::uint32_t flags = 0;
  std::uint64_t entry = 0;
  std::uint64_t phoff = 0;
  std::uint64_t shoff = 0;
  std::uint16_t phentsize = 0;
  std::uint16_t shentsize = 0;
  std::uint64_t phnum = 0;
  std::uint64_t shnum = 0;
  std::uint32_t shstrndx = 0;
};

class ElfParser {
 public:
  ElfParser(std::shared_ptr<const Bytes> file, const LoadOptions &options)
      : file_(std::move(file)), r_(*file_, Endian::little), options_(options) {}

  Image run() {
    img_.format = Format::elf;
    img_.file = file_;
    img_.memory = Memory(file_);

    read_header();
    read_section_headers();
    read_program_headers();
    choose_base();
    layout_relocatable();
    build_memory();
    read_symbols();
    read_eh_frame();
    read_relocations();
    read_plt_sections();
    read_init_fini();
    read_dynamic_names();
    read_build_id();
    build_blocks();
    // The processor spec's spaces and default blocks (32-bit and smaller
    // languages: AVR's SRAM, RISC-V's CSRs).
    std::optional<LanguageMemory> lm;
    if (!h_.wide && !relocatable())
      if (auto lang = guess_language(img_)) lm = language_memory(lang->language);
    if (lm) apply_language_memory(img_, *lm, false);
    if (h_.machine == EM_AVR) avr_spaces();
    if (lm) apply_language_memory(img_, *lm, true);
    return std::move(img_);
  }

 private:
  void warn(std::string msg) { img_.warnings.push_back(std::move(msg)); }

  std::uint64_t addr_limit() const {
    return h_.wide ? std::numeric_limits<std::uint64_t>::max() : 0xffffffffULL;
  }

  // Shift a file address by the rebase delta, wrapping within the address
  // space of the image's class.
  std::uint64_t shift(std::uint64_t addr) const {
    std::uint64_t a = addr + delta_;  // modular, like the hardware
    if (!h_.wide) a &= 0xffffffffULL;
    return a;
  }

  void read_header() {
    r_.require(0, 16, "ELF identification");
    std::uint8_t cls = r_.u8(4);
    std::uint8_t data = r_.u8(5);
    if (cls != 1 && cls != 2) fail("ELF: bad class " + std::to_string(cls));
    if (data != 1 && data != 2) fail("ELF: bad data encoding " + std::to_string(data));
    if (r_.u8(6) != 1) warn("ELF: unexpected EI_VERSION " + std::to_string(r_.u8(6)));
    h_.wide = cls == 2;
    r_.set_endian(data == 1 ? Endian::little : Endian::big);
    img_.endian = r_.endian();
    img_.bits = h_.wide ? 64 : 32;

    const std::uint64_t ehsize = h_.wide ? 64 : 52;
    r_.require(0, ehsize, "ELF header");
    h_.type = r_.u16(16);
    h_.machine = r_.u16(18);
    h_.entry = r_.word(24, h_.wide);
    if (h_.wide) {
      h_.phoff = r_.u64(32);
      h_.shoff = r_.u64(40);
      h_.flags = r_.u32(48);
      h_.phentsize = r_.u16(54);
      h_.phnum = r_.u16(56);
      h_.shentsize = r_.u16(58);
      h_.shnum = r_.u16(60);
      h_.shstrndx = r_.u16(62);
    } else {
      h_.phoff = r_.u32(28);
      h_.shoff = r_.u32(32);
      h_.flags = r_.u32(36);
      h_.phentsize = r_.u16(42);
      h_.phnum = r_.u16(44);
      h_.shentsize = r_.u16(46);
      h_.shnum = r_.u16(48);
      h_.shstrndx = r_.u16(50);
    }
    img_.machine = h_.machine;
    img_.flags = h_.flags;
    img_.elf_type = h_.type;
  }

  // Reads one section header. `i` must already be range-checked.
  Section read_shdr(std::uint64_t off) const {
    Section s;
    if (h_.wide) {
      s.type = r_.u32(off + 4);
      s.flags = r_.u64(off + 8);
      s.addr = r_.u64(off + 16);
      s.offset = r_.u64(off + 24);
      s.size = r_.u64(off + 32);
      s.link = r_.u32(off + 40);
      s.info = r_.u32(off + 44);
      s.addralign = r_.u64(off + 48);
      s.entsize = r_.u64(off + 56);
    } else {
      s.type = r_.u32(off + 4);
      s.flags = r_.u32(off + 8);
      s.addr = r_.u32(off + 12);
      s.offset = r_.u32(off + 16);
      s.size = r_.u32(off + 20);
      s.link = r_.u32(off + 24);
      s.info = r_.u32(off + 28);
      s.addralign = r_.u32(off + 32);
      s.entsize = r_.u32(off + 36);
    }
    return s;
  }

  void read_section_headers() {
    if (h_.shoff == 0) {
      if (h_.phnum == PN_XNUM) fail("ELF: e_phnum is PN_XNUM but there are no section headers");
      return;
    }
    const std::uint64_t min_ent = h_.wide ? 64 : 40;
    if (h_.shentsize < min_ent) {
      warn("ELF: e_shentsize " + std::to_string(h_.shentsize) + " too small; ignoring section headers");
      if (h_.phnum == PN_XNUM) fail("ELF: e_phnum is PN_XNUM but section 0 is unreadable");
      return;
    }
    if (!r_.has(h_.shoff, h_.shentsize)) {
      warn("ELF: section header table at " + hex(h_.shoff) + " is outside the file; ignoring it");
      if (h_.phnum == PN_XNUM) fail("ELF: e_phnum is PN_XNUM but section 0 is unreadable");
      return;
    }

    // Extended numbering: the real counts live in section 0.
    Section s0 = read_shdr(h_.shoff);
    std::uint64_t shnum = h_.shnum;
    if (shnum == 0) shnum = s0.size;
    if (h_.shstrndx == SHN_XINDEX) h_.shstrndx = s0.link;
    if (h_.phnum == PN_XNUM) h_.phnum = s0.info;

    std::uint64_t table = checked_mul(shnum, h_.shentsize, "ELF section header table");
    if (!r_.has(h_.shoff, table)) {
      warn("ELF: section header table (" + std::to_string(shnum) + " entries at " + hex(h_.shoff) +
           ") extends past end of file; ignoring it");
      return;
    }
    h_.shnum = shnum;

    img_.sections.reserve(static_cast<std::size_t>(shnum));
    for (std::uint64_t i = 0; i < shnum; ++i) {
      Section s = read_shdr(h_.shoff + i * h_.shentsize);
      s.alloc = (s.flags & SHF_ALLOC) != 0;
      s.perms = {true, (s.flags & SHF_WRITE) != 0, (s.flags & SHF_EXECINSTR) != 0};
      s.file_size = s.type == SHT_NOBITS ? 0 : s.size;
      if (s.type != SHT_NOBITS && !r_.has(s.offset, s.size)) {
        if (s.type != SHT_NULL) warn("ELF: section " + std::to_string(i) + " data is outside the file");
        s.file_size = 0;
      }
      img_.sections.push_back(std::move(s));
    }

    // Section names, from the section-header string table.
    std::optional<std::span<const std::byte>> names;
    if (h_.shstrndx != 0) {
      if (h_.shstrndx < img_.sections.size() && img_.sections[h_.shstrndx].file_size != 0) {
        const Section &st = img_.sections[h_.shstrndx];
        names = r_.bytes(st.offset, st.file_size, "ELF section name table");
      } else {
        warn("ELF: bad e_shstrndx " + std::to_string(h_.shstrndx));
      }
    }
    if (names) {
      for (std::uint64_t i = 0; i < shnum; ++i) {
        std::uint32_t name_off = r_.u32(h_.shoff + i * h_.shentsize);
        img_.sections[static_cast<std::size_t>(i)].name = string_at(*names, name_off);
      }
    }
  }

  // NUL-terminated string inside a string table; "" if it runs off the end.
  static std::string string_at(std::span<const std::byte> table, std::uint64_t off) {
    if (off >= table.size()) return {};
    auto begin = table.begin() + static_cast<std::ptrdiff_t>(off);
    auto end = std::find(begin, table.end(), std::byte{0});
    if (end == table.end()) return {};
    return std::string(reinterpret_cast<const char *>(&*begin), static_cast<std::size_t>(end - begin));
  }

  void read_program_headers() {
    if (h_.phnum == 0) return;
    if (h_.phoff == 0) fail("ELF: e_phnum is " + std::to_string(h_.phnum) + " but e_phoff is 0");
    const std::uint64_t min_ent = h_.wide ? 56 : 32;
    if (h_.phentsize < min_ent) fail("ELF: e_phentsize " + std::to_string(h_.phentsize) + " too small");
    std::uint64_t table = checked_mul(h_.phnum, h_.phentsize, "ELF program header table");
    r_.require(h_.phoff, table, "ELF program header table");

    img_.segments.reserve(static_cast<std::size_t>(h_.phnum));
    for (std::uint64_t i = 0; i < h_.phnum; ++i) {
      std::uint64_t off = h_.phoff + i * h_.phentsize;
      Segment s;
      s.type = r_.u32(off);
      if (h_.wide) {
        s.flags = r_.u32(off + 4);
        s.offset = r_.u64(off + 8);
        s.vaddr = r_.u64(off + 16);
        s.paddr = r_.u64(off + 24);
        s.file_size = r_.u64(off + 32);
        s.mem_size = r_.u64(off + 40);
        s.align = r_.u64(off + 48);
      } else {
        s.offset = r_.u32(off + 4);
        s.vaddr = r_.u32(off + 8);
        s.paddr = r_.u32(off + 12);
        s.file_size = r_.u32(off + 16);
        s.mem_size = r_.u32(off + 20);
        s.flags = r_.u32(off + 24);
        s.align = r_.u32(off + 28);
      }
      img_.segments.push_back(s);
    }
  }

  bool relocatable() const { return h_.type == ET_REL; }

  void choose_base() {
    // The file's own base: the lowest PT_LOAD address.
    std::optional<std::uint64_t> lowest;
    std::uint64_t n = std::min<std::uint64_t>(img_.segments.size(), kMaxHeadersForBase);
    if (!relocatable()) {
      for (std::uint64_t i = 0; i < n; ++i) {
        const Segment &s = img_.segments[static_cast<std::size_t>(i)];
        if (s.type == PT_LOAD && (!lowest || s.vaddr < *lowest)) lowest = s.vaddr;
      }
    }
    std::uint64_t file_base = lowest.value_or(0);

    std::uint64_t base = file_base;
    if (options_.image_base) {
      base = *options_.image_base;
    } else if (options_.ghidra_image_base && file_base == 0 && (h_.type == ET_DYN || relocatable())) {
      base = h_.wide ? 0x100000 : 0x10000;
    }
    if (base > addr_limit()) fail("ELF: image base " + hex(base) + " does not fit a 32-bit image");
    delta_ = base - file_base;
    img_.image_base = base;
    img_.file_base = file_base;

    for (Segment &s : img_.segments) s.vaddr = shift(s.vaddr);
    if (!relocatable()) {
      for (Section &s : img_.sections)
        if (s.alloc) s.addr = shift(s.addr);
    }
    if (h_.type == ET_EXEC || (h_.type == ET_DYN && h_.entry != 0)) img_.entry = shift(h_.entry);
  }

  // Object files have no addresses: pack allocated sections from the base,
  // honouring alignment, the way Ghidra does for relocatable images.
  void layout_relocatable() {
    if (!relocatable()) return;
    std::uint64_t next = img_.image_base;
    for (Section &s : img_.sections) {
      if (!s.alloc || s.type == SHT_NULL || s.size == 0) continue;
      if (s.addr != 0) {
        s.addr = shift(s.addr);
        continue;
      }
      std::uint64_t align = s.addralign > 1 ? s.addralign : 1;
      if ((align & (align - 1)) != 0) {
        warn("ELF: section " + s.name + " has non-power-of-two alignment");
        align = 1;
      }
      std::uint64_t a = checked_add(next, align - 1, "ELF section layout") & ~(align - 1);
      std::uint64_t end = checked_add(a, s.size, "ELF section layout");
      if (end - 1 > addr_limit()) fail("ELF: relocatable sections overflow the address space");
      s.addr = a;
      next = end;
    }
  }

  void add_region(const Region &region, std::string_view what) {
    if (region.size - 1 > addr_limit() - region.start) fail(std::string("ELF: ") + std::string(what) + " at " + hex(region.start) + " overflows the address space");
    try {
      img_.memory.add(region);
    } catch (const LoadError &e) {
      fail(std::string("ELF: ") + std::string(what) + ": " + e.what());
    }
  }

  void build_memory() {
    bool any_load = false;
    for (std::size_t i = 0; i < img_.segments.size(); ++i) {
      const Segment &s = img_.segments[i];
      if (s.type != PT_LOAD || relocatable()) continue;
      any_load = true;
      if (s.mem_size == 0) continue;
      Region r;
      r.start = s.vaddr;
      r.size = s.mem_size;
      r.file_offset = s.offset;
      r.file_size = std::min(s.file_size, s.mem_size);
      r.perms = {(s.flags & PF_R) != 0, (s.flags & PF_W) != 0, (s.flags & PF_X) != 0};
      if (r.file_size != 0 && !r_.has(r.file_offset, r.file_size)) {
        std::uint64_t avail = r.file_offset < r_.size() ? r_.size() - r.file_offset : 0;
        warn("ELF: segment " + std::to_string(i) + " is truncated by end of file");
        r.file_size = avail;
      }
      add_region(r, "segment " + std::to_string(i));
    }
    if (any_load) return;

    // No segments to map: object files, or images whose program headers are
    // missing. Map allocated sections directly.
    for (std::size_t i = 0; i < img_.sections.size(); ++i) {
      const Section &s = img_.sections[i];
      if (!s.alloc || s.type == SHT_NULL || s.size == 0 || (s.flags & SHF_TLS) != 0) continue;
      Region r;
      r.start = s.addr;
      r.size = s.size;
      r.file_offset = s.offset;
      r.file_size = s.file_size;
      r.perms = s.perms;
      add_region(r, "section " + std::to_string(i));
    }
  }

  static SymbolType sym_type(std::uint8_t t) {
    switch (t) {
      case 0: return SymbolType::notype;
      case 1: return SymbolType::object;
      case 2: return SymbolType::func;
      case 3: return SymbolType::section;
      case 4: return SymbolType::file;
      case 5: return SymbolType::common;
      case 6: return SymbolType::tls;
      case 10: return SymbolType::ifunc;
      default: return SymbolType::other;
    }
  }

  static SymbolBind sym_bind(std::uint8_t b) {
    switch (b) {
      case 0: return SymbolBind::local;
      case 1: return SymbolBind::global;
      case 2: return SymbolBind::weak;
      default: return SymbolBind::other;
    }
  }

  // DWARF pointer encodings used by .eh_frame.
  static constexpr std::uint8_t DW_EH_PE_omit = 0xff;

  struct Cursor {
    const Reader &r;
    std::uint64_t pos;
    std::uint64_t end;

    void need(std::uint64_t n) const {
      if (pos > end || n > end - pos) fail("ELF .eh_frame: record runs past its end");
    }
    std::uint64_t uint(unsigned n) {
      need(n);
      std::uint64_t v = 0;
      switch (n) {
        case 1: v = r.u8(pos, ".eh_frame"); break;
        case 2: v = r.u16(pos, ".eh_frame"); break;
        case 4: v = r.u32(pos, ".eh_frame"); break;
        default: v = r.u64(pos, ".eh_frame"); break;
      }
      pos += n;
      return v;
    }
    std::uint64_t uleb() {
      std::uint64_t v = 0;
      for (unsigned shift = 0;; shift += 7) {
        std::uint8_t b = static_cast<std::uint8_t>(uint(1));
        if (shift < 64) v |= std::uint64_t{b & 0x7fu} << shift;
        if ((b & 0x80) == 0) return v;
        if (shift > 70) fail("ELF .eh_frame: LEB128 too long");
      }
    }
    std::int64_t sleb() {
      std::uint64_t v = 0;
      unsigned shift = 0;
      std::uint8_t b = 0;
      do {
        b = static_cast<std::uint8_t>(uint(1));
        if (shift < 64) v |= std::uint64_t{b & 0x7fu} << shift;
        shift += 7;
        if (shift > 77) fail("ELF .eh_frame: LEB128 too long");
      } while ((b & 0x80) != 0);
      if (shift < 64 && (b & 0x40) != 0) v |= ~std::uint64_t{0} << shift;
      return static_cast<std::int64_t>(v);
    }
    std::string cstr() {
      std::string out;
      for (;;) {
        char c = static_cast<char>(uint(1));
        if (c == 0) return out;
        out.push_back(c);
        if (out.size() > 64) fail("ELF .eh_frame: augmentation string too long");
      }
    }
  };

  // Reads a pointer in DWARF encoding `enc`. `field_addr` is the run-time
  // address of the field, for pc-relative values. Relative bases other than
  // pc are not needed for .eh_frame and are rejected.
  std::uint64_t read_encoded(Cursor &c, std::uint8_t enc, std::uint64_t field_addr, bool apply_base) {
    std::uint64_t v = 0;
    switch (enc & 0x0f) {
      case 0x00: v = c.uint(h_.wide ? 8 : 4); break;
      case 0x01: v = c.uleb(); break;
      case 0x02: v = c.uint(2); break;
      case 0x03: v = c.uint(4); break;
      case 0x04: v = c.uint(8); break;
      case 0x09: v = static_cast<std::uint64_t>(c.sleb()); break;
      case 0x0a: v = static_cast<std::uint64_t>(static_cast<std::int16_t>(c.uint(2))); break;
      case 0x0b: v = static_cast<std::uint64_t>(static_cast<std::int32_t>(c.uint(4))); break;
      case 0x0c: v = c.uint(8); break;
      default: fail("ELF .eh_frame: unsupported pointer encoding " + hex(enc));
    }
    if (!apply_base) return v;
    switch (enc & 0x70) {
      case 0x00: return shift(v);  // absolute: moves with the image
      case 0x10: return v + field_addr;
      default: fail("ELF .eh_frame: unsupported pointer base " + hex(enc));
    }
  }

  // Function extents from .eh_frame FDEs: present even in stripped
  // binaries, so they seed functions where symbols are gone.
  void read_eh_frame() {
    if (relocatable()) return;  // addresses would need relocations
    const Section *eh = nullptr;
    for (const Section &s : img_.sections)
      if (s.name == ".eh_frame" && s.alloc && s.file_size != 0) eh = &s;
    if (eh == nullptr) return;
    try {
      parse_eh_frame(*eh);
    } catch (const LoadError &e) {
      warn(std::string(e.what()) + "; ignoring the rest of .eh_frame");
    }
    std::sort(img_.function_ranges.begin(), img_.function_ranges.end(),
              [](const FunctionRange &a, const FunctionRange &b) {
                return a.start != b.start ? a.start < b.start : a.end < b.end;
              });
    img_.function_ranges.erase(std::unique(img_.function_ranges.begin(), img_.function_ranges.end(),
                                           [](const FunctionRange &a, const FunctionRange &b) {
                                             return a.start == b.start;
                                           }),
                               img_.function_ranges.end());
  }

  void parse_eh_frame(const Section &eh) {
    constexpr std::size_t kMaxRecords = 1 << 20;
    struct Cie {
      std::uint8_t fde_enc = 0;
    };
    std::map<std::uint64_t, Cie> cies;  // by section offset
    const std::uint64_t base = eh.offset, size = eh.file_size;
    auto addr_of = [&](std::uint64_t file_off) { return eh.addr + (file_off - base); };

    std::uint64_t off = 0;
    for (std::size_t n = 0; n < kMaxRecords && off + 4 <= size; ++n) {
      Cursor c{r_, base + off, base + size};
      std::uint64_t len = c.uint(4);
      if (len == 0) break;  // terminator
      if (len == 0xffffffff) len = c.uint(8);
      const std::uint64_t body = c.pos;
      if (len > base + size - body) fail("ELF .eh_frame: record length past end of section");
      const std::uint64_t next = body + len;
      c.end = next;
      const std::uint64_t id_pos = c.pos;
      const std::uint64_t id = c.uint(4);
      if (id == 0) {
        Cie cie;
        std::uint8_t version = static_cast<std::uint8_t>(c.uint(1));
        std::string aug = c.cstr();
        if (aug.find("eh") != std::string::npos) c.uint(h_.wide ? 8 : 4);
        c.uleb();  // code alignment
        c.sleb();  // data alignment
        if (version == 1) c.uint(1);
        else c.uleb();  // return address register
        if (!aug.empty() && aug[0] == 'z') {
          c.uleb();  // augmentation data length
          for (std::size_t i = 1; i < aug.size(); ++i) {
            if (aug[i] == 'R') cie.fde_enc = static_cast<std::uint8_t>(c.uint(1));
            else if (aug[i] == 'L') c.uint(1);
            else if (aug[i] == 'P') {
              std::uint8_t penc = static_cast<std::uint8_t>(c.uint(1));
              read_encoded(c, penc & 0x0f, 0, false);
            } else if (aug[i] != 'S' && aug[i] != 'B') {
              break;  // unknown augmentation: the rest can't be read
            }
          }
        }
        cies[off] = cie;  // FDEs point at the CIE record start
      } else {
        if (id > id_pos - base) fail("ELF .eh_frame: FDE points before the section");
        auto it = cies.find(id_pos - base - id);
        if (it == cies.end()) fail("ELF .eh_frame: FDE without a CIE");
        const std::uint8_t enc = it->second.fde_enc;
        if (enc != DW_EH_PE_omit) {
          std::uint64_t field = addr_of(c.pos);
          std::uint64_t start = read_encoded(c, enc, field, true);
          std::uint64_t range = read_encoded(c, enc & 0x0f, 0, false);
          if (!h_.wide) {
            start &= 0xffffffffULL;
            range &= 0xffffffffULL;
          }
          if (range != 0 && range - 1 <= addr_limit() - start) {
            const Region *r = img_.memory.find(start);
            if (r != nullptr && r->perms.exec) img_.function_ranges.push_back({start, start + range});
          }
        }
      }
      off = next - base;
    }
  }

  void read_symbols() {
    const std::uint64_t min_ent = h_.wide ? 24 : 16;
    for (std::size_t si = 0; si < img_.sections.size(); ++si) {
      const Section &tab = img_.sections[si];
      if (tab.type != SHT_SYMTAB && tab.type != SHT_DYNSYM) continue;
      std::string label = tab.name.empty() ? "section " + std::to_string(si) : tab.name;
      std::uint64_t ent = tab.entsize;
      if (ent == 0) ent = min_ent;
      if (ent < min_ent) {
        warn("ELF: symbol table " + label + " has entry size " + std::to_string(ent) + "; skipping");
        continue;
      }
      if (tab.file_size == 0) {
        if (tab.size != 0) warn("ELF: symbol table " + label + " is outside the file; skipping");
        continue;
      }
      std::span<const std::byte> strtab;
      if (tab.link < img_.sections.size() && img_.sections[tab.link].type == SHT_STRTAB &&
          img_.sections[tab.link].file_size != 0) {
        const Section &st = img_.sections[tab.link];
        strtab = r_.bytes(st.offset, st.file_size, "ELF string table");
      } else {
        warn("ELF: symbol table " + label + " has no valid string table");
      }

      const SymbolSource source = tab.type == SHT_SYMTAB ? SymbolSource::symtab : SymbolSource::dynsym;
      std::uint64_t count = tab.file_size / ent;
      for (std::uint64_t i = 1; i < count; ++i) {  // entry 0 is the null symbol
        std::uint64_t off = tab.offset + i * ent;
        std::uint32_t name_off = r_.u32(off);
        Symbol sym;
        std::uint8_t info = 0;
        std::uint16_t shndx = 0;
        if (h_.wide) {
          info = r_.u8(off + 4);
          shndx = r_.u16(off + 6);
          sym.value = r_.u64(off + 8);
          sym.size = r_.u64(off + 16);
        } else {
          sym.value = r_.u32(off + 4);
          sym.size = r_.u32(off + 8);
          info = r_.u8(off + 12);
          shndx = r_.u16(off + 14);
        }
        sym.name = string_at(strtab, name_off);
        sym.type = sym_type(info & 0xf);
        sym.bind = sym_bind(info >> 4);
        sym.source = source;
        sym.section_index = shndx;
        sym.defined = shndx != SHN_UNDEF;

        // Symbols in allocated sections move with their section. ABS and
        // COMMON values are not addresses, and symbols in non-allocated
        // sections (debug info) are offsets that must not land on code.
        bool in_section = sym.defined && (shndx < SHN_LORESERVE || shndx == SHN_XINDEX);
        bool known = shndx < img_.sections.size();
        bool alloc = !known || img_.sections[shndx].alloc;
        if (in_section && alloc) {
          if (relocatable()) {
            if (known) sym.value = sym.value + img_.sections[shndx].addr;
          } else {
            sym.value = shift(sym.value);
          }
        }
        if (!h_.wide) sym.value &= 0xffffffffULL;
        img_.symbols.push_back(std::move(sym));
      }
    }
  }

  // Name of symbol `index` in the symbol table at section `symtab`; "" if
  // anything is out of range.
  std::string symbol_name(std::uint32_t symtab, std::uint64_t index) const {
    if (index == 0 || symtab >= img_.sections.size()) return {};
    const Section &tab = img_.sections[symtab];
    if (tab.type != SHT_SYMTAB && tab.type != SHT_DYNSYM) return {};
    const std::uint64_t ent = tab.entsize != 0 ? tab.entsize : (h_.wide ? 24 : 16);
    if (ent < (h_.wide ? 24u : 16u) || index >= tab.file_size / ent) return {};
    if (tab.link >= img_.sections.size()) return {};
    const Section &st = img_.sections[tab.link];
    if (st.type != SHT_STRTAB || st.file_size == 0) return {};
    std::uint32_t name_off = r_.u32(tab.offset + index * ent);
    return string_at(r_.bytes(st.offset, st.file_size, "ELF string table"), name_off);
  }

  // A word of the loaded image at `addr`, if it is file-backed.
  std::optional<std::uint64_t> image_word(std::uint64_t addr) const {
    const unsigned n = h_.wide ? 8 : 4;
    std::array<std::byte, 8> buf{};
    if (img_.memory.read(addr, std::span<std::byte>(buf.data(), n)) != n) return std::nullopt;
    std::uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i) {
      unsigned shift = img_.endian == Endian::little ? 8 * i : 8 * (n - 1 - i);
      v |= std::uint64_t{std::to_integer<std::uint8_t>(buf[i])} << shift;
    }
    return v;
  }

  // Relocation sections: allocated ones in linked images (the dynamic
  // relocations), every one in object files.
  void read_relocations() {
    constexpr std::size_t kMaxRelocations = 1 << 24;
    constexpr std::uint64_t SHF_INFO_LINK = 0x40;
    const unsigned word = h_.wide ? 8 : 4;
    const RelocationTypes types = relocation_types(h_.machine);
    for (std::size_t si = 0; si < img_.sections.size(); ++si) {
      const Section &sec = img_.sections[si];
      if (sec.type != SHT_RELA && sec.type != SHT_REL && sec.type != SHT_RELR) continue;
      if (!relocatable() && !sec.alloc) continue;
      if (sec.file_size == 0) continue;
      const std::string label = sec.name.empty() ? "section " + std::to_string(si) : sec.name;
      // In object files offsets are relative to the section they patch.
      std::uint64_t section_base = 0;
      if (relocatable()) {
        if ((sec.flags & SHF_INFO_LINK) == 0 && sec.info == 0) continue;
        if (sec.info >= img_.sections.size() || !img_.sections[sec.info].alloc) continue;
        section_base = img_.sections[sec.info].addr;
      }
      auto locate = [&](std::uint64_t r_offset) {
        std::uint64_t a = relocatable() ? section_base + r_offset : shift(r_offset);
        return h_.wide ? a : a & 0xffffffffULL;
      };
      auto add = [&](std::uint64_t r_offset, std::uint32_t type, std::uint64_t sym,
                     std::optional<std::uint64_t> explicit_addend) {
        if (img_.relocations.size() >= kMaxRelocations) return false;
        Relocation rel;
        rel.address = locate(r_offset);
        rel.type = type;
        rel.kind = relocation_kind(types, type);
        rel.symbol = symbol_name(sec.link, sym);
        std::uint64_t addend = 0;
        if (explicit_addend) {
          addend = *explicit_addend;
          if (!h_.wide) addend = static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(addend)));
        } else if (auto stored = image_word(rel.address)) {
          addend = *stored;
        }
        rel.addend = static_cast<std::int64_t>(addend);
        if (rel.kind == RelocationKind::relative || rel.kind == RelocationKind::irelative)
          rel.target = shift(addend);
        img_.relocations.push_back(std::move(rel));
        return true;
      };

      if (sec.type == SHT_RELR) {
        // Even entries are addresses; odd entries are bitmaps of the
        // following word-sized slots. Every one is a relative relocation.
        if (types.relative == RelocationTypes::none) continue;
        const std::uint32_t relative = types.relative;
        std::uint64_t where = 0;
        bool ok = true;
        for (std::uint64_t at = sec.offset; ok && at + word <= sec.offset + sec.file_size; at += word) {
          std::uint64_t entry = r_.word(at, h_.wide);
          if ((entry & 1) == 0) {
            where = entry;
            ok = add(where, relative, 0, std::nullopt);
            where += word;
          } else {
            for (unsigned bit = 1; ok && bit < 8 * word; ++bit)
              if ((entry >> bit) & 1) ok = add(where + (bit - 1) * word, relative, 0, std::nullopt);
            where += (8 * word - 1) * word;
          }
        }
        if (!ok) warn("ELF: too many relocations; ignoring the rest of " + label);
        continue;
      }

      const bool rela = sec.type == SHT_RELA;
      const std::uint64_t min_ent = word * (rela ? 3 : 2);
      const std::uint64_t ent = sec.entsize != 0 ? sec.entsize : min_ent;
      if (ent < min_ent) {
        warn("ELF: relocation section " + label + " has entry size " + std::to_string(ent) + "; skipping");
        continue;
      }
      for (std::uint64_t at = sec.offset; at + ent <= sec.offset + sec.file_size; at += ent) {
        std::uint64_t r_offset = r_.word(at, h_.wide);
        std::uint64_t info = r_.word(at + word, h_.wide);
        std::uint32_t type = h_.wide ? static_cast<std::uint32_t>(info & 0xffffffffu) : static_cast<std::uint32_t>(info & 0xff);
        std::uint64_t sym = h_.wide ? info >> 32 : info >> 8;
        std::optional<std::uint64_t> addend;
        if (rela) addend = r_.word(at + 2 * word, h_.wide);
        if (!add(r_offset, type, sym, addend)) {
          warn("ELF: too many relocations; ignoring the rest of " + label);
          break;
        }
      }
    }
    std::stable_sort(img_.relocations.begin(), img_.relocations.end(),
                     [](const Relocation &a, const Relocation &b) { return a.address < b.address; });
  }

  // PLT sections with the stub layout the linker uses on this machine.
  void read_plt_sections() {
    for (const Section &s : img_.sections) {
      if (!s.alloc || !s.perms.exec || s.size == 0 || s.type == SHT_NOBITS) continue;
      if (s.name != ".plt" && s.name != ".plt.sec" && s.name != ".plt.got" && s.name != ".iplt") continue;
      PltSection p{s.name, s.addr, s.size, 0, 0};
      const bool lazy = s.name == ".plt";
      switch (h_.machine) {
        case EM_X86_64:
        case EM_386:
          p.header_size = lazy ? 16 : 0;
          p.entry_size = s.name == ".plt.got" ? (s.entsize != 0 ? s.entsize : 8) : 16;
          break;
        case EM_AARCH64:
        case EM_RISCV:
          p.header_size = lazy ? 32 : 0;
          p.entry_size = 16;
          break;
        case EM_ARM: {
          // A header (push lr, load the GOT's address, jump through it: 20
          // bytes from binutils, 32 from lld), then one stub per lazily
          // bound import (add ip / add ip / ldr pc: 12 bytes from binutils,
          // 16 in its long form and from lld). sh_entsize says 4, an
          // instruction, not a stub. (binutils puts a Thumb bx pc stub
          // before some: then the stubs aren't evenly spaced, and only the
          // ones called become functions.)
          if (!lazy) {
            p.entry_size = s.entsize;
            break;
          }
          std::uint64_t slots = 0;
          for (const Relocation &r : img_.relocations) slots += r.kind == RelocationKind::jump_slot;
          for (std::uint64_t entry : {std::uint64_t{12}, std::uint64_t{16}})
            for (std::uint64_t header : {std::uint64_t{20}, std::uint64_t{32}})
              if (p.entry_size == 0 && slots != 0 && s.size == header + slots * entry) {
                p.header_size = header;
                p.entry_size = entry;
              }
          break;
        }
        default:
          p.entry_size = s.entsize;
          break;
      }
      if (p.header_size >= p.size) p.header_size = 0;
      img_.plt_sections.push_back(std::move(p));
    }
    std::sort(img_.plt_sections.begin(), img_.plt_sections.end(),
              [](const PltSection &a, const PltSection &b) { return a.start < b.start; });
  }

  // A pointer stored at `addr` as the dynamic linker would see it: the
  // relative relocation's target if one applies there, else the word.
  std::optional<std::uint64_t> stored_pointer(std::uint64_t addr) const {
    auto it = std::lower_bound(img_.relocations.begin(), img_.relocations.end(), addr,
                               [](const Relocation &r, std::uint64_t a) { return r.address < a; });
    for (; it != img_.relocations.end() && it->address == addr; ++it)
      if (it->kind == RelocationKind::relative && it->target) return it->target;
    return image_word(addr);
  }

  std::vector<std::uint64_t> pointer_array(std::uint64_t start, std::uint64_t bytes) const {
    constexpr std::uint64_t kMaxEntries = 1 << 16;
    const unsigned word = h_.wide ? 8 : 4;
    const std::uint64_t all_ones = h_.wide ? ~std::uint64_t{0} : 0xffffffffULL;
    std::vector<std::uint64_t> out;
    for (std::uint64_t i = 0; i < bytes / word && i < kMaxEntries; ++i) {
      if (start + i * word < start) break;
      auto v = stored_pointer(start + i * word);
      if (!v) break;
      if (*v != 0 && *v != all_ones) out.push_back(*v);
    }
    return out;
  }

  // The file offset of an address of the image (after the base shift), in a PT_LOAD.
  std::optional<std::uint64_t> file_offset_of(std::uint64_t addr) const {
    for (const Segment &s : img_.segments)
      if (s.type == PT_LOAD && addr >= s.vaddr && addr - s.vaddr < s.file_size) return s.offset + (addr - s.vaddr);
    return std::nullopt;
  }

  // DT_NEEDED, DT_SONAME and DT_RUNPATH (else DT_RPATH): names in the
  // dynamic string table (DT_STRTAB, bounded by DT_STRSZ).
  void read_dynamic_names() {
    if (relocatable()) return;
    std::optional<std::pair<std::uint64_t, std::uint64_t>> dyn;
    for (const Segment &s : img_.segments)
      if (s.type == PT_DYNAMIC && s.file_size != 0) dyn = {s.offset, s.file_size};
    if (!dyn)
      for (const Section &s : img_.sections)
        if (s.type == SHT_DYNAMIC && s.file_size != 0) dyn = {s.offset, s.file_size};
    if (!dyn || !r_.has(dyn->first, dyn->second)) return;
    const unsigned word = h_.wide ? 8 : 4;
    std::optional<std::uint64_t> strtab, strsz, soname, rpath, runpath;
    std::vector<std::uint64_t> needed;
    constexpr std::size_t kMaxEntries = 4096;
    std::size_t n = 0;
    for (std::uint64_t at = dyn->first; at + 2 * word <= dyn->first + dyn->second && n < kMaxEntries; at += 2 * word, ++n) {
      std::int64_t tag = h_.wide ? static_cast<std::int64_t>(r_.u64(at)) : static_cast<std::int32_t>(r_.u32(at));
      std::uint64_t val = r_.word(at + word, h_.wide);
      if (tag == DT_NULL) break;
      if (tag == DT_STRTAB) strtab = val;
      else if (tag == DT_STRSZ) strsz = val;
      else if (tag == DT_NEEDED) needed.push_back(val);
      else if (tag == DT_SONAME) soname = val;
      else if (tag == DT_RPATH) rpath = val;
      else if (tag == DT_RUNPATH) runpath = val;
    }
    if (!strtab) return;
    auto off = file_offset_of(shift(*strtab));
    if (!off) return;
    const std::uint64_t size = strsz && r_.has(*off, *strsz) ? *strsz : (file_->size() > *off ? file_->size() - *off : 0);
    auto str = [&](std::uint64_t i) -> std::string {
      if (i >= size) return {};
      std::string out;
      for (std::uint64_t p = *off + i; p < *off + size && out.size() < 4096; ++p) {
        char c = static_cast<char>((*file_)[p]);
        if (c == 0) break;
        out.push_back(c);
      }
      return out;
    };
    for (std::uint64_t i : needed)
      if (auto name = str(i); !name.empty()) img_.needed.push_back(std::move(name));
    if (soname) img_.soname = str(*soname);
    if (auto path = runpath ? runpath : rpath) {
      std::string all = str(*path);
      std::size_t start = 0;
      while (start <= all.size()) {
        std::size_t end = all.find(':', start);
        if (end == std::string::npos) end = all.size();
        if (end > start) img_.runpath.push_back(all.substr(start, end - start));
        start = end + 1;
      }
    }
  }

  // The GNU build ID: a note named "GNU" of type NT_GNU_BUILD_ID, in a
  // PT_NOTE segment or a SHT_NOTE section.
  void read_build_id() {
    std::vector<std::pair<std::uint64_t, std::uint64_t>> notes;
    for (const Segment &s : img_.segments)
      if (s.type == PT_NOTE && s.file_size != 0) notes.emplace_back(s.offset, s.file_size);
    for (const Section &s : img_.sections)
      if (s.type == SHT_NOTE && s.file_size != 0) notes.emplace_back(s.offset, s.file_size);
    for (auto [start, size] : notes) {
      if (!r_.has(start, size)) continue;
      std::uint64_t at = start;
      while (at + 12 <= start + size) {
        std::uint32_t namesz = r_.u32(at), descsz = r_.u32(at + 4), type = r_.u32(at + 8);
        std::uint64_t name_at = at + 12;
        std::uint64_t desc_at = name_at + ((static_cast<std::uint64_t>(namesz) + 3) & ~3ull);
        std::uint64_t next = desc_at + ((static_cast<std::uint64_t>(descsz) + 3) & ~3ull);
        if (next > start + size || next <= at) break;
        auto ch = [&](std::uint64_t i) { return static_cast<char>((*file_)[i]); };
        if (type == NT_GNU_BUILD_ID && namesz == 4 && r_.has(name_at, 4) && ch(name_at) == 'G' && ch(name_at + 1) == 'N' &&
            ch(name_at + 2) == 'U' && descsz > 0 && descsz <= 64 && r_.has(desc_at, descsz)) {
          static constexpr char kHex[] = "0123456789abcdef";
          std::string hex;
          for (std::uint32_t i = 0; i < descsz; ++i) {
            auto b = static_cast<std::uint8_t>((*file_)[desc_at + i]);
            hex.push_back(kHex[b >> 4]);
            hex.push_back(kHex[b & 15]);
          }
          img_.build_id = std::move(hex);
          return;
        }
        at = next;
      }
    }
  }

  void read_init_fini() {
    if (relocatable()) return;
    InitFini &out = img_.init_fini;
    // The dynamic table: PT_DYNAMIC, else the .dynamic section.
    std::optional<std::pair<std::uint64_t, std::uint64_t>> dyn;  // file offset, size
    for (const Segment &s : img_.segments)
      if (s.type == PT_DYNAMIC && s.file_size != 0) dyn = {s.offset, s.file_size};
    if (!dyn) {
      for (const Section &s : img_.sections)
        if (s.type == SHT_DYNAMIC && s.file_size != 0) dyn = {s.offset, s.file_size};
    }
    if (dyn && r_.has(dyn->first, dyn->second)) {
      const unsigned word = h_.wide ? 8 : 4;
      std::optional<std::uint64_t> arrays[3], sizes[3];  // preinit, init, fini
      for (std::uint64_t at = dyn->first; at + 2 * word <= dyn->first + dyn->second; at += 2 * word) {
        std::int64_t tag = h_.wide ? static_cast<std::int64_t>(r_.u64(at)) : static_cast<std::int32_t>(r_.u32(at));
        std::uint64_t val = r_.word(at + word, h_.wide);
        if (tag == DT_NULL) break;
        switch (tag) {
          case DT_INIT: out.init = shift(val); break;
          case DT_FINI: out.fini = shift(val); break;
          case DT_PREINIT_ARRAY: arrays[0] = shift(val); break;
          case DT_INIT_ARRAY: arrays[1] = shift(val); break;
          case DT_FINI_ARRAY: arrays[2] = shift(val); break;
          case DT_PREINIT_ARRAYSZ: sizes[0] = val; break;
          case DT_INIT_ARRAYSZ: sizes[1] = val; break;
          case DT_FINI_ARRAYSZ: sizes[2] = val; break;
          default: break;
        }
      }
      std::vector<std::uint64_t> *dest[3] = {&out.preinit_array, &out.init_array, &out.fini_array};
      for (int i = 0; i < 3; ++i)
        if (arrays[i] && sizes[i]) *dest[i] = pointer_array(*arrays[i], *sizes[i]);
      return;
    }
    // No dynamic table (static executables): use the sections.
    for (const Section &s : img_.sections) {
      if (!s.alloc || s.file_size == 0) continue;
      if (s.type == SHT_PREINIT_ARRAY) out.preinit_array = pointer_array(s.addr, s.size);
      else if (s.type == SHT_INIT_ARRAY) out.init_array = pointer_array(s.addr, s.size);
      else if (s.type == SHT_FINI_ARRAY) out.fini_array = pointer_array(s.addr, s.size);
    }
  }

  // PT_GNU_RELRO becomes read-only after relocation. Ghidra drops write
  // permission from every block the range touches, even one that extends
  // past its end (e.g. .got.plt under -z now).
  bool in_relro(std::uint64_t start, std::uint64_t size) const {
    for (const Segment &s : img_.segments) {
      if (s.type != PT_GNU_RELRO || s.mem_size == 0) continue;
      std::uint64_t last = s.vaddr + (s.mem_size - 1);
      if (start <= last && s.vaddr <= start + (size - 1)) return true;
    }
    return false;
  }

  bool overlaps_block(std::uint64_t start, std::uint64_t size) const {
    for (const Block &b : img_.blocks)
      if (start <= b.start + (b.size - 1) && b.start <= start + (size - 1)) return true;
    return false;
  }

  // Ghidra drops small all-zero segment fragments (alignment padding between
  // sections); 0xff is its default "max segment discard size".
  bool discardable_filler(std::uint64_t start, std::uint64_t size) const {
    constexpr std::uint64_t kMaxDiscard = 0xff;
    if (size > kMaxDiscard) return false;
    std::array<std::byte, kMaxDiscard> buf{};
    std::span<std::byte> view(buf.data(), static_cast<std::size_t>(size));
    img_.memory.read(start, view);
    return std::all_of(view.begin(), view.end(), [](std::byte b) { return b == std::byte{0}; });
  }

  void build_blocks() {
    // Named blocks follow Ghidra's ELF importer: one per allocated section,
    // plus "segment_N.K" fragments for loaded bytes no section covers.
    for (std::size_t i = 0; i < img_.sections.size(); ++i) {
      const Section &s = img_.sections[i];
      if (s.type == SHT_NULL || !s.alloc || s.size == 0) continue;
      if ((s.flags & SHF_TLS) != 0 && s.type == SHT_NOBITS) continue;  // .tbss takes no space
      if (s.type != SHT_NOBITS && s.file_size == 0) continue;
      if (s.size - 1 > addr_limit() - s.addr) continue;
      if (overlaps_block(s.addr, s.size)) {
        warn("ELF: section " + s.name + " overlaps another section; no block for it");
        continue;
      }
      Block b;
      b.name = s.name.empty() ? "section_" + std::to_string(i) : s.name;
      b.start = s.addr;
      b.size = s.size;
      b.perms = {true, s.perms.write && !in_relro(s.addr, s.size), s.perms.exec};
      b.initialized = s.type != SHT_NOBITS;
      img_.blocks.push_back(std::move(b));
    }
    const bool have_sections = !img_.blocks.empty();

    if (!relocatable()) {
      std::vector<Block> fragments;
      for (std::size_t i = 0; i < img_.segments.size(); ++i) {
        const Segment &s = img_.segments[i];
        if (s.type != PT_LOAD || s.mem_size == 0) continue;
        const Region *r = img_.memory.find(s.vaddr);
        if (r == nullptr) continue;
        Perms perms{(s.flags & PF_R) != 0, (s.flags & PF_W) != 0, (s.flags & PF_X) != 0};
        std::string name = "segment_" + std::to_string(i);
        if (!have_sections) {
          img_.blocks.push_back({name, s.vaddr, s.mem_size, perms, r->file_size != 0});
          continue;
        }
        // With sections present only the file-backed part is a segment block,
        // and Ghidra drops its execute bit.
        perms.exec = false;
        std::uint64_t start = r->start;
        std::uint64_t end = r->start + r->file_size;  // exclusive, can't wrap: file_size <= size
        int fragment = 0;
        std::uint64_t cur = start;
        while (cur < end) {
          // Skip over any block covering `cur`, else emit up to the next one.
          const Block *covering = nullptr;
          std::uint64_t next_start = end;
          for (const Block &b : img_.blocks) {
            if (cur >= b.start && cur - b.start < b.size) covering = &b;
            else if (b.start > cur && b.start < next_start) next_start = b.start;
          }
          if (covering != nullptr) {
            std::uint64_t past = covering->start + covering->size;
            if (past <= cur) break;  // block reaches the top of the space
            cur = past;
            continue;
          }
          std::string fragment_name = name + "." + std::to_string(++fragment);
          if (!discardable_filler(cur, next_start - cur))
            fragments.push_back({std::move(fragment_name), cur, next_start - cur, perms, true});
          cur = next_start;
        }
      }
      for (Block &b : fragments) img_.blocks.push_back(std::move(b));
    }

    std::sort(img_.blocks.begin(), img_.blocks.end(),
              [](const Block &a, const Block &b) { return a.start < b.start; });
  }

  // avr-gcc links flash (the code space) at 0 and SRAM (the data space,
  // SLEIGH's "mem") at 0x800000; EEPROM, fuses, lock bits and the
  // signature follow at 0x810000 and up. As Ghidra's AVR ELF support does,
  // data-space addresses move to "mem" (keys in that space, see
  // AddressSpace) and the rest, which no instruction addresses, is left
  // out. The image's pointers are 16 bits.
  void avr_spaces() {
    constexpr std::uint64_t kData = 0x800000, kDataEnd = 0x810000;
    img_.bits = 16;
    const AddressSpace &mem = add_space(img_, "mem");
    const std::uint64_t base = mem.base;
    auto key = [&](std::uint64_t a) -> std::optional<std::uint64_t> {
      if (a < kData) return a;
      if (a < kDataEnd) return base + (a - kData);
      return std::nullopt;
    };
    Memory memory(file_);
    for (Region r : img_.memory.regions()) {
      auto k = key(r.start);
      if (!k || (r.start < kData && r.last() >= kData) || (r.start >= kData && r.last() >= kDataEnd)) {
        warn("ELF: AVR memory at " + hex(r.start) + " is outside flash and SRAM; not loaded");
        continue;
      }
      r.start = *k;
      memory.add(r);
    }
    img_.memory = std::move(memory);
    std::vector<Block> blocks;
    for (Block b : img_.blocks) {
      auto k = key(b.start);
      if (!k || !img_.memory.is_mapped(*k)) continue;
      b.start = *k;
      blocks.push_back(std::move(b));
    }
    std::sort(blocks.begin(), blocks.end(), [](const Block &a, const Block &b) { return a.start < b.start; });
    img_.blocks = std::move(blocks);
    for (Symbol &sym : img_.symbols)
      if (sym.defined && sym.type != SymbolType::file && sym.type != SymbolType::section)
        if (auto k = key(sym.value)) sym.value = *k;
  }

  std::shared_ptr<const Bytes> file_;
  Reader r_;
  LoadOptions options_;
  Header h_;
  std::uint64_t delta_ = 0;
  Image img_;
};

}  // namespace

Image parse_elf(std::shared_ptr<const Bytes> file, const LoadOptions &options) {
  if (!file) detail::fail("ELF: no input");
  return ElfParser(std::move(file), options).run();
}

}  // namespace revkit::loader
