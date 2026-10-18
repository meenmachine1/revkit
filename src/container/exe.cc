#include "exe.hh"

#include "formats.hh"

#include <algorithm>
#include <cctype>

namespace revkit::container::detail {

namespace {

struct Rd {
  const Source &src;
  bool be = false;
  std::vector<std::byte> get(std::uint64_t off, std::uint64_t n) const { return src.read_exact(off, n, "headers"); }
  std::uint64_t un(const std::byte *p, unsigned n) const {
    std::uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i) v = v << 8 | static_cast<std::uint8_t>(p[be ? i : n - 1 - i]);
    return v;
  }
};

struct ElfSection {
  std::string name;
  std::uint32_t type = 0;
  std::uint64_t offset = 0, size = 0;
};

struct Load {
  std::uint64_t offset = 0, vaddr = 0, filesz = 0;
};
struct Elf {
  bool wide = false, be = false;
  std::vector<ElfSection> sections;
  std::vector<Range> note_segments;
  std::vector<Load> loads;
};

std::optional<Elf> read_elf(const Source &src) {
  try {
    const auto h = src.head(64);
    if (h.size() < 52 || std::memcmp(h.data(), "\x7f" "ELF", 4) != 0) return std::nullopt;
    Elf e;
    e.wide = static_cast<std::uint8_t>(h[4]) == 2;
    e.be = static_cast<std::uint8_t>(h[5]) == 2;
    if (e.wide && h.size() < 64) return std::nullopt;
    Rd r{src, e.be};
    const std::byte *p = h.data();
    const std::uint64_t phoff = e.wide ? r.un(p + 32, 8) : r.un(p + 28, 4);
    const std::uint64_t shoff = e.wide ? r.un(p + 40, 8) : r.un(p + 32, 4);
    const unsigned phentsize = static_cast<unsigned>(r.un(p + (e.wide ? 54 : 42), 2));
    const unsigned phnum = static_cast<unsigned>(r.un(p + (e.wide ? 56 : 44), 2));
    const unsigned shentsize = static_cast<unsigned>(r.un(p + (e.wide ? 58 : 46), 2));
    const unsigned shnum = static_cast<unsigned>(r.un(p + (e.wide ? 60 : 48), 2));
    const unsigned shstrndx = static_cast<unsigned>(r.un(p + (e.wide ? 62 : 50), 2));
    const unsigned need_ph = e.wide ? 56 : 32, need_sh = e.wide ? 64 : 40;
    if (phoff && phnum && phentsize >= need_ph && phnum <= 4096) {
      const auto t = r.get(phoff, std::uint64_t{phnum} * phentsize);
      for (unsigned i = 0; i < phnum; ++i) {
        const std::byte *q = t.data() + std::size_t{i} * phentsize;
        const std::uint64_t type = r.un(q, 4);
        const std::uint64_t off = e.wide ? r.un(q + 8, 8) : r.un(q + 4, 4);
        const std::uint64_t sz = e.wide ? r.un(q + 32, 8) : r.un(q + 16, 4);
        const std::uint64_t vaddr = e.wide ? r.un(q + 16, 8) : r.un(q + 8, 4);
        if (type == 4) e.note_segments.push_back({off, sz});  // PT_NOTE
        if (type == 1) e.loads.push_back({off, vaddr, sz});   // PT_LOAD
      }
    }
    if (shoff && shnum && shentsize >= need_sh && shnum <= 65535 && shstrndx < shnum) {
      const auto t = r.get(shoff, std::uint64_t{shnum} * shentsize);
      auto field = [&](unsigned i, unsigned off32, unsigned off64, unsigned n32, unsigned n64) {
        return r.un(t.data() + std::size_t{i} * shentsize + (e.wide ? off64 : off32), e.wide ? n64 : n32);
      };
      const std::uint64_t stroff = field(shstrndx, 16, 24, 4, 8), strsize = field(shstrndx, 20, 32, 4, 8);
      if (strsize > (16u << 20)) return e;
      const auto strtab = r.get(stroff, strsize);
      for (unsigned i = 0; i < shnum; ++i) {
        ElfSection s;
        const std::uint64_t name = field(i, 0, 0, 4, 4);
        s.type = static_cast<std::uint32_t>(field(i, 4, 4, 4, 4));
        s.offset = field(i, 16, 24, 4, 8);
        s.size = field(i, 20, 32, 4, 8);
        if (name < strtab.size())
          s.name = std::string(reinterpret_cast<const char *>(strtab.data() + name),
                               strnlen(reinterpret_cast<const char *>(strtab.data() + name), strtab.size() - name));
        e.sections.push_back(std::move(s));
      }
    }
    return e;
  } catch (const Error &) {
    return std::nullopt;
  }
}

std::optional<Range> note_in(const Source &src, bool be, Range area, std::string_view want) {
  if (area.size > (256ull << 20) || area.offset > src.size() || area.size > src.size() - area.offset) return std::nullopt;
  Rd r{src, be};
  std::uint64_t p = area.offset;
  const std::uint64_t end = area.offset + area.size;
  for (int n = 0; n < 4096 && p + 12 <= end; ++n) {
    const auto h = r.get(p, 12);
    const std::uint64_t namesz = r.un(h.data(), 4), descsz = r.un(h.data() + 4, 4);
    const std::uint64_t name_at = p + 12, desc_at = name_at + ((namesz + 3) & ~3ull);
    if (desc_at > end || descsz > end - desc_at) return std::nullopt;
    if (namesz >= 1 && namesz - 1 == want.size()) {
      const auto nm = r.get(name_at, namesz - 1);
      if (std::memcmp(nm.data(), want.data(), want.size()) == 0) return Range{desc_at, descsz};
    }
    p = desc_at + ((descsz + 3) & ~3ull);
  }
  return std::nullopt;
}

struct PeSection {
  std::uint32_t va = 0, vsize = 0, raw = 0, ptr = 0;
  std::string name;
};
struct Pe {
  std::vector<PeSection> sections;
  std::uint32_t dirs[16][2] = {};
  std::optional<std::uint64_t> offset_of(std::uint64_t rva) const {
    for (const PeSection &s : sections)
      if (rva >= s.va && rva - s.va < std::max(s.vsize, s.raw) && rva - s.va < s.raw) return s.ptr + (rva - s.va);
    return std::nullopt;
  }
};

std::optional<Pe> read_pe(const Source &src) {
  try {
    const auto h = src.head(64);
    if (h.size() < 64 || std::memcmp(h.data(), "MZ", 2) != 0) return std::nullopt;
    const std::uint32_t lfanew = le32(h.data() + 0x3c);
    const auto c = src.read_exact(lfanew, 24, "PE headers");
    if (std::memcmp(c.data(), "PE\0\0", 4) != 0) return std::nullopt;
    const unsigned nsec = le16(c.data() + 6), opt_size = le16(c.data() + 20);
    const auto o = src.read_exact(std::uint64_t{lfanew} + 24, opt_size, "PE optional header");
    if (opt_size < 2) return std::nullopt;
    const bool wide = le16(o.data()) == 0x20b;
    const unsigned dir_off = wide ? 112 : 96;
    Pe pe;
    if (opt_size >= dir_off) {
      const std::uint32_t ndirs = le32(o.data() + (wide ? 108 : 92));
      for (unsigned i = 0; i < 16 && i < ndirs && dir_off + i * 8 + 8 <= opt_size; ++i) {
        pe.dirs[i][0] = le32(o.data() + dir_off + i * 8);
        pe.dirs[i][1] = le32(o.data() + dir_off + i * 8 + 4);
      }
    }
    if (nsec > 96) return std::nullopt;
    const auto t = src.read_exact(std::uint64_t{lfanew} + 24 + opt_size, nsec * 40ull, "PE sections");
    for (unsigned i = 0; i < nsec; ++i) {
      const std::byte *s = t.data() + i * 40;
      const char *n = reinterpret_cast<const char *>(s);
      pe.sections.push_back({le32(s + 12), le32(s + 8), le32(s + 16), le32(s + 20), std::string(n, strnlen(n, 8))});
    }
    return pe;
  } catch (const Error &) {
    return std::nullopt;
  }
}

std::string lower(std::string s) {
  for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

}  // namespace

ExeFormat exe_format(const Source &src) {
  const auto h = src.head(4);
  if (h.size() < 4) return ExeFormat::none;
  if (std::memcmp(h.data(), "\x7f" "ELF", 4) == 0) return ExeFormat::elf;
  if (std::memcmp(h.data(), "MZ", 2) == 0) return ExeFormat::pe;
  const std::uint32_t m = le32(h.data());
  if (m == 0xfeedface || m == 0xfeedfacf || m == 0xcefaedfe || m == 0xcffaedfe) return ExeFormat::macho;
  return ExeFormat::none;
}

std::optional<Range> elf_section(const Source &src, std::string_view name) {
  auto e = read_elf(src);
  if (!e) return std::nullopt;
  for (const ElfSection &s : e->sections)
    if (s.name == name && s.type != 8 /* NOBITS */ && s.offset <= src.size() && s.size <= src.size() - s.offset)
      return Range{s.offset, s.size};
  return std::nullopt;
}

std::optional<Range> elf_note(const Source &src, std::string_view name) {
  auto e = read_elf(src);
  if (!e) return std::nullopt;
  try {
    for (const ElfSection &s : e->sections)
      if (s.type == 7)
        if (auto r = note_in(src, e->be, {s.offset, s.size}, name)) return r;
    for (const Range &seg : e->note_segments)
      if (auto r = note_in(src, e->be, seg, name)) return r;
  } catch (const Error &) {
  }
  return std::nullopt;
}

std::optional<Range> pe_resource(const Source &src, std::string_view type, std::string_view name) {
  auto pe = read_pe(src);
  if (!pe || pe->dirs[2][0] == 0) return std::nullopt;
  try {
    auto base = pe->offset_of(pe->dirs[2][0]);
    if (!base) return std::nullopt;
    const std::uint64_t root = *base;
    // A directory's entry named `want` ("#10" for id 10, else a string
    // matched without case), or the first one when `want` is empty.
    auto find = [&](std::uint64_t dir, std::string_view want) -> std::optional<std::uint32_t> {
      const auto d = src.read_exact(dir, 16, "a resource directory");
      const unsigned named = le16(d.data() + 12), ids = le16(d.data() + 14);
      if (named + ids > 4096) return std::nullopt;
      const auto es = src.read_exact(dir + 16, (named + ids) * 8ull, "resource entries");
      for (unsigned i = 0; i < named + ids; ++i) {
        const std::uint32_t nm = le32(es.data() + i * 8), off = le32(es.data() + i * 8 + 4);
        if (want.empty()) return off;
        std::string label;
        if (nm & 0x80000000u) {
          const std::uint64_t at = root + (nm & 0x7fffffffu);
          const auto len = src.read_exact(at, 2, "a resource name");
          const unsigned n = le16(len.data());
          if (n > 256) continue;
          const auto u = src.read_exact(at + 2, n * 2ull, "a resource name");
          for (unsigned k = 0; k < n; ++k) {
            const unsigned ch = le16(u.data() + k * 2);
            label += ch < 0x80 ? static_cast<char>(ch) : '?';
          }
        } else {
          label = "#" + std::to_string(nm & 0xffff);
        }
        if (lower(label) == lower(std::string(want))) return off;
      }
      return std::nullopt;
    };
    std::string t(type);
    if (t == "RCDATA") t = "#10";
    auto l1 = find(root, t);
    if (!l1 || !(*l1 & 0x80000000u)) return std::nullopt;
    auto l2 = find(root + (*l1 & 0x7fffffffu), name);
    if (!l2 || !(*l2 & 0x80000000u)) return std::nullopt;
    auto l3 = find(root + (*l2 & 0x7fffffffu), "");
    if (!l3 || (*l3 & 0x80000000u)) return std::nullopt;
    const auto data = src.read_exact(root + *l3, 16, "a resource data entry");
    auto off = pe->offset_of(le32(data.data()));
    const std::uint64_t size = le32(data.data() + 4);
    if (!off || *off > src.size() || size > src.size() - *off) return std::nullopt;
    return Range{*off, size};
  } catch (const Error &) {
    return std::nullopt;
  }
}

std::optional<std::uint64_t> elf_file_offset(const Source &src, std::uint64_t vaddr) {
  auto e = read_elf(src);
  if (!e) return std::nullopt;
  for (const Load &l : e->loads)
    if (vaddr >= l.vaddr && vaddr - l.vaddr < l.filesz) return l.offset + (vaddr - l.vaddr);
  return std::nullopt;
}

std::optional<Range> pe_section(const Source &src, std::string_view name) {
  auto pe = read_pe(src);
  if (!pe) return std::nullopt;
  for (const PeSection &s : pe->sections)
    if (s.name == name && s.ptr <= src.size() && s.raw <= src.size() - s.ptr) return Range{s.ptr, s.raw};
  return std::nullopt;
}

std::optional<std::uint64_t> pe_end_of_image(const Source &src) {
  auto pe = read_pe(src);
  if (!pe) return std::nullopt;
  std::uint64_t end = 0;
  for (const PeSection &s : pe->sections)
    if (s.raw) end = std::max<std::uint64_t>(end, std::uint64_t{s.ptr} + s.raw);
  // The certificate table's "RVA" is a file offset.
  if (pe->dirs[4][0] >= end && pe->dirs[4][1]) end = std::uint64_t{pe->dirs[4][0]} + pe->dirs[4][1];
  return end;
}

std::optional<Range> macho_section(const Source &src, std::string_view segment, std::string_view section) {
  try {
    const auto h = src.head(32);
    if (h.size() < 28) return std::nullopt;
    const std::uint32_t m = le32(h.data());
    if (m != 0xfeedface && m != 0xfeedfacf) return std::nullopt;  // little-endian thin files
    const bool wide = m == 0xfeedfacf;
    const std::uint32_t ncmds = le32(h.data() + 16), sizeofcmds = le32(h.data() + 20);
    if (ncmds > 4096 || sizeofcmds > (16u << 20)) return std::nullopt;
    const auto cmds = src.read_exact(wide ? 32 : 28, sizeofcmds, "load commands");
    std::size_t p = 0;
    auto name16 = [&](std::size_t at) {
      const char *c = reinterpret_cast<const char *>(cmds.data() + at);
      return std::string(c, strnlen(c, 16));
    };
    for (std::uint32_t i = 0; i < ncmds && p + 8 <= cmds.size(); ++i) {
      const std::uint32_t cmd = le32(cmds.data() + p), size = le32(cmds.data() + p + 4);
      if (size < 8 || size > cmds.size() - p) return std::nullopt;
      if ((cmd == 0x19 && wide) || (cmd == 0x1 && !wide)) {
        const std::size_t hdr = wide ? 72 : 56, sec = wide ? 80 : 68;
        if (size < hdr) return std::nullopt;
        const std::uint32_t nsects = le32(cmds.data() + p + (wide ? 64 : 48));
        if (hdr + std::uint64_t{nsects} * sec > size) return std::nullopt;
        if (name16(p + 8) == segment)
          for (std::uint32_t k = 0; k < nsects; ++k) {
            const std::size_t s = p + hdr + k * sec;
            if (name16(s) != section) continue;
            const std::uint64_t sz = wide ? le64(cmds.data() + s + 40) : le32(cmds.data() + s + 36);
            const std::uint64_t off = le32(cmds.data() + s + (wide ? 48 : 40));
            if (off > src.size() || sz > src.size() - off) return std::nullopt;
            return Range{off, sz};
          }
      }
      p += size;
    }
  } catch (const Error &) {
  }
  return std::nullopt;
}

}  // namespace revkit::container::detail
