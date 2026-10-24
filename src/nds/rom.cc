// DS ROM images and NARC archives (rom.hh).
#include "revkit/nds/rom.hh"

#include "revkit/nds/compress.hh"

#include <algorithm>
#include <cstdio>
#include <set>

namespace revkit::nds {

namespace {

std::uint32_t Le32(std::span<const std::uint8_t> d, std::size_t o) {
  return d[o] | d[o + 1] << 8 | d[o + 2] << 16 | static_cast<std::uint32_t>(d[o + 3]) << 24;
}
std::uint16_t Le16(std::span<const std::uint8_t> d, std::size_t o) {
  return static_cast<std::uint16_t>(d[o] | d[o + 1] << 8);
}

std::string Ascii(std::span<const std::uint8_t> d, std::size_t o, std::size_t n) {
  std::string s;
  for (std::size_t i = 0; i < n && o + i < d.size(); ++i) {
    const char c = static_cast<char>(d[o + i]);
    if (c == 0) break;
    s += (c >= 0x20 && c < 0x7f) ? c : '?';
  }
  return s;
}

std::string Hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

bool Fits(std::uint64_t off, std::uint64_t size, std::uint64_t total) { return off <= total && size <= total - off; }

constexpr std::uint32_t kNitrocodeLe = 0xdec00621;  // as the bytes 21 06 c0 de read little-endian
constexpr std::uint32_t kNitrocodeBe = 0x2106c0de;  // the same bytes read the other way

}  // namespace

std::uint16_t crc16(std::span<const std::uint8_t> data, std::uint16_t crc) {
  for (std::uint8_t b : data) {
    crc ^= b;
    for (int i = 0; i < 8; ++i) crc = (crc & 1) ? static_cast<std::uint16_t>((crc >> 1) ^ 0xa001) : static_cast<std::uint16_t>(crc >> 1);
  }
  return crc;
}

std::optional<NdsHeader> parse_nds_header(std::span<const std::uint8_t> d, std::string *error, std::uint64_t file_size) {
  const std::uint64_t total = file_size ? file_size : d.size();
  auto fail = [&](const std::string &m) -> std::optional<NdsHeader> {
    if (error) *error = m;
    return std::nullopt;
  };
  if (d.size() < 0x180) return fail("too small for a DS ROM header");
  NdsHeader h;
  h.title = Ascii(d, 0, 12);
  h.game_code = Ascii(d, 0x0c, 4);
  h.maker_code = Ascii(d, 0x10, 2);
  h.unit_code = d[0x12];
  h.rom_version = d[0x1e];
  h.arm9_rom_offset = Le32(d, 0x20);
  h.arm9_entry = Le32(d, 0x24);
  h.arm9_ram_address = Le32(d, 0x28);
  h.arm9_size = Le32(d, 0x2c);
  h.arm7_rom_offset = Le32(d, 0x30);
  h.arm7_entry = Le32(d, 0x34);
  h.arm7_ram_address = Le32(d, 0x38);
  h.arm7_size = Le32(d, 0x3c);
  h.fnt_offset = Le32(d, 0x40);
  h.fnt_size = Le32(d, 0x44);
  h.fat_offset = Le32(d, 0x48);
  h.fat_size = Le32(d, 0x4c);
  h.arm9_overlay_offset = Le32(d, 0x50);
  h.arm9_overlay_size = Le32(d, 0x54);
  h.arm7_overlay_offset = Le32(d, 0x58);
  h.arm7_overlay_size = Le32(d, 0x5c);
  h.banner_offset = Le32(d, 0x68);
  h.arm9_autoload_hook = Le32(d, 0x70);
  h.arm7_autoload_hook = Le32(d, 0x74);
  h.rom_size = Le32(d, 0x80);
  h.header_size = Le32(d, 0x84);
  h.logo_crc = Le16(d, 0x15c);
  h.header_crc = Le16(d, 0x15e);
  h.header_crc_ok = crc16(d.subspan(0, 0x15e)) == h.header_crc;
  h.logo_crc_ok = h.logo_crc == 0xcf56 && crc16(d.subspan(0xc0, 0x9c)) == 0xcf56;
  if (!h.header_crc_ok && !h.logo_crc_ok) return fail("not a DS ROM: neither the header CRC nor the logo checksum holds");
  if (!Fits(h.arm9_rom_offset, h.arm9_size, total) || h.arm9_size == 0)
    return fail("the ARM9 program (" + Hex(h.arm9_rom_offset) + ", " + Hex(h.arm9_size) + " bytes) is past the file");
  if (h.arm9_rom_offset < 0x180) return fail("the ARM9 program overlaps the header");
  return h;
}

bool is_nds(std::span<const std::uint8_t> data) {
  std::string e;
  return parse_nds_header(data, &e).has_value();
}

std::optional<NdsModuleParams> find_module_params(std::span<const std::uint8_t> a, std::uint32_t ram,
                                                  std::optional<std::uint32_t> footer_offset) {
  auto at = [&](std::size_t o) -> std::optional<NdsModuleParams> {
    if (o + 36 > a.size()) return std::nullopt;
    if (Le32(a, o + 28) != kNitrocodeBe || Le32(a, o + 32) != kNitrocodeLe) return std::nullopt;
    NdsModuleParams p;
    p.offset = static_cast<std::uint32_t>(o);
    p.autoload_list_start = Le32(a, o);
    p.autoload_list_end = Le32(a, o + 4);
    p.autoload_start = Le32(a, o + 8);
    p.bss_start = Le32(a, o + 12);
    p.bss_end = Le32(a, o + 16);
    p.compressed_static_end = Le32(a, o + 20);
    p.sdk_version = Le32(a, o + 24);
    (void)ram;
    return p;
  };
  if (footer_offset)
    if (auto p = at(*footer_offset)) return p;
  // The words read as 0x2106C0DE then 0xDEC00621 end the parameters.
  for (std::size_t o = 0; o + 36 <= a.size() && o < (1u << 20); o += 4)
    if (Le32(a, o + 28) == kNitrocodeBe && Le32(a, o + 32) == kNitrocodeLe) return at(o);
  return std::nullopt;
}

void split_autoloads(const NdsModuleParams &p, NdsModule &main, std::vector<NdsAutoload> &lists,
                     std::vector<NdsModule> &out, const NdsLimits &limits) {
  const std::uint32_t base = main.address;
  auto off = [&](std::uint32_t addr) -> std::optional<std::size_t> {
    if (addr < base || addr - base > main.data.size()) return std::nullopt;
    return addr - base;
  };
  auto ls = off(p.autoload_list_start), le = off(p.autoload_list_end), as = off(p.autoload_start);
  if (!ls || !le || !as || *le < *ls) {
    if (p.autoload_list_start != p.autoload_list_end)
      main.warnings.push_back("the module parameters' autoload list is outside the ARM9 program");
    return;
  }
  const std::span<const std::uint8_t> list(main.data.data() + *ls, *le - *ls);
  const std::size_t blocks = *ls >= *as ? *ls - *as : 0;
  // Two layouts: 12-byte entries (address, size, bss size) and 16-byte ones
  // (address, size, static initializers, bss size); the one whose sizes
  // add up to the autoload data is it.
  std::vector<NdsAutoload> chosen;
  for (std::size_t width : {std::size_t{12}, std::size_t{16}}) {
    if (list.size() % width != 0) continue;
    std::vector<NdsAutoload> v;
    std::uint64_t total = 0;
    for (std::size_t o = 0; o + width <= list.size() && v.size() < 64; o += width) {
      NdsAutoload e;
      e.address = Le32(list, o);
      e.size = Le32(list, o + 4);
      if (width == 12) {
        e.bss_size = Le32(list, o + 8);
      } else {
        e.sinit_start = Le32(list, o + 8);
        e.bss_size = Le32(list, o + 12);
      }
      total += e.size;
      v.push_back(e);
    }
    if (total == blocks || (chosen.empty() && width == 16 && list.size() % 12 != 0)) {
      chosen = std::move(v);
      if (total == blocks) break;
    }
  }
  if (chosen.empty() && list.size() % 12 == 0 && !list.empty()) {
    main.warnings.push_back("the autoload list's sizes don't add up to the autoload data; read as 12-byte entries");
    for (std::size_t o = 0; o + 12 <= list.size() && chosen.size() < 64; o += 12)
      chosen.push_back({Le32(list, o), Le32(list, o + 4), Le32(list, o + 8), 0});
  }
  std::size_t at = *as;
  int unknown = 0;
  for (const NdsAutoload &e : chosen) {
    if (at > main.data.size() || e.size > main.data.size() - at || e.size > limits.max_module) {
      main.warnings.push_back("autoload block at " + Hex(e.address) + " runs past the ARM9 program");
      break;
    }
    NdsModule m;
    m.cpu = NdsCpu::arm9;
    m.address = e.address;
    m.bss_size = e.bss_size;
    m.sinit_start = e.sinit_start;
    if (e.address == 0x01ff8000) {
      m.name = "itcm";
    } else if (e.address == 0x027e0000 || e.address == 0x027c0000 || e.address == 0x023c0000 || e.address == 0x02fe0000) {
      m.name = "dtcm";
    } else {
      m.name = "autoload_" + std::to_string(unknown + 2);
      ++unknown;
    }
    for (const NdsModule &o : out)
      if (o.name == m.name) m.name += "_" + std::to_string(out.size());
    m.data.assign(main.data.begin() + static_cast<std::ptrdiff_t>(at),
                  main.data.begin() + static_cast<std::ptrdiff_t>(at + e.size));
    at += e.size;
    out.push_back(std::move(m));
  }
  lists = chosen;
  // Main ends where the autoload data starts; its .bss follows.
  main.data.resize(*as);
  if (p.bss_end > p.bss_start && p.bss_end - p.bss_start < limits.max_module) main.bss_size = p.bss_end - p.bss_start;
}

bool parse_nitrofs(std::span<const std::uint8_t> fnt, std::span<const std::uint8_t> fat, std::vector<NdsFile> &files,
                   std::vector<NdsDirectory> &dirs, std::vector<std::string> &warnings, std::size_t max_files) {
  const std::size_t nfiles = std::min(fat.size() / 8, max_files);
  if (fat.size() / 8 > max_files) warnings.push_back("more files than the limit; the rest are left out");
  files.resize(nfiles);
  for (std::size_t i = 0; i < nfiles; ++i) {
    files[i].id = static_cast<std::uint32_t>(i);
    files[i].start = Le32(fat, i * 8);
    files[i].end = Le32(fat, i * 8 + 4);
  }
  if (fnt.size() < 8) return true;
  const std::uint16_t ndirs = Le16(fnt, 6);
  if (ndirs == 0 || static_cast<std::size_t>(ndirs) * 8 > fnt.size()) {
    warnings.push_back("the file name table's directory count doesn't fit");
    return false;
  }
  std::vector<std::string> paths(ndirs);
  std::vector<bool> seen(ndirs, false);
  paths[0] = "/";
  // Walk from the root (breadth first), so each directory's path is known
  // before its children; loops and orphans are left out.
  std::vector<std::uint16_t> queue{0};
  seen[0] = true;
  std::set<std::string> used;
  for (std::size_t qi = 0; qi < queue.size(); ++qi) {
    const std::uint16_t d = queue[qi];
    dirs.push_back({static_cast<std::uint16_t>(0xf000 + d), paths[d]});
    std::size_t o = Le32(fnt, d * 8u);
    std::uint32_t file = Le16(fnt, d * 8u + 4);
    std::size_t entries = 0;
    while (true) {
      if (o >= fnt.size()) {
        warnings.push_back("directory " + paths[d] + ": its names run past the table");
        break;
      }
      const std::uint8_t t = fnt[o++];
      if (t == 0) break;
      if (++entries > 65536) break;
      const std::size_t len = t & 0x7f;
      if (t == 0x80 || o + len > fnt.size()) {
        warnings.push_back("directory " + paths[d] + ": a bad name entry");
        break;
      }
      std::string name;
      for (std::size_t i = 0; i < len; ++i) {
        const char c = static_cast<char>(fnt[o + i]);
        name += (c == '/' || c == 0 || static_cast<unsigned char>(c) < 0x20) ? '_' : c;
      }
      if (name == "." || name == "..") name = "_" + name;
      o += len;
      const std::string path = (paths[d] == "/" ? "/" : paths[d] + "/") + name;
      if (t & 0x80) {
        if (o + 2 > fnt.size()) break;
        const std::uint16_t sub = Le16(fnt, o);
        o += 2;
        const std::uint16_t idx = static_cast<std::uint16_t>(sub - 0xf000);
        if (sub < 0xf000 || idx >= ndirs || seen[idx]) {
          warnings.push_back(path + ": a bad or repeated directory id");
          continue;
        }
        seen[idx] = true;
        paths[idx] = path;
        queue.push_back(idx);
      } else {
        if (file < files.size() && files[file].path.empty() && used.insert(path).second) files[file].path = path;
        ++file;
      }
    }
  }
  return true;
}

namespace {

bool ReadOverlays(std::span<const std::uint8_t> d, std::uint32_t off, std::uint32_t size, std::vector<NdsOverlay> &out,
                  std::vector<std::string> &warnings, const char *what, std::size_t max) {
  if (size == 0) return true;
  if (!Fits(off, size, d.size())) {
    warnings.push_back(std::string(what) + " overlay table is past the file");
    return false;
  }
  for (std::size_t o = off; o + 32 <= std::size_t{off} + size && out.size() < max; o += 32) {
    NdsOverlay v;
    v.id = Le32(d, o);
    v.ram_address = Le32(d, o + 4);
    v.ram_size = Le32(d, o + 8);
    v.bss_size = Le32(d, o + 12);
    v.sinit_start = Le32(d, o + 16);
    v.sinit_end = Le32(d, o + 20);
    v.file_id = Le32(d, o + 24);
    const std::uint32_t last = Le32(d, o + 28);
    v.compressed_size = last & 0xffffff;
    v.compressed = (last >> 24) & 1;
    v.authenticated = (last >> 25) & 1;
    out.push_back(v);
  }
  return true;
}

}  // namespace

std::optional<NdsRom> parse_nds(std::span<const std::uint8_t> d, std::string *error, bool modules,
                                const NdsLimits &limits) {
  std::optional<NdsHeader> h = parse_nds_header(d, error);
  if (!h) return std::nullopt;
  NdsRom rom;
  rom.header = *h;
  if (!h->header_crc_ok) rom.warnings.push_back("the header CRC doesn't match (an edited header?)");
  ReadOverlays(d, h->arm9_overlay_offset, h->arm9_overlay_size, rom.arm9_overlays, rom.warnings, "the ARM9",
               limits.max_overlays);
  ReadOverlays(d, h->arm7_overlay_offset, h->arm7_overlay_size, rom.arm7_overlays, rom.warnings, "the ARM7",
               limits.max_overlays);
  if (h->fat_size && Fits(h->fat_offset, h->fat_size, d.size())) {
    std::span<const std::uint8_t> fnt;
    if (h->fnt_size && Fits(h->fnt_offset, h->fnt_size, d.size())) fnt = d.subspan(h->fnt_offset, h->fnt_size);
    else if (h->fnt_size) rom.warnings.push_back("the file name table is past the file");
    parse_nitrofs(fnt, d.subspan(h->fat_offset, h->fat_size), rom.files, rom.directories, rom.warnings,
                  limits.max_files);
  } else if (h->fat_size) {
    rom.warnings.push_back("the file allocation table is past the file");
  }
  for (NdsFile &f : rom.files)
    if (f.end < f.start || f.end > d.size()) {
      if (f.start != 0 || f.end != 0)
        rom.warnings.push_back("file " + std::to_string(f.id) + (f.path.empty() ? "" : " (" + f.path + ")") +
                               " is past the end of the ROM");
      f.start = f.end = 0;
    }
  if (!modules) return rom;

  std::size_t total = 0;
  auto keep = [&](NdsModule &&m) {
    total += m.data.size();
    if (total > limits.max_total) {
      rom.warnings.push_back(m.name + " left out: the modules are over the size limit");
      return;
    }
    rom.modules.push_back(std::move(m));
  };
  // ARM9: decompress (the module parameters' compressed static end), then
  // cut the autoload blocks off.
  NdsModule main;
  main.name = "main";
  main.cpu = NdsCpu::arm9;
  main.address = h->arm9_ram_address;
  main.entry = h->arm9_entry;
  main.data.assign(d.begin() + h->arm9_rom_offset, d.begin() + h->arm9_rom_offset + h->arm9_size);
  // A retail dump's secure area (the first 2 KiB) is expected decrypted
  // (0xE7FFDEFF twice at its start); an encrypted one is loaded as it is
  // and reads as noise (docs/nds.md).
  // The ARM9 footer (12 bytes after the program in the ROM): nitrocode,
  // the module parameters' offset, the overlay signatures' offset.
  std::optional<std::uint32_t> footer;
  const std::size_t fo = std::size_t{h->arm9_rom_offset} + h->arm9_size;
  if (fo + 12 <= d.size() && Le32(d, fo) == kNitrocodeLe) footer = Le32(d, fo + 4);
  rom.params = find_module_params(main.data, main.address, footer);
  if (rom.params && rom.params->compressed_static_end) {
    const std::uint32_t cse = rom.params->compressed_static_end;
    if (cse > main.address && cse - main.address <= main.data.size()) {
      std::string e;
      const std::size_t end = cse - main.address;
      std::span<const std::uint8_t> packed(main.data.data(), end);
      std::optional<std::vector<std::uint8_t>> out = blz_decompress(packed, limits.max_module, &e);
      if (out) {
        // Whatever followed the compressed part (rare) is kept after it.
        out->insert(out->end(), main.data.begin() + static_cast<std::ptrdiff_t>(end), main.data.end());
        main.data = std::move(*out);
        main.was_compressed = true;
        // The decompressed program says it is no longer compressed.
        if (rom.params->offset + 24 <= main.data.size())
          for (int i = 0; i < 4; ++i) main.data[rom.params->offset + 20 + i] = 0;
      } else {
        main.warnings.push_back("the ARM9 program is compressed but doesn't decompress: " + e);
      }
    } else {
      main.warnings.push_back("the compressed static end " + Hex(cse) + " is outside the ARM9 program");
    }
  }
  std::vector<NdsModule> autoloads;
  if (rom.params) split_autoloads(*rom.params, main, rom.autoloads, autoloads, limits);
  else main.warnings.push_back("no module parameters (nitrocode) in the ARM9 program: autoloads not split");
  keep(std::move(main));
  for (NdsModule &m : autoloads) keep(std::move(m));
  // Overlays naming a file another already took, and any once the modules
  // are over the limit, aren't read again (bug scrub part 3: 8,192 overlays
  // of one file each decompressed it before the limit was checked).
  std::set<std::uint32_t> files_taken;
  auto overlay_modules = [&](const std::vector<NdsOverlay> &table, NdsCpu cpu) {
    std::set<std::uint32_t> ids;
    for (const NdsOverlay &v : table) {
      NdsModule m;
      m.cpu = cpu;
      m.overlay_id = static_cast<int>(v.id);
      char name[32];
      std::snprintf(name, sizeof name, "%sov%03u", cpu == NdsCpu::arm7 ? "arm7_" : "", v.id);
      m.name = name;
      m.address = v.ram_address;
      m.bss_size = v.bss_size;
      m.sinit_start = v.sinit_start;
      m.sinit_end = v.sinit_end;
      if (!ids.insert(v.id).second) {
        rom.warnings.push_back(m.name + " is listed twice; the second is left out");
        continue;
      }
      if (v.file_id >= rom.files.size() || rom.files[v.file_id].end <= rom.files[v.file_id].start) {
        rom.warnings.push_back(m.name + ": its file " + std::to_string(v.file_id) + " is missing");
        continue;
      }
      if (!files_taken.insert(v.file_id).second) {
        rom.warnings.push_back(m.name + ": its file " + std::to_string(v.file_id) + " is another overlay's; left out");
        continue;
      }
      if (total >= limits.max_total) {
        rom.warnings.push_back(m.name + " left out: the modules are over the size limit");
        continue;
      }
      const NdsFile &f = rom.files[v.file_id];
      std::span<const std::uint8_t> bytes = d.subspan(f.start, f.end - f.start);
      if (v.compressed) {
        // The table's compressed size, else the file's.
        if (v.compressed_size && v.compressed_size <= bytes.size()) bytes = bytes.subspan(0, v.compressed_size);
        std::string e;
        std::optional<std::vector<std::uint8_t>> out = blz_decompress(bytes, limits.max_module, &e);
        if (!out) {
          rom.warnings.push_back(m.name + " doesn't decompress: " + e);
          continue;
        }
        m.data = std::move(*out);
        m.was_compressed = true;
      } else {
        m.data.assign(bytes.begin(), bytes.end());
      }
      if (v.ram_size && m.data.size() > v.ram_size) m.data.resize(v.ram_size);
      if (v.ram_size && m.data.size() < v.ram_size)
        m.warnings.push_back("shorter than the overlay table's size (" + Hex(v.ram_size) + ")");
      keep(std::move(m));
    }
  };
  overlay_modules(rom.arm9_overlays, NdsCpu::arm9);
  if (h->arm7_size && Fits(h->arm7_rom_offset, h->arm7_size, d.size())) {
    NdsModule a7;
    a7.name = "arm7";
    a7.cpu = NdsCpu::arm7;
    a7.address = h->arm7_ram_address;
    a7.entry = h->arm7_entry;
    a7.data.assign(d.begin() + h->arm7_rom_offset, d.begin() + h->arm7_rom_offset + h->arm7_size);
    keep(std::move(a7));
  } else if (h->arm7_size) {
    rom.warnings.push_back("the ARM7 program is past the file");
  }
  overlay_modules(rom.arm7_overlays, NdsCpu::arm7);
  return rom;
}

// ---- NARC -----------------------------------------------------------------

bool is_narc(std::span<const std::uint8_t> d) {
  return d.size() >= 16 && d[0] == 'N' && d[1] == 'A' && d[2] == 'R' && d[3] == 'C' && Le16(d, 4) == 0xfffe;
}

std::optional<Narc> parse_narc(std::span<const std::uint8_t> d, std::string *error, std::size_t max_files) {
  auto fail = [&](const std::string &m) -> std::optional<Narc> {
    if (error) *error = m;
    return std::nullopt;
  };
  if (!is_narc(d)) return fail("not a NARC archive");
  const std::size_t header = Le16(d, 12);
  const std::size_t nblocks = Le16(d, 14);
  std::size_t o = header < 16 ? 16 : header;
  std::span<const std::uint8_t> fatb, fntb, fimg;
  bool have_fimg = false;
  for (std::size_t b = 0; b < nblocks && b < 16; ++b) {
    if (o + 8 > d.size()) return fail("a block header is past the end");
    const std::uint32_t size = Le32(d, o + 4);
    if (size < 8 || !Fits(o, size, d.size())) return fail("a block runs past the end");
    std::span<const std::uint8_t> body = d.subspan(o + 8, size - 8);
    const std::string magic(reinterpret_cast<const char *>(d.data() + o), 4);
    if (magic == "BTAF") fatb = body;
    else if (magic == "BTNF") fntb = body;
    else if (magic == "GMIF") fimg = body, have_fimg = true;
    o += size;
  }
  if (fatb.size() < 4) return fail("no file allocation block (BTAF)");
  // Offsets are from the image block's start: without one there is none to
  // count from (an empty file's offset came from a null pointer;
  // nds_narc_fuzzer, bug scrub part 3).
  if (!have_fimg) return fail("no file image block (GMIF)");
  const std::size_t n = std::min<std::size_t>(Le16(fatb, 0), (fatb.size() - 4) / 8);
  Narc out;
  if (n > max_files) return fail("more files than the limit");
  std::vector<NdsFile> files;
  std::vector<NdsDirectory> dirs;
  // BTAF: count (16 bits) and padding, then start/end pairs relative to GMIF.
  std::vector<std::uint8_t> fat(fatb.begin() + 4, fatb.begin() + 4 + static_cast<std::ptrdiff_t>(n * 8));
  bool named = false;
  if (fntb.size() >= 8 && Le16(fntb, 6) != 0 && Le32(fntb, 0) > 8) {
    named = parse_nitrofs(fntb, fat, files, dirs, out.warnings, max_files);
  } else {
    parse_nitrofs({}, fat, files, dirs, out.warnings, max_files);
  }
  std::set<std::string> taken;
  for (const NdsDirectory &dir : dirs)
    if (dir.path != "/") out.directories.push_back(dir.path);
  for (const NdsFile &f : files) {
    NarcFile nf;
    char buf[32];
    std::snprintf(buf, sizeof buf, "/%04u.bin", f.id);
    nf.path = named && !f.path.empty() ? f.path : buf;
    if (!taken.insert(nf.path).second) nf.path += "~" + std::to_string(f.id);
    if (f.end < f.start || f.end > fimg.size()) {
      out.warnings.push_back(nf.path + ": past the archive's data");
      continue;
    }
    nf.offset = static_cast<std::uint32_t>((fimg.data() - d.data()) + f.start);
    nf.size = f.end - f.start;
    out.files.push_back(std::move(nf));
  }
  return out;
}

}  // namespace revkit::nds
