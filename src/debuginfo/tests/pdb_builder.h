// Test helper: write small synthetic PDBs (MSF 7.00 container, info, DBI,
// TPI, IPI, section headers, symbol records and module streams), so tests
// can describe exactly the records they need, valid or not.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::debuginfo::testing {

class Buf {
 public:
  std::vector<std::uint8_t> b;

  Buf &u8(std::uint8_t v) {
    b.push_back(v);
    return *this;
  }
  Buf &u16(std::uint16_t v) { return u8(std::uint8_t(v)).u8(std::uint8_t(v >> 8)); }
  Buf &u32(std::uint32_t v) { return u16(std::uint16_t(v)).u16(std::uint16_t(v >> 16)); }
  Buf &u64(std::uint64_t v) { return u32(std::uint32_t(v)).u32(std::uint32_t(v >> 32)); }
  Buf &str(std::string_view s) {
    b.insert(b.end(), s.begin(), s.end());
    return u8(0);
  }
  Buf &bytes(const std::vector<std::uint8_t> &v) {
    b.insert(b.end(), v.begin(), v.end());
    return *this;
  }
  Buf &zeros(std::size_t n) {
    b.insert(b.end(), n, 0);
    return *this;
  }
  Buf &align4() {
    while (b.size() % 4) u8(0);
    return *this;
  }
  std::size_t size() const { return b.size(); }
};

// Type records with consecutive indices from 0x1000; payloads are padded
// with LF_PADn bytes like real ones.
class Types {
 public:
  std::uint32_t add(std::uint16_t kind, const Buf &payload) {
    Buf rec;
    rec.u16(kind).bytes(payload.b);
    while ((rec.size() + 2) % 4) rec.u8(std::uint8_t(0xf0 + (4 - (rec.size() + 2) % 4)));
    data.u16(std::uint16_t(rec.size())).bytes(rec.b);
    return next++;
  }
  // A record with an exact length field, for malformed cases.
  std::uint32_t add_raw(const std::vector<std::uint8_t> &bytes) {
    data.bytes(bytes);
    return next++;
  }
  std::uint32_t next = 0x1000;
  Buf data;
};

// Symbol records (u16 length, u16 kind, payload padded to 4).
class Symbols {
 public:
  Symbols &add(std::uint16_t kind, const Buf &payload) {
    Buf rec;
    rec.u16(kind).bytes(payload.b);
    while ((rec.size() + 2) % 4) rec.u8(0);
    data.u16(std::uint16_t(rec.size())).bytes(rec.b);
    return *this;
  }
  Buf data;
};

inline std::vector<std::uint8_t> type_stream(const Types &t) {
  Buf s;
  s.u32(20040203).u32(56).u32(0x1000).u32(t.next).u32(std::uint32_t(t.data.size()));
  s.u16(0xffff).u16(0xffff).u32(4).u32(0x3ffff);
  s.zeros(24);
  return s.bytes(t.data.b).b;
}

inline std::vector<std::uint8_t> info_stream(std::uint32_t age = 1, std::uint8_t guid_byte = 0x42) {
  Buf s;
  s.u32(20000404).u32(0x12345678).u32(age);
  for (int i = 0; i < 16; ++i) s.u8(std::uint8_t(guid_byte + i));
  // Named stream map: "/names" -> stream 0xffff... a hash table with one
  // present bucket.
  s.u32(7).str("/names");
  s.u32(1).u32(1);       // size, capacity
  s.u32(1).u32(1);       // present bit vector: bucket 0
  s.u32(0);              // deleted bit vector
  s.u32(0).u32(0xffff);  // key (string offset), value (stream)
  s.u32(20140508);       // feature code VC140: has IPI
  return s.b;
}

struct Section {
  std::string name;
  std::uint32_t va = 0;
  std::uint32_t size = 0;
  std::uint32_t characteristics = 0x60000020;
};

inline std::vector<std::uint8_t> section_headers(const std::vector<Section> &sections) {
  Buf s;
  for (const Section &sec : sections) {
    std::string n = sec.name.substr(0, 8);
    s.b.insert(s.b.end(), n.begin(), n.end());
    s.zeros(8 - n.size());
    s.u32(sec.size).u32(sec.va).u32(sec.size).u32(0x400).u32(0).u32(0).u16(0).u16(0);
    s.u32(sec.characteristics);
  }
  return s.b;
}

inline std::vector<std::uint8_t> module_stream(const Symbols &syms) {
  Buf s;
  s.u32(4).bytes(syms.data.b);
  return s.b;
}

struct Module {
  std::string name;
  std::uint16_t stream = 0xffff;
  std::uint32_t symbol_bytes = 0;
};

struct DbiSpec {
  std::vector<Module> modules;
  std::uint16_t symbol_stream = 0xffff;
  std::uint16_t section_header_stream = 0xffff;
  std::uint16_t omap_from_src_stream = 0xffff;
  std::uint16_t original_section_header_stream = 0xffff;
  std::uint16_t section_count = 0;  // identity section map with this many entries
  std::uint16_t machine = 0x8664;
};

inline std::vector<std::uint8_t> dbi_stream(const DbiSpec &d) {
  Buf mods;
  for (const Module &m : d.modules) {
    mods.u32(0);
    mods.u16(1).u16(0).u32(0).u32(0).u32(0).u16(0).u16(0).u32(0).u32(0);  // contribution
    mods.u16(0).u16(m.stream).u32(m.symbol_bytes).u32(0).u32(0).u16(0).u16(0);
    mods.u32(0).u32(0).u32(0);
    mods.str(m.name).str(m.name).align4();
  }
  Buf contribs;
  contribs.u32(0xeffe0000u + 19970605u);
  for (std::size_t i = 0; i < d.modules.size(); ++i)
    contribs.u16(1).u16(0).u32(std::uint32_t(i) * 16).u32(16).u32(0x60000020).u16(std::uint16_t(i)).u16(0).u32(0).u32(0);
  Buf secmap;
  secmap.u16(d.section_count).u16(d.section_count);
  for (std::uint16_t i = 0; i < d.section_count; ++i)
    secmap.u16(0x10d).u16(0).u16(0).u16(std::uint16_t(i + 1)).u16(0xffff).u16(0xffff).u32(0).u32(0x1000);
  Buf optional;
  for (unsigned i = 0; i < 11; ++i) {
    std::uint16_t v = 0xffff;
    if (i == 4) v = d.omap_from_src_stream;
    if (i == 5) v = d.section_header_stream;
    if (i == 10) v = d.original_section_header_stream;
    optional.u16(v);
  }
  Buf s;
  s.u32(0xffffffffu).u32(19990903).u32(1);
  s.u16(0xffff).u16(0).u16(0xffff).u16(0).u16(d.symbol_stream).u16(0);
  s.u32(std::uint32_t(mods.size())).u32(std::uint32_t(contribs.size())).u32(std::uint32_t(secmap.size()));
  s.u32(0).u32(0).u32(0).u32(std::uint32_t(optional.size())).u32(0);
  s.u16(0).u16(d.machine).u32(0);
  return s.bytes(mods.b).bytes(contribs.b).bytes(secmap.b).bytes(optional.b).b;
}

// The MSF container: superblock, two free-block-map blocks, the streams,
// the directory and the block map.
inline std::vector<std::uint8_t> msf(const std::vector<std::vector<std::uint8_t>> &streams,
                                     std::uint32_t block_size = 512) {
  std::vector<std::vector<std::uint8_t>> blocks(3, std::vector<std::uint8_t>(block_size, 0));
  std::vector<std::vector<std::uint32_t>> stream_blocks;
  auto place = [&](const std::vector<std::uint8_t> &data) {
    std::vector<std::uint32_t> ids;
    for (std::size_t off = 0; off < data.size(); off += block_size) {
      std::vector<std::uint8_t> blk(block_size, 0);
      std::copy(data.begin() + off, data.begin() + std::min(data.size(), off + block_size), blk.begin());
      ids.push_back(std::uint32_t(blocks.size()));
      blocks.push_back(std::move(blk));
    }
    return ids;
  };
  for (const auto &s : streams) stream_blocks.push_back(place(s));
  Buf dir;
  dir.u32(std::uint32_t(streams.size()));
  for (const auto &s : streams) dir.u32(std::uint32_t(s.size()));
  for (const auto &ids : stream_blocks)
    for (std::uint32_t id : ids) dir.u32(id);
  std::vector<std::uint32_t> dir_blocks = place(dir.b);
  Buf map;
  for (std::uint32_t id : dir_blocks) map.u32(id);
  std::uint32_t map_block = place(map.b).front();

  Buf super;
  const char magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0";
  super.b.assign(magic, magic + 32);
  super.u32(block_size).u32(1).u32(std::uint32_t(blocks.size())).u32(std::uint32_t(dir.size()));
  super.u32(0).u32(map_block);
  std::copy(super.b.begin(), super.b.end(), blocks[0].begin());
  std::vector<std::uint8_t> out;
  for (const auto &blk : blocks) out.insert(out.end(), blk.begin(), blk.end());
  return out;
}

// A whole PDB: streams 0-4 (old directory, info, TPI, DBI, IPI), then
// section headers (5), global symbols (6) and one module stream per entry
// of `modules` (7, 8, ...).
struct PdbSpec {
  Types tpi;
  Types ipi;
  std::vector<Section> sections = {{".text", 0x1000, 0x1000}, {".data", 0x2000, 0x1000, 0xc0000040}};
  Symbols globals;
  std::vector<Symbols> modules;
  std::vector<std::pair<std::uint32_t, std::uint32_t>> omap;  // from, to
  std::vector<Section> original_sections;                     // with omap
};

inline std::vector<std::uint8_t> build_pdb(const PdbSpec &p) {
  std::vector<std::vector<std::uint8_t>> streams(7);
  streams[1] = info_stream();
  streams[2] = type_stream(p.tpi);
  streams[4] = type_stream(p.ipi);
  streams[5] = section_headers(p.sections);
  streams[6] = p.globals.data.b;
  DbiSpec d;
  d.symbol_stream = 6;
  d.section_header_stream = 5;
  d.section_count = std::uint16_t(p.sections.size());
  for (std::size_t i = 0; i < p.modules.size(); ++i) {
    std::vector<std::uint8_t> m = module_stream(p.modules[i]);
    d.modules.push_back({"mod" + std::to_string(i) + ".obj", std::uint16_t(streams.size()),
                         std::uint32_t(m.size())});
    streams.push_back(std::move(m));
  }
  if (!p.omap.empty()) {
    Buf o;
    for (auto [from, to] : p.omap) o.u32(from).u32(to);
    d.omap_from_src_stream = std::uint16_t(streams.size());
    streams.push_back(o.b);
    d.original_section_header_stream = std::uint16_t(streams.size());
    streams.push_back(section_headers(p.original_sections));
  }
  streams[3] = dbi_stream(d);
  return msf(streams);
}

// Payload helpers for common records.
inline Buf proc(std::uint32_t type, std::uint32_t offset, std::uint16_t segment, std::uint32_t length,
                std::string_view name) {
  Buf b;
  b.u32(0).u32(0).u32(0).u32(length).u32(0).u32(0).u32(type).u32(offset).u16(segment).u8(0).str(name);
  return b;
}

}  // namespace revkit::debuginfo::testing
