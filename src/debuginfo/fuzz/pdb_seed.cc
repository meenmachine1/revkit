// pdb_seed OUTDIR: writes a small synthetic pdb_fuzzer seed (stream-list
// form) touching most record kinds, so the fuzzer has a fast input to
// mutate besides the large real PDBs from make_pdb_seeds.py.
#include "../tests/pdb_builder.h"
#include <fstream>
using namespace revkit::debuginfo::testing;
static void write(const std::string &path, const PdbSpec &p) {
  // build_pdb()'s stream layout, written as [u32 length][bytes] records.
  std::vector<std::vector<std::uint8_t>> streams(7);
  streams[1] = info_stream();
  streams[2] = type_stream(p.tpi);
  streams[4] = type_stream(p.ipi);
  streams[5] = section_headers(p.sections);
  streams[6] = p.globals.data.b;
  DbiSpec d; d.symbol_stream = 6; d.section_header_stream = 5; d.section_count = std::uint16_t(p.sections.size());
  for (std::size_t i = 0; i < p.modules.size(); ++i) {
    auto m = module_stream(p.modules[i]);
    d.modules.push_back({"mod.obj", std::uint16_t(streams.size()), std::uint32_t(m.size())});
    streams.push_back(m);
  }
  streams[3] = dbi_stream(d);
  std::ofstream out(path, std::ios::binary);
  for (auto &s : streams) { Buf b; b.u32(std::uint32_t(s.size())); out.write((const char*)b.b.data(), 4); out.write((const char*)s.data(), s.size()); }
}
int main(int, char **argv) {
  std::string dir = argv[1];
  PdbSpec p;
  Buf args; args.u32(2).u32(0x74).u32(0x670);
  auto al = p.tpi.add(0x1201, args);
  auto fn = p.tpi.add(0x1008, Buf().u32(0x74).u8(0).u8(0).u16(2).u32(al));
  auto fl = p.tpi.add(0x1203, Buf().u16(0x150d).u16(3).u32(0x74).u16(0).str("x").u8(0xf2).u8(0xf1).u16(0x150d).u16(3).u32(0x670).u16(8).str("p"));
  auto st = p.tpi.add(0x1505, Buf().u16(2).u16(0).u32(fl).u32(0).u32(0).u16(16).str("S"));
  auto fw = p.tpi.add(0x1505, Buf().u16(0).u16(0x80).u32(0).u32(0).u32(0).u16(0).str("S"));
  auto ptr = p.tpi.add(0x1002, Buf().u32(fw).u32(0x1000c));
  p.tpi.add(0x1001, Buf().u32(ptr).u16(3));
  p.tpi.add(0x1503, Buf().u32(st).u32(0x23).u16(64).str(""));
  auto el = p.tpi.add(0x1203, Buf().u16(0x1502).u16(3).u16(1).str("A").u8(0xf1).u16(0x1502).u16(3).u16(0x8000).u8(0xff).str("B"));
  p.tpi.add(0x1507, Buf().u16(2).u16(0).u32(0x74).u32(el).str("E"));
  p.tpi.add(0x1205, Buf().u32(0x75).u8(3).u8(1));
  Symbols m;
  m.add(0x1110, proc(fn, 0x10, 1, 0x20, "f"));
  m.add(0x113e, Buf().u32(0x74).u16(1).str("a"));
  m.add(0x1142, Buf().u32(8).u32(0).u16(0).u16(0));
  m.add(0x1111, Buf().u32(8).u32(0x670).u16(335).str("b"));
  m.add(0x1103, Buf().u32(0).u32(0).u32(4).u32(0x14).u16(1).str(""));
  m.add(0x110b, Buf().u32(0xfffffffc).u32(ptr).str("c"));
  m.add(0x0006, Buf());
  m.add(0x114d, Buf().u32(0).u32(0).u32(0));
  m.add(0x114e, Buf());
  m.add(0x0006, Buf());
  m.add(0x1102, Buf().u32(0).u32(0).u32(0).u32(0x40).u16(1).u16(5).u8(0).str("thunk"));
  m.add(0x0006, Buf());
  m.add(0x110d, Buf().u32(st).u32(0x10).u16(2).str("g"));
  m.add(0x1108, Buf().u32(ptr).str("SP"));
  p.modules.push_back(m);
  p.globals.add(0x110e, Buf().u32(2).u32(0x10).u16(1).str("?f@@YAHHPEAD@Z"));
  p.globals.add(0x110e, Buf().u32(2).u32(0x10).u16(1).str("_Z1fiPc"));
  write(dir + "/synthetic.streams", p);
}
