// Go's pclntab (gopclntab.hh): synthetic tables in each of the four layouts,
// both byte orders and pointer sizes, and every refusal; finding a table in
// an image (its section, the magic scan checked by the moduledata, the
// moduledata's text start); names and the no-return list; the golang
// compiler spec choice. Then Go 1.15's table from Go's own test data
// (debug/gosym/testdata/pcln115.gz in the Go toolchain) and real binaries
// built at test time when Go is installed: ELF, PIE, arm64, PE and Mach-O,
// stripped, checked against the unstripped build's symbol table; with
// $RK_GO_OLD (a Go before 1.18), the 1.16 layout the same way.

#include "builders.hh"

#include "revkit/loader/gopclntab.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>
#include <zlib.h>

#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>

namespace revkit::loader {
namespace {

using testing::ByteWriter;
using testing::ElfBuilder;
using testing::ElfSpec;
using testing::scratch_dir;
using testing::to_bytes;

constexpr std::uint32_t kPfR = 4, kPfW = 2, kPfX = 1;

struct SynthFunc {
  std::uint64_t off = 0;  // from the text start
  std::string name;
  std::string file;
  std::int32_t line = 0;
};

void PutVarint(std::vector<std::uint8_t> &out, std::uint64_t v) {
  while (v >= 0x80) {
    out.push_back(static_cast<std::uint8_t>(v | 0x80));
    v >>= 7;
  }
  out.push_back(static_cast<std::uint8_t>(v));
}

// A pc-value table holding `value` for `size` bytes (in quanta) from the entry.
void PcValue(std::vector<std::uint8_t> &out, std::int32_t value, std::uint64_t quanta) {
  PutVarint(out, 2 * static_cast<std::uint64_t>(value + 1));  // value - (-1), zigzag
  PutVarint(out, quanta);
  out.push_back(0);
}

// A table in Go's layout `v` for functions at text + off, the last ending
// at text + end. Go 1.20's startLine is each function's line and its pcln
// table says line + 1, so a test sees which one was read.
std::vector<std::uint8_t> BuildTable(GoPclntabVersion v, unsigned ptr, bool big, std::uint64_t text,
                                     const std::vector<SynthFunc> &fs, std::uint64_t end, unsigned quantum = 1,
                                     std::uint64_t header_text = ~0ull) {
  const bool v116 = v != GoPclntabVersion::go12, v118 = v >= GoPclntabVersion::go118;
  const std::uint32_t magic = v == GoPclntabVersion::go12    ? 0xfffffffb
                              : v == GoPclntabVersion::go116 ? 0xfffffffa
                              : v == GoPclntabVersion::go118 ? 0xfffffff0
                                                             : 0xfffffff1;
  const std::size_t n = fs.size();
  // The parts, each with offsets relative to itself.
  std::vector<std::uint8_t> names, files, pctab(1, 0);  // pctab offset 0 is "none"
  std::vector<std::uint32_t> name_off, file_off, pcfile_off, pcln_off;
  for (std::size_t i = 0; i < n; ++i) {
    name_off.push_back(static_cast<std::uint32_t>(names.size()));
    names.insert(names.end(), fs[i].name.begin(), fs[i].name.end());
    names.push_back(0);
    file_off.push_back(static_cast<std::uint32_t>(files.size()));
    files.insert(files.end(), fs[i].file.begin(), fs[i].file.end());
    files.push_back(0);
    const std::uint64_t size = ((i + 1 < n ? fs[i + 1].off : end) - fs[i].off) / quantum;
    if (fs[i].file.empty()) {  // no tables (go:buildid)
      pcfile_off.push_back(0);
      pcln_off.push_back(0);
      continue;
    }
    pcfile_off.push_back(static_cast<std::uint32_t>(pctab.size()));
    PcValue(pctab, v116 ? 0 : static_cast<std::int32_t>(i + 1), size);
    pcln_off.push_back(static_cast<std::uint32_t>(pctab.size()));
    PcValue(pctab, v == GoPclntabVersion::go120 ? fs[i].line + 1 : fs[i].line, size);
  }
  const unsigned fs_size = v118 ? 4 : ptr;
  const std::size_t functab_size = (2 * n + 1) * fs_size;
  const unsigned sz0 = v118 ? 4 : ptr;
  const std::size_t func_size = sz0 + (v == GoPclntabVersion::go120 ? 9 : v116 ? 8 : 7) * 4 + 4;
  ByteWriter w(big);
  w.put(magic, 4);
  w.put(0, 2);
  w.put(quantum, 1);
  w.put(ptr, 1);
  if (!v116) {
    // 1.2: nfunc, the function table, the file table's offset; then the
    // _funcs, names, pc tables and file table, all from the header.
    w.put(n, ptr);
    const std::size_t functab = w.size();
    const std::size_t funcs = functab + functab_size + 4;
    const std::size_t names_at = funcs + n * func_size;
    const std::size_t files_at = names_at + names.size();
    const std::size_t pctab_at = files_at + files.size();
    const std::size_t filetab_at = (pctab_at + pctab.size() + 3) / 4 * 4;
    for (std::size_t i = 0; i < n; ++i) {
      w.put_at(functab + 2 * i * ptr, text + fs[i].off, ptr);
      w.put_at(functab + (2 * i + 1) * ptr, funcs + i * func_size, ptr);
      const std::size_t f = funcs + i * func_size;
      w.put_at(f, text + fs[i].off, ptr);
      w.put_at(f + ptr, names_at + name_off[i], 4);
      w.put_at(f + ptr + 16, pctab_at + pcfile_off[i], 4);
      w.put_at(f + ptr + 20, pctab_at + pcln_off[i], 4);
    }
    w.put_at(functab + 2 * n * ptr, text + end, ptr);
    w.put_at(functab + functab_size, filetab_at, 4);
    w.bytes_at(names_at, names);
    w.bytes_at(files_at, files);
    w.bytes_at(pctab_at, pctab);
    w.put_at(filetab_at, n + 1, 4);
    for (std::size_t i = 0; i < n; ++i) w.put_at(filetab_at + 4 * (i + 1), files_at + file_off[i], 4);
    return w.data();
  }
  // 1.16+: the header's offsets to funcnametab, cutab, filetab, pctab and
  // the pclntable (function table, then the _funcs).
  const std::size_t header = 8 + (v118 ? 8 : 7) * ptr;
  const std::size_t names_at = header;
  const std::size_t cutab_at = (names_at + names.size() + 3) / 4 * 4;
  const std::size_t files_at = cutab_at + 4 * n;
  const std::size_t pctab_at = files_at + files.size();
  const std::size_t pcln_at = (pctab_at + pctab.size() + 7) / 8 * 8;
  unsigned word = 0;
  auto header_word = [&](std::uint64_t value) { w.put_at(8 + (word++) * ptr, value, ptr); };
  header_word(n);
  header_word(n);
  if (v118) header_word(header_text == ~0ull ? text : header_text);
  for (std::size_t o : {names_at, cutab_at, files_at, pctab_at, pcln_at}) header_word(o);
  w.bytes_at(names_at, names);
  for (std::size_t i = 0; i < n; ++i) w.put_at(cutab_at + 4 * i, file_off[i], 4);
  w.bytes_at(files_at, files);
  w.bytes_at(pctab_at, pctab);
  const std::size_t funcs = functab_size;  // from pcln_at
  for (std::size_t i = 0; i < n; ++i) {
    const std::uint64_t entry = v118 ? fs[i].off : text + fs[i].off;
    w.put_at(pcln_at + 2 * i * fs_size, entry, fs_size);
    w.put_at(pcln_at + (2 * i + 1) * fs_size, funcs + i * func_size, fs_size);
    const std::size_t f = pcln_at + funcs + i * func_size;
    w.put_at(f, entry, sz0);
    w.put_at(f + sz0, name_off[i], 4);
    w.put_at(f + sz0 + 16, pcfile_off[i], 4);
    w.put_at(f + sz0 + 20, pcln_off[i], 4);
    w.put_at(f + sz0 + 28, i, 4);  // cuOffset
    if (v == GoPclntabVersion::go120) {
      w.put_at(f + sz0 + 32, static_cast<std::uint32_t>(fs[i].line), 4);
      w.put_at(f + sz0 + 36, 7, 1);  // funcID
      w.put_at(f + sz0 + 37, kGoFuncFlagAsm, 1);
    }
  }
  w.put_at(pcln_at + 2 * n * fs_size, v118 ? end : text + end, fs_size);
  w.pad_to(pcln_at + funcs + n * func_size);
  return w.data();
}

const std::vector<SynthFunc> kFuncs = {
    {0x0, "go:buildid", "", 0},
    {0x20, "main.main", "/src/hello/main.go", 12},
    {0x80, "main.(*T).Method", "/src/hello/t.go", 40},
    {0x100, "example.com/dep.Greeting", "/src/dep/dep.go", 3},
};

std::span<const std::byte> Span(const std::vector<std::uint8_t> &v) {
  return {reinterpret_cast<const std::byte *>(v.data()), v.size()};
}

const GoPclntabVersion kVersions[] = {GoPclntabVersion::go12, GoPclntabVersion::go116, GoPclntabVersion::go118,
                                      GoPclntabVersion::go120};

TEST(GoPclntab, EveryLayoutBothOrdersAndPointerSizes) {
  for (GoPclntabVersion v : kVersions)
    for (auto [ptr, big] : {std::pair{8u, false}, std::pair{4u, true}, std::pair{4u, false}, std::pair{8u, true}}) {
      SCOPED_TRACE(std::string(to_string(v)) + (big ? " BE " : " LE ") + std::to_string(ptr));
      const std::uint64_t text = ptr == 8 ? 0x401000 : 0x8049000;
      auto table = BuildTable(v, ptr, big, text, kFuncs, 0x180, ptr == 4 && big ? 4 : 1);
      std::string error;
      auto t = parse_go_pclntab(Span(table), 0x500000, nullptr, {}, &error);
      ASSERT_TRUE(t) << error;
      EXPECT_EQ(t->version, v);
      EXPECT_EQ(t->pointer_size, ptr);
      EXPECT_EQ(t->endian, big ? Endian::big : Endian::little);
      EXPECT_EQ(t->function_count, 4u);
      EXPECT_TRUE(t->warnings.empty());
      ASSERT_EQ(t->functions.size(), 4u);
      for (std::size_t i = 0; i < 4; ++i) {
        const GoFunction &f = t->functions[i];
        EXPECT_EQ(f.entry, text + kFuncs[i].off);
        EXPECT_EQ(f.end, text + (i + 1 < 4 ? kFuncs[i + 1].off : 0x180));
        EXPECT_EQ(f.name, kFuncs[i].name);
        EXPECT_EQ(f.file, kFuncs[i].file);
        EXPECT_EQ(f.line, kFuncs[i].line);  // 1.20: startLine, not the pcln table's line + 1
      }
      if (v == GoPclntabVersion::go120) {
        EXPECT_EQ(t->functions[1].func_id, 7);
        EXPECT_EQ(t->functions[1].flag, kGoFuncFlagAsm);
      }
      // Without the lines: names and extents only.
      GoPclntabOptions o;
      o.lines = false;
      auto quick = parse_go_pclntab(Span(table), 0x500000, nullptr, o, &error);
      ASSERT_TRUE(quick) << error;
      EXPECT_TRUE(quick->functions[1].file.empty());
      EXPECT_EQ(quick->functions[1].name, "main.main");
    }
}

TEST(GoPclntab, TextStartAndPointers) {
  // 1.18+: the entries count from the text start (the header's, or the
  // caller's); before, they are pointers the pointer function relocates.
  auto t118 = BuildTable(GoPclntabVersion::go120, 8, false, 0x401000, kFuncs, 0x180, 1, 0);
  std::string error;
  auto t = parse_go_pclntab(Span(t118), 0x500000, nullptr, {}, &error);
  ASSERT_TRUE(t) << error;
  EXPECT_EQ(t->text_start, 0u);  // the header's "unused" field
  EXPECT_EQ(t->functions[1].entry, 0x20u);
  GoPclntabOptions o;
  o.text_start = 0x401000;
  t = parse_go_pclntab(Span(t118), 0x500000, nullptr, o, &error);
  ASSERT_TRUE(t) << error;
  EXPECT_EQ(t->functions[1].entry, 0x401020u);

  auto t116 = BuildTable(GoPclntabVersion::go116, 8, false, 0, kFuncs, 0x180);
  GoPointerFn moved = [](std::uint64_t, std::uint64_t raw) { return raw + 0x7f0000000000; };
  t = parse_go_pclntab(Span(t116), 0x500000, moved, {}, &error);
  ASSERT_TRUE(t) << error;
  EXPECT_EQ(t->functions[1].entry, 0x7f0000000020u);
  EXPECT_EQ(t->functions[3].end, 0x7f0000000180u);
}

TEST(GoPclntab, Refusals) {
  auto good = BuildTable(GoPclntabVersion::go120, 8, false, 0x401000, kFuncs, 0x180);
  auto refused = [](std::vector<std::uint8_t> b, const std::string &why, GoPclntabOptions o = {}) {
    std::string error;
    auto t = parse_go_pclntab(Span(b), 0x500000, nullptr, o, &error);
    EXPECT_FALSE(t) << why;
    EXPECT_NE(error.find(why), std::string::npos) << error;
  };
  refused({}, "not a pclntab header");
  auto bad = good;
  bad[0] = 0xfe;
  refused(bad, "not a pclntab header");
  bad = good;
  bad[6] = 3;  // quantum
  refused(bad, "not a pclntab header");
  bad = good;
  bad[7] = 2;  // pointer size
  refused(bad, "not a pclntab header");
  refused(std::vector<std::uint8_t>(good.begin(), good.begin() + 40), "past its end");
  refused(std::vector<std::uint8_t>(good.begin(), good.begin() + 20), "truncated header");
  bad = good;
  std::fill(bad.begin() + 8, bad.begin() + 16, 0);  // nfunc
  refused(bad, "no functions");
  bad = good;
  bad[8 + 7 * 8 + 3] = 0x7f;  // the pclntable offset
  refused(bad, "past its end");
  GoPclntabOptions few;
  few.max_functions = 3;
  refused(good, "more functions than the limit", few);
  // The function table cut short.
  auto t = BuildTable(GoPclntabVersion::go120, 8, false, 0x401000, kFuncs, 0x180);
  t.resize(t.size() - (4 * 44) - 8);
  refused(t, "runs past the data");
  // Unsorted entries.
  std::vector<SynthFunc> unsorted = kFuncs;
  std::swap(unsorted[1].off, unsorted[2].off);
  refused(BuildTable(GoPclntabVersion::go116, 8, false, 0x401000, unsorted, 0x180), "isn't sorted");
  // A function whose name is outside the table is skipped, with a warning.
  std::vector<SynthFunc> one = {{0x0, "main.main", "/m.go", 1}, {0x10, "main.f", "/m.go", 5}};
  auto b = BuildTable(GoPclntabVersion::go12, 8, false, 0x401000, one, 0x20);
  // The second _func's nameoff (1.2: from the header).
  const std::size_t functab = 16, funcs = functab + 5 * 8 + 4;
  const std::size_t func_size = 8 + 7 * 4 + 4;
  testing::ByteWriter patch(false);
  patch.data() = b;
  patch.put_at(funcs + func_size + 8, 0x7fffffff, 4);
  std::string error;
  auto partial = parse_go_pclntab(Span(patch.data()), 0x500000, nullptr, {}, &error);
  ASSERT_TRUE(partial) << error;
  ASSERT_EQ(partial->functions.size(), 1u);
  ASSERT_EQ(partial->warnings.size(), 1u);
  EXPECT_NE(partial->warnings[0].find("1 of 2 functions"), std::string::npos) << partial->warnings[0];
  // All of them: refused.
  patch.put_at(funcs + 8, 0x7fffffff, 4);
  refused(patch.data(), "no function decodes");
}

// An ELF with code at 0x401000, the table in `table_section` at 0x4c0000
// and (when `moduledata`) a Go 1.16+ moduledata pointing to it in
// .noptrdata, its text field `md_text`.
// `no_sections`: without section headers (sstrip), so only the segments say
// where things are.
std::vector<std::uint8_t> GoElfBytes(const std::vector<std::uint8_t> &table, const std::string &table_section,
                                     bool moduledata, std::uint64_t md_text, const std::vector<std::uint8_t> &decoy = {},
                                     bool no_sections = false) {
  ElfBuilder b(ElfSpec{});
  b.add_load(".text", 0x401000, std::vector<std::uint8_t>(0x200, 0xc3), kPfR | kPfX);
  std::vector<std::uint8_t> rodata = decoy;
  rodata.resize((rodata.size() + 15) / 16 * 16, 0);
  const std::uint64_t at = 0x4c0000 + rodata.size();
  rodata.insert(rodata.end(), table.begin(), table.end());
  b.add_load(table_section, 0x4c0000, rodata, kPfR);
  ByteWriter md(false);
  md.pad_to(64);  // something before it
  if (moduledata) {
    const std::size_t m = md.size();
    // pcHeader, funcnametab (data, len, cap), ... minpc (20), maxpc, text (22).
    md.put_at(m, at, 8);
    md.put_at(m + 8, at + 8 + 8 * 8, 8);  // funcnametab = header + funcnameOffset (right after the header)
    md.put_at(m + 20 * 8, md_text + kFuncs.front().off, 8);
    md.put_at(m + 21 * 8, md_text + 0x180, 8);
    md.put_at(m + 22 * 8, md_text, 8);
    md.pad_to(m + 30 * 8);
  }
  b.add_load(".noptrdata", 0x5a0000, md.data(), kPfR | kPfW);
  std::vector<std::uint8_t> file = b.build();
  if (no_sections) {
    std::fill(file.begin() + 0x28, file.begin() + 0x30, 0);  // e_shoff
    std::fill(file.begin() + 0x3c, file.begin() + 0x40, 0);  // e_shnum, e_shstrndx
  }
  return file;
}

Image GoElf(const std::vector<std::uint8_t> &table, const std::string &table_section, bool moduledata,
            std::uint64_t md_text, const std::vector<std::uint8_t> &decoy = {}, bool no_sections = false) {
  return parse_elf(to_bytes(GoElfBytes(table, table_section, moduledata, md_text, decoy, no_sections)));
}

// With $RK_FUZZ_SEEDS set, the synthetic tables and images are written
// there as go_pclntab_fuzzer seeds (its first byte picks the path).
TEST(GoPclntab, FuzzSeeds) {
  const char *dir = std::getenv("RK_FUZZ_SEEDS");
  if (!dir || !*dir) GTEST_SKIP() << "set RK_FUZZ_SEEDS to write the fuzzer's seeds";
  std::filesystem::create_directories(dir);
  int n = 0;
  auto seed = [&](std::uint8_t mode, const std::vector<std::uint8_t> &bytes) {
    std::ofstream out(std::filesystem::path(dir) / ("seed-" + std::to_string(n++)), std::ios::binary);
    out.put(static_cast<char>(mode));
    out.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  };
  for (GoPclntabVersion v : kVersions)
    for (auto [ptr, big] : {std::pair{8u, false}, std::pair{4u, true}}) {
      auto t = BuildTable(v, ptr, big, 0x401000, kFuncs, 0x180, big ? 4 : 1);
      seed(0, t);
      seed(2, t);
    }
  auto t = BuildTable(GoPclntabVersion::go120, 8, false, 0x401000, kFuncs, 0x180, 1, 0);
  seed(3, GoElfBytes(t, ".gopclntab", true, 0x401000));
  seed(3, GoElfBytes(t, ".rodata", true, 0x401000, BuildTable(GoPclntabVersion::go116, 8, false, 0x900000, kFuncs, 0x180), true));
}

TEST(GoPclntab, FoundInItsSection) {
  auto table = BuildTable(GoPclntabVersion::go120, 8, false, 0x401000, kFuncs, 0x180);
  Image img = GoElf(table, ".gopclntab", true, 0x401000);
  std::string error;
  auto t = read_go_pclntab(img, &error);
  ASSERT_TRUE(t) << error;
  EXPECT_EQ(t->found_by, "section");
  EXPECT_EQ(t->address, 0x4c0000u);
  ASSERT_TRUE(t->moduledata);
  EXPECT_EQ(*t->moduledata, 0x5a0040u);
  EXPECT_EQ(t->functions[1].entry, 0x401020u);
  EXPECT_TRUE(t->warnings.empty()) << t->warnings[0];
}

TEST(GoPclntab, TextStartFromTheModuledata) {
  // Go 1.2x leaves the header's textStart 0: the moduledata's text counts.
  auto table = BuildTable(GoPclntabVersion::go120, 8, false, 0x401000, kFuncs, 0x180, 1, 0);
  std::string error;
  auto t = read_go_pclntab(GoElf(table, ".gopclntab", true, 0x401000), &error);
  ASSERT_TRUE(t) << error;
  EXPECT_EQ(t->text_start, 0x401000u);
  EXPECT_EQ(t->functions[2].entry, 0x401080u);
  // Without a moduledata: the text section.
  t = read_go_pclntab(GoElf(table, ".gopclntab", false, 0), &error);
  ASSERT_TRUE(t) << error;
  EXPECT_FALSE(t->moduledata);
  EXPECT_EQ(t->text_start, 0x401000u);
}

TEST(GoPclntab, ScannedWithoutTheSectionName) {
  // An ELF without section headers (or a stripped PE) has no .gopclntab:
  // the magic in read-only data. A decoy
  // table before the real one decodes too, but no moduledata points to it
  // and its functions aren't code.
  auto table = BuildTable(GoPclntabVersion::go120, 8, false, 0x401000, kFuncs, 0x180, 1, 0);
  auto decoy = BuildTable(GoPclntabVersion::go116, 8, false, 0x900000, kFuncs, 0x180);
  std::string error;
  Image img = GoElf(table, ".rodata", true, 0x401000, decoy, true);
  ASSERT_TRUE(img.sections.empty());
  auto t = read_go_pclntab(img, &error);
  ASSERT_TRUE(t) << error;
  EXPECT_EQ(t->found_by, "scan");
  EXPECT_EQ(t->version, GoPclntabVersion::go120);
  EXPECT_EQ(t->address % 16, 0u);
  EXPECT_GT(t->address, 0x4c0000u);
  EXPECT_TRUE(t->moduledata);
  EXPECT_EQ(t->functions[3].name, "example.com/dep.Greeting");
  // A 32-bit table in a 64-bit image isn't taken from a scan.
  auto narrow = BuildTable(GoPclntabVersion::go120, 4, false, 0x401000, kFuncs, 0x180);
  EXPECT_FALSE(read_go_pclntab(GoElf(narrow, ".rodata", false, 0, {}, true), &error));
  EXPECT_TRUE(error.empty());
  // With section headers and no .gopclntab, nothing is scanned: not Go.
  EXPECT_FALSE(read_go_pclntab(GoElf(table, ".rodata", true, 0x401000), &error));
  EXPECT_TRUE(error.empty());
}

TEST(GoPclntab, NotGo) {
  ElfBuilder b(ElfSpec{});
  b.add_load(".text", 0x401000, std::vector<std::uint8_t>(64, 0xc3), kPfR | kPfX);
  b.add_load(".rodata", 0x402000, std::vector<std::uint8_t>(256, 0), kPfR);
  std::string error;
  EXPECT_FALSE(read_go_pclntab(parse_elf(to_bytes(b.build())), &error));
  EXPECT_TRUE(error.empty());
  // A named table that doesn't decode says why.
  auto bad = BuildTable(GoPclntabVersion::go120, 8, false, 0x401000, kFuncs, 0x180);
  std::fill(bad.begin() + 8, bad.begin() + 16, 0);
  EXPECT_FALSE(read_go_pclntab(GoElf(bad, ".gopclntab", false, 0), &error));
  EXPECT_NE(error.find("no functions"), std::string::npos) << error;
}

TEST(GoPclntab, DisplayNames) {
  EXPECT_EQ(go_display_name("main.(*T).Method"), "main.(*T).Method");
  EXPECT_EQ(go_display_name("example.com/dep.Greeting"), "example.com/dep.Greeting");
  EXPECT_EQ(go_display_name("main.(*Lister).List\xc2\xb7" "dwrap\xc2\xb7" "1"), "main.(*Lister).List.dwrap.1");
  EXPECT_EQ(go_display_name("a\xe2\x88\x95" "b.f"), "a/b.f");
  EXPECT_EQ(go_display_name("sync.(*Pool[go.shape.interface {}]).Get"), "sync.(*Pool[go.shape.interface_{}]).Get");
  const std::string shapes(300, 'x');
  EXPECT_EQ(go_display_name("p.F[" + shapes + "].func1"), "p.F[...].func1");
  const std::string long_name = "p." + std::string(400, 'y');
  EXPECT_EQ(go_display_name(long_name).size(), 256u);
  // Not cut inside a UTF-8 sequence.
  std::string wide = "p.";
  while (wide.size() < 300) wide += "\xc3\xa9";
  const std::string cut = go_display_name(wide);
  EXPECT_LE(cut.size(), 256u);
  EXPECT_NE(static_cast<unsigned char>(cut.back()), 0xc3);
}

TEST(GoPclntab, NoReturnNames) {
  EXPECT_TRUE(go_function_no_return("runtime.throw"));
  EXPECT_TRUE(go_function_no_return("runtime.goPanicIndex"));
  EXPECT_TRUE(go_function_no_return("runtime.panicBounds"));
  EXPECT_FALSE(go_function_no_return("runtime.main"));
  EXPECT_FALSE(go_function_no_return("main.main"));
}

TEST(GoPclntab, GolangCompilerSpec) {
  auto spec = [](GoPclntabVersion v, std::uint16_t machine, bool wide) {
    ElfSpec s;
    s.machine = machine;
    s.wide = wide;
    ElfBuilder b(s);
    b.add_load(".text", 0x401000, std::vector<std::uint8_t>(0x200, 0xc3), kPfR | kPfX);
    b.add_load(".gopclntab", 0x4c0000, BuildTable(v, wide ? 8 : 4, false, 0x401000, kFuncs, 0x180), kPfR);
    return guess_language(parse_elf(to_bytes(b.build())))->id();
  };
  EXPECT_EQ(spec(GoPclntabVersion::go120, 62, true), "x86:LE:64:default:golang");
  EXPECT_EQ(spec(GoPclntabVersion::go118, 183, true), "AARCH64:LE:64:v8A:golang");
  EXPECT_EQ(spec(GoPclntabVersion::go120, 3, false), "x86:LE:32:default:golang");
  // 1.16's layout (Go 1.16 or 1.17) without build info: the stack ABI may
  // be in use, so the platform's spec.
  EXPECT_EQ(spec(GoPclntabVersion::go116, 62, true), "x86:LE:64:default:gcc");
  EXPECT_EQ(spec(GoPclntabVersion::go12, 3, false), "x86:LE:32:default:golang");  // 386: abi0 always
  // Not Go.
  ElfBuilder b(ElfSpec{});
  b.add_load(".text", 0x401000, std::vector<std::uint8_t>(16, 0xc3), kPfR | kPfX);
  EXPECT_EQ(guess_language(parse_elf(to_bytes(b.build())))->id(), "x86:LE:64:default:gcc");
}

// --- Go's own and real binaries --------------------------------------------------

std::string Env(const char *name, const char *fallback) {
  const char *v = std::getenv(name);
  return v && *v ? v : fallback;
}

bool RunQuiet(const std::string &cmd) { return std::system((cmd + " >/dev/null 2>&1").c_str()) == 0; }

std::string Capture(const std::string &cmd) {
  std::string out;
  if (FILE *p = popen(cmd.c_str(), "r")) {
    char buf[4096];
    while (std::size_t n = fread(buf, 1, sizeof buf, p)) out.append(buf, n);
    pclose(p);
  }
  while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
  return out;
}

TEST(GoPclntabReal, Go115TableFromGosymTestdata) {
  const std::string go = Env("RK_GO", REVKIT_TEST_GO);
  if (go.empty()) GTEST_SKIP() << "no Go toolchain (set RK_GO)";
  const std::string root = Capture("env GOTOOLCHAIN=local " + go + " env GOROOT");
  const std::string gz = root + "/src/debug/gosym/testdata/pcln115.gz";
  gzFile f = gzopen(gz.c_str(), "rb");
  if (!f) GTEST_SKIP() << "no " << gz;
  std::vector<std::uint8_t> data;
  char buf[65536];
  for (int n; (n = gzread(f, buf, sizeof buf)) > 0;) data.insert(data.end(), buf, buf + n);
  gzclose(f);
  std::string error;
  auto t = parse_go_pclntab(Span(data), 0, nullptr, {}, &error);
  ASSERT_TRUE(t) << error;
  EXPECT_EQ(t->version, GoPclntabVersion::go12);
  // What gosym's Test115PclnParsing expects: main.main at 0x105c280, from
  // /tmp/hello.go line 3.
  auto it = std::find_if(t->functions.begin(), t->functions.end(), [](const GoFunction &g) { return g.name == "main.main"; });
  ASSERT_NE(it, t->functions.end());
  EXPECT_EQ(it->entry, 0x105c280u);
  EXPECT_EQ(it->file, "/tmp/hello.go");
  EXPECT_EQ(it->line, 3);
  EXPECT_TRUE(t->warnings.empty());
  EXPECT_GT(t->functions.size(), 1000u);
}

// A module with methods, a closure, generics (Go 1.18+) and a dependency.
std::filesystem::path GoModule(const std::string &name, bool generics) {
  auto dir = scratch_dir(name);
  auto write = [&](const std::string &file, const std::string &text) {
    std::filesystem::create_directories((dir / file).parent_path());
    std::ofstream(dir / file) << text;
  };
  write("go.mod", "module example.com/hello\n\ngo 1.17\n\nrequire example.com/dep v0.1.0\n\nreplace example.com/dep => ./dep\n");
  write("dep/go.mod", "module example.com/dep\n\ngo 1.17\n");
  write("dep/dep.go", "package dep\n\nfunc Greeting() string { return \"hello from dep\" }\n");
  write("main.go",
        "package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n\t\"sort\"\n\n\t\"example.com/dep\"\n)\n\n"
        "type T struct{ n []int }\n\n"
        "func (t *T) Method(i int) int { return t.n[i] }\n\n"
        "func main() {\n"
        "\tt := &T{n: []int{3, 1, 2}}\n"
        "\tsort.Slice(t.n, func(i, j int) bool { return t.n[i] < t.n[j] })\n"
        "\tfmt.Println(dep.Greeting(), t.Method(len(os.Args)))\n}\n");
  if (generics) {
    std::string mod = "module example.com/hello\n\ngo 1.18\n\nrequire example.com/dep v0.1.0\n\nreplace example.com/dep => ./dep\n";
    write("go.mod", mod);
    write("generic.go",
          "package main\n\nfunc Map[T, U any](xs []T, f func(T) U) []U {\n\tvar out []U\n\tfor _, x := range xs "
          "{\n\t\tout = append(out, f(x))\n\t}\n\treturn out\n}\n\nvar _ = Map([]int{1}, func(i int) string { return \"\" "
          "})\n");
  }
  return dir;
}

// Builds `dir` twice (with and without symbols) and checks the stripped
// build's table against the other's symbol table: every function is at a
// symbol of its name (assembly ones have ".abi0" there; Mach-O adds "_").
void CheckAgainstSymbols(const std::string &go, const std::filesystem::path &dir, const std::string &env,
                         const std::string &flags, const std::string &tag, GoPclntabVersion version) {
  SCOPED_TRACE(tag);
  const std::string base = "cd " + dir.string() + " && env GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-p=2 GOWORK=off CGO_ENABLED=0 " +
                           env + " " + go + " build " + flags;
  ASSERT_TRUE(RunQuiet(base + " -o " + tag + " .")) << base;
  ASSERT_TRUE(RunQuiet(base + " -ldflags=\"-s -w\" -o " + tag + "-s .")) << base;
  Image full = load_file(dir / tag);
  Image stripped = load_file(dir / (tag + "-s"));
  std::string error;
  auto t = read_go_pclntab(stripped, &error);
  ASSERT_TRUE(t) << error;
  EXPECT_EQ(t->version, version);
  EXPECT_TRUE(t->moduledata);
  // The symbol table as Go's own nm reads it (the PE loader doesn't read
  // COFF symbols): "  4b4f60 T main.main".
  std::multimap<std::uint64_t, std::string> syms;
  {
    std::istringstream nm(Capture("env GOTOOLCHAIN=local " + go + " tool nm " + (dir / tag).string()));
    for (std::string line; std::getline(nm, line);) {
      std::istringstream f(line);
      std::string addr, kind, name;
      if (f >> addr >> kind >> name && (kind == "T" || kind == "t")) syms.emplace(std::stoull(addr, nullptr, 16), name);
    }
  }
  ASSERT_FALSE(syms.empty());
  // The two builds lay the code out alike: the full build's table has the
  // same functions at the same addresses.
  auto ft = read_go_pclntab(full, &error);
  ASSERT_TRUE(ft) << error;
  ASSERT_EQ(ft->functions.size(), t->functions.size());
  std::size_t matched = 0;
  bool main_main = false;
  for (std::size_t i = 0; i < t->functions.size(); ++i) {
    const GoFunction &f = t->functions[i];
    EXPECT_EQ(f.entry, ft->functions[i].entry) << f.name;
    EXPECT_EQ(f.name, ft->functions[i].name);
    bool found = false;
    // nm spells an old toolchain's middle dots as '.', Mach-O's names with
    // a leading '_'.
    const std::string shown = go_display_name(f.name);
    for (auto [it, end] = syms.equal_range(ft->functions[i].entry); it != end && !found; ++it)
      for (std::string_view s : {std::string_view(it->second), std::string_view(it->second).substr(it->second.starts_with("_"))})
        found = found || s == f.name || s == shown || s == shown + ".abi0";
    matched += found;
    if (f.name == "main.main") {
      main_main = true;
      EXPECT_TRUE(f.file.ends_with("main.go")) << f.file;
      EXPECT_EQ(f.line, 15);
    }
  }
  EXPECT_TRUE(main_main);
  // go:buildid has no symbol of that name on every format, and a few
  // linker-made functions are spelled differently (Mach-O's
  // "_.goready.func1").
  EXPECT_GE(matched * 100, t->functions.size() * 99) << matched << " of " << t->functions.size();
}

TEST(GoPclntabReal, CurrentGo) {
  const std::string go = Env("RK_GO", REVKIT_TEST_GO);
  if (go.empty()) GTEST_SKIP() << "no Go toolchain (set RK_GO)";
  auto dir = GoModule("pclntab-new", true);
  CheckAgainstSymbols(go, dir, "", "", "elf", GoPclntabVersion::go120);
  CheckAgainstSymbols(go, dir, "", "-buildmode=pie", "pie", GoPclntabVersion::go120);
  CheckAgainstSymbols(go, dir, "GOARCH=arm64", "", "arm64", GoPclntabVersion::go120);
  CheckAgainstSymbols(go, dir, "GOARCH=386", "", "386", GoPclntabVersion::go120);
  CheckAgainstSymbols(go, dir, "GOOS=windows GOARCH=amd64", "", "pe.exe", GoPclntabVersion::go120);
  CheckAgainstSymbols(go, dir, "GOOS=darwin GOARCH=amd64", "", "macho", GoPclntabVersion::go120);
  CheckAgainstSymbols(go, dir, "GOOS=darwin GOARCH=arm64", "", "macho-arm64", GoPclntabVersion::go120);
  // A stripped PE has no section to find it by: the scan.
  std::string error;
  auto pe = read_go_pclntab(load_file(dir / "pe.exe-s"), &error);
  ASSERT_TRUE(pe) << error;
  EXPECT_EQ(pe->found_by, "scan");
  EXPECT_EQ(guess_language(load_file(dir / "elf-s"))->id(), "x86:LE:64:default:golang");
  EXPECT_EQ(guess_language(load_file(dir / "pe.exe-s"))->id(), "x86:LE:64:default:golang");
  EXPECT_EQ(guess_language(load_file(dir / "arm64-s"))->id(), "AARCH64:LE:64:v8A:golang");
  EXPECT_EQ(guess_language(load_file(dir / "macho-arm64-s"))->id(), "AARCH64:LE:64:AppleSilicon:golang");
}

TEST(GoPclntabReal, GoBefore118) {
  const std::string go = Env("RK_GO_OLD", "");
  if (go.empty()) GTEST_SKIP() << "no Go before 1.18 (set RK_GO_OLD to its go binary)";
  auto dir = GoModule("pclntab-old", false);
  CheckAgainstSymbols(go, dir, "", "", "elf", GoPclntabVersion::go116);
  // A PIE's table is in .data.rel.ro, its entries relocated.
  CheckAgainstSymbols(go, dir, "", "-buildmode=pie", "pie", GoPclntabVersion::go116);
  CheckAgainstSymbols(go, dir, "GOOS=windows", "", "pe.exe", GoPclntabVersion::go116);
  CheckAgainstSymbols(go, dir, "GOARCH=arm64", "", "arm64", GoPclntabVersion::go116);
  // Go 1.17: the register ABI on amd64 (golang), not yet on arm64.
  EXPECT_EQ(guess_language(load_file(dir / "elf-s"))->id(), "x86:LE:64:default:golang");
  EXPECT_EQ(guess_language(load_file(dir / "arm64-s"))->id(), "AARCH64:LE:64:v8A:default");
}

}  // namespace
}  // namespace revkit::loader
