// The PDB reader on synthetic and damaged input: hand-written records for
// paths the fixtures don't reach (MSVC-style frame symbols, OMAP), broken
// containers and records, truncation and random mutation of a real PDB.
// Nothing may crash, hang or read out of bounds (run these under ASan).
#include "pdb_builder.h"
#include "revkit/debuginfo/pdb.h"
#include "revkit/types/print.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>

namespace revkit::debuginfo {
namespace {

using testing::Buf;
using testing::PdbSpec;
using testing::Symbols;
using types::TypeStore;

constexpr std::uint16_t LF_MODIFIER = 0x1001, LF_POINTER = 0x1002, LF_PROCEDURE = 0x1008,
                        LF_ARGLIST = 0x1201, LF_FIELDLIST = 0x1203, LF_INDEX = 0x1404,
                        LF_MEMBER = 0x150d, LF_ARRAY = 0x1503, LF_STRUCTURE = 0x1505,
                        LF_ENUM = 0x1507, LF_ENUMERATE = 0x1502, LF_FUNC_ID = 0x1601;
constexpr std::uint16_t S_END = 0x0006, S_BLOCK32 = 0x1103, S_REGISTER = 0x1106,
                        S_UDT = 0x1108, S_BPREL32 = 0x110b, S_GDATA32 = 0x110d,
                        S_PUB32 = 0x110e, S_GPROC32 = 0x1110, S_REGREL32 = 0x1111,
                        S_GPROC32_ID = 0x1147, S_INLINESITE = 0x114d, S_INLINESITE_END = 0x114e,
                        S_LOCAL = 0x113e;
constexpr std::uint32_t T_INT4 = 0x74, T_VOID = 0x03;

PdbDebugInfo read(const std::vector<std::uint8_t> &bytes, TypeStore &store, std::uint64_t base = 0) {
  PdbOptions opt;
  opt.image_base = base;
  PdbDebugInfo info = read_pdb(bytes, store, opt);
  // Everything read must be printable without trouble.
  for (const Function &f : info.functions)
    if (f.prototype.valid()) (void)types::prototype(store, f.prototype, f.name);
  for (types::TypeId id : info.types) {
    (void)types::definition(store, id);
    (void)store.size_of(id);
    (void)store.align_of(id);
  }
  return info;
}

// Read, tolerating PdbError (an unreadable container) but nothing else.
void exercise(const std::vector<std::uint8_t> &bytes) {
  TypeStore store;
  try {
    read(bytes, store, 0x140000000);
    (void)read_pdb_identity(bytes);
  } catch (const PdbError &) {
  }
}

bool has_diag(const DebugInfo &info, std::string_view what) {
  for (const Diagnostic &d : info.diagnostics)
    if (d.message.find(what) != std::string::npos) return true;
  return false;
}

std::uint32_t int_int_proc(testing::Types &t, std::uint32_t nargs = 2) {
  Buf args;
  args.u32(nargs);
  for (std::uint32_t i = 0; i < nargs; ++i) args.u32(T_INT4);
  std::uint32_t al = t.add(LF_ARGLIST, args);
  return t.add(LF_PROCEDURE, Buf().u32(T_INT4).u8(0).u8(0).u16(std::uint16_t(nargs)).u32(al));
}

TEST(PdbSynthetic, MinimalPdbReads) {
  PdbSpec p;
  std::uint32_t fn = int_int_proc(p.tpi);
  Symbols m;
  m.add(S_GPROC32, testing::proc(fn, 0x10, 1, 0x20, "ns::add"));
  m.add(S_LOCAL, Buf().u32(T_INT4).u16(1).str("a"));
  m.add(S_LOCAL, Buf().u32(T_INT4).u16(1).str("b"));
  m.add(S_END, Buf());
  p.modules.push_back(m);
  p.globals.add(S_PUB32, Buf().u32(2).u32(0x10).u16(1).str("?add@ns@@YAHHH@Z"));
  TypeStore s;
  PdbDebugInfo info = read(testing::build_pdb(p), s, 0x400000);
  EXPECT_TRUE(info.diagnostics.empty()) << info.diagnostics.front().message;
  EXPECT_EQ(info.identity.age, 1u);
  EXPECT_TRUE(info.identity.has_ipi);
  EXPECT_EQ(info.identity.named_streams.count("/names"), 1u);
  ASSERT_EQ(info.functions.size(), 1u);
  const Function &f = info.functions[0];
  EXPECT_EQ(f.entry, 0x401010u);
  EXPECT_EQ(f.ranges[0].end, 0x401030u);
  EXPECT_EQ(f.name, "add");
  EXPECT_EQ(f.qualified_name, "ns::add");
  EXPECT_EQ(f.linkage_name, "?add@ns@@YAHHH@Z");
  EXPECT_EQ(types::prototype(s, f.prototype, f.name), "int add(int a, int b)");
  ASSERT_EQ(info.publics.size(), 1u);
  EXPECT_EQ(info.publics[0].demangled, "int __cdecl ns::add(int, int)");
  ASSERT_EQ(info.modules.size(), 1u);
  ASSERT_EQ(info.contributions.size(), 1u);
  EXPECT_EQ(info.contributions[0].address, 0x401000u);
}

// MSVC writes parameters as S_REGREL32 (or S_BPREL32 on x86), first and in
// order, without S_LOCAL's parameter flag.
TEST(PdbSynthetic, FrameSymbolParameters) {
  PdbSpec p;
  std::uint32_t fn = int_int_proc(p.tpi);
  Symbols m;
  m.add(S_GPROC32, testing::proc(fn, 0x0, 1, 0x40, "regrel"));
  m.add(S_REGREL32, Buf().u32(8).u32(T_INT4).u16(335).str("x"));
  m.add(S_REGREL32, Buf().u32(16).u32(T_INT4).u16(335).str("y"));
  m.add(S_REGREL32, Buf().u32(0xfffffff8u).u32(T_INT4).u16(335).str("local"));
  m.add(S_END, Buf());
  m.add(S_GPROC32, testing::proc(fn, 0x40, 1, 0x40, "bprel"));
  m.add(S_BPREL32, Buf().u32(8).u32(T_INT4).str("p"));
  m.add(S_REGISTER, Buf().u32(T_INT4).u16(17).str("q"));
  m.add(S_BLOCK32, Buf().u32(0).u32(0).u32(4).u32(0x44).u16(1).str(""));
  m.add(S_BPREL32, Buf().u32(0xfffffffcu).u32(T_INT4).str("inner"));
  m.add(S_END, Buf());
  m.add(S_END, Buf());
  p.modules.push_back(m);
  TypeStore s;
  PdbDebugInfo info = read(testing::build_pdb(p), s);
  EXPECT_TRUE(info.diagnostics.empty()) << info.diagnostics.front().message;
  ASSERT_EQ(info.functions.size(), 2u);
  EXPECT_EQ(types::prototype(s, info.functions[0].prototype, "regrel"), "int regrel(int x, int y)");
  ASSERT_EQ(info.functions[0].locals.size(), 3u);
  EXPECT_EQ(info.functions[0].locals[2].offset, -8);
  EXPECT_EQ(info.functions[0].locals[2].reg, 335);
  EXPECT_EQ(info.functions[0].locals[2].location, LocalVariable::Location::RegisterRelative);
  EXPECT_EQ(types::prototype(s, info.functions[1].prototype, "bprel"), "int bprel(int p, int q)");
  EXPECT_EQ(info.functions[1].locals[1].location, LocalVariable::Location::Register);
}

// Clang leaves unused parameters out; the rest are named if their types
// place them unambiguously.
TEST(PdbSynthetic, PartialParameterNames) {
  PdbSpec p;
  constexpr std::uint32_t T_64PRCHAR = 0x670;
  std::uint32_t args = p.tpi.add(LF_ARGLIST, Buf().u32(3).u32(T_INT4).u32(T_64PRCHAR).u32(T_INT4));
  std::uint32_t fn = p.tpi.add(LF_PROCEDURE, Buf().u32(T_INT4).u8(0).u8(0).u16(3).u32(args));
  Symbols m;
  m.add(S_GPROC32, testing::proc(fn, 0x0, 1, 0x10, "unique"));
  m.add(S_LOCAL, Buf().u32(T_64PRCHAR).u16(1).str("s"));
  m.add(S_LOCAL, Buf().u32(T_INT4).u16(1).str("n"));
  m.add(S_END, Buf());
  m.add(S_GPROC32, testing::proc(fn, 0x10, 1, 0x10, "ambiguous"));
  m.add(S_LOCAL, Buf().u32(T_INT4).u16(1).str("n"));
  m.add(S_END, Buf());
  p.modules.push_back(m);
  TypeStore s;
  PdbDebugInfo info = read(testing::build_pdb(p), s);
  ASSERT_EQ(info.functions.size(), 2u);
  EXPECT_EQ(types::prototype(s, info.functions[0].prototype, "unique"),
            "int unique(int param_1, char *s, int n)");
  EXPECT_EQ(types::prototype(s, info.functions[1].prototype, "ambiguous"),
            "int ambiguous(int param_1, char *param_2, int param_3)");
}

// Parameters of an inlined call are the inlinee's, not the caller's.
TEST(PdbSynthetic, InlineSiteLocalsAreNotParameters) {
  PdbSpec p;
  std::uint32_t fn = int_int_proc(p.tpi, 1);
  Symbols m;
  m.add(S_GPROC32, testing::proc(fn, 0x0, 1, 0x40, "outer"));
  m.add(S_INLINESITE, Buf().u32(0).u32(0).u32(0));
  m.add(S_LOCAL, Buf().u32(T_INT4).u16(1).str("inlinee_param"));
  m.add(S_INLINESITE_END, Buf());
  m.add(S_LOCAL, Buf().u32(T_INT4).u16(1).str("n"));
  m.add(S_END, Buf());
  p.modules.push_back(m);
  TypeStore s;
  PdbDebugInfo info = read(testing::build_pdb(p), s);
  ASSERT_EQ(info.functions.size(), 1u);
  EXPECT_EQ(info.functions[0].param_names, std::vector<std::string>{"n"});
}

// S_GPROC32_ID names an LF_FUNC_ID in the IPI stream, which names the type.
TEST(PdbSynthetic, IdRecords) {
  PdbSpec p;
  std::uint32_t fn = int_int_proc(p.tpi, 1);
  std::uint32_t id = p.ipi.add(LF_FUNC_ID, Buf().u32(0).u32(fn).str("f"));
  Symbols m;
  m.add(S_GPROC32_ID, testing::proc(id, 0x0, 1, 0x10, "f"));
  m.add(S_END, Buf());
  p.modules.push_back(m);
  TypeStore s;
  PdbDebugInfo info = read(testing::build_pdb(p), s);
  ASSERT_EQ(info.functions.size(), 1u);
  EXPECT_EQ(types::prototype(s, info.functions[0].prototype, "f"), "int f(int param_1)");
}

// A rewritten image (OMAP): addresses map from the original layout.
TEST(PdbSynthetic, Omap) {
  PdbSpec p;
  p.original_sections = {{".text", 0x1000, 0x1000}};
  p.omap = {{0x1000, 0x5000}, {0x1100, 0}, {0x1200, 0x7000}};
  std::uint32_t fn = int_int_proc(p.tpi, 0);
  Symbols m;
  m.add(S_GPROC32, testing::proc(fn, 0x10, 1, 0x10, "moved"));
  m.add(S_END, Buf());
  m.add(S_GPROC32, testing::proc(fn, 0x110, 1, 0x10, "removed"));
  m.add(S_END, Buf());
  m.add(S_GPROC32, testing::proc(fn, 0x204, 1, 0x10, "later"));
  m.add(S_END, Buf());
  p.modules.push_back(m);
  TypeStore s;
  PdbDebugInfo info = read(testing::build_pdb(p), s);
  ASSERT_EQ(info.functions.size(), 2u);
  EXPECT_EQ(info.functions[0].entry, 0x5010u);
  EXPECT_EQ(info.functions[1].entry, 0x7004u);
  EXPECT_TRUE(has_diag(info, "removed"));
}

TEST(PdbSynthetic, ForwardReferences) {
  PdbSpec p;
  // struct a; (no definition), struct b; with two different definitions,
  // struct c; with one.
  auto fwd = [&](const char *name) {
    return p.tpi.add(LF_STRUCTURE, Buf().u16(0).u16(0x80).u32(0).u32(0).u32(0).u16(0).str(name));
  };
  auto def = [&](const char *name, std::uint16_t size) {
    std::uint32_t fl = p.tpi.add(LF_FIELDLIST, Buf().u16(LF_MEMBER).u16(3).u32(T_INT4).u16(0).str("x"));
    return p.tpi.add(LF_STRUCTURE, Buf().u16(1).u16(0).u32(fl).u32(0).u32(0).u16(size).str(name));
  };
  std::uint32_t a = fwd("a"), b = fwd("b"), c = fwd("c");
  def("b", 4);
  def("b", 8);
  def("c", 4);
  std::uint32_t pa = p.tpi.add(LF_POINTER, Buf().u32(a).u32(0x1000c));
  std::uint32_t pb = p.tpi.add(LF_POINTER, Buf().u32(b).u32(0x1000c));
  std::uint32_t pc = p.tpi.add(LF_POINTER, Buf().u32(c).u32(0x1000c));
  std::uint32_t args = p.tpi.add(LF_ARGLIST, Buf().u32(3).u32(pa).u32(pb).u32(pc));
  std::uint32_t fn = p.tpi.add(LF_PROCEDURE, Buf().u32(T_VOID).u8(0).u8(0).u16(3).u32(args));
  Symbols m;
  m.add(S_GPROC32, testing::proc(fn, 0, 1, 1, "f"));
  m.add(S_END, Buf());
  p.modules.push_back(m);
  TypeStore s;
  PdbDebugInfo info = read(testing::build_pdb(p), s);
  ASSERT_EQ(info.functions.size(), 1u);
  const auto *ft = s.get(info.functions[0].prototype).as<types::FunctionType>();
  ASSERT_EQ(ft->params.size(), 3u);
  auto target = [&](int i) {
    return s.get(s.get(ft->params[i].type).as<types::PointerType>()->target).as<types::AggregateType>();
  };
  EXPECT_FALSE(target(0)->complete);  // no definition
  EXPECT_FALSE(target(1)->complete);  // ambiguous
  EXPECT_TRUE(target(2)->complete);
  EXPECT_EQ(target(2)->size, 4u);
}

TEST(PdbSynthetic, EnumValuesAndPadding) {
  PdbSpec p;
  Buf fl;
  fl.u16(LF_ENUMERATE).u16(3).u16(0x8000).u8(0xff).str("NEG");  // LF_CHAR -1
  while (fl.size() % 4) fl.u8(std::uint8_t(0xf0 + 4 - fl.size() % 4));
  fl.u16(LF_ENUMERATE).u16(3).u16(0x8001).u16(0x8000).str("LOW");  // LF_SHORT -32768
  while (fl.size() % 4) fl.u8(std::uint8_t(0xf0 + 4 - fl.size() % 4));
  fl.u16(LF_ENUMERATE).u16(3).u16(7).str("SEVEN");
  std::uint32_t list = p.tpi.add(LF_FIELDLIST, fl);
  std::uint32_t e = p.tpi.add(LF_ENUM, Buf().u16(3).u16(0).u32(T_INT4).u32(list).str("E"));
  p.globals.add(S_UDT, Buf().u32(e).str("E"));
  p.globals.add(S_UDT, Buf().u32(e).str("E_t"));
  TypeStore s;
  PdbDebugInfo info = read(testing::build_pdb(p), s);
  EXPECT_TRUE(info.diagnostics.empty()) << info.diagnostics.front().message;
  ASSERT_EQ(info.type_names.size(), 2u);
  EXPECT_EQ(types::definition(s, info.type_names[0].type),
            "enum E {\n    NEG = -1,\n    LOW = -32768,\n    SEVEN = 7\n};\n");
  EXPECT_EQ(types::definition(s, info.type_names[1].type), "typedef enum E E_t;\n");
}

TEST(PdbMalformed, NotAPdb) {
  TypeStore s;
  EXPECT_THROW(read_pdb({}, s), PdbError);
  std::vector<std::uint8_t> junk(4096, 0x41);
  EXPECT_THROW(read_pdb(junk, s), PdbError);
  std::string old("Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0", 44);
  old.resize(1024);
  try {
    read_pdb(std::vector<std::uint8_t>(old.begin(), old.end()), s);
    ADD_FAILURE();
  } catch (const PdbError &e) {
    EXPECT_NE(std::string(e.what()).find("2.00"), std::string::npos);
  }
}

// Damage to the superblock and directory.
TEST(PdbMalformed, Container) {
  PdbSpec p;
  int_int_proc(p.tpi);
  const std::vector<std::uint8_t> good = testing::build_pdb(p);
  auto patch32 = [&](std::size_t off, std::uint32_t v) {
    std::vector<std::uint8_t> b = good;
    for (int i = 0; i < 4; ++i) b[off + i] = std::uint8_t(v >> (8 * i));
    return b;
  };
  TypeStore s;
  EXPECT_NO_THROW(read_pdb(good, s));
  for (std::uint32_t bs : {0u, 1u, 100u, 513u, 1u << 20})
    EXPECT_THROW(read_pdb(patch32(32, bs), s), PdbError) << bs;
  EXPECT_THROW(read_pdb(patch32(40, 0), s), PdbError);           // no blocks
  EXPECT_THROW(read_pdb(patch32(40, 0xffffffff), s), PdbError);  // more blocks than the file
  EXPECT_THROW(read_pdb(patch32(44, 0), s), PdbError);           // empty directory
  EXPECT_THROW(read_pdb(patch32(44, 0x7fffffff), s), PdbError);  // directory larger than its map
  EXPECT_THROW(read_pdb(patch32(52, 0xffffff), s), PdbError);    // block map outside the file
  // The directory: stream count, a stream size, a block index.
  std::uint32_t map_block = good[52] | good[53] << 8;
  std::uint32_t dir_block = good[map_block * 512] | good[map_block * 512 + 1] << 8;
  std::size_t dir = std::size_t(dir_block) * 512;
  EXPECT_THROW(read_pdb(patch32(dir, 0xffffff), s), PdbError);
  EXPECT_THROW(read_pdb(patch32(dir + 4 + 4 * 2, 0x7fffffff), s), PdbError);  // TPI size
  std::uint32_t n = good[dir] | good[dir + 1] << 8;
  std::size_t info_block = dir + 4 + 4 * n;  // stream 1's block (stream 0 is empty)
  EXPECT_THROW(read_pdb(patch32(info_block, 0xfffff), s), PdbError);  // info stream is required
}

TEST(PdbMalformed, BadTypeRecords) {
  PdbSpec p;
  // A modifier and a pointer that refer to themselves, a struct whose field
  // list continues into itself and holds the struct by value, an argument
  // list claiming 2^32-1 entries, references past the end of the stream,
  // an unknown numeric leaf, an unknown record kind and a truncated one.
  std::uint32_t self_mod = p.tpi.next;
  p.tpi.add(LF_MODIFIER, Buf().u32(self_mod).u16(1));
  std::uint32_t self_ptr = p.tpi.next;
  p.tpi.add(LF_POINTER, Buf().u32(self_ptr).u32(0x1000c));
  std::uint32_t loop_list = p.tpi.next;
  p.tpi.add(LF_FIELDLIST, Buf().u16(LF_MEMBER).u16(3).u32(loop_list + 1).u16(0).str("self").u8(0xf1)
                              .u16(LF_INDEX).u16(0).u32(loop_list));
  p.tpi.add(LF_STRUCTURE, Buf().u16(1).u16(0).u32(loop_list).u32(0).u32(0).u16(8).str("S"));
  std::uint32_t huge = p.tpi.add(LF_ARGLIST, Buf().u32(0xffffffffu).u32(T_INT4));
  std::uint32_t bad_fn = p.tpi.add(LF_PROCEDURE, Buf().u32(0x7fffffff).u8(0).u8(0).u16(1).u32(huge));
  p.tpi.add(LF_ARRAY, Buf().u32(T_INT4).u32(0x23).u16(0x80ff).u32(0));
  p.tpi.add(LF_ARRAY, Buf().u32(0x9999).u32(0x23).u16(12).str(""));
  std::uint32_t unknown = p.tpi.add(0x7777, Buf().u32(1));
  p.tpi.add(LF_POINTER, Buf().u32(unknown).u32(0x1000c));
  p.tpi.add(LF_POINTER, Buf().u16(1));
  Symbols m;
  m.add(S_GPROC32, testing::proc(bad_fn, 0, 1, 1, "bad"));
  m.add(S_END, Buf());
  m.add(S_GPROC32, testing::proc(0x123456, 0, 1, 1, "untyped"));
  m.add(S_END, Buf());
  m.add(S_GDATA32, Buf().u32(self_ptr).u32(0x10).u16(2).str("g"));
  p.modules.push_back(m);
  TypeStore s;
  PdbDebugInfo info = read(testing::build_pdb(p), s);
  EXPECT_TRUE(has_diag(info, "argument list"));
  EXPECT_TRUE(has_diag(info, "invalid type cycles"));
  EXPECT_TRUE(has_diag(info, "numeric leaf"));
  EXPECT_TRUE(has_diag(info, "unsupported type record"));
  EXPECT_EQ(info.functions.size(), 2u);
  ASSERT_EQ(info.variables.size(), 1u);
  EXPECT_EQ(info.variables[0].address, 0x2010u);
}

TEST(PdbMalformed, SharedArgumentListsAreBudgeted) {
  // 100 procedures share one 16000-parameter list: each re-expanded it, so
  // 65k of them in a 1 MB stream made 1e9 parameters. The expansion stops
  // at a budget (4 per byte of the stream, plus 1M) with a diagnostic.
  PdbSpec p;
  Buf args;
  args.u32(16000);
  for (int i = 0; i < 16000; ++i) args.u32(T_INT4);
  const std::uint32_t al = p.tpi.add(LF_ARGLIST, args);
  for (int i = 0; i < 100; ++i) p.tpi.add(LF_PROCEDURE, Buf().u32(T_INT4).u8(0).u8(0).u16(16000).u32(al));
  TypeStore s;
  PdbDebugInfo info = read_pdb(testing::build_pdb(p), s);
  EXPECT_TRUE(has_diag(info, "too many parameters"));
}

TEST(PdbMalformed, BadSymbols) {
  PdbSpec p;
  std::uint32_t fn = int_int_proc(p.tpi);
  Symbols m;
  m.add(S_END, Buf());                                      // nothing to end
  m.add(S_GPROC32, testing::proc(fn, 0, 9, 1, "nowhere"));  // no section 9
  m.add(S_END, Buf());
  m.add(S_GPROC32, Buf().u32(0));  // truncated
  for (int i = 0; i < 2000; ++i) m.add(S_BLOCK32, Buf().u32(0).u32(0).u32(0).u32(0).u16(1).str(""));
  m.add(S_LOCAL, Buf().u32(T_INT4));  // truncated
  p.modules.push_back(m);
  Symbols bad_len;
  bad_len.data.u16(1).u16(S_END);  // length below the minimum
  p.modules.push_back(bad_len);
  p.globals.add(S_PUB32, Buf().u32(2));
  TypeStore s;
  PdbDebugInfo info = read(testing::build_pdb(p), s);
  EXPECT_TRUE(has_diag(info, "scope end without a scope"));
  EXPECT_TRUE(has_diag(info, "outside the image"));
  EXPECT_TRUE(has_diag(info, "nest too deeply"));
  EXPECT_TRUE(has_diag(info, "too many bad symbols"));
  EXPECT_TRUE(has_diag(info, "bad symbol record length"));
  EXPECT_LE(info.diagnostics.size(), 40u);
}

std::optional<std::vector<std::uint8_t>> fixture_pdb() {
  std::string path = std::string(REVKIT_FIXTURE_DIR) + "/pe-clang-O0.pdb";
  if (!std::filesystem::exists(path)) return std::nullopt;
  std::ifstream in(path, std::ios::binary);
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

TEST(PdbMalformed, Truncation) {
  auto pdb = fixture_pdb();
  if (!pdb) GTEST_SKIP() << "fixture not built";
  for (std::size_t cut = 0; cut < pdb->size(); cut += std::max<std::size_t>(1, pdb->size() / 211)) {
    std::vector<std::uint8_t> b(pdb->begin(), pdb->begin() + std::ptrdiff_t(cut));
    exercise(b);
  }
}

// Random byte changes anywhere in a real PDB.
TEST(PdbMalformed, RandomMutations) {
  auto pdb = fixture_pdb();
  if (!pdb) GTEST_SKIP() << "fixture not built";
  std::mt19937 rng(4321);
  for (int iter = 0; iter < 1200; ++iter) {
    std::vector<std::uint8_t> b = *pdb;
    int flips = 1 + int(rng() % 16);
    for (int k = 0; k < flips; ++k) {
      std::size_t at = rng() % b.size();
      switch (rng() % 4) {
        case 0: b[at] = std::uint8_t(rng()); break;
        case 1: b[at] ^= std::uint8_t(1u << (rng() % 8)); break;
        case 2: b[at] = 0xff; break;
        default: b[at] = 0; break;
      }
    }
    exercise(b);
  }
}

}  // namespace
}  // namespace revkit::debuginfo

namespace revkit::debuginfo {
namespace {

// MSVC 17.x's LF_STRUCTURE2 (32-bit properties; count and size as
// numerics), and a C++ class's vftable pointer (LF_VFUNCTAB) with the
// virtual functions it introduces (LF_ONEMETHOD, LF_METHOD over an
// LF_METHODLIST): a "vftable" field pointing to "<class>_vtbl".
TEST(PdbSynthetic, Structure2AndVirtualFunctions) {
  constexpr std::uint16_t LF_STRUCTURE2 = 0x1609, LF_VFUNCTAB = 0x1409, LF_ONEMETHOD = 0x1511,
                          LF_METHOD = 0x150f, LF_METHODLIST = 0x1206, LF_VTSHAPE = 0x000a;
  PdbSpec p;
  const std::uint32_t fn = int_int_proc(p.tpi, 1);
  const std::uint32_t shape = p.tpi.add(LF_VTSHAPE, Buf().u16(2).u8(0x11));
  const std::uint32_t vtptr = p.tpi.add(LF_POINTER, Buf().u32(shape).u32(0x1000c));
  // Two overloads of "scale", one an introducing virtual at slot 1.
  const std::uint32_t ml = p.tpi.add(LF_METHODLIST, Buf().u16(0x13).u16(0).u32(fn).u32(8).u16(0x03).u16(0).u32(fn));
  Buf fl;
  fl.u16(LF_VFUNCTAB).u16(0).u32(vtptr);
  fl.u16(LF_MEMBER).u16(3).u32(T_INT4).u16(8).str("x");
  while (fl.size() % 4) fl.u8(std::uint8_t(0xf0 + 4 - fl.size() % 4));
  fl.u16(LF_ONEMETHOD).u16(0x13).u32(fn).u32(0).str("area");  // intro virtual, slot 0
  while (fl.size() % 4) fl.u8(std::uint8_t(0xf0 + 4 - fl.size() % 4));
  fl.u16(LF_METHOD).u16(2).u32(ml).str("scale");
  const std::uint32_t list = p.tpi.add(LF_FIELDLIST, fl);
  // props, field list, derived, vshape, count, size, name.
  const std::uint32_t cls =
      p.tpi.add(LF_STRUCTURE2, Buf().u32(0).u32(list).u32(0).u32(shape).u16(3).u16(16).str("geo::Shape"));
  const std::uint32_t pcls = p.tpi.add(LF_POINTER, Buf().u32(cls).u32(0x1000c));
  const std::uint32_t args = p.tpi.add(LF_ARGLIST, Buf().u32(1).u32(pcls));
  const std::uint32_t use = p.tpi.add(LF_PROCEDURE, Buf().u32(T_VOID).u8(0).u8(0).u16(1).u32(args));
  Symbols m;
  m.add(S_GPROC32, testing::proc(use, 0, 1, 1, "f"));
  m.add(S_END, Buf());
  p.modules.push_back(m);
  TypeStore s;
  PdbDebugInfo info = read(testing::build_pdb(p), s);
  ASSERT_EQ(info.functions.size(), 1u);
  const auto *ft = s.get(info.functions[0].prototype).as<types::FunctionType>();
  ASSERT_EQ(ft->params.size(), 1u);
  const auto *agg = s.get(s.get(ft->params[0].type).as<types::PointerType>()->target).as<types::AggregateType>();
  ASSERT_NE(agg, nullptr);
  EXPECT_EQ(agg->name, "geo::Shape");
  EXPECT_EQ(agg->kind, types::AggregateKind::Struct);
  EXPECT_EQ(agg->size, 16u);
  ASSERT_EQ(agg->fields.size(), 2u);
  EXPECT_EQ(agg->fields[0].name, "vftable");
  EXPECT_EQ(agg->fields[0].bit_offset, 0u);
  EXPECT_EQ(agg->fields[1].name, "x");
  const auto *vt = s.get(s.get(agg->fields[0].type).as<types::PointerType>()->target).as<types::AggregateType>();
  ASSERT_NE(vt, nullptr);
  EXPECT_EQ(vt->name, "geo::Shape_vtbl");
  ASSERT_EQ(vt->fields.size(), 2u);
  EXPECT_EQ(vt->fields[0].name, "area");
  EXPECT_EQ(vt->fields[0].bit_offset, 0u);
  EXPECT_EQ(vt->fields[1].name, "scale");
  EXPECT_EQ(vt->fields[1].bit_offset, 64u);
}

}  // namespace
}  // namespace revkit::debuginfo
