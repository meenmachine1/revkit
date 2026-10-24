// Type archives (revkit/cparse/archive.h): a header that parses back to the
// same types, byte-identically when written again.

#include "revkit/cparse/archive.h"
#include "revkit/cparse/cparse.h"

#include "revkit/types/describe.h"
#include "revkit/types/packing.h"

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <unistd.h>

namespace {

using namespace revkit;
using types::TypeId;

struct Parsed {
  types::TypeStore store;
  cparse::Result r;
  std::map<std::string, TypeId> named;
};

std::unique_ptr<Parsed> Parse(const std::string &text, const std::string &target = "x86_64-linux-gnu") {
  auto p = std::make_unique<Parsed>();
  cparse::Options o;
  o.profile = *cparse::profile_named(target);
  const cparse::Source src{"t.h", text, false};
  p->r = cparse::parse(p->store, std::span<const cparse::Source>(&src, 1), o);
  for (const auto &n : p->r.named) p->named.emplace(n.key, n.id);
  return p;
}

cparse::Archive Write(const Parsed &p, const std::string &target = "x86_64-linux-gnu") {
  std::vector<TypeId> roots;
  for (const auto &n : p.r.named)
    if (!n.where.system) roots.push_back(n.id);
  cparse::ArchiveOptions o;
  o.name = "t";
  o.profile = *cparse::profile_named(target);
  return cparse::write_archive(p.store, roots, o);
}

// The archive reproduces every type, and writing the parsed archive again
// gives the same bytes.
void ExpectRoundTrip(const std::string &text, const std::string &target = "x86_64-linux-gnu") {
  SCOPED_TRACE(target);
  auto p = Parse(text, target);
  ASSERT_EQ(p->r.errors, 0u) << (p->r.diagnostics.empty() ? "" : p->r.diagnostics[0].text);
  cparse::Archive a = Write(*p, target);
  EXPECT_EQ(a.mismatches, 0u) << a.header;
  for (const std::string &n : a.notes) ADD_FAILURE() << n;
  auto q = Parse(a.header, target);
  EXPECT_EQ(q->r.errors, 0u) << a.header;
  for (const auto &e : a.entries) {
    ASSERT_TRUE(q->named.contains(e.key)) << e.key;
    EXPECT_EQ(q->store.hash(q->named.at(e.key)).hex(), e.source_hash) << e.key;
    EXPECT_EQ(e.hash, e.source_hash) << e.key;
  }
  cparse::Archive again = Write(*q, target);
  EXPECT_EQ(again.header, a.header);
}

constexpr const char *kHeader = R"(
#include <stdint.h>
#include <stdbool.h>
struct node;
typedef struct node node_t;
typedef int (*cmp_fn)(const node_t *a, const node_t *b);
enum color { RED, GREEN = 5, BLUE };
enum __attribute__((packed)) small { S0, S1 };
typedef enum { A1 = 1, A2 = 2 } anon_enum_t;
struct node {
  node_t *next;
  struct { int x, y; } pos;
  union { uint32_t u; float f; };
  unsigned flag : 1, kind : 3;
  int delta : 7;
  bool live;
  enum color c;
  enum small s;
  cmp_fn cmp;
  char name[16];
};
#pragma pack(push, 2)
struct pk2 { char a; int b; short c; double d; };
#pragma pack(pop)
struct __attribute__((packed)) pk1 { char a; long b; unsigned bits : 5; };
struct al { int x; } __attribute__((aligned(32)));
typedef struct { struct pk2 inner; struct al a; } holder_t;
struct flex { uint16_t len; uint8_t data[]; };
typedef holder_t holders_t[4];
typedef void (*callback_t)(void *ctx, holders_t *h, ...);
struct only_declared;
struct uses { struct only_declared *p; callback_t cb; anon_enum_t e; };
)";

TEST(TypeArchive, RoundTripsEveryTarget) {
  for (const char *target : {"x86_64-linux-gnu", "aarch64-linux-gnu", "riscv64-linux-gnu", "x86_64-w64-mingw32",
                             "x86_64-pc-windows-msvc", "i386-linux-gnu", "arm-linux-gnueabihf"})
    ExpectRoundTrip(kHeader, target);
}

TEST(TypeArchive, HeaderShape) {
  auto p = Parse(kHeader);
  cparse::Archive a = Write(*p);
  const std::string &h = a.header;
  EXPECT_NE(h.find("#ifndef REVKIT_ARCHIVE_T_H"), std::string::npos);
  EXPECT_NE(h.find("x86_64-linux-gnu: pointer 8"), std::string::npos);
  EXPECT_NE(h.find("struct only_declared;\n"), std::string::npos);
  EXPECT_NE(h.find("#pragma pack(push, 2)\nstruct pk2 {"), std::string::npos) << h;
  EXPECT_NE(h.find("_Static_assert(sizeof(struct node) == "), std::string::npos);
  EXPECT_NE(h.find("_Static_assert(sizeof(holders_t) == "), std::string::npos);
  EXPECT_NE(h.find("#define bool _Bool"), std::string::npos);
  EXPECT_NE(h.find("typedef enum {\n    A1 = 1,\n    A2 = 2\n} anon_enum_t;"), std::string::npos) << h;
  // Dependencies first: what a struct holds by value, and the typedefs it names.
  EXPECT_LT(h.find("struct pk2 {"), h.find("holder_t;"));
  EXPECT_LT(h.find("} holder_t;"), h.find("holders_t[4];"));
  EXPECT_LT(h.find("typedef struct node node_t;"), h.find("struct node {"));
  std::map<std::string, std::string> forms;
  for (const auto &e : a.entries) forms[e.key] = e.form;
  EXPECT_EQ(forms["struct pk2"], "pack(2)");
  EXPECT_EQ(forms["struct pk1"], "pack(1)");
  EXPECT_EQ(forms["struct node"], "natural");
  EXPECT_EQ(forms["struct only_declared"], "declaration");
  EXPECT_EQ(forms["typedef node_t"], "typedef");
  for (const auto &e : a.entries) EXPECT_GT(e.line, 0u) << e.key;
}

// A layout no #pragma pack gives (debug info's, or the editor's explicit
// offsets): a packed struct whose gaps are unnamed bitfields.
TEST(TypeArchive, ExplicitOffsets) {
  types::TypeStore s;
  const TypeId c = s.int_type(1, true, types::IntRank::Char);  // signed char: the same on every target
  const TypeId i = s.int_type(4, true, types::IntRank::Int);
  const TypeId u = s.int_type(4, false, types::IntRank::Int);
  types::TypeGraph g;
  types::AggregateType a;
  a.name = "odd";
  a.size = 16;
  a.fields = {{"a", c, 0, 0}, {"b", i, 2 * 8, 0}, {"bits", u, 7 * 8 + 3, 4}, {"c", c, 9 * 8, 0}};
  const TypeId local = g.add(a);
  types::infer_packing(g, s, {{local, 8}});
  const TypeId odd = s.intern(g)[0];
  ASSERT_TRUE(s.get(odd).as<types::AggregateType>()->packed);
  const TypeId undef = s.undefined(4);
  types::AggregateType w;
  w.name = "wrap";
  w.size = 28;
  w.fields = {{"o", odd, 0, 0}, {"raw", undef, 16 * 8, 0}, {"p", s.pointer_to(s.undefined(1)), 20 * 8, 0}};
  types::TypeGraph g2;
  const TypeId l2 = g2.add(w);
  types::infer_packing(g2, s, {{l2, 8}});
  const TypeId wrap = s.intern(g2)[0];

  for (const char *target : {"x86_64-linux-gnu", "aarch64-linux-gnu"}) {
    cparse::ArchiveOptions o;
    o.name = "odd";
    o.profile = *cparse::profile_named(target);
    std::vector<TypeId> roots{wrap};
    cparse::Archive ar = cparse::write_archive(s, roots, o);
    EXPECT_EQ(ar.mismatches, 0u) << ar.header;
    for (const auto &e : ar.entries)
      if (e.key == "struct odd") EXPECT_EQ(e.form, "explicit");
    EXPECT_NE(ar.header.find("#if !defined(__revkit__)\ntypedef unsigned char undefined1;\n"
                             "typedef unsigned char undefined4[4];\n#endif"),
              std::string::npos)
        << ar.header;
    EXPECT_NE(ar.header.find("    unsigned char : 8;\n"), std::string::npos);
    auto q = Parse(ar.header, target);
    EXPECT_EQ(q->r.errors, 0u) << (q->r.diagnostics.empty() ? "" : q->r.diagnostics[0].text);
    EXPECT_EQ(q->store.hash(q->named.at("struct wrap")), s.hash(wrap));
  }
}

// Ghidra's undefinedN names parse as undefined types (and a header's own
// typedef of one still wins).
TEST(TypeArchive, UndefinedNamesParse) {
  auto p = Parse("struct s { undefined4 a; undefined b; undefined8 *c; };\ntypedef int undefined2;\nundefined2 x;");
  EXPECT_EQ(p->r.errors, 0u);
  const auto *a = p->store.get(p->named.at("struct s")).as<types::AggregateType>();
  ASSERT_NE(a, nullptr);
  EXPECT_EQ(p->store.get(a->fields[0].type).as<types::UndefinedType>()->size, 4u);
  EXPECT_EQ(p->store.get(a->fields[1].type).as<types::UndefinedType>()->size, 1u);
  EXPECT_TRUE(p->named.contains("typedef undefined2"));
}

// One name, two definitions: the root's is written, the other is a note.
TEST(TypeArchive, OneDefinitionPerName) {
  types::TypeStore s;
  auto agg = [&](std::string name, std::uint64_t size, std::vector<types::Field> fields) {
    types::AggregateType a;
    a.name = std::move(name);
    a.size = size;
    a.fields = std::move(fields);
    return s.intern(types::Type(a));
  };
  const TypeId a1 = agg("a", 4, {{"x", s.int_type(4, true, types::IntRank::Int), 0, 0}});
  const TypeId a2 = agg("a", 8, {{"y", s.int_type(8, true, types::IntRank::Long), 0, 0}});
  const TypeId b = agg("b", 8, {{"p", s.pointer_to(a2), 0, 0}});
  std::vector<TypeId> roots{a1, b};
  cparse::ArchiveOptions o;
  o.profile = *cparse::profile_named("x86_64-linux-gnu");
  cparse::Archive ar = cparse::write_archive(s, roots, o);
  EXPECT_NE(ar.header.find("int x;"), std::string::npos);
  EXPECT_EQ(ar.header.find("long y;"), std::string::npos);
  ASSERT_FALSE(ar.notes.empty());
  EXPECT_NE(ar.notes[0].find("struct a: 2 definitions"), std::string::npos) << ar.notes[0];
  EXPECT_EQ(ar.mismatches, 1u);  // struct b names the other one
}

}  // namespace

namespace {

// A library archive's prototypes: asm labels, noreturn and calling
// conventions survive the header, and every prototype parses back to the
// same type.
TEST(TypeArchive, LibraryPrototypes) {
  const std::string text =
      "typedef struct _IO_FILE FILE;\n"
      "struct _IO_FILE { int _flags; };\n"
      "extern int fprintf(FILE *__restrict __stream, const char *__restrict __format, ...);\n"
      "extern int sscanf(const char *__s, const char *__format, ...) __asm__(\"\" \"__isoc99_sscanf\");\n"
      "extern void exit(int __status) __attribute__((__noreturn__));\n"
      "_Noreturn void abort(void);\n"
      "double erf(double);\n"
      "typedef void (__stdcall *CB)(int);\n"
      "int __stdcall WinThing(CB cb, int x);\n";
  for (const std::string target : {"x86_64-linux-gnu", "i686-w64-mingw32"}) {
    auto p = Parse(text, target);
    ASSERT_EQ(p->r.errors, 0u) << target;
    std::map<std::string, const cparse::Prototype *> protos;
    for (const auto &pr : p->r.prototypes) protos.emplace(pr.name, &pr);
    ASSERT_TRUE(protos.contains("sscanf"));
    EXPECT_EQ(protos.at("sscanf")->asm_label, "__isoc99_sscanf");
    EXPECT_TRUE(protos.at("exit")->noreturn);
    EXPECT_TRUE(protos.at("abort")->noreturn);
    EXPECT_FALSE(protos.at("fprintf")->noreturn);

    cparse::ArchiveOptions o;
    o.name = "lib";
    o.profile = *cparse::profile_named(target);
    for (const auto &pr : p->r.prototypes) o.functions.push_back({pr.name, pr.type, pr.noreturn});
    cparse::Archive a = cparse::write_archive(p->store, {}, o);
    EXPECT_EQ(a.mismatches, 0u) << target << "\n" << a.header;
    std::size_t prototypes = 0;
    for (const auto &e : a.entries) {
      if (e.form != "prototype") continue;
      ++prototypes;
      EXPECT_EQ(e.key.rfind("function ", 0), 0u);
      EXPECT_EQ(e.hash, e.source_hash) << e.key;
    }
    EXPECT_EQ(prototypes, p->r.prototypes.size());
    EXPECT_NE(a.header.find("_Noreturn void exit(int __status);"), std::string::npos) << a.header;
    EXPECT_NE(a.header.find("double erf(double);"), std::string::npos) << a.header;
    if (target.starts_with("i686"))
      EXPECT_NE(a.header.find("int __stdcall WinThing("), std::string::npos) << a.header;
  }
}

// The prototypes system headers declare are listed only on request, and a
// library's interface declaration wins over a later inline definition.
TEST(TypeArchive, SystemPrototypes) {
  revkit::types::TypeStore store;
  cparse::Options o;
  o.profile = *cparse::profile_named("x86_64-linux-gnu");
  const cparse::Source src{"s.h",
                           "# 1 \"s.h\" 3\n"
                           "int f(int a);\n"
                           "extern inline int f(int b) { return b; }\n",
                           false};
  cparse::Result r = cparse::parse(store, std::span<const cparse::Source>(&src, 1), o);
  EXPECT_TRUE(r.prototypes.empty());
  o.system_prototypes = true;
  r = cparse::parse(store, std::span<const cparse::Source>(&src, 1), o);
  ASSERT_EQ(r.prototypes.size(), 1u);
  const auto *fn = store.get(r.prototypes[0].type).as<revkit::types::FunctionType>();
  ASSERT_NE(fn, nullptr);
  EXPECT_EQ(fn->params.at(0).name, "a");
}

}  // namespace

namespace {

// What a C89 compiler accepts: clang -std=c89 -pedantic-errors for an
// ARMv5TE target (CodeWarrior's DS games), when the build found clang.
// Returns the compiler's messages, or "" when it accepted the text.
std::string CompileC89(const std::string &text, const std::string &name) {
  const std::filesystem::path dir = std::filesystem::temp_directory_path() / ("revkit-c89-" + std::to_string(::getpid()));
  std::filesystem::create_directories(dir);
  std::ofstream(dir / (name + ".c")) << text;
  const std::string cmd = std::string(REVKIT_TEST_CLANG) +
                          " -std=c89 -pedantic-errors --target=armv5te-none-eabi -c -o /dev/null " +
                          (dir / (name + ".c")).string() + " 2>" + (dir / (name + ".log")).string();
  const int rc = std::system(cmd.c_str());
  std::ifstream in(dir / (name + ".log"));
  std::string log((std::istreambuf_iterator<char>(in)), {});
  std::filesystem::remove_all(dir);
  return rc == 0 ? std::string() : log.empty() ? std::string("failed") : log;
}

constexpr const char *kC89Header = R"(
#include <stdint.h>
#include <stdbool.h>
struct node;
typedef struct node node_t;
enum color { RED, GREEN = 5, BLUE };
enum big { TOP = 0x80000000u, LOW = 1 };
struct node {
  node_t *next;
  union { uint32_t u; float f; };
  unsigned flag : 1, kind : 3;
  bool live;
  int64_t wide;
  enum color c;
  char name[16];
};
struct flex { uint16_t len; uint8_t data[]; };
)";

// The C89 dialect (cparse::Dialect::C89): what an old compiler accepts,
// laid out as the types are (the parser checks each layout).
TEST(TypeArchive, C89Dialect) {
  auto p = Parse(kC89Header, "arm-none-eabi");
  ASSERT_EQ(p->r.errors, 0u);
  std::vector<TypeId> roots;
  for (const auto &n : p->r.named)
    if (!n.where.system) roots.push_back(n.id);
  cparse::ArchiveOptions o;
  o.name = "t";
  o.profile = *cparse::profile_named("arm-none-eabi");
  o.dialect = cparse::Dialect::C89;
  cparse::Archive a = cparse::write_archive(p->store, roots, o);
  const std::string &h = a.header;
  EXPECT_EQ(h.find("_Static_assert"), std::string::npos) << h;
  EXPECT_EQ(h.find("_Bool"), std::string::npos) << h;
  EXPECT_NE(h.find("typedef unsigned char bool;"), std::string::npos) << h;
  EXPECT_NE(h.find("typedef char rk_size_t_1[sizeof("), std::string::npos) << h;
  EXPECT_NE(h.find("TOP = (-2147483647 - 1)"), std::string::npos) << h;
  EXPECT_NE(h.find("__extension__ typedef "), std::string::npos) << h;  // int64_t's long long
  EXPECT_NE(h.find(" field_1;"), std::string::npos) << h;  // the anonymous union, named
  EXPECT_EQ(h.find("data[]"), std::string::npos) << h;     // no flexible array members
  // Every layout is the type's (the names and the left-out member aside).
  for (const auto &e : a.entries)
    if (e.key != "struct node" && e.key != "typedef node_t" && e.key != "struct flex" && e.key != "enum big")
      EXPECT_EQ(e.hash, e.source_hash) << e.key;
  for (const std::string &n : a.notes) EXPECT_EQ(n.find("another layout"), std::string::npos) << n;
  if (std::string(REVKIT_TEST_CLANG).empty()) GTEST_SKIP() << "no clang";
  EXPECT_EQ(CompileC89(h + "int revkit_check;\n", "c89"), "") << h;
  // The default dialect isn't C89.
  o.dialect = cparse::Dialect::C11;
  EXPECT_NE(CompileC89(cparse::write_archive(p->store, roots, o).header + "int revkit_check;\n", "c11"), "");
}

// The decompiler's view (ArchiveOptions::decompiler_view): an inferred
// structure's gaps are byte members named as the decompiler's C names
// them, fields it drops (an overlap) are left out, unnamed fields are
// field_<ordinal>, the layout stays natural (no packing, so loads aren't
// split into bytes), and nothing is defined that the includer provides.
TEST(TypeArchive, DecompilerView) {
  types::TypeStore s;
  const TypeId i = s.int_type(4, true, types::IntRank::Int);
  const TypeId sh = s.int_type(2, false, types::IntRank::Short);
  const TypeId u4 = s.undefined(4);
  types::AggregateType a;
  a.name = "astruct_1";
  a.size = 0x20;
  a.fields = {{"field_0x0", i, 0, 0},       {"field_0x8", u4, 8 * 8, 0}, {"", sh, 0xc * 8, 0},
              {"field_0xd", sh, 0xd * 8, 0}, {"field_0x18", i, 0x18 * 8, 0}};
  const TypeId st = s.intern(types::Type(a));
  std::vector<TypeId> roots{st};
  for (cparse::Dialect d : {cparse::Dialect::C11, cparse::Dialect::C89}) {
    cparse::ArchiveOptions o;
    o.name = "view";
    o.profile = *cparse::profile_named("arm-none-eabi");
    o.dialect = d;
    o.decompiler_view = true;
    o.provided = {"undefined4"};
    cparse::Archive ar = cparse::write_archive(s, roots, o);
    const std::string &h = ar.header;
    EXPECT_EQ(ar.mismatches, 0u) << h;
    for (const std::string &n : ar.notes) ADD_FAILURE() << n;
    EXPECT_EQ(h.find("typedef unsigned char undefined4"), std::string::npos) << h;  // provided
    EXPECT_EQ(h.find("#pragma pack"), std::string::npos) << h;                      // natural
    for (const char *gap : {"field_0x4;", "field_0x7;", "field_0xe;", "field_0x17;", "field_0x1c;", "field_0x1f;"})
      EXPECT_NE(h.find(std::string("unsigned char ") + gap), std::string::npos) << gap << "\n" << h;
    EXPECT_NE(h.find("short field_2;"), std::string::npos) << h;  // unnamed: by ordinal
    EXPECT_EQ(h.find("field_0xd;"), std::string::npos) << h;      // overlaps field_2: dropped
    if (std::string(REVKIT_TEST_CLANG).empty()) continue;
    const std::string use = "#include <stddef.h>\ntypedef unsigned int undefined4;\n" + h +
                            "typedef struct astruct_1 astruct_1;\n"
                            "int f(astruct_1 *p) { return *(int *)&p->field_0x4 + p->field_0x13 + p->field_0x18; }\n"
                            "typedef char at_0x18[offsetof(astruct_1, field_0x18) == 0x18 ? 1 : -1];\n";
    if (d == cparse::Dialect::C89) EXPECT_EQ(CompileC89(use, "view"), "") << use;
  }
}

}  // namespace
