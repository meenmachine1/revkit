// revkit::cparse: preprocessor, declarations, layout, recovery and limits.

#include "revkit/cparse/cparse.h"

#include "revkit/types/describe.h"
#include "revkit/types/print.h"
#include "revkit/types/transform.h"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <random>
#include <set>

namespace {

using namespace revkit;
using types::TypeId;
namespace fs = std::filesystem;

struct Parsed {
  types::TypeStore store;
  cparse::Result r;

  const cparse::NamedType *named(std::string_view key) const {
    for (const auto &n : r.named)
      if (n.key == key) return &n;
    return nullptr;
  }
  TypeId id(std::string_view key) const {
    const auto *n = named(key);
    EXPECT_NE(n, nullptr) << "no " << key;
    return n ? n->id : TypeId();
  }
  std::uint64_t size(std::string_view key) const {
    TypeId i = id(key);
    return i.valid() ? store.size_of(i) : 0;
  }
  const types::AggregateType &agg(std::string_view key) const {
    static types::AggregateType empty;
    TypeId i = id(key);
    if (!i.valid()) return empty;
    const auto *a = store.get(store.strip_typedefs(i)).as<types::AggregateType>();
    EXPECT_NE(a, nullptr);
    return a ? *a : empty;
  }
  // "name@bit:width" for every field.
  std::string fields(std::string_view key) const {
    std::string out;
    for (const auto &f : agg(key).fields) {
      if (!out.empty()) out += " ";
      out += f.name + "@" + std::to_string(f.bit_offset);
      if (f.bit_size) out += ":" + std::to_string(f.bit_size);
    }
    return out;
  }
  const cparse::Prototype *proto(std::string_view name) const {
    for (const auto &p : r.prototypes)
      if (p.name == name) return &p;
    return nullptr;
  }
  std::string diags() const {
    std::string out;
    for (const auto &d : r.diagnostics)
      out += d.file + ":" + std::to_string(d.line) + ":" + std::to_string(d.col) + ": " + d.text + "\n";
    return out;
  }
  bool has_diag(std::string_view text) const {
    for (const auto &d : r.diagnostics)
      if (d.text.find(text) != std::string::npos) return true;
    return false;
  }
};

cparse::Options options(std::string_view target = "x86_64-linux-gnu") {
  cparse::Options o;
  o.profile = *cparse::profile_named(target);
  return o;
}

std::unique_ptr<Parsed> parse_with(std::string text, cparse::Options o, std::string name = "test.h") {
  auto p = std::make_unique<Parsed>();
  cparse::Source s{std::move(name), std::move(text), false};
  p->r = cparse::parse(p->store, std::span(&s, 1), o);
  return p;
}

std::unique_ptr<Parsed> parse(std::string text, std::string_view target = "x86_64-linux-gnu") {
  return parse_with(std::move(text), options(target));
}

// A temporary directory removed at the end of the test.
struct TempDir {
  fs::path path;
  TempDir() {
    std::mt19937_64 rng(std::random_device{}());
    path = fs::temp_directory_path() / ("revkit-cparse-" + std::to_string(rng()));
    fs::create_directories(path);
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path, ec);
  }
  void write(const std::string &rel, const std::string &text) const {
    fs::create_directories((path / rel).parent_path());
    std::ofstream(path / rel) << text;
  }
};

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

TEST(CParseLayout, ScalarsAndNesting) {
  auto p = parse(R"(
struct point { int x, y; };
struct rect { struct point min, max; unsigned char color; double area; };
struct s_ld { char c; long double ld; };
struct s_arr { char name[13]; int vals[3][4]; short tail; };
)");
  EXPECT_EQ(p->r.errors, 0u) << p->diags();
  EXPECT_EQ(p->size("struct rect"), 32u);
  EXPECT_EQ(p->fields("struct rect"), "min@0 max@64 color@128 area@192");
  EXPECT_EQ(p->size("struct s_ld"), 32u);
  EXPECT_EQ(p->fields("struct s_arr"), "name@0 vals@128 tail@512");
  // i386: long double is 12 bytes, 4-aligned; double 4-aligned in structs.
  auto q = parse("struct s_ld { char c; long double ld; }; struct d { char c; double d; };", "i386-linux-gnu");
  EXPECT_EQ(q->size("struct s_ld"), 16u);
  EXPECT_EQ(q->size("struct d"), 12u);
  // LLP64 and Microsoft's 8-byte long double.
  auto w = parse("struct s { long l; long double ld; void *p; };", "x86_64-pc-windows-msvc");
  EXPECT_EQ(w->fields("struct s"), "l@0 ld@64 p@128");
}

TEST(CParseLayout, BitfieldsGccAndMsvc) {
  const std::string src = R"(
struct flags { unsigned visible : 1, layer : 4, kind : 3; int delta : 6; };
struct mixed { char a : 4; short b : 12; int c : 20; long long d : 40; };
struct straddle { char c; int x : 4; int y : 28; char d; };
struct zero { char a; int : 0; char b; };
struct unnamed { int a : 3; unsigned : 5; int b : 7; };
)";
  auto g = parse(src);
  EXPECT_EQ(g->r.errors, 0u) << g->diags();
  EXPECT_EQ(g->fields("struct flags"), "visible@0:1 layer@1:4 kind@5:3 delta@8:6");
  EXPECT_EQ(g->size("struct flags"), 4u);
  EXPECT_EQ(g->fields("struct mixed"), "a@0:4 b@4:12 c@32:20 d@64:40");  // c would straddle an int
  EXPECT_EQ(g->size("struct mixed"), 16u);
  EXPECT_EQ(g->fields("struct straddle"), "c@0 x@8:4 y@32:28 d@64");
  EXPECT_EQ(g->size("struct zero"), 5u);
  EXPECT_EQ(g->fields("struct unnamed"), "a@0:3 b@8:7");  // unnamed bitfields are padding
  auto m = parse(src, "x86_64-pc-windows-msvc");
  EXPECT_EQ(m->fields("struct mixed"), "a@0:4 b@16:12 c@32:20 d@64:40");
  EXPECT_EQ(m->size("struct mixed"), 16u);
  EXPECT_EQ(m->fields("struct straddle"), "c@0 x@32:4 y@36:28 d@64");
  EXPECT_EQ(m->size("struct straddle"), 12u);
  // AAPCS: a zero-width bitfield aligns the struct.
  EXPECT_EQ(parse(src, "aarch64-linux-gnu")->size("struct zero"), 8u);
}

TEST(CParseLayout, PackingAndAlignment) {
  auto p = parse(R"(
struct packed { char c; int i; short s; } __attribute__((packed));
struct packed_member { char c; int i __attribute__((packed)); char d; };
struct aligned_member { char c; int i __attribute__((aligned(16))); };
struct aligned { char c; } __attribute__((aligned(8)));
#pragma pack(push, 2)
struct pack2 { char c; int i; double d; };
#pragma pack(pop)
struct natural { char c; int i; };
#pragma pack(1)
struct pack1 { char c; long long l; };
#pragma pack()
struct flex { int n; char data[]; };
)");
  EXPECT_EQ(p->r.errors, 0u) << p->diags();
  EXPECT_EQ(p->size("struct packed"), 7u);
  EXPECT_TRUE(p->agg("struct packed").packed);  // inferred, as from DWARF
  EXPECT_EQ(p->fields("struct packed_member"), "c@0 i@8 d@40");
  EXPECT_EQ(p->size("struct aligned_member"), 32u);
  EXPECT_EQ(p->size("struct aligned"), 8u);
  EXPECT_EQ(p->agg("struct aligned").alignment, 8u);
  EXPECT_EQ(p->fields("struct pack2"), "c@0 i@16 d@48");
  EXPECT_EQ(p->size("struct natural"), 8u);
  EXPECT_EQ(p->size("struct pack1"), 9u);
  EXPECT_EQ(p->size("struct flex"), 4u);
  const auto &flex = p->agg("struct flex");
  ASSERT_EQ(flex.fields.size(), 2u);
  EXPECT_EQ(p->store.get(flex.fields[1].type).as<types::ArrayType>()->count, 0u);
}

TEST(CParseLayout, AnonymousMembersAndUnions) {
  auto p = parse(R"(
struct s { int a; union { int b; float c; }; struct { char d; short e; }; int f; };
union u { char c[5]; int i; double d; };
typedef struct { int x; char y; } point;
)");
  EXPECT_EQ(p->r.errors, 0u) << p->diags();
  EXPECT_EQ(p->fields("struct s"), "a@0 @32 @64 f@96");
  EXPECT_EQ(p->size("union u"), 8u);
  EXPECT_EQ(p->fields("union u"), "c@0 i@0 d@0");
  EXPECT_EQ(p->size("typedef point"), 8u);
  EXPECT_EQ(p->named("struct point"), nullptr);  // the struct is anonymous
}

TEST(CParseLayout, EnumsGccAndMsvc) {
  const std::string src = R"(
enum pos { A, B, C };
enum neg { N = -1, P = 1 };
enum wide { W = 0x100000000LL };
enum __attribute__((packed)) small { S1, S2 };
struct uses { enum pos p; enum small s; };
)";
  auto e = [](Parsed &p, std::string_view key) {
    TypeId i = p.id(key);
    return i.valid() ? *p.store.get(i).as<types::EnumType>() : types::EnumType{};
  };
  auto g = parse(src);
  EXPECT_EQ(e(*g, "enum pos").size, 4u);
  EXPECT_FALSE(e(*g, "enum pos").is_signed);  // unsigned int, as GCC
  EXPECT_TRUE(e(*g, "enum neg").is_signed);
  EXPECT_EQ(e(*g, "enum wide").size, 8u);
  EXPECT_EQ(e(*g, "enum small").size, 1u);
  EXPECT_EQ(g->size("struct uses"), 8u);
  auto m = parse(src, "x86_64-pc-windows-msvc");
  EXPECT_TRUE(e(*m, "enum pos").is_signed);  // int, as MSVC
  EXPECT_EQ(e(*m, "enum pos").size, 4u);
}

TEST(CParseLayout, PlainCharFollowsTheTarget) {
  auto x = parse("struct s { char c; };");
  auto a = parse("struct s { char c; };", "aarch64-linux-gnu");
  // Different hashes: char is signed on x86-64, unsigned on AArch64.
  EXPECT_NE(x->store.hash(x->id("struct s")), a->store.hash(a->id("struct s")));
  const auto *c = a->store.get(a->agg("struct s").fields[0].type).as<types::IntType>();
  ASSERT_NE(c, nullptr);
  EXPECT_FALSE(c->is_signed);
  EXPECT_EQ(c->rank, types::IntRank::PlainChar);
}

TEST(CParseLayout, HashesAreTheDebugInfosForTheSameType) {
  // The same struct built by hand as the DWARF importer builds it.
  auto p = parse("struct node { struct node *next; int value; };");
  types::TypeStore &s = p->store;
  types::TypeGraph g;
  TypeId n = g.reserve();
  TypeId ptr = g.add(types::PointerType{n, 8, types::PointerKind::Pointer});
  types::AggregateType a;
  a.name = "node";
  a.size = 16;
  a.fields = {{"next", ptr, 0, 0}, {"value", s.int_type(4, true, types::IntRank::Int), 64, 0}};
  g.set(n, a);
  EXPECT_EQ(s.intern(g)[n.index()], p->id("struct node"));
}

// ---------------------------------------------------------------------------
// Declarations
// ---------------------------------------------------------------------------

TEST(CParseDecl, PrototypesAndFunctionPointers) {
  auto p = parse(R"(
typedef int (*binop)(int a, int b);
struct ops { long (*area)(const struct shape *s); void (*table[3])(void); };
int add(int a, int b);
char *strdup2(const char *s, ...);
int old();
static int defined_here(int x) { return x * 2; }
void (*signal2(int sig, void (*func)(int)))(int);
)");
  EXPECT_EQ(p->r.errors, 0u) << p->diags();
  ASSERT_NE(p->proto("add"), nullptr);
  EXPECT_EQ(types::prototype(p->store, p->proto("add")->type, "add"), "int add(int a, int b)");
  ASSERT_NE(p->proto("strdup2"), nullptr);
  EXPECT_EQ(types::prototype(p->store, p->proto("strdup2")->type, "strdup2"), "char *strdup2(const char *s, ...)");
  // C's () is unprototyped: varargs, as DWARF records it.
  ASSERT_NE(p->proto("old"), nullptr);
  EXPECT_TRUE(p->store.get(p->proto("old")->type).as<types::FunctionType>()->varargs);
  ASSERT_NE(p->proto("defined_here"), nullptr);
  EXPECT_TRUE(p->proto("defined_here")->defined);
  ASSERT_NE(p->proto("signal2"), nullptr);
  EXPECT_EQ(types::prototype(p->store, p->proto("signal2")->type, "signal2"),
            "void (*signal2(int sig, void (*func)(int)))(int)");
  // Function types inside others have no parameter names (as in DWARF).
  EXPECT_EQ(types::definition(p->store, p->id("typedef binop")), "typedef int (*binop)(int, int);\n");
  EXPECT_EQ(p->fields("struct ops"), "area@0 table@64");
}

// Calling conventions as keywords and GNU attributes, as the compiler
// records them: on i386 what the declaration says (__cdecl is the
// default), elsewhere the target's own convention is the default.
TEST(CParseDecl, CallingConventions) {
  const char *src = R"(
int __stdcall s1(int a);
int _stdcall s2(int a);
int __attribute__((stdcall)) s3(int a);
__attribute__((__fastcall__)) int f1(int a, int b);
int __fastcall f2(int a, int b);
int __thiscall t1(void *self, int a);
int __vectorcall v1(int a);
int __cdecl c1(int a);
int __attribute__((cdecl)) c2(int a);
int plain(int a);
typedef int (__stdcall *proc_t)(int);
)";
  auto cc = [](const Parsed &p, std::string_view name) {
    const cparse::Prototype *proto = p.proto(name);
    EXPECT_NE(proto, nullptr) << name;
    return proto ? p.store.get(proto->type).as<types::FunctionType>()->cc : types::CallConv::Other;
  };
  using types::CallConv;
  for (const char *target : {"i686-w64-mingw32", "i386-pc-windows-msvc", "i386-linux-gnu"}) {
    auto p = parse(src, target);
    EXPECT_EQ(p->r.errors, 0u) << target << ": " << p->diags();
    for (const char *n : {"s1", "s2", "s3"}) EXPECT_EQ(cc(*p, n), CallConv::Stdcall) << target << " " << n;
    for (const char *n : {"f1", "f2"}) EXPECT_EQ(cc(*p, n), CallConv::Fastcall) << target << " " << n;
    EXPECT_EQ(cc(*p, "t1"), CallConv::Thiscall) << target;
    EXPECT_EQ(cc(*p, "v1"), CallConv::Vectorcall) << target;
    for (const char *n : {"c1", "c2", "plain"}) EXPECT_EQ(cc(*p, n), CallConv::Default) << target << " " << n;
    const types::Type &ptr = p->store.get(p->store.get(p->id("typedef proc_t")).as<types::TypedefType>()->target);
    EXPECT_EQ(p->store.get(ptr.as<types::PointerType>()->target).as<types::FunctionType>()->cc, CallConv::Stdcall) << target;
  }
  // x86-64: one convention (vectorcall aside).
  auto p = parse(src, "x86_64-pc-windows-msvc");
  EXPECT_EQ(p->r.errors, 0u) << p->diags();
  for (const char *n : {"s1", "f1", "t1", "c1", "plain"}) EXPECT_EQ(cc(*p, n), CallConv::Default) << n;
  EXPECT_EQ(cc(*p, "v1"), CallConv::Vectorcall);
}

TEST(CParseDecl, QualifiersAttributesAndBuiltins) {
  auto p = parse(R"(
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>
struct q { const char *const *argv; volatile int *vi; char *restrict r; _Atomic(long) a; };
struct b { bool flag; uint8_t u8; int64_t i64; size_t sz; wchar_t wc; va_list ap; };
typedef int i8 __attribute__((__mode__(__QI__)));
typedef float v4 __attribute__((vector_size(16)));
struct m { i8 x; v4 v; __int128 big; _Complex double cd; };
)");
  EXPECT_EQ(p->r.errors, 0u) << p->diags();
  EXPECT_EQ(p->size("struct b"), 56u);
  EXPECT_EQ(p->size("typedef i8"), 1u);
  EXPECT_EQ(p->size("typedef v4"), 16u);
  EXPECT_EQ(p->fields("struct m"), "x@0 v@128 big@256 cd@384");
}

TEST(CParseDecl, StaticAssertAndConstantExpressions) {
  auto p = parse(R"(
#include <stddef.h>
struct s { char c; int i; long arr[sizeof(int) * 2]; };
_Static_assert(sizeof(struct s) == 72, "size");
_Static_assert(offsetof(struct s, arr[1]) == 16, "offsetof");
_Static_assert(_Alignof(struct s) == 8, "align");
_Static_assert((unsigned char)-1 == 255 && (1 << 31) < 0 && (-1 >> 1) == -1, "arithmetic");
_Static_assert(sizeof(((struct s *)0)->arr) == 64, "member through a cast");
enum { K = 3, L = K * 4 + (K > 2 ? 1 : 0) };
char buf[L];
_Static_assert(sizeof buf == 13, "enum constants");
_Static_assert(1 == 2, "this one fails");
)");
  EXPECT_EQ(p->r.errors, 1u) << p->diags();
  EXPECT_TRUE(p->has_diag("static assertion failed: this one fails"));
}

TEST(CParseDecl, UnknownTypesBecomeUndefinedWithADiagnostic) {
  auto p = parse("struct s { mystery_t a; int b; };\nunknown_t *f(unknown_t x);\n");
  EXPECT_EQ(p->size("struct s"), 8u);
  EXPECT_EQ(p->fields("struct s"), "a@0 b@32");
  const auto &f = p->agg("struct s").fields.at(0);
  EXPECT_EQ(p->store.get(f.type).kind(), types::Kind::Undefined);
  ASSERT_GE(p->r.diagnostics.size(), 1u);
  EXPECT_EQ(p->r.diagnostics[0].line, 1u);
  EXPECT_EQ(p->r.diagnostics[0].col, 12u);
  EXPECT_NE(p->r.diagnostics[0].text.find("mystery_t"), std::string::npos);
  EXPECT_NE(p->proto("f"), nullptr);
}

TEST(CParseDecl, LookupUsesTheProgramsTypes) {
  types::TypeStore store;
  types::AggregateType a;
  a.name = "cJSON";
  a.size = 8;
  a.fields = {{"type", store.int_type(4, true, types::IntRank::Int), 0, 0}};
  TypeId cjson = store.intern(a);
  TypeId td = store.typedef_of("cJSON", cjson);
  cparse::Options o = options();
  o.lookup = [&](std::string_view key) -> std::optional<TypeId> {
    if (key == "typedef cJSON") return td;
    if (key == "struct cJSON") return cjson;
    return std::nullopt;
  };
  cparse::Source s{"t.h", "struct wrap { cJSON *item; struct cJSON inline_one; };\nint f(cJSON *x);\n", false};
  cparse::Result r = cparse::parse(store, std::span(&s, 1), o);
  EXPECT_EQ(r.errors, 0u);
  EXPECT_EQ(r.used_existing.size(), 2u);
  const cparse::NamedType *wrap = nullptr;
  for (const auto &n : r.named)
    if (n.key == "struct wrap") wrap = &n;
  ASSERT_NE(wrap, nullptr);
  EXPECT_EQ(store.size_of(wrap->id), 16u);
  // Only declared here: the program's definition.
  cparse::Source d{"d.h", "struct cJSON;\nstruct holder { struct cJSON *p; };\n", false};
  cparse::Result r2 = cparse::parse(store, std::span(&d, 1), o);
  for (const auto &n : r2.named)
    if (n.key == "struct cJSON") EXPECT_EQ(n.id, cjson);
}

TEST(CParseDecl, Cplusplus) {
  auto p = parse_with(R"(
namespace ns {
struct Base { int b; };
class Thing : public Base {
 public:
  Thing();
  ~Thing();
  int method(int x) const { return x; }
  static int counter;
  enum class Mode : unsigned char { A, B };
  Mode mode;
 private:
  double d;
};
template <typename T> struct Box { T value; };
using Alias = Thing;
}
enum class Big : long long { X };
)", options(), "t.hpp");
  EXPECT_EQ(p->r.errors, 0u) << p->diags();
  EXPECT_EQ(p->fields("class ns::Thing"), "@0 mode@32 d@64");
  EXPECT_EQ(p->size("enum ns::Thing::Mode"), 1u);
  EXPECT_EQ(p->size("enum Big"), 8u);
  EXPECT_NE(p->named("typedef ns::Alias"), nullptr);
  EXPECT_TRUE(p->has_diag("template declaration skipped"));
}

// ---------------------------------------------------------------------------
// Preprocessor
// ---------------------------------------------------------------------------

TEST(CParsePreprocessor, MacrosAndConditionals) {
  auto p = parse(R"(
#define CAT(a, b) a ## b
#define STR(x) #x
#define COUNT(...) (sizeof((int[]){__VA_ARGS__}) / sizeof(int))
#define FIELDS(T, ...) T first; __VA_OPT__(T rest[3];)
#define LOG(fmt, ...) printf(fmt, ## __VA_ARGS__)
#define SELF SELF + 1
#if defined(__x86_64__) && __SIZEOF_POINTER__ == 8 && !defined(_WIN32)
struct CAT(my, struct) { FIELDS(int, 1, 2, 3) };
struct CAT(no, rest) { FIELDS(char) };
#elif 1
#error not this branch
#else
#endif
#ifdef __has_include
#if __has_include(<stddef.h>) && !__has_include("nope.h")
struct has_include_works { int x; };
#endif
#endif
#define ONE 1
#if ONE + 0x10 == 17 && (ONE ? 2 : 3) == 2 && 'a' == 97
struct arithmetic_works { int x; };
#endif
enum { s = sizeof STR(hello) };
_Static_assert(s == 6, "stringize");
)");
  EXPECT_EQ(p->r.errors, 0u) << p->diags();
  EXPECT_EQ(p->fields("struct mystruct"), "first@0 rest@32");
  EXPECT_EQ(p->size("struct mystruct"), 16u);
  EXPECT_EQ(p->fields("struct norest"), "first@0");
  EXPECT_NE(p->named("struct has_include_works"), nullptr);
  EXPECT_NE(p->named("struct arithmetic_works"), nullptr);
}

TEST(CParsePreprocessor, IncludesGuardsAndOnce) {
  TempDir d;
  d.write("inc/a.h", "#ifndef A_H\n#define A_H\nstruct a { int x; };\n#include \"b.h\"\n#endif\n");
  d.write("inc/b.h", "#pragma once\nstruct b { struct a a; };\n#include \"a.h\"\n");
  d.write("sys/lib.h", "struct from_sys { int y; };\n");
  d.write("sys2/limits.h", "#define FROM_NEXT 1\n");
  d.write("main.h", "#include <a.h>\n#include \"inc/b.h\"\n#include <lib.h>\n#include <limits.h>\n"
                    "#ifndef FROM_NEXT\n#error include_next missed\n#endif\nenum { m = INT_MAX };\n");
  auto fsys = cparse::host_file_system();
  cparse::Options o = options();
  o.fs = fsys.get();
  o.include_dirs = {(d.path / "inc").string()};
  o.system_include_dirs = {(d.path / "sys").string(), (d.path / "sys2").string()};
  cparse::Source s{(d.path / "main.h").string(), {}, true};
  types::TypeStore store;
  cparse::Result r = cparse::parse(store, std::span(&s, 1), o);
  std::string diags;
  for (const auto &x : r.diagnostics) diags += x.file + ":" + std::to_string(x.line) + ": " + x.text + "\n";
  EXPECT_EQ(r.errors, 0u) << diags;
  bool sys = false, a = false;
  for (const auto &n : r.named) {
    if (n.key == "struct from_sys") sys = n.where.system;
    if (n.key == "struct a") a = !n.where.system;
  }
  EXPECT_TRUE(sys);
  EXPECT_TRUE(a);
}

TEST(CParsePreprocessor, PreprocessedOutputPassesThrough) {
  // As clang -E -dD writes it: line markers, the #defines, expanded text.
  auto p = parse(R"(# 1 "lib.h"
# 1 "<built-in>" 1
#define __GNUC__ 4
# 1 "lib.h" 2
#define LIB_VERSION 3
#define name renamed_by_macro
struct lib { int name; long version; };
# 1 "/usr/include/sys.h" 1 3
struct sys_thing { int z; };
# 5 "lib.h" 2
#pragma pack(push, 1)
struct packed { char c; int i; };
#pragma pack(pop)
int broken(
)");
  EXPECT_EQ(p->fields("struct lib"), "name@0 version@64");  // not expanded again
  bool found = false;
  for (const auto &c : p->r.constants)
    if (c.name == "LIB_VERSION") found = c.value == 3;
  EXPECT_TRUE(found);
  ASSERT_NE(p->named("struct sys_thing"), nullptr);
  EXPECT_TRUE(p->named("struct sys_thing")->where.system);
  EXPECT_EQ(p->size("struct packed"), 5u);
  ASSERT_FALSE(p->r.diagnostics.empty());
  EXPECT_EQ(p->r.diagnostics.back().file, "lib.h");
  EXPECT_EQ(p->r.diagnostics.back().line, 8u) << p->diags();
}

TEST(CParsePreprocessor, ConstantsAndEnums) {
  cparse::Options o = options();
  o.defines_as_enums = true;
  o.defines = {{"FROM_COMMAND_LINE", "7"}};
  auto p = parse_with(R"(
#define VERSION_MAJOR 1
#define FLAG_A (1u << 0)
#define FLAG_B (1u << 31)
#define NEG (-5)
#define SIZE (sizeof(int) * 4)
#define STRING "not a number"
#define FLOATY 1.5
#define FUNC(x) (x)
#define USES_CMD FROM_COMMAND_LINE
)", o, "cJSON.h");
  std::map<std::string, std::int64_t> c;
  for (const auto &k : p->r.constants) c[k.name] = k.value;
  EXPECT_EQ(c.size(), 6u);
  EXPECT_EQ(c["VERSION_MAJOR"], 1);
  EXPECT_EQ(c["FLAG_B"], 0x80000000LL);
  EXPECT_EQ(c["NEG"], -5);
  EXPECT_EQ(c["SIZE"], 16);
  EXPECT_EQ(c["USES_CMD"], 7);
  ASSERT_EQ(p->r.constant_enums.size(), 1u);
  EXPECT_EQ(p->r.constant_enums[0].key, "enum cJSON_h_constants");
}

TEST(CParsePreprocessor, MsvcDialect) {
  auto p = parse(R"(
#if defined(_MSC_VER) && !defined(__GNUC__) && defined(_WIN64)
typedef struct __declspec(align(16)) _M128 { unsigned __int64 lo; __int64 hi; } M128;
struct callbacks { int (__stdcall *proc)(void *); void (__cdecl *free)(void *); };
#pragma pack(push, 8)
struct packed8 { char c; double d; };
#pragma pack(pop)
#endif
)", "x86_64-pc-windows-msvc");
  EXPECT_EQ(p->r.errors, 0u) << p->diags();
  EXPECT_EQ(p->size("struct _M128"), 16u);
  EXPECT_EQ(p->agg("struct _M128").alignment, 16u);
  EXPECT_EQ(p->size("struct callbacks"), 16u);
  EXPECT_EQ(p->size("struct packed8"), 16u);
}

// ---------------------------------------------------------------------------
// Recovery and limits
// ---------------------------------------------------------------------------

TEST(CParseRecovery, KeepsWhatParsed) {
  auto p = parse(R"(struct good1 { int a; };
struct bad { int x; @@@ garbage ; int y; };
int f(int, ;
struct good2 { char c; };
struct unbalanced { int a;
struct good3 { long l; };
)");
  EXPECT_GT(p->r.errors, 0u);
  EXPECT_NE(p->named("struct good1"), nullptr);
  EXPECT_NE(p->named("struct good2"), nullptr);
  EXPECT_EQ(p->fields("struct bad"), "x@0 y@32");
  for (const auto &d : p->r.diagnostics) EXPECT_GT(d.line, 0u) << d.text;
  ASSERT_FALSE(p->r.diagnostics.empty());
  EXPECT_EQ(p->r.diagnostics[0].line, 2u);
}

TEST(CParseRecovery, ParametersThatGrowTheGraph) {
  // Array and function parameters become pointers, which adds types while
  // the parameter's own is looked at (a use after free the fuzzer found).
  std::string src = "struct s;\n";
  for (int i = 0; i < 200; ++i)
    src += "void f" + std::to_string(i) + "(struct s *a[" + std::to_string(i + 1) + "], struct s *g(int, struct s *[" +
           std::to_string(i + 2) + "]));\n";
  auto p = parse(src);
  EXPECT_EQ(p->r.errors, 0u) << p->diags();
  ASSERT_NE(p->proto("f7"), nullptr);
  EXPECT_EQ(types::prototype(p->store, p->proto("f7")->type, "f7"), "void f7(struct s **a, struct s *(*g)(int, struct s **))");
}

TEST(CParseRecovery, TruncatedInput) {
  const std::string full = R"(#include <stdint.h>
typedef struct node { struct node *next; uint32_t v; } node_t;
enum e { A = 1, B = A << 2 };
#define M(x) ((x) + 1)
int f(node_t *n, enum e k);
struct big { char name[M(15)]; union { int i; float f; } u; };
)";
  for (std::size_t n = 0; n <= full.size(); ++n) {
    auto p = parse(full.substr(0, n));
    (void)p;  // never crashes, never hangs
  }
  SUCCEED();
}

TEST(CParseLimits, MacroBombStops) {
  std::string bomb = "#define A0 x x\n";
  for (int i = 1; i < 40; ++i)
    bomb += "#define A" + std::to_string(i) + " A" + std::to_string(i - 1) + " A" + std::to_string(i - 1) + "\n";
  bomb += "int v = A39;\n";
  cparse::Options o = options();
  o.limits.max_expansion_tokens = 200'000;
  const auto t0 = std::chrono::steady_clock::now();
  auto p = parse_with(bomb, o);
  EXPECT_TRUE(p->r.limit_hit);
  EXPECT_LT(std::chrono::steady_clock::now() - t0, std::chrono::seconds(10));
  EXPECT_TRUE(p->has_diag("macro expansion produced more than"));
}

TEST(CParseLimits, RecursiveIncludeAndDeepNesting) {
  TempDir d;
  d.write("self.h", "#include \"self.h\"\nstruct s;\n");
  auto fsys = cparse::host_file_system();
  cparse::Options o = options();
  o.fs = fsys.get();
  cparse::Source s{(d.path / "self.h").string(), {}, true};
  types::TypeStore store;
  cparse::Result r = cparse::parse(store, std::span(&s, 1), o);
  bool depth = false;
  for (const auto &x : r.diagnostics) depth |= x.text.find("nested deeper") != std::string::npos;
  EXPECT_TRUE(depth);

  std::string deep = "int " + std::string(5000, '(') + "x" + std::string(5000, ')') + ";\n";
  EXPECT_TRUE(parse(deep)->r.limit_hit);
  std::string deep_if;
  for (int i = 0; i < 5000; ++i) deep_if += "#if 1\n";
  EXPECT_TRUE(parse(deep_if)->r.limit_hit);
  std::string deep_struct;
  for (int i = 0; i < 5000; ++i) deep_struct += "struct s" + std::to_string(i) + " { ";
  EXPECT_TRUE(parse(deep_struct)->r.limit_hit);
  std::string deep_expr = "int a[" + std::string(5000, '(') + "1" + std::string(5000, ')') + "];";
  EXPECT_TRUE(parse(deep_expr)->r.limit_hit);
}

TEST(CParseLimits, BytesAndTime) {
  cparse::Options o = options();
  o.limits.max_bytes = 1000;
  EXPECT_TRUE(parse_with(std::string(5000, ' ') + "int x;", o)->r.limit_hit);
  cparse::Options t = options();
  t.limits.wall_time = std::chrono::milliseconds(1);
  std::string big;
  for (int i = 0; i < 200000; ++i) big += "struct s" + std::to_string(i) + " { int a; };\n";
  EXPECT_TRUE(parse_with(big, t)->r.limit_hit);
}

TEST(CParseFiles, IncludesStayUnderTheRoots) {
  TempDir d;
  d.write("root/main.h", "#include \"../secret.h\"\n#include \"/etc/hostname\"\n#include \"link.h\"\n#include \"ok.h\"\n");
  d.write("root/ok.h", "struct ok { int x; };\n");
  d.write("secret.h", "struct secret { int x; };\n");
  fs::create_symlink(d.path / "secret.h", d.path / "root" / "link.h");
  auto fsys = cparse::host_file_system({(d.path / "root").string()});
  cparse::Options o = options();
  o.fs = fsys.get();
  cparse::Source s{(d.path / "root" / "main.h").string(), {}, true};
  types::TypeStore store;
  cparse::Result r = cparse::parse(store, std::span(&s, 1), o);
  std::set<std::string> keys;
  for (const auto &n : r.named) keys.insert(n.key);
  EXPECT_TRUE(keys.contains("struct ok"));
  EXPECT_FALSE(keys.contains("struct secret"));
  EXPECT_EQ(r.errors, 3u);
  // A source outside the roots isn't read either.
  cparse::Source out{(d.path / "secret.h").string(), {}, true};
  cparse::Result r2 = cparse::parse(store, std::span(&out, 1), o);
  EXPECT_TRUE(r2.named.empty());
  EXPECT_EQ(r2.errors, 1u);
  // Without a file system nothing is read.
  cparse::Options none = options();
  cparse::Result r3 = cparse::parse(store, std::span(&s, 1), none);
  EXPECT_TRUE(r3.named.empty());
}

// ---------------------------------------------------------------------------
// Linking and profiles
// ---------------------------------------------------------------------------

TEST(CParseLink, DeclarationsResolveToTheOtherUnitsDefinition) {
  types::TypeStore store;
  cparse::Options o = options();
  std::vector<cparse::Source> src = {
      {"a.c", "struct opaque; struct user { struct opaque *o; };\n", false},
      {"b.c", "struct opaque { int secret; }; struct user { struct opaque *o; };\n", false},
  };
  std::vector<cparse::Result> units;
  for (auto &s : src) units.push_back(cparse::parse(store, std::span(&s, 1), o));
  auto user = [&](const cparse::Result &r) {
    for (const auto &n : r.named)
      if (n.key == "struct user") return n.id;
    return TypeId();
  };
  EXPECT_NE(user(units[0]), user(units[1]));
  EXPECT_TRUE(cparse::link(store, units).empty());
  EXPECT_EQ(user(units[0]), user(units[1]));
}

TEST(CParseProfile, FromADataOrganization) {
  // x86-64 gcc's cspec as written.
  cparse::ProfileInputs in;
  in.language_id = "x86:LE:64:default";
  in.compiler_id = "gcc";
  in.format = "elf";
  cparse::DataOrganization o;
  o.pointer_size = 8;
  o.wchar_size = 4;
  o.long_size = 8;
  o.long_double_size = 10;
  o.size_alignment = {{1, 1}, {2, 2}, {4, 4}, {8, 8}, {16, 16}};
  in.data_org = o;
  EXPECT_EQ(cparse::profile_for(in).rules, cparse::profile_named("x86_64-linux-gnu")->rules);
  // AArch64's says 8-byte long double and nothing about char: the ABI wins.
  in.language_id = "AARCH64:LE:64:v8A";
  in.compiler_id = "default";
  o.long_double_size = 8;
  in.data_org = o;
  std::vector<std::string> notes;
  cparse::Profile a = cparse::profile_for(in, &notes);
  EXPECT_EQ(a.rules.long_double_size, 16u);
  EXPECT_FALSE(a.rules.char_signed);
  EXPECT_EQ(notes.size(), 2u);
  // A PE with Microsoft bitfields.
  in.language_id = "x86:LE:64:default";
  in.compiler_id = "windows";
  in.format = "pe";
  o = {};
  o.long_size = 4;
  o.ms_bitfields = true;
  in.data_org = o;
  cparse::Profile w = cparse::profile_for(in);
  EXPECT_EQ(w.rules.long_size, 4u);
  EXPECT_EQ(w.rules.bitfields, cparse::BitfieldModel::Msvc);
  EXPECT_EQ(w.os, cparse::Os::Windows);
}

}  // namespace
