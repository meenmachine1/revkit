#include "revkit/types/print.h"

#include <gtest/gtest.h>

namespace revkit::types {
namespace {

class PrintTest : public ::testing::Test {
 protected:
  TypeStore s;
  TypeId v = s.void_type();
  TypeId c = s.int_type(1, true, IntRank::PlainChar);
  TypeId uc = s.int_type(1, false, IntRank::Char);
  TypeId i = s.int_type(4, true, IntRank::Int);
  TypeId u = s.int_type(4, false, IntRank::Int);
  TypeId ul = s.int_type(8, false, IntRank::Long);
  TypeId ll = s.int_type(8, true, IntRank::LongLong);
  TypeId ld = s.float_type(16, FloatKind::LongDouble);
  TypeId size_t_ = s.typedef_of("size_t", ul);
  const PrintOptions ghidra{Style::Ghidra, false};

  TypeId fn(TypeId ret, std::vector<Param> params, bool varargs = false) {
    return s.function(FunctionType{ret, std::move(params), varargs, CallConv::Default});
  }
};

TEST_F(PrintTest, Basic) {
  EXPECT_EQ(type_name(s, i), "int");
  EXPECT_EQ(type_name(s, u), "unsigned int");
  EXPECT_EQ(type_name(s, ul), "unsigned long");
  EXPECT_EQ(type_name(s, ll), "long long");
  EXPECT_EQ(type_name(s, uc), "unsigned char");
  EXPECT_EQ(type_name(s, ld), "long double");
  EXPECT_EQ(type_name(s, s.int_type(4, false)), "uint32_t");
  EXPECT_EQ(type_name(s, s.undefined(8)), "undefined8");
  EXPECT_EQ(type_name(s, s.bool_type()), "bool");
}

TEST_F(PrintTest, Declarators) {
  TypeId cpp = s.pointer_to(s.pointer_to(c));
  EXPECT_EQ(declaration(s, cpp, "argv"), "char **argv");
  EXPECT_EQ(type_name(s, cpp), "char **");
  TypeId ccp = s.pointer_to(s.qualified(c, kConst));
  EXPECT_EQ(declaration(s, ccp, "s"), "const char *s");
  EXPECT_EQ(declaration(s, s.qualified(s.pointer_to(c), kConst), "p"), "char *const p");
  EXPECT_EQ(type_name(s, s.qualified(s.pointer_to(c), kConst | kVolatile)), "char *const volatile");
  EXPECT_EQ(declaration(s, s.array_of(i, 4), "a"), "int a[4]");
  EXPECT_EQ(declaration(s, s.array_of(s.array_of(i, 3), 2), "m"), "int m[2][3]");
  EXPECT_EQ(declaration(s, s.pointer_to(s.array_of(i, 8)), "row"), "int (*row)[8]");
  EXPECT_EQ(declaration(s, s.array_of(s.pointer_to(c), 0), "names"), "char *names[]");
  TypeId binop = fn(i, {{"", i}, {"", i}});
  EXPECT_EQ(declaration(s, s.pointer_to(binop), "f"), "int (*f)(int, int)");
  EXPECT_EQ(type_name(s, s.pointer_to(binop)), "int (*)(int, int)");
  EXPECT_EQ(declaration(s, s.pointer_to(fn(v, {})), "cb"), "void (*cb)(void)");
  EXPECT_EQ(declaration(s, s.pointer_to(i, 8, PointerKind::LValueRef), "r"), "int &r");
}

TEST_F(PrintTest, Prototypes) {
  TypeId main_t = fn(i, {{"argc", i}, {"argv", s.pointer_to(s.pointer_to(c))}});
  EXPECT_EQ(prototype(s, main_t, "main"), "int main(int argc, char **argv)");
  EXPECT_EQ(prototype(s, main_t, "main", ghidra), "int main(int argc, char * * argv)");
  TypeId pf = fn(ul, {{"fmt", s.pointer_to(s.qualified(c, kConst))}}, true);
  EXPECT_EQ(prototype(s, pf, "f"), "unsigned long f(const char *fmt, ...)");
  EXPECT_EQ(prototype(s, pf, "f", ghidra), "ulong f(char * fmt, ...)");
  EXPECT_EQ(prototype(s, fn(v, {}), "g"), "void g(void)");
  EXPECT_EQ(prototype(s, fn(v, {}), "g", ghidra), "void g(void)");
  EXPECT_EQ(prototype(s, fn(i, {}, true), "h"), "int h(...)");
  EXPECT_EQ(prototype(s, fn(i, {{"", i}, {"", u}}), "k"), "int k(int param_1, unsigned int param_2)");
  // A function returning a function pointer.
  TypeId binop = s.pointer_to(fn(i, {{"", i}, {"", i}}));
  EXPECT_EQ(prototype(s, fn(binop, {{"which", i}}), "pick"), "int (*pick(int which))(int, int)");
  EXPECT_EQ(prototype(s, fn(binop, {{"which", i}}), "pick", ghidra),
            "_func_int_int_int * pick(int which)");
}

TEST_F(PrintTest, GhidraStyle) {
  TypeId node = s.intern(AggregateType{AggregateKind::Struct, "node", 8, 0, false, false, {}});
  EXPECT_EQ(type_name(s, s.pointer_to(node)), "struct node *");
  EXPECT_EQ(type_name(s, s.pointer_to(node), ghidra), "node *");
  EXPECT_EQ(type_name(s, s.pointer_to(s.array_of(i, 8)), ghidra), "int[8] *");
  EXPECT_EQ(type_name(s, s.array_of(s.array_of(i, 3), 2), ghidra), "int[2][3]");
  TypeId cb = fn(v, {{"", s.pointer_to(i)}, {"", s.pointer_to(v)}});
  EXPECT_EQ(type_name(s, s.pointer_to(cb), ghidra), "_func_void_int_ptr_void_ptr *");
  TypeId dd = fn(s.float_type(8, FloatKind::Double), {{"", s.float_type(8, FloatKind::Double)}});
  EXPECT_EQ(type_name(s, s.pointer_to(dd), ghidra), "_func_double_double *");
  EXPECT_EQ(type_name(s, s.pointer_to(fn(i, {{"", i}}, true)), ghidra), "_func_int_int_varargs *");
  EXPECT_EQ(type_name(s, ld, ghidra), "longdouble");
  EXPECT_EQ(type_name(s, uc, ghidra), "uchar");
  EXPECT_EQ(type_name(s, ll, ghidra), "longlong");
  EXPECT_EQ(type_name(s, size_t_, ghidra), "size_t");
  PrintOptions resolved = ghidra;
  resolved.resolve_typedefs = true;
  EXPECT_EQ(type_name(s, size_t_, resolved), "ulong");
}

TEST_F(PrintTest, Definitions) {
  TypeGraph g;
  TypeId n = g.reserve();
  TypeId p = g.add(PointerType{n, 8});
  g.set(n, AggregateType{AggregateKind::Struct, "node", 16, 0, false, true,
                         {{"next", p, 0, 0}, {"flags", u, 64, 3}, {"kind", u, 67, 5}}});
  TypeId node = s.intern(g)[0];
  EXPECT_EQ(definition(s, node),
            "struct node {\n"
            "    struct node *next; /* 0x0 */\n"
            "    unsigned int flags : 3; /* 0x8:0 */\n"
            "    unsigned int kind : 5; /* 0x8:3 */\n"
            "}; /* size 0x10 */\n");
  TypeId e = s.intern(EnumType{"color", 4, false, true, {{"RED", 0}, {"GREEN", 1}}});
  EXPECT_EQ(definition(s, e), "enum color {\n    RED = 0,\n    GREEN = 1\n};\n");
  EXPECT_EQ(definition(s, s.typedef_of("binop", s.pointer_to(fn(i, {{"", i}, {"", i}})))),
            "typedef int (*binop)(int, int);\n");
  TypeId inner = s.intern(AggregateType{AggregateKind::Union, "", 4, 0, false, true,
                                        {{"i", i, 0, 0}, {"u", u, 0, 0}}});
  TypeId outer = s.intern(AggregateType{AggregateKind::Struct, "outer", 5, 0, true, true,
                                        {{"tag", c, 0, 0}, {"", inner, 8, 0}}});
  EXPECT_EQ(definition(s, outer),
            "struct outer {\n"
            "    char tag; /* 0x0 */\n"
            "    union {\n"
            "        int i; /* 0x0 */\n"
            "        unsigned int u; /* 0x0 */\n"
            "    }; /* 0x1 */\n"
            "} __attribute__((packed)); /* size 0x5 */\n");
}

TEST_F(PrintTest, DeepNestingIsBounded) {
  TypeId t = i;
  for (int k = 0; k < 200; ++k) t = s.pointer_to(fn(t, {{"", t}}));
  EXPECT_FALSE(type_name(s, t).empty());
  EXPECT_FALSE(type_name(s, t, ghidra).empty());
}

}  // namespace
}  // namespace revkit::types
