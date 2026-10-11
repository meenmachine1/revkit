#include "revkit/types/transform.h"

#include <gtest/gtest.h>

namespace revkit::types {
namespace {

TEST(WithoutTypedefs, ReplacesTypedefsEverywhere) {
  TypeStore s;
  TypeId u64 = s.int_type(8, false, IntRank::LongLong);
  TypeId size_t_ = s.typedef_of("size_t", u64);
  TypeId binop = s.typedef_of("binop", s.pointer_to(s.function({s.int_type(4, true, IntRank::Int), {}})));
  AggregateType with;
  with.name = "rec";
  with.size = 16;
  with.fields = {{"n", size_t_, 0, 0}, {"f", binop, 64, 0}};
  AggregateType without = with;
  without.fields[0].type = u64;
  without.fields[1].type = s.strip_typedefs(binop);
  TypeId a = s.intern(with), b = s.intern(without);
  EXPECT_NE(a, b);
  EXPECT_EQ(without_typedefs(s, a), b);
  EXPECT_EQ(without_typedefs(s, b), b);
  EXPECT_EQ(without_typedefs(s, size_t_), u64);

  FunctionType fn{size_t_, {{"x", s.pointer_to(size_t_)}}, false, CallConv::Default};
  FunctionType plain{u64, {{"x", s.pointer_to(u64)}}, false, CallConv::Default};
  EXPECT_EQ(without_typedefs(s, s.function(fn)), s.function(plain));
}

TEST(WithoutTypedefs, CyclesThroughTypedefs) {
  // typedef struct node node_t; struct node { node_t *next; int v; };
  TypeStore s;
  TypeId i = s.int_type(4, true, IntRank::Int);
  TypeGraph g;
  TypeId node = g.reserve();
  TypeId td = g.add(TypedefType{"node_t", node});
  AggregateType a;
  a.name = "node";
  a.size = 16;
  a.fields = {{"next", g.add(PointerType{td, 8}), 0, 0}, {"v", i, 64, 0}};
  g.set(node, a);
  TypeId with = s.intern(g)[node.index()];

  TypeGraph h;
  TypeId n2 = h.reserve();
  a.fields[0].type = h.add(PointerType{n2, 8});
  h.set(n2, a);
  TypeId plain = s.intern(h)[n2.index()];
  EXPECT_NE(with, plain);
  EXPECT_EQ(without_typedefs(s, with), plain);
}

TEST(WithoutTypedefs, MergesQualifiersTypedefsSeparated) {
  TypeStore s;
  TypeId i = s.int_type(4, true, IntRank::Int);
  TypeId vint = s.typedef_of("vint", s.qualified(i, kVolatile));
  TypeId cv = s.qualified(vint, kConst);
  EXPECT_EQ(without_typedefs(s, cv), s.qualified(i, kConst | kVolatile));
  EXPECT_EQ(without_typedefs(s, s.qualified(i, 0)), i);
}

TEST(WithoutTypedefs, NamesAnonymousTags) {
  TypeStore s;
  AggregateType anon;
  anon.size = 8;
  anon.fields = {{"x", s.int_type(4, true, IntRank::Int), 0, 0}};
  TypeId point = s.typedef_of("point", s.intern(anon));
  AggregateType named = anon;
  named.name = "point";
  EXPECT_EQ(without_typedefs(s, point), s.intern(anon));
  EXPECT_EQ(without_typedefs(s, point, {.name_anonymous_tags = true}), s.intern(named));
  // Enums keep no name: CodeView calls them <unnamed-tag>.
  TypeId e = s.intern(EnumType{"", 4, false, true, {{"A", 0}}});
  EXPECT_EQ(without_typedefs(s, s.typedef_of("kind", e), {.name_anonymous_tags = true}), e);
}

}  // namespace
}  // namespace revkit::types
