#include "revkit/types/store.h"

#include <gtest/gtest.h>

namespace revkit::types {
namespace {

AggregateType node_struct(TypeId next_ptr, TypeId value) {
  AggregateType a;
  a.name = "node";
  a.size = 16;
  a.fields = {{"next", next_ptr, 0, 0}, {"value", value, 64, 0}};
  return a;
}

TEST(TypeStore, InternsEqualTypesOnce) {
  TypeStore s;
  TypeId i1 = s.int_type(4, true, IntRank::Int);
  TypeId i2 = s.int_type(4, true, IntRank::Int);
  EXPECT_EQ(i1, i2);
  EXPECT_NE(i1, s.int_type(4, false, IntRank::Int));
  EXPECT_NE(i1, s.int_type(4, true, IntRank::Long));  // distinct C types
  TypeId p1 = s.pointer_to(i1);
  std::size_t n = s.size();
  EXPECT_EQ(p1, s.pointer_to(i2));
  EXPECT_EQ(n, s.size());
}

TEST(TypeStore, HashesAreStableAcrossStores) {
  // Golden values: the encoding is explicit little-endian, so these must not
  // change across runs or machines. Changing them is a format change.
  TypeStore s;
  TypeId i = s.int_type(4, true, IntRank::Int);
  EXPECT_EQ(s.hash(s.void_type()).hex(), "78803710efd636c57d3dbc02a3b4b210");
  EXPECT_EQ(s.hash(i).hex(), s.hash(TypeStore().int_type(4, true, IntRank::Int)).hex());
}

TEST(TypeStore, SelfReferentialStruct) {
  TypeStore s;
  TypeId i = s.int_type(4, true, IntRank::Int);
  TypeGraph g;
  TypeId n = g.reserve();
  TypeId p = g.add(PointerType{n, 8});
  g.set(n, node_struct(p, i));
  auto ids = s.intern(g);
  ASSERT_EQ(ids.size(), 2u);
  const auto &st = *s.get(ids[0]).as<AggregateType>();
  EXPECT_EQ(st.fields[0].type, ids[1]);
  EXPECT_EQ(s.get(ids[1]).as<PointerType>()->target, ids[0]);
  EXPECT_EQ(s.cycle_of(ids[0]).size(), 2u);

  // The same type built again, from either end, interns to the same ids.
  TypeGraph g2;
  TypeId p2 = g2.reserve();
  TypeId n2 = g2.add(node_struct(p2, i));
  g2.set(p2, PointerType{n2, 8});
  auto ids2 = s.intern(g2);
  EXPECT_EQ(ids2[0], ids[1]);
  EXPECT_EQ(ids2[1], ids[0]);
}

TEST(TypeStore, UnrolledCycleHashesLikeMinimalCycle) {
  // node -> ptr -> node' -> ptr' -> node, with node == node' structurally,
  // is the same infinite type as the two-node cycle.
  TypeStore minimal, unrolled;
  TypeGraph g1;
  {
    TypeId i = minimal.int_type(4, true, IntRank::Int);
    TypeId n = g1.reserve();
    g1.set(n, node_struct(g1.add(PointerType{n, 8}), i));
  }
  auto a = minimal.intern(g1);
  TypeGraph g2;
  {
    TypeId i = unrolled.int_type(4, true, IntRank::Int);
    TypeId n1 = g2.reserve(), n2 = g2.reserve();
    g2.set(n1, node_struct(g2.add(PointerType{n2, 8}), i));
    g2.set(n2, node_struct(g2.add(PointerType{n1, 8}), i));
  }
  auto b = unrolled.intern(g2);
  EXPECT_EQ(minimal.hash(a[0]), unrolled.hash(b[0]));
  EXPECT_EQ(b[0], b[1]);  // both copies interned once
  EXPECT_EQ(unrolled.size(), minimal.size());
}

TEST(TypeStore, MutualRecursionIsCanonical) {
  auto build = [](TypeStore &s, bool a_first) {
    TypeId i = s.int_type(4, true, IntRank::Int);
    TypeGraph g;
    TypeId a = g.reserve(), b = g.reserve();
    if (!a_first) std::swap(a, b);
    AggregateType sa{AggregateKind::Struct, "A", 16, 0, false, true,
                     {{"b", g.add(PointerType{b, 8}), 0, 0}, {"x", i, 64, 0}}};
    AggregateType sb{AggregateKind::Struct, "B", 8, 0, false, true,
                     {{"a", g.add(PointerType{a, 8}), 0, 0}}};
    g.set(a, sa);
    g.set(b, sb);
    auto ids = s.intern(g);
    return std::pair{ids[a.index()], ids[b.index()]};
  };
  TypeStore s1, s2;
  auto [a1, b1] = build(s1, true);
  auto [a2, b2] = build(s2, false);
  EXPECT_EQ(s1.hash(a1), s2.hash(a2));
  EXPECT_EQ(s1.hash(b1), s2.hash(b2));
  EXPECT_NE(s1.hash(a1), s1.hash(b1));
}

TEST(TypeStore, DifferentCyclesDiffer) {
  TypeStore s;
  TypeId i = s.int_type(4, true, IntRank::Int);
  TypeId l = s.int_type(8, true, IntRank::Long);
  TypeGraph g;
  TypeId n1 = g.reserve(), n2 = g.reserve();
  g.set(n1, node_struct(g.add(PointerType{n1, 8}), i));
  g.set(n2, node_struct(g.add(PointerType{n2, 8}), l));
  auto ids = s.intern(g);
  EXPECT_NE(ids[0], ids[1]);
}

TEST(TypeStore, LocalTypeEqualToStoredCycleMember) {
  // Store A <-> B. Then intern a new struct equal to A that points at the
  // stored B: it must be recognised as A.
  TypeStore s;
  TypeGraph g;
  TypeId a = g.reserve(), b = g.reserve();
  g.set(a, AggregateType{AggregateKind::Struct, "A", 8, 0, false, true,
                         {{"b", g.add(PointerType{b, 8}), 0, 0}}});
  g.set(b, AggregateType{AggregateKind::Struct, "B", 8, 0, false, true,
                         {{"a", g.add(PointerType{a, 8}), 0, 0}}});
  auto ids = s.intern(g);
  TypeId stored_a = ids[0], stored_b = ids[1];
  std::size_t n = s.size();
  TypeId pb = s.pointer_to(stored_b);
  TypeId again = s.intern(AggregateType{AggregateKind::Struct, "A", 8, 0, false, true,
                                        {{"b", pb, 0, 0}}});
  EXPECT_EQ(again, stored_a);
  EXPECT_EQ(s.size(), n);
}

TEST(TypeStore, RejectsCyclesWithoutAggregates) {
  TypeStore s;
  TypeGraph g;
  TypeId p = g.reserve();
  g.set(p, PointerType{p, 8});
  EXPECT_THROW(s.intern(g), std::invalid_argument);
  EXPECT_EQ(g.break_invalid_cycles(), 1u);
  auto ids = s.intern(g);
  EXPECT_EQ(s.kind(s.get(ids[0]).as<PointerType>()->target), Kind::Undefined);
}

TEST(TypeStore, RejectsByValueSelfContainment) {
  TypeStore s;
  TypeGraph g;
  TypeId a = g.reserve();
  g.set(a, AggregateType{AggregateKind::Struct, "S", 8, 0, false, true, {{"self", a, 0, 0}}});
  EXPECT_THROW(s.intern(g), std::invalid_argument);
  EXPECT_EQ(g.break_invalid_cycles(), 1u);
  EXPECT_NO_THROW(s.intern(g));
}

TEST(TypeStore, RejectsBadGraphs) {
  TypeStore s;
  TypeGraph unset;
  unset.reserve();
  EXPECT_THROW(s.intern(unset), std::invalid_argument);
  TypeGraph dangling;
  dangling.add(PointerType{TypeId::local(7), 8});
  EXPECT_THROW(s.intern(dangling), std::invalid_argument);
  TypeGraph bad_store;
  bad_store.add(PointerType{TypeId::store(12345), 8});
  EXPECT_THROW(s.intern(bad_store), std::invalid_argument);
  EXPECT_THROW(s.get(TypeId::store(99)), std::out_of_range);
}

TEST(TypeStore, FieldNamesAndOffsetsAffectIdentity) {
  TypeStore s;
  TypeId i = s.int_type(4, true, IntRank::Int);
  auto mk = [&](std::string field, std::uint64_t off, std::uint32_t bits) {
    return s.intern(AggregateType{AggregateKind::Struct, "S", 8, 0, false, true,
                                  {{field, i, off, bits}}});
  };
  TypeId base = mk("x", 0, 0);
  EXPECT_EQ(base, mk("x", 0, 0));
  EXPECT_NE(base, mk("y", 0, 0));
  EXPECT_NE(base, mk("x", 32, 0));
  EXPECT_NE(base, mk("x", 0, 3));
}

TEST(TypeStore, SizeAndAlignment) {
  TypeStore s;
  TypeId c = s.int_type(1, true, IntRank::PlainChar);
  TypeId i = s.int_type(4, true, IntRank::Int);
  TypeId d = s.float_type(8, FloatKind::Double);
  TypeId arr = s.array_of(s.array_of(i, 3), 2);
  EXPECT_EQ(s.size_of(arr), 24u);
  EXPECT_EQ(s.align_of(arr), 4u);
  TypeId st = s.intern(AggregateType{AggregateKind::Struct, "S", 16, 0, false, true,
                                     {{"c", c, 0, 0}, {"d", d, 64, 0}}});
  EXPECT_EQ(s.size_of(s.typedef_of("S_t", st)), 16u);
  EXPECT_EQ(s.align_of(st), 8u);
  TypeId packed = s.intern(AggregateType{AggregateKind::Struct, "P", 9, 0, true, true,
                                         {{"c", c, 0, 0}, {"d", d, 8, 0}}});
  EXPECT_EQ(s.align_of(packed), 1u);
  EXPECT_EQ(s.size_of(s.array_of(i, 0)), 0u);
  EXPECT_EQ(s.size_of(s.void_type()), 0u);
}

TEST(TypeStore, LookupByName) {
  TypeStore s;
  TypeId i = s.int_type(4, true, IntRank::Int);
  TypeId t = s.typedef_of("myint", i);
  EXPECT_EQ(s.lookup("myint"), std::vector<TypeId>{t});
  EXPECT_TRUE(s.lookup("nothing").empty());
  EXPECT_EQ(s.strip_typedefs(s.qualified(t, kConst)), i);
  EXPECT_EQ(s.find(s.hash(t)), t);
}

}  // namespace
}  // namespace revkit::types
