// compose_structure: fields from pointer accesses (docs/types.md,
// "Structures from pointer use"). The p-code walk is tested through the
// backend (auto_struct_test.cc), on real decompilations.
#include "revkit/infer/accesses.h"

#include <gtest/gtest.h>

namespace revkit::infer {
namespace {

PointerAccess Load(std::int64_t off, std::uint32_t size, ValueKind v = ValueKind::unknown) {
  PointerAccess a;
  a.offset = off;
  a.size = size;
  a.kind = AccessKind::load;
  a.value = v;
  return a;
}

PointerAccess Store(std::int64_t off, std::uint32_t size, ValueKind v = ValueKind::unknown) {
  PointerAccess a = Load(off, size, v);
  a.kind = AccessKind::store;
  return a;
}

PointerAccess Passed(std::int64_t off) {
  PointerAccess a;
  a.offset = off;
  a.kind = AccessKind::passed;
  return a;
}

TEST(ComposeStructure, FieldPerOffsetSizedByAccesses) {
  const StructurePlan p = compose_structure(
      {Load(0, 8, ValueKind::pointer), Load(8, 4, ValueKind::signed_int), Store(8, 4), Load(0x10, 8, ValueKind::floating)},
      {});
  ASSERT_EQ(p.fields.size(), 3u);
  EXPECT_EQ(p.size, 0x18u);
  EXPECT_EQ(p.fields[0].offset, 0u);
  EXPECT_EQ(p.fields[0].size, 8u);
  EXPECT_EQ(p.fields[0].value, ValueKind::pointer);
  EXPECT_EQ(p.fields[0].name, "field_0x0");
  EXPECT_EQ(p.fields[1].offset, 8u);
  EXPECT_EQ(p.fields[1].value, ValueKind::signed_int);
  EXPECT_EQ(p.fields[1].accesses, 2u);
  EXPECT_EQ(p.fields[2].value, ValueKind::floating);
  EXPECT_EQ(p.fields[2].name, "field_0x10");
}

TEST(ComposeStructure, CommonestSizeWinsAndWiderOnATie) {
  StructurePlan p = compose_structure({Load(4, 4), Load(4, 4), Load(4, 1)}, {});
  ASSERT_EQ(p.fields.size(), 1u);
  EXPECT_EQ(p.fields[0].size, 4u);
  p = compose_structure({Load(4, 2), Load(4, 4)}, {});
  EXPECT_EQ(p.fields[0].size, 4u);
}

TEST(ComposeStructure, MergedStoresSplitAtTheNextField) {
  // An 8-byte store of two adjacent ints: two fields, the first truncated
  // to undefined bytes.
  const StructurePlan p = compose_structure({Store(0x10, 8, ValueKind::signed_int), Load(0x14, 4, ValueKind::signed_int)}, {});
  ASSERT_EQ(p.fields.size(), 2u);
  EXPECT_EQ(p.fields[0].size, 4u);
  EXPECT_TRUE(p.fields[0].truncated);
  EXPECT_EQ(p.fields[0].value, ValueKind::unknown);
  EXPECT_EQ(p.fields[1].offset, 0x14u);
  EXPECT_EQ(p.size, 0x18u);
}

TEST(ComposeStructure, PassedPointerPlusOffsetMarksAField) {
  const StructurePlan p = compose_structure({Passed(0), Passed(0x20), Load(0, 8)}, {});
  ASSERT_EQ(p.fields.size(), 2u);
  EXPECT_EQ(p.fields[1].offset, 0x20u);
  EXPECT_EQ(p.fields[1].size, 1u);
  EXPECT_EQ(p.size, 0x21u);
}

TEST(ComposeStructure, NegativeAndFarOffsetsAreDropped) {
  const StructurePlan p = compose_structure({Load(-8, 8), Load(0x2000, 4), Load(0, 4)}, {});
  ASSERT_EQ(p.fields.size(), 1u);
  EXPECT_EQ(p.size, 4u);
  // Unless an existing structure is that large.
  const StructurePlan q = compose_structure({Load(0x2000, 4)}, {}, {{0, 4, "a"}}, 0x3000);
  EXPECT_EQ(q.fields.size(), 2u);
}

TEST(ComposeStructure, ValueKindsNeedASizeThatFits) {
  const StructurePlan p = compose_structure({Load(0, 4, ValueKind::pointer), Load(8, 3, ValueKind::signed_int)}, {});
  ASSERT_EQ(p.fields.size(), 2u);
  EXPECT_EQ(p.fields[0].value, ValueKind::unknown);  // a 4-byte "pointer" on a 64-bit target
  EXPECT_EQ(p.fields[1].value, ValueKind::unknown);
}

TEST(ComposeStructure, FillInKeepsExistingFieldsAndOnlyGrows) {
  const std::vector<ExistingField> old{{0, 8, "next"}, {8, 4, "count"}};
  const StructurePlan p = compose_structure(
      {Load(0, 4), Load(10, 2), Load(0xc, 4, ValueKind::unsigned_int), Store(0x18, 8, ValueKind::pointer)}, {}, old, 0x10);
  // 0 and 10 are inside existing fields; 0xc is new, 0x18 grows it.
  ASSERT_EQ(p.fields.size(), 4u);
  EXPECT_TRUE(p.fields[0].existing);
  EXPECT_EQ(p.fields[0].name, "next");
  EXPECT_EQ(p.fields[0].accesses, 1u);
  EXPECT_TRUE(p.fields[1].existing);
  EXPECT_EQ(p.fields[2].offset, 0xcu);
  EXPECT_FALSE(p.fields[2].existing);
  EXPECT_EQ(p.fields[2].value, ValueKind::unsigned_int);
  EXPECT_EQ(p.fields[3].offset, 0x18u);
  EXPECT_EQ(p.size, 0x20u);
  // Nothing new: the same fields, the same size.
  const StructurePlan same = compose_structure({Load(0, 8)}, {}, old, 0x10);
  EXPECT_EQ(same.fields.size(), 2u);
  EXPECT_EQ(same.size, 0x10u);
}

TEST(ComposeStructure, NewFieldStopsAtAnExistingOne) {
  const StructurePlan p = compose_structure({Load(4, 8)}, {}, {{8, 4, "b"}}, 0x10);
  ASSERT_EQ(p.fields.size(), 2u);
  EXPECT_EQ(p.fields[0].offset, 4u);
  EXPECT_EQ(p.fields[0].size, 4u);
  EXPECT_TRUE(p.fields[0].truncated);
}

TEST(PointerAccess, RoundTrips) {
  PointerAccess a = Passed(0x18);
  a.callee = 0x401000;
  a.parameter = 2;
  a.storage = "register:RDX";
  a.address = 0x401234;
  EXPECT_EQ(facts::decode_from_string<PointerAccess>(facts::encode_to_string(a)), a);
}

}  // namespace
}  // namespace revkit::infer
