#include "revkit/facts/address.h"
#include "revkit/facts/codec.h"
#include "revkit/facts/fact.h"
#include "revkit/facts/fingerprint.h"

#include <gtest/gtest.h>

namespace revkit::facts {
namespace {

Address ram(std::uint64_t off) { return {1, off}; }
AddressRange rr(std::uint64_t a, std::uint64_t b) { return *AddressRange::make(ram(a), ram(b)); }

TEST(Address, SpacesAndFormatting) {
  SpaceTable t = SpaceTable::standard();
  const AddressSpace *r = t.find("ram");
  ASSERT_NE(r, nullptr);
  EXPECT_EQ(r->kind, SpaceKind::Ram);
  SpaceId ov = t.add_overlay("ov1", r->id);
  EXPECT_EQ(t.find(ov)->kind, SpaceKind::Overlay);
  EXPECT_EQ(t.find(ov)->overlay_base, r->id);
  EXPECT_THROW(t.add("ram", SpaceKind::Ram, 8), std::invalid_argument);

  Address a{r->id, 0x401000};
  EXPECT_EQ(t.format(a), "ram:0x401000");
  EXPECT_EQ(t.parse("ram:0x401000"), a);
  EXPECT_EQ(t.parse("ov1:10"), (Address{ov, 0x10}));
  EXPECT_FALSE(t.parse("nope:0x1"));
  EXPECT_FALSE(t.parse("ram:0xzz"));
  EXPECT_FALSE(t.parse("register:0x100000000"));  // 4-byte space

  // Overlay addresses are distinct from the base space's.
  EXPECT_NE((Address{ov, 0x10}), (Address{r->id, 0x10}));
  EXPECT_EQ(t.advance(a, 0x10), (Address{r->id, 0x401010}));
  EXPECT_FALSE(t.advance(Address{r->id, ~0ULL}, 1));
  EXPECT_FALSE(t.advance(*t.parse("register:0xfffffff0"), 0x20));
}

TEST(Address, RangeConstruction) {
  EXPECT_FALSE(AddressRange::make(ram(5), ram(4)));
  EXPECT_FALSE(AddressRange::make(ram(1), Address{2, 3}));
  EXPECT_FALSE(AddressRange::sized(ram(1), 0));
  EXPECT_FALSE(AddressRange::sized(ram(~0ULL), 2));
  auto full = AddressRange::make(ram(0), ram(~0ULL));
  ASSERT_TRUE(full);
  EXPECT_EQ(full->span(), ~0ULL);
}

TEST(AddressSet, MergesAdjacentAndOverlapping) {
  AddressSet s;
  s.add(rr(10, 19));
  s.add(rr(30, 39));
  s.add(rr(20, 25));  // adjacent to the first
  ASSERT_EQ(s.ranges().size(), 2u);
  EXPECT_EQ(s.ranges()[0], rr(10, 25));
  s.add(rr(0, 100));
  ASSERT_EQ(s.ranges().size(), 1u);
  EXPECT_EQ(s.ranges()[0], rr(0, 100));
  s.add(AddressRange{Address{2, 0}, Address{2, 5}});
  EXPECT_EQ(s.ranges().size(), 2u);
  s.add(rr(~0ULL - 1, ~0ULL));
  s.add(rr(~0ULL - 5, ~0ULL - 2));
  EXPECT_TRUE(s.contains(ram(~0ULL)));
  EXPECT_EQ(s.ranges().size(), 3u);
}

TEST(AddressSet, SubtractIntersectContains) {
  AddressSet s(rr(0, 99));
  s.subtract(rr(10, 19));
  s.subtract(rr(90, 200));
  ASSERT_EQ(s.ranges().size(), 2u);
  EXPECT_EQ(s.ranges()[0], rr(0, 9));
  EXPECT_EQ(s.ranges()[1], rr(20, 89));
  EXPECT_TRUE(s.contains(ram(0)));
  EXPECT_FALSE(s.contains(ram(15)));
  EXPECT_TRUE(s.contains(ram(89)));
  EXPECT_FALSE(s.contains(ram(90)));
  EXPECT_FALSE(s.contains(Address{2, 5}));

  AddressSet t(rr(5, 25));
  AddressSet i = s.intersect(t);
  ASSERT_EQ(i.ranges().size(), 2u);
  EXPECT_EQ(i.ranges()[0], rr(5, 9));
  EXPECT_EQ(i.ranges()[1], rr(20, 25));
  EXPECT_TRUE(s.intersects(rr(9, 12)));
  EXPECT_FALSE(s.intersects(rr(10, 19)));
  EXPECT_EQ(s.min(), ram(0));
  EXPECT_EQ(s.max(), ram(89));
}

TEST(Codec, RoundTripsAndRejectsBadInput) {
  FactValue values[] = {std::monostate{}, std::int64_t{-5}, std::string("hello"), ram(0x1234),
                        AddressSet(rr(1, 2))};
  for (const auto &v : values) EXPECT_EQ(decode_from_string<FactValue>(encode_to_string(v)), v);

  for (std::uint64_t v : {0ULL, 127ULL, 128ULL, ~0ULL})
    EXPECT_EQ(decode_from_string<std::uint64_t>(encode_to_string(v)), v);
  for (std::int64_t v : {std::int64_t{0}, std::int64_t{-1}, INT64_MIN, INT64_MAX})
    EXPECT_EQ(decode_from_string<std::int64_t>(encode_to_string(v)), v);

  std::string s = encode_to_string(std::string("abcdef"));
  EXPECT_THROW(decode_from_string<std::string>(s.substr(0, 3)), DecodeError);
  EXPECT_THROW(decode_from_string<std::string>(s + "x"), DecodeError);
  EXPECT_THROW(decode_from_string<std::uint8_t>(encode_to_string(std::uint64_t{300})), DecodeError);
  EXPECT_THROW(decode_from_string<std::uint64_t>(std::string(11, '\xff')), DecodeError);
  // A huge element count must fail, not allocate.
  EXPECT_THROW(decode_from_string<std::vector<std::uint64_t>>(encode_to_string(~0ULL)), DecodeError);
  EXPECT_THROW(decode_from_string<FactValue>(encode_to_string(std::uint64_t{9})), DecodeError);
  // Ranges that would wrap are rejected.
  Encoder e;
  encode(e, ram(10));
  e.varint(~0ULL);
  EXPECT_THROW(decode_from_string<AddressRange>(e.str()), DecodeError);
}

TEST(Fingerprint, StableAndSensitive) {
  EXPECT_EQ(Fingerprint::of("abc"), Fingerprint::of("abc"));
  EXPECT_NE(Fingerprint::of("abc"), Fingerprint::of("abd"));
  EXPECT_NE(Fingerprint::of(""), Fingerprint::of(std::string(1, '\0')));
  // Pinned so a change in the hash (which would orphan persisted memos)
  // is noticed.
  EXPECT_EQ(Fingerprint::of("revkit").hex(), "9bf2bec2b94c6e1cd9c219378aa4521e");
  EXPECT_EQ(Fingerprint::of("").hex(), "c001f26eaae4d7e5c3f49c40543bf2b7");
  // Lengths that exercise both tail branches differ from each other.
  std::string s(31, 'x');
  EXPECT_NE(Fingerprint::of(s.substr(0, 9)), Fingerprint::of(s.substr(0, 8)));
  EXPECT_NE(Fingerprint::of(s.substr(0, 17)), Fingerprint::of(s.substr(0, 16)));
}

TEST(Provenance, ParseAndRank) {
  auto p = Provenance::parse("agent:model@1.2");
  ASSERT_TRUE(p);
  EXPECT_EQ(p->kind, ProvenanceKind::Agent);
  EXPECT_EQ(p->id, "model");
  EXPECT_EQ(p->version, "1.2");
  EXPECT_EQ(p->str(), "agent:model@1.2");
  EXPECT_EQ(Provenance::parse("user:alice")->str(), "user:alice");
  EXPECT_EQ(Provenance::parse("migration")->kind, ProvenanceKind::Migration);
  EXPECT_FALSE(Provenance::parse("robot:x"));
  EXPECT_GT(rank(ProvenanceKind::User), rank(ProvenanceKind::Import));
  EXPECT_GT(rank(ProvenanceKind::Import), rank(ProvenanceKind::Agent));
  EXPECT_GT(rank(ProvenanceKind::Agent), rank(ProvenanceKind::Analysis));
  auto plugin = Provenance::parse("plugin:rename-regex@1.0.0");
  ASSERT_TRUE(plugin);
  EXPECT_EQ(plugin->kind, ProvenanceKind::Plugin);
  EXPECT_EQ(plugin->str(), "plugin:rename-regex@1.0.0");
  EXPECT_EQ(rank(ProvenanceKind::Plugin), rank(ProvenanceKind::Agent));
  auto script = Provenance::parse("script:fix-names@0123456789ab");
  ASSERT_TRUE(script);
  EXPECT_EQ(script->kind, ProvenanceKind::Script);
  EXPECT_EQ(script->str(), "script:fix-names@0123456789ab");
  // A script ranks with agents: a person's later edit survives a re-run.
  EXPECT_EQ(rank(ProvenanceKind::Script), rank(ProvenanceKind::Agent));
  EXPECT_LT(rank(ProvenanceKind::Script), rank(ProvenanceKind::User));
  Encoder e;
  script->encode(e);
  Decoder d(e.str());
  EXPECT_EQ(Provenance::decode(d).kind, ProvenanceKind::Script);
}

}  // namespace
}  // namespace revkit::facts
