// Checksum algorithms against their standard check values, and the
// detector finding header fields, trailers and file-name rules.
#include "revkit/patch/checksum.h"

#include <gtest/gtest.h>

#include <random>
#include <string>

namespace revkit::patch {
namespace {

std::vector<std::uint8_t> bytes(std::string_view s) { return {s.begin(), s.end()}; }

TEST(Checksum, CheckValues) {
  const auto c = bytes("123456789");
  EXPECT_EQ(compute(Algorithm::crc32, c), 0xCBF43926u);
  EXPECT_EQ(compute(Algorithm::crc32_bzip2, c), 0xFC891918u);
  EXPECT_EQ(compute(Algorithm::crc32_mpeg2, c), 0x0376E6E7u);
  EXPECT_EQ(compute(Algorithm::crc32_posix, c), 0x765E7680u);
  EXPECT_EQ(compute(Algorithm::crc32_jamcrc, c), 0x340BC6D9u);
  EXPECT_EQ(compute(Algorithm::crc32c, c), 0xE3069283u);
  EXPECT_EQ(compute(Algorithm::crc16_ccitt_false, c), 0x29B1u);
  EXPECT_EQ(compute(Algorithm::crc16_xmodem, c), 0x31C3u);
  EXPECT_EQ(compute(Algorithm::crc16_kermit, c), 0x2189u);
  EXPECT_EQ(compute(Algorithm::crc16_modbus, c), 0x4B37u);
  EXPECT_EQ(compute(Algorithm::crc16_arc, c), 0xBB3Du);
  EXPECT_EQ(compute(Algorithm::fletcher16, bytes("abcde")), 0xC8F0u);
  EXPECT_EQ(compute(Algorithm::fletcher32, bytes("abcde")), 0xF04FC729u);
  EXPECT_EQ(compute(Algorithm::adler32, bytes("Wikipedia")), 0x11E60398u);
  EXPECT_EQ(compute(Algorithm::sum8, bytes("\x01\xff\x02")), 0x02u);
  EXPECT_EQ(compute(Algorithm::sum32, bytes("\x01\xff\x02")), 0x102u);
  EXPECT_EQ(compute(Algorithm::sum32_neg, bytes("\x01")), 0xffffffffu);
  EXPECT_EQ(compute(Algorithm::sum16_words_le, bytes("\x01\x02\x03")), 0x0204u);
  EXPECT_EQ(compute(Algorithm::sum16_words_be, bytes("\x01\x02\x03")), 0x0402u);
  EXPECT_EQ(compute(Algorithm::sum32_words_be, std::vector<std::uint8_t>{0, 0, 1, 0, 0, 0, 0, 2}), 0x102u);
  for (Algorithm a : all_algorithms()) EXPECT_EQ(parse_algorithm(name(a)), a);
}

std::vector<std::uint8_t> firmware(std::size_t n, unsigned seed) {
  std::mt19937 rng(seed);
  std::vector<std::uint8_t> f(n);
  for (auto &b : f) b = static_cast<std::uint8_t>(rng());
  return f;
}

TEST(Checksum, DetectsAHeaderCrcOfThePayload) {
  auto f = firmware(0x4000, 1);
  // A vendor header: magic, then at 0x1c the CRC32 (LE) of what follows 0x200.
  Spec s;
  s.algorithm = Algorithm::crc32;
  s.start = 0x200;
  s.field = true;
  s.field_offset = 0x1c;
  s.field_width = 4;
  ASSERT_TRUE(write_field(s, *evaluate(s, f), f));
  DetectOptions o;
  o.image_offset = 0x200;
  auto r = detect(f, o);
  ASSERT_FALSE(r.hits.empty());
  EXPECT_EQ(r.hits[0].spec, s) << r.hits[0].evidence;
  EXPECT_GT(r.tried, 40u);
}

TEST(Checksum, DetectsASumInTheFileName) {
  auto f = firmware(0x3000, 2);
  for (int i = 0; i < 0x400; ++i) f.push_back(0xff);  // erased flash at the end
  const std::uint64_t sum = compute(Algorithm::sum32, f);
  char name[64];
  std::snprintf(name, sizeof name, "FW_202401011200_%08llX.bin", static_cast<unsigned long long>(sum));
  DetectOptions o;
  o.expected = values_in_name(name);
  ASSERT_EQ(o.expected.size(), 1u);
  EXPECT_EQ(o.expected[0].first, sum);
  auto r = detect(f, o);
  ASSERT_FALSE(r.hits.empty());
  EXPECT_TRUE(r.hits[0].spec.name);
  EXPECT_EQ(r.hits[0].spec.algorithm, Algorithm::sum32);
  EXPECT_EQ(r.hits[0].spec.start, 0u);
  EXPECT_EQ(r.hits[0].spec.end, 0);
  EXPECT_NE(r.hits[0].evidence.find("file name"), std::string::npos) << r.hits[0].evidence;
}

TEST(Checksum, DetectsATrailerAndASumWithItsFieldInside) {
  auto f = firmware(0x2000, 3);
  // A CRC-16/XMODEM of everything before it in the last two bytes (BE).
  Spec t;
  t.algorithm = Algorithm::crc16_xmodem;
  t.end = -2;
  t.field = true;
  t.field_offset = f.size() - 2;
  t.field_width = 2;
  t.field_big_endian = true;
  ASSERT_TRUE(write_field(t, *evaluate(t, f), f));
  auto r = detect(f, {});
  bool found = false;
  for (const Hit &h : r.hits) found |= h.spec == t;
  EXPECT_TRUE(found);

  // A 32-bit byte sum over the whole file with its own field (at 8) as zero.
  auto g = firmware(0x1800, 4);
  Spec s;
  s.algorithm = Algorithm::sum32;
  s.field = true;
  s.field_offset = 8;
  s.field_width = 4;
  ASSERT_TRUE(write_field(s, *evaluate(s, g), g));
  r = detect(g, {});
  found = false;
  for (const Hit &h : r.hits) found |= h.spec == s;
  EXPECT_TRUE(found);
}

TEST(Checksum, ValuesInNamesAreWholeHexRuns) {
  EXPECT_TRUE(values_in_name("firmware.bin").empty());
  auto v = values_in_name("dir/FW-v1_DEADBEEF.bin");
  ASSERT_EQ(v.size(), 1u);
  EXPECT_EQ(v[0].first, 0xDEADBEEFu);
  EXPECT_EQ(values_in_name("x_1a2b.img").at(0).first, 0x1a2bu);
}

TEST(Checksum, PeCheckSum) {
  // A minimal PE: MZ header pointing at a PE signature and an optional header.
  std::vector<std::uint8_t> f(0x400, 0);
  f[0] = 'M';
  f[1] = 'Z';
  f[0x3c] = 0x80;
  f[0x80] = 'P';
  f[0x81] = 'E';
  for (std::size_t i = 0x100; i < f.size(); ++i) f[i] = static_cast<std::uint8_t>(i * 7);
  ASSERT_EQ(pe_checksum_offset(f), 0x80u + 24 + 64);
  const auto c = pe_checksum(f);
  ASSERT_TRUE(c);
  // The field's own value doesn't change the result.
  f[0x80 + 24 + 64] = 0x12;
  EXPECT_EQ(pe_checksum(f), c);
  // The reference fold: sum of LE halfwords with carries, plus the size.
  std::uint64_t s = 0;
  for (std::size_t i = 0; i < f.size(); i += 2)
    if (i < 0x80 + 24 + 64 || i >= 0x80 + 24 + 68) s += f[i] | f[i + 1] << 8;
  while (s >> 16) s = (s & 0xffff) + (s >> 16);
  EXPECT_EQ(*c, s + f.size());
}

}  // namespace
}  // namespace revkit::patch
