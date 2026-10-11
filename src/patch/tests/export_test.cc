// Export of a raw image behind a header: patches at their file offsets,
// refusals outside file-backed bytes, fixups into a field and into the
// file name, and verification by loading the output again.
#include "revkit/loader/load.hh"
#include "revkit/patch/export.h"

#include <gtest/gtest.h>

namespace revkit::patch {
namespace {

std::shared_ptr<const loader::Bytes> file_bytes(std::size_t n) {
  auto f = std::make_shared<loader::Bytes>(n);
  for (std::size_t i = 0; i < n; ++i) (*f)[i] = static_cast<std::byte>((i * 31 + 7) & 0xff);
  return f;
}

loader::RawOptions raw_options() {
  loader::RawOptions o;
  o.language = "ARM:LE:32:v4t";
  o.offset = 0x200;  // a header before the image
  loader::RawRegion ram;
  ram.name = "ram";
  ram.start = 0x20000000;
  ram.size = 0x1000;
  o.regions.push_back(ram);
  return o;
}

std::vector<std::uint8_t> u8(const loader::Bytes &b) {
  std::vector<std::uint8_t> v(b.size());
  for (std::size_t i = 0; i < b.size(); ++i) v[i] = std::to_integer<std::uint8_t>(b[i]);
  return v;
}

TEST(Export, RawWithHeaderSumInTheNameAndAFieldCrc) {
  auto file = file_bytes(0x2200);
  const loader::Image image = loader::parse_raw(file, raw_options());
  const std::vector<Patch> patches{{0x1dd8, std::string("\x7d\x58\x03\xeb", 4)}, {0x0108, std::string("\x09", 1)}};
  MapResult m = map_to_file(image, patches);
  ASSERT_TRUE(m.error.empty()) << m.error;
  ASSERT_EQ(m.mapped.size(), 2u);
  EXPECT_EQ(m.mapped[0].file_offset, 0x200u + 0x1dd8);

  ExportOptions o;
  o.original_name = "firmware.bin";
  o.name_template = "FW_202401011200_{SUM:08X}.bin";
  Fixup crc;
  crc.spec.algorithm = Algorithm::crc32;
  crc.spec.start = 0x200;
  crc.spec.field = true;
  crc.spec.field_offset = 0x10;
  crc.spec.field_width = 4;
  Fixup sum;
  sum.spec.algorithm = Algorithm::sum32;
  sum.spec.name = true;
  o.fixups = {sum, crc};  // the name sum is taken last whatever the order
  const auto original = u8(*file);
  ExportResult r = build_export(original, m.mapped, o);
  ASSERT_TRUE(r.error.empty()) << r.error;
  EXPECT_EQ(r.data.size(), original.size());
  EXPECT_EQ(r.data[0x200 + 0x1dd8], 0x7d);
  EXPECT_EQ(r.data[0x200 + 0x108], 0x09);
  // The CRC field holds the payload's CRC; the name, the final bytes' sum.
  Spec s = crc.spec;
  std::uint32_t stored = r.data[0x10] | r.data[0x11] << 8 | r.data[0x12] << 16 | static_cast<std::uint32_t>(r.data[0x13]) << 24;
  EXPECT_EQ(stored, *evaluate(s, r.data));
  char want[64];
  std::snprintf(want, sizeof want, "FW_202401011200_%08llX.bin",
                static_cast<unsigned long long>(compute(Algorithm::sum32, r.data)));
  EXPECT_EQ(r.file_name, want);
  // Every byte but the header's field differs from the original only where patched.
  std::size_t differ = 0;
  for (std::size_t i = 0; i < original.size(); ++i) differ += r.data[i] != original[i];
  EXPECT_LE(differ, 4u + 1u + 4u);

  // Loading the output as the program was loaded gives the patched bytes.
  auto out = std::make_shared<loader::Bytes>(r.data.size());
  for (std::size_t i = 0; i < r.data.size(); ++i) (*out)[i] = static_cast<std::byte>(r.data[i]);
  const loader::Image reloaded = loader::parse_raw(out, raw_options());
  Verification v = verify_export(image, patches, reloaded, r.fixed);
  EXPECT_TRUE(v.ok) << v.detail;
  EXPECT_EQ(v.compared, 0x2000u);
  // A wrong output is caught.
  (*out)[0x200 + 0x40] ^= std::byte{1};
  v = verify_export(image, patches, loader::parse_raw(out, raw_options()), r.fixed);
  EXPECT_FALSE(v.ok);
  EXPECT_EQ(v.first_mismatch, 0x40u);
}

TEST(Export, RefusesPatchesTheFileDoesntBack) {
  auto file = file_bytes(0x1200);
  const loader::Image image = loader::parse_raw(file, raw_options());
  MapResult m = map_to_file(image, {{0x20000010, "x"}});
  EXPECT_TRUE(m.mapped.empty());
  EXPECT_NE(m.error.find("0x20000010"), std::string::npos) << m.error;
  m = map_to_file(image, {{0xfff, "xy"}});  // runs off the end of the image
  EXPECT_FALSE(m.error.empty());
}

TEST(Export, ImageOnlyDropsTheHeader) {
  auto file = file_bytes(0x1200);
  const loader::Image image = loader::parse_raw(file, raw_options());
  MapResult m = map_to_file(image, {{0x10, "AB"}});
  ExportOptions o;
  o.image_only = true;
  o.image_offset = 0x200;
  ExportResult r = build_export(u8(*file), m.mapped, o);
  ASSERT_TRUE(r.error.empty());
  EXPECT_EQ(r.data.size(), 0x1000u);
  EXPECT_EQ(r.data[0x10], 'A');
}

TEST(Export, NameTemplates) {
  EXPECT_EQ(render_name("{NAME}_{SUM:08X}{EXT}", "dir/fw.bin", 0xbeef, 32), "fw_0000BEEF.bin");
  EXPECT_EQ(render_name("{NAME}-{SUM:x}{EXT}", "fw.img", 0xbeef, 32), "fw-beef.img");
  EXPECT_EQ(render_name("", "fw.bin", 1, 32), "fw.bin");
  EXPECT_EQ(template_for("FW_202401011200_1234ABCD.bin", 0x1234ABCD), "FW_202401011200_{SUM:08X}.bin");
  EXPECT_EQ(template_for("x_1234abcd.bin", 0x1234ABCD), "x_{SUM:08x}.bin");
}

}  // namespace
}  // namespace revkit::patch
