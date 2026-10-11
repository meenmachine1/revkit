#include "revkit/plugins/abi.h"
#include "revkit/plugins/manifest.h"

#include <gtest/gtest.h>

namespace revkit::plugins {
namespace {

std::string error_of(const std::string &json) {
  try {
    parse_manifest(json);
  } catch (const ManifestError &e) {
    return e.what();
  }
  return "";
}

TEST(Manifest, ParsesEveryField) {
  Manifest m = parse_manifest(R"({
    "name": "rename-regex", "version": "1.2.3-beta.1", "kind": "command", "interface": 1,
    "description": "Renames \"things\" é",
    "capabilities": ["code", "memory"],
    "command": {"args": [{"name": "pattern", "required": true, "description": "re"}, {"name": "limit"}]},
    "limits": {"fuel": 1000, "memory_mb": 8}
  })");
  EXPECT_EQ(m.id(), "rename-regex@1.2.3-beta.1");
  EXPECT_EQ(m.kind, Kind::command);
  EXPECT_EQ(m.interface_version, 1u);
  EXPECT_EQ(m.description, "Renames \"things\" \xc3\xa9");
  EXPECT_EQ(m.capabilities, (std::set<Capability>{Capability::code, Capability::memory}));
  ASSERT_EQ(m.args.size(), 2u);
  EXPECT_TRUE(m.args[0].required);
  EXPECT_FALSE(m.args[1].required);
  EXPECT_EQ(m.fuel, 1000u);
  EXPECT_EQ(m.memory_bytes, 8u << 20);

  Manifest l = parse_manifest(R"({"name": "raw", "version": "0.1.0", "kind": "loader", "interface": 1,
                                  "loader": {"magic": "7f454C46", "offset": 2}})");
  EXPECT_EQ(l.magic, std::string("\x7f" "ELF"));
  EXPECT_EQ(l.magic_offset, 2u);
  Manifest a = parse_manifest(R"({"name": "a", "version": "1.0.0", "kind": "analyzer", "interface": 1,
                                  "analyzer": {"scope": "function"}})");
  EXPECT_TRUE(a.function_scope);
}

TEST(Manifest, RejectsWhatItDoesntUnderstand) {
  const std::string base = R"("name": "x", "version": "1.0.0", "kind": "analyzer", "interface": 1)";
  EXPECT_NE(error_of("{" + base + R"(, "capabilites": []})").find("unknown field \"capabilites\""), std::string::npos);
  EXPECT_NE(error_of("{" + base + R"(, "capabilities": ["network"]})").find("unknown capability"), std::string::npos);
  EXPECT_NE(error_of(R"({"name": "X!", "version": "1.0.0", "kind": "analyzer", "interface": 1})").find("name"),
            std::string::npos);
  EXPECT_NE(error_of(R"({"name": "x", "version": "1.0", "kind": "analyzer", "interface": 1})").find("version"),
            std::string::npos);
  EXPECT_NE(error_of(R"({"name": "x", "version": "1.0.0", "kind": "daemon", "interface": 1})").find("kind"),
            std::string::npos);
  EXPECT_NE(error_of(R"({"name": "x", "version": "1.0.0", "kind": "analyzer"})").find("interface"), std::string::npos);
  EXPECT_NE(error_of("{" + base + R"(, "loader": {"magic": "00"}})").find("another kind"), std::string::npos);
  EXPECT_NE(error_of(R"({"name": "x", "version": "1.0.0", "kind": "loader", "interface": 1})").find("magic"),
            std::string::npos);
  EXPECT_NE(error_of("{" + base + ", " + base + "}").find("duplicate key"), std::string::npos);
  EXPECT_NE(error_of("{" + base + "} trailing").find("trailing"), std::string::npos);
  EXPECT_NE(error_of("{" + base + R"(, "limits": {"fuel": 1.5}})").find("integers"), std::string::npos);
  EXPECT_NE(error_of(std::string(100, '[')).find("too deep"), std::string::npos);
}

TEST(Abi, RecordsSkipFieldsTheyDontKnow) {
  // A newer writer appends a field to a record; an older reader still reads
  // what follows the record correctly.
  abi::Writer w;
  auto list = w.begin();
  for (int i = 0; i < 2; ++i) {
    auto rec = w.begin();
    w.u64(100 + i);
    w.str("name");
    w.u32(0xdeadbeef);  // the new field
    w.end_record(rec);
  }
  w.end_list(list, 2);
  w.str("after");
  abi::Reader r(w.bytes());
  ASSERT_EQ(r.list(), 2u);
  for (int i = 0; i < 2; ++i) {
    abi::Reader rec = r.record();
    EXPECT_EQ(rec.u64(), 100u + i);
    EXPECT_EQ(rec.str(), "name");
  }
  EXPECT_EQ(r.str(), "after");
  EXPECT_TRUE(r.done());
}

TEST(Abi, TruncatedOrLyingBlobsThrow) {
  const std::string truncated("\x05\x00\x00\x00" "ab", 6), lying("\xff\xff\xff\x7f", 4);
  abi::Reader short_read(truncated);
  EXPECT_THROW(short_read.str(), abi::AbiError);
  abi::Reader liar(lying);
  EXPECT_THROW(liar.list(4), abi::AbiError);
}

}  // namespace
}  // namespace revkit::plugins
