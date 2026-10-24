// revkit::nds: ds-decomp's files, the DS ROM format, NARC and the DS
// compressions (docs/nds.md).
#include "revkit/nds/compress.hh"
#include "revkit/nds/dsd.hh"
#include "revkit/nds/rom.hh"

#include "nds_fixture.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <map>

namespace revkit::nds {
namespace {

std::optional<std::filesystem::path> Fixture() {
  return testing::nds_fixture(REVKIT_NDS_PYTHON, REVKIT_NDS_CLANG, REVKIT_NDS_LLD, REVKIT_NDS_FIXTURE);
}

// ---- YAML and config.yaml ---------------------------------------------------

TEST(NdsYaml, MapsSequencesScalarsAndTags) {
  std::string e;
  auto y = parse_yaml(R"(# a comment
name: "quoted # not a comment"
plain: value   # trailing comment
num: 0x1F
list:
  - id: 1
    name: one
  - id: 2
    name: 'it''s'
same_indent:
- a
- b
kind: !Unknown 3
empty: []
nested:
  deeper:
    key: v
)", &e);
  ASSERT_TRUE(y) << e;
  EXPECT_EQ(y->str("name"), "quoted # not a comment");
  EXPECT_EQ(y->str("plain"), "value");
  EXPECT_EQ(y->num("num"), 0x1fu);
  ASSERT_EQ(y->get("list")->seq.size(), 2u);
  EXPECT_EQ(y->get("list")->seq[1].str("name"), "it's");
  EXPECT_EQ(y->get("same_indent")->seq.size(), 2u);
  EXPECT_EQ(y->get("kind")->tag, "Unknown");
  EXPECT_EQ(y->get("kind")->scalar, "3");
  EXPECT_EQ(y->get("empty")->kind, YamlNode::Kind::seq);
  EXPECT_EQ(y->get("nested")->get("deeper")->str("key"), "v");
}

TEST(NdsYaml, RefusesWhatItDoesNotRead) {
  std::string e;
  EXPECT_FALSE(parse_yaml("a: [1, 2]\n", &e));
  EXPECT_FALSE(parse_yaml("a: &x 1\n", &e));
  EXPECT_FALSE(parse_yaml("a: |\n  text\n", &e));
  EXPECT_FALSE(parse_yaml("a:\n\tb: 1\n", &e));
  EXPECT_FALSE(parse_yaml("a: 1\n  b: 2\n", &e));
  // Deep nesting is bounded.
  std::string deep;
  for (int i = 0; i < 200; ++i) deep += std::string(i * 2, ' ') + "k:\n";
  EXPECT_FALSE(parse_yaml(deep, &e));
}

constexpr const char *kConfig = R"(rom_config: ../../extract/config.yaml
build_path: ../../build
delinks_path: ../../build/delinks
main_module:
  name: main
  object: ../../build/arm9.bin
  hash: 0123456789abcdef
  delinks: delinks.txt
  symbols: symbols.txt
  relocations: relocs.txt
autoloads:
  - kind: Itcm
    name: itcm
    object: ../../build/itcm.bin
    hash: 1
    delinks: itcm/delinks.txt
    symbols: itcm/symbols.txt
    relocations: itcm/relocs.txt
  - kind: !Unknown 2
    name: extra
    object: ../../build/extra.bin
    hash: 2
    delinks: extra/delinks.txt
    symbols: extra/symbols.txt
    relocations: extra/relocs.txt
overlays:
  - id: 6
    signed: true
    name: ov006
    object: ../../build/arm9_ov006.bin
    hash: 3
    delinks: overlays/ov006/delinks.txt
    symbols: overlays/ov006/symbols.txt
    relocations: overlays/ov006/relocs.txt
)";

TEST(NdsDsdConfig, Modules) {
  std::string e;
  auto c = parse_dsd_config(kConfig, &e);
  ASSERT_TRUE(c) << e;
  EXPECT_EQ(c->rom_config, "../../extract/config.yaml");
  ASSERT_EQ(c->modules.size(), 4u);
  EXPECT_EQ(c->modules[0].kind, DsdModuleKind::main);
  EXPECT_EQ(c->modules[1].kind, DsdModuleKind::itcm);
  EXPECT_EQ(c->modules[2].kind, DsdModuleKind::autoload);
  EXPECT_EQ(c->modules[2].autoload_index, 2u);
  EXPECT_EQ(c->modules[3].overlay_id, 6);
  EXPECT_TRUE(c->modules[3].signed_overlay);
  EXPECT_EQ(c->overlay(6)->symbols, "overlays/ov006/symbols.txt");
  EXPECT_EQ(c->by_kind(DsdModuleKind::itcm)->name, "itcm");
  EXPECT_FALSE(parse_dsd_config("foo: bar\n", &e));
  EXPECT_FALSE(parse_dsd_config(std::string(kConfig) + "  - id: 6\n    name: again\n    symbols: s\n", &e));
  // A module's name is printed into the backend's records: one with a line
  // break (YAML's "\n" escape) could forge a record's fields, so names
  // with spaces or control characters are refused (bug scrub part 3).
  auto named = [](const std::string &name) {
    std::string c = kConfig;
    c.replace(c.find("name: main"), 10, "name: " + name);
    return c;
  };
  ASSERT_TRUE(parse_dsd_config(named("main2"), &e)) << e;
  EXPECT_FALSE(parse_dsd_config(named("\"x\\nsymbols /etc/passwd\""), &e));
  EXPECT_FALSE(parse_dsd_config(named("\"two words\""), &e));
}

// ---- symbols.txt -------------------------------------------------------------

// A line naming its kind (or address) twice is refused: the second kind
// kept the first's size and was written back as a kind that doesn't parse
// (nds_dsd_fuzzer, bug scrub part 3).
TEST(NdsDsdSymbols, AFieldGivenTwice) {
  const DsdSymbols s = parse_dsd_symbols("v kind:function(arm,size=0) kind:function(arm) addr:0\n"
                                         "w kind:function(arm,size=0x4) addr:0x10 addr:0x20\n"
                                         "ok kind:function(arm,size=0x4) addr:0x30\n");
  ASSERT_EQ(s.symbols.size(), 1u);
  EXPECT_EQ(s.symbols[0].name, "ok");
  EXPECT_EQ(s.errors.size(), 2u);
  const DsdSymbols again = parse_dsd_symbols(format_dsd_symbol(s.symbols[0]));
  ASSERT_EQ(again.symbols.size(), 1u);
  EXPECT_EQ(again.symbols[0].addr, 0x30u);
}

TEST(NdsDsdSymbols, EveryKind) {
  // The kinds and attributes a real project's files use (docs/nds.md).
  const char *text = R"(_ZN13GameOverSceneC1Ev kind:function(arm,size=0x7c) addr:0x02219440
Thumbish kind:function(thumb,size=0x1a) addr:0x02000114 local
// a comment line

OV006_RODATA_START kind:data(any) addr:0x0221a49c
sTable kind:data(word[4]) addr:0x0221a4f0 local // trailing comment
sBytes kind:data(byte[]) addr:0x0221a500
sHalf kind:data(short) addr:0x0221a504 weak
@86 kind:data(any) addr:0x0221a6b4 local
OV006_BSS_START kind:bss addr:0x0221aa40
gBuf kind:bss(size=0x40) addr:0x0221aa60 ambiguous
.L_loop kind:label(arm) addr:0x02219460
func_02000400 kind:function(arm,size=0x10,unknown) addr:0x02000400
bad kind:function(arm) addr:0x1
worse kind:data(float) addr:0x1
noaddr kind:bss
)";
  DsdSymbols s = parse_dsd_symbols(text);
  ASSERT_EQ(s.symbols.size(), 11u);
  EXPECT_EQ(s.errors.size(), 3u);
  const DsdSymbol &f = s.symbols[0];
  EXPECT_EQ(f.kind, DsdSymbolKind::function);
  EXPECT_EQ(f.size, 0x7cu);
  EXPECT_EQ(f.addr, 0x02219440u);
  EXPECT_EQ(s.symbols[1].mode, DsdMode::thumb);
  EXPECT_EQ(s.symbols[1].scope, DsdScope::local);
  EXPECT_EQ(s.symbols[3].count, 4u);
  EXPECT_EQ(s.symbols[3].byte_size(), 16u);
  EXPECT_EQ(s.symbols[3].comment, "trailing comment");
  EXPECT_FALSE(s.symbols[4].count.has_value());
  EXPECT_EQ(s.symbols[5].scope, DsdScope::weak);
  EXPECT_EQ(s.symbols[5].byte_size(), 2u);
  EXPECT_EQ(s.symbols[7].kind, DsdSymbolKind::bss);
  EXPECT_EQ(s.symbols[8].size, 0x40u);
  EXPECT_TRUE(s.symbols[8].ambiguous);
  EXPECT_EQ(s.symbols[9].kind, DsdSymbolKind::label);
  EXPECT_TRUE(s.symbols[10].unknown);
  // Written back as dsd writes them.
  EXPECT_EQ(format_dsd_symbol(s.symbols[0]), "_ZN13GameOverSceneC1Ev kind:function(arm,size=0x7c) addr:0x02219440");
  EXPECT_EQ(format_dsd_symbol(s.symbols[3]), "sTable kind:data(word[4]) addr:0x0221a4f0 local // trailing comment");
  DsdSymbol made;
  made.name = "x";
  made.kind = DsdSymbolKind::data;
  made.data = DsdDataKind::short_;
  made.count = 3;
  made.addr = 0x10;
  EXPECT_EQ(format_dsd_symbol(made), "x kind:data(short[3]) addr:0x00000010");
  made.kind = DsdSymbolKind::function;
  made.mode = DsdMode::thumb;
  made.size = 0x20;
  EXPECT_EQ(format_dsd_symbol(made), "x kind:function(thumb,size=0x20) addr:0x00000010");
}

TEST(NdsDsdSymbols, Names) {
  EXPECT_TRUE(dsd_name_ok("_ZN13GameOverSceneC1Ev"));
  EXPECT_TRUE(dsd_name_ok("@86"));
  EXPECT_TRUE(dsd_name_ok("Foo::Bar"));
  EXPECT_FALSE(dsd_name_ok("Foo::Bar(int)x)"));
  EXPECT_FALSE(dsd_name_ok("two words"));
  EXPECT_FALSE(dsd_name_ok("a//b"));
  EXPECT_FALSE(dsd_name_ok(""));
  EXPECT_TRUE(generated_name("FUN_0200abcd"));
  EXPECT_TRUE(generated_name("func_0200abcd"));
  EXPECT_TRUE(generated_name("func_ov006_0221a000"));
  EXPECT_TRUE(generated_name("DAT_020d433c"));
  EXPECT_FALSE(generated_name("func_Update"));
  EXPECT_FALSE(generated_name("GameOverScene::Update"));
}

// ---- relocs.txt ------------------------------------------------------------------

TEST(NdsDsdRelocs, KindsAndModules) {
  const char *text = R"(from:0x02219450 kind:arm_call to:0x0202236c module:main
from:0x0221948c kind:arm_call to:0x01ff94fc module:itcm
from:0x022194b4 kind:load to:0x0221a6a0 add:0x8 module:overlay(6)
from:0x02000010 kind:arm_call_thumb to:0x02000114 module:main
from:0x02000020 kind:thumb_call_arm to:0x02000000 module:dtcm
from:0x02024f8c kind:arm_call to:0x02219440 module:overlays(0,1,2,3)
from:0x020202e8 kind:link_time_const(ARM9_CTOR_START)
from:0x02000030 kind:arm_branch to:0x02000040 add:-0x4 module:none
from:0x02000040 kind:overlay_id to:0x6
from:0x02000050 kind:load to:0x1 module:autoload(2)
from:0x02000060 kind:load to:0x1
from:0x02000070 kind:jump to:0x1 module:main
from:0x02000080 kind:load to:0x1 module:overlays(1)
)";
  DsdRelocs r = parse_dsd_relocs(text);
  ASSERT_EQ(r.relocs.size(), 10u);
  EXPECT_EQ(r.errors.size(), 3u);
  EXPECT_EQ(r.relocs[0].module.kind, DsdRelocModule::Kind::main);
  EXPECT_TRUE(r.relocs[0].call());
  EXPECT_EQ(r.relocs[1].module.kind, DsdRelocModule::Kind::itcm);
  EXPECT_EQ(r.relocs[2].addend, 8);
  EXPECT_EQ(r.relocs[2].module.ids, std::vector<std::uint16_t>{6});
  EXPECT_FALSE(r.relocs[2].call());
  EXPECT_EQ(r.relocs[3].kind, DsdRelocKind::arm_call_thumb);
  EXPECT_EQ(r.relocs[5].module.kind, DsdRelocModule::Kind::overlays);
  EXPECT_EQ(r.relocs[5].module.ids.size(), 4u);
  EXPECT_EQ(r.relocs[6].kind, DsdRelocKind::link_time_const);
  EXPECT_EQ(r.relocs[6].constant, "ARM9_CTOR_START");
  EXPECT_EQ(r.relocs[7].addend, -4);
  EXPECT_EQ(r.relocs[8].kind, DsdRelocKind::overlay_id);
  EXPECT_EQ(r.relocs[9].module.index, 2u);
}

// ---- delinks.txt -----------------------------------------------------------------

TEST(NdsDsdDelinks, SectionsAndFiles) {
  const char *text = R"(    .text       start:0x02219440 end:0x0221a49c kind:code align:32
    .rodata     start:0x0221a49c end:0x0221a694 kind:rodata align:4
    .ctor       start:0x0221a694 end:0x0221a694 kind:rodata align:4
    .data       start:0x0221a6a0 end:0x0221aa40 kind:data align:32
    .bss        start:0x0221aa40 end:0x0221aa60 kind:bss align:32

// a library, code only
libs/a.c:
    complete
    categories: lib, sdk
    .text       start:0x02219440 end:0x02219500

src/b.cpp:
    .text       start:0x02219500 end:0x0221a49c
    .data       start:0x0221a6a0 end:0x0221aa40
    .weird      start:0x10
)";
  DsdDelinks d = parse_dsd_delinks(text);
  ASSERT_EQ(d.sections.size(), 5u);
  EXPECT_EQ(d.section(".bss")->kind, "bss");
  EXPECT_EQ(d.section(".text")->align, 32u);
  EXPECT_EQ(d.extent(), std::make_pair(0x02219440u, 0x0221aa60u));
  ASSERT_EQ(d.files.size(), 2u);
  EXPECT_EQ(d.files[0].name, "libs/a.c");
  EXPECT_TRUE(d.files[0].complete);
  EXPECT_EQ(d.files[0].categories, (std::vector<std::string>{"lib", "sdk"}));
  EXPECT_FALSE(d.files[1].complete);
  EXPECT_EQ(d.files[1].sections.size(), 2u);
  EXPECT_EQ(d.errors.size(), 1u);
}

// ---- export ---------------------------------------------------------------------------

bool DemangledSame(void *, std::string_view dsd, std::string_view rk) {
  static const std::map<std::string, std::string, std::less<>> kDemangled = {
      {"_ZN13GameOverSceneC1Ev", "GameOverScene::GameOverScene"},
      {"_ZN13GameOverScene6UpdateEv", "GameOverScene::Update"},
  };
  auto it = kDemangled.find(dsd);
  return it != kDemangled.end() && it->second == rk;
}

TEST(NdsDsdExport, RenamesInPlaceAndAddsInOrder) {
  const std::string old = R"(// header comment
_ZN13GameOverSceneC1Ev kind:function(arm,size=0x7c) addr:0x02219440
func_022194bc kind:function(arm,size=0xa0) addr:0x022194bc local // keep me
_ZN13GameOverScene6UpdateEv kind:function(arm,size=0x3b4) addr:0x02219604

data_0221a4f0 kind:data(any) addr:0x0221a4f0
)";
  std::vector<ExportSymbol> rk = {
      {0x02219440, "GameOverScene::GameOverScene", DsdSymbolKind::function, DsdMode::arm, 0x7c},  // demangled: same
      {0x022194bc, "GameOverScene_Dtor", DsdSymbolKind::function, DsdMode::arm, 0xa0},         // renamed
      {0x02219604, "GameOverScene::Update", DsdSymbolKind::function, DsdMode::arm, 0x3b4},      // same
      {0x02219580, "NewThumb", DsdSymbolKind::function, DsdMode::thumb, 0x22},                  // added, in order
      {0x0221a4f0, "sRetryItems", DsdSymbolKind::data, DsdMode::arm, 0, DsdDataKind::word, 4},  // renamed
      {0x0221a600, "sTable", DsdSymbolKind::data, DsdMode::arm, 0, DsdDataKind::any},           // added
      {0x0221a700, "FUN_0221a700", DsdSymbolKind::function, DsdMode::arm, 0x10},                // generated: no
      {0x0221a800, "bad name", DsdSymbolKind::function, DsdMode::arm, 0x10},                    // skipped
      {0x0221a900, "NoSize", DsdSymbolKind::function, DsdMode::arm, 0},                         // skipped
      {0x0221aa40, "gBuffer", DsdSymbolKind::data, DsdMode::arm, 0, DsdDataKind::any, 1, true},  // bss
  };
  SymbolsExport ex = export_dsd_symbols(old, rk, DemangledSame, nullptr);
  EXPECT_EQ(ex.renamed, 2u);
  EXPECT_EQ(ex.added, 3u);
  EXPECT_EQ(ex.skipped, 2u);
  EXPECT_EQ(ex.text, R"(// header comment
_ZN13GameOverSceneC1Ev kind:function(arm,size=0x7c) addr:0x02219440
GameOverScene_Dtor kind:function(arm,size=0xa0) addr:0x022194bc local // keep me
NewThumb kind:function(thumb,size=0x22) addr:0x02219580
_ZN13GameOverScene6UpdateEv kind:function(arm,size=0x3b4) addr:0x02219604

sRetryItems kind:data(any) addr:0x0221a4f0
sTable kind:data(any) addr:0x0221a600
gBuffer kind:bss addr:0x0221aa40
)");
  // Nothing changed: the same text.
  SymbolsExport again = export_dsd_symbols(ex.text, rk, DemangledSame, nullptr);
  EXPECT_EQ(again.text, ex.text);
  EXPECT_EQ(again.renamed + again.added, 0u);
  // The diff.
  const std::string diff = unified_diff(old, ex.text, "a/symbols.txt", "b/symbols.txt");
  EXPECT_NE(diff.find("--- a/symbols.txt\n+++ b/symbols.txt\n@@ -1,6 +1,9 @@\n"), std::string::npos) << diff;
  EXPECT_NE(diff.find("-func_022194bc kind:function(arm,size=0xa0) addr:0x022194bc local // keep me\n"
                      "+GameOverScene_Dtor kind"),
            std::string::npos);
  EXPECT_NE(diff.find("+gBuffer kind:bss addr:0x0221aa40"), std::string::npos);
  EXPECT_EQ(unified_diff(old, old, "a", "b"), "");
}

// ---- compressions -------------------------------------------------------------------

TEST(NdsCompress, HandMadeStreams) {
  // LZ10: "abcabcabc" as 3 literals and a pair (len 6, disp 3).
  const std::vector<std::uint8_t> lz10 = {0x10, 9, 0, 0, 0x10, 'a', 'b', 'c', 0x30, 0x02};
  std::string e;
  auto out = decompress(lz10, 1 << 20, &e);
  ASSERT_TRUE(out) << e;
  EXPECT_EQ(std::string(out->begin(), out->end()), "abcabcabc");
  // RLE: a run of 5 'x' and 2 literals.
  const std::vector<std::uint8_t> rle = {0x30, 7, 0, 0, 0x82, 'x', 0x01, 'y', 'z'};
  out = decompress(rle, 1 << 20, &e);
  ASSERT_TRUE(out) << e;
  EXPECT_EQ(std::string(out->begin(), out->end()), "xxxxxyz");
  // A reference before the start, a size over the limit, truncation.
  EXPECT_FALSE(decompress(std::vector<std::uint8_t>{0x10, 9, 0, 0, 0x80, 0x00, 0x05}, 1 << 20, &e));
  EXPECT_FALSE(decompress(std::vector<std::uint8_t>{0x10, 0xff, 0xff, 0xff, 0}, 1 << 20, &e));
  EXPECT_FALSE(decompress(std::vector<std::uint8_t>{0x11, 9, 0, 0, 0x00, 'a'}, 1 << 20, &e));
  EXPECT_FALSE(decompress(std::vector<std::uint8_t>{0x24, 4, 0, 0, 0x00}, 1 << 20, &e));
  EXPECT_FALSE(compression_header(std::vector<std::uint8_t>{0x40, 1, 0, 0}));
  // BLZ: a footer that claims more than the data has.
  std::vector<std::uint8_t> blz(16, 0);
  blz[8] = 0x40;  // compressed length 0x40 > 16
  blz[11] = 8;
  EXPECT_FALSE(blz_decompress(blz, 1 << 20, &e));
  // A footer claiming 60 MiB more from a 16-byte stream: refused before the
  // output is allocated (bug scrub part 3).
  std::vector<std::uint8_t> bomb(16, 0);
  bomb[8] = 16;  // compressed length 16, header 8
  bomb[11] = 8;
  bomb[12] = 0, bomb[13] = 0, bomb[14] = 0xc0, bomb[15] = 0x03;  // extra 60 MiB
  EXPECT_FALSE(blz_decompress(bomb, 64u << 20, &e));
  EXPECT_NE(e.find("more than its stream can make"), std::string::npos) << e;
}

TEST(NdsCompress, FixtureStreams) {
  auto dir = Fixture();
  if (!dir) GTEST_SKIP() << "no clang/ld.lld/python3 for the DS fixture";
  for (const char *name : {"msg.lz", "tiles.lz11", "rle.bin", "huff.bin"}) {
    std::vector<std::uint8_t> packed = testing::read_bytes(*dir / "packed" / name);
    std::vector<std::uint8_t> plain = testing::read_bytes(*dir / "plain" / name);
    std::string e;
    std::size_t used = 0;
    auto out = decompress(packed, 1 << 24, &e, &used);
    ASSERT_TRUE(out) << name << ": " << e;
    EXPECT_EQ(*out, plain) << name;
    EXPECT_TRUE(looks_compressed(packed, 1 << 24)) << name;
    EXPECT_LE(packed.size() - used, 3u) << name;
  }
  for (const char *name : {"arm9", "ov000"}) {
    std::vector<std::uint8_t> packed = testing::read_bytes(*dir / "packed" / (std::string(name) + ".blz"));
    std::vector<std::uint8_t> plain = testing::read_bytes(*dir / "plain" / (std::string(name) + ".bin"));
    std::string e;
    auto out = blz_decompress(packed, 1 << 24, &e);
    ASSERT_TRUE(out) << name << ": " << e;
    EXPECT_EQ(*out, plain) << name;
    EXPECT_LT(packed.size(), plain.size()) << name;
  }
}

// ---- the ROM ---------------------------------------------------------------------------

TEST(NdsRom, FixtureModulesAndFiles) {
  auto dir = Fixture();
  if (!dir) GTEST_SKIP() << "no clang/ld.lld/python3 for the DS fixture";
  std::vector<std::uint8_t> rom = testing::read_bytes(*dir / "game.nds");
  ASSERT_TRUE(is_nds(rom));
  std::string e;
  auto r = parse_nds(rom, &e);
  ASSERT_TRUE(r) << e;
  EXPECT_EQ(r->header.title, "REVKITTEST");
  EXPECT_EQ(r->header.game_code, "RKTE");
  EXPECT_TRUE(r->header.header_crc_ok);
  EXPECT_FALSE(r->header.logo_crc_ok);
  ASSERT_TRUE(r->params);
  EXPECT_NE(r->params->compressed_static_end, 0u);
  ASSERT_EQ(r->arm9_overlays.size(), 2u);
  EXPECT_TRUE(r->arm9_overlays[0].compressed);
  EXPECT_FALSE(r->arm9_overlays[1].compressed);
  EXPECT_EQ(r->arm9_overlays[0].ram_address, r->arm9_overlays[1].ram_address);
  std::map<std::string, const NdsModule *> by;
  for (const NdsModule &m : r->modules) by[m.name] = &m;
  ASSERT_TRUE(by.count("main") && by.count("itcm") && by.count("dtcm") && by.count("ov000") && by.count("ov001") &&
              by.count("arm7"));
  EXPECT_TRUE(by["main"]->was_compressed);
  EXPECT_EQ(by["main"]->address, 0x02000000u);
  EXPECT_EQ(by["itcm"]->address, 0x01ff8000u);
  EXPECT_EQ(by["dtcm"]->address, 0x027e0000u);
  EXPECT_EQ(by["arm7"]->cpu, NdsCpu::arm7);
  EXPECT_EQ(by["arm7"]->address, 0x037f8000u);
  // Each module as the dsd extract has it (decompressed, autoloads apart).
  EXPECT_EQ(by["main"]->data, testing::read_bytes(*dir / "dsd/extract/arm9/arm9.bin"));
  EXPECT_EQ(by["itcm"]->data, testing::read_bytes(*dir / "dsd/extract/arm9/itcm.bin"));
  EXPECT_EQ(by["dtcm"]->data, testing::read_bytes(*dir / "dsd/extract/arm9/dtcm.bin"));
  EXPECT_EQ(by["ov000"]->data, testing::read_bytes(*dir / "dsd/extract/arm9_overlays/ov000.bin"));
  EXPECT_EQ(by["ov001"]->data, testing::read_bytes(*dir / "dsd/extract/arm9_overlays/ov001.bin"));
  EXPECT_EQ(by["arm7"]->data, testing::read_bytes(*dir / "dsd/extract/arm7/arm7.bin"));
  EXPECT_TRUE(by["ov000"]->was_compressed);
  EXPECT_GT(by["main"]->bss_size, 0u);
  EXPECT_EQ(r->autoloads.size(), 2u);
  // NitroFS.
  std::map<std::string, const NdsFile *> files;
  for (const NdsFile &f : r->files)
    if (!f.path.empty()) files[f.path] = &f;
  for (const char *p : {"/data/msg.lz", "/data/huff.bin", "/data/pack.narc", "/data/sub/tiles.lz11", "/data/sub/rle.bin"})
    EXPECT_TRUE(files.count(p)) << p;
  ASSERT_GE(r->files.size(), 7u);
  EXPECT_TRUE(r->files[0].path.empty());  // the overlays' files have no names
  EXPECT_EQ(r->directories.size(), 3u);
  // The NARC inside.
  const NdsFile &n = *files["/data/pack.narc"];
  std::span<const std::uint8_t> narc_bytes(rom.data() + n.start, n.end - n.start);
  ASSERT_TRUE(is_narc(narc_bytes));
  auto narc = parse_narc(narc_bytes, &e);
  ASSERT_TRUE(narc) << e;
  std::map<std::string, NarcFile> nf;
  for (const NarcFile &f : narc->files) nf[f.path] = f;
  ASSERT_TRUE(nf.count("/readme.txt") && nf.count("/gfx/pal.bin") && nf.count("/gfx/chr.bin"));
  EXPECT_EQ(std::string(narc_bytes.begin() + nf["/readme.txt"].offset,
                        narc_bytes.begin() + nf["/readme.txt"].offset + nf["/readme.txt"].size),
            "inside a NARC\n");
  EXPECT_EQ(nf["/gfx/pal.bin"].size, 32u);
}

// Bug scrub part 3: overlays naming one file read it once (8,192 of them
// would each decompress it before the size limit was checked).
TEST(NdsRom, OverlaysSharingAFile) {
  auto dir = Fixture();
  if (!dir) GTEST_SKIP() << "no clang/ld.lld/python3 for the DS fixture";
  std::vector<std::uint8_t> b = testing::read_bytes(*dir / "game.nds");
  auto le32 = [&](std::size_t o) { return b[o] | b[o + 1] << 8 | b[o + 2] << 16 | std::uint32_t{b[o + 3]} << 24; };
  const std::uint32_t table = le32(0x50), size = le32(0x54);
  ASSERT_GE(size, 64u);
  for (int i = 0; i < 4; ++i) b[table + 32 + 24 + i] = b[table + 24 + i];  // the second overlay's file: the first's
  const std::uint16_t crc = crc16(std::span<const std::uint8_t>(b.data(), 0x15e));
  b[0x15e] = crc & 0xff;
  b[0x15f] = crc >> 8;
  std::string e;
  auto r = parse_nds(b, &e);
  ASSERT_TRUE(r) << e;
  EXPECT_TRUE(std::any_of(r->warnings.begin(), r->warnings.end(),
                          [](const std::string &w) { return w.find("another overlay's") != std::string::npos; }));
  EXPECT_EQ(std::count_if(r->modules.begin(), r->modules.end(), [](const NdsModule &m) { return m.overlay_id >= 0; }), 1);
}

TEST(NdsRom, Hostile) {
  std::string e;
  EXPECT_FALSE(parse_nds(std::vector<std::uint8_t>(0x100, 0), &e));
  // A valid header CRC over offsets past the file.
  std::vector<std::uint8_t> h(0x200, 0);
  h[0x20] = 0x00;
  h[0x21] = 0x40;  // ARM9 at 0x4000, past the 0x200-byte file
  h[0x2c] = 0x10;
  const std::uint16_t crc = crc16(std::span<const std::uint8_t>(h.data(), 0x15e));
  h[0x15e] = crc & 0xff;
  h[0x15f] = crc >> 8;
  EXPECT_FALSE(parse_nds(h, &e));
  EXPECT_NE(e.find("past the file"), std::string::npos) << e;
  // A NitroFS whose directories loop and run past the table.
  std::vector<std::uint8_t> fnt = {16, 0, 0, 0, 0, 0, 2, 0, 16, 0, 0, 0, 0, 0, 0, 0xf0, 0x81, 'a', 0x01, 0xf0, 0};
  std::vector<std::uint8_t> fat(8, 0);
  std::vector<NdsFile> files;
  std::vector<NdsDirectory> dirs;
  std::vector<std::string> warnings;
  parse_nitrofs(fnt, fat, files, dirs, warnings, 100);
  EXPECT_LE(dirs.size(), 2u);
  EXPECT_FALSE(parse_narc(std::vector<std::uint8_t>{'N', 'A', 'R', 'C', 0xfe, 0xff, 0, 1, 0xff, 0xff, 0, 0, 16, 0, 1, 0}, &e));
  // A NARC with an allocation table but no image block: its files' offsets
  // were counted from a null pointer (nds_narc_fuzzer, bug scrub part 3).
  std::vector<std::uint8_t> narc = {'N', 'A', 'R', 'C', 0xfe, 0xff, 0, 1, 40, 0, 0, 0, 16, 0, 1, 0,
                                    'B', 'T', 'A', 'F', 24, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0};
  narc.resize(40);
  EXPECT_FALSE(parse_narc(narc, &e));
  EXPECT_NE(e.find("GMIF"), std::string::npos) << e;
}

}  // namespace
}  // namespace revkit::nds
