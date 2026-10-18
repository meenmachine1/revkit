// The Mach-O loader on tests/data/macho's fixtures (built at test time by
// build.sh with clang and ld64.lld; the tests skip without them), checked
// against llvm-nm's and llvm-objdump's accounts of the same files; and on
// small hand-built files for what lld doesn't write (arm64e chained
// fixups, encryption) and for malformed input.
#include "macho_fixture.h"

#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>

namespace revkit::loader {
namespace {

using macho_testing::Fixtures;

const Fixtures *fx() {
  const auto &f = macho_testing::fixtures(REVKIT_TEST_CLANG, REVKIT_TEST_LD64, REVKIT_TEST_LIPO, REVKIT_TEST_NM,
                                          REVKIT_TEST_OBJDUMP, REVKIT_MACHO_FIXTURE);
  return f ? &*f : nullptr;
}

#define NEED_FIXTURES()                                                                 \
  const Fixtures *F = fx();                                                             \
  if (F == nullptr) GTEST_SKIP() << "clang, ld64.lld or llvm tools missing, or the fixtures didn't build"

const Symbol *find_symbol(const Image &img, std::string_view name, bool defined = true) {
  for (const Symbol &s : img.symbols)
    if (s.name == name && s.defined == defined) return &s;
  return nullptr;
}

const Block *find_block(const Image &img, std::string_view name) {
  for (const Block &b : img.blocks)
    if (b.name == name) return &b;
  return nullptr;
}

// The relocation at `a`: a rebase (`bound` false) or a bind (a lazy
// pointer has both: its stub helper's address, and its symbol).
const Relocation *reloc_at(const Image &img, std::uint64_t a, bool bound = false) {
  for (const Relocation &r : img.relocations)
    if (r.address == a && r.symbol.empty() != bound) return &r;
  return nullptr;
}

// Every symbol llvm-nm lists is the loader's, at the same address; every
// fixup llvm-objdump lists is a relocation of the right kind.
void check_against_tools(const Fixtures &f, const std::string &name, const Image &img) {
  for (const auto &[sym, addr] : f.symbols(name)) {
    const Symbol *s = find_symbol(img, sym);
    ASSERT_NE(s, nullptr) << name << ": " << sym;
    EXPECT_EQ(s->value & ~std::uint64_t{1}, addr) << name << ": " << sym;
  }
  for (const std::string &sym : f.undefined(name)) EXPECT_NE(find_symbol(img, sym, false), nullptr) << name << ": " << sym;
  const auto fixups = f.fixups(name);
  EXPECT_FALSE(fixups.empty()) << name;
  for (const auto &x : fixups) {
    const Relocation *r = reloc_at(img, x.address, x.kind != "rebase");
    ASSERT_NE(r, nullptr) << name << ": " << x.kind << " at 0x" << std::hex << x.address;
    if (x.kind == "rebase") {
      EXPECT_EQ(r->kind, RelocationKind::relative) << name << " 0x" << std::hex << x.address;
      ASSERT_TRUE(r->target);
      if (x.target != 0) {
        EXPECT_EQ(*r->target, x.target) << name << " 0x" << std::hex << x.address;
      }
    } else {
      EXPECT_EQ(r->symbol, x.symbol) << name << " 0x" << std::hex << x.address;
      EXPECT_EQ(r->kind, x.kind == "lazy" ? RelocationKind::jump_slot : RelocationKind::glob_dat);
      auto imp = std::find_if(img.imports.begin(), img.imports.end(),
                              [&](const Import &i) { return i.iat_address == x.address; });
      ASSERT_NE(imp, img.imports.end());
      EXPECT_EQ(imp->name, x.symbol);
      EXPECT_NE(imp->library.find(x.dylib), std::string::npos) << imp->library << " vs " << x.dylib;
    }
  }
}

TEST(Macho, LoadsArm64WithDyldInfo) {
  NEED_FIXTURES();
  const Image img = load_file(F->path("hello-arm64"));
  ASSERT_TRUE(img.macho);
  const MachoInfo &m = *img.macho;
  EXPECT_EQ(img.format, Format::macho);
  EXPECT_EQ(img.bits, 64u);
  EXPECT_EQ(img.endian, Endian::little);
  EXPECT_EQ(img.machine, 0x0100000cu);
  EXPECT_EQ(m.arch, "arm64");
  EXPECT_EQ(m.filetype, 2u);
  EXPECT_TRUE(m.slices.empty());
  EXPECT_EQ(img.image_base, 0x100000000u);
  EXPECT_TRUE(img.warnings.empty()) << img.warnings.front();

  const auto syms = F->symbols("hello-arm64");
  ASSERT_TRUE(img.entry);
  EXPECT_EQ(*img.entry, syms.at("_main"));  // LC_MAIN

  // Ghidra's blocks: the header's part of __TEXT, each section, __LINKEDIT.
  ASSERT_NE(find_block(img, "__TEXT"), nullptr);
  EXPECT_EQ(find_block(img, "__TEXT")->start, 0x100000000u);
  const Block *text = find_block(img, "__text");
  ASSERT_NE(text, nullptr);
  EXPECT_EQ(text->perms.str(), "r-x");
  EXPECT_EQ(find_block(img, "__stubs")->perms.str(), "r-x");
  EXPECT_EQ(find_block(img, "__cstring")->perms.str(), "r--");
  EXPECT_EQ(find_block(img, "__got")->perms.str(), "rw-");
  EXPECT_EQ(find_block(img, "__la_symbol_ptr")->perms.str(), "rw-");
  EXPECT_EQ(find_block(img, "__data")->perms.str(), "rw-");
  ASSERT_NE(find_block(img, "__LINKEDIT"), nullptr);
  EXPECT_EQ(find_block(img, "__LINKEDIT")->perms.str(), "r--");
  // lld pads __DATA's file bytes to the page, so its zero-fill __common is
  // in them: initialized, as Ghidra leaves a section inside file bytes.
  ASSERT_NE(find_block(img, "__common"), nullptr);
  for (std::size_t i = 1; i < img.blocks.size(); ++i)
    EXPECT_LE(img.blocks[i - 1].start + img.blocks[i - 1].size, img.blocks[i].start);

  // The header's magic is readable at the image base.
  std::array<std::byte, 4> magic{};
  ASSERT_EQ(img.memory.read(img.image_base, magic), 4u);
  EXPECT_EQ(magic[0], std::byte{0xcf});

  const Section *stubs = find_section(img, "__stubs");
  ASSERT_NE(stubs, nullptr);
  EXPECT_EQ(stubs->segment, "__TEXT");
  EXPECT_EQ(stubs->type, 8u);
  EXPECT_EQ(stubs->entsize, 12u);
  ASSERT_EQ(img.plt_sections.size(), 1u);
  EXPECT_EQ(img.plt_sections[0].start, stubs->addr);
  EXPECT_EQ(img.plt_sections[0].entry_size, 12u);
  ASSERT_EQ(m.stub_names.size(), 2u);
  EXPECT_EQ(m.stub_names.begin()->first, stubs->addr);

  check_against_tools(*F, "hello-arm64", img);
  const Symbol *twice = find_symbol(img, "_twice");
  ASSERT_NE(twice, nullptr);
  EXPECT_EQ(twice->type, SymbolType::func);
  EXPECT_EQ(twice->bind, SymbolBind::local);
  EXPECT_EQ(find_symbol(img, "_main")->bind, SymbolBind::global);
  EXPECT_EQ(find_symbol(img, "_table")->type, SymbolType::object);
  // In __TEXT's executable header part, but in no section of code.
  EXPECT_EQ(find_symbol(img, "__mh_execute_header")->type, SymbolType::object);

  // Classic rebases hold their target already.
  const Relocation *table = reloc_at(img, syms.at("_table"));
  ASSERT_NE(table, nullptr);
  EXPECT_EQ(*table->target, syms.at("_add"));

  // Exports: the trie, at their symbols' addresses.
  auto exported = [&](std::string_view n) {
    auto it = std::find_if(img.exports.begin(), img.exports.end(), [&](const Export &e) { return e.name == n; });
    return it == img.exports.end() ? std::optional<std::uint64_t>() : std::optional<std::uint64_t>(it->address);
  };
  EXPECT_EQ(exported("_main"), syms.at("_main"));
  EXPECT_EQ(exported("_add"), syms.at("_add"));
  EXPECT_EQ(exported("__mh_execute_header"), 0x100000000u);
  EXPECT_FALSE(exported("_twice"));

  // Function starts: every function, sorted.
  for (const char *fn : {"_add", "_main", "_twice"})
    EXPECT_TRUE(std::binary_search(m.function_starts.begin(), m.function_starts.end(), syms.at(fn))) << fn;

  // Libraries and metadata.
  EXPECT_EQ(img.needed, std::vector<std::string>{"/usr/lib/libSystem.B.dylib"});
  ASSERT_EQ(m.dylibs.size(), 1u);
  EXPECT_EQ(m.dylibs[0].kind, "load");
  EXPECT_EQ(m.dylinker, "/usr/lib/dyld");
  EXPECT_EQ(m.uuid.size(), 36u);
  EXPECT_EQ(img.build_id.size(), 32u);
  EXPECT_EQ(m.platform, "macos");
  EXPECT_EQ(m.min_os, "11.0");
  EXPECT_EQ(m.sdk, "11.0");
  EXPECT_TRUE(m.code_signature);
  EXPECT_FALSE(m.encrypted);
  EXPECT_TRUE(m.dyld_info);
  EXPECT_FALSE(m.chained_fixups);
  EXPECT_EQ(relocation_type_name(img, table->type), "REBASE_TYPE_POINTER");

  auto lang = guess_language(img);
  ASSERT_TRUE(lang);
  EXPECT_EQ(lang->id(), "AARCH64:LE:64:AppleSilicon:default");
}

TEST(Macho, LoadsChainedFixups) {
  NEED_FIXTURES();
  for (const char *name : {"hello-arm64-chained", "hello-x86_64-chained"}) {
    SCOPED_TRACE(name);
    const Image img = load_file(F->path(name));
    ASSERT_TRUE(img.macho);
    EXPECT_TRUE(img.macho->chained_fixups);
    EXPECT_EQ(img.macho->chained_pointer_format, 2u);  // DYLD_CHAINED_PTR_64
    EXPECT_TRUE(img.warnings.empty()) << img.warnings.front();
    check_against_tools(*F, name, img);
    const auto syms = F->symbols(name);
    const Relocation *table = reloc_at(img, syms.at("_table"));
    ASSERT_NE(table, nullptr);
    EXPECT_EQ(*table->target, syms.at("_add"));
    EXPECT_EQ(relocation_type_name(img, table->type), "DYLD_CHAINED_PTR_64");
  }
}

TEST(Macho, LoadsX86_64) {
  NEED_FIXTURES();
  const Image img = load_file(F->path("hello-x86_64"));
  ASSERT_TRUE(img.macho);
  EXPECT_EQ(img.macho->arch, "x86_64");
  EXPECT_EQ(img.machine, 0x01000007u);
  check_against_tools(*F, "hello-x86_64", img);
  const Section *stubs = find_section(img, "__stubs");
  ASSERT_NE(stubs, nullptr);
  EXPECT_EQ(stubs->entsize, 6u);
  EXPECT_EQ(guess_language(img)->id(), "x86:LE:64:default:gcc");
  ASSERT_TRUE(img.entry);
  EXPECT_EQ(*img.entry, F->symbols("hello-x86_64").at("_main"));
}

TEST(Macho, NamesArchitectures) {
  EXPECT_EQ(macho_arch_name(0x0100000c, 0x80000002), "arm64e");  // with the ptrauth ABI bit
  EXPECT_EQ(macho_arch_name(0x0100000c, 0), "arm64");
  EXPECT_EQ(macho_arch_name(0x01000007, 3), "x86_64");
  EXPECT_EQ(macho_arch_name(0x01000007, 8), "x86_64h");
  EXPECT_EQ(macho_arch_name(7, 3), "i386");
  EXPECT_EQ(macho_arch_name(12, 9), "armv7");
  EXPECT_EQ(macho_arch_name(12, 11), "armv7s");
  EXPECT_EQ(macho_arch_name(18, 0), "ppc");
}

TEST(Macho, LoadsArm64_32) {
  NEED_FIXTURES();
  const Image w = load_file(F->path("hello-arm64_32"));
  EXPECT_EQ(w.bits, 32u);
  EXPECT_EQ(w.macho->arch, "arm64_32");
  EXPECT_EQ(guess_language(w)->id(), "AARCH64:LE:32:ilp32:default");
  EXPECT_EQ(w.macho->platform, "watchos");
  EXPECT_EQ(w.macho->min_os, "5.0");
  check_against_tools(*F, "hello-arm64_32", w);
  EXPECT_EQ(find_section(w, "__stubs")->entsize, 12u);
}

TEST(Macho, ChoosesUniversalSlices) {
  NEED_FIXTURES();
  const auto bytes = [&] {
    std::ifstream in(F->path("hello-fat"), std::ios::binary);
    std::vector<char> v((std::istreambuf_iterator<char>(in)), {});
    auto b = std::make_shared<Bytes>(v.size());
    std::memcpy(b->data(), v.data(), v.size());
    return b;
  }();
  const std::vector<MachoSlice> slices = macho_slices(*bytes);
  ASSERT_EQ(slices.size(), 2u);
  EXPECT_EQ(slices[0].arch, "x86_64");
  EXPECT_EQ(slices[1].arch, "arm64");
  EXPECT_EQ(macho_default_slice(slices), 1u);
  EXPECT_TRUE(is_macho(*bytes));

  // By default, arm64; its addresses and bytes are the thin file's.
  const Image arm = parse(bytes);
  ASSERT_TRUE(arm.macho);
  EXPECT_EQ(arm.macho->arch, "arm64");
  EXPECT_EQ(arm.macho->slice, 1u);
  EXPECT_EQ(arm.macho->slice_offset, slices[1].offset);
  EXPECT_EQ(arm.macho->slices, slices);
  const Image thin = load_file(F->path("hello-arm64"));
  EXPECT_EQ(arm.entry, thin.entry);
  ASSERT_EQ(arm.blocks.size(), thin.blocks.size());
  std::array<std::byte, 64> a{}, b{};
  const Block *text = find_block(arm, "__text");
  arm.memory.read(text->start, a);
  thin.memory.read(text->start, b);
  EXPECT_EQ(a, b);
  const Section *s = find_section(arm, "__text");
  EXPECT_EQ(section_bytes(arm, *s).size(), s->size);
  EXPECT_EQ(std::memcmp(section_bytes(arm, *s).data(), a.data(), 32), 0);
  check_against_tools(*F, "hello-arm64", arm);

  LoadOptions o;
  o.macho_slice = "x86_64";
  EXPECT_EQ(parse(bytes, o).macho->arch, "x86_64");
  o.macho_slice = "#0";
  EXPECT_EQ(parse(bytes, o).macho->arch, "x86_64");
  o.macho_slice = "ppc";
  try {
    parse(bytes, o);
    FAIL() << "loaded a slice that isn't there";
  } catch (const LoadError &e) {
    EXPECT_NE(std::string(e.what()).find("x86_64, arm64"), std::string::npos) << e.what();
  }
}

TEST(Macho, LoadsObjectFiles) {
  NEED_FIXTURES();
  const Image arm = load_file(F->path("hello-armv7.o"));
  EXPECT_EQ(arm.bits, 32u);
  EXPECT_EQ(arm.macho->filetype, 1u);  // MH_OBJECT
  EXPECT_EQ(arm.macho->arch, "armv7");
  EXPECT_EQ(guess_language(arm)->id(), "ARM:LE:32:v8:default");
  const Symbol *main = find_symbol(arm, "_main");
  ASSERT_NE(main, nullptr);
  EXPECT_EQ(main->value & 1, 1u);  // Thumb (N_ARM_THUMB_DEF)
  EXPECT_NE(find_block(arm, "__text"), nullptr);

  const Image x86 = load_file(F->path("hello-i386.o"));
  EXPECT_EQ(x86.bits, 32u);
  EXPECT_EQ(guess_language(x86)->id(), "x86:LE:32:default:gcc");
  EXPECT_NE(find_symbol(x86, "_main"), nullptr);
}

TEST(Macho, RebasesTheImage) {
  NEED_FIXTURES();
  LoadOptions o;
  o.image_base = 0x200000000;
  const Image img = load_file(F->path("hello-arm64-chained"), o);
  const auto syms = F->symbols("hello-arm64-chained");
  const std::uint64_t delta = 0x100000000;
  EXPECT_EQ(img.image_base, 0x200000000u);
  EXPECT_EQ(img.file_base, 0x100000000u);
  EXPECT_EQ(*img.entry, syms.at("_main") + delta);
  EXPECT_EQ(find_symbol(img, "_add")->value, syms.at("_add") + delta);
  const Relocation *table = reloc_at(img, syms.at("_table") + delta);
  ASSERT_NE(table, nullptr);
  EXPECT_EQ(*table->target, syms.at("_add") + delta);
  EXPECT_EQ(find_block(img, "__TEXT")->start, 0x200000000u);

  const Image classic = load_file(F->path("hello-arm64"), o);
  const auto csyms = F->symbols("hello-arm64");
  const Relocation *ct = reloc_at(classic, csyms.at("_table") + delta);
  ASSERT_NE(ct, nullptr);
  EXPECT_EQ(*ct->target, csyms.at("_add") + delta);
}

TEST(Macho, ReadsDylibsAndRpaths) {
  NEED_FIXTURES();
  const Image lib = load_file(F->path("libgreet.dylib"));
  EXPECT_EQ(lib.macho->filetype, 6u);  // MH_DYLIB
  EXPECT_EQ(lib.soname, "@rpath/libgreet.dylib");
  EXPECT_EQ(lib.macho->install_name, "@rpath/libgreet.dylib");
  const auto syms = F->symbols("libgreet.dylib");
  auto exp = std::find_if(lib.exports.begin(), lib.exports.end(), [](const Export &e) { return e.name == "_greet"; });
  ASSERT_NE(exp, lib.exports.end());
  EXPECT_EQ(exp->address, syms.at("_greet"));
  check_against_tools(*F, "libgreet.dylib", lib);

  const Image prog = load_file(F->path("uses-greet"));
  EXPECT_EQ(prog.needed, (std::vector<std::string>{"@rpath/libgreet.dylib", "/usr/lib/libSystem.B.dylib"}));
  EXPECT_EQ(prog.runpath, std::vector<std::string>{"@loader_path"});
  check_against_tools(*F, "uses-greet", prog);
  auto greet = std::find_if(prog.imports.begin(), prog.imports.end(), [](const Import &i) { return i.name == "_greet"; });
  ASSERT_NE(greet, prog.imports.end());
  EXPECT_EQ(greet->library, "@rpath/libgreet.dylib");
}

TEST(Macho, LoadsObjectiveC) {
  NEED_FIXTURES();
  const Image img = load_file(F->path("objc-arm64"));
  check_against_tools(*F, "objc-arm64", img);
  EXPECT_NE(find_section(img, "__objc_classlist"), nullptr);
  EXPECT_NE(find_symbol(img, "-[Point sum]"), nullptr);
  EXPECT_EQ(img.needed, (std::vector<std::string>{"/usr/lib/libobjc.A.dylib", "/usr/lib/libSystem.B.dylib"}));
}

// ---- hand-built files ----

struct Builder {
  std::vector<std::uint8_t> b;
  void put(std::size_t at, std::uint64_t v, unsigned n) {
    if (b.size() < at + n) b.resize(at + n);
    for (unsigned i = 0; i < n; ++i) b[at + i] = static_cast<std::uint8_t>(v >> (8 * i));
  }
  void str(std::size_t at, std::string_view s, std::size_t n) {
    if (b.size() < at + n) b.resize(at + n);
    for (std::size_t i = 0; i < n; ++i) b[at + i] = i < s.size() ? static_cast<std::uint8_t>(s[i]) : 0;
  }
  std::shared_ptr<Bytes> bytes() const {
    auto out = std::make_shared<Bytes>(b.size());
    for (std::size_t i = 0; i < b.size(); ++i) (*out)[i] = std::byte{b[i]};
    return out;
  }
};

// A 64-bit arm64 executable: __TEXT (0x100000000, the header and __text
// at 0x1000), __DATA (0x100004000, __data), __LINKEDIT (file 0x5000), and
// whatever load commands `extra` adds after the segments. Returns the
// offset where the next load command goes.
struct Mini {
  Builder m;
  std::size_t lc = 32;
  std::uint32_t ncmds = 0;

  Mini() {
    m.put(0, 0xfeedfacf, 4);
    m.put(4, 0x0100000c, 4);
    m.put(8, 0, 4);
    m.put(12, 2, 4);  // MH_EXECUTE
    segment("__TEXT", 0x100000000, 0x4000, 0, 0x4000, 5, "__text", 0x100001000, 0x100, 0x1000, 0x80000400);
    segment("__DATA", 0x100004000, 0x1000, 0x4000, 0x1000, 3, "__data", 0x100004000, 0x100, 0x4000, 0);
    segment("__LINKEDIT", 0x100005000, 0x1000, 0x5000, 0x1000, 1, "", 0, 0, 0, 0);
    m.put(0x5fff, 0, 1);
  }
  void segment(std::string_view name, std::uint64_t vm, std::uint64_t vmsize, std::uint64_t off, std::uint64_t fsize,
               std::uint32_t prot, std::string_view sect, std::uint64_t saddr, std::uint64_t ssize, std::uint32_t soff,
               std::uint32_t sflags) {
    const bool has = !sect.empty();
    const std::uint32_t size = 72 + (has ? 80 : 0);
    m.put(lc, 0x19, 4);
    m.put(lc + 4, size, 4);
    m.str(lc + 8, name, 16);
    m.put(lc + 24, vm, 8);
    m.put(lc + 32, vmsize, 8);
    m.put(lc + 40, off, 8);
    m.put(lc + 48, fsize, 8);
    m.put(lc + 56, prot, 4);
    m.put(lc + 60, prot, 4);
    m.put(lc + 64, has ? 1 : 0, 4);
    if (has) {
      const std::size_t s = lc + 72;
      m.str(s, sect, 16);
      m.str(s + 16, name, 16);
      m.put(s + 32, saddr, 8);
      m.put(s + 40, ssize, 8);
      m.put(s + 48, soff, 4);
      m.put(s + 64, sflags, 4);
    }
    end_command(size);
  }
  void end_command(std::uint32_t size) {
    lc += size;
    ++ncmds;
    m.put(16, ncmds, 4);
    m.put(20, lc - 32, 4);
  }
  void command(std::uint32_t cmd, std::vector<std::uint32_t> words) {
    m.put(lc, cmd, 4);
    m.put(lc + 4, 8 + 4 * words.size(), 4);
    for (std::size_t i = 0; i < words.size(); ++i) m.put(lc + 8 + 4 * i, words[i], 4);
    end_command(static_cast<std::uint32_t>(8 + 4 * words.size()));
  }
  void dylib(std::string_view name) {
    const std::uint32_t size = static_cast<std::uint32_t>((24 + name.size() + 1 + 7) / 8 * 8);
    m.put(lc, 0xc, 4);
    m.put(lc + 4, size, 4);
    m.put(lc + 8, 24, 4);
    m.str(lc + 24, name, size - 24);
    end_command(size);
  }
};

TEST(Macho, DecodesArm64eChainedFixups) {
  Mini mini;
  mini.dylib("/usr/lib/libext.dylib");
  // The fixups blob at __LINKEDIT's start (file 0x5000): the header, the
  // starts in image (3 segments), __DATA's starts (ARM64E_USERLAND, one
  // page), one import and its name.
  Builder &m = mini.m;
  const std::size_t h = 0x5000;
  m.put(h, 0, 4);
  m.put(h + 4, 32, 4);   // starts_offset
  m.put(h + 8, 72, 4);   // imports_offset
  m.put(h + 12, 76, 4);  // symbols_offset
  m.put(h + 16, 1, 4);   // imports_count
  m.put(h + 20, 1, 4);   // DYLD_CHAINED_IMPORT
  m.put(h + 24, 0, 4);
  m.put(h + 32, 3, 4);  // seg_count
  m.put(h + 36, 0, 4);
  m.put(h + 40, 16, 4);  // __DATA's starts at starts + 16
  m.put(h + 44, 0, 4);
  const std::size_t ss = h + 48;
  m.put(ss, 24, 4);
  m.put(ss + 4, 0x1000, 2);
  m.put(ss + 6, 9, 2);  // DYLD_CHAINED_PTR_ARM64E_USERLAND
  m.put(ss + 8, 0x4000, 8);
  m.put(ss + 16, 0, 4);
  m.put(ss + 20, 1, 2);
  m.put(ss + 22, 0, 2);
  m.put(h + 72, 1 | (0u << 9), 4);  // library 1, name at 0
  m.str(h + 76, "_ext", 5);
  mini.command(0x80000034, {0x5000, 0x60});
  // __data: an authenticated rebase, a plain rebase with high bits, an
  // authenticated bind and a plain bind with an addend.
  const std::uint64_t next = std::uint64_t{1} << 51;
  m.put(0x4000, (std::uint64_t{1} << 63) | next | 0x1000, 8);
  m.put(0x4008, next | (std::uint64_t{0x12} << 43) | 0x1010, 8);
  m.put(0x4010, (std::uint64_t{3} << 62) | next | 0, 8);
  m.put(0x4018, (std::uint64_t{1} << 62) | (std::uint64_t{5} << 32) | 0, 8);

  const Image img = parse(m.bytes());
  EXPECT_TRUE(img.warnings.empty()) << img.warnings.front();
  ASSERT_EQ(img.relocations.size(), 4u);
  const Relocation &a = img.relocations[0], &b = img.relocations[1], &c = img.relocations[2], &d = img.relocations[3];
  EXPECT_EQ(a.address, 0x100004000u);
  EXPECT_EQ(*a.target, 0x100001000u);
  EXPECT_EQ(*b.target, (std::uint64_t{0x12} << 56) + 0x100001010u);
  EXPECT_EQ(c.symbol, "_ext");
  EXPECT_EQ(c.kind, RelocationKind::glob_dat);
  EXPECT_EQ(c.addend, 0);
  EXPECT_EQ(d.symbol, "_ext");
  EXPECT_EQ(d.addend, 5);
  EXPECT_EQ(relocation_type_name(img, a.type), "DYLD_CHAINED_PTR_ARM64E_USERLAND");
  ASSERT_EQ(img.imports.size(), 2u);
  EXPECT_EQ(img.imports[0].library, "/usr/lib/libext.dylib");
}

TEST(Macho, ReportsEncryption) {
  Mini mini;
  mini.command(0x2c, {0x1000, 0x100, 1, 0});  // LC_ENCRYPTION_INFO_64, cryptid 1
  const Image img = parse(mini.m.bytes());
  ASSERT_TRUE(img.macho);
  EXPECT_TRUE(img.macho->has_encryption_info);
  EXPECT_TRUE(img.macho->encrypted);
  EXPECT_EQ(img.macho->crypt_offset, 0x1000u);
  ASSERT_FALSE(img.warnings.empty());
  EXPECT_NE(img.warnings.back().find("encrypted"), std::string::npos);
}

TEST(Macho, LoadsAMinimalFile) {
  Mini mini;
  mini.command(0x80000028, {0x1000, 0, 0, 0});  // LC_MAIN, entryoff 0x1000
  const Image img = parse(mini.m.bytes());
  ASSERT_TRUE(img.entry);
  EXPECT_EQ(*img.entry, 0x100001000u);
  // Each segment split by its section, the rest keeping the segment's name.
  ASSERT_EQ(img.blocks.size(), 6u);
  EXPECT_EQ(img.blocks[0].name, "__TEXT");
  EXPECT_EQ(img.blocks[1].name, "__text");
  EXPECT_EQ(img.blocks[1].size, 0x100u);
  EXPECT_EQ(img.blocks[1].perms.str(), "r-x");
  EXPECT_EQ(img.blocks[2].name, "__TEXT");
  EXPECT_EQ(img.blocks[3].name, "__data");
  EXPECT_EQ(img.blocks[4].name, "__DATA");
  EXPECT_EQ(img.blocks[5].name, "__LINKEDIT");
  EXPECT_TRUE(img.warnings.empty()) << img.warnings.front();
}

TEST(Macho, RejectsMalformedHeaders) {
  auto load = [](Builder b) { return parse(b.bytes()); };
  {
    Mini mini;
    mini.m.put(20, 0x100000, 4);  // sizeofcmds past the file
    EXPECT_THROW(load(mini.m), LoadError);
  }
  {
    Mini mini;
    mini.m.put(36, 0, 4);  // the first command's cmdsize
    EXPECT_THROW(load(mini.m), LoadError);
  }
  {
    Mini mini;
    mini.m.put(32 + 64, 1000, 4);  // nsects that don't fit
    EXPECT_THROW(load(mini.m), LoadError);
  }
  {
    Builder b;
    b.put(0, 0xfeedfacf, 4);
    b.b.resize(20);
    EXPECT_THROW(load(b), LoadError);
  }
  {
    // A Java class file shares the universal magic.
    Builder b;
    b.put(0, 0xbebafeca, 4);
    b.put(4, 0x34000000, 4);
    b.b.resize(64);
    EXPECT_FALSE(is_macho(*b.bytes()));
    EXPECT_THROW(load(b), LoadError);
  }
}

TEST(Macho, ToleratesBadLinkeditData) {
  Mini mini;
  mini.command(0x2, {0x9000, 100, 0x9100, 10});  // LC_SYMTAB past the file
  mini.command(0x80000033, {0x5000, 0x10});      // an export trie of garbage
  mini.m.put(0x5000, 0xffffffffffffffff, 8);
  const Image img = parse(mini.m.bytes());
  EXPECT_GE(img.warnings.size(), 2u);
  EXPECT_TRUE(img.symbols.empty());
}

}  // namespace
}  // namespace revkit::loader
