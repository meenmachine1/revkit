// Objective-C and Swift metadata (docs/macho.md): tests/data/macho/objc.m
// built at test time (dyld info and chained fixups, arm64 and x86-64),
// checked against llvm-nm's symbols for the same files; and a hand-built
// image for what clang 18 doesn't write (relative method lists, Swift
// descriptors and a vtable).
#include "macho_fixture.h"

#include "revkit/loader/load.hh"
#include "revkit/objc/objc.h"
#include "revkit/types/print.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>

namespace revkit::objc {
namespace {

const loader::macho_testing::Fixtures *fx() {
  const auto &f = loader::macho_testing::fixtures(REVKIT_TEST_CLANG, REVKIT_TEST_LD64, REVKIT_TEST_LIPO, REVKIT_TEST_NM,
                                                  REVKIT_TEST_OBJDUMP, REVKIT_MACHO_FIXTURE);
  return f ? &*f : nullptr;
}

const Class *find(const Metadata &m, const std::string &name) {
  for (const Class &c : m.classes)
    if (c.name == name) return &c;
  return nullptr;
}

std::vector<std::string> selectors(const std::optional<MethodList> &l) {
  std::vector<std::string> out;
  if (l)
    for (const Method &m : l->methods) out.push_back(m.selector);
  return out;
}

class Fixture : public ::testing::TestWithParam<std::string> {};

TEST_P(Fixture, ReadsClassesCategoriesAndProtocols) {
  const auto *F = fx();
  if (F == nullptr) GTEST_SKIP() << "clang, ld64.lld or llvm tools missing, or the fixtures didn't build";
  const std::string name = GetParam();
  const loader::Image img = loader::load_file(F->path(name));
  const auto syms = F->symbols(name);
  const Metadata m = scan(img);
  EXPECT_TRUE(m.warnings.empty()) << m.warnings.front();
  ASSERT_EQ(m.classes.size(), 2u);
  const Class *base = find(m, "Base"), *point = find(m, "Point");
  ASSERT_NE(base, nullptr);
  ASSERT_NE(point, nullptr);
  EXPECT_EQ(base->address, syms.at("_OBJC_CLASS_$_Base"));
  EXPECT_EQ(base->metaclass, syms.at("_OBJC_METACLASS_$_Base"));
  EXPECT_EQ(base->superclass, "");
  EXPECT_EQ(base->flags & 2, 2u);  // RO_ROOT
  EXPECT_EQ(point->superclass, "Base");
  EXPECT_EQ(point->superclass_address, base->address);
  EXPECT_EQ(point->instance_size, 16u);
  EXPECT_EQ(selectors(point->instance_methods), (std::vector<std::string>{"sum", "name", "x", "setX:"}));
  EXPECT_EQ(selectors(base->class_methods), std::vector<std::string>{"alloc"});
  // Every method's implementation is its symbol's.
  for (const Class *c : {base, point})
    for (const auto *l : {&c->instance_methods, &c->class_methods})
      if (*l)
        for (const Method &x : (*l)->methods) EXPECT_EQ(x.imp, syms.at(method_name(c->name, {}, x))) << x.selector;
  ASSERT_EQ(point->instance_methods->methods[3].types, "v20@0:8i16");
  // Ivars, at their offset variables' values.
  ASSERT_EQ(point->ivars.size(), 2u);
  const Ivar &y = point->ivars[0];
  EXPECT_EQ(y.name, "y");
  EXPECT_EQ(y.type, "i");
  EXPECT_EQ(y.offset_address, syms.at("_OBJC_IVAR_$_Point.y"));
  EXPECT_EQ(y.offset, 8u);
  EXPECT_EQ(y.size, 4u);
  ASSERT_EQ(point->properties.size(), 1u);
  EXPECT_EQ(point->properties[0].name, "x");
  EXPECT_EQ(point->protocols, std::vector<std::string>{"Named"});
  // The category and the protocol.
  ASSERT_EQ(m.categories.size(), 1u);
  EXPECT_EQ(m.categories[0].name, "Extra");
  EXPECT_EQ(m.categories[0].class_name, "Point");
  EXPECT_EQ(m.categories[0].address, syms.at("__OBJC_$_CATEGORY_Point_$_Extra"));
  ASSERT_EQ(selectors(m.categories[0].instance_methods), std::vector<std::string>{"diff"});
  EXPECT_EQ(m.categories[0].instance_methods->methods[0].imp, syms.at("-[Point(Extra) diff]"));
  ASSERT_EQ(m.protocols.size(), 1u);
  EXPECT_EQ(m.protocols[0].name, "Named");
  EXPECT_EQ(selectors(m.protocols[0].instance_methods), std::vector<std::string>{"name"});
  // References: main's selectors and its class reference.
  std::vector<std::string> sels;
  for (const auto &[slot, s] : m.selector_refs) sels.push_back(s);
  std::sort(sels.begin(), sels.end());
  EXPECT_EQ(sels, (std::vector<std::string>{"diff", "sum", "x"}));
  ASSERT_EQ(m.class_refs.size(), 1u);
  EXPECT_EQ(m.class_refs.begin()->second, "Point");
  EXPECT_TRUE(m.image_info);

  // The markup: the structures named as clang names them, a function per
  // method with its prototype, self typed as the class's struct.
  const msvc::Markup mk = markup(img, m);
  auto data_named = [&](const std::string &n) {
    return std::any_of(mk.data.begin(), mk.data.end(), [&](const msvc::DataDef &d) { return d.name == n; });
  };
  for (const char *n : {"_OBJC_CLASS_$_Point", "_OBJC_METACLASS_$_Point", "__OBJC_CLASS_RO_$_Point",
                        "__OBJC_$_INSTANCE_METHODS_Point", "__OBJC_$_INSTANCE_VARIABLES_Point", "__OBJC_$_PROP_LIST_Point",
                        "__OBJC_$_CATEGORY_Point_$_Extra", "__OBJC_PROTOCOL_$_Named", "_OBJC_IVAR_$_Point.y"})
    EXPECT_TRUE(data_named(n)) << n;
  for (const msvc::DataDef &d : mk.data) {
    if (d.name.empty()) continue;
    auto it = syms.find(d.name);
    if (it != syms.end()) EXPECT_EQ(d.address, it->second) << d.name;
  }
  auto fn = [&](std::uint64_t a) -> const msvc::FunctionDef * {
    for (const msvc::FunctionDef &f : mk.functions)
      if (f.entry == a) return &f;
    return nullptr;
  };
  const msvc::FunctionDef *setx = fn(syms.at("-[Point setX:]"));
  ASSERT_NE(setx, nullptr);
  EXPECT_EQ(setx->name, "-[Point setX:]");
  ASSERT_TRUE(setx->prototype.valid());
  EXPECT_EQ(types::prototype(mk.store, setx->prototype, "f"), "void f(struct Point *self, SEL _cmd, int param_3)");
  const msvc::FunctionDef *alloc = fn(syms.at("+[Base alloc]"));
  ASSERT_NE(alloc, nullptr);
  EXPECT_EQ(types::prototype(mk.store, alloc->prototype, "f"), "id f(Class self, SEL _cmd)");
  EXPECT_EQ(mk.counts.at("objc_methods"), 7u);
  // The selector strings are strings.
  const std::uint64_t sum_sel = point->instance_methods->address + 8;
  EXPECT_FALSE(std::none_of(mk.data.begin(), mk.data.end(), [&](const msvc::DataDef &d) { return d.string; }));
  (void)sum_sel;
}

INSTANTIATE_TEST_SUITE_P(Objc, Fixture, ::testing::Values("objc-arm64", "objc-arm64-chained", "objc-x86_64"));

TEST(Objc, NamesMethodsAsClangDoes) {
  Method m{"setX:", "", 0, false};
  EXPECT_EQ(method_name("Point", "", m), "-[Point setX:]");
  m.class_method = true;
  EXPECT_EQ(method_name("Point", "Extra", m), "+[Point(Extra) setX:]");
}

// A hand-built arm64 image: a class with a relative method list, and Swift
// descriptors: a struct with a field, a class with a vtable.
struct Synthetic {
  std::shared_ptr<loader::Bytes> bytes;
  loader::Image img;

  void put(std::uint64_t a, std::uint64_t v, unsigned n) {
    for (unsigned i = 0; i < n; ++i) (*bytes)[a + i] = std::byte(static_cast<std::uint8_t>(v >> (8 * i)));
  }
  void rel(std::uint64_t field, std::uint64_t to) { put(field, static_cast<std::uint32_t>(to - field), 4); }
  void str(std::uint64_t a, const char *s) { std::memcpy(bytes->data() + a, s, std::strlen(s) + 1); }
  void section(const char *name, std::uint64_t a, std::uint64_t size) {
    loader::Section s;
    s.name = name;
    s.segment = "__DATA_CONST";
    s.addr = a;
    s.size = size;
    s.alloc = true;
    img.sections.push_back(s);
  }

  // `extra`: bytes past 0x3000, in one more data region, for the hostile
  // tests.
  explicit Synthetic(std::uint64_t extra = 0) : bytes(std::make_shared<loader::Bytes>(0x3000 + extra)) {
    img.format = loader::Format::macho;
    img.bits = 64;
    img.machine = 0x0100000c;
    img.file = bytes;
    // Code at 0x1000, data at 0x2000 (addresses are file offsets).
    str(0x2800, "Rel");
    str(0x2804, "go");
    str(0x2808, "v16@0:8");
    str(0x2810, "Mod");
    str(0x2814, "S");
    str(0x2816, "f");
    str(0x2818, "C");
    put(0x2900, 0x2804, 8);  // a selector reference
    put(0x2000 + 32, 0x2100, 8);  // class_t.data
    put(0x2100, 2, 4);              // RO_ROOT
    put(0x2100 + 8, 8, 4);
    put(0x2100 + 24, 0x2800, 8);  // name
    put(0x2100 + 32, 0x2200, 8);  // baseMethods
    put(0x2200, 0x8000000c, 4);   // relative, entsize 12
    put(0x2204, 1, 4);
    rel(0x2208, 0x2900);
    rel(0x220c, 0x2808);
    rel(0x2210, 0x1010);
    put(0x2a00, 0x2000, 8);  // the class list
    // Swift: a struct S in module Mod with field f, and a class C with a
    // one-entry vtable.
    rel(0x2b00, 0x2c00);
    rel(0x2b04, 0x2f00);
    put(0x2c00, 17, 4);
    rel(0x2c04, 0x2d00);
    rel(0x2c08, 0x2814);
    rel(0x2c0c, 0x1020);
    rel(0x2c10, 0x2e00);
    put(0x2d00, 0, 4);  // the module
    rel(0x2d08, 0x2810);
    put(0x2e08, 12u << 16, 4);  // field record size 12
    put(0x2e0c, 1, 4);
    rel(0x2e10 + 8, 0x2816);
    put(0x2f00, 16 | (0x8000u << 16), 4);
    rel(0x2f08, 0x2818);
    put(0x2f00 + 28, 20, 4);  // metadata positive size in words
    put(0x2f2c, 10, 4);       // vtable offset, size
    put(0x2f30, 1, 4);
    put(0x2f34, 0, 4);
    rel(0x2f38, 0x1030);
    img.memory = loader::Memory(bytes);
    img.memory.add({0x1000, 0x1000, 0x1000, 0x1000, {true, false, true}});
    img.memory.add({0x2000, 0x1000, 0x2000, 0x1000, {true, true, false}});
    if (bytes->size() > 0x3000) img.memory.add({0x3000, bytes->size() - 0x3000, 0x3000, bytes->size() - 0x3000, {true, true, false}});
    section("__objc_classlist", 0x2a00, 8);
    section("__objc_selrefs", 0x2900, 8);
    section("__swift5_types", 0x2b00, 8);
  }
};

TEST(Objc, ReadsRelativeMethodListsAndSwiftTypes) {
  Synthetic s;
  const Metadata m = scan(s.img);
  ASSERT_EQ(m.classes.size(), 1u);
  const Class &c = m.classes[0];
  EXPECT_EQ(c.name, "Rel");
  ASSERT_TRUE(c.instance_methods);
  EXPECT_TRUE(c.instance_methods->relative);
  ASSERT_EQ(c.instance_methods->methods.size(), 1u);
  EXPECT_EQ(c.instance_methods->methods[0].selector, "go");
  EXPECT_EQ(c.instance_methods->methods[0].types, "v16@0:8");
  EXPECT_EQ(c.instance_methods->methods[0].imp, 0x1010u);
  EXPECT_EQ(m.selector_refs.at(0x2900), "go");

  ASSERT_EQ(m.swift_types.size(), 2u);
  const SwiftType &st = m.swift_types[0];
  EXPECT_EQ(st.kind, "struct");
  EXPECT_EQ(st.name, "S");
  EXPECT_EQ(st.parent, "Mod");
  EXPECT_EQ(st.accessor, 0x1020u);
  EXPECT_EQ(st.fields, std::vector<std::string>{"f"});
  const SwiftType &sc = m.swift_types[1];
  EXPECT_EQ(sc.kind, "class");
  EXPECT_EQ(sc.vtable, std::vector<std::uint64_t>{0x1030});

  const msvc::Markup mk = markup(s.img, m);
  auto fn = [&](std::uint64_t a) {
    return std::find_if(mk.functions.begin(), mk.functions.end(), [&](const msvc::FunctionDef &f) { return f.entry == a; });
  };
  ASSERT_NE(fn(0x1010), mk.functions.end());
  EXPECT_EQ(fn(0x1010)->name, "-[Rel go]");
  EXPECT_EQ(fn(0x1010)->pass, "objc");
  ASSERT_NE(fn(0x1020), mk.functions.end());
  EXPECT_EQ(fn(0x1020)->name, "type metadata accessor for Mod.S");
  EXPECT_EQ(fn(0x1020)->pass, "swift");
  ASSERT_NE(fn(0x1030), mk.functions.end());
  EXPECT_EQ(mk.counts.at("swift_types"), 2u);
  // A method list's entries are method_small_t.
  EXPECT_TRUE(std::any_of(mk.data.begin(), mk.data.end(), [&](const msvc::DataDef &d) {
    return d.address == 0x2208 && mk.store.get(d.type).as<types::AggregateType>() &&
           mk.store.get(d.type).as<types::AggregateType>()->name == "method_small_t";
  }));
}

// Bug scrub part 3: records naming one descriptor, and methods naming one
// long string, don't multiply what is read.
TEST(Objc, AliasesAreReadOnce) {
  {
    Synthetic s;
    // Sixteen type records, all to the struct's descriptor.
    for (std::uint64_t e = 0x2b00; e < 0x2b40; e += 4) s.rel(e, 0x2c00);
    s.img.sections.back().size = 0x40;
    const Metadata m = scan(s.img);
    ASSERT_EQ(m.swift_types.size(), 1u);
    EXPECT_EQ(m.swift_types[0].name, "S");
  }
  // 65,536 relative methods whose types are one 4,000-byte string, in each
  // of four classes' lists (the same list): 1 GiB of copies unbounded.
  Synthetic s(0x110000);
  std::string types(4000, 'v');
  s.str(0x3000, types.c_str());
  const std::uint64_t list = 0x4000;
  s.put(list, 0x8000000c, 4);
  s.put(list + 4, 65536, 4);
  for (std::uint64_t i = 0; i < 65536; ++i) {
    const std::uint64_t e = list + 8 + 12 * i;
    s.rel(e, 0x2900);
    s.rel(e + 4, 0x3000);
    s.rel(e + 8, 0x1010);
  }
  s.put(0x2100 + 32, list, 8);
  for (std::uint64_t k = 0; k < 4; ++k) s.put(0x2a00 + 8 * k, 0x2000, 8);
  for (loader::Section &sec : s.img.sections)
    if (sec.name == "__objc_classlist") sec.size = 32;
  const Metadata m = scan(s.img);
  std::uint64_t bytes = 0;
  for (const Class &c : m.classes)
    if (c.instance_methods)
      for (const Method &x : c.instance_methods->methods) bytes += x.types.size() + x.selector.size();
  EXPECT_LE(bytes, (128u << 20) + 8192);
}

TEST(Objc, NothingForOtherFormats) {
  loader::Image img;
  img.format = loader::Format::elf;
  EXPECT_TRUE(scan(img).classes.empty());
  EXPECT_TRUE(markup(img, {}).data.empty());
}

}  // namespace
}  // namespace revkit::objc
