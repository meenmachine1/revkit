// The demangler analysis's prototypes (docs/demangle.md).
#include "revkit/inputs/demangled.h"

#include "revkit/inputs/ghidra_types.h"
#include "revkit/types/print.h"

#include <gtest/gtest.h>

namespace revkit::inputs {
namespace {

cparse::Profile Lp64() { return *cparse::profile_named("x86_64-linux-gnu"); }

struct Fixture {
  ClassScopes scopes;
  types::TypeStore store;
  cparse::Profile profile = Lp64();

  std::optional<DemangledPrototype> proto(std::string_view symbol) {
    auto d = demangle::parse(symbol);
    if (!d) return std::nullopt;
    return demangled_prototype(*d, scopes, profile, store);
  }
  std::string show(std::string_view symbol) {
    auto d = demangle::parse(symbol);
    auto p = proto(symbol);
    return p ? demangled_display(*p, store, d->name) : std::string("-");
  }
};

TEST(Demangled, SplitQualified) {
  EXPECT_EQ(split_qualified("std::vector<a::b>::push_back"), (std::vector<std::string>{"std", "vector<a::b>", "push_back"}));
  EXPECT_EQ(split_qualified("Foo::operator<"), (std::vector<std::string>{"Foo", "operator<"}));
  EXPECT_EQ(split_qualified("Foo::operator()"), (std::vector<std::string>{"Foo", "operator()"}));
  EXPECT_EQ(split_qualified("f::{lambda(int)#1}::operator()"),
            (std::vector<std::string>{"f", "{lambda(int)#1}", "operator()"}));
  EXPECT_EQ(split_qualified("main"), (std::vector<std::string>{"main"}));
  // The same scope gets the same ids.
  EXPECT_EQ(namespace_path({"geo", "Shape"}), namespace_path({"geo", "Shape"}));
  EXPECT_NE(namespace_path({"geo", "Shape"})[1].first, namespace_path({"geo", "Circle"})[1].first);
}

TEST(Demangled, Prototypes) {
  Fixture f;
  // Free functions: references as pointers, varargs, no parameters.
  EXPECT_EQ(f.show("_Z8distanceRKN3geo5PointES2_"),
            "undefined distance(const geo::Point *param_1, const geo::Point *param_2)");
  EXPECT_EQ(f.show("_Z3addPKcz"), "undefined add(const char *param_1, ...)");
  EXPECT_EQ(f.show("_Z4tickv"), "undefined tick(void)");
  // A template's return type is in the mangling.
  EXPECT_EQ(f.show("_Z3maxIiET_S0_S0_"), "int max<int>(int param_1, int param_2)");
  // A function pointer parameter.
  EXPECT_EQ(f.show("_Z5applyPFiiiEii"), "undefined apply(int (*param_1)(int, int), int param_2, int param_3)");
  // A class by value can't be laid out: no prototype.
  EXPECT_FALSE(f.proto("_Z4areaN3geo4RectE"));
  // Clones: no prototype (GCC changes their parameters).
  EXPECT_FALSE(f.proto("_ZL6helperi.isra.0"));
}

TEST(Demangled, This) {
  Fixture f;
  // Const members, constructors and destructors take `this` for certain.
  auto area = f.proto("_ZNK3geo6Circle4areaEv");
  ASSERT_TRUE(area);
  EXPECT_TRUE(area->has_this);
  EXPECT_FALSE(area->this_guessed);
  EXPECT_EQ(f.show("_ZNK3geo6Circle4areaEv"), "undefined geo::Circle::area(const geo::Circle *this)");
  EXPECT_EQ(f.show("_ZN3geo6CircleD2Ev"), "void geo::Circle::~Circle(geo::Circle *this)");
  // Unknown scope: a namespace function until the scope is seen to be a class.
  EXPECT_EQ(f.show("_ZN3geo6Circle5scaleEd"), "undefined geo::Circle::scale(double param_1)");
  f.scopes.add(*demangle::parse("_ZTVN3geo6CircleE"));  // vtable for geo::Circle
  auto scale = f.proto("_ZN3geo6Circle5scaleEd");
  ASSERT_TRUE(scale);
  EXPECT_TRUE(scale->has_this);
  EXPECT_TRUE(scale->this_guessed);
  EXPECT_EQ(f.show("_ZN3geo6Circle5scaleEd"), "undefined geo::Circle::scale(geo::Circle *this, double param_2)");
  // A class template's scope is a class.
  EXPECT_TRUE(f.proto("_ZNSt6vectorIiSaIiEE9push_backERKi")->has_this);
  // std is a namespace.
  EXPECT_FALSE(f.proto("_ZSt9terminatev")->has_this);
}

TEST(Demangled, RefineThis) {
  Fixture f;
  f.scopes.add(*demangle::parse("_ZTV8Registry"));
  types::TypeStore &store = f.store;
  auto apply = [&](std::string_view symbol) {
    auto p = f.proto(symbol);
    lift::FunctionFacts out;
    GhidraTypes enc(store, DataOrg{}, nullptr);
    apply_demangled(out, *p, enc, {});
    return out;
  };
  // static Registry &Registry::global(): another analysis found no parameter.
  lift::FunctionFacts global = apply("_ZN8Registry6globalEv");
  EXPECT_TRUE(global.demangled);
  EXPECT_TRUE(global.this_guessed);
  ASSERT_EQ(global.params.size(), 1u);
  EXPECT_TRUE(global.ret.is_default);
  EXPECT_TRUE(refine_demangled_this(global, {}));
  EXPECT_TRUE(global.params.empty());
  // void Registry::scale(double): one integer register more than the
  // mangled parameters is `this`, whatever the count.
  lift::FunctionFacts scale = apply("_ZN8Registry5scaleEd");
  EXPECT_FALSE(refine_demangled_this(scale, {false}));
  EXPECT_EQ(scale.params.size(), 2u);
  EXPECT_TRUE(refine_demangled_this(scale, {true}));
  ASSERT_EQ(scale.params.size(), 1u);
  EXPECT_EQ(scale.params[0].name, "param_1");
  // A certain `this` stays.
  lift::FunctionFacts get = apply("_ZNK8Registry3getEv");
  EXPECT_FALSE(refine_demangled_this(get, {}));
}

TEST(Demangled, BatchParsesEach) {
  Fixture f;
  DemangledPrototypes batch(f.scopes, f.profile, f.store);
  auto a = batch.add(*demangle::parse("_Z1fi"));
  auto b = batch.add(*demangle::parse("_Z4areaN3geo4RectE"));  // can't be written
  auto c = batch.add(*demangle::parse("_Z1gRKN1n1SE"));
  ASSERT_TRUE(a && c);
  EXPECT_FALSE(b);
  batch.parse();
  ASSERT_TRUE(batch.get(*a));
  ASSERT_TRUE(batch.get(*c));
  EXPECT_EQ(demangled_display(*batch.get(*a), f.store, "f"), "undefined f(int param_1)");
  EXPECT_EQ(demangled_display(*batch.get(*c), f.store, "g"), "undefined g(const n::S *param_1)");
}

TEST(Demangled, Microsoft) {
  Fixture f;
  f.profile = *cparse::profile_named("i386-pc-windows-msvc");
  // public: int __thiscall Foo::get(void) const
  auto get = f.proto("?get@Foo@@QBEHXZ");
  ASSERT_TRUE(get);
  EXPECT_TRUE(get->has_this);
  EXPECT_FALSE(get->this_guessed);
  EXPECT_FALSE(get->unknown_return);
  const auto *fn = f.store.get(get->type).as<types::FunctionType>();
  ASSERT_TRUE(fn);
  EXPECT_EQ(fn->cc, types::CallConv::Thiscall);
  // static: no this
  auto make = f.proto("?make@Shape@geo@@SAPAV12@H@Z");
  ASSERT_TRUE(make);
  EXPECT_FALSE(make->has_this);
  EXPECT_EQ(demangled_display(*make, f.store, "geo::Shape::make"), "geo::Shape *geo::Shape::make(int param_1)");
  // An enum by value is an int.
  EXPECT_TRUE(f.proto("?f@@YAXW4Color@@@Z"));
}

}  // namespace
}  // namespace revkit::inputs
