#include "revkit/demangle/demangle.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <memory>

namespace revkit::demangle {
namespace {

TEST(Demangle, Detect) {
  EXPECT_EQ(detect("_ZN3foo3barEv"), Scheme::Itanium);
  EXPECT_EQ(detect("__ZN3foo3barEv"), Scheme::Itanium);
  EXPECT_EQ(detect("?f@@YAXH@Z"), Scheme::Microsoft);
  EXPECT_EQ(detect("_RNvCs1234_7mycrate3foo"), Scheme::Rust);
  EXPECT_EQ(detect("_D3foo3barFZv"), Scheme::D);
  EXPECT_EQ(detect("main"), Scheme::None);
  EXPECT_EQ(detect("_init"), Scheme::None);
}

TEST(Demangle, Itanium) {
  EXPECT_EQ(demangle("_ZN3geo5Shape4makeEi"), "geo::Shape::make(int)");
  EXPECT_EQ(demangle("_ZNK3geo3Vec3dotERKS0_"), "geo::Vec::dot(geo::Vec const&) const");
  EXPECT_EQ(demangle("_ZNSt6vectorIiSaIiEE9push_backERKi"),
            "std::vector<int, std::allocator<int>>::push_back(int const&)");
  EXPECT_EQ(demangle("__ZN3foo3barEv"), "foo::bar()");
  EXPECT_EQ(demangle_itanium("_ZN3geo5Shape4makeEi", false), "geo::Shape::make");
  // GCC clone suffixes.
  EXPECT_EQ(demangle("_ZL6helperi.isra.0"), "helper(int) (.isra.0)");
  EXPECT_EQ(demangle("_ZTV5Shape"), "vtable for Shape");
}

TEST(Demangle, Microsoft) {
  EXPECT_EQ(demangle("?f@@YAXH@Z"), "void __cdecl f(int)");
  EXPECT_EQ(demangle("?make@Shape@geo@@SAPEAV12@H@Z"),
            "public: static class geo::Shape * __cdecl geo::Shape::make(int)");
  EXPECT_EQ(demangle("__imp_?f@@YAXH@Z"), "void __cdecl f(int)");
}

TEST(Demangle, RustAndD) {
  EXPECT_EQ(demangle("_RNvCs15kBYyAo9fc_7mycrate7example"), "mycrate::example");
  EXPECT_EQ(demangle("_D8demangle4testZ"), "demangle.test");
  EXPECT_EQ(demangle("_Dmain"), "D main");
}

TEST(Demangle, NotMangled) {
  EXPECT_EQ(demangle("main"), std::nullopt);
  EXPECT_EQ(demangle("_Zinvalid"), std::nullopt);
  EXPECT_EQ(demangle("?"), std::nullopt);
  EXPECT_EQ(demangle(""), std::nullopt);
  EXPECT_EQ(demangle_or_self("printf"), "printf");
}

TEST(Demangle, Parts) {
  auto p = itanium_function_parts("_ZN3geo5Shape4makeEi");
  ASSERT_TRUE(p);
  EXPECT_EQ(p->name, "geo::Shape::make");
  EXPECT_EQ(p->base_name, "make");
  EXPECT_EQ(p->context, "geo::Shape");
  EXPECT_EQ(p->parameters, "(int)");
  EXPECT_FALSE(p->is_ctor_or_dtor);
  auto ctor = itanium_function_parts("_ZN3geo5ShapeC2Ei");
  ASSERT_TRUE(ctor);
  EXPECT_TRUE(ctor->is_ctor_or_dtor);
  EXPECT_FALSE(itanium_function_parts("_ZTV5Shape"));  // data, not a function
  EXPECT_FALSE(itanium_function_parts("main"));
}

TEST(Demangle, StructuredItanium) {
  auto d = parse("_ZNSt6vectorIiSaIiEE9push_backERKi");
  ASSERT_TRUE(d);
  EXPECT_EQ(d->scheme, Scheme::Itanium);
  EXPECT_EQ(d->name, "std::vector<int,std::allocator<int>>::push_back");
  EXPECT_EQ(d->full, "std::vector<int, std::allocator<int>>::push_back(int const&)");
  ASSERT_TRUE(d->function);
  EXPECT_EQ(d->function->context, "std::vector<int,std::allocator<int>>");
  EXPECT_EQ(d->function->base_name, "push_back");
  EXPECT_EQ(d->function->member, Member::Unknown);
  ASSERT_EQ(d->function->params.size(), 1u);
  const Type &p = d->function->params[0];
  EXPECT_EQ(p.kind, Type::Kind::Reference);
  ASSERT_EQ(p.children.size(), 1u);
  EXPECT_EQ(p.children[0].kind, Type::Kind::Builtin);
  EXPECT_EQ(p.children[0].name, "int");
  EXPECT_TRUE(p.children[0].is_const);

  auto k = parse("_ZNK3geo3Vec3dotERKS0_");
  ASSERT_TRUE(k && k->function);
  EXPECT_EQ(k->name, "geo::Vec::dot");
  EXPECT_EQ(k->function->member, Member::Yes);
  EXPECT_TRUE(k->function->this_const);
  ASSERT_EQ(k->function->params.size(), 1u);
  EXPECT_EQ(k->function->params[0].children[0].kind, Type::Kind::Named);
  EXPECT_EQ(k->function->params[0].children[0].name, "geo::Vec");

  auto ctor = parse("_ZN3geo5ShapeC2Ei");
  ASSERT_TRUE(ctor && ctor->function);
  EXPECT_EQ(ctor->name, "geo::Shape::Shape");
  EXPECT_TRUE(ctor->function->constructor);
  EXPECT_EQ(ctor->function->member, Member::Yes);

  auto free_fn = parse("_Z3addPKcz");
  ASSERT_TRUE(free_fn && free_fn->function);
  EXPECT_EQ(free_fn->name, "add");
  EXPECT_EQ(free_fn->function->member, Member::No);
  EXPECT_TRUE(free_fn->function->varargs);
  ASSERT_EQ(free_fn->function->params.size(), 1u);
  EXPECT_EQ(free_fn->function->params[0].kind, Type::Kind::Pointer);

  auto none = parse("_Z4tickv");
  ASSERT_TRUE(none && none->function);
  EXPECT_TRUE(none->function->params.empty());

  auto tmpl = parse("_Z3maxIiET_S0_S0_");
  ASSERT_TRUE(tmpl && tmpl->function);
  EXPECT_EQ(tmpl->name, "max<int>");
  ASSERT_TRUE(tmpl->function->ret);
  EXPECT_EQ(tmpl->function->ret->name, "int");
  ASSERT_EQ(tmpl->function->params.size(), 2u);
  EXPECT_EQ(tmpl->function->params[1].name, "int");

  auto fp = parse("_Z5applyPFiiEi");
  ASSERT_TRUE(fp && fp->function);
  ASSERT_EQ(fp->function->params.size(), 2u);
  EXPECT_EQ(fp->function->params[0].kind, Type::Kind::Pointer);
  EXPECT_EQ(fp->function->params[0].children[0].kind, Type::Kind::Function);

  auto clone = parse("_ZL6helperi.isra.0");
  ASSERT_TRUE(clone && clone->function);
  EXPECT_EQ(clone->name, "helper.isra.0");
  EXPECT_EQ(clone->function->clone_suffix, ".isra.0");

  auto vt = parse("_ZTV5Shape");
  ASSERT_TRUE(vt);
  EXPECT_EQ(vt->name, "Shape::vtable");
  EXPECT_FALSE(vt->function);
  EXPECT_EQ(parse("_ZTI5Shape")->name, "Shape::typeinfo");
  EXPECT_EQ(parse("_ZN3geo5countE")->name, "geo::count");
  EXPECT_FALSE(parse("_ZN3geo5countE")->function);
  EXPECT_FALSE(parse("main"));
  EXPECT_FALSE(parse("_Zinvalid"));
  // One token: "operator new" as "operator_new", template arguments unspaced.
  EXPECT_EQ(parse("_Znwm")->name, "operator_new");
#if __has_include(<cxxabi.h>)
  // LLVM's demangler can't parse it; the C++ runtime's can.
  auto relocate = parse("_ZSt14__relocate_a_1IiiENSt9enable_ifIXsrSt24__is_bitwise_relocatableIT_vE5valueEPS2_E4typeES4_S4_S4_RSaIT0_E");
  ASSERT_TRUE(relocate);
  EXPECT_EQ(relocate->name, "std::__relocate_a_1<int,int>");
  EXPECT_FALSE(relocate->function);
#endif
  EXPECT_EQ(parse("_ZNSt3mapIijSt4lessIiESaISt4pairIKijEEE5clearEv")->name.find(' '), std::string::npos);
}

TEST(Demangle, StructuredMicrosoft) {
  auto d = parse("?make@Shape@geo@@SAPEAV12@H@Z");
  ASSERT_TRUE(d && d->function);
  EXPECT_EQ(d->scheme, Scheme::Microsoft);
  EXPECT_EQ(d->name, "geo::Shape::make");
  EXPECT_EQ(d->function->member, Member::No);  // static
  EXPECT_EQ(d->function->convention, "__cdecl");
  ASSERT_TRUE(d->function->ret);
  EXPECT_EQ(d->function->ret->kind, Type::Kind::Pointer);
  EXPECT_EQ(d->function->ret->children[0].kind, Type::Kind::Record);
  EXPECT_EQ(d->function->ret->children[0].name, "geo::Shape");
  ASSERT_EQ(d->function->params.size(), 1u);
  EXPECT_EQ(d->function->params[0].name, "int");

  // public: int __thiscall Foo::get(void) const
  auto m = parse("?get@Foo@@QBEHXZ");
  ASSERT_TRUE(m && m->function);
  EXPECT_EQ(m->function->member, Member::Yes);
  EXPECT_TRUE(m->function->this_const);
  EXPECT_EQ(m->function->convention, "__thiscall");
  EXPECT_TRUE(m->function->params.empty());

  // void __cdecl f(enum Color)
  auto e = parse("?f@@YAXW4Color@@@Z");
  ASSERT_TRUE(e && e->function);
  ASSERT_EQ(e->function->params.size(), 1u);
  EXPECT_EQ(e->function->params[0].kind, Type::Kind::Enum);
}

// Found by demangle_fuzzer: LLVM's D demangler reads one byte past the
// view. The input sits in an exactly-sized heap buffer so ASan sees it.
TEST(Demangle, UnterminatedInput) {
  for (std::string_view text : {"_D7x", "_D8demangle4testZ", "_ZN3foo3barEv", "?f@@YAXH@Z", "_RNv"}) {
    auto buf = std::make_unique<char[]>(text.size());
    std::copy(text.begin(), text.end(), buf.get());
    std::string_view view(buf.get(), text.size());
    (void)demangle(view);
    (void)demangle_itanium(view);
    (void)demangle_microsoft(view);
    (void)itanium_function_parts(view);
  }
}

TEST(Demangle, GarbageDoesNotCrash) {
  for (std::string s : {"_Z", "_ZN", "_ZNNNNNNNNNNN", "?@@@", "?$", "_R", "_D9", "_ZTV", "_Z1fIiE"})
    (void)demangle(s);
  std::string deep = "_Z";
  for (int i = 0; i < 5000; ++i) deep += "PP";
  (void)demangle(deep + "i");
}

}  // namespace
}  // namespace revkit::demangle
