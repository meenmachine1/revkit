// MSVC RTTI and PE markup on tests/data/msvc/classes.cc, built at test
// time for x86_64 and i686 (absolute and image-relative RTTI), checked
// against the linker map's symbols.
#include "msvc_fixture.h"

#include "revkit/loader/load.hh"
#include "revkit/msvc/msvc.h"
#include "revkit/types/print.h"

#include <gtest/gtest.h>

#include <algorithm>

namespace revkit::msvc {
namespace {

class MsvcTest : public ::testing::TestWithParam<std::string> {
 protected:
  static std::map<std::string, std::optional<testing::Fixture>> &fixtures() {
    static std::map<std::string, std::optional<testing::Fixture>> f;
    return f;
  }
  void SetUp() override {
    auto &f = fixtures();
    if (!f.contains(GetParam()))
      f[GetParam()] = testing::build_fixture(REVKIT_TEST_CLANG, REVKIT_TEST_LLD_LINK, REVKIT_MSVC_FIXTURE, GetParam());
    if (!f[GetParam()]) GTEST_SKIP() << "clang or lld-link missing, or the fixture didn't build";
    fx_ = &*f[GetParam()];
    image_ = loader::load_file(fx_->stripped);
  }
  const testing::Fixture *fx_ = nullptr;
  loader::Image image_;
};

const ClassInfo *Find(const Rtti &r, const std::string &name) {
  for (const ClassInfo &c : r.classes)
    if (c.name == name) return &c;
  return nullptr;
}

TEST_P(MsvcTest, FindsClassesFromTypeDescriptors) {
  Rtti r = scan_rtti(image_);
  EXPECT_EQ(r.image_relative, GetParam() == "x86_64");
  for (const auto &[name, mangled] : std::map<std::string, std::string>{{"geo::Shape", "??_R0?AUShape@geo@@@8"},
                                                                          {"geo::Named", "??_R0?AUNamed@geo@@@8"},
                                                                          {"geo::Rect", "??_R0?AURect@geo@@@8"},
                                                                          {"geo::Square", "??_R0?AUSquare@geo@@@8"},
                                                                          {"geo::Base", "??_R0?AUBase@geo@@@8"},
                                                                          {"geo::Left", "??_R0?AULeft@geo@@@8"},
                                                                          {"geo::Box<int>", "??_R0?AU?$Box@H@geo@@@8"}}) {
    const ClassInfo *c = Find(r, name);
    ASSERT_NE(c, nullptr) << name;
    EXPECT_EQ(c->type_descriptor, fx_->at(mangled)) << name;
    EXPECT_TRUE(c->is_struct);
  }
  // The exception's type has a descriptor (for catch) but no hierarchy.
  const ClassInfo *err = Find(r, "Error");
  ASSERT_NE(err, nullptr);
}

TEST_P(MsvcTest, ReadsHierarchies) {
  Rtti r = scan_rtti(image_);
  const ClassInfo *sq = Find(r, "geo::Square");
  ASSERT_NE(sq, nullptr);
  EXPECT_EQ(sq->hierarchy, fx_->at("??_R3Square@geo@@8"));
  ASSERT_EQ(sq->bases.size(), 4u);  // Square, Rect, Shape, Named
  EXPECT_EQ(sq->bases[0].name, "geo::Square");
  EXPECT_EQ(sq->bases[1].name, "geo::Rect");
  EXPECT_EQ(sq->bases[2].name, "geo::Shape");
  EXPECT_EQ(sq->bases[3].name, "geo::Named");
  EXPECT_EQ(sq->bases[3].mdisp, GetParam() == "x86_64" ? 16 : 8);
  EXPECT_EQ(sq->bases[1].depth, 1u);
  EXPECT_EQ(sq->bases[2].depth, 2u);
  ASSERT_EQ(sq->direct_bases().size(), 1u);
  EXPECT_EQ(sq->bases[sq->direct_bases()[0]].name, "geo::Rect");
  EXPECT_NE(sq->hierarchy_attributes & kChdMultipleInheritance, 0u);
  const ClassInfo *rect = Find(r, "geo::Rect");
  ASSERT_NE(rect, nullptr);
  ASSERT_EQ(rect->direct_bases().size(), 2u);
  const ClassInfo *left = Find(r, "geo::Left");
  ASSERT_NE(left, nullptr);
  ASSERT_EQ(left->bases.size(), 2u);
  EXPECT_TRUE(left->bases[1].is_virtual());
}

TEST_P(MsvcTest, FindsVftablesThroughLocators) {
  Rtti r = scan_rtti(image_);
  std::map<std::uint64_t, const Vftable *> by_address;
  for (const Vftable &t : r.vftables) by_address[t.address] = &t;
  struct Want {
    const char *symbol, *cls, *sub;
    std::size_t entries;
  };
  for (const Want &w : {Want{"??_7Rect@geo@@6BShape@1@@", "geo::Rect", "geo::Rect", 3},
                        Want{"??_7Rect@geo@@6BNamed@1@@", "geo::Rect", "geo::Named", 2},
                        Want{"??_7Square@geo@@6BShape@1@@", "geo::Square", "geo::Square", 3},
                        Want{"??_7Square@geo@@6BNamed@1@@", "geo::Square", "geo::Named", 2},
                        Want{"??_7?$Box@H@geo@@6B@", "geo::Box<int>", "geo::Box<int>", 3},
                        Want{"??_7Left@geo@@6B@", "geo::Left", "geo::Base", 1}}) {
    const std::uint64_t a = fx_->at(w.symbol);
    ASSERT_NE(a, 0u) << w.symbol;
    ASSERT_TRUE(by_address.contains(a)) << w.symbol;
    const Vftable &t = *by_address[a];
    EXPECT_EQ(r.classes[t.cls].name, w.cls) << w.symbol;
    EXPECT_EQ(r.classes[t.subobject].name, w.sub) << w.symbol;
    EXPECT_EQ(t.entries.size(), w.entries) << w.symbol;
    for (std::uint64_t e : t.entries) EXPECT_TRUE(image_.memory.find(e) && image_.memory.find(e)->perms.exec);
  }
  // Square overrides scale and area, inherits Rect's name().
  const Vftable &rs = *by_address[fx_->at("??_7Rect@geo@@6BShape@1@@")];
  const Vftable &ss = *by_address[fx_->at("??_7Square@geo@@6BShape@1@@")];
  EXPECT_NE(rs.entries[1], ss.entries[1]);  // area
  EXPECT_EQ(by_address[fx_->at("??_7Rect@geo@@6BNamed@1@@")]->entries[0],
            by_address[fx_->at("??_7Square@geo@@6BNamed@1@@")]->entries[0]);  // name()
}

TEST_P(MsvcTest, MarksUpRttiAndVirtualFunctions) {
  MarkupOptions o;
  o.named = [](std::uint64_t) { return std::string(); };
  Markup m = analyze(image_, o);
  std::map<std::uint64_t, const DataDef *> data;
  for (const DataDef &d : m.data) data[d.address] = &d;
  auto name_at = [&](const std::string &symbol) -> std::string {
    auto it = data.find(fx_->at(symbol));
    return it == data.end() ? "" : it->second->name;
  };
  EXPECT_EQ(name_at("??_R0?AURect@geo@@@8"), "geo::Rect::RTTI_Type_Descriptor");
  EXPECT_EQ(name_at("??_R4Rect@geo@@6BShape@1@@"), "geo::Rect::RTTI_Complete_Object_Locator");
  EXPECT_EQ(name_at("??_R4Rect@geo@@6BNamed@1@@"), "geo::Rect::RTTI_Complete_Object_Locator_for_Named");
  EXPECT_EQ(name_at("??_R3Rect@geo@@8"), "geo::Rect::RTTI_Class_Hierarchy_Descriptor");
  EXPECT_EQ(name_at("??_R2Rect@geo@@8"), "geo::Rect::RTTI_Base_Class_Array");
  EXPECT_EQ(name_at("??_7Rect@geo@@6BShape@1@@"), "geo::Rect::vftable");
  EXPECT_EQ(name_at("??_7Rect@geo@@6BNamed@1@@"), "geo::Rect::vftable_for_Named");
  // Left's one table is its virtual base's: still just "vftable", as MSVC
  // names it.
  EXPECT_EQ(name_at("??_7Left@geo@@6B@"), "geo::Left::vftable");
  // The vftable's type: a struct of function pointers taking the class.
  const DataDef *vt = data.at(fx_->at("??_7Rect@geo@@6BShape@1@@"));
  EXPECT_EQ(types::type_name(m.store, vt->type), "struct geo::Rect_vftable");
  // Every vftable entry is a function; Rect's own are named after it.
  std::map<std::uint64_t, const FunctionDef *> fns;
  for (const FunctionDef &f : m.functions) fns[f.entry] = &f;
  Rtti r = scan_rtti(image_);
  for (const Vftable &t : r.vftables)
    for (std::uint64_t e : t.entries) EXPECT_TRUE(fns.contains(e));
  for (const Vftable &t : r.vftables) {
    if (t.address != fx_->at("??_7Square@geo@@6BShape@1@@")) continue;
    const FunctionDef &area = *fns.at(t.entries[1]);
    EXPECT_EQ(area.name, "geo::Square::vfunc1");
    ASSERT_TRUE(area.this_type.valid());
    EXPECT_EQ(types::type_name(m.store, area.this_type), "struct geo::Square *");
    ASSERT_TRUE(area.prototype.valid());
    const auto *fn = m.store.get(area.prototype).as<types::FunctionType>();
    ASSERT_NE(fn, nullptr);
    EXPECT_TRUE(fn->varargs);
    EXPECT_EQ(fn->cc, GetParam() == "x86_64" ? types::CallConv::Default : types::CallConv::Thiscall);
  }
  // Rect's name() (in its table for Named) takes the Named subobject.
  for (const Vftable &t : r.vftables) {
    if (t.address != fx_->at("??_7Rect@geo@@6BNamed@1@@")) continue;
    const FunctionDef &name = *fns.at(t.entries[0]);
    EXPECT_EQ(name.name, "geo::Rect::Named_vfunc0");
    EXPECT_EQ(types::type_name(m.store, name.this_type), "struct geo::Named *");
  }
  const auto cls = std::find_if(m.classes.begin(), m.classes.end(), [](const ClassStruct &c) { return c.name == "geo::Rect"; });
  ASSERT_NE(cls, m.classes.end());
  const auto *agg = m.store.get(cls->type).as<types::AggregateType>();
  ASSERT_NE(agg, nullptr);
  ASSERT_FALSE(agg->fields.empty());
  EXPECT_EQ(agg->fields[0].name, "vftable");
  EXPECT_GT(m.counts["rtti_classes"], 6u);
}

const DataDef *DataAt(const Markup &m, std::uint64_t a) {
  for (const DataDef &d : m.data)
    if (d.address == a) return &d;
  return nullptr;
}
const LabelDef *LabelAt(const Markup &m, std::uint64_t a) {
  for (const LabelDef &l : m.labels)
    if (l.address == a) return &l;
  return nullptr;
}
const FunctionDef *FunctionAt(const Markup &m, std::uint64_t a) {
  for (const FunctionDef &f : m.functions)
    if (f.entry == a) return &f;
  return nullptr;
}

TEST_P(MsvcTest, MarksUpPeStructures) {
  MarkupOptions o;
  o.named = [](std::uint64_t) { return std::string(); };
  Markup m = analyze(image_, o);
  const bool x64 = GetParam() == "x86_64";
  // Headers.
  const DataDef *dos = DataAt(m, image_.image_base);
  ASSERT_NE(dos, nullptr);
  EXPECT_EQ(types::type_name(m.store, dos->type), "struct IMAGE_DOS_HEADER");
  EXPECT_EQ(dos->pass, "pe");
  bool nt = false, sections = false;
  for (const DataDef &d : m.data) {
    const std::string n = types::type_name(m.store, d.type);
    nt = nt || n == (x64 ? "struct IMAGE_NT_HEADERS64" : "struct IMAGE_NT_HEADERS32");
    sections = sections || (n == "struct IMAGE_SECTION_HEADER" && d.count == image_.sections.size());
  }
  EXPECT_TRUE(nt);
  EXPECT_TRUE(sections);
  // The load config, its cookie and the guard tables.
  const std::uint64_t lc = fx_->at(x64 ? "_load_config_used" : "__load_config_used");
  ASSERT_NE(DataAt(m, lc), nullptr);
  const std::uint64_t cookie = fx_->at(x64 ? "__security_cookie" : "___security_cookie");
  ASSERT_NE(LabelAt(m, cookie), nullptr);
  EXPECT_EQ(LabelAt(m, cookie)->name, "__security_cookie");
  EXPECT_NE(DataAt(m, cookie), nullptr);
  EXPECT_GT(m.counts["guard_cf_functions"], 5u);
  std::size_t guard = 0;
  for (const FunctionDef &f : m.functions) guard += f.why == "guard_cf";
  EXPECT_GT(guard, 0u);
  // TLS: the directory and its callback, a function.
  const std::uint64_t cb_c = fx_->at(x64 ? "rk_tls_callback" : "_rk_tls_callback@12");
  ASSERT_NE(cb_c, 0u);
  const FunctionDef *tls = FunctionAt(m, cb_c);
  ASSERT_NE(tls, nullptr);
  EXPECT_EQ(tls->name, "tls_callback_0");
  EXPECT_EQ(m.counts["tls_callbacks"], 1u);
  // C++ exception data: guarded()'s FuncInfo and its catch handlers as
  // functions.
  EXPECT_GE(m.counts["eh_functions"], 1u);
  std::size_t catches = 0;
  for (const FunctionDef &f : m.functions)
    if (f.why == "eh_catch") {
      ++catches;
      EXPECT_TRUE(f.name.starts_with("Catch@") || f.name.starts_with("Catch_All@")) << f.name;
      EXPECT_EQ(f.pass, "msvc");
    }
  EXPECT_EQ(catches, 2u);  // catch (const Error &) and catch (...)
  if (x64) {
    // .pdata and its UNWIND_INFOs; the C-specific handler's scope table.
    EXPECT_GT(m.counts["pdata_entries"], 5u);
    EXPECT_GT(m.counts["unwind_infos"], 3u);
    EXPECT_EQ(m.counts["c_scope_tables"], 1u);  // filtered()'s __try/__except
  }
}

TEST_P(MsvcTest, NoMarkupOutsidePe) {
  loader::Image elf;
  elf.format = loader::Format::elf;
  EXPECT_TRUE(analyze(elf).data.empty());
}

INSTANTIATE_TEST_SUITE_P(Arch, MsvcTest, ::testing::Values("x86_64", "i686"));

}  // namespace
}  // namespace revkit::msvc
