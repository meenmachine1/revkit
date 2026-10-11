#include "revkit/debuginfo/dwarf.h"
#include "revkit/debuginfo/image.h"
#include "revkit/loader/load.hh"
#include "revkit/types/print.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <map>
#include <set>

namespace revkit::debuginfo {
namespace {

using types::TypeId;
using types::TypeStore;

std::string fixture_path(const std::string &name) {
  return std::string(REVKIT_FIXTURE_DIR) + "/" + name;
}

struct Loaded {
  loader::Image image;
  ImageSections sections;
  DebugInfo info;
};

std::optional<Loaded> load(const std::string &name, TypeStore &store) {
  std::string path = fixture_path(name);
  if (!std::filesystem::exists(path)) return std::nullopt;
  Loaded l;
  try {
    l.image = loader::load_file(path);
  } catch (const loader::LoadError &e) {
    ADD_FAILURE() << e.what();
    return std::nullopt;
  }
  l.sections = dwarf_sections(l.image);
  l.info = import_dwarf(l.sections.sections, store);
  return l;
}

const Function *find_fn(const DebugInfo &info, std::string_view name) {
  for (const Function &f : info.functions)
    if (f.name == name) return &f;
  return nullptr;
}

TypeId find_type(const TypeStore &s, const DebugInfo &info, std::string_view name) {
  for (TypeId id : info.types) {
    const types::Type &t = s.get(id);
    if (auto *a = t.as<types::AggregateType>(); a && a->name == name && a->complete) return id;
    if (auto *e = t.as<types::EnumType>(); e && e->name == name) return id;
    if (auto *d = t.as<types::TypedefType>(); d && d->name == name) return id;
  }
  return TypeId();
}

// Prototypes as written in fixture.c (C style, LP64).
const std::map<std::string, std::string> kPrototypes = {
    {"add", "int add(int a, int b)"},
    {"sum_ints", "long sum_ints(int count, ...)"},
    {"fold", "int fold(const int *values, size_t n, binop f, int init)"},
    {"apply", "void apply(struct ops *o, void *ctx)"},
    {"list_push", "struct node *list_push(struct node *head, int v)"},
    {"point_add", "point point_add(point a, point b)"},
    {"pack_flags", "unsigned int pack_flags(struct flags f)"},
    {"color_weight", "int color_weight(enum color c, enum sign s)"},
    {"as_float", "float as_float(union number n)"},
    {"matmul", "void matmul(int (*a)[4], int (*m)[4], ulong_t rows)"},
    {"split", "char **split(char *s, char sep, int *count)"},
    {"forest_size", "int forest_size(const struct forest *f, struct tree *t)"},
    {"packed_value",
     "double packed_value(struct packed_rec *r, struct with_array *w, struct anon_member *m)"},
    {"pick", "binop pick(int which)"},
    {"no_args", "void no_args(void)"},
    {"helper", "int helper(int x)"},
    {"main", "int main(int argc, char **argv)"},
};

class CFixture : public ::testing::TestWithParam<std::string> {};

TEST_P(CFixture, Prototypes) {
  TypeStore s;
  auto l = load(GetParam(), s);
  if (!l) GTEST_SKIP() << "fixture not built";
  EXPECT_TRUE(l->info.diagnostics.empty()) << l->info.diagnostics.front().message;
  const bool optimized = GetParam().find("O2") != std::string::npos;
  for (const auto &[name, proto] : kPrototypes) {
    const Function *f = find_fn(l->info, name);
    if (!f) {
      // At -O2 small static functions may be inlined away.
      EXPECT_TRUE(optimized) << name << " missing";
      continue;
    }
    if (f->abi_changed) continue;
    EXPECT_EQ(types::prototype(s, f->prototype, f->name), proto);
  }
  const Function *main_fn = find_fn(l->info, "main");
  ASSERT_NE(main_fn, nullptr);
  EXPECT_EQ(types::prototype(s, main_fn->prototype, "main", {types::Style::Ghidra}),
            "int main(int argc, char * * argv)");
  EXPECT_EQ(main_fn->param_names, (std::vector<std::string>{"argc", "argv"}));
  EXPECT_TRUE(main_fn->external);
}

TEST_P(CFixture, EntriesMatchSymbols) {
  TypeStore s;
  auto l = load(GetParam(), s);
  if (!l) GTEST_SKIP() << "fixture not built";
  std::map<std::string, std::uint64_t> syms;
  for (const auto &sym : l->image.symbols)
    if (sym.type == loader::SymbolType::func) syms.emplace(sym.name, sym.value);
  int checked = 0;
  for (const Function &f : l->info.functions) {
    ASSERT_FALSE(f.ranges.empty());
    EXPECT_TRUE(std::is_sorted(f.ranges.begin(), f.ranges.end()));
    auto it = syms.find(f.name);
    if (it == syms.end()) continue;  // e.g. a clone named foo.isra.0
    EXPECT_EQ(f.entry, it->second) << f.name;
    EXPECT_TRUE(is_code(l->image, f.entry)) << f.name;
    ++checked;
  }
  EXPECT_GE(checked, 10);
}

TEST_P(CFixture, Layouts) {
  TypeStore s;
  auto l = load(GetParam(), s);
  if (!l) GTEST_SKIP() << "fixture not built";
  const DebugInfo &info = l->info;

  TypeId flags = find_type(s, info, "flags");
  ASSERT_TRUE(flags.valid());
  EXPECT_EQ(types::definition(s, flags),
            "struct flags {\n"
            "    unsigned int ready : 1; /* 0x0:0 */\n"
            "    unsigned int mode : 3; /* 0x0:1 */\n"
            "    int delta : 4; /* 0x0:4 */\n"
            "    unsigned char tail; /* 0x1 */\n"
            "}; /* size 0x4 */\n");

  TypeId packed = find_type(s, info, "packed_rec");
  ASSERT_TRUE(packed.valid());
  auto *pr = s.get(packed).as<types::AggregateType>();
  EXPECT_TRUE(pr->packed);
  EXPECT_EQ(pr->size, 7u);
  EXPECT_EQ(pr->fields[1].bit_offset, 8u);

  TypeId wa = find_type(s, info, "with_array");
  ASSERT_TRUE(wa.valid());
  EXPECT_EQ(types::definition(s, wa),
            "struct with_array {\n"
            "    int grid[3][4]; /* 0x0 */\n"
            "    char name[16]; /* 0x30 */\n"
            "    int tail[]; /* 0x40 */\n"
            "}; /* size 0x40 */\n");
  EXPECT_FALSE(s.get(wa).as<types::AggregateType>()->packed);

  TypeId am = find_type(s, info, "anon_member");
  ASSERT_TRUE(am.valid());
  EXPECT_EQ(types::definition(s, am),
            "struct anon_member {\n"
            "    int kind; /* 0x0 */\n"
            "    union {\n"
            "        int as_int; /* 0x0 */\n"
            "        double as_double; /* 0x0 */\n"
            "    }; /* 0x8 */\n"
            "}; /* size 0x10 */\n");

  TypeId number = find_type(s, info, "number");
  ASSERT_TRUE(number.valid());
  EXPECT_EQ(s.size_of(number), 4u);
  EXPECT_EQ(s.get(number).as<types::AggregateType>()->kind, types::AggregateKind::Union);

  TypeId color = find_type(s, info, "color");
  ASSERT_TRUE(color.valid());
  EXPECT_EQ(types::definition(s, color), "enum color {\n    RED = 0,\n    GREEN = 5,\n    BLUE = 6\n};\n");
  TypeId sign = find_type(s, info, "sign");
  ASSERT_TRUE(sign.valid());
  EXPECT_EQ(types::definition(s, sign), "enum sign {\n    NEG = -1,\n    ZERO = 0,\n    POS = 1\n};\n");

  EXPECT_EQ(types::definition(s, find_type(s, info, "binop")), "typedef int (*binop)(int, int);\n");
  TypeId ops = find_type(s, info, "ops");
  ASSERT_TRUE(ops.valid());
  EXPECT_EQ(types::definition(s, ops),
            "struct ops {\n"
            "    binop combine; /* 0x0 */\n"
            "    void (*callback)(void *, const char *); /* 0x8 */\n"
            "}; /* size 0x10 */\n");

  // forest <-> tree is a cycle through two named structs.
  TypeId forest = find_type(s, info, "forest");
  ASSERT_TRUE(forest.valid());
  EXPECT_FALSE(s.cycle_of(forest).empty());
  TypeId node = find_type(s, info, "node");
  ASSERT_TRUE(node.valid());
  EXPECT_FALSE(s.cycle_of(node).empty());
}

TEST_P(CFixture, Variables) {
  TypeStore s;
  auto l = load(GetParam(), s);
  if (!l) GTEST_SKIP() << "fixture not built";
  std::map<std::string, std::uint64_t> syms;
  for (const auto &sym : l->image.symbols)
    if (sym.type == loader::SymbolType::object) syms.emplace(sym.name, sym.value);
  std::map<std::string, const Variable *> vars;
  for (const Variable &v : l->info.variables) vars.emplace(v.name, &v);
  ASSERT_TRUE(vars.count("global_counter"));
  ASSERT_TRUE(vars.count("global_list"));
  ASSERT_TRUE(vars.count("global_status"));
  EXPECT_EQ(types::declaration(s, vars["global_counter"]->type, "global_counter"), "int global_counter");
  EXPECT_EQ(types::declaration(s, vars["global_list"]->type, "global_list"),
            "struct node global_list[2]");
  EXPECT_EQ(types::declaration(s, vars["global_status"]->type, "global_status"),
            "volatile uint32_t global_status");
  for (const auto &[name, v] : vars) {
    if (auto it = syms.find(name); it != syms.end()) {
      EXPECT_EQ(v->address, it->second) << name;
    }
  }
  EXPECT_TRUE(vars["global_counter"]->external);
}

INSTANTIATE_TEST_SUITE_P(Builds, CFixture,
                         ::testing::Values("gcc-dwarf5", "gcc-dwarf4", "gcc-O2", "clang-dwarf5",
                                           "clang-dwarf4", "clang-O2", "aarch64-gcc",
                                           "riscv64-gcc"),
                         [](const auto &info) {
                           std::string n = info.param;
                           for (char &c : n)
                             if (c == '-') c = '_';
                           return n;
                         });

// The same source compiled differently must yield the same type hashes.
// Plain char is unsigned on AArch64 and RISC-V, so types mentioning it (ops)
// legitimately differ from x86-64's.
TEST(CrossBuild, SameTypesSameHashes) {
  const std::vector<std::string> names = {"node", "point", "number", "color", "sign", "flags",
                                          "ops", "forest", "tree", "binop", "anon_member"};
  std::map<std::string, std::map<std::string, std::string>> by_build;
  for (const std::string build : {"gcc-dwarf5", "gcc-dwarf4", "gcc-O2", "clang-dwarf5",
                                  "clang-dwarf4", "aarch64-gcc", "riscv64-gcc"}) {
    TypeStore s;
    auto l = load(build, s);
    if (!l) continue;
    for (const std::string &n : names) {
      TypeId id = find_type(s, l->info, n);
      ASSERT_TRUE(id.valid()) << build << " " << n;
      by_build[build][n] = s.hash(id).hex();
    }
  }
  if (by_build.size() < 2) GTEST_SKIP() << "need two builds";
  const auto &ref = by_build.begin()->second;  // aarch64-gcc, if built
  for (const auto &[build, hashes] : by_build)
    for (const std::string &n : names) {
      if (n == "ops" && build.find("gcc-") != 0 && build.find("clang-") != 0) continue;
      if (n == "ops") {
        EXPECT_EQ(hashes.at(n), by_build.at("gcc-dwarf5").at(n)) << build;
        continue;
      }
      EXPECT_EQ(hashes.at(n), ref.at(n)) << n << " differs in " << build << " from "
                                          << by_build.begin()->first;
    }
}

// One store shared by two builds: the second import adds no new types for
// the shared definitions.
TEST(CrossBuild, SharedStoreInterns) {
  TypeStore s;
  auto a = load("gcc-dwarf5", s);
  if (!a) GTEST_SKIP();
  std::size_t after_first = s.size();
  auto b = load("gcc-dwarf4", s);
  if (!b) GTEST_SKIP();
  EXPECT_EQ(find_type(s, a->info, "forest"), find_type(s, b->info, "forest"));
  EXPECT_LE(s.size(), after_first + after_first / 10);
}

class Cxx : public ::testing::TestWithParam<std::string> {};

TEST_P(Cxx, NamesAndMethods) {
  TypeStore s;
  auto l = load(GetParam(), s);
  if (!l) GTEST_SKIP() << "fixture not built";
  std::map<std::string, const Function *> fns;
  for (const Function &f : l->info.functions) fns.emplace(f.qualified_name, &f);
  ASSERT_TRUE(fns.count("geo::Shape::make"));
  const Function *make = fns["geo::Shape::make"];
  EXPECT_EQ(make->name, "make");
  EXPECT_EQ(make->linkage_name, "_ZN3geo5Shape4makeEi");
  EXPECT_EQ(types::prototype(s, make->prototype, make->name), "class geo::Shape *make(int n)");
  ASSERT_TRUE(fns.count("geo::length"));
  EXPECT_EQ(types::prototype(s, fns["geo::length"]->prototype, "length"),
            "double length(const struct geo::Vec &v, struct geo::Vec &&w)");
  ASSERT_TRUE(fns.count("geo::Vec::dot"));
  // GCC declares `this` as a const pointer, clang doesn't.
  const std::string this_const = GetParam().starts_with("clang") ? "" : "const ";
  EXPECT_EQ(types::prototype(s, fns["geo::Vec::dot"]->prototype, "dot"),
            "double dot(const struct geo::Vec *" + this_const + "this, const struct geo::Vec &o)");
  EXPECT_EQ(types::prototype(s, fns["geo::Vec::dot"]->prototype, "dot", {types::Style::Ghidra}),
            "double dot(geo::Vec * this, geo::Vec * o)");
  ASSERT_TRUE(fns.count("geo::Shape::sides"));
  EXPECT_EQ(types::prototype(s, fns["geo::Shape::sides"]->prototype, "sides"),
            "int sides(const class geo::Shape *" + this_const + "this)");
}

// Type units (-fdebug-types-section) give the same types as inline ones.
INSTANTIATE_TEST_SUITE_P(Builds, Cxx,
                         ::testing::Values("gxx-dwarf5", "gxx-typeunits", "clangxx-typeunits"),
                         [](const auto &info) {
                           std::string n = info.param;
                           for (char &c : n)
                             if (c == '-') c = '_';
                           return n;
                         });

}  // namespace
}  // namespace revkit::debuginfo
