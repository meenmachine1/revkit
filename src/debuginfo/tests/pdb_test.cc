// PDB reader tests on PE fixtures built at test time by clang for mingw
// with lld (see CMakeLists.txt). The fixtures carry CodeView in a PDB and
// DWARF in the image for the same code, so most checks compare the two.
#include "revkit/debuginfo/dwarf.h"
#include "revkit/debuginfo/image.h"
#include "revkit/debuginfo/pdb.h"
#include "revkit/loader/load.hh"
#include "revkit/types/print.h"
#include "revkit/types/transform.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <set>

namespace revkit::debuginfo {
namespace {

using types::TypeId;
using types::TypeStore;

std::string fixture_path(const std::string &name) {
  return std::string(REVKIT_FIXTURE_DIR) + "/" + name;
}

std::vector<std::uint8_t> read_bytes(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

struct Pe {
  loader::Image image;
  std::vector<std::uint8_t> pdb_bytes;
  PdbDebugInfo pdb;
  ImageSections sections;
  DebugInfo dwarf;

  const Function *pdb_fn(std::string_view qualified) const {
    for (const Function &f : pdb.functions)
      if (f.qualified_name == qualified) return &f;
    return nullptr;
  }
  const Function *dwarf_at(std::uint64_t entry) const {
    for (const Function &f : dwarf.functions)
      if (f.entry == entry) return &f;
    return nullptr;
  }
};

std::optional<Pe> load(const std::string &name, TypeStore &store) {
  std::string exe = fixture_path(name + ".exe");
  if (!std::filesystem::exists(exe)) {
    // The build probes the toolchain; if it could write PDBs, the fixture
    // must exist.
    if (REVKIT_PE_FIXTURES) ADD_FAILURE() << exe << " missing";
    return std::nullopt;
  }
  Pe pe;
  pe.image = loader::load_file(exe);
  pe.pdb_bytes = read_bytes(fixture_path(name + ".pdb"));
  PdbOptions opt;
  opt.image_base = pe.image.image_base;
  pe.pdb = read_pdb(pe.pdb_bytes, store, opt);
  pe.sections = dwarf_sections(pe.image);
  pe.dwarf = import_dwarf(pe.sections.sections, store);
  return pe;
}

// Prototypes as fixture.c declares them, as CodeView records them: no
// typedefs (size_t, binop, ulong_t, point's typedef name is its tag), LLP64.
const std::map<std::string, std::string> kPrototypes = {
    {"add", "int add(int a, int b)"},
    {"sum_ints", "long sum_ints(int count, ...)"},
    {"fold", "int fold(const int *values, unsigned long long n, int (*f)(int, int), int init)"},
    {"apply", "void apply(struct ops *o, void *ctx)"},
    {"list_push", "struct node *list_push(struct node *head, int v)"},
    {"point_add", "struct point point_add(struct point a, struct point b)"},
    {"pack_flags", "unsigned int pack_flags(struct flags f)"},
    {"color_weight", "int color_weight(enum color c, enum sign s)"},
    {"as_float", "float as_float(union number n)"},
    {"matmul", "void matmul(int (*a)[4], int (*m)[4], unsigned long rows)"},
    {"split", "char **split(char *s, char sep, int *count)"},
    {"forest_size", "int forest_size(const struct forest *f, struct tree *t)"},
    {"packed_value",
     "double packed_value(struct packed_rec *r, struct with_array *w, struct anon_member *m)"},
    {"pick", "int (*pick(int which))(int, int)"},
    {"no_args", "void no_args(void)"},
    {"helper", "int helper(int x)"},
    {"main", "int main(int argc, char **argv)"},
};

class PeFixture : public ::testing::TestWithParam<std::string> {};

// The fixture really is CodeView: an RSDS record naming a PDB with this
// GUID and age, and clang-compiled modules with procedures and their
// parameters in the PDB.
TEST_P(PeFixture, ReallyCodeView) {
  TypeStore s;
  auto pe = load(GetParam(), s);
  if (!pe) GTEST_SKIP() << "fixture not built";
  ASSERT_TRUE(pe->image.codeview);
  EXPECT_TRUE(pe->image.codeview->rsds);
  EXPECT_EQ(std::filesystem::path(pe->image.codeview->pdb_path).filename(), GetParam() + ".pdb");
  PdbIdentity id = read_pdb_identity(pe->pdb_bytes);
  EXPECT_TRUE(id.matches(pe->image.codeview->guid, pe->image.codeview->age));
  EXPECT_EQ(id.guid, pe->pdb.identity.guid);
  EXPECT_EQ(id.machine, 0x8664);
  EXPECT_TRUE(id.has_ipi);
  EXPECT_TRUE(id.named_streams.count("/names"));
  EXPECT_EQ(guid_string(id.guid).size(), 38u);
  PdbGuid other = id.guid;
  other[0] ^= 1;
  EXPECT_FALSE(id.matches(other, pe->image.codeview->age));

  EXPECT_TRUE(pe->pdb.diagnostics.empty()) << pe->pdb.diagnostics.front().message;
  bool clang_module = false;
  for (const PdbModule &m : pe->pdb.modules)
    if (m.compiler.find("clang") != std::string::npos && m.stream != 0xffff) clang_module = true;
  EXPECT_TRUE(clang_module);
  ASSERT_GE(pe->pdb.functions.size(), 5u);
  const Function *main_fn = pe->pdb_fn("main");
  ASSERT_NE(main_fn, nullptr);
  if (GetParam().find("xx") == std::string::npos) {
    EXPECT_EQ(main_fn->param_names, (std::vector<std::string>{"argc", "argv"}));
  }
  EXPECT_TRUE(main_fn->external);

  // Section headers match the image's.
  ASSERT_FALSE(pe->pdb.sections.empty());
  EXPECT_EQ(pe->pdb.sections[0].name, ".text");
  EXPECT_EQ(pe->pdb.sections[0].virtual_address + pe->image.image_base,
            loader::find_section(pe->image, ".text")->addr);
}

TEST_P(PeFixture, Prototypes) {
  if (GetParam().find("xx") != std::string::npos) GTEST_SKIP() << "C fixture only";
  TypeStore s;
  auto pe = load(GetParam(), s);
  if (!pe) GTEST_SKIP() << "fixture not built";
  const bool optimized = GetParam().find("O2") != std::string::npos;
  for (const auto &[name, proto] : kPrototypes) {
    const Function *f = pe->pdb_fn(name);
    if (!f) {
      EXPECT_TRUE(optimized) << name << " missing";
      continue;
    }
    ASSERT_TRUE(f->prototype.valid()) << name;
    EXPECT_EQ(types::prototype(s, f->prototype, f->name), proto);
  }
  // Ghidra notation, as rk-debuginfo writes it.
  const Function *fold = pe->pdb_fn("fold");
  ASSERT_NE(fold, nullptr);
  EXPECT_EQ(types::prototype(s, fold->prototype, "fold", {types::Style::Ghidra}),
            "int fold(int * values, ulonglong n, _func_int_int_int * f, int init)");
}

// Every PDB procedure is where DWARF says it is, with the same extent.
TEST_P(PeFixture, EntriesMatchDwarf) {
  TypeStore s;
  auto pe = load(GetParam(), s);
  if (!pe) GTEST_SKIP() << "fixture not built";
  int checked = 0;
  for (const Function &f : pe->pdb.functions) {
    ASSERT_EQ(f.ranges.size(), 1u) << f.qualified_name;
    EXPECT_TRUE(is_code(pe->image, f.entry)) << f.qualified_name;
    const Function *d = pe->dwarf_at(f.entry);
    ASSERT_NE(d, nullptr) << f.qualified_name << " has no DWARF subprogram";
    EXPECT_EQ(f.name, d->name);
    EXPECT_EQ(f.qualified_name, d->qualified_name);
    EXPECT_EQ(f.ranges, d->ranges) << f.qualified_name;
    EXPECT_EQ(f.param_names, d->param_names) << f.qualified_name;
    ++checked;
  }
  EXPECT_GE(checked, 5);
}

// The point of importing into one content-hashed store: the same C type
// from DWARF and from the PDB is the same TypeId. DWARF has typedefs and
// CodeView doesn't, so the DWARF side is compared with its typedefs
// resolved (and anonymous tags named by their typedef, as CodeView does).
TEST_P(PeFixture, HashesAgreeWithDwarf) {
  TypeStore s;
  auto pe = load(GetParam(), s);
  if (!pe) GTEST_SKIP() << "fixture not built";
  const types::WithoutTypedefsOptions resolve{.name_anonymous_tags = true};
  // CodeView flattens an anonymous union member into its parent's fields.
  const std::set<std::string> exceptions = {"packed_value", "anon_member"};

  int agree = 0;
  for (const Function &f : pe->pdb.functions) {
    const Function *d = pe->dwarf_at(f.entry);
    ASSERT_NE(d, nullptr);
    TypeId dwarf = types::without_typedefs(s, d->prototype, resolve);
    if (exceptions.count(f.name)) {
      EXPECT_NE(dwarf, f.prototype) << f.name;
      continue;
    }
    EXPECT_EQ(dwarf, f.prototype) << f.qualified_name << "\n  PDB:   "
                                  << types::prototype(s, f.prototype, f.name) << "\n  DWARF: "
                                  << types::prototype(s, dwarf, f.name);
    agree += dwarf == f.prototype;
  }
  EXPECT_GE(agree, 5);

  // Named aggregates and enums.
  std::map<std::string, TypeId> dwarf_tags;
  for (TypeId id : pe->dwarf.types) {
    TypeId r = types::without_typedefs(s, id, resolve);
    const types::Type &t = s.get(r);
    if (auto *a = t.as<types::AggregateType>(); a && a->complete && !a->name.empty())
      dwarf_tags.emplace(a->name, r);
    if (auto *e = t.as<types::EnumType>(); e && !e->name.empty()) dwarf_tags.emplace(e->name, r);
  }
  int tags = 0;
  for (TypeId id : pe->pdb.types) {
    const types::Type &t = s.get(id);
    std::string name;
    if (auto *a = t.as<types::AggregateType>(); a && a->complete) name = a->name;
    if (auto *e = t.as<types::EnumType>()) name = e->name;
    auto it = dwarf_tags.find(name);
    if (name.empty() || it == dwarf_tags.end()) continue;
    if (exceptions.count(name)) {
      EXPECT_NE(it->second, id) << name;
      continue;
    }
    EXPECT_EQ(it->second, id) << name << "\n  PDB:\n" << types::definition(s, id) << "  DWARF:\n"
                              << types::definition(s, it->second);
    ++tags;
  }
  EXPECT_GE(tags, GetParam().find("xx") != std::string::npos ? 2 : 10);
}

TEST_P(PeFixture, Layouts) {
  if (GetParam().find("xx") != std::string::npos) GTEST_SKIP() << "C fixture only";
  TypeStore s;
  auto pe = load(GetParam(), s);
  if (!pe) GTEST_SKIP() << "fixture not built";
  std::map<std::string, TypeId> tags;
  for (TypeId id : pe->pdb.types) {
    const types::Type &t = s.get(id);
    if (auto *a = t.as<types::AggregateType>(); a && a->complete) tags.emplace(a->name, id);
    if (auto *e = t.as<types::EnumType>()) tags.emplace(e->name, id);
  }
  ASSERT_TRUE(tags.count("flags"));
  EXPECT_EQ(types::definition(s, tags["flags"]),
            "struct flags {\n"
            "    unsigned int ready : 1; /* 0x0:0 */\n"
            "    unsigned int mode : 3; /* 0x0:1 */\n"
            "    int delta : 4; /* 0x0:4 */\n"
            "    unsigned char tail; /* 0x4 */\n"
            "}; /* size 0x8 */\n");
  ASSERT_TRUE(tags.count("packed_rec"));
  auto *pr = s.get(tags["packed_rec"]).as<types::AggregateType>();
  EXPECT_TRUE(pr->packed);
  EXPECT_EQ(pr->size, 7u);
  ASSERT_TRUE(tags.count("with_array"));
  EXPECT_EQ(types::definition(s, tags["with_array"]),
            "struct with_array {\n"
            "    int grid[3][4]; /* 0x0 */\n"
            "    char name[16]; /* 0x30 */\n"
            "    int tail[]; /* 0x40 */\n"
            "}; /* size 0x40 */\n");
  EXPECT_FALSE(s.get(tags["with_array"]).as<types::AggregateType>()->packed);
  // CodeView flattens the anonymous union.
  ASSERT_TRUE(tags.count("anon_member"));
  EXPECT_EQ(types::definition(s, tags["anon_member"]),
            "struct anon_member {\n"
            "    int kind; /* 0x0 */\n"
            "    int as_int; /* 0x8 */\n"
            "    double as_double; /* 0x8 */\n"
            "}; /* size 0x10 */\n");
  ASSERT_TRUE(tags.count("number"));
  EXPECT_EQ(s.get(tags["number"]).as<types::AggregateType>()->kind, types::AggregateKind::Union);
  EXPECT_EQ(s.size_of(tags["number"]), 4u);
  ASSERT_TRUE(tags.count("color"));
  EXPECT_EQ(types::definition(s, tags["color"]), "enum color {\n    RED = 0,\n    GREEN = 5,\n    BLUE = 6\n};\n");
  ASSERT_TRUE(tags.count("sign"));
  EXPECT_EQ(types::definition(s, tags["sign"]), "enum sign {\n    NEG = -1,\n    ZERO = 0,\n    POS = 1\n};\n");
  ASSERT_TRUE(tags.count("ops"));
  EXPECT_EQ(types::definition(s, tags["ops"]),
            "struct ops {\n"
            "    int (*combine)(int, int); /* 0x0 */\n"
            "    void (*callback)(void *, const char *); /* 0x8 */\n"
            "}; /* size 0x10 */\n");
  // Forward references resolve: forest <-> tree is a cycle.
  ASSERT_TRUE(tags.count("forest"));
  EXPECT_FALSE(s.cycle_of(tags["forest"]).empty());
  ASSERT_TRUE(tags.count("node"));
  EXPECT_FALSE(s.cycle_of(tags["node"]).empty());

  // S_UDT: typedefs become typedef types; tag names don't.
  std::map<std::string, TypeId> names;
  for (const PdbTypeName &n : pe->pdb.type_names) names.emplace(n.name, n.type);
  ASSERT_TRUE(names.count("binop"));
  EXPECT_EQ(types::definition(s, names["binop"]), "typedef int (*binop)(int, int);\n");
  ASSERT_TRUE(names.count("point"));
  EXPECT_EQ(names["point"], tags["point"]);

  // LF_UDT_SRC_LINE: each struct's declaring file (types' categories); a
  // typedef CodeView has no record for, its type's. DWARF says the same.
  auto file = [](const DebugInfo &info, TypeId id) {
    auto it = info.type_files.find(id);
    return it == info.type_files.end() ? std::string() : std::filesystem::path(it->second).filename().string();
  };
  EXPECT_EQ(file(pe->pdb, tags["flags"]), "fixture.c");
  EXPECT_EQ(file(pe->pdb, tags["color"]), "fixture.c");
  EXPECT_EQ(file(pe->pdb, names["binop"]), "");  // a function pointer typedef: no UDT record
  for (TypeId id : pe->dwarf.types)
    if (const auto *a = s.get(id).as<types::AggregateType>(); a && a->name == "flags" && a->complete)
      EXPECT_EQ(file(pe->dwarf, id), "fixture.c");
}

TEST_P(PeFixture, Variables) {
  if (GetParam().find("xx") != std::string::npos) GTEST_SKIP() << "C fixture only";
  TypeStore s;
  auto pe = load(GetParam(), s);
  if (!pe) GTEST_SKIP() << "fixture not built";
  std::map<std::string, const Variable *> pdb, dwarf;
  for (const Variable &v : pe->pdb.variables) pdb.emplace(v.name, &v);
  for (const Variable &v : pe->dwarf.variables) dwarf.emplace(v.name, &v);
  for (const char *name : {"global_counter", "global_list", "global_status"}) {
    ASSERT_TRUE(pdb.count(name)) << name;
    ASSERT_TRUE(dwarf.count(name)) << name;
    EXPECT_EQ(pdb[name]->address, dwarf[name]->address) << name;
    EXPECT_EQ(pdb[name]->type, types::without_typedefs(s, dwarf[name]->type)) << name;
  }
  EXPECT_TRUE(pdb["global_counter"]->external);
  EXPECT_EQ(types::declaration(s, pdb["global_status"]->type, "global_status"),
            "volatile unsigned int global_status");
}

TEST_P(PeFixture, LocalsPublicsContributions) {
  TypeStore s;
  auto pe = load(GetParam(), s);
  if (!pe) GTEST_SKIP() << "fixture not built";
  const Function *main_fn = pe->pdb_fn("main");
  ASSERT_NE(main_fn, nullptr);
  std::vector<std::string> params;
  for (const LocalVariable &v : main_fn->locals) {
    if (v.is_param) params.push_back(v.name);
    if (GetParam().find("O0") != std::string::npos) {
      EXPECT_NE(v.location, LocalVariable::Location::Unknown) << v.name;
    }
  }
  if (GetParam().find("xx") == std::string::npos) {
    EXPECT_EQ(params, (std::vector<std::string>{"argc", "argv"}));
  }

  // Publics carry the link names, mapped to the same addresses.
  bool found = false;
  for (const PdbPublic &p : pe->pdb.publics)
    if (p.name == "main") {
      found = true;
      EXPECT_TRUE(p.function);
      EXPECT_EQ(p.address, main_fn->entry);
    }
  EXPECT_TRUE(found);
  EXPECT_TRUE(std::is_sorted(pe->pdb.publics.begin(), pe->pdb.publics.end(),
                             [](const PdbPublic &a, const PdbPublic &b) { return a.address < b.address; }));

  // A section contribution from the fixture's module covers main.
  bool covered = false;
  for (const PdbContribution &c : pe->pdb.contributions) {
    if (c.address <= main_fn->entry && main_fn->entry < c.address + c.size) {
      ASSERT_LT(c.module, pe->pdb.modules.size());
      EXPECT_NE(pe->pdb.modules[c.module].compiler.find("clang"), std::string::npos);
      covered = true;
    }
  }
  EXPECT_TRUE(covered);
}

INSTANTIATE_TEST_SUITE_P(Builds, PeFixture,
                         ::testing::Values("pe-clang-O0", "pe-clang-O2", "pe-clangxx-O0"),
                         [](const auto &info) {
                           std::string n = info.param;
                           for (char &c : n)
                             if (c == '-') c = '_';
                           return n;
                         });

TEST(PeCxx, Methods) {
  TypeStore s;
  auto pe = load("pe-clangxx-O0", s);
  if (!pe) GTEST_SKIP() << "fixture not built";
  const Function *dot = pe->pdb_fn("geo::Vec::dot");
  ASSERT_NE(dot, nullptr);
  EXPECT_EQ(dot->name, "dot");
  EXPECT_EQ(types::prototype(s, dot->prototype, "dot"),
            "double dot(const struct geo::Vec *this, const struct geo::Vec &o)");
  const Function *length = pe->pdb_fn("geo::length");
  ASSERT_NE(length, nullptr);
  EXPECT_EQ(types::prototype(s, length->prototype, "length"),
            "double length(const struct geo::Vec &v, struct geo::Vec &&w)");
  const Function *make = pe->pdb_fn("geo::Shape::make");
  ASSERT_NE(make, nullptr);
  EXPECT_EQ(types::prototype(s, make->prototype, "make"), "class geo::Shape *make(int n)");
  // The public symbol for it is the mangled name.
  EXPECT_EQ(make->linkage_name, "_ZN3geo5Shape4makeEi");
  bool demangled = false;
  for (const PdbPublic &p : pe->pdb.publics)
    if (p.name == "_ZN3geo5Shape4makeEi") demangled = p.demangled == "geo::Shape::make(int)";
  EXPECT_TRUE(demangled);
}

}  // namespace
}  // namespace revkit::debuginfo
