#include "builders.hh"
#include "program.h"

#include "revkit/facts/fact_db.h"
#include "revkit/lift/lifter.hh"

#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <tuple>

namespace revkit::backend {
namespace {

std::shared_ptr<const loader::Bytes> ReadFile(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  std::string s((std::istreambuf_iterator<char>(in)), {});
  auto bytes = std::make_shared<loader::Bytes>(s.size());
  std::memcpy(bytes->data(), s.data(), s.size());
  return bytes;
}

// What the queries derive from a program, computed directly: discovery in
// a fact store of its own, then the backend's listing and references.
struct Analysis {
  std::shared_ptr<Program> p;
  std::unique_ptr<facts::FactDb> db;
  analysis::ProgramInfo info;
  facts::Ref<analysis::FunctionList> found;
  FunctionTable functions;
  LabelMap labels;
  CodeMap code;
  RowIndex rows;
  XrefTable xrefs;
  facts::Ref<analysis::DataList> data;

  const Func *function(const std::string &name) const {
    for (const auto &f : functions.funcs)
      if (f.name == name) return &f;
    return nullptr;
  }
};

Analysis Analyze(std::shared_ptr<const loader::Bytes> bytes) {
  Analysis a;
  a.p = Program::Load(std::move(bytes), {});
  a.db = std::make_unique<facts::FactDb>();
  analysis::register_queries(a.db->engine());
  a.info = a.p->Describe(1);
  analysis::import_image(*a.db, {}, a.p->image(), a.info);
  facts::Snapshot snap = a.db->snapshot();
  a.found = snap.get<analysis::Functions>({});
  for (const analysis::FunctionInfo &f : a.found->functions) {
    Func fn;
    fn.entry = f.entry.offset;
    for (const facts::AddressRange &r : f.body.ranges()) fn.body.emplace_back(r.first.offset, r.last.offset);
    fn.name = f.name;
    fn.flags = f.flags;
    a.functions.funcs.push_back(std::move(fn));
    auto refs = a.p->FunctionXrefs(f, *snap.get<analysis::Flow>({{}, f.entry.offset}));
    a.xrefs.xrefs.insert(a.xrefs.xrefs.end(), refs.begin(), refs.end());
  }
  a.functions.index();
  std::sort(a.xrefs.xrefs.begin(), a.xrefs.xrefs.end(), [](const StaticXref &x, const StaticXref &y) {
    return std::tie(x.from, x.to, x.kind) < std::tie(y.from, y.to, y.kind);
  });
  a.xrefs.index();
  a.code = a.p->Code(a.found->code);
  a.data = snap.get<analysis::Data>({});
  a.labels = a.p->DefaultLabels(a.p->LoaderLabels(a.info), a.functions, a.xrefs, *a.data);
  a.rows = a.p->Rows(a.code, a.labels, *a.data);
  return a;
}

class ProgramTest : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    lift::initialize(REVKIT_GHIDRA_ROOT);
  }
};

// Every row's address round-trips through row_at, rows tile each span, and
// pages agree with the index.
void CheckListing(const Analysis &a) {
  const RowIndex &rows = a.rows;
  ASSERT_GT(rows.total_rows, 0);
  for (std::int64_t r = 0; r < rows.total_rows; r += 1 + r / 7) {
    std::uint64_t addr = rows.row_address(r);
    EXPECT_EQ(rows.row_at(addr), r) << std::hex << addr;
  }
  auto page = a.p->Page(rows, 0);
  ASSERT_FALSE(page.empty());
  for (std::size_t i = 0; i < page.size(); ++i) {
    EXPECT_EQ(page[i].address, rows.row_address(static_cast<std::int64_t>(i)));
    if (i + 1 < page.size() && page[i + 1].address > page[i].address) {
      EXPECT_LE(page[i].address + page[i].length, page[i + 1].address);
    }
  }
}

TEST_F(ProgramTest, LuaFromCorpus) {
  std::filesystem::path lua = std::filesystem::path(REVKIT_CORPUS) / "elf-x86_64/gcc-O2/debug/lua";
  if (!std::filesystem::exists(lua)) GTEST_SKIP() << "corpus not built";
  auto t = std::chrono::steady_clock::now();
  Analysis a = Analyze(ReadFile(lua));
  std::cout << "load+analyze " << std::chrono::duration<double>(std::chrono::steady_clock::now() - t).count()
            << " s, rows " << a.rows.total_rows << ", insns " << a.code.instructions << ", functions "
            << a.functions.funcs.size() << ", xrefs " << a.xrefs.xrefs.size() << ", labels " << a.labels.labels.size()
            << "\n";
  EXPECT_EQ(a.p->language().id(), "x86:LE:64:default:gcc");
  EXPECT_GT(a.functions.funcs.size(), 600u);
  EXPECT_GT(a.code.instructions, 40000u);  // 45,000, as rk-lift --analyze lists
  CheckListing(a);

  // Function entries start rows; main's call to luaL_newstate is a CALL xref.
  const Func *main_fn = a.function("main"), *newstate = a.function("luaL_newstate");
  ASSERT_TRUE(main_fn && newstate);
  EXPECT_EQ(a.rows.row_address(a.rows.row_at(main_fn->entry)), main_fn->entry);
  bool found = false;
  for (const StaticXref *x : a.xrefs.to(newstate->entry, newstate->entry))
    found |= x->kind == pb::XREF_KIND_CALL && Contains(main_fn->body, x->from);
  EXPECT_TRUE(found);
  EXPECT_GT(a.xrefs.count_to(newstate->entry), 0u);

  // Page build cost, cold.
  auto t0 = std::chrono::steady_clock::now();
  auto page = a.p->Page(a.rows, a.rows.row_at(main_fn->entry) / RowIndex::kPageRows);
  double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
  std::cout << "cold page " << ms << " ms\n";
  EXPECT_EQ(page.size(), static_cast<std::size_t>(RowIndex::kPageRows));

  // Every value survives its fact-store encoding.
  EXPECT_EQ(facts::encode_to_string(facts::decode_from_string<RowIndex>(facts::encode_to_string(a.rows))),
            facts::encode_to_string(a.rows));
  EXPECT_EQ(facts::decode_from_string<XrefTable>(facts::encode_to_string(a.xrefs)).count_to(newstate->entry),
            a.xrefs.count_to(newstate->entry));
  auto again = facts::decode_from_string<std::vector<StaticRow>>(facts::encode_to_string(page));
  ASSERT_EQ(again.size(), page.size());
  for (std::size_t i = 0; i < page.size(); ++i) EXPECT_EQ(again[i].tokens, page[i].tokens);
}

// The listing's instructions are exactly what discovery reached; what lies
// between (alignment padding, data in code) is undefined data, and the
// jump tables' cases are references from their jumps.
TEST_F(ProgramTest, ListingRowsAreDiscoveredCode) {
  std::filesystem::path bin = std::filesystem::path(REVKIT_CORPUS) / "elf-x86_64/gcc-O2/stripped/zlib";
  if (!std::filesystem::exists(bin)) GTEST_SKIP() << "corpus not built";
  Analysis a = Analyze(ReadFile(bin));
  std::set<std::uint64_t> code;
  for (const analysis::CodeUnit &c : a.found->code) code.insert(c.address);
  std::size_t instructions = 0, padding = 0;
  for (std::int64_t r = 0; r < a.rows.total_rows; ++r) {
    const ListingSpan &s = a.rows.span_of_row(r);
    const std::uint64_t addr = a.rows.row_address(r);
    if (s.code) {
      EXPECT_TRUE(code.contains(addr)) << std::hex << addr;
      ++instructions;
    } else if (a.p->executable(addr)) {
      ++padding;
    }
  }
  EXPECT_EQ(instructions, code.size());
  EXPECT_EQ(a.code.instructions, code.size());
  EXPECT_GT(padding, 0u);
  // Every function's entry starts an instruction row.
  for (const Func &f : a.functions.funcs) {
    std::int64_t r = a.rows.row_at(f.entry);
    EXPECT_EQ(a.rows.row_address(r), f.entry);
    EXPECT_TRUE(a.rows.span_of_row(r).code);
  }
  bool table = false;
  for (const StaticXref &x : a.xrefs.xrefs) table |= x.kind == pb::XREF_KIND_INDIRECT_JUMP;
  EXPECT_TRUE(table);
}

// Data analysis's strings and pointers are data rows named as Ghidra's
// listing names them: ds "text" under s_<text>_<address>, addr <symbol>.
TEST_F(ProgramTest, DataRowsShowStringsAndPointers) {
  std::filesystem::path bin = std::filesystem::path(REVKIT_CORPUS) / "elf-x86_64/gcc-O2/stripped/zlib";
  if (!std::filesystem::exists(bin)) GTEST_SKIP() << "corpus not built";
  Analysis a = Analyze(ReadFile(bin));
  CheckListing(a);
  std::size_t strings = 0, pointers = 0;
  for (const analysis::DataItem &d : a.data->items) {
    if (d.kind == analysis::DataKind::label) continue;
    const std::int64_t r = a.rows.row_at(d.address);
    ASSERT_EQ(a.rows.row_address(r), d.address);
    ASSERT_TRUE(a.rows.span_of_row(r).data);
    auto page = a.p->Page(a.rows, r / RowIndex::kPageRows);
    const StaticRow &row = page[static_cast<std::size_t>(r % RowIndex::kPageRows)];
    EXPECT_EQ(row.kind, pb::LISTING_ROW_KIND_DATA);
    EXPECT_EQ(row.length, d.length) << std::hex << d.address << " kind " << int(d.kind);
    const Label *label = a.labels.find(d.address);
    if (d.kind == analysis::DataKind::string) {
      EXPECT_EQ(row.data_mnemonic, "ds");
      EXPECT_EQ(row.data_value, "\"" + d.text + "\"") << std::hex << d.address;
      ASSERT_NE(label, nullptr);
      EXPECT_TRUE(label->name.starts_with("s_")) << label->name;
      if (++strings > 40) break;
    } else if (d.kind == analysis::DataKind::pointer) {
      EXPECT_EQ(row.data_mnemonic, "addr");
      EXPECT_EQ(row.data_target, d.value);
      ++pointers;
    }
  }
  EXPECT_GT(strings, 20u);
}

// A PIE's pointer tables hold link-time addresses plus RELATIVE
// relocations; after rebasing they must point at the rebased functions.
TEST_F(ProgramTest, RebasedPieHasRelocatedPointers) {
  constexpr const char *kSource = R"(
__attribute__((noinline)) int f(int x) { return x + 1; }
__attribute__((noinline)) int g(int x) { return x * 3; }
int (*const table[])(int) = {f, g};
int main(int argc, char **argv) { (void)argv; return table[argc & 1](argc); }
)";
  auto dir = testing::scratch_dir("backend-reloc");
  auto exe = dir / "pie";
  if (!testing::compile(REVKIT_TEST_CC, kSource, "-O1 -fPIE -pie", exe)) GTEST_SKIP() << "no C compiler";
  Analysis a = Analyze(ReadFile(exe));
  ASSERT_GE(a.p->image().image_base, 0x100000u);  // rebased like a Ghidra import
  std::uint64_t table = 0, f = 0, g = 0;
  for (const Label &l : a.labels.labels)
    if (l.name == "table") table = l.address;
  for (const auto &fn : a.functions.funcs) {
    if (fn.name == "f") f = fn.entry;
    if (fn.name == "g") g = fn.entry;
  }
  ASSERT_TRUE(table && f && g);
  std::string bytes = a.p->read(table, 16);
  ASSERT_EQ(bytes.size(), 16u);
  std::uint64_t first = 0, second = 0;
  std::memcpy(&first, bytes.data(), 8);
  std::memcpy(&second, bytes.data() + 8, 8);
  EXPECT_EQ(first, f);
  EXPECT_EQ(second, g);
}

}  // namespace
}  // namespace revkit::backend
