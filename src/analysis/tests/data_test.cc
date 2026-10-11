// Data analysis (data.h) and no-return evidence (no_return.h) on a small
// hosted program built at test time, and the string model and labels.

#include "builders.hh"

#include "revkit/analysis/analysis.h"
#include "revkit/analysis/data.h"
#include "revkit/analysis/no_return.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <algorithm>
#include <map>

namespace revkit::analysis {
namespace {

constexpr const char *kSource = R"(
#include <stdio.h>
#include <stdlib.h>
int counter;
static const char *const names[] = {"alpha_name", "beta_name", "gamma_name"};
__attribute__((noinline, noreturn)) void fatal(const char *m) { fputs(m, stderr); exit(2); }
__attribute__((noinline)) int check(int x) { if (x > 100) fatal("too big value"); return x + 1; }
__attribute__((noinline)) int check2(int x) { if (x < -100) fatal("too small value"); return x - 1; }
__attribute__((noinline)) int check3(int x) { if (x == 42) fatal("forbidden value"); return x * 2; }
int main(int argc, char **argv) {
  (void)argv;
  counter = argc;
  printf("Hello, data analysis world: %d %s\n", check(argc) + check2(argc) + check3(argc), names[argc % 3]);
  return 0;
}
)";

struct Program {
  std::shared_ptr<const loader::Image> image;
  std::unique_ptr<facts::FactDb> db = std::make_unique<facts::FactDb>();
  facts::Ref<DataList> data;
  facts::Ref<FunctionList> functions;
  std::vector<std::uint64_t> no_return;
};

std::unique_ptr<Program> analyse(const std::filesystem::path &file) {
  auto p = std::make_unique<Program>();
  p->image = std::make_shared<const loader::Image>(
      loader::load_file(file, {.image_base = std::nullopt, .ghidra_image_base = true}));
  auto lang = loader::guess_language(*p->image);
  if (!lang) throw std::runtime_error("no language");
  register_queries(p->db->engine());
  ProgramInfo info = describe(*p->image, lang->id());
  import_image(*p->db, ProgramKey{}, *p->image, info);
  facts::Snapshot snap = p->db->snapshot();
  p->functions = snap.get<Functions>(ProgramKey{});
  p->data = snap.get<Data>(ProgramKey{});
  p->no_return = *snap.get<NoReturnEvidence>(ProgramKey{});
  return p;
}

std::map<std::string, std::uint64_t> symbols(const std::filesystem::path &file) {
  loader::Image img = loader::load_file(file, {.image_base = std::nullopt, .ghidra_image_base = true});
  std::map<std::string, std::uint64_t> out;
  for (const loader::Symbol &s : img.symbols)
    if (s.defined) out[s.name] = s.value;
  return out;
}

class DataAnalysis : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    lift::initialize(REVKIT_GHIDRA_ROOT);
    dir_ = testing::scratch_dir("data-analysis");
    if (!testing::compile(REVKIT_TEST_CC, kSource, "-O2 -fPIE -pie", dir_ / "named") ||
        !testing::compile(REVKIT_TEST_CC, kSource, "-O2 -fPIE -pie -s", dir_ / "stripped"))
      GTEST_SKIP() << "no C compiler";
  }
  std::filesystem::path dir_;
};

const DataItem *string_item(const DataList &list, const std::string &text) {
  for (const DataItem &d : list.items)
    if (d.kind == DataKind::string && d.text == text) return &d;
  return nullptr;
}

// Constants carried for data references live on across a call only in the
// registers the compiler spec says a call preserves: a PowerPC global's
// address in r31 (callee-saved) still types the load after the call as
// undefined4, one in r3 (the return register) doesn't.
TEST(RawDataAccesses, CalleeSavedRegistersKeepAddressesAcrossCalls) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  const std::vector<std::uint32_t> words = {
      0x3fe00002,  // 00 lis r31,0x2
      0x3bff0010,  // 04 addi r31,r31,0x10     r31 = 0x20010
      0x3c600002,  // 08 lis r3,0x2
      0x38630020,  // 0c addi r3,r3,0x20       r3 = 0x20020
      0x48000021,  // 10 bl 0x30
      0x813f0000,  // 14 lwz r9,0(r31)         a 4-byte global
      0x81430000,  // 18 lwz r10,0(r3)         r3 is the callee's return value
      0x48000000,  // 1c b 0x1c
      0, 0, 0, 0,
      0x4e800020,  // 30 blr
  };
  auto bytes = std::make_shared<loader::Bytes>(words.size() * 4);
  for (std::size_t i = 0; i < words.size(); ++i)
    for (int b = 0; b < 4; ++b) (*bytes)[4 * i + b] = static_cast<std::byte>(words[i] >> (24 - 8 * b));
  loader::RawOptions o;
  o.language = "PowerPC:BE:32:default:default";
  constexpr std::uint64_t base = 0x10000;
  o.base = base;
  o.entry = base;
  o.regions.push_back(loader::parse_raw_region("ram:20000:1000"));
  auto img = std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
  facts::FactDb db;
  register_queries(db.engine());
  ProgramInfo info = describe(*img, o.language);
  EXPECT_FALSE(info.call_preserved.empty());
  import_image(db, ProgramKey{}, *img, info);
  auto data = db.snapshot().get<Data>(ProgramKey{});
  std::map<std::uint64_t, const DataItem *> at;
  for (const DataItem &d : data->items) at[d.address] = &d;
  ASSERT_TRUE(at.contains(0x20010));
  EXPECT_EQ(at[0x20010]->kind, DataKind::undefined);
  EXPECT_EQ(at[0x20010]->length, 4u);
  EXPECT_TRUE(!at.contains(0x20020) || at[0x20020]->length != 4u);
}

TEST(StringModel, ScoresAndLabels) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  ASSERT_TRUE(ngram_model_available());
  EXPECT_TRUE(ngram_valid_string("Hello, data analysis world"));
  EXPECT_TRUE(ngram_valid_string("cannot open file"));
  EXPECT_FALSE(ngram_valid_string("qx#Zv@"));
  EXPECT_FALSE(ngram_valid_string("abc"));  // too short to score
  // StringDataInstance.makeStringLabel: spaces and others as one '_',
  // nothing trailing, at most 32 characters.
  EXPECT_EQ(string_label("s_", "%-10s %08x\n"), "s_%-10s_%08x");
  EXPECT_EQ(string_label("s_", "  two  words  "), "s_two_words");
  EXPECT_EQ(string_label("u_", "(null)"), "u_(null)");
  EXPECT_EQ(string_label("s_", std::string(40, 'a')), "s_" + std::string(32, 'a'));
}

TEST_F(DataAnalysis, StringsPointersAndAccesses) {
  auto named = symbols(dir_ / "named");
  auto p = analyse(dir_ / "stripped");
  const DataList &d = *p->data;
  // A string code refers to, and strings only a pointer table refers to.
  const DataItem *hello = string_item(d, "Hello, data analysis world: %d %s\n");
  ASSERT_NE(hello, nullptr);
  EXPECT_EQ(hello->length, hello->text.size() + 1);  // made by the reference: no padding
  EXPECT_NE(string_item(d, "alpha_name"), nullptr);
  EXPECT_NE(string_item(d, "too big value"), nullptr);
  // The global main writes: undefined4.
  ASSERT_TRUE(named.contains("counter"));
  const DataItem *counter = d.at(named.at("counter"));
  ASSERT_NE(counter, nullptr);
  EXPECT_EQ(counter->kind, DataKind::undefined);
  EXPECT_EQ(counter->length, 4u);
  EXPECT_TRUE(counter->written);
  // Items are sorted and disjoint, and never overlap code.
  for (std::size_t i = 1; i < d.items.size(); ++i) EXPECT_LT(d.items[i - 1].last(), d.items[i].address);
  for (const DataItem &x : d.items)
    for (const CodeUnit &c : p->functions->code)
      if (c.address <= x.last() && x.address < c.address + c.length) ADD_FAILURE() << std::hex << x.address;
}

TEST_F(DataAnalysis, NoReturnEvidenceFindsWhatCallsLeaveBehind) {
  auto named = symbols(dir_ / "named");
  auto p = analyse(dir_ / "stripped");
  ASSERT_TRUE(named.contains("fatal") && named.contains("main"));
  // Three calls each followed by something else: fatal never returns.
  EXPECT_TRUE(std::binary_search(p->no_return.begin(), p->no_return.end(), named.at("fatal")));
  EXPECT_FALSE(std::binary_search(p->no_return.begin(), p->no_return.end(), named.at("main")));
  EXPECT_FALSE(std::binary_search(p->no_return.begin(), p->no_return.end(), named.at("check")));
}

}  // namespace
}  // namespace revkit::analysis
