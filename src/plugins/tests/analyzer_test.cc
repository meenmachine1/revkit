// Analyzer plugins as fact-engine queries: what they derive from a compiled
// fixture, and that a byte patch or an assertion re-runs exactly the
// analyzers that read it.

#include "builders.hh"

#include "revkit/analysis/analysis.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"
#include "revkit/plugins/queries.h"

#include <gtest/gtest.h>

#include <map>
#include <sstream>

namespace revkit::plugins {
namespace {

std::string crc_table_c() {
  std::ostringstream s;
  s << "const unsigned crc_table[256] = {";
  for (unsigned i = 0; i < 256; ++i) {
    unsigned c = i;
    for (int k = 0; k < 8; ++k) c = (c & 1) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
    s << (i ? ", " : "") << c << "u";
  }
  s << "};\n";
  return s.str();
}

// Strings on pages of their own, so a patch to one touches no other fact.
const std::string kFixture = crc_table_c() + R"(
const char greeting[] __attribute__((aligned(4096))) = "hello, plugin";
const char other[] __attribute__((aligned(4096))) = "another string";
__attribute__((noinline)) int sum(const char *s) { int t = 0; while (*s) t += *s++; return t; }
__attribute__((noinline)) int uses_greeting(void) { return sum(greeting); }
__attribute__((noinline)) int uses_other(void) { return sum(other) + 1; }
__attribute__((noinline)) int no_strings(int x) { return x * 3 + 1; }
__attribute__((noinline)) unsigned crc(const unsigned char *p, int n) {
  unsigned c = ~0u;
  while (n--) c = crc_table[(c ^ *p++) & 0xff] ^ (c >> 8);
  return ~c;
}
void _start(void) {
  volatile int r = uses_greeting() + uses_other() + no_strings(3) + (int)crc((const unsigned char *)greeting, 4);
  (void)r;
  for (;;) {}
}
)";

class Analyzers : public ::testing::Test {
 protected:
  void SetUp() override {
    if (!Host::available()) GTEST_SKIP() << "built without wasmtime";
    if (std::string(REVKIT_EXAMPLE_PLUGINS).empty()) GTEST_SKIP() << "example plugins not built (no wasm32 clang)";
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    lift::initialize(REVKIT_GHIDRA_ROOT);
    dir_ = revkit::testing::scratch_dir("plugins-analyzer");
    const std::string flags =
        "-O1 -nostdlib -static -ffreestanding -fno-pie -no-pie -fno-asynchronous-unwind-tables -fno-unwind-tables "
        "-fno-optimize-sibling-calls";
    if (!revkit::testing::compile(REVKIT_TEST_CC, kFixture, flags, dir_ / "named") ||
        !revkit::testing::compile(REVKIT_TEST_CC, kFixture, flags + " -s", dir_ / "stripped"))
      GTEST_SKIP() << "can't build the fixture";
    loader::Image named = loader::load_file(dir_ / "named", {.image_base = std::nullopt, .ghidra_image_base = true});
    for (const loader::Symbol &s : named.symbols)
      if (s.defined) sym_[s.name] = s.value;
    host_ = std::make_unique<Host>();
    auto rejected = host_->load_dir(REVKIT_EXAMPLE_PLUGINS);
    for (const auto &r : rejected) ADD_FAILURE() << r.path << ": " << r.error;
    strings_ = host_->find("string-refs");
    crc_ = host_->find("crc32-tables");
    ASSERT_TRUE(strings_ && crc_);
    db_ = open(dir_ / "stripped");
  }

  std::unique_ptr<facts::FactDb> open(const std::filesystem::path &file) {
    auto db = std::make_unique<facts::FactDb>();
    analysis::register_queries(db->engine());
    register_queries(db->engine());
    image_ = std::make_shared<loader::Image>(loader::load_file(file, {.image_base = std::nullopt, .ghidra_image_base = true}));
    info_ = analysis::describe(*image_, loader::guess_language(*image_)->id());
    auto tx = db->begin();
    analysis::stage_image(tx, kProgram, *image_, info_);
    stage_program(tx, kProgram, *image_, 0, 0);
    tx.commit();
    return db;
  }

  AnalyzeKey fn_key(const Plugin &p, const std::string &fn) {
    return {p.id(), p.fingerprint(), kProgram, abi::Scope::function, sym(fn)};
  }
  AnalyzeKey prog_key(const Plugin &p) { return {p.id(), p.fingerprint(), kProgram, abi::Scope::program, 0}; }
  std::uint64_t sym(const std::string &name) {
    EXPECT_TRUE(sym_.contains(name)) << name;
    return sym_[name];
  }
  // Reads one analyzer result and reports whether the plugin ran for it.
  std::pair<facts::Ref<AnalyzeOutput>, bool> read(facts::FactDb &db, const AnalyzeKey &k) {
    auto before = db.engine().stats<Analyze>().executions;
    auto v = db.snapshot().get<Analyze>(k);
    return {v, db.engine().stats<Analyze>().executions != before};
  }
  static std::vector<std::string> texts(const AnalyzeOutput &o, abi::FactKind kind) {
    std::vector<std::string> out;
    for (const DerivedItem &f : o.facts)
      if (f.kind == kind) out.push_back(f.text);
    return out;
  }

  inline static const analysis::ProgramKey kProgram{"test/fixture"};
  std::filesystem::path dir_;
  std::map<std::string, std::uint64_t> sym_;
  std::unique_ptr<Host> host_;
  std::shared_ptr<const Plugin> strings_, crc_;
  std::shared_ptr<loader::Image> image_;
  analysis::ProgramInfo info_;
  std::unique_ptr<facts::FactDb> db_;
};

TEST_F(Analyzers, DeriveFactsTaggedWithTheirRule) {
  auto [greet, ran] = read(*db_, fn_key(*strings_, "uses_greeting"));
  EXPECT_TRUE(ran);
  ASSERT_EQ(greet->failure, Failure::none) << greet->error;
  EXPECT_EQ(texts(*greet, abi::FactKind::comment), std::vector<std::string>{"\"hello, plugin\""});
  EXPECT_EQ(texts(*greet, abi::FactKind::label), std::vector<std::string>{"str_hello_plugin"});
  EXPECT_EQ(texts(*read(*db_, fn_key(*strings_, "uses_other")).first, abi::FactKind::comment),
            std::vector<std::string>{"\"another string\""});
  EXPECT_TRUE(read(*db_, fn_key(*strings_, "no_strings")).first->facts.empty());

  auto [crc, crc_ran] = read(*db_, prog_key(*crc_));
  ASSERT_EQ(crc->failure, Failure::none) << crc->error;
  ASSERT_EQ(crc->facts.size(), 3u);
  EXPECT_EQ(crc->facts[0].address, sym("crc_table"));
  EXPECT_EQ(crc->facts[0].text, "crc32_table");
  EXPECT_EQ(crc->facts[1].text, "uint32_t[256]");
  EXPECT_NE(crc->facts[2].text.find("0xEDB88320, little-endian"), std::string::npos);
  EXPECT_EQ(crc->log, std::vector<std::string>{"crc32-tables: 1 table(s)"});

  // analyze_keys enumerates one key per discovered function.
  auto keys = analyze_keys(db_->snapshot(), *strings_, kProgram);
  EXPECT_GE(keys.size(), 5u);
  EXPECT_EQ(analyze_keys(db_->snapshot(), *crc_, kProgram).size(), 1u);

  // The memo says what it read: the function's code and the string's page
  // (as patched: bytes.effective).
  auto fact = db_->snapshot().fact<Analyze>(fn_key(*strings_, "uses_greeting"));
  EXPECT_EQ(fact.rule, "plugins.analyze");
  auto has = [&](const std::string &prefix) {
    return std::any_of(fact.inputs.begin(), fact.inputs.end(), [&](const std::string &s) { return s.starts_with(prefix); });
  };
  EXPECT_TRUE(has("plugins.code(")) << ::testing::PrintToString(fact.inputs);
  EXPECT_TRUE(has("bytes.effective(")) << ::testing::PrintToString(fact.inputs);
  EXPECT_TRUE(has("plugins.name(")) << ::testing::PrintToString(fact.inputs);
}

TEST_F(Analyzers, ABytePatchRerunsOnlyTheAnalyzersThatReadIt) {
  for (const char *fn : {"uses_greeting", "uses_other", "no_strings"}) read(*db_, fn_key(*strings_, fn));
  read(*db_, prog_key(*crc_));
  {
    auto tx = db_->begin();
    tx.write_bytes({info_.space, sym("other")}, "A");
    tx.commit();
  }
  EXPECT_FALSE(read(*db_, fn_key(*strings_, "uses_greeting")).second);
  EXPECT_FALSE(read(*db_, fn_key(*strings_, "no_strings")).second);
  auto [other, ran] = read(*db_, fn_key(*strings_, "uses_other"));
  EXPECT_TRUE(ran);
  EXPECT_EQ(texts(*other, abi::FactKind::comment), std::vector<std::string>{"\"Another string\""});
  EXPECT_EQ(texts(*other, abi::FactKind::label), std::vector<std::string>{"str_Another_string"});
  // The CRC scan read every initialized page, that one included.
  EXPECT_TRUE(read(*db_, prog_key(*crc_)).second);
  // Nothing changed since: everything is a hit.
  EXPECT_FALSE(read(*db_, prog_key(*crc_)).second);
}

TEST_F(Analyzers, AnAssertionRerunsOnlyTheAnalyzersThatAskedForIt) {
  for (const char *fn : {"uses_greeting", "uses_other", "no_strings"}) read(*db_, fn_key(*strings_, fn));
  read(*db_, prog_key(*crc_));
  {
    auto tx = db_->begin();
    tx.assert_fact(facts::Provenance::user("tester"), facts::FactKey::name({info_.space, sym("uses_greeting")}),
                   std::string("greet"));
    tx.commit();
  }
  // uses_greeting read its own name to decide on a label; now it has one.
  auto [greet, ran] = read(*db_, fn_key(*strings_, "uses_greeting"));
  EXPECT_TRUE(ran);
  EXPECT_TRUE(texts(*greet, abi::FactKind::label).empty());
  EXPECT_EQ(texts(*greet, abi::FactKind::comment), std::vector<std::string>{"\"hello, plugin\""});
  EXPECT_FALSE(read(*db_, fn_key(*strings_, "uses_other")).second);
  EXPECT_FALSE(read(*db_, fn_key(*strings_, "no_strings")).second);
  EXPECT_FALSE(read(*db_, prog_key(*crc_)).second);
  // Retracting the name brings the label back; the analyzer runs again.
  {
    auto tx = db_->begin();
    tx.revert(facts::Provenance::user("tester"), facts::Provenance::user("tester"));
    tx.commit();
  }
  auto [back, ran2] = read(*db_, fn_key(*strings_, "uses_greeting"));
  EXPECT_TRUE(ran2);
  EXPECT_EQ(texts(*back, abi::FactKind::label), std::vector<std::string>{"str_hello_plugin"});
}

TEST_F(Analyzers, AreDeterministic) {
  // A second store and a second host: the same facts and the same fuel.
  Host other_host;
  other_host.load_dir(REVKIT_EXAMPLE_PLUGINS);
  auto db2 = open(dir_ / "stripped");
  for (const char *fn : {"uses_greeting", "uses_other", "no_strings", "sum", "crc"}) {
    auto a = read(*db_, fn_key(*strings_, fn)).first;
    auto b = read(*db2, fn_key(*other_host.find("string-refs"), fn)).first;
    EXPECT_EQ(*a, *b) << fn;
  }
  EXPECT_EQ(*read(*db_, prog_key(*crc_)).first, *read(*db2, prog_key(*other_host.find("crc32-tables"))).first);
}

TEST_F(Analyzers, AModuleThatIsNotLoadedIsAnErrorNotAMemo) {
  AnalyzeKey k = fn_key(*strings_, "uses_greeting");
  k.fingerprint = std::string(32, '0');
  EXPECT_THROW(db_->snapshot().get<Analyze>(k), std::runtime_error);
}

}  // namespace
}  // namespace revkit::plugins
