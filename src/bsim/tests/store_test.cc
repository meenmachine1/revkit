#include "revkit/bsim/store.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <random>

#include <unistd.h>

namespace revkit::bsim {
namespace {

namespace fs = std::filesystem;

fs::path fresh_dir(const std::string &name) {
  fs::path d = fs::temp_directory_path() / ("rk-bsim-test-" + std::to_string(::getpid())) / name;
  fs::remove_all(d);
  fs::create_directories(d.parent_path());
  return d;
}

std::vector<std::uint32_t> random_features(std::mt19937 &rng, int n) {
  std::vector<std::uint32_t> v;
  for (int i = 0; i < n; ++i) v.push_back(static_cast<std::uint32_t>(rng()));
  std::sort(v.begin(), v.end());
  return v;
}

// `base` with `change` of its hashes replaced by new ones.
std::vector<std::uint32_t> perturb(std::mt19937 &rng, std::vector<std::uint32_t> base, int change) {
  for (int i = 0; i < change && !base.empty(); ++i) base[rng() % base.size()] = static_cast<std::uint32_t>(rng());
  std::sort(base.begin(), base.end());
  return base;
}

Executable exe(const std::string &id, const std::string &name, const std::string &language = "x86:LE:64:default") {
  Executable e;
  e.id = id;
  e.name = name;
  e.language = language;
  e.compiler = "gcc";
  return e;
}

FunctionRecord fn(const std::string &name, std::uint64_t entry, std::vector<std::uint32_t> features) {
  FunctionRecord f;
  f.name = name;
  f.entry = entry;
  f.size = 16;
  f.prototype = "int " + name + "(int)";
  if (is_default_name(name)) f.flags |= kDefaultName;
  f.features = std::move(features);
  return f;
}

const std::string kA = "aaaaaaaa00000000000000000000000000000000000000000000000000000001";
const std::string kB = "bbbbbbbb00000000000000000000000000000000000000000000000000000002";

TEST(BsimStore, CreateOpenPeek) {
  const fs::path dir = fresh_dir("create");
  DatabaseInfo info;
  info.weights = Template::nosize;
  info.description = "test";
  Database db = Database::create(dir, info);
  EXPECT_EQ(db.info().settings, 0x4du);
  EXPECT_EQ(db.info().name, "create");
  EXPECT_TRUE(Database::looks_like(dir));
  DatabaseInfo p = Database::peek(dir);
  EXPECT_EQ(p.weights, Template::nosize);
  EXPECT_EQ(p.description, "test");
  EXPECT_EQ(p.lsh, db.info().lsh);
  EXPECT_THROW(Database::create(dir, info), BsimError);  // not empty
  EXPECT_THROW(Database::open(dir / "nope"), BsimError);
  EXPECT_EQ(template_for_language("x86:LE:64:default"), Template::w64);
  EXPECT_EQ(template_for_language("ARM:LE:32:v8"), Template::w32);
  EXPECT_EQ(template_for_language("8051:BE:16:default"), Template::nosize);
  EXPECT_EQ(parse_template("medium_32"), Template::w32);
}

TEST(BsimStore, DefaultNames) {
  EXPECT_TRUE(is_default_name("FUN_00401000"));
  EXPECT_TRUE(is_default_name("thunk_FUN_00401000"));
  EXPECT_FALSE(is_default_name("FUN_main"));
  EXPECT_FALSE(is_default_name("inflate"));
}

TEST(BsimStore, CodecRoundTripsAndRefusesDamage) {
  std::mt19937 rng(1);
  Executable e = exe(kA, "zlib");
  e.categories["vendor"] = "madler";
  std::vector<FunctionRecord> fns = {fn("inflate", 0x1000, random_features(rng, 40)),
                                     fn("FUN_00002000", 0x2000, random_features(rng, 5))};
  for (auto &f : fns) f.buckets.assign(4, 7);
  const std::string bytes = encode_executable(e, fns, 4);
  auto [e2, f2] = decode_executable(bytes, 4);
  EXPECT_EQ(e2.name, "zlib");
  EXPECT_EQ(e2.categories.at("vendor"), "madler");
  ASSERT_EQ(f2.size(), 2u);
  EXPECT_EQ(f2[0].features, fns[0].features);
  EXPECT_EQ(f2[1].flags, kDefaultName);
  EXPECT_EQ(f2[0].prototype, "int inflate(int)");
  EXPECT_THROW(decode_executable(bytes, 5), BsimError);
  // Every truncation and many corruptions are a BsimError, never a crash.
  for (std::size_t n = 0; n < bytes.size(); ++n) EXPECT_THROW(decode_executable(bytes.substr(0, n), 4), BsimError) << n;
  for (int i = 0; i < 2000; ++i) {
    std::string bad = bytes;
    for (int j = 0; j < 3; ++j) bad[rng() % bad.size()] = static_cast<char>(rng());
    try {
      decode_executable(bad, 4);
    } catch (const BsimError &) {
    }
  }
}

TEST(BsimStore, AddReplaceRemoveUpdateAndReload) {
  const fs::path dir = fresh_dir("crud");
  Database db = Database::create(dir, {});
  std::mt19937 rng(2);
  auto r = db.add(exe(kA, "one"), {fn("f", 0x10, random_features(rng, 30)), fn("empty", 0x20, {})});
  EXPECT_FALSE(r.replaced);
  EXPECT_EQ(r.functions, 1u);
  EXPECT_EQ(r.empty, 1u);
  db.add(exe(kB, "two"), {fn("g", 0x10, random_features(rng, 30)), fn("h", 0x30, random_features(rng, 30))});
  EXPECT_EQ(db.function_count(), 3u);
  ASSERT_EQ(db.executables().size(), 2u);
  EXPECT_EQ(db.executables()[0]->name, "one");
  EXPECT_EQ(db.executable(kB)->function_count, 2u);
  EXPECT_EQ(db.find_executable("bbbbbbbb"), db.executable(kB));
  EXPECT_EQ(db.find_executable("two"), db.executable(kB));
  EXPECT_EQ(db.find_executable("three"), nullptr);
  // Ingesting the same binary again replaces it.
  r = db.add(exe(kA, "one again"), {fn("f2", 0x10, random_features(rng, 30))});
  EXPECT_TRUE(r.replaced);
  EXPECT_EQ(db.functions(kA)[0].name, "f2");
  EXPECT_EQ(db.function_count(), 3u);
  // Another handle sees the writes; this one sees its.
  Database other = Database::open(dir);
  EXPECT_EQ(other.function_count(), 3u);
  EXPECT_TRUE(other.update(kB, {{"vendor", "x"}}, "renamed"));
  EXPECT_TRUE(other.remove(kA));
  EXPECT_FALSE(other.remove(kA));
  db.reload();
  EXPECT_EQ(db.function_count(), 2u);
  EXPECT_EQ(db.executable(kB)->name, "renamed");
  EXPECT_EQ(db.executable(kB)->categories.at("vendor"), "x");
  EXPECT_EQ(db.executable(kA), nullptr);
  EXPECT_THROW(db.add(exe("../evil", "x"), {}), BsimError);
  // A damaged executable file names itself.
  {
    std::ofstream bad(dir / "exe" / (kA + ".rkbx"), std::ios::binary);
    bad << "RKBSIMX";
  }
  try {
    Database::open(dir);
    ADD_FAILURE() << "opened a damaged database";
  } catch (const BsimError &e) {
    EXPECT_NE(std::string(e.what()).find(kA), std::string::npos) << e.what();
  }
}

TEST(BsimStore, SearchFindsNeighboursWithFilters) {
  const fs::path dir = fresh_dir("search");
  Database db = Database::create(dir, {});
  std::mt19937 rng(3);
  const auto target = random_features(rng, 60);
  std::vector<FunctionRecord> a, b;
  for (int i = 0; i < 300; ++i) a.push_back(fn("a" + std::to_string(i), 0x1000 + i, random_features(rng, 50)));
  a.push_back(fn("target_a", 0x9000, target));
  for (int i = 0; i < 300; ++i) b.push_back(fn("FUN_" + std::to_string(1000 + i), 0x1000 + i, random_features(rng, 50)));
  b.push_back(fn("target_b", 0x9000, perturb(rng, target, 6)));
  db.add(exe(kA, "liba"), a);
  db.add(exe(kB, "libb", "AARCH64:LE:64:v8A"), b);

  SearchOptions o;
  o.exhaustive_below = 0;  // LSH
  SearchStats st;
  auto m = db.search(target, o, &st);
  ASSERT_GE(m.size(), 2u);
  EXPECT_EQ(m[0].function->name, "target_a");
  EXPECT_DOUBLE_EQ(m[0].similarity, 1.0);
  EXPECT_GT(m[0].confidence, 10);
  EXPECT_EQ(m[1].function->name, "target_b");
  EXPECT_GT(m[1].similarity, 0.7);
  EXPECT_LT(st.candidates, st.total / 2) << "LSH scored most of the database";
  EXPECT_EQ(st.total, 602u);

  o.exclude_executables = {"liba"};
  m = db.search(target, o);
  ASSERT_FALSE(m.empty());
  EXPECT_EQ(m[0].function->name, "target_b");
  o.exclude_executables.clear();
  o.languages = {"AARCH64"};
  m = db.search(target, o);
  ASSERT_EQ(m.size(), 1u);
  EXPECT_EQ(m[0].executable->name, "libb");
  o.languages.clear();
  o.name_contains = "TARGET_A";
  m = db.search(target, o);
  ASSERT_EQ(m.size(), 1u);
  o.name_contains.clear();
  o.max_matches = 1;
  EXPECT_EQ(db.search(target, o).size(), 1u);
  o.max_matches = 100;
  o.min_similarity = 1.01;
  EXPECT_TRUE(db.search(target, o).empty());
  o.min_similarity = 0;
  o.exclude_default_names = true;
  for (const Match &x : db.search(target, o)) EXPECT_FALSE(x.function->flags & kDefaultName);
  EXPECT_TRUE(db.search({}, SearchOptions{}).empty());
  EXPECT_GT(db.self_significance(target), 10);
}

// LSH finds what exhaustive search finds for near copies (cosine >= ~0.8).
TEST(BsimStore, LshRecallOnNearCopies) {
  const fs::path dir = fresh_dir("recall");
  Database db = Database::create(dir, {});
  std::mt19937 rng(4);
  std::vector<std::vector<std::uint32_t>> bases;
  std::vector<FunctionRecord> a, b;
  for (int i = 0; i < 400; ++i) {
    bases.push_back(random_features(rng, 20 + static_cast<int>(rng() % 80)));
    a.push_back(fn("f" + std::to_string(i), i, bases.back()));
  }
  db.add(exe(kA, "a"), a);
  int found = 0, eligible = 0;
  for (int i = 0; i < 400; ++i) {
    const auto q = perturb(rng, bases[i], static_cast<int>(bases[i].size() / 10));
    SearchOptions ex;
    ex.exhaustive = true;
    ex.max_matches = 1;
    ex.min_similarity = 0;
    auto truth = db.search(q, ex);
    if (truth.empty() || truth[0].similarity < 0.8) continue;
    ++eligible;
    SearchOptions lsh;
    lsh.max_matches = 1;
    lsh.exhaustive_below = 0;
    auto got = db.search(q, lsh);
    if (!got.empty() && got[0].function == truth[0].function) ++found;
  }
  ASSERT_GT(eligible, 300);
  EXPECT_GE(found, eligible * 97 / 100) << found << " of " << eligible;
}

}  // namespace
}  // namespace revkit::bsim
