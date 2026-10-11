#include "revkit/diff/lsh.h"

#include <gtest/gtest.h>

#include <bit>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace revkit::diff {
namespace {

std::uint64_t bits(double d) { return std::bit_cast<std::uint64_t>(d); }

Weights by_name(const std::string &n) {
  for (Weights w : {Weights::w64, Weights::w64_32, Weights::w32, Weights::nosize})
    if (n == weights_name(w)) return w;
  throw std::runtime_error("unknown weights " + n);
}

TEST(Lsh, WeightsForLanguages) {
  // GenSignatures.getWeightsFile.
  EXPECT_EQ(weights_for("x86:LE:64:default:gcc", "AARCH64:LE:64:v8A:default"), Weights::w64);
  EXPECT_EQ(weights_for("x86:LE:32:default", "ARM:LE:32:v8"), Weights::w32);
  EXPECT_EQ(weights_for("x86:LE:64:default", "ARM:LE:32:v8"), Weights::nosize);
  EXPECT_EQ(weights_for("AARCH64:LE:64:AppleSilicon-32", "AARCH64:LE:64:v8A"), Weights::w64_32);
  EXPECT_EQ(weights_for("toy:BE:16:default", "toy:BE:16:default"), Weights::nosize);
  EXPECT_EQ(weights_for("toy:BE:16:default", "x86:LE:64:default"), std::nullopt);
  EXPECT_EQ(weights_for("JVM:BE:32:default", "JVM:BE:32:default"), std::nullopt);
  EXPECT_EQ(weights_for("x86", "x86:LE:64:default"), std::nullopt);
}

TEST(Lsh, BuiltinTables) {
  for (Weights w : {Weights::w64, Weights::w64_32, Weights::w32, Weights::nosize}) {
    const WeightTable &t = WeightTable::builtin(w);
    EXPECT_EQ(t.idf_entries(), 1000u) << weights_name(w);
    EXPECT_GT(t.scale(), 1.0);
    EXPECT_DOUBLE_EQ(t.file_idf(0), 1.0);
  }
  EXPECT_EQ(WeightTable::builtin(Weights::w64).settings(), 0x49u);
  EXPECT_EQ(WeightTable::builtin(Weights::nosize).settings(), 0x4du);
  // The last entry of lshweights_64.xml.
  EXPECT_EQ(WeightTable::builtin(Weights::w64).idf_count(0xab6831d3u), 511);
  EXPECT_EQ(WeightTable::builtin(Weights::w64).idf_count(0x12345678u), 0);
}

TEST(Lsh, XmlRoundTrip) {
  const WeightTable &t = WeightTable::builtin(Weights::w64);
  WeightTable back = WeightTable::parse(t.to_xml());
  EXPECT_EQ(back.settings(), t.settings());
  EXPECT_EQ(back.idf_entries(), t.idf_entries());
  for (int i = 0; i < WeightTable::kIdfSize; ++i) EXPECT_EQ(bits(back.coeff(i, 3)), bits(t.coeff(i, 3)));
  EXPECT_EQ(bits(back.flip_norm1()), bits(t.flip_norm1()));
  EXPECT_EQ(back.idf_count(0xab6831d3u), 511);
}

TEST(Lsh, BasicCompare) {
  const WeightTable &w = WeightTable::builtin(Weights::w64);
  std::vector<std::uint32_t> a{1, 2, 2, 3, 0xffffffffu};
  LshVector va(a, w), vb(a, w), empty;
  ASSERT_EQ(va.entries().size(), 4u);
  EXPECT_EQ(va.hash_count(), 5);
  EXPECT_EQ(va.entries()[1].tf, 1);
  VectorCompare d;
  EXPECT_NEAR(compare(va, vb, &d), 1.0, 1e-12);
  EXPECT_EQ(d.intersectcount, 5);
  EXPECT_EQ(compare(va, empty), 0.0);
  VectorCompare e;
  compare(empty, empty, &e);
  EXPECT_TRUE(std::isnan(significance(w, e)));
}

TEST(Lsh, DerivedIdfDownweightsCommonHashes) {
  const WeightTable &w = WeightTable::builtin(Weights::w64);
  std::vector<std::vector<std::uint32_t>> corpus;
  for (std::uint32_t i = 0; i < 100; ++i) {
    std::vector<std::uint32_t> f{7, 1000 + i};
    if (i % 10 == 0) f.push_back(9);
    std::sort(f.begin(), f.end());
    corpus.push_back(f);
  }
  WeightTable d = derive_idf(w, corpus, 2);
  EXPECT_EQ(d.idf_entries(), 2u);
  EXPECT_GT(d.idf_count(7), d.idf_count(9));  // in every function: weighs least
  EXPECT_EQ(d.idf_count(9), 0);               // the least common kept: weight 1
  EXPECT_EQ(d.idf_count(1000), 0);            // not kept
}

// Java's values on the same vectors, bit for bit
// (scripts/diff-bsim-reference.py fixtures).
TEST(Lsh, MatchesGhidraJava) {
  std::ifstream in(std::string(REVKIT_DIFF_TEST_DATA) + "/lsh_java_pairs.txt");
  ASSERT_TRUE(in) << "missing fixture";
  std::string line;
  int n = 0, nan_sig = 0;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    std::istringstream s(line);
    std::string wname, cos_hex, sig_hex, self_hex, dot_hex, bar;
    int intersect = 0;
    s >> wname >> cos_hex >> sig_hex >> self_hex >> dot_hex >> intersect >> bar;
    ASSERT_EQ(bar, "|") << line;
    std::vector<std::uint32_t> a, b;
    std::vector<std::uint32_t> *cur = &a;
    std::string tok;
    while (s >> tok) {
      if (tok == "|") {
        cur = &b;
        continue;
      }
      cur->push_back(static_cast<std::uint32_t>(std::stoul(tok, nullptr, 16)));
    }
    const WeightTable &w = WeightTable::builtin(by_name(wname));
    LshVector va(a, w), vb(b, w);
    VectorCompare d;
    const double cos = compare(va, vb, &d);
    const double sig = significance(w, d);
    const double self = self_significance(w, va);
    const auto hex = [](const std::string &h) { return std::stoull(h, nullptr, 16); };
    EXPECT_EQ(bits(cos), hex(cos_hex)) << "cosine, line " << n << ": " << cos;
    EXPECT_EQ(d.intersectcount, intersect) << "line " << n;
    EXPECT_EQ(bits(d.dotproduct), hex(dot_hex)) << "dot product, line " << n;
    if (std::isnan(sig)) {
      ++nan_sig;
      EXPECT_TRUE(std::isnan(std::bit_cast<double>(hex(sig_hex)))) << "line " << n;
    } else {
      EXPECT_EQ(bits(sig), hex(sig_hex)) << "significance, line " << n << ": " << sig;
    }
    EXPECT_EQ(bits(self), hex(self_hex)) << "self significance, line " << n;
    ++n;
  }
  EXPECT_GT(n, 500);
  EXPECT_GT(nan_sig, 0);  // the empty pairs
}

}  // namespace
}  // namespace revkit::diff
