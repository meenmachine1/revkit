// BSim's feature-vector comparison, ported from Ghidra's Java
// (Ghidra/Framework/Generic, generic.lsh.vector: LSHCosineVector,
// WeightFactory, IDFLookup, LSHVectorFactory.calculateSignificance) so that
// cosine similarity and significance are bit-for-bit the values Ghidra
// computes for the same feature hashes (tests/lsh_test.cc checks them
// against fixtures Ghidra produced, tests/data/lsh_java_pairs.txt).
//
// A function's features are the sorted 32-bit hashes the decompiler's
// GraphSigManager emits (decompd mode signature, signature.h). A vector
// weighs each distinct hash by its term frequency (how often it occurs in
// the function) and its document frequency in BSim's training corpus
// (idflookup: the 1000 most common hashes, rarer ones weigh most).
// Significance is BSim's "confidence": the dot product less a penalty for
// hashes that differ, under BSim's model of hashes flipping, appearing and
// disappearing between versions of a function.
//
// The weight tables are BSim's (third_party/bsim, Apache 2.0), embedded in
// the library; weights_for() picks one the way GenSignatures.getWeightsFile
// does. No LSH buckets: pairwise diffing needs only the comparison.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace revkit::diff {

// BSim's weight tables (third_party/bsim).
enum class Weights : std::uint8_t {
  w64 = 0,     // lshweights_64.xml: both programs 64-bit (settings 0x49)
  w64_32 = 1,  // lshweights_64_32.xml: 64-bit, a language variant with "-32" (0x49)
  w32 = 2,     // lshweights_32.xml: both 32-bit (0x49)
  nosize = 3,  // lshweights_nosize.xml: different sizes, or equal and neither 32 nor 64 (0x4d)
};
const char *weights_name(Weights w);  // "lshweights_64.xml"

// GenSignatures.getWeightsFile for programs of two languages
// ("proc:endian:size:variant[:compiler]"); nullopt where Ghidra has no
// table (fewer than three fields, Dalvik or JVM).
std::optional<Weights> weights_for(std::string_view language_a, std::string_view language_b);

// One weights file: WeightFactory (idf and tf weight curves, the
// significance model) and IDFLookup (document counts of common hashes),
// and the signature settings the vectors it weighs were generated with.
class WeightTable {
 public:
  static constexpr int kIdfSize = 512;
  static constexpr int kTfSize = 64;

  // Parses a weights file (<weights settings=..><weightfactory ..>
  // <idflookup ..></weights>), as LSHVectorFactory.readWeights. Throws
  // std::runtime_error.
  static WeightTable parse(std::string_view xml);
  // The embedded table (parsed once).
  static const WeightTable &builtin(Weights w);

  std::uint32_t settings() const { return settings_; }
  // WeightFactory.getCoeff: idf weight (scaled) times tf weight.
  double coeff(int idf, int tf) const { return idf_[idf] * tf_[tf]; }
  // IDFLookup.getCount: the hash's normalized document count, 0 when the
  // table doesn't hold it (or is empty).
  int idf_count(std::uint32_t hash) const;
  bool has_idf() const { return !counts_.empty(); }
  std::size_t idf_entries() const { return counts_.size(); }

  double scale() const { return scale_; }
  double addend() const { return addend_; }
  double flip_norm0() const { return flip0_ * scale_; }
  double flip_norm1() const { return flip1_ * scale_; }
  double diff_norm0() const { return diff0_ * scale_; }
  double diff_norm1() const { return diff1_ * scale_; }
  // The idf weight curve as the file holds it (unscaled), index 0..511.
  double file_idf(int i) const;
  // -log2(document probability of the least common hash in the table)
  // (the file's weightnorm, unscaled).
  double weight_norm() const { return weightnorm_; }

  // This table with its idf lookup replaced by `counts` (hash, normalized
  // document count 0..511): the curves and the significance model stay.
  WeightTable with_idf(const std::vector<std::pair<std::uint32_t, int>> &counts) const;
  // The table as a weights file (what parse() reads back).
  std::string to_xml() const;

 private:
  std::uint32_t settings_ = 0;
  std::array<double, kIdfSize> idf_{};  // scaled by sqrt(scale), as WeightFactory holds them
  std::array<double, kTfSize> tf_{};
  double weightnorm_ = 0;               // as WeightFactory holds it (the file's / scale)
  double flip0_ = 0, flip1_ = 0, diff0_ = 0, diff1_ = 0;
  double scale_ = 0, addend_ = 0;
  std::unordered_map<std::uint32_t, int> counts_;
};

// Re-derives the idf lookup of `base` from a corpus of feature vectors (each
// a function's sorted hashes): the `entries` hashes found in the most
// functions, each given the count whose weight on base's idf curve is
// closest to -log2(p) / -log2(p_last), p being the fraction of functions
// holding the hash and p_last that of the least common one kept (the
// normalization BSim's weightnorm describes). Deterministic: ties in
// frequency break on the hash.
WeightTable derive_idf(const WeightTable &base, const std::vector<std::vector<std::uint32_t>> &corpus,
                       std::size_t entries = 1000);

// HashEntry: one distinct hash of a vector.
struct HashEntry {
  std::uint32_t hash = 0;
  std::uint16_t tf = 0;   // occurrences - 1, at most 63
  std::uint16_t idf = 0;  // the lookup's count, at most 511
  double coeff = 0;
};

// LSHCosineVector.
class LshVector {
 public:
  LshVector() = default;
  // `features`: hashes sorted ascending as unsigned (the decompiler's
  // order), repeats adjacent.
  LshVector(std::span<const std::uint32_t> features, const WeightTable &weights);

  const std::vector<HashEntry> &entries() const { return entries_; }
  double length() const { return length_; }
  int hash_count() const { return hash_count_; }  // with multiplicity
  bool empty() const { return entries_.empty(); }

 private:
  std::vector<HashEntry> entries_;
  double length_ = 0;
  int hash_count_ = 0;
};

// VectorCompare: what compare() leaves for calculate_significance.
struct VectorCompare {
  double dotproduct = 0;
  int acount = 0, bcount = 0, intersectcount = 0;
  int min = 0, max = 0, numflip = 0, diff = 0;
  void fill_out();
};

// LSHCosineVector.compare: the cosine of the two weighted vectors (0 when
// either is empty); fills `data` if given.
double compare(const LshVector &a, const LshVector &b, VectorCompare *data = nullptr);
// LSHVectorFactory.calculateSignificance (calls data.fill_out()). NaN for
// two empty vectors, as in Java.
double significance(const WeightTable &weights, VectorCompare &data);
// LSHVectorFactory.getSelfSignificance.
double self_significance(const WeightTable &weights, const LshVector &v);

}  // namespace revkit::diff
