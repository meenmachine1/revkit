// rk-sigdiff: BSim signature measurements over two builds of a program
// (docs/diff.md, "Signatures"), with revkit's C++ comparison (src/diff).
//
//   rk-sigdiff stability A.json B.json [--weights auto|64|64_32|32|nosize|FILE.xml] [--label L]
//       The design's table (docs/diff/design.md §0): functions present
//       once by name on both sides (names are the truth: debug builds),
//       median cosine to the true counterpart, the fraction identical and
//       at >= 0.7, strict top-1 (the true counterpart scores above every
//       other function of B; ties lose) overall and by A's distinct
//       features (<10, 10-29, 30-99, >=100), median significance, and the
//       residue matcher (match_residue over every pair: mutual best,
//       cosine >= 0.35, significance >= 10) as precision and recall. One
//       JSON object on stdout.
//   rk-sigdiff derive-idf OUT.xml [--base 64|...] [--entries N] IN.json...
//       BSim's weights with the idf lookup re-derived from the functions
//       of the given files (derive_idf).
//
// Inputs are rk-lift --signatures documents ({"language", "functions":
// [{"name", "status", "features"}]}) or scripts/diff-bsim-reference.py dump
// documents ({"language", "functions": {name: {"features"}}}).
#include "json.hh"

#include "revkit/diff/lsh.h"
#include "revkit/diff/residue.h"

#include <algorithm>
#include <cmath>
#include <optional>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

using rklift::Json;
using namespace revkit::diff;

struct Program {
  std::string language;
  std::map<std::string, std::vector<std::uint32_t>> functions;  // unique names only
  std::size_t total = 0;                                         // signed functions
};

std::string read_file(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw std::runtime_error("cannot read " + path);
  std::ostringstream s;
  s << in.rdbuf();
  return s.str();
}

Program load(const std::string &path) {
  Json doc = Json::parse(read_file(path));
  Program p;
  if (const Json *l = doc.find("language"); l && l->is_string()) p.language = l->str();
  std::map<std::string, int> seen;
  auto add = [&](const std::string &name, const Json &features) {
    std::vector<std::uint32_t> f;
    for (const Json &h : features.array()) f.push_back(static_cast<std::uint32_t>(h.uint64()));
    std::sort(f.begin(), f.end());
    ++p.total;
    if (++seen[name] == 1) p.functions[name] = std::move(f);
    else p.functions.erase(name);
  };
  const Json &fns = doc["functions"];
  if (fns.is_array()) {
    for (const Json &f : fns.array()) {
      if (f["status"].is_string() && f["status"].str() != "ok") continue;
      add(f["name"].str(), f["features"]);
    }
  } else if (fns.is_object()) {
    for (const auto &[name, f] : fns.object()) add(name, f["features"]);
  }
  return p;
}

const WeightTable &table_named(const std::string &w, const std::string &la, const std::string &lb,
                               std::optional<WeightTable> &owned) {
  if (w == "auto") {
    std::optional<Weights> k = weights_for(la, lb);
    return WeightTable::builtin(k.value_or(Weights::nosize));
  }
  if (w == "64") return WeightTable::builtin(Weights::w64);
  if (w == "64_32") return WeightTable::builtin(Weights::w64_32);
  if (w == "32") return WeightTable::builtin(Weights::w32);
  if (w == "nosize") return WeightTable::builtin(Weights::nosize);
  owned = WeightTable::parse(read_file(w));
  return *owned;
}

double median(std::vector<double> v) {
  if (v.empty()) return 0;
  std::sort(v.begin(), v.end());
  return v[v.size() / 2];
}

double round3(double x) { return std::round(x * 1000) / 1000; }

int stability(int argc, char **argv) {
  std::vector<std::string> files;
  std::string weights = "auto", label;
  for (int i = 2; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--weights" && i + 1 < argc) weights = argv[++i];
    else if (a == "--label" && i + 1 < argc) label = argv[++i];
    else files.push_back(a);
  }
  if (files.size() != 2) {
    std::cerr << "usage: rk-sigdiff stability A.json B.json [--weights auto|64|32|nosize|FILE] [--label L]\n";
    return 2;
  }
  Program pa = load(files[0]), pb = load(files[1]);
  std::optional<WeightTable> owned;
  const WeightTable &w = table_named(weights, pa.language, pb.language, owned);
  std::vector<std::string> bnames;
  std::vector<LshVector> bvecs;
  for (const auto &[n, f] : pb.functions) {
    bnames.push_back(n);
    bvecs.emplace_back(f, w);
  }
  std::vector<double> sims, sigs;
  std::size_t common = 0, top1 = 0, identical = 0, ge07 = 0;
  std::map<std::string, std::pair<std::size_t, std::size_t>> buckets;
  for (const auto &[name, fa] : pa.functions) {
    auto tb = pb.functions.find(name);
    if (tb == pb.functions.end()) continue;
    ++common;
    LshVector va(fa, w);
    const std::size_t truth = static_cast<std::size_t>(std::distance(pb.functions.begin(), tb));
    VectorCompare d;
    const double s_true = compare(va, bvecs[truth], &d);
    sigs.push_back(significance(w, d));
    sims.push_back(s_true);
    if (s_true >= 0.999999) ++identical;
    if (s_true >= 0.7) ++ge07;
    double best_other = -1;
    for (std::size_t k = 0; k < bvecs.size(); ++k)
      if (k != truth) best_other = std::max(best_other, compare(va, bvecs[k]));
    const bool is_top1 = s_true > best_other;
    top1 += is_top1;
    const std::size_t n = va.entries().size();
    const char *bk = n < 10 ? "<10" : n < 30 ? "10-29" : n < 100 ? "30-99" : ">=100";
    buckets[bk].first += 1;
    buckets[bk].second += is_top1;
  }
  // The residue matcher over everything.
  std::vector<ResidueFunction> ra, rb;
  std::vector<std::string> anames;
  for (const auto &[n, f] : pa.functions) {
    ra.push_back({ra.size(), f});
    anames.push_back(n);
  }
  for (const auto &[n, f] : pb.functions) rb.push_back({rb.size(), f});
  ResidueResult r = match_residue(ra, rb, nullptr, {}, w);
  std::size_t correct = 0;
  std::map<std::string, std::pair<std::size_t, std::size_t>> bands;  // cosine band -> (accepted, correct)
  for (const ResiduePair &m : r.matches) {
    const bool ok = anames[m.a] == bnames[m.b];
    correct += ok;
    const char *band = m.cosine >= 0.95 ? ">=0.95" : m.cosine >= 0.7 ? "0.7-0.95" : m.cosine >= 0.5 ? "0.5-0.7" : "0.35-0.5";
    bands[band].first += 1;
    bands[band].second += ok;
  }
  Json::Object by;
  for (const auto &[k, v] : buckets) by[k] = std::to_string(v.second) + "/" + std::to_string(v.first);
  Json::Object out;
  if (!label.empty()) out["label"] = label;
  out["a"] = files[0];
  out["b"] = files[1];
  out["weights"] = weights == "auto" ? std::string(weights_name(weights_for(pa.language, pb.language).value_or(Weights::nosize)))
                                     : weights;
  out["functions_a"] = static_cast<std::uint64_t>(pa.functions.size());
  out["functions_b"] = static_cast<std::uint64_t>(pb.functions.size());
  out["common"] = static_cast<std::uint64_t>(common);
  const double n = std::max<double>(1, static_cast<double>(common));
  out["sim_median"] = round3(median(sims));
  out["frac_identical"] = round3(static_cast<double>(identical) / n);
  out["frac_sim_ge_0.7"] = round3(static_cast<double>(ge07) / n);
  out["top1"] = round3(static_cast<double>(top1) / n);
  out["top1_by_features"] = std::move(by);
  out["signif_median"] = std::round(median(sigs) * 100) / 100;
  out["residue_matched"] = static_cast<std::uint64_t>(r.matches.size());
  out["residue_correct"] = static_cast<std::uint64_t>(correct);
  out["residue_precision"] = round3(r.matches.empty() ? 1.0 : static_cast<double>(correct) / r.matches.size());
  out["residue_recall"] = round3(static_cast<double>(correct) / n);
  Json::Object bj;
  for (const auto &[k, v] : bands) bj[k] = std::to_string(v.second) + "/" + std::to_string(v.first);
  out["residue_by_cosine"] = std::move(bj);
  std::cout << Json(std::move(out)).compact() << "\n";
  return 0;
}

int derive(int argc, char **argv) {
  if (argc < 4) {
    std::cerr << "usage: rk-sigdiff derive-idf OUT.xml [--base 64|64_32|32|nosize] [--entries N] IN.json...\n";
    return 2;
  }
  std::string out = argv[2], base = "64";
  std::size_t entries = 1000;
  std::vector<std::vector<std::uint32_t>> corpus;
  for (int i = 3; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--base" && i + 1 < argc) base = argv[++i];
    else if (a == "--entries" && i + 1 < argc) entries = std::strtoull(argv[++i], nullptr, 10);
    else
      for (auto &[n, f] : load(a).functions) corpus.push_back(std::move(f));
  }
  std::optional<WeightTable> owned;
  const WeightTable &b = table_named(base, "", "", owned);
  WeightTable d = derive_idf(b, corpus, entries);
  std::ofstream o(out, std::ios::binary);
  o << d.to_xml();
  std::cerr << "rk-sigdiff: " << d.idf_entries() << " hashes from " << corpus.size() << " functions -> " << out << "\n";
  return o ? 0 : 1;
}

}  // namespace

int main(int argc, char **argv) {
  try {
    if (argc >= 2 && std::strcmp(argv[1], "stability") == 0) return stability(argc, argv);
    if (argc >= 2 && std::strcmp(argv[1], "derive-idf") == 0) return derive(argc, argv);
  } catch (const std::exception &e) {
    std::cerr << "rk-sigdiff: " << e.what() << "\n";
    return 1;
  }
  std::cerr << "usage: rk-sigdiff stability A.json B.json [...] | derive-idf OUT.xml [...] IN.json...\n";
  return 2;
}
