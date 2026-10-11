#include "revkit/diff/lsh.h"

#include "lsh_weights_data.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <mutex>
#include <stdexcept>

// Compiled with -ffp-contract=off (CMakeLists.txt): every product and sum
// rounds as Java's double arithmetic does.

namespace revkit::diff {

namespace {

std::vector<std::string_view> split(std::string_view s, char sep) {
  std::vector<std::string_view> out;
  std::size_t at = 0;
  for (;;) {
    std::size_t next = s.find(sep, at);
    out.push_back(s.substr(at, next == std::string_view::npos ? std::string_view::npos : next - at));
    if (next == std::string_view::npos) return out;
    at = next + 1;
  }
}

// A minimal reader for the weights files' fixed shape: elements, attributes
// and text, no entities, comments skipped.
class XmlScanner {
 public:
  explicit XmlScanner(std::string_view s) : s_(s) {}

  struct Tag {
    std::string name;
    std::map<std::string, std::string> attrs;
    bool close = false;      // </name>
    bool self_close = false;  // <name/>
  };

  // The next tag, skipping text, comments and declarations; nullopt at the end.
  std::optional<Tag> next() {
    for (;;) {
      std::size_t lt = s_.find('<', at_);
      if (lt == std::string_view::npos) return std::nullopt;
      if (s_.compare(lt, 4, "<!--") == 0) {
        std::size_t end = s_.find("-->", lt);
        if (end == std::string_view::npos) fail("unterminated comment");
        at_ = end + 3;
        continue;
      }
      if (s_.compare(lt, 2, "<?") == 0) {
        std::size_t end = s_.find("?>", lt);
        if (end == std::string_view::npos) fail("unterminated declaration");
        at_ = end + 2;
        continue;
      }
      std::size_t gt = s_.find('>', lt);
      if (gt == std::string_view::npos) fail("unterminated tag");
      std::string_view body = s_.substr(lt + 1, gt - lt - 1);
      at_ = gt + 1;
      Tag t;
      if (!body.empty() && body.front() == '/') {
        t.close = true;
        body.remove_prefix(1);
      }
      if (!body.empty() && body.back() == '/') {
        t.self_close = true;
        body.remove_suffix(1);
      }
      std::size_t i = 0;
      while (i < body.size() && !std::isspace(static_cast<unsigned char>(body[i]))) ++i;
      t.name = std::string(body.substr(0, i));
      while (i < body.size()) {
        while (i < body.size() && std::isspace(static_cast<unsigned char>(body[i]))) ++i;
        if (i >= body.size()) break;
        std::size_t eq = body.find('=', i);
        if (eq == std::string_view::npos) fail("bad attribute in <" + t.name + ">");
        std::string key(body.substr(i, eq - i));
        while (!key.empty() && std::isspace(static_cast<unsigned char>(key.back()))) key.pop_back();
        std::size_t q = body.find_first_of("\"'", eq);
        if (q == std::string_view::npos) fail("unquoted attribute in <" + t.name + ">");
        std::size_t qe = body.find(body[q], q + 1);
        if (qe == std::string_view::npos) fail("unterminated attribute in <" + t.name + ">");
        t.attrs[key] = std::string(body.substr(q + 1, qe - q - 1));
        i = qe + 1;
      }
      return t;
    }
  }

  // The text up to the next tag (which must close `name`), consumed with it.
  std::string text_of(const std::string &name) {
    std::size_t lt = s_.find('<', at_);
    if (lt == std::string_view::npos) fail("missing </" + name + ">");
    std::string text(s_.substr(at_, lt - at_));
    at_ = lt;
    std::optional<Tag> t = next();
    if (!t || !t->close || t->name != name) fail("expected </" + name + ">");
    std::size_t b = text.find_first_not_of(" \t\r\n");
    std::size_t e = text.find_last_not_of(" \t\r\n");
    return b == std::string::npos ? std::string() : text.substr(b, e - b + 1);
  }

  [[noreturn]] static void fail(const std::string &why) { throw std::runtime_error("BSim weights: " + why); }

 private:
  std::string_view s_;
  std::size_t at_ = 0;
};

double parse_double(const std::string &s) {
  // Java's Double.parseDouble and strtod both round correctly.
  char *end = nullptr;
  const double v = std::strtod(s.c_str(), &end);
  if (s.empty() || end != s.c_str() + s.size()) XmlScanner::fail("bad number '" + s + "'");
  return v;
}

// Integer.decode / SpecXmlUtils.decodeInt: decimal, or 0x hex; a value
// past 2^31 wraps as Java's int does.
std::int64_t parse_int(const std::string &s) {
  std::string_view v = s;
  bool neg = false;
  if (!v.empty() && (v.front() == '-' || v.front() == '+')) {
    neg = v.front() == '-';
    v.remove_prefix(1);
  }
  int base = 10;
  if (v.size() > 2 && v[0] == '0' && (v[1] == 'x' || v[1] == 'X')) {
    base = 16;
    v.remove_prefix(2);
  }
  std::uint64_t out = 0;
  auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), out, base);
  if (ec != std::errc() || p != v.data() + v.size()) XmlScanner::fail("bad integer '" + s + "'");
  return neg ? -static_cast<std::int64_t>(out) : static_cast<std::int64_t>(out);
}

std::string format_double(double v) {
  char buf[64];
  std::snprintf(buf, sizeof buf, "%.17g", v);
  return buf;
}

}  // namespace

const char *weights_name(Weights w) {
  switch (w) {
    case Weights::w64: return "lshweights_64.xml";
    case Weights::w64_32: return "lshweights_64_32.xml";
    case Weights::w32: return "lshweights_32.xml";
    case Weights::nosize: return "lshweights_nosize.xml";
  }
  return "?";
}

std::optional<Weights> weights_for(std::string_view language_a, std::string_view language_b) {
  const std::vector<std::string_view> a = split(language_a, ':');
  const std::vector<std::string_view> b = split(language_b, ':');
  if (a.size() < 3 || b.size() < 3) return std::nullopt;
  if (a[0] == "Dalvik" || a[0] == "JVM") return std::nullopt;  // lshweights_cpool.xml, not vendored
  const std::string_view size_a = a[2], size_b = b[2];
  if (size_a != size_b) {
    if ((size_a != "64" && size_a != "32") || (size_b != "64" && size_b != "32")) return std::nullopt;
    return Weights::nosize;
  }
  if (size_a == "32") return Weights::w32;
  if (size_a == "64") {
    if (a.size() > 3 && a[3].find("-32") != std::string_view::npos) return Weights::w64_32;
    return Weights::w64;
  }
  return Weights::nosize;
}

// ---- WeightTable ------------------------------------------------------------------

WeightTable WeightTable::parse(std::string_view xml) {
  WeightTable t;
  XmlScanner x(xml);
  std::optional<XmlScanner::Tag> root = x.next();
  if (!root || root->close) XmlScanner::fail("no root element");
  auto settings = root->attrs.find("settings");
  if (settings == root->attrs.end()) XmlScanner::fail("no settings attribute");
  t.settings_ = static_cast<std::uint32_t>(parse_int(settings->second));
  bool weights = false, lookup = false;
  for (;;) {
    std::optional<XmlScanner::Tag> el = x.next();
    if (!el) XmlScanner::fail("unterminated <" + root->name + ">");
    if (el->close) {
      if (el->name != root->name) XmlScanner::fail("unexpected </" + el->name + ">");
      break;
    }
    if (el->name == "weightfactory") {
      // WeightFactory.restoreXml
      t.scale_ = parse_double(el->attrs.at("scale"));
      t.addend_ = parse_double(el->attrs.at("addend"));
      const double scale_sqrt = std::sqrt(t.scale_);
      auto value = [&](const char *name) {
        std::optional<XmlScanner::Tag> v = x.next();
        if (!v || v->close || v->name != name) XmlScanner::fail(std::string("expected <") + name + ">");
        return parse_double(x.text_of(name));
      };
      for (int i = 0; i < kIdfSize; ++i) t.idf_[i] = value("idf") * scale_sqrt;
      for (int i = 0; i < kTfSize; ++i) t.tf_[i] = value("tf");
      t.weightnorm_ = value("weightnorm");
      t.weightnorm_ /= t.scale_;
      t.flip0_ = value("probflip0");
      t.flip1_ = value("probflip1");
      t.diff0_ = value("probdiff0");
      t.diff1_ = value("probdiff1");
      std::optional<XmlScanner::Tag> end = x.next();
      if (!end || !end->close || end->name != "weightfactory") XmlScanner::fail("expected </weightfactory>");
      weights = true;
    } else if (el->name == "idflookup") {
      // IDFLookup.restoreXml: no size attribute, an empty table.
      lookup = true;
      if (el->self_close) continue;
      const bool sized = el->attrs.contains("size");
      for (;;) {
        std::optional<XmlScanner::Tag> h = x.next();
        if (!h) XmlScanner::fail("unterminated <idflookup>");
        if (h->close && h->name == "idflookup") break;
        if (h->close || h->name != "hash") XmlScanner::fail("unexpected <" + h->name + "> in <idflookup>");
        const int count = static_cast<int>(parse_int(h->attrs.at("count")));
        const auto hash = static_cast<std::uint32_t>(parse_int(x.text_of("hash")));
        // IDFLookup probes from hash & mask and stops at the first entry
        // with the hash: the first one inserted wins.
        if (sized) t.counts_.emplace(hash, count);
      }
    } else {
      // parser.discardSubTree()
      if (el->self_close) continue;
      int depth = 1;
      while (depth > 0) {
        std::optional<XmlScanner::Tag> s = x.next();
        if (!s) XmlScanner::fail("unterminated <" + el->name + ">");
        if (s->close) --depth;
        else if (!s->self_close) ++depth;
      }
    }
  }
  if (!weights) XmlScanner::fail("Could not find <weightfactory> tag in configuration");
  if (!lookup) XmlScanner::fail("Could not find <idflookup> tag in configuration");
  return t;
}

const WeightTable &WeightTable::builtin(Weights w) {
  static std::once_flag once;
  static std::array<WeightTable, 4> tables;
  std::call_once(once, [] {
    tables[static_cast<int>(Weights::w64)] = parse(bsim_data::kLshWeights64);
    tables[static_cast<int>(Weights::w64_32)] = parse(bsim_data::kLshWeights64_32);
    tables[static_cast<int>(Weights::w32)] = parse(bsim_data::kLshWeights32);
    tables[static_cast<int>(Weights::nosize)] = parse(bsim_data::kLshWeightsNosize);
  });
  return tables.at(static_cast<std::size_t>(w));
}

int WeightTable::idf_count(std::uint32_t hash) const {
  auto it = counts_.find(hash);
  return it == counts_.end() ? 0 : it->second;
}

double WeightTable::file_idf(int i) const { return idf_[i] / std::sqrt(scale_); }

WeightTable WeightTable::with_idf(const std::vector<std::pair<std::uint32_t, int>> &counts) const {
  WeightTable t = *this;
  t.counts_.clear();
  for (const auto &[h, c] : counts) t.counts_.emplace(h, std::clamp(c, 0, kIdfSize - 1));
  return t;
}

std::string WeightTable::to_xml() const {
  std::string out;
  char buf[32];
  std::snprintf(buf, sizeof buf, "0x%x", settings_);
  out += "<weights settings=\"" + std::string(buf) + "\">\n";
  out += "<weightfactory scale=\"" + format_double(scale_) + "\" addend=\"" + format_double(addend_) + "\">\n";
  for (int i = 0; i < kIdfSize; ++i) out += " <idf>" + format_double(file_idf(i)) + "</idf>\n";
  for (int i = 0; i < kTfSize; ++i) out += " <tf>" + format_double(tf_[i]) + "</tf>\n";
  out += " <weightnorm>" + format_double(weightnorm_ * scale_) + "</weightnorm>\n";
  out += " <probflip0>" + format_double(flip0_) + "</probflip0>\n";
  out += " <probflip1>" + format_double(flip1_) + "</probflip1>\n";
  out += " <probdiff0>" + format_double(diff0_) + "</probdiff0>\n";
  out += " <probdiff1>" + format_double(diff1_) + "</probdiff1>\n";
  out += "</weightfactory>\n";
  std::vector<std::pair<int, std::uint32_t>> sorted;
  for (const auto &[h, c] : counts_) sorted.emplace_back(c, h);
  std::sort(sorted.begin(), sorted.end());
  out += "<idflookup size=\"" + std::to_string(sorted.size()) + "\">\n";
  for (const auto &[c, h] : sorted) {
    std::snprintf(buf, sizeof buf, "0x%08x", h);
    out += "<hash count=\"" + std::to_string(c) + "\">" + buf + "</hash>\n";
  }
  out += "</idflookup>\n</weights>\n";
  return out;
}

WeightTable derive_idf(const WeightTable &base, const std::vector<std::vector<std::uint32_t>> &corpus,
                       std::size_t entries) {
  std::unordered_map<std::uint32_t, std::uint64_t> df;
  std::uint64_t docs = 0;
  for (const std::vector<std::uint32_t> &v : corpus) {
    if (v.empty()) continue;
    ++docs;
    for (std::size_t i = 0; i < v.size(); ++i)
      if (i == 0 || v[i] != v[i - 1]) ++df[v[i]];
  }
  std::vector<std::pair<std::uint64_t, std::uint32_t>> common;  // (functions, hash)
  common.reserve(df.size());
  for (const auto &[h, n] : df) common.emplace_back(n, h);
  std::sort(common.begin(), common.end(), [](const auto &a, const auto &b) {
    return a.first != b.first ? a.first > b.first : a.second < b.second;
  });
  if (common.size() > entries) common.resize(entries);
  std::vector<std::pair<std::uint32_t, int>> counts;
  if (common.empty() || docs == 0) return base.with_idf(counts);
  const double norm = -std::log2(static_cast<double>(common.back().first) / static_cast<double>(docs));
  for (const auto &[n, h] : common) {
    const double p = static_cast<double>(n) / static_cast<double>(docs);
    const double w = norm > 0 ? -std::log2(p) / norm : 0.0;
    // The count whose weight on the curve is closest (the curve falls).
    int best = 0;
    double best_d = std::abs(base.file_idf(0) - w);
    for (int i = 1; i < WeightTable::kIdfSize; ++i) {
      const double d = std::abs(base.file_idf(i) - w);
      if (d < best_d) {
        best = i;
        best_d = d;
      }
    }
    counts.emplace_back(h, best);
  }
  return base.with_idf(counts);
}

// ---- LshVector ---------------------------------------------------------------------

LshVector::LshVector(std::span<const std::uint32_t> features, const WeightTable &weights) {
  // LSHCosineVector.installFeatures, then calcLength.
  if (features.empty()) return;
  std::size_t distinct = 1;
  for (std::size_t i = 1; i < features.size(); ++i)
    if (features[i] != features[i - 1]) ++distinct;
  entries_.reserve(distinct);
  auto add = [&](std::uint32_t hash, int count, int idf) {
    HashEntry e;
    e.hash = hash;
    e.tf = static_cast<std::uint16_t>(count > 63 ? 63 : count - 1);
    e.idf = static_cast<std::uint16_t>(idf > 511 ? 511 : idf);
    e.coeff = weights.coeff(e.idf, e.tf);
    entries_.push_back(e);
  };
  const bool lookup = weights.has_idf();
  std::uint32_t last = features[0];
  int count = 1;
  for (std::size_t i = 1; i < features.size(); ++i) {
    if (features[i] != last) {
      add(last, count, lookup ? weights.idf_count(last) : 0);
      last = features[i];
      count = 1;
    } else {
      ++count;
    }
  }
  add(last, count, lookup ? weights.idf_count(last) : 0);
  double length = 0.0;
  for (const HashEntry &e : entries_) {
    length += e.coeff * e.coeff;
    hash_count_ += e.tf;
  }
  // Java's calcLength sums getTF(), which HashEntry returns as tf + 1.
  hash_count_ += static_cast<int>(entries_.size());
  length_ = std::sqrt(length);
}

void VectorCompare::fill_out() {
  if (acount < bcount) {
    min = acount;
    max = bcount;
  } else {
    min = bcount;
    max = acount;
  }
  diff = max - min;
  numflip = min - intersectcount;
}

double compare(const LshVector &a, const LshVector &b, VectorCompare *data) {
  const std::vector<HashEntry> &x = a.entries();
  const std::vector<HashEntry> &y = b.entries();
  std::size_t i = 0, j = 0;
  double res = 0.0;
  int intersect = 0;
  double dot = 0.0;
  if (!x.empty() && !y.empty()) {
    while (i < x.size() && j < y.size()) {
      const std::uint32_t h1 = x[i].hash, h2 = y[j].hash;
      if (h1 == h2) {
        const int t1 = x[i].tf + 1, t2 = y[j].tf + 1;
        if (t1 < t2) {
          res += x[i].coeff * x[i].coeff;
          intersect += t1;
        } else {
          res += y[j].coeff * y[j].coeff;
          intersect += t2;
        }
        ++i;
        ++j;
      } else if (h1 < h2) {
        ++i;
      } else {
        ++j;
      }
    }
    dot = res;
    res /= (a.length() * b.length());
  }
  if (data != nullptr) {
    data->dotproduct = dot;
    data->intersectcount = intersect;
    data->acount = a.hash_count();
    data->bcount = b.hash_count();
  }
  return res;
}

double significance(const WeightTable &w, VectorCompare &data) {
  data.fill_out();
  return data.dotproduct - data.numflip * (w.flip_norm0() + w.flip_norm1() / data.max) -
         data.diff * (w.diff_norm0() + w.diff_norm1() / data.max) + w.addend();
}

double self_significance(const WeightTable &w, const LshVector &v) {
  return v.length() * v.length() + w.addend();
}

}  // namespace revkit::diff
