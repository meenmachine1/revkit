// FidProgramSeeker (scoring) and ApplyFidEntriesCommand / MatchNameAnalysis
// (naming), ported (Ghidra 12.1.4, Apache 2.0).

#include "revkit/fid/match.h"

#include "revkit/demangle/demangle.h"

#include <algorithm>
#include <map>
#include <optional>
#include <set>

namespace revkit::fid {

namespace {

constexpr std::size_t kMaxParentsForScore = 500;
constexpr std::size_t kLibraryLimit = 5;  // MAGIC_MULTIPLE_LIBRARY_LIMIT

// HashFamily: callees and callers unique by full hash (the last one with a
// hash wins, in first-seen order, as a LinkedHashMap keeps them).
std::vector<HashQuad> family(const ProgramHashes &p, const std::vector<std::size_t> &idx) {
  std::vector<HashQuad> out;
  for (std::size_t i : idx) {
    const auto &h = p.functions[i].hash;
    if (!h) continue;
    auto it = std::find_if(out.begin(), out.end(), [&](const HashQuad &q) { return q.full == h->full; });
    if (it != out.end()) *it = *h;
    else out.push_back(*h);
  }
  return out;
}

std::optional<Candidate> score(const Database &db, const Function &fn, const HashQuad &hash,
                               const std::vector<HashQuad> &children, const std::vector<HashQuad> &parents,
                               const std::vector<const Database *> &dbs, float threshold) {
  if (fn.flags & kAutoFail) return std::nullopt;
  int units = fn.hash.code_units;
  int specific_units = 0;
  bool specific = false;
  if (fn.hash.specific == hash.specific) {
    specific_units = fn.hash.specific_extra;
    specific = true;
  }
  if ((fn.flags & kForceSpecific) && !specific) return std::nullopt;
  if ((fn.flags & kAutoPass) && units < kMediumHashCodeUnits) units = kMediumHashCodeUnits;
  int child_units = 0;
  for (const HashQuad &c : children)
    for (const Database *d : dbs)
      if (d->superior(fn.id, c.full)) {
        child_units += c.code_units;
        break;
      }
  if ((fn.flags & kForceRelation) && child_units == 0) return std::nullopt;
  int parent_units = 0;
  if (parents.size() < kMaxParentsForScore)
    for (const HashQuad &c : parents)
      for (const Database *d : dbs)
        if (d->inferior(c.full, fn.id)) {
          parent_units += c.code_units;
          break;
        }
  Candidate cand;
  cand.db = &db;
  cand.function = &fn;
  cand.library = db.library(fn.library);
  // Java: float += double, computed in double and narrowed.
  const float fs = static_cast<float>(static_cast<double>(static_cast<float>(units)) + 0.67 * specific_units);
  cand.primary = fs;
  cand.children = static_cast<float>(child_units);
  cand.parents = static_cast<float>(parent_units);
  cand.specific = specific;
  if (fs + cand.children + cand.parents < threshold) return std::nullopt;
  return cand;
}

std::string strip_underscores(const std::string &s) {
  std::size_t i = 0;
  while (i < s.size() && s[i] == '_') ++i;
  return s.substr(i);
}

// NameVersions.
struct Versions {
  std::string raw, similar;
  std::optional<std::string> no_template, base, full;
};

Versions versions(const std::string &raw) {
  Versions v;
  v.raw = raw;
  v.similar = strip_underscores(raw);
  if (auto d = demangle::parse(raw)) {
    v.full = d->full;
    std::string object = d->function ? d->function->base_name : d->name;
    std::string context = d->function ? d->function->context : std::string();
    if (!d->function) {
      // "ns::Class::member": the last component (outside template arguments).
      int depth = 0;
      std::size_t cut = std::string::npos;
      for (std::size_t i = 0; i + 1 < object.size(); ++i) {
        if (object[i] == '<') ++depth;
        else if (object[i] == '>') --depth;
        else if (depth == 0 && object[i] == ':' && object[i + 1] == ':') cut = i;
      }
      if (cut != std::string::npos) {
        context = object.substr(0, cut);
        object = object.substr(cut + 2);
      }
    }
    // removeTemplateParams: the object's name with its first template
    // argument list emptied.
    if (auto lt = object.find('<'); lt != std::string::npos) {
      int nesting = 1;
      std::size_t gt = lt + 1;
      for (; gt < object.size(); ++gt) {
        if (object[gt] == '<') ++nesting;
        else if (object[gt] == '>' && --nesting == 0) break;
      }
      if (nesting == 0) v.no_template = object.substr(0, lt + 1) + object.substr(gt);
    }
    // constructBaseName.
    std::string name = strip_underscores(object);
    if (!context.empty()) {
      // revkit's demangler spells MSVC's special destructors `..._dtor'
      // where Ghidra's says `... destructor'.
      if (object.ends_with("destructor'") || object.ends_with("dtor'") || object.starts_with("operator") ||
          object.starts_with("dtor$")) {
        // getBaseClass: the innermost namespace's name, or the whole
        // namespace for an anonymous one (`1').
        std::string base = context;
        int depth = 0;
        std::size_t cut = std::string::npos;
        for (std::size_t k = 0; k + 1 < context.size(); ++k) {
          if (context[k] == '<') ++depth;
          else if (context[k] == '>') --depth;
          else if (depth == 0 && context[k] == ':' && context[k + 1] == ':') cut = k;
        }
        if (cut != std::string::npos) base = context.substr(cut + 2);
        if (base.size() > 1 && base[0] == '`' && base[1] >= '0' && base[1] <= '9') base = context;
        name = base + "::" + object;
      } else if (context.starts_with("std::vector") || context.starts_with("std::list") ||
                 context.starts_with("std::map") || context.starts_with("std::set") ||
                 context.starts_with("std::basic_string")) {
        name = context + "::" + object;
      }
    }
    v.base = name;
  }
  return v;
}

void analyze(Match &m, float multi_threshold) {
  std::set<std::string> raw, similar;
  std::optional<std::set<std::string>> no_template(std::in_place), base(std::in_place);
  std::map<std::string, Versions> by_raw;
  for (const Candidate &c : m.candidates) {
    Versions v = versions(c.function->name);
    raw.insert(v.raw);
    similar.insert(v.similar);
    if (v.no_template && no_template) no_template->insert(*v.no_template);
    else no_template.reset();
    if (v.base && base) base->insert(*v.base);
    else base.reset();
    by_raw[v.raw] = std::move(v);
  }
  std::vector<std::string> final_names(raw.begin(), raw.end());
  if (raw.size() == 1 || similar.size() == 1) final_names = {*raw.begin()};
  else if (raw.size() > similar.size()) final_names.assign(similar.begin(), similar.end());
  std::size_t optimistic = raw.size();
  optimistic = std::min(optimistic, similar.size());
  if (no_template) optimistic = std::min(optimistic, no_template->size());
  if (base) optimistic = std::min(optimistic, base->size());
  m.names = final_names;

  if (optimistic > 1 && m.score() < multi_threshold) {
    m.verdict = Verdict::below_threshold;
    m.name.clear();
  } else if (final_names.size() == 1) {
    m.verdict = Verdict::single;
    m.name = final_names.front();
  } else if (optimistic == 1) {
    m.verdict = Verdict::same_base;
    if (raw.size() == 1) m.name = *raw.begin();
    else if (similar.size() == 1) m.name = *similar.begin();
    else if (no_template && no_template->size() == 1) m.name = *no_template->begin();
    else m.name = *base->begin();
  } else {
    m.verdict = Verdict::different;
    m.name = "FID_conflict:" + final_names.front();
  }

  // analyzeLibraries.
  std::set<std::string> libs;
  auto collect = [&](auto label) {
    libs.clear();
    for (const Candidate &c : m.candidates) {
      if (c.library == nullptr) continue;
      libs.insert(label(*c.library));
      if (libs.size() >= kLibraryLimit) break;
    }
  };
  collect([](const Library &l) { return l.family + " " + l.version + " " + l.variant; });
  if (libs.size() >= kLibraryLimit) collect([](const Library &l) { return l.family + " " + l.version; });
  if (libs.size() >= kLibraryLimit) {
    libs.clear();
    for (const Candidate &c : m.candidates)
      if (c.library) libs.insert(c.library->family);
  }
  m.libraries.assign(libs.begin(), libs.end());
}

}  // namespace

std::string Match::comment() const {
  std::string header;
  switch (verdict) {
    case Verdict::single: header = "Library Function - Single Match"; break;
    case Verdict::same_base: header = "Library Function - Multiple Matches With Same Base Name"; break;
    default: header = "Library Function - Multiple Matches With Different Base Names"; break;
  }
  std::string out = header + "\n";
  std::size_t n = 0;
  for (const std::string &nm : names) {
    std::string display = nm;
    if (auto d = demangle::demangle(nm)) display = *d;
    out += " " + display + "\n";
    if (++n > 3) break;
  }
  if (names.size() > n) out += "  " + std::to_string(names.size()) + " names - too many to list\n";
  out += "\n";
  out += libraries.size() == 1 ? "Library: " : "Libraries: ";
  if (libraries.size() < kLibraryLimit) {
    for (std::size_t i = 0; i < libraries.size(); ++i) out += (i ? ", " : "") + libraries[i];
  } else {
    out += std::to_string(libraries.size()) + " - too many to list";
  }
  return out;
}

std::vector<const Database *> for_language(const std::vector<const Database *> &dbs, const std::string &language) {
  std::string lang = language;
  if (std::count(lang.begin(), lang.end(), ':') >= 4) lang = lang.substr(0, lang.rfind(':'));
  std::vector<const Database *> out;
  for (const Database *d : dbs)
    if (d->has_language(lang)) out.push_back(d);
  return out;
}

std::vector<Match> search(const ProgramHashes &p, const std::vector<const Database *> &dbs, const SearchOptions &o) {
  std::vector<Match> out;
  const std::size_t n = p.functions.size();
  for (std::size_t i = 0; i < n; ++i) {
    if (o.cancel && o.cancel->load(std::memory_order_relaxed)) throw FidError("cancelled");
    if (o.progress && i % 256 == 0) o.progress(i, n);
    const ProgramFunction &f = p.functions[i];
    if (!f.hash || f.thunk) continue;
    const std::vector<HashQuad> children = family(p, f.callees);
    const std::vector<HashQuad> parents = family(p, f.callers);
    std::vector<Candidate> cands;
    for (const Database *db : dbs)
      for (const Function &fn : db->by_full(f.hash->full))
        if (auto c = score(*db, fn, *f.hash, children, parents, dbs, o.threshold)) cands.push_back(*c);
    if (cands.empty()) continue;
    std::stable_sort(cands.begin(), cands.end(),
                     [](const Candidate &a, const Candidate &b) { return a.score() > b.score(); });
    const float best = cands.front().score();
    std::size_t keep = 1;
    while (keep < cands.size() && !(cands[keep].score() < best)) ++keep;
    cands.resize(keep);
    Match m;
    m.entry = f.entry;
    m.function = i;
    m.hash = *f.hash;
    m.candidates = std::move(cands);
    analyze(m, o.multi_name_threshold);
    out.push_back(std::move(m));
  }
  if (o.progress) o.progress(n, n);
  return out;
}

}  // namespace revkit::fid
