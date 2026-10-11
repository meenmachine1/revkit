// Ghidra's function-start pattern files (Ghidra/Processors/<proc>/data/
// patterns, Apache 2.0): read from the install as data, as Ghidra's
// FunctionStartAnalyzer reads them (PatternPairSet, DittedBitSequence,
// AlignRule, FunctionStartAction).

#include "revkit/analysis/analysis.h"

#include "revkit/lift/lifter.hh"

#include "xml.hh"  // Ghidra's

#include <bit>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>

namespace revkit::analysis {

namespace {

// One ditted byte sequence: "0x..d.4de2 ........ 0100...." (hex pairs or
// binary octets, '.' a bit that doesn't matter).
struct Ditted {
  std::vector<std::uint8_t> value, mask;
  unsigned fixed_bits() const {
    unsigned n = 0;
    for (std::uint8_t m : mask) n += static_cast<unsigned>(std::popcount(m));
    return n;
  }
};

int hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

Ditted parse_ditted(const std::string &text, const std::string &file) {
  Ditted out;
  auto bad = [&] { return lift::LiftError(file + ": bad ditted bit sequence \"" + text + "\""); };
  std::size_t i = 0;
  while (i < text.size()) {
    const char c = text[i];
    if (std::isspace(static_cast<unsigned char>(c))) {
      ++i;
      continue;
    }
    if (c == '#') {  // a comment to the end of the line
      while (i < text.size() && text[i] != '\n') ++i;
      continue;
    }
    if (c == '*') {  // a mark; the patterns we read don't use it
      ++i;
      continue;
    }
    if (c == '0' && i + 1 < text.size() && text[i + 1] == 'x') {
      i += 2;
      while (i + 1 < text.size() && !std::isspace(static_cast<unsigned char>(text[i]))) {
        std::uint8_t v = 0, m = 0xff;
        for (int half = 0; half < 2; ++half) {
          const char h = text[i + half];
          const int shift = half == 0 ? 4 : 0;
          if (h == '.') {
            m = static_cast<std::uint8_t>(m & ~(0xf << shift));
          } else {
            int d = hex_digit(h);
            if (d < 0) throw bad();
            v = static_cast<std::uint8_t>(v | d << shift);
          }
        }
        out.value.push_back(v);
        out.mask.push_back(m);
        i += 2;
      }
      if (i < text.size() && !std::isspace(static_cast<unsigned char>(text[i]))) throw bad();
      continue;
    }
    if (c != '0' && c != '1' && c != '.') throw bad();
    if (i + 8 > text.size()) throw bad();
    std::uint8_t v = 0, m = 0;
    for (int b = 0; b < 8; ++b) {
      const char d = text[i + b];
      v = static_cast<std::uint8_t>(v << 1);
      m = static_cast<std::uint8_t>(m << 1);
      if (d == '0') m |= 1;
      else if (d == '1') v |= 1, m |= 1;
      else if (d != '.') throw bad();
    }
    out.value.push_back(v);
    out.mask.push_back(m);
    i += 8;
  }
  return out;
}

const std::string *attribute(const ghidra::Element *el, const std::string &name) {
  for (int i = 0; i < el->getNumAttributes(); ++i)
    if (el->getAttributeName(i) == name) return &el->getAttributeValue(i);
  return nullptr;
}

// What a <pattern> or <postpatterns> says beyond its bytes; nullopt when
// it starts no function (a code boundary only).
struct Actions {
  std::uint32_t align = 1;
  std::int32_t isa = -1;
  std::optional<StartPattern> start;
  std::string label;  // funcstart label="...": the name of the function that starts there
};

Actions parse_actions(const ghidra::Element *el, const std::string &isa_context, const std::string &file) {
  Actions a;
  for (const ghidra::Element *c : el->getChildren()) {
    const std::string &n = c->getName();
    if (n == "align") {
      const std::string *bits = attribute(c, "bits");
      a.align = 1u << (bits ? std::stoi(*bits) : 0);
    } else if (n == "setcontext") {
      const std::string *name = attribute(c, "name"), *value = attribute(c, "value");
      if (name && value && *name == isa_context) a.isa = std::stoi(*value);
    } else if (n == "funcstart" || n == "possiblefuncstart") {
      StartPattern p;
      p.kind = n == "funcstart" ? StartPattern::Kind::function : StartPattern::Kind::possible;
      for (int i = 0; i < c->getNumAttributes(); ++i) {
        std::string k = c->getAttributeName(i), v = c->getAttributeValue(i);
        for (char &ch : k) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (k == "after") {
          if (v.starts_with("func")) p.after = StartPattern::After::function;
          else if (v.starts_with("inst")) p.after = StartPattern::After::instruction;
          else if (v.starts_with("data")) p.after = StartPattern::After::data;
          else if (v.starts_with("ptr")) p.after = StartPattern::After::pointer;
          else if (v.starts_with("def")) p.after = StartPattern::After::defined;
          else throw lift::LiftError(file + ": unknown after=\"" + v + "\"");
        } else if (k == "validcode") {
          if (v == "0" || v == "false") p.valid_min = 0;
          else if (v == "true" || v == "subroutine" || v == "function") p.valid_min = 1;  // approximated
          else p.valid_min = static_cast<std::uint16_t>(std::stoi(v));
          if (p.valid_max == 0) p.valid_max = p.valid_min;
        } else if (k == "validcodemax") {
          p.valid_max = static_cast<std::uint16_t>(std::stoi(v));
          if (p.valid_min == 0) p.valid_min = 1;
        } else if (k == "contiguous") {
          p.contiguous = v != "false";
        } else if (k == "label") {
          a.label = v;
        }
        // thunk, noreturn, section: not used for discovery.
      }
      a.start = std::move(p);
    }
  }
  return a;
}

StartPattern finish(const Ditted &pre, const Ditted &post, const Actions &a) {
  StartPattern p = *a.start;
  p.value = pre.value;
  p.mask = pre.mask;
  p.value.insert(p.value.end(), post.value.begin(), post.value.end());
  p.mask.insert(p.mask.end(), post.mask.begin(), post.mask.end());
  p.pre = static_cast<std::uint32_t>(pre.value.size());
  p.align = a.align;
  p.isa = a.isa;
  return p;
}

std::string content_of(const ghidra::Element *el) { return el->getContent(); }

// With `labelled`, the patterns that name the function they start go
// there (with the name) and the others nowhere.
void read_pattern_file(const std::filesystem::path &path, const std::string &isa_context, std::vector<StartPattern> &out,
                       std::vector<LabelPattern> *labelled = nullptr) {
  auto add = [&](StartPattern p, const Actions &a) {
    if (labelled == nullptr) out.push_back(std::move(p));
    else if (!a.label.empty()) labelled->push_back({std::move(p), a.label});
  };
  const std::string file = path.string();
  ghidra::DocumentStorage store;
  ghidra::Element *root;
  try {
    root = store.openDocument(file)->getRoot();
  } catch (const ghidra::DecoderError &e) {
    throw lift::LiftError(file + ": " + e.explain);
  }
  for (const ghidra::Element *el : root->getChildren()) {
    if (el->getName() == "pattern") {
      Ditted data;
      for (const ghidra::Element *c : el->getChildren())
        if (c->getName() == "data") data = parse_ditted(content_of(c), file);
      Actions a = parse_actions(el, isa_context, file);
      if (a.start && !data.value.empty()) add(finish({}, data, a), a);
    } else if (el->getName() == "patternpairs") {
      const std::string *total = attribute(el, "totalbits"), *postbits = attribute(el, "postbits");
      const unsigned total_bits = total ? static_cast<unsigned>(std::stoi(*total)) : 0;
      const unsigned post_bits = postbits ? static_cast<unsigned>(std::stoi(*postbits)) : 0;
      std::vector<Ditted> pres;
      for (const ghidra::Element *c : el->getChildren()) {
        if (c->getName() == "prepatterns") {
          for (const ghidra::Element *d : c->getChildren())
            if (d->getName() == "data") pres.push_back(parse_ditted(content_of(d), file));
        } else if (c->getName() == "postpatterns") {
          std::vector<Ditted> posts;
          for (const ghidra::Element *d : c->getChildren())
            if (d->getName() == "data") posts.push_back(parse_ditted(content_of(d), file));
          Actions a = parse_actions(c, isa_context, file);
          if (!a.start) continue;
          // PatternPairSet.createFinalPatterns: every pre with every post
          // that checks enough bits.
          for (const Ditted &post : posts) {
            if (post.fixed_bits() < post_bits) continue;
            for (const Ditted &pre : pres)
              if (pre.fixed_bits() + post.fixed_bits() >= total_bits) add(finish(pre, post, a), a);
          }
        }
      }
    }
  }
}

// Ghidra's language id globs ("ARM:LE:32:*").
bool glob_match(std::string_view pattern, std::string_view s) {
  if (pattern.empty()) return s.empty();
  if (pattern[0] == '*') {
    for (std::size_t i = 0; i <= s.size(); ++i)
      if (glob_match(pattern.substr(1), s.substr(i))) return true;
    return false;
  }
  return !s.empty() && (pattern[0] == '?' || pattern[0] == s[0]) && glob_match(pattern.substr(1), s.substr(1));
}

}  // namespace

namespace {

// The pattern files `constraints` (patternconstraints.xml or
// prepatternconstraints.xml in the language's patterns directory) selects
// for the language and compiler.
std::vector<std::filesystem::path> pattern_files(const std::string &language, const std::string &compiler,
                                                 const char *constraints_name) {
  auto data = lift::processor_data_dir(language);
  if (!data) return {};
  const std::filesystem::path dir = *data / "patterns";
  const std::filesystem::path constraints = dir / constraints_name;
  if (!std::filesystem::exists(constraints)) return {};
  std::vector<std::filesystem::path> files;
  auto globals = lift::lock_ghidra_globals();  // Ghidra's XML parser keeps global state
  ghidra::DocumentStorage store;
  ghidra::Element *root;
  try {
    root = store.openDocument(constraints.string())->getRoot();
  } catch (const ghidra::DecoderError &e) {
    throw lift::LiftError(constraints.string() + ": " + e.explain);
  }
  auto add = [&](std::string f) {
    while (!f.empty() && std::isspace(static_cast<unsigned char>(f.back()))) f.pop_back();
    while (!f.empty() && std::isspace(static_cast<unsigned char>(f.front()))) f.erase(f.begin());
    if (!f.empty()) files.push_back(dir / f);
  };
  for (const ghidra::Element *lang : root->getChildren()) {
    const std::string *id = attribute(lang, "id");
    if (lang->getName() != "language" || !id || !glob_match(*id, language)) continue;
    for (const ghidra::Element *c : lang->getChildren()) {
      if (c->getName() == "patternfile") {
        add(content_of(c));
      } else if (c->getName() == "compiler") {
        const std::string *cid = attribute(c, "id");
        if (!cid || !glob_match(*cid, compiler)) continue;
        for (const ghidra::Element *f : c->getChildren())
          if (f->getName() == "patternfile") add(content_of(f));
      }
    }
  }
  return files;
}

void read_files(const std::vector<std::filesystem::path> &files, std::vector<StartPattern> &out,
                std::vector<LabelPattern> *labelled) {
  for (const std::filesystem::path &f : files) {
    try {
      read_pattern_file(f, "TMode", out, labelled);
    } catch (const std::invalid_argument &) {
      throw lift::LiftError(f.string() + ": bad number");
    } catch (const std::out_of_range &) {
      throw lift::LiftError(f.string() + ": bad number");
    }
  }
}

}  // namespace

std::vector<StartPattern> load_start_patterns(const std::string &language, const std::string &compiler) {
  const std::vector<std::filesystem::path> files = pattern_files(language, compiler, "patternconstraints.xml");
  // Ghidra's XML parser keeps global state.
  auto globals = lift::lock_ghidra_globals();
  std::vector<StartPattern> out;
  read_files(files, out, nullptr);
  return out;
}

const std::vector<LabelPattern> &label_patterns(const std::string &language, const std::string &compiler) {
  static std::mutex mu;
  static std::map<std::pair<std::string, std::string>, std::vector<LabelPattern>> cache;
  std::lock_guard lock(mu);
  auto it = cache.find({language, compiler});
  if (it != cache.end()) return it->second;
  std::vector<LabelPattern> out;
  try {
    // (Function Start Pre Search's files, then Function Start Search's.)
    std::vector<std::filesystem::path> files = pattern_files(language, compiler, "prepatternconstraints.xml");
    for (std::filesystem::path &f : pattern_files(language, compiler, "patternconstraints.xml")) files.push_back(std::move(f));
    auto globals = lift::lock_ghidra_globals();
    std::vector<StartPattern> none;
    read_files(files, none, &out);
  } catch (const lift::LiftError &) {
    out.clear();  // an install without readable patterns names nothing
  }
  return cache.emplace(std::make_pair(language, compiler), std::move(out)).first->second;
}

}  // namespace revkit::analysis
