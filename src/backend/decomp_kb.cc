#include "decomp_kb.h"

#include <google/protobuf/struct.pb.h>
#include <google/protobuf/util/json_util.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>

namespace revkit::backend {

namespace fs = std::filesystem;

namespace {

std::optional<std::string> ReadText(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) return std::nullopt;
  return std::string((std::istreambuf_iterator<char>(in)), {});
}

bool Ident(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$'; }

// `s` with comments, string and character literals blanked (newlines
// kept), so braces and names in them don't count.
std::string Masked(std::string_view s) {
  std::string out(s);
  std::size_t i = 0;
  while (i < s.size()) {
    if (s[i] == '/' && i + 1 < s.size() && s[i + 1] == '/') {
      while (i < s.size() && s[i] != '\n') out[i++] = ' ';
    } else if (s[i] == '/' && i + 1 < s.size() && s[i + 1] == '*') {
      out[i] = out[i + 1] = ' ';
      i += 2;
      while (i < s.size() && !(s[i] == '*' && i + 1 < s.size() && s[i + 1] == '/')) {
        if (s[i] != '\n') out[i] = ' ';
        ++i;
      }
      if (i < s.size()) out[i] = ' ';
      if (i + 1 < s.size()) out[i + 1] = ' ';
      i += 2;
    } else if (s[i] == '"' || s[i] == '\'') {
      const char q = s[i++];
      while (i < s.size() && s[i] != q && s[i] != '\n') {
        if (s[i] == '\\' && i + 1 < s.size()) out[i++] = ' ';
        out[i++] = ' ';
      }
      ++i;
    } else if (s[i] == '#' && (i == 0 || s[i - 1] == '\n')) {
      // A preprocessor line (with continuations) holds no definition.
      while (i < s.size() && s[i] != '\n') {
        if (s[i] == '\\' && i + 1 < s.size() && s[i + 1] == '\n') out[i++] = ' ';
        out[i++] = ' ';
      }
    } else {
      ++i;
    }
  }
  return out;
}

// The index past the group opening at `i` (`(`, `{`, `[`, `<`), or npos.
std::size_t Close(const std::string &m, std::size_t i) {
  const char open = m[i];
  const char close = open == '(' ? ')' : open == '{' ? '}' : open == '[' ? ']' : '>';
  int depth = 0;
  for (std::size_t j = i; j < m.size(); ++j) {
    if (m[j] == open) ++depth;
    else if (m[j] == close && --depth == 0) return j + 1;
  }
  return std::string::npos;
}

std::size_t SkipSpace(const std::string &m, std::size_t i) {
  while (i < m.size() && std::isspace(static_cast<unsigned char>(m[i]))) ++i;
  return i;
}

// The body's `{` after a parameter list ending at `i`: qualifiers
// (const, noexcept, override, final, throw(...), a trailing return type)
// and a constructor's initializer list; npos for a declaration.
std::size_t BodyOpen(const std::string &m, std::size_t i) {
  for (int guard = 0; guard < 64; ++guard) {
    i = SkipSpace(m, i);
    if (i >= m.size()) return std::string::npos;
    const char c = m[i];
    if (c == '{') return i;
    if (c == ';' || c == '=' || c == ',' || c == ')') return std::string::npos;
    if (c == ':') {
      // An initializer list: member(...) or member{...}, separated by commas.
      ++i;
      while (true) {
        i = SkipSpace(m, i);
        std::size_t start = i;
        while (i < m.size() && (Ident(m[i]) || m[i] == ':' || m[i] == '~')) ++i;
        if (i < m.size() && m[i] == '<') i = Close(m, i);
        if (i == std::string::npos || i == start) return std::string::npos;
        i = SkipSpace(m, i);
        if (i >= m.size() || (m[i] != '(' && m[i] != '{')) return std::string::npos;
        i = Close(m, i);
        if (i == std::string::npos) return std::string::npos;
        i = SkipSpace(m, i);
        if (i < m.size() && m[i] == ',') {
          ++i;
          continue;
        }
        break;
      }
      continue;
    }
    if (c == '(') {  // throw(...), noexcept(...)
      i = Close(m, i);
      if (i == std::string::npos) return std::string::npos;
      continue;
    }
    if (c == '-' && i + 1 < m.size() && m[i + 1] == '>') {
      i += 2;
      continue;
    }
    if (Ident(c) || c == '*' || c == '&' || c == '<' || c == '>' || c == ':') {
      if (c == '<') {
        i = Close(m, i);
        if (i == std::string::npos) return std::string::npos;
      } else {
        ++i;
      }
      continue;
    }
    return std::string::npos;
  }
  return std::string::npos;
}

std::optional<std::string> Find(std::string_view src, const std::string &m, std::string_view name) {
  if (name.empty()) return std::nullopt;
  for (std::size_t at = m.find(name); at != std::string::npos; at = m.find(name, at + 1)) {
    // The whole name: not part of a longer identifier or qualified name.
    if (at > 0 && (Ident(m[at - 1]) || m[at - 1] == ':' || m[at - 1] == '~')) continue;
    std::size_t i = at + name.size();
    if (i < m.size() && Ident(m[i])) continue;
    i = SkipSpace(m, i);
    if (i >= m.size() || m[i] != '(') continue;
    const std::size_t params = Close(m, i);
    if (params == std::string::npos) continue;
    const std::size_t open = BodyOpen(m, params);
    if (open == std::string::npos) continue;
    const std::size_t end = Close(m, open);
    if (end == std::string::npos) continue;
    // The declaration starts after the previous `;`, `}` or `{`, or a blank line.
    std::size_t start = at;
    while (start > 0) {
      const char p = m[start - 1];
      if (p == ';' || p == '}' || p == '{') break;
      // A label or an access specifier ("public:"), not a "::".
      if (p == ':' && (start < 2 || m[start - 2] != ':') && m[start] != ':') break;
      if (p == '\n' && start >= 2 && m[start - 2] == '\n') break;
      --start;
    }
    start = SkipSpace(m, start);
    // From the line's start, so indentation and a return type on the line stay.
    while (start > 0 && m[start - 1] != '\n' && std::isspace(static_cast<unsigned char>(m[start - 1]))) --start;
    return std::string(src.substr(start, end - start));
  }
  return std::nullopt;
}

}  // namespace

std::optional<std::string> ExtractFunctionText(std::string_view source, std::string_view qualified) {
  if (source.size() > (64u << 20)) return std::nullopt;
  const std::string m = Masked(source);
  if (auto t = Find(source, m, qualified)) return t;
  // Defined inside its class: by its last component.
  const std::size_t sep = qualified.rfind("::");
  if (sep != std::string_view::npos) return Find(source, m, qualified.substr(sep + 2));
  return std::nullopt;
}

std::optional<DecompKb> ReadDecompKb(const std::string &dir, std::string *error) {
  DecompKb kb;
  const fs::path d(dir);
  std::optional<std::string> meta = ReadText(d / "kb.json");
  if (!meta) return kb;  // a new KB
  google::protobuf::Struct st;
  if (!google::protobuf::util::JsonStringToMessage(*meta, &st).ok()) {
    if (error) *error = (d / "kb.json").string() + " doesn't parse";
    return std::nullopt;
  }
  const auto &f = st.fields();
  if (!f.contains("format") || f.at("format").string_value() != kDecompKbFormat) {
    if (error) *error = (d / "kb.json").string() + " is not a " + std::string(kDecompKbFormat) + " knowledge base";
    return std::nullopt;
  }
  if (f.contains("name")) kb.name = f.at("name").string_value();
  if (f.contains("language")) kb.language = f.at("language").string_value();
  if (f.contains("games"))
    for (const auto &g : f.at("games").list_value().values()) kb.games.push_back(g.string_value());
  if (std::optional<std::string> lines = ReadText(d / "functions.jsonl")) {
    std::size_t start = 0, n = 0;
    google::protobuf::util::JsonParseOptions po;
    po.ignore_unknown_fields = true;
    while (start < lines->size()) {
      std::size_t end = lines->find('\n', start);
      if (end == std::string::npos) end = lines->size();
      std::string_view line(lines->data() + start, end - start);
      start = end + 1;
      ++n;
      if (line.find_first_not_of(" \t\r") == std::string_view::npos) continue;
      pb::DecompKbFunction fn;
      if (!google::protobuf::util::JsonStringToMessage(line, &fn, po).ok()) {
        if (error) *error = "functions.jsonl:" + std::to_string(n) + " doesn't parse";
        return std::nullopt;
      }
      kb.functions.push_back(std::move(fn));
    }
  }
  return kb;
}

bool WriteDecompKb(const std::string &dir, const DecompKb &kb, std::string *error) {
  std::error_code ec;
  fs::create_directories(dir, ec);
  google::protobuf::Struct st;
  auto &f = *st.mutable_fields();
  f["format"].set_string_value(std::string(kDecompKbFormat));
  f["name"].set_string_value(kb.name);
  f["language"].set_string_value(kb.language);
  auto *games = f["games"].mutable_list_value();
  for (const std::string &g : kb.games) games->add_values()->set_string_value(g);
  std::string meta;
  google::protobuf::util::JsonPrintOptions jo;
  jo.add_whitespace = true;
  (void)google::protobuf::util::MessageToJsonString(st, &meta, jo);
  std::string lines;
  google::protobuf::util::JsonPrintOptions lo;
  lo.preserve_proto_field_names = true;
  for (const pb::DecompKbFunction &fn : kb.functions) {
    std::string l;
    (void)google::protobuf::util::MessageToJsonString(fn, &l, lo);
    lines += l + "\n";
  }
  for (const auto &[name, text] : {std::pair<std::string, const std::string *>{"kb.json", &meta},
                                   std::pair<std::string, const std::string *>{"functions.jsonl", &lines}}) {
    const fs::path tmp = fs::path(dir) / (name + ".tmp");
    {
      std::ofstream o(tmp, std::ios::binary | std::ios::trunc);
      o << *text;
      if (!o) {
        if (error) *error = "cannot write " + tmp.string();
        return false;
      }
    }
    fs::rename(tmp, fs::path(dir) / name, ec);
    if (ec) {
      if (error) *error = "cannot replace " + (fs::path(dir) / name).string() + ": " + ec.message();
      return false;
    }
  }
  return true;
}

std::string NormalizeStatus(std::string_view status) {
  std::string s(status);
  for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  if (s == "exact" || s == "matching" || s == "match" || s == "matched" || s == "ok") return "matching";
  if (s == "fuzzy" || s == "nonmatching" || s == "non-matching" || s == "nonmatch" || s == "partial") return "nonmatching";
  return s;
}

std::map<std::pair<std::string, std::uint64_t>, ManifestEntry> ReadManifest(std::string_view text, std::size_t *bad) {
  std::map<std::pair<std::string, std::uint64_t>, ManifestEntry> out;
  std::size_t start = 0;
  using Fields = google::protobuf::Map<std::string, google::protobuf::Value>;
  auto str = [](const Fields &f, std::initializer_list<const char *> keys) -> std::string {
    for (const char *k : keys) {
      auto it = f.find(k);
      if (it == f.end()) continue;
      if (it->second.has_string_value()) return it->second.string_value();
      if (it->second.has_number_value()) return std::to_string(static_cast<long long>(it->second.number_value()));
    }
    return {};
  };
  auto num = [](const Fields &f, const char *k) -> std::optional<std::uint64_t> {
    auto it = f.find(k);
    if (it == f.end()) return std::nullopt;
    if (it->second.has_number_value()) {
      const double d = it->second.number_value();
      if (!(d >= 0) || d > 1.8e19) return std::nullopt;
      return static_cast<std::uint64_t>(d);
    }
    const std::string s = it->second.string_value();
    if (s.empty() || s[0] == '-' || s[0] == '+' || std::isspace(static_cast<unsigned char>(s[0]))) return std::nullopt;
    try {
      std::size_t used = 0;
      const std::uint64_t v = std::stoull(s, &used, 0);
      if (used == s.size()) return v;
    } catch (...) {
    }
    return std::nullopt;
  };
  while (start < text.size()) {
    std::size_t end = text.find('\n', start);
    if (end == std::string_view::npos) end = text.size();
    std::string_view line = text.substr(start, end - start);
    start = end + 1;
    if (line.find_first_not_of(" \t\r") == std::string_view::npos) continue;
    google::protobuf::Struct st;
    std::optional<std::uint64_t> addr;
    if (google::protobuf::util::JsonStringToMessage(line, &st).ok()) addr = num(st.fields(), "address");
    if (!addr) {
      if (bad) ++*bad;
      continue;
    }
    const Fields &f = st.fields();
    ManifestEntry e;
    e.module = str(f, {"module"});
    e.address = *addr;
    e.size = num(f, "size").value_or(0);
    e.mode = str(f, {"isa", "mode"});
    for (char &c : e.mode) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    e.symbol = str(f, {"name", "symbol"});
    e.compiler = str(f, {"compiler"});
    e.flags = str(f, {"flags"});
    if (auto it = f.find("flags"); it != f.end() && it->second.has_list_value()) {
      for (const auto &v : it->second.list_value().values())
        if (v.has_string_value()) e.flags += (e.flags.empty() ? "" : " ") + v.string_value();
    }
    e.status = NormalizeStatus(str(f, {"status"}));
    e.source = str(f, {"source"});
    e.masked_hash = str(f, {"masked_sha256", "masked_hash"});
    e.library = str(f, {"library"});
    e.object = str(f, {"object"});
    e.variant = str(f, {"variant"});
    if (auto it = f.find("fuzzy"); it != f.end() && it->second.has_number_value()) e.fuzzy = it->second.number_value();
    if (auto it = f.find("relocations"); it != f.end()) {
      if (it->second.has_list_value()) e.relocations = static_cast<std::uint32_t>(it->second.list_value().values_size());
      else if (it->second.has_number_value() && it->second.number_value() >= 0 && it->second.number_value() < 4e9)
        e.relocations = static_cast<std::uint32_t>(it->second.number_value());
    }
    out[{e.module, e.address}] = std::move(e);
  }
  return out;
}

std::string InstructionDiff(const std::vector<std::string> &a0, const std::vector<std::string> &b0, std::size_t limit) {
  const std::size_t n = std::min(a0.size(), limit), m = std::min(b0.size(), limit);
  // The common prefix and suffix first: most near matches differ in a few lines.
  std::size_t pre = 0;
  while (pre < n && pre < m && a0[pre] == b0[pre]) ++pre;
  std::size_t suf = 0;
  while (suf < n - pre && suf < m - pre && a0[n - 1 - suf] == b0[m - 1 - suf]) ++suf;
  const std::size_t an = n - pre - suf, bn = m - pre - suf;
  std::string out;
  for (std::size_t i = 0; i < pre; ++i) out += " " + a0[i] + "\n";
  // LCS lengths over the middle (an x bn, bounded by limit^2 / 4 cells).
  std::vector<std::uint16_t> L((an + 1) * (bn + 1), 0);
  auto at = [&](std::size_t i, std::size_t j) -> std::uint16_t & { return L[i * (bn + 1) + j]; };
  for (std::size_t i = an; i-- > 0;)
    for (std::size_t j = bn; j-- > 0;)
      at(i, j) = a0[pre + i] == b0[pre + j] ? static_cast<std::uint16_t>(at(i + 1, j + 1) + 1)
                                            : std::max(at(i + 1, j), at(i, j + 1));
  std::size_t i = 0, j = 0;
  while (i < an || j < bn) {
    if (i < an && j < bn && a0[pre + i] == b0[pre + j]) {
      out += " " + a0[pre + i] + "\n";
      ++i, ++j;
    } else if (i < an && (j == bn || at(i + 1, j) >= at(i, j + 1))) {
      out += "-" + a0[pre + i] + "\n";
      ++i;
    } else {
      out += "+" + b0[pre + j] + "\n";
      ++j;
    }
  }
  for (std::size_t k = 0; k < suf; ++k) out += " " + a0[n - suf + k] + "\n";
  if (a0.size() > limit || b0.size() > limit) out += "...\n";
  return out;
}

}  // namespace revkit::backend
