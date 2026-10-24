// ds-decomp's project files (dsd.hh).
#include "revkit/nds/dsd.hh"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <set>

namespace revkit::nds {

namespace {

constexpr std::size_t kMaxModules = 4096;
constexpr std::size_t kMaxName = 4096;

std::string_view Trim(std::string_view s) {
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  return s;
}

std::string Hex(std::uint64_t v, int width = 0) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "%0*llx", width, static_cast<unsigned long long>(v));
  return buf;
}

// Splits a line into its text and the comment after `//`.
std::pair<std::string_view, std::string_view> SplitComment(std::string_view line) {
  std::size_t c = line.find("//");
  if (c == std::string_view::npos) return {line, {}};
  return {line.substr(0, c), Trim(line.substr(c + 2))};
}

// Words separated by whitespace outside parentheses, as dsd splits them.
std::vector<std::string_view> Words(std::string_view s) {
  std::vector<std::string_view> out;
  int depth = 0;
  std::size_t start = std::string_view::npos;
  for (std::size_t i = 0; i <= s.size(); ++i) {
    const bool end = i == s.size();
    const char c = end ? ' ' : s[i];
    if (c == '(') ++depth;
    if (c == ')' && depth > 0) --depth;
    const bool space = c == ' ' || c == '\t' || c == '\r';
    if (space && depth == 0) {
      if (start != std::string_view::npos) out.push_back(s.substr(start, i - start));
      start = std::string_view::npos;
      if (end) break;
    } else if (start == std::string_view::npos) {
      start = i;
    }
    if (end) {
      if (start != std::string_view::npos) out.push_back(s.substr(start));
      break;
    }
  }
  return out;
}

// Comma-separated items outside parentheses.
std::vector<std::string_view> Commas(std::string_view s) {
  std::vector<std::string_view> out;
  int depth = 0;
  std::size_t start = 0;
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '(') ++depth;
    else if (s[i] == ')' && depth > 0) --depth;
    else if (s[i] == ',' && depth == 0) {
      out.push_back(Trim(s.substr(start, i - start)));
      start = i + 1;
    }
  }
  if (start < s.size()) out.push_back(Trim(s.substr(start)));
  return out;
}

std::optional<std::uint32_t> U32(std::string_view s) {
  auto v = parse_number(s);
  if (!v || *v > 0xffffffffu) return std::nullopt;
  return static_cast<std::uint32_t>(*v);
}

std::optional<std::int64_t> I64(std::string_view s) {
  s = Trim(s);
  bool neg = false;
  if (!s.empty() && (s[0] == '-' || s[0] == '+')) {
    neg = s[0] == '-';
    s.remove_prefix(1);
  }
  auto v = parse_number(s);
  if (!v || *v > 0x7fffffffffffffffull) return std::nullopt;
  return neg ? -static_cast<std::int64_t>(*v) : static_cast<std::int64_t>(*v);
}

// `name(options)` -> name, options (without the parentheses).
std::pair<std::string_view, std::string_view> Call(std::string_view s) {
  std::size_t p = s.find('(');
  if (p == std::string_view::npos) return {s, {}};
  std::string_view opts = s.substr(p + 1);
  if (!opts.empty() && opts.back() == ')') opts.remove_suffix(1);
  return {s.substr(0, p), opts};
}

template <typename F>
void EachLine(std::string_view text, F f) {
  std::size_t start = 0, number = 0;
  while (start <= text.size()) {
    std::size_t end = text.find('\n', start);
    if (end == std::string_view::npos) end = text.size();
    std::string_view line = text.substr(start, end - start);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    ++number;
    if (!(end == text.size() && line.empty() && start == text.size() && number > 1)) f(number, line);
    if (end == text.size()) break;
    start = end + 1;
  }
}

std::vector<std::string> Lines(std::string_view text) {
  std::vector<std::string> out;
  std::size_t start = 0;
  while (start < text.size()) {
    std::size_t end = text.find('\n', start);
    if (end == std::string_view::npos) end = text.size();
    out.emplace_back(text.substr(start, end - start));
    start = end + 1;
  }
  return out;
}

bool ParseModule(const YamlNode &n, DsdModuleConfig &m, std::string *error) {
  if (n.kind != YamlNode::Kind::map) {
    if (error) *error = "a module is not a map";
    return false;
  }
  m.name = n.str("name");
  m.object = n.str("object");
  m.hash = n.str("hash");
  m.delinks = n.str("delinks");
  m.symbols = n.str("symbols");
  m.relocations = n.str("relocations");
  if (m.name.empty() || m.name.size() > 256) {
    if (error) *error = "a module has no name";
    return false;
  }
  // A name is printed into records and file names: printable ASCII with no
  // spaces ("main", "itcm", "ov003"), never a line break.
  for (const char c : m.name)
    if (c <= 0x20 || c >= 0x7f) {
      if (error) *error = "a module's name has a space or control character";
      return false;
    }
  if (m.symbols.empty() && m.delinks.empty() && m.relocations.empty()) {
    if (error) *error = "module " + m.name + " names no symbols, relocations or delinks file";
    return false;
  }
  return true;
}

}  // namespace

std::string_view to_string(DsdModuleKind k) {
  switch (k) {
    case DsdModuleKind::main: return "main";
    case DsdModuleKind::itcm: return "itcm";
    case DsdModuleKind::dtcm: return "dtcm";
    case DsdModuleKind::autoload: return "autoload";
    case DsdModuleKind::overlay: return "overlay";
  }
  return "?";
}

const DsdModuleConfig *DsdConfig::find(std::string_view module_name) const {
  for (const DsdModuleConfig &m : modules)
    if (m.name == module_name) return &m;
  return nullptr;
}

const DsdModuleConfig *DsdConfig::overlay(int id) const {
  for (const DsdModuleConfig &m : modules)
    if (m.kind == DsdModuleKind::overlay && m.overlay_id == id) return &m;
  return nullptr;
}

const DsdModuleConfig *DsdConfig::by_kind(DsdModuleKind kind) const {
  for (const DsdModuleConfig &m : modules)
    if (m.kind == kind) return &m;
  return nullptr;
}

std::optional<DsdConfig> parse_dsd_config(std::string_view yaml, std::string *error) {
  std::optional<YamlNode> root = parse_yaml(yaml, error);
  if (!root) return std::nullopt;
  if (root->kind != YamlNode::Kind::map || !root->get("main_module")) {
    if (error) *error = "not a ds-decomp config: no main_module";
    return std::nullopt;
  }
  DsdConfig c;
  c.rom_config = root->str("rom_config");
  c.build_path = root->str("build_path");
  c.delinks_path = root->str("delinks_path");
  DsdModuleConfig main;
  main.kind = DsdModuleKind::main;
  if (!ParseModule(*root->get("main_module"), main, error)) return std::nullopt;
  c.modules.push_back(std::move(main));
  std::set<std::string> names{c.modules[0].name};
  if (const YamlNode *a = root->get("autoloads"); a && a->kind == YamlNode::Kind::seq) {
    for (const YamlNode &n : a->seq) {
      if (c.modules.size() >= kMaxModules) break;
      DsdModuleConfig m;
      if (!ParseModule(n, m, error)) return std::nullopt;
      const YamlNode *kind = n.get("kind");
      std::string k = kind ? (kind->tag.empty() ? kind->scalar : kind->tag) : std::string();
      if (kind && kind->kind == YamlNode::Kind::map && !kind->map.empty()) k = kind->map[0].first;
      if (k == "Itcm") {
        m.kind = DsdModuleKind::itcm;
      } else if (k == "Dtcm") {
        m.kind = DsdModuleKind::dtcm;
      } else if (k == "Unknown") {
        m.kind = DsdModuleKind::autoload;
        std::string v = kind->kind == YamlNode::Kind::map ? kind->map[0].second.scalar : kind->scalar;
        m.autoload_index = U32(v).value_or(0);
      } else {
        if (error) *error = "autoload " + m.name + " has an unknown kind '" + k + "'";
        return std::nullopt;
      }
      if (!names.insert(m.name).second) {
        if (error) *error = "two modules are named " + m.name;
        return std::nullopt;
      }
      c.modules.push_back(std::move(m));
    }
  }
  if (const YamlNode *o = root->get("overlays"); o && o->kind == YamlNode::Kind::seq) {
    std::set<int> ids;
    for (const YamlNode &n : o->seq) {
      if (c.modules.size() >= kMaxModules) break;
      DsdModuleConfig m;
      if (!ParseModule(n, m, error)) return std::nullopt;
      m.kind = DsdModuleKind::overlay;
      auto id = n.num("id");
      if (!id || *id > 0xffff) {
        if (error) *error = "overlay " + m.name + " has no id";
        return std::nullopt;
      }
      m.overlay_id = static_cast<int>(*id);
      m.signed_overlay = n.flag("signed");
      if (!ids.insert(m.overlay_id).second || !names.insert(m.name).second) {
        if (error) *error = "overlay " + m.name + " is listed twice";
        return std::nullopt;
      }
      c.modules.push_back(std::move(m));
    }
  }
  return c;
}

std::optional<RomExtract> parse_rom_extract(std::string_view config_yaml, ReadText read, void *ctx,
                                            std::string *error) {
  std::optional<YamlNode> root = parse_yaml(config_yaml, error);
  if (!root) return std::nullopt;
  if (root->kind != YamlNode::Kind::map || root->str("arm9_bin").empty()) {
    if (error) *error = "not a ds-rom extract config: no arm9_bin";
    return std::nullopt;
  }
  RomExtract out;
  auto yaml_file = [&](const std::string &path) -> std::optional<YamlNode> {
    if (path.empty()) return std::nullopt;
    std::optional<std::string> text = read(ctx, path);
    if (!text) {
      out.warnings.push_back(path + ": missing");
      return std::nullopt;
    }
    std::string e;
    std::optional<YamlNode> n = parse_yaml(*text, &e);
    if (!n) out.warnings.push_back(path + ": " + e);
    return n;
  };
  auto dir_of = [](const std::string &p) {
    std::size_t s = p.rfind('/');
    return s == std::string::npos ? std::string() : p.substr(0, s + 1);
  };
  // ARM9 main.
  {
    RomExtractModule m;
    m.name = "main";
    m.bin = root->str("arm9_bin");
    if (auto y = yaml_file(root->str("arm9_config"))) {
      if (auto b = y->num("base_address")) {
        m.base_address = static_cast<std::uint32_t>(*b);
        m.known_address = true;
      }
      m.entry = static_cast<std::uint32_t>(y->num("entry_function").value_or(0));
      // The module's .bss, from its build info (addresses).
      auto bs = y->num("bss_start"), be = y->num("bss_end");
      if (bs && be && *be > *bs && *be - *bs < 0x1000000) m.bss_size = static_cast<std::uint32_t>(*be - *bs);
    }
    if (!m.known_address) {
      m.base_address = 0x02000000;
      out.warnings.push_back("main: no base address in the ARM9 config; 0x02000000 assumed");
    }
    out.modules.push_back(std::move(m));
  }
  // Autoloads.
  auto autoload = [&](const YamlNode *n, const std::string &name) {
    if (!n || n->kind != YamlNode::Kind::map) return;
    RomExtractModule m;
    m.name = name;
    m.bin = n->str("bin");
    if (auto y = yaml_file(n->str("config"))) {
      if (auto b = y->num("base_address")) {
        m.base_address = static_cast<std::uint32_t>(*b);
        m.known_address = true;
      }
      m.code_size = static_cast<std::uint32_t>(y->num("code_size").value_or(0));
      m.bss_size = static_cast<std::uint32_t>(y->num("bss_size").value_or(0));
    }
    if (!m.known_address) {
      m.base_address = name == "itcm" ? 0x01ff8000 : name == "dtcm" ? 0x027e0000 : 0;
      out.warnings.push_back(name + ": no base address in its config; " + Hex(m.base_address) + " assumed");
    }
    if (!m.bin.empty()) out.modules.push_back(std::move(m));
  };
  autoload(root->get("itcm"), "itcm");
  autoload(root->get("dtcm"), "dtcm");
  if (const YamlNode *u = root->get("unknown_autoloads"); u && u->kind == YamlNode::Kind::seq) {
    for (const YamlNode &n : u->seq) autoload(&n, "autoload_" + std::to_string(n.num("index").value_or(0)));
  }
  // Overlays.
  auto overlays = [&](const std::string &path, bool arm7) {
    std::optional<YamlNode> y = yaml_file(path);
    if (!y) return;
    const YamlNode *list = y->get("overlays");
    if (!list || list->kind != YamlNode::Kind::seq) return;
    const std::string dir = dir_of(path);
    for (const YamlNode &n : list->seq) {
      if (out.modules.size() >= kMaxModules) break;
      RomExtractModule m;
      auto id = n.num("id");
      if (!id || *id > 0xffff) continue;
      m.overlay_id = static_cast<int>(*id);
      char name[32];
      std::snprintf(name, sizeof name, "%sov%03d", arm7 ? "arm7_" : "", m.overlay_id);
      m.name = name;
      m.arm7 = arm7;
      m.bin = dir + n.str("file_name");
      if (auto b = n.num("base_address")) {
        m.base_address = static_cast<std::uint32_t>(*b);
        m.known_address = true;
      }
      m.code_size = static_cast<std::uint32_t>(n.num("code_size").value_or(0));
      m.bss_size = static_cast<std::uint32_t>(n.num("bss_size").value_or(0));
      if (n.str("file_name").empty() || !m.known_address) {
        out.warnings.push_back(m.name + ": no file name or base address");
        continue;
      }
      out.modules.push_back(std::move(m));
    }
  };
  if (std::string p = root->str("arm9_overlays"); !p.empty()) overlays(p, false);
  // ARM7.
  if (std::string bin = root->str("arm7_bin"); !bin.empty()) {
    RomExtractModule m;
    m.name = "arm7";
    m.arm7 = true;
    m.bin = bin;
    if (auto y = yaml_file(root->str("arm7_config"))) {
      if (auto b = y->num("base_address")) {
        m.base_address = static_cast<std::uint32_t>(*b);
        m.known_address = true;
      }
      m.entry = static_cast<std::uint32_t>(y->num("entry_function").value_or(0));
    }
    if (m.known_address) out.modules.push_back(std::move(m));
    else out.warnings.push_back("arm7: no base address in its config");
  }
  if (std::string p = root->str("arm7_overlays"); !p.empty()) overlays(p, true);
  return out;
}

// ---- symbols.txt --------------------------------------------------------

std::uint32_t DsdSymbol::byte_size() const {
  switch (kind) {
    case DsdSymbolKind::function: return size;
    case DsdSymbolKind::bss: return has_size ? size : 0;
    case DsdSymbolKind::label: return 0;
    case DsdSymbolKind::data: {
      if (data == DsdDataKind::any || !count) return 0;
      const std::uint32_t el = data == DsdDataKind::byte ? 1 : data == DsdDataKind::short_ ? 2 : 4;
      return *count > 0x10000000u ? 0 : el * *count;
    }
  }
  return 0;
}

bool dsd_name_ok(std::string_view name) {
  if (name.empty() || name.size() > kMaxName) return false;
  if (name.find("//") != std::string_view::npos) return false;
  int depth = 0;
  for (char c : name) {
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || static_cast<unsigned char>(c) < 0x20) return false;
    if (c == '(') ++depth;
    if (c == ')' && --depth < 0) return false;
  }
  return depth == 0;
}

namespace {

std::optional<DsdSymbol> ParseSymbolLine(std::string_view raw, std::size_t number, std::string *error) {
  auto [text, comment] = SplitComment(raw);
  std::vector<std::string_view> words = Words(Trim(text));
  if (words.empty()) return std::nullopt;
  DsdSymbol s;
  s.line = number;
  s.comment = std::string(comment);
  s.name = std::string(words[0]);
  if (s.name.size() > kMaxName) {
    *error = "name too long";
    return std::nullopt;
  }
  bool have_kind = false, have_addr = false, have_scope = false;
  for (std::size_t i = 1; i < words.size(); ++i) {
    std::string_view w = words[i];
    std::size_t colon = w.find(':');
    std::string_view key = colon == std::string_view::npos ? w : w.substr(0, colon);
    std::string_view value = colon == std::string_view::npos ? std::string_view() : w.substr(colon + 1);
    if ((key == "kind" && have_kind) || (key == "addr" && have_addr)) {
      // A second kind kept the first's size (has_size) and wrote back a
      // kind that doesn't parse (nds_dsd_fuzzer, bug scrub part 3).
      *error = std::string(key) + " given twice";
      return std::nullopt;
    }
    if (key == "kind") {
      have_kind = true;
      s.kind_text = std::string(value);
      auto [k, opts] = Call(value);
      if (k == "function" || k == "label") {
        s.kind = k == "function" ? DsdSymbolKind::function : DsdSymbolKind::label;
        bool mode = false;
        for (std::string_view o : Commas(opts)) {
          if (o == "arm" || o == "thumb") {
            s.mode = o == "thumb" ? DsdMode::thumb : DsdMode::arm;
            mode = true;
          } else if (o.starts_with("size=")) {
            auto v = U32(o.substr(5));
            if (!v) {
              *error = "bad size '" + std::string(o.substr(5)) + "'";
              return std::nullopt;
            }
            s.size = *v;
            s.has_size = true;
          } else if (o == "unknown") {
            s.unknown = true;
          }
          // dsprot=..., dsprot_range=... are kept in kind_text.
        }
        if (!mode) {
          *error = "kind " + std::string(k) + " needs arm or thumb";
          return std::nullopt;
        }
        if (s.kind == DsdSymbolKind::function && !s.has_size) {
          *error = "function without size";
          return std::nullopt;
        }
      } else if (k == "data") {
        s.kind = DsdSymbolKind::data;
        std::string_view d = opts;
        std::size_t br = d.find('[');
        std::string_view base = br == std::string_view::npos ? d : d.substr(0, br);
        if (base == "any") s.data = DsdDataKind::any;
        else if (base == "byte") s.data = DsdDataKind::byte;
        else if (base == "short") s.data = DsdDataKind::short_;
        else if (base == "word") s.data = DsdDataKind::word;
        else {
          *error = "unknown data kind '" + std::string(base) + "'";
          return std::nullopt;
        }
        if (br != std::string_view::npos) {
          std::size_t close = d.find(']', br);
          if (close == std::string_view::npos || close + 1 != d.size() || s.data == DsdDataKind::any) {
            *error = "bad data array '" + std::string(d) + "'";
            return std::nullopt;
          }
          std::string_view n = d.substr(br + 1, close - br - 1);
          if (n.empty()) {
            s.count = std::nullopt;
          } else {
            auto v = U32(n);
            if (!v) {
              *error = "bad count '" + std::string(n) + "'";
              return std::nullopt;
            }
            s.count = *v;
          }
        }
      } else if (k == "bss") {
        s.kind = DsdSymbolKind::bss;
        for (std::string_view o : Commas(opts)) {
          if (o.starts_with("size=")) {
            auto v = U32(o.substr(5));
            if (!v) {
              *error = "bad size";
              return std::nullopt;
            }
            s.size = *v;
            s.has_size = true;
          }
        }
      } else {
        *error = "unknown kind '" + std::string(k) + "'";
        return std::nullopt;
      }
    } else if (key == "addr") {
      auto v = U32(value);
      if (!v) {
        *error = "bad address '" + std::string(value) + "'";
        return std::nullopt;
      }
      s.addr = *v;
      have_addr = true;
    } else if (key == "local" || key == "weak") {
      if (have_scope) {
        *error = "two scopes";
        return std::nullopt;
      }
      s.scope = key == "local" ? DsdScope::local : DsdScope::weak;
      have_scope = true;
    } else if (key == "global") {
      have_scope = true;
    } else if (key == "ambiguous") {
      s.ambiguous = true;
    } else {
      *error = "unknown attribute '" + std::string(key) + "'";
      return std::nullopt;
    }
  }
  if (!have_kind || !have_addr) {
    *error = have_kind ? "missing addr" : "missing kind";
    return std::nullopt;
  }
  return s;
}

}  // namespace

DsdSymbols parse_dsd_symbols(std::string_view text) {
  DsdSymbols out;
  EachLine(text, [&](std::size_t number, std::string_view line) {
    std::string_view t = Trim(line);
    if (t.empty() || t.starts_with("//")) return;
    std::string error;
    std::optional<DsdSymbol> s = ParseSymbolLine(line, number, &error);
    if (s) out.symbols.push_back(std::move(*s));
    else if (!error.empty()) out.errors.push_back({number, error});
  });
  return out;
}

std::string format_dsd_kind(const DsdSymbol &s) {
  switch (s.kind) {
    case DsdSymbolKind::function: {
      std::string k = "function(";
      k += s.mode == DsdMode::thumb ? "thumb" : "arm";
      k += ",size=0x" + Hex(s.size);
      if (s.unknown) k += ",unknown";
      return k + ")";
    }
    case DsdSymbolKind::label: return std::string("label(") + (s.mode == DsdMode::thumb ? "thumb" : "arm") + ")";
    case DsdSymbolKind::bss: return s.has_size ? "bss(size=0x" + Hex(s.size) + ")" : "bss";
    case DsdSymbolKind::data: {
      const char *base = s.data == DsdDataKind::any     ? "any"
                         : s.data == DsdDataKind::byte  ? "byte"
                         : s.data == DsdDataKind::short_ ? "short"
                                                        : "word";
      std::string k = std::string("data(") + base;
      if (s.data != DsdDataKind::any) {
        if (!s.count) k += "[]";
        else if (*s.count != 1) k += "[" + std::to_string(*s.count) + "]";
      }
      return k + ")";
    }
  }
  return "";
}

std::string format_dsd_symbol(const DsdSymbol &s) {
  std::string out = s.name + " kind:" + (s.kind_text.empty() ? format_dsd_kind(s) : s.kind_text) + " addr:0x" +
                    Hex(s.addr, 8);
  if (s.scope == DsdScope::local) out += " local";
  if (s.scope == DsdScope::weak) out += " weak";
  if (s.ambiguous) out += " ambiguous";
  if (!s.comment.empty()) out += " // " + s.comment;
  return out;
}

// ---- relocs.txt ---------------------------------------------------------

std::string_view to_string(DsdRelocKind k) {
  switch (k) {
    case DsdRelocKind::arm_call: return "arm_call";
    case DsdRelocKind::thumb_call: return "thumb_call";
    case DsdRelocKind::arm_call_thumb: return "arm_call_thumb";
    case DsdRelocKind::thumb_call_arm: return "thumb_call_arm";
    case DsdRelocKind::arm_branch: return "arm_branch";
    case DsdRelocKind::load: return "load";
    case DsdRelocKind::overlay_id: return "overlay_id";
    case DsdRelocKind::link_time_const: return "link_time_const";
  }
  return "?";
}

bool DsdReloc::call() const {
  return kind == DsdRelocKind::arm_call || kind == DsdRelocKind::thumb_call || kind == DsdRelocKind::arm_call_thumb ||
         kind == DsdRelocKind::thumb_call_arm || kind == DsdRelocKind::arm_branch;
}

DsdRelocs parse_dsd_relocs(std::string_view text) {
  DsdRelocs out;
  EachLine(text, [&](std::size_t number, std::string_view line) {
    auto [body, comment] = SplitComment(line);
    std::vector<std::string_view> words = Words(Trim(body));
    if (words.empty()) return;
    DsdReloc r;
    r.line = number;
    bool from = false, to = false, kind = false, module = false;
    std::string error;
    for (std::string_view w : words) {
      std::size_t colon = w.find(':');
      std::string_view key = colon == std::string_view::npos ? w : w.substr(0, colon);
      std::string_view value = colon == std::string_view::npos ? std::string_view() : w.substr(colon + 1);
      if (key == "from" || key == "to") {
        auto v = U32(value);
        if (!v) {
          error = "bad " + std::string(key) + " '" + std::string(value) + "'";
          break;
        }
        (key == "from" ? r.from : r.to) = *v;
        (key == "from" ? from : to) = true;
      } else if (key == "add") {
        auto v = I64(value);
        if (!v) {
          error = "bad add '" + std::string(value) + "'";
          break;
        }
        r.addend = *v;
      } else if (key == "kind") {
        kind = true;
        auto [k, opts] = Call(value);
        if (k == "arm_call") r.kind = DsdRelocKind::arm_call;
        else if (k == "thumb_call") r.kind = DsdRelocKind::thumb_call;
        else if (k == "arm_call_thumb") r.kind = DsdRelocKind::arm_call_thumb;
        else if (k == "thumb_call_arm") r.kind = DsdRelocKind::thumb_call_arm;
        else if (k == "arm_branch") r.kind = DsdRelocKind::arm_branch;
        else if (k == "load") r.kind = DsdRelocKind::load;
        else if (k == "overlay_id") r.kind = DsdRelocKind::overlay_id;
        else if (k == "link_time_const") {
          r.kind = DsdRelocKind::link_time_const;
          r.constant = std::string(opts);
        } else {
          error = "unknown kind '" + std::string(k) + "'";
          break;
        }
      } else if (key == "module") {
        module = true;
        auto [m, opts] = Call(value);
        using K = DsdRelocModule::Kind;
        if (m == "none") r.module.kind = K::none;
        else if (m == "main") r.module.kind = K::main;
        else if (m == "itcm") r.module.kind = K::itcm;
        else if (m == "dtcm") r.module.kind = K::dtcm;
        else if (m == "overlay" || m == "overlays") {
          r.module.kind = m == "overlay" ? K::overlay : K::overlays;
          for (std::string_view id : Commas(opts)) {
            auto v = U32(id);
            if (!v || *v > 0xffff || r.module.ids.size() >= 4096) {
              error = "bad overlay id '" + std::string(id) + "'";
              break;
            }
            r.module.ids.push_back(static_cast<std::uint16_t>(*v));
          }
          if (error.empty() && (m == "overlay" ? r.module.ids.size() != 1 : r.module.ids.size() < 2))
            error = "bad overlay list '" + std::string(opts) + "'";
          if (!error.empty()) break;
        } else if (m == "autoload") {
          r.module.kind = K::autoload;
          auto v = U32(opts);
          if (!v) {
            error = "bad autoload index";
            break;
          }
          r.module.index = *v;
        } else {
          error = "unknown module '" + std::string(m) + "'";
          break;
        }
      } else {
        error = "unknown attribute '" + std::string(key) + "'";
        break;
      }
    }
    if (error.empty()) {
      const bool constant = r.kind == DsdRelocKind::link_time_const;
      if (!from) error = "missing from";
      else if (!kind) error = "missing kind";
      else if (!to && !constant) error = "missing to";
      else if (!module && !constant && r.kind != DsdRelocKind::overlay_id) error = "missing module";
    }
    if (!error.empty()) {
      out.errors.push_back({number, error});
      return;
    }
    out.relocs.push_back(std::move(r));
  });
  return out;
}

// ---- delinks.txt --------------------------------------------------------

const DsdSection *DsdDelinks::section(std::string_view name) const {
  for (const DsdSection &s : sections)
    if (s.name == name) return &s;
  return nullptr;
}

std::pair<std::uint32_t, std::uint32_t> DsdDelinks::extent() const {
  if (sections.empty()) return {0, 0};
  std::uint32_t lo = 0xffffffffu, hi = 0;
  for (const DsdSection &s : sections) {
    lo = std::min(lo, s.start);
    hi = std::max(hi, s.end);
  }
  return {lo, hi};
}

DsdDelinks parse_dsd_delinks(std::string_view text) {
  DsdDelinks out;
  DsdDelinkFile *file = nullptr;
  EachLine(text, [&](std::size_t number, std::string_view line) {
    auto [body, comment] = SplitComment(line);
    std::string_view t = Trim(body);
    if (t.empty()) {
      // A blank line ends a file's entry.
      if (Trim(line).empty()) file = nullptr;
      return;
    }
    const bool indented = body.front() == ' ' || body.front() == '\t';
    if (!indented) {
      if (t.back() != ':') {
        out.errors.push_back({number, "expected a file path ending in ':'"});
        file = nullptr;
        return;
      }
      if (out.files.size() >= (1u << 20)) return;
      DsdDelinkFile f;
      f.name = std::string(t.substr(0, t.size() - 1));
      f.line = number;
      out.files.push_back(std::move(f));
      file = &out.files.back();
      return;
    }
    if (t == "complete") {
      if (file) file->complete = true;
      return;
    }
    if (t.starts_with("categories:")) {
      std::vector<std::string> &into = file ? file->categories : out.categories;
      for (std::string_view c : Commas(t.substr(11)))
        if (!c.empty()) into.emplace_back(c);
      return;
    }
    std::vector<std::string_view> words = Words(t);
    DsdSection s;
    s.name = std::string(words[0]);
    s.line = number;
    bool start = false, end = false;
    std::string error;
    for (std::size_t i = 1; i < words.size(); ++i) {
      std::string_view w = words[i];
      std::size_t colon = w.find(':');
      std::string_view key = colon == std::string_view::npos ? w : w.substr(0, colon);
      std::string_view value = colon == std::string_view::npos ? std::string_view() : w.substr(colon + 1);
      if (key == "start" || key == "end" || key == "align") {
        auto v = U32(value);
        if (!v) {
          error = "bad " + std::string(key);
          break;
        }
        if (key == "start") s.start = *v, start = true;
        else if (key == "end") s.end = *v, end = true;
        else s.align = *v;
      } else if (key == "kind") {
        if (value != "code" && value != "data" && value != "rodata" && value != "bss") {
          error = "unknown section kind '" + std::string(value) + "'";
          break;
        }
        s.kind = std::string(value);
      } else {
        error = "unknown attribute '" + std::string(key) + "'";
        break;
      }
    }
    if (error.empty() && (!start || !end)) error = "a section needs start and end";
    if (error.empty() && s.end < s.start) error = "a section ends before it starts";
    if (error.empty() && !file && s.kind.empty()) error = "a module section needs a kind";
    if (!error.empty()) {
      out.errors.push_back({number, error});
      return;
    }
    if (file) {
      if (file->sections.size() < 4096) file->sections.push_back(std::move(s));
    } else if (out.sections.size() < 4096) {
      out.sections.push_back(std::move(s));
    }
  });
  return out;
}

// ---- Export ---------------------------------------------------------------

bool generated_name(std::string_view n) {
  static constexpr std::string_view kPrefixes[] = {
      "FUN_",  "DAT_",  "LAB_",  "SUB_",  "PTR_",    "UNK_",      "EXT_",     "thunk_FUN_", "switchD_", "caseD_",
      "s_",    "u_",    "BYTE_", "WORD_", "DWORD_",  "QWORD_",    "OFF_",     "ADDR_",      "func_",    "data_",
      "Elf",   "_LAB_", "LAB",   "fun_",  "__sinit_"};
  for (std::string_view p : kPrefixes) {
    if (!n.starts_with(p)) continue;
    std::string_view rest = n.substr(p.size());
    if (p == "s_" || p == "u_") return true;  // string labels
    if (p == "Elf") return false;
    // func_0200abcd, func_ov006_0221a000, FUN_0200abcd, switchD_...
    if (rest.starts_with("ov") && rest.size() > 6 && rest[5] == '_') rest = rest.substr(6);
    if (p == "switchD_" || p == "caseD_" || p == "thunk_FUN_") return true;
    if (rest.empty()) return false;
    bool hex = std::all_of(rest.begin(), rest.end(), [](char c) {
      return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    });
    if (hex) return true;
  }
  return false;
}

SymbolsExport export_dsd_symbols(std::string_view old_text, const std::vector<ExportSymbol> &symbols, SameName same,
                                 void *ctx, const ExportOptions &options) {
  SymbolsExport out;
  std::vector<std::string> lines = Lines(old_text);
  const bool trailing_newline = old_text.empty() || old_text.back() == '\n';
  // The old file's symbols by address, with their line index.
  std::multimap<std::uint32_t, std::pair<std::size_t, DsdSymbol>> old;
  std::uint32_t last = 0;
  bool sorted = true;
  for (std::size_t i = 0; i < lines.size(); ++i) {
    std::string_view t = Trim(lines[i]);
    if (t.empty() || t.starts_with("//")) continue;
    std::string error;
    std::optional<DsdSymbol> s = ParseSymbolLine(lines[i], i + 1, &error);
    if (!s) continue;
    if (s->addr < last) sorted = false;
    last = s->addr;
    old.emplace(s->addr, std::make_pair(i, std::move(*s)));
  }
  auto is_same = [&](std::string_view dsd, std::string_view rk) { return dsd == rk || (same && same(ctx, dsd, rk)); };
  // Inserted lines, keyed by the line index they go before (lines.size(): the end).
  std::multimap<std::size_t, std::string> inserts;
  std::map<std::uint32_t, std::size_t> first_line_at_or_after;  // for sorted insertion
  for (const auto &[addr, v] : old) first_line_at_or_after.emplace(addr, v.first);
  for (const ExportSymbol &e : symbols) {
    if (e.name.empty()) continue;
    auto [lo, hi] = old.equal_range(e.addr);
    if (lo != hi) {
      bool matched = false;
      for (auto it = lo; it != hi; ++it)
        if (is_same(it->second.second.name, e.name)) matched = true;
      if (matched || !options.rename) continue;
      if (generated_name(e.name)) continue;  // revkit's FUN_ never replaces a dsd name
      // Rename the listed symbol of the matching kind (functions for
      // functions, the rest for data), else the first one.
      auto pick = lo;
      for (auto it = lo; it != hi; ++it) {
        const bool fn = it->second.second.kind == DsdSymbolKind::function;
        if (fn == (e.kind == DsdSymbolKind::function)) {
          pick = it;
          break;
        }
      }
      DsdSymbol &s = pick->second.second;
      SymbolChange c;
      c.addr = e.addr;
      c.old_name = s.name;
      c.new_name = e.name;
      c.line = pick->second.first + 1;
      if (!dsd_name_ok(e.name)) {
        c.kind = SymbolChange::Kind::skipped;
        c.reason = "dsd can't read this name back (spaces, '//' or unbalanced parentheses)";
        ++out.skipped;
        out.changes.push_back(std::move(c));
        continue;
      }
      // Replace only the name, keeping the rest of the line as written.
      std::string &line = lines[pick->second.first];
      std::size_t lead = 0;
      while (lead < line.size() && (line[lead] == ' ' || line[lead] == '\t')) ++lead;
      line = line.substr(0, lead) + e.name + line.substr(lead + s.name.size());
      s.name = e.name;
      c.kind = SymbolChange::Kind::renamed;
      ++out.renamed;
      out.changes.push_back(std::move(c));
      continue;
    }
    if (!options.add_new || generated_name(e.name)) continue;
    SymbolChange c;
    c.kind = SymbolChange::Kind::added;
    c.addr = e.addr;
    c.new_name = e.name;
    if (!dsd_name_ok(e.name)) {
      c.kind = SymbolChange::Kind::skipped;
      c.reason = "dsd can't read this name back (spaces, '//' or unbalanced parentheses)";
      ++out.skipped;
      out.changes.push_back(std::move(c));
      continue;
    }
    if (e.kind == DsdSymbolKind::function && e.size == 0) {
      c.kind = SymbolChange::Kind::skipped;
      c.reason = "a function needs its size";
      ++out.skipped;
      out.changes.push_back(std::move(c));
      continue;
    }
    DsdSymbol s;
    s.name = e.name;
    s.addr = e.addr;
    s.mode = e.mode;
    if (e.kind == DsdSymbolKind::function) {
      s.kind = DsdSymbolKind::function;
      s.size = e.size;
      s.has_size = true;
    } else if (e.kind == DsdSymbolKind::label) {
      s.kind = DsdSymbolKind::label;
    } else if (e.in_bss || e.kind == DsdSymbolKind::bss) {
      s.kind = DsdSymbolKind::bss;
    } else {
      s.kind = DsdSymbolKind::data;
      s.data = e.data;
      s.count = e.data == DsdDataKind::any ? std::optional<std::uint32_t>(1) : e.count;
    }
    std::size_t at = lines.size();
    if (sorted) {
      auto it = first_line_at_or_after.lower_bound(e.addr);
      if (it != first_line_at_or_after.end()) at = it->second;
    }
    inserts.emplace(at, format_dsd_symbol(s));
    ++out.added;
    out.changes.push_back(std::move(c));
  }
  std::string text;
  for (std::size_t i = 0; i <= lines.size(); ++i) {
    auto [lo, hi] = inserts.equal_range(i);
    for (auto it = lo; it != hi; ++it) text += it->second + "\n";
    if (i < lines.size()) {
      text += lines[i];
      if (i + 1 < lines.size() || trailing_newline) text += "\n";
    }
  }
  if (!trailing_newline && !inserts.empty() && inserts.rbegin()->first == lines.size() && !lines.empty()) {
    // An append after a last line without a newline: that line got one above.
  }
  out.text = std::move(text);
  std::sort(out.changes.begin(), out.changes.end(),
            [](const SymbolChange &a, const SymbolChange &b) { return a.addr < b.addr; });
  return out;
}

std::string unified_diff(std::string_view a, std::string_view b, std::string_view label_a, std::string_view label_b) {
  if (a == b) return "";
  std::vector<std::string> x = Lines(a), y = Lines(b);
  // Trim the common prefix and suffix, then an LCS over what is left
  // (bounded: past 4000x4000 lines the middle is one replaced hunk).
  std::size_t pre = 0;
  while (pre < x.size() && pre < y.size() && x[pre] == y[pre]) ++pre;
  std::size_t suf = 0;
  while (suf < x.size() - pre && suf < y.size() - pre && x[x.size() - 1 - suf] == y[y.size() - 1 - suf]) ++suf;
  const std::size_t n = x.size() - pre - suf, m = y.size() - pre - suf;
  // ops: ' ' keep, '-' delete, '+' insert, with indexes.
  struct Op {
    char c;
    std::size_t i, j;
  };
  std::vector<Op> ops;
  for (std::size_t k = 0; k < pre; ++k) ops.push_back({' ', k, k});
  // One flat table of (n+1) x (m+1) entries, at most 16M (64 MB): a vector
  // per row cost 40 bytes a row, 640 MB for 16M lines against one (bug
  // scrub part 3).
  if ((n + 1) * (m + 1) <= 16'000'000) {
    std::vector<std::uint32_t> table((n + 1) * (m + 1), 0);
    auto L = [&](std::size_t i, std::size_t j) -> std::uint32_t & { return table[i * (m + 1) + j]; };
    for (std::size_t i = n; i-- > 0;)
      for (std::size_t j = m; j-- > 0;)
        L(i, j) = x[pre + i] == y[pre + j] ? L(i + 1, j + 1) + 1 : std::max(L(i + 1, j), L(i, j + 1));
    std::size_t i = 0, j = 0;
    while (i < n || j < m) {
      if (i < n && j < m && x[pre + i] == y[pre + j]) {
        ops.push_back({' ', pre + i, pre + j});
        ++i, ++j;
      } else if (j < m && (i == n || L(i, j + 1) > L(i + 1, j))) {
        ops.push_back({'+', pre + i, pre + j});
        ++j;
      } else {
        ops.push_back({'-', pre + i, pre + j});
        ++i;
      }
    }
  } else {
    for (std::size_t i = 0; i < n; ++i) ops.push_back({'-', pre + i, pre});
    for (std::size_t j = 0; j < m; ++j) ops.push_back({'+', pre + n, pre + j});
  }
  for (std::size_t k = 0; k < suf; ++k) ops.push_back({' ', pre + n + k, pre + m + k});
  std::string out = "--- " + std::string(label_a) + "\n+++ " + std::string(label_b) + "\n";
  const std::size_t ctx = 3;
  std::size_t k = 0;
  while (k < ops.size()) {
    while (k < ops.size() && ops[k].c == ' ') ++k;
    if (k >= ops.size()) break;
    std::size_t start = k >= ctx ? k - ctx : 0;
    std::size_t end = k;
    // Extend while changes are within 2*ctx of each other.
    while (end < ops.size()) {
      if (ops[end].c != ' ') {
        ++end;
        continue;
      }
      std::size_t run = end;
      while (run < ops.size() && ops[run].c == ' ') ++run;
      if (run < ops.size() && run - end <= 2 * ctx) {
        end = run;
        continue;
      }
      end = std::min(end + ctx, ops.size());
      break;
    }
    std::size_t a0 = ops[start].i, b0 = ops[start].j, na = 0, nb = 0;
    for (std::size_t q = start; q < end; ++q) {
      if (ops[q].c != '+') ++na;
      if (ops[q].c != '-') ++nb;
    }
    out += "@@ -" + std::to_string(na ? a0 + 1 : a0) + "," + std::to_string(na) + " +" +
           std::to_string(nb ? b0 + 1 : b0) + "," + std::to_string(nb) + " @@\n";
    for (std::size_t q = start; q < end; ++q) {
      const Op &o = ops[q];
      out += o.c;
      out += o.c == '+' ? y[o.j] : x[o.i];
      out += "\n";
    }
    k = end;
  }
  return out;
}

}  // namespace revkit::nds
