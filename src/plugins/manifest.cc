#include "revkit/plugins/manifest.h"

#include <cctype>
#include <map>
#include <memory>
#include <variant>

namespace revkit::plugins {

std::string_view to_string(Kind k) {
  switch (k) {
    case Kind::analyzer: return "analyzer";
    case Kind::loader: return "loader";
    case Kind::command: return "command";
    case Kind::peripheral: return "peripheral";
  }
  return "?";
}

std::string_view to_string(Capability c) {
  switch (c) {
    case Capability::memory: return "memory";
    case Capability::code: return "code";
    case Capability::file: return "file";
    case Capability::irq: return "irq";
    case Capability::output: return "output";
    case Capability::bus: return "bus";
  }
  return "?";
}

std::optional<Capability> capability_from_string(std::string_view s) {
  if (s == "memory") return Capability::memory;
  if (s == "code") return Capability::code;
  if (s == "file") return Capability::file;
  if (s == "irq") return Capability::irq;
  if (s == "output") return Capability::output;
  if (s == "bus") return Capability::bus;
  return std::nullopt;
}

namespace {

// Just enough JSON for manifests: objects, arrays, strings (with escapes),
// numbers (non-negative integers), booleans and null. Duplicate keys and
// trailing data are errors.
struct Json;
using Object = std::map<std::string, Json>;
using Array = std::vector<Json>;
struct Json {
  std::variant<std::nullptr_t, bool, std::uint64_t, std::string, std::shared_ptr<Array>, std::shared_ptr<Object>> v;
};

class Parser {
 public:
  explicit Parser(std::string_view in) : in_(in) {}

  Json document() {
    Json j = value(0);
    ws();
    if (pos_ != in_.size()) fail("trailing data");
    return j;
  }

 private:
  [[noreturn]] void fail(const std::string &what) {
    throw ManifestError("manifest is not valid JSON: " + what + " at offset " + std::to_string(pos_));
  }
  void ws() {
    while (pos_ < in_.size() && std::isspace(static_cast<unsigned char>(in_[pos_]))) ++pos_;
  }
  bool eat(char c) {
    ws();
    if (pos_ < in_.size() && in_[pos_] == c) {
      ++pos_;
      return true;
    }
    return false;
  }
  void expect(char c) {
    if (!eat(c)) fail(std::string("expected '") + c + "'");
  }
  bool word(std::string_view w) {
    if (in_.substr(pos_, w.size()) != w) return false;
    pos_ += w.size();
    return true;
  }

  Json value(int depth) {
    if (depth > 32) fail("nesting too deep");
    ws();
    if (pos_ >= in_.size()) fail("unexpected end");
    char c = in_[pos_];
    if (c == '{') {
      ++pos_;
      auto obj = std::make_shared<Object>();
      if (eat('}')) return {obj};
      do {
        ws();
        std::string key = string();
        expect(':');
        if (!obj->emplace(key, value(depth + 1)).second) fail("duplicate key \"" + key + "\"");
      } while (eat(','));
      expect('}');
      return {obj};
    }
    if (c == '[') {
      ++pos_;
      auto arr = std::make_shared<Array>();
      if (eat(']')) return {arr};
      do arr->push_back(value(depth + 1));
      while (eat(','));
      expect(']');
      return {arr};
    }
    if (c == '"') return {string()};
    if (word("true")) return {true};
    if (word("false")) return {false};
    if (word("null")) return {nullptr};
    if (std::isdigit(static_cast<unsigned char>(c))) {
      std::uint64_t n = 0;
      while (pos_ < in_.size() && std::isdigit(static_cast<unsigned char>(in_[pos_]))) {
        std::uint64_t d = static_cast<std::uint64_t>(in_[pos_++] - '0');
        if (n > (UINT64_MAX - d) / 10) fail("number too large");
        n = n * 10 + d;
      }
      if (pos_ < in_.size() && (in_[pos_] == '.' || in_[pos_] == 'e' || in_[pos_] == 'E'))
        fail("only non-negative integers are allowed");
      return {n};
    }
    fail("unexpected character");
  }

  std::string string() {
    if (pos_ >= in_.size() || in_[pos_] != '"') fail("expected a string");
    ++pos_;
    std::string out;
    while (true) {
      if (pos_ >= in_.size()) fail("unterminated string");
      char c = in_[pos_++];
      if (c == '"') return out;
      if (static_cast<unsigned char>(c) < 0x20) fail("control character in string");
      if (c != '\\') {
        out.push_back(c);
        continue;
      }
      if (pos_ >= in_.size()) fail("unterminated escape");
      char e = in_[pos_++];
      switch (e) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          if (in_.size() - pos_ < 4) fail("short \\u escape");
          unsigned cp = 0;
          for (int i = 0; i < 4; ++i) {
            char h = in_[pos_++];
            cp <<= 4;
            if (h >= '0' && h <= '9') cp |= static_cast<unsigned>(h - '0');
            else if (h >= 'a' && h <= 'f') cp |= static_cast<unsigned>(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F') cp |= static_cast<unsigned>(h - 'A' + 10);
            else fail("bad \\u escape");
          }
          if (cp >= 0xd800 && cp < 0xe000) fail("surrogates are not supported");
          if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
          } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
          } else {
            out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
          }
          break;
        }
        default: fail("bad escape");
      }
    }
  }

  std::string_view in_;
  std::size_t pos_ = 0;
};

// Typed access with errors that name the field.
class Fields {
 public:
  Fields(const Json &j, std::string path) : path_(std::move(path)) {
    auto *o = std::get_if<std::shared_ptr<Object>>(&j.v);
    if (!o) throw ManifestError(where() + "must be an object");
    obj_ = o->get();
  }

  const Json *get(const std::string &key) {
    seen_.insert(key);
    auto it = obj_->find(key);
    return it == obj_->end() ? nullptr : &it->second;
  }
  std::string str(const std::string &key, bool required) {
    const Json *j = get(key);
    if (!j) {
      if (required) throw ManifestError(where() + "\"" + key + "\" is required");
      return {};
    }
    auto *s = std::get_if<std::string>(&j->v);
    if (!s) throw ManifestError(where() + "\"" + key + "\" must be a string");
    return *s;
  }
  std::uint64_t num(const std::string &key, bool required) {
    const Json *j = get(key);
    if (!j) {
      if (required) throw ManifestError(where() + "\"" + key + "\" is required");
      return 0;
    }
    auto *n = std::get_if<std::uint64_t>(&j->v);
    if (!n) throw ManifestError(where() + "\"" + key + "\" must be a non-negative integer");
    return *n;
  }
  bool boolean(const std::string &key) {
    const Json *j = get(key);
    if (!j) return false;
    auto *b = std::get_if<bool>(&j->v);
    if (!b) throw ManifestError(where() + "\"" + key + "\" must be true or false");
    return *b;
  }
  const Array *array(const std::string &key) {
    const Json *j = get(key);
    if (!j) return nullptr;
    auto *a = std::get_if<std::shared_ptr<Array>>(&j->v);
    if (!a) throw ManifestError(where() + "\"" + key + "\" must be an array");
    return a->get();
  }
  // Unknown keys are errors, so a typo ("capabilites") can't silently
  // drop a request.
  void done() {
    for (const auto &[k, v] : *obj_)
      if (!seen_.contains(k)) throw ManifestError(where() + "unknown field \"" + k + "\"");
  }
  std::string where() const { return path_.empty() ? std::string("manifest: ") : "manifest: " + path_ + ": "; }

 private:
  const Object *obj_ = nullptr;
  std::string path_;
  std::set<std::string> seen_;
};

bool valid_name(const std::string &s) {
  if (s.empty() || s.size() > 64) return false;
  if (!std::islower(static_cast<unsigned char>(s[0])) && !std::isdigit(static_cast<unsigned char>(s[0]))) return false;
  for (char c : s)
    if (!std::islower(static_cast<unsigned char>(c)) && !std::isdigit(static_cast<unsigned char>(c)) && c != '-' &&
        c != '_' && c != '.')
      return false;
  return true;
}

bool valid_version(const std::string &s) {
  // MAJOR.MINOR.PATCH, optionally with a -prerelease of [0-9A-Za-z.-].
  std::size_t i = 0;
  for (int part = 0; part < 3; ++part) {
    std::size_t start = i;
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) ++i;
    if (i == start || i - start > 9) return false;
    if (part < 2) {
      if (i >= s.size() || s[i] != '.') return false;
      ++i;
    }
  }
  if (i == s.size()) return true;
  if (s[i] != '-' || i + 1 == s.size()) return false;
  for (++i; i < s.size(); ++i)
    if (!std::isalnum(static_cast<unsigned char>(s[i])) && s[i] != '.' && s[i] != '-') return false;
  return true;
}

}  // namespace

Manifest parse_manifest(std::string_view json) {
  if (json.size() > (1u << 20)) throw ManifestError("manifest is larger than 1 MiB");
  Json doc = Parser(json).document();
  Fields f(doc, "");
  Manifest m;
  m.name = f.str("name", true);
  if (!valid_name(m.name))
    throw ManifestError("manifest: \"name\" must be 1-64 characters of [a-z0-9._-], starting with a letter or digit");
  m.version = f.str("version", true);
  if (!valid_version(m.version)) throw ManifestError("manifest: \"version\" must be a semantic version (1.2.3)");
  std::string kind = f.str("kind", true);
  if (kind == "analyzer") m.kind = Kind::analyzer;
  else if (kind == "loader") m.kind = Kind::loader;
  else if (kind == "command") m.kind = Kind::command;
  else if (kind == "peripheral") m.kind = Kind::peripheral;
  else throw ManifestError("manifest: \"kind\" must be analyzer, loader, command or peripheral");
  std::uint64_t iface = f.num("interface", true);
  if (iface == 0 || iface > 0xffffffffu) throw ManifestError("manifest: \"interface\" must be a positive version");
  m.interface_version = static_cast<std::uint32_t>(iface);
  m.description = f.str("description", false);
  if (const Array *caps = f.array("capabilities")) {
    for (const Json &c : *caps) {
      auto *s = std::get_if<std::string>(&c.v);
      if (!s) throw ManifestError("manifest: \"capabilities\" must be strings");
      auto cap = capability_from_string(*s);
      if (!cap) throw ManifestError("manifest: unknown capability \"" + *s + "\" (memory, code, file, irq, output, bus)");
      m.capabilities.insert(*cap);
    }
  }

  const Json *analyzer = f.get("analyzer");
  const Json *loader = f.get("loader");
  const Json *command = f.get("command");
  const Json *peripheral = f.get("peripheral");
  if ((analyzer && m.kind != Kind::analyzer) || (loader && m.kind != Kind::loader) ||
      (command && m.kind != Kind::command) || (peripheral && m.kind != Kind::peripheral))
    throw ManifestError("manifest: a section for another kind of plugin is present");
  if (analyzer) {
    Fields a(*analyzer, "analyzer");
    std::string scope = a.str("scope", false);
    if (scope == "function") m.function_scope = true;
    else if (!scope.empty() && scope != "program")
      throw ManifestError("manifest: analyzer: \"scope\" must be program or function");
    a.done();
  }
  if (m.kind == Kind::loader) {
    if (!loader) throw ManifestError("manifest: loaders need a \"loader\" section with their magic");
    Fields l(*loader, "loader");
    std::string hex = l.str("magic", true);
    if (hex.empty() || hex.size() % 2 || hex.size() > 128)
      throw ManifestError("manifest: loader: \"magic\" must be 1 to 64 bytes of hex");
    for (std::size_t i = 0; i < hex.size(); i += 2) {
      auto nib = [&](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw ManifestError("manifest: loader: \"magic\" must be hex");
      };
      m.magic.push_back(static_cast<char>(nib(hex[i]) * 16 + nib(hex[i + 1])));
    }
    m.magic_offset = l.num("offset", false);
    l.done();
  }
  if (command) {
    Fields c(*command, "command");
    if (const Array *args = c.array("args")) {
      std::set<std::string> names;
      for (const Json &aj : *args) {
        Fields a(aj, "command.args");
        CommandArg arg;
        arg.name = a.str("name", true);
        arg.description = a.str("description", false);
        arg.required = a.boolean("required");
        a.done();
        if (!names.insert(arg.name).second) throw ManifestError("manifest: duplicate command arg \"" + arg.name + "\"");
        m.args.push_back(std::move(arg));
      }
    }
    c.done();
  }
  if (m.kind == Kind::peripheral) {
    for (Capability c : m.capabilities)
      if (c == Capability::memory || c == Capability::code || c == Capability::file)
        throw ManifestError("manifest: a peripheral sees the emulated machine, not the program: capabilities irq, output, bus");
    m.outputs = {"irq"};
    if (peripheral) {
      Fields p(*peripheral, "peripheral");
      if (const Array *outs = p.array("outputs")) {
        m.outputs.clear();
        for (const Json &o : *outs) {
          auto *s = std::get_if<std::string>(&o.v);
          if (!s || s->empty() || s->size() > 32) throw ManifestError("manifest: peripheral: \"outputs\" are names");
          m.outputs.push_back(*s);
        }
        if (m.outputs.size() > 64) throw ManifestError("manifest: peripheral: at most 64 outputs");
      }
      const std::uint64_t inputs = p.num("inputs", false);
      if (inputs > 1024) throw ManifestError("manifest: peripheral: at most 1024 inputs");
      m.inputs = static_cast<std::uint32_t>(inputs);
      if (const std::uint64_t size = p.num("size", false)) m.region_size = size;
      p.done();
    }
  } else {
    for (Capability c : m.capabilities)
      if (c == Capability::irq || c == Capability::output || c == Capability::bus)
        throw ManifestError("manifest: capability \"" + std::string(to_string(c)) + "\" is for peripherals");
  }
  if (const Json *limits = f.get("limits")) {
    Fields l(*limits, "limits");
    m.fuel = l.num("fuel", false);
    std::uint64_t mb = l.num("memory_mb", false);
    if (mb > (1u << 20)) throw ManifestError("manifest: limits: \"memory_mb\" is too large");
    m.memory_bytes = mb << 20;
    l.done();
  }
  f.done();
  return m;
}

}  // namespace revkit::plugins
