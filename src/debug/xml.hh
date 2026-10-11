// A small XML reader for what GDB stubs send: target descriptions,
// library lists, thread lists and memory maps. Elements, attributes and
// text with the predefined and numeric entities; no DTDs, namespaces are
// kept in names ("xi:include").
#pragma once

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::debug::xml {

struct Node {
  std::string name;
  std::map<std::string, std::string> attrs;
  std::vector<Node> children;
  std::string text;

  const std::string *attr(const std::string &key) const {
    auto it = attrs.find(key);
    return it == attrs.end() ? nullptr : &it->second;
  }
  std::string attr_or(const std::string &key, std::string def = {}) const {
    const std::string *a = attr(key);
    return a != nullptr ? *a : def;
  }
  // Direct children named `name`.
  std::vector<const Node *> all(std::string_view name) const;
  const Node *first(std::string_view name) const;
};

// The document's root element; nullopt if it isn't well-formed enough.
std::optional<Node> parse(std::string_view text, std::string *error = nullptr);

// "0x1f" / "31" to a number.
std::optional<unsigned long long> number(std::string_view text);

}  // namespace revkit::debug::xml
