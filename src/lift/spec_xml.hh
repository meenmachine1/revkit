// Reading Ghidra's spec XML (.pspec, .cspec) through the decompiler's
// Element tree (internal).
#pragma once

#include "xml.hh"

#include <optional>
#include <string>

namespace revkit::lift::spec_xml {

inline std::string attribute(const ghidra::Element *el, const std::string &name) {
  for (int i = 0; i < el->getNumAttributes(); ++i)
    if (el->getAttributeName(i) == name) return el->getAttributeValue(i);
  return {};
}

inline const ghidra::Element *child(const ghidra::Element *el, const std::string &name) {
  for (const ghidra::Element *c : el->getChildren())
    if (c->getName() == name) return c;
  return nullptr;
}

// An attribute of a <data_organization> child, e.g. <long_size value="8"/>:
// true/false as 1/0, numbers in any base.
inline std::optional<long> org_value(const ghidra::Element *org, const std::string &tag,
                                     const std::string &attr = "value") {
  if (org == nullptr) return std::nullopt;
  for (const ghidra::Element *el : org->getChildren()) {
    if (el->getName() != tag) continue;
    for (int i = 0; i < el->getNumAttributes(); ++i) {
      if (el->getAttributeName(i) != attr) continue;
      const std::string &v = el->getAttributeValue(i);
      if (v == "true") return 1;
      if (v == "false") return 0;
      try {
        return std::stol(v, nullptr, 0);
      } catch (const std::exception &) {
        return std::nullopt;
      }
    }
  }
  return std::nullopt;
}

}  // namespace revkit::lift::spec_xml
