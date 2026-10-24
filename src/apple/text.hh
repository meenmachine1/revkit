// Text and byte helpers the Apple readers share (internal).
#pragma once

#include "revkit/apple/plist.hh"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace revkit::apple::detail {

inline void append_utf8(std::string &out, std::uint32_t cp) {
  if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) cp = 0xfffd;
  if (cp < 0x80) {
    out += static_cast<char>(cp);
  } else if (cp < 0x800) {
    out += static_cast<char>(0xc0 | cp >> 6);
    out += static_cast<char>(0x80 | (cp & 0x3f));
  } else if (cp < 0x10000) {
    out += static_cast<char>(0xe0 | cp >> 12);
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
    out += static_cast<char>(0x80 | (cp & 0x3f));
  } else {
    out += static_cast<char>(0xf0 | cp >> 18);
    out += static_cast<char>(0x80 | ((cp >> 12) & 0x3f));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
    out += static_cast<char>(0x80 | (cp & 0x3f));
  }
}

// UTF-16 code units to UTF-8; a lone surrogate is U+FFFD.
inline std::string utf16_to_utf8(std::span<const std::uint16_t> u) {
  std::string out;
  out.reserve(u.size());
  for (std::size_t i = 0; i < u.size(); ++i) {
    std::uint32_t c = u[i];
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < u.size() && u[i + 1] >= 0xdc00 && u[i + 1] <= 0xdfff) {
      c = 0x10000 + ((c - 0xd800) << 10) + (u[i + 1] - 0xdc00);
      ++i;
    } else if (c >= 0xd800 && c <= 0xdfff) {
      c = 0xfffd;
    }
    append_utf8(out, c);
  }
  return out;
}

// Bytes as valid UTF-8: invalid sequences become U+FFFD.
inline std::string valid_utf8(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size();) {
    const auto c = static_cast<std::uint8_t>(s[i]);
    unsigned n = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
    bool ok = n != 0 && i + n <= s.size();
    std::uint32_t cp = n == 1 ? c : n == 2 ? (c & 0x1f) : n == 3 ? (c & 0x0f) : (c & 0x07);
    for (unsigned k = 1; ok && k < n; ++k) {
      const auto d = static_cast<std::uint8_t>(s[i + k]);
      if ((d & 0xc0) != 0x80) ok = false;
      cp = cp << 6 | (d & 0x3f);
    }
    if (ok && ((n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10ffff)) ||
               (cp >= 0xd800 && cp <= 0xdfff)))
      ok = false;
    if (!ok) {
      out += "\xef\xbf\xbd";
      ++i;
      continue;
    }
    out.append(s.substr(i, n));
    i += n;
  }
  return out;
}

// A dictionary's repeated keys: the last value wins, in the first key's
// place (CFDictionary's behaviour when a file repeats a key).
inline void dedupe(std::vector<DictEntry> &d) {
  if (d.size() < 2) return;
  std::unordered_map<std::string, std::size_t> first;
  first.reserve(d.size());
  std::vector<DictEntry> out;
  out.reserve(d.size());
  for (DictEntry &e : d) {
    auto [it, fresh] = first.try_emplace(e.key, out.size());
    if (fresh) out.push_back(std::move(e));
    else out[it->second].value = std::move(e.value);
  }
  d = std::move(out);
}

inline std::string hex(std::span<const std::byte> b) {
  static const char *digits = "0123456789abcdef";
  std::string out;
  out.reserve(b.size() * 2);
  for (std::byte x : b) {
    out += digits[std::to_integer<unsigned>(x) >> 4];
    out += digits[std::to_integer<unsigned>(x) & 15];
  }
  return out;
}

}  // namespace revkit::apple::detail
