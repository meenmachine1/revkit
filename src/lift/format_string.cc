#include "revkit/lift/format_string.hh"

#include <cctype>

namespace revkit::lift {

namespace {

enum class Length { none, hh, h, l, ll, L, j, z, t, i64, i32 };

// Reads a length modifier at `i`.
Length length(std::string_view f, std::size_t &i, const FormatModel &m) {
  auto at = [&](std::size_t k) { return k < f.size() ? f[k] : '\0'; };
  switch (at(i)) {
    case 'h':
      if (at(i + 1) == 'h') {
        i += 2;
        return Length::hh;
      }
      ++i;
      return Length::h;
    case 'l':
      if (at(i + 1) == 'l') {
        i += 2;
        return Length::ll;
      }
      ++i;
      return Length::l;
    case 'q': ++i; return Length::ll;
    case 'L': ++i; return Length::L;
    case 'j': ++i; return Length::j;
    case 'z': ++i; return Length::z;
    case 't': ++i; return Length::t;
    case 'I':
      if (!m.windows) return Length::none;
      if (at(i + 1) == '6' && at(i + 2) == '4') {
        i += 3;
        return Length::i64;
      }
      if (at(i + 1) == '3' && at(i + 2) == '2') {
        i += 3;
        return Length::i32;
      }
      ++i;
      return Length::z;  // %Id: pointer-sized
    case 'w':
      if (!m.windows) return Length::none;
      ++i;
      return Length::l;
    default: return Length::none;
  }
}

int integer_size(Length l, const FormatModel &m) {
  switch (l) {
    case Length::l: return m.long_size;
    case Length::ll: case Length::j: case Length::i64: return m.long_long_size;
    case Length::z: case Length::t: return m.pointer_size;
    case Length::i32: return 4;
    default: return m.int_size;
  }
}

// The conversion's argument, or none (%%); false for an unknown conversion.
bool convert(char c, Length l, bool scan, const FormatModel &m, std::vector<FormatArg> &out) {
  using K = FormatArg::Kind;
  const bool wide_default = m.windows;  // Microsoft's %S/%C: the other width
  switch (c) {
    case 'd': case 'i':
      if (scan) out.push_back({K::int_ptr, l == Length::hh ? 1 : l == Length::h ? 2 : integer_size(l, m), true});
      else out.push_back({K::integer, integer_size(l, m), true});
      return true;
    case 'u': case 'o': case 'x': case 'X': case 'b': case 'B':
      if (scan) out.push_back({K::int_ptr, l == Length::hh ? 1 : l == Length::h ? 2 : integer_size(l, m), false});
      else out.push_back({K::integer, integer_size(l, m), false});
      return true;
    case 'n':
      out.push_back({K::int_ptr, l == Length::hh ? 1 : l == Length::h ? 2 : integer_size(l, m), true});
      return true;
    case 'c':
      if (scan) out.push_back({K::string, l == Length::l ? m.wchar_size : 1, true});
      else out.push_back({K::integer, m.int_size, l != Length::l});
      return true;
    case 'C':
      if (!wide_default && !scan) {
        out.push_back({K::integer, m.int_size, false});  // POSIX %C: %lc
        return true;
      }
      if (scan) out.push_back({K::string, m.wchar_size, true});
      else out.push_back({K::integer, m.int_size, false});
      return true;
    case 's':
      out.push_back({K::string, l == Length::l ? m.wchar_size : 1, true});
      return true;
    case 'S':
      out.push_back({K::string, m.wchar_size, true});
      return true;
    case 'p':
      out.push_back({scan ? K::int_ptr : K::pointer, m.pointer_size, false});
      return true;
    case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': case 'a': case 'A':
      if (scan) out.push_back({K::float_ptr, l == Length::L ? m.long_double_size : l == Length::l ? 8 : 4, true});
      else out.push_back({K::floating, l == Length::L ? m.long_double_size : 8, true});
      return true;
    case '%':
      return true;
    case 'm':
      return !scan;  // glibc's strerror(errno): no argument
    default:
      return false;
  }
}

std::optional<std::vector<FormatArg>> parse(std::string_view f, const FormatModel &m, bool scan) {
  std::vector<FormatArg> out;
  for (std::size_t i = 0; i < f.size(); ++i) {
    if (f[i] != '%') continue;
    ++i;
    if (i >= f.size()) return std::nullopt;
    if (f[i] == '%') continue;
    bool suppress = false;
    if (scan) {
      if (f[i] == '*') {
        suppress = true;
        ++i;
      }
      while (i < f.size() && std::isdigit(static_cast<unsigned char>(f[i]))) ++i;
      if (i < f.size() && f[i] == '$') return std::nullopt;
      if (i < f.size() && (f[i] == 'm' || f[i] == 'a') && i + 1 < f.size() &&
          (f[i + 1] == 's' || f[i + 1] == 'c' || f[i + 1] == '['))
        return std::nullopt;  // allocating conversions: char ** (rare); not read
    } else {
      // Flags, width (or *), precision (or .*).
      std::size_t digits = i;
      while (digits < f.size() && std::isdigit(static_cast<unsigned char>(f[digits]))) ++digits;
      if (digits < f.size() && f[digits] == '$') return std::nullopt;
      while (i < f.size() && std::string_view("-+ #0'I").find(f[i]) != std::string_view::npos) {
        if (f[i] == 'I' && m.windows) break;  // Microsoft's I64 length, not glibc's flag
        ++i;
      }
      if (i < f.size() && f[i] == '*') {
        out.push_back({FormatArg::Kind::integer, m.int_size, true});
        ++i;
      } else {
        while (i < f.size() && std::isdigit(static_cast<unsigned char>(f[i]))) ++i;
      }
      if (i < f.size() && f[i] == '.') {
        ++i;
        if (i < f.size() && f[i] == '*') {
          out.push_back({FormatArg::Kind::integer, m.int_size, true});
          ++i;
        } else {
          while (i < f.size() && std::isdigit(static_cast<unsigned char>(f[i]))) ++i;
        }
      }
    }
    const Length l = length(f, i, m);
    if (i >= f.size()) return std::nullopt;
    const char c = f[i];
    if (scan && c == '[') {
      // A scan set: to the closing ']' (a ']' first is a member).
      std::size_t j = i + 1;
      if (j < f.size() && f[j] == '^') ++j;
      if (j < f.size() && f[j] == ']') ++j;
      while (j < f.size() && f[j] != ']') ++j;
      if (j >= f.size()) return std::nullopt;
      i = j;
      if (!suppress) out.push_back({FormatArg::Kind::string, l == Length::l ? m.wchar_size : 1, true});
      continue;
    }
    std::vector<FormatArg> one;
    if (!convert(c, l, scan, m, one)) return std::nullopt;
    if (!suppress) out.insert(out.end(), one.begin(), one.end());
    if (out.size() > 64) return std::nullopt;
  }
  return out;
}

}  // namespace

std::optional<std::vector<FormatArg>> printf_arguments(std::string_view format, const FormatModel &model) {
  return parse(format, model, false);
}

std::optional<std::vector<FormatArg>> scanf_arguments(std::string_view format, const FormatModel &model) {
  return parse(format, model, true);
}

}  // namespace revkit::lift
