// A minimal DEX reader: the header, the string, type, proto and method id
// tables, the class definitions and their class data, enough to name the
// classes and find the native methods; and the JNI names those methods bind
// to. From the format as the Dalvik executable format document and the JNI
// specification ("Resolving Native Method Names") describe them. Written
// for revkit.
#include "reader.hh"

#include <cstdio>
#include <cstring>
#include <unordered_map>

namespace revkit::android {

using detail::Reader;

namespace {

std::uint32_t uleb(const Reader &r, std::uint64_t &p) {
  std::uint32_t v = 0;
  for (int i = 0; i < 5; ++i) {
    const std::uint8_t b = r.u8(p++, "a LEB128 value");
    v |= static_cast<std::uint32_t>(b & 0x7f) << (7 * i);
    if ((b & 0x80) == 0) return v;
  }
  throw Error("a LEB128 value is longer than five bytes");
}

// MUTF-8 to UTF-16 code units (what JNI mangles).
std::vector<std::uint16_t> utf16_units(std::string_view s) {
  std::vector<std::uint16_t> out;
  for (std::size_t i = 0; i < s.size();) {
    const unsigned char c = static_cast<unsigned char>(s[i]);
    std::uint32_t cp = 0xfffd;
    std::size_t n = 1;
    if (c < 0x80) {
      cp = c;
    } else if ((c & 0xe0) == 0xc0 && i + 1 < s.size()) {
      cp = (c & 0x1fu) << 6 | (static_cast<unsigned char>(s[i + 1]) & 0x3f), n = 2;
    } else if ((c & 0xf0) == 0xe0 && i + 2 < s.size()) {
      cp = (c & 0x0fu) << 12 | (static_cast<unsigned char>(s[i + 1]) & 0x3fu) << 6 |
           (static_cast<unsigned char>(s[i + 2]) & 0x3f);
      n = 3;
    } else if ((c & 0xf8) == 0xf0 && i + 3 < s.size()) {
      cp = (c & 0x07u) << 18 | (static_cast<unsigned char>(s[i + 1]) & 0x3fu) << 12 |
           (static_cast<unsigned char>(s[i + 2]) & 0x3fu) << 6 | (static_cast<unsigned char>(s[i + 3]) & 0x3f);
      n = 4;
    }
    if (cp >= 0x10000) {
      cp -= 0x10000;
      out.push_back(static_cast<std::uint16_t>(0xd800 + (cp >> 10)));
      out.push_back(static_cast<std::uint16_t>(0xdc00 + (cp & 0x3ff)));
    } else {
      out.push_back(static_cast<std::uint16_t>(cp));
    }
    i += n;
  }
  return out;
}

std::string mangle(std::string_view s) {
  std::string out;
  for (std::uint16_t u : utf16_units(s)) {
    if ((u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z') || (u >= '0' && u <= '9')) out += static_cast<char>(u);
    else if (u == '/' || u == '.') out += '_';
    else if (u == '_') out += "_1";
    else if (u == ';') out += "_2";
    else if (u == '[') out += "_3";
    else {
      char b[8];
      std::snprintf(b, sizeof b, "_0%04x", u);
      out += b;
    }
  }
  return out;
}

std::string dotted(std::string_view descriptor) {
  if (descriptor.size() >= 2 && descriptor.front() == 'L' && descriptor.back() == ';') {
    std::string s(descriptor.substr(1, descriptor.size() - 2));
    for (char &c : s)
      if (c == '/') c = '.';
    return s;
  }
  return std::string(descriptor);
}

}  // namespace

std::string jni_short_name(std::string_view class_name, std::string_view method) {
  return "Java_" + mangle(class_name) + "_" + mangle(method);
}

std::string jni_long_name(std::string_view class_name, std::string_view method, std::string_view descriptor) {
  std::string_view args = descriptor;
  if (args.starts_with('(')) args.remove_prefix(1);
  if (const auto close = args.find(')'); close != std::string_view::npos) args = args.substr(0, close);
  return jni_short_name(class_name, method) + "__" + mangle(args);
}

std::optional<JniName> parse_jni_name(std::string_view sym) {
  if (!sym.starts_with("Java_") || sym.size() < 8) return std::nullopt;
  sym.remove_prefix(5);
  std::vector<std::string> parts(1);
  std::string sig;
  bool in_sig = false;
  for (std::size_t i = 0; i < sym.size(); ++i) {
    const char c = sym[i];
    std::string &cur = in_sig ? sig : parts.back();
    if (c != '_') {
      cur += c;
      continue;
    }
    const char n = i + 1 < sym.size() ? sym[i + 1] : '\0';
    if (n == '1') cur += '_', ++i;
    else if (n == '2') cur += ';', ++i;
    else if (n == '3') cur += '[', ++i;
    else if (n == '0' && i + 5 < sym.size()) {
      unsigned v = 0;
      bool ok = true;
      for (int k = 2; k < 6; ++k) {
        const char h = sym[i + k];
        v <<= 4;
        if (h >= '0' && h <= '9') v |= h - '0';
        else if (h >= 'a' && h <= 'f') v |= h - 'a' + 10;
        else if (h >= 'A' && h <= 'F') v |= h - 'A' + 10;
        else ok = false;
      }
      if (!ok) return std::nullopt;
      detail::append_utf8(cur, v);
      i += 5;
    } else if (in_sig) {
      cur += '/';
    } else if (n == '_') {
      in_sig = true;
      ++i;
    } else {
      parts.emplace_back();
    }
  }
  if (parts.size() < 2 || parts.back().empty()) return std::nullopt;
  JniName j;
  j.method = parts.back();
  for (std::size_t i = 0; i + 1 < parts.size(); ++i) j.class_name += (i ? "." : "") + parts[i];
  if (j.class_name.empty()) return std::nullopt;
  if (in_sig) j.signature = "(" + sig + ")";
  return j;
}

DexFile parse_dex(Bytes data, const DexLimits &limits) {
  const Reader r(data);
  if (data.size() < 0x70) throw Error("too short for a DEX header");
  const char *m = reinterpret_cast<const char *>(data.data());
  if (std::memcmp(m, "dex\n", 4) != 0 || m[7] != 0) throw Error("not a DEX file");
  DexFile d;
  d.version.assign(m + 4, 3);
  if (r.u32(0x28) != 0x12345678) throw Error("a big-endian DEX file (not supported)");
  const std::uint32_t header_size = r.u32(0x24);
  if (header_size < 0x70 || header_size > data.size()) throw Error("the DEX header's size is out of range");
  if (r.u32(0x20) < data.size()) d.warnings.push_back("the file holds more than its header's file_size (a DEX container)");
  struct Table {
    std::uint32_t size, off;
  };
  auto table = [&](std::uint64_t at, std::uint32_t width, const char *what) {
    Table t{r.u32(at), r.u32(at + 4)};
    if (t.size > limits.max_ids) throw Error(std::string("the DEX file has too many ") + what);
    if (t.size != 0) r.need(t.off, static_cast<std::uint64_t>(t.size) * width, what);
    return t;
  };
  const Table strings = table(0x38, 4, "string ids"), types = table(0x40, 4, "type ids"),
              protos = table(0x48, 12, "proto ids"), methods = table(0x58, 8, "method ids"),
              classes = table(0x60, 32, "class definitions");
  d.strings = strings.size;
  d.types = types.size;
  d.methods = methods.size;
  d.classes = classes.size;
  std::unordered_map<std::uint32_t, std::string> cache;
  auto string = [&](std::uint32_t i) -> const std::string & {
    static const std::string none;
    if (i >= strings.size) return none;
    auto it = cache.find(i);
    if (it != cache.end()) return it->second;
    std::string s;
    std::uint64_t p = r.u32(strings.off + 4ull * i);
    try {
      uleb(r, p);
      if (!r.cstr(p, 1u << 16, s)) s.clear();
    } catch (const Error &) {
      s.clear();
    }
    return cache.emplace(i, detail::clean_utf8(s)).first->second;
  };
  auto type = [&](std::uint32_t i) -> std::string {
    if (i >= types.size) return "?";
    return string(r.u32(types.off + 4ull * i));
  };
  auto proto = [&](std::uint32_t i) -> std::string {
    if (i >= protos.size) return "()?";
    const std::uint64_t at = protos.off + 12ull * i;
    std::string s = "(";
    if (const std::uint32_t params = r.u32(at + 8); params != 0) {
      const std::uint32_t n = r.u32(params, "a parameter list");
      r.need(params + 4, 2ull * n, "a parameter list");
      for (std::uint32_t k = 0; k < n && k < 256; ++k) s += type(r.u16(params + 4 + 2ull * k));
    }
    return s + ")" + type(r.u32(at + 4));
  };
  std::size_t walked = 0;
  for (std::uint32_t c = 0; c < classes.size; ++c) {
    const std::uint64_t at = classes.off + 32ull * c;
    const std::string cls = dotted(type(r.u32(at)));
    if (d.class_names.size() < limits.max_class_names) d.class_names.push_back(cls);
    const std::uint32_t data_off = r.u32(at + 24);
    if (data_off == 0) continue;
    try {
      std::uint64_t p = data_off;
      const std::uint32_t sf = uleb(r, p), inf = uleb(r, p), dm = uleb(r, p), vm = uleb(r, p);
      if (static_cast<std::uint64_t>(sf) + inf + dm + vm > data.size()) throw Error("a class has more members than bytes");
      for (std::uint32_t k = 0; k < sf + inf; ++k) {
        uleb(r, p);
        uleb(r, p);
      }
      for (std::uint32_t list : {dm, vm}) {
        std::uint32_t idx = 0;
        for (std::uint32_t k = 0; k < list; ++k) {
          idx += uleb(r, p);
          const std::uint32_t access = uleb(r, p);
          uleb(r, p);
          if (++walked > limits.max_ids) throw Error("the DEX file has too many methods");
          if ((access & 0x100) == 0 || idx >= methods.size) continue;
          const std::uint64_t mi = methods.off + 8ull * idx;
          DexMethod nm;
          nm.class_name = dotted(type(r.u16(mi)));
          nm.name = string(r.u32(mi + 4));
          nm.descriptor = proto(r.u16(mi + 2));
          nm.access = access;
          d.native_methods.push_back(std::move(nm));
        }
      }
    } catch (const Error &e) {
      d.warnings.push_back("class " + cls + ": " + e.what());
    }
  }
  return d;
}

}  // namespace revkit::android
