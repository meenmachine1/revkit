// Android's binary XML and its string pools, from the format as AOSP's
// ResourceTypes.h describes it (ResChunk_header, ResStringPool_header,
// ResXMLTree_node and its extensions, Res_value). Written for revkit.
#include "reader.hh"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace revkit::android {

using detail::Reader;

namespace detail {

void append_utf8(std::string &out, std::uint32_t cp) {
  if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) cp = 0xfffd;
  if (cp < 0x80) {
    out += static_cast<char>(cp);
  } else if (cp < 0x800) {
    out += static_cast<char>(0xc0 | (cp >> 6));
    out += static_cast<char>(0x80 | (cp & 0x3f));
  } else if (cp < 0x10000) {
    out += static_cast<char>(0xe0 | (cp >> 12));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
    out += static_cast<char>(0x80 | (cp & 0x3f));
  } else {
    out += static_cast<char>(0xf0 | (cp >> 18));
    out += static_cast<char>(0x80 | ((cp >> 12) & 0x3f));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
    out += static_cast<char>(0x80 | (cp & 0x3f));
  }
}

std::string utf16_to_utf8(const std::uint16_t *u, std::size_t n) {
  std::string out;
  out.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    std::uint32_t c = u[i];
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < n && u[i + 1] >= 0xdc00 && u[i + 1] <= 0xdfff) {
      c = 0x10000 + ((c - 0xd800) << 10) + (u[i + 1] - 0xdc00);
      ++i;
    }
    append_utf8(out, c);
  }
  return out;
}

std::string hex_bytes(Bytes b) {
  static const char *d = "0123456789abcdef";
  std::string s;
  s.reserve(b.size() * 2);
  for (std::byte x : b) {
    s += d[static_cast<unsigned>(x) >> 4];
    s += d[static_cast<unsigned>(x) & 15];
  }
  return s;
}

// Valid UTF-8 out of what a pool calls UTF-8 (Java's modified UTF-8
// included: its surrogate pairs and two-byte NUL are decoded); what doesn't
// decode becomes U+FFFD, and control characters other than tab and
// newline are kept as they are (the caller escapes them).
std::string clean_utf8(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  auto cont = [&](std::size_t i) { return i < s.size() && (static_cast<unsigned char>(s[i]) & 0xc0) == 0x80; };
  for (std::size_t i = 0; i < s.size();) {
    const unsigned char c = static_cast<unsigned char>(s[i]);
    std::uint32_t cp;
    std::size_t n;
    if (c < 0x80) {
      cp = c, n = 1;
    } else if ((c & 0xe0) == 0xc0 && cont(i + 1)) {
      cp = (c & 0x1fu) << 6 | (static_cast<unsigned char>(s[i + 1]) & 0x3f), n = 2;
      if (cp < 0x80 && cp != 0) cp = 0xfffd;
    } else if ((c & 0xf0) == 0xe0 && cont(i + 1) && cont(i + 2)) {
      cp = (c & 0x0fu) << 12 | (static_cast<unsigned char>(s[i + 1]) & 0x3fu) << 6 | (static_cast<unsigned char>(s[i + 2]) & 0x3f);
      n = 3;
      if (cp < 0x800) cp = 0xfffd;
      // Modified UTF-8: a surrogate pair as two three-byte sequences.
      if (cp >= 0xd800 && cp <= 0xdbff && i + 5 < s.size() && static_cast<unsigned char>(s[i + 3]) == 0xed &&
          cont(i + 4) && cont(i + 5)) {
        const std::uint32_t lo = 0xd000u | (static_cast<unsigned char>(s[i + 4]) & 0x3fu) << 6 |
                                 (static_cast<unsigned char>(s[i + 5]) & 0x3f);
        if (lo >= 0xdc00 && lo <= 0xdfff) {
          cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
          n = 6;
        }
      }
    } else if ((c & 0xf8) == 0xf0 && cont(i + 1) && cont(i + 2) && cont(i + 3)) {
      cp = (c & 0x07u) << 18 | (static_cast<unsigned char>(s[i + 1]) & 0x3fu) << 12 |
           (static_cast<unsigned char>(s[i + 2]) & 0x3fu) << 6 | (static_cast<unsigned char>(s[i + 3]) & 0x3f);
      n = 4;
      if (cp < 0x10000) cp = 0xfffd;
    } else {
      cp = 0xfffd, n = 1;
    }
    append_utf8(out, cp);
    i += n;
  }
  return out;
}

}  // namespace detail

using detail::clean_utf8;

// --- Values ---

std::string_view value_type_name(std::uint8_t t) {
  switch (t) {
    case 0x00: return "null";
    case 0x01: return "reference";
    case 0x02: return "attribute";
    case 0x03: return "string";
    case 0x04: return "float";
    case 0x05: return "dimension";
    case 0x06: return "fraction";
    case 0x07: return "dynamic-reference";
    case 0x08: return "dynamic-attribute";
    case 0x10: return "int";
    case 0x11: return "hex";
    case 0x12: return "bool";
    case 0x1c: case 0x1d: case 0x1e: case 0x1f: return "color";
    default: return "unknown";
  }
}

namespace {

std::string hex32(std::uint32_t v, int width = 8) {
  char b[16];
  std::snprintf(b, sizeof b, "0x%0*x", width, v);
  return b;
}

std::string number(double v) {
  char b[64];
  std::snprintf(b, sizeof b, "%g", v);
  std::string s = b;
  if (s.find_first_of(".eEn") == std::string::npos) s += ".0";
  return s;
}

double complex_value(std::uint32_t data) {
  static const double mults[] = {1.0, 1.0 / (1 << 7), 1.0 / (1 << 15), 1.0 / (1 << 23)};
  const auto mantissa = static_cast<std::int32_t>(data & 0xffffff00u);
  return static_cast<double>(mantissa) / 256.0 * mults[(data >> 4) & 3];
}

}  // namespace

std::string format_value(const Value &v, std::string_view str) {
  switch (v.type) {
    case 0x00: return v.data == 1 ? "@empty" : "@null";
    case 0x01: return v.data == 0 ? "@null" : "@" + hex32(v.data);
    case 0x07: return "@" + hex32(v.data);
    case 0x02: case 0x08: return "?" + hex32(v.data);
    case 0x03: return std::string(str);
    case 0x04: {
      float f;
      std::memcpy(&f, &v.data, 4);
      return number(f);
    }
    case 0x05: {
      static const char *units[] = {"px", "dip", "sp", "pt", "in", "mm"};
      const unsigned u = v.data & 15;
      return number(complex_value(v.data)) + (u < 6 ? units[u] : " (unit " + std::to_string(u) + ")");
    }
    case 0x06: return number(complex_value(v.data) * 100) + ((v.data & 15) == 1 ? "%p" : "%");
    case 0x10: return std::to_string(static_cast<std::int32_t>(v.data));
    case 0x11: return hex32(v.data, 1);
    case 0x12: return v.data != 0 ? "true" : "false";
    case 0x1c: case 0x1e: {
      char b[16];
      std::snprintf(b, sizeof b, "#%08x", v.data);
      return b;
    }
    case 0x1d: case 0x1f: {
      char b[16];
      std::snprintf(b, sizeof b, "#%06x", v.data & 0xffffff);
      return b;
    }
    default: return "(type " + hex32(v.type, 2) + ")" + hex32(v.data);
  }
}

// --- String pools ---

StringPool parse_string_pool(Bytes chunk, std::vector<std::string> *warnings) {
  Reader r(chunk);
  if (r.u16(0, "the string pool's type") != 0x0001) throw Error("not a string pool");
  const std::uint16_t hsize = r.u16(2, "the string pool's header");
  const std::uint32_t size = r.u32(4, "the string pool's size");
  if (hsize < 28 || size < hsize || size > chunk.size()) throw Error("the string pool's header or size is out of range");
  StringPool pool;
  const std::uint32_t count = r.u32(8), styles = r.u32(12), flags = r.u32(16), strings_start = r.u32(20);
  pool.utf8 = (flags & 0x100) != 0;
  pool.sorted = (flags & 1) != 0;
  pool.styles = styles;
  if (count > (size - hsize) / 4) throw Error("the string pool has more strings than fit in it");
  if (count > 0 && (strings_start < hsize || strings_start > size)) throw Error("the string pool's strings lie outside it");
  pool.strings.resize(count);
  std::size_t bad = 0, over = 0;
  const Reader body(chunk.first(size));
  // Offsets may all name one long string: what the pool decodes to is
  // budgeted at four times its size (UTF-16 to UTF-8 grows by half at
  // most) plus 1 MiB, and strings past that are left empty (bug scrub
  // part 3: a 1 MB pool of aliases decoded to terabytes).
  const std::uint64_t budget = 4ull * size + (1u << 20);
  std::uint64_t decoded = 0;
  for (std::uint32_t i = 0; i < count; ++i) {
    if (decoded > budget) {
      ++over;
      continue;
    }
    const std::uint64_t off = static_cast<std::uint64_t>(strings_start) + r.u32(hsize + 4ull * i);
    try {
      if (pool.utf8) {
        std::uint64_t p = off;
        auto len = [&]() -> std::uint32_t {
          std::uint32_t n = body.u8(p, "a string's length");
          ++p;
          if (n & 0x80) n = (n & 0x7f) << 8 | body.u8(p++, "a string's length");
          return n;
        };
        len();  // its length in UTF-16 units
        const std::uint32_t n = len();
        const Bytes s = body.sub(p, n, "a string");
        pool.strings[i] = clean_utf8(std::string_view(reinterpret_cast<const char *>(s.data()), n));
      } else {
        std::uint64_t p = off;
        std::uint32_t n = body.u16(p, "a string's length");
        p += 2;
        if (n & 0x8000) {
          n = (n & 0x7fff) << 16 | body.u16(p, "a string's length");
          p += 2;
        }
        const Bytes s = body.sub(p, 2ull * n, "a string");
        std::vector<std::uint16_t> u(n);
        for (std::uint32_t k = 0; k < n; ++k) u[k] = body.u16(p + 2ull * k);
        pool.strings[i] = detail::utf16_to_utf8(u.data(), n);
        (void)s;
      }
      decoded += pool.strings[i].size() + 1;
    } catch (const Error &) {
      ++bad;
    }
  }
  if (over != 0 && warnings != nullptr)
    warnings->push_back(std::to_string(over) + " of the string pool's " + std::to_string(count) +
                        " strings left empty: the pool decodes to more than four times its size");
  if (bad != 0 && warnings != nullptr)
    warnings->push_back(std::to_string(bad) + " of the string pool's " + std::to_string(count) + " strings lie outside it");
  return pool;
}

// --- Framework attributes ---

std::string_view framework_attribute(std::uint32_t id) {
  // android.R.attr: 0x01010000 to 0x0101002f are consecutive; the rest are
  // the manifest attributes this reader looks for.
  static const char *first[] = {
      "theme", "label", "icon", "name", "manageSpaceActivity", "allowClearUserData", "permission", "readPermission",
      "writePermission", "protectionLevel", "permissionGroup", "sharedUserId", "hasCode", "persistent", "enabled",
      "debuggable", "exported", "process", "taskAffinity", "multiprocess", "finishOnTaskLaunch", "clearTaskOnLaunch",
      "stateNotNeeded", "excludeFromRecents", "authorities", "syncable", "initOrder", "grantUriPermissions", "priority",
      "launchMode", "screenOrientation", "configChanges", "description", "targetPackage", "handleProfiling",
      "functionalTest", "value", "resource", "mimeType", "scheme", "host", "port", "path", "pathPrefix", "pathPattern",
      "action", "data", "targetClass"};
  if (id >= 0x01010000 && id < 0x01010000 + std::size(first)) return first[id - 0x01010000];
  switch (id) {
    case 0x01010202: return "targetActivity";
    case 0x0101020c: return "minSdkVersion";
    case 0x0101021b: return "versionCode";
    case 0x0101021c: return "versionName";
    case 0x01010270: return "targetSdkVersion";
    case 0x01010271: return "maxSdkVersion";
    case 0x01010272: return "testOnly";
    case 0x01010280: return "allowBackup";
    case 0x010102b7: return "installLocation";
    case 0x010102d3: return "hardwareAccelerated";
    case 0x0101035a: return "largeHeap";
    case 0x010103af: return "supportsRtl";
    case 0x010104ea: return "extractNativeLibs";
    case 0x010104eb: return "fullBackupContent";
    case 0x010104ec: return "usesCleartextTraffic";
    case 0x010104ee: return "autoVerify";
    case 0x01010527: return "networkSecurityConfig";
    case 0x0101052c: return "roundIcon";
    case 0x01010572: return "compileSdkVersion";
    case 0x01010573: return "compileSdkVersionCodename";
    case 0x01010576: return "versionCodeMajor";
    case 0x0101057a: return "appComponentFactory";
    case 0x01010603: return "requestLegacyExternalStorage";
    default: return {};
  }
}

// --- Binary XML ---

namespace {
constexpr std::string_view kAndroidNs = "http://schemas.android.com/apk/res/android";

void escape(std::string &out, std::string_view s, bool attr) {
  for (char c : s) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"':
        if (attr) out += "&quot;";
        else out += c;
        break;
      case '\n':
        if (attr) out += "&#10;";
        else out += c;
        break;
      case '\t':
        if (attr) out += "&#9;";
        else out += c;
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) {
          char b[12];
          std::snprintf(b, sizeof b, "&#%d;", c);
          out += b;
        } else {
          out += c;
        }
    }
  }
}

std::string qname(const std::string &prefix, const std::string &name) {
  return prefix.empty() ? name : prefix + ":" + name;
}

void write(std::string &out, const XmlElement &e, int depth, bool resolved,
           const std::vector<std::pair<std::string, std::string>> *ns) {
  const std::string pad(2 * depth, ' ');
  out += pad + "<" + qname(e.prefix, e.name);
  if (ns != nullptr)
    for (const auto &[p, u] : *ns) {
      out += p.empty() ? " xmlns=\"" : " xmlns:" + p + "=\"";
      escape(out, u, true);
      out += '"';
    }
  for (const XmlAttribute &a : e.attributes) {
    out += " " + qname(a.prefix, a.name) + "=\"";
    escape(out, resolved && !a.resolved.empty() ? a.resolved : a.text, true);
    out += '"';
  }
  std::string text = e.text;
  const bool blank = std::all_of(text.begin(), text.end(), [](char c) { return c == ' ' || c == '\n' || c == '\t' || c == '\r'; });
  if (e.children.empty() && blank) {
    out += " />\n";
    return;
  }
  out += ">";
  if (!blank) escape(out, text, false);
  if (!e.children.empty()) {
    out += "\n";
    for (const XmlElement &c : e.children) write(out, c, depth + 1, resolved, nullptr);
    out += pad;
  }
  out += "</" + qname(e.prefix, e.name) + ">\n";
}
}  // namespace

const XmlAttribute *XmlElement::attr(std::string_view n) const {
  for (const XmlAttribute &a : attributes)
    if (a.name == n) return &a;
  return nullptr;
}

const XmlAttribute *XmlElement::android_attr(std::string_view n) const {
  for (const XmlAttribute &a : attributes)
    if (a.name == n && (a.ns == kAndroidNs || (a.resource_id >> 16) == 0x0101)) return &a;
  return nullptr;
}

std::string XmlDocument::to_xml(bool resolved_values) const {
  std::string out = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
  if (!root.name.empty()) write(out, root, 0, resolved_values, &namespaces);
  return out;
}

bool is_binary_xml(Bytes b) {
  if (b.size() < 8) return false;
  const Reader r(b);
  return r.u16(0) == 0x0003 && r.u16(2) == 8;
}

XmlDocument decode_xml(Bytes data, const ResourceTable *table, const XmlLimits &limits) {
  const Reader r(data);
  if (r.u16(0, "the XML header") != 0x0003) throw Error("not binary XML (no RES_XML_TYPE chunk)");
  const std::uint16_t hsize = r.u16(2, "the XML header");
  std::uint64_t end = r.u32(4, "the XML header");
  XmlDocument doc;
  if (end > data.size()) {
    doc.warnings.push_back("the document says it is " + std::to_string(end) + " bytes; it is " + std::to_string(data.size()));
    end = data.size();
  }
  if (hsize < 8 || hsize > end) throw Error("the XML header's size is out of range");
  StringPool pool;
  bool have_pool = false;
  std::vector<std::uint32_t> resmap;
  // Namespaces in scope, innermost last: uri index -> prefix.
  std::vector<std::pair<std::string, std::string>> scope;  // (uri, prefix)
  std::vector<XmlElement *> stack;
  bool rooted = false;
  std::size_t nodes = 0;
  // Every element, attribute and text copies its strings out of the pool,
  // and they may all name one long string: what the document copies is
  // budgeted at eight times the file plus 16 MiB (bug scrub part 3).
  const std::uint64_t budget = 8ull * data.size() + (16u << 20);
  std::uint64_t copied = 0;
  auto charge = [&](std::size_t n) {
    copied += n;
    if (copied > budget) throw Error("the document's strings expand to more than eight times its size");
  };
  auto str = [&](std::uint32_t i) -> std::string {
    if (i == 0xffffffffu) return {};
    const std::string *s = pool.at(i);
    if (s == nullptr) return {};
    charge(s->size());
    return *s;
  };
  auto prefix_of = [&](const std::string &uri) -> std::string {
    for (auto it = scope.rbegin(); it != scope.rend(); ++it)
      if (it->first == uri) return it->second;
    return {};
  };
  std::uint64_t p = hsize;
  while (p + 8 <= end) {
    const std::uint16_t type = r.u16(p), ch = r.u16(p + 2);
    const std::uint32_t size = r.u32(p + 4);
    if (size < 8 || ch < 8 || ch > size || size > end - p) {
      doc.warnings.push_back("a chunk at offset " + std::to_string(p) + " has a bad size; the rest is skipped");
      break;
    }
    if (++nodes > limits.max_nodes) throw Error("the document has more than " + std::to_string(limits.max_nodes) + " nodes");
    const Bytes chunk = data.subspan(p, size);
    const Reader c(chunk);
    switch (type) {
      case 0x0001:
        if (!have_pool) {
          pool = parse_string_pool(chunk, &doc.warnings);
          have_pool = true;
        }
        break;
      case 0x0180:
        for (std::uint64_t q = ch; q + 4 <= size && resmap.size() < (1u << 20); q += 4) resmap.push_back(c.u32(q));
        break;
      case 0x0100: {  // start namespace
        const std::string prefix = str(c.u32(ch, "a namespace")), uri = str(c.u32(ch + 4, "a namespace"));
        scope.emplace_back(uri, prefix);
        if (!rooted) doc.namespaces.emplace_back(prefix, uri);
        break;
      }
      case 0x0101:  // end namespace
        if (!scope.empty()) scope.pop_back();
        break;
      case 0x0102: {  // start element
        if (stack.size() >= limits.max_depth) throw Error("the document nests deeper than " + std::to_string(limits.max_depth));
        XmlElement e;
        e.line = c.u32(8, "an element");
        e.ns = str(c.u32(ch, "an element"));
        e.prefix = e.ns.empty() ? std::string() : prefix_of(e.ns);
        e.name = str(c.u32(ch + 4, "an element"));
        const std::uint16_t astart = c.u16(ch + 8, "an element"), asize = c.u16(ch + 10, "an element"),
                            acount = c.u16(ch + 12, "an element");
        if (acount > limits.max_attributes) throw Error("an element has " + std::to_string(acount) + " attributes");
        if (acount > 0 && asize < 20) throw Error("an element's attributes are smaller than 20 bytes");
        for (std::uint32_t k = 0; k < acount; ++k) {
          const std::uint64_t a = ch + static_cast<std::uint64_t>(astart) + static_cast<std::uint64_t>(k) * asize;
          if (!c.fits(a, 20)) {
            doc.warnings.push_back("an attribute of <" + e.name + "> lies outside its element");
            break;
          }
          XmlAttribute at;
          at.ns = str(c.u32(a));
          at.prefix = at.ns.empty() ? std::string() : prefix_of(at.ns);
          const std::uint32_t name_index = c.u32(a + 4);
          at.name = str(name_index);
          if (name_index < resmap.size()) at.resource_id = resmap[name_index];
          // Android looks attributes up by their id, so a name an
          // obfuscator changed still means the framework's attribute.
          if (const std::string_view fw = framework_attribute(at.resource_id); !fw.empty()) {
            at.name = std::string(fw);
            if (at.ns.empty()) {
              at.ns = std::string(kAndroidNs);
              at.prefix = prefix_of(at.ns);
              if (at.prefix.empty()) at.prefix = "android";
            }
          }
          if (at.name.empty()) at.name = at.resource_id != 0 ? "attr_" + hex32(at.resource_id).substr(2) : "attr";
          const std::uint32_t raw = c.u32(a + 8);
          if (raw != 0xffffffffu) at.raw = str(raw);
          at.value.type = c.u8(a + 15);
          at.value.data = c.u32(a + 16);
          if (at.value.type == 0x03) {
            at.text = str(at.value.data);
          } else {
            at.text = format_value(at.value);
            if (table != nullptr &&
                (at.value.type == 0x01 || at.value.type == 0x07 || at.value.type == 0x02 || at.value.type == 0x08)) {
              const std::string n = table->name_of(at.value.data);
              const bool attr_ref = at.value.type == 0x02 || at.value.type == 0x08;
              if (!n.empty()) at.text = attr_ref ? "?" + n.substr(1) : n;
              if (at.value.type == 0x01 || at.value.type == 0x07) {
                at.resolved = table->resolve(at.value);
                charge(at.resolved.size() + n.size());
              }
            }
            if (at.raw && at.value.type == 0x00) at.text = *at.raw;
          }
          e.attributes.push_back(std::move(at));
        }
        if (stack.empty()) {
          if (rooted) {
            doc.warnings.push_back("a second root element <" + e.name + "> is ignored");
            stack.push_back(nullptr);
            break;
          }
          rooted = true;
          doc.root = std::move(e);
          stack.push_back(&doc.root);
        } else if (stack.back() == nullptr) {
          stack.push_back(nullptr);
        } else {
          stack.back()->children.push_back(std::move(e));
          stack.push_back(&stack.back()->children.back());
        }
        break;
      }
      case 0x0103:  // end element
        if (stack.empty()) doc.warnings.push_back("an element ends that never started");
        else stack.pop_back();
        break;
      case 0x0104:  // character data
        if (!stack.empty() && stack.back() != nullptr) stack.back()->text += str(c.u32(ch, "character data"));
        break;
      default:
        break;  // RES_NULL_TYPE and unknown chunks are skipped, as Android does
    }
    p += size;
  }
  if (!stack.empty()) doc.warnings.push_back("the document ends inside <" + (stack.front() ? stack.front()->name : std::string("?")) + ">");
  if (!rooted) throw Error("the document has no element");
  return doc;
}

}  // namespace revkit::android
