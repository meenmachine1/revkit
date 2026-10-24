// resources.arsc, from the format as AOSP's ResourceTypes.h describes it:
// the table, its global string pool, packages with their type and key
// pools, type specs, types (dense, sparse and 16-bit offsets), entries
// (simple, compact and maps), configurations and shared libraries. Written
// for revkit.
#include "reader.hh"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace revkit::android {

using detail::Reader;

namespace {

std::string char16_name(const Reader &r, std::uint64_t off, std::size_t units) {
  std::vector<std::uint16_t> u;
  for (std::size_t i = 0; i < units; ++i) {
    const std::uint16_t c = r.u16(off + 2 * i, "a package name");
    if (c == 0) break;
    u.push_back(c);
  }
  return detail::utf16_to_utf8(u.data(), u.size());
}

std::string unpack(const unsigned char in[2], char base) {
  std::string out;
  if (in[0] == 0) return out;
  if (in[0] & 0x80) {
    const unsigned first = in[1] & 0x1f, second = ((in[1] & 0xe0) >> 5) + ((in[0] & 0x03) << 3), third = (in[0] & 0x7c) >> 2;
    out += static_cast<char>(base + first);
    out += static_cast<char>(base + second);
    out += static_cast<char>(base + third);
  } else {
    out += static_cast<char>(in[0]);
    if (in[1] != 0) out += static_cast<char>(in[1]);
  }
  // Display text only: anything not alphanumeric is dropped.
  std::erase_if(out, [](char c) { return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')); });
  return out;
}

}  // namespace

std::string config_qualifiers(Bytes cfg) {
  // Fields past the stored size are zero.
  unsigned char b[64] = {};
  if (cfg.size() < 4) return {};
  const Reader r(cfg);
  const std::size_t n = std::min<std::size_t>({sizeof b, cfg.size(), r.u32(0)});
  for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<unsigned char>(cfg[i]);
  auto u16 = [&](int o) { return static_cast<unsigned>(b[o] | b[o + 1] << 8); };
  std::vector<std::string> q;
  auto add = [&](std::string s) {
    if (!s.empty()) q.push_back(std::move(s));
  };
  if (u16(4)) add("mcc" + std::to_string(u16(4)));
  if (u16(6)) add("mnc" + std::to_string(u16(6) == 0xffff ? 0 : u16(6)));
  const std::string lang = unpack(b + 8, 'a'), region = unpack(b + 10, '0');
  std::string script, variant;
  for (int i = 36; i < 40 && b[i]; ++i)
    if (std::isalnum(b[i])) script += static_cast<char>(b[i]);
  for (int i = 40; i < 48 && b[i]; ++i)
    if (std::isalnum(b[i])) variant += static_cast<char>(b[i]);
  if (!lang.empty()) {
    if (!script.empty() || !variant.empty() || lang.size() == 3 || region.size() == 3) {
      std::string s = "b+" + lang;
      if (!script.empty()) s += "+" + script;
      if (!region.empty()) s += "+" + region;
      if (!variant.empty()) s += "+" + variant;
      add(s);
    } else {
      add(region.empty() ? lang : lang + "-r" + region);
    }
  }
  const unsigned layout = b[28], ui = b[29], layout2 = b[48], color = b[49];
  if ((layout & 0xc0) == 0x40) add("ldltr");
  if ((layout & 0xc0) == 0x80) add("ldrtl");
  if (u16(30)) add("sw" + std::to_string(u16(30)) + "dp");
  if (u16(32)) add("w" + std::to_string(u16(32)) + "dp");
  if (u16(34)) add("h" + std::to_string(u16(34)) + "dp");
  static const char *sizes[] = {"", "small", "normal", "large", "xlarge"};
  if ((layout & 0x0f) >= 1 && (layout & 0x0f) <= 4) add(sizes[layout & 0x0f]);
  if ((layout & 0x30) == 0x10) add("notlong");
  if ((layout & 0x30) == 0x20) add("long");
  if ((layout2 & 3) == 1) add("notround");
  if ((layout2 & 3) == 2) add("round");
  if ((color & 3) == 1) add("nowidecg");
  if ((color & 3) == 2) add("widecg");
  if ((color & 0xc) == 4) add("lowdr");
  if ((color & 0xc) == 8) add("highdr");
  static const char *orient[] = {"", "port", "land", "square"};
  if (b[12] >= 1 && b[12] <= 3) add(orient[b[12]]);
  static const char *uitype[] = {"", "", "desk", "car", "television", "appliance", "watch", "vrheadset"};
  if ((ui & 0x0f) >= 2 && (ui & 0x0f) <= 7) add(uitype[ui & 0x0f]);
  if ((ui & 0x30) == 0x10) add("notnight");
  if ((ui & 0x30) == 0x20) add("night");
  switch (const unsigned d = u16(14)) {
    case 0: break;
    case 120: add("ldpi"); break;
    case 160: add("mdpi"); break;
    case 213: add("tvdpi"); break;
    case 240: add("hdpi"); break;
    case 320: add("xhdpi"); break;
    case 480: add("xxhdpi"); break;
    case 640: add("xxxhdpi"); break;
    case 0xfffe: add("anydpi"); break;
    case 0xffff: add("nodpi"); break;
    default: add(std::to_string(d) + "dpi");
  }
  static const char *touch[] = {"", "notouch", "stylus", "finger"};
  if (b[13] >= 1 && b[13] <= 3) add(touch[b[13]]);
  static const char *keys[] = {"", "keysexposed", "keyshidden", "keyssoft"};
  if (b[18] & 3) add(keys[b[18] & 3]);
  static const char *kbd[] = {"", "nokeys", "qwerty", "12key"};
  if (b[16] >= 1 && b[16] <= 3) add(kbd[b[16]]);
  if ((b[18] & 0xc) == 4) add("navexposed");
  if ((b[18] & 0xc) == 8) add("navhidden");
  static const char *nav[] = {"", "nonav", "dpad", "trackball", "wheel"};
  if (b[17] >= 1 && b[17] <= 4) add(nav[b[17]]);
  if (u16(20) && u16(22)) add(std::to_string(u16(20)) + "x" + std::to_string(u16(22)));
  if (u16(24)) add("v" + std::to_string(u16(24)));
  std::string out;
  for (const std::string &s : q) out += (out.empty() ? "" : "-") + s;
  return out;
}

namespace {

struct PackageReader {
  const ResourceLimits &limits;
  ResourceTable &table;
  std::size_t &entries;
  // Entries may all name one long key or alias one large bag: what the
  // entries copy (names and bag items) is budgeted at eight times the
  // table plus 64 MiB (bug scrub part 3).
  std::uint64_t budget = 0, copied = 0;
  void charge(std::uint64_t n) {
    copied += n;
    if (copied > budget) throw Error("the table's entries expand to more than eight times its size");
  }

  void type_chunk(const Reader &c, std::uint16_t hsize, ResourcePackage &pkg, const StringPool &keys,
                  std::uint32_t type_id_offset, const StringPool &type_names) {
    const std::uint8_t id = c.u8(8, "a type");
    const std::uint8_t flags = c.u8(9, "a type");
    const std::uint32_t count = c.u32(12, "a type"), start = c.u32(16, "a type");
    if (id == 0) throw Error("a type has id 0");
    if (hsize < 20 + 4) throw Error("a type's header is too small");
    const Bytes cfg = c.sub(20, std::min<std::uint64_t>(c.u32(20, "a configuration"), hsize - 20), "a configuration");
    const std::string config = config_qualifiers(cfg);
    ResourceType &t = type_for(pkg, id, type_id_offset, type_names);
    if (std::find(t.configs.begin(), t.configs.end(), config) == t.configs.end()) t.configs.push_back(config);
    const bool sparse = flags & 1, offset16 = flags & 2;
    const std::uint64_t width = sparse ? 4 : offset16 ? 2 : 4;
    if (count > (c.size() - std::min<std::uint64_t>(hsize, c.size())) / width) throw Error("a type has more entries than fit in it");
    for (std::uint32_t i = 0; i < count; ++i) {
      std::uint32_t index = i;
      std::uint64_t off;
      if (sparse) {
        index = c.u16(hsize + 4ull * i);
        off = 4ull * c.u16(hsize + 4ull * i + 2);
      } else if (offset16) {
        const std::uint16_t o = c.u16(hsize + 2ull * i);
        if (o == 0xffff) continue;
        off = 4ull * o;
      } else {
        const std::uint32_t o = c.u32(hsize + 4ull * i);
        if (o == 0xffffffffu) continue;
        off = o;
      }
      if (++entries > limits.max_entries) throw Error("the table has more than " + std::to_string(limits.max_entries) + " entries");
      const std::uint64_t e = static_cast<std::uint64_t>(start) + off;
      if (!c.fits(e, 8)) {
        table.warnings.push_back("an entry of type " + t.name + " lies outside its chunk");
        continue;
      }
      ResourceEntry re;
      re.id = (pkg.id & 0xff) << 24 | static_cast<std::uint32_t>(id) << 16 | (index & 0xffff);
      re.config = config;
      const std::uint16_t esize = c.u16(e), eflags = c.u16(e + 2);
      re.is_public = eflags & 2;
      std::uint32_t key;
      if (eflags & 8) {  // compact: the key in the size field, the type in the flags' high byte
        key = esize;
        re.value.type = static_cast<std::uint8_t>(eflags >> 8);
        re.value.data = c.u32(e + 4);
      } else {
        key = c.u32(e + 4);
        if (eflags & 1) {
          re.complex = true;
          if (!c.fits(e, 16)) continue;
          re.parent = c.u32(e + 8);
          const std::uint32_t n = c.u32(e + 12);
          const std::uint64_t base = e + esize;
          if (n > (c.size() > base ? (c.size() - base) / 12 : 0)) {
            table.warnings.push_back("a bag of type " + t.name + " has more items than fit in its chunk");
          } else {
            charge(16ull * n);
            for (std::uint32_t k = 0; k < n; ++k) {
              const std::uint64_t m = base + 12ull * k;
              re.items.emplace_back(c.u32(m), Value{c.u8(m + 7), c.u32(m + 8)});
            }
          }
        } else if (c.fits(e + esize, 8)) {
          re.value.type = c.u8(e + esize + 3);
          re.value.data = c.u32(e + esize + 4);
        }
      }
      if (const std::string *k = keys.at(key)) {
        charge(k->size() + sizeof(ResourceEntry));
        re.name = *k;
      } else {
        charge(sizeof(ResourceEntry));
      }
      t.entries.push_back(std::move(re));
    }
  }

  static ResourceType &type_for(ResourcePackage &pkg, std::uint8_t id, std::uint32_t type_id_offset,
                                const StringPool &type_names) {
    for (ResourceType &t : pkg.types)
      if (t.id == id) return t;
    ResourceType t;
    t.id = id;
    const std::int64_t i = static_cast<std::int64_t>(id) - 1 - type_id_offset;
    if (i >= 0)
      if (const std::string *s = type_names.at(static_cast<std::uint32_t>(i))) t.name = *s;
    if (t.name.empty()) t.name = "type" + std::to_string(id);
    pkg.types.push_back(std::move(t));
    return pkg.types.back();
  }

  void package(Bytes chunk) {
    const Reader c(chunk);
    const std::uint16_t hsize = c.u16(2);
    if (hsize < 284) throw Error("a package's header is too small");
    ResourcePackage pkg;
    pkg.id = c.u32(8, "a package");
    pkg.name = char16_name(c, 12, 128);
    const std::uint32_t type_off = c.u32(268), key_off = c.u32(276);
    const std::uint32_t type_id_offset = hsize >= 288 ? c.u32(284) : 0;
    StringPool types, keys;
    auto pool_at = [&](std::uint32_t off, const char *what) {
      if (off == 0 || off >= chunk.size()) return StringPool{};
      const std::uint32_t sz = c.u32(off + 4, what);
      return parse_string_pool(c.sub(off, std::min<std::uint64_t>(sz, chunk.size() - off), what), &table.warnings);
    };
    types = pool_at(type_off, "the type names");
    keys = pool_at(key_off, "the key names");
    for (std::uint64_t p = hsize; p + 8 <= chunk.size();) {
      const std::uint16_t type = c.u16(p), ch = c.u16(p + 2);
      const std::uint32_t size = c.u32(p + 4);
      if (size < 8 || ch < 8 || ch > size || size > chunk.size() - p) {
        table.warnings.push_back("a chunk in package " + pkg.name + " has a bad size; the rest is skipped");
        break;
      }
      const Reader sub(chunk.subspan(p, size));
      try {
        switch (type) {
          case 0x0202: {  // type spec
            const std::uint8_t id = sub.u8(8);
            if (id == 0) break;
            ResourceType &t = type_for(pkg, id, type_id_offset, types);
            t.entry_count = std::max(t.entry_count, sub.u32(12));
            break;
          }
          case 0x0201: type_chunk(sub, ch, pkg, keys, type_id_offset, types); break;
          case 0x0203: {  // shared libraries
            const std::uint32_t n = sub.u32(8);
            for (std::uint32_t k = 0; k < n && sub.fits(ch + 260ull * k, 260); ++k)
              pkg.libraries[sub.u32(ch + 260ull * k)] = char16_name(sub, ch + 260ull * k + 4, 128);
            break;
          }
          default: break;  // string pools (read above), overlayables, staged aliases
        }
      } catch (const Error &e) {
        table.warnings.push_back(std::string("package ") + pkg.name + ": " + e.what());
      }
      p += size;
    }
    table.packages.push_back(std::move(pkg));
  }
};

}  // namespace

ResourceTable parse_resource_table(Bytes data, const ResourceLimits &limits) {
  const Reader r(data);
  if (r.u16(0, "the table header") != 0x0002) throw Error("not a resource table (no RES_TABLE_TYPE chunk)");
  const std::uint16_t hsize = r.u16(2);
  std::uint64_t end = r.u32(4);
  ResourceTable table;
  if (end > data.size()) {
    table.warnings.push_back("the table says it is " + std::to_string(end) + " bytes; it is " + std::to_string(data.size()));
    end = data.size();
  }
  if (hsize < 12 || hsize > end) throw Error("the table header's size is out of range");
  std::size_t entries = 0;
  PackageReader pr{limits, table, entries};
  pr.budget = 8ull * data.size() + (64u << 20);
  bool pool = false;
  for (std::uint64_t p = hsize; p + 8 <= end;) {
    const std::uint16_t type = r.u16(p), ch = r.u16(p + 2);
    const std::uint32_t size = r.u32(p + 4);
    if (size < 8 || ch < 8 || ch > size || size > end - p) {
      table.warnings.push_back("a chunk at offset " + std::to_string(p) + " has a bad size; the rest is skipped");
      break;
    }
    const Bytes chunk = data.subspan(p, size);
    if (type == 0x0001 && !pool) {
      table.strings = parse_string_pool(chunk, &table.warnings);
      if (table.strings.strings.size() > limits.max_strings) throw Error("the table's string pool is too large");
      pool = true;
    } else if (type == 0x0200) {
      if (table.packages.size() >= 256) throw Error("the table has more than 256 packages");
      pr.package(chunk);
    }
    p += size;
  }
  for (std::uint32_t pi = 0; pi < table.packages.size(); ++pi)
    for (std::uint32_t ti = 0; ti < table.packages[pi].types.size(); ++ti)
      for (std::uint32_t ei = 0; ei < table.packages[pi].types[ti].entries.size(); ++ei)
        table.index[table.packages[pi].types[ti].entries[ei].id].push_back({pi, ti, ei});
  return table;
}

const ResourcePackage *ResourceTable::package(std::uint32_t id) const {
  for (const ResourcePackage &p : packages)
    if (p.id == id) return &p;
  return nullptr;
}

std::vector<const ResourceEntry *> ResourceTable::find(std::uint32_t id) const {
  std::vector<const ResourceEntry *> out;
  auto it = index.find(id);
  if (it == index.end()) return out;
  for (const auto &[p, t, e] : it->second) out.push_back(&packages[p].types[t].entries[e]);
  return out;
}

const ResourceEntry *ResourceTable::best(std::uint32_t id) const {
  const auto all = find(id);
  for (const ResourceEntry *e : all)
    if (e->config.empty()) return e;
  return all.empty() ? nullptr : all.front();
}

std::string ResourceTable::name_of(std::uint32_t id) const {
  if ((id >> 24) == 0x01) {
    if ((id >> 16) == 0x0101)
      if (const std::string_view a = framework_attribute(id); !a.empty()) return "@android:attr/" + std::string(a);
    return {};
  }
  auto it = index.find(id);
  if (it == index.end() || it->second.empty()) return {};
  const auto &[p, t, e] = it->second.front();
  const ResourcePackage &pkg = packages[p];
  const std::string prefix = p == 0 ? std::string() : pkg.name + ":";
  return "@" + prefix + pkg.types[t].name + "/" + pkg.types[t].entries[e].name;
}

std::string ResourceTable::resolve(const Value &v, std::string *ref_name) const {
  Value cur = v;
  for (int hop = 0; hop < 8; ++hop) {
    if (cur.type == 0x03) {
      const std::string *s = strings.at(cur.data);
      return s != nullptr ? *s : std::string();
    }
    if (cur.type != 0x01 && cur.type != 0x07) return format_value(cur);
    if (cur.data == 0) return "@null";
    if (hop == 0 && ref_name != nullptr) *ref_name = name_of(cur.data);
    const ResourceEntry *e = best(cur.data);
    if (e == nullptr) return {};
    if (e->complex) return name_of(cur.data);
    cur = e->value;
  }
  return {};
}

std::size_t ResourceTable::entry_count() const {
  std::size_t n = 0;
  for (const ResourcePackage &p : packages)
    for (const ResourceType &t : p.types) n += t.entries.size();
  return n;
}

}  // namespace revkit::android
