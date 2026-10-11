#include "revkit/inputs/ghidra_archive.h"

#include <zlib.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <functional>
#include <mutex>
#include <span>
#include <variant>

namespace revkit::inputs {

namespace {

// ---- the packed database --------------------------------------------------

using Bytes = std::vector<std::uint8_t>;

std::uint32_t be32(const std::uint8_t *p) {
  return std::uint32_t{p[0]} << 24 | std::uint32_t{p[1]} << 16 | std::uint32_t{p[2]} << 8 | p[3];
}
std::uint64_t be64(const std::uint8_t *p) { return std::uint64_t{be32(p)} << 32 | be32(p + 4); }
std::uint32_t le32(const std::uint8_t *p) {
  return std::uint32_t{p[0]} | std::uint32_t{p[1]} << 8 | std::uint32_t{p[2]} << 16 | std::uint32_t{p[3]} << 24;
}
std::uint16_t le16(const std::uint8_t *p) { return static_cast<std::uint16_t>(p[0] | p[1] << 8); }

// ItemSerializer: the database is the one entry of a zip stream written
// without a central directory.
Bytes unpack(const Bytes &file) {
  static const std::uint8_t kLocal[] = {'P', 'K', 3, 4};
  auto it = std::search(file.begin(), file.end(), std::begin(kLocal), std::end(kLocal));
  if (it == file.end() || file.end() - it < 30) throw ArchiveError("not a packed database");
  const std::uint8_t *h = &*it;
  if (le16(h + 8) != 8) throw ArchiveError("packed database is not deflated");
  const std::size_t start = static_cast<std::size_t>(it - file.begin()) + 30 + le16(h + 26) + le16(h + 28);
  if (start > file.size()) throw ArchiveError("truncated packed database");
  z_stream z{};
  if (inflateInit2(&z, -15) != Z_OK) throw ArchiveError("zlib");
  z.next_in = const_cast<Bytef *>(file.data() + start);
  z.avail_in = static_cast<uInt>(file.size() - start);
  Bytes out;
  std::uint8_t buf[1 << 16];
  int rc = Z_OK;
  while (rc == Z_OK) {
    z.next_out = buf;
    z.avail_out = sizeof buf;
    rc = inflate(&z, Z_NO_FLUSH);
    out.insert(out.end(), buf, buf + (sizeof buf - z.avail_out));
    if (out.size() > (std::size_t{1} << 31)) rc = Z_DATA_ERROR;
  }
  inflateEnd(&z);
  if (rc != Z_STREAM_END) throw ArchiveError("corrupt packed database");
  return out;
}

using Value = std::variant<std::monostate, std::int64_t, std::string>;

enum FieldType : std::uint8_t { kByte = 0, kShort = 1, kInt = 2, kLong = 3, kString = 4, kBinary = 5, kBool = 6, kFixed10 = 7 };

int field_size(std::uint8_t t) {
  switch (t) {
    case kByte:
    case kBool: return 1;
    case kShort: return 2;
    case kInt: return 4;
    case kLong: return 8;
    case kFixed10: return 10;
    default: return -1;
  }
}

struct Schema {
  std::uint8_t key_type = kLong;
  std::vector<std::uint8_t> fields;
  std::vector<std::string> names;
  std::vector<bool> sparse;

  int column(const std::string &name) const {
    for (std::size_t i = 0; i < names.size(); ++i)
      if (names[i] == name) return static_cast<int>(i);
    return -1;
  }
  int fixed_length() const {
    int n = 0;
    for (std::uint8_t f : fields) {
      int s = field_size(f);
      if (s < 0) return -1;
      n += s;
    }
    return n;
  }
};

class Database {
 public:
  explicit Database(Bytes raw) : raw_(std::move(raw)) {
    if (raw_.size() < 32 || be64(raw_.data()) != 0x2f30312c34292c2aULL) throw ArchiveError("not a buffer file");
    block_ = be32(raw_.data() + 20);
    if (block_ <= 5 || block_ > (1u << 24)) throw ArchiveError("bad buffer size");
    const std::span<const std::uint8_t> parms = buffer(0);
    if (parms.size() < 10) throw ArchiveError("bad database parameters");
    const int master_root = static_cast<int>(be32(parms.data() + 6));
    Schema master;
    master.fields = {kString, kInt, kInt, kByte, kBinary, kString, kInt, kLong, kInt};
    master.sparse.assign(master.fields.size(), false);
    scan(master_root, master, [&](std::int64_t, const std::vector<Value> &v) {
      if (std::get<std::int64_t>(v[6]) != -1) return;  // an index table
      Table t;
      t.root = static_cast<int>(std::get<std::int64_t>(v[2]));
      t.schema = parse_schema(static_cast<std::uint8_t>(std::get<std::int64_t>(v[3])), std::get<std::string>(v[4]),
                              std::get<std::string>(v[5]));
      tables_[std::get<std::string>(v[0])] = std::move(t);
    });
  }

  struct Table {
    int root = -1;
    Schema schema;
  };
  const Table *table(const std::string &name) const {
    auto it = tables_.find(name);
    return it == tables_.end() ? nullptr : &it->second;
  }

  // Calls f(key, values) for every record of a long- or fixed-key table.
  void scan(int root, const Schema &schema, const std::function<void(std::int64_t, const std::vector<Value> &)> &f) {
    if (root < 0) return;
    std::vector<int> stack{root};
    int visited = 0;
    while (!stack.empty()) {
      if (++visited > 1 << 22) throw ArchiveError("B-tree loop");
      const int id = stack.back();
      stack.pop_back();
      std::span<const std::uint8_t> b = buffer(id);
      const std::uint8_t type = b[0];
      const std::uint32_t count = be32(b.data() + 1);
      const int key_size = type >= 5 ? field_size(schema.key_type) : 8;
      if (key_size <= 0) throw ArchiveError("unsupported key type");
      auto key_at = [&](std::size_t off) -> std::int64_t {
        need(b, off, static_cast<std::size_t>(key_size));
        std::uint64_t k = 0;
        for (int i = 0; i < key_size; ++i) k = k << 8 | b[off + static_cast<std::size_t>(i)];
        if (key_size < 8 && (k >> (8 * key_size - 1)) & 1) k |= ~std::uint64_t{0} << (8 * key_size);
        return static_cast<std::int64_t>(k);
      };
      switch (type) {
        case 0:    // LONGKEY_INTERIOR_NODE
        case 5: {  // FIXEDKEY_INTERIOR_NODE
          const std::size_t entry = static_cast<std::size_t>(key_size) + 4;
          for (std::uint32_t i = count; i-- > 0;) {
            const std::size_t off = 5 + i * entry + static_cast<std::size_t>(key_size);
            need(b, off, 4);
            stack.push_back(static_cast<int>(be32(b.data() + off)));
          }
          break;
        }
        case 1:    // LONGKEY_VAR_REC_NODE
        case 6: {  // FIXEDKEY_VAR_REC_NODE
          const std::size_t entry = static_cast<std::size_t>(key_size) + 5;
          const std::size_t base = 13;
          for (std::uint32_t i = 0; i < count; ++i) {
            const std::size_t e = base + i * entry;
            need(b, e, entry);
            const std::int64_t key = key_at(e);
            const std::uint32_t off = be32(b.data() + e + static_cast<std::size_t>(key_size));
            const bool indirect = b[e + static_cast<std::size_t>(key_size) + 4] != 0;
            if (indirect) {
              need(b, off, 4);
              Bytes data = chained(static_cast<int>(be32(b.data() + off)));
              f(key, read(schema, data, 0));
            } else {
              f(key, read(schema, b, off));
            }
          }
          break;
        }
        case 2:    // LONGKEY_FIXED_REC_NODE
        case 7: {  // FIXEDKEY_FIXED_REC_NODE
          const int len = schema.fixed_length();
          if (len < 0) throw ArchiveError("fixed records of variable length");
          const std::size_t entry = static_cast<std::size_t>(key_size + len);
          for (std::uint32_t i = 0; i < count; ++i) {
            const std::size_t e = 13 + i * entry;
            need(b, e, entry);
            f(key_at(e), read(schema, b, e + static_cast<std::size_t>(key_size)));
          }
          break;
        }
        default: throw ArchiveError("unsupported B-tree node type " + std::to_string(type));
      }
    }
  }

 private:
  static void need(std::span<const std::uint8_t> b, std::size_t off, std::size_t n) {
    if (off > b.size() || n > b.size() - off) throw ArchiveError("record out of bounds");
  }

  std::span<const std::uint8_t> buffer(int id) const {
    if (id < 0) throw ArchiveError("bad buffer id");
    const std::size_t off = (static_cast<std::size_t>(id) + 1) * block_;
    if (off + block_ > raw_.size()) throw ArchiveError("buffer out of bounds");
    return {raw_.data() + off + 5, block_ - 5};
  }

  // ChainedBuffer: one data buffer, or index buffers listing data buffers.
  Bytes chained(int id) const {
    std::span<const std::uint8_t> first = buffer(id);
    std::int32_t size = static_cast<std::int32_t>(be32(first.data() + 1));
    if (size < 0) throw ArchiveError("obfuscated chained buffer");
    Bytes out;
    if (first[0] == 9) {
      out.assign(first.begin() + 5, first.end());
    } else if (first[0] == 8) {
      std::span<const std::uint8_t> index = first;
      for (int hops = 0; hops < 1 << 16; ++hops) {
        const std::int32_t next = static_cast<std::int32_t>(be32(index.data() + 5));
        for (std::size_t off = 9; off + 4 <= index.size(); off += 4) {
          const std::int32_t data = static_cast<std::int32_t>(be32(index.data() + off));
          if (data < 0) break;
          std::span<const std::uint8_t> d = buffer(data);
          out.insert(out.end(), d.begin() + 1, d.end());
          if (out.size() >= static_cast<std::size_t>(size)) break;
        }
        if (next < 0 || out.size() >= static_cast<std::size_t>(size)) break;
        index = buffer(next);
      }
    } else {
      throw ArchiveError("bad chained buffer");
    }
    if (out.size() < static_cast<std::size_t>(size)) throw ArchiveError("short chained buffer");
    out.resize(static_cast<std::size_t>(size));
    return out;
  }

  static Value field(std::span<const std::uint8_t> b, std::size_t &off, std::uint8_t t) {
    switch (t) {
      case kByte:
      case kBool:
        need(b, off, 1);
        return std::int64_t{static_cast<std::int8_t>(b[off++])};
      case kShort: {
        need(b, off, 2);
        auto v = static_cast<std::int16_t>(b[off] << 8 | b[off + 1]);
        off += 2;
        return std::int64_t{v};
      }
      case kInt: {
        need(b, off, 4);
        auto v = static_cast<std::int32_t>(be32(b.data() + off));
        off += 4;
        return std::int64_t{v};
      }
      case kLong: {
        need(b, off, 8);
        auto v = static_cast<std::int64_t>(be64(b.data() + off));
        off += 8;
        return v;
      }
      case kFixed10:
        need(b, off, 10);
        off += 10;
        return std::monostate{};
      case kString:
      case kBinary: {
        need(b, off, 4);
        auto len = static_cast<std::int32_t>(be32(b.data() + off));
        off += 4;
        if (len < 0) return std::monostate{};
        need(b, off, static_cast<std::size_t>(len));
        std::string s(reinterpret_cast<const char *>(b.data() + off), static_cast<std::size_t>(len));
        off += static_cast<std::size_t>(len);
        return s;
      }
      default: throw ArchiveError("unsupported field type");
    }
  }

  static std::vector<Value> read(const Schema &s, std::span<const std::uint8_t> b, std::size_t off) {
    std::vector<Value> v(s.fields.size());
    bool any_sparse = false;
    for (std::size_t i = 0; i < s.fields.size(); ++i) {
      if (s.sparse[i]) {
        any_sparse = true;
        continue;
      }
      v[i] = field(b, off, s.fields[i]);
    }
    if (any_sparse) {
      need(b, off, 1);
      int n = b[off++];
      for (int k = 0; k < n; ++k) {
        need(b, off, 1);
        std::size_t idx = b[off++];
        if (idx >= s.fields.size()) throw ArchiveError("bad sparse column");
        v[idx] = field(b, off, s.fields[idx]);
      }
    }
    return v;
  }
  static std::vector<Value> read(const Schema &s, const Bytes &b, std::size_t off) {
    return read(s, std::span<const std::uint8_t>(b), off);
  }

  static Schema parse_schema(std::uint8_t key_type, const std::string &types, const std::string &names) {
    Schema s;
    s.key_type = key_type & 0x0f;
    std::size_t i = 0;
    for (; i < types.size(); ++i) {
      auto b = static_cast<std::uint8_t>(types[i]);
      if (b == 0xff) {
        ++i;
        break;
      }
      s.fields.push_back(b & 0x0f);
    }
    s.sparse.assign(s.fields.size(), false);
    while (i < types.size()) {
      auto ext = static_cast<std::uint8_t>(types[i++]);
      if (ext != 1) throw ArchiveError("unsupported schema extension");
      for (; i < types.size() && static_cast<std::uint8_t>(types[i]) != 0xff; ++i) {
        auto c = static_cast<std::uint8_t>(types[i]);
        if (c < s.sparse.size()) s.sparse[c] = true;
      }
    }
    std::size_t start = 0;
    bool key = true;
    for (std::size_t p = 0; p <= names.size(); ++p) {
      if (p == names.size() || names[p] == ';') {
        if (!key) s.names.push_back(names.substr(start, p - start));
        key = false;
        start = p + 1;
      }
    }
    return s;
  }

  Bytes raw_;
  std::uint32_t block_ = 0;
  std::map<std::string, Table> tables_;
};

std::int64_t num(const std::vector<Value> &v, int col, std::int64_t dflt = 0) {
  if (col < 0 || static_cast<std::size_t>(col) >= v.size()) return dflt;
  if (const auto *i = std::get_if<std::int64_t>(&v[static_cast<std::size_t>(col)])) return *i;
  return dflt;
}
std::string str(const std::vector<Value> &v, int col) {
  if (col < 0 || static_cast<std::size_t>(col) >= v.size()) return {};
  if (const auto *s = std::get_if<std::string>(&v[static_cast<std::size_t>(col)])) return *s;
  return {};
}

constexpr int kKindShift = 56;
std::uint64_t kind_of(std::uint64_t id) { return id >> kKindShift; }

}  // namespace

// ---- the data type manager's tables -----------------------------------------

std::shared_ptr<const GhidraArchive> GhidraArchive::load(const std::filesystem::path &gdt) {
  std::ifstream in(gdt, std::ios::binary);
  if (!in) throw ArchiveError("cannot read " + gdt.string());
  Bytes file((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  Database db(unpack(file));
  auto out = std::shared_ptr<GhidraArchive>(new GhidraArchive());
  auto each = [&](const char *name, const std::function<void(std::int64_t, const std::vector<Value> &, const Schema &)> &f) {
    const Database::Table *t = db.table(name);
    if (t == nullptr) return;
    const Schema &s = t->schema;
    db.scan(t->root, s, [&](std::int64_t k, const std::vector<Value> &v) { f(k, v, s); });
  };

  std::map<std::int64_t, std::string> conventions;
  each("Calling Conventions", [&](std::int64_t k, const std::vector<Value> &v, const Schema &s) {
    conventions[k] = str(v, s.column("Name"));
  });
  each("Built-in datatypes", [&](std::int64_t k, const std::vector<Value> &v, const Schema &s) {
    out->builtins_[static_cast<std::uint64_t>(k)] = {str(v, s.column("Name")), str(v, s.column("Class Name"))};
  });
  each("Typedefs", [&](std::int64_t k, const std::vector<Value> &v, const Schema &s) {
    out->typedefs_[static_cast<std::uint64_t>(k)] = {str(v, s.column("Name")),
                                                      static_cast<std::uint64_t>(num(v, s.column("Data Type ID")))};
  });
  each("Pointers", [&](std::int64_t k, const std::vector<Value> &v, const Schema &s) {
    std::int64_t len = num(v, s.column("Length"), -1);
    out->pointers_[static_cast<std::uint64_t>(k)] = {static_cast<std::uint64_t>(num(v, s.column("Data Type ID"))),
                                                      len < 0 || len == 255 ? -1 : static_cast<int>(len)};
  });
  each("Arrays", [&](std::int64_t k, const std::vector<Value> &v, const Schema &s) {
    out->arrays_[static_cast<std::uint64_t>(k)] = {static_cast<std::uint64_t>(num(v, s.column("Data Type ID"))),
                                                    static_cast<int>(num(v, s.column("Dimension"))),
                                                    static_cast<int>(num(v, s.column("Length")))};
  });
  each("Composite Data Types", [&](std::int64_t k, const std::vector<Value> &v, const Schema &s) {
    Composite c;
    c.name = str(v, s.column("Name"));
    c.is_union = num(v, s.column("Is Union")) != 0;
    c.length = static_cast<int>(num(v, s.column("Length")));
    c.alignment = static_cast<int>(num(v, s.column("Alignment")));
    out->composites_[static_cast<std::uint64_t>(k)] = std::move(c);
  });
  each("Component Data Types", [&](std::int64_t, const std::vector<Value> &v, const Schema &s) {
    auto it = out->composites_.find(static_cast<std::uint64_t>(num(v, s.column("Parent"))));
    if (it == out->composites_.end()) return;
    it->second.components.push_back({static_cast<int>(num(v, s.column("Offset"))),
                                     static_cast<std::uint64_t>(num(v, s.column("Data Type ID"))),
                                     str(v, s.column("Field Name")), static_cast<int>(num(v, s.column("Component Size"))),
                                     static_cast<int>(num(v, s.column("Ordinal")))});
  });
  for (auto &[id, c] : out->composites_)
    std::sort(c.components.begin(), c.components.end(),
              [](const Component &a, const Component &b) { return a.ordinal < b.ordinal; });
  each("Enumeration Data Types", [&](std::int64_t k, const std::vector<Value> &v, const Schema &s) {
    out->enums_[static_cast<std::uint64_t>(k)] = {str(v, s.column("Name")), static_cast<int>(num(v, s.column("Size"), 4)), {}};
  });
  each("Enumeration Values", [&](std::int64_t, const std::vector<Value> &v, const Schema &s) {
    auto it = out->enums_.find(static_cast<std::uint64_t>(num(v, s.column("Enum ID"))));
    if (it != out->enums_.end()) it->second.values.emplace_back(str(v, s.column("Name")), num(v, s.column("Value")));
  });
  each("Function Definitions", [&](std::int64_t k, const std::vector<Value> &v, const Schema &s) {
    FunctionDef f;
    f.name = str(v, s.column("Name"));
    f.ret = static_cast<std::uint64_t>(num(v, s.column("Return Type ID")));
    const std::int64_t flags = num(v, s.column("Flags"));
    f.varargs = (flags & 1) != 0;
    f.noreturn = (flags & 2) != 0;
    const std::int64_t cc = num(v, s.column("Call Conv ID"));
    f.convention = cc == 0 ? "unknown" : cc == 1 ? "default" : conventions.contains(cc) ? conventions[cc] : "unknown";
    out->functions_[static_cast<std::uint64_t>(k)] = std::move(f);
  });
  std::map<std::uint64_t, std::vector<std::pair<int, Param>>> params;
  each("Function Parameters", [&](std::int64_t, const std::vector<Value> &v, const Schema &s) {
    params[static_cast<std::uint64_t>(num(v, s.column("Parent ID")))].push_back(
        {static_cast<int>(num(v, s.column("Ordinal"))),
         {str(v, s.column("Name")), static_cast<std::uint64_t>(num(v, s.column("Data Type ID")))}});
  });
  for (auto &[id, list] : params) {
    auto it = out->functions_.find(id);
    if (it == out->functions_.end()) continue;
    std::sort(list.begin(), list.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
    for (auto &[ord, p] : list) it->second.params.push_back(std::move(p));
  }
  // ApplyFunctionDataTypesCmd: a name defined twice differently applies to nothing.
  for (const auto &[id, f] : out->functions_) {
    auto [it, fresh] = out->by_name_.emplace(f.name, id);
    if (!fresh && it->second != 0) {
      const FunctionDef &other = out->functions_.at(it->second);
      bool same = other.ret == f.ret && other.varargs == f.varargs && other.params.size() == f.params.size();
      for (std::size_t i = 0; same && i < f.params.size(); ++i) same = other.params[i].type == f.params[i].type;
      if (!same) it->second = 0;
    }
  }
  return out;
}

std::shared_ptr<const GhidraArchive> GhidraArchive::for_program(const std::filesystem::path &ghidra_root, bool pe,
                                                               unsigned pointer_bits) {
  const char *file = pe ? (pointer_bits == 64 ? "win32/windows_vs12_64.gdt" : "win32/windows_vs12_32.gdt")
                        : (pointer_bits == 64 ? "generic/generic_clib_64.gdt" : "generic/generic_clib.gdt");
  const std::filesystem::path path = ghidra_root / "Ghidra/Features/Base/data/typeinfo" / file;
  static std::mutex mu;
  static std::map<std::filesystem::path, std::shared_ptr<const GhidraArchive>> cache;
  std::lock_guard lock(mu);
  if (auto it = cache.find(path); it != cache.end()) return it->second;
  std::shared_ptr<const GhidraArchive> a;
  std::error_code ec;
  if (std::filesystem::is_regular_file(path, ec)) {
    try {
      a = load(path);
    } catch (const ArchiveError &) {
      a = nullptr;
    }
  }
  cache.emplace(path, a);
  return a;
}

const GhidraArchive::FunctionDef *GhidraArchive::function(const std::string &name) const {
  auto it = by_name_.find(name);
  if (it == by_name_.end() || it->second == 0) return nullptr;
  return &functions_.at(it->second);
}

template <class M>
static const typename M::mapped_type *find_in(const M &m, std::uint64_t id) {
  auto it = m.find(id);
  return it == m.end() ? nullptr : &it->second;
}

const GhidraArchive::Builtin *GhidraArchive::builtin(std::uint64_t id) const { return find_in(builtins_, id); }
const GhidraArchive::Typedef *GhidraArchive::typedef_(std::uint64_t id) const { return find_in(typedefs_, id); }
const GhidraArchive::Pointer *GhidraArchive::pointer(std::uint64_t id) const { return find_in(pointers_, id); }
const GhidraArchive::Array *GhidraArchive::array(std::uint64_t id) const { return find_in(arrays_, id); }
const GhidraArchive::Composite *GhidraArchive::composite(std::uint64_t id) const { return find_in(composites_, id); }
const GhidraArchive::Enum *GhidraArchive::enumeration(std::uint64_t id) const { return find_in(enums_, id); }
const GhidraArchive::FunctionDef *GhidraArchive::function_type(std::uint64_t id) const { return find_in(functions_, id); }

// ---- encoding ----------------------------------------------------------------

namespace {

using lift::DecompElement;
using Attrs = std::vector<std::pair<std::string, DecompElement::Value>>;

DecompElement el(std::string tag, Attrs a = {}, std::vector<DecompElement> kids = {}) {
  return DecompElement{std::move(tag), std::move(a), std::move(kids)};
}

constexpr std::uint64_t kArchiveIds = 0x0020000000000000ULL;  // apart from Ghidra's and GhidraTypes' ids

}  // namespace

std::uint64_t ArchiveTypes::own_id(std::uint64_t id) const { return id | kArchiveIds; }

// Ghidra's built-in class names to the decompiler's names for them.
DecompElement ArchiveTypes::builtin(const GhidraArchive::Builtin &b) const {
  static const std::map<std::string, std::string> kClass = {
      {"UnsignedCharDataType", "uchar"},   {"UnsignedShortDataType", "ushort"}, {"UnsignedIntegerDataType", "uint"},
      {"UnsignedLongDataType", "ulong"},   {"CharDataType", "char"},            {"ShortDataType", "short"},
      {"IntegerDataType", "int"},          {"LongDataType", "long"},            {"VoidDataType", "void"},
      {"UnsignedLongLongDataType", "ulonglong"}, {"LongLongDataType", "longlong"}, {"WideCharDataType", "wchar_t"},
      {"DoubleDataType", "double"},        {"FloatDataType", "float"},          {"LongDoubleDataType", "longdouble"},
      {"BooleanDataType", "bool"},         {"SignedCharDataType", "schar"},     {"ByteDataType", "byte"},
      {"WordDataType", "word"},            {"DWordDataType", "dword"},          {"QWordDataType", "qword"},
      {"WideChar16DataType", "wchar16"},   {"WideChar32DataType", "wchar32"},   {"Undefined1DataType", "undefined1"},
      {"Undefined2DataType", "undefined2"}, {"Undefined4DataType", "undefined4"}, {"Undefined8DataType", "undefined8"},
      {"SignedByteDataType", "sbyte"},     {"SignedWordDataType", "sword"},     {"SignedDWordDataType", "sdword"},
      {"SignedQWordDataType", "sqword"},
  };
  std::string cls = b.class_name.substr(b.class_name.rfind('.') + 1);
  auto it = kClass.find(cls);
  return builtin_type(it != kClass.end() ? it->second : b.name, org_);
}

int ArchiveTypes::size_of(std::uint64_t id) const {
  if (id == 0) return 1;  // DEFAULT
  if (const auto *t = archive_.typedef_(id)) return size_of(t->target);
  if (const auto *p = archive_.pointer(id)) return p->length > 0 ? p->length : static_cast<int>(org_.pointer);
  if (const auto *a = archive_.array(id)) return a->count * a->element_length;
  if (const auto *c = archive_.composite(id)) return c->length;
  if (const auto *e = archive_.enumeration(id)) return e->size;
  if (const auto *b = archive_.builtin(id)) {
    DecompElement e = builtin(*b);
    if (const auto *sz = e.attr("size")) return static_cast<int>(std::get<std::int64_t>(*sz));
    if (e.tag == "void") return 0;
    const auto *n = e.attr("name");
    std::string nm = n ? std::get<std::string>(*n) : std::string();
    if (nm.starts_with("undefined") && nm.size() > 9) return std::stoi(nm.substr(9));
    return 1;
  }
  return 1;
}

DecompElement ArchiveTypes::ref(std::uint64_t id) {
  if (id == 0) return builtin_type("undefined", org_);
  if (depth_ > 64) return builtin_type("undefined", org_);
  struct Depth {
    int &d;
    explicit Depth(int &x) : d(x) { ++d; }
    ~Depth() { --d; }
  } guard(depth_);
  switch (kind_of(id)) {
    case 0:
      if (const auto *b = archive_.builtin(id)) return builtin(*b);
      break;
    case 3:
      if (const auto *a = archive_.array(id)) {
        return el("type",
                  {{"arraysize", std::int64_t{a->count}},
                   {"metatype", std::string("array")},
                   {"name", std::string()},
                   {"size", std::int64_t{a->count * a->element_length}}},
                  {ref(a->element)});
      }
      break;
    case 4:
      if (const auto *p = archive_.pointer(id)) {
        const int size = p->length > 0 ? p->length : static_cast<int>(org_.pointer);
        DecompElement target = p->target == 0 ? builtin_type("undefined", org_) : ref(p->target);
        return el("type", {{"metatype", std::string("ptr")}, {"name", std::string()}, {"size", std::int64_t{size}}},
                  {std::move(target)});
      }
      break;
    case 5:
      if (const auto *t = archive_.typedef_(id)) {
        if (!defined_.contains(id)) {
          defined_[id] = true;
          DecompElement target = ref(t->target);
          defs_.push_back(el("def", {{"id", own_id(id)}, {"name", t->name}}, {std::move(target)}));
        }
        return el("typeref", {{"id", own_id(id)}, {"name", t->name}});
      }
      break;
    case 1:
      if (const auto *c = archive_.composite(id)) {
        if (!defined_.contains(id)) {
          defined_[id] = true;
          std::vector<DecompElement> fields;
          for (const GhidraArchive::Component &m : c->components) {
            if (m.type == 0 && m.name.empty()) continue;  // undefined filler
            const int fsize = size_of(m.type);
            if (fsize <= 0 || (!c->is_union && m.offset + fsize > c->length)) continue;
            Attrs fa;
            if (c->is_union) fa.emplace_back("id", std::int64_t{m.ordinal});
            fa.emplace_back("name", m.name.empty() ? "field_0x" + std::to_string(m.offset) : m.name);
            fa.emplace_back("offset", std::int64_t{c->is_union ? 0 : m.offset});
            fields.push_back(el("field", std::move(fa), {ref(m.type)}));
          }
          const int length = c->length > 0 ? c->length : 1;
          defs_.push_back(el("type",
                             {{"alignment", std::int64_t{std::max(1, c->alignment)}},
                              {"id", own_id(id)},
                              {"metatype", std::string(c->is_union ? "union" : "struct")},
                              {"name", c->name},
                              {"size", std::int64_t{length}}},
                             std::move(fields)));
        }
        return el("typeref", {{"id", own_id(id)}, {"name", c->name}});
      }
      break;
    case 8:
      if (const auto *e = archive_.enumeration(id)) {
        if (!defined_.contains(id)) {
          defined_[id] = true;
          bool negative = false;
          std::vector<DecompElement> vals;
          for (const auto &[n, v] : e->values) {
            negative = negative || v < 0;
            vals.push_back(el("val", {{"name", n}, {"value", v}}));
          }
          defs_.push_back(el("type",
                             {{"id", own_id(id)},
                              {"metatype", std::string(negative ? "enum_int" : "enum_uint")},
                              {"name", e->name},
                              {"size", std::int64_t{e->size}}},
                             std::move(vals)));
        }
        return el("typeref", {{"id", own_id(id)}, {"name", e->name}});
      }
      break;
    case 6:
      if (const auto *f = archive_.function_type(id)) {
        if (!defined_.contains(id)) {
          defined_[id] = true;
          Attrs pa{{"extrapop", std::int64_t{org_.extrapop}}, {"model", std::string("unknown")}, {"modellock", true}};
          if (f->varargs) pa.emplace_back("dotdotdot", true);
          if (f->params.empty()) pa.emplace_back("voidlock", true);
          std::vector<DecompElement> params;
          for (const GhidraArchive::Param &p : f->params)
            params.push_back(el("param", {{"namelock", false}, {"typelock", true}}, {el("addr"), ref(p.type)}));
          DecompElement proto = el("prototype", std::move(pa),
                                   {el("returnsym", {{"typelock", true}}, {el("addr"), ref(f->ret)}),
                                    el("internallist", {}, std::move(params))});
          defs_.push_back(el("type",
                             {{"id", own_id(id)},
                              {"metatype", std::string("code")},
                              {"name", f->name},
                              {"size", std::int64_t{1}}},
                             {std::move(proto)}));
        }
        return el("typeref", {{"id", own_id(id)}, {"name", f->name}, {"size", std::int64_t{1}}});
      }
      break;
    default: break;
  }
  return builtin_type("undefined", org_);
}

}  // namespace revkit::inputs
