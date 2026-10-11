// Function ID databases: Ghidra's .fidbf (read-only) and revkit's .rkfid.
//
// .fidbf is a Ghidra LocalBufferFile holding a DBHandle database
// (Ghidra/Framework/DB, Apache 2.0): a header block, then fixed-size
// blocks of a 5-byte prefix (flags, buffer id) and a buffer. Buffer 0 is
// DBParms (parameter 0: the master table's root buffer); the master table
// is a B-tree of TableRecords (name, schema, root buffer, index column);
// each table is a B-tree of long-keyed records, interior nodes
// (LONGKEY_INTERIOR_NODE) above leaves of fixed-length (LONGKEY_FIXED_REC_NODE)
// or variable-length records (LONGKEY_VAR_REC_NODE, large ones in a
// ChainedBuffer). Index tables are skipped: every table is read whole.
// Everything is big-endian.

#include "revkit/fid/db.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>

namespace revkit::fid {

namespace {

constexpr std::uint64_t kFnvPrime = 1099511628211ULL;
constexpr std::uint64_t kFidbfMagic = 0x2f30312c34292c2aULL;
constexpr char kRkfidMagic[8] = {'R', 'K', 'F', 'I', 'D', '\0', '\1', '\0'};

[[noreturn]] void bad(const std::string &what) { throw FidError("bad Function ID database: " + what); }

std::uint64_t be(std::span<const std::byte> b, std::size_t off, std::size_t n) {
  if (off > b.size() || n > b.size() - off) bad("read past the end of a buffer");
  std::uint64_t v = 0;
  for (std::size_t i = 0; i < n; ++i) v = (v << 8) | std::to_integer<std::uint64_t>(b[off + i]);
  return v;
}
std::int32_t be32(std::span<const std::byte> b, std::size_t off) { return static_cast<std::int32_t>(be(b, off, 4)); }
std::int64_t be64(std::span<const std::byte> b, std::size_t off) { return static_cast<std::int64_t>(be(b, off, 8)); }

// ChainedBuffer's obfuscation mask.
constexpr std::uint8_t kXor[128] = {
    0x59, 0xea, 0x67, 0x23, 0xda, 0xb8, 0x00, 0xb8, 0xc3, 0x48, 0xdd, 0x8b, 0x21, 0xd6, 0x94, 0x78, 0x35, 0xab, 0x2b,
    0x7e, 0xb2, 0x4f, 0x82, 0x4e, 0x0e, 0x16, 0xc4, 0x57, 0x12, 0x8e, 0x7e, 0xe6, 0xb6, 0xbd, 0x56, 0x91, 0x57, 0x72,
    0xe6, 0x91, 0xdc, 0x52, 0x2e, 0xf2, 0x1a, 0xb7, 0xd6, 0x6f, 0xda, 0xde, 0xe8, 0x48, 0xb1, 0xbb, 0x50, 0x6f, 0xf4,
    0xdd, 0x11, 0xee, 0xf2, 0x67, 0xfe, 0x48, 0x8d, 0xae, 0x69, 0x1a, 0xe0, 0x26, 0x8c, 0x24, 0x8e, 0x17, 0x76, 0x51,
    0xe2, 0x60, 0xd7, 0xe6, 0x83, 0x65, 0xd5, 0xf0, 0x7f, 0xf2, 0xa0, 0xd6, 0x4b, 0xbd, 0x24, 0xd8, 0xab, 0xea, 0x9e,
    0xa6, 0x48, 0x94, 0x3e, 0x7b, 0x2c, 0xf4, 0xce, 0xdc, 0x69, 0x11, 0xf8, 0x3c, 0xa7, 0x3f, 0x5d, 0x77, 0x94, 0x3f,
    0xe4, 0x8e, 0x48, 0x20, 0xdb, 0x56, 0x32, 0xc1, 0x87, 0x01, 0x2e, 0xe3, 0x7f, 0x40};

// Field types (db.Field).
enum : std::uint8_t { kByte = 0, kShort = 1, kInt = 2, kLong = 3, kString = 4, kBinary = 5, kBool = 6, kFixed10 = 7 };

struct Value {
  std::int64_t i = 0;
  std::optional<std::string> s;  // strings and binaries
};

class BufferFile {
 public:
  explicit BufferFile(std::span<const std::byte> data) : d_(data) {
    if (d_.size() < 32) bad("too short");
    if (be(d_, 0, 8) != kFidbfMagic) bad("not a Ghidra buffer file");
    if (be32(d_, 16) != 1) bad("unsupported buffer file version");
    const std::int32_t bs = be32(d_, 20);
    if (bs < 128 || bs > (1 << 22)) bad("block size out of range");
    block_ = static_cast<std::size_t>(bs);
    if (d_.size() % block_ != 0) bad("file is not a whole number of blocks");
    count_ = d_.size() / block_ - 1;
  }
  std::size_t buffer_size() const { return block_ - 5; }
  std::size_t count() const { return count_; }
  // Buffer `id` (block id + 1), which must be in use and say it is `id`.
  std::span<const std::byte> buffer(std::int64_t id) const {
    if (id < 0 || static_cast<std::uint64_t>(id) >= count_) bad("buffer id out of range");
    std::span<const std::byte> blk = d_.subspan((static_cast<std::size_t>(id) + 1) * block_, block_);
    if (std::to_integer<int>(blk[0]) != 0) bad("reference to a free buffer");
    if (be32(blk, 1) != id) bad("buffer id mismatch");
    return blk.subspan(5);
  }
  // Records may all point at one string or chained buffer, each decoded
  // and kept: 160 GB from a 4 MB node. What the records decode to is
  // capped at four times the file (plus 1 MiB).
  void charge(std::size_t bytes) const {
    decoded_ += bytes;
    if (decoded_ > 4 * d_.size() + (1u << 20)) bad("records decode to more than the file holds");
  }

 private:
  std::span<const std::byte> d_;
  std::size_t block_ = 0, count_ = 0;
  mutable std::size_t decoded_ = 0;
};

// ChainedBuffer contents (a record stored outside its node).
std::string chained(const BufferFile &f, std::int64_t id) {
  std::span<const std::byte> b = f.buffer(id);
  std::int32_t size = be32(b, 1);
  const bool xored = size < 0;
  size &= 0x7fffffff;
  const auto type = std::to_integer<int>(b[0]);
  std::string out;
  if (size == 0) bad("empty chained buffer");
  if (type == 9) {  // CHAINED_BUFFER_DATA_NODE: one buffer
    if (static_cast<std::size_t>(size) > b.size() - 5) bad("chained buffer longer than its buffer");
    out.resize(static_cast<std::size_t>(size));
    for (std::size_t i = 0; i < out.size(); ++i) {
      auto c = std::to_integer<std::uint8_t>(b[5 + i]);
      out[i] = static_cast<char>(xored ? c ^ kXor[i % 128] : c);
    }
    return out;
  }
  if (type != 8) bad("bad chained buffer node");
  f.charge(static_cast<std::size_t>(size));
  const std::size_t space = b.size() - 1;
  const std::size_t n = (static_cast<std::size_t>(size) - 1) / space + 1;
  if (n > f.count()) bad("chained buffer larger than the file");
  const std::size_t per = (b.size() - 9) / 4;
  std::vector<std::int32_t> ids;
  std::span<const std::byte> ib = b;
  std::size_t off = 9, ix = 0, hops = 0;
  for (std::size_t i = 0; i < n; ++i) {
    if (ix == per) {
      if (++hops > f.count()) bad("chained buffer index loops");
      ib = f.buffer(be32(ib, 5));
      if (std::to_integer<int>(ib[0]) != 8) bad("bad chained buffer index node");
      off = 9;
      ix = 0;
    }
    ids.push_back(be32(ib, off));
    off += 4;
    ++ix;
  }
  out.reserve(static_cast<std::size_t>(size));
  for (std::size_t k = 0; k < n; ++k) {
    const std::size_t len = std::min(space, static_cast<std::size_t>(size) - k * space);
    if (ids[k] < 0) {
      out.append(len, '\0');
      continue;
    }
    std::span<const std::byte> db = f.buffer(ids[k]);
    for (std::size_t i = 0; i < len; ++i) {
      auto c = std::to_integer<std::uint8_t>(db[1 + i]);
      out.push_back(static_cast<char>(xored ? c ^ kXor[i % 128] : c));
    }
  }
  return out;
}

std::size_t fixed_length(const std::vector<std::uint8_t> &types) {
  std::size_t n = 0;
  for (std::uint8_t t : types) {
    switch (t) {
      case kByte: case kBool: n += 1; break;
      case kShort: n += 2; break;
      case kInt: n += 4; break;
      case kLong: n += 8; break;
      case kFixed10: n += 10; break;
      default: bad("variable-length field in a fixed record");
    }
  }
  return n;
}

std::vector<Value> read_record(const std::vector<std::uint8_t> &types, std::span<const std::byte> b, std::size_t off) {
  std::vector<Value> out;
  for (std::uint8_t t : types) {
    Value v;
    switch (t) {
      case kByte: v.i = static_cast<std::int8_t>(be(b, off, 1)); off += 1; break;
      case kBool: v.i = be(b, off, 1) != 0; off += 1; break;
      case kShort: v.i = static_cast<std::int16_t>(be(b, off, 2)); off += 2; break;
      case kInt: v.i = be32(b, off); off += 4; break;
      case kLong: v.i = be64(b, off); off += 8; break;
      case kFixed10: off += 10; if (off > b.size()) bad("record past its buffer"); break;
      case kString:
      case kBinary: {
        const std::int32_t len = be32(b, off);
        off += 4;
        if (len >= 0) {
          if (static_cast<std::size_t>(len) > b.size() - off) bad("string past its buffer");
          v.s = std::string(reinterpret_cast<const char *>(b.data() + off), static_cast<std::size_t>(len));
          off += static_cast<std::size_t>(len);
        }
        break;
      }
      default: bad("unknown field type");
    }
    out.push_back(std::move(v));
  }
  return out;
}

// Every record of the table rooted at `root`, in key order.
template <class Fn>
void each_record(const BufferFile &f, std::int32_t root, const std::vector<std::uint8_t> &types, Fn &&fn) {
  if (root < 0) return;  // empty table
  std::vector<std::int32_t> stack{root};
  std::unordered_set<std::int32_t> seen;
  while (!stack.empty()) {
    const std::int32_t id = stack.back();
    stack.pop_back();
    if (!seen.insert(id).second) bad("a table's tree has a cycle");
    std::span<const std::byte> b = f.buffer(id);
    const auto type = std::to_integer<int>(b[0]);
    const std::int32_t keys = be32(b, 1);
    if (keys < 0) bad("negative key count");
    const auto n = static_cast<std::size_t>(keys);
    if (type == 0) {  // LONGKEY_INTERIOR_NODE: (key, child id) entries
      if (n > (b.size() - 5) / 12) bad("interior node overflows its buffer");
      for (std::size_t i = n; i-- > 0;) stack.push_back(be32(b, 5 + i * 12 + 8));
    } else if (type == 2) {  // LONGKEY_FIXED_REC_NODE
      const std::size_t entry = 8 + fixed_length(types);
      if (n > (b.size() - 13) / entry) bad("record node overflows its buffer");
      for (std::size_t i = 0; i < n; ++i) {
        const std::size_t o = 13 + i * entry;
        fn(be64(b, o), read_record(types, b, o + 8));
      }
    } else if (type == 1) {  // LONGKEY_VAR_REC_NODE: (key, data offset, indirect) entries
      if (n > (b.size() - 13) / 13) bad("record node overflows its buffer");
      for (std::size_t i = 0; i < n; ++i) {
        const std::size_t e = 13 + i * 13;
        const std::int64_t key = be64(b, e);
        const std::int32_t off = be32(b, e + 8);
        if (off < 13 || static_cast<std::size_t>(off) >= b.size()) bad("record offset out of its buffer");
        std::vector<Value> v;
        if (std::to_integer<int>(b[e + 12]) != 0) {
          const std::string data = chained(f, be32(b, static_cast<std::size_t>(off)));
          v = read_record(types, std::as_bytes(std::span(data.data(), data.size())), 0);
        } else {
          v = read_record(types, b, static_cast<std::size_t>(off));
        }
        std::size_t bytes = 13;
        for (const Value &x : v) bytes += x.s ? x.s->size() : 0;
        f.charge(bytes);
        fn(key, std::move(v));
      }
    } else {
      bad("unexpected node type " + std::to_string(type));
    }
  }
}

struct TableInfo {
  std::int32_t version = 0;
  std::int32_t root = -1;
  std::int64_t records = 0;
  std::uint8_t key_type = 0;
  std::vector<std::uint8_t> types;
};

std::string str(const Value &v) { return v.s.value_or(std::string()); }

// Little-endian writer/reader for .rkfid.
struct Out {
  std::string s;
  void u8(std::uint8_t v) { s.push_back(static_cast<char>(v)); }
  void u16(std::uint16_t v) { for (int i = 0; i < 2; ++i) u8(static_cast<std::uint8_t>(v >> (8 * i))); }
  void u32(std::uint32_t v) { for (int i = 0; i < 4; ++i) u8(static_cast<std::uint8_t>(v >> (8 * i))); }
  void u64(std::uint64_t v) { for (int i = 0; i < 8; ++i) u8(static_cast<std::uint8_t>(v >> (8 * i))); }
  void text(const std::string &t) {
    u32(static_cast<std::uint32_t>(t.size()));
    s += t;
  }
};

struct In {
  std::span<const std::byte> b;
  std::size_t off = 0;
  std::uint64_t le(std::size_t n) {
    if (off > b.size() || n > b.size() - off) bad("truncated");
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i) v |= std::to_integer<std::uint64_t>(b[off + i]) << (8 * i);
    off += n;
    return v;
  }
  std::string text() {
    const std::uint64_t n = le(4);
    if (n > b.size() - off) bad("string past the end");
    std::string t(reinterpret_cast<const char *>(b.data() + off), static_cast<std::size_t>(n));
    off += static_cast<std::size_t>(n);
    return t;
  }
  std::size_t count(std::size_t min_size) {
    const std::uint64_t n = le(4);
    if (n > (b.size() - off) / min_size) bad("count larger than the file");
    return static_cast<std::size_t>(n);
  }
};

}  // namespace

std::uint64_t superior_key(std::int64_t caller_id, std::uint64_t callee_full) {
  return (static_cast<std::uint64_t>(caller_id) * kFnvPrime) ^ callee_full;
}
std::uint64_t inferior_key(std::int64_t callee_id, std::uint64_t caller_full) {
  return (static_cast<std::uint64_t>(callee_id) * kFnvPrime) ^ caller_full;
}

Database Database::open(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw FidError("cannot read " + path.string());
  std::ostringstream s;
  s << in.rdbuf();
  const std::string data = s.str();
  return parse(std::as_bytes(std::span(data.data(), data.size())), path.stem().string());
}

Database Database::parse(std::span<const std::byte> bytes, std::string name) {
  Database db;
  if (bytes.size() >= 8 && std::memcmp(bytes.data(), kRkfidMagic, 8) == 0) db = parse_rkfid(bytes);
  else db = parse_fidbf(bytes);
  db.name_ = std::move(name);
  return db;
}

Database Database::parse_fidbf(std::span<const std::byte> bytes, bool libraries_only) {
  BufferFile f(bytes);
  if (f.count() == 0) bad("no buffers");
  // DBParms: a one-buffer chained buffer (type 9), version 1, int parameters.
  std::span<const std::byte> parms = f.buffer(0);
  if (std::to_integer<int>(parms[0]) != 9 || std::to_integer<int>(parms[5]) != 1) bad("bad database parameters");
  if (be32(parms, 1) < 5) bad("no master table parameter");
  const std::int32_t master_root = be32(parms, 6);

  std::map<std::string, TableInfo> tables;
  const std::vector<std::uint8_t> master = {kString, kInt, kInt, kByte, kBinary, kString, kInt, kLong, kInt};
  each_record(f, master_root, master, [&](std::int64_t, std::vector<Value> v) {
    if (v[6].i != -1) return;  // an index table
    TableInfo t;
    t.version = static_cast<std::int32_t>(v[1].i);
    t.root = static_cast<std::int32_t>(v[2].i);
    t.key_type = static_cast<std::uint8_t>(v[3].i);
    t.records = v[8].i;
    for (char c : str(v[4])) t.types.push_back(static_cast<std::uint8_t>(c));
    tables[str(v[0])] = std::move(t);
  });
  auto table = [&](const std::string &name, const std::vector<std::uint8_t> &types) -> const TableInfo & {
    auto it = tables.find(name);
    if (it == tables.end()) bad("no table \"" + name + "\"");
    if (it->second.key_type != kLong || it->second.types != types) bad("table \"" + name + "\" has another schema");
    return it->second;
  };
  const TableInfo &libs = table("Libraries Table", {kString, kString, kString, kString, kString, kInt, kInt, kString});
  if (libs.version != 6) bad("Function ID schema version " + std::to_string(libs.version) + " (revkit reads 6)");
  Database db;
  db.format_ = Format::fidbf;
  auto read_libraries = [&] {
    each_record(f, libs.root, libs.types, [&](std::int64_t key, std::vector<Value> v) {
      Library l;
      l.id = key;
      l.family = str(v[0]);
      l.version = str(v[1]);
      l.variant = str(v[2]);
      l.ghidra_version = str(v[3]);
      l.language = str(v[4]);
      l.language_version = static_cast<std::int32_t>(v[5].i);
      l.language_minor = static_cast<std::int32_t>(v[6].i);
      l.compiler = str(v[7]);
      db.library_index_[l.id] = db.libraries_.size();
      db.libraries_.push_back(std::move(l));
    });
  };
  read_libraries();
  if (libraries_only) {
    if (auto it = tables.find("Functions Table"); it != tables.end() && it->second.records > 0)
      db.peeked_functions_ = static_cast<std::uint64_t>(it->second.records);
    return db;
  }
  const TableInfo &funcs = table("Functions Table", {kShort, kLong, kByte, kLong, kLong, kLong, kLong, kLong, kByte});
  const TableInfo &strings = table("Strings Table", {kString});
  const TableInfo &sup = table("Superior Table", {});
  const TableInfo &inf = table("Inferior Table", {});

  std::unordered_map<std::int64_t, std::string> text;
  each_record(f, strings.root, strings.types,
              [&](std::int64_t key, std::vector<Value> v) { text[key] = str(v[0]); });
  auto lookup = [&](std::int64_t id) {
    auto it = text.find(id);
    return it == text.end() ? std::string() : it->second;
  };
  each_record(f, funcs.root, funcs.types, [&](std::int64_t key, std::vector<Value> v) {
    Function fn;
    fn.id = key;
    fn.hash.code_units = static_cast<std::uint16_t>(v[0].i);
    fn.hash.full = static_cast<std::uint64_t>(v[1].i);
    fn.hash.specific_extra = static_cast<std::uint8_t>(v[2].i);
    fn.hash.specific = static_cast<std::uint64_t>(v[3].i);
    fn.library = v[4].i;
    fn.name = lookup(v[5].i);
    fn.entry = static_cast<std::uint64_t>(v[6].i);
    fn.path = db.intern_path(lookup(v[7].i));
    fn.flags = static_cast<std::uint8_t>(v[8].i);
    db.functions_.push_back(std::move(fn));
  });
  each_record(f, sup.root, sup.types,
              [&](std::int64_t key, std::vector<Value>) { db.superior_.insert(static_cast<std::uint64_t>(key)); });
  each_record(f, inf.root, inf.types,
              [&](std::int64_t key, std::vector<Value>) { db.inferior_.insert(static_cast<std::uint64_t>(key)); });
  db.index();
  return db;
}

Database Database::parse_rkfid(std::span<const std::byte> bytes, bool libraries_only) {
  In in{bytes, 8};
  Database db;
  db.format_ = Format::rkfid;
  const std::size_t nl = in.count(40);
  for (std::size_t i = 0; i < nl; ++i) {
    Library l;
    l.id = static_cast<std::int64_t>(in.le(8));
    l.family = in.text();
    l.version = in.text();
    l.variant = in.text();
    l.ghidra_version = in.text();
    l.language = in.text();
    l.compiler = in.text();
    l.language_version = static_cast<std::int32_t>(in.le(4));
    l.language_minor = static_cast<std::int32_t>(in.le(4));
    db.library_index_[l.id] = db.libraries_.size();
    db.libraries_.push_back(std::move(l));
  }
  if (libraries_only) {
    db.peeked_functions_ = in.le(4);
    return db;
  }
  const std::size_t nf = in.count(52);  // a function with empty name and path
  db.functions_.reserve(nf);
  for (std::size_t i = 0; i < nf; ++i) {
    Function fn;
    fn.id = static_cast<std::int64_t>(in.le(8));
    fn.hash.code_units = static_cast<std::uint16_t>(in.le(2));
    fn.hash.full = in.le(8);
    fn.hash.specific_extra = static_cast<std::uint8_t>(in.le(1));
    fn.hash.specific = in.le(8);
    fn.library = static_cast<std::int64_t>(in.le(8));
    fn.name = in.text();
    fn.entry = in.le(8);
    fn.path = db.intern_path(in.text());
    fn.flags = static_cast<std::uint8_t>(in.le(1));
    db.next_id_ = std::max(db.next_id_, fn.id + 1);
    db.functions_.push_back(std::move(fn));
  }
  const std::size_t ns = in.count(8);
  for (std::size_t i = 0; i < ns; ++i) db.superior_.insert(in.le(8));
  const std::size_t ni = in.count(8);
  for (std::size_t i = 0; i < ni; ++i) db.inferior_.insert(in.le(8));
  if (in.off != bytes.size()) bad("trailing bytes");
  db.index();
  return db;
}

std::string Database::serialize() const {
  Out o;
  o.s.assign(kRkfidMagic, 8);
  o.u32(static_cast<std::uint32_t>(libraries_.size()));
  for (const Library &l : libraries_) {
    o.u64(static_cast<std::uint64_t>(l.id));
    o.text(l.family);
    o.text(l.version);
    o.text(l.variant);
    o.text(l.ghidra_version);
    o.text(l.language);
    o.text(l.compiler);
    o.u32(static_cast<std::uint32_t>(l.language_version));
    o.u32(static_cast<std::uint32_t>(l.language_minor));
  }
  o.u32(static_cast<std::uint32_t>(functions_.size()));
  for (const Function &f : functions_) {
    o.u64(static_cast<std::uint64_t>(f.id));
    o.u16(f.hash.code_units);
    o.u64(f.hash.full);
    o.u8(f.hash.specific_extra);
    o.u64(f.hash.specific);
    o.u64(static_cast<std::uint64_t>(f.library));
    o.text(f.name);
    o.u64(f.entry);
    o.text(path(f));
    o.u8(f.flags);
  }
  auto keys = [&](const std::unordered_set<std::uint64_t> &set) {
    std::vector<std::uint64_t> v(set.begin(), set.end());
    std::sort(v.begin(), v.end());  // deterministic files
    o.u32(static_cast<std::uint32_t>(v.size()));
    for (std::uint64_t k : v) o.u64(k);
  };
  keys(superior_);
  keys(inferior_);
  return o.s;
}

void Database::write(const std::filesystem::path &path) const {
  const std::string data = serialize();
  const std::filesystem::path tmp = path.string() + ".tmp";
  {
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out) throw FidError("cannot write " + tmp.string());
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!out) throw FidError("cannot write " + tmp.string());
  }
  std::filesystem::rename(tmp, path);
}

std::span<const Function> Database::by_full(std::uint64_t full) const {
  auto lo = std::lower_bound(functions_.begin(), functions_.end(), full,
                             [](const Function &f, std::uint64_t h) { return f.hash.full < h; });
  auto hi = std::upper_bound(lo, functions_.end(), full,
                             [](std::uint64_t h, const Function &f) { return h < f.hash.full; });
  return {functions_.data() + (lo - functions_.begin()), static_cast<std::size_t>(hi - lo)};
}

std::uint32_t Database::intern_path(const std::string &p) {
  if (p.empty()) return 0;
  auto [it, added] = path_index_.try_emplace(p, static_cast<std::uint32_t>(paths_.size()));
  if (added) paths_.push_back(p);
  return it->second;
}

Database::Peek Database::peek(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw FidError("cannot read " + path.string());
  std::ostringstream s;
  s << in.rdbuf();
  const std::string data = s.str();
  const auto bytes = std::as_bytes(std::span(data.data(), data.size()));
  const bool rkfid = bytes.size() >= 8 && std::memcmp(bytes.data(), kRkfidMagic, 8) == 0;
  Database db = rkfid ? parse_rkfid(bytes, true) : parse_fidbf(bytes, true);
  return Peek{std::move(db.libraries_), db.peeked_functions_, rkfid ? Format::rkfid : Format::fidbf};
}

const Library *Database::library(std::int64_t id) const {
  auto it = library_index_.find(id);
  return it == library_index_.end() ? nullptr : &libraries_[it->second];
}

bool Database::has_language(std::string_view language) const {
  for (const Library &l : libraries_)
    if (l.language == language) return true;
  return false;
}

std::int64_t Database::add_library(Library lib) {
  if (lib.id == 0) lib.id = next_id_++;
  next_id_ = std::max(next_id_, lib.id + 1);
  library_index_[lib.id] = libraries_.size();
  libraries_.push_back(std::move(lib));
  return libraries_.back().id;
}

std::int64_t Database::add_function(Function f) {
  if (f.id == 0) f.id = next_id_++;
  next_id_ = std::max(next_id_, f.id + 1);
  functions_.push_back(std::move(f));
  return functions_.back().id;
}

void Database::index() {
  std::sort(functions_.begin(), functions_.end(), [](const Function &a, const Function &b) {
    return a.hash.full != b.hash.full ? a.hash.full < b.hash.full : a.id < b.id;
  });
  library_index_.clear();
  for (std::size_t i = 0; i < libraries_.size(); ++i) library_index_[libraries_[i].id] = i;
}

std::vector<const Function *> Database::by_name(std::int64_t library, std::string_view name) const {
  std::vector<const Function *> out;
  for (const Function &f : functions_)
    if (f.library == library && f.name == name) out.push_back(&f);
  return out;
}

}  // namespace revkit::fid
