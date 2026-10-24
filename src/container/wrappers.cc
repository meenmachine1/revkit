// Firmware wrappers and image formats (docs/filesystems.md): Broadcom TRX
// images (their partitions), Android sparse images (expanded to the raw
// image), device tree blobs (the tree as directories of property files,
// with the source as text; U-Boot FIT images are device trees, so their
// images come out as files with their load addresses), and Intel HEX and
// Motorola S-records (one flat image per address range, at its address).
#include "formats.hh"

#include <algorithm>
#include <cstdio>
#include <map>
#include <set>

namespace revkit::container::detail {
namespace {

std::string hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::string base_name(std::string_view name) {
  if (const auto slash = name.find_last_of('/'); slash != std::string_view::npos) name = name.substr(slash + 1);
  if (const auto dot = name.find_last_of('.'); dot != std::string_view::npos && dot > 0) name = name.substr(0, dot);
  return name.empty() ? "image" : std::string(name);
}

// A file made of pieces: stored bytes of the container, a repeated 4-byte
// pattern, or erased flash (0xff). What no piece covers reads as zeros.
struct Piece {
  std::uint64_t logical = 0, length = 0;
  enum Type : std::uint8_t { stored, fill, erased, memory } type = stored;
  std::uint64_t physical = 0;  // stored: where; memory: index of a buffer
  std::uint32_t pattern = 0;   // fill: as stored (little-endian)
};

class PieceSource final : public Source {
 public:
  PieceSource(std::shared_ptr<const Source> base, std::vector<Piece> pieces, std::uint64_t size,
              std::shared_ptr<const std::vector<std::vector<std::byte>>> buffers = {})
      : base_(std::move(base)), pieces_(std::move(pieces)), size_(size), buffers_(std::move(buffers)) {}
  std::uint64_t size() const override { return size_; }
  std::size_t read(std::uint64_t offset, std::span<std::byte> out) const override {
    if (offset >= size_) return 0;
    const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(out.size(), size_ - offset));
    std::size_t done = 0;
    auto it = std::upper_bound(pieces_.begin(), pieces_.end(), offset,
                               [](std::uint64_t o, const Piece &p) { return o < p.logical + p.length; });
    while (done < want) {
      const std::uint64_t at = offset + done;
      if (it == pieces_.end() || at < it->logical) {
        const std::uint64_t until = it == pieces_.end() ? size_ : it->logical;
        const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(want - done, until - at));
        std::memset(out.data() + done, 0, n);
        done += n;
        continue;
      }
      const std::uint64_t in = at - it->logical;
      const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(want - done, it->length - in));
      switch (it->type) {
        case Piece::stored: {
          const std::size_t got = base_->read(it->physical + in, out.subspan(done, n));
          if (got < n) std::memset(out.data() + done + got, 0, n - got);
          break;
        }
        case Piece::fill:
          for (std::size_t k = 0; k < n; ++k)
            out[done + k] = static_cast<std::byte>(it->pattern >> (8 * ((in + k) & 3)));
          break;
        case Piece::erased: std::memset(out.data() + done, 0xff, n); break;
        case Piece::memory: {
          const auto &b = buffers_->at(it->physical);
          std::memcpy(out.data() + done, b.data() + in, n);
          break;
        }
      }
      done += n;
      ++it;
    }
    return done;
  }

 private:
  std::shared_ptr<const Source> base_;
  std::vector<Piece> pieces_;
  std::uint64_t size_;
  std::shared_ptr<const std::vector<std::vector<std::byte>>> buffers_;
};

// A FileSystem of flat files, each a PieceSource.
class PieceFileSystem : public FileSystem {
 public:
  explicit PieceFileSystem(std::shared_ptr<const Source> src) : src_(std::move(src)) {}
  std::shared_ptr<Source> open(std::uint32_t entry, const Context &) const override {
    const Entry &e = entries_.at(entry);
    if (e.kind != Kind::file) throw Error(display_name(e.name) + " is not a file");
    if (e.loc2 == UINT64_MAX) throw Error(display_name(e.name) + ": " + e.note);
    const auto &f = files_.at(e.loc0);
    return std::make_shared<PieceSource>(src_, f.pieces, f.size, buffers_);
  }
  bool stored_plain(std::uint32_t) const override { return true; }

 protected:
  struct File {
    std::vector<Piece> pieces;
    std::uint64_t size = 0;
  };
  std::uint64_t add_file(std::vector<Piece> pieces, std::uint64_t size) {
    std::sort(pieces.begin(), pieces.end(), [](const Piece &a, const Piece &b) { return a.logical < b.logical; });
    files_.push_back({std::move(pieces), size});
    return files_.size() - 1;
  }
  std::shared_ptr<const Source> src_;
  std::vector<File> files_;
  std::shared_ptr<std::vector<std::vector<std::byte>>> buffers_ = std::make_shared<std::vector<std::vector<std::byte>>>();
};

// ---- TRX ----------------------------------------------------------------------------

class Trx final : public SliceFileSystem {
 public:
  using SliceFileSystem::SliceFileSystem;
  void parse(const Context &ctx) {
    format_ = "trx";
    const auto hb = src_->read_exact(0, 32, "the TRX header");
    Buf h(hb, "the TRX header");
    if (h.l32(0) != 0x30524448) throw Error("not a TRX image");
    std::uint32_t len = h.l32(4);
    const std::uint32_t crc = h.l32(8), flags = h.l32(12);
    const std::uint32_t version = flags >> 16;
    if (version != 1 && version != 2) throw Error("TRX version " + std::to_string(version) + " is not known");
    const unsigned nparts = version == 2 ? 4 : 3;
    const std::uint32_t hdr = 16 + 4 * nparts;
    if (len < hdr) throw Error("a TRX image shorter than its header");
    if (len > src_->size()) {
      warn("the image is truncated: it says " + std::to_string(len) + " bytes");
      len = static_cast<std::uint32_t>(src_->size());
    } else {
      const auto body = src_->read_exact(12, len - 12, "the TRX image");
      if ((crc32_ieee(body, 0) ^ 0xffffffffu) != crc) warn("the image's CRC doesn't match");
    }
    std::vector<std::uint32_t> offs;
    for (unsigned i = 0; i < nparts; ++i) offs.push_back(h.l32(16 + 4 * i));
    // Named as Linux's TRX partition parser names them: a third offset
    // means the first part is an LZMA loader.
    std::vector<std::string> names;
    if (offs[2]) names.push_back("loader");
    names.push_back("linux");
    names.push_back("rootfs");
    while (names.size() < nparts) names.push_back("part" + std::to_string(names.size()));
    TreeBuilder tree(*this, ctx.limits);
    for (unsigned i = 0; i < nparts; ++i) {
      if (offs[i] == 0) continue;
      if (offs[i] < hdr || offs[i] >= len) {
        warn("partition " + names[i] + " starts outside the image");
        continue;
      }
      std::uint32_t end = len;
      for (unsigned k = 0; k < nparts; ++k)
        if (offs[k] > offs[i] && offs[k] < end) end = offs[k];
      Entry e;
      e.kind = Kind::file;
      e.name = names[i];
      e.loc0 = offs[i];
      e.loc1 = e.size = e.stored_size = end - offs[i];
      e.note = "partition " + std::to_string(i) + " at " + hex(offs[i]);
      tree.add_child(0, std::move(e));
    }
    tree.finish();
    description_ = "TRX v" + std::to_string(version) + " firmware, " + plural(entries_.size() - 1, "partition", "partitions") +
                   ", " + std::to_string(len) + " bytes";
  }
};

// ---- Android sparse images ---------------------------------------------------------

class Sparse final : public PieceFileSystem {
 public:
  using PieceFileSystem::PieceFileSystem;
  void parse(std::string_view name, const Context &ctx) {
    format_ = "android-sparse";
    const auto hb = src_->read_exact(0, 28, "the sparse image header");
    Buf h(hb, "the sparse image header");
    if (h.l32(0) != 0xed26ff3a) throw Error("not an Android sparse image");
    const std::uint16_t major = h.l16(4), fhdr = h.l16(8), chdr = h.l16(10);
    const std::uint32_t blk = h.l32(12), total_blks = h.l32(16), chunks = h.l32(20);
    if (major != 1) throw Error("sparse image version " + std::to_string(major) + " is not known");
    if (fhdr < 28 || chdr < 12 || blk == 0 || blk % 4) throw Error("a sparse image header with impossible sizes");
    const std::uint64_t size = std::uint64_t{total_blks} * blk;
    if (size > ctx.limits.max_file_bytes * 64) throw LimitError("a sparse image that expands past the limits");
    std::vector<Piece> pieces;
    std::uint64_t pos = fhdr, out = 0, raw = 0, fill = 0, skip = 0;
    for (std::uint32_t i = 0; i < chunks; ++i) {
      if ((i & 1023) == 0) ctx.check_cancelled();
      const auto cb = src_->read_exact(pos, chdr, "a sparse chunk header");
      const std::uint16_t type = le16(cb.data());
      const std::uint32_t csz = le32(cb.data() + 4), total = le32(cb.data() + 8);
      const std::uint64_t bytes = std::uint64_t{csz} * blk;
      if (total < chdr || pos + total > src_->size()) throw Error("a sparse chunk runs past the file");
      if (out + bytes > size && type != 0xcac4) throw Error("sparse chunks run past the image's size");
      switch (type) {
        case 0xcac1:  // raw
          if (total - chdr != bytes) throw Error("a raw sparse chunk of the wrong length");
          if (bytes) pieces.push_back({out, bytes, Piece::stored, pos + chdr, 0});
          ++raw;
          break;
        case 0xcac2: {  // fill
          if (total - chdr < 4) throw Error("a fill sparse chunk without its value");
          const auto v = src_->read_exact(pos + chdr, 4, "a sparse fill value");
          if (bytes && le32(v.data())) pieces.push_back({out, bytes, Piece::fill, 0, le32(v.data())});
          ++fill;
          break;
        }
        case 0xcac3: ++skip; break;  // don't care: zeros
        case 0xcac4: break;          // CRC32 of the data so far
        default: throw Error("sparse chunk type " + hex(type) + " is not known");
      }
      if (type != 0xcac4) out += bytes;
      pos += total;
    }
    if (out != size) warn("the chunks cover " + std::to_string(out) + " bytes of " + std::to_string(size));
    TreeBuilder tree(*this, ctx.limits);
    Entry e;
    e.kind = Kind::file;
    e.name = base_name(name) + ".raw.img";
    e.size = size;
    e.stored_size = src_->size();
    e.loc0 = add_file(std::move(pieces), size);
    tree.add_child(0, std::move(e));
    tree.finish();
    description_ = "Android sparse image, " + std::to_string(size) + " bytes in blocks of " + std::to_string(blk) + " (" +
                   plural(raw, "raw chunk", "raw chunks") + ", " + plural(fill, "fill", "fills") + ", " +
                   plural(skip, "hole", "holes") + ")";
  }
};

// ---- device trees -------------------------------------------------------------------

struct FitArch {
  const char *arch;
  const char *language;
};
constexpr FitArch kFitArchs[] = {
    {"arm", "ARM:LE:32:v8"}, {"arm64", "AARCH64:LE:64:v8A"}, {"x86", "x86:LE:32:default"},
    {"x86_64", "x86:LE:64:default"}, {"powerpc", "PowerPC:BE:32:default"}, {"ppc", "PowerPC:BE:32:default"},
};

bool printable_strings(std::span<const std::byte> v) {
  if (v.empty() || v.back() != std::byte{0}) return false;
  bool start = true;
  for (std::size_t i = 0; i < v.size(); ++i) {
    const auto c = static_cast<std::uint8_t>(v[i]);
    if (c == 0) {
      if (start) return false;  // an empty string
      start = true;
      continue;
    }
    if (c < 0x20 || c > 0x7e) return false;
    start = false;
  }
  return true;
}

std::string dts_value(std::span<const std::byte> v) {
  if (v.empty()) return "";
  std::string s = " = ";
  if (printable_strings(v)) {
    bool first = true;
    std::size_t a = 0;
    for (std::size_t i = 0; i < v.size(); ++i)
      if (v[i] == std::byte{0}) {
        s += (first ? "\"" : ", \"");
        for (std::size_t k = a; k < i; ++k) {
          const char c = static_cast<char>(v[k]);
          if (c == '"' || c == '\\') s += '\\';
          s += c;
        }
        s += "\"";
        first = false;
        a = i + 1;
      }
    return s;
  }
  char buf[16];
  if (v.size() % 4 == 0 && v.size() <= 4096) {
    s += "<";
    for (std::size_t i = 0; i < v.size(); i += 4) {
      std::snprintf(buf, sizeof buf, "%s0x%08x", i ? " " : "", be32(v.data() + i));
      s += buf;
    }
    return s + ">";
  }
  s += "[";
  const std::size_t shown = std::min<std::size_t>(v.size(), 4096);
  for (std::size_t i = 0; i < shown; ++i) {
    std::snprintf(buf, sizeof buf, "%s%02x", i ? " " : "", static_cast<unsigned>(static_cast<std::uint8_t>(v[i])));
    s += buf;
  }
  if (shown < v.size()) s += " /* " + std::to_string(v.size() - shown) + " more bytes */";
  return s + "]";
}

class DeviceTree final : public PieceFileSystem {
 public:
  using PieceFileSystem::PieceFileSystem;
  void parse(const Context &ctx) {
    format_ = "dtb";
    const auto hb = src_->read_exact(0, 40, "the device tree header");
    Buf h(hb, "the device tree header");
    if (h.b32(0) != 0xd00dfeed) throw Error("not a device tree blob");
    const std::uint32_t total = h.b32(4), off_struct = h.b32(8), off_strings = h.b32(12), version = h.b32(20);
    const std::uint32_t size_strings = h.b32(32), size_struct = version >= 17 ? h.b32(36) : total - off_struct;
    if (total > src_->size()) throw Error("a device tree blob longer than its file");
    if (total > (256u << 20)) throw LimitError("a device tree blob over 256 MiB");
    if (version < 16) throw Error("device tree version " + std::to_string(version) + " is not supported");
    if (off_struct > total || size_struct > total - off_struct || off_strings > total || size_strings > total - off_strings)
      throw Error("a device tree blob whose blocks lie outside it");
    const auto blob = src_->read_exact(0, total, "the device tree");
    const std::span<const std::byte> st(blob.data() + off_struct, size_struct);
    const std::span<const std::byte> strs(blob.data() + off_strings, size_strings);
    TreeBuilder tree(*this, ctx.limits);
    std::string dts = "/dts-v1/;\n\n";
    std::vector<std::uint32_t> stack;  // the entries of the open nodes
    std::vector<std::map<std::string, std::span<const std::byte>>> props;  // each open node's
    std::vector<std::map<std::string, std::uint32_t>> prop_entries;
    std::uint64_t nodes = 0, nprops = 0;
    std::size_t p = 0;
    const std::uint64_t ext_base = (std::uint64_t{total} + 3) & ~3ull;  // FIT external data
    auto sp = [](std::size_t depth) { return std::string(4 * depth, ' '); };
    bool ended = false;
    while (!ended) {
      if (p + 4 > st.size()) throw Error("the device tree's structure block ends early");
      const std::uint32_t tok = be32(st.data() + p);
      p += 4;
      switch (tok) {
        case 1: {  // begin node
          const char *n = reinterpret_cast<const char *>(st.data() + p);
          const std::size_t len = strnlen(n, st.size() - p);
          if (p + len >= st.size()) throw Error("a device tree node name runs past the block");
          std::string name(n, len);
          p = (p + len + 1 + 3) & ~std::size_t{3};
          if (stack.size() > 64) throw LimitError("device tree nodes nest too deep");
          std::uint32_t idx = 0;
          if (!stack.empty()) {
            Entry e;
            e.kind = Kind::directory;
            e.name = name.empty() ? "_" : name;
            idx = tree.add_child(stack.back(), std::move(e));
            ++nodes;
          }
          dts += sp(stack.size()) + (stack.empty() ? std::string("/") : name) + " {\n";
          stack.push_back(idx);
          props.emplace_back();
          prop_entries.emplace_back();
          break;
        }
        case 2:  // end node
          if (stack.empty()) throw Error("an unbalanced device tree");
          fit_image(tree, stack.back(), props.back(), prop_entries.back(), ext_base);
          dts += sp(stack.size() - 1) + "};\n";
          stack.pop_back();
          props.pop_back();
          prop_entries.pop_back();
          break;
        case 3: {  // property
          if (stack.empty() || p + 8 > st.size()) throw Error("a device tree property outside a node");
          const std::uint32_t len = be32(st.data() + p), nameoff = be32(st.data() + p + 4);
          p += 8;
          if (len > st.size() - p) throw Error("a device tree property runs past the block");
          if (nameoff >= strs.size()) throw Error("a device tree property name outside the strings block");
          const char *n = reinterpret_cast<const char *>(strs.data() + nameoff);
          const std::string name(n, strnlen(n, strs.size() - nameoff));
          const auto value = st.subspan(p, len);
          Entry e;
          e.kind = Kind::file;
          e.name = name.empty() ? "_" : name;
          e.size = e.stored_size = len;
          e.loc0 = add_file({{0, len, Piece::stored, off_struct + p, 0}}, len);
          if (printable_strings(value) && len <= 256) {
            std::string shown(reinterpret_cast<const char *>(value.data()), len - 1);
            for (std::size_t k = shown.find('\0'); k != std::string::npos; k = shown.find('\0', k))
              shown.replace(k, 1, ", ");
            e.note = display_name(shown);
          }
          const std::uint32_t idx = tree.add_child(stack.back(), std::move(e));
          props.back()[name] = value;
          prop_entries.back()[name] = idx;
          ++nprops;
          dts += sp(stack.size()) + name + dts_value(value) + ";\n";
          p = (p + len + 3) & ~std::size_t{3};
          break;
        }
        case 4: break;  // nop
        case 9: ended = true; break;
        default: throw Error("device tree token " + hex(tok) + " is not known");
      }
      if (dts.size() > (16u << 20)) throw LimitError("a device tree whose source passes 16 MiB");
    }
    if (!stack.empty()) throw Error("an unbalanced device tree");
    buffers_->emplace_back(reinterpret_cast<const std::byte *>(dts.data()),
                           reinterpret_cast<const std::byte *>(dts.data()) + dts.size());
    Entry e;
    e.kind = Kind::file;
    e.name = "devicetree.dts";
    e.size = dts.size();
    e.note = "the tree as source (made by revkit)";
    e.content_kind = "dts-source";
    e.loc0 = add_file({{0, dts.size(), Piece::memory, buffers_->size() - 1, 0}}, dts.size());
    tree.add_child(0, std::move(e));
    tree.finish();
    description_ = std::string(fit_ ? "FIT image (device tree)" : "device tree blob") + " v" + std::to_string(version) + ", " +
                   plural(nodes, "node", "nodes") + ", " + plural(nprops, "property", "properties");
    if (fit_) description_ += ", " + plural(fit_, "image", "images");
  }

 private:
  // A FIT image node (/images/<name>): its data (inline, or external by
  // data-offset or data-position) with the load address and the
  // architecture's language when it isn't compressed.
  void fit_image(TreeBuilder &tree, std::uint32_t node, const std::map<std::string, std::span<const std::byte>> &props,
                 std::map<std::string, std::uint32_t> &entries, std::uint64_t ext_base) {
    auto cells = [&](const char *name) -> std::optional<std::uint64_t> {
      auto it = props.find(name);
      if (it == props.end()) return std::nullopt;
      if (it->second.size() == 4) return be32(it->second.data());
      if (it->second.size() == 8) return be64(it->second.data());
      return std::nullopt;
    };
    auto str = [&](const char *name) -> std::string {
      auto it = props.find(name);
      if (it == props.end() || !printable_strings(it->second)) return "";
      return std::string(reinterpret_cast<const char *>(it->second.data()));
    };
    const bool has_data = props.count("data") > 0;
    const auto off = cells("data-offset"), position = cells("data-position"), size = cells("data-size");
    if (!has_data && !((off || position) && size)) return;
    if (props.count("type") == 0 && props.count("arch") == 0 && props.count("compression") == 0) return;
    ++fit_;
    std::uint32_t data_entry;
    if (has_data) {
      data_entry = entries.at("data");
    } else {
      const std::uint64_t at = position ? *position : ext_base + *off;
      if (at > src_->size() || *size > src_->size() - at) {
        warn("a FIT image's external data lies outside the file");
        return;
      }
      Entry e;
      e.kind = Kind::file;
      e.name = "data";
      e.size = e.stored_size = *size;
      e.note = "external data at " + hex(at);
      e.loc0 = add_file({{0, *size, Piece::stored, at, 0}}, *size);
      data_entry = tree.add_child(node, std::move(e));
    }
    const std::string compression = str("compression");
    const std::string arch = str("arch");
    const auto load = cells("load");
    if ((compression.empty() || compression == "none") && load) {
      const char *lang = "";
      for (const FitArch &a : kFitArchs)
        if (arch == a.arch) lang = a.language;
      Entry &e = entries_.at(data_entry);
      e.load_address = *load;
      e.language = lang;
    }
  }

  std::uint64_t fit_ = 0;
};

// ---- Intel HEX and Motorola S-records ----------------------------------------------

int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

class HexImage final : public PieceFileSystem {
 public:
  using PieceFileSystem::PieceFileSystem;
  void parse(bool srec, std::string_view name, const Context &ctx) {
    format_ = srec ? "srec" : "ihex";
    if (src_->size() > ctx.limits.max_file_bytes) throw LimitError("a hex file over the size limit");
    // Data by address, merged where records follow each other.
    std::map<std::uint64_t, std::vector<std::byte>> data;
    std::uint64_t base = 0, records = 0, bad_sums = 0;
    std::optional<std::uint64_t> entry;
    std::string header;
    WindowReader rd(*src_);
    std::uint64_t pos = 0, line_no = 0;
    std::vector<std::uint8_t> rec;
    auto add = [&](std::uint64_t addr, std::span<const std::uint8_t> bytes) {
      if (bytes.empty()) return;
      auto it = data.upper_bound(addr);
      if (it != data.begin()) {
        auto prev = std::prev(it);
        if (prev->first + prev->second.size() == addr) {
          for (std::uint8_t b : bytes) prev->second.push_back(static_cast<std::byte>(b));
          return;
        }
      }
      std::vector<std::byte> v(bytes.size());
      std::memcpy(v.data(), bytes.data(), bytes.size());
      data[addr] = std::move(v);
    };
    bool done = false;
    while (pos < src_->size() && !done) {
      if ((++line_no & 4095) == 0) ctx.check_cancelled();
      auto w = rd.get(pos, 1024);
      std::size_t n = 0;
      while (n < w.size() && w[n] != std::byte{'\n'}) ++n;
      if (n == w.size() && pos + n < src_->size()) throw Error("a hex record line over 1 KiB, line " + std::to_string(line_no));
      std::string line(reinterpret_cast<const char *>(w.data()), n);
      pos += n + 1;
      while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.pop_back();
      if (line.empty()) continue;
      const std::size_t start = srec ? 2 : 1;
      if (line[0] != (srec ? 'S' : ':') || line.size() < start + 2 || (line.size() - start) % 2)
        throw Error("not a " + std::string(srec ? "S-record" : "HEX record") + ", line " + std::to_string(line_no));
      rec.clear();
      for (std::size_t i = start; i < line.size(); i += 2) {
        const int hi = hexval(line[i]), lo = hexval(line[i + 1]);
        if (hi < 0 || lo < 0) throw Error("a bad hex digit, line " + std::to_string(line_no));
        rec.push_back(static_cast<std::uint8_t>(hi << 4 | lo));
      }
      ++records;
      unsigned sum = 0;
      for (std::uint8_t b : rec) sum += b;
      if (srec) {
        const char t = line[1];
        if (rec[0] + 1u != rec.size()) throw Error("an S-record whose count is wrong, line " + std::to_string(line_no));
        if ((sum & 0xff) != 0xff) ++bad_sums;
        const unsigned alen = t == '0' || t == '1' || t == '5' || t == '9' ? 2 : t == '2' || t == '6' || t == '8' ? 3 : 4;
        if (rec.size() < 2 + alen) throw Error("a short S-record, line " + std::to_string(line_no));
        std::uint64_t addr = 0;
        for (unsigned k = 0; k < alen; ++k) addr = addr << 8 | rec[1 + k];
        const std::span<const std::uint8_t> payload(rec.data() + 1 + alen, rec.size() - 2 - alen);
        switch (t) {
          case '0': header.assign(payload.begin(), payload.end()); break;
          case '1':
          case '2':
          case '3': add(addr, payload); break;
          case '7':
          case '8':
          case '9':
            entry = addr;
            done = true;
            break;
          default: break;  // S4 (reserved), S5 and S6 (counts)
        }
      } else {
        if (rec.size() < 5 || rec[0] + 5u != rec.size())
          throw Error("a HEX record whose length is wrong, line " + std::to_string(line_no));
        if ((sum & 0xff) != 0) ++bad_sums;
        const std::uint32_t off = rec[1] << 8 | rec[2];
        const std::uint8_t type = rec[3];
        const std::span<const std::uint8_t> payload(rec.data() + 4, rec[0]);
        switch (type) {
          case 0: add(base + off, payload); break;
          case 1: done = true; break;
          case 2:
            if (payload.size() == 2) base = (std::uint64_t{payload[0]} << 8 | payload[1]) << 4;
            break;
          case 3:
            if (payload.size() == 4) entry = (std::uint64_t{payload[0]} << 8 | payload[1]) * 16 + (payload[2] << 8 | payload[3]);
            break;
          case 4:
            if (payload.size() == 2) base = (std::uint64_t{payload[0]} << 8 | payload[1]) << 16;
            break;
          case 5:
            if (payload.size() == 4)
              entry = std::uint64_t{payload[0]} << 24 | payload[1] << 16 | payload[2] << 8 | payload[3];
            break;
          default: throw Error("HEX record type " + std::to_string(type) + " is not known");
        }
      }
    }
    if (data.empty()) throw Error("a hex file with no data records");
    if (bad_sums) warn(plural(bad_sums, "record's checksum doesn't", "records' checksums don't") + " match");
    // One image per range; gaps under 64 KiB read as erased flash (0xff).
    TreeBuilder tree(*this, ctx.limits);
    const std::string stem = base_name(name);
    auto it = data.begin();
    while (it != data.end()) {
      const std::uint64_t start = it->first;
      std::uint64_t end = start;
      std::vector<Piece> pieces;
      while (it != data.end() && it->first <= end + 65536) {
        if (it->first < end) {
          warn("records overlap at " + hex(it->first) + ": the later one is kept");
        } else if (it->first > end) {
          pieces.push_back({end - start, it->first - end, Piece::erased, 0, 0});
        }
        const std::uint64_t from = std::max(it->first, end);
        const std::uint64_t skip = from - it->first;
        if (skip < it->second.size()) {
          buffers_->push_back(std::vector<std::byte>(it->second.begin() + static_cast<std::ptrdiff_t>(skip), it->second.end()));
          pieces.push_back({from - start, it->second.size() - skip, Piece::memory, buffers_->size() - 1, 0});
          end = it->first + it->second.size();
        }
        ++it;
      }
      Entry e;
      e.kind = Kind::file;
      e.name = stem + "@" + hex(start) + ".bin";
      e.size = end - start;
      e.load_address = start;
      e.loc0 = add_file(std::move(pieces), end - start);
      tree.add_child(0, std::move(e));
    }
    tree.finish();
    description_ = std::string(srec ? "Motorola S-record" : "Intel HEX") + ", " + plural(records, "record", "records") +
                   ", " + plural(entries_.size() - 1, "image", "images") +
                   (entry ? ", entry " + hex(*entry) : std::string()) +
                   (header.empty() ? "" : ", header \"" + display_name(header.substr(0, 64)) + "\"");
  }
};

}  // namespace

bool trx_header(std::span<const std::byte> b) {
  if (b.size() < 28 || le32(b.data()) != 0x30524448) return false;
  const std::uint32_t version = le32(b.data() + 12) >> 16;
  return (version == 1 || version == 2) && le32(b.data() + 4) >= 28;
}

bool sparse_header(std::span<const std::byte> b) {
  return b.size() >= 28 && le32(b.data()) == 0xed26ff3a && le16(b.data() + 4) == 1 && le16(b.data() + 8) >= 28 &&
         le16(b.data() + 10) >= 12;
}

bool dtb_header(std::span<const std::byte> b, std::uint64_t size) {
  if (b.size() < 40 || be32(b.data()) != 0xd00dfeed) return false;
  const std::uint32_t total = be32(b.data() + 4), off_struct = be32(b.data() + 8), version = be32(b.data() + 20);
  return total >= 40 && total <= size && off_struct < total && version >= 16 && version < 64;
}

std::shared_ptr<FileSystem> open_trx(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<Trx>(std::move(src));
  fs->parse(ctx);
  return fs;
}

std::shared_ptr<FileSystem> open_android_sparse(std::shared_ptr<const Source> src, std::string_view name,
                                                const Context &ctx) {
  auto fs = std::make_shared<Sparse>(std::move(src));
  fs->parse(name, ctx);
  return fs;
}

std::shared_ptr<FileSystem> open_dtb(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<DeviceTree>(std::move(src));
  fs->parse(ctx);
  return fs;
}

std::shared_ptr<FileSystem> open_ihex(std::shared_ptr<const Source> src, std::string_view name, const Context &ctx) {
  auto fs = std::make_shared<HexImage>(std::move(src));
  fs->parse(false, name, ctx);
  return fs;
}

std::shared_ptr<FileSystem> open_srec(std::shared_ptr<const Source> src, std::string_view name, const Context &ctx) {
  auto fs = std::make_shared<HexImage>(std::move(src));
  fs->parse(true, name, ctx);
  return fs;
}

}  // namespace revkit::container::detail
