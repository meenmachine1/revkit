// The DS compressions (compress.hh). Written from GBATEK's descriptions.
#include "revkit/nds/compress.hh"

#include <algorithm>

namespace revkit::nds {

namespace {

bool Fail(std::string *error, const char *m) {
  if (error) *error = m;
  return false;
}

std::uint32_t Le32(std::span<const std::uint8_t> d, std::size_t o) {
  return d[o] | d[o + 1] << 8 | d[o + 2] << 16 | static_cast<std::uint32_t>(d[o + 3]) << 24;
}

bool Lz(std::span<const std::uint8_t> in, std::size_t pos, bool ext, std::vector<std::uint8_t> &out, std::size_t size,
        std::size_t &consumed, std::string *error) {
  while (out.size() < size) {
    if (pos >= in.size()) return Fail(error, "LZ: truncated");
    std::uint8_t flags = in[pos++];
    for (int bit = 0; bit < 8 && out.size() < size; ++bit, flags <<= 1) {
      if (!(flags & 0x80)) {
        if (pos >= in.size()) return Fail(error, "LZ: truncated literal");
        out.push_back(in[pos++]);
        continue;
      }
      std::size_t len = 0, disp = 0;
      if (!ext) {
        if (pos + 2 > in.size()) return Fail(error, "LZ: truncated pair");
        len = (in[pos] >> 4) + 3;
        disp = (((in[pos] & 0x0f) << 8) | in[pos + 1]) + 1;
        pos += 2;
      } else {
        if (pos >= in.size()) return Fail(error, "LZ: truncated pair");
        const unsigned ind = in[pos] >> 4;
        if (ind == 0) {
          if (pos + 3 > in.size()) return Fail(error, "LZ: truncated pair");
          len = (((in[pos] & 0x0f) << 4) | (in[pos + 1] >> 4)) + 0x11;
          disp = (((in[pos + 1] & 0x0f) << 8) | in[pos + 2]) + 1;
          pos += 3;
        } else if (ind == 1) {
          if (pos + 4 > in.size()) return Fail(error, "LZ: truncated pair");
          len = (((in[pos] & 0x0f) << 12) | (in[pos + 1] << 4) | (in[pos + 2] >> 4)) + 0x111;
          disp = (((in[pos + 2] & 0x0f) << 8) | in[pos + 3]) + 1;
          pos += 4;
        } else {
          if (pos + 2 > in.size()) return Fail(error, "LZ: truncated pair");
          len = ind + 1;
          disp = (((in[pos] & 0x0f) << 8) | in[pos + 1]) + 1;
          pos += 2;
        }
      }
      if (disp > out.size()) return Fail(error, "LZ: reference before the start");
      // A copy may run past the claimed size; the BIOS stops at it.
      len = std::min(len, size - out.size());
      const std::size_t from = out.size() - disp;
      for (std::size_t i = 0; i < len; ++i) out.push_back(out[from + i]);
    }
  }
  consumed = pos;
  return true;
}

bool Rle(std::span<const std::uint8_t> in, std::size_t pos, std::vector<std::uint8_t> &out, std::size_t size,
         std::size_t &consumed, std::string *error) {
  while (out.size() < size) {
    if (pos >= in.size()) return Fail(error, "RLE: truncated");
    const std::uint8_t f = in[pos++];
    if (f & 0x80) {
      std::size_t n = (f & 0x7f) + 3;
      if (pos >= in.size()) return Fail(error, "RLE: truncated run");
      const std::uint8_t b = in[pos++];
      n = std::min(n, size - out.size());
      out.insert(out.end(), n, b);
    } else {
      std::size_t n = (f & 0x7f) + 1;
      if (pos + n > in.size()) return Fail(error, "RLE: truncated literals");
      n = std::min(n, size - out.size());
      out.insert(out.end(), in.begin() + static_cast<std::ptrdiff_t>(pos), in.begin() + static_cast<std::ptrdiff_t>(pos + n));
      pos += (f & 0x7f) + 1;
    }
  }
  consumed = pos;
  return true;
}

// Huffman: after the header, the tree size byte ((n+1)*2 bytes of tree),
// the tree, then 32-bit little-endian words of bits, most significant
// first. Each node byte: bits 0-5 the offset to the children pair
// ((node & ~1) + offset*2 + 2, relative to the tree start), bit 7 the left
// (0) child is data, bit 6 the right (1) child is data.
bool Huffman(std::span<const std::uint8_t> in, std::size_t pos, unsigned bits, std::vector<std::uint8_t> &out,
             std::size_t size, std::size_t &consumed, std::string *error) {
  if (pos >= in.size()) return Fail(error, "Huffman: no tree");
  const std::size_t tree = pos + 1;  // the root node
  const std::size_t tree_len = (static_cast<std::size_t>(in[pos]) + 1) * 2;
  std::size_t data = pos + tree_len;
  if (data > in.size() || tree >= in.size()) return Fail(error, "Huffman: truncated tree");
  const std::size_t tree_end = data;
  std::size_t node = tree;  // offset of the current node byte
  std::uint8_t acc = 0;
  unsigned have = 0;
  while (out.size() < size) {
    if (data + 4 > in.size()) return Fail(error, "Huffman: truncated data");
    const std::uint32_t word = Le32(in, data);
    data += 4;
    for (int b = 31; b >= 0 && out.size() < size; --b) {
      const unsigned dir = (word >> b) & 1;
      const std::uint8_t n = in[node];
      // Children pair of node at `node`: aligned down to the pair start.
      const std::size_t rel = node - (tree - 1);  // offset from the size byte
      const std::size_t child = (tree - 1) + ((rel & ~std::size_t{1}) + (n & 0x3f) * 2 + 2) + dir;
      if (child >= tree_end) return Fail(error, "Huffman: node out of the tree");
      const bool leaf = dir ? (n & 0x40) : (n & 0x80);
      if (!leaf) {
        node = child;
        continue;
      }
      const std::uint8_t value = in[child];
      node = tree;
      if (bits == 8) {
        out.push_back(value);
      } else {
        acc |= static_cast<std::uint8_t>((value & 0x0f) << have);
        have += 4;
        if (have == 8) {
          out.push_back(acc);
          acc = 0;
          have = 0;
        }
      }
    }
  }
  consumed = data;
  return true;
}

}  // namespace

const char *to_string(Compression c) {
  switch (c) {
    case Compression::none: return "none";
    case Compression::lz10: return "LZ10";
    case Compression::lz11: return "LZ11";
    case Compression::huffman4: return "Huffman (4-bit)";
    case Compression::huffman8: return "Huffman (8-bit)";
    case Compression::rle: return "RLE";
  }
  return "?";
}

std::optional<CompressionHeader> compression_header(std::span<const std::uint8_t> d) {
  if (d.size() < 4) return std::nullopt;
  CompressionHeader h;
  switch (d[0]) {
    case 0x10: h.type = Compression::lz10; break;
    case 0x11: h.type = Compression::lz11; break;
    case 0x24: h.type = Compression::huffman4; break;
    case 0x28: h.type = Compression::huffman8; break;
    case 0x30: h.type = Compression::rle; break;
    default: return std::nullopt;
  }
  h.size = d[1] | d[2] << 8 | d[3] << 16;
  if (h.size == 0) {
    // A zero 24-bit size: a 32-bit size follows (larger files).
    if (d.size() < 8) return std::nullopt;
    h.size = Le32(d, 4);
    h.header_size = 8;
    if (h.size == 0) return std::nullopt;
  }
  return h;
}

std::optional<std::vector<std::uint8_t>> decompress(std::span<const std::uint8_t> data, std::size_t max_out,
                                                    std::string *error, std::size_t *consumed) {
  std::optional<CompressionHeader> h = compression_header(data);
  if (!h) {
    Fail(error, "not LZ10, LZ11, Huffman or RLE data");
    return std::nullopt;
  }
  if (h->size > max_out) {
    Fail(error, "the decompressed size is over the limit");
    return std::nullopt;
  }
  std::vector<std::uint8_t> out;
  out.reserve(std::min<std::size_t>(h->size, 1u << 24));
  std::size_t used = 0;
  bool ok = false;
  switch (h->type) {
    case Compression::lz10: ok = Lz(data, h->header_size, false, out, h->size, used, error); break;
    case Compression::lz11: ok = Lz(data, h->header_size, true, out, h->size, used, error); break;
    case Compression::huffman4: ok = Huffman(data, h->header_size, 4, out, h->size, used, error); break;
    case Compression::huffman8: ok = Huffman(data, h->header_size, 8, out, h->size, used, error); break;
    case Compression::rle: ok = Rle(data, h->header_size, out, h->size, used, error); break;
    case Compression::none: break;
  }
  if (!ok) return std::nullopt;
  if (consumed) *consumed = used;
  return out;
}

bool looks_compressed(std::span<const std::uint8_t> data, std::size_t max_out) {
  std::optional<CompressionHeader> h = compression_header(data);
  if (!h || data.size() < 8) return false;
  if (h->size <= data.size() / 2 && h->type != Compression::rle) return false;
  if (h->size > max_out || h->size / 64 > data.size()) return false;
  std::size_t used = 0;
  std::optional<std::vector<std::uint8_t>> out = decompress(data, max_out, nullptr, &used);
  if (!out) return false;
  // The stream should end the file, give or take alignment padding.
  return used <= data.size() && data.size() - used < 32;
}

std::optional<BlzFooter> blz_footer(std::span<const std::uint8_t> d) {
  if (d.size() < 8) return std::nullopt;
  BlzFooter f;
  const std::uint32_t a = Le32(d, d.size() - 8);
  f.compressed_length = a & 0xffffff;
  f.header_length = a >> 24;
  f.extra = Le32(d, d.size() - 4);
  if (f.header_length < 8 || f.header_length > f.compressed_length || f.compressed_length > d.size()) return std::nullopt;
  return f;
}

std::optional<std::vector<std::uint8_t>> blz_decompress(std::span<const std::uint8_t> d, std::size_t max_out,
                                                        std::string *error) {
  std::optional<BlzFooter> f = blz_footer(d);
  if (!f) {
    Fail(error, "BLZ: no valid footer");
    return std::nullopt;
  }
  const std::size_t total = d.size() + f->extra;
  if (total > max_out || total < d.size()) {
    Fail(error, "BLZ: the decompressed size is over the limit");
    return std::nullopt;
  }
  // A flag byte and eight 2-byte pairs (17 bytes) make at most 144: more
  // than that from the compressed area is a footer no stream fills, refused
  // before the output is allocated (bug scrub part 3).
  if (f->extra > 8ull * f->compressed_length + 64) {
    Fail(error, "BLZ: the footer's size is more than its stream can make");
    return std::nullopt;
  }
  std::vector<std::uint8_t> out(total, 0);
  // The part before the compressed area is stored as is.
  const std::size_t plain = d.size() - f->compressed_length;
  std::copy(d.begin(), d.begin() + static_cast<std::ptrdiff_t>(plain), out.begin());
  std::size_t src = d.size() - f->header_length;  // exclusive, read backward
  std::size_t dst = total;                        // exclusive, written backward
  while (src > plain) {
    std::uint8_t flags = d[--src];
    for (int bit = 0; bit < 8 && src > plain; ++bit, flags <<= 1) {
      if (!(flags & 0x80)) {
        if (dst <= plain) {
          Fail(error, "BLZ: output overruns the stored part");
          return std::nullopt;
        }
        out[--dst] = d[--src];
        continue;
      }
      if (src < plain + 2) {
        Fail(error, "BLZ: truncated pair");
        return std::nullopt;
      }
      const unsigned hi = d[--src];
      const unsigned lo = d[--src];
      const std::size_t len = (hi >> 4) + 3;
      const std::size_t disp = (((hi & 0x0f) << 8) | lo) + 3;
      if (dst < plain + len) {
        Fail(error, "BLZ: output overruns the stored part");
        return std::nullopt;
      }
      for (std::size_t i = 0; i < len; ++i) {
        --dst;
        if (dst + disp >= total) {
          Fail(error, "BLZ: reference past the end");
          return std::nullopt;
        }
        out[dst] = out[dst + disp];
      }
    }
  }
  if (dst != plain) {
    // A short stream leaves a gap: the footer and the data disagree.
    Fail(error, "BLZ: the stream doesn't fill the output");
    return std::nullopt;
  }
  return out;
}

}  // namespace revkit::nds
