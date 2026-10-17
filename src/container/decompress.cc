// The codecs: zlib (deflate, zlib, gzip), libbz2, liblzma (xz, .lzma),
// libzstd, and LZ4 and LZO1X decoded here. Streams go into a Sink, which
// applies the limits; blocks into a buffer of the expected size.
#include "revkit/container/decompress.hh"

#include <bzlib.h>
#include <lzma.h>
#include <zlib.h>
#include <zstd.h>
#include <zstd_errors.h>

#include <algorithm>
#include <cstring>

namespace revkit::container {

namespace {

constexpr std::size_t kChunk = 256 * 1024;
// What a decoder may allocate for its dictionary or window: xz -9 and zstd
// --long=27 fit; anything asking for more is refused.
constexpr std::uint64_t kDecoderMemory = 256ull << 20;

// Reads a range of a Source in order.
class Input {
 public:
  Input(const Source &src, std::uint64_t offset, std::uint64_t length) : src_(src), pos_(offset) {
    if (offset > src.size()) throw Error("compressed data lies outside its container");
    end_ = offset + std::min(length, src.size() - offset);
  }
  // The next piece (empty at the end).
  std::span<const std::byte> next(std::size_t max = kChunk) {
    const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(max, end_ - pos_));
    buf_.resize(n);
    const std::size_t got = n ? src_.read(pos_, buf_) : 0;
    buf_.resize(got);
    pos_ += got;
    consumed_ += got;
    return buf_;
  }
  // Exactly n bytes, or Error.
  std::vector<std::byte> take(std::size_t n, const char *what) {
    if (n > end_ - pos_) throw Error(std::string("truncated ") + what);
    std::vector<std::byte> out(n);
    if (src_.read(pos_, out) != n) throw Error(std::string("truncated ") + what);
    pos_ += n;
    consumed_ += n;
    return out;
  }
  bool done() const { return pos_ >= end_; }
  std::uint64_t remaining() const { return end_ - pos_; }
  std::uint64_t consumed() const { return consumed_; }
  // Puts back the last n bytes of the piece next() returned.
  void unread(std::size_t n) {
    pos_ -= n;
    consumed_ -= n;
  }

 private:
  const Source &src_;
  std::uint64_t pos_, end_;
  std::uint64_t consumed_ = 0;
  std::vector<std::byte> buf_;
};

std::uint32_t le32(const std::byte *p) {
  return static_cast<std::uint32_t>(p[0]) | static_cast<std::uint32_t>(p[1]) << 8 |
         static_cast<std::uint32_t>(p[2]) << 16 | static_cast<std::uint32_t>(p[3]) << 24;
}

// ---- zlib ------------------------------------------------------------------------

void inflate_stream(Codec codec, Input &in, Sink &out, const Context &ctx) {
  const int bits = codec == Codec::deflate ? -15 : codec == Codec::zlib ? 15 : 31;
  z_stream z{};
  if (inflateInit2(&z, bits) != Z_OK) throw Error("zlib: cannot start");
  struct Guard {
    z_stream &z;
    ~Guard() { inflateEnd(&z); }
  } guard{z};
  std::vector<std::byte> obuf(kChunk);
  std::span<const std::byte> piece;
  bool ended = false;
  while (!out.full()) {
    ctx.check_cancelled();
    if (z.avail_in == 0) {
      piece = in.next();
      if (piece.empty()) break;
      z.next_in = reinterpret_cast<Bytef *>(const_cast<std::byte *>(piece.data()));
      z.avail_in = static_cast<uInt>(piece.size());
    }
    z.next_out = reinterpret_cast<Bytef *>(obuf.data());
    z.avail_out = static_cast<uInt>(obuf.size());
    const int r = inflate(&z, Z_NO_FLUSH);
    out.append(std::span(obuf).first(obuf.size() - z.avail_out));
    out.consumed(in.consumed() - z.avail_in);
    if (r == Z_STREAM_END) {
      ended = true;
      if (codec != Codec::gzip) break;
      // Another gzip member may follow; anything else is trailing data.
      if (z.avail_in == 0) {
        piece = in.next();
        z.next_in = reinterpret_cast<Bytef *>(const_cast<std::byte *>(piece.data()));
        z.avail_in = static_cast<uInt>(piece.size());
      }
      if (z.avail_in >= 2 && z.next_in[0] == 0x1f && z.next_in[1] == 0x8b) {
        inflateReset(&z);
        ended = false;
        continue;
      }
      break;
    }
    if (r == Z_BUF_ERROR && z.avail_in == 0) continue;
    if (r != Z_OK) throw Error(std::string("corrupt deflate data") + (z.msg ? std::string(": ") + z.msg : ""));
  }
  if (!ended && !out.full()) throw Error("truncated deflate data");
}

// ---- bzip2 -----------------------------------------------------------------------

void bzip2_stream(Input &in, Sink &out, const Context &ctx) {
  bz_stream s{};
  if (BZ2_bzDecompressInit(&s, 0, 0) != BZ_OK) throw Error("bzip2: cannot start");
  bool live = true;
  struct Guard {
    bz_stream &s;
    bool &live;
    ~Guard() {
      if (live) BZ2_bzDecompressEnd(&s);
    }
  } guard{s, live};
  std::vector<std::byte> obuf(kChunk);
  std::span<const std::byte> piece;
  bool ended = false;
  while (!out.full()) {
    ctx.check_cancelled();
    if (s.avail_in == 0) {
      piece = in.next();
      if (piece.empty()) break;
      s.next_in = reinterpret_cast<char *>(const_cast<std::byte *>(piece.data()));
      s.avail_in = static_cast<unsigned>(piece.size());
    }
    s.next_out = reinterpret_cast<char *>(obuf.data());
    s.avail_out = static_cast<unsigned>(obuf.size());
    const int r = BZ2_bzDecompress(&s);
    out.append(std::span(obuf).first(obuf.size() - s.avail_out));
    out.consumed(in.consumed() - s.avail_in);
    if (r == BZ_STREAM_END) {
      ended = true;
      if (s.avail_in == 0) {
        piece = in.next();
        s.next_in = reinterpret_cast<char *>(const_cast<std::byte *>(piece.data()));
        s.avail_in = static_cast<unsigned>(piece.size());
      }
      if (s.avail_in >= 3 && std::memcmp(s.next_in, "BZh", 3) == 0) {
        char *next = s.next_in;
        unsigned avail = s.avail_in;
        BZ2_bzDecompressEnd(&s);
        live = false;
        s = bz_stream{};
        if (BZ2_bzDecompressInit(&s, 0, 0) != BZ_OK) throw Error("bzip2: cannot start");
        live = true;
        s.next_in = next;
        s.avail_in = avail;
        ended = false;
        continue;
      }
      break;
    }
    if (r != BZ_OK) throw Error("corrupt bzip2 data");
  }
  if (!ended && !out.full()) throw Error("truncated bzip2 data");
}

// ---- xz and .lzma ----------------------------------------------------------------

void lzma_stream_decode(Codec codec, Input &in, Sink &out, const Context &ctx) {
  lzma_stream s = LZMA_STREAM_INIT;
  const lzma_ret init = codec == Codec::xz ? lzma_stream_decoder(&s, kDecoderMemory, LZMA_CONCATENATED)
                                           : lzma_alone_decoder(&s, kDecoderMemory);
  if (init != LZMA_OK) throw Error("liblzma: cannot start");
  struct Guard {
    lzma_stream &s;
    ~Guard() { lzma_end(&s); }
  } guard{s};
  std::vector<std::byte> obuf(kChunk);
  std::span<const std::byte> piece;
  lzma_action action = LZMA_RUN;
  while (!out.full()) {
    ctx.check_cancelled();
    if (s.avail_in == 0 && action == LZMA_RUN) {
      piece = in.next();
      s.next_in = reinterpret_cast<const uint8_t *>(piece.data());
      s.avail_in = piece.size();
      if (piece.empty()) action = LZMA_FINISH;
    }
    s.next_out = reinterpret_cast<uint8_t *>(obuf.data());
    s.avail_out = obuf.size();
    const lzma_ret r = lzma_code(&s, action);
    out.append(std::span(obuf).first(obuf.size() - s.avail_out));
    out.consumed(in.consumed() - s.avail_in);
    if (r == LZMA_STREAM_END) return;
    if (r == LZMA_MEMLIMIT_ERROR) throw LimitError("the compressed data asks for a dictionary over 256 MiB");
    if (r == LZMA_BUF_ERROR && action == LZMA_FINISH) throw Error("truncated xz/lzma data");
    if (r != LZMA_OK) throw Error(std::string("corrupt ") + (codec == Codec::xz ? "xz" : "lzma") + " data");
  }
}

// ---- zstd ------------------------------------------------------------------------

void zstd_stream(Input &in, Sink &out, const Context &ctx) {
  ZSTD_DCtx *d = ZSTD_createDCtx();
  if (!d) throw Error("zstd: cannot start");
  struct Guard {
    ZSTD_DCtx *d;
    ~Guard() { ZSTD_freeDCtx(d); }
  } guard{d};
  ZSTD_DCtx_setParameter(d, ZSTD_d_windowLogMax, 27);
  std::vector<std::byte> obuf(kChunk);
  std::span<const std::byte> piece;
  ZSTD_inBuffer ib{nullptr, 0, 0};
  std::size_t last = 1;  // nonzero: a frame isn't complete
  bool any = false;
  while (!out.full()) {
    ctx.check_cancelled();
    if (ib.pos == ib.size) {
      piece = in.next();
      if (piece.empty()) break;
      ib = {piece.data(), piece.size(), 0};
      any = true;
    }
    ZSTD_outBuffer ob{obuf.data(), obuf.size(), 0};
    last = ZSTD_decompressStream(d, &ob, &ib);
    if (ZSTD_isError(last)) {
      if (ZSTD_getErrorCode(last) == ZSTD_error_frameParameter_windowTooLarge)
        throw LimitError("the zstd data asks for a window over 128 MiB");
      throw Error(std::string("corrupt zstd data: ") + ZSTD_getErrorName(last));
    }
    out.append(std::span(obuf).first(ob.pos));
    out.consumed(in.consumed() - (ib.size - ib.pos));
  }
  if (!out.full() && (last != 0 || !any)) throw Error("truncated zstd data");
}

// ---- LZ4 -------------------------------------------------------------------------

void lz4_frame_stream(Input &in, Sink &out, const Context &ctx) {
  bool any = false;
  std::vector<std::byte> window;  // the last 64 KiB of output, then the block decoded
  while (!out.full() && !in.done()) {
    ctx.check_cancelled();
    if (in.remaining() < 4) break;
    const std::uint32_t magic = le32(in.take(4, "LZ4 frame").data());
    if ((magic & 0xfffffff0u) == 0x184d2a50u) {  // skippable frame
      const std::uint32_t n = le32(in.take(4, "LZ4 frame").data());
      if (n > in.remaining()) throw Error("truncated LZ4 skippable frame");
      for (std::uint64_t left = n; left;) {
        const auto piece = in.next(static_cast<std::size_t>(std::min<std::uint64_t>(left, kChunk)));
        if (piece.empty()) throw Error("truncated LZ4 skippable frame");
        left -= piece.size();
      }
      continue;
    }
    if (magic == 0x184c2102u) {  // legacy (lz4 -l, the kernel's): independent 8 MiB blocks
      any = true;
      while (!out.full() && in.remaining() >= 4) {
        const auto sz = in.take(4, "LZ4 block");
        const std::uint32_t n = le32(sz.data());
        if (n == 0x184c2102u) continue;  // another legacy frame
        if (n > (8u << 20) + (8u << 20) / 255 + 16 || n > in.remaining()) {
          in.unread(4);  // not a block: whatever follows (the kernel's size word)
          return;
        }
        auto block = in.take(n, "LZ4 block");
        std::vector<std::byte> dec;
        lz4_decode_block(block, dec, 8u << 20);
        out.append(dec);
        out.consumed(in.consumed());
      }
      return;
    }
    if (magic != 0x184d2204u) {
      if (any) return;  // trailing data
      throw Error("not LZ4 data");
    }
    any = true;
    const auto fd = in.take(2, "LZ4 frame header");
    const auto flg = static_cast<std::uint8_t>(fd[0]), bd = static_cast<std::uint8_t>(fd[1]);
    if ((flg >> 6) != 1) throw Error("unsupported LZ4 frame version");
    const bool independent = flg & 0x20, block_checksum = flg & 0x10, content_size = flg & 0x08,
               content_checksum = flg & 0x04, dict_id = flg & 0x01;
    const unsigned bsid = (bd >> 4) & 7;
    if (bsid < 4) throw Error("bad LZ4 block size");
    const std::size_t block_max = std::size_t{1} << (8 + 2 * bsid);
    if (content_size) in.take(8, "LZ4 frame header");
    if (dict_id) throw Error("LZ4 frames with a dictionary are not supported");
    in.take(1, "LZ4 frame header");  // header checksum
    window.clear();
    for (;;) {
      ctx.check_cancelled();
      const std::uint32_t word = le32(in.take(4, "LZ4 block").data());
      if (word == 0) break;  // end mark
      const bool raw = word & 0x80000000u;
      const std::uint32_t n = word & 0x7fffffffu;
      if (n > block_max) throw Error("an LZ4 block is larger than the frame's block size");
      auto block = in.take(n, "LZ4 block");
      if (block_checksum) in.take(4, "LZ4 block checksum");
      const std::size_t before = window.size();
      if (raw) {
        window.insert(window.end(), block.begin(), block.end());
      } else {
        lz4_decode_block(block, window, before + block_max);
      }
      out.append(std::span(window).subspan(before));
      out.consumed(in.consumed());
      if (out.full()) return;
      if (independent) {
        window.clear();
      } else if (window.size() > 65536) {
        window.erase(window.begin(), window.end() - 65536);
      }
    }
    if (content_checksum) in.take(4, "LZ4 content checksum");
  }
  if (!any) throw Error("not LZ4 data");
}

}  // namespace

std::string_view name(Codec c) {
  switch (c) {
    case Codec::deflate: return "deflate";
    case Codec::zlib: return "zlib";
    case Codec::gzip: return "gzip";
    case Codec::bzip2: return "bzip2";
    case Codec::xz: return "xz";
    case Codec::lzma_alone: return "lzma";
    case Codec::zstd: return "zstd";
    case Codec::lz4_frame: return "lz4";
    case Codec::lz4_block: return "lz4-block";
    case Codec::lzo1x: return "lzo";
  }
  return "?";
}

void lz4_decode_block(std::span<const std::byte> in, std::vector<std::byte> &out, std::size_t max_out) {
  std::size_t ip = 0;
  const std::size_t n = in.size();
  auto byte = [&](std::size_t i) { return static_cast<std::uint8_t>(in[i]); };
  auto length = [&](std::size_t base) {
    std::size_t len = base;
    if (base == 15) {
      for (;;) {
        if (ip >= n) throw Error("truncated LZ4 block");
        const std::uint8_t b = byte(ip++);
        len += b;
        if (len > max_out) throw Error("an LZ4 block decodes past its size");
        if (b != 255) break;
      }
    }
    return len;
  };
  if (n == 0) throw Error("empty LZ4 block");
  for (;;) {
    if (ip >= n) throw Error("truncated LZ4 block");
    const std::uint8_t token = byte(ip++);
    const std::size_t lit = length(token >> 4);
    if (lit > n - ip) throw Error("truncated LZ4 literals");
    if (out.size() + lit > max_out) throw Error("an LZ4 block decodes past its size");
    out.insert(out.end(), in.begin() + static_cast<std::ptrdiff_t>(ip),
               in.begin() + static_cast<std::ptrdiff_t>(ip + lit));
    ip += lit;
    if (ip == n) return;  // the last sequence has literals only
    if (n - ip < 2) throw Error("truncated LZ4 match");
    const std::size_t offset = byte(ip) | (std::size_t{byte(ip + 1)} << 8);
    ip += 2;
    if (offset == 0 || offset > out.size()) throw Error("an LZ4 match reaches before the start");
    const std::size_t len = length(token & 15) + 4;
    if (out.size() + len > max_out) throw Error("an LZ4 block decodes past its size");
    std::size_t from = out.size() - offset;
    out.reserve(out.size() + len);
    for (std::size_t k = 0; k < len; ++k) out.push_back(out[from + k]);
  }
}

// LZO1X as the Linux kernel's lzo.rst describes the format.
void lzo1x_decode(std::span<const std::byte> in, std::vector<std::byte> &out, std::size_t max_out) {
  std::size_t ip = 0;
  const std::size_t n = in.size();
  const std::size_t start = out.size();
  auto need = [&](std::size_t k) {
    if (n - ip < k) throw Error("truncated LZO data");
  };
  auto byte = [&]() {
    need(1);
    return static_cast<std::uint8_t>(in[ip++]);
  };
  auto literals = [&](std::size_t k) {
    need(k);
    if (out.size() - start + k > max_out) throw Error("LZO data decodes past its size");
    out.insert(out.end(), in.begin() + static_cast<std::ptrdiff_t>(ip),
               in.begin() + static_cast<std::ptrdiff_t>(ip + k));
    ip += k;
  };
  auto copy = [&](std::size_t distance, std::size_t len) {
    if (distance == 0 || distance > out.size() - start) throw Error("an LZO match reaches before the start");
    if (out.size() - start + len > max_out) throw Error("LZO data decodes past its size");
    const std::size_t from = out.size() - distance;
    out.reserve(out.size() + len);
    for (std::size_t k = 0; k < len; ++k) out.push_back(out[from + k]);
  };
  // A length continued in zero bytes (255 each) and a last nonzero one.
  auto extended = [&](std::size_t base) {
    std::size_t zeros = 0;
    std::uint8_t b;
    while ((b = byte()) == 0) {
      if (++zeros > max_out / 255 + 1) throw Error("LZO length overflows");
    }
    return base + zeros * 255 + b;
  };
  unsigned state = 0;
  std::uint8_t t = byte();
  if (t > 17) {
    const std::size_t k = t - 17u;
    literals(k);
    state = k < 4 ? static_cast<unsigned>(k) : 4;
    t = byte();
  }
  for (;;) {
    unsigned s;
    if (t < 16) {
      if (state == 0) {
        const std::size_t len = 3 + (t ? t : extended(15));
        literals(len);
        state = 4;
        t = byte();
        continue;
      }
      const std::uint8_t h = byte();
      s = t & 3;
      if (state == 4)
        copy((std::size_t{h} << 2) + ((t >> 2) & 3) + 2049, 3);
      else
        copy((std::size_t{h} << 2) + ((t >> 2) & 3) + 1, 2);
    } else if (t < 32) {
      const std::size_t len = 2 + ((t & 7) ? (t & 7) : extended(7));
      need(2);
      const std::size_t le = static_cast<std::uint8_t>(in[ip]) | (std::size_t{static_cast<std::uint8_t>(in[ip + 1])} << 8);
      ip += 2;
      const std::size_t distance = 16384 + (std::size_t{(t >> 3) & 1u} << 14) + (le >> 2);
      if (distance == 16384) return;  // end of stream
      s = le & 3;
      copy(distance, len);
    } else if (t < 64) {
      const std::size_t len = 2 + ((t & 31) ? (t & 31) : extended(31));
      need(2);
      const std::size_t le = static_cast<std::uint8_t>(in[ip]) | (std::size_t{static_cast<std::uint8_t>(in[ip + 1])} << 8);
      ip += 2;
      s = le & 3;
      copy((le >> 2) + 1, len);
    } else {
      const std::uint8_t h = byte();
      s = t & 3;
      copy((std::size_t{h} << 3) + ((t >> 2) & 7) + 1, (t >> 5) + 1u);
    }
    if (s) literals(s);
    state = s;
    t = byte();
  }
}

void decompress(Codec codec, const Source &src, std::uint64_t offset, std::uint64_t length, Sink &out,
                const Context &ctx) {
  Input in(src, offset, length);
  switch (codec) {
    case Codec::deflate:
    case Codec::zlib:
    case Codec::gzip: inflate_stream(codec, in, out, ctx); return;
    case Codec::bzip2: bzip2_stream(in, out, ctx); return;
    case Codec::xz:
    case Codec::lzma_alone: lzma_stream_decode(codec, in, out, ctx); return;
    case Codec::zstd: zstd_stream(in, out, ctx); return;
    case Codec::lz4_frame: lz4_frame_stream(in, out, ctx); return;
    case Codec::lz4_block:
    case Codec::lzo1x: {
      if (in.remaining() > (64u << 20)) throw LimitError("a raw LZ4/LZO block over 64 MiB");
      auto data = in.take(static_cast<std::size_t>(in.remaining()), "block");
      std::vector<std::byte> dec;
      const std::size_t max = static_cast<std::size_t>(ctx.limits.max_file_bytes);
      if (codec == Codec::lz4_block)
        lz4_decode_block(data, dec, max);
      else
        lzo1x_decode(data, dec, max);
      out.consumed(data.size());
      out.append(dec);
      return;
    }
  }
}

std::size_t decompress_block(Codec codec, std::span<const std::byte> in, std::span<std::byte> out) {
  switch (codec) {
    case Codec::deflate:
    case Codec::zlib:
    case Codec::gzip: {
      z_stream z{};
      if (inflateInit2(&z, codec == Codec::deflate ? -15 : codec == Codec::zlib ? 15 : 31) != Z_OK)
        throw Error("zlib: cannot start");
      z.next_in = reinterpret_cast<Bytef *>(const_cast<std::byte *>(in.data()));
      z.avail_in = static_cast<uInt>(in.size());
      z.next_out = reinterpret_cast<Bytef *>(out.data());
      z.avail_out = static_cast<uInt>(out.size());
      const int r = inflate(&z, Z_FINISH);
      const std::size_t n = out.size() - z.avail_out;
      inflateEnd(&z);
      if (r != Z_STREAM_END) throw Error(r == Z_BUF_ERROR && n == out.size() ? "a block decompresses past its size"
                                                                             : "corrupt zlib block");
      return n;
    }
    case Codec::bzip2: {
      unsigned n = static_cast<unsigned>(out.size());
      const int r = BZ2_bzBuffToBuffDecompress(reinterpret_cast<char *>(out.data()), &n,
                                               reinterpret_cast<char *>(const_cast<std::byte *>(in.data())),
                                               static_cast<unsigned>(in.size()), 0, 0);
      if (r != BZ_OK) throw Error(r == BZ_OUTBUFF_FULL ? "a block decompresses past its size" : "corrupt bzip2 block");
      return n;
    }
    case Codec::xz:
    case Codec::lzma_alone: {
      lzma_stream s = LZMA_STREAM_INIT;
      const lzma_ret init = codec == Codec::xz ? lzma_stream_decoder(&s, kDecoderMemory, 0)
                                               : lzma_alone_decoder(&s, kDecoderMemory);
      if (init != LZMA_OK) throw Error("liblzma: cannot start");
      s.next_in = reinterpret_cast<const uint8_t *>(in.data());
      s.avail_in = in.size();
      s.next_out = reinterpret_cast<uint8_t *>(out.data());
      s.avail_out = out.size();
      const lzma_ret r = lzma_code(&s, LZMA_FINISH);
      const std::size_t n = out.size() - s.avail_out;
      lzma_end(&s);
      if (r == LZMA_MEMLIMIT_ERROR) throw LimitError("a block asks for a dictionary over 256 MiB");
      if (r != LZMA_STREAM_END) {
        // .lzma blocks with a known size and no end marker stop when full.
        if (codec == Codec::lzma_alone && r == LZMA_OK && n == out.size()) return n;
        throw Error(n == out.size() ? "a block decompresses past its size" : "corrupt xz/lzma block");
      }
      return n;
    }
    case Codec::zstd: {
      const std::size_t r = ZSTD_decompress(out.data(), out.size(), in.data(), in.size());
      if (ZSTD_isError(r)) throw Error(std::string("corrupt zstd block: ") + ZSTD_getErrorName(r));
      return r;
    }
    case Codec::lz4_frame:
    case Codec::lz4_block:
    case Codec::lzo1x: {
      std::vector<std::byte> dec;
      if (codec == Codec::lzo1x) {
        lzo1x_decode(in, dec, out.size());
      } else if (codec == Codec::lz4_block) {
        lz4_decode_block(in, dec, out.size());
      } else {
        throw Error("LZ4 frames are not blocks");
      }
      if (!dec.empty()) std::memcpy(out.data(), dec.data(), dec.size());
      return dec.size();
    }
  }
  throw Error("unknown codec");
}

}  // namespace revkit::container
