// Lua and LuaJIT chunks carved out of a firmware image or any other file
// (docs/filesystems.md): each "\x1bLua" or "\x1bLJ" whose header parses
// (bytecode.cc: the version, format and sizes) and whose functions walk to
// an end inside the file becomes an entry, named by its version and offset
// ("lua-5.4@0x1a2b0.luac"). LuaJIT prototypes are checked against their
// own sizes too, as their framing alone accepts much random data.
#include "luacarve.hh"

#include "bytecode.hh"
#include "formats.hh"

#include <algorithm>
#include <cstdio>

namespace revkit::container::detail {

namespace {

constexpr std::uint64_t kMaxScan = 256ull << 20;
constexpr std::size_t kMaxChunks = 65536;
constexpr std::uint64_t kMaxUnmeasured = 16ull << 20;

std::optional<std::uint64_t> uleb(std::span<const std::byte> b, std::size_t &p) {
  std::uint64_t v = 0;
  for (unsigned shift = 0; shift < 35; shift += 7) {
    if (p >= b.size()) return std::nullopt;
    const std::uint8_t c = static_cast<std::uint8_t>(b[p++]);
    v |= std::uint64_t{c & 0x7fu} << shift;
    if (!(c & 0x80)) return v;
  }
  return std::nullopt;
}

// LuaJIT's prototypes (lj_bcwrite.c): flags, numparams, framesize, numuv,
// then the counts of GC and numeric constants and of instructions (and,
// unstripped, the debug info's size and lines), the instructions and the
// upvalue slots must fit in the prototype's length.
bool luajit_protos_ok(std::span<const std::byte> b, std::size_t at, const LuaHeader &h, std::size_t len) {
  const bool stripped = (h.luajit_flags & 2) != 0;
  std::size_t p = at + h.size;
  const std::size_t end = at + len;
  int protos = 0;
  while (p < end) {
    auto plen = uleb(b, p);
    if (!plen) return false;
    if (*plen == 0) return protos > 0 && p == end;
    const std::size_t start = p, stop = p + *plen;
    if (stop > end || *plen < 4) return false;
    const std::uint8_t pflags = static_cast<std::uint8_t>(b[p]);
    const std::uint8_t framesize = static_cast<std::uint8_t>(b[p + 2]);
    const std::uint64_t numuv = static_cast<std::uint8_t>(b[p + 3]);
    if (pflags > 0x7f || framesize == 0) return false;
    p += 4;
    auto kgc = uleb(b, p), kn = uleb(b, p), bc = uleb(b, p);
    if (!kgc || !kn || !bc || *bc == 0) return false;
    if (!stripped) {
      auto dbg = uleb(b, p);
      if (!dbg) return false;
      if (*dbg && (!uleb(b, p) || !uleb(b, p))) return false;
    }
    if (p > stop || (stop - p) < *bc * 4 + numuv * 2) return false;
    p = stop;
    ++protos;
    (void)start;
  }
  return false;
}

std::string hex(std::uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

struct Found {
  std::uint64_t offset = 0, length = 0;
  LuaHeader h;
  bool measured = true;
};

std::vector<Found> scan(const Source &src, std::size_t max, const std::function<bool()> &cancelled) {
  const std::uint64_t n = std::min(src.size(), kMaxScan);
  std::vector<Found> out;
  constexpr std::uint64_t kWindow = 8ull << 20, kSlack = 8192;
  std::uint64_t next_free = 0;  // past the last chunk found
  for (std::uint64_t base = 0; base < n && out.size() < max; base += kWindow) {
    if (cancelled && cancelled()) throw Error("cancelled");
    const auto win = src.read_exact(base, std::min(n - base, kWindow + kSlack), "the image");
    const std::span<const std::byte> b(win);
    const std::size_t limit = static_cast<std::size_t>(std::min<std::uint64_t>(b.size(), kWindow));
    std::size_t i = next_free > base ? static_cast<std::size_t>(next_free - base) : 0;
    while (i < limit && out.size() < max) {
      const void *hit = std::memchr(b.data() + i, 0x1b, limit - i);
      if (!hit) break;
      i = static_cast<std::size_t>(static_cast<const std::byte *>(hit) - b.data());
      auto h = lua_header(b, i);
      if (!h) {
        ++i;
        continue;
      }
      Found f;
      f.offset = base + i;
      f.h = *h;
      if (!h->luajit && h->version > 0x54) {
        f.measured = false;  // Lua 5.5: cut at the next chunk below
      } else {
        // Walk it in a span of its own: a MiB, then 64 when that's short.
        std::optional<std::size_t> len;
        for (std::uint64_t span : {1ull << 20, 64ull << 20}) {
          const std::uint64_t take = std::min(span, n - f.offset);
          const auto c = src.read_exact(f.offset, take, "a Lua chunk");
          len = lua_chunk_length(c, 0, *h);
          if (len && h->luajit && !luajit_protos_ok(c, 0, *h, *len)) {
            len.reset();
            break;
          }
          if (len || take < span) break;
        }
        if (!len) {
          ++i;
          continue;
        }
        f.length = *len;
      }
      out.push_back(f);
      next_free = f.offset + (f.measured ? f.length : h->size);
      if (next_free >= base + limit) break;
      i = static_cast<std::size_t>(next_free - base);
    }
  }
  // Unmeasured chunks run to the next one (or the end), at most 16 MiB.
  for (std::size_t k = 0; k < out.size(); ++k) {
    if (out[k].measured) continue;
    const std::uint64_t next = k + 1 < out.size() ? out[k + 1].offset : n;
    out[k].length = std::min(next - out[k].offset, kMaxUnmeasured);
  }
  return out;
}

class LuaChunks final : public SliceFileSystem {
 public:
  using SliceFileSystem::SliceFileSystem;
  void parse(const Context &ctx) {
    format_ = "lua-chunks";
    const auto found = scan(*src_, std::min<std::size_t>(kMaxChunks, ctx.limits.max_entries), ctx.cancelled);
    if (found.empty()) throw Error("no Lua or LuaJIT chunks in it");
    TreeBuilder tree(*this, ctx.limits);
    std::map<std::string, int> versions;
    for (const Found &f : found) {
      Entry e;
      e.kind = Kind::file;
      e.size = e.stored_size = f.length;
      e.loc0 = f.offset;
      e.loc1 = f.length;
      e.content_kind = f.h.content_kind();
      std::string kind = e.content_kind;
      std::replace(kind.begin(), kind.end(), ':', '-');
      e.note = f.h.description() + " at " + hex(f.offset) +
               (f.measured ? "" : "; its length isn't measured (Lua 5.5): cut at the next chunk");
      tree.add_path(kind + "@" + hex(f.offset) + ".luac", e);
      ++versions[e.content_kind];
    }
    tree.finish();
    description_ = "Lua chunks carved out of the file: " + plural(found.size(), "chunk", "chunks") + " (";
    bool first = true;
    for (const auto &[k, c] : versions) {
      description_ += (first ? "" : ", ") + std::to_string(c) + " " + k;
      first = false;
    }
    description_ += ")";
    if (src_->size() > kMaxScan) warn("only the first 256 MiB were searched");
  }
};

}  // namespace

bool lua_chunks_payload(const Source &src, const std::function<bool()> &cancelled) {
  try {
    return !scan(src, 1, cancelled).empty();
  } catch (const Error &) {
    return false;
  }
}

std::shared_ptr<FileSystem> open_lua_chunks(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<LuaChunks>(std::move(src));
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
