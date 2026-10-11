// zip (and jar, apk, and anything else in zip's clothing): the central
// directory, zip64, Unix modes and symlinks; stored, deflate, bzip2, zstd
// and xz members. Members whose data overlaps another's (the "overlapping
// files" zip bomb) are listed but refused.
#include "formats.hh"

#include <algorithm>
#include <ctime>

namespace revkit::container::detail {
namespace {

constexpr std::uint32_t kEocd = 0x06054b50, kCentral = 0x02014b50, kLocal = 0x04034b50, kZip64Eocd = 0x06064b50,
                        kZip64Locator = 0x07064b50;

std::int64_t dos_time(std::uint16_t date, std::uint16_t time) {
  std::tm tm{};
  tm.tm_year = ((date >> 9) & 0x7f) + 80;
  tm.tm_mon = std::max(0, ((date >> 5) & 0x0f) - 1);
  tm.tm_mday = std::max(1, date & 0x1f);
  tm.tm_hour = (time >> 11) & 0x1f;
  tm.tm_min = (time >> 5) & 0x3f;
  tm.tm_sec = (time & 0x1f) * 2;
  return static_cast<std::int64_t>(timegm(&tm));
}

class Zip final : public SliceFileSystem {
 public:
  using SliceFileSystem::SliceFileSystem;

  void parse(std::string_view, const Context &ctx) {
    format_ = "zip";
    const std::uint64_t size = src_->size();
    // The end of central directory record: within the last 64 KiB + 22.
    const std::uint64_t tail = std::min<std::uint64_t>(size, 65557);
    const auto t = src_->read_exact(size - tail, tail, "the end of the zip");
    std::optional<std::uint64_t> eocd;
    for (std::size_t i = t.size() >= 22 ? t.size() - 22 + 1 : 0; i-- > 0;) {
      if (le32(t.data() + i) != kEocd) continue;
      const std::uint16_t comment = le16(t.data() + i + 20);
      if (i + 22 + comment <= t.size()) {
        eocd = size - tail + i;
        break;
      }
    }
    if (!eocd) throw Error("no zip central directory (a truncated or streamed zip)");
    const auto e = src_->read_exact(*eocd, 22, "the zip's end record");
    Buf eb(e, "the zip's end record");
    std::uint64_t count = eb.l16(10), cd_size = eb.l32(12), cd_offset = eb.l32(16);
    if (eb.l16(4) != 0 || eb.l16(6) != 0) warn("a multi-disk zip: only this part is listed");
    if ((count == 0xffff || cd_size == 0xffffffff || cd_offset == 0xffffffff) && *eocd >= 20) {
      const auto l = src_->read_exact(*eocd - 20, 20, "the zip64 locator");
      if (le32(l.data()) == kZip64Locator) {
        const std::uint64_t at = le64(l.data() + 8);
        const auto z = src_->read_exact(at, 56, "the zip64 end record");
        if (le32(z.data()) != kZip64Eocd) throw Error("the zip64 end record is missing");
        count = le64(z.data() + 32);
        cd_size = le64(z.data() + 40);
        cd_offset = le64(z.data() + 48);
      }
    }
    // Data before the archive (a self-extractor's stub) shifts every
    // offset by its size.
    std::uint64_t shift = 0;
    if (cd_size <= *eocd && *eocd - cd_size > cd_offset) shift = *eocd - cd_size - cd_offset;
    if (cd_offset + shift > size || cd_size > size - (cd_offset + shift))
      throw Error("the zip's central directory lies outside the file");
    if (count > ctx.limits.max_entries)
      throw LimitError("the zip lists " + std::to_string(count) + " members, more than the limit of " +
                       std::to_string(ctx.limits.max_entries));
    if (cd_size > (512ull << 20)) throw LimitError("the zip's central directory is over 512 MiB");
    const auto cd = src_->read_exact(cd_offset + shift, cd_size, "the zip's central directory");
    Buf b(cd, "the zip's central directory");
    TreeBuilder tree(*this, ctx.limits);
    struct Span {
      std::uint64_t start, end;
      std::uint32_t entry;
    };
    std::vector<Span> spans;
    std::size_t p = 0;
    for (std::uint64_t n = 0; n < count; ++n) {
      ctx.check_cancelled();
      if (b.l32(p) != kCentral) {
        warn("the central directory ends early: " + std::to_string(n) + " of " +
                            std::to_string(count) + " members listed");
        break;
      }
      const std::uint16_t made_by = b.l16(p + 4), flags = b.l16(p + 8), method = b.l16(p + 10);
      const std::uint16_t mtime = b.l16(p + 12), mdate = b.l16(p + 14);
      std::uint64_t csize = b.l32(p + 20), usize = b.l32(p + 24);
      const std::uint16_t nlen = b.l16(p + 28), xlen = b.l16(p + 30), clen = b.l16(p + 32);
      const std::uint32_t ext_attr = b.l32(p + 38);
      std::uint64_t local = b.l32(p + 42);
      std::string name = b.str(p + 46, nlen);
      // Zip64 sizes and offset, for the fields that overflowed.
      {
        Buf x(b.span(p + 46 + nlen, xlen), "a zip extra field");
        std::size_t q = 0;
        while (q + 4 <= xlen) {
          const std::uint16_t id = x.l16(q), len = x.l16(q + 2);
          if (q + 4 + len > xlen) break;
          if (id == 0x0001) {
            std::size_t r = q + 4;
            auto next = [&](std::uint64_t &v) {
              if (r + 8 <= q + 4u + len) {
                v = x.l64(r);
                r += 8;
              }
            };
            if (usize == 0xffffffff) next(usize);
            if (csize == 0xffffffff) next(csize);
            if (local == 0xffffffff) next(local);
          }
          q += 4u + len;
        }
      }
      p += 46u + nlen + xlen + clen;
      // Windows tools write '\'.
      if (!(flags & 0x800)) std::replace(name.begin(), name.end(), '\\', '/');
      Entry en;
      en.mtime = dos_time(mdate, mtime);
      en.has_mtime = true;
      const bool unix_mode = (made_by >> 8) == 3 && (ext_attr >> 16) != 0;
      const std::uint32_t mode = ext_attr >> 16;
      if (unix_mode) {
        en.mode = mode & 07777;
        en.has_mode = true;
      }
      const bool dir = (!name.empty() && name.back() == '/') || (unix_mode && (mode & 0170000) == 0040000) ||
                       (!unix_mode && (ext_attr & 0x10));
      if (dir) {
        en.kind = Kind::directory;
        tree.add_path(name, std::move(en));
        continue;
      }
      en.size = usize;
      en.stored_size = csize;
      const std::uint64_t at = local + shift;
      std::uint64_t data = 0;
      try {
        const auto lh = src_->read_exact(at, 30, "a zip local header");
        if (le32(lh.data()) != kLocal) throw Error("bad local header");
        data = at + 30 + le16(lh.data() + 26) + le16(lh.data() + 28);
        if (data > size || csize > size - data) throw Error("member data outside the file");
      } catch (const Error &err) {
        en.note = std::string("unreadable: ") + err.what();
        en.loc2 = UINT64_MAX;
      }
      en.loc0 = data;
      en.loc1 = csize;
      if (en.loc2 != UINT64_MAX) {
        if (flags & 1) {
          en.note = "encrypted";
          en.loc2 = UINT64_MAX;
        } else {
          switch (method) {
            case 0: en.loc2 = 0; break;
            case 8: en.loc2 = 1 + static_cast<std::uint64_t>(Codec::deflate); break;
            case 12: en.loc2 = 1 + static_cast<std::uint64_t>(Codec::bzip2); break;
            case 93: en.loc2 = 1 + static_cast<std::uint64_t>(Codec::zstd); break;
            case 95: en.loc2 = 1 + static_cast<std::uint64_t>(Codec::xz); break;
            default:
              en.note = "compression method " + std::to_string(method) + " is not supported";
              en.loc2 = UINT64_MAX;
          }
          if (method == 0 && csize != usize) {
            en.note = "a stored member whose sizes disagree";
            en.loc2 = UINT64_MAX;
          }
        }
      }
      if (unix_mode && (mode & 0170000) == 0120000) en.kind = Kind::symlink;
      const bool link = en.kind == Kind::symlink;
      const bool readable = en.loc2 != UINT64_MAX;
      const std::uint32_t idx = tree.add_path(name, std::move(en));
      if (readable) spans.push_back({at, data + csize, idx});
      if (link && readable) {
        Entry &le = entries_[idx];
        try {
          if (le.size > 4096) throw Error("a symlink target over 4 KiB");
          auto bytes = head_entry(le, 4096, ctx);
          le.link_target.assign(reinterpret_cast<const char *>(bytes.data()), bytes.size());
        } catch (const Error &err) {
          le.kind = Kind::file;
          le.note = std::string("a symlink whose target can't be read: ") + err.what();
        }
      }
    }
    tree.finish();
    // Members sharing compressed data: refuse all but the first.
    std::sort(spans.begin(), spans.end(), [](const Span &a, const Span &b) { return a.start < b.start; });
    std::uint64_t reach = 0, overlaps = 0;
    for (const Span &s : spans) {
      if (s.start < reach && entries_[s.entry].kind != Kind::directory) {
        Entry &en = entries_[s.entry];
        en.note = "its data overlaps another member's (a zip bomb?)";
        en.loc2 = UINT64_MAX;
        ++overlaps;
      }
      reach = std::max(reach, s.end);
    }
    if (overlaps)
      warn(plural(overlaps, "member shares", "members share") +
                          " compressed data with another: refused, as zip bombs do this");
    description_ = "zip archive, " + summary_counts(*this);
  }
};

}  // namespace

std::shared_ptr<FileSystem> open_zip(std::shared_ptr<const Source> src, std::string_view name, const Context &ctx) {
  auto fs = std::make_shared<Zip>(std::move(src));
  fs->parse(name, ctx);
  return fs;
}

}  // namespace revkit::container::detail
