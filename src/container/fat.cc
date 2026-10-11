// FAT12, FAT16 and FAT32 (the type from the cluster count, as Microsoft's
// specification says): long file names (checked against their short
// entry), 8.3 names with the lowercase flags, DOS times, cluster chains
// (loops and chains that end early refused). Files map onto the image's
// clusters without a copy.
#include "formats.hh"

#include <ctime>
#include <set>

namespace revkit::container::detail {
namespace {

std::int64_t dos_time(std::uint16_t date, std::uint16_t time) {
  if (date == 0) return 0;
  std::tm tm{};
  tm.tm_year = ((date >> 9) & 0x7f) + 80;
  tm.tm_mon = std::max(0, ((date >> 5) & 0x0f) - 1);
  tm.tm_mday = std::max(1, date & 0x1f);
  tm.tm_hour = (time >> 11) & 0x1f;
  tm.tm_min = (time >> 5) & 0x3f;
  tm.tm_sec = (time & 0x1f) * 2;
  return static_cast<std::int64_t>(timegm(&tm));
}

void utf8(std::string &out, std::uint32_t c) {
  if (c < 0x80) {
    out += static_cast<char>(c);
  } else if (c < 0x800) {
    out += static_cast<char>(0xc0 | (c >> 6));
    out += static_cast<char>(0x80 | (c & 0x3f));
  } else {
    out += static_cast<char>(0xe0 | (c >> 12));
    out += static_cast<char>(0x80 | ((c >> 6) & 0x3f));
    out += static_cast<char>(0x80 | (c & 0x3f));
  }
}

class Fat final : public FileSystem {
 public:
  explicit Fat(std::shared_ptr<const Source> src) : src_(std::move(src)) {}

  void parse(const Context &ctx) {
    format_ = "fat";
    const auto bs = src_->read_exact(0, 512, "the FAT boot sector");
    Buf b(bs, "the FAT boot sector");
    bps_ = b.l16(11);
    spc_ = b.u8(13);
    const std::uint16_t reserved = b.l16(14);
    const std::uint8_t nfats = b.u8(16);
    const std::uint16_t root_entries = b.l16(17);
    std::uint64_t total = b.l16(19) ? b.l16(19) : b.l32(32);
    const std::uint32_t fat_size = b.l16(22) ? b.l16(22) : b.l32(36);
    if ((bps_ != 512 && bps_ != 1024 && bps_ != 2048 && bps_ != 4096) || spc_ == 0 || (spc_ & (spc_ - 1)) ||
        reserved == 0 || nfats == 0 || fat_size == 0)
      throw Error("a FAT boot sector with impossible geometry");
    cluster_bytes_ = static_cast<std::uint64_t>(bps_) * spc_;
    const std::uint64_t root_sectors = (static_cast<std::uint64_t>(root_entries) * 32 + bps_ - 1) / bps_;
    fat_offset_ = static_cast<std::uint64_t>(reserved) * bps_;
    root_offset_ = (reserved + static_cast<std::uint64_t>(nfats) * fat_size) * bps_;
    root_bytes_ = root_sectors * bps_;
    data_offset_ = root_offset_ + root_bytes_;
    const std::uint64_t first_data = reserved + static_cast<std::uint64_t>(nfats) * fat_size + root_sectors;
    if (total <= first_data) throw Error("a FAT volume with no data area");
    clusters_ = (total - first_data) / spc_;
    bits_ = clusters_ < 4085 ? 12 : clusters_ < 65525 ? 16 : 32;
    fat_bytes_ = static_cast<std::uint64_t>(fat_size) * bps_;
    if (fat_bytes_ > (256u << 20)) throw LimitError("a FAT over 256 MiB");
    fat_ = src_->read_exact(fat_offset_, fat_bytes_, "the FAT");
    if (total * bps_ > src_->size() + bps_) warn("the image is shorter than its volume");
    std::string label;
    TreeBuilder tree(*this, ctx.limits);
    std::set<std::uint32_t> seen;
    if (bits_ == 32) {
      const std::uint32_t root = b.l32(44);
      walk(tree, 0, chain_bytes(root, 0, true), seen, ctx, 0, label);
    } else {
      const auto root = src_->read_exact(root_offset_, root_bytes_, "the FAT root directory");
      walk(tree, 0, root, seen, ctx, 0, label);
    }
    tree.finish();
    description_ = "FAT" + std::to_string(bits_) + " file system" +
                   (label.empty() ? "" : " \"" + display_name(label) + "\"") + ", " + summary_counts(*this);
  }

  std::shared_ptr<Source> open(std::uint32_t entry, const Context &) const override {
    const Entry &e = entries_.at(entry);
    if (e.kind != Kind::file) throw Error(display_name(e.name) + " is not a file");
    if (e.size == 0) return memory_source({});
    std::vector<Run> runs;
    std::uint64_t logical = 0;
    for (std::uint32_t c : chain(static_cast<std::uint32_t>(e.loc0), e.size)) {
      const std::uint64_t at = data_offset_ + static_cast<std::uint64_t>(c - 2) * cluster_bytes_;
      const std::uint64_t n = std::min(cluster_bytes_, e.size - logical);
      if (!runs.empty() && runs.back().physical + runs.back().length == at)
        runs.back().length += n;
      else
        runs.push_back({logical, at, n, false});
      logical += n;
      if (logical >= e.size) break;
    }
    if (logical < e.size) throw Error(display_name(e.name) + ": its cluster chain ends before its size");
    return mapped_source(src_, std::move(runs), e.size);
  }

 private:
  std::uint32_t next(std::uint32_t c) const {
    if (bits_ == 12) {
      const std::uint64_t at = c + c / 2;
      if (at + 2 > fat_.size()) return 0x0fffffff;
      const std::uint16_t v = le16(fat_.data() + at);
      const std::uint32_t r = (c & 1) ? v >> 4 : v & 0xfff;
      return r >= 0xff8 ? 0x0fffffff : r;
    }
    if (bits_ == 16) {
      const std::uint64_t at = 2ull * c;
      if (at + 2 > fat_.size()) return 0x0fffffff;
      const std::uint32_t r = le16(fat_.data() + at);
      return r >= 0xfff8 ? 0x0fffffff : r;
    }
    const std::uint64_t at = 4ull * c;
    if (at + 4 > fat_.size()) return 0x0fffffff;
    const std::uint32_t r = le32(fat_.data() + at) & 0x0fffffff;
    return r >= 0x0ffffff8 ? 0x0fffffff : r;
  }

  // The clusters of a chain; `bytes` bounds it (0: to its end), and at most
  // `limit` are listed.
  std::vector<std::uint32_t> chain(std::uint32_t c, std::uint64_t bytes, std::uint64_t limit = UINT64_MAX) const {
    std::vector<std::uint32_t> out;
    std::vector<bool> seen;  // a bit per cluster: a set of 64M clusters took GBs
    const std::uint64_t want = bytes ? (bytes + cluster_bytes_ - 1) / cluster_bytes_ : UINT64_MAX;
    while (c >= 2 && c < clusters_ + 2 && out.size() < want && out.size() < limit) {
      // Clusters past the FAT's entries end their chain (next()), so only
      // those it has can loop.
      if (seen.empty()) seen.resize(static_cast<std::size_t>(std::min<std::uint64_t>(clusters_, fat_bytes_ * 8 / bits_) + 2));
      if (c < seen.size()) {
        if (seen[c]) throw Error("a FAT cluster chain loops");
        seen[c] = true;
      }
      out.push_back(c);
      c = next(c);
    }
    if (c != 0x0fffffff && out.size() < want && out.size() < limit && !(c >= 2 && c < clusters_ + 2) && bytes)
      throw Error("a FAT cluster chain points outside the volume");
    return out;
  }

  std::vector<std::byte> chain_bytes(std::uint32_t c, std::uint64_t bytes, bool directory) const {
    std::vector<std::byte> out;
    // A directory's chain is listed only as far as the 4 MiB limit.
    const std::uint64_t limit = directory ? (4u << 20) / cluster_bytes_ + 2 : UINT64_MAX;
    for (std::uint32_t k : chain(c, bytes, limit)) {
      if (directory && out.size() > (4u << 20)) throw LimitError("a FAT directory over 4 MiB");
      auto part = src_->read_exact(data_offset_ + static_cast<std::uint64_t>(k - 2) * cluster_bytes_, cluster_bytes_,
                                   "a FAT cluster");
      out.insert(out.end(), part.begin(), part.end());
    }
    return out;
  }

  void walk(TreeBuilder &tree, std::uint32_t parent, const std::vector<std::byte> &dir, std::set<std::uint32_t> &seen,
            const Context &ctx, unsigned depth, std::string &label) {
    if (depth > ctx.limits.max_dir_depth) throw LimitError("FAT directories nest too deep");
    std::vector<std::uint32_t> lfn(256 * 13);  // the long name collected so far
    int lfn_order = -1;
    std::uint8_t lfn_sum = 0;
    std::size_t lfn_len = 0;
    for (std::size_t p = 0; p + 32 <= dir.size(); p += 32) {
      ctx.check_cancelled();
      const std::byte *d = dir.data() + p;
      const std::uint8_t first = static_cast<std::uint8_t>(d[0]);
      if (first == 0) break;
      if (first == 0xe5) {
        lfn_order = -1;
        continue;
      }
      const std::uint8_t attr = static_cast<std::uint8_t>(d[11]);
      if ((attr & 0x3f) == 0x0f) {
        const std::uint8_t ord = first & 0x3f;
        if (first & 0x40) {
          lfn_order = ord;
          lfn_sum = static_cast<std::uint8_t>(d[13]);
          lfn_len = 0;
          std::fill(lfn.begin(), lfn.end(), 0);
        } else if (lfn_order < 0 || ord != lfn_order - 1 || static_cast<std::uint8_t>(d[13]) != lfn_sum) {
          lfn_order = -1;
          continue;
        } else {
          lfn_order = ord;
        }
        if (ord == 0 || ord > 20) {
          lfn_order = -1;
          continue;
        }
        static const int offs[13] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
        for (int k = 0; k < 13; ++k) {
          const std::uint16_t ch = le16(d + offs[k]);
          const std::size_t at = (ord - 1u) * 13u + k;
          lfn[at] = ch;
          if (ch && ch != 0xffff) lfn_len = std::max(lfn_len, at + 1);
        }
        continue;
      }
      // A short entry.
      std::string base(reinterpret_cast<const char *>(d), 8), ext(reinterpret_cast<const char *>(d + 8), 3);
      if (static_cast<std::uint8_t>(base[0]) == 0x05) base[0] = static_cast<char>(0xe5);
      while (!base.empty() && base.back() == ' ') base.pop_back();
      while (!ext.empty() && ext.back() == ' ') ext.pop_back();
      if (attr & 0x08) {  // the volume label
        if (!(attr & 0x10)) label = base + ext;
        lfn_order = -1;
        continue;
      }
      std::uint8_t sum = 0;
      for (int k = 0; k < 11; ++k) sum = static_cast<std::uint8_t>(((sum & 1) << 7) + (sum >> 1) + static_cast<std::uint8_t>(d[k]));
      std::string name;
      if (lfn_order == 1 && sum == lfn_sum && lfn_len) {
        for (std::size_t k = 0; k < lfn_len; ++k)
          if (lfn[k] && lfn[k] != 0xffff) utf8(name, lfn[k]);
      } else {
        const std::uint8_t nt = static_cast<std::uint8_t>(d[12]);
        auto lower = [](std::string s) {
          for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          return s;
        };
        name = (nt & 0x08 ? lower(base) : base) + (ext.empty() ? "" : "." + (nt & 0x10 ? lower(ext) : ext));
      }
      lfn_order = -1;
      if (name.empty() || name == "." || name == "..") continue;
      const std::uint32_t cluster = static_cast<std::uint32_t>(le16(d + 20)) << 16 | le16(d + 26);
      Entry e;
      e.name = name;
      e.mtime = dos_time(le16(d + 24), le16(d + 22));
      e.has_mtime = true;
      e.mode = (attr & 0x01) ? 0444 : 0644;
      e.loc0 = cluster;
      if (attr & 0x10) {
        e.kind = Kind::directory;
        e.mode |= 0111;
        e.has_mode = true;
        const std::uint32_t idx = tree.add_child(parent, std::move(e));
        if (cluster < 2) continue;
        if (!seen.insert(cluster).second) throw Error("a FAT directory contains itself");
        walk(tree, idx, chain_bytes(cluster, 0, true), seen, ctx, depth + 1, label);
      } else {
        e.kind = Kind::file;
        e.size = le32(d + 28);
        e.has_mode = true;
        tree.add_child(parent, std::move(e));
      }
    }
  }

  std::shared_ptr<const Source> src_;
  std::uint16_t bps_ = 512;
  std::uint8_t spc_ = 1;
  std::uint64_t cluster_bytes_ = 512, fat_offset_ = 0, fat_bytes_ = 0, root_offset_ = 0, root_bytes_ = 0,
                data_offset_ = 0, clusters_ = 0;
  int bits_ = 12;
  std::vector<std::byte> fat_;
};

}  // namespace

std::shared_ptr<FileSystem> open_fat(std::shared_ptr<const Source> src, std::string_view, const Context &ctx) {
  auto fs = std::make_shared<Fat>(std::move(src));
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
