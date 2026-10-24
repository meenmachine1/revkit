// What the formats share: archives whose members are slices of the file
// (stored or compressed with one codec), and wording.
#include "formats.hh"

#include <algorithm>

namespace revkit::container::detail {

std::string plural(std::uint64_t n, std::string_view one, std::string_view many) {
  return std::to_string(n) + " " + std::string(n == 1 ? one : many);
}

std::string summary_counts(const FileSystem &fs) {
  std::uint64_t files = 0, dirs = 0, links = 0;
  for (std::size_t i = 1; i < fs.entries().size(); ++i) {
    const Kind k = fs.entries()[i].kind;
    if (k == Kind::file || k == Kind::hardlink)
      ++files;
    else if (k == Kind::directory)
      ++dirs;
    else if (k == Kind::symlink)
      ++links;
  }
  std::string s = plural(files, "file", "files");
  if (dirs) s += ", " + plural(dirs, "directory", "directories");
  if (links) s += ", " + plural(links, "link", "links");
  return s;
}

std::string strip_suffix(std::string_view name, std::initializer_list<std::string_view> suffixes) {
  if (const auto slash = name.find_last_of('/'); slash != std::string_view::npos) name = name.substr(slash + 1);
  for (std::string_view s : suffixes) {
    if (name.size() > s.size()) {
      std::string_view tail = name.substr(name.size() - s.size());
      bool same = true;
      for (std::size_t i = 0; i < s.size() && same; ++i)
        same = std::tolower(static_cast<unsigned char>(tail[i])) == s[i];
      if (same) {
        std::string out(name.substr(0, name.size() - s.size()));
        // "x.tgz" holds "x.tar".
        if (s == ".tgz" || s == ".tbz2" || s == ".tbz" || s == ".txz" || s == ".tzst") out += ".tar";
        return out;
      }
    }
  }
  if (name.empty()) return "data";
  return std::string(name) + ".out";
}

Kind mode_kind(std::uint32_t mode) {
  switch (mode & 0170000) {
    case 0100000: return Kind::file;
    case 0040000: return Kind::directory;
    case 0120000: return Kind::symlink;
    case 0020000: return Kind::char_device;
    case 0060000: return Kind::block_device;
    case 0010000: return Kind::fifo;
    case 0140000: return Kind::socket;
    default: return Kind::other;
  }
}

std::span<const std::byte> WindowReader::get(std::uint64_t off, std::size_t n) {
  const std::uint64_t size = src_.size();
  if (off >= size) return {};
  const std::uint64_t want_end = std::min<std::uint64_t>(size, off + n);
  if (off < start_ || want_end > start_ + buf_.size()) {
    const std::size_t len = static_cast<std::size_t>(std::min<std::uint64_t>(std::max(window_, n), size - off));
    buf_.resize(len);
    buf_.resize(src_.read(off, buf_));
    start_ = off;
  }
  const std::size_t at = static_cast<std::size_t>(off - start_);
  if (at >= buf_.size()) return {};
  return std::span<const std::byte>(buf_).subspan(at, std::min<std::size_t>(n, buf_.size() - at));
}

namespace {

class MappedSource final : public Source {
 public:
  MappedSource(std::shared_ptr<const Source> base, std::vector<Run> runs, std::uint64_t size)
      : base_(std::move(base)), runs_(std::move(runs)), size_(size) {}
  std::uint64_t size() const override { return size_; }
  std::size_t read(std::uint64_t offset, std::span<std::byte> out) const override {
    if (offset >= size_) return 0;
    const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(out.size(), size_ - offset));
    std::size_t done = 0;
    // The first run ending after `offset`.
    auto it = std::upper_bound(runs_.begin(), runs_.end(), offset,
                               [](std::uint64_t o, const Run &r) { return o < r.logical + r.length; });
    while (done < want) {
      const std::uint64_t at = offset + done;
      if (it == runs_.end() || at < it->logical) {
        // A hole up to the next run (or the end).
        const std::uint64_t until = it == runs_.end() ? size_ : it->logical;
        const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(want - done, until - at));
        std::memset(out.data() + done, 0, n);
        done += n;
        continue;
      }
      const std::uint64_t in = at - it->logical;
      const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(want - done, it->length - in));
      if (it->zero) {
        std::memset(out.data() + done, 0, n);
      } else {
        const std::size_t got = base_->read(it->physical + in, out.subspan(done, n));
        if (got < n) std::memset(out.data() + done + got, 0, n - got);
      }
      done += n;
      ++it;
    }
    return done;
  }

 private:
  std::shared_ptr<const Source> base_;
  std::vector<Run> runs_;
  std::uint64_t size_;
};

}  // namespace

std::shared_ptr<Source> mapped_source(std::shared_ptr<const Source> base, std::vector<Run> runs, std::uint64_t size) {
  std::sort(runs.begin(), runs.end(), [](const Run &a, const Run &b) { return a.logical < b.logical; });
  for (std::size_t i = 0; i < runs.size(); ++i) {
    const Run &r = runs[i];
    if (r.logical + r.length < r.logical) throw Error("a file's extent overflows");
    if (i && runs[i - 1].logical + runs[i - 1].length > r.logical) throw Error("a file's extents overlap");
    if (!r.zero && (r.physical > base->size() || r.length > base->size() - r.physical))
      throw Error("a file's data lies outside its container");
  }
  return std::make_shared<MappedSource>(std::move(base), std::move(runs), size);
}

std::uint32_t SliceFileSystem::target_of(std::uint32_t entry) const {
  const Entry &e = entries_.at(entry);
  if (e.kind == Kind::hardlink) {
    auto t = resolve_link(entry);
    if (!t || entries_[*t].kind != Kind::file) throw Error("a hard link's target is missing: " + e.link_target);
    return *t;
  }
  if (e.kind != Kind::file) throw Error(display_name(e.name) + " is a " + std::string(name(e.kind)) + ", not a file");
  return entry;
}

std::shared_ptr<Source> SliceFileSystem::open(std::uint32_t entry, const Context &ctx) const {
  const Entry &e = entries_.at(target_of(entry));
  if (e.loc2 == UINT64_MAX) throw Error(display_name(e.name) + ": " + (e.note.empty() ? "unreadable" : e.note));
  if (e.loc2 == 0) return slice(src_, e.loc0, e.loc1);
  Sink sink(ctx);
  decompress(static_cast<Codec>(e.loc2 - 1), *src_, e.loc0, e.loc1, sink, ctx);
  if (sink.size() != e.size && e.size != UINT64_MAX)
    throw Error(display_name(e.name) + " decompresses to " + std::to_string(sink.size()) + " bytes, not " +
                std::to_string(e.size));
  return sink.finish();
}

std::vector<std::byte> SliceFileSystem::head(std::uint32_t entry, std::uint64_t n, const Context &ctx) const {
  return head_entry(entries_.at(target_of(entry)), n, ctx);
}

std::vector<std::byte> SliceFileSystem::head_entry(const Entry &e, std::uint64_t n, const Context &ctx) const {
  if (e.loc2 == UINT64_MAX) throw Error(display_name(e.name) + ": " + (e.note.empty() ? "unreadable" : e.note));
  if (e.loc2 == 0) return slice(src_, e.loc0, e.loc1)->head(n);
  Sink sink(ctx, n);
  decompress(static_cast<Codec>(e.loc2 - 1), *src_, e.loc0, e.loc1, sink, ctx);
  return sink.finish()->head(n);
}

}  // namespace revkit::container::detail
