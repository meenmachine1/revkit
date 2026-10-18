// A host directory as the outermost layer (batch import). Walked with
// openat and O_NOFOLLOW from a directory descriptor held open, so a
// symlink (or one swapped in later) never leads outside: links are listed
// and resolved inside the tree, as a container's are.
#include "formats.hh"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace revkit::container {
namespace {

using detail::summary_counts;

Kind kind_of(mode_t m) {
  if (S_ISREG(m)) return Kind::file;
  if (S_ISDIR(m)) return Kind::directory;
  if (S_ISLNK(m)) return Kind::symlink;
  if (S_ISCHR(m)) return Kind::char_device;
  if (S_ISBLK(m)) return Kind::block_device;
  if (S_ISFIFO(m)) return Kind::fifo;
  if (S_ISSOCK(m)) return Kind::socket;
  return Kind::other;
}

class Dir final : public FileSystem {
 public:
  ~Dir() override {
    if (root_fd_ >= 0) ::close(root_fd_);
  }

  void open_root(const std::string &path, const Context &ctx) {
    format_ = "dir";
    root_fd_ = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd_ < 0) throw Error("cannot open the directory " + path + ": " + std::strerror(errno));
    TreeBuilder tree(*this, ctx.limits);
    walk(tree, root_fd_, 0, ctx, 0);
    tree.finish();
    description_ = "directory, " + summary_counts(*this);
  }

  bool stored_plain(std::uint32_t) const override { return true; }
  std::shared_ptr<Source> open(std::uint32_t entry, const Context &) const override {
    std::uint32_t target = entry;
    if (entries_.at(entry).kind == Kind::symlink) {
      auto t = resolve_link(entry);
      if (!t) throw Error("a symlink whose target isn't in the directory");
      target = *t;
    }
    if (entries_.at(target).kind != Kind::file) throw Error("not a regular file");
    const auto parts = components_of(target);
    int dir = ::dup(root_fd_);
    if (dir < 0) throw Error("cannot read the directory");
    for (std::size_t i = 0; i + 1 < parts.size(); ++i) {
      const int next = ::openat(dir, parts[i].c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      ::close(dir);
      if (next < 0) throw Error("cannot open " + display_name(parts[i]) + ": " + std::strerror(errno));
      dir = next;
    }
    const int fd = ::openat(dir, parts.back().c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    ::close(dir);
    if (fd < 0) throw Error("cannot open " + display_name(parts.back()) + ": " + std::strerror(errno));
    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
      ::close(fd);
      throw Error(display_name(parts.back()) + " is no longer a regular file");
    }
    return file_source(fd, static_cast<std::uint64_t>(st.st_size));
  }

 private:
  void walk(TreeBuilder &tree, int dirfd, std::uint32_t parent, const Context &ctx, unsigned depth) {
    if (depth > ctx.limits.max_dir_depth) throw LimitError("directories nest too deep");
    const int fd = ::dup(dirfd);
    if (fd < 0) return;
    DIR *d = ::fdopendir(fd);
    if (!d) {
      ::close(fd);
      return;
    }
    struct Closer {
      DIR *d;
      ~Closer() { ::closedir(d); }
    } closer{d};
    ::rewinddir(d);
    std::vector<std::string> names;
    while (dirent *de = ::readdir(d)) {
      const std::string n = de->d_name;
      if (n == "." || n == "..") continue;
      names.push_back(n);
      if (names.size() > ctx.limits.max_entries)
        throw LimitError("more than " + std::to_string(ctx.limits.max_entries) + " entries");
    }
    for (const std::string &n : names) {
      ctx.check_cancelled();
      struct stat st {};
      if (::fstatat(dirfd, n.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
      Entry e;
      e.name = n;
      e.kind = kind_of(st.st_mode);
      e.mode = st.st_mode & 07777;
      e.has_mode = true;
      e.uid = st.st_uid;
      e.gid = st.st_gid;
      e.has_owner = true;
      e.mtime = st.st_mtime;
      e.has_mtime = true;
      if (e.kind == Kind::file) e.size = static_cast<std::uint64_t>(st.st_size);
      if (e.kind == Kind::symlink) {
        char buf[4096];
        const ssize_t len = ::readlinkat(dirfd, n.c_str(), buf, sizeof buf);
        if (len > 0) e.link_target.assign(buf, static_cast<std::size_t>(len));
        e.size = e.link_target.size();
      }
      const bool dir = e.kind == Kind::directory;
      const std::uint32_t idx = tree.add_child(parent, std::move(e));
      if (dir) {
        const int sub = ::openat(dirfd, n.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (sub < 0) continue;
        try {
          walk(tree, sub, idx, ctx, depth + 1);
        } catch (...) {
          ::close(sub);
          throw;
        }
        ::close(sub);
      }
    }
  }

  int root_fd_ = -1;
};

}  // namespace

std::shared_ptr<FileSystem> open_host_directory(const std::string &path, const Context &ctx) {
  auto fs = std::make_shared<Dir>();
  fs->open_root(path, ctx);
  return fs;
}

}  // namespace revkit::container
