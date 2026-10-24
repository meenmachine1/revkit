#include "open_beneath.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <string>
#include <vector>

namespace revkit::backend {

int OpenBeneath(int dirfd, const std::filesystem::path &rel, int flags, mode_t mode) {
  if (rel.is_absolute()) {
    errno = EXDEV;
    return -1;
  }
  std::vector<std::string> parts;
  for (const std::filesystem::path &c : rel) {
    const std::string s = c.string();
    if (s.empty() || s == ".") continue;
    if (s == "..") {
      errno = EXDEV;
      return -1;
    }
    parts.push_back(s);
  }
  if (parts.empty()) return ::openat(dirfd, ".", flags | O_CLOEXEC, mode);
  int at = dirfd;
  for (std::size_t i = 0; i + 1 < parts.size(); ++i) {
    const int next = ::openat(at, parts[i].c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    const int saved = errno;
    if (at != dirfd) ::close(at);
    if (next < 0) {
      errno = saved;
      return -1;
    }
    at = next;
  }
  const int fd = ::openat(at, parts.back().c_str(), flags | O_NOFOLLOW | O_CLOEXEC, mode);
  const int saved = errno;
  if (at != dirfd) ::close(at);
  errno = saved;
  return fd;
}

int OpenBeneath(const std::filesystem::path &root, const std::filesystem::path &rel, int flags, mode_t mode) {
  const int rfd = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (rfd < 0) return -1;
  const int fd = OpenBeneath(rfd, rel, flags, mode);
  const int saved = errno;
  ::close(rfd);
  errno = saved;
  return fd;
}

std::optional<std::string> ReadRegularFile(const std::filesystem::path &canonical, const std::vector<std::string> &roots,
                                           std::uint64_t max_bytes, std::string *why) {
  auto fail = [&](const char *m) -> std::optional<std::string> {
    if (why) *why = m;
    return std::nullopt;
  };
  if (!canonical.is_absolute()) return fail("missing");
  const int flags = O_RDONLY | O_NONBLOCK | O_NOCTTY;
  int fd = -1;
  if (roots.empty()) {
    fd = ::open(canonical.c_str(), flags | O_NOFOLLOW | O_CLOEXEC);
  } else {
    bool under = false;
    for (const std::string &r : roots) {
      std::error_code ec;
      const std::filesystem::path root = std::filesystem::canonical(r, ec);
      if (ec) continue;
      const std::filesystem::path rel = canonical.lexically_normal().lexically_relative(root);
      if (rel.empty() || *rel.begin() == "..") continue;
      under = true;
      fd = OpenBeneath(root, rel, flags);
      if (fd >= 0) break;
    }
    if (!under) return fail("outside the browse roots");
  }
  if (fd < 0) return fail(errno == ELOOP || errno == ENOTDIR ? "not a regular file" : "missing");
  struct stat st {};
  if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    ::close(fd);
    return fail("not a regular file");
  }
  if (static_cast<std::uint64_t>(st.st_size) > max_bytes) {
    ::close(fd);
    return fail("too large");
  }
  std::string out(static_cast<std::size_t>(st.st_size), '\0');
  std::size_t got = 0;
  while (got < out.size()) {
    const ssize_t n = ::pread(fd, out.data() + got, out.size() - got, static_cast<off_t>(got));
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) break;
    got += static_cast<std::size_t>(n);
  }
  ::close(fd);
  if (got != out.size()) return fail("unreadable");
  return out;
}

}  // namespace revkit::backend
