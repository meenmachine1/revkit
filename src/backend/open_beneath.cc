#include "open_beneath.h"

#include <fcntl.h>
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

}  // namespace revkit::backend
