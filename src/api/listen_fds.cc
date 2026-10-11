#include "revkit/api/listen_fds.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>

namespace revkit::api {
namespace {

constexpr int kFirstFd = 3;  // SD_LISTEN_FDS_START

bool ParseUnsigned(const char *s, unsigned long &out) {
  if (!s || !*s) return false;
  char *end = nullptr;
  errno = 0;
  out = std::strtoul(s, &end, 10);
  return errno == 0 && end && *end == '\0';
}

}  // namespace

std::string SocketAddress(int fd) {
  sockaddr_storage ss{};
  socklen_t len = sizeof ss;
  if (getsockname(fd, reinterpret_cast<sockaddr *>(&ss), &len) != 0) return "";
  char host[INET6_ADDRSTRLEN] = {};
  if (ss.ss_family == AF_INET) {
    auto *in = reinterpret_cast<sockaddr_in *>(&ss);
    if (!inet_ntop(AF_INET, &in->sin_addr, host, sizeof host)) return "";
    return std::string(host) + ":" + std::to_string(ntohs(in->sin_port));
  }
  if (ss.ss_family == AF_INET6) {
    auto *in6 = reinterpret_cast<sockaddr_in6 *>(&ss);
    // An IPv4-mapped address is the IPv4 one (systemd binds
    // ListenStream=127.0.0.1:N as AF_INET, but be exact either way).
    if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
      in_addr v4;
      std::memcpy(&v4, in6->sin6_addr.s6_addr + 12, 4);
      if (!inet_ntop(AF_INET, &v4, host, sizeof host)) return "";
      return std::string(host) + ":" + std::to_string(ntohs(in6->sin6_port));
    }
    if (!inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof host)) return "";
    return "[" + std::string(host) + "]:" + std::to_string(ntohs(in6->sin6_port));
  }
  return "";
}

bool TakeListenFds(std::vector<InheritedSocket> &out, std::string &error) {
  out.clear();
  const char *pid_env = std::getenv("LISTEN_PID");
  const char *fds_env = std::getenv("LISTEN_FDS");
  const char *names_env = std::getenv("LISTEN_FDNAMES");
  unsigned long pid = 0, n = 0;
  bool ours = ParseUnsigned(pid_env, pid) && pid == static_cast<unsigned long>(getpid()) && ParseUnsigned(fds_env, n);
  std::string names = names_env ? names_env : "";
  // Not for children, whatever happens next (sd_listen_fds with unset_environment).
  unsetenv("LISTEN_PID");
  unsetenv("LISTEN_FDS");
  unsetenv("LISTEN_FDNAMES");
  if (!ours || n == 0) return true;
  if (n > 64) {
    error = "LISTEN_FDS=" + std::to_string(n) + " is more sockets than rk-daemon can use";
    return false;
  }

  std::vector<std::string> split;
  for (std::size_t at = 0; at <= names.size();) {
    std::size_t colon = names.find(':', at);
    if (colon == std::string::npos) colon = names.size();
    split.push_back(names.substr(at, colon - at));
    at = colon + 1;
  }

  for (int i = 0; i < static_cast<int>(n); ++i) {
    int fd = kFirstFd + i;
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) {
      error = "inherited descriptor " + std::to_string(fd) + " is not open";
      return false;
    }
    fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    int type = 0, listening = 0;
    socklen_t len = sizeof type;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) != 0 || type != SOCK_STREAM) {
      error = "inherited descriptor " + std::to_string(fd) + " is not a stream socket (want ListenStream=host:port)";
      return false;
    }
    len = sizeof listening;
    if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &listening, &len) != 0 || !listening) {
      error = "inherited socket " + std::to_string(fd) + " is not listening (Accept=no is required)";
      return false;
    }
    InheritedSocket s;
    s.fd = fd;
    s.name = i < static_cast<int>(split.size()) ? split[i] : "";
    s.address = SocketAddress(fd);
    if (s.address.empty()) {
      error = "inherited socket " + std::to_string(fd) + " is not TCP over IPv4 or IPv6";
      return false;
    }
    out.push_back(std::move(s));
  }
  return true;
}

}  // namespace revkit::api
