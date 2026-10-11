// Listening sockets inherited from a service manager: systemd's socket
// activation protocol (sd_listen_fds(3)), implemented here so the daemon
// needs no libsystemd.
//
// The manager passes LISTEN_PID (the process the sockets are for),
// LISTEN_FDS (how many, starting at descriptor 3) and optionally
// LISTEN_FDNAMES (colon-separated names, from FileDescriptorName=).
// TakeListenFds reads them once, unsets them so child processes (decompiler
// workers, script hosts) don't take the sockets for theirs, and marks the
// descriptors close-on-exec.
#pragma once

#include <string>
#include <vector>

namespace revkit::api {

struct InheritedSocket {
  int fd = -1;
  // FileDescriptorName= of the socket unit ("" when not given).
  std::string name;
  // Where it listens: "127.0.0.1:50052", "[::1]:50052" (getsockname).
  std::string address;
};

// The sockets passed to this process, or none when LISTEN_PID is not this
// process (or unset). Every descriptor must be a listening TCP socket (IPv4
// or IPv6); otherwise returns false with `error`.
bool TakeListenFds(std::vector<InheritedSocket> &out, std::string &error);

// "host:port" of a listening socket, or "" when it is not TCP.
std::string SocketAddress(int fd);

}  // namespace revkit::api
