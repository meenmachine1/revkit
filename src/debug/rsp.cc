#include "revkit/debug/rsp.hh"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace revkit::debug {

namespace {

int poll_ms(Clock::time_point deadline) {
  const auto now = Clock::now();
  if (deadline <= now) return 0;
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
  return static_cast<int>(std::min<long long>(ms + 1, 1000 * 60 * 60));
}

int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

// --- Transports ---

FdTransport::FdTransport(int read_fd, int write_fd, std::string description)
    : read_fd_(read_fd), write_fd_(write_fd), description_(std::move(description)) {}

FdTransport::~FdTransport() { close(); }

void FdTransport::close() {
  std::lock_guard g(write_mu_);
  if (write_fd_ >= 0 && write_fd_ != read_fd_) ::close(write_fd_);
  if (read_fd_ >= 0) ::close(read_fd_);
  read_fd_ = write_fd_ = -1;
}

void FdTransport::write(std::string_view bytes) {
  std::lock_guard g(write_mu_);
  if (write_fd_ < 0) throw DebugError("the connection to the stub is closed");
  while (!bytes.empty()) {
    const ssize_t n = ::send(write_fd_, bytes.data(), bytes.size(), MSG_NOSIGNAL);
    if (n < 0 && errno == ENOTSOCK) {
      const ssize_t m = ::write(write_fd_, bytes.data(), bytes.size());
      if (m < 0) {
        if (errno == EINTR) continue;
        throw DebugError(std::string("writing to the stub: ") + std::strerror(errno));
      }
      bytes.remove_prefix(static_cast<std::size_t>(m));
      continue;
    }
    if (n < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN) {
        pollfd p{write_fd_, POLLOUT, 0};
        ::poll(&p, 1, 1000);
        continue;
      }
      throw DebugError(std::string("writing to the stub: ") + std::strerror(errno));
    }
    bytes.remove_prefix(static_cast<std::size_t>(n));
  }
}

std::size_t FdTransport::read(char *buf, std::size_t size, Clock::time_point deadline) {
  if (read_fd_ < 0) throw DebugError("the connection to the stub is closed");
  for (;;) {
    pollfd p{read_fd_, POLLIN, 0};
    const int r = ::poll(&p, 1, poll_ms(deadline));
    if (r < 0) {
      if (errno == EINTR) continue;
      throw DebugError(std::string("waiting for the stub: ") + std::strerror(errno));
    }
    if (r == 0) {
      if (Clock::now() >= deadline) return 0;
      continue;
    }
    const ssize_t n = ::read(read_fd_, buf, size);
    if (n < 0) {
      if (errno == EINTR || errno == EAGAIN) continue;
      throw DebugError(std::string("reading from the stub: ") + std::strerror(errno));
    }
    if (n == 0) throw DebugError("the stub closed the connection");
    return static_cast<std::size_t>(n);
  }
}

namespace {

// Waits for a non-blocking connect.
void finish_connect(int fd, const std::string &what, std::chrono::milliseconds timeout) {
  pollfd p{fd, POLLOUT, 0};
  const int r = ::poll(&p, 1, static_cast<int>(timeout.count()));
  if (r <= 0) throw DebugError("connecting to " + what + ": timed out");
  int err = 0;
  socklen_t len = sizeof err;
  ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
  if (err != 0) throw DebugError("connecting to " + what + ": " + std::strerror(err));
}

}  // namespace

std::unique_ptr<Transport> connect_tcp(const std::string &host, std::uint16_t port, std::chrono::milliseconds timeout) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo *res = nullptr;
  const std::string what = host + ":" + std::to_string(port);
  if (const int e = ::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res); e != 0)
    throw DebugError("resolving " + host + ": " + gai_strerror(e));
  std::string last = "no address";
  for (addrinfo *a = res; a != nullptr; a = a->ai_next) {
    const int fd = ::socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK, a->ai_protocol);
    if (fd < 0) continue;
    try {
      if (::connect(fd, a->ai_addr, a->ai_addrlen) != 0) {
        if (errno != EINPROGRESS) throw DebugError("connecting to " + what + ": " + std::strerror(errno));
        finish_connect(fd, what, timeout);
      }
      const int one = 1;
      ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
      ::freeaddrinfo(res);
      return std::make_unique<FdTransport>(fd, fd, "tcp:" + what);
    } catch (const DebugError &e) {
      last = e.what();
      ::close(fd);
    }
  }
  ::freeaddrinfo(res);
  throw DebugError(last);
}

std::unique_ptr<Transport> connect_unix(const std::string &path, std::chrono::milliseconds timeout) {
  sockaddr_un sa{};
  sa.sun_family = AF_UNIX;
  if (path.size() >= sizeof sa.sun_path) throw DebugError("socket path too long: " + path);
  std::memcpy(sa.sun_path, path.c_str(), path.size() + 1);
  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0) throw DebugError(std::string("socket: ") + std::strerror(errno));
  if (::connect(fd, reinterpret_cast<sockaddr *>(&sa), sizeof sa) != 0) {
    if (errno != EINPROGRESS && errno != EAGAIN) {
      const std::string e = std::strerror(errno);
      ::close(fd);
      throw DebugError("connecting to " + path + ": " + e);
    }
    try {
      finish_connect(fd, path, timeout);
    } catch (...) {
      ::close(fd);
      throw;
    }
  }
  return std::make_unique<FdTransport>(fd, fd, "unix:" + path);
}

std::unique_ptr<Transport> connect_url(const std::string &url_in, std::chrono::milliseconds timeout) {
  std::string url = url_in;
  for (const char *p : {"tcp://", "gdb://", "tcp:"})
    if (url.rfind(p, 0) == 0) {
      url = url.substr(std::strlen(p));
      break;
    }
  if (url.rfind("unix://", 0) == 0) return connect_unix(url.substr(7), timeout);
  if (url.rfind("unix:", 0) == 0) return connect_unix(url.substr(5), timeout);
  // host:port, [v6]:port, :port
  std::string host, port;
  if (!url.empty() && url[0] == '[') {
    const auto close = url.find(']');
    if (close == std::string::npos || close + 1 >= url.size() || url[close + 1] != ':')
      throw DebugError("not a gdb remote address: " + url_in + " (host:port, unix:/path)");
    host = url.substr(1, close - 1);
    port = url.substr(close + 2);
  } else {
    const auto colon = url.rfind(':');
    if (colon == std::string::npos) throw DebugError("not a gdb remote address: " + url_in + " (host:port, unix:/path)");
    host = url.substr(0, colon);
    port = url.substr(colon + 1);
  }
  if (host.empty()) host = "127.0.0.1";
  char *end = nullptr;
  const long p = std::strtol(port.c_str(), &end, 10);
  if (port.empty() || *end != '\0' || p <= 0 || p > 65535) throw DebugError("bad port in " + url_in);
  return connect_tcp(host, static_cast<std::uint16_t>(p), timeout);
}

// --- Packets ---

RspClient::RspClient(std::unique_ptr<Transport> transport)
    : transport_(std::move(transport)), trace_(std::getenv("RK_RSP_TRACE") != nullptr) {}

std::uint8_t RspClient::checksum(std::string_view bytes) {
  std::uint8_t s = 0;
  for (char c : bytes) s = static_cast<std::uint8_t>(s + static_cast<std::uint8_t>(c));
  return s;
}

std::string RspClient::frame(std::string_view payload) {
  static const char *digits = "0123456789abcdef";
  std::string out;
  out.reserve(payload.size() + 4);
  out += '$';
  out += payload;
  const std::uint8_t cs = checksum(payload);
  out += '#';
  out += digits[cs >> 4];
  out += digits[cs & 15];
  return out;
}

std::string RspClient::escape(std::span<const std::uint8_t> bytes) {
  std::string out;
  out.reserve(bytes.size());
  for (std::uint8_t b : bytes) {
    if (b == '#' || b == '$' || b == '}' || b == '*') {
      out += '}';
      out += static_cast<char>(b ^ 0x20);
    } else {
      out += static_cast<char>(b);
    }
  }
  return out;
}

std::string RspClient::decode(std::string_view body) {
  std::string out;
  out.reserve(body.size());
  for (std::size_t i = 0; i < body.size(); ++i) {
    const char c = body[i];
    if (c == '}' && i + 1 < body.size()) {
      out += static_cast<char>(body[++i] ^ 0x20);
    } else if (c == '*' && i + 1 < body.size() && !out.empty()) {
      // Run-length: the previous character repeated (n - 29) more times.
      const int n = static_cast<std::uint8_t>(body[++i]) - 29;
      if (n > 0) out.append(static_cast<std::size_t>(n), out.back());
    } else {
      out += c;
    }
  }
  return out;
}

std::string RspClient::to_hex(std::span<const std::uint8_t> bytes) {
  static const char *digits = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (std::uint8_t b : bytes) {
    out += digits[b >> 4];
    out += digits[b & 15];
  }
  return out;
}

std::string RspClient::to_hex(std::string_view text) {
  return to_hex(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(text.data()), text.size()));
}

std::optional<std::vector<std::uint8_t>> RspClient::from_hex(std::string_view hex) {
  if (hex.size() % 2 != 0) return std::nullopt;
  std::vector<std::uint8_t> out(hex.size() / 2);
  for (std::size_t i = 0; i < out.size(); ++i) {
    const char a = hex[2 * i], b = hex[2 * i + 1];
    if ((a == 'x' || a == 'X') && (b == 'x' || b == 'X')) {
      out[i] = 0;
      continue;
    }
    const int hi = hexval(a), lo = hexval(b);
    if (hi < 0 || lo < 0) return std::nullopt;
    out[i] = static_cast<std::uint8_t>(hi << 4 | lo);
  }
  return out;
}

int RspClient::getc(Clock::time_point deadline) {
  if (pos_ >= buf_.size()) {
    buf_.resize(16384);
    const std::size_t n = transport_->read(buf_.data(), buf_.size(), deadline);
    buf_.resize(n);
    pos_ = 0;
    stats_.bytes_received += n;
    if (n == 0) return -1;
  }
  return static_cast<std::uint8_t>(buf_[pos_++]);
}

void RspClient::write_raw(std::string_view bytes) {
  stats_.bytes_sent += bytes.size();
  transport_->write(bytes);
}

void RspClient::interrupt() { transport_->write(std::string_view("\x03", 1)); }

void RspClient::send(std::string_view payload, Clock::time_point deadline) {
  if (trace_) std::fprintf(stderr, "rsp -> %.*s\n", static_cast<int>(std::min<std::size_t>(payload.size(), 200)), payload.data());
  const std::string framed = frame(payload);
  for (int attempt = 0;; ++attempt) {
    write_raw(framed);
    ++stats_.packets_sent;
    if (no_ack_) return;
    // Wait for the acknowledgement; anything else before it is noise.
    for (;;) {
      const int c = getc(deadline);
      if (c < 0) throw DebugError("the stub did not acknowledge a packet (" + std::string(payload.substr(0, 24)) + ")");
      if (c == '+') return;
      if (c == '-') break;  // retransmit
      if (c == '$') {
        // A stub that answers without acknowledging: keep the reply.
        --pos_;
        return;
      }
    }
    ++stats_.retransmits;
    if (attempt >= 5) throw DebugError("the stub keeps rejecting a packet (" + std::string(payload.substr(0, 24)) + ")");
  }
}

std::optional<std::string> RspClient::receive(Clock::time_point deadline) {
  for (;;) {
    int c = getc(deadline);
    if (c < 0) return std::nullopt;
    if (c != '$' && c != '%') continue;  // acks, interrupts echoed, line noise
    const bool notification = c == '%';
    std::string body;
    for (;;) {
      c = getc(deadline + std::chrono::seconds(5));
      if (c < 0) throw DebugError("a packet from the stub was cut off");
      if (c == '#') break;
      body += static_cast<char>(c);
      if (body.size() > (64u << 20)) throw DebugError("a packet from the stub is too large");
    }
    const int h = getc(deadline + std::chrono::seconds(5)), l = getc(deadline + std::chrono::seconds(5));
    if (h < 0 || l < 0) throw DebugError("a packet from the stub was cut off");
    const int hv = hexval(static_cast<char>(h)), lv = hexval(static_cast<char>(l));
    if (!no_ack_ && (hv < 0 || lv < 0 || static_cast<std::uint8_t>(hv << 4 | lv) != checksum(body))) {
      ++stats_.bad_checksums;
      if (!notification) write_raw("-");
      continue;
    }
    if (notification) continue;  // non-stop notifications: not used
    if (!no_ack_) write_raw("+");
    ++stats_.packets_received;
    std::string out = decode(body);
    if (trace_) std::fprintf(stderr, "rsp <- %.*s\n", static_cast<int>(std::min<std::size_t>(out.size(), 200)), out.data());
    return out;
  }
}

std::string RspClient::request(std::string_view payload, Clock::time_point deadline) {
  send(payload, deadline);
  auto r = receive(deadline);
  if (!r) throw DebugError("the stub did not answer " + std::string(payload.substr(0, 40)));
  return *r;
}

}  // namespace revkit::debug
