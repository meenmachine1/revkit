// The GDB Remote Serial Protocol, client side: transports (TCP, Unix
// sockets, a child's pipe) and the packet layer (framing, checksums,
// acknowledgements and no-ack mode, run-length decoding, binary escapes).
// GdbRemoteTarget (gdb_remote.hh) speaks the packets.
#pragma once

#include "revkit/debug/target.hh"

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace revkit::debug {

using Clock = std::chrono::steady_clock;

// A byte stream to a stub.
class Transport {
 public:
  virtual ~Transport() = default;
  // Writes everything; throws DebugError if the stream is gone.
  virtual void write(std::string_view bytes) = 0;
  // Reads what is available, waiting until `deadline`: the byte count, 0
  // at the deadline. Throws DebugError when the stream closed.
  virtual std::size_t read(char *buf, std::size_t size, Clock::time_point deadline) = 0;
  virtual void close() = 0;
  virtual std::string describe() const = 0;
};

// A transport over a connected file descriptor (socket, socketpair, pipe
// pair); it owns the descriptors.
class FdTransport : public Transport {
 public:
  FdTransport(int read_fd, int write_fd, std::string description);
  ~FdTransport() override;
  void write(std::string_view bytes) override;
  std::size_t read(char *buf, std::size_t size, Clock::time_point deadline) override;
  void close() override;
  std::string describe() const override { return description_; }

 private:
  int read_fd_, write_fd_;
  std::string description_;
  std::mutex write_mu_;
};

// "host:port", "tcp:host:port", "tcp://host:port", "gdb://host:port",
// "unix:/path" or "unix:///path". Throws DebugError.
std::unique_ptr<Transport> connect_url(const std::string &url,
                                       std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));
std::unique_ptr<Transport> connect_tcp(const std::string &host, std::uint16_t port, std::chrono::milliseconds timeout);
std::unique_ptr<Transport> connect_unix(const std::string &path, std::chrono::milliseconds timeout);

struct RspStats {
  std::uint64_t packets_sent = 0, packets_received = 0;
  std::uint64_t retransmits = 0, bad_checksums = 0;
  std::uint64_t bytes_sent = 0, bytes_received = 0;
};

// One connection's packet layer. request() and receive() are for one
// thread at a time (the session's); interrupt() may come from any thread.
class RspClient {
 public:
  explicit RspClient(std::unique_ptr<Transport> transport);

  // Sends `payload` and returns the reply packet. Throws DebugError on a
  // timeout or a closed connection.
  std::string request(std::string_view payload, Clock::time_point deadline);
  std::string request(std::string_view payload) { return request(payload, Clock::now() + timeout_); }
  // Sends without waiting for a reply (vCont: the reply is a stop, later).
  void send(std::string_view payload, Clock::time_point deadline);
  // The next packet (acknowledged), or nullopt at the deadline.
  std::optional<std::string> receive(Clock::time_point deadline);
  // The interrupt byte (0x03), for a running target.
  void interrupt();

  // After QStartNoAckMode was accepted.
  void set_no_ack(bool on) { no_ack_ = on; }
  bool no_ack() const { return no_ack_; }
  void set_timeout(std::chrono::milliseconds t) { timeout_ = t; }
  std::chrono::milliseconds timeout() const { return timeout_; }
  const RspStats &stats() const { return stats_; }
  Transport &transport() { return *transport_; }

  // --- Encoding ---
  // "$payload#cs"; binary parts of `payload` must already be escape()d.
  static std::string frame(std::string_view payload);
  static std::uint8_t checksum(std::string_view bytes);
  // Run-length expansion and binary unescaping of a received packet body.
  static std::string decode(std::string_view body);
  // Escapes '#', '$', '}' and '*' for binary payloads (X, vFile:pwrite).
  static std::string escape(std::span<const std::uint8_t> bytes);
  static std::string to_hex(std::span<const std::uint8_t> bytes);
  static std::string to_hex(std::string_view text);
  // nullopt if `hex` isn't hex. "xx" (an unavailable byte) reads as 0.
  static std::optional<std::vector<std::uint8_t>> from_hex(std::string_view hex);

 private:
  int getc(Clock::time_point deadline);  // -1 at the deadline
  void write_raw(std::string_view bytes);

  std::unique_ptr<Transport> transport_;
  std::string buf_;
  std::size_t pos_ = 0;
  bool no_ack_ = false;
  std::chrono::milliseconds timeout_{5000};
  RspStats stats_;
  bool trace_ = false;  // RK_RSP_TRACE: packets to stderr
};

}  // namespace revkit::debug
