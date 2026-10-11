// Browser transport: Connect (unary and server-streaming, JSON and binary)
// and gRPC-web (binary) over HTTP/1.1, plus static files for the web UI.
//
// The gateway has no per-method code. It finds the method in the generated
// descriptor pool, transcodes JSON with protobuf's type resolver when
// needed, and forwards the call over an in-process gRPC channel. New RPCs in
// the schema are reachable from browsers as soon as the gRPC server
// implements them.
#pragma once

#include "revkit/api/server.h"

#include <grpcpp/grpcpp.h>

#include <memory>
#include <string>
#include <vector>

namespace revkit::api {

struct GatewayOptions {
  std::vector<std::string> allowed_origins;
  std::string web_root;
  std::size_t max_message_bytes = 64u << 20;
  // Browser sessions: the gateway turns its session cookie into the
  // bearer metadata the gRPC handlers check, after checking the CSRF
  // header (docs/security.md). Null: no authentication.
  std::shared_ptr<auth::Store> auth;
  // Sent as x-rk-gateway so the handlers trust x-forwarded-for.
  std::string gateway_secret;
  // HTTPS instead of HTTP.
  TlsConfig tls;
  // Names the Host header may carry besides loopback names and IP
  // literals (DNS rebinding protection, docs/security.md): exact names
  // ("build.example.com") or "*.example.com".
  std::vector<std::string> allowed_hosts;
};

class ConnectGateway {
 public:
  ConnectGateway(std::shared_ptr<grpc::Channel> channel, GatewayOptions options);
  ~ConnectGateway();

  // False (with `error`) if the TLS certificate or key was refused.
  bool Valid(std::string &error) const;

  // Binds host:port (port 0 picks one). Returns the bound port, or -1.
  int Bind(const std::string &address, std::string &error);
  // Serves on a listening socket the daemon inherited (systemd socket
  // activation, listen_fds.h) instead of binding one. Returns its port, or -1.
  int Adopt(int fd, std::string &error);
  // Serves on a background thread until Stop().
  void Start();
  // Answers new calls UNAVAILABLE from now on (the server is shutting
  // down); calls under way go on. Before gRPC's Shutdown.
  void Close();
  void Stop();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// The session cookie's name: "__Host-rk_session" over TLS (which browsers
// only accept with Secure, Path=/ and no Domain), else "rk_session".
const char *SessionCookieName(bool tls);

// Whether a request's Host header names this daemon: empty (not a
// browser), localhost or a *.localhost name, an IP literal (DNS rebinding
// needs a name: a browser sends an IP only when it connected to that IP),
// or one of `allowed_hosts`. The port is not compared.
bool HostHeaderAllowed(const std::string &host_header, const std::vector<std::string> &allowed_hosts);

// Splits "host:port" (IPv6 as "[::1]:port"). False if malformed.
bool SplitHostPort(const std::string &address, std::string &host, int &port);

}  // namespace revkit::api
