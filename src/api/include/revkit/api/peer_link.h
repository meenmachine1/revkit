// Replication between daemons (docs/collab.md): a PeerLink keeps every
// project of a local backend in sync with one peer daemon, in both
// directions, through the peer's SyncService.
//
// For each project either side has, it runs two loops:
//   inbound   Pull from the peer (catch-up from our version vector, then
//             live), Push each batch into the local backend; fetch the
//             files of programs the peer imported.
//   outbound  Pull from the local backend (catch-up from the peer's version
//             vector, then live), Push each batch to the peer; send it the
//             files it reports missing.
// Either loop reconnects with backoff after an error and starts again from
// a fresh version-vector exchange, so a partition heals by anti-entropy.
// Ops relayed from third daemons flow on: a chain or a mesh of links
// converges. Presence rides the same streams.
//
// The link authenticates to the peer with a bearer token (a ROLE_PEER API
// token the peer issued, or the daemons' shared peer secret) and, over TLS,
// checks the peer's certificate against system roots, a CA file, or one
// pinned certificate (docs/security.md).
#pragma once

#include "revkit/api/backend.h"

#include <chrono>
#include <memory>
#include <string>

namespace revkit::api {

struct PeerLinkOptions {
  // The peer's gRPC address, "host:port" ("grpc://" or "http://" prefixes
  // are accepted and dropped).
  std::string target;
  // Our name, for the peer's logs.
  std::string name = "rk-daemon";
  // How often to look for projects that aren't linked yet.
  std::chrono::milliseconds rescan{1000};
  // Reconnect backoff.
  std::chrono::milliseconds min_backoff{100};
  std::chrono::milliseconds max_backoff{5000};
  // Relay presence.
  bool presence = true;
  // Log connections and errors to stderr.
  bool verbose = false;
  // Sent as `authorization: Bearer <token>` on every call; empty for a peer
  // running without authentication.
  std::string bearer_token;
  // TLS: connect with TLS, trusting these PEM roots (empty: the system's).
  // A pinned self-signed certificate is its own root.
  bool tls = false;
  std::string tls_root_pem;
  // The name to check the peer's certificate against, when it isn't the
  // target's host (a pinned self-signed certificate always has
  // "localhost").
  std::string tls_server_name;
};

class PeerLink {
 public:
  PeerLink(std::shared_ptr<Backend> local, PeerLinkOptions options);
  // Stops both loops of every project (cancelling open calls) and joins.
  ~PeerLink();
  PeerLink(const PeerLink &) = delete;
  PeerLink &operator=(const PeerLink &) = delete;

  const std::string &target() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace revkit::api
