// Serves a Backend over two transports from one process:
//
//   * gRPC over HTTP/2 for native clients (Python SDK, CLI, MCP server).
//   * Connect and gRPC-web over HTTP/1.1 for browsers, from an embedded HTTP
//     server that also serves the static web bundle. It forwards each call
//     to the gRPC server through an in-process channel, so both transports
//     run the same handlers, interceptors and limits (see docs/api.md).
#pragma once

#include "revkit/api/backend.h"

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace revkit::auth {
class Store;
}

namespace revkit::api {

// PEM certificate (chain) and private key for both listeners.
struct TlsConfig {
  std::string cert_pem;
  std::string key_pem;
  bool enabled() const { return !cert_pem.empty(); }
};

// The daemon's script host (ScriptService, docs/scripting.md): which
// callers it runs Python scripts for and where the scripts live.
struct ScriptHostOptions {
  // Who may run scripts: "" decides (editor and above when every listener
  // is on loopback, nobody otherwise); "off"; "viewer" (everyone: a
  // viewer's runs and consoles read but can't edit); "editor"; "admin".
  // (rk-daemon --scripts-host-role.) A script is full Python with the
  // daemon's user's rights.
  std::string role;
  // The Python to run scripts with (--script-python); empty: the first of
  // $REVKIT_PYTHON, ~/.local/share/revkit/pyenv/bin/python and python3
  // that can import revkit.
  std::string python;
  // The per-user library (default ~/.config/revkit/scripts) and the trust
  // pins (default ~/.config/revkit/trusted-scripts).
  std::string user_dir;
  std::string trust_file;
  // Per-project libraries: <project_dir>/<project>/scripts (--project-dir).
  std::string project_dir;
  // The shipped library: the first directory holding a script wins.
  std::vector<std::string> shipped_dirs;
  // The source tree's sdk/python, tried on PYTHONPATH when no Python
  // imports revkit by itself.
  std::string sdk_pythonpath;
  // What SetupScriptPython installs: the first of these that holds a
  // revkit-*.whl (the newest), or is an SDK source tree (pyproject.toml):
  // share/revkit/python, share/revkit/sdk, the source tree's sdk/python.
  std::vector<std::string> sdk_sources;
  // The Python SetupScriptPython makes the environment from
  // (--script-setup-python); empty: python3 on PATH.
  std::string setup_python;
  // Runs at once, all callers together.
  unsigned max_runs = 8;
  // Python consoles (RunScript interactive): one per caller and program,
  // at most this many at once; one idle this long is closed
  // (--console-idle-timeout; 0: never).
  unsigned max_consoles = 16;
  unsigned console_idle_seconds = 1800;
};

struct ServerOptions {
  // host:port for gRPC; port 0 picks a free port. Empty: no gRPC listener
  // (the HTTP gateway still works through the in-process channel).
  std::string grpc_address = "127.0.0.1:50051";
  // host:port for Connect/gRPC-web/static files; port 0 picks a free port.
  // Empty: no HTTP listener.
  std::string http_address = "127.0.0.1:50052";
  // A listening socket inherited from the service manager (systemd socket
  // activation; listen_fds.h) to serve HTTP on instead of binding
  // http_address; -1: none. The loopback, authentication and TLS rules
  // apply to the address it listens on, exactly as to http_address.
  int http_fd = -1;
  // With http_address 127.0.0.1, ::1 or localhost, also listen on the
  // other loopback family on the same port (skipped quietly when that
  // fails), so http://revkit.localhost works whichever address a browser
  // tries first. Not for a socket systemd passes.
  bool http_also_loopback = true;
  // Origins allowed to make cross-origin browser calls ("*" for any). The
  // bundle served from web_root is same-origin and needs no entry.
  std::vector<std::string> allowed_origins;
  // Host names the HTTP listener answers to besides localhost, *.localhost
  // and IP literals (DNS rebinding protection, docs/security.md): exact
  // names or "*.example.com" (rk-daemon --allow-host). The TLS
  // certificate's names are added, and on a listener beyond loopback its
  // own host name and the machine's (gethostname, and NAME.local).
  std::vector<std::string> allowed_hosts;
  // Directory served at "/" (the web UI build). Empty: none.
  std::string web_root;
  std::size_t max_message_bytes = 64u << 20;
  // Register the gRPC server reflection service (for grpcurl and friends).
  bool reflection = true;
  // Authentication and authorization (docs/security.md): the credential
  // store. Null disables both (rk-daemon --no-auth), and then both
  // listeners must be on loopback.
  std::shared_ptr<auth::Store> auth;
  // TLS for both listeners. Without it they must be on loopback, unless
  // insecure_allow_remote.
  TlsConfig tls;
  bool insecure_allow_remote = false;
  ScriptHostOptions scripts;
  // The daemon's command line, reported by GetServerInfo to admins (a
  // client's "start it again" hint; feature "daemon-info").
  std::vector<std::string> launch_args;
  // Restarts the daemon (MetaService.RestartDaemon, admins; feature
  // "daemon-restart"): rk-daemon shuts down gracefully, then runs itself
  // again (restart_mode "reexec") or exits for systemd to start it again
  // ("exit", socket activation). Called on a thread of its own shortly after
  // the reply is sent. Empty: no restarts (the RPC answers
  // FAILED_PRECONDITION and the feature isn't listed).
  std::function<void()> restart;
  std::string restart_mode = "reexec";
};

// Whether host:port (or a unix: socket) only accepts local connections.
bool IsLoopbackAddress(const std::string &address);

class Server {
 public:
  // Starts both listeners. Returns null and sets `error` on failure.
  static std::unique_ptr<Server> Start(std::shared_ptr<Backend> backend, const ServerOptions &options,
                                       std::string &error);
  ~Server();
  Server(const Server &) = delete;
  Server &operator=(const Server &) = delete;

  // Bound ports (useful with port 0); 0 when that listener is disabled.
  int grpc_port() const;
  int http_port() const;
  // The HTTP listener's address ("127.0.0.1:50052"), bound or inherited.
  const std::string &http_address() const;
  // The other loopback family's listener ("[::1]:50052"), or empty.
  const std::string &http_also_address() const;

  // Stops accepting calls, ends open streams with UNAVAILABLE and waits for
  // handlers to finish. Idempotent; the destructor calls it.
  void Shutdown();
  // Blocks until Shutdown() has been called (from another thread).
  void Wait();

 private:
  struct Impl;
  explicit Server(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
};

}  // namespace revkit::api
