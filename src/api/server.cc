#include "revkit/api/server.h"

#include "connect_gateway.h"
#include "grpc_services.h"

#include "revkit/api/listen_fds.h"

#include "revkit/auth/crypto.h"
#include "revkit/auth/store.h"
#include "revkit/auth/tls.h"

#include <grpcpp/grpcpp.h>
#ifdef REVKIT_GRPC_REFLECTION
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#endif

#include <unistd.h>

#include <atomic>
#include <cstring>
#include <condition_variable>
#include <mutex>

namespace revkit::api {

bool IsLoopbackAddress(const std::string &address) {
  if (address.starts_with("unix:") || address.starts_with("unix-abstract:")) return true;
  std::string host;
  int port = 0;
  if (!SplitHostPort(address, host, port)) return false;
  return host == "localhost" || host == "::1" || host == "ip6-localhost" || host.starts_with("127.");
}

struct Server::Impl {
  std::shared_ptr<std::atomic<bool>> stopping = std::make_shared<std::atomic<bool>>(false);
  std::unique_ptr<GrpcServices> services;
  std::unique_ptr<grpc::Server> grpc;
  std::unique_ptr<ConnectGateway> gateway;
  // The other loopback family's listener on the same port (127.0.0.1 and
  // ::1 both, so http://revkit.localhost works whichever a browser tries).
  std::unique_ptr<ConnectGateway> gateway_also;
  std::string http_also_address;
  int grpc_port = 0;
  int http_port = 0;
  std::string http_address;

  enum class State { kRunning, kStopping, kStopped };
  std::mutex mu;
  std::condition_variable cv;
  State state = State::kRunning;
};

Server::Server(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

Server::~Server() { Shutdown(); }

std::unique_ptr<Server> Server::Start(std::shared_ptr<Backend> backend, const ServerOptions &options,
                                      std::string &error) {
  // An inherited HTTP socket (socket activation) is judged by where it
  // listens, like an address given on the command line.
  std::string http_address = options.http_address;
  if (options.http_fd >= 0) {
    http_address = SocketAddress(options.http_fd);
    if (http_address.empty()) {
      error = "the inherited HTTP socket (descriptor " + std::to_string(options.http_fd) +
              ") is not a listening TCP socket";
      return nullptr;
    }
  }
  // Plaintext and unauthenticated listeners stay on this host.
  for (const std::string *addr : {&options.grpc_address, static_cast<const std::string *>(&http_address)}) {
    if (addr->empty() || IsLoopbackAddress(*addr)) continue;
    if (!options.auth) {
      error = "refusing to listen on " + *addr + " without authentication: --no-auth is for loopback addresses only";
      return nullptr;
    }
    if (!options.tls.enabled() && !options.insecure_allow_remote) {
      error = "refusing plaintext on " + *addr +
              ": give a certificate (--tls-cert and --tls-key, or --tls-self-signed), or accept the risk with "
              "--insecure-allow-remote";
      return nullptr;
    }
  }

  if (options.tls.enabled()) {
    std::string why;
    if (!auth::check_cert_key({options.tls.cert_pem, options.tls.key_pem}, why)) {
      error = "TLS: " + why;
      return nullptr;
    }
  }

  auto impl = std::make_unique<Impl>();
  // Proves to the gRPC handlers that a call came through our own gateway, so
  // they may trust the browser address it forwards (login throttling).
  const std::string gateway_secret = auth::base64url(auth::random_bytes(32));
  auto gate = std::make_shared<AuthGate>(options.auth, gateway_secret);
  // Scripts (ScriptService): on by default only when nothing listens
  // beyond loopback; their hosts connect to the gRPC listener.
  ScriptServiceOptions scripts;
  scripts.host = options.scripts;
  scripts.all_loopback = true;
  for (const std::string *addr : {&options.grpc_address, static_cast<const std::string *>(&http_address)})
    if (!addr->empty() && !IsLoopbackAddress(*addr)) scripts.all_loopback = false;
  auto script_target = std::make_shared<ScriptHostTarget>();
  DaemonInfo info;
  info.launch_args = options.launch_args;
  info.socket_activated = options.http_fd >= 0;
  info.restart = options.restart;
  info.restart_mode = options.restart_mode;
  impl->services = std::make_unique<GrpcServices>(std::move(backend), impl->stopping, gate, std::move(scripts),
                                                  script_target, std::move(info));

#ifdef REVKIT_GRPC_REFLECTION
  if (options.reflection) grpc::reflection::InitProtoReflectionServerBuilderPlugin();
#endif
  grpc::ServerBuilder builder;
  const int max_bytes = static_cast<int>(options.max_message_bytes);
  builder.SetMaxReceiveMessageSize(max_bytes);
  builder.SetMaxSendMessageSize(max_bytes);
  if (!options.grpc_address.empty()) {
    std::shared_ptr<grpc::ServerCredentials> creds = grpc::InsecureServerCredentials();
    if (options.tls.enabled()) {
      grpc::SslServerCredentialsOptions ssl;
      ssl.pem_key_cert_pairs.push_back({options.tls.key_pem, options.tls.cert_pem});
      creds = grpc::SslServerCredentials(ssl);
    }
    builder.AddListeningPort(options.grpc_address, creds, &impl->grpc_port);
  }
  impl->services->RegisterAll(builder);
  impl->grpc = builder.BuildAndStart();
  if (!impl->grpc || (!options.grpc_address.empty() && impl->grpc_port == 0)) {
    error = "cannot start gRPC server on " + options.grpc_address;
    return nullptr;
  }
  if (impl->grpc_port) {
    // A wildcard bind is reached on loopback; a named host as it is.
    std::string host;
    int port = 0;
    if (!SplitHostPort(options.grpc_address, host, port) || host.empty() || host == "0.0.0.0" || host == "::" ||
        host == "[::]")
      host = "127.0.0.1";
    if (host.find(':') != std::string::npos && host.front() != '[') host = "[" + host + "]";
    std::lock_guard lock(script_target->mu);
    script_target->grpc_target = host + ":" + std::to_string(impl->grpc_port);
    if (options.tls.enabled()) script_target->tls_fingerprint = auth::fingerprint_sha256(options.tls.cert_pem);
  }

  if (!http_address.empty()) {
    grpc::ChannelArguments args;
    args.SetMaxReceiveMessageSize(max_bytes);
    args.SetMaxSendMessageSize(max_bytes);
    GatewayOptions gw;
    gw.allowed_origins = options.allowed_origins;
    gw.web_root = options.web_root;
    gw.max_message_bytes = options.max_message_bytes;
    gw.auth = options.auth;
    gw.gateway_secret = gateway_secret;
    gw.tls = options.tls;
    gw.allowed_hosts = options.allowed_hosts;
    if (options.tls.enabled())
      for (std::string &h : auth::certificate_hosts(options.tls.cert_pem)) gw.allowed_hosts.push_back(std::move(h));
    if (!IsLoopbackAddress(http_address)) {
      // Beyond loopback: the name it listens on, and the machine's.
      std::string host;
      int port = 0;
      if (SplitHostPort(http_address, host, port)) gw.allowed_hosts.push_back(host);
      char name[256] = {};
      if (::gethostname(name, sizeof name - 1) == 0 && *name) {
        gw.allowed_hosts.emplace_back(name);
        if (!std::strchr(name, '.')) gw.allowed_hosts.push_back(std::string(name) + ".local");
      }
    }
    impl->gateway = std::make_unique<ConnectGateway>(impl->grpc->InProcessChannel(args), gw);
    if (!impl->gateway->Valid(error)) {
      impl->stopping->store(true);
      impl->grpc->Shutdown();
      return nullptr;
    }
    impl->http_port = options.http_fd >= 0 ? impl->gateway->Adopt(options.http_fd, error)
                                           : impl->gateway->Bind(options.http_address, error);
    if (impl->http_port < 0) {
      impl->stopping->store(true);
      impl->grpc->Shutdown();
      return nullptr;
    }
    impl->gateway->Start();
    // A loopback listener named by address (not one systemd passed) listens
    // on the other loopback family too, on the same port, when it can.
    {
      std::string host;
      int port = 0;
      std::vector<std::string> others;
      if (options.http_fd < 0 && options.http_also_loopback && SplitHostPort(options.http_address, host, port)) {
        if (host == "127.0.0.1") others = {"[::1]"};
        else if (host == "::1") others = {"127.0.0.1"};
        else if (host == "localhost") others = {"127.0.0.1", "[::1]"};
      }
      for (const std::string &other : others) {
        auto also = std::make_unique<ConnectGateway>(impl->grpc->InProcessChannel(args), gw);
        std::string ignored;
        const std::string address = other + ":" + std::to_string(impl->http_port);
        if (!also->Valid(ignored) || also->Bind(address, ignored) != impl->http_port) continue;
        also->Start();
        impl->gateway_also = std::move(also);
        impl->http_also_address = address;
        break;
      }
    }
    // With port 0, the port bound.
    std::string host;
    int port = 0;
    impl->http_address = SplitHostPort(http_address, host, port)
                             ? (host.find(':') != std::string::npos && host.front() != '[' ? "[" + host + "]" : host) +
                                   ":" + std::to_string(impl->http_port)
                             : http_address;
  }
  return std::unique_ptr<Server>(new Server(std::move(impl)));
}

int Server::grpc_port() const { return impl_->grpc_port; }
int Server::http_port() const { return impl_->http_port; }
const std::string &Server::http_address() const { return impl_->http_address; }
const std::string &Server::http_also_address() const { return impl_->http_also_address; }

void Server::Shutdown() {
  std::unique_lock lock(impl_->mu);
  if (impl_->state != Impl::State::kRunning) {
    // Someone else is shutting down; return only once they are done, so a
    // caller may destroy the server right after.
    impl_->cv.wait(lock, [&] { return impl_->state == Impl::State::kStopped; });
    return;
  }
  impl_->state = Impl::State::kStopping;
  lock.unlock();

  // Order matters: subscription handlers see `stopping` and end their
  // streams, which lets gateway workers relaying them finish; then gRPC
  // cancels whatever is left after a grace period; then the HTTP server can
  // join its (now idle) workers.
  impl_->stopping->store(true);
  // No new browser call may reach gRPC once it is shutting down.
  if (impl_->gateway) impl_->gateway->Close();
  if (impl_->gateway_also) impl_->gateway_also->Close();
  impl_->grpc->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(2));
  if (impl_->gateway) impl_->gateway->Stop();
  if (impl_->gateway_also) impl_->gateway_also->Stop();

  lock.lock();
  impl_->state = Impl::State::kStopped;
  impl_->cv.notify_all();
}

void Server::Wait() {
  std::unique_lock lock(impl_->mu);
  impl_->cv.wait(lock, [&] { return impl_->state == Impl::State::kStopped; });
}

}  // namespace revkit::api
