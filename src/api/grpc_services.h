// gRPC service implementations that forward to a Backend.
#pragma once

#include "revkit/api/backend.h"
#include "script_service.h"
#include "revkit/auth/rate_limit.h"
#include "revkit/auth/store.h"

#include <grpcpp/grpcpp.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace google::protobuf {
class Message;
}

namespace revkit::api {

grpc::Status ToGrpc(const Status &status);

// Authentication for every handler: who the caller is (from the
// `authorization: Bearer` metadata), whether the method's policy lets it
// in (auth_policy.h), and the login throttle. A null store means
// authentication is disabled: every caller is an anonymous admin.
class AuthGate {
 public:
  AuthGate(std::shared_ptr<auth::Store> store, std::string gateway_secret);

  bool enabled() const { return store_ != nullptr; }
  auth::Store *store() const { return store_.get(); }
  auth::LoginLimiter &limiter() { return limiter_; }
  const std::string &gateway_secret() const { return gateway_secret_; }

  // The bearer secret the call carries ("" if none).
  static std::string Bearer(const grpc::ServerContext *ctx);
  // The caller, or nullopt when it sent no valid credentials.
  std::optional<auth::Principal> Identify(const grpc::ServerContext *ctx) const;
  // Identifies and authorizes a call to `method` ("revkit.v1.X/Y").
  Status Check(const grpc::ServerContext *ctx, const char *method, const google::protobuf::Message &request,
               std::optional<auth::Principal> &who) const;
  // The client's address: the browser's when the call came through our own
  // HTTP gateway (which proves it with gateway_secret), else the peer's.
  std::string ClientAddress(const grpc::ServerContext *ctx) const;

 private:
  std::shared_ptr<auth::Store> store_;
  std::string gateway_secret_;
  auth::LoginLimiter limiter_;
};

// What GetServerInfo says about the process (feature "daemon-info").
struct DaemonInfo {
  std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();
  // argv; reported to admins only.
  std::vector<std::string> launch_args;
  bool socket_activated = false;
  // MetaService.RestartDaemon (feature "daemon-restart"); see ServerOptions.
  std::function<void()> restart;
  std::string restart_mode;
  // Subscribe streams open now (RestartDaemon reports them).
  std::shared_ptr<std::atomic<int>> open_streams = std::make_shared<std::atomic<int>>(0);
};

// Owns one instance of every revkit.v1 service. `stopping` is shared with
// the server so long-lived subscription streams end promptly on shutdown.
class GrpcServices {
 public:
  // `scripts` configures ScriptService; `script_target` is where its
  // hosts connect, filled in once the gRPC listener is bound.
  GrpcServices(std::shared_ptr<Backend> backend, std::shared_ptr<std::atomic<bool>> stopping,
               std::shared_ptr<AuthGate> auth, ScriptServiceOptions scripts = {},
               std::shared_ptr<ScriptHostTarget> script_target = nullptr, DaemonInfo info = {});
  ~GrpcServices();

  void RegisterAll(grpc::ServerBuilder &builder);

 private:
  std::vector<std::unique_ptr<grpc::Service>> services_;
};

// AuthService (auth_service.cc).
std::unique_ptr<grpc::Service> MakeAuthService(std::shared_ptr<AuthGate> gate);

// The metadata key the HTTP gateway proves itself with, and the one it
// passes the browser's address in.
inline constexpr const char *kGatewayMetadata = "x-rk-gateway";
inline constexpr const char *kForwardedForMetadata = "x-forwarded-for";

}  // namespace revkit::api
