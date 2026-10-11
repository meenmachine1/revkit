// AuthService: login, logout, identity, and account and token management
// over the API (docs/security.md). The same store backs `rk-daemon user`
// and `rk-daemon token`.
#include "grpc_services.h"

#include "revkit/api/auth_policy.h"
#include "revkit/v1/auth.grpc.pb.h"

#include <iostream>

namespace revkit::api {
namespace {

using auth::AuthError;

auth::Role FromPb(pb::Role r) { return static_cast<auth::Role>(static_cast<int>(r)); }
pb::Role ToPb(auth::Role r) { return static_cast<pb::Role>(static_cast<int>(r)); }

void SetTime(google::protobuf::Timestamp *t, std::int64_t seconds) {
  if (seconds) t->set_seconds(seconds);
}

pb::User ToPb(const auth::UserRecord &u) {
  pb::User out;
  out.set_name(u.name);
  out.set_role(ToPb(u.role));
  for (const auto &p : u.projects) out.add_projects(p);
  SetTime(out.mutable_created_at(), u.created_at);
  return out;
}

pb::ApiToken ToPb(const auth::TokenRecord &t) {
  pb::ApiToken out;
  out.set_id(t.id);
  out.set_name(t.name);
  out.set_role(ToPb(t.role));
  out.set_user(t.user);
  for (const auto &p : t.projects) out.add_projects(p);
  SetTime(out.mutable_created_at(), t.created_at);
  if (t.expires_at) SetTime(out.mutable_expires_at(), t.expires_at);
  return out;
}

Status FromAuthError(const AuthError &e) {
  switch (e.code()) {
    case AuthError::Code::kInvalidArgument: return Error(StatusCode::kInvalidArgument, e.what());
    case AuthError::Code::kNotFound: return Error(StatusCode::kNotFound, e.what());
    case AuthError::Code::kAlreadyExists: return Error(StatusCode::kAlreadyExists, e.what());
    case AuthError::Code::kIo: break;
  }
  return Error(StatusCode::kInternal, e.what());
}

std::vector<std::string> Projects(const google::protobuf::RepeatedPtrField<std::string> &p) { return {p.begin(), p.end()}; }

Status Disabled() {
  return Error(StatusCode::kFailedPrecondition, "authentication is disabled on this daemon (rk-daemon --no-auth)");
}

void Log(const std::string &msg) { std::cerr << "rk-daemon: auth: " << msg << std::endl; }

template <class Fn>
grpc::Status Guarded(Fn &&fn) {
  try {
    return ToGrpc(fn());
  } catch (const AuthError &e) {
    return ToGrpc(FromAuthError(e));
  } catch (const std::exception &e) {
    return {grpc::StatusCode::INTERNAL, std::string("auth error: ") + e.what()};
  }
}

class AuthServiceImpl final : public pb::AuthService::Service {
 public:
  explicit AuthServiceImpl(std::shared_ptr<AuthGate> gate) : gate_(std::move(gate)) {}

  grpc::Status Login(grpc::ServerContext *ctx, const pb::LoginRequest *req, pb::LoginResponse *resp) override {
    return Guarded([&] {
      std::optional<auth::Principal> who;
      if (Status st = gate_->Check(ctx, "revkit.v1.AuthService/Login", *req, who); !st.ok()) return st;
      if (!gate_->enabled()) return Disabled();
      const std::string addr = gate_->ClientAddress(ctx);
      // Bounded keys: account names are at most 64 characters.
      const std::vector<std::string> keys = {"ip:" + addr.substr(0, 64), "user:" + req->username().substr(0, 64)};
      if (auto wait = gate_->limiter().check(keys); wait.count() > 0)
        return Error(StatusCode::kResourceExhausted,
                     "too many failed logins; try again in " + std::to_string(wait.count()) + " s");
      // An over-long password can't be right; don't spend scrypt on it.
      std::optional<auth::Store::NewSession> session;
      if (req->password().size() <= 1024 && req->username().size() <= 64)
        session = gate_->store()->login(req->username(), req->password());
      if (!session) {
        gate_->limiter().failure(keys);
        Log("failed login as \"" + req->username().substr(0, 64) + "\" from " + addr);
        return Error(StatusCode::kUnauthenticated, "wrong account name or password");
      }
      gate_->limiter().success(keys);
      Log(session->principal.display() + " logged in from " + addr +
          (req->client().empty() ? "" : " (" + req->client().substr(0, 64) + ")"));
      resp->set_token(session->token);
      SetTime(resp->mutable_expires_at(), session->principal.expires_at);
      *resp->mutable_identity() = ToIdentity(session->principal);
      resp->set_csrf_token(session->principal.csrf);
      return Status::Ok();
    });
  }

  grpc::Status Logout(grpc::ServerContext *ctx, const pb::LogoutRequest *req, pb::LogoutResponse *) override {
    return Guarded([&] {
      std::optional<auth::Principal> who;
      if (Status st = gate_->Check(ctx, "revkit.v1.AuthService/Logout", *req, who); !st.ok()) return st;
      if (gate_->enabled() && who->method == auth::AuthMethod::kSession) {
        gate_->store()->logout(AuthGate::Bearer(ctx));
        Log(who->display() + " logged out");
      }
      return Status::Ok();
    });
  }

  grpc::Status WhoAmI(grpc::ServerContext *ctx, const pb::WhoAmIRequest *req, pb::WhoAmIResponse *resp) override {
    return Guarded([&] {
      std::optional<auth::Principal> who;
      if (Status st = gate_->Check(ctx, "revkit.v1.AuthService/WhoAmI", *req, who); !st.ok()) return st;
      resp->set_auth_enabled(gate_->enabled());
      if (who) {
        *resp->mutable_identity() = ToIdentity(*who);
        if (who->method == auth::AuthMethod::kSession) resp->set_csrf_token(who->csrf);
      }
      return Status::Ok();
    });
  }

  grpc::Status ChangePassword(grpc::ServerContext *ctx, const pb::ChangePasswordRequest *req,
                              pb::ChangePasswordResponse *) override {
    return Guarded([&] {
      std::optional<auth::Principal> who;
      if (Status st = gate_->Check(ctx, "revkit.v1.AuthService/ChangePassword", *req, who); !st.ok()) return st;
      if (!gate_->enabled()) return Disabled();
      if (who->method != auth::AuthMethod::kSession)
        return Error(StatusCode::kFailedPrecondition, "log in (AuthService.Login) to change your password");
      const std::vector<std::string> keys = {"user:" + who->name};
      if (auto wait = gate_->limiter().check(keys); wait.count() > 0)
        return Error(StatusCode::kResourceExhausted,
                     "too many wrong passwords; try again in " + std::to_string(wait.count()) + " s");
      if (!gate_->store()->change_password(who->name, req->old_password(), req->new_password(), AuthGate::Bearer(ctx))) {
        gate_->limiter().failure(keys);
        return Error(StatusCode::kPermissionDenied, "the old password is wrong");
      }
      Log(who->display() + " changed their password");
      return Status::Ok();
    });
  }

  grpc::Status ListUsers(grpc::ServerContext *ctx, const pb::ListUsersRequest *req,
                         pb::ListUsersResponse *resp) override {
    return Admin(ctx, "ListUsers", *req, [&](const auth::Principal &) {
      for (const auto &u : gate_->store()->users()) *resp->add_users() = ToPb(u);
      return Status::Ok();
    });
  }

  grpc::Status CreateUser(grpc::ServerContext *ctx, const pb::CreateUserRequest *req,
                          pb::CreateUserResponse *resp) override {
    return Admin(ctx, "CreateUser", *req, [&](const auth::Principal &who) {
      auto u = gate_->store()->add_user(req->name(), FromPb(req->role()), req->password(), Projects(req->projects()));
      *resp->mutable_user() = ToPb(u);
      Log(who.display() + " created account " + u.name + " (" + auth::to_string(u.role) + ")");
      return Status::Ok();
    });
  }

  grpc::Status UpdateUser(grpc::ServerContext *ctx, const pb::UpdateUserRequest *req,
                          pb::UpdateUserResponse *resp) override {
    return Admin(ctx, "UpdateUser", *req, [&](const auth::Principal &who) {
      std::optional<auth::Role> role;
      if (req->role() != pb::ROLE_UNSPECIFIED) role = FromPb(req->role());
      std::optional<std::string> password;
      if (!req->password().empty()) password = req->password();
      std::optional<std::vector<std::string>> projects;
      if (req->set_projects()) projects = Projects(req->projects());
      auto u = gate_->store()->update_user(req->name(), role, password, projects);
      *resp->mutable_user() = ToPb(u);
      Log(who.display() + " updated account " + u.name);
      return Status::Ok();
    });
  }

  grpc::Status DeleteUser(grpc::ServerContext *ctx, const pb::DeleteUserRequest *req, pb::DeleteUserResponse *) override {
    return Admin(ctx, "DeleteUser", *req, [&](const auth::Principal &who) {
      gate_->store()->delete_user(req->name());
      Log(who.display() + " deleted account " + req->name());
      return Status::Ok();
    });
  }

  grpc::Status ListTokens(grpc::ServerContext *ctx, const pb::ListTokensRequest *req,
                          pb::ListTokensResponse *resp) override {
    return Admin(ctx, "ListTokens", *req, [&](const auth::Principal &) {
      for (const auto &t : gate_->store()->tokens()) *resp->add_tokens() = ToPb(t);
      return Status::Ok();
    });
  }

  grpc::Status CreateToken(grpc::ServerContext *ctx, const pb::CreateTokenRequest *req,
                           pb::CreateTokenResponse *resp) override {
    return Admin(ctx, "CreateToken", *req, [&](const auth::Principal &who) {
      if (req->ttl_seconds() > (std::uint64_t{1} << 40))
        return Error(StatusCode::kInvalidArgument, "ttl_seconds is too large");
      auto t = gate_->store()->create_token(req->name(), FromPb(req->role()), req->user(), Projects(req->projects()),
                                            static_cast<std::int64_t>(req->ttl_seconds()));
      *resp->mutable_token() = ToPb(t.record);
      resp->set_secret(t.secret);
      Log(who.display() + " created token " + t.record.name + " (" + auth::to_string(t.record.role) + ")");
      return Status::Ok();
    });
  }

  grpc::Status RevokeToken(grpc::ServerContext *ctx, const pb::RevokeTokenRequest *req,
                           pb::RevokeTokenResponse *) override {
    return Admin(ctx, "RevokeToken", *req, [&](const auth::Principal &who) {
      if (!gate_->store()->revoke_token(req->id())) return Error(StatusCode::kNotFound, "no token \"" + req->id() + "\"");
      Log(who.display() + " revoked token " + req->id());
      return Status::Ok();
    });
  }

 private:
  template <class Req, class Fn>
  grpc::Status Admin(grpc::ServerContext *ctx, const char *method, const Req &req, Fn &&fn) {
    return Guarded([&] {
      std::optional<auth::Principal> who;
      const std::string m = std::string("revkit.v1.AuthService/") + method;
      if (Status st = gate_->Check(ctx, m.c_str(), req, who); !st.ok()) return st;
      if (!gate_->enabled()) return Disabled();
      return fn(*who);
    });
  }

  std::shared_ptr<AuthGate> gate_;
};

}  // namespace

std::unique_ptr<grpc::Service> MakeAuthService(std::shared_ptr<AuthGate> gate) {
  return std::make_unique<AuthServiceImpl>(std::move(gate));
}

}  // namespace revkit::api
