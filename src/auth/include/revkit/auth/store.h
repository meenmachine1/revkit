// Accounts, API tokens and sessions for rk-daemon, kept in one text file
// (docs/security.md, "Where credentials live"):
//
//   <project-dir>/.revkit/auth.db, or --auth-file
//
// The file holds scrypt hashes of passwords and SHA-256 hashes of token and
// session secrets, never a secret itself. It is written atomically (a
// temporary file renamed over it, mode 0600) under an flock on
// "<file>.lock", and re-read when it changes, so `rk-daemon user ...` and
// `rk-daemon token ...` can manage a running daemon's accounts: the daemon
// sees a change within a second.
//
// Bearer secrets:
//   rks_<43 chars>             a session (Login), expiring after session_ttl
//   rkt_<16 hex>_<43 chars>    an API token; the hex part is its public id
//   rkr_<16 hex>_<43 chars>    a run token (a script the daemon runs for a
//                              caller): in memory only, never in the file
//   anything else              compared with the shared peer secret, if any
#pragma once

#include "revkit/auth/password.h"

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::auth {

// Numeric values match revkit.v1.Role.
enum class Role : int { kNone = 0, kViewer = 1, kEditor = 2, kAdmin = 3, kPeer = 4 };

std::optional<Role> role_from_string(std::string_view s);  // "viewer", "editor", "admin", "peer"
const char *to_string(Role r);
// Whether a caller with `have` may call a method needing `need`. kNone is a
// public method. Viewer < editor < admin; peer is separate and only
// satisfies peer (and public) methods.
bool role_allows(Role have, Role need);

// Numeric values match revkit.v1.PrincipalKind and revkit.v1.AuthMethod.
enum class PrincipalKind : int { kUser = 1, kAgent = 2, kPeer = 3, kAnonymous = 4 };
enum class AuthMethod : int { kNone = 1, kSession = 2, kToken = 3, kPeerSecret = 4 };

// An authenticated caller.
struct Principal {
  PrincipalKind kind = PrincipalKind::kAnonymous;
  std::string name;
  Role role = Role::kNone;
  std::vector<std::string> projects;  // empty: every project
  AuthMethod method = AuthMethod::kNone;
  std::int64_t expires_at = 0;        // unix seconds; 0: never
  std::string csrf;                   // sessions only
  std::string token_id;               // API tokens only

  bool may_use_project(std::string_view project) const;
  // "user:alice", "agent:ci-bot", "peer:secret".
  std::string display() const;
};

struct UserRecord {
  std::string name;
  Role role = Role::kViewer;
  std::string password_hash;
  std::vector<std::string> projects;
  std::int64_t created_at = 0;
};

struct TokenRecord {
  std::string id;
  std::string name;
  Role role = Role::kViewer;
  std::string user;  // empty: an agent token
  std::vector<std::string> projects;
  std::int64_t created_at = 0;
  std::int64_t expires_at = 0;  // 0: never
  std::string hash;             // hex SHA-256 of the secret
};

struct SessionRecord {
  std::string hash;  // hex SHA-256 of the session token
  std::string user;
  std::int64_t created_at = 0;
  std::int64_t expires_at = 0;
  std::string csrf;
};

class AuthError : public std::runtime_error {
 public:
  enum class Code { kInvalidArgument, kNotFound, kAlreadyExists, kIo };
  AuthError(Code code, const std::string &message) : std::runtime_error(message), code_(code) {}
  Code code() const { return code_; }

 private:
  Code code_;
};

struct StoreOptions {
  std::string path;
  std::int64_t session_ttl_seconds = 7 * 24 * 3600;
  ScryptParams scrypt{};
  // Accepted from peer daemons when non-empty (--peer-secret-file); at
  // least 32 characters.
  std::string peer_secret;
  // Unix seconds; tests replace it.
  std::function<std::int64_t()> now;
};

// Account names: 1-64 of [A-Za-z0-9._@-]. Project lists: ids without
// whitespace or commas.
bool valid_account_name(std::string_view name);
bool valid_project_id(std::string_view id);
// Passwords: 8 to 1024 bytes.
bool valid_password(std::string_view password);

class Store {
 public:
  explicit Store(StoreOptions options);
  Store(const Store &) = delete;
  Store &operator=(const Store &) = delete;

  const std::string &path() const { return opt_.path; }
  std::int64_t now() const;

  // Accounts. Throw AuthError.
  UserRecord add_user(const std::string &name, Role role, std::string_view password,
                      const std::vector<std::string> &projects = {});
  // Also removes the account's sessions and the tokens issued to it.
  void delete_user(const std::string &name);
  // A new password or role ends the account's sessions.
  UserRecord update_user(const std::string &name, std::optional<Role> role, std::optional<std::string> password,
                         std::optional<std::vector<std::string>> projects);
  std::vector<UserRecord> users();
  std::optional<UserRecord> user(const std::string &name);

  // API tokens.
  struct NewToken {
    TokenRecord record;
    std::string secret;
  };
  NewToken create_token(const std::string &name, Role role, const std::string &user = "",
                        const std::vector<std::string> &projects = {}, std::int64_t ttl_seconds = 0);
  // By id or name; false if none matched.
  bool revoke_token(const std::string &id_or_name);
  std::vector<TokenRecord> tokens();

  // Sessions. login returns nullopt for a wrong name or password (and
  // spends the same time either way).
  struct NewSession {
    std::string token;
    Principal principal;
  };
  std::optional<NewSession> login(const std::string &name, std::string_view password);
  // Checks the password of an existing session's account and replaces it,
  // ending its other sessions. False if `old_password` is wrong.
  bool change_password(const std::string &name, std::string_view old_password, std::string_view new_password,
                       const std::string &keep_session_token);
  // Ends the session with this token; false if there was none.
  bool logout(std::string_view session_token);

  // The caller a bearer secret names, or nullopt.
  std::optional<Principal> authenticate(std::string_view bearer);

  // Run tokens (ScriptService, docs/scripting.md): a bearer the daemon
  // gives a script host it starts, which authenticates as `as` (its kind,
  // name, role and projects) until revoked or `ttl_seconds` pass. Kept in
  // memory only. Each use re-derives the principal from the account (or the
  // API token) `as` came from, so deleting the account, revoking the token
  // or lowering the role applies to running scripts at once. The principal
  // it yields has method kToken and token_id "run:<id>". Returns the
  // secret; `id` names it for revoke_run_token.
  std::string mint_run_token(const Principal &as, std::int64_t ttl_seconds, std::string &id);
  void revoke_run_token(const std::string &id);
  std::size_t run_token_count();

  // No accounts and no tokens.
  bool empty();
  // Re-reads the file now (normally done at most once a second).
  void reload();

 private:
  struct Data {
    std::map<std::string, UserRecord> users;
    std::map<std::string, TokenRecord> tokens;      // by id
    std::map<std::string, SessionRecord> sessions;  // by hash
  };
  struct FileStamp {
    std::uint64_t ino = 0, size = 0;
    std::int64_t mtime_ns = -1;
    bool operator==(const FileStamp &) const = default;
  };

  // Each runs `fn` on fresh data under the in-process mutex and the file
  // lock, then writes the file. Callers hold neither.
  template <class Fn>
  auto mutate(Fn &&fn);
  void refresh_locked(bool force);
  void load_locked();
  void save_locked();
  Principal user_principal_locked(const UserRecord &u) const;
  std::optional<Principal> lookup_locked(std::string_view bearer) const;

  struct RunToken {
    std::string hash;
    Principal as;
    std::int64_t expires_at = 0;
  };
  std::optional<Principal> run_token_locked(std::string_view bearer) const;

  StoreOptions opt_;
  std::mutex mu_;
  std::map<std::string, RunToken> run_tokens_;  // by id
  Data data_;
  FileStamp stamp_;
  std::int64_t last_check_ms_ = 0;
};

}  // namespace revkit::auth
