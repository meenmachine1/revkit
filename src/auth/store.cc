#include "revkit/auth/store.h"

#include "revkit/auth/crypto.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>

namespace revkit::auth {
namespace {

namespace fs = std::filesystem;

constexpr const char *kHeader = "revkit-auth 1";

std::string join(const std::vector<std::string> &v) {
  if (v.empty()) return "*";
  std::string out;
  for (const auto &s : v) out += (out.empty() ? "" : ",") + s;
  return out;
}

std::vector<std::string> split_projects(std::string_view s) {
  std::vector<std::string> out;
  if (s == "*" || s.empty()) return out;
  for (std::size_t start = 0;;) {
    auto comma = s.find(',', start);
    std::string_view p = s.substr(start, comma == std::string_view::npos ? std::string_view::npos : comma - start);
    if (!p.empty()) out.emplace_back(p);
    if (comma == std::string_view::npos) break;
    start = comma + 1;
  }
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

std::vector<std::string> normalized(std::vector<std::string> v) {
  for (const auto &p : v)
    if (!valid_project_id(p)) throw AuthError(AuthError::Code::kInvalidArgument, "invalid project id \"" + p + "\"");
  std::sort(v.begin(), v.end());
  v.erase(std::unique(v.begin(), v.end()), v.end());
  return v;
}

// Projects both lists allow (empty = all).
std::vector<std::string> intersect(const std::vector<std::string> &a, const std::vector<std::string> &b) {
  if (a.empty()) return b;
  if (b.empty()) return a;
  std::vector<std::string> out;
  std::set_intersection(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(out));
  // Nothing in common must not read as "everything".
  if (out.empty()) out.push_back("\x01none");
  return out;
}

std::int64_t to_i64(const std::string &s) {
  try {
    return std::stoll(s);
  } catch (...) {
    return 0;
  }
}

std::int64_t steady_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

// An exclusive flock on "<path>.lock" for the object's lifetime.
class FileLock {
 public:
  explicit FileLock(const std::string &path) {
    fd_ = ::open((path + ".lock").c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd_ < 0) throw AuthError(AuthError::Code::kIo, "cannot open " + path + ".lock: " + std::strerror(errno));
    while (::flock(fd_, LOCK_EX) != 0) {
      if (errno != EINTR) {
        ::close(fd_);
        throw AuthError(AuthError::Code::kIo, "cannot lock " + path + ".lock: " + std::strerror(errno));
      }
    }
  }
  ~FileLock() {
    ::flock(fd_, LOCK_UN);
    ::close(fd_);
  }

 private:
  int fd_ = -1;
};

}  // namespace

std::optional<Role> role_from_string(std::string_view s) {
  if (s == "viewer") return Role::kViewer;
  if (s == "editor") return Role::kEditor;
  if (s == "admin") return Role::kAdmin;
  if (s == "peer") return Role::kPeer;
  return std::nullopt;
}

const char *to_string(Role r) {
  switch (r) {
    case Role::kViewer: return "viewer";
    case Role::kEditor: return "editor";
    case Role::kAdmin: return "admin";
    case Role::kPeer: return "peer";
    case Role::kNone: break;
  }
  return "none";
}

bool role_allows(Role have, Role need) {
  if (need == Role::kNone) return true;
  if (need == Role::kPeer || have == Role::kPeer) return have == need;
  if (have == Role::kNone) return false;
  return static_cast<int>(have) >= static_cast<int>(need);
}

bool Principal::may_use_project(std::string_view project) const {
  if (projects.empty()) return true;
  return std::find(projects.begin(), projects.end(), project) != projects.end();
}

std::string Principal::display() const {
  switch (kind) {
    case PrincipalKind::kUser: return "user:" + name;
    case PrincipalKind::kAgent: return "agent:" + name;
    case PrincipalKind::kPeer: return "peer:" + name;
    case PrincipalKind::kAnonymous: break;
  }
  return "anonymous";
}

bool valid_account_name(std::string_view name) {
  if (name.empty() || name.size() > 64) return false;
  return std::all_of(name.begin(), name.end(), [](unsigned char c) {
    return std::isalnum(c) || c == '.' || c == '_' || c == '-' || c == '@';
  });
}

bool valid_project_id(std::string_view id) {
  if (id.empty() || id.size() > 128 || id == "*") return false;
  return std::all_of(id.begin(), id.end(), [](unsigned char c) { return c > 0x20 && c < 0x7f && c != ','; });
}

bool valid_password(std::string_view password) { return password.size() >= 8 && password.size() <= 1024; }

Store::Store(StoreOptions options) : opt_(std::move(options)) {
  if (opt_.path.empty()) throw AuthError(AuthError::Code::kInvalidArgument, "no auth file path");
  if (!opt_.peer_secret.empty() && opt_.peer_secret.size() < 32)
    throw AuthError(AuthError::Code::kInvalidArgument, "the peer secret must be at least 32 characters");
  std::lock_guard lock(mu_);
  refresh_locked(true);
}

std::int64_t Store::now() const {
  if (opt_.now) return opt_.now();
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

// ---------------------------------------------------------------- file I/O --

void Store::refresh_locked(bool force) {
  const std::int64_t t = steady_ms();
  if (!force && t - last_check_ms_ < 1000) return;
  last_check_ms_ = t;
  struct stat st {};
  FileStamp s;
  if (::stat(opt_.path.c_str(), &st) == 0) {
    s.ino = st.st_ino;
    s.size = static_cast<std::uint64_t>(st.st_size);
    s.mtime_ns = std::int64_t(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
  }
  if (s == stamp_) return;
  stamp_ = s;
  load_locked();
}

void Store::load_locked() {
  Data d;
  std::ifstream in(opt_.path);
  if (in) {
    std::string line;
    bool header = false;
    while (std::getline(in, line)) {
      if (line.empty() || line[0] == '#') continue;
      std::istringstream ls(line);
      std::vector<std::string> f;
      for (std::string w; ls >> w;) f.push_back(w);
      if (!header) {
        if (line != kHeader) throw AuthError(AuthError::Code::kIo, opt_.path + ": not a revkit auth file");
        header = true;
        continue;
      }
      if (f[0] == "user" && f.size() == 6) {
        UserRecord u;
        u.name = f[1];
        u.role = role_from_string(f[2]).value_or(Role::kNone);
        u.password_hash = f[3];
        u.created_at = to_i64(f[4]);
        u.projects = split_projects(f[5]);
        d.users[u.name] = std::move(u);
      } else if (f[0] == "token" && f.size() == 9) {
        TokenRecord t;
        t.id = f[1];
        t.name = f[2];
        t.role = role_from_string(f[3]).value_or(Role::kNone);
        t.user = f[4] == "-" ? "" : f[4];
        t.projects = split_projects(f[5]);
        t.created_at = to_i64(f[6]);
        t.expires_at = to_i64(f[7]);
        t.hash = f[8];
        d.tokens[t.id] = std::move(t);
      } else if (f[0] == "session" && f.size() == 6) {
        SessionRecord s;
        s.hash = f[1];
        s.user = f[2];
        s.created_at = to_i64(f[3]);
        s.expires_at = to_i64(f[4]);
        s.csrf = f[5];
        d.sessions[s.hash] = std::move(s);
      }
      // Unknown lines are skipped, so an older daemon reads a newer file.
    }
  }
  data_ = std::move(d);
}

void Store::save_locked() {
  const std::int64_t t = now();
  for (auto it = data_.sessions.begin(); it != data_.sessions.end();)
    it = it->second.expires_at <= t || !data_.users.contains(it->second.user) ? data_.sessions.erase(it) : std::next(it);

  std::ostringstream out;
  out << kHeader << "\n"
      << "# Managed by rk-daemon (rk-daemon user|token ...). Secrets are stored hashed.\n";
  for (const auto &[_, u] : data_.users)
    out << "user " << u.name << " " << to_string(u.role) << " " << u.password_hash << " " << u.created_at << " "
        << join(u.projects) << "\n";
  for (const auto &[_, k] : data_.tokens)
    out << "token " << k.id << " " << k.name << " " << to_string(k.role) << " " << (k.user.empty() ? "-" : k.user)
        << " " << join(k.projects) << " " << k.created_at << " " << k.expires_at << " " << k.hash << "\n";
  for (const auto &[_, s] : data_.sessions)
    out << "session " << s.hash << " " << s.user << " " << s.created_at << " " << s.expires_at << " " << s.csrf
        << "\n";
  const std::string text = out.str();

  const std::string tmp = opt_.path + ".tmp." + std::to_string(::getpid());
  int fd = ::open(tmp.c_str(), O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) throw AuthError(AuthError::Code::kIo, "cannot write " + tmp + ": " + std::strerror(errno));
  std::size_t done = 0;
  while (done < text.size()) {
    ssize_t n = ::write(fd, text.data() + done, text.size() - done);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) {
      ::close(fd);
      ::unlink(tmp.c_str());
      throw AuthError(AuthError::Code::kIo, "cannot write " + tmp + ": " + std::strerror(errno));
    }
    done += static_cast<std::size_t>(n);
  }
  ::fsync(fd);
  ::close(fd);
  if (::rename(tmp.c_str(), opt_.path.c_str()) != 0) {
    ::unlink(tmp.c_str());
    throw AuthError(AuthError::Code::kIo, "cannot replace " + opt_.path + ": " + std::strerror(errno));
  }
  // Remember what we wrote, so we don't re-read our own write.
  last_check_ms_ = 0;
  struct stat st {};
  if (::stat(opt_.path.c_str(), &st) == 0) {
    stamp_.ino = st.st_ino;
    stamp_.size = static_cast<std::uint64_t>(st.st_size);
    stamp_.mtime_ns = std::int64_t(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
  }
}

template <class Fn>
auto Store::mutate(Fn &&fn) {
  std::lock_guard lock(mu_);
  fs::path dir = fs::path(opt_.path).parent_path();
  if (!dir.empty() && !fs::exists(dir)) {
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) throw AuthError(AuthError::Code::kIo, "cannot create " + dir.string() + ": " + ec.message());
    fs::permissions(dir, fs::perms::owner_all, ec);
  }
  FileLock file_lock(opt_.path);
  refresh_locked(true);
  if constexpr (std::is_void_v<decltype(fn(data_))>) {
    fn(data_);
    save_locked();
  } else {
    auto result = fn(data_);
    save_locked();
    return result;
  }
}

void Store::reload() {
  std::lock_guard lock(mu_);
  refresh_locked(true);
}

// ---------------------------------------------------------------- accounts --

UserRecord Store::add_user(const std::string &name, Role role, std::string_view password,
                           const std::vector<std::string> &projects) {
  if (!valid_account_name(name))
    throw AuthError(AuthError::Code::kInvalidArgument,
                    "invalid account name \"" + name + "\" (1-64 letters, digits, . _ - @)");
  if (role != Role::kViewer && role != Role::kEditor && role != Role::kAdmin)
    throw AuthError(AuthError::Code::kInvalidArgument, "an account's role is viewer, editor or admin");
  if (!valid_password(password)) throw AuthError(AuthError::Code::kInvalidArgument, "passwords are 8 to 1024 bytes");
  UserRecord u;
  u.name = name;
  u.role = role;
  u.projects = normalized(projects);
  u.password_hash = hash_password(password, opt_.scrypt);  // before taking any lock: it is slow
  u.created_at = now();
  return mutate([&](Data &d) {
    if (d.users.contains(name)) throw AuthError(AuthError::Code::kAlreadyExists, "account \"" + name + "\" exists");
    d.users[name] = u;
    return u;
  });
}

void Store::delete_user(const std::string &name) {
  mutate([&](Data &d) {
    if (!d.users.erase(name)) throw AuthError(AuthError::Code::kNotFound, "no account \"" + name + "\"");
    std::erase_if(d.sessions, [&](const auto &kv) { return kv.second.user == name; });
    std::erase_if(d.tokens, [&](const auto &kv) { return kv.second.user == name; });
  });
}

UserRecord Store::update_user(const std::string &name, std::optional<Role> role, std::optional<std::string> password,
                              std::optional<std::vector<std::string>> projects) {
  if (role && *role != Role::kViewer && *role != Role::kEditor && *role != Role::kAdmin)
    throw AuthError(AuthError::Code::kInvalidArgument, "an account's role is viewer, editor or admin");
  if (password && !valid_password(*password))
    throw AuthError(AuthError::Code::kInvalidArgument, "passwords are 8 to 1024 bytes");
  std::optional<std::string> hash;
  if (password) hash = hash_password(*password, opt_.scrypt);
  if (projects) projects = normalized(*projects);
  return mutate([&](Data &d) {
    auto it = d.users.find(name);
    if (it == d.users.end()) throw AuthError(AuthError::Code::kNotFound, "no account \"" + name + "\"");
    UserRecord &u = it->second;
    bool end_sessions = false;
    if (role && *role != u.role) u.role = *role, end_sessions = true;
    if (hash) u.password_hash = *hash, end_sessions = true;
    if (projects) u.projects = *projects;
    if (end_sessions) std::erase_if(d.sessions, [&](const auto &kv) { return kv.second.user == name; });
    return u;
  });
}

std::vector<UserRecord> Store::users() {
  std::lock_guard lock(mu_);
  refresh_locked(true);
  std::vector<UserRecord> out;
  for (const auto &[_, u] : data_.users) out.push_back(u);
  return out;
}

std::optional<UserRecord> Store::user(const std::string &name) {
  std::lock_guard lock(mu_);
  refresh_locked(false);
  auto it = data_.users.find(name);
  if (it == data_.users.end()) return std::nullopt;
  return it->second;
}

bool Store::empty() {
  std::lock_guard lock(mu_);
  refresh_locked(false);
  return data_.users.empty() && data_.tokens.empty();
}

// ------------------------------------------------------------------ tokens --

Store::NewToken Store::create_token(const std::string &name, Role role, const std::string &user,
                                    const std::vector<std::string> &projects, std::int64_t ttl_seconds) {
  if (!valid_account_name(name))
    throw AuthError(AuthError::Code::kInvalidArgument,
                    "invalid token name \"" + name + "\" (1-64 letters, digits, . _ - @)");
  if (role == Role::kNone) throw AuthError(AuthError::Code::kInvalidArgument, "a token needs a role");
  if (role == Role::kPeer && !user.empty())
    throw AuthError(AuthError::Code::kInvalidArgument, "a peer token cannot be issued to an account");
  if (ttl_seconds < 0) throw AuthError(AuthError::Code::kInvalidArgument, "negative lifetime");
  NewToken out;
  out.record.id = hex(random_bytes(8));
  out.secret = "rkt_" + out.record.id + "_" + base64url(random_bytes(32));
  out.record.name = name;
  out.record.role = role;
  out.record.user = user;
  out.record.projects = normalized(projects);
  out.record.created_at = now();
  out.record.expires_at = ttl_seconds ? out.record.created_at + ttl_seconds : 0;
  out.record.hash = sha256_hex(out.secret);
  mutate([&](Data &d) {
    if (!user.empty() && !d.users.contains(user))
      throw AuthError(AuthError::Code::kNotFound, "no account \"" + user + "\"");
    for (const auto &[_, t] : d.tokens)
      if (t.name == name)
        throw AuthError(AuthError::Code::kAlreadyExists, "a token named \"" + name + "\" exists; revoke it first");
    d.tokens[out.record.id] = out.record;
  });
  return out;
}

bool Store::revoke_token(const std::string &id_or_name) {
  return mutate([&](Data &d) {
    return std::erase_if(d.tokens, [&](const auto &kv) {
             return kv.second.id == id_or_name || kv.second.name == id_or_name;
           }) > 0;
  });
}

std::vector<TokenRecord> Store::tokens() {
  std::lock_guard lock(mu_);
  refresh_locked(true);
  std::vector<TokenRecord> out;
  for (const auto &[_, t] : data_.tokens) out.push_back(t);
  return out;
}

// ---------------------------------------------------------------- sessions --

Principal Store::user_principal_locked(const UserRecord &u) const {
  Principal p;
  p.kind = PrincipalKind::kUser;
  p.name = u.name;
  p.role = u.role;
  p.projects = u.projects;
  return p;
}

std::optional<Store::NewSession> Store::login(const std::string &name, std::string_view password) {
  std::optional<std::string> hash;
  {
    std::lock_guard lock(mu_);
    refresh_locked(true);
    if (auto it = data_.users.find(name); it != data_.users.end()) hash = it->second.password_hash;
  }
  // The slow part, outside every lock.
  if (!hash) {
    dummy_verify(password);
    return std::nullopt;
  }
  if (!verify_password(password, *hash)) return std::nullopt;
  std::optional<std::string> rehash;
  if (needs_rehash(*hash, opt_.scrypt)) rehash = hash_password(password, opt_.scrypt);

  NewSession out;
  out.token = "rks_" + base64url(random_bytes(32));
  SessionRecord s;
  s.hash = sha256_hex(out.token);
  s.user = name;
  s.created_at = now();
  s.expires_at = s.created_at + opt_.session_ttl_seconds;
  s.csrf = base64url(random_bytes(32));
  bool ok = mutate([&](Data &d) {
    auto it = d.users.find(name);
    // Deleted, or the password changed, while we were hashing.
    if (it == d.users.end() || it->second.password_hash != *hash) return false;
    if (rehash) it->second.password_hash = *rehash;
    d.sessions[s.hash] = s;
    out.principal = user_principal_locked(it->second);
    return true;
  });
  if (!ok) return std::nullopt;
  out.principal.method = AuthMethod::kSession;
  out.principal.expires_at = s.expires_at;
  out.principal.csrf = s.csrf;
  return out;
}

bool Store::change_password(const std::string &name, std::string_view old_password, std::string_view new_password,
                            const std::string &keep_session_token) {
  if (!valid_password(new_password))
    throw AuthError(AuthError::Code::kInvalidArgument, "passwords are 8 to 1024 bytes");
  std::optional<std::string> hash;
  {
    std::lock_guard lock(mu_);
    refresh_locked(true);
    if (auto it = data_.users.find(name); it != data_.users.end()) hash = it->second.password_hash;
  }
  if (!hash) throw AuthError(AuthError::Code::kNotFound, "no account \"" + name + "\"");
  if (!verify_password(old_password, *hash)) return false;
  std::string fresh = hash_password(new_password, opt_.scrypt);
  const std::string keep = sha256_hex(keep_session_token);
  return mutate([&](Data &d) {
    auto it = d.users.find(name);
    if (it == d.users.end() || it->second.password_hash != *hash) return false;
    it->second.password_hash = fresh;
    std::erase_if(d.sessions, [&](const auto &kv) { return kv.second.user == name && kv.first != keep; });
    return true;
  });
}

bool Store::logout(std::string_view session_token) {
  const std::string h = sha256_hex(session_token);
  {
    std::lock_guard lock(mu_);
    refresh_locked(true);
    if (!data_.sessions.contains(h)) return false;
  }
  return mutate([&](Data &d) { return d.sessions.erase(h) > 0; });
}

std::optional<Principal> Store::lookup_locked(std::string_view bearer) const {
  const std::string h = sha256_hex(bearer);
  const std::int64_t t = now();
  if (bearer.starts_with("rks_")) {
    auto it = data_.sessions.find(h);
    if (it == data_.sessions.end() || it->second.expires_at <= t) return std::nullopt;
    auto u = data_.users.find(it->second.user);
    if (u == data_.users.end()) return std::nullopt;
    Principal p = user_principal_locked(u->second);
    p.method = AuthMethod::kSession;
    p.expires_at = it->second.expires_at;
    p.csrf = it->second.csrf;
    return p;
  }
  // rkt_<id>_<secret>: find by id, compare the hash in constant time.
  std::string_view rest = bearer.substr(4);
  auto us = rest.find('_');
  if (us == std::string_view::npos) return std::nullopt;
  auto it = data_.tokens.find(std::string(rest.substr(0, us)));
  if (it == data_.tokens.end() || !constant_time_equal(it->second.hash, h)) return std::nullopt;
  const TokenRecord &k = it->second;
  if (k.expires_at && k.expires_at <= t) return std::nullopt;
  Principal p;
  p.method = AuthMethod::kToken;
  p.token_id = k.id;
  p.expires_at = k.expires_at;
  if (!k.user.empty()) {
    auto u = data_.users.find(k.user);
    if (u == data_.users.end()) return std::nullopt;
    p.kind = PrincipalKind::kUser;
    p.name = u->second.name;
    // Never more than the account itself may do.
    p.role = static_cast<int>(k.role) < static_cast<int>(u->second.role) ? k.role : u->second.role;
    p.projects = intersect(k.projects, u->second.projects);
  } else {
    p.kind = k.role == Role::kPeer ? PrincipalKind::kPeer : PrincipalKind::kAgent;
    p.name = k.name;
    p.role = k.role;
    p.projects = k.projects;
  }
  return p;
}

std::string Store::mint_run_token(const Principal &as, std::int64_t ttl_seconds, std::string &id) {
  if (as.kind != PrincipalKind::kUser && as.kind != PrincipalKind::kAgent)
    throw AuthError(AuthError::Code::kInvalidArgument, "run tokens act for accounts and agents only");
  RunToken t;
  id = hex(random_bytes(8));
  std::string secret = "rkr_" + id + "_" + base64url(random_bytes(32));
  t.hash = sha256_hex(secret);
  t.as = as;
  t.as.method = AuthMethod::kToken;
  t.as.csrf.clear();
  t.expires_at = ttl_seconds > 0 ? now() + ttl_seconds : 0;
  std::lock_guard lock(mu_);
  run_tokens_[id] = std::move(t);
  return secret;
}

void Store::revoke_run_token(const std::string &id) {
  std::lock_guard lock(mu_);
  run_tokens_.erase(id);
}

std::size_t Store::run_token_count() {
  std::lock_guard lock(mu_);
  return run_tokens_.size();
}

std::optional<Principal> Store::run_token_locked(std::string_view bearer) const {
  std::string_view rest = bearer.substr(4);
  auto us = rest.find('_');
  if (us == std::string_view::npos) return std::nullopt;
  const std::string id(rest.substr(0, us));
  auto it = run_tokens_.find(id);
  if (it == run_tokens_.end() || !constant_time_equal(it->second.hash, sha256_hex(bearer))) return std::nullopt;
  const RunToken &t = it->second;
  if (t.expires_at && t.expires_at <= now()) return std::nullopt;
  Principal p = t.as;
  // What it was minted from must still stand: the API token (an agent's,
  // or one issued to an account) and the account.
  if (!t.as.token_id.empty() && !t.as.token_id.starts_with("run:")) {
    auto k = data_.tokens.find(t.as.token_id);
    if (k == data_.tokens.end()) return std::nullopt;
    if (static_cast<int>(k->second.role) < static_cast<int>(p.role)) p.role = k->second.role;
  }
  if (p.kind == PrincipalKind::kUser) {
    auto u = data_.users.find(p.name);
    if (u == data_.users.end()) return std::nullopt;
    if (static_cast<int>(u->second.role) < static_cast<int>(p.role)) p.role = u->second.role;
    p.projects = intersect(p.projects, u->second.projects);
  }
  p.token_id = "run:" + id;
  p.expires_at = t.expires_at;
  return p;
}

std::optional<Principal> Store::authenticate(std::string_view bearer) {
  if (bearer.empty() || bearer.size() > 4096) return std::nullopt;
  if (bearer.starts_with("rkr_")) {
    std::lock_guard lock(mu_);
    refresh_locked(false);
    return run_token_locked(bearer);
  }
  if (bearer.starts_with("rks_") || bearer.starts_with("rkt_")) {
    std::lock_guard lock(mu_);
    refresh_locked(false);
    if (auto p = lookup_locked(bearer)) return p;
    // Unknown here: perhaps just issued by `rk-daemon token create`. Look at
    // the file now rather than within the second (a stat when unchanged).
    refresh_locked(true);
    return lookup_locked(bearer);
  }
  if (!opt_.peer_secret.empty() && constant_time_equal(sha256(bearer), sha256(opt_.peer_secret))) {
    Principal p;
    p.kind = PrincipalKind::kPeer;
    p.name = "shared-secret";
    p.role = Role::kPeer;
    p.method = AuthMethod::kPeerSecret;
    return p;
  }
  return std::nullopt;
}

}  // namespace revkit::auth
