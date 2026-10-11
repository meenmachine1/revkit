#include "revkit/auth/store.h"

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>

namespace revkit::auth {
namespace {

namespace fs = std::filesystem;

class StoreTest : public ::testing::Test {
 protected:
  void SetUp() override {
    dir_ = fs::temp_directory_path() /
           ("rk-auth-" + std::to_string(::getpid()) + "-" + ::testing::UnitTest::GetInstance()->current_test_info()->name());
    fs::remove_all(dir_);
  }
  void TearDown() override { fs::remove_all(dir_); }

  StoreOptions options() {
    StoreOptions o;
    o.path = (dir_ / "sub" / "auth.db").string();
    o.scrypt = {10, 8, 1};
    o.now = [this] { return now_.load(); };
    return o;
  }
  std::string file_text() {
    std::ifstream in(dir_ / "sub" / "auth.db");
    std::ostringstream s;
    s << in.rdbuf();
    return s.str();
  }

  fs::path dir_;
  std::atomic<std::int64_t> now_{1'800'000'000};
};

TEST(Roles, Hierarchy) {
  using R = Role;
  EXPECT_TRUE(role_allows(R::kViewer, R::kNone));
  EXPECT_TRUE(role_allows(R::kNone, R::kNone));
  EXPECT_FALSE(role_allows(R::kNone, R::kViewer));
  EXPECT_TRUE(role_allows(R::kViewer, R::kViewer));
  EXPECT_FALSE(role_allows(R::kViewer, R::kEditor));
  EXPECT_TRUE(role_allows(R::kEditor, R::kViewer));
  EXPECT_FALSE(role_allows(R::kEditor, R::kAdmin));
  EXPECT_TRUE(role_allows(R::kAdmin, R::kEditor));
  // Peers are outside the ladder both ways.
  EXPECT_TRUE(role_allows(R::kPeer, R::kPeer));
  EXPECT_TRUE(role_allows(R::kPeer, R::kNone));
  EXPECT_FALSE(role_allows(R::kPeer, R::kViewer));
  EXPECT_FALSE(role_allows(R::kAdmin, R::kPeer));
  EXPECT_EQ(role_from_string("editor"), R::kEditor);
  EXPECT_FALSE(role_from_string("root"));
  EXPECT_STREQ(to_string(R::kAdmin), "admin");
}

TEST(Roles, ProjectLists) {
  Principal p;
  EXPECT_TRUE(p.may_use_project("anything"));
  p.projects = {"a", "b"};
  EXPECT_TRUE(p.may_use_project("a"));
  EXPECT_FALSE(p.may_use_project("c"));
}

TEST_F(StoreTest, LoginAuthenticateLogout) {
  Store s(options());
  EXPECT_TRUE(s.empty());
  s.add_user("alice", Role::kEditor, "correct horse");
  EXPECT_FALSE(s.empty());
  EXPECT_FALSE(s.login("alice", "wrong password"));
  EXPECT_FALSE(s.login("mallory", "correct horse"));
  auto sess = s.login("alice", "correct horse");
  ASSERT_TRUE(sess);
  EXPECT_TRUE(sess->token.starts_with("rks_"));
  EXPECT_EQ(sess->principal.kind, PrincipalKind::kUser);
  EXPECT_EQ(sess->principal.name, "alice");
  EXPECT_EQ(sess->principal.role, Role::kEditor);
  EXPECT_FALSE(sess->principal.csrf.empty());

  auto p = s.authenticate(sess->token);
  ASSERT_TRUE(p);
  EXPECT_EQ(p->display(), "user:alice");
  EXPECT_EQ(p->method, AuthMethod::kSession);
  EXPECT_EQ(p->csrf, sess->principal.csrf);
  EXPECT_EQ(p->expires_at, now_ + 7 * 24 * 3600);
  EXPECT_FALSE(s.authenticate(sess->token + "x"));
  EXPECT_FALSE(s.authenticate(""));
  EXPECT_FALSE(s.authenticate("rks_"));

  EXPECT_TRUE(s.logout(sess->token));
  EXPECT_FALSE(s.authenticate(sess->token));
  EXPECT_FALSE(s.logout(sess->token));
}

TEST_F(StoreTest, SecretsAreStoredHashedAndPrivate) {
  Store s(options());
  s.add_user("alice", Role::kAdmin, "hunter2hunter2");
  auto sess = s.login("alice", "hunter2hunter2");
  auto tok = s.create_token("ci", Role::kViewer);
  std::string text = file_text();
  EXPECT_EQ(text.find("hunter2"), std::string::npos);
  EXPECT_EQ(text.find(sess->token), std::string::npos);
  EXPECT_EQ(text.find(tok.secret), std::string::npos);
  // The random part, after "rkt_<id>_" (base64url, so it may hold '_' itself).
  const std::string prefix = "rkt_" + tok.record.id + "_";
  ASSERT_TRUE(tok.secret.starts_with(prefix));
  EXPECT_EQ(text.find(tok.secret.substr(prefix.size())), std::string::npos);
  struct stat st {};
  ASSERT_EQ(::stat((dir_ / "sub" / "auth.db").c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777, 0600u);
  ASSERT_EQ(::stat((dir_ / "sub").c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777, 0700u);
}

TEST_F(StoreTest, SessionsExpire) {
  auto o = options();
  o.session_ttl_seconds = 60;
  Store s(o);
  s.add_user("alice", Role::kViewer, "password1");
  auto sess = s.login("alice", "password1");
  ASSERT_TRUE(s.authenticate(sess->token));
  now_ += 61;
  EXPECT_FALSE(s.authenticate(sess->token));
}

TEST_F(StoreTest, NewPasswordOrRoleEndsSessions) {
  Store s(options());
  s.add_user("alice", Role::kEditor, "password1");
  auto a = s.login("alice", "password1");
  auto b = s.login("alice", "password1");
  s.update_user("alice", std::nullopt, std::nullopt, std::vector<std::string>{"p1"});
  ASSERT_TRUE(s.authenticate(a->token));  // a project change keeps sessions
  EXPECT_EQ(s.authenticate(a->token)->projects, std::vector<std::string>{"p1"});
  s.update_user("alice", Role::kViewer, std::nullopt, std::nullopt);
  EXPECT_FALSE(s.authenticate(a->token));
  EXPECT_FALSE(s.authenticate(b->token));

  auto c = s.login("alice", "password1");
  auto d = s.login("alice", "password1");
  EXPECT_FALSE(s.change_password("alice", "wrong-old", "password2", c->token));
  EXPECT_TRUE(s.change_password("alice", "password1", "password2", c->token));
  EXPECT_TRUE(s.authenticate(c->token));   // the caller's own session stays
  EXPECT_FALSE(s.authenticate(d->token));  // the others end
  EXPECT_FALSE(s.login("alice", "password1"));
  EXPECT_TRUE(s.login("alice", "password2"));
}

TEST_F(StoreTest, ApiTokens) {
  Store s(options());
  s.add_user("bob", Role::kEditor, "password1", {"p1", "p2"});
  auto agent = s.create_token("claude", Role::kEditor);
  auto viewer = s.create_token("dash", Role::kViewer, "", {"p1"});
  auto bobs = s.create_token("bob-script", Role::kAdmin, "bob", {"p2", "p3"});
  auto peer = s.create_token("daemon-b", Role::kPeer);
  EXPECT_TRUE(agent.secret.starts_with("rkt_" + agent.record.id + "_"));

  auto p = s.authenticate(agent.secret);
  ASSERT_TRUE(p);
  EXPECT_EQ(p->kind, PrincipalKind::kAgent);
  EXPECT_EQ(p->display(), "agent:claude");
  EXPECT_EQ(p->role, Role::kEditor);
  EXPECT_EQ(p->method, AuthMethod::kToken);
  EXPECT_TRUE(p->projects.empty());

  EXPECT_EQ(s.authenticate(viewer.secret)->projects, std::vector<std::string>{"p1"});

  // Issued to an account: acts as it, never beyond it.
  p = s.authenticate(bobs.secret);
  ASSERT_TRUE(p);
  EXPECT_EQ(p->display(), "user:bob");
  EXPECT_EQ(p->role, Role::kEditor);
  EXPECT_EQ(p->projects, std::vector<std::string>{"p2"});

  p = s.authenticate(peer.secret);
  ASSERT_TRUE(p);
  EXPECT_EQ(p->kind, PrincipalKind::kPeer);
  EXPECT_EQ(p->role, Role::kPeer);

  // A right id with a wrong secret.
  std::string forged = agent.secret;
  forged.back() = forged.back() == 'A' ? 'B' : 'A';
  EXPECT_FALSE(s.authenticate(forged));
  EXPECT_FALSE(s.authenticate("rkt_" + agent.record.id));

  EXPECT_THROW(s.create_token("claude", Role::kViewer), AuthError);  // names are unique
  EXPECT_THROW(s.create_token("x", Role::kPeer, "bob"), AuthError);
  EXPECT_THROW(s.create_token("y", Role::kViewer, "nobody"), AuthError);
  EXPECT_EQ(s.tokens().size(), 4u);

  EXPECT_TRUE(s.revoke_token("claude"));
  EXPECT_FALSE(s.authenticate(agent.secret));
  EXPECT_TRUE(s.revoke_token(viewer.record.id));
  EXPECT_FALSE(s.authenticate(viewer.secret));
  EXPECT_FALSE(s.revoke_token("claude"));

  // Deleting the account takes its tokens and sessions with it.
  auto sess = s.login("bob", "password1");
  s.delete_user("bob");
  EXPECT_FALSE(s.authenticate(bobs.secret));
  EXPECT_FALSE(s.authenticate(sess->token));
  EXPECT_EQ(s.tokens().size(), 1u);
}

TEST_F(StoreTest, TokensExpire) {
  Store s(options());
  auto t = s.create_token("short", Role::kViewer, "", {}, 30);
  EXPECT_EQ(t.record.expires_at, now_ + 30);
  EXPECT_TRUE(s.authenticate(t.secret));
  now_ += 30;
  EXPECT_FALSE(s.authenticate(t.secret));
}

TEST_F(StoreTest, PeerSecret) {
  auto o = options();
  o.peer_secret = std::string(40, 'k');
  Store s(o);
  auto p = s.authenticate(std::string(40, 'k'));
  ASSERT_TRUE(p);
  EXPECT_EQ(p->kind, PrincipalKind::kPeer);
  EXPECT_EQ(p->method, AuthMethod::kPeerSecret);
  EXPECT_FALSE(s.authenticate(std::string(39, 'k')));
  o.peer_secret = "short";
  EXPECT_THROW(Store bad(o), AuthError);
}

TEST_F(StoreTest, Validation) {
  Store s(options());
  EXPECT_THROW(s.add_user("", Role::kViewer, "password1"), AuthError);
  EXPECT_THROW(s.add_user("has space", Role::kViewer, "password1"), AuthError);
  EXPECT_THROW(s.add_user("ok", Role::kViewer, "short"), AuthError);
  EXPECT_THROW(s.add_user("ok", Role::kPeer, "password1"), AuthError);
  EXPECT_THROW(s.add_user("ok", Role::kViewer, "password1", {"a,b"}), AuthError);
  s.add_user("ok", Role::kViewer, "password1");
  EXPECT_THROW(s.add_user("ok", Role::kViewer, "password1"), AuthError);
  try {
    s.delete_user("ghost");
    FAIL();
  } catch (const AuthError &e) {
    EXPECT_EQ(e.code(), AuthError::Code::kNotFound);
  }
}

// rk-daemon user/token commands and the running daemon share the file.
TEST_F(StoreTest, TwoStoresShareTheFile) {
  Store daemon(options());
  Store cli(options());
  cli.add_user("alice", Role::kAdmin, "password1");
  auto tok = cli.create_token("bot", Role::kEditor);
  daemon.reload();
  EXPECT_TRUE(daemon.authenticate(tok.secret));
  auto sess = daemon.login("alice", "password1");
  ASSERT_TRUE(sess);
  cli.reload();
  EXPECT_TRUE(cli.authenticate(sess->token));
  cli.revoke_token("bot");
  cli.delete_user("alice");
  daemon.reload();
  EXPECT_FALSE(daemon.authenticate(tok.secret));
  EXPECT_FALSE(daemon.authenticate(sess->token));
  EXPECT_EQ(Store(options()).users().size(), 0u);
}

TEST_F(StoreTest, ConcurrentWritersLoseNothing) {
  Store a(options()), b(options());
  std::vector<std::thread> threads;
  for (int t = 0; t < 4; ++t)
    threads.emplace_back([&, t] {
      for (int i = 0; i < 10; ++i) (t % 2 ? a : b).create_token("t" + std::to_string(t) + "-" + std::to_string(i), Role::kViewer);
    });
  for (auto &t : threads) t.join();
  EXPECT_EQ(Store(options()).tokens().size(), 40u);
}

TEST_F(StoreTest, RejectsForeignFile) {
  fs::create_directories(dir_ / "sub");
  std::ofstream(dir_ / "sub" / "auth.db") << "something else\n";
  EXPECT_THROW(Store s(options()), AuthError);
}

}  // namespace
}  // namespace revkit::auth
