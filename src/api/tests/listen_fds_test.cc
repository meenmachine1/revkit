// Socket activation: the sd_listen_fds protocol (listen_fds.cc) and a
// Server serving HTTP on an inherited listening socket under the same
// loopback, authentication and TLS rules as a bound one.
#include "revkit/api/fake_backend.h"
#include "revkit/api/listen_fds.h"
#include "revkit/api/server.h"
#include "revkit/auth/store.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include <httplib.h>

#include <cstdlib>
#include <future>
#include <thread>
#include <filesystem>

namespace revkit::api {
namespace {

namespace fs = std::filesystem;

// A listening TCP socket on host (port 0: any free one).
int Listener(const char *host = "127.0.0.1") {
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  sockaddr_in a{};
  a.sin_family = AF_INET;
  inet_pton(AF_INET, host, &a.sin_addr);
  if (bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof a) != 0 || listen(fd, 16) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

int PortOf(int fd) {
  sockaddr_in a{};
  socklen_t len = sizeof a;
  getsockname(fd, reinterpret_cast<sockaddr *>(&a), &len);
  return ntohs(a.sin_port);
}

TEST(ListenFds, NothingWithoutTheEnvironment) {
  unsetenv("LISTEN_PID");
  unsetenv("LISTEN_FDS");
  std::vector<InheritedSocket> got;
  std::string error;
  EXPECT_TRUE(TakeListenFds(got, error)) << error;
  EXPECT_TRUE(got.empty());
}

TEST(ListenFds, AnotherProcessesSocketsAreNotOursAndTheVariablesGo) {
  setenv("LISTEN_PID", std::to_string(getpid() + 1).c_str(), 1);
  setenv("LISTEN_FDS", "1", 1);
  setenv("LISTEN_FDNAMES", "http", 1);
  std::vector<InheritedSocket> got;
  std::string error;
  EXPECT_TRUE(TakeListenFds(got, error)) << error;
  EXPECT_TRUE(got.empty());
  EXPECT_EQ(std::getenv("LISTEN_PID"), nullptr);
  EXPECT_EQ(std::getenv("LISTEN_FDS"), nullptr);
  EXPECT_EQ(std::getenv("LISTEN_FDNAMES"), nullptr);
}

// The protocol proper needs the socket at descriptor 3, so it runs in a
// child process (exit status: which check failed).
TEST(ListenFds, TakesDescriptorThreeWithItsNameAndAddress) {
  int sock = Listener();
  ASSERT_GE(sock, 0);
  const int port = PortOf(sock);
  pid_t pid = fork();
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    if (dup2(sock, 3) != 3) _exit(10);  // dup2 clears close-on-exec
    setenv("LISTEN_PID", std::to_string(getpid()).c_str(), 1);
    setenv("LISTEN_FDS", "1", 1);
    setenv("LISTEN_FDNAMES", "http", 1);
    std::vector<InheritedSocket> got;
    std::string error;
    if (!TakeListenFds(got, error)) _exit(11);
    if (got.size() != 1 || got[0].fd != 3) _exit(12);
    if (got[0].name != "http") _exit(13);
    if (got[0].address != "127.0.0.1:" + std::to_string(port)) _exit(14);
    if (!(fcntl(3, F_GETFD) & FD_CLOEXEC)) _exit(15);  // not for our children
    if (std::getenv("LISTEN_FDS")) _exit(16);
    _exit(0);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  close(sock);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(ListenFds, RefusesWhatIsNotAListeningStreamSocket) {
  pid_t pid = fork();
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp < 0 || dup2(udp, 3) != 3) _exit(10);
    setenv("LISTEN_PID", std::to_string(getpid()).c_str(), 1);
    setenv("LISTEN_FDS", "1", 1);
    std::vector<InheritedSocket> got;
    std::string error;
    if (TakeListenFds(got, error)) _exit(11);
    if (error.find("not a stream socket") == std::string::npos) _exit(12);
    // A stream socket that does not listen (Accept=yes would pass one).
    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp < 0 || dup2(tcp, 3) != 3) _exit(13);
    setenv("LISTEN_PID", std::to_string(getpid()).c_str(), 1);
    setenv("LISTEN_FDS", "1", 1);
    if (TakeListenFds(got, error)) _exit(14);
    if (error.find("not listening") == std::string::npos) _exit(15);
    _exit(0);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(ListenFds, ServerServesOnTheInheritedSocket) {
  int sock = Listener();
  ASSERT_GE(sock, 0);
  const int port = PortOf(sock);
  // A client already waiting when the daemon starts: what activation does.
  httplib::Client early("127.0.0.1", port);
  early.set_read_timeout(std::chrono::seconds(10));

  ServerOptions o;
  o.grpc_address = "";
  o.http_address = "127.0.0.1:1";  // ignored: the socket says where
  o.http_fd = sock;
  o.launch_args = {"rk-daemon", "--backend", "fake"};
  std::string error;
  auto server = Server::Start(MakeFakeBackend(), o, error);
  ASSERT_TRUE(server) << error;
  EXPECT_EQ(server->http_port(), port);
  EXPECT_EQ(server->http_address(), "127.0.0.1:" + std::to_string(port));

  auto health = early.Get("/healthz");
  ASSERT_TRUE(health);
  EXPECT_EQ(health->status, 200);
  // No accounts here (auth null, as --no-auth): the caller is an admin and
  // sees the command line.
  auto info = early.Post("/revkit.v1.MetaService/GetServerInfo", "{}", "application/json");
  ASSERT_TRUE(info);
  EXPECT_EQ(info->status, 200);
  EXPECT_NE(info->body.find("\"socketActivated\":true"), std::string::npos) << info->body;
  EXPECT_NE(info->body.find("\"launchArgs\":[\"rk-daemon\",\"--backend\",\"fake\"]"), std::string::npos) << info->body;
  EXPECT_NE(info->body.find("\"daemon-info\""), std::string::npos) << info->body;
  server->Shutdown();
}

// Stopping leaves the service manager's socket listening (no shutdown() on
// it), so the next connection starts the daemon again: here, a second
// server on the same socket answers a request that arrived in between.
TEST(ListenFds, StoppingLeavesTheSocketForTheNextStart) {
  int keep = Listener();  // systemd's copy
  ASSERT_GE(keep, 0);
  const int port = PortOf(keep);
  ServerOptions o;
  o.grpc_address = "";
  o.http_fd = dup(keep);
  std::string error;
  auto first = Server::Start(MakeFakeBackend(), o, error);
  ASSERT_TRUE(first) << error;
  httplib::Client c("127.0.0.1", port);
  ASSERT_TRUE(c.Get("/healthz"));
  const auto t0 = std::chrono::steady_clock::now();
  first->Shutdown();
  first.reset();
  EXPECT_LT(std::chrono::steady_clock::now() - t0, std::chrono::seconds(5));
  int listening = 0;
  socklen_t len = sizeof listening;
  ASSERT_EQ(getsockopt(keep, SOL_SOCKET, SO_ACCEPTCONN, &listening, &len), 0);
  EXPECT_EQ(listening, 1) << "the inherited socket no longer listens";
  // A client arrives while no daemon runs; the next one answers it.
  httplib::Client waiting("127.0.0.1", port);
  waiting.set_read_timeout(std::chrono::seconds(10));
  auto answer = std::async(std::launch::async, [&] { return waiting.Get("/healthz"); });
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  o.http_fd = dup(keep);
  auto second = Server::Start(MakeFakeBackend(), o, error);
  ASSERT_TRUE(second) << error;
  auto r = answer.get();
  ASSERT_TRUE(r);
  EXPECT_EQ(r->status, 200);
  second->Shutdown();
  close(keep);
}

// Socket activation creates no listener a normal start would refuse.
TEST(ListenFds, TheListenerRulesApplyToTheInheritedSocket) {
  int wild = Listener("0.0.0.0");
  ASSERT_GE(wild, 0);
  std::string error;
  ServerOptions o;
  o.grpc_address = "";
  o.http_fd = wild;
  // No accounts on a socket off loopback: refused.
  EXPECT_FALSE(Server::Start(MakeFakeBackend(), o, error));
  EXPECT_NE(error.find("without authentication"), std::string::npos) << error;
  EXPECT_NE(error.find("0.0.0.0:"), std::string::npos) << error;
  // Accounts but plaintext off loopback: refused too.
  auth::StoreOptions so;
  so.path = (fs::temp_directory_path() / ("rk-listen-fds-" + std::to_string(getpid()) + ".db")).string();
  o.auth = std::make_shared<auth::Store>(so);
  error.clear();
  EXPECT_FALSE(Server::Start(MakeFakeBackend(), o, error));
  EXPECT_NE(error.find("refusing plaintext"), std::string::npos) << error;
  close(wild);
  fs::remove(so.path);
}

// With accounts, an anonymous caller learns the uptime and that the socket
// was inherited, but not the command line (it names host paths); an admin
// does.
TEST(ListenFds, LaunchArgsOnlyForAdmins) {
  int sock = Listener();
  ASSERT_GE(sock, 0);
  const int port = PortOf(sock);
  auth::StoreOptions so;
  so.path = (fs::temp_directory_path() / ("rk-listen-fds-admin-" + std::to_string(getpid()) + ".db")).string();
  so.scrypt = {10, 8, 1};
  auto store = std::make_shared<auth::Store>(so);
  const std::string admin = store->create_token("root", auth::Role::kAdmin).secret;
  const std::string editor = store->create_token("ed", auth::Role::kEditor).secret;

  ServerOptions o;
  o.grpc_address = "";
  o.http_fd = sock;
  o.auth = store;
  o.launch_args = {"rk-daemon", "--project-dir", "/secret/place"};
  std::string error;
  auto server = Server::Start(MakeFakeBackend(), o, error);
  ASSERT_TRUE(server) << error;
  httplib::Client c("127.0.0.1", port);
  auto ask = [&](const std::string &token) {
    httplib::Headers h;
    if (!token.empty()) h.emplace("Authorization", "Bearer " + token);
    auto r = c.Post("/revkit.v1.MetaService/GetServerInfo", h, "{}", "application/json");
    return r ? r->body : std::string("no response");
  };
  std::string anon = ask("");
  EXPECT_NE(anon.find("\"socketActivated\":true"), std::string::npos) << anon;
  EXPECT_EQ(anon.find("/secret/place"), std::string::npos) << anon;
  EXPECT_EQ(ask(editor).find("/secret/place"), std::string::npos);
  EXPECT_NE(ask(admin).find("/secret/place"), std::string::npos);
  // And the API itself needs credentials, as on any start.
  auto denied = c.Post("/revkit.v1.ProjectService/ListProjects", "{}", "application/json");
  ASSERT_TRUE(denied);
  EXPECT_EQ(denied->status, 401);
  server->Shutdown();
  fs::remove(so.path);
}

}  // namespace
}  // namespace revkit::api
