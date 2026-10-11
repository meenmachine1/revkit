// Loopback integration: a real Server on ephemeral ports, exercised over
// gRPC (HTTP/2) and over the browser protocols (Connect, gRPC-web) with a
// plain HTTP/1.1 client, the way a browser's fetch() would.
#include "revkit/api/fake_backend.h"
#include "revkit/api/server.h"
#include "revkit/auth/tls.h"

#include "connect_gateway.h"

#include "revkit/v1/assertion.grpc.pb.h"
#include "revkit/v1/meta.grpc.pb.h"
#include "revkit/v1/query.grpc.pb.h"
#include "revkit/v1/subscription.grpc.pb.h"

#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <httplib.h>

#include <atomic>
#include <future>
#include <thread>

namespace revkit::api {
namespace {

std::string Envelope(std::uint8_t flags, const std::string &payload) {
  std::string out(5, '\0');
  out[0] = static_cast<char>(flags);
  auto n = static_cast<std::uint32_t>(payload.size());
  for (int i = 0; i < 4; ++i) out[1 + i] = static_cast<char>(n >> (24 - 8 * i));
  return out + payload;
}

// Splits a body of enveloped messages into (flags, payload) frames.
std::vector<std::pair<std::uint8_t, std::string>> Frames(const std::string &body) {
  std::vector<std::pair<std::uint8_t, std::string>> out;
  std::size_t pos = 0;
  while (pos + 5 <= body.size()) {
    std::uint32_t n = 0;
    for (int i = 0; i < 4; ++i) n = (n << 8) | static_cast<std::uint8_t>(body[pos + 1 + i]);
    if (pos + 5 + n > body.size()) break;
    out.emplace_back(static_cast<std::uint8_t>(body[pos]), body.substr(pos + 5, n));
    pos += 5 + n;
  }
  return out;
}

class ServerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ServerOptions opts;
    opts.grpc_address = "127.0.0.1:0";
    opts.http_address = "127.0.0.1:0";
    opts.allowed_origins = {"http://localhost:5173"};
    std::string error;
    server = Server::Start(MakeFakeBackend(), opts, error);
    ASSERT_TRUE(server) << error;
    channel = grpc::CreateChannel("127.0.0.1:" + std::to_string(server->grpc_port()),
                                  grpc::InsecureChannelCredentials());
  }

  httplib::Client Http() {
    httplib::Client c("127.0.0.1", server->http_port());
    c.set_read_timeout(std::chrono::seconds(10));
    return c;
  }

  pb::AppendAssertionsResponse RenameOverGrpc(std::uint64_t addr, const std::string &name) {
    auto stub = pb::AssertionService::NewStub(channel);
    pb::AppendAssertionsRequest req;
    req.set_program_id(fake::kProgramId);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("test");
    auto *r = req.add_assertions()->mutable_body()->mutable_rename();
    r->mutable_target()->mutable_address()->set_offset(addr);
    r->set_name(name);
    pb::AppendAssertionsResponse resp;
    grpc::ClientContext ctx;
    grpc::Status st = stub->AppendAssertions(&ctx, req, &resp);
    EXPECT_TRUE(st.ok()) << st.error_message();
    return resp;
  }

  std::unique_ptr<Server> server;
  std::shared_ptr<grpc::Channel> channel;
};

TEST_F(ServerTest, GrpcUnaryAndErrors) {
  auto meta = pb::MetaService::NewStub(channel);
  pb::GetServerInfoResponse info;
  grpc::ClientContext c1;
  ASSERT_TRUE(meta->GetServerInfo(&c1, {}, &info).ok());
  EXPECT_EQ(info.api_major(), "v1");

  auto query = pb::QueryService::NewStub(channel);
  pb::ListFunctionsRequest req;
  req.set_program_id(fake::kProgramId);
  pb::ListFunctionsResponse resp;
  grpc::ClientContext c2;
  ASSERT_TRUE(query->ListFunctions(&c2, req, &resp).ok());
  EXPECT_EQ(resp.functions_size(), 4);

  req.set_program_id("missing");
  grpc::ClientContext c3;
  EXPECT_EQ(query->ListFunctions(&c3, req, &resp).error_code(), grpc::StatusCode::NOT_FOUND);
}

TEST_F(ServerTest, GrpcSubscriptionSeesRename) {
  auto subs = pb::SubscriptionService::NewStub(channel);
  grpc::ClientContext ctx;
  pb::SubscribeRequest req;
  req.set_project_id(fake::kProjectId);
  auto reader = subs->Subscribe(&ctx, req);
  pb::SubscribeResponse ev;
  ASSERT_TRUE(reader->Read(&ev));
  ASSERT_TRUE(ev.has_hello());

  RenameOverGrpc(fake::kChecksum, "checksum");
  ASSERT_TRUE(reader->Read(&ev));
  ASSERT_TRUE(ev.has_revision());
  EXPECT_EQ(ev.revision().revision(), ev.revision().previous_revision() + 1);
  EXPECT_FALSE(ev.revision().invalidated().empty());
  ctx.TryCancel();
  while (reader->Read(&ev)) {
  }
  EXPECT_EQ(reader->Finish().error_code(), grpc::StatusCode::CANCELLED);
}

TEST_F(ServerTest, ConnectUnaryJsonAndProto) {
  auto http = Http();
  auto res = http.Post("/revkit.v1.QueryService/ListFunctions", "{\"programId\":\"demo/hello\"}",
                       "application/json");
  ASSERT_TRUE(res);
  EXPECT_EQ(res->status, 200);
  EXPECT_EQ(res->get_header_value("Content-Type"), "application/json");
  EXPECT_NE(res->body.find("\"FUN_00401040\""), std::string::npos) << res->body;
  EXPECT_NE(res->body.find("\"snapshot\""), std::string::npos);

  pb::GetFunctionRequest req;
  req.set_program_id(fake::kProgramId);
  req.mutable_address()->set_offset(fake::kMain);
  res = http.Post("/revkit.v1.QueryService/GetFunction", req.SerializeAsString(), "application/proto");
  ASSERT_TRUE(res);
  ASSERT_EQ(res->status, 200);
  pb::GetFunctionResponse fn;
  ASSERT_TRUE(fn.ParseFromString(res->body));
  EXPECT_EQ(fn.function().name(), "main");

  // A write over Connect is visible over gRPC: one backend, two transports.
  res = http.Post("/revkit.v1.AssertionService/AppendAssertions",
                  R"({"programId":"demo/hello","provenance":{"kind":"PROVENANCE_KIND_USER","id":"web"},
                      "assertions":[{"body":{"rename":{"target":{"address":{"offset":"4198464"}},"name":"checksum"}}}]})",
                  "application/json");
  ASSERT_TRUE(res);
  ASSERT_EQ(res->status, 200) << res->body;
  auto query = pb::QueryService::NewStub(channel);
  pb::GetFunctionResponse viaGrpc;
  grpc::ClientContext ctx;
  req.mutable_address()->set_offset(fake::kChecksum);
  ASSERT_TRUE(query->GetFunction(&ctx, req, &viaGrpc).ok());
  EXPECT_EQ(viaGrpc.function().name(), "checksum");
}

TEST_F(ServerTest, ConnectErrors) {
  auto http = Http();
  auto res = http.Post("/revkit.v1.QueryService/GetFunction", R"({"programId":"nope"})", "application/json");
  ASSERT_TRUE(res);
  EXPECT_EQ(res->status, 404);
  EXPECT_NE(res->body.find("\"code\":\"not_found\""), std::string::npos) << res->body;

  res = http.Post("/revkit.v1.QueryService/NoSuchMethod", "{}", "application/json");
  ASSERT_TRUE(res);
  EXPECT_EQ(res->status, 501);
  EXPECT_NE(res->body.find("unimplemented"), std::string::npos);

  res = http.Post("/revkit.v1.QueryService/GetFunction", "{not json", "application/json");
  ASSERT_TRUE(res);
  EXPECT_EQ(res->status, 400);

  res = http.Post("/revkit.v1.QueryService/GetFunction", "{}", "text/plain");
  ASSERT_TRUE(res);
  EXPECT_EQ(res->status, 415);
}

TEST_F(ServerTest, ConnectServerStreamingSubscription) {
  // Read the stream on a client thread; rename once the Hello has arrived.
  std::promise<void> got_hello;
  std::string received;
  std::thread reader([&] {
    auto http = Http();
    httplib::Request req;
    req.method = "POST";
    req.path = "/revkit.v1.SubscriptionService/Subscribe";
    req.set_header("Content-Type", "application/connect+json");
    req.body = Envelope(0, R"({"projectId":"demo"})");
    bool hello_seen = false;
    req.content_receiver = [&](const char *data, std::size_t len, std::uint64_t, std::uint64_t) {
      received.append(data, len);
      auto frames = Frames(received);
      if (!hello_seen && !frames.empty()) {
        hello_seen = true;
        got_hello.set_value();
      }
      // Stop once a revision event arrived (cancels the stream server-side).
      return frames.size() < 2;
    };
    http.send(req);
  });
  ASSERT_EQ(got_hello.get_future().wait_for(std::chrono::seconds(10)), std::future_status::ready);
  RenameOverGrpc(fake::kHelper, "times_two");
  reader.join();

  auto frames = Frames(received);
  ASSERT_GE(frames.size(), 2u);
  EXPECT_EQ(frames[0].first, 0);
  EXPECT_NE(frames[0].second.find("\"hello\""), std::string::npos) << frames[0].second;
  EXPECT_NE(frames[1].second.find("\"revision\""), std::string::npos) << frames[1].second;
  EXPECT_NE(frames[1].second.find("QUERY_KIND_FUNCTION_LIST"), std::string::npos);
}

TEST_F(ServerTest, ConnectStreamingErrorIsInBand) {
  auto http = Http();
  auto res = http.Post("/revkit.v1.SubscriptionService/Subscribe", Envelope(0, R"({"projectId":"nope"})"),
                       "application/connect+json");
  ASSERT_TRUE(res);
  EXPECT_EQ(res->status, 200);
  auto frames = Frames(res->body);
  ASSERT_EQ(frames.size(), 1u);
  EXPECT_EQ(frames[0].first, 0x02);
  EXPECT_NE(frames[0].second.find("not_found"), std::string::npos) << frames[0].second;
}

TEST_F(ServerTest, GrpcWebUnary) {
  auto http = Http();
  pb::GetServerInfoRequest req;
  req.set_client("test");
  auto res = http.Post("/revkit.v1.MetaService/GetServerInfo", Envelope(0, req.SerializeAsString()),
                       "application/grpc-web+proto");
  ASSERT_TRUE(res);
  EXPECT_EQ(res->status, 200);
  auto frames = Frames(res->body);
  ASSERT_EQ(frames.size(), 2u);
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(info.ParseFromString(frames[0].second));
  EXPECT_EQ(info.api_major(), "v1");
  EXPECT_EQ(frames[1].first, 0x80);
  EXPECT_NE(frames[1].second.find("grpc-status:0"), std::string::npos);
}

TEST_F(ServerTest, CorsPreflightAndHealth) {
  auto http = Http();
  httplib::Headers h = {{"Origin", "http://localhost:5173"},
                        {"Access-Control-Request-Method", "POST"},
                        {"Access-Control-Request-Headers", "content-type,connect-protocol-version"}};
  auto res = http.Options("/revkit.v1.QueryService/ListFunctions", h);
  ASSERT_TRUE(res);
  EXPECT_EQ(res->status, 204);
  EXPECT_EQ(res->get_header_value("Access-Control-Allow-Origin"), "http://localhost:5173");
  EXPECT_EQ(res->get_header_value("Access-Control-Allow-Headers"), "content-type,connect-protocol-version");

  httplib::Headers evil = {{"Origin", "http://evil.example"}};
  res = http.Post("/revkit.v1.MetaService/GetServerInfo", evil, "{}", "application/json");
  ASSERT_TRUE(res);
  EXPECT_FALSE(res->has_header("Access-Control-Allow-Origin"));

  res = http.Get("/healthz");
  ASSERT_TRUE(res);
  EXPECT_EQ(res->body, "ok\n");
}

// DNS rebinding: a page on a name its owner rebinds to 127.0.0.1 is
// same-origin with the daemon to the browser, but its requests carry that
// name in Host. Only the daemon's own names are answered.
TEST(HostHeader, LoopbackNamesIpLiteralsAndAllowedNames) {
  const std::vector<std::string> none;
  for (const char *ok : {"", "localhost", "localhost:50052", "LOCALHOST:1", "revkit.localhost:50052",
                         "a.b.localhost", "localhost.", "127.0.0.1", "127.0.0.1:50052", "127.9.8.7:1", "[::1]",
                         "[::1]:50052", "10.1.2.3:80", "[fe80::1]:8080"})
    EXPECT_TRUE(HostHeaderAllowed(ok, none)) << ok;
  for (const char *bad : {"evil.example.com", "evil.example.com:50052", "localhost.evil.example", "xlocalhost",
                          "127.0.0.1.evil.example", "[::1", "localhost:", "localhost:abc", "a b", "user@localhost",
                          "localhost/x"})
    EXPECT_FALSE(HostHeaderAllowed(bad, none)) << bad;
  const std::vector<std::string> allowed = {"Build.Example.com", "*.lab.example"};
  EXPECT_TRUE(HostHeaderAllowed("build.example.com:50052", allowed));
  EXPECT_TRUE(HostHeaderAllowed("rk.lab.example", allowed));
  EXPECT_TRUE(HostHeaderAllowed("a.rk.lab.example:1", allowed));
  EXPECT_FALSE(HostHeaderAllowed("lab.example", allowed));
  EXPECT_FALSE(HostHeaderAllowed("evillab.example", allowed));
  EXPECT_FALSE(HostHeaderAllowed("example.com", allowed));
}

TEST_F(ServerTest, ForeignHostIsRefused) {
  auto http = Http();
  const std::string port = std::to_string(server->http_port());
  // The rebinding attack: same-origin to the browser, Host and Origin both
  // the attacker's name. Refused before any handler, static files too.
  httplib::Headers evil = {{"Host", "evil.example.com:" + port}, {"Origin", "http://evil.example.com:" + port}};
  auto res = http.Post("/revkit.v1.QueryService/ListFunctions", evil, R"({"programId":"demo/hello"})",
                       "application/json");
  ASSERT_TRUE(res);
  EXPECT_EQ(res->status, 421);
  EXPECT_NE(res->body.find("--allow-host"), std::string::npos) << res->body;
  EXPECT_EQ(res->body.find("FUN_"), std::string::npos);
  res = http.Get("/healthz", httplib::Headers{{"Host", "evil.example.com"}});
  ASSERT_TRUE(res);
  EXPECT_EQ(res->status, 421);
  // The daemon's own names, with their own Origin, are answered.
  for (const std::string host : {"localhost:" + port, "revkit.localhost:" + port, "127.0.0.1:" + port,
                                 "[::1]:" + port}) {
    res = http.Post("/revkit.v1.QueryService/ListFunctions", {{"Host", host}, {"Origin", "http://" + host}},
                    R"({"programId":"demo/hello"})", "application/json");
    ASSERT_TRUE(res) << host;
    EXPECT_EQ(res->status, 200) << host << ": " << res->body;
  }
  // A call from another site's page (a loopback Host, a foreign Origin)
  // is refused too; one from an origin --allow-origin names is not.
  res = http.Post("/revkit.v1.QueryService/ListFunctions", {{"Origin", "http://evil.example.com"}},
                  R"({"programId":"demo/hello"})", "application/json");
  ASSERT_TRUE(res);
  EXPECT_EQ(res->status, 403) << res->body;
  res = http.Post("/revkit.v1.QueryService/ListFunctions", {{"Origin", "http://localhost:5173"}},
                  R"({"programId":"demo/hello"})", "application/json");
  ASSERT_TRUE(res);
  EXPECT_EQ(res->status, 200) << res->body;
  // An own name on another port is another origin.
  res = http.Post("/revkit.v1.QueryService/ListFunctions", {{"Origin", "http://localhost:1"}},
                  R"({"programId":"demo/hello"})", "application/json");
  ASSERT_TRUE(res);
  EXPECT_EQ(res->status, 403) << res->body;
}

TEST_F(ServerTest, LoopbackListensOnBothFamilies) {
  // 127.0.0.1 named, ::1 too on the same port (http://revkit.localhost
  // resolves to either), unless this host has no IPv6 loopback.
  if (server->http_also_address().empty()) GTEST_SKIP() << "no IPv6 loopback here";
  EXPECT_EQ(server->http_also_address(), "[::1]:" + std::to_string(server->http_port()));
  httplib::Client v6("::1", server->http_port());
  v6.set_read_timeout(std::chrono::seconds(10));
  auto res = v6.Post("/revkit.v1.QueryService/ListFunctions", httplib::Headers{{"Host", "revkit.localhost"}},
                     R"({"programId":"demo/hello"})", "application/json");
  ASSERT_TRUE(res);
  EXPECT_EQ(res->status, 200) << res->body;
  res = v6.Get("/healthz", httplib::Headers{{"Host", "evil.example.com"}});
  ASSERT_TRUE(res);
  EXPECT_EQ(res->status, 421);
}

TEST(ServerHosts, AllowHostAndCertificateNames) {
  // --allow-host names, and over TLS the certificate's names.
  auto cert = auth::generate_self_signed({"rk.example.test"});
  ServerOptions opts;
  opts.grpc_address = "127.0.0.1:0";
  opts.http_address = "127.0.0.1:0";
  opts.allowed_hosts = {"build.example.com", "*.lab.example"};
  opts.tls = {cert.cert_pem, cert.key_pem};
  std::string error;
  auto server = Server::Start(MakeFakeBackend(), opts, error);
  ASSERT_TRUE(server) << error;
  httplib::SSLClient https("127.0.0.1", server->http_port());
  https.enable_server_certificate_verification(false);
  https.set_read_timeout(std::chrono::seconds(10));
  for (const char *host : {"build.example.com", "x.lab.example", "rk.example.test", "localhost"}) {
    auto res = https.Get("/healthz", httplib::Headers{{"Host", host}});
    ASSERT_TRUE(res) << host;
    EXPECT_EQ(res->status, 200) << host;
  }
  for (const char *host : {"evil.example.com", "lab.example", "example.test"}) {
    auto res = https.Get("/healthz", httplib::Headers{{"Host", host}});
    ASSERT_TRUE(res) << host;
    EXPECT_EQ(res->status, 421) << host;
  }
}

TEST_F(ServerTest, ShutdownEndsOpenStreams) {
  auto subs = pb::SubscriptionService::NewStub(channel);
  grpc::ClientContext ctx;
  pb::SubscribeRequest req;
  req.set_project_id(fake::kProjectId);
  auto reader = subs->Subscribe(&ctx, req);
  pb::SubscribeResponse ev;
  ASSERT_TRUE(reader->Read(&ev));
  auto start = std::chrono::steady_clock::now();
  server->Shutdown();
  while (reader->Read(&ev)) {
  }
  EXPECT_EQ(reader->Finish().error_code(), grpc::StatusCode::UNAVAILABLE);
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(3));
}

// Browser calls arriving while the server shuts down (a page reconnecting
// as its stream ends) get UNAVAILABLE; creating them on the in-process
// channel after gRPC's Shutdown used to crash the daemon.
TEST_F(ServerTest, BrowserCallsDuringShutdown) {
  std::atomic<bool> done{false};
  std::atomic<int> answered{0};
  std::vector<std::thread> callers;
  for (int i = 0; i < 4; ++i)
    callers.emplace_back([&] {
      httplib::Client c("127.0.0.1", server->http_port());
      c.set_connection_timeout(std::chrono::seconds(1));
      c.set_read_timeout(std::chrono::seconds(5));
      while (!done) {
        auto r = c.Post("/revkit.v1.MetaService/GetServerInfo", "{}", "application/json");
        if (r) ++answered;
      }
    });
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  server->Shutdown();
  done = true;
  for (auto &t : callers) t.join();
  EXPECT_GT(answered.load(), 0);
}

}  // namespace
}  // namespace revkit::api
