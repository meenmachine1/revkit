// The bounded GET the symbol server and debuginfod downloads use: the
// redirect policy (the same origin always; another host over https only
// when allowed; never to plain http; no malformed locations; at most 5),
// the size limit, the whole-transfer deadline, and certificate checks (a
// self-signed server is refused). Loopback servers only.
#include "http_fetch.h"

#include "revkit/auth/tls.h"

#include <gtest/gtest.h>
#include <httplib.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

namespace revkit::backend {
namespace {

using Kind = HttpGetResult::Kind;

struct Served {
  httplib::Server server;
  int port = 0;
  std::thread thread;
  Served() = default;
  void Start() {
    port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);
    thread = std::thread([this] { server.listen_after_bind(); });
    server.wait_until_ready();
  }
  ~Served() {
    server.stop();
    if (thread.joinable()) thread.join();
  }
  std::string Origin() const { return "http://127.0.0.1:" + std::to_string(port); }
};

HttpGetResult Get(const std::string &origin, const std::string &path, const HttpGetOptions &o, std::string &body) {
  return HttpGetBounded(
      origin, path, o, [&] { body.clear(); }, [&](const char *d, std::size_t n) { body.append(d, n); });
}

TEST(HttpFetch, PercentEncodesASegment) {
  EXPECT_EQ(PercentEncodeSegment("ntdll.pdb"), "ntdll.pdb");
  EXPECT_EQ(PercentEncodeSegment("a?b#c%d e/f"), "a%3Fb%23c%25d%20e%2Ff");
  EXPECT_EQ(UrlOrigin("HTTPS://Example.COM:8443/x/Y"), "https://example.com:8443");
}

TEST(HttpFetch, RedirectPolicy) {
  Served other;
  std::atomic<int> other_asked{0};
  other.server.Get(R"(/.*)", [&](const httplib::Request &, httplib::Response &res) {
    ++other_asked;
    res.set_content("elsewhere", "text/plain");
  });
  other.Start();
  Served s;
  s.server.Get("/file", [](const httplib::Request &, httplib::Response &res) { res.set_content("body", "text/plain"); });
  s.server.Get("/same", [](const httplib::Request &, httplib::Response &res) { res.set_redirect("/file"); });
  s.server.Get("/same-absolute", [&](const httplib::Request &, httplib::Response &res) {
    res.set_redirect(s.Origin() + "/file");
  });
  s.server.Get("/other", [&](const httplib::Request &, httplib::Response &res) {
    res.set_redirect(other.Origin() + "/file");
  });
  s.server.Get("/protocol-relative", [&](const httplib::Request &, httplib::Response &res) {
    res.set_redirect("//127.0.0.1:" + std::to_string(other.port) + "/file");
  });
  s.server.Get("/spaces", [](const httplib::Request &, httplib::Response &res) {
    res.status = 302;
    res.set_header("Location", "/file HTTP/1.1\tX-Injected: 1");
  });
  s.server.Get("/loop", [](const httplib::Request &, httplib::Response &res) { res.set_redirect("/loop"); });
  s.server.Get("/missing", [](const httplib::Request &, httplib::Response &res) { res.status = 404; });
  s.Start();

  HttpGetOptions o;
  o.timeout_seconds = 5;
  std::string body;
  auto r = Get(s.Origin(), "/same", o, body);
  EXPECT_EQ(r.kind, Kind::kOk) << r.error;
  EXPECT_EQ(body, "body");
  r = Get(s.Origin(), "/same-absolute", o, body);
  EXPECT_EQ(r.kind, Kind::kOk) << r.error;
  EXPECT_EQ(body, "body");
  // Another host: never without cross_origin_https; with it, only to https.
  for (bool cross : {false, true}) {
    o.cross_origin_https = cross;
    r = Get(s.Origin(), "/other", o, body);
    EXPECT_EQ(r.kind, Kind::kRedirectRefused) << cross;
    EXPECT_NE(r.error.find("another host"), std::string::npos) << r.error;
    EXPECT_TRUE(body.empty());
    r = Get(s.Origin(), "/protocol-relative", o, body);
    EXPECT_EQ(r.kind, Kind::kRedirectRefused) << cross;
  }
  EXPECT_EQ(other_asked.load(), 0);
  o.cross_origin_https = false;
  r = Get(s.Origin(), "/spaces", o, body);
  EXPECT_EQ(r.kind, Kind::kRedirectRefused);
  EXPECT_NE(r.error.find("malformed"), std::string::npos) << r.error;
  r = Get(s.Origin(), "/loop", o, body);
  EXPECT_EQ(r.kind, Kind::kRedirectRefused);
  EXPECT_NE(r.error.find("redirects"), std::string::npos) << r.error;
  r = Get(s.Origin(), "/missing", o, body);
  EXPECT_EQ(r.kind, Kind::kHttpStatus);
  EXPECT_EQ(r.status, 404);
}

TEST(HttpFetch, SizeAndDeadline) {
  Served s;
  s.server.Get("/big", [](const httplib::Request &, httplib::Response &res) {
    res.set_content(std::string(1 << 20, 'x'), "application/octet-stream");
  });
  // A byte every 200 ms: no read times out, the transfer never ends.
  s.server.Get("/trickle", [](const httplib::Request &, httplib::Response &res) {
    res.set_chunked_content_provider("application/octet-stream", [](std::size_t, httplib::DataSink &sink) {
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
      return sink.write("x", 1);
    });
  });
  s.Start();
  HttpGetOptions o;
  o.timeout_seconds = 5;
  o.max_bytes = 1000;
  std::string body;
  auto r = Get(s.Origin(), "/big", o, body);
  EXPECT_EQ(r.kind, Kind::kTooBig);
  EXPECT_NE(r.error.find("larger than allowed"), std::string::npos);
  EXPECT_TRUE(body.empty());
  o.max_bytes = 1 << 20;
  o.total_seconds = 1;
  const auto start = std::chrono::steady_clock::now();
  r = Get(s.Origin(), "/trickle", o, body);
  EXPECT_EQ(r.kind, Kind::kTooBig);
  EXPECT_NE(r.error.find("longer than"), std::string::npos) << r.error;
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(5));
}

TEST(HttpFetch, RefusesAnUntrustedCertificate) {
  const auth::CertKey ck = auth::generate_self_signed({}, 1);
  httplib::SSLServer::PemMemory pem{};
  pem.cert_pem = ck.cert_pem.c_str();
  pem.cert_pem_len = ck.cert_pem.size();
  pem.key_pem = ck.key_pem.c_str();
  pem.key_pem_len = ck.key_pem.size();
  httplib::SSLServer server(pem);
  ASSERT_TRUE(server.is_valid());
  std::atomic<int> asked{0};
  server.Get("/file", [&](const httplib::Request &, httplib::Response &res) {
    ++asked;
    res.set_content("secret", "text/plain");
  });
  const int port = server.bind_to_any_port("127.0.0.1");
  ASSERT_GT(port, 0);
  std::thread t([&] { server.listen_after_bind(); });
  server.wait_until_ready();
  HttpGetOptions o;
  o.timeout_seconds = 5;
  std::string body;
  const auto r = Get("https://127.0.0.1:" + std::to_string(port), "/file", o, body);
  EXPECT_EQ(r.kind, Kind::kUnreachable) << r.error;
  EXPECT_TRUE(body.empty());
  EXPECT_EQ(asked.load(), 0);
  server.stop();
  t.join();
}

}  // namespace
}  // namespace revkit::backend
