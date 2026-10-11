#include "connect_gateway.h"

#include "grpc_services.h"
#include "revkit/auth/crypto.h"
#include "revkit/auth/store.h"
#include "revkit/v1/auth.pb.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/util/json_util.h>
#include <google/protobuf/util/type_resolver.h>
#include <google/protobuf/util/type_resolver_util.h>
#include <grpcpp/generic/generic_stub.h>
#include <httplib.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <functional>
#include <optional>
#include <shared_mutex>
#include <thread>

namespace revkit::api {
namespace {

namespace gp = google::protobuf;

constexpr const char *kTypeUrlPrefix = "type.googleapis.com";

enum class Protocol { kConnectUnary, kConnectStream, kGrpcWeb };
enum class Codec { kProto, kJson };

struct CodeInfo {
  const char *name;
  int http;
};

// Connect's code names and their HTTP statuses (connectrpc.com/docs/protocol).
CodeInfo ConnectCode(grpc::StatusCode code) {
  switch (code) {
    case grpc::StatusCode::CANCELLED: return {"canceled", 499};
    case grpc::StatusCode::INVALID_ARGUMENT: return {"invalid_argument", 400};
    case grpc::StatusCode::DEADLINE_EXCEEDED: return {"deadline_exceeded", 504};
    case grpc::StatusCode::NOT_FOUND: return {"not_found", 404};
    case grpc::StatusCode::ALREADY_EXISTS: return {"already_exists", 409};
    case grpc::StatusCode::PERMISSION_DENIED: return {"permission_denied", 403};
    case grpc::StatusCode::RESOURCE_EXHAUSTED: return {"resource_exhausted", 429};
    case grpc::StatusCode::FAILED_PRECONDITION: return {"failed_precondition", 400};
    case grpc::StatusCode::ABORTED: return {"aborted", 409};
    case grpc::StatusCode::OUT_OF_RANGE: return {"out_of_range", 400};
    case grpc::StatusCode::UNIMPLEMENTED: return {"unimplemented", 501};
    case grpc::StatusCode::INTERNAL: return {"internal", 500};
    case grpc::StatusCode::UNAVAILABLE: return {"unavailable", 503};
    case grpc::StatusCode::DATA_LOSS: return {"data_loss", 500};
    case grpc::StatusCode::UNAUTHENTICATED: return {"unauthenticated", 401};
    default: return {"unknown", 500};
  }
}

std::string Lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
  return s;
}

std::string JsonString(const std::string &s) {
  std::string out = "\"";
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", c);
          out += buf;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out + "\"";
}

std::string ConnectErrorJson(const grpc::Status &st) {
  return "{\"code\":" + JsonString(ConnectCode(st.error_code()).name) + ",\"message\":" +
         JsonString(st.error_message()) + "}";
}

// gRPC's percent-encoding for grpc-message.
std::string PercentEncode(const std::string &s) {
  std::string out;
  for (unsigned char c : s) {
    if (c >= 0x20 && c <= 0x7e && c != '%') {
      out += static_cast<char>(c);
    } else {
      char buf[4];
      std::snprintf(buf, sizeof buf, "%%%02X", c);
      out += buf;
    }
  }
  return out;
}

// Length-prefixed message framing shared by Connect streaming and gRPC-web.
std::string Envelope(std::uint8_t flags, const std::string &payload) {
  std::string out(5, '\0');
  out[0] = static_cast<char>(flags);
  auto n = static_cast<std::uint32_t>(payload.size());
  out[1] = static_cast<char>(n >> 24);
  out[2] = static_cast<char>(n >> 16);
  out[3] = static_cast<char>(n >> 8);
  out[4] = static_cast<char>(n);
  return out + payload;
}

bool Unenvelope(const std::string &body, std::uint8_t &flags, std::string &payload) {
  if (body.size() < 5) return false;
  flags = static_cast<std::uint8_t>(body[0]);
  std::uint32_t n = (std::uint32_t(std::uint8_t(body[1])) << 24) | (std::uint32_t(std::uint8_t(body[2])) << 16) |
                    (std::uint32_t(std::uint8_t(body[3])) << 8) | std::uint32_t(std::uint8_t(body[4]));
  if (body.size() < 5 + std::size_t{n}) return false;
  payload = body.substr(5, n);
  return true;
}

// Headers that describe the HTTP exchange itself rather than the call.
bool ForwardableHeader(const std::string &key) {
  static const char *const kSkip[] = {
      "host", "content-type", "content-length", "connection", "accept", "accept-encoding", "accept-language",
      "user-agent", "connect-protocol-version", "connect-timeout-ms", "connect-accept-encoding",
      "connect-content-encoding", "content-encoding", "grpc-timeout", "grpc-encoding", "grpc-accept-encoding",
      "te", "origin", "referer", "transfer-encoding", "keep-alive", "upgrade", "cookie", "x-grpc-web",
      "x-user-agent", "remote_addr", "remote_port", "local_addr", "local_port", "cache-control", "pragma",
      "priority", "dnt", "x-csrf-token", kGatewayMetadata, kForwardedForMetadata, "x-real-ip", "forwarded"};
  if (key.starts_with("sec-") || key.starts_with("access-control-") || key.starts_with(":")) return false;
  for (const char *s : kSkip)
    if (key == s) return false;
  return std::all_of(key.begin(), key.end(), [](unsigned char c) {
    return std::islower(c) || std::isdigit(c) || c == '-' || c == '_' || c == '.';
  });
}

bool PrintableValue(const std::string &v) {
  return std::all_of(v.begin(), v.end(), [](unsigned char c) { return c >= 0x20 && c <= 0x7e; });
}

// "10S", "250m" -> duration (gRPC timeout header syntax).
std::optional<std::chrono::milliseconds> ParseGrpcTimeout(const std::string &v) {
  if (v.size() < 2) return std::nullopt;
  std::uint64_t n = 0;
  for (std::size_t i = 0; i + 1 < v.size(); ++i) {
    if (!std::isdigit(static_cast<unsigned char>(v[i]))) return std::nullopt;
    n = n * 10 + (v[i] - '0');
  }
  using namespace std::chrono;
  switch (v.back()) {
    case 'H': return duration_cast<milliseconds>(hours(n));
    case 'M': return duration_cast<milliseconds>(minutes(n));
    case 'S': return duration_cast<milliseconds>(seconds(n));
    case 'm': return milliseconds(n);
    case 'u': return duration_cast<milliseconds>(microseconds(n));
    case 'n': return duration_cast<milliseconds>(nanoseconds(n));
    default: return std::nullopt;
  }
}

// The value of cookie `name` in the request's Cookie headers ("" if none).
std::string CookieValue(const httplib::Request &req, const std::string &name) {
  auto range = req.headers.equal_range("Cookie");
  for (auto it = range.first; it != range.second; ++it) {
    std::string_view rest = it->second;
    while (!rest.empty()) {
      auto semi = rest.find(';');
      std::string_view pair = rest.substr(0, semi);
      rest = semi == std::string_view::npos ? std::string_view() : rest.substr(semi + 1);
      while (!pair.empty() && pair.front() == ' ') pair.remove_prefix(1);
      auto eq = pair.find('=');
      if (eq != std::string_view::npos && pair.substr(0, eq) == name) return std::string(pair.substr(eq + 1));
    }
  }
  return "";
}

// Calls a cookie-authenticated browser may make without the CSRF header:
// they change nothing, and WhoAmI is how a reloaded page gets the token.
bool CsrfExempt(const std::string &path) {
  return path == "revkit.v1.AuthService/WhoAmI" || path == "revkit.v1.AuthService/Login" ||
         path == "revkit.v1.MetaService/GetServerInfo";
}

// A call through the generic stub, driven synchronously from one HTTP
// worker thread. Unary and server-streaming methods are both run as
// "send one message, half-close, read until the end", which is what they
// are on the wire.
class GenericCall {
 public:
  GenericCall(grpc::GenericStub &stub, const std::string &path) : stub_(stub), path_(path) {}

  ~GenericCall() {
    if (started_ && !finished_) {
      ctx_.TryCancel();
      Finish();
    }
    cq_.Shutdown();
    void *tag;
    bool ok;
    while (cq_.Next(&tag, &ok)) {
    }
  }

  grpc::ClientContext &context() { return ctx_; }

  // Starts the call and sends the request. On false, Finish() has the reason.
  bool Start(const std::string &request) {
    started_ = true;
    rw_ = stub_.PrepareCall(&ctx_, path_, &cq_);
    rw_->StartCall(this);
    if (!Wait(nullptr)) return false;
    grpc::Slice slice(request);
    grpc::ByteBuffer buf(&slice, 1);
    rw_->Write(buf, this);
    if (!Wait(nullptr)) return false;
    rw_->WritesDone(this);
    return Wait(nullptr);
  }

  // The next response message, or nullopt at the end of the stream. While
  // waiting, polls `alive`; once it reports the HTTP client gone, the call
  // is cancelled so the server-side handler stops.
  std::optional<std::string> Read(const std::function<bool()> &alive) {
    if (read_done_) return std::nullopt;
    grpc::ByteBuffer buf;
    rw_->Read(&buf, this);
    if (!Wait(alive)) {
      read_done_ = true;
      return std::nullopt;
    }
    std::vector<grpc::Slice> slices;
    std::string out;
    if (buf.Dump(&slices).ok())
      for (const auto &s : slices) out.append(reinterpret_cast<const char *>(s.begin()), s.size());
    return out;
  }

  grpc::Status Finish() {
    if (finished_) return status_;
    finished_ = true;
    rw_->Finish(&status_, this);
    Wait(nullptr);
    return status_;
  }

 private:
  // Only one operation is ever outstanding, so the tag carries no meaning.
  bool Wait(const std::function<bool()> &alive) {
    void *tag;
    bool ok = false;
    while (true) {
      auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(250);
      switch (cq_.AsyncNext(&tag, &ok, deadline)) {
        case grpc::CompletionQueue::GOT_EVENT: return ok;
        case grpc::CompletionQueue::SHUTDOWN: return false;
        case grpc::CompletionQueue::TIMEOUT:
          if (alive && !alive()) ctx_.TryCancel();
          break;
      }
    }
  }

  grpc::GenericStub &stub_;
  std::string path_;
  grpc::ClientContext ctx_;
  grpc::CompletionQueue cq_;
  std::unique_ptr<grpc::GenericClientAsyncReaderWriter> rw_;
  grpc::Status status_;
  bool started_ = false, finished_ = false, read_done_ = false;
};

}  // namespace

bool SplitHostPort(const std::string &address, std::string &host, int &port) {
  auto colon = address.rfind(':');
  if (colon == std::string::npos || colon + 1 == address.size()) return false;
  host = address.substr(0, colon);
  if (host.size() >= 2 && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size() - 2);
  try {
    std::size_t used = 0;
    port = std::stoi(address.substr(colon + 1), &used);
    if (used != address.size() - colon - 1 || port < 0 || port > 65535) return false;
  } catch (...) {
    return false;
  }
  return !host.empty();
}

const char *SessionCookieName(bool tls) { return tls ? "__Host-rk_session" : "rk_session"; }

namespace {

// The host of an authority ("[::1]:80" -> "::1", "Name.Example:1" ->
// "name.example"), lowercased, without a trailing dot; nullopt when it isn't
// one (a path, user info, a bad port).
std::optional<std::string> AuthorityHost(std::string_view a) {
  if (a.empty() || a.size() > 300) return std::nullopt;
  std::string host;
  if (a.front() == '[') {
    const auto close = a.find(']');
    if (close == std::string_view::npos) return std::nullopt;
    host = std::string(a.substr(1, close - 1));
    a.remove_prefix(close + 1);
    if (!a.empty() && a.front() != ':') return std::nullopt;
  } else {
    const auto colon = a.find(':');
    host = std::string(a.substr(0, colon));
    a.remove_prefix(colon == std::string_view::npos ? a.size() : colon);
  }
  if (!a.empty()) {  // ":port"
    a.remove_prefix(1);
    if (a.empty() || a.size() > 5 || !std::all_of(a.begin(), a.end(), [](char c) { return c >= '0' && c <= '9'; }))
      return std::nullopt;
  }
  for (char &c : host) {
    const auto u = static_cast<unsigned char>(c);
    if (!(std::isalnum(u) || c == '-' || c == '.' || c == '_' || c == ':' || c == '%')) return std::nullopt;
    c = static_cast<char>(std::tolower(u));
  }
  if (!host.empty() && host.back() == '.') host.pop_back();
  if (host.empty()) return std::nullopt;
  return host;
}

bool IpLiteral(const std::string &host) {
  unsigned char buf[16];
  return inet_pton(AF_INET, host.c_str(), buf) == 1 || inet_pton(AF_INET6, host.c_str(), buf) == 1;
}

// The port of an authority, or `dflt` when it names none.
int AuthorityPort(std::string_view a, int dflt) {
  const auto close = a.rfind(']');
  const auto colon = a.rfind(':');
  if (colon == std::string_view::npos || (close != std::string_view::npos && colon < close)) return dflt;
  try {
    return std::stoi(std::string(a.substr(colon + 1)));
  } catch (...) {
    return -1;
  }
}

}  // namespace

bool HostHeaderAllowed(const std::string &host_header, const std::vector<std::string> &allowed_hosts) {
  if (host_header.empty()) return true;
  const auto host = AuthorityHost(host_header);
  if (!host) return false;
  if (*host == "localhost" || host->ends_with(".localhost") || IpLiteral(*host)) return true;
  for (std::string a : allowed_hosts) {
    std::transform(a.begin(), a.end(), a.begin(), [](unsigned char c) { return std::tolower(c); });
    if (!a.empty() && a.back() == '.') a.pop_back();
    if (a == *host) return true;
    if (a.starts_with("*.") && host->size() > a.size() - 1 && host->ends_with(a.substr(1))) return true;
  }
  return false;
}

struct ConnectGateway::Impl {
  GatewayOptions options;
  grpc::GenericStub stub;
  std::unique_ptr<gp::util::TypeResolver> resolver;
  std::unique_ptr<httplib::Server> server;
  httplib::Server &http;
  std::thread thread;
  const std::string cookie_name;
  // Set by Close() as the server shuts down: no new call may be created on
  // the in-process channel once gRPC is shutting down (gRPC crashes creating
  // one then). Held shared while a call is created.
  std::shared_mutex closing_mu;
  bool closing = false;
  // The listening socket came from the service manager (Adopt).
  bool adopted = false;

  // Starts `call` unless the gateway is closing: nullopt then (the caller
  // answers UNAVAILABLE), else whether it started.
  std::optional<bool> StartCall(GenericCall &call, const std::string &request) {
    std::shared_lock lock(closing_mu);
    if (closing) return std::nullopt;
    return call.Start(request);
  }

  static std::unique_ptr<httplib::Server> MakeServer(const TlsConfig &tls) {
    if (!tls.enabled()) return std::make_unique<httplib::Server>();
    httplib::SSLServer::PemMemory pem{};
    pem.cert_pem = tls.cert_pem.c_str();
    pem.cert_pem_len = tls.cert_pem.size();
    pem.key_pem = tls.key_pem.c_str();
    pem.key_pem_len = tls.key_pem.size();
    auto server = std::make_unique<httplib::SSLServer>(pem);
    if (server->is_valid()) SSL_CTX_set_min_proto_version(static_cast<SSL_CTX *>(server->tls_context()), TLS1_2_VERSION);
    return server;
  }

  Impl(std::shared_ptr<grpc::Channel> channel, GatewayOptions opts)
      : options(std::move(opts)),
        stub(std::move(channel)),
        resolver(gp::util::NewTypeResolverForDescriptorPool(kTypeUrlPrefix, gp::DescriptorPool::generated_pool())),
        server(MakeServer(options.tls)),
        http(*server),
        cookie_name(SessionCookieName(options.tls.enabled())) {
    http.set_payload_max_length(options.max_message_bytes);
    // DNS rebinding: a page on a name the attacker controls, rebound to this
    // host's address, is same-origin with us to the browser. Its requests
    // still carry that name in Host: every request (static files too) must
    // name this daemon.
    http.set_pre_routing_handler([this](const httplib::Request &req, httplib::Response &res) {
      const std::string host = req.get_header_value("Host");
      if (HostHeaderAllowed(host, options.allowed_hosts)) return httplib::Server::HandlerResponse::Unhandled;
      SecurityHeaders(req, res);
      res.status = 421;  // Misdirected Request
      res.set_content("rk-daemon: refusing a request for host \"" + Printable(host) +
                          "\": not a name this daemon answers to (DNS rebinding protection). To allow it, start "
                          "rk-daemon with --allow-host NAME (or allow-host = NAME in revkit.conf).\n",
                      "text/plain");
      return httplib::Server::HandlerResponse::Handled;
    });
    http.set_post_routing_handler([this](const httplib::Request &req, httplib::Response &res) {
      Cors(req, res);
      SecurityHeaders(req, res);
    });
    http.Options(R"(/.*)", [this](const httplib::Request &req, httplib::Response &res) { Preflight(req, res); });
    http.Post(R"(/([A-Za-z_][A-Za-z0-9_.]*)/([A-Za-z_][A-Za-z0-9_]*))",
              [this](const httplib::Request &req, httplib::Response &res) { Handle(req, res); });
    http.Get("/healthz", [](const httplib::Request &, httplib::Response &res) { res.set_content("ok\n", "text/plain"); });
    if (!options.web_root.empty()) {
      http.set_mount_point("/", options.web_root);
    } else {
      http.Get("/", [](const httplib::Request &, httplib::Response &res) {
        res.set_content(
            "rk-daemon: revkit API\n"
            "POST /revkit.v1.<Service>/<Method> with Content-Type application/json (Connect unary),\n"
            "application/connect+json (Connect streaming) or application/grpc-web+proto.\n"
            "Example: curl -sS -H 'Content-Type: application/json' -d '{}' "
            "http://HOST/revkit.v1.MetaService/GetServerInfo\n",
            "text/plain");
      });
    }
  }

  // At most 100 bytes of `s`, printable ASCII only (for an error message).
  static std::string Printable(const std::string &s) {
    std::string out;
    for (char c : s.substr(0, 100)) out += (c >= 0x20 && c < 0x7f && c != '"') ? c : '?';
    return out;
  }

  // An Origin that is this daemon's own page: our scheme, a host the Host
  // check accepts and the port the request came to (not merely equal to
  // the request's Host, which the page's own name would satisfy).
  bool OwnOrigin(const std::string &origin, const httplib::Request &req) const {
    const std::string scheme = options.tls.enabled() ? "https://" : "http://";
    if (!origin.starts_with(scheme)) return false;
    const std::string authority = origin.substr(scheme.size());
    if (!AuthorityHost(authority) || !HostHeaderAllowed(authority, options.allowed_hosts)) return false;
    const int dflt = options.tls.enabled() ? 443 : 80;
    const std::string host = req.get_header_value("Host");
    return AuthorityPort(authority, dflt) == (host.empty() ? req.local_port : AuthorityPort(host, dflt));
  }

  bool OriginAllowed(const std::string &origin) const {
    return std::any_of(options.allowed_origins.begin(), options.allowed_origins.end(),
                       [&](const std::string &o) { return o == "*" || o == origin; });
  }

  void Cors(const httplib::Request &req, httplib::Response &res) const {
    std::string origin = req.get_header_value("Origin");
    if (origin.empty() || !OriginAllowed(origin)) return;
    res.set_header("Access-Control-Allow-Origin", origin);
    res.set_header("Vary", "Origin");
    res.set_header("Access-Control-Expose-Headers",
                   "Grpc-Status, Grpc-Message, Grpc-Status-Details-Bin, Connect-Protocol-Version, Content-Encoding");
  }

  static void SecurityHeaders(const httplib::Request &req, httplib::Response &res) {
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("Referrer-Policy", "no-referrer");
    if (req.method == "POST") res.set_header("Cache-Control", "no-store");
  }

  // "Set-Cookie" for the session (empty token: delete it).
  std::string SessionCookie(const std::string &token, std::int64_t max_age) const {
    std::string c = cookie_name + "=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" +
                    std::to_string(token.empty() ? 0 : std::max<std::int64_t>(max_age, 0));
    if (options.tls.enabled()) c += "; Secure";
    return c;
  }

  void Preflight(const httplib::Request &req, httplib::Response &res) const {
    res.status = 204;
    if (!OriginAllowed(req.get_header_value("Origin"))) return;
    res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.has_header("Access-Control-Request-Headers"))
      res.set_header("Access-Control-Allow-Headers", req.get_header_value("Access-Control-Request-Headers"));
    res.set_header("Access-Control-Max-Age", "7200");
  }

  std::string TypeUrl(const gp::Descriptor *d) const { return std::string(kTypeUrlPrefix) + "/" + d->full_name(); }

  bool JsonToBinary(const gp::Descriptor *type, const std::string &json, std::string &out, std::string &err) const {
    gp::util::JsonParseOptions opts;
    opts.ignore_unknown_fields = true;  // newer clients may send fields this server predates
    auto st = gp::util::JsonToBinaryString(resolver.get(), TypeUrl(type), json.empty() ? "{}" : json, &out, opts);
    if (!st.ok()) err = st.ToString();
    return st.ok();
  }

  bool BinaryToJson(const gp::Descriptor *type, const std::string &bin, std::string &out, std::string &err) const {
    auto st = gp::util::BinaryToJsonString(resolver.get(), TypeUrl(type), bin, &out, gp::util::JsonPrintOptions{});
    if (!st.ok()) err = st.ToString();
    return st.ok();
  }

  static void ConnectError(httplib::Response &res, const grpc::Status &st) {
    res.status = ConnectCode(st.error_code()).http;
    res.set_content(ConnectErrorJson(st), "application/json");
  }

  void Handle(const httplib::Request &req, httplib::Response &res) {
    const std::string service = req.matches[1], method = req.matches[2];
    std::string ct = Lower(req.get_header_value("Content-Type"));
    ct = ct.substr(0, ct.find(';'));
    while (!ct.empty() && ct.back() == ' ') ct.pop_back();

    Protocol protocol;
    Codec codec;
    if (ct == "application/json") protocol = Protocol::kConnectUnary, codec = Codec::kJson;
    else if (ct == "application/proto") protocol = Protocol::kConnectUnary, codec = Codec::kProto;
    else if (ct == "application/connect+json") protocol = Protocol::kConnectStream, codec = Codec::kJson;
    else if (ct == "application/connect+proto") protocol = Protocol::kConnectStream, codec = Codec::kProto;
    else if (ct == "application/grpc-web" || ct == "application/grpc-web+proto")
      protocol = Protocol::kGrpcWeb, codec = Codec::kProto;
    else {
      res.status = 415;
      res.set_header("Accept-Post",
                     "application/json, application/proto, application/connect+json, application/connect+proto, "
                     "application/grpc-web+proto");
      res.set_content("unsupported content type \"" + ct + "\"\n", "text/plain");
      return;
    }

    auto fail = [&](grpc::StatusCode code, const std::string &msg) {
      grpc::Status st(code, msg);
      if (protocol == Protocol::kConnectUnary) return ConnectError(res, st);
      // Streaming protocols report errors in-band with HTTP 200.
      res.status = 200;
      if (protocol == Protocol::kConnectStream) {
        res.set_content(Envelope(0x02, "{\"error\":" + ConnectErrorJson(st) + "}"), ct);
      } else {
        res.set_content(Envelope(0x80, "grpc-status:" + std::to_string(int(code)) + "\r\ngrpc-message:" +
                                           PercentEncode(msg) + "\r\n"),
                        "application/grpc-web+proto");
      }
    };

    // A browser call from another site's page: only the origins
    // --allow-origin names may make one (the browser's CORS check stops it
    // reading the answer, not the call itself).
    if (const std::string origin = req.get_header_value("Origin");
        !origin.empty() && !OriginAllowed(origin) && !OwnOrigin(origin, req))
      return fail(grpc::StatusCode::PERMISSION_DENIED,
                  "cross-origin call from " + Printable(origin) + " refused (rk-daemon --allow-origin allows an origin)");

    const gp::MethodDescriptor *md = gp::DescriptorPool::generated_pool()->FindMethodByName(service + "." + method);
    if (!md) return fail(grpc::StatusCode::UNIMPLEMENTED, "unknown method " + service + "/" + method);
    if (md->client_streaming())
      return fail(grpc::StatusCode::UNIMPLEMENTED, "client-streaming methods are not available over HTTP/1.1");
    if (protocol == Protocol::kConnectUnary && md->server_streaming())
      return fail(grpc::StatusCode::UNIMPLEMENTED,
                  "streaming method: use Content-Type application/connect+json or application/connect+proto");
    if (protocol == Protocol::kConnectStream && !md->server_streaming())
      return fail(grpc::StatusCode::UNIMPLEMENTED,
                  "unary method: use Content-Type application/json or application/proto");
    for (const char *h : {"Content-Encoding", "Connect-Content-Encoding", "Grpc-Encoding"}) {
      std::string enc = Lower(req.get_header_value(h));
      if (!enc.empty() && enc != "identity")
        return fail(grpc::StatusCode::UNIMPLEMENTED, std::string("compression \"") + enc + "\" is not supported");
    }

    // Request message, as binary protobuf.
    std::string request = req.body;
    if (protocol != Protocol::kConnectUnary) {
      std::uint8_t flags = 0;
      if (!Unenvelope(req.body, flags, request))
        return fail(grpc::StatusCode::INVALID_ARGUMENT, "malformed message envelope");
      if (flags & 0x01) return fail(grpc::StatusCode::UNIMPLEMENTED, "compressed messages are not supported");
    }
    if (codec == Codec::kJson) {
      std::string bin, err;
      if (!JsonToBinary(md->input_type(), request, bin, err))
        return fail(grpc::StatusCode::INVALID_ARGUMENT, "invalid JSON request: " + err);
      request = std::move(bin);
    }

    // Browser sessions: the cookie stands for `authorization: Bearer`,
    // once the request proves it came from our own page (Origin and the
    // session's CSRF token). An explicit authorization header wins.
    const std::string path = service + "/" + method;
    std::string session_token;
    if (options.auth && !req.has_header("Authorization")) {
      if (std::string token = CookieValue(req, cookie_name); !token.empty()) {
        auto who = options.auth->authenticate(token);
        if (who && who->method == auth::AuthMethod::kSession) {
          if (!CsrfExempt(path)) {
            const std::string origin = req.get_header_value("Origin");
            if (!origin.empty() && !OwnOrigin(origin, req))
              return fail(grpc::StatusCode::PERMISSION_DENIED,
                          "cross-origin request with the session cookie refused; send a bearer token instead");
            const std::string csrf = req.get_header_value("X-CSRF-Token");
            if (csrf.empty() || !auth::constant_time_equal(csrf, who->csrf))
              return fail(grpc::StatusCode::PERMISSION_DENIED,
                          "missing or wrong x-csrf-token header (CSRF protection; WhoAmI returns the token)");
          }
          session_token = std::move(token);
        }
      }
    }
    const bool login = path == "revkit.v1.AuthService/Login", logout = path == "revkit.v1.AuthService/Logout";
    bool cookie_login = false;
    if (login) {
      pb::LoginRequest lr;
      cookie_login = lr.ParseFromString(request) && lr.session_cookie();
    }

    auto call = std::make_shared<GenericCall>(stub, "/" + service + "/" + method);
    auto &ctx = call->context();
    if (!session_token.empty()) ctx.AddMetadata("authorization", "Bearer " + session_token);
    if (!options.gateway_secret.empty()) ctx.AddMetadata(kGatewayMetadata, options.gateway_secret);
    if (std::string t = req.get_header_value("Connect-Timeout-Ms"); !t.empty()) {
      try {
        ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(std::stoll(t)));
      } catch (...) {
        return fail(grpc::StatusCode::INVALID_ARGUMENT, "malformed Connect-Timeout-Ms");
      }
    }
    if (auto t = ParseGrpcTimeout(req.get_header_value("Grpc-Timeout")))
      ctx.set_deadline(std::chrono::system_clock::now() + *t);
    for (const auto &[k, v] : req.headers) {
      std::string key = Lower(k);
      if (ForwardableHeader(key) && (key.ends_with("-bin") || PrintableValue(v))) ctx.AddMetadata(key, v);
    }
    // The in-process channel shows the server no peer; pass the browser's.
    ctx.AddMetadata("x-forwarded-for", req.remote_addr);

    const gp::Descriptor *out_type = md->output_type();
    if (protocol == Protocol::kConnectUnary) {
      Unary(*call, codec, out_type, request, res, [&](grpc::Status &st, std::optional<std::string> &reply) {
        if (logout) res.set_header("Set-Cookie", SessionCookie("", 0));
        if (!st.ok() || !reply || !cookie_login) return;
        pb::LoginResponse lr;
        if (!lr.ParseFromString(*reply)) return;
        res.set_header("Set-Cookie", SessionCookie(lr.token(), lr.expires_at().seconds() - std::time(nullptr)));
        lr.clear_token();  // the page never sees it
        reply = lr.SerializeAsString();
      });
      return;
    }
    Stream(std::move(call), protocol, codec, ct, out_type, request, res);
  }

  using UnaryHook = std::function<void(grpc::Status &, std::optional<std::string> &)>;

  void Unary(GenericCall &call, Codec codec, const gp::Descriptor *out_type, const std::string &request,
             httplib::Response &res, const UnaryHook &hook) {
    std::optional<std::string> reply;
    std::optional<bool> started = StartCall(call, request);
    if (!started) return ConnectError(res, grpc::Status(grpc::StatusCode::UNAVAILABLE, "rk-daemon is shutting down"));
    if (*started) {
      reply = call.Read(nullptr);
      while (call.Read(nullptr)) {
      }
    }
    grpc::Status st = call.Finish();
    hook(st, reply);
    for (const auto &[k, v] : call.context().GetServerInitialMetadata())
      res.set_header(std::string(k.data(), k.size()), std::string(v.data(), v.size()));
    for (const auto &[k, v] : call.context().GetServerTrailingMetadata())
      res.set_header("trailer-" + std::string(k.data(), k.size()), std::string(v.data(), v.size()));
    if (!st.ok()) return ConnectError(res, st);
    if (!reply) return ConnectError(res, grpc::Status(grpc::StatusCode::INTERNAL, "no response message"));
    if (codec == Codec::kProto) return res.set_content(*reply, "application/proto");
    std::string json, err;
    if (!BinaryToJson(out_type, *reply, json, err))
      return ConnectError(res, grpc::Status(grpc::StatusCode::INTERNAL, "cannot encode response: " + err));
    res.set_content(json, "application/json");
  }

  // Streams responses as they arrive. httplib calls the provider repeatedly
  // on this request's worker thread until it calls done() or returns false;
  // the GenericCall's destructor cancels the call if the client leaves early.
  void Stream(std::shared_ptr<GenericCall> call, Protocol protocol, Codec codec, const std::string &ct,
              const gp::Descriptor *out_type, const std::string &request, httplib::Response &res) {
    std::optional<bool> opened = StartCall(*call, request);
    if (!opened) return ConnectError(res, grpc::Status(grpc::StatusCode::UNAVAILABLE, "rk-daemon is shutting down"));
    bool started = *opened;
    res.status = 200;
    bool grpc_web = protocol == Protocol::kGrpcWeb;
    auto provider = [this, call, started, grpc_web, codec, out_type](std::size_t, httplib::DataSink &sink) {
      std::optional<std::string> msg;
      if (started) msg = call->Read([&sink] { return sink.is_writable(); });
      grpc::Status st;
      if (msg && codec == Codec::kJson) {
        std::string json, err;
        if (BinaryToJson(out_type, *msg, json, err)) {
          msg = std::move(json);
        } else {
          msg.reset();
          st = grpc::Status(grpc::StatusCode::INTERNAL, "cannot encode response: " + err);
        }
      }
      if (msg) {
        std::string frame = Envelope(0x00, *msg);
        return sink.write(frame.data(), frame.size());
      }
      grpc::Status finished = call->Finish();
      if (st.ok()) st = finished;
      std::string frame;
      if (grpc_web) {
        std::string trailers = "grpc-status:" + std::to_string(int(st.error_code())) + "\r\n";
        if (!st.ok()) trailers += "grpc-message:" + PercentEncode(st.error_message()) + "\r\n";
        for (const auto &[k, v] : call->context().GetServerTrailingMetadata())
          trailers += std::string(k.data(), k.size()) + ":" + std::string(v.data(), v.size()) + "\r\n";
        frame = Envelope(0x80, trailers);
      } else {
        std::string end = "{";
        if (!st.ok()) end += "\"error\":" + ConnectErrorJson(st);
        end += "}";
        frame = Envelope(0x02, end);
      }
      bool ok = sink.write(frame.data(), frame.size());
      sink.done();
      return ok;
    };
    res.set_chunked_content_provider(grpc_web ? "application/grpc-web+proto" : ct, std::move(provider));
  }
};

ConnectGateway::ConnectGateway(std::shared_ptr<grpc::Channel> channel, GatewayOptions options)
    : impl_(std::make_unique<Impl>(std::move(channel), std::move(options))) {}

ConnectGateway::~ConnectGateway() { Stop(); }

bool ConnectGateway::Valid(std::string &error) const {
  if (impl_->server->is_valid()) return true;
  error = "the HTTP listener refused the TLS certificate or key";
  return false;
}

int ConnectGateway::Bind(const std::string &address, std::string &error) {
  std::string host;
  int port = 0;
  if (!SplitHostPort(address, host, port)) {
    error = "malformed HTTP address \"" + address + "\" (want host:port)";
    return -1;
  }
  if (port == 0) port = impl_->http.bind_to_any_port(host);
  else if (!impl_->http.bind_to_port(host, port)) port = -1;
  if (port < 0) error = "cannot listen on " + address;
  return port;
}

namespace {
// httplib has no call to serve an existing listening socket, but keeps it in
// a protected member that bind_to_port fills; set it as bind_to_port would.
struct ListenSocketOf : httplib::Server {
  static std::atomic<socket_t> &Of(httplib::Server &s) { return s.*(&ListenSocketOf::svr_sock_); }
};
}  // namespace

int ConnectGateway::Adopt(int fd, std::string &error) {
  sockaddr_storage ss{};
  socklen_t len = sizeof ss;
  if (fd < 0 || getsockname(fd, reinterpret_cast<sockaddr *>(&ss), &len) != 0) {
    error = "inherited HTTP socket " + std::to_string(fd) + " is not a socket";
    return -1;
  }
  int port = -1;
  if (ss.ss_family == AF_INET) port = ntohs(reinterpret_cast<sockaddr_in *>(&ss)->sin_port);
  else if (ss.ss_family == AF_INET6) port = ntohs(reinterpret_cast<sockaddr_in6 *>(&ss)->sin6_port);
  if (port < 0) {
    error = "inherited HTTP socket " + std::to_string(fd) + " is not TCP";
    return -1;
  }
  auto &sock = ListenSocketOf::Of(impl_->http);
  if (sock != INVALID_SOCKET) {
    error = "the HTTP listener is already bound";
    return -1;
  }
  sock = fd;
  impl_->adopted = true;
  // Stop() can't shutdown() this socket (see there), so the accept loop
  // polls, and notices the stop within this interval.
  impl_->http.set_idle_interval(0, 200000);
  return port;
}

void ConnectGateway::Start() {
  impl_->thread = std::thread([this] { impl_->http.listen_after_bind(); });
}

void ConnectGateway::Close() {
  std::unique_lock lock(impl_->closing_mu);
  impl_->closing = true;
}

void ConnectGateway::Stop() {
  if (!impl_) return;
  if (impl_->adopted) {
    // Not httplib's stop(): it shutdown()s the listening socket, which would
    // end the service manager's copy too (the socket unit fails, and nothing
    // starts the daemon again). Take it out of the loop, let the loop see
    // that, then close only our descriptor.
    socket_t fd = ListenSocketOf::Of(impl_->http).exchange(INVALID_SOCKET);
    if (impl_->thread.joinable()) impl_->thread.join();
    if (fd != INVALID_SOCKET) ::close(fd);
    impl_->adopted = false;
  }
  impl_->http.stop();
  if (impl_->thread.joinable()) impl_->thread.join();
}

}  // namespace revkit::api
