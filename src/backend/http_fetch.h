// A bounded HTTP(S) GET for the downloads the daemon makes on its users'
// behalf (symbol servers, debuginfod; docs/security.md): at most max_bytes,
// a deadline for the whole transfer as well as for each connect and read,
// certificates checked (httplib's defaults: the system's roots, the host
// name), and redirects followed by a policy instead of httplib's, which
// follows any redirect anywhere, https to http included.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace revkit::backend {

// scheme://host[:port] of a URL, lower-cased; "" when it has none.
std::string UrlOrigin(std::string_view url);

// `s` with every byte but RFC 3986's unreserved ones (A-Z a-z 0-9 - . _ ~)
// percent-encoded: one path segment.
std::string PercentEncodeSegment(std::string_view s);

struct HttpGetOptions {
  std::string user_agent;
  int timeout_seconds = 60;  // the connection, and each read
  // The whole transfer, redirects included; 0: 30 × timeout_seconds.
  int total_seconds = 0;
  std::uint64_t max_bytes = std::uint64_t{1} << 30;
  // A redirect to another scheme, host or port is followed only when this
  // is set and it is to https:// (msdl.microsoft.com sends its PDBs from a
  // CDN). Never from https to http. Within the same origin always.
  bool cross_origin_https = false;
  int max_redirects = 5;
};

struct HttpGetResult {
  enum class Kind {
    kOk,           // HTTP 200, the body delivered
    kUnreachable,  // no connection, TLS refused, a read timed out
    kTooBig,       // more than max_bytes, or past the deadline
    kHttpStatus,   // another status (`status`)
    kRedirectRefused,
  };
  Kind kind = Kind::kUnreachable;
  int status = 0;
  std::string url;    // the last URL asked
  std::string error;  // why, for a log line ("" when kOk)
};

// GETs origin + path. `clear` and `append` receive the body (cleared again
// on each redirect); the body is only the answer's when kOk.
HttpGetResult HttpGetBounded(const std::string &origin, const std::string &path, const HttpGetOptions &options,
                             const std::function<void()> &clear,
                             const std::function<void(const char *, std::size_t)> &append);

}  // namespace revkit::backend
