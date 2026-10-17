#include "http_fetch.h"

#include <httplib.h>

#include <algorithm>
#include <cctype>
#include <chrono>

namespace revkit::backend {

std::string UrlOrigin(std::string_view url) {
  const std::size_t scheme_end = url.find("://");
  if (scheme_end == std::string_view::npos) return {};
  const std::size_t path_at = url.find('/', scheme_end + 3);
  std::string o(url.substr(0, path_at));
  std::transform(o.begin(), o.end(), o.begin(), [](unsigned char c) { return std::tolower(c); });
  return o;
}

std::string PercentEncodeSegment(std::string_view s) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(s.size());
  for (char ch : s) {
    const auto c = static_cast<unsigned char>(ch);
    if (std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~') {
      out += ch;
    } else {
      out += '%';
      out += kHex[c >> 4];
      out += kHex[c & 15];
    }
  }
  return out;
}

namespace {

// A Location value fit to put on a request line: no controls, no spaces.
bool PlainLocation(std::string_view loc) {
  if (loc.empty() || loc.size() > 4096) return false;
  return std::none_of(loc.begin(), loc.end(), [](char c) {
    const auto u = static_cast<unsigned char>(c);
    return u <= 0x20 || u == 0x7f;
  });
}

}  // namespace

HttpGetResult HttpGetBounded(const std::string &origin_in, const std::string &path_in, const HttpGetOptions &options,
                             const std::function<void()> &clear,
                             const std::function<void(const char *, std::size_t)> &append) {
  using Clock = std::chrono::steady_clock;
  const int total = options.total_seconds > 0 ? options.total_seconds : 30 * std::max(options.timeout_seconds, 1);
  const Clock::time_point deadline = Clock::now() + std::chrono::seconds(total);
  std::string origin = UrlOrigin(origin_in), path = path_in;
  HttpGetResult r;
  for (int hop = 0;; ++hop) {
    r.url = origin + path;
    if (!origin.starts_with("https://") && !origin.starts_with("http://")) {
      r.kind = HttpGetResult::Kind::kUnreachable;
      r.error = "not an http(s) URL";
      return r;
    }
    httplib::Client client(origin);
    client.set_follow_location(false);  // by the policy below
    client.set_connection_timeout(options.timeout_seconds, 0);
    client.set_read_timeout(options.timeout_seconds, 0);
    if (!options.user_agent.empty()) client.set_default_headers({{"User-Agent", options.user_agent}});
    clear();
    std::uint64_t got = 0;
    bool too_big = false, late = false;
    auto res = client.Get(path, [&](const char *data, std::size_t n) {
      if (got + n > options.max_bytes) {
        too_big = true;
        return false;
      }
      if (Clock::now() > deadline) {
        late = true;
        return false;
      }
      got += n;
      append(data, n);
      return true;
    });
    if (too_big || late) {
      clear();
      r.kind = HttpGetResult::Kind::kTooBig;
      r.error = too_big ? "larger than allowed" : "took longer than " + std::to_string(total) + " s";
      return r;
    }
    if (!res) {
      clear();
      r.kind = HttpGetResult::Kind::kUnreachable;
      r.error = httplib::to_string(res.error());
      return r;
    }
    r.status = res->status;
    if (res->status >= 300 && res->status < 400 && res->has_header("Location")) {
      clear();
      const std::string loc = res->get_header_value("Location");
      if (hop >= options.max_redirects) {
        r.kind = HttpGetResult::Kind::kRedirectRefused;
        r.error = "more than " + std::to_string(options.max_redirects) + " redirects";
        return r;
      }
      if (!PlainLocation(loc)) {
        r.kind = HttpGetResult::Kind::kRedirectRefused;
        r.error = "a redirect to a malformed location isn't followed";
        return r;
      }
      if (loc.starts_with("/") && !loc.starts_with("//")) {
        path = loc;
        continue;
      }
      const std::string to = UrlOrigin(loc);
      const std::size_t path_at = to.size();
      const std::string to_path = loc.size() > path_at ? loc.substr(path_at) : std::string("/");
      if (to.empty() || (path_at < loc.size() && loc[path_at] != '/')) {
        r.kind = HttpGetResult::Kind::kRedirectRefused;
        r.error = "a redirect to a relative or odd location (" + loc.substr(0, 200) + ") isn't followed";
        return r;
      }
      if (to == origin) {
        path = to_path;
        continue;
      }
      const bool https = to.starts_with("https://");
      const std::string_view host = std::string_view(to).substr(to.find("://") + 3);
      const bool plain_host = !host.empty() && std::all_of(host.begin(), host.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == ':' || c == '[' || c == ']';
      });
      if (!options.cross_origin_https || !https || !plain_host) {
        r.kind = HttpGetResult::Kind::kRedirectRefused;
        r.error = "a redirect to another host (" + loc.substr(0, 200) + ") isn't followed" +
                  std::string(options.cross_origin_https && !https ? ": it isn't https" : "");
        return r;
      }
      origin = to;
      path = to_path;
      continue;
    }
    if (res->status != 200) {
      clear();
      r.kind = HttpGetResult::Kind::kHttpStatus;
      r.error = "HTTP " + std::to_string(res->status);
      return r;
    }
    r.kind = HttpGetResult::Kind::kOk;
    r.error.clear();
    return r;
  }
}

}  // namespace revkit::backend
