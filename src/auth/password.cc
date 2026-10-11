#include "revkit/auth/password.h"

#include "revkit/auth/crypto.h"

#include <openssl/evp.h>

#include <charconv>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <vector>

namespace revkit::auth {
namespace {

constexpr std::size_t kSaltBytes = 16;
constexpr std::size_t kHashBytes = 32;

// Bounds on parameters read from a stored hash.
constexpr unsigned kMinLogN = 1, kMaxLogN = 22;
constexpr unsigned kMaxR = 32, kMaxP = 16;

// Two scrypt computations at a time (2 x 128 MiB with the defaults).
class Gate {
 public:
  void enter() {
    std::unique_lock lock(mu_);
    cv_.wait(lock, [&] { return busy_ < 2; });
    ++busy_;
  }
  void leave() {
    std::lock_guard lock(mu_);
    --busy_;
    cv_.notify_one();
  }

 private:
  std::mutex mu_;
  std::condition_variable cv_;
  int busy_ = 0;
};
Gate &gate() {
  static Gate g;
  return g;
}

std::string unpadded(std::string_view bytes) {
  std::string s = base64(bytes);
  while (!s.empty() && s.back() == '=') s.pop_back();
  return s;
}

std::optional<std::string> from_unpadded(std::string_view text) {
  std::string s(text);
  while (s.size() % 4) s += '=';
  return unbase64(s);
}

std::string scrypt(std::string_view password, std::string_view salt, const ScryptParams &p) {
  std::string out(kHashBytes, '\0');
  const std::uint64_t n = std::uint64_t{1} << p.log_n;
  // scrypt needs 128 * N * r * p bytes, plus a little.
  const std::uint64_t maxmem = 128 * n * p.r * p.p + (std::uint64_t{1} << 20) + 128 * n * p.r;
  gate().enter();
  int ok = EVP_PBE_scrypt(password.data(), password.size(), reinterpret_cast<const unsigned char *>(salt.data()),
                          salt.size(), n, p.r, p.p, maxmem, reinterpret_cast<unsigned char *>(out.data()), out.size());
  gate().leave();
  if (ok != 1) throw std::runtime_error("scrypt failed");
  return out;
}

struct Parsed {
  ScryptParams params;
  std::string salt, hash;
};

bool parse_uint(std::string_view s, unsigned &out) {
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
  return ec == std::errc() && ptr == s.data() + s.size();
}

std::optional<Parsed> parse(std::string_view encoded) {
  // "", "scrypt", "ln=..,r=..,p=..", salt, hash
  std::vector<std::string_view> parts;
  for (std::size_t start = 0;;) {
    auto pos = encoded.find('$', start);
    parts.push_back(encoded.substr(start, pos == std::string_view::npos ? std::string_view::npos : pos - start));
    if (pos == std::string_view::npos) break;
    start = pos + 1;
  }
  if (parts.size() != 5 || !parts[0].empty() || parts[1] != "scrypt") return std::nullopt;
  Parsed out;
  bool have_n = false, have_r = false, have_p = false;
  for (std::string_view rest = parts[2]; !rest.empty();) {
    auto comma = rest.find(',');
    std::string_view kv = rest.substr(0, comma);
    rest = comma == std::string_view::npos ? std::string_view() : rest.substr(comma + 1);
    auto eq = kv.find('=');
    if (eq == std::string_view::npos) return std::nullopt;
    std::string_view k = kv.substr(0, eq), v = kv.substr(eq + 1);
    unsigned x = 0;
    if (!parse_uint(v, x)) return std::nullopt;
    if (k == "ln") out.params.log_n = x, have_n = true;
    else if (k == "r") out.params.r = x, have_r = true;
    else if (k == "p") out.params.p = x, have_p = true;
    else return std::nullopt;
  }
  if (!have_n || !have_r || !have_p) return std::nullopt;
  if (out.params.log_n < kMinLogN || out.params.log_n > kMaxLogN || out.params.r < 1 || out.params.r > kMaxR ||
      out.params.p < 1 || out.params.p > kMaxP)
    return std::nullopt;
  auto salt = from_unpadded(parts[3]);
  auto hash = from_unpadded(parts[4]);
  if (!salt || !hash || salt->size() < 8 || hash->size() != kHashBytes) return std::nullopt;
  out.salt = std::move(*salt);
  out.hash = std::move(*hash);
  return out;
}

}  // namespace

std::string hash_password(std::string_view password, const ScryptParams &params) {
  if (params.log_n < kMinLogN || params.log_n > kMaxLogN || params.r < 1 || params.r > kMaxR || params.p < 1 ||
      params.p > kMaxP)
    throw std::invalid_argument("scrypt parameters out of range");
  std::string salt = random_bytes(kSaltBytes);
  std::string hash = scrypt(password, salt, params);
  return "$scrypt$ln=" + std::to_string(params.log_n) + ",r=" + std::to_string(params.r) +
         ",p=" + std::to_string(params.p) + "$" + unpadded(salt) + "$" + unpadded(hash);
}

bool verify_password(std::string_view password, std::string_view encoded) {
  auto parsed = parse(encoded);
  if (!parsed) return false;
  try {
    return constant_time_equal(scrypt(password, parsed->salt, parsed->params), parsed->hash);
  } catch (const std::exception &) {
    return false;
  }
}

bool needs_rehash(std::string_view encoded, const ScryptParams &params) {
  auto parsed = parse(encoded);
  if (!parsed) return true;
  return parsed->params.log_n < params.log_n || parsed->params.r < params.r || parsed->params.p < params.p;
}

void dummy_verify(std::string_view password) {
  static const std::string kDummy = hash_password("revkit dummy password", ScryptParams{});
  (void)verify_password(password, kDummy);
}

}  // namespace revkit::auth
