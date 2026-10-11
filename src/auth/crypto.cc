#include "revkit/auth/crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cctype>
#include <stdexcept>

namespace revkit::auth {

std::string random_bytes(std::size_t n) {
  std::string out(n, '\0');
  if (n && RAND_bytes(reinterpret_cast<unsigned char *>(out.data()), static_cast<int>(n)) != 1)
    throw std::runtime_error("RAND_bytes failed");
  return out;
}

std::string base64(std::string_view bytes) {
  std::string out(4 * ((bytes.size() + 2) / 3) + 1, '\0');
  int n = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()),
                          reinterpret_cast<const unsigned char *>(bytes.data()), static_cast<int>(bytes.size()));
  out.resize(static_cast<std::size_t>(n));
  return out;
}

std::optional<std::string> unbase64(std::string_view text) {
  if (text.size() % 4 != 0) return std::nullopt;
  for (char c : text)
    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/' || c == '=')) return std::nullopt;
  std::string out(3 * text.size() / 4 + 1, '\0');
  int n = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(out.data()),
                          reinterpret_cast<const unsigned char *>(text.data()), static_cast<int>(text.size()));
  if (n < 0) return std::nullopt;
  // EVP_DecodeBlock counts padding as zero bytes.
  std::size_t len = static_cast<std::size_t>(n);
  if (!text.empty() && text.back() == '=') --len;
  if (text.size() >= 2 && text[text.size() - 2] == '=') --len;
  out.resize(len);
  return out;
}

std::string base64url(std::string_view bytes) {
  std::string s = base64(bytes);
  while (!s.empty() && s.back() == '=') s.pop_back();
  for (char &c : s) {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }
  return s;
}

std::string hex(std::string_view bytes) {
  static const char *digits = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (unsigned char c : bytes) {
    out += digits[c >> 4];
    out += digits[c & 15];
  }
  return out;
}

std::string sha256(std::string_view data) {
  std::string out(SHA256_DIGEST_LENGTH, '\0');
  SHA256(reinterpret_cast<const unsigned char *>(data.data()), data.size(),
         reinterpret_cast<unsigned char *>(out.data()));
  return out;
}

std::string sha256_hex(std::string_view data) { return hex(sha256(data)); }

bool constant_time_equal(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  return a.empty() || CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace revkit::auth
