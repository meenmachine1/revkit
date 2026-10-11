// Small cryptographic helpers over OpenSSL: random bytes, encodings,
// SHA-256 and constant-time comparison.
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace revkit::auth {

// `n` bytes from the OS CSPRNG (RAND_bytes). Throws if it fails.
std::string random_bytes(std::size_t n);

// RFC 4648 base64 (standard alphabet, padded) and base64url (no padding).
std::string base64(std::string_view bytes);
std::optional<std::string> unbase64(std::string_view text);
std::string base64url(std::string_view bytes);

std::string hex(std::string_view bytes);

// Raw 32-byte digest, and its lowercase hex.
std::string sha256(std::string_view data);
std::string sha256_hex(std::string_view data);

// Equal length and content, in time independent of where they differ.
bool constant_time_equal(std::string_view a, std::string_view b);

}  // namespace revkit::auth
