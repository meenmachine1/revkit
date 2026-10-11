// Password hashes: scrypt (RFC 7914) from OpenSSL, in a PHC-style string
//
//   $scrypt$ln=17,r=8,p=1$<salt>$<hash>      (base64, unpadded)
//
// The defaults are OWASP's recommendation for scrypt: N = 2^17, r = 8,
// p = 1, which costs 128 MiB and a few hundred milliseconds per hash. The
// parameters live in each hash, so they can be raised later and old hashes
// still verify (needs_rehash tells the caller to store a new one).
//
// At most two hashes are computed at a time, process-wide, which bounds
// both memory and the CPU an attacker can make the daemon spend.
#pragma once

#include <string>
#include <string_view>

namespace revkit::auth {

struct ScryptParams {
  unsigned log_n = 17;  // N = 2^log_n
  unsigned r = 8;
  unsigned p = 1;
};

// A fresh hash with a random 16-byte salt.
std::string hash_password(std::string_view password, const ScryptParams &params = {});

// Whether `password` matches `encoded`. False for malformed or unsupported
// hashes (never throws on bad input).
bool verify_password(std::string_view password, std::string_view encoded);

// True when `encoded` was made with weaker parameters than `params`.
bool needs_rehash(std::string_view encoded, const ScryptParams &params = {});

// Burns the same time as a verification, for unknown account names, so a
// login's timing doesn't tell whether the account exists.
void dummy_verify(std::string_view password);

}  // namespace revkit::auth
