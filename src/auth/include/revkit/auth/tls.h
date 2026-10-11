// TLS certificates for rk-daemon's listeners and for clients that pin a
// self-signed certificate by fingerprint (docs/security.md).
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::auth {

struct CertKey {
  std::string cert_pem;
  std::string key_pem;
};

// A self-signed ECDSA P-256 certificate valid for `days`, with these DNS
// names and IP addresses as subject alternative names (localhost,
// 127.0.0.1 and ::1 are always included). It is its own trust anchor:
// clients pin it (fingerprint) or trust it as their CA file.
CertKey generate_self_signed(const std::vector<std::string> &hosts, int days = 825);

// Loads <dir>/cert.pem and <dir>/key.pem, or creates them (key mode 0600)
// with generate_self_signed. `created` tells which. Throws on I/O errors.
CertKey load_or_create_self_signed(const std::string &dir, const std::vector<std::string> &hosts, bool &created);

// SHA-256 of the certificate's DER encoding, as uppercase hex pairs joined
// by ':' (what browsers and `openssl x509 -fingerprint -sha256` show).
// Empty if the PEM doesn't parse.
std::string fingerprint_sha256(std::string_view cert_pem);
// Compares with a fingerprint written in any common form: with or without
// "sha256:" / "SHA256 Fingerprint=", colons, either case.
bool fingerprint_matches(std::string_view cert_pem, std::string_view fingerprint);

// The certificate's DNS and IP subject alternative names.
std::vector<std::string> certificate_hosts(std::string_view cert_pem);

// Whether the key is the certificate's, and both parse. Sets `error`.
bool check_cert_key(const CertKey &ck, std::string &error);

// The certificate a TLS server at host:port presents, without verifying
// it, for pinning by fingerprint (the caller compares fingerprints and then
// connects for real with the certificate as its only trust anchor).
std::optional<std::string> fetch_server_certificate(const std::string &host, int port, std::string &error,
                                                    int timeout_ms = 5000);

}  // namespace revkit::auth
