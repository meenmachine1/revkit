#include "revkit/auth/tls.h"

#include "revkit/auth/crypto.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace revkit::auth {
namespace {

namespace fs = std::filesystem;

template <class T, void (*F)(T *)>
struct Deleter {
  void operator()(T *p) const { F(p); }
};
using X509Ptr = std::unique_ptr<X509, Deleter<X509, X509_free>>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, Deleter<EVP_PKEY, EVP_PKEY_free>>;
using BioPtr = std::unique_ptr<BIO, Deleter<BIO, BIO_free_all>>;
using CtxPtr = std::unique_ptr<SSL_CTX, Deleter<SSL_CTX, SSL_CTX_free>>;
using SslPtr = std::unique_ptr<SSL, Deleter<SSL, SSL_free>>;

std::string openssl_error() {
  unsigned long e = ERR_get_error();
  if (!e) return "unknown OpenSSL error";
  char buf[256];
  ERR_error_string_n(e, buf, sizeof buf);
  ERR_clear_error();
  return buf;
}

X509Ptr parse_cert(std::string_view pem) {
  BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  if (!bio) return nullptr;
  return X509Ptr(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

std::string bio_string(BIO *bio) {
  char *data = nullptr;
  long n = BIO_get_mem_data(bio, &data);
  return std::string(data, static_cast<std::size_t>(n));
}

bool is_ip(const std::string &s) {
  unsigned char buf[16];
  return inet_pton(AF_INET, s.c_str(), buf) == 1 || inet_pton(AF_INET6, s.c_str(), buf) == 1;
}

void add_ext(X509 *x, int nid, const std::string &value) {
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, x, x, nullptr, nullptr, 0);
  X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str());
  if (!ext) throw std::runtime_error("certificate extension " + value + ": " + openssl_error());
  X509_add_ext(x, ext, -1);
  X509_EXTENSION_free(ext);
}

std::string read_file(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) throw std::runtime_error("cannot read " + p.string());
  std::ostringstream s;
  s << in.rdbuf();
  return s.str();
}

void write_file(const fs::path &p, const std::string &text, mode_t mode) {
  int fd = ::open(p.c_str(), O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, mode);
  if (fd < 0) throw std::runtime_error("cannot write " + p.string() + ": " + std::strerror(errno));
  std::size_t done = 0;
  while (done < text.size()) {
    ssize_t n = ::write(fd, text.data() + done, text.size() - done);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) {
      ::close(fd);
      throw std::runtime_error("cannot write " + p.string() + ": " + std::strerror(errno));
    }
    done += static_cast<std::size_t>(n);
  }
  ::fchmod(fd, mode);
  ::close(fd);
}

std::string normalize_fingerprint(std::string_view f) {
  std::string s;
  for (std::string_view prefix : {"sha256:", "SHA256:", "sha256 fingerprint=", "SHA256 Fingerprint="})
    if (f.starts_with(prefix)) {
      f.remove_prefix(prefix.size());
      break;
    }
  for (char c : f)
    if (std::isxdigit(static_cast<unsigned char>(c))) s += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    else if (c != ':' && c != ' ') return "";
  return s;
}

}  // namespace

CertKey generate_self_signed(const std::vector<std::string> &hosts, int days) {
  PkeyPtr key(EVP_EC_gen("P-256"));
  if (!key) throw std::runtime_error("EC key generation failed: " + openssl_error());
  X509Ptr x(X509_new());
  X509_set_version(x.get(), 2);
  std::string serial = random_bytes(16);
  serial[0] = static_cast<char>(serial[0] & 0x7f);  // positive
  BIGNUM *bn = BN_bin2bn(reinterpret_cast<const unsigned char *>(serial.data()), static_cast<int>(serial.size()), nullptr);
  BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x.get()));
  BN_free(bn);
  X509_gmtime_adj(X509_getm_notBefore(x.get()), -3600);
  X509_gmtime_adj(X509_getm_notAfter(x.get()), static_cast<long>(days) * 86400L);
  X509_set_pubkey(x.get(), key.get());
  X509_NAME *name = X509_get_subject_name(x.get());
  X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("revkit"), -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("rk-daemon (self-signed)"),
                             -1, -1, 0);
  X509_set_issuer_name(x.get(), name);

  std::vector<std::string> all = {"localhost", "127.0.0.1", "::1"};
  for (const auto &h : hosts)
    if (!h.empty() && h != "0.0.0.0" && h != "::" && std::find(all.begin(), all.end(), h) == all.end()) all.push_back(h);
  std::string san;
  for (const auto &h : all) san += (san.empty() ? "" : ",") + std::string(is_ip(h) ? "IP:" : "DNS:") + h;
  add_ext(x.get(), NID_basic_constraints, "critical,CA:FALSE");
  add_ext(x.get(), NID_key_usage, "critical,digitalSignature");
  add_ext(x.get(), NID_ext_key_usage, "serverAuth,clientAuth");
  add_ext(x.get(), NID_subject_key_identifier, "hash");
  add_ext(x.get(), NID_subject_alt_name, san);
  if (!X509_sign(x.get(), key.get(), EVP_sha256())) throw std::runtime_error("signing failed: " + openssl_error());

  CertKey out;
  BioPtr cb(BIO_new(BIO_s_mem()));
  PEM_write_bio_X509(cb.get(), x.get());
  out.cert_pem = bio_string(cb.get());
  BioPtr kb(BIO_new(BIO_s_mem()));
  PEM_write_bio_PrivateKey(kb.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr);
  out.key_pem = bio_string(kb.get());
  return out;
}

CertKey load_or_create_self_signed(const std::string &dir, const std::vector<std::string> &hosts, bool &created) {
  const fs::path d(dir), cert = d / "cert.pem", key = d / "key.pem";
  created = false;
  if (fs::exists(cert) && fs::exists(key)) {
    CertKey ck{read_file(cert), read_file(key)};
    std::string err;
    if (!check_cert_key(ck, err)) throw std::runtime_error(dir + ": " + err);
    return ck;
  }
  std::error_code ec;
  fs::create_directories(d, ec);
  if (ec) throw std::runtime_error("cannot create " + dir + ": " + ec.message());
  fs::permissions(d, fs::perms::owner_all, ec);
  CertKey ck = generate_self_signed(hosts);
  write_file(key, ck.key_pem, 0600);
  write_file(cert, ck.cert_pem, 0644);
  created = true;
  return ck;
}

std::string fingerprint_sha256(std::string_view cert_pem) {
  X509Ptr x = parse_cert(cert_pem);
  if (!x) return "";
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int n = 0;
  if (!X509_digest(x.get(), EVP_sha256(), md, &n)) return "";
  static const char *digits = "0123456789ABCDEF";
  std::string out;
  for (unsigned i = 0; i < n; ++i) {
    if (i) out += ':';
    out += digits[md[i] >> 4];
    out += digits[md[i] & 15];
  }
  return out;
}

bool fingerprint_matches(std::string_view cert_pem, std::string_view fingerprint) {
  std::string want = normalize_fingerprint(fingerprint);
  std::string have = normalize_fingerprint(fingerprint_sha256(cert_pem));
  return want.size() == 64 && constant_time_equal(want, have);
}

std::vector<std::string> certificate_hosts(std::string_view cert_pem) {
  std::vector<std::string> out;
  X509Ptr x = parse_cert(cert_pem);
  if (!x) return out;
  auto *names = static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(x.get(), NID_subject_alt_name, nullptr, nullptr));
  if (!names) return out;
  for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
    const GENERAL_NAME *g = sk_GENERAL_NAME_value(names, i);
    if (g->type == GEN_DNS) {
      const ASN1_STRING *s = g->d.dNSName;
      out.emplace_back(reinterpret_cast<const char *>(ASN1_STRING_get0_data(s)), ASN1_STRING_length(s));
    } else if (g->type == GEN_IPADD) {
      const ASN1_STRING *s = g->d.iPAddress;
      char buf[INET6_ADDRSTRLEN] = {};
      int len = ASN1_STRING_length(s);
      if (len == 4 || len == 16) {
        inet_ntop(len == 4 ? AF_INET : AF_INET6, ASN1_STRING_get0_data(s), buf, sizeof buf);
        out.emplace_back(buf);
      }
    }
  }
  GENERAL_NAMES_free(names);
  return out;
}

bool check_cert_key(const CertKey &ck, std::string &error) {
  X509Ptr x = parse_cert(ck.cert_pem);
  if (!x) {
    error = "the certificate is not PEM";
    return false;
  }
  BioPtr kb(BIO_new_mem_buf(ck.key_pem.data(), static_cast<int>(ck.key_pem.size())));
  PkeyPtr key(PEM_read_bio_PrivateKey(kb.get(), nullptr, nullptr, nullptr));
  if (!key) {
    error = "the private key is not PEM (or is encrypted)";
    return false;
  }
  if (X509_check_private_key(x.get(), key.get()) != 1) {
    ERR_clear_error();
    error = "the private key does not match the certificate";
    return false;
  }
  return true;
}

std::optional<std::string> fetch_server_certificate(const std::string &host, int port, std::string &error,
                                                    int timeout_ms) {
  addrinfo hints{}, *res = nullptr;
  hints.ai_socktype = SOCK_STREAM;
  if (int rc = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res); rc != 0) {
    error = host + ": " + gai_strerror(rc);
    return std::nullopt;
  }
  int fd = -1;
  for (addrinfo *ai = res; ai && fd < 0; ai = ai->ai_next) {
    fd = ::socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK, ai->ai_protocol);
    if (fd < 0) continue;
    if (::connect(fd, ai->ai_addr, ai->ai_addrlen) != 0 && errno != EINPROGRESS) {
      ::close(fd);
      fd = -1;
      continue;
    }
    pollfd p{fd, POLLOUT, 0};
    int soerr = 0;
    socklen_t len = sizeof soerr;
    if (::poll(&p, 1, timeout_ms) != 1 || ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len) != 0 || soerr) {
      ::close(fd);
      fd = -1;
    }
  }
  freeaddrinfo(res);
  if (fd < 0) {
    error = "cannot connect to " + host + ":" + std::to_string(port);
    return std::nullopt;
  }
  ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) & ~O_NONBLOCK);
  timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

  CtxPtr ctx(SSL_CTX_new(TLS_client_method()));
  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
  SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);  // we only want to look at it
  static const unsigned char alpn[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
  SSL_CTX_set_alpn_protos(ctx.get(), alpn, sizeof alpn);
  SslPtr ssl(SSL_new(ctx.get()));
  SSL_set_fd(ssl.get(), fd);
  if (!is_ip(host)) SSL_set_tlsext_host_name(ssl.get(), host.c_str());
  std::optional<std::string> out;
  if (SSL_connect(ssl.get()) == 1) {
    X509 *peer = SSL_get1_peer_certificate(ssl.get());
    if (peer) {
      BioPtr b(BIO_new(BIO_s_mem()));
      PEM_write_bio_X509(b.get(), peer);
      out = bio_string(b.get());
      X509_free(peer);
    } else {
      error = host + ":" + std::to_string(port) + " presented no certificate";
    }
    SSL_shutdown(ssl.get());
  } else {
    error = "TLS handshake with " + host + ":" + std::to_string(port) + " failed: " + openssl_error();
  }
  ::close(fd);
  return out;
}

}  // namespace revkit::auth
