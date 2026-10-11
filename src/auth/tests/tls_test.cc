#include "revkit/auth/tls.h"

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>

namespace revkit::auth {
namespace {

namespace fs = std::filesystem;

TEST(Tls, SelfSignedCertificate) {
  CertKey ck = generate_self_signed({"revkit.example", "100.68.1.2", "0.0.0.0"});
  std::string err;
  EXPECT_TRUE(check_cert_key(ck, err)) << err;
  auto hosts = certificate_hosts(ck.cert_pem);
  for (const char *h : {"localhost", "127.0.0.1", "::1", "revkit.example", "100.68.1.2"})
    EXPECT_NE(std::find(hosts.begin(), hosts.end(), h), hosts.end()) << h;
  EXPECT_EQ(std::find(hosts.begin(), hosts.end(), "0.0.0.0"), hosts.end());

  std::string fp = fingerprint_sha256(ck.cert_pem);
  EXPECT_EQ(fp.size(), 95u);  // 32 pairs and 31 colons
  EXPECT_TRUE(fingerprint_matches(ck.cert_pem, fp));
  std::string bare = fp;
  bare.erase(std::remove(bare.begin(), bare.end(), ':'), bare.end());
  std::transform(bare.begin(), bare.end(), bare.begin(), ::tolower);
  EXPECT_TRUE(fingerprint_matches(ck.cert_pem, "sha256:" + bare));
  EXPECT_FALSE(fingerprint_matches(ck.cert_pem, ""));
  EXPECT_FALSE(fingerprint_matches(ck.cert_pem, fp.substr(3)));
  EXPECT_FALSE(fingerprint_matches(generate_self_signed({}).cert_pem, fp));

  CertKey other = generate_self_signed({});
  EXPECT_FALSE(check_cert_key({ck.cert_pem, other.key_pem}, err));
  EXPECT_FALSE(check_cert_key({"junk", ck.key_pem}, err));
  EXPECT_EQ(fingerprint_sha256("junk"), "");
}

TEST(Tls, PersistedAndReused) {
  fs::path dir = fs::temp_directory_path() / ("rk-tls-" + std::to_string(::getpid()));
  fs::remove_all(dir);
  bool created = false;
  CertKey a = load_or_create_self_signed((dir / "tls").string(), {"host.example"}, created);
  EXPECT_TRUE(created);
  CertKey b = load_or_create_self_signed((dir / "tls").string(), {"host.example"}, created);
  EXPECT_FALSE(created);
  EXPECT_EQ(fingerprint_sha256(a.cert_pem), fingerprint_sha256(b.cert_pem));
  struct stat st {};
  ASSERT_EQ(::stat((dir / "tls" / "key.pem").c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777, 0600u);
  fs::remove_all(dir);
}

TEST(Tls, FetchFailsCleanly) {
  std::string err;
  EXPECT_FALSE(fetch_server_certificate("127.0.0.1", 1, err, 500));
  EXPECT_FALSE(err.empty());
}

}  // namespace
}  // namespace revkit::auth
