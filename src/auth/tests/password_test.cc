#include "revkit/auth/crypto.h"
#include "revkit/auth/password.h"

#include <gtest/gtest.h>

namespace revkit::auth {
namespace {

const ScryptParams kFast{10, 8, 1};  // tests only: 1 MiB

TEST(Password, HashVerifiesAndRejects) {
  std::string h = hash_password("correct horse", kFast);
  EXPECT_TRUE(h.starts_with("$scrypt$ln=10,r=8,p=1$")) << h;
  EXPECT_TRUE(verify_password("correct horse", h));
  EXPECT_FALSE(verify_password("correct hors", h));
  EXPECT_FALSE(verify_password("", h));
}

TEST(Password, SaltedSoEqualPasswordsHashDifferently) {
  EXPECT_NE(hash_password("same password", kFast), hash_password("same password", kFast));
}

TEST(Password, DefaultsAreOwaspScrypt) {
  std::string h = hash_password("x", ScryptParams{});
  EXPECT_TRUE(h.starts_with("$scrypt$ln=17,r=8,p=1$")) << h;
  EXPECT_TRUE(verify_password("x", h));
  EXPECT_FALSE(needs_rehash(h));
  EXPECT_TRUE(needs_rehash(hash_password("x", kFast)));
}

TEST(Password, MalformedHashesNeverVerify) {
  std::string h = hash_password("pw", kFast);
  for (std::string bad : {std::string(""), std::string("plain"), std::string("$scrypt$ln=10,r=8$a$b"),
                          std::string("$argon2id$v=19$m=65536,t=3,p=4$abc$def"),
                          std::string("$scrypt$ln=40,r=8,p=1") + h.substr(h.find("$", 9)),
                          std::string("$scrypt$ln=10,r=8,p=1$!!!$???"), h.substr(0, h.size() - 2),
                          h + "$extra"}) {
    EXPECT_FALSE(verify_password("pw", bad)) << bad;
    EXPECT_TRUE(needs_rehash(bad)) << bad;
  }
}

TEST(Password, RejectsOutOfRangeParameters) {
  EXPECT_THROW(hash_password("x", ScryptParams{0, 8, 1}), std::invalid_argument);
  EXPECT_THROW(hash_password("x", ScryptParams{10, 0, 1}), std::invalid_argument);
}

TEST(Crypto, EncodingsAndComparison) {
  EXPECT_EQ(base64("hello"), "aGVsbG8=");
  EXPECT_EQ(*unbase64("aGVsbG8="), "hello");
  EXPECT_EQ(*unbase64("aGVsbG8h"), "hello!");
  EXPECT_FALSE(unbase64("aGVsbG8"));
  EXPECT_EQ(base64url(std::string("\xfb\xff", 2)), "-_8");
  EXPECT_EQ(sha256_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  EXPECT_TRUE(constant_time_equal("abc", "abc"));
  EXPECT_FALSE(constant_time_equal("abc", "abd"));
  EXPECT_FALSE(constant_time_equal("abc", "abcd"));
  EXPECT_EQ(random_bytes(32).size(), 32u);
  EXPECT_NE(random_bytes(16), random_bytes(16));
}

}  // namespace
}  // namespace revkit::auth
