#include "revkit/types/hash.h"

#include <gtest/gtest.h>

#include <string>

namespace revkit::types {
namespace {

std::string sha(std::string_view s) {
  Sha256 h;
  h.update(s);
  return to_hex(h.finish());
}

TEST(Sha256, KnownVectors) {
  EXPECT_EQ(sha(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  EXPECT_EQ(sha("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  EXPECT_EQ(sha("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(Sha256, IncrementalMatchesOneShot) {
  std::string data(1000, 'x');
  for (std::size_t i = 0; i < data.size(); ++i) data[i] = char(i * 7);
  Sha256 a;
  a.update(data);
  Sha256 b;
  for (std::size_t i = 0; i < data.size(); i += 13)
    b.update(std::string_view(data).substr(i, 13));
  EXPECT_EQ(to_hex(a.finish()), to_hex(b.finish()));
}

}  // namespace
}  // namespace revkit::types
