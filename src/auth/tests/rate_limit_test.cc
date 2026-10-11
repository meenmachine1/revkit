#include "revkit/auth/rate_limit.h"

#include <gtest/gtest.h>

namespace revkit::auth {
namespace {

using namespace std::chrono_literals;
using Clock = LoginLimiter::Clock;

TEST(LoginLimiter, FreeFailuresThenDoublingDelays) {
  LoginLimiter lim;
  Clock::time_point t{};
  t += 1h;
  const std::vector<std::string> keys = {"ip:10.0.0.1", "user:alice"};
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(lim.check(keys, t), 0s);
    lim.failure(keys, t);
  }
  EXPECT_EQ(lim.check(keys, t), 0s);
  lim.failure(keys, t);  // 6th: 1 s
  EXPECT_EQ(lim.check(keys, t), 1s);
  t += 1s;
  EXPECT_EQ(lim.check(keys, t), 0s);
  lim.failure(keys, t);  // 7th: 2 s
  EXPECT_EQ(lim.check(keys, t), 2s);
  for (int i = 0; i < 20; ++i) lim.failure(keys, t);
  EXPECT_EQ(lim.check(keys, t), 900s);  // capped
  // Any one throttled key blocks: another address, same account.
  EXPECT_EQ(lim.check({"ip:10.0.0.2", "user:alice"}, t), 900s);
  EXPECT_EQ(lim.check({"ip:10.0.0.2", "user:bob"}, t), 0s);
}

TEST(LoginLimiter, SuccessAndTimeForget) {
  LoginLimiter lim;
  Clock::time_point t{};
  t += 1h;
  const std::vector<std::string> keys = {"user:alice"};
  for (int i = 0; i < 8; ++i) lim.failure(keys, t);
  EXPECT_GT(lim.check(keys, t), 0s);
  lim.success(keys);
  EXPECT_EQ(lim.check(keys, t), 0s);
  for (int i = 0; i < 8; ++i) lim.failure(keys, t);
  EXPECT_EQ(lim.check(keys, t + 16min), 0s);  // past the window
}

TEST(LoginLimiter, BoundedMemory) {
  LoginLimiter::Options o;
  o.max_keys = 100;
  LoginLimiter lim(o);
  Clock::time_point t{};
  for (int i = 0; i < 1000; ++i) lim.failure({"ip:" + std::to_string(i)}, t + std::chrono::seconds(i));
  // Old keys were forgotten; recent ones are still counted.
  for (int i = 0; i < 6; ++i) lim.failure({"ip:999"}, t + 1000s);
  EXPECT_GT(lim.check({"ip:999"}, t + 1000s), 0s);
}

}  // namespace
}  // namespace revkit::auth
