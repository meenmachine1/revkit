// Login throttling. Each key (a client address, an account name) may fail
// `free_failures` times; after that every further failure doubles a
// lockout delay, from `base_delay` up to `max_delay`, during which logins
// on that key are refused without checking the password. A key's count
// is forgotten `window` after its last failure, and a success clears it.
//
// Throttling by account as well as by address slows a distributed guesser
// down, at the price that someone can delay a known account's logins by
// up to max_delay (docs/security.md).
#pragma once

#include <chrono>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace revkit::auth {

class LoginLimiter {
 public:
  using Clock = std::chrono::steady_clock;
  struct Options {
    unsigned free_failures = 5;
    std::chrono::seconds base_delay{1};
    std::chrono::seconds max_delay{900};
    std::chrono::seconds window{900};
    std::size_t max_keys = 100000;
  };

  LoginLimiter() : LoginLimiter(Options{}) {}
  explicit LoginLimiter(Options options) : opt_(options) {}

  // Zero when a login on these keys may proceed, else how long to wait.
  std::chrono::seconds check(const std::vector<std::string> &keys, Clock::time_point now = Clock::now());
  void failure(const std::vector<std::string> &keys, Clock::time_point now = Clock::now());
  void success(const std::vector<std::string> &keys);

 private:
  struct Entry {
    unsigned failures = 0;
    Clock::time_point last{};
    Clock::time_point blocked_until{};
  };
  void prune(Clock::time_point now);

  Options opt_;
  std::mutex mu_;
  std::map<std::string, Entry> entries_;
};

}  // namespace revkit::auth
