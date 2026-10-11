#include "revkit/auth/rate_limit.h"

#include <algorithm>

namespace revkit::auth {

std::chrono::seconds LoginLimiter::check(const std::vector<std::string> &keys, Clock::time_point now) {
  std::lock_guard lock(mu_);
  Clock::duration wait{0};
  for (const std::string &k : keys) {
    auto it = entries_.find(k);
    if (it == entries_.end()) continue;
    if (now - it->second.last > opt_.window) {
      entries_.erase(it);
      continue;
    }
    if (it->second.blocked_until > now) wait = std::max(wait, it->second.blocked_until - now);
  }
  auto s = std::chrono::ceil<std::chrono::seconds>(wait);
  return s;
}

void LoginLimiter::failure(const std::vector<std::string> &keys, Clock::time_point now) {
  std::lock_guard lock(mu_);
  if (entries_.size() >= opt_.max_keys) prune(now);
  for (const std::string &k : keys) {
    Entry &e = entries_[k];
    if (e.failures && now - e.last > opt_.window) e = Entry{};
    ++e.failures;
    e.last = now;
    if (e.failures > opt_.free_failures) {
      unsigned excess = std::min(e.failures - opt_.free_failures - 1, 30u);
      auto delay = std::min<std::chrono::seconds>(opt_.base_delay * (std::int64_t{1} << excess), opt_.max_delay);
      e.blocked_until = now + delay;
    }
  }
}

void LoginLimiter::success(const std::vector<std::string> &keys) {
  std::lock_guard lock(mu_);
  for (const std::string &k : keys) entries_.erase(k);
}

void LoginLimiter::prune(Clock::time_point now) {
  for (auto it = entries_.begin(); it != entries_.end();)
    it = now - it->second.last > opt_.window ? entries_.erase(it) : std::next(it);
  // Still full (an address sweep): forget the oldest half.
  if (entries_.size() >= opt_.max_keys) {
    std::vector<std::pair<Clock::time_point, std::string>> by_age;
    for (const auto &[k, e] : entries_) by_age.emplace_back(e.last, k);
    std::sort(by_age.begin(), by_age.end());
    for (std::size_t i = 0; i < by_age.size() / 2; ++i) entries_.erase(by_age[i].second);
  }
}

}  // namespace revkit::auth
