// A bounded pool of objects that must be used by one thread at a time
// (SLEIGH engines). Objects are created on demand up to a limit and reused.
#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace revkit::backend {

template <class T>
class Pool {
 public:
  Pool(std::function<std::unique_ptr<T>()> make, unsigned max) : make_(std::move(make)), max_(max ? max : 1) {}

  class Lease {
   public:
    Lease(Pool *pool, std::unique_ptr<T> item) : pool_(pool), item_(std::move(item)) {}
    Lease(Lease &&) = default;
    Lease &operator=(Lease &&) = delete;
    ~Lease() {
      if (item_) pool_->Return(std::move(item_));
    }
    T &operator*() const { return *item_; }
    T *operator->() const { return item_.get(); }

   private:
    Pool *pool_;
    std::unique_ptr<T> item_;
  };

  Lease Acquire() {
    std::unique_lock lock(mu_);
    for (;;) {
      if (!idle_.empty()) {
        auto item = std::move(idle_.back().first);
        idle_.pop_back();
        return Lease(this, std::move(item));
      }
      if (created_ < max_) {
        ++created_;
        lock.unlock();
        try {
          return Lease(this, make_());
        } catch (...) {
          lock.lock();
          --created_;
          cv_.notify_one();
          throw;
        }
      }
      cv_.wait(lock);
    }
  }

  // Calls park() on the items idle for at least `idle_for` (SLEIGH engines:
  // lift::Lifter::park lets the engine go to the language's spares); how many parked.
  std::size_t ParkIdle(std::chrono::steady_clock::duration idle_for) {
    const auto now = std::chrono::steady_clock::now();
    std::size_t n = 0;
    std::lock_guard lock(mu_);
    for (auto &[item, since] : idle_)
      if (now - since >= idle_for)
        if constexpr (requires(T &t) { t.park(); t.parked(); })
          if (!item->parked() && item->park()) ++n;
    return n;
  }

 private:
  void Return(std::unique_ptr<T> item) {
    std::lock_guard lock(mu_);
    idle_.emplace_back(std::move(item), std::chrono::steady_clock::now());
    cv_.notify_one();
  }

  std::function<std::unique_ptr<T>()> make_;
  unsigned max_;
  std::mutex mu_;
  std::condition_variable cv_;
  std::vector<std::pair<std::unique_ptr<T>, std::chrono::steady_clock::time_point>> idle_;  // since returned
  unsigned created_ = 0;
};

}  // namespace revkit::backend
