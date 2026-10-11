// A fixed-size pool for data-parallel query evaluation. parallel_for hands
// out indices dynamically, so which thread runs which index varies, but each
// index writes only its own result slot, keeping output deterministic.
#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace revkit::facts {

class ThreadPool {
 public:
  explicit ThreadPool(unsigned threads = std::thread::hardware_concurrency());
  ~ThreadPool();
  ThreadPool(const ThreadPool &) = delete;
  ThreadPool &operator=(const ThreadPool &) = delete;

  unsigned size() const { return static_cast<unsigned>(workers_.size()); }

  // Runs fn(0..n-1) on the pool and the calling thread; returns when all are
  // done. If any calls throw, rethrows the exception from the lowest index.
  // May be called from a worker (nested): the caller never waits for
  // helpers that haven't started, so it can't deadlock on a busy pool.
  void parallel_for(std::size_t n, const std::function<void(std::size_t)> &fn);

 private:
  void run();

  std::mutex mu_;
  std::condition_variable cv_;
  std::deque<std::function<void()>> queue_;
  bool stop_ = false;
  std::vector<std::jthread> workers_;
};

}  // namespace revkit::facts
