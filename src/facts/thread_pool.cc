#include "revkit/facts/thread_pool.h"

#include <atomic>
#include <exception>
#include <memory>

namespace revkit::facts {

ThreadPool::ThreadPool(unsigned threads) {
  if (threads == 0) threads = 1;
  // The caller of parallel_for also works, so n threads means n-1 workers.
  for (unsigned i = 1; i < threads; ++i) workers_.emplace_back([this] { run(); });
}

ThreadPool::~ThreadPool() {
  {
    std::lock_guard lock(mu_);
    stop_ = true;
  }
  cv_.notify_all();
}

void ThreadPool::run() {
  for (;;) {
    std::function<void()> task;
    {
      std::unique_lock lock(mu_);
      cv_.wait(lock, [&] { return stop_ || !queue_.empty(); });
      if (queue_.empty()) return;
      task = std::move(queue_.front());
      queue_.pop_front();
    }
    task();
  }
}

void ThreadPool::parallel_for(std::size_t n, const std::function<void(std::size_t)> &fn) {
  if (n == 0) return;
  struct State {
    std::atomic<std::size_t> next{0};
    std::mutex mu;
    std::condition_variable done_cv;
    std::size_t active = 0;  // helpers running items
    bool closed = false;     // every item taken: helpers starting now do nothing
    std::size_t error_index = SIZE_MAX;
    std::exception_ptr error;
  };
  auto st = std::make_shared<State>();
  auto items = [st, n, &fn] {
    for (;;) {
      std::size_t i = st->next.fetch_add(1, std::memory_order_relaxed);
      if (i >= n) break;
      try {
        fn(i);
      } catch (...) {
        std::lock_guard lock(st->mu);
        if (i < st->error_index) {
          st->error_index = i;
          st->error = std::current_exception();
        }
      }
    }
  };
  // A helper that starts after the caller has taken the last item leaves
  // at once, so the caller never waits for helpers still in the queue:
  // parallel_for called from a worker (a query computed on the pool that
  // splits its own work) can't deadlock with every worker waiting.
  auto helper = [st, items] {
    {
      std::lock_guard lock(st->mu);
      if (st->closed) return;
      ++st->active;
    }
    items();
    std::lock_guard lock(st->mu);
    if (--st->active == 0) st->done_cv.notify_all();
  };

  const std::size_t helpers = std::min<std::size_t>(workers_.size(), n - 1);
  if (helpers > 0) {
    {
      std::lock_guard lock(mu_);
      for (std::size_t i = 0; i < helpers; ++i) queue_.emplace_back(helper);
    }
    cv_.notify_all();
  }
  items();
  std::unique_lock lock(st->mu);
  st->closed = true;
  st->done_cv.wait(lock, [&] { return st->active == 0; });
  // Take the error out: a worker may hold the last reference to `st`, and
  // the exception must not be destroyed on that thread while this one is
  // still reading it (the reference count lives in uninstrumented libstdc++,
  // so ThreadSanitizer reports that as a race).
  std::exception_ptr error = std::move(st->error);
  lock.unlock();
  if (error) std::rethrow_exception(error);
}

}  // namespace revkit::facts
