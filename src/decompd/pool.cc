#include "revkit/decompd/pool.h"

#include "revkit/decompd/runner.h"
#include "revkit/lift/lifter.hh"

#include <algorithm>
#include <bit>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <new>
#include <stdexcept>

#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#ifndef REVKIT_DECOMPILER_BUILD
#define REVKIT_DECOMPILER_BUILD "ghidra-unknown"
#endif
#ifndef REVKIT_DECOMPD_BUILD_PATH
#define REVKIT_DECOMPD_BUILD_PATH ""
#endif

namespace revkit::decompd {

namespace {

using Clock = std::chrono::steady_clock;

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
constexpr bool kSanitized = true;
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
constexpr bool kSanitized = true;
#else
constexpr bool kSanitized = false;
#endif
#else
constexpr bool kSanitized = false;
#endif

// Frames: u32 length (little-endian, of type and payload), u8 type, payload.
enum Frame : std::uint8_t { kHello = 1, kRun = 2, kWarm = 3, kResult = 4 };
constexpr std::uint32_t kMaxFrame = 1u << 30;
constexpr std::size_t kTail = 8192;  // stderr kept per worker

bool write_all(int fd, const char *p, std::size_t n) {
  while (n > 0) {
    const ssize_t w = ::send(fd, p, n, MSG_NOSIGNAL);
    if (w < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    p += w;
    n -= static_cast<std::size_t>(w);
  }
  return true;
}

bool send_frame(int fd, Frame type, std::string_view payload) {
  std::string head(5, '\0');
  const auto len = static_cast<std::uint32_t>(payload.size() + 1);
  for (int i = 0; i < 4; ++i) head[i] = static_cast<char>(len >> (8 * i));
  head[4] = static_cast<char>(type);
  return write_all(fd, head.data(), head.size()) && write_all(fd, payload.data(), payload.size());
}

// A complete frame at the front of `buf`, removed from it.
bool take_frame(std::string &buf, Frame &type, std::string &payload, bool &bad) {
  if (buf.size() < 4) return false;
  std::uint32_t len = 0;
  for (int i = 0; i < 4; ++i) len |= std::uint32_t{static_cast<unsigned char>(buf[i])} << (8 * i);
  if (len == 0 || len > kMaxFrame) {
    bad = true;
    return false;
  }
  if (buf.size() < 4 + std::size_t{len}) return false;
  type = static_cast<Frame>(static_cast<unsigned char>(buf[4]));
  payload.assign(buf, 5, len - 1);
  buf.erase(0, 4 + std::size_t{len});
  return true;
}

void keep_tail(std::string &tail, const char *p, std::size_t n) {
  tail.append(p, n);
  if (tail.size() > kTail) tail.erase(0, tail.size() - kTail);
}

std::string find_worker() {
  namespace fs = std::filesystem;
  if (const char *env = std::getenv("REVKIT_DECOMPD"); env != nullptr && *env != 0) return env;
  std::error_code ec;
  const fs::path exe = fs::read_symlink("/proc/self/exe", ec);
  std::vector<fs::path> candidates;
  if (!ec) {
    const fs::path dir = exe.parent_path();
    candidates = {dir / "rk-decompd", dir / ".." / "rk-decompd" / "rk-decompd",
                  dir / ".." / "tools" / "rk-decompd" / "rk-decompd"};
  }
  if (*REVKIT_DECOMPD_BUILD_PATH != 0) candidates.emplace_back(REVKIT_DECOMPD_BUILD_PATH);
  for (const fs::path &c : candidates)
    if (::access(c.c_str(), X_OK) == 0) return fs::weakly_canonical(c, ec).string();
  throw std::runtime_error("rk-decompd not found (set REVKIT_DECOMPD to the decompiler worker)");
}

std::string signal_name(int sig) {
  switch (sig) {
    case SIGSEGV: return "SIGSEGV";
    case SIGBUS: return "SIGBUS";
    case SIGFPE: return "SIGFPE";
    case SIGABRT: return "SIGABRT";
    case SIGILL: return "SIGILL";
    case SIGTRAP: return "SIGTRAP";
    case SIGKILL: return "SIGKILL";
    default: return "signal " + std::to_string(sig);
  }
}

// A process's anonymous resident memory (bytes), 0 if it is gone.
std::uint64_t anon_rss(int pid) {
  char path[64];
  std::snprintf(path, sizeof path, "/proc/%d/statm", pid);
  std::FILE *f = std::fopen(path, "r");
  if (f == nullptr) return 0;
  unsigned long long size = 0, resident = 0, shared = 0;
  const int n = std::fscanf(f, "%llu %llu %llu", &size, &resident, &shared);
  std::fclose(f);
  if (n != 3) return 0;
  return (resident > shared ? resident - shared : 0) * static_cast<std::uint64_t>(::sysconf(_SC_PAGESIZE));
}

// The exit status the worker uses when it runs out of memory.
constexpr int kExitOom = 3;

}  // namespace

const std::string &decompiler_build() {
  static const std::string b = REVKIT_DECOMPILER_BUILD;
  return b;
}

const char *failure_kind_name(FailureKind k) {
  switch (k) {
    case FailureKind::segv: return "segv";
    case FailureKind::fpe: return "fpe";
    case FailureKind::abort: return "abort";
    case FailureKind::timeout: return "timeout";
    case FailureKind::oom: return "oom";
  }
  return "?";
}

void Failure::encode(facts::Encoder &e) const {
  e.varint(function);
  e.bytes(bundle_hash);
  e.bytes(decompiler_build);
  e.u8(static_cast<std::uint8_t>(kind));
  e.u64be(std::bit_cast<std::uint64_t>(deadline_seconds));
  e.bytes(stderr_tail);
  e.bytes(detail);
  facts::encode(e, escalated);
}

Failure Failure::decode(facts::Decoder &d) {
  Failure f;
  f.function = d.varint();
  f.bundle_hash = std::string(d.bytes());
  f.decompiler_build = std::string(d.bytes());
  const std::uint8_t k = d.u8();
  if (k < 1 || k > 5) throw facts::DecodeError("bad failure kind");
  f.kind = static_cast<FailureKind>(k);
  f.deadline_seconds = std::bit_cast<double>(d.u64be());
  f.stderr_tail = std::string(d.bytes());
  f.detail = std::string(d.bytes());
  f.escalated = facts::decode<bool>(d);
  return f;
}

PoolOptions default_pool_options() {
  PoolOptions o;
  if (const char *env = std::getenv("REVKIT_DECOMPILE_IN_PROCESS"); env != nullptr && *env != 0 && *env != '0')
    o.in_process = true;
  return o;
}

std::optional<Failure> failure_of(const Outcome &o, std::uint64_t function, const std::string &bundle_hash,
                                  const Limits &limits) {
  std::optional<Failure> f;
  if (o.failure) {
    f = *o.failure;
  } else if (o.result && (o.result->stopped == lift::DecompileStop::timeout ||
                          o.result->stopped == lift::DecompileStop::too_large)) {
    f.emplace();
    f->kind = o.result->stopped == lift::DecompileStop::timeout ? FailureKind::timeout : FailureKind::oom;
    f->deadline_seconds = limits.timeout_seconds;
    f->detail = o.result->error.empty() ? lift::describe(o.result->stopped) : o.result->error;
  }
  if (f) {
    f->function = function;
    f->bundle_hash = bundle_hash;
    f->decompiler_build = decompiler_build();
  }
  return f;
}

// ---- the pool ---------------------------------------------------------------------

struct WorkerPool::Worker {
  pid_t pid = -1;
  int sock = -1;
  int err = -1;
  std::string inbuf;
  std::string tail;  // the end of its stderr
  std::string affinity;
  unsigned served = 0;
  std::uint64_t rss_anon = 0;
  bool reaped = false;
  int status = 0;

  ~Worker() {
    if (sock >= 0) ::close(sock);
    if (err >= 0) ::close(err);
    if (pid > 0 && !reaped) {
      ::kill(pid, SIGKILL);
      while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
      }
    }
  }

  void drain_err() {
    char buf[4096];
    for (;;) {
      const ssize_t n = ::read(err, buf, sizeof buf);
      if (n > 0) keep_tail(tail, buf, static_cast<std::size_t>(n));
      else if (n < 0 && errno == EINTR) continue;
      else break;
    }
  }

  // Waits until the worker has exited (after its socket closed or a kill).
  void reap() {
    if (reaped || pid <= 0) return;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    reaped = true;
    if (err >= 0) {
      ::fcntl(err, F_SETFL, ::fcntl(err, F_GETFL) | O_NONBLOCK);
      drain_err();
    }
  }

  enum class Wait { frame, dead, expired, cancelled };
  // Reads the next frame, giving up at `deadline` or when `cancelled`
  // (polled every 50 ms) says so.
  Wait next(Clock::time_point deadline, Frame &type, std::string &payload,
            const std::function<bool()> &cancelled = {}) {
    for (;;) {
      if (cancelled && cancelled()) return Wait::cancelled;
      bool bad = false;
      if (take_frame(inbuf, type, payload, bad)) return Wait::frame;
      if (bad) return Wait::dead;
      int timeout_ms = -1;
      if (deadline != Clock::time_point::max()) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        if (left <= 0) return Wait::expired;
        timeout_ms = static_cast<int>(std::min<long long>(left, 1 << 30));
      }
      if (cancelled) timeout_ms = timeout_ms < 0 ? 50 : std::min(timeout_ms, 50);
      pollfd fds[2] = {{sock, POLLIN, 0}, {err, POLLIN, 0}};
      const int n = ::poll(fds, err >= 0 ? 2 : 1, timeout_ms);
      if (n < 0) {
        if (errno == EINTR) continue;
        return Wait::dead;
      }
      if (n == 0) continue;  // the deadline check above decides
      if (err >= 0 && (fds[1].revents & (POLLIN | POLLHUP))) {
        char buf[4096];
        const ssize_t r = ::read(err, buf, sizeof buf);
        if (r > 0) keep_tail(tail, buf, static_cast<std::size_t>(r));
        else if (r == 0) {
          ::close(err);
          err = -1;
        }
      }
      if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
        char buf[65536];
        const ssize_t r = ::read(sock, buf, sizeof buf);
        if (r > 0) inbuf.append(buf, static_cast<std::size_t>(r));
        else if (r == 0 || (r < 0 && errno != EINTR && errno != EAGAIN)) return Wait::dead;
      }
    }
  }

  // Why it died, as a failure.
  Failure death(bool killed_at_deadline, double deadline) {
    reap();
    Failure f;
    f.deadline_seconds = deadline;
    f.stderr_tail = tail;
    if (killed_at_deadline) {
      f.kind = FailureKind::timeout;
      char buf[64];
      std::snprintf(buf, sizeof buf, "killed at the %.1f s deadline", deadline);
      f.detail = buf;
    } else if (WIFSIGNALED(status)) {
      const int sig = WTERMSIG(status);
      f.detail = signal_name(sig);
      switch (sig) {
        case SIGSEGV:
        case SIGBUS: f.kind = FailureKind::segv; break;
        case SIGFPE: f.kind = FailureKind::fpe; break;
        case SIGKILL: f.kind = FailureKind::oom; f.detail += " (not by revkit: the kernel's out-of-memory killer?)"; break;
        default: f.kind = FailureKind::abort; break;
      }
    } else if (WIFEXITED(status) && WEXITSTATUS(status) == kExitOom) {
      f.kind = FailureKind::oom;
      f.detail = "out of memory";
    } else if (tail.find("Sanitizer: SEGV") != std::string::npos || tail.find("Sanitizer: BUS") != std::string::npos) {
      // A sanitizer's handler reported the signal and exited (sanitizer builds).
      f.kind = FailureKind::segv;
      f.detail = "SIGSEGV (reported by the sanitizer)";
    } else if (tail.find("Sanitizer: FPE") != std::string::npos) {
      f.kind = FailureKind::fpe;
      f.detail = "SIGFPE (reported by the sanitizer)";
    } else if (tail.find("Sanitizer: requested allocation size") != std::string::npos ||
               tail.find("Sanitizer: out of memory") != std::string::npos ||
               tail.find("Sanitizer: allocator is out of memory") != std::string::npos) {
      f.kind = FailureKind::oom;
      f.detail = "out of memory (reported by the sanitizer)";
    } else {
      f.kind = FailureKind::abort;
      f.detail = WIFEXITED(status) ? "exited with status " + std::to_string(WEXITSTATUS(status)) : "died";
    }
    return f;
  }
};

struct WorkerPool::InProcess {
  std::mutex mu;
  std::vector<std::unique_ptr<Runner>> idle;
};

WorkerPool::WorkerPool(PoolOptions options) : options_(std::move(options)) {
  if (options_.workers == 0) options_.workers = 1;
  if (options_.in_process) local_ = std::make_unique<InProcess>();
  // Found once, before any thread spawns a worker.
  if (!local_ && options_.worker_path.empty()) {
    try {
      options_.worker_path = find_worker();
    } catch (const std::exception &e) {
      missing_worker_ = e.what();
    }
  }
}

WorkerPool::~WorkerPool() = default;

double WorkerPool::hard_deadline(double timeout_seconds) const {
  if (timeout_seconds <= 0) return options_.no_timeout_deadline;
  return timeout_seconds * options_.grace_factor + options_.grace_seconds;
}

std::unique_ptr<WorkerPool::Worker> WorkerPool::spawn() {
  if (options_.worker_path.empty()) throw std::runtime_error(missing_worker_);
  const std::optional<std::filesystem::path> root = lift::ghidra_root();
  int sv[2];
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
    throw std::runtime_error(std::string("socketpair: ") + std::strerror(errno));
  int ep[2];
  if (::pipe2(ep, O_CLOEXEC) != 0) {
    ::close(sv[0]);
    ::close(sv[1]);
    throw std::runtime_error(std::string("pipe: ") + std::strerror(errno));
  }
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
  posix_spawn_file_actions_adddup2(&fa, ep[1], 1);
  posix_spawn_file_actions_adddup2(&fa, ep[1], 2);
  posix_spawn_file_actions_adddup2(&fa, sv[1], 3);
  posix_spawn_file_actions_addclosefrom_np(&fa, 4);
  posix_spawnattr_t attr;
  posix_spawnattr_init(&attr);
  sigset_t none, all;
  sigemptyset(&none);
  sigfillset(&all);
  posix_spawnattr_setsigmask(&attr, &none);
  posix_spawnattr_setsigdefault(&attr, &all);
  posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
  std::vector<std::string> args = {options_.worker_path, "--worker", "--fd", "3"};
  if (root) {
    args.push_back("--ghidra");
    args.push_back(root->string());
  }
  std::vector<char *> argv;
  for (std::string &a : args) argv.push_back(a.data());
  argv.push_back(nullptr);
  pid_t pid = -1;
  const int rc = ::posix_spawn(&pid, options_.worker_path.c_str(), &fa, &attr, argv.data(), environ);
  posix_spawn_file_actions_destroy(&fa);
  posix_spawnattr_destroy(&attr);
  ::close(sv[1]);
  ::close(ep[1]);
  if (rc != 0) {
    ::close(sv[0]);
    ::close(ep[0]);
    throw std::runtime_error("cannot start " + options_.worker_path + ": " + std::strerror(rc));
  }
  auto w = std::make_unique<Worker>();
  w->pid = pid;
  w->sock = sv[0];
  w->err = ep[0];
  if (options_.memory_limit != 0 && !kSanitized) {
    const rlimit lim{options_.memory_limit, options_.memory_limit};
    ::prlimit(pid, RLIMIT_AS, &lim, nullptr);
  }
  Frame type{};
  std::string payload;
  const auto r = w->next(Clock::now() + std::chrono::seconds(60), type, payload);
  if (r != Worker::Wait::frame || type != kHello) {
    Failure f = w->death(false, 0);
    throw std::runtime_error("decompiler worker " + options_.worker_path + " did not start: " + f.detail +
                             (f.stderr_tail.empty() ? "" : "\n" + f.stderr_tail));
  }
  if (payload != decompiler_build())
    throw std::runtime_error("decompiler worker " + options_.worker_path + " is build " + payload + ", expected " +
                             decompiler_build());
  {
    std::lock_guard lock(mu_);
    ++stats_.spawned;
  }
  return w;
}

std::unique_ptr<WorkerPool::Worker> WorkerPool::acquire(const std::string &affinity) {
  std::unique_lock lock(mu_);
  for (;;) {
    if (!idle_.empty()) {
      auto it = std::find_if(idle_.begin(), idle_.end(), [&](const auto &w) { return w->affinity == affinity; });
      // Another worker if none matches and one more may start: its
      // architecture would be built either way.
      if (it == idle_.end() && live_ < options_.workers) break;
      if (it == idle_.end()) it = idle_.end() - 1;
      auto w = std::move(*it);
      idle_.erase(it);
      return w;
    }
    if (live_ < options_.workers) break;
    cv_.wait(lock);
  }
  ++live_;
  lock.unlock();
  try {
    return spawn();
  } catch (...) {
    lock.lock();
    --live_;
    cv_.notify_one();
    throw;
  }
}

void WorkerPool::forget(const Worker &w) { rss_.erase(w.pid); }

void WorkerPool::release(std::unique_ptr<Worker> w, bool keep) {
  std::unique_lock lock(mu_);
  if (keep) {
    rss_[w->pid] = w->rss_anon;
    idle_.push_back(std::move(w));
  } else {
    forget(*w);
    --live_;
    lock.unlock();
    w.reset();  // kills and reaps it
    lock.lock();
  }
  cv_.notify_one();
}

Outcome WorkerPool::run_in_process(const std::string &bundle, const Limits &limits) {
  std::unique_ptr<Runner> runner;
  {
    std::lock_guard lock(local_->mu);
    if (!local_->idle.empty()) {
      runner = std::move(local_->idle.back());
      local_->idle.pop_back();
    }
  }
  if (!runner) runner = std::make_unique<Runner>();
  const auto t0 = Clock::now();
  Outcome o;
  o.result = runner->run(bundle, limits);
  o.round_trip_ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
  std::lock_guard lock(local_->mu);
  local_->idle.push_back(std::move(runner));
  return o;
}

Outcome WorkerPool::run(const std::string &bundle, const Limits &limits, const std::string &affinity,
                        const std::function<bool()> &cancelled) {
  if (local_) {
    // In process, cancellation is the decompiler's cooperative check.
    return run_in_process(bundle, limits);
  }
  std::string request;
  {
    facts::Encoder e;
    limits.encode(e);
    e.bytes(bundle);
    request = std::move(e).str();
  }
  const double hard = hard_deadline(limits.timeout_seconds);
  // A worker that dies before it reads the request didn't fail on this
  // bundle: try once more on a fresh one.
  for (int attempt = 0;; ++attempt) {
    std::unique_ptr<Worker> w = acquire(affinity);
    const auto t0 = Clock::now();
    if (!send_frame(w->sock, kRun, request)) {
      release(std::move(w), false);
      if (attempt == 0) continue;
      throw std::runtime_error("decompiler worker: cannot send a request");
    }
    const auto deadline = hard > 0 ? t0 + std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(hard))
                                   : Clock::time_point::max();
    Frame type{};
    std::string payload;
    {
      std::lock_guard lock(mu_);
      busy_.insert(w->pid);
    }
    const Worker::Wait r = w->next(deadline, type, payload, cancelled);
    bool evicted = false;
    {
      std::lock_guard lock(mu_);
      busy_.erase(w->pid);
      evicted = evicted_.erase(w->pid) != 0;
    }
    Outcome o;
    if (evicted && r != Worker::Wait::frame) {
      // Killed to keep the pool within its memory budget: not this
      // bundle's failure. The caller runs it again (alone).
      o.evicted = true;
      w->reap();
      {
        std::lock_guard lock(mu_);
        ++stats_.evicted;
      }
      release(std::move(w), false);
      return o;
    }
    if (r == Worker::Wait::cancelled) {
      o.cancelled = true;
      release(std::move(w), false);
      return o;
    }
    o.round_trip_ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
    if (r == Worker::Wait::frame && type == kResult) {
      try {
        o.result = facts::decode_from_string<RunResult>(payload);
      } catch (const std::exception &e) {
        o.failure = w->death(false, hard);
        o.failure->kind = FailureKind::abort;
        o.failure->detail = std::string("bad reply: ") + e.what();
        release(std::move(w), false);
        return o;
      }
      w->affinity = affinity;
      ++w->served;
      w->rss_anon = o.result->rss_anon;
      bool keep = o.result->stopped == lift::DecompileStop::none;
      if (options_.recycle_after != 0 && w->served >= options_.recycle_after) keep = false;
      if (options_.recycle_rss != 0 && w->rss_anon > options_.recycle_rss) keep = false;
      {
        std::lock_guard lock(mu_);
        ++stats_.runs;
        stats_.ipc_ms += std::max(0.0, o.round_trip_ms - o.result->milliseconds);
        if (!keep) ++stats_.recycled;
      }
      release(std::move(w), keep);
      return o;
    }
    const bool expired = r == Worker::Wait::expired;
    if (expired) ::kill(w->pid, SIGKILL);
    o.failure = w->death(expired, hard);
    {
      std::lock_guard lock(mu_);
      ++stats_.runs;
      ++(expired ? stats_.killed : stats_.crashed);
    }
    release(std::move(w), false);
    return o;
  }
}

void WorkerPool::warm(const std::string &bundle) {
  if (local_) {
    std::unique_ptr<Runner> runner = std::make_unique<Runner>();
    try {
      runner->warm(decode_bundle(bundle));
    } catch (const std::exception &) {
      return;
    }
    std::lock_guard lock(local_->mu);
    local_->idle.push_back(std::move(runner));
    return;
  }
  std::string affinity;
  try {
    affinity = decode_bundle(bundle).arch_key();
  } catch (const std::exception &) {
    return;
  }
  std::unique_ptr<Worker> w;
  try {
    w = acquire(affinity);
  } catch (const std::exception &) {
    return;
  }
  bool ok = send_frame(w->sock, kWarm, bundle);
  Frame type{};
  std::string payload;
  ok = ok && w->next(Clock::now() + std::chrono::seconds(60), type, payload) == Worker::Wait::frame && type == kResult;
  if (ok) w->affinity = affinity;
  release(std::move(w), ok);
}

std::uint64_t WorkerPool::live_rss() const {
  std::vector<int> pids;
  {
    std::lock_guard lock(mu_);
    for (const auto &[pid, rss] : rss_) pids.push_back(pid);
    for (int pid : busy_) pids.push_back(pid);
  }
  std::sort(pids.begin(), pids.end());
  pids.erase(std::unique(pids.begin(), pids.end()), pids.end());
  std::uint64_t sum = 0;
  for (int pid : pids) sum += anon_rss(pid);
  return sum;
}

bool WorkerPool::evict_largest() {
  std::lock_guard lock(mu_);
  std::size_t running = 0;
  for (int pid : busy_) running += evicted_.contains(pid) ? 0 : 1;
  if (running <= 1) return false;  // the last run in flight always finishes
  int victim = -1;
  std::uint64_t most = 0;
  for (int pid : busy_) {
    if (evicted_.contains(pid)) continue;
    const std::uint64_t r = anon_rss(pid);
    if (r > most) most = r, victim = pid;
  }
  if (victim < 0) return false;
  evicted_.insert(victim);
  ::kill(victim, SIGKILL);
  return true;
}

std::uint64_t WorkerPool::workers_rss() const {
  std::lock_guard lock(mu_);
  std::uint64_t sum = 0;
  for (const auto &[pid, rss] : rss_) sum += rss;
  return sum;
}

unsigned WorkerPool::live_workers() const {
  std::lock_guard lock(mu_);
  return live_;
}

PoolStats WorkerPool::stats() const {
  std::lock_guard lock(mu_);
  return stats_;
}

// ---- the worker side ------------------------------------------------------------------

namespace {

volatile pid_t g_parent = 0;

[[noreturn]] void out_of_memory() {
  static const char msg[] = "rk-decompd: out of memory\n";
  [[maybe_unused]] auto n = ::write(2, msg, sizeof msg - 1);
  ::_exit(kExitOom);
}

void on_terminate() {
  if (std::exception_ptr e = std::current_exception()) {
    try {
      std::rethrow_exception(e);
    } catch (const std::bad_alloc &) {
      out_of_memory();
    } catch (...) {
    }
  }
  std::abort();
}

bool read_frame(int fd, std::string &buf, Frame &type, std::string &payload) {
  for (;;) {
    bool bad = false;
    if (take_frame(buf, type, payload, bad)) return true;
    if (bad) return false;
    char tmp[65536];
    const ssize_t n = ::read(fd, tmp, sizeof tmp);
    if (n > 0) buf.append(tmp, static_cast<std::size_t>(n));
    else if (n < 0 && errno == EINTR) continue;
    else return false;
  }
}

}  // namespace

int serve(int fd) {
  std::set_terminate(on_terminate);
  // A worker outlives nothing: once the process that started it is gone,
  // it exits, even in the middle of a decompilation that never returns.
  // (PR_SET_PDEATHSIG would follow the thread that started it, and pool
  // threads come and go.)
  g_parent = ::getppid();
  struct sigaction sa {};
  sa.sa_handler = [](int) {
    if (::getppid() != g_parent) ::_exit(0);
  };
  sa.sa_flags = SA_RESTART;
  ::sigaction(SIGALRM, &sa, nullptr);
  const itimerval every{{1, 0}, {1, 0}};
  ::setitimer(ITIMER_REAL, &every, nullptr);
  Runner runner;
  if (!send_frame(fd, kHello, decompiler_build())) return 1;
  std::string buf, payload;
  Frame type{};
  while (read_frame(fd, buf, type, payload)) {
    try {
      if (type == kRun) {
        facts::Decoder d(payload);
        const Limits limits = Limits::decode(d);
        const std::string_view bundle = d.bytes();
        RunResult r = runner.run(bundle, limits);
        if (!send_frame(fd, kResult, facts::encode_to_string(r))) return 1;
      } else if (type == kWarm) {
        RunResult r;
        try {
          runner.warm(decode_bundle(payload));
          r.ran = true;
        } catch (const std::bad_alloc &) {
          throw;
        } catch (const std::exception &e) {
          r.error = e.what();
        }
        if (!send_frame(fd, kResult, facts::encode_to_string(r))) return 1;
      } else {
        return 2;
      }
    } catch (const std::bad_alloc &) {
      out_of_memory();
    }
  }
  return 0;
}

}  // namespace revkit::decompd
