// The parent's side of the sandbox: starting rk-sandbox, the deadline, the
// output cap, killing the process group, classifying how the run ended.
#include "revkit/providers/sandbox.h"

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>

extern char **environ;

namespace revkit::providers {
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

namespace {

std::mutex g_mu;
std::string g_helper_override;
std::map<std::string, SandboxSupport> g_support;

std::string signal_name(int sig) {
  switch (sig) {
    case SIGSEGV: return "SIGSEGV";
    case SIGBUS: return "SIGBUS";
    case SIGFPE: return "SIGFPE";
    case SIGABRT: return "SIGABRT";
    case SIGILL: return "SIGILL";
    case SIGKILL: return "SIGKILL";
    case SIGTERM: return "SIGTERM";
    case SIGSYS: return "SIGSYS";
    case SIGXCPU: return "SIGXCPU";
    case SIGXFSZ: return "SIGXFSZ";
    case SIGPIPE: return "SIGPIPE";
    case SIGTRAP: return "SIGTRAP";
    default: return "signal " + std::to_string(sig);
  }
}

std::string tail_of(const fs::path &p, std::size_t n) {
  if (p.empty()) return {};
  const int fd = ::open(p.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return {};
  struct stat st {};
  ::fstat(fd, &st);
  const off_t from = st.st_size > static_cast<off_t>(n) ? st.st_size - static_cast<off_t>(n) : 0;
  std::string out(static_cast<std::size_t>(st.st_size - from), '\0');
  const ssize_t r = ::pread(fd, out.data(), out.size(), from);
  ::close(fd);
  out.resize(r > 0 ? static_cast<std::size_t>(r) : 0);
  return out;
}

// Bytes and entries below `dir`, stopping once past the caps (links are
// counted, never followed).
void measure(const fs::path &dir, std::uint64_t &bytes, std::uint64_t &entries, std::uint64_t max_entries) {
  std::error_code ec;
  fs::recursive_directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end;
  for (; !ec && it != end; it.increment(ec)) {
    ++entries;
    if (entries > max_entries) return;
    const fs::file_status st = it->symlink_status(ec);
    if (!ec && fs::is_regular_file(st)) bytes += it->file_size(ec);
    ec.clear();
  }
}

std::uint64_t size_of(const fs::path &p) {
  struct stat st {};
  return !p.empty() && ::stat(p.c_str(), &st) == 0 ? static_cast<std::uint64_t>(st.st_size) : 0;
}

// Kills every process in the group. One signal is enough: the kernel
// delivers it to the whole group at once, and a process forking at that
// moment can't make a child that misses it (fork fails with a fatal signal
// pending).
void kill_group(pid_t pgid) {
  ::kill(-pgid, SIGKILL);
  ::kill(pgid, SIGKILL);  // before its setsid(), the helper is in the daemon's group
}

bool contains_any(const std::string &s, std::initializer_list<const char *> needles) {
  for (const char *n : needles)
    if (s.find(n) != std::string::npos) return true;
  return false;
}

}  // namespace

const char *status_name(RunStatus s) {
  switch (s) {
    case RunStatus::ok: return "ok";
    case RunStatus::failed: return "failed";
    case RunStatus::crashed: return "crashed";
    case RunStatus::timeout: return "timeout";
    case RunStatus::out_of_memory: return "out_of_memory";
    case RunStatus::output_limit: return "output_limit";
    case RunStatus::cancelled: return "cancelled";
    case RunStatus::sandbox_error: return "sandbox_error";
  }
  return "?";
}

std::string SandboxSupport::describe() const {
  if (!error.empty()) return "unknown (" + error + ")";
  std::string s;
  if (landlock_abi > 0) {
    s = "Landlock ABI " + std::to_string(landlock_abi) + " (files";
    if (landlock_net) s += ", TCP";
    if (landlock_scope) s += ", abstract sockets and signals";
    s += ")";
  } else {
    s = "no Landlock (file access not confined)";
  }
  s += seccomp ? ", seccomp (no sockets)" : ", no seccomp";
  s += netns ? ", network namespace" : ", no network namespace (user namespaces restricted)";
  return s;
}

void set_helper_for_tests(std::string path) {
  std::lock_guard lock(g_mu);
  g_helper_override = std::move(path);
}

std::string find_helper() {
  {
    std::lock_guard lock(g_mu);
    if (!g_helper_override.empty()) return g_helper_override;
  }
  if (const char *env = std::getenv("REVKIT_SANDBOX"); env != nullptr && *env != 0) return env;
  std::error_code ec;
  const fs::path exe = fs::read_symlink("/proc/self/exe", ec);
  std::vector<fs::path> candidates;
  if (!ec) {
    const fs::path dir = exe.parent_path();
    candidates = {dir / "rk-sandbox", dir / ".." / "rk-sandbox" / "rk-sandbox",
                  dir / ".." / "tools" / "rk-sandbox" / "rk-sandbox", dir / ".." / ".." / "tools" / "rk-sandbox" / "rk-sandbox"};
  }
#ifdef REVKIT_SANDBOX_BUILD_PATH
  if (*REVKIT_SANDBOX_BUILD_PATH != 0) candidates.emplace_back(REVKIT_SANDBOX_BUILD_PATH);
#endif
  for (const fs::path &c : candidates)
    if (::access(c.c_str(), X_OK) == 0) return fs::weakly_canonical(c, ec).string();
  return {};
}

SandboxSupport probe_support() {
  const std::string helper = find_helper();
  {
    std::lock_guard lock(g_mu);
    if (auto it = g_support.find(helper); it != g_support.end()) return it->second;
  }
  SandboxSupport s;
  if (helper.empty()) {
    s.error = "rk-sandbox not found (set REVKIT_SANDBOX)";
    return s;
  }
  char tmpl[] = "/tmp/rk-sandbox-probe-XXXXXX";
  const int fd = ::mkstemp(tmpl);
  if (fd < 0) {
    s.error = std::string("probe: ") + std::strerror(errno);
    return s;
  }
  ::close(fd);
  SandboxSpec spec;
  spec.argv = {helper, "--probe"};
  spec.stdout_file = tmpl;
  spec.limits.timeout = std::chrono::seconds(10);
  // The probe runs the helper itself, unconfined: run_sandboxed would
  // confine it first.
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
  posix_spawn_file_actions_addopen(&fa, 1, tmpl, O_WRONLY | O_TRUNC, 0600);
  posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
  char *argv[] = {const_cast<char *>(helper.c_str()), const_cast<char *>("--probe"), nullptr};
  pid_t pid = -1;
  const int rc = ::posix_spawn(&pid, helper.c_str(), &fa, nullptr, argv, environ);
  posix_spawn_file_actions_destroy(&fa);
  if (rc != 0) {
    s.error = "cannot start " + helper + ": " + std::strerror(rc);
  } else {
    int st = 0;
    while (::waitpid(pid, &st, 0) < 0 && errno == EINTR) {
    }
    const std::string out = tail_of(tmpl, 256);
    int ll = 0, sc = 0, ns = 0;
    if (std::sscanf(out.c_str(), "landlock=%d seccomp=%d netns=%d", &ll, &sc, &ns) == 3) {
      s.landlock_abi = ll;
      s.landlock_net = ll >= 4;
      s.landlock_scope = ll >= 6;
      s.seccomp = sc != 0;
      s.netns = ns != 0;
    } else {
      s.error = "rk-sandbox --probe said \"" + out + "\"";
    }
  }
  ::unlink(tmpl);
  std::lock_guard lock(g_mu);
  g_support[helper] = s;
  return s;
}

RunOutcome run_sandboxed(const SandboxSpec &spec) {
  RunOutcome out;
  const auto start = Clock::now();
  const std::string helper = find_helper();
  if (helper.empty()) {
    out.detail = "rk-sandbox not found (set REVKIT_SANDBOX to the sandbox helper)";
    return out;
  }
  if (spec.argv.empty() || spec.argv[0].empty() || spec.argv[0][0] != '/') {
    out.detail = "the program must be an absolute path";
    return out;
  }
  const SandboxLimits &lim = spec.limits;
  const auto timeout_s = static_cast<std::uint64_t>(std::max<std::int64_t>(1, std::chrono::ceil<std::chrono::seconds>(lim.timeout).count()));
  std::vector<std::string> args = {helper};
  for (const fs::path &p : spec.read_paths) args.insert(args.end(), {"--ro", p.string()});
  for (const fs::path &p : spec.write_paths) args.insert(args.end(), {"--rw", p.string()});
  if (!spec.cwd.empty()) args.insert(args.end(), {"--cwd", spec.cwd.string()});
  if (lim.memory_bytes) args.insert(args.end(), {"--memory", std::to_string(lim.memory_bytes)});
  if (lim.address_space_bytes) args.insert(args.end(), {"--address-space", std::to_string(lim.address_space_bytes)});
  args.insert(args.end(), {"--cpu", std::to_string(lim.cpu_seconds ? lim.cpu_seconds : 4 * timeout_s)});
  // One more byte than the cap, so that reaching the cap exactly isn't a stop.
  if (lim.output_bytes) args.insert(args.end(), {"--file-size", std::to_string(lim.output_bytes + 1)});
  if (lim.open_files) args.insert(args.end(), {"--open-files", std::to_string(lim.open_files)});
  if (spec.allow_weak) args.push_back("--weak");
  args.push_back("--");
  args.insert(args.end(), spec.argv.begin(), spec.argv.end());
  std::vector<char *> argv, envp;
  for (std::string &a : args) argv.push_back(a.data());
  argv.push_back(nullptr);
  std::vector<std::string> env = spec.env;
  for (std::string &e : env) envp.push_back(e.data());
  envp.push_back(nullptr);

  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
  posix_spawn_file_actions_addopen(&fa, 1, spec.stdout_file.empty() ? "/dev/null" : spec.stdout_file.c_str(),
                                   O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
  posix_spawn_file_actions_addopen(&fa, 2, spec.stderr_file.empty() ? "/dev/null" : spec.stderr_file.c_str(),
                                   O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
  posix_spawnattr_t attr;
  posix_spawnattr_init(&attr);
  sigset_t none, all;
  sigemptyset(&none);
  sigfillset(&all);
  posix_spawnattr_setsigmask(&attr, &none);
  posix_spawnattr_setsigdefault(&attr, &all);
  posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
  pid_t pid = -1;
  const int rc = ::posix_spawn(&pid, helper.c_str(), &fa, &attr, argv.data(), envp.data());
  posix_spawn_file_actions_destroy(&fa);
  posix_spawnattr_destroy(&attr);
  if (rc != 0) {
    out.detail = "cannot start " + helper + ": " + std::strerror(rc);
    return out;
  }

  enum class Stop { none, deadline, output, cancelled } stop = Stop::none;
  int st = 0;
  const auto deadline = start + lim.timeout;
  auto next_measure = start;
  // waitid(WNOWAIT) sees the exit without reaping: while the zombie is
  // there its pid (the group's id) can't be reused, so killing the group
  // below can't reach anyone else.
  for (;;) {
    siginfo_t info{};
    const int w = ::waitid(P_PID, static_cast<id_t>(pid), &info, WEXITED | WNOHANG | WNOWAIT);
    if (w == 0 && info.si_pid == pid) break;
    if (w < 0 && errno != EINTR) break;
    const auto now = Clock::now();
    if (stop == Stop::none) {
      if (now >= deadline) stop = Stop::deadline;
      else if (spec.cancelled && spec.cancelled()) stop = Stop::cancelled;
      else if (now >= next_measure) {
        next_measure = now + std::chrono::milliseconds(250);
        std::uint64_t bytes = size_of(spec.stdout_file), entries = 0;
        if (!spec.output_dir.empty()) measure(spec.output_dir, bytes, entries, lim.output_files);
        if ((lim.output_bytes && bytes > lim.output_bytes) || entries > lim.output_files) stop = Stop::output;
      }
      if (stop != Stop::none) kill_group(pid);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(stop == Stop::none ? 20 : 5));
  }
  // Whatever the tool left running in its group goes with it; then reap.
  kill_group(pid);
  while (::waitpid(pid, &st, 0) < 0 && errno == EINTR) {
  }
  out.seconds = std::chrono::duration<double>(Clock::now() - start).count();
  out.stderr_tail = tail_of(spec.stderr_file, 4096);
  if (WIFEXITED(st)) out.exit_code = WEXITSTATUS(st);
  if (WIFSIGNALED(st)) out.signal = WTERMSIG(st);

  // A final measure: a tool may exit right after writing too much.
  if (stop == Stop::none && WIFEXITED(st)) {
    std::uint64_t bytes = size_of(spec.stdout_file), entries = 0;
    if (!spec.output_dir.empty()) measure(spec.output_dir, bytes, entries, lim.output_files);
    if ((lim.output_bytes && bytes > lim.output_bytes) || entries > lim.output_files) stop = Stop::output;
  }
  std::ostringstream cap;
  switch (stop) {
    case Stop::deadline:
      out.status = RunStatus::timeout;
      out.detail = "killed after " + std::to_string(timeout_s) + " s";
      return out;
    case Stop::output:
      out.status = RunStatus::output_limit;
      out.detail = "wrote more than " + std::to_string(lim.output_bytes >> 20) + " MiB or " +
                   std::to_string(lim.output_files) + " files";
      return out;
    case Stop::cancelled:
      out.status = RunStatus::cancelled;
      out.detail = "cancelled";
      return out;
    case Stop::none: break;
  }
  if (WIFSIGNALED(st)) {
    const int sig = WTERMSIG(st);
    if (sig == SIGXCPU) {
      out.status = RunStatus::timeout;
      out.detail = "over its CPU time";
    } else if (sig == SIGXFSZ) {
      out.status = RunStatus::output_limit;
      out.detail = "wrote a file larger than " + std::to_string(lim.output_bytes >> 20) + " MiB";
    } else if (sig == SIGKILL) {
      // Not revkit's: the kernel's OOM killer (or a cgroup's limit).
      out.status = RunStatus::out_of_memory;
      out.detail = "killed (SIGKILL), most likely out of memory";
    } else {
      out.status = RunStatus::crashed;
      out.detail = signal_name(sig) + (sig == SIGSYS ? " (a system call the sandbox doesn't allow)" : "");
    }
    return out;
  }
  if (out.exit_code == 0) {
    out.status = RunStatus::ok;
    out.detail = "exit status 0";
    return out;
  }
  if (out.exit_code == 125 && out.stderr_tail.find("rk-sandbox: ") != std::string::npos) {
    out.status = RunStatus::sandbox_error;
    const auto at = out.stderr_tail.rfind("rk-sandbox: ");
    out.detail = out.stderr_tail.substr(at + 12);
    while (!out.detail.empty() && (out.detail.back() == '\n' || out.detail.back() == '\r')) out.detail.pop_back();
    return out;
  }
  if (contains_any(out.stderr_tail, {"java.lang.OutOfMemoryError", "OutOfMemoryException", "std::bad_alloc",
                                     "Cannot allocate memory", "Could not reserve enough space",
                                     "GC heap initialization failed", "JavaScript heap out of memory",
                                     "insufficient memory for the Java Runtime"})) {
    out.status = RunStatus::out_of_memory;
    out.detail = "out of memory (exit status " + std::to_string(out.exit_code) + ")";
    return out;
  }
  out.status = RunStatus::failed;
  out.detail = "exit status " + std::to_string(out.exit_code);
  return out;
}

}  // namespace revkit::providers
