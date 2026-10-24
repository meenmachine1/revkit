// The helper's side of the sandbox (rk-sandbox): resource limits, a
// session of its own, an optional user and network namespace, Landlock and
// a seccomp filter, applied by a single-threaded process to itself before
// it executes the tool. See sandbox.h and docs/providers.md.
#include "revkit/providers/sandbox.h"

#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

namespace revkit::providers {
namespace {

// Landlock, defined here: the system's <linux/landlock.h> may predate the
// rights and scopes a newer kernel has.
constexpr unsigned kCreateRulesetVersion = 1u << 0;
constexpr int kRulePathBeneath = 1;
constexpr std::uint64_t kFsExecute = 1ull << 0, kFsWriteFile = 1ull << 1, kFsReadFile = 1ull << 2,
                        kFsReadDir = 1ull << 3, kFsRefer = 1ull << 13, kFsTruncate = 1ull << 14,
                        kFsIoctlDev = 1ull << 15;
constexpr std::uint64_t kNetBindTcp = 1ull << 0, kNetConnectTcp = 1ull << 1;
constexpr std::uint64_t kScopeAbstractUnix = 1ull << 0, kScopeSignal = 1ull << 1;

struct RulesetAttr {
  std::uint64_t handled_access_fs;
  std::uint64_t handled_access_net;
  std::uint64_t scoped;
};
struct __attribute__((packed)) PathBeneathAttr {
  std::uint64_t allowed_access;
  std::int32_t parent_fd;
};

int landlock_abi() {
  const long v = ::syscall(SYS_landlock_create_ruleset, nullptr, 0, kCreateRulesetVersion);
  return v < 0 ? 0 : static_cast<int>(v);
}

std::uint64_t fs_rights(int abi) {
  std::uint64_t r = (1ull << 13) - 1;  // ABI 1: execute .. make_sym
  if (abi >= 2) r |= kFsRefer;
  if (abi >= 3) r |= kFsTruncate;
  if (abi >= 5) r |= kFsIoctlDev;
  return r;
}

std::string err(const std::string &what) { return what + ": " + std::strerror(errno); }

std::string add_path(int ruleset, const std::string &path, std::uint64_t dir_rights, std::uint64_t file_rights) {
  const int fd = ::open(path.c_str(), O_PATH | O_CLOEXEC);
  if (fd < 0) return errno == ENOENT ? std::string() : err("landlock: " + path);
  struct stat st {};
  ::fstat(fd, &st);
  PathBeneathAttr attr{S_ISDIR(st.st_mode) ? dir_rights : file_rights, fd};
  const long rc = ::syscall(SYS_landlock_add_rule, ruleset, kRulePathBeneath, &attr, 0);
  const int saved = errno;
  ::close(fd);
  errno = saved;
  return rc < 0 ? err("landlock rule " + path) : std::string();
}

std::string apply_landlock(const ConfineOptions &o, int abi) {
  const std::uint64_t all = fs_rights(abi);
  RulesetAttr attr{all, 0, 0};
  std::size_t size = sizeof(std::uint64_t);
  if (abi >= 4) {
    attr.handled_access_net = kNetBindTcp | kNetConnectTcp;
    size = 2 * sizeof(std::uint64_t);
  }
  if (abi >= 6) {
    attr.scoped = kScopeAbstractUnix | kScopeSignal;
    size = sizeof(RulesetAttr);
  }
  const long rs = ::syscall(SYS_landlock_create_ruleset, &attr, size, 0);
  if (rs < 0) return err("landlock_create_ruleset");
  const int ruleset = static_cast<int>(rs);
  const std::uint64_t file_mask = kFsExecute | kFsWriteFile | kFsReadFile | kFsTruncate | kFsIoctlDev;
  const std::uint64_t read = kFsExecute | kFsReadFile | kFsReadDir;
  for (const std::string &p : o.read_paths) {
    if (p == "/proc" || p == "/proc/") {
      // Not every process's /proc/<pid> (the daemon's environ, cmdline and
      // fd links are readable to the same user): this process's own, which
      // the tool keeps across execve (its /proc/self), and the system-wide
      // files runtimes read about the machine.
      const std::string self = "/proc/" + std::to_string(::getpid());
      for (const std::string &q : {self, std::string("/proc/cpuinfo"), std::string("/proc/meminfo"),
                                  std::string("/proc/stat"), std::string("/proc/sys"), std::string("/proc/filesystems"),
                                  std::string("/proc/loadavg"), std::string("/proc/uptime"), std::string("/proc/version"),
                                  std::string("/proc/pressure")})
        if (std::string e = add_path(ruleset, q, read, read & file_mask & all); !e.empty()) return e;
      continue;
    }
    if (std::string e = add_path(ruleset, p, read, read & file_mask & all); !e.empty()) return e;
  }
  for (const std::string &p : o.write_paths)
    if (std::string e = add_path(ruleset, p, all, all & file_mask); !e.empty()) return e;
  // The character devices programs open for reading and writing.
  const std::uint64_t dev = (kFsReadFile | kFsWriteFile | kFsTruncate | kFsIoctlDev) & all;
  for (const char *d : {"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom"})
    if (std::string e = add_path(ruleset, d, dev, dev); !e.empty()) return e;
  if (::syscall(SYS_landlock_restrict_self, ruleset, 0) < 0) return err("landlock_restrict_self");
  ::close(ruleset);
  return {};
}

// --- seccomp --------------------------------------------------------------

#if defined(__x86_64__)
constexpr std::uint32_t kAuditArch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
constexpr std::uint32_t kAuditArch = AUDIT_ARCH_AARCH64;
#else
#error "the provider sandbox knows x86-64 and AArch64"
#endif

struct Filter {
  std::vector<sock_filter> code;
  void stmt(std::uint16_t c, std::uint32_t k) { code.push_back(BPF_STMT(c, k)); }
  void jump(std::uint16_t c, std::uint32_t k, std::uint8_t t, std::uint8_t f) { code.push_back(BPF_JUMP(c, k, t, f)); }
  void load_nr() { stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)); }
  void load_arg_lo(int i) { stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args) + 8 * i); }
  // if nr == n: return errno e (the accumulator holds nr)
  void deny(long n, int e) {
    jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(n), 0, 1);
    stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (static_cast<std::uint32_t>(e) & SECCOMP_RET_DATA));
  }
  // if nr == n: allowed when, for every (argument, values), the argument's
  // low 32 bits are one of the values (pids and the like: the kernel reads
  // an int); else errno e. The accumulator holds nr again after it.
  void allow_only(long n, const std::vector<std::pair<int, std::vector<std::uint32_t>>> &conditions, int e) {
    std::vector<sock_filter> b;
    std::vector<std::size_t> to_deny;  // JA instructions to point at the deny
    for (const auto &[arg, values] : conditions) {
      b.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<std::uint32_t>(offsetof(seccomp_data, args) + 8 * arg)));
      for (std::size_t j = 0; j < values.size(); ++j)  // a match skips the other tests and the JA
        b.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, values[j], static_cast<std::uint8_t>(values.size() - j), 0));
      to_deny.push_back(b.size());
      b.push_back(BPF_STMT(BPF_JMP | BPF_JA, 0));
    }
    b.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    const std::size_t deny_at = b.size();
    b.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (static_cast<std::uint32_t>(e) & SECCOMP_RET_DATA)));
    for (std::size_t p : to_deny) b[p].k = static_cast<std::uint32_t>(deny_at - p - 1);
    jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(n), 0, static_cast<std::uint8_t>(b.size()));
    code.insert(code.end(), b.begin(), b.end());
  }
};

// Numbers the system's headers may predate.
#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

// `abi`: the Landlock ABI applied (0: none). `self`: this process's pid,
// the tool's after execve.
std::string apply_seccomp(int abi, pid_t self) {
  Filter f;
  f.stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch));
  f.jump(BPF_JMP | BPF_JEQ | BPF_K, kAuditArch, 1, 0);
  f.stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
  f.load_nr();
#if defined(__x86_64__)
  // The x32 ABI's numbers (bit 30) would bypass every rule below.
  f.jump(BPF_JMP | BPF_JGE | BPF_K, 0x40000000u, 0, 1);
  f.stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
#endif
  // Sockets: none but socketpair(); no connect().
  f.deny(SYS_socket, EACCES);
  f.deny(SYS_connect, EACCES);
  // Namespaces and mounts.
  for (long n : {long{SYS_unshare}, long{SYS_setns}, long{SYS_mount}, long{SYS_umount2}, long{SYS_pivot_root},
                 long{SYS_chroot}, long{SYS_open_tree}, long{SYS_move_mount}, long{SYS_fsopen}, long{SYS_fsconfig},
                 long{SYS_fsmount}, long{SYS_fspick}, long{SYS_mount_setattr}})
    f.deny(n, EPERM);
  // The kernel's other attack surface and the user's other processes.
  for (long n : {long{SYS_keyctl}, long{SYS_add_key}, long{SYS_request_key}, long{SYS_io_uring_setup},
                 long{SYS_io_uring_enter}, long{SYS_io_uring_register}, long{SYS_bpf}, long{SYS_perf_event_open},
                 long{SYS_ptrace}, long{SYS_process_vm_readv}, long{SYS_process_vm_writev}, long{SYS_userfaultfd},
                 long{SYS_kexec_load}, long{SYS_kexec_file_load}, long{SYS_init_module}, long{SYS_finit_module},
                 long{SYS_delete_module}, long{SYS_setsid}, long{SYS_setpgid}, long{SYS_name_to_handle_at},
                 long{SYS_open_by_handle_at}, long{SYS_fanotify_init}, long{SYS_pidfd_getfd}})
    f.deny(n, EPERM);
  // Neither Landlock nor the rules above confine a file's mode, owner or
  // extended attributes by path: the tool could open up the daemon's
  // credentials or lock it out of its store (bug scrub part 3).
  for (long n : {
#ifdef SYS_chmod
           long{SYS_chmod}, long{SYS_chown}, long{SYS_lchown},
#endif
           long{SYS_fchmod}, long{SYS_fchmodat}, long{SYS_fchmodat2}, long{SYS_fchown}, long{SYS_fchownat},
           long{SYS_setxattr}, long{SYS_lsetxattr}, long{SYS_fsetxattr}, long{SYS_removexattr},
           long{SYS_lremovexattr}, long{SYS_fremovexattr}, long{SYS_process_madvise}, long{SYS_kcmp}})
    f.deny(n, EPERM);
  // Before Landlock ABI 3, truncate(path) isn't a right it handles.
  if (abi < 3) f.deny(SYS_truncate, EPERM);
  // Limits, priorities and memory placement of this process only: another
  // process of the daemon's user (the daemon itself: prlimit64(RLIMIT_CPU)
  // would kill it) is refused.
  const std::uint32_t me = static_cast<std::uint32_t>(self);
  f.allow_only(SYS_prlimit64, {{0, {0, me}}}, EPERM);
  f.allow_only(SYS_setpriority, {{0, {0 /* PRIO_PROCESS */}}, {1, {0, me}}}, EPERM);
  f.allow_only(SYS_ioprio_set, {{0, {1 /* IOPRIO_WHO_PROCESS */}}, {1, {0, me}}}, EPERM);
  for (long n : {long{SYS_sched_setaffinity}, long{SYS_sched_setscheduler}, long{SYS_sched_setparam},
                 long{SYS_sched_setattr}, long{SYS_migrate_pages}, long{SYS_move_pages}})
    f.allow_only(n, {{0, {0, me}}}, EPERM);
  // Signals: from Landlock ABI 6 they are scoped to the sandbox. Before,
  // only this process, its own threads and its own process group (the
  // session setsid made) may be signalled: kill(-1) and the daemon are
  // refused.
  if (abi < 6) {
    f.allow_only(SYS_kill, {{0, {0, me, static_cast<std::uint32_t>(-self)}}}, EPERM);
    f.allow_only(SYS_tgkill, {{0, {me}}}, EPERM);
    f.allow_only(SYS_rt_sigqueueinfo, {{0, {me}}}, EPERM);
    f.allow_only(SYS_rt_tgsigqueueinfo, {{0, {me}}}, EPERM);
    f.deny(SYS_tkill, EPERM);
    f.deny(SYS_pidfd_send_signal, EPERM);
  }
  // clone3's flags are in memory a filter can't read: ENOSYS makes libc
  // fall back to clone(), whose flags it can.
  f.deny(SYS_clone3, ENOSYS);
  constexpr std::uint32_t kNamespaces = CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC |
                                        CLONE_NEWUTS | CLONE_NEWCGROUP;
  f.jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 4);
  f.load_arg_lo(0);
  f.jump(BPF_JMP | BPF_JSET | BPF_K, kNamespaces, 0, 1);
  f.stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
  f.stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  f.stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  sock_fprog prog{static_cast<unsigned short>(f.code.size()), f.code.data()};
  if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) return err("seccomp");
  return {};
}

// --- a user and network namespace -------------------------------------

bool write_file(const char *path, const std::string &text) {
  const int fd = ::open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) return false;
  const bool ok = ::write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
  ::close(fd);
  return ok;
}

// A namespace with no network devices, the caller's uid and gid mapped to
// themselves (files it creates keep their owner). False when the kernel or
// its policy refuses any step; the process may then be in a user namespace
// with nothing mapped, so only a probe child tries it first.
bool enter_netns() {
  const uid_t uid = ::geteuid();
  const gid_t gid = ::getegid();
  if (::unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) return false;
  if (!write_file("/proc/self/setgroups", "deny")) return false;
  if (!write_file("/proc/self/uid_map", std::to_string(uid) + " " + std::to_string(uid) + " 1")) return false;
  if (!write_file("/proc/self/gid_map", std::to_string(gid) + " " + std::to_string(gid) + " 1")) return false;
  return true;
}

bool child_succeeds(bool (*fn)()) {
  const pid_t pid = ::fork();
  if (pid < 0) return false;
  if (pid == 0) ::_exit(fn() ? 0 : 1);
  int st = 0;
  while (::waitpid(pid, &st, 0) < 0 && errno == EINTR) {
  }
  return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

bool seccomp_works() {
  if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return false;
  if (!apply_seccomp(landlock_abi(), ::getpid()).empty()) return false;
  // A socket must now be refused.
  const int s = ::socket(AF_INET, SOCK_STREAM, 0);
  return s < 0 && errno == EACCES;
}

void set_limit(int which, std::uint64_t v) {
  if (v == 0) return;
  const rlimit r{static_cast<rlim_t>(v), static_cast<rlim_t>(v)};
  ::setrlimit(which, &r);
}

}  // namespace

SandboxSupport probe_self() {
  SandboxSupport s;
  s.landlock_abi = landlock_abi();
  s.landlock_net = s.landlock_abi >= 4;
  s.landlock_scope = s.landlock_abi >= 6;
  s.seccomp = child_succeeds(seccomp_works);
  s.netns = child_succeeds(enter_netns);
  return s;
}

std::string confine_self(const ConfineOptions &o) {
  if (::close_range(3, ~0u, 0) != 0) {
    // Kernels before 5.9: close them one by one.
    for (int fd = 3; fd < 65536; ++fd) ::close(fd);
  }
  // No core dumps; the limits the caller asked for.
  const rlimit no_core{0, 0};
  ::setrlimit(RLIMIT_CORE, &no_core);
  set_limit(RLIMIT_DATA, o.memory);
  set_limit(RLIMIT_AS, o.address_space);
  set_limit(RLIMIT_CPU, o.cpu);
  set_limit(RLIMIT_FSIZE, o.file_size);
  set_limit(RLIMIT_NOFILE, o.open_files);
  // A session (and process group) of its own: the parent kills the group.
  ::setsid();
  ::prctl(PR_SET_PDEATHSIG, SIGKILL);
  if (::getppid() == 1) return "the parent went away";
  if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return err("no_new_privs");
  if (child_succeeds(enter_netns) && !enter_netns()) return "entering a network namespace failed after the probe succeeded";
  int abi = landlock_abi();
  if (o.max_landlock_abi > 0 && abi > o.max_landlock_abi) abi = o.max_landlock_abi;
  if (abi > 0) {
    if (std::string e = apply_landlock(o, abi); !e.empty()) return e;
  } else if (!o.allow_weak) {
    return "this kernel has no Landlock, so the tool's file access can't be confined (an admin can allow running "
           "without it: allow_weak_sandbox)";
  }
  if (!o.cwd.empty() && ::chdir(o.cwd.c_str()) != 0) return err("chdir " + o.cwd);
  if (std::string e = apply_seccomp(abi, ::getpid()); !e.empty()) return e;
  return {};
}

}  // namespace revkit::providers
