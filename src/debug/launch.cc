// Starting processes to debug: gdbserver over a socketpair (no port is
// opened, and the connection ends with the process), qemu-user and
// qemu-system with their gdbstub on a Unix socket in a private directory.
#include "revkit/debug/gdb_remote.hh"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

extern char **environ;

namespace revkit::debug {

namespace fs = std::filesystem;

std::string find_program(const std::string &name) {
  if (name.empty()) return "";
  if (name.find('/') != std::string::npos) return ::access(name.c_str(), X_OK) == 0 ? name : "";
  const char *path = std::getenv("PATH");
  std::string p = path != nullptr ? path : "/usr/local/bin:/usr/bin:/bin";
  std::size_t at = 0;
  while (at <= p.size()) {
    const auto colon = p.find(':', at);
    const std::string dir = p.substr(at, colon == std::string::npos ? std::string::npos : colon - at);
    if (!dir.empty()) {
      const std::string full = dir + "/" + name;
      struct stat st {};
      if (::stat(full.c_str(), &st) == 0 && S_ISREG(st.st_mode) && ::access(full.c_str(), X_OK) == 0) return full;
    }
    if (colon == std::string::npos) break;
    at = colon + 1;
  }
  return "";
}

int ptrace_scope() {
  std::ifstream in("/proc/sys/kernel/yama/ptrace_scope");
  int v = -1;
  if (in >> v) return v;
  return -1;
}

std::string attach_hint() {
  const int scope = ptrace_scope();
  if (scope < 1) return "";
  if (scope >= 3) return "kernel.yama.ptrace_scope is 3: attaching is disabled until reboot";
  return "kernel.yama.ptrace_scope is " + std::to_string(scope) +
         ", so only a process's ancestors (or CAP_SYS_PTRACE) may attach: run `sudo sysctl kernel.yama.ptrace_scope=0`, "
         "or `sudo setcap cap_sys_ptrace+ep " + (find_program("gdbserver").empty() ? std::string("/usr/bin/gdbserver") : find_program("gdbserver")) +
         "`, or launch the program from the debugger instead";
}

std::uint32_t host_machine() {
  utsname u{};
  ::uname(&u);
  const std::string m = u.machine;
  if (m == "x86_64") return 62;
  if (m == "aarch64" || m == "arm64") return 183;
  if (m.rfind("arm", 0) == 0) return 40;
  if (m == "i686" || m == "i386") return 3;
  if (m == "riscv64") return 243;
  if (m.rfind("ppc64", 0) == 0) return 21;
  return 0;
}

std::string qemu_user_for_machine(std::uint32_t machine, bool big_endian) {
  switch (machine) {
    case 183: return big_endian ? "qemu-aarch64_be" : "qemu-aarch64";
    case 40: return big_endian ? "qemu-armeb" : "qemu-arm";
    case 62: return "qemu-x86_64";
    case 3: return "qemu-i386";
    case 243: return "qemu-riscv64";
    case 8: return big_endian ? "qemu-mips" : "qemu-mipsel";
    case 20: return "qemu-ppc";
    case 21: return big_endian ? "qemu-ppc64" : "qemu-ppc64le";
    default: return "";
  }
}

namespace {

std::string sysroot_for(std::uint32_t machine) {
  const char *dirs[] = {nullptr, nullptr};
  switch (machine) {
    case 183: dirs[0] = "/usr/aarch64-linux-gnu"; break;
    case 40: dirs[0] = "/usr/arm-linux-gnueabihf"; dirs[1] = "/usr/arm-linux-gnueabi"; break;
    case 243: dirs[0] = "/usr/riscv64-linux-gnu"; break;
    case 8: dirs[0] = "/usr/mips-linux-gnu"; break;
    default: break;
  }
  for (const char *d : dirs)
    if (d != nullptr && fs::exists(fs::path(d) / "lib")) return d;
  return "";
}

struct ElfHead {
  std::uint32_t machine = 0;
  bool big_endian = false;
  bool ok = false;
};

ElfHead read_elf_head(const fs::path &p) {
  ElfHead h;
  std::ifstream in(p, std::ios::binary);
  unsigned char b[20] = {};
  if (!in.read(reinterpret_cast<char *>(b), sizeof b)) return h;
  if (b[0] != 0x7f || b[1] != 'E' || b[2] != 'L' || b[3] != 'F') return h;
  h.big_endian = b[5] == 2;
  h.machine = h.big_endian ? (b[18] << 8 | b[19]) : (b[19] << 8 | b[18]);
  h.ok = true;
  return h;
}

// posix_spawn with stdin, stdout and stderr given; a new process group.
int spawn(const std::vector<std::string> &argv, const std::vector<std::string> &env_add, int in, int out, int err,
          const fs::path &cwd) {
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_adddup2(&fa, in, 0);
  posix_spawn_file_actions_adddup2(&fa, out, 1);
  posix_spawn_file_actions_adddup2(&fa, err, 2);
  if (!cwd.empty()) posix_spawn_file_actions_addchdir_np(&fa, cwd.c_str());
  posix_spawnattr_t at;
  posix_spawnattr_init(&at);
  posix_spawnattr_setflags(&at, POSIX_SPAWN_SETPGROUP);
  posix_spawnattr_setpgroup(&at, 0);
  std::vector<char *> args;
  for (const std::string &a : argv) args.push_back(const_cast<char *>(a.c_str()));
  args.push_back(nullptr);
  std::vector<std::string> envs;
  for (char **e = environ; e != nullptr && *e != nullptr; ++e) envs.emplace_back(*e);
  for (const std::string &e : env_add) envs.push_back(e);
  std::vector<char *> envp;
  for (std::string &e : envs) envp.push_back(e.data());
  envp.push_back(nullptr);
  pid_t pid = -1;
  const int rc = ::posix_spawn(&pid, argv[0].c_str(), &fa, &at, args.data(), envp.data());
  posix_spawn_file_actions_destroy(&fa);
  posix_spawnattr_destroy(&at);
  if (rc != 0) throw DebugError("starting " + argv[0] + ": " + std::strerror(rc));
  return pid;
}

int devnull() {
  const int fd = ::open("/dev/null", O_RDWR | O_CLOEXEC);
  if (fd < 0) throw DebugError(std::string("/dev/null: ") + std::strerror(errno));
  return fd;
}

// A pipe whose read end is non-blocking: the child's output.
std::pair<int, int> output_pipe() {
  int p[2];
  if (::pipe2(p, O_CLOEXEC) != 0) throw DebugError(std::string("pipe: ") + std::strerror(errno));
  ::fcntl(p[0], F_SETFL, ::fcntl(p[0], F_GETFL) | O_NONBLOCK);
  return {p[0], p[1]};
}

fs::path private_dir() {
  std::string tmpl = (fs::temp_directory_path() / "rk-dbg-XXXXXX").string();
  if (::mkdtemp(tmpl.data()) == nullptr) throw DebugError(std::string("mkdtemp: ") + std::strerror(errno));
  return tmpl;
}

// Waits for a Unix socket the child creates, and connects.
std::unique_ptr<Transport> connect_when_ready(const fs::path &sock, const std::shared_ptr<ChildProcess> &child,
                                              std::chrono::milliseconds timeout) {
  const auto end = Clock::now() + timeout;
  std::string last;
  while (Clock::now() < end) {
    int st = 0;
    if (::waitpid(child->pid, &st, WNOHANG) == child->pid) {
      child->pid = -1;
      throw DebugError(child->what + " exited before it could be debugged: " + child->drain());
    }
    if (fs::exists(sock)) {
      try {
        return connect_unix(sock.string(), std::chrono::milliseconds(1000));
      } catch (const DebugError &e) {
        last = e.what();
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  throw DebugError(child->what + " did not open its gdbstub" + (last.empty() ? "" : ": " + last));
}

}  // namespace

Launched launch(const LaunchOptions &o) {
  Launched out;
  auto child = std::make_shared<ChildProcess>();
  const ElfHead elf = o.attach_pid ? ElfHead{} : read_elf_head(o.program);
  if (!o.attach_pid && !fs::exists(o.program)) throw DebugError("no program at " + o.program.string());
  std::string qemu = o.qemu;
  if (qemu.empty() && elf.ok && elf.machine != host_machine()) {
    qemu = qemu_user_for_machine(elf.machine, elf.big_endian);
    if (qemu.empty())
      throw DebugError("the program is for ELF machine " + std::to_string(elf.machine) +
                       ", which this host can't run (no qemu-user for it)");
  }
  if (!qemu.empty()) {
    if (o.attach_pid) throw DebugError("attaching runs gdbserver, not qemu-user");
    const std::string exe = find_program(qemu);
    if (exe.empty())
      throw DebugError(qemu + " is not installed: install qemu-user (Debian/Ubuntu: apt install qemu-user) to run " +
                       o.program.filename().string() + " on this host");
    const fs::path dir = private_dir();
    child->cleanup_dir = dir;
    const fs::path sock = dir / "gdb.sock";
    std::vector<std::string> argv{exe, "-g", sock.string()};
    const std::string root = !o.sysroot.empty() ? o.sysroot.string() : sysroot_for(elf.machine);
    if (!root.empty()) {
      argv.push_back("-L");
      argv.push_back(root);
    }
    argv.push_back(o.program.string());
    for (const std::string &a : o.args) argv.push_back(a);
    auto [rd, wr] = output_pipe();
    const int in = devnull();
    try {
      child->pid = spawn(argv, o.env, in, wr, wr, o.working_dir);
    } catch (...) {
      ::close(rd);
      ::close(wr);
      ::close(in);
      throw;
    }
    ::close(wr);
    ::close(in);
    child->output_fd = rd;
    child->what = qemu;
    out.transport = connect_when_ready(sock, child, o.timeout);
    out.description = qemu + " " + o.program.filename().string();
    out.child = child;
    return out;
  }
  const std::string gdbserver = find_program(o.gdbserver);
  if (gdbserver.empty())
    throw DebugError("gdbserver is not installed: install it (Debian/Ubuntu: apt install gdbserver) to debug live "
                     "processes, or connect to a gdbserver elsewhere");
  if (o.attach_pid && ptrace_scope() >= 2)
    throw DebugError("kernel.yama.ptrace_scope is " + std::to_string(ptrace_scope()) +
                     ": attaching needs CAP_SYS_PTRACE (scope 2) or is disabled (scope 3); set it to 0 or 1 "
                     "(sysctl kernel.yama.ptrace_scope=1)");
  int sv[2];
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
    throw DebugError(std::string("socketpair: ") + std::strerror(errno));
  std::vector<std::string> argv{gdbserver, "--once"};
  if (o.attach_pid) {
    argv.push_back("--attach");
    argv.push_back("-");
    argv.push_back(std::to_string(*o.attach_pid));
  } else {
    argv.push_back("-");
    argv.push_back(o.program.string());
    for (const std::string &a : o.args) argv.push_back(a);
  }
  auto [rd, wr] = output_pipe();
  try {
    // stdio is the protocol; the program's output goes to gdbserver's stderr.
    child->pid = spawn(argv, o.env, sv[1], sv[1], wr, o.working_dir);
  } catch (...) {
    ::close(sv[0]);
    ::close(sv[1]);
    ::close(rd);
    ::close(wr);
    throw;
  }
  ::close(sv[1]);
  ::close(wr);
  child->output_fd = rd;
  child->what = "gdbserver";
  out.transport = std::make_unique<FdTransport>(sv[0], sv[0], "gdbserver (stdio)");
  out.description = o.attach_pid ? "gdbserver --attach " + std::to_string(*o.attach_pid)
                                 : "gdbserver " + o.program.filename().string();
  out.child = child;
  return out;
}

Launched launch_qemu_system(const std::string &qemu, const std::vector<std::string> &args, std::chrono::milliseconds timeout) {
  const std::string exe = find_program(qemu);
  if (exe.empty())
    throw DebugError(qemu + " is not installed: install qemu-system (Debian/Ubuntu: apt install qemu-system-arm, ...)");
  auto child = std::make_shared<ChildProcess>();
  const fs::path dir = private_dir();
  child->cleanup_dir = dir;
  const fs::path sock = dir / "gdb.sock";
  std::vector<std::string> argv{exe};
  for (const std::string &a : args) argv.push_back(a);
  for (const char *a : {"-nographic", "-monitor", "none", "-S"}) argv.emplace_back(a);
  argv.push_back("-gdb");
  argv.push_back("unix:" + sock.string() + ",server=on,wait=off");
  auto [rd, wr] = output_pipe();
  const int in = devnull();
  try {
    child->pid = spawn(argv, {}, in, wr, wr, {});
  } catch (...) {
    ::close(rd);
    ::close(wr);
    ::close(in);
    throw;
  }
  ::close(wr);
  ::close(in);
  child->output_fd = rd;
  child->what = qemu;
  Launched out;
  out.transport = connect_when_ready(sock, child, timeout);
  out.description = qemu;
  out.child = child;
  return out;
}

}  // namespace revkit::debug
