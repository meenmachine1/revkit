// Running an untrusted program (an external decompiler parsing hostile
// input) as a confined child process: docs/providers.md "The sandbox" and
// docs/security.md "External decompilers".
//
// The parent (`run_sandboxed`) starts `rk-sandbox`, which confines itself
// and then executes the tool, so nothing is forked from the daemon's
// threads and the confinement is applied by a single-threaded process:
//
//   - resource limits: data segment (memory), address space where the
//     tool allows it, CPU time, the size of any one file written, open
//     files, no core dumps;
//   - a session and process group of its own, killed as a whole at the
//     deadline, and SIGKILL when the parent thread goes away;
//   - Landlock: read and execute only below the paths named (system
//     directories, the tool and its runtime, the input), read and write
//     only below the scratch directories; TCP bind and connect refused;
//     abstract Unix sockets and signals scoped to the sandbox;
//   - seccomp: no sockets but socketpairs, no connect, no new
//     namespaces, keyrings, io_uring, BPF, perf, ptrace, mounts, sessions
//     or process groups, and only the native system call ABI;
//   - a network namespace of its own where unprivileged user namespaces
//     work (not under Ubuntu's AppArmor restriction);
//   - no_new_privs, a cleaned environment, stdin from /dev/null, every
//     other descriptor closed.
#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace revkit::providers {

// What this kernel lets an unprivileged process enforce on itself.
struct SandboxSupport {
  int landlock_abi = 0;        // 0: none
  bool landlock_net = false;   // ABI 4: TCP bind and connect
  bool landlock_scope = false; // ABI 6: abstract Unix sockets and signals
  bool seccomp = false;
  bool netns = false;          // a user and network namespace with the uid mapped
  std::string error;           // why the helper couldn't be asked
  // "landlock 6 (files, TCP, scoped), seccomp, no network namespace"
  std::string describe() const;
};

struct SandboxLimits {
  std::chrono::milliseconds timeout{120'000};  // wall clock; SIGKILL to the group
  std::uint64_t memory_bytes = 4ull << 30;     // RLIMIT_DATA
  std::uint64_t address_space_bytes = 0;       // RLIMIT_AS; 0: unlimited (JVM and .NET reserve far more than they use)
  std::uint64_t cpu_seconds = 0;               // RLIMIT_CPU; 0: 4 x the timeout
  std::uint64_t output_bytes = 256ull << 20;   // the output directory and stdout together; also RLIMIT_FSIZE
  std::uint64_t output_files = 50'000;         // files and directories under the output directory
  std::uint64_t open_files = 1024;             // RLIMIT_NOFILE
};

struct SandboxSpec {
  std::vector<std::string> argv;               // argv[0] an absolute path
  std::vector<std::string> env;                // "NAME=value"; nothing else is passed
  std::vector<std::filesystem::path> read_paths;   // read and execute below (files or directories)
  std::vector<std::filesystem::path> write_paths;  // read, write, create and remove below
  std::filesystem::path cwd;
  std::filesystem::path stdout_file;           // created; empty: /dev/null
  std::filesystem::path stderr_file;           // created; empty: /dev/null
  std::filesystem::path output_dir;            // watched for the output cap; may be empty
  SandboxLimits limits;
  bool allow_weak = false;                     // run without Landlock where the kernel lacks it
  std::function<bool()> cancelled;             // polled; true kills the run
};

enum class RunStatus {
  ok,            // exited 0
  failed,        // exited non-zero
  crashed,       // a signal (SIGSEGV, SIGABRT, ...)
  timeout,       // killed at the deadline, or over its CPU time
  out_of_memory, // over the memory limit (as the runtime reports it, or killed by the kernel)
  output_limit,  // wrote more than the output cap
  cancelled,     // the caller went away
  sandbox_error, // the helper couldn't confine itself (or start the tool)
};
const char *status_name(RunStatus s);

struct RunOutcome {
  RunStatus status = RunStatus::sandbox_error;
  int exit_code = -1;
  int signal = 0;
  std::string detail;       // "exit status 2", "SIGSEGV", "killed after 120 s", ...
  std::string stderr_tail;  // the last 4 KiB
  double seconds = 0;
};

// The rk-sandbox helper: $REVKIT_SANDBOX, beside this executable, or the
// build's. Empty when none is found.
std::string find_helper();
void set_helper_for_tests(std::string path);

// What the helper reports this kernel enforces (cached after the first
// call per helper path).
SandboxSupport probe_support();

RunOutcome run_sandboxed(const SandboxSpec &spec);

// --- the helper's side (rk-sandbox) --------------------------------------

struct ConfineOptions {
  std::vector<std::string> read_paths, write_paths;
  std::string cwd;
  std::uint64_t memory = 0, address_space = 0, cpu = 0, file_size = 0, open_files = 0;
  bool allow_weak = false;
};
// Confines the calling (single-threaded) process; returns "" or why not.
std::string confine_self(const ConfineOptions &o);
// Probes in a child process what the kernel supports.
SandboxSupport probe_self();

}  // namespace revkit::providers
