// A live target behind a GDB remote stub: gdbserver (Linux processes),
// QEMU's gdbstub (qemu-user and qemu-system, bare-metal firmware), OpenOCD
// and J-Link GDB servers (boards). The client side of the remote serial
// protocol, written here (rsp.hh): target descriptions (qXfer:features),
// registers mapped onto the program's SLEIGH registers, memory, Z0-Z4
// breakpoints and watchpoints, vCont, stop replies, threads, libraries,
// the auxiliary vector and memory maps. See docs/debugger.md.
#pragma once

#include "revkit/debug/rsp.hh"
#include "revkit/debug/target.hh"

#include <atomic>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace revkit::debug {

// A register of the program's language, for mapping a stub's onto.
struct SleighRegister {
  std::string name;
  std::uint32_t size = 0;
};

// The SLEIGH register (of `sleigh`) a stub register maps onto, or "" if
// none: explicit aliases per processor (x86-64 eflags -> rflags, fs_base ->
// FS_OFFSET, AArch64 v0 -> q0), then the same name ignoring case.
std::string map_register_name(const std::string &language, const std::string &stub_name, std::uint32_t size,
                              const std::vector<SleighRegister> &sleigh);

// A launched helper process (gdbserver, qemu): reaped and, unless it
// already exited, killed when the target goes away.
struct ChildProcess {
  int pid = -1;
  int output_fd = -1;  // its stdout and stderr (the debugged program's output), non-blocking
  std::string what;    // "gdbserver", "qemu-aarch64", ...
  std::filesystem::path cleanup_dir;  // removed after it exits
  ~ChildProcess();
  // Output read so far that isn't the helper's own chatter.
  std::string drain();
  std::string pending;
};

struct GdbRemoteOptions {
  // The program's language (SLEIGH id): registers map onto its registers,
  // and it is the target's language.
  std::string language;
  std::vector<SleighRegister> sleigh_registers;
  unsigned pointer_size = 8;
  bool big_endian = false;
  std::chrono::milliseconds timeout{5000};
  // Deliver signals the program got (SIGSEGV, ...) when it resumes, as gdb
  // does; SIGTRAP and SIGINT never are.
  bool pass_signals = true;
  // Extended remote (gdbserver --multi): attach to this process.
  std::optional<std::int64_t> attach_pid;
  std::string description;  // what to call the connection
  std::shared_ptr<ChildProcess> child;  // a helper this target owns
};

class GdbRemoteTarget : public Target {
 public:
  // Connects: qSupported, no-ack mode, the target description, the
  // initial stop. Throws DebugError.
  GdbRemoteTarget(std::unique_ptr<Transport> transport, GdbRemoteOptions options);
  ~GdbRemoteTarget() override;

  std::string kind() const override { return "gdb-remote"; }
  std::string description() const override;
  std::string language() const override { return options_.language; }
  unsigned pointer_size() const override { return options_.pointer_size; }
  bool big_endian() const override { return options_.big_endian; }

  const std::vector<RegisterDesc> &registers() const override { return regs_; }
  std::string pc_register() const override { return pc_name_; }
  std::string sp_register() const override { return sp_name_; }
  std::vector<std::uint8_t> read_register(std::string_view name) override;
  void write_register(std::string_view name, std::span<const std::uint8_t> value) override;

  std::size_t read_memory(std::uint64_t address, std::span<std::uint8_t> out,
                          std::vector<ByteRange> *unreadable = nullptr) override;
  bool write_memory(std::uint64_t address, std::span<const std::uint8_t> bytes) override;

  Stop resume(const ResumeOptions &options) override;
  Stop wait(Clock::time_point deadline) override;
  void interrupt() override;
  TargetState state() const override { return state_; }
  const Stop &last_stop() const override { return last_stop_; }
  std::uint64_t steps() const override { return stops_; }

  void insert_breakpoint(BreakKind kind, std::uint64_t address, std::uint32_t size) override;
  void remove_breakpoint(BreakKind kind, std::uint64_t address, std::uint32_t size) override;
  std::uint32_t breakpoint_size(std::uint64_t address) override;

  std::vector<ThreadInfo> threads() override;
  void select_thread(const std::string &id) override;
  std::string current_thread() const override { return thread_; }
  std::vector<ModuleInfo> modules() override;
  std::vector<MapRegion> memory_map() override;
  std::map<std::uint64_t, std::uint64_t> auxv() override;
  std::optional<std::int64_t> process_id() const override { return pid_; }

  void detach() override;
  void kill() override;
  std::string take_output() override;
  bool thumb() override;

  // --- For tests and tools ---
  const std::map<std::string, std::string> &stub_features() const { return features_; }
  const std::string &architecture() const { return arch_; }
  RspClient &rsp() { return *rsp_; }
  // The stub's target description, as read (empty when it had none).
  const std::string &target_xml() const { return target_xml_; }
  std::string exec_file();
  // qXfer:<object>:read:<annex> in full; nullopt if unsupported.
  std::optional<std::string> xfer(const std::string &object, const std::string &annex = "");
  // A monitor command (qRcmd): its output.
  std::string monitor(const std::string &command);

 private:
  struct RegInfo {
    int regnum = -1;
    std::uint32_t bits = 0;
    std::optional<std::size_t> g_offset;  // in the 'g' packet, bytes
  };

  void handshake();
  void read_description();
  void builtin_description();
  void finish_registers();
  Stop parse_stop(const std::string &packet, bool stepping);
  Stop wait_stop(Clock::time_point deadline, bool stepping);
  void ensure_thread();
  std::vector<std::uint8_t> fetch(std::size_t index);
  void load_g();
  void invalidate();
  std::string resume_packet(bool step, int signal);
  std::optional<std::string> vfile_read(const std::string &path);
  std::size_t read_chunk(std::uint64_t address, std::uint8_t *out, std::size_t len);
  std::string thread_arg(const std::string &id) const;
  const RegisterDesc &desc(std::string_view name) const;

  GdbRemoteOptions options_;
  std::unique_ptr<RspClient> rsp_;
  std::map<std::string, std::string> features_;
  std::string arch_;
  std::string target_xml_;
  std::size_t packet_size_ = 4096;
  bool vcont_ = false;
  std::set<char> vcont_actions_;
  bool multiprocess_ = false;
  std::optional<bool> x_packet_;     // binary memory writes
  std::optional<bool> p_packet_;     // single register reads
  std::optional<bool> P_packet_;     // single register writes
  std::vector<RegisterDesc> regs_;
  std::vector<RegInfo> info_;        // parallel to regs_ (derived flags: regnum -1)
  std::map<std::string, std::size_t> by_name_;  // lower-cased name and target name -> index
  std::string pc_name_, sp_name_;
  std::map<int, std::vector<std::uint8_t>> cache_;  // regnum -> target-order bytes, this stop
  bool g_loaded_ = false;
  TargetState state_ = TargetState::stopped;
  Stop last_stop_;
  bool stepping_ = false;
  std::atomic<bool> interrupt_sent_{false};
  std::string thread_;     // selected thread
  std::string hg_thread_;  // the thread the stub reads registers of
  std::optional<std::int64_t> pid_;
  std::uint64_t stops_ = 0;
  std::string output_;
  std::set<std::pair<std::uint64_t, int>> breakpoints_;  // (address, Z type) we inserted
  std::optional<std::vector<ModuleInfo>> modules_;  // this stop's
  std::optional<std::map<std::uint64_t, std::uint64_t>> auxv_;
};

// --- Launching ---

struct LaunchOptions {
  std::filesystem::path program;  // the executable to run
  std::vector<std::string> args;  // after argv[0]
  std::vector<std::string> env;   // NAME=value added to the environment
  std::filesystem::path working_dir;
  // Run it under qemu-user (a foreign architecture) instead of gdbserver:
  // "qemu-aarch64", ... Empty: gdbserver, unless the program's machine
  // isn't the host's (then qemu-<arch> when found).
  std::string qemu;
  std::filesystem::path sysroot;  // qemu-user's -L (default /usr/<triple> when it exists)
  std::string gdbserver = "gdbserver";
  // Attach to a running process instead of starting one (gdbserver --attach).
  std::optional<std::int64_t> attach_pid;
  std::chrono::milliseconds timeout{10000};
};

struct Launched {
  std::unique_ptr<Transport> transport;
  std::shared_ptr<ChildProcess> child;
  std::string description;
};

// Starts the program stopped at its first instruction under gdbserver
// (over a socketpair: no port is opened) or qemu-user (a Unix socket in a
// private directory). Throws DebugError, with what to install or change
// when the host can't (no gdbserver, ptrace_scope forbidding an attach).
Launched launch(const LaunchOptions &options);

// Starts qemu-system-<arch> with the gdbstub on a private Unix socket,
// halted: for bare-metal firmware. `args` are the machine options
// ("-M", "none", "-cpu", "arm926", "-m", "1G", "-device", "loader,...").
Launched launch_qemu_system(const std::string &qemu, const std::vector<std::string> &args,
                            std::chrono::milliseconds timeout = std::chrono::milliseconds(10000));

// The qemu-user binary for an ELF machine (e_machine), e.g. "qemu-aarch64".
std::string qemu_user_for_machine(std::uint32_t machine, bool big_endian);
// e_machine of the host, for deciding between gdbserver and qemu-user.
std::uint32_t host_machine();
// /proc/sys/kernel/yama/ptrace_scope, or -1 when there is none.
int ptrace_scope();
// What to change when attaching was refused ("" if ptrace_scope allows it).
std::string attach_hint();
// The executable `name` on PATH (or `name` if it has a slash), or "".
std::string find_program(const std::string &name);

}  // namespace revkit::debug
