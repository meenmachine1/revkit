// A debug target: something that runs machine code and can be stopped,
// inspected and resumed. The p-code emulator is one (EmulatorTarget), a
// live process or board behind a GDB remote stub another (GdbRemoteTarget);
// a Session (session.hh) drives either the same way. See docs/debugger.md.
//
// Addresses here are the target's own (runtime) addresses. Session maps them
// to the program's static image.
#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::debug {

// A request the target can't honour (an unknown register, a lost
// connection, a stub that refuses). Why execution stopped is a Stop.
class DebugError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Why execution stopped. The first block mirrors revkit::emu::StopKind (in
// the same order); the rest come from live targets.
enum class StopKind : std::uint8_t {
  none,
  stepped,
  step_limit,
  breakpoint,
  until,
  returned,
  exited,         // the process exited normally; Stop::exit_code
  halted,
  unmapped,
  protection,
  decode,
  unimplemented,
  userop,
  syscall,
  watchpoint,     // Stop::address is the watched address hit
  hook,
  divide_by_zero,
  memory_limit,
  time_limit,     // the call's deadline (the emulator stops; a live target keeps running: `running`)
  cancelled,
  // Live targets.
  signal,         // a signal other than the debugger's own traps; Stop::signal
  interrupted,    // interrupt() stopped it
  running,        // the deadline passed and the target is still running
  killed,         // terminated by a signal (gdb's X); Stop::signal
  detached,
  disconnected,   // the connection to the stub was lost
  // The emulator with a machine (after the live kinds, so saved traces keep their numbers).
  exception,      // an exception breakpoint: the CPU took an exception of a kind asked for
  idle,           // waiting for an interrupt with nothing scheduled to raise one
};
std::string_view to_string(StopKind kind);
std::optional<StopKind> stop_kind(std::string_view name);

struct Stop {
  StopKind kind = StopKind::none;
  std::uint64_t pc = 0;
  std::optional<std::uint64_t> address;  // faulting or watched address
  std::string detail;
  std::int64_t exit_code = 0;
  std::uint64_t steps = 0;  // emulator: instructions executed by the call
  int signal = 0;           // POSIX signal number (signal, killed)
  std::string thread;       // the thread that stopped, if the target has threads
};

// A register as the target presents it.
struct RegisterDesc {
  // The name clients use: the SLEIGH register of the program's language
  // when the target's register maps onto one ("RAX", "x0"), else the
  // target's own name.
  std::string name;
  std::string target_name;  // the stub's name ("rax", "cpsr"); the emulator's: = name
  std::uint32_t size = 0;   // bytes
  std::string sleigh;       // the SLEIGH register it maps to, empty if none
  std::string group;        // "general", "float", "vector", "system", "flags" ...
  bool display = false;     // one of the registers a debugger shows by default
  // A flag bit of another register (x86 CF in eflags, ARM NG in cpsr),
  // exposed as a one-byte register so live targets show what the emulator
  // shows.
  std::string parent;
  int bit = -1;
};

struct ThreadInfo {
  std::string id;      // the target's thread id ("p1234.1235", "1")
  std::string name;
  bool current = false;
  std::optional<std::uint64_t> pc;
  int core = -1;
};

// A loaded module (the main program, a shared library, the dynamic linker).
struct ModuleInfo {
  std::string name;  // file name
  std::string path;
  std::uint64_t base = 0;       // lowest mapped address, when known
  std::uint64_t load_bias = 0;  // ELF l_addr: runtime address minus link-time address
  std::uint64_t size = 0;       // 0: unknown
  bool main = false;            // the executable
};

struct MapRegion {
  std::uint64_t start = 0;
  std::uint64_t size = 0;
  std::string perms;  // "rwx", "r-x", "r--p" style trimmed to rwx
  std::string name;   // a path, "[stack]", or a region name
  std::uint64_t offset = 0;
  std::string kind;   // "image", "ram", "mmio", "stub", "file", "anon", "flash", "rom"
};

enum class BreakKind : std::uint8_t { software, hardware, watch_write, watch_read, watch_access };
std::string_view to_string(BreakKind kind);

enum class RunMode : std::uint8_t { run, step_into, step_over, step_out };

struct ResumeOptions {
  RunMode mode = RunMode::run;
  std::uint64_t max_steps = 1000000;  // the emulator's budget
  std::optional<std::uint64_t> until;
  std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max();
  std::function<bool()> cancelled;
};

enum class TargetState : std::uint8_t { stopped, running, exited, detached, disconnected, replay };
std::string_view to_string(TargetState state);

// Memory a target can't read, as [offset, offset+length) of a request.
struct ByteRange {
  std::uint32_t offset = 0;
  std::uint32_t length = 0;
};

// One recorded step of an emulated run between two stops (the emulator's
// trace): what a Session turns into instruction snapshots.
struct StepRecord {
  std::uint64_t index = 0;  // steps executed before it
  std::uint64_t pc = 0;
  std::string text;
  std::string event;
  // Firmware: the exception it entered ("irq", ...) or "return"; empty otherwise.
  std::string exception;
  std::int32_t exception_number = -1;
  std::vector<std::pair<std::string, std::vector<std::uint8_t>>> registers;  // written, by name
  struct Access {
    std::uint64_t address = 0;
    std::vector<std::uint8_t> bytes, before;  // before: writes only
    bool write = false;
  };
  std::vector<Access> memory;
};

class Target {
 public:
  virtual ~Target() = default;

  virtual std::string kind() const = 0;         // "emulator", "gdb-remote"
  virtual std::string description() const = 0;  // what it is connected to
  virtual std::string language() const = 0;     // the SLEIGH language its registers map onto
  virtual unsigned pointer_size() const = 0;
  virtual bool big_endian() const = 0;
  virtual bool stack_grows_down() const { return true; }
  // True when every memory change is recorded (the emulator): then a
  // byte's value at any recorded stop is known exactly.
  virtual bool complete_recording() const { return false; }

  // --- Registers (values least significant byte first) ---
  virtual const std::vector<RegisterDesc> &registers() const = 0;
  virtual std::string pc_register() const = 0;
  virtual std::string sp_register() const = 0;
  // Case-insensitive by name or target name; throws DebugError.
  virtual std::vector<std::uint8_t> read_register(std::string_view name) = 0;
  virtual void write_register(std::string_view name, std::span<const std::uint8_t> value) = 0;
  std::uint64_t read_register_u64(std::string_view name);
  void write_register_u64(std::string_view name, std::uint64_t value);
  const RegisterDesc *find_register(std::string_view name) const;
  std::uint64_t pc() { return read_register_u64(pc_register()); }
  std::uint64_t sp() { return read_register_u64(sp_register()); }

  // --- Memory ---
  // Fills `out`; bytes that can't be read are zero and listed in
  // `unreadable` (if given). Returns the number of bytes read.
  virtual std::size_t read_memory(std::uint64_t address, std::span<std::uint8_t> out,
                                  std::vector<ByteRange> *unreadable = nullptr) = 0;
  virtual bool write_memory(std::uint64_t address, std::span<const std::uint8_t> bytes) = 0;

  // --- Execution ---
  // Runs as asked until a stop or the deadline. The emulator stops at the
  // deadline (time_limit); a live target keeps running and the result is
  // `running`: wait() for it, or interrupt() it.
  virtual Stop resume(const ResumeOptions &options) = 0;
  // While running: the stop, or `running` again at the deadline.
  virtual Stop wait(std::chrono::steady_clock::time_point deadline) = 0;
  // Asks a running target to stop (thread-safe; returns at once).
  virtual void interrupt() = 0;
  // step_over and step_out natively (the emulator); otherwise Session
  // builds them from single steps and temporary breakpoints.
  virtual bool native_step_over() const { return false; }
  virtual TargetState state() const = 0;
  virtual const Stop &last_stop() const = 0;
  virtual std::uint64_t steps() const { return 0; }

  // --- Breakpoints and watchpoints (at runtime addresses) ---
  // Throws DebugError when the target refuses.
  virtual void insert_breakpoint(BreakKind kind, std::uint64_t address, std::uint32_t size) = 0;
  virtual void remove_breakpoint(BreakKind kind, std::uint64_t address, std::uint32_t size) = 0;
  // The size of a software breakpoint at `address` (ARM: 2 in Thumb, else 4).
  virtual std::uint32_t breakpoint_size(std::uint64_t /*address*/) { return 0; }

  // --- Threads, modules, memory map ---
  virtual std::vector<ThreadInfo> threads() = 0;
  virtual void select_thread(const std::string &id) = 0;
  virtual std::string current_thread() const = 0;
  virtual std::vector<ModuleInfo> modules() = 0;
  virtual std::vector<MapRegion> memory_map() = 0;
  // The ELF auxiliary vector (AT_ENTRY, AT_PHDR, ...), where the target has one.
  virtual std::map<std::uint64_t, std::uint64_t> auxv() { return {}; }
  virtual std::optional<std::int64_t> process_id() const { return std::nullopt; }

  // --- Lifetime ---
  virtual void detach() = 0;
  virtual void kill() = 0;
  // Output the program wrote since the last call (stdout and stderr; live
  // targets launched by revkit, console output from a stub).
  virtual std::string take_output() { return {}; }

  // The emulator: the steps executed since the last call, for
  // instruction-level recording. Others: nothing.
  virtual std::vector<StepRecord> take_steps() { return {}; }
  // The ARM/Thumb state at the pc (decoding a live target's instructions).
  virtual bool thumb() { return false; }
};

// Little-endian bytes to an integer (the low 8 bytes) and back.
std::uint64_t to_u64(std::span<const std::uint8_t> le);
std::vector<std::uint8_t> from_u64(std::uint64_t v, std::size_t size);
std::string hex(std::uint64_t v);

}  // namespace revkit::debug
