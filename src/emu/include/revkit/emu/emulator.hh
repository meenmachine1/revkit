// A p-code emulator: runs a loaded image's machine code, for any SLEIGH
// language, by interpreting the raw p-code revkit::lift decodes. See
// docs/emulator.md.
//
// The emulator's state (registers, memory written, breakpoints, the trace)
// is the user's session state, never a fact about the binary: nothing here
// touches the fact store.
#pragma once

#include "revkit/emu/trace.hh"
#include "revkit/loader/image.hh"

#include <array>
#include <chrono>
#include <deque>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::emu {

// A request the emulator can't honour: an unknown register, an overlapping
// mapping, an unknown language. Execution problems are Stops, not errors.
class EmuError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

enum class Os : std::uint8_t { none, linux };

// How start() prepares the machine.
enum class StartMode : std::uint8_t {
  automatic,  // process at an ELF's entry point on Linux, else call
  process,    // a Linux process: stack with argc, argv, envp and auxv
  call,       // a call: a stack, and a return address that stops the run (StopKind::returned)
  bare,       // only the program counter (firmware: the reset handler sets up its own stack)
};

enum class StopKind : std::uint8_t {
  none,            // nothing has run yet
  stepped,         // a step, step over or step out finished
  step_limit,      // the run's step budget is spent
  breakpoint,      // reached a breakpoint
  until,           // reached the run's `until` address
  returned,        // the call start() set up returned
  exited,          // exit syscall or an exit stub; Stop::exit_code
  halted,          // a halt instruction, or one that branches to itself without changing anything
  unmapped,        // fetch, read or write of unmapped memory; Stop::address
  protection,      // write to read-only or fetch from non-executable memory
  decode,          // the bytes at pc don't decode
  unimplemented,   // an instruction without semantics, or an op or size the emulator lacks
  userop,          // CALLOTHER with no handler
  syscall,         // a system call with no handler
  watchpoint,      // a watched address was read or written; Stop::address
  hook,            // a hook asked to stop
  divide_by_zero,
  memory_limit,    // the session's memory bound
  time_limit,      // the run's deadline
  cancelled,
  // Firmware (a machine attached).
  exception,       // an exception breakpoint: the CPU took an exception of a kind asked for
  idle,            // waiting for an interrupt (WFI, or a branch to itself) with nothing scheduled to raise one
};
std::string_view to_string(StopKind kind);
// The inverse of to_string; nullopt for an unknown name.
std::optional<StopKind> stop_kind(std::string_view name);

struct Stop {
  StopKind kind = StopKind::none;
  std::uint64_t pc = 0;  // where execution stands (the next instruction)
  std::optional<std::uint64_t> address;  // faulting or watched address
  std::string detail;
  std::int64_t exit_code = 0;
  std::uint64_t steps = 0;  // executed by the call that stopped
};

struct RegisterInfo {
  std::string name;
  std::uint64_t offset = 0;
  std::uint32_t size = 0;
};

struct RegionInfo {
  enum class Kind : std::uint8_t { image, ram, mmio, stub };
  std::string name;
  std::uint64_t start = 0;
  std::uint64_t size = 0;
  loader::Perms perms;
  Kind kind = Kind::image;
};

// What a skipped import call needs to know of its callee.
struct ImportPrototype {
  bool returns_value = true;
  std::uint32_t parameters = 0;   // integer-sized parameters
  bool varargs = false;
  bool callee_pops = false;       // stdcall: the callee pops its stack parameters
};

struct Options {
  // Ghidra language id, "proc:endian:size:variant[:compiler]"; empty: from
  // the image (loader::guess_language).
  std::string language;
  // Bytes laid over the image's, in order (later ones win): the program's
  // patches (docs/patching.md), so a session runs the patched program.
  std::vector<std::pair<std::uint64_t, std::string>> patches;
  std::optional<Os> os;            // default: Linux for ELF, none otherwise
  // Bytes of state the session may allocate: written pages, registers,
  // temporaries. Mapped but untouched memory costs nothing.
  std::uint64_t max_memory = 256ull << 20;
  std::size_t trace_capacity = 4096;   // steps kept (the summary counts all); 0: none
  bool trace_memory = true;            // record reads and writes in the trace
  // Writes to read-only memory and fetches from non-executable memory stop.
  // Never enforced on raw images, whose code often runs from RAM.
  bool enforce_permissions = true;
  std::uint64_t import_return = 0;     // what a skipped import call returns
  bool library_stubs = true;           // built-in stubs for common C library calls
  bool unknown_syscalls_fail = false;  // true: unhandled syscalls return -ENOSYS instead of stopping
  std::vector<std::string> argv{"prog"};
  std::vector<std::string> envp;
  std::string stdin_data;              // what read(0, ...) returns
  std::size_t mmio_log_capacity = 4096;
  // The prototype of an import by name, where known.
  std::function<std::optional<ImportPrototype>(std::string_view)> prototypes;
  // Emulating from a debugger's state (docs/emulator.md "Lazy memory"):
  // memory nothing wrote yet is read from `read` (a live process, a
  // recorded snapshot) the first time it is touched, a page at a time, then
  // copied on write; `regions` replace the image's segments, and no
  // imports are bound (the process bound its own).
  struct Backing {
    // Bytes at an address; returns how many it could read from the start
    // (the rest of the page reads as zero).
    std::function<std::size_t(std::uint64_t address, std::span<std::uint8_t> out)> read;
    std::vector<RegionInfo> regions;
  };
  std::optional<Backing> backing;
};

struct RunOptions {
  std::uint64_t max_steps = 1000000;
  std::optional<std::uint64_t> until;
  std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max();
  std::function<bool()> cancelled;
};

enum class HookAction : std::uint8_t { proceed, stop };

// A CALLOTHER the program executes.
class Machine;
struct CheckpointState;

// The emulator's whole state at one moment (Emulator::checkpoint): registers,
// memory (copy-on-write pages, so cheap to keep), the mapped regions, the
// process state (program break, heap, input read, output written), the step
// count. Restoring it rewinds the emulator (docs/emulator.md "Checkpoints").
class Checkpoint {
 public:
  Checkpoint() = default;
  bool valid() const { return state_ != nullptr; }
  std::uint64_t steps() const;
  std::uint64_t pc() const;

 private:
  friend class Emulator;
  std::shared_ptr<const CheckpointState> state_;
};
struct MachineSpec;
struct MachineOptions;

struct UseropCall {
  std::string name;
  std::uint32_t index = 0;
  std::vector<std::uint64_t> inputs;   // after the op index (wider values truncated)
  std::uint32_t output_size = 0;       // 0: no output
  std::optional<std::uint64_t> output; // set to write the output
  std::string note;                    // for the trace, or why the hook stopped
};

struct Syscall {
  std::uint64_t number = 0;
  std::array<std::uint64_t, 6> args{};
  std::uint64_t result = 0;  // written to the return register on proceed
  bool exited = false;       // the program exits with exit_code
  std::int64_t exit_code = 0;
  std::string note;
};

struct MmioAccess {
  std::uint64_t pc = 0;
  std::uint64_t address = 0;
  std::uint32_t size = 0;
  bool write = false;
  std::uint64_t value = 0;  // written, or read (a hook may set it for a read)
  std::uint64_t step = 0;
  // A hook sets this to stop before the instruction (it is undone), with `note`.
  bool stop = false;
  std::string note;
};

// A call to a stubbed function (an import, or an address given a stub).
struct StubCall {
  std::string name;
  std::uint64_t address = 0;
  std::uint64_t return_value = 0;
  bool returns_value = true;
  std::uint32_t stack_pop = 0;          // bytes the callee pops beyond the return address
  bool exited = false;                  // the program exits instead of returning
  std::int64_t exit_code = 0;
  std::optional<std::uint64_t> jump_to; // continue there instead of returning (the stub set up a call)
  std::string note;
};

class Emulator {
 public:
  using UseropHandler = std::function<HookAction(Emulator &, UseropCall &)>;
  using SyscallHandler = std::function<HookAction(Emulator &, Syscall &)>;
  using MmioHandler = std::function<void(Emulator &, MmioAccess &)>;
  using StubHandler = std::function<HookAction(Emulator &, StubCall &)>;

  // revkit::lift::initialize() must have been called. Throws EmuError (or
  // lift::LiftError) when the language is unknown or unusable.
  Emulator(std::shared_ptr<const loader::Image> image, Options options = {});
  ~Emulator();
  Emulator(const Emulator &) = delete;
  Emulator &operator=(const Emulator &) = delete;

  const std::string &language() const;
  const Options &options() const;
  Os os() const;
  const loader::Image &image() const;
  unsigned pointer_size() const;
  bool big_endian() const;

  // --- Setup ---
  void start(std::uint64_t entry, StartMode mode = StartMode::automatic, std::span<const std::uint64_t> args = {});
  // The address a call made by start() returns to.
  std::optional<std::uint64_t> return_trap() const;
  // Where an import's calls go (nullopt: not an import the emulator saw).
  std::optional<std::uint64_t> import_address(std::string_view name) const;

  // --- Registers ---
  std::uint64_t pc() const;
  void set_pc(std::uint64_t pc);
  bool thumb() const;  // ARM: executing Thumb code
  void set_thumb(bool thumb);
  const std::vector<RegisterInfo> &registers() const;  // every register the language names
  // The registers worth showing: general purpose, stack, pc, flags.
  const std::vector<std::string> &display_registers() const;
  const std::string &pc_register() const;
  const std::string &sp_register() const;
  // Case-insensitive. nullopt for an unknown name.
  std::optional<RegisterInfo> find_register(std::string_view name) const;
  // Values least significant byte first. Throw EmuError for unknown names.
  std::vector<std::uint8_t> read_register_bytes(std::string_view name) const;
  void write_register_bytes(std::string_view name, std::span<const std::uint8_t> value);
  std::uint64_t read_register(std::string_view name) const;
  void write_register(std::string_view name, std::uint64_t value);
  // The name of the register at (offset, size), or its "register:0x..:n" spelling.
  std::string register_name(std::uint64_t offset, std::uint32_t size) const;

  // --- Memory (the default space) ---
  // Bytes in memory order. Fails (false) if any byte is unmapped; ignores
  // permissions and MMIO hooks.
  bool read_memory(std::uint64_t address, std::span<std::uint8_t> out) const;
  bool write_memory(std::uint64_t address, std::span<const std::uint8_t> bytes);
  std::optional<std::uint64_t> read_word(std::uint64_t address, std::uint32_t size) const;
  bool write_word(std::uint64_t address, std::uint32_t size, std::uint64_t value);
  std::string read_cstring(std::uint64_t address, std::size_t max = 4096) const;
  // Maps zero-filled memory (or MMIO). Throws EmuError on overlap.
  void map(std::string name, std::uint64_t start, std::uint64_t size, loader::Perms perms, bool mmio = false);
  void unmap(std::uint64_t start, std::uint64_t size);
  std::vector<RegionInfo> regions() const;
  // A free, unmapped range of `size` bytes, aligned, searching upward from `hint`.
  std::optional<std::uint64_t> find_free(std::uint64_t size, std::uint64_t hint, std::uint64_t align = 0x1000) const;
  std::uint64_t memory_used() const;

  // --- Execution ---
  Stop step();
  // Over a call: runs until it returns (the fall-through address with the
  // stack pointer back where it was), a breakpoint or another stop.
  Stop step_over(const RunOptions &options = {});
  // Until the current function returns (a return op that leaves the stack
  // pointer above where it is now).
  Stop step_out(const RunOptions &options = {});
  Stop run(const RunOptions &options);
  const Stop &last_stop() const;
  std::uint64_t steps() const;

  void add_breakpoint(std::uint64_t address);
  bool remove_breakpoint(std::uint64_t address);
  void clear_breakpoints();
  const std::set<std::uint64_t> &breakpoints() const;
  // Stops after an instruction that reads or writes [start, start+size).
  int add_watchpoint(std::uint64_t start, std::uint64_t size, bool on_read, bool on_write);
  bool remove_watchpoint(int id);

  // --- Hooks ---
  void on_userop(std::string name, UseropHandler handler);
  // Replaces the OS's system calls (Linux: write, exit, brk, mmap, ...).
  void on_syscall(SyscallHandler handler);
  // Called for every access to an MMIO region; a read's value is the last
  // value written there unless the handler sets it.
  void on_mmio(MmioHandler handler);
  // The handlers installed now (to wrap one), and removing a user op's.
  SyscallHandler syscall_hook() const;
  MmioHandler mmio_hook() const;
  bool remove_userop(const std::string &name);
  // Marks the regions overlapping [start, start + size) as MMIO, so every
  // access there goes to the MMIO hook; false when none overlaps.
  bool mark_mmio(std::uint64_t start, std::uint64_t size);
  // As a stub returns: `value` in the convention's return register, and
  // back to the caller (the return address popped, or the link register's).
  // Throws EmuError when the return address can't be read.
  void return_from_call(std::uint64_t value);
  // Runs `handler` instead of the code at `address` (a library call stub).
  void stub(std::uint64_t address, std::string name, StubHandler handler);
  // The same for an import, by name.
  void stub_import(std::string_view name, StubHandler handler);
  // For hooks: integer argument `index` of the call being made.
  std::uint64_t arg(unsigned index) const;

  // --- Firmware ---
  // Attaches a board (machine.hh): maps its memory, builds and wires its
  // peripherals, and resets the CPU into its power-on state at the spec's
  // entry (or its reset vector). Replaces start(). Throws MachineError.
  Machine &attach_machine(const MachineSpec &spec, const MachineOptions &options);
  // The attached machine, or null.
  Machine *machine();
  const Machine *machine() const;

  // The instruction at `address` as the emulator decodes it (in the current
  // instruction set), with its p-code when `pcode`; empty if nothing decodes.
  std::string disassemble(std::uint64_t address, bool pcode = false);

  // --- Checkpoints (docs/emulator.md "Checkpoints") ---
  // The state now. Throws std::logic_error with a machine attached (its
  // peripherals' state isn't captured).
  Checkpoint checkpoint() const;
  // Back to a checkpoint of this emulator: state, step count and the trace
  // (entries after it are dropped). Breakpoints, watchpoints and hooks stay
  // as they are now.
  void restore(const Checkpoint &checkpoint);

  // --- What it did ---
  const std::string &stdout_data() const;
  const std::string &stderr_data() const;
  Trace &trace();
  const Trace &trace() const;
  const std::deque<MmioAccess> &mmio_log() const;

  struct Impl;
  // For revkit::emu's own hooks (Linux, library stubs); not an API.
  Impl &internals() { return *impl_; }
  const Impl &internals() const { return *impl_; }

 private:
  std::unique_ptr<Impl> impl_;
};

// Installs Linux system calls (x86-64, x86, AArch64, ARM, RISC-V): write,
// writev, read (stdin_data), exit, exit_group, brk, mmap, munmap,
// mprotect, arch_prctl, set_tid_address, getpid and the like, uname and a
// deterministic clock. The Emulator does this itself for Os::linux.
void install_linux(Emulator &emu);

// The registers a debugger shows for a language (SLEIGH names: general
// purpose, stack, pc, flags), whatever runs the code; empty for processors
// without a curated set.
std::vector<std::string> display_register_names(const std::string &language, unsigned pointer_size);

// The trace as JSON: summary, last stop, entries (deterministic).
std::string trace_json(const Emulator &emu, std::size_t max_entries = 0);

}  // namespace revkit::emu
