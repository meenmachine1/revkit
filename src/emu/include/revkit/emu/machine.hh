// Firmware emulation: a board around the emulator's CPU (see
// docs/firmware-emulation.md).
//
//   - A CPU exception model per architecture (ARM: vector table, IRQ, FIQ,
//     SWI, aborts, undefined, CPSR modes with banked SP/LR/SPSR, returns by
//     SUBS PC,LR and LDM ^; Cortex-M: NVIC, SysTick, stacking and
//     EXC_RETURN; MIPS: Status/Cause/EPC, ERET, Count/Compare). Ghidra's
//     SLEIGH specs leave mode banking and exception entry to the emulator,
//     so this lives in the emulator's state layer.
//   - Peripherals: memory-mapped register blocks with read/write callbacks,
//     a clock and interrupt lines (C++ here, or WebAssembly plugins of kind
//     "peripheral"), wired to interrupt controllers and the CPU.
//   - A declarative machine description (JSON): memory, the image load, the
//     entry, peripherals and their wiring (MachineSpec, parse_machine).
//
// Time is a tick count that advances with every step (deterministic) or,
// optionally, with the host's clock; an idle CPU (WFI, a branch to itself)
// skips ahead to the next scheduled event.
#pragma once

#include "revkit/emu/emulator.hh"
#include "revkit/emu/json.hh"
#include "revkit/loader/image.hh"

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::emu {

// A machine description that doesn't parse or doesn't fit the program.
class MachineError : public EmuError {
 public:
  using EmuError::EmuError;
};

// --- The description -----------------------------------------------------

struct MemorySpec {
  enum class Kind : std::uint8_t { ram, rom, mmio };
  std::string name;
  std::uint64_t start = 0;
  std::uint64_t size = 0;
  Kind kind = Kind::ram;
  loader::Perms perms{true, true, true};
};

// Where the firmware file goes, as a raw import would load it.
struct ImageSpec {
  std::uint64_t load = 0;                 // address of the first loaded byte
  std::uint64_t offset = 0;               // file bytes skipped (a header)
  std::optional<std::uint64_t> length;    // bytes loaded (default: to the end)
  loader::Perms perms{true, true, true};
  std::string name = "image";
};

struct PeripheralSpec {
  std::string name;   // unique in the machine
  std::string kind;   // "timer", "sp804", "uart", "pl011", "intc", "vic", "pl190", "gic", "rtc", "pl031", "auto-ack", "plugin:NAME"
  std::optional<std::uint64_t> base;
  std::uint64_t size = 0x1000;
  // Output line -> "target.input": "irq" -> "vic.4", "cpu.irq", "nvic.5".
  std::vector<std::pair<std::string, std::string>> irqs;
  json::Value config;  // the whole object (kind-specific fields)
};

struct CpuSpec {
  std::string model;  // "arm", "cortex-m", "mips"; empty: from the language
  std::optional<std::uint64_t> vector_base;  // ARM 0 or 0xffff0000; Cortex-M VTOR; MIPS EBase
  bool aborts = false;      // unmapped accesses enter the abort handlers instead of stopping
  bool undefined = false;   // undecodable instructions enter the undefined handler instead of stopping
  std::uint32_t nvic_irqs = 64;  // Cortex-M external interrupts
  std::uint32_t priority_bits = 8;  // Cortex-M implemented priority bits
  // ARM semihosting (SWI 0x123456, SVC 0xab, BKPT 0xab): console output and
  // exit, as qemu's -semihosting gives bare-metal test programs.
  bool semihosting = false;
};

struct ClockSpec {
  bool wall = false;                     // ticks follow the host's clock instead of the steps
  std::uint64_t hz = 1000000;            // ticks per emulated second
  std::uint32_t ticks_per_step = 1;
};

struct MachineSpec {
  std::string name;
  std::string description;
  std::string language;   // a Ghidra language id; empty: the program's
  CpuSpec cpu;
  ClockSpec clock;
  std::vector<MemorySpec> memory;
  std::optional<ImageSpec> image;
  // Where execution starts: an address, or (unset) the reset vector.
  std::optional<std::uint64_t> entry;
  std::vector<std::pair<std::string, std::uint64_t>> registers;  // set after reset
  std::vector<PeripheralSpec> peripherals;
  std::vector<std::string> break_on;  // exception breakpoints ("irq", "swi", "any", ...)
  std::string console;    // the UART that takes stdin and is the default input (default: the first)
  json::Value source;     // the parsed document
};

// Parses and checks a description; throws MachineError("line:col: ...").
MachineSpec parse_machine(std::string_view text);
// The description as JSON (what parse_machine reads back).
std::string machine_json(const MachineSpec &spec);
// The raw-import options for loading `file_size` bytes of firmware as the
// machine says: the image block, and the machine's other memory as regions
// (the parts the image doesn't cover).
loader::RawOptions machine_raw_options(const MachineSpec &spec, std::uint64_t file_size);

// --- Peripherals -----------------------------------------------------------

class Machine;

// What a peripheral can do to the machine around it.
class PeripheralContext {
 public:
  virtual ~PeripheralContext() = default;
  virtual std::uint64_t now() const = 0;  // ticks
  virtual std::uint64_t hz() const = 0;   // ticks per emulated second
  // Calls tick() once `now` reaches `at` (replacing an earlier request).
  virtual void schedule(std::uint64_t at) = 0;
  virtual void cancel_schedule() = 0;
  // Drives output line `line` (0: "irq"); level-sensitive.
  virtual void set_irq(unsigned line, bool level) = 0;
  // Bytes for the session's output (a UART's transmitter).
  virtual void output(std::string_view bytes) = 0;
  // The emulated machine's memory (DMA); false when unmapped.
  virtual bool read_memory(std::uint64_t address, std::span<std::uint8_t> out) = 0;
  virtual bool write_memory(std::uint64_t address, std::span<const std::uint8_t> bytes) = 0;
  // A line for the machine's log (what a peripheral wants to say).
  virtual void log(std::string_view line) = 0;
  // Stops the run after the current step (e.g. a reset request).
  virtual void request_stop(std::string reason) = 0;
};

class Peripheral {
 public:
  virtual ~Peripheral() = default;
  // A register read (offset from base; size 1, 2, 4 or 8). The value is
  // little-endian in the register's sense: bits as the CPU sees them.
  virtual std::uint64_t read(std::uint64_t offset, std::uint32_t size) = 0;
  virtual void write(std::uint64_t offset, std::uint32_t size, std::uint64_t value) = 0;
  // The time asked for with schedule() came.
  virtual void tick(std::uint64_t /*now*/) {}
  // Host input (a UART's receiver).
  virtual void input(std::string_view /*bytes*/) {}
  // An interrupt controller's input line changed level.
  virtual void irq_in(unsigned /*line*/, bool /*level*/) {}
  // Output line names; index 0 is the default ("irq").
  virtual std::vector<std::string> outputs() const { return {"irq"}; }
  // Input line names for controllers (empty: by number).
  virtual bool has_inputs() const { return false; }
  // Called once after wiring, before the CPU starts.
  virtual void reset() {}
  // A short state summary for debuggers ("count 1234, irq pending").
  virtual std::string state() const { return {}; }
  virtual bool is_uart() const { return false; }
  // The register block's size when the description gives none.
  virtual std::optional<std::uint64_t> default_size() const { return std::nullopt; }

  void bind(PeripheralContext *ctx) { ctx_ = ctx; }
  PeripheralContext &ctx() const { return *ctx_; }

 private:
  PeripheralContext *ctx_ = nullptr;
};

// Makes a peripheral for a spec the built-ins don't know ("plugin:NAME");
// nullptr with `error` set when it can't.
using PeripheralFactory = std::function<std::unique_ptr<Peripheral>(const PeripheralSpec &spec, std::string &error)>;

// The built-in kinds, with a one-line description each.
std::vector<std::pair<std::string, std::string>> builtin_peripheral_kinds();

// --- Running -----------------------------------------------------------------

// An exception the CPU took, or returned from.
struct ExceptionEvent {
  std::uint64_t step = 0;   // the emulator's step count when it happened
  std::uint64_t tick = 0;
  std::string kind;         // "irq", "fiq", "swi", "undefined", "prefetch_abort", "data_abort", "reset",
                            // "nmi", "hardfault", "svc", "pendsv", "systick", "external", "interrupt",
                            // "syscall", "exception"; returns: "return"
  std::int32_t number = -1; // IRQ line, exception number, MIPS cause
  std::uint64_t pc = 0;     // where execution was (the next instruction)
  std::uint64_t handler = 0;// where it went
  std::string source;       // the peripheral that raised it, when known
  std::string detail;
};

// Machine state for debuggers.
struct MachineState {
  std::string cpu;            // model
  std::string mode;           // "svc", "irq", "thread", "handler", "kernel", ...
  std::uint64_t tick = 0;
  std::uint64_t hz = 0;
  bool waiting = false;       // WFI or idle
  std::uint64_t interrupts = 0;  // exceptions taken
  std::vector<std::pair<std::string, std::uint64_t>> registers;  // banked and system registers
  struct Device {
    std::string name, kind;
    std::uint64_t base = 0, size = 0;
    std::string state;
    std::optional<std::uint64_t> next_tick;
  };
  std::vector<Device> devices;
  std::vector<std::string> pending;  // lines or exceptions asserted
  std::vector<std::string> log;      // the machine's log (last lines)
};

struct MachineOptions {
  PeripheralFactory factory;         // for kinds the built-ins don't know
  std::size_t event_capacity = 4096; // exception events kept
};

// The machine attached to an emulator (Emulator::attach_machine).
class Machine {
 public:
  virtual ~Machine() = default;
  virtual const MachineSpec &spec() const = 0;
  virtual std::uint64_t now() const = 0;
  virtual const std::deque<ExceptionEvent> &events() const = 0;
  virtual std::uint64_t event_count() const = 0;
  // Input for a UART (empty name: the console).
  virtual bool input(std::string_view peripheral, std::string_view bytes) = 0;
  // Exception breakpoints: kinds ("irq", "fiq", "swi", "svc", "systick", ...,
  // "any"), optionally with a number ("irq:4").
  virtual void set_break_on(std::vector<std::string> kinds) = 0;
  virtual const std::vector<std::string> &break_on() const = 0;
  virtual MachineState state() const = 0;
  // The CPU's model ("arm", "cortex-m", "mips").
  virtual std::string cpu_model() const = 0;
};

// --- A starter machine from a program ------------------------------------------

// An access the code makes at a constant address (revkit::analysis's data
// references), for derive_machine.
struct StaticAccess {
  std::uint64_t address = 0;
  std::uint32_t size = 0;
  bool write = false;
  std::uint64_t from = 0;  // the instruction
};

struct DeriveOptions {
  std::uint64_t trial_steps = 2000000;  // 0: no trial run
  std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max();
  std::size_t max_loops = 8;            // polling loops to answer
  std::size_t max_runs = 48;            // trial runs in all
};

struct DerivedMachine {
  MachineSpec spec;
  std::string json;                   // the description, with notes
  std::vector<std::string> notes;     // what was derived and why
  std::uint32_t mmio_registers = 0;   // distinct MMIO addresses the code reaches (statically)
  std::uint32_t polling_loops = 0;    // answered with auto-ack registers
  std::uint64_t trial_steps = 0;      // steps the last trial run took
  Stop trial_stop;
};

// A first machine description for a program: its memory (the image's
// blocks: RAM, ROM, MMIO), regions for what the code reaches outside them,
// the CPU model and reset entry for its language, and, from trial runs, MMIO
// regions where it faults and auto-ack registers for the polling loops it
// spins in. `image_spec` is how the file loads (a raw import's layout).
DerivedMachine derive_machine(std::shared_ptr<const loader::Image> image, const std::string &language,
                              const std::vector<StaticAccess> &accesses, const std::optional<ImageSpec> &image_spec,
                              const DeriveOptions &options = {});

}  // namespace revkit::emu
