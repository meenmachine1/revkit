// The machine runtime's internals (machine.cc, cpu_*.cc, peripherals.cc):
// CPU exception models, the scheduler, peripherals and their wiring.
#pragma once

#include "impl.hh"

#include "revkit/emu/machine.hh"

#include <array>
#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace revkit::emu::detail {

class MachineRuntime;

// An exception the CPU is about to take.
struct Pending {
  std::string kind;        // ExceptionEvent::kind
  std::int32_t number = -1;
  std::string source;      // the peripheral, when known
  std::uint64_t arg = 0;   // SWI/SVC immediate, abort address
};

// Classification bits a CPU model gives decoded instructions (Decoded::sys).
enum SysBits : std::uint32_t {
  kSysReadsCpsr = 1u << 0,       // composes the status register before it runs
  kSysMsrCpsr = 1u << 1,         // writes the status register (MSR)
  kSysMrsCpsr = 1u << 2,         // reads it into a register (MRS); sys_reg is the register
  kSysExcReturn = 1u << 3,       // ARM: SUBS PC / MOVS PC / LDM {..pc}^ restore CPSR from SPSR
  kSysUserBank = 1u << 4,        // ARM: LDM/STM ^ without pc: the user-mode registers
  kSysBogusCpsr = 1u << 5,       // ARM: the spec writes cpsr = spsr where the hardware doesn't (SUB pc without S)
  kSysMsrControl = 1u << 6,      // Cortex-M: MSR CONTROL (sys_reg is Rn)
  kSysEret = 1u << 7,            // MIPS: ERET
  kSysReadsCount = 1u << 8,      // MIPS: reads CP0 Count
};

// The architecture's exception model, in the emulator's state layer.
class CpuModel {
 public:
  explicit CpuModel(Emulator::Impl &m) : m(m) {}
  virtual ~CpuModel() = default;
  virtual std::string name() const = 0;
  // Power-on state; sets the pc (the reset vector unless `entry`).
  virtual void reset(std::optional<std::uint64_t> entry) = 0;
  // The CPU's interrupt inputs, by wiring name ("irq", "fiq", "5", "ip2"); -1: none.
  virtual int input(const std::string &name) const = 0;
  virtual void classify(Decoded &) const {}
  // Every instruction runs between before() and after() when true; else only
  // those classify() marked.
  virtual bool hooks_every_instruction() const { return false; }
  virtual void before(const Decoded &) {}
  // After the instruction's p-code (inside the step: writes are recorded
  // and undone on a fault). `next` is where execution continues.
  virtual void after(const Decoded &, std::uint64_t /*at*/, std::uint64_t & /*next*/) {}
  // CALLOTHERs the model implements (SWI, WFI, interrupt masks, ...).
  virtual bool userop(const std::string & /*name*/, UseropCall & /*call*/, const Op & /*op*/) { return false; }
  // The exception to take now, if any (lines, masks and priorities).
  virtual std::optional<Pending> pending() = 0;
  // Takes it: saves state, switches mode; returns the handler's address.
  // Writes go through store()/mem_write(), so the step's entry records them.
  virtual std::uint64_t enter(const Pending &p, std::uint64_t return_pc) = 0;
  // An exception return happened in the step just executed (for events).
  std::optional<ExceptionEvent> returned;
  // A synchronous exception the instruction raised, taken right after it
  // (SWI, SVC, syscall).
  std::optional<Pending> sync;
  // WFI ends: an interrupt is asserted, masked or not.
  virtual bool wake() const = 0;
  // Some interrupt could be taken (a branch to itself is an idle loop, not a halt).
  virtual bool interruptible() const { return true; }
  // A fault inside an instruction: true to take it as an exception (aborts)
  // instead of stopping; sets `p`.
  virtual bool fault_exception(const Fault &, std::uint64_t /*at*/, Pending & /*p*/, std::uint64_t & /*return_pc*/) {
    return false;
  }
  virtual void state(MachineState &out) const = 0;
  // A debugger wrote a register.
  virtual void register_written(const RegisterInfo &) {}
  // Peripherals the model brings (Cortex-M's system control space).
  virtual std::vector<std::pair<PeripheralSpec, std::unique_ptr<Peripheral>>> builtin_devices() { return {}; }
  // Line level changes (from the wiring).
  virtual void set_line(int input, bool level) {
    if (input < 0) return;
    if (static_cast<std::size_t>(input) >= lines.size()) lines.resize(static_cast<std::size_t>(input) + 1, false);
    lines[static_cast<std::size_t>(input)] = level;
  }
  // The CPU's display registers beyond the language's.
  virtual std::vector<std::string> display_extra() const { return {}; }
  // A step happened (clock-driven CPU state: MIPS Count).
  virtual void tick(std::uint64_t /*now*/) {}

  MachineRuntime *machine = nullptr;
  std::vector<bool> lines;

 protected:
  // Helpers over the register file. put() goes through store(): recorded
  // in the current step and undone on a fault; set() writes directly.
  const RegisterInfo &reg(std::string_view name) const { return m.reg(name); }
  std::optional<RegisterInfo> find(std::string_view name) const {
    if (auto i = m.find_reg(name)) return m.registers[*i];
    return std::nullopt;
  }
  std::uint64_t get(const RegisterInfo &r) const { return m.get_reg(r).lo(); }
  void put(const RegisterInfo &r, std::uint64_t v) { m.store(m.register_space, r.offset, Wide::of(r.size, v)); }
  void set(const RegisterInfo &r, std::uint64_t v) { m.set_reg(r, Wide::of(r.size, v)); }
  std::uint32_t load32(std::uint64_t addr);
  void store32(std::uint64_t addr, std::uint32_t v);
  std::uint32_t peek32(std::uint64_t addr) const;  // no MMIO side effects, no trace

  Emulator::Impl &m;
};

// ARM semihosting call `op` with parameter `arg` (SYS_WRITEC, SYS_WRITE0,
// SYS_WRITE, SYS_EXIT, SYS_CLOCK, ...): the result for r0, and an exit.
std::uint64_t semihosting_call(Emulator::Impl &m, std::uint32_t op, std::uint64_t arg);

std::unique_ptr<CpuModel> make_arm_model(Emulator::Impl &m, const CpuSpec &spec);
std::unique_ptr<CpuModel> make_cortexm_model(Emulator::Impl &m, const CpuSpec &spec);
std::unique_ptr<CpuModel> make_mips_model(Emulator::Impl &m, const CpuSpec &spec);
// The model a language implies: "arm", "cortex-m", "mips", or empty.
std::string default_cpu_model(const std::string &language);

// Built-in peripherals (peripherals.cc); nullptr for an unknown kind.
std::unique_ptr<Peripheral> make_builtin_peripheral(const PeripheralSpec &spec, std::string &error);

// Reads spec fields with messages naming where they are.
std::uint64_t num(const json::Value &v, const std::string &what);
std::optional<std::uint64_t> opt_num(const json::Value &obj, std::string_view key);
std::uint64_t num_or(const json::Value &obj, std::string_view key, std::uint64_t def);
bool bool_or(const json::Value &obj, std::string_view key, bool def);
std::string str_or(const json::Value &obj, std::string_view key, std::string def);

class MachineRuntime final : public Machine {
 public:
  MachineRuntime(Emulator::Impl &m, MachineSpec spec, MachineOptions options);
  ~MachineRuntime() override;

  // Machine
  const MachineSpec &spec() const override { return spec_; }
  std::uint64_t now() const override { return now_; }
  const std::deque<ExceptionEvent> &events() const override { return events_; }
  std::uint64_t event_count() const override { return event_count_; }
  bool input(std::string_view peripheral, std::string_view bytes) override;
  void set_break_on(std::vector<std::string> kinds) override { break_on_ = std::move(kinds); }
  const std::vector<std::string> &break_on() const override { return break_on_; }
  MachineState state() const override;
  std::string cpu_model() const override { return cpu ? cpu->name() : ""; }

  // Maps memory, builds and wires peripherals, resets the CPU.
  void build();
  void reset(std::optional<std::uint64_t> entry);

  // MMIO: true when a peripheral answered.
  bool mmio_read(std::uint64_t addr, std::uint32_t size, std::uint64_t &value);
  bool mmio_write(std::uint64_t addr, std::uint32_t size, std::uint64_t value);

  // After each executed step: time, events, idle, interrupts. A stop when
  // the run must end (an exception breakpoint, idle with nothing scheduled).
  std::optional<Stop> after_step(const RunOptions &o);
  // Before a run: a CPU left waiting waits on; a pending interrupt is taken.
  std::optional<Stop> resume_check(const RunOptions &o);
  // The CPU went idle (WFI, or a halt loop when interrupts can come).
  void wait() { waiting_ = true; }
  bool can_idle() const;
  // Takes a synchronous exception or a fault-turned-exception now (inside
  // the instruction's step).
  std::uint64_t take_now(const Pending &p, std::uint64_t return_pc);
  void record_event(ExceptionEvent e);
  // An exception breakpoint matches.
  bool breaks_on(const std::string &kind, std::int32_t number) const;

  // Peripheral wiring.
  void drive(int device, unsigned line, bool level);
  void schedule(int device, std::uint64_t at);
  void cancel(int device);
  void log(std::string line);
  void request_stop(std::string reason) { stop_request_ = std::move(reason); }

  std::unique_ptr<CpuModel> cpu;
  std::optional<Stop> pending_break;  // set by take_now for the run loop

 private:
  struct Device;
  struct Context;
  struct Target {
    int device = -1;  // -1: the CPU
    int input = 0;
  };
  void fire_due();
  std::uint64_t next_event() const;
  void map_memory();
  void advance(std::uint64_t ticks);
  std::optional<Stop> deliver(const Pending &p);
  std::optional<Stop> idle(const RunOptions &o);
  Target resolve(const std::string &where, const std::string &who);

  Emulator::Impl &m_;
  MachineSpec spec_;
  MachineOptions options_;
  std::vector<std::unique_ptr<Device>> devices_;
  std::vector<int> by_address_;  // device indices sorted by base
  int last_hit_ = -1;
  std::map<std::pair<int, unsigned>, std::vector<Target>> wires_;  // (device, output) -> targets
  std::map<std::pair<int, int>, std::set<std::pair<int, unsigned>>> asserted_;  // target -> sources high
  std::uint64_t now_ = 0;
  std::uint64_t idle_skipped_ = 0;
  std::chrono::steady_clock::time_point wall_start_;
  bool waiting_ = false;
  std::deque<ExceptionEvent> events_;
  std::uint64_t event_count_ = 0;
  std::vector<std::string> break_on_;
  std::deque<std::string> log_;
  std::optional<std::string> stop_request_;
  int console_ = -1;
};

}  // namespace revkit::emu::detail
