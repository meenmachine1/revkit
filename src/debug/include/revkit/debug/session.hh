// A debug session: one target (the emulator or a live process) seen
// through the program being analysed. It maps runtime addresses to the
// program's static image (PIE/ASLR slides, module bases), keeps breakpoints
// in either kind of address, builds step over and step out where the
// target can only single-step, and records every stop on a Timeline.
#pragma once

#include "revkit/debug/target.hh"
#include "revkit/debug/timeline.hh"
#include "revkit/debug/unwind.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/image.hh"

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace revkit::lift {
class Lifter;
}

namespace revkit::debug {

struct SessionOptions {
  // The program: static addresses, and decoding for live step over/out.
  std::shared_ptr<const loader::Image> image;
  std::string program_name;  // its file name, to find it among a process's modules
  std::string language;      // its SLEIGH language (default: the target's)
  Timeline::Limits timeline;
  bool record_steps = true;      // the emulator: a snapshot per instruction
  std::uint32_t stack_bytes = 256;  // live targets: stack recorded at each stop
  std::optional<std::int64_t> slide;  // force the runtime - static offset
  // The entry of the function containing a static address, if known: live
  // step out then breaks on the function's returns instead of stepping.
  std::function<std::optional<std::uint64_t>(std::uint64_t)> function_entry;
  // A saved recording to show instead of recording anew (a TraceTarget's).
  std::optional<Timeline> recorded;
};

struct AddressMapping {
  bool known = false;
  std::int64_t slide = 0;  // runtime address = program address + slide
  std::string how;         // "static", "auxv AT_ENTRY", "module <name>", "given", "emulator"
};

struct Breakpoint {
  int id = 0;
  BreakKind kind = BreakKind::software;
  std::uint64_t address = 0;                  // runtime
  std::optional<std::uint64_t> program_address;
  std::uint32_t size = 0;
  bool inserted = false;  // in the target now
  bool pending = false;   // waiting for the program's address mapping
  std::string error;      // why the target refused it
  std::uint64_t hits = 0;  // times the target reached it (stopped there or not)
  // Conditional breakpoints (docs/debugger.md "Breakpoints"): a run stops
  // here only after `ignore_count` hits and when `condition` (an
  // expression, Session::set_condition_check) holds. A disabled one is
  // out of the target.
  std::string condition;
  std::uint64_t ignore_count = 0;
  bool disabled = false;
  std::string condition_error;  // the last evaluation's error (it stopped)
};

class Session {
 public:
  using Clock = std::chrono::steady_clock;

  Session(std::unique_ptr<Target> target, SessionOptions options);
  ~Session();
  Session(const Session &) = delete;
  Session &operator=(const Session &) = delete;

  Target &target() { return *target_; }
  const Target &target() const { return *target_; }
  const SessionOptions &options() const { return options_; }

  // --- Addresses ---
  const AddressMapping &mapping() const { return mapping_; }
  void set_slide(std::int64_t slide);
  std::uint64_t to_runtime(std::uint64_t program_address) const;
  // The static address of a runtime one, when it lies in the program's image.
  std::optional<std::uint64_t> to_program(std::uint64_t runtime) const;
  // The module containing a runtime address and the offset into it.
  std::optional<std::pair<ModuleInfo, std::uint64_t>> module_at(std::uint64_t runtime);
  std::vector<ModuleInfo> modules();
  std::vector<MapRegion> memory_map();

  // --- Execution ---
  // Runs as asked (step over and out built here for targets without them)
  // and records the stop. A live target still running at the deadline
  // returns `running`: wait() for the rest.
  Stop resume(RunMode mode, const ResumeOptions &options);
  Stop wait(Clock::time_point deadline);
  void interrupt() { target_->interrupt(); }
  bool running() const { return target_->state() == TargetState::running; }
  const Stop &last_stop() const { return last_; }

  // --- Breakpoints ---
  // `program`: `address` is in the program's static addresses.
  const Breakpoint &add_breakpoint(BreakKind kind, std::uint64_t address, bool program, std::uint32_t size = 0);
  bool remove_breakpoint(int id);
  // By address (runtime or program), any kind at it.
  bool remove_breakpoint_at(std::uint64_t address, bool program);
  void clear_breakpoints();
  // Changes a breakpoint's condition, ignore count or enabled state; false: no such breakpoint.
  bool update_breakpoint(int id, std::optional<std::string> condition, std::optional<std::uint64_t> ignore_count,
                         std::optional<bool> disabled);
  // Evaluates a condition at a stop (the backend's: it knows the program's
  // types): true to stop; an error stops too, with `error` set.
  using ConditionCheck = std::function<bool(const Breakpoint &, std::string &error)>;
  void set_condition_check(ConditionCheck check) { condition_check_ = std::move(check); }
  const std::vector<Breakpoint> &breakpoints() const { return breakpoints_; }

  // --- State (now) ---
  std::vector<std::uint8_t> read_register(std::string_view name);
  // Records an edit snapshot.
  void write_register(std::string_view name, std::span<const std::uint8_t> value);
  // Recorded as seen at the current snapshot.
  std::size_t read_memory(std::uint64_t address, std::span<std::uint8_t> out, std::vector<ByteRange> *unreadable = nullptr);
  bool write_memory(std::uint64_t address, std::span<const std::uint8_t> bytes);
  // What the program printed so far (bounded to the last MiB).
  const std::string &output() const { return output_; }
  std::uint64_t output_size() const { return output_total_; }
  void select_thread(const std::string &id);

  // --- The call stack (docs/debugger.md, "Call stack") ---
  struct BacktraceOptions {
    std::size_t max_frames = 64;
    bool cfi = true;  // false: frame pointers and stack scanning only (tests)
    // A recorded snapshot instead of now (what was recorded of the stack).
    std::optional<std::uint64_t> snapshot;
    // Outside the program (a shared library the caller knows, another
    // project program): the CFI rules at a runtime pc, and whether a
    // runtime pc is a function's first instruction. Unset: none.
    std::function<std::optional<CfiRow>(std::uint64_t runtime)> library_cfi;
    std::function<bool(std::uint64_t runtime)> library_entry;
  };
  // The frames above the stop: the program's call-frame information where
  // it covers a pc, else frame pointers, else a stack scan.
  std::vector<Frame> backtrace(const BacktraceOptions &options);
  // Whether the instruction before a runtime address is a call (a return
  // address's).
  bool after_call(std::uint64_t runtime);

  // --- Operands and registers (value hovers, docs/debugger.md "Values") ---
  struct MemoryAccess {
    std::uint64_t address = 0;  // runtime
    std::uint32_t size = 0;
    bool store = false;
    bool operand = false;  // the asked-for operand's (its registers or address computed it)
  };
  // The memory the instruction at `runtime` (its encoding: `bytes`) reads
  // and writes, its p-code run with `registers` (a frame's, by name) and
  // `read` (for addresses loaded from memory). The access of print-order
  // `operand` first, when one is (-1: in order). Empty when it doesn't decode.
  std::vector<MemoryAccess> memory_accesses(
      std::uint64_t runtime, std::span<const std::uint8_t> bytes, const std::map<std::string, std::uint64_t> &registers,
      const std::function<std::optional<std::uint64_t>(std::uint64_t, unsigned)> &read, int operand);
  // The language's name for a register-space varnode, "" if none.
  std::string register_at(std::uint64_t offset, std::uint32_t size);
  // The instruction at a runtime address (its encoding: `bytes`), as the
  // program's language prints it, with its p-code; nullopt when it doesn't
  // decode (docs/debugger.md "Runtime disassembly").
  std::optional<lift::Instruction> disassemble(std::uint64_t runtime, std::span<const std::uint8_t> bytes);
  // A register's storage in the language's register space ("EAX": offset 0, size 4).
  std::optional<std::pair<std::uint64_t, std::uint32_t>> register_storage(const std::string &name);

  // Records an edit snapshot of the registers now: the target's state was
  // changed outside the session (a hook returned for a function).
  void note_edit(const std::string &what) { record_edit(what, display_registers(), {}); }

  // --- Rewinding (docs/debugger.md "Rewind") ---
  // The emulator (without a machine) can go back to any recorded snapshot
  // and continue from there; the snapshots after it are dropped.
  bool can_rewind() const;
  Stop rewind(std::uint64_t snapshot);
  // Back one snapshot (one instruction in the emulator's recording).
  Stop step_back();

  // --- The recording ---
  Timeline &timeline() { return timeline_; }
  const Timeline &timeline() const { return timeline_; }
  // The snapshot that is "now" (the latest one).
  std::uint64_t current_snapshot() const { return timeline_.last(); }
  // Memory at a recorded snapshot (see Timeline::memory_at).
  void memory_at(std::uint64_t snapshot, std::uint64_t address, std::span<std::uint8_t> out,
                 std::vector<Timeline::ByteState> &state);
  TraceHeader header(const std::string &name, const std::string &program_id) const;

 private:
  struct Decoded {
    std::uint32_t length = 0;
    bool call = false, ret = false;
  };
  std::optional<Decoded> decode(std::uint64_t runtime);
  // A run's breakpoint stop that its breakpoints' ignore counts and
  // conditions pass over (the hits counted); false: stop there.
  bool pass_over(const Stop &s);
  // A checkpoint of an emulator target at the latest snapshot (rewinding).
  void checkpoint_now();
  Stop resume_once(RunMode mode, const ResumeOptions &options);
  // The program's lifter (ARM: the Thumb one when the target is in Thumb), made on first use; null without one.
  lift::Lifter *lifter();
  void refresh_mapping();
  void resolve_pending();
  void insert(Breakpoint &b);
  Stop step_over_live(const ResumeOptions &o);
  Stop step_out_live(const ResumeOptions &o);
  Stop run_to(std::uint64_t address, const ResumeOptions &o, std::optional<std::uint64_t> sp_at_least);
  Stop single_step(const ResumeOptions &o);
  bool sp_above(std::uint64_t sp, std::uint64_t than, bool or_equal) const;
  void record(const Stop &s);
  void record_edit(const std::string &what, std::vector<std::pair<std::string, std::vector<std::uint8_t>>> regs,
                   std::vector<MemoryRecord> memory);
  std::vector<std::pair<std::string, std::vector<std::uint8_t>>> display_registers();
  void collect_output();

  std::unique_ptr<Target> target_;
  SessionOptions options_;
  AddressMapping mapping_;
  Timeline timeline_;
  std::vector<Breakpoint> breakpoints_;
  int next_breakpoint_ = 1;
  Stop last_;
  std::string output_;
  std::uint64_t output_total_ = 0;
  Clock::time_point started_ = Clock::now();
  std::unique_ptr<lift::Lifter> lifter_, thumb_lifter_;
  ConditionCheck condition_check_;
  RunMode running_mode_ = RunMode::run;  // what a run that went on in the background is
  std::shared_ptr<const CfiTable> cfi_;
  bool lifter_failed_ = false;
  // A run the session started for step over/out or until, still running.
  struct Pending {
    std::vector<std::uint64_t> temporary;  // breakpoints to remove after
    // What to do with the stop: may resume again (then `running`).
    std::function<Stop(Stop, Clock::time_point)> finish;
  };
  std::optional<Pending> pending_;
};

}  // namespace revkit::debug
