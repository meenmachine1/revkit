// revkit's p-code emulator as a debug target: the same registers, memory,
// breakpoints and stops a live process has, plus the emulator's own trace,
// which a Session turns into instruction-level snapshots.
#pragma once

#include "revkit/debug/target.hh"
#include "revkit/emu/emulator.hh"

#include <atomic>
#include <map>
#include <memory>

namespace revkit::debug {

class EmulatorTarget : public Target {
 public:
  // `emu` is started (Emulator::start) and owned from now on.
  explicit EmulatorTarget(std::unique_ptr<emu::Emulator> emu, std::string program_name = "program");

  emu::Emulator &emulator() { return *emu_; }

  std::string kind() const override { return "emulator"; }
  std::string description() const override;
  std::string language() const override { return emu_->language(); }
  unsigned pointer_size() const override { return emu_->pointer_size(); }
  bool big_endian() const override { return emu_->big_endian(); }
  bool complete_recording() const override;

  const std::vector<RegisterDesc> &registers() const override { return regs_; }
  std::string pc_register() const override { return emu_->pc_register(); }
  std::string sp_register() const override { return emu_->sp_register(); }
  std::vector<std::uint8_t> read_register(std::string_view name) override;
  void write_register(std::string_view name, std::span<const std::uint8_t> value) override;

  std::size_t read_memory(std::uint64_t address, std::span<std::uint8_t> out,
                          std::vector<ByteRange> *unreadable = nullptr) override;
  bool write_memory(std::uint64_t address, std::span<const std::uint8_t> bytes) override;

  Stop resume(const ResumeOptions &options) override;
  Stop wait(std::chrono::steady_clock::time_point) override { return last_; }
  void interrupt() override { interrupted_ = true; }
  bool native_step_over() const override { return true; }
  TargetState state() const override;
  const Stop &last_stop() const override { return last_; }
  std::uint64_t steps() const override { return emu_->steps(); }

  void insert_breakpoint(BreakKind kind, std::uint64_t address, std::uint32_t size) override;
  void remove_breakpoint(BreakKind kind, std::uint64_t address, std::uint32_t size) override;

  std::vector<ThreadInfo> threads() override;
  void select_thread(const std::string &id) override;
  std::string current_thread() const override { return "1"; }
  std::vector<ModuleInfo> modules() override;
  std::vector<MapRegion> memory_map() override;

  void detach() override { detached_ = true; }
  void kill() override { detached_ = true; }
  std::string take_output() override;
  std::vector<StepRecord> take_steps() override;
  bool thumb() override { return emu_->thumb(); }

  // Rewinding (docs/debugger.md "Rewind"): a checkpoint of the emulator at
  // a recorded snapshot; going back to a snapshot restores the nearest
  // checkpoint at or before it and runs the steps between again (the
  // emulator is deterministic). Not with a machine.
  bool rewindable() const { return emu_->machine() == nullptr; }
  void checkpoint(std::uint64_t snapshot);
  // Back to `snapshot`, whose step count is `steps`; throws DebugError
  // without a checkpoint at or before it. Later checkpoints are dropped.
  void rewind(std::uint64_t snapshot, std::uint64_t steps);
  // Drops checkpoints the timeline no longer needs (all but the last one before `first`).
  void forget_checkpoints_before(std::uint64_t first);
  void set_last_stop(const Stop &s) { last_ = s; }

 private:
  std::map<std::string, std::vector<std::uint8_t>> display_values() const;

  std::unique_ptr<emu::Emulator> emu_;
  std::string program_name_;
  std::vector<RegisterDesc> regs_;
  Stop last_;
  bool detached_ = false;
  std::atomic<bool> interrupted_{false};
  std::size_t stdout_at_ = 0, stderr_at_ = 0;
  std::uint64_t steps_at_resume_ = 0;
  std::map<std::string, std::vector<std::uint8_t>> display_at_resume_;
  std::map<std::tuple<int, std::uint64_t, std::uint32_t>, int> watches_;  // (kind, address, size) -> id
  std::map<std::uint64_t, emu::Checkpoint> checkpoints_;  // by snapshot
};

Stop from_emu(const emu::Stop &s);

}  // namespace revkit::debug
