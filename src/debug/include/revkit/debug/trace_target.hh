// A saved recording as a target: its snapshots can be read (the last one
// is "now"), nothing runs or changes. Opening a trace makes a Session over
// one of these with the recorded Timeline.
#pragma once

#include "revkit/debug/target.hh"
#include "revkit/debug/timeline.hh"

namespace revkit::debug {

class TraceTarget : public Target {
 public:
  explicit TraceTarget(TraceHeader header);
  // The session's timeline (set once the Session holds it).
  void attach(const Timeline *timeline) { timeline_ = timeline; }
  const TraceHeader &header() const { return header_; }

  std::string kind() const override { return "trace"; }
  std::string description() const override;
  std::string language() const override { return header_.language; }
  unsigned pointer_size() const override { return pointer_size_; }
  bool big_endian() const override { return false; }
  bool complete_recording() const override { return header_.complete; }

  const std::vector<RegisterDesc> &registers() const override { return header_.registers; }
  std::string pc_register() const override { return header_.pc_register; }
  std::string sp_register() const override { return header_.sp_register; }
  std::vector<std::uint8_t> read_register(std::string_view name) override;
  void write_register(std::string_view, std::span<const std::uint8_t>) override { refuse(); }

  std::size_t read_memory(std::uint64_t address, std::span<std::uint8_t> out,
                          std::vector<ByteRange> *unreadable = nullptr) override;
  bool write_memory(std::uint64_t, std::span<const std::uint8_t>) override { refuse(); }

  Stop resume(const ResumeOptions &) override { refuse(); }
  Stop wait(std::chrono::steady_clock::time_point) override { return last_; }
  void interrupt() override {}
  TargetState state() const override { return TargetState::replay; }
  const Stop &last_stop() const override { return last_; }

  void insert_breakpoint(BreakKind, std::uint64_t, std::uint32_t) override { refuse(); }
  void remove_breakpoint(BreakKind, std::uint64_t, std::uint32_t) override {}

  std::vector<ThreadInfo> threads() override { return {}; }
  void select_thread(const std::string &) override { refuse(); }
  std::string current_thread() const override;
  std::vector<ModuleInfo> modules() override { return header_.modules; }
  std::vector<MapRegion> memory_map() override { return {}; }

  void detach() override {}
  void kill() override {}

 private:
  [[noreturn]] static void refuse();
  TraceHeader header_;
  const Timeline *timeline_ = nullptr;
  Stop last_;
  unsigned pointer_size_ = 8;
};

}  // namespace revkit::debug
