// A crash dump as a target (docs/crash-dumps.md): an ELF core file or a
// Windows minidump (revkit::crash), stopped where it crashed and read-only.
// Its threads and their registers, memory as dumped, the modules and the
// memory map; nothing runs or changes. Memory the dump left out (the code
// of mapped files, usually) comes from the backing callback, which reads
// it from the programs of the project or the files themselves.
#pragma once

#include "revkit/crash/crash.hh"
#include "revkit/debug/gdb_remote.hh"
#include "revkit/debug/target.hh"

#include <functional>
#include <memory>

namespace revkit::debug {

struct CrashTargetOptions {
  // The program's SLEIGH language: registers map onto its registers.
  std::string language;
  std::vector<SleighRegister> sleigh_registers;
  std::string description;
  // Fills bytes of `out` (at runtime address `address`) the dump doesn't
  // hold; returns how many it filled, from the start (0: none). Called for
  // each missing run.
  std::function<std::size_t(std::uint64_t address, std::span<std::uint8_t> out)> backing;
};

class CrashTarget final : public Target {
 public:
  // `bytes` stays alive (held by `keep`) as long as the target.
  CrashTarget(std::shared_ptr<const void> keep, std::span<const std::byte> bytes, crash::CrashDump dump,
              CrashTargetOptions options);

  const crash::CrashDump &dump() const { return dump_; }
  std::span<const std::byte> bytes() const { return bytes_; }
  void set_backing(decltype(CrashTargetOptions::backing) b) { options_.backing = std::move(b); }
  // Memory as dumped only (no backing): what the dump itself holds.
  std::size_t read_dumped(std::uint64_t address, std::span<std::uint8_t> out, std::vector<ByteRange> *missing = nullptr) const;

  std::string kind() const override { return "crash-dump"; }
  std::string description() const override { return options_.description; }
  std::string language() const override { return options_.language; }
  unsigned pointer_size() const override { return dump_.pointer_size; }
  bool big_endian() const override { return dump_.big_endian; }

  const std::vector<RegisterDesc> &registers() const override { return regs_; }
  std::string pc_register() const override { return pc_; }
  std::string sp_register() const override { return sp_; }
  std::vector<std::uint8_t> read_register(std::string_view name) override;
  void write_register(std::string_view, std::span<const std::uint8_t>) override { refuse(); }

  std::size_t read_memory(std::uint64_t address, std::span<std::uint8_t> out, std::vector<ByteRange> *unreadable = nullptr) override;
  bool write_memory(std::uint64_t, std::span<const std::uint8_t>) override { refuse(); }

  Stop resume(const ResumeOptions &) override { refuse(); }
  Stop wait(std::chrono::steady_clock::time_point) override { return last_; }
  void interrupt() override {}
  TargetState state() const override { return TargetState::stopped; }
  const Stop &last_stop() const override { return last_; }

  void insert_breakpoint(BreakKind, std::uint64_t, std::uint32_t) override { refuse(); }
  void remove_breakpoint(BreakKind, std::uint64_t, std::uint32_t) override {}

  std::vector<ThreadInfo> threads() override;
  void select_thread(const std::string &id) override;
  std::string current_thread() const override;
  std::vector<ModuleInfo> modules() override { return modules_; }
  std::vector<MapRegion> memory_map() override;
  std::map<std::uint64_t, std::uint64_t> auxv() override { return dump_.auxv; }
  std::optional<std::int64_t> process_id() const override;

  void detach() override {}
  void kill() override {}
  bool thumb() override;

 private:
  [[noreturn]] static void refuse();
  const crash::Register *raw(const crash::Thread &t, std::string_view target_name) const;

  std::shared_ptr<const void> keep_;
  std::span<const std::byte> bytes_;
  crash::CrashDump dump_;
  CrashTargetOptions options_;
  std::vector<RegisterDesc> regs_;
  std::string pc_, sp_;
  std::size_t current_ = 0;
  Stop last_;
  std::vector<ModuleInfo> modules_;
};

// A stop as the dump says: the signal or exception, the faulting address,
// the thread.
Stop crash_stop(const crash::CrashDump &dump);

}  // namespace revkit::debug
