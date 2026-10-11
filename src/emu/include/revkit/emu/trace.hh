// What an emulation did, step by step: bounded, summarized, serializable.
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace revkit::emu {

// A register an instruction wrote, with its value afterwards.
struct RegisterWrite {
  std::string name;           // a register name, or "register:0x<offset>:<size>" for unnamed storage
  std::vector<std::uint8_t> value;  // least significant byte first, `size` bytes
};

// A memory access by the program (not by the debugger or a hook).
struct MemoryAccess {
  std::uint64_t address = 0;
  std::string space;                // empty: the default space ("ram")
  std::vector<std::uint8_t> bytes;  // as in memory (target byte order)
  bool mmio = false;                // in a memory-mapped I/O region
  // Writes: the bytes there before the write (what a debugger's time travel
  // needs to show memory as it was). Empty for reads.
  std::vector<std::uint8_t> before;
};

struct TraceEntry {
  std::uint64_t index = 0;  // steps executed before this one
  std::uint64_t pc = 0;
  bool thumb = false;                // ARM: decoded as Thumb
  std::vector<std::uint8_t> bytes;   // the instruction's bytes
  std::string text;                  // its disassembly, or "<stub name>" for a skipped call
  std::vector<RegisterWrite> registers;  // in the order first written
  std::vector<MemoryAccess> reads, writes;
  std::string event;                 // a hook's note: "syscall write(1, 0x4000, 6) = 6"
  // Firmware: the exception this step entered ("irq", "swi", ...) or
  // "return" for an exception return; empty for ordinary steps.
  std::string exception;
  std::int32_t exception_number = -1;
};

struct TraceSummary {
  std::uint64_t steps = 0;           // instructions executed (stubs count one each)
  std::uint64_t recorded = 0;        // entries ever added
  std::uint64_t dropped = 0;         // entries pushed out of the bounded window
  std::uint64_t unique_pcs = 0;
  std::uint64_t memory_reads = 0, memory_writes = 0;
  std::uint64_t mmio_reads = 0, mmio_writes = 0;
  std::uint64_t syscalls = 0, stub_calls = 0, userops = 0;
  std::uint64_t exceptions = 0;      // exceptions taken (firmware)
  std::optional<std::uint64_t> first_pc, last_pc;
};

// Keeps the last `capacity` entries and counts everything.
class Trace {
 public:
  explicit Trace(std::size_t capacity = 4096) : capacity_(capacity) {}

  void set_capacity(std::size_t capacity);
  std::size_t capacity() const { return capacity_; }
  // Counts the step (with its memory reads and writes); keeps the entry if
  // there is room for any.
  void add(TraceEntry entry, std::size_t reads, std::size_t writes);
  // Counts a step that wasn't recorded.
  void count(std::uint64_t pc, std::size_t reads, std::size_t writes);
  void count_mmio(bool write) { ++(write ? summary_.mmio_writes : summary_.mmio_reads); }
  void count_syscall() { ++summary_.syscalls; }
  void count_stub() { ++summary_.stub_calls; }
  void count_userop() { ++summary_.userops; }
  void count_exception() { ++summary_.exceptions; }

  const std::deque<TraceEntry> &entries() const { return entries_; }
  const TraceSummary &summary() const { return summary_; }
  void clear();
  // Drops the entries with index >= from (a rewind); the summary keeps counting what ran.
  void truncate(std::uint64_t from);

  // Entries with index >= from, at most `limit` (0: all).
  std::vector<TraceEntry> since(std::uint64_t from, std::size_t limit = 0) const;

 private:
  std::size_t capacity_;
  std::deque<TraceEntry> entries_;
  TraceSummary summary_;
  std::unordered_set<std::uint64_t> pcs_;
};

std::string hex(std::uint64_t v);
// A value's bytes (least significant first) as "0x..." without leading zeros.
std::string hex_value(const std::vector<std::uint8_t> &le);
// Bytes in order as "0a1b2c".
std::string hex_bytes(const std::vector<std::uint8_t> &bytes);

}  // namespace revkit::emu
