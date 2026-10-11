// A debug session's recording: one snapshot per stop (and, for the
// emulator, per instruction between stops), each with its pc, the registers
// that changed and the memory touched. Any snapshot's registers and memory
// can be reconstructed: the time-travel views. Session state, never facts:
// bounded, kept per session, and saved to a project only when asked.
#pragma once

#include "revkit/debug/target.hh"

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace revkit::debug {

struct MemoryRecord {
  enum class Kind : std::uint8_t {
    observed,  // read by the debugger at this snapshot (a memory view, the stack)
    read,      // read by the program in the step that led here
    write,     // written by the program (or the debugger) in the step that led here
  };
  std::uint64_t address = 0;
  std::vector<std::uint8_t> bytes;
  // Writes: the bytes before the write, when known (the emulator knows).
  std::vector<std::uint8_t> before;
  Kind kind = Kind::observed;
};

struct Snapshot {
  enum class Kind : std::uint8_t {
    stop,  // the target stopped (a step, a breakpoint, ...)
    step,  // an instruction inside a run (the emulator's trace)
    edit,  // the debugger changed a register or memory
  };
  std::uint64_t index = 0;  // position on the timeline (never reused)
  Kind kind = Kind::stop;
  std::uint64_t pc = 0;
  std::optional<std::uint64_t> program_pc;  // pc in the program's static addresses
  std::string thread;
  std::uint64_t steps = 0;  // the target's step (emulator) or stop (live) count
  StopKind stop = StopKind::none;
  std::string detail;
  std::string text;   // the instruction that led here (emulator), or an event
  bool keyframe = false;  // `registers` holds every recorded register, else only changes
  std::vector<std::pair<std::string, std::vector<std::uint8_t>>> registers;
  std::vector<MemoryRecord> memory;
  std::int64_t time_us = 0;  // since the session started
  bool gap = false;          // steps before this one were not recorded
  // Firmware: the exception the step entered ("irq", "swi", ...) or
  // "return"; empty for other snapshots.
  std::string event;
  std::int32_t event_number = -1;
};

// What a saved trace says about where it came from.
struct TraceHeader {
  std::string name;
  std::string program_id;
  std::string language;
  std::string target_kind;
  std::string target_description;
  std::string pc_register, sp_register;
  std::vector<RegisterDesc> registers;  // name, size, display
  std::int64_t slide = 0;
  std::vector<ModuleInfo> modules;
  std::int64_t created_unix = 0;
  bool complete = false;  // every memory change recorded (the emulator)
};

class Timeline {
 public:
  struct Limits {
    std::size_t max_snapshots = 10000;
    std::uint64_t max_bytes = 64ull << 20;  // registers and memory held
  };
  enum class ByteState : std::uint8_t {
    unknown,  // never recorded at or before the snapshot
    exact,    // the value at the snapshot
    stale,    // recorded at an earlier snapshot; may have changed since
  };

  Timeline() = default;
  explicit Timeline(Limits limits) : limits_(limits) {}

  // Appends (index assigned); drops the oldest snapshots past the limits.
  Snapshot &add(Snapshot s);
  // Drops the snapshots after `index`, which becomes the last; the next one
  // added is index + 1 (a rewind).
  void truncate_after(std::uint64_t index);
  // Adds memory seen at snapshot `index` (a debugger read at the latest stop).
  void observe(std::uint64_t index, std::uint64_t address, std::span<const std::uint8_t> bytes);

  bool empty() const { return snaps_.empty(); }
  std::size_t size() const { return snaps_.size(); }
  std::uint64_t first() const { return snaps_.empty() ? 0 : snaps_.front().index; }
  std::uint64_t last() const { return snaps_.empty() ? 0 : snaps_.back().index; }
  std::uint64_t next_index() const { return next_; }
  const std::deque<Snapshot> &snapshots() const { return snaps_; }
  const Snapshot *find(std::uint64_t index) const;
  std::uint64_t bytes() const { return bytes_; }
  std::uint64_t dropped() const { return dropped_; }
  const Limits &limits() const { return limits_; }
  void set_limits(Limits l);

  // Every recorded register's value at `index`.
  std::map<std::string, std::vector<std::uint8_t>> registers_at(std::uint64_t index) const;
  // Registers whose value at `index` differs from the snapshot before it.
  std::vector<std::string> changed_at(std::uint64_t index) const;
  // ... from snapshot `since` (an earlier one).
  std::vector<std::string> changed_between(std::uint64_t since, std::uint64_t index) const;
  // The snapshot a stop's changes are counted from: the stop or edit before
  // it (instruction snapshots in between are skipped); for an instruction
  // snapshot, the one before it.
  std::optional<std::uint64_t> previous(std::uint64_t index) const;

  // Memory at `index`. `complete`: every write was recorded (the emulator),
  // so bytes recorded later or never recorded (`current`, the value now)
  // are exact too. Otherwise only what was seen at or before `index`.
  void memory_at(std::uint64_t index, std::uint64_t address, std::span<std::uint8_t> out, std::vector<ByteState> &state,
                 bool complete, const std::function<void(std::uint64_t, std::span<std::uint8_t>, std::vector<bool> &)> &current = {}) const;

  // A compact binary encoding (save to a project) and back. Throws
  // DebugError for a malformed trace.
  std::string serialize(const TraceHeader &header) const;
  static Timeline deserialize(std::string_view data, TraceHeader &header);
  // Only the header and the number of snapshots (listing saved traces).
  static TraceHeader peek(std::string_view data, std::uint64_t *snapshots = nullptr);
  // Readable JSON (rk-dbg --trace).
  std::string to_json(const TraceHeader &header) const;

 private:
  static std::uint64_t cost(const Snapshot &s);
  void trim();

  Limits limits_;
  std::deque<Snapshot> snaps_;
  std::uint64_t next_ = 0;
  std::uint64_t bytes_ = 0;
  std::uint64_t dropped_ = 0;
};

std::string_view to_string(Snapshot::Kind kind);

}  // namespace revkit::debug
