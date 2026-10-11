#include "revkit/debug/target.hh"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>

namespace revkit::debug {

namespace {

constexpr std::array<std::string_view, 28> kStopNames = {
    "none",       "stepped",   "step_limit",     "breakpoint",   "until",      "returned", "exited",
    "halted",     "unmapped",  "protection",     "decode",       "unimplemented", "userop", "syscall",
    "watchpoint", "hook",      "divide_by_zero", "memory_limit", "time_limit", "cancelled", "signal",
    "interrupted", "running",  "killed",         "detached",     "disconnected",
    "exception",  "idle"};

bool iequal(std::string_view a, std::string_view b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
         });
}

}  // namespace

std::string_view to_string(StopKind kind) {
  const auto i = static_cast<std::size_t>(kind);
  return i < kStopNames.size() ? kStopNames[i] : "?";
}

std::optional<StopKind> stop_kind(std::string_view name) {
  for (std::size_t i = 0; i < kStopNames.size(); ++i)
    if (kStopNames[i] == name) return static_cast<StopKind>(i);
  return std::nullopt;
}

std::string_view to_string(BreakKind kind) {
  switch (kind) {
    case BreakKind::software: return "software";
    case BreakKind::hardware: return "hardware";
    case BreakKind::watch_write: return "write watchpoint";
    case BreakKind::watch_read: return "read watchpoint";
    case BreakKind::watch_access: return "access watchpoint";
  }
  return "?";
}

std::string_view to_string(TargetState state) {
  switch (state) {
    case TargetState::stopped: return "stopped";
    case TargetState::running: return "running";
    case TargetState::exited: return "exited";
    case TargetState::detached: return "detached";
    case TargetState::disconnected: return "disconnected";
    case TargetState::replay: return "a recorded trace";
  }
  return "?";
}

std::uint64_t to_u64(std::span<const std::uint8_t> le) {
  std::uint64_t v = 0;
  for (std::size_t i = 0; i < le.size() && i < 8; ++i) v |= std::uint64_t{le[i]} << (8 * i);
  return v;
}

std::vector<std::uint8_t> from_u64(std::uint64_t v, std::size_t size) {
  std::vector<std::uint8_t> out(size, 0);
  for (std::size_t i = 0; i < size && i < 8; ++i) out[i] = static_cast<std::uint8_t>(v >> (8 * i));
  return out;
}

std::string hex(std::uint64_t v) {
  char b[24];
  std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
  return b;
}

const RegisterDesc *Target::find_register(std::string_view name) const {
  for (const RegisterDesc &r : registers())
    if (iequal(r.name, name)) return &r;
  for (const RegisterDesc &r : registers())
    if (iequal(r.target_name, name)) return &r;
  return nullptr;
}

std::uint64_t Target::read_register_u64(std::string_view name) { return to_u64(read_register(name)); }

void Target::write_register_u64(std::string_view name, std::uint64_t value) {
  const RegisterDesc *r = find_register(name);
  if (r == nullptr) throw DebugError("no register " + std::string(name));
  const auto bytes = from_u64(value, r->size);
  write_register(name, bytes);
}

}  // namespace revkit::debug
