#include "revkit/debug/trace_target.hh"

namespace revkit::debug {

TraceTarget::TraceTarget(TraceHeader header) : header_(std::move(header)) {
  for (const RegisterDesc &r : header_.registers)
    if (r.name == header_.pc_register) pointer_size_ = r.size;
  last_.kind = StopKind::detached;
  last_.detail = "a recorded trace";
}

void TraceTarget::refuse() { throw DebugError("a recorded trace can be read, not run or changed"); }

std::string TraceTarget::description() const {
  return "trace \"" + header_.name + "\" of " + header_.target_kind + " (" + header_.target_description + ")";
}

std::string TraceTarget::current_thread() const {
  if (timeline_ == nullptr || timeline_->empty()) return "";
  return timeline_->snapshots().back().thread;
}

std::vector<std::uint8_t> TraceTarget::read_register(std::string_view name) {
  const RegisterDesc *d = find_register(name);
  if (d == nullptr || timeline_ == nullptr) throw DebugError("no register " + std::string(name) + " in the trace");
  auto regs = timeline_->registers_at(timeline_->last());
  auto it = regs.find(d->name);
  if (it == regs.end()) throw DebugError("register " + d->name + " was not recorded");
  return it->second;
}

std::size_t TraceTarget::read_memory(std::uint64_t address, std::span<std::uint8_t> out, std::vector<ByteRange> *unreadable) {
  std::vector<Timeline::ByteState> state;
  if (timeline_ == nullptr) {
    std::fill(out.begin(), out.end(), 0);
    if (unreadable != nullptr) unreadable->push_back({0, static_cast<std::uint32_t>(out.size())});
    return 0;
  }
  timeline_->memory_at(timeline_->last(), address, out, state, header_.complete);
  std::size_t known = 0;
  for (std::size_t i = 0; i < state.size(); ++i) {
    if (state[i] != Timeline::ByteState::unknown) {
      ++known;
      continue;
    }
    if (unreadable == nullptr) continue;
    if (!unreadable->empty() && unreadable->back().offset + unreadable->back().length == i) ++unreadable->back().length;
    else unreadable->push_back({static_cast<std::uint32_t>(i), 1});
  }
  return known;
}

}  // namespace revkit::debug
