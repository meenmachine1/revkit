#include "impl.hh"

#include "revkit/emu/machine.hh"

#include <sstream>

namespace revkit::emu {

void Trace::set_capacity(std::size_t capacity) {
  capacity_ = capacity;
  while (entries_.size() > capacity_) {
    entries_.pop_front();
    ++summary_.dropped;
  }
}

void Trace::add(TraceEntry entry, std::size_t reads, std::size_t writes) {
  count(entry.pc, reads, writes);
  ++summary_.recorded;
  if (capacity_ == 0) {
    ++summary_.dropped;
    return;
  }
  entries_.push_back(std::move(entry));
  while (entries_.size() > capacity_) {
    entries_.pop_front();
    ++summary_.dropped;
  }
}

void Trace::count(std::uint64_t pc, std::size_t reads, std::size_t writes) {
  ++summary_.steps;
  summary_.memory_reads += reads;
  summary_.memory_writes += writes;
  if (!summary_.first_pc) summary_.first_pc = pc;
  summary_.last_pc = pc;
  if (pcs_.insert(pc).second) summary_.unique_pcs = pcs_.size();
}

void Trace::clear() {
  entries_.clear();
  summary_ = {};
  pcs_.clear();
}

void Trace::truncate(std::uint64_t from) {
  while (!entries_.empty() && entries_.back().index >= from) entries_.pop_back();
}

std::vector<TraceEntry> Trace::since(std::uint64_t from, std::size_t limit) const {
  std::vector<TraceEntry> out;
  for (const TraceEntry &e : entries_) {
    if (e.index < from) continue;
    out.push_back(e);
    if (limit != 0 && out.size() >= limit) break;
  }
  return out;
}

std::string hex(std::uint64_t v) {
  std::ostringstream o;
  o << "0x" << std::hex << v;
  return o.str();
}

std::string hex_value(const std::vector<std::uint8_t> &le) {
  static const char *digits = "0123456789abcdef";
  std::string out;
  bool leading = true;
  for (std::size_t i = le.size(); i-- > 0;) {
    const std::uint8_t b = le[i];
    for (int nib : {b >> 4, b & 15}) {
      if (leading && nib == 0) continue;
      leading = false;
      out.push_back(digits[nib]);
    }
  }
  return "0x" + (out.empty() ? std::string("0") : out);
}

std::string hex_bytes(const std::vector<std::uint8_t> &bytes) {
  static const char *digits = "0123456789abcdef";
  std::string out;
  for (std::uint8_t b : bytes) {
    out.push_back(digits[b >> 4]);
    out.push_back(digits[b & 15]);
  }
  return out;
}

namespace {

std::string quote(const std::string &s) {
  std::string out = "\"";
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20 || c >= 0x7f) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  return out + "\"";
}

void accesses(std::ostringstream &o, const std::vector<MemoryAccess> &list) {
  o << "[";
  for (std::size_t i = 0; i < list.size(); ++i) {
    const MemoryAccess &a = list[i];
    o << (i ? "," : "") << "{\"address\":\"" << hex(a.address) << "\",";
    if (!a.space.empty()) o << "\"space\":" << quote(a.space) << ",";
    o << "\"bytes\":\"" << hex_bytes(a.bytes) << "\"" << (a.mmio ? ",\"mmio\":true" : "") << "}";
  }
  o << "]";
}

}  // namespace

std::string trace_json(const Emulator &emu, std::size_t max_entries) {
  const Trace &t = emu.trace();
  const TraceSummary &s = t.summary();
  const Stop &stop = emu.last_stop();
  std::ostringstream o;
  o << "{\n\"language\":" << quote(emu.language()) << ",\n";
  o << "\"stop\":{\"kind\":" << quote(std::string(to_string(stop.kind))) << ",\"pc\":\"" << hex(stop.pc) << "\"";
  if (stop.address) o << ",\"address\":\"" << hex(*stop.address) << "\"";
  if (stop.kind == StopKind::exited || stop.kind == StopKind::returned) o << ",\"exit_code\":" << stop.exit_code;
  o << ",\"detail\":" << quote(stop.detail) << "},\n";
  o << "\"summary\":{\"steps\":" << s.steps << ",\"recorded\":" << s.recorded << ",\"dropped\":" << s.dropped
    << ",\"unique_pcs\":" << s.unique_pcs << ",\"memory_reads\":" << s.memory_reads
    << ",\"memory_writes\":" << s.memory_writes << ",\"mmio_reads\":" << s.mmio_reads << ",\"mmio_writes\":" << s.mmio_writes
    << ",\"syscalls\":" << s.syscalls << ",\"stub_calls\":" << s.stub_calls << ",\"userops\":" << s.userops;
  if (s.exceptions != 0) o << ",\"exceptions\":" << s.exceptions;
  if (s.first_pc) o << ",\"first_pc\":\"" << hex(*s.first_pc) << "\"";
  if (s.last_pc) o << ",\"last_pc\":\"" << hex(*s.last_pc) << "\"";
  o << "},\n";
  o << "\"stdout\":" << quote(emu.stdout_data()) << ",\n\"stderr\":" << quote(emu.stderr_data()) << ",\n";
  o << "\"registers\":{";
  bool first = true;
  for (const std::string &name : emu.display_registers()) {
    o << (first ? "" : ",") << quote(name) << ":\"" << hex_value(emu.read_register_bytes(name)) << "\"";
    first = false;
  }
  o << "},\n\"mmio\":[";
  first = true;
  for (const MmioAccess &a : emu.mmio_log()) {
    o << (first ? "" : ",") << "\n {\"step\":" << a.step << ",\"pc\":\"" << hex(a.pc) << "\",\"address\":\"" << hex(a.address)
      << "\",\"size\":" << a.size << ",\"write\":" << (a.write ? "true" : "false") << ",\"value\":\"" << hex(a.value) << "\"}";
    first = false;
  }
  o << "],\n";
  if (const Machine *mc = emu.machine()) {
    o << "\"machine\":{\"cpu\":" << quote(mc->cpu_model()) << ",\"tick\":" << mc->now()
      << ",\"exceptions\":" << mc->event_count() << ",\"events\":[";
    first = true;
    for (const ExceptionEvent &ev : mc->events()) {
      o << (first ? "" : ",") << "\n {\"step\":" << ev.step << ",\"tick\":" << ev.tick << ",\"kind\":" << quote(ev.kind);
      if (ev.number >= 0) o << ",\"number\":" << ev.number;
      o << ",\"pc\":\"" << hex(ev.pc) << "\",\"handler\":\"" << hex(ev.handler) << "\"";
      if (!ev.source.empty()) o << ",\"source\":" << quote(ev.source);
      if (!ev.detail.empty()) o << ",\"detail\":" << quote(ev.detail);
      o << "}";
      first = false;
    }
    o << "]},\n";
  }
  o << "\"entries\":[";
  const auto &entries = t.entries();
  const std::size_t skip = max_entries != 0 && entries.size() > max_entries ? entries.size() - max_entries : 0;
  for (std::size_t i = skip; i < entries.size(); ++i) {
    const TraceEntry &e = entries[i];
    o << (i > skip ? "," : "") << "\n {\"index\":" << e.index << ",\"pc\":\"" << hex(e.pc) << "\"";
    if (e.thumb) o << ",\"thumb\":true";
    o << ",\"bytes\":\"" << hex_bytes(e.bytes) << "\",\"text\":" << quote(e.text) << ",\"registers\":[";
    for (std::size_t k = 0; k < e.registers.size(); ++k)
      o << (k ? "," : "") << "{\"name\":" << quote(e.registers[k].name) << ",\"value\":\""
        << hex_value(e.registers[k].value) << "\"}";
    o << "],\"reads\":";
    accesses(o, e.reads);
    o << ",\"writes\":";
    accesses(o, e.writes);
    if (!e.event.empty()) o << ",\"event\":" << quote(e.event);
    if (!e.exception.empty()) {
      o << ",\"exception\":" << quote(e.exception);
      if (e.exception_number >= 0) o << ",\"exception_number\":" << e.exception_number;
    }
    o << "}";
  }
  o << "\n]\n}\n";
  return o.str();
}

}  // namespace revkit::emu
