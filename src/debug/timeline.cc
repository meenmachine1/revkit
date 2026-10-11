#include "revkit/debug/timeline.hh"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace revkit::debug {

namespace {

constexpr std::uint64_t kKeyframeEvery = 256;

}  // namespace

std::string_view to_string(Snapshot::Kind kind) {
  switch (kind) {
    case Snapshot::Kind::stop: return "stop";
    case Snapshot::Kind::step: return "step";
    case Snapshot::Kind::edit: return "edit";
  }
  return "?";
}

std::uint64_t Timeline::cost(const Snapshot &s) {
  std::uint64_t c = 96 + s.detail.size() + s.text.size() + s.thread.size();
  for (const auto &[n, v] : s.registers) c += 32 + n.size() + v.size();
  for (const MemoryRecord &m : s.memory) c += 32 + m.bytes.size() + m.before.size();
  return c;
}

void Timeline::set_limits(Limits l) {
  limits_ = l;
  trim();
}

const Snapshot *Timeline::find(std::uint64_t index) const {
  if (snaps_.empty() || index < snaps_.front().index || index > snaps_.back().index) return nullptr;
  return &snaps_[static_cast<std::size_t>(index - snaps_.front().index)];
}

Snapshot &Timeline::add(Snapshot s) {
  s.index = next_++;
  if (!s.keyframe) {
    // Bound reconstruction: a full register set every kKeyframeEvery snapshots.
    std::uint64_t since = 0;
    for (auto it = snaps_.rbegin(); it != snaps_.rend() && !it->keyframe; ++it) ++since;
    if (snaps_.empty() || since + 1 >= kKeyframeEvery) {
      auto full = snaps_.empty() ? std::map<std::string, std::vector<std::uint8_t>>{} : registers_at(snaps_.back().index);
      for (auto &[n, v] : s.registers) full[n] = v;
      s.registers.assign(full.begin(), full.end());
      s.keyframe = true;
    }
  }
  bytes_ += cost(s);
  snaps_.push_back(std::move(s));
  trim();
  return snaps_.back();
}

void Timeline::truncate_after(std::uint64_t index) {
  while (!snaps_.empty() && snaps_.back().index > index) {
    bytes_ -= cost(snaps_.back());
    snaps_.pop_back();
  }
  next_ = snaps_.empty() ? next_ : snaps_.back().index + 1;
}

void Timeline::trim() {
  while (snaps_.size() > 1 && (snaps_.size() > limits_.max_snapshots || bytes_ > limits_.max_bytes)) {
    Snapshot &second = snaps_[1];
    if (!second.keyframe) {
      auto full = registers_at(second.index);
      bytes_ -= cost(second);
      second.registers.assign(full.begin(), full.end());
      second.keyframe = true;
      bytes_ += cost(second);
    }
    bytes_ -= cost(snaps_.front());
    snaps_.pop_front();
    ++dropped_;
  }
}

void Timeline::observe(std::uint64_t index, std::uint64_t address, std::span<const std::uint8_t> bytes) {
  if (bytes.empty()) return;
  auto *s = const_cast<Snapshot *>(find(index));
  if (s == nullptr) return;
  // Already seen these bytes here: nothing to add.
  for (const MemoryRecord &m : s->memory)
    if (m.kind == MemoryRecord::Kind::observed && m.address <= address &&
        address + bytes.size() <= m.address + m.bytes.size())
      return;
  MemoryRecord r;
  r.address = address;
  r.bytes.assign(bytes.begin(), bytes.end());
  r.kind = MemoryRecord::Kind::observed;
  const std::uint64_t before = cost(*s);
  s->memory.push_back(std::move(r));
  bytes_ += cost(*s) - before;
  trim();
}

std::map<std::string, std::vector<std::uint8_t>> Timeline::registers_at(std::uint64_t index) const {
  std::map<std::string, std::vector<std::uint8_t>> out;
  if (snaps_.empty() || index < snaps_.front().index) return out;
  std::size_t p = static_cast<std::size_t>(std::min(index, snaps_.back().index) - snaps_.front().index);
  std::size_t k = p;
  while (k > 0 && !snaps_[k].keyframe) --k;
  for (std::size_t i = k; i <= p; ++i)
    for (const auto &[n, v] : snaps_[i].registers) out[n] = v;
  return out;
}

std::vector<std::string> Timeline::changed_at(std::uint64_t index) const {
  std::vector<std::string> out;
  const Snapshot *s = find(index);
  if (s == nullptr || index == first()) return out;
  if (!s->keyframe) {
    const auto prev = registers_at(index - 1);
    for (const auto &[n, v] : s->registers) {
      auto it = prev.find(n);
      if (it == prev.end() || it->second != v) out.push_back(n);
    }
    return out;
  }
  const auto now = registers_at(index), prev = registers_at(index - 1);
  for (const auto &[n, v] : now) {
    auto it = prev.find(n);
    if (it == prev.end() || it->second != v) out.push_back(n);
  }
  return out;
}

std::vector<std::string> Timeline::changed_between(std::uint64_t since, std::uint64_t index) const {
  std::vector<std::string> out;
  if (find(since) == nullptr || find(index) == nullptr) return out;
  if (since + 1 == index) return changed_at(index);
  const auto now = registers_at(index), then = registers_at(since);
  for (const auto &[n, v] : now) {
    auto it = then.find(n);
    if (it == then.end() || it->second != v) out.push_back(n);
  }
  return out;
}

std::optional<std::uint64_t> Timeline::previous(std::uint64_t index) const {
  const Snapshot *s = find(index);
  if (s == nullptr || index == first()) return std::nullopt;
  if (s->kind == Snapshot::Kind::step) return index - 1;
  for (std::uint64_t i = index; i-- > first();)
    if (find(i)->kind != Snapshot::Kind::step) return i;
  return first();
}

void Timeline::memory_at(std::uint64_t index, std::uint64_t address, std::span<std::uint8_t> out,
                         std::vector<ByteState> &state, bool complete,
                         const std::function<void(std::uint64_t, std::span<std::uint8_t>, std::vector<bool> &)> &current) const {
  const std::size_t n = out.size();
  std::fill(out.begin(), out.end(), 0);
  state.assign(n, ByteState::unknown);
  if (n == 0) return;
  const std::uint64_t end = address + n;  // requests never wrap (checked by callers)
  auto overlap = [&](const MemoryRecord &m, auto &&fn) {
    const std::uint64_t lo = std::max(address, m.address), hi = std::min(end, m.address + m.bytes.size());
    for (std::uint64_t a = lo; a < hi; ++a) fn(static_cast<std::size_t>(a - address), static_cast<std::size_t>(a - m.address));
  };
  // The latest record at or before `index`.
  for (const Snapshot &s : snaps_) {
    if (s.index > index) break;
    const ByteState st = s.index == index ? ByteState::exact : ByteState::stale;
    for (const MemoryRecord &m : s.memory)
      overlap(m, [&](std::size_t i, std::size_t j) {
        out[i] = m.bytes[j];
        state[i] = st;
      });
  }
  if (!complete) return;
  // Every write was recorded: what was last seen is still the value.
  for (ByteState &b : state)
    if (b == ByteState::stale) b = ByteState::exact;
  // Bytes first touched later: a write's "before", or a read of an
  // unchanged byte. A gap (unrecorded steps) makes later ones uncertain.
  bool gap = false;
  std::vector<bool> resolved(n);
  for (std::size_t i = 0; i < n; ++i) resolved[i] = state[i] != ByteState::unknown;
  for (const Snapshot &s : snaps_) {
    if (s.index <= index) continue;
    if (s.gap) gap = true;
    for (const MemoryRecord &m : s.memory)
      overlap(m, [&](std::size_t i, std::size_t j) {
        if (resolved[i]) return;
        if (m.kind == MemoryRecord::Kind::write) {
          if (j >= m.before.size()) return;  // unknown before: leave unresolved
          out[i] = m.before[j];
        } else {
          out[i] = m.bytes[j];
        }
        state[i] = gap ? ByteState::stale : ByteState::exact;
        resolved[i] = true;
      });
  }
  for (const Snapshot &s : snaps_)
    if (s.index > index && s.gap) gap = true;
  // Never touched since: the value now.
  if (current) {
    std::vector<bool> readable(n, false);
    std::vector<std::uint8_t> now(n);
    current(address, now, readable);
    for (std::size_t i = 0; i < n; ++i)
      if (!resolved[i] && readable[i]) {
        out[i] = now[i];
        state[i] = gap ? ByteState::stale : ByteState::exact;
      }
  }
}

// --- Encoding ---

namespace {

class Writer {
 public:
  void u(std::uint64_t v) {
    while (v >= 0x80) {
      s += static_cast<char>((v & 0x7f) | 0x80);
      v >>= 7;
    }
    s += static_cast<char>(v);
  }
  void i(std::int64_t v) { u((static_cast<std::uint64_t>(v) << 1) ^ static_cast<std::uint64_t>(v >> 63)); }
  void str(std::string_view v) {
    u(v.size());
    s += v;
  }
  void bytes(const std::vector<std::uint8_t> &v) {
    u(v.size());
    s.append(reinterpret_cast<const char *>(v.data()), v.size());
  }
  std::string s;
};

class Reader {
 public:
  explicit Reader(std::string_view d) : d_(d) {}
  std::uint64_t u() {
    std::uint64_t v = 0;
    for (int shift = 0; shift < 64; shift += 7) {
      if (at_ >= d_.size()) bad();
      const std::uint8_t b = static_cast<std::uint8_t>(d_[at_++]);
      v |= std::uint64_t{b & 0x7fu} << shift;
      if ((b & 0x80) == 0) return v;
    }
    bad();
  }
  std::int64_t i() {
    const std::uint64_t v = u();
    return static_cast<std::int64_t>((v >> 1) ^ (~(v & 1) + 1));
  }
  std::size_t count(std::size_t max = 1u << 24) {
    const std::uint64_t n = u();
    if (n > max || n > d_.size() - at_ + 1) bad();
    return static_cast<std::size_t>(n);
  }
  std::string str() {
    const std::size_t n = count();
    if (at_ + n > d_.size()) bad();
    std::string out(d_.substr(at_, n));
    at_ += n;
    return out;
  }
  std::vector<std::uint8_t> bytes() {
    const std::string s = str();
    return std::vector<std::uint8_t>(s.begin(), s.end());
  }
  bool done() const { return at_ == d_.size(); }
  [[noreturn]] void bad() { throw DebugError("not a revkit trace, or a damaged one"); }

 private:
  std::string_view d_;
  std::size_t at_ = 0;
};

constexpr std::string_view kMagic{"RKTRACE\x02", 8};
// Version 1 (no snapshot events) still reads.
constexpr std::string_view kMagicV1{"RKTRACE\x01", 8};

}  // namespace

std::string Timeline::serialize(const TraceHeader &h) const {
  Writer w;
  w.s.append(kMagic);
  w.str(h.name);
  w.str(h.program_id);
  w.str(h.language);
  w.str(h.target_kind);
  w.str(h.target_description);
  w.str(h.pc_register);
  w.str(h.sp_register);
  w.u(h.registers.size());
  for (const RegisterDesc &r : h.registers) {
    w.str(r.name);
    w.str(r.target_name);
    w.u(r.size);
    w.u(r.display ? 1 : 0);
    w.str(r.group);
  }
  w.i(h.slide);
  w.u(h.modules.size());
  for (const ModuleInfo &m : h.modules) {
    w.str(m.name);
    w.str(m.path);
    w.u(m.base);
    w.u(m.load_bias);
    w.u(m.size);
    w.u(m.main ? 1 : 0);
  }
  w.i(h.created_unix);
  w.u(h.complete ? 1 : 0);
  w.u(next_);
  w.u(dropped_);
  w.u(snaps_.size());
  for (const Snapshot &s : snaps_) {
    w.u(s.index);
    w.u(static_cast<std::uint64_t>(s.kind));
    w.u(s.pc);
    w.u(s.program_pc ? 1 : 0);
    if (s.program_pc) w.u(*s.program_pc);
    w.str(s.thread);
    w.u(s.steps);
    w.u(static_cast<std::uint64_t>(s.stop));
    w.str(s.detail);
    w.str(s.text);
    w.u(s.keyframe ? 1 : 0);
    w.u(s.registers.size());
    for (const auto &[n, v] : s.registers) {
      w.str(n);
      w.bytes(v);
    }
    w.u(s.memory.size());
    for (const MemoryRecord &m : s.memory) {
      w.u(m.address);
      w.u(static_cast<std::uint64_t>(m.kind));
      w.bytes(m.bytes);
      w.bytes(m.before);
    }
    w.i(s.time_us);
    w.u(s.gap ? 1 : 0);
    w.str(s.event);
    w.i(s.event_number);
  }
  return w.s;
}

static void read_header(Reader &r, TraceHeader &h) {
  h = TraceHeader{};
  h.name = r.str();
  h.program_id = r.str();
  h.language = r.str();
  h.target_kind = r.str();
  h.target_description = r.str();
  h.pc_register = r.str();
  h.sp_register = r.str();
  for (std::size_t n = r.count(1u << 20); n > 0; --n) {
    RegisterDesc d;
    d.name = r.str();
    d.target_name = r.str();
    d.size = static_cast<std::uint32_t>(r.u());
    d.display = r.u() != 0;
    d.group = r.str();
    h.registers.push_back(d);
  }
  h.slide = r.i();
  for (std::size_t n = r.count(1u << 20); n > 0; --n) {
    ModuleInfo m;
    m.name = r.str();
    m.path = r.str();
    m.base = r.u();
    m.load_bias = r.u();
    m.size = r.u();
    m.main = r.u() != 0;
    h.modules.push_back(m);
  }
  h.created_unix = r.i();
  h.complete = r.u() != 0;
}

TraceHeader Timeline::peek(std::string_view data, std::uint64_t *snapshots) {
  if (data.substr(0, kMagic.size()) != kMagic && data.substr(0, kMagicV1.size()) != kMagicV1)
    throw DebugError("not a revkit trace");
  Reader r(data.substr(kMagic.size()));
  TraceHeader h;
  read_header(r, h);
  r.u();  // next
  r.u();  // dropped
  const std::uint64_t n = r.u();
  if (snapshots != nullptr) *snapshots = n;
  return h;
}

Timeline Timeline::deserialize(std::string_view data, TraceHeader &h) {
  const bool v1 = data.substr(0, kMagicV1.size()) == kMagicV1;
  if (data.substr(0, kMagic.size()) != kMagic && !v1) throw DebugError("not a revkit trace");
  Reader r(data.substr(kMagic.size()));
  read_header(r, h);
  Timeline t(Limits{~std::size_t{0}, ~std::uint64_t{0}});
  t.next_ = r.u();
  t.dropped_ = r.u();
  for (std::size_t n = r.count(); n > 0; --n) {
    Snapshot s;
    s.index = r.u();
    const auto kind = r.u();
    if (kind > 2) r.bad();
    s.kind = static_cast<Snapshot::Kind>(kind);
    s.pc = r.u();
    if (r.u() != 0) s.program_pc = r.u();
    s.thread = r.str();
    s.steps = r.u();
    const auto stop = r.u();
    if (stop > static_cast<std::uint64_t>(StopKind::idle)) r.bad();
    s.stop = static_cast<StopKind>(stop);
    s.detail = r.str();
    s.text = r.str();
    s.keyframe = r.u() != 0;
    for (std::size_t k = r.count(); k > 0; --k) {
      std::string name = r.str();
      s.registers.emplace_back(std::move(name), r.bytes());
    }
    for (std::size_t k = r.count(); k > 0; --k) {
      MemoryRecord m;
      m.address = r.u();
      const auto mk = r.u();
      if (mk > 2) r.bad();
      m.kind = static_cast<MemoryRecord::Kind>(mk);
      m.bytes = r.bytes();
      m.before = r.bytes();
      s.memory.push_back(std::move(m));
    }
    s.time_us = r.i();
    s.gap = r.u() != 0;
    if (!v1) {
      s.event = r.str();
      s.event_number = static_cast<std::int32_t>(r.i());
    }
    if (!t.snaps_.empty() && s.index != t.snaps_.back().index + 1) r.bad();
    if (t.snaps_.empty() && !s.keyframe) s.keyframe = true;
    t.bytes_ += cost(s);
    t.snaps_.push_back(std::move(s));
  }
  if (!r.done()) r.bad();
  if (!t.snaps_.empty() && t.next_ <= t.snaps_.back().index) t.next_ = t.snaps_.back().index + 1;
  return t;
}

namespace {

std::string json_string(std::string_view s) {
  std::string out = "\"";
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\t': out += "\\t"; break;
      case '\r': out += "\\r"; break;
      default:
        if (c < 0x20) {
          char b[8];
          std::snprintf(b, sizeof b, "\\u%04x", c);
          out += b;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out + "\"";
}

std::string hex_bytes(const std::vector<std::uint8_t> &v) {
  static const char *d = "0123456789abcdef";
  std::string s;
  for (std::uint8_t b : v) {
    s += d[b >> 4];
    s += d[b & 15];
  }
  return s;
}

std::string hex_le(const std::vector<std::uint8_t> &v) {
  std::vector<std::uint8_t> be(v.rbegin(), v.rend());
  std::string s = hex_bytes(be);
  const auto nz = s.find_first_not_of('0');
  return "0x" + (nz == std::string::npos ? "0" : s.substr(nz));
}

}  // namespace

std::string Timeline::to_json(const TraceHeader &h) const {
  std::ostringstream o;
  o << "{\"name\":" << json_string(h.name) << ",\"program\":" << json_string(h.program_id)
    << ",\"language\":" << json_string(h.language) << ",\"target\":" << json_string(h.target_kind)
    << ",\"description\":" << json_string(h.target_description) << ",\"slide\":" << h.slide
    << ",\"complete\":" << (h.complete ? "true" : "false") << ",\"dropped\":" << dropped_ << ",\"modules\":[";
  for (std::size_t i = 0; i < h.modules.size(); ++i) {
    const ModuleInfo &m = h.modules[i];
    o << (i ? "," : "") << "{\"name\":" << json_string(m.name) << ",\"base\":\"" << hex(m.base) << "\",\"bias\":\""
      << hex(m.load_bias) << "\",\"size\":" << m.size << (m.main ? ",\"main\":true" : "") << "}";
  }
  o << "],\"snapshots\":[";
  bool first_snap = true;
  for (const Snapshot &s : snaps_) {
    o << (first_snap ? "" : ",") << "\n{\"index\":" << s.index << ",\"kind\":\"" << to_string(s.kind) << "\",\"pc\":\""
      << hex(s.pc) << "\"";
    first_snap = false;
    if (s.program_pc) o << ",\"program_pc\":\"" << hex(*s.program_pc) << "\"";
    if (!s.thread.empty()) o << ",\"thread\":" << json_string(s.thread);
    o << ",\"steps\":" << s.steps;
    if (s.kind == Snapshot::Kind::stop) o << ",\"stop\":\"" << to_string(s.stop) << "\"";
    if (!s.detail.empty()) o << ",\"detail\":" << json_string(s.detail);
    if (!s.text.empty()) o << ",\"text\":" << json_string(s.text);
    if (s.gap) o << ",\"gap\":true";
    if (!s.event.empty()) {
      o << ",\"event\":" << json_string(s.event);
      if (s.event_number >= 0) o << ",\"event_number\":" << s.event_number;
    }
    o << ",\"time_us\":" << s.time_us << ",\"" << (s.keyframe ? "registers" : "changed") << "\":{";
    for (std::size_t i = 0; i < s.registers.size(); ++i)
      o << (i ? "," : "") << json_string(s.registers[i].first) << ":\"" << hex_le(s.registers[i].second) << "\"";
    o << "},\"memory\":[";
    for (std::size_t i = 0; i < s.memory.size(); ++i) {
      const MemoryRecord &m = s.memory[i];
      const char *k = m.kind == MemoryRecord::Kind::observed ? "observed" : m.kind == MemoryRecord::Kind::read ? "read" : "write";
      o << (i ? "," : "") << "{\"address\":\"" << hex(m.address) << "\",\"kind\":\"" << k << "\",\"bytes\":\""
        << hex_bytes(m.bytes) << "\"";
      if (!m.before.empty()) o << ",\"before\":\"" << hex_bytes(m.before) << "\"";
      o << "}";
    }
    o << "]}";
  }
  o << "]}\n";
  return o.str();
}

}  // namespace revkit::debug
