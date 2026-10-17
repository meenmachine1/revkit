// Register values over address ranges as queries (register_values.h).

#include "revkit/analysis/register_values.h"

#include "revkit/facts/fact_db.h"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <map>
#include <tuple>

namespace revkit::analysis {

using facts::Decoder;
using facts::Encoder;

// ---- assertions ----

std::string register_value_sub(std::string_view reg, std::uint64_t length) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(length));
  return std::string(reg) + ":" + buf;
}

std::optional<RegisterValueSub> parse_register_value_sub(std::string_view sub) {
  const auto colon = sub.rfind(':');
  if (colon == std::string_view::npos || colon == 0 || colon + 1 >= sub.size()) return std::nullopt;
  RegisterValueSub out;
  out.reg = std::string(sub.substr(0, colon));
  const std::string_view hex = sub.substr(colon + 1);
  auto [p, ec] = std::from_chars(hex.data(), hex.data() + hex.size(), out.length, 16);
  if (ec != std::errc() || p != hex.data() + hex.size() || out.length == 0) return std::nullopt;
  return out;
}

std::string register_value_text(std::optional<std::uint64_t> value) {
  if (!value) return std::string(kRegisterValueNone);
  char buf[24];
  std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(*value));
  return buf;
}

std::optional<std::optional<std::uint64_t>> parse_register_value_text(std::string_view text) {
  if (text == kRegisterValueNone) return std::optional<std::uint64_t>{};
  if (text.empty() || text.size() > 16) return std::nullopt;
  std::uint64_t v = 0;
  auto [p, ec] = std::from_chars(text.data(), text.data() + text.size(), v, 16);
  if (ec != std::errc() || p != text.data() + text.size()) return std::nullopt;
  return std::optional<std::uint64_t>{v};
}

// ---- codecs ----

void RegisterValuePiece::encode(Encoder &e) const {
  e.varint(first);
  e.varint(last);
  e.varint(value);
  e.u8(asserted ? 1 : 0);
  e.varint(start);
  e.bytes(sub);
  e.bytes(origin);
}

RegisterValuePiece RegisterValuePiece::decode(Decoder &d) {
  RegisterValuePiece p;
  p.first = d.varint();
  p.last = d.varint();
  p.value = d.varint();
  p.asserted = d.u8() != 0;
  p.start = d.varint();
  p.sub = std::string(d.bytes());
  p.origin = std::string(d.bytes());
  return p;
}

void RegisterRanges::encode(Encoder &e) const {
  e.bytes(name);
  facts::encode(e, slot);
  facts::encode(e, pieces);
}

RegisterRanges RegisterRanges::decode(Decoder &d) {
  RegisterRanges r;
  r.name = std::string(d.bytes());
  r.slot = facts::decode<RegisterSlot>(d);
  r.pieces = facts::decode<std::vector<RegisterValuePiece>>(d);
  return r;
}

const RegisterValuePiece *RegisterRanges::at(std::uint64_t a) const {
  auto it = std::upper_bound(pieces.begin(), pieces.end(), a, [](std::uint64_t x, const RegisterValuePiece &p) { return x < p.first; });
  if (it == pieces.begin()) return nullptr;
  --it;
  return a <= it->last ? &*it : nullptr;
}

void RegisterValueMap::encode(Encoder &e) const { facts::encode(e, registers); }

RegisterValueMap RegisterValueMap::decode(Decoder &d) {
  RegisterValueMap m;
  m.registers = facts::decode<std::vector<RegisterRanges>>(d);
  return m;
}

const RegisterRanges *RegisterValueMap::find(std::string_view name) const {
  for (const RegisterRanges &r : registers)
    if (r.name == name) return &r;
  return nullptr;
}

void RegisterValueSpan::encode(Encoder &e) const {
  e.varint(first);
  e.varint(last);
  facts::encode(e, slot);
  e.varint(value);
}

RegisterValueSpan RegisterValueSpan::decode(Decoder &d) {
  RegisterValueSpan s;
  s.first = d.varint();
  s.last = d.varint();
  s.slot = facts::decode<RegisterSlot>(d);
  s.value = d.varint();
  return s;
}

// ---- queries ----

namespace {

std::uint64_t last_of(std::uint64_t start, std::uint64_t length) {
  if (length == 0) length = 1;
  return start + (length - 1) < start ? ~std::uint64_t{0} : start + (length - 1);
}

// One register's marks, lowest first: what paints its pieces.
struct Mark {
  std::uint64_t first = 0, last = 0;
  std::optional<std::uint64_t> value;
  bool asserted = false;
  std::uint64_t start = 0;
  std::string sub, origin;
};

// Paints [first, last] for mark `m` over `pieces` (first -> (last, mark)).
void paint(std::map<std::uint64_t, std::pair<std::uint64_t, std::uint32_t>> &pieces, std::uint64_t first,
           std::uint64_t last, std::uint32_t m) {
  auto it = pieces.upper_bound(first);
  if (it != pieces.begin()) {
    auto prev = std::prev(it);
    if (prev->first < first && prev->second.first >= first) {
      const auto [plast, pm] = prev->second;
      prev->second.first = first - 1;
      if (plast > last) pieces.emplace(last + 1, std::pair{plast, pm});
    }
  }
  it = pieces.lower_bound(first);
  while (it != pieces.end() && it->first <= last) {
    const auto [plast, pm] = it->second;
    it = pieces.erase(it);
    if (plast > last) {
      pieces.emplace(last + 1, std::pair{plast, pm});
      break;
    }
  }
  pieces.emplace(first, std::pair{last, m});
}

}  // namespace

RegisterValues::Value RegisterValues::compute(facts::QueryContext &ctx, const Key &key) {
  auto info = ctx.get<Program>(key);
  const facts::SpaceId space = info->space;
  // name -> (slot, marks lowest first)
  std::map<std::string, std::pair<RegisterSlot, std::vector<Mark>>> regs;
  for (const RegisterDefault &d : info->register_defaults) {
    auto &[slot, marks] = regs[d.name];
    slot = d.slot;
    marks.push_back({d.range.first, d.range.last, d.value, false, 0, {}, d.origin});
  }
  struct Asserted {
    std::string order;
    std::uint64_t start;
    std::string sub;
    NamedRegister reg;
    std::uint64_t length;
    std::optional<std::uint64_t> value;
  };
  std::vector<Asserted> asserted;
  for (const facts::FactKey &k : facts::asserted_keys(ctx, facts::FactKind::RegisterValue, {space, 0}, {space, ~std::uint64_t{0}})) {
    auto v = ctx.get<facts::AssertedFact>(k);
    const std::string *text = std::get_if<std::string>(&*v);
    if (text == nullptr || text->empty()) continue;
    auto sub = parse_register_value_sub(k.sub);
    auto value = parse_register_value_text(*text);
    if (!sub || !value) continue;
    auto reg = find_register(*info, sub->reg);
    if (!reg) continue;  // not a register of this language (the language changed)
    if (*value && reg->slot.second < 8) **value &= (std::uint64_t{1} << (8 * reg->slot.second)) - 1;
    asserted.push_back({*ctx.get<facts::AssertedOrder>(k), k.addr.offset, k.sub, *reg, sub->length, *value});
  }
  std::sort(asserted.begin(), asserted.end(),
            [](const Asserted &a, const Asserted &b) { return std::tie(a.order, a.start, a.sub) < std::tie(b.order, b.start, b.sub); });
  for (const Asserted &a : asserted) {
    auto &[slot, marks] = regs[a.reg.name];
    slot = a.reg.slot;
    marks.push_back({a.start, last_of(a.start, a.length), a.value, true, a.start, a.sub, {}});
  }
  Value out;
  for (auto &[name, entry] : regs) {
    auto &[slot, marks] = entry;
    std::map<std::uint64_t, std::pair<std::uint64_t, std::uint32_t>> pieces;
    for (std::uint32_t i = 0; i < marks.size(); ++i) paint(pieces, marks[i].first, marks[i].last, i);
    RegisterRanges r{name, slot, {}};
    for (const auto &[first, rest] : pieces) {
      const Mark &m = marks[rest.second];
      if (!m.value) continue;
      // Neighbouring pieces of one mark (split by nothing) stay one.
      if (!r.pieces.empty()) {
        RegisterValuePiece &b = r.pieces.back();
        if (b.last + 1 == first && b.value == *m.value && b.asserted == m.asserted && b.start == m.start && b.sub == m.sub &&
            b.origin == m.origin) {
          b.last = rest.first;
          continue;
        }
      }
      r.pieces.push_back({first, rest.first, *m.value, m.asserted, m.start, m.sub, m.origin});
    }
    if (!r.pieces.empty()) out.registers.push_back(std::move(r));
  }
  return out;
}

RegisterValueSlots::Value RegisterValueSlots::compute(facts::QueryContext &ctx, const Key &key) {
  auto map = ctx.get<RegisterValues>(key);
  Value out;
  for (const RegisterRanges &r : map->registers) out.push_back(r.slot);
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

RegisterValueBucket::Value RegisterValueBucket::compute(facts::QueryContext &ctx, const Key &key) {
  auto map = ctx.get<RegisterValues>(key.program);
  const std::uint64_t lo = key.address << facts::kBucketShift;
  const std::uint64_t hi = lo + ((std::uint64_t{1} << facts::kBucketShift) - 1);
  Value out;
  for (const RegisterRanges &r : map->registers) {
    auto it = std::upper_bound(r.pieces.begin(), r.pieces.end(), lo, [](std::uint64_t x, const RegisterValuePiece &p) { return x < p.first; });
    if (it != r.pieces.begin()) --it;
    for (; it != r.pieces.end() && it->first <= hi; ++it) {
      if (it->last < lo) continue;
      out.push_back({std::max(it->first, lo), std::min(it->last, hi), r.slot, it->value});
    }
  }
  std::sort(out.begin(), out.end(), [](const RegisterValueSpan &a, const RegisterValueSpan &b) { return std::tie(a.first, a.slot) < std::tie(b.first, b.slot); });
  return out;
}

RegisterValuesAt::Value RegisterValuesAt::compute(facts::QueryContext &ctx, const Key &key) {
  auto info = ctx.get<Program>(key.program);
  auto slots = ctx.get<RegisterValueSlots>(key.program);
  Value out;
  if (slots->empty() && info->register_defaults.empty()) return out;
  auto map = ctx.get<RegisterValues>(key.program);
  std::map<std::string, std::optional<std::uint64_t>> by_name;
  for (const RegisterDefault &d : info->register_defaults) by_name.emplace(d.name, std::nullopt);
  for (const RegisterRanges &r : map->registers) {
    const RegisterValuePiece *p = r.at(key.address);
    by_name[r.name] = p ? std::optional(p->value) : std::nullopt;
  }
  out.assign(by_name.begin(), by_name.end());
  return out;
}

// ---- the reader ----

RegisterValueReader::RegisterValueReader(facts::QueryContext &ctx, const ProgramKey &program)
    : ctx_(ctx), program_(program), slots_(ctx.get<RegisterValueSlots>(program)) {}

const std::vector<RegisterValueSpan> &RegisterValueReader::bucket(std::uint64_t index) {
  for (const auto &[i, ref] : buckets_)
    if (i == index) return *ref;
  buckets_.emplace_back(index, ctx_.get<RegisterValueBucket>(Location{program_, index}));
  return *buckets_.back().second;
}

std::optional<std::uint64_t> RegisterValueReader::value(std::uint64_t a, std::uint64_t offset, std::uint32_t size,
                                                        bool big_endian) {
  if (slots_->empty() || size == 0) return std::nullopt;
  // Only slots that hold the read.
  bool any = false;
  for (const RegisterSlot &s : *slots_)
    if (offset >= s.first && offset + size <= s.first + s.second) any = true;
  if (!any) return std::nullopt;
  for (const RegisterValueSpan &s : bucket(a >> facts::kBucketShift)) {
    if (s.first > a) break;
    if (a > s.last) continue;
    const auto [so, ss] = s.slot;
    if (offset == so && size == ss) return s.value;
    if (size >= ss) continue;
    const std::uint64_t mask = (std::uint64_t{1} << (8 * size)) - 1;
    // The low part: at the slot's start (little-endian), or ending where
    // it ends (big-endian: MIPS and PowerPC read a 64-bit register's low
    // 32 bits at offset + 4).
    if (!big_endian && offset == so) return s.value & mask;
    if (big_endian && offset + size == so + ss) return s.value & mask;
  }
  return std::nullopt;
}

std::vector<std::pair<RegisterSlot, std::uint64_t>> RegisterValueReader::values_at(std::uint64_t a) {
  std::vector<std::pair<RegisterSlot, std::uint64_t>> out;
  if (slots_->empty()) return out;
  for (const RegisterValueSpan &s : bucket(a >> facts::kBucketShift)) {
    if (s.first > a) break;
    if (a <= s.last) out.emplace_back(s.slot, s.value);
  }
  return out;
}

void register_register_value_queries(facts::Engine &engine) {
  engine.add_query<RegisterValues>();
  engine.add_query<RegisterValueSlots>();
  engine.add_query<RegisterValueBucket>();
  engine.add_query<RegisterValuesAt>();
}

}  // namespace revkit::analysis
