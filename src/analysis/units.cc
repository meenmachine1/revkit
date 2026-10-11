// The listing's edits as queries (units.h, docs/listing-edit.md).

#include "revkit/analysis/units.h"

#include <algorithm>
#include <cstdio>
#include <map>

namespace revkit::analysis {

using facts::Decoder;
using facts::Encoder;

namespace {

constexpr std::uint8_t kMarkVersion = 1;

std::uint64_t last_of(std::uint64_t start, std::uint64_t length) {
  if (length == 0) length = 1;
  return start + (length - 1) < start ? ~std::uint64_t{0} : start + (length - 1);
}

template <class E>
E checked(std::uint8_t v, std::uint8_t max, const char *what) {
  if (v > max) throw facts::DecodeError(what);
  return static_cast<E>(v);
}

// Paints [first, last] for mark `m` over `pieces` (first -> (last, mark)).
void paint(std::map<std::uint64_t, std::pair<std::uint64_t, std::uint32_t>> &pieces, std::uint64_t first,
           std::uint64_t last, std::uint32_t m) {
  auto it = pieces.upper_bound(first);
  if (it != pieces.begin()) {
    auto prev = std::prev(it);
    if (prev->first < first && prev->second.first >= first) {
      // Split the piece that starts before and reaches into the new one.
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

std::string hex_length(std::uint64_t n) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(n));
  return buf;
}

std::string unit_sub(const UnitMark &m) {
  switch (m.kind) {
    case UnitKind::clear: return std::string(kUnitClearPrefix) + hex_length(m.length);
    case UnitKind::code: return std::string(kUnitCode);
    case UnitKind::data: return std::string(kUnitData);
  }
  return {};
}

// ---- values ----

void DataField::encode(Encoder &e) const {
  e.varint(offset);
  e.varint(size);
  e.bytes(name);
  e.bytes(type);
  e.u8(static_cast<std::uint8_t>(format));
  e.varint(depth);
}

DataField DataField::decode(Decoder &d) {
  DataField f;
  f.offset = d.varint();
  f.size = d.varint();
  f.name = std::string(d.bytes());
  f.type = std::string(d.bytes());
  f.format = checked<ValueFormat>(d.u8(), static_cast<std::uint8_t>(ValueFormat::string), "bad value format");
  f.depth = static_cast<std::uint32_t>(d.varint());
  return f;
}

void DataSpec::encode(Encoder &e) const {
  e.bytes(type);
  e.bytes(type_name);
  e.bytes(item_type);
  e.bytes(item_name);
  e.varint(element);
  e.varint(count);
  e.u8(static_cast<std::uint8_t>(string));
  e.u8(static_cast<std::uint8_t>(layout));
  e.u8(static_cast<std::uint8_t>(format));
  e.u8(collapsed ? 1 : 0);
  facts::encode(e, fields);
  facts::encode(e, pointers);
  e.u8(pointer_size);
}

DataSpec DataSpec::decode(Decoder &d) {
  DataSpec s;
  s.type = std::string(d.bytes());
  s.type_name = std::string(d.bytes());
  s.item_type = std::string(d.bytes());
  s.item_name = std::string(d.bytes());
  s.element = d.varint();
  s.count = d.varint();
  s.string = checked<StringKind>(d.u8(), static_cast<std::uint8_t>(StringKind::utf32), "bad string kind");
  s.layout = checked<StringLayout>(d.u8(), static_cast<std::uint8_t>(StringLayout::pascal16), "bad string layout");
  s.format = checked<ValueFormat>(d.u8(), static_cast<std::uint8_t>(ValueFormat::string), "bad value format");
  s.collapsed = d.u8() != 0;
  s.fields = facts::decode<std::vector<DataField>>(d);
  s.pointers = facts::decode<std::vector<std::uint64_t>>(d);
  s.pointer_size = d.u8();
  return s;
}

void UnitMark::encode(Encoder &e) const {
  e.u8(kMarkVersion);
  e.u8(static_cast<std::uint8_t>(kind));
  e.varint(length);
  switch (kind) {
    case UnitKind::clear: break;
    case UnitKind::code:
      e.u8(static_cast<std::uint8_t>(isa));
      e.u8(function ? 1 : 0);
      break;
    case UnitKind::data: data.encode(e); break;
  }
}

UnitMark UnitMark::decode(Decoder &d) {
  if (d.u8() != kMarkVersion) throw facts::DecodeError("unknown unit mark version");
  UnitMark m;
  const std::uint8_t k = d.u8();
  if (k < 1 || k > 3) throw facts::DecodeError("bad unit kind");
  m.kind = static_cast<UnitKind>(k);
  m.length = d.varint();
  switch (m.kind) {
    case UnitKind::clear: break;
    case UnitKind::code:
      m.isa = checked<Isa>(d.u8(), static_cast<std::uint8_t>(Isa::thumb), "bad instruction set");
      m.function = d.u8() != 0;
      break;
    case UnitKind::data: m.data = DataSpec::decode(d); break;
  }
  return m;
}

void MutabilityMark::encode(Encoder &e) const {
  e.u8(kMarkVersion);
  e.varint(length);
  e.u8(static_cast<std::uint8_t>(kind));
}

MutabilityMark MutabilityMark::decode(Decoder &d) {
  if (d.u8() != kMarkVersion) throw facts::DecodeError("unknown mutability mark version");
  MutabilityMark m;
  m.length = d.varint();
  const std::uint8_t k = d.u8();
  if (k < 1 || k > 4) throw facts::DecodeError("bad mutability");
  m.kind = static_cast<MutabilityKind>(k);
  return m;
}

const UnitPiece *UnitMap::at(std::uint64_t a) const {
  auto it = std::upper_bound(pieces.begin(), pieces.end(), a, [](std::uint64_t x, const UnitPiece &p) { return x < p.first; });
  if (it == pieces.begin()) return nullptr;
  --it;
  return a <= it->last ? &*it : nullptr;
}

const UnitMap::Mark *UnitMap::owner(std::uint64_t a) const {
  const UnitPiece *p = at(a);
  return p ? &marks[p->mark] : nullptr;
}

std::vector<UnitPiece> UnitMap::overlapping(std::uint64_t first, std::uint64_t last) const {
  std::vector<UnitPiece> out;
  auto it = std::upper_bound(pieces.begin(), pieces.end(), first, [](std::uint64_t x, const UnitPiece &p) { return x < p.first; });
  if (it != pieces.begin() && std::prev(it)->last >= first) --it;
  for (; it != pieces.end() && it->first <= last; ++it) out.push_back(*it);
  return out;
}

void UnitMap::encode(Encoder &e) const {
  e.varint(marks.size());
  for (const Mark &m : marks) {
    e.varint(m.start);
    e.bytes(m.sub);
    e.bytes(m.order);
    m.mark.encode(e);
    e.u8(m.alive ? 1 : 0);
    e.varint(m.key);
  }
  e.varint(pieces.size());
  for (const UnitPiece &p : pieces) {
    e.varint(p.first);
    e.varint(p.last);
    e.varint(p.mark);
  }
}

UnitMap UnitMap::decode(Decoder &d) {
  UnitMap out;
  const std::size_t n = d.count();
  for (std::size_t i = 0; i < n; ++i) {
    Mark m;
    m.start = d.varint();
    m.sub = std::string(d.bytes());
    m.order = std::string(d.bytes());
    m.mark = UnitMark::decode(d);
    m.alive = d.u8() != 0;
    m.key = d.varint();
    out.marks.push_back(std::move(m));
  }
  const std::size_t k = d.count();
  for (std::size_t i = 0; i < k; ++i) {
    UnitPiece p;
    p.first = d.varint();
    p.last = d.varint();
    p.mark = static_cast<std::uint32_t>(d.varint());
    if (p.mark >= out.marks.size()) throw facts::DecodeError("bad unit piece");
    out.pieces.push_back(p);
  }
  return out;
}

void UnitSpan::encode(Encoder &e) const {
  e.varint(first);
  e.varint(last);
  e.u8(static_cast<std::uint8_t>(state));
  e.bytes(order);
  e.varint(key);
}

UnitSpan UnitSpan::decode(Decoder &d) {
  UnitSpan s;
  s.first = d.varint();
  s.last = d.varint();
  s.state = checked<UnitState>(d.u8(), static_cast<std::uint8_t>(UnitState::data), "bad unit state");
  s.order = std::string(d.bytes());
  s.key = d.varint();
  return s;
}

bool UnitCodeInfo::is_blocked(std::uint64_t a) const {
  auto it = std::upper_bound(blocked.begin(), blocked.end(), a, [](std::uint64_t x, const Range &r) { return x < r.first; });
  return it != blocked.begin() && std::prev(it)->contains(a);
}

void UnitCodeInfo::encode(Encoder &e) const {
  e.varint(entries.size());
  for (const Entry &x : entries) {
    e.varint(x.key);
    e.u8(x.function ? 1 : 0);
  }
  facts::encode(e, blocked);
}

UnitCodeInfo UnitCodeInfo::decode(Decoder &d) {
  UnitCodeInfo out;
  const std::size_t n = d.count();
  for (std::size_t i = 0; i < n; ++i) {
    Entry x;
    x.key = d.varint();
    x.function = d.u8() != 0;
    out.entries.push_back(x);
  }
  out.blocked = facts::decode<std::vector<Range>>(d);
  return out;
}

void MutabilityPiece::encode(Encoder &e) const {
  e.varint(first);
  e.varint(last);
  e.u8(static_cast<std::uint8_t>(kind));
  e.varint(start);
  e.bytes(sub);
}

MutabilityPiece MutabilityPiece::decode(Decoder &d) {
  MutabilityPiece p;
  p.first = d.varint();
  p.last = d.varint();
  const std::uint8_t k = d.u8();
  if (k < 1 || k > 4) throw facts::DecodeError("bad mutability");
  p.kind = static_cast<MutabilityKind>(k);
  p.start = d.varint();
  p.sub = std::string(d.bytes());
  return p;
}

const MutabilityPiece *mutability_at(const std::vector<MutabilityPiece> &map, std::uint64_t a) {
  auto it = std::upper_bound(map.begin(), map.end(), a, [](std::uint64_t x, const MutabilityPiece &p) { return x < p.first; });
  if (it == map.begin()) return nullptr;
  --it;
  return a <= it->last ? &*it : nullptr;
}

// ---- queries ----

Units::Value Units::compute(facts::QueryContext &ctx, const Key &key) {
  auto info = ctx.get<Program>(key);
  const facts::SpaceId space = info->space;
  UnitMap out;
  for (const facts::FactKey &k :
       facts::asserted_keys(ctx, facts::FactKind::CodeUnit, {space, 0}, {space, ~std::uint64_t{0}})) {
    auto v = ctx.get<facts::AssertedFact>(k);
    const std::string *bytes = std::get_if<std::string>(&*v);
    if (bytes == nullptr || bytes->empty()) continue;
    UnitMap::Mark m;
    try {
      m.mark = facts::decode_from_string<UnitMark>(*bytes);
    } catch (const facts::DecodeError &) {
      continue;
    }
    m.start = k.addr.offset;
    m.sub = k.sub;
    m.order = *ctx.get<facts::AssertedOrder>(k);
    if (m.mark.kind == UnitKind::code) {
      m.mark.length = 1;
      const bool thumb = m.mark.isa == Isa::thumb ? true : m.mark.isa == Isa::arm ? false : info->thumb(m.start);
      m.key = info->code_key(m.start, thumb);
    }
    out.marks.push_back(std::move(m));
  }
  // Lowest first, so the winner of an overlap paints last.
  std::sort(out.marks.begin(), out.marks.end(), [](const UnitMap::Mark &a, const UnitMap::Mark &b) {
    return std::tie(a.order, a.start, a.sub) < std::tie(b.order, b.start, b.sub);
  });
  std::map<std::uint64_t, std::pair<std::uint64_t, std::uint32_t>> pieces;
  for (std::uint32_t i = 0; i < out.marks.size(); ++i) {
    const UnitMap::Mark &m = out.marks[i];
    paint(pieces, m.start, last_of(m.start, m.mark.length), i);
  }
  std::vector<std::uint64_t> owned(out.marks.size(), 0);
  for (const auto &[first, rest] : pieces) {
    out.pieces.push_back({first, rest.first, rest.second});
    owned[rest.second] += rest.first - first + 1;
  }
  for (std::uint32_t i = 0; i < out.marks.size(); ++i) {
    UnitMap::Mark &m = out.marks[i];
    if (m.mark.kind == UnitKind::data) m.alive = owned[i] == last_of(m.start, m.mark.length) - m.start + 1;
  }
  return out;
}

UnitBucket::Value UnitBucket::compute(facts::QueryContext &ctx, const Key &key) {
  auto map = ctx.get<Units>(key.program);
  const std::uint64_t lo = key.address << facts::kBucketShift;
  const std::uint64_t hi = lo + ((std::uint64_t{1} << facts::kBucketShift) - 1);
  Value out;
  for (const UnitPiece &p : map->overlapping(lo, hi)) {
    const UnitMap::Mark &m = map->marks[p.mark];
    UnitSpan s;
    s.first = p.first;
    s.last = p.last;
    s.order = m.order;
    switch (m.mark.kind) {
      case UnitKind::code:
        s.state = UnitState::code;
        s.key = m.key;
        break;
      case UnitKind::data: s.state = m.alive ? UnitState::data : UnitState::cleared; break;
      case UnitKind::clear: s.state = UnitState::cleared; break;
    }
    out.push_back(std::move(s));
  }
  return out;
}

UnitCode::Value UnitCode::compute(facts::QueryContext &ctx, const Key &key) {
  auto info = ctx.get<Program>(key);
  auto map = ctx.get<Units>(key);
  UnitCodeInfo out;
  std::vector<Range> blocked;
  for (const UnitMap::Mark &m : map->marks)
    if (m.mark.kind == UnitKind::code) out.entries.push_back({m.key, m.mark.function});
  std::sort(out.entries.begin(), out.entries.end(), [](const auto &a, const auto &b) { return a.key < b.key; });
  for (const UnitPiece &p : map->pieces) {
    if (map->marks[p.mark].mark.kind == UnitKind::code) continue;
    // Within code only: data defined elsewhere doesn't concern discovery.
    auto it = std::upper_bound(info->code.begin(), info->code.end(), p.first,
                               [](std::uint64_t x, const Range &r) { return x < r.first; });
    if (it != info->code.begin()) --it;
    for (; it != info->code.end() && it->first <= p.last; ++it) {
      const std::uint64_t f = std::max(it->first, p.first), l = std::min(it->last, p.last);
      if (f <= l) blocked.push_back({f, l});
    }
  }
  std::sort(blocked.begin(), blocked.end());
  for (const Range &r : blocked) {
    if (!out.blocked.empty() && out.blocked.back().last != ~std::uint64_t{0} && r.first <= out.blocked.back().last + 1)
      out.blocked.back().last = std::max(out.blocked.back().last, r.last);
    else
      out.blocked.push_back(r);
  }
  return out;
}

const std::vector<UnitSpan> &UnitReader::bucket(std::uint64_t index) {
  for (const auto &[i, ref] : buckets_)
    if (i == index) return *ref;
  buckets_.emplace_back(index, ctx_.get<UnitBucket>(Location{program_, index}));
  return *buckets_.back().second;
}

const UnitSpan *UnitReader::at(std::uint64_t a) {
  const std::vector<UnitSpan> &b = bucket(a >> facts::kBucketShift);
  auto it = std::upper_bound(b.begin(), b.end(), a, [](std::uint64_t x, const UnitSpan &s) { return x < s.first; });
  if (it == b.begin()) return nullptr;
  --it;
  return a <= it->last ? &*it : nullptr;
}

const UnitSpan *UnitReader::overlapping(std::uint64_t first, std::uint64_t last) {
  for (std::uint64_t index = first >> facts::kBucketShift;; ++index) {
    const std::vector<UnitSpan> &b = bucket(index);
    for (const UnitSpan &s : b)
      if (s.first <= last && s.last >= first) return &s;
    if (index >= (last >> facts::kBucketShift)) break;
  }
  return nullptr;
}

MutabilityMap::Value MutabilityMap::compute(facts::QueryContext &ctx, const Key &key) {
  auto info = ctx.get<Program>(key);
  const facts::SpaceId space = info->space;
  struct M {
    std::string order;
    std::uint64_t start;
    std::string sub;
    MutabilityMark mark;
  };
  std::vector<M> marks;
  for (const facts::FactKey &k :
       facts::asserted_keys(ctx, facts::FactKind::Mutability, {space, 0}, {space, ~std::uint64_t{0}})) {
    auto v = ctx.get<facts::AssertedFact>(k);
    const std::string *bytes = std::get_if<std::string>(&*v);
    if (bytes == nullptr || bytes->empty()) continue;
    try {
      marks.push_back({*ctx.get<facts::AssertedOrder>(k), k.addr.offset, k.sub, facts::decode_from_string<MutabilityMark>(*bytes)});
    } catch (const facts::DecodeError &) {
    }
  }
  std::sort(marks.begin(), marks.end(), [](const M &a, const M &b) { return std::tie(a.order, a.start, a.sub) < std::tie(b.order, b.start, b.sub); });
  std::map<std::uint64_t, std::pair<std::uint64_t, std::uint32_t>> pieces;
  for (std::uint32_t i = 0; i < marks.size(); ++i) paint(pieces, marks[i].start, last_of(marks[i].start, marks[i].mark.length), i);
  Value out;
  for (const auto &[first, rest] : pieces) {
    const M &m = marks[rest.second];
    if (m.mark.kind == MutabilityKind::as_map) continue;
    out.push_back({first, rest.first, m.mark.kind, m.start, m.sub});
  }
  return out;
}

void register_unit_queries(facts::Engine &engine) {
  engine.add_query<Units>();
  engine.add_query<UnitBucket>();
  engine.add_query<UnitCode>();
  engine.add_query<MutabilityMap>();
}

}  // namespace revkit::analysis
