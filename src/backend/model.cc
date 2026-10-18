#include "model.h"

#include "revkit/inputs/codec.h"

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

#include <algorithm>
#include <tuple>

namespace revkit::backend {

using facts::Decoder;
using facts::DecodeError;
using facts::Encoder;

bool Contains(const std::vector<Range> &ranges, std::uint64_t a) {
  return std::any_of(ranges.begin(), ranges.end(), [&](const Range &r) { return a >= r.first && a <= r.second; });
}

std::string Deterministic(const google::protobuf::MessageLite &m) {
  std::string out;
  {
    google::protobuf::io::StringOutputStream sos(&out);
    google::protobuf::io::CodedOutputStream cos(&sos);
    cos.SetSerializationDeterministic(true);
    m.SerializeToCodedStream(&cos);
  }
  return out;
}

namespace {

template <class M>
M ParseMessage(std::string_view bytes) {
  M m;
  if (!m.ParseFromArray(bytes.data(), static_cast<int>(bytes.size()))) throw DecodeError("bad protobuf message");
  return m;
}

}  // namespace

namespace {

std::uint8_t PermBits(const loader::Perms &p) {
  return static_cast<std::uint8_t>((p.read ? 1 : 0) | (p.write ? 2 : 0) | (p.exec ? 4 : 0));
}

loader::Perms PermsOf(std::uint8_t b) { return {(b & 1) != 0, (b & 2) != 0, (b & 4) != 0}; }

}  // namespace

void ProgramSource::encode(Encoder &e) const {
  e.bytes(id);
  e.bytes(name);
  e.bytes(sha256);
  e.varint(file_size);
  e.svarint(imported_at);
  e.bytes(language_id);
  e.bytes(compiler_spec_id);
  facts::encode(e, image_base);
  e.varint(ram_space);
  e.varint(file_space);
  e.varint(ordinal);
  // Optional trailers, so records without them (and their fingerprints)
  // are unchanged: the loader plugin, then the import path.
  // (Then the container path, then a Mach-O slice.)
  const bool more = !container_path.empty() || !macho_slice.empty();
  if (!loader.empty() || !path.empty() || raw || more) e.bytes(loader);
  if (!path.empty() || raw || more) e.bytes(path);
  // No raw trailer but a container path: raw version 0 says "none".
  if (!raw && more) e.u8(0);
  if (raw) {
    // The raw trailer's version: 2 adds spaces and the container, written
    // only when used so older records keep their bytes.
    bool v2 = !raw->space.empty() || raw->container != loader::RawContainer::detect;
    for (const loader::RawRegion &r : raw->regions) v2 = v2 || !r.space.empty();
    e.u8(v2 ? 2 : 1);
    e.varint(raw->base);
    e.varint(raw->offset);
    facts::encode(e, raw->length);
    e.bytes(raw->block_name);
    e.u8(PermBits(raw->perms));
    facts::encode(e, raw->entry);
    e.varint(raw->regions.size());
    for (const loader::RawRegion &r : raw->regions) {
      e.bytes(r.name);
      e.varint(r.start);
      e.varint(r.size);
      e.u8(static_cast<std::uint8_t>(PermBits(r.perms) | (r.initialized ? 8 : 0) | (r.is_volatile ? 16 : 0)));
      e.varint(r.file_offset);
      e.varint(r.file_size);
    }
    if (v2) {
      e.bytes(raw->space);
      e.u8(static_cast<std::uint8_t>(raw->container));
      for (const loader::RawRegion &r : raw->regions) e.bytes(r.space);
    }
  }
  if (more) e.bytes(container_path);
  if (!macho_slice.empty()) e.bytes(macho_slice);
}

ProgramSource ProgramSource::decode(Decoder &d) {
  ProgramSource s;
  s.id = d.bytes();
  s.name = d.bytes();
  s.sha256 = d.bytes();
  s.file_size = d.varint();
  s.imported_at = d.svarint();
  s.language_id = d.bytes();
  s.compiler_spec_id = d.bytes();
  s.image_base = facts::decode<std::optional<std::uint64_t>>(d);
  s.ram_space = facts::decode<facts::SpaceId>(d);
  s.file_space = facts::decode<facts::SpaceId>(d);
  s.ordinal = facts::decode<std::uint32_t>(d);
  if (!d.done()) s.loader = d.bytes();
  if (!d.done()) s.path = d.bytes();
  if (!d.done()) {
    const std::uint8_t version = d.u8();
    if (version > 2) throw DecodeError("unknown raw image record");
    if (version == 0) {
      if (!d.done()) s.container_path = d.bytes();
      if (!d.done()) s.macho_slice = d.bytes();
      return s;
    }
    loader::RawOptions raw;
    raw.base = d.varint();
    raw.offset = d.varint();
    raw.length = facts::decode<std::optional<std::uint64_t>>(d);
    raw.block_name = d.bytes();
    raw.perms = PermsOf(d.u8());
    raw.entry = facts::decode<std::optional<std::uint64_t>>(d);
    const std::size_t n = d.count();
    for (std::size_t i = 0; i < n; ++i) {
      loader::RawRegion r;
      r.name = d.bytes();
      r.start = d.varint();
      r.size = d.varint();
      const std::uint8_t f = d.u8();
      r.perms = PermsOf(f);
      r.initialized = (f & 8) != 0;
      r.is_volatile = (f & 16) != 0;
      r.file_offset = d.varint();
      r.file_size = d.varint();
      raw.regions.push_back(std::move(r));
    }
    if (version == 2) {
      raw.space = d.bytes();
      const std::uint8_t c = d.u8();
      if (c > static_cast<std::uint8_t>(loader::RawContainer::srec)) throw DecodeError("unknown raw container");
      raw.container = static_cast<loader::RawContainer>(c);
      for (loader::RawRegion &r : raw.regions) r.space = d.bytes();
    }
    s.raw = std::move(raw);
    if (!d.done()) s.container_path = d.bytes();
    if (!d.done()) s.macho_slice = d.bytes();
  }
  return s;
}

const std::string *NamedTypes::bound(const std::string &key) const {
  auto it = std::lower_bound(bindings.begin(), bindings.end(), key,
                             [](const auto &b, const std::string &k) { return b.first < k; });
  return it != bindings.end() && it->first == key ? &it->second : nullptr;
}

void NamedTypes::encode(Encoder &e) const {
  e.varint(types.size());
  for (const Entry &t : types) {
    e.bytes(t.key);
    e.bytes(t.hash);
    e.u8((t.library ? 1 : 0) | (t.project ? 2 : 0));
  }
  facts::encode(e, bindings);
}

NamedTypes NamedTypes::decode(Decoder &d) {
  NamedTypes n;
  const std::uint64_t count = d.varint();
  for (std::uint64_t i = 0; i < count; ++i) {
    Entry t;
    t.key = d.bytes();
    t.hash = d.bytes();
    const std::uint8_t flags = d.u8();
    t.library = flags & 1;
    t.project = flags & 2;
    n.types.push_back(std::move(t));
  }
  n.bindings = facts::decode<std::vector<std::pair<std::string, std::string>>>(d);
  return n;
}

void Label::encode(Encoder &e) const {
  e.varint(address);
  e.bytes(name);
  e.varint(size);
  e.bytes(mangled);
}

Label Label::decode(Decoder &d) {
  Label l;
  l.address = d.varint();
  l.name = d.bytes();
  l.size = d.varint();
  l.mangled = d.bytes();
  return l;
}

const Label *LabelMap::find(std::uint64_t a) const {
  auto it = std::lower_bound(labels.begin(), labels.end(), a, [](const Label &l, std::uint64_t v) { return l.address < v; });
  return it != labels.end() && it->address == a ? &*it : nullptr;
}

const Label *LabelMap::containing(std::uint64_t a) const {
  auto it = std::upper_bound(labels.begin(), labels.end(), a, [](std::uint64_t v, const Label &l) { return v < l.address; });
  if (it == labels.begin()) return nullptr;
  const Label &l = *std::prev(it);
  return a - l.address < std::max<std::uint64_t>(l.size, 1) ? &l : nullptr;
}

void StaticXref::encode(Encoder &e) const {
  e.varint(from);
  e.varint(to);
  e.varint(static_cast<std::uint64_t>(kind));
  e.svarint(operand);
  e.u8(static_cast<std::uint8_t>((delay_slot ? 1 : 0) | (user ? 2 : 0) | (primary ? 4 : 0)));
}

StaticXref StaticXref::decode(Decoder &d) {
  StaticXref x;
  x.from = d.varint();
  x.to = d.varint();
  x.kind = static_cast<pb::XrefKind>(facts::decode<std::uint32_t>(d));
  x.operand = facts::decode<int>(d);
  const std::uint8_t flags = d.u8();
  x.delay_slot = flags & 1;
  x.user = flags & 2;
  x.primary = flags & 4;
  return x;
}

std::int64_t ListingSpan::row_count() const {
  if (end <= start) return 0;
  if (code) return static_cast<std::int64_t>(rows.size());
  if (data) return rows.empty() ? 1 : static_cast<std::int64_t>(rows.size());
  // One row at `start`, then one at every 16-byte boundary before `end`.
  return 1 + static_cast<std::int64_t>((end - 1) / kDataLine - start / kDataLine);
}

void ListingSpan::encode(Encoder &e) const {
  e.varint(start);
  e.varint(end);
  e.svarint(first_row);
  e.varint(block);
  e.u8(static_cast<std::uint8_t>((code ? 1 : 0) | (thumb ? 2 : 0) | (data ? 4 : 0)));
  facts::encode(e, rows);
}

ListingSpan ListingSpan::decode(Decoder &d) {
  ListingSpan s;
  s.start = d.varint();
  s.end = d.varint();
  s.first_row = d.svarint();
  s.block = facts::decode<std::uint32_t>(d);
  const std::uint8_t kind = d.u8();
  if (kind > 7) throw DecodeError("bad listing span");
  s.code = (kind & 1) != 0;
  s.thumb = (kind & 2) != 0;
  s.data = (kind & 4) != 0;
  s.rows = facts::decode<std::vector<std::uint32_t>>(d);
  return s;
}

bool CodeMap::thumb_at(std::uint64_t addr) const {
  auto it = std::upper_bound(spans.begin(), spans.end(), addr,
                             [](std::uint64_t a, const ListingSpan &s) { return a < s.start; });
  return it != spans.begin() && std::prev(it)->code && addr < std::prev(it)->end && std::prev(it)->thumb;
}

void CodeMap::encode(Encoder &e) const {
  facts::encode(e, spans);
  e.varint(instructions);
}

CodeMap CodeMap::decode(Decoder &d) {
  CodeMap c;
  c.spans = facts::decode<std::vector<ListingSpan>>(d);
  c.instructions = facts::decode<std::uint32_t>(d);
  return c;
}

const ListingSpan &RowIndex::span_of_row(std::int64_t row) const {
  auto it = std::upper_bound(spans.begin(), spans.end(), row,
                             [](std::int64_t r, const ListingSpan &s) { return r < s.first_row; });
  return *std::prev(it);
}

std::int64_t RowIndex::row_at(std::uint64_t addr) const {
  auto it = std::upper_bound(spans.begin(), spans.end(), addr,
                             [](std::uint64_t a, const ListingSpan &s) { return a < s.start; });
  if (it == spans.begin()) return spans.empty() ? 0 : spans.front().first_row;
  const ListingSpan &s = *std::prev(it);
  if (addr >= s.end) return it == spans.end() ? total_rows : it->first_row;
  if (s.data) return s.first_row;
  if (!s.code)
    return s.first_row + static_cast<std::int64_t>(addr / ListingSpan::kDataLine - s.start / ListingSpan::kDataLine);
  const std::uint32_t off = static_cast<std::uint32_t>(addr - s.start);
  auto r = std::upper_bound(s.rows.begin(), s.rows.end(), off, [](std::uint32_t v, std::uint32_t row) {
    return v < (row & ListingSpan::kOffsetMask);
  });
  return s.first_row + static_cast<std::int64_t>(r - s.rows.begin()) - 1;
}

std::uint64_t RowIndex::row_address(std::int64_t row) const {
  const ListingSpan &s = span_of_row(row);
  const std::int64_t k = row - s.first_row;
  if (s.code || (s.data && !s.rows.empty())) return s.start + (s.rows[static_cast<std::size_t>(k)] & ListingSpan::kOffsetMask);
  if (k == 0) return s.start;
  return (s.start / ListingSpan::kDataLine + static_cast<std::uint64_t>(k)) * ListingSpan::kDataLine;
}

void RowIndex::encode(Encoder &e) const {
  facts::encode(e, spans);
  e.svarint(total_rows);
  facts::encode(e, data);
}

RowIndex RowIndex::decode(Decoder &d) {
  RowIndex r;
  r.spans = facts::decode<std::vector<ListingSpan>>(d);
  r.total_rows = d.svarint();
  r.data = facts::decode<std::vector<analysis::DataItem>>(d);
  return r;
}

void XrefTable::index() {
  by_to.resize(xrefs.size());
  for (std::uint32_t i = 0; i < by_to.size(); ++i) by_to[i] = i;
  std::stable_sort(by_to.begin(), by_to.end(), [&](std::uint32_t a, std::uint32_t b) { return xrefs[a].to < xrefs[b].to; });
}

XrefTable XrefTable::decode(Decoder &d) {
  XrefTable t;
  t.xrefs = facts::decode<std::vector<StaticXref>>(d);
  t.index();
  return t;
}

std::vector<const StaticXref *> XrefTable::to(std::uint64_t first, std::uint64_t last) const {
  std::vector<const StaticXref *> out;
  auto it = std::lower_bound(by_to.begin(), by_to.end(), first,
                             [&](std::uint32_t i, std::uint64_t v) { return xrefs[i].to < v; });
  for (; it != by_to.end() && xrefs[*it].to <= last; ++it) out.push_back(&xrefs[*it]);
  return out;
}

std::vector<const StaticXref *> XrefTable::from(std::uint64_t first, std::uint64_t last) const {
  std::vector<const StaticXref *> out;
  auto it = std::lower_bound(xrefs.begin(), xrefs.end(), first,
                             [](const StaticXref &x, std::uint64_t v) { return x.from < v; });
  for (; it != xrefs.end() && it->from <= last; ++it) out.push_back(&*it);
  return out;
}

std::uint32_t XrefTable::count_to(std::uint64_t addr) const {
  auto lo = std::lower_bound(by_to.begin(), by_to.end(), addr,
                             [&](std::uint32_t i, std::uint64_t v) { return xrefs[i].to < v; });
  auto hi = std::upper_bound(lo, by_to.end(), addr, [&](std::uint64_t v, std::uint32_t i) { return v < xrefs[i].to; });
  return static_cast<std::uint32_t>(hi - lo);
}

void StaticRow::encode(Encoder &e) const {
  e.varint(address);
  e.varint(length);
  e.varint(static_cast<std::uint64_t>(kind));
  e.varint(block);
  e.bytes(bytes);
  e.varint(tokens.size());
  for (const lift::Token &t : tokens) {
    e.u8(static_cast<std::uint8_t>(t.kind));
    e.bytes(t.text);
    e.svarint(t.operand);
    e.varint(t.value);
    e.u8(t.bits);
    e.bytes(t.reg.space);
    e.varint(t.reg.offset);
    e.varint(t.reg.size);
  }
  e.varint(static_cast<std::uint64_t>(flow));
  facts::encode(e, targets);
  e.bytes(data_type);
  e.bytes(data_mnemonic);
  e.bytes(data_value);
  facts::encode(e, data_target);
  e.u8(patched ? 1 : 0);
  if (patched) e.bytes(original);
  e.varint(data_components);
  e.u8(data_collapsed ? 1 : 0);
  e.bytes(data_field);
  e.varint(data_depth);
  facts::encode(e, data_parent);
  e.bytes(data_settings_type);
}

StaticRow StaticRow::decode(Decoder &d) {
  StaticRow r;
  r.address = d.varint();
  r.length = facts::decode<std::uint32_t>(d);
  r.kind = static_cast<pb::ListingRowKind>(facts::decode<std::uint32_t>(d));
  r.block = facts::decode<std::uint32_t>(d);
  r.bytes = d.bytes();
  const std::size_t n = d.count();
  r.tokens.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    lift::Token t;
    const std::uint8_t kind = d.u8();
    if (kind > static_cast<std::uint8_t>(lift::Token::Kind::whitespace)) throw DecodeError("bad token kind");
    t.kind = static_cast<lift::Token::Kind>(kind);
    t.text = d.bytes();
    t.operand = facts::decode<int>(d);
    t.value = d.varint();
    t.bits = d.u8();
    t.reg.space = d.bytes();
    t.reg.offset = d.varint();
    t.reg.size = facts::decode<std::uint32_t>(d);
    r.tokens.push_back(std::move(t));
  }
  r.flow = static_cast<pb::FlowKind>(facts::decode<std::uint32_t>(d));
  r.targets = facts::decode<std::vector<std::uint64_t>>(d);
  r.data_type = d.bytes();
  r.data_mnemonic = d.bytes();
  r.data_value = d.bytes();
  r.data_target = facts::decode<std::optional<std::uint64_t>>(d);
  r.patched = d.u8() != 0;
  if (r.patched) r.original = d.bytes();
  r.data_components = facts::decode<std::uint32_t>(d);
  r.data_collapsed = d.u8() != 0;
  r.data_field = d.bytes();
  r.data_depth = facts::decode<std::uint32_t>(d);
  r.data_parent = facts::decode<std::optional<std::uint64_t>>(d);
  r.data_settings_type = d.bytes();
  return r;
}

SearchRow SearchRow::From(const StaticRow &r) {
  SearchRow s;
  s.address = r.address;
  s.length = r.length;
  s.kind = r.kind;
  if (r.kind == pb::LISTING_ROW_KIND_INSTRUCTION) {
    bool ops = false;
    for (const lift::Token &t : r.tokens) {
      if (!ops && t.kind != lift::Token::Kind::mnemonic && t.kind != lift::Token::Kind::whitespace) {
        s.operands = static_cast<std::uint32_t>(s.text.size());
        ops = true;
      }
      if (t.kind == lift::Token::Kind::scalar || t.kind == lift::Token::Kind::address) {
        Number n;
        n.at = static_cast<std::uint32_t>(s.text.size());
        n.len = static_cast<std::uint32_t>(t.text.size());
        n.value = t.value;
        n.bits = t.bits;
        n.operand = static_cast<std::int8_t>(std::clamp(t.operand, -1, 127));
        n.address = t.kind == lift::Token::Kind::address;
        s.numbers.push_back(n);
      }
      s.text += t.text;
    }
    if (!ops) s.operands = static_cast<std::uint32_t>(s.text.size());
  } else if (r.kind == pb::LISTING_ROW_KIND_DATA) {
    s.text = r.data_value;
    s.data_type = r.data_type;
    s.data_mnemonic = r.data_mnemonic;
    s.data_target = r.data_target;
    if (r.bytes.size() <= 8) s.bytes = r.bytes;
  }
  return s;
}

void SearchRow::encode(Encoder &e) const {
  e.varint(address);
  e.varint(length);
  e.varint(static_cast<std::uint64_t>(kind));
  e.bytes(text);
  e.varint(operands);
  e.varint(numbers.size());
  for (const Number &n : numbers) {
    e.varint(n.at);
    e.varint(n.len);
    e.varint(n.value);
    e.u8(n.bits);
    e.svarint(n.operand);
    e.u8(n.address ? 1 : 0);
  }
  e.bytes(data_type);
  e.bytes(data_mnemonic);
  e.bytes(bytes);
  facts::encode(e, data_target);
}

SearchRow SearchRow::decode(Decoder &d) {
  SearchRow s;
  s.address = d.varint();
  s.length = facts::decode<std::uint32_t>(d);
  s.kind = static_cast<pb::ListingRowKind>(facts::decode<std::uint32_t>(d));
  s.text = d.bytes();
  s.operands = facts::decode<std::uint32_t>(d);
  const std::size_t n = d.count();
  s.numbers.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    Number x;
    x.at = facts::decode<std::uint32_t>(d);
    x.len = facts::decode<std::uint32_t>(d);
    x.value = d.varint();
    x.bits = d.u8();
    x.operand = static_cast<std::int8_t>(facts::decode<int>(d));
    x.address = d.u8() != 0;
    s.numbers.push_back(x);
  }
  s.data_type = d.bytes();
  s.data_mnemonic = d.bytes();
  s.bytes = d.bytes();
  s.data_target = facts::decode<std::optional<std::uint64_t>>(d);
  return s;
}

void HeaderBucket::index() {
  std::int64_t n = 0;
  for (Entry &e : entries) {
    e.before = n;
    n += e.lines;
  }
  lines = n;
}

void HeaderBucket::encode(Encoder &e) const {
  e.varint(entries.size());
  for (const Entry &x : entries) {
    e.varint(x.address);
    e.svarint(x.row);
    e.varint(x.lines);
  }
}

HeaderBucket HeaderBucket::decode(Decoder &d) {
  HeaderBucket h;
  const std::size_t n = d.count();
  h.entries.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    Entry x;
    x.address = d.varint();
    x.row = d.svarint();
    x.lines = facts::decode<std::uint32_t>(d);
    h.entries.push_back(x);
  }
  h.index();
  return h;
}

void HeaderIndex::index() {
  std::int64_t n = 0;
  for (Bucket &b : buckets) {
    b.before = n;
    n += b.lines;
  }
  total_lines = n;
}

void HeaderIndex::encode(Encoder &e) const {
  e.varint(buckets.size());
  for (const Bucket &b : buckets) {
    e.varint(b.index);
    e.svarint(b.first_row);
    e.svarint(b.last_row);
    e.svarint(b.lines);
  }
}

HeaderIndex HeaderIndex::decode(Decoder &d) {
  HeaderIndex h;
  const std::size_t n = d.count();
  h.buckets.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    Bucket b;
    b.index = d.varint();
    b.first_row = d.svarint();
    b.last_row = d.svarint();
    b.lines = d.svarint();
    h.buckets.push_back(b);
  }
  h.index();
  return h;
}

std::vector<std::string> CommentLines(const std::string &text) {
  constexpr std::size_t kMaxLines = 64;
  std::vector<std::string> out;
  std::size_t a = 0;
  while (a < text.size() && out.size() < kMaxLines) {
    std::size_t nl = text.find('\n', a);
    if (nl == std::string::npos) nl = text.size();
    std::string line = text.substr(a, nl - a);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    out.push_back(std::move(line));
    a = nl + 1;
  }
  return out;
}

void Func::encode(Encoder &e) const {
  e.varint(entry);
  facts::encode(e, body);
  facts::encode(e, asserted);
  e.bytes(name);
  e.varint(flags);
  e.varint(thunk_target);
  e.bytes(mangled);
}

Func Func::decode(Decoder &d) {
  Func f;
  f.entry = d.varint();
  f.body = facts::decode<std::vector<Range>>(d);
  f.asserted = facts::decode<bool>(d);
  f.name = d.bytes();
  f.flags = facts::decode<std::uint16_t>(d);
  f.thunk_target = d.varint();
  f.mangled = d.bytes();
  return f;
}

void FunctionTable::index() {
  pieces.clear();
  std::vector<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>> ranges;
  for (const Func &f : funcs)
    for (const auto &[first, last] : f.body) ranges.emplace_back(first, last, f.entry);
  std::sort(ranges.begin(), ranges.end());
  std::uint64_t covered = 0;
  bool any = false;
  for (const auto &[first, last, entry] : ranges) {
    if (any && covered == UINT64_MAX) break;
    std::uint64_t from = any ? std::max(first, covered + 1) : first;
    if (from > last) continue;
    pieces.push_back({from, last, entry});
    covered = any ? std::max(covered, last) : last;
    any = true;
  }
}

FunctionTable FunctionTable::decode(Decoder &d) {
  FunctionTable t;
  t.funcs = facts::decode<std::vector<Func>>(d);
  t.index();
  return t;
}

const Func *FunctionTable::at(std::uint64_t entry) const {
  auto it = std::lower_bound(funcs.begin(), funcs.end(), entry, [](const Func &f, std::uint64_t v) { return f.entry < v; });
  return it != funcs.end() && it->entry == entry ? &*it : nullptr;
}

const Func *FunctionTable::containing(std::uint64_t a) const {
  auto it = std::upper_bound(pieces.begin(), pieces.end(), a, [](std::uint64_t x, const Piece &p) { return x < p.first; });
  if (it == pieces.begin()) return nullptr;
  --it;
  return a <= it->last ? at(it->entry) : nullptr;
}

void SymbolInfo::encode(Encoder &e) const {
  e.u8(static_cast<std::uint8_t>(kind));
  e.bytes(name);
  e.varint(size);
  e.bytes(type);
  facts::encode(e, no_return);
  facts::encode(e, asserted);
  e.svarint(type_rank);
}

SymbolInfo SymbolInfo::decode(Decoder &d) {
  SymbolInfo s;
  const std::uint8_t kind = d.u8();
  if (kind > static_cast<std::uint8_t>(Kind::Data)) throw DecodeError("bad symbol kind");
  s.kind = static_cast<Kind>(kind);
  s.name = d.bytes();
  s.size = d.varint();
  s.type = d.bytes();
  s.no_return = facts::decode<bool>(d);
  s.asserted = facts::decode<bool>(d);
  s.type_rank = static_cast<int>(d.svarint());
  return s;
}

std::string DemangledProto::text(const std::string &name, bool without_this) const {
  return ret + (ret.ends_with("*") ? "" : " ") + name + (without_this && this_guessed ? params_static : params);
}

void DemangledProto::encode(Encoder &e) const {
  e.bytes(ret);
  e.bytes(params);
  e.bytes(params_static);
  facts::encode(e, this_guessed);
  facts::encode(e, param_float);
  e.bytes(full);
}

DemangledProto DemangledProto::decode(Decoder &d) {
  DemangledProto p;
  p.ret = d.bytes();
  p.params = d.bytes();
  p.params_static = d.bytes();
  p.this_guessed = facts::decode<bool>(d);
  p.param_float = facts::decode<std::vector<bool>>(d);
  p.full = d.bytes();
  return p;
}

void VariableType::encode(Encoder &e) const {
  e.bytes(key);
  e.bytes(hash);
  e.bytes(name);
  facts::encode(e, static_cast<std::int64_t>(param));
  e.bytes(space);
  e.varint(offset);
  e.varint(size);
  facts::encode(e, pc);
}

VariableType VariableType::decode(Decoder &d) {
  VariableType v;
  v.key = d.bytes();
  v.hash = d.bytes();
  v.name = d.bytes();
  v.param = static_cast<int>(facts::decode<std::int64_t>(d));
  v.space = d.bytes();
  v.offset = d.varint();
  v.size = static_cast<std::uint32_t>(d.varint());
  v.pc = facts::decode<std::optional<std::uint64_t>>(d);
  return v;
}

void DecompileInputs::encode(Encoder &e) const {
  e.varint(entry);
  facts::encode(e, exists);
  facts::encode(e, body);
  e.varint(comments.size());
  for (const Comment &c : comments) {
    e.varint(c.address);
    e.varint(static_cast<std::uint64_t>(c.kind));
    e.bytes(c.text);
  }
  facts::encode(e, flow_overrides);
  facts::encode(e, jump_tables);
  facts::encode(e, equates);
  facts::encode(e, call_targets);
  facts::encode(e, std::vector<std::uint64_t>(forced_tables.begin(), forced_tables.end()));
  facts::encode(e, call_signatures);
}

DecompileInputs DecompileInputs::decode(Decoder &d) {
  DecompileInputs in;
  in.entry = d.varint();
  in.exists = facts::decode<bool>(d);
  in.body = facts::decode<std::vector<Range>>(d);
  const std::size_t n = d.count();
  for (std::size_t i = 0; i < n; ++i) {
    Comment c;
    c.address = d.varint();
    c.kind = static_cast<pb::CommentKind>(facts::decode<std::uint32_t>(d));
    c.text = d.bytes();
    in.comments.push_back(std::move(c));
  }
  in.flow_overrides = facts::decode<std::map<std::uint64_t, int>>(d);
  in.jump_tables = facts::decode<std::map<std::uint64_t, std::vector<std::uint64_t>>>(d);
  in.equates = facts::decode<std::vector<lift::EquateFacts>>(d);
  in.call_targets = facts::decode<std::map<std::uint64_t, std::uint64_t>>(d);
  for (std::uint64_t a : facts::decode<std::vector<std::uint64_t>>(d)) in.forced_tables.insert(a);
  in.call_signatures = facts::decode<std::map<std::uint64_t, std::string>>(d);
  return in;
}

void DecompileOutput::encode(Encoder &e) const {
  e.bytes(Deterministic(function));
  e.varint(prototype.size());
  for (const TokenRef &r : prototype) {
    e.svarint(r.line);
    e.svarint(r.token);
  }
  e.varint(declaration_types.size());
  for (const auto &[r, var] : declaration_types) {
    e.svarint(r.line);
    e.svarint(r.token);
    e.varint(var);
  }
  facts::encode(e, references);
  facts::encode(e, touched);
  // Two runs with equal output differ here; that only costs early cutoff,
  // and no query reads a decompilation.
  e.varint(static_cast<std::uint64_t>(milliseconds * 1000));
  facts::encode(e, failure);
  e.bytes(failure_bundle);
  facts::encode(e, accesses);
  facts::encode(e, dynamic);
  e.varint(field_parents.size());
  for (const auto &[r, id] : field_parents) {
    e.svarint(r.line);
    e.svarint(r.token);
    e.varint(id);
  }
}

DecompileOutput DecompileOutput::decode(Decoder &d) {
  DecompileOutput o;
  o.function = ParseMessage<pb::DecompiledFunction>(d.bytes());
  std::size_t n = d.count();
  for (std::size_t i = 0; i < n; ++i) {
    TokenRef r;
    r.line = facts::decode<int>(d);
    r.token = facts::decode<int>(d);
    o.prototype.push_back(r);
  }
  n = d.count();
  for (std::size_t i = 0; i < n; ++i) {
    TokenRef r;
    r.line = facts::decode<int>(d);
    r.token = facts::decode<int>(d);
    o.declaration_types.emplace_back(r, facts::decode<std::uint32_t>(d));
  }
  o.references = facts::decode<std::vector<std::uint64_t>>(d);
  o.touched = facts::decode<std::vector<std::uint64_t>>(d);
  o.milliseconds = static_cast<double>(d.varint()) / 1000;
  o.failure = facts::decode<std::optional<decompd::Failure>>(d);
  o.failure_bundle = std::string(d.bytes());
  o.accesses = facts::decode<decltype(o.accesses)>(d);
  o.dynamic = facts::decode<decltype(o.dynamic)>(d);
  n = d.count();
  for (std::size_t i = 0; i < n; ++i) {
    TokenRef r;
    r.line = facts::decode<int>(d);
    r.token = facts::decode<int>(d);
    o.field_parents.emplace_back(r, d.varint());
  }
  return o;
}

}  // namespace revkit::backend
