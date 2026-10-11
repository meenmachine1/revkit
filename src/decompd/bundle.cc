#include "revkit/decompd/bundle.h"

#include "revkit/inputs/codec.h"

#include <algorithm>
#include <bit>
#include <cstring>

namespace revkit::decompd {

namespace {

void put_double(facts::Encoder &e, double v) { e.u64be(std::bit_cast<std::uint64_t>(v)); }
double get_double(facts::Decoder &d) { return std::bit_cast<double>(d.u64be()); }

void put_block(facts::Encoder &e, const loader::Block &b) {
  e.bytes(b.name);
  e.varint(b.start);
  e.varint(b.size);
  e.u8(static_cast<std::uint8_t>((b.perms.read ? 1 : 0) | (b.perms.write ? 2 : 0) | (b.perms.exec ? 4 : 0) |
                                 (b.initialized ? 8 : 0) | (b.is_volatile ? 16 : 0)));
}

loader::Block get_block(facts::Decoder &d) {
  loader::Block b;
  b.name = std::string(d.bytes());
  b.start = d.varint();
  b.size = d.varint();
  const std::uint8_t f = d.u8();
  b.perms.read = f & 1;
  b.perms.write = f & 2;
  b.perms.exec = f & 4;
  b.initialized = f & 8;
  b.is_volatile = f & 16;
  return b;
}

void put_context(facts::Encoder &e, const lift::ContextRegion &c) {
  e.bytes(c.name);
  e.varint(c.value);
  e.varint(c.start);
  e.varint(c.end);
}

lift::ContextRegion get_context(facts::Decoder &d) {
  lift::ContextRegion c;
  c.name = std::string(d.bytes());
  c.value = static_cast<std::uint32_t>(d.varint());
  c.start = d.varint();
  c.end = d.varint();
  return c;
}

void put_join(facts::Encoder &e, const lift::JoinFacts &j) {
  facts::encode(e, j.pieces);
  e.svarint(j.logical_size);
}

lift::JoinFacts get_join(facts::Decoder &d) {
  lift::JoinFacts j;
  j.pieces = facts::decode<std::vector<lift::StorageVarnode>>(d);
  j.logical_size = static_cast<int>(d.svarint());
  return j;
}

template <class T, class F>
void put_list(facts::Encoder &e, const std::vector<T> &v, F put) {
  e.varint(v.size());
  for (const T &x : v) put(e, x);
}

template <class F>
auto get_list(facts::Decoder &d, F get) {
  std::vector<decltype(get(d))> v;
  const std::size_t n = d.count();
  v.reserve(n);
  for (std::size_t i = 0; i < n; ++i) v.push_back(get(d));
  return v;
}

}  // namespace

const char *mode_name(Mode m) {
  switch (m) {
    case Mode::c_text: return "c_text";
    case Mode::tokens: return "tokens";
    case Mode::observe: return "observe";
    case Mode::param_id: return "param_id";
    case Mode::signature: return "signature";
  }
  return "?";
}

void AddressAnswer::encode(facts::Encoder &e) const {
  e.svarint(starts);
  e.svarint(contains);
  if (contains >= 0) {
    e.varint(body_first);
    e.varint(body_last);
  }
  e.svarint(data);
  e.svarint(external);
  e.svarint(label);
  facts::encode(e, block);
}

AddressAnswer AddressAnswer::decode(facts::Decoder &d) {
  AddressAnswer a;
  a.starts = static_cast<std::int32_t>(d.svarint());
  a.contains = static_cast<std::int32_t>(d.svarint());
  if (a.contains >= 0) {
    a.body_first = d.varint();
    a.body_last = d.varint();
  }
  a.data = static_cast<std::int32_t>(d.svarint());
  a.external = static_cast<std::int32_t>(d.svarint());
  a.label = static_cast<std::int32_t>(d.svarint());
  a.block = facts::decode<std::optional<lift::Mutability>>(d);
  return a;
}

std::optional<lift::Mutability> LiftFacts::default_block(const std::string &space, std::uint64_t a) const {
  // InputsLookup::block_at: the last block starting at or before the
  // address, if it reaches it.
  const lift::BlockFacts *best = nullptr;
  for (const lift::BlockFacts &b : blocks)
    if (b.space == space && b.start <= a && (best == nullptr || b.start >= best->start)) best = &b;
  if (best == nullptr || best->end < a) return std::nullopt;
  return best->is_volatile ? lift::Mutability::is_volatile
                           : !best->write ? lift::Mutability::constant : lift::Mutability::normal;
}

void LiftFacts::encode(facts::Encoder &e) const {
  e.u8(static_cast<std::uint8_t>((default_names ? 1 : 0) | (default_labels ? 2 : 0) | (default_extrapop ? 4 : 0) |
                                 (format_strings ? 8 : 0)));
  e.bytes(address_prefix);
  facts::encode(e, blocks);
  facts::encode(e, spaces);
  facts::encode(e, functions);
  facts::encode(e, data);
  facts::encode(e, externals);
  facts::encode(e, labels);
  facts::encode(e, addresses);
  facts::encode(e, code_labels);
  facts::encode(e, types);
  facts::encode(e, comments);
  facts::encode(e, flow_overrides);
  facts::encode(e, tracked);
  facts::encode(e, jump_tables);
  facts::encode(e, hook_flow_overrides);
  facts::encode(e, hook_comments);
  facts::encode(e, hook_equates);
  facts::encode(e, hook_call_targets);
  facts::encode(e, hook_forced_tables);
  facts::encode(e, hook_call_protos);
}

LiftFacts LiftFacts::decode(facts::Decoder &d) {
  LiftFacts f;
  const std::uint8_t flags = d.u8();
  f.default_names = flags & 1;
  f.default_labels = flags & 2;
  f.default_extrapop = flags & 4;
  f.format_strings = flags & 8;
  f.address_prefix = std::string(d.bytes());
  f.blocks = facts::decode<std::vector<lift::BlockFacts>>(d);
  f.spaces = facts::decode<std::vector<std::string>>(d);
  f.functions = facts::decode<std::vector<lift::FunctionFacts>>(d);
  f.data = facts::decode<std::vector<lift::DataFacts>>(d);
  f.externals = facts::decode<std::vector<lift::ExternalRefFacts>>(d);
  f.labels = facts::decode<std::vector<lift::LabelFacts>>(d);
  f.addresses = facts::decode<std::map<SpaceAddr, AddressAnswer>>(d);
  f.code_labels = facts::decode<std::map<SpaceAddr, std::optional<std::string>>>(d);
  f.types = facts::decode<std::map<std::uint64_t, std::string>>(d);
  f.comments = facts::decode<std::vector<lift::CommentFacts>>(d);
  f.flow_overrides = facts::decode<std::vector<std::pair<std::uint64_t, std::string>>>(d);
  f.tracked = facts::decode<std::vector<lift::TrackedFacts>>(d);
  f.jump_tables = facts::decode<std::map<std::uint64_t, std::vector<std::uint64_t>>>(d);
  f.hook_flow_overrides = facts::decode<std::vector<std::pair<std::uint64_t, std::string>>>(d);
  f.hook_comments = facts::decode<std::vector<lift::CommentFacts>>(d);
  f.hook_equates = facts::decode<std::vector<lift::EquateFacts>>(d);
  f.hook_call_targets = facts::decode<std::map<std::uint64_t, std::uint64_t>>(d);
  f.hook_forced_tables = facts::decode<std::vector<std::uint64_t>>(d);
  f.hook_call_protos = facts::decode<std::map<std::uint64_t, lift::FunctionFacts>>(d);
  // Indexes must be in range: a worker dereferences them.
  auto check = [&](std::int32_t i, std::size_t n) {
    if (i < -1 || (i >= 0 && static_cast<std::size_t>(i) >= n)) throw facts::DecodeError("bundle: index out of range");
  };
  for (const auto &[k, a] : f.addresses) {
    check(a.starts, f.functions.size());
    check(a.contains, f.functions.size());
    check(a.data, f.data.size());
    check(a.external, f.externals.size());
    check(a.label, f.labels.size());
  }
  return f;
}

bool Bundle::mapped_at(std::uint64_t a) const {
  auto it = std::upper_bound(mapped.begin(), mapped.end(), a,
                             [](std::uint64_t x, const std::pair<std::uint64_t, std::uint64_t> &r) { return x < r.first; });
  if (it == mapped.begin()) return false;
  --it;
  return a <= it->second;
}

std::string Bundle::arch_key() const {
  facts::Encoder e;
  e.u8(static_cast<std::uint8_t>(mode));
  e.bytes(language_id);
  e.u8(static_cast<std::uint8_t>(format));
  e.varint(bits);
  put_list(e, image_blocks, put_block);
  put_list(e, context, put_context);
  if (mode != Mode::observe) {
    e.u8(static_cast<std::uint8_t>((lift.default_names ? 1 : 0) | (lift.default_labels ? 2 : 0) |
                                   (lift.default_extrapop ? 4 : 0) | (lift.format_strings ? 8 : 0)));
    e.bytes(lift.address_prefix);
  }
  return std::move(e).str();
}

void Bundle::encode(facts::Encoder &e) const {
  e.raw("RKBUNDLE");
  e.varint(kBundleVersion);
  e.u8(static_cast<std::uint8_t>(mode));
  e.bytes(language_id);
  e.varint(entry);
  e.u8(static_cast<std::uint8_t>(format));
  e.varint(bits);
  put_list(e, image_blocks, put_block);
  facts::encode(e, mapped);
  e.varint(chunks.size());
  for (const auto &[index, bytes] : chunks) {
    e.varint(index);
    e.raw(bytes);
  }
  put_list(e, context, put_context);
  e.u8(joins ? 1 : 0);
  if (joins) put_list(e, *joins, put_join);
  if (mode == Mode::observe) e.bytes(extra);
  else lift.encode(e);
  if (mode == Mode::signature) e.bytes(extra);
}

Bundle Bundle::decode(facts::Decoder &d) {
  if (d.raw(8) != "RKBUNDLE") throw facts::DecodeError("not a revkit decompiler bundle");
  if (const std::uint64_t v = d.varint(); v != kBundleVersion)
    throw facts::DecodeError("bundle version " + std::to_string(v) + ", expected " + std::to_string(kBundleVersion));
  Bundle b;
  const std::uint8_t mode = d.u8();
  if (mode < 1 || mode > 5) throw facts::DecodeError("bundle: unknown mode");
  b.mode = static_cast<Mode>(mode);
  b.language_id = std::string(d.bytes());
  b.entry = d.varint();
  const std::uint8_t format = d.u8();
  if (format > static_cast<std::uint8_t>(loader::Format::raw)) throw facts::DecodeError("bundle: unknown format");
  b.format = static_cast<loader::Format>(format);
  b.bits = static_cast<unsigned>(d.varint());
  b.image_blocks = get_list(d, get_block);
  b.mapped = facts::decode<std::vector<std::pair<std::uint64_t, std::uint64_t>>>(d);
  const std::size_t n = d.count();
  for (std::size_t i = 0; i < n; ++i) {
    const std::uint64_t index = d.varint();
    b.chunks.emplace(index, std::string(d.raw(kChunk)));
  }
  b.context = get_list(d, get_context);
  if (d.u8() != 0) b.joins = get_list(d, get_join);
  if (b.mode == Mode::observe) b.extra = std::string(d.bytes());
  else b.lift = LiftFacts::decode(d);
  if (b.mode == Mode::signature) b.extra = std::string(d.bytes());
  return b;
}

std::string encode_bundle(const Bundle &b) {
  facts::Encoder e;
  b.encode(e);
  return std::move(e).str();
}

Bundle decode_bundle(std::string_view bytes) {
  facts::Decoder d(bytes);
  Bundle b = Bundle::decode(d);
  d.expect_done();
  return b;
}

std::string bundle_hash(std::string_view encoded) { return "b2-" + facts::Fingerprint::of(encoded).hex(); }

void Miss::encode(facts::Encoder &e) const {
  e.u8(kind);
  e.bytes(space);
  e.varint(value);
}

Miss Miss::decode(facts::Decoder &d) {
  Miss m;
  const std::uint8_t k = d.u8();
  if (k < 1 || k > 7) throw facts::DecodeError("bad miss kind");
  m.kind = static_cast<Kind>(k);
  m.space = std::string(d.bytes());
  m.value = d.varint();
  return m;
}

void Limits::encode(facts::Encoder &e) const {
  put_double(e, timeout_seconds);
  e.varint(max_varnodes);
}

Limits Limits::decode(facts::Decoder &d) {
  Limits l;
  l.timeout_seconds = get_double(d);
  l.max_varnodes = d.varint();
  return l;
}

void RunResult::encode(facts::Encoder &e) const {
  facts::encode(e, ran);
  e.bytes(error);
  e.bytes(payload);
  e.u8(static_cast<std::uint8_t>(stopped));
  facts::encode(e, misses);
  facts::encode(e, asked);
  facts::encode(e, asked_functions);
  put_list(e, joins_made, put_join);
  e.varint(varnodes);
  put_double(e, milliseconds);
  e.varint(rss);
  e.varint(rss_anon);
}

RunResult RunResult::decode(facts::Decoder &d) {
  RunResult r;
  r.ran = facts::decode<bool>(d);
  r.error = std::string(d.bytes());
  r.payload = std::string(d.bytes());
  const std::uint8_t s = d.u8();
  if (s > static_cast<std::uint8_t>(lift::DecompileStop::cancelled)) throw facts::DecodeError("bad stop reason");
  r.stopped = static_cast<lift::DecompileStop>(s);
  r.misses = facts::decode<std::vector<Miss>>(d);
  r.asked = facts::decode<std::vector<SpaceAddr>>(d);
  r.asked_functions = facts::decode<std::vector<std::uint64_t>>(d);
  r.joins_made = get_list(d, get_join);
  r.varnodes = d.varint();
  r.milliseconds = get_double(d);
  r.rss = d.varint();
  r.rss_anon = d.varint();
  return r;
}

}  // namespace revkit::decompd
