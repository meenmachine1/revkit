// The effective memory map (analysis.memory) and the loader's views with it
// laid over them (analysis.program, analysis.data_program). memory.h.

#include "revkit/analysis/memory.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <mutex>

namespace revkit::analysis {

using facts::Decoder;
using facts::Encoder;

namespace {

constexpr std::uint8_t kRegionVersion = 1;
constexpr std::uint8_t kBlockEditVersion = 1;

std::uint8_t perm_bits(bool r, bool w, bool x) {
  return static_cast<std::uint8_t>((r ? 1 : 0) | (w ? 2 : 0) | (x ? 4 : 0));
}

std::vector<Range> normalize(std::vector<Range> v) {
  std::sort(v.begin(), v.end());
  std::vector<Range> out;
  for (const Range &r : v) {
    if (!out.empty() && (out.back().last == ~std::uint64_t{0} || r.first <= out.back().last + 1))
      out.back().last = std::max(out.back().last, r.last);
    else
      out.push_back(r);
  }
  return out;
}

std::string describe_block(const MemoryBlock &b) {
  return b.name + " [" + hex_address(b.range.first) + ", " + hex_address(b.range.last) + "]";
}

}  // namespace

std::string hex_address(std::uint64_t a) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(a));
  return buf;
}

std::string region_sub(std::string_view id) { return std::string(kRegionSubPrefix) + std::string(id); }
std::string block_sub(std::uint64_t start) { return std::string(kBlockSubPrefix) + hex_address(start); }

// ---- values ----

void RegionBytes::encode(Encoder &e) const {
  e.varint(space);
  e.varint(offset);
  e.varint(length);
  e.bytes(sha256);
  e.bytes(file);
  e.varint(file_offset);
}

RegionBytes RegionBytes::decode(Decoder &d) {
  RegionBytes b;
  b.space = facts::decode<facts::SpaceId>(d);
  b.offset = d.varint();
  b.length = d.varint();
  b.sha256 = std::string(d.bytes());
  b.file = std::string(d.bytes());
  b.file_offset = d.varint();
  return b;
}

void RegionSpec::encode(Encoder &e) const {
  e.bytes(name);
  e.varint(start);
  e.varint(size);
  e.u8(static_cast<std::uint8_t>(perm_bits(read, write, exec) | (initialized ? 8 : 0) | (is_volatile ? 16 : 0)));
  facts::encode(e, bytes);
}

RegionSpec RegionSpec::decode(Decoder &d) {
  RegionSpec r;
  r.name = std::string(d.bytes());
  r.start = d.varint();
  r.size = d.varint();
  const std::uint8_t f = d.u8();
  r.read = f & 1;
  r.write = f & 2;
  r.exec = f & 4;
  r.initialized = f & 8;
  r.is_volatile = f & 16;
  r.bytes = facts::decode<std::optional<RegionBytes>>(d);
  return r;
}

void BlockEdit::encode(Encoder &e) const {
  e.bytes(name);
  e.u8(static_cast<std::uint8_t>(perm_bits(read, write, exec) | (is_volatile ? 16 : 0)));
}

BlockEdit BlockEdit::decode(Decoder &d) {
  BlockEdit b;
  b.name = std::string(d.bytes());
  const std::uint8_t f = d.u8();
  b.read = f & 1;
  b.write = f & 2;
  b.exec = f & 4;
  b.is_volatile = f & 16;
  return b;
}

std::string encode_region(const RegionSpec &r) {
  Encoder e;
  e.u8(kRegionVersion);
  r.encode(e);
  return std::move(e).str();
}

std::optional<RegionSpec> decode_region(std::string_view value) {
  if (value.empty()) return std::nullopt;
  try {
    Decoder d(value);
    if (d.u8() != kRegionVersion) return std::nullopt;
    RegionSpec r = RegionSpec::decode(d);
    d.expect_done();
    return r;
  } catch (const facts::DecodeError &) {
    return std::nullopt;
  }
}

std::string encode_block_edit(const BlockEdit &b) {
  Encoder e;
  e.u8(kBlockEditVersion);
  b.encode(e);
  return std::move(e).str();
}

std::optional<BlockEdit> decode_block_edit(std::string_view value) {
  if (value.empty()) return std::nullopt;
  try {
    Decoder d(value);
    if (d.u8() != kBlockEditVersion) return std::nullopt;
    BlockEdit b = BlockEdit::decode(d);
    d.expect_done();
    return b;
  } catch (const facts::DecodeError &) {
    return std::nullopt;
  }
}

void MemoryBlock::encode(Encoder &e) const {
  e.bytes(name);
  range.encode(e);
  e.u8(static_cast<std::uint8_t>(perm_bits(read, write, exec) | (initialized ? 8 : 0) | (is_volatile ? 16 : 0) |
                                 (edited ? 32 : 0) | (bytes_missing ? 64 : 0)));
  facts::encode(e, origin);
  e.bytes(id);
  facts::encode(e, bytes);
  e.bytes(rejected);
}

MemoryBlock MemoryBlock::decode(Decoder &d) {
  MemoryBlock b;
  b.name = std::string(d.bytes());
  b.range = Range::decode(d);
  const std::uint8_t f = d.u8();
  b.read = f & 1;
  b.write = f & 2;
  b.exec = f & 4;
  b.initialized = f & 8;
  b.is_volatile = f & 16;
  b.edited = f & 32;
  b.bytes_missing = f & 64;
  b.origin = facts::decode<BlockOrigin>(d);
  b.id = std::string(d.bytes());
  b.bytes = facts::decode<std::optional<RegionBytes>>(d);
  b.rejected = std::string(d.bytes());
  return b;
}

const MemoryBlock *MemoryMapInfo::block(std::uint64_t a) const {
  auto it = std::upper_bound(blocks.begin(), blocks.end(), a,
                             [](std::uint64_t x, const MemoryBlock &b) { return x < b.range.first; });
  if (it == blocks.begin() || !std::prev(it)->range.contains(a)) return nullptr;
  return &*std::prev(it);
}

const MemoryBlock *MemoryMapInfo::region(std::string_view id) const {
  for (const auto *list : {&blocks, &rejected})
    for (const MemoryBlock &b : *list)
      if (b.origin == BlockOrigin::user && b.id == id) return &b;
  return nullptr;
}

void MemoryMapInfo::encode(Encoder &e) const {
  facts::encode(e, blocks);
  facts::encode(e, rejected);
  facts::encode(e, edited);
  e.u8(address_bits);
  facts::encode(e, space_bases);
}

MemoryMapInfo MemoryMapInfo::decode(Decoder &d) {
  MemoryMapInfo m;
  m.blocks = facts::decode<std::vector<MemoryBlock>>(d);
  m.rejected = facts::decode<std::vector<MemoryBlock>>(d);
  m.edited = facts::decode<bool>(d);
  m.address_bits = d.u8();
  m.space_bases = facts::decode<std::vector<std::uint64_t>>(d);
  return m;
}

// ---- checks ----

std::string check_region(const MemoryMapInfo &map, const RegionSpec &r, std::string_view replacing) {
  if (r.name.empty()) return "a region needs a name";
  if (r.size == 0) return "region " + r.name + " is empty";
  constexpr std::uint64_t kSlot = std::uint64_t{1} << loader::kSpaceKeyShift;
  const std::uint64_t base = r.start & ~(kSlot - 1);
  if (base != 0 && std::find(map.space_bases.begin(), map.space_bases.end(), base) != map.space_bases.end()) {
    // In another memory space: its offsets, which may not leave it.
    if (r.size > kSlot || r.start - base > kSlot - r.size)
      return "region " + r.name + " at " + hex_address(r.start - base) + " is past the end of its memory space";
  } else {
    const std::uint64_t top = map.address_bits >= 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << map.address_bits) - 1;
    if (r.size - 1 > top || r.start > top - (r.size - 1))
      return "region " + r.name + " at " + hex_address(r.start) + " is past the top of the " +
             std::to_string(map.address_bits) + "-bit address space";
  }
  if (r.bytes && r.bytes->length > r.size) return "region " + r.name + " has more file bytes than its size";
  for (const MemoryBlock &b : map.blocks) {
    if (b.origin == BlockOrigin::user && !replacing.empty() && b.id == replacing) continue;
    if (b.range.first <= r.last() && r.start <= b.range.last)
      return "region " + r.name + " [" + hex_address(r.start) + ", " + hex_address(r.last()) + "] overlaps " +
             (b.origin == BlockOrigin::user ? "region " : "block ") + describe_block(b);
  }
  return {};
}

// ---- queries ----

MemoryMapInfo MemoryMap::compute(facts::QueryContext &ctx, const Key &key) {
  auto loaded = ctx.get<LoadedProgram>(key);
  auto data = ctx.get<LoadedDataProgram>(key);
  MemoryMapInfo out;
  out.address_bits = static_cast<std::uint8_t>(std::min(64, loaded->pointer_size * 8));
  if (out.address_bits == 0) out.address_bits = 64;
  // Word-addressed code (AVR, PIC): keys are bytes, so the space is wider.
  for (std::uint32_t w = loaded->code_wordsize(); w > 1 && out.address_bits < 64; w >>= 1) ++out.address_bits;
  for (const SpaceInfo &sp : loaded->spaces)
    if (!sp.alias && sp.base != 0) out.space_bases.push_back(sp.base);

  // The edits, by sub.
  std::map<std::uint64_t, BlockEdit> edits;
  std::vector<std::pair<std::string, RegionSpec>> regions;
  for (const facts::FactKey &k : facts::asserted_at(ctx, facts::FactKind::MemoryRegion, {loaded->space, 0})) {
    auto v = ctx.get<facts::AssertedFact>(k);
    const auto *text = std::get_if<std::string>(&*v);
    if (text == nullptr) continue;
    if (k.sub.starts_with(kRegionSubPrefix)) {
      if (auto r = decode_region(*text)) regions.emplace_back(k.sub.substr(kRegionSubPrefix.size()), std::move(*r));
    } else if (k.sub.starts_with(kBlockSubPrefix)) {
      if (auto e = decode_block_edit(*text)) {
        std::uint64_t start = 0;
        if (std::sscanf(k.sub.c_str() + kBlockSubPrefix.size(), "%llx",
                        reinterpret_cast<unsigned long long *>(&start)) == 1)
          edits.emplace(start, std::move(*e));
      }
    }
  }

  for (const DataBlock &d : data->blocks) {
    MemoryBlock b;
    b.name = d.name;
    b.range = d.range;
    b.read = d.read;
    b.write = d.write;
    b.exec = d.exec;
    b.initialized = d.initialized;
    b.is_volatile = d.is_volatile;
    if (auto e = edits.find(d.range.first); e != edits.end()) {
      b.name = e->second.name.empty() ? d.name : e->second.name;
      b.read = e->second.read;
      b.write = e->second.write;
      b.exec = e->second.exec;
      b.is_volatile = e->second.is_volatile;
      b.edited = true;
      out.edited = true;
    }
    out.blocks.push_back(std::move(b));
  }

  // The user's regions, by start then id, each where nothing mapped is.
  std::sort(regions.begin(), regions.end(), [](const auto &a, const auto &b) {
    return a.second.start != b.second.start ? a.second.start < b.second.start : a.first < b.first;
  });
  for (auto &[id, r] : regions) {
    out.edited = true;
    MemoryBlock b;
    b.name = r.name;
    b.range = {r.start, r.size ? r.last() : r.start};
    b.read = r.read;
    b.write = r.write;
    b.exec = r.exec;
    b.initialized = r.initialized;
    b.is_volatile = r.is_volatile;
    b.origin = BlockOrigin::user;
    b.id = id;
    b.bytes = r.bytes;
    if (r.initialized && r.bytes && r.bytes->length != 0) {
      // The bytes are in this store unless a collaborator's are on their way.
      auto first = ctx.get<facts::MemoryPage>(facts::PageKey{r.bytes->space, r.bytes->offset / facts::kPageSize});
      if (first->empty()) {
        b.bytes_missing = true;
        b.initialized = false;
      }
    }
    b.rejected = check_region(out, r);
    if (!b.rejected.empty()) {
      out.rejected.push_back(std::move(b));
      continue;
    }
    auto at = std::upper_bound(out.blocks.begin(), out.blocks.end(), b.range.first,
                               [](std::uint64_t x, const MemoryBlock &m) { return x < m.range.first; });
    out.blocks.insert(at, std::move(b));
  }
  return out;
}

ProgramInfo Program::compute(facts::QueryContext &ctx, const Key &key) {
  auto loaded = ctx.get<LoadedProgram>(key);
  auto map = ctx.get<MemoryMap>(key);
  if (!map->edited) return *loaded;
  ProgramInfo info = *loaded;
  std::vector<Range> code, mapped = info.mapped;
  for (const MemoryBlock &b : map->blocks) {
    if (b.exec && b.initialized) code.push_back(b.range);
    if (b.origin != BlockOrigin::user) continue;
    mapped.push_back(b.range);
    if (!b.initialized) continue;
    // Its bytes: a file's, then zeros to its end.
    std::uint64_t next = b.range.first;
    if (b.bytes && b.bytes->length != 0) {
      const std::uint64_t last = b.range.first + (b.bytes->length - 1);
      info.sources.push_back({{b.range.first, last}, b.bytes->space, b.bytes->offset});
      next = last == b.range.last ? b.range.last : last + 1;
      if (last == b.range.last) continue;
    }
    info.sources.push_back({{next, b.range.last}, 0, 0});
  }
  info.code = normalize(std::move(code));
  info.mapped = normalize(std::move(mapped));
  return info;
}

DataProgramInfo DataProgram::compute(facts::QueryContext &ctx, const Key &key) {
  auto loaded = ctx.get<LoadedDataProgram>(key);
  auto map = ctx.get<MemoryMap>(key);
  if (!map->edited) return *loaded;
  DataProgramInfo out = *loaded;
  out.blocks.clear();
  for (const MemoryBlock &b : map->blocks) {
    DataBlock d;
    d.name = b.name;
    d.range = b.range;
    d.read = b.read;
    d.write = b.write;
    d.exec = b.exec;
    d.initialized = b.initialized;
    d.is_volatile = b.is_volatile;
    out.blocks.push_back(std::move(d));
  }
  return out;
}

void register_memory_queries(facts::Engine &engine) {
  engine.add_query<MemoryMap>();
  engine.add_query<Program>();
}

// ---- the map over a loaded image ----

namespace {

// Region bytes by sha256 (remember_region_bytes), while something uses them.
std::mutex g_region_bytes_mu;
std::map<std::string, std::weak_ptr<const loader::Bytes>> g_region_bytes;

std::shared_ptr<const loader::Bytes> remembered(const std::string &sha256) {
  std::lock_guard lock(g_region_bytes_mu);
  auto it = g_region_bytes.find(sha256);
  return it == g_region_bytes.end() ? nullptr : it->second.lock();
}

template <class Reader>
std::shared_ptr<const loader::Bytes> read_region(Reader &reader, const RegionBytes &b) {
  if (auto known = remembered(b.sha256); known && known->size() == b.length) return known;
  auto out = std::make_shared<loader::Bytes>();
  out->reserve(static_cast<std::size_t>(b.length));
  for (std::uint64_t i = 0; i < b.length;) {
    const std::uint64_t at = b.offset + i;
    auto page = reader.template get<facts::MemoryPage>(facts::PageKey{b.space, at / facts::kPageSize});
    const std::uint64_t in = at % facts::kPageSize;
    if (page->size() <= in) break;
    const std::uint64_t take = std::min<std::uint64_t>(b.length - i, page->size() - in);
    const auto *p = reinterpret_cast<const std::byte *>(page->data() + in);
    out->insert(out->end(), p, p + take);
    i += take;
  }
  if (out->size() != b.length) return nullptr;
  remember_region_bytes(b.sha256, out);
  return out;
}

}  // namespace

std::shared_ptr<const loader::Bytes> region_bytes(facts::QueryContext &ctx, const RegionBytes &b) {
  return read_region(ctx, b);
}

std::shared_ptr<const loader::Bytes> region_bytes(const facts::Snapshot &snap, const RegionBytes &b) {
  return read_region(snap, b);
}

void remember_region_bytes(const std::string &sha256, std::shared_ptr<const loader::Bytes> bytes) {
  std::lock_guard lock(g_region_bytes_mu);
  std::erase_if(g_region_bytes, [](const auto &e) { return e.second.expired(); });
  g_region_bytes[sha256] = bytes;
}

std::shared_ptr<loader::Image> image_with_memory(const loader::Image &loaded, const MemoryMapInfo &map,
                                                 const RegionBytesReader &bytes) {
  auto image = std::make_shared<loader::Image>(loaded);
  for (const MemoryBlock &m : map.blocks) {
    const std::uint64_t size = m.range.last - m.range.first + 1;
    const loader::Perms perms{m.read, m.write, m.exec};
    if (m.origin == BlockOrigin::image) {
      if (!m.edited) continue;
      for (loader::Block &b : image->blocks)
        if (b.start == m.range.first && b.size == size) {
          b.name = m.name;
          b.perms = perms;
          b.is_volatile = m.is_volatile;
        }
      // Its memory takes its permissions: the loaded region it is (raw
      // images), or its piece of one (a section inside a segment).
      image->memory.set_perms(m.range.first, size, perms);
      continue;
    }
    loader::Block b{m.name, m.range.first, size, perms, m.initialized, m.is_volatile};
    image->blocks.insert(std::upper_bound(image->blocks.begin(), image->blocks.end(), b.start,
                                          [](std::uint64_t a, const loader::Block &x) { return a < x.start; }),
                         b);
    loader::Region r{m.range.first, size, 0, 0, perms};
    std::shared_ptr<const loader::Bytes> data;
    if (m.initialized && m.bytes && m.bytes->length != 0 && bytes) data = bytes(*m.bytes);
    if (data) r.file_size = std::min<std::uint64_t>({data->size(), m.bytes->length, size});
    try {
      image->memory.add(r, data);
    } catch (const loader::LoadError &) {
      // The map is disjoint; a loaded region the blocks don't show (rare)
      // can still be in the way: the block stays, without memory.
    }
  }
  return image;
}

}  // namespace revkit::analysis
