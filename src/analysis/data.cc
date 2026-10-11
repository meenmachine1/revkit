// Data analysis: the data Ghidra's analyzers define (see data.h).

#include "data_internal.h"
#include "internal.h"
#include "revkit/analysis/data.h"
#include "revkit/analysis/no_return.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <unordered_set>

namespace revkit::analysis {

using namespace std::string_view_literals;
using facts::Decoder;
using facts::Encoder;

// ---- values ----

void DataBlock::encode(Encoder &e) const {
  e.bytes(name);
  range.encode(e);
  e.u8(static_cast<std::uint8_t>((read ? 1 : 0) | (write ? 2 : 0) | (exec ? 4 : 0) | (initialized ? 8 : 0) |
                                 (is_volatile ? 16 : 0)));
}

DataBlock DataBlock::decode(Decoder &d) {
  DataBlock b;
  b.name = std::string(d.bytes());
  b.range = Range::decode(d);
  const std::uint8_t f = d.u8();
  b.read = f & 1;
  b.write = f & 2;
  b.exec = f & 4;
  b.initialized = f & 8;
  b.is_volatile = f & 16;
  return b;
}

const DataBlock *DataProgramInfo::block(std::uint64_t a) const {
  auto it = std::upper_bound(blocks.begin(), blocks.end(), a,
                             [](std::uint64_t x, const DataBlock &b) { return x < b.range.first; });
  if (it == blocks.begin() || !std::prev(it)->range.contains(a)) return nullptr;
  return &*std::prev(it);
}

bool DataProgramInfo::has_relocation(std::uint64_t a) const {
  return std::binary_search(relocations.begin(), relocations.end(), a);
}

void DataProgramInfo::encode(Encoder &e) const {
  facts::encode(e, present);
  facts::encode(e, pe);
  e.u8(wide_char);
  facts::encode(e, blocks);
  facts::encode(e, relocatable);
  facts::encode(e, relocations);
  facts::encode(e, defined);
  facts::encode(e, pointers);
  facts::encode(e, symbols);
  facts::encode(e, loader_pointers);
}

DataProgramInfo DataProgramInfo::decode(Decoder &d) {
  DataProgramInfo v;
  v.present = facts::decode<bool>(d);
  v.pe = facts::decode<bool>(d);
  v.wide_char = d.u8();
  v.blocks = facts::decode<std::vector<DataBlock>>(d);
  v.relocatable = facts::decode<bool>(d);
  v.relocations = facts::decode<std::vector<std::uint64_t>>(d);
  v.defined = facts::decode<std::vector<Range>>(d);
  v.pointers = facts::decode<std::vector<std::pair<std::uint64_t, std::uint64_t>>>(d);
  v.symbols = facts::decode<std::vector<std::pair<std::uint64_t, std::uint32_t>>>(d);
  v.loader_pointers = facts::decode<std::vector<std::pair<std::uint64_t, std::uint64_t>>>(d);
  return v;
}

void DataItem::encode(Encoder &e) const {
  e.varint(address);
  e.varint(length);
  e.u8(static_cast<std::uint8_t>(kind));
  e.u8(origin);
  e.bytes(text);
  e.varint(value);
  facts::encode(e, written);
  facts::encode(e, literal);
  if (origin == kDataUser) {
    spec.encode(e);
    facts::encode(e, refs);
  }
}

DataItem DataItem::decode(Decoder &d) {
  DataItem v;
  v.address = d.varint();
  v.length = static_cast<std::uint32_t>(d.varint());
  const std::uint8_t k = d.u8();
  if (k > static_cast<std::uint8_t>(DataKind::defined)) throw facts::DecodeError("bad data kind");
  v.kind = static_cast<DataKind>(k);
  v.origin = d.u8();
  v.text = std::string(d.bytes());
  v.value = d.varint();
  v.written = facts::decode<bool>(d);
  v.literal = facts::decode<bool>(d);
  if (v.origin == kDataUser) {
    v.spec = DataSpec::decode(d);
    v.refs = facts::decode<std::vector<std::pair<std::uint64_t, std::uint64_t>>>(d);
  }
  return v;
}

const DataItem *DataList::at(std::uint64_t a) const {
  auto it = std::lower_bound(items.begin(), items.end(), a,
                             [](const DataItem &x, std::uint64_t y) { return x.address < y; });
  return it != items.end() && it->address == a ? &*it : nullptr;
}

const DataItem *DataList::containing(std::uint64_t a) const {
  auto it = std::upper_bound(items.begin(), items.end(), a,
                             [](std::uint64_t y, const DataItem &x) { return y < x.address; });
  if (it == items.begin()) return nullptr;
  --it;
  return a <= it->last() ? &*it : nullptr;
}

void DataList::encode(Encoder &e) const { facts::encode(e, items); }
DataList DataList::decode(Decoder &d) { return {facts::decode<std::vector<DataItem>>(d)}; }

std::size_t Data::weight(const DataList &v) {
  std::size_t w = sizeof(DataList) + v.items.capacity() * sizeof(DataItem);
  for (const DataItem &i : v.items) w += i.text.capacity();
  return w;
}

// ---- references ----

namespace {

// Constants through registers and temporaries, over straight-line code:
// what Ghidra's constant propagation (SymbolicPropogator) knows within a
// block, enough for RIP-relative operands, AArch64 adrp/add and RISC-V
// auipc/addi pairs and pointers loaded from memory.
class Consts {
 public:
  Consts(const ProgramInfo &info, detail::ByteReader &bytes) : info_(info), bytes_(bytes) {}

  // Register values: offset -> (size, value). A handful at a time, copied
  // at every branch: a sorted vector.
  using State = detail::FlatMap<std::uint64_t, std::pair<std::uint32_t, std::optional<std::uint64_t>>>;
  void clear() { vals_.clear(); }
  // After a call, values live on only in the registers the compiler spec
  // says a call preserves (callee-saved registers holding an address across
  // calls); argument, return and scratch registers are unknown. Ghidra's
  // SymbolicPropogator clears only killed-by-call and return registers,
  // which leaves stale arguments in registers the spec doesn't list as
  // killed (SuperH r4-r7); the ABI's preserved set is what compiled code
  // relies on.
  void call_made() {
    const auto &kept = info_.call_preserved;
    for (auto it = vals_.begin(); it != vals_.end();) {
      const std::uint64_t first = it->first, end = first + it->second.first;
      auto k = std::upper_bound(kept.begin(), kept.end(), RegisterSlot{first, ~std::uint32_t{0}});
      const bool preserved = k != kept.begin() && std::prev(k)->first <= first &&
                             end <= std::prev(k)->first + std::prev(k)->second;
      it = preserved ? std::next(it) : vals_.erase(it);
    }
  }
  const State &state() const { return vals_; }
  void set_state(State s) { vals_ = std::move(s); }

  // Runs one instruction, recording its references in `out`.
  void step(const lift::Instruction &insn, std::vector<DataRef> &out) {
    uniques_.clear();
    const std::uint64_t next = insn.address + insn.length;
    for (const lift::PcodeOp &op : insn.pcode) {
      const std::string &o = op.opcode;
      if (o == "BRANCH"sv || o == "CBRANCH"sv || o == "BRANCHIND"sv || o == "RETURN"sv || o == "CALLOTHER"sv) {
        if (op.output) set(*op.output, std::nullopt);
        continue;
      }
      if (o == "CALL"sv || o == "CALLIND"sv) {
        // The callee's: return and scratch registers are unknown after it,
        // which this doesn't track; values in others live on, as Ghidra's.
        continue;
      }
      // Memory operands SLEIGH resolved itself (x86-64 RIP-relative, absolute
      // addresses) are varnodes in the code space.
      for (const lift::Varnode &in : op.inputs)
        if (in.space == info_.code_space && memory(in.offset))
          out.push_back({insn.address, in.offset, in.size, DataAccess::read});
      if (op.output && op.output->space == info_.code_space && memory(op.output->offset))
        out.push_back({insn.address, op.output->offset, op.output->size, DataAccess::write});
      if (o == "STORE"sv) {
        if (op.inputs.size() < 3) continue;
        auto addr = pointer(op.inputs[0], get(op.inputs[1]));
        auto val = get(op.inputs[2]);
        if (addr && memory(*addr)) out.push_back({insn.address, *addr, op.inputs[2].size, DataAccess::write});
        if (val && *val != next && pointer_like(*val, op.inputs[2].size))
          out.push_back({insn.address, *val, 0, DataAccess::address});
        continue;
      }
      if (o == "LOAD"sv) {
        if (op.inputs.size() < 2 || !op.output) continue;
        auto addr = pointer(op.inputs[0], get(op.inputs[1]));
        std::optional<std::uint64_t> v;
        if (addr && memory(*addr)) {
          out.push_back({insn.address, *addr, op.output->size, DataAccess::read});
          // Ghidra trusts initialized memory (the analyzer's "trust
          // writable memory" default): a value loaded from a constant
          // address is known.
          if (op.output->size <= 8) v = bytes_.uint(*addr, op.output->size, info_.big_endian);
        }
        set(*op.output, v);
        if (v && op.output->space == "register"sv && pointer_like(*v, op.output->size))
          out.push_back({insn.address, *v, 0, DataAccess::address});
        continue;
      }
      if (!op.output) continue;
      std::optional<std::uint64_t> v = apply(op);
      set(*op.output, v);
      // An address computed into a register: a data reference (lea, adrp
      // and add, a constant moved in).
      if (v && *v != next && (op.output->space == "register"sv || op.output->space == info_.code_space) &&
          pointer_like(*v, op.output->size) &&
          !(o == "COPY"sv && op.inputs[0].space == "register"sv))
        out.push_back({insn.address, *v, 0, DataAccess::address});
    }
  }

 private:
  bool memory(std::uint64_t a) const { return a >= 4 && info_.is_mapped(a); }
  // The key a LOAD or STORE through `value` reaches, in the space its
  // first input names (counted in that space's units).
  std::optional<std::uint64_t> pointer(const lift::Varnode &space, std::optional<std::uint64_t> value) const {
    if (!value || space.referenced_space.empty()) return value;
    return info_.pointer_key(space.referenced_space, *value);
  }
  bool pointer_like(std::uint64_t v, std::uint32_t size) const { return size >= 4 && v >= 0x100 && info_.is_mapped(v); }

  static std::uint64_t mask(std::uint64_t v, std::uint32_t size) {
    return size >= 8 ? v : v & ((std::uint64_t{1} << (8 * size)) - 1);
  }

  std::optional<std::uint64_t> get(const lift::Varnode &v) {
    if (v.space == "const"sv) return mask(v.offset, v.size);
    if (v.space == info_.code_space && v.size <= 8 && memory(v.offset))
      return bytes_.uint(v.offset, v.size, info_.big_endian);
    if (v.space == "unique"sv) {
      for (const auto &[off, size, val] : uniques_)
        if (off == v.offset && size >= v.size) return val ? std::optional(mask(*val, v.size)) : std::nullopt;
      return std::nullopt;
    }
    if (v.space == "register"sv) {
      // The value written at the same offset, or (big-endian) a wider
      // register ending where the read ends: its low part (MIPS and
      // PowerPC read a 64-bit register's low 32 bits at offset + 4).
      auto it = vals_.find(v.offset);
      if (it != vals_.end() && it->second.first >= v.size && !info_.big_endian)
        return it->second.second ? std::optional(mask(*it->second.second, v.size)) : std::nullopt;
      if (info_.big_endian) {
        for (auto w = vals_.upper_bound(v.offset); w != vals_.begin();) {
          --w;
          if (v.offset - w->first >= 16) break;
          const auto &[size, val] = w->second;
          if (w->first + size == v.offset + v.size)
            return val ? std::optional(mask(*val, v.size)) : std::nullopt;
        }
      }
    }
    return std::nullopt;
  }

  void set(const lift::Varnode &v, std::optional<std::uint64_t> val) {
    if (val) val = mask(*val, v.size);
    if (v.space == "unique"sv) {
      for (auto &u : uniques_)
        if (std::get<0>(u) == v.offset) {
          u = {v.offset, v.size, val};
          return;
        }
      uniques_.emplace_back(v.offset, v.size, val);
      return;
    }
    if (v.space != "register"sv) return;
    // Forget what this write overlaps.
    auto it = vals_.lower_bound(v.offset >= 16 ? v.offset - 16 : 0);
    while (it != vals_.end() && it->first < v.offset + v.size) {
      if (it->first + it->second.first > v.offset) it = vals_.erase(it);
      else ++it;
    }
    // x86-64: writing a 32-bit register zeroes the upper half, which the
    // p-code says with a ZEXT into the full register itself.
    if (val) vals_[v.offset] = {v.size, val};
  }

  std::optional<std::uint64_t> apply(const lift::PcodeOp &op) {
    const std::string &o = op.opcode;
    auto in = [&](std::size_t i) -> std::optional<std::uint64_t> {
      return i < op.inputs.size() ? get(op.inputs[i]) : std::nullopt;
    };
    if (o == "COPY"sv || o == "INT_ZEXT"sv) return in(0);
    if (o == "INT_SEXT"sv) {
      auto a = in(0);
      if (!a || op.inputs.empty()) return std::nullopt;
      const std::uint32_t s = op.inputs[0].size;
      if (s >= 8) return a;
      const std::uint64_t sign = std::uint64_t{1} << (8 * s - 1);
      return (*a & sign) ? (*a | ~((sign << 1) - 1)) : *a;
    }
    // Every operation below needs its first input known.
    auto a = in(0);
    if (!a) return std::nullopt;
    auto b = in(1);
    if (o == "INT_ADD"sv && a && b) return *a + *b;
    if (o == "INT_SUB"sv && a && b) return *a - *b;
    if (o == "INT_AND"sv && a && b) return *a & *b;
    if (o == "INT_OR"sv && a && b) return *a | *b;
    if (o == "INT_XOR"sv && a && b) return *a ^ *b;
    if (o == "INT_MULT"sv && a && b) return *a * *b;
    if (o == "INT_LEFT"sv && a && b) return *b >= 64 ? 0 : *a << *b;
    if (o == "INT_RIGHT"sv && a && b) return *b >= 64 ? 0 : *a >> *b;
    if (o == "SUBPIECE"sv && a && b) return *b >= 8 ? 0 : *a >> (8 * *b);
    if (o == "PIECE"sv && a && b && op.inputs.size() == 2 && op.inputs[1].size < 8)
      return (*a << (8 * op.inputs[1].size)) | *b;
    if (o == "INT_2COMP"sv && a) return 0 - *a;
    if (o == "INT_NEGATE"sv && a) return ~*a;
    return std::nullopt;
  }

  const ProgramInfo &info_;
  detail::ByteReader &bytes_;
  State vals_;  // nullopt values aren't kept
  std::vector<std::tuple<std::uint64_t, std::uint32_t, std::optional<std::uint64_t>>> uniques_;
};

}  // namespace

namespace detail {

void collect_data_refs(const ProgramInfo &info, ByteReader &bytes, std::uint64_t start, std::size_t count,
                       const std::function<DecodedAt(std::uint64_t)> &at, std::vector<DataRef> &out) {
  // Depth first along the flow, as SymbolicPropogator.flowConstants goes:
  // fallthrough first, branch targets later with the values at the branch;
  // each instruction once, with the values of the first path to reach it.
  Consts consts(info, bytes);
  std::unordered_set<std::uint64_t> visited;
  visited.reserve(count);
  std::vector<std::pair<std::uint64_t, Consts::State>> work{{start, {}}};
  while (!work.empty()) {
    auto [a, state] = std::move(work.back());
    work.pop_back();
    consts.set_state(std::move(state));
    for (;;) {
      const auto [insn, i] = at(a);
      if (i == nullptr || insn == nullptr || !visited.insert(a).second) break;
      consts.step(*insn, out);
      if (i->kind == FlowKind::call || i->kind == FlowKind::call_indirect) consts.call_made();
      if (i->kind == FlowKind::jump || i->kind == FlowKind::branch || i->kind == FlowKind::jump_indirect)
        for (auto t = i->targets.rbegin(); t != i->targets.rend(); ++t)
          if (!visited.contains(info.code_address(*t))) work.emplace_back(info.code_address(*t), consts.state());
      if (!i->falls_through) break;
      a = i->address + i->length;
    }
  }
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
}

}  // namespace detail

// ---- the program's data ----

namespace {

// What occupies the program's memory as the steps lay data down.
class Listing {
 public:
  // `marked`: bytes the user's edits own (units.h) other than code marks:
  // obstacles like the loader's markup, never replaced. Sorted, disjoint.
  Listing(const ProgramInfo &info, const DataProgramInfo &data, const FunctionList &list, detail::ByteReader &bytes,
          std::vector<Range> marked = {})
      : info_(info), data_(data), list_(list), bytes_(bytes), marked_(std::move(marked)) {
    for (const FunctionInfo &f : list.functions) entries_.insert(f.entry.offset);
  }

  const DataProgramInfo &program() const { return data_; }
  const ProgramInfo &info() const { return info_; }
  detail::ByteReader &bytes() { return bytes_; }

  // The instruction containing `a`, if any.
  const CodeUnit *insn_containing(std::uint64_t a) const {
    auto it = std::upper_bound(list_.code.begin(), list_.code.end(), a,
                               [](std::uint64_t x, const CodeUnit &c) { return x < c.address; });
    if (it == list_.code.begin()) return nullptr;
    --it;
    return a - it->address < std::max<std::uint32_t>(it->length, 1) ? &*it : nullptr;
  }
  bool code_overlaps(std::uint64_t first, std::uint64_t last) const {
    if (insn_containing(first)) return true;
    auto it = std::upper_bound(list_.code.begin(), list_.code.end(), first,
                               [](std::uint64_t x, const CodeUnit &c) { return x < c.address; });
    return it != list_.code.end() && it->address <= last;
  }
  // Loader-defined data overlapping [first, last].
  const Range *defined_overlapping(std::uint64_t first, std::uint64_t last) const {
    for (const std::vector<Range> *v : {&data_.defined, &marked_}) {
      auto it = std::upper_bound(v->begin(), v->end(), first, [](std::uint64_t x, const Range &r) { return x < r.first; });
      if (it != v->begin() && std::prev(it)->last >= first) return &*std::prev(it);
      if (it != v->end() && it->first <= last) return &*it;
    }
    return nullptr;
  }
  bool is_function(std::uint64_t a) const { return entries_.contains(a); }
  bool in_body(std::uint64_t a) {
    if (bodies_.empty()) {
      for (const FunctionInfo &f : list_.functions)
        for (const facts::AddressRange &r : f.body.ranges()) bodies_.push_back({r.first.offset, r.last.offset});
      std::sort(bodies_.begin(), bodies_.end());
      bodies_.push_back({~std::uint64_t{0}, 0});  // computed
    }
    // Bodies are disjoint (discovery gives code to one function).
    auto it = std::upper_bound(bodies_.begin(), bodies_.end() - 1, a,
                               [](std::uint64_t x, const Range &r) { return x < r.first; });
    if (it != bodies_.begin() && std::prev(it)->contains(a)) return true;
    return false;
  }

  // Analysis data overlapping [first, last].
  std::vector<std::map<std::uint64_t, DataItem>::iterator> items_overlapping(std::uint64_t first,
                                                                              std::uint64_t last) {
    std::vector<std::map<std::uint64_t, DataItem>::iterator> out;
    auto it = items_.upper_bound(first);
    if (it != items_.begin() && std::prev(it)->second.last() >= first) out.push_back(std::prev(it));
    for (; it != items_.end() && it->first <= last; ++it) out.push_back(it);
    return out;
  }
  DataItem *item_containing(std::uint64_t a) {
    auto it = items_.upper_bound(a);
    if (it == items_.begin()) return nullptr;
    --it;
    return a <= it->second.last() ? &it->second : nullptr;
  }

  // Whether [first, last] holds only undefined bytes and undefinedN data
  // (DataUtilities.isUndefinedRange; also in one block).
  bool undefined_range(std::uint64_t first, std::uint64_t last) {
    const DataBlock *b = data_.block(first);
    if (b == nullptr || !b->range.contains(last) || last < first) return false;
    if (code_overlaps(first, last) || defined_overlapping(first, last)) return false;
    for (auto it : items_overlapping(first, last))
      if (it->second.kind != DataKind::undefined) return false;
    return true;
  }
  // Lays `item` down, clearing the undefinedN data it overlaps (callers
  // check undefined_range first).
  void put(DataItem item) {
    for (auto it : items_overlapping(item.address, item.last())) items_.erase(it);
    items_.emplace(item.address, std::move(item));
  }
  void erase(std::uint64_t a) { items_.erase(a); }

  std::map<std::uint64_t, DataItem> &items() { return items_; }

 private:
  const ProgramInfo &info_;
  const DataProgramInfo &data_;
  const FunctionList &list_;
  detail::ByteReader &bytes_;
  std::vector<Range> marked_;
  std::set<std::uint64_t> entries_;
  std::vector<Range> bodies_;
  std::map<std::uint64_t, DataItem> items_;
};

// UTF-8 for one code point (replacement character for invalid ones).
void append_utf8(std::string &out, std::uint32_t c) {
  if (c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) c = 0xfffd;
  if (c < 0x80) {
    out += static_cast<char>(c);
  } else if (c < 0x800) {
    out += static_cast<char>(0xc0 | (c >> 6));
    out += static_cast<char>(0x80 | (c & 0x3f));
  } else if (c < 0x10000) {
    out += static_cast<char>(0xe0 | (c >> 12));
    out += static_cast<char>(0x80 | ((c >> 6) & 0x3f));
    out += static_cast<char>(0x80 | (c & 0x3f));
  } else {
    out += static_cast<char>(0xf0 | (c >> 18));
    out += static_cast<char>(0x80 | ((c >> 12) & 0x3f));
    out += static_cast<char>(0x80 | ((c >> 6) & 0x3f));
    out += static_cast<char>(0x80 | (c & 0x3f));
  }
}

constexpr std::size_t kMaxUserRefs = 1 << 16;

// A user's data definition (units.h) as a data item: strings with their
// text, a lone pointer with its value, anything else `defined`; the
// pointers in it, where they hold mapped addresses, as references.
DataItem user_item(const UnitMap::Mark &m, const ProgramInfo &info, const DataProgramInfo &data,
                   detail::ByteReader &bytes) {
  const DataSpec &spec = m.mark.data;
  DataItem item;
  item.address = m.start;
  item.length = static_cast<std::uint32_t>(std::min<std::uint64_t>(m.mark.length, 0xffffffffu));
  item.origin = kDataUser;
  item.spec = spec;
  item.kind = DataKind::defined;
  const bool be = info.big_endian;
  if (spec.string != StringKind::none) {
    const unsigned unit = spec.string == StringKind::utf8 ? 1 : spec.string == StringKind::utf16 ? 2 : 4;
    item.kind = spec.string == StringKind::utf8 ? DataKind::string : spec.string == StringKind::utf16 ? DataKind::unicode : DataKind::unicode32;
    std::uint64_t at = item.address, end = item.address + item.length;
    if (spec.layout == StringLayout::pascal) at += 1;
    else if (spec.layout == StringLayout::pascal16) at += 2;
    std::vector<std::uint32_t> units;
    for (; at + unit <= end; at += unit) {
      auto v = bytes.uint(at, unit, be);
      if (!v || *v == 0) break;
      units.push_back(static_cast<std::uint32_t>(*v));
    }
    if (unit == 1) {
      for (std::uint32_t c : units) item.text += static_cast<char>(c);
    } else {
      for (std::size_t i = 0; i < units.size(); ++i) {
        std::uint32_t c = units[i];
        if (unit == 2 && c >= 0xd800 && c < 0xdc00 && i + 1 < units.size() && units[i + 1] >= 0xdc00 && units[i + 1] < 0xe000)
          c = 0x10000 + ((c - 0xd800) << 10) + (units[++i] - 0xdc00);
        append_utf8(item.text, c);
      }
    }
    return item;
  }
  const std::uint64_t elements = std::max<std::uint64_t>(spec.count, 1);
  if (spec.count == 0 && spec.format == ValueFormat::pointer) item.kind = DataKind::pointer;
  if (spec.pointer_size == 0 || spec.pointers.empty()) return item;
  for (std::uint64_t e = 0; e < elements && item.refs.size() < kMaxUserRefs; ++e)
    for (std::uint64_t off : spec.pointers) {
      const std::uint64_t slot = item.address + e * spec.element + off;
      if (slot + spec.pointer_size > item.address + item.length) break;
      auto v = bytes.uint(slot, spec.pointer_size, be);
      if (!v) continue;
      if (item.kind == DataKind::pointer) item.value = *v;
      if (*v != 0 && data.block(*v) != nullptr) item.refs.emplace_back(slot, *v);
    }
  return item;
}

// Step 1: undefinedN where code accesses memory at a constant address.
void accesses(Listing &l, const std::vector<DataRef> &refs) {
  for (const DataRef &r : refs) {
    if (r.access == DataAccess::address || r.size < 1 || r.size > 8) continue;
    const std::uint64_t a = r.to, last = a + r.size - 1;
    if (last < a) continue;
    // createData: only where an undefined code unit starts (not inside an
    // instruction, defined data or another undefinedN).
    if (l.insn_containing(a) || l.defined_overlapping(a, a)) continue;
    if (DataItem *at = l.item_containing(a); at && (at->address != a || at->kind != DataKind::undefined)) continue;
    if (!l.undefined_range(a, last)) continue;
    l.put({a, r.size, DataKind::undefined, kDataAccess, {}, 0});
  }
}

// Step 2: OperandReferenceAnalyzer (and DataOperandReferenceAnalyzer for
// references from pointers): strings and pointers at referenced addresses.
class References {
 public:
  References(Listing &l, std::set<std::uint64_t> &targets) : l_(l), targets_(targets) {
    const std::string &lang = l.info().language;
    pointers_ = !lang.starts_with("ARM:");  // Ghidra turns pointer creation off for ARM
  }

  // Processes one referenced address; returns the pointer laid down, if any.
  std::optional<std::uint64_t> visit(std::uint64_t target, std::set<std::uint64_t> &checked) {
    if (!checked.insert(target).second) return std::nullopt;
    const DataProgramInfo &p = l_.program();
    if (p.block(target) == nullptr) return std::nullopt;
    bool undefined_stuff = false;
    if (l_.defined_overlapping(target, target)) return std::nullopt;
    if (const DataItem *d = l_.item_containing(target)) {
      if (d->kind != DataKind::undefined) return std::nullopt;  // a string or pointer already
      undefined_stuff = true;
    } else if (l_.insn_containing(target)) {
      return std::nullopt;
    }
    (void)undefined_stuff;
    if (ascii(target)) return std::nullopt;
    if (unicode(target)) return std::nullopt;
    if (pointers_) return pointer(target);
    return std::nullopt;
  }

 private:
  // A reference to an address in (start, start + length): Ghidra leaves
  // the range alone (desiredDataMemoryContainsReference).
  bool referenced_inside(std::uint64_t start, std::uint64_t length) const {
    auto it = targets_.upper_bound(start);
    return it != targets_.end() && *it - start < length;
  }

  // getStringLength: printable ASCII (and tab, CR, LF) to a NUL within
  // 1000 bytes, at least 5 characters; the length includes the NUL.
  bool ascii(std::uint64_t target) {
    auto bytes = l_.bytes().read(target, 1000);
    std::size_t n = 0;
    for (; n < bytes.size(); ++n) {
      const auto c = std::to_integer<std::uint8_t>(bytes[n]);
      if (c == 0) break;
      if (c >= 0x7f || (c < 0x20 && c != 0x09 && c != 0x0a && c != 0x0d)) return false;
    }
    if (n >= bytes.size() || n < 5) return false;
    const std::uint32_t length = static_cast<std::uint32_t>(n + 1);
    if (referenced_inside(target, length)) return true;  // as if made (asciiLen > 4)
    if (!l_.undefined_range(target, target + length - 1)) return true;
    std::string text(reinterpret_cast<const char *>(bytes.data()), n);
    l_.put({target, length, DataKind::string, kDataReference, std::move(text), 0});
    return true;
  }

  // getWStrLen: 16-bit printable ASCII characters to a 0 within 1000; at
  // least 4, and not much shorter than the string 8 bytes before.
  int wstrlen(std::uint64_t a) {
    const bool be = l_.info().big_endian;
    for (int i = 0; i < 1000; ++i) {
      auto v = l_.bytes().uint(a + 2 * static_cast<std::uint64_t>(i), 2, be);
      if (!v) return -1;
      if (*v == 0) return i;
      if (*v != 0x09 && *v != 0x0a && *v != 0x0d && (*v < 0x20 || *v >= 0x7f)) return -1;
    }
    return -1;
  }
  bool unicode(std::uint64_t target) {
    const int len = wstrlen(target);
    if (len <= 0) return false;
    if (wstrlen(target - 8) > len + 2) return false;
    if (len <= 3) return false;
    if (referenced_inside(target, static_cast<std::uint64_t>(len))) return false;
    const std::uint32_t length = 2 * static_cast<std::uint32_t>(len + 1);
    if (!l_.undefined_range(target, target + length - 1)) return true;
    std::string text;
    const bool be = l_.info().big_endian;
    for (int i = 0; i < len; ++i)
      text += static_cast<char>(*l_.bytes().uint(target + 2 * static_cast<std::uint64_t>(i), 2, be));
    l_.put({target, length, DataKind::unicode, kDataReference, std::move(text), 0});
    return true;
  }

  // checkForPointer.
  std::optional<std::uint64_t> pointer(std::uint64_t target) {
    const DataProgramInfo &p = l_.program();
    const unsigned size = l_.info().pointer_size;
    if (p.relocatable && !p.relocations.empty() && !p.has_relocation(target)) return std::nullopt;
    auto v = l_.bytes().uint(target, size, l_.info().big_endian);
    if (!v || *v < 4096) return std::nullopt;
    if (p.block(*v) == nullptr) return std::nullopt;
    if (referenced_inside(target, size)) return std::nullopt;
    // Not into the middle of something.
    if (const CodeUnit *c = l_.insn_containing(*v)) {
      if (c->address != *v) return std::nullopt;
      // An instruction others fall into is only a target as a function.
      if (!l_.is_function(*v)) {
        if (l_.insn_containing(*v - 1)) return std::nullopt;
        if (l_.in_body(*v)) return std::nullopt;
      }
    } else if (const DataItem *d = l_.item_containing(*v); d && d->address != *v) {
      return std::nullopt;
    }
    if (!l_.undefined_range(target, target + size - 1)) return std::nullopt;
    l_.put({target, size, DataKind::pointer, kDataReference, {}, *v});
    targets_.insert(*v);
    return target;
  }

  Listing &l_;
  std::set<std::uint64_t> &targets_;  // every referenced address
  bool pointers_ = true;
};

}  // namespace

namespace {
struct StepTimer {
  const char *what;
  std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
  void lap(const char *next) {
    static const bool on = std::getenv("REVKIT_TIMING") != nullptr;
    auto now = std::chrono::steady_clock::now();
    if (on) std::fprintf(stderr, "revkit: analysis.data %s %.1f ms\n", what, std::chrono::duration<double, std::milli>(now - start).count());
    what = next;
    start = now;
  }
};
}  // namespace

DataList Data::compute(facts::QueryContext &ctx, const ProgramKey &key) {
  DataList out;
  StepTimer timer{"inputs"};
  auto data = ctx.get<DataProgram>(key);
  if (!data->present) return out;
  auto info = ctx.get<Program>(key);
  auto list = ctx.get<Functions>(key);
  // Every flow's references, in order of the referring instruction.
  std::vector<Location> keys;
  keys.reserve(list->functions.size());
  for (const FunctionInfo &f : list->functions) keys.push_back({key, f.flow_key()});
  std::vector<DataRef> refs;
  std::vector<Range> literals;
  {
    auto got = ctx.get_all<Flow>(keys);
    std::size_t n = 0;
    for (const auto &g : got) n += g->data_refs.size();
    refs.reserve(n);
    for (const auto &g : got) {
      refs.insert(refs.end(), g->data_refs.begin(), g->data_refs.end());
      literals.insert(literals.end(), g->literals.begin(), g->literals.end());
    }
  }
  std::sort(literals.begin(), literals.end());
  {
    std::vector<Range> merged;  // disjoint, so one look back finds a range
    for (const Range &r : literals) {
      if (!merged.empty() && r.first <= merged.back().last + 1) merged.back().last = std::max(merged.back().last, r.last);
      else merged.push_back(r);
    }
    literals = std::move(merged);
  }
  timer.lap("sort");
  std::sort(refs.begin(), refs.end());
  refs.erase(std::unique(refs.begin(), refs.end()), refs.end());
  timer.lap("steps 1-2");

  detail::ByteReader bytes(ctx, *info);
  // The listing's edits (units.h): bytes they own are the user's, whatever
  // the steps below would find there; the live data items are laid first.
  auto units = ctx.get<Units>(key);
  std::vector<Range> marked;
  for (const UnitPiece &p : units->pieces) {
    if (units->marks[p.mark].mark.kind == UnitKind::code) continue;
    if (!marked.empty() && marked.back().last != ~std::uint64_t{0} && p.first == marked.back().last + 1) marked.back().last = p.last;
    else marked.push_back({p.first, p.last});
  }
  Listing l(*info, *data, *list, bytes, std::move(marked));
  std::vector<std::pair<std::uint64_t, std::uint64_t>> user_refs;
  for (const UnitMap::Mark &m : units->marks) {
    if (m.mark.kind != UnitKind::data || !m.alive) continue;
    DataItem item = user_item(m, *info, *data, bytes);
    user_refs.insert(user_refs.end(), item.refs.begin(), item.refs.end());
    l.items().emplace(item.address, std::move(item));
  }
  // The loader's markup: GOT pointers, and undefinedN at object symbols
  // (dropped from the result: the symbols are the inputs' own).
  for (const auto &[a, v] : data->loader_pointers)
    if (l.undefined_range(a, a + info->pointer_size - 1))
      l.put({a, info->pointer_size, DataKind::pointer, kDataLoader, {}, v});
  for (const auto &[a, size] : data->symbols)
    if (size != 0 && l.undefined_range(a, a + size - 1)) l.put({a, size, DataKind::undefined, 0, {}, 0});
  accesses(l, refs);

  std::set<std::uint64_t> targets;
  for (const DataRef &r : refs) targets.insert(r.to);
  for (const auto &[at, v] : data->pointers) targets.insert(v);
  for (const auto &[at, v] : user_refs) targets.insert(v);
  References step(l, targets);
  {
    std::set<std::uint64_t> checked;
    for (const DataRef &r : refs) step.visit(r.to, checked);
  }
  // References from data: the loader's pointers, then the pointers made,
  // in address order, until no new pointer appears.
  {
    std::set<std::uint64_t> checked;
    std::map<std::uint64_t, std::uint64_t> pending(data->pointers.begin(), data->pointers.end());
    for (const auto &[at, v] : user_refs) pending.emplace(at, v);
    for (const auto &[a, item] : l.items())
      if (item.kind == DataKind::pointer) pending.emplace(a, item.value);
    std::set<std::uint64_t> done;
    while (!pending.empty()) {
      auto [from, to] = *pending.begin();
      pending.erase(pending.begin());
      if (!done.insert(from).second) continue;
      if (auto made = step.visit(to, checked))
        if (const DataItem *d = l.item_containing(*made)) pending.emplace(*made, d->value);
    }
  }

  timer.lap("strings");
  detail::search_strings(l.info(), *data, bytes, [&](std::uint64_t first, std::uint64_t last) {
    return l.undefined_range(first, last);
  }, [&](std::uint64_t first, std::uint64_t last) {
    // Padding: bytes no code unit (instruction, defined or undefinedN data) holds.
    return !l.code_overlaps(first, last) && !l.defined_overlapping(first, last) &&
           l.items_overlapping(first, last).empty();
  }, [&](std::uint64_t a) -> const DataItem * { return l.item_containing(a); },
     [&](DataItem item) { l.put(std::move(item)); },
     [&](std::size_t n, const std::function<void(std::size_t)> &fn) { ctx.parallel_for(n, fn); });

  timer.lap("labels");
  // Step 4: what references reach that is still undefined.
  for (std::uint64_t t : targets) {
    if (data->block(t) == nullptr || l.item_containing(t) || l.insn_containing(t) || l.defined_overlapping(t, t))
      continue;
    l.put({t, 1, DataKind::label, kDataLabel, {}, 0});
  }

  std::set<std::uint64_t> written;
  for (const DataRef &r : refs)
    if (r.access == DataAccess::write) written.insert(r.to);
  for (auto &[a, item] : l.items()) {
    // Code writes somewhere in it (a buffer's element, not only its start).
    auto w = written.lower_bound(a);
    item.written = w != written.end() && *w <= item.last();
    auto it = std::upper_bound(literals.begin(), literals.end(), a, [](std::uint64_t x, const Range &r) { return x < r.first; });
    item.literal = it != literals.begin() && std::prev(it)->first <= a && item.last() <= std::prev(it)->last;
  }

  out.items.reserve(l.items().size());
  for (auto &[a, item] : l.items())
    if (item.origin != 0) out.items.push_back(std::move(item));
  timer.lap("");
  return out;
}

void register_data_queries(facts::Engine &engine) {
  engine.add_input<LoadedDataProgram>();
  engine.add_query<DataProgram>();
  engine.add_query<NoReturnEvidence>();
  engine.add_query<Data>();
}

}  // namespace revkit::analysis
