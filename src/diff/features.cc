// diff.features: per-function fingerprints F0-F4 (features.h).

#include "revkit/diff/features.h"

#include "revkit/facts/fact_db.h"
#include "internal.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <map>
#include <set>
#include <unordered_map>

namespace revkit::diff {

using namespace std::string_view_literals;

Hasher &Hasher::str(std::string_view s) {
  u64(s.size());
  std::uint64_t w = 0;
  std::size_t i = 0;
  for (; i + 8 <= s.size(); i += 8) {
    std::memcpy(&w, s.data() + i, 8);
    u64(w);
  }
  w = 0;
  for (std::size_t k = 0; i < s.size(); ++i, ++k) w |= std::uint64_t{static_cast<unsigned char>(s[i])} << (8 * k);
  return u64(w);
}

bool is_default_name(std::string_view name) {
  if (name.empty()) return true;
  for (std::string_view prefix : {"FUN_"sv, "thunk_FUN_"sv, "LAB_"sv, "SUB_"sv})
    if (name.starts_with(prefix)) return true;
  return false;
}

void FunctionFeatures::encode(facts::Encoder &e) const {
  e.varint(entry);
  e.bytes(name);
  facts::encode(e, name_source);
  facts::encode(e, thunk);
  e.u64be(bytes);
  e.u64be(raw);
  e.u64be(pcode);
  e.u64be(shape);
  e.u64be(opcodes);
  e.u64be(refs);
  std::uint64_t md = 0;
  std::memcpy(&md, &md_index, 8);
  e.u64be(md);
  e.varint(instructions);
  e.varint(blocks);
  e.varint(edges);
  e.varint(loops);
  e.varint(pcode_ops);
  facts::encode(e, calls);
  facts::encode(e, bag);
  facts::encode(e, strings);
  facts::encode(e, globals);
}

FunctionFeatures FunctionFeatures::decode(facts::Decoder &d) {
  FunctionFeatures f;
  f.entry = d.varint();
  f.name = std::string(d.bytes());
  f.name_source = facts::decode<NameSource>(d);
  f.thunk = facts::decode<bool>(d);
  f.bytes = d.u64be();
  f.raw = d.u64be();
  f.pcode = d.u64be();
  f.shape = d.u64be();
  f.opcodes = d.u64be();
  f.refs = d.u64be();
  std::uint64_t md = d.u64be();
  std::memcpy(&f.md_index, &md, 8);
  f.instructions = static_cast<std::uint32_t>(d.varint());
  f.blocks = static_cast<std::uint32_t>(d.varint());
  f.edges = static_cast<std::uint32_t>(d.varint());
  f.loops = static_cast<std::uint32_t>(d.varint());
  f.pcode_ops = static_cast<std::uint32_t>(d.varint());
  f.calls = facts::decode<std::vector<std::uint64_t>>(d);
  f.bag = facts::decode<std::vector<std::uint32_t>>(d);
  f.strings = facts::decode<std::vector<std::uint32_t>>(d);
  f.globals = facts::decode<std::vector<std::uint64_t>>(d);
  return f;
}

namespace {

using namespace detail;

struct Block {
  std::size_t first = 0, last = 0;  // instruction indexes
  std::vector<std::size_t> succ;
  std::uint32_t in = 0;
  std::uint32_t level = 0;
};

}  // namespace

FunctionFeatures Features::compute(facts::QueryContext &ctx, const Key &key) {
  FunctionFeatures f;
  auto info = ctx.get<analysis::Program>(key.program);
  auto fn = ctx.get<analysis::Function>(key);
  if (fn->name.empty() && fn->body.empty()) {
    ctx.set_confidence(facts::Confidence::Uncertain);
    return f;
  }
  f.entry = key.address;
  f.thunk = (fn->flags & analysis::kFunctionThunk) != 0;
  const facts::SpaceId space = info->space;

  // F0
  auto asserted = ctx.get<facts::AssertedFact>(facts::FactKey::name({space, key.address}));
  if (const auto *s = std::get_if<std::string>(asserted.get()); s && !s->empty() && !is_default_name(*s)) {
    f.name = *s;
    f.name_source = NameSource::asserted;
  } else if (!fn->import.empty()) {
    f.name = fn->import;
    f.name_source = NameSource::import;
  } else if (!is_default_name(fn->name)) {
    f.name = fn->name;
    f.name_source = NameSource::symbol;
  }

  auto flow = ctx.get<analysis::Flow>(analysis::Location{key.program, fn->flow_key()});
  const bool tagged = (fn->flags & analysis::kFunctionTagged) != 0;
  std::vector<const analysis::FlowInsn *> insns;
  std::vector<std::size_t> flow_index;  // index in flow->insns
  for (std::size_t i = 0; i < flow->insns.size(); ++i) {
    const analysis::FlowInsn &in = flow->insns[i];
    if (!fn->body.contains({space, in.address})) continue;
    insns.push_back(&in);
    flow_index.push_back(i);
  }
  f.instructions = static_cast<std::uint32_t>(insns.size());
  std::unordered_map<std::uint64_t, std::size_t> at;
  for (std::size_t i = 0; i < insns.size(); ++i) at.emplace(insns[i]->address, i);
  auto in_body = [&](std::uint64_t a) { return at.contains(a); };

  // References each instruction makes (flow->refs indexes flow->insns).
  std::map<std::uint32_t, std::vector<const analysis::FlowRef *>> refs_of;
  for (const analysis::FlowRef &r : flow->refs) refs_of[r.insn].push_back(&r);
  std::map<std::uint64_t, std::vector<std::uint64_t>> data_of;
  for (const analysis::DataRef &r : flow->data_refs) data_of[r.from].push_back(r.to);

  // Callees and other functions: what a target is, memoized per address.
  struct Target {
    bool function = false;
    std::string import, name;  // an import stub's symbol; a named function's name
  };
  std::map<std::uint64_t, Target> targets;
  auto target = [&](std::uint64_t a) -> const Target & {
    auto it = targets.find(a);
    if (it != targets.end()) return it->second;
    Target t;
    auto g = ctx.get<analysis::Function>(analysis::Location{key.program, a});
    if (!g->name.empty() || !g->body.empty()) {
      t.function = true;
      t.import = g->import;
      if (g->import.empty() && !is_default_name(g->name)) t.name = g->name;
    }
    return targets.emplace(a, std::move(t)).first->second;
  };
  // Data: strings by content, memoized per address.
  std::map<std::uint64_t, std::optional<std::uint32_t>> string_at;
  analysis::CodeReader code(ctx, *info);
  auto string_hash = [&](std::uint64_t a) -> std::optional<std::uint32_t> {
    auto it = string_at.find(a);
    if (it != string_at.end()) return it->second;
    std::optional<std::uint32_t> h;
    if (!info->is_code(a) && info->is_mapped(a))
      if (auto s = AsciiString(code.bytes(a, 64))) h = Hash32(Hasher().str("s").str(*s).done());
    return string_at.emplace(a, h).first->second;
  };

  std::set<std::uint32_t> bag;
  auto bag_add = [&](char tag, std::string_view s) { bag.insert(Hash32(Hasher().u64(static_cast<unsigned char>(tag)).str(s).done())); };
  std::set<std::uint32_t> seen_strings;
  std::set<std::uint64_t> seen_globals;

  Hasher bytes_h, pcode_h, raw_h;
  std::uint64_t opcodes = 1;
  const std::string &cs = info->code_space;
  for (std::size_t i = 0; i < insns.size(); ++i) {
    const analysis::FlowInsn &in = *insns[i];
    auto insn = code.decode(in.address, tagged);
    Hasher insn_p;  // this instruction's p-code tokens
    // External values: targets and references outside the function.
    std::vector<std::uint64_t> external;
    std::vector<std::string> tags;  // what they are, sorted for a stable order
    for (std::uint64_t t : in.targets) {
      if (in_body(t)) continue;
      external.push_back(t);
      const Target &g = target(t);
      if (!g.function) {
        tags.emplace_back("c");
        continue;
      }
      if (in.kind == analysis::FlowKind::call || in.kind == analysis::FlowKind::jump ||
          in.kind == analysis::FlowKind::branch || in.kind == analysis::FlowKind::call_indirect ||
          in.kind == analysis::FlowKind::jump_indirect)
        f.calls.push_back(t);
      if (!g.import.empty()) {
        tags.push_back("i:" + g.import);
        bag_add('i', g.import);
      } else {
        tags.emplace_back("f");
        if (!g.name.empty()) bag_add('n', g.name);
      }
    }
    auto data_value = [&](std::uint64_t to) {
      if (in_body(to)) return;
      if (std::find(external.begin(), external.end(), to) != external.end()) return;
      external.push_back(to);
      // No tag for F1 and F2: whether a constant is an address, and what is
      // there, depends on the memory map and on analysis (a firmware that
      // grew or shrank turns 2000000 into a pointer or back), not on the
      // code. Strings and other data go to the bag and the neighbourhoods.
      if (info->is_code(to)) return;
      if (auto s = string_hash(to)) {
        bag.insert(*s);
        if (seen_strings.insert(*s).second && f.strings.size() < FunctionFeatures::kMaxRefs) f.strings.push_back(*s);
        return;
      }
      if (seen_globals.insert(to).second && f.globals.size() < FunctionFeatures::kMaxRefs) f.globals.push_back(to);
    };
    if (auto r = refs_of.find(static_cast<std::uint32_t>(flow_index[i])); r != refs_of.end())
      for (const analysis::FlowRef *ref : r->second)
        if (ref->kind != analysis::RefKind::call && ref->kind != analysis::RefKind::jump &&
            ref->kind != analysis::RefKind::conditional_jump)
          data_value(ref->to);
    if (auto d = data_of.find(in.address); d != data_of.end())
      for (std::uint64_t to : d->second) data_value(to);
    std::sort(tags.begin(), tags.end());

    std::uint32_t own_length = in.length - in.delay;
    if (insn) {
      own_length = insn->length;
      for (const lift::PcodeOp &op : insn->pcode) {
        const std::uint32_t oi = OpcodeIndex(op.opcode);
        opcodes *= Prime(oi);
        ++f.pcode_ops;
        insn_p.u64(oi);
        auto operand = [&](const lift::Varnode &v, bool keep_value) {
          const Kind k = KindOf(v, cs);
          insn_p.u64(static_cast<std::uint64_t>(k) << 32 | v.size);
          // An instruction that refers outside the function may hold part of
          // an address in any constant (AArch64's add after adrp, RISC-V's
          // addi after auipc): its constants count by kind only.
          if (k != Kind::constant || !keep_value || !external.empty()) return;
          const bool address = info->is_mapped(v.offset) && v.offset >= 0x1000;
          if (address || std::find(external.begin(), external.end(), v.offset) != external.end()) {
            insn_p.u64(0xadd5);
            return;
          }
          insn_p.u64(v.offset);
          const std::int64_t sv = Signed(v.offset, v.size);
          if ((sv >= 0x10000 || sv <= -0x10000) && bag.size() < 256) {
            bag.insert(Hash32(Hasher().u64('k').u64(v.offset).done()));
          }
        };
        if (op.output) operand(*op.output, false);
        const bool is_space_op = op.opcode == "LOAD"sv || op.opcode == "STORE"sv;
        for (std::size_t j = 0; j < op.inputs.size(); ++j)
          operand(op.inputs[j], !(is_space_op && j == 0));
      }
      if (insn->unimplemented) insn_p.u64(0xbad);
    } else {
      insn_p.u64(0xdead);
    }
    for (const std::string &t : tags) insn_p.str(t);
    const std::uint64_t p = insn_p.done();
    pcode_h.u64(p);

    // F1: the bytes with address fields masked, at their offset from the entry.
    auto raw = code.bytes(in.address, in.length);
    raw_h.u64(in.address - key.address).u64(in.length);
    for (std::byte x : raw) raw_h.u64(std::to_integer<std::uint64_t>(x));
    std::vector<std::byte> b(raw.begin(), raw.end());
    std::vector<bool> masked(b.size(), false);
    bool whole = false;
    for (std::uint64_t v : external)
      if (!MaskField(b, masked, v, in.address, own_length, info->big_endian, info->pointer_size)) whole = true;
    bytes_h.u64(in.address - key.address).u64(in.length);
    if (whole) {
      bytes_h.u64(0x3a5c).u64(p);
    } else {
      for (std::size_t k = 0; k < b.size(); ++k) bytes_h.u64(masked[k] ? 0x100 : std::to_integer<std::uint64_t>(b[k]));
      for (const std::string &t : tags) bytes_h.str(t);
    }
  }
  f.bytes = bytes_h.u64(f.instructions).done();
  f.raw = raw_h.u64(f.instructions).done();
  f.pcode = pcode_h.u64(f.instructions).done();
  f.opcodes = Hasher().u64(opcodes).u64(f.instructions).done();

  // F3: basic blocks and edges within the body.
  std::vector<bool> leader(insns.size(), false);
  if (!insns.empty()) leader[0] = true;
  auto ends_block = [](const analysis::FlowInsn &in) {
    using K = analysis::FlowKind;
    return in.kind == K::jump || in.kind == K::branch || in.kind == K::jump_indirect || in.kind == K::ret ||
           !in.falls_through || in.tail_call;
  };
  for (std::size_t i = 0; i < insns.size(); ++i) {
    const analysis::FlowInsn &in = *insns[i];
    if (in.kind != analysis::FlowKind::call && in.kind != analysis::FlowKind::call_indirect)
      for (std::uint64_t t : in.targets)
        if (auto it = at.find(t); it != at.end()) leader[it->second] = true;
    if (i + 1 < insns.size() && (ends_block(in) || insns[i + 1]->address != in.address + in.length)) leader[i + 1] = true;
  }
  if (!insns.empty() && at.contains(key.address)) leader[at.at(key.address)] = true;
  std::vector<Block> blocks;
  std::vector<std::size_t> block_of(insns.size());
  for (std::size_t i = 0; i < insns.size(); ++i) {
    if (leader[i]) blocks.push_back({i, i, {}, 0, 0});
    blocks.back().last = i;
    block_of[i] = blocks.size() - 1;
  }
  for (Block &bl : blocks) {
    const analysis::FlowInsn &last = *insns[bl.last];
    std::set<std::size_t> succ;
    if (last.falls_through && !last.tail_call && last.kind != analysis::FlowKind::ret) {
      if (auto it = at.find(last.address + last.length); it != at.end()) succ.insert(block_of[it->second]);
    }
    if (last.kind != analysis::FlowKind::call && last.kind != analysis::FlowKind::call_indirect)
      for (std::uint64_t t : last.targets)
        if (auto it = at.find(t); it != at.end()) succ.insert(block_of[it->second]);
    bl.succ.assign(succ.begin(), succ.end());
  }
  for (const Block &bl : blocks)
    for (std::size_t s : bl.succ) ++blocks[s].in;
  f.blocks = static_cast<std::uint32_t>(blocks.size());
  for (const Block &bl : blocks) f.edges += static_cast<std::uint32_t>(bl.succ.size());
  if (!blocks.empty()) {
    // Levels: breadth first from the entry's block; unreached blocks last.
    const std::size_t start = at.contains(key.address) ? block_of[at.at(key.address)] : 0;
    constexpr std::uint32_t kUnset = ~0u;
    for (Block &bl : blocks) bl.level = kUnset;
    std::vector<std::size_t> queue{start};
    blocks[start].level = 0;
    std::uint32_t deepest = 0;
    for (std::size_t q = 0; q < queue.size(); ++q) {
      const Block &bl = blocks[queue[q]];
      for (std::size_t s : bl.succ)
        if (blocks[s].level == kUnset) {
          blocks[s].level = bl.level + 1;
          deepest = std::max(deepest, blocks[s].level);
          queue.push_back(s);
        }
    }
    for (Block &bl : blocks)
      if (bl.level == kUnset) bl.level = deepest + 1;
    // Back edges: an iterative depth-first search from the entry.
    std::vector<std::uint8_t> state(blocks.size(), 0);  // 0 new, 1 on stack, 2 done
    std::vector<std::pair<std::size_t, std::size_t>> stack{{start, 0}};
    state[start] = 1;
    while (!stack.empty()) {
      auto &[node, next] = stack.back();
      if (next < blocks[node].succ.size()) {
        const std::size_t s = blocks[node].succ[next++];
        if (state[s] == 1) ++f.loops;
        else if (state[s] == 0) {
          state[s] = 1;
          stack.emplace_back(s, 0);
        }
      } else {
        state[node] = 2;
        stack.pop_back();
      }
    }
    // BinDiff's MD index: each edge weighted by its ends' levels and
    // degrees, with square roots of primes as coefficients.
    const double s2 = std::sqrt(2.0), s3 = std::sqrt(3.0), s5 = std::sqrt(5.0), s7 = std::sqrt(7.0),
                 s11 = std::sqrt(11.0), s13 = std::sqrt(13.0);
    double md = 0;
    for (const Block &u : blocks)
      for (std::size_t vi : u.succ) {
        const Block &v = blocks[vi];
        md += 1.0 / std::sqrt(s2 * u.level + s3 * u.in + s5 * u.succ.size() + s7 * v.level + s11 * v.in +
                              s13 * v.succ.size());
      }
    f.md_index = md;
  }
  f.shape = Hasher()
                .u64(f.blocks)
                .u64(f.edges)
                .u64(f.loops)
                .u64(static_cast<std::uint64_t>(std::llround(f.md_index * 1e9)))
                .done();

  f.bag.assign(bag.begin(), bag.end());
  if (!f.bag.empty()) {
    Hasher h;
    for (std::uint32_t x : f.bag) h.u64(x);
    f.refs = h.done();
  }
  return f;
}

}  // namespace revkit::diff
