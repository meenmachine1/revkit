// diff.code: one function's instructions and blocks as the correlation
// compares them (correlate.h).

#include "internal.h"
#include "revkit/diff/correlate.h"
#include "revkit/diff/features.h"
#include "revkit/facts/fact_db.h"

#include <algorithm>
#include <map>
#include <set>
#include <unordered_map>

namespace revkit::diff {

using namespace detail;

void CodeRef::encode(facts::Encoder &e) const {
  facts::encode(e, kind);
  e.varint(to);
  e.varint(string);
}
CodeRef CodeRef::decode(facts::Decoder &d) {
  CodeRef r;
  r.kind = facts::decode<Kind>(d);
  r.to = d.varint();
  r.string = static_cast<std::uint32_t>(d.varint());
  return r;
}

void CodeInsn::encode(facts::Encoder &e) const {
  e.varint(address);
  e.varint(length);
  e.varint(block);
  e.u64be(kind);
  e.u64be(exact);
  e.u64be(raw);
  e.bytes(mnemonic);
  facts::encode(e, refs);
  facts::encode(e, local);
}
CodeInsn CodeInsn::decode(facts::Decoder &d) {
  CodeInsn i;
  i.address = d.varint();
  i.length = static_cast<std::uint32_t>(d.varint());
  i.block = static_cast<std::uint32_t>(d.varint());
  i.kind = d.u64be();
  i.exact = d.u64be();
  i.raw = d.u64be();
  i.mnemonic = std::string(d.bytes());
  i.refs = facts::decode<std::vector<CodeRef>>(d);
  i.local = facts::decode<std::vector<std::uint32_t>>(d);
  return i;
}

void CodeEdge::encode(facts::Encoder &e) const {
  e.varint(to);
  facts::encode(e, kind);
}
CodeEdge CodeEdge::decode(facts::Decoder &d) {
  CodeEdge x;
  x.to = static_cast<std::uint32_t>(d.varint());
  x.kind = facts::decode<EdgeKind>(d);
  return x;
}

void CodeBlock::encode(facts::Encoder &e) const {
  e.varint(first);
  e.varint(last);
  facts::encode(e, succ);
}
CodeBlock CodeBlock::decode(facts::Decoder &d) {
  CodeBlock b;
  b.first = static_cast<std::uint32_t>(d.varint());
  b.last = static_cast<std::uint32_t>(d.varint());
  b.succ = facts::decode<std::vector<CodeEdge>>(d);
  return b;
}

void FunctionCode::encode(facts::Encoder &e) const {
  e.varint(entry);
  e.varint(entry_block);
  facts::encode(e, insns);
  facts::encode(e, blocks);
}
FunctionCode FunctionCode::decode(facts::Decoder &d) {
  FunctionCode f;
  f.entry = d.varint();
  f.entry_block = static_cast<std::uint32_t>(d.varint());
  f.insns = facts::decode<std::vector<CodeInsn>>(d);
  f.blocks = facts::decode<std::vector<CodeBlock>>(d);
  return f;
}

FunctionCode Code::compute(facts::QueryContext &ctx, const Key &key) {
  FunctionCode out;
  auto info = ctx.get<analysis::Program>(key.program);
  auto fn = ctx.get<analysis::Function>(key);
  if (fn->name.empty() && fn->body.empty()) {
    ctx.set_confidence(facts::Confidence::Uncertain);
    return out;
  }
  out.entry = key.address;
  const facts::SpaceId space = info->space;
  auto flow = ctx.get<analysis::Flow>(analysis::Location{key.program, fn->flow_key()});
  const bool tagged = (fn->flags & analysis::kFunctionTagged) != 0;
  std::vector<const analysis::FlowInsn *> insns;
  std::vector<std::size_t> flow_index;
  for (std::size_t i = 0; i < flow->insns.size(); ++i) {
    const analysis::FlowInsn &in = flow->insns[i];
    if (!fn->body.contains({space, in.address})) continue;
    insns.push_back(&in);
    flow_index.push_back(i);
  }
  std::unordered_map<std::uint64_t, std::size_t> at;
  for (std::size_t i = 0; i < insns.size(); ++i) at.emplace(insns[i]->address, i);
  auto in_body = [&](std::uint64_t a) { return at.contains(a); };

  std::map<std::uint32_t, std::vector<const analysis::FlowRef *>> refs_of;
  for (const analysis::FlowRef &r : flow->refs) refs_of[r.insn].push_back(&r);
  std::map<std::uint64_t, std::vector<std::uint64_t>> data_of;
  for (const analysis::DataRef &r : flow->data_refs) data_of[r.from].push_back(r.to);

  // What a target outside the function is: a function (an import stub by
  // its import's name), or not.
  struct Target {
    bool function = false;
    std::string import;
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
    }
    return targets.emplace(a, std::move(t)).first->second;
  };
  analysis::CodeReader code(ctx, *info);
  std::map<std::uint64_t, std::uint32_t> string_at;
  auto string_hash = [&](std::uint64_t a) -> std::uint32_t {
    auto it = string_at.find(a);
    if (it != string_at.end()) return it->second;
    std::uint32_t h = 0;
    if (!info->is_code(a) && info->is_mapped(a))
      if (auto s = AsciiString(code.bytes(a, 64))) h = Hash32(Hasher().str("s").str(*s).done()) | 1;
    return string_at.emplace(a, h).first->second;
  };

  const std::string &cs = info->code_space;
  out.insns.reserve(insns.size());
  for (std::size_t i = 0; i < insns.size(); ++i) {
    const analysis::FlowInsn &in = *insns[i];
    CodeInsn ci;
    ci.address = in.address;
    ci.length = in.length;
    std::vector<std::uint64_t> external;
    std::vector<std::string> tags;
    std::vector<std::uint64_t> local;  // targets within the body: masked like external ones
    for (std::uint64_t t : in.targets) {
      if (in_body(t)) {
        if (in.kind != analysis::FlowKind::call && in.kind != analysis::FlowKind::call_indirect) {
          local.push_back(t);
          ci.local.push_back(static_cast<std::uint32_t>(at.at(t)));
        }
        continue;
      }
      external.push_back(t);
      const Target &g = target(t);
      const bool call = in.kind == analysis::FlowKind::call || in.kind == analysis::FlowKind::call_indirect;
      if (!g.function) {
        tags.emplace_back("c");
        ci.refs.push_back({call ? CodeRef::Kind::call : CodeRef::Kind::jump, t, 0});
        continue;
      }
      ci.refs.push_back({call ? CodeRef::Kind::call : CodeRef::Kind::jump, t, 0});
      if (!g.import.empty()) tags.push_back("i:" + g.import);
      else tags.emplace_back("f");
    }
    auto data_value = [&](std::uint64_t to) {
      if (in_body(to)) return;
      if (std::find(external.begin(), external.end(), to) != external.end()) return;
      external.push_back(to);
      ci.refs.push_back({CodeRef::Kind::data, to, info->is_code(to) ? 0u : string_hash(to)});
    };
    if (auto r = refs_of.find(static_cast<std::uint32_t>(flow_index[i])); r != refs_of.end())
      for (const analysis::FlowRef *ref : r->second)
        if (ref->kind != analysis::RefKind::call && ref->kind != analysis::RefKind::jump &&
            ref->kind != analysis::RefKind::conditional_jump)
          data_value(ref->to);
    if (auto d = data_of.find(in.address); d != data_of.end())
      for (std::uint64_t to : d->second) data_value(to);
    std::sort(tags.begin(), tags.end());

    Hasher kind_h, value_h;  // operand kinds only; and with the constants
    std::uint32_t own_length = in.length - in.delay;
    auto insn = code.decode(in.address, tagged);
    if (insn) {
      own_length = insn->length;
      ci.mnemonic = insn->mnemonic;
      for (const lift::PcodeOp &op : insn->pcode) {
        const std::uint32_t oi = OpcodeIndex(op.opcode);
        kind_h.u64(oi);
        value_h.u64(oi);
        auto operand = [&](const lift::Varnode &v, bool keep_value) {
          const Kind k = KindOf(v, cs);
          kind_h.u64(static_cast<std::uint64_t>(k) << 32 | v.size);
          value_h.u64(static_cast<std::uint64_t>(k) << 32 | v.size);
          if (k != Kind::constant || !keep_value) return;
          const bool address = (info->is_mapped(v.offset) && v.offset >= 0x1000) ||
                                std::find(external.begin(), external.end(), v.offset) != external.end() ||
                                std::find(local.begin(), local.end(), v.offset) != local.end();
          value_h.u64(address ? 0xadd5 : v.offset);
        };
        if (op.output) operand(*op.output, false);
        const bool is_space_op = op.opcode == "LOAD"sv || op.opcode == "STORE"sv;
        for (std::size_t j = 0; j < op.inputs.size(); ++j) operand(op.inputs[j], !(is_space_op && j == 0));
      }
      if (insn->unimplemented) {
        kind_h.u64(0xbad);
        value_h.u64(0xbad);
      }
    } else {
      kind_h.u64(0xdead);
      value_h.u64(0xdead);
    }
    for (const std::string &t : tags) {
      kind_h.str(t);
      value_h.str(t);
    }
    ci.kind = kind_h.u64(in.length).done();

    auto raw = code.bytes(in.address, in.length);
    Hasher raw_h;
    for (std::byte x : raw) raw_h.u64(std::to_integer<std::uint64_t>(x));
    ci.raw = raw_h.u64(in.length).done();
    std::vector<std::byte> b(raw.begin(), raw.end());
    std::vector<bool> masked(b.size(), false);
    // A target the bytes don't hold in a byte-aligned field (ARM's bl)
    // makes the p-code stand for the instruction. A data address they
    // don't hold was computed (a register's value), not encoded here: what
    // analysis knows of registers must not change how the code compares.
    bool whole = false;
    const std::size_t flows = external.size() - static_cast<std::size_t>(std::count_if(
        ci.refs.begin(), ci.refs.end(), [](const CodeRef &r) { return r.kind == CodeRef::Kind::data; }));
    for (std::size_t k = 0; k < external.size(); ++k)
      if (!MaskField(b, masked, external[k], in.address, own_length, info->big_endian, info->pointer_size) && k < flows)
        whole = true;
    for (std::uint64_t t : local)
      if (!MaskField(b, masked, t, in.address, own_length, info->big_endian, info->pointer_size)) whole = true;
    Hasher exact_h;
    exact_h.u64(in.length);
    if (whole || b.empty()) {
      exact_h.u64(0x3a5c).u64(value_h.done());
    } else {
      for (std::size_t k = 0; k < b.size(); ++k) exact_h.u64(masked[k] ? 0x100 : std::to_integer<std::uint64_t>(b[k]));
      for (const std::string &t : tags) exact_h.str(t);
    }
    ci.exact = exact_h.done();
    out.insns.push_back(std::move(ci));
  }

  // Blocks, as GetFunctionGraph cuts them.
  auto ends_block = [](const analysis::FlowInsn &in) {
    using K = analysis::FlowKind;
    return in.kind == K::jump || in.kind == K::branch || in.kind == K::jump_indirect || in.kind == K::ret ||
           !in.falls_through || in.tail_call;
  };
  std::vector<bool> leader(insns.size(), false);
  if (!insns.empty()) leader[0] = true;
  for (std::size_t i = 0; i < insns.size(); ++i) {
    const analysis::FlowInsn &in = *insns[i];
    if (in.kind == analysis::FlowKind::jump || in.kind == analysis::FlowKind::branch ||
        in.kind == analysis::FlowKind::jump_indirect)
      for (std::uint64_t t : in.targets)
        if (auto it = at.find(t); it != at.end()) leader[it->second] = true;
    if (i + 1 < insns.size() && (ends_block(in) || insns[i + 1]->address != in.address + in.length)) leader[i + 1] = true;
  }
  if (auto it = at.find(key.address); it != at.end()) leader[it->second] = true;
  std::vector<std::uint32_t> block_of(insns.size());
  for (std::size_t i = 0; i < insns.size(); ++i) {
    if (leader[i]) out.blocks.push_back({static_cast<std::uint32_t>(i), static_cast<std::uint32_t>(i), {}});
    out.blocks.back().last = static_cast<std::uint32_t>(i);
    block_of[i] = static_cast<std::uint32_t>(out.blocks.size() - 1);
    out.insns[i].block = block_of[i];
  }
  for (CodeBlock &bl : out.blocks) {
    const analysis::FlowInsn &last = *insns[bl.last];
    std::set<std::pair<std::uint32_t, EdgeKind>> succ;
    using K = analysis::FlowKind;
    if (last.kind == K::jump || last.kind == K::branch || last.kind == K::jump_indirect) {
      const EdgeKind k = last.kind == K::jump_indirect ? EdgeKind::switch_case : last.kind == K::branch ? EdgeKind::taken : EdgeKind::jump;
      for (std::uint64_t t : last.targets)
        if (auto it = at.find(t); it != at.end()) succ.insert({block_of[it->second], k});
    }
    if (last.falls_through && !last.tail_call && last.kind != K::ret)
      if (auto it = at.find(last.address + last.length); it != at.end()) succ.insert({block_of[it->second], EdgeKind::fall});
    for (const auto &[to, k] : succ) bl.succ.push_back({to, k});
  }
  if (auto it = at.find(key.address); it != at.end()) out.entry_block = block_of[it->second];
  return out;
}

}  // namespace revkit::diff
