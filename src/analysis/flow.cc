// analysis.thunk and analysis.flow: decoding from one address.

#include "data_internal.h"
#include "internal.h"

#include <algorithm>
#include <map>
#include <tuple>

namespace revkit::analysis {

using detail::ByteReader;
using detail::Decoder;
using detail::Evaluator;
using detail::InsnFlow;
using detail::Sym;

// ---- codecs ----

void ThunkInfo::encode(facts::Encoder &e) const {
  facts::encode(e, kind);
  e.varint(target);
  e.bytes(import);
  body.encode(e);
}

ThunkInfo ThunkInfo::decode(facts::Decoder &d) {
  ThunkInfo t;
  t.kind = facts::decode<ThunkKind>(d);
  if (t.kind > ThunkKind::direct) throw facts::DecodeError("bad thunk kind");
  t.target = d.varint();
  t.import = std::string(d.bytes());
  t.body = Range::decode(d);
  return t;
}

// One byte holds the kind (low four bits) and the flags.
constexpr std::uint8_t kFalls = 0x80, kNoReturn = 0x40, kTailCall = 0x20, kDelay = 0x10, kResolved = 0x08;

void FlowInsn::encode(facts::Encoder &e) const {
  e.varint(address);
  e.varint(length);
  e.u8(static_cast<std::uint8_t>(static_cast<unsigned>(kind) | (falls_through ? kFalls : 0) |
                                 (no_return ? kNoReturn : 0) | (tail_call ? kTailCall : 0) | (delay ? kDelay : 0) |
                                 (resolved ? kResolved : 0)));
  if (delay) e.varint(delay);
  facts::encode(e, conditional);
  e.varint(targets.size());
  for (std::uint64_t t : targets) e.svarint(static_cast<std::int64_t>(t - address));
}

FlowInsn FlowInsn::decode(facts::Decoder &d) {
  FlowInsn f;
  f.address = d.varint();
  f.length = facts::decode<std::uint32_t>(d);
  std::uint8_t k = d.u8();
  f.falls_through = (k & kFalls) != 0;
  f.no_return = (k & kNoReturn) != 0;
  f.tail_call = (k & kTailCall) != 0;
  f.resolved = (k & kResolved) != 0;
  if ((k & 0x07) > static_cast<unsigned>(FlowKind::ret)) throw facts::DecodeError("bad flow kind");
  f.kind = static_cast<FlowKind>(k & 0x07);
  if (k & kDelay) f.delay = facts::decode<std::uint32_t>(d);
  f.conditional = facts::decode<bool>(d);
  std::size_t n = d.count();
  for (std::size_t i = 0; i < n; ++i) f.targets.push_back(f.address + static_cast<std::uint64_t>(d.svarint()));
  return f;
}

std::uint64_t FlowRef::from(const FlowGraph &g) const {
  const FlowInsn &i = g.insns[insn];
  return delay_slot ? i.address + (i.length - i.delay) : i.address;
}

void FlowGraph::encode(facts::Encoder &e) const {
  e.varint(entry);
  facts::encode(e, truncated);
  facts::encode(e, insns);
  e.varint(refs.size());
  std::uint32_t at = 0;
  for (const FlowRef &r : refs) {
    e.varint(r.insn - at);
    at = r.insn;
    e.u8(static_cast<std::uint8_t>(static_cast<unsigned>(r.kind) | (r.delay_slot ? 0x10 : 0)));
    e.svarint(static_cast<std::int64_t>(r.to - insns[r.insn].address));
  }
  facts::encode(e, code_pointers);
  facts::encode(e, literals);
  e.varint(data_refs.size());
  std::uint64_t from = 0;
  for (const DataRef &r : data_refs) {
    e.varint(r.from - from);
    from = r.from;
    e.varint(r.to);
    e.varint(r.size);
    e.u8(static_cast<std::uint8_t>(r.access));
  }
  facts::encode(e, case_calls);
  facts::encode(e, far_jumps);
  facts::encode(e, ref_calls);
}

FlowGraph FlowGraph::decode(facts::Decoder &d) {
  FlowGraph g;
  g.entry = d.varint();
  g.truncated = facts::decode<bool>(d);
  g.insns = facts::decode<std::vector<FlowInsn>>(d);
  const std::size_t n = d.count();
  g.refs.reserve(n);
  std::uint64_t at = 0;
  for (std::size_t i = 0; i < n; ++i) {
    FlowRef r;
    at += d.varint();
    if (at >= g.insns.size()) throw facts::DecodeError("bad reference");
    r.insn = static_cast<std::uint32_t>(at);
    const std::uint8_t k = d.u8();
    if ((k & 0x0f) > static_cast<unsigned>(RefKind::data_write) || (k & 0xe0) != 0) throw facts::DecodeError("bad reference kind");
    r.kind = static_cast<RefKind>(k & 0x0f);
    r.delay_slot = (k & 0x10) != 0;
    r.to = g.insns[r.insn].address + static_cast<std::uint64_t>(d.svarint());
    g.refs.push_back(r);
  }
  g.code_pointers = facts::decode<std::vector<std::uint64_t>>(d);
  g.literals = facts::decode<std::vector<Range>>(d);
  const std::size_t m = d.count();
  g.data_refs.reserve(m);
  std::uint64_t from = 0;
  for (std::size_t i = 0; i < m; ++i) {
    DataRef r;
    r.from = from + d.varint();
    from = r.from;
    r.to = d.varint();
    r.size = static_cast<std::uint32_t>(d.varint());
    const std::uint8_t a = d.u8();
    if (a > static_cast<std::uint8_t>(DataAccess::address)) throw facts::DecodeError("bad data access");
    r.access = static_cast<DataAccess>(a);
    g.data_refs.push_back(r);
  }
  g.case_calls = facts::decode<std::vector<std::pair<std::uint64_t, std::uint64_t>>>(d);
  g.far_jumps = facts::decode<std::vector<std::uint64_t>>(d);
  g.ref_calls = facts::decode<std::vector<std::pair<std::uint64_t, std::uint64_t>>>(d);
  return g;
}

const FlowInsn *FlowGraph::at(std::uint64_t address) const {
  auto it = std::lower_bound(insns.begin(), insns.end(), address,
                             [](const FlowInsn &i, std::uint64_t a) { return i.address < a; });
  return it != insns.end() && it->address == address ? &*it : nullptr;
}

// ---- assertions ----

namespace detail {

facts::FactValue Assertions::value(facts::FactKind kind, std::uint64_t a) {
  auto &span = spans_[{kind, a >> facts::kSpanShift}];
  if (!span) span = ctx_.get<facts::AssertedSpan>(facts::BucketKey{kind, space_, a >> facts::kSpanShift});
  if (!std::binary_search(span->begin(), span->end(), std::pair{a, std::string()})) return {};
  return *ctx_.get<facts::AssertedFact>(facts::FactKey{kind, facts::Address{space_, a}, {}});
}

FlowOverride Assertions::flow_override(std::uint64_t a) {
  facts::FactValue v = value(facts::FactKind::FlowOverride, a);
  const auto *k = std::get_if<std::int64_t>(&v);
  if (!k || *k < static_cast<std::int64_t>(FlowOverride::none) || *k > static_cast<std::int64_t>(FlowOverride::ret))
    return FlowOverride::none;
  return static_cast<FlowOverride>(*k);
}

std::vector<UserRef> Assertions::references(std::uint64_t a) {
  auto &span = spans_[{facts::FactKind::Reference, a >> facts::kSpanShift}];
  if (!span)
    span = ctx_.get<facts::AssertedSpan>(facts::BucketKey{facts::FactKind::Reference, space_, a >> facts::kSpanShift});
  std::vector<UserRef> out;
  for (auto it = std::lower_bound(span->begin(), span->end(), std::pair{a, std::string()});
       it != span->end() && it->first == a; ++it) {
    auto v = ctx_.get<facts::AssertedFact>(facts::FactKey{facts::FactKind::Reference, facts::Address{space_, a}, it->second});
    if (const auto *text = std::get_if<std::string>(&*v))
      if (auto r = parse_user_ref(it->second, *text)) out.push_back(*r);
  }
  return out;
}

void apply_override(FlowInsn &f, FlowOverride o) {
  if (f.kind == FlowKind::fall || o == FlowOverride::none) return;  // overrides change flow instructions only
  const bool conditional = f.kind == FlowKind::branch;
  switch (o) {
    case FlowOverride::branch:
      if (f.kind == FlowKind::call) {
        f.kind = FlowKind::jump;
        f.falls_through = false;
      } else if (f.kind == FlowKind::call_indirect || f.kind == FlowKind::ret) {
        f.kind = FlowKind::jump_indirect;
        f.targets.clear();
        f.falls_through = false;
      }
      break;
    case FlowOverride::call:
      if (f.kind == FlowKind::jump || f.kind == FlowKind::branch) {
        f.kind = FlowKind::call;
        f.falls_through = true;
      } else if (f.kind == FlowKind::jump_indirect || f.kind == FlowKind::ret) {
        f.kind = FlowKind::call_indirect;
        f.targets.clear();
        f.falls_through = true;
      }
      break;
    case FlowOverride::call_return:
      if (conditional) break;  // Ghidra leaves a conditional jump alone
      if (f.kind == FlowKind::jump || f.kind == FlowKind::call) {
        f.kind = FlowKind::call;
      } else {
        f.kind = FlowKind::call_indirect;
        f.targets.clear();
      }
      f.falls_through = false;
      f.tail_call = true;
      break;
    case FlowOverride::ret:
      f.kind = FlowKind::ret;
      f.targets.clear();
      f.falls_through = conditional;
      break;
    case FlowOverride::none: break;
  }
}

// ---- thunks ----

// Whether a call to `target` never returns, judged by name alone: a symbol
// or an import (through jump stubs) on the known list.
bool named_no_return(facts::QueryContext &ctx, const ProgramKey &program, const ProgramInfo &info,
                     std::uint64_t target) {
  for (int depth = 0; depth < 4; ++depth) {
    // The user's word first (FactKind::NoReturn on the function's entry).
    auto said = ctx.get<facts::AssertedFact>(facts::FactKey{facts::FactKind::NoReturn, {info.space, target}, {}});
    if (const auto *i = std::get_if<std::int64_t>(&*said)) return *i != 0;
    if (const Seed *s = info.seed_at(info.code_address(target)); s && s->named_by_symbol)
      return is_known_no_return(s->name);
    auto t = ctx.get<JumpStub>(Location{program, target});
    if (t->kind == ThunkKind::import) return is_known_no_return(t->import);
    if (t->kind != ThunkKind::direct) return false;
    target = t->target;
  }
  return false;
}

ThunkInfo JumpStub::compute(facts::QueryContext &ctx, const Location &addr) {
  auto info = ctx.get<Program>(addr.program);
  ThunkInfo none;
  const std::uint64_t start = info->code_address(addr.address);
  const bool tagged = start != addr.address;
  const bool thumb = info->thumb(addr.address);
  if (!info->is_code(start)) return none;
  ByteReader bytes(ctx, *info);
  Decoder decoder(*info);
  Evaluator eval(*info, nullptr);
  // The same with literal pools read: a jump through a pointer in code
  // (ARM's ldr pc, [pc, #n]; a Thumb bx pc into ARM code).
  Evaluator literal(*info, &bytes);
  literal.restrict_loads_to_code();
  const std::string &ram = info->code_space;

  // Ghidra allows a leading instruction without p-code (ENDBR64) and a
  // short run of register computations before the jump, as long as they
  // only compute the jump: every register they write is read again, and
  // they read none they didn't write. (The jump itself may write a link
  // register, as RISC-V PLT stubs' jalr t1 does; Ghidra doesn't allow
  // that, so it leaves RISC-V PLT stubs unnamed.)
  constexpr int kMaxInstructions = 5;
  std::vector<std::pair<std::uint64_t, std::uint32_t>> written;
  std::uint64_t a = start;
  for (int n = 0; n < kMaxInstructions; ++n) {
    if (!info->is_code(a)) return none;
    auto insn = decoder.decode(a, bytes, tagged);
    if (!insn || insn->unimplemented) return none;
    const std::uint64_t end = a + insn->length + insn->delay_slot;
    if (insn->pcode.empty()) {
      if (n != 0) return none;
      a = end;
      continue;
    }
    InsnFlow f = classify(*insn, ram);
    const Range body{start, end - 1};
    if (f.kind == FlowKind::jump && f.targets.size() == 1) {
      if (!info->is_code(f.targets[0]) || !written.empty()) return none;
      return {ThunkKind::direct, info->code_key(f.targets[0], thumb), {}, body};
    }
    if (f.kind == FlowKind::jump_indirect) {
      literal.step(*insn);
      if (!eval.step(*insn) || !eval.free_registers().empty()) {
        // Not a stub Ghidra's rules allow, but a jump the literal pool
        // fixes is still one (it may write the mode register).
        const auto &t = literal.indirect_target();
        if (n == 0 && t && t->known() && info->is_code(t->value) && eval.free_registers().empty()) {
          bool to_thumb = thumb;
          if (info->isa_register)
            if (auto v = literal.register_value(info->isa_register->first, info->isa_register->second)) to_thumb = *v != 0;
          return {ThunkKind::direct, info->code_key(t->value, to_thumb), {}, body};
        }
        return none;
      }
      // Registers the earlier instructions wrote must feed the jump.
      for (const auto &w : written) {
        bool used = false;
        for (const auto &r : eval.reads())
          if (r.first == w.first) used = true;
        if (!used) return none;
      }
      const auto &t = eval.indirect_target();
      if (!t) return none;
      if (t->kind == Sym::Kind::loaded) {
        if (const ImportSlot *slot = info->import_at(t->value)) return {ThunkKind::import, t->value, slot->name, body};
        // A pointer in code (a literal pool) to code.
        const auto &l = literal.indirect_target();
        if (!l || !l->known() || !info->is_code(l->value)) return none;
        bool to_thumb = thumb;
        if (info->isa_register)
          if (auto v = literal.register_value(info->isa_register->first, info->isa_register->second)) to_thumb = *v != 0;
        return {ThunkKind::direct, info->code_key(l->value, to_thumb), {}, body};
      }
      if (t->known() && info->is_code(t->value)) {
        bool to_thumb = thumb;
        if (info->isa_register)
          if (auto v = eval.register_value(info->isa_register->first, info->isa_register->second)) to_thumb = *v != 0;
        return {ThunkKind::direct, info->code_key(t->value, to_thumb), {}, body};
      }
      return none;
    }
    if (f.kind != FlowKind::fall || !f.falls_through) return none;
    literal.step(*insn);
    if (!eval.step(*insn) || !eval.free_registers().empty()) return none;
    // One-byte registers are flags, which Ghidra lets a thunk set unused.
    for (const lift::PcodeOp &op : insn->pcode)
      if (op.output && op.output->space == "register" && op.output->size > 1)
        written.emplace_back(op.output->offset, op.output->size);
    a = end;
  }
  return none;
}

std::uint32_t CaseHelper::compute(facts::QueryContext &ctx, const Location &addr) {
  auto info = ctx.get<Program>(addr.program);
  if (!info->link_register) return 0;
  const std::uint64_t start = info->code_address(addr.address);
  const bool tagged = start != addr.address;
  if (!info->is_code(start)) return 0;
  ByteReader bytes(ctx, *info);
  Decoder decoder(*info);
  Evaluator eval(*info, nullptr);
  eval.keep_slots();  // a store through a pointer doesn't touch the saved link register
  constexpr std::uint32_t kMaxInstructions = 16;
  std::uint64_t a = start;
  for (std::uint32_t n = 0; n < kMaxInstructions; ++n) {
    if (!info->is_code(a)) return 0;
    auto insn = decoder.decode(a, bytes, tagged);
    if (!insn || insn->unimplemented || insn->pcode.empty()) return 0;
    const InsnFlow f = classify(*insn, info->code_space);
    // (Thumb's bx lr lifts to a RETURN.)
    if (f.kind == FlowKind::jump_indirect || f.kind == FlowKind::ret) {
      if (f.falls_through) return 0;  // a conditional one
      eval.step(*insn);
      // Somewhere computed (what a table held, added to the return
      // address): not a constant, a slot's contents or a register as it
      // came in (a return, a call through a parameter).
      const auto &t = eval.indirect_target();
      if (!t || t->kind != Sym::Kind::unknown) return 0;
      for (const auto &r : eval.free_registers())
        if (r.first == info->link_register->first) return n + 1;
      return 0;
    }
    if (f.kind != FlowKind::fall || !f.falls_through) return 0;
    eval.step(*insn);
    a += insn->length + insn->delay_slot;
  }
  return 0;
}

std::optional<std::int64_t> pops_callers_frame(facts::QueryContext &ctx, const ProgramKey &program,
                                               const ProgramInfo &info, std::uint64_t key, ByteReader &bytes,
                                               Decoder &decoder, const std::function<bool(std::uint64_t)> &stops,
                                               int depth) {
  if (!info.link_register) return std::nullopt;
  const std::optional<RegisterSlot> sp = stack_register(info);
  if (!sp) return std::nullopt;
  const std::uint64_t start = info.code_address(key);
  const bool tagged = start != key;
  Evaluator eval(info, nullptr);
  eval.keep_slots();
  std::vector<std::uint64_t> seen;
  // A far jump's own target is a short tail (an epilogue, a default case):
  // nested ones are followed only that far.
  const std::size_t path = depth == 0 ? 512 : 24;
  std::uint64_t at = start;
  for (std::size_t n = 0; n < path; ++n) {
    if (!info.is_code(at) || std::find(seen.begin(), seen.end(), at) != seen.end()) return std::nullopt;
    seen.push_back(at);
    auto insn = decoder.decode(at, bytes, tagged);
    if (!insn || insn->unimplemented || zero_instruction(*insn, bytes) || starts_fill(at, insn->length, bytes))
      return std::nullopt;
    const std::size_t before = eval.free_memory().size();
    eval.step(*insn);
    const InsnFlow f = classify(*insn, info.code_space);
    const std::uint64_t next = at + insn->length + insn->delay_slot;
    switch (f.kind) {
      case FlowKind::ret:
      case FlowKind::jump_indirect: {
        if (f.falls_through) break;  // a conditional one: on past it
        std::optional<std::int64_t> above;
        if (const auto &t = eval.indirect_target(); t && t->kind == Sym::Kind::unknown)
          for (std::size_t k = before; k < eval.free_memory().size(); ++k) {
            const Evaluator::FreeMemory &m = eval.free_memory()[k];
            const auto disp = static_cast<std::int64_t>(m.disp);
            if (m.reg == sp->first && disp >= 0 && m.size == info.pointer_size && (!above || disp > *above)) above = disp;
          }
        return above;
      }
      case FlowKind::jump:
        if (f.targets.size() != 1) return std::nullopt;
        at = f.targets[0];
        continue;
      case FlowKind::call:
        if (f.targets.size() == 1) {
          bool to_thumb = info.thumb(key);
          if (info.isa_register)
            if (auto v = eval.register_value(info.isa_register->first, info.isa_register->second)) to_thumb = *v != 0;
          const std::uint64_t callee = info.code_key(f.targets[0], to_thumb);
          if (stops && stops(callee)) return std::nullopt;
          // A switch helper doesn't come back here (a table follows).
          if (*ctx.get<CaseHelper>(Location{program, callee}) != 0) return std::nullopt;
          // A far jump to code that returns from the frame it came in
          // with: this code returns from that frame too.
          if (depth < 3)
            if (auto there = pops_callers_frame(ctx, program, info, callee, bytes, decoder, stops, depth + 1))
              if (auto now = eval.moved(sp->first); now && *there + *now >= 0) return *there + *now;
        }
        break;
      default: break;
    }
    if (!f.falls_through) return std::nullopt;
    at = next;
  }
  return std::nullopt;
}

std::int64_t FrameFragment::compute(facts::QueryContext &ctx, const Location &addr) {
  auto info = ctx.get<Program>(addr.program);
  ByteReader bytes(ctx, *info);
  Decoder decoder(*info);
  return pops_callers_frame(ctx, addr.program, *info, addr.address, bytes, decoder).value_or(-1);
}

std::optional<std::int64_t> prologue_frame(const ProgramInfo &info, std::uint64_t key, ByteReader &bytes,
                                           Decoder &decoder) {
  if (!info.link_register) return std::nullopt;
  const std::optional<RegisterSlot> sp = stack_register(info);
  if (!sp) return std::nullopt;
  const std::uint64_t start = info.code_address(key);
  Evaluator eval(info, nullptr);
  eval.keep_slots();
  constexpr int kPrologue = 8;
  std::uint64_t at = start;
  std::optional<std::int64_t> frame;
  for (int n = 0; n < kPrologue; ++n) {
    if (!info.is_code(at)) break;
    auto insn = decoder.decode(at, bytes, start != key);
    if (!insn || insn->unimplemented || insn->pcode.empty()) break;
    const InsnFlow f = classify(*insn, info.code_space);
    if (f.kind != FlowKind::fall || !f.falls_through) break;
    eval.step(*insn);
    if (auto above = eval.saved_above(info.link_register->first, sp->first)) frame = above;
    at += insn->length + insn->delay_slot;
  }
  return frame;
}

}  // namespace detail

ThunkInfo Thunk::compute(facts::QueryContext &ctx, const Location &addr) {
  auto stub = ctx.get<detail::JumpStub>(addr);
  if (stub->kind != ThunkKind::none) return *stub;
  // A function whose first real instruction calls a function that never
  // returns is a thunk of it too: Ghidra treats a function that only calls
  // abort() as abort's thunk. The callee is judged by name, through jump
  // stubs only, so thunks never depend on each other in a cycle.
  auto info = ctx.get<Program>(addr.program);
  const std::uint64_t start = info->code_address(addr.address);
  if (!info->is_code(start)) return {};
  ByteReader bytes(ctx, *info);
  Decoder decoder(*info);
  std::uint64_t a = start;
  for (int n = 0; n < 2; ++n) {
    auto insn = decoder.decode(a, bytes, start != addr.address);
    if (!insn || insn->unimplemented) return {};
    const std::uint64_t end = a + insn->length + insn->delay_slot;
    if (insn->pcode.empty() && n == 0) {
      a = end;
      continue;
    }
    InsnFlow f = detail::classify(*insn, info->code_space);
    if (f.kind == FlowKind::call && f.targets.size() == 1 && f.targets[0] != start && info->is_code(f.targets[0])) {
      bool to_thumb = info->thumb(addr.address);
      if (info->isa_register) {
        Evaluator eval(*info, nullptr);
        eval.step(*insn);
        if (auto v = eval.register_value(info->isa_register->first, info->isa_register->second)) to_thumb = *v != 0;
      }
      const std::uint64_t callee = info->code_key(f.targets[0], to_thumb);
      if (detail::named_no_return(ctx, addr.program, *info, callee))
        return {ThunkKind::direct, callee, {}, Range{start, end - 1}};
    }
    return {};
  }
  return {};
}

// ---- references ----

namespace detail {

void references(const lift::Instruction &insn, const ProgramInfo &info, std::uint32_t index, bool delay_slot,
                std::vector<FlowRef> &out) {
  const std::string &code = info.code_space;
  const std::size_t first = out.size();
  auto add = [&](std::uint64_t to, RefKind kind) { out.push_back({index, kind, delay_slot, to}); };
  // Small: an instruction has a handful of ops.
  std::vector<std::uint64_t> flow_targets;
  // Constants copied into temporaries, so a LOAD through one counts as a read.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> unique_const;
  for (const lift::PcodeOp &op : insn.pcode) {
    const std::string &opc = op.opcode;
    const bool branch = opc == "CBRANCH";
    if ((opc == "BRANCH" || branch || opc == "CALL") && !op.inputs.empty()) {
      const lift::Varnode &t = op.inputs[0];
      if (t.space == code && info.is_mapped(t.offset)) {
        flow_targets.push_back(t.offset);
        add(t.offset, opc == "CALL" ? RefKind::call : opc == "BRANCH" ? RefKind::jump : RefKind::conditional_jump);
      }
      if (!branch) continue;
    }
    if (opc == "COPY" && op.output && op.output->space == "unique" && !op.inputs.empty() &&
        op.inputs[0].space == "const") {
      auto it = std::find_if(unique_const.begin(), unique_const.end(),
                             [&](const auto &u) { return u.first == op.output->offset; });
      if (it != unique_const.end()) it->second = op.inputs[0].offset;
      else unique_const.emplace_back(op.output->offset, op.inputs[0].offset);
      continue;
    }
    const bool load = opc == "LOAD", store = opc == "STORE";
    // Direct memory varnodes: SLEIGH folds an absolute or pc-relative
    // operand into one (x86-64's `add [rip+x],ecx` reads and writes
    // ram:x), with no LOAD or STORE: a read, and as the output a write.
    if (op.output && op.output->space == code && op.output->size != 0 && info.is_mapped(op.output->offset))
      add(op.output->offset, RefKind::data_write);
    for (std::size_t i = branch ? 1 : 0; i < op.inputs.size(); ++i) {
      const lift::Varnode &in = op.inputs[i];
      if (in.space == code && in.size != 0 && info.is_mapped(in.offset)) {
        add(in.offset, RefKind::data_read);
        continue;
      }
    }
    for (std::size_t i = 0; i < op.inputs.size(); ++i) {
      const lift::Varnode &in = op.inputs[i];
      std::uint64_t v;
      if (in.space == "const") {
        v = in.offset;
      } else if (in.space == "unique") {
        auto it = std::find_if(unique_const.begin(), unique_const.end(), [&](const auto &u) { return u.first == in.offset; });
        if (it == unique_const.end()) continue;
        v = it->second;
      } else {
        continue;
      }
      if ((load || store) && i == 0) continue;  // the space id
      // The return address a CALL pushes is not a reference.
      if (v < 0x100 || !info.is_mapped(v) || v == insn.address + insn.length ||
          std::find(flow_targets.begin(), flow_targets.end(), v) != flow_targets.end())
        continue;
      RefKind kind = RefKind::data_pointer;
      if (load && i == 1) kind = RefKind::data_read;
      else if (store && i == 1) kind = RefKind::data_write;
      add(v, kind);
    }
  }
  // One reference per (target, kind) per instruction.
  std::sort(out.begin() + static_cast<std::ptrdiff_t>(first), out.end(),
            [](const FlowRef &a, const FlowRef &b) { return std::tie(a.to, a.kind) < std::tie(b.to, b.kind); });
  out.erase(std::unique(out.begin() + static_cast<std::ptrdiff_t>(first), out.end(),
                        [](const FlowRef &a, const FlowRef &b) { return a.to == b.to && a.kind == b.kind; }),
            out.end());
}

}  // namespace detail

// ---- flow ----

namespace detail {

bool starts_fill(std::uint64_t a, std::uint32_t length, ByteReader &bytes) {
  if (length == 0) return false;
  const std::size_t n = static_cast<std::size_t>(length) * (kMaxRepeatedByteInstructions + 1);
  auto b = bytes.read(a, n);
  if (b.size() < n) return false;
  return std::all_of(b.begin(), b.end(), [&](std::byte x) { return x == b[0]; });
}

}  // namespace detail

namespace {

constexpr std::size_t kMaxFlowInstructions = 200000;
// How far back a computed jump's path is followed to find its table.
constexpr std::size_t kJumpTablePath = 64;
// How far back a computed call's target is looked for on raw images, where
// a register loaded once at a function's start (SuperH, PowerPC) serves
// calls far into it, as Ghidra's constant propagation follows it.
constexpr std::size_t kComputedPath = 512;

}  // namespace

static FlowGraph compute_flow(facts::QueryContext &ctx, const Location &entry) {
  auto info = ctx.get<Program>(entry.program);
  FlowGraph out;
  out.entry = entry.address;
  // Interworking: a tagged key is Thumb code at the address without the tag.
  const std::uint64_t start = info->code_address(entry.address);
  const bool tagged = start != entry.address;
  const bool thumb = info->thumb(entry.address);
  // The listing's edits (units.h): a code mark at the entry forces this
  // flow (it decodes outside code and through cleared bytes older than the
  // mark); otherwise cleared bytes and data stop it.
  UnitReader units(ctx, entry.program);
  std::optional<std::string> forced;
  if (const UnitSpan *u = units.at(start); u && u->state == UnitState::code && u->key == entry.address) forced = u->order;
  if (!info->is_code(start) && !(forced && info->is_mapped(start))) {
    ctx.set_confidence(facts::Confidence::Uncertain);
    return out;
  }
  // Whether the bytes [a, last] may hold an instruction this flow decodes.
  auto passable = [&](std::uint64_t a, std::uint64_t last) {
    for (std::uint64_t x = a; x <= last;) {
      const UnitSpan *u = units.overlapping(x, last);
      if (u == nullptr) return true;
      if (u->state == UnitState::data) return false;
      if (u->state == UnitState::cleared && !(forced && u->order < *forced)) return false;
      if (u->last >= last) return true;
      x = u->last + 1;
    }
    return true;
  };
  ByteReader bytes(ctx, *info);
  Decoder decoder(*info);
  detail::Assertions asserted(ctx, info->space);
  const std::string &ram = info->code_space;
  // Another function starts at a seed, unless an assertion says none does.
  auto starts_function = [&](std::uint64_t a) {
    if (!info->seed_at(a)) return false;
    facts::FactValue b = asserted.bounds(a);
    const auto *v = std::get_if<std::int64_t>(&b);
    return !(v && *v == kNotAFunction);
  };

  struct Decoded {
    lift::Instruction insn;
    FlowInsn flow;
    std::uint64_t pred = 0;  // the instruction this one was first reached from
    bool has_pred = false;
  };
  std::map<std::uint64_t, Decoded> done;
  // Overlap check: an address inside an instruction already decoded.
  auto inside_other = [&](std::uint64_t a) {
    auto it = done.upper_bound(a);
    if (it == done.begin()) return false;
    --it;
    return it->first != a && a - it->first < it->second.flow.length;
  };
  // The straight-line instructions that led to `d`, oldest first.
  auto path_to = [&](const Decoded &d, std::size_t limit = kJumpTablePath) {
    std::vector<const lift::Instruction *> path{&d.insn};
    for (const Decoded *p = &d; p->has_pred && path.size() < limit;) {
      auto pit = done.find(p->pred);
      if (pit == done.end()) break;
      p = &pit->second;
      path.push_back(&p->insn);
    }
    std::reverse(path.begin(), path.end());
    return path;
  };
  std::vector<Range> literals;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> case_calls;
  std::vector<std::uint64_t> far_jumps;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> ref_calls;
  std::optional<std::int64_t> frame;  // the entry's prologue_frame (-1: none), once asked

  struct Work {
    std::uint64_t addr;
    std::uint64_t pred;
    bool has_pred;
  };
  std::vector<Work> work{{start, 0, false}};
  // Computed jumps the first path to them resolved to one address because
  // the index was a constant there (an out-of-range value clamped to a
  // case: cmp r0, #3; bls 1f; movs r0, #0; 1: lsls r0, #1; add pc, r0).
  std::set<std::uint64_t> constant_jumps;
  // A computed jump several jumps share (avr-gcc's __tablejump2__, an
  // epilogue's table dispatch): the first path to reach it probed its
  // table; another path that jumps into the same straight run may index a
  // table of its own, so it is probed along that path too and what it
  // finds joins the jump's targets. That path may also be the one with the
  // switch's guard when the first had none, or a constant index: a jump
  // the first path resolved to one address becomes the table's (two or
  // more destinations) when another path's probe finds one.
  auto reprobe_shared_jump = [&](std::uint64_t at, std::uint64_t from) {
    std::vector<const lift::Instruction *> tail;
    Decoded *jump = nullptr;
    std::uint64_t x = at;
    for (int k = 0; k < 8 && !jump; ++k) {
      auto it = done.find(x);
      if (it == done.end()) return;
      tail.push_back(&it->second.insn);
      const FlowInsn &f = it->second.flow;
      if (f.kind == FlowKind::jump_indirect || (f.kind == FlowKind::jump && constant_jumps.contains(x))) jump = &it->second;
      else if (f.kind != FlowKind::fall || !f.falls_through) return;
      else x += f.length;
    }
    if (!jump || jump->flow.no_return) return;
    const bool constant = jump->flow.kind == FlowKind::jump;
    if (jump->flow.resolved && !constant) return;
    auto pit = done.find(from);
    if (pit == done.end()) return;
    std::vector<const lift::Instruction *> path = path_to(pit->second);
    path.insert(path.end(), tail.begin(), tail.end());
    if (path.size() > kJumpTablePath) path.erase(path.begin(), path.end() - static_cast<std::ptrdiff_t>(kJumpTablePath));
    std::vector<Range> table_bytes;
    std::vector<std::uint64_t> table = detail::recover_jump_table(path, *info, bytes, &table_bytes);
    if (constant) {
      if (table.size() < 2) return;
      // The table's destinations in index order, then the one the constant
      // gave if the table lacks it (its target is decoded already).
      const std::vector<std::uint64_t> was = std::move(jump->flow.targets);
      jump->flow.kind = FlowKind::jump_indirect;
      jump->flow.resolved = false;
      jump->flow.targets.clear();
      for (std::uint64_t t : table)
        if (std::find(jump->flow.targets.begin(), jump->flow.targets.end(), t) == jump->flow.targets.end()) {
          jump->flow.targets.push_back(t);
          if (std::find(was.begin(), was.end(), t) == was.end()) work.push_back({t, jump->insn.address, true});
        }
      for (std::uint64_t t : was)
        if (std::find(jump->flow.targets.begin(), jump->flow.targets.end(), t) == jump->flow.targets.end())
          jump->flow.targets.push_back(t);
      constant_jumps.erase(jump->insn.address);
      literals.insert(literals.end(), table_bytes.begin(), table_bytes.end());
      return;
    }
    literals.insert(literals.end(), table_bytes.begin(), table_bytes.end());
    for (std::uint64_t t : table) {
      if (std::find(jump->flow.targets.begin(), jump->flow.targets.end(), t) != jump->flow.targets.end()) continue;
      jump->flow.targets.push_back(t);
      work.push_back({t, jump->insn.address, true});
    }
  };
  while (!work.empty()) {
    Work w = work.back();
    work.pop_back();
    std::uint64_t a = w.addr;
    std::uint64_t pred = w.pred;
    bool has_pred = w.has_pred;
    while (true) {
      if (done.contains(a)) {
        if (has_pred) reprobe_shared_jump(a, pred);
        break;
      }
      if (done.size() >= kMaxFlowInstructions) {
        out.truncated = true;
        break;
      }
      if (a != start && starts_function(a)) break;
      if (!(info->is_code(a) || (forced && info->is_mapped(a))) || inside_other(a)) break;
      if (!passable(a, a)) break;
      auto insn = decoder.decode(a, bytes, tagged);
      if (!insn) break;
      if (insn->length + insn->delay_slot > 1 && !passable(a, a + insn->length + insn->delay_slot - 1)) break;
      if (detail::starts_fill(a, insn->length, bytes)) break;
      InsnFlow f = detail::classify(*insn, ram);
      FlowInsn fi;
      fi.address = a;
      fi.length = insn->length + insn->delay_slot;
      fi.kind = f.kind;
      fi.falls_through = f.falls_through && !insn->unimplemented;
      fi.targets = f.targets;
      fi.tail_call = f.tail_call;
      fi.delay = insn->delay_slot;
      // Conditional execution: a CBRANCH to the next instruction, or within
      // the p-code to its end, skips the rest.
      for (std::size_t k = 0; k < insn->pcode.size(); ++k) {
        const lift::PcodeOp &op = insn->pcode[k];
        if (op.opcode != "CBRANCH" || op.inputs.empty()) continue;
        if (op.inputs[0].space == ram && op.inputs[0].offset == a + fi.length) fi.conditional = true;
        if (op.inputs[0].space == "const") {
          const unsigned bits = 8 * op.inputs[0].size;
          const auto rel = bits >= 64 ? static_cast<std::int64_t>(op.inputs[0].offset)
                                      : static_cast<std::int64_t>(op.inputs[0].offset << (64 - bits)) >> (64 - bits);
          if (static_cast<std::int64_t>(k) + rel >= static_cast<std::int64_t>(insn->pcode.size())) fi.conditional = true;
        }
      }
      if (fi.kind == FlowKind::call && !info->isa_context.empty()) {
        // A direct call into the other instruction set (BLX imm) sets the
        // mode register; others keep this function's.
        Evaluator eval(*info, nullptr);
        eval.step(*insn);
        bool to_thumb = thumb;
        if (auto v = eval.register_value(info->isa_register->first, info->isa_register->second)) to_thumb = *v != 0;
        for (std::uint64_t &t : fi.targets) t = info->code_key(t, to_thumb);
      }
      const FlowOverride override_kind = fi.kind != FlowKind::fall ? asserted.flow_override(a) : FlowOverride::none;
      if (override_kind != FlowOverride::none) detail::apply_override(fi, override_kind);
      if (fi.kind == FlowKind::call && fi.targets.size() == 1 && fi.falls_through &&
          detail::named_no_return(ctx, entry.program, *info, fi.targets[0]))
        fi.falls_through = false;
      if (fi.kind == FlowKind::call_indirect || fi.kind == FlowKind::jump_indirect) {
        // Through an import slot (-fno-plt, PE IAT, a tail call through the
        // GOT): a no-return import ends control here.
        Evaluator eval(*info, nullptr);
        eval.step(*insn);
        const auto &t = eval.indirect_target();
        if (t && t->kind == Sym::Kind::loaded)
          if (const ImportSlot *s = info->import_at(t->value); s && is_known_no_return(s->name)) {
            fi.no_return = true;
            fi.falls_through = false;
          }
      }
      auto [it, inserted] = done.emplace(a, Decoded{std::move(*insn), fi, pred, has_pred});
      Decoded &d = it->second;

      const bool computed = d.flow.kind == FlowKind::jump_indirect || d.flow.kind == FlowKind::call_indirect;
      if (computed && !d.flow.no_return && override_kind == FlowOverride::none) {
        const auto path = path_to(d);
        detail::Computed c = detail::resolve_computed(path, *info, bytes);
        if (!c.target && !c.returns && info->search && path.size() == kJumpTablePath)
          c = detail::resolve_computed(path_to(d, kComputedPath), *info, bytes);
        if (d.flow.kind == FlowKind::jump_indirect && c.returns) {
          d.flow.kind = FlowKind::ret;
          d.flow.targets.clear();
          d.flow.resolved = true;
        }
        // ARM before v5 calls through a register with "mov lr, pc" then a
        // jump: the jump returns here (Ghidra's ARM LRset).
        if (d.flow.kind == FlowKind::jump_indirect && c.links) {
          d.flow.kind = FlowKind::call_indirect;
          d.flow.falls_through = true;
          d.flow.resolved = true;
        }
        std::vector<std::uint64_t> table;
        if (d.flow.kind == FlowKind::ret) {
          // done: a return
        } else if (d.flow.kind == FlowKind::jump_indirect)
          table = detail::recover_jump_table(path, *info, bytes, &literals);
        if (d.flow.kind == FlowKind::ret) {
        } else if (table.size() >= 2) {
          d.flow.targets = std::move(table);
        } else if (c.target && info->is_code(*c.target) && (!info->isa_context.empty() || info->search)) {
          // (ARM, where literal pools and the program counter make these
          // targets, and raw images on every processor, where a call
          // through a register loaded with a constant is how firmware calls
          // far: MIPS's jalr after lui/addiu, SuperH's jsr @rn after a
          // literal load, PowerPC's bctrl after lis/ori, Xtensa's callx
          // after l32r, as Ghidra's constant propagation resolves them.
          // In ELF and PE programs elsewhere Ghidra leaves such jumps alone.)
          const bool to_thumb = c.thumb.value_or(thumb);
          const std::uint64_t key = info->code_key(*c.target, to_thumb);
          d.flow.resolved = true;
          if (d.flow.kind == FlowKind::call_indirect) {
            // A call through a known pointer.
            d.flow.kind = FlowKind::call;
            d.flow.targets = {key};
            if (d.flow.falls_through && detail::named_no_return(ctx, entry.program, *info, key))
              d.flow.falls_through = false;
          } else if (to_thumb == thumb && *c.target < start) {
            // A jump back before this function's entry: a tail call of the
            // code there (SuperH's braf after an epilogue), which Ghidra
            // makes a computed call to a function.
            d.flow.kind = FlowKind::call;
            d.flow.targets = {key};
            d.flow.tail_call = true;
            d.flow.falls_through = false;
          } else if (to_thumb == thumb) {
            // A jump to a known address in this instruction set: flow goes on there.
            d.flow.kind = FlowKind::jump;
            d.flow.targets = {*c.target};
            constant_jumps.insert(a);
          } else {
            // Into the other instruction set: a tail call of the code there.
            d.flow.kind = FlowKind::call;
            d.flow.targets = {key};
            d.flow.tail_call = true;
            d.flow.falls_through = false;
          }
        }
      } else if (d.flow.kind == FlowKind::jump_indirect) {
        d.flow.targets = detail::recover_jump_table(path_to(d), *info, bytes, &literals);
      }
      if (d.flow.kind == FlowKind::call && d.flow.targets.size() == 1 && d.flow.falls_through && info->link_register &&
          override_kind == FlowOverride::none) {
        // A call to a switch helper: it goes on at one of the places the
        // table after the call names, not after the call. The table comes
        // from running the path on through the helper's own instructions.
        const std::uint64_t callee = d.flow.targets[0];
        if (const std::uint32_t count = *ctx.get<detail::CaseHelper>(Location{entry.program, callee}); count != 0) {
          std::vector<lift::Instruction> helper;
          const std::uint64_t first = info->code_address(callee);
          std::uint64_t at = first;
          for (std::uint32_t k = 0; k < count; ++k) {
            auto h = decoder.decode(at, bytes, first != callee);
            if (!h) break;
            at += h->length + h->delay_slot;
            helper.push_back(std::move(*h));
          }
          if (helper.size() == count) {
            auto path = path_to(d);
            for (const lift::Instruction &h : helper) path.push_back(&h);
            std::vector<Range> table_bytes;
            std::vector<std::uint64_t> table = detail::recover_jump_table(path, *info, bytes, &table_bytes);
            if (table.size() >= 2) {
              d.flow.kind = FlowKind::jump_indirect;
              d.flow.targets = std::move(table);
              d.flow.falls_through = false;
              case_calls.emplace_back(a, callee);
              // (Not the helper's own code, should it load from itself.)
              for (const Range &r : table_bytes)
                if (r.last < first || r.first >= at) literals.push_back(r);
            }
          }
        }
      }
      if (d.flow.kind == FlowKind::call && d.flow.targets.size() == 1 && d.flow.falls_through && info->link_register &&
          override_kind == FlowOverride::none) {
        // A far jump (gcc's Thumb-1: bl to a place further on in this
        // function, whose prologue saved the link register): the code
        // there returns from exactly the frame this function's prologue
        // made, so it isn't a callee.
        const std::uint64_t callee = d.flow.targets[0];
        const std::uint64_t to = info->code_address(callee);
        constexpr std::uint64_t kFar = std::uint64_t{1} << 22;  // bl's reach
        if (to > start && to - start < kFar && info->thumb(callee) == thumb && !info->seed_at(to)) {
          if (!frame) frame = detail::prologue_frame(*info, entry.address, bytes, decoder).value_or(-1);
          if (*frame >= 0 && *ctx.get<detail::FrameFragment>(Location{entry.program, callee}) == *frame) {
            d.flow.kind = FlowKind::jump;
            d.flow.targets = {to};
            d.flow.falls_through = false;
            far_jumps.push_back(a);
          }
        }
      }
      // User references: a computed jump goes on at the user's targets
      // too; a call reference's target is a function (from any
      // instruction, as Ghidra makes one where a call reference points).
      for (const UserRef &u : asserted.references(a)) {
        if (u.remove) continue;
        std::uint64_t to = u.to;
        bool to_thumb = thumb;
        if (!info->isa_context.empty() && (to & 1)) {
          to &= ~std::uint64_t{1};
          to_thumb = true;
        }
        if (u.is_jump() && d.flow.kind == FlowKind::jump_indirect) {
          if (to_thumb == thumb && std::find(d.flow.targets.begin(), d.flow.targets.end(), to) == d.flow.targets.end())
            d.flow.targets.push_back(to);
        } else if (u.is_call()) {
          ref_calls.emplace_back(a, info->code_key(to, to_thumb));
        }
      }
      if (d.flow.kind != FlowKind::call && d.flow.kind != FlowKind::call_indirect) {
        // Push in reverse so lower targets are explored first (stable order).
        for (auto t = d.flow.targets.rbegin(); t != d.flow.targets.rend(); ++t)
          if (*t != a) work.push_back({*t, a, true});
      }
      if (!d.flow.falls_through) break;
      const std::uint64_t next = a + d.flow.length;
      if (next < a) break;
      pred = a;
      has_pred = true;
      a = next;
    }
  }

  detail::collect_data_refs(*info, bytes, start, done.size(),
                            [&](std::uint64_t a) -> detail::DecodedAt {
                              auto it = done.find(a);
                              if (it == done.end()) return {};
                              return {&it->second.insn, &it->second.flow};
                            },
                            out.data_refs);
  out.insns.reserve(done.size());
  for (auto &[addr, d] : done) {
    const auto index = static_cast<std::uint32_t>(out.insns.size());
    if (info->references) {
      detail::references(d.insn, *info, index, false, out.refs);
      // A delay slot's own references, from it decoded on its own.
      if (d.flow.delay != 0 && d.flow.delay < d.flow.length)
        if (auto slot = decoder.decode(addr + (d.flow.length - d.flow.delay), bytes, tagged))
          detail::references(*slot, *info, index, true, out.refs);
    }
    // Words loaded from code (literal pools): data, and what they hold may
    // be a function's address, or (as Ghidra's ARM constant references
    // name them) the address the code works on.
    // (A load from a constant address can also be a memory operand of
    // any op, as SuperH's mov.l @(disp,pc) lifts to a COPY from ram.)
    bool loads = false;
    for (const lift::PcodeOp &op : d.insn.pcode) {
      loads = loads || op.opcode == "LOAD";
      if (op.opcode != "BRANCH" && op.opcode != "CBRANCH" && op.opcode != "CALL")
        for (const lift::Varnode &v : op.inputs) loads = loads || v.space == ram;
    }
    if (loads) {
      Evaluator eval(*info, &bytes);
      eval.restrict_loads_to_code();
      eval.step(d.insn);
      const std::size_t first_ref = out.refs.size();
      for (const auto &[at, size] : eval.loads()) {
        literals.push_back({at, at + size - 1});
        if (size != info->pointer_size) continue;
        auto v = bytes.uint(at, size, info->big_endian);
        if (!v) continue;
        const std::uint64_t target = info->code_address(*v);
        const bool to_thumb = !info->isa_context.empty() && (*v & 1) != 0;
        if (info->is_code(target) && target % (to_thumb ? 2 : (info->isa_context.empty() ? 1 : 4)) == 0)
          out.code_pointers.push_back(info->code_key(target, to_thumb));
        if (info->references && *v >= 0x100 && info->is_mapped(target) && target != addr)
          out.refs.push_back({index, RefKind::data_pointer, false, target});
      }
      if (out.refs.size() != first_ref) {
        // Keep this instruction's references sorted and one per (to, kind).
        auto from = out.refs.begin() + static_cast<std::ptrdiff_t>(first_ref);
        while (from != out.refs.begin() && std::prev(from)->insn == index) --from;
        std::sort(from, out.refs.end(), [](const FlowRef &x, const FlowRef &y) {
          return std::tie(x.delay_slot, x.to, x.kind) < std::tie(y.delay_slot, y.to, y.kind);
        });
        out.refs.erase(std::unique(from, out.refs.end(),
                                   [](const FlowRef &x, const FlowRef &y) {
                                     return x.delay_slot == y.delay_slot && x.to == y.to && x.kind == y.kind;
                                   }),
                       out.refs.end());
      }
    }
    out.insns.push_back(std::move(d.flow));
  }
  std::sort(case_calls.begin(), case_calls.end());
  out.case_calls = std::move(case_calls);
  std::sort(far_jumps.begin(), far_jumps.end());
  out.far_jumps = std::move(far_jumps);
  std::sort(ref_calls.begin(), ref_calls.end());
  ref_calls.erase(std::unique(ref_calls.begin(), ref_calls.end()), ref_calls.end());
  out.ref_calls = std::move(ref_calls);
  std::sort(out.code_pointers.begin(), out.code_pointers.end());
  out.code_pointers.erase(std::unique(out.code_pointers.begin(), out.code_pointers.end()), out.code_pointers.end());
  std::sort(literals.begin(), literals.end());
  for (const Range &r : literals) {
    if (!out.literals.empty() && r.first <= out.literals.back().last + 1)
      out.literals.back().last = std::max(out.literals.back().last, r.last);
    else
      out.literals.push_back(r);
  }
  if (out.truncated || out.insns.empty()) ctx.set_confidence(facts::Confidence::Uncertain);
  return out;
}

FlowGraph Flow::compute(facts::QueryContext &ctx, const Location &entry) {
  FlowGraph out = compute_flow(ctx, entry);
  // An import following its progress (WatchDiscovery): what was decoded.
  if (DiscoveryProgress *p = detail::discovery_progress(entry.program)) {
    p->decoded_bytes.fetch_add(decoded_bytes(out), std::memory_order_relaxed);
    if (!out.insns.empty()) p->flows.fetch_add(1, std::memory_order_relaxed);
  }
  return out;
}

}  // namespace revkit::analysis
