// Jump-table recovery by probing.
//
// The instructions on the path to a computed jump are interpreted from just
// before its guard (the conditional branch that sends out-of-range values
// to the default case). One register the code reads there is the switch
// index: we give it the values 0, 1, 2, ... and run the path with real
// memory, so each value yields the jump's destination, read from the
// table. Values stop when the guard would leave the path. This needs no
// pattern per compiler or machine: the p-code itself computes the table
// address, the entry size and sign, and the base it is relative to.
//
// Recognised: a guarded index into a table of absolute or relative entries
// (gcc and clang on x86-64 and AArch64, RISC-V, PE), with the index in a
// register or a stack slot; an unguarded index masked with AND, whose
// table ends where entries stop being code nearby or start repeating; and
// a computed goto's table indexed by a zero-extended byte (at most 256
// entries, ending where they stop being code nearby). Not
// recognised: guards more than a few instructions before the jump. A guard
// on another path than the one flow first reached the jump by is probed
// when flow reaches the jump's straight run that way (analysis.flow's
// reprobe_shared_jump).

#include "internal.h"

#include <algorithm>

namespace revkit::analysis::detail {

using namespace std::string_view_literals;

namespace {

constexpr std::uint64_t kMaxEntries = 1024;
constexpr std::size_t kMaxGuards = 3;
constexpr std::size_t kSplitsPerGuard = 5;
constexpr std::size_t kMaxCandidates = 4;
// How far from the jump an unguarded table's destinations may lie.
constexpr std::uint64_t kNear = 256 * 1024;

// The CBRANCH into the code space in an instruction, if any.
const lift::PcodeOp *code_cbranch(const lift::Instruction &insn, const std::string &code_space) {
  for (const lift::PcodeOp &op : insn.pcode)
    if (op.opcode == "CBRANCH"sv && !op.inputs.empty() && op.inputs[0].space == code_space) return &op;
  return nullptr;
}

}  // namespace

namespace {

// The register an instruction's computed jump goes to, if it goes to one
// as it is (mov pc, lr: copies and masks of it), not to a value loaded or
// computed from it.
std::optional<std::uint64_t> jump_register(const lift::Instruction &insn) {
  const lift::Varnode *target = nullptr;
  std::size_t at = insn.pcode.size();
  for (std::size_t i = insn.pcode.size(); i-- > 0;)
    if ((insn.pcode[i].opcode == "BRANCHIND"sv || insn.pcode[i].opcode == "CALLIND"sv) && !insn.pcode[i].inputs.empty()) {
      target = &insn.pcode[i].inputs[0];
      at = i;
      break;
    }
  // Back through the copies and masks this instruction makes (ARM: pc =
  // (lr & ~1) & ~3) to a register it reads as it came in.
  while (target) {
    const lift::Varnode *from = nullptr;
    bool written = false;
    for (std::size_t i = at; i-- > 0;) {
      const lift::PcodeOp &op = insn.pcode[i];
      if (!op.output || op.output->space != target->space || op.output->offset != target->offset) continue;
      written = true;
      if ((op.opcode == "COPY"sv || op.opcode == "INT_AND"sv) && !op.inputs.empty()) {
        from = &op.inputs[0];
        at = i;
      }
      break;
    }
    if (!written) return target->space == "register"sv ? std::optional<std::uint64_t>(target->offset) : std::nullopt;
    target = from;
  }
  return std::nullopt;
}

// How many low bits a register can have set where the path reaches
// instruction `upto`: the width a zero extension (movzx eax, byte [rdi];
// ldrb w1; lbu a5; the 64-bit register's own zero extension of the 32-bit
// one) last gave it, through copies and through a sign extension of a
// value zero-extended from fewer bits (cdqe after movzx). nullopt when
// something else wrote it last.
std::optional<unsigned> zext_bits(const std::vector<const lift::Instruction *> &path, std::size_t upto,
                                  std::uint64_t reg) {
  std::size_t k = upto, i = 0;
  bool started = false;
  std::optional<unsigned> bits;
  // A sign extension keeps the value small only if it was zero-extended
  // from fewer bits than the extended width.
  unsigned below = UINT32_MAX;
  auto result = [&]() -> std::optional<unsigned> {
    if (bits && *bits < below) return bits;
    return below == UINT32_MAX ? bits : std::nullopt;
  };
  for (int hops = 0; hops < 8; ++hops) {
    const lift::PcodeOp *def = nullptr;
    // The last op before (k, i) that writes `reg`.
    while (!def) {
      if (started && i > 0) {
        --i;
      } else {
        if (k == 0) return result();
        --k;
        i = path[k]->pcode.size();
        started = true;
        continue;
      }
      const lift::PcodeOp &op = path[k]->pcode[i];
      if (op.output && op.output->space == "register"sv && op.output->offset == reg) def = &op;
    }
    if (def->inputs.empty()) return result();
    const lift::Varnode &in = def->inputs[0];
    if (def->opcode == "INT_ZEXT"sv) {
      const unsigned w = in.size * 8;
      bits = bits ? std::min(*bits, w) : w;
      if (bits && *bits < below) below = UINT32_MAX;  // settled
    } else if (def->opcode == "INT_SEXT"sv) {
      if (!bits || *bits >= in.size * 8) below = std::min(below, in.size * 8u);
    } else if (def->opcode != "COPY"sv) {
      return result();
    }
    if (in.space != "register"sv) return result();
    reg = in.offset;
  }
  return result();
}

}  // namespace

Computed resolve_computed(const std::vector<const lift::Instruction *> &path, const ProgramInfo &info,
                          ByteReader &bytes) {
  Computed out;
  if (path.empty()) return out;
  // mov pc, lr with lr not set to a known value: a return.
  if (info.link_register)
    if (auto reg = jump_register(*path.back()); reg && *reg == info.link_register->first) {
      Evaluator e(info, nullptr);
      e.forget_at_calls();
      for (const lift::Instruction *insn : path) e.step(*insn);
      if (!e.register_value(info.link_register->first, info.link_register->second)) {
        out.returns = true;
        return out;
      }
    }
  Evaluator e(info, &bytes);
  e.restrict_loads_to_code();
  e.forget_at_calls();
  e.keep_slots();
  // (The jump's own CALLIND reads its target before it clobbers.)
  for (const lift::Instruction *insn : path) e.step(*insn);
  const lift::Instruction &last = *path.back();
  if (const auto &t = e.indirect_target(); t && t->known()) out.target = t->value;
  // mov pc, lr; ldr pc, [sp], #4 after a push of lr: Ghidra's ARM analysis
  // makes these returns.
  if (const auto &t = e.indirect_target(); t && info.link_register) {
    if (auto reg = e.incoming_register(*t); reg && *reg == info.link_register->first) out.returns = true;
  }
  if (info.isa_register) {
    // Set only if this instruction (or the path) wrote it: BX and BLX.
    if (auto v = e.register_value(info.isa_register->first, info.isa_register->second)) out.thumb = *v != 0;
  }
  if (info.link_register)
    if (auto lr = e.register_value(info.link_register->first, info.link_register->second))
      out.links = *lr == last.address + last.length + last.delay_slot;
  return out;
}

std::vector<std::uint64_t> recover_jump_table(const std::vector<const lift::Instruction *> &path,
                                              const ProgramInfo &info, ByteReader &bytes,
                                              std::vector<Range> *table) {
  if (path.size() < 2) return {};
  const std::size_t n = path.size();

  // Where the path's conditional branches went.
  std::vector<std::optional<bool>> direction(n);
  for (std::size_t k = 0; k + 1 < n; ++k) {
    const lift::PcodeOp *cb = code_cbranch(*path[k], info.code_space);
    if (!cb) continue;
    const std::uint64_t target = cb->inputs[0].offset;
    const std::uint64_t fall = path[k]->address + path[k]->length + path[k]->delay_slot;
    if (target == fall) continue;
    if (path[k + 1]->address == target) direction[k] = true;
    else if (path[k + 1]->address == fall) direction[k] = false;
  }

  // The low-bits masks the code from `split` ANDs something with.
  auto index_masks = [&](std::size_t split) {
    std::vector<std::uint64_t> masks;
    for (std::size_t k = split; k < n; ++k)
      for (const lift::PcodeOp &op : path[k]->pcode) {
        if (op.opcode != "INT_AND"sv) continue;
        for (const lift::Varnode &v : op.inputs) {
          std::uint64_t m = v.offset;
          // (ARM's interworking tests every branch target's low bit: & 1.)
          if (v.space == "const"sv && m != 0 && m < kMaxEntries && (m & (m + 1)) == 0 && !(m == 1 && info.isa_register))
            masks.push_back(m);
        }
      }
    return masks;
  };
  auto masks_index = [&](std::size_t split) { return !index_masks(split).empty(); };

  // What gets probed: a register, or a stack slot addressed through one.
  struct Candidate {
    bool memory = false;
    std::pair<std::uint64_t, std::uint32_t> reg;
    Evaluator::FreeMemory slot{};
  };

  // Runs the path from `split` with the candidate set to `value`.
  enum class Probe : std::uint8_t {
    target,    // reached the jump; `at` is where it goes
    left,      // a guard sent this value off the path
    unknown,   // the destination doesn't follow from the candidate alone
    not_code,  // it does, but isn't code: past the end of the table
  };
  struct Outcome {
    Probe kind;
    std::uint64_t at = 0;
    bool blind = false;  // a guard on the path couldn't be evaluated
  };
  std::vector<Range> loaded;  // code the probes read entries from
  auto run = [&](const Evaluator &base, std::size_t split, const Candidate &c,
                 std::optional<std::uint64_t> value) -> Outcome {
    Evaluator e = base.fork();
    if (!c.memory) e.set_register(c.reg.first, c.reg.second, value);
    else if (!e.set_memory(c.slot, value)) return {Probe::unknown};
    bool blind = false;
    for (std::size_t k = split; k < n; ++k) {
      e.step(*path[k]);
      if (k + 1 < n && direction[k]) {
        if (!e.branch_condition() || !e.branch_condition()->known()) {
          blind = true;
          continue;
        }
        bool taken = e.branch_condition()->value != 0;
        if (taken != *direction[k]) return {Probe::left};
      }
    }
    const auto &t = e.indirect_target();
    // A conditional jump (ARM's ldrls pc, [pc, r0, lsl #2]) is its own
    // guard: the value skipped it.
    if (!t && e.decided()) return {Probe::left, 0, blind};
    if (!t || !t->known()) return {Probe::unknown, 0, blind};
    if (table)
      for (const auto &[addr, size] : e.loads())
        if (info.is_code(addr)) loaded.push_back({addr, addr + size - 1});
    if (!info.is_code(t->value)) return {Probe::not_code, 0, blind};
    return {Probe::target, t->value, blind};
  };

  // Probes a candidate: the table's destinations in index order, or empty.
  auto probe = [&](const Evaluator &base, std::size_t split, const Candidate &c) -> std::vector<std::uint64_t> {
    // ARM firmware, where nearly every word is a code address, would have
    // every value probed for computed jumps that aren't tables. Three
    // cheap probes reject most of them first: a destination that doesn't
    // move with the index; unmasked, a largest index that no guard sends
    // away (assuming range-check guards); masked, a largest index that
    // doesn't land where its masked value does. (Elsewhere every value is
    // probed, as these assumptions could reject a table probing accepts.)
    if (info.isa_register) {
      const Outcome big = run(base, split, c, kMaxEntries - 1);
      const Outcome zero = run(base, split, c, 0), one = run(base, split, c, 1);
      if (big.kind == Probe::target && zero.kind == Probe::target && one.kind == Probe::target && zero.at == one.at &&
          zero.at == big.at)
        return {};
      const std::vector<std::uint64_t> masks = index_masks(split);
      if (masks.empty() && big.kind != Probe::left) return {};
      if (!masks.empty() && big.kind == Probe::target) {
        bool masked = false;
        for (std::uint64_t m : masks) {
          const Outcome small = run(base, split, c, (kMaxEntries - 1) & m);
          masked = masked || (small.kind == Probe::target && small.at == big.at);
        }
        if (!masked) return {};
      }
    }
    // A jump whose outcome the code settles without the candidate is no
    // table indexed by it: every value would go the same way (a RISC-V far
    // tail call, auipc t1 / jr lo(t1), probed through each register the
    // code before it read). One run with the candidate unknown tells, in
    // place of kMaxEntries runs with it set that find one destination.
    if (run(base, split, c, std::nullopt).kind != Probe::unknown) return {};
    std::vector<std::uint64_t> targets;
    Probe end = Probe::target;
    bool blind = false;
    for (std::uint64_t i = 0; i < kMaxEntries; ++i) {
      Outcome o = run(base, split, c, i);
      blind = blind || o.blind;
      if (o.kind != Probe::target) {
        end = o.kind;
        break;
      }
      targets.push_back(o.at);
    }
    // A constant destination means the probe never reached the index.
    if (targets.size() < 2 ||
        std::all_of(targets.begin(), targets.end(), [&](std::uint64_t t) { return t == targets[0]; }))
      return {};
    // Without a guard to bound it, the table's size comes from its contents.
    // Only trust that for an index the code masks (x & 0x7f), and when no
    // guard on the way was unreadable (it may have been the bound, testing
    // something other than what we probed).
    if (end != Probe::left && (blind || !masks_index(split))) return {};
    switch (end) {
      case Probe::left: return targets;  // bounded by the guard
      case Probe::unknown: return {};
      case Probe::target: {
        // Never left the path: a table indexed by a masked value repeats
        // with a period, which is then its size.
        for (std::size_t p = 2; p <= kMaxEntries / 2; p *= 2) {
          bool repeats = true;
          for (std::size_t i = p; i < targets.size() && repeats; ++i) repeats = targets[i] == targets[i % p];
          if (repeats) return std::vector<std::uint64_t>(targets.begin(), targets.begin() + static_cast<std::ptrdiff_t>(p));
        }
        return {};
      }
      case Probe::not_code: {
        // No guard, and the table ends where entries stop being code: a
        // switch with no default case over a masked value (clang sizes the
        // table to the cases, as for lua's opcode dispatch). Accept it only
        // when every destination is near the jump.
        const std::uint64_t at = path.back()->address;
        for (std::uint64_t t : targets)
          if ((t > at ? t - at : at - t) > kNear) return {};
        return targets;
      }
    }
    return {};
  };

  // The guards to split at, nearest first; then the jump itself, for
  // tables indexed by a masked value (x & 0x7f) that need no guard.
  std::vector<std::size_t> guards;
  for (std::size_t g = n - 1; g-- > 0 && guards.size() < kMaxGuards;)
    if (direction[g]) guards.push_back(g);
  guards.push_back(n - 1);
  // A probe can only end at a guard: a conditional branch on the path, or
  // the jump itself when it is conditional (an internal CBRANCH skips it).
  bool conditional_jump = false;
  const lift::Instruction &jump = *path.back();
  for (const lift::PcodeOp &op : jump.pcode)
    if (op.opcode == "CBRANCH"sv && !op.inputs.empty() &&
        (op.inputs[0].space == "const"sv ||
         (op.inputs[0].space == info.code_space && op.inputs[0].offset == jump.address + jump.length + jump.delay_slot)))
      conditional_jump = true;
  auto guarded = [&](std::size_t split) {
    if (conditional_jump) return true;
    for (std::size_t k = split; k + 1 < n; ++k)
      if (direction[k]) return true;
    return false;
  };
  for (std::size_t g : guards) {
    // Split just before the guard first (where the compare usually is),
    // then further back, then at the guard itself.
    std::vector<std::size_t> splits;
    for (std::size_t d = 1; d < kSplitsPerGuard && d <= g; ++d) splits.push_back(g - d);
    splits.push_back(g);
    for (std::size_t s : splits) {
      // Without a guard or a mask, no table found from here is accepted
      // (see probe): don't probe.
      if (!guarded(s) && !masks_index(s)) continue;
      // Constants the code before the split computes (table bases hoisted
      // out of the switch block).
      Evaluator base(info, &bytes);
      for (std::size_t k = 0; k < s; ++k) base.step(*path[k]);
      // Registers the rest reads before writing them.
      Evaluator scout(info, &bytes);
      for (std::size_t k = s; k < n; ++k) scout.step(*path[k]);
      // Unknown registers first; then ones the path happens to know (a
      // loop's first iteration may start the switch variable at a
      // constant); then stack slots (unoptimized code keeps it there).
      std::vector<Candidate> candidates, known;
      for (const auto &r : scout.free_registers()) {
        auto same = [&](const Candidate &c) { return c.reg.first == r.first; };
        if (std::any_of(candidates.begin(), candidates.end(), same) || std::any_of(known.begin(), known.end(), same))
          continue;
        (base.register_known(r.first, r.second) ? known : candidates).push_back({false, r, {}});
      }
      candidates.insert(candidates.end(), known.begin(), known.end());
      if (candidates.size() > kMaxCandidates) candidates.resize(kMaxCandidates);
      for (const auto &m : scout.free_memory()) {
        if (candidates.size() >= 2 * kMaxCandidates) break;
        candidates.push_back({true, {}, m});
      }
      for (const Candidate &c : candidates) {
        loaded.clear();
        std::vector<std::uint64_t> targets = probe(base, s, c);
        if (targets.empty()) continue;
        if (table) table->insert(table->end(), loaded.begin(), loaded.end());
        std::sort(targets.begin(), targets.end());
        targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
        return targets;
      }
    }
  }

  // A computed goto (labels as values: an interpreter's opcode dispatch,
  // CPython's goto *opcode_targets[opcode]): no guard and no mask, but an
  // index the code zero-extends from a byte (movzx), so the table has at
  // most 256 entries; it ends where entries stop being code. Accepted when
  // the destinations differ and all lie near the jump, as for an unguarded
  // table ending in non-code.
  // The index is read a few instructions before the jump: the jump itself
  // (jmp [table + rax*8]), the table load before it (O0, AArch64: ldr x1,
  // [x2, w1, uxtw #3]; br x1), or the shift and add before that (RISC-V,
  // with other instructions scheduled in between).
  for (std::size_t back = 1; back <= 8 && back <= n; ++back) {
    const std::size_t split = n - back;
    Evaluator scout(info, &bytes);
    for (std::size_t k = split; k < n; ++k) scout.step(*path[k]);
    for (const auto &r : scout.free_registers()) {
      const std::optional<unsigned> bits = zext_bits(path, split, r.first);
      if (!bits || *bits > 8) continue;
      Evaluator base(info, &bytes);
      for (std::size_t k = 0; k < split; ++k) base.step(*path[k]);
      const Candidate c{false, r, {}};
      if (run(base, split, c, std::nullopt).kind != Probe::unknown) continue;
      loaded.clear();
      std::vector<std::uint64_t> targets;
      for (std::uint64_t i = 0; i < (std::uint64_t{1} << *bits); ++i) {
        const Outcome o = run(base, split, c, i);
        if (o.kind != Probe::target) break;
        targets.push_back(o.at);
      }
      const std::uint64_t at = path.back()->address;
      if (targets.size() < 2 || std::all_of(targets.begin(), targets.end(), [&](std::uint64_t t) { return t == targets[0]; }) ||
          std::any_of(targets.begin(), targets.end(), [&](std::uint64_t t) { return (t > at ? t - at : at - t) > kNear; }))
        continue;
      if (table) table->insert(table->end(), loaded.begin(), loaded.end());
      std::sort(targets.begin(), targets.end());
      targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
      return targets;
    }
  }
  return {};
}

}  // namespace revkit::analysis::detail
