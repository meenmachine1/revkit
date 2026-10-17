// What revkit's inputs say about one function's body: Ghidra's flow
// overrides and code labels in it, and its stack variables.

#include "stack_locals.h"
#include "revkit/inputs/inputs.h"

#include <algorithm>
#include <set>
#include <cstdio>

namespace revkit::inputs {

namespace an = analysis;

bool FunctionSets::is_entry(std::uint64_t a) const { return std::binary_search(entries.begin(), entries.end(), a); }
bool FunctionSets::is_no_return(std::uint64_t a) const {
  return std::binary_search(no_return.begin(), no_return.end(), a);
}

void FunctionSets::encode(facts::Encoder &e) const {
  facts::encode(e, entries);
  facts::encode(e, no_return);
}

FunctionSets FunctionSets::decode(facts::Decoder &d) {
  FunctionSets s;
  s.entries = facts::decode<std::vector<std::uint64_t>>(d);
  s.no_return = facts::decode<std::vector<std::uint64_t>>(d);
  return s;
}

std::vector<std::uint64_t> ghidra_no_return(const an::FunctionList &list, const std::vector<std::uint64_t> *evidence) {
  std::set<std::uint64_t> out;
  for (const an::FunctionInfo &f : list.functions)
    if (f.no_return == an::NoReturnReason::named || f.no_return == an::NoReturnReason::user) out.insert(f.entry.offset);
  if (evidence) out.insert(evidence->begin(), evidence->end());
  // A thunk is as its target (Ghidra's thunk functions answer for theirs).
  for (bool more = true; more;) {
    more = false;
    for (const an::FunctionInfo &f : list.functions)
      if ((f.flags & an::kFunctionThunk) && f.import.empty() && out.contains(f.thunk_target) &&
          out.insert(f.entry.offset).second)
        more = true;
  }
  return {out.begin(), out.end()};
}

FunctionSets function_sets(const an::FunctionList &list, const std::vector<std::uint64_t> *evidence) {
  FunctionSets s;
  for (const an::FunctionInfo &f : list.functions) s.entries.push_back(f.entry.offset);
  s.no_return = ghidra_no_return(list, evidence);
  // Discovery's list is sorted by entry; a list from elsewhere may not be.
  std::sort(s.entries.begin(), s.entries.end());
  std::sort(s.no_return.begin(), s.no_return.end());
  return s;
}

namespace {

std::string hex_name(const loader::Image &image, const std::string &prefix, const std::string &space_prefix,
                     std::uint64_t a) {
  return prefix + loader::name_address(image, a, space_prefix);
}

}  // namespace

FunctionInputs assemble_function(const Program &p, const Options &o, const FunctionSets &sets,
                                 const an::FunctionInfo &f, const an::FlowGraph &g,
                                 const std::vector<lift::LocalFacts> &debug_locals, lift::Lifter &lifter) {
  FunctionInputs out;
  const an::ProgramInfo &info = p.analysis->info();
  const std::string prefix = info.qualify_names ? info.code_space + "_" : std::string();
  const bool import_stub = (f.flags & an::kFunctionThunk) && !f.import.empty();
  const bool elf = p.image->format == loader::Format::elf;
  auto in_body = [&](std::uint64_t a) { return f.body.contains(facts::Address{f.entry.space, a}); };

  // Ghidra's CALL_RETURN flow overrides: on a jump into the EXTERNAL block
  // (an ELF import stub's, OperandReferenceAnalyzer), on an unconditional
  // jump to another function's entry from outside it
  // (SharedReturnAnalysisCmd), and on every call to a no-return function
  // (FindNoReturnFunctionsAnalyzer).
  std::vector<std::uint64_t> targets;
  for (const an::FlowInsn &insn : g.insns) {
    if (!in_body(insn.address)) continue;
    bool call_return = false;
    switch (insn.kind) {
      case an::FlowKind::call:
        call_return = o.no_return && insn.targets.size() == 1 && sets.is_no_return(info.code_address(insn.targets[0]));
        break;
      case an::FlowKind::jump:
        // (Unconditional: a conditional jump can't take the override.)
        call_return = o.plt_overrides && insn.targets.size() == 1 && sets.is_entry(info.code_address(insn.targets[0])) &&
                      insn.targets[0] != f.entry.offset && !sets.is_entry(insn.address);
        break;
      case an::FlowKind::jump_indirect:
        call_return = o.plt_overrides && o.relocations && elf && import_stub && insn.targets.empty();
        break;
      default: break;
    }
    // (Applied to the p-code for a conditional instruction, which
    // Funcdata::overrideFlow can't change.)
    if (call_return) out.flow_overrides.emplace_back(insn.address, insn.conditional ? "PCODE_CALL_RETURN" : "CALL_RETURN");
    // Computed jumps and calls discovery resolved (ARM: mov pc, lr returns;
    // mov lr, pc before a jump calls), as Ghidra's ARM constant analysis
    // overrides their flow; applied to the p-code (they may be conditional).
    else if (insn.resolved && insn.kind == an::FlowKind::ret)
      out.flow_overrides.emplace_back(insn.address, "PCODE_RETURN");
    else if (insn.resolved && (insn.kind == an::FlowKind::call || insn.kind == an::FlowKind::call_indirect))
      out.flow_overrides.emplace_back(insn.address, insn.tail_call ? "PCODE_CALL_RETURN" : "PCODE_CALL");
    // LAB_ names where Ghidra has a reference: branch, jump and jump-table
    // targets.
    if (o.labels && (insn.kind == an::FlowKind::jump || insn.kind == an::FlowKind::branch ||
                     insn.kind == an::FlowKind::jump_indirect))
      for (std::uint64_t t : insn.targets)
        if (!sets.is_entry(t)) targets.push_back(t);
    // The user's fallthrough override (SetFallthrough), for the p-code: a
    // branch to its address (with a label there, from Ghidra's FALL_THROUGH
    // reference), or, with none, the next address left undecoded unless
    // the body has code there.
    if (insn.fall_override) {
      if (insn.falls_through) {
        out.flow_overrides.emplace_back(insn.address, lift::fallthrough_kind({true, insn.fall_to}));
        if (o.labels && !sets.is_entry(insn.fall_to)) targets.push_back(insn.fall_to);
      } else if (const std::uint64_t next = insn.address + insn.length; !in_body(next)) {
        out.flow_overrides.emplace_back(insn.address, lift::fallthrough_kind({false, next}));
      }
    }
  }
  // A switch through a helper (bl __gnu_thumb1_case_uqi, then the table):
  // the helper's call fixup makes the call a computed jump; the call itself
  // doesn't come back to the table behind it (CALL_RETURN, as Ghidra's
  // switch analysis overrides it).
  for (const auto &[from, helper] : g.case_calls)
    if (in_body(from)) out.flow_overrides.emplace_back(from, "CALL_RETURN");
  // A far jump (a `bl` used as a branch within the function): BRANCH.
  for (std::uint64_t from : g.far_jumps)
    if (in_body(from)) out.flow_overrides.emplace_back(from, "BRANCH");
  std::sort(targets.begin(), targets.end());
  targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
  for (std::uint64_t t : targets) out.code_labels.push_back({{}, t, hex_name(*p.image, "LAB_", prefix, t), {}});

  // Ghidra's Stack analyzer: local_<offset> variables where instructions
  // address the stack (not in thunks), around the debug info's own.
  // (Thumb code would need a Thumb engine; it gets none.)
  if (o.stack_locals && !(f.flags & an::kFunctionThunk) && !(f.flags & an::kFunctionThumb)) {
    // What the lifter decoded before may have committed another instruction
    // set over this function (SLEIGH's globalset: an ARM blx to it, a Thumb
    // bl into it); paint its own back first, which rebuilds the engine
    // without those commits.
    if (!info.isa_context.empty() && lifter.context_changed())
      for (const facts::AddressRange &r : f.body.ranges())
        lifter.set_context(info.isa_context, 0, r.first.offset, r.last.offset + 1);
    out.locals = stack_locals(lifter, *p.image, p.language_id, p.image->format == loader::Format::pe, f, g, debug_locals);
  }
  return out;
}

}  // namespace revkit::inputs
