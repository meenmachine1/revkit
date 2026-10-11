// FindNoReturnFunctionsAnalyzer's evidence (no_return.h).

#include "internal.h"
#include "revkit/analysis/no_return.h"

#include <algorithm>
#include <map>
#include <set>
#include <unordered_map>

namespace revkit::analysis {

namespace {

constexpr int kThreshold = 3;  // OPTION_DEFAULT_EVIDENCE_THRESHOLD

struct Call {
  std::uint64_t address = 0;
  std::uint64_t target = 0;
  const FlowGraph *flow = nullptr;  // the flow the call was decoded in
  std::size_t index = 0;            // in Evidence::calls_
};

class Evidence {
 public:
  Evidence(const ProgramInfo &info, const FunctionList &list, std::vector<facts::Ref<FlowGraph>> flows,
           detail::ByteReader &bytes)
      : info_(info), list_(list), flows_(std::move(flows)), bytes_(bytes) {
    x86_ = info.language.starts_with("x86:");
    for (const FunctionInfo &f : list.functions) {
      entries_.insert(f.entry.offset);
      if (f.no_return == NoReturnReason::named) named_.insert(f.entry.offset);
    }
    for (std::size_t k = 0; k < list.functions.size(); ++k) by_entry_[list.functions[k].entry.offset] = k;
    // Every call that falls through, once per address (shared code is in
    // several flows), in address order: Ghidra's reference sources.
    std::map<std::uint64_t, Call> calls;
    for (const auto &g : flows_)
      for (const FlowInsn &i : g->insns)
        if (i.kind == FlowKind::call && i.falls_through && !i.tail_call && i.targets.size() == 1)
          calls.try_emplace(i.address, Call{i.address, info.code_address(i.targets[0]), g.get()});
    for (auto &[a, c] : calls) {
      c.index = calls_.size();
      calls_.push_back(c);
      callers_[c.target].push_back(c);
    }
    indicates_.assign(calls_.size(), kUnknown);
  }

  std::vector<std::uint64_t> run() {
    std::set<std::uint64_t> found;
    if (detect(found)) detect(found);
    return {found.begin(), found.end()};
  }

 private:
  // FindNoReturnFunctionsAnalyzer.detectNoReturn; true if some target was
  // suspicious without enough evidence.
  bool detect(std::set<std::uint64_t> &found) {
    std::set<std::uint64_t> checked;
    bool suspicious = false;
    for (const Call &c : calls_) {
      if (!checked.insert(c.address).second) continue;
      if (!indicates(c)) continue;
      const std::uint64_t target = c.target;
      int count = 1;
      for (const Call &o : callers_[target]) {
        if (!checked.insert(o.address).second) continue;
        if (found.contains(target)) continue;
        if (!indicates(o)) continue;
        if (++count >= kThreshold) {
          found.insert(target);
          break;
        }
      }
      if (count < kThreshold) {
        if (only_calls_no_return(target, found)) {
          found.insert(target);
          continue;
        }
        suspicious = true;
      }
    }
    return suspicious;
  }

  std::uint64_t function_after(std::uint64_t a) const {
    auto it = entries_.lower_bound(a);
    return it == entries_.end() ? ~std::uint64_t{0} : *it;
  }

  // checkNonReturningIndicators: what follows the call isn't code that
  // continues the caller. Remembered: the second detect() asks again.
  bool indicates(const Call &c) {
    std::int8_t &known = indicates_[c.index];
    if (known == kUnknown) known = walk_indicates(c) ? 1 : 0;
    return known == 1;
  }
  bool walk_indicates(const Call &c) {
    const FlowInsn *call = c.flow->at(c.address);
    if (call == nullptr) return false;
    std::uint64_t fall = c.address + call->length;
    const std::uint64_t next = function_after(fall);
    // The flow's instructions are in address order: the one at `fall` is
    // usually the one after the last (else a search finds it, or nothing).
    const FlowInsn *const end = c.flow->insns.data() + c.flow->insns.size();
    const FlowInsn *last = call;
    for (std::size_t steps = 0; steps < 4096; ++steps) {
      if (next == fall) return true;  // a function defined after the call
      const FlowInsn *i = last + 1 != end && last[1].address == fall ? last + 1 : c.flow->at(fall);
      if (i == nullptr) return true;  // falls into what isn't code (undefined or data)
      last = i;
      // A literal pool the code loads from is data (Ghidra's constant
      // analysis defines it), though this flow decoded through it.
      if (in_literals(*c.flow, fall, i->length)) return true;
      if (next > fall && next < fall + i->length) return true;  // a function inside the instruction
      if (x86_) {
        auto b = bytes_.uint(fall, 1, false);
        if (b && *b == 0xcc) return true;  // INT3 after the call
      }
      // On through plain instructions only (FlowType.isFallthrough).
      if (i->kind != FlowKind::fall || !i->falls_through) return false;
      fall += i->length;
    }
    return false;
  }

  static bool in_literals(const FlowGraph &g, std::uint64_t a, std::uint64_t length) {
    auto it = std::upper_bound(g.literals.begin(), g.literals.end(), a + length - 1,
                               [](std::uint64_t x, const Range &r) { return x < r.first; });
    return it != g.literals.begin() && std::prev(it)->last >= a;
  }
  bool no_return(std::uint64_t target, const std::set<std::uint64_t> &found) const {
    return found.contains(target) || named_.contains(target);
  }

  // targetOnlyCallsNoReturn: every path through the target ends in a call
  // to a non-returning function.
  bool only_calls_no_return(std::uint64_t target, const std::set<std::uint64_t> &found) {
    auto fit = by_entry_.find(target);
    if (fit == by_entry_.end()) return false;
    const FlowGraph &g = *flows_[fit->second];
    std::vector<std::uint64_t> todo{target};
    std::set<std::uint64_t> visited;
    bool hit = false;
    while (!todo.empty()) {
      std::uint64_t a = todo.back();
      todo.pop_back();
      if (!visited.insert(a).second) continue;
      // Along the block to its end.
      for (;;) {
        const FlowInsn *i = g.at(a);
        if (i == nullptr) return false;
        switch (i->kind) {
          case FlowKind::ret: return false;
          case FlowKind::call:
          case FlowKind::call_indirect: {
            const bool known = i->targets.size() == 1 && no_return(info_.code_address(i->targets[0]), found);
            // A call to a known name has no fallthrough (the disassembler
            // knew); one to a function found here still has its own until
            // the analyzer clears it, so the path goes on past it.
            if (known) hit = true;
            if (known && !i->falls_through) break;
            if (!known && (i->tail_call || !i->falls_through)) return false;  // a terminal call that returns
            if (i->tail_call) break;
            a += i->length;
            continue;
          }
          case FlowKind::jump:
            if (i->targets.size() == 1) {
              const std::uint64_t t = info_.code_address(i->targets[0]);
              if (no_return(t, found)) {
                hit = true;
              } else if (entries_.contains(t) && t != target) {
                return false;  // a tail call that returns
              } else {
                todo.push_back(t);
              }
            }
            break;
          case FlowKind::branch:
            for (std::uint64_t t : i->targets) todo.push_back(info_.code_address(t));
            a += i->length;
            continue;
          case FlowKind::jump_indirect:
            if (i->targets.empty()) return false;  // no destinations
            for (std::uint64_t t : i->targets) todo.push_back(info_.code_address(t));
            break;
          case FlowKind::fall:
            if (!i->falls_through) return false;  // a terminal without destinations
            a += i->length;
            continue;
        }
        break;
      }
    }
    return hit;
  }

  const ProgramInfo &info_;
  const FunctionList &list_;
  std::vector<facts::Ref<FlowGraph>> flows_;  // by function, as list_
  detail::ByteReader &bytes_;
  bool x86_ = false;
  std::set<std::uint64_t> entries_, named_;
  std::unordered_map<std::uint64_t, std::size_t> by_entry_;
  std::vector<Call> calls_;
  static constexpr std::int8_t kUnknown = -1;
  std::vector<std::int8_t> indicates_;  // by Call::index
  std::unordered_map<std::uint64_t, std::vector<Call>> callers_;
};

}  // namespace

std::vector<std::uint64_t> NoReturnEvidence::compute(facts::QueryContext &ctx, const ProgramKey &key) {
  auto info = ctx.get<Program>(key);
  auto list = ctx.get<Functions>(key);
  std::vector<Location> keys;
  keys.reserve(list->functions.size());
  for (const FunctionInfo &f : list->functions) keys.push_back({key, f.flow_key()});
  detail::ByteReader bytes(ctx, *info);
  return Evidence(*info, *list, ctx.get_all<Flow>(keys), bytes).run();
}

}  // namespace revkit::analysis
