// Ghidra's Stack analyzer (NewFunctionStackAnalysisCmd): local variables
// for the stack locations a function's instructions refer to, found by
// tracking the stack pointer through the p-code from the entry, as
// SymbolicPropogator does.

#include "stack_locals.h"

#include <array>

#include <algorithm>
#include <cstdio>
#include <map>
#include <set>

namespace revkit::inputs {

namespace {

namespace an = analysis;

struct Value {
  enum Kind : std::uint8_t { unknown, stack, constant } kind = unknown;
  std::int64_t v = 0;
  static Value stk(std::int64_t o) { return {stack, o}; }
  static Value con(std::int64_t c) { return {constant, c}; }
  friend bool operator==(const Value &, const Value &) = default;
};

// Register and stack contents along one path.
struct State {
  std::map<std::uint64_t, std::pair<std::uint32_t, Value>> regs;  // offset -> (size, value)
  std::map<std::int64_t, std::pair<std::uint32_t, Value>> stack;  // stack offset -> (size, value)

  Value reg(std::uint64_t off, std::uint32_t size) const {
    auto it = regs.find(off);
    if (it == regs.end() || it->second.first != size) return {};
    return it->second.second;
  }
  void set_reg(std::uint64_t off, std::uint32_t size, Value v) {
    for (auto it = regs.lower_bound(off >= 64 ? off - 64 : 0); it != regs.end() && it->first < off + size;)
      it = it->first + it->second.first > off ? regs.erase(it) : std::next(it);
    if (v.kind != Value::unknown) regs[off] = {size, v};
  }
  Value mem(std::int64_t off, std::uint32_t size) const {
    auto it = stack.find(off);
    if (it == stack.end() || it->second.first != size) return {};
    return it->second.second;
  }
  void set_mem(std::int64_t off, std::uint32_t size, Value v) {
    for (auto it = stack.lower_bound(off - 64); it != stack.end() && it->first < off + static_cast<std::int64_t>(size);)
      it = it->first + static_cast<std::int64_t>(it->second.first) > off ? stack.erase(it) : std::next(it);
    if (v.kind != Value::unknown) stack[off] = {size, v};
  }
};

std::int64_t sext(std::uint64_t v, std::uint32_t size) {
  if (size >= 8 || size == 0) return static_cast<std::int64_t>(v);
  const unsigned bits = size * 8;
  std::uint64_t m = std::uint64_t{1} << (bits - 1);
  v &= (std::uint64_t{1} << bits) - 1;
  return static_cast<std::int64_t>((v ^ m) - m);
}

struct Arch {
  lift::Varnode sp;
  std::set<std::uint64_t> preserved;  // register offsets a call leaves alone
  int extrapop = 0;
  std::int64_t param_offset = 0;  // stack offsets at or above it are parameters
  bool x86 = false;
};

std::optional<Arch> arch_for(lift::Lifter &lifter, const std::string &language_id, bool pe) {
  Arch a;
  std::vector<std::string> keep;
  std::string sp;
  if (language_id.starts_with("x86:LE:64")) {
    sp = "RSP";
    a.extrapop = 8;
    a.param_offset = 8;
    a.x86 = true;
    keep = {"RBX", "RBP", "R12", "R13", "R14", "R15"};
    if (pe) keep.insert(keep.end(), {"RDI", "RSI"});
  } else if (language_id.starts_with("x86:LE:32")) {
    sp = "ESP";
    a.extrapop = 4;
    a.param_offset = 4;
    a.x86 = true;
    keep = {"EBX", "EBP", "ESI", "EDI"};
  } else if (language_id.starts_with("AARCH64:")) {
    sp = "sp";
    keep = {"x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30"};
  } else if (language_id.starts_with("ARM:")) {
    // AAPCS: r4-r11 survive calls; parameters past r0-r3 are at sp.
    sp = "sp";
    keep = {"r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"};
  } else if (language_id.starts_with("RISCV:")) {
    sp = "sp";
    keep = {"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "gp", "tp"};
  } else {
    return std::nullopt;
  }
  auto v = lifter.register_varnode(sp);
  if (!v) return std::nullopt;
  a.sp = *v;
  a.preserved.insert(v->offset);
  for (const std::string &n : keep)
    if (auto r = lifter.register_varnode(n)) a.preserved.insert(r->offset);
  return a;
}

struct Ref {
  std::int64_t offset;
  int size;  // 0: an address computed, not accessed
};

class Walker {
 public:
  Walker(lift::Lifter &lifter, const loader::Image &image, const Arch &arch, const an::FunctionInfo &f,
         const an::FlowGraph &g)
      : lifter_(lifter), image_(image), arch_(arch), f_(f), g_(g) {}

  std::vector<Ref> run() {
    State entry;
    entry.set_reg(arch_.sp.offset, arch_.sp.size, Value::stk(0));
    std::vector<std::pair<std::uint64_t, State>> work{{f_.entry.offset, entry}};
    std::set<std::uint64_t> visited;
    int steps = 0;
    while (!work.empty() && steps < 200000) {
      auto [at, state] = std::move(work.back());
      work.pop_back();
      // Straight-line run from `at` until flow leaves or meets visited code.
      for (;;) {
        if (++steps > 200000) break;
        if (!in_body(at) || !visited.insert(at).second) break;
        const an::FlowInsn *fi = g_.at(at);
        if (fi == nullptr) break;
        // From the image's bytes, without the instruction's context
        // commits (SLEIGH globalset): what was decoded before, here or by
        // the lifter's other users, doesn't change how this decodes.
        std::array<std::byte, 16> buf{};
        const std::size_t n = image_.memory.read(at, buf);
        if (n == 0) break;
        std::optional<lift::Instruction> insn = lifter_.lift(at, std::span<const std::byte>(buf.data(), n));
        if (!insn) break;
        step(*insn, state);
        bool fall = fi->falls_through;
        switch (fi->kind) {
          case an::FlowKind::branch:
            for (std::uint64_t t : fi->targets) work.emplace_back(t, state);
            break;
          case an::FlowKind::jump:
          case an::FlowKind::jump_indirect:
            for (auto it = fi->targets.rbegin(); it != fi->targets.rend(); ++it) work.emplace_back(*it, state);
            fall = false;
            break;
          case an::FlowKind::ret: fall = false; break;
          default: break;
        }
        if (!fall) break;
        at += fi->length;
      }
    }
    return std::move(refs_);
  }

 private:
  bool in_body(std::uint64_t a) const { return f_.body.contains(facts::Address{f_.entry.space, a}); }

  Value read(const lift::Varnode &v, const State &s, const std::map<std::uint64_t, Value> &uniq) const {
    if (v.space == "const") return Value::con(sext(v.offset, v.size));
    if (v.space == "register") return s.reg(v.offset, v.size);
    if (v.space == "unique") {
      auto it = uniq.find(v.offset);
      return it == uniq.end() ? Value{} : it->second;
    }
    return {};
  }

  // NewFunctionStackAnalysisCmd.getStackOpIndex: the reference counts only
  // if an operand's registers (stack-valued ones) and scalars add up to it.
  bool operand_refers(const lift::Instruction &insn, const State &before, std::int64_t offset) const {
    if (insn.tokens.empty()) return false;
    int current = -2;
    std::int64_t sum = 0;
    for (const lift::Token &t : insn.tokens) {
      if (t.operand < 0) continue;
      if (t.operand != current) {
        current = t.operand;
        sum = 0;
      }
      if (t.kind == lift::Token::Kind::reg) {
        Value v = before.reg(t.reg.offset, t.reg.size);
        if (v.kind != Value::stack) continue;
        sum += v.v;
      } else if (t.kind == lift::Token::Kind::scalar) {
        sum += static_cast<std::int64_t>(t.value);
      } else {
        continue;
      }
      if (sum == offset || (sum & 0xffff) == offset) return true;
    }
    return false;
  }

  void step(const lift::Instruction &insn, State &s) {
    std::map<std::uint64_t, Value> uniq;
    auto write = [&](const lift::Varnode &out, Value v) {
      if (out.space == "register") s.set_reg(out.offset, out.size, v);
      else if (out.space == "unique") uniq[out.offset] = v;
    };
    std::vector<Ref> found;
    for (const lift::PcodeOp &op : insn.pcode) {
      const auto &in = op.inputs;
      auto val = [&](std::size_t i) { return i < in.size() ? read(in[i], s, uniq) : Value{}; };
      if (op.opcode == "COPY" && op.output) {
        write(*op.output, val(0));
      } else if ((op.opcode == "INT_ADD" || op.opcode == "INT_SUB") && op.output) {
        Value a = val(0), b = val(1);
        const bool add = op.opcode == "INT_ADD";
        Value r;
        if (a.kind == Value::stack && b.kind == Value::constant) r = Value::stk(add ? a.v + b.v : a.v - b.v);
        else if (add && a.kind == Value::constant && b.kind == Value::stack) r = Value::stk(a.v + b.v);
        else if (a.kind == Value::constant && b.kind == Value::constant) r = Value::con(add ? a.v + b.v : a.v - b.v);
        write(*op.output, r);
      } else if (op.opcode == "INT_AND" && op.output) {
        // Aligning the stack pointer keeps it symbolic (AND RSP,-0x10).
        Value a = val(0), b = val(1);
        Value r;
        if (a.kind == Value::stack && b.kind == Value::constant) r = Value::stk(a.v & b.v);
        else if (a.kind == Value::constant && b.kind == Value::constant) r = Value::con(a.v & b.v);
        write(*op.output, r);
      } else if ((op.opcode == "INT_ZEXT" || op.opcode == "INT_SEXT") && op.output) {
        Value a = val(0);
        write(*op.output, a.kind == Value::constant ? a : Value{});
      } else if (op.opcode == "LOAD" && op.output && in.size() >= 2) {
        Value addr = val(1);
        Value out;
        if (addr.kind == Value::stack) {
          found.push_back({addr.v, static_cast<int>(op.output->size)});
          out = s.mem(addr.v, op.output->size);
        }
        write(*op.output, out);
      } else if (op.opcode == "STORE" && in.size() >= 3) {
        Value addr = val(1);
        if (addr.kind == Value::stack) {
          found.push_back({addr.v, static_cast<int>(in[2].size)});
          s.set_mem(addr.v, in[2].size, val(2));
        }
      } else if (op.opcode == "CALL" || op.opcode == "CALLIND") {
        // The callee returns, popping what the convention says (the return
        // address on x86), and may change any register it needn't keep.
        Value sp = s.reg(arch_.sp.offset, arch_.sp.size);
        std::map<std::uint64_t, std::pair<std::uint32_t, Value>> kept;
        for (const auto &[off, sv] : s.regs)
          if (arch_.preserved.contains(off)) kept.emplace(off, sv);
        s.regs = std::move(kept);
        if (sp.kind == Value::stack) {
          s.set_reg(arch_.sp.offset, arch_.sp.size, Value::stk(sp.v + arch_.extrapop));
          for (auto it = s.stack.begin(); it != s.stack.end();) it = it->first < sp.v ? s.stack.erase(it) : std::next(it);
        }
      } else if (op.output) {
        write(*op.output, Value{});
      }
    }
    // Loads and stores through a stack-pointer operand; on x86, an address
    // an LEA computes into a register.
    // Operand registers count with their values once the instruction has
    // run: PUSH RSP stores where RSP then points; POP RBP loads through
    // RSP, not through RBP's earlier stack value.
    for (const Ref &r : found)
      if (operand_refers(insn, s, r.offset)) refs_.push_back(r);
    if (arch_.x86 && insn.mnemonic == "LEA") {
      for (const lift::PcodeOp &op : insn.pcode) {
        if (!op.output || op.output->space != "register") continue;
        Value v = s.reg(op.output->offset, op.output->size);
        if (v.kind == Value::stack && operand_refers(insn, s, v.v)) refs_.push_back({v.v, 0});
      }
    }
  }

  lift::Lifter &lifter_;
  const loader::Image &image_;
  const Arch &arch_;
  const an::FunctionInfo &f_;
  const an::FlowGraph &g_;
  std::vector<Ref> refs_;
};

struct Var {
  std::int64_t offset;
  int size;
  int type_size;  // 0: Ghidra's DEFAULT type
};

// NewFunctionStackAnalysisCmd.accumulateVariable.
void accumulate(std::vector<Var> &vars, std::int64_t offset, int ref_size) {
  const int size = ref_size > 0 ? ref_size : 1;
  std::vector<std::size_t> hits;
  for (std::size_t i = 0; i < vars.size(); ++i)
    if (vars[i].offset < offset + size && offset < vars[i].offset + vars[i].size) hits.push_back(i);
  if (!hits.empty()) {
    std::sort(hits.begin(), hits.end(), [&](std::size_t a, std::size_t b) { return vars[a].offset < vars[b].offset; });
    if (vars[hits.front()].size == size) return;  // the first one has this size: taken as a match
    std::int64_t lo = std::min(offset, vars[hits.front()].offset);
    std::int64_t hi = offset + size - 1;
    for (std::size_t i : hits) hi = std::max(hi, vars[i].offset + vars[i].size - 1);
    std::sort(hits.begin(), hits.end(), std::greater<>());
    for (std::size_t i : hits) vars.erase(vars.begin() + static_cast<std::ptrdiff_t>(i));
    const int span = static_cast<int>(hi - lo + 1);
    vars.push_back({lo, span, span});
    return;
  }
  vars.push_back({offset, size, ref_size});
}

std::string local_name(std::int64_t offset) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "local_%llx", static_cast<unsigned long long>(-offset));
  return buf;
}

lift::DecompElement undefined_type(int type_size) {
  if (type_size == 0) return {"typeref", {{"id", std::uint64_t{0xc000000000000000ULL}}, {"name", std::string("undefined")}}, {}};
  if (type_size <= 8)
    return {"typeref",
            {{"id", std::uint64_t{0xc0000000000000b3ULL + static_cast<std::uint64_t>(type_size)}},
             {"name", "undefined" + std::to_string(type_size)}},
            {}};
  return {"type",
          {{"arraysize", std::int64_t{type_size}},
           {"metatype", std::string("array")},
           {"name", std::string()},
           {"size", std::int64_t{type_size}}},
          {{"typeref", {{"id", std::uint64_t{0xc0000000000000b4ULL}}, {"name", std::string("undefined1")}}, {}}}};
}

}  // namespace

std::vector<lift::LocalFacts> stack_locals(lift::Lifter &lifter, const loader::Image &image,
                                           const std::string &language_id, bool pe,
                                           const analysis::FunctionInfo &f, const analysis::FlowGraph &g,
                                           const std::vector<lift::LocalFacts> &protected_locals) {
  std::vector<lift::LocalFacts> out;
  static thread_local std::map<std::string, std::optional<Arch>> arches;
  auto it = arches.find(language_id + (pe ? "/pe" : ""));
  if (it == arches.end()) it = arches.emplace(language_id + (pe ? "/pe" : ""), arch_for(lifter, language_id, pe)).first;
  if (!it->second) return out;
  const Arch &arch = *it->second;
  std::vector<Ref> refs = Walker(lifter, image, arch, f, g).run();
  std::vector<Var> vars;
  for (const Ref &r : refs) {
    // Locals only (Ghidra's default: no stack parameters), within bounds.
    if (r.offset >= arch.param_offset || r.offset < -(64 * 1024)) continue;
    accumulate(vars, r.offset, r.size);
  }
  std::sort(vars.begin(), vars.end(), [](const Var &a, const Var &b) { return a.offset > b.offset; });
  for (const Var &v : vars) {
    // A variable that would overlap one the debug info gave is left out.
    bool conflict = false;
    for (const lift::LocalFacts &p : protected_locals)
      for (const lift::StorageVarnode &s : p.storage)
        if (s.space == "stack") {
          auto so = sext(s.offset, arch.sp.size);
          if (so < v.offset + v.size && v.offset < so + s.size) conflict = true;
        }
    if (conflict) continue;
    lift::LocalFacts l;
    l.name = local_name(v.offset);
    l.undefined = true;
    // Offsets in the stack space are as wide as the stack pointer.
    std::uint64_t off = static_cast<std::uint64_t>(v.offset);
    if (arch.sp.size < 8) off &= (std::uint64_t{1} << (8 * arch.sp.size)) - 1;
    l.storage.push_back({"stack", off, v.size});
    l.type = undefined_type(v.type_size);
    l.type_size = v.size;
    out.push_back(std::move(l));
  }
  return out;
}

}  // namespace revkit::inputs
