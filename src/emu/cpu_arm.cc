// ARM (A/R profile, ARMv4T onward) exceptions in the emulator's state layer.
//
// Ghidra's ARM spec keeps the flags in NG/ZR/CY/OV/Q and the instruction set
// in TB, has one sp/lr/spsr, and leaves exception entry and mode banking to
// the emulator: MRS CPSR returns only the flags, MSR CPSR writes a `cpsr`
// register nothing else reads, LDM {..pc}^ is an ordinary load, and SWI is a
// CALLOTHER. This model keeps the canonical CPSR (mode, I, F, T, the flags),
// the banked SP, LR and SPSR per mode (and FIQ's r8-r12), and fixes those
// instructions up around their p-code:
//
//   - MRS Rd, CPSR gets the whole CPSR;
//   - MSR CPSR_<fields> switches mode and masks (flags from the value);
//   - SUBS/MOVS PC, ... and LDM {.., pc}^ restore CPSR from SPSR;
//   - LDM/STM ^ without pc reach the user-mode registers;
//   - SUB PC, ... without S keeps CPSR (the spec copies SPSR there);
//   - SWI (and the undefined, prefetch and data aborts, when asked for)
//     enter their handlers; IRQ and FIQ are taken between instructions.
#include "machine_impl.hh"

#include <algorithm>
#include <array>
#include <cstring>
#include <map>

namespace revkit::emu::detail {

namespace {

constexpr std::uint32_t kUsr = 0x10, kFiq = 0x11, kIrq = 0x12, kSvc = 0x13, kMon = 0x16, kAbt = 0x17, kHyp = 0x1a,
                        kUnd = 0x1b, kSys = 0x1f;

bool valid_mode(std::uint32_t m) {
  switch (m) {
    case kUsr: case kFiq: case kIrq: case kSvc: case kMon: case kAbt: case kHyp: case kUnd: case kSys: return true;
    default: return false;
  }
}

std::uint32_t bank_of(std::uint32_t mode) { return mode == kSys ? kUsr : mode; }

const char *mode_name(std::uint32_t m) {
  switch (m) {
    case kUsr: return "usr";
    case kFiq: return "fiq";
    case kIrq: return "irq";
    case kSvc: return "svc";
    case kMon: return "mon";
    case kAbt: return "abt";
    case kHyp: return "hyp";
    case kUnd: return "und";
    case kSys: return "sys";
    default: return "?";
  }
}

class ArmModel final : public CpuModel {
 public:
  ArmModel(Emulator::Impl &m, const CpuSpec &spec) : CpuModel(m), spec_(spec) {
    vector_base_ = spec.vector_base.value_or(0);
    for (int i = 8; i <= 12; ++i) r8_12_[static_cast<std::size_t>(i - 8)] = reg("r" + std::to_string(i));
    sp_ = reg("sp");
    lr_ = reg("lr");
    cpsr_ = find("cpsr");
    spsr_ = find("spsr");
    tb_ = find("TB");
    q_ = find("Q");
    for (const char *f : {"NG", "ZR", "CY", "OV"}) flags_.push_back(reg(f));
    for (const char *g : {"GE1", "GE2", "GE3", "GE4"})
      if (auto r = find(g)) ge_.push_back(*r);
    thumb2_ = m.language.find(":v7") != std::string::npos || m.language.find(":v6") != std::string::npos ||
              m.language.find(":v8") != std::string::npos;
  }

  std::string name() const override { return "arm"; }

  int input(const std::string &name) const override {
    if (name == "irq" || name == "0") return 0;
    if (name == "fiq" || name == "1") return 1;
    return -1;
  }

  void reset(std::optional<std::uint64_t> entry) override {
    mode_ = kSvc;
    i_ = f_ = true;
    banks_.clear();
    usr_r8_12_.fill(0);
    fiq_r8_12_.fill(0);
    if (tb_) set(*tb_, 0);
    m.thumb = false;
    m.itstate = 0;
    if (spsr_) set(*spsr_, 0);
    sync_cpsr(false);
    m.pc = (entry ? *entry : vector_base_) & m.code_mask;
    if (entry && (*entry & 1) && m.has_thumb) {
      m.pc &= ~std::uint64_t{1};
      m.thumb = true;
      if (tb_) set(*tb_, 1);
      sync_cpsr(false);
    }
  }

  // --- Instructions the spec leaves to the emulator ---

  void classify(Decoded &d) const override {
    if (d.bytes.size() < 2) return;
    auto half = [&](std::size_t at) -> std::uint32_t {
      return m.big_endian ? (std::uint32_t{d.bytes[at]} << 8 | d.bytes[at + 1]) : (std::uint32_t{d.bytes[at + 1]} << 8 | d.bytes[at]);
    };
    if (d.thumb) {
      if (d.length != 4 || d.bytes.size() < 4 || !thumb2_) return;
      const std::uint32_t hw1 = half(0), hw2 = half(2);
      if (hw1 == 0xf3ef && (hw2 & 0xf000) == 0x8000 && (hw2 & 0xff) == 0) {  // MRS Rd, CPSR
        d.sys |= kSysMrsCpsr;
        d.sys_reg = static_cast<std::uint8_t>((hw2 >> 8) & 0xf);
      } else if ((hw1 & 0xfff0) == 0xf380 && (hw2 & 0xf000) == 0x8000 && (hw2 & 0xff) == 0) {  // MSR CPSR_x, Rn
        d.sys |= kSysMsrCpsr | kSysReadsCpsr;
      } else if (hw1 == 0xf3de && (hw2 & 0xff00) == 0x8f00) {  // SUBS PC, LR, #imm
        d.sys |= kSysExcReturn | kSysReadsCpsr;
      }
      return;
    }
    if (d.length != 4 || d.bytes.size() < 4) return;
    const std::uint32_t w = m.big_endian ? (std::uint32_t{d.bytes[0]} << 24 | std::uint32_t{d.bytes[1]} << 16 |
                                            std::uint32_t{d.bytes[2]} << 8 | d.bytes[3])
                                         : (std::uint32_t{d.bytes[3]} << 24 | std::uint32_t{d.bytes[2]} << 16 |
                                            std::uint32_t{d.bytes[1]} << 8 | d.bytes[0]);
    if ((w >> 28) == 0xf) return;  // the unconditional space
    if ((w & 0x0fbf0fff) == 0x010f0000) {  // MRS Rd, CPSR (R=0)
      if ((w & (1u << 22)) == 0) {
        d.sys |= kSysMrsCpsr;
        d.sys_reg = static_cast<std::uint8_t>((w >> 12) & 0xf);
      }
      return;
    }
    if ((w & 0x0fb0f000) == 0x0320f000 || (w & 0x0fb0fff0) == 0x0120f000) {  // MSR <psr>_<fields>
      if ((w & (1u << 22)) == 0) d.sys |= kSysMsrCpsr | kSysReadsCpsr;
      return;
    }
    if ((w & 0x0c000000) == 0) {  // data processing (and misc, multiplies, extra loads)
      const bool multiply_or_extra = (w & (1u << 25)) == 0 && (w & 0x90) == 0x90;
      const std::uint32_t op = (w >> 21) & 0xf;
      const bool s = (w & (1u << 20)) != 0;
      const std::uint32_t rd = (w >> 12) & 0xf;
      if (multiply_or_extra || rd != 15) return;
      if (s && (op < 8 || op > 11)) d.sys |= kSysExcReturn | kSysReadsCpsr;
      else if (!s && op == 2) d.sys |= kSysBogusCpsr | kSysReadsCpsr;  // SUB PC without S
      return;
    }
    if ((w & 0x0e000000) == 0x08000000 && (w & (1u << 22)) != 0) {  // LDM/STM with S (^)
      const bool load = (w & (1u << 20)) != 0;
      if (load && (w & 0x8000)) d.sys |= kSysExcReturn | kSysReadsCpsr;
      else d.sys |= kSysUserBank;
    }
  }

  void before(const Decoded &d) override {
    if (d.sys & (kSysReadsCpsr | kSysBogusCpsr)) sync_cpsr(false);
    if (d.sys & kSysExcReturn) ret_spsr_ = spsr_ ? static_cast<std::uint32_t>(get(*spsr_)) : 0;
    if (d.sys & kSysBogusCpsr) tb_before_ = tb_ ? get(*tb_) : 0;
    if ((d.sys & kSysUserBank) && bank_of(mode_) != kUsr) {
      // The instruction reaches the user registers: bank them in for it.
      save_bank(mode_);
      load_user(true);
    }
  }

  void after(const Decoded &d, std::uint64_t at, std::uint64_t &next) override {
    if (d.sys & kSysMrsCpsr) {
      const RegisterInfo &rd = reg_n(d.sys_reg);
      if (written(rd)) put(rd, compose());
    }
    if ((d.sys & kSysMsrCpsr) && cpsr_ && written(*cpsr_)) {
      const auto v = static_cast<std::uint32_t>(get(*cpsr_));
      apply(v, /*control=*/mode_ != kUsr, /*thumb=*/false, true);
    }
    if ((d.sys & kSysExcReturn) && written(m.pc_reg)) {
      const std::uint32_t from = mode_;
      apply(ret_spsr_, true, true, true);
      ExceptionEvent e;
      e.kind = "return";
      e.pc = at;
      e.handler = next & ~std::uint64_t{1};
      e.detail = std::string("from ") + mode_name(from) + " to " + mode_name(mode_);
      returned = e;
    }
    if ((d.sys & kSysBogusCpsr) && cpsr_ && written(*cpsr_)) {
      if (tb_ && get(*tb_) != tb_before_) put(*tb_, tb_before_);
      sync_cpsr(true);
    }
    if ((d.sys & kSysUserBank) && bank_of(mode_) != kUsr) {
      save_user();
      load_bank(mode_, true);
    }
  }

  bool userop(const std::string &name, UseropCall &call, const Op &op) override {
    (void)op;
    if (spec_.semihosting && (name == "software_interrupt" || name == "software_bkpt") && !call.inputs.empty() &&
        ((name == "software_interrupt" && call.inputs[0] == (m.thumb ? 0xabu : 0x123456u)) ||
         (name == "software_bkpt" && call.inputs[0] == 0xab))) {
      const RegisterInfo &r0 = reg_n(0), &r1 = reg_n(1);
      const std::uint32_t op = static_cast<std::uint32_t>(get(r0));
      put(r0, semihosting_call(m, op, get(r1)) & 0xffffffffu);
      call.note = "semihosting " + std::to_string(op);
      return true;
    }
    if (name == "software_interrupt") {
      Pending p;
      p.kind = "swi";
      p.arg = call.inputs.empty() ? 0 : call.inputs[0];
      p.number = static_cast<std::int32_t>(p.arg & 0xffffff);
      sync = p;
      return true;
    }
    if (name == "WaitForInterrupt" || name == "coproc_moveto_Wait_for_interrupt") {
      machine->wait();
      call.note = "wait for interrupt";
      return true;
    }
    if (name == "WaitForEvent" || name == "SendEvent" || name == "HintYield") return true;
    if (name == "enableIRQinterrupts" || name == "disableIRQinterrupts" || name == "enableFIQinterrupts" ||
        name == "disableFIQinterrupts") {
      if (mode_ == kUsr) return true;  // CPS is a no-op in user mode
      const bool on = name.rfind("enable", 0) == 0;
      if (name.find("IRQ") != std::string::npos) i_ = !on;
      else f_ = !on;
      sync_cpsr(true);
      return true;
    }
    static const std::map<std::string, std::uint32_t> kModes = {
        {"setUserMode", kUsr}, {"setFIQMode", kFiq}, {"setIRQMode", kIrq}, {"setSupervisorMode", kSvc},
        {"setMonitorMode", kMon}, {"setAbortMode", kAbt}, {"setUndefinedMode", kUnd}, {"setSystemMode", kSys}};
    if (auto it = kModes.find(name); it != kModes.end()) {
      if (mode_ != kUsr) {
        switch_mode(it->second, true);
        sync_cpsr(true);
      }
      return true;
    }
    if (name == "isCurrentModePrivileged") {
      call.output = mode_ != kUsr ? 1 : 0;
      return true;
    }
    if (name == "isIRQinterruptsEnabled") {
      call.output = i_ ? 0 : 1;
      return true;
    }
    if (name == "isFIQinterruptsEnabled") {
      call.output = f_ ? 0 : 1;
      return true;
    }
    // CP15 and other coprocessors: a register file the firmware writes and
    // reads back; the ID registers say ARM926EJ-S, the control register's V
    // bit moves the vectors high.
    if (name.rfind("coproc_moveto_", 0) == 0) {
      const std::string r = name.substr(14);
      const std::uint64_t v = call.inputs.empty() ? 0 : call.inputs[0];
      cp15_[r] = v;
      if (r == "Control" && !spec_.vector_base) vector_base_ = (v & (1u << 13)) ? 0xffff0000u : 0;
      return true;
    }
    if (name.rfind("coproc_movefrom_", 0) == 0) {
      const std::string r = name.substr(16);
      auto it = cp15_.find(r);
      std::uint64_t v = it != cp15_.end() ? it->second : 0;
      if (it == cp15_.end() && r == "Main_ID") v = 0x41069265;
      if (it == cp15_.end() && r == "Cache_Type") v = 0x1d172172;
      call.output = v;
      return true;
    }
    if (name == "coprocessor_moveto" && op.in.size() >= 7 && call.inputs.size() >= 4) {
      // Other coprocessors: a write is kept by its operands (cp, opc1, opc2,
      // CRn, CRm); a read with the same operands returns it.
      cp_other_[cp_key(call, op.in[5].offset, op.in[6].offset)] = call.inputs[3];
      return true;
    }
    if (name == "coprocessor_movefromRt" && op.in.size() >= 6 && call.inputs.size() >= 3) {
      auto it = cp_other_.find(cp_key(call, op.in[4].offset, op.in[5].offset));
      call.output = it == cp_other_.end() ? 0 : it->second;
      return true;
    }
    if (name.rfind("coprocessor_", 0) == 0) {
      if (call.output_size != 0) call.output = 0;
      return true;
    }
    return false;
  }

  // --- Interrupts and exceptions ---

  std::optional<Pending> pending() override {
    if (line(1) && !f_) return Pending{"fiq", -1, "", 0};
    if (line(0) && !i_) return Pending{"irq", -1, "", 0};
    return std::nullopt;
  }

  bool wake() const override { return line(0) || line(1); }
  bool interruptible() const override { return !i_ || !f_; }

  std::uint64_t enter(const Pending &p, std::uint64_t ret) override {
    const std::uint32_t old = compose();
    std::uint32_t mode = kSvc, offset = 0;
    std::uint64_t lr = ret;
    bool mask_f = false;
    if (p.kind == "irq") mode = kIrq, offset = 0x18, lr = ret + 4;
    else if (p.kind == "fiq") mode = kFiq, offset = 0x1c, lr = ret + 4, mask_f = true;
    else if (p.kind == "swi") mode = kSvc, offset = 0x08, lr = ret;
    else if (p.kind == "undefined") mode = kUnd, offset = 0x04, lr = ret;
    else if (p.kind == "prefetch_abort") mode = kAbt, offset = 0x0c, lr = ret + 4;
    else if (p.kind == "data_abort") mode = kAbt, offset = 0x10, lr = ret + 8;
    else if (p.kind == "reset") mode = kSvc, offset = 0, mask_f = true;
    switch_mode(mode, true);
    if (spsr_) put(*spsr_, old);
    put(lr_, lr & 0xffffffffu);
    i_ = true;
    if (mask_f) f_ = true;
    if (tb_) put(*tb_, 0);
    m.itstate = 0;
    sync_cpsr(true);
    return (vector_base_ + offset) & 0xffffffffu;
  }

  bool fault_exception(const Fault &f, std::uint64_t at, Pending &p, std::uint64_t &ret) override {
    if (spec_.aborts && f.kind == StopKind::unmapped) {
      const bool fetch = f.has_address && f.address == at;
      p = Pending{fetch ? "prefetch_abort" : "data_abort", -1, "", f.address};
      ret = at;
      return true;
    }
    if (spec_.undefined && (f.kind == StopKind::decode || f.kind == StopKind::unimplemented)) {
      p = Pending{"undefined", -1, "", 0};
      ret = at + (m.thumb ? 2 : 4);
      return true;
    }
    return false;
  }

  void register_written(const RegisterInfo &r) override {
    if (cpsr_ && r.offset == cpsr_->offset) apply(static_cast<std::uint32_t>(get(*cpsr_)), true, true, false);
  }

  void state(MachineState &out) const override {
    out.cpu = "arm";
    out.mode = mode_name(mode_);
    out.registers.emplace_back("cpsr", compose());
    out.registers.emplace_back("vector_base", vector_base_);
    auto bank = [&](std::uint32_t b) -> Bank {
      if (bank_of(mode_) == b) {
        Bank x;
        x.r13 = static_cast<std::uint32_t>(get(sp_));
        x.r14 = static_cast<std::uint32_t>(get(lr_));
        x.spsr = spsr_ ? static_cast<std::uint32_t>(get(*spsr_)) : 0;
        return x;
      }
      auto it = banks_.find(b);
      return it == banks_.end() ? Bank{} : it->second;
    };
    for (std::uint32_t b : {kUsr, kSvc, kIrq, kFiq, kAbt, kUnd}) {
      const Bank x = bank(b);
      const std::string n = b == kUsr ? "usr" : mode_name(b);
      out.registers.emplace_back("sp_" + n, x.r13);
      out.registers.emplace_back("lr_" + n, x.r14);
      if (b != kUsr) out.registers.emplace_back("spsr_" + n, x.spsr);
    }
    if (line(0)) out.pending.push_back(std::string("irq") + (i_ ? " (masked)" : ""));
    if (line(1)) out.pending.push_back(std::string("fiq") + (f_ ? " (masked)" : ""));
  }

  std::vector<std::string> display_extra() const override { return {"cpsr", "spsr"}; }

 private:
  struct Bank {
    std::uint32_t r13 = 0, r14 = 0, spsr = 0;
  };

  bool line(std::size_t n) const { return n < lines.size() && lines[n]; }

  const RegisterInfo &reg_n(unsigned n) const {
    static const char *names[] = {"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"};
    return m.reg(names[n & 15]);
  }

  // The instruction being executed wrote `r` (it ran: its condition held).
  bool written(const RegisterInfo &r) const {
    for (const UndoEntry &u : m.undo)
      if (u.space == m.register_space && u.offset < r.offset + r.size && r.offset < u.offset + u.old.size()) return true;
    return false;
  }

  std::uint32_t compose() const {
    std::uint32_t v = 0;
    for (std::size_t k = 0; k < flags_.size(); ++k)
      if (get(flags_[k]) != 0) v |= 1u << (31 - k);
    if (q_ && get(*q_) != 0) v |= 1u << 27;
    for (std::size_t k = 0; k < ge_.size(); ++k)
      if (get(ge_[k]) != 0) v |= 1u << (16 + k);
    v |= static_cast<std::uint32_t>(m.itstate & 3) << 25 | static_cast<std::uint32_t>(m.itstate >> 2) << 10;
    if (i_) v |= 1u << 7;
    if (f_) v |= 1u << 6;
    if (m.thumb) v |= 1u << 5;
    return v | mode_;
  }

  // The `cpsr` register mirrors the canonical value.
  void sync_cpsr(bool recorded) {
    if (!cpsr_) return;
    if (recorded) put(*cpsr_, compose());
    else set(*cpsr_, compose());
  }

  // A new CPSR value: flags, and (privileged) mode and masks, and (exception
  // returns) the instruction set and IT state.
  void apply(std::uint32_t v, bool control, bool thumb, bool recorded) {
    auto w = [&](const RegisterInfo &r, std::uint64_t x) { recorded ? put(r, x) : set(r, x); };
    for (std::size_t k = 0; k < flags_.size(); ++k) w(flags_[k], (v >> (31 - k)) & 1);
    if (q_) w(*q_, (v >> 27) & 1);
    for (std::size_t k = 0; k < ge_.size(); ++k) w(ge_[k], (v >> (16 + k)) & 1);
    if (control) {
      i_ = (v >> 7) & 1;
      f_ = (v >> 6) & 1;
      const std::uint32_t mode = v & 0x1f;
      if (valid_mode(mode)) switch_mode(mode, recorded);
    }
    if (thumb && m.has_thumb) {
      const bool t = (v >> 5) & 1;
      if (tb_) w(*tb_, t ? 1 : 0);
      m.thumb = t;
      m.itstate = t ? static_cast<std::uint8_t>(((v >> 25) & 3) | ((v >> 10) & 0x3f) << 2) : 0;
    }
    if (cpsr_) w(*cpsr_, compose());
  }

  void save_bank(std::uint32_t mode) {
    Bank &b = banks_[bank_of(mode)];
    b.r13 = static_cast<std::uint32_t>(get(sp_));
    b.r14 = static_cast<std::uint32_t>(get(lr_));
    if (spsr_ && bank_of(mode) != kUsr) b.spsr = static_cast<std::uint32_t>(get(*spsr_));
    if (mode == kFiq)
      for (std::size_t k = 0; k < 5; ++k) fiq_r8_12_[k] = static_cast<std::uint32_t>(get(r8_12_[k]));
  }

  void load_bank(std::uint32_t mode, bool recorded) {
    auto w = [&](const RegisterInfo &r, std::uint64_t x) { recorded ? put(r, x) : set(r, x); };
    const Bank b = banks_[bank_of(mode)];
    w(sp_, b.r13);
    w(lr_, b.r14);
    if (spsr_) w(*spsr_, bank_of(mode) == kUsr ? 0 : b.spsr);
    if (mode == kFiq)
      for (std::size_t k = 0; k < 5; ++k) w(r8_12_[k], fiq_r8_12_[k]);
  }

  // The user registers into the live ones (LDM/STM ^), keeping the mode.
  void load_user(bool recorded) {
    auto w = [&](const RegisterInfo &r, std::uint64_t x) { recorded ? put(r, x) : set(r, x); };
    const Bank b = banks_[kUsr];
    w(sp_, b.r13);
    w(lr_, b.r14);
    if (mode_ == kFiq)
      for (std::size_t k = 0; k < 5; ++k) w(r8_12_[k], usr_r8_12_[k]);
  }

  void save_user() {
    Bank &b = banks_[kUsr];
    b.r13 = static_cast<std::uint32_t>(get(sp_));
    b.r14 = static_cast<std::uint32_t>(get(lr_));
    if (mode_ == kFiq)
      for (std::size_t k = 0; k < 5; ++k) usr_r8_12_[k] = static_cast<std::uint32_t>(get(r8_12_[k]));
  }

  void switch_mode(std::uint32_t mode, bool recorded) {
    if (mode == mode_) return;
    if (bank_of(mode) != bank_of(mode_) || mode == kFiq || mode_ == kFiq) {
      save_bank(mode_);
      if (mode_ != kFiq && mode == kFiq)
        for (std::size_t k = 0; k < 5; ++k) usr_r8_12_[k] = static_cast<std::uint32_t>(get(r8_12_[k]));
      auto w = [&](const RegisterInfo &r, std::uint64_t x) { recorded ? put(r, x) : set(r, x); };
      if (mode_ == kFiq && mode != kFiq)
        for (std::size_t k = 0; k < 5; ++k) w(r8_12_[k], usr_r8_12_[k]);
      load_bank(mode, recorded);
    }
    mode_ = mode;
  }

  static std::string cp_key(const UseropCall &c, std::uint64_t crn, std::uint64_t crm) {
    return std::to_string(c.inputs[0]) + ":" + std::to_string(c.inputs[1]) + ":" + std::to_string(c.inputs[2]) + ":" +
           std::to_string(crn) + ":" + std::to_string(crm);
  }

  CpuSpec spec_;
  std::uint64_t vector_base_ = 0;
  std::uint32_t mode_ = kSvc;
  bool i_ = true, f_ = true;
  bool thumb2_ = false;
  std::map<std::uint32_t, Bank> banks_;
  std::array<std::uint32_t, 5> usr_r8_12_{}, fiq_r8_12_{};
  std::array<RegisterInfo, 5> r8_12_;
  RegisterInfo sp_, lr_;
  std::optional<RegisterInfo> cpsr_, spsr_, tb_, q_;
  std::vector<RegisterInfo> flags_, ge_;
  std::uint32_t ret_spsr_ = 0;
  std::uint64_t tb_before_ = 0;
  std::map<std::string, std::uint64_t> cp15_, cp_other_;
};

}  // namespace

std::unique_ptr<CpuModel> make_arm_model(Emulator::Impl &m, const CpuSpec &spec) {
  return std::make_unique<ArmModel>(m, spec);
}

}  // namespace revkit::emu::detail
