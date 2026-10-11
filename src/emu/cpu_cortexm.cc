// Cortex-M (ARMv6-M/v7-M) exceptions in the emulator's state layer: the
// NVIC, SysTick and the system control block (the system control space at
// 0xe000e000, a built-in device), exception entry with the eight-word
// stack frame, EXC_RETURN, MSP/PSP, PRIMASK, FAULTMASK and BASEPRI.
//
// Ghidra's Cortex spec reaches the special registers through CALLOTHERs
// (getMainStackPointer, enableIRQinterrupts, getBasePriority, ...): they
// are implemented here. MSR CONTROL's p-code doesn't set SPSEL from the
// value, so the model does it after the instruction.
#include "machine_impl.hh"

#include <algorithm>
#include <array>

namespace revkit::emu::detail {

namespace {

constexpr std::uint32_t kScsBase = 0xe000e000;

const char *exception_name(std::uint32_t e) {
  switch (e) {
    case 1: return "reset";
    case 2: return "nmi";
    case 3: return "hardfault";
    case 4: return "memmanage";
    case 5: return "busfault";
    case 6: return "usagefault";
    case 11: return "svc";
    case 12: return "debugmon";
    case 14: return "pendsv";
    case 15: return "systick";
    default: return e >= 16 ? "irq" : "exception";
  }
}

class CortexModel;

// The system control space: NVIC, SysTick, SCB.
class Scs final : public Peripheral {
 public:
  explicit Scs(CortexModel &cpu) : cpu_(cpu) {}
  std::uint64_t read(std::uint64_t offset, std::uint32_t size) override;
  void write(std::uint64_t offset, std::uint32_t size, std::uint64_t value) override;
  void tick(std::uint64_t now) override;
  std::vector<std::string> outputs() const override { return {}; }
  std::string state() const override;

  // SysTick.
  std::uint32_t csr = 0, rvr = 0;
  std::uint64_t cvr_at = 0;      // the time CVR was last set
  std::uint32_t cvr_set = 0;     // ... to this
  bool countflag = false;
  std::uint32_t cvr(std::uint64_t now) const;
  void systick_schedule(std::uint64_t now);

 private:
  CortexModel &cpu_;
};

class CortexModel final : public CpuModel {
 public:
  CortexModel(Emulator::Impl &m, const CpuSpec &spec) : CpuModel(m), spec_(spec) {
    n_ = std::clamp<std::uint32_t>(spec.nvic_irqs, 1, 496);
    const std::size_t total = 16 + n_;
    pending_.assign(total, false);
    active_.assign(total, false);
    enabled_.assign(total, false);
    prio_.assign(total, 0);
    sp_ = reg("sp");
    lr_ = reg("lr");
    for (int i = 0; i <= 3; ++i) r_[static_cast<std::size_t>(i)] = reg("r" + std::to_string(i));
    r12_ = reg("r12");
    tb_ = find("TB");
    q_ = find("Q");
    for (const char *f : {"NG", "ZR", "CY", "OV"}) flags_.push_back(reg(f));
  }

  std::string name() const override { return "cortex-m"; }

  int input(const std::string &name) const override {
    std::string s = name;
    if (s.rfind("irq", 0) == 0) s = s.substr(3);
    if (s == "nmi") return static_cast<int>(n_);  // the NMI line
    if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos) return -1;
    const unsigned long v = std::stoul(s);
    return v < n_ ? static_cast<int>(v) : -1;
  }

  void set_line(int input, bool level) override {
    CpuModel::set_line(input, level);
    if (!level || input < 0) return;
    if (static_cast<std::uint32_t>(input) == n_) pending_[2] = true;  // NMI
    else pending_[16 + static_cast<std::size_t>(input)] = true;
  }

  void reset(std::optional<std::uint64_t> entry) override {
    vtor_ = static_cast<std::uint32_t>(spec_.vector_base.value_or(0));
    std::fill(pending_.begin(), pending_.end(), false);
    std::fill(active_.begin(), active_.end(), false);
    std::fill(enabled_.begin(), enabled_.end(), false);
    std::fill(prio_.begin(), prio_.end(), 0);
    primask_ = faultmask_ = false;
    basepri_ = 0;
    control_ = 0;
    ipsr_ = 0;
    msp_ = peek32(vtor_);
    psp_ = 0;
    set(sp_, msp_);
    set(lr_, 0xffffffff);
    const std::uint64_t pc = entry ? *entry : peek32(vtor_ + 4);
    m.pc = pc & ~std::uint64_t{1} & m.code_mask;
    m.thumb = true;
    m.itstate = 0;
    if (tb_) set(*tb_, 1);
    if (scs_) {
      scs_->csr = scs_->rvr = 0;
      scs_->countflag = false;
    }
  }

  void classify(Decoded &d) const override {
    if (!d.thumb || d.length != 4 || d.bytes.size() < 4) return;
    auto half = [&](std::size_t at) -> std::uint32_t {
      return m.big_endian ? (std::uint32_t{d.bytes[at]} << 8 | d.bytes[at + 1]) : (std::uint32_t{d.bytes[at + 1]} << 8 | d.bytes[at]);
    };
    const std::uint32_t hw1 = half(0), hw2 = half(2);
    if ((hw1 & 0xfff0) == 0xf380 && hw2 == 0x8814) {  // MSR CONTROL, Rn
      d.sys |= kSysMsrControl;
      d.sys_reg = static_cast<std::uint8_t>(hw1 & 0xf);
    }
  }

  bool hooks_every_instruction() const override { return true; }

  void after(const Decoded &d, std::uint64_t at, std::uint64_t &next) override {
    if ((d.sys & kSysMsrControl) && privileged()) {
      const std::uint32_t v = static_cast<std::uint32_t>(get(m.reg("r" + std::to_string(d.sys_reg))));
      control_ = (control_ & ~1u) | (v & 1);
      if (ipsr_ == 0) select_stack((v & 2) != 0);
    }
    // EXC_RETURN loaded into the pc in handler mode.
    if (ipsr_ != 0 && (next | 1) >= 0xffffffe1 && m.pointer_size == 4) {
      const std::uint32_t exc = static_cast<std::uint32_t>(next | 1);
      next = exception_return(exc, at);
    }
  }

  bool userop(const std::string &name, UseropCall &call, const Op &op) override {
    auto arg = [&](std::size_t i) -> std::optional<std::uint64_t> {
      return i < call.inputs.size() ? std::optional<std::uint64_t>(call.inputs[i]) : std::nullopt;
    };
    if (spec_.semihosting && name == "software_bkpt" && arg(0) == 0xabu) {
      const RegisterInfo &r0 = r_[0], &r1 = r_[1];
      const std::uint32_t code = static_cast<std::uint32_t>(get(r0));
      put(r0, semihosting_call(m, code, get(r1)) & 0xffffffffu);
      call.note = "semihosting " + std::to_string(code);
      return true;
    }
    if (name == "software_interrupt") {
      Pending p;
      p.kind = "svc";
      p.number = 11;
      p.arg = arg(0).value_or(0);
      sync = p;
      return true;
    }
    if (name == "WaitForInterrupt") {
      machine->wait();
      call.note = "wait for interrupt";
      return true;
    }
    if (name == "WaitForEvent" || name == "SendEvent" || name == "HintYield" || name == "setThreadModePrivileged" ||
        name == "setStackMode")
      return true;
    if (name == "getMainStackPointer") {
      call.output = main_active() ? get(sp_) : msp_;
      return true;
    }
    if (name == "setMainStackPointer") {
      const std::uint32_t v = static_cast<std::uint32_t>(arg(0).value_or(0)) & ~3u;
      if (main_active()) put(sp_, v);
      else msp_ = v;
      return true;
    }
    if (name == "getProcessStackPointer") {
      call.output = main_active() ? psp_ : get(sp_);
      return true;
    }
    if (name == "setProcessStackPointer") {
      const std::uint32_t v = static_cast<std::uint32_t>(arg(0).value_or(0)) & ~3u;
      if (main_active()) psp_ = v;
      else put(sp_, v);
      return true;
    }
    if (name == "isIRQinterruptsEnabled") {  // MRS PRIMASK reads it
      call.output = primask_ ? 1 : 0;
      return true;
    }
    if (name == "isFIQinterruptsEnabled") {  // MRS FAULTMASK
      call.output = faultmask_ ? 1 : 0;
      return true;
    }
    if (name == "enableIRQinterrupts") {  // CPSIE i, or MSR PRIMASK with the value
      if (privileged()) primask_ = arg(0) ? (*arg(0) & 1) != 0 : false;
      return true;
    }
    if (name == "disableIRQinterrupts") {
      if (privileged()) primask_ = true;
      return true;
    }
    if (name == "enableFIQinterrupts") {
      if (privileged()) faultmask_ = arg(0) ? (*arg(0) & 1) != 0 : false;
      return true;
    }
    if (name == "disableFIQinterrupts") {
      if (privileged() && ipsr_ != 2) faultmask_ = true;
      return true;
    }
    if (name == "getBasePriority") {
      call.output = basepri_;
      return true;
    }
    if (name == "setBasePriority") {
      if (privileged()) basepri_ = static_cast<std::uint8_t>(arg(0).value_or(0) & prio_mask());
      return true;
    }
    if (name == "isCurrentModePrivileged") {
      call.output = privileged() ? 1 : 0;
      return true;
    }
    if (name == "isThreadModePrivileged") {
      call.output = (control_ & 1) == 0 ? 1 : 0;
      return true;
    }
    if (name == "isUsingMainStack") {
      call.output = (control_ & 2) == 0 ? 1 : 0;
      return true;
    }
    if (name == "isThreadMode") {
      call.output = ipsr_ == 0 ? 1 : 0;
      return true;
    }
    if (name == "getCurrentExceptionNumber") {
      call.output = ipsr_;
      return true;
    }
    if (name == "readAPSR_nzcvq") {
      if (op.in.size() >= 2 && m.spaces[static_cast<std::size_t>(op.in[1].space)].kind == SpaceKind::registers) {
        const std::uint64_t v = m.read_vn(op.in[1]).lo() | flags_word();
        m.write_vn(op.in[1], Wide::of(op.in[1].size, v));
      }
      return true;
    }
    if (name == "writeAPSR_nzcvq") {
      set_flags(static_cast<std::uint32_t>(arg(0).value_or(0)));
      return true;
    }
    return false;
  }

  std::optional<Pending> pending() override {
    const int cur = execution_priority();
    std::optional<std::uint32_t> best;
    int best_p = 0;
    for (std::uint32_t e = 2; e < pending_.size(); ++e) {
      if (!pending_[e] || active_[e]) continue;
      if (e >= 16 && !enabled_[e]) continue;
      const int p = priority(e);
      if (p >= cur) continue;
      if (!best || p < best_p) {
        best = e;
        best_p = p;
      }
    }
    if (!best) return std::nullopt;
    Pending p;
    p.kind = exception_name(*best);
    p.number = *best >= 16 ? static_cast<std::int32_t>(*best - 16) : static_cast<std::int32_t>(*best);
    p.arg = *best;
    return p;
  }

  bool interruptible() const override { return !primask_ && !faultmask_; }

  bool wake() const override {
    for (std::uint32_t e = 2; e < pending_.size(); ++e)
      if (pending_[e] && (e < 16 || enabled_[e])) return true;
    return false;
  }

  std::uint64_t enter(const Pending &p, std::uint64_t ret) override {
    std::uint32_t e = static_cast<std::uint32_t>(p.arg);
    if (p.kind == "svc") e = 11;
    if (p.kind == "hardfault") e = 3;
    // Stacking: r0-r3, r12, lr, the return address, xPSR.
    std::uint32_t sp = static_cast<std::uint32_t>(get(sp_));
    std::uint32_t xpsr = flags_word() | (1u << 24) | ipsr_ | static_cast<std::uint32_t>(m.itstate & 3) << 25 |
                         static_cast<std::uint32_t>(m.itstate >> 2) << 10;
    const std::uint32_t align = (sp >> 2) & 1;
    if (align) xpsr |= 1u << 9;
    sp = (sp - 0x20) & ~(align << 2);
    const std::uint32_t frame[8] = {
        static_cast<std::uint32_t>(get(r_[0])), static_cast<std::uint32_t>(get(r_[1])),
        static_cast<std::uint32_t>(get(r_[2])), static_cast<std::uint32_t>(get(r_[3])),
        static_cast<std::uint32_t>(get(r12_)),  static_cast<std::uint32_t>(get(lr_)),
        static_cast<std::uint32_t>(ret & ~std::uint64_t{1}), xpsr};
    for (int k = 0; k < 8; ++k) store32(sp + 4u * static_cast<std::uint32_t>(k), frame[k]);
    const bool thread = ipsr_ == 0;
    const std::uint32_t exc = !thread ? 0xfffffff1u : (control_ & 2) ? 0xfffffffdu : 0xfffffff9u;
    if (thread && (control_ & 2)) {
      psp_ = sp;
      put(sp_, msp_);
    } else {
      put(sp_, sp);
    }
    control_ &= ~2u;  // handler mode runs on MSP
    put(lr_, exc);
    ipsr_ = e;
    active_[e] = true;
    pending_[e] = false;
    m.itstate = 0;
    if (tb_) put(*tb_, 1);
    const std::uint32_t handler = load32(vtor_ + 4 * e);
    return handler & ~1u;
  }

  bool fault_exception(const Fault &f, std::uint64_t at, Pending &p, std::uint64_t &ret) override {
    const bool fault = (spec_.aborts && f.kind == StopKind::unmapped) ||
                       (spec_.undefined && (f.kind == StopKind::decode || f.kind == StopKind::unimplemented));
    if (!fault || active_[3]) return false;  // a fault in the HardFault handler: lockup, stop
    p = Pending{"hardfault", 3, "", 3};
    ret = at;
    return true;
  }

  void register_written(const RegisterInfo &) override {}

  void state(MachineState &out) const override {
    out.cpu = "cortex-m";
    out.mode = ipsr_ == 0 ? ((control_ & 1) ? "thread (unprivileged)" : "thread") : std::string("handler ") + exception_name(ipsr_);
    const bool main = main_active();
    out.registers.emplace_back("msp", main ? get(sp_) : msp_);
    out.registers.emplace_back("psp", main ? psp_ : get(sp_));
    out.registers.emplace_back("primask", primask_ ? 1 : 0);
    out.registers.emplace_back("faultmask", faultmask_ ? 1 : 0);
    out.registers.emplace_back("basepri", basepri_);
    out.registers.emplace_back("control", control_);
    out.registers.emplace_back("ipsr", ipsr_);
    out.registers.emplace_back("vtor", vtor_);
    for (std::uint32_t e = 2; e < pending_.size(); ++e) {
      if (!pending_[e] && !active_[e]) continue;
      std::string s = e >= 16 ? "irq " + std::to_string(e - 16) : exception_name(e);
      if (active_[e]) s += " active";
      if (pending_[e]) s += e >= 16 && !enabled_[e] ? " pending (disabled)" : " pending";
      out.pending.push_back(s);
    }
  }

  std::vector<std::pair<PeripheralSpec, std::unique_ptr<Peripheral>>> builtin_devices() override {
    PeripheralSpec s;
    s.name = "scs";
    s.kind = "cortex-m-scs";
    s.base = kScsBase;
    s.size = 0x1000;
    auto dev = std::make_unique<Scs>(*this);
    scs_ = dev.get();
    std::vector<std::pair<PeripheralSpec, std::unique_ptr<Peripheral>>> out;
    out.emplace_back(std::move(s), std::move(dev));
    return out;
  }

  std::vector<std::string> display_extra() const override { return {}; }

  // --- What the system control space reaches ---
  std::uint32_t n_ = 64;
  std::vector<bool> pending_, active_, enabled_;
  std::vector<std::uint8_t> prio_;
  std::uint32_t vtor_ = 0;
  std::uint32_t aircr_prigroup_ = 0;
  std::uint32_t scr_ = 0, ccr_ = 0x200;
  std::uint32_t ipsr_ = 0;
  std::uint32_t prio_mask() const {
    const std::uint32_t bits = std::clamp<std::uint32_t>(spec_.priority_bits, 2, 8);
    return (0xffu << (8 - bits)) & 0xffu;
  }
  void pend(std::uint32_t e) {
    if (e < pending_.size()) pending_[e] = true;
  }
  std::uint32_t vectpending() const {
    std::uint32_t best = 0;
    int best_p = 1 << 20;
    for (std::uint32_t e = 2; e < pending_.size(); ++e)
      if (pending_[e] && (e < 16 || enabled_[e]) && priority(e) < best_p) best = e, best_p = priority(e);
    return best;
  }
  void request_reset() { machine->request_stop("the firmware requested a system reset (AIRCR.SYSRESETREQ)"); }

 private:
  bool privileged() const { return ipsr_ != 0 || (control_ & 1) == 0; }
  bool main_active() const { return ipsr_ != 0 || (control_ & 2) == 0; }

  int priority(std::uint32_t e) const {
    if (e == 1) return -3;
    if (e == 2) return -2;
    if (e == 3) return -1;
    return prio_[e] & prio_mask();
  }

  int execution_priority() const {
    int cur = 256;
    for (std::uint32_t e = 1; e < active_.size(); ++e)
      if (active_[e]) cur = std::min(cur, priority(e));
    if (basepri_ != 0) cur = std::min<int>(cur, basepri_ & prio_mask());
    if (primask_) cur = std::min(cur, 0);
    if (faultmask_) cur = std::min(cur, -1);
    return cur;
  }

  std::uint32_t flags_word() const {
    std::uint32_t v = 0;
    for (std::size_t k = 0; k < flags_.size(); ++k)
      if (get(flags_[k]) != 0) v |= 1u << (31 - k);
    if (q_ && get(*q_) != 0) v |= 1u << 27;
    return v;
  }

  void set_flags(std::uint32_t v) {
    for (std::size_t k = 0; k < flags_.size(); ++k) put(flags_[k], (v >> (31 - k)) & 1);
    if (q_) put(*q_, (v >> 27) & 1);
  }

  void select_stack(bool psp) {
    const bool now_psp = (control_ & 2) != 0;
    if (psp == now_psp) return;
    if (psp) {
      msp_ = static_cast<std::uint32_t>(get(sp_));
      put(sp_, psp_);
      control_ |= 2;
    } else {
      psp_ = static_cast<std::uint32_t>(get(sp_));
      put(sp_, msp_);
      control_ &= ~2u;
    }
  }

  std::uint64_t exception_return(std::uint32_t exc, std::uint64_t at) {
    const std::uint32_t from = ipsr_;
    if (from < active_.size()) active_[from] = false;
    if (from == 2 || from == 3) faultmask_ = false;
    const bool use_psp = (exc & 4) != 0;
    const bool to_thread = (exc & 8) != 0;
    std::uint32_t sp = use_psp ? psp_ : static_cast<std::uint32_t>(get(sp_));
    std::uint32_t frame[8];
    for (int k = 0; k < 8; ++k) frame[k] = load32(sp + 4u * static_cast<std::uint32_t>(k));
    sp += 0x20;
    if (frame[7] & (1u << 9)) sp += 4;
    for (int k = 0; k < 4; ++k) put(r_[static_cast<std::size_t>(k)], frame[k]);
    put(r12_, frame[4]);
    put(lr_, frame[5]);
    set_flags(frame[7]);
    m.itstate = static_cast<std::uint8_t>(((frame[7] >> 25) & 3) | ((frame[7] >> 10) & 0x3f) << 2);
    ipsr_ = to_thread ? 0 : (frame[7] & 0x1ff);
    if (use_psp) {
      msp_ = static_cast<std::uint32_t>(get(sp_));
      psp_ = sp;
      put(sp_, psp_);
      control_ |= 2;
    } else {
      put(sp_, sp);
      control_ &= ~2u;
    }
    if (tb_) put(*tb_, 1);
    // A level-sensitive line still high pends its interrupt again.
    if (from >= 16 && from - 16 < lines.size() && lines[from - 16]) pending_[from] = true;
    ExceptionEvent ev;
    ev.kind = "return";
    ev.number = from >= 16 ? static_cast<std::int32_t>(from - 16) : static_cast<std::int32_t>(from);
    ev.pc = at;
    ev.handler = frame[6] & ~1u;
    ev.detail = std::string("from ") + exception_name(from) + (from >= 16 ? " " + std::to_string(from - 16) : "") +
                (to_thread ? " to thread mode" : " to handler mode");
    returned = ev;
    return (frame[6] & ~1u) | 1u;
  }

  CpuSpec spec_;
  RegisterInfo sp_, lr_, r12_;
  std::array<RegisterInfo, 4> r_;
  std::optional<RegisterInfo> tb_, q_;
  std::vector<RegisterInfo> flags_;
  std::uint32_t msp_ = 0, psp_ = 0, control_ = 0;
  bool primask_ = false, faultmask_ = false;
  std::uint8_t basepri_ = 0;
  Scs *scs_ = nullptr;

  friend class Scs;
};

std::uint32_t Scs::cvr(std::uint64_t now) const {
  if (!(csr & 1)) return cvr_set;
  const std::uint64_t period = std::uint64_t{rvr} + 1;
  const std::uint64_t elapsed = now - cvr_at;
  if (elapsed < cvr_set) return static_cast<std::uint32_t>(cvr_set - elapsed);
  if (rvr == 0) return 0;
  const std::uint64_t past = (elapsed - cvr_set) % period;  // since the last wrap
  return past == 0 ? 0 : static_cast<std::uint32_t>(period - past);
}

void Scs::systick_schedule(std::uint64_t now) {
  if (!(csr & 1) || rvr == 0) {
    ctx().cancel_schedule();
    return;
  }
  const std::uint32_t c = cvr(now);
  ctx().schedule(now + (c == 0 ? std::uint64_t{rvr} + 1 : c));
}

void Scs::tick(std::uint64_t now) {
  if (!(csr & 1)) return;
  countflag = true;
  if (csr & 2) cpu_.pend(15);
  // Reload: the counter restarts from RVR at this tick.
  cvr_at = now;
  cvr_set = rvr;
  systick_schedule(now);
}

std::uint64_t Scs::read(std::uint64_t off, std::uint32_t size) {
  const std::uint64_t now = ctx().now();
  auto bits = [&](const std::vector<bool> &v, std::uint64_t base) {
    std::uint32_t w = 0;
    const std::uint32_t first = 16 + static_cast<std::uint32_t>((off - base) / 4) * 32;
    for (std::uint32_t b = 0; b < 32; ++b)
      if (first + b < v.size() && v[first + b]) w |= 1u << b;
    return w;
  };
  std::uint32_t v = 0;
  if (off == 0x004) v = (cpu_.n_ + 31) / 32 - 1;
  else if (off == 0x010) {
    v = csr | (countflag ? 1u << 16 : 0);
    countflag = false;
  } else if (off == 0x014) v = rvr;
  else if (off == 0x018) v = cvr(now);
  else if (off == 0x01c) v = 0x40000000u;  // CALIB: no reference clock
  else if (off >= 0x100 && off < 0x140) v = bits(cpu_.enabled_, 0x100);
  else if (off >= 0x180 && off < 0x1c0) v = bits(cpu_.enabled_, 0x180);
  else if (off >= 0x200 && off < 0x240) v = bits(cpu_.pending_, 0x200);
  else if (off >= 0x280 && off < 0x2c0) v = bits(cpu_.pending_, 0x280);
  else if (off >= 0x300 && off < 0x340) v = bits(cpu_.active_, 0x300);
  else if (off >= 0x400 && off < 0x400 + cpu_.n_) {
    for (std::uint32_t b = 0; b < size && b < 4; ++b) {
      const std::uint64_t irq = off - 0x400 + b;
      if (irq < cpu_.n_) v |= std::uint32_t{cpu_.prio_[16 + irq]} << (8 * b);
    }
    return v;
  } else if (off == 0xd00) v = 0x410fc231;  // CPUID: Cortex-M3 r0p1
  else if (off == 0xd04) {
    std::uint32_t vp = cpu_.vectpending();
    v = cpu_.ipsr_ & 0x1ff;
    v |= (vp & 0x1ff) << 12;
    bool isr = false;
    for (std::size_t e = 16; e < cpu_.pending_.size(); ++e) isr = isr || cpu_.pending_[e];
    if (isr) v |= 1u << 22;
    if (cpu_.pending_[14]) v |= 1u << 28;
    if (cpu_.pending_[15]) v |= 1u << 26;
    if (cpu_.pending_[2]) v |= 1u << 31;
  } else if (off == 0xd08) v = cpu_.vtor_;
  else if (off == 0xd0c) v = 0xfa050000u | (cpu_.aircr_prigroup_ << 8);
  else if (off == 0xd10) v = cpu_.scr_;
  else if (off == 0xd14) v = cpu_.ccr_;
  else if (off >= 0xd18 && off < 0xd24) {
    for (std::uint32_t b = 0; b < size && b < 4; ++b) {
      const std::uint64_t e = 4 + (off - 0xd18) + b;
      if (e < 16) v |= std::uint32_t{cpu_.prio_[e]} << (8 * b);
    }
    return v;
  } else if (off == 0xd24) {
    for (std::uint32_t e : {4u, 5u, 6u})
      if (cpu_.enabled_[e]) v |= 1u << (12 + e);  // MEMFAULTENA.. at 16..18
  }
  // Sub-word reads of word registers.
  const unsigned shift = static_cast<unsigned>(off & 3) * 8;
  return size >= 4 ? v : (v >> shift) & ((1u << (8 * size)) - 1);
}

void Scs::write(std::uint64_t off, std::uint32_t size, std::uint64_t value) {
  const std::uint64_t now = ctx().now();
  const std::uint32_t v = static_cast<std::uint32_t>(value);
  auto set_bits = [&](std::vector<bool> &vec, std::uint64_t base, bool to) {
    const std::uint32_t first = 16 + static_cast<std::uint32_t>((off - base) / 4) * 32;
    for (std::uint32_t b = 0; b < 32; ++b)
      if ((v >> b) & 1 && first + b < vec.size()) vec[first + b] = to;
  };
  if (off == 0x010) {
    const bool was = csr & 1;
    csr = v & 7;
    if (!was && (csr & 1)) {
      cvr_at = now;  // counting starts from CVR (a reload when it is 0)
    } else if (was && !(csr & 1)) {
      cvr_set = cvr(now);
      cvr_at = now;
    }
    systick_schedule(now);
  } else if (off == 0x014) {
    rvr = v & 0xffffff;
    systick_schedule(now);
  } else if (off == 0x018) {
    cvr_set = 0;  // any write clears the counter and COUNTFLAG
    cvr_at = now;
    countflag = false;
    systick_schedule(now);
  } else if (off >= 0x100 && off < 0x140) set_bits(cpu_.enabled_, 0x100, true);
  else if (off >= 0x180 && off < 0x1c0) set_bits(cpu_.enabled_, 0x180, false);
  else if (off >= 0x200 && off < 0x240) set_bits(cpu_.pending_, 0x200, true);
  else if (off >= 0x280 && off < 0x2c0) set_bits(cpu_.pending_, 0x280, false);
  else if (off >= 0x400 && off < 0x400 + cpu_.n_) {
    for (std::uint32_t b = 0; b < size && b < 4; ++b) {
      const std::uint64_t irq = off - 0x400 + b;
      if (irq < cpu_.n_) cpu_.prio_[16 + irq] = static_cast<std::uint8_t>(v >> (8 * b));
    }
  } else if (off == 0xd04) {
    if (v & (1u << 31)) cpu_.pend(2);
    if (v & (1u << 28)) cpu_.pend(14);
    if (v & (1u << 27)) cpu_.pending_[14] = false;
    if (v & (1u << 26)) cpu_.pend(15);
    if (v & (1u << 25)) cpu_.pending_[15] = false;
  } else if (off == 0xd08) cpu_.vtor_ = v & 0xffffff80u;
  else if (off == 0xd0c) {
    if ((v >> 16) == 0x05fa) {
      cpu_.aircr_prigroup_ = (v >> 8) & 7;
      if (v & 4) cpu_.request_reset();
    }
  } else if (off == 0xd10) cpu_.scr_ = v;
  else if (off == 0xd14) cpu_.ccr_ = v;
  else if (off >= 0xd18 && off < 0xd24) {
    for (std::uint32_t b = 0; b < size && b < 4; ++b) {
      const std::uint64_t e = 4 + (off - 0xd18) + b;
      if (e < 16) cpu_.prio_[e] = static_cast<std::uint8_t>(v >> (8 * b));
    }
  } else if (off == 0xd24) {
    for (std::uint32_t e : {4u, 5u, 6u}) cpu_.enabled_[e] = (v >> (12 + e)) & 1;
  } else if (off == 0xf00) {
    const std::uint32_t irq = v & 0x1ff;
    if (irq < cpu_.n_) cpu_.pend(16 + irq);
  }
}

std::string Scs::state() const {
  std::string s = "systick ";
  s += (csr & 1) ? "on" : "off";
  if (csr & 1) s += ", reload " + std::to_string(rvr) + ", value " + std::to_string(cvr(ctx().now()));
  return s;
}

}  // namespace

std::unique_ptr<CpuModel> make_cortexm_model(Emulator::Impl &m, const CpuSpec &spec) {
  return std::make_unique<CortexModel>(m, spec);
}

}  // namespace revkit::emu::detail
