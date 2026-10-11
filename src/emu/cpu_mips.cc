// MIPS32 exceptions in the emulator's state layer: Status (IE, EXL, ERL,
// BEV, IM), Cause (IP, ExcCode, IV), EPC, ERET, the CP0 Count/Compare
// timer (IP7) and hardware interrupt lines IP2-IP7. Ghidra's MIPS spec has
// the CP0 registers in its register space (MFC0 reads them, MTC0 is a
// setCopReg CALLOTHER the emulator implements), ERET jumps to EPC without
// clearing EXL, and SYSCALL and WAIT are CALLOTHERs: those are this model.
#include "machine_impl.hh"

#include <algorithm>

namespace revkit::emu::detail {

namespace {

constexpr std::uint32_t kIE = 1u << 0, kEXL = 1u << 1, kERL = 1u << 2, kBEV = 1u << 22;
constexpr std::uint32_t kCauseIV = 1u << 23, kCauseBD = 1u << 31;

class MipsModel;

// CP0 Count/Compare as a scheduled device: Count advances every other tick.
class CountCompare final : public Peripheral {
 public:
  explicit CountCompare(MipsModel &cpu) : cpu_(cpu) {}
  std::uint64_t read(std::uint64_t, std::uint32_t) override { return 0; }
  void write(std::uint64_t, std::uint32_t, std::uint64_t) override {}
  void tick(std::uint64_t now) override;
  std::vector<std::string> outputs() const override { return {}; }
  std::string state() const override;
  void reschedule();

 private:
  MipsModel &cpu_;
};

class MipsModel final : public CpuModel {
 public:
  MipsModel(Emulator::Impl &m, const CpuSpec &spec) : CpuModel(m), spec_(spec) {
    status_ = reg("Status");
    cause_ = reg("Cause");
    epc_ = reg("EPC");
    count_ = reg("Count");
    compare_ = reg("Compare");
    error_epc_ = find("ErrorEPC");
    ebase_ = find("EBase");
  }

  std::string name() const override { return "mips"; }

  int input(const std::string &name) const override {
    std::string s = name;
    if (s.rfind("ip", 0) == 0) s = s.substr(2);
    else if (s.rfind("hw", 0) == 0 && s.size() > 2 && s.find_first_not_of("0123456789", 2) == std::string::npos)
      return std::stoi(s.substr(2)) + 2 <= 7 ? std::stoi(s.substr(2)) + 2 : -1;
    if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos) return -1;
    const int n = std::stoi(s);
    return n >= 2 && n <= 7 ? n : -1;
  }

  void reset(std::optional<std::uint64_t> entry) override {
    set(status_, kBEV | kERL);
    set(cause_, 0);
    set(count_, 0);
    set(compare_, 0);
    count_base_ = 0;
    count_at_ = machine ? machine->now() : 0;
    timer_ip_ = false;
    if (ebase_) set(*ebase_, spec_.vector_base.value_or(0x80000000));
    m.pc = (entry ? *entry : 0xbfc00000) & m.code_mask;
    if (timer_) timer_->reschedule();
  }

  void classify(Decoded &d) const override {
    if (d.length != 4 || d.bytes.size() < 4) return;
    const std::uint32_t w = m.big_endian ? (std::uint32_t{d.bytes[0]} << 24 | std::uint32_t{d.bytes[1]} << 16 |
                                            std::uint32_t{d.bytes[2]} << 8 | d.bytes[3])
                                         : (std::uint32_t{d.bytes[3]} << 24 | std::uint32_t{d.bytes[2]} << 16 |
                                            std::uint32_t{d.bytes[1]} << 8 | d.bytes[0]);
    if (w == 0x42000018) d.sys |= kSysEret;
    const std::uint32_t op = w >> 21;
    const std::uint32_t rd = (w >> 11) & 31, sel = w & 7;
    if ((op == 0x204 || op == 0x200) && sel == 0 && (rd == 9 || rd == 11 || rd == 12 || rd == 13)) {
      // MTC0/MFC0 of Count, Compare, Status or Cause.
      d.sys |= kSysReadsCount;
      d.sys_reg = static_cast<std::uint8_t>(rd | (op == 0x204 ? 0x80 : 0));
    }
  }

  void before(const Decoded &d) override {
    if (d.sys & kSysReadsCount) {
      // Count and Cause.IP as they are now.
      set(count_, count_now());
      sync_cause(false);
    }
  }

  void after(const Decoded &d, std::uint64_t at, std::uint64_t &next) override {
    if (d.sys & kSysEret) {
      std::uint32_t st = static_cast<std::uint32_t>(get(status_));
      if (st & kERL) {
        st &= ~kERL;
        if (error_epc_) next = get(*error_epc_) & m.code_mask;
      } else {
        st &= ~kEXL;
      }
      put(status_, st);
      ExceptionEvent e;
      e.kind = "return";
      e.pc = at;
      e.handler = next;
      returned = e;
    }
    if ((d.sys & kSysReadsCount) && (d.sys_reg & 0x80)) {
      const unsigned rd = d.sys_reg & 31;
      if (rd == 9) {  // Count written
        count_base_ = static_cast<std::uint32_t>(get(count_));
        count_at_ = machine->now();
        if (timer_) timer_->reschedule();
      } else if (rd == 11) {  // Compare written: clears the timer interrupt
        timer_ip_ = false;
        if (timer_) timer_->reschedule();
        sync_cause(true);
      } else if (rd == 13) {  // Cause written: software interrupts IP0/IP1, IV
        sync_cause(true);
      }
    }
  }

  bool userop(const std::string &name, UseropCall &call, const Op &) override {
    if (name == "syscall" || name == "break" || name == "trap") {
      Pending p;
      p.kind = name == "syscall" ? "syscall" : "breakpoint";
      p.number = name == "syscall" ? 8 : 9;
      p.arg = call.inputs.empty() ? 0 : call.inputs[0];
      sync = p;
      return true;
    }
    if (name == "wait") {
      machine->wait();
      call.note = "wait for interrupt";
      return true;
    }
    if (name == "getCopReg" || name == "getCopRegH") {
      call.output = 0;
      return true;
    }
    return false;
  }

  std::optional<Pending> pending() override {
    const std::uint32_t st = static_cast<std::uint32_t>(get(status_));
    if (!(st & kIE) || (st & (kEXL | kERL))) return std::nullopt;
    const std::uint32_t ip = ip_bits() & ((st >> 8) & 0xff);
    if (ip == 0) return std::nullopt;
    int n = 7;
    while (n > 0 && !((ip >> n) & 1)) --n;
    Pending p;
    p.kind = "interrupt";
    p.number = n;
    return p;
  }

  bool wake() const override { return ip_bits() != 0; }
  bool interruptible() const override {
    const std::uint32_t st = static_cast<std::uint32_t>(get(status_));
    return (st & kIE) && !(st & (kEXL | kERL)) && ((st >> 8) & 0xff) != 0;
  }

  std::uint64_t enter(const Pending &p, std::uint64_t ret) override {
    std::uint32_t st = static_cast<std::uint32_t>(get(status_));
    std::uint32_t cause = static_cast<std::uint32_t>(get(cause_));
    std::uint32_t code = 0;
    std::uint64_t epc = ret;
    if (p.kind == "syscall") code = 8, epc = ret - 4;
    else if (p.kind == "breakpoint") code = 9, epc = ret - 4;
    else if (p.kind == "reserved") code = 10;
    else if (p.kind == "address_load") code = 4;
    else if (p.kind == "address_store") code = 5;
    else if (p.kind == "bus_error") code = 7;
    cause = (cause & ~(0x7cu | kCauseBD)) | (code << 2);
    sync_ip(cause);
    put(cause_, cause);
    if (!(st & kEXL)) put(epc_, epc & 0xffffffffu);
    st |= kEXL;
    put(status_, st);
    std::uint64_t base = (st & kBEV) ? 0xbfc00200 : (ebase_ ? (get(*ebase_) & 0xfffff000u) : spec_.vector_base.value_or(0x80000000));
    std::uint64_t offset = (p.kind == "interrupt" && (cause & kCauseIV)) ? 0x200 : 0x180;
    return (base + offset) & 0xffffffffu;
  }

  bool fault_exception(const Fault &f, std::uint64_t at, Pending &p, std::uint64_t &ret) override {
    if (spec_.aborts && f.kind == StopKind::unmapped) {
      p = Pending{"bus_error", 7, "", f.address};
      ret = at;
      return true;
    }
    if (spec_.undefined && (f.kind == StopKind::decode || f.kind == StopKind::unimplemented)) {
      p = Pending{"reserved", 10, "", 0};
      ret = at;
      return true;
    }
    return false;
  }

  void tick(std::uint64_t) override {}

  void state(MachineState &out) const override {
    out.cpu = "mips";
    const std::uint32_t st = static_cast<std::uint32_t>(get(status_));
    out.mode = (st & (kEXL | kERL)) ? "exception level" : ((st >> 3) & 3) == 2 ? "user" : "kernel";
    out.registers.emplace_back("Status", st);
    out.registers.emplace_back("Cause", (get(cause_) & ~0xff00u) | (ip_bits() << 8));
    out.registers.emplace_back("EPC", get(epc_));
    out.registers.emplace_back("Count", count_now());
    out.registers.emplace_back("Compare", get(compare_));
    for (int n = 2; n <= 7; ++n)
      if ((ip_bits() >> n) & 1) out.pending.push_back("ip" + std::to_string(n));
  }

  std::vector<std::pair<PeripheralSpec, std::unique_ptr<Peripheral>>> builtin_devices() override {
    PeripheralSpec s;
    s.name = "cp0-timer";
    s.kind = "mips-count-compare";
    auto dev = std::make_unique<CountCompare>(*this);
    timer_ = dev.get();
    std::vector<std::pair<PeripheralSpec, std::unique_ptr<Peripheral>>> out;
    out.emplace_back(std::move(s), std::move(dev));
    return out;
  }

  std::vector<std::string> display_extra() const override { return {"Status", "Cause", "EPC"}; }

  std::uint32_t count_now() const {
    const std::uint64_t now = machine ? machine->now() : 0;
    return static_cast<std::uint32_t>(count_base_ + (now - count_at_) / 2);
  }
  std::uint32_t compare() const { return static_cast<std::uint32_t>(get(compare_)); }
  std::uint64_t count_at_ = 0;
  std::uint32_t count_base_ = 0;
  bool timer_ip_ = false;
  void timer_fired() { timer_ip_ = true; }

 private:
  std::uint32_t ip_bits() const {
    std::uint32_t ip = static_cast<std::uint32_t>(get(cause_) >> 8) & 3;  // software IP0/IP1
    for (int n = 2; n <= 7; ++n)
      if (static_cast<std::size_t>(n) < lines.size() && lines[static_cast<std::size_t>(n)]) ip |= 1u << n;
    if (timer_ip_) ip |= 1u << 7;
    return ip;
  }
  void sync_ip(std::uint32_t &cause) const { cause = (cause & ~0xfc00u) | ((ip_bits() & 0xfc) << 8); }
  void sync_cause(bool recorded) {
    std::uint32_t cause = static_cast<std::uint32_t>(get(cause_));
    sync_ip(cause);
    if (recorded) put(cause_, cause);
    else set(cause_, cause);
  }

  CpuSpec spec_;
  RegisterInfo status_, cause_, epc_, count_, compare_;
  std::optional<RegisterInfo> error_epc_, ebase_;
  CountCompare *timer_ = nullptr;
};

void CountCompare::reschedule() {
  const std::uint64_t now = ctx().now();
  const std::uint32_t delta = cpu_.compare() - cpu_.count_now();
  ctx().schedule(now + (delta == 0 ? (std::uint64_t{1} << 33) : std::uint64_t{delta} * 2));
}

void CountCompare::tick(std::uint64_t) {
  if (cpu_.count_now() == cpu_.compare()) cpu_.timer_fired();
  reschedule();
}

std::string CountCompare::state() const {
  return "count " + std::to_string(cpu_.count_now()) + ", compare " + std::to_string(cpu_.compare());
}

}  // namespace

std::unique_ptr<CpuModel> make_mips_model(Emulator::Impl &m, const CpuSpec &spec) {
  return std::make_unique<MipsModel>(m, spec);
}

}  // namespace revkit::emu::detail
