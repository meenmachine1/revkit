// Built-in peripherals (docs/firmware-emulation.md): timers (generic and
// SP804), UARTs (generic and PL011), interrupt controllers (generic, PL190
// VIC, GIC-lite), the PL031 RTC, auto-acknowledging registers and plain
// register blocks. Each is a memory-mapped register block with read and
// write callbacks, the machine's clock and interrupt lines.
#include "machine_impl.hh"

#include <algorithm>
#include <deque>
#include <sstream>

namespace revkit::emu::detail {

namespace {

std::string hexs(std::uint64_t v) {
  std::ostringstream o;
  o << "0x" << std::hex << v;
  return o.str();
}

[[noreturn]] void bad(const PeripheralSpec &s, const std::string &what) {
  throw MachineError("peripheral " + s.name + " (" + s.kind + "): " + what);
}

std::uint32_t sub(std::uint32_t v, std::uint64_t off, std::uint32_t size) {
  if (size >= 4) return v;
  const unsigned shift = static_cast<unsigned>(off & 3) * 8;
  return (v >> shift) & ((1u << (8 * size)) - 1);
}

// Primecell identification registers (0xfe0..0xffc).
bool primecell_id(std::uint64_t off, const std::uint8_t (&periph)[4], std::uint32_t &v) {
  static const std::uint8_t cell[4] = {0x0d, 0xf0, 0x05, 0xb1};
  if (off >= 0xfe0 && off < 0xff0 && (off & 3) == 0) {
    v = periph[(off - 0xfe0) / 4];
    return true;
  }
  if (off >= 0xff0 && off < 0x1000 && (off & 3) == 0) {
    v = cell[(off - 0xff0) / 4];
    return true;
  }
  return false;
}

// Ticks of the machine clock for `counts` counts of a clock at `clock_hz`
// divided by `divider` (rounded up), and the reverse (rounded down).
std::uint64_t ticks_for(std::uint64_t counts, std::uint64_t machine_hz, std::uint64_t clock_hz, std::uint64_t divider) {
  const unsigned __int128 n = static_cast<unsigned __int128>(counts) * machine_hz * divider;
  const unsigned __int128 t = (n + clock_hz - 1) / clock_hz;
  return t > ~std::uint64_t{0} ? ~std::uint64_t{0} : static_cast<std::uint64_t>(t);
}

std::uint64_t counts_in(std::uint64_t ticks, std::uint64_t machine_hz, std::uint64_t clock_hz, std::uint64_t divider) {
  const unsigned __int128 n = static_cast<unsigned __int128>(ticks) * clock_hz;
  const unsigned __int128 d = static_cast<unsigned __int128>(machine_hz) * divider;
  const unsigned __int128 c = n / d;
  return c > ~std::uint64_t{0} ? ~std::uint64_t{0} : static_cast<std::uint64_t>(c);
}

// One counter: counts down to zero (or up to a top) at a clock rate,
// reloading when periodic, with a raw interrupt flag.
struct Counter {
  bool running = false;
  bool periodic = true;
  bool oneshot = false;
  bool up = false;
  std::uint64_t top = 0xffffffff;   // up: the value that fires; down: the free-running wrap
  std::uint64_t load = 0;
  std::uint64_t start = 0;          // tick the count started at
  std::uint64_t from = 0;           // ... from this value
  std::uint64_t clock_hz = 1000000, divider = 1;
  bool raw = false;

  std::uint64_t value(std::uint64_t now, std::uint64_t hz) const {
    if (!running) return from;
    const std::uint64_t c = counts_in(now - start, hz, clock_hz, divider);
    if (up) return std::min(from + c, top);
    return c >= from ? 0 : from - c;
  }
  // When the count next fires (reaches 0, or the top).
  std::optional<std::uint64_t> fires(std::uint64_t hz) const {
    if (!running) return std::nullopt;
    const std::uint64_t remaining = up ? (top > from ? top - from : 0) : from;
    return start + std::max<std::uint64_t>(ticks_for(remaining, hz, clock_hz, divider), 1);
  }
  void restart(std::uint64_t now, std::uint64_t v) {
    start = now;
    from = v;
  }
  // It fired at `at`: reload, wrap or stop.
  void fired(std::uint64_t at) {
    raw = true;
    if (oneshot) {
      running = false;
      from = up ? top : 0;
      return;
    }
    if (up) restart(at, load);
    else if (periodic) restart(at, std::max<std::uint64_t>(load, 1));
    else restart(at, top);  // free running: wraps
  }
};

// --- The generic timer -----------------------------------------------------

class GenericTimer final : public Peripheral {
 public:
  explicit GenericTimer(const PeripheralSpec &s) {
    const json::Value &c = s.config;
    channels_ = static_cast<unsigned>(num_or(c, "channels", 1));
    stride_ = num_or(c, "stride", 0x20);
    if (channels_ == 0 || channels_ > 64) bad(s, "channels must be 1 to 64");
    auto reg = [&](const char *k, std::int64_t def) -> std::int64_t {
      const json::Value *r = c.find("registers");
      if (r == nullptr || r->find(k) == nullptr) return def;
      const json::Value *v = r->find(k);
      if (v->is_null()) return -1;
      return static_cast<std::int64_t>(num(*v, std::string("registers.") + k));
    };
    load_ = reg("load", 0x0);
    value_ = reg("value", 0x4);
    control_ = reg("control", 0x8);
    status_ = reg("status", 0xc);
    clear_ = reg("clear", 0x10);
    auto bit = [&](const char *k, int def) -> int {
      const json::Value *b = c.find("bits");
      if (b == nullptr || b->find(k) == nullptr) return def;
      const json::Value *v = b->find(k);
      if (v->is_null()) return -1;
      return static_cast<int>(num(*v, std::string("bits.") + k));
    };
    enable_bit_ = bit("enable", 0);
    periodic_bit_ = bit("periodic", 1);
    irq_enable_bit_ = bit("irq_enable", 2);
    pending_bit_ = bit("pending", 0);
    status_in_control_ = bool_or(c, "status_in_control", false);
    clear_mode_ = str_or(c, "clear_mode", "write");
    if (clear_mode_ != "write" && clear_mode_ != "w1c" && clear_mode_ != "read")
      bad(s, "clear_mode is \"write\" (any write to clear), \"w1c\" (write 1 to the pending bit) or \"read\"");
    up_ = str_or(c, "count", "down") == "up";
    top_ = num_or(c, "top", up_ ? 0x10000 : 0xffffffff);
    clock_hz_ = num_or(c, "clock_hz", 0);
    divider_ = std::max<std::uint64_t>(num_or(c, "divider", 1), 1);
    period_ = opt_num(c, "period");
    autostart_ = bool_or(c, "autostart", false);
    default_periodic_ = bool_or(c, "periodic", true);
    load_mask_ = num_or(c, "load_mask", 0xffffffff);
    ch_.resize(channels_);
  }

  std::vector<std::string> outputs() const override {
    std::vector<std::string> out{"irq"};
    if (channels_ > 1)
      for (unsigned i = 0; i < channels_; ++i) out.push_back("irq" + std::to_string(i));
    return out;
  }

  void reset() override {
    for (Ch &ch : ch_) {
      ch = Ch{};
      ch.c.up = up_;
      ch.c.top = top_;
      ch.c.periodic = default_periodic_;
      ch.c.clock_hz = clock_hz_ ? clock_hz_ : ctx().hz();
      ch.c.divider = divider_;
      if (period_) {
        // A fixed period in machine ticks.
        ch.c.clock_hz = ctx().hz();
        ch.c.divider = 1;
        ch.c.load = *period_;
      }
      if (autostart_) {
        ch.c.running = true;
        ch.control = enable_bit_ >= 0 ? 1u << enable_bit_ : 0;
        if (irq_enable_bit_ >= 0) ch.control |= 1u << irq_enable_bit_;
        ch.c.restart(0, up_ ? ch.c.load : std::max<std::uint64_t>(ch.c.load, 1));
      }
    }
    reschedule();
  }

  std::uint64_t read(std::uint64_t off, std::uint32_t size) override {
    const unsigned i = static_cast<unsigned>(off / stride_);
    if (i >= channels_) return 0;
    Ch &ch = ch_[i];
    const std::int64_t r = static_cast<std::int64_t>(off % stride_) & ~3;
    const std::uint64_t now = ctx().now();
    std::uint32_t v = 0;
    if (r == load_) v = static_cast<std::uint32_t>(ch.c.load);
    else if (r == value_) v = static_cast<std::uint32_t>(ch.c.value(now, ctx().hz()));
    else if (r == control_) {
      v = ch.control;
      if (status_in_control_ && pending_bit_ >= 0) v = (v & ~(1u << pending_bit_)) | (ch.c.raw ? 1u << pending_bit_ : 0);
    } else if (r == status_) {
      v = ch.c.raw && pending_bit_ >= 0 ? 1u << pending_bit_ : 0;
      if (clear_mode_ == "read" && ch.c.raw) {
        ch.c.raw = false;
        update_irq();
      }
    }
    return sub(v, off, size);
  }

  void write(std::uint64_t off, std::uint32_t size, std::uint64_t value) override {
    (void)size;
    const unsigned i = static_cast<unsigned>(off / stride_);
    if (i >= channels_) return;
    Ch &ch = ch_[i];
    const std::int64_t r = static_cast<std::int64_t>(off % stride_) & ~3;
    const std::uint64_t now = ctx().now();
    const std::uint32_t v = static_cast<std::uint32_t>(value);
    if (r == load_) {
      ch.c.load = period_ ? *period_ : (v & load_mask_);
      if (ch.c.running && !up_) ch.c.restart(now, std::max<std::uint64_t>(ch.c.load, 1));
      if (!ch.c.running) ch.c.from = up_ ? ch.c.load : ch.c.load;
    } else if (r == control_) {
      if (status_in_control_ && pending_bit_ >= 0 && clear_mode_ == "w1c" && (v >> pending_bit_) & 1) ch.c.raw = false;
      ch.control = v;
      if (status_in_control_ && pending_bit_ >= 0) ch.control &= ~(1u << pending_bit_);
      const bool en = enable_bit_ < 0 || ((v >> enable_bit_) & 1);
      if (periodic_bit_ >= 0) ch.c.periodic = (v >> periodic_bit_) & 1;
      if (en && !ch.c.running) {
        ch.c.running = true;
        ch.c.restart(now, up_ ? ch.c.load : std::max<std::uint64_t>(ch.c.load, 1));
      } else if (!en && ch.c.running) {
        ch.c.from = ch.c.value(now, ctx().hz());
        ch.c.running = false;
      }
    } else if (r == clear_) {
      if (clear_mode_ == "write" || (clear_mode_ == "w1c" && pending_bit_ >= 0 && ((v >> pending_bit_) & 1))) ch.c.raw = false;
    } else if (r == status_ && clear_mode_ == "w1c" && pending_bit_ >= 0 && ((v >> pending_bit_) & 1)) {
      ch.c.raw = false;
    } else if (r == value_ && ch.c.running) {
      ch.c.restart(now, v);
    }
    update_irq();
    reschedule();
  }

  void tick(std::uint64_t at) override {
    const std::uint64_t hz = ctx().hz();
    for (Ch &ch : ch_)
      if (auto f = ch.c.fires(hz); f && *f <= at) ch.c.fired(*f);
    update_irq();
    reschedule();
  }

  std::string state() const override {
    std::string s;
    for (unsigned i = 0; i < channels_; ++i) {
      const Ch &ch = ch_[i];
      if (!s.empty()) s += "; ";
      if (channels_ > 1) s += std::to_string(i) + ": ";
      s += ch.c.running ? "running" : "stopped";
      s += ", value " + std::to_string(ch.c.value(ctx().now(), ctx().hz()));
      if (ch.c.raw) s += ", interrupt";
    }
    return s;
  }

 private:
  struct Ch {
    Counter c;
    std::uint32_t control = 0;
  };

  bool irq_enabled(const Ch &ch) const { return irq_enable_bit_ < 0 || ((ch.control >> irq_enable_bit_) & 1); }

  void update_irq() {
    bool any = false;
    for (unsigned i = 0; i < channels_; ++i) {
      const bool on = ch_[i].c.raw && irq_enabled(ch_[i]);
      any = any || on;
      if (channels_ > 1) ctx().set_irq(1 + i, on);
    }
    ctx().set_irq(0, any);
  }

  void reschedule() {
    std::optional<std::uint64_t> best;
    for (const Ch &ch : ch_)
      if (auto f = ch.c.fires(ctx().hz())) best = best ? std::min(*best, *f) : *f;
    if (best) ctx().schedule(*best);
    else ctx().cancel_schedule();
  }

  unsigned channels_ = 1;
  std::uint64_t stride_ = 0x20;
  std::int64_t load_, value_, control_, status_, clear_;
  int enable_bit_, periodic_bit_, irq_enable_bit_, pending_bit_;
  bool status_in_control_ = false;
  std::string clear_mode_;
  bool up_ = false;
  std::uint64_t top_ = 0xffffffff, clock_hz_ = 0, divider_ = 1, load_mask_ = 0xffffffff;
  std::optional<std::uint64_t> period_;
  bool autostart_ = false, default_periodic_ = true;
  std::vector<Ch> ch_;
};

// --- ARM SP804 dual timer ----------------------------------------------------

class Sp804 final : public Peripheral {
 public:
  explicit Sp804(const PeripheralSpec &s) {
    clock_hz_[0] = clock_hz_[1] = num_or(s.config, "clock_hz", 1000000);
    if (auto c = opt_num(s.config, "clock_hz2")) clock_hz_[1] = *c;
  }
  std::vector<std::string> outputs() const override { return {"irq", "irq1", "irq2"}; }

  void reset() override {
    for (int i = 0; i < 2; ++i) {
      t_[i] = T{};
      t_[i].c.from = 0xffffffff;
      t_[i].c.load = 0;
      t_[i].c.clock_hz = clock_hz_[i];
      t_[i].control = 0x20;  // IntEnable set at reset
    }
    reschedule();
  }

  std::uint64_t read(std::uint64_t off, std::uint32_t size) override {
    static const std::uint8_t id[4] = {0x04, 0x18, 0x14, 0x00};
    std::uint32_t v = 0;
    if (primecell_id(off, id, v)) return v;
    if (off >= 0x40) return 0;
    T &t = t_[off >= 0x20 ? 1 : 0];
    switch (off & 0x1c) {
      case 0x00: v = static_cast<std::uint32_t>(t.c.load); break;
      case 0x04: v = static_cast<std::uint32_t>(t.c.value(ctx().now(), ctx().hz())); break;
      case 0x08: v = t.control; break;
      case 0x10: v = t.c.raw ? 1 : 0; break;
      case 0x14: v = t.c.raw && (t.control & 0x20) ? 1 : 0; break;
      case 0x18: v = static_cast<std::uint32_t>(t.c.load); break;
      default: break;
    }
    return sub(v, off, size);
  }

  void write(std::uint64_t off, std::uint32_t, std::uint64_t value) override {
    if (off >= 0x40) return;
    T &t = t_[off >= 0x20 ? 1 : 0];
    const std::uint32_t v = static_cast<std::uint32_t>(value);
    const std::uint64_t now = ctx().now();
    switch (off & 0x1c) {
      case 0x00:  // Load: the counter reloads now
        t.c.load = mask(t, v);
        t.c.restart(now, std::max<std::uint64_t>(t.c.load, 1));
        if (!t.c.running) t.c.from = t.c.load;
        break;
      case 0x18:  // BGLoad: used at the next reload
        t.c.load = mask(t, v);
        break;
      case 0x08: {
        const bool was = t.c.running;
        const std::uint64_t cur = t.c.value(now, ctx().hz());
        t.control = v & 0xef;
        t.c.periodic = (v & 0x40) != 0;
        t.c.oneshot = (v & 0x01) != 0;
        t.c.top = (v & 0x02) ? 0xffffffff : 0xffff;
        static const std::uint64_t pres[4] = {1, 16, 256, 256};
        t.c.divider = pres[(v >> 2) & 3];
        t.c.running = (v & 0x80) != 0;
        if (t.c.running) t.c.restart(now, was ? cur : t.c.from);
        else t.c.from = cur;
        break;
      }
      case 0x0c: t.c.raw = false; break;  // IntClr
      default: break;
    }
    update_irq();
    reschedule();
  }

  void tick(std::uint64_t at) override {
    for (T &t : t_)
      if (auto f = t.c.fires(ctx().hz()); f && *f <= at) t.c.fired(*f);
    update_irq();
    reschedule();
  }

  std::string state() const override {
    std::string s;
    for (int i = 0; i < 2; ++i) {
      const T &t = t_[i];
      s += (i ? "; " : "") + std::string("timer") + std::to_string(i + 1) + (t.c.running ? " running " : " stopped ") +
           std::to_string(t.c.value(ctx().now(), ctx().hz())) + (t.c.raw ? " (interrupt)" : "");
    }
    return s;
  }

 private:
  struct T {
    Counter c;
    std::uint32_t control = 0x20;
  };
  static std::uint64_t mask(const T &t, std::uint32_t v) { return (t.control & 2) ? v : (v & 0xffff); }
  void update_irq() {
    const bool a = t_[0].c.raw && (t_[0].control & 0x20), b = t_[1].c.raw && (t_[1].control & 0x20);
    ctx().set_irq(1, a);
    ctx().set_irq(2, b);
    ctx().set_irq(0, a || b);
  }
  void reschedule() {
    std::optional<std::uint64_t> best;
    for (const T &t : t_)
      if (auto f = t.c.fires(ctx().hz())) best = best ? std::min(*best, *f) : *f;
    if (best) ctx().schedule(*best);
    else ctx().cancel_schedule();
  }
  std::uint64_t clock_hz_[2];
  T t_[2];
};

// --- UARTs ---------------------------------------------------------------------

class Pl011 final : public Peripheral {
 public:
  explicit Pl011(const PeripheralSpec &) {}
  bool is_uart() const override { return true; }
  void reset() override {
    rx_.clear();
    imsc_ = ris_ = 0;
    cr_ = 0x300;
    lcrh_ = ibrd_ = fbrd_ = ifls_ = 0;
  }
  void input(std::string_view bytes) override {
    for (char c : bytes) rx_.push_back(static_cast<std::uint8_t>(c));
    if (!rx_.empty()) ris_ |= 0x50;  // RX and receive timeout
    update();
  }
  std::uint64_t read(std::uint64_t off, std::uint32_t size) override {
    static const std::uint8_t id[4] = {0x11, 0x10, 0x14, 0x00};
    std::uint32_t v = 0;
    if (primecell_id(off, id, v)) return v;
    switch (off & ~std::uint64_t{3}) {
      case 0x00:
        if (!rx_.empty()) {
          v = rx_.front();
          rx_.pop_front();
        }
        if (rx_.empty()) ris_ &= ~0x50u;
        update();
        break;
      case 0x18: v = 0x80 | (rx_.empty() ? 0x10 : 0); break;  // TXFE, RXFE
      case 0x24: v = ibrd_; break;
      case 0x28: v = fbrd_; break;
      case 0x2c: v = lcrh_; break;
      case 0x30: v = cr_; break;
      case 0x34: v = ifls_; break;
      case 0x38: v = imsc_; break;
      case 0x3c: v = ris_; break;
      case 0x40: v = ris_ & imsc_; break;
      default: break;
    }
    return sub(v, off, size);
  }
  void write(std::uint64_t off, std::uint32_t, std::uint64_t value) override {
    const std::uint32_t v = static_cast<std::uint32_t>(value);
    switch (off & ~std::uint64_t{3}) {
      case 0x00: {
        const char c = static_cast<char>(v & 0xff);
        ctx().output(std::string_view(&c, 1));
        ris_ |= 0x20;  // the transmitter is empty again at once
        break;
      }
      case 0x24: ibrd_ = v; break;
      case 0x28: fbrd_ = v; break;
      case 0x2c: lcrh_ = v; break;
      case 0x30: cr_ = v; break;
      case 0x34: ifls_ = v; break;
      case 0x38: imsc_ = v & 0x7ff; break;
      case 0x44: ris_ &= ~v; break;
      default: break;
    }
    update();
  }
  std::string state() const override {
    return std::to_string(rx_.size()) + " bytes waiting" + ((ris_ & imsc_) ? ", interrupt" : "");
  }

 private:
  void update() { ctx().set_irq(0, (ris_ & imsc_) != 0); }
  std::deque<std::uint8_t> rx_;
  std::uint32_t imsc_ = 0, ris_ = 0, cr_ = 0x300, lcrh_ = 0, ibrd_ = 0, fbrd_ = 0, ifls_ = 0;
};

class GenericUart final : public Peripheral {
 public:
  explicit GenericUart(const PeripheralSpec &s) {
    const json::Value &c = s.config;
    data_ = num_or(c, "data", 0x0);
    status_ = num_or(c, "status", 0x4);
    tx_ready_ = num_or(c, "tx_ready", 0x20);
    rx_ready_ = num_or(c, "rx_ready", 0x01);
    rx_empty_ = num_or(c, "rx_empty", 0);
    irq_rx_ = bool_or(c, "irq_on_rx", true);
    status_const_ = num_or(c, "status_value", 0);
  }
  bool is_uart() const override { return true; }
  void input(std::string_view bytes) override {
    for (char c : bytes) rx_.push_back(static_cast<std::uint8_t>(c));
    update();
  }
  std::uint64_t read(std::uint64_t off, std::uint32_t size) override {
    std::uint64_t v = 0;
    if (off == data_) {
      if (!rx_.empty()) {
        v = rx_.front();
        rx_.pop_front();
      }
      update();
      return v;
    }
    if ((off & ~std::uint64_t{3}) == (status_ & ~std::uint64_t{3})) {
      std::uint32_t s = static_cast<std::uint32_t>(status_const_ | tx_ready_);
      s |= rx_.empty() ? static_cast<std::uint32_t>(rx_empty_) : static_cast<std::uint32_t>(rx_ready_);
      return sub(s, off - (status_ & ~std::uint64_t{3}) + (status_ & 3), size);
    }
    return 0;
  }
  void write(std::uint64_t off, std::uint32_t, std::uint64_t value) override {
    if (off == data_) {
      const char c = static_cast<char>(value & 0xff);
      ctx().output(std::string_view(&c, 1));
    }
  }
  std::string state() const override { return std::to_string(rx_.size()) + " bytes waiting"; }

 private:
  void update() { ctx().set_irq(0, irq_rx_ && !rx_.empty()); }
  std::uint64_t data_, status_, tx_ready_, rx_ready_, rx_empty_, status_const_;
  bool irq_rx_ = true;
  std::deque<std::uint8_t> rx_;
};

// --- Interrupt controllers -------------------------------------------------------

class Pl190 final : public Peripheral {
 public:
  explicit Pl190(const PeripheralSpec &) {}
  bool has_inputs() const override { return true; }
  std::vector<std::string> outputs() const override { return {"irq", "fiq"}; }
  void reset() override {
    lines_ = soft_ = select_ = enable_ = 0;
    defvect_ = 0;
    std::fill(std::begin(vect_), std::end(vect_), 0);
    std::fill(std::begin(cntl_), std::end(cntl_), 0);
    update();
  }
  void irq_in(unsigned line, bool level) override {
    if (line >= 32) return;
    if (level) lines_ |= 1u << line;
    else lines_ &= ~(1u << line);
    update();
  }
  std::uint64_t read(std::uint64_t off, std::uint32_t size) override {
    static const std::uint8_t id[4] = {0x90, 0x11, 0x04, 0x00};
    std::uint32_t v = 0;
    if (primecell_id(off, id, v)) return v;
    const std::uint32_t raw = lines_ | soft_;
    switch (off & ~std::uint64_t{3}) {
      case 0x000: v = raw & enable_ & ~select_; break;
      case 0x004: v = raw & enable_ & select_; break;
      case 0x008: v = raw; break;
      case 0x00c: v = select_; break;
      case 0x010: v = enable_; break;
      case 0x018: v = soft_; break;
      case 0x030: {
        v = defvect_;
        const std::uint32_t irq = raw & enable_ & ~select_;
        for (int k = 0; k < 16; ++k)
          if ((cntl_[k] & 0x20) && (irq >> (cntl_[k] & 0x1f)) & 1) {
            v = vect_[k];
            break;
          }
        break;
      }
      case 0x034: v = defvect_; break;
      default:
        if (off >= 0x100 && off < 0x140) v = vect_[(off - 0x100) / 4];
        else if (off >= 0x200 && off < 0x240) v = cntl_[(off - 0x200) / 4];
        break;
    }
    return sub(v, off, size);
  }
  void write(std::uint64_t off, std::uint32_t, std::uint64_t value) override {
    const std::uint32_t v = static_cast<std::uint32_t>(value);
    switch (off & ~std::uint64_t{3}) {
      case 0x00c: select_ = v; break;
      case 0x010: enable_ |= v; break;
      case 0x014: enable_ &= ~v; break;
      case 0x018: soft_ |= v; break;
      case 0x01c: soft_ &= ~v; break;
      case 0x034: defvect_ = v; break;
      default:
        if (off >= 0x100 && off < 0x140) vect_[(off - 0x100) / 4] = v;
        else if (off >= 0x200 && off < 0x240) cntl_[(off - 0x200) / 4] = v & 0x3f;
        break;
    }
    update();
  }
  std::string state() const override {
    const std::uint32_t raw = lines_ | soft_;
    return "raw " + hexs(raw) + ", enabled " + hexs(enable_) + ", irq " + hexs(raw & enable_ & ~select_);
  }

 private:
  void update() {
    const std::uint32_t raw = lines_ | soft_;
    ctx().set_irq(0, (raw & enable_ & ~select_) != 0);
    ctx().set_irq(1, (raw & enable_ & select_) != 0);
  }
  std::uint32_t lines_ = 0, soft_ = 0, select_ = 0, enable_ = 0, defvect_ = 0;
  std::uint32_t vect_[16] = {}, cntl_[16] = {};
};

class GenericIntc final : public Peripheral {
 public:
  explicit GenericIntc(const PeripheralSpec &s) {
    const json::Value &c = s.config;
    lines_n_ = static_cast<unsigned>(num_or(c, "lines", 32));
    if (lines_n_ == 0 || lines_n_ > 1024) bad(s, "lines must be 1 to 1024");
    base_number_ = static_cast<unsigned>(num_or(c, "number_base", 0));
    msb_ = str_or(c, "bit_order", "lsb") == "msb";
    latched_ = bool_or(c, "latched", true);
    ack_on_read_ = bool_or(c, "ack_on_read", true);
    none_value_ = num_or(c, "none_value", 0);
    enabled_default_ = bool_or(c, "enabled_at_reset", false);
    const json::Value *r = c.find("registers");
    if (r == nullptr || !r->is_object()) bad(s, "needs registers: {status, raw, enable, mask, enable_set, enable_clear, clear, pending_number, global_disable}");
    auto list = [&](const char *k) {
      std::vector<std::uint64_t> out;
      const json::Value *v = r->find(k);
      if (v == nullptr || v->is_null()) return out;
      if (v->is_array())
        for (const json::Value &x : v->items()) out.push_back(num(x, std::string("registers.") + k));
      else out.push_back(num(*v, std::string("registers.") + k));
      return out;
    };
    status_ = list("status");
    raw_ = list("raw");
    enable_ = list("enable");
    mask_ = list("mask");
    enable_set_ = list("enable_set");
    enable_clear_ = list("enable_clear");
    clear_ = list("clear");
    auto one = [&](const char *k) -> std::optional<std::uint64_t> {
      auto l = list(k);
      if (l.empty()) return std::nullopt;
      return l[0];
    };
    number_ = one("pending_number");
    global_ = one("global_disable");
    global_bit_ = static_cast<unsigned>(num_or(c, "global_disable_bit", 0));
  }
  bool has_inputs() const override { return true; }
  void reset() override {
    level_.assign(lines_n_ + base_number_, false);
    pending_.assign(lines_n_ + base_number_, false);
    enabled_.assign(lines_n_ + base_number_, enabled_default_);
    global_disable_ = false;
    update();
  }
  // Wired input N is line number N (in the controller's own numbering).
  void irq_in(unsigned line, bool level) override {
    if (line >= level_.size()) return;
    if (level && !level_[line]) pending_[line] = true;
    level_[line] = level;
    if (!latched_) pending_[line] = level;
    update();
  }
  std::uint64_t read(std::uint64_t off, std::uint32_t size) override {
    const std::uint64_t w = off & ~std::uint64_t{3};
    std::uint32_t v = 0;
    if (number_ && w == *number_) {
      v = static_cast<std::uint32_t>(none_value_);
      for (unsigned n = base_number_; n < pending_.size(); ++n)
        if (active(n)) {
          v = n;
          if (ack_on_read_) pending_[n] = latched_ ? false : level_[n];
          break;
        }
      update();
      return sub(v, off, size);
    }
    if (global_ && w == *global_) v = global_disable_ ? 1u << global_bit_ : 0;
    else if (word_of(status_, w, v, [&](unsigned n) { return active(n); })) {
    } else if (word_of(raw_, w, v, [&](unsigned n) { return pending_[n]; })) {
    } else if (word_of(enable_, w, v, [&](unsigned n) { return bool(enabled_[n]); })) {
    } else if (word_of(enable_set_, w, v, [&](unsigned n) { return bool(enabled_[n]); })) {
    } else if (word_of(mask_, w, v, [&](unsigned n) { return !enabled_[n]; })) {
    }
    return sub(v, off, size);
  }
  void write(std::uint64_t off, std::uint32_t, std::uint64_t value) override {
    const std::uint64_t w = off & ~std::uint64_t{3};
    const std::uint32_t v = static_cast<std::uint32_t>(value);
    if (global_ && w == *global_) global_disable_ = (v >> global_bit_) & 1;
    apply(enable_, w, v, [&](unsigned n, bool b) { enabled_[n] = b; });
    apply(mask_, w, v, [&](unsigned n, bool b) { enabled_[n] = !b; });
    apply(enable_set_, w, v, [&](unsigned n, bool b) { if (b) enabled_[n] = true; });
    apply(enable_clear_, w, v, [&](unsigned n, bool b) { if (b) enabled_[n] = false; });
    apply(clear_, w, v, [&](unsigned n, bool b) { if (b) pending_[n] = latched_ ? false : level_[n]; });
    update();
  }
  std::string state() const override {
    std::string p;
    for (unsigned n = base_number_; n < pending_.size(); ++n)
      if (pending_[n]) p += (p.empty() ? "" : " ") + std::to_string(n) + (enabled_[n] ? "" : "(masked)");
    return "pending: " + (p.empty() ? std::string("none") : p) + (global_disable_ ? ", disabled" : "");
  }

 private:
  bool active(unsigned n) const { return pending_[n] && enabled_[n] && !global_disable_; }
  // Line of bit b of the k-th register in a list.
  unsigned line_of(std::size_t k, unsigned b) const {
    return base_number_ + static_cast<unsigned>(k) * 32 + (msb_ ? 31 - b : b);
  }
  template <class F>
  bool word_of(const std::vector<std::uint64_t> &regs, std::uint64_t w, std::uint32_t &v, F &&bit) const {
    for (std::size_t k = 0; k < regs.size(); ++k) {
      if (regs[k] != w) continue;
      v = 0;
      for (unsigned b = 0; b < 32; ++b) {
        const unsigned n = line_of(k, b);
        if (n < pending_.size() && bit(n)) v |= 1u << b;
      }
      return true;
    }
    return false;
  }
  template <class F>
  void apply(const std::vector<std::uint64_t> &regs, std::uint64_t w, std::uint32_t v, F &&set) {
    for (std::size_t k = 0; k < regs.size(); ++k) {
      if (regs[k] != w) continue;
      for (unsigned b = 0; b < 32; ++b) {
        const unsigned n = line_of(k, b);
        if (n < pending_.size()) set(n, ((v >> b) & 1) != 0);
      }
    }
  }
  void update() {
    bool any = false;
    for (unsigned n = base_number_; n < pending_.size() && !any; ++n) any = active(n);
    ctx().set_irq(0, any);
  }
  unsigned lines_n_ = 32, base_number_ = 0, global_bit_ = 0;
  bool msb_ = false, latched_ = true, ack_on_read_ = true, enabled_default_ = false, global_disable_ = false;
  std::uint64_t none_value_ = 0;
  std::vector<std::uint64_t> status_, raw_, enable_, mask_, enable_set_, enable_clear_, clear_;
  std::optional<std::uint64_t> number_, global_;
  std::vector<bool> level_, pending_, enabled_;
};

// A GIC-lite: one distributor and one CPU interface, no security, no
// targets beyond CPU 0. Lines are level-sensitive; SGIs/PPIs are not modelled.
class GicLite final : public Peripheral {
 public:
  explicit GicLite(const PeripheralSpec &s) {
    n_ = static_cast<unsigned>(num_or(s.config, "lines", 96));
    if (n_ < 32 || n_ > 1020) bad(s, "lines must be 32 to 1020");
    cpu_ = num_or(s.config, "cpu_interface", 0x1000);
    first_spi_ = static_cast<unsigned>(num_or(s.config, "first_spi", 32));
  }
  bool has_inputs() const override { return true; }
  void reset() override {
    level_.assign(n_, false);
    soft_.assign(n_, false);
    active_.assign(n_, false);
    enabled_.assign(n_, false);
    prio_.assign(n_, 0);
    dctlr_ = cctlr_ = 0;
    pmr_ = 0;
    running_.clear();
    update();
  }
  // Wired input N is SPI N: interrupt ID first_spi + N.
  void irq_in(unsigned line, bool level) override {
    const unsigned id = first_spi_ + line;
    if (id >= n_) return;
    level_[id] = level;
    update();
  }
  std::uint64_t read(std::uint64_t off, std::uint32_t size) override {
    std::uint32_t v = 0;
    const std::uint64_t w = off & ~std::uint64_t{3};
    auto bits = [&](const std::vector<bool> &a, std::uint64_t base, auto pred) {
      const unsigned first = static_cast<unsigned>((w - base) / 4) * 32;
      std::uint32_t x = 0;
      for (unsigned b = 0; b < 32; ++b)
        if (first + b < n_ && pred(a, first + b)) x |= 1u << b;
      return x;
    };
    auto plain = [](const std::vector<bool> &a, unsigned i) { return bool(a[i]); };
    if (off >= cpu_) {
      const std::uint64_t c = w - cpu_;
      if (c == 0x00) v = cctlr_;
      else if (c == 0x04) v = pmr_;
      else if (c == 0x0c) {  // IAR: acknowledge the highest priority pending interrupt
        const int id = best();
        if (id < 0) v = 1023;
        else {
          v = static_cast<std::uint32_t>(id);
          active_[static_cast<std::size_t>(id)] = true;
          soft_[static_cast<std::size_t>(id)] = false;
          running_.push_back(static_cast<unsigned>(id));
        }
        update();
      } else if (c == 0x14) v = running_.empty() ? 0xff : prio_[running_.back()];
      else if (c == 0x18) {
        const int id = best();
        v = id < 0 ? 1023 : static_cast<std::uint32_t>(id);
      }
      return sub(v, off, size);
    }
    if (w == 0x000) v = dctlr_;
    else if (w == 0x004) v = (n_ / 32) - 1;
    else if (w >= 0x100 && w < 0x180) v = bits(enabled_, 0x100, plain);
    else if (w >= 0x180 && w < 0x200) v = bits(enabled_, 0x180, plain);
    else if (w >= 0x200 && w < 0x300) {
      const std::uint64_t base = w < 0x280 ? 0x200 : 0x280;
      const unsigned first = static_cast<unsigned>((w - base) / 4) * 32;
      for (unsigned b = 0; b < 32; ++b)
        if (first + b < n_ && pending(first + b)) v |= 1u << b;
    } else if (w >= 0x300 && w < 0x400) v = bits(active_, w < 0x380 ? 0x300 : 0x380, plain);
    else if (off >= 0x400 && off < 0x400 + n_) {
      for (std::uint32_t b = 0; b < size && b < 4; ++b)
        if (off - 0x400 + b < n_) v |= std::uint32_t{prio_[off - 0x400 + b]} << (8 * b);
      return v;
    } else if (off >= 0x800 && off < 0x800 + n_) {
      for (std::uint32_t b = 0; b < size && b < 4; ++b) v |= 1u << (8 * b);  // CPU 0
      return v;
    }
    return sub(v, off, size);
  }
  void write(std::uint64_t off, std::uint32_t size, std::uint64_t value) override {
    const std::uint32_t v = static_cast<std::uint32_t>(value);
    const std::uint64_t w = off & ~std::uint64_t{3};
    auto each = [&](std::uint64_t base, auto f) {
      const unsigned first = static_cast<unsigned>((w - base) / 4) * 32;
      for (unsigned b = 0; b < 32; ++b)
        if ((v >> b) & 1 && first + b < n_) f(first + b);
    };
    if (off >= cpu_) {
      const std::uint64_t c = w - cpu_;
      if (c == 0x00) cctlr_ = v & 1;
      else if (c == 0x04) pmr_ = v & 0xff;
      else if (c == 0x10) {  // EOIR
        const unsigned id = v & 0x3ff;
        if (id < n_) active_[id] = false;
        auto it = std::find(running_.begin(), running_.end(), id);
        if (it != running_.end()) running_.erase(it);
      }
      update();
      return;
    }
    if (w == 0x000) dctlr_ = v & 1;
    else if (w >= 0x100 && w < 0x180) each(0x100, [&](unsigned i) { enabled_[i] = true; });
    else if (w >= 0x180 && w < 0x200) each(0x180, [&](unsigned i) { enabled_[i] = false; });
    else if (w >= 0x200 && w < 0x280) each(0x200, [&](unsigned i) { soft_[i] = true; });
    else if (w >= 0x280 && w < 0x300) each(0x280, [&](unsigned i) { soft_[i] = false; });
    else if (w >= 0x300 && w < 0x380) each(0x300, [&](unsigned i) { active_[i] = true; });
    else if (w >= 0x380 && w < 0x400) each(0x380, [&](unsigned i) { active_[i] = false; });
    else if (w == 0xf00) {  // SGIR: software interrupt to ourselves
      const unsigned id = v & 0xf;
      soft_[id] = true;
    } else if (off >= 0x400 && off < 0x400 + n_) {
      for (std::uint32_t b = 0; b < size && b < 4; ++b)
        if (off - 0x400 + b < n_) prio_[off - 0x400 + b] = static_cast<std::uint8_t>(v >> (8 * b));
    }
    update();
  }
  std::string state() const override {
    std::string p;
    for (unsigned i = 0; i < n_; ++i)
      if (pending(i)) p += (p.empty() ? "" : " ") + std::to_string(i) + (enabled_[i] ? "" : "(disabled)");
    return "pending: " + (p.empty() ? std::string("none") : p);
  }

 private:
  bool pending(unsigned i) const { return (level_[i] || soft_[i]) && !active_[i]; }
  int best() const {
    if (!(dctlr_ & 1) || !(cctlr_ & 1)) return -1;
    const unsigned running = running_.empty() ? 0x100 : prio_[running_.back()];
    int best = -1;
    for (unsigned i = 0; i < n_; ++i) {
      if (!pending(i) || !enabled_[i]) continue;
      if (prio_[i] >= pmr_ || prio_[i] >= running) continue;
      if (best < 0 || prio_[i] < prio_[static_cast<std::size_t>(best)]) best = static_cast<int>(i);
    }
    return best;
  }
  void update() { ctx().set_irq(0, best() >= 0); }
  unsigned n_ = 96, first_spi_ = 32;
  std::uint64_t cpu_ = 0x1000;
  std::vector<bool> level_, soft_, active_, enabled_;
  std::vector<std::uint8_t> prio_;
  std::vector<unsigned> running_;
  std::uint32_t dctlr_ = 0, cctlr_ = 0, pmr_ = 0;
};

// --- RTC (PL031) -----------------------------------------------------------------

class Pl031 final : public Peripheral {
 public:
  explicit Pl031(const PeripheralSpec &s) { start_ = num_or(s.config, "start", 0); }
  void reset() override {
    load_ = start_;
    at_ = ctx().now();
    mr_ = 0;
    imsc_ = 0;
    ris_ = false;
    reschedule();
  }
  std::uint64_t read(std::uint64_t off, std::uint32_t size) override {
    static const std::uint8_t id[4] = {0x31, 0x10, 0x04, 0x00};
    std::uint32_t v = 0;
    if (primecell_id(off, id, v)) return v;
    switch (off & ~std::uint64_t{3}) {
      case 0x00: v = seconds(ctx().now()); break;
      case 0x04: v = mr_; break;
      case 0x08: v = static_cast<std::uint32_t>(load_); break;
      case 0x0c: v = 1; break;
      case 0x10: v = imsc_; break;
      case 0x14: v = ris_ ? 1 : 0; break;
      case 0x18: v = ris_ && imsc_ ? 1 : 0; break;
      default: break;
    }
    return sub(v, off, size);
  }
  void write(std::uint64_t off, std::uint32_t, std::uint64_t value) override {
    const std::uint32_t v = static_cast<std::uint32_t>(value);
    switch (off & ~std::uint64_t{3}) {
      case 0x04: mr_ = v; break;
      case 0x08:
        load_ = v;
        at_ = ctx().now();
        break;
      case 0x10: imsc_ = v & 1; break;
      case 0x1c:
        if (v & 1) ris_ = false;
        break;
      default: break;
    }
    ctx().set_irq(0, ris_ && imsc_);
    reschedule();
  }
  void tick(std::uint64_t at) override {
    if (seconds(at) == mr_) ris_ = true;
    ctx().set_irq(0, ris_ && imsc_);
    reschedule();
  }
  std::string state() const override { return std::to_string(seconds(ctx().now())) + " s"; }

 private:
  std::uint32_t seconds(std::uint64_t now) const {
    return static_cast<std::uint32_t>(load_ + (now - at_) / std::max<std::uint64_t>(ctx().hz(), 1));
  }
  void reschedule() {
    const std::uint64_t now = ctx().now(), hz = std::max<std::uint64_t>(ctx().hz(), 1);
    const std::uint32_t s = seconds(now);
    if (mr_ <= s) {
      ctx().cancel_schedule();
      return;
    }
    ctx().schedule(at_ + (std::uint64_t{mr_} - load_) * hz);
  }
  std::uint64_t start_ = 0, load_ = 0, at_ = 0;
  std::uint32_t mr_ = 0, imsc_ = 0;
  bool ris_ = false;
};

// --- Auto-acknowledging registers ------------------------------------------------

// Registers that read back a ready bit: (stored & ~mask) | (value & mask),
// toggling it every read, or counting up by a step every read.
class AutoAck final : public Peripheral {
 public:
  struct Rule {
    std::uint64_t offset = 0;
    std::uint32_t size = 4;
    std::uint64_t mask = 0xffffffff, value = 0xffffffff;
    std::string mode = "fixed";
    std::uint64_t step = 1;
    std::uint64_t stored = 0, count = 0;
    bool toggle = false;
    std::uint64_t reads = 0;
  };
  explicit AutoAck(std::vector<Rule> rules) : rules_(std::move(rules)) {}
  void reset() override {
    for (Rule &r : rules_) {
      r.count = 0;
      r.toggle = false;
      r.reads = 0;
    }
  }
  std::uint64_t read(std::uint64_t off, std::uint32_t size) override {
    for (Rule &r : rules_) {
      if (off < r.offset || off >= r.offset + r.size) continue;
      ++r.reads;
      std::uint64_t v = 0;
      if (r.mode == "toggle") {
        r.toggle = !r.toggle;
        v = (r.stored & ~r.mask) | ((r.toggle ? r.value : ~r.value) & r.mask);
      } else if (r.mode == "increment") {
        r.count += r.step;
        v = (r.stored & ~r.mask) | (r.count & r.mask);
      } else {
        v = (r.stored & ~r.mask) | (r.value & r.mask);
      }
      const unsigned shift = static_cast<unsigned>(off - r.offset) * 8;
      const std::uint64_t m = size >= 8 ? ~std::uint64_t{0} : (std::uint64_t{1} << (8 * size)) - 1;
      return (v >> shift) & m;
    }
    return 0;
  }
  void write(std::uint64_t off, std::uint32_t size, std::uint64_t value) override {
    for (Rule &r : rules_) {
      if (off < r.offset || off >= r.offset + r.size) continue;
      const unsigned shift = static_cast<unsigned>(off - r.offset) * 8;
      const std::uint64_t m = (size >= 8 ? ~std::uint64_t{0} : (std::uint64_t{1} << (8 * size)) - 1) << shift;
      r.stored = (r.stored & ~m) | ((value << shift) & m);
    }
  }
  std::vector<std::string> outputs() const override { return {}; }
  std::string state() const override {
    std::uint64_t n = 0;
    for (const Rule &r : rules_) n += r.reads;
    return std::to_string(rules_.size()) + " registers, " + std::to_string(n) + " reads answered";
  }

 private:
  std::vector<Rule> rules_;
};

class RegisterBlock final : public Peripheral {
 public:
  explicit RegisterBlock(const PeripheralSpec &s) : bytes_(s.size, 0) {
    if (s.size > (1u << 24)) bad(s, "a register block is at most 16 MiB");
    if (const json::Value *init = s.config.find("values"); init && init->is_object())
      for (const auto &[k, v] : init->members()) {
        const std::uint64_t off = num(json::Value::string(k), "values offset");
        const std::uint64_t x = num(v, "values." + k);
        for (unsigned b = 0; b < 4 && off + b < bytes_.size(); ++b) bytes_[off + b] = static_cast<std::uint8_t>(x >> (8 * b));
      }
    initial_ = bytes_;
  }
  void reset() override { bytes_ = initial_; }
  std::uint64_t read(std::uint64_t off, std::uint32_t size) override {
    std::uint64_t v = 0;
    for (std::uint32_t b = 0; b < size && off + b < bytes_.size(); ++b) v |= std::uint64_t{bytes_[off + b]} << (8 * b);
    return v;
  }
  void write(std::uint64_t off, std::uint32_t size, std::uint64_t value) override {
    for (std::uint32_t b = 0; b < size && off + b < bytes_.size(); ++b) bytes_[off + b] = static_cast<std::uint8_t>(value >> (8 * b));
  }
  std::vector<std::string> outputs() const override { return {}; }

 private:
  std::vector<std::uint8_t> bytes_, initial_;
};

}  // namespace

std::unique_ptr<Peripheral> make_builtin_peripheral(const PeripheralSpec &s, std::string &error) {
  (void)error;
  const std::string &k = s.kind;
  if (k == "timer") return std::make_unique<GenericTimer>(s);
  if (k == "sp804") return std::make_unique<Sp804>(s);
  if (k == "pl011") return std::make_unique<Pl011>(s);
  if (k == "uart") {
    if (str_or(s.config, "model", "") == "pl011") return std::make_unique<Pl011>(s);
    return std::make_unique<GenericUart>(s);
  }
  if (k == "vic" || k == "pl190") return std::make_unique<Pl190>(s);
  if (k == "intc") {
    const std::string model = str_or(s.config, "model", "");
    if (model == "vic" || model == "pl190") return std::make_unique<Pl190>(s);
    if (model == "gic") return std::make_unique<GicLite>(s);
    return std::make_unique<GenericIntc>(s);
  }
  if (k == "gic" || k == "gic-lite") return std::make_unique<GicLite>(s);
  if (k == "rtc" || k == "pl031") return std::make_unique<Pl031>(s);
  if (k == "ram-device" || k == "registers") return std::make_unique<RegisterBlock>(s);
  if (k == "auto-ack") {
    const json::Value *regs = s.config.find("registers");
    if (regs == nullptr || !regs->is_array() || regs->items().empty())
      bad(s, "needs registers: [{\"address\" (or \"offset\"), \"mask\", \"value\", \"mode\"}]");
    std::vector<AutoAck::Rule> rules;
    for (const json::Value &r : regs->items()) {
      AutoAck::Rule x;
      const std::optional<std::uint64_t> addr = opt_num(r, "address");
      const std::optional<std::uint64_t> off = opt_num(r, "offset");
      if (addr && s.base) {
        if (*addr < *s.base || *addr >= *s.base + s.size) bad(s, "register " + hexs(*addr) + " is outside the block");
        x.offset = *addr - *s.base;
      } else if (off) {
        x.offset = *off;
      } else if (addr) {
        bad(s, "register " + hexs(*addr) + " needs the block's base");
      } else {
        bad(s, "each register needs an address or an offset");
      }
      x.size = static_cast<std::uint32_t>(num_or(r, "size", 4));
      x.mask = num_or(r, "mask", 0xffffffff);
      x.value = num_or(r, "value", x.mask);
      x.mode = str_or(r, "mode", "fixed");
      x.step = num_or(r, "step", 1);
      x.stored = num_or(r, "initial", 0);
      if (x.mode != "fixed" && x.mode != "toggle" && x.mode != "increment")
        bad(s, "mode \"" + x.mode + "\" is not fixed, toggle or increment");
      rules.push_back(x);
    }
    return std::make_unique<AutoAck>(std::move(rules));
  }
  return nullptr;
}

}  // namespace revkit::emu::detail
