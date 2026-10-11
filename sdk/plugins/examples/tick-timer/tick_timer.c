/* tick-timer: a peripheral plugin (docs/firmware-emulation.md). A timer that
 * interrupts every PERIOD machine ticks, and a transmit register that
 * writes to the session's output.
 *
 *   0x00 CTRL    bit 0 enable, bit 1 interrupt enable, bit 2 periodic
 *   0x04 PERIOD  ticks between interrupts
 *   0x08 VALUE   ticks left until the next one (read)
 *   0x0c STATUS  bit 0 pending; write 1 to clear
 *   0x10 TX      a byte to the output
 *   0x14 COUNT   interrupts raised so far
 *
 * The machine description may set "period" (the PERIOD at reset). */
#include "revkit_plugin.h"

static uint8_t buffer[4096];
static uint32_t ctrl, period, status, count, initial_period;
static int64_t due = -1;

RK_EXPORT("rk_peripheral_buffer") int32_t rk_peripheral_buffer(void) { return (int32_t)(uintptr_t)buffer; }

static void update_irq(void) { rk_irq_set(0, (status & 1) && (ctrl & 2)); }

static void arm(void) {
  if ((ctrl & 1) && period) {
    due = rk_now() + period;
    rk_schedule(due);
  } else {
    due = -1;
    rk_schedule(-1);
  }
}

/* "period": N in the JSON object (a plain number). */
static uint32_t config_period(const uint8_t *json, int32_t n) {
  static const char key[] = "\"period\"";
  for (int32_t i = 0; i + 8 < n; ++i) {
    if (memcmp(json + i, key, 8) != 0) continue;
    int32_t j = i + 8;
    while (j < n && (json[j] == ' ' || json[j] == ':')) ++j;
    uint32_t v = 0;
    while (j < n && json[j] >= '0' && json[j] <= '9') v = v * 10 + (uint32_t)(json[j++] - '0');
    return v;
  }
  return 0;
}

RK_EXPORT("rk_peripheral_init") int32_t rk_peripheral_init(const uint8_t *json, int32_t n) {
  initial_period = config_period(json, n);
  period = initial_period;
  return 0;
}

RK_EXPORT("rk_peripheral_reset") int32_t rk_peripheral_reset(void) {
  ctrl = status = count = 0;
  period = initial_period;
  due = -1;
  rk_schedule(-1);
  update_irq();
  return 0;
}

RK_EXPORT("rk_peripheral_read") int64_t rk_peripheral_read(int64_t offset, int32_t size) {
  (void)size;
  switch (offset & ~3) {
    case 0x00: return ctrl;
    case 0x04: return period;
    case 0x08: return due < 0 ? 0 : due - rk_now();
    case 0x0c: return status;
    case 0x14: return count;
    default: return 0;
  }
}

RK_EXPORT("rk_peripheral_write") int32_t rk_peripheral_write(int64_t offset, int32_t size, int64_t value) {
  (void)size;
  const uint32_t v = (uint32_t)value;
  switch (offset & ~3) {
    case 0x00:
      ctrl = v & 7;
      arm();
      break;
    case 0x04:
      period = v;
      arm();
      break;
    case 0x0c:
      if (v & 1) status = 0;
      break;
    case 0x10: {
      const char c = (char)v;
      rk_output(&c, 1);
      break;
    }
    default: break;
  }
  update_irq();
  return 0;
}

RK_EXPORT("rk_peripheral_tick") int32_t rk_peripheral_tick(int64_t now) {
  (void)now;
  status |= 1;
  ++count;
  update_irq();
  if (ctrl & 4) arm();
  else {
    ctrl &= ~1u;
    due = -1;
  }
  return 0;
}
