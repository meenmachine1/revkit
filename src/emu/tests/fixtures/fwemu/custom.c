/* A made-up SoC described entirely with the configurable built-ins: an
 * interrupt controller whose pending-number register acknowledges the
 * lowest pending interrupt (numbered from 1) and whose mask registers
 * count bits from the top, four up-counting timers with run, interrupt
 * enable and write-1-to-clear pending bits in one control register, and a
 * UART with PL011-like status bits. Hand-checked expectations, no qemu. */
#include "arm_common.h"

#define INTC 0xa0001000u
#define INTC_DISABLE REG32(INTC + 0x08)
#define INTC_PENDING REG32(INTC + 0x10)
#define INTC_MASK_LO REG32(INTC + 0x20) /* IRQs 1..32: bit 32 - n masks */
#define INTC_MASK_HI REG32(INTC + 0x24) /* IRQs 33..64: bit 64 - n masks */
#define TIMER 0xa0002000u
#define TCTRL(n) REG32(TIMER + (n) * 0x10)
#define TRELOAD(n) REG32(TIMER + (n) * 0x10 + 4)
#define T_RUN (1u << 0)
#define T_IRQ (1u << 1)
#define T_PENDING (1u << 7)

volatile unsigned ticks, last_irq, others;

void irq_handler(void) {
  unsigned n;
  while ((n = INTC_PENDING) != 0) {
    last_irq = n;
    if (n == 45) {
      TCTRL(0) |= T_PENDING;
      ticks++;
    } else {
      others++;
    }
  }
}

int main(void) {
  puts_("custom soc test\n");
  INTC_MASK_LO = 0xffffffffu;
  INTC_MASK_HI = ~(1u << (64 - 45));
  INTC_DISABLE = 0;
  TRELOAD(0) = 0x8000 - 1000;
  TCTRL(0) = T_RUN | T_IRQ;
  TRELOAD(1) = 0x8000 - 300; /* runs, but IRQ 40 stays masked */
  TCTRL(1) = T_RUN | T_IRQ;
  for (unsigned seen = 0; seen < 5; seen = ticks) wait_while(&ticks, seen);
  TCTRL(0) = 0;
  TCTRL(1) = 0;
  puts_("ticks ");
  putu(ticks);
  puts_(" irq ");
  putu(last_irq);
  puts_(" others ");
  putu(others);
  puts_("\ndone\n");
  return 0;
}
