/* Timer interrupts on Versatile/PB: SP804 timer 0 raises IRQ 4 every 10 ms
 * (the VIC routes it to IRQ), timer 2 raises IRQ 5 every 45 ms (routed to
 * FIQ, whose handler uses FIQ's banked r8-r12 without saving them). main
 * runs in user mode and waits for interrupts until ten ticks have passed. */
#include "arm_common.h"

volatile unsigned ticks;
volatile unsigned fiq_count;

void irq_handler(void) {
  const unsigned status = VIC_IRQSTATUS;
  if (status & (1u << 4)) {
    T_INTCLR(TIMER0_BASE) = 1;
    ticks++;
  }
}

int main(void) {
  puts_("timer irq test\n");
  VIC_INTSELECT = 1u << 5;
  VIC_INTENABLE = (1u << 4) | (1u << 5);
  T_LOAD(TIMER0_BASE) = 10000;
  T_CTRL(TIMER0_BASE) = T_CTRL_ON;
  T_LOAD(TIMER2_BASE) = 45000;
  T_CTRL(TIMER2_BASE) = T_CTRL_ON;
  register unsigned keep asm("r8") = 0xa5a5a5a5u;
  for (unsigned seen = 0; seen < 10; seen = ticks) {
    asm volatile("" : "+r"(keep));
    wait_while(&ticks, seen);
  }
  asm volatile("" : "+r"(keep));
  T_CTRL(TIMER0_BASE) = 0;
  T_CTRL(TIMER2_BASE) = 0;
  puts_("ticks ");
  putu(ticks);
  puts_(" fiq ");
  putu(fiq_count);
  puts_(keep == 0xa5a5a5a5u ? " r8 kept\n" : " r8 corrupted\n");
  puts_("done\n");
  return 0;
}
