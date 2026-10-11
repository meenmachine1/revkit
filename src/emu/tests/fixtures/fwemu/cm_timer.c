/* SysTick and PendSV on a Cortex-M3: SysTick every 10000 cycles, PendSV
 * (the lowest priority) pended every fifth tick; main runs in thread mode
 * on the process stack and waits for interrupts. */
#include "cm_common.h"

extern unsigned __psp_top[];
volatile unsigned ticks, pendsvs;

void systick_handler(void) {
  if (++ticks % 5 == 0) SCB_ICSR = ICSR_PENDSVSET;
}

void pendsv_handler(void) { ++pendsvs; }

int main(void) {
  puts_("systick test\n");
  /* Thread mode on the process stack. */
  asm volatile("msr psp, %0\n\tmovs r0, #2\n\tmsr control, r0\n\tisb" : : "r"(__psp_top) : "r0", "memory");
  SCB_SHPR3 = 0x00ff0000u; /* SysTick highest, PendSV lowest */
  SYST_RVR = 10000 - 1;
  SYST_CVR = 0;
  SYST_CSR = 7; /* processor clock, interrupt, enabled */
  for (unsigned seen = 0; seen < 10; seen = ticks) wait_while(&ticks, seen);
  SYST_CSR = 0;
  unsigned control;
  asm volatile("mrs %0, control" : "=r"(control));
  puts_("ticks ");
  putu(ticks);
  puts_(" pendsv ");
  putu(pendsvs);
  puts_(control & 2 ? " psp\n" : " msp\n");
  puts_("done\n");
  semihosting_exit(0); /* main's frame is on the main stack: it can't return */
}
