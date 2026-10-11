/* A peripheral plugin on Versatile/PB (sdk/plugins/examples/tick-timer at
 * 0x10200000, IRQ 20 on the VIC): its timer interrupts three times, then
 * the program writes through its transmit register. */
#include "arm_common.h"

#define TT 0x10200000u
#define TT_CTRL REG32(TT + 0x00)
#define TT_PERIOD REG32(TT + 0x04)
#define TT_STATUS REG32(TT + 0x0c)
#define TT_TX REG32(TT + 0x10)
#define TT_COUNT REG32(TT + 0x14)

volatile unsigned ticks;

void irq_handler(void) {
  if (VIC_IRQSTATUS & (1u << 20)) {
    TT_STATUS = 1;
    ticks++;
  }
}

int main(void) {
  puts_("plugin test\n");
  VIC_INTENABLE = 1u << 20;
  TT_PERIOD = 2000;
  TT_CTRL = 7; /* enabled, interrupt, periodic */
  for (unsigned seen = 0; seen < 3; seen = ticks) wait_while(&ticks, seen);
  TT_CTRL = 0;
  for (const char *s = "via plugin: "; *s; ++s) TT_TX = (unsigned char)*s;
  TT_TX = '0' + ticks;
  TT_TX = '\n';
  puts_("count ");
  putu(TT_COUNT);
  puts_("\ndone\n");
  return 0;
}
