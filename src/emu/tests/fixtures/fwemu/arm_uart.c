/* UART receive interrupts on Versatile/PB: the PL011 raises IRQ 12 when
 * bytes arrive; the handler queues them, main echoes each line in upper
 * case until "quit". */
#include "arm_common.h"

static char queue[256];
volatile unsigned head;

void irq_handler(void) {
  if (VIC_IRQSTATUS & (1u << 12)) {
    REG32(UART_ICR) = UART_INT_RX | UART_INT_RT; /* first: a byte arriving later interrupts again */
    while (!(REG32(UART_FR) & UART_FR_RXFE)) {
      const char c = (char)REG32(UART_DR);
      if (head < sizeof queue) queue[head++] = c;
    }
  }
}

int main(void) {
  puts_("uart echo test\n");
  REG32(UART_IMSC) = UART_INT_RX | UART_INT_RT;
  VIC_INTENABLE = 1u << 12;
  char line[64];
  unsigned n = 0, tail = 0, lines = 0;
  for (;;) {
    wait_while(&head, tail);
    while (tail < head) {
      char c = queue[tail++];
      if (c == '\r') continue;
      if (c != '\n') {
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        if (n < sizeof line - 1) line[n++] = c;
        continue;
      }
      line[n] = 0;
      puts_("echo: ");
      puts_(line);
      putc_('\n');
      ++lines;
      if (n == 4 && line[0] == 'Q' && line[1] == 'U' && line[2] == 'I' && line[3] == 'T') {
        puts_("lines ");
        putu(lines);
        puts_("\ndone\n");
        return 0;
      }
      n = 0;
    }
  }
}
