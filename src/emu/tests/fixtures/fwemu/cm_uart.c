/* UART receive interrupts on a Cortex-M3: UART0 raises IRQ 5; the handler
 * queues bytes, main echoes lines in upper case until "quit". */
#include "cm_common.h"

static char queue[256];
volatile unsigned head;

void uart0_handler(void) {
  REG32(UART_ICR) = UART_INT_RX | UART_INT_RT; /* first: a byte arriving later interrupts again */
  while (!(REG32(UART_FR) & UART_FR_RXFE)) {
    const char c = (char)REG32(UART_DR);
    if (head < sizeof queue) queue[head++] = c;
  }
}

int main(void) {
  puts_("uart echo test\n");
  REG32(UART_IMSC) = UART_INT_RX | UART_INT_RT;
  NVIC_ISER0 = 1u << 5;
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
