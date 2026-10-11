/* Bare-metal helpers shared by the firmware-emulation fixtures: MMIO
 * access, a PL011 UART for output, number printing and semihosting exit.
 * No C library: everything here is freestanding. */
#ifndef FWEMU_COMMON_H
#define FWEMU_COMMON_H

#define REG32(a) (*(volatile unsigned int *)(a))

/* PL011 registers (UART_BASE is the board's). */
#define UART_DR (UART_BASE + 0x00)
#define UART_FR (UART_BASE + 0x18)
#define UART_IMSC (UART_BASE + 0x38)
#define UART_ICR (UART_BASE + 0x44)
#define UART_FR_RXFE (1u << 4)
#define UART_FR_TXFF (1u << 5)
#define UART_INT_RX (1u << 4)
#define UART_INT_RT (1u << 6)

static inline void putc_(char c) {
  while (REG32(UART_FR) & UART_FR_TXFF) {
  }
  REG32(UART_DR) = (unsigned char)c;
}

static inline void puts_(const char *s) {
  while (*s) putc_(*s++);
}

static inline void putu(unsigned v) {
  char buf[12];
  int n = 0;
  do {
    buf[n++] = (char)('0' + v % 10);
    v /= 10;
  } while (v);
  while (n) putc_(buf[--n]);
}

static inline void puthex(unsigned v) {
  static const char digits[] = "0123456789abcdef";
  int started = 0;
  for (int s = 28; s >= 0; s -= 4) {
    unsigned d = (v >> s) & 15;
    if (d || started || s == 0) {
      putc_(digits[d]);
      started = 1;
    }
  }
}

#endif
