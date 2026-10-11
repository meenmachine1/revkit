/* MIPS32 exceptions (hand-checked expectations): the CP0 Count/Compare
 * timer interrupts (IP7) five times while main waits, and a SYSCALL whose
 * handler doubles a0 into v0 and skips the instruction. Output goes to a
 * generic UART at 0xb8000000 (data at +0, ready bit 0x20 at +4). */
#define REG32(a) (*(volatile unsigned int *)(a))
#define UART_DATA REG32(0xb8000000u)
#define UART_STATUS REG32(0xb8000004u)

static void putc_(char c) {
  while (!(UART_STATUS & 0x20)) {
  }
  UART_DATA = (unsigned char)c;
}
static void puts_(const char *s) {
  while (*s) putc_(*s++);
}
static void putu(unsigned v) {
  char b[12];
  int n = 0;
  do b[n++] = (char)('0' + v % 10), v /= 10;
  while (v);
  while (n) putc_(b[--n]);
}

static inline unsigned count(void) {
  unsigned v;
  asm volatile("mfc0 %0, $9" : "=r"(v));
  return v;
}
static inline void set_compare(unsigned v) { asm volatile("mtc0 %0, $11" : : "r"(v)); }

volatile unsigned ticks;

unsigned exception(unsigned cause, unsigned epc, unsigned *frame) {
  const unsigned code = (cause >> 2) & 31;
  if (code == 8) {               /* SYSCALL: v0 = a0 * 2 */
    frame[1] = frame[3] * 2;
    return epc + 4;
  }
  if (code == 0 && (cause & (1u << 15))) { /* IP7: the timer */
    ticks++;
    set_compare(count() + 1000);
  }
  return epc;
}

int main(void) {
  puts_("mips test\n");
  set_compare(count() + 1000);
  asm volatile("mtc0 %0, $12" : : "r"((1u << 15) | 1u)); /* IM7, IE */
  for (unsigned seen = 0; seen < 5; seen = ticks)
    while (ticks == seen) asm volatile("wait");
  asm volatile("mtc0 $zero, $12");
  puts_("ticks ");
  putu(ticks);
  register unsigned a0 asm("$4") = 21;
  register unsigned v0 asm("$2");
  asm volatile("syscall" : "=r"(v0) : "r"(a0) : "memory");
  puts_("\nsyscall ");
  putu(v0);
  puts_("\ndone\n");
  return 0;
}
