/* Software interrupts, modes and the undefined-instruction trap on
 * Versatile/PB: services in supervisor mode called from user mode, the
 * banked stack pointers, and an undefined instruction that traps and
 * resumes. */
#include "arm_common.h"

extern volatile unsigned traps;

int main(void) {
  puts_("swi test\n");
  puts_("add ");
  putu(SWI(1, 2, 40));
  puts_("\nmul ");
  putu(SWI(2, 6, 7));
  const unsigned modes = SWI(3, 0, 0);
  puts_("\nmodes ");
  puthex(modes & 0xff);
  putc_(' ');
  puthex(modes >> 8);
  unsigned usp;
  asm volatile("mov %0, sp" : "=r"(usp));
  const unsigned ssp = SWI(5, 0, 0);
  unsigned usp2;
  asm volatile("mov %0, sp" : "=r"(usp2));
  puts_(usp == usp2 && ssp != usp ? "\nstacks banked\n" : "\nstacks shared\n");
  asm volatile(".word 0xe7f000f0" ::: "memory"); /* an undefined instruction */
  puts_("traps ");
  putu(traps);
  puts_("\ndone\n");
  return 0;
}
