/* The SWI handler (supervisor mode) and the undefined-instruction and abort
 * handlers shared by the ARM fixtures. */
#include "arm_common.h"

volatile unsigned traps;

static void semihosting_exit(unsigned code) {
  register unsigned r0 asm("r0") = 0x18;
  register unsigned r1 asm("r1") = code == 0 ? 0x20026u : 0x20023u;
  asm volatile("swi 0x123456" : : "r"(r0), "r"(r1) : "memory");
  for (;;) {
  }
}

void swi_handler(unsigned number, unsigned *regs) {
  switch (number) {
    case 1: regs[0] = regs[0] + regs[1]; break;
    case 2: regs[0] = regs[0] * regs[1]; break;
    case 3: {
      unsigned cpsr, spsr;
      asm volatile("mrs %0, cpsr" : "=r"(cpsr));
      asm volatile("mrs %0, spsr" : "=r"(spsr));
      regs[0] = (cpsr & 0xff) | (spsr & 0xff) << 8;
      break;
    }
    case 5: {
      unsigned sp;
      asm volatile("mov %0, sp" : "=r"(sp));
      regs[0] = sp;
      break;
    }
    case 6:  /* wait for an interrupt while *regs[0] == regs[1] */
      if (*(volatile unsigned *)regs[0] == regs[1]) asm volatile("mcr p15, 0, %0, c7, c0, 4" : : "r"(0) : "memory");
      break;
    case 7: {  /* disable IRQ and FIQ in the caller's PSR */
      unsigned spsr;
      asm volatile("mrs %0, spsr" : "=r"(spsr));
      spsr |= 0xc0;
      asm volatile("msr spsr_c, %0" : : "r"(spsr));
      break;
    }
    case 0x10: semihosting_exit(regs[1]); break;
    default: regs[0] = 0xffffffffu; break;
  }
}

void trap_handler(unsigned kind, unsigned address) {
  (void)address;
  traps += kind == 1 ? 1 : 0x100;
}
