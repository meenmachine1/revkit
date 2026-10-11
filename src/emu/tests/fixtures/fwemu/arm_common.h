/* Versatile/PB devices and the SWI services of arm_start.s's handler. */
#ifndef FWEMU_ARM_COMMON_H
#define FWEMU_ARM_COMMON_H

#define UART_BASE 0x101f1000u
#include "common.h"

#define VIC_BASE 0x10140000u
#define VIC_IRQSTATUS REG32(VIC_BASE + 0x000)
#define VIC_INTSELECT REG32(VIC_BASE + 0x00c)
#define VIC_INTENABLE REG32(VIC_BASE + 0x010)

#define TIMER0_BASE 0x101e2000u
#define TIMER2_BASE 0x101e3000u
#define T_LOAD(b) REG32((b) + 0x00)
#define T_VALUE(b) REG32((b) + 0x04)
#define T_CTRL(b) REG32((b) + 0x08)
#define T_INTCLR(b) REG32((b) + 0x0c)
#define T_CTRL_ON 0xe2u /* enabled, periodic, interrupt, 32-bit */

/* SWIs from user mode. */
#define SWI(num, a, b)                                                           \
  ({                                                                             \
    register unsigned r0_ asm("r0") = (a);                                       \
    register unsigned r1_ asm("r1") = (b);                                       \
    asm volatile("swi %2" : "+r"(r0_) : "r"(r1_), "i"(num) : "memory"); \
    r0_;                                                                         \
  })

/* Waits for an interrupt while *addr == value (the check and the wait are
 * atomic: the SWI runs with IRQs masked). */
#define wait_while(addr, value) ((void)SWI(6, (unsigned)(addr), (value)))
#define exit_(code) ((void)SWI(0x10, 0, (code)))

#endif
