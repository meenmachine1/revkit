/* Stellaris LM3S6965 (Cortex-M3) devices for the Cortex-M fixtures. */
#ifndef FWEMU_CM_COMMON_H
#define FWEMU_CM_COMMON_H

#define UART_BASE 0x4000c000u
#include "common.h"

#define SYST_CSR REG32(0xe000e010u)
#define SYST_RVR REG32(0xe000e014u)
#define SYST_CVR REG32(0xe000e018u)
#define NVIC_ISER0 REG32(0xe000e100u)
#define SCB_ICSR REG32(0xe000ed04u)
#define SCB_SHPR3 REG32(0xe000ed20u)
#define ICSR_PENDSVSET (1u << 28)

__attribute__((noreturn)) static inline void semihosting_exit(unsigned code) {
  register unsigned r0 asm("r0") = 0x18;
  register unsigned r1 asm("r1") = code == 0 ? 0x20026u : 0x20023u;
  asm volatile("bkpt 0xab" : : "r"(r0), "r"(r1) : "memory");
  for (;;) {
  }
}

/* Waits for an interrupt while *addr == value, without losing a wakeup. */
static inline void wait_while(volatile unsigned *addr, unsigned value) {
  asm volatile("cpsid i" ::: "memory");
  if (*addr == value) asm volatile("wfi" ::: "memory");
  asm volatile("cpsie i" ::: "memory");
}

#endif
