/* fwkit startup for Cortex-M: the vector table (initial stack, reset,
 * faults, the FreeRTOS port's SVC, PendSV and SysTick handlers, external
 * interrupts) and the reset handler. */
#include <stdint.h>

#include "board.h"
#include "printf.h"

extern char __stack_top[];
void fw_reset(void) __attribute__((noreturn));
void SVC_Handler(void);
void PendSV_Handler(void);
void SysTick_Handler(void);

void _start(void) __attribute__((noreturn));
void _start(void) { fw_reset(); }

static void fault(void) {
  volatile uint32_t *cfsr = (volatile uint32_t *)0xe000ed28;
  printf("fault: cfsr %08lx\n", (unsigned long)*cfsr);
  board_reset();
}

static void nmi(void) { board_reset(); }

static void external_irq(void) { board_irq_dispatch(); }

__attribute__((section(".vectors"), used)) void (*const vectors[16 + 32])(void) = {
    (void (*)(void))__stack_top,
    _start,
    nmi,
    fault, /* hard fault */
    fault, /* memory management */
    fault, /* bus fault */
    fault, /* usage fault */
    0, 0, 0, 0,
    SVC_Handler,
    0, 0,
    PendSV_Handler,
    SysTick_Handler,
    [16 ... 47] = external_irq,
};
