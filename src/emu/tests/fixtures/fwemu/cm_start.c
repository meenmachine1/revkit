/* Cortex-M start-up: the vector table at 0 (flash), the reset handler,
 * and default handlers. A program defines the handlers it needs. */
#include "cm_common.h"

extern unsigned __stack_top[], __bss_start[], __bss_end[];
int main(void);

void reset_handler(void);
void default_handler(void);
void nmi_handler(void) __attribute__((weak, alias("default_handler")));
void hardfault_handler(void) __attribute__((weak, alias("default_handler")));
void svc_handler(void) __attribute__((weak, alias("default_handler")));
void pendsv_handler(void) __attribute__((weak, alias("default_handler")));
void systick_handler(void) __attribute__((weak, alias("default_handler")));
void uart0_handler(void) __attribute__((weak, alias("default_handler")));

__attribute__((section(".vectors"), used)) void (*const vectors[16 + 8])(void) = {
    (void (*)(void))__stack_top,
    reset_handler,
    nmi_handler,
    hardfault_handler,
    default_handler,
    default_handler,
    default_handler,
    0,
    0,
    0,
    0,
    svc_handler,
    default_handler,
    0,
    pendsv_handler,
    systick_handler,
    default_handler, /* IRQ 0..4 */
    default_handler,
    default_handler,
    default_handler,
    default_handler,
    uart0_handler, /* IRQ 5: UART0 */
    default_handler,
    default_handler,
};

void default_handler(void) {
  puts_("unexpected exception\n");
  semihosting_exit(1);
}

void reset_handler(void) {
  for (unsigned *p = __bss_start; p < __bss_end; ++p) *p = 0;
  semihosting_exit((unsigned)main());
}
