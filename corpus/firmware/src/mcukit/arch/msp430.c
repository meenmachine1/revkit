/* mcukit's board layer for an MSP430G2553-class part (16-bit MSP430,
 * small model), without TI's device headers: the peripheral registers by
 * address, the interrupt vector table at 0xffe0, a reset handler that sets
 * up C. */
#include "../mcukit.h"

#define SFR8(a) (*(volatile uint8_t *)(a))
#define SFR16(a) (*(volatile uint16_t *)(a))
#define IE2 SFR8(0x0001)
#define IFG2 SFR8(0x0003)
#define P1OUT SFR8(0x0021)
#define P1DIR SFR8(0x0022)
#define P2SEL SFR8(0x002e)
#define UCA0CTL1 SFR8(0x0061)
#define UCA0BR0 SFR8(0x0062)
#define UCA0BR1 SFR8(0x0063)
#define UCA0RXBUF SFR8(0x0066)
#define UCA0TXBUF SFR8(0x0067)
#define WDTCTL SFR16(0x0120)
#define FCTL1 SFR16(0x0128)
#define FCTL3 SFR16(0x012c)
#define TA0CTL SFR16(0x0160)
#define TA0CCTL0 SFR16(0x0162)
#define TA0CCR0 SFR16(0x0172)
#define TA1CCR1 SFR16(0x0194)
#define ADC10CTL0 SFR16(0x01b0)
#define ADC10CTL1 SFR16(0x01b2)
#define ADC10MEM SFR16(0x01b4)
#define INFO_FLASH ((volatile uint8_t *)0x1000)

#define UCA0RXIE 0x01
#define UCA0TXIE 0x02

extern char __data_load[], __data_start[], __data_end[], __bss_start[], __bss_end[], __stack_top[];
void main(void);

__attribute__((interrupt)) void usci_rx_isr(void) { ring_put(&uart_rx, UCA0RXBUF); }

__attribute__((interrupt)) void usci_tx_isr(void) {
  int16_t c = ring_get(&uart_tx);
  if (c < 0) IE2 &= (uint8_t)~UCA0TXIE;
  else UCA0TXBUF = (uint8_t)c;
}

__attribute__((interrupt)) void timer_a0_isr(void) { mcu_tick(); }

__attribute__((interrupt)) void unexpected_isr(void) { mcu_fault(1); }

__attribute__((naked, noreturn)) void reset_handler(void) {
  char *s, *d;
  __asm__ volatile("mov #__stack_top, r1");
  WDTCTL = 0x5a80; /* hold the watchdog */
  for (s = __data_load, d = __data_start; d < __data_end;) *d++ = *s++;
  for (d = __bss_start; d < __bss_end;) *d++ = 0;
  main();
  for (;;) {
  }
}

typedef void (*vector_t)(void);
__attribute__((section(".vectors"), used)) const vector_t vectors[16] = {
    unexpected_isr, unexpected_isr, unexpected_isr, unexpected_isr, unexpected_isr, unexpected_isr,
    usci_tx_isr,    usci_rx_isr,    unexpected_isr, timer_a0_isr,   unexpected_isr, unexpected_isr,
    unexpected_isr, unexpected_isr, unexpected_isr, reset_handler,
};

void board_init(void) {
  P1DIR |= 0x41;
  P2SEL |= 0x02;
  UCA0CTL1 = 0x81;
  UCA0BR0 = 0x8a;
  UCA0BR1 = 0;
  UCA0CTL1 &= (uint8_t)~0x01;
  IE2 |= UCA0RXIE;
  TA0CCR0 = 999;
  TA0CCTL0 = 0x0010;
  TA0CTL = 0x0210;
  ADC10CTL0 = 0x0010;
  ADC10CTL1 = 0;
}

void board_uart_kick(void) { IE2 |= UCA0TXIE; }
void board_irq_off(void) { __asm__ volatile("dint\n nop"); }
void board_irq_on(void) { __asm__ volatile("eint"); }

void board_reset(void) {
  WDTCTL = 0; /* a bad password resets */
  for (;;) {
  }
}

uint8_t board_nvm_read(uint16_t at) { return INFO_FLASH[at & 0x3f]; }

void board_nvm_write(uint16_t at, uint8_t v) {
  FCTL3 = 0xa500;
  FCTL1 = 0xa540;
  INFO_FLASH[at & 0x3f] = v;
  FCTL1 = 0xa500;
  FCTL3 = 0xa510;
}

void board_led(uint8_t on) {
  if (on) P1OUT |= 0x01;
  else P1OUT &= (uint8_t)~0x01;
}

uint16_t board_adc(uint8_t channel) {
  ADC10CTL1 = (uint16_t)channel << 12;
  ADC10CTL0 |= 0x0003;
  while (ADC10CTL1 & 0x0001) {
  }
  return ADC10MEM;
}

void board_pwm(uint16_t duty) { TA1CCR1 = duty; }
void board_idle(void) { __asm__ volatile("bis #0x18, r2"); }
