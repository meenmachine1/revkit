/* mcukit's board layer for a classic 8051 under SDCC: the serial port and
 * Timer 0 interrupts (their prototypes are in mcukit.h, as SDCC wants them
 * where main is), settings in external RAM, an ADC and a PWM as
 * memory-mapped external registers. */
#include <8051.h>

#include "../mcukit.h"

static __xdata __at(0xf000) uint8_t nvm[64];
static volatile __xdata __at(0xff00) uint8_t adc_ctrl;
static volatile __xdata __at(0xff01) uint8_t adc_lo;
static volatile __xdata __at(0xff02) uint8_t adc_hi;
static volatile __xdata __at(0xff04) uint8_t pwm_lo;
static volatile __xdata __at(0xff05) uint8_t pwm_hi;
static volatile __xdata __at(0xff08) uint8_t reset_ctrl;
static __bit tx_busy;

void serial_isr(void) __interrupt(4) {
  int16_t c;
  if (RI) {
    RI = 0;
    ring_put(&uart_rx, SBUF);
  }
  if (TI) {
    TI = 0;
    c = ring_get(&uart_tx);
    if (c < 0) tx_busy = 0;
    else SBUF = (uint8_t)c;
  }
}

void timer0_isr(void) __interrupt(1) {
  TH0 = 0xfc;
  TL0 = 0x66;
  mcu_tick();
}

void board_init(void) {
  SCON = 0x50;
  TMOD = 0x21;
  TH1 = 0xfd;
  TR1 = 1;
  TH0 = 0xfc;
  TL0 = 0x66;
  TR0 = 1;
  ET0 = 1;
  ES = 1;
}

void board_uart_kick(void) {
  int16_t c;
  if (tx_busy) return;
  c = ring_get(&uart_tx);
  if (c >= 0) {
    tx_busy = 1;
    SBUF = (uint8_t)c;
  }
}

void board_irq_off(void) { EA = 0; }
void board_irq_on(void) { EA = 1; }

void board_reset(void) {
  reset_ctrl = 0xa5;
  for (;;) {
  }
}

uint8_t board_nvm_read(uint16_t at) { return nvm[at & 0x3f]; }
void board_nvm_write(uint16_t at, uint8_t v) { nvm[at & 0x3f] = v; }
void board_led(uint8_t on) { P1_0 = on ? 0 : 1; }

uint16_t board_adc(uint8_t channel) {
  adc_ctrl = (uint8_t)(0x80 | channel);
  while (adc_ctrl & 0x80) {
  }
  return (uint16_t)(adc_hi << 8 | adc_lo);
}

void board_pwm(uint16_t duty) {
  pwm_hi = (uint8_t)(duty >> 8);
  pwm_lo = (uint8_t)duty;
}

void board_idle(void) { PCON |= 1; }
