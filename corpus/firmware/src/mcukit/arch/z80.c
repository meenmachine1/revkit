/* mcukit's board layer for a Z80 board under SDCC: a UART and a timer on
 * I/O ports, polled from the idle loop (SDCC's crt0 leaves the interrupt
 * vectors alone), settings in battery-backed RAM. */
#include "../mcukit.h"

__sfr __at(0x10) uart_data;
__sfr __at(0x11) uart_status;
__sfr __at(0x12) uart_ctrl;
__sfr __at(0x20) timer_ctrl;
__sfr __at(0x21) timer_flags;
__sfr __at(0x30) led_port;
__sfr __at(0x40) adc_ctrl;
__sfr __at(0x41) adc_lo;
__sfr __at(0x42) adc_hi;
__sfr __at(0x50) pwm_lo;
__sfr __at(0x51) pwm_hi;
__sfr __at(0x60) reset_port;

static uint8_t nvm[64];
static uint8_t irq_enabled;

static void uart_service(void) {
  int16_t c;
  while (uart_status & 0x02) ring_put(&uart_rx, uart_data);
  while ((uart_status & 0x01) && (c = ring_get(&uart_tx)) >= 0) uart_data = (uint8_t)c;
}

void board_init(void) {
  uart_ctrl = 0x03;
  timer_ctrl = 0x01;
}

void board_uart_kick(void) { uart_service(); }
void board_irq_off(void) { irq_enabled = 0; }
void board_irq_on(void) { irq_enabled = 1; }

void board_reset(void) {
  reset_port = 0xa5;
  for (;;) {
  }
}

uint8_t board_nvm_read(uint16_t at) { return nvm[at & 0x3f]; }
void board_nvm_write(uint16_t at, uint8_t v) { nvm[at & 0x3f] = v; }
void board_led(uint8_t on) { led_port = on; }

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

void board_idle(void) {
  if (!irq_enabled) return;
  if (timer_flags & 0x01) {
    timer_flags = 0x01;
    mcu_tick();
  }
  uart_service();
}
