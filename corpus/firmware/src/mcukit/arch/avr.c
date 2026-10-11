/* mcukit's board layer for the ATmega328P (Arduino Uno class), on
 * avr-libc: USART0 interrupts, Timer0 as the 1 ms tick, Timer1 PWM, the
 * ADC, the EEPROM and the watchdog for resets. */
#include <avr/eeprom.h>
#include <avr/interrupt.h>
#include <avr/io.h>
#include <avr/sleep.h>
#include <avr/wdt.h>

#include "../mcukit.h"

ISR(USART_RX_vect) { ring_put(&uart_rx, UDR0); }

ISR(USART_UDRE_vect) {
  int16_t c = ring_get(&uart_tx);
  if (c < 0) UCSR0B &= (uint8_t)~_BV(UDRIE0);
  else UDR0 = (uint8_t)c;
}

ISR(TIMER0_COMPA_vect) { mcu_tick(); }

ISR(BADISR_vect) { mcu_fault(1); }

void board_init(void) {
  MCUSR = 0;
  wdt_disable();
  UBRR0 = 8; /* 115200 at 16 MHz */
  UCSR0B = _BV(RXEN0) | _BV(TXEN0) | _BV(RXCIE0);
  UCSR0C = _BV(UCSZ01) | _BV(UCSZ00);
  TCCR0A = _BV(WGM01);
  OCR0A = 249;
  TCCR0B = _BV(CS01) | _BV(CS00);
  TIMSK0 = _BV(OCIE0A);
  TCCR1A = _BV(COM1A1) | _BV(WGM11) | _BV(WGM10);
  TCCR1B = _BV(WGM12) | _BV(CS10);
  DDRB |= _BV(PB5) | _BV(PB1);
  ADMUX = _BV(REFS0);
  ADCSRA = _BV(ADEN) | _BV(ADPS2) | _BV(ADPS1) | _BV(ADPS0);
}

void board_uart_kick(void) { UCSR0B |= _BV(UDRIE0); }
void board_irq_off(void) { cli(); }
void board_irq_on(void) { sei(); }

void board_reset(void) {
  wdt_enable(WDTO_15MS);
  for (;;) {
  }
}

uint8_t board_nvm_read(uint16_t at) { return eeprom_read_byte((const uint8_t *)at); }
void board_nvm_write(uint16_t at, uint8_t v) { eeprom_update_byte((uint8_t *)at, v); }

void board_led(uint8_t on) {
  if (on) PORTB |= _BV(PB5);
  else PORTB &= (uint8_t)~_BV(PB5);
}

uint16_t board_adc(uint8_t channel) {
  ADMUX = (uint8_t)((ADMUX & 0xf0) | (channel & 0x07));
  ADCSRA |= _BV(ADSC);
  while (ADCSRA & _BV(ADSC)) {
  }
  return ADC;
}

void board_pwm(uint16_t duty) { OCR1A = duty; }

void board_idle(void) {
  set_sleep_mode(SLEEP_MODE_IDLE);
  sleep_mode();
}
