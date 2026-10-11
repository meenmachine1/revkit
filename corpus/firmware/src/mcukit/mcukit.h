/* mcukit: a small bare-metal MCU firmware for the revkit firmware corpus,
 * in the shape of what 8- and 16-bit microcontrollers run: a superloop
 * with a cooperative scheduler, interrupt-driven UART ring buffers, a
 * command shell dispatched through a table of function pointers, a framed
 * packet protocol as a state machine, CRCs from a table in code memory,
 * fixed-point control math and a settings block with a checksum. It is
 * built, never run (corpus/README.md). Each processor's board layer
 * (arch/<arch>.c) gives the registers, interrupts and code-memory reads;
 * the C here is what avr-gcc, msp430-gcc and SDCC all compile. */
#ifndef MCUKIT_H
#define MCUKIT_H

#include <stdint.h>

#if defined(__SDCC_mcs51)
#define MCU_CODE __code
#elif defined(__AVR__)
#include <avr/pgmspace.h>
#define MCU_CODE PROGMEM
#else
#define MCU_CODE
#endif

/* Reads of tables in code memory (PROGMEM on AVR, __code on the 8051). */
#if defined(__AVR__)
#define MCU_READ8(p) pgm_read_byte(p)
#define MCU_READ16(p) pgm_read_word(p)
#else
#define MCU_READ8(p) (*(p))
#define MCU_READ16(p) (*(p))
#endif

/* SDCC's 8051 passes a function pointer call's arguments in registers
 * only up to a byte or two; the shell's commands take theirs on the stack. */
#if defined(__SDCC_mcs51)
#define MCU_REENTRANT __reentrant
#else
#define MCU_REENTRANT
#endif

#define MCU_LINE_MAX 40
#define MCU_ARGS_MAX 6
#define MCU_RING_SIZE 32 /* a power of two */

typedef struct {
  volatile uint8_t head, tail;
  uint8_t buf[MCU_RING_SIZE];
} ring_t;

/* The board layer (arch/<arch>.c). */
void board_init(void);
void board_uart_kick(void); /* start sending what the tx ring holds */
void board_irq_off(void);
void board_irq_on(void);
void board_reset(void);
uint8_t board_nvm_read(uint16_t at);
void board_nvm_write(uint16_t at, uint8_t v);
void board_led(uint8_t on);
uint16_t board_adc(uint8_t channel);
void board_pwm(uint16_t duty);
void board_idle(void);

#if defined(__SDCC_mcs51)
/* SDCC makes the 8051's vectors from the prototypes main's file sees. */
void serial_isr(void) __interrupt(4);
void timer0_isr(void) __interrupt(1);
#endif

/* main.c, for the board layer's interrupts. */
extern ring_t uart_rx, uart_tx;
extern volatile uint16_t ticks;
uint8_t ring_put(ring_t *r, uint8_t c);
int16_t ring_get(ring_t *r);
void mcu_tick(void);
void mcu_fault(uint8_t code);
#endif
