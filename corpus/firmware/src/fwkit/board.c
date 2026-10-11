/* fwkit's board layer (board.h), and the C half of the startup: the
 * startup code (arch/<arch>/start.S, or the vector table below) sets a
 * stack and calls fw_reset. */
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "board.h"

extern char __data_load[], __data_start[], __data_end[], __bss_start[], __bss_end[];

static void (*tick_handler)(void);
static volatile uint32_t ticks;
static volatile unsigned long irq_enabled;

void fw_reset(void) __attribute__((noreturn));
void fw_reset(void) {
#ifndef __AVR__  /* avr-libc's crt copies .data and clears .bss */
  memcpy(__data_start, __data_load, (size_t)(__data_end - __data_start));
  memset(__bss_start, 0, (size_t)(__bss_end - __bss_start));
#endif
  board_init();
  main();
  board_reset();
}

void board_init(void) {
  INTC_MASK = 0;
  INTC_ACK = 0xffffffffu;
  UART_BAUD = BOARD_CPU_HZ / 115200;
  UART_CTRL = 0x3;
  MAC_CTRL = 0;
}

void board_putc(char c) {
  if (c == '\n') board_putc('\r');
  while (!(UART_STATUS & UART_TX_READY)) {
  }
  UART_DATA = (uint8_t)c;
}

int board_getc(void) {
  if (!(UART_STATUS & UART_RX_AVAIL)) return -1;
  return (int)(UART_DATA & 0xff);
}

unsigned long board_irq_save(void) {
  unsigned long was = irq_enabled;
  INTC_MASK = 0;
  irq_enabled = 0;
  return was;
}

void board_irq_restore(unsigned long state) {
  irq_enabled = state;
  if (state) INTC_MASK = IRQ_TIMER | IRQ_UART | IRQ_MAC;
}

void board_timer_start(uint32_t reload, void (*tick)(void)) {
  tick_handler = tick;
  TIMER_LOAD = reload;
  TIMER_CTRL = 0x3;
  board_irq_restore(1);
}

void board_timer_stop(void) {
  TIMER_CTRL = 0;
  tick_handler = NULL;
}

uint32_t board_ticks(void) { return ticks; }

extern void uart_rx_isr(void);
extern void mac_rx_isr(void);

/* Called from the processor's interrupt vector. */
void board_irq_dispatch(void) {
  uint32_t pending = INTC_STATUS;
  if (pending & IRQ_TIMER) {
    TIMER_ACK = 1;
    ticks++;
    if (tick_handler) tick_handler();
  }
  if (pending & IRQ_UART) uart_rx_isr();
  if (pending & IRQ_MAC) mac_rx_isr();
  INTC_ACK = pending;
}

#ifdef FWKIT_GENERIC_PORT
/* The register save and restore are the hardware's: tell it whose stack. */
extern void *volatile pxCurrentTCB;

void board_switch_context(void) { CTX_CURRENT = (uint32_t)(uintptr_t)pxCurrentTCB; }

void board_start_first_task(void) {
  StackType_t *top = *(StackType_t **)pxCurrentTCB;
  TaskFunction_t code = (TaskFunction_t)top[BOARD_FRAME_WORDS + 3];
  void *param = (void *)top[BOARD_FRAME_WORDS + 2];
  board_switch_context();
  code(param);
  vTaskDelete(NULL);
  for (;;) {
  }
}
#endif

void board_reset(void) {
  RESET_CTRL = 0xdead;
  for (;;) {
  }
}

int board_mac_send(const void *frame, size_t len) {
  const uint8_t *p = frame;
  size_t i;
  if (MAC_STATUS & 0x1) return -1;
  MAC_TXLEN = (uint32_t)len;
  for (i = 0; i + 4 <= len; i += 4) MAC_FIFO = (uint32_t)p[i] | (uint32_t)p[i + 1] << 8 | (uint32_t)p[i + 2] << 16 |
                                               (uint32_t)p[i + 3] << 24;
  for (; i < len; i++) MAC_FIFO = p[i];
  MAC_CTRL |= 0x1;
  return 0;
}

size_t board_mac_receive(void *frame, size_t max) {
  uint8_t *p = frame;
  size_t len = MAC_RXLEN, i;
  if (len > max) len = max;
  for (i = 0; i < len; i++) p[i] = (uint8_t)MAC_FIFO;
  MAC_CTRL |= 0x2;
  return len;
}

void board_mac_address(uint8_t mac[6]) {
  uint32_t lo = MAC_ADDR_LO, hi = MAC_ADDR_HI;
  mac[0] = (uint8_t)lo;
  mac[1] = (uint8_t)(lo >> 8);
  mac[2] = (uint8_t)(lo >> 16);
  mac[3] = (uint8_t)(lo >> 24);
  mac[4] = (uint8_t)hi;
  mac[5] = (uint8_t)(hi >> 8);
}
