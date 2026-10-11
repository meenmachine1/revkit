/* fwkit's board layer: a UART, an interrupt controller, a timer and an
 * Ethernet MAC as memory-mapped registers, at addresses each target's
 * cflags give (corpus/firmware/firmware.json). */
#ifndef FWKIT_BOARD_H
#define FWKIT_BOARD_H

#include <stddef.h>
#include <stdint.h>

#ifndef BOARD_MMIO
#error BOARD_MMIO (the peripherals' base address) must be defined
#endif
#ifdef __AVR__
#define BOARD_CPU_HZ    16000000UL
#define BOARD_MIN_STACK 96
#define BOARD_HEAP_SIZE 3072
#elif defined(__MSP430__)
#define BOARD_CPU_HZ    16000000UL
#define BOARD_MIN_STACK 128
#define BOARD_HEAP_SIZE (24 * 1024L)
#else
#define BOARD_CPU_HZ    100000000UL
#define BOARD_MIN_STACK 256
#define BOARD_HEAP_SIZE (48 * 1024)
#endif
#define BOARD_FRAME_WORDS 12

#define REG32(off) (*(volatile uint32_t *)(uintptr_t)(BOARD_MMIO + (off)))
#define UART_DATA    REG32(0x000)
#define UART_STATUS  REG32(0x004)
#define UART_CTRL    REG32(0x008)
#define UART_BAUD    REG32(0x00c)
#define INTC_STATUS  REG32(0x100)
#define INTC_MASK    REG32(0x104)
#define INTC_ACK     REG32(0x108)
#define TIMER_LOAD   REG32(0x200)
#define TIMER_CTRL   REG32(0x204)
#define TIMER_ACK    REG32(0x208)
#define MAC_CTRL     REG32(0x300)
#define MAC_STATUS   REG32(0x304)
#define MAC_TXLEN    REG32(0x308)
#define MAC_RXLEN    REG32(0x30c)
#define MAC_FIFO     REG32(0x310)
#define MAC_ADDR_LO  REG32(0x314)
#define MAC_ADDR_HI  REG32(0x318)
#define CTX_CURRENT  REG32(0x400)
#define RESET_CTRL   REG32(0x500)
#define WDT_KICK     REG32(0x504)

#define UART_TX_READY 0x01u
#define UART_RX_AVAIL 0x02u
#define IRQ_TIMER     0x01u
#define IRQ_UART      0x02u
#define IRQ_MAC       0x04u

void board_init(void);
void board_putc(char c);
int board_getc(void);
unsigned long board_irq_save(void);
void board_irq_restore(unsigned long state);
void board_timer_start(uint32_t reload, void (*tick)(void));
void board_timer_stop(void);
void board_switch_context(void);
void board_start_first_task(void) __attribute__((noreturn));
void board_reset(void) __attribute__((noreturn));
void board_irq_dispatch(void);
uint32_t board_ticks(void);
int board_mac_send(const void *frame, size_t len);
size_t board_mac_receive(void *frame, size_t max);
void board_mac_address(uint8_t mac[6]);

/* main.c's entry from the startup code. */
int main(void);
void fw_panic(const char *why) __attribute__((noreturn));
#endif
