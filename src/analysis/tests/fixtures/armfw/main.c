/* Synthetic ARM firmware (ARM code). What each function exercises:
 *   main            reached from reset through a literal (ldr r0, =main; bx r0)
 *   handlers[]      a table of function pointers in .rodata (rodata.c), called
 *                   indirectly (mov lr, pc; bx rN on ARMv4T)
 *   dispatch        a switch compiled to an ARM jump table
 *   thumb_*         Thumb code (thumb.c), called from ARM through
 *                   interworking pointers and veneers
 *   unreferenced    nothing calls it or points to it: only the start
 *                   patterns find it
 *   poke_bad_slot   stores through a read-only pointer slot that holds
 *                   0xffffffff (rodata.c): folding it must not fail the
 *                   function
 *   mmio_*          memory-mapped I/O at 0xd0000000 (a declared region)
 */
#include <stdint.h>

#define NOINLINE __attribute__((noinline))
#define MMIO(a) (*(volatile uint32_t *)(a))

extern int thumb_sum(int a, int b);
extern int thumb_scale(int x);
extern uint32_t *const bad_slot;

volatile int sink;

NOINLINE int h0(int v) { sink = 10; return v + 1; }
NOINLINE int h1(int v) { sink = 11; return v * 3; }
NOINLINE int h2(int v) { sink = 12; return v - 7; }
NOINLINE int h3(int v) { sink = 13; return thumb_scale(v); }

/* In rodata.c, so the calls through it stay indirect. */
typedef int (*handler)(int);
extern const handler handlers[];
extern volatile int handler_count;

NOINLINE int dispatch(int op, int v) {
  switch (op) {
    case 0: return h0(v) + 5;
    case 1: return h1(v) ^ 9;
    case 2: return h2(v) * 7;
    case 3: return v << 3;
    case 4: return v - 100;
    case 5: return thumb_sum(v, op);
    case 6: return v | 0x40;
    case 7: return h3(v) + 1;
    default: return -1;
  }
}

NOINLINE void mmio_init(void) {
  MMIO(0xd0000010) = 1;
  MMIO(0xd0000014) = 0x200;
  while ((MMIO(0xd0000018) & 1) == 0) {}
}

NOINLINE uint32_t mmio_status(void) { return MMIO(0xd0000018) >> 4; }

NOINLINE void poke_bad_slot(uint32_t v) { *bad_slot = v; }

__attribute__((used)) NOINLINE int unreferenced(int a, int b, int c) {
  int r = 0;
  for (int i = 0; i < a; i++) r += (b * i) ^ c;
  sink = r;
  return r + h1(c);
}

void irq_handler(void) { sink = (int)mmio_status(); }

int main(void) {
  mmio_init();
  int acc = 0;
  for (int i = 0; i < handler_count; i++) acc += handlers[i](acc + i);
  for (int op = 0; op < 9; op++) acc += dispatch(op, acc);
  acc += thumb_sum(acc, 3);
  poke_bad_slot((uint32_t)acc);
#ifdef ARMFW_BULK
  /* build.sh with a function count: bulk.py's generated functions. */
  extern int bulk_root(int, int);
  acc += bulk_root(acc, 7);
#endif
  for (;;) sink = acc;
}
