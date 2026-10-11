/* A read-only pointer slot holding 0xffffffff, as erased flash reads: a
 * decompiler that folds read-only memory must not fail on a store through
 * it (the folded address range would run past the top of memory). */
#include <stdint.h>
uint32_t *const bad_slot = (uint32_t *)0xffffffffu;

/* A table of code pointers in read-only data (one of them Thumb). */
typedef int (*handler)(int);
extern int h0(int), h1(int), h2(int), h3(int), thumb_scale(int);
const handler handlers[] = {h0, h1, h2, h3, thumb_scale};
volatile int handler_count = 5;
