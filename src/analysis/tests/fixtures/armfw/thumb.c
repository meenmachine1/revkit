/* Synthetic ARM firmware (Thumb code): reached from ARM code through
 * interworking (a function pointer with the low bit set, and BL through
 * a linker veneer). */
#define NOINLINE __attribute__((noinline))
extern volatile int sink;

NOINLINE static int thumb_helper(int x) { sink = x; return x * 5 + 1; }

NOINLINE int thumb_scale(int x) { return thumb_helper(x) << 2; }

NOINLINE int thumb_sum(int a, int b) {
  int r = 0;
  for (int i = 0; i < b; i++) r += thumb_helper(a + i);
  return r;
}
