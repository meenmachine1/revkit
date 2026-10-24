// Seven arguments, four in registers and three on the stack (kit.h).
#include "kit.h"

// Not inlined: an SDK routine its callers call.
__attribute__((noinline)) int mix7(int a, int b, int c, int d, int e, int f, int g) {
  return (a * 3 + b) ^ (c - d) ^ (e * f) ^ (g << 2);
}

int use_mix(int x, int y) { return mix7(x, y, x + y, x - y, 7, y * 2, x * 5) + mix7(y, x, 1, 2, 3, 4, x); }

int use_mix_dev(struct dev *d, int k) {
  return mix7(d->id, d->count, k, (int)d->flags, d->state, k * 3, d->id + k);
}

