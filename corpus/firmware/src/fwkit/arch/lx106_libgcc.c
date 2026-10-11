/* Integer division and widening multiplication for the ESP8266's L106
 * (no divider), which Debian's xtensa-lx106 libgcc leaves out. */
#include <stdint.h>

uint64_t __udivmoddi4(uint64_t a, uint64_t b, uint64_t *rem);
int64_t __divmoddi4(int64_t a, int64_t b, int64_t *rem);

static uint32_t udivmod32(uint32_t n, uint32_t d, uint32_t *rem) {
  uint32_t q = 0, r = 0;
  int i;
  if (d == 0) {
    if (rem) *rem = n;
    return 0xffffffffu;
  }
  for (i = 31; i >= 0; i--) {
    r = (r << 1) | ((n >> i) & 1);
    if (r >= d) {
      r -= d;
      q |= 1u << i;
    }
  }
  if (rem) *rem = r;
  return q;
}

uint32_t __udivsi3(uint32_t n, uint32_t d) { return udivmod32(n, d, 0); }

uint32_t __umodsi3(uint32_t n, uint32_t d) {
  uint32_t r;
  udivmod32(n, d, &r);
  return r;
}

int32_t __divsi3(int32_t n, int32_t d) {
  int neg = (n < 0) != (d < 0);
  uint32_t q = udivmod32(n < 0 ? -(uint32_t)n : (uint32_t)n, d < 0 ? -(uint32_t)d : (uint32_t)d, 0);
  return neg ? -(int32_t)q : (int32_t)q;
}

uint64_t __umulsidi3(uint32_t a, uint32_t b) {
  uint32_t al = a & 0xffff, ah = a >> 16, bl = b & 0xffff, bh = b >> 16;
  uint32_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
  uint32_t mid = (ll >> 16) + (lh & 0xffff) + (hl & 0xffff);
  uint32_t lo = (ll & 0xffff) | (mid << 16);
  uint32_t hi = hh + (lh >> 16) + (hl >> 16) + (mid >> 16);
  return (uint64_t)hi << 32 | lo;
}

uint64_t __udivdi3(uint64_t a, uint64_t b) { return __udivmoddi4(a, b, 0); }

uint64_t __umoddi3(uint64_t a, uint64_t b) {
  uint64_t r;
  __udivmoddi4(a, b, &r);
  return r;
}

int64_t __divdi3(int64_t a, int64_t b) { return __divmoddi4(a, b, 0); }
