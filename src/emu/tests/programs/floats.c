/* Floating point: arithmetic, square roots, conversions both ways and
 * between sizes, comparisons with NaN and infinity. */
#include "rt.h"

static volatile double seed = 1.0;
static volatile float fseed = 3.25f;
static volatile i64 iseed = -987654321;

static u64 bits(double d) {
  union {
    double d;
    u64 u;
  } x = {d};
  return x.u;
}
static u32 fbits(float f) {
  union {
    float f;
    u32 u;
  } x = {f};
  return x.u;
}

int test_main(void) {
  int k = 0;
  double h = 0;
  for (int i = 1; i <= 100; i++) h += seed / i;
  rk_mem[k++] = bits(h);
  rk_mem[k++] = bits(__builtin_sqrt(h * 1000.0));
  rk_mem[k++] = bits(h * h - 3.0 / h);
  float f = fseed;
  for (int i = 0; i < 10; i++) f = f * 1.5f - 0.25f;
  rk_mem[k++] = fbits(f);
  rk_mem[k++] = bits((double)f / 7.0);
  rk_mem[k++] = (u64)(i64)(h * -1e6);
  rk_mem[k++] = (u64)(i64)(-2.5 * seed);
  rk_mem[k++] = bits((double)iseed);
  rk_mem[k++] = fbits((float)iseed);
  rk_mem[k++] = (u64)(1e19 * seed);
  rk_mem[k++] = (u64)(u32)(4e9 * seed);
  const double inf = seed / 0.0, nan = inf - inf;
  rk_mem[k++] = (u64)(nan == nan) | (u64)(nan != nan) << 1 | (u64)(nan < 1.0) << 2 | (u64)(inf > 1e308) << 3 |
                (u64)(-inf < -1e308) << 4 | (u64)(h >= h) << 5 | (u64)(f < h) << 6;
  rk_mem[k++] = bits(__builtin_fabs(-h)) ^ bits(-h);
  double acc = 0;
  for (int i = 0; i < 50; i++) acc += (i & 1 ? -1.0 : 1.0) * (double)i * 0.1 * seed;
  rk_mem[k++] = bits(acc);
  rk_mem[k++] = (u64)(i64)(acc * 100.0);
  put_hex("floats", rk_mem[0] ^ rk_mem[3]);
  return (int)(rk_mem[5] & 0x7f);
}
