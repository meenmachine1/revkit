/* Calls: recursion, function pointers, varargs, structs by value, many
 * arguments (some on the stack), a callback-driven sort. */
#include <stdarg.h>
#include "rt.h"

struct triple {
  u64 a, b, c;
};

__attribute__((noinline)) static u64 fib(u32 n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
__attribute__((noinline)) static u64 ack(u64 m, u64 n) {
  if (m == 0) return n + 1;
  if (n == 0) return ack(m - 1, 1);
  return ack(m - 1, ack(m, n - 1));
}
__attribute__((noinline)) static i64 sum_va(int n, ...) {
  va_list ap;
  va_start(ap, n);
  i64 s = 0;
  for (int i = 0; i < n; i++) s = s * 3 + va_arg(ap, i64);
  va_end(ap);
  return s;
}
__attribute__((noinline)) static struct triple make(u64 x) {
  struct triple t = {x, x * x, x ^ 0x5555};
  return t;
}
__attribute__((noinline)) static u64 many(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g, u64 h, u64 i, u64 j, u64 k) {
  return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h + 9 * i + 10 * j + 11 * k;
}
static u64 op_add(u64 x) { return x + 17; }
static u64 op_mul(u64 x) { return x * 3; }
static u64 op_xor(u64 x) { return x ^ 0xabcdef; }
static u64 (*const ops[])(u64) = {op_add, op_mul, op_xor, op_mul, op_add};
static volatile int zero = 0;

static int cmp_desc(const void *a, const void *b) {
  i32 x = *(const i32 *)a, y = *(const i32 *)b;
  return (x < y) - (x > y);
}
__attribute__((noinline)) static void isort(void *base, int n, int size, int (*cmp)(const void *, const void *)) {
  u8 *p = base;
  u8 tmp[16];
  for (int i = 1; i < n; i++)
    for (int j = i; j > 0 && cmp(p + (j - 1) * size, p + j * size) > 0; j--) {
      for (int t = 0; t < size; t++) tmp[t] = p[(j - 1) * size + t];
      for (int t = 0; t < size; t++) p[(j - 1) * size + t] = p[j * size + t];
      for (int t = 0; t < size; t++) p[j * size + t] = tmp[t];
    }
}

int test_main(void) {
  int k = 0;
  rk_mem[k++] = fib(18 + (u32)zero);
  rk_mem[k++] = ack(2, 3 + (u64)zero);
  rk_mem[k++] = (u64)sum_va(6, (i64)1, (i64)-2, (i64)3, (i64)-4, (i64)5, (i64)600000000000);
  struct triple t = make(12345 + (u64)zero);
  rk_mem[k++] = t.a + t.b * 3 + t.c * 7;
  rk_mem[k++] = many(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 + (u64)zero);
  u64 v = 1;
  for (int i = 0; i < 20; i++) v = ops[(i + zero) % 5](v);
  rk_mem[k++] = v;
  i32 arr[12] = {5, -3, 12, 0, 7, 7, -20, 33, 1, 2, 9, -1};
  isort(arr, 12, 4, cmp_desc);
  u64 h = 0;
  for (int i = 0; i < 12; i++) h = h * 131 + (u64)(i64)arr[i];
  rk_mem[k++] = h;
  put_hex("calls", rk_mem[0] + rk_mem[k - 1]);
  return (int)(rk_mem[1] & 0x3f);
}
