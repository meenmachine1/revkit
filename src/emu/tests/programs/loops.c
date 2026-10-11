/* Loops: a sieve on the stack, Fibonacci, a sort of a global array, a
 * switch-driven state machine (a jump table), a matrix product. */
#include "rt.h"

static u32 table[32] = {9, 3, 27, 1, 88, 14, 5, 63, 2, 71, 40, 33, 18, 7, 95, 21,
                        11, 6, 59, 44, 30, 8, 77, 12, 4, 50, 26, 19, 66, 10, 38, 15};
static const char text[] = "the quick brown fox jumps over 13 lazy dogs, 42 times!";

int test_main(void) {
  int k = 0;
  u8 sieve[1000];
  for (int i = 0; i < 1000; i++) sieve[i] = 1;
  u64 primes = 0, psum = 0;
  for (int i = 2; i < 1000; i++) {
    if (!sieve[i]) continue;
    primes++;
    psum += (u64)i;
    for (int j = i * i; j < 1000; j += i) sieve[j] = 0;
  }
  rk_mem[k++] = primes;
  rk_mem[k++] = psum;
  u64 f0 = 0, f1 = 1;
  for (int i = 0; i < 90; i++) {
    u64 t = f0 + f1;
    f0 = f1;
    f1 = t;
  }
  rk_mem[k++] = f0;
  for (int i = 0; i < 32; i++)
    for (int j = 0; j + 1 < 32 - i; j++)
      if (table[j] > table[j + 1]) {
        u32 t = table[j];
        table[j] = table[j + 1];
        table[j + 1] = t;
      }
  u64 order = 0;
  for (int i = 0; i < 32; i++) order = order * 31 + table[i];
  rk_mem[k++] = order;
  u64 words = 0, digits = 0, num = 0, state = 0, other = 0;
  for (const char *p = text; *p; p++) {
    switch (*p) {
      case 'a': case 'e': case 'i': case 'o': case 'u': other += 3; /* fallthrough */
      case 'b': case 'c': case 'd': case 'f': case 'g': case 'h': case 'j': case 'k':
      case 'l': case 'm': case 'n': case 'p': case 'q': case 'r': case 's': case 't':
      case 'v': case 'w': case 'x': case 'y': case 'z':
        if (state != 1) words++;
        state = 1;
        break;
      case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9':
        num = num * 10 + (u64)(*p - '0');
        digits++;
        state = 2;
        break;
      case ' ': state = 0; break;
      default: other += 100; state = 3; break;
    }
  }
  rk_mem[k++] = words | digits << 16 | num << 32;
  rk_mem[k++] = other;
  i32 ma[8][8], mb[8][8], mc[8][8];
  for (int i = 0; i < 8; i++)
    for (int j = 0; j < 8; j++) {
      ma[i][j] = (i * 7 + j * 3) % 11 - 5;
      mb[i][j] = (i * 5 + j * 2) % 13 - 6;
    }
  for (int i = 0; i < 8; i++)
    for (int j = 0; j < 8; j++) {
      i32 acc = 0;
      for (int t = 0; t < 8; t++) acc += ma[i][t] * mb[t][j];
      mc[i][j] = acc;
    }
  u64 trace = 0;
  for (int i = 0; i < 8; i++) trace = trace * 1000003 + (u64)(i64)mc[i][(i * 3) % 8];
  rk_mem[k++] = trace;
  u64 collatz = 0;
  for (u64 n = 1; n < 60; n++) {
    u64 v = n;
    while (v != 1) {
      v = (v & 1) ? 3 * v + 1 : v / 2;
      collatz++;
    }
  }
  rk_mem[k++] = collatz;
  put_hex("loops", primes + collatz);
  return (int)(collatz % 100);
}
