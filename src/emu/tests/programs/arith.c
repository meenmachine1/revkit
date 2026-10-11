/* Integer arithmetic at every width, signed and unsigned division, shifts,
 * 128-bit products, overflow and comparison flags. */
#include "rt.h"

static volatile u64 seed_a = 0x123456789abcdef1ul;
static volatile u64 seed_b = 0xfedcba9876543210ul;
static volatile i64 seed_c = -1234567;

int test_main(void) {
  const u64 a = seed_a, b = seed_b;
  const i64 c = seed_c;
  int k = 0;
  rk_mem[k++] = a + b;
  rk_mem[k++] = a - b;
  rk_mem[k++] = a * b;
  rk_mem[k++] = a / ((b >> 40) | 1);
  rk_mem[k++] = a % 12345;
  rk_mem[k++] = (u64)((i64)a / c);
  rk_mem[k++] = (u64)((i64)b % c);
  rk_mem[k++] = (u64)((i64)b >> 13);
  rk_mem[k++] = (a << 17) | (a >> 47);
  const u32 x = (u32)a, y = (u32)b;
  rk_mem[k++] = (u64)(x * y);
  rk_mem[k++] = (u64)(x / (y | 1));
  rk_mem[k++] = (u64)(i64)((i32)y >> 5);
  rk_mem[k++] = (u64)(i64)(i32)((i32)x / (i32)(c | 1));
  rk_mem[k++] = (u64)(u8)(x + y) | (u64)(u16)(x * 3) << 8 | (u64)(i64)(signed char)(y >> 3) << 24;
  const unsigned __int128 m = (unsigned __int128)a * b;
  rk_mem[k++] = (u64)(m >> 64);
  rk_mem[k++] = (u64)m;
  const __int128 sm = (__int128)(i64)a * c;
  rk_mem[k++] = (u64)((unsigned __int128)sm >> 64);
  const unsigned __int128 q = (((unsigned __int128)a << 64) | b) / (b | 1);
  rk_mem[k++] = (u64)(q >> 64);
  rk_mem[k++] = (u64)q;
  u64 r;
  i64 sr;
  rk_mem[k++] = (u64)__builtin_add_overflow(a, b, &r) | (u64)__builtin_sub_overflow(a, b, &r) << 1 |
                (u64)__builtin_mul_overflow((i64)a, c, &sr) << 2 | (u64)__builtin_add_overflow((i64)a, (i64)a, &sr) << 3;
  rk_mem[k++] = (u64)((i64)a < c) | (u64)(a < b) << 1 | (u64)((i64)a <= (i64)b) << 2 | (u64)((i32)x > (i32)y) << 3 |
                (u64)(x >= y) << 4 | (u64)((i64)b > c) << 5 | (u64)(a == b) << 6 | (u64)(x != y) << 7;
  rk_mem[k++] = (u64)__builtin_popcountll(a) | (u64)__builtin_clzll(b >> 9) << 8 | (u64)__builtin_ctzll(a & ~0xfful) << 16;
  rk_mem[k++] = __builtin_bswap64(a);
  rk_mem[k++] = (u64)__builtin_bswap32(x);
  u64 h = 0xcbf29ce484222325ul;
  for (int i = 0; i < 64; i++) {
    h ^= (u8)(a >> (i % 64)) + (u8)i;
    h *= 0x100000001b3ul;
  }
  rk_mem[k++] = h;
  /* Shifts by variable amounts, including ones C leaves to the machine. */
  u64 s = 0;
  for (u32 i = 0; i < 64; i++) s += (a >> i) ^ (b << (63 - i)) ^ (u64)((i64)a >> (i & 31));
  rk_mem[k++] = s;
  put_hex("arith", rk_mem[0] ^ rk_mem[k - 1]);
  return (int)(h & 0x7f);
}
