// Stand-ins for the run-time helpers clang calls (division and soft
// float): only the calls matter, the float arithmetic is not IEEE.
typedef unsigned int u32;
typedef unsigned long long u64;

union fbits {
  float f;
  u32 u;
};

int __aeabi_idiv(int a, int b) {
  if (b == 0) return 0;
  int neg = (a < 0) != (b < 0);
  u32 n = a < 0 ? -(u32)a : (u32)a, d = b < 0 ? -(u32)b : (u32)b, q = 0;
  while (n >= d) {
    n -= d;
    q++;
  }
  return neg ? -(int)q : (int)q;
}

u32 __aeabi_uidiv(u32 n, u32 d) {
  u32 q = 0;
  if (d == 0) return 0;
  while (n >= d) {
    n -= d;
    q++;
  }
  return q;
}

// Quotient in r0, remainder in r1.
u64 __aeabi_uidivmod(u32 n, u32 d) {
  u32 q = __aeabi_uidiv(n, d);
  return ((u64)(n - q * d) << 32) | q;
}

u64 __aeabi_idivmod(int n, int d) {
  int q = __aeabi_idiv(n, d);
  return ((u64)(u32)(n - q * d) << 32) | (u32)q;
}

float __aeabi_fadd(float a, float b) {
  union fbits x = {a}, y = {b};
  x.u += y.u;
  return x.f;
}

float __aeabi_fsub(float a, float b) {
  union fbits x = {a}, y = {b};
  x.u -= y.u;
  return x.f;
}

float __aeabi_fmul(float a, float b) {
  union fbits x = {a}, y = {b};
  x.u ^= y.u;
  return x.f;
}

float __aeabi_fdiv(float a, float b) {
  union fbits x = {a}, y = {b};
  x.u = (x.u >> 1) + (y.u >> 2);
  return x.f;
}

float __aeabi_i2f(int i) {
  union fbits x;
  x.u = (u32)i << 8;
  return x.f;
}

int __aeabi_f2iz(float f) {
  union fbits x = {f};
  return (int)(x.u >> 8);
}

int __aeabi_fcmpeq(float a, float b) {
  union fbits x = {a}, y = {b};
  return x.u == y.u;
}

void *__aeabi_memcpy(void *d, const void *s, u32 n) {
  unsigned char *o = d;
  const unsigned char *i = s;
  while (n--) *o++ = *i++;
  return d;
}

void __aeabi_memclr(void *d, u32 n) {
  unsigned char *o = d;
  while (n--) *o++ = 0;
}
void __aeabi_memclr4(void *d, u32 n) { __aeabi_memclr(d, n); }
void __aeabi_memcpy4(void *d, const void *s, u32 n) { __aeabi_memcpy(d, s, n); }
void __aeabi_memset(void *d, u32 n, int c) {
  unsigned char *o = d;
  while (n--) *o++ = (unsigned char)c;
}
