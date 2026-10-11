// Freestanding fixture for function discovery. Linked without libc and,
// in the stripped build, without symbols or unwind tables, so the entry
// point is the only seed: every other function must be found by following
// calls, including calls reached only through jump tables.
//
//   sys_exit, fail   never return: no path reaches a return
//   check            calls fail on one path; nothing after that call is code
//   dispatch         a guarded switch (jump table) whose cases call m0..m9
//   masked           a switch on x & 7 with no default, so no guard

#define NOINLINE __attribute__((noinline))

#if defined(__x86_64__)
NOINLINE static void sys_exit(long code) {
  __asm__ volatile("mov $60, %%eax\n\tsyscall" : : "D"(code) : "rax", "rcx", "r11", "memory");
  for (;;) {}
}
#elif defined(__aarch64__)
NOINLINE static void sys_exit(long code) {
  register long x0 __asm__("x0") = code;
  register long x8 __asm__("x8") = 93;
  __asm__ volatile("svc 0" : : "r"(x0), "r"(x8) : "memory");
  for (;;) {}
}
#elif defined(__riscv)
NOINLINE static void sys_exit(long code) {
  register long a0 __asm__("a0") = code;
  register long a7 __asm__("a7") = 93;
  __asm__ volatile("ecall" : : "r"(a0), "r"(a7) : "memory");
  for (;;) {}
}
#endif

volatile int sink;
#define MARK(n) NOINLINE int m##n(int v) { sink = n; return v * (n + 3) + n; }
MARK(0) MARK(1) MARK(2) MARK(3) MARK(4) MARK(5) MARK(6) MARK(7) MARK(8)
// With -DSPLIT_PAGES, m9 starts a page of its own (for incremental tests).
#ifdef SPLIT_PAGES
__attribute__((aligned(4096)))
#endif
MARK(9)
#define MASKED(n) NOINLINE int k##n(int v) { sink = 100 + n; return v - n; }
MASKED(0) MASKED(1) MASKED(2) MASKED(3) MASKED(4) MASKED(5) MASKED(6) MASKED(7)

NOINLINE static void fail(int code) { sys_exit(100 + code); }

NOINLINE static int check(int x) {
  if (x < 0) fail(x);
  return x * 2;
}

NOINLINE int dispatch(int op, int v) {
  switch (op) {
    case 0: return m0(v);
    case 1: return m1(v);
    case 2: return m2(v);
    case 3: return m3(v);
    case 4: return m4(v);
    case 5: return m5(v);
    case 6: return m6(v);
    case 7: return m7(v);
    case 8: return m8(v);
    case 9: return m9(v);
    default: return -1;
  }
}

NOINLINE int masked(unsigned x, int v) {
  switch (x & 7) {
    case 0: return k0(v);
    case 1: return k1(v);
    case 2: return k2(v);
    case 3: return k3(v);
    case 4: return k4(v);
    case 5: return k5(v);
    case 6: return k6(v);
    default: return k7(v);
  }
}

void _start(void) {
  volatile int n = 3;
  int r = check(n);
  r += dispatch(n, r);
  r += masked((unsigned)n, r);
  sys_exit(r);
}
