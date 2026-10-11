// Freestanding fixture for a computed goto (labels as values), the opcode
// dispatch of interpreters such as CPython's: no guard and no mask, the
// index a zero-extended byte. Each handler calls g0..g5, which are found
// only by following the table, and interp's body must cover them all.

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
#define G(n) NOINLINE int g##n(int v) { sink = n; return v * (n + 5) + n; }
G(0) G(1) G(2) G(3) G(4) G(5)

NOINLINE int interp(const unsigned char *pc, int acc) {
  static void *const ops[256] = {[0] = &&op0, [1] = &&op1, [2] = &&op2, [3] = &&op3,
                                 [4] = &&op4, [5] = &&op5, [6 ... 255] = &&done};
  goto *ops[*pc++];
op0: acc = g0(acc); goto *ops[*pc++];
op1: acc = g1(acc) ^ 3; goto *ops[*pc++];
op2: acc = g2(acc) + 7; goto *ops[*pc++];
op3: acc = g3(acc) * 5; goto *ops[*pc++];
op4: acc = g4(acc) - 11; goto *ops[*pc++];
op5: acc = g5(acc) | 1; goto *ops[*pc++];
done:
  return acc;
}

void _start(void) {
  static const unsigned char prog[] = {0, 1, 2, 3, 4, 5, 9};
  sys_exit(interp(prog, 1));
}
