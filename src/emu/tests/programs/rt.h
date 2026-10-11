/* A freestanding runtime for the emulator's real-execution tests: system
 * calls, output helpers, a static stack (so stack addresses are the same
 * natively, under qemu-user and in the emulator), and rk_finish(), which
 * saves every general register (and the flags) where the test can compare
 * them, then prints them and the test's memory and exits. Built for
 * x86-64, AArch64 and RISC-V 64 with -nostdlib -static. */
#pragma once

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef int i32;
typedef unsigned short u16;
typedef unsigned char u8;

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_brk 12
#define SYS_exit 60
#define SYS_getpid 39
#define RK_NREGS 17
static inline i64 rk_syscall(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  register i64 r10 __asm__("r10") = d, r8 __asm__("r8") = e, r9 __asm__("r9") = f;
  i64 r;
  __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
  return r;
}
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_write 64
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_brk 214
#define SYS_exit 93
#define SYS_getpid 172
#define RK_NREGS 33
static inline i64 rk_syscall(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  register i64 x8 __asm__("x8") = n, x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c,
                x3 __asm__("x3") = d, x4 __asm__("x4") = e, x5 __asm__("x5") = f;
  __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
  return x0;
}
#elif defined(__riscv) && __riscv_xlen == 64
#define SYS_read 63
#define SYS_write 64
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_brk 214
#define SYS_exit 93
#define SYS_getpid 172
#define RK_NREGS 32
static inline i64 rk_syscall(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  register i64 a7 __asm__("a7") = n, a0 __asm__("a0") = a, a1 __asm__("a1") = b, a2 __asm__("a2") = c,
                a3 __asm__("a3") = d, a4 __asm__("a4") = e, a5 __asm__("a5") = f;
  __asm__ volatile("ecall" : "+r"(a0) : "r"(a7), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5) : "memory");
  return a0;
}
#else
#error "unsupported target"
#endif

static inline i64 sys_write(int fd, const void *buf, u64 n) { return rk_syscall(SYS_write, fd, (i64)buf, (i64)n, 0, 0, 0); }

static u64 rk_strlen(const char *s) {
  u64 n = 0;
  while (s[n]) n++;
  return n;
}

static void put(const char *s) { sys_write(1, s, rk_strlen(s)); }

static void put_hex(const char *label, u64 v) {
  char buf[64];
  int n = 0;
  while (label[n] && n < 40) {
    buf[n] = label[n];
    n++;
  }
  buf[n++] = '=';
  for (int i = 15; i >= 0; i--) buf[n++] = "0123456789abcdef"[(v >> (4 * i)) & 15];
  buf[n++] = '\n';
  sys_write(1, buf, (u64)n);
}

/* Memory the test fills; rk_report prints it. */
extern u64 rk_mem[64];
/* Saved by rk_finish: general registers, then the flags. */
extern u64 rk_regs[40];

__attribute__((noreturn)) void rk_finish(void);
int test_main(void);
