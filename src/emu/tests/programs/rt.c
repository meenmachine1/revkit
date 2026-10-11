/* The runtime of the real-execution tests (see rt.h). */
#include "rt.h"

u64 rk_mem[64];
u64 rk_regs[40];
int rk_exit_code;
u8 rk_stack[1 << 16] __attribute__((aligned(16)));

/* What -O2 may call even in freestanding code. */
void *memcpy(void *d, const void *s, u64 n) {
  u8 *dd = d;
  const u8 *ss = s;
  while (n--) *dd++ = *ss++;
  return d;
}
void *memmove(void *d, const void *s, u64 n) {
  u8 *dd = d;
  const u8 *ss = s;
  if (dd < ss) {
    while (n--) *dd++ = *ss++;
  } else {
    while (n--) dd[n] = ss[n];
  }
  return d;
}
void *memset(void *d, int c, u64 n) {
  u8 *dd = d;
  while (n--) *dd++ = (u8)c;
  return d;
}
int memcmp(const void *a, const void *b, u64 n) {
  const u8 *x = a, *y = b;
  for (u64 i = 0; i < n; i++)
    if (x[i] != y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}

__attribute__((noreturn, used)) void rk_report(void) {
  char label[4] = "r00";
  for (int i = 0; i < RK_NREGS; i++) {
    label[1] = (char)('0' + i / 10);
    label[2] = (char)('0' + i % 10);
    put_hex(label, rk_regs[i]);
  }
  label[0] = 'm';
  for (int i = 0; i < 64; i++) {
    label[1] = (char)('0' + i / 10);
    label[2] = (char)('0' + i % 10);
    put_hex(label, rk_mem[i]);
  }
  rk_syscall(SYS_exit, rk_exit_code, 0, 0, 0, 0, 0);
  for (;;) {
  }
}

__attribute__((noreturn, used)) void rk_main_c(void) {
  rk_exit_code = test_main();
  rk_finish();
}

#if defined(__x86_64__)
__asm__(
    ".text\n"
    ".globl _start\n"
    "_start:\n"
    "  lea rk_stack+65536(%rip), %rsp\n"
    "  call rk_main_c\n"
    "  hlt\n"
    ".globl rk_finish\n"
    "rk_finish:\n"
    "  movq %rax, rk_regs+0(%rip)\n"
    "  movq %rbx, rk_regs+8(%rip)\n"
    "  movq %rcx, rk_regs+16(%rip)\n"
    "  movq %rdx, rk_regs+24(%rip)\n"
    "  movq %rsi, rk_regs+32(%rip)\n"
    "  movq %rdi, rk_regs+40(%rip)\n"
    "  movq %rbp, rk_regs+48(%rip)\n"
    "  movq %rsp, rk_regs+56(%rip)\n"
    "  movq %r8, rk_regs+64(%rip)\n"
    "  movq %r9, rk_regs+72(%rip)\n"
    "  movq %r10, rk_regs+80(%rip)\n"
    "  movq %r11, rk_regs+88(%rip)\n"
    "  movq %r12, rk_regs+96(%rip)\n"
    "  movq %r13, rk_regs+104(%rip)\n"
    "  movq %r14, rk_regs+112(%rip)\n"
    "  movq %r15, rk_regs+120(%rip)\n"
    "  pushfq\n"
    "  popq %rax\n"
    "  movq %rax, rk_regs+128(%rip)\n"
    "  andq $-16, %rsp\n"
    "  call rk_report\n");
#elif defined(__aarch64__)
__asm__(
    ".text\n"
    ".globl _start\n"
    "_start:\n"
    "  adrp x0, rk_stack+65536\n"
    "  add x0, x0, :lo12:rk_stack+65536\n"
    "  mov sp, x0\n"
    "  cmp x0, #1\n" /* the flags as hardware, qemu-user and the emulator agree on */
    "  bl rk_main_c\n"
    "  b .\n"
    ".globl rk_finish\n"
    "rk_finish:\n"
    "  sub sp, sp, #16\n"
    "  str x16, [sp]\n"
    "  adrp x16, rk_regs\n"
    "  add x16, x16, :lo12:rk_regs\n"
    "  stp x0, x1, [x16, #0]\n"
    "  stp x2, x3, [x16, #16]\n"
    "  stp x4, x5, [x16, #32]\n"
    "  stp x6, x7, [x16, #48]\n"
    "  stp x8, x9, [x16, #64]\n"
    "  stp x10, x11, [x16, #80]\n"
    "  stp x12, x13, [x16, #96]\n"
    "  stp x14, x15, [x16, #112]\n"
    "  ldr x0, [sp]\n"
    "  str x0, [x16, #128]\n"
    "  str x17, [x16, #136]\n"
    "  stp x18, x19, [x16, #144]\n"
    "  stp x20, x21, [x16, #160]\n"
    "  stp x22, x23, [x16, #176]\n"
    "  stp x24, x25, [x16, #192]\n"
    "  stp x26, x27, [x16, #208]\n"
    "  stp x28, x29, [x16, #224]\n"
    "  str x30, [x16, #240]\n"
    "  add sp, sp, #16\n"
    "  mov x0, sp\n"
    "  str x0, [x16, #248]\n"
    "  mrs x0, nzcv\n"
    "  str x0, [x16, #256]\n"
    "  bl rk_report\n");
#elif defined(__riscv)
__asm__(
    ".text\n"
    ".globl _start\n"
    "_start:\n"
    "  .option push\n"
    "  .option norelax\n"
    "  lla gp, __global_pointer$\n"
    "  .option pop\n"
    "  lla sp, rk_stack+65536\n"
    "  call rk_main_c\n"
    "  j .\n"
    ".globl rk_finish\n"
    "rk_finish:\n"
    "  addi sp, sp, -16\n"
    "  sd t6, 0(sp)\n"
    "  lla t6, rk_regs\n"
    "  sd x1, 8(t6)\n"
    "  sd x3, 24(t6)\n"
    "  sd x4, 32(t6)\n"
    "  sd x5, 40(t6)\n"
    "  sd x6, 48(t6)\n"
    "  sd x7, 56(t6)\n"
    "  sd x8, 64(t6)\n"
    "  sd x9, 72(t6)\n"
    "  sd x10, 80(t6)\n"
    "  sd x11, 88(t6)\n"
    "  sd x12, 96(t6)\n"
    "  sd x13, 104(t6)\n"
    "  sd x14, 112(t6)\n"
    "  sd x15, 120(t6)\n"
    "  sd x16, 128(t6)\n"
    "  sd x17, 136(t6)\n"
    "  sd x18, 144(t6)\n"
    "  sd x19, 152(t6)\n"
    "  sd x20, 160(t6)\n"
    "  sd x21, 168(t6)\n"
    "  sd x22, 176(t6)\n"
    "  sd x23, 184(t6)\n"
    "  sd x24, 192(t6)\n"
    "  sd x25, 200(t6)\n"
    "  sd x26, 208(t6)\n"
    "  sd x27, 216(t6)\n"
    "  sd x28, 224(t6)\n"
    "  sd x29, 232(t6)\n"
    "  sd x30, 240(t6)\n"
    "  ld t5, 0(sp)\n"
    "  sd t5, 248(t6)\n"
    "  addi t5, sp, 16\n"
    "  sd t5, 16(t6)\n"
    "  addi sp, sp, 16\n"
    "  call rk_report\n");
#endif
