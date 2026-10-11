/* System calls: stdout, stderr, a bad descriptor, reading an empty stdin,
 * and the exit status. */
#include "rt.h"

int test_main(void) {
  int k = 0;
  rk_mem[k++] = (u64)sys_write(1, "out: hello\n", 11);
  rk_mem[k++] = (u64)sys_write(2, "err: world\n", 11);
  rk_mem[k++] = (u64)sys_write(99, "x", 1);
  char in[16];
  rk_mem[k++] = (u64)rk_syscall(SYS_read, 0, (i64)in, sizeof in, 0, 0, 0);
  rk_mem[k++] = (u64)rk_syscall(SYS_write, 1, (i64)"two\nlines\n", 10, 0, 0, 0);
  return 42;
}
