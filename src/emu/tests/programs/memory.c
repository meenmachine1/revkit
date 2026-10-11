/* Memory: the program break, anonymous mappings, a variable-length array,
 * byte, half and word stores at odd offsets, and a static array. */
#include "rt.h"

static volatile int length = 777;
static u8 buffer[300];

static u64 checksum(const u8 *p, u64 n) {
  u64 h = 1469598103934665603ul;
  for (u64 i = 0; i < n; i++) h = (h ^ p[i]) * 1099511628211ul;
  return h;
}

int test_main(void) {
  int k = 0;
  /* brk: grow by three pages and a bit, write all of it. */
  u64 start = (u64)rk_syscall(SYS_brk, 0, 0, 0, 0, 0, 0);
  u64 end = (u64)rk_syscall(SYS_brk, (i64)(start + 3 * 4096 + 100), 0, 0, 0, 0, 0);
  rk_mem[k++] = end - start;
  u8 *heap = (u8 *)start;
  for (u64 i = 0; i < end - start; i++) heap[i] = (u8)(i * 7 + (i >> 8));
  rk_mem[k++] = checksum(heap, end - start);
  /* An anonymous mapping of two pages. */
  i64 map = rk_syscall(SYS_mmap, 0, 8192, 3, 0x22, -1, 0);
  rk_mem[k++] = map < 0 ? (u64)map : 0;
  u64 *words = (u64 *)map;
  for (int i = 0; i < 1024; i++) words[i] = (u64)i * 0x9e3779b97f4a7c15ul;
  rk_mem[k++] = checksum((const u8 *)words, 8192);
  rk_mem[k++] = (u64)rk_syscall(SYS_munmap, map, 8192, 0, 0, 0, 0);
  /* A VLA on the stack, filled backwards. */
  u8 vla[length];
  for (int i = length - 1; i >= 0; i--) vla[i] = (u8)(i ^ 0x5a);
  rk_mem[k++] = checksum(vla, (u64)length);
  /* Unaligned stores of every width into a static buffer. */
  for (int i = 0; i < 40; i++) {
    *(volatile u8 *)(buffer + 3 * i) = (u8)i;
    *(volatile u16 *)(buffer + 3 * i + 1) = (u16)(i * 1000);
    *(volatile u32 *)(buffer + 150 + 3 * i) = (u32)(i * 0x01010101u);
  }
  *(volatile u64 *)(buffer + 271) = 0x0102030405060708ul;
  rk_mem[k++] = checksum(buffer, sizeof buffer);
  for (int i = 0; i < 16; i++) rk_mem[32 + i] = *(volatile u64 *)(buffer + 17 * i);
  put_hex("memory", rk_mem[1] ^ rk_mem[5]);
  return 3;
}
