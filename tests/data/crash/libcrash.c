/* libcrash.so for the crash dump tests (docs/crash-dumps.md): the fault
   happens two calls deep in this library, so the backtrace has to unwind
   through it by its call-frame information (built without frame pointers). */
#include <stddef.h>

__attribute__((noinline)) int lib_store(int *where, int value) {
  *where = value;  /* the fault: where is NULL */
  return value + 1;
}

__attribute__((noinline)) int lib_compute(int *where, int n) {
  int total = 0;
  for (int i = 0; i < n; ++i) total += i * 3;
  return lib_store(where, total) + total;
}
