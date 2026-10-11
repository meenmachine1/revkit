// Dynamically linked fixture: imports called through PLT stubs (or the
// GOT with -fno-plt), two of them no-return by name, and a local function
// that never returns because it ends in exit().
#include <stdio.h>
#include <stdlib.h>
__attribute__((noinline)) static void die(const char *m) { puts(m); exit(2); }
int main(int argc, char **argv) {
  if (argc > 3) die("too many");
  if (argc > 2) abort();
  puts(argv[0]);
  return 0;
}
