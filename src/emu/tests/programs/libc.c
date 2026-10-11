/* A statically linked glibc program: the C library's own start-up (TLS,
 * IRELATIVE resolvers choosing routines by CPUID or HWCAP), malloc,
 * stdio with floating point, exit handlers. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int calls;
static void bye(void) { printf("atexit after %d\n", calls); }

int main(int argc, char **argv) {
  atexit(bye);
  char *p = malloc(100);
  snprintf(p, 100, "%d %s %.3f %x", 42, strrchr(argv[0], '/') ? "path" : "name", 3.14159, 0xbeef);
  puts(p);
  long sum = 0;
  for (int i = 0; i < 1000; i++) sum += strlen(p) * i;
  calls = (int)(sum % 97);
  printf("%ld %zu\n", sum, strlen(p));
  free(p);
  return 7;
}
