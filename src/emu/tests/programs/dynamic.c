/* A dynamically linked program: everything it imports runs as the
 * emulator's library stubs (puts, printf, malloc, strlen, ...), from
 * __libc_start_main to exit. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int square(int x) { return x * x; }

int main(int argc, char **argv) {
  char *buf = malloc(64);
  strcpy(buf, "emulated");
  memset(buf + 8, '!', 3);
  buf[11] = 0;
  puts(buf);
  int total = 0;
  for (int i = 0; i < 10; i++) total += square(i);
  printf("argc=%d len=%lu total=%d hex=%x str=%s\n", argc, (unsigned long)strlen(buf), total, total * 3, argv[0] ? "ok" : "none");
  char *copy = calloc(4, 4);
  memcpy(copy, buf, 5);
  printf("%s %d\n", copy, strcmp(copy, "emula") == 0);
  free(copy);
  return total % 64;
}
