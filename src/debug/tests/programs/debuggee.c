/* The live debugging tests' program: calls to step over and out of,
 * recursion, a global to watch, a string to read and change, a thread. */
#include <pthread.h>
#include <stdio.h>
#include <string.h>

volatile int counter;
char message[32] = "hello, debugger";

__attribute__((noinline)) int leaf(int x) {
  counter += x;
  return x * 3;
}

__attribute__((noinline)) int middle(int x) {
  int r = leaf(x + 1);
  return r + 1;
}

__attribute__((noinline)) int fact(int n) { return n <= 1 ? 1 : n * fact(n - 1); }

static void *worker(void *arg) {
  (void)arg;
  for (int i = 0; i < 3; i++) leaf(i);
  return NULL;
}

int main(int argc, char **argv) {
  int a = middle(argc);
  int f = fact(5);
  message[0] = 'H';
  if (argc > 1 && strcmp(argv[1], "threads") == 0) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
  }
  printf("%s %d %d\n", message, a, f);
  fflush(stdout);
  return a + f == 127 ? 0 : 1;
}
