/* The crashing program of the crash dump tests (docs/crash-dumps.md):
   main starts a second thread that blocks, then calls into libcrash.so,
   which stores through a null pointer (SIGSEGV, SEGV_MAPERR at address 0).
   With "stop" as its argument it stops itself first (SIGSTOP) so a test
   can take the core with gcore instead. */
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int lib_compute(int *where, int n);

static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t never = PTHREAD_COND_INITIALIZER;
static volatile int ready;

static void *waiter(void *arg) {
  (void)arg;
  pthread_mutex_lock(&gate);
  ready = 1;
  pthread_cond_wait(&never, &gate);
  pthread_mutex_unlock(&gate);
  return NULL;
}

__attribute__((noinline)) int run_crash(int *target) {
  int r = lib_compute(target, 5);
  printf("not reached %d\n", r);
  return r;
}

int main(int argc, char **argv) {
  pthread_t t;
  pthread_create(&t, NULL, waiter, NULL);
  while (!ready) usleep(1000);
  if (argc > 1 && strcmp(argv[1], "stop") == 0) raise(SIGSTOP);
  return run_crash(NULL);
}
