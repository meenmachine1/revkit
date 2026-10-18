// A small C program for the Mach-O loader's tests (build.sh). Its calls go
// to libSystem (stubs and binds), its data has pointers to code and strings
// (rebases), and it has a static function, a global and a common symbol.
int printf(const char *, ...);
int puts(const char *);

static int counter = 3;
int shared_total;

int add(int a, int b) { return a + b + counter; }

__attribute__((noinline)) static int twice(int x) { return 2 * x + shared_total; }

int (*table[])(int, int) = {add};
const char *greeting = "hello %d\n";

int main(int argc, char **argv) {
  printf(greeting, table[0](argc, 2));
  puts(argv[0]);
  return twice(argc);
}
