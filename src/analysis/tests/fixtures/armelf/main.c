/* A stripped dynamic ARM program: its commands are reached only through a
   table of function pointers in .data, and its imports through the PLT. */
int ext1(int);
int ext2(int);
int ext3(const char *);

__attribute__((noinline)) static int cmd_a(int x) { return ext1(x) + ext2(x + 3); }
__attribute__((noinline)) static int cmd_b(int x) { return ext2(x) - ext3("b"); }
__attribute__((noinline)) static int cmd_c(int x) { return ext3("c") + ext1(x * 5); }
/* A leaf: no prologue for a start pattern to see, no call for the code
   finder; only the table reaches it. */
__attribute__((noinline)) static int cmd_d(int x) { return x * 7 + 3; }

struct cmd {
  const char *name;
  int (*fn)(int);
};
struct cmd table[] = {{"a", cmd_a}, {"b", cmd_b}, {"c", cmd_c}, {"d", cmd_d}, {0, 0}};

int main(int argc, char **argv) {
  for (struct cmd *c = table; c->name; ++c)
    if (c->name[0] == argv[0][0]) return c->fn(argc);
  return ext1(argc);
}

void _start(void) {
  main(0, 0);
  for (;;) {
  }
}
