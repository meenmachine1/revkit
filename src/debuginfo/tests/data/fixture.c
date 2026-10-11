/* DWARF fixture: one of everything the importer must understand. Compiled
 * at test time by several compilers and DWARF versions; the tests check the
 * same prototypes and layouts come out of every build. */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

struct node {
  struct node *next;
  int value;
};

typedef struct {
  int x, y;
} point;

union number {
  int i;
  float f;
  unsigned char bytes[4];
};

enum color { RED, GREEN = 5, BLUE };
enum sign { NEG = -1, ZERO, POS };

struct flags {
  unsigned int ready : 1;
  unsigned int mode : 3;
  signed int delta : 4;
  unsigned char tail;
};

struct __attribute__((packed)) packed_rec {
  char tag;
  int value;
  short extra;
};

struct with_array {
  int grid[3][4];
  char name[16];
  int tail[];
};

struct anon_member {
  int kind;
  union {
    int as_int;
    double as_double;
  };
};

typedef int (*binop)(int, int);
typedef unsigned long ulong_t;

struct ops {
  binop combine;
  void (*callback)(void *ctx, const char *msg);
};

/* Two structs that point at each other. */
struct tree;
struct forest {
  struct tree *first;
  int count;
};
struct tree {
  struct forest *children;
  struct tree *parent;
};

int global_counter = 3;
static const char *global_name = "fixture";
struct node global_list[2];
volatile uint32_t global_status;

int add(int a, int b) { return a + b; }

long sum_ints(int count, ...) {
  va_list ap;
  va_start(ap, count);
  long total = 0;
  for (int i = 0; i < count; ++i) total += va_arg(ap, int);
  va_end(ap);
  return total;
}

int fold(const int *values, size_t n, binop f, int init) {
  for (size_t i = 0; i < n; ++i) init = f(init, values[i]);
  return init;
}

void apply(struct ops *o, void *ctx) {
  if (o->callback) o->callback(ctx, "apply");
}

struct node *list_push(struct node *head, int v) {
  global_list[0].next = head;
  global_list[0].value = v;
  return &global_list[0];
}

point point_add(point a, point b) {
  point r = {a.x + b.x, a.y + b.y};
  return r;
}

unsigned int pack_flags(struct flags f) { return f.ready | f.mode << 1 | (unsigned)f.delta << 4; }

int color_weight(enum color c, enum sign s) { return (int)c * (int)s; }

float as_float(union number n) { return n.f; }

void matmul(int (*a)[4], int m[3][4], ulong_t rows) {
  for (ulong_t i = 0; i < rows && i < 3; ++i) a[0][i] = m[i][0];
}

char **split(char *s, char sep, int *count) {
  (void)s;
  (void)sep;
  *count = 0;
  return 0;
}

int forest_size(const struct forest *f, struct tree *t) { return f->count + (t != 0); }

double packed_value(struct packed_rec *r, struct with_array *w, struct anon_member *m) {
  return r->value + w->grid[1][2] + m->as_double;
}

binop pick(int which) { return which ? add : 0; }

void no_args(void) { global_status = 1; }

static int helper(int x) { return x * 2; }

int main(int argc, char **argv) {
  int v[3] = {1, 2, 3};
  struct ops o = {add, 0};
  apply(&o, 0);
  int n;
  split(argv[0], ',', &n);
  return fold(v, 3, pick(argc), 0) + (int)sum_ints(2, 1, 2) + helper(argc) +
         color_weight(GREEN, NEG) + (int)as_float((union number){.i = 1}) + global_counter +
         (global_name != 0) + (int)pack_flags((struct flags){1, 2, -3, 4});
}
