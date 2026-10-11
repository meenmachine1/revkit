#include <stdlib.h>
#include "features.h"

typedef int (*binop)(int, int);

static int add(int a, int b) { return a + b; }
static int sub(int a, int b) { return a - b; }
static int mul(int a, int b) { return a * b; }
static int maxi(int a, int b) { return a > b ? a : b; }

static const binop table[] = {add, sub, mul, maxi};

static int fold(const int *v, int n, binop f, int init)
{
    for (int i = 0; i < n; i++)
        init = f(init, v[i]);
    return init;
}

static int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

static int cmp_int_desc(const void *a, const void *b)
{
    return cmp_int(b, a);
}

/* A hand-rolled vtable. */
struct shape;
struct shape_ops {
    long (*area)(const struct shape *);
    long (*perimeter)(const struct shape *);
    const char *name;
};

struct shape {
    const struct shape_ops *ops;
    long a, b;
};

static long rect_area(const struct shape *s) { return s->a * s->b; }
static long rect_perim(const struct shape *s) { return 2 * (s->a + s->b); }
static long tri_area(const struct shape *s) { return s->a * s->b / 2; }
static long tri_perim(const struct shape *s) { return s->a + s->b + (s->a > s->b ? s->a : s->b); }

static const struct shape_ops rect_ops = {rect_area, rect_perim, "rect"};
static const struct shape_ops tri_ops = {tri_area, tri_perim, "tri"};

static void for_each(int *v, int n, void (*cb)(int *, void *), void *ctx)
{
    for (int i = 0; i < n; i++)
        cb(&v[i], ctx);
}

static void accumulate(int *x, void *ctx)
{
    *(long *)ctx += *x;
    *x = -*x;
}

static binop pick(int which)
{
    return table[(unsigned)which % (sizeof(table) / sizeof(table[0]))];
}

uint32_t run_funcptr(int n)
{
    int v[32];
    long total = 0;
    uint32_t h = 0;
    for (int i = 0; i < 32; i++)
        v[i] = (i * 37 + n) % 101;
    for (int k = 0; k < 4; k++)
        h = h * 17 + (uint32_t)fold(v, 32, pick(k + n), k);
    qsort(v, 32, sizeof(int), (n & 1) ? cmp_int : cmp_int_desc);
    h ^= fnv1a(v, sizeof(v));
    for_each(v, 32, accumulate, &total);
    struct shape shapes[2] = {{&rect_ops, n, n + 1}, {&tri_ops, n + 2, n + 3}};
    for (int i = 0; i < 2; i++)
        h += (uint32_t)(shapes[i].ops->area(&shapes[i]) + shapes[i].ops->perimeter(&shapes[i])) +
             (uint32_t)shapes[i].ops->name[0];
    return h + (uint32_t)total;
}
