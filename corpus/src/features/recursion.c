#include <stdlib.h>
#include "features.h"

static unsigned long fib(unsigned n)
{
    return n < 2 ? n : fib(n - 1) + fib(n - 2);
}

static unsigned long ackermann(unsigned long m, unsigned long n)
{
    if (m == 0)
        return n + 1;
    if (n == 0)
        return ackermann(m - 1, 1);
    return ackermann(m - 1, ackermann(m, n - 1));
}

static int is_odd(unsigned n);
static int is_even(unsigned n) { return n == 0 ? 1 : is_odd(n - 1); }
static int is_odd(unsigned n) { return n == 0 ? 0 : is_even(n - 1); }

static long gcd(long a, long b) { return b == 0 ? a : gcd(b, a % b); }

struct tree {
    struct tree *left, *right;
    int key;
};

static struct tree *tree_insert(struct tree *t, int key)
{
    if (!t) {
        t = calloc(1, sizeof(*t));
        if (!t)
            abort();
        t->key = key;
    } else if (key < t->key) {
        t->left = tree_insert(t->left, key);
    } else if (key > t->key) {
        t->right = tree_insert(t->right, key);
    }
    return t;
}

static int tree_height(const struct tree *t)
{
    if (!t)
        return 0;
    int l = tree_height(t->left), r = tree_height(t->right);
    return 1 + (l > r ? l : r);
}

static uint32_t tree_walk(const struct tree *t, uint32_t h)
{
    if (!t)
        return h;
    h = tree_walk(t->left, h);
    h = h * 31 + (uint32_t)t->key;
    return tree_walk(t->right, h);
}

static void tree_free(struct tree *t)
{
    if (!t)
        return;
    tree_free(t->left);
    tree_free(t->right);
    free(t);
}

static void quicksort(int *v, int lo, int hi)
{
    if (lo >= hi)
        return;
    int pivot = v[(lo + hi) / 2], i = lo, j = hi;
    while (i <= j) {
        while (v[i] < pivot) i++;
        while (v[j] > pivot) j--;
        if (i <= j) {
            int t = v[i];
            v[i++] = v[j];
            v[j--] = t;
        }
    }
    quicksort(v, lo, j);
    quicksort(v, i, hi);
}

static int hanoi(int disks, int from, int to, int via)
{
    if (disks == 0)
        return 0;
    return hanoi(disks - 1, from, via, to) + 1 + hanoi(disks - 1, via, to, from);
}

uint32_t run_recursion(int n)
{
    struct tree *t = NULL;
    int v[40];
    uint32_t h = (uint32_t)fib((unsigned)(n % 25));
    h += (uint32_t)ackermann(2, (unsigned long)(n % 8));
    h += (uint32_t)is_even((unsigned)n * 3) + (uint32_t)gcd(n * 462L, 1071);
    for (int i = 0; i < 40; i++) {
        v[i] = (i * 7919 + n) % 97;
        t = tree_insert(t, v[i]);
    }
    h ^= tree_walk(t, 7) + (uint32_t)tree_height(t);
    tree_free(t);
    quicksort(v, 0, 39);
    return h + fnv1a(v, sizeof(v)) + (uint32_t)hanoi(n % 12, 1, 3, 2);
}
