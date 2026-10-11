#include <stdlib.h>
#include <string.h>
#include "features.h"

#define DIM 8

static void matmul(const int a[DIM][DIM], const int b[DIM][DIM], int c[DIM][DIM])
{
    for (int i = 0; i < DIM; i++)
        for (int j = 0; j < DIM; j++) {
            int sum = 0;
            for (int k = 0; k < DIM; k++)
                sum += a[i][k] * b[k][j];
            c[i][j] = sum;
        }
}

static void prefix_sums(long *v, int n)
{
    for (int i = 1; i < n; i++)
        v[i] += v[i - 1];
}

static int count_primes(int limit)
{
    char *sieve = calloc((size_t)limit + 1, 1);
    int count = 0;
    if (!sieve)
        return -1;
    for (int i = 2; i <= limit; i++) {
        if (sieve[i])
            continue;
        count++;
        for (long j = (long)i * i; j <= limit; j += i)
            sieve[j] = 1;
    }
    free(sieve);
    return count;
}

static int collatz_steps(unsigned long x)
{
    int steps = 0;
    while (x != 1) {
        x = (x & 1) ? 3 * x + 1 : x / 2;
        steps++;
    }
    return steps;
}

static int find_first(const int *v, int n, int needle)
{
    int i = 0;
    do {
        if (v[i] == needle)
            break;
    } while (++i < n);
    return i < n ? i : -1;
}

static int skip_odd_sum(const int *v, int n)
{
    int s = 0;
    for (int i = 0; i < n; i++) {
        if (v[i] & 1)
            continue;
        if (v[i] > 1000)
            break;
        s += v[i];
    }
    return s;
}

static int nested_goto(int n)
{
    int found = 0;
    for (int i = 1; i < n; i++)
        for (int j = 1; j < n; j++)
            if (i * j == 42) {
                found = i * 100 + j;
                goto done;
            }
done:
    return found;
}

uint32_t run_loops(int n)
{
    int a[DIM][DIM], b[DIM][DIM], c[DIM][DIM];
    long sums[64];
    int vals[64];
    for (int i = 0; i < DIM; i++)
        for (int j = 0; j < DIM; j++) {
            a[i][j] = i + j + n;
            b[i][j] = i * j - n;
        }
    matmul(a, b, c);
    for (int i = 0; i < 64; i++) {
        sums[i] = i * n;
        vals[i] = (i * 7 + n) % 50;
    }
    prefix_sums(sums, 64);
    uint32_t h = fnv1a(c, sizeof(c));
    h ^= fnv1a(sums, sizeof(sums));
    h += (uint32_t)count_primes(n * 100);
    h += (uint32_t)collatz_steps((unsigned long)n * 27 + 1);
    h += (uint32_t)find_first(vals, 64, n % 50);
    h += (uint32_t)skip_odd_sum(vals, 64);
    h += (uint32_t)nested_goto(n + 10);
    return h;
}
