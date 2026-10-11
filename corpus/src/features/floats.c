#include <math.h>
#include "features.h"

static double horner(const double *coef, int n, double x)
{
    double r = 0;
    for (int i = n - 1; i >= 0; i--)
        r = r * x + coef[i];
    return r;
}

static double newton_sqrt(double x)
{
    if (x <= 0)
        return 0;
    double g = x > 1 ? x / 2 : 1;
    for (int i = 0; i < 30; i++)
        g = 0.5 * (g + x / g);
    return g;
}

static void mean_var(const float *v, int n, float *mean, float *var)
{
    float s = 0, s2 = 0;
    for (int i = 0; i < n; i++) {
        s += v[i];
        s2 += v[i] * v[i];
    }
    *mean = s / (float)n;
    *var = s2 / (float)n - *mean * *mean;
}

static double integrate(double (*f)(double), double a, double b, int steps)
{
    double h = (b - a) / steps, sum = 0.5 * (f(a) + f(b));
    for (int i = 1; i < steps; i++)
        sum += f(a + i * h);
    return sum * h;
}

static double gauss(double x) { return exp(-x * x); }

static long double ld_mix(long double a, long double b)
{
    /* 128-bit long double on aarch64/riscv64 lowers to soft-float calls. */
    return a * b + a / (b + 1.0L);
}

static int classify(double x)
{
    if (x != x)
        return 0;
    if (x == INFINITY || x == -INFINITY)
        return 1;
    if (x == 0.0)
        return 2;
    return x < 0 ? 3 : 4;
}

static uint32_t to_bits(double d)
{
    union { double d; uint64_t u; } u = {d};
    return (uint32_t)(u.u ^ (u.u >> 32));
}

uint32_t run_floats(int n)
{
    static const double coef[] = {1.0, -2.5, 0.75, 3.0, -0.125};
    float samples[16];
    float mean, var;
    for (int i = 0; i < 16; i++)
        samples[i] = (float)(i * n) * 0.5f - 3.0f;
    mean_var(samples, 16, &mean, &var);
    double x = n / 7.0;
    double r = horner(coef, 5, x) + newton_sqrt(n * 10.0) + sqrt((double)n);
    r += sin(x) * cos(x) + pow(x, 1.5) + floor(x * 3.3) + fabs(-x) + atan2(x, 2.0);
    r += integrate(gauss, -2, 2, 64 + n);
    long double ld = ld_mix((long double)n, 3.25L);
    int ix = (int)(r * 100);
    unsigned ux = (unsigned)(double)(n * 1e6);
    uint32_t h = to_bits(r) ^ to_bits((double)mean) ^ to_bits((double)var);
    h += (uint32_t)ix + ux + (uint32_t)(int64_t)(ld * 8) + (uint32_t)classify(r - r) +
         (uint32_t)classify(1.0 / (double)(n - n + 1)) + (uint32_t)(float)n;
    return h;
}
