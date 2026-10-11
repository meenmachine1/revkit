#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "features.h"

static long sum_ints(int count, ...)
{
    va_list ap;
    long total = 0;
    va_start(ap, count);
    for (int i = 0; i < count; i++)
        total += va_arg(ap, int);
    va_end(ap);
    return total;
}

static double avg_doubles(int count, ...)
{
    va_list ap;
    double total = 0;
    va_start(ap, count);
    for (int i = 0; i < count; i++)
        total += va_arg(ap, double);
    va_end(ap);
    return count ? total / count : 0.0;
}

/* A tiny formatter: %d %s %c %x and %%. */
static int mini_format(char *out, size_t cap, const char *fmt, ...)
{
    va_list ap;
    size_t n = 0;
    va_start(ap, fmt);
    for (const char *p = fmt; *p && n + 1 < cap; p++) {
        if (*p != '%') {
            out[n++] = *p;
            continue;
        }
        char tmp[24];
        const char *s = tmp;
        switch (*++p) {
        case 'd': snprintf(tmp, sizeof(tmp), "%d", va_arg(ap, int)); break;
        case 'x': snprintf(tmp, sizeof(tmp), "%x", va_arg(ap, unsigned)); break;
        case 'c': tmp[0] = (char)va_arg(ap, int); tmp[1] = 0; break;
        case 's': s = va_arg(ap, const char *); break;
        case '%': tmp[0] = '%'; tmp[1] = 0; break;
        default: tmp[0] = '?'; tmp[1] = 0; p--; break;
        }
        while (*s && n + 1 < cap)
            out[n++] = *s++;
    }
    out[n] = 0;
    va_end(ap);
    return (int)n;
}

static int vformat_twice(char *a, char *b, size_t cap, const char *fmt, va_list ap)
{
    va_list copy;
    va_copy(copy, ap);
    int r = vsnprintf(a, cap, fmt, ap);
    r += vsnprintf(b, cap, fmt, copy);
    va_end(copy);
    return r;
}

static int format_twice(char *a, char *b, size_t cap, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = vformat_twice(a, b, cap, fmt, ap);
    va_end(ap);
    return r;
}

uint32_t run_varargs(int n)
{
    char buf[128], b1[64], b2[64];
    uint32_t h = (uint32_t)sum_ints(5, n, 2, 3, 4, 5);
    h += (uint32_t)sum_ints(9, 1, 2, 3, 4, 5, 6, 7, 8, n);
    h += (uint32_t)(avg_doubles(4, 1.5, 2.5, (double)n, 0.25) * 1000);
    int len = mini_format(buf, sizeof(buf), "n=%d hex=%x c=%c s=%s 100%%", n, n * 255, 'A' + n % 26, "str");
    h ^= fnv1a(buf, (size_t)len);
    h += (uint32_t)format_twice(b1, b2, sizeof(b1), "%s-%d-%.2f", "v", n, n / 3.0);
    return h ^ fnv1a(b2, strlen(b2));
}
