#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "features.h"

static size_t my_strlen(const char *s)
{
    const char *p = s;
    while (*p)
        p++;
    return (size_t)(p - s);
}

static void reverse(char *s)
{
    size_t n = my_strlen(s);
    for (size_t i = 0; i < n / 2; i++) {
        char t = s[i];
        s[i] = s[n - 1 - i];
        s[n - 1 - i] = t;
    }
}

static int my_atoi(const char *s)
{
    int sign = 1, v = 0;
    while (isspace((unsigned char)*s))
        s++;
    if (*s == '-' || *s == '+')
        sign = *s++ == '-' ? -1 : 1;
    while (*s >= '0' && *s <= '9')
        v = v * 10 + (*s++ - '0');
    return sign * v;
}

static char *my_itoa(long v, char *buf, int base)
{
    static const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    char *p = buf;
    unsigned long u = v < 0 ? -(unsigned long)v : (unsigned long)v;
    do {
        *p++ = digits[u % (unsigned)base];
        u /= (unsigned)base;
    } while (u);
    if (v < 0)
        *p++ = '-';
    *p = 0;
    reverse(buf);
    return buf;
}

static const char *naive_strstr(const char *hay, const char *needle)
{
    if (!*needle)
        return hay;
    for (; *hay; hay++) {
        const char *h = hay, *n = needle;
        while (*h && *n && *h == *n)
            h++, n++;
        if (!*n)
            return hay;
    }
    return NULL;
}

static int tokenize(char *s, const char *delims, char **out, int max)
{
    int count = 0;
    while (*s && count < max) {
        while (*s && strchr(delims, *s))
            s++;
        if (!*s)
            break;
        out[count++] = s;
        while (*s && !strchr(delims, *s))
            s++;
        if (*s)
            *s++ = 0;
    }
    return count;
}

static void to_upper(char *s)
{
    for (; *s; s++)
        *s = (char)toupper((unsigned char)*s);
}

uint32_t run_strings(int n)
{
    char text[] = "alpha, beta;gamma  delta,epsilon;;zeta";
    char *tokens[8];
    char buf[64], num[40];
    uint32_t h = 0;
    int count = tokenize(text, ",; ", tokens, 8);
    for (int i = 0; i < count; i++) {
        h = h * 131 + (uint32_t)my_strlen(tokens[i]);
        strncpy(buf, tokens[i], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = 0;
        to_upper(buf);
        reverse(buf);
        h ^= fnv1a(buf, strlen(buf));
    }
    h += (uint32_t)my_atoi("  -12345") + (uint32_t)my_atoi(my_itoa(n * -77, num, 10));
    h ^= fnv1a(my_itoa(n * 1000003L, num, 16), strlen(num));
    const char *found = naive_strstr("the needle in the haystack", n & 1 ? "hay" : "needle");
    h += found ? (uint32_t)(found[0] + found[1]) : 0;
    snprintf(buf, sizeof(buf), "%s/%d/%c", "path", n, 'z');
    h += (uint32_t)strcmp(buf, "path/1/z") + (uint32_t)memcmp(buf, "pat", 3);
    memset(buf, 'x', 10);
    memmove(buf + 2, buf, 8);
    return h ^ fnv1a(buf, 10);
}
