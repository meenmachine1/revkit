/* fwkit's freestanding C library: conversions, sorting, ctype, and malloc
 * over the FreeRTOS heap. */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "FreeRTOS.h"

int errno;

int abs(int v) { return v < 0 ? -v : v; }
long labs(long v) { return v < 0 ? -v : v; }

int isdigit(int c) { return c >= '0' && c <= '9'; }
int isxdigit(int c) { return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
int isspace(int c) { return c == ' ' || (c >= '\t' && c <= '\r'); }
int isupper(int c) { return c >= 'A' && c <= 'Z'; }
int islower(int c) { return c >= 'a' && c <= 'z'; }
int isalpha(int c) { return isupper(c) || islower(c); }
int isalnum(int c) { return isalpha(c) || isdigit(c); }
int isprint(int c) { return c >= 0x20 && c < 0x7f; }
int toupper(int c) { return islower(c) ? c - 'a' + 'A' : c; }
int tolower(int c) { return isupper(c) ? c - 'A' + 'a' : c; }

static int digit_value(int c) {
  if (isdigit(c)) return c - '0';
  if (c >= 'a' && c <= 'z') return c - 'a' + 10;
  if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
  return 99;
}

unsigned long strtoul(const char *s, char **end, int base) {
  unsigned long v = 0;
  while (isspace(*s)) s++;
  if (*s == '+') s++;
  if ((base == 0 || base == 16) && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    s += 2;
    base = 16;
  } else if (base == 0) {
    base = *s == '0' ? 8 : 10;
  }
  for (;; s++) {
    int d = digit_value(*s);
    if (d >= base) break;
    v = v * base + d;
  }
  if (end) *end = (char *)s;
  return v;
}

long strtol(const char *s, char **end, int base) {
  int neg = 0;
  while (isspace(*s)) s++;
  if (*s == '-') {
    neg = 1;
    s++;
  }
  unsigned long v = strtoul(s, end, base);
  return neg ? -(long)v : (long)v;
}

int atoi(const char *s) { return (int)strtol(s, NULL, 10); }

static unsigned long rand_state = 1;
void srand(unsigned seed) { rand_state = seed; }
int rand(void) {
  rand_state = rand_state * 1103515245UL + 12345UL;
  return (int)((rand_state >> 16) & RAND_MAX);
}

static void swap_bytes(unsigned char *a, unsigned char *b, size_t size) {
  while (size--) {
    unsigned char t = *a;
    *a++ = *b;
    *b++ = t;
  }
}

/* Shell sort: small, no recursion. */
void qsort(void *base, size_t n, size_t size, int (*cmp)(const void *, const void *)) {
  unsigned char *p = base;
  for (size_t gap = n / 2; gap > 0; gap /= 2)
    for (size_t i = gap; i < n; i++)
      for (size_t j = i; j >= gap && cmp(p + (j - gap) * size, p + j * size) > 0; j -= gap)
        swap_bytes(p + (j - gap) * size, p + j * size, size);
}

void *bsearch(const void *key, const void *base, size_t n, size_t size, int (*cmp)(const void *, const void *)) {
  const unsigned char *p = base;
  size_t lo = 0, hi = n;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    int c = cmp(key, p + mid * size);
    if (c == 0) return (void *)(p + mid * size);
    if (c < 0) hi = mid;
    else lo = mid + 1;
  }
  return NULL;
}

void *malloc(size_t n) { return pvPortMalloc(n); }
void free(void *p) { vPortFree(p); }
void *calloc(size_t n, size_t size) {
  void *p = pvPortMalloc(n * size);
  if (p) memset(p, 0, n * size);
  return p;
}
