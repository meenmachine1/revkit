/* fwkit's freestanding C library: string and memory functions. */
#include <string.h>
#include <stdint.h>

void *memcpy(void *dst, const void *src, size_t n) {
  unsigned char *d = dst;
  const unsigned char *s = src;
  if ((((uintptr_t)d | (uintptr_t)s) & (sizeof(uint32_t) - 1)) == 0) {
    while (n >= sizeof(uint32_t)) {
      *(uint32_t *)d = *(const uint32_t *)s;
      d += sizeof(uint32_t);
      s += sizeof(uint32_t);
      n -= sizeof(uint32_t);
    }
  }
  while (n--) *d++ = *s++;
  return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
  unsigned char *d = dst;
  const unsigned char *s = src;
  if (d == s || n == 0) return dst;
  if (d < s || d >= s + n) return memcpy(dst, src, n);
  d += n;
  s += n;
  while (n--) *--d = *--s;
  return dst;
}

void *memset(void *dst, int c, size_t n) {
  unsigned char *d = dst;
  while (n && ((uintptr_t)d & 3)) {
    *d++ = (unsigned char)c;
    n--;
  }
  if (n >= 4) {
    uint32_t w = (unsigned char)c;
    w |= w << 8;
    w |= w << 16;
    while (n >= 4) {
      *(uint32_t *)d = w;
      d += 4;
      n -= 4;
    }
  }
  while (n--) *d++ = (unsigned char)c;
  return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
  const unsigned char *x = a, *y = b;
  for (; n; n--, x++, y++)
    if (*x != *y) return *x - *y;
  return 0;
}

void *memchr(const void *s, int c, size_t n) {
  const unsigned char *p = s;
  for (; n; n--, p++)
    if (*p == (unsigned char)c) return (void *)p;
  return NULL;
}

size_t strlen(const char *s) {
  const char *p = s;
  while (*p) p++;
  return (size_t)(p - s);
}

size_t strnlen(const char *s, size_t max) {
  size_t n = 0;
  while (n < max && s[n]) n++;
  return n;
}

int strcmp(const char *a, const char *b) {
  while (*a && *a == *b) a++, b++;
  return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n) {
  for (; n; n--, a++, b++) {
    if (*a != *b) return (unsigned char)*a - (unsigned char)*b;
    if (!*a) break;
  }
  return 0;
}

char *strcpy(char *dst, const char *src) {
  char *d = dst;
  while ((*d++ = *src++)) {
  }
  return dst;
}

char *strncpy(char *dst, const char *src, size_t n) {
  size_t i = 0;
  for (; i < n && src[i]; i++) dst[i] = src[i];
  for (; i < n; i++) dst[i] = 0;
  return dst;
}

char *strchr(const char *s, int c) {
  for (;; s++) {
    if (*s == (char)c) return (char *)s;
    if (!*s) return NULL;
  }
}

char *strrchr(const char *s, int c) {
  const char *last = NULL;
  for (;; s++) {
    if (*s == (char)c) last = s;
    if (!*s) return (char *)last;
  }
}

size_t strspn(const char *s, const char *accept) {
  size_t n = 0;
  while (s[n] && strchr(accept, s[n])) n++;
  return n;
}

size_t strcspn(const char *s, const char *reject) {
  size_t n = 0;
  while (s[n] && !strchr(reject, s[n])) n++;
  return n;
}

char *strstr(const char *haystack, const char *needle) {
  size_t n = strlen(needle);
  if (!n) return (char *)haystack;
  for (; *haystack; haystack++)
    if (*haystack == *needle && !strncmp(haystack, needle, n)) return (char *)haystack;
  return NULL;
}
