// The fixture's string and memory helpers (kit.h), ARM code.
#include "kit.h"

void *kit_memcpy(void *dst, const void *src, u32 n) {
  u8 *d = dst;
  const u8 *s = src;
  while (n--) *d++ = *s++;
  return dst;
}

void *kit_memset(void *dst, int c, u32 n) {
  u8 *d = dst;
  while (n--) *d++ = (u8)c;
  return dst;
}

u32 kit_strlen(const char *s) {
  u32 n = 0;
  while (s[n]) n++;
  return n;
}

int kit_strcmp(const char *a, const char *b) {
  while (*a && *a == *b) {
    a++;
    b++;
  }
  return (u8)*a - (u8)*b;
}

