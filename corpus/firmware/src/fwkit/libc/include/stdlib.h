#ifndef FWKIT_STDLIB_H
#define FWKIT_STDLIB_H
#include <stddef.h>

#define RAND_MAX 0x7fff
int abs(int v);
long labs(long v);
int atoi(const char *s);
long strtol(const char *s, char **end, int base);
unsigned long strtoul(const char *s, char **end, int base);
int rand(void);
void srand(unsigned seed);
void qsort(void *base, size_t n, size_t size, int (*cmp)(const void *, const void *));
void *bsearch(const void *key, const void *base, size_t n, size_t size, int (*cmp)(const void *, const void *));
/* The heap is FreeRTOS's (heap_4). */
void *malloc(size_t n);
void free(void *p);
void *calloc(size_t n, size_t size);
void abort(void) __attribute__((noreturn));
#endif
