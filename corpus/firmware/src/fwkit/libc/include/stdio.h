#ifndef FWKIT_STDIO_H
#define FWKIT_STDIO_H
/* printf and friends are mpaland/printf's (printf.h maps the names). */
#include "printf.h"
int puts(const char *s);
int putchar(int c);
#define EOF (-1)
#endif
