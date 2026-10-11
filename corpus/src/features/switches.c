#include <ctype.h>
#include "features.h"

enum color { RED, ORANGE, YELLOW, GREEN, BLUE, INDIGO, VIOLET, BLACK, WHITE, GREY, NCOLORS };

/* Dense switch: compilers emit a jump table at -O2. */
static int color_weight(enum color c)
{
    switch (c) {
    case RED: return 11;
    case ORANGE: return 23;
    case YELLOW: return 5;
    case GREEN: return 47;
    case BLUE: return 13;
    case INDIGO: return 71;
    case VIOLET: return 2;
    case BLACK: return 97;
    case WHITE: return 31;
    case GREY: return 59;
    default: return -1;
    }
}

/* Dense switch with code in each arm (not convertible to a lookup table). */
static int apply_op(int op, int a, int b)
{
    switch (op) {
    case 0: return a + b;
    case 1: return a - b;
    case 2: return a * b;
    case 3: return b ? a / b : 0;
    case 4: return b ? a % b : 0;
    case 5: return a & b;
    case 6: return a | b;
    case 7: return a ^ b;
    case 8: return a << (b & 31);
    case 9: return a >> (b & 31);
    case 10: return a < b;
    case 11: return a == b;
    default: return 0;
    }
}

/* Sparse switch: a compare tree, not a table. */
static int sparse(int x)
{
    switch (x) {
    case 3: return 1;
    case 100: return 2;
    case 1000: return 3;
    case 4096: return 4;
    case 65535: return 5;
    case -7: return 6;
    case 123456: return 7;
    default: return 0;
    }
}

/* Fallthrough. */
static int fallthrough(int x)
{
    int r = 0;
    switch (x & 7) {
    case 7: r += 7; /* fallthrough */
    case 6: r += 6; /* fallthrough */
    case 5: r += 5; /* fallthrough */
    case 4: r += 4; break;
    case 3: r -= 3; /* fallthrough */
    case 2: r -= 2; break;
    default: r = 100;
    }
    return r;
}

/* Character classes via a switch on char. */
static int classify(const char *s, int counts[4])
{
    int n = 0;
    for (; *s; s++, n++) {
        switch (*s) {
        case 'a': case 'e': case 'i': case 'o': case 'u':
            counts[0]++;
            break;
        case ' ': case '\t': case '\n':
            counts[1]++;
            break;
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            counts[2]++;
            break;
        default:
            if (ispunct((unsigned char)*s))
                counts[3]++;
        }
    }
    return n;
}

uint32_t run_switches(int n)
{
    uint32_t h = 0;
    int counts[4] = {0, 0, 0, 0};
    for (int i = 0; i < n + 12; i++) {
        h = h * 33 + (uint32_t)color_weight((enum color)(i % (NCOLORS + 1)));
        h += (uint32_t)apply_op(i % 13, n + i, i + 1);
        h ^= (uint32_t)sparse(i * i - 7);
        h += (uint32_t)fallthrough(i);
    }
    h += (uint32_t)classify("The quick brown fox, 42 times; jumps over the lazy dog!", counts);
    return h ^ fnv1a(counts, sizeof(counts));
}
