/* A small backtracking regular-expression engine: literals, ., classes
 * ([a-z], [^...], \d \w \s \D \W \S), groups with alternation, greedy
 * * + ? {m} {m,} {m,n}, and anchors ^ $. Matching is leftmost, with
 * Perl-style priority among alternatives. */
#ifndef RK_EXAMPLE_REGEX_H
#define RK_EXAMPLE_REGEX_H

#include "revkit_plugin.h"

#define RX_GROUPS 10

typedef struct rx_program rx_program;

/* Compiles a pattern; on error returns NULL and sets *error. */
rx_program *rx_compile(rk_str pattern, const char **error);
/* Searches s from `from`; on a match fills caps (start/end pairs, -1 when a
 * group didn't take part) and returns 1. */
int rx_search(const rx_program *p, rk_str s, uint32_t from, int32_t caps[2 * RX_GROUPS]);

#endif
