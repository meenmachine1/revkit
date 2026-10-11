#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "features.h"

typedef uint32_t (*module_fn)(int);

struct module {
    const char *name;
    module_fn run;
};

static const struct module modules[] = {
    {"loops", run_loops},         {"switches", run_switches},
    {"structs", run_structs},     {"funcptr", run_funcptr},
    {"recursion", run_recursion}, {"varargs", run_varargs},
    {"floats", run_floats},       {"strings", run_strings},
    {"bits", run_bits},           {"hashtable", run_hashtable},
    {"vm", run_vm},
};

#define NMODULES (sizeof(modules) / sizeof(modules[0]))

uint32_t fnv1a(const void *data, size_t len)
{
    const unsigned char *p = data;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static int usage(const char *argv0)
{
    fprintf(stderr, "usage: %s [n] [module...]\n", argv0);
    for (size_t i = 0; i < NMODULES; i++)
        fprintf(stderr, "  %s\n", modules[i].name);
    return 2;
}

int main(int argc, char **argv)
{
    int n = 10;
    int first = 1;
    if (argc > 1 && argv[1][0] >= '0' && argv[1][0] <= '9') {
        n = atoi(argv[1]);
        first = 2;
    }
    uint32_t total = 0;
    int ran = 0;
    for (size_t i = 0; i < NMODULES; i++) {
        int wanted = first >= argc;
        for (int a = first; a < argc && !wanted; a++)
            wanted = strcmp(argv[a], modules[i].name) == 0;
        if (!wanted)
            continue;
        uint32_t r = modules[i].run(n);
        printf("%-10s %08x\n", modules[i].name, (unsigned)r);
        total = total * 31 + r;
        ran++;
    }
    if (!ran)
        return usage(argv[0]);
    printf("total      %08x\n", (unsigned)total);
    return 0;
}
