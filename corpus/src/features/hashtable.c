#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "features.h"

struct entry {
    struct entry *next;
    char *key;
    int value;
};

struct table {
    struct entry **buckets;
    size_t nbuckets, count;
};

static char *dupstr(const char *s)
{
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    if (d)
        memcpy(d, s, n);
    return d;
}

static struct table *table_new(size_t nbuckets)
{
    struct table *t = malloc(sizeof(*t));
    if (!t)
        return NULL;
    t->buckets = calloc(nbuckets, sizeof(*t->buckets));
    t->nbuckets = nbuckets;
    t->count = 0;
    return t;
}

static void table_resize(struct table *t)
{
    size_t nb = t->nbuckets * 2;
    struct entry **b = calloc(nb, sizeof(*b));
    if (!b)
        return;
    for (size_t i = 0; i < t->nbuckets; i++) {
        struct entry *e = t->buckets[i];
        while (e) {
            struct entry *next = e->next;
            size_t slot = fnv1a(e->key, strlen(e->key)) % nb;
            e->next = b[slot];
            b[slot] = e;
            e = next;
        }
    }
    free(t->buckets);
    t->buckets = b;
    t->nbuckets = nb;
}

static int *table_get(struct table *t, const char *key, int create)
{
    size_t slot = fnv1a(key, strlen(key)) % t->nbuckets;
    for (struct entry *e = t->buckets[slot]; e; e = e->next)
        if (strcmp(e->key, key) == 0)
            return &e->value;
    if (!create)
        return NULL;
    if (t->count + 1 > t->nbuckets * 3 / 4) {
        table_resize(t);
        slot = fnv1a(key, strlen(key)) % t->nbuckets;
    }
    struct entry *e = malloc(sizeof(*e));
    if (!e)
        return NULL;
    e->key = dupstr(key);
    e->value = 0;
    e->next = t->buckets[slot];
    t->buckets[slot] = e;
    t->count++;
    return &e->value;
}

static void table_free(struct table *t)
{
    for (size_t i = 0; i < t->nbuckets; i++) {
        struct entry *e = t->buckets[i];
        while (e) {
            struct entry *next = e->next;
            free(e->key);
            free(e);
            e = next;
        }
    }
    free(t->buckets);
    free(t);
}

uint32_t run_hashtable(int n)
{
    struct table *t = table_new(4);
    char key[32];
    uint32_t h = 0;
    if (!t)
        return 0;
    for (int i = 0; i < n * 10; i++) {
        snprintf(key, sizeof(key), "k%d", (i * 7) % (n * 3 + 1));
        int *v = table_get(t, key, 1);
        if (v)
            *v += i;
    }
    for (int i = 0; i < n * 3 + 1; i++) {
        snprintf(key, sizeof(key), "k%d", i);
        int *v = table_get(t, key, 0);
        h = h * 31 + (v ? (uint32_t)*v : 0xdeadu);
    }
    h += (uint32_t)t->count + (uint32_t)t->nbuckets;
    table_free(t);
    return h;
}
