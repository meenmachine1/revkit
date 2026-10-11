#include <stdlib.h>
#include <string.h>
#include "features.h"

struct point {
    int x, y;
};

struct rect {
    struct point min, max;
    unsigned char color;
    double area_cache;
};

struct flags {
    unsigned visible : 1;
    unsigned layer : 4;
    unsigned kind : 3;
    signed delta : 6;
};

union number {
    int64_t i;
    double d;
    unsigned char bytes[8];
};

struct node {
    struct node *next;
    int value;
};

struct blob {
    uint16_t len;
    uint8_t tag;
    char data[];
};

/* Small struct passed and returned by value. */
static struct point point_add(struct point a, struct point b)
{
    struct point r = {a.x + b.x, a.y + b.y};
    return r;
}

/* Large struct returned by value (hidden pointer argument). */
static struct rect make_rect(int x0, int y0, int x1, int y1, unsigned char color)
{
    struct rect r;
    r.min.x = x0 < x1 ? x0 : x1;
    r.min.y = y0 < y1 ? y0 : y1;
    r.max.x = x0 < x1 ? x1 : x0;
    r.max.y = y0 < y1 ? y1 : y0;
    r.color = color;
    r.area_cache = (double)(r.max.x - r.min.x) * (double)(r.max.y - r.min.y);
    return r;
}

static int rect_overlap(const struct rect *a, const struct rect *b)
{
    return a->min.x < b->max.x && b->min.x < a->max.x &&
           a->min.y < b->max.y && b->min.y < a->max.y;
}

static unsigned pack_flags(struct flags f)
{
    unsigned r;
    memcpy(&r, &f, sizeof(r) < sizeof(f) ? sizeof(r) : sizeof(f));
    return r ^ (unsigned)(f.layer * 3 + f.kind + f.delta);
}

static struct node *list_push(struct node *head, int v)
{
    struct node *n = malloc(sizeof(*n));
    if (!n)
        abort();
    n->next = head;
    n->value = v;
    return n;
}

static struct node *list_reverse(struct node *head)
{
    struct node *prev = NULL;
    while (head) {
        struct node *next = head->next;
        head->next = prev;
        prev = head;
        head = next;
    }
    return prev;
}

static uint32_t list_free_hash(struct node *head)
{
    uint32_t h = 0;
    while (head) {
        struct node *next = head->next;
        h = h * 31 + (uint32_t)head->value;
        free(head);
        head = next;
    }
    return h;
}

static struct blob *blob_new(const char *s, uint8_t tag)
{
    size_t len = strlen(s);
    struct blob *b = malloc(sizeof(*b) + len + 1);
    if (!b)
        abort();
    b->len = (uint16_t)len;
    b->tag = tag;
    memcpy(b->data, s, len + 1);
    return b;
}

uint32_t run_structs(int n)
{
    struct point acc = {0, 0};
    struct rect rects[6];
    struct node *list = NULL;
    union number num;
    struct flags f = {1, (unsigned)(n & 15), 5, -3};
    uint32_t h = 0;

    for (int i = 0; i < 6; i++) {
        struct point p = {i * n, i - n};
        acc = point_add(acc, p);
        rects[i] = make_rect(i, i * 2, n + i, n - i, (unsigned char)i);
    }
    for (int i = 0; i < 6; i++)
        for (int j = i + 1; j < 6; j++)
            h += (uint32_t)rect_overlap(&rects[i], &rects[j]);
    for (int i = 0; i < n; i++)
        list = list_push(list, i * i);
    list = list_reverse(list);
    h ^= list_free_hash(list);
    num.d = n * 1.5;
    h += fnv1a(num.bytes, sizeof(num.bytes)) + (uint32_t)(num.i >> 32);
    h += pack_flags(f);
    struct blob *b = blob_new("flexible array member", (uint8_t)n);
    h += b->len + b->tag + (uint32_t)b->data[3];
    free(b);
    return h + (uint32_t)(acc.x * 7 + acc.y);
}
