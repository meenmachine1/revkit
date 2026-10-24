/* Source shape: each function is a pattern hand-matching a decompilation
   had to fix (docs/known-issues.md, "Found by a matching-decompilation run
   on a Nintendo DS game"). Built for ARMv5TE, x86-64 and AArch64 by
   tools/rk-lift/shape_smoke.sh; tests/data/shape/check.py says what the C
   must look like. */
#define NOINLINE __attribute__((noinline))

typedef unsigned short u16;
typedef short s16;
typedef unsigned char u8;
typedef signed char s8;

struct obj {
  u16 id;
  s16 x;
  u8 kind;
  s8 dir;
  u16 flags;
  s16 vel[2];
  int hp;
};

struct flags {
  unsigned int on : 1;
  unsigned int mode : 3;
  unsigned int level : 5;
  unsigned int rest : 23;
};

struct big { int a, b, c, d, e, f; };

volatile int sinkv;
struct obj gobj;
struct big gbig;

NOINLINE void use(int x) { sinkv = x; }

/* Load signedness follows ldrh/ldrsh/ldrb/ldrsb. */
NOINLINE void inc_fields(struct obj *o) { o->id = o->id + 1; o->x = o->x - 1; }
NOINLINE u16 get_id(struct obj *o) { return o->id; }
NOINLINE s16 get_x(struct obj *o) { return o->x; }
NOINLINE s8 get_dir(struct obj *o) { return o->dir; }
NOINLINE u8 get_kind(struct obj *o) { return o->kind; }

/* Comparisons keep the constant the code compares against. */
NOINLINE int cmp_le0(int x) { if (x <= 0) return sinkv; return x; }
NOINLINE int cmp_ge9(int x) { if (x >= 9) use(x); return 0; }
NOINLINE int clamp(int x) { if (x >= 10) x = 9; if (x <= 0) x = 1; return x; }

/* Bitfields, printed as fields where the type has them (-g). */
NOINLINE int bf_on(struct flags *f) { return f->on; }
NOINLINE void bf_clear(struct flags *f) { f->on = 0; }
NOINLINE int bf_level(struct flags *f) { return f->level; }

/* Bytes of a structure no field names. */
NOINLINE void copy_mixed(void) { gbig.a = *(int *)((char *)&gobj + 2); }

NOINLINE void loop_switch(int x, int y) {
  for (int i = 0; i < y; i++) {
    switch (x + i) {
    case 0: sinkv = 1; break;
    case 1: sinkv = 2; continue;
    case 2: sinkv = 3; break;
    case 3: sinkv = 5; break;
    case 9: continue;
    default: sinkv = 4;
    }
    sinkv = 7;
  }
}

#ifdef __arm__
extern void start_cw(void);
#endif

void _start(void) {
  struct flags f = {1, 2, 3, 4};
#ifdef __arm__
  start_cw();
#endif
  inc_fields(&gobj);
  use(get_id(&gobj) + get_x(&gobj) + get_dir(&gobj) + get_kind(&gobj));
  use(cmp_le0(sinkv) + cmp_ge9(sinkv) + clamp(sinkv));
  use(bf_on(&f) + bf_level(&f));
  bf_clear(&f);
  copy_mixed();
  loop_switch(sinkv, sinkv);
  for (;;) {}
}
