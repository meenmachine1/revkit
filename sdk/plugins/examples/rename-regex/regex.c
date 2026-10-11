#include "regex.h"

/* Compiled to a program for a backtracking VM, in the style of Russ Cox's
 * re1: jumps are relative, so fragments can be copied for {m,n}. */
enum { OP_CHAR, OP_ANY, OP_CLASS, OP_SPLIT, OP_JMP, OP_SAVE, OP_BOL, OP_EOL, OP_MATCH };

typedef struct {
  uint8_t op;
  uint8_t c;
  int32_t x, y; /* SPLIT: preferred and other target; JMP: x; SAVE: slot (x) */
  uint8_t set[32];
} inst;

typedef struct {
  inst *code;
  uint32_t len, cap;
} frag;

struct rx_program {
  frag f;
};

typedef struct {
  const char *p, *end;
  const char *error;
  int group;
} parser;

static void push(frag *f, inst i) {
  if (f->len == f->cap) {
    uint32_t cap = f->cap ? f->cap * 2 : 16;
    inst *code = rk_alloc_bytes(sizeof(inst) * cap);
    if (f->len) memcpy(code, f->code, sizeof(inst) * f->len);
    f->code = code;
    f->cap = cap;
  }
  f->code[f->len++] = i;
}

static inst mk(uint8_t op, int32_t x, int32_t y) {
  inst i;
  memset(&i, 0, sizeof i);
  i.op = op;
  i.x = x;
  i.y = y;
  return i;
}

static void append(frag *a, const frag *b) {
  for (uint32_t i = 0; i < b->len; ++i) push(a, b->code[i]);
}

static frag alt(parser *ps);

static void set_bit(uint8_t *set, uint8_t c) { set[c >> 3] |= (uint8_t)(1u << (c & 7)); }

static void set_range(uint8_t *set, uint8_t lo, uint8_t hi) {
  for (unsigned c = lo; c <= hi; ++c) set_bit(set, (uint8_t)c);
}

/* \d \w \s and their negations into a set; 0 if `e` isn't one. */
static int class_escape(uint8_t *set, char e) {
  uint8_t tmp[32];
  memset(tmp, 0, sizeof tmp);
  char lower = (char)(e | 0x20);
  if (lower == 'd') set_range(tmp, '0', '9');
  else if (lower == 'w') set_range(tmp, '0', '9'), set_range(tmp, 'a', 'z'), set_range(tmp, 'A', 'Z'), set_bit(tmp, '_');
  else if (lower == 's') set_bit(tmp, ' '), set_range(tmp, '\t', '\r');
  else return 0;
  int negate = e >= 'A' && e <= 'Z';
  for (int i = 0; i < 32; ++i) set[i] |= negate ? (uint8_t)~tmp[i] : tmp[i];
  return 1;
}

static frag atom(parser *ps) {
  frag f = {0, 0, 0};
  char c = *ps->p++;
  if (c == '(') {
    int g = ++ps->group;
    if (g >= RX_GROUPS) {
      ps->error = "too many groups";
      return f;
    }
    push(&f, mk(OP_SAVE, 2 * g, 0));
    frag inner = alt(ps);
    append(&f, &inner);
    if (ps->p >= ps->end || *ps->p != ')') {
      ps->error = "missing )";
      return f;
    }
    ++ps->p;
    push(&f, mk(OP_SAVE, 2 * g + 1, 0));
  } else if (c == '[') {
    inst i = mk(OP_CLASS, 0, 0);
    int negate = ps->p < ps->end && *ps->p == '^';
    if (negate) ++ps->p;
    int first = 1;
    while (ps->p < ps->end && (*ps->p != ']' || first)) {
      first = 0;
      char lo = *ps->p++;
      if (lo == '\\' && ps->p < ps->end) {
        char e = *ps->p++;
        if (class_escape(i.set, e)) continue;
        lo = e;
      }
      if (ps->p + 1 < ps->end && *ps->p == '-' && ps->p[1] != ']') {
        char hi = ps->p[1];
        ps->p += 2;
        if ((uint8_t)hi < (uint8_t)lo) {
          ps->error = "bad range in []";
          return f;
        }
        set_range(i.set, (uint8_t)lo, (uint8_t)hi);
      } else {
        set_bit(i.set, (uint8_t)lo);
      }
    }
    if (ps->p >= ps->end) {
      ps->error = "missing ]";
      return f;
    }
    ++ps->p;
    if (negate)
      for (int k = 0; k < 32; ++k) i.set[k] = (uint8_t)~i.set[k];
    push(&f, i);
  } else if (c == '.') {
    push(&f, mk(OP_ANY, 0, 0));
  } else if (c == '^') {
    push(&f, mk(OP_BOL, 0, 0));
  } else if (c == '$') {
    push(&f, mk(OP_EOL, 0, 0));
  } else if (c == '\\') {
    if (ps->p >= ps->end) {
      ps->error = "trailing \\";
      return f;
    }
    char e = *ps->p++;
    inst i = mk(OP_CLASS, 0, 0);
    if (class_escape(i.set, e)) {
      push(&f, i);
    } else {
      inst ch = mk(OP_CHAR, 0, 0);
      ch.c = (uint8_t)(e == 'n' ? '\n' : e == 't' ? '\t' : e);
      push(&f, ch);
    }
  } else if (c == '*' || c == '+' || c == '?' || c == '{' || c == ')' || c == '|') {
    ps->error = "nothing to repeat, or unbalanced )";
  } else {
    inst ch = mk(OP_CHAR, 0, 0);
    ch.c = (uint8_t)c;
    push(&f, ch);
  }
  return f;
}

static frag star(const frag *e) {
  frag f = {0, 0, 0};
  push(&f, mk(OP_SPLIT, 1, (int32_t)e->len + 2));
  append(&f, e);
  push(&f, mk(OP_JMP, -(int32_t)e->len - 1, 0));
  return f;
}

static frag quest(const frag *e) {
  frag f = {0, 0, 0};
  push(&f, mk(OP_SPLIT, 1, (int32_t)e->len + 1));
  append(&f, e);
  return f;
}

static int number(parser *ps, int *out) {
  int n = 0, any = 0;
  while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') {
    n = n * 10 + (*ps->p++ - '0');
    any = 1;
    if (n > 1000) return 0;
  }
  *out = n;
  return any;
}

static frag repeat(parser *ps) {
  frag e = atom(ps);
  while (!ps->error && ps->p < ps->end) {
    char q = *ps->p;
    if (q == '*') {
      ++ps->p;
      e = star(&e);
    } else if (q == '+') {
      ++ps->p;
      frag f = {0, 0, 0};
      append(&f, &e);
      push(&f, mk(OP_SPLIT, -(int32_t)e.len, 1));
      e = f;
    } else if (q == '?') {
      ++ps->p;
      e = quest(&e);
    } else if (q == '{') {
      ++ps->p;
      int m = 0, n = 0;
      if (!number(ps, &m)) {
        ps->error = "bad {m,n}";
        break;
      }
      n = m;
      int unbounded = 0;
      if (ps->p < ps->end && *ps->p == ',') {
        ++ps->p;
        if (!number(ps, &n)) unbounded = 1;
      }
      if (ps->p >= ps->end || *ps->p != '}' || (!unbounded && n < m)) {
        ps->error = "bad {m,n}";
        break;
      }
      ++ps->p;
      frag f = {0, 0, 0};
      for (int i = 0; i < m; ++i) append(&f, &e);
      if (unbounded) {
        frag s = star(&e);
        append(&f, &s);
      } else {
        /* (e(e(e)?)?)? for the optional copies, built inside out. */
        frag opt = {0, 0, 0};
        for (int i = m; i < n; ++i) {
          frag t = {0, 0, 0};
          append(&t, &e);
          append(&t, &opt);
          opt = quest(&t);
        }
        append(&f, &opt);
      }
      e = f;
    } else {
      break;
    }
  }
  return e;
}

static frag concat(parser *ps) {
  frag f = {0, 0, 0};
  while (!ps->error && ps->p < ps->end && *ps->p != '|' && *ps->p != ')') {
    frag r = repeat(ps);
    append(&f, &r);
  }
  return f;
}

static frag alt(parser *ps) {
  frag a = concat(ps);
  while (!ps->error && ps->p < ps->end && *ps->p == '|') {
    ++ps->p;
    frag b = concat(ps);
    frag f = {0, 0, 0};
    push(&f, mk(OP_SPLIT, 1, (int32_t)a.len + 2));
    append(&f, &a);
    push(&f, mk(OP_JMP, (int32_t)b.len + 1, 0));
    append(&f, &b);
    a = f;
  }
  return a;
}

rx_program *rx_compile(rk_str pattern, const char **error) {
  parser ps = {pattern.ptr, pattern.ptr + pattern.len, 0, 0};
  frag f = {0, 0, 0};
  push(&f, mk(OP_SAVE, 0, 0));
  frag body = alt(&ps);
  append(&f, &body);
  if (!ps.error && ps.p != ps.end) ps.error = "unbalanced )";
  push(&f, mk(OP_SAVE, 1, 0));
  push(&f, mk(OP_MATCH, 0, 0));
  if (ps.error) {
    *error = ps.error;
    return 0;
  }
  rx_program *p = rk_alloc_bytes(sizeof *p);
  p->f = f;
  return p;
}

/* Backtracking with an explicit stack of (pc, sp, saved slot to restore). */
typedef struct {
  int32_t pc, sp;
  int32_t slot, old; /* slot >= 0: restore caps[slot] = old when popped */
} thread;

enum { kMaxSteps = 1000000, kMaxStack = 4096 };

static int run(const rx_program *p, rk_str s, int32_t start, int32_t *caps) {
  static thread stack[kMaxStack];
  int n = 0, steps = 0;
  stack[n++] = (thread){0, start, -1, 0};
  while (n) {
    thread t = stack[--n];
    if (t.slot >= 0) {
      caps[t.slot] = t.old;
      continue;
    }
    int32_t pc = t.pc, sp = t.sp;
    for (;;) {
      if (++steps > kMaxSteps) rk_fail("rename-regex: pattern too expensive");
      const inst *i = &p->f.code[pc];
      if (i->op == OP_CHAR) {
        if (sp >= (int32_t)s.len || (uint8_t)s.ptr[sp] != i->c) break;
        ++pc, ++sp;
      } else if (i->op == OP_ANY) {
        if (sp >= (int32_t)s.len) break;
        ++pc, ++sp;
      } else if (i->op == OP_CLASS) {
        if (sp >= (int32_t)s.len) break;
        uint8_t c = (uint8_t)s.ptr[sp];
        if (!(i->set[c >> 3] & (1u << (c & 7)))) break;
        ++pc, ++sp;
      } else if (i->op == OP_BOL) {
        if (sp != 0) break;
        ++pc;
      } else if (i->op == OP_EOL) {
        if (sp != (int32_t)s.len) break;
        ++pc;
      } else if (i->op == OP_JMP) {
        pc += i->x;
      } else if (i->op == OP_SPLIT) {
        if (n >= kMaxStack) rk_fail("rename-regex: pattern too deep");
        stack[n++] = (thread){pc + i->y, sp, -1, 0};
        pc += i->x;
      } else if (i->op == OP_SAVE) {
        if (n >= kMaxStack) rk_fail("rename-regex: pattern too deep");
        stack[n++] = (thread){0, 0, i->x, caps[i->x]};
        caps[i->x] = sp;
        ++pc;
      } else { /* OP_MATCH */
        return 1;
      }
    }
  }
  return 0;
}

int rx_search(const rx_program *p, rk_str s, uint32_t from, int32_t caps[2 * RX_GROUPS]) {
  for (uint32_t start = from; start <= s.len; ++start) {
    for (int i = 0; i < 2 * RX_GROUPS; ++i) caps[i] = -1;
    if (run(p, s, (int32_t)start, caps)) return 1;
  }
  return 0;
}
