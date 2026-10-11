/* revkit plugin SDK for C: runtime (see revkit_plugin.h). */
#include "revkit_plugin.h"

/* ---- exports every plugin has ------------------------------------------------- */

RK_EXPORT("rk_abi_version") int32_t rk_abi_version(void) { return RK_ABI_VERSION; }

RK_EXPORT("rk_alloc") void *rk_alloc(int32_t n) { return rk_alloc_bytes(n < 0 ? 0 : (size_t)n); }

/* ---- memory ------------------------------------------------------------------------ */

extern unsigned char __heap_base;
static uintptr_t heap_top;

void *rk_alloc_bytes(size_t n) {
  if (!heap_top) heap_top = (uintptr_t)&__heap_base;
  uintptr_t p = (heap_top + 15) & ~(uintptr_t)15;
  if (n > 0x7fffffffu || p + n < p) rk_fail("out of memory");
  uintptr_t end = p + n;
  uintptr_t have = __builtin_wasm_memory_size(0) * 65536u;
  if (end > have) {
    uintptr_t pages = (end - have + 65535u) / 65536u;
    if (__builtin_wasm_memory_grow(0, pages) == (size_t)-1) rk_fail("out of memory");
  }
  heap_top = end;
  return (void *)p;
}

void *memcpy(void *dst, const void *src, size_t n) {
  uint8_t *d = dst;
  const uint8_t *s = src;
  while (n--) *d++ = *s++;
  return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
  uint8_t *d = dst;
  const uint8_t *s = src;
  if (d < s) {
    while (n--) *d++ = *s++;
  } else {
    while (n--) d[n] = s[n];
  }
  return dst;
}

void *memset(void *dst, int c, size_t n) {
  uint8_t *d = dst;
  while (n--) *d++ = (uint8_t)c;
  return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
  const uint8_t *x = a, *y = b;
  for (size_t i = 0; i < n; ++i)
    if (x[i] != y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}

size_t rk_strlen(const char *s) {
  size_t n = 0;
  while (s[n]) ++n;
  return n;
}

rk_str rk_s(const char *cstr) {
  rk_str s = {cstr, (uint32_t)rk_strlen(cstr)};
  return s;
}

int rk_str_eq(rk_str a, rk_str b) { return a.len == b.len && memcmp(a.ptr, b.ptr, a.len) == 0; }

int rk_str_starts_with(rk_str s, rk_str prefix) {
  return s.len >= prefix.len && memcmp(s.ptr, prefix.ptr, prefix.len) == 0;
}

char *rk_str_dup(rk_str s) {
  char *p = rk_alloc_bytes(s.len + 1);
  memcpy(p, s.ptr, s.len);
  p[s.len] = 0;
  return p;
}

void rk_buf_put(rk_buf *b, const void *data, uint32_t n) {
  if (b->len + n < b->len) rk_fail("buffer overflow");
  if (b->len + n > b->cap) {
    uint32_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + n) cap *= 2;
    uint8_t *p = rk_alloc_bytes(cap);
    if (b->len) memcpy(p, b->data, b->len);
    b->data = p;
    b->cap = cap;
  }
  memcpy(b->data + b->len, data, n);
  b->len += n;
}

void rk_buf_puts(rk_buf *b, rk_str s) { rk_buf_put(b, s.ptr, s.len); }

void rk_buf_put_hex(rk_buf *b, uint64_t v) {
  char tmp[16];
  int n = 0;
  do {
    tmp[n++] = "0123456789abcdef"[v & 15];
    v >>= 4;
  } while (v);
  while (n) rk_buf_put(b, &tmp[--n], 1);
}

void rk_buf_put_dec(rk_buf *b, uint64_t v) {
  char tmp[20];
  int n = 0;
  do {
    tmp[n++] = (char)('0' + v % 10);
    v /= 10;
  } while (v);
  while (n) rk_buf_put(b, &tmp[--n], 1);
}

rk_str rk_buf_str(const rk_buf *b) {
  rk_str s = {(const char *)b->data, b->len};
  return s;
}

void rk_log(rk_str text) { rk_host_log(text.ptr, (int32_t)text.len); }

_Noreturn void rk_fail(const char *message) {
  rk_host_fail(message, (int32_t)rk_strlen(message));
  __builtin_trap();
}

/* ---- the encoding ---------------------------------------------------------------- */

static const uint8_t *need(rk_reader *r, uint32_t n) {
  if ((uint32_t)(r->end - r->p) < n) rk_fail("malformed blob from the host");
  const uint8_t *p = r->p;
  r->p += n;
  return p;
}

uint8_t rk_read_u8(rk_reader *r) { return *need(r, 1); }

uint32_t rk_read_u32(rk_reader *r) {
  const uint8_t *p = need(r, 4);
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

uint64_t rk_read_u64(rk_reader *r) {
  uint64_t lo = rk_read_u32(r);
  uint64_t hi = rk_read_u32(r);
  return lo | hi << 32;
}

rk_str rk_read_str(rk_reader *r) {
  uint32_t n = rk_read_u32(r);
  rk_str s = {(const char *)need(r, n), n};
  return s;
}

rk_reader rk_read_record(rk_reader *r) {
  uint32_t n = rk_read_u32(r);
  const uint8_t *p = need(r, n);
  rk_reader sub = {p, p + n};
  return sub;
}

uint32_t rk_read_list(rk_reader *r) {
  uint32_t n = rk_read_u32(r);
  if (n > (uint32_t)(r->end - r->p)) rk_fail("malformed list from the host");
  return n;
}

void rk_put_u8(rk_buf *b, uint8_t v) { rk_buf_put(b, &v, 1); }

void rk_put_u32(rk_buf *b, uint32_t v) {
  uint8_t t[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
  rk_buf_put(b, t, 4);
}

void rk_put_u64(rk_buf *b, uint64_t v) {
  rk_put_u32(b, (uint32_t)v);
  rk_put_u32(b, (uint32_t)(v >> 32));
}

void rk_put_str(rk_buf *b, rk_str s) {
  rk_put_u32(b, s.len);
  rk_buf_put(b, s.ptr, s.len);
}

uint32_t rk_begin(rk_buf *b) {
  uint32_t at = b->len;
  rk_put_u32(b, 0);
  return at;
}

static void patch(rk_buf *b, uint32_t at, uint32_t v) {
  b->data[at] = (uint8_t)v;
  b->data[at + 1] = (uint8_t)(v >> 8);
  b->data[at + 2] = (uint8_t)(v >> 16);
  b->data[at + 3] = (uint8_t)(v >> 24);
}

void rk_end_record(rk_buf *b, uint32_t at) { patch(b, at, b->len - at - 4); }

void rk_end_list(rk_buf *b, uint32_t at, uint32_t count) { patch(b, at, count); }

/* ---- facts ------------------------------------------------------------------------ */

/* Takes the blob the last fact import staged. */
static rk_reader take(int32_t n) {
  rk_reader r = {0, 0};
  if (n < 0) return r;
  uint8_t *p = rk_alloc_bytes((size_t)n);
  rk_host_take(p);
  r.p = p;
  r.end = p + n;
  return r;
}

void rk_get_program(rk_program *out) {
  memset(out, 0, sizeof *out);
  rk_reader all = take(rk_host_program_info());
  rk_reader r = rk_read_record(&all);
  out->language = rk_read_str(&r);
  out->compiler = rk_read_str(&r);
  out->pointer_size = rk_read_u8(&r);
  out->big_endian = rk_read_u8(&r);
  out->has_entry = rk_read_u8(&r);
  out->entry = rk_read_u64(&r);
  out->file_size = rk_read_u64(&r);
  out->nblocks = rk_read_list(&r);
  out->blocks = rk_alloc_bytes(sizeof(rk_block) * out->nblocks);
  for (uint32_t i = 0; i < out->nblocks; ++i) {
    rk_reader b = rk_read_record(&r);
    out->blocks[i].name = rk_read_str(&b);
    out->blocks[i].start = rk_read_u64(&b);
    out->blocks[i].size = rk_read_u64(&b);
    out->blocks[i].perms = rk_read_u8(&b);
    out->blocks[i].initialized = rk_read_u8(&b);
  }
}

const rk_block *rk_block_at(const rk_program *p, uint64_t addr) {
  for (uint32_t i = 0; i < p->nblocks; ++i)
    if (addr >= p->blocks[i].start && addr - p->blocks[i].start < p->blocks[i].size) return &p->blocks[i];
  return 0;
}

uint32_t rk_read_memory(uint64_t addr, void *dst, uint32_t n) {
  return (uint32_t)rk_host_memory_read(addr, dst, (int32_t)n);
}

uint32_t rk_get_functions(rk_function **out) {
  rk_reader r = take(rk_host_functions());
  uint32_t n = rk_read_list(&r);
  rk_function *fs = rk_alloc_bytes(sizeof(rk_function) * n);
  for (uint32_t i = 0; i < n; ++i) {
    rk_reader f = rk_read_record(&r);
    fs[i].entry = rk_read_u64(&f);
    fs[i].name = rk_read_str(&f);
    fs[i].flags = rk_read_u32(&f);
    fs[i].nranges = rk_read_list(&f);
    fs[i].ranges = rk_alloc_bytes(sizeof(rk_range) * fs[i].nranges);
    for (uint32_t k = 0; k < fs[i].nranges; ++k) {
      fs[i].ranges[k].first = rk_read_u64(&f);
      fs[i].ranges[k].last = rk_read_u64(&f);
    }
  }
  *out = fs;
  return n;
}

static rk_varnode read_varnode(rk_reader *r) {
  rk_reader v = rk_read_record(r);
  rk_varnode out;
  out.space = rk_read_str(&v);
  out.offset = rk_read_u64(&v);
  out.size = rk_read_u32(&v);
  return out;
}

int rk_get_function_code(uint64_t entry, rk_code *out) {
  memset(out, 0, sizeof *out);
  int32_t n = rk_host_function_code(entry);
  if (n < 0) return 0;
  rk_reader all = take(n);
  rk_reader r = rk_read_record(&all);
  out->entry = rk_read_u64(&r);
  out->ninsns = rk_read_list(&r);
  out->insns = rk_alloc_bytes(sizeof(rk_insn) * out->ninsns);
  for (uint32_t i = 0; i < out->ninsns; ++i) {
    rk_reader ir = rk_read_record(&r);
    rk_insn *in = &out->insns[i];
    in->address = rk_read_u64(&ir);
    in->length = rk_read_u32(&ir);
    in->mnemonic = rk_read_str(&ir);
    in->text = rk_read_str(&ir);
    in->npcode = rk_read_list(&ir);
    in->pcode = rk_alloc_bytes(sizeof(rk_pcode) * in->npcode);
    for (uint32_t k = 0; k < in->npcode; ++k) {
      rk_reader orr = rk_read_record(&ir);
      rk_pcode *op = &in->pcode[k];
      op->opcode = rk_read_str(&orr);
      op->has_output = rk_read_u8(&orr);
      if (op->has_output) op->output = read_varnode(&orr);
      op->ninputs = rk_read_list(&orr);
      op->inputs = rk_alloc_bytes(sizeof(rk_varnode) * op->ninputs);
      for (uint32_t j = 0; j < op->ninputs; ++j) op->inputs[j] = read_varnode(&orr);
    }
  }
  return 1;
}

rk_str rk_get_symbol_name(uint64_t addr) {
  rk_str s = {"", 0};
  int32_t n = rk_host_symbol_name(addr);
  if (n <= 0) return s;
  rk_reader r = take(n);
  s.ptr = (const char *)r.p;
  s.len = (uint32_t)n;
  return s;
}

uint64_t rk_file_size(void) { return (uint64_t)rk_host_file_size(); }

uint32_t rk_read_file(uint64_t offset, void *dst, uint32_t n) {
  return (uint32_t)rk_host_file_read(offset, dst, (int32_t)n);
}

/* ---- results ------------------------------------------------------------------------- */

static void list_start(rk_list_out *out) {
  memset(out, 0, sizeof *out);
  out->at = rk_begin(&out->buf);
}

static void list_finish(rk_list_out *out) {
  rk_end_list(&out->buf, out->at, out->count);
  rk_host_set_output(out->buf.data, (int32_t)out->buf.len);
}

static void emit(rk_list_out *out, uint8_t kind, uint64_t address, rk_str text, rk_str sub) {
  uint32_t rec = rk_begin(&out->buf);
  rk_put_u8(&out->buf, kind);
  rk_put_u64(&out->buf, address);
  rk_put_str(&out->buf, text);
  rk_put_str(&out->buf, sub);
  rk_end_record(&out->buf, rec);
  out->count++;
}

void rk_emit_fact(rk_list_out *out, uint8_t kind, uint64_t address, rk_str text, rk_str sub) {
  emit(out, kind, address, text, sub);
}

void rk_emit_edit(rk_list_out *out, uint8_t op, uint64_t address, rk_str text, rk_str sub) {
  emit(out, op, address, text, sub);
}

void rk_load_target(rk_load_out *out, rk_str language, rk_str compiler) {
  out->head.len = 0;
  rk_put_str(&out->head, language);
  rk_put_str(&out->head, compiler);
}

void rk_load_entry(rk_load_out *out, uint64_t entry) {
  out->has_entry = 1;
  out->entry = entry;
}

void rk_load_block(rk_load_out *out, rk_str name, uint64_t start, uint64_t size, uint64_t file_offset,
                   uint64_t file_size, uint8_t perms) {
  uint32_t rec = rk_begin(&out->blocks);
  rk_put_str(&out->blocks, name);
  rk_put_u64(&out->blocks, start);
  rk_put_u64(&out->blocks, size);
  rk_put_u64(&out->blocks, file_offset);
  rk_put_u64(&out->blocks, file_size);
  rk_put_u8(&out->blocks, perms);
  rk_end_record(&out->blocks, rec);
  out->nblocks++;
}

void rk_load_symbol(rk_load_out *out, rk_str name, uint64_t address, uint64_t size, int is_function) {
  uint32_t rec = rk_begin(&out->symbols);
  rk_put_str(&out->symbols, name);
  rk_put_u64(&out->symbols, address);
  rk_put_u64(&out->symbols, size);
  rk_put_u8(&out->symbols, is_function ? 1 : 0);
  rk_end_record(&out->symbols, rec);
  out->nsymbols++;
}

/* ---- entry points ------------------------------------------------------------------------- */

int32_t rk__analyze(const uint8_t *in, int32_t n, rk_analyze_fn fn) {
  rk_reader all = {in, in + n};
  rk_reader r = rk_read_record(&all);
  rk_analyze_request req;
  req.scope = rk_read_u8(&r);
  req.address = rk_read_u64(&r);
  rk_list_out out;
  list_start(&out);
  int rc = fn(&req, &out);
  if (rc == 0) list_finish(&out);
  return rc;
}

int32_t rk__load(const uint8_t *in, int32_t n, rk_load_fn fn) {
  rk_load_out out;
  memset(&out, 0, sizeof out);
  int rc = fn(in, (uint32_t)n, &out);
  if (rc != 0) return rc;
  if (!out.head.len) rk_fail("the loader set no language (rk_load_target)");
  rk_buf res = {0, 0, 0};
  uint32_t rec = rk_begin(&res);
  rk_buf_put(&res, out.head.data, out.head.len);
  rk_put_u8(&res, out.has_entry);
  rk_put_u64(&res, out.entry);
  rk_put_u32(&res, out.nblocks);
  if (out.blocks.len) rk_buf_put(&res, out.blocks.data, out.blocks.len);
  rk_put_u32(&res, out.nsymbols);
  if (out.symbols.len) rk_buf_put(&res, out.symbols.data, out.symbols.len);
  rk_end_record(&res, rec);
  rk_host_set_output(res.data, (int32_t)res.len);
  return 0;
}

rk_str rk_command_arg(const rk_command_request *req, const char *key) {
  rk_str k = rk_s(key);
  for (uint32_t i = 0; i < req->nargs; ++i)
    if (rk_str_eq(req->args[i].key, k)) return req->args[i].value;
  rk_str none = {0, 0};
  return none;
}

int32_t rk__command(const uint8_t *in, int32_t n, rk_command_fn fn) {
  rk_reader all = {in, in + n};
  rk_reader r = rk_read_record(&all);
  rk_command_request req;
  req.program_id = rk_read_str(&r);
  req.nargs = rk_read_list(&r);
  req.args = rk_alloc_bytes(sizeof(rk_arg) * req.nargs);
  for (uint32_t i = 0; i < req.nargs; ++i) {
    rk_reader a = rk_read_record(&r);
    req.args[i].key = rk_read_str(&a);
    req.args[i].value = rk_read_str(&a);
  }
  rk_list_out out;
  list_start(&out);
  int rc = fn(&req, &out);
  if (rc == 0) list_finish(&out);
  return rc;
}
