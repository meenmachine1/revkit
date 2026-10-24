// Thumb code of the fixture (kit.h), built with -mthumb.
#include "kit.h"

u32 crc32_update(u32 crc, const u8 *p, u32 n) {
  while (n--) {
    crc ^= *p++;
    for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0xedb88320u & -(crc & 1));
  }
  return crc;
}

int queue_push(struct queue *q, int v) {
  int next = (q->tail + 1) % q->size;
  if (next == q->head) return -1;
  int s = OS_DisableInterrupts();
  q->items[q->tail] = v;
  q->tail = next;
  OS_RestoreInterrupts(s);
  return 0;
}

int queue_pop(struct queue *q, int *out) {
  if (q->head == q->tail) return -1;
  int s = OS_DisableInterrupts();
  *out = q->items[q->head];
  q->head = (q->head + 1) % q->size;
  OS_RestoreInterrupts(s);
  return 0;
}

int queue_len(const struct queue *q) { return (q->tail - q->head + q->size) % q->size; }

int h_reset(struct dev *d, int arg) {
  d->state = 0;
  d->count = arg;
  return 0;
}

int h_read(struct dev *d, int arg) {
  d->state = 1;
  return d->id * 16 + arg + d->count;
}

int h_write(struct dev *d, int arg) {
  d->state = 2;
  d->flags |= (u32)arg << 4;
  return d->id - arg;
}

static dev_handler const kHandlers[] = {h_reset, h_read, h_write};

int run_handlers(struct dev *d, int n) {
  int r = 0;
  if (!d) return -1;
  for (int i = 0; i < n; i++) r += kHandlers[i % 3](d, i);
  return r;
}

int fmt_int(char *out, int v, int base) {
  char tmp[12];
  int n = 0, neg = v < 0;
  unsigned u = neg ? -(unsigned)v : (unsigned)v;
  do {
    tmp[n++] = "0123456789abcdef"[u % base];
    u /= base;
  } while (u && n < 11);
  int len = 0;
  if (neg) out[len++] = '-';
  while (n) out[len++] = tmp[--n];
  out[len] = 0;
  return len;
}

int sum_block(struct bd *bd, u32 block) {
  u8 buf[32];
  int s = 0;
  for (u32 off = 0; off < bd->block_size; off += sizeof buf) {
    if (bd_read_from_thumb(bd, block, off, buf, sizeof buf)) return -1;
    for (u32 i = 0; i < sizeof buf; i++) s += buf[i];
  }
  return s;
}
