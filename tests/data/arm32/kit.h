// A small ARM firmware in C and C++ for inference on 32-bit ARM
// (docs/infer.md, "32-bit ARM"): ARM and Thumb code calling each other,
// an SDK's interrupt pair written in assembly, a function of seven
// arguments, structures reached through pointers, sizes and block numbers
// that are integers, a table of Thumb handlers, veneers, and soft float.
// Built by make_fixture.py with clang for ARMv5TE; nothing here comes from
// a real SDK or product.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

// The SDK's interrupt pair (veneers.S): the state Disable returns is what
// Restore takes back.
int OS_DisableInterrupts(void);
void OS_RestoreInterrupts(int state);

struct dev;
typedef int (*dev_handler)(struct dev *d, int arg);

struct dev {
  int id;
  u32 flags;
  const char *name;
  dev_handler handler;
  int count;
  u8 state;
  u8 pad[3];
  struct dev *next;
};

// A block device: blocks of block_size bytes in memory.
struct bd {
  u32 block_size;
  u32 block_count;
  u8 *mem;
  int reads;
  int writes;
  int errors;
};

struct queue {
  int head;
  int tail;
  int size;
  int *items;
};

void *kit_memcpy(void *dst, const void *src, u32 n);
void *kit_memset(void *dst, int c, u32 n);
u32 kit_strlen(const char *s);
int kit_strcmp(const char *a, const char *b);

int dev_init(struct dev *d, int id, const char *name, dev_handler h);
int dev_dispatch(struct dev *d, int arg);
void dev_touch(struct dev *d);
struct dev *dev_find(struct dev *list, int id);
int dev_count_all(struct dev *list);

int bd_read(struct bd *bd, u32 block, u32 off, void *buf, u32 size);
int bd_write(struct bd *bd, u32 block, u32 off, const void *buf, u32 size);
int bd_erase(struct bd *bd, u32 block);
int bd_copy(struct bd *bd, u32 from, u32 to, u8 *scratch, u32 size);

int mix7(int a, int b, int c, int d, int e, int f, int g);
int use_mix(int x, int y);
int use_mix_dev(struct dev *d, int k);

// Thumb code (thumb.c).
u32 crc32_update(u32 crc, const u8 *p, u32 n);
int queue_push(struct queue *q, int v);
int queue_pop(struct queue *q, int *out);
int queue_len(const struct queue *q);
int h_reset(struct dev *d, int arg);
int h_read(struct dev *d, int arg);
int h_write(struct dev *d, int arg);
int run_handlers(struct dev *d, int n);
int fmt_int(char *out, int v, int base);
int sum_block(struct bd *bd, u32 block);

// Veneers (veneers.S): a long-branch veneer to dev_dispatch and a Thumb
// stub into ARM bd_read.
int dev_dispatch_veneer(struct dev *d, int arg);
int bd_read_from_thumb(struct bd *bd, u32 block, u32 off, void *buf, u32 size);

// Soft float (softfloat.c): clang's calls to the runtime's helpers.
float lerpf(float a, float b, float t);
float scale_avg(const int *v, int n, float k);
int to_fixed(float f);

int cxx_main(int seed);

#ifdef __cplusplus
}
#endif
