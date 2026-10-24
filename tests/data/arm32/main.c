// The fixture's main (kit.h), ARM code.
#include "kit.h"

struct bd g_bd;
struct dev g_devs[4];
struct queue g_queue;
int g_items[16];
u8 g_mem[4 * 256];
u8 g_scratch[64];
volatile int g_sink;


static const char kNames[4][8] = {"uart", "spi", "i2c", "flash"};

int main(void) {
  g_bd.block_size = 256;
  g_bd.block_count = 4;
  g_bd.mem = g_mem;
  for (int i = 0; i < 4; i++) {
    dev_init(&g_devs[i], i + 1, kNames[i], i & 1 ? h_read : h_write);
    if (i) g_devs[i - 1].next = &g_devs[i];
  }
  g_queue.size = 16;
  g_queue.items = g_items;
  bd_erase(&g_bd, 1);
  bd_write(&g_bd, 1, 16, "hello", 6);
  bd_copy(&g_bd, 1, 2, g_scratch, sizeof g_scratch);
  int r = bd_read_from_thumb(&g_bd, 2, 16, g_scratch, 6);
  r += sum_block(&g_bd, 2);
  for (int i = 0; i < 4; i++) {
    dev_touch(&g_devs[i]);
    r += dev_dispatch(&g_devs[i], i);
    r += dev_dispatch_veneer(&g_devs[i], i * 2);
    r += use_mix_dev(&g_devs[i], r);
    queue_push(&g_queue, r);
  }
  int v = 0;
  while (queue_pop(&g_queue, &v) == 0) r ^= v;
  r += run_handlers(dev_find(g_devs, 3), 3) + dev_count_all(g_devs);
  r += use_mix(r, queue_len(&g_queue));
  char buf[16];
  r += fmt_int(buf, r, 10) + kit_strcmp(buf, kNames[1]);
  r += (int)crc32_update(0xffffffffu, g_mem, sizeof g_mem);
  r += to_fixed(lerpf(1.0f, 3.0f, 0.25f)) + to_fixed(scale_avg(g_items, 16, 0.5f));
  r += cxx_main(r);
  g_sink = r;
  return r;
}
