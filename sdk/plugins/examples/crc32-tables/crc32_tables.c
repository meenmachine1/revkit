/* crc32-tables: finds 256-entry CRC-32 lookup tables in initialized memory.
 *
 * Program scope: one run reads every initialized block, so it depends on
 * every page it read; a patched byte anywhere re-runs it. Emits, at each
 * table, a label (crc32_table), a data type (uint32_t[256]) and a plate
 * comment saying which polynomial and byte order. */
#include "revkit_plugin.h"

typedef struct {
  const char *what;
  uint32_t table[256];
  int big_endian;
} variant;

static void reflected(uint32_t *t, uint32_t poly) {
  for (uint32_t i = 0; i < 256; ++i) {
    uint32_t c = i;
    for (int k = 0; k < 8; ++k) c = (c & 1) ? (c >> 1) ^ poly : c >> 1;
    t[i] = c;
  }
}

static void normal(uint32_t *t, uint32_t poly) {
  for (uint32_t i = 0; i < 256; ++i) {
    uint32_t c = i << 24;
    for (int k = 0; k < 8; ++k) c = (c & 0x80000000u) ? (c << 1) ^ poly : c << 1;
    t[i] = c;
  }
}

static uint32_t load32(const uint8_t *p, int big_endian) {
  if (big_endian) return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
  return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0];
}

enum { kTable = 1024, kChunk = 64 * 1024 };

static int analyze(const rk_analyze_request *req, rk_list_out *facts) {
  (void)req;
  static variant v[4];
  reflected(v[0].table, 0xEDB88320u), v[0].what = "CRC-32 table, reflected polynomial 0xEDB88320, little-endian";
  reflected(v[1].table, 0xEDB88320u), v[1].what = "CRC-32 table, reflected polynomial 0xEDB88320, big-endian";
  v[1].big_endian = 1;
  normal(v[2].table, 0x04C11DB7u), v[2].what = "CRC-32 table, polynomial 0x04C11DB7 (MSB first), little-endian";
  normal(v[3].table, 0x04C11DB7u), v[3].what = "CRC-32 table, polynomial 0x04C11DB7 (MSB first), big-endian";
  v[3].big_endian = 1;

  rk_program prog;
  rk_get_program(&prog);
  uint8_t *buf = rk_alloc_bytes(kChunk + kTable);
  uint32_t found = 0;
  for (uint32_t b = 0; b < prog.nblocks; ++b) {
    const rk_block *blk = &prog.blocks[b];
    if (!blk->initialized || blk->size < kTable) continue;
    /* Chunks overlap by a table's length, so one straddling a boundary is
     * seen whole in the next chunk; a table starting in the overlap is
     * only reported from the chunk where it starts before kChunk. */
    for (uint64_t off = 0; off + kTable <= blk->size; off += kChunk) {
      uint32_t want = kChunk + kTable;
      if (blk->size - off < want) want = (uint32_t)(blk->size - off);
      uint32_t got = rk_read_memory(blk->start + off, buf, want);
      for (uint32_t i = 0; i + kTable <= got && i < kChunk; i += 4) {
        if (buf[i] | buf[i + 1] | buf[i + 2] | buf[i + 3]) continue; /* entry 0 is always 0 */
        for (int k = 0; k < 4; ++k) {
          if (load32(buf + i + 4, v[k].big_endian) != v[k].table[1]) continue;
          int match = 1;
          for (uint32_t e = 2; e < 256 && match; ++e) match = load32(buf + i + 4 * e, v[k].big_endian) == v[k].table[e];
          if (!match) continue;
          uint64_t at = blk->start + off + i;
          rk_emit_fact(facts, RK_FACT_LABEL, at, rk_s("crc32_table"), rk_s(""));
          rk_emit_fact(facts, RK_FACT_DATA_TYPE, at, rk_s("uint32_t[256]"), rk_s(""));
          rk_emit_fact(facts, RK_FACT_COMMENT, at, rk_s(v[k].what), rk_s("plate"));
          ++found;
          break;
        }
      }
    }
  }
  rk_buf msg = {0, 0, 0};
  rk_buf_puts(&msg, rk_s("crc32-tables: "));
  rk_buf_put_dec(&msg, found);
  rk_buf_puts(&msg, rk_s(" table(s)"));
  rk_log(rk_buf_str(&msg));
  return 0;
}

RK_ANALYZER(analyze)
