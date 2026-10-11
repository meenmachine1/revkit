/* rkraw-loader: loads the RKRAW format (README.md beside this file).
 * Every field is bounds-checked; a malformed file fails the load with a
 * message rather than producing a half-built image. */
#include "revkit_plugin.h"

enum { kHeader = 80, kBlock = 48, kSymbol = 32 };

static uint32_t u32(const uint8_t *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t u64(const uint8_t *p) { return (uint64_t)u32(p) | (uint64_t)u32(p + 4) << 32; }

/* A NUL-padded fixed-size field. */
static rk_str field(const uint8_t *p, uint32_t max) {
  uint32_t n = 0;
  while (n < max && p[n]) ++n;
  rk_str s = {(const char *)p, n};
  return s;
}

static int load(const uint8_t *file, uint32_t size, rk_load_out *out) {
  if (size < kHeader) rk_fail("RKRAW: file shorter than its header");
  if (memcmp(file, "RKRAW\x01", 6) != 0) rk_fail("RKRAW: bad magic or unsupported version");
  uint32_t nblocks = (uint32_t)file[6] | (uint32_t)file[7] << 8;
  uint64_t entry = u64(file + 8);
  rk_str language = field(file + 16, 40);
  rk_str compiler = field(file + 56, 16);
  uint32_t nsymbols = u32(file + 72);
  if (nblocks == 0) rk_fail("RKRAW: no blocks");
  if (language.len == 0) rk_fail("RKRAW: no language");
  uint64_t tables = (uint64_t)kHeader + (uint64_t)nblocks * kBlock + (uint64_t)nsymbols * kSymbol;
  if (tables > size) rk_fail("RKRAW: block or symbol table past the end of the file");

  rk_load_target(out, language, compiler);
  if (entry != ~(uint64_t)0) rk_load_entry(out, entry);
  for (uint32_t i = 0; i < nblocks; ++i) {
    const uint8_t *b = file + kHeader + i * kBlock;
    uint64_t address = u64(b + 16), bsize = u64(b + 24);
    uint32_t file_offset = u32(b + 32), file_size = u32(b + 36), perms = u32(b + 40);
    if (bsize == 0 || address + (bsize - 1) < address) rk_fail("RKRAW: a block is empty or wraps");
    if (file_size > bsize) rk_fail("RKRAW: a block has more file bytes than its size");
    if ((uint64_t)file_offset + file_size > size) rk_fail("RKRAW: a block's bytes are past the end of the file");
    rk_load_block(out, field(b, 16), address, bsize, file_offset, file_size, (uint8_t)(perms & 7));
  }
  const uint8_t *syms = file + kHeader + nblocks * kBlock;
  for (uint32_t i = 0; i < nsymbols; ++i) {
    const uint8_t *s = syms + i * kSymbol;
    rk_str name = field(s, 20);
    if (name.len == 0) continue;
    rk_load_symbol(out, name, u64(s + 20), 0, u32(s + 28) & 1);
  }
  return 0;
}

RK_LOADER(load)
