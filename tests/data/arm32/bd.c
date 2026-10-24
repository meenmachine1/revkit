// The block device (kit.h), ARM code.
#include "kit.h"

int bd_read(struct bd *bd, u32 block, u32 off, void *buf, u32 size) {
  if (block >= bd->block_count || off + size > bd->block_size) {
    bd->errors++;
    return -22;
  }
  kit_memcpy(buf, bd->mem + block * bd->block_size + off, size);
  bd->reads++;
  return 0;
}

int bd_write(struct bd *bd, u32 block, u32 off, const void *buf, u32 size) {
  if (block >= bd->block_count || off + size > bd->block_size) {
    bd->errors++;
    return -22;
  }
  int s = OS_DisableInterrupts();
  kit_memcpy(bd->mem + block * bd->block_size + off, buf, size);
  bd->writes++;
  OS_RestoreInterrupts(s);
  return 0;
}

int bd_erase(struct bd *bd, u32 block) {
  if (block >= bd->block_count) return -22;
  kit_memset(bd->mem + block * bd->block_size, 0xff, bd->block_size);
  return 0;
}

int bd_copy(struct bd *bd, u32 from, u32 to, u8 *scratch, u32 size) {
  for (u32 off = 0; off < bd->block_size; off += size) {
    int err = bd_read(bd, from, off, scratch, size);
    if (err) return err;
    err = bd_write(bd, to, off, scratch, size);
    if (err) return err;
  }
  return 0;
}

