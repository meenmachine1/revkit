# RKRAW

A trivial container for raw code and data: a header naming the processor
(as a Ghidra language id), the blocks to map, an entry point and symbols.
All integers are little-endian.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 6 | magic `RKRAW\x01` (the last byte is the format version) |
| 6 | 2 | number of blocks |
| 8 | 8 | entry point, or `0xffffffffffffffff` for none |
| 16 | 40 | language id, NUL-padded (`x86:LE:64:default`) |
| 56 | 16 | compiler spec id, NUL-padded (empty: the language's default) |
| 72 | 4 | number of symbols |
| 76 | 4 | reserved, 0 |
| 80 | 48 × blocks | `name[16]`, `address u64`, `size u64`, `file_offset u32`, `file_size u32`, `perms u32` (1 r, 2 w, 4 x), reserved `u32` |
| ... | 32 × symbols | `name[20]` (NUL-padded), `address u64`, `flags u32` (1: a function) |

A block's first `file_size` bytes come from the file at `file_offset`; the
rest of its `size` reads as zero.
