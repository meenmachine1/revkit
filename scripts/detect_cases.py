#!/usr/bin/env python3
"""Builds the test cases for auto-detection (docs/autodetect.md) from the
firmware corpus, whose images have known answers.

  detect_cases.py [--corpus out/firmware-corpus] [--out build/detect-cases]
                  [--only GLOB]

Every image of the corpus gives several cases, each a file and what a
detector should say about it (cases.json):

  plain        the image as built: its language, its base, offset 0
  hdr-fields   a vendor header before it: a magic, the payload's length, its
               CRC-32 and a version string, padded to the header's size
  hdr-opaque   a header that says nothing a detector can check (text and
               fill)
  pad          fill after the image, to a round size
  blob         compressed data after the image

Each case also carries the image's memory regions beyond its own bytes
(RAM, MMIO) in the raw loader's spelling: `regions`, exactly, where they
are known (fwkit's images: what its linker script and board put there, and
what corpus/firmware/regions-truth.json adds), else null; and
`regions_partial`, windows of the board's memory map they are somewhere in
(U-Boot's images: regions-truth.json, from the chips' and boards' manuals).
A file that is no program has none.

and images built here with clang (BUILT): position-independent code for
AArch64 and RISC-V (kind "pic"), and Thumb code with no vector table for
ARMv7 and ARMv4T (kind "thumb"), with their languages and bases; and a few
files that are no program at all, which a detector should refuse:
random bytes, compressed data, text, fill, and a table of numbers.

  near-miss    an image of a fixed-width processor turned into code of a
               processor derived from it, which revkit has no language
               for: some major opcodes trade places (a fixed permutation),
               while the branches, jumps and calls keep their encodings, so
               control flow still lands where it should. A detector may
               name the processor it came from, but not with confidence
               (near_miss_of: that processor).

Everything is derived from the corpus and a fixed seed, so two runs give the
same bytes. Nothing here is committed: the cases are built where they are
used (scripts/detect_score.py).
"""
import argparse
import fnmatch
import hashlib
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

HEADER_SIZES = [0x40, 0x100, 0x200, 0x400, 0x1000]


def pick(name, salt, choices):
    h = hashlib.sha256(f'{salt}:{name}'.encode()).digest()
    return choices[int.from_bytes(h[:4], 'big') % len(choices)]


def rng(name, salt):
    return random.Random(hashlib.sha256(f'{salt}:{name}'.encode()).digest())


def filler_text(r, n):
    """Text of about n bytes: log lines, as firmware carries them."""
    words = ('init start stop error timeout device sensor buffer length value retry flash write read '
             'config network connect failed ok version update checksum invalid state task queue').split()
    out = []
    size = 0
    while size < n:
        line = ' '.join(r.choice(words) for _ in range(r.randint(3, 9)))
        line = f'[{r.randint(0, 99999):05d}] {line} {r.randint(0, 255)}\r\n'
        out.append(line)
        size += len(line)
    return ''.join(out).encode()[:n]


def variants(image, data):
    """(suffix, kind, bytes, offset) for each case of one corpus image."""
    name = image['name']
    big = ':BE:' in image['language']
    u32 = '>I' if big else '<I'
    yield '', 'plain', data, 0

    size = pick(name, 'fields', HEADER_SIZES)
    head = b'FWIM' + struct.pack(u32, len(data)) + struct.pack(u32, zlib.crc32(data)) + b'v1.4.2-release\0'
    yield '+hdr-fields', 'hdr-fields', head.ljust(size, b'\xff') + data, size

    size = pick(name, 'opaque', HEADER_SIZES)
    head = filler_text(rng(name, 'opaque'), min(size, 96)).ljust(size, b'\0')
    yield '+hdr-opaque', 'hdr-opaque', head + data, size

    end = (len(data) + 0x10000) & ~0xffff
    yield '+pad', 'pad', data + b'\xff' * (end - len(data)), 0

    blob = zlib.compress(rng(name, 'blob').randbytes(1 << 15) + filler_text(rng(name, 'blobtext'), 1 << 16), 9)
    aligned = data + b'\0' * (-len(data) % 16)
    yield '+blob', 'blob', aligned + blob, 0


# Fixed-width processors whose code the near-miss cases derive a processor
# from: (instruction bytes, shift and width of the major opcode field,
# opcodes kept: the transfers', so that control flow is intact).
DERIVE = {
    'MIPS': (4, 26, 6, {0, 1, 2, 3, 4, 5, 6, 7}),          # SPECIAL (jr, jalr), REGIMM, j, jal, branches
    'PowerPC': (4, 26, 6, {16, 18, 19}),                     # bc, b, bclr/bcctr
    'SuperH4': (2, 12, 4, {0x0, 0x4, 0x8, 0x9, 0xa, 0xb, 0xd}),  # rts, jsr/jmp, bt/bf, PC-relative loads, bra, bsr
}


def derived(image, data):
    """The image as code of a processor derived from its own (a near miss),
    or None for a processor DERIVE doesn't cover."""
    processor = image['language'].split(':')[0]
    if processor not in DERIVE:
        return None
    size, shift, width, kept = DERIVE[processor]
    r = rng(image['name'], 'derive')
    free = [v for v in range(1 << width) if v not in kept]
    moved = free[:]
    r.shuffle(moved)
    perm = dict(zip(free, moved))
    fmt = ('>' if ':BE:' in image['language'] else '<') + ('I' if size == 4 else 'H')
    mask = ((1 << width) - 1) << shift
    out = bytearray(data)
    for at in range(0, len(data) - size + 1, size):
        word, = struct.unpack_from(fmt, data, at)
        op = (word & mask) >> shift
        if op in perm:
            struct.pack_into(fmt, out, at, (word & ~mask) | (perm[op] << shift))
    return bytes(out)


# Images the kit's corpus lacks, built here with clang and lld from mcukit's
# sources (corpus/firmware/src): position-independent code for AArch64 and
# RISC-V (addresses made from the program counter, adrp and auipc), linked
# two ways: at its address, so that only tables of pointers in data name
# addresses ("pic"), and as a position-independent executable whose
# pointers are relocations it applies itself, the slots left zero
# ("rela"); and Thumb code with no vector table, for ARMv7 (Thumb-2) and
# ARMv4T (Thumb only), which tells the variants apart. (name, language,
# base, arch, clang target and options, link options)
BUILT = [
    ('pic/mcukit-aarch64', 'AARCH64:LE:64:v8A:default', 0x40280000, 'aarch64',
     ['--target=aarch64-none-elf', '-O2'], []),
    ('pic/mcukit-aarch64-rela', 'AARCH64:LE:64:v8A:default', 0x40280000, 'aarch64',
     ['--target=aarch64-none-elf', '-O2', '-fPIE'], ['-pie', '--no-dynamic-linker', '-z', 'norelro']),
    ('pic/mcukit-riscv64', 'RISCV:LE:64:default:gcc', 0x80200000, 'riscv64',
     ['--target=riscv64-none-elf', '-march=rv64imac', '-mabi=lp64', '-mcmodel=medany', '-O2'], []),
    ('pic/mcukit-riscv64-rela', 'RISCV:LE:64:default:gcc', 0x80200000, 'riscv64',
     ['--target=riscv64-none-elf', '-march=rv64imac', '-mabi=lp64', '-mcmodel=medany', '-O2', '-fPIE'],
     ['-pie', '--no-dynamic-linker', '-z', 'norelro']),
    ('thumb/mcukit-armv7a-thumb', 'ARM:LE:32:v7:default', 0x60008000, 'thumb',
     ['--target=armv7a-none-eabi', '-mthumb', '-mfloat-abi=soft', '-O2'], []),
    ('thumb/mcukit-armv4t-thumb', 'ARM:LE:32:v4t:default', 0x00010000, 'thumb',
     ['--target=armv4t-none-eabi', '-mthumb', '-mfloat-abi=soft', '-Os'], []),
]

# The board: a UART, a timer, an LED, an ADC and a PWM as registers at
# BOARD_MMIO, settings in RAM; and for ARM, the division and memory helpers
# its run-time library would bring.
BOARD_C = r"""
#include "mcukit.h"
#include <string.h>
#define REG(o) (*(volatile uint32_t *)(BOARD_MMIO + (o)))
static uint8_t nvm[64];
void board_init(void) { REG(0x0c) = 3; REG(0x100) = 1; }
void board_uart_kick(void) {
  int16_t c;
  while ((REG(0x14) & 0x20) && (c = ring_get(&uart_tx)) >= 0) REG(0) = (uint8_t)c;
}
void board_irq_off(void) { REG(0x200) = 0; }
void board_irq_on(void) { REG(0x200) = 1; }
void board_reset(void) { REG(0x300) = 0xa5; for (;;) {} }
uint8_t board_nvm_read(uint16_t at) { return nvm[at & 63]; }
void board_nvm_write(uint16_t at, uint8_t v) { nvm[at & 63] = v; }
void board_led(uint8_t on) { REG(0x400) = on; }
uint16_t board_adc(uint8_t channel) {
  REG(0x500) = 0x80 | channel;
  while (REG(0x500) & 0x80) {}
  return (uint16_t)REG(0x504);
}
void board_pwm(uint16_t duty) { REG(0x600) = duty; }
void board_idle(void) {
  if (REG(0x104) & 1) { REG(0x104) = 1; mcu_tick(); }
  while (REG(0x14) & 1) ring_put(&uart_rx, (uint8_t)REG(0));
  board_uart_kick();
}
#if defined(__arm__)
static unsigned udiv(unsigned n, unsigned d, unsigned *rem) {
  unsigned q = 0;
  for (int i = 31; i >= 0; i--)
    if ((n >> i) >= d) { n -= d << i; q |= 1u << i; }
  *rem = n;
  return q;
}
unsigned __aeabi_uidiv(unsigned n, unsigned d) { unsigned r; return udiv(n, d, &r); }
unsigned long long __aeabi_uidivmod(unsigned n, unsigned d) {
  unsigned r, q = udiv(n, d, &r);
  return (unsigned long long)r << 32 | q;
}
int __aeabi_idiv(int n, int d) {
  unsigned r, q = udiv(n < 0 ? -n : n, d < 0 ? -d : d, &r);
  return (n < 0) != (d < 0) ? -(int)q : (int)q;
}
long long __aeabi_idivmod(int n, int d) {
  unsigned r, q = udiv(n < 0 ? -n : n, d < 0 ? -d : d, &r);
  int sq = (n < 0) != (d < 0) ? -(int)q : (int)q, sr = n < 0 ? -(int)r : (int)r;
  return (long long)(unsigned)sr << 32 | (unsigned)sq;
}
void __aeabi_memcpy(void *d, const void *s, size_t n) { memcpy(d, s, n); }
void __aeabi_memcpy4(void *d, const void *s, size_t n) { memcpy(d, s, n); }
void __aeabi_memset(void *d, size_t n, int c) { memset(d, c, n); }
void __aeabi_memclr(void *d, size_t n) { memset(d, 0, n); }
void __aeabi_memclr4(void *d, size_t n) { memset(d, 0, n); }
#endif
"""

START_S = {
    'aarch64': """
  .section .text.start, "ax"
  .global _start
_start:
  adrp x0, __stack_top
  add x0, x0, :lo12:__stack_top
  mov sp, x0
  bl main
1:wfe
  b 1b
""",
    'riscv64': """
  .section .text.start, "ax"
  .global _start
_start:
  lla sp, __stack_top
  call main
1:wfi
  j 1b
""",
    # A position-independent executable relocates itself first, as
    # OpenSBI and U-Boot do: where it runs, against where it was linked
    # (BASE, a constant), then each relocation moved by the difference.
    'aarch64-rela': """
  .section .text.start, "ax"
  .global _start
_start:
  adr x0, _start
  ldr x1, link_start
  subs x2, x0, x1
  b.eq 2f
  adrp x3, __rela_start
  add x3, x3, :lo12:__rela_start
  adrp x4, __rela_end
  add x4, x4, :lo12:__rela_end
1:cmp x3, x4
  b.hs 2f
  ldp x5, x6, [x3], #16
  ldr x7, [x3], #8
  add x7, x7, x2
  str x7, [x5, x2]
  b 1b
2:adrp x0, __stack_top
  add x0, x0, :lo12:__stack_top
  mov sp, x0
  bl main
3:wfe
  b 3b
  .balign 8
link_start:
  .quad BASE
""",
    'riscv64-rela': """
  .section .text.start, "ax"
  .global _start
_start:
  lla t0, _start
  ld t1, link_start
  sub t2, t0, t1
  beqz t2, 2f
  lla t3, __rela_start
  lla t4, __rela_end
1:bgeu t3, t4, 2f
  ld t5, 0(t3)
  ld t6, 16(t3)
  add t6, t6, t2
  add t5, t5, t2
  sd t6, 0(t5)
  addi t3, t3, 24
  j 1b
2:lla sp, __stack_top
  call main
3:wfi
  j 3b
  .balign 8
link_start:
  .dword BASE
""",
    'thumb': """
  .syntax unified
  .thumb
  .section .text.start, "ax"
  .global _start
  .thumb_func
_start:
  ldr r0, =__stack_top
  mov sp, r0
  bl main
1:b 1b
  .pool
""",
}

LINK_LD = """
ENTRY(_start)
SECTIONS {
  . = %(base)s;
  .text : { *(.text.start) *(.text*) }
  .rodata : { *(.rodata*) *(.srodata*) }
  .data.rel.ro : { *(.data.rel.ro*) }
  .dynamic : { *(.dynamic) }
  .rela.dyn : { __rela_start = .; *(.rela*) __rela_end = .; }
  .got : { *(.got*) }
  .data : { *(.data*) *(.sdata*) }
  .bss (NOLOAD) : { *(.bss*) *(.sbss*) *(COMMON) }
  . = ALIGN(16) + 0x1000;
  __stack_top = .;
  /DISCARD/ : { *(.comment) *(.note*) *(.ARM.attributes) *(.riscv.attributes) *(.ARM.exidx*) }
}
"""


def built_images(work):
    """(image, bytes) of each BUILT image, as the corpus manifest describes
    an image; none where clang, ld.lld or llvm-objcopy is missing."""
    tools = [shutil.which(t) for t in ('clang', 'ld.lld', 'llvm-objcopy')]
    if not all(tools):
        print('detect_cases: no clang, ld.lld and llvm-objcopy: no pic and thumb cases', file=sys.stderr)
        return
    clang, lld, objcopy = tools
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'corpus', 'firmware', 'src')
    resource = subprocess.run([clang, '-print-resource-dir'], capture_output=True, text=True).stdout.strip()
    with tempfile.TemporaryDirectory(dir=work) as tmp:
        with open(os.path.join(tmp, 'board.c'), 'w') as f:
            f.write(BOARD_C)
        for name, language, base, arch, cflags, lflags in BUILT:
            mmio = '0x09000000UL' if arch == 'aarch64' else '0x10000000UL' if arch == 'riscv64' else '0x40000000UL'
            common = [clang] + cflags + ['-ffreestanding', '-fno-builtin', '-nostdinc', '-isystem',
                                         os.path.join(resource, 'include'), '-I', os.path.join(src, 'fwkit', 'libc', 'include'),
                                         '-I', os.path.join(src, 'mcukit'), '-DBOARD_MMIO=' + mmio, '-DBASE=' + hex(base), '-w', '-c']
            stub = arch + '-rela' if '-pie' in lflags else arch
            start = os.path.join(tmp, stub + '.S')
            with open(start, 'w') as f:
                f.write(START_S[stub])
            objects = []
            for i, path in enumerate([start, os.path.join(tmp, 'board.c'), os.path.join(src, 'mcukit', 'main.c'),
                                      os.path.join(src, 'fwkit', 'libc', 'string.c')]):
                obj = os.path.join(tmp, '%s-%d.o' % (arch, i))
                subprocess.run(common + [path, '-o', obj], check=True)
                objects.append(obj)
            ld = os.path.join(tmp, 'link.ld')
            with open(ld, 'w') as f:
                f.write(LINK_LD % {'base': hex(base)})
            elf, raw = os.path.join(tmp, 'image.elf'), os.path.join(tmp, 'image.bin')
            subprocess.run([lld] + lflags + ['-T', ld, '--gc-sections', '-e', '_start', '-o', elf] + objects, check=True)
            subprocess.run([objcopy, '-O', 'binary', elf, raw], check=True)
            data = open(raw, 'rb').read()
            yield {'name': name, 'language': language, 'base': hex(base), 'arch': arch}, data


def negatives():
    """(name, reason, bytes): files a detector should refuse."""
    r = rng('negatives', 'random')
    yield 'none/random', 'high-entropy', r.randbytes(1 << 17)
    yield 'none/compressed', 'high-entropy', zlib.compress(filler_text(rng('negatives', 'z'), 1 << 20), 9)
    yield 'none/text', 'not-code', filler_text(rng('negatives', 'text'), 1 << 17)
    yield 'none/fill', 'not-code', b'\xff' * (1 << 16) + b'\0' * (1 << 16)
    t = rng('negatives', 'table')
    yield 'none/table', 'not-code', b''.join(struct.pack('<H', (i * i + t.randint(0, 3)) & 0xffff) for i in range(1 << 15))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--corpus', default='out/firmware-corpus')
    ap.add_argument('--out', default='build/detect-cases')
    ap.add_argument('--only', help='only corpus images whose name matches this glob')
    ap.add_argument('--regions-truth', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'corpus',
                                                            'firmware', 'regions-truth.json'))
    args = ap.parse_args()

    manifest = json.load(open(os.path.join(args.corpus, 'manifest.json')))
    extra = json.load(open(args.regions_truth))['images'] if os.path.exists(args.regions_truth) else {}
    os.makedirs(args.out, exist_ok=True)
    cases = []

    def emit(name, data, truth):
        path = name.replace('/', '__') + '.bin'
        with open(os.path.join(args.out, path), 'wb') as f:
            f.write(data)
        cases.append({'name': name, 'path': path, 'size': len(data), **truth})

    for image in manifest['images']:
        if args.only and not fnmatch.fnmatch(image['name'], args.only):
            continue
        data = open(os.path.join(args.corpus, image['path']), 'rb').read()
        more = extra.get(image['name'], {})
        regions = (image.get('regions') or []) + [r['region'] for r in more.get('regions', [])] or None
        partial = [{'kind': r['kind'], 'region': r['region']} for r in more.get('partial', [])] or None
        for suffix, kind, blob, offset in variants(image, data):
            emit(image['name'] + suffix, blob, {
                'kind': kind, 'split': 'kit', 'language': image['language'], 'base': image['base'],
                'offset': hex(offset), 'image_size': hex(len(data)), 'arch': image['arch'],
                'regions': regions, 'regions_partial': partial})
        near = derived(image, data)
        if near is not None and image['name'].split('/')[-1].startswith(('fwkit', 'uboot')):
            emit('near-miss/' + image['name'].replace('/', '-'), near, {
                'kind': 'near-miss', 'split': 'kit', 'language': None, 'near_miss_of': image['language'].split(':')[0],
                'arch': image['arch'], 'regions': None})
    for image, data in built_images(args.out):
        if args.only and not fnmatch.fnmatch(image['name'], args.only):
            continue
        emit(image['name'], data, {
            'kind': image['name'].split('/')[0], 'split': 'kit', 'language': image['language'], 'base': image['base'],
            'offset': '0x0', 'image_size': hex(len(data)), 'arch': image['arch'], 'regions': None,
            'regions_partial': None})
    if not args.only:
        for name, reason, blob in negatives():
            emit(name, blob, {'kind': 'negative', 'split': 'kit', 'language': None, 'refusal': reason,
                               'regions': []})

    json.dump({'cases': cases}, open(os.path.join(args.out, 'cases.json'), 'w'), indent=1)
    print(f'detect_cases: {len(cases)} cases in {args.out}', file=sys.stderr)


if __name__ == '__main__':
    main()
