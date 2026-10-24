#!/usr/bin/env python3
"""Builds the synthetic Nintendo DS fixtures (docs/nds.md, "Test fixtures").

From the C++ in this directory, compiled with clang for ARMv5TE (the ARM9)
and ARMv4T (the ARM7) and linked with ld.lld at the DS's addresses, it
writes:

  OUT/game.nds        a ROM image: header, a BLZ-compressed ARM9 with its
                      module parameters and ITCM/DTCM autoloads, an overlay
                      table with a compressed and a plain overlay sharing an
                      address range, an ARM7, and NitroFS holding a NARC and
                      LZ10, LZ11, Huffman and RLE files
  OUT/dsd/            a ds-decomp project for the same game: config.yaml,
                      each module's symbols.txt, relocs.txt and delinks.txt,
                      and the extract (ds-rom's layout) they point at
  OUT/dsd/src/        the game's source (the decomp's, for the knowledge base)
  OUT/dsd3/           the same project with dsd's placeholder names
  OUT/game3.nds       "game 3": the same source and flags built again, linked
                      in another order with code of its own (every address
                      moves), GameOverScene::Update changed a little
  OUT/objs/*.o        the relocatable objects (ARM ELF with symbols), as a
                      finished decomp's build directory would hold them
  OUT/expect.json     what the tests check against: modules, addresses,
                      symbols, cross-module references, files

Nothing here comes from a game, a ROM, ndstool or ds-decomp: the formats are
GBATEK's, and the compressors are written for this script.

usage: make_fixture.py --clang CLANG --lld LD_LLD --objcopy OBJCOPY --out DIR
"""

import argparse
import json
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

MAIN_BASE = 0x02000000
OVERLAY_BASE = 0x02100000
ITCM_BASE = 0x01FF8000
DTCM_BASE = 0x027E0000
ARM7_BASE = 0x037F8000

CFLAGS = [
    "-O2", "-ffreestanding", "-fno-exceptions", "-fno-rtti", "-nostdlib", "-fno-unwind-tables",
    "-fno-asynchronous-unwind-tables", "-mfloat-abi=soft", "-fno-threadsafe-statics", "-fno-use-cxa-atexit",
    "-ffunction-sections", "-fdata-sections", "-mno-unaligned-access", "-fno-builtin",
]


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(" ".join(cmd) + "\n" + r.stdout + r.stderr)
        raise SystemExit(1)
    return r.stdout


# ---- a small ELF32 reader ----------------------------------------------------

class Elf:
    def __init__(self, path):
        self.data = open(path, "rb").read()
        d = self.data
        assert d[:4] == b"\x7fELF" and d[4] == 1 and d[5] == 1
        (self.type, _, _, self.entry, _, shoff, _, _, _, _, shentsize, shnum, shstrndx) = struct.unpack_from(
            "<HHIIIIIHHHHHH", d, 16)
        self.sections = []
        for i in range(shnum):
            name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from(
                "<IIIIIIIIII", d, shoff + i * shentsize)
            self.sections.append(dict(name=name, type=typ, flags=flags, addr=addr, off=off, size=size, link=link,
                                      info=info, align=align, entsize=entsize))
        strtab = self.sections[shstrndx]
        for s in self.sections:
            s["name"] = self.cstr(strtab["off"] + s["name"])
        self.symbols = []
        for s in self.sections:
            if s["type"] != 2:  # SHT_SYMTAB
                continue
            names = self.sections[s["link"]]
            for i in range(s["size"] // 16):
                name, value, size, info, other, shndx = struct.unpack_from("<IIIBBH", d, s["off"] + i * 16)
                self.symbols.append(dict(name=self.cstr(names["off"] + name), value=value, size=size,
                                         bind=info >> 4, type=info & 15, shndx=shndx))
            self.symtab = s
        self.relocs = []  # (address, type, symbol index, target section)
        for s in self.sections:
            if s["type"] != 9:  # SHT_REL
                continue
            target = self.sections[s["info"]]
            for i in range(s["size"] // 8):
                off, info = struct.unpack_from("<II", d, s["off"] + i * 8)
                self.relocs.append((off, info & 0xFF, info >> 8, target))

    def cstr(self, o):
        e = self.data.index(b"\0", o)
        return self.data[o:e].decode()

    def section(self, name):
        for s in self.sections:
            if s["name"] == name:
                return s
        return None

    def word_at(self, addr):
        for s in self.sections:
            if s["type"] == 1 and s["addr"] <= addr < s["addr"] + s["size"]:
                return struct.unpack_from("<I", self.data, s["off"] + addr - s["addr"])[0]
        return None


# ---- compressors (the decoders are revkit's: src/nds/compress.cc) -------------

def lz_tokens(data, min_disp, max_disp, max_len, min_len=3):
    """Greedy LZ77 over data: a list of literals (int) and pairs (disp, len)."""
    out, i, n = [], 0, len(data)
    index = {}
    while i < n:
        best_len, best_disp = 0, 0
        if i + min_len <= n:
            key = bytes(data[i:i + 3])
            for j in reversed(index.get(key, [])[-64:]):
                disp = i - j
                if disp < min_disp:
                    continue
                if disp > max_disp:
                    break
                k = 0
                while k < max_len and i + k < n and data[j + k] == data[i + k]:
                    k += 1
                if k > best_len:
                    best_len, best_disp = k, disp
        if best_len >= min_len:
            out.append((best_disp, best_len))
            step = best_len
        else:
            out.append(data[i])
            step = 1
        for k in range(step):
            if i + k + 3 <= n:
                index.setdefault(bytes(data[i + k:i + k + 3]), []).append(i + k)
        i += step
    return out


def lz10(data):
    out = bytearray([0x10]) + struct.pack("<I", len(data))[:3]
    toks = lz_tokens(data, 1, 0x1000, 18)
    for g in range(0, len(toks), 8):
        group = toks[g:g + 8]
        flags = 0
        body = bytearray()
        for b, t in enumerate(group):
            if isinstance(t, tuple):
                disp, ln = t
                flags |= 0x80 >> b
                v = ((ln - 3) << 12) | (disp - 1)
                body += bytes([v >> 8, v & 0xFF])
            else:
                body.append(t)
        out.append(flags)
        out += body
    while len(out) % 4:
        out.append(0)
    return bytes(out)


def lz11(data):
    out = bytearray([0x11]) + struct.pack("<I", len(data))[:3]
    toks = lz_tokens(data, 1, 0x1000, 0x10110)
    for g in range(0, len(toks), 8):
        group = toks[g:g + 8]
        flags = 0
        body = bytearray()
        for b, t in enumerate(group):
            if isinstance(t, tuple):
                disp, ln = t
                flags |= 0x80 >> b
                d = disp - 1
                if ln <= 0x10:
                    body += bytes([((ln - 1) << 4) | (d >> 8), d & 0xFF])
                elif ln <= 0x110:
                    l = ln - 0x11
                    body += bytes([l >> 4, ((l & 0xF) << 4) | (d >> 8), d & 0xFF])
                else:
                    l = ln - 0x111
                    body += bytes([0x10 | (l >> 12), (l >> 4) & 0xFF, ((l & 0xF) << 4) | (d >> 8), d & 0xFF])
            else:
                body.append(t)
        out.append(flags)
        out += body
    while len(out) % 4:
        out.append(0)
    return bytes(out)


def rle(data):
    out = bytearray([0x30]) + struct.pack("<I", len(data))[:3]
    i, n = 0, len(data)
    lit = bytearray()

    def flush():
        while lit:
            chunk = lit[:128]
            del lit[:128]
            out.append(len(chunk) - 1)
            out.extend(chunk)

    while i < n:
        run_len = 1
        while i + run_len < n and data[i + run_len] == data[i] and run_len < 130:
            run_len += 1
        if run_len >= 3:
            flush()
            out += bytes([0x80 | (run_len - 3), data[i]])
            i += run_len
        else:
            lit.append(data[i])
            i += 1
    flush()
    while len(out) % 4:
        out.append(0)
    return bytes(out)


def huffman8(data):
    """GBATEK's Huffman (8-bit data): a tree whose nodes' child pairs are
    laid out breadth first, each node byte holding the offset to its pair."""
    import heapq
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    if len(freq) == 1:
        freq[(next(iter(freq)) + 1) & 0xFF] = 1
    heap = [(f, i, ("leaf", b)) for i, (b, f) in enumerate(sorted(freq.items()))]
    heapq.heapify(heap)
    k = len(heap)
    while len(heap) > 1:
        f1, _, a = heapq.heappop(heap)
        f2, _, b = heapq.heappop(heap)
        heapq.heappush(heap, (f1 + f2, k, ("node", a, b)))
        k += 1
    root = heap[0][2]
    codes = {}

    def walk(n, code):
        if n[0] == "leaf":
            codes[n[1]] = code
        else:
            walk(n[1], code + "0")
            walk(n[2], code + "1")

    walk(root, "")
    # Slot s is the tree byte at s + 1 after the size byte (the root is slot
    # 0); a node's children are the pair at (rel & ~1) + offset * 2 + 2,
    # rel = s + 1, so pairs start at odd slots. Breadth first.
    slots = [None]
    queue = [(root, 0)]
    while queue:
        n, s = queue.pop(0)
        if n[0] == "leaf":
            slots[s] = n[1]
            continue
        p = len(slots)
        slots += [None, None]
        offset = ((p + 1) - ((s + 1) & ~1) - 2) // 2
        assert 0 <= offset < 64, "tree too wide for the fixture"
        flags = (0x80 if n[1][0] == "leaf" else 0) | (0x40 if n[2][0] == "leaf" else 0)
        slots[s] = flags | offset
        queue.append((n[1], p))
        queue.append((n[2], p + 1))
    tree = bytearray(0 if v is None else v for v in slots)
    while (len(tree) + 1) % 4:
        tree.append(0)
    size_byte = (len(tree) + 1) // 2 - 1
    out = bytearray([0x28]) + struct.pack("<I", len(data))[:3] + bytes([size_byte]) + tree
    bits = "".join(codes[b] for b in data)
    while len(bits) % 32:
        bits += "0"
    for i in range(0, len(bits), 32):
        out += struct.pack("<I", int(bits[i:i + 32], 2))
    return bytes(out)


def blz(data, plain):
    """Backward LZ over data[plain:]: a forward LZ of the reversed tail
    (displacements of 3 or more), written reversed, then the footer."""
    tail = bytes(reversed(data[plain:]))
    toks = lz_tokens(tail, 3, 0x1002, 18)
    stream = bytearray()
    for g in range(0, len(toks), 8):
        group = toks[g:g + 8]
        flags = 0
        body = bytearray()
        for b, t in enumerate(group):
            if isinstance(t, tuple):
                disp, ln = t
                flags |= 0x80 >> b
                v = ((ln - 3) << 12) | (disp - 3)
                body += bytes([v >> 8, v & 0xFF])
            else:
                body.append(t)
        stream.append(flags)
        stream += body
    packed = bytes(reversed(stream))
    pad = (-(plain + len(packed))) % 4
    header_len = 8 + pad
    enc_len = len(packed) + header_len
    out = bytearray(data[:plain]) + packed + b"\xff" * pad
    total = len(data)
    extra = total - (len(out) + 8)
    out += struct.pack("<II", enc_len | (header_len << 24), extra)
    return bytes(out)


def narc(files):
    """files: list of (path, bytes); paths with one directory level at most."""
    dirs = {"": []}
    for path, _ in files:
        d = path.rsplit("/", 1)[0] if "/" in path else ""
        dirs.setdefault(d, [])
    order = sorted(dirs)  # root first
    ids = {d: i for i, d in enumerate(order)}
    by_dir = {d: [] for d in order}
    for i, (path, data) in enumerate(files):
        d = path.rsplit("/", 1)[0] if "/" in path else ""
        by_dir[d].append(i)
    # Files are numbered in directory order, as NitroFS needs.
    numbered = []
    for d in order:
        numbered += by_dir[d]
    gmif = bytearray()
    fat = bytearray()
    for i in numbered:
        while len(gmif) % 4:
            gmif.append(0)
        start = len(gmif)
        gmif += files[i][1]
        fat += struct.pack("<II", start, len(gmif))
    subtables = []
    first = 0
    for d in order:
        t = bytearray()
        for i in by_dir[d]:
            name = files[i][0].rsplit("/", 1)[-1].encode()
            t += bytes([len(name)]) + name
        if d == "":
            for sub in order[1:]:
                name = sub.encode()
                t += bytes([0x80 | len(name)]) + name + struct.pack("<H", 0xF000 + ids[sub])
        t.append(0)
        subtables.append((t, first))
        first += len(by_dir[d])
    main = bytearray()
    off = 8 * len(order)
    body = bytearray()
    for i, (t, firstid) in enumerate(subtables):
        parent = len(order) if i == 0 else 0xF000
        main += struct.pack("<IHH", off + len(body), firstid, parent)
        body += t
    fnt = main + body
    while len(fnt) % 4:
        fnt.append(0)
    blocks = [
        b"BTAF" + struct.pack("<IHH", 12 + len(fat), len(files), 0) + fat,
        b"BTNF" + struct.pack("<I", 8 + len(fnt)) + fnt,
        b"GMIF" + struct.pack("<I", 8 + len(gmif)) + gmif,
    ]
    total = 16 + sum(len(b) for b in blocks)
    return b"NARC" + struct.pack("<HHIHH", 0xFFFE, 0x0100, total, 16, 3) + b"".join(blocks)


def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


# ---- build -------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clang", default="clang")
    ap.add_argument("--lld", default="ld.lld")
    ap.add_argument("--objcopy", default="llvm-objcopy")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    out = os.path.abspath(a.out)
    objs = os.path.join(out, "objs")
    work = os.path.join(out, "work")
    for d in (out, objs, work):
        os.makedirs(d, exist_ok=True)

    def compile_one(src, target, lang):
        o = os.path.join(objs, os.path.splitext(src)[0] + ".o")
        cmd = [a.clang, "--target=" + target, "-c", os.path.join(HERE, src), "-o", o, "-I", HERE] + CFLAGS
        if lang == "c++":
            cmd += ["-x", "c++", "-std=c++17"]
        run(cmd)
        return o

    o_main = compile_one("main.cpp", "armv5te-none-eabi", "c++")
    o_itcm = compile_one("itcm.cpp", "armv5te-none-eabi", "c++")
    o_ov0 = compile_one("ov000.cpp", "armv5te-none-eabi", "c++")
    o_ov1 = compile_one("ov001.cpp", "armv5te-none-eabi", "c++")
    o_arm7 = compile_one("arm7.c", "armv4t-none-eabi", "c")

    discard = "/DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) *(.ARM.attributes) }"

    def link(name, script, objects, extra=()):
        ld = os.path.join(work, name + ".ld")
        open(ld, "w").write(script)
        elf = os.path.join(work, name + ".elf")
        run([a.lld, "--emit-relocs", "-T", ld, "-o", elf] + list(extra) + objects)
        return elf

    itcm_elf = link("itcm", f"""SECTIONS {{
  . = {ITCM_BASE:#x};
  .itcm : {{ *(.itcm) }}
  . = {DTCM_BASE:#x};
  .dtcm : {{ *(.dtcm) }}
  {discard}
}}""", [o_itcm])
    main_elf = link("main", f"""ENTRY(NitroMain)
SECTIONS {{
  . = {MAIN_BASE:#x};
  .text : {{ *(.text.NitroMain) *(.text*) }}
  .rodata : ALIGN(4) {{ *(.rodata.params) *(.rodata*) }}
  .data : ALIGN(32) {{ *(.data*) *(.init_array*) }}
  .bss : ALIGN(32) {{ *(.bss*) *(COMMON) }}
  {discard}
}}""", [o_main], ["--just-symbols=" + itcm_elf])
    ov_script = f"""SECTIONS {{
  . = {OVERLAY_BASE:#x};
  .text : {{ *(.text*) }}
  .rodata : ALIGN(4) {{ *(.rodata*) }}
  .data : ALIGN(32) {{ *(.data*) *(.init_array*) }}
  .bss : ALIGN(32) {{ *(.bss*) *(COMMON) }}
  {discard}
}}"""
    deps = ["--just-symbols=" + main_elf, "--just-symbols=" + itcm_elf]
    ov0_elf = link("ov000", ov_script, [o_ov0], deps)
    ov1_elf = link("ov001", ov_script, [o_ov1], deps)
    arm7_elf = link("arm7", f"""ENTRY(Arm7Main)
SECTIONS {{
  . = {ARM7_BASE:#x};
  .text : {{ *(.text*) }}
  .rodata : ALIGN(4) {{ *(.rodata*) }}
  .data : ALIGN(4) {{ *(.data*) }}
  .bss : ALIGN(4) {{ *(.bss*) *(COMMON) }}
  {discard}
}}""", [o_arm7])

    elfs = {"main": Elf(main_elf), "itcm": Elf(itcm_elf), "ov000": Elf(ov0_elf), "ov001": Elf(ov1_elf),
            "arm7": Elf(arm7_elf)}

    def flat(elf, sections):
        """The listed sections' bytes from the first one's address (gaps zero)."""
        secs = [elf.section(n) for n in sections]
        secs = [s for s in secs if s and s["size"]]
        start = secs[0]["addr"]
        end = max(s["addr"] + s["size"] for s in secs)
        buf = bytearray(end - start)
        for s in secs:
            buf[s["addr"] - start:s["addr"] - start + s["size"]] = elf.data[s["off"]:s["off"] + s["size"]]
        return start, bytes(buf)

    def bss_of(elf):
        s = elf.section(".bss")
        return (s["addr"], s["size"]) if s else (0, 0)

    def build_rom(elfs, rom_path):
        """The ROM image of a build (its ELFs), written to rom_path; what the dsd
        project and expect.json need from it."""
        mods = {}
        for name in ("main", "ov000", "ov001"):
            start, data = flat(elfs[name], [".text", ".rodata", ".data"])
            b = bss_of(elfs[name])
            mods[name] = dict(base=start, data=data, bss=b)
        mods["itcm"] = dict(base=ITCM_BASE, data=flat(elfs["itcm"], [".itcm"])[1], bss=(0, 0))
        mods["dtcm"] = dict(base=DTCM_BASE, data=flat(elfs["itcm"], [".dtcm"])[1], bss=(0, 0))
        start, data = flat(elfs["arm7"], [".text", ".rodata", ".data"])
        mods["arm7"] = dict(base=start, data=data, bss=bss_of(elfs["arm7"]))

        # The module parameters in main (its .rodata.params array).
        params_sym = next(s for s in elfs["main"].symbols if s["name"] == "_start_ModuleParams")
        params_off = params_sym["value"] - MAIN_BASE
        main_bin = bytearray(mods["main"]["data"])
        autoload_start = MAIN_BASE + len(main_bin)
        itcm_bin, dtcm_bin = mods["itcm"]["data"], mods["dtcm"]["data"]
        list_start = autoload_start + len(itcm_bin) + len(dtcm_bin)
        list_end = list_start + 24
        bss_start, bss_size = mods["main"]["bss"]

        def params(compressed_end):
            return struct.pack("<9I", list_start, list_end, autoload_start, bss_start, bss_start + bss_size,
                               compressed_end, 0x04020000, 0x2106C0DE, 0xDEC00621)

        main_bin[params_off:params_off + 36] = params(0)
        mods["main"]["data"] = bytes(main_bin)  # dsd's extract: decompressed, autoloads apart

        arm9 = bytearray(main_bin) + itcm_bin + dtcm_bin + struct.pack(
            "<6I", ITCM_BASE, len(itcm_bin), 0, DTCM_BASE, len(dtcm_bin), 0)
        plain = (params_off + 36 + 3) & ~3
        # The compressed end goes in before compressing (it is in the plain part).
        trial = blz(bytes(arm9), plain)
        arm9[params_off:params_off + 36] = params(MAIN_BASE + len(trial))
        arm9_packed = blz(bytes(arm9), plain)
        assert len(arm9_packed) == len(trial)
        arm9_plain = bytes(arm9)  # what decompression gives back

        ov0_packed = blz(mods["ov000"]["data"], 0)

        # ---- NitroFS ----
        text = b"Game over. Retry? " * 40
        tiles = bytes((i * 7) & 0x3F for i in range(2048)) + bytes(512)
        runs = b"\x00" * 300 + b"ABCD" * 20 + b"\xff" * 200
        huff_src = b"abracadabra, the DS's Huffman " * 20
        narc_files = [("readme.txt", b"inside a NARC\n"), ("gfx/pal.bin", bytes(range(32))),
                      ("gfx/chr.bin", bytes(64))]
        nfiles = [
            ("data/msg.lz", lz10(text), text),
            ("data/huff.bin", huffman8(huff_src), huff_src),
            ("data/pack.narc", narc(narc_files), None),
            ("data/sub/tiles.lz11", lz11(tiles), tiles),
            ("data/sub/rle.bin", rle(runs), runs),
        ]
        # Directories: / (0), /data (1), /data/sub (2). Files are numbered after
        # the two overlays, in directory order.
        fat_entries = []  # (bytes)
        fat_entries.append(ov0_packed)
        fat_entries.append(mods["ov001"]["data"])
        for _, b, _ in nfiles:
            fat_entries.append(b)

        def subtable(entries):
            t = bytearray()
            for kind, name, did in entries:
                n = name.encode()
                if kind == "dir":
                    t += bytes([0x80 | len(n)]) + n + struct.pack("<H", did)
                else:
                    t += bytes([len(n)]) + n
            t.append(0)
            return t

        tables = [
            (subtable([("dir", "data", 0xF001)]), 2, 3),
            (subtable([("file", "msg.lz", 0), ("file", "huff.bin", 0), ("file", "pack.narc", 0),
                       ("dir", "sub", 0xF002)]), 2, 0xF000),
            (subtable([("file", "tiles.lz11", 0), ("file", "rle.bin", 0)]), 5, 0xF001),
        ]
        fnt = bytearray()
        body = bytearray()
        for t, first, parent in tables:
            fnt += struct.pack("<IHH", 8 * len(tables) + len(body), first, parent)
            body += t
        fnt += body

        # ---- the ROM ----
        rom = bytearray(0x4000)

        def place(blob, align=0x200):
            while len(rom) % align:
                rom.append(0xFF)
            off = len(rom)
            rom.extend(blob)
            return off

        arm9_off = place(arm9_packed)
        rom.extend(struct.pack("<III", 0xDEC00621, params_off, 0))  # the ARM9 footer
        ovt = bytearray()
        ovt += struct.pack("<8I", 0, mods["ov000"]["base"], len(mods["ov000"]["data"]), mods["ov000"]["bss"][1], 0, 0, 0,
                           len(ov0_packed) | (1 << 24))
        ovt += struct.pack("<8I", 1, mods["ov001"]["base"], len(mods["ov001"]["data"]), mods["ov001"]["bss"][1], 0, 0, 1,
                           0)
        ovt_off = place(bytes(ovt))
        file_offs = []
        for b in fat_entries[:2]:
            o = place(b)
            file_offs.append((o, o + len(b)))
        arm7_off = place(mods["arm7"]["data"])
        fnt_off = place(bytes(fnt))
        fat_off_placeholder = place(bytes(8 * len(fat_entries)))
        for b in fat_entries[2:]:
            o = place(b)
            file_offs.append((o, o + len(b)))
        fat = b"".join(struct.pack("<II", s, e) for s, e in file_offs)
        rom[fat_off_placeholder:fat_off_placeholder + len(fat)] = fat
        while len(rom) % 0x200:
            rom.append(0xFF)
        h = bytearray(0x200)
        h[0:12] = b"REVKITTEST\0\0"
        h[12:16] = b"RKTE"
        h[16:18] = b"01"
        struct.pack_into("<IIII", h, 0x20, arm9_off, elfs["main"].entry, MAIN_BASE, len(arm9_packed))
        struct.pack_into("<IIII", h, 0x30, arm7_off, elfs["arm7"].entry, ARM7_BASE, len(mods["arm7"]["data"]))
        struct.pack_into("<IIII", h, 0x40, fnt_off, len(fnt), fat_off_placeholder, len(fat))
        struct.pack_into("<IIII", h, 0x50, ovt_off, len(ovt), 0, 0)
        struct.pack_into("<I", h, 0x80, len(rom))
        struct.pack_into("<I", h, 0x84, 0x4000)
        # No Nintendo logo (it isn't ours to copy): the header CRC alone marks it.
        struct.pack_into("<H", h, 0x15E, crc16(h[:0x15E]))
        rom[0:0x200] = h
        open(rom_path, "wb").write(rom)
        return dict(mods=mods, itcm_bin=itcm_bin, dtcm_bin=dtcm_bin, params_off=params_off, list_start=list_start,
                    list_end=list_end, autoload_start=autoload_start, bss_start=bss_start, bss_size=bss_size,
                    nfiles=nfiles, narc_files=narc_files, arm9_packed=arm9_packed, arm9_plain=arm9_plain,
                    ov0_packed=ov0_packed)

    built = build_rom(elfs, os.path.join(out, "game.nds"))
    (mods, itcm_bin, dtcm_bin, params_off, list_start, list_end, autoload_start, bss_start, bss_size, nfiles,
     narc_files, arm9_packed, arm9_plain, ov0_packed) = (built[k] for k in (
        "mods", "itcm_bin", "dtcm_bin", "params_off", "list_start", "list_end", "autoload_start", "bss_start",
        "bss_size", "nfiles", "narc_files", "arm9_packed", "arm9_plain", "ov0_packed"))

    # ---- "game 3": the same source and flags, built again ----
    # Linked in another order with code of its own first, so every address
    # moves (calls, literal pools); one function changed a little (a near
    # match); one only game 3 has.
    def compile_text(name, text):
        src = os.path.join(work, name + ".cpp")
        open(src, "w").write(text)
        o = os.path.join(work, name + ".o")
        run([a.clang, "--target=armv5te-none-eabi", "-c", src, "-o", o, "-I", HERE] + CFLAGS + ["-x", "c++", "-std=c++17"])
        return o

    o_g3 = compile_text("game3", '#include "game.h"\n\n'
                        '// Game 3\'s own code: nothing in the knowledge base matches it.\n'
                        'extern "C" int Game3Bonus(int a, int b) { return Clamp(a * b, -50, 50) ^ gFrameCount; }\n'
                        'extern "C" int Game3Mix(int a) { return ItcmMix(a, a + 1) + Game3Bonus(a, 3); }\n')
    ov0_src = open(os.path.join(HERE, "ov000.cpp")).read()
    changed = "  if (frame > 60) ShowRetryWindow(_s32_div_f(frame, 3));\n"
    assert changed in ov0_src
    o_ov0_3 = compile_text("ov000_3", ov0_src.replace(changed, changed + "  if (frame > 120) cursor.y = frame & 3;\n"))
    main3_elf = link("main3", f"""ENTRY(NitroMain)
SECTIONS {{
  . = {MAIN_BASE:#x};
  .text : {{ *(.text.NitroMain) *(.text.Game3*) *(SORT_BY_NAME(.text*)) }}
  .rodata : ALIGN(4) {{ *(.rodata.params) *(.rodata*) }}
  .data : ALIGN(32) {{ *(.data*) *(.init_array*) }}
  .bss : ALIGN(32) {{ *(.bss*) *(COMMON) }}
  {discard}
}}""", [o_main, o_g3], ["--just-symbols=" + itcm_elf])
    deps3 = ["--just-symbols=" + main3_elf, "--just-symbols=" + itcm_elf]
    ov0_3_elf = link("ov000_3", ov_script, [o_ov0_3], deps3)
    ov1_3_elf = link("ov001_3", ov_script, [o_ov1], deps3)
    elfs3 = {"main": Elf(main3_elf), "itcm": elfs["itcm"], "ov000": Elf(ov0_3_elf), "ov001": Elf(ov1_3_elf),
             "arm7": elfs["arm7"]}
    built3 = build_rom(elfs3, os.path.join(out, "game3.nds"))

    def functions_of(elf):
        return [dict(name=s["name"], addr=s["value"] & ~1, size=s["size"], thumb=bool(s["value"] & 1))
                for s in elf.symbols if s["type"] == 2 and s["name"] and s["shndx"] not in (0, 0xFFF1)]

    game3 = dict(modules={n: functions_of(elfs3[n]) for n in ("main", "ov000", "ov001")},
                 own=["Game3Bonus", "Game3Mix"], changed=["_ZN13GameOverScene6UpdateEv"])

    def write(path, data):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "wb" if isinstance(data, bytes) else "w").write(data)

    def write_dsd(name, built, elfs, elf_paths, copy_name):
        """A ds-decomp project for a build at OUT/name, and a copy with dsd's
    placeholder names at OUT/copy_name; what expect.json says of it."""
        (mods, itcm_bin, dtcm_bin, params_off, list_start, list_end, autoload_start, bss_start,
         bss_size) = (built[k] for k in ("mods", "itcm_bin", "dtcm_bin", "params_off", "list_start", "list_end",
                                         "autoload_start", "bss_start", "bss_size"))
        # ---- the dsd project ----
        dsd = os.path.join(out, name)
        ext = os.path.join(dsd, "extract")
        cfg = os.path.join(dsd, "config", "arm9")
        for d in (ext, os.path.join(ext, "arm9"), os.path.join(ext, "arm9_overlays"), os.path.join(ext, "arm7"), cfg):
            os.makedirs(d, exist_ok=True)


        write(os.path.join(ext, "arm9", "arm9.bin"), mods["main"]["data"])
        write(os.path.join(ext, "arm9", "itcm.bin"), itcm_bin)
        write(os.path.join(ext, "arm9", "dtcm.bin"), dtcm_bin)
        write(os.path.join(ext, "arm9_overlays", "ov000.bin"), mods["ov000"]["data"])
        write(os.path.join(ext, "arm9_overlays", "ov001.bin"), mods["ov001"]["data"])
        write(os.path.join(ext, "arm7", "arm7.bin"), mods["arm7"]["data"])
        write(os.path.join(ext, "config.yaml"), """# ds-rom's extract config (fixture)
header: header.yaml
header_logo: header_logo.png
arm9_bin: arm9/arm9.bin
arm9_config: arm9/arm9.yaml
arm7_bin: arm7/arm7.bin
arm7_config: arm7/arm7.yaml
itcm:
  bin: arm9/itcm.bin
  config: arm9/itcm.yaml
dtcm:
  bin: arm9/dtcm.bin
  config: arm9/dtcm.yaml
arm9_overlays: arm9_overlays/overlays.yaml
banner: banner/banner.yaml
files_dir: files
path_order: path_order.txt
alignment:
  arm9: 512
  arm9_overlay_table: 512
  arm9_overlay: 512
  arm7: 512
  arm7_overlay_table: 512
  arm7_overlay: 512
  file_name_table: 512
  file_allocation_table: 512
  banner: 512
  file_image_block: 512
  file: 512
""")
        write(os.path.join(ext, "arm9", "arm9.yaml"), f"""base_address: {MAIN_BASE:#010x}
entry_function: {elfs["main"].entry:#010x}
build_info: {params_off:#x}
autoload_callback: 0x0
overlay_signatures: 0x0
encrypted: false
compressed: true
autoload_infos_start: {list_start:#010x}
autoload_infos_end: {list_end:#010x}
autoload_blocks: {autoload_start:#010x}
bss_start: {bss_start:#010x}
bss_end: {bss_start + bss_size:#010x}
compressed_code_end: 0x0
sdk_version: 0x4020000
""")
        write(os.path.join(ext, "arm9", "itcm.yaml"),
              f"base_address: {ITCM_BASE:#010x}\ncode_size: {len(itcm_bin):#x}\nbss_size: 0x0\nkind: Itcm\n")
        write(os.path.join(ext, "arm9", "dtcm.yaml"),
              f"base_address: {DTCM_BASE:#010x}\ncode_size: {len(dtcm_bin):#x}\nbss_size: 0x0\nkind: Dtcm\n")
        write(os.path.join(ext, "arm7", "arm7.yaml"),
              f"base_address: {ARM7_BASE:#010x}\nentry_function: {elfs['arm7'].entry:#010x}\nbuild_info: 0x0\n"
              "autoload_callback: 0x0\n")
        ovy = "table_signed: false\noverlays:\n"
        for i, name in enumerate(("ov000", "ov001")):
            m = mods[name]
            ovy += (f"- id: {i}\n  base_address: {m['base']:#010x}\n  code_size: {len(m['data']):#x}\n"
                    f"  bss_size: {m['bss'][1]:#x}\n  ctor_start: 0x0\n  ctor_end: 0x0\n  file_id: {i}\n"
                    f"  compressed: {'true' if i == 0 else 'false'}\n  signed: false\n  file_name: {name}.bin\n")
        write(os.path.join(ext, "arm9_overlays", "overlays.yaml"), ovy)

        # Module ranges, for each reference's `module:`.
        ranges = {
            "main": (MAIN_BASE, MAIN_BASE + len(mods["main"]["data"]) + bss_size + 0x40),
            "itcm": (ITCM_BASE, ITCM_BASE + len(itcm_bin)),
            "dtcm": (DTCM_BASE, DTCM_BASE + len(dtcm_bin)),
        }
        ovr = {n: (OVERLAY_BASE, OVERLAY_BASE + len(mods[n]["data"]) + mods[n]["bss"][1] + 0x40) for n in ("ov000",
                                                                                                             "ov001")}

        def module_of(to, me):
            for n, (lo, hi) in ranges.items():
                if lo <= to < hi:
                    return n
            if me in ovr and ovr[me][0] <= to < ovr[me][1]:
                return f"overlay({int(me[2:])})"
            inside = [n for n, (lo, hi) in ovr.items() if lo <= to < hi]
            if len(inside) == 1:
                return f"overlay({int(inside[0][2:])})"
            if inside:
                return "overlays(" + ",".join(str(int(n[2:])) for n in inside) + ")"
            return "none"

        def symbols_txt(name, elf, rename=None):
            rename = rename or {}
            lines, out_syms = [], []
            text = elf.section(".text") or elf.section(".itcm")
            secs = {i: s for i, s in enumerate(elf.sections)}
            for s in sorted(elf.symbols, key=lambda s: (s["value"] & ~1, s["name"])):
                n = s["name"]
                if not n or n.startswith("$") or s["type"] in (3, 4) or s["shndx"] in (0, 0xFFF1, 0xFFF2):
                    continue
                sec = secs.get(s["shndx"])
                if sec is None or not (sec["flags"] & 2):
                    continue
                n = rename.get(n, n)
                scope = " local" if s["bind"] == 0 else " weak" if s["bind"] == 2 else ""
                if s["type"] == 2:
                    mode = "thumb" if s["value"] & 1 else "arm"
                    addr = s["value"] & ~1
                    kind = f"function({mode},size={s['size']:#x})"
                elif sec["type"] == 8:
                    addr = s["value"]
                    kind = "bss"
                else:
                    addr = s["value"]
                    kind = "data(word)" if s["size"] == 4 else "data(word[4])" if s["size"] == 16 else "data(any)"
                lines.append(f"{n} kind:{kind} addr:{addr:#010x}{scope}")
                out_syms.append(dict(name=n, kind=kind.split("(")[0], addr=addr, size=s["size"],
                                     thumb=bool(s["type"] == 2 and s["value"] & 1)))
            return "\n".join(lines) + "\n", out_syms

        def relocs_txt(name, elf):
            lines, out_refs = [], []
            syms = elf.symbols
            for off, typ, si, target in sorted(elf.relocs, key=lambda r: r[0]):
                if not (target["flags"] & 2):
                    continue
                sym = syms[si] if si < len(syms) else None
                word = elf.word_at(off)
                if word is None:
                    continue
                if typ in (28, 29, 10):  # R_ARM_CALL, R_ARM_JUMP24, R_ARM_THM_CALL
                    if sym is None:
                        continue
                    to = sym["value"] & ~1
                    to_thumb = sym["type"] == 2 and bool(sym["value"] & 1)
                    if typ == 29:
                        kind = "arm_branch"
                    elif typ == 28:
                        kind = "arm_call_thumb" if to_thumb else "arm_call"
                    else:
                        kind = "thumb_call" if to_thumb else "thumb_call_arm"
                    add = ""
                elif typ in (2, 38):  # R_ARM_ABS32, R_ARM_TARGET1
                    to = word & ~1 if sym and sym["type"] == 2 else word
                    base = (sym["value"] & ~1) if sym and sym["type"] in (1, 2) else to
                    add = f" add:{to - base:#x}" if sym and sym["type"] in (1, 2) and to != base else ""
                    if add:
                        to = base
                    kind = "load"
                else:
                    continue
                mod = module_of(to, name)
                lines.append(f"from:{off:#010x} kind:{kind} to:{to:#010x}{add} module:{mod}")
                out_refs.append(dict(frm=off, kind=kind, to=to, module=mod))
            return "\n".join(lines) + "\n", out_refs

        def delinks_txt(elf, sections, src):
            kinds = {".text": "code", ".itcm": "code", ".rodata": "rodata", ".data": "data", ".dtcm": "data",
                     ".bss": "bss"}
            lines, file_lines = [], []
            for n in sections:
                s = elf.section(n)
                if not s or not s["size"]:
                    continue
                nm = ".text" if n == ".itcm" else ".data" if n == ".dtcm" else n
                align = 32 if nm in (".text", ".data", ".bss") else 4
                lines.append(f"    {nm:<11} start:{s['addr']:#010x} end:{s['addr'] + s['size']:#010x} "
                             f"kind:{kinds[n]} align:{align}")
                file_lines.append(f"    {nm:<11} start:{s['addr']:#010x} end:{s['addr'] + s['size']:#010x}")
            return "\n".join(lines) + f"\n\n// The module's one translation unit.\n{src}:\n    complete\n" + \
                "\n".join(file_lines) + "\n"

        exp = dict(modules={})
        module_files = {
            "main": ("", elf_paths["main"], [".text", ".rodata", ".data", ".bss"], "src/main.cpp"),
            "itcm": ("itcm/", elf_paths["itcm"], [".itcm"], "src/itcm.cpp"),
            "dtcm": ("dtcm/", elf_paths["itcm"], [".dtcm"], "src/itcm.cpp"),
            "ov000": ("overlays/ov000/", elf_paths["ov000"], [".text", ".rodata", ".data", ".bss"], "src/ov000.cpp"),
            "ov001": ("overlays/ov001/", elf_paths["ov001"], [".text", ".rodata", ".data", ".bss"], "src/ov001.cpp"),
        }
        clamp = next(s for s in elfs["main"].symbols if s["name"] == "_Z5Clampiii")
        placeholder = f"func_{clamp['value'] & ~1:08x}"
        for mname, (sub, elf_path, sections, src) in module_files.items():
            elf = Elf(elf_path)
            if mname in ("itcm", "dtcm"):
                # One ELF holds both: each module lists its own section's symbols.
                keep = elf.section(".itcm" if mname == "itcm" else ".dtcm")
                idx = elf.sections.index(keep)
                elf.symbols = [s for s in elf.symbols if s["shndx"] == idx or s["shndx"] == 0]
                elf.relocs = [r for r in elf.relocs if r[3] is keep]
            rename = {"_Z5Clampiii": placeholder} if mname == "main" else None
            st, syms = symbols_txt(mname, elf, rename)
            rt, refs = relocs_txt(mname, elf)
            write(os.path.join(cfg, sub + "symbols.txt"), st)
            write(os.path.join(cfg, sub + "relocs.txt"), rt)
            write(os.path.join(cfg, sub + "delinks.txt"), delinks_txt(elf, sections, src))
            m = mods[mname]
            exp["modules"][mname] = dict(base=m["base"], size=len(m["data"]), bss=m["bss"][1], symbols=syms,
                                           refs=refs)
        exp["modules"]["arm7"] = dict(base=ARM7_BASE, size=len(mods["arm7"]["data"]), bss=mods["arm7"]["bss"][1],
                                         symbols=symbols_txt("arm7", elfs["arm7"])[1], refs=[])
        exp["placeholder"] = placeholder
        write(os.path.join(cfg, "config.yaml"), """rom_config: ../../extract/config.yaml
build_path: ../../build
delinks_path: ../../build/delinks
main_module:
  name: main
  object: ../../build/build/arm9.bin
  hash: 0000000000000000
  delinks: delinks.txt
  symbols: symbols.txt
  relocations: relocs.txt
autoloads:
  - kind: Itcm
    name: itcm
    object: ../../build/build/itcm.bin
    hash: 0000000000000000
    delinks: itcm/delinks.txt
    symbols: itcm/symbols.txt
    relocations: itcm/relocs.txt
  - kind: Dtcm
    name: dtcm
    object: ../../build/build/dtcm.bin
    hash: 0000000000000000
    delinks: dtcm/delinks.txt
    symbols: dtcm/symbols.txt
    relocations: dtcm/relocs.txt
overlays:
  - id: 0
    name: ov000
    object: ../../build/build/arm9_ov000.bin
    hash: 0000000000000000
    delinks: overlays/ov000/delinks.txt
    symbols: overlays/ov000/symbols.txt
    relocations: overlays/ov000/relocs.txt
  - id: 1
    name: ov001
    object: ../../build/build/arm9_ov001.bin
    hash: 0000000000000000
    delinks: overlays/ov001/delinks.txt
    symbols: overlays/ov001/symbols.txt
    relocations: overlays/ov001/relocs.txt
""")
        # The finished decomp's source tree (what the knowledge base ingests).
        for src in ("game.h", "main.cpp", "itcm.cpp", "ov000.cpp", "ov001.cpp"):
            write(os.path.join(dsd, "src", src), open(os.path.join(HERE, src)).read())
        # The same modules and layout with dsd's placeholder names
        # (func_<addr>, data_<addr>), as dsd init leaves a new game.
        import re as _re
        dsd3 = os.path.join(out, copy_name)
        for dp, _, fs in os.walk(dsd):
            for f in fs:
                src_path = os.path.join(dp, f)
                rel = os.path.relpath(src_path, dsd)
                if rel.startswith("src" + os.sep):
                    continue
                data = open(src_path, "rb").read()
                if f == "symbols.txt":
                    lines = []
                    for line in data.decode().splitlines():
                        name, rest = line.split(" ", 1)
                        m = _re.search(r"addr:0x([0-9a-f]+)", rest)
                        sub = os.path.relpath(dp, cfg)
                        ov = sub.split(os.sep)[-1] if sub.startswith("overlays") else ""
                        prefix = ("func_" if "kind:function" in rest else "data_") + (ov + "_" if ov else "")
                        lines.append(prefix + m.group(1) + " " + rest.replace(" local", ""))
                    data = ("\n".join(lines) + "\n").encode()
                write(os.path.join(dsd3, rel), data)
        return exp

    exp1 = write_dsd("dsd", built, elfs, {"main": main_elf, "itcm": itcm_elf, "ov000": ov0_elf, "ov001": ov1_elf}, "dsd3")
    expect = dict(modules=exp1["modules"], placeholder=exp1["placeholder"], files=[], rom={})
    # Game 3 as dsd init leaves it: its own build, placeholder names only.
    write_dsd("game3-named", built3, elfs3, {"main": main3_elf, "itcm": itcm_elf, "ov000": ov0_3_elf, "ov001": ov1_3_elf},
              "game3")
    for path, packed, plain_bytes in nfiles:
        expect["files"].append(dict(path="/" + path, size=len(packed), plain=len(plain_bytes) if plain_bytes else 0))
    expect["narc"] = [dict(path="/" + p, size=len(b)) for p, b in narc_files]
    expect["rom"] = dict(arm9_size=len(arm9_packed), arm9_plain=len(arm9_plain), params_offset=params_off,
                         main_size=len(mods["main"]["data"]), itcm_size=len(itcm_bin), dtcm_size=len(dtcm_bin),
                         ov000_packed=len(ov0_packed), entry=elfs["main"].entry, arm7_entry=elfs["arm7"].entry)
    expect["game3"] = game3
    write(os.path.join(out, "expect.json"), json.dumps(expect, indent=1))
    # The raw payloads, for the decoders' tests.
    for path, packed, plain_bytes in nfiles:
        if plain_bytes is not None:
            write(os.path.join(out, "plain", os.path.basename(path)), plain_bytes)
        write(os.path.join(out, "packed", os.path.basename(path)), packed)
    write(os.path.join(out, "packed", "arm9.blz"), arm9_packed)
    write(os.path.join(out, "plain", "arm9.bin"), arm9_plain)
    write(os.path.join(out, "packed", "ov000.blz"), ov0_packed)
    write(os.path.join(out, "plain", "ov000.bin"), mods["ov000"]["data"])
    print("ok", out)


if __name__ == "__main__":
    main()
