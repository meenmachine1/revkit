#!/usr/bin/env python3
"""Writes a Windows minidump for revkit's crash dump tests (docs/crash-dumps.md).

    make_minidump.py OUT.dmp --arch amd64|x86|arm64 [--pe PROGRAM.exe] [--slide N]

With --pe (a program built by mingw from tests/data/crash/win.c, exporting
crash_here and caller), the dump is of that program crashed in crash_here's
store through a null pointer: the module list has it at its image base plus
--slide (default 0x3000000) with a CodeView (RSDS) record and a version, and
a system DLL that isn't in any project; the crashed thread's context has the
pc at the faulting store, and its stack the return address into caller and,
above caller's frame, the one into main; an access violation (a write of
0x0) in the exception stream with that context. Without --pe the module and
addresses are made up (an ARM64 dump, say).

Every dump also has a second thread with a name, the stacks in the memory
list, a heap range in the Memory64 list, memory info, misc info with the
process id, system info and a comment. Written from the format as
minidumpapiset.h and winnt.h describe it.
"""
import argparse
import struct
import sys

ARCH = {"amd64": 9, "x86": 0, "arm64": 12}


def pe_info(path):
    b = open(path, "rb").read()
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    assert b[pe:pe + 4] == b"PE\0\0"
    machine, nsect = struct.unpack_from("<HH", b, pe + 4)
    timestamp = struct.unpack_from("<I", b, pe + 8)[0]
    opt_size = struct.unpack_from("<H", b, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", b, opt)[0]
    wide = magic == 0x20B
    image_base = struct.unpack_from("<Q", b, opt + 24)[0] if wide else struct.unpack_from("<I", b, opt + 28)[0]
    size_of_image, = struct.unpack_from("<I", b, opt + 56)
    checksum, = struct.unpack_from("<I", b, opt + 64)
    dirs = opt + (112 if wide else 96)
    export_rva, export_size = struct.unpack_from("<II", b, dirs)
    sections = []
    s = opt + opt_size
    for i in range(nsect):
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", b, s + 40 * i + 8)
        sections.append((vaddr, max(vsize, rsize), rptr, rsize))

    def off(rva):
        for va, size, ptr, rsize in sections:
            if va <= rva < va + size and rva - va < rsize:
                return ptr + rva - va
        raise ValueError(f"rva {rva:#x} isn't in the file")

    exports = {}
    if export_rva:
        e = off(export_rva)
        nfun, nnames, afun, anames, aords = struct.unpack_from("<IIIII", b, e + 20)
        for i in range(nnames):
            name_rva = struct.unpack_from("<I", b, off(anames) + 4 * i)[0]
            name = b[off(name_rva):b.index(b"\0", off(name_rva))].decode()
            ordinal = struct.unpack_from("<H", b, off(aords) + 2 * i)[0]
            exports[name.lstrip("_")] = struct.unpack_from("<I", b, off(afun) + 4 * ordinal)[0]
    return {"bytes": b, "off": off, "image_base": image_base, "size": size_of_image, "timestamp": timestamp,
            "checksum": checksum, "exports": exports, "wide": wide, "sections": sections}


def call_site(pe, caller_rva, target_rva, limit=64):
    """The return address after caller's call to target (an E8 rel32)."""
    b, o = pe["bytes"], pe["off"](caller_rva)
    for i in range(limit):
        if b[o + i] == 0xE8:
            rel = struct.unpack_from("<i", b, o + i + 1)[0]
            if caller_rva + i + 5 + rel == target_rva:
                return caller_rva + i + 5
    raise ValueError("no call to the target")


def any_call(pe, target_rva, skip):
    """The return address of the first call to target outside `skip` (an RVA range)."""
    b = pe["bytes"]
    for va, size, ptr, rsize in pe["sections"]:
        for i in range(min(size, rsize) - 5):
            if b[ptr + i] != 0xE8 or skip[0] <= va + i < skip[1]:
                continue
            rel = struct.unpack_from("<i", b, ptr + i + 1)[0]
            if va + i + 5 + rel == target_rva:
                return va + i + 5
    raise ValueError("no call to the target")


def md_string(s):
    raw = s.encode("utf-16-le")
    return struct.pack("<I", len(raw)) + raw + b"\0\0"


def context(arch, regs):
    if arch == "amd64":
        c = bytearray(1232)
        struct.pack_into("<I", c, 48, 0x10001F)
        struct.pack_into("<I", c, 52, 0x1F80)
        for name, o in (("cs", 56), ("ds", 58), ("es", 60), ("fs", 62), ("gs", 64), ("ss", 66)):
            struct.pack_into("<H", c, o, regs.get(name, 0x2B if name != "cs" else 0x33))
        struct.pack_into("<I", c, 68, regs.get("eflags", 0x10246))
        order = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
                 "r14", "r15", "rip"]
        for i, n in enumerate(order):
            struct.pack_into("<Q", c, 120 + 8 * i, regs.get(n, 0))
        return bytes(c)
    if arch == "x86":
        c = bytearray(716)
        struct.pack_into("<I", c, 0, 0x1003F)
        for n, o in (("gs", 140), ("fs", 144), ("es", 148), ("ds", 152), ("edi", 156), ("esi", 160), ("ebx", 164),
                     ("edx", 168), ("ecx", 172), ("eax", 176), ("ebp", 180), ("eip", 184), ("cs", 188),
                     ("eflags", 192), ("esp", 196), ("ss", 200)):
            struct.pack_into("<I", c, o, regs.get(n, {"cs": 0x23, "ss": 0x2B, "ds": 0x2B, "es": 0x2B, "fs": 0x53,
                                                      "gs": 0x2B, "eflags": 0x246}.get(n, 0)))
        return bytes(c)
    c = bytearray(912)
    struct.pack_into("<I", c, 0, 0x40000F)
    struct.pack_into("<I", c, 4, regs.get("cpsr", 0x60000000))
    for i in range(29):
        struct.pack_into("<Q", c, 8 + 8 * i, regs.get(f"x{i}", 0))
    for n, o in (("x29", 240), ("x30", 248), ("sp", 256), ("pc", 264)):
        struct.pack_into("<Q", c, o, regs.get(n, 0))
    return bytes(c)


class Writer:
    def __init__(self):
        self.data = bytearray(32)  # the header, written last
        self.streams = []

    def add(self, blob, align=8):
        while len(self.data) % align:
            self.data.append(0)
        rva = len(self.data)
        self.data += blob
        return rva

    def stream(self, kind, blob):
        rva = self.add(blob)
        self.streams.append((kind, len(blob), rva))
        return rva

    def finish(self, timestamp):
        dir_rva = self.add(b"".join(struct.pack("<III", k, n, r) for k, n, r in self.streams))
        struct.pack_into("<IIIIIIQ", self.data, 0, 0x504D444D, 0xA793, len(self.streams), dir_rva, 0, timestamp, 0)
        return bytes(self.data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--arch", choices=sorted(ARCH), default="amd64")
    ap.add_argument("--pe")
    ap.add_argument("--slide", type=lambda s: int(s, 0), default=0x3000000)
    args = ap.parse_args()
    arch = args.arch
    wide = arch != "x86"
    ptr = 8 if wide else 4
    w = Writer()

    # The program module, and where it crashed.
    if args.pe:
        pe = pe_info(args.pe)
        base = pe["image_base"] + args.slide
        size, ts, csum = pe["size"], pe["timestamp"], pe["checksum"]
        ex = pe["exports"]
        crash = ex["crash_here"]
        ret_caller = call_site(pe, ex["caller"], crash)
        # x86: the store is after two loads; amd64: the first instruction.
        o = pe["off"](crash)
        fault_off = next((i for i in range(16) if pe["bytes"][o + i:o + i + 2] == b"\x89\x02"), 0) if arch == "x86" else 0
        pc = base + crash + fault_off
        name = "C:\\build\\" + args.pe.replace("\\", "/").split("/")[-1]
        ret_main = base + any_call(pe, ex["caller"], (ex["caller"], ex["caller"] + 1))  # main's call to caller
    else:
        base, size, ts, csum = 0x140000000, 0x10000, 0x5F000000, 0
        pc = base + 0x1000
        ret_caller = 0x1100
        ret_main = base + 0x1200
        name = "C:\\build\\app.exe"
    stack1, stack2 = 0x7FF0000 if wide else 0x0019F000, 0x7FE0000 if wide else 0x0029F000
    ssize = 0x1000
    sp1 = stack1 + 0x800
    stack = bytearray(ssize)
    if args.pe:
        struct.pack_into("<Q" if wide else "<I", stack, 0x800, base + ret_caller)
        struct.pack_into("<Q" if wide else "<I", stack, 0x800 + (0x30 if wide else 12), ret_main)
    regs1 = {"amd64": {"rip": pc, "rsp": sp1, "rcx": 0, "rdx": 7, "rbp": sp1 + 0x100, "rax": 0x1234},
             "x86": {"eip": pc, "esp": sp1, "edx": 0, "eax": 7, "ebp": sp1 + 0x100},
             "arm64": {"pc": pc, "sp": sp1, "x0": 0, "x1": 7, "x29": sp1 + 0x40, "x30": base + 0x1100}}[arch]
    regs2 = {"amd64": {"rip": base + 0x1010, "rsp": stack2 + 0x900},
             "x86": {"eip": base + 0x1010, "esp": stack2 + 0x900},
             "arm64": {"pc": base + 0x1010, "sp": stack2 + 0x900}}[arch]
    # Bytes: contexts, stacks, strings, records.
    ctx1 = w.add(context(arch, regs1))
    ctx2 = w.add(context(arch, regs2))
    s1 = w.add(bytes(stack))
    s2 = w.add(bytes(ssize))
    tname1 = w.add(md_string("main thread"))
    tname2 = w.add(md_string("worker"))
    mname = w.add(md_string(name))
    kname = w.add(md_string("C:\\Windows\\System32\\KERNEL32.DLL"))
    cv = w.add(b"RSDS" + struct.pack("<IHH", 0x12345678, 0x9ABC, 0xDEF0) + bytes(range(1, 9)) + struct.pack("<I", 3) + b"win.pdb\0")
    cvlen = 4 + 16 + 4 + 8
    # Threads.
    tl = struct.pack("<I", 2)
    for tid, sbase, srva, csz, crva in ((1001, stack1, s1, len(context(arch, regs1)), ctx1),
                                         (1002, stack2, s2, len(context(arch, regs2)), ctx2)):
        tl += struct.pack("<IIIIQQIIII", tid, 0, 0x20, 0, 0x7FFDE000, sbase, ssize, srva, csz, crva)
    w.stream(3, tl)
    # Modules.
    def module(b, sz, csum_, ts_, name_rva, version, cv_rva, cv_len):
        vs = struct.pack("<13I", 0xFEEF04BD, 0x10000, version[0] << 16 | version[1], version[2] << 16 | version[3],
                         0, 0, 0x3F, 0, 0x40004, 1, 0, 0, 0)
        return struct.pack("<QIIII", b, sz, csum_, ts_, name_rva) + vs + struct.pack("<II", cv_len, cv_rva) + bytes(8 + 16)
    ml = struct.pack("<I", 2) + module(base, size, csum, ts, mname, (1, 2, 3, 4), cv, cvlen) + \
        module(0x7FF800000000 if wide else 0x76000000, 0x100000, 0, 0x60000000, kname, (10, 0, 19041, 1), 0, 0)
    w.stream(4, ml)
    # Memory: the stacks (list), a heap range (Memory64).
    w.stream(5, struct.pack("<I", 2) + struct.pack("<QII", stack1, ssize, s1) + struct.pack("<QII", stack2, ssize, s2))
    heap = (b"HEAP" + bytes(range(256)) * 16)[:0x1000]
    heap_rva = w.add(heap)
    w.stream(9, struct.pack("<QQ", 1, heap_rva) + struct.pack("<QQ", 0x20000000, len(heap)))
    # Memory info: the stacks and heap read-write, the module r-x.
    entries = [(stack1, ssize, 0x04), (stack2, ssize, 0x04), (0x20000000, 0x1000, 0x04), (base, size, 0x20)]
    mi = struct.pack("<IIQ", 16, 48, len(entries))
    for b_, sz, prot in entries:
        mi += struct.pack("<QQIIQIIII", b_, b_, prot, 0, sz, 0x1000, prot, 0x20000, 0)
    w.stream(16, mi)
    # The exception: an access violation, a write of 0x0, with the crashed thread's context.
    exc = struct.pack("<II", 1001, 0) + struct.pack("<IIQQII", 0xC0000005, 0, 0, pc, 2, 0)
    exc += struct.pack("<15Q", 1, 0, *([0] * 13)) + struct.pack("<II", len(context(arch, regs1)), ctx1)
    w.stream(6, exc)
    # System info: Windows 10.0.19045 on 8 processors.
    w.stream(7, struct.pack("<HHHBBIIIIIHH", ARCH[arch], 6, 0, 8, 1, 10, 0, 19045, 2, 0, 0, 0) + bytes(24))
    # Misc info: the process id.
    w.stream(15, struct.pack("<IIIIII", 24, 1, 4242, 0, 0, 0))
    # Thread names.
    w.stream(24, struct.pack("<I", 2) + struct.pack("<IQ", 1001, tname1) + struct.pack("<IQ", 1002, tname2))
    w.stream(10, b"revkit test dump\0")
    open(args.out, "wb").write(w.finish(0x65000000))
    return 0


if __name__ == "__main__":
    sys.exit(main())
