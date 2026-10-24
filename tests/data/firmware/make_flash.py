#!/usr/bin/env python3
"""Flash file system and firmware fixtures for revkit's container tests
(src/container/tests/flash_test.cc), written from the formats' public
descriptions where no tool is installed to make them.

  make_flash.py jffs2-update IMAGE le|be   append newer (and stale) nodes
  make_flash.py yaffs2 DIR OUT PAGE SPARE [le|be] [inband]
  make_flash.py sparse RAW OUT              an Android sparse image of RAW
  make_flash.py trx OUT PART...             a Broadcom TRX v1 image
  make_flash.py squashfs3 DIR OUT le|be gzip|lzma   (see the function)

Run with python3 -I; nothing here reads anything but its arguments.
"""
import os
import stat
import struct
import sys
import zlib


def jcrc(b):
    return zlib.crc32(b, 0xFFFFFFFF) ^ 0xFFFFFFFF


# ---- JFFS2 -------------------------------------------------------------------

def jffs2_nodes(img, e):
    """(offset, type, fields) of the dirent and inode nodes of an image."""
    out = []
    p = 0
    while p + 12 <= len(img):
        magic, ntype, totlen = struct.unpack(e + "HHI", img[p:p + 8])
        if magic != 0x1985 or totlen < 12:
            p += 4
            continue
        if ntype == 0xE001:
            pino, version, ino = struct.unpack(e + "III", img[p + 12:p + 24])
            nsize = img[p + 28]
            out.append(("dirent", pino, version, ino, img[p + 40:p + 40 + nsize]))
        elif ntype == 0xE002:
            ino, version = struct.unpack(e + "II", img[p + 12:p + 20])
            out.append(("inode", ino, version))
        p += (totlen + 3) & ~3
    return out


def jffs2_dirent(e, pino, version, ino, name, dtype=8):
    hdr = struct.pack(e + "HHI", 0x1985, 0xE001, 40 + len(name))
    hdr += struct.pack(e + "I", jcrc(hdr))
    body = hdr + struct.pack(e + "IIIIBBH", pino, version, ino, 0, len(name), dtype, 0)
    body += struct.pack(e + "II", jcrc(body), jcrc(name)) + name
    return body + b"\xff" * (-len(body) % 4)


def jffs2_inode(e, ino, version, mode, isize, offset, data, dsize=None, bad_crc=False):
    dsize = len(data) if dsize is None else dsize
    hdr = struct.pack(e + "HHI", 0x1985, 0xE002, 68 + len(data))
    hdr += struct.pack(e + "I", jcrc(hdr))
    body = hdr + struct.pack(e + "IIIHHIIIIIIIBBH", ino, version, mode, 0, 0, isize, 0, 0, 0, offset,
                             len(data), dsize, 0, 0, 0)
    crc = jcrc(body)
    body += struct.pack(e + "II", jcrc(data), crc ^ (1 if bad_crc else 0)) + data
    return body + b"\xff" * (-len(body) % 4)


def jffs2_update(path, order):
    """Appends to an image made from a root holding a.txt (10000 'a's), b.txt
    and c.txt: an overwrite of a.txt's bytes 100-109, b.txt deleted, c.txt
    truncated to 3 bytes, a new d.txt, a stale node of a.txt (version 0)
    that must lose, and a node whose CRC fails."""
    e = "<" if order == "le" else ">"
    img = open(path, "rb").read()
    nodes = jffs2_nodes(img, e)
    names = {}
    versions = {}
    dversions = {}
    for n in nodes:
        if n[0] == "dirent":
            _, pino, version, ino, name = n
            if pino == 1 and version >= dversions.get(name, -1):
                names[name] = ino
                dversions[name] = version
        else:
            versions[n[1]] = max(versions.get(n[1], 0), n[2])
    a, b, c = names[b"a.txt"], names[b"b.txt"], names[b"c.txt"]
    new = max(versions) + 1
    mode = stat.S_IFREG | 0o644
    out = bytearray(img)
    out += jffs2_inode(e, a, versions[a] + 1, mode, 10000, 100, b"XXXXXXXXXX")
    out += jffs2_dirent(e, 1, dversions[b"b.txt"] + 1, 0, b"b.txt")
    out += jffs2_inode(e, c, versions[c] + 1, mode, 3, 0, b"")
    out += jffs2_inode(e, new, 1, mode, 4, 0, b"dee\n")
    out += jffs2_dirent(e, 1, max(dversions.values()) + 1, new, b"d.txt")
    out += jffs2_inode(e, a, 0, mode, 10000, 0, b"OLD")
    out += jffs2_inode(e, c, versions[c] + 5, mode, 9, 0, b"corrupted", bad_crc=True)
    open(path, "wb").write(bytes(out))


# ---- YAFFS2 ------------------------------------------------------------------

def yaffs2(src, out, page, spare, order="le", inband=False, tag_off=0, rewrite=None):
    """A YAFFS2 image of directory `src` as mkyaffs2image lays it out: object
    headers then data chunks, depth first, object ids from 257, blocks of
    64 chunks with sequence numbers from 0x1000; the packed tags at
    `tag_off` in each page's spare area (or, inband, at the page's end).
    `rewrite`: (path, bytes) of a file written again in a later block, a
    newer version of it."""
    e = "<" if order == "le" else ">"
    per = page - 16 if inband else page
    chunks = []

    def tags(obj, chunk, nbytes):
        return (obj, chunk, nbytes)

    def header(otype, parent, name, st, size=0, alias=b"", equiv=-1):
        h = bytearray(b"\xff" * 512)
        struct.pack_into(e + "IIH", h, 0, otype, parent, 0xFFFF)
        h[10:266] = name[:255].ljust(256, b"\0")
        struct.pack_into(e + "IIIIIIIi", h, 268, st.st_mode, st.st_uid, st.st_gid, int(st.st_atime),
                         int(st.st_mtime), int(st.st_ctime), size & 0xFFFFFFFF, equiv)
        h[300:460] = alias[:159].ljust(160, b"\0")
        struct.pack_into(e + "I", h, 460, 0)
        return bytes(h)

    ids = {}
    inodes = {}
    next_id = [257]

    def add_file_chunks(obj, data):
        for k in range(0, len(data), per):
            piece = data[k:k + per]
            chunks.append((piece, tags(obj, k // per + 1, len(piece))))

    def walk(d, parent):
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            st = os.lstat(p)
            obj = next_id[0]
            next_id[0] += 1
            ids[os.path.relpath(p, src)] = obj
            bname = name.encode()
            if stat.S_ISLNK(st.st_mode):
                h = header(2, parent, bname, st, alias=os.readlink(p).encode())
                chunks.append((h, tags(obj | 2 << 28, 0x80000000 | parent, 0)))
            elif stat.S_ISDIR(st.st_mode):
                chunks.append((header(3, parent, bname, st), tags(obj | 3 << 28, 0x80000000 | parent, 0)))
                walk(p, obj)
            elif stat.S_ISREG(st.st_mode) and st.st_nlink > 1 and st.st_ino in inodes:
                equiv = inodes[st.st_ino]
                chunks.append((header(4, parent, bname, st, equiv=equiv), tags(obj | 4 << 28, 0x80000000 | parent, equiv)))
            elif stat.S_ISREG(st.st_mode):
                inodes[st.st_ino] = obj
                data = open(p, "rb").read()
                chunks.append((header(1, parent, bname, st, size=len(data)),
                               tags(obj | 1 << 28, 0x80000000 | parent, len(data))))
                add_file_chunks(obj, data)

    walk(src, 1)
    if rewrite:
        path, data = rewrite
        while len(chunks) % 64:
            chunks.append(None)  # erased to the block's end
        p = os.path.join(src, path)
        st = os.lstat(p)
        obj = ids[path]
        parent = ids.get(os.path.dirname(path), 1)
        chunks.append((header(1, parent, os.path.basename(path).encode(), st, size=len(data)),
                       tags(obj | 1 << 28, 0x80000000 | parent, len(data))))
        add_file_chunks(obj, data)
    with open(out, "wb") as f:
        for i, c in enumerate(chunks):
            if c is None:
                f.write(b"\xff" * (page + spare))
                continue
            data, (obj, chunk, nbytes) = c
            seq = 0x1000 + i // 64
            t = struct.pack(e + "IIII", seq, obj, chunk, nbytes)
            body = data.ljust(per, b"\xff")
            if inband:
                f.write(body + t)
            else:
                oob = bytearray(b"\xff" * spare)
                oob[tag_off:tag_off + 16] = t
                f.write(body + bytes(oob))


# ---- Android sparse and vendor boot images, TRX -------------------------------

def sparse(raw_path, out, blk=4096):
    """An Android sparse image of a raw image, as img2simg writes one: runs
    of zero blocks as "don't care", of one repeated word as fills, the rest
    raw, and a CRC chunk at the end."""
    raw = open(raw_path, "rb").read()
    raw += b"\0" * (-len(raw) % blk)
    n = len(raw) // blk
    chunks = []

    def kind(i):
        b = raw[i * blk:(i + 1) * blk]
        if b == b"\0" * blk:
            return ("skip", None)
        if b == b[:4] * (blk // 4):
            return ("fill", b[:4])
        return ("raw", None)

    i = 0
    while i < n:
        k, v = kind(i)
        j = i + 1
        while j < n and kind(j) == (k, v):
            j += 1
        chunks.append((k, v, i, j - i))
        i = j
    body = b""
    for k, v, start, count in chunks:
        if k == "raw":
            data = raw[start * blk:(start + count) * blk]
            body += struct.pack("<HHII", 0xCAC1, 0, count, 12 + len(data)) + data
        elif k == "fill":
            body += struct.pack("<HHII", 0xCAC2, 0, count, 16) + v
        else:
            body += struct.pack("<HHII", 0xCAC3, 0, count, 12)
    body += struct.pack("<HHII", 0xCAC4, 0, 0, 16) + struct.pack("<I", zlib.crc32(raw))
    hdr = struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk, n, len(chunks) + 1, 0)
    open(out, "wb").write(hdr + body)


def vendor_boot(out, version, ramdisks, dtb, bootconfig=b""):
    """An Android vendor boot image (v3, v4) of 4 KiB pages: the ramdisks
    (one, or v4's table of named ones), a DTB and (v4) a bootconfig."""
    page = 4096

    def pad(b):
        return b + b"\0" * (-len(b) % page)

    hsize = 2112 if version == 3 else 2128
    ramdisk = b"".join(r for _, r in ramdisks)
    h = bytearray(hsize)
    struct.pack_into("<8sIIIII", h, 0, b"VNDRBOOT", version, page, 0x10008000, 0x11000000, len(ramdisk))
    h[28:28 + 17] = b"console=ttyMSM0,1"
    struct.pack_into("<I16sIIQ", h, 2076, 0x10000100, b"revkit-board", hsize, len(dtb), 0x11f00000)
    table = b""
    if version >= 4:
        off = 0
        for i, (name, r) in enumerate(ramdisks):
            e = bytearray(108)
            struct.pack_into("<III32s", e, 0, len(r), off, 1 if i == 0 else 3, name.encode())
            table += bytes(e)
            off += len(r)
        struct.pack_into("<IIII", h, 2112, len(table), len(ramdisks), 108, len(bootconfig))
    data = pad(bytes(h)) + pad(ramdisk) + pad(dtb)
    if version >= 4:
        data += pad(table) + pad(bootconfig)
    open(out, "wb").write(data)


def trx(out, parts, version=1):
    """A Broadcom TRX image: the header, then the parts (4-byte aligned),
    their offsets in the header, and the CRC over everything past it."""
    nparts = 4 if version == 2 else 3
    hdr_len = 16 + 4 * nparts
    body = b""
    offs = []
    for p in parts:
        offs.append(hdr_len + len(body))
        body += p + b"\0" * (-len(p) % 4)
    offs += [0] * (nparts - len(offs))
    total = hdr_len + len(body)
    rest = struct.pack("<I", version << 16) + struct.pack("<%dI" % nparts, *offs) + body
    crc = zlib.crc32(rest) ^ 0xFFFFFFFF
    open(out, "wb").write(struct.pack("<4sII", b"HDR0", total, crc) + rest)


def main():
    cmd = sys.argv[1]
    if cmd == "jffs2-update":
        jffs2_update(sys.argv[2], sys.argv[3])
    elif cmd == "yaffs2":
        # DIR OUT PAGE SPARE ORDER TAG_OFFSET|inband [REWRITE_PATH REWRITE_TEXT]
        src, out, page, spare, order, where = sys.argv[2:8]
        rewrite = (sys.argv[8], sys.argv[9].encode()) if len(sys.argv) > 9 else None
        yaffs2(src, out, int(page), int(spare), order, where == "inband", 0 if where == "inband" else int(where),
               rewrite)
    elif cmd == "sparse":
        sparse(sys.argv[2], sys.argv[3])
    elif cmd == "vendor-boot":
        # OUT VERSION DTB RAMDISK...: v4 names the ramdisks by their files
        out, version, dtb = sys.argv[2], int(sys.argv[3]), open(sys.argv[4], "rb").read()
        ramdisks = [(os.path.basename(p), open(p, "rb").read()) for p in sys.argv[5:]]
        vendor_boot(out, version, ramdisks, dtb, b"androidboot.hardware=revkit\n" if version >= 4 else b"")
    elif cmd == "trx":
        # OUT VERSION PART...
        trx(sys.argv[2], [open(p, "rb").read() for p in sys.argv[4:]], int(sys.argv[3]))
    else:
        raise SystemExit("unknown command " + cmd)


if __name__ == "__main__":
    main()
