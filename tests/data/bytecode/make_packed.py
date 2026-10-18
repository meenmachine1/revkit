#!/usr/bin/env python3
"""Synthetic packed executables for the container tests (docs/filesystems.md,
"Packed executables"), written from the packers' documented formats with the
standard library only, onto a copy of a real executable (the base):

    python3 -I make_packed.py <base-executable> <out-dir>

Writes, each with a JSON line in <out-dir>/index.jsonl saying what the test
should find:

  pyinstaller-appended   a CArchive appended (cookie at the end), with a
                         script, a bootstrap module (bare code), a module
                         holding a whole .pyc (PyInstaller 5.2 and older),
                         a binary, a data file, a link, an option, and a
                         PYZ of two modules and a package
  pkg, pkg-gzip          pkg's payload and prelude (one file as source, one
                         compiled), plain and gzip
  nexe4, nexe5           nexe's resources with process.__nexe's index (v4),
                         and as a zip (v5)
  bun                    Bun's module graph appended (1.3.9's records)
  zip-appended           a zip appended to the executable (py2exe's library)
  sea                    (with --sea-blob <blob>) Node's SEA blob as an ELF
                         note, as postject injects it
  lua-firmware           data with a Lua 5.4 chunk (written here) and decoys
"""
import gzip
import io
import json
import marshal
import os
import struct
import sys
import zipfile
import zlib
import importlib.util

MAGIC = importlib.util.MAGIC_NUMBER  # this Python's .pyc magic


def code(src, name):
    return compile(src, name, "exec")


def write(out, name, data, expect):
    with open(os.path.join(out, name), "wb") as f:
        f.write(data)
    with open(os.path.join(out, "index.jsonl"), "a") as f:
        f.write(json.dumps({"file": name, **expect}) + "\n")


def pyz(entries):
    """PYZ: "PYZ\\0", the pyc magic, the TOC's offset, then zlib(marshal(code))
    blobs and the marshalled TOC [(name, (typecode, offset, length))]."""
    body = bytearray(b"PYZ\0" + MAGIC + b"\0\0\0\0" + b"\0" * 4)
    toc = []
    for name, typecode, c in entries:
        blob = zlib.compress(marshal.dumps(c), 6)
        toc.append((name, (typecode, len(body), len(blob))))
        body += blob
    struct.pack_into(">I", body, 8, len(body))
    body += marshal.dumps(toc)
    return bytes(body)


def carchive(entries, pyvers):
    """The CArchive: entries, the TOC (18 bytes, name, padded to 16), the
    88-byte cookie."""
    pkg = bytearray()
    toc = bytearray()
    for name, typecode, data, compress in entries:
        stored = zlib.compress(data) if compress else data
        off = len(pkg)
        pkg += stored
        nm = name.encode() + b"\0"
        elen = 18 + len(nm)
        elen += (16 - elen % 16) % 16
        nm = nm.ljust(elen - 18, b"\0")
        toc += struct.pack(">IIIIBc", elen, off, len(stored), len(data), 1 if compress else 0, typecode) + nm
    toc_off = len(pkg)
    pkg += toc
    length = len(pkg) + 88
    pkg += b"MEI\014\013\012\013\016" + struct.pack(">IIII", length, toc_off, len(toc), pyvers)
    pkg += b"libpython3.so".ljust(64, b"\0")
    return bytes(pkg)


def pkg(base, compressed):
    """pkg: the payload's stripes, then the prelude whose last arguments are
    the file system, the entry point, the links, the dictionary and the
    compression."""
    payload = bytearray()
    vfs = {}
    def stripe(key, store, data):
        data = gzip.compress(data) if compressed else data
        vfs.setdefault(key, {})[store] = [len(payload), len(data)]
        payload.extend(data)
    stripe("/snapshot/app/index.js", "1", b"console.log('pkg main')\n")
    stripe("/snapshot/app/index.js", "3", b'{"mode":33188,"size":24}')
    stripe("/snapshot/app/lib.js", "0", b"\xde\xc0\x00\x00fake-v8-cache")
    stripe("/snapshot/app", "2", b'["index.js","lib.js"]')
    dictionary = {}
    if compressed:
        # Keys through the dictionary: each component as a base-36 id.
        ids = {}
        def short(path):
            return "/".join(ids.setdefault(p, format(len(ids) + 1, "x")) for p in path.split("/"))
        vfs = {short(k): v for k, v in vfs.items()}
        dictionary = ids
    prelude = ("(function(process, require, console, EXECPATH_FD, PAYLOAD_POSITION, PAYLOAD_SIZE) { return "
               "(function (REQUIRE_COMMON, REQUIRE_SHARED, VIRTUAL_FILESYSTEM, DEFAULT_ENTRYPOINT, SYMLINKS, DICT, "
               "DOCOMPRESS) {\n/* bootstrap */\n})(function (exports) {\n/* common */\n},\n(function () { var module = "
               "{ exports: {} };\n/* shared */\nreturn module.exports; })(),\n" + json.dumps(vfs, separators=(",", ":")) +
               "\n,\n" + json.dumps("/snapshot/app/index.js") + "\n,\n{}\n,\n" +
               json.dumps(dictionary, separators=(",", ":")) + "\n,\n" + ("1" if compressed else "0") + "\n);\n})")
    return base + bytes(payload) + prelude.encode()


def nexe(base, v5):
    if v5:
        z = io.BytesIO()
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("snapshot/app/index.js", "console.log('nexe5')\n")
        resources = z.getvalue()
        code = b"/* nexe 5 launcher */\n"
    else:
        files = {"./index.js": b"console.log('nexe4')\n", "./data/a.txt": b"text\n"}
        resources, index = bytearray(), {}
        for k, v in files.items():
            index[k] = [len(resources), len(v)]
            resources += v
        resources = bytes(resources)
        code = ("!(function () {process.__nexe = " + json.dumps({"resources": index}, separators=(",", ":")) +
                ";\n})();\n/* launcher */\n").encode()
    return base + code + resources + b"<nexe~~sentinel>" + struct.pack("<dd", len(code), len(resources))


def bun(base):
    """Bun 1.3.9's module graph: data, the records (6 string pointers and 4
    bytes), argv, Offsets (32 bytes), the trailer, the total as a u64."""
    data = bytearray()
    def sp(b):
        off = len(data)
        data.extend(b + b"\0")
        return off, len(b)
    mods = [("/$bunfs/root/app.js", b"console.log('bun')\n"), ("/$bunfs/root/asset.txt", b"asset\n")]
    recs = bytearray()
    for name, contents in mods:
        n, c = sp(name.encode()), sp(contents)
        recs += struct.pack("<IIII", *n, *c) + b"\0" * 32 + bytes([0, 1, 1, 0])
    while len(data) % 4:
        data.append(0)
    mod_off = len(data)
    data += recs
    argv = len(data)
    data += b"\0"
    offsets = struct.pack("<QIIIIII", len(data), mod_off, len(recs), 0, argv, 0, 0)
    blob = bytes(data) + offsets + b"\n---- Bun! ----\n"
    return base + blob + struct.pack("<Q", len(base) + len(blob) + 8)


def zip_appended(base):
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("library/mod.pyc", MAGIC + b"\0" * 12 + marshal.dumps(code("x = 1\n", "mod")))
        zf.writestr("readme.txt", "py2exe-style library\n")
    return base + z.getvalue()


def lua54_chunk():
    """A Lua 5.4 chunk as ldump.c writes it: the header, one upvalue, the
    main function (two instructions, a string and an integer constant)."""
    def size(n):  # dumpSize: 7-bit groups, the last marked with 0x80
        out = [0x80 | (n & 0x7f)]
        n >>= 7
        while n:
            out.insert(0, n & 0x7f)
            n >>= 7
        return bytes(out)
    h = b"\x1bLuaT\x00\x19\x93\r\n\x1a\n\x04\x08\x08" + struct.pack("<q", 0x5678) + struct.pack("<d", 370.5) + b"\x01"
    f = size(len(b"@fw.lua") + 1) + b"@fw.lua" + size(0) + size(0) + bytes([0, 1, 2])
    f += size(2) + struct.pack("<II", 0x00000051, 0x01000046)  # VARARGPREP, RETURN
    f += size(2) + b"\x04" + size(len(b"hello") + 1) + b"hello" + b"\x03" + struct.pack("<q", 42)
    f += size(1) + bytes([1, 0, 0])  # upvalue _ENV
    f += size(0)  # protos
    f += size(2) + b"\x00\x01" + size(0) + size(0) + size(1) + size(len(b"_ENV") + 1) + b"_ENV"
    return h + f


def main():
    base_path, out = sys.argv[1], sys.argv[2]
    sea_blob = sys.argv[sys.argv.index("--sea-blob") + 1] if "--sea-blob" in sys.argv else None
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, "index.jsonl"), "w").close()
    base = open(base_path, "rb").read()
    pyvers = sys.version_info[0] * 100 + sys.version_info[1]
    ver = "%d.%d" % sys.version_info[:2]

    main_code = code("print('hello from pyinstaller')\n", "main.py")
    boot = code("import sys\n", "pyiboot01_bootstrap.py")
    old = MAGIC + b"\0" * 12 + marshal.dumps(code("y = 2\n", "oldmod.py"))
    z = pyz([("pkg", 1, code("", "pkg/__init__.py")), ("pkg.util", 0, code("def f(): return 1\n", "pkg/util.py")),
             ("json_helper", 0, code("import json\n", "json_helper.py"))])
    entries = [("pyiboot01_bootstrap", b"m", marshal.dumps(boot), True), ("oldmod", b"m", old, True),
               ("main", b"s", marshal.dumps(main_code), True), ("libfoo.so", b"b", base[:4096], True),
               ("data/conf.txt", b"x", b"conf\n", False), ("libbar.so", b"n", b"libfoo.so\0", False),
               ("pyi-python-flag Py_GIL_DISABLED", b"o", b"", False), ("PYZ.pyz", b"z", z, False)]
    write(out, "pyinstaller-appended", base + carchive(entries, pyvers),
          {"format": "pyinstaller", "python": ver, "pyc": ["/main.pyc", "/pyiboot01_bootstrap.pyc", "/oldmod.pyc"],
           "pyz": ["/pkg/__init__.pyc", "/pkg/util.pyc", "/json_helper.pyc"]})
    write(out, "pkg", pkg(base, False), {"format": "pkg"})
    write(out, "pkg-gzip", pkg(base, True), {"format": "pkg"})
    write(out, "nexe4", nexe(base, False), {"format": "nexe"})
    write(out, "nexe5", nexe(base, True), {"format": "nexe"})
    write(out, "bun", bun(base), {"format": "bun"})
    write(out, "zip-appended", zip_appended(base), {"format": "zip"})
    chunk = lua54_chunk()
    fw = os.urandom(4096) + b"\x1bLuaT\x00decoy" + os.urandom(1000)
    at = len(fw)
    fw += chunk + os.urandom(2048) + b"\x1bLJ\x02\x00junk" + os.urandom(512)
    write(out, "lua-firmware", fw, {"format": "lua-chunks", "offset": at, "size": len(chunk)})
    if sea_blob:
        blob = open(sea_blob, "rb").read()
        name = b"NODE_SEA_BLOB\0"
        pad = lambda b: b + b"\0" * ((4 - len(b) % 4) % 4)
        note = struct.pack("<III", len(name), len(blob), 0) + pad(name) + pad(blob)
        with open(os.path.join(out, "sea-note.bin"), "wb") as f:
            f.write(note)


if __name__ == "__main__":
    main()
