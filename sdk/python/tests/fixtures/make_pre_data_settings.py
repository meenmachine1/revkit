"""Writes pre_data_settings.rkproj and pre_data_settings.listing.json: a
project made by a daemon from before data settings (api_minor 84), for
test_data_settings.py's check that such a project loads unchanged.

    RK_DAEMON=<a daemon built from before data settings>/rk-daemon \\
        python -I sdk/python/tests/fixtures/make_pre_data_settings.py

The committed files were made by master at 85fbcb0 (api_minor 83). The
program is a raw x86-64 image whose bytes PROGRAM builds; the edits define
data of every kind (an integer, strings, a struct, an array, a pointer),
mark a range constant, comment, rename, leave a bookmark note and undo one
definition, so the archive's log has history too. (The Latin-1 bytes at
0x158 stay undefined: a daemon from before showed a string of them as
invalid UTF-8, which protobuf clients refuse to read.)"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from revkit import Client, Daemon  # noqa: E402
from revkit.v1 import listing_pb2  # noqa: E402

BASE = 0x10000
LANGUAGE = "x86:LE:64:default:gcc"
WINDOW = (BASE + 0x100, 40)  # the listing compared: from here, this many rows


def program() -> bytes:
    """The raw image: a little code, then data at fixed offsets."""
    b = bytearray(0x400)
    b[0:8] = bytes.fromhex("554889e58b05f600")  # push rbp; mov rbp, rsp; mov eax, [rip+...]
    b[8:12] = bytes.fromhex("00005dc3")
    b[0x100:0x104] = (0x12345678).to_bytes(4, "little")
    b[0x110:0x11e] = b"hello fixture\0"
    b[0x120:0x128] = (1).to_bytes(4, "little") + (2).to_bytes(2, "little") + (3).to_bytes(2, "little")
    for i, v in enumerate((10, 20, 30, 40)):
        b[0x130 + 4 * i:0x134 + 4 * i] = v.to_bytes(4, "little")
    b[0x140:0x148] = (BASE + 0x110).to_bytes(8, "little")
    b[0x150:0x156] = "hi\0".encode("utf-16-le")
    b[0x158:0x15d] = bytes([ord("c"), ord("a"), ord("f"), 0xE9, 0])
    return bytes(b)


def row_view(r) -> dict:
    """What a listing row shows, for comparing one daemon's listing with another's."""
    return {
        "address": r.address.offset,
        "kind": listing_pb2.ListingRowKind.Name(r.kind),
        "length": r.length,
        "data_type": r.data_type,
        "tokens": "".join(t.text for t in r.tokens),
        "targets": [t.target.offset for t in r.tokens if t.HasField("target")],
        "data_field": r.data_field,
        "data_parent": r.data_parent.offset if r.HasField("data_parent") else None,
        "data_components": r.data_components,
        "data_collapsed": r.data_collapsed,
        "mutability": r.mutability,
        "unit_origin": r.unit_origin.WhichOneof("source") or "",
        "labels": [lb.name for lb in r.labels],
        "comments": sorted(c.text for c in r.comments),
    }


def listing(prog) -> list:
    rows = prog.listing(WINDOW[0], max_rows=WINDOW[1]).rows
    return [row_view(r) for r in rows if r.kind != listing_pb2.LISTING_ROW_KIND_HEADER]


def make(rk, out_dir: Path):
    pid = rk.import_program("default", content=program(), name="pre-data-settings.bin", format="raw",
                            language_id=LANGUAGE, image_base=BASE).program.program_id
    prog = rk.program(pid)
    prog.define_data(BASE + 0x100, "int")
    prog.define_data(BASE + 0x110, string="utf8")
    prog.define_data(BASE + 0x120, "struct pair { int a; short b; short c; }")
    prog.define_data(BASE + 0x130, "uint32_t", count=4)
    prog.define_data(BASE + 0x140, "char *")
    prog.define_data(BASE + 0x150, string="utf16")
    undone = prog.define_data(BASE + 0x160, "dword")
    prog.retract(*[a.seq for a in undone.assertions])
    prog.set_mutability(BASE + 0x100, 4, "constant")
    prog.rename(BASE + 0x100, "threshold")
    prog.comment(BASE + 0x130, "four counts")
    prog.note(BASE + 0x130, "check these", tag="todo")
    rk.export_project("default", out_dir / "pre_data_settings.rkproj")
    (out_dir / "pre_data_settings.listing.json").write_text(json.dumps(listing(prog), indent=1) + "\n")


if __name__ == "__main__":
    with Daemon(None, "--backend", "image", startup_timeout=60) as d, Client(d.grpc_target, actor="user:fixture") as rk:
        info = rk.server_info()
        if "data-settings" in info.features:
            sys.exit("this daemon already has data settings: give one from before (RK_DAEMON)")
        make(rk, HERE)
        print(f"written by a daemon at api_minor {info.api_minor}")
