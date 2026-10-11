"""Reading, writing and normalizing reference JSON (docs/reference-format.md).

Shared by tools/ghidra-export (writer) and tools/refdiff (reader). Standard
library only, so revkit's own tools can import it too.
"""

from __future__ import annotations

import gzip
import json
import os
from typing import Any, Iterable

FORMAT_VERSION = 1

# Top-level arrays and the key each one is sorted by.
ARRAY_SORT_KEYS = {
    "memory": "start",
    "functions": "entry",
    "instructions": "addr",
}


def addr_key(text: str) -> int:
    """Sort key for a "0x..." address string."""
    return int(text, 16)


def hex_addr(value: int) -> str:
    return "0x%x" % value


def _compact(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def dumps(doc: dict) -> str:
    """Serialize a reference document canonically.

    Keys are sorted at every level, top-level arrays are sorted by their key
    and written one element per line, everything else is compact. The same
    document always gives the same bytes.
    """
    lines = ["{"]
    keys = sorted(doc)
    for i, key in enumerate(keys):
        value = doc[key]
        sep = "," if i + 1 < len(keys) else ""
        if key in ARRAY_SORT_KEYS and isinstance(value, list):
            sort_key = ARRAY_SORT_KEYS[key]
            items = sorted(value, key=lambda item: addr_key(item[sort_key]))
            if not items:
                lines.append("%s:[]%s" % (_compact(key), sep))
                continue
            lines.append("%s:[" % _compact(key))
            for j, item in enumerate(items):
                lines.append(_compact(item) + ("," if j + 1 < len(items) else ""))
            lines.append("]" + sep)
        else:
            lines.append("%s:%s%s" % (_compact(key), _compact(value), sep))
    lines.append("}")
    return "\n".join(lines) + "\n"


def write(path: str, doc: dict) -> None:
    """Write atomically (temp file + rename) so readers never see half a file."""
    data = dumps(doc).encode("ascii")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp.%d" % os.getpid()
    opener = gzip.open if path.endswith(".gz") else open
    if path.endswith(".gz"):
        # mtime=0 keeps the gzip header deterministic.
        with open(tmp, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as f:
            f.write(data)
    else:
        with opener(tmp, "wb") as f:
            f.write(data)
    os.replace(tmp, path)


def load(path: str) -> dict:
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rb") as f:
        doc = json.loads(f.read().decode("utf-8"))
    version = doc.get("format_version")
    if version != FORMAT_VERSION:
        raise ValueError("%s: format_version %r, expected %d" % (path, version, FORMAT_VERSION))
    return doc


def is_reference_file(name: str) -> bool:
    return (name.endswith(".json") or name.endswith(".json.gz")) and not name.startswith(("_", "."))


def find_reference_files(root: str) -> dict[str, str]:
    """Map each reference file under root to its path relative to root,
    with the .json/.json.gz suffix removed (so .json and .json.gz pair up)."""
    found: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            if not is_reference_file(name):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            for suffix in (".json.gz", ".json"):
                if rel.endswith(suffix):
                    rel = rel[: -len(suffix)]
                    break
            found[rel] = full
    return found


# --- p-code normalization -------------------------------------------------

def normalize_pcode(ops: Iterable[dict]) -> list[tuple]:
    """Return an instruction's p-code as comparable tuples, with `unique`
    offsets renumbered in order of first appearance (0, 1, 2, ...).

    Two unique varnodes that share an offset get the same number even if their
    sizes differ, matching how SLEIGH reuses temporaries.
    """
    renumber: dict[str, int] = {}

    def vn(v):
        if v is None:
            return None
        space, offset, size = v
        if space == "unique":
            if offset not in renumber:
                renumber[offset] = len(renumber)
            offset = "u%d" % renumber[offset]
        return (space, offset, size)

    out = []
    for op in ops:
        # Order of appearance: ops in order; within an op the output first,
        # then inputs left to right (docs/reference-format.md).
        o = vn(op.get("out"))
        ins = tuple(vn(v) for v in op.get("in", []))
        out.append((op["op"], o, ins))
    return out
