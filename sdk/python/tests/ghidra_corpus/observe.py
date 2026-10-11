"""What the Ghidra compatibility corpus observes about a script's run, and
how two observations (revkit's and Ghidra's) are compared.

Shared by the revkit runner (run.py, CPython with the revkit SDK) and the
reference driver (ghidra_reference.py, PyGhidra's CPython with JPype), so it
imports nothing but the standard library.

An observation is a dict:

    {"status": "ok" | "error", "error": str, "output": [lines], "messages": [lines],
     "functions": {"0x101295": "main", ...},           # after the run
     "changes": {"functions": {...}, "comments": {...}, "names": {...}},
     "bytes": {"0x104010": "6865..."}, "file": str | None}

``changes`` are what the script did: each maps a key ("0x101295" or
"0x101295/eol") to [before, after]. Comparisons are restricted to the
addresses both programs have (Ghidra's ELF loader adds an EXTERNAL pseudo
block that revkit doesn't have).
"""

from __future__ import annotations

import re

ADDR = re.compile(r"\b(?:0x)?([0-9a-f]{8,16})\b")
SPACE_ADDR = re.compile(r"[\w.]+::[0-9a-f]+")  # an address in another space (".symtab::00000330")


def scenarios(path, program: str = "fixture", only=()) -> list:
    """corpus.json's scenarios for ``program``, with its overrides ("on")
    applied."""
    import json

    out = []
    for s in json.loads(open(path).read())["scenarios"]:
        if program not in s.get("programs", ["fixture", "features"]) or (only and s["name"] not in only):
            continue
        spec = {k: v for k, v in s.items() if k != "on"}
        spec.update(s.get("on", {}).get(program, {}))
        if spec.get("skip"):
            continue
        out.append(spec)
    return out


def normalize_output(lines: list, script: str) -> list:
    """Script output without Ghidra's "Script.py> " decoration or trailing blanks."""
    out = []
    prefix = re.compile(r"^" + re.escape(script) + r"> ?")
    for line in lines:
        line = prefix.sub("", line.rstrip("\r"))
        out.append(line.rstrip())
    while out and not out[-1]:
        out.pop()
    return out


def diff(before: dict, after: dict) -> dict:
    """{key: [before, after]} for keys whose value changed (None: absent)."""
    out = {}
    for k in set(before) | set(after):
        if before.get(k) != after.get(k):
            out[k] = [before.get(k), after.get(k)]
    return out


def in_blocks(key: str, blocks: list) -> bool:
    a = int(key.split("/", 1)[0], 16)
    return any(lo <= a <= hi for lo, hi in blocks)


def _addresses_ok(line: str, blocks: list) -> bool:
    if SPACE_ADDR.search(line):
        return False
    for m in ADDR.finditer(line):
        a = int(m.group(1), 16)
        if a >= 0x10000 and not any(lo <= a <= hi for lo, hi in blocks):
            return False
    return True


def comparable(obs: dict, spec: dict, blocks: list) -> dict:
    """The parts of an observation a scenario compares, normalized."""
    script = spec["script"]
    norm = spec.get("normalize", {})
    out = {"status": obs.get("status")}
    if obs.get("status") != "ok":
        out["error"] = obs.get("unsupported") or obs.get("error", "")[:200]
    want = spec.get("compare", ["output"])
    if "output" in want or "output_sorted" in want:
        lines = normalize_output(obs.get("output", []), script)
        for pat in norm.get("drop_lines", []):
            lines = [l for l in lines if not re.search(pat, l)]
        for pat, rep in norm.get("replace", []):
            lines = [re.sub(pat, rep, l) for l in lines]
        if norm.get("common_addresses_only", True):
            lines = [l for l in lines if _addresses_ok(l, blocks)]
        out["output"] = sorted(lines) if "output_sorted" in want else lines
    if "messages" in want:
        msgs = [m for m in obs.get("messages", [])]
        for pat, rep in norm.get("replace", []):
            msgs = [re.sub(pat, rep, l) for l in msgs]
        out["messages"] = msgs
    for kind in ("functions", "comments", "names"):
        if kind in want:
            ch = obs.get("changes", {}).get(kind, {})
            out[kind] = {k: v for k, v in sorted(ch.items()) if in_blocks(k, blocks)}
    if "bytes" in want:
        out["bytes"] = obs.get("bytes", {})
    if "file" in want:
        text = obs.get("file") or ""
        if norm.get("file_json_common"):
            import json

            key = norm["file_json_common"]
            try:
                items = json.loads(text)
                text = json.dumps([x for x in items if in_blocks(x[key], blocks)], indent=1)
            except ValueError:
                pass
        for pat, rep in norm.get("file_replace", []):
            text = re.sub(pat, rep, text)
        out["file"] = text
    return out


def compare(spec: dict, revkit: dict, ghidra: dict, blocks: list) -> tuple:
    """(agree, revkit part, ghidra part, differences as text lines)."""
    r = comparable(revkit, spec, blocks)
    g = comparable(ghidra, spec, blocks)
    lines = []
    for k in sorted(set(r) | set(g)):
        if r.get(k) != g.get(k):
            lines.append(f"{k}: revkit {_short(r.get(k))} != ghidra {_short(g.get(k))}")
    return not lines, r, g, lines


def _short(v) -> str:
    text = repr(v)
    return text if len(text) < 600 else text[:600] + "..."
