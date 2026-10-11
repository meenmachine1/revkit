#!/usr/bin/env python3
"""Ghidra reads revkit's type archives (docs/types.md#type-archives).

Each corpus debug binary's types are exported as an archive
(rk-debuginfo --archive, the archive revkit's ExportTypeArchive writes),
parsed by Ghidra's own C parser through PyGhidra (type_archive_ghidra.py)
for the binary's language and compiler spec, and every struct, union, enum
and typedef Ghidra makes is compared with revkit's layout of the same
header (rk-cparse --json): its size, and each named member's offset
(a bitfield's bit position and width).

    type_archive_check.py --rk-debuginfo B --rk-cparse C --pyghidra PY [--corpus DIR] [--json out.json]
    type_archive_check.py --rk-debuginfo B --rk-cparse C --clang CLANG --compile-only

--compile-only instead has a real compiler (clang -fsyntax-only for each
binary's target) check each header, its _Static_asserts of every size
included. Exit 0 when every header parses and every layout agrees (or
compiles), 1 otherwise, 77 when PyGhidra (or clang) or the corpus is
missing.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# Types Ghidra's parser has built in, so a header's typedef of one is
# dropped (its own, of the data organization's size, is used).
GHIDRA_BUILTINS = {"wchar_t"}

# (corpus path, revkit target, Ghidra language, Ghidra compiler spec)
TARGETS = [
    ("elf-x86_64/gcc-O2/debug/cjson", "x86_64-linux-gnu", "x86:LE:64:default", "gcc"),
    ("elf-x86_64/gcc-O2/debug/zlib", "x86_64-linux-gnu", "x86:LE:64:default", "gcc"),
    ("elf-x86_64/gcc-O2/debug/lua", "x86_64-linux-gnu", "x86:LE:64:default", "gcc"),
    ("elf-x86_64/gcc-O0/debug/features", "x86_64-linux-gnu", "x86:LE:64:default", "gcc"),
    ("elf-aarch64/clang-O2/debug/lua", "aarch64-linux-gnu", "AARCH64:LE:64:v8A", "default"),
    ("elf-aarch64/gcc-O2/debug/features", "aarch64-linux-gnu", "AARCH64:LE:64:v8A", "default"),
    ("elf-riscv64/gcc-O2/debug/zlib", "riscv64-linux-gnu", "RISCV:LE:64:RV64GC", "gcc"),
    ("pe-x86_64/clang-O2/debug/cjson.exe", "x86_64-w64-mingw32", "x86:LE:64:default", "windows"),
    ("pe-x86_64/clang-O2/debug/features.exe", "x86_64-w64-mingw32", "x86:LE:64:default", "windows"),
]


def run(cmd, **kw):
    return subprocess.run(cmd, check=False, capture_output=True, text=True, **kw)


def compare(ours: dict, ghidra: list, header: str) -> dict:
    """Revkit's layouts (rk-cparse --json) against Ghidra's (in the header's category)."""
    cat = "/" + os.path.basename(header)
    theirs = {}
    for t in ghidra:
        if t["category"] == cat:
            theirs.setdefault((t["kind"], t["name"]), t)
    tags = {(n["key"].split(" ", 1)[1]) for n in ours["named"] if not n["key"].startswith("typedef ")}
    out = {"types": 0, "sizes_agree": 0, "fields": 0, "fields_agree": 0, "missing": [], "differ": [], "builtin": []}
    for n in ours["named"]:
        kind, name = n["key"].split(" ", 1)
        if kind == "class" or not n.get("complete", True):
            continue
        g = theirs.get((kind, name))
        if g is None and kind == "typedef":
            # Ghidra folds `typedef struct x x;` into the struct, and names
            # an anonymous struct, union or enum after its typedef.
            if name in tags:
                continue
            # Ghidra's own wchar_t stands for a typedef of it.
            if name in GHIDRA_BUILTINS:
                out["builtin"].append(n["key"])
                continue
            g = next((theirs[(k, name)] for k in ("struct", "union", "enum") if (k, name) in theirs), None)
        if g is None:
            out["missing"].append(n["key"])
            continue
        out["types"] += 1
        if g["length"] == n["size"] or (kind == "typedef" and n["size"] == 0):
            out["sizes_agree"] += 1
        else:
            out["differ"].append(f"{n['key']}: size {n['size']} in revkit, {g['length']} in Ghidra")
        if kind not in ("struct", "union"):
            continue
        by_name = {c["name"]: c for c in g["components"] if c["name"]}
        for f in n.get("fields", []):
            if not f["name"]:
                continue
            out["fields"] += 1
            c = by_name.get(f["name"])
            if c is None:
                out["differ"].append(f"{n['key']}.{f['name']}: not in Ghidra's")
                continue
            if f["bit_size"]:
                at = c["offset"] * 8 + c.get("bit_offset", 0)
                ok = c.get("bit_size") == f["bit_size"] and at == f["bit_offset"]
                where = f"bit {f['bit_offset']}:{f['bit_size']} in revkit, {at}:{c.get('bit_size')} in Ghidra"
            else:
                ok = c["offset"] * 8 == f["bit_offset"]
                where = f"offset {f['bit_offset'] // 8} in revkit, {c['offset']} in Ghidra"
            if ok:
                out["fields_agree"] += 1
            else:
                out["differ"].append(f"{n['key']}.{f['name']}: {where}")
    return out


def compile_only(a) -> int:
    """Each corpus archive through clang -fsyntax-only for its target."""
    if not a.clang or not os.path.exists(a.clang):
        print("type_archive_check: no clang; skipped")
        return 77
    targets = [t for t in TARGETS if os.path.exists(os.path.join(a.corpus, t[0]))]
    if not targets:
        print("type_archive_check: corpus not built; skipped")
        return 77
    bad = 0
    with tempfile.TemporaryDirectory(prefix="rk-archive-cc-") as tmp:
        for rel, target, _, _ in targets:
            name = rel.replace("/", "_").replace(".exe", "")
            header = os.path.join(tmp, name + ".h")
            r = run([a.rk_debuginfo, "--archive", name, "--target", target, os.path.join(a.corpus, rel)])
            with open(header, "w") as f:
                f.write(r.stdout)
            asserts = r.stdout.count("_Static_assert(")
            c = run([a.clang, f"--target={target}", "-fsyntax-only", "-x", "c", header])
            ok = r.returncode == 0 and c.returncode == 0
            bad += not ok
            print(f"{'ok  ' if ok else 'FAIL'} {rel}: {target}, {asserts} sizes asserted"
                  + ("" if r.returncode == 0 else f"; rk-debuginfo: {r.stderr.strip()[-500:]}")
                  + ("" if c.returncode == 0 else f"; clang: {c.stderr.strip()[-1500:]}"))
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rk-debuginfo", required=True)
    ap.add_argument("--rk-cparse", required=True)
    ap.add_argument("--pyghidra", default=os.environ.get("REVKIT_PYGHIDRA", ""))
    ap.add_argument("--corpus", default=os.path.join(HERE, "..", "..", "out", "corpus"))
    ap.add_argument("--json", default="")
    ap.add_argument("--clang", default="")
    ap.add_argument("--compile-only", action="store_true")
    ap.add_argument("--header", action="append", default=[],
                    help="also check a header: PATH,TARGET,LANGUAGE,COMPILER (an archive's header)")
    a = ap.parse_args()
    if a.compile_only:
        return compile_only(a)
    if not a.pyghidra or not os.path.exists(a.pyghidra):
        print("type_archive_check: no PyGhidra (scripts/setup-pyghidra.sh); skipped")
        return 77
    targets = [t for t in TARGETS if os.path.exists(os.path.join(a.corpus, t[0]))]
    extra = [h.split(",") for h in a.header]
    if not targets and not extra:
        print("type_archive_check: corpus not built; skipped")
        return 77
    with tempfile.TemporaryDirectory(prefix="rk-archive-ghidra-") as tmp:
        jobs, ours = [], {}
        for rel, target, language, compiler in targets:
            name = rel.replace("/", "_").replace(".exe", "")
            header = os.path.join(tmp, name + ".h")
            r = run([a.rk_debuginfo, "--archive", name, "--target", target, os.path.join(a.corpus, rel)])
            if not r.stdout:
                print(f"{rel}: rk-debuginfo --archive failed: {r.stderr}")
                return 1
            with open(header, "w") as f:
                f.write(r.stdout)
            j = run([a.rk_cparse, "--json", "--target", target, header])
            ours[header] = json.loads(j.stdout)
            jobs.append({"header": header, "language": language, "compiler": compiler, "rel": rel})
        for path, target, language, compiler in extra:
            j = run([a.rk_cparse, "--json", "--target", target, path])
            ours[path] = json.loads(j.stdout)
            jobs.append({"header": path, "language": language, "compiler": compiler, "rel": os.path.basename(path)})
        jobs_path, out_path = os.path.join(tmp, "jobs.json"), os.path.join(tmp, "ghidra.json")
        with open(jobs_path, "w") as f:
            json.dump(jobs, f)
        env = dict(os.environ)
        r = run([a.pyghidra, os.path.join(HERE, "type_archive_ghidra.py"), jobs_path, out_path], env=env)
        if r.returncode != 0 or not os.path.exists(out_path):
            print(f"type_archive_ghidra.py failed:\n{r.stdout[-4000:]}\n{r.stderr[-4000:]}")
            return 1
        with open(out_path) as f:
            ghidra = {g["header"]: g for g in json.load(f)}
        report, bad = [], 0
        for job in jobs:
            g = ghidra[job["header"]]
            c = compare(ours[job["header"]], g["types"], job["header"])
            errors = [m for m in g["messages"].splitlines() if "error" in m.lower()]
            ok = g["success"] and not errors and not c["missing"] and not c["differ"]
            bad += not ok
            report.append({"binary": job["rel"], "parsed": g["success"], "errors": errors, **c})
            print(f"{'ok  ' if ok else 'FAIL'} {job['rel']}: parsed {g['success']}, {c['types']} types "
                  f"({c['sizes_agree']} sizes agree), {c['fields']} members ({c['fields_agree']} agree)"
                  + (f", {len(c['missing'])} missing" if c["missing"] else "")
                  + (f"; Ghidra's own: {', '.join(c['builtin'])}" if c["builtin"] else ""))
            for m in errors[:10] + c["missing"][:10] + c["differ"][:20]:
                print(f"     {m}")
        if a.json:
            with open(a.json, "w") as f:
                json.dump(report, f, indent=1)
        return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
