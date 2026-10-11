#!/usr/bin/env python3
"""Function ID gate (docs/fid.md, "Gates"): name a static library's
functions in a stripped program that links it, from a database built from
another program that links the same library.

For zlib 1.3.1 and Lua 5.4.7 (the corpus's pinned tarballs in out/cache),
built here with the host's gcc -O2 -g:
  - the library's objects into lib<x>.a;
  - a "source" program linking it (zlib: minigzip; Lua: lua) and a "target"
    program linking it too (zlib: example; Lua: luac), the target stripped.
Then `rk-fid create` makes a database from the source's debug build and
`rk-fid match` names the stripped target; the truth is the target's
debug build at the same addresses. Precision: of the names revkit applies,
the fraction that are right. Recall: of the target's functions the
database could name (their true name is in it), the fraction named right.

With --ghidra, the same with Ghidra's own database: Ghidra populates a FID
database from the source (ghidra_fid_create.py), Ghidra's FID searches the
stripped target with it (ghidra_fid.py --fidb), and revkit matches the same
target with the same database read natively (.fidbf); agreement is the
fraction of functions where both name the same (or both name nothing).

  scripts/fid-gate.py [--ghidra] [--out report.json] [--work DIR]

Exit 1 if precision < 0.95 on any library (and, with --ghidra, agreement
< 0.90).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RKFID = os.path.join(ROOT, "build", "tools", "rk-fid", "rk-fid")
CACHE = os.path.join(ROOT, "out", "cache")

LIBS = {
    "zlib": {
        "tarball": "zlib-1.3.1.tar.gz",
        "version": "1.3.1",
        "lib": ["adler32", "compress", "crc32", "deflate", "gzclose", "gzlib", "gzread", "gzwrite", "infback",
                "inffast", "inflate", "inftrees", "trees", "uncompr", "zutil"],
        "cflags": ["-D_LARGEFILE64_SOURCE=1", "-DHAVE_HIDDEN", "-I."],
        "source": "test/minigzip.c",
        "target": "test/example.c",
        "libs": [],
    },
    "lua": {
        "tarball": "lua-5.4.7.tar.gz",
        "version": "5.4.7",
        "srcdir": "src",
        "lib": ["lapi", "lcode", "lctype", "ldebug", "ldo", "ldump", "lfunc", "lgc", "llex", "lmem", "lobject",
                "lopcodes", "lparser", "lstate", "lstring", "ltable", "ltm", "lundump", "lvm", "lzio", "lauxlib",
                "lbaselib", "lcorolib", "ldblib", "liolib", "lmathlib", "loadlib", "loslib", "lstrlib", "ltablib",
                "lutf8lib", "linit"],
        "cflags": ["-DLUA_COMPAT_5_3", "-DLUA_USE_POSIX"],
        "source": "lua.c",
        "target": "luac.c",
        "libs": ["-lm"],
    },
}


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


def build(name: str, spec: dict, work: str) -> dict:
    """Builds lib<name>.a and the two programs; returns their paths."""
    src = os.path.join(work, name + "-src")
    if not os.path.isdir(src):
        with tarfile.open(os.path.join(CACHE, spec["tarball"])) as t:
            members = []
            for m in t.getmembers():
                parts = m.name.split("/", 1)
                if len(parts) < 2 or m.issym() or m.islnk() or ".." in parts[1].split("/"):
                    continue
                m.name = parts[1]
                members.append(m)
            t.extractall(src, members=members, filter="data")
    d = os.path.join(src, spec.get("srcdir", ""))
    cc = ["gcc", "-O2", "-g"] + spec["cflags"]
    objs = []
    for f in spec["lib"]:
        o = os.path.join(work, f"{name}-{f}.o")
        if not os.path.exists(o):
            run(cc + ["-c", f + ".c", "-o", o], cwd=d)
        objs.append(o)
    lib = os.path.join(work, f"lib{name}.a")
    if not os.path.exists(lib):
        run(["ar", "rcs", lib] + objs)
    out = {}
    for role in ("source", "target"):
        exe = os.path.join(work, f"{name}-{role}")
        if not os.path.exists(exe):
            run(cc + [spec[role], lib, "-o", exe] + spec["libs"], cwd=d)
        stripped = exe + "-stripped"
        if not os.path.exists(stripped):
            shutil.copy(exe, stripped)
            run(["strip", "--strip-all", stripped])
        out[role] = exe
        out[role + "_stripped"] = stripped
    return out


def rkfid(*args) -> str:
    return subprocess.run([RKFID, *args], check=True, capture_output=True, text=True).stdout


def truth(debug_exe: str) -> dict:
    doc = json.loads(rkfid("hash", debug_exe, "--json"))
    return {f["entry"]: f["name"] for f in doc["functions"]}


def strip_us(n: str) -> str:
    """Compared names: leading underscores and GCC clone suffixes aside
    (".part.0", ".isra.0", ".constprop.0", ".cold"), which debug info and
    symbol tables spell differently."""
    n = n.lstrip("_")
    for marker in (".part.", ".isra.", ".constprop.", ".cold", ".lto_priv."):
        i = n.find(marker)
        if i > 0:
            n = n[:i]
    return n


def library_names(lib: str) -> set:
    """The functions the static library defines (nm: T and t symbols)."""
    out = subprocess.run(["nm", "--defined-only", lib], check=True, capture_output=True, text=True).stdout
    return {strip_us(l.split()[2]) for l in out.splitlines() if len(l.split()) == 3 and l.split()[1] in "Tt"}


def score(matches: list, truth_names: dict, db_names: set, lib_names: set) -> dict:
    applied = [m for m in matches if m["name"] and not m["name"].startswith("FID_conflict:")]
    right = [m for m in applied if strip_us(m["name"]) == strip_us(truth_names.get(m["entry"], ""))]
    known = {strip_us(n) for n in db_names}
    identifiable = {e for e, n in truth_names.items() if strip_us(n) in known and strip_us(n) in lib_names}
    named_right = {m["entry"] for m in right} & identifiable
    return {
        "applied": len(applied),
        "correct": len(right),
        "precision": round(len(right) / len(applied), 4) if applied else None,
        "identifiable": len(identifiable),
        "recall": round(len(named_right) / len(identifiable), 4) if identifiable else None,
        "missed": sorted((e, truth_names[e]) for e in identifiable - named_right)[:40],
        "wrong": sorted((m["entry"], m["name"], truth_names.get(m["entry"], "")) for m in applied if m not in right)[:20],
    }


def db_names(db: str) -> set:
    """Function names in a database, through rk-fid's matcher's view."""
    return set(json.loads(rkfid("names", db)))


def ghidra_check(name: str, built: dict, work: str, truth_names: dict, lib_names: set) -> dict:
    py = subprocess.run([os.path.join(ROOT, "scripts", "setup-pyghidra.sh")], check=True, capture_output=True,
                        text=True).stdout.strip()
    fidb = os.path.join(work, f"{name}-ghidra.fidb")
    raw = os.path.join(work, f"{name}-ghidra.fidbf")
    run([py, os.path.join(ROOT, "tools", "ghidra-export", "ghidra_fid_create.py"), "--library",
         f"{name}:{LIBS[name]['version']}:gcc-O2", "--out", fidb, "--raw", raw, built["source"]],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    gout = os.path.join(work, f"{name}-ghidra-match.json")
    run([py, os.path.join(ROOT, "tools", "ghidra-export", "ghidra_fid.py"), built["target_stripped"], "--out", gout,
         "--no-fid-analyzer", "--fidb", fidb], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    g = json.load(open(gout))
    ghidra_names = {}
    for r in g.get("matches", []):
        names = sorted({m["name"] for m in r["matches"]})
        best = max((m["score"] for m in r["matches"]), default=0)
        if not names:
            continue
        similar = {strip_us(n) for n in names}
        if len(names) == 1 or len(similar) == 1:
            ghidra_names[r["entry"]] = names[0]
        elif best >= 30:
            ghidra_names[r["entry"]] = "FID_conflict:" + names[0]
    rk = json.loads(rkfid("match", built["target_stripped"], "--db", raw, "--json"))
    rk_names = {m["entry"]: m["name"] for m in rk if m["name"]}
    entries = set(ghidra_names) | set(rk_names)
    agree = sum(1 for e in entries if ghidra_names.get(e) == rk_names.get(e))
    funcs = len(truth_names)
    return {
        "ghidra_named": len(ghidra_names),
        "revkit_named": len(rk_names),
        "both_same": agree,
        "agreement_named": round(agree / len(entries), 4) if entries else None,
        "agreement_all": round((funcs - len(entries) + agree) / funcs, 4) if funcs else None,
        "revkit_on_ghidra_db": score(rk, truth_names, db_names(raw), lib_names),
        "ghidra": score([{"entry": e, "name": n} for e, n in ghidra_names.items()], truth_names, db_names(raw),
                        lib_names),
        "disagree": sorted((e, ghidra_names.get(e, ""), rk_names.get(e, "")) for e in entries
                           if ghidra_names.get(e) != rk_names.get(e))[:20],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ghidra", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--work")
    ap.add_argument("--only", choices=sorted(LIBS))
    args = ap.parse_args()
    if not os.path.exists(RKFID):
        print("build rk-fid first", file=sys.stderr)
        return 2
    work = args.work or tempfile.mkdtemp(prefix="rk-fid-gate-")
    os.makedirs(work, exist_ok=True)
    report, ok = {}, True
    for name, spec in LIBS.items():
        if args.only and name != args.only:
            continue
        if not os.path.exists(os.path.join(CACHE, spec["tarball"])):
            print(f"{name}: {spec['tarball']} not in out/cache (scripts/build-corpus.sh fetches it)", file=sys.stderr)
            continue
        built = build(name, spec, work)
        db = os.path.join(work, f"{name}.rkfid")
        rkfid("create", "--name", name, "--version", spec["version"], "--variant", "gcc-O2", "-o", db,
              built["source"])
        matches = json.loads(rkfid("match", built["target_stripped"], "--db", db, "--json"))
        t = truth(built["target"])
        lib_names = library_names(os.path.join(work, f"lib{name}.a"))
        r = {"revkit": score(matches, t, db_names(db), lib_names), "functions": len(t)}
        if args.ghidra:
            r["ghidra_check"] = ghidra_check(name, built, work, t, lib_names)
            if (r["ghidra_check"]["agreement_named"] or 0) < 0.90:
                ok = False
        if (r["revkit"]["precision"] or 0) < 0.95:
            ok = False
        report[name] = r
        print(f"{name}: precision {r['revkit']['precision']} ({r['revkit']['correct']}/{r['revkit']['applied']}), "
              f"recall {r['revkit']['recall']} of {r['revkit']['identifiable']} identifiable")
        if args.ghidra:
            g = r["ghidra_check"]
            print(f"  vs Ghidra on Ghidra's database: agreement {g['agreement_named']} of named "
                  f"({g['both_same']} of {len(set())+g['ghidra_named']} Ghidra / {g['revkit_named']} revkit), "
                  f"{g['agreement_all']} of all functions")
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(report, fh, indent=1)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
