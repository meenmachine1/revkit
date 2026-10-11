#!/usr/bin/env python3
"""Function ID cross-check with Ghidra on its shipped MSVC databases
(docs/fid.md, "Gates"): for each PE, Ghidra's FID search (ghidra_fid.py
--fidb, FidProgramSeeker with the analyzer's threshold) and revkit's
(`rk-fid match`) with the same .fidbf files (Ghidra/Features/FunctionID/
data: vs2012-vs2019 and vsOlder, x86 or x64 by the program's bitness), and
the agreement on the name each function gets.

  scripts/fid-crosscheck.py [--out report.json] program.exe...

The default programs are MSVC-built PEs that ship with Ghidra itself (its
native decompiler, sleigh and pdb tools, and the GhidraClass exercises).
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RKFID = os.path.join(ROOT, "build", "tools", "rk-fid", "rk-fid")
GHIDRA = os.environ.get("REVKIT_GHIDRA_ROOT", os.path.expanduser("~/ghidra/ghidra_12.1.4_PUBLIC"))
DEFAULT = [
    "Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe",
    "Ghidra/Features/Decompiler/os/win_x86_64/sleigh.exe",
    "Ghidra/Features/PDB/os/win_x86_64/pdb.exe",
    "docs/GhidraClass/ExerciseFiles/WinhelloCPP/WinHelloCPP.exe",
    "docs/GhidraClass/ExerciseFiles/VersionTracking/WallaceSrc.exe",
]


def ghidra_name(ms: list) -> str:
    """ApplyFidEntriesCommand's choice, as revkit's Match.name spells it."""
    names = sorted({m["name"] for m in ms})
    if not names:
        return ""
    if len(names) == 1 or len({n.lstrip("_") for n in names}) == 1:
        return names[0]
    return ""  # several names: compared as "named differently" by count only


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("programs", nargs="*")
    ap.add_argument("--out")
    ap.add_argument("--keep", help="directory for both sides' raw results")
    args = ap.parse_args()
    programs = args.programs or [os.path.join(GHIDRA, p) for p in DEFAULT]
    py = subprocess.run([os.path.join(ROOT, "scripts", "setup-pyghidra.sh")], check=True, capture_output=True,
                        text=True).stdout.strip()
    data = os.path.join(GHIDRA, "Ghidra", "Features", "FunctionID", "data")
    report = {}
    for prog in programs:
        if not os.path.exists(prog):
            continue
        with open(prog, "rb") as fh:
            head = fh.read(4096)
        pe = int.from_bytes(head[0x3c:0x40], "little")
        bits = 64 if head[pe + 24:pe + 26] == b"\x0b\x02" else 32
        dbs = sorted(glob.glob(os.path.join(data, f"*_x{'64' if bits == 64 else '86'}.fidbf")))
        gout = tempfile.mktemp(suffix=".json")
        cmd = [py, os.path.join(ROOT, "tools", "ghidra-export", "ghidra_fid.py"), prog, "--out", gout,
               "--no-fid-analyzer"]
        for d in dbs:
            cmd += ["--fidb", d]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        g = json.load(open(gout))
        os.remove(gout)
        rcmd = [RKFID, "match", prog, "--json"]
        for d in dbs:
            rcmd += ["--db", d]
        r = json.loads(subprocess.run(rcmd, check=True, capture_output=True, text=True).stdout)
        if args.keep:
            with open(os.path.join(args.keep, os.path.basename(prog) + ".json"), "w") as fh:
                json.dump({"ghidra": g, "revkit": r}, fh)
        gm = {x["entry"]: x.get("applied", ghidra_name(x["matches"])) for x in g.get("matches", [])}
        g_multi = {e for e, n in gm.items() if n.startswith("FID_conflict:")}
        gm = {e: n for e, n in gm.items() if n}
        rm = {x["entry"]: x["name"] for x in r if x["name"]}
        r_multi = {e for e, n in rm.items() if n.startswith("FID_conflict:")}
        entries = set(gm) | set(rm)
        same = sum(1 for e in entries if gm.get(e) == rm.get(e))
        funcs = len(g["functions"])
        res = {
            "bits": bits,
            "functions": funcs,
            "ghidra_named": len(gm),
            "revkit_named": len(rm),
            "same": same,
            "agreement_named": round(same / len(entries), 4) if entries else None,
            "ghidra_conflicts": len(g_multi),
            "revkit_conflicts": len(r_multi),
            "disagree": sorted((e, gm.get(e, ""), rm.get(e, "")) for e in entries if gm.get(e) != rm.get(e))[:25],
        }
        report[os.path.basename(prog)] = res
        print(f"{os.path.basename(prog)} (x{bits}): Ghidra names {len(gm)}, revkit {len(rm)}, same {same}: "
              f"agreement {res['agreement_named']}; FID_conflict: Ghidra {len(g_multi)}, revkit {len(r_multi)}")
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(report, fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
