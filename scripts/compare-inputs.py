#!/usr/bin/env python3
"""Compare revkit's own decompiler inputs with Ghidra's, kind by kind.

  scripts/decompile-corpus.sh --inputs own --dump-inputs --out out/revkit-decomp-own
  scripts/compare-inputs.py out/ghidra-db out/revkit-decomp-own [--by-group] [--examples N]

The first directory holds Ghidra's exports (docs/decompiler-inputs.md), the
second rk-lift --dump-inputs documents (_<name>.inputs.json beside each
output). Per kind, agreement is items equal on both sides / items on
either side, as refdiff counts:

  functions   function entries (EXTERNAL placeholders included)
  names       function names, on common entries
  noreturn    the no-return flag, on common entries
  signatures  parameter and return types and storage, on common entries
  patches     relocated bytes (address and value)
  overrides   flow overrides (address and kind)
  labels      code labels (address and name)
  tracked     tracked registers at function entries (entry, value)
  data        data symbols (address and name)
  datatypes   data symbols' types, on common addresses
  externals   PE import slots (address and label)
  locals      local variables' names and storage, on common entries
  comments    comments (address, kind and text)
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys

KINDS = ["functions", "names", "noreturn", "signatures", "patches", "overrides", "labels", "tracked", "data",
         "datatypes", "externals", "locals", "comments"]


def _load(path):
    with open(path) as f:
        return json.load(f)


def _int(a):
    return int(a, 16) if isinstance(a, str) else a


def _strip_ids(x):
    """A type reference without ids, which differ between the two sides by
    construction; inline built-in types and references to them alike."""
    if isinstance(x, list):
        if len(x) >= 2 and isinstance(x[0], str) and isinstance(x[1], dict):
            a = {k: v for k, v in x[1].items() if k not in ("id", "char", "utf")}
            tag = x[0]
            if tag == "type" and a.get("metatype") not in ("ptr", "array", "struct", "union", "code") and \
                    a.get("name"):
                tag, a = "typeref", {"name": a["name"]}  # inline built-in == its reference
            if tag == "typeref":
                a = {"name": a.get("name")}
            return [tag, a] + [[_strip_ids(c) for c in x[2]]] if len(x) > 2 else [tag, a]
        return [_strip_ids(c) for c in x]
    return x


def _type(x):
    return json.dumps(_strip_ids(x), sort_keys=True)


def _sig(f):
    t = _type
    if f.get("signature_source", "DEFAULT") == "DEFAULT" and not f.get("params"):
        return ("DEFAULT",)  # an unlocked return encodes as undefined or void alike
    r = f.get("return", {})
    return (f.get("signature_source"), t(r.get("type")), json.dumps(r.get("storage")),
            tuple((p.get("name"), t(p.get("type")), json.dumps(p.get("storage"))) for p in f.get("params", [])),
            f.get("varargs", False))


def _locals(f):
    return sorted((l["name"], json.dumps(l.get("storage") or l.get("hash")), _type(l.get("type")))
                  for l in f.get("locals", []))


def compare(ref: dict, own: dict, tally, examples, rel, max_examples):
    def add(kind, ok, ex):
        tally[kind][1] += 1
        if ok:
            tally[kind][0] += 1
        elif len(examples[kind]) < max_examples:
            examples[kind].append((rel,) + ex)

    def sets(kind, a, b):
        for k in sorted(set(a) | set(b)):
            add(kind, k in a and k in b and a[k] == b[k], (k, a.get(k), b.get(k)))

    rf = {_int(f["entry"]): f for f in ref["functions"]}
    of = {_int(f["entry"]): f for f in own["functions"]}
    sets("functions", {k: True for k in rf}, {k: True for k in of})
    for e in sorted(set(rf) & set(of)):
        add("names", rf[e]["name"] == of[e]["name"], (hex(e), rf[e]["name"], of[e]["name"]))
        add("noreturn", bool(rf[e].get("noreturn")) == bool(of[e].get("noreturn")),
            (hex(e), rf[e]["name"], rf[e].get("noreturn"), of[e].get("noreturn")))
        add("signatures", _sig(rf[e]) == _sig(of[e]), (hex(e), rf[e]["name"], _sig(rf[e]), _sig(of[e])))
        add("locals", _locals(rf[e]) == _locals(of[e]), (hex(e), rf[e]["name"], _locals(rf[e]), _locals(of[e])))
    sets("patches", {_int(p["addr"]): p["bytes"] for p in ref.get("patches", [])},
         {_int(p["addr"]): p["bytes"] for p in own.get("patches", [])})
    sets("overrides", {_int(o["addr"]): o["kind"] for o in ref.get("flow_overrides", [])},
         {_int(o["addr"]): o["kind"] for o in own.get("flow_overrides", [])})
    sets("labels", {_int(l["addr"]): l["name"] for l in ref.get("code_labels", [])},
         {_int(l["addr"]): l["name"] for l in own.get("code_labels", [])})

    def tracked(doc):
        out = {}
        for e, regs in (doc.get("tracked") or {}).items():
            vals = sorted(_int(r[3]) for r in regs if not (r[1] in ("0x20a", "DF")))  # DF comes from the pspec
            if vals:
                out[_int(e)] = vals
        return out
    sets("tracked", tracked(ref), tracked(own))
    sets("data", {(d.get("space", ""), _int(d["addr"])): d["name"] for d in ref.get("data", [])},
         {(d.get("space", ""), _int(d["addr"])): d["name"] for d in own.get("data", [])})
    rd = {(d.get("space", ""), _int(d["addr"])): d for d in ref.get("data", [])}
    od = {(d.get("space", ""), _int(d["addr"])): d for d in own.get("data", [])}
    for k in sorted(set(rd) & set(od)):
        a, b = _type(rd[k]["type"]), _type(od[k]["type"])
        add("datatypes", a == b and rd[k].get("length") == od[k].get("length"), (k, rd[k]["name"], a, b))
    sets("comments", {(_int(c["addr"]), c["kind"]): c["text"] for c in ref.get("comments", [])},
         {(_int(c["addr"]), c["kind"]): c["text"] for c in own.get("comments", [])})
    sets("externals", {_int(x["addr"]): x["label"] for x in ref.get("external_refs", [])},
         {_int(x["addr"]): x["label"] for x in own.get("external_refs", [])})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ghidra", help="Ghidra's decompiler inputs (out/ghidra-db)")
    ap.add_argument("own", help="rk-lift output with --dump-inputs")
    ap.add_argument("--by-group", action="store_true", help="also per arch/toolchain/variant")
    ap.add_argument("--examples", type=int, default=0, metavar="N", help="N mismatches per kind")
    ap.add_argument("--only", help="comma-separated kinds")
    args = ap.parse_args()
    kinds = args.only.split(",") if args.only else KINDS

    total = {k: [0, 0] for k in KINDS}
    groups = collections.defaultdict(lambda: {k: [0, 0] for k in KINDS})
    examples = {k: [] for k in KINDS}
    for dirpath, _, files in os.walk(args.ghidra):
        for name in sorted(files):
            if not name.endswith(".json") or name.startswith("_"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), args.ghidra)[:-5]
            own_path = os.path.join(args.own, os.path.dirname(rel), "_" + os.path.basename(rel) + ".inputs.json")
            if not os.path.exists(own_path):
                print("missing: " + own_path, file=sys.stderr)
                continue
            t = {k: [0, 0] for k in KINDS}
            compare(_load(os.path.join(dirpath, name)), _load(own_path), t, examples, rel, args.examples)
            g = "/".join(rel.split("/")[:3])
            for k in KINDS:
                for i in (0, 1):
                    total[k][i] += t[k][i]
                    groups[g][k][i] += t[k][i]

    def pct(a, t):
        return "     n/a" if t == 0 else "%7.2f%%" % (100.0 * a / t)
    if args.by_group:
        print("%-32s %s" % ("group", " ".join("%9s" % k[:9] for k in kinds)))
        for g in sorted(groups):
            print("%-32s %s" % (g, " ".join("%9s" % pct(*groups[g][k]) for k in kinds)))
        print()
    print("%-12s %8s %8s %9s" % ("kind", "agree", "total", "rate"))
    for k in kinds:
        print("%-12s %8d %8d %s" % (k, total[k][0], total[k][1], pct(*total[k])))
    for k in kinds:
        if examples[k]:
            print("\n== %s mismatches ==" % k)
            for ex in examples[k]:
                print("  " + " | ".join(str(x)[:240] for x in ex))
    return 0


if __name__ == "__main__":
    sys.exit(main())
