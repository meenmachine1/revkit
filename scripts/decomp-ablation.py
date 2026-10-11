#!/usr/bin/env python3
"""Measure what each kind of Ghidra fact contributes to decompiler parity.

Starting from Ghidra's full decompiler inputs (out/ghidra-db), removes one
kind of fact at a time, decompiles the corpus with rk-lift, and reports the
c_ast agreement with the reference. The drop for each kind is how many
functions depend on it.

  scripts/decomp-ablation.py [--only KIND ...] [--json out.json]

With --own, starts instead from revkit's own inputs (rk-lift --analyze
--decompile --dump-inputs, nothing from Ghidra) and replaces one kind of
revkit's facts at a time with Ghidra's: the gain for each kind is how many
functions revkit's version of it still costs (the remaining gap). Rates
count only the functions both sides have (refdiff --common-functions).

  scripts/decomp-ablation.py --own [--only KIND ...] [--json out.json]
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools", "refdiff"))
import cnorm  # noqa: E402
import refdiff  # noqa: E402


def _default_signature(f: dict) -> dict:
    f = dict(f)
    f.update(signature_source="DEFAULT", convention="unknown", params=[], varargs=False,
             custom_storage=False)
    f["return"] = {"type": ["void", {}], "default": True, "storage": [], "void_storage": True, "size": 0}
    return f


# kind -> (description, function editing one document in place)
ABLATIONS = {
    "signatures": ("function signatures: parameters, return types, calling conventions",
                   lambda d: d.update(functions=[_default_signature(f) for f in d["functions"]],
                                      external_refs=[dict(x, function=_default_signature(x["function"]))
                                                     if x.get("function") else x for x in d["external_refs"]])),
    "noreturn": ("non-returning functions",
                 lambda d: [f.update(noreturn=False) for f in d["functions"]]),
    "locals": ("local variables (stack and DWARF locals)",
               lambda d: [f.update(locals=[]) for f in d["functions"]]),
    "data": ("defined data and data symbols (names, types)",
             lambda d: d.update(data=[])),
    "labels": ("code labels and other labels",
               lambda d: d.update(labels=[], code_labels=[])),
    "comments": ("comments (PLATE/PRE: DWARF notes, import versions)",
                 lambda d: d.update(comments=[])),
    "external_refs": ("pointer slots with external references (PE imports)",
                      lambda d: d.update(external_refs=[])),
    "patches": ("relocated bytes (GOT/IAT contents, RELATIVE pointers)",
                lambda d: d.update(patches=[])),
    "synthesized_memory": ("memory no file backs (PE thread data block)",
                           lambda d: d.update(synthesized_memory=[])),
    "flow_overrides": ("flow overrides (PLT jumps as CALL_RETURN)",
                       lambda d: d.update(flow_overrides=[])),
    "tracked": ("tracked register values (DF, GS_OFFSET, RISC-V gp)",
                lambda d: d.update(tracked={})),
    "namespaces": ("namespaces (DWARF static locals, external libraries)",
                   lambda d: [x.pop("namespace", None) for k in ("functions", "data", "labels")
                              for x in d[k]]),
    "memory_map": ("Ghidra's memory blocks (mutability of unnamed addresses)",
                   lambda d: d.update(memory=[])),
}


def run(inputs_dir: str, out_dir: str, args, examples: list | None = None, extra=()):
    subprocess.run([os.path.join(ROOT, "scripts", "decompile-corpus.sh"), "--inputs", inputs_dir, "--out", out_dir,
                    "-P", str(args.procs), "--in-order", "--rk-lift", args.rk_lift, *extra],
                   check=True, stdout=subprocess.DEVNULL)
    total, _, _ = refdiff.compare_paths(args.ref, out_dir, only={"c_ast", "binaries"}, max_examples=200,
                                        common=args.own)
    if examples is not None:
        # A few mismatches, spread over the corpus: where the tokens part.
        seen = set()
        for key, a, b in total.examples["c_ast"]:
            binary = key.split(" ")[0]
            if binary in seen or not (isinstance(a, str) and isinstance(b, str)):
                continue
            seen.add(binary)
            ra, rb = cnorm.first_difference(a, b, "ast", context=5)
            examples.append({"function": key, "ref": ra, "revkit": rb})
            if len(examples) >= args.examples:
                break
    return total.counts["c_ast"]


def _by_entry(doc):
    return {int(f["entry"], 16): f for f in doc["functions"]}


def _swap_function_fields(fields):
    def edit(own, ghidra):
        g = _by_entry(ghidra)
        for f in own["functions"]:
            h = g.get(int(f["entry"], 16))
            if h is None:
                continue
            for k in fields:
                if k in h:
                    f[k] = h[k]
                else:
                    f.pop(k, None)
    return edit


def _swap_keys(*keys):
    def edit(own, ghidra):
        for k in keys:
            own[k] = ghidra.get(k, {} if k == "tracked" else [])
    return edit


_SIGNATURE = ["signature_source", "convention", "params", "varargs", "custom_storage", "return", "extrapop",
              "has_this", "dynamic_storage"]


# kind -> (description, function moving Ghidra's facts of that kind into revkit's inputs)
SWAPS = {
    "names": ("function names", _swap_function_fields(["name"])),
    "signatures": ("function signatures: parameters, return types, calling conventions",
                   lambda o, g: (_swap_function_fields(_SIGNATURE)(o, g),
                                 o.update(external_refs=g.get("external_refs", [])))),
    "signatures_imports": ("signatures of imported functions (EXTERNAL, thunks, PE import slots)",
                           lambda o, g: (_swap_signature(o, g, imports=True),
                                         o.update(external_refs=g.get("external_refs", [])))),
    "signatures_local": ("signatures of the program's own functions",
                         lambda o, g: _swap_signature(o, g, imports=False)),
    "signatures_paramid": ("signatures Ghidra's Decompiler Parameter ID committed (source ANALYSIS)",
                           lambda o, g: _swap_signature(o, g, imports=False, source="ANALYSIS")),
    "signatures_other": ("the program's own signatures from elsewhere (debug info, archives)",
                         lambda o, g: _swap_signature(o, g, imports=False, source="!ANALYSIS")),
    "noreturn": ("non-returning functions", _swap_function_fields(["noreturn"])),
    "locals": ("local variables (stack and DWARF locals)", _swap_function_fields(["locals"])),
    "namespaces": ("namespaces", _swap_function_fields(["namespace"])),
    "data": ("defined data and data symbols (names, types)", _swap_keys("data")),
    "labels": ("code labels and other labels",
               lambda o, g: (_swap_keys("labels", "code_labels")(o, g), _swap_function_fields(["label"])(o, g))),
    "comments": ("comments", _swap_keys("comments")),
    "external_refs": ("pointer slots with external references (PE imports)", _swap_keys("external_refs")),
    "patches": ("relocated bytes", _swap_keys("patches")),
    "memory": ("memory blocks, EXTERNAL and synthesized memory", _swap_keys("memory", "synthesized_memory")),
    "flow_overrides": ("flow overrides", _swap_keys("flow_overrides")),
    "tracked": ("tracked register values", _swap_keys("tracked")),
}

def _swap_signature(own, ghidra, imports, source=None):
    """Ghidra's signatures for imported functions (thunks and the EXTERNAL
    block) or for the others; with `source`, only those of that signature
    source in Ghidra's database ("!X": all but X)."""
    external = [(int(m["start"], 16), int(m["end"], 16)) for m in ghidra["memory"] if m.get("external")]
    g = _by_entry(ghidra)
    for f in own["functions"]:
        h = g.get(int(f["entry"], 16))
        if h is None:
            continue
        e = int(h["entry"], 16)
        is_import = bool(h.get("thunk_of")) or any(a <= e <= b for a, b in external)
        if is_import != imports:
            continue
        if source is not None:
            src = h.get("signature_source", "DEFAULT")
            if (src == source[1:]) if source.startswith("!") else (src != source):
                continue
        for k in _SIGNATURE:
            if k in h:
                f[k] = h[k]
            else:
                f.pop(k, None)


def main_own(args) -> int:
    """Revkit's own inputs, then each kind swapped for Ghidra's."""
    tmp = tempfile.mkdtemp(prefix="revkit-ablation-own-")
    results = {}
    try:
        base_out = os.path.join(tmp, "out")
        agree, total = run("own", base_out, args, extra=("--dump-inputs",))
        results["(own)"] = {"agree": agree, "total": total}
        print("%-20s %6d / %d  %6.2f%%" % ("(revkit's inputs)", agree, total, 100.0 * agree / total), flush=True)
        own_docs = {}
        for dirpath, _, files in os.walk(base_out):
            for name in files:
                if name.startswith("_") and name.endswith(".inputs.json"):
                    rel = os.path.join(os.path.relpath(dirpath, base_out), name[1:-len(".inputs.json")])
                    own_docs[os.path.normpath(rel)] = os.path.join(dirpath, name)
        for kind in args.only or SWAPS:
            desc, edit = SWAPS[kind]
            src = os.path.join(tmp, "inputs-" + kind)
            for rel, path in own_docs.items():
                with open(path) as f:
                    doc = json.load(f)
                with open(os.path.join(args.inputs, rel + ".json")) as f:
                    ghidra = json.load(f)
                edit(doc, ghidra)
                if kind.startswith("signatures") or kind in ("data", "locals", "external_refs"):
                    doc["types"] = ghidra.get("types", []) + doc.get("types", [])
                os.makedirs(os.path.dirname(os.path.join(src, rel)), exist_ok=True)
                with open(os.path.join(src, rel + ".json"), "w") as f:
                    json.dump(doc, f)
            examples: list = []
            a, t = run(src, os.path.join(tmp, "out-" + kind), args, examples)
            shutil.rmtree(src)
            results[kind] = {"agree": a, "total": t, "gain": a - agree, "description": desc, "examples": examples}
            print("%-20s %6d / %d  %6.2f%%  +%d  %s" % ("with Ghidra's " + kind, a, t, 100.0 * a / t, a - agree, desc),
                  flush=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=1, sort_keys=True)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inputs", default=os.path.join(ROOT, "out", "ghidra-db"))
    ap.add_argument("--ref", default=os.path.join(ROOT, "out", "ref"))
    ap.add_argument("--rk-lift", default=os.path.join(ROOT, "build", "tools", "rk-lift", "rk-lift"))
    ap.add_argument("-P", "--procs", type=int, default=16)
    ap.add_argument("--only", action="append", choices=sorted(set(ABLATIONS) | set(SWAPS)))
    ap.add_argument("--own", action="store_true",
                    help="start from revkit's own inputs and swap in Ghidra's, one kind at a time")
    ap.add_argument("--json")
    ap.add_argument("--examples", type=int, default=3, help="example mismatches kept per kind")
    args = ap.parse_args()
    if args.own:
        return main_own(args)

    tmp = tempfile.mkdtemp(prefix="revkit-ablation-")
    results = {}
    try:
        agree, total = run(args.inputs, os.path.join(tmp, "out"), args)
        results["(none)"] = {"agree": agree, "total": total}
        print("%-20s %6d / %d  %6.2f%%" % ("(all inputs)", agree, total, 100.0 * agree / total), flush=True)
        for kind in args.only or ABLATIONS:
            desc, edit = ABLATIONS[kind]
            src = os.path.join(tmp, "inputs-" + kind)
            for dirpath, _, files in os.walk(args.inputs):
                for name in files:
                    if not name.endswith(".json") or name.startswith("_"):
                        continue
                    rel = os.path.relpath(os.path.join(dirpath, name), args.inputs)
                    with open(os.path.join(dirpath, name)) as f:
                        doc = json.load(f)
                    for fn in doc["functions"]:
                        fn.pop("decompiled_c", None)
                    edit(doc)
                    os.makedirs(os.path.dirname(os.path.join(src, rel)), exist_ok=True)
                    with open(os.path.join(src, rel), "w") as f:
                        json.dump(doc, f)
            examples: list = []
            a, t = run(src, os.path.join(tmp, "out-" + kind), args, examples)
            shutil.rmtree(src)
            results[kind] = {"agree": a, "total": t, "lost": agree - a, "description": desc, "examples": examples}
            print("%-20s %6d / %d  %6.2f%%  -%d  %s" % ("without " + kind, a, t, 100.0 * a / t, agree - a, desc),
                  flush=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
