#!/usr/bin/env python3
"""Compare reference JSON files (docs/reference-format.md).

  refdiff.py REF CAND                 # two files, or two directories of them
  refdiff.py REF CAND --baseline B    # exit 1 if any rate dropped below B's
  refdiff.py REF CAND --save-baseline B
  refdiff.py REF CAND --require functions=1.0 --require pcode=0.99

REF is the reference (usually Ghidra's export), CAND the candidate (usually
revkit's). Per category, agreement = items that match / items in either side
(union), so missing and extra items both count against it:

  binaries      files present on both sides (directory mode)
  memory        memory blocks, keyed by (space, start); match = identical entry
  functions     function entry points present on both sides
  names         function name equal
  bodies        function body ranges equal
  prototypes    prototype string equal
  decompiled_c  decompiled C equal (exact, or whitespace-collapsed with --loose-c)
  c_tokens      decompiled C, same tokens (comments included) ignoring whitespace
  c_ast         decompiled C, same tokens without comments: structurally
                identical C (same syntax tree) modulo whitespace
  c_alpha       c_ast with local variable and parameter names normalized
                (secondary, variable-name-insensitive; see cnorm.py)
  instructions  instruction at the same address with equal len, mnemonic, text
  pcode         instruction p-code equal after renumbering `unique` offsets
  pcode_shared  the same, over the addresses both sides have an instruction at
                (identity where both lift; pcode also counts coverage)

With --common-functions, the per-function categories (names, bodies,
prototypes and the C categories) count only functions both sides have
(matched by entry address); `functions` still measures the overlap of the
two function sets. Use it when the candidate finds its own functions.

Exit status: 0 ok, 1 regression / requirement failed, 2 bad input.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
from collections import OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cnorm  # noqa: E402
import refformat  # noqa: E402

CATEGORIES = ["binaries", "memory", "functions", "names", "bodies", "prototypes",
              "decompiled_c", "c_tokens", "c_ast", "c_alpha", "instructions", "pcode", "pcode_shared"]
_C_MODES = {"c_tokens": "tokens", "c_ast": "ast", "c_alpha": "alpha"}
_MISSING = object()


class Tally:
    """agree/total counters per category, plus a few example mismatches."""

    def __init__(self, max_examples: int = 0):
        self.counts = OrderedDict((c, [0, 0]) for c in CATEGORIES)
        self.examples: dict[str, list] = {c: [] for c in CATEGORIES}
        self.max_examples = max_examples

    def add(self, cat: str, ok: bool, example=None):
        c = self.counts[cat]
        c[1] += 1
        if ok:
            c[0] += 1
        elif example is not None and len(self.examples[cat]) < self.max_examples:
            self.examples[cat].append(example)

    def merge(self, other: "Tally"):
        for cat, (a, t) in other.counts.items():
            self.counts[cat][0] += a
            self.counts[cat][1] += t
            room = self.max_examples - len(self.examples[cat])
            if room > 0:
                self.examples[cat].extend(other.examples[cat][:room])

    def rate(self, cat: str):
        a, t = self.counts[cat]
        return None if t == 0 else a / t

    def to_json(self) -> dict:
        return {cat: {"agree": a, "total": t, "rate": None if t == 0 else round(a / t, 6)}
                for cat, (a, t) in self.counts.items()}


def _space_key(item: dict, field: str):
    return (item.get("space", ""), refformat.addr_key(item[field]))


def _index(items, field):
    return {_space_key(it, field): it for it in items or []}


def _fmt_key(key) -> str:
    space, off = key
    return ("%s:" % space if space else "") + "0x%x" % off


_WS = re.compile(r"\s+")


def compare_docs(ref: dict, cand: dict, *, loose_c: bool = False, max_examples: int = 0,
                 label: str = "", only=None, common: bool = False) -> Tally:
    t = Tally(max_examples)
    where = (label + " ") if label else ""

    def want(cat):
        return only is None or cat in only

    # memory
    rm, cm = _index(ref.get("memory"), "start"), _index(cand.get("memory"), "start")
    for key in sorted(set(rm) | set(cm)) if want("memory") else ():
        a, b = rm.get(key), cm.get(key)
        t.add("memory", a == b, (where + _fmt_key(key), a, b))

    # functions and their attributes
    rf, cf = _index(ref.get("functions"), "entry"), _index(cand.get("functions"), "entry")
    for key in sorted(set(rf) | set(cf)):
        a, b = rf.get(key), cf.get(key)
        k = where + _fmt_key(key)
        both = a is not None and b is not None
        if want("functions"):
            t.add("functions", both, (k, a and a.get("name"), b and b.get("name")))
        if common and not both:
            continue
        for cat, field in (("names", "name"), ("bodies", "body"), ("prototypes", "prototype"),
                           ("decompiled_c", "decompiled_c"), ("c_tokens", "decompiled_c"),
                           ("c_ast", "decompiled_c"), ("c_alpha", "decompiled_c")):
            if not want(cat):
                continue
            va = a.get(field, _MISSING) if a is not None else _MISSING
            vb = b.get(field, _MISSING) if b is not None else _MISSING
            if cat == "decompiled_c" and loose_c:
                va = _WS.sub(" ", va).strip() if isinstance(va, str) else va
                vb = _WS.sub(" ", vb).strip() if isinstance(vb, str) else vb
            if cat in _C_MODES:
                ok = both and cnorm.normalize(va if va is not _MISSING else None, _C_MODES[cat]) == \
                    cnorm.normalize(vb if vb is not _MISSING else None, _C_MODES[cat])
            else:
                ok = both and va == vb
            t.add(cat, ok, (k, None if va is _MISSING else va, None if vb is _MISSING else vb))

    # instructions and p-code
    ri, ci = _index(ref.get("instructions"), "addr"), _index(cand.get("instructions"), "addr")
    for key in sorted(set(ri) | set(ci)) if (want("instructions") or want("pcode") or want("pcode_shared")) else ():
        a, b = ri.get(key), ci.get(key)
        k = where + _fmt_key(key)
        both = a is not None and b is not None
        sig_a = a and (a.get("len"), a.get("mnemonic"), a.get("text"))
        sig_b = b and (b.get("len"), b.get("mnemonic"), b.get("text"))
        if want("instructions"):
            t.add("instructions", both and sig_a == sig_b, (k, sig_a, sig_b))
        if not (want("pcode") or want("pcode_shared")):
            continue
        if both:
            pa = refformat.normalize_pcode(a.get("pcode", []))
            pb = refformat.normalize_pcode(b.get("pcode", []))
            for cat in ("pcode", "pcode_shared"):
                if want(cat):
                    t.add(cat, pa == pb, (k, _pcode_text(a), _pcode_text(b)))
        elif want("pcode"):
            t.add("pcode", False, (k, a and _pcode_text(a), b and _pcode_text(b)))
    return t


def _pcode_text(insn: dict) -> str:
    def vn(v):
        return "-" if v is None else "(%s,%s,%d)" % tuple(v)
    ops = ["%s = %s %s" % (vn(op.get("out")), op["op"], " ".join(vn(v) for v in op.get("in", [])))
           for op in insn.get("pcode", [])]
    return "%s: %s" % (insn.get("text"), "; ".join(ops))


# --------------------------------------------------------------------------

def _compare_pair(args):
    """Compare one file pair. A missing side (path None) compares as an empty
    document, so everything on the other side counts as disagreement."""
    rel, ref_path, cand_path, loose_c, max_examples, only, common = args
    ref = refformat.load(ref_path) if ref_path else {}
    cand = refformat.load(cand_path) if cand_path else {}
    warn = None
    if ref_path is None or cand_path is None:
        warn = "%s: missing from %s" % (rel, "reference" if ref_path is None else "candidate")
    sa, sb = ref.get("binary", {}).get("sha256"), cand.get("binary", {}).get("sha256")
    if sa and sb and sa != sb:
        warn = "%s: binary sha256 differs (%s vs %s): comparing different binaries" % (rel, sa[:12], sb[:12])
    tally = compare_docs(ref, cand, loose_c=loose_c, max_examples=max_examples, label=rel, only=only,
                         common=common)
    present = ref_path is not None and cand_path is not None
    tally.add("binaries", present, (rel, ref_path, cand_path))
    return rel, tally, warn


def compare_paths(ref: str, cand: str, *, loose_c=False, max_examples=0, jobs=0, only=None, common=False):
    """Returns (total Tally, {rel: Tally}, warnings)."""
    if os.path.isdir(ref) != os.path.isdir(cand):
        raise ValueError("compare two files or two directories, not one of each")
    if not os.path.isdir(ref):
        rel, tally, warn = _compare_pair((os.path.basename(ref), ref, cand, loose_c, max_examples, only, common))
        return tally, {rel: tally}, [warn] if warn else []

    rfiles, cfiles = refformat.find_reference_files(ref), refformat.find_reference_files(cand)
    if not rfiles and not cfiles:
        raise ValueError("no reference files in %s or %s" % (ref, cand))
    total = Tally(max_examples)
    per: dict[str, Tally] = {}
    warnings = []
    pairs = [(rel, rfiles.get(rel), cfiles.get(rel), loose_c, max_examples, only, common)
             for rel in sorted(set(rfiles) | set(cfiles))]
    workers = jobs or min(len(pairs), os.cpu_count() or 4, 16)
    if workers > 1:
        with concurrent.futures.ProcessPoolExecutor(workers) as pool:
            results = list(pool.map(_compare_pair, pairs))
    else:
        results = [_compare_pair(p) for p in pairs]
    for rel, tally, warn in results:
        per[rel] = tally
        total.merge(tally)
        if warn:
            warnings.append(warn)
    return total, dict(sorted(per.items())), warnings


# --------------------------------------------------------------------------

def _pct(rate) -> str:
    return "     n/a" if rate is None else "%7.2f%%" % (100 * rate)


def _group(rel: str, depth: int) -> str:
    return "/".join(rel.split("/")[:depth])


def _variant(rel: str) -> str:
    parts = rel.split("/")
    return parts[2] if len(parts) > 3 else "-"


def print_summary(total: Tally, per: dict, out=None, by_group=False, per_binary=False, group_depth=1,
                  only=None, by_variant=False):
    out = out or sys.stdout
    shown = [c for c in CATEGORIES[1:] if only is None or c in only]
    if per_binary:
        cats = shown
        out.write("%-48s %s\n" % ("binary", " ".join("%8s" % c[:8] for c in cats)))
        for rel, t in per.items():
            out.write("%-48s %s\n" % (rel[-48:], " ".join(_pct(t.rate(c)) for c in cats)))
        out.write("\n")
    if by_group:
        groups: dict[str, Tally] = {}
        for rel, t in per.items():
            groups.setdefault(_group(rel, group_depth), Tally()).merge(t)
        cats = shown
        out.write("%-24s %s\n" % ("group", " ".join("%8s" % c[:8] for c in cats)))
        for g, t in sorted(groups.items()):
            out.write("%-24s %s\n" % (g, " ".join(_pct(t.rate(c)) for c in cats)))
        if by_variant:
            variants: dict[str, Tally] = {}
            for rel, t in per.items():
                variants.setdefault(_variant(rel), Tally()).merge(t)
            for g, t in sorted(variants.items()):
                out.write("%-24s %s\n" % ("(" + g + ")", " ".join(_pct(t.rate(c)) for c in cats)))
        out.write("\n")
    out.write("%-14s %10s %10s %9s\n" % ("category", "agree", "total", "rate"))
    for cat, (a, t) in total.counts.items():
        if only is None or cat in only or cat == "binaries":
            out.write("%-14s %10d %10d %s\n" % (cat, a, t, _pct(total.rate(cat))))


def print_examples(total: Tally, out=None, width=300):
    out = out or sys.stdout
    for cat in CATEGORIES:
        ex = total.examples[cat]
        if not ex:
            continue
        out.write("\n== %s mismatches (first %d) ==\n" % (cat, len(ex)))
        for key, a, b in ex:
            if cat in _C_MODES and isinstance(a, str) and isinstance(b, str):
                a, b = cnorm.first_difference(a, b, _C_MODES[cat])  # where the tokens part
            out.write("%s\n  ref : %s\n  cand: %s\n" % (key, _short(a, width), _short(b, width)))


def _short(v, width):
    s = v if isinstance(v, str) else json.dumps(v, sort_keys=True)
    s = s.replace("\n", "\\n")
    return s if len(s) <= width else s[:width] + "..."


def baseline_doc(total: Tally, per: dict) -> dict:
    return {
        "refdiff_baseline": 1,
        "total": total.to_json(),
        "binaries": {rel: {c: v["rate"] for c, v in t.to_json().items() if v["rate"] is not None}
                     for rel, t in per.items()},
    }


# Baselines store rates rounded (see Tally.to_json), so compare at that precision;
# otherwise a run identical to the one that wrote the baseline reads as a regression.
_BASELINE_DIGITS = 6


def _below(new, old, tolerance) -> bool:
    return new is None or round(new, _BASELINE_DIGITS) < old - tolerance


def check_baseline(baseline: dict, total: Tally, per: dict, tolerance: float) -> list[str]:
    """Regressions: any category rate (overall or per binary) below the baseline's."""
    problems = []
    for cat, v in baseline.get("total", {}).items():
        old, new = v.get("rate"), total.rate(cat) if cat in total.counts else None
        if old is not None and _below(new, old, tolerance):
            problems.append("total %s: %s -> %s" % (cat, _pct(old).strip(), _pct(new).strip()))
    for rel, cats in baseline.get("binaries", {}).items():
        t = per.get(rel)
        for cat, old in cats.items():
            new = t.rate(cat) if t is not None and cat in t.counts else None
            if _below(new, old, tolerance):
                problems.append("%s %s: %s -> %s" % (rel, cat, _pct(old).strip(), _pct(new).strip()))
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ref", help="reference file or directory (e.g. Ghidra export)")
    ap.add_argument("cand", help="candidate file or directory (e.g. revkit output)")
    ap.add_argument("--baseline", help="fail if any rate is below this saved baseline")
    ap.add_argument("--save-baseline", metavar="FILE", help="write this run's rates as a baseline")
    ap.add_argument("--tolerance", type=float, default=0.0, help="allowed drop vs baseline (fraction, default 0)")
    ap.add_argument("--require", action="append", default=[], metavar="CAT=RATE",
                    help="fail unless overall CAT rate >= RATE (e.g. pcode=0.99); repeatable")
    ap.add_argument("--details", type=int, default=0, metavar="N", help="print N example mismatches per category")
    ap.add_argument("--loose-c", action="store_true", help="collapse whitespace before comparing decompiled C")
    ap.add_argument("--by-group", action="store_true", help="also print rates per top-level dir (e.g. elf-x86_64)")
    ap.add_argument("--group-depth", type=int, default=1, metavar="N",
                    help="--by-group groups by the first N path components (2: elf-x86_64/gcc-O2)")
    ap.add_argument("--only", metavar="CATS",
                    help="compare only these comma-separated categories (e.g. c_ast,c_alpha)")
    ap.add_argument("--per-binary", action="store_true", help="also print rates per binary")
    ap.add_argument("--common-functions", action="store_true",
                    help="compare function attributes and C only on functions both sides have; "
                         "'functions' still reports the overlap")
    ap.add_argument("--by-variant", action="store_true",
                    help="with --by-group, also print totals per build variant (the third path "
                         "component: debug, stripped)")
    ap.add_argument("--json", metavar="FILE", help="write the full result as JSON")
    ap.add_argument("-j", "--jobs", type=int, default=0)
    args = ap.parse_args(argv)

    only = None
    if args.only:
        only = set(c.strip() for c in args.only.split(",") if c.strip())
        unknown = only - set(CATEGORIES)
        if unknown:
            print("refdiff: unknown categories: %s" % ", ".join(sorted(unknown)), file=sys.stderr)
            return 2
        only.add("binaries")
    try:
        total, per, warnings = compare_paths(args.ref, args.cand, loose_c=args.loose_c,
                                             max_examples=args.details, jobs=args.jobs, only=only,
                                             common=args.common_functions)
    except (OSError, ValueError) as e:
        print("refdiff: %s" % e, file=sys.stderr)
        return 2
    for w in warnings:
        print("warning: " + w, file=sys.stderr)
    print_summary(total, per, by_group=args.by_group, per_binary=args.per_binary,
                  group_depth=args.group_depth, only=only, by_variant=args.by_variant)
    if args.details:
        print_examples(total)

    failed = []
    for req in args.require:
        cat, _, val = req.partition("=")
        if cat not in total.counts:
            print("refdiff: unknown category %r" % cat, file=sys.stderr)
            return 2
        rate = total.rate(cat)
        if rate is None or rate < float(val):
            failed.append("required %s >= %s, got %s" % (cat, val, _pct(rate).strip()))
    if args.baseline:
        with open(args.baseline) as f:
            failed += ["regression: " + p for p in check_baseline(json.load(f), total, per, args.tolerance)]
    doc = baseline_doc(total, per)
    if args.save_baseline:
        with open(args.save_baseline, "w") as f:
            json.dump(doc, f, indent=1, sort_keys=True)
            f.write("\n")
    if args.json:
        doc["warnings"] = warnings
        doc["failures"] = failed
        with open(args.json, "w") as f:
            json.dump(doc, f, indent=1, sort_keys=True)
            f.write("\n")
    if failed:
        print("\nFAIL (%d):" % len(failed))
        for msg in failed[:50]:
            print("  " + msg)
        if len(failed) > 50:
            print("  ... and %d more" % (len(failed) - 50))
        return 1
    print("\nOK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
