#!/usr/bin/env python3
"""Scores revkit on a raw firmware image against Ghidra (scripts/bench-firmware.sh).

Ghidra is only the yardstick: nothing from it reaches revkit. Its side is
read from files in the benchmarks directory (outside the repository):

  <name>-ghidra-functions.json  {"functions": [{"address": "0001a2b0", "name": ...}]}
                                the user's Ghidra function list (required)
  <name>-ghidra-disasm.json     {"<address>": {"instructions": [{"address": ...}]}}
                                every function's disassembly (listing coverage)
  <name>-ghidra-c.json          {"0x1a2b0": "C text" | null}: Ghidra's decompiled C
                                for the sample (the user's, through ghidra-mcp)
  <name>-ghidra-headless.json   Ghidra's default analysis of the same image
                                (bench_firmware_ghidra.py): a second function
                                list, and C when <name>-ghidra-c.json can't be had

revkit runs from scratch: rk-lift --raw --analyze (functions, instructions),
then rk-lift --decompile-only for a sample of functions both sides have
(stratified by size, deterministic). C is compared token by token after
normalization (tools/refdiff/cnorm.py): ast and alpha as refdiff has them,
and two structural levels, since Ghidra's output carries the user's names
and types: shape (identifiers, casts and declarations abstracted) and flow
(the control-flow skeleton).
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools", "refdiff"))
import cnorm  # noqa: E402

KEYWORDS = cnorm._KEYWORDS
FLOW = {"if", "else", "while", "do", "for", "switch", "case", "default", "return", "goto", "break", "continue", "{", "}"}


def body_tokens(text: str):
    """The function's statements as tokens: the signature and the block of
    local declarations dropped, comments dropped."""
    lines = text.split("\n")
    brace = next((i for i, l in enumerate(lines) if l.strip() == "{"), None)
    if brace is None:
        return [t for k, t in cnorm.tokenize(text) if k != "comment"]
    i = brace + 1
    # Ghidra prints one declaration per line, then a blank line.
    while i < len(lines) and lines[i].strip() and lines[i].rstrip().endswith(";") and "(" not in lines[i] \
            and "=" not in lines[i]:
        i += 1
    return [(k, t) for k, t in cnorm.tokenize("\n".join(lines[i:])) if k != "comment"]


TYPEISH = re.compile(r"^(u?int\d*|u?char|u?short|u?long|undefined\d*|bool|byte|code|ulonglong|longlong|float|double|void|"
                     r"struct|union|enum|const|volatile|unsigned|signed|char|int|long|short|\w+_t)$")


def _cast_end(toks, i):
    """If toks[i] opens a cast, the index after its ')'; else None."""
    if toks[i][1] != "(":
        return None
    j = i + 1
    inner = []
    while j < len(toks) and (toks[j][0] == "ident" or toks[j][1] == "*"):
        inner.append(toks[j][1])
        j += 1
    if not inner or j + 1 >= len(toks) or toks[j][1] != ")":
        return None
    nxt = toks[j + 1]
    operand = nxt[0] in ("ident", "number", "string", "char") or nxt[1] in ("(", "*", "&", "~", "!")
    if operand and (inner[-1] == "*" and inner[0] != "*" or (len(inner) <= 2 and all(TYPEISH.match(t) for t in inner))):
        return j + 1
    return None


def shape(text: str):
    """Identifiers (variables, functions, globals, types, fields) become
    `id`, casts disappear: what's left is the statements' structure,
    operators and constants."""
    toks = body_tokens(text)
    out = []
    i = 0
    while i < len(toks):
        end = _cast_end(toks, i)
        if end is not None:
            i = end
            continue
        k, t = toks[i]
        # Namespaced names (Ghidra's switchD_...::caseD_x labels): one id.
        if k == "ident" and i + 2 < len(toks) and toks[i + 1][1] == "::" and toks[i + 2][0] == "ident":
            out.append("id")
            i += 3
            continue
        if k == "ident" and t not in KEYWORDS:
            out.append("id")
        elif k == "string":
            out.append("str")
        else:
            out.append(t)
        i += 1
    return tuple(out)


def flow(text: str):
    return tuple(t for t in shape(text) if t in FLOW)


def first_difference(a, b, context=8):
    i = 0
    while i < len(a) and i < len(b) and a[i] == b[i]:
        i += 1
    lo = max(0, i - context)
    return " ".join(a[lo:i + context]), " ".join(b[lo:i + context])


def categorize(gc: str, rc: str, splits=frozenset()) -> str:
    """Why two functions' C differs, judged from the first difference.
    `splits`: names of functions revkit has that Ghidra doesn't."""
    if gc is None:
        return "ghidra failed"
    if rc is None:
        return "revkit failed"
    called = set(re.findall(r"\b(FUN_[0-9a-f]{8})\s*\(", rc)) - set(re.findall(r"\b(FUN_[0-9a-f]{8})\b", gc))
    if called & splits:
        return "boundaries: revkit calls a function Ghidra keeps inside this one"
    gs, rs = shape(gc), shape(rc)
    gf, rf = flow(gc), flow(rc)
    def sig(t):
        lines = [l for l in t.split("\n") if l.strip() and not l.strip().startswith(("/*", "*"))]
        return lines[0] if lines else ""
    g_params = sig(gc).count(",") + (0 if "(void)" in sig(gc) else 1)
    r_params = sig(rc).count(",") + (0 if "(void)" in sig(rc) else 1)
    if gf != rf:
        if "switch" in gf and "switch" not in rf:
            return "control flow: switch only in Ghidra"
        if "switch" in rf and "switch" not in gf:
            return "control flow: switch only in revkit"
        if gf.count("return") != rf.count("return"):
            return "control flow: returns differ (no-return calls, tail calls)"
        if ("while" in gf or "do" in gf) != ("while" in rf or "do" in rf):
            return "control flow: loop structure"
        return "control flow: other"
    if gs == rs:
        if g_params != r_params:
            return "same structure; signature differs (parameter count)"
        return "same structure; names, types or casts differ"
    if g_params != r_params:
        return "parameter count (callee or own signature) changes expressions"
    a, b = first_difference(gs, rs)
    if len(gs) != len(rs):
        return "statements differ (data types, struct fields, folding)"
    return "expressions differ (constants, operators)"


def run(cmd, **kw):
    t = time.time()
    r = subprocess.run(cmd, **kw)
    return r, time.time() - t


def raw_layout(raw_args):
    """The image's address and the header bytes before it, from rk-lift's flags."""
    base = offset = 0
    for flag, value in zip(raw_args, raw_args[1:]):
        if flag == "--base":
            base = int(value, 0)
        elif flag == "--raw-offset":
            offset = int(value, 0)
    return base, offset


def elf_image(data, image_base):
    """An ELF's loaded segments as one flat buffer from `image_base` (revkit's
    and Ghidra's address for the lowest segment), for looking at bytes by
    address. Returns (buffer, base)."""
    import struct
    is64 = data[4] == 2
    le = data[5] == 1
    e = "<" if le else ">"
    if is64:
        phoff, = struct.unpack_from(e + "Q", data, 0x20)
        phentsize, phnum = struct.unpack_from(e + "HH", data, 0x36)
    else:
        phoff, = struct.unpack_from(e + "I", data, 0x1c)
        phentsize, phnum = struct.unpack_from(e + "HH", data, 0x2a)
    segs = []
    for i in range(phnum):
        o = phoff + i * phentsize
        if is64:
            ptype, _, off, vaddr, _, filesz, memsz = struct.unpack_from(e + "IIQQQQQ", data, o)
        else:
            ptype, off, vaddr, _, filesz, memsz = struct.unpack_from(e + "IIIIII", data, o)
        if ptype == 1:
            segs.append((vaddr, off, filesz, memsz))
    lo = min(v for v, _, _, _ in segs)
    bias = image_base - lo if image_base is not None and image_base >= lo else 0
    top = max(v + m for v, _, _, m in segs)
    buf = bytearray(top - lo)
    for v, off, filesz, _ in segs:
        buf[v - lo:v - lo + filesz] = data[off:off + filesz]
    return bytes(buf), lo + bias


def failures(c_by_entry):
    """Counts over decompiled C: functions that didn't decompile, whose C
    halts on bad data (halt_baddata: flow ran into bytes that don't
    decode), and whose C carries a bad-instruction warning."""
    texts = list(c_by_entry.values())
    return {"functions": len(texts),
            "failed": sum(1 for t in texts if t is None),
            "halt_baddata": sum(1 for t in texts if t and "halt_baddata" in t),
            "bad_instruction_warning": sum(1 for t in texts if t and "Bad instruction" in t)}


def text_at(image, at, minimum=4):
    """Whether printable ASCII (tab, CR, LF too) runs through `at`: at least
    `minimum` characters from the start of the run to a NUL or the run's end."""
    if at < 0 or at >= len(image):
        return False
    printable = lambda c: 0x20 <= c < 0x7f or c in (9, 10, 13)
    if not printable(image[at]):
        return False
    lo = at
    while lo > 0 and printable(image[lo - 1]) and at - lo < 256:
        lo -= 1
    hi = at
    while hi < len(image) and printable(image[hi]) and hi - at < 256:
        hi += 1
    return hi - lo >= minimum


class Listing:
    """Instructions as sorted (address, length) for 'which instruction covers a'."""

    def __init__(self, items):
        import bisect
        self._bisect = bisect
        self.items = sorted(items)
        self.starts = [a for a, _ in self.items]

    def covering(self, a):
        i = self._bisect.bisect_right(self.starts, a) - 1
        if i >= 0 and self.items[i][0] <= a < self.items[i][0] + self.items[i][1]:
            return self.items[i][0]
        return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--firmware", required=True)
    ap.add_argument("--name", default="firmware")
    ap.add_argument("--bench", default=os.environ.get("RK_FW_BENCH", os.path.expanduser("~/revkit-bench")))
    ap.add_argument("--rk-lift", default=os.path.join(HERE, "..", "build", "tools", "rk-lift", "rk-lift"))
    ap.add_argument("--raw-args", default="", help="rk-lift's raw layout flags, one string (none: an ELF)")
    ap.add_argument("--sample", type=int, default=200)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--out", help="where revkit's outputs go (default: <bench>/<name>-revkit-*.json)")
    ap.add_argument("--examples", type=int, default=3, help="examples per difference category")
    ap.add_argument("--report", help="also write the report as JSON here")
    args = ap.parse_args(argv)

    b = lambda suffix: os.path.join(args.bench, f"{args.name}-{suffix}")
    headless = json.load(open(b("ghidra-headless.json"))) if os.path.exists(b("ghidra-headless.json")) else None
    if os.path.exists(b("ghidra-functions.json")):
        gfuncs = json.load(open(b("ghidra-functions.json")))["functions"]
        primary = "user's Ghidra"
    elif headless is not None:
        gfuncs = headless["functions"]
        primary = "Ghidra default analysis"
    else:
        print(f"no {b('ghidra-functions.json')} or {b('ghidra-headless.json')}", file=sys.stderr)
        return 1
    G = {int(f["address"], 16): f["name"] for f in gfuncs}
    out = args.out or args.bench
    os.makedirs(out, exist_ok=True)
    rk_json = os.path.join(out, f"{args.name}-revkit-analyze.json")
    raw = args.raw_args.split()
    r, secs = run([args.rk_lift, *raw, "--analyze", "-j", str(args.jobs), "-o", rk_json, args.firmware])
    if r.returncode != 0:
        print("rk-lift failed", file=sys.stderr)
        return 1
    rk = json.load(open(rk_json))
    R = {int(f["entry"], 16): f for f in rk["functions"]}
    report = {"reference": primary, "revkit_seconds": round(secs, 2)}
    base, offset = raw_layout(raw)
    with open(args.firmware, "rb") as f:
        image = f.read()[offset:]
    if "--raw" not in raw and image[:4] == b"\x7fELF":
        # An ELF, loaded by its program headers. Ghidra's functions outside
        # them (its EXTERNAL block's import thunks) aren't code.
        ib = rk.get("binary", {}).get("image_base")
        image, base = elf_image(image, int(ib, 16) if ib else None)
        inside = lambda a: base <= a < base + len(image)
        for k in [a for a in G if not inside(a)]:
            del G[k]
        gfuncs = [f for f in gfuncs if inside(int(f["address"], 16))]
        if headless is not None:
            headless["functions"] = [f for f in headless["functions"] if inside(int(f["address"], 16))]

    def score(label, ref):
        common = len(set(R) & set(ref))
        row = {"ghidra": len(ref), "revkit": len(R), "common": common,
               "recall": round(100 * common / max(1, len(ref)), 2), "precision": round(100 * common / max(1, len(R)), 2)}
        report[label] = row
        print(f"functions vs {label}: revkit {len(R)}, ghidra {len(ref)}, common {common}: "
              f"recall {row['recall']}%, precision {row['precision']}%")

    score(primary, G)
    if headless is not None and primary != "Ghidra default analysis":
        H = {int(f["address"], 16) for f in headless["functions"]}
        score("Ghidra default analysis", H)
        hc = len(H & set(G))
        print(f"  (Ghidra's default analysis itself: {len(H)} functions, {hc} of the user's {len(G)}: "
              f"recall {100 * hc / len(G):.1f}%, precision {100 * hc / len(H):.1f}%)")
        report["Ghidra default vs user's"] = {"recall": round(100 * hc / len(G), 2), "precision": round(100 * hc / len(H), 2)}

    # Ghidra's instructions in functions (the user's disassembly, else the
    # headless listing), each with its instruction set where known.
    gi = {}  # address -> (length, thumb or None)
    g_all = None  # Ghidra's whole listing (also code outside functions), headless only
    if os.path.exists(b("ghidra-disasm.json")):
        for v in json.load(open(b("ghidra-disasm.json"))).values():
            for i in v.get("instructions", []):
                gi[int(i["address"], 16)] = (None, None)
    elif headless is not None and "listing" in headless:
        g_all = {a: (n, t) for a, n, t, inside, _ in headless["listing"]}
        gi = {a: (n, t) for a, n, t, inside, _ in headless["listing"] if inside}
    # revkit's: each instruction in a function's body, the function's set.
    r_thumb = []
    for f in rk["functions"]:
        for lo, hi in f["body"]:
            r_thumb.append((int(lo, 16), int(hi, 16), bool(f.get("thumb"))))
    r_thumb.sort()
    import bisect
    r_lo = [lo for lo, _, _ in r_thumb]

    def thumb_of(a):
        i = bisect.bisect_right(r_lo, a) - 1
        return r_thumb[i][2] if i >= 0 and r_thumb[i][0] <= a <= r_thumb[i][1] else None

    ri = {int(i["addr"], 16): i["len"] for i in rk["instructions"]}
    if gi:
        both = set(gi) & set(ri)
        row = {"ghidra": len(gi), "revkit": len(ri), "both": len(both), "revkit_only": len(set(ri) - set(gi)),
               "ghidra_only": len(set(gi) - set(ri)), "agreement": round(100 * len(both) / max(1, len(set(gi) | set(ri))), 2)}
        known = [a for a in both if gi[a][1] is not None]
        if known:
            same = sum(1 for a in known if gi[a][1] == thumb_of(a))
            row["mode_agreement"] = round(100 * same / len(known), 3)
            row["mode_disagreements"] = len(known) - same
        if g_all is not None:
            # revkit's instructions Ghidra decodes too, outside its functions.
            row["revkit_only_in_ghidra_listing"] = sum(1 for a in set(ri) - set(gi) if a in g_all)
        report["listing"] = row
        print(f"listing (instructions in Ghidra's functions vs revkit's): both {len(both)} "
              f"({100 * len(both) / len(gi):.1f}% of Ghidra's; {row['agreement']}% of either's), "
              f"revkit only {row['revkit_only']}, Ghidra only {row['ghidra_only']}"
              + (f"; same instruction set {row['mode_agreement']}% ({row['mode_disagreements']} differ)"
                 if "mode_agreement" in row else ""))

    # Function entries, mode by mode, and what the differences are.
    g_mode = {int(f["address"], 16): f["thumb"] for f in gfuncs if "thumb" in f}
    if g_mode:
        common = [a for a in set(R) & set(G) if a in g_mode]
        differ = [a for a in common if g_mode[a] != bool(R[a].get("thumb"))]
        report["function_modes"] = {"common": len(common), "differ": len(differ),
                                    "ghidra_thumb": sum(g_mode.values()),
                                    "revkit_thumb": sum(1 for f in R.values() if f.get("thumb"))}
        print(f"function modes: {len(differ)} of {len(common)} common entries differ "
              f"(Thumb: Ghidra {report['function_modes']['ghidra_thumb']}, "
              f"revkit {report['function_modes']['revkit_thumb']})")
    if gi:
        g_listing = Listing((a, n or 2) for a, (n, _) in (g_all or gi).items())
        g_in_func = Listing((a, n or 2) for a, (n, _) in gi.items())
        r_listing = Listing(ri.items())
        classes = collections.Counter()
        cases = collections.defaultdict(list)

        def note(cls, a):
            classes[cls] += 1
            if len(cases[cls]) < args.examples:
                cases[cls].append("0x%x" % a)

        for a in sorted(set(R) - set(G)):
            at = g_in_func.covering(a)
            off = a - base
            if at == a:
                note("revkit only: an instruction inside a Ghidra function (split or mid-function entry)", a)
            elif at is not None:
                note("revkit only: inside a Ghidra instruction (offcut)", a)
            elif g_listing.covering(a) is not None:
                note("revkit only: code Ghidra has outside functions", a)
            elif text_at(image, off):
                note("revkit only: text Ghidra leaves as data", a)
            elif 0 <= off < len(image) - 4 and image[off:off + 4] in (b"\0\0\0\0", b"\xff\xff\xff\xff"):
                note("revkit only: zero or erased bytes", a)
            else:
                note("revkit only: bytes Ghidra doesn't decode", a)
        for a in sorted(set(G) - set(R)):
            at = r_listing.covering(a)
            if at == a:
                note("Ghidra only: an instruction inside a revkit function", a)
            elif at is not None:
                note("Ghidra only: inside a revkit instruction (offcut)", a)
            else:
                note("Ghidra only: revkit doesn't decode it", a)
        report["function_differences"] = {k: {"count": v, "examples": cases[k]} for k, v in classes.most_common()}
        for k, v in classes.most_common():
            print(f"  {v:5d}  {k}")

    # Decompile every function revkit has (C for the sample comes from it):
    # what fails or halts on bad data, on both sides.
    rc_json = os.path.join(out, f"{args.name}-revkit-c.json")
    r, csecs = run([args.rk_lift, *raw, "--analyze", "--decompile", "--no-instructions", "-j", str(args.jobs),
                    "-o", rc_json, args.firmware], stderr=subprocess.DEVNULL)
    if r.returncode != 0:
        print("rk-lift --decompile failed", file=sys.stderr)
        return 1
    rc = {int(f["entry"], 16): f.get("decompiled_c") for f in json.load(open(rc_json))["functions"]}
    report["revkit_decompile_seconds"] = round(csecs, 2)
    report["revkit_c"] = failures(rc)
    gc_all = None
    if headless is not None and headless.get("c") and len(headless["c"]) >= len(headless["functions"]):
        gc_all = {int(k, 16): v for k, v in headless["c"].items()}
        report["ghidra_c"] = failures(gc_all)
    print(f"decompiled C, every function: revkit {report['revkit_c']}"
          + (f"; Ghidra {report['ghidra_c']}" if gc_all is not None else ""))

    # The decompile sample, from Ghidra's side alone so it doesn't move
    # with revkit: the reference's functions (that Ghidra's default analysis
    # has too, when its C stands in), stratified by their instruction count
    # in Ghidra's disassembly into five equal strata, evenly spaced in each.
    gsize = {}
    if os.path.exists(b("ghidra-disasm.json")):
        for k, v in json.load(open(b("ghidra-disasm.json"))).items():
            gsize[int(k, 16)] = len(v.get("instructions", []))
    else:
        gsize = {int(f["address"], 16): f.get("size", 0) for f in gfuncs}
    population = set(G)
    if headless is not None:
        population &= {int(f["address"], 16) for f in headless["functions"]}
    ranked = sorted((gsize.get(a, 0), a) for a in population)
    strata = 5
    per = (args.sample + strata - 1) // strata
    sample = []
    for s in range(strata):
        chunk = ranked[len(ranked) * s // strata: len(ranked) * (s + 1) // strata]
        step = max(1, len(chunk) // per)
        sample += [a for _, a in chunk[::step][:per]]
    sample = sorted(sample)
    with open(b("decompile-sample.txt"), "w") as f:
        f.write("\n".join("0x%x" % a for a in sample) + "\n")
    report["decompile_sample_missing_in_revkit"] = sum(1 for a in sample if a not in R)

    gc_path = b("ghidra-c.json")
    source = "user's Ghidra (ghidra-mcp)"
    gc = json.load(open(gc_path)) if os.path.exists(gc_path) else {}
    if not any(gc.get("0x%x" % a) for a in sample):
        hc_path = b("ghidra-headless-c.json")
        gc = json.load(open(hc_path)) if os.path.exists(hc_path) else (headless or {}).get("c", {})
        source = "Ghidra's default analysis (headless, same memory map)"
    if not any(gc.get("0x%x" % a) for a in sample):
        print(f"no Ghidra C for the sample: fetch it (see bench-firmware.sh), sample in {b('decompile-sample.txt')}")
        if args.report:
            json.dump(report, open(args.report, "w"), indent=1)
        return 0

    # A function revkit doesn't have can't match.
    splits = frozenset("FUN_%08x" % a for a in set(R) - set(G))
    tally = collections.Counter()
    cats = collections.Counter()
    examples = collections.defaultdict(list)
    n = 0
    for a in sample:
        g = gc.get("0x%x" % a)
        if g is None and "0x%x" % a not in gc:
            continue
        n += 1
        c = rc.get(a)
        if g is not None and c is not None:
            for mode in ("ast", "alpha"):
                tally[mode] += cnorm.normalize(g, mode) == cnorm.normalize(c, mode)
            tally["shape"] += shape(g) == shape(c)
            tally["flow"] += flow(g) == flow(c)
        elif g is None and c is None:
            for mode in ("ast", "alpha", "shape", "flow"):
                tally[mode] += 1
        if g is not None and c is not None and shape(g) == shape(c):
            continue
        cat = categorize(g, c, splits) if a in rc else "revkit has no function at this entry"
        cats[cat] += 1
        if len(examples[cat]) < args.examples:
            ga, ra = first_difference(shape(g), shape(c)) if g and c else ("", "")
            examples[cat].append({"function": "0x%x" % a, "ghidra": ga, "revkit": ra})
    sample_c = {a: rc.get(a) for a in sample if a in rc}
    report["decompile"] = {"source": source, "functions": n, **{m: round(100 * tally[m] / max(1, n), 1) for m in
                                                                  ("ast", "alpha", "shape", "flow")},
                           "revkit_failures": failures(sample_c),
                           "ghidra_failures": failures({a: gc.get("0x%x" % a) for a in sample if "0x%x" % a in gc}),
                           "categories": dict(cats.most_common()), "examples": examples}
    print(f"decompiled C vs {source}: {n} functions; identical ast {report['decompile']['ast']}%, "
          f"alpha {report['decompile']['alpha']}%, shape {report['decompile']['shape']}%, "
          f"flow {report['decompile']['flow']}%")
    for cat, k in cats.most_common():
        print(f"  {k:4d}  {cat}")
        for e in examples[cat]:
            print(f"        {e['function']}: ghidra  {e['ghidra'][:150]}")
            print(f"        {' ' * len(e['function'])}  revkit  {e['revkit'][:150]}")
    if args.report:
        json.dump(report, open(args.report, "w"), indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
