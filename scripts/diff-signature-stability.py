#!/usr/bin/env python3
"""BSim signature stability with revkit's own signatures (docs/diff.md).

The design's measurement (docs/diff/design.md §0, scripts/diff-bsim-stability.py)
recomputed with revkit's F5: rk-lift --analyze --signatures on each debug
build (revkit's discovery and inputs, the signature profile: no names,
types or prototypes), compared with revkit's C++ BSim comparison
(rk-sigdiff stability). Names from the debug builds are the truth; on
firmware images (raw, no symbols) the truth is the DWARF function list of
the matching ELF (out/firmware-corpus/*.truth.json).

  diff-signature-stability.py [--out DIR] [--variant NAME:RK-LIFT-ARGS] [--weights auto|FILE]
                              [--idf lopo|corpus|FILE.xml,FILE32.xml] [--ghidra DIR]
                              [--families b,c,d,e,design] [--heldout] [-j N]

--idf re-derives BSim's idf lookup from revkit's own vectors (rk-sigdiff
derive-idf, design §7 M4): "lopo" evaluates each program with a table
derived from the other tuning programs (the firmware's 32-bit table from
the u-boot images, which no pair uses), "corpus" derives one table from
every tuning binary (what would ship; DIR/idf-*.xml), FILE.xml,FILE32.xml
uses given 64- and 32-bit tables.

Writes DIR/<variant>/<binary>.json (signatures), DIR/pairs-<variant>.jsonl
(one rk-sigdiff line per pair, with Ghidra's on the same pair where
--ghidra has its vectors: scripts/diff-bsim-reference.py dump), and prints
a summary per family. Tuning corpus only, unless --heldout (measure once:
docs/heldout.md).
"""
import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RK_LIFT = os.path.join(ROOT, "build", "tools", "rk-lift", "rk-lift")
RK_SIGDIFF = os.path.join(ROOT, "build", "tools", "rk-sigdiff", "rk-sigdiff")
FIRMWARE = os.path.join(ROOT, "out", "firmware-corpus")

ARCHES = ["elf-x86_64", "elf-aarch64", "elf-riscv64"]
COMPILERS = ["gcc", "clang"]
OPTS = ["O0", "O2"]

# The design's table (§0), in its order.
DESIGN = [
    ("cjson", "elf-x86_64/gcc-O0", "elf-x86_64/clang-O0"),
    ("cjson", "elf-x86_64/gcc-O2", "elf-aarch64/gcc-O2"),
    ("cjson", "elf-x86_64/gcc-O2", "elf-x86_64/clang-O2"),
    ("cjson", "elf-x86_64/gcc-O0", "elf-x86_64/gcc-O2"),
    ("zlib", "elf-x86_64/gcc-O2", "elf-riscv64/gcc-O2"),
    ("zlib", "elf-x86_64/gcc-O2", "elf-x86_64/clang-O0"),
    ("lua", "elf-x86_64/gcc-O2", "elf-aarch64/clang-O2"),
]


def corpus_configs(corpus, program):
    out = []
    for arch in ARCHES:
        for c in COMPILERS:
            for o in OPTS:
                cfg = "%s/%s-%s" % (arch, c, o)
                if os.path.exists(os.path.join(corpus, arch, "%s-%s" % (c, o), "debug", program)):
                    out.append(cfg)
    return out


def elf_families(corpus, programs):
    """(family, program, cfg_a, cfg_b) for b (-O0/-O2), c (gcc/clang), d (ISAs)."""
    pairs = []
    for p in programs:
        have = set(corpus_configs(corpus, p))
        for arch in ARCHES:
            for c in COMPILERS:
                a, b = "%s/%s-O0" % (arch, c), "%s/%s-O2" % (arch, c)
                if a in have and b in have:
                    pairs.append(("b", p, a, b))
            for o in OPTS:
                a, b = "%s/gcc-%s" % (arch, o), "%s/clang-%s" % (arch, o)
                if a in have and b in have:
                    pairs.append(("c", p, a, b))
        for c in COMPILERS:
            for o in OPTS:
                for i in range(len(ARCHES)):
                    for j in range(i + 1, len(ARCHES)):
                        a, b = "%s/%s-%s" % (ARCHES[i], c, o), "%s/%s-%s" % (ARCHES[j], c, o)
                        if a in have and b in have:
                            pairs.append(("d", p, a, b))
    return pairs


def firmware_images():
    with open(os.path.join(FIRMWARE, "manifest.json")) as f:
        return [i for i in json.load(f)["images"] if i.get("project") == "fwkit"]


def firmware_families(images):
    """(e): fwkit across processors, at the same optimization level."""
    pairs = []
    by_opt = {}
    for i in images:
        by_opt.setdefault(i["opt"], []).append(i["name"])
    for opt, names in sorted(by_opt.items()):
        names = sorted(names)
        for x in range(len(names)):
            for y in range(x + 1, len(names)):
                pairs.append(("e", "fwkit", names[x], names[y]))
    return pairs


def sig_path(outdir, variant, program, cfg):
    return os.path.join(outdir, variant, "%s@%s.json" % (program, cfg.replace("/", "_")))


def run_rk_lift(args, label, path, stats_path):
    t0 = time.time()
    r = subprocess.run([RK_LIFT] + args + ["--no-instructions", "--signatures", path, "--stats", stats_path,
                                           "-o", "/dev/null"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("rk-lift failed on %s:\n%s" % (label, r.stderr[-3000:]))
    return time.time() - t0


def sign_elf(corpus, outdir, variant, extra, program, cfg, jobs):
    path = sig_path(outdir, variant, program, cfg)
    if os.path.exists(path):
        return path
    arch, oc = cfg.split("/")
    binary = os.path.join(corpus, arch, oc, "debug", program)
    run_rk_lift(["--analyze", "-j", str(jobs)] + extra + [binary], cfg, path + ".tmp", path + ".stats")
    os.replace(path + ".tmp", path)
    return path


def sign_firmware(outdir, variant, extra, image, jobs):
    path = sig_path(outdir, variant, "fwkit", image["name"])
    if os.path.exists(path):
        return path
    args = ["--raw", "--lang", image["language"], "--base", image["base"], "--raw-entry", image["entry"], "--analyze",
            "-j", str(jobs)]
    for r in image["regions"]:
        args += ["--region", r]
    run_rk_lift(args + extra + [os.path.join(FIRMWARE, image["path"])], image["name"], path + ".tmp",
                path + ".stats")
    # Names from the ELF's DWARF: the image has none.
    with open(os.path.join(FIRMWARE, image["truth"])) as f:
        truth = {int(t["address"], 16) & ~1: t["name"] for t in json.load(f)["dwarf_functions"]}
    with open(path + ".tmp") as f:
        doc = json.load(f)
    named = []
    for fn in doc["functions"]:
        name = truth.get(int(fn["entry"], 16) & ~1)
        if name is not None:
            fn["name"] = name
            named.append(fn)
    doc["functions"] = named
    with open(path, "w") as f:
        json.dump(doc, f)
    os.remove(path + ".tmp")
    return path


def sigdiff(a, b, weights, label):
    args = [RK_SIGDIFF, "stability", a, b, "--label", label]
    if weights:
        args += ["--weights", weights]
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("rk-sigdiff failed on %s: %s" % (label, r.stderr))
    return json.loads(r.stdout)


def summarize(rows, key):
    out = {}
    for fam in sorted(set(r["family"] for r in rows)):
        sel = [r[key] for r in rows if r["family"] == fam and r.get(key)]
        if not sel:
            continue
        n = sum(s["common"] for s in sel)
        out[fam] = {
            "pairs": len(sel),
            "functions": n,
            "top1": round(sum(s["top1"] * s["common"] for s in sel) / max(1, n), 3),
            "sim_median_mean": round(sum(s["sim_median"] for s in sel) / len(sel), 3),
            "residue_precision": round(sum(s["residue_correct"] for s in sel) /
                                       max(1, sum(s["residue_matched"] for s in sel)), 3),
            "residue_recall": round(sum(s["residue_correct"] for s in sel) / max(1, n), 3),
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "build", "sig-stability"))
    ap.add_argument("--variant", default="own:", help="NAME:extra rk-lift args (comma-separated)")
    ap.add_argument("--weights", default="", help="rk-sigdiff --weights (default: per language pair)")
    ap.add_argument("--idf", default="", help="lopo, corpus, or FILE64.xml,FILE32.xml")
    ap.add_argument("--ghidra", default=os.path.join(ROOT, "build", "bsim-ghidra", "0x49"))
    ap.add_argument("--families", default="design,b,c,d,e")
    ap.add_argument("--heldout", action="store_true", help="the held-out corpus (measure once)")
    ap.add_argument("-j", type=int, default=8)
    args = ap.parse_args()
    name, _, extra = args.variant.partition(":")
    extra = [x for x in extra.split(",") if x]
    corpus = os.path.join(ROOT, "out", "corpus-heldout" if args.heldout else "corpus")
    fams = set(args.families.split(","))
    os.makedirs(os.path.join(args.out, name), exist_ok=True)

    if args.heldout:
        programs = sorted(p for p in os.listdir(os.path.join(corpus, "elf-x86_64", "gcc-O2", "debug")))
    else:
        programs = ["cjson", "zlib", "lua", "features"]
    pairs = []
    if "design" in fams and not args.heldout:
        pairs += [("design",) + p for p in DESIGN]
    pairs += [p for p in elf_families(corpus, programs) if p[0] in fams]
    images = firmware_images() if "e" in fams and not args.heldout else []
    pairs += firmware_families(images)
    uboot = []
    if args.idf in ("lopo", "corpus") and not args.heldout:
        with open(os.path.join(FIRMWARE, "manifest.json")) as f:
            uboot = [i for i in json.load(f)["images"] if i.get("project") == "u-boot"]

    # Sign every binary the pairs name (two at a time, -j/2 threads each).
    need = sorted({(p[1], c) for p in pairs for c in p[2:] if p[1] != "fwkit"})
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=2) as ex:
        futs = [ex.submit(sign_elf, corpus, args.out, name, extra, p, c, max(1, args.j // 2)) for p, c in need]
        futs += [ex.submit(sign_firmware, args.out, name, extra, i, max(1, args.j // 2)) for i in images + uboot]
        for f in futs:
            f.result()
    print("signed %d binaries in %.0f s" % (len(need) + len(images), time.time() - t0), file=sys.stderr)

    # idf tables, by program ("" for every program).
    tables = {}
    if args.idf:
        sigdir = os.path.join(args.out, name)

        def derive(out, base, files):
            subprocess.run([RK_SIGDIFF, "derive-idf", out, "--base", base] + files, check=True,
                           capture_output=True)
            return out
        elf_files = {p: [sig_path(args.out, name, p, c) for p in [p] for c in corpus_configs(corpus, p)
                         if os.path.exists(sig_path(args.out, name, p, c))] for p in programs}
        fw_tuning = [sig_path(args.out, name, "fwkit", i["name"]) for i in images]
        fw_uboot = [sig_path(args.out, name, "fwkit", i["name"]) for i in uboot]
        if args.idf == "lopo":
            for p in programs:
                others = [f for q in programs if q != p for f in elf_files[q]]
                tables[p] = derive(os.path.join(sigdir, "idf-64-without-%s.xml" % p), "64", others)
            tables["fwkit"] = derive(os.path.join(sigdir, "idf-32-uboot.xml"), "32", fw_uboot)
        elif args.idf == "corpus":
            t64 = derive(os.path.join(sigdir, "idf-64.xml"), "64", [f for p in programs for f in elf_files[p]])
            t32 = derive(os.path.join(sigdir, "idf-32.xml"), "32", fw_tuning + fw_uboot)
            tables = {p: t64 for p in programs}
            tables["fwkit"] = t32
        else:
            t64, t32 = args.idf.split(",")
            tables = {p: t64 for p in programs}
            tables["fwkit"] = t32

    rows = []
    for fam, prog, a, b in pairs:
        label = "%s %s %s vs %s" % (fam, prog, a, b)
        row = {"family": fam, "program": prog, "a": a, "b": b}
        row["revkit"] = sigdiff(sig_path(args.out, name, prog, a), sig_path(args.out, name, prog, b),
                                tables.get(prog, args.weights), label)
        ga = os.path.join(args.ghidra, "%s@%s.json" % (prog, a.replace("/", "_")))
        gb = os.path.join(args.ghidra, "%s@%s.json" % (prog, b.replace("/", "_")))
        if os.path.exists(ga) and os.path.exists(gb):
            row["ghidra"] = sigdiff(ga, gb, "", label)
        rows.append(row)
        g = row.get("ghidra")
        print("%-58s revkit top1 %5.1f%% med %.2f resid %3d/%3d | ghidra %s" % (
            label, 100 * row["revkit"]["top1"], row["revkit"]["sim_median"], row["revkit"]["residue_correct"],
            row["revkit"]["residue_matched"],
            "top1 %5.1f%% med %.2f" % (100 * g["top1"], g["sim_median"]) if g else "-"), flush=True)
    tag = name + ("-idf-" + os.path.basename(args.idf).replace(",", "+") if args.idf else "") + \
        ("-w-" + os.path.basename(args.weights) if args.weights else "")
    with open(os.path.join(args.out, "pairs-%s.jsonl" % tag), "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    summary = {"revkit": summarize(rows, "revkit"), "ghidra": summarize(rows, "ghidra"),
               "revkit_where_ghidra": summarize([r for r in rows if r.get("ghidra")], "revkit")}
    with open(os.path.join(args.out, "summary-%s.json" % tag), "w") as f:
        json.dump(summary, f, indent=1)
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
