#!/usr/bin/env python3
"""The assembler's round-trip gate (docs/patching.md, "Round-trip gate").

For every instruction discovery finds in the corpus binaries, assemble the
text the listing prints at its address, under the context it decoded with,
and classify: exact (an encoding equals the original bytes), equivalent
(only other encodings, which the disassembler prints the same), failed, or
skipped (no ISA mode reproduces the listed text from the bytes). Figures
are per language, and per ISA mode where the language has one (ARM/Thumb).

  scripts/asm_roundtrip.py [--build build] [-j N] [--per-binary N] [--only TEXT]
                           [--save-baseline] [--extra name=..,path=..,lang=..[,offset=..][,base=..]]

Inputs: the corpus (out/corpus: x86-64, AArch64, RISC-V; ELF and PE), the
firmware corpus (out/firmware-corpus: Cortex-M, MIPS, PowerPC, SuperH4,
68000, Xtensa; raw images), and ARM builds made here with the host clang
from the firmware corpus's cached sources (out/cache-firmware: monocypher,
heatshrink, littlefs, printf) for ARMv4T (ARM and Thumb) and ARMv7-A (ARM
and Thumb-2). --extra adds a local binary (never saved to the baseline).

Gate: every language's ok rate (exact + equivalent) and exact rate within
0.5 points of corpus/baselines/asm.json; ARM and Thumb modes ok >= 99%; ARM
and Thumb median time per line under 1 ms. Outputs under
build/corpus-out/asm (report.json, failures.txt).
"""
import argparse
import concurrent.futures as cf
import json
import os
import shutil
import statistics
import subprocess
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SLACK = 0.005
ISA_MODES = ("TMode", "ISA_MODE", "ISAModeSwitch", "vle")  # rk-asm --roundtrip's context order
ARM_TARGETS = [
    ("armv4t-arm", "armv4t-none-eabi", "-marm", "ARM:LE:32:v4t:default"),
    ("armv4t-thumb", "armv4t-none-eabi", "-mthumb", "ARM:LE:32:v4t:default"),
    ("armv7-arm", "armv7a-none-eabi", "-marm", "ARM:LE:32:v7:default"),
    ("armv7-thumb2", "armv7a-none-eabi", "-mthumb", "ARM:LE:32:v7:default"),
]
ARM_SOURCES = [
    ("monocypher-4.0.2.tar.gz", ["monocypher-4.0.2/src/monocypher.c"]),
    ("heatshrink-0.4.1.tar.gz", ["heatshrink-0.4.1/heatshrink_decoder.c", "heatshrink-0.4.1/heatshrink_encoder.c"]),
    ("littlefs-2.10.1.tar.gz", ["littlefs-2.10.1/lfs.c", "littlefs-2.10.1/lfs_util.c"]),
    ("printf-4.0.0.tar.gz", ["printf-4.0.0/printf.c"]),
]


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def build_arm(out, cache):
    """ARM ELF executables from cached sources, one per target; [] without clang."""
    clang, lld = shutil.which("clang"), shutil.which("ld.lld")
    if not clang or not lld:
        log("asm: no clang/ld.lld: skipping the ARM builds")
        return []
    src = os.path.join(out, "src")
    os.makedirs(src, exist_ok=True)
    for tarball, _ in ARM_SOURCES:
        path = os.path.join(cache, tarball)
        stamp = os.path.join(src, tarball + ".done")
        if not os.path.exists(path):
            log("asm: missing", path, "(scripts/build-firmware-corpus.sh fetches it)")
            return []
        if not os.path.exists(stamp):
            with tarfile.open(path) as t:
                t.extractall(src, filter="data")
            open(stamp, "w").close()
    libc = os.path.join(ROOT, "corpus/firmware/src/fwkit/libc/include")
    targets = []
    for name, triple, mode, lang in ARM_TARGETS:
        elf = os.path.join(out, "bin", name + ".elf")
        if not os.path.exists(elf):
            os.makedirs(os.path.dirname(elf), exist_ok=True)
            objs = []
            for _, files in ARM_SOURCES:
                for f in files:
                    o = os.path.join(out, "obj", name, os.path.basename(f) + ".o")
                    os.makedirs(os.path.dirname(o), exist_ok=True)
                    subprocess.run([clang, "--target=" + triple, mode, "-mfloat-abi=soft", "-ffreestanding", "-O2",
                                    "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-isystem", libc,
                                    "-I" + os.path.join(src, "heatshrink-0.4.1"), "-I" + os.path.join(src, "littlefs-2.10.1"),
                                    "-I" + os.path.join(src, "printf-4.0.0"), "-DLFS_NO_MALLOC", "-DLFS_NO_ASSERT",
                                    "-DLFS_NO_DEBUG", "-DLFS_NO_WARN", "-DLFS_NO_ERROR", "-DHEATSHRINK_DYNAMIC_ALLOC=0",
                                    "-c", os.path.join(src, f), "-o", o], check=True)
                    objs.append(o)
            subprocess.run([lld, "-e", "0", "--unresolved-symbols=ignore-all", *objs, "-o", elf],
                           check=True)
        targets.append({"name": "arm/" + name, "path": elf, "lang": lang})
    return targets


def corpus_targets():
    out = []
    corpus = os.path.join(ROOT, "out/corpus")
    for arch in ("elf-x86_64", "elf-aarch64", "elf-riscv64", "pe-x86_64"):
        for comp in ("gcc-O2", "clang-O2"):
            d = os.path.join(corpus, arch, comp, "stripped")
            if not os.path.isdir(d):
                continue
            for f in sorted(os.listdir(d)):
                if f.endswith(".pdb"):
                    continue
                out.append({"name": "%s/%s/%s" % (arch, comp, f), "path": os.path.join(d, f)})
    fw = os.path.join(ROOT, "out/firmware-corpus/manifest.json")
    if os.path.exists(fw):
        for img in json.load(open(fw))["images"]:
            out.append({"name": "fw/" + img["name"], "path": os.path.join(ROOT, "out/firmware-corpus", img["path"]),
                        "lang": img["language"], "raw": True, "base": img["base"],
                        "regions": img.get("regions", [])})
    return out


def lift(t, args, out):
    """rk-lift --analyze's JSON for a target (cached)."""
    js = os.path.join(out, "lift", t["name"].replace("/", "__") + ".json")
    if os.path.exists(js) and os.path.getmtime(js) >= os.path.getmtime(t["path"]):
        return js
    os.makedirs(os.path.dirname(js), exist_ok=True)
    cmd = [os.path.join(args.build, "tools/rk-lift/rk-lift"), "--analyze", "-j", "2", "-o", js]
    if t.get("raw"):
        cmd += ["--raw", "--lang", t["lang"]]
        if t.get("base"):
            cmd += ["--base", t["base"]]
        if t.get("offset"):
            cmd += ["--raw-offset", t["offset"]]
        for r in t.get("regions", []):
            cmd += ["--region", r]
    elif t.get("lang"):
        cmd += ["--lang", t["lang"]]
    cmd.append(t["path"])
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return js


def roundtrip(t, js, args, out):
    d = json.load(open(js))
    lang = d["binary"]["language"]
    ins = d["instructions"]
    step = max(1, len(ins) // args.per_binary)
    lines = ["%s\t%d\t%s\n" % (i["addr"], i["len"], i["text"]) for i in ins[::step]]
    cmd = [os.path.join(args.build, "tools/rk-asm/rk-asm"), "--roundtrip", "--lang", lang]
    if t.get("raw"):
        cmd += ["--raw"]
        if t.get("base"):
            cmd += ["--base", t["base"]]
        if t.get("offset"):
            cmd += ["--raw-offset", t["offset"]]
    cmd.append(t["path"])
    # Split across processes.
    chunks = max(1, min(args.jobs, len(lines) // 400 or 1))
    size = (len(lines) + chunks - 1) // chunks
    procs = []
    for k in range(chunks):
        part = "".join(lines[k * size:(k + 1) * size])
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        procs.append((p, part))
    results = []
    for p, part in procs:
        o, e = p.communicate(part)
        if p.returncode != 0:
            raise RuntimeError("rk-asm failed on %s: %s" % (t["name"], e[-2000:]))
        results += [json.loads(l) for l in o.splitlines() if l.strip()]
    return lang, results


def key(lang, mode_index):
    base = ":".join(lang.split(":")[:4])
    if base.startswith("ARM:"):
        return base + (" Thumb" if mode_index == 1 else " ARM")
    return base


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default=os.path.join(ROOT, "build"))
    ap.add_argument("-j", "--jobs", type=int, default=int(os.environ.get("RK_CI_JOBS", os.cpu_count() or 4)))
    ap.add_argument("--per-binary", type=int, default=6000)
    ap.add_argument("--only")
    ap.add_argument("--save-baseline", action="store_true")
    ap.add_argument("--baseline", default=os.path.join(ROOT, "corpus/baselines/asm.json"))
    ap.add_argument("--extra", action="append", default=[])
    args = ap.parse_args()
    out = os.path.join(args.build, "corpus-out/asm")
    os.makedirs(out, exist_ok=True)

    targets = corpus_targets() + build_arm(out, os.path.join(ROOT, "out/cache-firmware"))
    extras = []
    for spec in args.extra:
        kv = dict(p.split("=", 1) for p in spec.split(","))
        t = {"name": "extra/" + kv.get("name", os.path.basename(kv["path"])), "path": kv["path"], "lang": kv.get("lang"),
             "raw": "offset" in kv or "base" in kv or kv.get("raw") == "1", "offset": kv.get("offset"),
             "base": kv.get("base"), "regions": [], "extra": True}
        extras.append(t)
    targets += extras
    if args.only:
        targets = [t for t in targets if args.only in t["name"] or args.only in (t.get("lang") or "")]
    if not targets:
        log("asm: no inputs (out/corpus, out/firmware-corpus missing?)")
        return 1

    with cf.ThreadPoolExecutor(max(1, args.jobs // 2)) as pool:
        lifted = list(pool.map(lambda t: lift(t, args, out), targets))
    stats, failures = {}, []
    for t, js in zip(targets, lifted):
        lang, results = roundtrip(t, js, args, out)
        skipped = sum(1 for r in results if r["s"] == "skipped")
        for r in results:
            if r["s"] == "skipped":
                continue
            k = key(lang, r.get("m", 0))
            if t.get("extra"):
                k = "local " + k
            s = stats.setdefault(k, {"lines": 0, "exact": 0, "equivalent": 0, "failed": 0, "skipped": 0, "us": []})
            s[r["s"]] += 1
            if r["s"] != "skipped":
                s["lines"] += 1
                s["us"].append(r["us"])
            if r["s"] == "failed":
                failures.append("%s %s 0x%x: %s | %s" % (k, t["name"], r["a"], r.get("t", ""), r.get("e", "")))
        log("asm: %-40s %s (%d lines, %d skipped: no mode reproduces the listed text)" % (t["name"], lang, len(results), skipped))

    report = {}
    for k, s in sorted(stats.items()):
        n = max(1, s["lines"])
        us = sorted(s["us"]) or [0]
        report[k] = {"lines": s["lines"], "skipped": s["skipped"], "exact": round(s["exact"] / n, 4),
                     "ok": round((s["exact"] + s["equivalent"]) / n, 4), "failed": s["failed"],
                     "us_median": us[len(us) // 2], "us_mean": round(statistics.mean(us), 1),
                     "us_p95": us[int(len(us) * 0.95)]}
    json.dump(report, open(os.path.join(out, "report.json"), "w"), indent=1, sort_keys=True)
    with open(os.path.join(out, "failures.txt"), "w") as f:
        f.write("\n".join(failures) + "\n")
    print("%-28s %8s %8s %8s %8s %9s %9s" % ("language", "lines", "exact", "ok", "failed", "median us", "mean us"))
    for k, r in report.items():
        print("%-28s %8d %7.2f%% %7.2f%% %8d %9d %9.0f" % (k, r["lines"], 100 * r["exact"], 100 * r["ok"], r["failed"],
                                                            r["us_median"], r["us_mean"]))

    committed = {k: v for k, v in report.items() if not k.startswith("local ")}
    if args.save_baseline:
        json.dump({k: {"lines": v["lines"], "exact": v["exact"], "ok": v["ok"]} for k, v in committed.items()},
                  open(args.baseline, "w"), indent=1, sort_keys=True)
        print("asm: baseline saved to", args.baseline)
        return 0
    status = 0
    base = json.load(open(args.baseline)) if os.path.exists(args.baseline) else {}
    for k, b in base.items():
        r = committed.get(k)
        if r is None:
            if not args.only:
                print("asm: FAIL %s: in the baseline, not measured" % k)
                status = 1
            continue
        for m in ("ok", "exact"):
            if r[m] < b[m] - SLACK:
                print("asm: FAIL %s: %s %.2f%% < baseline %.2f%%" % (k, m, 100 * r[m], 100 * b[m]))
                status = 1
    for k, r in report.items():
        if " ARM" in k or " Thumb" in k:
            if r["lines"] >= 200 and r["ok"] < 0.99:
                print("asm: FAIL %s: ok %.2f%% < 99%%" % (k, 100 * r["ok"]))
                status = 1
            if r["lines"] >= 200 and r["us_median"] > 1000:
                print("asm: FAIL %s: median %d us per line > 1 ms" % (k, r["us_median"]))
                status = 1
    print("asm: %s" % ("ok" if status == 0 else "FAILED"))
    return status


if __name__ == "__main__":
    sys.exit(main())
