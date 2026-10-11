#!/usr/bin/env python3
"""The processor sweep: every SLEIGH language in the Ghidra install,
smoke-tested end to end by tools/rk-sweep (docs/processors.md).

  processor_sweep.py [--rk-sweep build/tools/rk-sweep/rk-sweep] [-j N]
                     [--timeout S] [--sample N] [--only GLOB]
                     [--corpus out/firmware-corpus] [--json out.json]
                     [--write-doc docs/processors.md] [--check]

For each language, rk-sweep loads an image as the raw loader does (with
the language's memory spaces and default blocks), decodes it linearly,
discovers functions from the first instruction that decodes, decompiles
that function and emulates a few steps from it, each in a child process
with a timeout. The image is real code where the firmware corpus has an
image for the language (its first 64 KB), else deterministic random bytes.

A stage is: ok, failed (an error the tool reported: no instruction
decodes, the decompiler gave up, the emulator met an instruction it can't
run), crashed (the process died on a signal) or hung (the timeout). The
loads/lifts/discovers/decompiles/emulates columns of docs/processors.md
come from them: --write-doc replaces the generated section of that file
(between its sweep:begin and sweep:end markers) and leaves the rest alone.
--sample N runs a deterministic N languages (the CI test); --check exits 1
if any language crashed, hung, or failed to load.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STAGES = ["load", "lift", "discover", "decompile", "emulate"]
# Always in a sample: the processors docs/firmware.md benchmarks.
MUST = ["avr8:LE:16:default", "8051:BE:16:default", "TI_MSP430:LE:16:default", "z80:LE:16:default",
        "PIC-16:LE:16:PIC-16F"]


def languages(rk_sweep: str) -> list[dict]:
    out = subprocess.run([rk_sweep, "--list"], stdout=subprocess.PIPE, text=True, check=True).stdout
    langs = []
    for line in out.splitlines():
        lid, compiler, deprecated, processor = line.split("\t", 3)  # ids may hold spaces (x86 "Real Mode")
        langs.append({"id": lid, "compiler": compiler, "deprecated": deprecated == "deprecated",
                      "processor": processor})
    return langs


def corpus_samples(corpus: str, tmp: str) -> dict[str, dict]:
    """A real image per language from the firmware corpus: its first 64 KB."""
    path = os.path.join(corpus, "manifest.json")
    if not os.path.exists(path):
        return {}
    out = {}
    for im in json.load(open(path))["images"]:
        lang = ":".join(im["language"].split(":")[:4])
        if lang in out or not os.path.exists(os.path.join(corpus, im["path"])):
            continue
        sample = os.path.join(tmp, lang.replace(":", "_") + ".bin")
        with open(os.path.join(corpus, im["path"]), "rb") as f, open(sample, "wb") as g:
            g.write(f.read(64 << 10))
        out[lang] = {"sample": sample, "base": im["base"], "entry": im["entry"], "image": im["name"]}
    return out


def sweep_one(rk_sweep: str, lang: dict, sample: dict | None, timeout: float) -> dict:
    cmd = [rk_sweep, "--lang", lang["id"] + ":" + lang["compiler"]]
    if sample:
        cmd += ["--sample", sample["sample"], "--base", sample["base"], "--entry", sample["entry"]]
    result = {"language": lang["id"], "processor": lang["processor"], "deprecated": lang["deprecated"],
              "sample": sample["image"] if sample else None, "stages": {}}
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        out, err, code = p.stdout, p.stderr, p.returncode
        hung = False
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = ""
        code = None
        hung = True
    for line in out.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        result["stages"][rec["stage"]] = rec
    # The first stage that never reported is where it crashed or hung.
    for s in STAGES:
        if s not in result["stages"]:
            if hung:
                result["stages"][s] = {"stage": s, "ok": False, "hung": True}
            elif code is not None and code < 0:
                result["stages"][s] = {"stage": s, "ok": False, "crashed": -code, "stderr": err[-400:]}
            break
    return result


def status(rec: dict | None) -> str:
    if rec is None:
        return "-"
    if rec.get("hung"):
        return "HANG"
    if rec.get("crashed"):
        return "CRASH"
    return "yes" if rec.get("ok") else "no"


def cell(r: dict, stage: str) -> str:
    rec = r["stages"].get(stage)
    s = status(rec)
    if rec is None or s != "yes":
        if rec is not None and s == "no" and rec.get("error"):
            return "no"
        return s
    if stage == "lift":
        return "%d%%" % round(100 * rec.get("coverage", 0))
    if stage == "discover":
        return str(rec.get("functions", 0))
    if stage == "emulate":
        steps = rec.get("steps", 0)
        if steps == 0:
            return "no"
        return str(steps)
    return "yes"


def notes(r: dict) -> str:
    out = []
    lift = r["stages"].get("lift", {})
    spaces = [s for s in lift.get("memory_spaces", []) if s]
    if len(spaces) > 1 or any("/" in s for s in spaces):
        out.append("spaces " + " ".join(spaces))
    for s in STAGES:
        rec = r["stages"].get(s)
        if rec is None:
            continue
        if rec.get("hung"):
            out.append("%s hangs" % s)
        elif rec.get("crashed"):
            out.append("%s crashes (signal %d)" % (s, rec["crashed"]))
        elif not rec.get("ok") and rec.get("error"):
            out.append("%s: %s" % (s, rec["error"][:70].replace("|", "/")))
    emu = r["stages"].get("emulate")
    if emu and emu.get("ok") and emu.get("stop") not in ("step_limit",):
        detail = emu.get("detail", "")[:60].replace("|", "/")
        out.append("emulator stops: %s%s" % (emu.get("stop"), " (" + detail + ")" if detail else ""))
    return "; ".join(out)


BEGIN = "<!-- sweep:begin (generated by scripts/processor_sweep.py --write-doc; edit the script, not this section) -->"
END = "<!-- sweep:end -->"


def sweep_section(results: list[dict]) -> str:
    """The generated part of docs/processors.md: totals and a row per language."""
    rows = sorted(results, key=lambda r: r["language"].lower())
    counts = {s: {} for s in STAGES}
    for r in rows:
        for s in STAGES:
            k = status(r["stages"].get(s))
            counts[s][k] = counts[s].get(k, 0) + 1
    lines = [BEGIN, ""]
    lines.append("Totals (%d languages, %d on a firmware-corpus sample):" % (
        len(rows), sum(1 for r in rows if r["sample"])))
    lines.append("")
    lines.append("| stage | " + " | ".join(["yes", "no", "CRASH", "HANG"]) + " |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for s in STAGES:
        c = counts[s]
        lines.append("| %s | %d | %d | %d | %d |" % (s, c.get("yes", 0), c.get("no", 0) + c.get("-", 0),
                                                  c.get("CRASH", 0), c.get("HANG", 0)))
    lines.append("")
    lines.append("| language | processor | loads | lifts | discovers | decompiles | emulates | sample | notes |")
    lines.append("| --- | --- | --- | ---: | ---: | --- | ---: | --- | --- |")
    for r in rows:
        name = "`%s`%s" % (r["language"], " *dep*" if r["deprecated"] else "")
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            name, r["processor"], cell(r, "load"), cell(r, "lift"), cell(r, "discover"), cell(r, "decompile"),
            cell(r, "emulate"), r["sample"] or "random", notes(r)))
    lines += ["", END]
    return "\n".join(lines)


def write_doc(path: str, results: list[dict]) -> None:
    """Replaces the generated section of the document (between BEGIN and END),
    keeping the text around it; a new file gets a title and the section."""
    section = sweep_section(results)
    text = open(path).read() if os.path.exists(path) else ""
    a, b = text.find("<!-- sweep:begin"), text.find(END)
    if a >= 0 and b > a:
        text = text[:a] + section + text[b + len(END):]
    else:
        text = (text.rstrip("\n") + "\n\n" if text else "# Processor coverage\n\n") + section + "\n"
    with open(path, "w") as f:
        f.write(text)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rk-sweep", default=os.path.join(ROOT, "build", "tools", "rk-sweep", "rk-sweep"))
    ap.add_argument("--corpus", default=os.path.join(ROOT, "out", "firmware-corpus"))
    ap.add_argument("-j", "--jobs", type=int, default=int(os.environ.get("RK_CI_JOBS", 4)))
    ap.add_argument("--timeout", type=float, default=120.0, help="seconds per language")
    ap.add_argument("--sample", type=int, default=0, help="a deterministic sample of N languages")
    ap.add_argument("--only", action="append", default=[], metavar="GLOB")
    ap.add_argument("--no-samples", action="store_true", help="random bytes for every language (no corpus images)")
    ap.add_argument("--json", help="write the results here")
    ap.add_argument("--write-doc", metavar="MD", help="write the coverage table (docs/processors.md)")
    ap.add_argument("--check", action="store_true", help="exit 1 on a crash, a hang or a load failure")
    args = ap.parse_args(argv)

    langs = languages(args.rk_sweep)
    if args.only:
        langs = [l for l in langs if any(fnmatch.fnmatch(l["id"], p) for p in args.only)]
    if args.sample:
        must = [l for l in langs if l["id"] in MUST]
        rest = [l for l in langs if l["id"] not in MUST and not l["deprecated"]]
        step = max(1, len(rest) // max(1, args.sample - len(must)))
        langs = must + rest[::step][:max(0, args.sample - len(must))]
    with tempfile.TemporaryDirectory(prefix="rk-sweep-") as tmp:
        samples = {} if args.no_samples else corpus_samples(args.corpus, tmp)
        results = []
        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            futs = [pool.submit(sweep_one, args.rk_sweep, l, samples.get(l["id"]), args.timeout) for l in langs]
            for fut in concurrent.futures.as_completed(futs):
                r = fut.result()
                results.append(r)
                print("%-34s %s" % (r["language"], " ".join("%s=%s" % (s, cell(r, s)) for s in STAGES)), flush=True)
    bad = []
    for r in results:
        for s in STAGES:
            st = status(r["stages"].get(s))
            if st in ("CRASH", "HANG") or (s == "load" and st != "yes"):
                bad.append("%s: %s %s" % (r["language"], s, st))
    if args.json:
        with open(args.json, "w") as f:
            json.dump(sorted(results, key=lambda r: r["language"]), f, indent=1)
    if args.write_doc:
        write_doc(args.write_doc, results)
    for b in bad:
        print("SWEEP FAILURE " + b, file=sys.stderr)
    print("%d languages, %d failures" % (len(results), len(bad)))
    return 1 if args.check and bad else 0


if __name__ == "__main__":
    sys.exit(main())
