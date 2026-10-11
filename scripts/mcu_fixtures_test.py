#!/usr/bin/env python3
"""Discovery and decompilation on real MCU firmware: the firmware corpus's
mcukit images for AVR (avr-gcc), the 8051 (SDCC), the MSP430 (TI's GCC)
and the Z80 (SDCC), against their DWARF or SDCC debug records
(docs/processors.md). A CTest (mcu_fixtures).

  mcu_fixtures_test.py --rk-lift build/tools/rk-lift/rk-lift [--corpus out/firmware-corpus]

The images come from the firmware corpus when it has been built
(scripts/build-firmware-corpus.sh); otherwise they are built here in the
corpus's Docker toolchain image if Docker and that image are available.
Without either, the test is skipped (exit 77).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SKIP = 77
# image -> (functions at least, DWARF recall at least, the entry's default name)
EXPECT = {
    "avr/mcukit-atmega328p-Os": (30, 0.5, None),
    "mcs51/mcukit-8051-Os": (15, 0.25, None),
    "msp430/mcukit-msp430-Os": (20, 0.4, None),
    "z80/mcukit-z80-Os": (20, 0.3, None),
}


def docker_image() -> str | None:
    if shutil.which("docker") is None:
        return None
    dockerfile = os.path.join(ROOT, "corpus", "firmware", "docker", "Dockerfile")
    tag = "revkit-fwcorpus:" + hashlib.sha256(open(dockerfile, "rb").read()).hexdigest()[:12]
    r = subprocess.run(["docker", "image", "inspect", tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return tag if r.returncode == 0 else None


def build(out: str) -> bool:
    """The mcukit images, built with the corpus's own script."""
    if docker_image() is None:
        return False
    only = []
    for name in EXPECT:
        only += ["--only", name]
    r = subprocess.run([os.path.join(ROOT, "scripts", "build-firmware-corpus.sh"), "--out", out, "--"] + only,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=dict(os.environ, RK_CI_JOBS="2"))
    if r.returncode != 0:
        print(r.stdout[-3000:], file=sys.stderr)
    return r.returncode == 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rk-lift", required=True)
    ap.add_argument("--corpus", default=os.path.join(ROOT, "out", "firmware-corpus"))
    args = ap.parse_args(argv)

    # Outputs go to a directory of this run's own: the test may run for
    # several build trees (and worktrees) at once.
    tmp = tempfile.mkdtemp(prefix="rk-mcu-")
    corpus = args.corpus
    manifest_path = os.path.join(corpus, "manifest.json")
    have = os.path.exists(manifest_path) and all(
        any(im["name"] == n for im in json.load(open(manifest_path))["images"]) for n in EXPECT)
    if not have:
        corpus = os.path.join(tmp, "corpus")
        if not build(corpus):
            print("skipped: no firmware corpus with the mcukit images, and no Docker toolchain image to build them")
            shutil.rmtree(tmp, ignore_errors=True)
            return SKIP
    failures = []
    try:
        images = {im["name"]: im for im in json.load(open(os.path.join(corpus, "manifest.json")))["images"]}
        for name, (min_functions, min_recall, _) in EXPECT.items():
            im = images[name]
            out = os.path.join(tmp, name.replace("/", "_") + ".json")
            cmd = [args.rk_lift, "--raw", "--lang", im["language"], "--base", im["base"], "--raw-entry", im["entry"]]
            for r in im.get("regions", []):
                cmd += ["--region", r]
            cmd += ["--analyze", "--decompile", "-j", "2", "-o", out, os.path.join(corpus, im["path"])]
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600)
            if r.returncode != 0:
                failures.append("%s: rk-lift failed: %s" % (name, r.stderr[-500:]))
                continue
            doc = json.load(open(out))
            truth = json.load(open(os.path.join(corpus, im["truth"])))
            found = {int(f["entry"], 16) for f in doc["functions"]}
            dwarf = {int(f["address"], 16) for f in truth["dwarf_functions"]}
            recall = len(found & dwarf) / max(1, len(dwarf))
            decompiled = sum(1 for f in doc["functions"] if f.get("decompiled_c"))
            print("%-28s %3d functions, DWARF recall %.2f, %d decompiled" % (name, len(found), recall, decompiled))
            if len(found) < min_functions:
                failures.append("%s: %d functions, expected at least %d" % (name, len(found), min_functions))
            if recall < min_recall:
                failures.append("%s: DWARF recall %.2f below %.2f" % (name, recall, min_recall))
            if decompiled < len(found):
                failures.append("%s: %d of %d functions decompiled" % (name, decompiled, len(found)))
            # Names count in the code space's units, qualified by space.
            if name.startswith("avr/") and not any(f["name"].startswith("FUN_code_") for f in doc["functions"]):
                failures.append("%s: no FUN_code_ default names" % name)
            if name.startswith("mcs51/") and not any(f["name"].startswith("FUN_CODE_") for f in doc["functions"]):
                failures.append("%s: no FUN_CODE_ default names" % name)
            # The processor spec's labels name what the C reads and writes
            # (AVR's status register, the 8051's register bank).
            label = {"avr": "SREG", "mcs51": "BANK0_R"}.get(name.split("/")[0])
            if label and not any(label in (f.get("decompiled_c") or "") for f in doc["functions"]):
                failures.append("%s: no processor label (%s) in the decompiled C" % (name, label))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for f in failures:
        print("FAIL " + f, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
