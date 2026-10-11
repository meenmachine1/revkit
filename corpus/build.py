#!/usr/bin/env python3
"""Build the benchmark corpus. Runs inside the toolchain container
(corpus/docker/Dockerfile); scripts/build-corpus.sh is the host-side wrapper.

  build.py --corpus /src --cache /cache --out /out [--defn corpus.json] [--only GLOB] [-j N]

Reads corpus.json (or --defn, e.g. heldout.json), builds every (program, config) pair the program's
`configs` patterns select, and writes <out>/manifest.json. Each config yields
a debug binary and a stripped binary built from the same objects.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile

BUILD = "/build"

# Every config the recipes know. A program's `configs` patterns select from these.
# Config id: <format>-<arch>/<compiler>-<opt>.
TOOLCHAINS = {
    ("elf", "x86_64", "gcc"): {"cc": ["gcc"]},
    ("elf", "x86_64", "clang"): {"cc": ["clang", "--target=x86_64-linux-gnu"]},
    ("elf", "aarch64", "gcc"): {"cc": ["aarch64-linux-gnu-gcc"]},
    ("elf", "aarch64", "clang"): {"cc": ["clang", "--target=aarch64-linux-gnu"]},
    ("elf", "riscv64", "gcc"): {"cc": ["riscv64-linux-gnu-gcc"]},
    ("elf", "riscv64", "clang"): {"cc": ["clang", "--target=riscv64-linux-gnu"]},
    # PE: clang targeting mingw-w64, linked by lld, CodeView debug info in a PDB.
    ("pe", "x86_64", "clang"): {
        "cc": ["clang", "--target=x86_64-w64-mingw32"],
        "debug": ["-g", "-gcodeview"],
        "ldflags": ["-fuse-ld=lld", "-Wl,--no-insert-timestamp"],
    },
    # PE with gcc (DWARF in the image, no PDB). Not selected by default.
    ("pe", "x86_64", "gcc"): {
        "cc": ["x86_64-w64-mingw32-gcc"],
        "ldflags": ["-Wl,--no-insert-timestamp"],
    },
}
OPTS = ["O0", "O2"]


def all_configs() -> list[str]:
    return sorted("%s-%s/%s-%s" % (fmt, arch, cc, opt)
                  for (fmt, arch, cc) in TOOLCHAINS for opt in OPTS)


def parse_config(cid: str):
    fa, co = cid.split("/")
    fmt, arch = fa.split("-", 1)
    cc, opt = co.rsplit("-", 1)
    return fmt, arch, cc, opt


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_json(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def run(cmd: list[str], cwd: str, env=None) -> None:
    proc = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        raise RuntimeError("command failed in %s:\n  %s\n%s" % (cwd, " ".join(cmd), proc.stdout))


def tool_version(cmd: list[str]) -> str:
    out = subprocess.run(cmd + ["--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).stdout
    return out.splitlines()[0].strip() if out else "?"


# --------------------------------------------------------------------------
# Sources

def prepare_sources(corpus: str, cache: str, defn: dict) -> dict:
    """Unpack/copy every program's sources under /build/src/<name>.

    Returns {program: {"root": dir, "files": [rel...], "inputs": {rel: sha256}, "origin": {...}}}."""
    prepared = {}
    externals = defn.get("externals", {})
    for name, prog in sorted(defn["programs"].items()):
        root = os.path.join(BUILD, "src", name)
        shutil.rmtree(root, ignore_errors=True)
        origin = {}
        if "external" in prog:
            ext = externals[prog["external"]]
            tarball = os.path.join(cache, os.path.basename(ext["url"]))
            digest = sha256_file(tarball)
            if digest != ext["sha256"]:
                raise RuntimeError("%s: sha256 %s, expected %s" % (tarball, digest, ext["sha256"]))
            os.makedirs(root)
            strip = ext.get("strip_components", 0)
            with tarfile.open(tarball) as tf:
                for member in tf.getmembers():
                    parts = member.name.split("/")[strip:]
                    if not parts or not member.isfile():
                        continue
                    member.name = "/".join(parts)
                    tf.extract(member, root, filter="data")
            origin = {"url": ext["url"], "sha256": ext["sha256"], "license": ext.get("license", "")}
            # Files a configure step would write (e.g. config.h), given verbatim.
            for rel, text in sorted(prog.get("generated", {}).items()):
                path = os.path.join(root, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    f.write(text)
        else:
            shutil.copytree(os.path.join(corpus, prog["source"]), root)
            origin = {"path": "corpus/" + prog["source"]}

        files = set()
        for pattern in prog["srcs"]:
            matches = sorted(glob.glob(pattern, root_dir=root))
            if not matches:
                raise RuntimeError("%s: no sources match %s" % (name, pattern))
            files.update(matches)
        for pattern in prog.get("exclude", []):
            files -= set(fnmatch.filter(files, pattern))
        # Inputs: every C source/header in the tree (headers affect the build too).
        inputs = {}
        for dirpath, _dirs, filenames in os.walk(root):
            for fn in filenames:
                if fn.endswith((".c", ".h")):
                    full = os.path.join(dirpath, fn)
                    inputs[os.path.relpath(full, root)] = sha256_file(full)
        prepared[name] = {"root": root, "files": sorted(files), "inputs": dict(sorted(inputs.items())),
                          "origin": origin}
    return prepared


# --------------------------------------------------------------------------
# Building one (program, config)

def build_one(corpus: str, out: str, name: str, prog: dict, src: dict, cid: str) -> list[dict]:
    fmt, arch, ccname, opt = parse_config(cid)
    tc = TOOLCHAINS[(fmt, arch, ccname)]
    cc = list(tc["cc"])
    debug = tc.get("debug", ["-g"])
    root = src["root"]
    objdir = os.path.join(BUILD, "obj", cid, name)
    os.makedirs(objdir, exist_ok=True)

    cflags = ["-" + opt, "-ffile-prefix-map=%s=." % root,
              "-w"]  # third-party code: warnings are noise here
    cflags += ["-I" + os.path.join(root, d) for d in prog.get("include", [])]
    cflags += prog.get("cflags", []) + prog.get("cflags_by_format", {}).get(fmt, [])

    objects = []
    for rel in src["files"]:
        obj = os.path.join(objdir, rel.replace("/", "__") + ".o")
        run(cc + cflags + debug + ["-c", rel, "-o", obj], cwd=root)
        objects.append(obj)

    exe = ".exe" if fmt == "pe" else ""
    ddir = os.path.join(out, cid, "debug")
    sdir = os.path.join(out, cid, "stripped")
    os.makedirs(ddir, exist_ok=True)
    os.makedirs(sdir, exist_ok=True)
    dbin = os.path.join(ddir, name + exe)
    sbin = os.path.join(sdir, name + exe)
    ldflags = tc.get("ldflags", [])
    libs = ["-l" + lib for lib in prog.get("libs", []) + prog.get("libs_by_format", {}).get(fmt, [])]
    env = dict(os.environ, SOURCE_DATE_EPOCH="0")

    debug_info = "dwarf"
    extra = {}
    if fmt == "pe" and ccname == "clang":
        pdb = os.path.join(ddir, name + ".pdb")
        # The image records just the PDB file name (no container path).
        run(cc + ldflags + objects + libs + ["-o", dbin, "-Wl,--pdb=" + os.path.basename(pdb),
                                             "-Wl,-Xlink=-pdbaltpath:%_PDB%"], cwd=ddir, env=env)
        # Stripped: same objects, no PDB, no symbols.
        run(cc + ldflags + objects + libs + ["-s", "-o", sbin], cwd=sdir, env=env)
        debug_info = "pdb"
        extra["pdb"] = os.path.relpath(pdb, out)
    else:
        run(cc + ldflags + objects + libs + ["-o", dbin], cwd=ddir, env=env)
        run(["llvm-strip", "--strip-all", dbin, "-o", sbin], cwd=sdir, env=env)

    flags_digest = sha256_json({"cc": cc, "cflags": cflags, "debug": debug, "ldflags": ldflags, "libs": libs})
    source_sha256 = sha256_json({"inputs": src["inputs"], "files": src["files"]})
    entries = []
    for path, stripped in ((dbin, False), (sbin, True)):
        entry = {
            "path": os.path.relpath(path, out),
            "program": name,
            "config": cid,
            "format": fmt,
            "arch": arch,
            "compiler": ccname,
            "opt": opt,
            "stripped": stripped,
            "debug_info": "none" if stripped else debug_info,
            "source_sha256": source_sha256,
            "flags_sha256": flags_digest,
            "sha256": sha256_file(path),
            "size": os.path.getsize(path),
        }
        if not stripped:
            entry.update(extra)
        entries.append(entry)
    return entries


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default="/src", help="corpus/ directory (recipes)")
    ap.add_argument("--cache", default="/cache", help="downloaded external tarballs")
    ap.add_argument("--out", default="/out")
    ap.add_argument("--defn", default="corpus.json",
                    help="corpus definition, relative to --corpus (heldout.json: the held-out set)")
    ap.add_argument("--only", action="append", default=[], metavar="GLOB",
                    help="build only binaries whose <config>/<program> matches GLOB")
    ap.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--list-configs", action="store_true")
    args = ap.parse_args(argv)

    if args.list_configs:
        print("\n".join(all_configs()))
        return 0

    with open(os.path.join(args.corpus, args.defn)) as f:
        defn = json.load(f)
    configs = all_configs()
    src = prepare_sources(args.corpus, args.cache, defn)

    tasks = []
    for name, prog in sorted(defn["programs"].items()):
        selected = sorted({c for c in configs if any(fnmatch.fnmatch(c, p) for p in prog["configs"])})
        for cid in selected:
            if args.only and not any(fnmatch.fnmatch(cid + "/" + name, p) for p in args.only):
                continue
            tasks.append((name, prog, cid))

    os.makedirs(args.out, exist_ok=True)
    binaries, failures = [], []
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        futs = {pool.submit(build_one, args.corpus, args.out, n, p, src[n], c): (n, c) for n, p, c in tasks}
        for fut in concurrent.futures.as_completed(futs):
            n, c = futs[fut]
            try:
                binaries.extend(fut.result())
                print("built %s/%s" % (c, n), flush=True)
            except Exception as e:  # keep going, report at the end
                failures.append("%s/%s: %s" % (c, n, e))
                print("FAILED %s/%s" % (c, n), flush=True)

    compilers = {}
    for (fmt, arch, ccname), tc in sorted(TOOLCHAINS.items()):
        compilers["%s-%s/%s" % (fmt, arch, ccname)] = tool_version(tc["cc"][:1])
    manifest = {
        "manifest_version": 1,
        "toolchain": {
            "image": os.environ.get("RK_CORPUS_IMAGE", ""),
            "compilers": compilers,
            "lld": tool_version(["ld.lld"]),
        },
        "programs": {
            name: {"origin": s["origin"], "inputs": s["inputs"], "srcs": s["files"]}
            for name, s in sorted(src.items())
        },
        "binaries": sorted(binaries, key=lambda b: b["path"]),
    }
    with open(os.path.join(args.out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
        f.write("\n")
    print("%d binaries, %d failed builds" % (len(binaries), len(failures)))
    for msg in failures:
        print(msg, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
