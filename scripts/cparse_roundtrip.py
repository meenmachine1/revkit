#!/usr/bin/env python3
"""The C parser's round-trip gate (docs/cparse.md).

Parses each corpus program's own sources (headers and .c files, function
bodies skipped) with rk-cparse under the data model of each binary the
corpus built from them, and compares every named struct, union, enum and
typedef with the debug-info truth rk-debuginfo reads from the binary
(DWARF; for PE the PDB):

  layout  the same size, and for each field the same name, bit offset and
          bit width (enums: size, signedness, enumerators; typedefs: size)
  hash    the same TypeId once typedefs are resolved and anonymous tags are
          named after their typedefs (types::without_typedefs with
          name_anonymous_tags, the form DWARF and PDB are held to agree in)

The sources are the corpus's (corpus/src/features, the cached tarballs in
out/cache) and the C library headers the corpus was compiled against
(scripts/cparse-sysroots.sh copies them out of the corpus image).

  scripts/cparse_roundtrip.py [--baseline FILE | --save-baseline FILE] [-j N]

With --baseline, exits 1 if any data model's layout or hash rate for
structs and unions drops below the baseline's.
"""

import argparse
import concurrent.futures
import fnmatch
import glob
import json
import os
import shutil
import subprocess
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Corpus config prefix -> (rk-cparse target, sysroot directories under
# out/cache/cparse-sysroots, rk-debuginfo flags, data model label).
MODELS = {
    "elf-x86_64": ("x86_64-linux-gnu", ["x86_64-linux-gnu/include/x86_64-linux-gnu", "x86_64-linux-gnu/include"], [],
                   "x86-64 SysV (LP64)"),
    "elf-aarch64": ("aarch64-linux-gnu", ["aarch64-linux-gnu/include"], [], "AArch64 (LP64)"),
    "elf-riscv64": ("riscv64-linux-gnu", ["riscv64-linux-gnu/include"], [], "RISC-V 64 (LP64)"),
    "pe-x86_64": ("x86_64-w64-mingw32", ["x86_64-w64-mingw32/include"], ["--no-dwarf"],
                  "x86-64 PE (LLP64, Microsoft bitfields; PDB)"),
}


def run(cmd, **kw):
    return subprocess.run(cmd, check=False, capture_output=True, text=True, **kw)


def program_sources(name, prog, srcroot, fmt):
    """(directory, [.c files], [extra rk-cparse flags]) of a corpus program."""
    if "external" in prog:
        base = os.path.join(srcroot, name)
    else:
        base = os.path.join(ROOT, "corpus", prog["source"])
    files = []
    for pat in prog["srcs"]:
        files += sorted(glob.glob(os.path.join(base, pat)))
    for pat in prog.get("exclude", []):
        files = [f for f in files if not fnmatch.fnmatch(os.path.relpath(f, base), pat)]
    flags = ["-I" + os.path.join(base, d) for d in prog.get("include", [])]
    for f in prog.get("cflags", []) + prog.get("cflags_by_format", {}).get(fmt, []):
        if f.startswith("-D") or f.startswith("-U") or f.startswith("-I"):
            flags.append(f)
    return base, files, flags


def extract(corpus, cache, dest):
    """Unpacks the external programs' tarballs (as corpus/build.py does)."""
    os.makedirs(dest, exist_ok=True)
    for name, ext in corpus["externals"].items():
        out = os.path.join(dest, name)
        if os.path.isdir(out):
            continue
        url = ext["url"]
        tarball = os.path.join(cache, os.path.basename(url))
        if not os.path.exists(tarball):
            sys.exit(f"cparse_roundtrip: {tarball} missing (scripts/build-corpus.sh fetches it)")
        tmp = out + ".tmp"
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp)
        strip = ext.get("strip_components", 0)
        with tarfile.open(tarball) as t:
            for m in t.getmembers():
                parts = m.name.split("/")[strip:]
                if not parts or ".." in parts or m.issym() or m.islnk():
                    continue
                m.name = "/".join(parts)
                t.extract(m, tmp, filter="data")
        os.rename(tmp, out)


def parse_program(rk_cparse, target, sysroots, flags, paths):
    """Each source a translation unit, linked (rk-cparse --units)."""
    cmd = [rk_cparse, "--json", "--system", "-q", "--units", "--target", target]
    for s in sysroots:
        cmd += ["-isystem", s]
    cmd += flags + paths
    p = run(cmd)
    if not p.stdout:
        return {"error": p.stderr.strip() or "no output", "path": " ".join(paths)}
    r = json.loads(p.stdout)
    r["path"] = os.path.dirname(paths[0])
    return r


def truth(rk_debuginfo, flags, binary):
    p = run([rk_debuginfo, "--types-json"] + flags + [binary])
    if p.returncode != 0:
        sys.exit(f"cparse_roundtrip: rk-debuginfo failed on {binary}: {p.stderr}")
    out = {}
    for line in p.stdout.splitlines():
        t = json.loads(line)
        out.setdefault(t["key"], []).append(t)
    return out


def category(t):
    k = t["key"]
    if k.startswith("typedef "):
        return "typedefs"
    if k.startswith("enum "):
        return "enums"
    return "aggregates"


def layout_of(t):
    if t["kind"] in ("struct", "union", "class") and not t["key"].startswith("typedef "):
        return (t["size"], tuple((f["name"], f["bit_offset"], f["bit_size"]) for f in t["fields"]))
    if t["kind"] == "enum" and not t["key"].startswith("typedef "):
        return (t["size"], t["signed"], tuple(tuple(v) for v in t["values"]))
    return (t["size"],)


def complete(t):
    return t.get("complete", True)


def compare(truth_types, ours):
    """Per category counts and the mismatches."""
    stats = {c: {"compared": 0, "layout": 0, "hash": 0, "typed_hash": 0, "missing": 0} for c in
             ("aggregates", "enums", "typedefs")}
    problems = []
    for key, defs in sorted(truth_types.items()):
        full = [d for d in defs if complete(d)]
        if not full:
            continue
        cat = category(full[0])
        mine = [d for d in ours.get(key, []) if complete(d)]
        if not mine:
            stats[cat]["missing"] += 1
            problems.append({"key": key, "missing": True})
            continue
        s = stats[cat]
        s["compared"] += 1
        t_layouts = {layout_of(d) for d in full}
        m_layouts = {layout_of(d) for d in mine}
        layout_ok = bool(t_layouts & m_layouts)
        hash_ok = bool({d["flat_hash"] for d in full} & {d["flat_hash"] for d in mine})
        typed_ok = bool({d["hash"] for d in full} & {d["hash"] for d in mine})
        s["layout"] += layout_ok
        s["hash"] += hash_ok
        s["typed_hash"] += typed_ok
        if not layout_ok or not hash_ok:
            problems.append({"key": key, "layout": layout_ok, "hash": hash_ok, "truth": full[0], "ours": mine[0]})
    return stats, problems


def add(into, stats):
    for c, s in stats.items():
        for k, v in s.items():
            into.setdefault(c, {}).setdefault(k, 0)
            into[c][k] += v


def rate(s, k):
    return s[k] / s["compared"] if s["compared"] else 1.0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=os.path.join(ROOT, "out", "corpus"))
    ap.add_argument("--cache", default=os.path.join(ROOT, "out", "cache"))
    ap.add_argument("--build", default=os.path.join(ROOT, "build"))
    ap.add_argument("--out", default=os.path.join(ROOT, "build", "corpus-out", "cparse"))
    ap.add_argument("-j", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--baseline")
    ap.add_argument("--save-baseline")
    ap.add_argument("--only", help="fnmatch over config/program, e.g. 'elf-x86_64/*/features'")
    ap.add_argument("--show", type=int, default=20, help="mismatches to print per binary")
    args = ap.parse_args()

    rk_cparse = os.path.join(args.build, "tools", "rk-cparse", "rk-cparse")
    rk_debuginfo = os.path.join(args.build, "tools", "rk-debuginfo", "rk-debuginfo")
    for b in (rk_cparse, rk_debuginfo):
        if not os.access(b, os.X_OK):
            sys.exit(f"cparse_roundtrip: {b} missing: build first")
    sysroot_base = os.path.join(args.cache, "cparse-sysroots")
    if not os.path.exists(os.path.join(sysroot_base, ".complete")):
        p = subprocess.run([os.path.join(ROOT, "scripts", "cparse-sysroots.sh")])
        if p.returncode != 0:
            sys.exit(1)
    with open(os.path.join(ROOT, "corpus", "corpus.json")) as f:
        corpus = json.load(f)
    srcroot = os.path.join(args.out, "src")
    extract(corpus, args.cache, srcroot)

    # Every debug binary of the corpus.
    binaries = []
    for name, prog in corpus["programs"].items():
        for cfg_dir in sorted(glob.glob(os.path.join(args.corpus, "*", "*"))):
            cfg = os.path.relpath(cfg_dir, args.corpus)
            fmt_arch = cfg.split("/")[0]
            if fmt_arch not in MODELS or not any(fnmatch.fnmatch(cfg, c) for c in prog["configs"]):
                continue
            exe = os.path.join(cfg_dir, "debug", name + (".exe" if fmt_arch.startswith("pe") else ""))
            if not os.path.exists(exe):
                continue
            if args.only and not fnmatch.fnmatch(cfg + "/" + name, args.only):
                continue
            binaries.append((cfg, fmt_arch, name, prog, exe))
    if not binaries:
        sys.exit("cparse_roundtrip: no corpus binaries (scripts/build-corpus.sh)")

    # Parse each (program, data model, flags) once.
    jobs = {}
    for cfg, fmt_arch, name, prog, exe in binaries:
        target, sysroots, _, _ = MODELS[fmt_arch]
        fmt = fmt_arch.split("-")[0]
        base, files, flags = program_sources(name, prog, srcroot, fmt)
        key = (name, target, tuple(flags))
        jobs[key] = ([os.path.join(sysroot_base, s) for s in sysroots], flags, files, target)
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.j) as ex:
        futs = {ex.submit(parse_program, rk_cparse, j[3], j[0], j[1], j[2]): k for k, j in jobs.items()}
        for fut in concurrent.futures.as_completed(futs):
            results[futs[fut]] = fut.result()
        truths = {}
        tfuts = {ex.submit(truth, rk_debuginfo, MODELS[b[1]][2], b[4]): b[4] for b in binaries}
        for fut in concurrent.futures.as_completed(tfuts):
            truths[tfuts[fut]] = fut.result()

    report = {"models": {}, "binaries": {}, "parse_errors": [], "unique": {}}
    for key, r in sorted(results.items()):
        if "error" in r:
            report["parse_errors"].append({"file": r["path"], "error": r["error"]})
        elif r.get("errors") or r.get("limit_hit"):
            errs = [d for d in r["diagnostics"] if d["severity"] == "error"]
            report["parse_errors"].append({"file": r["path"], "errors": r["errors"], "first": errs[:5]})

    status = 0
    for cfg, fmt_arch, name, prog, exe in binaries:
        target, _, _, label = MODELS[fmt_arch]
        fmt = fmt_arch.split("-")[0]
        _, files, flags = program_sources(name, prog, srcroot, fmt)
        ours = {}
        r = results[(name, target, tuple(flags))]
        for t in r.get("named", []):
            ours.setdefault(t["key"], []).append(t)
            # clang's CodeView names typedef struct {...} point; "struct point".
            if fmt == "pe" and t["key"].startswith("typedef ") and t.get("tag") == "" and t["kind"] != "other":
                alias = dict(t, key=t["kind"] + " " + t["key"][len("typedef "):])
                ours.setdefault(alias["key"], []).append(alias)
        stats, problems = compare(truths[exe], ours)
        # Distinct types per data model (a program built four ways counts once).
        u = report["unique"].setdefault(label, {})
        for key, defs in truths[exe].items():
            full = [d for d in defs if complete(d)]
            if full and key in ours:
                ok = bool({d["flat_hash"] for d in full} & {d["flat_hash"] for d in ours[key] if complete(d)})
                for d in full:
                    u.setdefault(category(d), {})[(key, d["flat_hash"])] = ok
        rel = os.path.relpath(exe, args.corpus)
        report["binaries"][rel] = {"model": label, "stats": stats, "mismatches": problems}
        add(report["models"].setdefault(label, {}), stats)

    print("C parser round trip: corpus headers vs debug-info truth")
    for rel, b in report["binaries"].items():
        a = b["stats"]["aggregates"]
        print(f"  {rel}: {a['compared']} structs/unions, layout {a['layout']}, hash {a['hash']}"
              f" (typed {a['typed_hash']}), missing {a['missing']}; enums {b['stats']['enums']['hash']}/"
              f"{b['stats']['enums']['compared']}, typedefs {b['stats']['typedefs']['hash']}/"
              f"{b['stats']['typedefs']['compared']}")
        for p in b["mismatches"][: args.show]:
            what = "missing" if p.get("missing") else "LAYOUT" if not p["layout"] else "hash"
            print(f"    {what} {p['key']}")
    print()
    summary = {}
    for label, stats in report["models"].items():
        a = stats["aggregates"]
        summary[label] = {c: {"compared": s["compared"], "layout": round(rate(s, "layout"), 4),
                              "hash": round(rate(s, "hash"), 4), "typed_hash": round(rate(s, "typed_hash"), 4),
                              "missing": s["missing"]} for c, s in stats.items()}
        typed = "n/a: a PDB has no typedefs" if "PDB" in label else f"{100 * rate(a, 'typed_hash'):.2f}%"
        print(f"{label}: structs/unions {a['compared']}: layout {100 * rate(a, 'layout'):.2f}%, hash "
              f"{100 * rate(a, 'hash'):.2f}% (with typedefs {typed}); enums "
              f"{100 * rate(stats['enums'], 'hash'):.2f}% of {stats['enums']['compared']}; typedefs "
              f"{100 * rate(stats['typedefs'], 'hash'):.2f}% of {stats['typedefs']['compared']}")
    for label, cats in report["unique"].items():
        parts = [f"{c} {sum(v.values())}/{len(v)}" for c, v in sorted(cats.items())]
        print(f"  distinct types, {label}: " + ", ".join(parts))
    report["unique"] = {label: {c: {"compared": len(v), "hash": sum(v.values())} for c, v in cats.items()}
                        for label, cats in report["unique"].items()}
    if report["parse_errors"]:
        print(f"{len(report['parse_errors'])} sources had parse errors:")
        for e in report["parse_errors"][:20]:
            print("  ", e)
    report["summary"] = summary
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "report.json"), "w") as f:
        json.dump(report, f, indent=1, sort_keys=True)

    if args.save_baseline:
        with open(args.save_baseline, "w") as f:
            json.dump(summary, f, indent=1, sort_keys=True)
            f.write("\n")
        print(f"baseline saved to {args.save_baseline}")
    elif args.baseline:
        with open(args.baseline) as f:
            base = json.load(f)
        for label, cats in base.items():
            if label not in summary:
                print(f"REGRESSION: {label} not measured")
                status = 1
                continue
            for cat in ("aggregates", "enums", "typedefs"):
                for k in ("layout", "hash"):
                    if summary[label][cat][k] + 1e-9 < cats[cat][k]:
                        print(f"REGRESSION: {label} {cat} {k} {summary[label][cat][k]} < baseline {cats[cat][k]}")
                        status = 1
        if report["parse_errors"]:
            print("REGRESSION: sources with parse errors")
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
