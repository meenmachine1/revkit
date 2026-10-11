#!/usr/bin/env python3
"""Ghidra's BSim, headless, as the reference for revkit's port (src/diff/lsh)
and its own signatures (decompd mode signature).

  diff-bsim-reference.py fixtures OUT.txt
      Java's cosine and significance (generic.lsh.vector) on pairs of
      feature vectors, for every vendored weights file: real vectors
      (GenSignatures over two cJSON builds) and synthetic ones (repeats past
      the tf cap, hashes from the idf table, empty and one-hash vectors).
      Each line: weights cos_bits sig_bits selfsig_a_bits dot_bits intersect
      | a hashes | b hashes, doubles as their IEEE bits in hex. revkit's
      unit test (src/diff/tests/lsh_test.cc) requires the same bits.

  diff-bsim-reference.py dump OUTDIR [program/config ...]
      Ghidra's feature vectors per function (debug builds of the tuning
      corpus, auto-analysis, GenSignatures with the weights file's
      settings): OUTDIR/<program>@<arch>_<config>.json = {"language",
      "settings", "functions": {name: {"entry", "features"}}}, names that
      occur twice dropped. --stripped-names-from=DIR signs the stripped twins
      instead, naming their functions by entry from DIR's dump of the
      debug builds; --weights=FILE picks the weights file (and settings).

Run with the PyGhidra venv (scripts/setup-pyghidra.sh).
"""
import json
import os
import random
import struct
import sys

GHIDRA = os.path.expanduser("~/ghidra/ghidra_12.1.4_PUBLIC")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "out", "corpus")
WEIGHTS = ["lshweights_64.xml", "lshweights_64_32.xml", "lshweights_32.xml", "lshweights_nosize.xml"]

STABILITY_SET = [
    "cjson/elf-x86_64/gcc-O0", "cjson/elf-x86_64/gcc-O2", "cjson/elf-x86_64/clang-O0",
    "cjson/elf-x86_64/clang-O2", "cjson/elf-aarch64/gcc-O2", "cjson/elf-riscv64/clang-O2",
    "zlib/elf-x86_64/gcc-O2", "zlib/elf-x86_64/clang-O0", "zlib/elf-aarch64/clang-O2", "zlib/elf-riscv64/gcc-O2",
    "lua/elf-x86_64/gcc-O2", "lua/elf-aarch64/clang-O2",
]


def start(tmp):
    os.environ["GHIDRA_INSTALL_DIR"] = GHIDRA
    os.makedirs(tmp, exist_ok=True)
    from pyghidra.launcher import HeadlessPyGhidraLauncher
    launcher = HeadlessPyGhidraLauncher(install_dir=GHIDRA)
    launcher.add_vmargs("-Xmx6g", "-Djava.io.tmpdir=" + tmp)
    launcher.start()


def factory_for_file(name):
    from generic.lsh.vector import WeightedLSHCosineVectorFactory
    from ghidra.xml import XmlPullParserFactory
    from ghidra.util.xml import SpecXmlUtils
    from generic.jar import ResourceFile
    from ghidra.framework import Application
    rf = ResourceFile(Application.getModuleDataSubDirectory("BSim", ""), name)
    f = WeightedLSHCosineVectorFactory()
    parser = XmlPullParserFactory.create(rf, SpecXmlUtils.getXmlHandler(), False)
    f.readWeights(parser)
    return f


def features_of(vec):
    """The int features (unsigned) a vector was built from: each hash tf times."""
    out = []
    for i in range(int(vec.numEntries())):
        e = vec.getEntry(i)
        out.extend([int(e.getHash()) & 0xffffffff] * int(e.getTF()))
    return out


def signatures(path, tmp, weights_override=None):
    """(language, settings, {name: (entry, features)}) for one binary."""
    import pyghidra
    from ghidra.features.bsim.query import GenSignatures
    from ghidra.util.task import TaskMonitor
    from java.util import ArrayList
    name = "p_" + path.replace("/", "_")
    with pyghidra.open_program(path, project_location=tmp, project_name=name, analyze=True) as flat:
        program = flat.getCurrentProgram()
        lid = program.getLanguageID()
        if weights_override:
            factory = factory_for_file(weights_override)
        else:
            factory = factory_for_file(str(GenSignatures.getWeightsFile(lid, lid).getName()))
        gen = GenSignatures(False)
        gen.setVectorFactory(factory)
        gen.openProgram(program, None, None, None, None, None)
        funcs = [f for f in program.getFunctionManager().getFunctions(True) if not f.isThunk() and not f.isExternal()]
        jl = ArrayList()
        for f in funcs:
            jl.add(f)
        gen.scanFunctions(jl.iterator(), len(funcs), TaskMonitor.DUMMY)
        out, dup = {}, set()
        it = gen.getDescriptionManager().listAllFunctions()
        while it.hasNext():
            fd = it.next()
            sr = fd.getSignatureRecord()
            if sr is None:
                continue
            n = str(fd.getFunctionName())
            if n in out:
                dup.add(n)
            out[n] = (int(fd.getAddress()), features_of(sr.getLSHVector()))
        for d in dup:
            out.pop(d, None)
        settings = int(factory.getSettings())
        gen.dispose()
        return str(lid), settings, out


def bits(x):
    return "%016x" % struct.unpack("<Q", struct.pack("<d", float(x)))[0]


def jints(features):
    from jpype import JArray, JInt
    return JArray(JInt)([h - (1 << 32) if h >= (1 << 31) else h for h in features])


def fixtures(out_path):
    tmp = os.path.join(ROOT, "build", "ghidra-tmp")
    start(tmp)
    from generic.lsh.vector import VectorCompare
    rng = random.Random(20261005)
    # Real vectors: two builds of one program, compared function by function
    # and against a neighbour.
    real = []
    for cfg in ["elf-x86_64/gcc-O2", "elf-aarch64/gcc-O2"]:
        _, _, funcs = signatures(os.path.join(CORPUS, cfg, "debug", "cjson"), tmp)
        real.append(funcs)
    common = sorted(set(real[0]) & set(real[1]))
    lines = []
    for wname in WEIGHTS:
        factory = factory_for_file(wname)
        # The idf table's hashes, to draw synthetic features from.
        table_hashes = []
        import re
        with open(os.path.join(GHIDRA, "Ghidra/Features/BSim/data", wname)) as fh:
            for m in re.finditer(r"<hash count=\"\d+\">(0x[0-9a-fA-F]+)</hash>", fh.read()):
                table_hashes.append(int(m.group(1), 16))
        pairs = []
        for i, n in enumerate(common[:40]):
            pairs.append((real[0][n][1], real[1][n][1]))
            m = common[(i + 7) % 40]
            pairs.append((real[0][n][1], real[1][m][1]))
        for _ in range(100):
            def synth():
                k = rng.choice([0, 1, 2, 5, 20, 60, 120])
                f = []
                for _ in range(k):
                    r = rng.random()
                    if r < 0.4 and table_hashes:
                        f.append(rng.choice(table_hashes))
                    elif r < 0.5:
                        f.append(rng.choice([0, 1, 0x7fffffff, 0x80000000, 0xffffffff]))
                    else:
                        f.append(rng.getrandbits(32))
                if f and rng.random() < 0.3:
                    f.extend([f[0]] * rng.choice([1, 10, 63, 64, 80]))  # past the tf cap
                return sorted(f)
            a = synth()
            b = list(a) if rng.random() < 0.3 else synth()
            if rng.random() < 0.5 and b:
                b = sorted(b[: len(b) // 2] + [rng.getrandbits(32) for _ in range(3)])
            pairs.append((a, b))
        for a, b in pairs:
            va = factory.buildVector(jints(a))
            vb = factory.buildVector(jints(b))
            data = VectorCompare()
            cos = va.compare(vb, data)
            sig = factory.calculateSignificance(data)
            selfsig = factory.getSelfSignificance(va)
            lines.append("%s %s %s %s %s %d | %s | %s" % (
                wname, bits(cos), bits(sig), bits(selfsig), bits(data.dotproduct), int(data.intersectcount),
                " ".join("%x" % h for h in a), " ".join("%x" % h for h in b)))
    with open(out_path, "w") as fh:
        fh.write("# Java (Ghidra 12.1.4 generic.lsh.vector) on these vectors; scripts/diff-bsim-reference.py fixtures\n")
        fh.write("\n".join(lines) + "\n")
    print("%d pairs -> %s" % (len(lines), out_path))


def dump(outdir, which, weights_override=None, names_from=None):
    """names_from: a dump of the debug builds; the stripped twins are signed
    and their functions named by entry from it."""
    tmp = os.path.join(ROOT, "build", "ghidra-tmp")
    start(tmp)
    os.makedirs(outdir, exist_ok=True)
    for spec in which:
        prog, arch, cfg = spec.split("/")
        path = os.path.join(CORPUS, arch, cfg, "stripped" if names_from else "debug", prog)
        lang, settings, funcs = signatures(path, tmp, weights_override)
        if names_from:
            with open(os.path.join(names_from, "%s@%s_%s.json" % (prog, arch, cfg))) as fh:
                by_entry = {v["entry"]: n for n, v in json.load(fh)["functions"].items()}
            funcs = {by_entry[e]: (e, f) for n, (e, f) in funcs.items() if e in by_entry}
        rec = {"language": lang, "settings": settings,
               "functions": {n: {"entry": e, "features": f} for n, (e, f) in sorted(funcs.items())}}
        out = os.path.join(outdir, "%s@%s_%s.json" % (prog, arch, cfg))
        with open(out, "w") as fh:
            json.dump(rec, fh)
        print("%s: %d functions -> %s" % (spec, len(funcs), out), flush=True)


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "fixtures":
        fixtures(sys.argv[2])
    elif len(sys.argv) >= 3 and sys.argv[1] == "dump":
        args = sys.argv[3:]
        override = names = None
        while args and args[0].startswith("--"):
            if args[0].startswith("--weights="):
                override = args[0].split("=", 1)[1]
            elif args[0].startswith("--stripped-names-from="):
                names = args[0].split("=", 1)[1]
            args = args[1:]
        dump(sys.argv[2], args or STABILITY_SET, override, names)
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
