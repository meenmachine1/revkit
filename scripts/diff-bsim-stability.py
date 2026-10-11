#!/usr/bin/env python3
"""Measure BSim feature-vector stability across compilers, -O levels and
architectures on the tuning corpus (debug builds: names are ground truth).

For each binary: Ghidra auto-analysis, then GenSignatures over every
non-thunk function (timed), optionally a timed full decompile of the same
functions. For each pair of builds of one program: the similarity of each
function to its true counterpart, whether the true counterpart is the top-1
candidate, and the fraction with identical vectors.
"""
import json
import os
import sys
import time
from collections import defaultdict

GHIDRA = os.path.expanduser("~/ghidra/ghidra_12.1.4_PUBLIC")
CORPUS = os.path.expanduser("~/dev/revkit/out/corpus")
OUT = os.path.dirname(os.path.abspath(__file__))

SETS = {
    "zlib": ["elf-x86_64/gcc-O2", "elf-x86_64/clang-O0", "elf-aarch64/clang-O2", "elf-riscv64/gcc-O2"],
    "cjson": ["elf-x86_64/gcc-O0", "elf-x86_64/gcc-O2", "elf-x86_64/clang-O0", "elf-x86_64/clang-O2",
              "elf-aarch64/gcc-O2", "elf-riscv64/clang-O2"],
    "lua": ["elf-x86_64/gcc-O2", "elf-aarch64/clang-O2"],
}
DECOMPILE_COST_ON = {("zlib", "elf-x86_64/gcc-O2"), ("lua", "elf-x86_64/gcc-O2")}


def main():
    only = sys.argv[1:]  # optional program names
    os.environ["GHIDRA_INSTALL_DIR"] = GHIDRA
    tmp = os.path.join(OUT, "ghidra-tmp")
    os.makedirs(tmp, exist_ok=True)
    from pyghidra.launcher import HeadlessPyGhidraLauncher
    launcher = HeadlessPyGhidraLauncher(install_dir=GHIDRA)
    launcher.add_vmargs("-Xmx6g", "-Djava.io.tmpdir=" + tmp)
    launcher.start()
    import pyghidra
    from ghidra.features.bsim.query import GenSignatures
    from generic.lsh.vector import WeightedLSHCosineVectorFactory, VectorCompare
    from ghidra.xml import XmlPullParserFactory
    from ghidra.util.xml import SpecXmlUtils
    from ghidra.util.task import TaskMonitor
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from java.util import ArrayList

    results = {"binaries": {}, "pairs": []}
    vectors = {}  # (program, config) -> {name: (LSHVector, nfeatures)}
    factories = {}

    def factory_for(program):
        lid = program.getLanguageID()
        key = str(lid)
        if key not in factories:
            f = WeightedLSHCosineVectorFactory()
            rf = GenSignatures.getWeightsFile(lid, lid)
            parser = XmlPullParserFactory.create(rf, SpecXmlUtils.getXmlHandler(), False)
            f.readWeights(parser)
            factories[key] = (f, str(rf.getName()))
        return factories[key]

    for prog, configs in SETS.items():
        if only and prog not in only:
            continue
        for cfg in configs:
            path = os.path.join(CORPUS, cfg, "debug", prog)
            t0 = time.time()
            with pyghidra.open_program(path, project_location=tmp, project_name="p_" + prog + "_" + cfg.replace("/", "_"),
                                       analyze=True) as flat:
                program = flat.getCurrentProgram()
                t_analyze = time.time() - t0
                factory, wname = factory_for(program)
                gen = GenSignatures(False)
                gen.setVectorFactory(factory)
                gen.openProgram(program, None, None, None, None, None)
                fm = program.getFunctionManager()
                funcs = [f for f in fm.getFunctions(True) if not f.isThunk() and not f.isExternal()]
                jl = ArrayList()
                for f in funcs:
                    jl.add(f)
                t1 = time.time()
                gen.scanFunctions(jl.iterator(), len(funcs), TaskMonitor.DUMMY)
                t_sig = time.time() - t1
                man = gen.getDescriptionManager()
                byname = {}
                dup = set()
                nfeat = []
                it = man.listAllFunctions()
                while it.hasNext():
                    fd = it.next()
                    sr = fd.getSignatureRecord()
                    if sr is None:
                        continue
                    vec = sr.getLSHVector()
                    name = str(fd.getFunctionName())
                    n = int(vec.numEntries())
                    nfeat.append(n)
                    if name in byname:
                        dup.add(name)
                    byname[name] = (vec, n)
                for d in dup:
                    byname.pop(d, None)
                vectors[(prog, cfg)] = byname
                rec = {"functions": len(funcs), "signatured": len(nfeat), "unique_names": len(byname),
                       "analyze_s": round(t_analyze, 2), "signatures_s": round(t_sig, 2),
                       "ms_per_function_sig": round(1000 * t_sig / max(1, len(funcs)), 2),
                       "features_median": sorted(nfeat)[len(nfeat) // 2] if nfeat else 0,
                       "features_mean": round(sum(nfeat) / max(1, len(nfeat)), 1),
                       "weights": wname, "language": str(program.getLanguageID())}
                if (prog, cfg) in DECOMPILE_COST_ON:
                    opts = DecompileOptions()
                    opts.grabFromProgram(program)
                    ifc = DecompInterface()
                    ifc.setOptions(opts)
                    ifc.toggleCCode(True)
                    ifc.toggleSyntaxTree(False)
                    ifc.setSimplificationStyle("decompile")
                    ifc.openProgram(program)
                    t2 = time.time()
                    ok = 0
                    for f in funcs:
                        r = ifc.decompileFunction(f, 60, TaskMonitor.DUMMY)
                        if r is not None and r.decompileCompleted():
                            ok += 1
                    t_dec = time.time() - t2
                    ifc.dispose()
                    rec["decompile_s"] = round(t_dec, 2)
                    rec["ms_per_function_decompile"] = round(1000 * t_dec / max(1, len(funcs)), 2)
                    rec["decompiled_ok"] = ok
                    # signatures again, single-threaded, for a like-for-like cost
                    gen2 = GenSignatures(False)
                    gen2.setVectorFactory(factory)
                    gen2.openProgram(program, None, None, None, None, None)
                    t3 = time.time()
                    for f in funcs:
                        gen2.scanFunction(f)
                    t_sig1 = time.time() - t3
                    gen2.dispose()
                    rec["signatures_1thread_s"] = round(t_sig1, 2)
                    rec["ms_per_function_sig_1thread"] = round(1000 * t_sig1 / max(1, len(funcs)), 2)
                gen.dispose()
                results["binaries"][prog + "@" + cfg] = rec
                print(json.dumps({prog + "@" + cfg: rec}), flush=True)

    # Pairwise comparisons
    for prog, configs in SETS.items():
        if only and prog not in only:
            continue
        for i in range(len(configs)):
            for j in range(i + 1, len(configs)):
                a, b = configs[i], configs[j]
                va, vb = vectors.get((prog, a)), vectors.get((prog, b))
                if not va or not vb:
                    continue
                factory = factories[next(iter(factories))][0]
                common = sorted(set(va) & set(vb))
                bnames = list(vb)
                bvecs = [vb[n][0] for n in bnames]
                sims, top1, top1_thr, ident, sig_true = [], 0, 0, 0, []
                buckets = defaultdict(lambda: [0, 0])  # by feature-count bucket: [n, top1]
                for name in common:
                    av, an = va[name]
                    tv, tn = vb[name]
                    data = VectorCompare()
                    s_true = float(av.compare(tv, data))
                    sig = float(factory.calculateSignificance(data))
                    sims.append(s_true)
                    sig_true.append(sig)
                    if s_true >= 0.999999:
                        ident += 1
                    best_other = -1.0
                    for k, bn in enumerate(bnames):
                        if bn == name:
                            continue
                        s = float(av.compare(bvecs[k], VectorCompare()))
                        if s > best_other:
                            best_other = s
                    is_top1 = s_true > best_other
                    top1 += is_top1
                    top1_thr += is_top1 and s_true >= 0.7
                    bk = "<10" if an < 10 else ("10-29" if an < 30 else ("30-99" if an < 100 else ">=100"))
                    buckets[bk][0] += 1
                    buckets[bk][1] += is_top1
                n = len(common)
                sims_sorted = sorted(sims)
                rec = {"program": prog, "a": a, "b": b, "common": n,
                       "sim_mean": round(sum(sims) / max(1, n), 3),
                       "sim_median": round(sims_sorted[n // 2], 3) if n else None,
                       "frac_identical": round(ident / max(1, n), 3),
                       "frac_sim_ge_0.7": round(sum(1 for s in sims if s >= 0.7) / max(1, n), 3),
                       "frac_sim_ge_0.5": round(sum(1 for s in sims if s >= 0.5) / max(1, n), 3),
                       "top1": round(top1 / max(1, n), 3),
                       "top1_and_sim_ge_0.7": round(top1_thr / max(1, n), 3),
                       "signif_median": round(sorted(sig_true)[n // 2], 2) if n else None,
                       "top1_by_features": {k: f"{v[1]}/{v[0]}" for k, v in sorted(buckets.items())}}
                results["pairs"].append(rec)
                print(json.dumps(rec), flush=True)

    with open(os.path.join(OUT, "bsim_stability%s.json" % ("_" + "_".join(only) if only else "")), "w") as f:
        json.dump(results, f, indent=1)


if __name__ == "__main__":
    main()
