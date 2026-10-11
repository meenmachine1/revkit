#!/bin/sh
# Local CI: build and test, then gate revkit's output against Ghidra's
# reference exports for the corpus.
#
#   scripts/ci.sh [--asan] [--tsan] [--no-corpus] [--heldout | --heldout-only] [--firmware | --firmware-only]
#                 [--diff | --diff-only] [--asm | --asm-only] [--package | --package-only] [--save-baseline]
#
# The corpus, references and Ghidra's decompiler inputs come from
# scripts/phase0.sh (out/corpus, out/ref, out/ghidra-db). Seven gates fail if
# any agreement rate drops below its baseline in corpus/baselines/:
#   rk-lift.json             rk-lift's functions, instructions and p-code
#                            (functions from file metadata)
#   rk-lift-analyze.json     the same with --analyze (revkit::analysis
#                            function discovery)
#   rk-decomp.json           decompiled C under Ghidra's inputs (Phase 2 gate:
#                            c_ast is structurally identical C)
#   rk-decomp-refonly.json   decompiled C from the reference's function list
#                            and revkit's own loader only
#   rk-decomp-own.json       decompiled C from revkit alone (rk-lift --analyze
#                            --decompile: discovery, loader, debug info), on
#                            the functions both sides have; "functions" is
#                            the function-set overlap
#   rk-infer.json            inferred prototypes on the stripped corpus vs
#                            DWARF/PDB truth (tools/rk-infer/score.py, also
#                            failing if the gain over Ghidra's signatures at
#                            "signature" drops below 8 pp; the Phase 4 target,
#                            10 pp, is reported)
#   (and scripts/demangle_gate.py: corpus/cxx built with the host's C++
#   compilers, decompiled with and without the demangler analysis; every
#   mangled function named demangled, parameter counts no worse)
#   cparse-roundtrip.json    the C parser on the corpus programs' own sources
#                            per data model vs the binaries' DWARF/PDB: every
#                            named struct, union, enum and typedef's layout
#                            and typedef-free hash (scripts/cparse_roundtrip.py;
#                            the C library headers come from the corpus image,
#                            scripts/cparse-sysroots.sh)
# --save-baseline rewrites them after an intended improvement. Before the
# corpus gates, scripts/scale-check.sh bounds rk-lift's peak RSS on bash
# (corpus/large/manifest.json; skipped if that binary differs).
#
# --heldout also runs the same gates on the held-out set (docs/heldout.md:
# out/corpus-heldout, out/ref-heldout, out/ghidra-db-heldout; outputs under
# build/corpus-out/heldout; baselines corpus/baselines/heldout-*.json), the
# Phase 4 gate on the matchable subset. --heldout-only runs just those (no
# build, tests or tuning gates). Held-out results are for measurement only:
# never tune on them, and read summary rates, not per-function diffs.
#
# --firmware also gates revkit's firmware analysis per processor on the
# firmware corpus (docs/firmware.md: out/firmware-corpus, out/firmware-ref;
# scripts/firmware_score.py, outputs under build/corpus-out/firmware;
# baselines corpus/baselines/firmware-<arch>.json): function recall and
# precision vs Ghidra, recall vs DWARF, listing coverage and decompiled C
# structure; and on the same images with nothing said about them, that
# detection (docs/autodetect.md; scripts/detect_cases.py, detect_score.py,
# baseline corpus/baselines/detect-kit.json) names each one's processor and
# refuses what is no program, with no confident answer wrong.
# --firmware-only runs just that gate (no build or tests).
# --diff also gates binary diffing (docs/diff.md): scripts/diff_eval.py over
# family (a) adjacent source versions (out/corpus-diff: scripts/build-corpus.sh
# --diff), (b) -O0/-O2, (c) gcc/clang and (e) the firmware corpus, matching
# stripped binaries against DWARF truth and porting names through the
# backend. Family (a)'s auto-applied matches (confidence >= 0.95) must have
# precision >= 0.99 and recall >= 0.9; every family's figures are guarded by
# corpus/baselines/diff.json. Outputs under build/corpus-out/diff.
# --diff-only runs just that gate (no build or tests).
# --asm also gates the assembler (docs/patching.md): scripts/asm_roundtrip.py
# assembles every sampled instruction of the corpus, the firmware corpus and
# ARMv4T/ARMv7 builds of the firmware corpus's sources back to its bytes;
# per-language rates are guarded by corpus/baselines/asm.json, ARM and Thumb
# must round-trip 99% under 1 ms per line. Outputs under build/corpus-out/asm.
# --asm-only runs just that gate (no build or tests).
# --package also checks the release packaging (docs/packaging.md): that
# VERSION's copies agree (scripts/version.sh check) and build versions order
# correctly (scripts/version-test.sh), then scripts/package.sh
# --smoke builds the Linux bundle, the .deb and the SDK packages (the native
# part in Docker on Debian 12) and smoke-tests them on clean ubuntu:24.04 and
# debian:12 containers. About 20 minutes from a clean build-release/ with 4
# jobs, so it is not in the default run. Skipped, with a message, when
# Docker is not available. --package-only runs just that.
# RK_CI_JOBS caps parallel processes (default nproc).
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

presets="default"
corpus=1
save=0
heldout=0
firmware=0
diffgate=0
asmgate=0
asm_failed=0
package=0
package_status=0
tuning=1
for arg in "$@"; do
  case $arg in
    --asan) presets="$presets asan" ;;
    --tsan) presets="$presets tsan" ;;
    --no-corpus) corpus=0 ;;
    --save-baseline) save=1 ;;
    --heldout) heldout=1 ;;
    --heldout-only) heldout=1; tuning=0; presets= ;;
    --firmware) firmware=1 ;;
    --firmware-only) firmware=1; tuning=0; presets= ;;
    --diff) diffgate=1 ;;
    --diff-only) diffgate=1; tuning=0; presets= ;;
    --asm) asmgate=1 ;;
    --asm-only) asmgate=1; tuning=0; presets= ;;
    --package) package=1 ;;
    --package-only) package=1; tuning=0; corpus=0; presets= ;;
    *) echo "usage: $0 [--asan] [--tsan] [--no-corpus] [--heldout | --heldout-only] [--firmware | --firmware-only] [--diff | --diff-only] [--asm | --asm-only] [--package | --package-only] [--save-baseline]" >&2
       exit 2 ;;
  esac
done

for preset in $presets; do
  echo "== $preset: configure, build, test"
  cmake --preset "$preset" >/dev/null
  cmake --build --preset "$preset" -j "${RK_CI_JOBS:-$(nproc)}"
  ctest --preset "$preset" -j "${RK_CI_JOBS:-$(nproc)}"
done

if [ "$tuning" = 1 ]; then
  echo "== scale: rk-lift peak RSS on the smallest large binary"
  scripts/scale-check.sh "$root/build"
fi

if [ "$asmgate" = 1 ]; then
  echo "== asm: assembling the corpus's instructions back to their bytes (docs/patching.md)"
  for b in build/tools/rk-asm/rk-asm build/tools/rk-lift/rk-lift; do
    if [ ! -x "$b" ]; then
      echo "$b missing: build first (cmake --build --preset default)" >&2
      exit 1
    fi
  done
  asm_args="-j ${RK_CI_JOBS:-$(nproc)}"
  if [ "$save" = 1 ]; then
    python3 scripts/asm_roundtrip.py $asm_args --save-baseline || asm_failed=1
  else
    python3 scripts/asm_roundtrip.py $asm_args || asm_failed=1
  fi
fi

if [ "$package" = 1 ]; then
  echo "== package: version copies, Linux bundle, .deb, SDKs; smoke test on clean ubuntu:24.04 and debian:12"
  scripts/version.sh check || package_status=1
  scripts/version-test.sh >/dev/null || package_status=1
  if docker info >/dev/null 2>&1; then
    RK_CI_JOBS=${RK_CI_JOBS:-4} scripts/package.sh --smoke || package_status=1
  else
    echo "== package: Docker is not available; packaging check skipped"
  fi
fi

if [ "$corpus" != 1 ]; then
  [ "$asm_failed" = 0 ] || package_status=1
  exit $package_status
fi
jobs=${RK_CI_JOBS:-$(nproc)}
export JOBS=$jobs   # scripts/lift-corpus.sh

# Inputs (out/corpus, out/ref, out/ghidra-db) may be shared between worktrees,
# e.g. by symlinking out/ to one copy; outputs go under this worktree's build/
# so concurrent CI runs in different worktrees never write the same files.
# The corpus gates read set_corpus's choice: the tuning corpus (out/corpus,
# out/ref, out/ghidra-db) or the held-out set.
set_corpus() {
  case $1 in
    tuning) bins=out/corpus ref=out/ref db=out/ghidra-db outd=build/corpus-out bl=corpus/baselines/ what=corpus ;;
    heldout) bins=out/corpus-heldout ref=out/ref-heldout db=out/ghidra-db-heldout outd=build/corpus-out/heldout
             bl=corpus/baselines/heldout- what=held-out ;;
  esac
}

# gate <label> <out-dir> <baseline> [rk-lift options...]
gate() {
  label=$1 dir=$2 baseline=$3
  shift 3
  echo "== $what: $label vs Ghidra references"
  scripts/lift-corpus.sh "$bins" "$dir" build/tools/rk-lift/rk-lift "$@"
  compare "$dir" "$baseline" --by-group
}

# compare <candidate dir> <baseline> [refdiff args...]
compare() {
  cand=$1 baseline=$2
  shift 2
  if [ "$save" = 1 ]; then
    mkdir -p "$(dirname "$baseline")"
    python3 tools/refdiff/refdiff.py "$ref" "$cand" "$@" --save-baseline "$baseline"
  else
    python3 tools/refdiff/refdiff.py "$ref" "$cand" "$@" --baseline "$baseline"
  fi
}

status=$package_status
procs=$(( jobs / 2 ))
[ "$procs" -ge 1 ] || procs=1
c_args="--only c_tokens,c_ast,c_alpha --by-group --group-depth 2"

if [ "$tuning" = 1 ]; then
set_corpus tuning
if [ ! -d out/corpus ] || [ ! -d out/ref ]; then
  echo "out/corpus or out/ref missing: run scripts/phase0.sh first" >&2
  exit 1
fi
gate rk-lift build/corpus-out/revkit corpus/baselines/rk-lift.json || status=1
gate "rk-lift --analyze" build/corpus-out/revkit-analyze corpus/baselines/rk-lift-analyze.json --analyze || status=1

if [ ! -d out/ghidra-db ]; then
  echo "out/ghidra-db missing: run scripts/phase0.sh --skip-build, or" >&2
  echo "  \$(scripts/setup-pyghidra.sh) tools/ghidra-export/ghidra_dbexport.py --corpus out/corpus --out out/ghidra-db" >&2
  exit 1
fi
echo "== corpus: decompiled C under Ghidra's inputs"
scripts/decompile-corpus.sh --inputs out/ghidra-db --out build/corpus-out/revkit-decomp --in-order -P "$procs"
compare build/corpus-out/revkit-decomp corpus/baselines/rk-decomp.json $c_args || status=1
echo "== corpus: decompiled C from the reference's function list only"
scripts/decompile-corpus.sh --inputs none --ref out/ref --out build/corpus-out/revkit-decomp-refonly --in-order -P "$procs"
compare build/corpus-out/revkit-decomp-refonly corpus/baselines/rk-decomp-refonly.json $c_args || status=1
echo "== corpus: decompiled C from revkit's own inputs"
scripts/decompile-corpus.sh --inputs own --out build/corpus-out/revkit-decomp-own --in-order -P "$procs"
compare build/corpus-out/revkit-decomp-own corpus/baselines/rk-decomp-own.json \
  --only functions,c_tokens,c_ast,c_alpha --common-functions --by-group --group-depth 2 || status=1
echo "== corpus: inferred prototypes (rk-infer) vs DWARF/PDB truth, beside Ghidra's (Phase 4)"
infer_args="--out build/corpus-out/infer --truth build/corpus-out/infer-truth -P $procs -j 2 --target-gain 10"
if [ "$save" = 1 ]; then
  python3 tools/rk-infer/score.py $infer_args --save-baseline corpus/baselines/rk-infer.json || status=1
else
  python3 tools/rk-infer/score.py $infer_args --baseline corpus/baselines/rk-infer.json --min-gain 8 || status=1
fi
echo "== corpus: C++ names and prototypes with the demangler analysis vs without, against DWARF (docs/demangle.md)"
python3 scripts/demangle_gate.py -j "$jobs" --out build/corpus-out/demangle || status=1
echo "== corpus: C parser round trip (the programs' sources vs their DWARF/PDB layouts and hashes)"
if [ "$save" = 1 ]; then
  python3 scripts/cparse_roundtrip.py -j "$procs" --save-baseline corpus/baselines/cparse-roundtrip.json || status=1
else
  python3 scripts/cparse_roundtrip.py -j "$procs" --baseline corpus/baselines/cparse-roundtrip.json || status=1
fi
fi

if [ "$heldout" = 1 ]; then
  set_corpus heldout
  for d in "$bins" "$ref" "$db"; do
    if [ ! -d "$d" ]; then
      echo "$d missing: see docs/heldout.md (scripts/build-corpus.sh --heldout, ghidra_export.py)" >&2
      exit 1
    fi
  done
  gate rk-lift "$outd/revkit" "${bl}rk-lift.json" || status=1
  gate "rk-lift --analyze" "$outd/revkit-analyze" "${bl}rk-lift-analyze.json" --analyze || status=1
  echo "== held-out: decompiled C under Ghidra's inputs"
  # A binary rk-lift fails on (docs/heldout.md, known bugs) scores as all
  # disagreement and the rest still count; the baseline judges the result.
  scripts/decompile-corpus.sh --corpus "$bins" --inputs "$db" --out "$outd/revkit-decomp" --in-order -P "$procs" \
    --timeout 1800 ||
    echo "(held-out: continuing; failed binaries count as disagreement)"
  compare "$outd/revkit-decomp" "${bl}rk-decomp.json" $c_args || status=1
  echo "== held-out: decompiled C from revkit's own inputs"
  scripts/decompile-corpus.sh --corpus "$bins" --inputs own --ref "$ref" --out "$outd/revkit-decomp-own" \
    --in-order -P "$procs" --timeout 1800 || echo "(held-out: continuing; failed binaries count as disagreement)"
  compare "$outd/revkit-decomp-own" "${bl}rk-decomp-own.json" \
    --only functions,c_tokens,c_ast,c_alpha --common-functions --by-group --group-depth 2 || status=1
  echo "== held-out: inferred prototypes vs DWARF/PDB truth, beside Ghidra's (Phase 4 gate: matchable subset)"
  infer_args="--corpus $bins --ref $ref --out $outd/infer --truth $outd/infer-truth -P $procs -j 2"
  infer_args="$infer_args --gate-subset matchable --target-gain 10 --keep-going --timeout 5400"
  if [ "$save" = 1 ]; then
    python3 tools/rk-infer/score.py $infer_args --save-baseline "${bl}rk-infer.json" || status=1
  else
    python3 tools/rk-infer/score.py $infer_args --baseline "${bl}rk-infer.json" || status=1
  fi
fi
if [ "$firmware" = 1 ]; then
  echo "== firmware: revkit's analysis of raw images vs Ghidra's, per processor"
  for d in out/firmware-corpus out/firmware-ref; do
    if [ ! -d "$d" ]; then
      echo "$d missing: see docs/firmware.md (scripts/build-firmware-corpus.sh, ghidra_export.py --firmware-corpus)" >&2
      exit 1
    fi
  done
  if [ ! -x build/tools/rk-lift/rk-lift ]; then
    echo "build/tools/rk-lift/rk-lift missing: build first (cmake --build --preset default)" >&2
    exit 1
  fi
  fw_args="--corpus out/firmware-corpus --ref out/firmware-ref --out build/corpus-out/firmware -j $jobs"
  if [ "$save" = 1 ]; then
    python3 scripts/firmware_score.py $fw_args --save-baseline corpus/baselines || status=1
  else
    python3 scripts/firmware_score.py $fw_args --baseline-dir corpus/baselines || status=1
  fi
  echo "== firmware: detecting each image's processor and layout from its bytes (docs/autodetect.md)"
  python3 scripts/detect_cases.py --corpus out/firmware-corpus --out build/detect-cases || status=1
  # Each detection uses 8 threads.
  detect_args="--cases build/detect-cases --out build/detect-out -j $(( (jobs + 7) / 8 ))"
  if [ "$save" = 1 ]; then
    python3 scripts/detect_score.py $detect_args --save-baseline corpus/baselines/detect-kit.json || status=1
  else
    python3 scripts/detect_score.py $detect_args --baseline corpus/baselines/detect-kit.json || status=1
  fi
fi
if [ "$diffgate" = 1 ]; then
  echo "== diff: matching versions of a program against DWARF truth (docs/diff.md)"
  for d in out/corpus-diff out/firmware-corpus; do
    if [ ! -d "$d" ]; then
      echo "$d missing: scripts/build-corpus.sh --diff (out/corpus-diff), scripts/build-firmware-corpus.sh" >&2
      exit 1
    fi
  done
  for b in build/tools/rk-diff/rk-diff build/tools/rk-debuginfo/rk-debuginfo; do
    if [ ! -x "$b" ]; then
      echo "$b missing: build first (cmake --build --preset default)" >&2
      exit 1
    fi
  done
  diff_jobs=$(( jobs / 2 ))
  [ "$diff_jobs" -ge 1 ] || diff_jobs=1
  diff_args="--families a,b,c,e -j $diff_jobs --gate"
  if [ "$save" = 1 ]; then
    python3 scripts/diff_eval.py $diff_args --save-baseline corpus/baselines/diff.json || status=1
  else
    python3 scripts/diff_eval.py $diff_args --baseline corpus/baselines/diff.json || status=1
  fi
fi
[ "$asm_failed" = 0 ] || status=1
exit $status
