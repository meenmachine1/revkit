#!/bin/sh
# Decompile every corpus binary in process with rk-lift, under the
# reference's conditions, into reference-format JSON (functions with
# decompiled_c, no instructions).
#
#   scripts/decompile-corpus.sh [options]
#     --corpus DIR   corpus binaries (default out/corpus)
#     --inputs DIR   Ghidra's decompiler inputs, from
#                    tools/ghidra-export/ghidra_dbexport.py (default out/ghidra-db);
#                    "none" takes only the function list from --ref; "own"
#                    uses nothing from Ghidra: revkit's function discovery,
#                    loader and debug info (rk-lift --analyze --decompile)
#     --ref DIR      reference exports, for --inputs none (default out/ref)
#     --out DIR      output (default out/revkit-decomp)
#     --rk-lift EXE  (default build/tools/rk-lift/rk-lift)
#     -P N           binaries decompiled at once (default 4)
#     -j N           decompiler threads per binary (default nproc / P)
#     --in-order     decompile each binary's functions in address order on one
#                    thread, the sequence Ghidra uses (implies -j 1)
#     --rk-args ARGS more rk-lift options (with --inputs own: --no-own KIND to
#                    leave out one kind of revkit fact)
#     --timeout S    give up on a binary after S seconds (counts as failed)
#     --dump-inputs  also write each binary's decompiler inputs to
#                    <out>/<dir>/_<name>.inputs.json
#
# Prints the wall-clock time of the whole run; per-binary timings go to
# <out>/<dir>/_<name>.stats.json (refdiff skips files starting with "_").
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
corpus=$root/out/corpus
inputs=$root/out/ghidra-db
ref=$root/out/ref
out=$root/out/revkit-decomp
rk_lift=$root/build/tools/rk-lift/rk-lift
procs=4
threads=
order=
rk_args=
dump=
failed=0
limit=
while [ $# -gt 0 ]; do
  case $1 in
    --corpus) corpus=$2; shift 2 ;;
    --inputs) inputs=$2; shift 2 ;;
    --ref) ref=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --rk-lift) rk_lift=$2; shift 2 ;;
    -P) procs=$2; shift 2 ;;
    -j) threads=$2; shift 2 ;;
    --in-order) order=--in-order; threads=1; shift ;;
    --rk-args) rk_args=$2; shift 2 ;;
    --dump-inputs) dump=1; shift ;;
    --timeout) limit="timeout $2"; shift 2 ;;
    *) sed -n '2,24p' "$0" >&2; exit 2 ;;
  esac
done
[ -n "$threads" ] || threads=$(( $(nproc) / procs ))
[ "$threads" -ge 1 ] || threads=1

corpus=$(realpath "$corpus")
rk_lift=$(realpath "$rk_lift")
out=$(realpath -m "$out")
if [ "$inputs" = none ]; then
  ref=$(realpath "$ref")
  mode=ref
elif [ "$inputs" = own ]; then
  ref=$(realpath "$ref")
  mode=own
else
  inputs=$(realpath "$inputs")
  mode=inputs
fi

rm -rf "$out"
mkdir -p "$out"
cd "$corpus"
# Most code first, so the slowest binaries don't straggle at the end: bytes
# in function bodies, from the function list, else the file size.
python3 - "$corpus" "$( [ $mode = inputs ] && echo "$inputs" || echo "$ref" )" <<'PY' |
import json, os, sys
corpus, src = sys.argv[1:3]
with open(os.path.join(corpus, "manifest.json")) as f:
    rels = [b["path"] for b in json.load(f)["binaries"]]
def work(rel):
    try:
        with open(os.path.join(src, rel + ".json")) as f:
            fs = json.load(f)["functions"]
        return sum(int(b, 16) - int(a, 16) + 1 for x in fs for a, b in x.get("body", []))
    except (OSError, ValueError, KeyError):
        return os.path.getsize(os.path.join(corpus, rel))
for rel in sorted(rels, key=lambda r: (-work(r), r)):
    print(rel)
PY
  cat > "$out/_order.txt"
start=$(date +%s.%N)
xargs -P "$procs" -I{} sh -c '
    rel=$1 out=$2 exe=$3 mode=$4 src=$5 threads=$6 order=$7 extra=$8 dump=$9 limit=${10}
    mkdir -p "$(dirname "$out/$rel")"
    case $mode in
      inputs) from="--inputs $src/$rel.json" ;;
      own) from="--analyze" ;;
      *) from="--functions-from $src/$rel.json" ;;
    esac
    [ -z "$dump" ] || extra="$extra --dump-inputs $(dirname "$out/$rel")/_$(basename "$rel").inputs.json"
    $limit "$exe" --decompile --no-instructions -j "$threads" $order $from $extra --name "$rel" \
      --stats "$(dirname "$out/$rel")/_$(basename "$rel").stats.json" -o "$out/$rel.json" "$rel" 2>"$out/$rel.log" ||
      { echo "rk-lift failed: $rel (see $out/$rel.log)" >&2; rm -f "$out/$rel.json"; exit 1; }
  ' _ {} "$out" "$rk_lift" "$mode" "$( [ $mode = inputs ] && echo "$inputs" || echo "$ref" )" "$threads" "$order" \
  "$rk_args" "$dump" "$limit" \
  < "$out/_order.txt" || failed=1
end=$(date +%s.%N)
n=$(find "$out" -name '*.json' ! -name '_*' | wc -l)
printf 'decompiled %d binaries into %s in %.1f s wall (%d at once, %d threads each)\n' \
  "$n" "$out" "$(echo "$end - $start" | bc)" "$procs" "$threads"
# A binary rk-lift fails on has no output (refdiff counts all of its
# functions as disagreement); the others still run, and the exit status is 1.
[ "$failed" = 0 ] || { echo "decompile-corpus: rk-lift failed on some binaries (above)" >&2; exit 1; }
