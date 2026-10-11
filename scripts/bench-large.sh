#!/bin/sh
# Scale benchmarks on large real binaries (docs/scale.md).
#
#   scripts/bench-large.sh [--only id,id] [--stages lift,analyze,decompile,daemon]
#                          [-j N] [--out dir] [--rk-lift path] [--rk-daemon path]
#                          [--timeout seconds] [--mem-cap MB] [--keep]
#   scripts/bench-large.sh --report [--out dir]
#
# Binaries come from corpus/large/manifest.json (path and sha256 on this
# host; they are not committed). A binary that is missing or whose sha256
# differs is skipped with a note. For each binary and stage it records wall
# time, peak RSS, CPU time and utilisation and the 1-minute load average
# (/usr/bin/time), plus rk-lift's --stats or the cold-start timeline, as one
# JSON line in <out>/results.jsonl. --report prints them as a Markdown table.
#
# Stages:
#   lift       rk-lift (functions from file metadata, every instruction)
#   analyze    rk-lift --analyze (function discovery, every instruction)
#   decompile  rk-lift --analyze --decompile -j N (also every instruction)
#   daemon     rk-daemon + Python SDK: import, first listing page, first
#              decompile (scripts/bench-coldstart.py)
# -j N (default 8) goes to every rk-lift run; outputs are written to <out>
# and deleted unless --keep. --mem-cap runs each stage in a systemd user
# scope with that memory limit and no swap (exit 137 = over the cap), so a
# run that would need tens of GB fails fast instead of pushing a shared
# machine into swap. The machine is shared: note the load column.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
manifest=$root/corpus/large/manifest.json
out=$root/build/bench-large
rk_lift=$root/build/tools/rk-lift/rk-lift
rk_daemon=$root/build/tools/rk-daemon/rk-daemon
python=${REVKIT_PYTHON:-$HOME/.cache/revkit/venv/bin/python}
only=""
stages="lift,analyze,decompile,daemon"
jobs=8
timeout_s=7200
mem_cap=""
keep=0
report=0

while [ $# -gt 0 ]; do
  case $1 in
    --only) only=$2; shift 2 ;;
    --stages) stages=$2; shift 2 ;;
    -j) jobs=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --rk-lift) rk_lift=$2; shift 2 ;;
    --rk-daemon) rk_daemon=$2; shift 2 ;;
    --timeout) timeout_s=$2; shift 2 ;;
    --mem-cap) mem_cap=$2; shift 2 ;;
    --keep) keep=1; shift ;;
    --report) report=1; shift ;;
    *) sed -n '2,30p' "$0" >&2; exit 2 ;;
  esac
done

mkdir -p "$out"
results=$out/results.jsonl

if [ "$report" = 1 ]; then
  python3 - "$results" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
print("| binary | stage | wall s | peak RSS MB | CPU s | CPU % | load | notes |")
print("| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |")
for r in rows:
    s = r.get("stats") or {}
    notes = []
    if "functions" in s: notes.append("%d functions" % s["functions"])
    if s.get("instructions"): notes.append("%d instructions" % s["instructions"])
    if s.get("decompile_s"): notes.append("decompile %.1f s" % s["decompile_s"])
    if "decompile_s" in r and "import_s" in r:
        notes.append("import %.2f s, listing %.2f s, functions %.2f s, decompile %s %.2f s (%s ms)" % (
            r["import_s"], r["listing_s"], r["functions_s"], r["function"], r["decompile_s"], r["decompile_ms"]))
    if r.get("rc", 0) == 137 and r.get("mem_cap_mb"): notes.append("killed at the %d MB cap" % r["mem_cap_mb"])
    elif r.get("rc", 0) == 124: notes.append("timed out")
    elif r.get("rc", 0) != 0: notes.append("exit %s" % r["rc"])
    print("| %s | %s | %.2f | %d | %.1f | %s | %.1f | %s |" % (
        r["id"], r["stage"], r["wall_s"], r["peak_rss_mb"], r["cpu_s"], r["cpu_pct"], r["load"], "; ".join(notes)))
PY
  exit 0
fi

[ -x "$rk_lift" ] || { echo "no rk-lift at $rk_lift (cmake --build --preset default)" >&2; exit 1; }

# id <tab> path <tab> sha256 for the selected binaries.
list=$(python3 - "$manifest" "$only" <<'PY'
import json, sys
only = set(filter(None, sys.argv[2].split(",")))
for b in json.load(open(sys.argv[1]))["binaries"]:
    if not only or b["id"] in only:
        print("%s\t%s\t%s" % (b["id"], b["path"], b["sha256"]))
PY
)

# run <id> <stage> <stats file or ""> cmd...: time cmd and append a result line.
run() {
  id=$1 stage=$2 stats=$3
  shift 3
  tf=$out/.time.$$
  set +e
  if [ -n "$mem_cap" ]; then
    set -- systemd-run --user --scope --quiet -p "MemoryMax=${mem_cap}M" -p MemorySwapMax=0 "$@"
  fi
  timeout "$timeout_s" /usr/bin/time -o "$tf" -f '%e %M %U %S %P' "$@" >"$out/$id.$stage.stdout" 2>"$out/$id.$stage.stderr"
  rc=$?
  set -e
  load=$(cut -d' ' -f1 /proc/loadavg)
  # The last line: time prefixes "Command exited with non-zero status N"
  # or "Command terminated by signal N".
  read -r wall rss user sys pct <<EOF || true
$(tail -n 1 "$tf" 2>/dev/null)
EOF
  rm -f "$tf"
  python3 - "$results" "$id" "$stage" "$rc" "$wall" "$rss" "$user" "$sys" "$pct" "$load" "$stats" "$jobs" "$mem_cap" <<'PY'
import json, sys
results, id_, stage, rc, wall, rss, user, sys_, pct, load, stats, jobs, cap = sys.argv[1:]
def num(x, kind=float):
    try:
        return kind(x)
    except ValueError:
        return kind(0)
wall, rss, user, sys_ = num(wall), num(rss, int), num(user), num(sys_)
row = {"mem_cap_mb": int(cap) if cap else None, "id": id_, "stage": stage, "rc": int(rc), "wall_s": wall, "peak_rss_mb": rss // 1024,
       "cpu_s": round(user + sys_, 2), "cpu_pct": pct, "load": float(load), "jobs": int(jobs)}
if stats:
    try:
        row["stats"] = json.load(open(stats))
    except (OSError, ValueError):
        pass
with open(results, "a") as f:
    f.write(json.dumps(row) + "\n")
print("%-18s %-10s rc=%s wall=%ss rss=%dMB cpu=%s load=%s" % (id_, stage, rc, wall, row["peak_rss_mb"], pct, load))
PY
}

echo "$list" | while IFS='	' read -r id path sha; do
  [ -n "$id" ] || continue
  if [ ! -f "$path" ]; then
    echo "$id: $path missing, skipped"
    continue
  fi
  have=$(sha256sum "$path" | cut -c1-64)
  if [ "$have" != "$sha" ]; then
    echo "$id: $path has sha256 $have, manifest says $sha: skipped"
    continue
  fi
  for stage in $(echo "$stages" | tr ',' ' '); do
    json=$out/$id.$stage.json
    st=$out/$id.$stage.stats.json
    case $stage in
      lift) run "$id" lift "$st" "$rk_lift" -j "$jobs" --stats "$st" -o "$json" "$path" ;;
      analyze) run "$id" analyze "$st" "$rk_lift" --analyze -j "$jobs" --stats "$st" -o "$json" "$path" ;;
      decompile) run "$id" decompile "$st" "$rk_lift" --analyze --decompile -j "$jobs" --stats "$st" -o "$json" "$path" ;;
      daemon)
        run "$id" daemon "$st" "$python" "$root/scripts/bench-coldstart.py" --daemon "$rk_daemon" --json "$st" "$path"
        python3 - "$results" "$st" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
try:
    rows[-1].update(json.load(open(sys.argv[2])))
except (OSError, ValueError):
    pass
open(sys.argv[1], "w").write("".join(json.dumps(r) + "\n" for r in rows))
PY
        ;;
      *) echo "unknown stage $stage" >&2; exit 2 ;;
    esac
    [ "$keep" = 1 ] || rm -f "$json"
  done
done
