#!/bin/sh
# Compile a small program, run rk-lift on it twice, and check the output is
# deterministic, valid JSON, and carries the expected functions and p-code.
# Exits 77 (skip) when the compiler is missing.
set -eu

rk_lift=$1
ghidra_root=$2
workdir=$3
cc=${4:-cc}

command -v "$cc" >/dev/null 2>&1 || exit 77
mkdir -p "$workdir"
cat > "$workdir/prog.c" <<'SRC'
int add(int a, int b) { return a + b; }
int main(int argc, char **argv) { return add(argc, argv[0][0]); }
SRC
"$cc" -O1 -fno-inline "$workdir/prog.c" -o "$workdir/prog"

"$rk_lift" --ghidra "$ghidra_root" --name prog -o "$workdir/a.json" "$workdir/prog"
"$rk_lift" --ghidra "$ghidra_root" --name prog -o "$workdir/b.json" "$workdir/prog"
cmp "$workdir/a.json" "$workdir/b.json"
# The second pass on several threads writes the same bytes.
RK_LIFT_BYTES_PER_ENGINE=32 "$rk_lift" --ghidra "$ghidra_root" --name prog -j 3 -o "$workdir/b.json" "$workdir/prog"
cmp "$workdir/a.json" "$workdir/b.json"

grep -q '"name":"main"' "$workdir/a.json"
grep -q '"name":"add"' "$workdir/a.json"
grep -q '"RETURN"' "$workdir/a.json"
grep -q '"name":".text"' "$workdir/a.json"
grep -q '"format_version":1' "$workdir/a.json"

if command -v python3 >/dev/null 2>&1; then
  python3 - "$workdir/a.json" "$(dirname "$0")/../refdiff" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[2])
import refformat
text = open(sys.argv[1]).read()
d = json.loads(text)
# The streamed document is byte-identical to the canonical layout.
assert refformat.dumps(d) == text, "not in refformat.dumps() layout"
assert d["binary"]["path"] == "prog"
for key in ("memory", "functions", "instructions"):
    assert d[key], key
starts = [int(m["start"], 16) for m in d["memory"]]
assert starts == sorted(starts)
entries = [int(f["entry"], 16) for f in d["functions"]]
assert entries == sorted(entries)
addrs = [int(i["addr"], 16) for i in d["instructions"]]
assert addrs == sorted(addrs) and len(addrs) == len(set(addrs))
# Every instruction lies inside some function body.
bodies = [(int(a, 16), int(b, 16)) for f in d["functions"] for a, b in f["body"]]
assert all(any(a <= x <= b for a, b in bodies) for x in addrs)
for i in d["instructions"]:
    for op in i["pcode"]:
        assert "out" in op and "in" in op
PY
fi

# Decompile in process: from its own symbols, then with the function list
# taken from the first run's output (reference format), on several threads.
"$rk_lift" --ghidra "$ghidra_root" --name prog --decompile --no-instructions -o "$workdir/c.json" "$workdir/prog"
"$rk_lift" --ghidra "$ghidra_root" --name prog --decompile --no-instructions -j 3 \
  --functions-from "$workdir/a.json" --stats "$workdir/c2.stats.json" -o "$workdir/c2.json" "$workdir/prog"
grep -q '"decompiled_c"' "$workdir/c.json"
grep -q '"decompiled_c"' "$workdir/c2.json"
! grep -q '"instructions"' "$workdir/c2.json"
grep -q '"decompile_s"' "$workdir/c2.stats.json"
if command -v python3 >/dev/null 2>&1; then
  python3 - "$workdir/c2.json" <<'PY'
import json, sys
fs = {f["name"]: f for f in json.load(open(sys.argv[1]))["functions"]}
c = fs["main"]["decompiled_c"]
assert "main(" in c and "add(" in c, c  # the callee prints by name
assert "return" in fs["add"]["decompiled_c"]
PY
fi
