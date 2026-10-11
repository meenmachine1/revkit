#!/bin/sh
# rk-dwarf on a compiled fixture: valid reference JSON, expected prototypes,
# byte-identical across runs.
set -eu
rk_dwarf=$1 fixture=$2 python=$3 out=$4
mkdir -p "$out"
"$rk_dwarf" --path fixture "$fixture" > "$out/a.json"
"$rk_dwarf" --path fixture "$fixture" > "$out/b.json"
cmp "$out/a.json" "$out/b.json"
"$python" - "$out/a.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc["format_version"] == 1 and doc["producer"].startswith("revkit-"), doc
fns = {f["name"]: f for f in doc["functions"]}
expect = {
    "main": "int main(int argc, char * * argv)",
    "sum_ints": "long sum_ints(int count, ...)",
    "fold": "int fold(int * values, size_t n, binop f, int init)",
    "matmul": "void matmul(int[4] * a, int[4] * m, ulong_t rows)",
    "pack_flags": "uint pack_flags(flags f)",
    "no_args": "void no_args(void)",
}
for name, proto in expect.items():
    assert fns[name]["prototype"] == proto, (name, fns[name]["prototype"])
entries = [int(f["entry"], 16) for f in doc["functions"]]
assert entries == sorted(entries) and len(set(entries)) == len(entries)
for f in doc["functions"]:
    first, last = (int(x, 16) for x in f["body"][0])
    assert first == int(f["entry"], 16) and last >= first, f
print("ok:", len(fns), "functions")
PY
