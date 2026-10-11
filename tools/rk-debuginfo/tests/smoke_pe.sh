#!/bin/sh
# rk-debuginfo on a PE fixture whose debug directory names its PDB by file
# name only: the PDB is found beside the binary, prototypes come from it,
# output is byte-identical across runs, and a PDB that doesn't match the
# image is refused. Exits 77 (skip) if the fixture wasn't built.
set -eu
tool=$1 exe=$2 python=$3 out=$4
[ -f "$exe" ] || exit 77
mkdir -p "$out/copy" "$out/stale"
cp "$exe" "${exe%.exe}.pdb" "$out/copy/"
copy="$out/copy/$(basename "$exe")"
# Run from elsewhere so only the beside-the-binary lookup can succeed.
cd "$out"
"$tool" --path fixture.exe "$copy" > a.json 2> a.err
"$tool" --path fixture.exe "$copy" > b.json
cmp a.json b.json
"$tool" --no-dwarf --path fixture.exe "$copy" > pdb.json
"$tool" --no-pdb --path fixture.exe "$copy" > dwarf.json 2>/dev/null
"$python" - a.json pdb.json dwarf.json <<'PY'
import json, sys
doc, pdb, dwarf = (json.load(open(p)) for p in sys.argv[1:4])
assert doc["format_version"] == 1 and doc["producer"].startswith("revkit-"), doc
assert doc["binary"]["compiler"] == "clangwindows", doc["binary"]
assert doc["binary"]["language"] == "x86:LE:64:default", doc["binary"]
fns = {f["name"]: f for f in pdb["functions"]}
expect = {
    "main": "int main(int argc, char * * argv)",
    "sum_ints": "long sum_ints(int count, ...)",
    "fold": "int fold(int * values, ulonglong n, _func_int_int_int * f, int init)",
    "matmul": "void matmul(int[4] * a, int[4] * m, ulong rows)",
    "pack_flags": "uint pack_flags(flags f)",
    "point_add": "point point_add(point a, point b)",
    "no_args": "void no_args(void)",
}
for name, proto in expect.items():
    assert fns[name]["prototype"] == proto, (name, fns[name]["prototype"])
# PDB plus the image's DWARF (the mingw runtime) covers more functions than
# either; where both describe one, the PDB's typedef-free prototype wins.
merged = {f["entry"]: f for f in doc["functions"]}
assert len(merged) > len(pdb["functions"]), (len(merged), len(pdb["functions"]))
for f in pdb["functions"]:
    assert merged[f["entry"]] == f, f
d = {f["entry"]: f for f in dwarf["functions"]}
assert d[fns["fold"]["entry"]]["prototype"] == "int fold(int * values, size_t n, binop f, int init)"
entries = [int(f["entry"], 16) for f in doc["functions"]]
assert entries == sorted(entries) and len(set(entries)) == len(entries)
print("ok:", len(pdb["functions"]), "PDB functions,", len(merged), "in all")
PY
# A PDB from another build (another fixture's) is skipped, with a warning.
stale_pdb="stale/$(basename "${exe%.exe}").pdb"
other=$(ls "$(dirname "$exe")"/*.pdb | grep -v "/$(basename "${exe%.exe}").pdb$" | head -n 1)
cp "$copy" stale/
cp "$other" "$stale_pdb"
"$tool" --no-dwarf "stale/$(basename "$exe")" > stale.json 2> stale.err
grep -q "doesn't match the image" stale.err
grep -q "no PDB found" stale.err
"$python" -c "import json; assert json.load(open('stale.json'))['functions'] == []"
# Unless asked for explicitly.
"$tool" --no-dwarf --pdb "$stale_pdb" "stale/$(basename "$exe")" > forced.json 2> forced.err
grep -q "doesn't match the image" forced.err
# Not a PDB at all.
printf 'Microsoft C/C++ MSF 7.00\r\n\032DS\0\0\0' > "$stale_pdb"
"$tool" --no-dwarf "stale/$(basename "$exe")" > junk.json 2> junk.err
grep -q "no PDB found" junk.err
echo "ok: mismatched and broken PDBs refused"
