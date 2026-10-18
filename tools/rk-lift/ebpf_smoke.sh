#!/bin/sh
# An eBPF object built by clang (EM_BPF, 247) loads with Ghidra's eBPF
# language picked from the ELF header, with no --lang, in both byte
# orders, and its function decompiles (docs/bytecode-lifting.md, E7).
# Exits 77 (skip) when clang can't target BPF.
set -eu

rk_lift=$1
ghidra_root=$2
workdir=$3
clang=${4:-clang}

command -v "$clang" >/dev/null 2>&1 || exit 77
mkdir -p "$workdir"
cat > "$workdir/filt.c" <<'SRC'
struct pkt { unsigned int len; unsigned int proto; unsigned int flags; };
__attribute__((section("socket"), used))
int filt(struct pkt *p) {
  if (p->proto != 6) return 0;
  return p->len > 64 ? (int)(p->flags & 0xff) : 0;
}
char _license[] __attribute__((section("license"), used)) = "GPL";
SRC
"$clang" -O2 -target bpfel -c "$workdir/filt.c" -o "$workdir/filt-le.o" 2>/dev/null || exit 77
"$clang" -O2 -target bpfeb -c "$workdir/filt.c" -o "$workdir/filt-be.o" 2>/dev/null || exit 77

for order in le be; do
  "$rk_lift" --ghidra "$ghidra_root" --name filt --decompile --no-instructions \
    -o "$workdir/$order.json" "$workdir/filt-$order.o"
  grep -q '"name":"filt"' "$workdir/$order.json"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$workdir/$order.json" "$order" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
want = "eBPF:%s:64:default" % sys.argv[2].upper()
lang = d["binary"].get("language", "")
assert lang.startswith(want), (lang, want)
fs = {f["name"]: f for f in d["functions"]}
c = fs["filt"]["decompiled_c"]
assert "return" in c and "6" in c, c
PY
  fi
done
