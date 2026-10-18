#!/bin/bash
# Builds the experiment's Ghidra root (docs/bytecode-lifting.md, "Experiments"):
# every processor of a Ghidra install linked in, copies of JVM and Dalvik whose
# compiler specs replace the dynamic "uponentry" injection with a static one,
# and the two sketch processors (PyVM, LuaVM) compiled to .sla.
#
#   make-root.sh <ghidra install> <out dir> [sleigh compiler]
#
# The compiler defaults to the install's support/sleigh (Java); a C++ one
# built from the fork's slgh_compile/slghparse/slghscan gives the same .sla.
set -euo pipefail
ghidra=$(realpath "$1")
out=$2
sleighc=${3:-$ghidra/support/sleigh}
here=$(dirname "$(realpath "$0")")

mkdir -p "$out/Ghidra/Processors"
out=$(realpath "$out")
for f in "$ghidra"/*; do b=$(basename "$f"); [ "$b" = Ghidra ] || ln -sfn "$f" "$out/$b"; done
for f in "$ghidra"/Ghidra/*; do b=$(basename "$f"); [ "$b" = Processors ] || ln -sfn "$f" "$out/Ghidra/$b"; done
for f in "$ghidra"/Ghidra/Processors/*; do
  b=$(basename "$f")
  case $b in JVM|Dalvik) ;; *) ln -sfn "$f" "$out/Ghidra/Processors/$b" ;; esac
done
for p in JVM Dalvik; do
  rm -rf "$out/Ghidra/Processors/$p"
  mkdir -p "$out/Ghidra/Processors/$p"
  cp -r "$ghidra/Ghidra/Processors/$p/data" "$out/Ghidra/Processors/$p/"
done

# What Ghidra's PcodeInjectLibraryJava and PcodeInjectLibraryDex compute per
# method, written out for the test methods: JVM copies two parameters from
# parameterSpace to localVariableArray (static int add(int,int), sum(int[])
# uses the first); Dalvik copies iv0, iv1 into v1, v2 (registers_size 3,
# ins_size 2).
python3 -I - "$out" <<'EOF'
import sys
root = sys.argv[1] + '/Ghidra/Processors'
old = '<pcode inject="uponentry" dynamic="true"/>'
patches = {
    'JVM/data/languages/JVM.cspec': '''<pcode inject="uponentry"><body><![CDATA[
  LVA = 0;
  t0:4 = *[parameterSpace]:4 LVA; *[localVariableArray]:4 LVA = t0; LVA = LVA + 4;
  t1:4 = *[parameterSpace]:4 LVA; *[localVariableArray]:4 LVA = t1; LVA = LVA + 4;
]]></body></pcode>''',
    'Dalvik/data/languages/Dalvik_Base.cspec': '''<pcode inject="uponentry"><body><![CDATA[
  v1 = iv0; v2 = iv1;
]]></body></pcode>''',
}
for path, new in patches.items():
    p = f'{root}/{path}'
    s = open(p).read()
    assert old in s, p
    open(p, 'w').write(s.replace(old, new))
EOF

for spec in PyVM:py312 LuaVM:lua54; do
  proc=${spec%%:*} name=${spec#*:}
  d="$out/Ghidra/Processors/$proc/data/languages"
  mkdir -p "$d"
  cp "$here/$name".{slaspec,cspec,pspec,ldefs} "$d/"
  if [ "$(basename "$sleighc")" = sleigh ]; then
    (cd "$d" && "$sleighc" "$name.slaspec" >/dev/null)
  else
    "$sleighc" "$d/$name.slaspec" "$d/$name.sla" >/dev/null
  fi
  [ -s "$d/$name.sla" ] || { echo "make-root.sh: $name.slaspec did not compile" >&2; exit 1; }
done
echo "$out"
