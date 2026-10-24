#!/bin/sh
# Typecheck, build the bundle and run the end-to-end test (e2e/run.ts).
# Used by CTest (ui_e2e); also runnable by hand from ui/:
#
#   RK_DAEMON=../build/tools/rk-daemon/rk-daemon e2e/run.sh
#
# RK_WEB_ROOT is where the bundle is built (default: a temporary directory,
# so the source tree's dist/ is left alone).
#
# The whole run needs more than 6 GB (its daemons load many processor
# specifications and programs; Chrome holds every page), so it runs in
# parts, one after another, each with the two setup checks (RK_E2E_ONLY
# regexes; e2e/run.ts skips the modules a part doesn't want). Each part runs
# in its own memory-capped scope when systemd-run --user works:
#   RK_E2E_MEMORY_MAX  the cap (default 6G; "none": no scope)
#   RK_E2E_SLICE       a systemd slice the scopes go in (revkit-work.slice:
#                      a cap shared with other work); default none
#   RK_E2E_ONLY        set by hand: that one filtered run instead of the parts
set -eu
cd "$(dirname "$0")/.."
[ -d node_modules/playwright ] || { echo "ui/node_modules missing: run npm ci in ui/" >&2; exit 1; }
out=${RK_WEB_ROOT:-}
tmp=""
if [ -z "$out" ]; then
  tmp=$(mktemp -d)
  out=$tmp/dist
  trap 'rm -rf "$tmp"' EXIT
fi
node_modules/.bin/tsc --noEmit -p .
node_modules/.bin/vite build --logLevel warn --outDir "$out" --emptyOutDir
export RK_WEB_ROOT="$out"

if [ -n "${RK_E2E_ONLY:-}" ]; then
  exec node_modules/.bin/tsx e2e/run.ts
fi

# A part runs in a scope capped at RK_E2E_MEMORY_MAX when the user's systemd
# can make one; else as it is.
cap=${RK_E2E_MEMORY_MAX:-6G}
slice=${RK_E2E_SLICE:+--slice=$RK_E2E_SLICE}
scope=""
if [ "$cap" != none ] && command -v systemd-run >/dev/null 2>&1 &&
   systemd-run --user $slice --scope --quiet -p MemoryMax="$cap" true >/dev/null 2>&1; then
  scope="systemd-run --user $slice --scope --quiet -p MemoryMax=$cap -p MemorySwapMax=0"
fi

setup='^(open: the program|second page)'
a1='navigate|functions panel|xrefs|decompiler <-> listing|rename|right-click|set type|provenance|comment|undo|header rows|a name on|flow|retype a|function bounds|notes|listing edit|auto-struct:|search|equates|references|hover|type-uses|find uses|signature override|byte viewer|navigation|go to|overview|copy special|fields|presence|open:|listing:|emulator|debugger|open dialog'
a2='raw detection|graph|call graph|strings window|types|retype with|plugins|layout|compare|programs|functions:|large tables|file chooser|accessibility|keyboard'
b1='project tree|project archive|file system browser|android|crash dumps|scripts|console'
b2='patching|memory map|demangled|class hierarchy|Load PDB|project types|archives|Function ID'
failed=""
for part in A1 A2 B1 B2 B3; do
  case $part in
    A1) re="$setup|^($a1)" ;;
    A2) re="$setup|^($a2)" ;;
    B1) re="$setup|^($b1)" ;;
    B2) re="$setup|^($b2)" ;;
    B3) re="$setup|^(?!($a1|$a2|$b1|$b2))" ;;  # everything the others don't name
  esac
  echo "=== ui_e2e part $part${scope:+ (scope, MemoryMax=$cap)}"
  if ! RK_E2E_ONLY="$re" $scope node_modules/.bin/tsx e2e/run.ts; then
    failed="$failed $part"
  fi
done
if [ -n "$failed" ]; then
  echo "ui_e2e: parts failed:$failed" >&2
  exit 1
fi
echo "ui_e2e: every part passed"
