#!/usr/bin/env bash
# Create (or reuse) the PyGhidra virtualenv used by tools/ghidra-export.
# Installs the PyGhidra and JPype wheels shipped with Ghidra, plus pytest.
#
#   scripts/setup-pyghidra.sh      # prints the venv's python path
#
# Env: GHIDRA_INSTALL_DIR (default ~/ghidra/ghidra_12.1.4_PUBLIC),
#      REVKIT_PYGHIDRA_VENV (default ~/.local/share/revkit-pyghidra).
set -euo pipefail

ghidra=${GHIDRA_INSTALL_DIR:-$HOME/ghidra/ghidra_12.1.4_PUBLIC}
venv=${REVKIT_PYGHIDRA_VENV:-$HOME/.local/share/revkit-pyghidra}
dist=$ghidra/Ghidra/Features/PyGhidra/pypkg/dist

if ! "$venv/bin/python" -c "import pyghidra" 2>/dev/null; then
  echo "creating PyGhidra venv in $venv" >&2
  python3 -m venv "$venv"
  "$venv/bin/pip" install -q --no-index -f "$dist" pyghidra >&2
fi
"$venv/bin/python" -c "import pytest" 2>/dev/null || "$venv/bin/pip" install -q pytest >&2 || \
  echo "warning: pytest not installed (unit tests can still run with unittest)" >&2
echo "$venv/bin/python"
