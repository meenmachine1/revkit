# ghidra-interop

Two-way interop between Ghidra projects and revkit; the design, the JSON
format and the gaps are in [docs/ghidra-interop.md](../../docs/ghidra-interop.md).

| File | Runs in | What |
| --- | --- | --- |
| `ghidra_dump.py` | PyGhidra venv | A Ghidra program's user work as JSON (read-only, with a baseline re-analysis) |
| `ghidra_apply.py` | PyGhidra venv | revkit-ghidra-export JSON applied to a Ghidra program, traced with `revkit` bookmarks |
| `ghidra_common.py` | PyGhidra venv | Launching, opening projects, the `revkit.applied` fingerprints |
| `roundtrip_ghidra.py`, `roundtrip_test.py` | PyGhidra / SDK venv | The headless round trip (CTest `ghidra_roundtrip`) |
| `tests/` | SDK venv | Mapping unit tests (CTest `ghidra_interop_mapping`) |

The revkit side is the SDK's `revkit.ghidra` package (`revkit-ghidra-import`,
`revkit-ghidra-export`).

```sh
py=$(scripts/setup-pyghidra.sh)
$py tools/ghidra-interop/ghidra_dump.py --project ~/work/proj.gpr --program /prog -o prog.ghidra.json
revkit-ghidra-import prog.ghidra.json --binary prog
revkit-ghidra-export --binary prog -o prog.revkit.json
$py tools/ghidra-interop/ghidra_apply.py --project ~/work/proj.gpr --program /prog prog.revkit.json
```
