# refdiff

Compares reference JSON (docs/reference-format.md): two files, or two
directories matched by relative path. Standard library only.

```sh
python3 tools/refdiff/refdiff.py out/ref out/ref                    # self-check: 100% everywhere
python3 tools/refdiff/refdiff.py out/ref out/revkit --by-group --details 5
python3 tools/refdiff/refdiff.py out/ref out/revkit --save-baseline baseline.json
python3 tools/refdiff/refdiff.py out/ref out/revkit --baseline baseline.json   # exit 1 on any drop
python3 tools/refdiff/refdiff.py out/ref out/revkit --require functions=1.0 --require pcode=0.99
python3 tools/refdiff/refdiff.py out/ref out/revkit-decomp --only c_tokens,c_ast,c_alpha --by-group --group-depth 2
```

Categories: `binaries`, `memory`, `functions`, `names`, `bodies`,
`prototypes`, `decompiled_c`, `c_tokens`, `c_ast`, `c_alpha`,
`instructions`, `pcode`. Each rate is matching items / items on either side,
so missing and extra items both count; a binary missing on one side counts
all of its items as disagreement. P-code is compared after renumbering
`unique` offsets per instruction. A baseline stores overall and per-binary
rates; `--baseline` fails if any of them drops by more than `--tolerance`
(default 0). `--json` writes the full result.

`--only c_ast,c_alpha` compares only the listed categories (and skips the
expensive instruction comparison when it isn't listed). `--by-group
--group-depth 2` prints rates per architecture and toolchain/opt level
(`elf-x86_64/gcc-O2`).

### Decompiled C

`decompiled_c` compares the text exactly (`--loose-c`: whitespace
collapsed). The other three compare token sequences (`cnorm.py`), so line
breaks, wrapping and indentation never matter:

| category | equal when |
| --- | --- |
| `c_tokens` | same tokens, comments included (compared word by word) |
| `c_ast` | same tokens without comments: the C parses to the same syntax tree. This is the Phase 2 gate's "structurally identical C (same AST modulo whitespace)". |
| `c_alpha` | `c_ast` after renaming local variables and parameters (declared in the function, or one of Ghidra's invented names such as `uVar1`, `local_10`, `in_RAX`) to `v0`, `v1`, ... in order of use. Secondary and looser: it forgives naming only, not globals, callees, types, fields or constants. |

With `--details N`, C mismatches show the tokens around the first
difference.

Tests: `python3 -m pytest tools/refdiff/tests` or
`python3 -m unittest discover -s tools/refdiff/tests` (also registered with
ctest as `refdiff_unit`). With `out/ref` present, a test also self-checks
the real export.
