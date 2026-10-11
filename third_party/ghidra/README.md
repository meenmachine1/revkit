# Ghidra's decompiler: revkit's fork

revkit links Ghidra's C++ decompiler and SLEIGH engine in process. It is
never rewritten: it is kept as a fork of one Ghidra release, as the
pristine release plus a short, ordered patch series.

- Upstream: Ghidra 12.1.4 PUBLIC (`UPSTREAM_VERSION`),
  `Ghidra/Features/Decompiler/src/decompile`.
- License: Apache 2.0, see `LICENSE.txt` and `GHIDRA_LICENSE`.
- Patches and their upstream status: [UPSTREAM.md](UPSTREAM.md).

## Layout

| Path | What |
| --- | --- |
| `decompiler/` | upstream `cpp/`, the C++ sources only (not its Makefile, bison/flex grammars or Doxyfile). **Pristine** |
| `datatests/`, `unittests/` | upstream's own test suites, same release. **Pristine** |
| `PRISTINE.sha256` | the SHA-256 of every pristine file |
| `patches/series` | the patches, in the order they apply |
| `patches/NNNN-*.patch` | one change each, in `git format-patch` form: the commit message is the upstream description, paths are Ghidra repository paths (`a/Ghidra/Features/Decompiler/src/decompile/cpp/merge.cc`), so a patch applies to upstream as it is |
| `repro/` | each patch's repro: a decompiler savefile (`.xml`) and the outcome it must have (`.expect`) |
| `fork.sh` | applies, checks, unpacks and exports the series |
| `upstream-tests.sh`, `repro/replay.sh` | test drivers (below) |

Never edit the pristine trees. A change to the decompiler is a patch.

## Build

At configure time `CMakeLists.txt` runs `fork.sh apply build/third_party/ghidra/src`:
it verifies the pristine trees against `PRISTINE.sha256`, copies them into
the build tree in upstream's layout (`src/cpp`, `src/datatests`,
`src/unittests`), and applies `patches/series` with `patch --fuzz=0`.
A patch that doesn't apply exactly (fuzz or offset), a series entry
without a file, a patch file not in the series, or a changed pristine file
stops the configure with the reason. Only files whose content changed are
rewritten, so editing a patch rebuilds just what it touches; patches, the
series and the pristine files are configure dependencies, so a build
re-runs this by itself. Everything (`ghidra::decomp` and the tools below) is
compiled from the patched copy.

Two upstream executables are built from the same sources:
`ghidra_decomp_dbg` (upstream's `decomp_dbg` console) and `ghidra_test`
(upstream's `decomp_test_dbg`).

## Tests (CTest)

| Test | What |
| --- | --- |
| `ghidra_fork_series` | `fork.sh check`: the pristine trees match `PRISTINE.sha256`, the series applies to them exactly, and the build tree holds what it produces |
| `ghidra_unittests`, `ghidra_datatests` | upstream's own suites on the patched sources (`upstream-tests.sh`). A release has no Toy processor, so the 21 `funcproto_*` unit tests and `skipnext2.xml` that need it are excluded; anything else that fails, fails the test |
| `ghidra_repro_<name>` | `repro/replay.sh`: restores `repro/<name>.xml` in `ghidra_decomp_dbg`, decompiles the function the savefile names, and requires a normal exit (no crash, within 300 s) and output matching every regex in `<name>.expect` |

The repro format is the only thing `replay.sh` knows about; once the
out-of-process decompiler's input bundles exist, a repro can also be a
bundle replayed with `rk-decompd --bundle` against the same `.expect`.

A repro is the file Ghidra's "Debug Function Decompilation" writes, the
form upstream asks for in bug reports, so it needs neither the original
binary nor revkit. `tools/ghidra-export/ghidra_debug_xml.py` captures one
headlessly:

```sh
py=$(scripts/setup-pyghidra.sh)
$py tools/ghidra-export/ghidra_debug_xml.py --out /tmp/dbg path/to/binary 0x10d8e0   # --pdb F for a PE
```

A repro can also be written with the console: `restore` a minimal
savefile, define what's needed (`map function`, `parse line`, `type
varnode`), `save`, then edit (see `repro/0003-storeopaque.xml`). Replay one
by hand:

```sh
printf 'restore repro/0001-mbedtls_aria_self_test.xml\nload function mbedtls_aria_self_test\ndecompile\nprint C\n' |
  SLEIGHHOME=~/ghidra/ghidra_12.1.4_PUBLIC build/third_party/ghidra/ghidra_decomp_dbg
```

## Changing a patch, or adding one

```sh
third_party/ghidra/fork.sh unpack /tmp/fork      # git repo: tag ghidra-12.1.4, then one commit per patch
cd /tmp/fork                                     # Ghidra's layout: Ghidra/Features/Decompiler/src/decompile/...
# edit and commit (git commit --amend / rebase -i to change an existing patch)
third_party/ghidra/fork.sh export /tmp/fork      # rewrites patches/*.patch and patches/series
```

Then add the repro (`repro/NNNN-name.xml` and `.expect`), an entry in
UPSTREAM.md, and re-run CMake and CTest.

What a patch may be:

1. **Defensive** (preferred): where the decompiler would crash, throw a
   `LowlevelError`. The decompiler's callers already catch it per
   function, so that function fails cleanly and the rest of the binary
   decompiles. Only functions that crashed before change.
2. **Algorithmic**, only if small, clearly correct, and output parity
   holds: `scripts/ci.sh` (the Phase 2 gate, decompiled C under Ghidra's
   inputs) on the tuning corpus and `scripts/ci.sh --heldout` must not move.

Every patch has its own repro, and its commit message says what fails, why,
what the patch does, where it was seen, and the Ghidra version, ready to
offer upstream. Crashes the series doesn't fix are contained by running the
decompiler out of process; patches lower the failure rate, isolation is
the guarantee.

## Upgrading to a new Ghidra release

```sh
third_party/ghidra/fork.sh import ~/ghidra/ghidra_<new>_PUBLIC   # replace the pristine trees, rewrite PRISTINE.sha256
echo <new> > third_party/ghidra/UPSTREAM_VERSION
```

1. Update the file lists in `CMakeLists.txt` from upstream's `Makefile`
   (`LIBDECOMP_NAMES`) if they changed.
2. Drop the patches upstream has taken (UPSTREAM.md says which were
   offered) from `patches/` and `patches/series`.
3. Rebase the rest: `fork.sh unpack /tmp/fork` commits the new release and
   `git am`s the series onto it. Where a patch no longer applies, `git am`
   stops: resolve, `git am --continue`, and when it is done
   `fork.sh export /tmp/fork`. A patch that applies with an offset must be
   re-exported the same way (configure rejects offsets).
4. Configure, build and run CTest: `ghidra_fork_series`, upstream's
   suites and every repro must pass. A repro whose crash upstream fixed
   differently may now decompile: update its `.expect`.
5. Run `scripts/ci.sh` (and `--heldout`) and re-save baselines only for
   changes the new release explains.
