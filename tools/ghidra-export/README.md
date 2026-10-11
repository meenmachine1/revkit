# ghidra-export

Writes Ghidra's view of each corpus binary as reference JSON
([docs/reference-format.md](../../docs/reference-format.md)): memory map,
functions (entry, name, body, prototype, decompiled C) and every instruction in
every function body with its raw p-code.

## Setup

Needs Ghidra 12.1.4 (default `~/ghidra/ghidra_12.1.4_PUBLIC`, or
`GHIDRA_INSTALL_DIR`/`--ghidra`), JDK 21 and Python 3.10+.
`scripts/setup-pyghidra.sh` creates a virtualenv outside the repo
(`~/.local/share/revkit-pyghidra`) from the PyGhidra and JPype wheels that ship
with Ghidra, and prints its python.

## Use

```sh
py=$(scripts/setup-pyghidra.sh)
$py tools/ghidra-export/ghidra_export.py --corpus out/corpus --out out/ref --stats out/ref.stats.json
$py tools/ghidra-export/ghidra_export.py --corpus out/corpus --out out/ref --only 'elf-riscv64/*'
$py tools/ghidra-export/ghidra_export.py --out /tmp/ref some/binary other.exe   # ad hoc; uses a .pdb beside an .exe
$py tools/ghidra-export/ghidra_export.py --firmware-corpus out/firmware-corpus --out out/firmware-ref -j 6 --heap 4g
```

`--firmware-corpus` reads a firmware corpus manifest (`corpus/firmware`)
and imports each raw image with Ghidra's Raw Binary loader at its load
address (`-loader-baseAddr`), adds its regions (uninitialized blocks; a
`volatile` one is volatile) and its entry point (an external entry point
labelled `entry`), then analyzes and exports as usual; the 23 images take
about 100 s with 6 workers.

Options: `-j N` worker processes (default min(cores/3, RAM GB/3, binaries));
`--heap 3g` Java heap per worker; `--gzip` writes `.json.gz`;
`--skip-existing` skips binaries whose output already has the binary's sha256;
`--decompile-timeout` seconds per function (default 120).
`scripts/phase0.sh` runs it as part of the full harness.

## Decompiler inputs

`ghidra_dbexport.py` writes what Ghidra's Java side tells its decompiler
about each binary (signatures, locals, data and label symbols, external
references, comments, flow overrides, tracked registers, relocated bytes,
data types; [docs/decompiler-inputs.md](../../docs/decompiler-inputs.md))
after the same import and auto-analysis, so `rk-lift --decompile --inputs`
can decompile under the reference's conditions:

```sh
$py tools/ghidra-export/ghidra_dbexport.py --corpus out/corpus --out out/ghidra-db [--with-c]
$py tools/ghidra-export/ghidra_export.py --corpus out/corpus --out out/ref --inputs-out out/ghidra-db
```

Auto-analysis is not fully deterministic (a RISC-V `gp` value at one
function's entry varies between runs), so prefer `ghidra_export.py
--inputs-out`, which writes the references and the inputs from the same
session (`scripts/phase0.sh` does). `--with-c` adds Ghidra's own C from the
inputs' session to each function, to tell revkit's differences from
Ghidra's run-to-run ones.

Timing helpers for [docs/decomp-parity.md](../../docs/decomp-parity.md):
`ghidra_decompile_timing.py` times Ghidra's decompilation alone (workers
analyze, then all decompile from a common start), and
`ghidra_scripts/RevkitTiming{Pre,Post}.java` are the `analyzeHeadless`
scripts `scripts/ghidra-headless-timing.py` uses.

## How it works

The parent sorts binaries largest first and feeds them to a pool of worker
processes. Each worker starts one headless JVM through PyGhidra and, per binary:

1. imports it with `ProgramLoader` into memory (nothing is saved; no Ghidra
   project is created, Java's temp dir points at a temp dir that is removed);
2. for PE debug binaries, sets the PDB Universal analyzer's PDB file to the
   manifest's `.pdb`;
3. runs full auto-analysis with default options;
4. decompiles every function (`DecompileOptions.grabFromProgram`, style
   `decompile`) and walks every instruction in the union of function bodies;
5. writes the canonical JSON atomically (temp file + rename).

A binary that fails is reported and the rest continue; the exit status is 1 if
any failed. Per-binary timings (import, analysis, export), counts and
decompiler failures go to `--stats`.

## Timings

Full corpus (54 binaries, 11,380 functions, 635k instructions, ~2.5M p-code ops,
269 MB of JSON) on 32 cores / 31 GB:

| workers | wall | note |
| ---: | ---: | --- |
| 10 (default) | 69-73 s | ~620 CPU-seconds of per-binary time; peak RSS ~2.3 GB per worker |
| 16 | 82 s | oversubscribed: Ghidra's analysis is itself multithreaded |

The wall time is bounded by the largest binary (Lua x86-64 debug: ~31 s
analysis + ~20 s export). Small binaries take 3-8 s, PE ones 10-50 s because of
the statically linked CRT. Roughly a third of per-binary time is the Python side
walking instructions and p-code through JPype.

## Determinism

Outputs are byte-identical across runs and across worker counts (checked
for the full corpus with `scripts/phase0.sh --check-determinism` and with
`-j 10` vs `-j 16`). Arrays are sorted numerically and the JSON is written
canonically by `tools/refdiff/refformat.py`.

## Known limitations

- References reflect Ghidra's default auto-analysis; nothing is tuned.
  Debug and stripped builds of the same code give different function sets
  and names, as expected.
- One function fails to decompile (Lua on AArch64 clang -O2, `0x107b70`:
  "Overlapping input varnodes"); per the format, its `decompiled_c` is omitted.
- Prototypes use Ghidra's formatting (`char * * argv`, `undefined8`, odd
  library guesses like `_init(EVP_PKEY_CTX * ctx)`); revkit has to reproduce
  Ghidra's type naming to match, or refdiff's prototype rate will reflect it.
- Ghidra still writes its `application.log` under
  `~/.config/ghidra/ghidra_12.1.4_PUBLIC/` (shared by all workers).
- Per-binary decompilation is sequential inside a worker; parallelizing it
  would mainly help the largest binaries.
