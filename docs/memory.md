# Memory: what the daemon holds, and what it lets go

What `rk-daemon` keeps in memory for the programs it has open, and what it
gives back when they are idle. The large-binary budgets (a 100 MB binary
in 4 GB, the decompiler's bounds) are in [scale.md](scale.md); the
fact store's memo budget (`--memo-budget`) is in
[backend.md](backend.md#persistence).

## SLEIGH engines

A SLEIGH engine (`lift::Lifter`, over Ghidra's C++ `Sleigh`) decodes
instructions for one language. Most of its memory, and most of the time it
takes to build, is the decoded `.sla` file: about 35 MB for x86-64, tens
of milliseconds to read. That part depends on the language alone. What
depends on the program is small: the bytes it reads (a load image), its
context database (ARM's Thumb regions, x86-64's long mode from the
`.pspec`) and the caches of instructions it has decoded.

A program keeps several engines: its listing and instruction-detail pool
(`ImageBackendOptions::lifters_per_program`, 4), a pool for flow walks,
one for Thumb on ARM, and the decompiler's prediction engines. Discovery
and data analysis use a shared pool of decoders. Kept for every open
program, they were most of an idle daemon's memory: 8 tiny programs held
about 900 MB, almost all of it the same x86-64 `.sla` decoded over and
over.

**Parking.** An engine idle for `ImageBackendOptions::engine_idle_seconds`
(`rk-daemon --engine-idle <s>`, default 15; 0 keeps them) is parked:
`Lifter::park` detaches it from its program (`Sleigh::reset` with no load
image or context database) and gives it to its language's spares. A
sweeper thread in the image backend looks every `engine_idle_seconds` at
every program's pools (and their memory-map variants'), the decompiler's
prediction pool and analysis's decoders, then calls `malloc_trim` when it
parked any. A pool counts as idle by item (`backend::Pool`: each engine
since it was returned) or as a whole (the decoders and the prediction
pool: nothing taken or returned for that long, so a running analysis keeps
its engines).

**Spares.** At most two spares are kept per language; more are freed. A
Lifter of the language, of any program, that needs an engine (a new one,
a parked one decoding again, or one whose context changed) takes a spare
and attaches its own program to it, as Ghidra does for a new program:
`Sleigh::reset` with its load image and a new context database, then
`initialize`, which only registers the context variables again since the
`.sla` is already decoded. The `.pspec`'s context and what was painted
(`set_context`) are applied afresh, so a reused engine decodes exactly as
one built from the `.sla` would; the unit tests compare the two
(`Lift.ParkedEngine*`). With no spare, it decodes the `.sla` as before.
A Lifter's own rebuild after a context change also reuses its engine
this way instead of building another.

Spares are keyed by the `.sla` file and the language's space truncations,
not the `.sla` alone: languages sharing a `.sla` may truncate a space
differently (AArch64's ilp32 has 4-byte `ram` addresses in `AARCH64.sla`,
PowerPC's 64-32addr likewise), and a truncation stays in the engine.

**What is not parked.** A Lifter whose decoding committed context (an ARM
`blx` makes its target Thumb; SLEIGH's `globalset`) keeps its engine:
a rebuilt one wouldn't have those commits. `lift::engine_stats()` counts
the engines alive and spare; `lift::trim_spare_engines()` frees the
spares.

**Measured** (`rk-daemon` RSS 40 s after start, `--open` of tiny x86-64
programs and lua, analysis settled; this machine, 2026-10-15):

| programs | `--engine-idle 0` | default (15 s) |
| --- | --- | --- |
| 1 tiny | 386 MB | 268 MB |
| 4 tiny | 603 MB | 272 MB |
| 8 tiny | 917 MB | 274 MB |
| 8 tiny and lua | 1051 MB | 302 MB |

The peak during the imports is the same either way (463 to 1245 MB):
parking lowers what an idle daemon holds, not what an import needs. The
first decode after a park costs a reset rather than a decode when a
spare is there, and a `.sla` decode when not.
