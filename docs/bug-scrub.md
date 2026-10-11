# Bug scrub

The roadmap's bug scrub: sanitizer runs over everything that landed while
features were iterated without them, and a read-through of the parsers of
untrusted input.

**Status (2026-10-09): part 1, partly done; the rest is deferred to the
end-phase scrub.**

- Done: the parser read-through, an ASan + UBSan pass over the default
  ctest, and TSan on two suites. The fixes below are on master.
- Deferred to the end: the rest of TSan, a final ASan + UBSan run,
  fuzzing (the harness list at the end) and the security review.
  Features iterate in the meantime without sanitizer runs.

## How to run it

```sh
cmake --preset asan && cmake --build --preset asan -j2
ctest --preset asan -j2                       # ASan + UBSan; UBSan halts on error
cmake --preset tsan && cmake --build --preset tsan -j2
ctest --preset tsan -j1                       # TSan (tools/sanitizers/tsan.supp)
```

- The asan test preset sets `UBSAN_OPTIONS=halt_on_error=1` with
  `tools/sanitizers/ubsan.supp`. Before, UBSan only printed and a report in
  a passing test went unseen.
- A decompiler worker (`rk-decompd --worker`) that UBSan stops exits 1: the
  parent reports "decompiler crashed (exited with status 1)" and keeps the
  stderr tail in the failure (`DecompileFailure.stderr_tail`). To log every
  worker's reports, point `REVKIT_DECOMPD` at a wrapper that appends the
  worker's stderr to a file. GCC's UBSan ignores `log_path`.
- Memory: build with `-j2` and run ctest with `-j2` (TSan `-j1`). The ASan
  ctest takes about 55 minutes on the 32 GB host. ASan test daemons reach
  about 8 GB RSS; three were OOM-killed while other work ran. Wrap every
  build, ctest and daemon in a cap, for example `systemd-run --user
  --scope -p MemoryMax=8G -p MemorySwapMax=0 --quiet <command>`. Under
  ASan, add `ASAN_OPTIONS=quarantine_size_mb=64:malloc_context_size=10`
  and run the daemon-heavy tests and `ui_e2e` at `-j1`.

## Part 1: what was run

- **ASan + UBSan:** the full default ctest (1161 tests; `python_sdk` timed
  out, needing more than its 900 s under ASan).
  - It ran to the end once, as found. Every UBSan report in the test logs
    was then triaged.
  - A second run had UBSan fatal and every decompiler worker's stderr
    logged. It covered the decompile-heavy suites and stopped when the
    sanitizer phase was deferred.
- **TSan:** the tsan preset, with the test targets of the concurrency-heavy
  suites built. Two suites have run (results below); the others are
  deferred.
- **Read-through:**
  - containers and file systems (`src/container`, `src/backend/filesystems.cc`);
  - `.fidbf` and `.rkfid` (`src/fid/db.cc`);
  - MSF/PDB and the symbol server (`src/debuginfo`, `src/backend/symbol_server.cc`);
  - `rk-typeinfo` and type archive sidecars;
  - the PE walkers: imports, exports, `.pdata`/UNWIND_INFO, C scope tables,
    C++ EH FuncInfo, RTTI and base relocations.

## Found and fixed

By severity. Each fix has a regression test from a small crafted input
where one is practical (named in parentheses).

### Memory safety

- **Script metadata (ASan).** `ParseScriptMetadata` kept a `string_view`
  of a `sub_match` temporary: a stack-use-after-scope on any `@arg [a|b]`
  list, reached through `ListScripts`. (`ScriptMetadata.ReadsTheHeaderOnly`,
  `ui_e2e`, `ts_sdk_scripts`)
- **Symbol server `.pd_` cabinet.** `coffFiles` or a folder's data offset
  near 2^32 wrapped the 32-bit bounds checks, and the reads went ~4 GiB past
  the buffer. The sums are now 64-bit. (`SymbolPath.ExpandsCabinets`)
- **squashfs (UBSan).** A `block_log` over 31 was an undefined shift.
  (`ContainerHostile.CorruptedImages`)
- **RTTI.** A base class descriptor that spans two regions passed
  `mapped()`, but each field read failed, and `*optional` dereferenced
  nothing.

### Hangs and memory or disk exhaustion from small inputs

- **tar.** A base-256 size of 2^64-512 wrapped the next header's offset
  back to the same header: an endless loop whose warnings grew without
  bound. (`ContainerHostile.TarSizeWrapsToItsOwnHeader`)
- **ext block maps.** An old-style block map whose indirect blocks repeat
  made one run per block, 2^28 from one double-indirect block. Runs are now
  capped at 4M, as extents already were.
  (`ContainerHostile.ExtSparseDirectoriesAndBlockMaps`)
- **ext sparse directories.** Each 64 MiB directory of holes gave 65,536
  warnings and was held while its subdirectories were read. Now:
  - one warning per directory;
  - the buffer is released before the subdirectories are read;
  - directories are capped at 1 GiB in all.

  (same test)
- **ISO 9660 Rock Ridge.** A continuation area pointing at itself repeated
  its NM fields into a ~1 MiB name per record. Names and link targets now
  stop at 4 KiB, and continuations at 64 KiB per record.
- **ISO 9660 and cramfs directory buffers.** Overlapping directories nested
  256 deep held 256 buffers at once: 16 GiB for ISO, 4 GiB for cramfs.
  Each directory's buffer is now released before its subdirectories are
  read.
- **squashfs block lists.**
  - Hard links each copied their inode's block list (up to 64 MiB). They
    now share it (`ContainerHostile.SquashfsHardLinksShareTheirBlockList`).
  - The block lists read are capped at 256 MiB in all.
  - Names are limited to 256 bytes.
  - The fragment index must be in order: one repeated metablock made
    512 MiB.
- **FAT.** A directory chain was walked in full into a `std::set` before
  the 4 MiB check. It now stops at the limit, and loops are detected with a
  bitmap.
- **Container warnings.** All formats are capped at 1,000.
- **Extraction and hashing of stored members.** Mapped members skipped the
  decompression limits, so a sparse 2^60-byte ext or ISO member filled the
  disk under `--browse-root` or hashed forever. The file limit and the
  session total now apply to them.
- **PE imports.** 4,096 descriptors sharing one 64k-entry lookup table made
  268M imports from 600 KB. Imports now stop at 1M and 64 MiB of names, and
  export names at 64 MiB. (`MalformedPe.SharedImportTablesStayBounded`)
- **MSVC markup.**
  - Try blocks sharing a handler array replayed it, 1,024 functions each.
    A handler array is now claimed before it is used.
  - C scope tables are now claimed before their filters are added.
  - Shared import lookup tables are walked once, with at most 65,536
    thunks in all.
- **RTTI.** A class whose hierarchy failed was re-read on every fixpoint
  pass.
- **PE base relocations.** A block larger than its directory read 2^31
  entries (`data_program.cc`).
- **PDB types.** Every LF_PROCEDURE re-expanded the argument list it names,
  and every aggregate its field list: 1e9 parameters from a 1 MB TPI.
  Parameters, fields and enumerators are now charged to a budget of 4 per
  TPI byte plus 1M. (`PdbMalformed.SharedArgumentListsAreBudgeted`)
- **MSF directory.** The stream directory may no longer exceed the file.
  One repeated block listed 64M streams and 1.6 GB of block lists.
- **`.fidbf`.** Var-record entries may all point at one string or chained
  buffer, and each was decoded and kept: 160 GB from a 4 MB node. Decoding
  now stops at four times the file. (`FidDb.AliasedRecordsAreBudgeted`)

### Host files

- **PDB next to a PE.** The PDB path a PE's CodeView record names was read
  whole, whatever file it was, including on a daemon importing an uploaded
  binary. Only an MSF 7.00 file of at most 4 GiB is read now.
- **`open_host_file`.** It blocked on a FIFO; it now opens `O_NONBLOCK` and
  refuses it.

### Correctness found on the way

- **`.rkfid`.** The count check required 60 bytes per function, but the
  smallest record is 52, so databases of unnamed functions didn't read
  back. (`FidDb.RkfidFunctionsWithoutNames`)
- **Symbol server downloads.** A downloaded PDB is moved, not copied: both
  copies could be up to `max_bytes`.

### Vendored decompiler (triaged, suppressed)

`tools/sanitizers/ubsan.supp` lists the Ghidra decompiler and SLEIGH
engine's reports. None is patched: x86 wraps and masks shift counts as
Java's `long` does, so the C++ decompiler computes what Ghidra's Java side
does.

- **Shifts by 64 or more, or by a negative amount.** These come from
  varnodes over 8 bytes in `calc_mask`, `SubvariableFlow`,
  `RuleAndCommute`, `varnode.cc` and `sign_extend`. They were seen on
  AArch64's 128-bit soft-float helpers and in lua's `luaV_execute`.
- **Signed shifts and overflowing multiplies** in SLEIGH pattern
  expressions.
- **Negating INT64_MIN** in `OperandSymbol::print`.
- **An uninitialized enum copy** in `ConstTpl`'s copy constructor.

## TSan

| Suite | Result |
| --- | --- |
| `revkit_facts_tests` (the thread pool, the fact engine) | 97 tests pass, no warnings |
| `revkit_decompd_tests` (worker pool, batches) | 16 tests pass, no warnings |
| `revkit_detect_tests`, `revkit_analysis_tests` (parallel discovery), `revkit_plugins_backend_tests`, `revkit_api_tests` (gRPC services, job queue, replication, peer links), `revkit_backend_tests` (background analyzers, decompiler workers, collab) | not run: deferred to the end-phase scrub |

Run them with the memory caps above, one suite at a time at `-j1`, e.g.
`TSAN_OPTIONS="suppressions=tools/sanitizers/tsan.supp halt_on_error=0"
setarch -R build-tsan/src/api/tests/revkit_api_tests`.

## Left

Deferred to the end-phase scrub:

- **TSan** on the five suites above.
- **A final ASan + UBSan run** of the whole default ctest, with UBSan fatal
  (the asan preset now does that) and the workers' stderr logged.
  - It will show whether the vendored suppressions are complete. The
    shifts are suppressed for the whole vendored tree; the other
    suppressions name single files.
  - `python_sdk` needs a longer timeout under ASan.
  - `ui_e2e` under ASan only if one daemon fits the cap.
- **Fuzzing:** the harnesses below.
- **The security review.**

Known gaps from the read-through, not fixed yet:

- **ext CPU.** The extent visit cap (2^20 × a block read) and the block map
  read cap (2^22) bound memory, not time. A crafted image can spend tens of
  seconds per open. Cache index blocks or lower the caps.
- **FAT directory buffers.** Like ISO's, they are held across recursion,
  bounded at 4 MiB × 256 levels = 1 GiB.
- **Extraction TOCTOU.** The destination is canonicalized, then reopened
  by path. A local user who can write inside the browse root could swap in
  a symlink between the two steps. Fix: `openat2(RESOLVE_BENEATH |
  RESOLVE_NO_SYMLINKS)`.
- **Symbol server.**
  - Redirects are followed across hosts and from https to http. The
    content is still checked against the PE's GUID and age.
  - A PDB name with `?`, `#` or `%` goes into the URL path as is.
- **MSF streams sharing blocks.** Up to 65,535 module streams can each
  copy a file's worth of shared blocks: CPU, not memory. Refusing shared
  blocks needs checking against real PDBs first.
- **Type archive sidecars.** `ProfileOf` takes sizes and alignments as
  given. No crash was found; validate them like the spec path does (1–64).
- **`python_sdk` under ASan.** It needs more than its 900 s timeout. Run
  it by hand with a longer one.

## Fuzz harnesses (part 2)

Existing (`-DREVKIT_FUZZ=ON`, clang):

- `fuzz_elf`, `fuzz_pe`
- `dwarf_fuzzer`, `pdb_fuzzer`
- `fuzz_fid_db` (`.fidbf` and `.rkfid`)
- `container_<format>_fuzzer` for every format, and `container_codecs_fuzzer`
- `cparse_fuzzer`, `demangle_fuzzer`, `project_archive_fuzzer`

To add:

1. `cabinet_fuzzer`: `ExpandCabinet` (`.pd_` from a symbol server or a
   store). It had the out-of-bounds read above.
2. `msvc_markup_fuzzer`: `parse_pe`, then `msvc::analyze`. This covers RTTI
   and PE markup: `.pdata`, UNWIND_INFO, scope tables, FuncInfo, TLS and
   imports. `fuzz_pe` stops at the loader.
3. `container_session_fuzzer`: `identify`/`guess`, nested `mount` 2–3
   layers deep, `locate`/`find` with crafted paths, and `decode_component`.
4. `extract_fuzzer`: `ExtractFileSystem` into a scratch directory, checking
   that nothing is written outside it and that the byte limits hold.
5. `script_metadata_fuzzer`: `ParseScriptMetadata`. It had the ASan bug
   above and uses `std::regex`.
6. `symbol_path_fuzzer`: `ParseSymbolPath` and `FindPdb`'s name handling.
7. `fid_program_fuzzer`: FID hashing and `pe_base_relocations` over a
   hostile PE, and matching against a hostile database.
8. `data_program_fuzzer`: `analysis::data_program` PE and ELF walks.
9. `type_archive_fuzzer`: `ReadTypeArchiveSidecar`, `ProfileOf`, and the
   C parser under a hostile profile.
10. `raw_loader_fuzzer`: Intel HEX, S-records and the raw loader
    (`src/loader/raw.cc`).
11. `detect_fuzzer`: processor auto-detection on arbitrary bytes.

How to run them:

- Most of the amplification bugs above need inputs of 100 KB to several MB.
  Run the PDB, `.fidbf`, PE and container fuzzers with a larger `-max_len`
  (1–8 MB), `-rss_limit_mb=2048` and `-timeout=10`. At the default 4 KB
  they find none of them.
- Seed each harness from the regression tests' crafted inputs and the
  corpus.
