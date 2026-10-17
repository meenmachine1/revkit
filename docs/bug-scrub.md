# Bug scrub

The roadmap's bug scrub: sanitizer runs over everything that landed while
features were iterated without them, and a read-through of the parsers of
untrusted input.

**Status (2026-10-16): done.** Part 1 (2026-10-09) read the parsers,
ran ASan + UBSan once and TSan on two suites; part 2, the end-phase scrub,
ran the final ASan + UBSan pass, the rest of TSan, the fuzz harnesses and
the security review. The fixes of both are on master. What is left is at
the end ("Left").

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
- Three tests inject a SIGSEGV or SIGFPE into a decompiler worker
  (`ImageBackendTest.DecompilerCrashesAndHangsCostOneFunction`,
  `Decompd.FailuresAreClassifiedAndCostOneRun`,
  `Signature.FailuresAreFacts`); ASan and TSan catch the signal first, so
  run them with `ASAN_OPTIONS=handle_segv=0:handle_sigfpe=0` (under TSan
  they report the injected SEGV; that is expected).
- `python_sdk` under ASan: one test module per capped scope, with
  `ASAN_OPTIONS=quarantine_size_mb=8` (collab and libraries start several
  daemons, which outgrow 8 GiB at the default quarantine). Point
  `RK_DAEMON` at a wrapper that appends the daemon's stderr to a file: the
  SDK's daemon log is in a temporary directory removed afterwards, and
  GCC's UBSan only writes to stderr.
- TSan on `revkit_backend_tests`: one process per test (a loop over
  `--gtest_list_tests`, or ctest with your own `TSAN_OPTIONS`). One
  process for the whole suite grows past 8 GiB about halfway.

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

## Part 2 (2026-10-16): the end-phase scrub

Over everything that landed since part 1: BSim stages 2 and 3, shared
SLEIGH engines and their sweeper, library linking, Comments, Relocations,
the Symbol tree, Export C, Clear Flow, fallthrough overrides, data
settings, external debug files (debuginfod), register values, the
language switch, and the debugger and emulator work.

### What was run

- **ASan + UBSan** (asan preset, UBSan fatal, every decompiler worker's
  stderr logged): the default ctest without `python_sdk` and `ui_e2e`,
  1,276 tests at `-j2` in 54 minutes. 1,273 passed; the 3 that failed
  inject a SIGSEGV or SIGFPE into a decompiler worker and expect it
  classified as that signal, which ASan's own handler turns into exit 1
  (they pass with `ASAN_OPTIONS=handle_segv=0:handle_sigfpe=0`). No ASan
  or UBSan report in the test logs or the workers' stderr besides those
  injected faults.
- **`python_sdk` under ASan**, one test module per 8 GiB scope (50
  modules): all pass once the two findings below were fixed. Run as the
  four ctest parts, two parts were OOM-killed inside the cap (collab and
  libraries start several ASan daemons); with
  `ASAN_OPTIONS=quarantine_size_mb=8` they fit. `ui_e2e` wasn't run under
  ASan (nothing found was UI-related).
- **TSan** (tsan preset, `halt_on_error=0`, `tools/sanitizers/tsan.supp`):
  the five suites part 1 left, `revkit_lift_tests` and two new stress
  tests for the new concurrency (below). Results in the TSan table.
- **Fuzzing:** every harness of the part 1 list and the new ones, 3
  minutes each, then 5 to 15 more on the parsers that found bugs or ran
  slowly (the fuzzing table).

### Found and fixed

By severity, with the commit and its regression test.

**Security and integrity**

- **Archive op stamps wrapped the clock** (medium; `de872e86`). An
  archive's ops kept their stamps. One stamped `UINT64_MAX` raised the
  importing daemon's hybrid clock to the top, where its next tick wrapped
  to 0: every later edit sorted before the archive's and lost to it, for
  good (the clock is restored from the log's largest stamp), and peers
  synced the same. The clock saturates now, and an import refuses ops
  stamped more than a day past the daemon's clock.
  (`Replication.TheClockSaturatesInsteadOfWrapping`,
  `ProjectArchiveContainer.ValidatesTheOps`)
- **Downloads** (low to medium; `b101577f`). Symbol server and
  debuginfod downloads share one bounded GET (`src/backend/http_fetch.cc`)
  instead of httplib's redirect following:
  - a redirect to another host is followed only over https, and only for
    symbol servers (msdl answers from a CDN); never from https to http,
    never to a location with spaces or control characters, at most five;
  - a whole transfer has a deadline (30 times the read timeout) besides
    the size limit: a server sending a byte a minute held a download open
    indefinitely;
  - a PDB name's `?`, `#` and `%` are percent-encoded into the path;
  - certificates are checked (httplib's defaults: the system's roots and
    the host name), and a test proves a self-signed server is refused.

  (`HttpFetch.*`, `SymbolServer.NamesAreEncodedAndRedirectsStayOnHttps`)
- **Extraction and library roots: check, then open by path** (low:
  needs a local user who can write under the browse root; `b101577f`).
  The canonicalized destination is now opened from the root down with
  `openat(O_NOFOLLOW)` one component at a time (`OpenBeneath`: what
  `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` does, without needing
  Linux 5.6), so a component swapped for a link in between is refused. A
  library found in a root file system on the host is read the same way
  and imported from those bytes instead of reopened by path.
  (`ExtractTest.*`)
- **`CompareLanguages` wasn't project-scoped** (low; `af5d33bb`). It
  names a program and decodes its code, but a viewer limited to one
  project could run it on another's program. It is now; and a limited
  caller is checked against every project a request names, whatever the
  method (`ListScripts` and `SaveScript` take an optional `project_id`,
  which the script service also checks). A schema test now fails for any
  method whose request names a program but isn't project-scoped.
  (`AuthPolicyUnit.MethodsNamingAProgramAreProjectScoped`)
- **Archive values the API would refuse** (low; `de872e86`). Type
  archive settings in an archive are checked as `SetTypeArchive` checks
  them (a valid name, the size limits, a sidecar that reads, at most 256
  archives, each parsed at every program load), and data settings must
  parse and name a field or type of at most 512 bytes.

**Hangs, CPU and memory from small inputs**

- **Address sets decoded in O(n^2)** (medium; `1ef9ca33`). An
  `AddressSet` from an archive or a peer was built by inserting its
  ranges one at a time into a sorted vector: in descending order, hours
  for one 64 MiB op. They are sorted first. A decoded vector also reserved
  as many elements as bytes were left (32 times the op for address
  ranges); it reserves at most 4,096 now.
- **ext extent trees and block maps** (the "ext CPU" gap; `400ba18a`).
  The caps bounded memory, not time. A file's tree nodes, indirect blocks
  and data blocks are distinct blocks of the image, so each is now capped
  at the image's block count, and a file mapping more blocks than the
  image holds is refused: the crafted map in
  `ContainerHostile.ExtSparseDirectoriesAndBlockMaps` stops in
  milliseconds.
- **FAT directories** (the "FAT directory buffers" gap; `6a83d4d3`). Each
  directory's buffer is released before its subdirectories are read (256
  nested 4 MiB directories held 1 GiB). Directories sharing their chains'
  clusters each read them again (a terabyte from a 17 MB image within the
  entry limit); directory reads are capped at 1 GiB in all.
  (`ContainerHostile.FatDirectoriesSharingTheirChains`)
- **MSF streams sharing blocks** (the gap of that name; `ed5e8702`).
  Rather than refusing shared blocks, which would need checking against
  real PDBs, what all of an MSF's reads gather is budgeted at four times
  the file plus 64 MiB: 20,000 streams of a 3 MB file listing one block 40
  times each gathered 3.2 GB. A real PDB's streams don't share blocks and
  are each read about once. (`PdbMalformed.SharedStreamBlocksAreBudgeted`)
- **Type archive sidecars** (the gap of that name; `de872e86`).
  `ProfileOf` keeps sizes and alignments to 1-64 bytes as the spec path
  does (a 64-bit value no longer truncates to 32 bits), at most 64 size
  alignments. (`TypeArchiveSidecar.HostileDataModelKeepsSaneLayouts`)
- **A peripheral past the end of memory** (low; `71193aab`). A machine's
  peripheral whose base plus size passed the top of the address space
  wrapped, passed its range check and mapped nothing. It is refused.
  (`FirmwareMachine.APeripheralPastTheEndOfMemoryIsRefused`)

**Found by the sanitizers and the fuzzers**

- **ExportC's results raced** (TSan; medium: memory corruption or a
  crash from a viewer's call; `3c3430ae`). ExportC decompiles through
  DecompileMany, which calls its callback from several worker threads at
  once (a stream's contract: the transport serializes the writes).
  ExportC's callback pushed into a shared vector without a lock. It locks
  now, as FindTypeUses' and SearchDecompiled's callbacks do.
  (`SearchTest.ExportC` under TSan)
- **Function ID's duplicate hash overflowed** (UBSan; the daemon stopped
  under the asan build; `27bddc81`). `LibraryBuilder` computes Java's long
  hash over 64-bit hashes in `int64_t`: it is `uint64_t` now, the same
  bits. (`FidCreate.LargeHashesWrapAsJavasLongsDo`; the python SDK's
  `test_fid` found it)
- **Zero-length container reads** (UBSan; `3309ca7a`). A memory source's
  0-byte read passed `memcpy` a null buffer, as could the LZ4/LZO block
  reader. (`ContainerHostile.ZeroLengthReads`; `extract_fuzzer` found it
  with a zip header naming an empty extra field)
- **`ListPlugins` showed viewers the plugin directory** (low;
  `08f7c19e`). A rejected plugin's error named the daemon's plugin
  directory; it is cut for callers who aren't admins.
  (`PluginBackend.RejectedPluginsDontShowViewersTheHostPath`)

**Verified false positives, suppressed** (`2927d4b2`, each with its
reason in the suppression file)

- TSan: a lock-order cycle between a project's store writer, taken under
  `Core::mu` only in `FactDb`'s constructor (where no other thread can
  reach the writer yet), and the rebase and language hooks, which take
  `Core::mu` briefly under that writer inside a commit. It can't deadlock.
- UBSan (vendored SLEIGH): `SleighBuilder::buildEmpty` casts an operand's
  symbol to `SubtableSymbol` before checking its type with a virtual
  call; raw-firmware detection reaches it.

**Tests**

- **Leaked scratch directories** (`a9bb0ace`). `testing::scratch_dir`
  made a directory in `/tmp` for each test and nothing removed it: a full
  ctest left 334 (the host had about 24,600 from earlier runs, left as
  they are). They are removed when the test process exits now
  (`RK_KEEP_TEST_DIRS=1` keeps them), as are the facts storage tests' and
  `project_org_test`'s. A full ctest now leaves none.

### The security review

- **Auth policy.** Every RPC added since part 1 (35: BSim's 11, the
  debugger's 7, `RestartDaemon`, the language switch, `LoadDebugFile`,
  libraries, and the new query views) has an `auth_policy.cc` entry; the
  existing test fails for one without. Levels checked by hand: host paths
  and downloads are admin's (`LoadDebugFile`, `AttachBSimDatabase`,
  `CreateBSimDatabase` with a path, `CopyDebugMemory` to a new program,
  `RestartDaemon`, `Get`/`SetSymbolSettings`), edits are editors', reads
  viewers'. Debug sessions are their creator's (`DebugSessions`), checked
  in the backend for each session RPC. The one wrong level was
  `CompareLanguages` (above).
- **Paths under `--browse-root`.** Library roots (`library_root`, and the
  root file system an import lies in) must be under a browse root and are
  resolved inside it with `lstat`, links followed inside the root, and
  now opened without following links. `LoadDebugFile` by path is an
  admin's, as `ImportProgram` by path is, and like it is not limited to
  the browse roots (the admin role is the host's; docs/security.md): it
  reads only a regular file of at most `debug_file_max_bytes`. The
  debuglink name is a bare file name.
- **debuginfod.** Off by default; TLS verified; redirects only within the
  same scheme, host and port; the size limit and now a deadline; the
  cache path is `<cache>/<build id>/debuginfo` with the build ID checked
  to be lower-case hex, written atomically; what arrives must be an ELF
  with `.debug_info` and the program's build ID before it is kept.
- **The HTTP gateway.** `Host` must be loopback, an IP literal, an
  `--allow-host` name or a certificate name on every request (static files
  too); a foreign `Origin` is refused unless `--allow-origin` names it; a
  session cookie is honoured only with the daemon's own `Origin` (or none)
  and the CSRF token. No change needed.
- **Scripts and plugins.** Scripts are not sandboxed, by decision (docs/
  security.md, "Limits"): whoever may run them has a shell as the daemon's
  user. Plugins are WebAssembly in wasmtime: fuel and a 30 s epoch limit,
  at most 1 GiB of memory, no WASI, only the imports their capabilities
  grant, guest pointers bounds-checked, output capped and decoded with
  checked readers; grants come only from `rk-daemon --plugin-grant`, and
  plugins can't be installed over the API. Left, low: the epoch limit
  doesn't interrupt a host call (`function_code` runs to completion and is
  charged after; memoized), `GetPluginFacts` re-runs analyzers that timed
  out each time a viewer asks (timeouts aren't memoized), and
  `ListPlugins` shows viewers rejected plugins' errors, which name host
  paths.
- **Project archive import.** Admin-only. Member names are never file
  names (members land in a scratch directory under names of our own),
  only regular ustar files are read, sizes and hashes match the manifest,
  inflation stops at the declared size, and nothing can overwrite files
  outside the project. Found: the stamps, the address sets and the
  unchecked values above. Decided, not changed: an archive keeps its ops'
  provenance and metadata (who made each edit), as `project_archive.h`
  says; the importer shows on the import's commit. An archive can
  therefore claim any author, which only an admin can import.

## TSan

| Suite | Result |
| --- | --- |
| `revkit_facts_tests` (the thread pool, the fact engine) | part 1: 97 tests pass, no warnings |
| `revkit_decompd_tests` (worker pool, batches) | part 1: 16 tests pass, no warnings |
| `revkit_detect_tests` (parallel candidate sweeps) | 25 tests, no warnings (24 minutes) |
| `revkit_analysis_tests` (parallel discovery) | 75 tests, no warnings |
| `revkit_plugins_backend_tests` | 7 tests, no warnings |
| `revkit_api_tests` (gRPC services, the gateway, auth, replication) | 73 tests, no warnings |
| `revkit_lift_tests`, with `Lift.ParkingFromManyThreads` (engines parked and taken back from several threads while another frees the spares) | 44 tests, no warnings |
| `revkit_backend_tests` (background analyzers, decompiler workers, collab, the engine sweeper, the language switch with `RawRebaseTest.ReadersAndTheSweeperDuringALanguageSwitch`) | 319 tests pass. Reports: the ExportC race (fixed), the store-writer lock-order cycle (a false positive, suppressed), and the injected worker SEGV. The six tests with reports pass clean since. |

Run them with the memory caps above, one suite at a time, e.g.
`TSAN_OPTIONS="suppressions=tools/sanitizers/tsan.supp halt_on_error=0"
setarch -R build-tsan/src/api/tests/revkit_api_tests`, and the backend
suite one test per process (see "How to run it").

## Left

Decided, not done (each a bigger change than a fix, or needing more than
the scrub had):

- **Archive provenance.** An archive keeps its ops' authors and
  metadata, by design (history and blame survive); only an admin can
  import one, and the import's commit names the importer. Re-stamping
  imported ops as `import:archive` would lose that history: left as is.
- **Integer facts from archives** (flow overrides, no-return marks,
  fallthrough numbers) are checked to be numbers, not range-checked; the
  readers treat unknown values as unset. Range checks would be cheap if a
  reader ever trusts them.
- **Plugins.** The 30 s epoch limit doesn't interrupt a host call (they
  are memoized and charged afterwards); `GetPluginFacts` doesn't memoize
  timeouts, so a viewer asking again re-runs analyzers that timed out.
  Both bounded; a per-caller rate limit would cover them, with the other
  expensive calls ("Rate of expensive calls" in security.md).
- **`ExportProject` to a host path** writes `<path>.tmp-<pid>` following
  links: an admin's own path, left.
- **Library roots on the host** read through the root now, but
  `FindLibrary`'s host directories (no root) are ordinary paths: an
  admin's import, as before.
- **`ui_e2e` under ASan**: not run (no finding was UI-related).
- **`detect_fuzzer`** needs `REVKIT_FUZZ_UBSAN_RECOVER=ON` (the vendored
  SLEIGH engine's known shifts); see the fuzzing table.

Every gap part 1 listed is fixed (ext CPU, FAT buffers, extraction
TOCTOU, the symbol server's redirects and URL characters, MSF shared
blocks, type archive sidecars) or, for `python_sdk` under ASan, has its
recipe in "How to run it".

## Fuzzing

`-DREVKIT_FUZZ=ON` with clang builds every harness (coverage, ASan and
UBSan, any report fatal). Part 2's runs, seeded from the corpus
(`out/corpus`) and the repo's fixtures, one at a time with
`-rss_limit_mb=2048`, `-timeout=10` and the `-max_len` shown:

| Harness | What | Runs | Executions | Found |
| --- | --- | --- | --- | --- |
| `cabinet_fuzzer` | `ExpandCabinet` | 3 + 5 min, 1 MiB | 9.6M | nothing |
| `symbol_path_fuzzer` | `ParseSymbolPath`, `FindPdb`'s names | 3 min | 1.6M | nothing |
| `debug_file_fuzzer` | build ID, debuglink, `CheckDebugFile` on a downloaded ELF, debuginfod URLs | 3 + 5 min, 2 MiB | 335k | nothing |
| `assertion_values_fuzzer` | data settings (with a round trip) and register values from archives | 1 + 3 min | 9.9M | nothing |
| `type_archive_fuzzer` | sidecars, `ProfileOf`, a header under the hostile profile | 3 + 5 min | 17k | nothing |
| `skeleton_prototype_fuzzer` | `ParseSkeletonPrototype` (BSim prototypes) | 3 + 5 min | 175k | nothing |
| `script_metadata_fuzzer` | `ParseScriptMetadata` | 3 min | 220k | nothing |
| `pe_reloc_fuzzer` | the PE `.reloc` reader, relocation names | 3 + 5 min, 2 MiB | 90k | nothing |
| `msvc_markup_fuzzer` | `parse_pe`, then `msvc::analyze` | 3 + 10 min, 2 MiB | 14k | nothing |
| `data_program_fuzzer` | `describe_data` over ELF and PE | 3 + 5 min, 2 MiB | 113k | nothing |
| `fid_program_fuzzer` | matching against a hostile database; `image_relocations` | 3 + 5 min, 2 MiB | 150k | nothing |
| `raw_loader_fuzzer` | Intel HEX, S-records, raw images, region specs | 3 min | 744k | nothing |
| `container_session_fuzzer` | sessions: nested mounts, crafted paths, identify | 3 + 10 min, 1 MiB | 2.1M | a harness bug (an uncaught refusal) |
| `extract_fuzzer` | `ExtractFileSystem`, checked for writes outside, links, limits | 1.5 + 10 min, 1 MiB | 2.1M | the zero-length read (fixed) |
| `project_archive_fuzzer` | (part 1's) | 3 + 5 min, 4 MiB, now seeded with a real `.rkproj` | 4.9M | nothing |
| `fuzz_pe`, `fuzz_elf` | (part 1's) | 5 min each, 2 MiB | 325k | nothing |
| `detect_fuzzer` | auto-detection on arbitrary bytes | 15 min, 2 KiB, with `REVKIT_FUZZ_UBSAN_RECOVER` | 229 | nothing; slow, not stuck (13 s for a 2 KiB input instrumented, 100 s for a 15 KB one) |

Notes:

- Part 1's harnesses not rerun here: `dwarf_fuzzer`, `pdb_fuzzer`,
  `fuzz_fid_db`, the `container_<format>_fuzzer`s and
  `container_codecs_fuzzer`, `cparse_fuzzer`, `demangle_fuzzer`.
- Most amplification bugs need inputs of 100 KB to several MB: run the
  PDB, `.fidbf`, PE and container fuzzers with a `-max_len` of 1-8 MB. At
  the default 4 KB they find none of part 1's.
- The loaders' and markup's harnesses run slowly on 1-2 MB PEs (a few
  hundred executions a second at most): longer runs would be worth it
  before a release.
- `extract_fuzzer` needs `RK_FUZZ_SCRATCH` (a directory of its own), and
  `detect_fuzzer` and `skeleton_prototype_fuzzer` need
  `GHIDRA_INSTALL_DIR`.
- Seeds were made by a script from the corpus and the SDK's fixtures
  (PEs and ELFs, `objcopy --only-keep-debug`, Intel HEX and S-records of
  `.text`, cabinets of a corpus PDB, zips and tars with nesting, links and
  traversal names). Crashes are kept as regression tests, not as files.

