# Crash dumps

A program that crashed leaves its state behind: an ELF core file on Linux
(and Android), a minidump on Windows (and from crashpad or breakpad
anywhere). revkit opens either as a debug session that is stopped where the
program crashed and never runs: the threads and their registers, memory as
it was dumped, the modules, the call stack unwound through the program and
its libraries, the faulting instruction, and a summary that says what
happened where. `api_minor` 102, feature `crash-dumps`.

- [What is read](#what-is-read)
- [The session](#the-session)
- [Where the missing bytes come from](#where-the-missing-bytes-come-from)
- [The summary](#the-summary)
- [Interfaces](#interfaces)
- [Limits and hostile input](#limits-and-hostile-input)
- [Tests and fuzzing](#tests-and-fuzzing)
- [Known gaps](#known-gaps)

The code: `src/crash` (`revkit::crash`: the two parsers into one model, no
dependency on the rest of revkit), `src/debug/crash_target.cc` (the dump as
a debugger target), `src/backend/debugger.cc` (the session: the bytes the
dump lacks, modules read from the host, the summary), `ui/src/debug/panel.ts`
(Crash dump… and the crash box).

## What is read

**ELF core files** (`ET_CORE`; 32 and 64-bit, either byte order), as Linux
writes them (`fs/binfmt_elf.c`), and as gdb's `gcore` and QEMU's user mode
do:

| Part | What revkit takes |
| --- | --- |
| `PT_LOAD` | each segment's address, size, file bytes and permissions (a segment the kernel didn't dump, such as a mapped file's code, has its size and no bytes) |
| `NT_PRSTATUS` | one per thread, the dumping thread first: the LWP, the pending signal, and the registers of `pr_reg` for x86-64 (27, `user_regs_struct`), i386 (17), AArch64 (34: `x0`-`x30`, `sp`, `pc`, `pstate` as `cpsr`), ARM (18) and RISC-V (32) |
| `NT_PRPSINFO` | the command (`pr_fname`), its arguments (`pr_psargs`), uid and gid (16-bit on i386 and ARM) |
| `NT_SIGINFO` | the signal, its code (`SEGV_MAPERR`, `BUS_ADRALN`, `SI_TKILL`, ...) and, for SIGSEGV, SIGBUS, SIGILL, SIGFPE and SIGTRAP raised by the kernel, the faulting address |
| `NT_AUXV` | the auxiliary vector (`AT_ENTRY` says which mapping is the program; `AT_SYSINFO_EHDR` the vDSO) |
| `NT_FILE` | every mapped file's range and file offset; grouped by path they are the modules, the one holding `AT_ENTRY` the main one |

A module's load bias comes from its ELF header and program headers when
the dump holds its first page (the kernel dumps it by default), else its
lowest address.

**Windows minidumps** (`MDMP`), from `minidumpapiset.h`:

| Stream | What revkit takes |
| --- | --- |
| ThreadList (3) | each thread's id, TEB, stack range and context |
| ModuleList (4) | each module's base, size, checksum, timestamp, path, version (`VS_FIXEDFILEINFO`) and CodeView record: `RSDS` (the PDB's path, and its GUID and age as a symbol server keys them) or breakpad's `BpEL` (an ELF build ID) |
| MemoryList (5), Memory64List (9) | the memory ranges and where their bytes are |
| Exception (6) | the thread, the code and its name (`EXCEPTION_ACCESS_VIOLATION`, `EXCEPTION_STACK_OVERFLOW`, `STATUS_STACK_BUFFER_OVERRUN`, C++ and .NET exceptions, ...), the address, the parameters (an access violation's read, write or execute and its address), and the context at the exception, which replaces the thread's |
| SystemInfo (7) | the processor architecture, the count of processors, the OS (Windows and its version, or breakpad's Linux, Android, macOS, iOS) |
| MiscInfo (15) | the process id |
| MemoryInfoList (16) | each region's protection, onto the memory ranges |
| ThreadNames (24) | thread names |
| CommentA/W (10, 11) | comments |

Thread contexts are read for x86-64 (`CONTEXT`, 1232 bytes), x86 (716),
ARM64 (`ARM64_NT_CONTEXT`, 912) and ARM; without SystemInfo the
architecture is guessed from the context's size.

The registers keep the names gdb uses (`rax`, `eflags`, `x0`, `cpsr`) and
map onto the program's SLEIGH registers as a GDB stub's do
([debugger.md](debugger.md#the-remote-serial-protocol-client)), with the
flag bits (`ZF`, `NG`, ...) derived as the emulator shows them.

## The session

`CreateDebugSession` with the target `crash` (`DebugCrashTarget`): the dump
is a program of the project (`dump_program_id`; an ELF core imports as a
program whose PT_LOAD segments are its memory blocks, and
`ProgramInfo.crash_dump` says `elf-core`), a file on the daemon's host
(`host_path`) or an upload (`upload_id`); the last two need an admin, as
an import does. The session's `program_id` is the program to see the crash
through: the crashed executable is best, for its code and its names; the
response's `crash.main_program_id` names the project's program of the
dump's executable when the session's program isn't it.

The session is a `CrashTarget` ([debugger.md](debugger.md#one-target-interface)):
its target kind is `crash-dump`, its state stopped, its stop a `SIGNAL`
whose detail is the reason ("SIGSEGV (SEGV_MAPERR) at 0x0") with the
faulting address, at the crashed thread's pc. Everything that reads a
stopped session works: registers, memory, threads (select one to see its
registers and stack), modules and the memory map, `GetDebugBacktrace`,
`EvaluateDebug` (watches and value hovers), `DisassembleDebugMemory`,
`CopyDebugMemory` (the heap or a stack into the program), Emulate from a
stop. Running, stepping, breakpoints and writes are refused (a
`FAILED_PRECONDITION`).

The program's address mapping is worked out as for a live process
([debugger.md](debugger.md#addresses)): `AT_ENTRY` minus the program's
entry for an ELF core, the main module's base for a minidump's PE. A module
that is another project program (a library the program links, or a
program of the module's name) is mapped to it with its slide
([debugger.md](debugger.md#libraries)): locations in it name that
program's function, and the call stack unwinds through it by its CFI.

## Where the missing bytes come from

A core leaves out what the files it maps already hold (their code, unless
a page was written), and a minidump usually holds only stacks and some
data. When a read asks for bytes the dump doesn't have, they come from, in
order:

1. the session's program, at its static address (code is what was mapped,
   unless the process changed it);
2. a project program that is the module there, at the module's slide;
3. for an admin's session, the module's file on the daemon's host, when
   its path (`NT_FILE`'s) lies under a `--browse-root`: opened without
   following links, at most 512 MiB, loaded once per session. Its
   call-frame information unwinds through it and its symbols name the
   frames they cover (by the symbol's size: a stripped library's
   internal functions keep their module and offset), so a stack through
   a C library that isn't in the project still reaches `main` by CFI.

What none of them has reads as unreadable, as a live target's unmapped
memory does.

## The summary

`GetDebugCrash` (and `CreateDebugSessionResponse.crash`) gives the
`DebugCrash`: the `reason`, the signal and its code or the exception and
its access, the `fault_address`, where it happened (`pc` with its module
and offset, `function` such as `lib_store` or `libc.so.6+0x98e51`), the
faulting `instruction` as the program's language decodes it, the crashed
thread's `backtrace` (`DebugFrame`s, as `GetDebugBacktrace` gives them),
every thread with its pc and where it is, the modules with the project
programs they are (and a minidump's versions and PDB keys), the process
and system, and `summary`, the report as text:

```
SIGSEGV (SEGV_MAPERR) at 0x0
at 0x76e73f3cb11d in lib_store+0x4 (libcrash.so+0x111d), thread 325885: MOV dword ptr [RDI],ESI
#0  0x76e73f3cb11d  lib_store+0x4  [libcrash.so+0x111d]  (registers)
#1  0x76e73f3cb149  lib_compute+0x26  [libcrash.so+0x1149]  (cfi)
#2  0x606f88b112b4  run_crash+0xf  [crash+0x12b4]  (cfi)
#3  0x606f88b1134b  main+0x79  [crash+0x134b]  (cfi)
#4  0x76e73f02a1ca  libc.so.6+0x2a1ca  [libc.so.6+0x2a1ca]  (cfi)
#5  0x76e73f02a28b  __libc_start_main+0x8b  [libc.so.6+0x2a28b]  (cfi)
#6  0x606f88b111a5  _start+0x25  [crash+0x11a5]  (cfi)
2 threads: 325885 (crashed) in lib_store+0x4; 325886 in libc.so.6+0x98e51
process 325885 "./crash"
```

(`tests/data/crash/crash.c` over its program and `libcrash.so` in the
project, the C library read from the host: frame 4 is an internal libc
function no exported symbol covers, so the module and offset name it.)

## Interfaces

- **API**: `DebugService.CreateDebugSession{program_id, crash{dump_program_id
  | host_path | upload_id}}`, `GetDebugCrash{session_id, max_frames}`;
  `ProgramInfo.crash_dump` ([api.md](api.md#crash-dumps)).
- **Python SDK**: `Program.crash_dump(dump_program, host_path=, file=)`
  returns a `DebugSession`; `DebugSession.crash()`.
- **MCP**: `debug_crash_dump` (opens it: the session id and the crash),
  `debug_crash`; the other `debug_*` read tools work on the session.
- **The UI**: the Debugger view's target picker has **Crash dump…**: a dump
  program of the project, a file on the daemon host, or one from this
  computer; the view then shows the crash box (the reason, where, the
  faulting instruction, **Copy report**, and **Open the executable** when
  the dump's program is another), and its registers, stack, threads,
  modules, memory and disassembly as for any stop
  ([ui.md](ui.md#crash-dumps)).

## Limits and hostile input

Both parsers check every offset and count against the file; at most
16,384 threads, 2^20 segments or memory ranges, 262,144 mapped files and
16,384 modules; a note or stream that doesn't fit is a warning, and the
rest is read. A truncated core (a segment whose bytes run past the file)
reads what is there. The dump file is mapped read-only (a host file or an
upload) or is the program's stored bytes.

## Tests and fuzzing

- `revkit_crash_tests` (`src/crash/tests/crash_test.cc`): a real core of
  `tests/data/crash/crash.c` crashing in `libcrash.so` (two threads), made
  at test time by the host's kernel when `core_pattern` writes a file, else
  by `gcore` on the program stopped; an AArch64 program's core written by
  `qemu-aarch64`; 32-bit cores in the i386 and ARM note layouts built by the
  test; minidumps of `tests/data/crash/win.c` built with mingw for x86-64
  and x86 (`tests/data/crash/make_minidump.py` writes the dump: the module
  list with CodeView and version records, two named threads, the
  exception, the stacks in the memory list, a heap range in Memory64,
  memory info, misc and system info, a comment) and an ARM64 one; truncated
  and flipped bytes of each.
- `python_sdk` (`sdk/python/tests/test_crash_dumps.py`): the core imported
  as a program and opened over the program with its library in the
  project (the summary's reason, the faulting instruction from the
  library's bytes, the backtrace through the library by CFI to `main`, the
  second thread, the memory map), the same core from the host with the C
  library read from its file under `--browse-root`, the x86-64 minidump
  over the mingw program at another base, the roles, MCP.
- `revkit_debug_tests` (`src/debug/tests/crash_target_test.cc`): the
  target over a dump built in the test (registers by SLEIGH name, derived
  flags, threads, the backing, refusals), and the CFI interpreter's
  `DW_CFA_restore_state`, which brings the CFA back with the registers
  (found here: GCC's mid-function epilogues left a thread waiting in
  libc unwound with the epilogue's CFA, and the stack stopped there).
- `ui_e2e` (`ui/e2e/crash.ts`): Crash dump… from the daemon host over the
  imported program: the crash box, the stack through the library to
  `main`, Continue disabled.
- **Fuzzing** (`-DREVKIT_FUZZ=ON`, clang): `crash_elf_core_fuzzer` and
  `crash_minidump_fuzzer` (the parse, then every register read back as an
  address): 1.2M and 2.0M executions in four minutes each (2026-10-18),
  seeded with the cores and minidumps above, nothing found.

## Known gaps

- Floating-point and vector registers (`NT_FPREGSET`, `NT_X86_XSTATE`, a
  context's XMM area) are not read.
- Minidumps don't import as programs; open them from the host or an upload
  over their executable's program. Windows unwind data (`.pdata`) is still
  not read, so a minidump's stack above frame 0 is found by frame pointers
  or a stack scan.
- Kernel dumps (`kdump`, Windows full memory dumps), Apport's `.crash`
  files and macOS cores are not read.
- RISC-V cores are parsed by their layout but no test made one (QEMU's
  user mode writes none for RISC-V).
