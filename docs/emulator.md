# Emulator

revkit runs machine code in a p-code emulator: any SLEIGH language, from
the API, the command line and the UI. It is the base of the debugger
([debugger.md](debugger.md)), and of firmware emulation: a board around
the CPU, with exceptions, interrupts, peripherals and a clock
([firmware-emulation.md](firmware-emulation.md)).

| Where | What |
| --- | --- |
| `src/emu` (`revkit::emu`, `include/revkit/emu/emulator.hh`) | The emulator: state, execution, hooks, trace |
| `src/emu` (`include/revkit/emu/machine.hh`) | Machines: CPU exception models, peripherals, the machine description ([firmware-emulation.md](firmware-emulation.md)) |
| `tools/rk-emu` | `rk-emu`, the command line |
| `proto/revkit/v1/emulator.proto`, `src/backend/emulator.cc` | `EmulatorService` (`api_minor` 12, feature `emulator`) on the image backend |
| `sdk/python` (`Program.emulate`, `EmulatorSession`) | Python helpers |
| `ui/src/emu/panel.ts` | The UI's emulator panel |

**Session state, not facts.** What an emulation does (registers, memory
it writes, breakpoints, the trace) belongs to the person or agent running
it. Nothing is asserted, no revision is made, and other clients see a
session only if they hold its id. The emulator reads the loaded image, and
never the fact store.

## Design

### An interpreter of our own, over revkit's p-code

Ghidra's C++ sources include an emulator core (`emulate.{hh,cc}`,
`memstate.{hh,cc}`, `opbehavior.{hh,cc}`: `EmulatePcodeCache` over a
`MemoryState` of `MemoryBank`s). revkit doesn't use it, and interprets the
p-code `revkit::lift` decodes itself (`src/emu/interp.cc`, about 600 lines):

- **Values wider than 64 bits.** `OpBehavior` and `MemoryBank::getValue`
  compute on `uintb`, eight bytes. Real code needs more: x86 `XMM`/`YMM`
  registers (SSE in any compiled C), AArch64's `Q` registers, the 128-bit
  `RDX:RAX` dividend of x86-64 `DIV`, a `PIECE` of two 8-byte halves.
  (Ghidra's Java emulator uses `BigInteger` for this reason.) revkit's
  values are 1 to 64 bytes (`src/emu/wide.hh`).
- **Faults and hooks on every access.** A debugger needs to stop on an
  unmapped or protected access and leave the machine as it was before the
  instruction, record each read and write in a trace, route MMIO to hooks,
  and stop on watchpoints. `MemoryState` reads unmapped memory as the load
  image's fill and has no way to refuse an access. revkit's memory checks
  every access against the mapped regions and undoes a faulting
  instruction's writes.
- **Decoding from the emulator's memory.** `EmulatePcodeCache` decodes
  through its own `Sleigh` over a static `LoadImage`. revkit decodes the
  bytes the emulated program sees (`Lifter::lift(address, bytes)`), so code
  it writes runs as written, and the instruction set (ARM/Thumb) is the
  emulator's state, not the image's.

What is Ghidra's: the decoding and the p-code (SLEIGH, identical to
Ghidra's), the opcode semantics as Ghidra documents them (`FLOAT_ROUND` is
`floor(x + 0.5)` as in `FloatFormat::opRound`), and the calling
conventions, read from the language's `.pspec` and `.cspec`
(`lift::read_abi`: program counter, stack pointer, where calls leave the
return address, integer parameter and return registers).

### State

- **Registers**: the register space, flat (`registers()` lists every
  register the language names; `display_registers()` the ones a debugger
  shows: general purpose, sp, pc, flags).
- **Memory**: the default space as the loaded image with written pages laid
  over it. A page is copied from the image on its first write, and pages
  are shared (`std::shared_ptr`) so a copy of the state costs a pointer per
  page: the base of checkpoints later. Regions are the image's segments
  (rounded to pages for ELF and PE, as a process maps them), plus what a
  session maps: a stack, the program break and anonymous mappings, the
  stub region. Other address spaces (RISC-V `csreg`, ...) are sparse and
  read as zero.
- **MMIO**: a raw image's volatile regions (`--region ...:volatile`,
  `MemoryRegion.is_volatile`). Each access goes to a hook if there is one
  (which may supply a read's value) and is recorded in a bounded log; a
  read without a hook returns the last value written. With a machine
  attached (`attach_machine`), its peripherals' registers answer first
  ([firmware-emulation.md](firmware-emulation.md#peripherals)).
- **Byte order and word size** come from the language; LOAD and STORE scale
  pointers by the space's word size.
- **Bounds**: `Options::max_memory` counts written pages, registers and
  temporaries; mapped but untouched memory costs nothing.

### Execution

`step()`, `run()` (a step budget, an `until` address, a deadline,
cancellation), `step_over()` (a call runs to its fall-through, with the
stack pointer back at least where it was, so recursion doesn't stop early)
and `step_out()` (until a return leaves the current call depth). A run
starting on a breakpoint executes that instruction first. Stops:

| Stop | When |
| --- | --- |
| `stepped`, `step_limit`, `until`, `breakpoint` | as asked |
| `returned` | a `call` start's function returned to its return trap (`exit_code` holds the return value) |
| `exited` | an exit system call or exit stub |
| `halted` | a halt, or an instruction that branches to itself and changes nothing (x86 `HLT`, ARM `b .`) |
| `unmapped`, `protection` | fetch, read or write of unmapped memory; a write to read-only or fetch from non-executable memory (ELF and PE; raw images run code from RAM) |
| `decode`, `unimplemented` | bytes that don't decode; an instruction without semantics, or an op or size the emulator lacks |
| `userop`, `syscall` | a `CALLOTHER` or system call without a handler |
| `watchpoint` | after an instruction read or wrote a watched range |
| `divide_by_zero`, `memory_limit`, `time_limit`, `cancelled`, `hook` | |
| `exception`, `idle` | with a machine: the CPU took an exception a breakpoint asked for; it waits for an interrupt and nothing is scheduled to raise one |

A fault undoes the instruction: registers and memory are as before it, and
the pc is on it, so the person can fix the cause (map memory, add a hook,
set a register) and continue.

**Starting.** `start(entry, mode)`: `process` builds a Linux process's
stack (argc, argv, envp, the auxiliary vector with `AT_PHDR`, `AT_ENTRY`
and a fixed `AT_RANDOM`); `call` maps a stack, passes integer arguments
in the convention's registers (then the stack), and sets a return address
(on the stack, or in the link register) that stops the run; `bare` sets
only the pc. `automatic` is a process at an ELF's entry point on Linux,
bare for raw images, else a call.

**Instruction sets.** ARM's Thumb state follows the `TB` register, which
Ghidra's ARM spec sets where the hardware switches (`BX`, `BLX`, loads to
pc); Thumb code decodes with a second engine (`TMode` set). AArch64 keeps
NZCV in four flag registers, but `MRS`/`MSR NZCV` move a separate
register: the emulator composes it before an instruction reads it and
splits it after one writes it. x86 user code runs with `IF` set. Thumb-2
IT blocks are the emulator's state too (`ITSTATE`: the decoder carries no
context for them), so the instructions of a block run or are skipped by
its condition, and 16-bit instructions inside one leave the flags alone.

**Machines.** `attach_machine(spec, options)` replaces `start`: it maps
the board's memory, builds and wires its peripherals, and resets the CPU
into its power-on state at the machine's entry or reset vector. From then
on the CPU model delivers interrupts between instructions, exception
entries and returns are recorded steps, and time is a tick count that
peripherals schedule against ([firmware-emulation.md](firmware-emulation.md)).

### Hooks

- **User ops** (`on_userop(name, handler)`): a `CALLOTHER` by name, with its
  inputs; the handler may produce the output. Barriers, hints and cache
  maintenance are no-ops. Built in, where the specs leave semantics to the
  emulator: x86 `CPUID` (a baseline x86-64: SSE2, no AVX, so libraries pick
  their generic routines) and `RDTSC` (the step count); AArch64 `DC ZVA`
  (zeroes the 64-byte block `DCZID_EL0` announces), exclusive monitors
  (one thread: stores always succeed), and the NEON ops glibc's string
  functions use that the spec leaves as `CALLOTHER`s (`EXT`, the pairwise
  `ADDP`/`UMAXP`/`UMINP`/`SMAXP`/`SMINP` and their across-vector forms).
  A user handler replaces a built-in one; anything else without a handler
  stops.
- **System calls** (`on_syscall`): Linux is installed for ELF programs on
  x86-64, x86, AArch64, ARM and RISC-V: `read` (from `stdin_data`),
  `write`, `writev` (fds 1 and 2 are captured), `exit`, `exit_group`,
  `brk`, `mmap`/`mmap2` (anonymous), `munmap`, `mprotect`, `arch_prctl`,
  `set_tid_address`, `uname`, `clock_gettime`, `gettimeofday` (a clock
  that advances with the step count), `getrandom` (fixed bytes), the
  process and user ids, and failures for files (`openat` is `-ENOENT`).
  An unknown call stops (or returns `-ENOSYS` with
  `unknown_syscalls_fail`). x86-64's `SYSCALL` leaves `RFLAGS` in `R11` as
  the kernel does.
- **MMIO** (`on_mmio`), above. A hook can set `MmioAccess::stop` to
  stop before the instruction (it is undone), which is how the debugger's
  client-answered hooks work ([debugger.md](debugger.md#hooks)). Its
  `mark_mmio` makes any mapped range MMIO, so its accesses reach the hook.
- **Watchpoints** (`add_watchpoint(start, size, read, write)`).
- **Stubs** (`stub(address, name, handler)`): a handler runs instead of
  the code at an address. Imports are bound to stub addresses as the
  dynamic loader would bind them: ELF `JUMP_SLOT`, `GLOB_DAT` and absolute
  relocations of undefined symbols (and `RELATIVE` ones applied), PE import
  address tables. Built-in stubs cover what a small C program imports:
  `__libc_start_main` (which calls `main(argc, argv, envp)` and exits with
  its result), `exit`, `abort`, `puts`, `putchar`, `printf`/`__printf_chk`
  (integer and string conversions), `write`, `strlen`, `strcmp`,
  `strncmp`, `strcpy`, `memcpy`, `memmove`, `memset`, `memcmp`, `malloc`,
  `calloc`, `realloc`, `free`, `__cxa_atexit` and the like. Any other
  import is **skipped**: it returns `import_return` (0 by default) unless
  its prototype returns nothing, and a callee-pops (stdcall) import pops
  its parameters. Prototypes come from revkit's library signatures
  (`infer::library_prototype`, glibc and Windows headers).

### Trace

Each step records the pc, the instruction (bytes and text, or `<stub
name>`), the registers it wrote with their new values, its memory reads and
writes (address, bytes, MMIO or not), and a note (a system call, a stub).
The trace keeps the last `trace_capacity` steps (4096 by default); its
summary counts everything (steps, distinct pcs, reads, writes, MMIO,
system calls, stubs, user ops). `trace_json()` (and `rk-emu --trace`,
`GetEmulatorTrace(json)`) serializes the language, the stop, the summary,
stdout and stderr, the display registers, the MMIO log and the entries.

**Determinism.** The same image, options and inputs give the same trace,
byte for byte: nothing reads the host's clock or randomness (the clock and
`AT_RANDOM` are functions of the step count), maps are laid out by search
from fixed hints, and output orders are fixed. A unit test runs a program
twice and compares the JSON.

### Lazy memory

`Options::backing` starts an emulator on a debugger's state instead of
the image ([debugger.md](debugger.md#emulating-from-a-stop)). Its
`regions` replace the image's segments. Memory nothing has written yet is
read through `read`, a page at a time, the first time it is touched, and
kept as a clean copy. A write copies it, as image pages are copied. With
a backing no imports are bound and no library stubs are installed,
because the process bound its own and its library code runs as it is.

### Checkpoints

`checkpoint()` captures the whole state: registers, memory (the page table
of copy-on-write pages, so a checkpoint costs a pointer per page until
either side writes), the mapped regions, the process state (program
break, mmap hint, the malloc stub's arena, stdin read so far, output
length), the step count, Thumb and IT state, and the call depth.
`restore()` goes back to it. Restoring also cuts the output and the trace
back, drops the decode cache, and leaves breakpoints, watchpoints and
hooks as they are now. A checkpoint belongs to its emulator, and another
emulator refuses it. With a machine attached, `checkpoint()` throws,
because peripheral state isn't captured. The debugger keeps one per
recorded stop, to go back to any snapshot ([debugger.md](debugger.md#rewind)).

## Command line

```sh
rk-emu prog                                   # a Linux process from the entry point, to its exit
rk-emu --entry fib --arg 10 prog              # a call: fib(10), stops when it returns
rk-emu --break main --steps 100000 --reg RBX=0x1234 --trace out.json prog
rk-emu --print-pcode --steps 20 prog          # each instruction, its p-code and what it wrote
rk-emu --raw --lang ARM:LE:32:v4t:default --region sysctrl:d0000000:1000:rw-:volatile \
    --region sram:20000000:10000 --mmio 0xd0000018=1 --steps 100000 firmware.bin
```

The raw options are rk-lift's (`--raw`, `--lang`, `--base`, `--raw-offset`,
`--raw-length`, `--raw-perms`, `--raw-entry`, `--region`); also `--mode
process|call|bare`, `--until`, `--mem addr=hexbytes`, `--watch
addr:size[:r|w|rw]`, `--stdin file`, `--import-return`, `--no-stubs`,
`--enosys`, `--max-memory`, `--timeout`. The program's stdout and stderr
are printed as they were captured, then a summary (why it stopped, the
registers, counts) on stderr. The exit status is 0 when the emulation ran,
3 when it stopped on a fault, 1 and 2 for load and option errors.
`--version` prints revkit's version.

Firmware on a board ([firmware-emulation.md](firmware-emulation.md#rk-emu)):

```sh
rk-emu --machine board.json --input 'help\n' --events firmware.bin     # memory, peripherals, interrupts
rk-emu --machine board.json --break-on irq:4 firmware.bin              # stop when the CPU takes IRQ 4
rk-emu --raw --lang ARM:LE:32:v4t --derive-machine starter.json firmware.bin
```

`--machine` runs the file on a machine description (a file the ELF and
PE loaders don't take loads as the machine's raw image); `--input` feeds
the console UART, `--break-on` sets exception breakpoints, `--events`
prints the exceptions taken, `--derive-machine` writes a starter
description and exits, and `--plugin-dir` and `--plugin-grant` load
peripheral plugins for a machine's `plugin:NAME` kinds.

## API

`EmulatorService` (`api_minor` 12, feature `emulator`):

| RPC | |
| --- | --- |
| `CreateEmulatorSession` | program, entry (default: the entry point), start mode, arguments, registers, memory, breakpoints, limits, `import_return`, `no_library_stubs`, stdin, `client`. Returns the session id, the language, every register (with the display set marked), the pc and sp registers, the state and the limits in force |
| `RunEmulator` | `RUN`, `STEP_INTO`, `STEP_OVER`, `STEP_OUT`, with `max_steps`, `until`, `time_limit_ms`. Returns the stop and the state |
| `GetEmulatorState` | pc, Thumb, steps, the last stop, registers (the display set, named ones, or all) each with `changed` (since before the last run), breakpoints, memory used, stdout and stderr from an offset, regions |
| `WriteEmulatorRegisters`, `ReadEmulatorMemory`, `WriteEmulatorMemory` | by name (any width, as `bytes`); memory reads report unmapped ranges |
| `SetEmulatorBreakpoints` | add, remove, clear |
| `GetEmulatorTrace` | entries from an index, the summary, or the whole trace as JSON |
| `ListEmulatorSessions`, `CloseEmulatorSession` | |

Firmware (`api_minor` 20, feature `firmware-emulation`;
[firmware-emulation.md](firmware-emulation.md#api-python-mcp-and-ui)):
`CreateEmulatorSession` takes a `machine` description or the
`machine_name` of a saved one, and then describes the machine in its
response; states carry `machine`, `tick` and `waiting`; trace entries the
`exception` they entered; `SetEmulatorBreakpoints` takes
`exception_breaks`.

| RPC | |
| --- | --- |
| `WriteEmulatorInput` | bytes for a UART of the session's machine (the console by default) |
| `GetEmulatorMachine` | the CPU's mode, banked and system registers, each device's state, pending lines, the machine's log, and the exceptions taken from an index on |
| `ListMachines`, `GetMachine`, `SaveMachine`, `DeleteMachine` | machine descriptions kept with a program (64 at most, 4 MiB each) |
| `DeriveMachine` | a starter description for a program, from its memory, the MMIO its code reaches and trial runs |
| `ListPeripheralKinds` | the built-in peripheral kinds and the daemon's peripheral plugins |

Bounds (the server's defaults and caps; a request may ask for less, or up
to the cap):

| | Default | Cap |
| --- | --- | --- |
| steps per call | 1,000,000 | 50,000,000 |
| steps per session | 100,000,000 | 1,000,000,000 (then stop kind `SESSION_LIMIT`) |
| memory per session | 256 MiB | 1 GiB |
| trace | 4,096 steps | 65,536 |
| time per call | 5 s | 60 s (and never past the call's deadline) |
| sessions | 8 per client, 64 in all | |

A session belongs to `client` (default: the connection's peer): it counts
toward that client's bound and is listed for it. It is closed after 30
minutes without a call. Calls on one session run one at a time.

With authentication ([security.md](security.md)), a session also belongs
to the identity that created it (`user:alice`, `agent:ci`): every call on
it by anyone else answers `NOT_FOUND`, as if it didn't exist, and
`ListEmulatorSessions` shows a caller only its own sessions (all of them
when `client` is empty, whichever tab or connection made them). Admins
reach every session, to inspect or close a runaway one. The bound of 8 is
then per identity, whatever `client` says. Creating, running, stepping,
writing registers or memory, setting breakpoints and closing need the
editor role (creating also needs access to the program's project);
reading state, memory and the trace and listing need viewer, though only
an owner or admin gets past `NOT_FOUND`. Input to a session's machine is a
write (editor, the owner); saving, deleting and deriving machines need
editor on the program's project, listing and reading them viewer.

Python:

```python
with rk.program("default/prog").emulate(fib, mode="call", args=[10]) as emu:
    emu.breakpoint(fib)
    print(stop_kind(emu.run().stop), emu.registers("RAX"))
    emu.step_over(); emu.step_out()
    print(emu.read(emu.register("RSP"), 16), emu.trace(limit=10).summary.steps)

with rk.program("default/fw").emulate(machine=open("board.json").read()) as emu:   # firmware on a board
    emu.run(); emu.input(b"help\n"); emu.run()
    print(emu.stdout, [e.kind for e in emu.machine().events])
```

## UI

The **Emulator** view (`Ctrl+8`; docked at the side by default, movable like
the other views) works on one session. "Emulate from here" (command
palette) starts it at the selected instruction: a call into it, or the
process at the entry point. Step, Over, Out and Continue (F7, F8, Shift+F8,
F9), Restart and close; the display registers, the ones the last step or
run changed highlighted, double-click to change one; a memory view at an
address or a register's value; the program's output and why it stopped. A
click in the listing's gutter sets or clears a breakpoint (kept for the
next session too); the listing follows the pc and marks its row, the graph
marks its line, and the decompiler marks the C lines the pc's instruction
produced. The panel is its own module (`ui/src/emu/panel.ts`: its DOM,
styles and keys); the app registers it as a view with a few lines.

## Verification

| Test | What |
| --- | --- |
| `RealExecution.*` (`src/emu/tests/realexec_test.cc`) | Six C programs (`programs/`: loops, integer arithmetic at every width with overflow and comparison flags and 128-bit products, calls with recursion, function pointers, varargs, structs by value and stack arguments, the stack, the program break and mappings, floating point, system calls) at -O0 and -O2 for x86-64, AArch64 and RISC-V 64: 36 builds, run natively (x86-64) or under qemu-user, and in the emulator. They must agree on every general register (and the flags) entering the program's final `rk_finish` (the program dumps them; the emulator stops there on a breakpoint), on the memory the program filled, on stdout, stderr and the exit status. **35 pass; 1 is skipped** (RISC-V floats at -O2, a spec bug below) |
| `StaticLibc.*` | A statically linked glibc program (`programs/libc.c`: glibc's own start-up with TLS and IRELATIVE resolvers, malloc, `snprintf` with `%.3f`, `atexit`) for x86-64 and AArch64: the same output and status as natively and under qemu-user |
| `LibraryStubs.*` | A dynamically linked PIE (glibc) runs on the library stubs from `_start` to `exit` with the same output and status as natively; skipped imports return the configured value |
| `Firmware.*` | The synthetic ARM firmware (`src/analysis/tests/fixtures/armfw`) from its reset vector: unanswered MMIO spins `mmio_init` (writes and reads recorded); with a hook answering the status register it runs ARM and Thumb code (interworking both ways, the jump table, the function pointer table) until `poke_bad_slot` stores through `0xffffffff`, an unmapped write, deterministically |
| `Emu.*` | Stepping and the trace, breakpoints, step over and out, faults that undo the instruction, `CALLOTHER` without and with a handler, watchpoints, the step and memory bounds, 128-bit `DIV` and SSE, the return trap, deterministic traces |
| `EmulatorApi.*`, `python_sdk` (`test_emulator.py`), `rk_emu_smoke` | The service on the image backend (sessions per client, bounds, changed registers, memory with unmapped ranges, the trace), the SDK, the CLI |
| `ui_e2e` | Emulate from here, a step with a changed register, a breakpoint from the gutter, continue to it, step over the call (RAX changed), the return |
| `FirmwareMachine.*`, `Machine.*`, `PeripheralPlugins.*`, `FirmwareApi.*` | Machines: [firmware-emulation.md](firmware-emulation.md#verification) |

All of them pass under ASan+UBSan and TSan (`scripts/ci.sh --asan --tsan`).

Differences the tests mask, each from Ghidra's specs, not from the
emulator: x86's spec leaves `AF` alone in most arithmetic and `PUSHF` omits
the always-one bit 1 of RFLAGS (so flags are compared on CF PF ZF SF IF DF
OF, and `R11` after `SYSCALL` without AF); qemu-user starts AArch64 with Z
set where Linux clears NZCV (the test program sets the flags first).

**Speed**: about 2.8 million instructions a second without a trace and
1.6 million with one (ARM firmware loop, one core); decoding is cached per
address and dropped when code is written.

## Limits

- **Spec bugs reproduce.** The emulator runs Ghidra's p-code as written:
  RISC-V's `fmv.x.d` reads a register through the address of a temporary
  (`&frs1D`), so it reads the wrong register (found by the RISC-V -O2 float
  test); x86's AF and PUSHF bit 1 as above.
- **Floating point**: round to nearest even only (MXCSR, FPCR and `frm`
  rounding modes are ignored); NaN payloads follow the host (x86-64);
  x87's 80-bit values and quad precision compute in `long double`. Out of
  range `TRUNC` wraps into the unsigned range (what AArch64 `FCVTZU` and
  RISC-V `fcvt.lu.d` do, which the specs write with `trunc`), beyond it is
  the most negative value (x86's integer indefinite).
- **Operating system**: Linux system calls only, the subset above; no
  signals, threads, `fork`, files or sockets; no Windows system calls (PE
  imports are stubbed or skipped). Dynamically linked programs run on
  stubs, not on their real libraries, and the C library stubs are minimal
  (printf has no floating point conversions); statically linked programs
  run their real C library (tested with glibc on x86-64 and AArch64; on
  RISC-V the `fmv.x.d` spec bug breaks its floating point output).
- **Missing semantics**: SIMD instructions the specs leave as `CALLOTHER`s
  stop the run (`userop`) unless built in above or given a handler
  (Ghidra's AArch64 spec has a few hundred, mostly NEON).
- **Firmware without a machine**: no interrupts or exceptions are
  delivered (an IRQ handler runs only if called); MMIO is a value store
  unless a hook models the device; Cortex-M's initial SP is not loaded
  from the vector table (set it with `--reg sp=...`). A machine
  (`--machine`, `attach_machine`) gives all three on ARM, Cortex-M and
  MIPS32, within [its own limits](firmware-emulation.md#limits).
- **Context**: only ARM's Thumb and IT state are tracked at run time. Other
  `globalset` context (MIPS16, microMIPS, PowerPC VLE) keeps the
  language's defaults. Spaces with a word size above one byte are scaled
  for LOAD/STORE but otherwise untested.
- Values are at most 64 bytes (AVX-512); delay-slot instructions execute
  with their branch as one step.
- Step over is a heuristic: the call's fall-through with the stack pointer
  back at or above where it was. A function that never returns there (a
  longjmp, a tail call into a no-return function) runs to the next stop.

## Toward the debugger

The debugger is built: [debugger.md](debugger.md) (the emulator as one
target, live processes and boards as others, one session model, the
recorded timeline). What follows is the plan it started from.

The emulator is the first target of a debugger whose sessions look the same
whatever runs the code:

1. **Checkpoints and reverse execution** (done: [Checkpoints](#checkpoints),
   [debugger.md](debugger.md#rewind)). Memory is copy-on-write in
   shared pages, so a checkpoint is a copy of the page table and the
   register file. With the deterministic execution above, stepping back is
   re-running from the nearest checkpoint; the trace already says what
   each step wrote, so short reverse steps can undo from it directly.
2. **A target interface.** `EmulatorService`'s calls (registers by name,
   memory, breakpoints, run/step/out, stops) are what a live target needs
   too. A `gdbserver` (remote serial protocol) or ptrace target behind the
   same session API makes "attach" another start mode, with the emulator
   available to run a function of the live process's memory on the side.
3. **Events.** Long runs report through the per-call time bound now; a
   server stream of stops and progress (like `Subscribe`) lets a UI follow
   a run and cancel it.
4. **Source-level stepping.** The decompiler's token map (instruction
   address per C token) already marks the pc's C lines; stepping by C line
   is running until the pc leaves the current line's instructions.
5. **Facts where they belong.** A session stays user state; what a person
   learns from it (a resolved indirect call, a decrypted string) becomes an
   assertion with `user:` or `agent:` provenance through the existing API,
   and could later be suggested by analyses that emulate (constant
   propagation through `CALLOTHER`s, string deobfuscation) with
   `analysis:` provenance.
