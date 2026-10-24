# Debugger

revkit debugs the program it analyses, whatever runs it: its own p-code
emulator, a Linux process, a QEMU machine, or a board behind a GDB server.
One session model covers them all: the same registers (named as the
program's SLEIGH language names them), memory, breakpoints, stops, threads
and modules, with every stop recorded on a timeline that can be scrubbed.

| Where | What |
| --- | --- |
| `src/debug` (`revkit::debug`) | Targets, the GDB remote client, sessions, the timeline |
| `proto/revkit/v1/debugger.proto`, `src/backend/debugger.cc` | `DebugService` (`api_minor` 14; features `debugger`, `debugger-live`; firmware on a machine: `api_minor` 20, feature `firmware-emulation`; the call stack: `api_minor` 59, feature `debugger-stack`) |
| `src/debug/unwind.cc` | Call-stack unwinding: CFI, frame pointers, a stack scan |
| `src/debug/expr.cc` | Expressions: what watches, value hovers and conditions evaluate (`api_minor` 60, feature `debugger-values`) |
| `tools/rk-dbg` | `rk-dbg`, scripted sessions |
| `sdk/python` (`Program.debug`, `DebugSession`) | Python helpers |
| `ui/src/debug/panel.ts` | The UI's Debugger view |

A session is the caller's state, as an emulator session is
([emulator.md](emulator.md)): nothing is asserted and no revision is made.
A trace goes to the project only when saved, and never into the assertion
log.

## Design

### One target interface

`Target` (`target.hh`) runs code and can be stopped and inspected:
registers by name, memory (reads report unreadable ranges), resume (run,
step; step over and out where the target has them), wait, interrupt,
software and hardware breakpoints, write/read/access watchpoints, stop
reasons, threads (list, select), modules, the memory map, and lifetime
(detach, kill). Stop kinds are the emulator's plus `signal`, `interrupted`,
`running` (still running at the call's deadline), `killed`, `detached` and
`disconnected`; and, for the emulator on a machine, `exception` (an
exception breakpoint) and `idle` (the CPU waits for an interrupt nothing
is scheduled to raise).

| Target | |
| --- | --- |
| `EmulatorTarget` | revkit's emulator. Its own step over and out; between stops it hands over the instructions it ran (registers written, memory read and written with the bytes each write replaced). With a machine ([firmware-emulation.md](firmware-emulation.md)) it runs firmware on a board, and each instruction also says which exception it entered or returned from |
| `GdbRemoteTarget` | a stub speaking the GDB remote serial protocol |
| `TraceTarget` | a saved trace: read-only, its last snapshot is "now" |
| `CrashTarget` | a crash dump (an ELF core file, a Windows minidump; `api_minor` 102, feature `crash-dumps`; [crash-dumps.md](crash-dumps.md)): stopped where it crashed, read-only; threads, registers, memory as dumped (the rest from the programs it ran), modules, the memory map |

A `Session` (`session.hh`) drives a target through the program: it maps
addresses, keeps breakpoints in program or runtime terms, builds step over
and out for targets that only single-step, and records the timeline.

### The remote serial protocol client

Written for revkit (`rsp.cc`, `gdb_remote.cc`), rather than driving gdb as
Ghidra's agents do: one process fewer, and the same code for gdbserver,
QEMU, OpenOCD and J-Link.

- Transports: TCP (`host:port`, `tcp:`, `gdb://`), Unix sockets
  (`unix:/path`), a socketpair to a child.
- Packets: checksums, acknowledgements with retransmission,
  `QStartNoAckMode`, run-length decoding, binary escapes, `O` output while
  running, the interrupt byte. `RK_RSP_TRACE=1` prints every packet.
- Registers: `qXfer:features:read` target descriptions with nested
  `xi:include`s; `g` for the contiguous block, `p` for the rest, `P` or `G`
  to write; built-in layouts for stubs without descriptions (x86, x86-64,
  ARM, Cortex-M, AArch64); expedited registers from stop replies.
- Memory: `m` in packet-sized chunks, skipping unreadable pages; `X` or `M`.
- Execution: `vCont` (a step holds other threads, a continue runs all);
  signals the program received are delivered on resume, as gdb does.
  Resuming from a breakpoint steps off it with the breakpoint removed
  first: stubs report it again otherwise.
- Breakpoints: `Z0`-`Z4` with each architecture's kind (ARM 2 for Thumb,
  an odd address); a refused software breakpoint becomes a hardware one.
- Threads, `qXfer:libraries-svr4` and `exec-file`, the auxiliary vector,
  `/proc/<pid>/maps` through `vFile`, `qXfer:memory-map`, `qRcmd` monitor
  commands, extended mode (`vAttach`).

**Register names.** A stub's register maps onto the SLEIGH register with
the same name ignoring case, with aliases where gdb and SLEIGH differ:
x86-64 `eflags` is `rflags` (as Ghidra's gdb agent maps it), `fs_base` and
`gs_base` are `FS_OFFSET` and `GS_OFFSET`, AArch64 `v0`-`v31` are `q0`-`q31`.
The emulator's flag registers are derived from the status register (x86
`CF ZF SF ...` from `eflags`, ARM/AArch64 `NG ZR CY OV` from `cpsr`, ARM
`TB` from the T bit), read and written through it, so the register panel
is the same whatever runs the code.

### Launching

`launch()` starts the program stopped at its first instruction under
`gdbserver --once -` over a socketpair, or under `qemu-<arch> -g` on a
private Unix socket when the program is for another machine (with
`-L /usr/<triple>` when a cross sysroot exists). gdbserver rather than
ptrace directly: it already handles threads, signals, exit-kill, watchpoint
registers and software single-step on every Linux architecture, and the
protocol client is needed anyway for the other stubs, so one code path is
tested for all. No port is opened. The program's stdout and stderr both
arrive on gdbserver's stderr, which is filtered of gdbserver's own lines.
`launch_qemu_system()` boots firmware under `qemu-system-*` halted, with
its gdbstub on a private socket. Through the API the daemon launches a copy
of the program's bytes in a private directory.

### Addresses

runtime address = program address + slide.

| Target | Slide |
| --- | --- |
| Emulator, raw images, fixed-address executables | 0 |
| A Linux executable | `AT_ENTRY` minus the image's entry point |
| A shared library | its `l_addr` from the library list, once loaded |
| Given | `--slide`, `CreateDebugSessionRequest.slide` |

revkit loads PIEs at Ghidra's base (0x100000 for 64-bit), so a breakpoint
set at the listing's `main` lands on the kernel's 0x5555...; locations in
responses carry both addresses and the module, so the listing marks the pc
at its program address. Breakpoints in program addresses wait until the
mapping is known.

### Libraries

`api_minor` 70, feature `program-libraries` ([api.md](api.md#libraries)).
A runtime module (a shared library in the process) that is another program
of the project is mapped to it: the library of that name the session's
program links (`ListProgramLibraries`, `LinkProgramLibrary`), else a program
of the module's name or soname. Its slide is worked out as the program's:
an ELF shared object moves by its link map's `l_addr` (revkit loads shared
objects at Ghidra's base, 0x100000), a PE by where its image starts; the
mapping follows the module list at each stop, so a library loaded later is
mapped once it is listed.

- **Locations** outside the program but in such a module carry
  `library_program_id`, `library_address` (in the library's image) and
  `library_function` ("strlen+0x10", from the library's analysis and names).
- **The stack**: a frame in such a library is named from its functions
  (`function`, `function_entry` in the library's image, `function_offset`;
  `pc.library_program_id` says whose); a return address looks up the call
  before it, as in the program.
- **Runtime disassembly** names its instructions `libc.so.6!strlen+0x10`.
- **Modules**: `DebugModule.program_id` and `library_slide` (runtime =
  library address + slide).
- **The UI**: the status reads `stopped at libmylib.so!lib_add (0x7f…)` with
  **Open libmylib.so at lib_add**, which opens the library program in a new
  tab at the function (its listing and decompiler); a library frame picked in
  the Stack offers it too, and its Disassembly is named. That tab follows
  the session's pc while it is in the library, as the program's own tab
  does: at each stop there its listing and decompiler go to the pc and mark
  it, and the mark goes when execution leaves the library or the session
  closes (the tabs talk over a `BroadcastChannel`, so in the same browser
  only).
- **Unwinding**: a frame whose pc is in such a library is unwound with the
  library's own call-frame information (`.eh_frame` and `.debug_frame`,
  read once per session from the library program), and a pc at one of its
  functions' first instruction counts as an entry, as in the program; so a
  stack through a library function that keeps no frame pointer reaches the
  program's frames by `cfi` rather than a stack scan. Live stops only: at a
  recorded snapshot the module list isn't known.

Breakpoints are set at runtime addresses in a library.

### Step over and out on live targets

Step over decodes the instruction at pc with the program's SLEIGH language;
a call gets a temporary breakpoint at its fall-through, accepted only with
the stack pointer back (recursion runs on). Step out breaks on the current
function's returns (and indirect jumps: ARMv4T returns with `bx r1`), from
the analysis's function bounds; after one, a single step must leave the
frame. Without bounds (code outside the program) it single-steps over calls
until a return leaves the frame. A run still going at the deadline stays
pending: `Wait` finishes it.

### Recording and time travel

Every stop is a snapshot: pc, thread, stop, all display registers, and for
live targets the code at pc, the stack (256 bytes) and any memory the
debugger read. The emulator also records each instruction between stops
(registers it changed, memory it read and wrote with the replaced bytes).
Registers are stored as changes with a full set every 256 snapshots.

Memory at snapshot N is the latest record at or before N. For the emulator,
which records every write, that is exact, and so are bytes first written
later (their previous bytes) and bytes never written since (their value
now). For live targets it is only what was seen; older values are marked
stale and unseen bytes unknown. The timeline is bounded (10,000 snapshots,
64 MiB by default) and drops its oldest snapshots. Traces save in a compact
binary form (`.rktrace`, with the project's directory under
`traces/<program>/` when it has one, else in memory) or as JSON.

**Firmware.** On a machine, a snapshot that entered an exception or
returned from one carries an `event` (`irq`, `fiq`, `swi`, `svc`,
`systick`, …, `return`) and its number, so the timeline shows where
interrupts landed, and `events_only` lists just those. Saved traces keep
them (format 2; format 1 traces still load, without events). Exception
breakpoints (`irq`, `irq:4`, `any`, …) stop at a handler's first
instruction.

What time travel shows of a machine is the registers the language names
and memory. **Banked registers are not replayed**: at a past snapshot the
register panel has the `sp`, `lr` and `spsr` of the mode the CPU was in
then, with `cpsr`, but the other modes' banked copies, the Cortex-M and
CP0 system registers and every peripheral's state exist only as they are
now (`GetDebugMachine` takes no snapshot). To see the stack a handler was
entered on, go to the exception's own snapshot.

### Call stack

`Session::backtrace` unwinds a stop, or a recorded snapshot, into frames,
innermost first. Each caller frame is found by the first of these that
works, and says which (`how`):

| `how` | |
| --- | --- |
| `registers` | frame 0: the stop's own pc and registers |
| `cfi` | the program's call-frame information (`.eh_frame` and `.debug_frame`, read once per session) covers the pc: the CFA and the saved registers by its rules (CIE and FDE programs, `remember`/`restore_state`, `z`/`R`/`P`/`L`/`S` augmentations); a return address marked undefined ends the stack (`_start`) |
| `entry` | the pc is a function's first instruction (the analysis knows the function): the return address is at the stack pointer, or in the link register |
| `frame pointer` | the frame-record chain: `[fp]` the caller's fp, `[fp+8]` the return address on x86-64 and AArch64; RISC-V's record below fp |
| `link register` | frame 0 of a leaf on AArch64, ARM and RISC-V, whose return address is still in `lr`/`x30`/`ra` |
| `stack scan` | a guess: the first word above the stack pointer (512 words at most) that is a code address just after a call instruction (decoded by the lifter) |

A frame must move up the stack (its stack pointer above the one before),
so a corrupt chain stops rather than loops; 64 frames by default, 256 at
most. Callers' pcs are return addresses; their function names come from
`pc - 1`, so a call at a function's end is named for that function. Frames
in a library that is a project program unwind by that library's CFI
([Libraries](#libraries)); in other code outside the program (a library
not in the project, JIT code), by frame pointer or scan. Architectures: x86-64, x86, AArch64, ARM,
RISC-V; others say `unsupported`. At a snapshot of a live target the stack
is what was recorded (256 bytes at sp, and memory read then), so deep
stacks unwind fewer frames back in time; the emulator's are exact.

Each frame carries the registers the unwinding restored (pc, sp, fp, and
callee-saved ones the CFI saved): clicking a frame in the UI shows them.

### Expressions

`EvaluateDebug` evaluates C expressions at a stop or a recorded snapshot,
in a call-stack frame. The value hovers and watches are built on it, and
so are breakpoint conditions.

- **Names.** A bare name is looked up in this order: the frame's function
  variables (as the decompiler names them, `param_1` or a name you gave),
  then a register (any case: `RAX`, `rax`, `x0`, and sub-registers like
  `EAX` and `w0` taken from the register that holds them), then a program
  symbol. `$name` means only a register.
- **Symbols.** A symbol whose data has a type (a defined global) is that
  typed variable, so `ctx.len` and `&ctx` work. A function, or a label with
  no type, stands for its address, as in Go To: `main + 0x10`,
  `*(int *)counter`.
- **Operators.** All of C's: arithmetic, comparisons, `&&`, `||`, `?:`,
  shifts and bitwise operators, unary `*` and `&`, `[]`, `.`, `->`,
  `sizeof`, and casts to the program's types (`(struct ctx *)$RDI`,
  `(uint8_t)x`) or the built-in ones (C's own, the `<stdint.h>` names,
  Ghidra's `undefined4`, `dword`). Pointer arithmetic scales by the size
  of the target.
- **Numbers** follow C: decimal, or hex with `0x`. Go To's bare-hex
  addresses are not accepted here, so `n == 10` means ten.
- **Values** are formatted by type: integers in decimal (with a `hex`
  field), `char` as `65 'A'`, pointers as
  `0x5555… <main+0x10>`, with the string for `char *`, structs as
  `{x = 1, y = 2}` (fields are also returned as `children`), arrays as
  `{1, 2, …}` or a string, enums by name, floats and doubles. Registers and
  untyped memory show in hex.
- **What can't be read.** Memory a live target's snapshot never saw, or a
  register the unwinder didn't recover in a caller's frame, gives an
  `error` instead of a value. Only registers the CFI saved, plus pc, sp and
  fp, are known above frame 0.

**Decompiler variables** are read through their storage (`DebugVariable`):

| Storage | How it is read |
| --- | --- |
| A register | In the frame |
| A stack slot | Its offset is counted from the stack pointer at the entry of the frame's function. That pointer is the frame's CFA, minus the return address on x86 |
| A global | At its runtime address |
| A decompiler temporary (`unique`) | Has no location at runtime, so there is no value |

A split variable's pieces are joined. Unless a frame is given, the
innermost frame in the variable's function is used.

**Watches** are expressions evaluated at every stop and at every snapshot
you scrub to. Each item can carry a `frame_function` (`api_minor` 61,
feature `debugger-watches`): the watch is then evaluated in the innermost
frame of that function, whatever frame is selected, so a watch on a
function's local keeps working while you step into its callees. A watch's
`changed` mark compares with the stop before (`compare_snapshot`).

**Listing operands** (`DebugOperand`) run the instruction's p-code with
the frame's registers (a pc-relative or absolute address works the same
way). The operand's memory access is the one computed from its own
registers or address. Its address and bytes come back, typed as a
decompiler variable when one lives at that stack slot or global, and as
`undefinedN` otherwise. The registers are the ones at the stop, as in
Ghidra: an operand of an instruction that runs after a `sub rsp` gets
the address it would have now.

### Runtime disassembly

`DisassembleDebugMemory` (`api_minor` 62, feature `debugger-disassembly`)
decodes target memory with the program's language. That memory can be
inside the program or not: libraries, code a packer unpacked, JIT output.
It starts at an address (the pc by default) and can include `before`
instructions of context.

- **Finding where to start.** On fixed-width instruction sets it steps
  back. On variable-length ones (x86) it tries earlier starts and keeps
  the nearest one whose decoding lands exactly on the address, looking at
  most 16 instructions back.
- **What each instruction carries:** its runtime address, its program
  address when it is in the program, and the module; its bytes, mnemonic
  and operands; a symbol (`main+0x10` in the program, `libc.so.6+0x2a1ca`
  in a module); a direct call's or branch's target with its symbol; and
  marks for the pc and for breakpoints.
- **Bytes that don't decode** come back as one unit with an `error`.
  Memory that can't be read (or wasn't recorded at a snapshot) ends the
  list, and `unreadable` says when nothing was read at all.

The listing follows the pc whenever it is in the program. When the pc
leaves it, the Debugger view's **Disassembly** box takes over (Follow pc).
That box also shows a frame outside the program when you click the frame
in the Stack, and any address or expression typed into it, as does
**Debugger ▸ Disassemble runtime memory…**.

### Crash dumps

`api_minor` 102, feature `crash-dumps`; [crash-dumps.md](crash-dumps.md). A
core file or minidump opens as a session on a `CrashTarget`: one stop (a
`SIGNAL` whose detail is "SIGSEGV (SEGV_MAPERR) at 0x0" or the exception),
the dump's threads to select, its modules mapped to project programs as a
live process's are ([Libraries](#libraries)), the call stack unwound with
their CFI (and, for an admin's session, with the CFI and symbols of mapped
files under `--browse-root` that aren't in the project), and the faulting
instruction decoded from the program's bytes when the dump left the code
out. `GetDebugCrash` sums it up. Nothing runs: Continue and the steps are
refused, and so are writes.

### Rewind

An emulator session can go back (`RewindDebugSession`, `api_minor` 65,
feature `debugger-rewind`). It returns to any recorded snapshot, one
instruction back included, and continues from there with a run or a step,
or with registers and memory changed first ("what if").

**How.** The emulator checkpoints its whole state at every stop and edit
(`Emulator::checkpoint`, [emulator.md](emulator.md#checkpoints)): the
registers, copy-on-write memory pages, the mapped regions and the process
state. Going back to a snapshot restores the nearest checkpoint at or
before it, then runs again the instructions in between. The emulator is
deterministic, so that state is the recorded one. The timeline is
truncated after the snapshot, and the next one takes the index after it.
The output is cut back to what had been printed by then.

**Branches.** The timeline is linear. Going back drops the later
snapshots, unless `save_branch_as` first saves the whole timeline as a
trace: that is the branch that was, viewable as the target
`trace:<name>`. The UI asks which you want when you resume from a
scrubbed snapshot.

`DebugState.rewindable` says whether a session can go back. A live
process or board can't: its past is a recording to look at (no reverse
execution). A saved trace can't either, and neither can an emulator on a
machine, whose peripherals aren't checkpointed. At most 1,024 checkpoints
are kept, thinned from the oldest, and those before the timeline's first
snapshot are dropped with it.

### Emulating from a stop

An emulator can start from another session's state
(`DebugEmulatorTarget.from_session`, `api_minor` 67, feature
`debugger-emulate-from`). Stop a live process (or pick a recorded
snapshot, `from_snapshot`), then explore "what if" in the emulator without
touching the process.

- **Registers** are copied from the source's stop or snapshot. Any
  `registers` in the request are written over them.
- **Memory** comes from the source's memory map, one region per mapping,
  with its permissions. A page is read from the source the first time the
  emulator touches it: from the live process while it is stopped, or from
  the recording at the snapshot. Writes then stay in the emulator
  (copy-on-write). A recording (a snapshot, a saved trace) has no memory
  map of its own, so the whole space is one region. Bytes the recording
  never saw (code is never written, so an emulator's recording doesn't
  hold it) are read from the program's image, at the program's addresses.
- **No imports are bound** (the process bound its own), so calls into the
  C library run the library's own code from the process's memory. The
  address mapping is the source's, so breakpoints at program addresses
  land where they do in the process.
- **The source isn't changed**, and it stays usable. A page it changes
  after the emulator has read that page isn't seen again. Close the source
  and the emulator can't read more of it.

In the UI, **Emulate** in the Debugger view's header starts such an
emulator at the stop or at the snapshot shown. Its title says where it
came from. Closing it returns to the source session, as that session was.

### Hooks

An emulator session can hand parts of a run to the client
(`SetDebugHooks`, `AnswerDebugHook`, `api_minor` 68, feature
`debugger-hooks`): a function to replace, a system call to answer, a
device register to model, a user op the spec leaves open. A run stops at a
hooked point with kind `HOOK` and a `DebugHookEvent`. The client answers,
then resumes:

| Hook | Stops | The answer |
| --- | --- | --- |
| `FUNCTION` (an entry, or an import's or symbol's name) | at the entry, with the integer arguments by the calling convention | the value it returns: it returns now, without running. No value: it runs |
| `SYSCALL` (a number, or -1 for all) | before the instruction, with the call's number and arguments | its result. No value: the emulator's own handler |
| `MMIO` (a range, read and/or write; its region becomes MMIO) | before the accessing instruction, with the address, size and (a write's) value | a read's value. No value, or a write: as memory |
| `USEROP` (a CALLOTHER by name) | before the instruction, with its inputs | its output |

The instruction a hook stopped is undone, and runs again when the run
resumes, this time with the answer. A run resumed without an answer goes
on as if the hook weren't there. A function hook's return value is
recorded as an edit on the timeline, so rewinding and time travel see it.
Live sessions refuse hooks: they run their own code.

**From Python** the hooks' code runs in the client, a script host's
script included, under the session owner's rights (editor for the
emulator):

```python
with prog.debug("emulator") as dbg:
    dbg.hook_function("rand", hooklib.sequence([4, 2, 7]))
    dbg.hook_function("check_license", lambda h: 1)            # always licensed
    dbg.hook_syscall(39, lambda h: 4242)                       # getpid
    dbg.hook_mmio(0x40000000, 0x40000004, read=lambda h: 0x1)  # STATUS: ready
    dbg.hook_userop("rdtsc", lambda h: 0)
    dbg.run()                                                  # answers hooks until another stop
```

A handler returns an int (the answer) or None (go on as if not hooked).
`HookEvent` has `args`, `number`, `address`, `size`, `write` and `value`,
and `read`, `read_string`, `write_memory` and `register` over the session.
`run()` answers each hook stop its handlers cover and resumes.
`revkit.hooklib` has ready handlers: `returns`, `sequence`, `record`,
`skip`, `printf` (integer, character, string and pointer conversions),
`strlen` and `memset`. The emulator's own C library stubs
([emulator.md](emulator.md#hooks)) still cover what isn't hooked.

**MCP**: `emu_call` runs one function with integer arguments to its
return. Stubbed functions (`returns`, by name or address) answer with
constants, and their calls are reported. It is the quick way for an agent
to learn what a function computes.

### Breakpoints

A software or hardware breakpoint can have a **condition** and an
**ignore count** (`api_minor` 64, feature `debugger-conditions`), and can
be **disabled**. A disabled breakpoint is kept but taken out of the target.

- **Conditions.** A condition is an expression as watches take it
  ([Expressions](#expressions)), evaluated in frame 0 when the target
  reaches the breakpoint: `$RDI == 3`, `n > 10 && *(int *)p == 0`,
  `ctx->len == 0`.
- **When a run stops.** A run (Continue, and run until) stops only after
  the first `ignore_count` hits, and only when the condition holds.
  Passed-over hits still count in `hits`, but they are not recorded on the
  timeline, so a breakpoint in a hot loop doesn't flood the recording.
- **Errors.** A condition that can't be evaluated (an unknown name,
  unreadable memory) stops there with the error in `condition_error`. A
  condition that doesn't parse is refused when it is set.
- **Where it is evaluated.** In the daemon, against the program's types
  and the decompiler's variables, for the emulator and live targets alike.
  `rk-dbg` evaluates with the built-in types.
- **Steps.** Step into, over and out stop at any breakpoint they meet, as
  before. Conditions apply to runs only.
- **Runs that go on in the background.** A live run that continues after
  its time limit (`WaitDebugSession`) passes over breakpoints the same way.

`SetDebugBreakpointsRequest.update` (`DebugBreakpointUpdate`) changes a
breakpoint's condition, ignore count or enabled state. `DebugBreakpoint`
reports them, with the hits.

### Copying runtime memory

`CopyDebugMemory` (`api_minor` 63, feature `debugger-copy`) is how
unpacked or decrypted code, a library, or a heap structure gets into the
analysis. It copies a range of target memory, or with `region` the whole
region of the target's memory map that holds an address, in one of
three ways:

| Mode | What it makes |
| --- | --- |
| `BLOCK` | A new memory block of the program at the bytes' runtime address (`AddMemoryRegion` with the bytes as its contents). Named after the region and the address (`libc.so.6_7ffff7c28000`, `_stack__7ffffffde000`) unless one is given, with the region's permissions. A range inside the program's own blocks is refused, with a pointer to patches. |
| `PATCH` | Patches over the program's own bytes, at its static addresses: only the bytes that differ from the program now (patches included), in runs. Code a packer unpacked in place, a decrypted string table. |
| `NEW_PROGRAM` | A raw program in the project, in the program's language and compiler spec, based at the runtime address (optionally analyzed). Needs admin, as any import does. |

Every byte must be readable (now, or recorded at the `snapshot` asked
for). Otherwise the call fails and says which bytes were missing. A copy
is one revision: retracting its `seqs` undoes it, and the UI records it
as one undo step. At most 64 MiB is copied in one call.

## API

`DebugService` (`api_minor` 14; `docs/api.md`): create a session on the
emulator (CreateEmulatorSession's fields), a remote stub, a launched or
attached process, or a saved trace; resume (run, into, over, out, until);
wait and interrupt; state, registers and memory now or at a snapshot
(`unavailable` and `stale` byte ranges); breakpoints and watchpoints by
`DebugAddress` (`program: true` for listing addresses); threads; modules,
memory map and mapping; the timeline; save, list, delete traces.
`GetDebugBacktrace` (`api_minor` 59, feature `debugger-stack`): the call
stack now or at a `snapshot`, each `DebugFrame` with `level`, `pc` (a
`DebugLocation`), `sp`, `cfa`, `how`, `function`, `function_entry`,
`function_offset` and `registers`; `unsupported` names an architecture
without an unwinder. A running live target has to be stopped first.
`EvaluateDebug` (`api_minor` 60, feature `debugger-values`): `items`, each
an `expression`, a decompiler `variable` or a listing `operand`. The
request can also give a `snapshot`, a `frame` and a `compare_snapshot`
(the earlier stop to compare with, which sets `changed`). Each
`DebugValue` has `text`, `type`, `hex`, `address` or `register_name`,
`program_address`, `location`, `bytes`, `children` and `name`, or an
`error`. The response also says which frame and function were used.

Firmware (`api_minor` 20, feature `firmware-emulation`;
[firmware-emulation.md](firmware-emulation.md#api-python-mcp-and-ui)): the
emulator target takes a `machine` description or a saved `machine_name`
and the response describes the machine; `WriteDebugInput` sends bytes to
a UART; `GetDebugMachine` returns the machine's state now and the
exceptions taken; `SetDebugBreakpoints` takes `exception_breaks`; states
carry `machine`, `tick` and `waiting`; `GetDebugTimeline` snapshots carry
`event` and `event_number`, and `events_only` filters to them.

Live targets are off unless `rk-daemon --debug-live` (feature
`debugger-live`). With authentication (docs/security.md), sessions belong
to the identity that made them, live targets need admin, and the emulator
and traces need editor.

Bounds: 8 sessions per client, 32 in all, closed after 30 idle minutes; 5 s
per live call (60 s at most), the emulator's limits for emulator sessions;
64 traces per program, 512 MiB each.

## Command line, Python, UI

```sh
rk-dbg --entry fib --mode call --arg 10 -c 'break fib' -c c -c regs prog     # emulator
rk-dbg --launch -c 'break main' -c c -c finish -c 'x message 16' prog -- arg  # gdbserver
rk-dbg --remote 127.0.0.1:3333 --raw --lang ARM:LE:32:Cortex fw.bin           # OpenOCD
rk-dbg --raw --lang ARM:LE:32:v4t --qemu-system qemu-system-arm -M none -cpu arm926 \
  -m 3584M -device loader,file=fw.bin,addr=0,force-raw=on -- -x cmds fw.bin
```

Commands: `break`, `hbreak`, `watch`, `rwatch`, `awatch`, `delete`,
`continue`, `step`, `next`, `finish`, `until`, `wait`, `interrupt`, `regs`,
`back` (one instruction back) and `rewind <snapshot>` (the emulator),
`break <loc> if <expr>`, `condition <id> [expr]`, `ignore <id> <n>`,
`disable`/`enable <id>` (conditional breakpoints; `info breakpoints` shows them),
`bt [N]` (the call stack: `#1  0x5555555552c6 (main+0x2c) [program 0x1012c6]  sp … (cfi)`),
`disas [loc] [n]` (instructions in target memory, the pc's by default),
`print`/`p <expr>` and `display <expr>` (printed at every stop; `undisplay [n]`): expressions as above
over registers, the image's symbols (their addresses) and memory, with C's built-in types,
`set`, `x`, `write`, `threads`, `thread`, `modules`, `maps`, `mapping`,
`timeline`, `snap N`, `xs N addr` (memory at a snapshot), `save`, `json`,
`monitor`, `kill`, `detach`.

```python
with prog.debug("launch", breakpoints=[main]) as dbg:
    dbg.run(); dbg.step_over(); dbg.step_out()
    print(dbg.registers()["RAX"], dbg.read(message, 16))
    print(dbg.registers(snapshot=dbg.timeline().first))
    for f in dbg.backtrace():                             # the call stack
        print(f.level, f.function, hex(f.function_offset), f.how)
    print(dbg.value("*(int *)($RBP - 0x14)"), dbg.value("param_1", frame=1))

with fw.debug(machine_name="board") as dbg:              # firmware on a saved machine
    dbg.break_on("irq"); dbg.run(); dbg.input(b"go\n")
    print(dbg.machine().state.mode, [s.event for s in dbg.timeline(events_only=True).snapshots])
```

The UI's Debugger view replaces the Emulator view when the daemon has
`debugger` ([ui.md](ui.md)). With `firmware-emulation` its target picker
has **Emulator (machine…)**: a machine saved with the program, one
derived from it (**Derive**), or a description edited in place and saved.
A session on a machine marks the exceptions the CPU took under the
timeline's scrubber (click one to look at that snapshot) and counts them,
takes a line of input for the UART, and can break on exceptions.

With `debugger-stack` the view has a **Stack** box: the frames of the stop
(or of the snapshot scrubbed to), as `#1 main+0x2c  0x1012c6` with how each
was found (a scanned frame is in italics, a guess). Clicking a frame moves
the listing and decompiler to its pc and shows that frame's registers
(outlined; #0 brings back the stop's own, which are the editable ones).
MCP: `debug_backtrace`.

With `debugger-values`, while a session is stopped (or scrubbed to a
snapshot), the hover cards also show values. A decompiler variable's card
has **value of x**: its typed value in the innermost frame of that
function, where it is, and a struct's fields. In the listing, a register
operand's card has its value in the selected frame, and a memory
operand's card has the address it makes and what is there. MCP:
`debug_evaluate`.

With `debugger-watches` the view has a **Watches** box. You can type an
expression into it, or right-click a variable or a token in the
decompiler or listing and choose **Debugger ▸ Add watch…**: a decompiler
variable is watched in its function's frame, and a listing register is
watched as `$REG`. Each row shows the typed value and the type. A value
that changed since the previous stop is marked, and a struct or array
expands into its fields with a click. Double-click a row to edit it, ×
removes it. Watches are kept per program in this browser.

With `debugger-disassembly` the view has a **Disassembly** box ([Runtime
disassembly](#runtime-disassembly)). It shows the instructions around the
pc at each stop when Follow pc is on, and always when the pc is outside
the program. Each row has a mark for the pc (▶) or a breakpoint (●), the
runtime address, the symbol, the bytes and the instruction. Clicking a row
in the program shows it in the listing, clicking a call's or branch's
target disassembles there, and **More** continues. Type an address or
expression into the box, or use **Debugger ▸ Disassemble runtime
memory…**. MCP: `debug_disassemble`.

With `debugger-copy`, **Debugger ▸ Copy runtime memory into the
program…** (from the listing's menu or the command palette) asks for an
address or expression and a length (empty: the whole mapped region that
holds it). It then asks how to copy it ([Copying runtime
memory](#copying-runtime-memory)): as a new memory block, as patches, or
as a new program. A block or patches are one undo step. SDK:
`DebugSession.copy_memory()`. MCP: `debug_copy_memory`.

With `debugger-rewind` an emulator session has **Back** (Shift+F7, one
instruction back), and a scrubbed snapshot has **Resume from here**. The
latter asks whether to drop the later snapshots or keep them as a trace,
then continues from the snapshot ([Rewind](#rewind)). SDK: `rewind()` and
`step_back()`. MCP: `debug_rewind`.

With `debugger-conditions` the view has a **Breakpoints** box: every
breakpoint with an enabled checkbox, its address, its condition and
ignore count ("if $RDI == 3 · skip 2", marked ⚠ when the condition
failed), its hits and ×. Clicking a row shows it in the listing.
Double-clicking a row, or **Debugger ▸ Breakpoint condition…** at an
address, sets the condition and ignore count (adding the breakpoint).
Conditions set before a session starts are given to it. SDK:
`breakpoint(addr, condition=, ignore_count=)` and `update_breakpoint()`.
MCP: `debug_breakpoints` takes `condition` and `ignore_count`. `rk-dbg`
has no machine option yet: `rk-emu --machine` is the command line.

## Verification

| Test | What |
| --- | --- |
| `Rsp.*`, `GdbRemote.*` | Framing, encodings, retransmission, XML; a scripted x86-64 stub (description with includes, `g`/`p`, holes in memory, binary writes, a breakpoint hit, output) |
| `Timeline.*`, `EmulatorSession.*` | Keyframes and bounds, known/stale memory, save and load; every emulator snapshot checked against an independent replay (pc, registers, memory) |
| `LiveX86.*` | A PIE under gdbserver: breakpoint at program addresses with the slide, step over, step out (with recursion), registers, memory then and now, a watchpoint, threads, modules and maps, register and flag writes, interrupt and kill, attach and detach; `LiveX86.Backtrace`: leaf, middle, main by CFI, and without CFI by entry and frame pointer; five frames of recursion; a frame limit; a snapshot's stack |
| `Linkage/LiveAarch64.*` | Static and static-pie AArch64 under qemu-aarch64 (the stack at a function's entry: by CFI, a return address after a `bl`) |
| `Firmware.DebugUnderQemuSystem` | The synthetic ARM firmware (`src/analysis/tests/fixtures/armfw`) under `qemu-system-arm -M none -cpu arm926`: from reset to main, interrupting its spin on the device's ready bit, writing the bit, a watchpoint, Thumb code, step out back to ARM, and the same register value as the emulator |
| `DebuggerApi.*`, `AuthPolicyUnit.LiveDebugTargetsNeedAdmin` | The service: time travel, traces saved, persisted and replayed, ownership, launch and remote targets, the call stack (fib's recursion in the emulator now and at a snapshot, fib from main under gdbserver); the access policy |
| `FirmwareApi.DebuggerTimelineShowsInterrupts` | A timer program on a machine: IRQ and FIQ events on the timeline, an exception breakpoint, the events saved in a trace and replayed |
| `Expr.*` | Expressions over a fake target: precedence, C's conversions, casts to built-in and program types, fields and bitfields, pointers and arrays, typed and untyped symbols, unreadable memory, formatting |
| `Emu.CheckpointsRewind`, `EmulatorSession.Rewind`, `DebuggerApi.Rewind` | A checkpoint restores registers, memory, steps and the trace, and the same steps follow; another emulator's checkpoint is refused. In a session: back to an instruction mid-run (registers and memory as recorded, later snapshots gone, the same end), back with a register changed (a different end), step back. The service: back to an earlier stop with the branch saved as a trace, on to the same next stop, step back, a trace session refused |
| `DebuggerApi.EmulateFromATraceSnapshot` | An emulator from a saved trace's snapshot: the recorded registers, code from the image, on to fib's next call |
| `DebuggerApi.EmulateFromALiveStop` | An emulator from a process stopped in fib(10): the process's registers and pc, fib(10) run to its return (55) on the process's stack and code read lazily, the process unchanged and running on |
| `DebuggerApi.Hooks` | fib answered by name (the program exits as fib(10) = 89 says), unanswered (it runs), a `syscall` instruction's getpid, RDTSC's user op, a global's read answered and write seen as MMIO; a live session refuses hooks |
| `DebuggerApi.ConditionalBreakpoints` | In the emulator: a condition over a register (hits counted), an ignore count, a condition naming nothing stopping with its error, a disabled breakpoint, a condition that doesn't parse refused; under gdbserver, a condition with an ignore count and one recorded stop |
| `DebuggerApi.CopyMemory` | Under gdbserver: unchanged code makes no patch, two bytes written in the process make one revision of patches, the stack's region becomes a block at its runtime address, a block inside the program is refused, a C library page becomes a new program based there |
| `DebuggerApi.Disassembly` | Under gdbserver: the pc with context before it (contiguous, marked, named), main's call to fib by its target, a C library frame's code, unreadable memory |
| `Libraries.TheDebuggerNamesALibraryFrameFromTheLibraryProgram` | Under gdbserver, a program built against a shared library built in the test, both in the project: the module mapped to the library program with its slide, a breakpoint in the library function at its runtime address, the stop named from the library (`library_function`), the stack's library frame and main, a stack out of a library function without a frame pointer unwound by the library's CFI back to main, the disassembly's `libmylib.so!lib_add` |
| `DebuggerApi.Values` | Registers and sub-registers, a parameter through its storage now and at a snapshot, changed marks, a watch in a function's frame (`frame_function`), a `push`'s memory, errors; the same under gdbserver |
| `python_sdk` (`test_debugger.py`, `test_firmware.py`, `test_hooklib.py`), `rk_dbg_smoke`, `ui_e2e` | The SDK (with `backtrace`, `evaluate` and `value`, and MCP `debug_backtrace` and `debug_evaluate`), the CLI (`bt`), and the UI launching under gdbserver, breaking, its Stack (clicking the caller's frame), value hovers (a parameter in the decompiler, a memory operand in the listing), watches (typed and from the decompiler's menu; the changed mark after a step), runtime disassembly (a C library frame from the Stack, the pc from an expression), copying the stack into a block from the Debugger menu and undoing it, a conditional breakpoint set from the palette and passed over (one hit in the table), stepping and scrubbing; an emulator session stepping back (Shift+F7 and the button) and resuming from snapshot 0 with the branch kept as a trace; Emulate from the gdbserver stop, a step there, and back to the process unchanged; `rk-dbg` `print`, `display`, `disas` and `break … if`; SDK `disassemble` and `copy_memory`, MCP `debug_disassemble` and `debug_copy_memory`; the UI on a machine (ten IRQs and two FIQs on the timeline, a derived machine) |

Tests skip cleanly without gdbserver, qemu-aarch64, the AArch64 cross
compiler, or qemu-system-arm.

## Host requirements

- `gdbserver` to launch or attach locally; `qemu-user` for other machines'
  programs; `qemu-system-arm` (and others) for firmware.
- `kernel.yama.ptrace_scope` 1 (Ubuntu's default) allows launching, since
  the program is gdbserver's child. Attaching to an existing process also
  needs scope 0, or `CAP_SYS_PTRACE` for gdbserver, or a process that
  allowed it (`PR_SET_PTRACER`); the error says so.

## Limits

- GDB remote only; DAP is not implemented.
- All-stop mode only (no non-stop); a step holds the other threads.
- Shared-library programs: breakpoints resolve at the first stop after the
  library loads; there is no stop-on-load.
- Live time travel shows only what was recorded; the emulator's is exact.
- On a machine, time travel covers the named registers and memory only:
  banked registers, system registers and peripheral state are not
  recorded or replayed (above).
- Step out without function bounds single-steps and can be slow; a frame
  left by longjmp or a tail call ends at the next stop.
- QEMU reports watchpoints before the access, gdbserver on x86 after.
- Unwinding reads the program's CFI and that of libraries that are project
  programs (live stops and crash dumps), and a crash dump's modules from
  their files under `--browse-root`; not of other modules; PE unwind data
  (`.pdata`/`UNWIND_INFO`) is not read; CFA expressions (`DW_CFA_def_cfa_expression`, signal frames) are not
  evaluated and fall back to frame pointers or a scan.
- `qemu-system-arm` 8.2 aborts on the fixture's store to 0xffffffff
  ("Bad ram pointer"), so the test returns from that function instead.
- Launching runs the program natively on the daemon's host: only with
  `--debug-live`, and only admins when authentication is on.
