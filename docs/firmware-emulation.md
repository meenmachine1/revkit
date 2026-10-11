# Firmware emulation

The emulator ([emulator.md](emulator.md)) runs instructions. Firmware also
needs the board around them: interrupts and exceptions, timers that fire,
a UART that answers, status registers that say "ready". A **machine** is
that board: a CPU exception model, memory, peripherals, their interrupt
wiring and a clock, written down as a JSON description.

```sh
rk-emu --machine board.json firmware.bin                 # from the reset vector, to an exit, a fault or idle
rk-emu --machine board.json --events --break-on irq firmware.bin
rk-emu --raw --lang ARM:LE:32:v4t --derive-machine starter.json firmware.bin   # a first draft of board.json
```

| Where | What |
| --- | --- |
| `src/emu` (`include/revkit/emu/machine.hh`) | Machines: the description (`parse_machine`), the runtime (`machine.cc`), CPU models (`cpu_arm.cc`, `cpu_cortexm.cc`, `cpu_mips.cc`), built-in peripherals (`peripherals.cc`), starter machines (`derive.cc`) |
| `src/plugins` (`peripheral.h`) | Peripheral plugins as machine peripherals |
| `tools/rk-emu` | `--machine`, `--input`, `--break-on`, `--events`, `--derive-machine`, `--plugin-dir`, `--plugin-grant` |
| `proto/revkit/v1/emulator.proto`, `debugger.proto` | `api_minor` 20, features `firmware-emulation` and `peripheral-plugins` |
| `src/backend/machines.cc` | Machines saved with a program |
| `sdk/python` | `emulate(machine=)`, `debug(machine=)`, `save_machine`, `derive_machine`, `input`, `machine`, `break_on` |
| `ui/src/debug/panel.ts` | The Debugger's "Emulator (machine…)" target |
| `sdk/plugins/examples/tick-timer` | An example peripheral plugin |

- [CPU exception models](#cpu-exception-models)
- [Time](#time)
- [Peripherals](#peripherals)
- [Peripheral plugins](#peripheral-plugins)
- [The machine description](#the-machine-description)
- [rk-emu](#rk-emu)
- [A starter machine](#a-starter-machine)
- [API, Python, MCP and UI](#api-python-mcp-and-ui)
- [Verification](#verification)
- [Limits](#limits)

A session on a machine is still session state ([emulator.md](emulator.md)):
nothing is asserted. A machine description saved with a program is a file
beside the project, not a fact.

## CPU exception models

Ghidra's SLEIGH specs describe instructions, and leave exception entry,
mode banking and most system registers to whatever runs the p-code. The
models live in the emulator's state layer and fix those instructions up
around their p-code. The model comes from the language (`ARM:…:Cortex` is
`cortex-m`, other ARM is `arm`, MIPS is `mips`) unless `cpu.model` names
one; `none` gives a machine with memory and peripherals but no interrupts.

### ARM (A and R profile, ARMv4T onward)

- **Modes**: the canonical CPSR (mode, I, F, T, the flags) with banked SP,
  LR and SPSR for usr/sys, svc, irq, fiq, abt and und, and FIQ's own
  r8-r12.
- **Entry**: the vector table at `vector_base` (0 by default; 0xffff0000
  for high vectors). IRQ and FIQ are taken between instructions when their
  line is high and CPSR doesn't mask them; SWI enters its handler from the
  instruction; undefined instructions and prefetch and data aborts enter
  theirs when the description asks (`cpu.undefined`, `cpu.aborts`), and
  stop the run as faults otherwise. Entry banks the registers, saves CPSR
  to SPSR, sets LR to the architecture's return offset for the exception,
  masks IRQ (and FIQ on FIQ and reset) and leaves Thumb state.
- **Instructions the spec leaves out**: `MRS Rd, CPSR` returns the whole
  CPSR, `MSR CPSR_<fields>` switches mode and masks, `SUBS`/`MOVS PC, …`
  and `LDM {…, pc}^` restore CPSR from SPSR, `LDM`/`STM ^` without pc
  reach the user-mode registers, and `SUB PC, …` without S keeps CPSR.
  `WFI` (and the CP15 wait-for-interrupt write) idle the CPU.
- **CP15**: a register file that reads back what was written, with
  ARM926 values for the main ID and cache type. There is no MMU or cache.
- **Thumb-2 IT blocks** are tracked by the emulator (`ITSTATE`, the
  conditions, and 16-bit instructions that don't set flags inside a
  block): the decoder has no run-time context for them.
- **Semihosting** (`cpu.semihosting`): `SWI 0x123456`, `SVC 0xab` and
  `BKPT 0xab` with `SYS_WRITEC`, `SYS_WRITE0`, `SYS_WRITE`, `SYS_CLOCK`,
  `SYS_TIME` and the exit calls, as qemu's `-semihosting` gives bare-metal
  programs.

### Cortex-M (ARMv6-M, ARMv7-M)

- **Reset** loads SP and PC from the vector table at `vector_base` (the
  image's start by default); VTOR moves it.
- **The system control space** at 0xe000e000 is a device the CPU brings
  with it: the NVIC (enable, pending, active, priorities with
  `priority_bits` implemented bits, `nvic_irqs` external lines), SysTick,
  and the SCB (ICSR, VTOR, AIRCR, SCR, CCR, SHPR, SHCSR). A system reset
  request (`AIRCR.SYSRESETREQ`) stops the run.
- **Entry and return**: the eight-word frame on MSP or PSP, handler mode
  on MSP, `EXC_RETURN` in LR; a branch to an `EXC_RETURN` value unstacks.
  Priorities preempt; PRIMASK, FAULTMASK and BASEPRI mask. The special
  registers Ghidra's spec reaches through `CALLOTHER`s
  (`getMainStackPointer`, `enableIRQinterrupts`, `getBasePriority`, …) are
  implemented, and `MSR CONTROL` selects the stack.
- **Exceptions**: NMI, HardFault (what `aborts` and `undefined` turn
  faults into), SVC, PendSV, SysTick and external interrupts.

### MIPS32

- **CP0**: Status (IE, EXL, ERL, BEV, IM), Cause (IP, ExcCode, IV), EPC,
  EBase, and the Count/Compare timer on IP7 (Count advances every other
  tick). `MTC0` and `ERET` behave as the hardware does (the spec's `ERET`
  doesn't clear EXL).
- **Entry**: interrupts on IP2-IP7 when Status enables them, `SYSCALL`,
  `BREAK` and traps, and, when asked (`cpu.aborts`, `cpu.undefined`), bus
  errors and reserved instructions; the
  vector is `vector_base` (default 0x80000000) + 0x180, + 0x200 for
  interrupts with Cause.IV, or the boot vectors while BEV is set. `WAIT`
  idles the CPU.

### What a session sees

Each exception taken, and each return, is a recorded step with an
**event**: its kind (`irq`, `fiq`, `swi`, `undefined`, `prefetch_abort`,
`data_abort`; `nmi`, `hardfault`, `svc`, `pendsv`, `systick`, `external`;
`interrupt`, `syscall`; `return`), a number where there is one (the IRQ
line, the exception number, the MIPS cause), where execution was, the
handler, and the peripheral that raised it. The machine keeps the last
4,096.

**Exception breakpoints** stop the run when the CPU takes an exception of
a kind asked for: `irq`, `fiq`, `swi`, `svc`, `systick`, …, `irq:4` for
one line, `any`, and `return`. The stop (kind `exception`) is at the
handler's first instruction, with the registers already banked.

**Idle.** A CPU waiting in `WFI`/`WAIT`, or in a branch to itself with
interrupts enabled, doesn't burn steps: the clock skips to the next
scheduled event. With nothing scheduled the run stops (kind `idle`): the
firmware waits for input that only the session can give
(`WriteEmulatorInput`, `--input`), and continuing after giving it wakes
the CPU.

The machine's state (`GetEmulatorMachine`, `rk-emu`'s summary) has the
CPU's mode, the banked and system registers the language doesn't name
(`sp_irq`, `lr_svc`, `spsr_fiq`, `msp`, `psp`, `primask`, …), each device
with a line of state, the asserted lines, and the machine's log.

## Time

Time is a tick count. By default (`clock.mode` `instructions`) each step
advances it by `ticks_per_step` (1), and `clock.hz` says how many ticks
are an emulated second (1,000,000: an instruction takes a microsecond).
Peripherals count in their own clocks (`clock_hz`, `divider`) converted to
ticks, schedule the tick they next need, and are called exactly then. So a
run is **deterministic**: the same image, description and input give the
same trace, interrupts included, byte for byte.

`clock.mode` `wall` follows the host's clock instead (an idle CPU sleeps
until the next event). Runs then differ from each other; use it to watch
firmware that paces itself against real time, not to record.

## Peripherals

A peripheral is a block of memory-mapped registers with read and write
callbacks, the machine's clock, and interrupt lines out (and, for
controllers, in). The built-in kinds:

| Kind | |
| --- | --- |
| `sp804` | ARM SP804 dual timer: both counters, one-shot, periodic and free-running, 16 and 32 bits, prescalers, the combined interrupt and one per counter (`irq`, `irq1`, `irq2`); `clock_hz`, `clock_hz2` |
| `pl011` | ARM PL011 UART: transmits to the session's output, receives the session's input, receive and transmit interrupts |
| `pl190` (`vic`) | ARM PL190 vectored interrupt controller: 32 inputs, IRQ and FIQ outputs, vectors, soft interrupts |
| `gic` | A GIC-lite: a distributor and one CPU interface (enable, pending, priority, acknowledge, end of interrupt); `lines` (96), `first_spi` (32), `cpu_interface` (offset 0x1000) |
| `pl031` (`rtc`) | ARM PL031 real-time clock: seconds from the machine clock (`start`), the match interrupt |
| `timer` | A configurable timer (below) |
| `uart` | A configurable UART (below) |
| `intc` | A configurable interrupt controller (below) |
| `auto-ack` | Registers that answer polling loops (below) |
| `ram-device` (`registers`) | Registers that read back what was written; `values` gives initial contents |
| `plugin:NAME` | A [peripheral plugin](#peripheral-plugins) |

Every peripheral has a `name` (unique; how wiring refers to it), a `kind`,
a `base`, and a `size` when the kind has no natural one (default 0x1000).
Its registers are mapped as MMIO whether or not a memory region covers
them; two peripherals can't overlap, and one can't sit on the loaded
image. An access to MMIO no peripheral claims behaves as before machines:
a value store, recorded in the MMIO log.

**Wiring.** `"irq": "vic.4"` connects the peripheral's first output to
input 4 of the peripheral named `vic`; `"irq": {"irq0": "intc.9", "irq1":
"intc.10"}` wires outputs by name. The CPU's inputs are `cpu.irq` and
`cpu.fiq` (ARM), `nvic.N` or `cpu.N` and `cpu.nmi` (Cortex-M), and
`cpu.ip2`-`cpu.ip7` or `cpu.hw0`-`cpu.hw5` (MIPS). A controller's outputs
that aren't wired go to the CPU inputs of the same name, so a `pl190`
needs no `irq` of its own. Lines are level-sensitive, and several sources
may drive one input.

### Configurable built-ins

Most SoCs have a timer, a UART and an interrupt controller that are not
ARM's but work the same way with other offsets and bits. These three take
their layout from the description.

`timer`: `channels` (1) at a `stride` (0x20), each with `registers`
`load` (0x0), `value` (0x4), `control` (0x8), `status` (0xc) and `clear`
(0x10), any of them `null` when absent; `bits` `enable` (0), `periodic`
(1), `irq_enable` (2) and `pending` (0) by bit number;
`status_in_control` when the pending bit lives in the control register;
`clear_mode` `write` (any write to `clear`), `w1c` (write 1 to the pending
bit) or `read`; `count` `down` or `up` to `top`; `clock_hz` and `divider`;
`period` for a timer that needs no programming, `autostart`, `periodic`
(the default when there is no periodic bit), `load_mask`. Outputs: `irq`
(any channel) and `irq0`, `irq1`, … per channel.

`uart`: `data` (0x0) and `status` (0x4) offsets, the status bits
`tx_ready` (0x20), `rx_ready` (0x01) and `rx_empty` (0), `status_value`
for bits that always read set, and `irq_on_rx` (true). `"model": "pl011"`
is the PL011.

`intc`: `lines` (32) numbered from `number_base` (0), bits counted from
the `lsb` or `msb` (`bit_order`), `latched` (true), and `registers`, each
an offset or a list of offsets for controllers wider than 32 lines:
`status`, `raw`, `enable`, `mask` (the inverse), `enable_set`,
`enable_clear`, `clear`, `pending_number` (reads the lowest pending line's
number, or `none_value`; `ack_on_read` clears it) and `global_disable`
(bit `global_disable_bit`). `enabled_at_reset` for controllers that start
unmasked. `"model": "pl190"` or `"gic"` are those.

### Auto-ack registers

Boot code polls: a PLL's lock bit, a flash controller's busy bit, a FIFO's
level. An `auto-ack` peripheral answers without modelling the device:

```json
{"name": "acks", "kind": "auto-ack",
 "registers": [
   {"address": "0x40003010", "mask": "0x1", "value": "0x1", "note": "PLL locked"},
   {"address": "0x40004004", "mode": "toggle", "mask": "0x80"},
   {"address": "0x40005000", "mode": "increment", "step": "0x10"}]}
```

A read returns what was last written with the `mask` bits replaced:
`fixed` (the default) by `value`, `toggle` by `value` and its complement
in turn, `increment` by a count that grows by `step` each read. Registers
are 4 bytes unless `size` says otherwise. With a `base`, registers are
`offset`s in one block; without, each `address` is a device of its own
size, and the memory around it stays as it was.

## Peripheral plugins

A device none of the built-ins describes is a WebAssembly plugin of kind
`peripheral` ([plugins.md](plugins.md)), named in a machine as
`"kind": "plugin:NAME"`. Unlike the other plugin kinds, a peripheral is
**one live instance per session**: its globals are the device's state,
from the machine's reset to the session's end.

| Export | |
| --- | --- |
| `rk_peripheral_buffer() -> i32` | a buffer of at least 4,096 bytes the host writes input into |
| `rk_peripheral_init(ptr, len) -> i32` | once: the peripheral's own JSON object from the description |
| `rk_peripheral_read(offset: i64, size: i32) -> i64` | a register read |
| `rk_peripheral_write(offset: i64, size: i32, value: i64) -> i32` | a register write |
| `rk_peripheral_tick(now: i64) -> i32` | optional: the time asked for with `schedule` came |
| `rk_peripheral_input(ptr, len) -> i32` | optional: session input (a UART's receiver) |
| `rk_peripheral_irq_in(line: i32, level: i32) -> i32` | optional: an interrupt input changed (controllers) |
| `rk_peripheral_reset() -> i32` | optional: the machine resets |

| Import | Capability | |
| --- | --- | --- |
| `now() -> i64` | | machine ticks |
| `schedule(at: i64)` | | `rk_peripheral_tick` at tick `at`; negative cancels |
| `irq_set(line: i32, level: i32)` | `irq` (default) | drives one of the manifest's `outputs` |
| `output(ptr, len)` | `output` (default) | bytes for the session's output |
| `bus_read(addr: i64, dst, len) -> i32`, `bus_write(addr: i64, src, len) -> i32` | `bus` (needs a grant) | the emulated machine's memory (DMA), at most 1 MiB a call |

The manifest's `peripheral` object gives the interrupt `outputs` (default
`["irq"]`), the number of interrupt `inputs` (0 unless it is a
controller), and the register block's default `size`. Peripherals can't
import program facts (`memory_read`, `functions`, …), and other kinds
can't import these.

Each call into the plugin has its own fuel (50,000,000 unless the manifest
asks otherwise) and the wall-clock backstop. A call that fails (a trap,
out of fuel, a non-zero return) stops the run with stop kind `hook` and
the reason; the instance is dead for the rest of the session, and the
daemon is unaffected. Fuel makes a plugin as deterministic as a built-in.

```sh
rk-daemon --plugin-dir build/plugins [--plugin-grant my-dma=bus]
rk-emu --machine board.json --plugin-dir build/plugins firmware.bin
```

`sdk/plugins/examples/tick-timer` (100 lines of C) is a periodic timer
with an interrupt and a transmit register; `"period": 500` in its machine
entry sets its reset period. `ListPeripheralKinds` lists the built-ins and
the loaded plugins.

## The machine description

JSON, with `//` and `/* */` comments, trailing commas, and numbers as
JSON integers or strings: `"0x1000"`, `"4096"`, `"64K"`, `"8M"`,
`"1_000_000"`. Unknown fields are errors with a line and column, except
`note`, `comment` and names starting with `_`, which are yours.

```json
// A made-up ARM9 board: RAM at 0, an interrupt controller, a timer, a UART,
// and one status register the boot code polls.
{
  "machine": 1,
  "name": "example-board",
  "description": "RAM, a PL190 VIC, an SP804 timer, a PL011 console",
  "language": "ARM:LE:32:v4t",
  "cpu": {"model": "arm", "semihosting": false},
  "clock": {"mode": "instructions", "hz": 1000000},
  "memory": [
    {"name": "ram", "start": "0x0", "size": "16M", "kind": "ram"},
    {"name": "io", "start": "0x40000000", "size": "64K", "kind": "mmio"}
  ],
  "image": {"load": "0x0", "offset": "0x0"},
  "entry": "reset",
  "peripherals": [
    {"name": "vic", "kind": "pl190", "base": "0x40000000"},
    {"name": "timer", "kind": "sp804", "base": "0x40001000", "irq": "vic.4", "clock_hz": 1000000},
    {"name": "uart", "kind": "pl011", "base": "0x40002000", "irq": "vic.12"},
    {"name": "pll", "kind": "auto-ack", "base": "0x40003000", "size": "0x100",
     "registers": [{"offset": "0x10", "mask": "0x1", "value": "0x1", "note": "PLL locked"}]}
  ],
  "console": "uart",
  "break_on": ["fiq"]
}
```

| Field | |
| --- | --- |
| `machine` | The format's version: 1 |
| `name`, `description` | |
| `language` | A Ghidra language id. A raw file loads with it; a program in another language is refused |
| `cpu` | A model name, or `model` (`arm`, `cortex-m`, `mips`, `none`; default: from the language), `vector_base`, `aborts`, `undefined`, `semihosting`, and for Cortex-M `nvic_irqs` (64) and `priority_bits` (8) |
| `clock` | `mode` (`instructions` or `wall`), `hz` (1,000,000), `ticks_per_step` (1) |
| `memory` | Regions: `name`, `start`, `size` (or `end`), `kind` (`ram`, `rom`, `mmio`), `perms` (`rwx`; by default from the kind). They can't overlap |
| `image` | How a raw file loads: `load` address, `offset` into the file (a header to skip; `header` is the same), `length`, `perms`, `name` |
| `entry` | An address, or `reset` (the default): the architecture's reset vector |
| `registers` | Register values set after reset: `{"sp": "0x20008000"}` |
| `peripherals` | The list [above](#peripherals) |
| `console` | The UART that takes the session's stdin and unnamed input (default: the first) |
| `break_on` | Exception breakpoints set from the start |

The image is the program's: memory regions the image covers hold its
bytes, and the rest of each region is zero-filled RAM (or unanswered
MMIO). `machine_json` writes a description back in this form.

## rk-emu

| Option | |
| --- | --- |
| `--machine board.json` | Run on a machine. An ELF or PE loads as itself; any other file is the machine's raw image (`language`, `image`), so `--raw` and `--lang` aren't needed |
| `--entry addr` | Start there instead of the machine's entry |
| `--input text` | Bytes for the console UART, after `--stdin file`'s; `\n` escapes |
| `--break-on kinds` | Exception breakpoints: `irq,fiq,swi,svc,systick,any,irq:4,…` |
| `--events` | Print the exceptions taken |
| `--derive-machine out.json` | Write a [starter machine](#a-starter-machine) and exit |
| `--plugin-dir dir`, `--plugin-grant name=bus` | Peripheral plugins for `plugin:NAME` kinds |

The other options are the emulator's ([emulator.md](emulator.md#command-line)):
`--steps`, `--until`, `--break`, `--reg`, `--mem`, `--trace`,
`--print-steps`, `--timeout`. The summary adds the machine: the CPU's
mode, the clock, the exceptions taken, and each device's state.

```
$ rk-emu --machine versatilepb.json --events --break-on fiq arm_timer.bin
timer irq test
rk-emu: stopped (exception) at 0x1c after 324 steps: took fiq (handler 0x1c)
  r0       0x0                 r1       0x4                 r2       0x168               r3       0x101f1000
  ...
  TB       0x0                 cpsr     0x600000d1          spsr     0x60000093
  machine: arm in fiq, tick 45131, 19 exceptions taken
    vic (pl190): raw 0x20, enabled 0x30, irq 0x0
    timer01 (sp804): timer1 running 4997; timer2 stopped 4294967295
    timer23 (sp804): timer1 running 45000 (interrupt); timer2 stopped 4294967295
    rtc (pl031): 0 s
    uart0 (pl011): 0 bytes waiting
    step 32 tick 32: return at 0x90 -> 0x94 from svc to usr
    step 133 tick 133: swi 6 at 0x440 -> 0x8
    step 153 tick 10130: return at 0xec -> 0x440 from svc to usr
    step 153 tick 10130: irq at 0x440 -> 0x18 (vic)
    step 172 tick 10148: return at 0xb0 -> 0x440 from irq to usr
    ...
```

(`src/emu/tests/fixtures/fwemu` has the boards and programs:
`versatilepb.json`, `lm3s6965.json`, `mips.json`, and `custom_soc.json`, a
made-up SoC on the configurable built-ins.) Ticks jump where the program
waits: between tick 133 and 10130 the CPU idled in the SWI handler until
the timer fired.

## A starter machine

Nobody starts with a description. `rk-emu --derive-machine`,
`DeriveMachine` and the UI's **Derive** write a first one from the
program:

1. **Memory**: the program's blocks (a raw import's image and its
   `--region`s: RAM, ROM, MMIO).
2. **What the code reaches** (the API and UI, from revkit's analysis: data
   references at constant addresses outside that memory): clusters become
   MMIO regions, and on Cortex-M addresses in 0x20000000-0x3fffffff become
   RAM. `rk-emu` has no analysis and skips this step.
3. **The CPU**: the model for the language; the entry (the reset vector,
   or the vector table on Cortex-M).
4. **Trial runs** (`trial_steps`, 2,000,000 by default through the API;
   `rk-emu`'s `--steps`, 1,000,000):
   a run that faults on unmapped memory gets a 64 KiB MMIO region there
   and runs again; a run that spins reading one MMIO register (hundreds of
   reads, most of a 100,000-step window's) gets an auto-ack register for
   it. Four answers are tried (all ones, zero, a counter, toggling) and
   the one that reaches the most new instructions is kept. At most 8 loops
   and 48 runs.

The description comes with `note`s saying what was guessed and why, and
where the last trial run stopped:

```
$ rk-emu --raw --lang ARM:LE:32:v4t --region sram:20000000:10000 --derive-machine starter.json fw.bin
rk-emu: memory: the program's 2 blocks
rk-emu: entry: the reset vector at 0
rk-emu: MMIO mmio_d0000000 0xd0000000+0x10000: the trial run accessed 0xd0000010 (from 0x188)
rk-emu: auto-ack 0xd0000018: the code polls it (33329 reads in 100000 steps); toggles all its bits on each read gets it furthest (160 more instructions reached)
rk-emu: MMIO mmio_ffff0000 0xffff0000+0x10000: the trial run accessed 0xffffffff (from 0x1c0)
rk-emu: the trial run stopped: write of 4 bytes at 0xffffffff (unmapped)
rk-emu: trial run: 412 steps, stopped (unmapped) at 0x1c0: write of 4 bytes at 0xffffffff (unmapped)
```

(the synthetic firmware of `src/analysis/tests/fixtures/armfw`, whose
last act is a store through a bad pointer). It is a draft: it gets code
past its first polling loops so that there is something to look at. The
interrupt controller, timers and UART are yours to add: the MMIO log and
the regions it found say where they are.

## API, Python, MCP and UI

`api_minor` 20, feature `firmware-emulation` (and `peripheral-plugins`
when the daemon has plugins); [api.md](api.md#firmware-emulation).

| | |
| --- | --- |
| `CreateEmulatorSession`, `CreateDebugSession` (emulator target) | `machine` (a description) or `machine_name` (a saved one). The machine sets the entry unless the request does; `mode` and `arguments` don't apply; `stdin` goes to the console UART. The response describes the machine (CPU, devices, clock) |
| `WriteEmulatorInput`, `WriteDebugInput` | Bytes for a UART (the console unless named) |
| `GetEmulatorMachine`, `GetDebugMachine` | The machine's state and the exceptions taken from an index on |
| `SetEmulatorBreakpoints`, `SetDebugBreakpoints` | `exception_breaks` with `set_exception_breaks` |
| `GetEmulatorState`, `GetDebugState` | `machine`, `tick`, `waiting` |
| `GetEmulatorTrace` | Entries carry `exception`; the summary counts them |
| `GetDebugTimeline` | Snapshots carry `event` and `event_number`; `events_only` |
| `ListMachines`, `GetMachine`, `SaveMachine`, `DeleteMachine` | Descriptions kept with a program: under the project's directory (`machines/<program>/<name>.json`) when it has one, else in memory. Checked when saved; at most 64 per program, 4 MiB each |
| `DeriveMachine` | A starter, with its notes and where the trial run stopped (at most 50,000,000 trial steps, 60 s) |
| `ListPeripheralKinds` | Built-ins and peripheral plugins |

Stop kinds `EXCEPTION` and `IDLE` are new. Saved traces (`.rktrace`) are
format 2, which keeps the events; format 1 still loads. With
authentication, saving, deleting and deriving machines need the editor
role, reading them viewer; input belongs to the session's owner like its
other writes.

```python
board = open("board.json").read()
prog = rk.program(rk.import_program("default", path="fw.bin", format="raw",
                                    language_id="ARM:LE:32:v4t").program.program_id)
with prog.emulate(machine=board) as emu:
    emu.run()                      # ... "idle": waiting for the UART
    emu.input(b"help\n"); emu.run()
    print(emu.stdout, [e.kind for e in emu.machine().events])

prog.save_machine("board", board)
starter = prog.derive_machine()    # .machine, .notes
with prog.debug(machine_name="board") as dbg:
    dbg.break_on("irq:4"); dbg.run()
    print([s.event for s in dbg.timeline(events_only=True).snapshots])
```

**MCP** (`revkit.mcp_server`): `emu_start` and `debug_start` take
`machine` (a description, or a saved machine's name) and `derive_machine`
(start on a starter, returned with its notes); `emu_machine` reads the
machine and its exceptions; `emu_input` sends UART bytes and sets
exception breakpoints.

**UI.** The Debugger's target picker has **Emulator (machine…)** when the
daemon has `firmware-emulation`: pick a machine saved with the program,
**Derive** one, or write one under **Edit** and **Save as…**. A session on
a machine marks the exceptions under the timeline's scrubber (click one to
look at that snapshot) and counts them, has a line of input for the UART,
and a **Break on exceptions** box.

## Verification

| Test | What |
| --- | --- |
| `FirmwareMachine.Arm*` (`src/emu/tests/machine_test.cc`, fixtures in `fixtures/fwemu`) | Bare-metal ARMv4T programs on `versatilepb.json`: SP804 interrupts through the VIC as IRQ and FIQ (FIQ's banked r8-r12 kept), PL011 echo with receive interrupts, SWI from user mode, mode switches, an undefined instruction |
| `FirmwareMachine.Cortex*` | Cortex-M3 programs on `lm3s6965.json`: SysTick, PendSV on the process stack, UART interrupts through the NVIC, SVC frames, IT blocks |
| `FirmwareMachine.SameOutputAsQemu` | The same ELFs under `qemu-system-arm -M versatilepb` and `-M lm3s6965evb`: the same UART output (skipped without qemu) |
| `FirmwareMachine.MipsTimerAndSyscall` | MIPS32: Count/Compare interrupts on IP7, `SYSCALL`, `ERET`. Hand-checked; skipped when clang has no MIPS target |
| `FirmwareMachine.ConfigurableBuiltinsOnAMadeUpSoc` | `custom_soc.json`: the configurable timer, interrupt controller and UART |
| `FirmwareMachine.TracesAreDeterministic`, `BreaksOnIrqEntry`, `IdleWithNothingScheduledStops`, `InputArrivingLaterWakesTheCpu`, `AutoAckGetsPastAPollingLoop` | Two runs give the same trace; exception breakpoints; idle and input; auto-ack on the synthetic firmware |
| `Machine.*` | Parse errors with line and column; the raw-import options a description gives |
| `PeripheralPlugins.*` (`src/plugins/tests/peripheral_test.cc`) | State that carries between calls, imports that follow the grants, a plugin out of fuel stopping the run and not the host, `tick-timer` interrupting a program on Versatile/PB |
| `FirmwareApi.*` (`src/backend/tests/firmware_api_test.cc`), `AuthPolicyUnit.*` | The service: UART input, IRQ events, exception breakpoints, timeline events saved and replayed, saved machines, a derived machine past a polling loop; the access policy |
| `python_sdk` (`test_firmware.py`, `test_mcp_tools.py`), `ui_e2e` | The SDK, the MCP tools, and the UI running the timer fixture on a machine: ten IRQs and two FIQs on the timeline, a derived machine |

The fixtures need clang with ARM targets, `ld.lld` and `llvm-objcopy`,
and skip without them.

## Limits

- **Architectures**: ARM (A/R), Cortex-M and MIPS32 have exception models.
  For the others (AArch64, RISC-V, x86, PowerPC, …) a machine gives memory
  and peripherals only: there is no CPU input to wire an interrupt to.
- **ARM**: no MMU, TLB, caches or coprocessors beyond a CP15 register
  file; no Security Extensions or virtualization (the monitor and hyp
  modes bank registers and nothing more); no Jazelle. Big-endian ARM is
  untested.
- **Cortex-M**: no MPU, no floating-point context (frames are always
  eight words), no TrustZone; faults all become HardFault, with no
  MemManage, BusFault or UsageFault status.
- **MIPS**: MIPS32 only, no TLB (kseg0 and kseg1 are whatever the memory
  list maps there, and don't alias), no MIPS16 or microMIPS, no shadow
  register sets. Not compared with another emulator.
- **Time travel doesn't replay banked registers.** A debug session's
  timeline records the registers the language names (so the current
  mode's `sp` and `lr`, `cpsr`, `spsr`) and memory. The banked registers
  of the other modes, the Cortex-M and CP0 system state, and every
  peripheral's state are not recorded: `GetDebugMachine` answers for the
  present, whatever snapshot the registers and memory are shown at. Look
  at the exception's own snapshot for what a handler saw.
- **Time** is counted in instructions, not cycles: an instruction is one
  tick whatever it does, so timing loops calibrated against a real clock
  run at the wrong speed, and a UART has no baud rate (bytes arrive when
  written).
- **Peripherals**: the built-ins are what bare-metal bring-up needs, not
  whole devices: PL011 has no modem lines or DMA, the GIC-lite one CPU and
  no groups, and there is no GPIO, SPI, I2C, flash controller, network or
  display model. An unmodelled register reads back what was written; a
  peripheral plugin or an auto-ack register covers what must answer.
- **One CPU.** No SMP, no second core's reset or mailbox.
- **Starter machines** are drafts: memory and polling loops only, four
  kinds of answer, no interrupt wiring and no recognition of which device
  a register belongs to.
- **Peripheral plugins** load when the daemon (or `rk-emu`) starts; their
  state lives in the instance and is not saved with a trace.
- **Wall-clock mode** is not deterministic: two runs of it differ.
