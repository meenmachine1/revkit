# @category Analysis/Strings
# @description Decrypts strings by emulating each call to a decryption function and comments
# @description every call site with what the buffer holds afterwards.
# @context program
# @arg decryptor:address The decryption function (a name or an address)
# @arg pointer_arg:int=0 Which argument is the buffer (0 = first)
# @arg length_arg:int=1 Which argument is its length (-1: read up to a NUL)
# @arg max_length:int=256 Longest string to read
"""Decrypt strings by emulation (EmulatorService).

For every function calling the decryptor, an emulation session runs that
function in call mode with a breakpoint on each call; at each one the
buffer and length arguments are read from the calling convention's
registers, the call is stepped over, and the buffer is read back. Nothing
the emulator does is asserted: only the comments are edits. Register
arguments only (x86-64 System V, AArch64, ARM, MIPS, RISC-V).
"""
from collections import defaultdict

from revkit.script import *

ARG_REGISTERS = {
    "x86:LE:64": ["RDI", "RSI", "RDX", "RCX", "R8", "R9"],
    "AARCH64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    "ARM": ["r0", "r1", "r2", "r3"],
    "MIPS": ["a0", "a1", "a2", "a3"],
    "RISCV": ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
}

lang = current_program.summary().language.language_id
regs = next((r for prefix, r in ARG_REGISTERS.items() if lang.startswith(prefix)), None)
if regs is None:
    raise SystemExit(f"decrypt_strings: no register calling convention for {lang}")

target = ask_address("decryptor", "The decryption function")
calls = defaultdict(list)
for x in xrefs_to(target):
    if x.kind == 1 and x.HasField("from_function"):  # XREF_KIND_CALL
        calls[x.from_function.offset].append(x.from_address.offset)
if not calls:
    raise SystemExit(f"decrypt_strings: nothing calls 0x{target:x}")


def printable(data: bytes) -> str:
    data = data.split(b"\0")[0]
    return "".join(chr(b) if 32 <= b < 127 else f"\\x{b:02x}" for b in data)


decrypted = 0
monitor.set_max(sum(len(v) for v in calls.values()))
for caller, sites in sorted(calls.items()):
    with current_program.emulate(caller, mode="call", breakpoints=sites, max_total_steps=5_000_000) as emu:
        pending = set(sites)
        while pending:
            monitor.check_cancelled()
            stop = emu.run().stop
            pc = emu.pc
            if pc not in pending:
                break  # returned, faulted or ran out of steps
            pending.discard(pc)
            values = emu.registers(*regs)
            ptr = values[regs[args["pointer_arg"]]]
            n = values[regs[args["length_arg"]]] if args["length_arg"] >= 0 else args["max_length"]
            emu.step_over()
            text = printable(emu.read(ptr, min(max(n, 0), args["max_length"])))
            print(f"0x{pc:x}: 0x{ptr:x} = \"{text}\"")
            comment(pc, f'decrypted: "{text}"')
            decrypted += 1
            monitor.increment()
print(f"{decrypted} string(s) decrypted")
