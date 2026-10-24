#!/usr/bin/env python3
"""Writes evm.slaspec, revkit's SLEIGH spec of Ethereum Virtual Machine bytecode
(docs/evm.md). Run it after changing the tables below; the output is committed:

    python3 processors/EVM/gen_slaspec.py > processors/EVM/data/languages/evm.slaspec

The model (docs/evm.md, "The processor"):

- Code is `ram`, byte-addressed with 4-byte addresses. A contract's runtime code
  is at 0; its creation code, when the file holds it, at 0x100000 (docs/evm.md,
  "Loading"). Jump targets are offsets in the code they are in: a jump adds
  the segment of its own address (inst_start & 0xfff00000).
- The operand stack is `opstack`, below SP, in 32-byte slots, as Ghidra's JVM
  models its operand stack; the decompiler turns pushes and pops back into
  expressions. Memory is `mem` (MLOAD, MSTORE), byte-addressed, big-endian.
- Words are 32 bytes. Ghidra's decompiler computes constants and known-zero
  bits in 64 bits, so every operation that moves bits across bit 64 is a
  CALLOTHER named as Yul names the instruction (shr, mul, div, exp, ...):
  folding it would be wrong for 256-bit values. Addition, subtraction, the
  bitwise operations and comparisons stay p-code, which is sound there because
  every constant is below 2^64: PUSH1..PUSH8 push their value, PUSH9..PUSH32
  push u256(limbs), 4-byte limbs, most significant first (the SLEIGH engine
  reads token fields 32 bits at a time).
- `PUSHn tag; JUMP` and `PUSHn tag; JUMPI` (n <= 4) are one instruction each,
  a direct branch to the tag, the way bytecode-lifting.md folds instruction
  pairs: most of a contract's jumps then need no analysis. Other jumps are
  computed (BRANCHIND); the loader's stack analysis gives their targets as
  references (revkit/backend/evm_import.cc).
- STOP, RETURN, REVERT, INVALID and SELFDESTRUCT end the contract's run: a
  CALLOTHER saying which, then a return.
"""

import sys

# (opcode, mnemonic, pops, pushes, semantics): semantics "p-code" for those
# written below, else the CALLOTHER's name.
BINARY_PCODE = {
    0x01: ("ADD", "a + b"),
    0x03: ("SUB", "a - b"),
    0x16: ("AND", "a & b"),
    0x17: ("OR", "a | b"),
    0x18: ("XOR", "a ^ b"),
}
COMPARE = {
    0x10: ("LT", "a < b"),
    0x11: ("GT", "a > b"),
    0x12: ("SLT", "a s< b"),
    0x13: ("SGT", "a s> b"),
    0x14: ("EQ", "a == b"),
}
# CALLOTHERs with their input count and whether they push a result.
CALLS = {
    0x02: ("MUL", "mul", 2, 1),
    0x04: ("DIV", "div", 2, 1),
    0x05: ("SDIV", "sdiv", 2, 1),
    0x06: ("MOD", "mod", 2, 1),
    0x07: ("SMOD", "smod", 2, 1),
    0x08: ("ADDMOD", "addmod", 3, 1),
    0x09: ("MULMOD", "mulmod", 3, 1),
    0x0A: ("EXP", "exp", 2, 1),
    0x0B: ("SIGNEXTEND", "signextend", 2, 1),
    0x1A: ("BYTE", "byte", 2, 1),
    0x1B: ("SHL", "shl", 2, 1),
    0x1C: ("SHR", "shr", 2, 1),
    0x1D: ("SAR", "sar", 2, 1),
    0x20: ("KECCAK256", "keccak256", 2, 1),
    0x30: ("ADDRESS", "address", 0, 1),
    0x31: ("BALANCE", "balance", 1, 1),
    0x32: ("ORIGIN", "origin", 0, 1),
    0x33: ("CALLER", "caller", 0, 1),
    0x34: ("CALLVALUE", "callvalue", 0, 1),
    0x35: ("CALLDATALOAD", "calldataload", 1, 1),
    0x36: ("CALLDATASIZE", "calldatasize", 0, 1),
    0x37: ("CALLDATACOPY", "calldatacopy", 3, 0),
    0x38: ("CODESIZE", "codesize", 0, 1),
    0x39: ("CODECOPY", "codecopy", 3, 0),
    0x3A: ("GASPRICE", "gasprice", 0, 1),
    0x3B: ("EXTCODESIZE", "extcodesize", 1, 1),
    0x3C: ("EXTCODECOPY", "extcodecopy", 4, 0),
    0x3D: ("RETURNDATASIZE", "returndatasize", 0, 1),
    0x3E: ("RETURNDATACOPY", "returndatacopy", 3, 0),
    0x3F: ("EXTCODEHASH", "extcodehash", 1, 1),
    0x40: ("BLOCKHASH", "blockhash", 1, 1),
    0x41: ("COINBASE", "coinbase", 0, 1),
    0x42: ("TIMESTAMP", "timestamp", 0, 1),
    0x43: ("NUMBER", "number", 0, 1),
    0x44: ("PREVRANDAO", "prevrandao", 0, 1),
    0x45: ("GASLIMIT", "gaslimit", 0, 1),
    0x46: ("CHAINID", "chainid", 0, 1),
    0x47: ("SELFBALANCE", "selfbalance", 0, 1),
    0x48: ("BASEFEE", "basefee", 0, 1),
    0x49: ("BLOBHASH", "blobhash", 1, 1),
    0x4A: ("BLOBBASEFEE", "blobbasefee", 0, 1),
    0x54: ("SLOAD", "sload", 1, 1),
    0x55: ("SSTORE", "sstore", 2, 0),
    0x59: ("MSIZE", "msize", 0, 1),
    0x5A: ("GAS", "gas", 0, 1),
    0x5C: ("TLOAD", "tload", 1, 1),
    0x5D: ("TSTORE", "tstore", 2, 0),
    0x5E: ("MCOPY", "mcopy", 3, 0),
    0xA0: ("LOG0", "log0", 2, 0),
    0xA1: ("LOG1", "log1", 3, 0),
    0xA2: ("LOG2", "log2", 4, 0),
    0xA3: ("LOG3", "log3", 5, 0),
    0xA4: ("LOG4", "log4", 6, 0),
    0xF0: ("CREATE", "create", 3, 1),
    0xF1: ("CALL", "evm_call", 7, 1),
    0xF2: ("CALLCODE", "callcode", 7, 1),
    0xF4: ("DELEGATECALL", "delegatecall", 6, 1),
    0xF5: ("CREATE2", "create2", 4, 1),
    0xFA: ("STATICCALL", "staticcall", 6, 1),
}
# Instructions that end the run: the CALLOTHER and its input count.
HALTS = {
    0x00: ("STOP", "stop", 0),
    0xF3: ("RETURN", "evm_return", 2),
    0xFD: ("REVERT", "revert", 2),
    0xFE: ("INVALID", "invalid", 0),
    0xFF: ("SELFDESTRUCT", "selfdestruct", 1),
}
# Opcodes assigned nowhere decode as INVALID (as the EVM runs them).
SEG = "(inst_start & 0xfff00000)"


def pops(n):
    names = [f"x{i}" for i in range(n)]
    lines = [f"local {v}:32 = 0; pop({v});" for v in names]
    return names, " ".join(lines)


def main(out):
    w = out.write
    w("# Ethereum Virtual Machine bytecode: revkit's SLEIGH spec (docs/evm.md).\n")
    w("# GENERATED by processors/EVM/gen_slaspec.py: edit that, not this.\n\n")
    w("""define endian=big;
define alignment=1;

define space ram      type=ram_space      size=4 wordsize=1 default;
define space opstack  type=ram_space      size=4 wordsize=1;
define space mem      type=ram_space      size=4 wordsize=1;
define space register type=register_space size=4;

define register offset=0x0 size=4 [ SP PC RA ];

define token opbyte (8) op=(0,7);
define token tail   (8) op2=(0,7);
""")
    # Immediates in pieces of at most 4 bytes: the SLEIGH engine reads a
    # token's fields 32 bits at a time.
    for k in range(1, 5):
        w(f"define token tk{k} ({8 * k}) h{k}=(0,{8 * k - 1});\n")
    for k in range(1, 8):
        w(f"define token tw{k} (32) w{k}=(0,31);\n")
    w("\n")
    names = sorted({c[1] for c in CALLS.values()} | {h[1] for h in HALTS.values()} | {"u256"})
    for n in names:
        w(f"define pcodeop {n};\n")
    w("""
macro push(v) { SP = SP - 32; *[opstack]:32 SP = v; }
macro pop(v)  { v = *[opstack]:32 SP; SP = SP + 32; }

# A jump's tag, in the segment of the jump's own code.
""")
    for k in range(1, 5):
        w(f"jtag{k}: loc is h{k} [ loc = {SEG} + h{k}; ] {{ export *:1 loc; }}\n")
    w("\n# Folded PUSHn tag; JUMP and PUSHn tag; JUMPI: direct branches.\n")
    for k in range(1, 5):
        w(f":JUMP jtag{k} is op={0x5f + k:#x}; jtag{k}; op2=0x56 {{ goto jtag{k}; }}\n")
        w(f":JUMPI jtag{k} is op={0x5f + k:#x}; jtag{k}; op2=0x57 "
          f"{{ local c:32 = 0; pop(c); if (c != 0) goto jtag{k}; }}\n")
    w("""
# Computed jumps.
:JUMP  is op=0x56 { local d:32 = 0; pop(d); local t:4 = d:4 + """ + SEG + """; goto [t]; }
:JUMPI is op=0x57 { local d:32 = 0; pop(d); local c:32 = 0; pop(c); local t:4 = d:4 + """ + SEG + """;
                    if (c == 0) goto inst_next; goto [t]; }
:JUMPDEST is op=0x5b { }
:PC is op=0x58 { local s:4 = inst_start; local o:4 = s & 0xfffff; local v:32 = zext(o); push(v); }
:POP is op=0x50 { SP = SP + 32; }
:PUSH0 is op=0x5f { local v:32 = 0; push(v); }
""")
    # PUSH1..PUSH8: the value (built in 8 bytes, so the decompiler folds
    # it). PUSH9..PUSH15: u256(limbs of 4 bytes), most significant first.
    # PUSH16..PUSH32 are longer than the 16 bytes the SLEIGH engine decodes:
    # the opcode alone is the instruction, its limbs are loads from the code
    # (read-only, so the decompiler folds them to constants) and it branches
    # past its immediate, which the listing shows as bytes.
    for n in range(1, 33):
        opc = 0x5F + n
        k = n % 4 or 4
        words = (n - k) // 4
        fields = [f"h{k}"] + [f"w{i}" for i in range(1, words + 1)]
        pattern = "; ".join(fields)
        disp = "^\":\"^".join(fields)
        if n <= 4:
            w(f":PUSH{n} h{n} is op={opc:#x}; h{n} {{ local v:32 = h{n}; push(v); }}\n")
        elif n <= 8:
            w(f":PUSH{n} {disp} is op={opc:#x}; {pattern} {{ local hi:8 = h{k}; local lo:8 = w1; "
              f"local t:8 = (hi << 32) | lo; local v:32 = zext(t); push(v); }}\n")
        elif n <= 15:
            args = ", ".join([f"h{k}:4"] + [f"w{i}:4" for i in range(1, words + 1)])
            w(f":PUSH{n} {disp} is op={opc:#x}; {pattern} {{ local v:32 = u256({args}); push(v); }}\n")
        else:
            sizes = [k] + [4] * words
            limbs, off = [], 1
            for i, size in enumerate(sizes):
                name = f"imm{n}_{i}"
                w(f"{name}: loc is epsilon [ loc = inst_start + {off}; ] {{ export *[ram]:{size} loc; }}\n")
                limbs.append(name)
                off += size
            w(f"skip{n}: loc is epsilon [ loc = inst_start + {n + 1}; ] {{ export *:1 loc; }}\n")
            subs = " & ".join(limbs + [f"skip{n}"])
            w(f":PUSH{n} is op={opc:#x} & {subs} {{ local v:32 = u256({', '.join(limbs)}); push(v); goto skip{n}; }}\n")
    w("\n# DUPn and SWAPn.\n")
    for n in range(1, 17):
        w(f":DUP{n} is op={0x7f + n:#x} {{ local v:32 = *[opstack]:32 (SP + {32 * (n - 1)}); push(v); }}\n")
    for n in range(1, 17):
        w(f":SWAP{n} is op={0x8f + n:#x} {{ local a:32 = *[opstack]:32 SP; local b:32 = *[opstack]:32 (SP + {32 * n}); "
          f"*[opstack]:32 SP = b; *[opstack]:32 (SP + {32 * n}) = a; }}\n")
    w("\n# Arithmetic and logic in p-code (sound below 2^64; see the header).\n")
    for opc, (m, expr) in sorted(BINARY_PCODE.items()):
        w(f":{m} is op={opc:#x} {{ local a:32 = 0; pop(a); local b:32 = 0; pop(b); local r:32 = {expr}; push(r); }}\n")
    for opc, (m, expr) in sorted(COMPARE.items()):
        w(f":{m} is op={opc:#x} {{ local a:32 = 0; pop(a); local b:32 = 0; pop(b); local r:32 = zext({expr}); push(r); }}\n")
    w(":ISZERO is op=0x15 { local a:32 = 0; pop(a); local r:32 = zext(a == 0); push(r); }\n")
    w(":NOT is op=0x19 { local a:32 = 0; pop(a); local r:32 = ~a; push(r); }\n")
    w("\n# Memory.\n")
    w(":MLOAD is op=0x51 { local o:32 = 0; pop(o); local a:4 = o:4; local v:32 = *[mem]:32 a; push(v); }\n")
    w(":MSTORE is op=0x52 { local o:32 = 0; pop(o); local v:32 = 0; pop(v); local a:4 = o:4; *[mem]:32 a = v; }\n")
    w(":MSTORE8 is op=0x53 { local o:32 = 0; pop(o); local v:32 = 0; pop(v); local a:4 = o:4; *[mem]:1 a = v:1; }\n")
    w("\n# The rest, as Yul names them.\n")
    for opc, (m, name, n, result) in sorted(CALLS.items()):
        args, code = pops(n)
        call = f"{name}({', '.join(args)})"
        body = f"{code} local r:32 = {call}; push(r);" if result else f"{code} {call};"
        w(f":{m} is op={opc:#x} {{ {body.strip()} }}\n")
    w("\n# The end of a run.\n")
    for opc, (m, name, n) in sorted(HALTS.items()):
        args, code = pops(n)
        w(f":{m} is op={opc:#x} {{ {code} {name}({', '.join(args)}); return [RA]; }}\n".replace("{  ", "{ "))
    used = set(BINARY_PCODE) | set(COMPARE) | set(CALLS) | set(HALTS)
    used |= {0x15, 0x19, 0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x58, 0x5B} | set(range(0x5F, 0xA0))
    w("\n# Unassigned opcodes run as INVALID.\n")
    for opc in range(256):
        if opc not in used:
            w(f":INVALID is op={opc:#x} {{ invalid(); return [RA]; }}\n")


if __name__ == "__main__":
    main(sys.stdout)
