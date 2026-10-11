"""Shared by export_function_signatures and apply_function_signatures (a
module, not a script: the leading underscore keeps it out of the lists)."""
import hashlib
import re

_DEFAULT = re.compile(r"^(FUN|thunk_FUN|SUB|sub)_[0-9a-fA-F]+$")


def is_default_name(name: str) -> bool:
    """A name analysis made up (FUN_00401000), not a symbol's."""
    return bool(_DEFAULT.match(name))


def signature(program, function) -> tuple:
    """(SHA-256 hex, instruction count) of the function's instructions in
    address order: mnemonic and operand text, every operand that refers to
    an address replaced by "*"."""
    h = hashlib.sha256()
    n = 0
    for ins in program.instructions(function=function.entry.offset, pcode=False):
        ops = []
        for op in ins.operands:
            ops.append("*" if op.references else "".join(t.text for t in op.tokens))
        h.update(f"{ins.mnemonic} {','.join(ops)};".encode())
        n += 1
    return h.hexdigest(), n
