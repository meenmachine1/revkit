"""Normalizing decompiled C for comparison (tools/refdiff).

Ghidra's printer and revkit's emit the same tokens but may break lines and
indent differently, so decompiled C is compared as a token sequence:

  tokens   every token, comments included; whitespace (line breaks,
           indentation, wrapping) ignored
  ast      the same, without comments: equal token sequences parse to the
           same syntax tree, which is the Phase 2 gate's "structurally
           identical C (same AST modulo whitespace)"
  alpha    ast, and local variable and parameter names renamed v0, v1, ...
           in order of first use: a looser, variable-name-insensitive
           secondary measure (globals, functions, types and fields keep
           their names)

Standard library only.
"""

from __future__ import annotations

import re

_TOKEN = re.compile(r"""
    (?P<comment>/\*.*?\*/|//[^\n]*)
  | (?P<string>[LuU]?8?"(?:\\.|[^"\\\n])*")
  | (?P<char>[LuU]?'(?:\\.|[^'\\\n])*')
  | (?P<ident>[A-Za-z_][A-Za-z_0-9]*)
  | (?P<number>(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d*)?(?:[eE][-+]?\d+)?|\.\d+(?:[eE][-+]?\d+)?)[A-Za-z]*)
  | (?P<op>->|\+\+|--|<<=|>>=|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%&|^]=|::|\.\.\.|\S)
""", re.X | re.S)

_KEYWORDS = frozenset("""
    auto break case char const continue default do double else enum extern float for goto if
    inline int long register restrict return short signed sizeof static struct switch typedef
    union unsigned void volatile while bool true false
""".split())

# Names Ghidra's decompiler invents for variables (database.cc
# buildVariableName, varmap.cc): uVar1, local_10, param_1, in_RAX,
# unaff_RBX, extraout_EAX, auStack_28, stack0x00000008, ...
_AUTO_VAR = re.compile(r"""^(?:
    [a-z]{0,4}Var\d+
  | local_[0-9a-f]+(?:_[0-9a-f]+)?
  | param_\d+
  | in_[A-Za-z0-9_]+
  | unaff_[A-Za-z0-9_]+
  | extraout_[A-Za-z0-9_]+
  | [a-z]{0,4}Stack_[0-9a-f]+(?:_[0-9a-f]+)?
  | stack0x[0-9a-f]+
  | [a-z]{0,4}Ram[0-9a-f]+
)$""", re.X)


def tokenize(text: str) -> list[tuple[str, str]]:
    """(kind, text) pairs; kind is comment, string, char, ident, number or op."""
    return [(m.lastgroup, m.group(m.lastgroup)) for m in _TOKEN.finditer(text)]


def _declared_names(text: str) -> set[str]:
    """Parameters from the signature and locals from the declaration block
    at the top of the body (Ghidra prints one declaration per line, then a
    blank line)."""
    names: set[str] = set()
    lines = text.split("\n")
    brace = next((i for i, l in enumerate(lines) if l.strip() == "{"), None)
    if brace is None:
        return names
    # Signature: the last line before the brace that has the parameter list.
    sig = " ".join(l for l in lines[:brace] if not l.strip().startswith(("/*", "*")) and l.strip())
    open_paren = sig.find("(")
    if open_paren >= 0:
        params = sig[open_paren + 1:sig.rfind(")")]
        depth = 0
        part = ""
        for c in params + ",":
            if c in "([":
                depth += 1
            elif c in ")]":
                depth -= 1
            if c == "," and depth == 0:
                toks = [t for k, t in tokenize(part) if k == "ident"]
                if toks and toks[-1] != "void":
                    names.add(toks[-1])
                part = ""
            else:
                part += c
    for line in lines[brace + 1:]:
        s = line.strip()
        if not s:
            break
        if s.startswith(("/*", "*", "//")) or not s.endswith(";"):
            continue
        toks = tokenize(s)
        # TYPE ... NAME ; or TYPE ... NAME [ N ] ;
        idx = len(toks) - 2
        if idx >= 0 and toks[idx][1] == "]":
            while idx >= 0 and toks[idx][1] != "[":
                idx -= 1
            idx -= 1
        if idx >= 1 and toks[idx][0] == "ident":
            names.add(toks[idx][1])
    return names


def normalize(text: str | None, mode: str):
    """A comparable form of `text` for `mode` (exact, loose, tokens, ast,
    alpha), or None for a missing function."""
    if not isinstance(text, str):
        return None
    if mode == "exact":
        return text
    if mode == "loose":
        return " ".join(text.split())
    toks = tokenize(text)
    if mode == "tokens":
        # Comments compared word by word, so their layout doesn't matter.
        out = []
        for kind, t in toks:
            out.extend(t.split() if kind == "comment" else [t])
        return tuple(out)
    toks = [(k, t) for k, t in toks if k != "comment"]
    if mode == "ast":
        return tuple(t for _, t in toks)
    if mode == "alpha":
        variables = _declared_names(text)
        renamed: dict[str, str] = {}
        out = []
        for i, (kind, t) in enumerate(toks):
            if kind == "ident" and t not in _KEYWORDS and (t in variables or _AUTO_VAR.match(t)):
                # Not a member name (after . or ->) or a call.
                prev = toks[i - 1][1] if i > 0 else ""
                if prev not in (".", "->"):
                    t = renamed.setdefault(t, "v%d" % len(renamed))
            out.append(t)
        return tuple(out)
    raise ValueError("unknown C comparison mode %r" % mode)


MODES = ("exact", "loose", "tokens", "ast", "alpha")


def first_difference(a: str, b: str, mode: str = "ast", context: int = 6) -> tuple[str, str]:
    """The neighbourhood of the first token where `a` and `b` differ."""
    ta, tb = normalize(a, mode) or (), normalize(b, mode) or ()
    i = 0
    while i < len(ta) and i < len(tb) and ta[i] == tb[i]:
        i += 1
    lo = max(0, i - context)
    return " ".join(ta[lo:i + context]), " ".join(tb[lo:i + context])
