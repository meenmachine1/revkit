#!/usr/bin/env python3
"""Source truth for decompiler quality (scripts/decomp-quality.py).

From a debug build's DWARF (pyelftools) and the corpus sources:

  functions  every concrete subprogram: entry, name, source file and line,
             the type class of its return, parameters and locals
  globals    global variables at fixed addresses: address, size, class
  source     a function's definition text, found from its declaration line
             by brace matching (comments and strings skipped)

and light source facts about a definition (source_facts): gotos, switches,
loops, member accesses, string and numeric literals, local declarations.
The source is not preprocessed: a loop or switch a macro hides is not
counted (Lua's vmdispatch), and that is the main limit of these facts.

Sources come from the same archives the corpus builds unpack (corpus.json,
corpus/firmware/firmware.json), unpacked under --src (build/quality/src).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tarfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# --------------------------------------------------------------------------
# Type classes


def type_class(die, depth: int = 0) -> str:
    """void, bool, char, int, float, ptr, struct, array, func or other."""
    if die is None:
        return "void"
    if depth > 20:
        return "other"
    tag = die.tag
    if tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restrict_type",
               "DW_TAG_atomic_type"):
        t = die.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in die.attributes else None
        return type_class(t, depth + 1)
    if tag == "DW_TAG_base_type":
        enc = die.attributes.get("DW_AT_encoding")
        enc = enc.value if enc else 0
        size = die.attributes["DW_AT_byte_size"].value if "DW_AT_byte_size" in die.attributes else 0
        if enc == 0x02:
            return "bool"
        if enc in (0x04, 0x03):  # float, complex float
            return "float"
        if enc in (0x06, 0x08) or size == 1:
            return "char"
        return "int"
    if tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type", "DW_TAG_rvalue_reference_type"):
        return "ptr"
    if tag in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_class_type"):
        return "struct"
    if tag == "DW_TAG_enumeration_type":
        return "int"
    if tag == "DW_TAG_array_type":
        return "array"
    if tag == "DW_TAG_subroutine_type":
        return "func"
    return "other"


def type_size(die, depth: int = 0) -> int:
    if die is None or depth > 20:
        return 0
    if "DW_AT_byte_size" in die.attributes:
        return die.attributes["DW_AT_byte_size"].value
    if die.tag in ("DW_TAG_pointer_type",):
        return die.cu["address_size"]
    if "DW_AT_type" in die.attributes and die.tag != "DW_TAG_array_type":
        return type_size(die.get_DIE_from_attribute("DW_AT_type"), depth + 1)
    return 0


_C_CLASS = [
    (re.compile(r"\*\s*$|\[\s*\]$"), "ptr"),
    (re.compile(r"^(?:const\s+)?(?:float|double|longdouble|long double|float\d+)$"), "float"),
    (re.compile(r"^(?:const\s+)?bool$|^_Bool$"), "bool"),
    (re.compile(r"^(?:const\s+)?(?:u?char|signed char|unsigned char|byte|sbyte|undefined1|char)$"), "char"),
    (re.compile(r"^void$"), "void"),
    (re.compile(r"^(?:const\s+)?(?:u?int\d*|u?short|u?long|u?longlong|long long|unsigned.*|signed.*|int|long|short|"
                r"uint\d+_t|int\d+_t|size_t|ssize_t|ulong|undefined[2-8]|wchar\d*|wchar_t|word|dword|qword|"
                r"enum\s+\w+)$"), "int"),
    (re.compile(r"^undefined$"), "unknown"),
    (re.compile(r"^code$"), "func"),
]


def c_type_class(t: str) -> str:
    """The class of a type as decompiled C spells it (Ghidra's names)."""
    t = " ".join(t.replace("*", " * ").split()).replace(" *", "*").strip()
    if t.endswith("*"):
        return "ptr"
    t = re.sub(r"^(?:struct|union)\s+", "S:", t)
    if t.startswith("S:"):
        return "struct"
    for rx, cls in _C_CLASS:
        if rx.search(t):
            return cls
    return "struct"  # a named type: a typedef'd struct or enum the decompiler knows


# --------------------------------------------------------------------------
# DWARF


def _attr_die(die, name):
    """Follows DW_AT_abstract_origin / DW_AT_specification for an attribute."""
    seen = 0
    while die is not None and seen < 4:
        if name in die.attributes:
            return die
        nxt = None
        for link in ("DW_AT_abstract_origin", "DW_AT_specification"):
            if link in die.attributes:
                nxt = die.get_DIE_from_attribute(link)
                break
        die = nxt
        seen += 1
    return None


def _name(die):
    d = _attr_die(die, "DW_AT_name")
    if d is None:
        return None
    v = d.attributes["DW_AT_name"].value
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else v


def _file_table(dwarf, cu):
    lp = dwarf.line_program_for_CU(cu)
    if lp is None:
        return [], 5
    ver = lp.header["version"]
    dirs = [d.decode("utf-8", "replace") if isinstance(d, bytes) else d for d in lp.header["include_directory"]]
    comp_dir = cu.get_top_DIE().attributes.get("DW_AT_comp_dir")
    comp_dir = comp_dir.value.decode("utf-8", "replace") if comp_dir else ""
    files = []
    for fe in lp.header["file_entry"]:
        name = fe.name.decode("utf-8", "replace") if isinstance(fe.name, bytes) else fe.name
        di = fe.dir_index
        if ver >= 5:
            d = dirs[di] if di < len(dirs) else ""
        else:
            d = comp_dir if di == 0 else (dirs[di - 1] if di - 1 < len(dirs) else "")
        files.append(os.path.join(d, name) if not name.startswith("/") else name)
    return files, ver


def _location_addr(die):
    loc = die.attributes.get("DW_AT_location")
    if loc is None or loc.form not in ("DW_FORM_exprloc", "DW_FORM_block1", "DW_FORM_block"):
        return None
    v = loc.value
    if v and v[0] == 0x03 and len(v) == 1 + die.cu["address_size"]:  # DW_OP_addr
        b = bytes(v[1:])
        return int.from_bytes(b, "little" if die.dwarfinfo.config.little_endian else "big")
    if v and v[0] in (0xa1, 0xfb):  # DW_OP_addrx, DW_OP_GNU_addr_index
        idx, shift, i = 0, 0, 1
        while i < len(v):
            idx |= (v[i] & 0x7f) << shift
            shift += 7
            i += 1
            if not v[i - 1] & 0x80:
                break
        if i != len(v):
            return None
        try:
            return die.dwarfinfo.get_addr(die.cu, idx)
        except Exception:  # noqa: BLE001 (no .debug_addr)
            return None
    return None


def read_dwarf(elf_path: str) -> dict:
    """{functions: [...], globals: [...]} from an ELF's DWARF."""
    from elftools.elf.elffile import ELFFile

    functions: dict[int, dict] = {}
    globals_: list[dict] = []
    with open(elf_path, "rb") as fh:
        elf = ELFFile(fh)
        if not elf.has_dwarf_info():
            return {"functions": [], "globals": []}
        arm = elf.header["e_machine"] == "EM_ARM"
        # Ghidra (and revkit) load a position-independent image at 0x100000.
        loads = [seg["p_vaddr"] for seg in elf.iter_segments() if seg["p_type"] == "PT_LOAD"]
        bias = 0x100000 if elf.header["e_type"] == "ET_DYN" and loads and min(loads) == 0 else 0
        dwarf = elf.get_dwarf_info()
        for cu in dwarf.iter_CUs():
            files, ver = _file_table(dwarf, cu)

            def file_of(die):
                d = _attr_die(die, "DW_AT_decl_file")
                if d is None:
                    return None, None
                idx = d.attributes["DW_AT_decl_file"].value
                line = d.attributes.get("DW_AT_decl_line")
                i = idx if ver >= 5 else idx - 1
                return (files[i] if 0 <= i < len(files) else None), (line.value if line else None)

            def locals_of(die, out):
                for ch in die.iter_children():
                    if ch.tag == "DW_TAG_variable":
                        t = _attr_die(ch, "DW_AT_type")
                        td = t.get_DIE_from_attribute("DW_AT_type") if t is not None else None
                        out.append({"name": _name(ch), "class": type_class(td)})
                    elif ch.tag == "DW_TAG_lexical_block":
                        locals_of(ch, out)

            for die in cu.iter_DIEs():
                if die.tag == "DW_TAG_variable" and die.get_parent() is not None and \
                        die.get_parent().tag == "DW_TAG_compile_unit":
                    a = _location_addr(die)
                    if a is not None and a != 0:
                        t = _attr_die(die, "DW_AT_type")
                        td = t.get_DIE_from_attribute("DW_AT_type") if t is not None else None
                        globals_.append({"addr": a + bias, "name": _name(die), "class": type_class(td),
                                         "size": type_size(td)})
                    continue
                if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attributes:
                    continue
                if "DW_AT_inline" in die.attributes and die.attributes["DW_AT_inline"].value in (1, 3) and \
                        "DW_AT_high_pc" not in die.attributes:
                    continue
                entry = die.attributes["DW_AT_low_pc"].value
                if arm:
                    entry &= ~1
                if entry == 0:
                    continue
                entry += bias
                path, line = file_of(die)
                t = _attr_die(die, "DW_AT_type")
                ret = type_class(t.get_DIE_from_attribute("DW_AT_type")) if t is not None else "void"
                params, locs = [], []
                proto_die = _attr_die(die, "DW_AT_name") or die
                variadic = False
                for ch in die.iter_children():
                    if ch.tag == "DW_TAG_formal_parameter":
                        pt = _attr_die(ch, "DW_AT_type")
                        params.append(type_class(pt.get_DIE_from_attribute("DW_AT_type")) if pt is not None
                                      else "other")
                    elif ch.tag == "DW_TAG_unspecified_parameters":
                        variadic = True
                if not params and proto_die is not die:
                    for ch in proto_die.iter_children():
                        if ch.tag == "DW_TAG_formal_parameter":
                            pt = _attr_die(ch, "DW_AT_type")
                            params.append(type_class(pt.get_DIE_from_attribute("DW_AT_type")) if pt is not None
                                          else "other")
                locals_of(die, locs)
                functions.setdefault(entry, {
                    "entry": entry, "name": _name(die), "file": path, "line": line, "ret": ret,
                    "params": params, "varargs": variadic, "locals": [l["class"] for l in locs],
                    "noreturn": _attr_die(die, "DW_AT_noreturn") is not None,
                })
    return {"functions": sorted(functions.values(), key=lambda f: f["entry"]), "globals": globals_}


# --------------------------------------------------------------------------
# Sources


def _unpack(archive: str, dest: str, strip: int) -> None:
    os.makedirs(dest, exist_ok=True)
    if archive.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                parts = info.filename.split("/")[strip:]
                if not parts or not parts[-1] or info.is_dir() or not parts[-1].endswith((".c", ".h", ".S", ".inc")):
                    continue
                target = os.path.join(dest, *parts)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as s, open(target, "wb") as o:
                    o.write(s.read())
        return
    with tarfile.open(archive) as tf:
        for m in tf.getmembers():
            parts = m.name.split("/")[strip:]
            if not parts or not m.isfile() or not parts[-1].endswith((".c", ".h", ".S", ".inc", ".patch")):
                continue
            m.name = "/".join(parts)
            tf.extract(m, dest, filter="data")


def prepare_sources(src_dir: str, heldout: bool = False) -> dict[str, str]:
    """Unpacks the corpus programs' sources (the held-out set's with
    `heldout`); {program: root}."""
    roots = {}
    corpus = json.load(open(os.path.join(ROOT, "corpus", "heldout.json" if heldout else "corpus.json")))
    cache = os.path.join(ROOT, "out", "cache-heldout" if heldout else "cache")
    for name, prog in corpus["programs"].items():
        root = os.path.join(src_dir, "heldout" if heldout else "tuning", name)
        roots[name] = root
        if os.path.isdir(root):
            continue
        if "external" in prog:
            ext = corpus["externals"][prog["external"]]
            _unpack(os.path.join(cache, ext.get("file") or os.path.basename(ext["url"])), root + ".tmp",
                    ext.get("strip_components", 0))
            os.rename(root + ".tmp", root)
        else:
            import shutil
            shutil.copytree(os.path.join(ROOT, "corpus", prog["source"]), root)
    fw = json.load(open(os.path.join(ROOT, "corpus", "firmware", "firmware.json")))
    froot = os.path.join(src_dir, "firmware")
    if not os.path.isdir(froot):
        import shutil
        tmp = froot + ".tmp"
        shutil.rmtree(tmp, ignore_errors=True)
        for name, ext in fw["externals"].items():
            if "xtensa" in name or "toolchain" in name:
                continue
            fname = ext.get("file") or os.path.basename(ext["url"])
            archive = os.path.join(ROOT, "out", "cache-firmware", fname)
            if not os.path.exists(archive):
                continue
            _unpack(archive, os.path.join(tmp, name), ext.get("strip_components", 0))
            for rel in ext.get("patches", []):
                subprocess.run(["patch", "-p1", "-s", "-f", "-i", os.path.join(ROOT, "corpus", "firmware", rel)],
                               cwd=os.path.join(tmp, name), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.copytree(os.path.join(ROOT, "corpus", "firmware", "src", "fwkit"), os.path.join(tmp, "fwkit"))
        os.rename(tmp, froot)
    roots["firmware"] = froot
    return roots


class SourceIndex:
    """Resolves a DWARF file path to a file under a source root by its
    longest matching path suffix (ambiguous: none)."""

    def __init__(self, root: str, exclude: tuple[str, ...] = ()):
        self.by_base: dict[str, list[str]] = {}
        for dirpath, dirs, files in os.walk(root):
            if dirpath == root:
                dirs[:] = [d for d in dirs if d not in exclude]
            for f in files:
                self.by_base.setdefault(f, []).append(os.path.join(dirpath, f))
        self.cache: dict[str, str | None] = {}
        self.text: dict[str, list[str]] = {}

    def resolve(self, path: str | None) -> str | None:
        if not path:
            return None
        if path in self.cache:
            return self.cache[path]
        parts = [p for p in os.path.normpath(path).split("/") if p not in ("", ".")]
        cands = self.by_base.get(parts[-1], []) if parts else []
        best, score = None, 0
        for c in cands:
            cp = c.split("/")
            n = 0
            while n < len(parts) and n < len(cp) and cp[-1 - n] == parts[-1 - n]:
                n += 1
            if n > score:
                best, score = c, n
            elif n == score:
                best = None if best is not None and best != c else best
        self.cache[path] = best
        return best

    def lines(self, path: str) -> list[str]:
        if path not in self.text:
            with open(path, encoding="utf-8", errors="replace") as f:
                self.text[path] = f.read().split("\n")
        return self.text[path]


_SKIP = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', re.S)


def _mask_alternatives(lines: list[str]) -> list[str]:
    """Blanks preprocessor lines and the #else/#elif branches of
    conditionals, so braces balance as in one configuration."""
    out, stack = [], []  # stack: is the current branch skipped
    for ln in lines:
        d = ln.strip()
        if d.startswith("#"):
            w = d[1:].strip().split(None, 1)[0] if d[1:].strip() else ""
            if w in ("if", "ifdef", "ifndef"):
                stack.append(False)
            elif w in ("else", "elif") and stack:
                stack[-1] = True
            elif w == "endif" and stack:
                stack.pop()
            out.append(" " * len(ln))
        elif any(stack):
            out.append(" " * len(ln))
        else:
            out.append(ln)
    return out


def function_source(index: SourceIndex, path: str | None, line: int | None, name: str | None) -> str | None:
    """The definition of the function declared at path:line."""
    f = index.resolve(path)
    if f is None or not line:
        return None
    lines = index.lines(f)
    if line > len(lines):
        return None
    start = line - 1
    # The return type may sit on the lines before the name (K&R, GNU style).
    while start > 0 and start > line - 4:
        prev = lines[start - 1].strip()
        if not prev or prev.endswith((";", "}", "{", "*/")) or prev.startswith(("#", "/*", "//", "*")):
            break
        start -= 1
    text = "\n".join(lines[start:start + 3000])
    masked = _SKIP.sub(lambda m: " " * len(m.group(0)) if "\n" not in m.group(0) else
                       re.sub(r"[^\n]", " ", m.group(0)), text)
    masked = "\n".join(_mask_alternatives(masked.split("\n")))
    depth = paren = 0
    opened = None
    for i, ch in enumerate(masked):
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
        elif ch == ";" and opened is None and paren == 0:
            return None  # a declaration, or a macro-made definition
        elif ch == "{":
            if opened is None:
                opened = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if opened is not None and depth == 0:
                out = text[:i + 1]
                if name and name not in masked[:opened]:
                    return None
                return out
    return None


# --------------------------------------------------------------------------
# Facts of C text (the source, or decompiled C)

_TOK = re.compile(r"""
    (?P<comment>/\*.*?\*/|//[^\n]*)
  | (?P<string>[LuU]?8?"(?:\\.|[^"\\\n])*")
  | (?P<char>[LuU]?'(?:\\.|[^'\\\n])*')
  | (?P<ident>[A-Za-z_][A-Za-z_0-9]*)
  | (?P<number>(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d*)?(?:[eE][-+]?\d+)?)[A-Za-z]*)
  | (?P<op>->|\+\+|--|<<=|>>=|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%&|^]=|\.\.\.|\S)
""", re.X | re.S)


def tokens(text: str) -> list[tuple[str, str]]:
    return [(m.lastgroup, m.group(m.lastgroup)) for m in _TOK.finditer(text) if m.lastgroup != "comment"]


def _unescape(s: str) -> str:
    body = s[s.index('"') + 1:-1]
    try:
        return body.encode("latin-1", "backslashreplace").decode("unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return body


def number_value(t: str):
    t = t.rstrip("uUlLfF")
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        if "." in t or "e" in t.lower():
            return None
        if len(t) > 1 and t.startswith("0"):
            return int(t, 8)
        return int(t)
    except ValueError:
        return None


_NOT_CALLS = {"if", "while", "for", "switch", "return", "sizeof", "_Alignof", "alignof", "do", "else", "case",
              "defined", "__attribute__", "typeof", "__typeof__", "_Generic"}


def named_calls(toks: list) -> list:
    """(name, argument count) of every call by name in a token list:
    `name(` not preceded by '.', '->' or a type keyword's declarator."""
    out = []
    for i, (k, t) in enumerate(toks):
        if k != "ident" or t in _NOT_CALLS or i + 1 >= len(toks) or toks[i + 1][1] != "(":
            continue
        if i > 0 and toks[i - 1][1] in (".", "->", "&"):
            continue
        depth, n, j, empty = 0, 0, i + 1, True
        while j < len(toks):
            tt = toks[j][1]
            if tt in ("(", "[", "{"):
                depth += 1
            elif tt in (")", "]", "}"):
                depth -= 1
                if depth == 0:
                    break
            elif tt == "," and depth == 1:
                n += 1
            if depth >= 1 and j > i + 1:
                empty = False
            j += 1
        out.append((t, 0 if empty else n + 1))
    return out


def c_facts(text: str) -> dict:
    """Control flow, member accesses and literals of a function's text."""
    toks = tokens(text)
    words = [t for k, t in toks if k == "ident"]
    body_at = next((i for i, (k, t) in enumerate(toks) if t == "{"), len(toks))
    body = toks[body_at:]
    members = 0
    for i, (k, t) in enumerate(body):
        if t == "->":
            members += 1
        elif t == "." and i + 1 < len(body) and body[i + 1][0] == "ident" and i > 0 and \
                (body[i - 1][0] == "ident" or body[i - 1][1] in (")", "]")):
            members += 1
    do = words.count("do")
    strings = [_unescape(t) for k, t in body if k == "string"]
    nums = {number_value(t) for k, t in body if k == "number"}
    return {
        "calls": named_calls(body),
        "gotos": words.count("goto"),
        "switches": words.count("switch"),
        "loops": words.count("for") + words.count("while"),  # a do-while's while counts as its loop
        "do": do,
        "members": members,
        "strings": strings,
        "numbers": {n for n in nums if n is not None},
        "lines": len([l for l in text.split("\n") if l.strip()]),
    }
