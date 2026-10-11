"""A script's metadata, from the comment lines at its top.

    # @category Analysis/Strings
    # @description Names unnamed functions after the identifiers their strings mention
    # @menupath Analysis.Rename by strings
    # @keybinding ctrl shift R
    # @context program
    # @arg min_length:int=4 Shortest identifier to take from a string
    # @arg dry_run:bool=false Report the renames without making them

Only the leading block of comments (and blank lines, a shebang, an encoding
line) is read; the first line of code ends it, so a ``@`` in the body never
counts. Unknown tags are kept in ``extra``. The same parser serves
``rk-script info``; the daemon's ``ScriptService.ListScripts`` reads the same tags in C++.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

# What a script asks for (@context): where in the program it applies.
CONTEXTS = ("program", "function", "address", "selection")
ARG_TYPES = ("str", "int", "float", "bool", "address", "file", "choice")

_TAG = re.compile(r"^#\s*@(\w+)\s*(.*?)\s*$")
_ARG = re.compile(r"^(\w+)(?::(\w+))?(?:\[([^\]]*)\])?(?:=(\S*))?(?:\s+(.*))?$")


@dataclass
class ScriptArg:
    """One ``@arg name[:type][[choice|choice]][=default] description``."""

    name: str
    type: str = "str"
    default: Optional[str] = None
    description: str = ""
    choices: list = field(default_factory=list)

    def convert(self, text: str) -> Any:
        """The value of ``text`` (an ``--arg`` or a typed answer) as this
        argument's type; addresses stay text (the script resolves them)."""
        return convert(self.type, text, self.choices, self.name)


@dataclass
class ScriptMeta:
    path: str
    name: str
    category: str = ""
    description: str = ""
    menupath: str = ""
    keybinding: str = ""
    context: str = "program"
    args: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)
    # First 12 hex digits of the source's SHA-256: the provenance version.
    sha12: str = ""
    errors: list = field(default_factory=list)

    def arg(self, name: str) -> Optional[ScriptArg]:
        return next((a for a in self.args if a.name == name), None)

    def to_dict(self) -> dict:
        return asdict(self)


def convert(kind: str, text: Any, choices=(), name: str = "") -> Any:
    """Converts an answer's text to ``kind`` (see ARG_TYPES)."""
    if not isinstance(text, str):
        return text
    t = text.strip()
    if kind == "int":
        return int(t, 0)
    if kind == "float":
        return float(t)
    if kind == "bool":
        low = t.lower()
        if low in ("1", "true", "yes", "y", "on"):
            return True
        if low in ("0", "false", "no", "n", "off", ""):
            return False
        raise ValueError(f"{name or 'value'}: {text!r} is not yes or no")
    if kind == "choice" and choices and t not in choices:
        raise ValueError(f"{name or 'value'}: {text!r} is not one of {', '.join(choices)}")
    return text


def parse_metadata(source: Union[str, bytes], path: Union[str, Path] = "<script>") -> ScriptMeta:
    """The metadata of a script's text."""
    if isinstance(source, bytes):
        raw = source
        source = source.decode("utf-8", errors="replace")
    else:
        raw = source.encode()
    p = Path(str(path))
    meta = ScriptMeta(path=str(path), name=p.stem if p.suffix == ".py" else p.name, sha12=hashlib.sha256(raw).hexdigest()[:12])
    untagged: list = []  # Ghidra's convention: the comment lines are the description
    in_licence = False
    for line in source.splitlines():
        s = line.strip()
        if not s or s.startswith("#!"):
            continue
        if not s.startswith("#"):
            break  # the first line of code ends the header
        if s.startswith("## ###"):
            in_licence = True  # Ghidra's licence block, "## ###" ... "##"
            continue
        if in_licence:
            in_licence = s != "##"
            continue
        m = _TAG.match(s)
        if not m:
            text = s.lstrip("#").strip()
            if text and "-*-" not in text and not text.startswith("type:"):
                untagged.append(text)
            continue
        tag, value = m.group(1).lower(), m.group(2)
        if value.startswith(":"):
            value = value[1:].strip()  # Ghidra's "# @category: Examples"
        if tag == "arg":
            a = _ARG.match(value)
            if not a:
                meta.errors.append(f"@arg {value!r}: expected name[:type][[a|b]][=default] description")
                continue
            kind = a.group(2) or "str"
            if kind not in ARG_TYPES:
                meta.errors.append(f"@arg {a.group(1)}: unknown type {kind!r} (one of {', '.join(ARG_TYPES)})")
                kind = "str"
            choices = [c for c in (a.group(3) or "").split("|") if c]
            if choices and kind == "str":
                kind = "choice"
            meta.args.append(ScriptArg(a.group(1), kind, a.group(4), a.group(5) or "", choices))
        elif tag == "context":
            if value not in CONTEXTS:
                meta.errors.append(f"@context {value!r}: one of {', '.join(CONTEXTS)}")
            else:
                meta.context = value
        elif tag in ("category", "description", "menupath", "keybinding", "name"):
            if tag == "description" and meta.description:
                meta.description += " " + value  # continued on another line
            else:
                setattr(meta, tag, value)
        else:
            meta.extra[tag] = value
    if not meta.description and untagged:
        meta.description = " ".join(untagged)
    return meta


def read_metadata(path: Union[str, Path]) -> ScriptMeta:
    p = Path(path)
    return parse_metadata(p.read_bytes(), p)


def shipped_scripts_dir() -> Path:
    """The starter scripts that ship with the SDK (revkit/scripts)."""
    return Path(__file__).resolve().parent.parent / "scripts"


def list_scripts(*dirs: Union[str, Path]) -> list:
    """The metadata of every ``*.py`` script in ``dirs`` (default: the
    shipped starters), by category then name."""
    out = []
    for d in dirs or (shipped_scripts_dir(),):
        for p in sorted(Path(d).glob("*.py")):
            if p.name.startswith("_"):
                continue
            out.append(read_metadata(p))
    return sorted(out, key=lambda m: (m.category, m.name))


def find_script(name: str, *dirs: Union[str, Path]) -> Path:
    """A script by path, or by name among ``dirs`` and the shipped starters."""
    p = Path(name)
    if p.is_file():
        return p
    stem = p.stem if p.suffix == ".py" else name
    for d in [*dirs, shipped_scripts_dir()]:
        for cand in (Path(d) / f"{stem}.py", Path(d) / f"{stem.replace('-', '_')}.py"):
            if cand.is_file():
                return cand
    raise FileNotFoundError(f"no script {name!r} (a path, or one of: {', '.join(m.name for m in list_scripts())})")
