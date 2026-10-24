"""revkit's script API: a flat layer over the SDK for scripts (docs/scripting.md).

A script is an ordinary Python file. ``rk-script run`` (or the daemon, later)
runs it with these names already defined, so it needs no imports; ``from
revkit.script import *`` makes an editor and a linter know them too::

    # @category Examples
    # @description Name every function that only returns a constant
    from revkit.script import *

    for f in current_program.functions():
        monitor.check_cancelled()
        if f.name.startswith("FUN_") and f.size <= 8:
            rename(f.entry, f"ret_const_{f.entry.offset:x}")

Context: ``current_program`` (a :class:`revkit.Program`),
``current_address``, ``current_function``, ``current_selection``
(``(first, last)`` or None), ``args`` (``--arg``, typed by ``@arg``),
``script`` (its metadata), ``run_id``, ``client``.

Edits (``rename``, ``rename_local``, ``retype``, ``retype_local``,
``comment``, ``set_function``, ``remove_function``, ``flow_override``,
``note``, ``define_type``, ``define_data``, ``clear``, ``disassemble``,
``set_mutability``, ``auto_create_structure``, ``auto_fill_structure``,
``create_structure``, ``import_type_archive``, ``set_type_category``,
``convert``, ``set_equate``, ``set_enum_equate``, ``clear_display``,
``rename_equate``, ``remove_equate``, ``add_reference``,
``remove_reference``, ``set_primary_reference``) are buffered and committed when the script ends,
as one revision with ``script:<name>@<sha12>`` provenance; ``commit()``
commits what is buffered now. ``revert()`` undoes this run's committed edits
(or another run's: ``revert(session=...)``).

Project (api_minor 37): ``current_project`` (the program's project id),
``project_programs`` and ``folders`` read the project's tree;
``create_folder``, ``rename_folder``, ``move_to_folder`` and
``delete_folder`` change it at once (not buffered), each one revision with
the run's provenance; ``export_project`` writes a .rkproj archive.

File systems (api_minor 48): ``open_filesystem`` opens a container (an
archive, a compressed file, a file system image, a firmware package; a
program's stored file, a file on the daemon's host or bytes) as a
``FileSystem`` to ``list``, ``read`` and ``info``; ``import_from_filesystem``
imports files from it as programs (one, or a batch) with the run's
provenance.

Prompts (``ask_string``, ``ask_int``, ``ask_float``, ``ask_address``,
``ask_yes_no``, ``ask_choice``, ``ask_choices``, ``ask_file``,
``ask_values``) are answered by ``--arg NAME=VALUE`` headless, by the user
in the UI. ``monitor`` reports progress and cancellation; ``print`` goes to
the run's console and ``log`` to its log.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from revkit.client import (_COMMENT_KINDS, _FLOW_OVERRIDES, AddressLike, address, address_range, auto_structure_bodies,
                           clear_code_body, define_data_body, disassemble_body, header_import_bodies, mutability_body,
                           operand_display_body, reference_body, remove_equate_bodies, rename_equate_bodies,
                           type_category_body)
from revkit.script.host import HeadlessHost, Prompt, PromptUnanswered, ScriptHost, StreamHost
from revkit.script.meta import ScriptArg, ScriptMeta, find_script, list_scripts, parse_metadata, read_metadata
from revkit.script.runtime import Cancelled, EditError, Monitor, Run, RunResult, current, run_script
from revkit.v1 import assertion_pb2

# What this SDK offers rk-daemon's script host, which the daemon checks
# before running scripts or a console with it (src/api/script_service.cc,
# kScriptSdkApi): an SDK below the daemon's number, or without the stamp,
# is older than the daemon, and "Set up Python" (rk-script setup) updates
# it. Raise both together when the daemon starts relying on something new
# here. 1: the worker's stream protocol and revkit.script.console.
SCRIPT_API = 1

_CONTEXT = ("current_program", "current_address", "current_function", "current_selection", "args", "script", "run_id",
            "client", "monitor", "current_project")

__all__ = [
    # context
    *_CONTEXT,
    # reads
    "functions", "function_at", "function_containing", "decompile", "decompile_many", "read_bytes", "find_bytes",
    "search_memory", "search_text", "search_scalars", "search_decompiled",
    "strings", "instructions", "xrefs_to", "xrefs_from", "symbol_at", "to_addr", "export_type_archive",
    "type_categories", "equates", "enums_with_value", "mangled_name", "demangled_signature", "image_base", "preview",
    # edits
    "set_image_base", "rename", "rename_local", "retype", "retype_local", "comment", "set_function", "remove_function",
    "flow_override", "note", "define_type", "define_data", "clear", "disassemble", "set_mutability",
    "auto_create_structure", "auto_fill_structure", "create_structure", "import_type_archive", "set_type_category",
    "move_types_to_project", "copy_types_to_program", "type_archives", "set_type_archive_enabled",
    "convert", "set_equate", "set_enum_equate", "clear_display", "rename_equate", "remove_equate", "add_reference",
    "remove_reference", "set_primary_reference",
    "commit", "revert",
    "pending_edits",
    # the project (api_minor 37)
    "project_programs", "folders", "create_folder", "rename_folder", "move_to_folder", "delete_folder",
    "export_project",
    # file systems (api_minor 48)
    "open_filesystem", "import_from_filesystem",
    # Function ID (api_minor 51)
    "fid_matches", "run_fid", "apply_fid", "reject_fid",
    # prompts
    "ask_string", "ask_int", "ask_float", "ask_address", "ask_yes_no", "ask_choice", "ask_choices", "ask_file",
    "ask_values",
    # output
    "log",
    # errors
    "Cancelled", "EditError", "PromptUnanswered",
]


def __getattr__(name: str) -> Any:
    """The context names (``current_program``, ...) of the running script."""
    if name in _CONTEXT:
        return _context(current(), name)
    raise AttributeError(f"module 'revkit.script' has no attribute {name!r}")


def _context(run: Run, name: str) -> Any:
    return {
        "current_program": lambda: run.program,
        "current_address": lambda: run.current_address,
        "current_function": lambda: run.current_function,
        "current_selection": lambda: run.current_selection,
        "args": lambda: run.args,
        "script": lambda: run.meta,
        "run_id": lambda: run.id,
        "client": lambda: run.client,
        "monitor": lambda: run.monitor,
        "current_project": lambda: run.program.id.split("/")[0] if run.program else "",
    }[name]()


def namespace(run: Run) -> dict:
    """The globals a script starts with."""
    ns = {name: globals()[name] for name in __all__ if name not in _CONTEXT}
    ns.update({name: _context(run, name) for name in _CONTEXT})
    return ns


def _prog():
    return current().need_program()


def _a(addr: Any) -> int:
    """An address argument: an int, an Address, a Function, or a symbol name."""
    if hasattr(addr, "entry") and hasattr(addr.entry, "offset"):
        return addr.entry.offset
    return current().resolve_address(addr)


# -- reads ---------------------------------------------------------------------


def to_addr(value: Any) -> int:
    """An address from an int, "0x401000", "401000h" or a symbol's name."""
    return _a(value)


def functions(name_contains: str = ""):
    """Every function (``listing_pb2.Function``), in address order."""
    return _prog().functions(name_contains)


def function_at(addr: AddressLike):
    """The function starting at ``addr``, or None."""
    from revkit.client import NotFound

    try:
        return _prog().function(_a(addr))
    except NotFound:
        return None


def function_containing(addr: AddressLike):
    """The function whose body holds ``addr``, or None."""
    from revkit.client import NotFound

    try:
        return _prog().function(_a(addr), containing=True)
    except NotFound:
        return None


def symbol_at(addr: AddressLike) -> str:
    """The effective name at ``addr`` ("" if none)."""
    from revkit.v1 import query_pb2

    a, prog = _a(addr), _prog()
    req = query_pb2.ListSymbolsRequest(program_id=prog.id, read=prog._read(), range=address_range(a, a))
    for s in prog._paged("ListSymbols", req, "symbols", 10):
        return s.name
    return ""


def preview(addr: AddressLike) -> dict:
    """What is at ``addr``, as the UI's hover card previews it (docs/ui.md
    "Hover cards"): a function's ``signature`` and first ``lines`` of C, else
    the listing's rows there (``kind`` "function" or "data"; ``name``)."""
    return _prog().preview(_a(addr))


def mangled_name(addr: AddressLike) -> str:
    """The mangled symbol the name at ``addr`` was demangled from ("" when the
    name isn't a demangled one; docs/demangle.md)."""
    return _prog().mangled_name(_a(addr))


def demangled_signature(addr: AddressLike) -> str:
    """The demangler's whole output for the name at ``addr``, parameters
    included ("geo::Shape::scale(double)"); "" when it isn't demangled."""
    d = _prog().demangled(_a(addr))
    return d.full if d is not None else ""


def image_base() -> int:
    """Where the program's image is now (its lowest loaded address)."""
    return _prog().image_base()


def set_image_base(base: int) -> None:
    """Moves the program to a new image base, with everything recorded about it
    (docs/memory-map.md, "Rebase"). Not buffered: it commits at once (the program
    reloads at the new base), and edits buffered before it are committed first."""
    from revkit.v1 import project_pb2

    run = current()
    if run.read_only:
        raise RuntimeError("set_image_base: this run is read-only")
    if len(run.edits):
        run.edits.commit()
    run.require_script_provenance()
    prog = run.need_program()
    req = project_pb2.SetImageBaseRequest(program_id=prog.id, image_base=int(base),
                                          provenance=run.provenance("set image base"))
    run.client._call(run.client.stubs.projects.SetImageBase, req)


def fid_matches() -> list:
    """Function ID's matches on the current program (docs/fid.md): each with ``entry``,
    ``name`` (what Function ID names it), ``status`` and ``candidates``."""
    return list(_prog().fid_matches().matches)


def run_fid() -> list:
    """Runs Function ID on the current program again and returns its matches."""
    return list(_prog().run_fid().matches)


def _fid_edit(what: str):
    run = current()
    if run.read_only:
        raise RuntimeError(f"{what}: this run is read-only")
    if len(run.edits):
        run.edits.commit()
    run.require_script_provenance()
    return run


def apply_fid(entry: AddressLike, name: str = "") -> None:
    """Names a function as one of its Function ID candidates (default the proposed name).
    Not buffered: it commits at once."""
    from revkit.v1 import analysis_pb2

    run = _fid_edit("apply_fid")
    req = analysis_pb2.ApplyFidMatchRequest(program_id=run.need_program().id, entry=_a(entry), name=name,
                                            provenance=run.provenance("Function ID match"))
    run.client._call(run.client.stubs.analysis.ApplyFidMatch, req)


def reject_fid(entry: AddressLike) -> None:
    """Rejects a function's Function ID match (its name goes, later runs leave it). Not
    buffered: it commits at once."""
    from revkit.v1 import analysis_pb2

    run = _fid_edit("reject_fid")
    req = analysis_pb2.RejectFidMatchRequest(program_id=run.need_program().id, entry=_a(entry),
                                             provenance=run.provenance("Function ID match rejected"))
    run.client._call(run.client.stubs.analysis.RejectFidMatch, req)


def decompile(func: Any, *, text: bool = True):
    """A function's decompilation (``.text``, ``.lines``, ``.variables``)."""
    return _prog().decompile(_a(func), text=text)


def decompile_many(funcs: Optional[Sequence[Any]] = None, *, text: bool = True, parallelism: int = 0):
    """Decompiles many functions (None: all) on the daemon's workers, yielding
    results as they complete (see Program.decompile_many)."""
    entries = None if funcs is None else [_a(f) for f in funcs]
    return _prog().decompile_many(entries, text=text, parallelism=parallelism)


def read_bytes(addr: AddressLike, length: int) -> bytes:
    """Initialized bytes at ``addr`` (fewer at the end of initialized memory)."""
    out, a = bytearray(), _a(addr)
    while length > 0:
        chunk = _prog().read_memory(a, min(length, 1 << 20))
        if not chunk:
            break
        out += chunk
        a += len(chunk)
        length -= len(chunk)
    return bytes(out)


def find_bytes(pattern, mask: Optional[bytes] = None, **kw) -> list:
    """Addresses of ``pattern`` ("48 8b ?? 05", or bytes and a mask)."""
    return _prog().find_bytes(pattern, mask, **kw)


class _MonitorCancel:
    """The run's monitor as the ``cancel`` a search polls (``is_set``)."""

    def __init__(self, monitor):
        self._m = monitor

    def is_set(self) -> bool:
        return self._m is not None and self._m.is_cancelled


def _cancel_event():
    run = current()
    return _MonitorCancel(run.monitor if run else None)


def search_memory(query: str, **kw) -> list:
    """Ghidra's Search Memory on the daemon: ``query`` as hex ("48 8b ?? e8"),
    or ``format="string"``, "decimal", "float", "double", "binary", "regex"
    (``Program.search_memory`` has every option). The run's monitor cancels
    it. Matches have ``.address``, ``.bytes``, ``.label``, ``.preview``."""
    return _prog().search_memory(query, cancel=_cancel_event(), **kw)


def search_text(query: str, **kw) -> list:
    """Ghidra's Search Program Text: what the listing shows (``fields``:
    comments, labels, functions, mnemonics, operands, data_mnemonics,
    data_values), plain or ``regex=True``. Matches have ``.address``,
    ``.field``, ``.text``, ``.match_start``, ``.match_length``."""
    return _prog().search_text(query, cancel=_cancel_event(), **kw)


def search_scalars(min=None, max=None, **kw) -> list:
    """Instructions and data using a constant: ``search_scalars(value=0x1000)``
    or a range ``search_scalars(0, 0xff)``. Matches have ``.address``,
    ``.value``, ``.text``, ``.operand_index``."""
    return _prog().search_scalars(min, max, cancel=_cancel_event(), **kw)


def search_decompiled(query: str, functions=None, **kw) -> list:
    """Decompiled C of every function (or ``functions``) searched on the
    daemon's decompiler workers, with the monitor's progress. Matches have
    ``.function``, ``.function_name``, ``.line``, ``.text``."""
    mon = current().monitor if current() else None

    def progress(m):
        if mon is not None and m.functions_total:
            if mon.maximum != m.functions_total:
                mon.set_max(m.functions_total)
            mon.set_progress(m.functions_done)

    funcs = None if functions is None else [_a(f) for f in functions]
    return _prog().search_decompiled(query, functions=funcs, progress=progress, cancel=_cancel_event(), **kw)


def strings(text_contains: str = "", *, min_length: int = 0):
    """The program's strings (``.address``, ``.value``, ``.xref_to_count``)."""
    return _prog().strings(text_contains, min_length=min_length)


def instructions(first: Optional[AddressLike] = None, last: Optional[AddressLike] = None, *, function=None,
                 pcode: bool = True):
    """Instructions with p-code in a range or a function's body."""
    return _prog().instructions(
        None if first is None else _a(first), None if last is None else _a(last),
        function=None if function is None else _a(function), pcode=pcode,
    )


def xrefs_to(addr: AddressLike) -> list:
    return _prog().xrefs_to(_a(addr))


def xrefs_from(addr: AddressLike) -> list:
    return _prog().xrefs_from(_a(addr))


# -- edits (buffered; one revision per run) -----------------------------------


def _target(addr: AddressLike) -> assertion_pb2.Target:
    return assertion_pb2.Target(address=address(_a(addr)))


def _local(function: AddressLike, storage_key: str) -> assertion_pb2.Target:
    return assertion_pb2.Target(local=assertion_pb2.LocalVariableRef(function=address(_a(function)), storage_key=storage_key))


def rename(addr: AddressLike, name: str) -> None:
    """Names a function, label or global."""
    a = _a(addr)
    current().edits.add(f"rename 0x{a:x} to {name!r}",
                        assertion_pb2.AssertionBody(rename=assertion_pb2.Rename(target=_target(a), name=name)))


def rename_local(function: AddressLike, storage_key: str, name: str) -> None:
    """Names a local variable by its storage key (``Decompile`` variables)."""
    current().edits.add(f"rename local {storage_key} to {name!r}", assertion_pb2.AssertionBody(
        rename=assertion_pb2.Rename(target=_local(function, storage_key), name=name)))


def retype(addr: AddressLike, c_declaration: str = "", *, type_hash: str = "") -> None:
    """Types a global or gives a function its prototype (a C declaration)."""
    spec = assertion_pb2.TypeSpec(type_hash=type_hash) if type_hash else assertion_pb2.TypeSpec(c_declaration=c_declaration)
    a = _a(addr)
    current().edits.add(f"retype 0x{a:x} as {c_declaration or type_hash!r}",
                        assertion_pb2.AssertionBody(retype=assertion_pb2.Retype(target=_target(a), type=spec)))


def retype_local(function: AddressLike, storage_key: str, c_declaration: str) -> None:
    current().edits.add(f"retype local {storage_key} as {c_declaration!r}", assertion_pb2.AssertionBody(
        retype=assertion_pb2.Retype(target=_local(function, storage_key), type=assertion_pb2.TypeSpec(c_declaration=c_declaration))))


def comment(addr: AddressLike, text: str, kind: str = "eol") -> None:
    """A comment: eol, pre, post, plate, repeatable or decompiler; "" deletes."""
    a = _a(addr)
    current().edits.add(f"{kind} comment at 0x{a:x}", assertion_pb2.AssertionBody(
        comment=assertion_pb2.Comment(address=address(a), kind=_COMMENT_KINDS[kind], text=text)))


def set_function(entry: AddressLike, body: Sequence[tuple] = (), isa: Optional[str] = None) -> None:
    """Declares a function at ``entry`` (``body``: inclusive ranges; empty: discovered; ``isa``: "arm",
    "thumb", or None for the mode the entry already has)."""
    a = _a(entry)
    from ..client import _INSTRUCTION_SETS, _choice
    b = assertion_pb2.SetFunctionBounds(entry=address(a), body=[address_range(*r) for r in body],
                                        instruction_set=_choice(_INSTRUCTION_SETS, isa, "isa"))
    current().edits.add(f"function at 0x{a:x}", assertion_pb2.AssertionBody(function_bounds=b))


def remove_function(entry: AddressLike) -> None:
    a = _a(entry)
    current().edits.add(f"remove function 0x{a:x}", assertion_pb2.AssertionBody(
        function_bounds=assertion_pb2.SetFunctionBounds(entry=address(a), remove=True)))


def flow_override(addr: AddressLike, kind: str) -> None:
    """none, branch, call, call_return or return."""
    a = _a(addr)
    current().edits.add(f"flow override {kind} at 0x{a:x}", assertion_pb2.AssertionBody(
        flow_override=assertion_pb2.FlowOverride(address=address(a), kind=_FLOW_OVERRIDES[kind])))


def note(addr: AddressLike, text: str, tag: str = "") -> None:
    """A note (a tagged annotation that is not a comment)."""
    a = _a(addr)
    current().edits.add(f"note {tag!r} at 0x{a:x}",
                        assertion_pb2.AssertionBody(note=assertion_pb2.Note(address=address(a), tag=tag, text=text)))


def define_type(c_source: str, keys: Optional[Sequence[str]] = None) -> list:
    """Parses C declarations for the program and defines their types (binding
    their names) with the run's edits. Returns the names it will define
    ("struct point"); retype with them after ``commit()``."""
    parsed = _prog().parse_c(c_source, name=f"{current().name}.h")
    if parsed.errors:
        raise ValueError("define_type: " + "; ".join(parsed.errors))
    bodies = header_import_bodies(parsed, keys, categories="none")
    names = [n.key for n in parsed.named if keys is None or n.key in keys]
    if bodies:
        current().edits.add(f"define {', '.join(names) or 'types'}", *bodies)
    return names


def define_data(addr: AddressLike, type: Optional[str] = None, *, count: int = 0, string: Optional[str] = None,
                layout: Optional[str] = None, collapsed: Optional[bool] = None, type_hash: Optional[str] = None) -> None:
    """Defines data at ``addr``: ``type`` (C such as "uint32_t" or "struct hdr",
    or a builtin name such as "dword"; or ``type_hash``), an array of ``count``
    of them, or a string (``string`` "utf8", "utf16" or "utf32"; ``layout``
    "terminated", "fixed" (``count`` characters), "pascal" or "pascal16")."""
    a = _a(addr)
    body = define_data_body(a, type, count=count, string=string, layout=layout, collapsed=collapsed,
                            type_hash=type_hash)
    what = f"{string} string" if string else (type or type_hash)
    current().edits.add(f"define {what}{f'[{count}]' if count and not string else ''} at 0x{a:x}", body)


def clear(addr: AddressLike, length: int = 1) -> None:
    """Clears [addr, addr + length) back to undefined bytes (Ghidra's Clear Code Bytes)."""
    a = _a(addr)
    current().edits.add(f"clear 0x{a:x}..0x{a + int(length):x}", clear_code_body(a, length))


def disassemble(addr: AddressLike, isa: Optional[str] = None, function: bool = False) -> None:
    """Disassembles from ``addr`` (``isa``: None, "arm" or "thumb");
    ``function=True`` also makes it a function."""
    a = _a(addr)
    current().edits.add(f"disassemble at 0x{a:x}", disassemble_body(a, isa, function))


def set_mutability(addr: AddressLike, length: int, mutability: str) -> None:
    """Marks [addr, addr + length) "constant", "volatile", "normal" or "default"."""
    a = _a(addr)
    current().edits.add(f"{mutability} 0x{a:x}..0x{a + int(length):x}", mutability_body(a, length, mutability))


_STRUCT_NAMES: dict = {}  # run id -> names this run's buffered structures took


def _new_structure(make, name: str):
    """``make(name)``'s structure, under a name no buffered edit of this run
    has taken either (the daemon only knows the committed ones)."""
    from revkit.client import RevkitError

    taken = _STRUCT_NAMES.setdefault(current().id, set())
    made = make(name)
    i = 1
    while not name and made.name in taken and i < 1000:
        try:
            made = make(f"astruct_{i}")
        except RevkitError:  # committed under that name: the next
            pass
        i += 1
    taken.add(made.name)
    return made


def auto_create_structure(function: AddressLike, storage_key: str, *, call_depth: Optional[int] = None,
                          name: str = "") -> str:
    """Ghidra's Auto Create Structure: a structure from how the variable
    (``storage_key`` from ``decompile``) is used as a pointer, here and
    ``call_depth`` calls deep (default 1), defined and bound by name, and the
    variable retyped to a pointer to it. Returns the structure's name."""
    f = _a(function)
    made = _new_structure(lambda n: _prog().auto_structure(f, storage_key, call_depth=call_depth, name=n), name)
    if made.unchanged:
        return made.name
    current().edits.add(f"create struct {made.name} from {storage_key} at 0x{f:x}",
                        *auto_structure_bodies(made, function=f, storage_key=storage_key))
    return made.name


def auto_fill_structure(function: AddressLike, storage_key: str, *, call_depth: Optional[int] = None) -> str:
    """Ghidra's Auto Fill in Structure: fields added to the structure the
    variable points to where its use shows some and it has none. Returns the
    structure's name."""
    f = _a(function)
    made = _prog().auto_structure(f, storage_key, fill=True, call_depth=call_depth)
    if not made.unchanged:
        current().edits.add(f"fill in struct {made.name} from {storage_key} at 0x{f:x}",
                            *auto_structure_bodies(made, function=f, storage_key=storage_key))
    return made.name


def create_structure(first: AddressLike, last: AddressLike, *, name: str = "") -> str:
    """Create Structure from a selection: a structure of the data defined in
    [first, last] (undefined filler elsewhere), defined at ``first``. Returns
    its name."""
    a, b = _a(first), _a(last)
    made = _new_structure(lambda n: _prog().structure_from_range(a, b, name=n), name)
    current().edits.add(f"create struct {made.name} at 0x{a:x}..0x{b:x}", *auto_structure_bodies(made, at=a))
    return made.name


def export_type_archive(directory: Optional[str] = None, *, keys: Sequence[str] = (), category: str = "",
                        scope: str = "", name: str = ""):
    """The program's types as a type archive (a C header and a JSON sidecar
    of hashes, categories and the data model): ``keys`` ("struct hdr"), a
    ``category`` and below, or ``scope`` "user" (the default: made, edited or
    imported in revkit) or "all". With ``directory`` both files are written
    there. Returns the response (``.header``, ``.sidecar``, ``.notes``)."""
    return _prog().export_type_archive(keys, scope=scope, category=category, name=name, directory=directory)


def import_type_archive(header_path: str, sidecar_path: Optional[str] = None) -> list:
    """Imports a type archive (``<name>.h`` and, beside it unless given,
    ``<name>.json``) with the run's edits: checked against the sidecar's
    hashes, its types defined and bound where the program lacks them, filed
    under its categories. Returns the names it defines or rebinds."""
    import os

    with open(header_path, encoding="utf-8", newline="") as f:
        header = f.read()
    with open(sidecar_path or os.path.splitext(header_path)[0] + ".json", encoding="utf-8") as f:
        sidecar = f.read()
    parsed = _prog().parse_type_archive(header, sidecar, name=os.path.basename(header_path))
    if parsed.archive.mismatches:
        raise ValueError(f"import_type_archive: {len(parsed.archive.mismatches)} type(s) don't parse to the "
                         f"sidecar's hashes ({', '.join(m.key for m in list(parsed.archive.mismatches)[:5])})")
    bodies = header_import_bodies(parsed, include_library=True, categories="all")
    names = [n.key for n in parsed.named if n.existing_hash != n.hash or n.existing_library]
    if bodies:
        current().edits.add(f"import type archive {parsed.archive.name}", *bodies)
    return names


def set_type_category(keys: Any, path: str) -> None:
    """Files named types ("struct hdr", or a list of them) under a category
    ("/net/http"; "/" the top)."""
    keys = [keys] if isinstance(keys, str) else list(keys)
    current().edits.add(f"file {', '.join(keys)} under {path or '/'}", *(type_category_body(k, path) for k in keys))


def move_types_to_project(keys: Any) -> list:
    """Moves named types ("struct hdr", or a list) to project scope, where
    every program of the project sees them (now, not with the run's edits).
    Returns the keys moved."""
    keys = [keys] if isinstance(keys, str) else list(keys)
    return [t.key for t in _prog().move_types_to_project(keys, reason="script").types]


def copy_types_to_program(keys: Any) -> list:
    """Copies project types into this program (now): its copy then wins over
    the project's. Returns the keys copied."""
    keys = [keys] if isinstance(keys, str) else list(keys)
    return [t.key for t in _prog().copy_types_to_program(keys, reason="script").types]


def type_archives() -> list:
    """The type archives of the program's project: [{"name", "kind",
    "enabled", "applies", "functions", "types"}]."""
    from revkit.v1 import types_pb2

    return [{"name": a.name, "kind": types_pb2.TypeArchiveKind.Name(a.kind).removeprefix("TYPE_ARCHIVE_KIND_").lower(),
             "enabled": a.enabled, "applies": a.applies, "functions": a.functions, "types": a.types}
            for a in _prog().type_archives()]


def set_type_archive_enabled(name: str, enabled: bool) -> None:
    """Turns a type archive ("libc-lp64", "ghidra", an attached one) on or
    off for every program of the project, with the run's edits."""
    from revkit.v1 import assertion_pb2

    body = assertion_pb2.AssertionBody(type_archive=assertion_pb2.TypeArchiveSetting(name=name, enabled=enabled))
    current().edits.add(f"type archive {name} {'on' if enabled else 'off'}", body)


def type_categories() -> dict:
    """Every category the program files a named type under: path -> how many
    types are directly in it ("/": those with none)."""
    return _prog().type_categories()


# -- equates and user references (api_minor 39, features "equates", "user-references") --


def convert(addr: AddressLike, value, format: str, *, operand: Optional[int] = None,
            apply_to: Optional[str] = None, constant_hash: int = 0) -> None:
    """Shows the scalar ``value`` at the instruction ``addr`` as Ghidra's
    Convert does: "hex", "signed", "unsigned", "octal", "binary", "char",
    "float" ("default": as the disassembler prints it)."""
    a = _a(addr)
    current().edits.add(f"convert {value!r} at 0x{a:x} to {format}",
                        operand_display_body(a, value, operand=operand, format=format or "default",
                                             constant_hash=constant_hash, apply_to=apply_to))


def set_equate(addr: AddressLike, value, name: str, *, operand: Optional[int] = None, apply_to: Optional[str] = None,
               constant_hash: int = 0) -> None:
    """Shows the scalar ``value`` at the instruction ``addr`` as ``name``
    (Set Equate); ``apply_to`` "function" or "program" names every operand
    holding the value there too."""
    a = _a(addr)
    current().edits.add(f"equate {name} at 0x{a:x}", operand_display_body(
        a, value, operand=operand, equate=name, constant_hash=constant_hash, apply_to=apply_to))


def set_enum_equate(addr: AddressLike, value, enum: str, member: str, *, operand: Optional[int] = None,
                    apply_to: Optional[str] = None, constant_hash: int = 0) -> None:
    """Shows the scalar as an enum's member (``enum`` by name or type hash)."""
    a = _a(addr)
    current().edits.add(f"{enum}.{member} at 0x{a:x}", operand_display_body(
        a, value, operand=operand, enum=_prog().enum_hash(enum), member=member, constant_hash=constant_hash,
        apply_to=apply_to))


def clear_display(addr: AddressLike, value, *, operand: Optional[int] = None, constant_hash: int = 0) -> None:
    """The scalar shows as the disassembler prints it again (a conversion or
    an equate cleared)."""
    a = _a(addr)
    current().edits.add(f"clear the display at 0x{a:x}",
                        operand_display_body(a, value, operand=operand, constant_hash=constant_hash))


def equates() -> dict:
    """The equates table as committed: {name: Equate(name, value,
    references, ...)} (edits still buffered aren't in it)."""
    return _prog().equates()


def rename_equate(old: str, new: str) -> None:
    """Renames an equate at every operand that shows it (as committed)."""
    current().edits.add(f"rename equate {old} to {new}", *rename_equate_bodies(_prog().equates(), old, new))


def remove_equate(name: str) -> None:
    """Removes an equate everywhere (as committed): its operands show the
    disassembler's text again."""
    current().edits.add(f"remove equate {name}", *remove_equate_bodies(_prog().equates(), name))


def enums_with_value(value, *, program_only: bool = False) -> list:
    """Enums with a member of this value, the program's first."""
    return _prog().enums_with_value(value, program_only=program_only)


def add_reference(from_: AddressLike, to: AddressLike, type: str = "data", *, operand: Optional[int] = None,
                  primary: bool = False) -> None:
    """Adds a reference from the instruction at ``from_`` to ``to``: "data",
    "read", "write", "call", "jump", "computed_call" or "computed_jump", on
    ``operand`` (None: the instruction as a whole)."""
    f, t = _a(from_), _a(to)
    current().edits.add(f"{type} reference 0x{f:x} -> 0x{t:x}",
                        reference_body(f, t, type, operand=operand, primary=primary))


def remove_reference(from_: AddressLike, to: AddressLike, *, operand: Optional[int] = None) -> None:
    """Deletes the references from ``from_`` to ``to``: the user's (as
    committed) and analysis's."""
    f, t = _a(from_), _a(to)
    current().edits.add(f"remove references 0x{f:x} -> 0x{t:x}", *_prog().remove_reference_bodies(f, t, operand))


def set_primary_reference(from_: AddressLike, to: AddressLike, *, operand: Optional[int] = None,
                          type: Optional[str] = None, primary: bool = True) -> None:
    """Makes the (committed) reference from ``from_`` to ``to`` its
    operand's primary one, or not."""
    f, t = _a(from_), _a(to)
    current().edits.add(f"primary reference 0x{f:x} -> 0x{t:x}", _prog().primary_reference_body(
        f, t, operand=operand, type=type, primary=primary))


def commit(reason: str = ""):
    """Commits the buffered edits now (one revision); None when there are none."""
    return current().edits.commit(reason)


def pending_edits() -> int:
    """How many edits are buffered."""
    return len(current().edits)


def revert(session: str = "", *, dry_run: bool = False):
    """Undoes a run's committed edits in one revision (default: this run's)."""
    run = current()
    return run.need_program().revert(session=session or run.id, dry_run=dry_run)


# -- the project (api_minor 37: features project-folders, project-archive) -----


def _project(project: str) -> str:
    if project:
        return project
    run = current()
    if run.program is None:
        raise RuntimeError("this run has no program: name the project")
    return run.program.id.split("/")[0]


class _AsRun:
    """The run's client, writing with the run's provenance for one call."""

    def __enter__(self):
        run = current()
        if run.client is None:
            raise RuntimeError("this run has no daemon")
        self.client, self.saved = run.client, run.client.provenance
        run.client.provenance = run.provenance()
        return run.client

    def __exit__(self, *exc):
        self.client.provenance = self.saved


def project_programs(project: str = ""):
    """The project's programs (``ProgramInfo``: ``program_id``, ``name``, ``folder_path``)."""
    return list(current().client.programs(_project(project)))


def folders(project: str = ""):
    """The project's folders (``ProjectFolder``: ``path``, ``folder_id``), parents first."""
    return list(current().client.folders(_project(project)))


def create_folder(path: str, *, project: str = "", parents: bool = True) -> str:
    """Creates the folder at ``path`` ("/libs/json"; with ``parents``, the
    missing ones above it too) and returns its id; an existing one's id."""
    with _AsRun() as client:
        p = _project(project)
        if parents:
            return client.folder_id(p, path, create=True)
        return client.create_folder(p, path).folder.folder_id


def rename_folder(folder: str, name: str, *, project: str = ""):
    """Renames a folder (its id or path)."""
    with _AsRun() as client:
        return client.rename_folder(_project(project), folder, name)


def move_to_folder(folder: str, *, programs: Sequence[str] = (), folders: Sequence[str] = (), project: str = ""):
    """Moves programs (ids) and folders (ids or paths) into ``folder`` ("/" the root)."""
    with _AsRun() as client:
        return client.move_to_folder(_project(project), folder, programs=programs, folders=folders)


def delete_folder(folder: str, *, project: str = ""):
    """Deletes an empty folder."""
    with _AsRun() as client:
        return client.delete_folder(_project(project), folder)


def export_project(path: str, *, programs: Sequence[str] = (), folders: Sequence[str] = (),
                   annotations_only: bool = False, project: str = ""):
    """Writes a .rkproj archive of the project (or of ``programs`` and
    ``folders``) to ``path``; returns its ``ExportSummary``."""
    return current().client.export_project(_project(project), path, programs=programs, folders=folders,
                                           annotations_only=annotations_only)


# -- file systems (api_minor 48) ------------------------------------------------


def open_filesystem(*, host_path: str = "", program_id: str = "", file: Any = None, project: str = "",
                    limits: Optional[dict] = None):
    """Opens a container as a ``FileSystem`` (``list``, ``entries``, ``walk``,
    ``read``, ``info``, ``extract``, ``close``; use it with ``with``): a
    program's stored file (``program_id``; default the current program's when
    nothing else is named), a file or directory on the daemon's host
    (``host_path``) or local bytes or a path (``file``)."""
    run = current()
    if run.client is None:
        raise RuntimeError("this run has no daemon")
    if not host_path and not program_id and file is None:
        program_id = run.program.id if run.program else ""
    return run.client.open_filesystem(_project(project), host_path=host_path, program_id=program_id, file=file,
                                      limits=limits)


def import_from_filesystem(fs, paths: Any = "/", **options):
    """Imports files from an open ``FileSystem`` as programs, with the run's
    provenance; ``options`` are ``FileSystem.import_``'s (``recursive``,
    ``descend``, ``programs_only``, ``detect_raw``, ``preview``,
    ``max_programs``, ``folder``, ``keep_folders``, ``analyze``)."""
    with _AsRun():
        return fs.import_(paths, **options)


# -- prompts ------------------------------------------------------------------


def ask_string(name: str, message: str = "", default: Optional[str] = None) -> str:
    return current().ask("string", name, message, default)


def ask_int(name: str, message: str = "", default: Optional[int] = None) -> int:
    return current().ask("int", name, message, default)


def ask_float(name: str, message: str = "", default: Optional[float] = None) -> float:
    return current().ask("float", name, message, default)


def ask_address(name: str, message: str = "", default: Optional[Any] = None) -> int:
    """An address: hex, decimal or a symbol's name."""
    return current().ask("address", name, message, default)


def ask_yes_no(name: str, message: str = "", default: Optional[bool] = None) -> bool:
    return current().ask("yes_no", name, message, default)


def ask_choice(name: str, message: str, choices: Sequence, default: Any = None):
    return current().ask("choice", name, message, default, choices)


def ask_choices(name: str, message: str, choices: Sequence, default: Optional[Sequence] = None) -> list:
    return current().ask("choices", name, message, None if default is None else list(default), choices)


def ask_file(name: str, message: str = "", default: Optional[str] = None) -> str:
    return current().ask("file", name, message, default)


def ask_values(fields: dict, message: str = "") -> dict:
    """Several answers at once: ``{"min_len": 4, "prefix": "sub_"}`` asks each
    by name with that default (its type picks the kind)."""
    out = {}
    for name, default in fields.items():
        kind = {bool: "yes_no", int: "int", float: "float"}.get(type(default), "string")
        out[name] = current().ask(kind, name, f"{message}: {name}" if message else name, default)
    return out


# -- output -------------------------------------------------------------------


def log(*parts: Any) -> None:
    """A line for the run's log (stderr headless)."""
    current().host.output(" ".join(str(p) for p in parts) + "\n", "stderr")
