"""An MCP server that lets AI agents read and annotate programs through rk-daemon.

Built only on the public Python SDK, like any other client. Read tools cover
programs, functions, symbols, strings and data, memory, disassembly,
decompilation, control-flow graphs, callers and callees, xrefs, types,
plugins and blame. Write tools cover names, types and prototypes, comments,
notes, functions, flow overrides and plugin commands. Program comparison
(matching, what changed, porting names), patching (assembling, byte patches,
export with checksum fixups), emulation and debugging have their own tool
groups. Every write is an assertion with AGENT
provenance (``agent:<name>@<version>``), tagged with this server's session
and the agent's stated reason, so a user can see who changed what (Blame)
and undo an agent's whole run in one call (RevertByProvenance). The server
cannot write as a user.

    revkit-mcp --daemon 127.0.0.1:50051 --agent claude --agent-version opus-5.5

Against a daemon with authentication (docs/security.md), give it an agent
token, which the daemon stamps on every edit as agent:<token name>, and say
how to trust the daemon's certificate:

    rk-daemon token create --name claude --role editor     # prints the token
    RK_TOKEN=rkt_... revkit-mcp --daemon host:50051 --fingerprint AB:CD:...

Configuration may also come from RK_GRPC, RK_AGENT, RK_AGENT_VERSION,
RK_SESSION, RK_TOKEN (or RK_TOKEN_FILE), RK_TLS_CA, RK_TLS_FINGERPRINT and
RK_TLS=1. Requires the ``mcp`` extra (``pip install 'revkit[mcp]'``).
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import sys
import uuid
from typing import Optional, Union

from mcp.server.mcpserver import MCPServer
from mcp_types import ToolAnnotations

from google.protobuf.json_format import MessageToDict

from revkit import (Client, RevkitError, __version__, debug_stop_kind, detect_confidence, format_memory_region, format_provenance,
                    patching, provenance)
from revkit.expr import ExprError, is_number, parse_number
from revkit.v1 import assertion_pb2, auth_pb2, bsim_pb2, decompile_pb2, diff_pb2, filesystem_pb2, listing_pb2, patch_pb2, project_pb2, query_pb2, types_pb2

READ = ToolAnnotations(read_only_hint=True, open_world_hint=False)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False)

WORKFLOW = """\
1. list_programs: the projects and their programs; every program tool takes a program_id from it.
2. program_summary (language, entry points, memory) and overview (where code, data, undefined bytes and
   high-entropy (packed or encrypted) regions are).
3. Find what matters: list_functions (filters: named, unnamed, thunks; paged), search_symbols, list_strings,
   search_strings (substring or regex over the strings), search_text (the listing), search_memory (bytes), search_scalars (constants), search_decompiled (the C),
   find_next (the next function, label, data, undefined bytes, note).
4. Read: decompile (paged by line), disassemble (paged by row), function_graph, xrefs, callers, callees,
   get_type, find_type_uses (where a struct or one field is read and written), slice_decompiled (where a
   variable's value comes from or flows to).
5. Record what you learn, each edit with a short, specific reason: rename (functions, labels, globals),
   rename_variable / retype_variable (from decompile's variables), retype (globals, prototypes),
   rename_field / retype_field (a struct's fields), parse_c + import_header (new types), set_comment,
   add_note, set_equate, override_call_signature (one call's prototype: a varargs call's arguments).
6. Search again with the new names, and decompile the callers: names and types propagate.
Every edit is attributed to you (agent provenance, with your reason; blame shows who set what), a human's
edit outranks yours, and everything is undoable: undo_changes with a result's seqs, or revert_my_changes for
the whole session (list_my_changes reviews them)."""

ADDRESSES = """\
Addresses are hex strings: "0x401040", or "401040" as the listing prints them (bare numbers are hex). Any
address argument also takes a symbol name ("main", a demangled "ns::Class::method" or its mangled
spelling) or a Go To expression: "main+0x10", "tbl + 4*8", "(end - start) / 2", a file offset
"file:0x200", an address in another memory space "mem:0x100". The emulator, debug and diff_* tools, which
have no program to look names up in, take hex numbers only. Results give addresses as "0x..." strings.
Sizes, lengths and values are decimal or 0x hex."""

PAGING = """\
Long results come a page at a time: a result with "truncated": true says in "more" how to get the next
page (offset, start_line, start), so ask for more only when you need it."""

INSTRUCTIONS = f"""\
Tools for reverse engineering with revkit. Call about for the workflow and what this daemon can do.

{WORKFLOW}

{ADDRESSES}

{PAGING}

C++ (and Rust, D) names are demangled ("std::vector<int>::push_back"), and searches find the mangled
spelling too. preview shows what is at an address (a function's signature and first lines of C, or the
listing there); describe_value spells a constant (hex, decimal, char) and names the symbol it points at.
set_image_base moves a program whose base was guessed wrong, with all its work. fid_matches lists the
statically linked library functions Function ID named (MSVC runtime, attached libraries). memory_map
shows a program's memory; add_memory_region maps RAM, memory-mapped I/O or another file's bytes the code
refers to (firmware loaded as raw bytes knows only its image). Where analysis got the listing wrong,
clear_code, disassemble_here and define_data say what bytes are, and set_mutability marks memory constant
or volatile for the decompiler; set_data_settings shows a data item (or every item of a type) in decimal,
another charset or byte order; set_fallthrough sends flow on past inline data after a call. set_equate names a constant (O_RDONLY, an enum member) and convert_operand
shows it as a char or decimal, in the listing and the decompiler; add_reference adds a reference analysis
missed (an indirect call's target) and remove_reference deletes a wrong one. To give a program structs and
other types, parse_c checks C declarations (a header, a struct you write) and import_header makes them the
program's; then retype with them. auto_structure builds a struct from how a pointer is used.
export_type_archive and import_type_archive carry types between programs (a C header plus a JSON sidecar
of hashes); set_type_category files types in folders. compare_programs and the diff_* tools match two
programs' functions and show what changed; compare_functions compares any two functions (one program or
two) and port_function_markup carries a name, signature, variable names and types and comments from one to
the other (diff_port_function does it through a comparison's match); emu_* runs code in the emulator (firmware with interrupts and
peripherals on a machine: emu_start's machine or derive_machine, then emu_machine and emu_input); debug_*
drives a debug session. Emulator and debug sessions are yours alone and assert nothing: close them when
done. To change code, try assemble first (it writes nothing), then patch_instruction or patch_bytes: a
patch is an edit like any other (listed, blamed, reverted), every view shows the program as patched, and
export_patched gives the file with its checksums fixed. For a file that is not ELF or PE (raw firmware),
detect_raw_layout suggests the language, load address and header offset for import_program; rely only on
answers it gives at high confidence, and ask the user about the rest. list_scripts shows the Python
scripts the daemon can run (shipped, the user's, the project's) and run_script runs one on a program (its
edits are one revision, revertable as a whole); a script the user has not confirmed comes back with its
source and sha256: show it to the user and pass confirm_sha256 only if they agree."""


def _addr(value) -> int:
    """A plain address, where no program is at hand to look names up in (an
    emulator or debug session, a comparison): hex, "0x401040" or "401040"."""
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not is_number(text):
        raise ValueError(f"not an address: {value!r} (give a hex number such as \"0x401040\")")
    return parse_number(text)


def _num(value) -> int:
    """A size, offset or value: decimal or 0x hex."""
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip(), 0)
    except ValueError:
        raise ValueError(f"not a number: {value!r} (decimal, or hex with 0x)") from None


def _hex(offset: int) -> str:
    return f"0x{offset:x}"


def _more(hint: str, **page) -> dict:
    """What a paged result adds when there is more: the next page's arguments and a sentence saying so."""
    return {"truncated": True, **page, "more": hint}


def _address(value):
    from revkit import address
    return address(_addr(value))


def _origin(o) -> str:
    if o.HasField("asserted"):
        return format_provenance(o.asserted.provenance)
    if o.HasField("derived"):
        return f"derived:{o.derived.rule}"
    return ""


_DROP = {"snapshot", "page", "origin", "name_origin", "type_origin", "prototype_origin"}


def _tidy(v):
    """A message's dict, as a model reads it: addresses as hex strings, enum
    prefixes gone, bytes as hex, and paging/origin bookkeeping dropped."""
    if isinstance(v, dict):
        if v and set(v) <= {"offset", "space"} and "offset" in v:
            text = _hex(int(v["offset"]))
            return f"{v['space']}:{text}" if v.get("space") else text
        return {k: _tidy(x) for k, x in v.items() if k not in _DROP}
    if isinstance(v, list):
        return [_tidy(x) for x in v]
    return v


def _d(message, **kw) -> dict:
    return _tidy(MessageToDict(message, preserving_proto_field_name=True, **kw))


def _dump(data: bytes, base: int) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:08x}  {chunk.hex(' '):<47}  {text}")
    return "\n".join(lines)


def _hex_bytes(text: str) -> bytes:
    """Bytes from hex as people write it: "e3500009", "e3 50 00 09", "0xe3,0x50"."""
    digits = "".join(part.removeprefix("0x").removeprefix("0X") for part in text.replace(",", " ").split())
    try:
        return bytes.fromhex(digits)
    except ValueError:
        raise ValueError(f"not hex bytes: {text!r}") from None


_ALGORITHM_NAMES = {v: k for k, v in patching.ALGORITHMS.items()}


def _checksum_spec(spec: patch_pb2.ChecksumSpec) -> dict:
    """A checksum rule as a model reads it, and as export_patched's fixups take it back."""
    out = {"algorithm": _ALGORITHM_NAMES.get(spec.algorithm, str(spec.algorithm)), "start": _hex(spec.start), "end": spec.end}
    if spec.skip_padding:
        out["skip_padding"] = True
    if spec.field:
        out.update(field_offset=_hex(spec.field_offset), field_width=spec.field_width, big_endian=spec.field_big_endian)
    if spec.name:
        out["name"] = True
    return out


def _fixup(d: dict) -> patch_pb2.ExportFixup:
    """An export fixup from a tool argument: {"pe_checksum": true}, or a checksum rule (_checksum_spec)."""
    known = {"pe_checksum", "algorithm", "start", "end", "skip_padding", "field_offset", "field_width", "big_endian", "name"}
    if not isinstance(d, dict) or set(d) - known:
        raise ValueError(f"a fixup is {{\"pe_checksum\": true}} or a checksum rule with keys from {sorted(known - {'pe_checksum'})}")
    if d.get("pe_checksum"):
        return patching.pe_checksum()
    if "algorithm" not in d:
        raise ValueError("a checksum fixup needs an algorithm (such as \"sum32\" or \"crc32\")")
    in_name = bool(d.get("name"))
    if in_name == ("field_offset" in d):
        raise ValueError("a checksum fixup goes either into the file (field_offset) or into its name (name: true)")
    spec = patch_pb2.ChecksumSpec(algorithm=patching.algorithm(d["algorithm"]), start=_num(d.get("start", 0)),
                                  end=_num(d.get("end", 0)), skip_padding=bool(d.get("skip_padding")), name=in_name)
    if not in_name:
        spec.field = True
        spec.field_offset = _num(d["field_offset"])
        spec.field_width = int(d.get("field_width", 4))
        spec.field_big_endian = bool(d.get("big_endian"))
    return patch_pb2.ExportFixup(checksum=spec)


# What one result may hold (its JSON, as the client gets it): an agent's context
# is precious, and clients cut longer tool results off (Claude Code at 25k tokens).
RESULT_BUDGET = 50_000


def _size(v) -> int:
    return len(json.dumps(v, indent=2, default=str))


def _fit(out: dict, budget: int = RESULT_BUDGET) -> dict:
    """A result cut to the budget: its longest list shortened (with "truncated", and
    "next_offset" where the tool pages by offset), else its longest text."""
    if _size(out) <= budget:
        return out
    lists = [(k, v) for k, v in out.items() if isinstance(v, list) and v]
    if lists:
        key, items = max(lists, key=lambda kv: _size(kv[1]))
        lo, hi = 0, len(items)
        while lo < hi:  # the most items that fit
            mid = (lo + hi + 1) // 2
            if _size({**out, key: items[:mid]}) + 200 <= budget:
                lo = mid
            else:
                hi = mid - 1
        if lo < len(items):
            out = {**out, key: items[:lo], "truncated": True}
            if isinstance(out.get("offset"), int):
                out["next_offset"] = out["offset"] + lo
                out["more"] = (f"{lo} of the {len(items)} {key} fit in one result: call again with offset="
                               f"{out['next_offset']} for the next")
            elif key == "matches" and "functions_searched" not in out and lo and isinstance(items[lo - 1], dict):
                out["more"] = (f"{lo} of the {len(items)} matches fit in one result: call again with start="
                               f"{items[lo - 1].get('address')} for the ones after them")
            else:
                out["more"] = (f"{lo} of the {len(items)} {key} fit in one result: narrow the query (a filter, an "
                               "address range, a smaller limit)")
            if _size(out) <= budget:
                return out
    texts = [(k, v) for k, v in out.items() if isinstance(v, str)]
    if texts:
        key, text = max(texts, key=lambda kv: len(kv[1]))
        over = _size(out) - budget + 200
        if over > 0 and len(text) > over:
            out = {**out, key: text[: len(text) - over] + f"\n...[{over} characters cut]", "truncated": True}
    return out


def create_server(
    target: str = "127.0.0.1:50051",
    agent: Optional[str] = None,
    agent_version: str = "",
    session: Optional[str] = None,
    *,
    token: Optional[str] = None,
    tls: Optional[bool] = None,
    ca_cert: Optional[str] = None,
    fingerprint: Optional[str] = None,
    server_name: Optional[str] = None,
) -> MCPServer:
    """Builds the MCP server. All writes use ``agent:<agent>[@<agent_version>]``.

    With a token (``token`` or RK_TOKEN) the daemon stamps the token's
    identity, so ``agent`` defaults to the agent token's name (and must equal
    it if given). A user's token can read, but the daemon refuses its agent
    edits: issue an agent token (rk-daemon token create --name ...).
    """
    session = session or f"mcp-{uuid.uuid4().hex[:12]}"
    rk = Client(target, actor="", session=session, token=token, tls=tls, ca_cert=ca_cert, fingerprint=fingerprint,
                server_name=server_name)
    if rk.token:
        who = rk.whoami()
        if who.auth_enabled and who.HasField("identity"):
            ident = who.identity
            if ident.kind == auth_pb2.PRINCIPAL_KIND_AGENT:
                if agent and agent != ident.name:
                    rk.close()
                    raise ValueError(f"the token is agent:{ident.name}; the daemon would refuse edits as agent:{agent}")
                agent = ident.name
            else:
                print(f"revkit-mcp: the token is {ident.name!r}'s, not an agent's; the daemon will refuse this "
                      "server's edits (issue one with rk-daemon token create --name <agent> --role editor)",
                      file=sys.stderr)
        elif who.auth_enabled:
            print("revkit-mcp: the daemon does not accept the token", file=sys.stderr)
    agent = agent or "mcp"
    if ":" in agent or "@" in agent:
        rk.close()
        raise ValueError("agent must be a bare name such as 'claude'")
    rk.provenance = provenance(f"agent:{agent}" + (f"@{agent_version}" if agent_version else ""), session=session)
    server = MCPServer("revkit", instructions=INSTRUCTIONS, version=__version__)

    def guarded(fn):
        # Report API errors to the model as text it can act on, not a crash.
        # functools.wraps keeps the signature MCP derives the tool schema from.
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                out = fn(*args, **kwargs)
            except RevkitError as e:
                return {"error": e.code.name, "message": e.message}
            except ValueError as e:  # an argument that is not an address, hex bytes or a known name
                return {"error": "INVALID_ARGUMENT", "message": str(e)}
            except KeyError as e:  # a kind, direction or format the tool doesn't know
                return {"error": "INVALID_ARGUMENT", "message": f"unknown value {e} (the tool's description lists the choices)"}
            except Exception as e:  # anything else, as text rather than a traceback
                return {"error": "INTERNAL", "message": f"{type(e).__name__}: {e}"}
            return _fit(out) if isinstance(out, dict) else out

        return wrapper

    def at(program_id: str, value) -> int:
        """An address argument: a number, a symbol or a Go To expression (ADDRESSES), in a program."""
        if value is None or (isinstance(value, str) and not value.strip()):
            raise ValueError("an address is required")
        try:
            return rk.program(program_id).resolve(value)
        except ExprError as e:
            raise ValueError(f"address {value!r}: {e}") from None

    def write_result(resp: assertion_pb2.AppendAssertionsResponse) -> dict:
        a = resp.assertions[0]
        return {
            "ok": True,
            "seq": a.seq,
            "revision": resp.snapshot.revision,
            "status": assertion_pb2.AssertionStatus.Name(a.status),
            "provenance": format_provenance(a.provenance),
            "note": "SHADOWED means a higher-precedence (e.g. human) assertion still wins" if a.status == assertion_pb2.ASSERTION_STATUS_SHADOWED else "",
        }

    # -- reads -------------------------------------------------------------------

    @server.tool(annotations=READ)
    @guarded
    def about() -> dict:
        """Start here: how to work with these tools (the workflow, how to give addresses, how long results
        page), who your edits are recorded as, and what this daemon can do (its version and features)."""
        info = rk.server_info()
        out = {
            "workflow": WORKFLOW.splitlines(),
            "addresses": " ".join(ADDRESSES.split()),
            "paging": " ".join(PAGING.split()),
            "you": {"edits_recorded_as": format_provenance(rk.provenance), "session": session,
                    "undo": "undo_changes(seqs) for one edit, revert_my_changes for this whole session"},
            "daemon": {"server_version": info.server_version, "api": f"{info.api_major}.{info.api_minor}",
                       "features": sorted(info.features)},
            "mcp_server": __version__,
        }
        if rk.token:
            who = rk.whoami()
            if who.auth_enabled and who.HasField("identity"):
                out["you"]["token"] = who.identity.name
        return out

    @server.tool(annotations=READ)
    @guarded
    def list_programs() -> dict:
        """Projects and the programs in them (use a program_id with the other tools),
        with each program's folder and the project's folders."""
        out = []
        for p in rk.projects():
            if not p.open:
                continue
            listed = rk._call(rk.stubs.projects.ListPrograms, project_pb2.ListProgramsRequest(project_id=p.project_id))
            out.append(
                {
                    "project_id": p.project_id,
                    "head_revision": p.head_revision,
                    "programs": [
                        {"program_id": g.program_id, "name": g.name, "format": g.format, "language": g.language_id,
                         "folder": g.folder_path or "/"}
                        for g in listed.programs
                    ],
                    "folders": [f.path for f in listed.folders],
                }
            )
        return {"projects": out}

    # -- the project: folders and archives (api_minor 37) ---------------------------

    class reasoned:
        """The client's provenance carries ``reason`` for one call."""

        def __init__(self, reason: str):
            self.reason = reason

        def __enter__(self):
            self.saved = rk.provenance.reason
            rk.provenance.reason = self.reason

        def __exit__(self, *exc):
            rk.provenance.reason = self.saved

    @server.tool(annotations=WRITE)
    @guarded
    def create_folder(project_id: str, path: str, reason: str) -> dict:
        """Creates a folder in a project ("/libs/json", with any missing parents), to
        organize its programs. Returns its id (an existing folder's if it is there)."""
        with reasoned(reason):
            return {"ok": True, "folder_id": rk.folder_id(project_id, path, create=True), "path": path}

    @server.tool(annotations=WRITE)
    @guarded
    def move_to_folder(project_id: str, folder: str, reason: str, program_ids: Optional[list[str]] = None,
                       folders: Optional[list[str]] = None) -> dict:
        """Moves programs (ids) and folders (paths) into a folder (a path; "/" is the
        root), in one undoable revision."""
        with reasoned(reason):
            resp = rk.move_to_folder(project_id, folder, programs=program_ids or [], folders=folders or [])
            return {"ok": True, "seqs": [a.seq for a in resp.assertions], "revision": resp.snapshot.revision}

    @server.tool(annotations=WRITE)
    @guarded
    def rename_folder(project_id: str, folder: str, name: str, reason: str) -> dict:
        """Renames a folder (by its path) to a new name (not a path)."""
        with reasoned(reason):
            resp = rk.rename_folder(project_id, folder, name)
            return {"ok": True, "path": resp.folder.path, "seq": resp.assertion.seq}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False))
    @guarded
    def delete_folder(project_id: str, folder: str, reason: str) -> dict:
        """Deletes an empty folder (by its path). Undoable like any edit."""
        with reasoned(reason):
            resp = rk.delete_folder(project_id, folder)
            return {"ok": True, "seq": resp.assertion.seq}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def export_project(project_id: str, path: str, program_ids: Optional[list[str]] = None,
                       folders: Optional[list[str]] = None, annotations_only: bool = False) -> dict:
        """Writes a project (or some programs, or folders by path) to a .rkproj archive
        at ``path`` on this machine: the programs' bytes (unless annotations_only),
        every edit with its history and provenance, the folders and the types."""
        summary = rk.export_project(project_id, path, programs=program_ids or [], folders=folders or [],
                                    annotations_only=annotations_only)
        m = summary.manifest
        return {"ok": True, "path": path, "programs": [{"name": p.name, "folder": p.folder, "sha256": p.sha256}
                                                       for p in m.programs],
                "ops": m.log.count, "annotations_only": m.annotations_only}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def import_project(path: str, reason: str, into_project_id: str = "", new_project_name: str = "", folder: str = "",
                       binaries: Optional[list[str]] = None, inspect: bool = False, skip_missing: bool = False) -> dict:
        """Imports a .rkproj archive from ``path`` on this machine: into a new project, or
        into an existing one (``into_project_id``, under ``folder``) as new programs. An
        annotations-only archive needs its binaries: local file paths in ``binaries``
        (matched by sha256), or programs already in the project. ``inspect`` only
        describes it. Needs an admin token, as importing a program does."""
        with reasoned(reason):
            resp = rk.import_project(path, into=into_project_id, name=new_project_name, folder=folder,
                                     binaries=binaries or [], inspect=inspect, skip_missing=skip_missing)
            return {
                "project_id": resp.project.project_id,
                "programs": [{"name": p.name, "program_id": p.program.program_id, "folder": p.program.folder_path,
                              "binary": p.binary_source or "not found", "skipped": p.skipped} for p in resp.programs],
                "warnings": list(resp.warnings),
            }

    # -- container file systems (api_minor 48; docs/filesystems.md) ----------------

    filesystems: dict = {}

    def _fs(session_id: str):
        fs = filesystems.get(session_id)
        if fs is None:
            raise ValueError(f"no open file system {session_id}: open_filesystem first")
        return fs

    def _entry(e) -> dict:
        out = {"name": e.name, "path": e.path, "kind": filesystem_pb2.FileSystemEntryKind.Name(e.kind)
               .removeprefix("FILE_SYSTEM_ENTRY_KIND_").lower()}
        if e.kind != filesystem_pb2.FILE_SYSTEM_ENTRY_KIND_DIRECTORY:
            out["size"] = None if e.size_unknown else e.size
        for field in ("permissions", "link_target", "link_path", "note", "detected", "container_format",
                      "processor", "language_id"):
            if getattr(e, field):
                out[field] = getattr(e, field)
        if e.child_count:
            out["entries"] = e.child_count
        if e.renamed:
            out["renamed"] = True
        if e.unreadable:
            out["unreadable"] = True
        return out

    @server.tool(annotations=READ)
    @guarded
    def open_filesystem(project_id: str, file: str = "", host_path: str = "", program_id: str = "") -> dict:
        """Opens a container as a file system: an archive (zip, tar, cpio, ar, ISO), a
        compressed file (gzip, xz, bzip2, zstd, lz4, lzma), a file system image (squashfs,
        ext2/3/4, cramfs, FAT) or a firmware package (uImage, Android boot, UF2), nested
        to any depth. The source is ``file`` (a path on this machine, sent to the daemon),
        ``host_path`` (a file or directory on the daemon's host) or ``program_id`` (a
        program's stored file, e.g. a raw firmware dump). Returns a session_id for the
        other file system tools. Paths cross nested containers with "!":
        "/rootfs.sqfs!/bin/busybox"."""
        fs = rk.open_filesystem(project_id, host_path=host_path, program_id=program_id, file=file or None)
        filesystems[fs.session_id] = fs
        return {"session_id": fs.session_id, "name": fs.name, "format": fs.root.format,
                "description": fs.root.description, "warnings": list(fs.root.warnings)}

    @server.tool(annotations=READ)
    @guarded
    def list_filesystem(session_id: str, path: str = "/", recursive: bool = False, limit: int = 200) -> dict:
        """A directory's entries (or a container file's root) with what each file is
        (ELF/PE and processor, a nested container's format, text, data); ``recursive``
        lists everything below, not into nested containers."""
        r = _fs(session_id).list(path, recursive=recursive, detect=True, limit=max(1, min(limit, 2000)))
        return {"layer": {"format": r.layer.format, "description": r.layer.description,
                          "container_path": r.layer.container_path},
                "entries": [_entry(e) for e in r.entries], "total": r.total,
                "truncated": r.total > len(r.entries)}

    @server.tool(annotations=READ)
    @guarded
    def read_filesystem_file(session_id: str, path: str, offset: int = 0, length: int = 4096) -> dict:
        """Bytes of a file in an open file system (at most 64 KiB), as text when they
        decode as UTF-8, else hex."""
        data = _fs(session_id).read(path, offset, max(0, min(length, 65536)))
        try:
            return {"offset": offset, "length": len(data), "text": data.decode("utf-8")}
        except UnicodeDecodeError:
            return {"offset": offset, "length": len(data), "hex": data.hex()}

    @server.tool(annotations=READ)
    @guarded
    def filesystem_file_info(session_id: str, path: str, hashes: bool = True) -> dict:
        """A file's details: what it is, its container path (provenance), SHA-256/SHA-1/
        MD5, its first bytes, and the container it holds, if any."""
        r = _fs(session_id).info(path, hashes=hashes)
        out = {"entry": _entry(r.entry), "container_path": r.container_path, "magic": r.magic[:16].hex()}
        if hashes:
            out.update(sha256=r.sha256, sha1=r.sha1, md5=r.md5)
        if r.HasField("container"):
            out["container"] = {"format": r.container.format, "description": r.container.description}
        return out

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def import_from_filesystem(session_id: str, paths: list[str], reason: str, project_id: str = "",
                               folder: str = "", recursive: bool = False, descend: bool = False,
                               programs_only: bool = False, detect_raw: bool = False, preview: bool = False,
                               max_programs: int = 0, keep_folders: bool = False, analyze: bool = True,
                               import_libraries: bool = False) -> dict:
        """Imports files from an open file system as programs (batch import). One file
        named alone is imported whatever it is; directories (``recursive``: and below)
        and containers inside them (``descend``) give their programs only (ELF, PE, raw
        images whose header names the processor, or with ``detect_raw`` those raw
        detection identifies). ``preview`` imports nothing and says what would be;
        ``max_programs`` caps the count (default 100). Each program records its
        container path. ``import_libraries`` also imports the shared libraries they need from the
        same file system (beside each program, its runpath, the container's /lib, /usr/lib and
        ld.so.conf directories): items with ``library_of``; ``libraries_not_found`` the rest."""
        fs = _fs(session_id)
        with reasoned(reason):
            r = fs.import_(paths, project_id=project_id, folder=folder, recursive=recursive, descend=descend,
                           programs_only=programs_only, detect_raw=detect_raw, preview=preview,
                           max_programs=max_programs, keep_folders=keep_folders, analyze=analyze,
                           import_libraries=import_libraries)
        out = {"imported": r.imported, "skipped": r.skipped, "failed": r.failed, "capped": r.capped,
               "items": [{"path": i.path, "action": i.action, "reason": i.reason, "detected": i.detected,
                          **({"library_of": i.library_of} if i.library_of else {}),
                          **({"program_id": i.program.program_id, "folder": i.program.folder_path or "/"}
                             if i.program.program_id else {})} for i in r.items]}
        if r.libraries_not_found:
            out["libraries_not_found"] = [{"name": m.name, "needed_by": m.needed_by} for m in r.libraries_not_found]
        return out

    @server.tool(annotations=WRITE)
    @guarded
    def close_filesystem(session_id: str) -> dict:
        """Closes an open file system session."""
        fs = filesystems.pop(session_id, None)
        if fs is not None:
            fs.close()
        return {"ok": True}

    @server.tool(annotations=READ)
    @guarded
    def program_summary(program_id: str) -> dict:
        """Language, image base, entry points, memory blocks and function count of a program (overview shows
        where its code, data and undefined bytes are)."""
        s = rk.program(program_id).summary()
        out = {
            "name": s.info.name,
            "language": s.language.language_id,
            "compiler": s.language.compiler_spec_id,
            "image_base": _hex(s.image_base.offset),
            "import_image_base": _hex(s.import_image_base.offset),
            "entry_points": [{"address": _hex(e.address.offset), "name": e.name} for e in s.entry_points],
            "memory": [
                {
                    "name": b.name,
                    "start": _hex(b.range.first.offset),
                    "end": _hex(b.range.last.offset),
                    "perms": ("r" if b.read else "-") + ("w" if b.write else "-") + ("x" if b.execute else "-"),
                }
                for b in s.memory
            ],
            "function_count": s.function_count,
        }
        spaces = [sp for sp in s.spaces if not sp.alias and sp.key_base]
        if spaces:  # other memory spaces, addressed "name:0x100" (key_base + offset * word_size)
            out["spaces"] = [{"name": sp.name, "key_base": _hex(sp.key_base), "word_size": sp.word_size}
                             for sp in spaces]
        return out

    _NAMED = {"": query_pb2.FUNCTION_NAME_FILTER_UNSPECIFIED, "named": query_pb2.FUNCTION_NAME_FILTER_NAMED,
              "unnamed": query_pb2.FUNCTION_NAME_FILTER_UNNAMED}
    _THUNKS = {"": query_pb2.FUNCTION_THUNK_FILTER_UNSPECIFIED, "only": query_pb2.FUNCTION_THUNK_FILTER_ONLY,
               "exclude": query_pb2.FUNCTION_THUNK_FILTER_EXCLUDE}

    def _choice(what: str, value: str, choices) -> None:
        if value not in choices:
            raise ValueError(f"{what} is one of {', '.join(repr(c) for c in choices if c) or choices}"
                             + (" or empty" if "" in choices else ""))

    @server.tool(annotations=READ)
    @guarded
    def list_functions(program_id: str, name_contains: str = "", limit: int = 200, offset: int = 0,
                       named: str = "", thunks: str = "", decompile_failed: bool = False, sort: str = "address",
                       first: str = "", last: str = "") -> dict:
        """Functions (address, name, prototype, callers), a page at a time (limit, then offset for the next).
        Filters: name_contains (a substring, any case), named "named" (named by a symbol, debug info or an
        edit) or "unnamed" (only FUN_<address>, the ones left to work out), thunks "only" or "exclude",
        decompile_failed (functions the decompiler fails on), and an address range first..last. sort "address"
        or "name". C++ (and Rust, D) names are demangled ("geo::Shape::scale", with "mangled" set); the filter
        finds either spelling."""
        _choice("named", named, _NAMED)
        _choice("thunks", thunks, _THUNKS)
        _choice("sort", sort, ("address", "name"))
        prog = rk.program(program_id)
        limit = max(1, min(limit, 2000))
        req = query_pb2.ListFunctionsRequest(
            program_id=program_id, read=prog._read(), name_contains=name_contains, offset=max(0, offset),
            sort=listing_pb2.FUNCTION_SORT_NAME if sort == "name" else listing_pb2.FUNCTION_SORT_ADDRESS,
            named=_NAMED[named], thunks=_THUNKS[thunks], decompile_failed=decompile_failed)
        if first or last:
            req.range.first.offset = at(program_id, first) if first else 0
            req.range.last.offset = at(program_id, last) if last else (1 << 64) - 1
        req.page.page_size = limit + 1
        resp = prog._q("ListFunctions", req)
        out = []
        for f in resp.functions[:limit]:
            item = {"address": _hex(f.entry.offset), "name": f.name, "prototype": f.prototype, "callers": f.caller_count}
            if f.HasField("demangled"):
                item["mangled"] = f.demangled.mangled
            if f.thunk:
                item["thunk_to"] = _hex(f.thunk_target.offset)
            out.append(item)
        result = {"functions": out, "offset": offset, "truncated": False}
        if len(resp.functions) > limit or (resp.page.next_page_token and len(resp.functions) >= limit):
            result.update(_more(f"more functions: call again with offset={offset + len(out)}",
                                next_offset=offset + len(out)))
        return result

    @server.tool(annotations=READ)
    @guarded
    def disassemble(program_id: str, address: str, max_rows: int = 60) -> dict:
        """Listing rows from an address (a function's name starts at its entry): labels, instructions and data
        with their bytes and comments. At most 500 rows; "next" is the address to continue from."""
        page = rk.program(program_id).listing(at(program_id, address), max_rows=max(1, min(max_rows, 500)))
        lines = []
        end = None
        for r in page.rows:
            if r.HasField("header"):
                continue
            for c in r.comments:
                if c.kind in (assertion_pb2.COMMENT_KIND_PLATE, assertion_pb2.COMMENT_KIND_PRE):
                    lines += [f"  ; {t}" for t in c.text.splitlines()]
            for label in r.labels:
                lines.append(f"{label.name}:")
            text = "".join(t.text for t in r.tokens)
            raw = r.bytes[:8].hex() + ("+" if len(r.bytes) > 8 else "")
            eol = [c.text for c in r.comments if c.kind in (assertion_pb2.COMMENT_KIND_EOL, assertion_pb2.COMMENT_KIND_REPEATABLE)]
            lines.append(f"  {_hex(r.address.offset)}  {raw:<17} {text}" + (f"  ; {eol[0]}" if eol else ""))
            end = r.address.offset + max(1, r.length)
        out = {"revision": page.snapshot.revision, "listing": "\n".join(lines)}
        if end is not None:
            out["next"] = _hex(end)
        return out

    @server.tool(annotations=READ)
    @guarded
    def decompile(program_id: str, function_address: str, start_line: int = 0, max_lines: int = 300,
                  variables: bool = True) -> dict:
        """C pseudocode for the function at or containing an address (or named: "main"), max_lines lines from
        start_line (0-based; "more" says where the rest starts), plus its variables with the storage keys
        rename_variable and retype_variable need (variables=false leaves them out), the struct fields it uses
        (name, offset, and the struct's hash for get_type, rename_field and retype_field) and the demangled
        names it shows."""
        prog = rk.program(program_id)
        a = at(program_id, function_address)
        try:
            fn = prog.decompile(a)
        except RevkitError as e:
            if e.code.name != "NOT_FOUND":
                raise
            fn = prog.decompile(prog.function(a, containing=True).entry.offset)
        fields = {}
        demangled = {}
        for line in fn.lines:
            for t in line.tokens:
                if t.kind == decompile_pb2.CODE_TOKEN_KIND_FIELD and t.HasField("field_offset"):
                    fields.setdefault((t.parent_type_hash, t.field_offset, t.text), None)
                if t.HasField("demangled"):
                    demangled.setdefault(t.demangled.mangled, {"name": t.text, "mangled": t.demangled.mangled,
                                                               "signature": t.demangled.full,
                                                               "address": _hex(t.target.offset)})
        text = fn.text.split("\n")
        start_line = max(0, start_line)
        max_lines = max(1, max_lines)
        out = {
            "name": fn.name,
            "entry": _hex(fn.entry.offset) if fn.HasField("entry") else _hex(a),
            "prototype": fn.prototype.c_declaration,
            "c": "\n".join(text[start_line:start_line + max_lines]),
            "lines": len(text),
        }
        if start_line or start_line + max_lines < len(text):
            out["start_line"] = start_line
        if start_line + max_lines < len(text):
            out.update(_more(f"lines {start_line}-{start_line + max_lines - 1} of {len(text)}: call again with "
                             f"start_line={start_line + max_lines} for the rest", next_start_line=start_line + max_lines))
        if variables:
            out["variables"] = [
                {
                    "name": v.name,
                    "type": v.type.display,
                    "kind": decompile_pb2.VariableKind.Name(v.kind).removeprefix("VARIABLE_KIND_").lower(),
                    "storage_key": v.storage_key,
                    **({"named_by": _origin(v.name_origin)} if _origin(v.name_origin) else {}),
                }
                for v in fn.variables
            ]
        out["fields"] = [{"name": n, "offset": _hex(o), "struct_hash": h} for h, o, n in fields]
        # Demangled names it shows (docs/demangle.md): their mangled symbols and full signatures.
        out["demangled"] = list(demangled.values())
        out["warnings"] = list(fn.warnings)
        return out

    _XREF_KINDS = ("", "call", "jump", "conditional_jump", "indirect_call", "indirect_jump", "data_read", "data_write",
                   "data_pointer", "thunk", "fallthrough")

    @server.tool(annotations=READ)
    @guarded
    def xrefs(program_id: str, address: str, direction: str = "to", limit: int = 200, offset: int = 0,
              kind: str = "") -> dict:
        """Cross-references to ("to"), from ("from") or both ("both") an address, a page at a time (limit, then
        offset); kind keeps one kind: "call", "jump", "conditional_jump", "indirect_call", "indirect_jump",
        "data_read", "data_write", "data_pointer" (address taken), "thunk" or "fallthrough" (a fallthrough override's
        address). "total" counts them all."""
        _choice("direction", direction, ("to", "from", "both"))
        _choice("kind", kind.lower(), _XREF_KINDS)
        prog = rk.program(program_id)
        out, total = [], 0
        limit = max(1, limit)
        for x in prog.xrefs(at(program_id, address), direction=direction):
            k = listing_pb2.XrefKind.Name(x.kind).removeprefix("XREF_KIND_").lower()
            if kind and k != kind.lower():
                continue
            total += 1
            if total <= offset or len(out) >= limit:
                continue
            out.append({
                "from": _hex(x.from_address.offset),
                "to": _hex(x.to_address.offset),
                "kind": k,
                "from_function": x.from_function_name,
                "to_name": x.to_name,
                **({"operand": x.operand_index} if x.HasField("operand_index") else {}),
                **({"primary": True} if x.primary else {}),
                **({"added_by": format_provenance(x.origin.asserted.provenance), "seq": x.origin.asserted.seq}
                   if x.origin.HasField("asserted") else {}),
            })
        result = {"xrefs": out, "total": total, "offset": offset, "truncated": False}
        if offset + len(out) < total:
            result.update(_more(f"{total} xrefs: call again with offset={offset + len(out)} for the next",
                                next_offset=offset + len(out)))
        return result

    @server.tool(annotations=READ)
    @guarded
    def instruction(program_id: str, address: str) -> dict:
        """One instruction with its raw p-code."""
        i = rk.program(program_id).instruction(at(program_id, address))

        def vn(v):
            return f"{v.register_name or v.space + ':' + hex(v.offset)}:{v.size}"

        pcode = []
        for op in i.pcode:
            ins = ", ".join(vn(v) for v in op.inputs)
            pcode.append(f"{vn(op.output) + ' = ' if op.HasField('output') else ''}{op.mnemonic} {ins}")
        return {"text": "".join(t.text for t in i.tokens), "bytes": i.bytes.hex(), "pcode": pcode}

    @server.tool(annotations=READ)
    @guarded
    def blame(program_id: str, address: str, kind: str = "name", sub: str = "") -> dict:
        """Who set a fact (kind: name, type, comment, function, flow_override, note) and what competes with it."""
        _choice("kind", kind, ("name", "type", "comment", "function", "flow_override", "note"))
        prog = rk.program(program_id)
        b = prog.blame(prog.key(kind, at(program_id, address), sub))
        return {
            "value": b.value_text,
            "set_by": _origin(b.origin),
            "candidates": [
                {
                    "seq": a.seq,
                    "by": format_provenance(a.provenance),
                    "reason": a.provenance.reason,
                    "status": assertion_pb2.AssertionStatus.Name(a.status).removeprefix("ASSERTION_STATUS_").lower(),
                }
                for a in b.candidates
            ],
        }

    # -- writes (always agent provenance) ------------------------------------------

    @server.tool(annotations=WRITE)
    @guarded
    def rename(program_id: str, address: str, new_name: str, reason: str) -> dict:
        """Rename the function, label or global at an address (a hex address, or its current name: "FUN_00401040",
        "DAT_00404010"). The new name shows everywhere: the listing, the decompiler, callers' C."""
        return write_result(rk.program(program_id).rename(at(program_id, address), new_name, reason=reason))

    @server.tool(annotations=WRITE)
    @guarded
    def rename_variable(program_id: str, function_address: str, storage_key: str, new_name: str, reason: str) -> dict:
        """Rename a parameter or local; storage_key comes from decompile's variables."""
        return write_result(rk.program(program_id).rename_local(at(program_id, function_address), storage_key, new_name, reason=reason))

    @server.tool(annotations=WRITE)
    @guarded
    def set_comment(program_id: str, address: str, text: str, reason: str, kind: str = "eol") -> dict:
        """Set a comment at an address (kind: "eol" at the end of the line, "pre" above it, "post" below it,
        "plate" (a function's or block's header), "repeatable" (shown wherever the address is referenced) or
        "decompiler" (shown in the C)). Empty text clears it."""
        _choice("kind", kind, ("eol", "pre", "post", "plate", "repeatable", "decompiler"))
        return write_result(rk.program(program_id).comment(at(program_id, address), text, kind=kind, reason=reason))

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False))
    @guarded
    def revert_my_changes(program_id: str) -> dict:
        """Undo every edit this MCP session made to a program (one revision)."""
        r = rk.program(program_id).revert(kind="agent", id=agent, session=session)
        return {"retracted": len(r.retracted_seqs), "revision": r.snapshot.revision}


    # -- more reads ----------------------------------------------------------------

    @server.tool(annotations=READ)
    @guarded
    def search_symbols(program_id: str, name_contains: str = "", name_equals: str = "", limit: int = 200,
                       offset: int = 0) -> dict:
        """Functions and labels by name (substring, any case, or exact), in address order, a page at a time
        (limit, then offset). Demangled names match by either spelling (a mangled name_equals finds its
        demangled symbol, with "demangled" set)."""
        out, n = [], 0
        limit = max(1, limit)
        for sym in rk.program(program_id).symbols(name_contains, name_equals=name_equals):
            n += 1
            if n <= offset:
                continue
            if len(out) >= limit:
                return {"symbols": out, "offset": offset,
                        **_more(f"more symbols: call again with offset={offset + len(out)}", next_offset=offset + len(out))}
            d = _d(sym)
            d["kind"] = str(d.get("kind", "")).removeprefix("SYMBOL_KIND_").lower()
            out.append(d)
        return {"symbols": out, "offset": offset, "truncated": False}

    @server.tool(annotations=READ)
    @guarded
    def get_function(program_id: str, address: str) -> dict:
        """The function containing an address: entry, name, prototype, body ranges, counts."""
        return _d(rk.program(program_id).function(at(program_id, address), containing=True))

    @server.tool(annotations=READ)
    @guarded
    def preview(program_id: str, address: str) -> dict:
        """What is at an address, as revkit's hover card shows it: a function's
        signature and first lines of C (kind "function"), else the listing's
        rows there and the symbol's name (kind "data")."""
        p = rk.program(program_id).preview(at(program_id, address))
        p["address"] = _hex(p["address"])
        return p

    @server.tool(annotations=READ)
    @guarded
    def describe_value(program_id: str, value: str, bits: int = 64) -> dict:
        """A constant (decimal or 0x hex) in hex, unsigned and signed decimal and as
        a C character constant, and, if it is an address, the symbol there and its memory block."""
        return rk.program(program_id).describe_scalar(_num(value), bits)

    def _data(program_id: str, categories, text_contains: str, limit: int, offset: int, first: str = "",
              last: str = "") -> dict:
        prog = rk.program(program_id)
        limit = max(1, min(limit, 5000))
        req = query_pb2.ListDataRequest(program_id=program_id, read=prog._read(), categories=categories,
                                        text_contains=text_contains, offset=max(0, offset))
        if first or last:
            req.range.first.offset = at(program_id, first) if first else 0
            req.range.last.offset = at(program_id, last) if last else (1 << 64) - 1
        req.page.page_size = limit + 1
        resp = prog._q("ListData", req)
        out = []
        for item in resp.data[:limit]:
            d = _d(item)
            d["category"] = str(d.get("category", "")).removeprefix("DATA_CATEGORY_").lower()
            out.append(d)
        result = {"data": out, "offset": offset, "truncated": False}
        if len(resp.data) > limit or (resp.page.next_page_token and len(resp.data) >= limit):
            result.update(_more(f"more data: call again with offset={offset + len(out)}", next_offset=offset + len(out)))
        return result

    @server.tool(annotations=READ)
    @guarded
    def list_strings(program_id: str, text_contains: str = "", limit: int = 100, offset: int = 0,
                     first: str = "", last: str = "") -> dict:
        """Strings the analysis found (address, text, label, how many references), in address order, a page at
        a time (limit, then offset); text_contains (any case) and an address range first..last narrow them.
        xrefs on a string's address shows the code that uses it."""
        return _data(program_id, [query_pb2.DATA_CATEGORY_STRING], text_contains, limit, offset, first, last)

    @server.tool(annotations=READ)
    @guarded
    def search_strings(program_id: str, query: str, regex: bool = False, case_sensitive: bool = False,
                       min_length: int = 0, limit: int = 100, offset: int = 0, first: str = "",
                       last: str = "") -> dict:
        """Search the strings the analysis found: query is a substring (any case unless case_sensitive) or,
        with regex, a Python regular expression (re.search); min_length drops shorter strings; first..last
        narrows to an address range. Matches come in address order, a page at a time (limit, then offset
        over the matches), each with its address, text (value), label and reference count; xrefs on an
        address shows the code that uses it. For bytes the analysis didn't define as a string, use
        search_memory."""
        if not regex and not case_sensitive and min_length <= 0:
            return _data(program_id, [query_pb2.DATA_CATEGORY_STRING], query, limit, offset, first, last)
        import re
        try:
            pattern = re.compile(query if regex else re.escape(query), 0 if case_sensitive else re.IGNORECASE)
        except re.error as e:
            return {"error": f"invalid regular expression: {e}"}
        prog = rk.program(program_id)
        limit = max(1, min(limit, 5000))
        offset = max(0, offset)
        # The daemon's text_contains is a case-insensitive substring: a cheap prefilter for a plain query.
        prefilter = "" if regex else query
        out, skipped, scanned, at_offset, page = [], 0, 0, 0, 2000
        while True:
            req = query_pb2.ListDataRequest(program_id=program_id, read=prog._read(),
                                            categories=[query_pb2.DATA_CATEGORY_STRING],
                                            text_contains=prefilter, offset=at_offset)
            if first or last:
                req.range.first.offset = at(program_id, first) if first else 0
                req.range.last.offset = at(program_id, last) if last else (1 << 64) - 1
            req.page.page_size = page
            resp = prog._q("ListData", req)
            for item in resp.data:
                scanned += 1
                if len(item.value) < min_length or not pattern.search(item.value):
                    continue
                if skipped < offset:
                    skipped += 1
                    continue
                if len(out) == limit:
                    result = {"data": out, "offset": offset, "truncated": False, "scanned": scanned}
                    result.update(_more(f"more matches: call again with offset={offset + len(out)}",
                                        next_offset=offset + len(out)))
                    return result
                d = _d(item)
                d["category"] = "string"
                out.append(d)
            if not resp.data or (len(resp.data) < page and not resp.page.next_page_token) or scanned >= 500_000:
                break
            at_offset += len(resp.data)
        return {"data": out, "offset": offset, "truncated": False, "scanned": scanned}

    @server.tool(annotations=READ)
    @guarded
    def symbol_tree(program_id: str, path: Optional[list[str]] = None, contains: str = "", limit: int = 200,
                    offset: int = 0) -> dict:
        """Ghidra's symbol tree, one level at a time. No path: the folders Imports, Exports, Functions,
        Labels, Classes, Namespaces with their sizes. ["Imports"]: libraries ("<EXTERNAL>" when the file
        doesn't say); ["Imports", lib]: its imports; ["Exports"]; ["Functions"]; ["Labels"]; ["Classes"]:
        every class by qualified name; ["Classes", "geo::Circle"]: its members; ["Namespaces", "geo", ...]:
        a namespace's inner namespaces, classes and symbols. contains filters by name (any case). Each node:
        name, kind, address (symbols), full_name, children (scopes)."""
        prog = rk.program(program_id)
        limit, offset = max(1, min(limit, 5000)), max(0, offset)
        req = query_pb2.ListSymbolTreeRequest(program_id=program_id, read=prog._read(), path=list(path or []),
                                              name_contains=contains)
        req.page.page_size = 5000
        nodes, total = [], 0
        while True:
            resp = prog._q("ListSymbolTree", req)
            total = resp.total
            nodes.extend(resp.nodes)
            if len(nodes) >= offset + limit or not resp.page.next_page_token:
                break
            req.page.page_token = resp.page.next_page_token
        out = []
        for n in nodes[offset:offset + limit]:
            e = {"name": n.name, "kind": query_pb2.SymbolTreeNodeKind.Name(n.kind).removeprefix("SYMBOL_TREE_NODE_KIND_").lower()}
            if n.HasField("address"):
                e["address"] = _hex(n.address.offset)
            if n.full_name and n.full_name != n.name:
                e["full_name"] = n.full_name
            if n.children:
                e["children"] = n.children
            if n.library:
                e["library"] = n.library
            out.append(e)
        result = {"path": list(path or []), "nodes": out, "total": total, "offset": offset}
        if offset + len(out) < total:
            result.update(_more(f"more nodes: call again with offset={offset + len(out)}", next_offset=offset + len(out)))
        return result

    @server.tool(annotations=READ)
    @guarded
    def list_relocations(program_id: str, contains: str = "", limit: int = 200, offset: int = 0, first: str = "",
                         last: str = "") -> dict:
        """The relocations the file carries (Ghidra's relocation table), in address order: ELF dynamic and
        object relocations, PE base relocations. contains matches the symbol or the type name (any case);
        first..last narrows to an address range. Each: address, type (its name, e.g. R_X86_64_JUMP_SLOT),
        kind (relative, irelative, jump_slot, glob_dat, absolute, other), symbol, addend, target (where it
        points once applied, when that is known here, with its name) and the bytes there (hex)."""
        prog = rk.program(program_id)
        limit = max(1, min(limit, 5000))
        req = query_pb2.ListRelocationsRequest(program_id=program_id, read=prog._read(), text_contains=contains)
        if first or last:
            req.range.first.offset = at(program_id, first) if first else 0
            req.range.last.offset = at(program_id, last) if last else (1 << 64) - 1
        out, skipped, total = [], 0, 0
        req.page.page_size = 5000
        while True:
            resp = prog._q("ListRelocations", req)
            total = resp.total
            for r in resp.relocations:
                if skipped < offset:
                    skipped += 1
                    continue
                if len(out) == limit:
                    break
                e = {"address": _hex(r.address.offset), "type": r.type_name,
                     "kind": query_pb2.RelocationKind.Name(r.kind).removeprefix("RELOCATION_KIND_").lower(),
                     "addend": r.addend, "bytes": r.original.hex()}
                if r.symbol:
                    e["symbol"] = r.symbol
                if r.HasField("target"):
                    e["target"] = _hex(r.target.offset)
                    if r.target_name:
                        e["target_name"] = r.target_name
                out.append(e)
            if len(out) == limit or not resp.page.next_page_token:
                break
            req.page.page_token = resp.page.next_page_token
        result = {"format": resp.format, "total": total, "relocations": out, "offset": offset}
        if offset + len(out) < total:
            result.update(_more(f"more relocations: call again with offset={offset + len(out)}",
                                next_offset=offset + len(out)))
        return result

    @server.tool(annotations=READ)
    @guarded
    def list_comments(program_id: str, kinds: Optional[list[str]] = None, contains: str = "", limit: int = 200) -> dict:
        """Every comment of a program (Ghidra's comment window), in address order: kinds among "eol", "pre",
        "post", "plate", "repeatable", "decompiler" (default all); contains filters by text, case-insensitively.
        Each: address, kind, text, the function it is in, who wrote it."""
        out = []
        for c in rk.program(program_id).comments(*(kinds or []), text_contains=contains, page_size=min(max(limit, 1), 1000)):
            e = {"address": _hex(c.address.offset), "kind": assertion_pb2.CommentKind.Name(c.kind).removeprefix("COMMENT_KIND_").lower(),
                 "text": c.text}
            if c.function_name:
                e["function"] = c.function_name
            if c.label:
                e["label"] = c.label
            out.append(e)
            if len(out) >= limit:
                break
        return {"comments": out}

    @server.tool(annotations=READ)
    @guarded
    def list_data(program_id: str, category: str = "", text_contains: str = "", limit: int = 100, offset: int = 0,
                  first: str = "", last: str = "") -> dict:
        """Defined data, a page at a time (limit, then offset): category "string", "pointer", "typed" (typed
        globals), "defined" (other data defined with define_data), "undefined" or "" for all; text_contains
        matches the value, label or type; first..last an address range."""
        cats = {"string": query_pb2.DATA_CATEGORY_STRING, "pointer": query_pb2.DATA_CATEGORY_POINTER,
                "typed": query_pb2.DATA_CATEGORY_TYPED, "defined": query_pb2.DATA_CATEGORY_DEFINED,
                "undefined": query_pb2.DATA_CATEGORY_UNDEFINED}
        _choice("category", category, ("",) + tuple(cats))
        return _data(program_id, [cats[category]] if category else [], text_contains, limit, offset, first, last)

    @server.tool(annotations=WRITE)
    @guarded
    def load_pdb(program_id: str, path: str = "", from_symbol_path: bool = False, force: bool = False) -> dict:
        """Loads a PDB into a Windows program: a path on the daemon's host, or (from_symbol_path) the one the
        program names, found on the daemon's symbol path. Another build's PDB needs force. Its names and types are import:pdb assertions."""
        r = rk.program(program_id).load_pdb(path or None, symbol_path=from_symbol_path, force=force, reason="mcp load_pdb")
        return {"pdb_file": r.pdb_file, "exact": r.exact, "source": r.source, "functions": r.functions,
                "variables": r.variables, "types": r.types, "warnings": list(r.warnings), "revision": r.snapshot.revision}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=True))
    @guarded
    def load_debug_file(program_id: str, path: str = "", search: bool = False, force: bool = False) -> dict:
        """Loads a stripped Linux (ELF) program's separate debug file: a path on the daemon's host, or (search) the
        one its build ID or .gnu_debuglink names, looked up locally and, only if an admin enabled them, on debuginfod
        servers. Another build's file needs force. Its names, prototypes and types become import:dwarf assertions."""
        r = rk.program(program_id).load_debug_file(path or None, search=search, force=force, reason="mcp load_debug_file")
        return {"debug_file": r.debug_file, "exact": r.exact, "source": r.source, "build_id": r.build_id,
                "functions": r.functions, "variables": r.variables, "types": r.types, "warnings": list(r.warnings),
                "search_log": list(r.search_log)[:50], "revision": r.snapshot.revision, "seqs": list(r.assertion_seqs)}

    @server.tool(annotations=READ)
    @guarded
    def list_calling_conventions(program_id: str) -> dict:
        """The calling conventions a function of the program can have: its compiler spec's prototype models
        (the default first) and how a C prototype spells each. Set one with retype on the function's address and a
        C declaration using that spelling ("int __fastcall f(int a, int b)")."""
        cc = rk.program(program_id).calling_conventions()
        return {"default": next((c.name for c in cc if c.is_default), ""),
                "conventions": [{"name": c.name, "default": c.is_default, "c_spelling": c.c_spelling} for c in cc]}

    @server.tool(annotations=READ)
    @guarded
    def list_classes(program_id: str, name_contains: str = "", limit: int = 200, offset: int = 0) -> dict:
        """C++ classes from MSVC RTTI (Windows programs), a page at a time (limit, then offset): each class's
        bases (direct or not, virtual, offset), derived classes, vftables with their functions (slot, address,
        name) and the struct `this` points to."""
        out, n = [], 0
        for c in rk.program(program_id).classes(name_contains):
            n += 1
            if n <= offset:
                continue
            if len(out) >= max(1, limit):
                return {"classes": out, "offset": offset,
                        **_more(f"more classes: call again with offset={offset + len(out)}", next_offset=offset + len(out))}
            out.append({
                "name": c.name,
                "bases": [{"name": b.name, "direct": b.direct, "virtual": b.is_virtual, "offset": b.offset} for b in c.bases],
                "derived": list(c.derived),
                "vftables": [{"address": _hex(t.address.offset), "name": t.name, "subobject": t.subobject,
                              "functions": [{"slot": f.slot, "address": _hex(f.entry.offset), "name": f.name}
                                            for f in t.functions]} for t in c.vftables],
                "type": c.type_name,
            })
        return {"classes": out, "offset": offset, "truncated": False}

    @server.tool(annotations=READ)
    @guarded
    def read_memory(program_id: str, address: str, length: int = 64) -> dict:
        """Bytes of the program's image at an address (at most 4096), as hex and a dump."""
        a = at(program_id, address)
        data = rk.program(program_id).read_memory(a, max(1, min(length, 4096)))
        return {"address": _hex(a), "hex": data.hex(), "dump": _dump(data, a)}

    _NAV = ("instruction", "data", "undefined", "label", "function", "different_byte", "note")

    @server.tool(annotations=READ)
    @guarded
    def find_next(program_id: str, address: str, kind: str, backward: bool = False, count: int = 1) -> dict:
        """The next (backward: previous) place of a kind after an address, as Ghidra's Navigation menu: kind
        "function" (an entry), "label" (an address with a name), "instruction", "data" or "undefined" (the next
        run of them: undefined bytes are code or data analysis left alone), "different_byte" (the next byte
        whose value differs from the one at address, past padding) or "note" (one add_note left). count (up to
        50) follows that many in a row. Each with its listing row."""
        _choice("kind", kind, _NAV)
        prog = rk.program(program_id)
        here = at(program_id, address)
        found = []
        for _ in range(max(1, min(count, 50))):
            nxt = prog.find_next(here, kind, backward=backward)
            if nxt is None or nxt == here:
                break
            item = {"address": _hex(nxt)}
            rows = [r for r in prog.listing(nxt, max_rows=2).rows if not r.HasField("header")]
            if rows:
                r = rows[0]
                if r.labels:
                    item["label"] = r.labels[0].name
                item["row"] = "".join(t.text for t in r.tokens)
            found.append(item)
            here = nxt
        return {"from": _hex(at(program_id, address)), "kind": kind, "backward": backward, "found": found,
                **({} if found else {"note": f"no {kind} {'before' if backward else 'after'} that address"})}

    @server.tool(annotations=READ)
    @guarded
    def overview(program_id: str, slices: int = 32) -> dict:
        """Where a program's code, data and undefined bytes are, and how random they look: each memory block
        with its bytes by kind and entropy, then about `slices` slices (up to 512) of the whole image, each with
        its main kind, the percentages of code, data and undefined bytes, and its entropy in bits per byte (0 to
        8: above ~7 is compressed or encrypted, under ~1 padding or tables of zeros). high_entropy lists those
        regions; undefined slices are where code or data may hide."""
        r = rk.program(program_id).overview(max(1, min(slices, 512)))
        kinds = query_pb2.ByteKind

        def name(k):
            return kinds.Name(k).removeprefix("BYTE_KIND_").lower()

        blocks: dict = {}
        out_slices, high = [], []
        for b in r.buckets:
            n = max(1, b.length)
            blk = blocks.setdefault(b.block, {"name": b.block, "start": _hex(b.start.offset), "end": _hex(b.start.offset),
                                              "code": 0, "data": 0, "undefined": 0, "external": 0,
                                              "uninitialized": 0, "_entropy": 0.0})
            blk["end"] = _hex(b.start.offset + b.length - 1)
            for k in ("code", "data", "undefined", "external", "uninitialized"):
                blk[k] += getattr(b, k)
            blk["_entropy"] += b.entropy * b.length
            sl = {"start": _hex(b.start.offset), "length": _hex(b.length), "block": b.block, "kind": name(b.kind),
                  "entropy": round(b.entropy, 2)}
            for k in ("code", "data", "undefined"):
                if getattr(b, k):
                    sl[k + "_pct"] = round(100 * getattr(b, k) / n)
            out_slices.append(sl)
            if b.entropy >= 7.0:
                if high and high[-1]["_end"] == b.start.offset:
                    high[-1]["_end"] = b.start.offset + b.length
                    high[-1]["entropy"] = max(high[-1]["entropy"], round(b.entropy, 2))
                else:
                    high.append({"start": _hex(b.start.offset), "_end": b.start.offset + b.length,
                                 "entropy": round(b.entropy, 2)})
        for blk in blocks.values():
            size = int(blk["end"], 16) - int(blk["start"], 16) + 1
            blk["entropy"] = round(blk.pop("_entropy") / max(1, size), 2)
            for k in ("external", "uninitialized"):
                if not blk[k]:
                    del blk[k]
        for h in high:
            h["length"] = _hex(h.pop("_end") - int(h["start"], 16))
        return {"total_bytes": r.total_bytes, "blocks": list(blocks.values()), "high_entropy": high,
                "slices": out_slices}

    # -- searches (api_minor 41, feature "search") --

    def _where(function_address, function_name) -> dict:
        return {"function": _hex(function_address.offset), "function_name": function_name} if function_name else {}

    def _search_more(out: dict, backward: bool) -> dict:
        if out["truncated"] and out["matches"]:
            out["more"] = (f"more matches: call again with start={out['matches'][-1]['address']}"
                           + (" (and backward)" if backward else "") + " for the next ones")
        return out

    @server.tool(annotations=READ)
    @guarded
    def search_memory(program_id: str, query: str, format: str = "hex", encoding: str = "ascii",
                      case_sensitive: bool = False, size: int = 4, byte_order: str = "", first: str = "", last: str = "",
                      code_units: Optional[list[str]] = None, start: str = "", backward: bool = False,
                      limit: int = 100) -> dict:
        """Search the program's bytes (Ghidra's Search Memory): format "hex" ("48 8b ?? e8", nibble wildcards
        "4?"), "string" (encoding ascii, utf8 or utf16; any case unless case_sensitive), "decimal" (size 1, 2, 4
        or 8 bytes), "float", "double", "binary" ("10xx0101") or "regex" (RE2 over bytes, "\\x55\\x48\\x89\\xe5").
        byte_order "little"/"big" (default the program's). Optionally within [first, last], only in code_units
        ("instructions", "data", "undefined"), or the next match after start (backward: before it).
        Each match: address, the bytes, the label and the code unit as the listing shows it."""
        prog = rk.program(program_id)
        ranges = [(at(program_id, first) if first else 0, at(program_id, last) if last else (1 << 64) - 1)] if first or last else None
        hits = prog.search_memory(query, format=format, encoding=encoding, case_sensitive=case_sensitive, size=size,
                                  byte_order=byte_order or None, ranges=ranges, code_units=code_units,
                                  start=at(program_id, start) if start else None, backward=backward,
                                  max_results=max(1, min(limit, 10000)))
        last_msg = prog.last_search
        out = {"pattern": last_msg.pattern if last_msg else "", "truncated": bool(last_msg and last_msg.truncated),
               "matches": [{"address": _hex(m.address.offset), "bytes": m.bytes.hex()[:64], "label": m.label,
                            "code_unit": m.preview, **_where(m.function, m.function_name)} for m in hits]}
        return _search_more(out, backward)

    _FIELDS = ["comments", "labels", "functions", "mnemonics", "operands", "data_mnemonics", "data_values"]

    @server.tool(annotations=READ)
    @guarded
    def search_text(program_id: str, query: str, regex: bool = False, case_sensitive: bool = False,
                    whole_word: bool = False, fields: Optional[list[str]] = None, start: str = "",
                    backward: bool = False, limit: int = 100) -> dict:
        """Search what the listing shows (Ghidra's Search Program Text), names as they are now: fields any of
        comments, labels, functions (signatures), mnemonics, operands, data_mnemonics, data_values (default
        all). Plain text or regex (RE2). Each match: address, field, the line and the matched part."""
        prog = rk.program(program_id)
        names = {1: "comments", 2: "labels", 3: "functions", 4: "mnemonics", 5: "operands", 6: "data_mnemonics", 7: "data_values"}
        hits = prog.search_text(query, regex=regex, case_sensitive=case_sensitive, whole_word=whole_word, fields=fields,
                                start=at(program_id, start) if start else None, backward=backward,
                                max_results=max(1, min(limit, 10000)))
        out = []
        for m in hits:
            b = m.text.encode()
            out.append({"address": _hex(m.address.offset), "field": names.get(m.field, ""), "text": m.text,
                        "match": b[m.match_start : m.match_start + m.match_length].decode(errors="replace"),
                        "label": m.label, **_where(m.function, m.function_name)})
        return _search_more({"matches": out, "truncated": bool(prog.last_search and prog.last_search.truncated)},
                            backward)

    @server.tool(annotations=READ)
    @guarded
    def search_scalars(program_id: str, value: str = "", min_value: str = "", max_value: str = "",
                       instructions: bool = True, data: bool = True, start: str = "", backward: bool = False,
                       limit: int = 100) -> dict:
        """Instructions and defined data that use a constant (Ghidra's Search for Scalars): value, or the range
        [min_value, max_value] (decimal or 0x hex; a negative value matches as signed), optionally the matches
        after start (backward: before it). Each match: address, the instruction or data as shown, the value,
        its width and operand, the function."""
        def num(text):
            return _num(text) if text else None
        prog = rk.program(program_id)
        hits = prog.search_scalars(num(min_value), num(max_value), value=num(value), instructions=instructions,
                                   data=data, start=at(program_id, start) if start else None, backward=backward,
                                   max_results=max(1, min(limit, 10000)))
        out = {"truncated": bool(prog.last_search and prog.last_search.truncated),
               "matches": [{"address": _hex(m.address.offset), "text": m.text, "value": m.value,
                            "hex": hex(m.unsigned_value), "bits": m.bits, "operand": m.operand_index,
                            **_where(m.function, m.function_name)} for m in hits]}
        return _search_more(out, backward)

    @server.tool(annotations=READ)
    @guarded
    def search_decompiled(program_id: str, query: str, regex: bool = False, case_sensitive: bool = False,
                          whole_word: bool = False, functions: Optional[list[str]] = None, limit: int = 100) -> dict:
        """Search decompiled C (Ghidra's Decompiler Text Finder): every function, or those listed (addresses or names).
        Decompiling every function of a large program takes minutes the first time (results are cached); pass
        functions to narrow it. Each match: the function, the line number (0-based) and the line's text."""
        prog = rk.program(program_id)
        hits = prog.search_decompiled(query, regex=regex, case_sensitive=case_sensitive, whole_word=whole_word,
                                      functions=[at(program_id, f) for f in functions] if functions else None,
                                      max_results=max(1, min(limit, 10000)))
        last_msg = prog.last_search
        return {"truncated": bool(last_msg and last_msg.truncated),
                **({"more": "more matches: narrow the query, or pass functions (addresses or names) to search"}
                   if last_msg and last_msg.truncated else {}),
                "functions_searched": last_msg.functions_done if last_msg else 0,
                "matches": [{"function": _hex(m.function.offset), "function_name": m.function_name, "line": m.line,
                             "text": m.text, **({"address": _hex(m.address.offset)} if m.HasField("address") else {})}
                            for m in hits]}

    @server.tool(annotations=READ)
    @guarded
    def slice_decompiled(program_id: str, function_address: str, variable: str, kind: str = "backward") -> dict:
        """Data flow in a function's decompiled C (Ghidra's Highlight Def-use and Forward/Backward Slice): where a
        variable's value comes from or goes to. variable: its name as decompile shows it (a parameter, a local,
        a global it uses). kind: "backward" (every value it is computed from), "forward" (every value computed
        from it), "def_use" (its definition and uses), "forward_ops" / "backward_ops" (the operations, with their
        instructions). Returns the C lines the slice touches (0-based line numbers, as decompile numbers them)
        with the tokens in the slice on each, and the instruction addresses."""
        prog = rk.program(program_id)
        a = at(program_id, function_address)
        try:
            fn = prog.decompile(a, text=False)
        except RevkitError as e:
            if e.code.name != "NOT_FOUND":
                raise
            a = prog.function(a, containing=True).entry.offset
            fn = prog.decompile(a, text=False)
        r = prog.slice(a, kind, variable=variable)
        by_line: dict[int, list[str]] = {}
        for p in r.tokens:
            by_line.setdefault(p.line, []).append(fn.lines[p.line].tokens[p.token].text)
        lines = []
        for n in sorted(by_line):
            line = fn.lines[n]
            lines.append({"line": n, "text": "  " * line.indent + "".join(t.text for t in line.tokens),
                          "tokens": by_line[n]})
        return {"function": fn.name, "start": r.start, "kind": kind, "lines": lines,
                "addresses": [_hex(x.offset) for x in r.addresses]}

    @server.tool(annotations=READ)
    @guarded
    def find_type_uses(program_id: str, struct: str, field: Optional[str] = None,
                       functions: Optional[list[str]] = None, limit: int = 200) -> dict:
        """Where a struct or union, or one of its fields, is used (Ghidra's Find Uses of), from the decompiled C
        of every function or those listed (addresses or names). struct: its name ("struct node", "node") or hash;
        field: its name or offset ("0x10"), or omit it for every use of the type (its fields, and the type named
        in declarations and casts). Each use: the function, line (0-based) and text, kind "field" or "type",
        and for a field its name, offset and access ("read", "write", "read_write", "address"). Decompiling
        every function of a large program takes minutes the first time (results are cached)."""
        prog = rk.program(program_id)
        uses = prog.find_type_uses(struct, field, functions=[at(program_id, f) for f in functions] if functions else None,
                                   max_results=max(1, min(limit, 10000)))
        last_msg = prog.last_search
        kinds = {query_pb2.TYPE_USE_KIND_FIELD: "field", query_pb2.TYPE_USE_KIND_TYPE: "type"}
        access = {query_pb2.FIELD_ACCESS_READ: "read", query_pb2.FIELD_ACCESS_WRITE: "write",
                  query_pb2.FIELD_ACCESS_READ_WRITE: "read_write", query_pb2.FIELD_ACCESS_ADDRESS: "address"}
        out = []
        for u in uses:
            e = {"function": _hex(u.function.offset), "function_name": u.function_name, "line": u.line,
                 "text": u.text, "kind": kinds.get(u.kind, "?")}
            if u.HasField("address"):
                e["address"] = _hex(u.address.offset)
            if u.kind == query_pb2.TYPE_USE_KIND_FIELD:
                e["field"] = u.field_name
                if u.HasField("field_offset"):
                    e["offset"] = _hex(u.field_offset)
                if u.access in access:
                    e["access"] = access[u.access]
            out.append(e)
        return {"truncated": bool(last_msg and last_msg.truncated),
                **({"more": "more uses: raise limit, or pass functions (addresses or names)"}
                   if last_msg and last_msg.truncated else {}),
                "functions_searched": last_msg.functions_done if last_msg else 0,
                "functions_failed": last_msg.functions_failed if last_msg else 0,
                "uses": out}

    @server.tool(annotations=READ)
    @guarded
    def function_graph(program_id: str, function_address: str, instructions: bool = True, max_blocks: int = 60,
                       block_offset: int = 0) -> dict:
        """A function's control-flow graph: basic blocks (start, end, and with instructions=true their
        instructions) and typed edges ("from->to kind"), max_blocks blocks from block_offset (with the edges
        leaving them; "more" says where the rest start). instructions=false gives the shape of a big function
        cheaply."""
        prog = rk.program(program_id)
        req = query_pb2.GetFunctionGraphRequest(program_id=program_id, function=_address(at(program_id, function_address)),
                                                containing=True, read=prog._read(), omit_bytes=True)
        g = prog._q("GetFunctionGraph", req)
        block_offset = max(0, block_offset)
        page = range(block_offset, min(len(g.blocks), block_offset + max(1, max_blocks)))
        blocks = []
        for i in page:
            b = g.blocks[i]
            block = {"block": i, "start": _hex(b.range.first.offset), "end": _hex(b.range.last.offset)}
            if instructions:
                block["instructions"] = [f"{_hex(r.address.offset)}  {''.join(t.text for t in r.tokens)}" for r in b.rows]
            blocks.append(block)
        edges = [f"{e.from_block}->{e.to_block} "
                 + query_pb2.FlowEdgeKind.Name(e.kind).removeprefix("FLOW_EDGE_KIND_").lower()
                 for e in g.edges if e.from_block in page]
        out = {"function": g.function.name, "entry": _hex(g.function.entry.offset), "entry_block": g.entry_block,
               "block_count": len(g.blocks), "blocks": blocks, "edges": edges, "truncated": g.truncated}
        if page.stop < len(g.blocks):
            out.update(_more(f"blocks {page.start}-{page.stop - 1} of {len(g.blocks)}: call again with "
                             f"block_offset={page.stop} for the rest", next_block_offset=page.stop))
        return out

    def _calls(program_id: str, function_address: str, callers_of: bool, limit: int) -> dict:
        prog = rk.program(program_id)
        fn = prog.function(at(program_id, function_address), containing=True)
        seen, out = set(), []
        if callers_of:
            refs = prog.xrefs(fn.entry.offset, direction="to")
        else:
            ranges = list(fn.body) or []
            refs = (x for r in ranges for x in prog.xrefs(range=(r.first.offset, r.last.offset), direction="from"))
        for x in refs:
            if x.kind not in (listing_pb2.XREF_KIND_CALL, listing_pb2.XREF_KIND_JUMP) and callers_of:
                continue
            if not callers_of and x.kind != listing_pb2.XREF_KIND_CALL:
                continue
            key = (x.from_function.offset, x.from_address.offset) if callers_of else x.to_address.offset
            if key in seen:
                continue
            seen.add(key)
            out.append({"function": _hex(x.from_function.offset), "name": x.from_function_name, "at": _hex(x.from_address.offset)}
                       if callers_of else {"function": _hex(x.to_address.offset), "name": x.to_name, "at": _hex(x.from_address.offset)})
            if len(out) >= limit:
                break
        result = {"function": fn.name, "entry": _hex(fn.entry.offset), "callers" if callers_of else "callees": out,
                  "truncated": len(out) >= limit}
        if result["truncated"]:
            result["more"] = (f"the first {limit}: raise limit" + (", or page through xrefs to the entry (kind "
                                                                 "\"call\") with offset" if callers_of else ""))
        return result

    @server.tool(annotations=READ)
    @guarded
    def callers(program_id: str, function_address: str, limit: int = 200) -> dict:
        """The call sites that call a function (calling function and address)."""
        return _calls(program_id, function_address, True, limit)

    @server.tool(annotations=READ)
    @guarded
    def callees(program_id: str, function_address: str, limit: int = 200) -> dict:
        """The functions a function calls (one per target, with a call site)."""
        return _calls(program_id, function_address, False, limit)

    @server.tool(annotations=READ)
    @guarded
    def find_types(program_id: str, name_contains: str = "", limit: int = 100, offset: int = 0, category: str = "",
                   enum_value: Optional[Union[int, str]] = None) -> dict:
        """Types by name (the program's own and library archives'), a page at a time (limit, then offset): name,
        kind, hash (for get_type), C display and the category (folder, "/net/http") the program files it under;
        `category` keeps only those in it or below. enum_value ("0xa", 10) finds the enums with a member of that
        value instead (for set_equate's enum)."""
        out, n = [], 0
        prog = rk.program(program_id)
        by_value = enum_value not in (None, "")
        found = prog.enums_with_value(enum_value) if by_value else prog.find_types(name_contains, category=category)
        for t in found:
            if by_value and name_contains.lower() not in t.name.lower():
                continue
            n += 1
            if n <= offset:
                continue
            if len(out) >= max(1, limit):
                return {"types": out, "offset": offset,
                        **_more(f"more types: call again with offset={offset + len(out)}", next_offset=offset + len(out))}
            d = {k: v for k, v in _d(t).items()
                 if k in ("hash", "name", "kind", "display", "size", "bound", "source", "category", "project")}
            if "kind" in d:
                d["kind"] = str(d["kind"]).removeprefix("TYPE_KIND_").lower()
            out.append(d)
        return {"types": out, "offset": offset, "truncated": False}

    @server.tool(annotations=READ)
    @guarded
    def export_type_archive(program_id: str, names: Optional[list[str]] = None, category: str = "",
                            scope: str = "", name: str = "") -> dict:
        """A set of the program's types as a type archive: a self-contained C header (with #pragma pack and a
        _Static_assert of every size) and a JSON sidecar of content hashes, categories and the data model.
        Which types: `names` ("struct foo"), a `category` ("/net" and below), or `scope` "user" (made, edited
        or imported in revkit; the default) or "all"; what they reference comes along. Import the two texts
        into another program with import_type_archive (also readable by Ghidra's C parser)."""
        r = rk.program(program_id).export_type_archive(names or (), scope=scope, category=category, name=name)
        return {
            "header_name": r.header_name,
            "header": r.header,
            "sidecar_name": r.sidecar_name,
            "sidecar": r.sidecar,
            "types": [t.key for t in r.archive.types],
            "notes": list(r.notes),
            "mismatches": r.mismatches,
        }

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def export_c(program_id: str, function_addresses: Optional[list[str]] = None, header: bool = True,
                 directory: str = "", file_name: str = "") -> dict:
        """Ghidra's C/C++ exporter: functions (function_addresses; default every one) decompiled into one .c
        file in address order and, with header, a .h of the program's types, Ghidra's built-in type names and
        each function's prototype. With directory (on this MCP server's machine), both files are written
        there and only their paths and counts come back; without it the texts come back when the source is
        at most 200 kB (else an error asking for a directory). file_name: the files' name without the
        extension (default the program's)."""
        prog = rk.program(program_id)
        entries = [at(program_id, a) for a in function_addresses] if function_addresses else None
        r = prog.export_c(entries, header=header, name=file_name, directory=directory or None)
        out = {"source_name": r.source_name, "functions": r.functions,
               "failed": [_hex(a) for a in r.failed][:50], "revision": r.revision}
        if r.header_name:
            out["header_name"] = r.header_name
        if r.notes:
            out["notes"] = r.notes[:20]
        if directory:
            import os
            out["source_path"] = os.path.join(directory, r.source_name)
            if r.header_name:
                out["header_path"] = os.path.join(directory, r.header_name)
            return out
        if len(r.source) + len(r.header) > 200_000:
            return {"error": f"the export is {len(r.source) + len(r.header):,} bytes: give a directory to write it to, "
                             "or fewer function_addresses", **out}
        out["source"] = r.source
        if r.header_name:
            out["header"] = r.header
        return out

    @server.tool(annotations=WRITE)
    @guarded
    def import_type_archive(program_id: str, header: str, sidecar: str, reason: str) -> dict:
        """Import a type archive (export_type_archive's header and sidecar, from this or another program):
        checked against the sidecar's hashes, then its types defined and bound by name where the program
        doesn't have them already, and filed under the archive's categories, as one edit. Importing the
        same archive again does nothing."""
        prog = rk.program(program_id)
        parsed = prog.parse_type_archive(header, sidecar)
        check = parsed.archive
        if check.mismatches or parsed.errors:
            return {"ok": False, "verified": check.verified, "types": check.types,
                    "mismatches": [m.key for m in check.mismatches][:50],
                    "diagnostics": [f"{d.file}:{d.line}:{d.column}: {d.text}" for d in parsed.diagnostics][:50]}
        imported = [n.key for n in parsed.named if n.existing_hash != n.hash or n.existing_library]
        resp = prog.import_type_archive(parsed, actor=None, session=session, reason=reason)
        if resp is None:
            return {"ok": True, "verified": check.verified, "types": check.types, "imported": [],
                    "note": "nothing to do: the program has every type already, filed as the archive files it"}
        return {"ok": True, "verified": check.verified, "types": check.types, "imported": imported,
                "revision": resp.snapshot.revision, "seqs": [a.seq for a in resp.assertions],
                "provenance": format_provenance(resp.assertions[0].provenance)}

    @server.tool(annotations=WRITE)
    @guarded
    def set_type_category(program_id: str, names: list[str], category: str, reason: str) -> dict:
        """File named types ("struct foo", "typedef bar_t") under a category: a folder path such as
        "/net/http" ("/" for the top). Categories organize the types view and archives; they don't change
        any type."""
        return write_result(rk.program(program_id).set_type_category(names, category, reason=reason))

    @server.tool(annotations=WRITE)
    @guarded
    def move_types_to_project(program_id: str, names: list[str], reason: str) -> dict:
        """Move named types ("struct foo") to project scope, with every type they reach, as one edit: every
        program of the project then sees one definition, and editing it (the project's) changes them all."""
        r = rk.program(program_id).move_types_to_project(names, actor=None, reason=reason)
        return {"ok": True, "types": [{"key": t.key, "hash": t.hash} for t in r.types], "records": r.records,
                "retracted": r.retracted, "revision": r.snapshot.revision}

    @server.tool(annotations=WRITE)
    @guarded
    def copy_types_to_program(program_id: str, names: list[str], reason: str) -> dict:
        """Copy project types ("struct foo") into one program, as one edit: the program's copy then wins over
        the project's, so it can change alone."""
        r = rk.program(program_id).copy_types_to_program(names, actor=None, reason=reason)
        return {"ok": True, "types": [{"key": t.key, "hash": t.hash} for t in r.types], "records": r.records,
                "revision": r.snapshot.revision}

    @server.tool(annotations=READ)
    @guarded
    def list_type_archives(program_id: str) -> dict:
        """The type archives whose prototypes and types the program's project applies: revkit's library
        archives (libc, the Windows API; `applies` to this program's format), Ghidra's ("ghidra") and those
        attached to the project, each enabled or not, with how many functions and types each gives it."""
        out = []
        for a in rk.program(program_id).type_archives():
            out.append({"name": a.name, "kind": types_pb2.TypeArchiveKind.Name(a.kind).removeprefix("TYPE_ARCHIVE_KIND_").lower(),
                        "enabled": a.enabled, "applies": a.applies, "functions": a.functions, "types": a.types,
                        "data_model": a.data_model, "origin": a.origin, "diagnostics": list(a.diagnostics)})
        return {"archives": out}

    @server.tool(annotations=WRITE)
    @guarded
    def set_type_archive(program_id: str, name: str, enabled: bool, reason: str) -> dict:
        """Turn a type archive (list_type_archives' name: "libc-lp64", "ghidra") on or off for every program
        of the project: its prototypes stop or start applying to imports by name."""
        return write_result(rk.program(program_id).set_type_archive_enabled(name, enabled, actor=None, reason=reason))

    @server.tool(annotations=READ)
    @guarded
    def get_type(program_id: str, type_hash: str) -> dict:
        """One type by hash (from find_types, decompile's fields or a variable): its C definition and fields."""
        r = rk.program(program_id).types(type_hash, dependencies=False)
        return {"types": [_d(t) for t in r.types], "missing": list(r.missing)}

    @server.tool(annotations=READ)
    @guarded
    def list_plugins() -> dict:
        """The daemon's plugins (analyzers, commands, loaders) and each command's arguments."""
        return {"plugins": [_d(p) for p in rk.plugins()]}

    @server.tool(annotations=READ)
    @guarded
    def plugin_facts(program_id: str, plugin: str = "", first: str = "", last: str = "", limit: int = 200) -> dict:
        """What analyzer plugins found (all of them, or one), optionally in an address range."""
        r = rk.program(program_id).plugin_facts(*([plugin] if plugin else []), first=at(program_id, first) if first else None,
                                                last=at(program_id, last) if last else None)
        d = _d(r)
        facts = d.get("facts", [])
        return {"facts": facts[:limit], "truncated": len(facts) > limit, "errors": d.get("errors", [])}

    @server.tool(annotations=READ)
    @guarded
    def analysis_status(program_id: str) -> dict:
        """Whether analysis of a program is running, and its jobs."""
        return _d(rk.program(program_id).analysis_status())

    @server.tool(annotations=READ)
    @guarded
    def list_my_changes(program_id: str, include_inactive: bool = False, limit: int = 100, offset: int = 0) -> dict:
        """The edits this MCP session made to a program (seq, what, status, reason), oldest first, a page at a
        time (limit, then offset), for review or undo (undo_changes with their seqs)."""
        mine = list(rk.program(program_id).assertions(actor=f"agent:{agent}", session=session,
                                                      include_inactive=include_inactive))
        page = mine[max(0, offset):max(0, offset) + max(1, limit)]
        out = {"changes": [_d(a) for a in page], "total": len(mine), "offset": offset, "truncated": False}
        if offset + len(page) < len(mine):
            out.update(_more(f"{len(mine)} changes: call again with offset={offset + len(page)}",
                             next_offset=offset + len(page)))
        return out

    @server.tool(annotations=READ)
    @guarded
    def list_languages(name_contains: str = "", limit: int = 100) -> dict:
        """Processor languages the daemon can load (for import_program's language_id on a raw image)."""
        r = rk._call(rk.stubs.projects.ListLanguages, project_pb2.ListLanguagesRequest())
        want = name_contains.lower()
        out = [_d(l) for l in r.languages if want in l.language_id.lower() or want in l.description.lower()]
        return {"languages": out[:limit], "truncated": len(out) > limit}

    def _parse_status(n) -> str:
        if not n.existing_hash:
            return "new"
        return "identical" if n.existing_hash == n.hash else "replaces"

    @server.tool(annotations=READ)
    @guarded
    def parse_c(program_id: str, c_text: str, prototypes: bool = False, defines: Optional[list[str]] = None) -> dict:
        """Parse C declarations (a header, or a struct to paste) for the program's target, without changing
        anything: each named type with its size, C definition and status (new, replaces the program's
        definition, or identical), function prototypes, #define constants and line-numbered diagnostics.
        Types the program already has (find_types) can be used by name. Import with import_header."""
        prog = rk.program(program_id)
        r = prog.parse_c(c_text, name="input.h", prototypes=prototypes, defines=defines or ())
        conflicts = {c.named_key: c for c in r.conflicts}
        out = []
        for n in r.named:
            d = {"key": n.key, "hash": n.hash, "status": _parse_status(n), "line": n.line}
            if n.key in conflicts:
                d["same_layout"] = conflicts[n.key].same_layout
            out.append(d)
        return {
            "profile": r.profile,
            "types": out,
            "prototypes": [p.declaration for p in r.prototypes],
            "constants": {c.name: c.value for c in r.constants},
            "diagnostics": [f"{d.file}:{d.line}:{d.column}: {d.text}" for d in r.diagnostics][:50],
            "errors": r.errors,
        }

    # -- more writes (always agent provenance) ---------------------------------------

    @server.tool(annotations=WRITE)
    @guarded
    def import_header(program_id: str, c_text: str, reason: str, names: Optional[list[str]] = None) -> dict:
        """Define the types C declarations declare and make them the program's (by name, so every use of a
        name shows the new definition): all new or changed ones, or just `names` ("struct foo"). One edit,
        undone with undo_changes on its seqs or revert_my_changes. Then retype functions and variables with them."""
        prog = rk.program(program_id)
        parsed = prog.parse_c(c_text, name="input.h")
        if parsed.errors:
            return {"ok": False, "diagnostics": [f"{d.file}:{d.line}:{d.column}: {d.text}" for d in parsed.diagnostics][:50]}
        resp = prog.import_header(parsed, names, file="input.h", actor=None, session=session, reason=reason,
                                  categories="none")
        bound = [n.key for n in parsed.named if (names is None or n.key in names) and n.existing_hash != n.hash
                 and not n.system]
        return {"ok": True, "revision": resp.snapshot.revision, "bound": bound,
                "seqs": [a.seq for a in resp.assertions], "provenance": format_provenance(resp.assertions[0].provenance)}

    @server.tool(annotations=WRITE)
    @guarded
    def retype(program_id: str, address: str, c_declaration: str, reason: str) -> dict:
        """Set the type of a global, or a function's prototype, from a C declaration
        ("int counter", "char *name[4]", "int parse(const char *s, size_t n)"). Types named in it must exist
        (find_types), or be imported first (import_header)."""
        return write_result(rk.program(program_id).retype(at(program_id, address), c_declaration, reason=reason))

    @server.tool(annotations=WRITE)
    @guarded
    def retype_variable(program_id: str, function_address: str, storage_key: str, c_declaration: str, reason: str) -> dict:
        """Set a parameter's or local's type from a C declaration; storage_key comes from decompile's variables."""
        return write_result(rk.program(program_id).retype_local(at(program_id, function_address), storage_key, c_declaration, reason=reason))

    def _field_result(resp, info) -> dict:
        # The binding of the struct's name is what makes the new version the program's.
        bind = next((a for a in resp.assertions if a.body.WhichOneof("kind") == "bind_type_name"), resp.assertions[0])
        out = write_result(assertion_pb2.AppendAssertionsResponse(snapshot=resp.snapshot, assertions=[bind]))
        if bind.status == assertion_pb2.ASSERTION_STATUS_SHADOWED:
            out["note"] = (f"SHADOWED: {info['key']} was defined by a user or an import, which outranks an agent, so "
                           "the program still uses their definition; ask the user to make the change, and undo_changes "
                           "these seqs")
        out.update(seqs=[a.seq for a in resp.assertions], struct=info["key"], field=info["field"],
                   offset=_hex(info["offset"]), c_definition=info["c_definition"])
        return out

    @server.tool(annotations=WRITE)
    @guarded
    def rename_field(program_id: str, struct: str, field: str, new_name: str, reason: str) -> dict:
        """Rename a field of a struct or union, everywhere the struct is used (the decompiler shows
        p->new_name). struct: its name ("lua_State", "struct node", or a typedef of it) or its hash (decompile's
        fields give struct_hash, find_types gives hash); field: its name, or its offset ("0x10") when one field
        starts there. One edit: the struct's new version (undo_changes on the seqs). Returns the struct's new C."""
        prog = rk.program(program_id)
        bodies, info = prog.field_edit_bodies(struct, field,
                                              name=new_name)
        return _field_result(prog.append(*bodies, reason=reason), info)

    @server.tool(annotations=WRITE)
    @guarded
    def retype_field(program_id: str, struct: str, field: str, c_type: str, reason: str) -> dict:
        """Set the type of a field of a struct or union from C ("char *", "struct node *", "uint8_t[16]",
        "int (*)(void *)"), everywhere the struct is used. struct and field as rename_field takes them. The other
        fields keep their offsets: a type that would overlap the next field or end past the struct is refused
        (retype that field first, or redefine the struct with parse_c and import_header). Types named in it must
        exist (find_types) or be imported first. One edit (undo_changes on the seqs). Returns the struct's new C."""
        prog = rk.program(program_id)
        bodies, info = prog.field_edit_bodies(struct, field,
                                              type=c_type)
        return _field_result(prog.append(*bodies, reason=reason), info)

    @server.tool(annotations=WRITE)
    @guarded
    def override_call_signature(program_id: str, call_address: str, prototype: str, reason: str) -> dict:
        """Override the prototype one call uses (Ghidra's Override Signature), for a call to a varargs function
        (printf-like: the arguments this call passes) or one whose callee's prototype is wrong for it, or a
        computed call: prototype is C, "int sum(int n, int a, int b)" (the name is ignored; types must exist).
        call_address is the call instruction (decompile's tokens and disassemble give addresses). The
        decompiler takes it for that call alone. Pass prototype "" to remove the override (Ghidra's Remove
        Signature Override). Undo with undo_changes."""
        prog = rk.program(program_id)
        a = at(program_id, call_address)
        if prototype.strip():
            r = prog.override_call_signature(a, prototype, reason=reason)
        else:
            r = prog.remove_call_signature(a, reason=reason)
        return {**write_result(r), "call_signature": prog.call_signature(a)}

    @server.tool(annotations=WRITE)
    @guarded
    def create_function(program_id: str, address: str, reason: str) -> dict:
        """Declare that a function starts at an address (its body is discovered)."""
        return write_result(rk.program(program_id).set_function(at(program_id, address), reason=reason))

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False))
    @guarded
    def remove_function(program_id: str, address: str, reason: str) -> dict:
        """Declare that no function starts at an address (undo with undo_changes)."""
        return write_result(rk.program(program_id).remove_function(at(program_id, address), reason=reason))

    @server.tool(annotations=WRITE)
    @guarded
    def set_flow_override(program_id: str, address: str, kind: str, reason: str) -> dict:
        """Override an instruction's flow: kind "call", "call_return" (a call that does not return), "jump" (a
        branch), "return" or "none" (as decoded)."""
        _choice("kind", kind, ("call", "call_return", "jump", "branch", "return", "none"))
        return write_result(rk.program(program_id).flow_override(at(program_id, address),
                                                                 "branch" if kind == "jump" else kind, reason=reason))

    @server.tool(annotations=WRITE)
    @guarded
    def set_fallthrough(program_id: str, address: str, reason: str, target: str = "", no_fallthrough: bool = False,
                        clear: bool = False) -> dict:
        """Set where control goes on after an instruction (Ghidra's Set Fallthrough): target, instead of the next
        instruction (inline data after a call, a jump over junk); no_fallthrough, nowhere; clear, back to its own
        (Clear Fallthrough). Function bodies, the listing, the function graph, references and the decompiler (a
        branch to target) follow it."""
        if sum((bool(target), no_fallthrough, clear)) != 1:
            raise ValueError("give one of target, no_fallthrough or clear")
        prog = rk.program(program_id)
        a = at(program_id, address)
        if clear:
            return write_result(prog.clear_fallthrough(a, reason=reason))
        return write_result(prog.set_fallthrough(a, None if no_fallthrough else at(program_id, target), reason=reason))

    @server.tool(annotations=WRITE)
    @guarded
    def set_no_return(program_id: str, function_address: str, no_return: bool, reason: str) -> dict:
        """Say whether a function returns (Ghidra's Set No-Return): true, calls to it end their caller's flow
        (function bodies, the listing and the decompiler stop after the call); false, it returns, even where
        analysis decided it doesn't (exit-like names, no path to a return)."""
        return write_result(rk.program(program_id).set_no_return(at(program_id, function_address), no_return, reason=reason))

    @server.tool(annotations=WRITE)
    @guarded
    def set_register_value(program_id: str, register: str, reason: str, value: str = "", first: str = "", last: str = "",
                           function_address: str = "", clear: bool = False) -> dict:
        """Say a register holds a constant over an address range (Ghidra's Set Register Values): MIPS gp, the
        PowerPC TOC (r2) or small data base (r13). Analysis's references and the decompiler then resolve
        register-relative loads to globals there. The range is first..last (last defaults to first) or a
        function's body (function_address); value is a number ("0x418ff0"). clear says the register has no
        value there instead (over analysis's own, such as the loader's _gp). One undo step (undo_changes with
        seqs)."""
        p = rk.program(program_id)
        kw = {"function": at(program_id, function_address)} if function_address else {}
        lo = at(program_id, first) if first else None
        hi = at(program_id, last) if last else None
        if clear:
            resp = p.clear_register_value(register, lo, hi, reason=reason, **kw)
        elif not value:
            raise ValueError("value is required (or clear)")
        else:
            resp = p.set_register_value(register, int(value, 0), lo, hi, reason=reason, **kw)
        # A function's body may be several ranges: one assertion each, one revision.
        return {**write_result(resp), "seqs": [a.seq for a in resp.assertions]}

    @server.tool(annotations=READ)
    @guarded
    def list_register_values(program_id: str, register: str = "", first: str = "", last: str = "", limit: int = 200) -> dict:
        """Register values over address ranges (Ghidra's register manager): each range with its register,
        value and who set it ("analysis:mips-gp" for the loader's _gp, else the assertion's author); optionally
        one register and ranges overlapping first..last. Also the registers values can be set on."""
        p = rk.program(program_id)
        lo = at(program_id, first) if first else None
        hi = at(program_id, last) if last else None
        out = []
        for r in p.register_values(register, first=lo, last=hi, page_size=min(max(limit, 1), 1000)):
            if r.origin.HasField("derived"):
                who = "analysis:" + r.origin.derived.rule.split(":", 1)[-1]
            else:
                who = format_provenance(r.origin.asserted.provenance)
            out.append({"register": r.register_name, "first": _hex(r.range.first.offset), "last": _hex(r.range.last.offset),
                        "value": _hex(r.value), "set_by": who})
            if len(out) >= limit:
                break
        return {"ranges": out, "registers": [r.name for r in p.value_registers()]}

    @server.tool(annotations=READ)
    @guarded
    def compare_languages(program_id: str, language_ids: list[str] | None = None) -> dict:
        """Which processor variant fits the program's code (ARM v4T/v5/v7/v8, Thumb or ARM mode, ...): each
        variant in the program's byte order swept over samples of its executable bytes, with the share
        decoded, invalid and unimplemented instructions, and the code control flow reaches. The variant
        auto-detection picks is "recommended", with why. language_ids compares others. set_language
        switches."""
        r = rk.program(program_id).compare_languages(language_ids)
        fits = [
            {
                "language_id": f.language_id,
                "mode": f.mode or "default",
                "current": f.current,
                "recommended": f.recommended,
                "can_switch": f.compatible,
                "decoded": round(f.decoded, 4),
                "instructions": f.instructions,
                "invalid": f.invalid,
                "unimplemented": f.unimplemented,
                "reached": f.reached,
                "reached_cut_short": f.reached_invalid,
                **({"note": f.note} if f.note else {}),
            }
            for f in r.fits
        ]
        return {"fits": fits, "bytes_swept": r.bytes, "samples": r.samples, "seconds": round(r.elapsed_seconds, 2)}

    @server.tool(annotations=WRITE)
    @guarded
    def set_language(program_id: str, language_id: str, reason: str, compiler_spec_id: str = "") -> dict:
        """Change the language the program is decoded and analyzed in (Ghidra's Set Language): same bytes and
        addresses, every name, comment and type kept, analysis run again. language_id "" goes back to the
        imported language. Only between languages with the same memory layout (e.g. ARM variants);
        compare_languages first to pick one. Undo with undo_changes on the returned seq."""
        r = rk.program(program_id).set_language(language_id, compiler_spec_id, reason=reason)
        out = {
            "ok": True,
            "language_id": r.language_id or "(as imported)",
            "compiler_spec_id": r.compiler_spec_id,
            "previous_language_id": r.previous_language_id,
            "previous_compiler_spec_id": r.previous_compiler_spec_id,
            "revision": r.snapshot.revision,
        }
        if r.HasField("assertion"):
            out["seq"] = r.assertion.seq
        else:
            out["note"] = "already in that language: nothing changed"
        return out

    @server.tool(annotations=WRITE)
    @guarded
    def add_note(program_id: str, address: str, text: str, reason: str, tag: str = "") -> dict:
        """Attach a note (a finding, a question, a to-do) to an address; empty text clears it."""
        return write_result(rk.program(program_id).note(at(program_id, address), text, tag=tag, reason=reason))

    # -- what bytes are, from the listing (api_minor 30, feature "listing-edit") ------

    def listing_edit_of(resp: assertion_pb2.AppendAssertionsResponse) -> assertion_pb2.Assertion:
        # The edit itself; a define_data that parsed a type also has that type's TYPE_DEF assertions.
        return next((a for a in resp.assertions if a.body.WhichOneof("kind") in ("listing_edit", "mutability")),
                    resp.assertions[0])

    def listing_result(resp: assertion_pb2.AppendAssertionsResponse) -> dict:
        edit = listing_edit_of(resp)
        out = write_result(assertion_pb2.AppendAssertionsResponse(snapshot=resp.snapshot, assertions=[edit]))
        out["seqs"] = [a.seq for a in resp.assertions]  # undo_changes takes them all
        return out

    @server.tool(annotations=WRITE)
    @guarded
    def define_data(program_id: str, address: str, reason: str, type: str = "", count: int = 0, string: str = "",
                    layout: str = "", collapsed: Optional[bool] = None) -> dict:
        """Define a data item at an address, as Ghidra's Data menu: type is C ("uint32_t", "struct hdr",
        "char *") or a builtin ("byte", "word", "dword", "qword", "float", "double", "pointer"); count > 0
        makes an array of that many. For a string give string "utf8", "utf16" or "utf32" (type is then
        ignored) and layout "terminated" (default), "fixed" (count characters), "pascal" or "pascal16".
        collapsed: one row, or a row per field. Undo with undo_changes on every seq returned."""
        r = rk.program(program_id).define_data(at(program_id, address), type or None, count=count, string=string or None,
                                               layout=layout or None, collapsed=collapsed, reason=reason)
        out = listing_result(r)
        d = listing_edit_of(r).body.listing_edit.data
        out.update(size=d.size, type_name=d.type_name, type_hash=d.type_hash)
        return out

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False))
    @guarded
    def clear_code(program_id: str, address: str, reason: str, length: int = 1) -> dict:
        """Clear length bytes from an address back to undefined (Ghidra's Clear Code Bytes): instructions,
        data and functions starting there go, and analysis puts nothing there again until disassemble_here
        or define_data. Undo with undo_changes."""
        return listing_result(rk.program(program_id).clear_code(at(program_id, address), length, reason=reason))

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False))
    @guarded
    def clear_flow(program_id: str, address: str, reason: str, follow_calls: bool = False, dry_run: bool = False) -> dict:
        """Ghidra's Clear Flow and Repair: clear the code the flow from an instruction reaches (fallthrough,
        branches, jumps, jump tables) that no other code reaches; what other code reaches stays code. With
        follow_calls, also the functions only this flow calls. Functions whose entry is cleared go. dry_run
        returns the plan (ranges, counts, functions) without clearing. Undo with undo_changes on every seq
        returned (one revision)."""
        prog = rk.program(program_id)
        a = at(program_id, address)
        plan = prog.plan_clear_flow(a, follow_calls=follow_calls)
        out = {"ranges": [{"address": _hex(r.address.offset), "length": r.length} for r in plan.ranges][:200],
               "instructions": plan.instructions, "kept": plan.kept,
               "functions": [_hex(f.offset) for f in plan.functions]}
        if dry_run or not plan.ranges:
            out["dry_run"] = dry_run
            return out
        from revkit.client import clear_code_body
        resp = prog.append(*(clear_code_body(r.address.offset, r.length) for r in plan.ranges), reason=reason)
        out.update({"ok": True, "revision": resp.snapshot.revision, "seqs": [x.seq for x in resp.assertions]})
        return out

    @server.tool(annotations=WRITE)
    @guarded
    def disassemble_here(program_id: str, address: str, reason: str, isa: str = "", function: bool = False) -> dict:
        """Mark that code starts at an address and disassemble from there, following its flow (Ghidra's
        Disassemble), even over data or cleared bytes; isa "arm" or "thumb" where the language has both
        (default: as the context says); function true also makes it a function. Undo with undo_changes."""
        return listing_result(rk.program(program_id).disassemble(at(program_id, address), isa or None, function, reason=reason))

    @server.tool(annotations=WRITE)
    @guarded
    def set_mutability(program_id: str, address: str, length: int, mutability: str, reason: str) -> dict:
        """Mark length bytes from an address "constant" (the decompiler folds reads to the bytes' value),
        "volatile" (memory-mapped I/O: reads are never folded), "normal" (writable) or "default" (as the
        memory map says). Undo with undo_changes."""
        return listing_result(rk.program(program_id).set_mutability(at(program_id, address), length, mutability, reason=reason))

    @server.tool(annotations=WRITE)
    @guarded
    def set_data_settings(program_id: str, reason: str, address: str = "", field: str = "", type_name: str = "",
                          format: str = "", signed: Optional[bool] = None, endian: str = "", padding: str = "",
                          charset: str = "", termination: str = "", pointer: str = "", mask: Optional[str] = None,
                          shift: Optional[int] = None) -> dict:
        """Change how a defined data item displays in the listing (Ghidra's Data Settings): give address (the
        item; field a struct field's path such as "hdr.magic"), or type_name instead for that type's default
        settings (every row of the type, e.g. "uint32_t", "string", "pointer", "undefined4"). format "hex",
        "decimal", "octal", "binary" or "char"; signed true/false; endian "little" or "big"; padding "padded"
        or "unpadded"; charset for strings ("US-ASCII", "ISO-8859-1", "windows-1252", "UTF-8", "UTF-16",
        "UTF-16LE", "UTF-16BE", "UTF-32", "UTF-32LE", "UTF-32BE"); termination "nul" or "all"; pointer
        "absolute", "image-base" (an RVA) or "relative", after mask (hex) and shift. Empty leaves a setting
        to the type's default; none at all removes them. Display only: definitions, references and the
        decompiler don't change. Undo with undo_changes."""
        from revkit.client import data_settings_body
        if bool(address) == bool(type_name):
            raise ValueError("give address (an item's settings) or type_name (a type's default settings)")
        body = data_settings_body(at(program_id, address) if address else None, field=field, type_name=type_name,
                                  format=format or None, signed=signed, endian=endian or None, padding=padding or None,
                                  charset=charset or None, termination=termination or None, pointer=pointer or None,
                                  mask=int(mask, 16) if mask else None, shift=shift)
        resp = rk.program(program_id).append(body, reason=reason)
        out = write_result(resp)
        out["seqs"] = [a.seq for a in resp.assertions]
        return out

    # -- equates and user references (api_minor 39, features "equates", "user-references") --

    def seqs_result(resp: assertion_pb2.AppendAssertionsResponse) -> dict:
        out = write_result(resp)
        out["seqs"] = [a.seq for a in resp.assertions]  # undo_changes takes them all
        return out

    def display_result(resp: assertion_pb2.AppendAssertionsResponse) -> dict:
        out = seqs_result(resp)
        out["operands"] = [{"address": _hex(a.body.operand_display.address.offset),
                            "operand": a.body.operand_display.operand_index} for a in resp.assertions
                           if a.body.operand_display.HasField("operand_index")]
        return out

    def _operand(operand: Optional[int]) -> Optional[int]:
        return None if operand is None or operand < 0 else operand

    @server.tool(annotations=WRITE)
    @guarded
    def convert_operand(program_id: str, address: str, value: Union[int, str], format: str, reason: str,
                        operand: Optional[int] = None, apply_to: str = "") -> dict:
        """Show a scalar operand of an instruction in another format, as Ghidra's Convert menu: format "hex",
        "signed", "unsigned", "octal", "binary", "char" ('A') or "float" (32/64-bit scalars), or "default"
        (as the disassembler prints it; clears a conversion or an equate). value is the scalar as the
        listing shows it ("0x41", "-16"); operand is its index (default: the operand holding the value).
        apply_to "function" or "program" converts every operand holding the value there too. The listing
        and the decompiler both show it. Undo with undo_changes on every seq returned."""
        return display_result(rk.program(program_id).convert(at(program_id, address), value, format, operand=_operand(operand),
                                                             apply_to=apply_to or None, reason=reason))

    @server.tool(annotations=WRITE)
    @guarded
    def set_equate(program_id: str, address: str, value: Union[int, str], reason: str, name: str = "", enum: str = "",
                   member: str = "", operand: Optional[int] = None, apply_to: str = "") -> dict:
        """Name a scalar operand of an instruction (Ghidra's Set Equate): it shows as `name` in the listing and
        the decompiler (O_RDONLY, SIGINT, SYS_getpid). Or give enum (a C enum's name, from find_types with
        enum_value) and member to show an enum member. One name has one value program-wide. value is the
        scalar ("0x41", "-16"); operand its index (default: the operand holding it); apply_to "function" or
        "program" names every operand holding the value there too. Undo with undo_changes on every seq."""
        prog = rk.program(program_id)
        if enum or member:
            r = prog.set_enum_equate(at(program_id, address), value, enum, member, operand=_operand(operand),
                                     apply_to=apply_to or None, reason=reason)
        elif name:
            r = prog.set_equate(at(program_id, address), value, name, operand=_operand(operand), apply_to=apply_to or None,
                                reason=reason)
        else:
            return {"error": "INVALID_ARGUMENT", "message": "give a name, or an enum and member"}
        return display_result(r)

    @server.tool(annotations=READ)
    @guarded
    def list_equates(program_id: str, name_contains: str = "", limit: int = 100, offset: int = 0) -> dict:
        """The program's equates (Ghidra's Equates table), a page at a time (limit, then offset): each name, its
        value, the enum member it is (if any) and every operand showing it (address, operand index, the seq
        that set it)."""
        out = []
        found = [e for e in rk.program(program_id).equates().values() if name_contains.lower() in e.name.lower()]
        page = found[max(0, offset):max(0, offset) + max(1, limit)]
        for e in page:
            d = {"name": e.name, "value": _hex(e.value),
                 "references": [{"address": _hex(r.address), "operand": r.operand_index, "seq": r.seq}
                                for r in e.references]}
            if e.enum_type_hash:
                d.update(enum_type_hash=e.enum_type_hash, member=e.member)
            out.append(d)
        result = {"equates": out, "total": len(found), "offset": offset, "truncated": False}
        if offset + len(page) < len(found):
            result.update(_more(f"{len(found)} equates: call again with offset={offset + len(page)}",
                                next_offset=offset + len(page)))
        return result

    @server.tool(annotations=WRITE)
    @guarded
    def rename_equate(program_id: str, name: str, new_name: str, reason: str) -> dict:
        """Rename an equate at every operand that shows it, as one edit (undo_changes on its seqs)."""
        return seqs_result(rk.program(program_id).rename_equate(name, new_name, reason=reason))

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False))
    @guarded
    def remove_equate(program_id: str, name: str, reason: str) -> dict:
        """Remove an equate everywhere: its operands show the disassembler's numbers again (one edit; undo
        with undo_changes on its seqs)."""
        return seqs_result(rk.program(program_id).remove_equate(name, reason=reason))

    @server.tool(annotations=WRITE)
    @guarded
    def add_reference(program_id: str, from_address: str, to_address: str, type: str, reason: str,
                      operand: Optional[int] = None, primary: bool = False) -> dict:
        """Add a reference from an instruction to an address, where analysis missed it (Ghidra's References >
        Add): type "data", "read", "write", "call", "jump", "computed_call" (an indirect call's target: it
        becomes a function) or "computed_jump" (a switch case). operand is the operand's index (default: the
        instruction as a whole). primary shows the operand as the target's name; a primary computed_call
        makes the decompiler call the target directly. xrefs lists it. Undo with undo_changes."""
        return seqs_result(rk.program(program_id).add_reference(at(program_id, from_address), at(program_id, to_address), type,
                                                                operand=_operand(operand), primary=primary,
                                                                reason=reason))

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False))
    @guarded
    def remove_reference(program_id: str, from_address: str, to_address: str, reason: str,
                         operand: Optional[int] = None) -> dict:
        """Delete the references from an instruction to an address (a wrong one analysis made, or one added
        with add_reference): they leave xrefs (a function analysis found stays). Undo with undo_changes."""
        return seqs_result(rk.program(program_id).remove_reference(at(program_id, from_address), at(program_id, to_address),
                                                                   operand=operand, reason=reason))

    @server.tool(annotations=WRITE)
    @guarded
    def set_primary_reference(program_id: str, from_address: str, to_address: str, reason: str,
                              primary: bool = True, operand: Optional[int] = None) -> dict:
        """Make an existing reference its operand's primary one (the operand shows the target's name; on an
        indirect call the decompiler calls the target), or not (primary false). Undo with undo_changes."""
        return seqs_result(rk.program(program_id).set_primary_reference(
            at(program_id, from_address), at(program_id, to_address), operand=operand, primary=primary, reason=reason))

    # -- structures from pointer use and from data (api_minor 32, feature "auto-struct") --

    def structure_result(made, applied=None) -> dict:
        out = {
            "name": made.name,
            "size": made.size,
            "c_definition": made.c_definition,
            "fields": [{"offset": hex(f.offset), "size": f.size, "name": f.name, "type": f.type_display,
                        "source": types_pb2.AutoStructureFieldSource.Name(f.source).removeprefix("AUTO_STRUCTURE_FIELD_SOURCE_").lower(),
                        "accesses": f.accesses} for f in made.fields][:200],
            "functions_read": len(made.functions),
            "notes": list(made.notes),
            "unchanged": made.unchanged,
        }
        if applied is not None:
            out.update(ok=True, revision=applied.snapshot.revision, seqs=[a.seq for a in applied.assertions],
                       provenance=format_provenance(applied.assertions[0].provenance))
        return out

    @server.tool(annotations=WRITE)
    @guarded
    def auto_structure(program_id: str, function_address: str, storage_key: str, reason: str, fill: bool = False,
                       call_depth: int = 1, name: str = "", apply: bool = False) -> dict:
        """A structure from how a pointer variable is used (Ghidra's Auto Create Structure; fill=true: Auto Fill in
        Structure, adding fields to the struct it already points to). storage_key comes from decompile's
        variables. Fields are field_0x<offset>, undefinedN or a pointer/int/float type where the code says, from
        loads and stores through the variable here and, call_depth calls deep, in the functions it is passed to.
        apply=false previews; apply=true defines the struct, binds its name and retypes the variable in one edit
        (undo_changes on the seqs)."""
        prog = rk.program(program_id)
        made = prog.auto_structure(at(program_id, function_address), storage_key, fill=fill, call_depth=call_depth, name=name)
        if not apply or made.unchanged:
            return structure_result(made)
        r = prog.apply_structure(made, function=at(program_id, function_address), storage_key=storage_key, reason=reason)
        return structure_result(made, r)

    @server.tool(annotations=WRITE)
    @guarded
    def create_structure(program_id: str, first: str, last: str, reason: str, name: str = "", apply: bool = False) -> dict:
        """A structure of the data defined in [first, last] (fields from the data items there, undefined filler
        elsewhere), as Ghidra's Create Structure on a listing selection. apply=true defines it, binds its name and
        defines it at first in one edit (undo_changes on the seqs)."""
        prog = rk.program(program_id)
        made = prog.structure_from_range(at(program_id, first), at(program_id, last), name=name)
        if not apply:
            return structure_result(made)
        return structure_result(made, prog.apply_structure(made, at=at(program_id, first), reason=reason))

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False))
    @guarded
    def undo_changes(program_id: str, seqs: list[int], reason: str) -> dict:
        """Retract specific assertions by seq (from a write's result or list_my_changes)."""
        r = rk.program(program_id).retract(*seqs, reason=reason)
        return {"ok": True, "revision": r.snapshot.revision}

    @server.tool(annotations=WRITE)
    @guarded
    def run_plugin_command(program_id: str, plugin: str, reason: str, args: Optional[dict] = None, dry_run: bool = True) -> dict:
        """Run a command plugin (list_plugins shows them and their arguments). dry_run (the default) returns
        the edits it would make without committing them; its edits are recorded as yours, with the plugin as the tool."""
        r = rk.program(program_id).run_command(plugin, args or {}, dry_run=dry_run, reason=reason)
        return _d(r)

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def import_program(project_id: str, path: str, name: str = "", language_id: str = "", image_base: str = "",
                       format: str = "", raw_offset: str = "", regions: Optional[list[str]] = None,
                       import_libraries: bool = False, library_search_paths: Optional[list[str]] = None,
                       library_root: str = "") -> dict:
        """Import a file on the daemon's host into a project (needs an admin token when the daemon has accounts).
        ELF and PE are detected; for raw firmware give format "raw", a language_id (list_languages, or
        detect_raw_layout's suggestion) and an image_base, and where they apply raw_offset (bytes of header
        before the image) and regions ("name:start:size[:perms][:init|uninit|volatile]", hex: RAM, MMIO).
        import_libraries also imports the shared libraries it needs that the project lacks (found in
        library_search_paths, beside the file and on its runpath, then the host's /lib and /usr/lib), two levels
        deep; the result lists them and the ones found nowhere. library_root names the root file system they
        are in instead of the host's (a directory under the daemon's --browse-root, an extracted firmware root);
        a file inside such a tree under a --browse-root uses it by itself (the result's library_root)."""
        r = rk.import_program(project_id, path=path, name=name, language_id=language_id,
                              image_base=_addr(image_base) if image_base else None, format=format,
                              raw_offset=_num(raw_offset) if raw_offset else 0, regions=regions or (),
                              import_libraries=import_libraries, library_search_paths=library_search_paths or (),
                              library_root=library_root)
        return _d(r)

    def _resolved(i) -> dict:
        out = {"name": i.name, "library": i.library, "resolved": i.resolved}
        if i.HasField("thunk"):
            out["thunk"] = _hex(i.thunk.offset)
        if i.HasField("slot"):
            out["slot"] = _hex(i.slot.offset)
        if i.resolved:
            out.update({"program_id": i.program_id, "address": _hex(i.address.offset), "function": i.function_name})
        return out

    @server.tool(annotations=READ)
    @guarded
    def list_libraries(program_id: str, include_imports: bool = False) -> dict:
        """A program's shared libraries (ELF DT_NEEDED, PE import DLLs), its own first, then theirs (depth,
        needed_by), each with the project program it resolves to (resolution "linked" by link_library, "name",
        "soname", or "none": not in the project; import_program with import_libraries brings missing ones) and
        how many of its imports resolve there. include_imports lists every import with the library function it
        goes to (program_id and address there: read that program with the other tools)."""
        r = rk.libraries(program_id, include_imports=include_imports)
        out = {
            "soname": r.soname,
            "build_id": r.build_id,
            "libraries": [{
                "name": l.name,
                "resolution": project_pb2.LibraryResolution.Name(l.resolution).removeprefix("LIBRARY_RESOLUTION_").lower(),
                "program_id": l.program_id,
                "program_name": l.program_name,
                "imports_resolved": l.imports_resolved,
                "depth": l.depth,
                **({"needed_by": l.needed_by} if l.needed_by else {}),
            } for l in r.libraries],
        }
        if include_imports:
            out["imports"] = [_resolved(i) for i in r.imports]
        return out

    @server.tool(annotations=READ)
    @guarded
    def resolve_import(program_id: str, name: str = "", address: str = "") -> dict:
        """Where one import of a program goes, by its name ("strlen") or its thunk's or slot's address: the
        library, the library program (program_id) and the function's address there, to read with the other
        tools (get_function, decompile_function on that program_id)."""
        if address:
            return _resolved(rk.resolve_import(program_id, address=_addr(address)))
        return _resolved(rk.resolve_import(program_id, name=name))

    @server.tool(annotations=READ)
    @guarded
    def list_library_importers(program_id: str, address: str = "", name: str = "",
                               include_references: bool = True) -> dict:
        """References back from a library program: the project's programs whose imports resolve to it, each
        import that does (its thunk in the importer and the function here), and the importer's references to
        it (calls of the thunk: from_address and from_function in the importer's program_id). One export by
        address (the function there) or name; neither: every import of the library."""
        r = rk.library_importers(program_id, address=_addr(address) if address else None, name=name,
                                 include_references=include_references)
        out = []
        for i in r.importers:
            item = {"program_id": i.program_id, "program_name": i.program_name, "library": i.library,
                    "import": _resolved(i.resolved)}
            if include_references:
                item["references"] = [{"from": _hex(x.from_address.offset), "to": _hex(x.to_address.offset),
                                       "kind": listing_pb2.XrefKind.Name(x.kind).removeprefix("XREF_KIND_").lower(),
                                       **({"from_function": x.from_function_name} if x.from_function_name else {})}
                                      for x in i.references]
                if i.references_truncated:
                    item["references_truncated"] = True
            out.append(item)
        return {"importers": out}

    @server.tool(annotations=WRITE)
    @guarded
    def link_library(program_id: str, library: str, target_program_id: str, reason: str) -> dict:
        """Says which project program a library the program needs is (when its name doesn't find it: a renamed
        or differently named copy); an empty target_program_id finds it by name again. Undo with undo_changes."""
        with reasoned(reason):
            r = rk.link_library(program_id, library, target_program_id)
        return {"ok": True, "seq": r.assertion.seq, "program_id": r.library.program_id,
                "resolution": project_pb2.LibraryResolution.Name(r.library.resolution).removeprefix("LIBRARY_RESOLUTION_").lower()}

    @server.tool(annotations=READ)
    @guarded
    def detect_raw_layout(project_id: str, path: str, language_id: str = "", processor: str = "") -> dict:
        """For a file on the daemon's host that is not ELF or PE (raw firmware, a dump): detect what a raw import
        needs, from its bytes. Imports nothing (needs an admin token when the daemon has accounts; a few seconds).
        Returns up to three suggestions, best first: language_id, compiler_spec_id, image_base (null: undetermined,
        e.g. position-independent code), raw_offset, regions, a confidence per answer ("high", "medium", "low" for
        processor, variant, base and offset), the evidence sentences, tie_group: languages the evidence cannot
        tell from language_id, and region_details: each suggested region (RAM, MMIO, or memory accessed that nothing
        classifies, kind "unknown", which regions leaves out) with its own confidence and evidence. With a refusal (reason "high-entropy", "not-code", "unknown-processor" or "too-small")
        the suggestions are only its closest guesses. Rely on "high" answers only: for anything else, show the user
        the evidence and ask before import_program (format "raw"). language_id or processor say what is already
        known and narrow the search."""
        r = rk.detect_raw_layout(project_id, path=path, language_id=language_id, processor=processor)
        suggestions = []
        for s in r.suggestions:
            o = s.options
            suggestions.append({
                "language_id": o.language_id,
                "compiler_spec_id": o.compiler_spec_id,
                "image_base": _hex(o.image_base) if o.has_image_base else None,
                "raw_offset": _hex(o.raw_offset),
                "regions": [format_memory_region(m) for m in o.regions],
                # Each region (and memory accessed that nothing classifies: kind "unknown") with
                # its confidence and evidence, to show before regions are imported.
                "region_details": [{
                    "kind": project_pb2.RawRegionKind.Name(g.kind).removeprefix("RAW_REGION_KIND_").lower(),
                    "region": format_memory_region(g.region),
                    "start": _hex(g.region.start),
                    "size": _hex(g.region.size),
                    "confidence": detect_confidence(g.confidence),
                    "evidence": list(g.evidence),
                } for g in s.region_details],
                "confidence": {
                    "processor": detect_confidence(s.processor_confidence),
                    "variant": detect_confidence(s.variant_confidence),
                    "base": detect_confidence(s.base_confidence),
                    "offset": detect_confidence(s.offset_confidence),
                },
                "evidence": [{"about": e.about, "text": e.text} for e in s.evidence],
                "tie_group": list(s.tie_group),
                "language_pinned": s.language_pinned,
            })
        kinds = project_pb2.RawSegmentKind
        return {
            "refusal": {"reason": r.refusal.reason, "detail": r.refusal.detail} if r.HasField("refusal") else None,
            "suggestions": suggestions,
            "segments": [{"offset": _hex(g.offset), "size": _hex(g.size),
                          "kind": kinds.Name(g.kind).removeprefix("RAW_SEGMENT_KIND_").lower()} for g in r.segments[:200]],
            "segments_truncated": len(r.segments) > 200,
            "file_size": r.file_size,
        }

    # -- the memory map (api_minor 24, feature "memory-map") ----------------------------

    def _block(b) -> dict:
        kinds = {project_pb2.MEMORY_BLOCK_SOURCE_KIND_IMAGE: "image", project_pb2.MEMORY_BLOCK_SOURCE_KIND_FILE: "file",
                 project_pb2.MEMORY_BLOCK_SOURCE_KIND_ZERO: "zero", project_pb2.MEMORY_BLOCK_SOURCE_KIND_NONE: "none"}
        out = {
            "name": b.name,
            "start": _hex(b.range.first.offset),
            "end": _hex(b.range.last.offset),
            "size": b.range.last.offset - b.range.first.offset + 1,
            "perms": ("r" if b.read else "-") + ("w" if b.write else "-") + ("x" if b.execute else "-"),
            "initialized": b.initialized,
            "volatile": b.is_volatile,
            "source": kinds.get(b.source.kind, "unknown"),
            "origin": _origin(b.origin),
        }
        if b.region_id:
            out["region_id"] = b.region_id
        if b.edited:
            out["edited"] = True
        if b.source.kind == project_pb2.MEMORY_BLOCK_SOURCE_KIND_FILE:
            out["file"] = {"name": b.source.file, "offset": _hex(b.source.file_offset), "length": b.source.length,
                           "missing": b.source.missing}
        elif b.has_file_offset:
            out["file_offset"] = _hex(b.file_offset)
        if b.rejected:
            out["rejected"] = b.rejected
        return out

    def _memory_write(resp, region_id: str = "") -> dict:
        out = {"ok": True, "seq": resp.assertion.seq, "revision": resp.snapshot.revision,
               "provenance": format_provenance(resp.assertion.provenance)}
        if region_id:
            out["region_id"] = region_id
        if "block" in resp.DESCRIPTOR.fields_by_name and resp.HasField("block"):
            out["block"] = _block(resp.block)
        return out

    def _region_ref(region: str):
        # A region's id, or an image block by its start address.
        return region if region and not region.lower().startswith("0x") and not region.isdigit() else _addr(region)

    @server.tool(annotations=READ)
    @guarded
    def memory_map(program_id: str) -> dict:
        """The program's memory map: the image's blocks and the regions added since import, each with its
        range, permissions, whether it is initialized or volatile (MMIO), where its bytes come from (image, file,
        zero, none) and who added or edited it; plus added regions the map can't place, with why."""
        prog = rk.program(program_id)
        return {"blocks": [_block(b) for b in prog.memory_map()],
                "rejected": [_block(b) for b in prog.memory_map(rejected=True)]}

    @server.tool(annotations=WRITE)
    @guarded
    def add_memory_region(program_id: str, name: str, start: str, reason: str, size: str = "", perms: str = "rw-",
                          initialized: bool = False, volatile: bool = False, path: str = "", file_offset: str = "",
                          length: str = "", space: str = "") -> dict:
        """Add memory the code refers to but the image lacks: uninitialized RAM (the default), zero-filled memory
        (initialized), memory-mapped I/O (volatile: never folded), or bytes from another file on the daemon's host
        (path; needs an admin token when the daemon has accounts), e.g. a second flash dump or a bootloader, from
        file_offset for length bytes (size defaults to that length). It may not overlap a block. Analysis,
        references, data and the decompiler follow; undo_changes with the returned seq removes it. space: another
        memory space the program has (an 8051's "EXTMEM"), start being an offset there."""
        r = rk.program(program_id).add_memory_region(
            name, at(program_id, start), _num(size) if size else 0, perms=perms, initialized=initialized, volatile=volatile,
            space=space, path=path, file_offset=_num(file_offset) if file_offset else 0,
            length=_num(length) if length else 0, reason=reason)
        return _memory_write(r, r.region_id)

    @server.tool(annotations=WRITE)
    @guarded
    def update_memory_region(program_id: str, region: str, reason: str, name: str = "", start: str = "",
                             size: str = "", perms: str = "", initialized: Optional[bool] = None,
                             volatile: Optional[bool] = None) -> dict:
        """Change a region added since import (region = its region_id: name, start, size, perms, initialized,
        volatile) or one of the image's own blocks (region = its start address: name, perms and volatile only).
        Empty arguments keep their values."""
        r = rk.program(program_id).update_memory_region(
            _region_ref(region), name=name or None, start=at(program_id, start) if start else None,
            size=_num(size) if size else None, perms=perms or None, initialized=initialized, volatile=volatile,
            reason=reason)
        return _memory_write(r)

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False))
    @guarded
    def remove_memory_region(program_id: str, region: str, reason: str) -> dict:
        """Remove a region added since import (by region_id), or revert the edits to one of the image's blocks
        (by its start address; the image's own blocks can't be removed). undo_changes with the seq brings it back."""
        return _memory_write(rk.program(program_id).remove_memory_region(_region_ref(region), reason=reason))

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def set_image_base(program_id: str, image_base: str, reason: str, validate_only: bool = False) -> dict:
        """Move the whole program to a new image base (Ghidra's Set Image Base): its blocks, functions, symbols
        and everything recorded about it (names, comments, types, listing edits, patches, notes, memory regions,
        references) come along. For raw firmware whose base was guessed wrong (pointers in the code don't land in
        the image, few functions). One edit: undo_changes with the returned seq moves it back. validate_only
        checks the image fits there."""
        prog = rk.program(program_id)
        r = prog.set_image_base(_addr(image_base), validate_only=validate_only, reason=reason)
        out = {"ok": True, "image_base": _hex(r.image_base), "previous_image_base": _hex(r.previous_image_base),
               "import_image_base": _hex(r.import_image_base), "revision": r.snapshot.revision}
        if r.HasField("assertion"):
            out["seq"] = r.assertion.seq
            out["provenance"] = format_provenance(r.assertion.provenance)
        return out

    # -- Function ID (docs/fid.md) -----------------------------------------------------

    def _fid_match(m) -> dict:
        from revkit.v1 import analysis_pb2

        status = analysis_pb2.FidMatchStatus.Name(m.status).removeprefix("FID_MATCH_STATUS_").lower()
        return {"entry": _hex(m.entry), "now": m.current_name, "fid_name": m.name, "verdict": m.verdict,
                "score": round(m.score, 2), "status": status, "libraries": list(m.libraries),
                "candidates": [{"name": c.name, "score": round(c.score, 2), "library": c.library,
                                "database": c.database} for c in m.candidates[:8]]}

    @server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    @guarded
    def fid_matches(program_id: str, run: bool = False, status: str = "", offset: int = 0, limit: int = 100) -> dict:
        """Function ID's matches: statically linked library functions named by hash from Ghidra's databases
        (the MSVC runtimes) and attached ones. Each: entry, the name now, the name Function ID gives
        (fid_name), score, status (applied, kept: a better name stays, not applied, rejected, accepted) and the
        candidates. run=true runs it again first (waits). status filters ("applied")."""
        prog = rk.program(program_id)
        r = prog.run_fid() if run else prog.fid_matches()
        rows = [_fid_match(m) for m in r.matches]
        if status:
            rows = [x for x in rows if x["status"] == status.lower()]
        page = rows[offset:offset + limit]
        out = {"revision": r.revision, "functions_hashed": r.functions_hashed, "databases": list(r.databases),
               "total": len(rows), "matches": page}
        if offset + limit < len(rows):
            out["truncated"] = True
            out["more"] = f"offset={offset + limit}"
        return out

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def apply_fid_match(program_id: str, entry: str, reason: str, name: str = "") -> dict:
        """Name a function as one of its Function ID candidates (name: a candidate's; default the proposed
        one). Your edit: undo_changes undoes it."""
        rev = rk.program(program_id).apply_fid(at(program_id, entry), name, reason=reason)
        return {"ok": True, "revision": rev}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False))
    @guarded
    def reject_fid_match(program_id: str, entry: str, reason: str) -> dict:
        """Reject a function's Function ID match: the name and plate comment Function ID gave go, and later runs
        leave the function alone."""
        rev = rk.program(program_id).reject_fid(at(program_id, entry), reason=reason)
        return {"ok": True, "revision": rev}

    @server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    @guarded
    def bsim_databases(project_id: str = "default", executables: bool = True) -> dict:
        """The project's BSim databases (signature stores for finding similar functions across programs): id
        (the path other BSim tools take), template, sizes and, with executables=true, each executable ingested
        (id, name, language, functions, categories)."""
        out = []
        for d in rk.bsim_databases(project_id):
            row = {"id": d.id, "name": d.name, "description": d.description, "settings": hex(d.settings),
                   "executables": d.executables, "functions": d.functions, "error": d.error}
            if executables and not d.error:
                row["executable_list"] = [{"id": e.id, "name": e.name, "language": e.language,
                                           "compiler": e.compiler, "functions": e.function_count,
                                           "categories": dict(e.categories)}
                                          for e in rk.bsim_executables(d.id, project_id=project_id)]
            out.append(row)
        return {"databases": out}

    def _bsim_db(database: str, project_id: str) -> str:
        if database:
            return database
        dbs = [d.id for d in rk.bsim_databases(project_id) if not d.error]
        if len(dbs) != 1:
            raise ValueError("name the database (bsim_databases lists them)" if dbs else
                             "no BSim database is attached to the project")
        return dbs[0]

    def _bsim_match(m) -> dict:
        row = {"similarity": round(m.similarity, 3), "confidence": round(m.confidence, 1),
               "executable": m.executable.name, "executable_id": m.executable.id[:12],
               "function": m.function.name, "entry": _hex(m.function.entry.offset)}
        if m.function.prototype:
            row["prototype"] = m.function.prototype
        if m.program_id:
            row["program_id"] = m.program_id
        return row

    @server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    @guarded
    def bsim_search(program_id: str, address: str = "", database: str = "", all_functions: bool = False,
                    min_similarity: float = 0.7, min_confidence: float = 0.0, max_matches: int = 5,
                    executable: str = "", name_contains: str = "", exclude_default_names: bool = True,
                    project_id: str = "default", offset: int = 0, limit: int = 50) -> dict:
        """Find functions similar to this one (address: anywhere inside it) or, with all_functions, to every
        function of the program, among all the programs ingested in a BSim database: names, prototypes and
        their executables to learn from (an unknown function that matches a library's `inflate` at 0.95 is
        probably inflate). similarity is the cosine of BSim's feature vectors (0.7 is Ghidra's default
        threshold; identical code is 1.0); confidence is BSim's significance (tiny functions score low and
        match many). A match whose file is a program of this project has its program_id (compare_functions,
        port_function_markup). With all_functions, only functions with matches are listed, best first."""
        db = _bsim_db(database, project_id)
        funcs = [] if all_functions else [at(program_id, address)] if address else []
        if not funcs and not all_functions:
            raise ValueError("give an address, or all_functions=true")
        r = rk.bsim_search(db, program_id, funcs, all_functions=all_functions, min_similarity=min_similarity,
                           min_confidence=min_confidence, max_matches=max_matches,
                           executables=[executable] if executable else [], name_contains=name_contains,
                           exclude_default_names=exclude_default_names, project_id=project_id)
        rows = []
        for q in r.results:
            if q.skipped:
                if not all_functions:
                    rows.append({"function": q.name, "entry": _hex(q.function.offset), "skipped": q.skipped})
                continue
            if all_functions and not q.matches:
                continue
            rows.append({"function": q.name, "entry": _hex(q.function.offset),
                         "self_significance": round(q.self_significance, 1), "hits": q.hit_count,
                         "matches": [_bsim_match(m) for m in q.matches]})
        if all_functions:
            rows.sort(key=lambda x: -x["matches"][0]["similarity"])
        out = {"database": db, "total": len(rows), "results": rows[offset:offset + limit]}
        if offset + limit < len(rows):
            out["truncated"] = True
        return out

    @server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    @guarded
    def bsim_overview(program_id: str, database: str = "", min_similarity: float = 0.7, min_confidence: float = 0.0,
                      exclude_default_names: bool = True, project_id: str = "default", limit: int = 100) -> dict:
        """How many functions of a BSim database resemble each function of the program (Ghidra's overview):
        the functions with the most hits first, and how many have none. A cheap first look before
        bsim_search."""
        db = _bsim_db(database, project_id)
        r = rk.bsim_search(db, program_id, all_functions=True, overview=True, min_similarity=min_similarity,
                           min_confidence=min_confidence, exclude_default_names=exclude_default_names,
                           project_id=project_id)
        rows = [{"function": q.name, "entry": _hex(q.function.offset), "hits": q.hit_count,
                 "self_significance": round(q.self_significance, 1)} for q in r.results if not q.skipped]
        rows.sort(key=lambda x: (-x["hits"], x["entry"]))
        return {"database": db, "functions": len(rows), "with_hits": sum(1 for x in rows if x["hits"]),
                "results": [x for x in rows if x["hits"]][:limit]}

    @server.tool(annotations=WRITE)
    @guarded
    def bsim_apply(program_id: str, matches: list[dict], reason: str, kind: str = "name", database: str = "",
                   overwrite: bool = False, dry_run: bool = False, project_id: str = "default") -> dict:
        """Apply BSim matches (from bsim_search) to the program's functions, as Ghidra's BSim results do. matches:
        [{"address": the queried function, "executable_id": the match's, "entry": the match's}, ...] (the fields
        bsim_search returns: the result's entry as address, the match's executable_id and entry). kind: "name",
        "signature" (the name and a skeleton signature: types the program lacks become empty placeholder
        structures) or "signature_and_types" (with the types themselves when the match's file is a program of this
        project). Without overwrite a name replaces only a default one (FUN_...) and a signature only a guess.
        A function given two matches gets neither. One revision; undo_changes with the result's seqs undoes it."""
        db = _bsim_db(database, project_id)
        pairs = []
        for m in matches:
            fn = m.get("address") or m.get("function_address")
            exe = m.get("executable_id") or m.get("executable")
            entry = m.get("entry") or m.get("match_entry")
            if not fn or not exe or not entry:
                raise ValueError("each match needs address, executable_id and entry")
            pairs.append((at(program_id, str(fn)), str(exe), _addr(str(entry))))
        r = rk.bsim_apply(db, program_id, pairs, kind, overwrite=overwrite, dry_run=dry_run, project_id=project_id,
                          reason=reason)
        status = {bsim_pb2.BSIM_APPLY_STATUS_APPLIED: "applied", bsim_pb2.BSIM_APPLY_STATUS_UNCHANGED: "unchanged",
                  bsim_pb2.BSIM_APPLY_STATUS_SKIPPED: "skipped", bsim_pb2.BSIM_APPLY_STATUS_FAILED: "failed"}
        rows = []
        for x in r.results:
            row = {"address": _hex(x.function.offset), "status": status.get(x.status, "?"),
                   "name": x.name_after, "was": x.name_before}
            if x.signature_after != x.signature_before:
                row["signature"] = x.signature_after
                row["signature_was"] = x.signature_before
            if x.message:
                row["message"] = x.message
            if x.from_program:
                row["from_program"] = x.from_program
            rows.append(row)
        return {"database": db, "names": r.names, "signatures": r.signatures, "types": r.types, "skipped": r.skipped,
                "failed": r.failed, "seqs": list(r.seqs), "dry_run": dry_run, "results": rows}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def bsim_ingest(database: str, program_ids: list[str], categories: dict | None = None,
                    project_id: str = "default") -> dict:
        """Sign every function of each program and store it in a BSim database (replacing an earlier ingest of
        the same file), so later searches can find its functions from other programs. Returns per program the
        functions stored and those left out (thunks, externals, decompiler failures)."""
        rows = []
        for r in rk.bsim_ingest(database, program_ids, categories=categories or {}, project_id=project_id):
            rows.append({"program_id": r.program_id, "executable": r.executable.id, "name": r.executable.name,
                         "functions": r.functions, "excluded": dict(r.excluded), "replaced": r.replaced,
                         "seconds": round(r.seconds, 2), "warning": r.warning})
        return {"programs": rows}

    @server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    @guarded
    def fid_databases(project_id: str = "default", program_id: str = "") -> dict:
        """Function ID's databases: Ghidra's builtin ones, yours and the project's, with whether each is attached,
        its libraries and (with program_id) whether it is for that program's language."""
        dbs = rk.program(program_id).fid_databases() if program_id else rk.fid_databases(project_id)
        from revkit.v1 import analysis_pb2

        return {"databases": [{"id": d.id, "name": d.name, "scope": analysis_pb2.FidScope.Name(d.scope).removeprefix(
            "FID_SCOPE_").lower(), "attached": d.attached, "applies": d.applies, "functions": d.functions,
            "libraries": [f"{l.family} {l.version} {l.variant} ({l.language})" for l in d.libraries],
            "error": d.error} for d in dbs]}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def attach_fid_database(path: str, reason: str, scope: str = "project", project_id: str = "default",
                            detach: bool = False) -> dict:
        """Attach (or with detach=true, detach) a Function ID database: a .fidbf or .rkfid file on the daemon's
        host, or a builtin id ("builtin:vs2019_x64"), for the project (scope project) or for you (user).
        fid_matches run=true applies the change."""
        if detach:
            rk.detach_fid_database(path, scope=scope, project_id=project_id, reason=reason)
            return {"ok": True}
        d = rk.attach_fid_database(path, scope=scope, project_id=project_id, reason=reason)
        return {"ok": True, "id": d.id, "name": d.name, "functions": d.functions}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def create_fid_database(path: str, program_ids: list[str], family: str, reason: str, version: str = "",
                            variant: str = "", attach: str = "project", project_id: str = "default") -> dict:
        """Write a Function ID database (.rkfid at path, on the daemon's host) from programs of the project that
        have symbols or debug info (a library's debug build), one library family/version/variant, and attach
        it (attach: project, user or none)."""
        r = rk.create_fid_database(path, program_ids, family, version=version, variant=variant,
                                   attach=None if attach == "none" else attach, project_id=project_id, reason=reason)
        return {"ok": True, "functions": r.functions_added, "excluded": dict(r.excluded),
                "unresolved_callees": len(r.unresolved_callees), "id": r.database.id}

    # -- comparing programs (version tracking) ---------------------------------------

    def _diff(project_id: str, session_id: str):
        return rk.diff_session(project_id, session_id)

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def compare_programs(project_id: str, program_a: str, program_b: str, similarity: bool = True, name: str = "") -> dict:
        """Match the functions of two programs (A: the analysed one, B: the new one) and wait for the result.
        Returns the session id for the diff_* tools and the counts (matched, unchanged, unmatched)."""
        opts = {"similarity_tiers": ["bsim"]} if similarity else {}
        s = rk.diff(project_id, program_a, program_b, name=name, run=True, **opts)
        st = s.wait()
        return {"session_id": s.id, "counts": _d(st.counts), "run": _d(st.session.run)}

    @server.tool(annotations=READ)
    @guarded
    def list_diff_sessions(project_id: str, program_id: str = "") -> dict:
        """Comparison sessions in a project (optionally those involving one program)."""
        return {"sessions": [_d(x) for x in rk.diff_sessions(project_id, program_id)]}

    @server.tool(annotations=READ)
    @guarded
    def diff_matches(project_id: str, session_id: str, change: str = "modified", name_contains: str = "",
                     min_confidence: float = 0.0, limit: int = 200) -> dict:
        """Matched function pairs: change "modified", "unchanged" or "" for all. Each has both addresses and names,
        the tier and confidence of the match, and a one-line summary of what changed."""
        s = _diff(project_id, session_id)
        out = []
        for m in s.matches(change_kinds=[change] if change else [], name_contains=name_contains, min_confidence=min_confidence):
            out.append(_d(m))
            if len(out) >= limit:
                break
        pairs = [(int(m["a"]["entry"], 16), int(m["b"]["entry"], 16)) for m in out if m.get("change_kind", "").endswith("MODIFIED")][:100]
        if pairs:
            try:
                for m, summary in zip([m for m in out if m.get("change_kind", "").endswith("MODIFIED")], s.summaries(*pairs)):
                    m["what_changed"] = getattr(summary, "text", "") or _d(summary).get("text", "")
            except RevkitError:
                pass
        return {"matches": out, "truncated": len(out) >= limit, "counts": _d(s.counts())}

    @server.tool(annotations=READ)
    @guarded
    def diff_unmatched(project_id: str, session_id: str, side: str = "b", limit: int = 200) -> dict:
        """Functions without a match: side "a" (removed in B) or "b" (added in B), with candidates and why."""
        out = []
        for u in _diff(project_id, session_id).unmatched(side):
            out.append(_d(u))
            if len(out) >= limit:
                break
        return {"functions": out, "truncated": len(out) >= limit}

    @server.tool(annotations=READ)
    @guarded
    def diff_function(project_id: str, session_id: str, address_a: str = "", address_b: str = "") -> dict:
        """What changed inside one matched pair (give either side's entry): the summary, and each changed,
        inserted or deleted instruction, A against B."""
        r = _diff(project_id, session_id).function_diff(_addr(address_a) if address_a else None,
                                                         _addr(address_b) if address_b else None, detail=True)
        det = r.detail

        def text(rows, i):
            if i < 0 or i >= len(rows):
                return ""
            row = rows[i]
            return f"{_hex(row.address.offset)}  {row.text}"

        def status(rows, i):
            if i < 0 or i >= len(rows):
                return ""
            name = diff_pb2.DiffLineStatus.Name(rows[i].status).removeprefix("DIFF_LINE_STATUS_").lower()
            return name + (" (moved)" if rows[i].moved else "")

        changes = []
        for line in det.lines:
            st = status(det.rows_b, line.b) or status(det.rows_a, line.a)
            if st in ("equal", "unspecified", ""):
                continue
            changes.append({"status": st, "a": text(det.rows_a, line.a), "b": text(det.rows_b, line.b)})
        d = _d(r)
        return {"match": d.get("match", {}), "summary": d.get("detail", {}).get("summary", {}),
                "changes": changes[:400], "truncated": len(changes) > 400,
                "references": d.get("detail", {}).get("references", [])}

    @server.tool(annotations=WRITE)
    @guarded
    def diff_accept(project_id: str, session_id: str, pairs: list[list[str]], reason: str) -> dict:
        """Accept matches: pairs of [address_a, address_b]. Accepted pairs steer the rest of the matching."""
        r = _diff(project_id, session_id).accept(*[(_addr(a), _addr(b)) for a, b in pairs], reason=reason)
        return _d(r)

    @server.tool(annotations=WRITE)
    @guarded
    def diff_reject(project_id: str, session_id: str, pairs: list[list[str]], reason: str) -> dict:
        """Reject matches: pairs of [address_a, address_b] that are not the same function."""
        r = _diff(project_id, session_id).reject(*[(_addr(a), _addr(b)) for a, b in pairs], reason=reason)
        return _d(r)

    @server.tool(annotations=WRITE)
    @guarded
    def diff_apply_markup(project_id: str, session_id: str, reason: str, min_confidence: float = 0.95,
                          items: Optional[list[str]] = None) -> dict:
        """Carry names, comments and prototypes from A to B for matches at or above a confidence.
        One revision; the result names the apply run, which a user can revert as a whole."""
        r = _diff(project_id, session_id).apply(min_confidence=min_confidence,
                                                 items=items or ["names", "comments", "prototypes"], reason=reason)
        return _d(r)

    @server.tool(annotations=WRITE)
    @guarded
    def diff_set_match(project_id: str, session_id: str, address_a: str, address_b: str, reason: str) -> dict:
        """Match two functions of a comparison by hand (address_a in A, address_b in B), replacing the matches
        either had. diff_unmatch undoes it."""
        r = _diff(project_id, session_id).set_match(_addr(address_a), _addr(address_b), reason=reason)
        return {"match_seq": r.match_seq, "retracted": list(r.retracted_seqs), "seqs": list(r.seqs)}

    @server.tool(annotations=WRITE)
    @guarded
    def diff_unmatch(project_id: str, session_id: str, pairs: list[list[str]], reason: str) -> dict:
        """Undo the decisions on pairs of [address_a, address_b] (an accepted, applied or rejected match), so
        the matcher's proposals apply to both functions again. Anything ported through the match goes too."""
        r = _diff(project_id, session_id).unmatch(*[(_addr(a), _addr(b)) for a, b in pairs], reason=reason)
        return {"retracted": list(r.retracted_seqs), "seqs": list(r.seqs)}

    def _compare_view(r) -> dict:
        det = r.detail

        def row(rows, i):
            if i < 0 or i >= len(rows):
                return ""
            return f"{_hex(rows[i].address.offset)}  {rows[i].text}"

        changes = []
        for line in det.lines:
            src = det.rows_b[line.b] if 0 <= line.b < len(det.rows_b) else det.rows_a[line.a]
            st = diff_pb2.DiffLineStatus.Name(src.status).removeprefix("DIFF_LINE_STATUS_").lower()
            if st in ("equal", "unspecified") and not src.moved:
                continue
            changes.append({"status": st + (" (moved)" if src.moved else ""), "a": row(det.rows_a, line.a), "b": row(det.rows_b, line.b)})
        m = r.markup

        def var(v):
            return {"name": v.name, "type": v.type, "storage_key": v.storage_key, "named": v.named, "typed": v.typed}

        out = {"a": {"name": r.a.function.name, "entry": _hex(r.a.function.entry.offset), "instructions": r.a.function.instructions},
               "b": {"name": r.b.function.name, "entry": _hex(r.b.function.entry.offset), "instructions": r.b.function.instructions},
               "summary": det.summary.text, "equal": det.summary.equal, "changed": det.summary.changed,
               "inserted": det.summary.inserted, "deleted": det.summary.deleted,
               "changes": changes[:300], "truncated": len(changes) > 300}
        if r.HasField("markup"):
            out["signature_a"], out["signature_b"] = m.signature_a, m.signature_b
            out["variables"] = [{"a": var(v.a) if v.HasField("a") else None, "b": var(v.b) if v.HasField("b") else None,
                                 "evidence": v.evidence} for v in m.variables]
            out["comments"] = [{"kind": c.kind, "address_a": _hex(c.address_a.offset) if c.HasField("address_a") else None,
                                "address_b": _hex(c.address_b.offset) if c.HasField("address_b") else None,
                                "a": c.text_a, "b": c.text_b} for c in m.comments]
            for k in ("error_a", "error_b"):
                if getattr(m, k):
                    out[k] = getattr(m, k)
        if r.HasField("match"):
            out["match"] = _d(r.match)
        return out

    @server.tool(annotations=READ)
    @guarded
    def compare_functions(program_a: str, address_a: str, program_b: str, address_b: str, session_id: str = "",
                          project_id: str = "") -> dict:
        """Compare any two functions, in one program or two: what changed (each changed, inserted or deleted
        instruction, A against B, aligned), both signatures, the variables that correspond (parameters by
        position, locals by the instructions they are printed from) and the comments of either side with their
        place on the other. With a comparison's session_id its matches decide which calls correspond."""
        a, b = at(program_a, address_a), at(program_b, address_b)
        r = rk.compare_functions(program_a, a, program_b, b, project_id=project_id, session_id=session_id)
        return _compare_view(r)

    def _port_view(r) -> dict:
        return {"names": r.names, "signatures": r.signatures, "variable_names": r.variable_names,
                "variable_types": r.variable_types, "comments": r.comments, "globals": r.globals, "callees": r.callees,
                "types": r.types, "skipped": r.skipped,
                "warnings": list(r.warnings), "seqs": list(r.seqs),
                "ported": [{"kind": diff_pb2.FunctionMarkupKind.Name(x.kind).removeprefix("FUNCTION_MARKUP_KIND_").lower(),
                            "at": _hex(x.address.offset), **({"variable": x.variable} if x.variable else {}),
                            **({"comment_kind": x.comment_kind} if x.comment_kind else {}),
                            "before": x.before, "after": x.after} for x in r.ported]}

    def _items(items, variables):
        out = list(items or [])
        for v in variables or []:
            out.append(("variable_name", v))
            out.append(("variable_type", v))
        return out

    @server.tool(annotations=WRITE)
    @guarded
    def port_function_markup(from_program: str, from_address: str, to_program: str, to_address: str, reason: str,
                             items: Optional[list[str]] = None, variables: Optional[list[str]] = None,
                             overwrite: bool = False, dry_run: bool = False, project_id: str = "") -> dict:
        """Carry markup from one function to another (any two programs of a project, or one): items among
        "name", "signature", "variable_names", "variable_types", "comments", "global_names", "global_types",
        "callee_names", "callee_signatures" (default: everything someone set on the source: its name, a signature
        not guessed, named and typed variables, every comment, placed by aligned instruction, and the names, types
        and signatures of the globals and callees its aligned instructions reference); variables limits to these source storage keys (from compare_functions). Without
        overwrite only default names and the decompiler's guesses are replaced. One revision; undo_changes with
        the result's seqs on to_program undoes it."""
        r = rk.port_function_markup(from_program, at(from_program, from_address), to_program, at(to_program, to_address),
                                    items=_items(items, variables), overwrite=overwrite, dry_run=dry_run,
                                    project_id=project_id, reason=reason)
        return _port_view(r)

    @server.tool(annotations=WRITE)
    @guarded
    def diff_port_function(project_id: str, session_id: str, address_a: str, address_b: str, reason: str,
                           items: Optional[list[str]] = None, reverse: bool = False, overwrite: bool = False,
                           dry_run: bool = False) -> dict:
        """Apply from a match of a comparison: port the name, signature, variables' names and types and comments
        of A's function to B's (reverse: B's to A's), as port_function_markup does, recording the session."""
        r = _diff(project_id, session_id).port(_addr(address_a), _addr(address_b), items=list(items or []),
                                                reverse=reverse, overwrite=overwrite, dry_run=dry_run, reason=reason)
        return _port_view(r)

    # -- patching (assembling, byte patches as assertions, export with fixups) --------

    def _patch_info(p: patch_pb2.PatchInfo) -> dict:
        out = {"seq": p.seq, "address": _hex(p.address.offset), "bytes": p.bytes.hex(), "original": p.original.hex(),
               "text": p.text, "original_text": p.original_text, "by": format_provenance(p.provenance),
               "reason": p.provenance.reason, "revision": p.revision}
        if p.typed_text:
            out["typed"] = p.typed_text
        if p.function_name:
            out.update(function=_hex(p.function.offset), function_name=p.function_name)
        if p.shadowed_bytes:
            out["shadowed_bytes"] = p.shadowed_bytes
        return out

    @server.tool(annotations=READ)
    @guarded
    def assemble(program_id: str, address: str, text: str, max_candidates: int = 8) -> dict:
        """Assemble one instruction as the listing prints it ("cmp r0,#0x9", "CALL twice"; labels and function
        names resolve) at an address, in the processor mode there. Writes nothing. Returns the encodings,
        best first (shortest, then closest to the bytes there now), each verified to disassemble back to the
        text; or the error, its column and what could come there. current_text is the instruction there now."""
        a = at(program_id, address)
        r = rk.program(program_id).assemble(a, text, max_candidates=max(1, min(max_candidates, 64)))
        out = {
            "address": _hex(a),
            "current_text": r.current_text,
            "current_bytes": r.current_bytes.hex(),
            "candidates": [{"bytes": c.bytes.hex(), "text": c.text, "length": len(c.bytes), "bits_changed": c.hamming,
                            "current": c.current} for c in r.candidates],
            "truncated": r.truncated,
        }
        if r.context:
            out["context"] = r.context
        if r.error:
            out["assembly_error"] = {"message": r.error, "column": r.error_column, "expected": list(r.expected)}
        return out

    @server.tool(annotations=WRITE)
    @guarded
    def patch_instruction(program_id: str, address: str, text: str, reason: str, encoding: str = "",
                          pad: bool = False) -> dict:
        """Replace the instruction at an address with one assembled from text (try assemble first). Writes the
        best encoding, or the one given (encoding: a candidate's bytes as hex). pad fills the rest of a longer
        instruction with NOPs; without it a shorter encoding leaves the old instruction's tail bytes in place.
        Returns the patches' seqs (for revert_patch or undo_changes) and the instruction as it now disassembles."""
        a = at(program_id, address)
        r = rk.program(program_id).patch_instruction(a, text, encoding=_hex_bytes(encoding), pad=pad, reason=reason)
        return {"ok": True, "seqs": list(r.seqs), "revision": r.revision, "address": _hex(a),
                "bytes": r.bytes.hex(), "padding": r.padding.hex(), "text": r.text,
                "provenance": format_provenance(rk.provenance)}

    @server.tool(annotations=WRITE)
    @guarded
    def patch_bytes(program_id: str, address: str, hex_bytes: str, reason: str) -> dict:
        """Overwrite bytes at an address (1 to 256, as hex: "1eff2fe1" or "1e ff 2f e1") as one patch.
        Code there is decoded again from the new bytes. Returns the patch's seq."""
        data = _hex_bytes(hex_bytes)
        if not data:
            raise ValueError("hex_bytes is empty")
        a = at(program_id, address)
        r = rk.program(program_id).patch_bytes(a, data, reason=reason)
        return {"ok": True, "seqs": list(r.seqs), "revision": r.revision, "address": _hex(a),
                "length": len(data), "provenance": format_provenance(rk.provenance)}

    @server.tool(annotations=READ)
    @guarded
    def list_patches(program_id: str, first: str = "", last: str = "", limit: int = 200) -> dict:
        """The program's live patches in address order (all, or those overlapping first..last): the bytes and
        instruction now and before, the function, who patched and why."""
        patches = rk.program(program_id).patches(at(program_id, first) if first else None, at(program_id, last) if last else None)
        return {"patches": [_patch_info(p) for p in patches[:limit]], "truncated": len(patches) > limit,
                "patched_bytes": sum(len(p.bytes) - p.shadowed_bytes for p in patches)}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False))
    @guarded
    def revert_patch(program_id: str, reason: str, seqs: Optional[list[int]] = None, address: str = "",
                     last: str = "") -> dict:
        """Revert patches: by seq (from a patch's result or list_patches), and/or every live patch overlapping
        an address (or the range address..last). The original bytes show again; undo_changes on the returned
        seqs brings the patches back."""
        if not seqs and not address:
            raise ValueError("give seqs, an address, or both")
        r = rk.program(program_id).revert_patches(seqs or [], first=at(program_id, address) if address else None,
                                                  last=at(program_id, last) if last else None, reason=reason)
        return {"ok": True, "reverted": len(r.seqs), "seqs": list(r.seqs), "revision": r.revision}

    @server.tool(annotations=READ)
    @guarded
    def detect_checksum(program_id: str, file_name: str = "", expected: str = "", patched: bool = False,
                        limit: int = 10) -> dict:
        """Find the checksum rule a program's file obeys, so an export can keep it valid. Tries every algorithm
        over candidate ranges against the header's words, against expected (a value as hex) and against the hex
        runs of a file name that carries its checksum ("FW_1234ABCD.bin"). Hits come simplest first: the rule
        (pass it to export_patched's fixups), its value, the evidence in words, and for a file name its template.
        patched searches the patched file instead of the file as imported."""
        r = rk.program(program_id).detect_checksum(expected=expected, file_name=file_name, patched=patched)
        hits = []
        for h in r.hits[:max(1, limit)]:
            hit = {"rule": _checksum_spec(h.spec), "value": _hex(h.value), "evidence": h.evidence}
            if h.file_name_template:
                hit["file_name_template"] = h.file_name_template
            hits.append(hit)
        return {"hits": hits, "truncated": len(r.hits) > len(hits), "tried": r.tried}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def export_patched(program_id: str, save_to: str = "", fixups: Optional[list[dict]] = None,
                       file_name_template: str = "", image_only: bool = False, host_path: str = "",
                       overwrite: bool = False) -> dict:
        """Export the program's file with its patches written in, checksums fixed, and verified by the daemon
        (the output is loaded again and compared with the patched program). fixups: rules from detect_checksum
        ({"algorithm": "sum32", "start": "0x0", "end": 0, "name": true}, or with "field_offset", "field_width",
        "big_endian" for a field of the file) and/or {"pe_checksum": true}. file_name_template: "{NAME}_{SUM:08X}{EXT}".
        image_only: only the loaded image of a raw import, without its header. With no fixups, template or
        image_only, the settings stored with the program are used. save_to: a directory or file path where this
        MCP server runs; host_path: one on the daemon's host (admin). With neither, nothing is written: the
        result (name, size, SHA-256, changes, fixup values, verification) says what an export would be."""
        prog = rk.program(program_id)
        custom = bool(fixups) or bool(file_name_template) or image_only
        settings = patching.settings(*[_fixup(f) for f in fixups or []], template=file_name_template,
                                     image_only=image_only) if custom else None
        target = None
        if save_to:
            target = os.path.abspath(os.path.expanduser(save_to))
            if not os.path.isdir(target) and not os.path.isdir(os.path.dirname(target)):
                raise ValueError(f"save_to: no directory {os.path.dirname(target)}")
        r = prog.export(settings, host_path=host_path)
        out = {
            "file_name": r.file_name,
            "size": r.size,
            "sha256": r.sha256,
            "changes": [{"file_offset": _hex(c.file_offset), "length": c.length, "what": c.what,
                         **({"address": _hex(c.address.offset)} if c.HasField("address") else {})} for c in r.changes[:200]],
            "changes_truncated": len(r.changes) > 200,
            "fixups": list(r.fixups),
            "verified": r.verification.ok,
            "verification": {"compared_bytes": r.verification.compared, "mismatches": r.verification.mismatches,
                             "detail": r.verification.detail,
                             **({"first_mismatch": _hex(r.verification.first_mismatch.offset)}
                                if r.verification.HasField("first_mismatch") else {})},
            "settings": "given" if custom else "stored",
        }
        if r.path:
            out["host_path"] = r.path
        if target is not None:
            if not r.verification.ok:
                out["saved"] = False
                out["note"] = "not saved: the export did not verify"
                return out
            if os.path.isdir(target):
                target = os.path.join(target, os.path.basename(r.file_name) or "export.bin")
            if os.path.exists(target) and not overwrite:
                out["saved"] = False
                out["note"] = f"not saved: {target} exists (overwrite: true replaces it)"
                return out
            with open(target, "wb") as f:
                f.write(r.data)
            out["saved"] = True
            out["path"] = target
        return out

    # -- emulation (sessions are this server's; nothing is asserted) ------------------

    def _emu(session_id: str):
        return rk.emulator_session(session_id)

    def _reg_values(values: Optional[dict]) -> dict:
        return {k: _num(v) for k, v in (values or {}).items()}

    def _machine_args(prog, machine: str, derive_machine: bool) -> tuple[dict, dict]:
        """emulate()/debug() keywords for a machine argument, and what to tell the caller about it."""
        if derive_machine:
            if machine:
                raise ValueError("give machine or derive_machine, not both")
            d = prog.derive_machine()
            return {"machine": d.machine}, {"derived_machine": d.machine, "notes": list(d.notes)}
        text = machine.strip()
        if not text:
            return {}, {}
        # A description is a JSON object (comments allowed); anything else names a saved machine.
        if text[0] == "{" or text.startswith("//") or text.startswith("/*"):
            return {"machine": text}, {}
        return {"machine_name": text}, {}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def emu_start(program_id: str, entry: str = "", mode: str = "auto", args: Optional[list[str]] = None,
                  registers: Optional[dict] = None, breakpoints: Optional[list[str]] = None,
                  machine: str = "", derive_machine: bool = False) -> dict:
        """Start an emulator session. mode: "call" (a function with integer args; stops when it returns),
        "process" (a Linux program from its entry), "bare" (firmware) or "auto". Returns the session id and state.
        Firmware with interrupts and peripherals runs on a machine: machine is a machine description (JSON:
        memory, peripherals, interrupt wiring) or the name of one saved with the program, and derive_machine
        starts on a starter machine derived from the program (returned as derived_machine, with notes on what was
        guessed, to edit and pass back as machine). A machine starts at its reset vector unless entry is given;
        mode and args don't apply. See emu_machine and emu_input."""
        prog = rk.program(program_id)
        on, told = _machine_args(prog, machine, derive_machine)
        s = prog.emulate(at(program_id, entry) if entry else None, mode=mode,
                         args=[_num(a) for a in (args or [])], registers=_reg_values(registers),
                         breakpoints=[at(program_id, b) for b in (breakpoints or [])], client=session, **on)
        out = {"session_id": s.id, "state": _d(s.state) if s.state is not None else {}}
        if on and s.created is not None:
            out["machine"] = _d(s.created.machine)
        out.update(told)
        return out

    @server.tool(annotations=READ)
    @guarded
    def emu_machine(session_id: str, from_event: int = 0, limit: int = 50) -> dict:
        """The machine of a session started with one: the CPU's mode, banked and system registers, each device's
        state, pending interrupt lines, and the exceptions taken (interrupts, SWI/SVC, returns) from from_event
        on, at most limit."""
        r = _emu(session_id).machine(from_event=from_event, limit=max(1, min(limit, 1000)))
        return _d(r)

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def emu_input(session_id: str, text: str = "", hex_bytes: str = "", peripheral: str = "",
                  break_on: Optional[list[str]] = None) -> dict:
        """Send bytes to a UART of the session's machine (text, or hex_bytes; the console unless peripheral names
        one), and/or set the exceptions the run stops on (break_on: "irq", "fiq", "swi", "svc", "systick",
        "irq:4", "any", "return"; an empty list clears them)."""
        s = _emu(session_id)
        data = text.encode("utf-8") + bytes.fromhex(hex_bytes.replace(" ", ""))
        if data:
            s.input(data, peripheral)
        out: dict = {"sent": len(data)}
        if break_on is not None:
            out["break_on"] = s.break_on(*break_on)
        return out

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def emu_run(session_id: str, mode: str = "run", max_steps: int = 0, until: str = "",
                registers: Optional[list[str]] = None) -> dict:
        """Run ("run") or step ("into", "over", "out") until a stop; returns why it stopped, the pc and the
        registers that changed (plus any named in registers)."""
        r = _emu(session_id).run(mode=mode, max_steps=max_steps, until=_addr(until) if until else None,
                                 registers=registers or [])
        return _d(r)

    @server.tool(annotations=READ)
    @guarded
    def emu_state(session_id: str, registers: Optional[list[str]] = None, all_registers: bool = False) -> dict:
        """The session's pc, named (or all) registers, and program output so far."""
        s = _emu(session_id)
        return {"state": _d(s.get_state(*(registers or []), all_registers=all_registers)),
                "stdout": s.stdout.decode("utf-8", "replace")}

    @server.tool(annotations=READ)
    @guarded
    def emu_read_memory(session_id: str, address: str, length: int = 64) -> dict:
        """Bytes of the emulated memory (at most 4096), as hex and a dump."""
        a = _addr(address)
        data = _emu(session_id).read(a, max(1, min(length, 4096)))
        return {"address": _hex(a), "hex": data.hex(), "dump": _dump(data, a)}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def emu_write(session_id: str, registers: Optional[dict] = None, address: str = "", hex_bytes: str = "") -> dict:
        """Set registers ({"r0": "0x10"}) and/or write bytes (hex) at an address in the emulated memory."""
        s = _emu(session_id)
        if address and hex_bytes:
            s.write(_addr(address), bytes.fromhex(hex_bytes.replace(" ", "")))
        state = s.set_registers(_reg_values(registers)) if registers else s.get_state()
        return {"state": _d(state)}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def emu_breakpoints(session_id: str, set: Optional[list[str]] = None, clear: Optional[list[str]] = None) -> dict:
        """Set and/or clear breakpoints; returns the breakpoints now set."""
        s = _emu(session_id)
        now = []
        if clear:
            now = s.clear_breakpoint(*[_addr(a) for a in clear])
        if set or not clear:
            now = s.breakpoint(*[_addr(a) for a in (set or [])])
        return {"breakpoints": [_tidy(MessageToDict(b, preserving_proto_field_name=True)) if hasattr(b, "DESCRIPTOR") else _hex(int(b)) for b in now]}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False))
    @guarded
    def emu_close(session_id: str) -> dict:
        """End an emulator session."""
        _emu(session_id).close()
        return {"ok": True}

    # -- debugging (emulator, a live process, a GDB remote stub, a saved trace) ------

    def _dbg(session_id: str):
        return rk.debug_session(session_id)

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=True))
    @guarded
    def debug_start(program_id: str, target: str = "emulator", entry: str = "", mode: str = "auto",
                    args: Optional[list[str]] = None, breakpoints: Optional[list[str]] = None,
                    machine: str = "", derive_machine: bool = False, from_session: str = "", from_snapshot: int = -1) -> dict:
        """Start a debug session. target: "emulator", "launch" (run the program on the daemon's host; the daemon
        must allow live targets and the token be an admin's), "host:port" (a GDB remote stub: gdbserver, QEMU,
        OpenOCD) or "trace:<name>" (a saved trace). Breakpoints are program addresses. The emulator target takes
        machine and derive_machine as emu_start does (firmware on a board; the timeline then marks exceptions).
        from_session (the emulator): start from another session's stop (or from_snapshot): its registers, and its
        memory read when first touched; that session isn't changed ("what if" from a live process)."""
        emu = target == "emulator"
        prog = rk.program(program_id)
        if (machine or derive_machine) and not emu:
            raise ValueError("a machine is for the emulator target")
        on, told = _machine_args(prog, machine, derive_machine)
        if from_session and not emu:
            raise ValueError("from_session is for the emulator target")
        s = prog.debug(target, entry=at(program_id, entry) if entry and emu else None, mode=mode,
                       args=[_num(a) for a in (args or [])] if emu else list(args or []),
                       breakpoints=[at(program_id, b) for b in (breakpoints or [])], client=session,
                       from_session=from_session or None, from_snapshot=from_snapshot if from_snapshot >= 0 else None, **on)
        out = {"session_id": s.id, "created": _d(s.created) if s.created is not None else {}}
        out.update(told)
        return out

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=True))
    @guarded
    def debug_run(session_id: str, mode: str = "run", until: str = "", max_steps: int = 0) -> dict:
        """Run ("run") or step ("into", "over", "out"). A live target still running answers RUNNING: call again
        with mode "wait", or "interrupt" to stop it."""
        s = _dbg(session_id)
        if mode == "wait":
            return _d(s.wait())
        if mode == "interrupt":
            s.interrupt()
            return _d(s.wait())
        return _d(s.run(mode=mode, until=_addr(until) if until else None, max_steps=max_steps))

    @server.tool(annotations=READ)
    @guarded
    def debug_state(session_id: str, registers: Optional[list[str]] = None, all_registers: bool = False,
                    snapshot: int = -1) -> dict:
        """pc, registers and stop reason, now or at a recorded snapshot (time travel); plus threads and output."""
        s = _dbg(session_id)
        st = s.get_state(*(registers or []), all_registers=all_registers, snapshot=snapshot if snapshot >= 0 else None)
        return {"state": _d(st), "threads": [_d(t) for t in s.threads()], "output": s.output.decode("utf-8", "replace")}

    @server.tool(annotations=READ)
    @guarded
    def debug_backtrace(session_id: str, snapshot: int = -1, max_frames: int = 32) -> dict:
        """The call stack of a stopped debug session (or at a recorded snapshot): each frame's pc (program
        address and function, or the module), stack pointer, and how it was found ("cfi" is reliable, "stack
        scan" least)."""
        frames = _dbg(session_id).backtrace(snapshot=snapshot if snapshot >= 0 else None, max_frames=max(1, min(max_frames, 256)))
        out = []
        for f in frames:
            e = {"level": f.level, "pc": _hex(f.pc.address.offset), "sp": _hex(f.sp), "how": f.how}
            if f.pc.HasField("program_address"):
                e["program_address"] = _hex(f.pc.program_address.offset)
            if f.function:
                e["function"] = f.function + (f"+{_hex(f.function_offset)}" if f.function_offset else "")
            elif f.pc.module:
                e["module"] = f"{f.pc.module}+{_hex(f.pc.module_offset)}"
            out.append(e)
        return {"frames": out}

    @server.tool(annotations=READ)
    @guarded
    def debug_evaluate(session_id: str, expressions: list[str], snapshot: int = -1, frame: int = -1, function: str = "") -> dict:
        """Watch values: C expressions in a stopped debug session (or at a snapshot), in a call-stack frame
        (-1: the stop's). Registers ($RAX or RAX), symbols, the frame's variables by their decompiler names,
        memory and casts to the program's types: "*(int *)($RBP - 0x14)", "ctx->len", "n == 5". Numbers are
        C's (0x for hex). function: a function's entry address whose innermost frame names its variables.
        Each value: text (typed), type, hex, address or register, error when it has none."""
        vals = _dbg(session_id).evaluate(*expressions[:64], snapshot=snapshot if snapshot >= 0 else None,
                                         frame=frame if frame >= 0 else None,
                                         function=_addr(function) if function else None)
        out = []
        for x, v in zip(expressions, vals):
            e = {"expression": x, "text": v.text, "type": v.type}
            if v.error:
                e["error"] = v.error
            if v.hex and v.hex != v.text:
                e["hex"] = v.hex
            if v.HasField("address"):
                e["address"] = _hex(v.address)
            if v.register_name:
                e["register"] = v.register_name
            if v.children:
                e["fields"] = {c.name: c.text for c in v.children[:32]}
            out.append(e)
        return {"values": out}

    @server.tool(annotations=READ)
    @guarded
    def debug_disassemble(session_id: str, address: str = "", count: int = 24, runtime: bool = False, before: int = 0) -> dict:
        """Instructions in a stopped debug session's memory, in the program or outside it (libraries, unpacked
        or JIT code): at a program address (or a runtime one with runtime=true; the pc when empty), with
        `before` instructions of context. Lines are "address  symbol: mnemonic operands", the pc marked =>."""
        r = _dbg(session_id).disassemble(_addr(address) if address else None, max(1, min(count, 256)), before=before,
                                         runtime=runtime)
        lines = []
        for i in r.instructions:
            at = i.location.address.offset
            text = f"{i.mnemonic} {i.operands}".strip()
            if i.HasField("target") and i.target_symbol:
                text += f"  ; {i.target_symbol}"
            prog = f" [program {_hex(i.location.program_address.offset)}]" if i.location.HasField("program_address") else ""
            lines.append(f"{'=> ' if i.pc else '   '}{_hex(at)}{prog}  {i.symbol + ': ' if i.symbol else ''}{text}")
        return {"lines": lines, "next": _hex(r.next), "unreadable": r.unreadable}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def debug_copy_memory(session_id: str, address: str, length: int = 0, mode: str = "block", region: bool = False,
                          runtime: bool = True, name: str = "") -> dict:
        """Capture target memory (unpacked or decrypted code, a library, the heap) into the program: mode "block" (a
        new memory block at its runtime address), "patch" (over the program's own bytes, only what differs) or
        "program" (a new raw program based at the runtime address). address is runtime by default; region=true
        copies the whole mapped region holding it. One undo step."""
        r = _dbg(session_id).copy_memory(_addr(address), length, mode=mode, region=region, runtime=runtime, name=name)
        out = {"address": _hex(r.address), "length": r.length, "program_address": _hex(r.program_address), "revision": r.revision}
        if r.region_id:
            out["block"] = r.block.name
        if r.program.program_id:
            out["program_id"] = r.program.program_id
        if mode.startswith("patch"):
            out["changed"] = r.changed
        return out

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False))
    @guarded
    def debug_rewind(session_id: str, snapshot: int = -1, save_branch_as: str = "") -> dict:
        """Go back in an emulator session: to a recorded snapshot (from debug_timeline), or one instruction
        back (snapshot -1), and continue from there with debug_run. The later snapshots are dropped; give
        save_branch_as to keep them as a trace first. Live sessions can't go back."""
        r = _dbg(session_id).rewind(snapshot if snapshot >= 0 else None, save_branch_as=save_branch_as)
        out = {"snapshot": r.state.last_snapshot, "discarded": r.discarded, "pc": _hex(r.stop.pc.address.offset)}
        if r.stop.pc.HasField("program_address"):
            out["program_address"] = _hex(r.stop.pc.program_address.offset)
        if r.saved.name:
            out["saved_trace"] = r.saved.name
        return out

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
    @guarded
    def emu_call(program_id: str, function: str, args: Optional[list[str]] = None, returns: Optional[dict] = None,
                 stdin: str = "", until: str = "", max_steps: int = 2000000) -> dict:
        """Run one function in the emulator with these integer arguments and report what it returned: the quickest
        way to learn what code computes. returns stubs functions (imports or the program's, by name or address)
        with a constant return value, e.g. {"rand": "4", "time": "0", "check_license": "1"}; each stubbed call's
        first arguments are reported. until: stop at this address instead of the return. Pointer arguments need
        memory the function can read: use debug_start and debug_write for those."""
        prog = rk.program(program_id)
        calls: dict = {}
        with prog.debug("emulator", entry=at(program_id, function), mode="call", args=[_num(a) for a in (args or [])],
                        stdin=stdin.encode(), client=session, max_steps_per_call=max(1, min(max_steps, 50000000))) as s:
            for name, value in (returns or {}).items():
                v = _num(str(value))

                def answer(h, name=name, v=v):
                    calls.setdefault(name, []).append([_hex(a) for a in h.args[:4]])
                    return v
                s.hook_function(at(program_id, name) if str(name).startswith("0x") else name, answer)
            r = s.run(max_steps=max(1, min(max_steps, 50000000)), until=at(program_id, until) if until else None)
            kind = debug_stop_kind(r.stop)
            out = {"stop": kind, "detail": r.stop.detail, "pc": _hex(r.stop.pc.address.offset), "steps": r.state.steps}
            if r.stop.pc.HasField("program_address"):
                out["program_address"] = _hex(r.stop.pc.program_address.offset)
            if kind in ("returned", "exited"):
                out["return_value" if kind == "returned" else "exit_code"] = r.stop.exit_code
                out["return_hex"] = _hex(r.stop.exit_code & 0xFFFFFFFFFFFFFFFF)
            text = s.output.decode("utf-8", "replace")
            if text:
                out["output"] = text[-8000:]
            if calls:
                out["stubbed_calls"] = calls
            return out

    @server.tool(annotations=READ)
    @guarded
    def debug_read_memory(session_id: str, address: str, length: int = 64, runtime: bool = False, snapshot: int = -1) -> dict:
        """Target memory (at most 4096 bytes) at a program address (or a runtime one), now or at a snapshot."""
        a = _addr(address)
        data = _dbg(session_id).read(a, max(1, min(length, 4096)), runtime=runtime, snapshot=snapshot if snapshot >= 0 else None)
        return {"address": _hex(a), "hex": data.hex(), "dump": _dump(data, a)}

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=True))
    @guarded
    def debug_breakpoints(session_id: str, set: Optional[list[str]] = None, clear: Optional[list[str]] = None,
                          watch: str = "", watch_size: int = 4, watch_kind: str = "write", condition: str = "",
                          ignore_count: int = 0) -> dict:
        """Set and/or clear breakpoints (program addresses), or set a watchpoint (watch: an address;
        watch_kind "write", "read" or "access"). condition (a C expression over registers, variables and memory,
        e.g. "$RDI == 3") and ignore_count apply to the ones set: a run stops there only when it holds, after that
        many hits. Returns what is now set, with each one's hits."""
        s = _dbg(session_id)
        now = []
        if clear:
            now = s.clear_breakpoint(*[_addr(a) for a in clear])
        if watch:
            now = s.watch(_addr(watch), size=watch_size, kind=watch_kind)
        if set or not (clear or watch):
            now = s.breakpoint(*[_addr(a) for a in (set or [])], condition=condition, ignore_count=ignore_count)
        return {"breakpoints": [_d(b) for b in now]}

    @server.tool(annotations=READ)
    @guarded
    def debug_timeline(session_id: str, from_snapshot: int = 0, limit: int = 100, stops_only: bool = False) -> dict:
        """The recorded snapshots (each stop, and every instruction in the emulator), to scrub back through."""
        return _d(_dbg(session_id).timeline(from_snapshot, limit, stops_only))

    @server.tool(annotations=READ)
    @guarded
    def debug_modules(session_id: str) -> dict:
        """The target's modules and memory map, with the slide between runtime and program addresses."""
        return _d(_dbg(session_id).modules())

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=True))
    @guarded
    def debug_close(session_id: str, kill: bool = False) -> dict:
        """End a debug session (kill: also kill a launched process)."""
        _dbg(session_id).close(kill=kill)
        return {"ok": True}

    # -- scripts the daemon runs (api_minor 31, feature "scripts-host") ----------

    @server.tool(annotations=READ)
    @guarded
    def list_scripts(project_id: str = "") -> dict:
        """Python scripts the daemon can run on a program: shipped starters, the user's own and (with
        project_id) the project's, with category, description, context (program, function, address,
        selection) and arguments. host_enabled says whether the daemon runs scripts for you."""
        r = rk.list_scripts(project_id)
        return {
            "host_enabled": r.host_enabled,
            "host_disabled_reason": r.host_disabled_reason,
            "python_problem": r.python_problem,
            "scripts": [
                {"script_id": s.script_id, "name": s.name, "category": s.category, "description": s.description,
                 "context": s.context, "trusted": s.trusted,
                 "args": [{"name": a.name, "type": a.type, "default": a.default_value if a.has_default else None,
                           "choices": list(a.choices), "description": a.description} for a in s.args]}
                for s in r.scripts
            ],
        }

    @server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=True))
    @guarded
    def run_script(program_id: str, script_id: str, args: Optional[dict[str, str]] = None, address: str = "",
                   confirm_sha256: str = "", reason: str = "", timeout_seconds: float = 600) -> dict:
        """Run a script (script_id from list_scripts) on a program, to its end. args fill its @arg values
        and answer its prompts by name (a prompt with no answer in args cancels the run, naming it);
        address is its current_address. Its edits are one revision (revert_by run_id with
        undo_changes on the seqs, or the UI). An unconfirmed user or project script returns
        trust_required with its source: show the user and pass confirm_sha256 only with their consent."""
        asked = []

        def answer(p):
            asked.append(p.name)
            return None  # args already answered the prompts they could

        run = rk.run_script(script_id, program_id, args=args or {}, address=at(program_id, address) if address else None,
                            confirm_sha256=confirm_sha256, reason=reason, timeout=timeout_seconds)
        run.wait(answer)
        text = run.text
        out = {"run_id": run.run_id, "status": run.status,
               "output": text if len(text) <= 20000 else text[:10000] + "\n...\n" + text[-10000:]}
        if run.trust is not None:
            t = run.trust
            out.update(trust_required=True, sha256=t.script.sha256, reason=t.reason, source=t.source[:20000],
                       message="the user has not confirmed this script: show them the source and run again with "
                               "confirm_sha256 if they agree")
            return out
        if run.result is not None:
            out.update(revisions=list(run.result.revisions), seqs=list(run.result.seqs), seconds=run.result.seconds)
        if run.error is not None:
            e = run.error
            out.update(error=e.message, traceback=e.traceback, line=e.line)
            if asked:
                out["unanswered_prompts"] = asked
                out["hint"] = "pass args for these prompts: " + ", ".join(asked)
        return out

    server.revkit_client = rk  # for callers that want to close it
    server.revkit_session = session
    return server


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--daemon", default=os.environ.get("RK_GRPC", "127.0.0.1:50051"), help="rk-daemon gRPC address")
    parser.add_argument("--agent", default=os.environ.get("RK_AGENT"),
                        help="agent name recorded on edits (default: the agent token's name, else mcp)")
    parser.add_argument("--agent-version", default=os.environ.get("RK_AGENT_VERSION", ""))
    parser.add_argument("--session", default=os.environ.get("RK_SESSION"), help="session id grouping this run's edits")
    parser.add_argument("--transport", default="stdio", choices=["stdio", "streamable-http"])
    parser.add_argument("--token", help="API token (default $RK_TOKEN, or the first line of $RK_TOKEN_FILE)")
    parser.add_argument("--tls", action="store_true", default=None, help="TLS, trusting the system's CAs")
    parser.add_argument("--ca", help="trust this CA or self-signed certificate (PEM; default $RK_TLS_CA)")
    parser.add_argument("--fingerprint", help="pin the daemon's certificate by SHA-256 (default $RK_TLS_FINGERPRINT)")
    parser.add_argument("--server-name", help="name to check the certificate against")
    args = parser.parse_args(argv)
    create_server(
        args.daemon, args.agent, args.agent_version, args.session, token=args.token, tls=args.tls, ca_cert=args.ca,
        fingerprint=args.fingerprint, server_name=args.server_name,
    ).run(args.transport)


if __name__ == "__main__":
    main()
