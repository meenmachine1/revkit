"""One script run: its context, buffered edits, monitor and prompts.

:func:`run_script` executes a script file in this process with the flat API
(``revkit.script``) bound to a :class:`Run`, and returns a
:class:`RunResult`. Every edit the script makes is buffered and committed at
the end as one ``AppendAssertions`` (one revision, one undo), checked with
``validate_only`` first so a bad edit names the script line that made it
and nothing lands. ``commit()`` flushes early. A script that raises, exits
non-zero or is cancelled commits nothing it had buffered.

Provenance: kind ``script``, id the script's name, version the first 12 hex
digits of its source's SHA-256, session the run id, tool
``script:<name>@<sha12>``, reason the script's ``@description`` unless given;
the daemon stamps who ran it (``on_behalf_of``), so ``revert(session=run)``
undoes exactly one run and blame says "alice via script:fix-names".
"""

from __future__ import annotations

import contextlib
import copy
import getpass
import hashlib
import io
import os
import re
import sys
import threading
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, Union

import grpc

from revkit.client import (
    Client,
    InvalidArgument,
    NotFound,
    Program,
    RevkitError,
    _COMMENT_KINDS,
    _FLOW_OVERRIDES,
    address,
    address_range,
    format_provenance,
    header_import_bodies,
)
from revkit.script.host import HeadlessHost, Prompt, ScriptHost
from revkit.script.meta import ScriptMeta, convert, parse_metadata
from revkit.v1 import assertion_pb2, common_pb2, listing_pb2


class Cancelled(Exception):
    """The run was cancelled (``monitor.check_cancelled()`` raises it)."""


class EditError(Exception):
    """An edit the daemon refused; names the script line that made it."""


# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------


class Monitor:
    """Progress and cancellation, as Ghidra's ``monitor``: ``set_max``,
    ``increment``, ``set_progress``, ``message``, ``check_cancelled``. Sent
    to the host at most ten times a second."""

    def __init__(self, host: ScriptHost, interval: float = 0.1):
        self._host = host
        self._interval = interval
        self._last = 0.0
        self._cancel = threading.Event()
        self.maximum = 0
        self.progress = 0
        self.text = ""

    def _emit(self, force: bool = False) -> None:
        now = time.monotonic()
        if force or now - self._last >= self._interval:
            self._last = now
            self._host.progress(self.progress, self.maximum, self.text)

    def set_max(self, n: int) -> None:
        self.maximum = int(n)
        self._emit(True)

    def set_progress(self, value: int) -> None:
        self.progress = int(value)
        self._emit()

    def increment(self, by: int = 1) -> None:
        self.progress += by
        self.check_cancelled()
        self._emit()

    def message(self, text: str) -> None:
        self.text = str(text)
        self._emit(True)

    # Ghidra's spellings.
    setMaximum = set_max
    setProgress = set_progress
    setMessage = message

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def is_cancelled(self) -> bool:
        return self._cancel.is_set() or self._host.cancelled()

    def check_cancelled(self) -> None:
        """Raises :class:`Cancelled` when the run was cancelled."""
        if self.is_cancelled:
            raise Cancelled("cancelled")

    checkCancelled = check_cancelled


# ---------------------------------------------------------------------------
# Edits
# ---------------------------------------------------------------------------


@dataclass
class _Pending:
    bodies: list  # AssertionBody; assertion_index references relative to this group
    what: str
    where: str


def _shift_refs(body: assertion_pb2.AssertionBody, offset: int) -> None:
    def fix(ref):
        if ref.WhichOneof("kind") == "assertion_index":
            ref.assertion_index += offset

    if body.HasField("define_type"):
        node = body.define_type.type
        if node.HasField("target"):
            fix(node.target)
        for f in node.fields:
            fix(f.type)
        for p in node.params:
            fix(p.type)
    elif body.HasField("bind_type_name"):
        fix(body.bind_type_name.type)


def _caller_line(script_path: str) -> str:
    """``script.py:12``: the innermost frame of the script itself."""
    for frame in reversed(traceback.extract_stack()):
        if frame.filename == script_path:
            return f"{Path(frame.filename).name}:{frame.lineno}"
    return ""


_INDEX = re.compile(r"assertions\[(\d+)\]")


class EditBuffer:
    """The run's edits, waiting to be committed as one revision."""

    def __init__(self, run: "Run"):
        self.run = run
        self.pending: list = []
        self.commits: list = []  # AppendAssertionsResponse, one per commit

    def __len__(self) -> int:
        return sum(len(p.bodies) for p in self.pending)

    def add(self, what: str, *bodies: assertion_pb2.AssertionBody) -> None:
        if self.run.read_only:
            raise RuntimeError(f"{what}: {self.run.read_only_why}")
        self.pending.append(_Pending(list(bodies), what, _caller_line(self.run.path)))

    def discard(self) -> int:
        n = len(self)
        self.pending.clear()
        return n

    def commit(self, reason: str = "") -> Optional[assertion_pb2.AppendAssertionsResponse]:
        """Validates then appends what is buffered as one revision; None when
        nothing is."""
        if not self.pending:
            return None
        self.run.require_script_provenance()
        bodies, owner = [], []
        for p in self.pending:
            offset = len(bodies)
            for b in p.bodies:
                c = assertion_pb2.AssertionBody()
                c.CopyFrom(b)
                _shift_refs(c, offset)
                bodies.append(c)
                owner.append(p)
        req = assertion_pb2.AppendAssertionsRequest(
            program_id=self.run.program.id,
            assertions=[assertion_pb2.AssertionInput(body=b) for b in bodies],
            provenance=self.run.provenance(reason),
            validate_only=True,
        )
        stub = self.run.client.stubs.assertions.AppendAssertions
        try:
            self.run.client._call(stub, req)
        except InvalidArgument as e:
            m = _INDEX.search(e.message)
            if m and int(m.group(1)) < len(owner):
                p = owner[int(m.group(1))]
                raise EditError(f"{p.where or self.run.name}: {p.what}: {e.message}") from None
            raise EditError(f"{self.run.name}: {e.message}") from None
        req.validate_only = False
        global committing
        committing = True
        try:
            resp = self.run.client._call(stub, req)
        finally:
            committing = False
        self.pending.clear()
        self.commits.append(resp)
        return resp


# ---------------------------------------------------------------------------
# A run
# ---------------------------------------------------------------------------


@dataclass
class RunResult:
    script: str
    name: str
    version: str
    run_id: str
    program_id: str
    status: str = "ok"  # ok, error, cancelled
    error: str = ""
    error_type: str = ""
    traceback: str = ""
    error_file: str = ""
    error_line: int = 0
    exit_code: int = 0
    revisions: list = field(default_factory=list)
    # The committed assertions' seqs, in order (the UI's one undo step).
    seqs: list = field(default_factory=list)
    assertions: int = 0
    discarded: int = 0
    seconds: float = 0.0
    phase: str = "script"  # pre, script or post (rk-script)
    # "ghidra" when the script ran under the Ghidra compatibility shim
    # (revkit.ghidra.compat), else "".
    compat: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict:
        return asdict(self)


class Run:
    """The state behind ``revkit.script`` while one script runs."""

    def __init__(
        self,
        *,
        client: Optional[Client],
        program_id: str,
        path: str,
        source: bytes,
        meta: ScriptMeta,
        args: dict,
        host: ScriptHost,
        context: Optional[dict] = None,
        run_id: str = "",
        reason: str = "",
        on_behalf_of: str = "",
        read_only: bool = False,
    ):
        self.client = client
        self.path = path
        self.meta = meta
        self.name = meta.extra.get("name") or meta.name
        self.sha12 = meta.sha12 or hashlib.sha256(source).hexdigest()[:12]
        self.id = run_id or f"run-{uuid.uuid4().hex[:16]}"
        self.host = host
        self.reason = reason
        self.read_only = read_only
        self.read_only_why = "this run is read-only (the caller is a viewer: reads work, edits don't)"
        self.monitor = Monitor(host)
        self.edits = EditBuffer(self)
        self.context = dict(context or {})
        self.namespace: Optional[dict] = None  # the script's globals, once it runs
        # Called (in order) before the final commit of a successful run.
        self.finalizers: list = []
        # Called when the UI's cursor or selection moves.
        self.context_listeners: list = []
        if hasattr(host, "attach_context"):
            host.attach_context(self.context, self._context_changed)  # a UI's cursor moves follow
        self.args = self._typed_args(args)
        self.program: Optional[Program] = client.program(program_id) if (client and program_id) else None
        self._function_cache: dict = {}
        self._features: Optional[set] = None
        if on_behalf_of:
            self.on_behalf_of = on_behalf_of
        elif client is not None and client.token:
            self.on_behalf_of = ""  # the daemon stamps who we are
        elif client is not None and client.provenance.id and client.provenance.id != "unknown":
            self.on_behalf_of = format_provenance(client.provenance).split("@")[0]
        else:
            self.on_behalf_of = f"user:{_login()}"

    def _typed_args(self, raw: dict) -> dict:
        out = {}
        for a in self.meta.args:
            if a.default is not None:
                out[a.name] = a.convert(a.default)
        for k, v in (raw or {}).items():
            spec = self.meta.arg(k)
            out[k] = spec.convert(v) if spec else v
        self.raw_args = dict(raw or {})
        return out

    # -- provenance --------------------------------------------------------------

    def provenance(self, reason: str = "") -> common_pb2.Provenance:
        return common_pb2.Provenance(
            kind=common_pb2.PROVENANCE_KIND_SCRIPT,
            id=self.name,
            version=self.sha12,
            session=self.id,
            reason=reason or self.reason or self.meta.description,
            tool=f"script:{self.name}@{self.sha12}",
            on_behalf_of=self.on_behalf_of,
        )

    def features(self) -> set:
        if self._features is None:
            self._features = set(self.client.server_info().features) if self.client else set()
        return self._features

    def require_script_provenance(self) -> None:
        if "script-provenance" not in self.features():
            raise RevkitError(
                grpc.StatusCode.FAILED_PRECONDITION,
                "this daemon predates script provenance (api_minor 29, feature script-provenance): it can't record a script's edits",
            )

    # -- context -----------------------------------------------------------------

    def need_program(self) -> Program:
        if self.program is None:
            raise RuntimeError("this run has no program: give rk-script --program or --import")
        return self.program

    @property
    def current_address(self) -> Optional[int]:
        a = self.context.get("address")
        return None if a in (None, "") else _int(a)

    @property
    def current_selection(self) -> Optional[tuple]:
        sel = self.context.get("selection")
        if not sel:
            return None
        first, last = sel
        return (_int(first), _int(last))

    @property
    def current_function(self) -> Optional[listing_pb2.Function]:
        a = self.current_address
        if a is None or self.program is None:
            return None
        if a not in self._function_cache:
            try:
                self._function_cache[a] = self.program.function(a, containing=True)
            except NotFound:
                self._function_cache[a] = None
        return self._function_cache[a]

    def _context_changed(self) -> None:
        """The UI's cursor moved: the script's current_* names follow."""
        ns = self.namespace
        if ns is None:
            return
        ns["current_address"] = self.current_address
        ns["current_selection"] = self.current_selection
        try:
            ns["current_function"] = self.current_function
        except RevkitError:
            ns["current_function"] = None
        for listener in self.context_listeners:
            listener()

    # -- prompts -------------------------------------------------------------------

    def ask(self, kind: str, name: str, message: str = "", default: Any = None, choices: Sequence = ()) -> Any:
        prompt = Prompt(kind=kind, name=name, message=message or name, default=default, choices=list(choices))
        # --arg name=value answers a prompt in every host.
        raw = self.raw_args[name] if name in self.raw_args else self.host.ask(prompt)
        return self._answer(prompt, raw)

    def _answer(self, prompt: Prompt, raw: Any) -> Any:
        kind = prompt.kind
        try:
            if kind == "string" or kind == "file":
                return "" if raw is None else str(raw)
            if kind == "int":
                return convert("int", raw)
            if kind == "float":
                return convert("float", raw)
            if kind == "yes_no":
                return convert("bool", raw)
            if kind == "address":
                return self.resolve_address(raw)
            if kind == "choice":
                value = str(raw)
                if prompt.choices and value not in [str(c) for c in prompt.choices]:
                    raise ValueError(f"{value!r} is not one of {', '.join(map(str, prompt.choices))}")
                return prompt.choices[[str(c) for c in prompt.choices].index(value)] if prompt.choices else value
            if kind == "choices":
                values = raw if isinstance(raw, (list, tuple)) else [v for v in str(raw).split(",") if v]
                names = [str(c) for c in prompt.choices]
                bad = [v for v in values if prompt.choices and str(v) not in names]
                if bad:
                    raise ValueError(f"{', '.join(map(str, bad))} not among {', '.join(names)}")
                return [prompt.choices[names.index(str(v))] for v in values] if prompt.choices else list(values)
        except (TypeError, ValueError) as e:
            raise ValueError(f"answer to {prompt.name!r}: {e}") from None
        return raw

    def resolve_address(self, value: Any) -> int:
        """An int, "0x401000", "401000h", or a symbol's name."""
        if isinstance(value, int):
            return value
        if isinstance(value, common_pb2.Address):
            return value.offset
        text = str(value).strip()
        try:
            if text.lower().endswith("h") and re.fullmatch(r"[0-9a-fA-F]+h", text):
                return int(text[:-1], 16)
            return int(text, 0)
        except ValueError:
            pass
        if re.fullmatch(r"[0-9a-fA-F]+", text):
            return int(text, 16)
        prog = self.need_program()
        for s in prog.symbols(name_equals=text):
            return s.address.offset
        raise ValueError(f"no symbol named {text!r}")


def _is_ghidra(text: str) -> bool:
    from revkit.ghidra.compat import is_ghidra_script

    return is_ghidra_script(text)


def _int(v: Any) -> int:
    if isinstance(v, int):
        return v
    return int(str(v), 0)


def _login() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no passwd entry in a container
        return os.environ.get("USER", "unknown")


# ---------------------------------------------------------------------------
# Script libraries: what `import mylib` finds
# ---------------------------------------------------------------------------


def user_scripts_dir() -> Path:
    """The per-user library: $XDG_CONFIG_HOME/revkit/scripts, else
    ~/.config/revkit/scripts (rk-daemon --scripts-dir moves the daemon's)."""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "revkit" / "scripts"


def library_dirs(script: Optional[Union[str, Path]] = None, *, user_dir: Optional[Union[str, Path]] = None,
                 project_dir: Optional[Union[str, Path]] = None, extra: Sequence = ()) -> list:
    """Where a script's imports look, in order: the per-user library, the
    project's (``<project-dir>/<project>/scripts``), then ``extra``, then
    the script's own directory when it is none of these."""
    out: list = []
    for d in [user_dir if user_dir is not None else user_scripts_dir(), project_dir, *extra]:
        if d and str(Path(d)) not in out:
            out.append(str(Path(d)))
    if script is not None:
        own = str(Path(script).resolve().parent)
        if own not in [str(Path(d).resolve()) for d in out]:
            out.append(own)
    return out


def install_library_paths(dirs: Sequence) -> None:
    """Puts the library directories on ``sys.path`` in order, after Python's
    standard library and before installed packages (site-packages): a
    library can't shadow ``json``, and wins over an installed package of
    the same name."""
    dirs = [str(d) for d in dirs if d and str(d) not in sys.path]
    if not dirs:
        return
    at = next((i for i, p in enumerate(sys.path) if "site-packages" in p or "dist-packages" in p), len(sys.path))
    sys.path[at:at] = dirs


# True while a commit's AppendAssertions is in flight: a cancel (SIGTERM)
# then waits for it rather than interrupting it, so a run never reports
# "cancelled" for edits that landed.
committing = False

# The run the flat API acts on (one per process: rk-script runs each program
# in its own host process).
_current: Optional[Run] = None
_lock = threading.Lock()


def current() -> Run:
    if _current is None:
        raise RuntimeError("no script is running: run scripts with rk-script (or revkit.script.run_script)")
    return _current


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


class _HostWriter(io.TextIOBase):
    """Line-buffered: ``print("a", b)`` reaches the host as one line, not
    four writes; ``flush()`` (``print(..., flush=True)``) sends a partial
    line, and the run's end sends what is left."""

    def __init__(self, host: ScriptHost, stream: str):
        self._host = host
        self._stream = stream
        self._buf = ""
        self._lock = threading.Lock()

    def writable(self) -> bool:
        return True

    def write(self, s: str) -> int:
        if not s:
            return 0
        with self._lock:
            self._buf += s
            nl = self._buf.rfind("\n")
            if nl < 0 and len(self._buf) < 65536:
                return len(s)
            cut = nl + 1 if nl >= 0 else len(self._buf)
            out, self._buf = self._buf[:cut], self._buf[cut:]
        self._host.output(out, self._stream)
        return len(s)

    def flush(self) -> None:
        with self._lock:
            out, self._buf = self._buf, ""
        if out:
            self._host.output(out, self._stream)


def _script_frames(tb, path: str) -> list:
    frames = traceback.extract_tb(tb)
    for i, f in enumerate(frames):
        if f.filename == path:
            return frames[i:]
    return frames


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------


def run_script(
    script: Union[str, Path],
    *,
    client: Optional[Client] = None,
    program_id: str = "",
    args: Optional[dict] = None,
    host: Optional[ScriptHost] = None,
    context: Optional[dict] = None,
    run_id: str = "",
    reason: str = "",
    on_behalf_of: str = "",
    phase: str = "script",
    read_only: bool = False,
    compat: str = "auto",
) -> RunResult:
    """Runs a script file in this process and commits its edits as one
    revision. ``args`` answer its prompts and fill ``args`` (``--arg``);
    ``context`` gives ``current_address`` (``{"address": "0x401000",
    "selection": ["0x401000", "0x40101f"]}``) and, for a Ghidra-style
    script, ``script_args`` (its ``getScriptArgs()``, which answer its
    ``ask*`` calls in order, as in Ghidra's headless mode). ``compat``:
    "auto" runs a Ghidra-style script under revkit.ghidra.compat, "ghidra"
    always does, "off" never. Never raises for what the script does: the
    result says how it ended."""
    global _current
    path = str(Path(script).resolve())
    source = Path(path).read_bytes()
    meta = parse_metadata(source, path)
    host = host or HeadlessHost(args)
    run = Run(
        client=client, program_id=program_id, path=path, source=source, meta=meta, args=args or {}, host=host,
        context=context, run_id=run_id, reason=reason, on_behalf_of=on_behalf_of, read_only=read_only,
    )
    result = RunResult(script=path, name=run.name, version=run.sha12, run_id=run.id, program_id=program_id, phase=phase)
    from revkit import script as api

    namespace = api.namespace(run)
    namespace.update({"__name__": "__main__", "__file__": path, "__builtins__": __builtins__})
    run.namespace = namespace
    text = source.decode("utf-8", "replace")
    uninstall = None
    if compat not in ("auto", "ghidra", "off"):
        raise ValueError(f"compat is auto, ghidra or off, not {compat!r}")
    if compat == "ghidra" or compat == "auto" and _is_ghidra(text):
        result.compat = "ghidra"
    started = time.monotonic()
    host.event("start", run_id=run.id, script=path, name=run.name, version=run.sha12, program_id=program_id, phase=phase)
    with _lock:
        previous, _current = _current, run
    committed_ok = False
    writers: tuple = ()
    try:
        if result.compat == "ghidra":
            from revkit.ghidra import compat as ghidra_compat
            from revkit.ghidra.compat.modules import bind_class_imports

            uninstall = ghidra_compat.setup(run, namespace)
            code = compile(bind_class_imports(text), path, "exec")
        else:
            code = compile(source, path, "exec")
        out_w, err_w = _HostWriter(host, "stdout"), _HostWriter(host, "stderr")
        writers = (out_w, err_w)
        with contextlib.redirect_stdout(out_w), contextlib.redirect_stderr(err_w):
            try:
                exec(code, namespace)
            except SystemExit as e:
                if e.code not in (None, 0):
                    result.status = "error"
                    result.exit_code = e.code if isinstance(e.code, int) else 1
                    result.error = f"exited with {e.code}"
            if result.status == "ok":
                if run.monitor.is_cancelled:
                    raise Cancelled("cancelled")
                for finish in run.finalizers:
                    finish()
                run.edits.commit()
                committed_ok = True
    except (Cancelled, KeyboardInterrupt) as e:
        result.status = "cancelled"
        result.error = str(e) or "cancelled"
    except BaseException as e:  # noqa: BLE001 - the script's failure is the result
        result.status = "error"
        result.error_type = type(e).__name__
        result.error = f"{type(e).__name__}: {e}"
        frames = _script_frames(e.__traceback__, path)
        result.traceback = "Traceback (most recent call last):\n" + "".join(traceback.format_list(frames)) + "".join(
            traceback.format_exception_only(type(e), e)
        )
        own = [f for f in frames if f.filename == path]
        if own:
            result.error_file, result.error_line = path, own[-1].lineno or 0
        elif isinstance(e, SyntaxError) and e.filename == path:
            result.error_file, result.error_line = path, e.lineno or 0
        if isinstance(e, SyntaxError):
            from revkit.ghidra.compat import python2_hint

            hint = python2_hint(text, e)
            if hint:
                result.error += f" ({hint})"
                result.traceback += hint + "\n"
    finally:
        for w in writers:
            w.flush()
        if uninstall is not None:
            uninstall()
        with _lock:
            _current = previous
    if not committed_ok:
        result.discarded = run.edits.discard()
    result.revisions = [c.snapshot.revision for c in run.edits.commits]
    result.seqs = [a.seq for c in run.edits.commits for a in c.assertions]
    result.assertions = len(result.seqs)
    result.seconds = round(time.monotonic() - started, 3)
    if result.status == "ok":
        host.event("result", **result.to_dict())
    else:
        host.event("error", **result.to_dict())
    return result
