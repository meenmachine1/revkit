"""The Python console's host process: a REPL bound to one program.

The daemon's script service starts one per caller and program for
``RunScript{interactive: true}`` (docs/scripting.md, "The console") and
keeps it between statements, so the namespace persists:

    python -m revkit.script.console --daemon 127.0.0.1:50051 --program default/bash \\
        --run-id console-ab12 [--context JSON] [--read-only] [--ghidra] [--lib DIR ...]

It speaks the stream host's JSON lines (:class:`revkit.script.host.StreamHost`)
plus three messages in:

- ``{"type": "exec", "id": N, "source": "...", "context": {...}, "ghidra": bool}``
  runs a statement (or a block, or a paste) and answers ``{"type": "done",
  "id": N, "more": bool, "status": "ok" | "error" | "interrupted" | "exit",
  "revisions": [...], "seqs": [...], "discarded": n, "seconds": s,
  "error": "..."}``; an open block answers ``more`` and runs nothing;
- ``{"type": "complete", "id": N, "text": "...", "limit": n}`` answers
  ``{"type": "completions", "id": N, "completions": [{text, kind,
  signature, doc}], "prefix_length": k, "engine": "jedi" | "rlcompleter"}``
  from the live namespace, also while a statement runs;
- ``{"type": "quit"}`` ends the host.

Each statement's edits are buffered and committed when it ends, as one
revision with script provenance ``console`` (version the statement's
SHA-256 prefix, the console's run id as the session): one undo step. A
statement that raises or is interrupted (SIGINT: ``KeyboardInterrupt``)
commits nothing it had buffered. With ``--read-only`` (a viewer's console)
edits fail at once; reads work.
"""

from __future__ import annotations

import argparse
import ast
import builtins
import codeop
import hashlib
import inspect
import io
import json
import keyword
import linecache
import queue
import re
import signal
import sys
import time
import traceback
from typing import Any, Optional

from revkit.client import Client
from revkit.script import runtime
from revkit.script.host import StreamHost
from revkit.script.meta import ScriptMeta

CONSOLE_NAME = "console"
_FILE = re.compile(r"^<console \d+>$")


class ConsoleHost(StreamHost):
    """The stream host plus the console's own messages: ``exec`` and
    ``quit`` queue for the main thread; ``complete`` is answered from the
    reader thread (so it works while a statement runs)."""

    def __init__(self, write, read, *, background: bool = True):
        self.requests: "queue.Queue[dict]" = queue.Queue()
        self.completer = None  # set by Console
        super().__init__(write, read, background=background)

    @classmethod
    def stdio(cls, *, background: bool = True) -> "ConsoleHost":
        out = sys.__stdout__

        def write(line: str) -> None:
            out.write(line)
            out.flush()

        return cls(write, sys.__stdin__.readline, background=background)

    def _dispatch(self, line: str) -> None:
        try:
            msg = json.loads(line)
        except ValueError:
            return
        if isinstance(msg, dict) and msg.get("type") in ("exec", "quit"):
            self.requests.put(msg)
            return
        if isinstance(msg, dict) and msg.get("type") == "complete":
            try:
                answer = self.completer(str(msg.get("text", "")), int(msg.get("limit") or 200)) if self.completer else {}
            except Exception as e:  # noqa: BLE001 - completion must never kill the host
                answer = {"completions": [], "prefix_length": 0, "error": f"{type(e).__name__}: {e}"}
            self.send({"type": "completions", "id": msg.get("id"), **answer})
            return
        super()._dispatch(line)

    def _reader(self) -> None:
        super()._reader()
        self.requests.put({"type": "quit"})  # stdin closed: the daemon is gone


# ---------------------------------------------------------------------------
# Completion
# ---------------------------------------------------------------------------


def _first_line(doc: Optional[str]) -> str:
    if not doc:
        return ""
    for line in doc.strip().splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""


def _signature(name: str, obj: Any) -> str:
    """``name(a, b=2, *, c=True)``, as the editor's index spells them (no
    annotations)."""
    if not callable(obj):
        return ""
    from revkit.script.completion_index import signature

    sig = signature(name, obj)
    return "" if sig.endswith("(…)") else sig


def _kind(obj: Any) -> str:
    if inspect.ismodule(obj):
        return "module"
    if inspect.isclass(obj):
        return "class"
    if callable(obj):
        return "function"
    if isinstance(obj, property):
        return "property"
    return "instance"


class Completer:
    """Completions from a namespace: jedi's when it is importable (and
    ``engine`` allows), else the standard library's rlcompleter."""

    def __init__(self, namespace: dict, engine: str = "auto"):
        self.namespace = namespace
        self.engine = "rlcompleter"
        if engine in ("auto", "jedi"):
            try:
                import jedi  # noqa: F401

                self.engine = "jedi"
            except ImportError:
                if engine == "jedi":
                    raise

    def __call__(self, text: str, limit: int = 200) -> dict:
        if self.engine == "jedi":
            try:
                return self._jedi(text, limit)
            except Exception:  # noqa: BLE001 - jedi failing on odd input: fall back
                pass
        return self._rl(text, limit)

    def _jedi(self, text: str, limit: int) -> dict:
        import jedi

        comps = jedi.Interpreter(text, [self.namespace]).complete()
        out, prefix = [], 0
        m = re.search(r"[A-Za-z_][\w.]*$|$", text)
        head = (m.group(0) if m else "").rpartition(".")[0]
        base = self._eval(head) if head else None
        for c in comps[:limit]:
            prefix = len(c.name) - len(c.complete or "")
            sig = ""
            obj = self._lookup(base, head, c.name)
            if obj is not None and callable(obj):
                sig = _signature(c.name, obj)
            elif c.type in ("function", "class"):
                try:
                    sigs = c.get_signatures()
                    sig = sigs[0].to_string() if sigs else ""
                except Exception:  # noqa: BLE001
                    sig = ""
            try:
                doc = _first_line(c.docstring(raw=True))
            except Exception:  # noqa: BLE001
                doc = ""
            out.append({"text": c.name, "kind": c.type, "signature": sig, "doc": doc})
        return {"completions": out, "prefix_length": prefix, "engine": "jedi"}

    def _eval(self, head: str) -> Any:
        """The object an attribute chain names ("current_program"), or None."""
        if not re.fullmatch(r"[A-Za-z_]\w*(\.[A-Za-z_]\w*)*", head):
            return None
        try:
            return eval(head, dict(self.namespace))  # noqa: S307 - an attribute chain in the user's own namespace
        except Exception:  # noqa: BLE001
            return None

    def _lookup(self, base: Any, head: str, name: str) -> Any:
        """``name`` in ``base`` (without running a property), or among the
        globals and builtins when there is no ``head``."""
        try:
            if head:
                if base is None:
                    return None
                obj = inspect.getattr_static(base, name)
                if isinstance(obj, (staticmethod, classmethod)) or (inspect.isfunction(obj) and not inspect.isclass(base)):
                    return getattr(base, name)  # bound: the signature without self
                return obj
            if name in self.namespace:
                return self.namespace[name]
            return getattr(builtins, name, None)
        except Exception:  # noqa: BLE001
            return None

    def _rl(self, text: str, limit: int) -> dict:
        import rlcompleter

        m = re.search(r"[A-Za-z_][\w.]*$|$", text)
        word = m.group(0) if m else ""
        if text[: len(text) - len(word)].endswith((".", "'", '"')) and "." not in word:
            word = ""  # after a literal: nothing to complete
        completer = rlcompleter.Completer(self.namespace)
        seen, raw = set(), []
        for state in range(10000):
            try:
                c = completer.complete(word, state)
            except Exception:  # noqa: BLE001 - evaluating the object failed
                c = None
            if c is None:
                break
            c = c.rstrip("(").rstrip(":").rstrip()
            if c not in seen:
                seen.add(c)
                raw.append(c)
        head, _, last = word.rpartition(".")
        base = self._eval(head) if head else None
        if not last.startswith("_"):
            raw = [c for c in raw if not c.rpartition(".")[2].startswith("_")]
        raw.sort(key=lambda c: (c.rpartition(".")[2].lower(), c))
        out = []
        for c in raw[:limit]:
            name = c.rpartition(".")[2]
            obj = self._lookup(base, head, name)
            kind = "keyword" if keyword.iskeyword(name) else ("" if obj is None else _kind(obj))
            doc = "" if obj is None or kind == "instance" else _first_line(getattr(obj, "__doc__", None))
            out.append({"text": name, "kind": kind, "signature": _signature(name, obj) if obj is not None else "",
                        "doc": doc})
        return {"completions": out, "prefix_length": len(last), "engine": "rlcompleter"}


# ---------------------------------------------------------------------------
# The console
# ---------------------------------------------------------------------------


class Console:
    def __init__(self, client: Optional[Client], program_id: str, host: ConsoleHost, *, run_id: str = "",
                 context: Optional[dict] = None, read_only: bool = False, ghidra: bool = False,
                 completion: str = "auto"):
        from revkit import script as api

        self.host = host
        meta = ScriptMeta(path="<console>", name=CONSOLE_NAME, description="Python console")
        self.run = runtime.Run(
            client=client, program_id=program_id, path="<console>", source=b"", meta=meta, args={}, host=host,
            context=context, run_id=run_id, reason="", read_only=read_only,
        )
        if read_only:
            self.run.read_only_why = "this console is read-only (a viewer's: reads work, edits don't)"
        self.ns = api.namespace(self.run)
        self.ns.update({"__name__": "__console__", "__builtins__": builtins, "__doc__": None})
        self.ns["input"] = self._input
        self.run.namespace = self.ns
        runtime._current = self.run
        self.count = 0
        self.ghidra = False
        self._ghidra_undo = None
        self._ghidra_names: dict = {}
        self.completer = Completer(self.ns, completion)
        host.completer = self.completer
        if ghidra:
            self.set_ghidra(True)

    # -- input() reads the UI's prompt, never the protocol's stdin ------------

    def _input(self, prompt: str = "") -> str:
        return self.run.ask("string", "input", str(prompt) or "input()", None)

    # -- Ghidra's names ----------------------------------------------------------

    def set_ghidra(self, on: bool) -> None:
        if on == self.ghidra:
            return
        if on:
            from revkit.ghidra import compat as ghidra_compat

            before = dict(self.ns)
            self._ghidra_undo = ghidra_compat.setup(self.run, self.ns)
            self._ghidra_names = {k: before.get(k, _MISSING) for k, v in self.ns.items()
                                  if k not in before or before[k] is not v}
        else:
            if self._ghidra_undo:
                self._ghidra_undo()
            for k, old in self._ghidra_names.items():
                if old is _MISSING:
                    self.ns.pop(k, None)
                else:
                    self.ns[k] = old
            self.run.finalizers.clear()
            self.run.context_listeners.clear()
            self._ghidra_undo, self._ghidra_names = None, {}
        self.ghidra = on

    # -- one statement -------------------------------------------------------------

    def execute(self, source: str, context: Optional[dict] = None) -> dict:
        started = time.monotonic()
        src = source.replace("\r\n", "\n").replace("\r", "\n")
        if context is not None:
            self.run.context["address"] = context.get("address")
            self.run.context["selection"] = context.get("selection")
            self.run._context_changed()
        if not src.strip():
            return {"more": False, "status": "ok"}
        ended = src.endswith("\n")  # a blank line ends a block, as in the REPL
        if not ended:
            try:
                if codeop.compile_command(src, "<console>", "single") is None:
                    return {"more": True, "status": ""}
            except (SyntaxError, OverflowError, ValueError):
                pass  # several statements (a paste), or a real error: ast says which
        self.count += 1
        filename = f"<console {self.count}>"
        linecache.cache[filename] = (len(src), None, src.splitlines(True), filename)
        self.run.path = filename
        self.run.sha12 = hashlib.sha256(src.encode("utf-8", "replace")).hexdigest()[:12]
        before = len(self.run.edits.commits)
        result: dict = {"more": False, "status": "ok", "error": ""}
        try:
            try:
                tree = ast.parse(src, filename, "exec")
            except SyntaxError as e:
                if not ended and _open_block(src):
                    self.count -= 1
                    return {"more": True, "status": ""}
                raise e
            for node in tree.body:
                code = compile(ast.Interactive([node]), filename, "single")
                exec(code, self.ns)
            for finish in self.run.finalizers:
                finish()
            self.run.edits.commit()
        except SystemExit:
            result.update(status="exit")
        except (KeyboardInterrupt, runtime.Cancelled) as e:
            result.update(status="interrupted", error=type(e).__name__)
            sys.stderr.write("KeyboardInterrupt\n" if isinstance(e, KeyboardInterrupt) else f"Cancelled: {e}\n")
        except BaseException as e:  # noqa: BLE001 - the statement's failure is its result
            result.update(status="error", error=f"{type(e).__name__}: {e}")
            sys.stderr.write(_format_exception(e))
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
        if result["status"] != "ok":
            result["discarded"] = self.run.edits.discard()
        commits = self.run.edits.commits[before:]
        result["revisions"] = [c.snapshot.revision for c in commits]
        result["seqs"] = [a.seq for c in commits for a in c.assertions]
        result["seconds"] = round(time.monotonic() - started, 3)
        return result

    def serve(self) -> int:
        """Answers ``exec`` requests until ``quit`` (or stdin ends)."""
        import platform

        self.host.send({"type": "ready", "python": platform.python_version(), "engine": self.completer.engine,
                        "read_only": self.run.read_only, "run_id": self.run.id})
        while True:
            try:
                msg = self.host.requests.get()
            except KeyboardInterrupt:
                continue  # an interrupt between statements: nothing to stop
            if msg.get("type") == "quit":
                return 0
            if "ghidra" in msg:
                try:
                    self.set_ghidra(bool(msg["ghidra"]))
                except Exception as e:  # noqa: BLE001
                    sys.stderr.write(f"Ghidra names: {type(e).__name__}: {e}\n")
                    sys.stderr.flush()
            try:
                result = self.execute(str(msg.get("source", "")), msg.get("context"))
            except KeyboardInterrupt:
                result = {"more": False, "status": "interrupted", "error": "KeyboardInterrupt"}
            self.host.send({"type": "done", "id": msg.get("id"), **result})
            if result.get("status") == "exit":
                return 0


_MISSING = object()


def _open_block(src: str) -> bool:
    """Whether ``src`` (which doesn't compile) only lacks its end: the last
    line opens or continues a block."""
    try:
        return codeop.compile_command(src + "\n", "<console>", "exec") is None
    except (SyntaxError, OverflowError, ValueError):
        return False


def _format_exception(e: BaseException) -> str:
    """The traceback from the console's own frames (not this module's); just
    the error when none of its frames is the console's (a refused commit)."""
    frames = traceback.extract_tb(e.__traceback__)
    own = next((i for i, f in enumerate(frames) if _FILE.match(f.filename)), None)
    out = "".join(traceback.format_exception_only(type(e), e))
    if own is None:
        return out
    return "Traceback (most recent call last):\n" + "".join(traceback.format_list(frames[own:])) + out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m revkit.script.console", description=__doc__.split("\n\n")[0])
    ap.add_argument("--daemon", required=True)
    ap.add_argument("--program", required=True)
    ap.add_argument("--run-id", default="")
    ap.add_argument("--context", default="", help="JSON: {address, selection}")
    ap.add_argument("--read-only", action="store_true", help="edits fail at once (a viewer's console)")
    ap.add_argument("--ghidra", action="store_true", help="bind Ghidra's names (revkit.ghidra.compat)")
    ap.add_argument("--lib", action="append", default=[], help="a script library directory to import from")
    ap.add_argument("--actor", default=None, help="no-auth daemons: who runs it (user:NAME)")
    ap.add_argument("--completion", choices=("auto", "jedi", "rlcompleter"), default="auto")
    a = ap.parse_args(argv)
    runtime.install_library_paths(a.lib)
    host = ConsoleHost.stdio()
    context = json.loads(a.context) if a.context else {}
    # The protocol owns stdin and stdout: the console's own output goes to
    # the host as events, and input() asks the UI.
    sys.stdin = io.StringIO("")
    sys.stdout = runtime._HostWriter(host, "stdout")
    sys.stderr = runtime._HostWriter(host, "stderr")
    client = Client(a.daemon, actor=a.actor, timeout=300.0)
    console = Console(client, a.program, host, run_id=a.run_id, context=context, read_only=a.read_only,
                      ghidra=a.ghidra, completion=a.completion)

    def on_int(signum, frame):
        # Ctrl+C: KeyboardInterrupt in the statement (between statements
        # serve() ignores it), never in the middle of a commit.
        if not runtime.committing:
            raise KeyboardInterrupt

    def on_term(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGINT, on_int)
    signal.signal(signal.SIGTERM, on_term)
    try:
        return console.serve()
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
