"""Where a running script's output, progress and questions go.

A run talks to its host through four calls: ``output`` (what it prints and
logs), ``progress`` (the monitor, at most ten times a second), ``ask`` (a
prompt; returns the answer's text or raises) and ``cancelled``. Two hosts
ship:

- :class:`HeadlessHost` (``rk-script``): output to the terminal; prompts
  answered from ``--arg name=value``, then from stdin when it is a
  terminal (or ``--stdin``), then from the prompt's default, and otherwise
  the run fails at once naming the ``--arg`` that would answer it.
- :class:`StreamHost`: JSON lines both ways, one event per line out
  (``output``, ``progress``, ``prompt``, ``result``, ``error``) and answers
  in (``{"type": "answer", "id": 3, "value": "..."}``, ``{"type":
  "cancel"}``). The daemon's script service runs scripts this
  way and turns the events into its RunScript stream.
"""

from __future__ import annotations

import json
import sys
import threading
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional, TextIO


class PromptUnanswered(Exception):
    """A prompt nobody can answer: headless, with no ``--arg`` for it."""

    def __init__(self, prompt: "Prompt", why: str = ""):
        self.prompt = prompt
        hint = f"pass --arg {prompt.name}=VALUE" if prompt.name else "run it interactively"
        super().__init__(f"{prompt.kind} prompt {prompt.name!r} ({prompt.message}) has no answer: {why or hint}")


@dataclass
class Prompt:
    """One question. ``kind`` is string, int, float, address, yes_no, choice,
    choices or file; ``name`` is what ``--arg`` answers it by."""

    kind: str
    name: str
    message: str
    default: Any = None
    choices: list = field(default_factory=list)
    id: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        if isinstance(self.default, (bytes, bytearray)):
            d["default"] = self.default.hex()
        return d


class ScriptHost:
    """The interface a run talks to. Subclasses override what they show."""

    def output(self, text: str, stream: str = "stdout") -> None:
        raise NotImplementedError

    def progress(self, current: int, maximum: int, message: str) -> None:
        pass

    def ask(self, prompt: Prompt) -> Any:
        """The answer's text (a list of texts for ``choices``); raises
        PromptUnanswered, or Cancelled when the user cancels."""
        raise PromptUnanswered(prompt)

    def cancelled(self) -> bool:
        return False

    def event(self, kind: str, **fields) -> None:
        """A run's start, result or error (stream hosts forward them)."""


class HeadlessHost(ScriptHost):
    def __init__(
        self,
        answers: Optional[dict] = None,
        *,
        stdin: Optional[TextIO] = None,
        interactive: Optional[bool] = None,
        out: Optional[TextIO] = None,
        err: Optional[TextIO] = None,
        prefix: str = "",
        show_progress: bool = False,
    ):
        self.answers = dict(answers or {})
        self.stdin = stdin if stdin is not None else sys.stdin
        if interactive is None:
            try:
                interactive = self.stdin.isatty()
            except (AttributeError, ValueError):
                interactive = False
        self.interactive = interactive
        self.out = out
        self.err = err
        self.prefix = prefix
        self.show_progress = show_progress
        self._cancel = threading.Event()
        self._at_line_start = {"stdout": True, "stderr": True}

    def _stream(self, stream: str) -> TextIO:
        if stream == "stdout":
            return self.out or sys.__stdout__
        return self.err or sys.__stderr__

    def output(self, text: str, stream: str = "stdout") -> None:
        s = self._stream(stream)
        if self.prefix:
            out = []
            for chunk in text.splitlines(keepends=True):
                if self._at_line_start[stream]:
                    out.append(self.prefix)
                out.append(chunk)
                self._at_line_start[stream] = chunk.endswith("\n")
            text = "".join(out)
        s.write(text)
        s.flush()

    def progress(self, current: int, maximum: int, message: str) -> None:
        if self.show_progress:
            frac = f" {current}/{maximum}" if maximum else (f" {current}" if current else "")
            self.output(f"[progress]{frac} {message}\n".replace("  ", " "), "stderr")

    def ask(self, prompt: Prompt) -> Any:
        if prompt.name in self.answers:
            value = self.answers[prompt.name]
            if prompt.kind == "choices" and isinstance(value, str):
                return [v for v in value.split(",") if v]
            return value
        if self.interactive:
            err = self._stream("stderr")
            extra = f" [{'/'.join(map(str, prompt.choices))}]" if prompt.choices else ""
            default = f" (default {prompt.default})" if prompt.default not in (None, "") else ""
            err.write(f"{prompt.message or prompt.name}{extra}{default}: ")
            err.flush()
            line = self.stdin.readline()
            if not line:
                raise PromptUnanswered(prompt, "stdin ended")
            line = line.rstrip("\n")
            if line == "" and prompt.default is not None:
                return prompt.default
            if prompt.kind == "choices":
                return [v.strip() for v in line.split(",") if v.strip()]
            return line
        if prompt.default is not None:
            return prompt.default
        raise PromptUnanswered(prompt)

    def cancel(self) -> None:
        self._cancel.set()

    def cancelled(self) -> bool:
        return self._cancel.is_set()


class StreamHost(ScriptHost):
    """JSON lines: events written with ``write(line)``, messages read with
    ``read()`` (a line, or "" at the end). Thread-safe for writes.

    Messages in: ``{"type": "answer", "id": N, "value": ...}`` (or
    ``"cancelled": true``), ``{"type": "cancel"}`` and ``{"type":
    "context", "address": ..., "selection": [first, last] | null}`` (the
    UI's cursor moved: ``current_address`` follows). With ``background``
    a thread reads them as they come, so a cancel or a context change is
    seen while the script runs, not only while it asks; otherwise they are
    read while a prompt waits for its answer."""

    def __init__(self, write: Callable[[str], None], read: Callable[[], str], *, background: bool = False):
        self._write = write
        self._read = read
        self._lock = threading.Lock()
        self._next_id = 0
        self._cancel = threading.Event()
        self._cv = threading.Condition()
        self._answers: dict = {}
        self._closed = False
        self._context: Optional[dict] = None
        self._context_changed: Optional[Callable[[], None]] = None
        self._on_cancel: Optional[Callable[[], None]] = None
        self._background = background
        if background:
            threading.Thread(target=self._reader, name="stream-host-input", daemon=True).start()

    @classmethod
    def stdio(cls, *, background: bool = True) -> "StreamHost":
        out = sys.__stdout__

        def write(line: str) -> None:
            out.write(line)
            out.flush()

        return cls(write, sys.__stdin__.readline, background=background)

    def send(self, event: dict) -> None:
        with self._lock:
            self._write(json.dumps(event, default=str) + "\n")

    def output(self, text: str, stream: str = "stdout") -> None:
        self.send({"type": "output", "stream": stream, "text": text})

    def progress(self, current: int, maximum: int, message: str) -> None:
        self.send({"type": "progress", "current": current, "maximum": maximum, "message": message})

    def event(self, kind: str, **fields) -> None:
        self.send({"type": kind, **fields})

    def attach_context(self, context: dict, changed: Optional[Callable[[], None]] = None) -> None:
        """The run's context dict, which ``context`` messages update (then
        ``changed`` is called)."""
        self._context = context
        self._context_changed = changed

    def on_cancel(self, fn: Optional[Callable[[], None]]) -> None:
        """Called (from the reader thread) when a cancel arrives."""
        self._on_cancel = fn

    def _dispatch(self, line: str) -> None:
        try:
            msg = json.loads(line)
        except ValueError:
            return
        if not isinstance(msg, dict):
            return
        kind = msg.get("type")
        if kind == "cancel":
            self._cancel.set()
            if self._on_cancel:
                self._on_cancel()
        elif kind == "answer":
            self._answers[msg.get("id")] = msg
        elif kind == "context" and self._context is not None:
            self._context["address"] = msg.get("address")
            self._context["selection"] = msg.get("selection")
            if self._context_changed:
                self._context_changed()
        with self._cv:
            self._cv.notify_all()

    def _reader(self) -> None:
        while True:
            try:
                line = self._read()
            except (OSError, ValueError):
                line = ""
            if not line:
                with self._cv:
                    self._closed = True
                    self._cv.notify_all()
                return
            self._dispatch(line)

    def ask(self, prompt: Prompt) -> Any:
        from revkit.script.runtime import Cancelled

        self._next_id += 1
        prompt.id = self._next_id
        self.send({"type": "prompt", **prompt.to_dict()})
        while True:
            if not self._background:
                line = self._read()
                if not line:
                    self._closed = True
                else:
                    self._dispatch(line)
            else:
                with self._cv:
                    self._cv.wait_for(lambda: prompt.id in self._answers or self._cancel.is_set() or self._closed)
            msg = self._answers.pop(prompt.id, None)
            if msg is not None:
                if msg.get("cancelled"):
                    raise Cancelled(f"prompt {prompt.name!r} was cancelled")
                return msg.get("value")
            if self._cancel.is_set():
                raise Cancelled("cancelled while asking " + (prompt.name or prompt.message))
            if self._closed:
                raise PromptUnanswered(prompt, "the host closed its input")

    def cancel(self) -> None:
        self._cancel.set()

    def cancelled(self) -> bool:
        return self._cancel.is_set()
