"""The GhidraScript and FlatProgramAPI functions a Ghidra script calls
unqualified (``println``, ``toAddr``, ``getFunctionAt``, ``createLabel``,
``askString``, ...), bound to one run.

:func:`namespace` returns the names a Ghidra-style script starts with:
``currentProgram``, ``currentAddress``, ``currentLocation``,
``currentSelection``, ``currentHighlight``, ``monitor``, ``state`` and every
flat function. A GhidraScript/FlatProgramAPI method the shim lacks is still
defined, and raises :class:`Unsupported` naming it and its revkit
replacement.
"""

from __future__ import annotations

import datetime
import getpass
import os
import re
from pathlib import Path
from typing import Any, Optional

from revkit.client import RevkitError, address, clear_code_body, define_data_body, disassemble_body, latin1_regex
from revkit.ghidra.compat.errors import Unsupported
from revkit.ghidra.compat.model import (
    Address,
    AddressSet,
    AddressSetView,
    ByteArray,
    DataType,
    JavaList,
    JavaObject,
    SourceType,
    addr_int,
    comment_kind,
    to_bytes,
)
from revkit.ghidra.compat.program import Data, Function, Instruction, Session, delete_reference, user_reference
from revkit.v1 import assertion_pb2

# Every public GhidraScript / FlatProgramAPI method (Ghidra 12.1). Those the
# shim doesn't implement raise Unsupported when called.
GHIDRA_FLAT_METHODS = (
    "addEntryPoint addInstructionXref analyze analyzeAll analyzeChanges askAddress askBytes askChoice askChoices "
    "askDirectory askDomainFile askDouble askFile askInt askLanguage askLong askPassword askProgram askProjectFolder "
    "askString askValues askYesNo cleanup clearBackgroundColor clearListing clearStatusText closeProgram "
    "createAddressSet createAsciiString createBookmark createByte createChar createClass createData createDouble "
    "createDWord createDwords createEquate createExternalReference createFloat createFragment createFunction "
    "createHighlight createLabel createMemoryBlock createMemoryReference createNamespace createProgram createQWord "
    "createSelection createStackReference createSymbol createTableChooserDialog createUnicodeString createWord "
    "disassemble end execute find findBytes findPascalStrings findStrings getAddressFactory "
    "getAnalysisOptionDefaultValue getAnalysisOptionDefaultValues getAnalysisOptionDescription "
    "getAnalysisOptionDescriptions getBookmarks getByte getBytes getCategory getCodeUnitFormat getControls "
    "getCurrentAnalysisOptionsAndValues getCurrentProgram getDataAfter getDataAt getDataBefore getDataContaining "
    "getDataTypes getDefaultLanguage getDemangled getDouble getEOLComment getEOLCommentAsRendered getEquate "
    "getEquates getFirstData getFirstFunction getFirstInstruction getFloat getFragment getFunction getFunctionAfter "
    "getFunctionAt getFunctionBefore getFunctionContaining getGhidraVersion getGlobalFunctions getInstructionAfter "
    "getInstructionAt getInstructionBefore getInstructionContaining getInt getLanguage getLastData getLastFunction "
    "getLastInstruction getLong getMemoryBlock getMemoryBlocks getMonitor getNamespace getPlateComment "
    "getPlateCommentAsRendered getPostComment getPostCommentAsRendered getPreComment getPreCommentAsRendered "
    "getProgramFile getProjectRootFolder getReference getReferencesFrom getReferencesTo getRepeatableComment "
    "getRepeatableCommentAsRendered getReusePreviousChoices getScriptAnalysisMode getScriptArgs getScriptName "
    "getShort getSourceFile getState getSymbol getSymbolAfter getSymbolAt getSymbolBefore getSymbols "
    "getUndefinedDataAfter getUndefinedDataAt getUndefinedDataBefore getUserName getWorkerName goTo importFile "
    "importFileAsBinary isAnalysisOptionDefaultValue isRunningHeadless openDataTypeArchive openProgram parseAddress "
    "parseBoolean parseBytes parseChoice parseChoices parseDirectory parseDomainFile parseDouble parseInt "
    "parseLanguageCompileSpecPair parseLong parseProjectFolder popup printerr printf println removeBookmark "
    "removeData removeDataAt removeEntryPoint removeEquate removeEquates removeFunction removeFunctionAt "
    "removeHighlight removeInstruction removeInstructionAt removeMemoryBlock removeReference removeSelection "
    "removeSymbol resetAllAnalysisOptions resetAnalysisOption resetAnalysisOptions runCommand runScript "
    "runScriptPreserveMyState saveProgram setAnalysisOption setAnalysisOptions setAnonymousServerCredentials "
    "setBackgroundColor setByte setBytes setCurrentHighlight setCurrentLocation setCurrentSelection setDouble "
    "setEOLComment setFloat setInt setLong setPlateComment setPostComment setPotentialPropertiesFileLocations "
    "setPreComment setPropertiesFile setPropertiesFileLocation setReferencePrimary setRepeatableComment "
    "setReusePreviousChoices setScriptArgs setServerCredentials setShort setSourceFile setStatusText "
    "setToolStatusMessage show start toAddr toHexString"
).split()


# ---------------------------------------------------------------------------
# monitor, state, locations, files
# ---------------------------------------------------------------------------


class TaskMonitor(JavaObject):
    """Ghidra's ``monitor`` on the run's monitor (progress reaches the UI)."""

    _java_name = "TaskMonitor"

    def __init__(self, m):
        self._m = m
        self._indeterminate = False

    def isCancelled(self) -> bool:
        return self._m.is_cancelled

    isCanceled = isCancelled

    def checkCancelled(self) -> None:
        self._m.check_cancelled()

    checkCanceled = checkCancelled

    def cancel(self) -> None:
        self._m.cancel()

    def clearCancelled(self) -> None:
        pass

    clearCanceled = clearCancelled

    def setMessage(self, text) -> None:
        self._m.message(str(text))

    def getMessage(self) -> str:
        return self._m.text

    def setMaximum(self, n) -> None:
        self._m.set_max(int(n))

    def getMaximum(self) -> int:
        return self._m.maximum

    def setProgress(self, v) -> None:
        self._m.set_progress(int(v))

    def getProgress(self) -> int:
        return self._m.progress

    def incrementProgress(self, n: int = 1) -> None:
        self._m.increment(int(n))

    def initialize(self, maximum, message: Optional[str] = None) -> None:
        self._m.progress = 0
        self._m.set_max(int(maximum))
        if message is not None:
            self._m.message(message)

    def setIndeterminate(self, value: bool) -> None:
        self._indeterminate = bool(value)

    def isIndeterminate(self) -> bool:
        return self._indeterminate

    def setShowProgressValue(self, value: bool) -> None:
        pass

    def setCancelEnabled(self, value: bool) -> None:
        pass

    def isCancelEnabled(self) -> bool:
        return True

    def addCancelledListener(self, listener) -> None:
        pass

    def removeCancelledListener(self, listener) -> None:
        pass

    # revkit's spellings too
    def __getattr__(self, name):
        if hasattr(self._m, name):
            return getattr(self._m, name)
        return JavaObject.__getattr__(self, name)


class ProgramLocation(JavaObject):
    def __init__(self, program, a: Address):
        self._p = program
        self._a = a

    def getAddress(self) -> Address:
        return self._a

    def getByteAddress(self) -> Address:
        return self._a

    def getProgram(self):
        return self._p

    def __str__(self):
        return str(self._a)


class ProgramSelection(AddressSet):
    _java_name = "ProgramSelection"


class File(JavaObject):
    """``java.io.File`` as askFile returns it; ``str(f)`` and ``open(f)`` work."""

    def __init__(self, path):
        self._p = Path(str(path))

    def getAbsolutePath(self) -> str:
        return str(self._p.absolute())

    def getPath(self) -> str:
        return str(self._p)

    def getName(self) -> str:
        return self._p.name

    def getParent(self) -> str:
        return str(self._p.parent)

    def getParentFile(self) -> "File":
        return File(self._p.parent)

    def exists(self) -> bool:
        return self._p.exists()

    def isDirectory(self) -> bool:
        return self._p.is_dir()

    def isFile(self) -> bool:
        return self._p.is_file()

    def length(self) -> int:
        return self._p.stat().st_size if self._p.exists() else 0

    def mkdirs(self) -> bool:
        self._p.mkdir(parents=True, exist_ok=True)
        return True

    def delete(self) -> bool:
        try:
            self._p.unlink()
            return True
        except OSError:
            return False

    def toPath(self) -> Path:
        return self._p

    def __fspath__(self):
        return str(self._p)

    def __str__(self):
        return str(self._p)


class GhidraState(JavaObject):
    def __init__(self, flat: "Flat"):
        self._flat = flat
        self._env: dict = {}

    def getCurrentProgram(self):
        return self._flat.s.program

    def getCurrentAddress(self) -> Optional[Address]:
        return self._flat.current_address()

    def getCurrentLocation(self) -> Optional[ProgramLocation]:
        a = self._flat.current_address()
        return ProgramLocation(self._flat.s.program, a) if a is not None else None

    def getCurrentSelection(self) -> Optional[ProgramSelection]:
        return self._flat.current_selection()

    def getCurrentHighlight(self):
        return None

    def setCurrentAddress(self, a) -> None:
        self._flat.set_current_address(a)

    def setCurrentLocation(self, loc) -> None:
        self._flat.set_current_address(loc.getAddress() if loc is not None else None)

    def getEnvironmentVar(self, name: str):
        return self._env.get(name)

    def addEnvironmentVar(self, name: str, value) -> None:
        self._env[name] = value

    def removeEnvironmentVar(self, name: str) -> None:
        self._env.pop(name, None)

    def getTool(self):
        raise Unsupported("state.getTool")

    def getProject(self):
        raise Unsupported("state.getProject", "no Ghidra project; revkit.Client(...).projects() lists revkit's")

    def setCurrentSelection(self, sel):
        raise Unsupported("setCurrentSelection")

    def setCurrentHighlight(self, sel):
        raise Unsupported("setCurrentHighlight")


# ---------------------------------------------------------------------------
# Java's printf
# ---------------------------------------------------------------------------

_FMT = re.compile(r"%(?:(\d+)\$|(<))?([-#+ 0,(]*)(\d+)?(?:\.(\d+))?([tT]?[a-zA-Z%])")
_TIME = {
    "H": "%H", "I": "%I", "M": "%M", "S": "%S", "p": "%p", "Z": "%Z", "z": "%z", "B": "%B", "b": "%b", "h": "%b",
    "A": "%A", "a": "%a", "Y": "%Y", "y": "%y", "m": "%m", "d": "%d", "j": "%j", "R": "%H:%M", "T": "%H:%M:%S",
    "r": "%I:%M:%S %p", "D": "%m/%d/%y", "F": "%Y-%m-%d", "c": "%a %b %d %H:%M:%S %Z %Y",
}


def java_format(fmt: str, *args) -> str:
    """``String.format`` for the conversions scripts use: %s %d %x %o %f %e
    %c %b %n %%, widths, flags, ``n$`` and ``%<``, and %t/%T dates."""
    out, pos, ordinary, last = [], 0, 0, None
    for m in _FMT.finditer(fmt):
        out.append(fmt[pos:m.start()])
        pos = m.end()
        index, rel, flags, width, prec, conv = m.groups()
        if conv == "%":
            out.append("%")
            continue
        if conv == "n":
            out.append("\n")
            continue
        if rel:
            arg = last
        elif index:
            arg = args[int(index) - 1]
        else:
            arg = args[ordinary] if ordinary < len(args) else None
            ordinary += 1
        last = arg
        text = _convert(arg, conv, flags or "", prec)
        if width:
            w = int(width)
            if "-" in flags:
                text = text.ljust(w)
            elif "0" in flags and conv[-1] in "dxXofeE":
                sign = text[0] if text[:1] in "+-" else ""
                text = sign + text[len(sign):].rjust(w - len(sign), "0")
            else:
                text = text.rjust(w)
        out.append(text)
    out.append(fmt[pos:])
    return "".join(out)


def _convert(arg, conv: str, flags: str, prec) -> str:
    if conv[0] in "tT":
        t = arg
        if isinstance(t, (int, float)):
            t = datetime.datetime.fromtimestamp(t / 1000 if t > 1e11 else t)
        if t is None:
            return "null"
        if not isinstance(t, (datetime.datetime, datetime.date)):
            t = datetime.datetime.now()
        c = conv[1]
        if isinstance(t, datetime.datetime) and t.tzinfo is None:
            t = t.astimezone()
        if c == "l":
            text = str(int(t.strftime("%I")))
        elif c == "k":
            text = str(t.hour)
        elif c == "e":
            text = str(t.day)
        elif c == "L":
            text = f"{t.microsecond // 1000:03d}"
        elif c == "s":
            text = str(int(t.timestamp()))
        elif c == "Q":
            text = str(int(t.timestamp() * 1000))
        else:
            text = t.strftime(_TIME.get(c, "%c"))
        return text.upper() if conv[0] == "T" else text
    upper = conv.isupper()
    c = conv.lower()
    if arg is None and c != "b":
        text = "null"
    elif c == "s":
        text = _jstr(arg)
        if prec:
            text = text[:int(prec)]
    elif c == "d":
        v = int(arg)
        text = f"{v:,d}" if "," in flags else str(v)
        if "+" in flags and v >= 0:
            text = "+" + text
    elif c in ("x", "o"):
        v = int(arg)
        if v < 0:
            v &= (1 << 64) - 1 if v < -(1 << 31) else (1 << 32) - 1
        text = format(v, c)
        if "#" in flags:
            text = ("0x" if c == "x" else "0") + text
    elif c in ("f", "e", "g"):
        text = format(float(arg), f".{prec or 6}{c}")
    elif c == "c":
        text = chr(arg) if isinstance(arg, int) else str(arg)[:1]
    elif c == "b":
        text = "false" if arg is None or arg is False else "true"
    elif c == "h":
        text = format(hash(arg) & 0xFFFFFFFF, "x")
    else:
        text = _jstr(arg)
    return text.upper() if upper else text


def _jstr(v) -> str:
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    return str(v)


# ---------------------------------------------------------------------------
# edits that return what they made
# ---------------------------------------------------------------------------


def create_function(s: Session, entry, name: Optional[str] = None, body=None) -> Optional[Function]:
    """A function at ``entry`` (Ghidra's createFunction): committed at once
    so the Function it returns is the daemon's; None if revkit refuses it."""
    from revkit.script.runtime import EditError

    a = addr_int(entry)
    if s.function_at(a) is not None and not name:
        return None
    s.commit()  # what was buffered first, so a refusal names only this
    ranges = []
    if body is not None:
        view = body if isinstance(body, AddressSetView) else AddressSet(body)
        from revkit.client import address_range

        ranges = [address_range(lo, hi) for lo, hi in view._r]
    s.edit(f"function at 0x{a:x}", assertion_pb2.AssertionBody(function_bounds=assertion_pb2.SetFunctionBounds(
        entry=address(a), body=ranges)), structural=True)
    if name:
        s.edit(f"rename 0x{a:x} to {name!r}", assertion_pb2.AssertionBody(
            rename=assertion_pb2.Rename(target=assertion_pb2.Target(address=address(a)), name=name)))
    try:
        s.commit()
    except EditError as e:
        import sys

        print(f"WARN createFunction at 0x{a:x}: revkit refused it: {e}", file=sys.stderr)
        s.run.edits.discard()
        s.structural = False
        return None
    return s.function_at(a)


def _data_type(s: Session, dt) -> DataType:
    if isinstance(dt, DataType):
        return dt
    if isinstance(dt, type) and issubclass(dt, JavaObject):
        raise Unsupported(f"{dt.__name__} as a data type", "pass a DataType instance (IntegerDataType.dataType or IntegerDataType())")
    if isinstance(dt, str):
        got = s.program.getDataTypeManager().getDataType(dt if dt.startswith("/") else "/" + dt)
        return got or DataType(dt, dt, -1)
    raise TypeError(f"not a data type: {dt!r}")


def create_data(s: Session, at, dt, length: int = -1) -> Optional[Data]:
    """``createData(addr, type)``: revkit's define_data with the type's C (or
    builtin) name, committed at once so the Data it returns is the daemon's."""
    from revkit.script.runtime import EditError

    a = addr_int(at)
    t = _data_type(s, dt)
    if t.kind == "string":
        layout, count = ("fixed", length) if length and length > 0 else ("terminated", 0)
        if t.name == "PascalString":
            layout, count = "pascal", 0
        body = define_data_body(a, None, count=count, string=t.string, layout=layout)
    elif t.kind == "array" and t.base is not None:
        if t.base.type_hash:
            body = define_data_body(a, None, count=t.count, type_hash=t.base.type_hash)
        else:
            body = define_data_body(a, t.base.c, count=t.count)
    elif t.type_hash:
        body = define_data_body(a, None, type_hash=t.type_hash)
    else:
        body = define_data_body(a, t.c)
    s.commit()
    s.edit(f"define {t.name} at 0x{a:x}", body, structural=True)
    try:
        s.commit()
    except EditError as e:
        s.run.edits.discard()
        s.structural = False
        raise Unsupported(f"createData({t.name})", f"revkit refused it: {e}") from None
    return s.data_at(a)


# ---------------------------------------------------------------------------
# The flat API
# ---------------------------------------------------------------------------


class Flat:
    """The flat functions of one run (bound methods become the script's globals)."""

    def __init__(self, run, script_args: Optional[list] = None):
        self.run = run
        self.s = Session(run)
        self.monitor = TaskMonitor(run.monitor)
        self.state = GhidraState(self)
        self.script_args = list(script_args or [])
        self._arg_index = 0
        self.namespace: Optional[dict] = None

    # -- context --
    def current_address(self) -> Optional[Address]:
        a = self.run.current_address
        return None if a is None else self.s.addr(a)

    def current_selection(self) -> Optional[ProgramSelection]:
        sel = self.run.current_selection
        if not sel:
            return None
        return ProgramSelection(self.s.addr(sel[0]), self.s.addr(sel[1]))

    def set_current_address(self, a) -> None:
        self.run.context["address"] = None if a is None else hex(addr_int(a))
        self.refresh_context()

    def refresh_context(self) -> None:
        ns = self.namespace
        if ns is None:
            return
        a = self.current_address()
        ns["currentAddress"] = a
        ns["currentLocation"] = ProgramLocation(self.s.program, a) if a is not None else None
        ns["currentSelection"] = self.current_selection()

    # -- output --
    def println(self, message: Any = "") -> None:
        print(_jstr(message))

    def printf(self, fmt: str, *args) -> None:
        print(java_format(fmt, *args), end="", flush=True)

    def printerr(self, message: Any = "") -> None:
        import sys

        print(_jstr(message), file=sys.stderr)

    def popup(self, message: Any) -> None:
        """Headless, Ghidra logs it (Msg.info): the run's log; else the console."""
        if self.isRunningHeadless():
            import sys

            print("INFO " + _jstr(message), file=sys.stderr)
        else:
            print(_jstr(message))

    def setToolStatusMessage(self, message: Any, beep: bool = False) -> None:
        print(_jstr(message))

    def toHexString(self, value: int, zeropad: bool = False, header: bool = False) -> str:
        v = int(value)
        width = {True: 2}.get(zeropad, 0)
        if v < 0:
            v &= 0xFF if v >= -128 else (0xFFFF if v >= -(1 << 15) else ((1 << 32) - 1 if v >= -(1 << 31) else (1 << 64) - 1))
            width = width and len(f"{v:x}")
        text = f"{v:x}"
        if zeropad:
            text = text.rjust(max(2, len(text) + len(text) % 2), "0")
        return ("0x" if header else "") + text

    # -- script --
    def getScriptName(self) -> str:
        return Path(self.run.path).name

    def getScriptArgs(self) -> list:
        return list(self.script_args)

    def setScriptArgs(self, args) -> None:
        self.script_args = list(args)
        self._arg_index = 0

    def isRunningHeadless(self) -> bool:
        from revkit.script.host import HeadlessHost

        return isinstance(self.run.host, HeadlessHost)

    def getState(self) -> GhidraState:
        return self.state

    def getMonitor(self) -> TaskMonitor:
        return self.monitor

    def getCurrentProgram(self):
        return self.s.program

    def getUserName(self) -> str:
        try:
            return getpass.getuser()
        except Exception:  # noqa: BLE001
            return os.environ.get("USER", "unknown")

    def getGhidraVersion(self) -> str:
        return "12.1.4 (revkit compat)"

    def goTo(self, *a) -> bool:
        """No tool to navigate; True when the address is in the program."""
        target = a[-1] if a else None
        if target is None:
            return False
        if hasattr(target, "getEntryPoint"):
            target = target.getEntryPoint()
        try:
            return self.s.block_of(addr_int(target)) is not None
        except TypeError:
            return False

    def start(self) -> None:
        pass

    def end(self, commit: bool) -> None:
        if not commit:
            raise Unsupported("Program.endTransaction(rollback)")

    # -- prompts --
    def _ask(self, kind: str, title: str, message: str, default=None, choices=()):
        if self._arg_index < len(self.script_args):
            raw = self.script_args[self._arg_index]
            self._arg_index += 1
            from revkit.script.host import Prompt

            return self.run._answer(Prompt(kind=kind, name=title, message=message or title, default=default,
                                           choices=list(choices)), raw)
        return self.run.ask(kind, title, message, default, choices)

    def askString(self, title: str, message: str, default: Optional[str] = None) -> str:
        return self._ask("string", title, message, default)

    def askInt(self, title: str, message: str, default: Optional[int] = None) -> int:
        return self._ask("int", title, message, default)

    askLong = askInt

    def askDouble(self, title: str, message: str, default: Optional[float] = None) -> float:
        return self._ask("float", title, message, default)

    def askYesNo(self, title: str, message: str) -> bool:
        return self._ask("yes_no", title, message)

    def askAddress(self, title: str, message: str, default=None) -> Address:
        if isinstance(default, Address):
            default = hex(default.offset)
        return self.s.addr(self._ask("address", title, message, default))

    def askChoice(self, title: str, message: str, choices, default=None):
        return self._ask("choice", title, message, default, list(choices))

    def askChoices(self, title: str, message: str, choices, labels=None):
        return JavaList(self._ask("choices", title, message, None, list(choices)))

    def askFile(self, title: str, approve: str = "") -> File:
        return File(self._ask("file", title, approve or title))

    def askDirectory(self, title: str, approve: str = "") -> File:
        return File(self._ask("file", title, approve or title))

    def askBytes(self, title: str, message: str) -> ByteArray:
        return self.parseBytes(self._ask("string", title, message))

    def parseBytes(self, text: str) -> ByteArray:
        return ByteArray.of(bytes(int(t, 16) for t in str(text).replace(",", " ").split()))

    def parseInt(self, text: str) -> int:
        return int(str(text), 0)

    parseLong = parseInt

    def parseDouble(self, text: str) -> float:
        return float(text)

    def parseBoolean(self, text: str) -> bool:
        from revkit.script.meta import convert

        return convert("bool", str(text))

    def parseAddress(self, text: str) -> Address:
        return self.s.addr(self.run.resolve_address(text))

    # -- addresses --
    def toAddr(self, value) -> Optional[Address]:
        if isinstance(value, Address):
            return value
        if isinstance(value, int):
            return self.s.addr(value)
        return self.s.program.getAddressFactory().getAddress(str(value))

    def getAddressFactory(self):
        return self.s.program.getAddressFactory()

    def createAddressSet(self) -> AddressSet:
        return AddressSet(space=self.s.space)

    # -- functions --
    def getFirstFunction(self) -> Optional[Function]:
        fs = self.s.functions()
        return fs[0] if fs else None

    def getLastFunction(self) -> Optional[Function]:
        fs = self.s.functions()
        return fs[-1] if fs else None

    def getFunctionAfter(self, x) -> Optional[Function]:
        return self.s.function_after(addr_int(x))

    def getFunctionBefore(self, x) -> Optional[Function]:
        return self.s.function_before(addr_int(x))

    def getFunctionAt(self, a) -> Optional[Function]:
        return None if a is None else self.s.function_at(addr_int(a))

    def getFunctionContaining(self, a) -> Optional[Function]:
        return None if a is None else self.s.function_containing(addr_int(a))

    def getFunction(self, name: str) -> Optional[Function]:
        return next((f for f in self.s.functions() if f.getName() == name), None)

    def getGlobalFunctions(self, name: str) -> list:
        return [f for f in self.s.functions() if f.getName() == name]

    def createFunction(self, entry, name: Optional[str] = None) -> Optional[Function]:
        return create_function(self.s, entry, name)

    def removeFunction(self, f) -> None:
        self.s.program.getFunctionManager().removeFunction(f.getEntryPoint() if hasattr(f, "getEntryPoint") else f)

    def removeFunctionAt(self, a) -> None:
        self.s.program.getFunctionManager().removeFunction(a)

    # -- instructions and data --
    def getFirstInstruction(self, f=None):
        if f is not None:
            for ins in self.s.insns(addr_int(f.getEntryPoint())):
                return ins if f.getBody().contains(ins.getAddress()) else None
            return None
        for ins in self.s.insns():
            return ins
        return None

    def getLastInstruction(self):
        for ins in self.s.insns(forward=False):
            return ins
        return None

    def getInstructionAt(self, a):
        return None if a is None else self.s.insn_at(addr_int(a))

    def getInstructionContaining(self, a):
        return None if a is None else self.s.insn_containing(addr_int(a))

    def getInstructionAfter(self, x):
        return self.s.insn_after(addr_int(x))

    def getInstructionBefore(self, x):
        return self.s.insn_before(addr_int(x))

    def getFirstData(self):
        for d in self.s.defined_data():
            return d
        return None

    def getLastData(self):
        for d in self.s.defined_data(forward=False):
            return d
        return None

    def getDataAt(self, a):
        return self.s.program.getListing().getDataAt(a)

    def getDataContaining(self, a):
        return self.s.program.getListing().getDataContaining(a)

    def getDataAfter(self, x):
        return self.s.program.getListing().getDataAfter(x)

    def getDataBefore(self, x):
        return self.s.program.getListing().getDataBefore(x)

    def getUndefinedDataAt(self, a):
        return self.s._undefined_at(addr_int(a))

    def getUndefinedDataAfter(self, a, monitor=None):
        for u in self.s.code_units(addr_int(a) + 1, kinds=("undef",)):
            return u
        return None

    def getUndefinedDataBefore(self, a, monitor=None):
        o = addr_int(a)
        for u in self.s.code_units(0, o - 1, forward=False, kinds=("undef",)) if o else ():
            return u
        return None

    def disassemble(self, a) -> bool:
        o = addr_int(a)
        if self.s.insn_at(o) is not None:
            return True
        self.s.edit(f"disassemble at 0x{o:x}", disassemble_body(o, None, False), structural=True)
        self.s.commit()
        return self.s.insn_at(o) is not None

    def clearListing(self, a, b=None) -> None:
        """``clearListing(addr)``, ``clearListing(start, end)`` or ``clearListing(set)``."""
        if isinstance(a, AddressSetView):
            ranges = list(a._r)
        elif b is not None:
            ranges = [(addr_int(a), addr_int(b))]
        else:
            o = addr_int(a)
            cu = self.s.code_unit_containing(o)
            n = cu.getLength() if cu is not None else 1
            ranges = [(o, o + n - 1)]
        for lo, hi in ranges:
            self.s.edit(f"clear 0x{lo:x}..0x{hi + 1:x}", clear_code_body(lo, hi - lo + 1), structural=True)

    def removeData(self, d) -> None:
        self.clearListing(d.getMinAddress(), d.getMaxAddress())

    def removeDataAt(self, a) -> None:
        d = self.s.data_containing(addr_int(a))
        if d is not None:
            self.removeData(d)

    def removeInstruction(self, ins) -> None:
        self.clearListing(ins.getMinAddress(), ins.getMaxAddress())

    def removeInstructionAt(self, a) -> None:
        ins = self.s.insn_containing(addr_int(a))
        if ins is not None:
            self.removeInstruction(ins)

    def createData(self, a, dt):
        return create_data(self.s, a, dt)

    def _builtin(self, a, name: str):
        return create_data(self.s, a, DataType.builtin(name))

    def createByte(self, a):
        return self._builtin(a, "byte")

    def createWord(self, a):
        return self._builtin(a, "word")

    def createDWord(self, a):
        return self._builtin(a, "dword")

    def createQWord(self, a):
        return self._builtin(a, "qword")

    def createChar(self, a):
        return self._builtin(a, "char")

    def createFloat(self, a):
        return self._builtin(a, "float")

    def createDouble(self, a):
        return self._builtin(a, "double")

    def createDwords(self, a, count: int):
        from revkit.ghidra.compat.model import array_of

        return create_data(self.s, a, array_of(DataType.builtin("dword"), int(count)))

    def createAsciiString(self, a, length: int = -1):
        return create_data(self.s, a, DataType.builtin("string"), length)

    def createUnicodeString(self, a):
        return create_data(self.s, a, DataType.builtin("unicode"))

    def getDataTypes(self, name: str) -> list:
        out: list = []
        self.s.program.getDataTypeManager().findDataTypes(name, out)
        return out

    # -- symbols and names --
    def getSymbolAt(self, a, name: Optional[str] = None):
        return self.s.program.getSymbolTable().getSymbolAt(a, name)

    def getSymbolAfter(self, x):
        o = addr_int(x)
        for sym in self.s.program.getSymbolTable()._all(False):
            if sym._a > o:
                return sym
        return None

    def getSymbolBefore(self, x):
        o = addr_int(x)
        for sym in reversed(self.s.program.getSymbolTable()._all(False)):
            if sym._a < o:
                return sym
        return None

    def getSymbols(self, name: str, namespace=None) -> list:
        return self.s.program.getSymbolTable()._by_name(name)

    def getSymbol(self, name: str, namespace=None):
        found = self.getSymbols(name)
        if len(found) > 1:
            raise Unsupported(f"getSymbol({name!r}): {len(found)} symbols have that name", "use getSymbols(name, None)")
        return found[0] if found else None

    def createLabel(self, a, name: str, *rest):
        """``createLabel(addr, name, makePrimary[, source])`` (or ``(addr, name,
        namespace, makePrimary, source)``): names the address."""
        return self.s.program.getSymbolTable().createLabel(a, name)

    createSymbol = createLabel

    def getNamespace(self, parent, name: str):
        if name in (None, "", "Global"):
            from revkit.ghidra.compat.program import GlobalNamespace

            return GlobalNamespace(self.s)
        raise Unsupported("getNamespace")

    # -- comments --
    def _set_comment(self, a, kind: str, text) -> bool:
        self.s.set_comment(addr_int(a), kind, text)
        return True

    def setEOLComment(self, a, text) -> bool:
        return self._set_comment(a, "eol", text)

    def setPlateComment(self, a, text) -> bool:
        return self._set_comment(a, "plate", text)

    def setPreComment(self, a, text) -> bool:
        return self._set_comment(a, "pre", text)

    def setPostComment(self, a, text) -> bool:
        return self._set_comment(a, "post", text)

    def setRepeatableComment(self, a, text) -> bool:
        return self._set_comment(a, "repeatable", text)

    def getEOLComment(self, a):
        return self.s.comment_at(addr_int(a), "eol")

    def getPlateComment(self, a):
        return self.s.comment_at(addr_int(a), "plate")

    def getPreComment(self, a):
        return self.s.comment_at(addr_int(a), "pre")

    def getPostComment(self, a):
        return self.s.comment_at(addr_int(a), "post")

    def getRepeatableComment(self, a):
        return self.s.comment_at(addr_int(a), "repeatable")

    getEOLCommentAsRendered = getEOLComment
    getPlateCommentAsRendered = getPlateComment
    getPreCommentAsRendered = getPreComment
    getPostCommentAsRendered = getPostComment
    getRepeatableCommentAsRendered = getRepeatableComment

    # -- references --
    def getReferencesTo(self, a) -> list:
        return list(self.s.program.getReferenceManager().getReferencesTo(a))

    def getReferencesFrom(self, a) -> list:
        return self.s.program.getReferenceManager().getReferencesFrom(a)

    def getReference(self, frm, to):
        rm = self.s.program.getReferenceManager()
        return next((r for r in rm.getReferencesFrom(frm) if r.getToAddress() == to), None)

    def createMemoryReference(self, unit, x, y=None, z=None):
        """``createMemoryReference(instruction, operandIndex, toAddress, refType)``;
        from data (``createMemoryReference(data, toAddress, refType)``) is
        refused: revkit's references are made from instructions."""
        if isinstance(unit, Data):
            raise Unsupported("createMemoryReference(Data, ...)",
                              "references are from instructions in revkit; define_data(addr, 'void *') makes a pointer")
        return user_reference(self.s, addr_int(unit.getAddress()), addr_int(y), z, int(x))

    def addInstructionXref(self, frm, to, op_index: int, ref_type):
        return user_reference(self.s, addr_int(frm), addr_int(to), ref_type, int(op_index))

    def removeReference(self, ref) -> None:
        delete_reference(self.s, ref)

    def setReferencePrimary(self, ref, primary: bool = True) -> None:
        self.s.program.getReferenceManager().setPrimary(ref, primary)

    # -- equates (on instruction operands; revkit has no data equates) --
    def _scalar(self, ins, op_index: int):
        from revkit.ghidra.compat.model import Scalar
        from revkit.ghidra.compat.modules import InvalidInputException

        for o in ins.getOpObjects(op_index):
            if isinstance(o, Scalar):
                return o
        raise InvalidInputException(f"Unable to create equate on non-scalar instruction operand at {ins.getAddress()}")

    def createEquate(self, unit, x, name=None):
        """``createEquate(instruction, operandIndex, name)``: the operand's
        scalar shows as ``name`` (an equate with that value is reused)."""
        from revkit.ghidra.compat.modules import DuplicateNameException

        if not isinstance(unit, Instruction):
            raise Unsupported("createEquate(Data, ...)", "revkit's equates name instruction operands")
        value = self._scalar(unit, int(x)).getUnsignedValue()
        table = self.s.program.getEquateTable()
        e = table.getEquate(name)
        if e is None:
            e = table.createEquate(name, value)
        elif e._value != value & ((1 << 64) - 1) and e.getValue() != value:
            raise DuplicateNameException(f"{name} already exists with the value {e.getDisplayValue()}")
        e.addReference(unit.getAddress(), int(x))
        return e

    def getEquate(self, unit, op_index=None, value=None):
        if not isinstance(unit, Instruction):
            return None
        return self.s.program.getEquateTable().getEquate(unit.getAddress(), int(op_index), value)

    def getEquates(self, unit, op_index: int):
        return self.s.program.getEquateTable().getEquates(unit.getAddress(), int(op_index))

    def removeEquate(self, unit, op_index=None, value=None) -> None:
        if not isinstance(unit, Instruction):
            return
        table = self.s.program.getEquateTable()
        e = table.getEquate(unit.getAddress(), int(op_index), value)
        if e is not None:
            e.removeReference(unit.getAddress(), int(op_index))
            self.s.pending_equates.pop(e.getName(), None)  # gone from the table with its last reference

    def removeEquates(self, unit, op_index: int) -> None:
        for e in self.getEquates(unit, op_index):
            e.removeReference(unit.getAddress(), int(op_index))
            self.s.pending_equates.pop(e.getName(), None)

    # -- memory --
    def getMemoryBlock(self, x):
        return self.s.program.getMemory().getBlock(x)

    def getMemoryBlocks(self) -> list:
        return self.s.program.getMemory().getBlocks()

    def getBytes(self, a, length: int) -> ByteArray:
        raw = self.s.read(addr_int(a), int(length))
        if len(raw) < length:
            raise Unsupported(f"getBytes at {a} (uninitialized memory)", "read initialized memory only")
        return ByteArray.of(raw)

    def getByte(self, a) -> int:
        return self.s.program.getMemory().getByte(a)

    def getShort(self, a) -> int:
        return self.s.program.getMemory().getShort(a)

    def getInt(self, a) -> int:
        return self.s.program.getMemory().getInt(a)

    def getLong(self, a) -> int:
        return self.s.program.getMemory().getLong(a)

    def getFloat(self, a) -> float:
        import struct

        return struct.unpack("<f" if self.s.little else ">f", self.s.read(addr_int(a), 4))[0]

    def getDouble(self, a) -> float:
        import struct

        return struct.unpack("<d" if self.s.little else ">d", self.s.read(addr_int(a), 8))[0]

    def setByte(self, a, v) -> None:
        self.s.patch(addr_int(a), to_bytes(v))

    def setBytes(self, a, data) -> None:
        self.s.patch(addr_int(a), to_bytes(data))

    def setShort(self, a, v) -> None:
        self.s.program.getMemory().setShort(a, v)

    def setInt(self, a, v) -> None:
        self.s.program.getMemory().setInt(a, v)

    def setLong(self, a, v) -> None:
        self.s.program.getMemory().setLong(a, v)

    def setFloat(self, a, v) -> None:
        import struct

        self.s.patch(addr_int(a), struct.pack("<f" if self.s.little else ">f", float(v)))

    def setDouble(self, a, v) -> None:
        import struct

        self.s.patch(addr_int(a), struct.pack("<d" if self.s.little else ">d", float(v)))

    # -- search --
    def find(self, a, values=None):
        """``find(text)``: plate and pre comments, labels, then mnemonics
        (FlatProgramAPI's order); ``find(start, byte | bytes)``: the bytes."""
        if values is None and isinstance(a, str):
            return self._find_text(a)
        start = addr_int(a) if a is not None else 0
        pattern = to_bytes(values)
        found = self.s.prog.find_bytes(pattern, None, first=start, max_results=1)
        return self.s.addr(found[0]) if found else None

    def _find_text(self, text: str):
        # On the daemon (SearchText, feature "search"): plate comments, then
        # pre-comments, then labels, then mnemonics, each the first in
        # address order.
        prog = self.s.prog
        comments = prog.search_text(text, fields=["comments"], case_sensitive=True, max_results=100000)
        for kind in (assertion_pb2.COMMENT_KIND_PLATE, assertion_pb2.COMMENT_KIND_PRE):
            for m in comments:
                if m.comment_kind == kind:
                    return self.s.addr(m.address.offset)
        for fields in (["labels"], ["mnemonics", "data_mnemonics"]):
            found = prog.search_text(text, fields=fields, case_sensitive=True, max_results=1)
            if found:
                return self.s.addr(found[0].address.offset)
        return None

    def findBytes(self, start, pattern, limit: int = 1, alignment: int = 1, across_gaps: bool = False):
        """``findBytes(start, "\\x55\\x48.")`` (a regular expression over the
        bytes, as Ghidra's) -> the first match; with ``limit`` (and
        ``alignment``) -> a list of up to ``limit`` matches. ``start`` may be
        an AddressSetView to search within. Searched on the daemon
        (SearchMemory, RE2 syntax); a regex RE2 can't run (backreferences,
        lookaround) is matched here instead."""
        if isinstance(start, AddressSetView):
            ranges = list(start._r)
        else:
            lo = addr_int(start) if start is not None else 0
            ranges = [(lo, (1 << 64) - 1)]
        want = max(1, limit)
        try:
            found = self.s.prog.search_memory(
                "(?s)" + latin1_regex(pattern), format="regex", ranges=ranges, alignment=max(1, alignment),
                max_results=want, details=False)
            hits = sorted({m.address.offset for m in found})
        except RevkitError:
            hits = self._find_bytes_here(pattern, ranges, want, alignment)
        addrs = [self.s.addr(o) for o in hits]
        if limit == 1 and not isinstance(start, AddressSetView):
            return addrs[0] if addrs else None
        return addrs

    def _find_bytes_here(self, pattern, ranges, want: int, alignment: int) -> list:
        rx = re.compile(pattern.encode("latin-1") if isinstance(pattern, str) else bytes(pattern), re.DOTALL)
        hits = []
        for b in self.s.blocks():
            if not b._b.initialized:
                continue
            for lo, hi in ranges:
                first, last = max(lo, b._lo), min(hi, b._hi)
                if first > last:
                    continue
                data = self.s.read(first, last - first + 1)
                for m in rx.finditer(data):
                    o = first + m.start()
                    if alignment > 1 and o % alignment:
                        continue
                    hits.append(o)
                    if len(hits) >= want:
                        return sorted(hits)
        return sorted(hits)

    def findStrings(self, view=None, min_length: int = 5, alignment: int = 1, require_null: bool = True,
                    include_all_char_widths: bool = True) -> list:
        out = []
        for d in self.s.prog.strings(min_length=min_length):
            a = self.s.addr(d.address.offset)
            if view is None or view.contains(a):
                out.append(FoundString(a, d.length, d.value))
        return out


class FoundString(JavaObject):
    def __init__(self, a: Address, length: int, value: str):
        self._a = a
        self._n = length
        self._v = value

    def getAddress(self) -> Address:
        return self._a

    def getLength(self) -> int:
        return self._n

    def getString(self, memory=None) -> str:
        return self._v

    def getEndAddress(self) -> Address:
        return self._a.add(self._n - 1)

    def __str__(self):
        return self._v


def namespace(run, script_args: Optional[list] = None) -> tuple:
    """(names, flat): the globals a Ghidra-style script starts with."""
    flat = Flat(run, script_args)
    ns: dict = {}
    for name in GHIDRA_FLAT_METHODS:
        impl = getattr(flat, name, None)
        if impl is None:
            def fail(*_a, _name=name, **_k):
                raise Unsupported(_name)

            fail.__name__ = name
            impl = fail
        ns[name] = impl
    for name in ("parseBytes", "parseInt", "parseLong", "parseDouble", "parseBoolean", "parseAddress"):
        ns[name] = getattr(flat, name)
    a = flat.current_address()
    ns.update({
        "currentProgram": flat.s.program,
        "currentAddress": a,
        "currentLocation": ProgramLocation(flat.s.program, a) if a is not None else None,
        "currentSelection": flat.current_selection(),
        "currentHighlight": None,
        "monitor": flat.monitor,
        "state": flat.state,
    })
    flat.namespace = ns
    return ns, flat
