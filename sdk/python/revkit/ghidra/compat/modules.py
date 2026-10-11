"""``ghidra.*`` import paths aliased to the shim, for a Ghidra-style script.

While such a script runs, an import hook answers ``from
ghidra.program.model.listing import Function``, ``import
ghidra.program.model.data.StringDataType as StringDataType`` (Jython's
class-as-module form) and ``from ghidra.program.model.symbol.SourceType
import *`` with the shim's classes. A Ghidra class the shim doesn't have
imports as a placeholder that raises :class:`Unsupported` naming it when
used, so an unused import costs nothing and a used one fails loudly.
``java.*``, ``javax.*``, ``docking.*`` and ``jpype`` import the same way and
fail when used: revkit runs scripts in CPython, without a JVM.
"""

from __future__ import annotations

import importlib.abc
import importlib.machinery
import re
import sys
import types
from typing import Optional

from revkit.ghidra.compat import decompiler as dec
from revkit.ghidra.compat import model as m
from revkit.ghidra.compat import program as p
from revkit.ghidra.compat.errors import Unsupported, replacement_for

ROOTS = ("ghidra", "java", "javax", "docking", "jpype", "generic")

# The Flat of the running script (FlatProgramAPI(...) and helpers bind to it).
_flat = None


# ---------------------------------------------------------------------------
# Helper classes scripts import
# ---------------------------------------------------------------------------


class Msg(m.JavaObject):
    """``ghidra.util.Msg``: messages go to the run's log (stderr)."""

    @staticmethod
    def _log(level: str, origin, message, *rest) -> None:
        print(f"{level} {message}", file=sys.stderr)

    @staticmethod
    def info(origin, message, *rest):
        Msg._log("INFO", origin, message)

    @staticmethod
    def debug(origin, message, *rest):
        Msg._log("DEBUG", origin, message)

    @staticmethod
    def trace(origin, message, *rest):
        Msg._log("TRACE", origin, message)

    @staticmethod
    def warn(origin, message, *rest):
        Msg._log("WARN", origin, message)

    @staticmethod
    def error(origin, message, *rest):
        Msg._log("ERROR", origin, message)

    @staticmethod
    def out(message):
        print(message)

    @staticmethod
    def showInfo(origin, parent, title, message):
        print(f"{title}: {message}")

    @staticmethod
    def showWarn(origin, parent, title, message):
        print(f"{title}: {message}", file=sys.stderr)

    @staticmethod
    def showError(origin, parent, title, message, *rest):
        print(f"{title}: {message}", file=sys.stderr)


class SystemUtilities(m.JavaObject):
    @staticmethod
    def isInHeadlessMode() -> bool:
        return _flat.isRunningHeadless() if _flat is not None else True

    @staticmethod
    def isInTestingMode() -> bool:
        return False

    @staticmethod
    def isInDevelopmentMode() -> bool:
        return False


_INVALID = re.compile(r"[\s]")


class SymbolUtilities(m.JavaObject):
    """``ghidra.program.model.symbol.SymbolUtilities``: Ghidra's naming rules."""

    INVALIDCHARS = [" "]

    @staticmethod
    def replaceInvalidChars(name: str, replace_with_underscore: bool = True) -> Optional[str]:
        if name is None:
            return None
        out = []
        for ch in name:
            if ch.isspace() or ord(ch) < 0x20:
                if replace_with_underscore:
                    out.append("_")
            else:
                out.append(ch)
        return "".join(out)

    @staticmethod
    def containsInvalidChars(name: str) -> bool:
        return any(ch.isspace() or ord(ch) < 0x20 for ch in name)

    @staticmethod
    def getDefaultFunctionName(a) -> str:
        return f"FUN_{a}"

    @staticmethod
    def isDefaultFunctionName(name: str) -> bool:
        return bool(re.fullmatch(r"FUN_[0-9a-fA-F]+", name or ""))

    @staticmethod
    def isReservedDynamicLabelName(name: str, factory=None) -> bool:
        return name.startswith(p._DEFAULT_PREFIXES)

    @staticmethod
    def getAddressAppendedName(name: str, a) -> str:
        return f"{name}_{a}"


class DataTypeConflictHandler(m.JavaObject):
    DEFAULT_HANDLER = "DEFAULT_HANDLER"
    REPLACE_HANDLER = "REPLACE_HANDLER"
    KEEP_HANDLER = "KEEP_HANDLER"
    REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER = "REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER"


class CParser(m.JavaObject):
    """``ghidra.app.util.cparser.C.CParser``: parses C with revkit's ParseC;
    ``parse(text)`` returns the last type it defines, which
    ``getDataTypeManager().addDataType(dt, handler)`` then defines."""

    def __init__(self, dtm=None, *rest):
        self._dtm = dtm

    def parse(self, text: str):
        s = _flat.s
        parsed = s.prog.parse_c(text, name=f"{s.run.name}.h")
        if parsed.errors:
            raise ParseException("; ".join(parsed.errors))
        if not parsed.named:
            raise ParseException("no named type in the C text")
        key = parsed.named[-1].key
        name = key.split(" ", 1)[1] if key.startswith(("struct ", "union ", "enum ")) else key
        dt = m.DataType(name, key, -1, kind=key.split(" ", 1)[0] if " " in key else "typedef")
        dt.c_source = text
        return dt


class FlatProgramAPI(m.JavaObject):
    """``FlatProgramAPI(currentProgram)``: the running script's flat functions."""

    MAX_REFERENCES_TO = 0x1000

    def __new__(cls, *args, **kw):
        if _flat is None:
            raise Unsupported("FlatProgramAPI outside a script", "run the script with rk-script")
        return _flat


class FlatDecompilerAPI(m.JavaObject):
    """``ghidra.app.decompiler.flatapi.FlatDecompilerAPI``: ``decompile(f)`` -> C."""

    def __init__(self, flat=None):
        self._iface = dec.DecompInterface()

    def initialize(self) -> None:
        self._iface.openProgram(_flat.s.program)

    def getDecompiler(self) -> dec.DecompInterface:
        if self._iface.getProgram() is None:
            self.initialize()
        return self._iface

    def decompile(self, function, timeout: int = 0) -> str:
        r = self.getDecompiler().decompileFunction(function, timeout, None)
        if not r.decompileCompleted():
            raise Unsupported(f"decompile {function}", f"the decompiler failed: {r.getErrorMessage()}")
        return r.getDecompiledFunction().getC()

    def dispose(self) -> None:
        self._iface.dispose()


class _DummyMonitor(m.JavaObject):
    _java_name = "TaskMonitor"

    def isCancelled(self):
        return False

    isCanceled = isCancelled

    def checkCancelled(self):
        pass

    checkCanceled = checkCancelled

    def setMessage(self, *a):
        pass

    def setMaximum(self, *a):
        pass

    def setProgress(self, *a):
        pass

    def incrementProgress(self, *a):
        pass

    def initialize(self, *a):
        pass

    def setIndeterminate(self, *a):
        pass

    def getMessage(self):
        return ""


class TaskMonitorClass(m.JavaObject):
    DUMMY = _DummyMonitor()


class GhidraScript(m.JavaObject):
    """Importable for type hints; scripts are files, not subclasses."""


# Exceptions scripts catch.
class GhidraException(Exception):
    pass


class CancelledException(GhidraException):
    pass


class InvalidInputException(GhidraException):
    pass


class DuplicateNameException(GhidraException):
    pass


class AddressOutOfBoundsException(GhidraException, ValueError):
    pass


class AddressFormatException(GhidraException, ValueError):
    pass


class MemoryAccessException(GhidraException):
    pass


class CodeUnitInsertionException(GhidraException):
    pass


class ParseException(GhidraException):
    pass


class UsrException(GhidraException):
    pass


class NotFoundException(GhidraException):
    pass


# ---------------------------------------------------------------------------
# The class registry
# ---------------------------------------------------------------------------


def _classes() -> dict:
    """{java package: {simple name: object}} of what the shim provides."""
    from revkit.ghidra.compat import flat as f
    from revkit.script.runtime import Cancelled

    reg = {
        "ghidra.program.model.address": {
            "Address": m.Address, "AddressSet": m.AddressSet, "AddressSetView": m.AddressSetView,
            "AddressRange": m.AddressRange, "AddressSpace": m.AddressSpace, "AddressFactory": p.AddressFactory,
            "AddressIterator": m.JavaIterator, "AddressRangeIterator": m.JavaIterator,
            "AddressOutOfBoundsException": AddressOutOfBoundsException,
            "AddressFormatException": AddressFormatException, "GenericAddress": m.Address,
        },
        "ghidra.program.model.listing": {
            "Program": p.Program, "Listing": p.Listing, "Function": p.Function, "FunctionManager": p.FunctionManager,
            "Instruction": p.Instruction, "Data": p.Data, "CodeUnit": p.CodeUnit, "CommentType": m.CommentType,
            "Variable": p.Variable, "Parameter": p.Parameter, "LocalVariable": p.Variable,
            "FunctionIterator": m.JavaIterator, "InstructionIterator": m.JavaIterator, "DataIterator": m.JavaIterator,
            "CodeUnitIterator": m.JavaIterator, "FunctionSignature": p.FunctionSignature,
            "VariableStorage": p.VariableStorage,
        },
        "ghidra.program.model.symbol": {
            "Symbol": p.Symbol, "SymbolTable": p.SymbolTable, "SymbolType": m.SymbolType,
            "SourceType": m.SourceType, "RefType": m.RefType, "FlowType": m.FlowType, "Reference": p.Reference,
            "ReferenceManager": p.ReferenceManager, "Namespace": p.GlobalNamespace,
            "SymbolIterator": m.JavaIterator, "ReferenceIterator": m.JavaIterator,
            "SymbolUtilities": SymbolUtilities, "Equate": p.Equate, "EquateTable": p.EquateTable,
            "EquateReference": p.EquateReference,
        },
        "ghidra.program.model.mem": {
            "Memory": p.Memory, "MemoryBlock": p.MemoryBlock, "MemoryAccessException": MemoryAccessException,
        },
        "ghidra.program.model.lang": {
            "Register": m.Register, "OperandType": m.OperandType, "Language": p.Language,
            "LanguageID": p.LanguageID, "CompilerSpec": p.CompilerSpec, "CompilerSpecID": p.CompilerSpecID,
            "Processor": p.Processor,
        },
        "ghidra.program.model.scalar": {"Scalar": m.Scalar},
        "ghidra.program.model.data": {
            "DataType": m.DataType, "CategoryPath": m.CategoryPath, "DataTypeManager": p.DataTypeManager,
            "DataTypeConflictHandler": DataTypeConflictHandler, **m.BUILTIN_CLASSES,
        },
        "ghidra.program.model.pcode": {
            "PcodeOp": dec.PcodeOp, "PcodeOpAST": dec.PcodeOpAST, "Varnode": dec.Varnode,
            "VarnodeAST": dec.Varnode, "HighFunction": dec.HighFunction, "HighSymbol": dec.HighSymbol,
            "HighVariable": dec.HighVariable, "LocalSymbolMap": dec.LocalSymbolMap,
            "HighFunctionDBUtil": dec.HighFunctionDBUtil, "SequenceNumber": dec.SequenceNumber,
            "FunctionPrototype": dec.FunctionPrototype,
        },
        "ghidra.program.model.pcode.HighFunctionDBUtil": {"ReturnCommitOption": dec.ReturnCommitOption},
        "ghidra.app.decompiler": {
            "DecompInterface": dec.DecompInterface, "DecompileOptions": dec.DecompileOptions,
            "DecompileResults": dec.DecompileResults, "DecompiledFunction": dec.DecompiledFunction,
        },
        "ghidra.app.decompiler.flatapi": {"FlatDecompilerAPI": FlatDecompilerAPI},
        "ghidra.program.flatapi": {"FlatProgramAPI": FlatProgramAPI},
        "ghidra.app.script": {"GhidraScript": GhidraScript, "GhidraState": f.GhidraState},
        "ghidra.program.util": {"ProgramLocation": f.ProgramLocation, "ProgramSelection": f.ProgramSelection},
        "ghidra.util": {"Msg": Msg, "SystemUtilities": SystemUtilities},
        "ghidra.util.task": {"TaskMonitor": TaskMonitorClass},
        "ghidra.util.exception": {
            "CancelledException": Cancelled, "InvalidInputException": InvalidInputException,
            "DuplicateNameException": DuplicateNameException, "UsrException": UsrException,
            "NotFoundException": NotFoundException,
        },
        "ghidra.program.model.util": {"CodeUnitInsertionException": CodeUnitInsertionException},
        "ghidra.app.util.cparser.C": {"CParser": CParser, "ParseException": ParseException},
    }
    return reg


_REGISTRY: Optional[dict] = None
_BY_NAME: dict = {}


def registry() -> dict:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = _classes()
        for pkg, classes in _REGISTRY.items():
            for name, obj in classes.items():
                _BY_NAME.setdefault(name, obj)
    return _REGISTRY


def placeholder(full: str):
    """A stand-in for a Ghidra or Java class the shim lacks: any use raises
    Unsupported naming it."""
    api = full
    simple = full.rsplit(".", 1)[-1]

    class _Meta(type):
        def __getattr__(cls, name):
            if name.startswith("__"):
                raise AttributeError(name)
            raise Unsupported(f"{api}.{name}", replacement_for(api))

        def __call__(cls, *a, **k):
            raise Unsupported(api, replacement_for(api))

        def __repr__(cls):
            return f"<unsupported {api}>"

    return _Meta(simple, (), {"__module__": full.rsplit(".", 1)[0], "_unsupported": api})


def lookup(full: str):
    """The shim's object for a dotted Java name, or a placeholder."""
    reg = registry()
    pkg, _, name = full.rpartition(".")
    if pkg in reg and name in reg[pkg]:
        return reg[pkg][name]
    if full.split(".", 1)[0] == "ghidra" and name in _BY_NAME:
        return _BY_NAME[name]
    return placeholder(full)


def _is_class_name(name: str) -> bool:
    return name[:1].isupper()


class _Package(types.ModuleType):
    """A ``ghidra.x.y`` package: its attributes are classes (or subpackages)."""

    def __getattr__(self, attr):
        if attr.startswith("__"):
            if attr == "__all__":
                return sorted(registry().get(self.__name__, {}))
            raise AttributeError(attr)
        full = f"{self.__name__}.{attr}"
        if _is_class_name(attr) or self.__name__ == "jpype":
            obj = lookup(full)
            setattr(self, attr, obj)
            return obj
        mod = importlib.import_module(full)
        setattr(self, attr, mod)
        return mod


class _Loader(importlib.abc.Loader):
    def create_module(self, spec):
        name = spec.name
        if "." in name and _is_class_name(name.rsplit(".", 1)[-1]) and name not in registry():
            return _ClassModule(name, lookup(name))
        return _Package(name)

    def exec_module(self, module):
        module.__path__ = []


class _ClassModule(_Package):
    """``import ghidra.program.model.data.StringDataType as StringDataType``
    binds the class itself (see :func:`_bind_class_imports`); ``from
    ...SourceType import *`` takes the class's public constants."""

    def __init__(self, name, cls):
        super().__init__(name)
        self._cls = cls
        names = [k for k in dir(cls) if not k.startswith("_") and not callable(getattr(cls, k, None))]
        names += [k for k, v in vars(cls).items() if not k.startswith("_") and isinstance(v, m.JavaObject)]
        for k in names:
            try:
                setattr(self, k, getattr(cls, k))
            except Unsupported:
                pass
        self.__all__ = sorted(set(names))

    def __getattr__(self, attr):
        if attr.startswith("__"):
            raise AttributeError(attr)
        return getattr(self._cls, attr)


class _Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        root = name.split(".", 1)[0]
        if root not in ROOTS:
            return None
        if root == "generic" and not _flat:
            return None
        return importlib.machinery.ModuleSpec(name, _Loader(), is_package=True)


_finder = _Finder()


def install(flat) -> None:
    global _flat
    _flat = flat
    registry()
    if _finder not in sys.meta_path:
        sys.meta_path.insert(0, _finder)
    for k in [k for k in sys.modules if k.split(".", 1)[0] in ROOTS]:
        del sys.modules[k]


def uninstall() -> None:
    global _flat
    _flat = None
    if _finder in sys.meta_path:
        sys.meta_path.remove(_finder)
    for k in [k for k, v in list(sys.modules.items()) if isinstance(v, _Package)]:
        del sys.modules[k]


_CLASS_IMPORT = re.compile(r"^(\s*)import\s+((?:ghidra)(?:\.\w+)+\.([A-Z]\w*))\s+as\s+(\w+)\s*$", re.M)


def bind_class_imports(source: str) -> str:
    """``import ghidra.a.b.Class as X`` -> ``from ghidra.a.b import Class as X``,
    so X is the class (Jython and JPype bind the class for that form)."""
    def sub(mt):
        indent, full, cls, alias = mt.groups()
        return f"{indent}from {full.rsplit('.', 1)[0]} import {cls} as {alias}"

    return _CLASS_IMPORT.sub(sub, source)
