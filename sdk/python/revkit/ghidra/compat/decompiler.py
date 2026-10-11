"""``ghidra.app.decompiler`` for the compat shim: ``DecompInterface`` over
revkit's ``Decompile``.

``decompileFunction(f, timeout, monitor).getDecompiledFunction().getC()`` is
the daemon's C. ``getHighFunction()`` gives ``getLocalSymbolMap()`` from the
decompilation's variables (renamed and retyped with
``HighFunctionDBUtil.updateDBVariable``, which buffers ``rename_local`` and
``retype_local``) and ``getPcodeOps()``: the *raw* p-code of the function's
instructions, with each varnode tied to the decompiler's variable where the
decompilation's varnode table maps it. Ghidra's high p-code (SSA, after the
decompiler's simplification) is not exposed, so op counts differ from
Ghidra's; scripts that walk def-use chains fail with Unsupported.
"""

from __future__ import annotations

from typing import Optional

from revkit.client import RevkitError
from revkit.ghidra.compat.errors import Unsupported
from revkit.ghidra.compat.model import Address, JavaIterator, JavaObject, addr_int, space_named
from revkit.v1 import listing_pb2, query_pb2


def _opcodes() -> dict:
    out = {}
    for name, value in listing_pb2.PcodeOpcode.items():
        if name != "PCODE_OPCODE_UNSPECIFIED":
            out[name.replace("PCODE_OPCODE_", "")] = value
    out["UNIMPLEMENTED"] = 0
    out["EXTRACT"] = out.get("ZPULL", 71)
    return out


OPCODES = _opcodes()
_MNEMONIC = {v: k for k, v in OPCODES.items() if k not in ("EXTRACT", "UNIMPLEMENTED")}


class SequenceNumber(JavaObject):
    def __init__(self, target: Address, time: int):
        self.target = target
        self.time = time

    def getTarget(self) -> Address:
        return self.target

    def getTime(self) -> int:
        return self.time

    def getOrder(self) -> int:
        return self.time

    def __str__(self):
        return f"({self.target}, 0x{self.time:x}, {self.time})"


class Varnode(JavaObject):
    """A p-code varnode (``ghidra.program.model.pcode.Varnode``)."""

    _java_name = "Varnode"

    def __init__(self, v, high: Optional["HighVariable"] = None):
        self._v = v
        self._high = high

    def getAddress(self) -> Address:
        return Address(self._v.offset, space_named(self._v.space or "ram"))

    def getOffset(self) -> int:
        o = self._v.offset
        return o - (1 << 64) if o >= 1 << 63 else o

    def getSize(self) -> int:
        return self._v.size

    def getSpace(self) -> int:
        return hash(self._v.space) & 0x7FFFFFFF

    def isConstant(self) -> bool:
        return self._v.space == "const"

    def isRegister(self) -> bool:
        return self._v.space == "register"

    def isUnique(self) -> bool:
        return self._v.space == "unique"

    def isAddress(self) -> bool:
        return self._v.space not in ("const", "register", "unique", "stack")

    def isStackAddress(self) -> bool:
        return self._v.space == "stack"

    def isFree(self) -> bool:
        return self._v.space in ("register", "unique") and self._high is None

    def isInput(self) -> bool:
        return False

    def getHigh(self) -> Optional["HighVariable"]:
        return self._high

    def getRegisterName(self) -> str:
        """revkit's register name for a register varnode ("" otherwise)."""
        return self._v.register_name

    def getDef(self):
        raise Unsupported("Varnode.getDef")

    def getDescendants(self):
        raise Unsupported("Varnode.getDescendants")

    def __str__(self):
        if self._v.space == "register" and self._v.register_name:
            return f"({self._v.register_name}, {self._v.size})"
        return f"({self._v.space}, 0x{self._v.offset:x}, {self._v.size})"

    def __eq__(self, other):
        return isinstance(other, Varnode) and (other._v.space, other._v.offset, other._v.size) == (
            self._v.space, self._v.offset, self._v.size)

    def __hash__(self):
        return hash((self._v.space, self._v.offset, self._v.size))


class PcodeOp(JavaObject):
    """One p-code op of an instruction (``PcodeOp`` / ``PcodeOpAST``)."""

    _java_name = "PcodeOp"
    locals().update(OPCODES)

    def __init__(self, s, op: listing_pb2.PcodeOp, at: int, index: int, highs: Optional[dict] = None):
        self._s = s
        self._op = op
        self._at = at
        self._index = index
        self._highs = highs or {}

    def _vn(self, v) -> Varnode:
        return Varnode(v, self._highs.get((v.space, v.offset, v.size)))

    def getOpcode(self) -> int:
        return int(self._op.opcode)

    def getMnemonic(self) -> str:
        return self._op.mnemonic or _MNEMONIC.get(int(self._op.opcode), "UNKNOWN")

    @staticmethod
    def getMnemonicStatic(opcode: int) -> str:
        return _MNEMONIC.get(int(opcode), "UNKNOWN")

    def getOutput(self) -> Optional[Varnode]:
        return self._vn(self._op.output) if self._op.HasField("output") else None

    def getInput(self, i: int) -> Optional[Varnode]:
        return self._vn(self._op.inputs[i]) if 0 <= i < len(self._op.inputs) else None

    def getInputs(self) -> list:
        return [self._vn(v) for v in self._op.inputs]

    def getNumInputs(self) -> int:
        return len(self._op.inputs)

    def getSeqnum(self) -> SequenceNumber:
        return SequenceNumber(self._s.addr(self._at), self._index)

    def isAssignment(self) -> bool:
        return self._op.HasField("output")

    def getParent(self):
        raise Unsupported("PcodeOpAST.getParent", "the function's blocks: GetFunctionGraph (QueryService)")

    def __str__(self):
        out = f"{self.getOutput()} = " if self._op.HasField("output") else ""
        return out + self.getMnemonic() + " " + " , ".join(str(v) for v in self.getInputs())


PcodeOpAST = PcodeOp


class DecompileOptions(JavaObject):
    def __init__(self):
        self.timeout = 30

    def grabFromProgram(self, program) -> None:
        pass

    def getDefaultTimeout(self) -> int:
        return self.timeout

    def setDefaultTimeout(self, seconds: int) -> None:
        self.timeout = int(seconds)

    def setMaxPayloadMBytes(self, n: int) -> None:
        pass

    def getMaxPayloadMBytes(self) -> int:
        return 50

    def setEliminateUnreachable(self, value: bool) -> None:
        pass

    def setRespectReadOnly(self, value: bool) -> None:
        pass


class DecompInterface(JavaObject):
    """``ghidra.app.decompiler.DecompInterface``: the daemon's decompiler.

    The style (``setSimplificationStyle``), ``toggleCCode`` and
    ``toggleSyntaxTree`` are accepted and ignored: revkit decompiles
    one way and always returns C and variables."""

    def __init__(self):
        self._program = None
        self._options = DecompileOptions()
        self._last = ""

    def openProgram(self, program) -> bool:
        self._program = program
        return True

    def closeProgram(self) -> None:
        self._program = None

    def dispose(self) -> None:
        self._program = None

    def getProgram(self):
        return self._program

    def setOptions(self, options) -> bool:
        self._options = options or DecompileOptions()
        return True

    def getOptions(self) -> DecompileOptions:
        return self._options

    def toggleCCode(self, on: bool) -> bool:
        return True

    def toggleSyntaxTree(self, on: bool) -> bool:
        return True

    def toggleParamMeasures(self, on: bool) -> bool:
        return True

    def toggleJumpLoads(self, on: bool) -> bool:
        return True

    def setSimplificationStyle(self, style: str) -> bool:
        return True

    def getSimplificationStyle(self) -> str:
        return "decompile"

    def getLastMessage(self) -> str:
        return self._last

    def decompileFunction(self, func, timeout: int = 0, monitor=None) -> "DecompileResults":
        if self._program is None:
            raise Unsupported("DecompInterface.decompileFunction before openProgram", "call openProgram(currentProgram) first")
        s = self._program._s
        if monitor is not None and hasattr(monitor, "checkCancelled"):
            monitor.checkCancelled()
        s.sync()
        from revkit.v1 import common_pb2

        req = query_pb2.DecompileRequest(program_id=s.prog.id, function=common_pb2.Address(offset=addr_int(func)),
                                         read=s.prog._read())
        req.options.include_text = True
        if timeout:
            req.options.timeout_ms = int(timeout) * 1000
        try:
            resp = s.prog._q("Decompile", req)
        except RevkitError as e:
            self._last = e.message
            return DecompileResults(s, func, None, e.message)
        if resp.HasField("failure"):
            f = resp.failure
            from revkit.v1 import decompile_pb2

            kind = decompile_pb2.DecompileFailureKind.Name(f.kind).replace("DECOMPILE_FAILURE_KIND_", "")
            self._last = f"{kind}: {f.detail}".strip(": ")
            return DecompileResults(s, func, None, self._last, timed_out=kind == "TIMEOUT")
        self._last = ""
        return DecompileResults(s, func, resp.function, "")


class DecompileResults(JavaObject):
    def __init__(self, s, func, d, error: str, timed_out: bool = False):
        self._s = s
        self._func = func
        self._d = d
        self._error = error
        self._timed_out = timed_out
        self._high = None

    def decompileCompleted(self) -> bool:
        return self._d is not None

    def getErrorMessage(self) -> str:
        return self._error

    def isTimedOut(self) -> bool:
        return self._timed_out

    def isCancelled(self) -> bool:
        return False

    def failedToStart(self) -> bool:
        return False

    def isValid(self) -> bool:
        return self._d is not None

    def getFunction(self):
        if hasattr(self._func, "getEntryPoint"):
            return self._func
        return self._s.function_at(addr_int(self._func))

    def getDecompiledFunction(self) -> Optional["DecompiledFunction"]:
        return DecompiledFunction(self._d) if self._d is not None else None

    def getHighFunction(self) -> Optional["HighFunction"]:
        if self._d is None:
            return None
        if self._high is None:
            self._high = HighFunction(self._s, self.getFunction(), self._d)
        return self._high

    def getCCodeMarkup(self):
        raise Unsupported("DecompileResults.getCCodeMarkup")


class DecompiledFunction(JavaObject):
    def __init__(self, d):
        self._d = d

    def getC(self) -> str:
        return self._d.text

    def getSignature(self) -> str:
        return self._d.prototype.c_declaration


class HighSymbol(JavaObject):
    """A decompiler variable (``HighSymbol``), from ``Decompile.variables``."""

    _java_name = "HighSymbol"

    def __init__(self, high: "HighFunction", v):
        self._high = high
        self._v = v

    def getName(self) -> str:
        s = self._high._s
        return s.local_names.get((self._high._entry, self._v.storage_key), self._v.name)

    def getDataType(self):
        from revkit.ghidra.compat.program import type_named

        return type_named(self._high._s, self._v.type.display)

    def getSize(self) -> int:
        return sum(v.size for v in self._v.storage)

    def getStorage(self):
        from revkit.ghidra.compat.program import VariableStorage

        return VariableStorage(self._v.storage)

    def isParameter(self) -> bool:
        return self._v.kind == 1

    def isGlobal(self) -> bool:
        return self._v.kind == 3

    def getCategoryIndex(self) -> int:
        return self._v.parameter_index if self._v.kind == 1 else -1

    def getHighFunction(self) -> "HighFunction":
        return self._high

    def getHighVariable(self) -> "HighVariable":
        return HighVariable(self)

    def getPCAddress(self) -> Optional[Address]:
        key = self._v.storage_key
        if "@" in key:
            return self._high._s.addr(int(key.rsplit("@", 1)[1], 16))
        return None

    def getId(self) -> int:
        return self._v.index

    def isNameLocked(self) -> bool:
        return self._v.name_origin.WhichOneof("source") == "asserted"

    def isTypeLocked(self) -> bool:
        return self._v.type_origin.WhichOneof("source") == "asserted"

    def getStorageKey(self) -> str:
        """revkit's storage key (rename_local / retype_local)."""
        return self._v.storage_key

    def __str__(self):
        return self.getName()

    def __eq__(self, other):
        return isinstance(other, HighSymbol) and other._v.storage_key == self._v.storage_key

    def __hash__(self):
        return hash(self._v.storage_key)


class HighVariable(JavaObject):
    _java_name = "HighVariable"

    def __init__(self, sym: HighSymbol):
        self._sym = sym

    def getName(self) -> str:
        return self._sym.getName()

    def getSymbol(self) -> HighSymbol:
        return self._sym

    def getDataType(self):
        return self._sym.getDataType()

    def getSize(self) -> int:
        return self._sym.getSize()

    def getHighFunction(self) -> "HighFunction":
        return self._sym._high

    def getRepresentative(self):
        st = self._sym._v.storage
        return Varnode(st[0], self) if st else None

    def getInstances(self) -> list:
        return [Varnode(m.varnode, self) for m in self._sym._high._d.varnodes
                if m.HasField("variable_index") and m.variable_index == self._sym._v.index]

    def __str__(self):
        return self.getName()

    def __eq__(self, other):
        return isinstance(other, HighVariable) and other._sym == self._sym

    def __hash__(self):
        return hash(self._sym)


class LocalSymbolMap(JavaObject):
    def __init__(self, high: "HighFunction"):
        self._high = high

    def _syms(self) -> list:
        return [HighSymbol(self._high, v) for v in self._high._d.variables if v.kind in (1, 2)]

    def getSymbols(self):
        return JavaIterator(self._syms())

    def getNumParams(self) -> int:
        return sum(1 for v in self._high._d.variables if v.kind == 1)

    def getParamSymbol(self, i: int) -> Optional[HighSymbol]:
        for v in self._high._d.variables:
            if v.kind == 1 and v.parameter_index == i:
                return HighSymbol(self._high, v)
        return None

    def getParam(self, i: int):
        s = self.getParamSymbol(i)
        return s.getHighVariable() if s else None

    def getNameToSymbolMap(self) -> dict:
        return {s.getName(): s for s in self._syms()}

    def getHighFunction(self) -> "HighFunction":
        return self._high


class FunctionPrototype(JavaObject):
    def __init__(self, high: "HighFunction"):
        self._high = high

    def getReturnType(self):
        from revkit.ghidra.compat.program import type_named

        return type_named(self._high._s, self._high._d.prototype.return_type.display)

    def getNumParams(self) -> int:
        return self._high.getLocalSymbolMap().getNumParams()

    def getParam(self, i: int):
        return self._high.getLocalSymbolMap().getParamSymbol(i)

    def isVarArg(self) -> bool:
        return self._high._d.prototype.varargs

    def hasNoReturn(self) -> bool:
        return self._high._d.prototype.no_return

    def getModelName(self) -> str:
        return self._high._d.prototype.calling_convention or "unknown"


class HighFunction(JavaObject):
    _java_name = "HighFunction"

    def __init__(self, s, func, d):
        self._s = s
        self._func = func
        self._d = d
        self._entry = d.entry.offset
        self._ops = None

    def getFunction(self):
        return self._func

    def getLocalSymbolMap(self) -> LocalSymbolMap:
        return LocalSymbolMap(self)

    def getFunctionPrototype(self) -> FunctionPrototype:
        return FunctionPrototype(self)

    def getLanguage(self):
        return self._s.program.getLanguage()

    def _highs(self) -> dict:
        syms = {v.index: HighSymbol(self, v) for v in self._d.variables}
        out = {}
        for m in self._d.varnodes:
            if m.HasField("variable_index") and m.variable_index in syms:
                vn = m.varnode
                out[(vn.space, vn.offset, vn.size)] = HighVariable(syms[m.variable_index])
        return out

    def getPcodeOps(self, a=None):
        """Raw p-code of the function's instructions (or of the one at ``a``),
        varnodes tied to the decompiler's variables where its table maps them."""
        if self._ops is None:
            highs = self._highs()
            ops = []
            for d in self._s.prog.instructions(function=self._entry, pcode=True):
                for i, op in enumerate(d.pcode):
                    ops.append(PcodeOp(self._s, op, d.address.offset, i, highs))
            self._ops = ops
        if a is None:
            return JavaIterator(list(self._ops))
        o = addr_int(a)
        return JavaIterator([op for op in self._ops if op._at == o])

    def getPcodeOp(self, seq):
        raise Unsupported("HighFunction.getPcodeOp(seqnum)", "iterate getPcodeOps(address)")

    def getBasicBlocks(self):
        raise Unsupported("HighFunction.getBasicBlocks")

    def getGlobalSymbolMap(self):
        raise Unsupported("HighFunction.getGlobalSymbolMap")

    def getVarnodes(self, *a):
        raise Unsupported("HighFunction.getVarnodes")


class HighFunctionDBUtil(JavaObject):
    """``updateDBVariable(symbol, name, type, source)``: a buffered
    ``rename_local`` / ``retype_local``."""

    @staticmethod
    def updateDBVariable(sym: HighSymbol, name, dtype, source=None) -> None:
        high = sym._high
        key = sym._v.storage_key
        if name is not None and name != sym.getName():
            high._s.rename_local(high._entry, key, name)
        if dtype is not None:
            high._s.retype_local(high._entry, key, getattr(dtype, "c", str(dtype)))

    @staticmethod
    def commitParamsToDatabase(*a, **k):
        raise Unsupported("HighFunctionDBUtil.commitParamsToDatabase")

    @staticmethod
    def commitLocalNamesToDatabase(*a, **k):
        raise Unsupported("HighFunctionDBUtil.commitLocalNamesToDatabase")

    @staticmethod
    def commitReturnToDatabase(*a, **k):
        raise Unsupported("HighFunctionDBUtil.commitReturnToDatabase",
                          "give the prototype as C: retype(entry, 'int f(char *s)')")


class ReturnCommitOption(JavaObject):
    NO_COMMIT = "NO_COMMIT"
    COMMIT = "COMMIT"
    COMMIT_NO_VOID = "COMMIT_NO_VOID"
