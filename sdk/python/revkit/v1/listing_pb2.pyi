from revkit.v1 import assertion_pb2 as _assertion_pb2
from revkit.v1 import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class FunctionSort(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FUNCTION_SORT_UNSPECIFIED: _ClassVar[FunctionSort]
    FUNCTION_SORT_ADDRESS: _ClassVar[FunctionSort]
    FUNCTION_SORT_NAME: _ClassVar[FunctionSort]
    FUNCTION_SORT_SIZE: _ClassVar[FunctionSort]
    FUNCTION_SORT_XREFS: _ClassVar[FunctionSort]

class SymbolKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SYMBOL_KIND_UNSPECIFIED: _ClassVar[SymbolKind]
    SYMBOL_KIND_FUNCTION: _ClassVar[SymbolKind]
    SYMBOL_KIND_LABEL: _ClassVar[SymbolKind]

class ListingRowKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    LISTING_ROW_KIND_UNSPECIFIED: _ClassVar[ListingRowKind]
    LISTING_ROW_KIND_INSTRUCTION: _ClassVar[ListingRowKind]
    LISTING_ROW_KIND_DATA: _ClassVar[ListingRowKind]
    LISTING_ROW_KIND_UNDEFINED: _ClassVar[ListingRowKind]
    LISTING_ROW_KIND_HEADER: _ClassVar[ListingRowKind]

class ListingHeaderKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    LISTING_HEADER_KIND_UNSPECIFIED: _ClassVar[ListingHeaderKind]
    LISTING_HEADER_KIND_PLATE: _ClassVar[ListingHeaderKind]
    LISTING_HEADER_KIND_SIGNATURE: _ClassVar[ListingHeaderKind]
    LISTING_HEADER_KIND_LABEL: _ClassVar[ListingHeaderKind]
    LISTING_HEADER_KIND_PRE_COMMENT: _ClassVar[ListingHeaderKind]

class ListingTokenKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    LISTING_TOKEN_KIND_UNSPECIFIED: _ClassVar[ListingTokenKind]
    LISTING_TOKEN_KIND_MNEMONIC: _ClassVar[ListingTokenKind]
    LISTING_TOKEN_KIND_REGISTER: _ClassVar[ListingTokenKind]
    LISTING_TOKEN_KIND_SCALAR: _ClassVar[ListingTokenKind]
    LISTING_TOKEN_KIND_ADDRESS: _ClassVar[ListingTokenKind]
    LISTING_TOKEN_KIND_SYMBOL: _ClassVar[ListingTokenKind]
    LISTING_TOKEN_KIND_SEPARATOR: _ClassVar[ListingTokenKind]
    LISTING_TOKEN_KIND_WHITESPACE: _ClassVar[ListingTokenKind]
    LISTING_TOKEN_KIND_PREFIX: _ClassVar[ListingTokenKind]
    LISTING_TOKEN_KIND_DATA_VALUE: _ClassVar[ListingTokenKind]
    LISTING_TOKEN_KIND_TYPE: _ClassVar[ListingTokenKind]

class PcodeOpcode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PCODE_OPCODE_UNSPECIFIED: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_COPY: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_LOAD: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_STORE: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_BRANCH: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_CBRANCH: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_BRANCHIND: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_CALL: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_CALLIND: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_CALLOTHER: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_RETURN: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_EQUAL: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_NOTEQUAL: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_SLESS: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_SLESSEQUAL: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_LESS: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_LESSEQUAL: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_ZEXT: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_SEXT: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_ADD: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_SUB: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_CARRY: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_SCARRY: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_SBORROW: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_2COMP: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_NEGATE: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_XOR: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_AND: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_OR: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_LEFT: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_RIGHT: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_SRIGHT: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_MULT: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_DIV: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_SDIV: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_REM: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INT_SREM: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_BOOL_NEGATE: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_BOOL_XOR: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_BOOL_AND: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_BOOL_OR: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_EQUAL: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_NOTEQUAL: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_LESS: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_LESSEQUAL: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_NAN: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_ADD: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_DIV: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_MULT: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_SUB: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_NEG: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_ABS: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_SQRT: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_INT2FLOAT: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_FLOAT2FLOAT: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_TRUNC: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_CEIL: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_FLOOR: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_FLOAT_ROUND: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_MULTIEQUAL: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INDIRECT: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_PIECE: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_SUBPIECE: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_CAST: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_PTRADD: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_PTRSUB: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_SEGMENTOP: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_CPOOLREF: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_NEW: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_INSERT: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_ZPULL: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_POPCOUNT: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_LZCOUNT: _ClassVar[PcodeOpcode]
    PCODE_OPCODE_SPULL: _ClassVar[PcodeOpcode]

class FlowKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FLOW_KIND_UNSPECIFIED: _ClassVar[FlowKind]
    FLOW_KIND_FALL_THROUGH: _ClassVar[FlowKind]
    FLOW_KIND_UNCONDITIONAL_BRANCH: _ClassVar[FlowKind]
    FLOW_KIND_CONDITIONAL_BRANCH: _ClassVar[FlowKind]
    FLOW_KIND_CALL: _ClassVar[FlowKind]
    FLOW_KIND_RETURN: _ClassVar[FlowKind]
    FLOW_KIND_INDIRECT_BRANCH: _ClassVar[FlowKind]
    FLOW_KIND_INDIRECT_CALL: _ClassVar[FlowKind]
    FLOW_KIND_TERMINATOR: _ClassVar[FlowKind]

class XrefKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    XREF_KIND_UNSPECIFIED: _ClassVar[XrefKind]
    XREF_KIND_CALL: _ClassVar[XrefKind]
    XREF_KIND_JUMP: _ClassVar[XrefKind]
    XREF_KIND_CONDITIONAL_JUMP: _ClassVar[XrefKind]
    XREF_KIND_INDIRECT_CALL: _ClassVar[XrefKind]
    XREF_KIND_INDIRECT_JUMP: _ClassVar[XrefKind]
    XREF_KIND_DATA_READ: _ClassVar[XrefKind]
    XREF_KIND_DATA_WRITE: _ClassVar[XrefKind]
    XREF_KIND_DATA_POINTER: _ClassVar[XrefKind]
    XREF_KIND_THUNK: _ClassVar[XrefKind]
    XREF_KIND_FALLTHROUGH: _ClassVar[XrefKind]

class XrefDirection(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    XREF_DIRECTION_UNSPECIFIED: _ClassVar[XrefDirection]
    XREF_DIRECTION_TO: _ClassVar[XrefDirection]
    XREF_DIRECTION_FROM: _ClassVar[XrefDirection]
    XREF_DIRECTION_BOTH: _ClassVar[XrefDirection]
FUNCTION_SORT_UNSPECIFIED: FunctionSort
FUNCTION_SORT_ADDRESS: FunctionSort
FUNCTION_SORT_NAME: FunctionSort
FUNCTION_SORT_SIZE: FunctionSort
FUNCTION_SORT_XREFS: FunctionSort
SYMBOL_KIND_UNSPECIFIED: SymbolKind
SYMBOL_KIND_FUNCTION: SymbolKind
SYMBOL_KIND_LABEL: SymbolKind
LISTING_ROW_KIND_UNSPECIFIED: ListingRowKind
LISTING_ROW_KIND_INSTRUCTION: ListingRowKind
LISTING_ROW_KIND_DATA: ListingRowKind
LISTING_ROW_KIND_UNDEFINED: ListingRowKind
LISTING_ROW_KIND_HEADER: ListingRowKind
LISTING_HEADER_KIND_UNSPECIFIED: ListingHeaderKind
LISTING_HEADER_KIND_PLATE: ListingHeaderKind
LISTING_HEADER_KIND_SIGNATURE: ListingHeaderKind
LISTING_HEADER_KIND_LABEL: ListingHeaderKind
LISTING_HEADER_KIND_PRE_COMMENT: ListingHeaderKind
LISTING_TOKEN_KIND_UNSPECIFIED: ListingTokenKind
LISTING_TOKEN_KIND_MNEMONIC: ListingTokenKind
LISTING_TOKEN_KIND_REGISTER: ListingTokenKind
LISTING_TOKEN_KIND_SCALAR: ListingTokenKind
LISTING_TOKEN_KIND_ADDRESS: ListingTokenKind
LISTING_TOKEN_KIND_SYMBOL: ListingTokenKind
LISTING_TOKEN_KIND_SEPARATOR: ListingTokenKind
LISTING_TOKEN_KIND_WHITESPACE: ListingTokenKind
LISTING_TOKEN_KIND_PREFIX: ListingTokenKind
LISTING_TOKEN_KIND_DATA_VALUE: ListingTokenKind
LISTING_TOKEN_KIND_TYPE: ListingTokenKind
PCODE_OPCODE_UNSPECIFIED: PcodeOpcode
PCODE_OPCODE_COPY: PcodeOpcode
PCODE_OPCODE_LOAD: PcodeOpcode
PCODE_OPCODE_STORE: PcodeOpcode
PCODE_OPCODE_BRANCH: PcodeOpcode
PCODE_OPCODE_CBRANCH: PcodeOpcode
PCODE_OPCODE_BRANCHIND: PcodeOpcode
PCODE_OPCODE_CALL: PcodeOpcode
PCODE_OPCODE_CALLIND: PcodeOpcode
PCODE_OPCODE_CALLOTHER: PcodeOpcode
PCODE_OPCODE_RETURN: PcodeOpcode
PCODE_OPCODE_INT_EQUAL: PcodeOpcode
PCODE_OPCODE_INT_NOTEQUAL: PcodeOpcode
PCODE_OPCODE_INT_SLESS: PcodeOpcode
PCODE_OPCODE_INT_SLESSEQUAL: PcodeOpcode
PCODE_OPCODE_INT_LESS: PcodeOpcode
PCODE_OPCODE_INT_LESSEQUAL: PcodeOpcode
PCODE_OPCODE_INT_ZEXT: PcodeOpcode
PCODE_OPCODE_INT_SEXT: PcodeOpcode
PCODE_OPCODE_INT_ADD: PcodeOpcode
PCODE_OPCODE_INT_SUB: PcodeOpcode
PCODE_OPCODE_INT_CARRY: PcodeOpcode
PCODE_OPCODE_INT_SCARRY: PcodeOpcode
PCODE_OPCODE_INT_SBORROW: PcodeOpcode
PCODE_OPCODE_INT_2COMP: PcodeOpcode
PCODE_OPCODE_INT_NEGATE: PcodeOpcode
PCODE_OPCODE_INT_XOR: PcodeOpcode
PCODE_OPCODE_INT_AND: PcodeOpcode
PCODE_OPCODE_INT_OR: PcodeOpcode
PCODE_OPCODE_INT_LEFT: PcodeOpcode
PCODE_OPCODE_INT_RIGHT: PcodeOpcode
PCODE_OPCODE_INT_SRIGHT: PcodeOpcode
PCODE_OPCODE_INT_MULT: PcodeOpcode
PCODE_OPCODE_INT_DIV: PcodeOpcode
PCODE_OPCODE_INT_SDIV: PcodeOpcode
PCODE_OPCODE_INT_REM: PcodeOpcode
PCODE_OPCODE_INT_SREM: PcodeOpcode
PCODE_OPCODE_BOOL_NEGATE: PcodeOpcode
PCODE_OPCODE_BOOL_XOR: PcodeOpcode
PCODE_OPCODE_BOOL_AND: PcodeOpcode
PCODE_OPCODE_BOOL_OR: PcodeOpcode
PCODE_OPCODE_FLOAT_EQUAL: PcodeOpcode
PCODE_OPCODE_FLOAT_NOTEQUAL: PcodeOpcode
PCODE_OPCODE_FLOAT_LESS: PcodeOpcode
PCODE_OPCODE_FLOAT_LESSEQUAL: PcodeOpcode
PCODE_OPCODE_FLOAT_NAN: PcodeOpcode
PCODE_OPCODE_FLOAT_ADD: PcodeOpcode
PCODE_OPCODE_FLOAT_DIV: PcodeOpcode
PCODE_OPCODE_FLOAT_MULT: PcodeOpcode
PCODE_OPCODE_FLOAT_SUB: PcodeOpcode
PCODE_OPCODE_FLOAT_NEG: PcodeOpcode
PCODE_OPCODE_FLOAT_ABS: PcodeOpcode
PCODE_OPCODE_FLOAT_SQRT: PcodeOpcode
PCODE_OPCODE_FLOAT_INT2FLOAT: PcodeOpcode
PCODE_OPCODE_FLOAT_FLOAT2FLOAT: PcodeOpcode
PCODE_OPCODE_FLOAT_TRUNC: PcodeOpcode
PCODE_OPCODE_FLOAT_CEIL: PcodeOpcode
PCODE_OPCODE_FLOAT_FLOOR: PcodeOpcode
PCODE_OPCODE_FLOAT_ROUND: PcodeOpcode
PCODE_OPCODE_MULTIEQUAL: PcodeOpcode
PCODE_OPCODE_INDIRECT: PcodeOpcode
PCODE_OPCODE_PIECE: PcodeOpcode
PCODE_OPCODE_SUBPIECE: PcodeOpcode
PCODE_OPCODE_CAST: PcodeOpcode
PCODE_OPCODE_PTRADD: PcodeOpcode
PCODE_OPCODE_PTRSUB: PcodeOpcode
PCODE_OPCODE_SEGMENTOP: PcodeOpcode
PCODE_OPCODE_CPOOLREF: PcodeOpcode
PCODE_OPCODE_NEW: PcodeOpcode
PCODE_OPCODE_INSERT: PcodeOpcode
PCODE_OPCODE_ZPULL: PcodeOpcode
PCODE_OPCODE_POPCOUNT: PcodeOpcode
PCODE_OPCODE_LZCOUNT: PcodeOpcode
PCODE_OPCODE_SPULL: PcodeOpcode
FLOW_KIND_UNSPECIFIED: FlowKind
FLOW_KIND_FALL_THROUGH: FlowKind
FLOW_KIND_UNCONDITIONAL_BRANCH: FlowKind
FLOW_KIND_CONDITIONAL_BRANCH: FlowKind
FLOW_KIND_CALL: FlowKind
FLOW_KIND_RETURN: FlowKind
FLOW_KIND_INDIRECT_BRANCH: FlowKind
FLOW_KIND_INDIRECT_CALL: FlowKind
FLOW_KIND_TERMINATOR: FlowKind
XREF_KIND_UNSPECIFIED: XrefKind
XREF_KIND_CALL: XrefKind
XREF_KIND_JUMP: XrefKind
XREF_KIND_CONDITIONAL_JUMP: XrefKind
XREF_KIND_INDIRECT_CALL: XrefKind
XREF_KIND_INDIRECT_JUMP: XrefKind
XREF_KIND_DATA_READ: XrefKind
XREF_KIND_DATA_WRITE: XrefKind
XREF_KIND_DATA_POINTER: XrefKind
XREF_KIND_THUNK: XrefKind
XREF_KIND_FALLTHROUGH: XrefKind
XREF_DIRECTION_UNSPECIFIED: XrefDirection
XREF_DIRECTION_TO: XrefDirection
XREF_DIRECTION_FROM: XrefDirection
XREF_DIRECTION_BOTH: XrefDirection

class Function(_message.Message):
    __slots__ = ("entry", "name", "name_origin", "body", "bounds_origin", "prototype", "prototype_origin", "calling_convention", "no_return", "thunk", "thunk_target", "external", "instruction_count", "caller_count", "size", "xref_count", "decompile_failed", "demangled")
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    NAME_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    BOUNDS_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    PROTOTYPE_FIELD_NUMBER: _ClassVar[int]
    PROTOTYPE_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    CALLING_CONVENTION_FIELD_NUMBER: _ClassVar[int]
    NO_RETURN_FIELD_NUMBER: _ClassVar[int]
    THUNK_FIELD_NUMBER: _ClassVar[int]
    THUNK_TARGET_FIELD_NUMBER: _ClassVar[int]
    EXTERNAL_FIELD_NUMBER: _ClassVar[int]
    INSTRUCTION_COUNT_FIELD_NUMBER: _ClassVar[int]
    CALLER_COUNT_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    XREF_COUNT_FIELD_NUMBER: _ClassVar[int]
    DECOMPILE_FAILED_FIELD_NUMBER: _ClassVar[int]
    DEMANGLED_FIELD_NUMBER: _ClassVar[int]
    entry: _common_pb2.Address
    name: str
    name_origin: _common_pb2.FactOrigin
    body: _containers.RepeatedCompositeFieldContainer[_common_pb2.AddressRange]
    bounds_origin: _common_pb2.FactOrigin
    prototype: str
    prototype_origin: _common_pb2.FactOrigin
    calling_convention: str
    no_return: bool
    thunk: bool
    thunk_target: _common_pb2.Address
    external: bool
    instruction_count: int
    caller_count: int
    size: int
    xref_count: int
    decompile_failed: bool
    demangled: _common_pb2.DemangledName
    def __init__(self, entry: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., name: _Optional[str] = ..., name_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., body: _Optional[_Iterable[_Union[_common_pb2.AddressRange, _Mapping]]] = ..., bounds_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., prototype: _Optional[str] = ..., prototype_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., calling_convention: _Optional[str] = ..., no_return: _Optional[bool] = ..., thunk: _Optional[bool] = ..., thunk_target: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., external: _Optional[bool] = ..., instruction_count: _Optional[int] = ..., caller_count: _Optional[int] = ..., size: _Optional[int] = ..., xref_count: _Optional[int] = ..., decompile_failed: _Optional[bool] = ..., demangled: _Optional[_Union[_common_pb2.DemangledName, _Mapping]] = ...) -> None: ...

class Symbol(_message.Message):
    __slots__ = ("address", "name", "kind", "origin", "demangled")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    DEMANGLED_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    name: str
    kind: SymbolKind
    origin: _common_pb2.FactOrigin
    demangled: _common_pb2.DemangledName
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., name: _Optional[str] = ..., kind: _Optional[_Union[SymbolKind, str]] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., demangled: _Optional[_Union[_common_pb2.DemangledName, _Mapping]] = ...) -> None: ...

class ListingHeader(_message.Message):
    __slots__ = ("kind", "text", "line", "origin", "demangled")
    KIND_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    LINE_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    DEMANGLED_FIELD_NUMBER: _ClassVar[int]
    kind: ListingHeaderKind
    text: str
    line: int
    origin: _common_pb2.FactOrigin
    demangled: _common_pb2.DemangledName
    def __init__(self, kind: _Optional[_Union[ListingHeaderKind, str]] = ..., text: _Optional[str] = ..., line: _Optional[int] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., demangled: _Optional[_Union[_common_pb2.DemangledName, _Mapping]] = ...) -> None: ...

class ListingToken(_message.Message):
    __slots__ = ("kind", "text", "operand_index", "target", "value", "register_varnode", "scalar_bits", "display_origin", "reference_origin", "demangled")
    KIND_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    OPERAND_INDEX_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    REGISTER_VARNODE_FIELD_NUMBER: _ClassVar[int]
    SCALAR_BITS_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    REFERENCE_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    DEMANGLED_FIELD_NUMBER: _ClassVar[int]
    kind: ListingTokenKind
    text: str
    operand_index: int
    target: _common_pb2.Address
    value: int
    register_varnode: _common_pb2.Varnode
    scalar_bits: int
    display_origin: _common_pb2.FactOrigin
    reference_origin: _common_pb2.FactOrigin
    demangled: _common_pb2.DemangledName
    def __init__(self, kind: _Optional[_Union[ListingTokenKind, str]] = ..., text: _Optional[str] = ..., operand_index: _Optional[int] = ..., target: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., value: _Optional[int] = ..., register_varnode: _Optional[_Union[_common_pb2.Varnode, _Mapping]] = ..., scalar_bits: _Optional[int] = ..., display_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., reference_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., demangled: _Optional[_Union[_common_pb2.DemangledName, _Mapping]] = ...) -> None: ...

class CommentView(_message.Message):
    __slots__ = ("kind", "text", "origin")
    KIND_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    kind: _assertion_pb2.CommentKind
    text: str
    origin: _common_pb2.FactOrigin
    def __init__(self, kind: _Optional[_Union[_assertion_pb2.CommentKind, str]] = ..., text: _Optional[str] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ...) -> None: ...

class Label(_message.Message):
    __slots__ = ("name", "primary", "origin", "demangled")
    NAME_FIELD_NUMBER: _ClassVar[int]
    PRIMARY_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    DEMANGLED_FIELD_NUMBER: _ClassVar[int]
    name: str
    primary: bool
    origin: _common_pb2.FactOrigin
    demangled: _common_pb2.DemangledName
    def __init__(self, name: _Optional[str] = ..., primary: _Optional[bool] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., demangled: _Optional[_Union[_common_pb2.DemangledName, _Mapping]] = ...) -> None: ...

class ListingRow(_message.Message):
    __slots__ = ("row", "address", "length", "kind", "bytes", "block", "labels", "function", "function_entry", "tokens", "comments", "xref_to_count", "data_type", "data_type_hash", "header", "flow", "flow_targets", "flow_override", "flow_override_origin", "patched", "original_bytes", "data_field", "data_parent", "data_depth", "data_components", "data_collapsed", "unit_origin", "mutability", "mutability_origin", "call_signature", "call_signature_origin", "data_settings", "data_settings_origin", "data_settings_type", "data_type_settings", "fallthrough_override", "fallthrough", "fallthrough_origin", "register_values")
    ROW_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    BLOCK_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_ENTRY_FIELD_NUMBER: _ClassVar[int]
    TOKENS_FIELD_NUMBER: _ClassVar[int]
    COMMENTS_FIELD_NUMBER: _ClassVar[int]
    XREF_TO_COUNT_FIELD_NUMBER: _ClassVar[int]
    DATA_TYPE_FIELD_NUMBER: _ClassVar[int]
    DATA_TYPE_HASH_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    FLOW_FIELD_NUMBER: _ClassVar[int]
    FLOW_TARGETS_FIELD_NUMBER: _ClassVar[int]
    FLOW_OVERRIDE_FIELD_NUMBER: _ClassVar[int]
    FLOW_OVERRIDE_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    PATCHED_FIELD_NUMBER: _ClassVar[int]
    ORIGINAL_BYTES_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_FIELD_NUMBER: _ClassVar[int]
    DATA_PARENT_FIELD_NUMBER: _ClassVar[int]
    DATA_DEPTH_FIELD_NUMBER: _ClassVar[int]
    DATA_COMPONENTS_FIELD_NUMBER: _ClassVar[int]
    DATA_COLLAPSED_FIELD_NUMBER: _ClassVar[int]
    UNIT_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    MUTABILITY_FIELD_NUMBER: _ClassVar[int]
    MUTABILITY_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    CALL_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    CALL_SIGNATURE_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    DATA_SETTINGS_FIELD_NUMBER: _ClassVar[int]
    DATA_SETTINGS_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    DATA_SETTINGS_TYPE_FIELD_NUMBER: _ClassVar[int]
    DATA_TYPE_SETTINGS_FIELD_NUMBER: _ClassVar[int]
    FALLTHROUGH_OVERRIDE_FIELD_NUMBER: _ClassVar[int]
    FALLTHROUGH_FIELD_NUMBER: _ClassVar[int]
    FALLTHROUGH_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    REGISTER_VALUES_FIELD_NUMBER: _ClassVar[int]
    row: int
    address: _common_pb2.Address
    length: int
    kind: ListingRowKind
    bytes: bytes
    block: str
    labels: _containers.RepeatedCompositeFieldContainer[Label]
    function: _common_pb2.Address
    function_entry: bool
    tokens: _containers.RepeatedCompositeFieldContainer[ListingToken]
    comments: _containers.RepeatedCompositeFieldContainer[CommentView]
    xref_to_count: int
    data_type: str
    data_type_hash: str
    header: ListingHeader
    flow: FlowKind
    flow_targets: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    flow_override: _assertion_pb2.FlowOverrideKind
    flow_override_origin: _common_pb2.FactOrigin
    patched: bool
    original_bytes: bytes
    data_field: str
    data_parent: _common_pb2.Address
    data_depth: int
    data_components: int
    data_collapsed: bool
    unit_origin: _common_pb2.FactOrigin
    mutability: _assertion_pb2.Mutability
    mutability_origin: _common_pb2.FactOrigin
    call_signature: str
    call_signature_origin: _common_pb2.FactOrigin
    data_settings: _assertion_pb2.DataSettings
    data_settings_origin: _common_pb2.FactOrigin
    data_settings_type: str
    data_type_settings: _assertion_pb2.DataSettings
    fallthrough_override: bool
    fallthrough: _common_pb2.Address
    fallthrough_origin: _common_pb2.FactOrigin
    register_values: _containers.RepeatedCompositeFieldContainer[RegisterAssumption]
    def __init__(self, row: _Optional[int] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., length: _Optional[int] = ..., kind: _Optional[_Union[ListingRowKind, str]] = ..., bytes: _Optional[bytes] = ..., block: _Optional[str] = ..., labels: _Optional[_Iterable[_Union[Label, _Mapping]]] = ..., function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., function_entry: _Optional[bool] = ..., tokens: _Optional[_Iterable[_Union[ListingToken, _Mapping]]] = ..., comments: _Optional[_Iterable[_Union[CommentView, _Mapping]]] = ..., xref_to_count: _Optional[int] = ..., data_type: _Optional[str] = ..., data_type_hash: _Optional[str] = ..., header: _Optional[_Union[ListingHeader, _Mapping]] = ..., flow: _Optional[_Union[FlowKind, str]] = ..., flow_targets: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., flow_override: _Optional[_Union[_assertion_pb2.FlowOverrideKind, str]] = ..., flow_override_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., patched: _Optional[bool] = ..., original_bytes: _Optional[bytes] = ..., data_field: _Optional[str] = ..., data_parent: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., data_depth: _Optional[int] = ..., data_components: _Optional[int] = ..., data_collapsed: _Optional[bool] = ..., unit_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., mutability: _Optional[_Union[_assertion_pb2.Mutability, str]] = ..., mutability_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., call_signature: _Optional[str] = ..., call_signature_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., data_settings: _Optional[_Union[_assertion_pb2.DataSettings, _Mapping]] = ..., data_settings_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., data_settings_type: _Optional[str] = ..., data_type_settings: _Optional[_Union[_assertion_pb2.DataSettings, _Mapping]] = ..., fallthrough_override: _Optional[bool] = ..., fallthrough: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., fallthrough_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., register_values: _Optional[_Iterable[_Union[RegisterAssumption, _Mapping]]] = ...) -> None: ...

class RegisterAssumption(_message.Message):
    __slots__ = ("register_name", "value", "analysis", "origin")
    REGISTER_NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    ANALYSIS_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    register_name: str
    value: int
    analysis: bool
    origin: _common_pb2.FactOrigin
    def __init__(self, register_name: _Optional[str] = ..., value: _Optional[int] = ..., analysis: _Optional[bool] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ...) -> None: ...

class RowWindow(_message.Message):
    __slots__ = ("first_row", "row_count")
    FIRST_ROW_FIELD_NUMBER: _ClassVar[int]
    ROW_COUNT_FIELD_NUMBER: _ClassVar[int]
    first_row: int
    row_count: int
    def __init__(self, first_row: _Optional[int] = ..., row_count: _Optional[int] = ...) -> None: ...

class AddressWindow(_message.Message):
    __slots__ = ("start", "end", "max_rows", "rows_before")
    START_FIELD_NUMBER: _ClassVar[int]
    END_FIELD_NUMBER: _ClassVar[int]
    MAX_ROWS_FIELD_NUMBER: _ClassVar[int]
    ROWS_BEFORE_FIELD_NUMBER: _ClassVar[int]
    start: _common_pb2.Address
    end: _common_pb2.Address
    max_rows: int
    rows_before: int
    def __init__(self, start: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., end: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., max_rows: _Optional[int] = ..., rows_before: _Optional[int] = ...) -> None: ...

class PcodeOp(_message.Message):
    __slots__ = ("opcode", "mnemonic", "output", "inputs", "index")
    OPCODE_FIELD_NUMBER: _ClassVar[int]
    MNEMONIC_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    INPUTS_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    opcode: PcodeOpcode
    mnemonic: str
    output: _common_pb2.Varnode
    inputs: _containers.RepeatedCompositeFieldContainer[_common_pb2.Varnode]
    index: int
    def __init__(self, opcode: _Optional[_Union[PcodeOpcode, str]] = ..., mnemonic: _Optional[str] = ..., output: _Optional[_Union[_common_pb2.Varnode, _Mapping]] = ..., inputs: _Optional[_Iterable[_Union[_common_pb2.Varnode, _Mapping]]] = ..., index: _Optional[int] = ...) -> None: ...

class Operand(_message.Message):
    __slots__ = ("index", "tokens", "references")
    INDEX_FIELD_NUMBER: _ClassVar[int]
    TOKENS_FIELD_NUMBER: _ClassVar[int]
    REFERENCES_FIELD_NUMBER: _ClassVar[int]
    index: int
    tokens: _containers.RepeatedCompositeFieldContainer[ListingToken]
    references: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    def __init__(self, index: _Optional[int] = ..., tokens: _Optional[_Iterable[_Union[ListingToken, _Mapping]]] = ..., references: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ...) -> None: ...

class InstructionDetail(_message.Message):
    __slots__ = ("address", "length", "bytes", "mnemonic", "tokens", "operands", "flow", "flow_targets", "fall_through", "flow_override", "flow_override_origin", "pcode", "function", "origin", "fallthrough_override", "fallthrough_origin")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    MNEMONIC_FIELD_NUMBER: _ClassVar[int]
    TOKENS_FIELD_NUMBER: _ClassVar[int]
    OPERANDS_FIELD_NUMBER: _ClassVar[int]
    FLOW_FIELD_NUMBER: _ClassVar[int]
    FLOW_TARGETS_FIELD_NUMBER: _ClassVar[int]
    FALL_THROUGH_FIELD_NUMBER: _ClassVar[int]
    FLOW_OVERRIDE_FIELD_NUMBER: _ClassVar[int]
    FLOW_OVERRIDE_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    PCODE_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    FALLTHROUGH_OVERRIDE_FIELD_NUMBER: _ClassVar[int]
    FALLTHROUGH_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    length: int
    bytes: bytes
    mnemonic: str
    tokens: _containers.RepeatedCompositeFieldContainer[ListingToken]
    operands: _containers.RepeatedCompositeFieldContainer[Operand]
    flow: FlowKind
    flow_targets: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    fall_through: _common_pb2.Address
    flow_override: _assertion_pb2.FlowOverrideKind
    flow_override_origin: _common_pb2.FactOrigin
    pcode: _containers.RepeatedCompositeFieldContainer[PcodeOp]
    function: _common_pb2.Address
    origin: _common_pb2.Derivation
    fallthrough_override: bool
    fallthrough_origin: _common_pb2.FactOrigin
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., length: _Optional[int] = ..., bytes: _Optional[bytes] = ..., mnemonic: _Optional[str] = ..., tokens: _Optional[_Iterable[_Union[ListingToken, _Mapping]]] = ..., operands: _Optional[_Iterable[_Union[Operand, _Mapping]]] = ..., flow: _Optional[_Union[FlowKind, str]] = ..., flow_targets: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., fall_through: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., flow_override: _Optional[_Union[_assertion_pb2.FlowOverrideKind, str]] = ..., flow_override_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., pcode: _Optional[_Iterable[_Union[PcodeOp, _Mapping]]] = ..., function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., origin: _Optional[_Union[_common_pb2.Derivation, _Mapping]] = ..., fallthrough_override: _Optional[bool] = ..., fallthrough_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ...) -> None: ...

class Xref(_message.Message):
    __slots__ = ("from_address", "to_address", "kind", "operand_index", "from_function", "from_function_name", "to_name", "direction", "origin", "primary")
    FROM_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    TO_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    OPERAND_INDEX_FIELD_NUMBER: _ClassVar[int]
    FROM_FUNCTION_FIELD_NUMBER: _ClassVar[int]
    FROM_FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    TO_NAME_FIELD_NUMBER: _ClassVar[int]
    DIRECTION_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    PRIMARY_FIELD_NUMBER: _ClassVar[int]
    from_address: _common_pb2.Address
    to_address: _common_pb2.Address
    kind: XrefKind
    operand_index: int
    from_function: _common_pb2.Address
    from_function_name: str
    to_name: str
    direction: XrefDirection
    origin: _common_pb2.FactOrigin
    primary: bool
    def __init__(self, from_address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., to_address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., kind: _Optional[_Union[XrefKind, str]] = ..., operand_index: _Optional[int] = ..., from_function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., from_function_name: _Optional[str] = ..., to_name: _Optional[str] = ..., direction: _Optional[_Union[XrefDirection, str]] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., primary: _Optional[bool] = ...) -> None: ...
