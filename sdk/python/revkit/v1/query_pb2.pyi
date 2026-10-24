from revkit.v1 import assertion_pb2 as _assertion_pb2
from revkit.v1 import common_pb2 as _common_pb2
from revkit.v1 import decompile_pb2 as _decompile_pb2
from revkit.v1 import listing_pb2 as _listing_pb2
from revkit.v1 import project_pb2 as _project_pb2
from revkit.v1 import types_pb2 as _types_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class FunctionNameFilter(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FUNCTION_NAME_FILTER_UNSPECIFIED: _ClassVar[FunctionNameFilter]
    FUNCTION_NAME_FILTER_NAMED: _ClassVar[FunctionNameFilter]
    FUNCTION_NAME_FILTER_UNNAMED: _ClassVar[FunctionNameFilter]

class FunctionThunkFilter(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FUNCTION_THUNK_FILTER_UNSPECIFIED: _ClassVar[FunctionThunkFilter]
    FUNCTION_THUNK_FILTER_ONLY: _ClassVar[FunctionThunkFilter]
    FUNCTION_THUNK_FILTER_EXCLUDE: _ClassVar[FunctionThunkFilter]

class SymbolTreeNodeKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SYMBOL_TREE_NODE_KIND_UNSPECIFIED: _ClassVar[SymbolTreeNodeKind]
    SYMBOL_TREE_NODE_KIND_FOLDER: _ClassVar[SymbolTreeNodeKind]
    SYMBOL_TREE_NODE_KIND_LIBRARY: _ClassVar[SymbolTreeNodeKind]
    SYMBOL_TREE_NODE_KIND_NAMESPACE: _ClassVar[SymbolTreeNodeKind]
    SYMBOL_TREE_NODE_KIND_CLASS: _ClassVar[SymbolTreeNodeKind]
    SYMBOL_TREE_NODE_KIND_FUNCTION: _ClassVar[SymbolTreeNodeKind]
    SYMBOL_TREE_NODE_KIND_LABEL: _ClassVar[SymbolTreeNodeKind]
    SYMBOL_TREE_NODE_KIND_IMPORT: _ClassVar[SymbolTreeNodeKind]
    SYMBOL_TREE_NODE_KIND_EXPORT: _ClassVar[SymbolTreeNodeKind]

class SliceKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SLICE_KIND_UNSPECIFIED: _ClassVar[SliceKind]
    SLICE_KIND_DEF_USE: _ClassVar[SliceKind]
    SLICE_KIND_FORWARD: _ClassVar[SliceKind]
    SLICE_KIND_BACKWARD: _ClassVar[SliceKind]
    SLICE_KIND_FORWARD_OPS: _ClassVar[SliceKind]
    SLICE_KIND_BACKWARD_OPS: _ClassVar[SliceKind]

class TraceDirection(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TRACE_DIRECTION_UNSPECIFIED: _ClassVar[TraceDirection]
    TRACE_DIRECTION_BACKWARD: _ClassVar[TraceDirection]
    TRACE_DIRECTION_FORWARD: _ClassVar[TraceDirection]

class TraceEdgeKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TRACE_EDGE_KIND_UNSPECIFIED: _ClassVar[TraceEdgeKind]
    TRACE_EDGE_KIND_DATAFLOW: _ClassVar[TraceEdgeKind]
    TRACE_EDGE_KIND_ARGUMENT: _ClassVar[TraceEdgeKind]
    TRACE_EDGE_KIND_RETURN: _ClassVar[TraceEdgeKind]

class TraceUnknownKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TRACE_UNKNOWN_KIND_UNSPECIFIED: _ClassVar[TraceUnknownKind]
    TRACE_UNKNOWN_KIND_INDIRECT_CALL: _ClassVar[TraceUnknownKind]
    TRACE_UNKNOWN_KIND_EXTERNAL_CALL: _ClassVar[TraceUnknownKind]
    TRACE_UNKNOWN_KIND_MEMORY: _ClassVar[TraceUnknownKind]
    TRACE_UNKNOWN_KIND_NO_CALLERS: _ClassVar[TraceUnknownKind]
    TRACE_UNKNOWN_KIND_DECOMPILE_FAILED: _ClassVar[TraceUnknownKind]
    TRACE_UNKNOWN_KIND_BUDGET: _ClassVar[TraceUnknownKind]
    TRACE_UNKNOWN_KIND_UNMATCHED: _ClassVar[TraceUnknownKind]

class TypeSource(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TYPE_SOURCE_UNSPECIFIED: _ClassVar[TypeSource]
    TYPE_SOURCE_PROGRAM: _ClassVar[TypeSource]
    TYPE_SOURCE_LIBRARY: _ClassVar[TypeSource]
    TYPE_SOURCE_PROJECT: _ClassVar[TypeSource]

class FlowEdgeKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FLOW_EDGE_KIND_UNSPECIFIED: _ClassVar[FlowEdgeKind]
    FLOW_EDGE_KIND_FALL_THROUGH: _ClassVar[FlowEdgeKind]
    FLOW_EDGE_KIND_CONDITIONAL_TRUE: _ClassVar[FlowEdgeKind]
    FLOW_EDGE_KIND_CONDITIONAL_FALSE: _ClassVar[FlowEdgeKind]
    FLOW_EDGE_KIND_UNCONDITIONAL: _ClassVar[FlowEdgeKind]
    FLOW_EDGE_KIND_SWITCH: _ClassVar[FlowEdgeKind]

class DataCategory(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DATA_CATEGORY_UNSPECIFIED: _ClassVar[DataCategory]
    DATA_CATEGORY_STRING: _ClassVar[DataCategory]
    DATA_CATEGORY_POINTER: _ClassVar[DataCategory]
    DATA_CATEGORY_UNDEFINED: _ClassVar[DataCategory]
    DATA_CATEGORY_TYPED: _ClassVar[DataCategory]
    DATA_CATEGORY_DEFINED: _ClassVar[DataCategory]

class RelocationKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RELOCATION_KIND_UNSPECIFIED: _ClassVar[RelocationKind]
    RELOCATION_KIND_OTHER: _ClassVar[RelocationKind]
    RELOCATION_KIND_RELATIVE: _ClassVar[RelocationKind]
    RELOCATION_KIND_IRELATIVE: _ClassVar[RelocationKind]
    RELOCATION_KIND_JUMP_SLOT: _ClassVar[RelocationKind]
    RELOCATION_KIND_GLOB_DAT: _ClassVar[RelocationKind]
    RELOCATION_KIND_ABSOLUTE: _ClassVar[RelocationKind]

class CDialect(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    C_DIALECT_UNSPECIFIED: _ClassVar[CDialect]
    C_DIALECT_C11: _ClassVar[CDialect]
    C_DIALECT_C89: _ClassVar[CDialect]

class ByteKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    BYTE_KIND_UNSPECIFIED: _ClassVar[ByteKind]
    BYTE_KIND_CODE: _ClassVar[ByteKind]
    BYTE_KIND_DATA: _ClassVar[ByteKind]
    BYTE_KIND_UNDEFINED: _ClassVar[ByteKind]
    BYTE_KIND_EXTERNAL: _ClassVar[ByteKind]
    BYTE_KIND_UNINITIALIZED: _ClassVar[ByteKind]

class NavigationKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NAVIGATION_KIND_UNSPECIFIED: _ClassVar[NavigationKind]
    NAVIGATION_KIND_INSTRUCTION: _ClassVar[NavigationKind]
    NAVIGATION_KIND_DATA: _ClassVar[NavigationKind]
    NAVIGATION_KIND_UNDEFINED: _ClassVar[NavigationKind]
    NAVIGATION_KIND_LABEL: _ClassVar[NavigationKind]
    NAVIGATION_KIND_FUNCTION: _ClassVar[NavigationKind]
    NAVIGATION_KIND_DIFFERENT_BYTE: _ClassVar[NavigationKind]
    NAVIGATION_KIND_NOTE: _ClassVar[NavigationKind]

class SearchFormat(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SEARCH_FORMAT_UNSPECIFIED: _ClassVar[SearchFormat]
    SEARCH_FORMAT_HEX: _ClassVar[SearchFormat]
    SEARCH_FORMAT_STRING: _ClassVar[SearchFormat]
    SEARCH_FORMAT_DECIMAL: _ClassVar[SearchFormat]
    SEARCH_FORMAT_FLOAT: _ClassVar[SearchFormat]
    SEARCH_FORMAT_DOUBLE: _ClassVar[SearchFormat]
    SEARCH_FORMAT_BINARY: _ClassVar[SearchFormat]
    SEARCH_FORMAT_REGEX: _ClassVar[SearchFormat]

class SearchEncoding(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SEARCH_ENCODING_UNSPECIFIED: _ClassVar[SearchEncoding]
    SEARCH_ENCODING_ASCII: _ClassVar[SearchEncoding]
    SEARCH_ENCODING_UTF8: _ClassVar[SearchEncoding]
    SEARCH_ENCODING_UTF16: _ClassVar[SearchEncoding]

class TextField(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TEXT_FIELD_UNSPECIFIED: _ClassVar[TextField]
    TEXT_FIELD_COMMENTS: _ClassVar[TextField]
    TEXT_FIELD_LABELS: _ClassVar[TextField]
    TEXT_FIELD_FUNCTIONS: _ClassVar[TextField]
    TEXT_FIELD_MNEMONICS: _ClassVar[TextField]
    TEXT_FIELD_OPERANDS: _ClassVar[TextField]
    TEXT_FIELD_DATA_MNEMONICS: _ClassVar[TextField]
    TEXT_FIELD_DATA_VALUES: _ClassVar[TextField]

class TypeUseKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TYPE_USE_KIND_UNSPECIFIED: _ClassVar[TypeUseKind]
    TYPE_USE_KIND_FIELD: _ClassVar[TypeUseKind]
    TYPE_USE_KIND_TYPE: _ClassVar[TypeUseKind]

class FieldAccess(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FIELD_ACCESS_UNSPECIFIED: _ClassVar[FieldAccess]
    FIELD_ACCESS_READ: _ClassVar[FieldAccess]
    FIELD_ACCESS_WRITE: _ClassVar[FieldAccess]
    FIELD_ACCESS_READ_WRITE: _ClassVar[FieldAccess]
    FIELD_ACCESS_ADDRESS: _ClassVar[FieldAccess]
FUNCTION_NAME_FILTER_UNSPECIFIED: FunctionNameFilter
FUNCTION_NAME_FILTER_NAMED: FunctionNameFilter
FUNCTION_NAME_FILTER_UNNAMED: FunctionNameFilter
FUNCTION_THUNK_FILTER_UNSPECIFIED: FunctionThunkFilter
FUNCTION_THUNK_FILTER_ONLY: FunctionThunkFilter
FUNCTION_THUNK_FILTER_EXCLUDE: FunctionThunkFilter
SYMBOL_TREE_NODE_KIND_UNSPECIFIED: SymbolTreeNodeKind
SYMBOL_TREE_NODE_KIND_FOLDER: SymbolTreeNodeKind
SYMBOL_TREE_NODE_KIND_LIBRARY: SymbolTreeNodeKind
SYMBOL_TREE_NODE_KIND_NAMESPACE: SymbolTreeNodeKind
SYMBOL_TREE_NODE_KIND_CLASS: SymbolTreeNodeKind
SYMBOL_TREE_NODE_KIND_FUNCTION: SymbolTreeNodeKind
SYMBOL_TREE_NODE_KIND_LABEL: SymbolTreeNodeKind
SYMBOL_TREE_NODE_KIND_IMPORT: SymbolTreeNodeKind
SYMBOL_TREE_NODE_KIND_EXPORT: SymbolTreeNodeKind
SLICE_KIND_UNSPECIFIED: SliceKind
SLICE_KIND_DEF_USE: SliceKind
SLICE_KIND_FORWARD: SliceKind
SLICE_KIND_BACKWARD: SliceKind
SLICE_KIND_FORWARD_OPS: SliceKind
SLICE_KIND_BACKWARD_OPS: SliceKind
TRACE_DIRECTION_UNSPECIFIED: TraceDirection
TRACE_DIRECTION_BACKWARD: TraceDirection
TRACE_DIRECTION_FORWARD: TraceDirection
TRACE_EDGE_KIND_UNSPECIFIED: TraceEdgeKind
TRACE_EDGE_KIND_DATAFLOW: TraceEdgeKind
TRACE_EDGE_KIND_ARGUMENT: TraceEdgeKind
TRACE_EDGE_KIND_RETURN: TraceEdgeKind
TRACE_UNKNOWN_KIND_UNSPECIFIED: TraceUnknownKind
TRACE_UNKNOWN_KIND_INDIRECT_CALL: TraceUnknownKind
TRACE_UNKNOWN_KIND_EXTERNAL_CALL: TraceUnknownKind
TRACE_UNKNOWN_KIND_MEMORY: TraceUnknownKind
TRACE_UNKNOWN_KIND_NO_CALLERS: TraceUnknownKind
TRACE_UNKNOWN_KIND_DECOMPILE_FAILED: TraceUnknownKind
TRACE_UNKNOWN_KIND_BUDGET: TraceUnknownKind
TRACE_UNKNOWN_KIND_UNMATCHED: TraceUnknownKind
TYPE_SOURCE_UNSPECIFIED: TypeSource
TYPE_SOURCE_PROGRAM: TypeSource
TYPE_SOURCE_LIBRARY: TypeSource
TYPE_SOURCE_PROJECT: TypeSource
FLOW_EDGE_KIND_UNSPECIFIED: FlowEdgeKind
FLOW_EDGE_KIND_FALL_THROUGH: FlowEdgeKind
FLOW_EDGE_KIND_CONDITIONAL_TRUE: FlowEdgeKind
FLOW_EDGE_KIND_CONDITIONAL_FALSE: FlowEdgeKind
FLOW_EDGE_KIND_UNCONDITIONAL: FlowEdgeKind
FLOW_EDGE_KIND_SWITCH: FlowEdgeKind
DATA_CATEGORY_UNSPECIFIED: DataCategory
DATA_CATEGORY_STRING: DataCategory
DATA_CATEGORY_POINTER: DataCategory
DATA_CATEGORY_UNDEFINED: DataCategory
DATA_CATEGORY_TYPED: DataCategory
DATA_CATEGORY_DEFINED: DataCategory
RELOCATION_KIND_UNSPECIFIED: RelocationKind
RELOCATION_KIND_OTHER: RelocationKind
RELOCATION_KIND_RELATIVE: RelocationKind
RELOCATION_KIND_IRELATIVE: RelocationKind
RELOCATION_KIND_JUMP_SLOT: RelocationKind
RELOCATION_KIND_GLOB_DAT: RelocationKind
RELOCATION_KIND_ABSOLUTE: RelocationKind
C_DIALECT_UNSPECIFIED: CDialect
C_DIALECT_C11: CDialect
C_DIALECT_C89: CDialect
BYTE_KIND_UNSPECIFIED: ByteKind
BYTE_KIND_CODE: ByteKind
BYTE_KIND_DATA: ByteKind
BYTE_KIND_UNDEFINED: ByteKind
BYTE_KIND_EXTERNAL: ByteKind
BYTE_KIND_UNINITIALIZED: ByteKind
NAVIGATION_KIND_UNSPECIFIED: NavigationKind
NAVIGATION_KIND_INSTRUCTION: NavigationKind
NAVIGATION_KIND_DATA: NavigationKind
NAVIGATION_KIND_UNDEFINED: NavigationKind
NAVIGATION_KIND_LABEL: NavigationKind
NAVIGATION_KIND_FUNCTION: NavigationKind
NAVIGATION_KIND_DIFFERENT_BYTE: NavigationKind
NAVIGATION_KIND_NOTE: NavigationKind
SEARCH_FORMAT_UNSPECIFIED: SearchFormat
SEARCH_FORMAT_HEX: SearchFormat
SEARCH_FORMAT_STRING: SearchFormat
SEARCH_FORMAT_DECIMAL: SearchFormat
SEARCH_FORMAT_FLOAT: SearchFormat
SEARCH_FORMAT_DOUBLE: SearchFormat
SEARCH_FORMAT_BINARY: SearchFormat
SEARCH_FORMAT_REGEX: SearchFormat
SEARCH_ENCODING_UNSPECIFIED: SearchEncoding
SEARCH_ENCODING_ASCII: SearchEncoding
SEARCH_ENCODING_UTF8: SearchEncoding
SEARCH_ENCODING_UTF16: SearchEncoding
TEXT_FIELD_UNSPECIFIED: TextField
TEXT_FIELD_COMMENTS: TextField
TEXT_FIELD_LABELS: TextField
TEXT_FIELD_FUNCTIONS: TextField
TEXT_FIELD_MNEMONICS: TextField
TEXT_FIELD_OPERANDS: TextField
TEXT_FIELD_DATA_MNEMONICS: TextField
TEXT_FIELD_DATA_VALUES: TextField
TYPE_USE_KIND_UNSPECIFIED: TypeUseKind
TYPE_USE_KIND_FIELD: TypeUseKind
TYPE_USE_KIND_TYPE: TypeUseKind
FIELD_ACCESS_UNSPECIFIED: FieldAccess
FIELD_ACCESS_READ: FieldAccess
FIELD_ACCESS_WRITE: FieldAccess
FIELD_ACCESS_READ_WRITE: FieldAccess
FIELD_ACCESS_ADDRESS: FieldAccess

class GetMemoryMapRequest(_message.Message):
    __slots__ = ("program_id", "read")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ...) -> None: ...

class GetMemoryMapResponse(_message.Message):
    __slots__ = ("snapshot", "blocks", "rejected")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    BLOCKS_FIELD_NUMBER: _ClassVar[int]
    REJECTED_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    blocks: _containers.RepeatedCompositeFieldContainer[_project_pb2.MemoryBlock]
    rejected: _containers.RepeatedCompositeFieldContainer[_project_pb2.MemoryBlock]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., blocks: _Optional[_Iterable[_Union[_project_pb2.MemoryBlock, _Mapping]]] = ..., rejected: _Optional[_Iterable[_Union[_project_pb2.MemoryBlock, _Mapping]]] = ...) -> None: ...

class ReadMemoryRequest(_message.Message):
    __slots__ = ("program_id", "address", "length", "read")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    address: _common_pb2.Address
    length: int
    read: _common_pb2.ReadOptions
    def __init__(self, program_id: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., length: _Optional[int] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ...) -> None: ...

class ReadMemoryResponse(_message.Message):
    __slots__ = ("snapshot", "address", "data")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    address: _common_pb2.Address
    data: bytes
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class ListFunctionsRequest(_message.Message):
    __slots__ = ("program_id", "read", "page", "name_contains", "range", "sort", "offset", "descending", "named", "thunks", "decompile_failed")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    NAME_CONTAINS_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    SORT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    DESCENDING_FIELD_NUMBER: _ClassVar[int]
    NAMED_FIELD_NUMBER: _ClassVar[int]
    THUNKS_FIELD_NUMBER: _ClassVar[int]
    DECOMPILE_FAILED_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    page: _common_pb2.PageRequest
    name_contains: str
    range: _common_pb2.AddressRange
    sort: _listing_pb2.FunctionSort
    offset: int
    descending: bool
    named: FunctionNameFilter
    thunks: FunctionThunkFilter
    decompile_failed: bool
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., page: _Optional[_Union[_common_pb2.PageRequest, _Mapping]] = ..., name_contains: _Optional[str] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., sort: _Optional[_Union[_listing_pb2.FunctionSort, str]] = ..., offset: _Optional[int] = ..., descending: _Optional[bool] = ..., named: _Optional[_Union[FunctionNameFilter, str]] = ..., thunks: _Optional[_Union[FunctionThunkFilter, str]] = ..., decompile_failed: _Optional[bool] = ...) -> None: ...

class ListFunctionsResponse(_message.Message):
    __slots__ = ("snapshot", "functions", "page")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    functions: _containers.RepeatedCompositeFieldContainer[_listing_pb2.Function]
    page: _common_pb2.PageInfo
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., functions: _Optional[_Iterable[_Union[_listing_pb2.Function, _Mapping]]] = ..., page: _Optional[_Union[_common_pb2.PageInfo, _Mapping]] = ...) -> None: ...

class ListSymbolsRequest(_message.Message):
    __slots__ = ("program_id", "read", "page", "name_contains", "name_equals", "kinds", "range")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    NAME_CONTAINS_FIELD_NUMBER: _ClassVar[int]
    NAME_EQUALS_FIELD_NUMBER: _ClassVar[int]
    KINDS_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    page: _common_pb2.PageRequest
    name_contains: str
    name_equals: str
    kinds: _containers.RepeatedScalarFieldContainer[_listing_pb2.SymbolKind]
    range: _common_pb2.AddressRange
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., page: _Optional[_Union[_common_pb2.PageRequest, _Mapping]] = ..., name_contains: _Optional[str] = ..., name_equals: _Optional[str] = ..., kinds: _Optional[_Iterable[_Union[_listing_pb2.SymbolKind, str]]] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ...) -> None: ...

class ListSymbolsResponse(_message.Message):
    __slots__ = ("snapshot", "symbols", "page")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    SYMBOLS_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    symbols: _containers.RepeatedCompositeFieldContainer[_listing_pb2.Symbol]
    page: _common_pb2.PageInfo
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., symbols: _Optional[_Iterable[_Union[_listing_pb2.Symbol, _Mapping]]] = ..., page: _Optional[_Union[_common_pb2.PageInfo, _Mapping]] = ...) -> None: ...

class ListSymbolTreeRequest(_message.Message):
    __slots__ = ("program_id", "read", "page", "path", "name_contains")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    NAME_CONTAINS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    page: _common_pb2.PageRequest
    path: _containers.RepeatedScalarFieldContainer[str]
    name_contains: str
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., page: _Optional[_Union[_common_pb2.PageRequest, _Mapping]] = ..., path: _Optional[_Iterable[str]] = ..., name_contains: _Optional[str] = ...) -> None: ...

class SymbolTreeNode(_message.Message):
    __slots__ = ("name", "kind", "address", "full_name", "children", "library")
    NAME_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    FULL_NAME_FIELD_NUMBER: _ClassVar[int]
    CHILDREN_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_FIELD_NUMBER: _ClassVar[int]
    name: str
    kind: SymbolTreeNodeKind
    address: _common_pb2.Address
    full_name: str
    children: int
    library: str
    def __init__(self, name: _Optional[str] = ..., kind: _Optional[_Union[SymbolTreeNodeKind, str]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., full_name: _Optional[str] = ..., children: _Optional[int] = ..., library: _Optional[str] = ...) -> None: ...

class ListSymbolTreeResponse(_message.Message):
    __slots__ = ("snapshot", "nodes", "page", "total")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    NODES_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    nodes: _containers.RepeatedCompositeFieldContainer[SymbolTreeNode]
    page: _common_pb2.PageInfo
    total: int
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., nodes: _Optional[_Iterable[_Union[SymbolTreeNode, _Mapping]]] = ..., page: _Optional[_Union[_common_pb2.PageInfo, _Mapping]] = ..., total: _Optional[int] = ...) -> None: ...

class PlanClearFlowRequest(_message.Message):
    __slots__ = ("program_id", "read", "address", "follow_calls")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    FOLLOW_CALLS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    address: _common_pb2.Address
    follow_calls: bool
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., follow_calls: _Optional[bool] = ...) -> None: ...

class ClearFlowRange(_message.Message):
    __slots__ = ("address", "length")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    length: int
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., length: _Optional[int] = ...) -> None: ...

class PlanClearFlowResponse(_message.Message):
    __slots__ = ("snapshot", "ranges", "instructions", "kept", "functions")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    RANGES_FIELD_NUMBER: _ClassVar[int]
    INSTRUCTIONS_FIELD_NUMBER: _ClassVar[int]
    KEPT_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    ranges: _containers.RepeatedCompositeFieldContainer[ClearFlowRange]
    instructions: int
    kept: int
    functions: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., ranges: _Optional[_Iterable[_Union[ClearFlowRange, _Mapping]]] = ..., instructions: _Optional[int] = ..., kept: _Optional[int] = ..., functions: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ...) -> None: ...

class GetFunctionRequest(_message.Message):
    __slots__ = ("program_id", "address", "containing", "read")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    CONTAINING_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    address: _common_pb2.Address
    containing: bool
    read: _common_pb2.ReadOptions
    def __init__(self, program_id: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., containing: _Optional[bool] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ...) -> None: ...

class GetFunctionResponse(_message.Message):
    __slots__ = ("snapshot", "function")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    function: _listing_pb2.Function
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., function: _Optional[_Union[_listing_pb2.Function, _Mapping]] = ...) -> None: ...

class GetListingRequest(_message.Message):
    __slots__ = ("program_id", "read", "rows", "addresses", "omit_bytes", "header_rows")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    OMIT_BYTES_FIELD_NUMBER: _ClassVar[int]
    HEADER_ROWS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    rows: _listing_pb2.RowWindow
    addresses: _listing_pb2.AddressWindow
    omit_bytes: bool
    header_rows: bool
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., rows: _Optional[_Union[_listing_pb2.RowWindow, _Mapping]] = ..., addresses: _Optional[_Union[_listing_pb2.AddressWindow, _Mapping]] = ..., omit_bytes: _Optional[bool] = ..., header_rows: _Optional[bool] = ...) -> None: ...

class GetListingResponse(_message.Message):
    __slots__ = ("snapshot", "rows", "first_row", "total_rows", "truncated")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    FIRST_ROW_FIELD_NUMBER: _ClassVar[int]
    TOTAL_ROWS_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    rows: _containers.RepeatedCompositeFieldContainer[_listing_pb2.ListingRow]
    first_row: int
    total_rows: int
    truncated: bool
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., rows: _Optional[_Iterable[_Union[_listing_pb2.ListingRow, _Mapping]]] = ..., first_row: _Optional[int] = ..., total_rows: _Optional[int] = ..., truncated: _Optional[bool] = ...) -> None: ...

class GetInstructionRequest(_message.Message):
    __slots__ = ("program_id", "address", "read")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    address: _common_pb2.Address
    read: _common_pb2.ReadOptions
    def __init__(self, program_id: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ...) -> None: ...

class GetInstructionResponse(_message.Message):
    __slots__ = ("snapshot", "instruction")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    INSTRUCTION_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    instruction: _listing_pb2.InstructionDetail
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., instruction: _Optional[_Union[_listing_pb2.InstructionDetail, _Mapping]] = ...) -> None: ...

class GetXrefsRequest(_message.Message):
    __slots__ = ("program_id", "address", "range", "direction", "kinds", "read", "page")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    DIRECTION_FIELD_NUMBER: _ClassVar[int]
    KINDS_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    address: _common_pb2.Address
    range: _common_pb2.AddressRange
    direction: _listing_pb2.XrefDirection
    kinds: _containers.RepeatedScalarFieldContainer[_listing_pb2.XrefKind]
    read: _common_pb2.ReadOptions
    page: _common_pb2.PageRequest
    def __init__(self, program_id: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., direction: _Optional[_Union[_listing_pb2.XrefDirection, str]] = ..., kinds: _Optional[_Iterable[_Union[_listing_pb2.XrefKind, str]]] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., page: _Optional[_Union[_common_pb2.PageRequest, _Mapping]] = ...) -> None: ...

class GetXrefsResponse(_message.Message):
    __slots__ = ("snapshot", "xrefs", "page")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    XREFS_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    xrefs: _containers.RepeatedCompositeFieldContainer[_listing_pb2.Xref]
    page: _common_pb2.PageInfo
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., xrefs: _Optional[_Iterable[_Union[_listing_pb2.Xref, _Mapping]]] = ..., page: _Optional[_Union[_common_pb2.PageInfo, _Mapping]] = ...) -> None: ...

class ListLibraryImportersRequest(_message.Message):
    __slots__ = ("program_id", "address", "name", "include_references", "max_references", "read")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_REFERENCES_FIELD_NUMBER: _ClassVar[int]
    MAX_REFERENCES_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    address: _common_pb2.Address
    name: str
    include_references: bool
    max_references: int
    read: _common_pb2.ReadOptions
    def __init__(self, program_id: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., name: _Optional[str] = ..., include_references: _Optional[bool] = ..., max_references: _Optional[int] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ...) -> None: ...

class LibraryImporter(_message.Message):
    __slots__ = ("program_id", "program_name", "library", "resolved", "references", "references_truncated")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_NAME_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_FIELD_NUMBER: _ClassVar[int]
    RESOLVED_FIELD_NUMBER: _ClassVar[int]
    REFERENCES_FIELD_NUMBER: _ClassVar[int]
    REFERENCES_TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    program_name: str
    library: str
    resolved: _project_pb2.ResolvedImport
    references: _containers.RepeatedCompositeFieldContainer[_listing_pb2.Xref]
    references_truncated: bool
    def __init__(self, program_id: _Optional[str] = ..., program_name: _Optional[str] = ..., library: _Optional[str] = ..., resolved: _Optional[_Union[_project_pb2.ResolvedImport, _Mapping]] = ..., references: _Optional[_Iterable[_Union[_listing_pb2.Xref, _Mapping]]] = ..., references_truncated: _Optional[bool] = ...) -> None: ...

class ListLibraryImportersResponse(_message.Message):
    __slots__ = ("snapshot", "importers")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    IMPORTERS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    importers: _containers.RepeatedCompositeFieldContainer[LibraryImporter]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., importers: _Optional[_Iterable[_Union[LibraryImporter, _Mapping]]] = ...) -> None: ...

class DecompileRequest(_message.Message):
    __slots__ = ("program_id", "function", "read", "options")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    OPTIONS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    function: _common_pb2.Address
    read: _common_pb2.ReadOptions
    options: _decompile_pb2.DecompileOptions
    def __init__(self, program_id: _Optional[str] = ..., function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., options: _Optional[_Union[_decompile_pb2.DecompileOptions, _Mapping]] = ...) -> None: ...

class DecompileResponse(_message.Message):
    __slots__ = ("snapshot", "function", "failure")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    function: _decompile_pb2.DecompiledFunction
    failure: _decompile_pb2.DecompileFailure
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., function: _Optional[_Union[_decompile_pb2.DecompiledFunction, _Mapping]] = ..., failure: _Optional[_Union[_decompile_pb2.DecompileFailure, _Mapping]] = ...) -> None: ...

class TokenPosition(_message.Message):
    __slots__ = ("line", "token")
    LINE_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    line: int
    token: int
    def __init__(self, line: _Optional[int] = ..., token: _Optional[int] = ...) -> None: ...

class SliceDecompiledRequest(_message.Message):
    __slots__ = ("program_id", "function", "read", "kind", "token", "varnode_index", "variable_index")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    VARNODE_INDEX_FIELD_NUMBER: _ClassVar[int]
    VARIABLE_INDEX_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    function: _common_pb2.Address
    read: _common_pb2.ReadOptions
    kind: SliceKind
    token: TokenPosition
    varnode_index: int
    variable_index: int
    def __init__(self, program_id: _Optional[str] = ..., function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., kind: _Optional[_Union[SliceKind, str]] = ..., token: _Optional[_Union[TokenPosition, _Mapping]] = ..., varnode_index: _Optional[int] = ..., variable_index: _Optional[int] = ...) -> None: ...

class SliceDecompiledResponse(_message.Message):
    __slots__ = ("snapshot", "tokens", "addresses", "varnode_indices", "start")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    TOKENS_FIELD_NUMBER: _ClassVar[int]
    ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    VARNODE_INDICES_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    tokens: _containers.RepeatedCompositeFieldContainer[TokenPosition]
    addresses: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    varnode_indices: _containers.RepeatedScalarFieldContainer[int]
    start: str
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., tokens: _Optional[_Iterable[_Union[TokenPosition, _Mapping]]] = ..., addresses: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., varnode_indices: _Optional[_Iterable[int]] = ..., start: _Optional[str] = ...) -> None: ...

class TraceValueRequest(_message.Message):
    __slots__ = ("program_id", "read", "function", "direction", "token", "varnode_index", "variable_index", "max_depth", "max_functions", "max_nodes", "max_edges")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    DIRECTION_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    VARNODE_INDEX_FIELD_NUMBER: _ClassVar[int]
    VARIABLE_INDEX_FIELD_NUMBER: _ClassVar[int]
    MAX_DEPTH_FIELD_NUMBER: _ClassVar[int]
    MAX_FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    MAX_NODES_FIELD_NUMBER: _ClassVar[int]
    MAX_EDGES_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    function: _common_pb2.Address
    direction: TraceDirection
    token: TokenPosition
    varnode_index: int
    variable_index: int
    max_depth: int
    max_functions: int
    max_nodes: int
    max_edges: int
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., direction: _Optional[_Union[TraceDirection, str]] = ..., token: _Optional[_Union[TokenPosition, _Mapping]] = ..., varnode_index: _Optional[int] = ..., variable_index: _Optional[int] = ..., max_depth: _Optional[int] = ..., max_functions: _Optional[int] = ..., max_nodes: _Optional[int] = ..., max_edges: _Optional[int] = ...) -> None: ...

class TraceNode(_message.Message):
    __slots__ = ("function", "node", "varnode_index", "varnode", "constant", "text", "address", "depth")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    NODE_FIELD_NUMBER: _ClassVar[int]
    VARNODE_INDEX_FIELD_NUMBER: _ClassVar[int]
    VARNODE_FIELD_NUMBER: _ClassVar[int]
    CONSTANT_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DEPTH_FIELD_NUMBER: _ClassVar[int]
    function: int
    node: int
    varnode_index: int
    varnode: _common_pb2.Varnode
    constant: bool
    text: str
    address: _common_pb2.Address
    depth: int
    def __init__(self, function: _Optional[int] = ..., node: _Optional[int] = ..., varnode_index: _Optional[int] = ..., varnode: _Optional[_Union[_common_pb2.Varnode, _Mapping]] = ..., constant: _Optional[bool] = ..., text: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., depth: _Optional[int] = ...) -> None: ...

class TraceEdge(_message.Message):
    __slots__ = ("to", "kind", "address", "opcode")
    FROM_FIELD_NUMBER: _ClassVar[int]
    TO_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    OPCODE_FIELD_NUMBER: _ClassVar[int]
    to: int
    kind: TraceEdgeKind
    address: _common_pb2.Address
    opcode: str
    def __init__(self, to: _Optional[int] = ..., kind: _Optional[_Union[TraceEdgeKind, str]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., opcode: _Optional[str] = ..., **kwargs) -> None: ...

class TraceUnknown(_message.Message):
    __slots__ = ("kind", "node", "address", "detail")
    KIND_FIELD_NUMBER: _ClassVar[int]
    NODE_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    kind: TraceUnknownKind
    node: int
    address: _common_pb2.Address
    detail: str
    def __init__(self, kind: _Optional[_Union[TraceUnknownKind, str]] = ..., node: _Optional[int] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., detail: _Optional[str] = ...) -> None: ...

class TraceLine(_message.Message):
    __slots__ = ("line", "text", "tokens")
    LINE_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    TOKENS_FIELD_NUMBER: _ClassVar[int]
    line: int
    text: str
    tokens: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, line: _Optional[int] = ..., text: _Optional[str] = ..., tokens: _Optional[_Iterable[int]] = ...) -> None: ...

class TraceFunction(_message.Message):
    __slots__ = ("entry", "name", "depth", "lines", "addresses")
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DEPTH_FIELD_NUMBER: _ClassVar[int]
    LINES_FIELD_NUMBER: _ClassVar[int]
    ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    entry: _common_pb2.Address
    name: str
    depth: int
    lines: _containers.RepeatedCompositeFieldContainer[TraceLine]
    addresses: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    def __init__(self, entry: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., name: _Optional[str] = ..., depth: _Optional[int] = ..., lines: _Optional[_Iterable[_Union[TraceLine, _Mapping]]] = ..., addresses: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ...) -> None: ...

class TraceValueResponse(_message.Message):
    __slots__ = ("snapshot", "start", "functions", "nodes", "start_nodes", "edges", "unknowns", "truncated")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    NODES_FIELD_NUMBER: _ClassVar[int]
    START_NODES_FIELD_NUMBER: _ClassVar[int]
    EDGES_FIELD_NUMBER: _ClassVar[int]
    UNKNOWNS_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    start: str
    functions: _containers.RepeatedCompositeFieldContainer[TraceFunction]
    nodes: _containers.RepeatedCompositeFieldContainer[TraceNode]
    start_nodes: _containers.RepeatedScalarFieldContainer[int]
    edges: _containers.RepeatedCompositeFieldContainer[TraceEdge]
    unknowns: _containers.RepeatedCompositeFieldContainer[TraceUnknown]
    truncated: bool
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., start: _Optional[str] = ..., functions: _Optional[_Iterable[_Union[TraceFunction, _Mapping]]] = ..., nodes: _Optional[_Iterable[_Union[TraceNode, _Mapping]]] = ..., start_nodes: _Optional[_Iterable[int]] = ..., edges: _Optional[_Iterable[_Union[TraceEdge, _Mapping]]] = ..., unknowns: _Optional[_Iterable[_Union[TraceUnknown, _Mapping]]] = ..., truncated: _Optional[bool] = ...) -> None: ...

class GetTypesRequest(_message.Message):
    __slots__ = ("program_id", "hashes", "include_dependencies")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    HASHES_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_DEPENDENCIES_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    hashes: _containers.RepeatedScalarFieldContainer[str]
    include_dependencies: bool
    def __init__(self, program_id: _Optional[str] = ..., hashes: _Optional[_Iterable[str]] = ..., include_dependencies: _Optional[bool] = ...) -> None: ...

class GetTypesResponse(_message.Message):
    __slots__ = ("snapshot", "types", "missing")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    TYPES_FIELD_NUMBER: _ClassVar[int]
    MISSING_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    types: _containers.RepeatedCompositeFieldContainer[_types_pb2.TypeDefinition]
    missing: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., types: _Optional[_Iterable[_Union[_types_pb2.TypeDefinition, _Mapping]]] = ..., missing: _Optional[_Iterable[str]] = ...) -> None: ...

class FindTypesRequest(_message.Message):
    __slots__ = ("program_id", "name_contains", "kinds", "read", "page", "include_superseded", "sources", "name_prefix", "summary_only", "category", "category_exact", "include_categories", "enum_value")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_CONTAINS_FIELD_NUMBER: _ClassVar[int]
    KINDS_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_SUPERSEDED_FIELD_NUMBER: _ClassVar[int]
    SOURCES_FIELD_NUMBER: _ClassVar[int]
    NAME_PREFIX_FIELD_NUMBER: _ClassVar[int]
    SUMMARY_ONLY_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_EXACT_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    ENUM_VALUE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    name_contains: str
    kinds: _containers.RepeatedScalarFieldContainer[_types_pb2.TypeKind]
    read: _common_pb2.ReadOptions
    page: _common_pb2.PageRequest
    include_superseded: bool
    sources: _containers.RepeatedScalarFieldContainer[TypeSource]
    name_prefix: str
    summary_only: bool
    category: str
    category_exact: bool
    include_categories: bool
    enum_value: int
    def __init__(self, program_id: _Optional[str] = ..., name_contains: _Optional[str] = ..., kinds: _Optional[_Iterable[_Union[_types_pb2.TypeKind, str]]] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., page: _Optional[_Union[_common_pb2.PageRequest, _Mapping]] = ..., include_superseded: _Optional[bool] = ..., sources: _Optional[_Iterable[_Union[TypeSource, str]]] = ..., name_prefix: _Optional[str] = ..., summary_only: _Optional[bool] = ..., category: _Optional[str] = ..., category_exact: _Optional[bool] = ..., include_categories: _Optional[bool] = ..., enum_value: _Optional[int] = ...) -> None: ...

class TypeCategory(_message.Message):
    __slots__ = ("path", "types")
    PATH_FIELD_NUMBER: _ClassVar[int]
    TYPES_FIELD_NUMBER: _ClassVar[int]
    path: str
    types: int
    def __init__(self, path: _Optional[str] = ..., types: _Optional[int] = ...) -> None: ...

class FindTypesResponse(_message.Message):
    __slots__ = ("snapshot", "types", "page", "categories")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    TYPES_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    types: _containers.RepeatedCompositeFieldContainer[_types_pb2.TypeDefinition]
    page: _common_pb2.PageInfo
    categories: _containers.RepeatedCompositeFieldContainer[TypeCategory]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., types: _Optional[_Iterable[_Union[_types_pb2.TypeDefinition, _Mapping]]] = ..., page: _Optional[_Union[_common_pb2.PageInfo, _Mapping]] = ..., categories: _Optional[_Iterable[_Union[TypeCategory, _Mapping]]] = ...) -> None: ...

class GetFunctionGraphRequest(_message.Message):
    __slots__ = ("program_id", "function", "containing", "read", "omit_bytes")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    CONTAINING_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    OMIT_BYTES_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    function: _common_pb2.Address
    containing: bool
    read: _common_pb2.ReadOptions
    omit_bytes: bool
    def __init__(self, program_id: _Optional[str] = ..., function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., containing: _Optional[bool] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., omit_bytes: _Optional[bool] = ...) -> None: ...

class FlowEdge(_message.Message):
    __slots__ = ("from_block", "to_block", "kind")
    FROM_BLOCK_FIELD_NUMBER: _ClassVar[int]
    TO_BLOCK_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    from_block: int
    to_block: int
    kind: FlowEdgeKind
    def __init__(self, from_block: _Optional[int] = ..., to_block: _Optional[int] = ..., kind: _Optional[_Union[FlowEdgeKind, str]] = ...) -> None: ...

class BasicBlock(_message.Message):
    __slots__ = ("range", "rows", "exit")
    RANGE_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    EXIT_FIELD_NUMBER: _ClassVar[int]
    range: _common_pb2.AddressRange
    rows: _containers.RepeatedCompositeFieldContainer[_listing_pb2.ListingRow]
    exit: bool
    def __init__(self, range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., rows: _Optional[_Iterable[_Union[_listing_pb2.ListingRow, _Mapping]]] = ..., exit: _Optional[bool] = ...) -> None: ...

class GetFunctionGraphResponse(_message.Message):
    __slots__ = ("snapshot", "function", "blocks", "entry_block", "edges", "truncated")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    BLOCKS_FIELD_NUMBER: _ClassVar[int]
    ENTRY_BLOCK_FIELD_NUMBER: _ClassVar[int]
    EDGES_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    function: _listing_pb2.Function
    blocks: _containers.RepeatedCompositeFieldContainer[BasicBlock]
    entry_block: int
    edges: _containers.RepeatedCompositeFieldContainer[FlowEdge]
    truncated: bool
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., function: _Optional[_Union[_listing_pb2.Function, _Mapping]] = ..., blocks: _Optional[_Iterable[_Union[BasicBlock, _Mapping]]] = ..., entry_block: _Optional[int] = ..., edges: _Optional[_Iterable[_Union[FlowEdge, _Mapping]]] = ..., truncated: _Optional[bool] = ...) -> None: ...

class DefinedData(_message.Message):
    __slots__ = ("address", "length", "category", "data_type", "value", "target", "label", "xref_to_count", "origin")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    DATA_TYPE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    XREF_TO_COUNT_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    length: int
    category: DataCategory
    data_type: str
    value: str
    target: _common_pb2.Address
    label: str
    xref_to_count: int
    origin: _common_pb2.FactOrigin
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., length: _Optional[int] = ..., category: _Optional[_Union[DataCategory, str]] = ..., data_type: _Optional[str] = ..., value: _Optional[str] = ..., target: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., label: _Optional[str] = ..., xref_to_count: _Optional[int] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ...) -> None: ...

class ListDataRequest(_message.Message):
    __slots__ = ("program_id", "read", "page", "categories", "text_contains", "range", "offset")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    TEXT_CONTAINS_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    page: _common_pb2.PageRequest
    categories: _containers.RepeatedScalarFieldContainer[DataCategory]
    text_contains: str
    range: _common_pb2.AddressRange
    offset: int
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., page: _Optional[_Union[_common_pb2.PageRequest, _Mapping]] = ..., categories: _Optional[_Iterable[_Union[DataCategory, str]]] = ..., text_contains: _Optional[str] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., offset: _Optional[int] = ...) -> None: ...

class ListDataResponse(_message.Message):
    __slots__ = ("snapshot", "data", "page")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    data: _containers.RepeatedCompositeFieldContainer[DefinedData]
    page: _common_pb2.PageInfo
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., data: _Optional[_Iterable[_Union[DefinedData, _Mapping]]] = ..., page: _Optional[_Union[_common_pb2.PageInfo, _Mapping]] = ...) -> None: ...

class ListCommentsRequest(_message.Message):
    __slots__ = ("program_id", "read", "page", "kinds", "text_contains", "range")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    KINDS_FIELD_NUMBER: _ClassVar[int]
    TEXT_CONTAINS_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    page: _common_pb2.PageRequest
    kinds: _containers.RepeatedScalarFieldContainer[_assertion_pb2.CommentKind]
    text_contains: str
    range: _common_pb2.AddressRange
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., page: _Optional[_Union[_common_pb2.PageRequest, _Mapping]] = ..., kinds: _Optional[_Iterable[_Union[_assertion_pb2.CommentKind, str]]] = ..., text_contains: _Optional[str] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ...) -> None: ...

class ProgramComment(_message.Message):
    __slots__ = ("address", "kind", "text", "function", "function_name", "label", "origin")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    kind: _assertion_pb2.CommentKind
    text: str
    function: _common_pb2.Address
    function_name: str
    label: str
    origin: _common_pb2.FactOrigin
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., kind: _Optional[_Union[_assertion_pb2.CommentKind, str]] = ..., text: _Optional[str] = ..., function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., function_name: _Optional[str] = ..., label: _Optional[str] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ...) -> None: ...

class ListCommentsResponse(_message.Message):
    __slots__ = ("snapshot", "comments", "page", "total")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    COMMENTS_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    comments: _containers.RepeatedCompositeFieldContainer[ProgramComment]
    page: _common_pb2.PageInfo
    total: int
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., comments: _Optional[_Iterable[_Union[ProgramComment, _Mapping]]] = ..., page: _Optional[_Union[_common_pb2.PageInfo, _Mapping]] = ..., total: _Optional[int] = ...) -> None: ...

class ListRelocationsRequest(_message.Message):
    __slots__ = ("program_id", "read", "page", "range", "text_contains")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    TEXT_CONTAINS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    page: _common_pb2.PageRequest
    range: _common_pb2.AddressRange
    text_contains: str
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., page: _Optional[_Union[_common_pb2.PageRequest, _Mapping]] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., text_contains: _Optional[str] = ...) -> None: ...

class ProgramRelocation(_message.Message):
    __slots__ = ("address", "type", "type_name", "kind", "symbol", "addend", "target", "original", "target_name")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    TYPE_NAME_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    SYMBOL_FIELD_NUMBER: _ClassVar[int]
    ADDEND_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    ORIGINAL_FIELD_NUMBER: _ClassVar[int]
    TARGET_NAME_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    type: int
    type_name: str
    kind: RelocationKind
    symbol: str
    addend: int
    target: _common_pb2.Address
    original: bytes
    target_name: str
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., type: _Optional[int] = ..., type_name: _Optional[str] = ..., kind: _Optional[_Union[RelocationKind, str]] = ..., symbol: _Optional[str] = ..., addend: _Optional[int] = ..., target: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., original: _Optional[bytes] = ..., target_name: _Optional[str] = ...) -> None: ...

class ListRelocationsResponse(_message.Message):
    __slots__ = ("snapshot", "relocations", "page", "total", "format")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    RELOCATIONS_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    relocations: _containers.RepeatedCompositeFieldContainer[ProgramRelocation]
    page: _common_pb2.PageInfo
    total: int
    format: str
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., relocations: _Optional[_Iterable[_Union[ProgramRelocation, _Mapping]]] = ..., page: _Optional[_Union[_common_pb2.PageInfo, _Mapping]] = ..., total: _Optional[int] = ..., format: _Optional[str] = ...) -> None: ...

class GetBuildInfoRequest(_message.Message):
    __slots__ = ("program_id", "read")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ...) -> None: ...

class GoModule(_message.Message):
    __slots__ = ("path", "version", "sum", "replacement")
    PATH_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    SUM_FIELD_NUMBER: _ClassVar[int]
    REPLACEMENT_FIELD_NUMBER: _ClassVar[int]
    path: str
    version: str
    sum: str
    replacement: GoModuleReplacement
    def __init__(self, path: _Optional[str] = ..., version: _Optional[str] = ..., sum: _Optional[str] = ..., replacement: _Optional[_Union[GoModuleReplacement, _Mapping]] = ...) -> None: ...

class GoModuleReplacement(_message.Message):
    __slots__ = ("path", "version", "sum")
    PATH_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    SUM_FIELD_NUMBER: _ClassVar[int]
    path: str
    version: str
    sum: str
    def __init__(self, path: _Optional[str] = ..., version: _Optional[str] = ..., sum: _Optional[str] = ...) -> None: ...

class GoBuildSetting(_message.Message):
    __slots__ = ("key", "value")
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    value: str
    def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class GoBuildInfo(_message.Message):
    __slots__ = ("go_version", "path", "main", "deps", "settings", "format", "pointer_size", "address", "module_text", "unparsed")
    GO_VERSION_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    MAIN_FIELD_NUMBER: _ClassVar[int]
    DEPS_FIELD_NUMBER: _ClassVar[int]
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    POINTER_SIZE_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    MODULE_TEXT_FIELD_NUMBER: _ClassVar[int]
    UNPARSED_FIELD_NUMBER: _ClassVar[int]
    go_version: str
    path: str
    main: GoModule
    deps: _containers.RepeatedCompositeFieldContainer[GoModule]
    settings: _containers.RepeatedCompositeFieldContainer[GoBuildSetting]
    format: str
    pointer_size: int
    address: _common_pb2.Address
    module_text: str
    unparsed: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, go_version: _Optional[str] = ..., path: _Optional[str] = ..., main: _Optional[_Union[GoModule, _Mapping]] = ..., deps: _Optional[_Iterable[_Union[GoModule, _Mapping]]] = ..., settings: _Optional[_Iterable[_Union[GoBuildSetting, _Mapping]]] = ..., format: _Optional[str] = ..., pointer_size: _Optional[int] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., module_text: _Optional[str] = ..., unparsed: _Optional[_Iterable[str]] = ...) -> None: ...

class RustPackage(_message.Message):
    __slots__ = ("name", "version", "source", "kind", "dependencies", "root")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    DEPENDENCIES_FIELD_NUMBER: _ClassVar[int]
    ROOT_FIELD_NUMBER: _ClassVar[int]
    name: str
    version: str
    source: str
    kind: str
    dependencies: _containers.RepeatedScalarFieldContainer[int]
    root: bool
    def __init__(self, name: _Optional[str] = ..., version: _Optional[str] = ..., source: _Optional[str] = ..., kind: _Optional[str] = ..., dependencies: _Optional[_Iterable[int]] = ..., root: _Optional[bool] = ...) -> None: ...

class RustDependencies(_message.Message):
    __slots__ = ("format", "packages", "root", "compressed_size", "uncompressed_size")
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    PACKAGES_FIELD_NUMBER: _ClassVar[int]
    ROOT_FIELD_NUMBER: _ClassVar[int]
    COMPRESSED_SIZE_FIELD_NUMBER: _ClassVar[int]
    UNCOMPRESSED_SIZE_FIELD_NUMBER: _ClassVar[int]
    format: int
    packages: _containers.RepeatedCompositeFieldContainer[RustPackage]
    root: int
    compressed_size: int
    uncompressed_size: int
    def __init__(self, format: _Optional[int] = ..., packages: _Optional[_Iterable[_Union[RustPackage, _Mapping]]] = ..., root: _Optional[int] = ..., compressed_size: _Optional[int] = ..., uncompressed_size: _Optional[int] = ...) -> None: ...

class GetBuildInfoResponse(_message.Message):
    __slots__ = ("snapshot", "go", "rust", "rustc_version", "rustc_commits", "warnings", "go_pclntab")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    GO_FIELD_NUMBER: _ClassVar[int]
    RUST_FIELD_NUMBER: _ClassVar[int]
    RUSTC_VERSION_FIELD_NUMBER: _ClassVar[int]
    RUSTC_COMMITS_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    GO_PCLNTAB_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    go: GoBuildInfo
    rust: RustDependencies
    rustc_version: str
    rustc_commits: _containers.RepeatedScalarFieldContainer[str]
    warnings: _containers.RepeatedScalarFieldContainer[str]
    go_pclntab: GoPclntab
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., go: _Optional[_Union[GoBuildInfo, _Mapping]] = ..., rust: _Optional[_Union[RustDependencies, _Mapping]] = ..., rustc_version: _Optional[str] = ..., rustc_commits: _Optional[_Iterable[str]] = ..., warnings: _Optional[_Iterable[str]] = ..., go_pclntab: _Optional[_Union[GoPclntab, _Mapping]] = ...) -> None: ...

class GoPclntab(_message.Message):
    __slots__ = ("layout", "address", "pointer_size", "quantum", "big_endian", "text_start", "function_count", "functions_read", "file_count", "moduledata", "found_by", "warnings")
    LAYOUT_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    POINTER_SIZE_FIELD_NUMBER: _ClassVar[int]
    QUANTUM_FIELD_NUMBER: _ClassVar[int]
    BIG_ENDIAN_FIELD_NUMBER: _ClassVar[int]
    TEXT_START_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_COUNT_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_READ_FIELD_NUMBER: _ClassVar[int]
    FILE_COUNT_FIELD_NUMBER: _ClassVar[int]
    MODULEDATA_FIELD_NUMBER: _ClassVar[int]
    FOUND_BY_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    layout: str
    address: _common_pb2.Address
    pointer_size: int
    quantum: int
    big_endian: bool
    text_start: _common_pb2.Address
    function_count: int
    functions_read: int
    file_count: int
    moduledata: _common_pb2.Address
    found_by: str
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, layout: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., pointer_size: _Optional[int] = ..., quantum: _Optional[int] = ..., big_endian: _Optional[bool] = ..., text_start: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., function_count: _Optional[int] = ..., functions_read: _Optional[int] = ..., file_count: _Optional[int] = ..., moduledata: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., found_by: _Optional[str] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class ListRegisterValuesRequest(_message.Message):
    __slots__ = ("program_id", "read", "page", "register_name", "range")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    REGISTER_NAME_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    page: _common_pb2.PageRequest
    register_name: str
    range: _common_pb2.AddressRange
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., page: _Optional[_Union[_common_pb2.PageRequest, _Mapping]] = ..., register_name: _Optional[str] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ...) -> None: ...

class RegisterValueRange(_message.Message):
    __slots__ = ("register_name", "range", "value", "origin", "key")
    REGISTER_NAME_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    register_name: str
    range: _common_pb2.AddressRange
    value: int
    origin: _common_pb2.FactOrigin
    key: _common_pb2.FactKey
    def __init__(self, register_name: _Optional[str] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., value: _Optional[int] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., key: _Optional[_Union[_common_pb2.FactKey, _Mapping]] = ...) -> None: ...

class RegisterDescription(_message.Message):
    __slots__ = ("name", "size")
    NAME_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    name: str
    size: int
    def __init__(self, name: _Optional[str] = ..., size: _Optional[int] = ...) -> None: ...

class ListRegisterValuesResponse(_message.Message):
    __slots__ = ("snapshot", "ranges", "page", "total", "registers")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    RANGES_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    REGISTERS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    ranges: _containers.RepeatedCompositeFieldContainer[RegisterValueRange]
    page: _common_pb2.PageInfo
    total: int
    registers: _containers.RepeatedCompositeFieldContainer[RegisterDescription]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., ranges: _Optional[_Iterable[_Union[RegisterValueRange, _Mapping]]] = ..., page: _Optional[_Union[_common_pb2.PageInfo, _Mapping]] = ..., total: _Optional[int] = ..., registers: _Optional[_Iterable[_Union[RegisterDescription, _Mapping]]] = ...) -> None: ...

class GetClassHierarchyRequest(_message.Message):
    __slots__ = ("program_id", "read", "name_contains")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    NAME_CONTAINS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    name_contains: str
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., name_contains: _Optional[str] = ...) -> None: ...

class RttiBase(_message.Message):
    __slots__ = ("name", "type_descriptor", "direct", "is_virtual", "offset", "vbtable_offset", "vbtable_index", "attributes", "depth", "base_descriptor")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_DESCRIPTOR_FIELD_NUMBER: _ClassVar[int]
    DIRECT_FIELD_NUMBER: _ClassVar[int]
    IS_VIRTUAL_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    VBTABLE_OFFSET_FIELD_NUMBER: _ClassVar[int]
    VBTABLE_INDEX_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    DEPTH_FIELD_NUMBER: _ClassVar[int]
    BASE_DESCRIPTOR_FIELD_NUMBER: _ClassVar[int]
    name: str
    type_descriptor: _common_pb2.Address
    direct: bool
    is_virtual: bool
    offset: int
    vbtable_offset: int
    vbtable_index: int
    attributes: int
    depth: int
    base_descriptor: _common_pb2.Address
    def __init__(self, name: _Optional[str] = ..., type_descriptor: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., direct: _Optional[bool] = ..., is_virtual: _Optional[bool] = ..., offset: _Optional[int] = ..., vbtable_offset: _Optional[int] = ..., vbtable_index: _Optional[int] = ..., attributes: _Optional[int] = ..., depth: _Optional[int] = ..., base_descriptor: _Optional[_Union[_common_pb2.Address, _Mapping]] = ...) -> None: ...

class RttiVirtualFunction(_message.Message):
    __slots__ = ("slot", "entry", "name")
    SLOT_FIELD_NUMBER: _ClassVar[int]
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    slot: int
    entry: _common_pb2.Address
    name: str
    def __init__(self, slot: _Optional[int] = ..., entry: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., name: _Optional[str] = ...) -> None: ...

class RttiVftable(_message.Message):
    __slots__ = ("address", "name", "offset", "subobject", "locator", "functions")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    SUBOBJECT_FIELD_NUMBER: _ClassVar[int]
    LOCATOR_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    name: str
    offset: int
    subobject: str
    locator: _common_pb2.Address
    functions: _containers.RepeatedCompositeFieldContainer[RttiVirtualFunction]
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., name: _Optional[str] = ..., offset: _Optional[int] = ..., subobject: _Optional[str] = ..., locator: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., functions: _Optional[_Iterable[_Union[RttiVirtualFunction, _Mapping]]] = ...) -> None: ...

class RttiClass(_message.Message):
    __slots__ = ("name", "mangled", "is_struct", "type_descriptor", "hierarchy", "hierarchy_attributes", "bases", "derived", "vftables", "type_name", "type_hash")
    NAME_FIELD_NUMBER: _ClassVar[int]
    MANGLED_FIELD_NUMBER: _ClassVar[int]
    IS_STRUCT_FIELD_NUMBER: _ClassVar[int]
    TYPE_DESCRIPTOR_FIELD_NUMBER: _ClassVar[int]
    HIERARCHY_FIELD_NUMBER: _ClassVar[int]
    HIERARCHY_ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    BASES_FIELD_NUMBER: _ClassVar[int]
    DERIVED_FIELD_NUMBER: _ClassVar[int]
    VFTABLES_FIELD_NUMBER: _ClassVar[int]
    TYPE_NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_HASH_FIELD_NUMBER: _ClassVar[int]
    name: str
    mangled: str
    is_struct: bool
    type_descriptor: _common_pb2.Address
    hierarchy: _common_pb2.Address
    hierarchy_attributes: int
    bases: _containers.RepeatedCompositeFieldContainer[RttiBase]
    derived: _containers.RepeatedScalarFieldContainer[str]
    vftables: _containers.RepeatedCompositeFieldContainer[RttiVftable]
    type_name: str
    type_hash: str
    def __init__(self, name: _Optional[str] = ..., mangled: _Optional[str] = ..., is_struct: _Optional[bool] = ..., type_descriptor: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., hierarchy: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., hierarchy_attributes: _Optional[int] = ..., bases: _Optional[_Iterable[_Union[RttiBase, _Mapping]]] = ..., derived: _Optional[_Iterable[str]] = ..., vftables: _Optional[_Iterable[_Union[RttiVftable, _Mapping]]] = ..., type_name: _Optional[str] = ..., type_hash: _Optional[str] = ...) -> None: ...

class GetClassHierarchyResponse(_message.Message):
    __slots__ = ("snapshot", "classes")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    CLASSES_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    classes: _containers.RepeatedCompositeFieldContainer[RttiClass]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., classes: _Optional[_Iterable[_Union[RttiClass, _Mapping]]] = ...) -> None: ...

class DecompileManyRequest(_message.Message):
    __slots__ = ("program_id", "functions", "all", "read", "options", "parallelism")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    ALL_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    OPTIONS_FIELD_NUMBER: _ClassVar[int]
    PARALLELISM_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    functions: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    all: bool
    read: _common_pb2.ReadOptions
    options: _decompile_pb2.DecompileOptions
    parallelism: int
    def __init__(self, program_id: _Optional[str] = ..., functions: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., all: _Optional[bool] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., options: _Optional[_Union[_decompile_pb2.DecompileOptions, _Mapping]] = ..., parallelism: _Optional[int] = ...) -> None: ...

class DecompileManyResponse(_message.Message):
    __slots__ = ("snapshot", "index", "total", "entry", "function", "failure", "error", "served_before", "elapsed_ms", "function_ms")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    SERVED_BEFORE_FIELD_NUMBER: _ClassVar[int]
    ELAPSED_MS_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_MS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    index: int
    total: int
    entry: _common_pb2.Address
    function: _decompile_pb2.DecompiledFunction
    failure: _decompile_pb2.DecompileFailure
    error: str
    served_before: bool
    elapsed_ms: float
    function_ms: float
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., index: _Optional[int] = ..., total: _Optional[int] = ..., entry: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., function: _Optional[_Union[_decompile_pb2.DecompiledFunction, _Mapping]] = ..., failure: _Optional[_Union[_decompile_pb2.DecompileFailure, _Mapping]] = ..., error: _Optional[str] = ..., served_before: _Optional[bool] = ..., elapsed_ms: _Optional[float] = ..., function_ms: _Optional[float] = ...) -> None: ...

class ExportCRequest(_message.Message):
    __slots__ = ("program_id", "read", "functions", "all", "header", "name", "timeout_ms", "parallelism", "dialect", "per_function")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    ALL_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    PARALLELISM_FIELD_NUMBER: _ClassVar[int]
    DIALECT_FIELD_NUMBER: _ClassVar[int]
    PER_FUNCTION_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    functions: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    all: bool
    header: bool
    name: str
    timeout_ms: int
    parallelism: int
    dialect: CDialect
    per_function: bool
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., functions: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., all: _Optional[bool] = ..., header: _Optional[bool] = ..., name: _Optional[str] = ..., timeout_ms: _Optional[int] = ..., parallelism: _Optional[int] = ..., dialect: _Optional[_Union[CDialect, str]] = ..., per_function: _Optional[bool] = ...) -> None: ...

class ExportedCFunction(_message.Message):
    __slots__ = ("entry", "name", "source", "prototype", "failure")
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    PROTOTYPE_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    entry: _common_pb2.Address
    name: str
    source: str
    prototype: str
    failure: str
    def __init__(self, entry: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., name: _Optional[str] = ..., source: _Optional[str] = ..., prototype: _Optional[str] = ..., failure: _Optional[str] = ...) -> None: ...

class ExportCResponse(_message.Message):
    __slots__ = ("snapshot", "done", "total", "source_name", "header_name", "header", "source_part", "finished", "functions", "failed", "notes", "function_sources")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    DONE_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    SOURCE_NAME_FIELD_NUMBER: _ClassVar[int]
    HEADER_NAME_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    SOURCE_PART_FIELD_NUMBER: _ClassVar[int]
    FINISHED_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    FAILED_FIELD_NUMBER: _ClassVar[int]
    NOTES_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_SOURCES_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    done: int
    total: int
    source_name: str
    header_name: str
    header: str
    source_part: str
    finished: bool
    functions: int
    failed: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    notes: _containers.RepeatedScalarFieldContainer[str]
    function_sources: _containers.RepeatedCompositeFieldContainer[ExportedCFunction]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., done: _Optional[int] = ..., total: _Optional[int] = ..., source_name: _Optional[str] = ..., header_name: _Optional[str] = ..., header: _Optional[str] = ..., source_part: _Optional[str] = ..., finished: _Optional[bool] = ..., functions: _Optional[int] = ..., failed: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., notes: _Optional[_Iterable[str]] = ..., function_sources: _Optional[_Iterable[_Union[ExportedCFunction, _Mapping]]] = ...) -> None: ...

class FindBytesRequest(_message.Message):
    __slots__ = ("program_id", "pattern", "mask", "range", "max_results", "alignment", "read", "executable_only")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    PATTERN_FIELD_NUMBER: _ClassVar[int]
    MASK_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    MAX_RESULTS_FIELD_NUMBER: _ClassVar[int]
    ALIGNMENT_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    EXECUTABLE_ONLY_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    pattern: bytes
    mask: bytes
    range: _common_pb2.AddressRange
    max_results: int
    alignment: int
    read: _common_pb2.ReadOptions
    executable_only: bool
    def __init__(self, program_id: _Optional[str] = ..., pattern: _Optional[bytes] = ..., mask: _Optional[bytes] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., max_results: _Optional[int] = ..., alignment: _Optional[int] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., executable_only: _Optional[bool] = ...) -> None: ...

class FindBytesResponse(_message.Message):
    __slots__ = ("snapshot", "addresses", "truncated", "bytes_searched")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    BYTES_SEARCHED_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    addresses: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    truncated: bool
    bytes_searched: int
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., addresses: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., truncated: _Optional[bool] = ..., bytes_searched: _Optional[int] = ...) -> None: ...

class ListInstructionsRequest(_message.Message):
    __slots__ = ("program_id", "range", "function", "read", "omit_pcode", "limit")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    OMIT_PCODE_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    range: _common_pb2.AddressRange
    function: _common_pb2.Address
    read: _common_pb2.ReadOptions
    omit_pcode: bool
    limit: int
    def __init__(self, program_id: _Optional[str] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., omit_pcode: _Optional[bool] = ..., limit: _Optional[int] = ...) -> None: ...

class ListInstructionsResponse(_message.Message):
    __slots__ = ("snapshot", "instructions", "truncated")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    INSTRUCTIONS_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    instructions: _containers.RepeatedCompositeFieldContainer[_listing_pb2.InstructionDetail]
    truncated: bool
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., instructions: _Optional[_Iterable[_Union[_listing_pb2.InstructionDetail, _Mapping]]] = ..., truncated: _Optional[bool] = ...) -> None: ...

class GetByteViewRequest(_message.Message):
    __slots__ = ("program_id", "read", "address", "length")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    address: _common_pb2.Address
    length: int
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., length: _Optional[int] = ...) -> None: ...

class ByteRun(_message.Message):
    __slots__ = ("start", "length", "kind")
    START_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    start: _common_pb2.Address
    length: int
    kind: ByteKind
    def __init__(self, start: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., length: _Optional[int] = ..., kind: _Optional[_Union[ByteKind, str]] = ...) -> None: ...

class PatchedBytes(_message.Message):
    __slots__ = ("start", "original")
    START_FIELD_NUMBER: _ClassVar[int]
    ORIGINAL_FIELD_NUMBER: _ClassVar[int]
    start: _common_pb2.Address
    original: bytes
    def __init__(self, start: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., original: _Optional[bytes] = ...) -> None: ...

class GetByteViewResponse(_message.Message):
    __slots__ = ("snapshot", "address", "data", "runs", "patched")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    RUNS_FIELD_NUMBER: _ClassVar[int]
    PATCHED_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    address: _common_pb2.Address
    data: bytes
    runs: _containers.RepeatedCompositeFieldContainer[ByteRun]
    patched: _containers.RepeatedCompositeFieldContainer[PatchedBytes]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., data: _Optional[bytes] = ..., runs: _Optional[_Iterable[_Union[ByteRun, _Mapping]]] = ..., patched: _Optional[_Iterable[_Union[PatchedBytes, _Mapping]]] = ...) -> None: ...

class GetOverviewRequest(_message.Message):
    __slots__ = ("program_id", "read", "buckets")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    BUCKETS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    buckets: int
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., buckets: _Optional[int] = ...) -> None: ...

class OverviewBucket(_message.Message):
    __slots__ = ("start", "length", "kind", "code", "data", "undefined", "external", "uninitialized", "entropy", "block")
    START_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    CODE_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    UNDEFINED_FIELD_NUMBER: _ClassVar[int]
    EXTERNAL_FIELD_NUMBER: _ClassVar[int]
    UNINITIALIZED_FIELD_NUMBER: _ClassVar[int]
    ENTROPY_FIELD_NUMBER: _ClassVar[int]
    BLOCK_FIELD_NUMBER: _ClassVar[int]
    start: _common_pb2.Address
    length: int
    kind: ByteKind
    code: int
    data: int
    undefined: int
    external: int
    uninitialized: int
    entropy: float
    block: str
    def __init__(self, start: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., length: _Optional[int] = ..., kind: _Optional[_Union[ByteKind, str]] = ..., code: _Optional[int] = ..., data: _Optional[int] = ..., undefined: _Optional[int] = ..., external: _Optional[int] = ..., uninitialized: _Optional[int] = ..., entropy: _Optional[float] = ..., block: _Optional[str] = ...) -> None: ...

class GetOverviewResponse(_message.Message):
    __slots__ = ("snapshot", "buckets", "total_bytes")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    BUCKETS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_BYTES_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    buckets: _containers.RepeatedCompositeFieldContainer[OverviewBucket]
    total_bytes: int
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., buckets: _Optional[_Iterable[_Union[OverviewBucket, _Mapping]]] = ..., total_bytes: _Optional[int] = ...) -> None: ...

class FindNextRequest(_message.Message):
    __slots__ = ("program_id", "read", "kind", "backward")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    FROM_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    BACKWARD_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    kind: NavigationKind
    backward: bool
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., kind: _Optional[_Union[NavigationKind, str]] = ..., backward: _Optional[bool] = ..., **kwargs) -> None: ...

class FindNextResponse(_message.Message):
    __slots__ = ("snapshot", "address", "found")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    FOUND_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    address: _common_pb2.Address
    found: bool
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., found: _Optional[bool] = ...) -> None: ...

class SearchScope(_message.Message):
    __slots__ = ("ranges", "instructions", "defined_data", "undefined", "executable_only")
    RANGES_FIELD_NUMBER: _ClassVar[int]
    INSTRUCTIONS_FIELD_NUMBER: _ClassVar[int]
    DEFINED_DATA_FIELD_NUMBER: _ClassVar[int]
    UNDEFINED_FIELD_NUMBER: _ClassVar[int]
    EXECUTABLE_ONLY_FIELD_NUMBER: _ClassVar[int]
    ranges: _containers.RepeatedCompositeFieldContainer[_common_pb2.AddressRange]
    instructions: bool
    defined_data: bool
    undefined: bool
    executable_only: bool
    def __init__(self, ranges: _Optional[_Iterable[_Union[_common_pb2.AddressRange, _Mapping]]] = ..., instructions: _Optional[bool] = ..., defined_data: _Optional[bool] = ..., undefined: _Optional[bool] = ..., executable_only: _Optional[bool] = ...) -> None: ...

class SearchStart(_message.Message):
    __slots__ = ("backward", "wrap")
    FROM_FIELD_NUMBER: _ClassVar[int]
    BACKWARD_FIELD_NUMBER: _ClassVar[int]
    WRAP_FIELD_NUMBER: _ClassVar[int]
    backward: bool
    wrap: bool
    def __init__(self, backward: _Optional[bool] = ..., wrap: _Optional[bool] = ..., **kwargs) -> None: ...

class SearchMemoryRequest(_message.Message):
    __slots__ = ("program_id", "read", "format", "query", "encoding", "case_sensitive", "escape_sequences", "value_size", "unsigned_values", "byte_order", "scope", "alignment", "start", "max_results", "details")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    ENCODING_FIELD_NUMBER: _ClassVar[int]
    CASE_SENSITIVE_FIELD_NUMBER: _ClassVar[int]
    ESCAPE_SEQUENCES_FIELD_NUMBER: _ClassVar[int]
    VALUE_SIZE_FIELD_NUMBER: _ClassVar[int]
    UNSIGNED_VALUES_FIELD_NUMBER: _ClassVar[int]
    BYTE_ORDER_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    ALIGNMENT_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    MAX_RESULTS_FIELD_NUMBER: _ClassVar[int]
    DETAILS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    format: SearchFormat
    query: str
    encoding: SearchEncoding
    case_sensitive: bool
    escape_sequences: bool
    value_size: int
    unsigned_values: bool
    byte_order: _project_pb2.Endianness
    scope: SearchScope
    alignment: int
    start: SearchStart
    max_results: int
    details: bool
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., format: _Optional[_Union[SearchFormat, str]] = ..., query: _Optional[str] = ..., encoding: _Optional[_Union[SearchEncoding, str]] = ..., case_sensitive: _Optional[bool] = ..., escape_sequences: _Optional[bool] = ..., value_size: _Optional[int] = ..., unsigned_values: _Optional[bool] = ..., byte_order: _Optional[_Union[_project_pb2.Endianness, str]] = ..., scope: _Optional[_Union[SearchScope, _Mapping]] = ..., alignment: _Optional[int] = ..., start: _Optional[_Union[SearchStart, _Mapping]] = ..., max_results: _Optional[int] = ..., details: _Optional[bool] = ...) -> None: ...

class MemoryMatch(_message.Message):
    __slots__ = ("address", "bytes", "label", "preview", "code_unit", "function", "function_name", "wrapped")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    PREVIEW_FIELD_NUMBER: _ClassVar[int]
    CODE_UNIT_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    WRAPPED_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    bytes: bytes
    label: str
    preview: str
    code_unit: _common_pb2.Address
    function: _common_pb2.Address
    function_name: str
    wrapped: bool
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., bytes: _Optional[bytes] = ..., label: _Optional[str] = ..., preview: _Optional[str] = ..., code_unit: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., function_name: _Optional[str] = ..., wrapped: _Optional[bool] = ...) -> None: ...

class SearchMemoryResponse(_message.Message):
    __slots__ = ("snapshot", "matches", "bytes_searched", "bytes_total", "done", "truncated", "pattern", "elapsed_ms")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    MATCHES_FIELD_NUMBER: _ClassVar[int]
    BYTES_SEARCHED_FIELD_NUMBER: _ClassVar[int]
    BYTES_TOTAL_FIELD_NUMBER: _ClassVar[int]
    DONE_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    PATTERN_FIELD_NUMBER: _ClassVar[int]
    ELAPSED_MS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    matches: _containers.RepeatedCompositeFieldContainer[MemoryMatch]
    bytes_searched: int
    bytes_total: int
    done: bool
    truncated: bool
    pattern: str
    elapsed_ms: float
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., matches: _Optional[_Iterable[_Union[MemoryMatch, _Mapping]]] = ..., bytes_searched: _Optional[int] = ..., bytes_total: _Optional[int] = ..., done: _Optional[bool] = ..., truncated: _Optional[bool] = ..., pattern: _Optional[str] = ..., elapsed_ms: _Optional[float] = ...) -> None: ...

class SearchTextRequest(_message.Message):
    __slots__ = ("program_id", "read", "query", "regex", "case_sensitive", "whole_word", "fields", "scope", "start", "max_results")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    REGEX_FIELD_NUMBER: _ClassVar[int]
    CASE_SENSITIVE_FIELD_NUMBER: _ClassVar[int]
    WHOLE_WORD_FIELD_NUMBER: _ClassVar[int]
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    MAX_RESULTS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    query: str
    regex: bool
    case_sensitive: bool
    whole_word: bool
    fields: _containers.RepeatedScalarFieldContainer[TextField]
    scope: SearchScope
    start: SearchStart
    max_results: int
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., query: _Optional[str] = ..., regex: _Optional[bool] = ..., case_sensitive: _Optional[bool] = ..., whole_word: _Optional[bool] = ..., fields: _Optional[_Iterable[_Union[TextField, str]]] = ..., scope: _Optional[_Union[SearchScope, _Mapping]] = ..., start: _Optional[_Union[SearchStart, _Mapping]] = ..., max_results: _Optional[int] = ...) -> None: ...

class TextMatch(_message.Message):
    __slots__ = ("address", "field", "text", "match_start", "match_length", "comment_kind", "label", "function", "function_name", "wrapped")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    FIELD_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    MATCH_START_FIELD_NUMBER: _ClassVar[int]
    MATCH_LENGTH_FIELD_NUMBER: _ClassVar[int]
    COMMENT_KIND_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    WRAPPED_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    field: TextField
    text: str
    match_start: int
    match_length: int
    comment_kind: _assertion_pb2.CommentKind
    label: str
    function: _common_pb2.Address
    function_name: str
    wrapped: bool
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., field: _Optional[_Union[TextField, str]] = ..., text: _Optional[str] = ..., match_start: _Optional[int] = ..., match_length: _Optional[int] = ..., comment_kind: _Optional[_Union[_assertion_pb2.CommentKind, str]] = ..., label: _Optional[str] = ..., function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., function_name: _Optional[str] = ..., wrapped: _Optional[bool] = ...) -> None: ...

class SearchTextResponse(_message.Message):
    __slots__ = ("snapshot", "matches", "rows_searched", "rows_total", "done", "truncated", "elapsed_ms")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    MATCHES_FIELD_NUMBER: _ClassVar[int]
    ROWS_SEARCHED_FIELD_NUMBER: _ClassVar[int]
    ROWS_TOTAL_FIELD_NUMBER: _ClassVar[int]
    DONE_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    ELAPSED_MS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    matches: _containers.RepeatedCompositeFieldContainer[TextMatch]
    rows_searched: int
    rows_total: int
    done: bool
    truncated: bool
    elapsed_ms: float
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., matches: _Optional[_Iterable[_Union[TextMatch, _Mapping]]] = ..., rows_searched: _Optional[int] = ..., rows_total: _Optional[int] = ..., done: _Optional[bool] = ..., truncated: _Optional[bool] = ..., elapsed_ms: _Optional[float] = ...) -> None: ...

class SearchScalarsRequest(_message.Message):
    __slots__ = ("program_id", "read", "min", "max", "scope", "start", "max_results")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    MIN_FIELD_NUMBER: _ClassVar[int]
    MAX_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    MAX_RESULTS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    min: int
    max: int
    scope: SearchScope
    start: SearchStart
    max_results: int
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., min: _Optional[int] = ..., max: _Optional[int] = ..., scope: _Optional[_Union[SearchScope, _Mapping]] = ..., start: _Optional[_Union[SearchStart, _Mapping]] = ..., max_results: _Optional[int] = ...) -> None: ...

class ScalarMatch(_message.Message):
    __slots__ = ("address", "value", "unsigned_value", "bits", "operand_index", "data", "text", "label", "function", "function_name", "wrapped")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    UNSIGNED_VALUE_FIELD_NUMBER: _ClassVar[int]
    BITS_FIELD_NUMBER: _ClassVar[int]
    OPERAND_INDEX_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    WRAPPED_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    value: int
    unsigned_value: int
    bits: int
    operand_index: int
    data: bool
    text: str
    label: str
    function: _common_pb2.Address
    function_name: str
    wrapped: bool
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., value: _Optional[int] = ..., unsigned_value: _Optional[int] = ..., bits: _Optional[int] = ..., operand_index: _Optional[int] = ..., data: _Optional[bool] = ..., text: _Optional[str] = ..., label: _Optional[str] = ..., function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., function_name: _Optional[str] = ..., wrapped: _Optional[bool] = ...) -> None: ...

class SearchScalarsResponse(_message.Message):
    __slots__ = ("snapshot", "matches", "rows_searched", "rows_total", "done", "truncated", "elapsed_ms")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    MATCHES_FIELD_NUMBER: _ClassVar[int]
    ROWS_SEARCHED_FIELD_NUMBER: _ClassVar[int]
    ROWS_TOTAL_FIELD_NUMBER: _ClassVar[int]
    DONE_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    ELAPSED_MS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    matches: _containers.RepeatedCompositeFieldContainer[ScalarMatch]
    rows_searched: int
    rows_total: int
    done: bool
    truncated: bool
    elapsed_ms: float
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., matches: _Optional[_Iterable[_Union[ScalarMatch, _Mapping]]] = ..., rows_searched: _Optional[int] = ..., rows_total: _Optional[int] = ..., done: _Optional[bool] = ..., truncated: _Optional[bool] = ..., elapsed_ms: _Optional[float] = ...) -> None: ...

class SearchDecompiledRequest(_message.Message):
    __slots__ = ("program_id", "read", "query", "regex", "case_sensitive", "whole_word", "functions", "ranges", "all", "parallelism", "timeout_ms", "max_results")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    REGEX_FIELD_NUMBER: _ClassVar[int]
    CASE_SENSITIVE_FIELD_NUMBER: _ClassVar[int]
    WHOLE_WORD_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    RANGES_FIELD_NUMBER: _ClassVar[int]
    ALL_FIELD_NUMBER: _ClassVar[int]
    PARALLELISM_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    MAX_RESULTS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    query: str
    regex: bool
    case_sensitive: bool
    whole_word: bool
    functions: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    ranges: _containers.RepeatedCompositeFieldContainer[_common_pb2.AddressRange]
    all: bool
    parallelism: int
    timeout_ms: int
    max_results: int
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., query: _Optional[str] = ..., regex: _Optional[bool] = ..., case_sensitive: _Optional[bool] = ..., whole_word: _Optional[bool] = ..., functions: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., ranges: _Optional[_Iterable[_Union[_common_pb2.AddressRange, _Mapping]]] = ..., all: _Optional[bool] = ..., parallelism: _Optional[int] = ..., timeout_ms: _Optional[int] = ..., max_results: _Optional[int] = ...) -> None: ...

class DecompiledMatch(_message.Message):
    __slots__ = ("function", "function_name", "line", "text", "match_start", "match_length", "address")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    LINE_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    MATCH_START_FIELD_NUMBER: _ClassVar[int]
    MATCH_LENGTH_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    function: _common_pb2.Address
    function_name: str
    line: int
    text: str
    match_start: int
    match_length: int
    address: _common_pb2.Address
    def __init__(self, function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., function_name: _Optional[str] = ..., line: _Optional[int] = ..., text: _Optional[str] = ..., match_start: _Optional[int] = ..., match_length: _Optional[int] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ...) -> None: ...

class SearchDecompiledResponse(_message.Message):
    __slots__ = ("snapshot", "matches", "functions_done", "functions_total", "functions_failed", "done", "truncated", "elapsed_ms")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    MATCHES_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_DONE_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_TOTAL_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FAILED_FIELD_NUMBER: _ClassVar[int]
    DONE_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    ELAPSED_MS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    matches: _containers.RepeatedCompositeFieldContainer[DecompiledMatch]
    functions_done: int
    functions_total: int
    functions_failed: int
    done: bool
    truncated: bool
    elapsed_ms: float
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., matches: _Optional[_Iterable[_Union[DecompiledMatch, _Mapping]]] = ..., functions_done: _Optional[int] = ..., functions_total: _Optional[int] = ..., functions_failed: _Optional[int] = ..., done: _Optional[bool] = ..., truncated: _Optional[bool] = ..., elapsed_ms: _Optional[float] = ...) -> None: ...

class FindTypeUsesRequest(_message.Message):
    __slots__ = ("program_id", "read", "type_hash", "field_offset", "field_name", "functions", "ranges", "all", "parallelism", "timeout_ms", "max_results")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    TYPE_HASH_FIELD_NUMBER: _ClassVar[int]
    FIELD_OFFSET_FIELD_NUMBER: _ClassVar[int]
    FIELD_NAME_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    RANGES_FIELD_NUMBER: _ClassVar[int]
    ALL_FIELD_NUMBER: _ClassVar[int]
    PARALLELISM_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    MAX_RESULTS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    type_hash: str
    field_offset: int
    field_name: str
    functions: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    ranges: _containers.RepeatedCompositeFieldContainer[_common_pb2.AddressRange]
    all: bool
    parallelism: int
    timeout_ms: int
    max_results: int
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., type_hash: _Optional[str] = ..., field_offset: _Optional[int] = ..., field_name: _Optional[str] = ..., functions: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., ranges: _Optional[_Iterable[_Union[_common_pb2.AddressRange, _Mapping]]] = ..., all: _Optional[bool] = ..., parallelism: _Optional[int] = ..., timeout_ms: _Optional[int] = ..., max_results: _Optional[int] = ...) -> None: ...

class TypeUse(_message.Message):
    __slots__ = ("function", "function_name", "kind", "access", "address", "line", "text", "match_start", "match_length", "field_name", "field_offset")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LINE_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    MATCH_START_FIELD_NUMBER: _ClassVar[int]
    MATCH_LENGTH_FIELD_NUMBER: _ClassVar[int]
    FIELD_NAME_FIELD_NUMBER: _ClassVar[int]
    FIELD_OFFSET_FIELD_NUMBER: _ClassVar[int]
    function: _common_pb2.Address
    function_name: str
    kind: TypeUseKind
    access: FieldAccess
    address: _common_pb2.Address
    line: int
    text: str
    match_start: int
    match_length: int
    field_name: str
    field_offset: int
    def __init__(self, function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., function_name: _Optional[str] = ..., kind: _Optional[_Union[TypeUseKind, str]] = ..., access: _Optional[_Union[FieldAccess, str]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., line: _Optional[int] = ..., text: _Optional[str] = ..., match_start: _Optional[int] = ..., match_length: _Optional[int] = ..., field_name: _Optional[str] = ..., field_offset: _Optional[int] = ...) -> None: ...

class FindTypeUsesResponse(_message.Message):
    __slots__ = ("snapshot", "uses", "functions_done", "functions_total", "functions_failed", "done", "truncated", "elapsed_ms")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    USES_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_DONE_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_TOTAL_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FAILED_FIELD_NUMBER: _ClassVar[int]
    DONE_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    ELAPSED_MS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    uses: _containers.RepeatedCompositeFieldContainer[TypeUse]
    functions_done: int
    functions_total: int
    functions_failed: int
    done: bool
    truncated: bool
    elapsed_ms: float
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., uses: _Optional[_Iterable[_Union[TypeUse, _Mapping]]] = ..., functions_done: _Optional[int] = ..., functions_total: _Optional[int] = ..., functions_failed: _Optional[int] = ..., done: _Optional[bool] = ..., truncated: _Optional[bool] = ..., elapsed_ms: _Optional[float] = ...) -> None: ...

class ListCallingConventionsRequest(_message.Message):
    __slots__ = ("program_id",)
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    def __init__(self, program_id: _Optional[str] = ...) -> None: ...

class CallingConvention(_message.Message):
    __slots__ = ("name", "is_default", "c_spelling")
    NAME_FIELD_NUMBER: _ClassVar[int]
    IS_DEFAULT_FIELD_NUMBER: _ClassVar[int]
    C_SPELLING_FIELD_NUMBER: _ClassVar[int]
    name: str
    is_default: bool
    c_spelling: str
    def __init__(self, name: _Optional[str] = ..., is_default: _Optional[bool] = ..., c_spelling: _Optional[str] = ...) -> None: ...

class ListCallingConventionsResponse(_message.Message):
    __slots__ = ("conventions", "default_name")
    CONVENTIONS_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_NAME_FIELD_NUMBER: _ClassVar[int]
    conventions: _containers.RepeatedCompositeFieldContainer[CallingConvention]
    default_name: str
    def __init__(self, conventions: _Optional[_Iterable[_Union[CallingConvention, _Mapping]]] = ..., default_name: _Optional[str] = ...) -> None: ...

class ListObjcClassesRequest(_message.Message):
    __slots__ = ("program_id", "read", "name_contains")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    NAME_CONTAINS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    name_contains: str
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., name_contains: _Optional[str] = ...) -> None: ...

class ObjcMethod(_message.Message):
    __slots__ = ("selector", "types", "implementation", "class_method", "category", "optional", "function_name")
    SELECTOR_FIELD_NUMBER: _ClassVar[int]
    TYPES_FIELD_NUMBER: _ClassVar[int]
    IMPLEMENTATION_FIELD_NUMBER: _ClassVar[int]
    CLASS_METHOD_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    OPTIONAL_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    selector: str
    types: str
    implementation: _common_pb2.Address
    class_method: bool
    category: str
    optional: bool
    function_name: str
    def __init__(self, selector: _Optional[str] = ..., types: _Optional[str] = ..., implementation: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., class_method: _Optional[bool] = ..., category: _Optional[str] = ..., optional: _Optional[bool] = ..., function_name: _Optional[str] = ...) -> None: ...

class ObjcIvar(_message.Message):
    __slots__ = ("name", "type", "offset", "size", "offset_variable")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    OFFSET_VARIABLE_FIELD_NUMBER: _ClassVar[int]
    name: str
    type: str
    offset: int
    size: int
    offset_variable: _common_pb2.Address
    def __init__(self, name: _Optional[str] = ..., type: _Optional[str] = ..., offset: _Optional[int] = ..., size: _Optional[int] = ..., offset_variable: _Optional[_Union[_common_pb2.Address, _Mapping]] = ...) -> None: ...

class ObjcProperty(_message.Message):
    __slots__ = ("name", "attributes")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    name: str
    attributes: str
    def __init__(self, name: _Optional[str] = ..., attributes: _Optional[str] = ...) -> None: ...

class ObjcClass(_message.Message):
    __slots__ = ("name", "address", "metaclass", "superclass", "instance_size", "root", "swift", "external", "methods", "ivars", "properties", "protocols", "categories")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    METACLASS_FIELD_NUMBER: _ClassVar[int]
    SUPERCLASS_FIELD_NUMBER: _ClassVar[int]
    INSTANCE_SIZE_FIELD_NUMBER: _ClassVar[int]
    ROOT_FIELD_NUMBER: _ClassVar[int]
    SWIFT_FIELD_NUMBER: _ClassVar[int]
    EXTERNAL_FIELD_NUMBER: _ClassVar[int]
    METHODS_FIELD_NUMBER: _ClassVar[int]
    IVARS_FIELD_NUMBER: _ClassVar[int]
    PROPERTIES_FIELD_NUMBER: _ClassVar[int]
    PROTOCOLS_FIELD_NUMBER: _ClassVar[int]
    CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    name: str
    address: _common_pb2.Address
    metaclass: _common_pb2.Address
    superclass: str
    instance_size: int
    root: bool
    swift: bool
    external: bool
    methods: _containers.RepeatedCompositeFieldContainer[ObjcMethod]
    ivars: _containers.RepeatedCompositeFieldContainer[ObjcIvar]
    properties: _containers.RepeatedCompositeFieldContainer[ObjcProperty]
    protocols: _containers.RepeatedScalarFieldContainer[str]
    categories: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, name: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., metaclass: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., superclass: _Optional[str] = ..., instance_size: _Optional[int] = ..., root: _Optional[bool] = ..., swift: _Optional[bool] = ..., external: _Optional[bool] = ..., methods: _Optional[_Iterable[_Union[ObjcMethod, _Mapping]]] = ..., ivars: _Optional[_Iterable[_Union[ObjcIvar, _Mapping]]] = ..., properties: _Optional[_Iterable[_Union[ObjcProperty, _Mapping]]] = ..., protocols: _Optional[_Iterable[str]] = ..., categories: _Optional[_Iterable[str]] = ...) -> None: ...

class ObjcProtocol(_message.Message):
    __slots__ = ("name", "address", "methods", "properties", "protocols")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    METHODS_FIELD_NUMBER: _ClassVar[int]
    PROPERTIES_FIELD_NUMBER: _ClassVar[int]
    PROTOCOLS_FIELD_NUMBER: _ClassVar[int]
    name: str
    address: _common_pb2.Address
    methods: _containers.RepeatedCompositeFieldContainer[ObjcMethod]
    properties: _containers.RepeatedCompositeFieldContainer[ObjcProperty]
    protocols: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, name: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., methods: _Optional[_Iterable[_Union[ObjcMethod, _Mapping]]] = ..., properties: _Optional[_Iterable[_Union[ObjcProperty, _Mapping]]] = ..., protocols: _Optional[_Iterable[str]] = ...) -> None: ...

class SwiftType(_message.Message):
    __slots__ = ("name", "parent", "kind", "type_descriptor", "accessor", "fields", "vtable")
    NAME_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    TYPE_DESCRIPTOR_FIELD_NUMBER: _ClassVar[int]
    ACCESSOR_FIELD_NUMBER: _ClassVar[int]
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    VTABLE_FIELD_NUMBER: _ClassVar[int]
    name: str
    parent: str
    kind: str
    type_descriptor: _common_pb2.Address
    accessor: _common_pb2.Address
    fields: _containers.RepeatedScalarFieldContainer[str]
    vtable: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    def __init__(self, name: _Optional[str] = ..., parent: _Optional[str] = ..., kind: _Optional[str] = ..., type_descriptor: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., accessor: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., fields: _Optional[_Iterable[str]] = ..., vtable: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ...) -> None: ...

class ListObjcClassesResponse(_message.Message):
    __slots__ = ("snapshot", "classes", "protocols", "swift_types")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    CLASSES_FIELD_NUMBER: _ClassVar[int]
    PROTOCOLS_FIELD_NUMBER: _ClassVar[int]
    SWIFT_TYPES_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    classes: _containers.RepeatedCompositeFieldContainer[ObjcClass]
    protocols: _containers.RepeatedCompositeFieldContainer[ObjcProtocol]
    swift_types: _containers.RepeatedCompositeFieldContainer[SwiftType]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., classes: _Optional[_Iterable[_Union[ObjcClass, _Mapping]]] = ..., protocols: _Optional[_Iterable[_Union[ObjcProtocol, _Mapping]]] = ..., swift_types: _Optional[_Iterable[_Union[SwiftType, _Mapping]]] = ...) -> None: ...

class ExportDecompScratchRequest(_message.Message):
    __slots__ = ("program_id", "function", "read", "module", "timeout_ms", "dialect")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    MODULE_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    DIALECT_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    function: _common_pb2.Address
    read: _common_pb2.ReadOptions
    module: str
    timeout_ms: int
    dialect: CDialect
    def __init__(self, program_id: _Optional[str] = ..., function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., module: _Optional[str] = ..., timeout_ms: _Optional[int] = ..., dialect: _Optional[_Union[CDialect, str]] = ...) -> None: ...

class ExportDecompScratchResponse(_message.Message):
    __slots__ = ("snapshot", "text", "context", "source", "probe", "function_name", "symbol", "module", "types", "callees", "globals", "notes", "failure")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    PROBE_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    SYMBOL_FIELD_NUMBER: _ClassVar[int]
    MODULE_FIELD_NUMBER: _ClassVar[int]
    TYPES_FIELD_NUMBER: _ClassVar[int]
    CALLEES_FIELD_NUMBER: _ClassVar[int]
    GLOBALS_FIELD_NUMBER: _ClassVar[int]
    NOTES_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    text: str
    context: str
    source: str
    probe: str
    function_name: str
    symbol: str
    module: str
    types: int
    callees: int
    globals: int
    notes: _containers.RepeatedScalarFieldContainer[str]
    failure: _decompile_pb2.DecompileFailure
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., text: _Optional[str] = ..., context: _Optional[str] = ..., source: _Optional[str] = ..., probe: _Optional[str] = ..., function_name: _Optional[str] = ..., symbol: _Optional[str] = ..., module: _Optional[str] = ..., types: _Optional[int] = ..., callees: _Optional[int] = ..., globals: _Optional[int] = ..., notes: _Optional[_Iterable[str]] = ..., failure: _Optional[_Union[_decompile_pb2.DecompileFailure, _Mapping]] = ...) -> None: ...
