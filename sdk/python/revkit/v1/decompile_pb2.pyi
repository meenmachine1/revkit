from revkit.v1 import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class VariableKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VARIABLE_KIND_UNSPECIFIED: _ClassVar[VariableKind]
    VARIABLE_KIND_PARAMETER: _ClassVar[VariableKind]
    VARIABLE_KIND_LOCAL: _ClassVar[VariableKind]
    VARIABLE_KIND_GLOBAL: _ClassVar[VariableKind]

class CodeTokenKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CODE_TOKEN_KIND_UNSPECIFIED: _ClassVar[CodeTokenKind]
    CODE_TOKEN_KIND_KEYWORD: _ClassVar[CodeTokenKind]
    CODE_TOKEN_KIND_TYPE: _ClassVar[CodeTokenKind]
    CODE_TOKEN_KIND_FUNCTION_NAME: _ClassVar[CodeTokenKind]
    CODE_TOKEN_KIND_LOCAL_VARIABLE: _ClassVar[CodeTokenKind]
    CODE_TOKEN_KIND_PARAMETER: _ClassVar[CodeTokenKind]
    CODE_TOKEN_KIND_GLOBAL_VARIABLE: _ClassVar[CodeTokenKind]
    CODE_TOKEN_KIND_CONSTANT: _ClassVar[CodeTokenKind]
    CODE_TOKEN_KIND_STRING: _ClassVar[CodeTokenKind]
    CODE_TOKEN_KIND_OPERATOR: _ClassVar[CodeTokenKind]
    CODE_TOKEN_KIND_PUNCTUATION: _ClassVar[CodeTokenKind]
    CODE_TOKEN_KIND_COMMENT: _ClassVar[CodeTokenKind]
    CODE_TOKEN_KIND_LABEL: _ClassVar[CodeTokenKind]
    CODE_TOKEN_KIND_FIELD: _ClassVar[CodeTokenKind]
    CODE_TOKEN_KIND_WHITESPACE: _ClassVar[CodeTokenKind]
    CODE_TOKEN_KIND_ERROR: _ClassVar[CodeTokenKind]

class DecompileFailureKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DECOMPILE_FAILURE_KIND_UNSPECIFIED: _ClassVar[DecompileFailureKind]
    DECOMPILE_FAILURE_KIND_SEGV: _ClassVar[DecompileFailureKind]
    DECOMPILE_FAILURE_KIND_FPE: _ClassVar[DecompileFailureKind]
    DECOMPILE_FAILURE_KIND_ABORT: _ClassVar[DecompileFailureKind]
    DECOMPILE_FAILURE_KIND_TIMEOUT: _ClassVar[DecompileFailureKind]
    DECOMPILE_FAILURE_KIND_OOM: _ClassVar[DecompileFailureKind]
VARIABLE_KIND_UNSPECIFIED: VariableKind
VARIABLE_KIND_PARAMETER: VariableKind
VARIABLE_KIND_LOCAL: VariableKind
VARIABLE_KIND_GLOBAL: VariableKind
CODE_TOKEN_KIND_UNSPECIFIED: CodeTokenKind
CODE_TOKEN_KIND_KEYWORD: CodeTokenKind
CODE_TOKEN_KIND_TYPE: CodeTokenKind
CODE_TOKEN_KIND_FUNCTION_NAME: CodeTokenKind
CODE_TOKEN_KIND_LOCAL_VARIABLE: CodeTokenKind
CODE_TOKEN_KIND_PARAMETER: CodeTokenKind
CODE_TOKEN_KIND_GLOBAL_VARIABLE: CodeTokenKind
CODE_TOKEN_KIND_CONSTANT: CodeTokenKind
CODE_TOKEN_KIND_STRING: CodeTokenKind
CODE_TOKEN_KIND_OPERATOR: CodeTokenKind
CODE_TOKEN_KIND_PUNCTUATION: CodeTokenKind
CODE_TOKEN_KIND_COMMENT: CodeTokenKind
CODE_TOKEN_KIND_LABEL: CodeTokenKind
CODE_TOKEN_KIND_FIELD: CodeTokenKind
CODE_TOKEN_KIND_WHITESPACE: CodeTokenKind
CODE_TOKEN_KIND_ERROR: CodeTokenKind
DECOMPILE_FAILURE_KIND_UNSPECIFIED: DecompileFailureKind
DECOMPILE_FAILURE_KIND_SEGV: DecompileFailureKind
DECOMPILE_FAILURE_KIND_FPE: DecompileFailureKind
DECOMPILE_FAILURE_KIND_ABORT: DecompileFailureKind
DECOMPILE_FAILURE_KIND_TIMEOUT: DecompileFailureKind
DECOMPILE_FAILURE_KIND_OOM: DecompileFailureKind

class TypeRef(_message.Message):
    __slots__ = ("hash", "display")
    HASH_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_FIELD_NUMBER: _ClassVar[int]
    hash: str
    display: str
    def __init__(self, hash: _Optional[str] = ..., display: _Optional[str] = ...) -> None: ...

class Variable(_message.Message):
    __slots__ = ("index", "kind", "name", "name_origin", "type", "type_origin", "storage_key", "storage", "parameter_index", "address")
    INDEX_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    NAME_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    TYPE_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    STORAGE_KEY_FIELD_NUMBER: _ClassVar[int]
    STORAGE_FIELD_NUMBER: _ClassVar[int]
    PARAMETER_INDEX_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    index: int
    kind: VariableKind
    name: str
    name_origin: _common_pb2.FactOrigin
    type: TypeRef
    type_origin: _common_pb2.FactOrigin
    storage_key: str
    storage: _containers.RepeatedCompositeFieldContainer[_common_pb2.Varnode]
    parameter_index: int
    address: _common_pb2.Address
    def __init__(self, index: _Optional[int] = ..., kind: _Optional[_Union[VariableKind, str]] = ..., name: _Optional[str] = ..., name_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., type: _Optional[_Union[TypeRef, _Mapping]] = ..., type_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., storage_key: _Optional[str] = ..., storage: _Optional[_Iterable[_Union[_common_pb2.Varnode, _Mapping]]] = ..., parameter_index: _Optional[int] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ...) -> None: ...

class FunctionPrototype(_message.Message):
    __slots__ = ("c_declaration", "return_type", "parameter_indices", "calling_convention", "varargs", "no_return", "origin")
    C_DECLARATION_FIELD_NUMBER: _ClassVar[int]
    RETURN_TYPE_FIELD_NUMBER: _ClassVar[int]
    PARAMETER_INDICES_FIELD_NUMBER: _ClassVar[int]
    CALLING_CONVENTION_FIELD_NUMBER: _ClassVar[int]
    VARARGS_FIELD_NUMBER: _ClassVar[int]
    NO_RETURN_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    c_declaration: str
    return_type: TypeRef
    parameter_indices: _containers.RepeatedScalarFieldContainer[int]
    calling_convention: str
    varargs: bool
    no_return: bool
    origin: _common_pb2.FactOrigin
    def __init__(self, c_declaration: _Optional[str] = ..., return_type: _Optional[_Union[TypeRef, _Mapping]] = ..., parameter_indices: _Optional[_Iterable[int]] = ..., calling_convention: _Optional[str] = ..., varargs: _Optional[bool] = ..., no_return: _Optional[bool] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ...) -> None: ...

class CodeToken(_message.Message):
    __slots__ = ("kind", "text", "address", "variable_index", "varnode_indices", "target", "type_hash", "value", "parent_type_hash", "field_offset", "constant_hash", "display_set", "demangled", "call_signature", "op_index")
    KIND_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    VARIABLE_INDEX_FIELD_NUMBER: _ClassVar[int]
    VARNODE_INDICES_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    TYPE_HASH_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    PARENT_TYPE_HASH_FIELD_NUMBER: _ClassVar[int]
    FIELD_OFFSET_FIELD_NUMBER: _ClassVar[int]
    CONSTANT_HASH_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_SET_FIELD_NUMBER: _ClassVar[int]
    DEMANGLED_FIELD_NUMBER: _ClassVar[int]
    CALL_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    OP_INDEX_FIELD_NUMBER: _ClassVar[int]
    kind: CodeTokenKind
    text: str
    address: _common_pb2.Address
    variable_index: int
    varnode_indices: _containers.RepeatedScalarFieldContainer[int]
    target: _common_pb2.Address
    type_hash: str
    value: int
    parent_type_hash: str
    field_offset: int
    constant_hash: int
    display_set: bool
    demangled: _common_pb2.DemangledName
    call_signature: str
    op_index: int
    def __init__(self, kind: _Optional[_Union[CodeTokenKind, str]] = ..., text: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., variable_index: _Optional[int] = ..., varnode_indices: _Optional[_Iterable[int]] = ..., target: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., type_hash: _Optional[str] = ..., value: _Optional[int] = ..., parent_type_hash: _Optional[str] = ..., field_offset: _Optional[int] = ..., constant_hash: _Optional[int] = ..., display_set: _Optional[bool] = ..., demangled: _Optional[_Union[_common_pb2.DemangledName, _Mapping]] = ..., call_signature: _Optional[str] = ..., op_index: _Optional[int] = ...) -> None: ...

class CodeLine(_message.Message):
    __slots__ = ("indent", "tokens", "address")
    INDENT_FIELD_NUMBER: _ClassVar[int]
    TOKENS_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    indent: int
    tokens: _containers.RepeatedCompositeFieldContainer[CodeToken]
    address: _common_pb2.Address
    def __init__(self, indent: _Optional[int] = ..., tokens: _Optional[_Iterable[_Union[CodeToken, _Mapping]]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ...) -> None: ...

class MappedVarnode(_message.Message):
    __slots__ = ("varnode", "variable_index", "defined_at")
    VARNODE_FIELD_NUMBER: _ClassVar[int]
    VARIABLE_INDEX_FIELD_NUMBER: _ClassVar[int]
    DEFINED_AT_FIELD_NUMBER: _ClassVar[int]
    varnode: _common_pb2.Varnode
    variable_index: int
    defined_at: _common_pb2.Address
    def __init__(self, varnode: _Optional[_Union[_common_pb2.Varnode, _Mapping]] = ..., variable_index: _Optional[int] = ..., defined_at: _Optional[_Union[_common_pb2.Address, _Mapping]] = ...) -> None: ...

class DataFlowNode(_message.Message):
    __slots__ = ("varnode", "constant")
    DEF_FIELD_NUMBER: _ClassVar[int]
    VARNODE_FIELD_NUMBER: _ClassVar[int]
    CONSTANT_FIELD_NUMBER: _ClassVar[int]
    varnode: _common_pb2.Varnode
    constant: bool
    def __init__(self, varnode: _Optional[_Union[_common_pb2.Varnode, _Mapping]] = ..., constant: _Optional[bool] = ..., **kwargs) -> None: ...

class DataFlowOp(_message.Message):
    __slots__ = ("address", "opcode", "output", "inputs")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    OPCODE_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    INPUTS_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    opcode: str
    output: int
    inputs: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., opcode: _Optional[str] = ..., output: _Optional[int] = ..., inputs: _Optional[_Iterable[int]] = ...) -> None: ...

class DataFlow(_message.Message):
    __slots__ = ("nodes", "ops")
    NODES_FIELD_NUMBER: _ClassVar[int]
    OPS_FIELD_NUMBER: _ClassVar[int]
    nodes: _containers.RepeatedCompositeFieldContainer[DataFlowNode]
    ops: _containers.RepeatedCompositeFieldContainer[DataFlowOp]
    def __init__(self, nodes: _Optional[_Iterable[_Union[DataFlowNode, _Mapping]]] = ..., ops: _Optional[_Iterable[_Union[DataFlowOp, _Mapping]]] = ...) -> None: ...

class DecompiledFunction(_message.Message):
    __slots__ = ("entry", "name", "prototype", "variables", "lines", "varnodes", "text", "warnings", "origin", "dataflow", "unknowns")
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROTOTYPE_FIELD_NUMBER: _ClassVar[int]
    VARIABLES_FIELD_NUMBER: _ClassVar[int]
    LINES_FIELD_NUMBER: _ClassVar[int]
    VARNODES_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    DATAFLOW_FIELD_NUMBER: _ClassVar[int]
    UNKNOWNS_FIELD_NUMBER: _ClassVar[int]
    entry: _common_pb2.Address
    name: str
    prototype: FunctionPrototype
    variables: _containers.RepeatedCompositeFieldContainer[Variable]
    lines: _containers.RepeatedCompositeFieldContainer[CodeLine]
    varnodes: _containers.RepeatedCompositeFieldContainer[MappedVarnode]
    text: str
    warnings: _containers.RepeatedScalarFieldContainer[str]
    origin: _common_pb2.Derivation
    dataflow: DataFlow
    unknowns: _containers.RepeatedCompositeFieldContainer[_common_pb2.Unknown]
    def __init__(self, entry: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., name: _Optional[str] = ..., prototype: _Optional[_Union[FunctionPrototype, _Mapping]] = ..., variables: _Optional[_Iterable[_Union[Variable, _Mapping]]] = ..., lines: _Optional[_Iterable[_Union[CodeLine, _Mapping]]] = ..., varnodes: _Optional[_Iterable[_Union[MappedVarnode, _Mapping]]] = ..., text: _Optional[str] = ..., warnings: _Optional[_Iterable[str]] = ..., origin: _Optional[_Union[_common_pb2.Derivation, _Mapping]] = ..., dataflow: _Optional[_Union[DataFlow, _Mapping]] = ..., unknowns: _Optional[_Iterable[_Union[_common_pb2.Unknown, _Mapping]]] = ...) -> None: ...

class DecompileOptions(_message.Message):
    __slots__ = ("include_text", "timeout_ms", "escalate", "include_bundle", "include_dataflow")
    INCLUDE_TEXT_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    ESCALATE_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_BUNDLE_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_DATAFLOW_FIELD_NUMBER: _ClassVar[int]
    include_text: bool
    timeout_ms: int
    escalate: bool
    include_bundle: bool
    include_dataflow: bool
    def __init__(self, include_text: _Optional[bool] = ..., timeout_ms: _Optional[int] = ..., escalate: _Optional[bool] = ..., include_bundle: _Optional[bool] = ..., include_dataflow: _Optional[bool] = ...) -> None: ...

class DecompileFailure(_message.Message):
    __slots__ = ("kind", "bundle_hash", "decompiler_build", "deadline_ms", "stderr_tail", "detail", "can_escalate", "escalated", "bundle")
    KIND_FIELD_NUMBER: _ClassVar[int]
    BUNDLE_HASH_FIELD_NUMBER: _ClassVar[int]
    DECOMPILER_BUILD_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_MS_FIELD_NUMBER: _ClassVar[int]
    STDERR_TAIL_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    CAN_ESCALATE_FIELD_NUMBER: _ClassVar[int]
    ESCALATED_FIELD_NUMBER: _ClassVar[int]
    BUNDLE_FIELD_NUMBER: _ClassVar[int]
    kind: DecompileFailureKind
    bundle_hash: str
    decompiler_build: str
    deadline_ms: int
    stderr_tail: str
    detail: str
    can_escalate: bool
    escalated: bool
    bundle: bytes
    def __init__(self, kind: _Optional[_Union[DecompileFailureKind, str]] = ..., bundle_hash: _Optional[str] = ..., decompiler_build: _Optional[str] = ..., deadline_ms: _Optional[int] = ..., stderr_tail: _Optional[str] = ..., detail: _Optional[str] = ..., can_escalate: _Optional[bool] = ..., escalated: _Optional[bool] = ..., bundle: _Optional[bytes] = ...) -> None: ...
