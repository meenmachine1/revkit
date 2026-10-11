from revkit.v1 import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class TypeKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TYPE_KIND_UNSPECIFIED: _ClassVar[TypeKind]
    TYPE_KIND_VOID: _ClassVar[TypeKind]
    TYPE_KIND_BOOL: _ClassVar[TypeKind]
    TYPE_KIND_INT: _ClassVar[TypeKind]
    TYPE_KIND_UINT: _ClassVar[TypeKind]
    TYPE_KIND_CHAR: _ClassVar[TypeKind]
    TYPE_KIND_FLOAT: _ClassVar[TypeKind]
    TYPE_KIND_POINTER: _ClassVar[TypeKind]
    TYPE_KIND_ARRAY: _ClassVar[TypeKind]
    TYPE_KIND_STRUCT: _ClassVar[TypeKind]
    TYPE_KIND_UNION: _ClassVar[TypeKind]
    TYPE_KIND_ENUM: _ClassVar[TypeKind]
    TYPE_KIND_FUNCTION: _ClassVar[TypeKind]
    TYPE_KIND_TYPEDEF: _ClassVar[TypeKind]
    TYPE_KIND_UNDEFINED: _ClassVar[TypeKind]
    TYPE_KIND_QUALIFIED: _ClassVar[TypeKind]

class IntegerRank(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INTEGER_RANK_UNSPECIFIED: _ClassVar[IntegerRank]
    INTEGER_RANK_CHAR: _ClassVar[IntegerRank]
    INTEGER_RANK_SHORT: _ClassVar[IntegerRank]
    INTEGER_RANK_INT: _ClassVar[IntegerRank]
    INTEGER_RANK_LONG: _ClassVar[IntegerRank]
    INTEGER_RANK_LONG_LONG: _ClassVar[IntegerRank]
    INTEGER_RANK_INT128: _ClassVar[IntegerRank]
    INTEGER_RANK_WCHAR: _ClassVar[IntegerRank]
    INTEGER_RANK_CHAR8: _ClassVar[IntegerRank]
    INTEGER_RANK_CHAR16: _ClassVar[IntegerRank]
    INTEGER_RANK_CHAR32: _ClassVar[IntegerRank]

class FloatKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FLOAT_KIND_UNSPECIFIED: _ClassVar[FloatKind]
    FLOAT_KIND_HALF: _ClassVar[FloatKind]
    FLOAT_KIND_FLOAT: _ClassVar[FloatKind]
    FLOAT_KIND_DOUBLE: _ClassVar[FloatKind]
    FLOAT_KIND_LONG_DOUBLE: _ClassVar[FloatKind]
    FLOAT_KIND_FLOAT128: _ClassVar[FloatKind]

class TypeNodeReference(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TYPE_NODE_REFERENCE_UNSPECIFIED: _ClassVar[TypeNodeReference]
    TYPE_NODE_REFERENCE_LVALUE: _ClassVar[TypeNodeReference]
    TYPE_NODE_REFERENCE_RVALUE: _ClassVar[TypeNodeReference]

class CopyTypesMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    COPY_TYPES_MODE_UNSPECIFIED: _ClassVar[CopyTypesMode]
    COPY_TYPES_MODE_MOVE_TO_PROJECT: _ClassVar[CopyTypesMode]
    COPY_TYPES_MODE_COPY_TO_PROGRAM: _ClassVar[CopyTypesMode]

class TypeArchiveKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TYPE_ARCHIVE_KIND_UNSPECIFIED: _ClassVar[TypeArchiveKind]
    TYPE_ARCHIVE_KIND_SHIPPED: _ClassVar[TypeArchiveKind]
    TYPE_ARCHIVE_KIND_GHIDRA: _ClassVar[TypeArchiveKind]
    TYPE_ARCHIVE_KIND_ATTACHED: _ClassVar[TypeArchiveKind]

class ParseCSeverity(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PARSE_C_SEVERITY_UNSPECIFIED: _ClassVar[ParseCSeverity]
    PARSE_C_SEVERITY_NOTE: _ClassVar[ParseCSeverity]
    PARSE_C_SEVERITY_WARNING: _ClassVar[ParseCSeverity]
    PARSE_C_SEVERITY_ERROR: _ClassVar[ParseCSeverity]

class TypeArchiveScope(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TYPE_ARCHIVE_SCOPE_UNSPECIFIED: _ClassVar[TypeArchiveScope]
    TYPE_ARCHIVE_SCOPE_SELECTED: _ClassVar[TypeArchiveScope]
    TYPE_ARCHIVE_SCOPE_CATEGORY: _ClassVar[TypeArchiveScope]
    TYPE_ARCHIVE_SCOPE_USER: _ClassVar[TypeArchiveScope]
    TYPE_ARCHIVE_SCOPE_ALL: _ClassVar[TypeArchiveScope]

class AutoStructureMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AUTO_STRUCTURE_MODE_UNSPECIFIED: _ClassVar[AutoStructureMode]
    AUTO_STRUCTURE_MODE_CREATE: _ClassVar[AutoStructureMode]
    AUTO_STRUCTURE_MODE_FILL: _ClassVar[AutoStructureMode]

class PointerAccessKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    POINTER_ACCESS_KIND_UNSPECIFIED: _ClassVar[PointerAccessKind]
    POINTER_ACCESS_KIND_LOAD: _ClassVar[PointerAccessKind]
    POINTER_ACCESS_KIND_STORE: _ClassVar[PointerAccessKind]
    POINTER_ACCESS_KIND_PASSED: _ClassVar[PointerAccessKind]

class PointerValueKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    POINTER_VALUE_KIND_UNSPECIFIED: _ClassVar[PointerValueKind]
    POINTER_VALUE_KIND_POINTER: _ClassVar[PointerValueKind]
    POINTER_VALUE_KIND_SIGNED: _ClassVar[PointerValueKind]
    POINTER_VALUE_KIND_UNSIGNED: _ClassVar[PointerValueKind]
    POINTER_VALUE_KIND_FLOAT: _ClassVar[PointerValueKind]
    POINTER_VALUE_KIND_BOOL: _ClassVar[PointerValueKind]

class AutoStructureFieldSource(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AUTO_STRUCTURE_FIELD_SOURCE_UNSPECIFIED: _ClassVar[AutoStructureFieldSource]
    AUTO_STRUCTURE_FIELD_SOURCE_ACCESS: _ClassVar[AutoStructureFieldSource]
    AUTO_STRUCTURE_FIELD_SOURCE_EXISTING: _ClassVar[AutoStructureFieldSource]
    AUTO_STRUCTURE_FIELD_SOURCE_DATA: _ClassVar[AutoStructureFieldSource]
TYPE_KIND_UNSPECIFIED: TypeKind
TYPE_KIND_VOID: TypeKind
TYPE_KIND_BOOL: TypeKind
TYPE_KIND_INT: TypeKind
TYPE_KIND_UINT: TypeKind
TYPE_KIND_CHAR: TypeKind
TYPE_KIND_FLOAT: TypeKind
TYPE_KIND_POINTER: TypeKind
TYPE_KIND_ARRAY: TypeKind
TYPE_KIND_STRUCT: TypeKind
TYPE_KIND_UNION: TypeKind
TYPE_KIND_ENUM: TypeKind
TYPE_KIND_FUNCTION: TypeKind
TYPE_KIND_TYPEDEF: TypeKind
TYPE_KIND_UNDEFINED: TypeKind
TYPE_KIND_QUALIFIED: TypeKind
INTEGER_RANK_UNSPECIFIED: IntegerRank
INTEGER_RANK_CHAR: IntegerRank
INTEGER_RANK_SHORT: IntegerRank
INTEGER_RANK_INT: IntegerRank
INTEGER_RANK_LONG: IntegerRank
INTEGER_RANK_LONG_LONG: IntegerRank
INTEGER_RANK_INT128: IntegerRank
INTEGER_RANK_WCHAR: IntegerRank
INTEGER_RANK_CHAR8: IntegerRank
INTEGER_RANK_CHAR16: IntegerRank
INTEGER_RANK_CHAR32: IntegerRank
FLOAT_KIND_UNSPECIFIED: FloatKind
FLOAT_KIND_HALF: FloatKind
FLOAT_KIND_FLOAT: FloatKind
FLOAT_KIND_DOUBLE: FloatKind
FLOAT_KIND_LONG_DOUBLE: FloatKind
FLOAT_KIND_FLOAT128: FloatKind
TYPE_NODE_REFERENCE_UNSPECIFIED: TypeNodeReference
TYPE_NODE_REFERENCE_LVALUE: TypeNodeReference
TYPE_NODE_REFERENCE_RVALUE: TypeNodeReference
COPY_TYPES_MODE_UNSPECIFIED: CopyTypesMode
COPY_TYPES_MODE_MOVE_TO_PROJECT: CopyTypesMode
COPY_TYPES_MODE_COPY_TO_PROGRAM: CopyTypesMode
TYPE_ARCHIVE_KIND_UNSPECIFIED: TypeArchiveKind
TYPE_ARCHIVE_KIND_SHIPPED: TypeArchiveKind
TYPE_ARCHIVE_KIND_GHIDRA: TypeArchiveKind
TYPE_ARCHIVE_KIND_ATTACHED: TypeArchiveKind
PARSE_C_SEVERITY_UNSPECIFIED: ParseCSeverity
PARSE_C_SEVERITY_NOTE: ParseCSeverity
PARSE_C_SEVERITY_WARNING: ParseCSeverity
PARSE_C_SEVERITY_ERROR: ParseCSeverity
TYPE_ARCHIVE_SCOPE_UNSPECIFIED: TypeArchiveScope
TYPE_ARCHIVE_SCOPE_SELECTED: TypeArchiveScope
TYPE_ARCHIVE_SCOPE_CATEGORY: TypeArchiveScope
TYPE_ARCHIVE_SCOPE_USER: TypeArchiveScope
TYPE_ARCHIVE_SCOPE_ALL: TypeArchiveScope
AUTO_STRUCTURE_MODE_UNSPECIFIED: AutoStructureMode
AUTO_STRUCTURE_MODE_CREATE: AutoStructureMode
AUTO_STRUCTURE_MODE_FILL: AutoStructureMode
POINTER_ACCESS_KIND_UNSPECIFIED: PointerAccessKind
POINTER_ACCESS_KIND_LOAD: PointerAccessKind
POINTER_ACCESS_KIND_STORE: PointerAccessKind
POINTER_ACCESS_KIND_PASSED: PointerAccessKind
POINTER_VALUE_KIND_UNSPECIFIED: PointerValueKind
POINTER_VALUE_KIND_POINTER: PointerValueKind
POINTER_VALUE_KIND_SIGNED: PointerValueKind
POINTER_VALUE_KIND_UNSIGNED: PointerValueKind
POINTER_VALUE_KIND_FLOAT: PointerValueKind
POINTER_VALUE_KIND_BOOL: PointerValueKind
AUTO_STRUCTURE_FIELD_SOURCE_UNSPECIFIED: AutoStructureFieldSource
AUTO_STRUCTURE_FIELD_SOURCE_ACCESS: AutoStructureFieldSource
AUTO_STRUCTURE_FIELD_SOURCE_EXISTING: AutoStructureFieldSource
AUTO_STRUCTURE_FIELD_SOURCE_DATA: AutoStructureFieldSource

class PointerType(_message.Message):
    __slots__ = ("target_hash", "space")
    TARGET_HASH_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    target_hash: str
    space: str
    def __init__(self, target_hash: _Optional[str] = ..., space: _Optional[str] = ...) -> None: ...

class ArrayType(_message.Message):
    __slots__ = ("element_hash", "count")
    ELEMENT_HASH_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    element_hash: str
    count: int
    def __init__(self, element_hash: _Optional[str] = ..., count: _Optional[int] = ...) -> None: ...

class Field(_message.Message):
    __slots__ = ("name", "offset", "type_hash", "bit_offset", "bit_size", "comment")
    NAME_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    TYPE_HASH_FIELD_NUMBER: _ClassVar[int]
    BIT_OFFSET_FIELD_NUMBER: _ClassVar[int]
    BIT_SIZE_FIELD_NUMBER: _ClassVar[int]
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    name: str
    offset: int
    type_hash: str
    bit_offset: int
    bit_size: int
    comment: str
    def __init__(self, name: _Optional[str] = ..., offset: _Optional[int] = ..., type_hash: _Optional[str] = ..., bit_offset: _Optional[int] = ..., bit_size: _Optional[int] = ..., comment: _Optional[str] = ...) -> None: ...

class CompositeType(_message.Message):
    __slots__ = ("fields", "packed")
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    PACKED_FIELD_NUMBER: _ClassVar[int]
    fields: _containers.RepeatedCompositeFieldContainer[Field]
    packed: bool
    def __init__(self, fields: _Optional[_Iterable[_Union[Field, _Mapping]]] = ..., packed: _Optional[bool] = ...) -> None: ...

class EnumValue(_message.Message):
    __slots__ = ("name", "value")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: int
    def __init__(self, name: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...

class EnumType(_message.Message):
    __slots__ = ("values", "underlying_hash")
    VALUES_FIELD_NUMBER: _ClassVar[int]
    UNDERLYING_HASH_FIELD_NUMBER: _ClassVar[int]
    values: _containers.RepeatedCompositeFieldContainer[EnumValue]
    underlying_hash: str
    def __init__(self, values: _Optional[_Iterable[_Union[EnumValue, _Mapping]]] = ..., underlying_hash: _Optional[str] = ...) -> None: ...

class FunctionType(_message.Message):
    __slots__ = ("return_hash", "params", "varargs", "calling_convention", "no_return")
    RETURN_HASH_FIELD_NUMBER: _ClassVar[int]
    PARAMS_FIELD_NUMBER: _ClassVar[int]
    VARARGS_FIELD_NUMBER: _ClassVar[int]
    CALLING_CONVENTION_FIELD_NUMBER: _ClassVar[int]
    NO_RETURN_FIELD_NUMBER: _ClassVar[int]
    return_hash: str
    params: _containers.RepeatedCompositeFieldContainer[FunctionTypeParam]
    varargs: bool
    calling_convention: str
    no_return: bool
    def __init__(self, return_hash: _Optional[str] = ..., params: _Optional[_Iterable[_Union[FunctionTypeParam, _Mapping]]] = ..., varargs: _Optional[bool] = ..., calling_convention: _Optional[str] = ..., no_return: _Optional[bool] = ...) -> None: ...

class FunctionTypeParam(_message.Message):
    __slots__ = ("name", "type_hash")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_HASH_FIELD_NUMBER: _ClassVar[int]
    name: str
    type_hash: str
    def __init__(self, name: _Optional[str] = ..., type_hash: _Optional[str] = ...) -> None: ...

class TypedefType(_message.Message):
    __slots__ = ("target_hash",)
    TARGET_HASH_FIELD_NUMBER: _ClassVar[int]
    target_hash: str
    def __init__(self, target_hash: _Optional[str] = ...) -> None: ...

class QualifiedType(_message.Message):
    __slots__ = ("target_hash", "is_const", "is_volatile", "is_restrict", "is_atomic")
    TARGET_HASH_FIELD_NUMBER: _ClassVar[int]
    IS_CONST_FIELD_NUMBER: _ClassVar[int]
    IS_VOLATILE_FIELD_NUMBER: _ClassVar[int]
    IS_RESTRICT_FIELD_NUMBER: _ClassVar[int]
    IS_ATOMIC_FIELD_NUMBER: _ClassVar[int]
    target_hash: str
    is_const: bool
    is_volatile: bool
    is_restrict: bool
    is_atomic: bool
    def __init__(self, target_hash: _Optional[str] = ..., is_const: _Optional[bool] = ..., is_volatile: _Optional[bool] = ..., is_restrict: _Optional[bool] = ..., is_atomic: _Optional[bool] = ...) -> None: ...

class TypeDefinition(_message.Message):
    __slots__ = ("hash", "name", "kind", "size", "alignment", "display", "c_definition", "pointer", "array", "composite", "enumeration", "function", "typedef_type", "qualified", "origin", "rank", "float_kind", "complete", "superseded", "bound", "is_complex", "reference", "is_class", "category", "project")
    HASH_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    ALIGNMENT_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_FIELD_NUMBER: _ClassVar[int]
    C_DEFINITION_FIELD_NUMBER: _ClassVar[int]
    POINTER_FIELD_NUMBER: _ClassVar[int]
    ARRAY_FIELD_NUMBER: _ClassVar[int]
    COMPOSITE_FIELD_NUMBER: _ClassVar[int]
    ENUMERATION_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    TYPEDEF_TYPE_FIELD_NUMBER: _ClassVar[int]
    QUALIFIED_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    RANK_FIELD_NUMBER: _ClassVar[int]
    FLOAT_KIND_FIELD_NUMBER: _ClassVar[int]
    COMPLETE_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDED_FIELD_NUMBER: _ClassVar[int]
    BOUND_FIELD_NUMBER: _ClassVar[int]
    IS_COMPLEX_FIELD_NUMBER: _ClassVar[int]
    REFERENCE_FIELD_NUMBER: _ClassVar[int]
    IS_CLASS_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    PROJECT_FIELD_NUMBER: _ClassVar[int]
    hash: str
    name: str
    kind: TypeKind
    size: int
    alignment: int
    display: str
    c_definition: str
    pointer: PointerType
    array: ArrayType
    composite: CompositeType
    enumeration: EnumType
    function: FunctionType
    typedef_type: TypedefType
    qualified: QualifiedType
    origin: _common_pb2.FactOrigin
    rank: IntegerRank
    float_kind: FloatKind
    complete: bool
    superseded: bool
    bound: bool
    is_complex: bool
    reference: TypeNodeReference
    is_class: bool
    category: str
    project: bool
    def __init__(self, hash: _Optional[str] = ..., name: _Optional[str] = ..., kind: _Optional[_Union[TypeKind, str]] = ..., size: _Optional[int] = ..., alignment: _Optional[int] = ..., display: _Optional[str] = ..., c_definition: _Optional[str] = ..., pointer: _Optional[_Union[PointerType, _Mapping]] = ..., array: _Optional[_Union[ArrayType, _Mapping]] = ..., composite: _Optional[_Union[CompositeType, _Mapping]] = ..., enumeration: _Optional[_Union[EnumType, _Mapping]] = ..., function: _Optional[_Union[FunctionType, _Mapping]] = ..., typedef_type: _Optional[_Union[TypedefType, _Mapping]] = ..., qualified: _Optional[_Union[QualifiedType, _Mapping]] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., rank: _Optional[_Union[IntegerRank, str]] = ..., float_kind: _Optional[_Union[FloatKind, str]] = ..., complete: _Optional[bool] = ..., superseded: _Optional[bool] = ..., bound: _Optional[bool] = ..., is_complex: _Optional[bool] = ..., reference: _Optional[_Union[TypeNodeReference, str]] = ..., is_class: _Optional[bool] = ..., category: _Optional[str] = ..., project: _Optional[bool] = ...) -> None: ...

class TypeNodeRef(_message.Message):
    __slots__ = ("hash", "assertion_index")
    HASH_FIELD_NUMBER: _ClassVar[int]
    ASSERTION_INDEX_FIELD_NUMBER: _ClassVar[int]
    hash: str
    assertion_index: int
    def __init__(self, hash: _Optional[str] = ..., assertion_index: _Optional[int] = ...) -> None: ...

class TypeNode(_message.Message):
    __slots__ = ("kind", "name", "size", "rank", "is_signed", "float_kind", "target", "count", "fields", "enumerators", "params", "varargs", "calling_convention", "alignment", "packed", "incomplete", "qualifiers", "is_complex", "reference", "is_class")
    KIND_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    RANK_FIELD_NUMBER: _ClassVar[int]
    IS_SIGNED_FIELD_NUMBER: _ClassVar[int]
    FLOAT_KIND_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    ENUMERATORS_FIELD_NUMBER: _ClassVar[int]
    PARAMS_FIELD_NUMBER: _ClassVar[int]
    VARARGS_FIELD_NUMBER: _ClassVar[int]
    CALLING_CONVENTION_FIELD_NUMBER: _ClassVar[int]
    ALIGNMENT_FIELD_NUMBER: _ClassVar[int]
    PACKED_FIELD_NUMBER: _ClassVar[int]
    INCOMPLETE_FIELD_NUMBER: _ClassVar[int]
    QUALIFIERS_FIELD_NUMBER: _ClassVar[int]
    IS_COMPLEX_FIELD_NUMBER: _ClassVar[int]
    REFERENCE_FIELD_NUMBER: _ClassVar[int]
    IS_CLASS_FIELD_NUMBER: _ClassVar[int]
    kind: TypeKind
    name: str
    size: int
    rank: IntegerRank
    is_signed: bool
    float_kind: FloatKind
    target: TypeNodeRef
    count: int
    fields: _containers.RepeatedCompositeFieldContainer[TypeNodeField]
    enumerators: _containers.RepeatedCompositeFieldContainer[EnumValue]
    params: _containers.RepeatedCompositeFieldContainer[TypeNodeParam]
    varargs: bool
    calling_convention: str
    alignment: int
    packed: bool
    incomplete: bool
    qualifiers: QualifiedType
    is_complex: bool
    reference: TypeNodeReference
    is_class: bool
    def __init__(self, kind: _Optional[_Union[TypeKind, str]] = ..., name: _Optional[str] = ..., size: _Optional[int] = ..., rank: _Optional[_Union[IntegerRank, str]] = ..., is_signed: _Optional[bool] = ..., float_kind: _Optional[_Union[FloatKind, str]] = ..., target: _Optional[_Union[TypeNodeRef, _Mapping]] = ..., count: _Optional[int] = ..., fields: _Optional[_Iterable[_Union[TypeNodeField, _Mapping]]] = ..., enumerators: _Optional[_Iterable[_Union[EnumValue, _Mapping]]] = ..., params: _Optional[_Iterable[_Union[TypeNodeParam, _Mapping]]] = ..., varargs: _Optional[bool] = ..., calling_convention: _Optional[str] = ..., alignment: _Optional[int] = ..., packed: _Optional[bool] = ..., incomplete: _Optional[bool] = ..., qualifiers: _Optional[_Union[QualifiedType, _Mapping]] = ..., is_complex: _Optional[bool] = ..., reference: _Optional[_Union[TypeNodeReference, str]] = ..., is_class: _Optional[bool] = ...) -> None: ...

class TypeNodeField(_message.Message):
    __slots__ = ("name", "type", "offset", "bit_offset", "bit_size")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    BIT_OFFSET_FIELD_NUMBER: _ClassVar[int]
    BIT_SIZE_FIELD_NUMBER: _ClassVar[int]
    name: str
    type: TypeNodeRef
    offset: int
    bit_offset: int
    bit_size: int
    def __init__(self, name: _Optional[str] = ..., type: _Optional[_Union[TypeNodeRef, _Mapping]] = ..., offset: _Optional[int] = ..., bit_offset: _Optional[int] = ..., bit_size: _Optional[int] = ...) -> None: ...

class TypeNodeParam(_message.Message):
    __slots__ = ("name", "type")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    name: str
    type: TypeNodeRef
    def __init__(self, name: _Optional[str] = ..., type: _Optional[_Union[TypeNodeRef, _Mapping]] = ...) -> None: ...

class CopyTypesRequest(_message.Message):
    __slots__ = ("program_id", "keys", "mode", "provenance", "expected_head_revision")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    KEYS_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_HEAD_REVISION_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    keys: _containers.RepeatedScalarFieldContainer[str]
    mode: CopyTypesMode
    provenance: _common_pb2.Provenance
    expected_head_revision: int
    def __init__(self, program_id: _Optional[str] = ..., keys: _Optional[_Iterable[str]] = ..., mode: _Optional[_Union[CopyTypesMode, str]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., expected_head_revision: _Optional[int] = ...) -> None: ...

class CopyTypesResponse(_message.Message):
    __slots__ = ("snapshot", "types", "records", "asserted", "retracted", "seqs")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    TYPES_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    ASSERTED_FIELD_NUMBER: _ClassVar[int]
    RETRACTED_FIELD_NUMBER: _ClassVar[int]
    SEQS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    types: _containers.RepeatedCompositeFieldContainer[NamedTypeRef]
    records: int
    asserted: int
    retracted: int
    seqs: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., types: _Optional[_Iterable[_Union[NamedTypeRef, _Mapping]]] = ..., records: _Optional[int] = ..., asserted: _Optional[int] = ..., retracted: _Optional[int] = ..., seqs: _Optional[_Iterable[int]] = ...) -> None: ...

class NamedTypeRef(_message.Message):
    __slots__ = ("key", "hash")
    KEY_FIELD_NUMBER: _ClassVar[int]
    HASH_FIELD_NUMBER: _ClassVar[int]
    key: str
    hash: str
    def __init__(self, key: _Optional[str] = ..., hash: _Optional[str] = ...) -> None: ...

class ListTypeArchivesRequest(_message.Message):
    __slots__ = ("program_id", "read")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ...) -> None: ...

class TypeArchiveInfo(_message.Message):
    __slots__ = ("name", "kind", "enabled", "applies", "functions", "types", "data_model", "origin", "diagnostics", "origin_fact")
    NAME_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    APPLIES_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    TYPES_FIELD_NUMBER: _ClassVar[int]
    DATA_MODEL_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    DIAGNOSTICS_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FACT_FIELD_NUMBER: _ClassVar[int]
    name: str
    kind: TypeArchiveKind
    enabled: bool
    applies: bool
    functions: int
    types: int
    data_model: str
    origin: str
    diagnostics: _containers.RepeatedScalarFieldContainer[str]
    origin_fact: _common_pb2.FactOrigin
    def __init__(self, name: _Optional[str] = ..., kind: _Optional[_Union[TypeArchiveKind, str]] = ..., enabled: _Optional[bool] = ..., applies: _Optional[bool] = ..., functions: _Optional[int] = ..., types: _Optional[int] = ..., data_model: _Optional[str] = ..., origin: _Optional[str] = ..., diagnostics: _Optional[_Iterable[str]] = ..., origin_fact: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ...) -> None: ...

class ListTypeArchivesResponse(_message.Message):
    __slots__ = ("snapshot", "archives")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ARCHIVES_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    archives: _containers.RepeatedCompositeFieldContainer[TypeArchiveInfo]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., archives: _Optional[_Iterable[_Union[TypeArchiveInfo, _Mapping]]] = ...) -> None: ...

class ParseCSource(_message.Message):
    __slots__ = ("text", "path", "name")
    TEXT_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    text: str
    path: str
    name: str
    def __init__(self, text: _Optional[str] = ..., path: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class ParseCOptions(_message.Message):
    __slots__ = ("defines_as_enum", "prototypes", "cplusplus", "include_system")
    DEFINES_AS_ENUM_FIELD_NUMBER: _ClassVar[int]
    PROTOTYPES_FIELD_NUMBER: _ClassVar[int]
    CPLUSPLUS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_SYSTEM_FIELD_NUMBER: _ClassVar[int]
    defines_as_enum: bool
    prototypes: bool
    cplusplus: bool
    include_system: bool
    def __init__(self, defines_as_enum: _Optional[bool] = ..., prototypes: _Optional[bool] = ..., cplusplus: _Optional[bool] = ..., include_system: _Optional[bool] = ...) -> None: ...

class ParseCRequest(_message.Message):
    __slots__ = ("program_id", "sources", "include_dirs", "system_include_dirs", "defines", "undefines", "profile", "options", "read", "archive_sidecar")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    SOURCES_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_DIRS_FIELD_NUMBER: _ClassVar[int]
    SYSTEM_INCLUDE_DIRS_FIELD_NUMBER: _ClassVar[int]
    DEFINES_FIELD_NUMBER: _ClassVar[int]
    UNDEFINES_FIELD_NUMBER: _ClassVar[int]
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    OPTIONS_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    ARCHIVE_SIDECAR_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    sources: _containers.RepeatedCompositeFieldContainer[ParseCSource]
    include_dirs: _containers.RepeatedScalarFieldContainer[str]
    system_include_dirs: _containers.RepeatedScalarFieldContainer[str]
    defines: _containers.RepeatedScalarFieldContainer[str]
    undefines: _containers.RepeatedScalarFieldContainer[str]
    profile: str
    options: ParseCOptions
    read: _common_pb2.ReadOptions
    archive_sidecar: str
    def __init__(self, program_id: _Optional[str] = ..., sources: _Optional[_Iterable[_Union[ParseCSource, _Mapping]]] = ..., include_dirs: _Optional[_Iterable[str]] = ..., system_include_dirs: _Optional[_Iterable[str]] = ..., defines: _Optional[_Iterable[str]] = ..., undefines: _Optional[_Iterable[str]] = ..., profile: _Optional[str] = ..., options: _Optional[_Union[ParseCOptions, _Mapping]] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., archive_sidecar: _Optional[str] = ...) -> None: ...

class ParseCDiagnostic(_message.Message):
    __slots__ = ("file", "line", "column", "severity", "text", "source_line")
    FILE_FIELD_NUMBER: _ClassVar[int]
    LINE_FIELD_NUMBER: _ClassVar[int]
    COLUMN_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    SOURCE_LINE_FIELD_NUMBER: _ClassVar[int]
    file: str
    line: int
    column: int
    severity: ParseCSeverity
    text: str
    source_line: str
    def __init__(self, file: _Optional[str] = ..., line: _Optional[int] = ..., column: _Optional[int] = ..., severity: _Optional[_Union[ParseCSeverity, str]] = ..., text: _Optional[str] = ..., source_line: _Optional[str] = ...) -> None: ...

class ParseCNamedType(_message.Message):
    __slots__ = ("key", "index", "hash", "file", "line", "system", "existing_hash", "c_definition", "category", "existing_category", "existing_library")
    KEY_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    HASH_FIELD_NUMBER: _ClassVar[int]
    FILE_FIELD_NUMBER: _ClassVar[int]
    LINE_FIELD_NUMBER: _ClassVar[int]
    SYSTEM_FIELD_NUMBER: _ClassVar[int]
    EXISTING_HASH_FIELD_NUMBER: _ClassVar[int]
    C_DEFINITION_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    EXISTING_CATEGORY_FIELD_NUMBER: _ClassVar[int]
    EXISTING_LIBRARY_FIELD_NUMBER: _ClassVar[int]
    key: str
    index: int
    hash: str
    file: str
    line: int
    system: bool
    existing_hash: str
    c_definition: str
    category: str
    existing_category: str
    existing_library: bool
    def __init__(self, key: _Optional[str] = ..., index: _Optional[int] = ..., hash: _Optional[str] = ..., file: _Optional[str] = ..., line: _Optional[int] = ..., system: _Optional[bool] = ..., existing_hash: _Optional[str] = ..., c_definition: _Optional[str] = ..., category: _Optional[str] = ..., existing_category: _Optional[str] = ..., existing_library: _Optional[bool] = ...) -> None: ...

class ParseCPrototype(_message.Message):
    __slots__ = ("name", "index", "hash", "declaration", "file", "line", "defined")
    NAME_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    HASH_FIELD_NUMBER: _ClassVar[int]
    DECLARATION_FIELD_NUMBER: _ClassVar[int]
    FILE_FIELD_NUMBER: _ClassVar[int]
    LINE_FIELD_NUMBER: _ClassVar[int]
    DEFINED_FIELD_NUMBER: _ClassVar[int]
    name: str
    index: int
    hash: str
    declaration: str
    file: str
    line: int
    defined: bool
    def __init__(self, name: _Optional[str] = ..., index: _Optional[int] = ..., hash: _Optional[str] = ..., declaration: _Optional[str] = ..., file: _Optional[str] = ..., line: _Optional[int] = ..., defined: _Optional[bool] = ...) -> None: ...

class ParseCConstant(_message.Message):
    __slots__ = ("name", "value", "is_unsigned", "file", "line")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    IS_UNSIGNED_FIELD_NUMBER: _ClassVar[int]
    FILE_FIELD_NUMBER: _ClassVar[int]
    LINE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: int
    is_unsigned: bool
    file: str
    line: int
    def __init__(self, name: _Optional[str] = ..., value: _Optional[int] = ..., is_unsigned: _Optional[bool] = ..., file: _Optional[str] = ..., line: _Optional[int] = ...) -> None: ...

class ParseCConflict(_message.Message):
    __slots__ = ("named_key", "existing_hash", "new_hash", "same_layout")
    NAMED_KEY_FIELD_NUMBER: _ClassVar[int]
    EXISTING_HASH_FIELD_NUMBER: _ClassVar[int]
    NEW_HASH_FIELD_NUMBER: _ClassVar[int]
    SAME_LAYOUT_FIELD_NUMBER: _ClassVar[int]
    named_key: str
    existing_hash: str
    new_hash: str
    same_layout: bool
    def __init__(self, named_key: _Optional[str] = ..., existing_hash: _Optional[str] = ..., new_hash: _Optional[str] = ..., same_layout: _Optional[bool] = ...) -> None: ...

class ParseCResponse(_message.Message):
    __slots__ = ("snapshot", "nodes", "hashes", "named", "constants", "prototypes", "diagnostics", "conflicts", "profile", "profile_notes", "errors", "warnings", "limit_hit", "files", "displays", "archive")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    NODES_FIELD_NUMBER: _ClassVar[int]
    HASHES_FIELD_NUMBER: _ClassVar[int]
    NAMED_FIELD_NUMBER: _ClassVar[int]
    CONSTANTS_FIELD_NUMBER: _ClassVar[int]
    PROTOTYPES_FIELD_NUMBER: _ClassVar[int]
    DIAGNOSTICS_FIELD_NUMBER: _ClassVar[int]
    CONFLICTS_FIELD_NUMBER: _ClassVar[int]
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    PROFILE_NOTES_FIELD_NUMBER: _ClassVar[int]
    ERRORS_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    LIMIT_HIT_FIELD_NUMBER: _ClassVar[int]
    FILES_FIELD_NUMBER: _ClassVar[int]
    DISPLAYS_FIELD_NUMBER: _ClassVar[int]
    ARCHIVE_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    nodes: _containers.RepeatedCompositeFieldContainer[TypeNode]
    hashes: _containers.RepeatedScalarFieldContainer[str]
    named: _containers.RepeatedCompositeFieldContainer[ParseCNamedType]
    constants: _containers.RepeatedCompositeFieldContainer[ParseCConstant]
    prototypes: _containers.RepeatedCompositeFieldContainer[ParseCPrototype]
    diagnostics: _containers.RepeatedCompositeFieldContainer[ParseCDiagnostic]
    conflicts: _containers.RepeatedCompositeFieldContainer[ParseCConflict]
    profile: str
    profile_notes: _containers.RepeatedScalarFieldContainer[str]
    errors: int
    warnings: int
    limit_hit: bool
    files: _containers.RepeatedScalarFieldContainer[str]
    displays: _containers.RepeatedScalarFieldContainer[str]
    archive: ParseCArchiveCheck
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., nodes: _Optional[_Iterable[_Union[TypeNode, _Mapping]]] = ..., hashes: _Optional[_Iterable[str]] = ..., named: _Optional[_Iterable[_Union[ParseCNamedType, _Mapping]]] = ..., constants: _Optional[_Iterable[_Union[ParseCConstant, _Mapping]]] = ..., prototypes: _Optional[_Iterable[_Union[ParseCPrototype, _Mapping]]] = ..., diagnostics: _Optional[_Iterable[_Union[ParseCDiagnostic, _Mapping]]] = ..., conflicts: _Optional[_Iterable[_Union[ParseCConflict, _Mapping]]] = ..., profile: _Optional[str] = ..., profile_notes: _Optional[_Iterable[str]] = ..., errors: _Optional[int] = ..., warnings: _Optional[int] = ..., limit_hit: _Optional[bool] = ..., files: _Optional[_Iterable[str]] = ..., displays: _Optional[_Iterable[str]] = ..., archive: _Optional[_Union[ParseCArchiveCheck, _Mapping]] = ...) -> None: ...

class ParseCArchiveCheck(_message.Message):
    __slots__ = ("name", "origin", "data_model", "types", "verified", "mismatches", "header_changed")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    DATA_MODEL_FIELD_NUMBER: _ClassVar[int]
    TYPES_FIELD_NUMBER: _ClassVar[int]
    VERIFIED_FIELD_NUMBER: _ClassVar[int]
    MISMATCHES_FIELD_NUMBER: _ClassVar[int]
    HEADER_CHANGED_FIELD_NUMBER: _ClassVar[int]
    name: str
    origin: str
    data_model: str
    types: int
    verified: int
    mismatches: _containers.RepeatedCompositeFieldContainer[ParseCArchiveMismatch]
    header_changed: bool
    def __init__(self, name: _Optional[str] = ..., origin: _Optional[str] = ..., data_model: _Optional[str] = ..., types: _Optional[int] = ..., verified: _Optional[int] = ..., mismatches: _Optional[_Iterable[_Union[ParseCArchiveMismatch, _Mapping]]] = ..., header_changed: _Optional[bool] = ...) -> None: ...

class ParseCArchiveMismatch(_message.Message):
    __slots__ = ("key", "expected_hash", "parsed_hash")
    KEY_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_HASH_FIELD_NUMBER: _ClassVar[int]
    PARSED_HASH_FIELD_NUMBER: _ClassVar[int]
    key: str
    expected_hash: str
    parsed_hash: str
    def __init__(self, key: _Optional[str] = ..., expected_hash: _Optional[str] = ..., parsed_hash: _Optional[str] = ...) -> None: ...

class ExportTypeArchiveRequest(_message.Message):
    __slots__ = ("program_id", "scope", "keys", "hashes", "category", "name", "read")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    KEYS_FIELD_NUMBER: _ClassVar[int]
    HASHES_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    scope: TypeArchiveScope
    keys: _containers.RepeatedScalarFieldContainer[str]
    hashes: _containers.RepeatedScalarFieldContainer[str]
    category: str
    name: str
    read: _common_pb2.ReadOptions
    def __init__(self, program_id: _Optional[str] = ..., scope: _Optional[_Union[TypeArchiveScope, str]] = ..., keys: _Optional[_Iterable[str]] = ..., hashes: _Optional[_Iterable[str]] = ..., category: _Optional[str] = ..., name: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ...) -> None: ...

class ExportTypeArchiveResponse(_message.Message):
    __slots__ = ("snapshot", "header", "sidecar", "header_name", "sidecar_name", "archive", "notes", "mismatches")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    SIDECAR_FIELD_NUMBER: _ClassVar[int]
    HEADER_NAME_FIELD_NUMBER: _ClassVar[int]
    SIDECAR_NAME_FIELD_NUMBER: _ClassVar[int]
    ARCHIVE_FIELD_NUMBER: _ClassVar[int]
    NOTES_FIELD_NUMBER: _ClassVar[int]
    MISMATCHES_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    header: str
    sidecar: str
    header_name: str
    sidecar_name: str
    archive: TypeArchiveSidecar
    notes: _containers.RepeatedScalarFieldContainer[str]
    mismatches: int
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., header: _Optional[str] = ..., sidecar: _Optional[str] = ..., header_name: _Optional[str] = ..., sidecar_name: _Optional[str] = ..., archive: _Optional[_Union[TypeArchiveSidecar, _Mapping]] = ..., notes: _Optional[_Iterable[str]] = ..., mismatches: _Optional[int] = ...) -> None: ...

class TypeArchiveSidecar(_message.Message):
    __slots__ = ("format", "version", "name", "header", "header_sha256", "data_model", "provenance", "types")
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    HEADER_SHA256_FIELD_NUMBER: _ClassVar[int]
    DATA_MODEL_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    TYPES_FIELD_NUMBER: _ClassVar[int]
    format: str
    version: int
    name: str
    header: str
    header_sha256: str
    data_model: TypeArchiveDataModel
    provenance: TypeArchiveProvenance
    types: _containers.RepeatedCompositeFieldContainer[TypeArchiveEntry]
    def __init__(self, format: _Optional[str] = ..., version: _Optional[int] = ..., name: _Optional[str] = ..., header: _Optional[str] = ..., header_sha256: _Optional[str] = ..., data_model: _Optional[_Union[TypeArchiveDataModel, _Mapping]] = ..., provenance: _Optional[_Union[TypeArchiveProvenance, _Mapping]] = ..., types: _Optional[_Iterable[_Union[TypeArchiveEntry, _Mapping]]] = ...) -> None: ...

class TypeArchiveDataModel(_message.Message):
    __slots__ = ("profile", "arch", "os", "compiler", "pointer_size", "short_size", "int_size", "long_size", "long_long_size", "float_size", "double_size", "long_double_size", "long_double_align", "wchar_size", "wchar_signed", "char_signed", "big_endian", "has_int128", "size_alignment", "max_alignment", "bitfields", "msvc_enums", "zero_width_bitfield_aligns", "biggest_alignment", "max_vector_alignment", "description")
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    OS_FIELD_NUMBER: _ClassVar[int]
    COMPILER_FIELD_NUMBER: _ClassVar[int]
    POINTER_SIZE_FIELD_NUMBER: _ClassVar[int]
    SHORT_SIZE_FIELD_NUMBER: _ClassVar[int]
    INT_SIZE_FIELD_NUMBER: _ClassVar[int]
    LONG_SIZE_FIELD_NUMBER: _ClassVar[int]
    LONG_LONG_SIZE_FIELD_NUMBER: _ClassVar[int]
    FLOAT_SIZE_FIELD_NUMBER: _ClassVar[int]
    DOUBLE_SIZE_FIELD_NUMBER: _ClassVar[int]
    LONG_DOUBLE_SIZE_FIELD_NUMBER: _ClassVar[int]
    LONG_DOUBLE_ALIGN_FIELD_NUMBER: _ClassVar[int]
    WCHAR_SIZE_FIELD_NUMBER: _ClassVar[int]
    WCHAR_SIGNED_FIELD_NUMBER: _ClassVar[int]
    CHAR_SIGNED_FIELD_NUMBER: _ClassVar[int]
    BIG_ENDIAN_FIELD_NUMBER: _ClassVar[int]
    HAS_INT128_FIELD_NUMBER: _ClassVar[int]
    SIZE_ALIGNMENT_FIELD_NUMBER: _ClassVar[int]
    MAX_ALIGNMENT_FIELD_NUMBER: _ClassVar[int]
    BITFIELDS_FIELD_NUMBER: _ClassVar[int]
    MSVC_ENUMS_FIELD_NUMBER: _ClassVar[int]
    ZERO_WIDTH_BITFIELD_ALIGNS_FIELD_NUMBER: _ClassVar[int]
    BIGGEST_ALIGNMENT_FIELD_NUMBER: _ClassVar[int]
    MAX_VECTOR_ALIGNMENT_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    profile: str
    arch: str
    os: str
    compiler: str
    pointer_size: int
    short_size: int
    int_size: int
    long_size: int
    long_long_size: int
    float_size: int
    double_size: int
    long_double_size: int
    long_double_align: int
    wchar_size: int
    wchar_signed: bool
    char_signed: bool
    big_endian: bool
    has_int128: bool
    size_alignment: _containers.RepeatedScalarFieldContainer[str]
    max_alignment: int
    bitfields: str
    msvc_enums: bool
    zero_width_bitfield_aligns: bool
    biggest_alignment: int
    max_vector_alignment: int
    description: str
    def __init__(self, profile: _Optional[str] = ..., arch: _Optional[str] = ..., os: _Optional[str] = ..., compiler: _Optional[str] = ..., pointer_size: _Optional[int] = ..., short_size: _Optional[int] = ..., int_size: _Optional[int] = ..., long_size: _Optional[int] = ..., long_long_size: _Optional[int] = ..., float_size: _Optional[int] = ..., double_size: _Optional[int] = ..., long_double_size: _Optional[int] = ..., long_double_align: _Optional[int] = ..., wchar_size: _Optional[int] = ..., wchar_signed: _Optional[bool] = ..., char_signed: _Optional[bool] = ..., big_endian: _Optional[bool] = ..., has_int128: _Optional[bool] = ..., size_alignment: _Optional[_Iterable[str]] = ..., max_alignment: _Optional[int] = ..., bitfields: _Optional[str] = ..., msvc_enums: _Optional[bool] = ..., zero_width_bitfield_aligns: _Optional[bool] = ..., biggest_alignment: _Optional[int] = ..., max_vector_alignment: _Optional[int] = ..., description: _Optional[str] = ...) -> None: ...

class TypeArchiveProvenance(_message.Message):
    __slots__ = ("generator", "origin")
    GENERATOR_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    generator: str
    origin: str
    def __init__(self, generator: _Optional[str] = ..., origin: _Optional[str] = ...) -> None: ...

class TypeArchiveEntry(_message.Message):
    __slots__ = ("key", "hash", "size", "line", "category", "form", "source_hash", "noreturn")
    KEY_FIELD_NUMBER: _ClassVar[int]
    HASH_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    LINE_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    FORM_FIELD_NUMBER: _ClassVar[int]
    SOURCE_HASH_FIELD_NUMBER: _ClassVar[int]
    NORETURN_FIELD_NUMBER: _ClassVar[int]
    key: str
    hash: str
    size: int
    line: int
    category: str
    form: str
    source_hash: str
    noreturn: bool
    def __init__(self, key: _Optional[str] = ..., hash: _Optional[str] = ..., size: _Optional[int] = ..., line: _Optional[int] = ..., category: _Optional[str] = ..., form: _Optional[str] = ..., source_hash: _Optional[str] = ..., noreturn: _Optional[bool] = ...) -> None: ...

class AutoStructureVariable(_message.Message):
    __slots__ = ("function", "storage_key")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    STORAGE_KEY_FIELD_NUMBER: _ClassVar[int]
    function: _common_pb2.Address
    storage_key: str
    def __init__(self, function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., storage_key: _Optional[str] = ...) -> None: ...

class AutoStructureRequest(_message.Message):
    __slots__ = ("program_id", "variable", "range", "field", "mode", "call_depth", "name", "read", "edits")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    VARIABLE_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    FIELD_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    CALL_DEPTH_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    EDITS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    variable: AutoStructureVariable
    range: _common_pb2.AddressRange
    field: AutoStructureFieldTarget
    mode: AutoStructureMode
    call_depth: int
    name: str
    read: _common_pb2.ReadOptions
    edits: _containers.RepeatedCompositeFieldContainer[AutoStructureFieldEdit]
    def __init__(self, program_id: _Optional[str] = ..., variable: _Optional[_Union[AutoStructureVariable, _Mapping]] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., field: _Optional[_Union[AutoStructureFieldTarget, _Mapping]] = ..., mode: _Optional[_Union[AutoStructureMode, str]] = ..., call_depth: _Optional[int] = ..., name: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., edits: _Optional[_Iterable[_Union[AutoStructureFieldEdit, _Mapping]]] = ...) -> None: ...

class AutoStructureFieldTarget(_message.Message):
    __slots__ = ("function", "struct_hash", "offset", "base_storage_key")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    STRUCT_HASH_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    BASE_STORAGE_KEY_FIELD_NUMBER: _ClassVar[int]
    function: _common_pb2.Address
    struct_hash: str
    offset: int
    base_storage_key: str
    def __init__(self, function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., struct_hash: _Optional[str] = ..., offset: _Optional[int] = ..., base_storage_key: _Optional[str] = ...) -> None: ...

class AutoStructureFieldEdit(_message.Message):
    __slots__ = ("offset", "name", "type_c", "type_hash", "remove", "add")
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_C_FIELD_NUMBER: _ClassVar[int]
    TYPE_HASH_FIELD_NUMBER: _ClassVar[int]
    REMOVE_FIELD_NUMBER: _ClassVar[int]
    ADD_FIELD_NUMBER: _ClassVar[int]
    offset: int
    name: str
    type_c: str
    type_hash: str
    remove: bool
    add: bool
    def __init__(self, offset: _Optional[int] = ..., name: _Optional[str] = ..., type_c: _Optional[str] = ..., type_hash: _Optional[str] = ..., remove: _Optional[bool] = ..., add: _Optional[bool] = ...) -> None: ...

class AutoStructureFieldError(_message.Message):
    __slots__ = ("offset", "message")
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    offset: int
    message: str
    def __init__(self, offset: _Optional[int] = ..., message: _Optional[str] = ...) -> None: ...

class PointerAccess(_message.Message):
    __slots__ = ("function", "storage_key", "offset", "size", "kind", "value", "address", "callee", "parameter_index", "depth")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    STORAGE_KEY_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    CALLEE_FIELD_NUMBER: _ClassVar[int]
    PARAMETER_INDEX_FIELD_NUMBER: _ClassVar[int]
    DEPTH_FIELD_NUMBER: _ClassVar[int]
    function: _common_pb2.Address
    storage_key: str
    offset: int
    size: int
    kind: PointerAccessKind
    value: PointerValueKind
    address: _common_pb2.Address
    callee: _common_pb2.Address
    parameter_index: int
    depth: int
    def __init__(self, function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., storage_key: _Optional[str] = ..., offset: _Optional[int] = ..., size: _Optional[int] = ..., kind: _Optional[_Union[PointerAccessKind, str]] = ..., value: _Optional[_Union[PointerValueKind, str]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., callee: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., parameter_index: _Optional[int] = ..., depth: _Optional[int] = ...) -> None: ...

class AutoStructureField(_message.Message):
    __slots__ = ("offset", "size", "name", "type_display", "type_hash", "source", "accesses", "truncated", "edited")
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_DISPLAY_FIELD_NUMBER: _ClassVar[int]
    TYPE_HASH_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    ACCESSES_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    EDITED_FIELD_NUMBER: _ClassVar[int]
    offset: int
    size: int
    name: str
    type_display: str
    type_hash: str
    source: AutoStructureFieldSource
    accesses: int
    truncated: bool
    edited: bool
    def __init__(self, offset: _Optional[int] = ..., size: _Optional[int] = ..., name: _Optional[str] = ..., type_display: _Optional[str] = ..., type_hash: _Optional[str] = ..., source: _Optional[_Union[AutoStructureFieldSource, str]] = ..., accesses: _Optional[int] = ..., truncated: _Optional[bool] = ..., edited: _Optional[bool] = ...) -> None: ...

class AutoStructureResponse(_message.Message):
    __slots__ = ("snapshot", "fields", "size", "name", "named_key", "c_definition", "nodes", "hashes", "struct_index", "pointer_index", "struct_hash", "pointer_hash", "existing_hash", "accesses", "functions", "notes", "unchanged", "field_errors", "outer_index", "outer_hash", "outer_named_key")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    NAMED_KEY_FIELD_NUMBER: _ClassVar[int]
    C_DEFINITION_FIELD_NUMBER: _ClassVar[int]
    NODES_FIELD_NUMBER: _ClassVar[int]
    HASHES_FIELD_NUMBER: _ClassVar[int]
    STRUCT_INDEX_FIELD_NUMBER: _ClassVar[int]
    POINTER_INDEX_FIELD_NUMBER: _ClassVar[int]
    STRUCT_HASH_FIELD_NUMBER: _ClassVar[int]
    POINTER_HASH_FIELD_NUMBER: _ClassVar[int]
    EXISTING_HASH_FIELD_NUMBER: _ClassVar[int]
    ACCESSES_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    NOTES_FIELD_NUMBER: _ClassVar[int]
    UNCHANGED_FIELD_NUMBER: _ClassVar[int]
    FIELD_ERRORS_FIELD_NUMBER: _ClassVar[int]
    OUTER_INDEX_FIELD_NUMBER: _ClassVar[int]
    OUTER_HASH_FIELD_NUMBER: _ClassVar[int]
    OUTER_NAMED_KEY_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    fields: _containers.RepeatedCompositeFieldContainer[AutoStructureField]
    size: int
    name: str
    named_key: str
    c_definition: str
    nodes: _containers.RepeatedCompositeFieldContainer[TypeNode]
    hashes: _containers.RepeatedScalarFieldContainer[str]
    struct_index: int
    pointer_index: int
    struct_hash: str
    pointer_hash: str
    existing_hash: str
    accesses: _containers.RepeatedCompositeFieldContainer[PointerAccess]
    functions: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    notes: _containers.RepeatedScalarFieldContainer[str]
    unchanged: bool
    field_errors: _containers.RepeatedCompositeFieldContainer[AutoStructureFieldError]
    outer_index: int
    outer_hash: str
    outer_named_key: str
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., fields: _Optional[_Iterable[_Union[AutoStructureField, _Mapping]]] = ..., size: _Optional[int] = ..., name: _Optional[str] = ..., named_key: _Optional[str] = ..., c_definition: _Optional[str] = ..., nodes: _Optional[_Iterable[_Union[TypeNode, _Mapping]]] = ..., hashes: _Optional[_Iterable[str]] = ..., struct_index: _Optional[int] = ..., pointer_index: _Optional[int] = ..., struct_hash: _Optional[str] = ..., pointer_hash: _Optional[str] = ..., existing_hash: _Optional[str] = ..., accesses: _Optional[_Iterable[_Union[PointerAccess, _Mapping]]] = ..., functions: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., notes: _Optional[_Iterable[str]] = ..., unchanged: _Optional[bool] = ..., field_errors: _Optional[_Iterable[_Union[AutoStructureFieldError, _Mapping]]] = ..., outer_index: _Optional[int] = ..., outer_hash: _Optional[str] = ..., outer_named_key: _Optional[str] = ...) -> None: ...
