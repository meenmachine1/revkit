from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ProvenanceKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PROVENANCE_KIND_UNSPECIFIED: _ClassVar[ProvenanceKind]
    PROVENANCE_KIND_USER: _ClassVar[ProvenanceKind]
    PROVENANCE_KIND_IMPORT: _ClassVar[ProvenanceKind]
    PROVENANCE_KIND_AGENT: _ClassVar[ProvenanceKind]
    PROVENANCE_KIND_ANALYSIS: _ClassVar[ProvenanceKind]
    PROVENANCE_KIND_MIGRATION: _ClassVar[ProvenanceKind]
    PROVENANCE_KIND_PLUGIN: _ClassVar[ProvenanceKind]
    PROVENANCE_KIND_SCRIPT: _ClassVar[ProvenanceKind]

class FactKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FACT_KIND_UNSPECIFIED: _ClassVar[FactKind]
    FACT_KIND_NAME: _ClassVar[FactKind]
    FACT_KIND_TYPE: _ClassVar[FactKind]
    FACT_KIND_COMMENT: _ClassVar[FactKind]
    FACT_KIND_FUNCTION_BOUNDS: _ClassVar[FactKind]
    FACT_KIND_FLOW_OVERRIDE: _ClassVar[FactKind]
    FACT_KIND_NOTE: _ClassVar[FactKind]
    FACT_KIND_TYPE_DEF: _ClassVar[FactKind]
    FACT_KIND_MATCH: _ClassVar[FactKind]
    FACT_KIND_PATCH: _ClassVar[FactKind]
    FACT_KIND_MEMORY_REGION: _ClassVar[FactKind]
    FACT_KIND_CODE_UNIT: _ClassVar[FactKind]
    FACT_KIND_MUTABILITY: _ClassVar[FactKind]
    FACT_KIND_EQUATE: _ClassVar[FactKind]
    FACT_KIND_REFERENCE: _ClassVar[FactKind]
    FACT_KIND_REBASE: _ClassVar[FactKind]
    FACT_KIND_CALL_SIGNATURE: _ClassVar[FactKind]
    FACT_KIND_NO_RETURN: _ClassVar[FactKind]
    FACT_KIND_LANGUAGE: _ClassVar[FactKind]
    FACT_KIND_FALLTHROUGH: _ClassVar[FactKind]
    FACT_KIND_REGISTER_VALUE: _ClassVar[FactKind]

class SourceTier(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SOURCE_TIER_UNSPECIFIED: _ClassVar[SourceTier]
    SOURCE_TIER_USER: _ClassVar[SourceTier]
    SOURCE_TIER_DEBUG_INFO: _ClassVar[SourceTier]
    SOURCE_TIER_SYMBOL: _ClassVar[SourceTier]
    SOURCE_TIER_LIBRARY: _ClassVar[SourceTier]
    SOURCE_TIER_AGENT: _ClassVar[SourceTier]
    SOURCE_TIER_INFERRED: _ClassVar[SourceTier]
    SOURCE_TIER_GUESSED: _ClassVar[SourceTier]
    SOURCE_TIER_DEFAULT: _ClassVar[SourceTier]

class UnknownKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNKNOWN_KIND_UNSPECIFIED: _ClassVar[UnknownKind]
    UNKNOWN_KIND_INDIRECT_CALL: _ClassVar[UnknownKind]
    UNKNOWN_KIND_INDIRECT_JUMP: _ClassVar[UnknownKind]
    UNKNOWN_KIND_FLOW_TRUNCATED: _ClassVar[UnknownKind]
    UNKNOWN_KIND_DECOMPILE_FAILED: _ClassVar[UnknownKind]
    UNKNOWN_KIND_ANALYSIS_RUNNING: _ClassVar[UnknownKind]
    UNKNOWN_KIND_BUDGET: _ClassVar[UnknownKind]
    UNKNOWN_KIND_NOT_ANALYZED: _ClassVar[UnknownKind]
PROVENANCE_KIND_UNSPECIFIED: ProvenanceKind
PROVENANCE_KIND_USER: ProvenanceKind
PROVENANCE_KIND_IMPORT: ProvenanceKind
PROVENANCE_KIND_AGENT: ProvenanceKind
PROVENANCE_KIND_ANALYSIS: ProvenanceKind
PROVENANCE_KIND_MIGRATION: ProvenanceKind
PROVENANCE_KIND_PLUGIN: ProvenanceKind
PROVENANCE_KIND_SCRIPT: ProvenanceKind
FACT_KIND_UNSPECIFIED: FactKind
FACT_KIND_NAME: FactKind
FACT_KIND_TYPE: FactKind
FACT_KIND_COMMENT: FactKind
FACT_KIND_FUNCTION_BOUNDS: FactKind
FACT_KIND_FLOW_OVERRIDE: FactKind
FACT_KIND_NOTE: FactKind
FACT_KIND_TYPE_DEF: FactKind
FACT_KIND_MATCH: FactKind
FACT_KIND_PATCH: FactKind
FACT_KIND_MEMORY_REGION: FactKind
FACT_KIND_CODE_UNIT: FactKind
FACT_KIND_MUTABILITY: FactKind
FACT_KIND_EQUATE: FactKind
FACT_KIND_REFERENCE: FactKind
FACT_KIND_REBASE: FactKind
FACT_KIND_CALL_SIGNATURE: FactKind
FACT_KIND_NO_RETURN: FactKind
FACT_KIND_LANGUAGE: FactKind
FACT_KIND_FALLTHROUGH: FactKind
FACT_KIND_REGISTER_VALUE: FactKind
SOURCE_TIER_UNSPECIFIED: SourceTier
SOURCE_TIER_USER: SourceTier
SOURCE_TIER_DEBUG_INFO: SourceTier
SOURCE_TIER_SYMBOL: SourceTier
SOURCE_TIER_LIBRARY: SourceTier
SOURCE_TIER_AGENT: SourceTier
SOURCE_TIER_INFERRED: SourceTier
SOURCE_TIER_GUESSED: SourceTier
SOURCE_TIER_DEFAULT: SourceTier
UNKNOWN_KIND_UNSPECIFIED: UnknownKind
UNKNOWN_KIND_INDIRECT_CALL: UnknownKind
UNKNOWN_KIND_INDIRECT_JUMP: UnknownKind
UNKNOWN_KIND_FLOW_TRUNCATED: UnknownKind
UNKNOWN_KIND_DECOMPILE_FAILED: UnknownKind
UNKNOWN_KIND_ANALYSIS_RUNNING: UnknownKind
UNKNOWN_KIND_BUDGET: UnknownKind
UNKNOWN_KIND_NOT_ANALYZED: UnknownKind

class Address(_message.Message):
    __slots__ = ("space", "offset")
    SPACE_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    space: str
    offset: int
    def __init__(self, space: _Optional[str] = ..., offset: _Optional[int] = ...) -> None: ...

class AddressRange(_message.Message):
    __slots__ = ("first", "last")
    FIRST_FIELD_NUMBER: _ClassVar[int]
    LAST_FIELD_NUMBER: _ClassVar[int]
    first: Address
    last: Address
    def __init__(self, first: _Optional[_Union[Address, _Mapping]] = ..., last: _Optional[_Union[Address, _Mapping]] = ...) -> None: ...

class Varnode(_message.Message):
    __slots__ = ("space", "offset", "size", "register_name")
    SPACE_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    REGISTER_NAME_FIELD_NUMBER: _ClassVar[int]
    space: str
    offset: int
    size: int
    register_name: str
    def __init__(self, space: _Optional[str] = ..., offset: _Optional[int] = ..., size: _Optional[int] = ..., register_name: _Optional[str] = ...) -> None: ...

class ReadOptions(_message.Message):
    __slots__ = ("revision", "min_revision")
    REVISION_FIELD_NUMBER: _ClassVar[int]
    MIN_REVISION_FIELD_NUMBER: _ClassVar[int]
    revision: int
    min_revision: int
    def __init__(self, revision: _Optional[int] = ..., min_revision: _Optional[int] = ...) -> None: ...

class Snapshot(_message.Message):
    __slots__ = ("revision", "head_revision")
    REVISION_FIELD_NUMBER: _ClassVar[int]
    HEAD_REVISION_FIELD_NUMBER: _ClassVar[int]
    revision: int
    head_revision: int
    def __init__(self, revision: _Optional[int] = ..., head_revision: _Optional[int] = ...) -> None: ...

class Provenance(_message.Message):
    __slots__ = ("kind", "id", "version", "session", "reason", "tool", "on_behalf_of")
    KIND_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    SESSION_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    TOOL_FIELD_NUMBER: _ClassVar[int]
    ON_BEHALF_OF_FIELD_NUMBER: _ClassVar[int]
    kind: ProvenanceKind
    id: str
    version: str
    session: str
    reason: str
    tool: str
    on_behalf_of: str
    def __init__(self, kind: _Optional[_Union[ProvenanceKind, str]] = ..., id: _Optional[str] = ..., version: _Optional[str] = ..., session: _Optional[str] = ..., reason: _Optional[str] = ..., tool: _Optional[str] = ..., on_behalf_of: _Optional[str] = ...) -> None: ...

class FactKey(_message.Message):
    __slots__ = ("program_id", "kind", "address", "sub", "project")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SUB_FIELD_NUMBER: _ClassVar[int]
    PROJECT_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    kind: FactKind
    address: Address
    sub: str
    project: bool
    def __init__(self, program_id: _Optional[str] = ..., kind: _Optional[_Union[FactKind, str]] = ..., address: _Optional[_Union[Address, _Mapping]] = ..., sub: _Optional[str] = ..., project: _Optional[bool] = ...) -> None: ...

class Derivation(_message.Message):
    __slots__ = ("rule", "inputs", "inputs_truncated", "confidence", "computed_at_revision")
    RULE_FIELD_NUMBER: _ClassVar[int]
    INPUTS_FIELD_NUMBER: _ClassVar[int]
    INPUTS_TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    COMPUTED_AT_REVISION_FIELD_NUMBER: _ClassVar[int]
    rule: str
    inputs: _containers.RepeatedCompositeFieldContainer[FactKey]
    inputs_truncated: bool
    confidence: float
    computed_at_revision: int
    def __init__(self, rule: _Optional[str] = ..., inputs: _Optional[_Iterable[_Union[FactKey, _Mapping]]] = ..., inputs_truncated: _Optional[bool] = ..., confidence: _Optional[float] = ..., computed_at_revision: _Optional[int] = ...) -> None: ...

class FactOrigin(_message.Message):
    __slots__ = ("asserted", "derived", "tier")
    ASSERTED_FIELD_NUMBER: _ClassVar[int]
    DERIVED_FIELD_NUMBER: _ClassVar[int]
    TIER_FIELD_NUMBER: _ClassVar[int]
    asserted: AssertedBy
    derived: Derivation
    tier: SourceTier
    def __init__(self, asserted: _Optional[_Union[AssertedBy, _Mapping]] = ..., derived: _Optional[_Union[Derivation, _Mapping]] = ..., tier: _Optional[_Union[SourceTier, str]] = ...) -> None: ...

class Unknown(_message.Message):
    __slots__ = ("kind", "address", "detail")
    KIND_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    kind: UnknownKind
    address: Address
    detail: str
    def __init__(self, kind: _Optional[_Union[UnknownKind, str]] = ..., address: _Optional[_Union[Address, _Mapping]] = ..., detail: _Optional[str] = ...) -> None: ...

class AssertedBy(_message.Message):
    __slots__ = ("seq", "provenance", "id")
    SEQ_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    seq: int
    provenance: Provenance
    id: OpId
    def __init__(self, seq: _Optional[int] = ..., provenance: _Optional[_Union[Provenance, _Mapping]] = ..., id: _Optional[_Union[OpId, _Mapping]] = ...) -> None: ...

class OpId(_message.Message):
    __slots__ = ("replica", "counter")
    REPLICA_FIELD_NUMBER: _ClassVar[int]
    COUNTER_FIELD_NUMBER: _ClassVar[int]
    replica: int
    counter: int
    def __init__(self, replica: _Optional[int] = ..., counter: _Optional[int] = ...) -> None: ...

class PageRequest(_message.Message):
    __slots__ = ("page_size", "page_token")
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    page_size: int
    page_token: str
    def __init__(self, page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class PageInfo(_message.Message):
    __slots__ = ("next_page_token", "total_count")
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    TOTAL_COUNT_FIELD_NUMBER: _ClassVar[int]
    next_page_token: str
    total_count: int
    def __init__(self, next_page_token: _Optional[str] = ..., total_count: _Optional[int] = ...) -> None: ...

class DemangledName(_message.Message):
    __slots__ = ("mangled", "full")
    MANGLED_FIELD_NUMBER: _ClassVar[int]
    FULL_FIELD_NUMBER: _ClassVar[int]
    mangled: str
    full: str
    def __init__(self, mangled: _Optional[str] = ..., full: _Optional[str] = ...) -> None: ...
