from revkit.v1 import analysis_pb2 as _analysis_pb2
from revkit.v1 import assertion_pb2 as _assertion_pb2
from revkit.v1 import common_pb2 as _common_pb2
from revkit.v1 import listing_pb2 as _listing_pb2
from revkit.v1 import presence_pb2 as _presence_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ChangeCause(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CHANGE_CAUSE_UNSPECIFIED: _ClassVar[ChangeCause]
    CHANGE_CAUSE_ASSERTION: _ClassVar[ChangeCause]
    CHANGE_CAUSE_RETRACTION: _ClassVar[ChangeCause]
    CHANGE_CAUSE_IMPORT: _ClassVar[ChangeCause]
    CHANGE_CAUSE_ANALYSIS: _ClassVar[ChangeCause]
    CHANGE_CAUSE_REPLICATION: _ClassVar[ChangeCause]

class QueryKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    QUERY_KIND_UNSPECIFIED: _ClassVar[QueryKind]
    QUERY_KIND_PROGRAM: _ClassVar[QueryKind]
    QUERY_KIND_MEMORY: _ClassVar[QueryKind]
    QUERY_KIND_FUNCTION_LIST: _ClassVar[QueryKind]
    QUERY_KIND_FUNCTION: _ClassVar[QueryKind]
    QUERY_KIND_LISTING: _ClassVar[QueryKind]
    QUERY_KIND_INSTRUCTION: _ClassVar[QueryKind]
    QUERY_KIND_XREFS: _ClassVar[QueryKind]
    QUERY_KIND_DECOMPILE: _ClassVar[QueryKind]
    QUERY_KIND_TYPES: _ClassVar[QueryKind]
    QUERY_KIND_ASSERTIONS: _ClassVar[QueryKind]
    QUERY_KIND_PLUGIN_FACTS: _ClassVar[QueryKind]
    QUERY_KIND_DIFF_SESSION: _ClassVar[QueryKind]
    QUERY_KIND_PATCHES: _ClassVar[QueryKind]
    QUERY_KIND_PROJECT_TREE: _ClassVar[QueryKind]
CHANGE_CAUSE_UNSPECIFIED: ChangeCause
CHANGE_CAUSE_ASSERTION: ChangeCause
CHANGE_CAUSE_RETRACTION: ChangeCause
CHANGE_CAUSE_IMPORT: ChangeCause
CHANGE_CAUSE_ANALYSIS: ChangeCause
CHANGE_CAUSE_REPLICATION: ChangeCause
QUERY_KIND_UNSPECIFIED: QueryKind
QUERY_KIND_PROGRAM: QueryKind
QUERY_KIND_MEMORY: QueryKind
QUERY_KIND_FUNCTION_LIST: QueryKind
QUERY_KIND_FUNCTION: QueryKind
QUERY_KIND_LISTING: QueryKind
QUERY_KIND_INSTRUCTION: QueryKind
QUERY_KIND_XREFS: QueryKind
QUERY_KIND_DECOMPILE: QueryKind
QUERY_KIND_TYPES: QueryKind
QUERY_KIND_ASSERTIONS: QueryKind
QUERY_KIND_PLUGIN_FACTS: QueryKind
QUERY_KIND_DIFF_SESSION: QueryKind
QUERY_KIND_PATCHES: QueryKind
QUERY_KIND_PROJECT_TREE: QueryKind

class SubscribeRequest(_message.Message):
    __slots__ = ("project_id", "program_ids", "from_revision", "include_assertions", "heartbeat_seconds", "include_presence")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_IDS_FIELD_NUMBER: _ClassVar[int]
    FROM_REVISION_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_ASSERTIONS_FIELD_NUMBER: _ClassVar[int]
    HEARTBEAT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_PRESENCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    program_ids: _containers.RepeatedScalarFieldContainer[str]
    from_revision: int
    include_assertions: bool
    heartbeat_seconds: int
    include_presence: bool
    def __init__(self, project_id: _Optional[str] = ..., program_ids: _Optional[_Iterable[str]] = ..., from_revision: _Optional[int] = ..., include_assertions: _Optional[bool] = ..., heartbeat_seconds: _Optional[int] = ..., include_presence: _Optional[bool] = ...) -> None: ...

class SubscribeResponse(_message.Message):
    __slots__ = ("hello", "revision", "heartbeat", "analysis", "presence")
    HELLO_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    HEARTBEAT_FIELD_NUMBER: _ClassVar[int]
    ANALYSIS_FIELD_NUMBER: _ClassVar[int]
    PRESENCE_FIELD_NUMBER: _ClassVar[int]
    hello: Hello
    revision: RevisionEvent
    heartbeat: Heartbeat
    analysis: _analysis_pb2.AnalysisProgress
    presence: _presence_pb2.Presence
    def __init__(self, hello: _Optional[_Union[Hello, _Mapping]] = ..., revision: _Optional[_Union[RevisionEvent, _Mapping]] = ..., heartbeat: _Optional[_Union[Heartbeat, _Mapping]] = ..., analysis: _Optional[_Union[_analysis_pb2.AnalysisProgress, _Mapping]] = ..., presence: _Optional[_Union[_presence_pb2.Presence, _Mapping]] = ...) -> None: ...

class Hello(_message.Message):
    __slots__ = ("head_revision", "resync_required")
    HEAD_REVISION_FIELD_NUMBER: _ClassVar[int]
    RESYNC_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    head_revision: int
    resync_required: bool
    def __init__(self, head_revision: _Optional[int] = ..., resync_required: _Optional[bool] = ...) -> None: ...

class Heartbeat(_message.Message):
    __slots__ = ("head_revision",)
    HEAD_REVISION_FIELD_NUMBER: _ClassVar[int]
    head_revision: int
    def __init__(self, head_revision: _Optional[int] = ...) -> None: ...

class InvalidatedQuery(_message.Message):
    __slots__ = ("program_id", "kind", "address", "range", "rows", "previous_rows", "header_rows", "previous_header_rows", "diff_session_id")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_ROWS_FIELD_NUMBER: _ClassVar[int]
    HEADER_ROWS_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_HEADER_ROWS_FIELD_NUMBER: _ClassVar[int]
    DIFF_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    kind: QueryKind
    address: _common_pb2.Address
    range: _common_pb2.AddressRange
    rows: _listing_pb2.RowWindow
    previous_rows: _listing_pb2.RowWindow
    header_rows: _listing_pb2.RowWindow
    previous_header_rows: _listing_pb2.RowWindow
    diff_session_id: str
    def __init__(self, program_id: _Optional[str] = ..., kind: _Optional[_Union[QueryKind, str]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., rows: _Optional[_Union[_listing_pb2.RowWindow, _Mapping]] = ..., previous_rows: _Optional[_Union[_listing_pb2.RowWindow, _Mapping]] = ..., header_rows: _Optional[_Union[_listing_pb2.RowWindow, _Mapping]] = ..., previous_header_rows: _Optional[_Union[_listing_pb2.RowWindow, _Mapping]] = ..., diff_session_id: _Optional[str] = ...) -> None: ...

class RevisionEvent(_message.Message):
    __slots__ = ("revision", "previous_revision", "cause", "provenance", "assertion_seqs", "assertions", "changed_keys", "invalidated", "invalidate_all_programs")
    REVISION_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_REVISION_FIELD_NUMBER: _ClassVar[int]
    CAUSE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    ASSERTION_SEQS_FIELD_NUMBER: _ClassVar[int]
    ASSERTIONS_FIELD_NUMBER: _ClassVar[int]
    CHANGED_KEYS_FIELD_NUMBER: _ClassVar[int]
    INVALIDATED_FIELD_NUMBER: _ClassVar[int]
    INVALIDATE_ALL_PROGRAMS_FIELD_NUMBER: _ClassVar[int]
    revision: int
    previous_revision: int
    cause: ChangeCause
    provenance: _common_pb2.Provenance
    assertion_seqs: _containers.RepeatedScalarFieldContainer[int]
    assertions: _containers.RepeatedCompositeFieldContainer[_assertion_pb2.Assertion]
    changed_keys: _containers.RepeatedCompositeFieldContainer[_common_pb2.FactKey]
    invalidated: _containers.RepeatedCompositeFieldContainer[InvalidatedQuery]
    invalidate_all_programs: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, revision: _Optional[int] = ..., previous_revision: _Optional[int] = ..., cause: _Optional[_Union[ChangeCause, str]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., assertion_seqs: _Optional[_Iterable[int]] = ..., assertions: _Optional[_Iterable[_Union[_assertion_pb2.Assertion, _Mapping]]] = ..., changed_keys: _Optional[_Iterable[_Union[_common_pb2.FactKey, _Mapping]]] = ..., invalidated: _Optional[_Iterable[_Union[InvalidatedQuery, _Mapping]]] = ..., invalidate_all_programs: _Optional[_Iterable[str]] = ...) -> None: ...
