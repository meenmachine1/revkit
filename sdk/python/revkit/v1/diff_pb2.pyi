import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from revkit.v1 import common_pb2 as _common_pb2
from revkit.v1 import decompile_pb2 as _decompile_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class DiffTier(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DIFF_TIER_UNSPECIFIED: _ClassVar[DiffTier]
    DIFF_TIER_ACCEPTED: _ClassVar[DiffTier]
    DIFF_TIER_NAME: _ClassVar[DiffTier]
    DIFF_TIER_BYTES: _ClassVar[DiffTier]
    DIFF_TIER_PCODE: _ClassVar[DiffTier]
    DIFF_TIER_SHAPE_REFS: _ClassVar[DiffTier]
    DIFF_TIER_SHAPE: _ClassVar[DiffTier]
    DIFF_TIER_REFS: _ClassVar[DiffTier]
    DIFF_TIER_CALL_ORDER: _ClassVar[DiffTier]
    DIFF_TIER_LONE: _ClassVar[DiffTier]
    DIFF_TIER_SIMILARITY: _ClassVar[DiffTier]
    DIFF_TIER_NEIGHBOUR: _ClassVar[DiffTier]

class DiffRelation(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DIFF_RELATION_UNSPECIFIED: _ClassVar[DiffRelation]
    DIFF_RELATION_GLOBAL: _ClassVar[DiffRelation]
    DIFF_RELATION_RESIDUE: _ClassVar[DiffRelation]
    DIFF_RELATION_CALLEE: _ClassVar[DiffRelation]
    DIFF_RELATION_CALLER: _ClassVar[DiffRelation]
    DIFF_RELATION_STRING: _ClassVar[DiffRelation]
    DIFF_RELATION_DATA: _ClassVar[DiffRelation]
    DIFF_RELATION_SEED: _ClassVar[DiffRelation]
    DIFF_RELATION_SIMILAR: _ClassVar[DiffRelation]
    DIFF_RELATION_ADDRESS: _ClassVar[DiffRelation]

class DiffMatchStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DIFF_MATCH_STATUS_UNSPECIFIED: _ClassVar[DiffMatchStatus]
    DIFF_MATCH_STATUS_PROPOSED: _ClassVar[DiffMatchStatus]
    DIFF_MATCH_STATUS_ACCEPTED: _ClassVar[DiffMatchStatus]
    DIFF_MATCH_STATUS_APPLIED: _ClassVar[DiffMatchStatus]

class DiffChangeKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DIFF_CHANGE_KIND_UNSPECIFIED: _ClassVar[DiffChangeKind]
    DIFF_CHANGE_KIND_UNCHANGED: _ClassVar[DiffChangeKind]
    DIFF_CHANGE_KIND_MODIFIED: _ClassVar[DiffChangeKind]
    DIFF_CHANGE_KIND_ADDED: _ClassVar[DiffChangeKind]
    DIFF_CHANGE_KIND_REMOVED: _ClassVar[DiffChangeKind]

class DiffSide(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DIFF_SIDE_UNSPECIFIED: _ClassVar[DiffSide]
    DIFF_SIDE_A: _ClassVar[DiffSide]
    DIFF_SIDE_B: _ClassVar[DiffSide]

class DiffRunState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DIFF_RUN_STATE_UNSPECIFIED: _ClassVar[DiffRunState]
    DIFF_RUN_STATE_IDLE: _ClassVar[DiffRunState]
    DIFF_RUN_STATE_RUNNING: _ClassVar[DiffRunState]
    DIFF_RUN_STATE_SUCCEEDED: _ClassVar[DiffRunState]
    DIFF_RUN_STATE_FAILED: _ClassVar[DiffRunState]
    DIFF_RUN_STATE_CANCELLED: _ClassVar[DiffRunState]

class DiffSort(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DIFF_SORT_UNSPECIFIED: _ClassVar[DiffSort]
    DIFF_SORT_ADDRESS_A: _ClassVar[DiffSort]
    DIFF_SORT_ADDRESS_B: _ClassVar[DiffSort]
    DIFF_SORT_CONFIDENCE: _ClassVar[DiffSort]
    DIFF_SORT_SIMILARITY: _ClassVar[DiffSort]
    DIFF_SORT_NAME_A: _ClassVar[DiffSort]
    DIFF_SORT_NAME_B: _ClassVar[DiffSort]
    DIFF_SORT_TIER: _ClassVar[DiffSort]
    DIFF_SORT_STATUS: _ClassVar[DiffSort]

class DiffUnmatchedReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DIFF_UNMATCHED_REASON_UNSPECIFIED: _ClassVar[DiffUnmatchedReason]
    DIFF_UNMATCHED_REASON_NO_CANDIDATE: _ClassVar[DiffUnmatchedReason]
    DIFF_UNMATCHED_REASON_TIE: _ClassVar[DiffUnmatchedReason]
    DIFF_UNMATCHED_REASON_WEAK: _ClassVar[DiffUnmatchedReason]

class DiffLineStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DIFF_LINE_STATUS_UNSPECIFIED: _ClassVar[DiffLineStatus]
    DIFF_LINE_STATUS_EQUAL: _ClassVar[DiffLineStatus]
    DIFF_LINE_STATUS_CHANGED: _ClassVar[DiffLineStatus]
    DIFF_LINE_STATUS_INSERTED: _ClassVar[DiffLineStatus]
    DIFF_LINE_STATUS_DELETED: _ClassVar[DiffLineStatus]

class DiffBlockStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DIFF_BLOCK_STATUS_UNSPECIFIED: _ClassVar[DiffBlockStatus]
    DIFF_BLOCK_STATUS_UNCHANGED: _ClassVar[DiffBlockStatus]
    DIFF_BLOCK_STATUS_MODIFIED: _ClassVar[DiffBlockStatus]
    DIFF_BLOCK_STATUS_ADDED: _ClassVar[DiffBlockStatus]
    DIFF_BLOCK_STATUS_REMOVED: _ClassVar[DiffBlockStatus]

class DiffReferenceKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DIFF_REFERENCE_KIND_UNSPECIFIED: _ClassVar[DiffReferenceKind]
    DIFF_REFERENCE_KIND_CALL: _ClassVar[DiffReferenceKind]
    DIFF_REFERENCE_KIND_DATA: _ClassVar[DiffReferenceKind]

class DiffMarkupItem(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DIFF_MARKUP_ITEM_UNSPECIFIED: _ClassVar[DiffMarkupItem]
    DIFF_MARKUP_ITEM_NAMES: _ClassVar[DiffMarkupItem]
    DIFF_MARKUP_ITEM_COMMENTS: _ClassVar[DiffMarkupItem]
    DIFF_MARKUP_ITEM_PROTOTYPES: _ClassVar[DiffMarkupItem]

class DiffApplyPolicy(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DIFF_APPLY_POLICY_UNSPECIFIED: _ClassVar[DiffApplyPolicy]
    DIFF_APPLY_POLICY_SAFE: _ClassVar[DiffApplyPolicy]
    DIFF_APPLY_POLICY_ADD: _ClassVar[DiffApplyPolicy]
    DIFF_APPLY_POLICY_REPLACE: _ClassVar[DiffApplyPolicy]

class FunctionMarkupKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FUNCTION_MARKUP_KIND_UNSPECIFIED: _ClassVar[FunctionMarkupKind]
    FUNCTION_MARKUP_KIND_NAME: _ClassVar[FunctionMarkupKind]
    FUNCTION_MARKUP_KIND_SIGNATURE: _ClassVar[FunctionMarkupKind]
    FUNCTION_MARKUP_KIND_VARIABLE_NAME: _ClassVar[FunctionMarkupKind]
    FUNCTION_MARKUP_KIND_VARIABLE_TYPE: _ClassVar[FunctionMarkupKind]
    FUNCTION_MARKUP_KIND_COMMENT: _ClassVar[FunctionMarkupKind]
    FUNCTION_MARKUP_KIND_GLOBAL_NAME: _ClassVar[FunctionMarkupKind]
    FUNCTION_MARKUP_KIND_GLOBAL_TYPE: _ClassVar[FunctionMarkupKind]
    FUNCTION_MARKUP_KIND_CALLEE_NAME: _ClassVar[FunctionMarkupKind]
    FUNCTION_MARKUP_KIND_CALLEE_SIGNATURE: _ClassVar[FunctionMarkupKind]
DIFF_TIER_UNSPECIFIED: DiffTier
DIFF_TIER_ACCEPTED: DiffTier
DIFF_TIER_NAME: DiffTier
DIFF_TIER_BYTES: DiffTier
DIFF_TIER_PCODE: DiffTier
DIFF_TIER_SHAPE_REFS: DiffTier
DIFF_TIER_SHAPE: DiffTier
DIFF_TIER_REFS: DiffTier
DIFF_TIER_CALL_ORDER: DiffTier
DIFF_TIER_LONE: DiffTier
DIFF_TIER_SIMILARITY: DiffTier
DIFF_TIER_NEIGHBOUR: DiffTier
DIFF_RELATION_UNSPECIFIED: DiffRelation
DIFF_RELATION_GLOBAL: DiffRelation
DIFF_RELATION_RESIDUE: DiffRelation
DIFF_RELATION_CALLEE: DiffRelation
DIFF_RELATION_CALLER: DiffRelation
DIFF_RELATION_STRING: DiffRelation
DIFF_RELATION_DATA: DiffRelation
DIFF_RELATION_SEED: DiffRelation
DIFF_RELATION_SIMILAR: DiffRelation
DIFF_RELATION_ADDRESS: DiffRelation
DIFF_MATCH_STATUS_UNSPECIFIED: DiffMatchStatus
DIFF_MATCH_STATUS_PROPOSED: DiffMatchStatus
DIFF_MATCH_STATUS_ACCEPTED: DiffMatchStatus
DIFF_MATCH_STATUS_APPLIED: DiffMatchStatus
DIFF_CHANGE_KIND_UNSPECIFIED: DiffChangeKind
DIFF_CHANGE_KIND_UNCHANGED: DiffChangeKind
DIFF_CHANGE_KIND_MODIFIED: DiffChangeKind
DIFF_CHANGE_KIND_ADDED: DiffChangeKind
DIFF_CHANGE_KIND_REMOVED: DiffChangeKind
DIFF_SIDE_UNSPECIFIED: DiffSide
DIFF_SIDE_A: DiffSide
DIFF_SIDE_B: DiffSide
DIFF_RUN_STATE_UNSPECIFIED: DiffRunState
DIFF_RUN_STATE_IDLE: DiffRunState
DIFF_RUN_STATE_RUNNING: DiffRunState
DIFF_RUN_STATE_SUCCEEDED: DiffRunState
DIFF_RUN_STATE_FAILED: DiffRunState
DIFF_RUN_STATE_CANCELLED: DiffRunState
DIFF_SORT_UNSPECIFIED: DiffSort
DIFF_SORT_ADDRESS_A: DiffSort
DIFF_SORT_ADDRESS_B: DiffSort
DIFF_SORT_CONFIDENCE: DiffSort
DIFF_SORT_SIMILARITY: DiffSort
DIFF_SORT_NAME_A: DiffSort
DIFF_SORT_NAME_B: DiffSort
DIFF_SORT_TIER: DiffSort
DIFF_SORT_STATUS: DiffSort
DIFF_UNMATCHED_REASON_UNSPECIFIED: DiffUnmatchedReason
DIFF_UNMATCHED_REASON_NO_CANDIDATE: DiffUnmatchedReason
DIFF_UNMATCHED_REASON_TIE: DiffUnmatchedReason
DIFF_UNMATCHED_REASON_WEAK: DiffUnmatchedReason
DIFF_LINE_STATUS_UNSPECIFIED: DiffLineStatus
DIFF_LINE_STATUS_EQUAL: DiffLineStatus
DIFF_LINE_STATUS_CHANGED: DiffLineStatus
DIFF_LINE_STATUS_INSERTED: DiffLineStatus
DIFF_LINE_STATUS_DELETED: DiffLineStatus
DIFF_BLOCK_STATUS_UNSPECIFIED: DiffBlockStatus
DIFF_BLOCK_STATUS_UNCHANGED: DiffBlockStatus
DIFF_BLOCK_STATUS_MODIFIED: DiffBlockStatus
DIFF_BLOCK_STATUS_ADDED: DiffBlockStatus
DIFF_BLOCK_STATUS_REMOVED: DiffBlockStatus
DIFF_REFERENCE_KIND_UNSPECIFIED: DiffReferenceKind
DIFF_REFERENCE_KIND_CALL: DiffReferenceKind
DIFF_REFERENCE_KIND_DATA: DiffReferenceKind
DIFF_MARKUP_ITEM_UNSPECIFIED: DiffMarkupItem
DIFF_MARKUP_ITEM_NAMES: DiffMarkupItem
DIFF_MARKUP_ITEM_COMMENTS: DiffMarkupItem
DIFF_MARKUP_ITEM_PROTOTYPES: DiffMarkupItem
DIFF_APPLY_POLICY_UNSPECIFIED: DiffApplyPolicy
DIFF_APPLY_POLICY_SAFE: DiffApplyPolicy
DIFF_APPLY_POLICY_ADD: DiffApplyPolicy
DIFF_APPLY_POLICY_REPLACE: DiffApplyPolicy
FUNCTION_MARKUP_KIND_UNSPECIFIED: FunctionMarkupKind
FUNCTION_MARKUP_KIND_NAME: FunctionMarkupKind
FUNCTION_MARKUP_KIND_SIGNATURE: FunctionMarkupKind
FUNCTION_MARKUP_KIND_VARIABLE_NAME: FunctionMarkupKind
FUNCTION_MARKUP_KIND_VARIABLE_TYPE: FunctionMarkupKind
FUNCTION_MARKUP_KIND_COMMENT: FunctionMarkupKind
FUNCTION_MARKUP_KIND_GLOBAL_NAME: FunctionMarkupKind
FUNCTION_MARKUP_KIND_GLOBAL_TYPE: FunctionMarkupKind
FUNCTION_MARKUP_KIND_CALLEE_NAME: FunctionMarkupKind
FUNCTION_MARKUP_KIND_CALLEE_SIGNATURE: FunctionMarkupKind

class DiffOptions(_message.Message):
    __slots__ = ("similarity_tiers",)
    SIMILARITY_TIERS_FIELD_NUMBER: _ClassVar[int]
    similarity_tiers: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, similarity_tiers: _Optional[_Iterable[str]] = ...) -> None: ...

class DiffCounts(_message.Message):
    __slots__ = ("functions_a", "functions_b", "matched", "accepted", "applied", "auto_matches", "unchanged", "unmatched_a", "unmatched_b", "rounds")
    FUNCTIONS_A_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_B_FIELD_NUMBER: _ClassVar[int]
    MATCHED_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_FIELD_NUMBER: _ClassVar[int]
    APPLIED_FIELD_NUMBER: _ClassVar[int]
    AUTO_MATCHES_FIELD_NUMBER: _ClassVar[int]
    UNCHANGED_FIELD_NUMBER: _ClassVar[int]
    UNMATCHED_A_FIELD_NUMBER: _ClassVar[int]
    UNMATCHED_B_FIELD_NUMBER: _ClassVar[int]
    ROUNDS_FIELD_NUMBER: _ClassVar[int]
    functions_a: int
    functions_b: int
    matched: int
    accepted: int
    applied: int
    auto_matches: int
    unchanged: int
    unmatched_a: int
    unmatched_b: int
    rounds: int
    def __init__(self, functions_a: _Optional[int] = ..., functions_b: _Optional[int] = ..., matched: _Optional[int] = ..., accepted: _Optional[int] = ..., applied: _Optional[int] = ..., auto_matches: _Optional[int] = ..., unchanged: _Optional[int] = ..., unmatched_a: _Optional[int] = ..., unmatched_b: _Optional[int] = ..., rounds: _Optional[int] = ...) -> None: ...

class DiffRun(_message.Message):
    __slots__ = ("state", "phase", "progress", "started_at", "finished_at", "revision", "message", "features_ms", "match_ms")
    STATE_FIELD_NUMBER: _ClassVar[int]
    PHASE_FIELD_NUMBER: _ClassVar[int]
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    STARTED_AT_FIELD_NUMBER: _ClassVar[int]
    FINISHED_AT_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    FEATURES_MS_FIELD_NUMBER: _ClassVar[int]
    MATCH_MS_FIELD_NUMBER: _ClassVar[int]
    state: DiffRunState
    phase: str
    progress: float
    started_at: _timestamp_pb2.Timestamp
    finished_at: _timestamp_pb2.Timestamp
    revision: int
    message: str
    features_ms: float
    match_ms: float
    def __init__(self, state: _Optional[_Union[DiffRunState, str]] = ..., phase: _Optional[str] = ..., progress: _Optional[float] = ..., started_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., finished_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., revision: _Optional[int] = ..., message: _Optional[str] = ..., features_ms: _Optional[float] = ..., match_ms: _Optional[float] = ...) -> None: ...

class DiffSessionInfo(_message.Message):
    __slots__ = ("session_id", "project_id", "program_a", "program_b", "name", "options", "created_at", "created_by", "run")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_A_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_B_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    OPTIONS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    CREATED_BY_FIELD_NUMBER: _ClassVar[int]
    RUN_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    project_id: str
    program_a: str
    program_b: str
    name: str
    options: DiffOptions
    created_at: _timestamp_pb2.Timestamp
    created_by: _common_pb2.Provenance
    run: DiffRun
    def __init__(self, session_id: _Optional[str] = ..., project_id: _Optional[str] = ..., program_a: _Optional[str] = ..., program_b: _Optional[str] = ..., name: _Optional[str] = ..., options: _Optional[_Union[DiffOptions, _Mapping]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., created_by: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., run: _Optional[_Union[DiffRun, _Mapping]] = ...) -> None: ...

class CreateDiffSessionRequest(_message.Message):
    __slots__ = ("project_id", "program_a", "program_b", "name", "options", "provenance", "run")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_A_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_B_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    OPTIONS_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    RUN_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    program_a: str
    program_b: str
    name: str
    options: DiffOptions
    provenance: _common_pb2.Provenance
    run: bool
    def __init__(self, project_id: _Optional[str] = ..., program_a: _Optional[str] = ..., program_b: _Optional[str] = ..., name: _Optional[str] = ..., options: _Optional[_Union[DiffOptions, _Mapping]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., run: _Optional[bool] = ...) -> None: ...

class CreateDiffSessionResponse(_message.Message):
    __slots__ = ("snapshot", "session")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    SESSION_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    session: DiffSessionInfo
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., session: _Optional[_Union[DiffSessionInfo, _Mapping]] = ...) -> None: ...

class ListDiffSessionsRequest(_message.Message):
    __slots__ = ("project_id", "read", "program_id")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    read: _common_pb2.ReadOptions
    program_id: str
    def __init__(self, project_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., program_id: _Optional[str] = ...) -> None: ...

class ListDiffSessionsResponse(_message.Message):
    __slots__ = ("snapshot", "sessions")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    SESSIONS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    sessions: _containers.RepeatedCompositeFieldContainer[DiffSessionInfo]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., sessions: _Optional[_Iterable[_Union[DiffSessionInfo, _Mapping]]] = ...) -> None: ...

class RunDiffRequest(_message.Message):
    __slots__ = ("project_id", "session_id")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    session_id: str
    def __init__(self, project_id: _Optional[str] = ..., session_id: _Optional[str] = ...) -> None: ...

class RunDiffResponse(_message.Message):
    __slots__ = ("run",)
    RUN_FIELD_NUMBER: _ClassVar[int]
    run: DiffRun
    def __init__(self, run: _Optional[_Union[DiffRun, _Mapping]] = ...) -> None: ...

class GetDiffStatusRequest(_message.Message):
    __slots__ = ("project_id", "session_id")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    session_id: str
    def __init__(self, project_id: _Optional[str] = ..., session_id: _Optional[str] = ...) -> None: ...

class GetDiffStatusResponse(_message.Message):
    __slots__ = ("session", "counts")
    SESSION_FIELD_NUMBER: _ClassVar[int]
    COUNTS_FIELD_NUMBER: _ClassVar[int]
    session: DiffSessionInfo
    counts: DiffCounts
    def __init__(self, session: _Optional[_Union[DiffSessionInfo, _Mapping]] = ..., counts: _Optional[_Union[DiffCounts, _Mapping]] = ...) -> None: ...

class CancelDiffRequest(_message.Message):
    __slots__ = ("project_id", "session_id")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    session_id: str
    def __init__(self, project_id: _Optional[str] = ..., session_id: _Optional[str] = ...) -> None: ...

class CancelDiffResponse(_message.Message):
    __slots__ = ("run",)
    RUN_FIELD_NUMBER: _ClassVar[int]
    run: DiffRun
    def __init__(self, run: _Optional[_Union[DiffRun, _Mapping]] = ...) -> None: ...

class DiffEvidence(_message.Message):
    __slots__ = ("tier", "relation", "parent_a", "parent_b", "round", "group", "detail")
    TIER_FIELD_NUMBER: _ClassVar[int]
    RELATION_FIELD_NUMBER: _ClassVar[int]
    PARENT_A_FIELD_NUMBER: _ClassVar[int]
    PARENT_B_FIELD_NUMBER: _ClassVar[int]
    ROUND_FIELD_NUMBER: _ClassVar[int]
    GROUP_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    tier: DiffTier
    relation: DiffRelation
    parent_a: _common_pb2.Address
    parent_b: _common_pb2.Address
    round: int
    group: int
    detail: str
    def __init__(self, tier: _Optional[_Union[DiffTier, str]] = ..., relation: _Optional[_Union[DiffRelation, str]] = ..., parent_a: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., parent_b: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., round: _Optional[int] = ..., group: _Optional[int] = ..., detail: _Optional[str] = ...) -> None: ...

class DiffFunctionRef(_message.Message):
    __slots__ = ("entry", "name", "default_name", "instructions", "blocks")
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_NAME_FIELD_NUMBER: _ClassVar[int]
    INSTRUCTIONS_FIELD_NUMBER: _ClassVar[int]
    BLOCKS_FIELD_NUMBER: _ClassVar[int]
    entry: _common_pb2.Address
    name: str
    default_name: bool
    instructions: int
    blocks: int
    def __init__(self, entry: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., name: _Optional[str] = ..., default_name: _Optional[bool] = ..., instructions: _Optional[int] = ..., blocks: _Optional[int] = ...) -> None: ...

class DiffMatch(_message.Message):
    __slots__ = ("a", "b", "tier", "confidence", "similarity", "status", "change_kind", "evidence", "match_seq")
    A_FIELD_NUMBER: _ClassVar[int]
    B_FIELD_NUMBER: _ClassVar[int]
    TIER_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    SIMILARITY_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    CHANGE_KIND_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    MATCH_SEQ_FIELD_NUMBER: _ClassVar[int]
    a: DiffFunctionRef
    b: DiffFunctionRef
    tier: DiffTier
    confidence: float
    similarity: float
    status: DiffMatchStatus
    change_kind: DiffChangeKind
    evidence: DiffEvidence
    match_seq: int
    def __init__(self, a: _Optional[_Union[DiffFunctionRef, _Mapping]] = ..., b: _Optional[_Union[DiffFunctionRef, _Mapping]] = ..., tier: _Optional[_Union[DiffTier, str]] = ..., confidence: _Optional[float] = ..., similarity: _Optional[float] = ..., status: _Optional[_Union[DiffMatchStatus, str]] = ..., change_kind: _Optional[_Union[DiffChangeKind, str]] = ..., evidence: _Optional[_Union[DiffEvidence, _Mapping]] = ..., match_seq: _Optional[int] = ...) -> None: ...

class DiffMatchFilter(_message.Message):
    __slots__ = ("tiers", "min_confidence", "max_confidence", "statuses", "change_kinds", "name_contains")
    TIERS_FIELD_NUMBER: _ClassVar[int]
    MIN_CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    MAX_CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    STATUSES_FIELD_NUMBER: _ClassVar[int]
    CHANGE_KINDS_FIELD_NUMBER: _ClassVar[int]
    NAME_CONTAINS_FIELD_NUMBER: _ClassVar[int]
    tiers: _containers.RepeatedScalarFieldContainer[DiffTier]
    min_confidence: float
    max_confidence: float
    statuses: _containers.RepeatedScalarFieldContainer[DiffMatchStatus]
    change_kinds: _containers.RepeatedScalarFieldContainer[DiffChangeKind]
    name_contains: str
    def __init__(self, tiers: _Optional[_Iterable[_Union[DiffTier, str]]] = ..., min_confidence: _Optional[float] = ..., max_confidence: _Optional[float] = ..., statuses: _Optional[_Iterable[_Union[DiffMatchStatus, str]]] = ..., change_kinds: _Optional[_Iterable[_Union[DiffChangeKind, str]]] = ..., name_contains: _Optional[str] = ...) -> None: ...

class ListMatchesRequest(_message.Message):
    __slots__ = ("project_id", "session_id", "read", "filter", "sort", "descending", "page", "offset")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    FILTER_FIELD_NUMBER: _ClassVar[int]
    SORT_FIELD_NUMBER: _ClassVar[int]
    DESCENDING_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    session_id: str
    read: _common_pb2.ReadOptions
    filter: DiffMatchFilter
    sort: DiffSort
    descending: bool
    page: _common_pb2.PageRequest
    offset: int
    def __init__(self, project_id: _Optional[str] = ..., session_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., filter: _Optional[_Union[DiffMatchFilter, _Mapping]] = ..., sort: _Optional[_Union[DiffSort, str]] = ..., descending: _Optional[bool] = ..., page: _Optional[_Union[_common_pb2.PageRequest, _Mapping]] = ..., offset: _Optional[int] = ...) -> None: ...

class ListMatchesResponse(_message.Message):
    __slots__ = ("snapshot", "matches", "page", "counts")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    MATCHES_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    COUNTS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    matches: _containers.RepeatedCompositeFieldContainer[DiffMatch]
    page: _common_pb2.PageInfo
    counts: DiffCounts
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., matches: _Optional[_Iterable[_Union[DiffMatch, _Mapping]]] = ..., page: _Optional[_Union[_common_pb2.PageInfo, _Mapping]] = ..., counts: _Optional[_Union[DiffCounts, _Mapping]] = ...) -> None: ...

class DiffCandidate(_message.Message):
    __slots__ = ("function", "tier", "score", "matched")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    TIER_FIELD_NUMBER: _ClassVar[int]
    SCORE_FIELD_NUMBER: _ClassVar[int]
    MATCHED_FIELD_NUMBER: _ClassVar[int]
    function: DiffFunctionRef
    tier: DiffTier
    score: float
    matched: bool
    def __init__(self, function: _Optional[_Union[DiffFunctionRef, _Mapping]] = ..., tier: _Optional[_Union[DiffTier, str]] = ..., score: _Optional[float] = ..., matched: _Optional[bool] = ...) -> None: ...

class DiffUnmatched(_message.Message):
    __slots__ = ("function", "side", "reason", "candidates")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    SIDE_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    CANDIDATES_FIELD_NUMBER: _ClassVar[int]
    function: DiffFunctionRef
    side: DiffSide
    reason: DiffUnmatchedReason
    candidates: _containers.RepeatedCompositeFieldContainer[DiffCandidate]
    def __init__(self, function: _Optional[_Union[DiffFunctionRef, _Mapping]] = ..., side: _Optional[_Union[DiffSide, str]] = ..., reason: _Optional[_Union[DiffUnmatchedReason, str]] = ..., candidates: _Optional[_Iterable[_Union[DiffCandidate, _Mapping]]] = ...) -> None: ...

class ListUnmatchedRequest(_message.Message):
    __slots__ = ("project_id", "session_id", "read", "side", "name_contains", "page", "offset", "max_candidates")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    SIDE_FIELD_NUMBER: _ClassVar[int]
    NAME_CONTAINS_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    MAX_CANDIDATES_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    session_id: str
    read: _common_pb2.ReadOptions
    side: DiffSide
    name_contains: str
    page: _common_pb2.PageRequest
    offset: int
    max_candidates: int
    def __init__(self, project_id: _Optional[str] = ..., session_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., side: _Optional[_Union[DiffSide, str]] = ..., name_contains: _Optional[str] = ..., page: _Optional[_Union[_common_pb2.PageRequest, _Mapping]] = ..., offset: _Optional[int] = ..., max_candidates: _Optional[int] = ...) -> None: ...

class ListUnmatchedResponse(_message.Message):
    __slots__ = ("snapshot", "functions", "page")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    functions: _containers.RepeatedCompositeFieldContainer[DiffUnmatched]
    page: _common_pb2.PageInfo
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., functions: _Optional[_Iterable[_Union[DiffUnmatched, _Mapping]]] = ..., page: _Optional[_Union[_common_pb2.PageInfo, _Mapping]] = ...) -> None: ...

class GetFunctionDiffRequest(_message.Message):
    __slots__ = ("project_id", "session_id", "read", "entry_a", "entry_b", "detail", "omit_bytes")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    ENTRY_A_FIELD_NUMBER: _ClassVar[int]
    ENTRY_B_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    OMIT_BYTES_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    session_id: str
    read: _common_pb2.ReadOptions
    entry_a: _common_pb2.Address
    entry_b: _common_pb2.Address
    detail: bool
    omit_bytes: bool
    def __init__(self, project_id: _Optional[str] = ..., session_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., entry_a: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., entry_b: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., detail: _Optional[bool] = ..., omit_bytes: _Optional[bool] = ...) -> None: ...

class DiffFunctionSummary(_message.Message):
    __slots__ = ("function", "edges", "loops", "pcode_ops", "callees", "callers", "bytes_hash", "pcode_hash", "shape_hash", "refs_hash", "prototype")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    EDGES_FIELD_NUMBER: _ClassVar[int]
    LOOPS_FIELD_NUMBER: _ClassVar[int]
    PCODE_OPS_FIELD_NUMBER: _ClassVar[int]
    CALLEES_FIELD_NUMBER: _ClassVar[int]
    CALLERS_FIELD_NUMBER: _ClassVar[int]
    BYTES_HASH_FIELD_NUMBER: _ClassVar[int]
    PCODE_HASH_FIELD_NUMBER: _ClassVar[int]
    SHAPE_HASH_FIELD_NUMBER: _ClassVar[int]
    REFS_HASH_FIELD_NUMBER: _ClassVar[int]
    PROTOTYPE_FIELD_NUMBER: _ClassVar[int]
    function: DiffFunctionRef
    edges: int
    loops: int
    pcode_ops: int
    callees: _containers.RepeatedCompositeFieldContainer[DiffFunctionRef]
    callers: int
    bytes_hash: str
    pcode_hash: str
    shape_hash: str
    refs_hash: str
    prototype: str
    def __init__(self, function: _Optional[_Union[DiffFunctionRef, _Mapping]] = ..., edges: _Optional[int] = ..., loops: _Optional[int] = ..., pcode_ops: _Optional[int] = ..., callees: _Optional[_Iterable[_Union[DiffFunctionRef, _Mapping]]] = ..., callers: _Optional[int] = ..., bytes_hash: _Optional[str] = ..., pcode_hash: _Optional[str] = ..., shape_hash: _Optional[str] = ..., refs_hash: _Optional[str] = ..., prototype: _Optional[str] = ...) -> None: ...

class GetFunctionDiffResponse(_message.Message):
    __slots__ = ("snapshot", "a", "b", "match", "candidates", "detail")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    A_FIELD_NUMBER: _ClassVar[int]
    B_FIELD_NUMBER: _ClassVar[int]
    MATCH_FIELD_NUMBER: _ClassVar[int]
    CANDIDATES_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    a: DiffFunctionSummary
    b: DiffFunctionSummary
    match: DiffMatch
    candidates: _containers.RepeatedCompositeFieldContainer[DiffCandidate]
    detail: DiffDetail
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., a: _Optional[_Union[DiffFunctionSummary, _Mapping]] = ..., b: _Optional[_Union[DiffFunctionSummary, _Mapping]] = ..., match: _Optional[_Union[DiffMatch, _Mapping]] = ..., candidates: _Optional[_Iterable[_Union[DiffCandidate, _Mapping]]] = ..., detail: _Optional[_Union[DiffDetail, _Mapping]] = ...) -> None: ...

class DiffBlock(_message.Message):
    __slots__ = ("range", "status", "partner", "first_row", "rows", "successors")
    RANGE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PARTNER_FIELD_NUMBER: _ClassVar[int]
    FIRST_ROW_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    SUCCESSORS_FIELD_NUMBER: _ClassVar[int]
    range: _common_pb2.AddressRange
    status: DiffBlockStatus
    partner: int
    first_row: int
    rows: int
    successors: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., status: _Optional[_Union[DiffBlockStatus, str]] = ..., partner: _Optional[int] = ..., first_row: _Optional[int] = ..., rows: _Optional[int] = ..., successors: _Optional[_Iterable[int]] = ...) -> None: ...

class DiffToken(_message.Message):
    __slots__ = ("text", "kind", "target", "operand")
    TEXT_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    OPERAND_FIELD_NUMBER: _ClassVar[int]
    text: str
    kind: int
    target: _common_pb2.Address
    operand: int
    def __init__(self, text: _Optional[str] = ..., kind: _Optional[int] = ..., target: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., operand: _Optional[int] = ...) -> None: ...

class DiffRow(_message.Message):
    __slots__ = ("address", "status", "partner", "block", "moved", "length", "text", "tokens", "label", "comment", "flow")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PARTNER_FIELD_NUMBER: _ClassVar[int]
    BLOCK_FIELD_NUMBER: _ClassVar[int]
    MOVED_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    TOKENS_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    FLOW_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    status: DiffLineStatus
    partner: int
    block: int
    moved: bool
    length: int
    text: str
    tokens: _containers.RepeatedCompositeFieldContainer[DiffToken]
    label: str
    comment: str
    flow: int
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., status: _Optional[_Union[DiffLineStatus, str]] = ..., partner: _Optional[int] = ..., block: _Optional[int] = ..., moved: _Optional[bool] = ..., length: _Optional[int] = ..., text: _Optional[str] = ..., tokens: _Optional[_Iterable[_Union[DiffToken, _Mapping]]] = ..., label: _Optional[str] = ..., comment: _Optional[str] = ..., flow: _Optional[int] = ...) -> None: ...

class DiffLine(_message.Message):
    __slots__ = ("a", "b")
    A_FIELD_NUMBER: _ClassVar[int]
    B_FIELD_NUMBER: _ClassVar[int]
    a: int
    b: int
    def __init__(self, a: _Optional[int] = ..., b: _Optional[int] = ...) -> None: ...

class DiffReferenceChange(_message.Message):
    __slots__ = ("side", "kind", "row", "target", "name", "partner", "unmatched")
    SIDE_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    FROM_FIELD_NUMBER: _ClassVar[int]
    ROW_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PARTNER_FIELD_NUMBER: _ClassVar[int]
    UNMATCHED_FIELD_NUMBER: _ClassVar[int]
    side: DiffSide
    kind: DiffReferenceKind
    row: int
    target: _common_pb2.Address
    name: str
    partner: DiffFunctionRef
    unmatched: bool
    def __init__(self, side: _Optional[_Union[DiffSide, str]] = ..., kind: _Optional[_Union[DiffReferenceKind, str]] = ..., row: _Optional[int] = ..., target: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., name: _Optional[str] = ..., partner: _Optional[_Union[DiffFunctionRef, _Mapping]] = ..., unmatched: _Optional[bool] = ..., **kwargs) -> None: ...

class DiffChangeSummary(_message.Message):
    __slots__ = ("equal", "changed", "inserted", "deleted", "blocks_unchanged", "blocks_modified", "blocks_added", "blocks_removed", "hunks", "text", "entry_a", "entry_b")
    EQUAL_FIELD_NUMBER: _ClassVar[int]
    CHANGED_FIELD_NUMBER: _ClassVar[int]
    INSERTED_FIELD_NUMBER: _ClassVar[int]
    DELETED_FIELD_NUMBER: _ClassVar[int]
    BLOCKS_UNCHANGED_FIELD_NUMBER: _ClassVar[int]
    BLOCKS_MODIFIED_FIELD_NUMBER: _ClassVar[int]
    BLOCKS_ADDED_FIELD_NUMBER: _ClassVar[int]
    BLOCKS_REMOVED_FIELD_NUMBER: _ClassVar[int]
    HUNKS_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    ENTRY_A_FIELD_NUMBER: _ClassVar[int]
    ENTRY_B_FIELD_NUMBER: _ClassVar[int]
    equal: int
    changed: int
    inserted: int
    deleted: int
    blocks_unchanged: int
    blocks_modified: int
    blocks_added: int
    blocks_removed: int
    hunks: int
    text: str
    entry_a: _common_pb2.Address
    entry_b: _common_pb2.Address
    def __init__(self, equal: _Optional[int] = ..., changed: _Optional[int] = ..., inserted: _Optional[int] = ..., deleted: _Optional[int] = ..., blocks_unchanged: _Optional[int] = ..., blocks_modified: _Optional[int] = ..., blocks_added: _Optional[int] = ..., blocks_removed: _Optional[int] = ..., hunks: _Optional[int] = ..., text: _Optional[str] = ..., entry_a: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., entry_b: _Optional[_Union[_common_pb2.Address, _Mapping]] = ...) -> None: ...

class DiffDetail(_message.Message):
    __slots__ = ("blocks_a", "blocks_b", "rows_a", "rows_b", "lines", "hunks", "references", "summary", "correlate_ms", "total_ms")
    BLOCKS_A_FIELD_NUMBER: _ClassVar[int]
    BLOCKS_B_FIELD_NUMBER: _ClassVar[int]
    ROWS_A_FIELD_NUMBER: _ClassVar[int]
    ROWS_B_FIELD_NUMBER: _ClassVar[int]
    LINES_FIELD_NUMBER: _ClassVar[int]
    HUNKS_FIELD_NUMBER: _ClassVar[int]
    REFERENCES_FIELD_NUMBER: _ClassVar[int]
    SUMMARY_FIELD_NUMBER: _ClassVar[int]
    CORRELATE_MS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_MS_FIELD_NUMBER: _ClassVar[int]
    blocks_a: _containers.RepeatedCompositeFieldContainer[DiffBlock]
    blocks_b: _containers.RepeatedCompositeFieldContainer[DiffBlock]
    rows_a: _containers.RepeatedCompositeFieldContainer[DiffRow]
    rows_b: _containers.RepeatedCompositeFieldContainer[DiffRow]
    lines: _containers.RepeatedCompositeFieldContainer[DiffLine]
    hunks: _containers.RepeatedScalarFieldContainer[int]
    references: _containers.RepeatedCompositeFieldContainer[DiffReferenceChange]
    summary: DiffChangeSummary
    correlate_ms: float
    total_ms: float
    def __init__(self, blocks_a: _Optional[_Iterable[_Union[DiffBlock, _Mapping]]] = ..., blocks_b: _Optional[_Iterable[_Union[DiffBlock, _Mapping]]] = ..., rows_a: _Optional[_Iterable[_Union[DiffRow, _Mapping]]] = ..., rows_b: _Optional[_Iterable[_Union[DiffRow, _Mapping]]] = ..., lines: _Optional[_Iterable[_Union[DiffLine, _Mapping]]] = ..., hunks: _Optional[_Iterable[int]] = ..., references: _Optional[_Iterable[_Union[DiffReferenceChange, _Mapping]]] = ..., summary: _Optional[_Union[DiffChangeSummary, _Mapping]] = ..., correlate_ms: _Optional[float] = ..., total_ms: _Optional[float] = ...) -> None: ...

class SummarizeFunctionDiffsRequest(_message.Message):
    __slots__ = ("project_id", "session_id", "read", "pairs")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    PAIRS_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    session_id: str
    read: _common_pb2.ReadOptions
    pairs: _containers.RepeatedCompositeFieldContainer[DiffPair]
    def __init__(self, project_id: _Optional[str] = ..., session_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., pairs: _Optional[_Iterable[_Union[DiffPair, _Mapping]]] = ...) -> None: ...

class SummarizeFunctionDiffsResponse(_message.Message):
    __slots__ = ("snapshot", "summaries")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    SUMMARIES_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    summaries: _containers.RepeatedCompositeFieldContainer[DiffChangeSummary]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., summaries: _Optional[_Iterable[_Union[DiffChangeSummary, _Mapping]]] = ...) -> None: ...

class DiffPair(_message.Message):
    __slots__ = ("entry_a", "entry_b")
    ENTRY_A_FIELD_NUMBER: _ClassVar[int]
    ENTRY_B_FIELD_NUMBER: _ClassVar[int]
    entry_a: _common_pb2.Address
    entry_b: _common_pb2.Address
    def __init__(self, entry_a: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., entry_b: _Optional[_Union[_common_pb2.Address, _Mapping]] = ...) -> None: ...

class AcceptMatchesRequest(_message.Message):
    __slots__ = ("project_id", "session_id", "pairs", "provenance", "min_confidence")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PAIRS_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    MIN_CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    session_id: str
    pairs: _containers.RepeatedCompositeFieldContainer[DiffPair]
    provenance: _common_pb2.Provenance
    min_confidence: float
    def __init__(self, project_id: _Optional[str] = ..., session_id: _Optional[str] = ..., pairs: _Optional[_Iterable[_Union[DiffPair, _Mapping]]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., min_confidence: _Optional[float] = ...) -> None: ...

class AcceptMatchesResponse(_message.Message):
    __slots__ = ("snapshot", "match_seqs", "seqs")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    MATCH_SEQS_FIELD_NUMBER: _ClassVar[int]
    SEQS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    match_seqs: _containers.RepeatedScalarFieldContainer[int]
    seqs: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., match_seqs: _Optional[_Iterable[int]] = ..., seqs: _Optional[_Iterable[int]] = ...) -> None: ...

class RejectMatchesRequest(_message.Message):
    __slots__ = ("project_id", "session_id", "pairs", "provenance")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PAIRS_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    session_id: str
    pairs: _containers.RepeatedCompositeFieldContainer[DiffPair]
    provenance: _common_pb2.Provenance
    def __init__(self, project_id: _Optional[str] = ..., session_id: _Optional[str] = ..., pairs: _Optional[_Iterable[_Union[DiffPair, _Mapping]]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class RejectMatchesResponse(_message.Message):
    __slots__ = ("snapshot", "match_seqs", "retracted_seqs", "seqs")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    MATCH_SEQS_FIELD_NUMBER: _ClassVar[int]
    RETRACTED_SEQS_FIELD_NUMBER: _ClassVar[int]
    SEQS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    match_seqs: _containers.RepeatedScalarFieldContainer[int]
    retracted_seqs: _containers.RepeatedScalarFieldContainer[int]
    seqs: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., match_seqs: _Optional[_Iterable[int]] = ..., retracted_seqs: _Optional[_Iterable[int]] = ..., seqs: _Optional[_Iterable[int]] = ...) -> None: ...

class SetMatchRequest(_message.Message):
    __slots__ = ("project_id", "session_id", "entry_a", "entry_b", "provenance")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ENTRY_A_FIELD_NUMBER: _ClassVar[int]
    ENTRY_B_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    session_id: str
    entry_a: _common_pb2.Address
    entry_b: _common_pb2.Address
    provenance: _common_pb2.Provenance
    def __init__(self, project_id: _Optional[str] = ..., session_id: _Optional[str] = ..., entry_a: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., entry_b: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class SetMatchResponse(_message.Message):
    __slots__ = ("snapshot", "match_seq", "retracted_seqs", "seqs")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    MATCH_SEQ_FIELD_NUMBER: _ClassVar[int]
    RETRACTED_SEQS_FIELD_NUMBER: _ClassVar[int]
    SEQS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    match_seq: int
    retracted_seqs: _containers.RepeatedScalarFieldContainer[int]
    seqs: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., match_seq: _Optional[int] = ..., retracted_seqs: _Optional[_Iterable[int]] = ..., seqs: _Optional[_Iterable[int]] = ...) -> None: ...

class UnmatchRequest(_message.Message):
    __slots__ = ("project_id", "session_id", "pairs", "provenance")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PAIRS_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    session_id: str
    pairs: _containers.RepeatedCompositeFieldContainer[DiffPair]
    provenance: _common_pb2.Provenance
    def __init__(self, project_id: _Optional[str] = ..., session_id: _Optional[str] = ..., pairs: _Optional[_Iterable[_Union[DiffPair, _Mapping]]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class UnmatchResponse(_message.Message):
    __slots__ = ("snapshot", "retracted_seqs", "seqs")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    RETRACTED_SEQS_FIELD_NUMBER: _ClassVar[int]
    SEQS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    retracted_seqs: _containers.RepeatedScalarFieldContainer[int]
    seqs: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., retracted_seqs: _Optional[_Iterable[int]] = ..., seqs: _Optional[_Iterable[int]] = ...) -> None: ...

class ApplyMarkupRequest(_message.Message):
    __slots__ = ("project_id", "session_id", "pairs", "min_confidence", "items", "policy", "provenance", "dry_run")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PAIRS_FIELD_NUMBER: _ClassVar[int]
    MIN_CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    DRY_RUN_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    session_id: str
    pairs: _containers.RepeatedCompositeFieldContainer[DiffPair]
    min_confidence: float
    items: _containers.RepeatedScalarFieldContainer[DiffMarkupItem]
    policy: DiffApplyPolicy
    provenance: _common_pb2.Provenance
    dry_run: bool
    def __init__(self, project_id: _Optional[str] = ..., session_id: _Optional[str] = ..., pairs: _Optional[_Iterable[_Union[DiffPair, _Mapping]]] = ..., min_confidence: _Optional[float] = ..., items: _Optional[_Iterable[_Union[DiffMarkupItem, str]]] = ..., policy: _Optional[_Union[DiffApplyPolicy, str]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., dry_run: _Optional[bool] = ...) -> None: ...

class ApplyMarkupResponse(_message.Message):
    __slots__ = ("snapshot", "run_id", "pairs", "matches_recorded", "names", "comments", "prototypes", "types", "skipped", "warnings", "seqs")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    PAIRS_FIELD_NUMBER: _ClassVar[int]
    MATCHES_RECORDED_FIELD_NUMBER: _ClassVar[int]
    NAMES_FIELD_NUMBER: _ClassVar[int]
    COMMENTS_FIELD_NUMBER: _ClassVar[int]
    PROTOTYPES_FIELD_NUMBER: _ClassVar[int]
    TYPES_FIELD_NUMBER: _ClassVar[int]
    SKIPPED_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    SEQS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    run_id: str
    pairs: int
    matches_recorded: int
    names: int
    comments: int
    prototypes: int
    types: int
    skipped: int
    warnings: _containers.RepeatedScalarFieldContainer[str]
    seqs: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., run_id: _Optional[str] = ..., pairs: _Optional[int] = ..., matches_recorded: _Optional[int] = ..., names: _Optional[int] = ..., comments: _Optional[int] = ..., prototypes: _Optional[int] = ..., types: _Optional[int] = ..., skipped: _Optional[int] = ..., warnings: _Optional[_Iterable[str]] = ..., seqs: _Optional[_Iterable[int]] = ...) -> None: ...

class RevertApplyRequest(_message.Message):
    __slots__ = ("project_id", "session_id", "run_id", "provenance")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    session_id: str
    run_id: str
    provenance: _common_pb2.Provenance
    def __init__(self, project_id: _Optional[str] = ..., session_id: _Optional[str] = ..., run_id: _Optional[str] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class RevertApplyResponse(_message.Message):
    __slots__ = ("snapshot", "retracted_seqs")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    RETRACTED_SEQS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    retracted_seqs: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., retracted_seqs: _Optional[_Iterable[int]] = ...) -> None: ...

class DiffMatchBody(_message.Message):
    __slots__ = ("session_id", "entry_a", "entry_b", "status", "rejected", "tier", "confidence")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ENTRY_A_FIELD_NUMBER: _ClassVar[int]
    ENTRY_B_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    REJECTED_FIELD_NUMBER: _ClassVar[int]
    TIER_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    entry_a: _common_pb2.Address
    entry_b: _common_pb2.Address
    status: DiffMatchStatus
    rejected: bool
    tier: DiffTier
    confidence: float
    def __init__(self, session_id: _Optional[str] = ..., entry_a: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., entry_b: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., status: _Optional[_Union[DiffMatchStatus, str]] = ..., rejected: _Optional[bool] = ..., tier: _Optional[_Union[DiffTier, str]] = ..., confidence: _Optional[float] = ...) -> None: ...

class PortedFrom(_message.Message):
    __slots__ = ("session_id", "run_id", "program_id", "function", "address", "source_seq", "source_id", "match_seq")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SOURCE_SEQ_FIELD_NUMBER: _ClassVar[int]
    SOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    MATCH_SEQ_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    run_id: str
    program_id: str
    function: _common_pb2.Address
    address: _common_pb2.Address
    source_seq: int
    source_id: _common_pb2.OpId
    match_seq: int
    def __init__(self, session_id: _Optional[str] = ..., run_id: _Optional[str] = ..., program_id: _Optional[str] = ..., function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., source_seq: _Optional[int] = ..., source_id: _Optional[_Union[_common_pb2.OpId, _Mapping]] = ..., match_seq: _Optional[int] = ...) -> None: ...

class CompareFunctionsRequest(_message.Message):
    __slots__ = ("project_id", "read", "program_a", "entry_a", "program_b", "entry_b", "session_id", "omit_bytes", "markup")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_A_FIELD_NUMBER: _ClassVar[int]
    ENTRY_A_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_B_FIELD_NUMBER: _ClassVar[int]
    ENTRY_B_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    OMIT_BYTES_FIELD_NUMBER: _ClassVar[int]
    MARKUP_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    read: _common_pb2.ReadOptions
    program_a: str
    entry_a: _common_pb2.Address
    program_b: str
    entry_b: _common_pb2.Address
    session_id: str
    omit_bytes: bool
    markup: bool
    def __init__(self, project_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., program_a: _Optional[str] = ..., entry_a: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., program_b: _Optional[str] = ..., entry_b: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., session_id: _Optional[str] = ..., omit_bytes: _Optional[bool] = ..., markup: _Optional[bool] = ...) -> None: ...

class CompareFunctionsResponse(_message.Message):
    __slots__ = ("snapshot", "a", "b", "detail", "match", "markup")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    A_FIELD_NUMBER: _ClassVar[int]
    B_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    MATCH_FIELD_NUMBER: _ClassVar[int]
    MARKUP_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    a: DiffFunctionSummary
    b: DiffFunctionSummary
    detail: DiffDetail
    match: DiffMatch
    markup: CompareMarkup
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., a: _Optional[_Union[DiffFunctionSummary, _Mapping]] = ..., b: _Optional[_Union[DiffFunctionSummary, _Mapping]] = ..., detail: _Optional[_Union[DiffDetail, _Mapping]] = ..., match: _Optional[_Union[DiffMatch, _Mapping]] = ..., markup: _Optional[_Union[CompareMarkup, _Mapping]] = ...) -> None: ...

class CompareVariable(_message.Message):
    __slots__ = ("storage_key", "name", "type", "kind", "parameter_index", "named", "typed")
    STORAGE_KEY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    PARAMETER_INDEX_FIELD_NUMBER: _ClassVar[int]
    NAMED_FIELD_NUMBER: _ClassVar[int]
    TYPED_FIELD_NUMBER: _ClassVar[int]
    storage_key: str
    name: str
    type: str
    kind: _decompile_pb2.VariableKind
    parameter_index: int
    named: bool
    typed: bool
    def __init__(self, storage_key: _Optional[str] = ..., name: _Optional[str] = ..., type: _Optional[str] = ..., kind: _Optional[_Union[_decompile_pb2.VariableKind, str]] = ..., parameter_index: _Optional[int] = ..., named: _Optional[bool] = ..., typed: _Optional[bool] = ...) -> None: ...

class CompareVariablePair(_message.Message):
    __slots__ = ("a", "b", "evidence", "votes")
    A_FIELD_NUMBER: _ClassVar[int]
    B_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    VOTES_FIELD_NUMBER: _ClassVar[int]
    a: CompareVariable
    b: CompareVariable
    evidence: str
    votes: int
    def __init__(self, a: _Optional[_Union[CompareVariable, _Mapping]] = ..., b: _Optional[_Union[CompareVariable, _Mapping]] = ..., evidence: _Optional[str] = ..., votes: _Optional[int] = ...) -> None: ...

class CompareComment(_message.Message):
    __slots__ = ("kind", "address_a", "address_b", "text_a", "text_b")
    KIND_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_A_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_B_FIELD_NUMBER: _ClassVar[int]
    TEXT_A_FIELD_NUMBER: _ClassVar[int]
    TEXT_B_FIELD_NUMBER: _ClassVar[int]
    kind: str
    address_a: _common_pb2.Address
    address_b: _common_pb2.Address
    text_a: str
    text_b: str
    def __init__(self, kind: _Optional[str] = ..., address_a: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., address_b: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., text_a: _Optional[str] = ..., text_b: _Optional[str] = ...) -> None: ...

class CompareMarkup(_message.Message):
    __slots__ = ("signature_a", "signature_b", "signature_set_a", "signature_set_b", "variables", "comments", "error_a", "error_b")
    SIGNATURE_A_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_B_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_SET_A_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_SET_B_FIELD_NUMBER: _ClassVar[int]
    VARIABLES_FIELD_NUMBER: _ClassVar[int]
    COMMENTS_FIELD_NUMBER: _ClassVar[int]
    ERROR_A_FIELD_NUMBER: _ClassVar[int]
    ERROR_B_FIELD_NUMBER: _ClassVar[int]
    signature_a: str
    signature_b: str
    signature_set_a: bool
    signature_set_b: bool
    variables: _containers.RepeatedCompositeFieldContainer[CompareVariablePair]
    comments: _containers.RepeatedCompositeFieldContainer[CompareComment]
    error_a: str
    error_b: str
    def __init__(self, signature_a: _Optional[str] = ..., signature_b: _Optional[str] = ..., signature_set_a: _Optional[bool] = ..., signature_set_b: _Optional[bool] = ..., variables: _Optional[_Iterable[_Union[CompareVariablePair, _Mapping]]] = ..., comments: _Optional[_Iterable[_Union[CompareComment, _Mapping]]] = ..., error_a: _Optional[str] = ..., error_b: _Optional[str] = ...) -> None: ...

class FunctionMarkupItem(_message.Message):
    __slots__ = ("kind", "variable", "address", "comment_kind")
    KIND_FIELD_NUMBER: _ClassVar[int]
    VARIABLE_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    COMMENT_KIND_FIELD_NUMBER: _ClassVar[int]
    kind: FunctionMarkupKind
    variable: str
    address: _common_pb2.Address
    comment_kind: str
    def __init__(self, kind: _Optional[_Union[FunctionMarkupKind, str]] = ..., variable: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., comment_kind: _Optional[str] = ...) -> None: ...

class PortFunctionMarkupRequest(_message.Message):
    __slots__ = ("project_id", "from_program", "from_entry", "to_program", "to_entry", "items", "overwrite", "provenance", "dry_run", "session_id")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    FROM_PROGRAM_FIELD_NUMBER: _ClassVar[int]
    FROM_ENTRY_FIELD_NUMBER: _ClassVar[int]
    TO_PROGRAM_FIELD_NUMBER: _ClassVar[int]
    TO_ENTRY_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    OVERWRITE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    DRY_RUN_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    from_program: str
    from_entry: _common_pb2.Address
    to_program: str
    to_entry: _common_pb2.Address
    items: _containers.RepeatedCompositeFieldContainer[FunctionMarkupItem]
    overwrite: bool
    provenance: _common_pb2.Provenance
    dry_run: bool
    session_id: str
    def __init__(self, project_id: _Optional[str] = ..., from_program: _Optional[str] = ..., from_entry: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., to_program: _Optional[str] = ..., to_entry: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., items: _Optional[_Iterable[_Union[FunctionMarkupItem, _Mapping]]] = ..., overwrite: _Optional[bool] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., dry_run: _Optional[bool] = ..., session_id: _Optional[str] = ...) -> None: ...

class PortedMarkup(_message.Message):
    __slots__ = ("kind", "address", "variable", "comment_kind", "before", "after")
    KIND_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    VARIABLE_FIELD_NUMBER: _ClassVar[int]
    COMMENT_KIND_FIELD_NUMBER: _ClassVar[int]
    BEFORE_FIELD_NUMBER: _ClassVar[int]
    AFTER_FIELD_NUMBER: _ClassVar[int]
    kind: FunctionMarkupKind
    address: _common_pb2.Address
    variable: str
    comment_kind: str
    before: str
    after: str
    def __init__(self, kind: _Optional[_Union[FunctionMarkupKind, str]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., variable: _Optional[str] = ..., comment_kind: _Optional[str] = ..., before: _Optional[str] = ..., after: _Optional[str] = ...) -> None: ...

class PortFunctionMarkupResponse(_message.Message):
    __slots__ = ("snapshot", "names", "signatures", "variable_names", "variable_types", "comments", "types", "skipped", "warnings", "ported", "seqs", "globals", "callees")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    NAMES_FIELD_NUMBER: _ClassVar[int]
    SIGNATURES_FIELD_NUMBER: _ClassVar[int]
    VARIABLE_NAMES_FIELD_NUMBER: _ClassVar[int]
    VARIABLE_TYPES_FIELD_NUMBER: _ClassVar[int]
    COMMENTS_FIELD_NUMBER: _ClassVar[int]
    TYPES_FIELD_NUMBER: _ClassVar[int]
    SKIPPED_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    PORTED_FIELD_NUMBER: _ClassVar[int]
    SEQS_FIELD_NUMBER: _ClassVar[int]
    GLOBALS_FIELD_NUMBER: _ClassVar[int]
    CALLEES_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    names: int
    signatures: int
    variable_names: int
    variable_types: int
    comments: int
    types: int
    skipped: int
    warnings: _containers.RepeatedScalarFieldContainer[str]
    ported: _containers.RepeatedCompositeFieldContainer[PortedMarkup]
    seqs: _containers.RepeatedScalarFieldContainer[int]
    globals: int
    callees: int
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., names: _Optional[int] = ..., signatures: _Optional[int] = ..., variable_names: _Optional[int] = ..., variable_types: _Optional[int] = ..., comments: _Optional[int] = ..., types: _Optional[int] = ..., skipped: _Optional[int] = ..., warnings: _Optional[_Iterable[str]] = ..., ported: _Optional[_Iterable[_Union[PortedMarkup, _Mapping]]] = ..., seqs: _Optional[_Iterable[int]] = ..., globals: _Optional[int] = ..., callees: _Optional[int] = ...) -> None: ...
