import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from revkit.v1 import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class FidScope(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FID_SCOPE_UNSPECIFIED: _ClassVar[FidScope]
    FID_SCOPE_BUILTIN: _ClassVar[FidScope]
    FID_SCOPE_USER: _ClassVar[FidScope]
    FID_SCOPE_PROJECT: _ClassVar[FidScope]

class FidMatchStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FID_MATCH_STATUS_UNSPECIFIED: _ClassVar[FidMatchStatus]
    FID_MATCH_STATUS_APPLIED: _ClassVar[FidMatchStatus]
    FID_MATCH_STATUS_KEPT: _ClassVar[FidMatchStatus]
    FID_MATCH_STATUS_UNAPPLIED: _ClassVar[FidMatchStatus]
    FID_MATCH_STATUS_REJECTED: _ClassVar[FidMatchStatus]
    FID_MATCH_STATUS_ACCEPTED: _ClassVar[FidMatchStatus]

class AnalysisState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ANALYSIS_STATE_UNSPECIFIED: _ClassVar[AnalysisState]
    ANALYSIS_STATE_QUEUED: _ClassVar[AnalysisState]
    ANALYSIS_STATE_RUNNING: _ClassVar[AnalysisState]
    ANALYSIS_STATE_SUCCEEDED: _ClassVar[AnalysisState]
    ANALYSIS_STATE_FAILED: _ClassVar[AnalysisState]
    ANALYSIS_STATE_CANCELLED: _ClassVar[AnalysisState]
FID_SCOPE_UNSPECIFIED: FidScope
FID_SCOPE_BUILTIN: FidScope
FID_SCOPE_USER: FidScope
FID_SCOPE_PROJECT: FidScope
FID_MATCH_STATUS_UNSPECIFIED: FidMatchStatus
FID_MATCH_STATUS_APPLIED: FidMatchStatus
FID_MATCH_STATUS_KEPT: FidMatchStatus
FID_MATCH_STATUS_UNAPPLIED: FidMatchStatus
FID_MATCH_STATUS_REJECTED: FidMatchStatus
FID_MATCH_STATUS_ACCEPTED: FidMatchStatus
ANALYSIS_STATE_UNSPECIFIED: AnalysisState
ANALYSIS_STATE_QUEUED: AnalysisState
ANALYSIS_STATE_RUNNING: AnalysisState
ANALYSIS_STATE_SUCCEEDED: AnalysisState
ANALYSIS_STATE_FAILED: AnalysisState
ANALYSIS_STATE_CANCELLED: AnalysisState

class FidLibrary(_message.Message):
    __slots__ = ("family", "version", "variant", "language", "compiler")
    FAMILY_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    VARIANT_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    COMPILER_FIELD_NUMBER: _ClassVar[int]
    family: str
    version: str
    variant: str
    language: str
    compiler: str
    def __init__(self, family: _Optional[str] = ..., version: _Optional[str] = ..., variant: _Optional[str] = ..., language: _Optional[str] = ..., compiler: _Optional[str] = ...) -> None: ...

class FidDatabase(_message.Message):
    __slots__ = ("id", "name", "path", "scope", "attached", "format", "libraries", "functions", "error", "applies")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    ATTACHED_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    LIBRARIES_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    APPLIES_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    path: str
    scope: FidScope
    attached: bool
    format: str
    libraries: _containers.RepeatedCompositeFieldContainer[FidLibrary]
    functions: int
    error: str
    applies: bool
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., path: _Optional[str] = ..., scope: _Optional[_Union[FidScope, str]] = ..., attached: _Optional[bool] = ..., format: _Optional[str] = ..., libraries: _Optional[_Iterable[_Union[FidLibrary, _Mapping]]] = ..., functions: _Optional[int] = ..., error: _Optional[str] = ..., applies: _Optional[bool] = ...) -> None: ...

class ListFidDatabasesRequest(_message.Message):
    __slots__ = ("project_id", "program_id")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    program_id: str
    def __init__(self, project_id: _Optional[str] = ..., program_id: _Optional[str] = ...) -> None: ...

class ListFidDatabasesResponse(_message.Message):
    __slots__ = ("databases",)
    DATABASES_FIELD_NUMBER: _ClassVar[int]
    databases: _containers.RepeatedCompositeFieldContainer[FidDatabase]
    def __init__(self, databases: _Optional[_Iterable[_Union[FidDatabase, _Mapping]]] = ...) -> None: ...

class AttachFidDatabaseRequest(_message.Message):
    __slots__ = ("project_id", "path", "scope", "provenance")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    path: str
    scope: FidScope
    provenance: _common_pb2.Provenance
    def __init__(self, project_id: _Optional[str] = ..., path: _Optional[str] = ..., scope: _Optional[_Union[FidScope, str]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class AttachFidDatabaseResponse(_message.Message):
    __slots__ = ("database",)
    DATABASE_FIELD_NUMBER: _ClassVar[int]
    database: FidDatabase
    def __init__(self, database: _Optional[_Union[FidDatabase, _Mapping]] = ...) -> None: ...

class DetachFidDatabaseRequest(_message.Message):
    __slots__ = ("project_id", "id", "scope", "provenance")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    id: str
    scope: FidScope
    provenance: _common_pb2.Provenance
    def __init__(self, project_id: _Optional[str] = ..., id: _Optional[str] = ..., scope: _Optional[_Union[FidScope, str]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class DetachFidDatabaseResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class FidCandidate(_message.Message):
    __slots__ = ("name", "library", "database", "score", "function_score", "child_score", "parent_score", "specific")
    NAME_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_FIELD_NUMBER: _ClassVar[int]
    DATABASE_FIELD_NUMBER: _ClassVar[int]
    SCORE_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_SCORE_FIELD_NUMBER: _ClassVar[int]
    CHILD_SCORE_FIELD_NUMBER: _ClassVar[int]
    PARENT_SCORE_FIELD_NUMBER: _ClassVar[int]
    SPECIFIC_FIELD_NUMBER: _ClassVar[int]
    name: str
    library: str
    database: str
    score: float
    function_score: float
    child_score: float
    parent_score: float
    specific: bool
    def __init__(self, name: _Optional[str] = ..., library: _Optional[str] = ..., database: _Optional[str] = ..., score: _Optional[float] = ..., function_score: _Optional[float] = ..., child_score: _Optional[float] = ..., parent_score: _Optional[float] = ..., specific: _Optional[bool] = ...) -> None: ...

class FidMatch(_message.Message):
    __slots__ = ("entry", "current_name", "name", "verdict", "score", "candidates", "libraries", "status", "comment", "full_hash", "specific_hash", "code_units")
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    CURRENT_NAME_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERDICT_FIELD_NUMBER: _ClassVar[int]
    SCORE_FIELD_NUMBER: _ClassVar[int]
    CANDIDATES_FIELD_NUMBER: _ClassVar[int]
    LIBRARIES_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    FULL_HASH_FIELD_NUMBER: _ClassVar[int]
    SPECIFIC_HASH_FIELD_NUMBER: _ClassVar[int]
    CODE_UNITS_FIELD_NUMBER: _ClassVar[int]
    entry: int
    current_name: str
    name: str
    verdict: str
    score: float
    candidates: _containers.RepeatedCompositeFieldContainer[FidCandidate]
    libraries: _containers.RepeatedScalarFieldContainer[str]
    status: FidMatchStatus
    comment: str
    full_hash: str
    specific_hash: str
    code_units: int
    def __init__(self, entry: _Optional[int] = ..., current_name: _Optional[str] = ..., name: _Optional[str] = ..., verdict: _Optional[str] = ..., score: _Optional[float] = ..., candidates: _Optional[_Iterable[_Union[FidCandidate, _Mapping]]] = ..., libraries: _Optional[_Iterable[str]] = ..., status: _Optional[_Union[FidMatchStatus, str]] = ..., comment: _Optional[str] = ..., full_hash: _Optional[str] = ..., specific_hash: _Optional[str] = ..., code_units: _Optional[int] = ...) -> None: ...

class ListFidMatchesRequest(_message.Message):
    __slots__ = ("program_id",)
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    def __init__(self, program_id: _Optional[str] = ...) -> None: ...

class ListFidMatchesResponse(_message.Message):
    __slots__ = ("matches", "revision", "databases", "functions_hashed")
    MATCHES_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    DATABASES_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_HASHED_FIELD_NUMBER: _ClassVar[int]
    matches: _containers.RepeatedCompositeFieldContainer[FidMatch]
    revision: int
    databases: _containers.RepeatedScalarFieldContainer[str]
    functions_hashed: int
    def __init__(self, matches: _Optional[_Iterable[_Union[FidMatch, _Mapping]]] = ..., revision: _Optional[int] = ..., databases: _Optional[_Iterable[str]] = ..., functions_hashed: _Optional[int] = ...) -> None: ...

class ApplyFidMatchRequest(_message.Message):
    __slots__ = ("program_id", "entry", "name", "provenance")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    entry: int
    name: str
    provenance: _common_pb2.Provenance
    def __init__(self, program_id: _Optional[str] = ..., entry: _Optional[int] = ..., name: _Optional[str] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class ApplyFidMatchResponse(_message.Message):
    __slots__ = ("revision",)
    REVISION_FIELD_NUMBER: _ClassVar[int]
    revision: int
    def __init__(self, revision: _Optional[int] = ...) -> None: ...

class RejectFidMatchRequest(_message.Message):
    __slots__ = ("program_id", "entry", "provenance")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    entry: int
    provenance: _common_pb2.Provenance
    def __init__(self, program_id: _Optional[str] = ..., entry: _Optional[int] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class RejectFidMatchResponse(_message.Message):
    __slots__ = ("revision",)
    REVISION_FIELD_NUMBER: _ClassVar[int]
    revision: int
    def __init__(self, revision: _Optional[int] = ...) -> None: ...

class CreateFidDatabaseRequest(_message.Message):
    __slots__ = ("project_id", "program_ids", "path", "family", "version", "variant", "common_symbols", "attach", "provenance")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_IDS_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    FAMILY_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    VARIANT_FIELD_NUMBER: _ClassVar[int]
    COMMON_SYMBOLS_FIELD_NUMBER: _ClassVar[int]
    ATTACH_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    program_ids: _containers.RepeatedScalarFieldContainer[str]
    path: str
    family: str
    version: str
    variant: str
    common_symbols: _containers.RepeatedScalarFieldContainer[str]
    attach: FidScope
    provenance: _common_pb2.Provenance
    def __init__(self, project_id: _Optional[str] = ..., program_ids: _Optional[_Iterable[str]] = ..., path: _Optional[str] = ..., family: _Optional[str] = ..., version: _Optional[str] = ..., variant: _Optional[str] = ..., common_symbols: _Optional[_Iterable[str]] = ..., attach: _Optional[_Union[FidScope, str]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class CreateFidDatabaseResponse(_message.Message):
    __slots__ = ("database", "functions_added", "excluded", "unresolved_callees")
    class ExcludedEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    DATABASE_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_ADDED_FIELD_NUMBER: _ClassVar[int]
    EXCLUDED_FIELD_NUMBER: _ClassVar[int]
    UNRESOLVED_CALLEES_FIELD_NUMBER: _ClassVar[int]
    database: FidDatabase
    functions_added: int
    excluded: _containers.ScalarMap[str, int]
    unresolved_callees: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, database: _Optional[_Union[FidDatabase, _Mapping]] = ..., functions_added: _Optional[int] = ..., excluded: _Optional[_Mapping[str, int]] = ..., unresolved_callees: _Optional[_Iterable[str]] = ...) -> None: ...

class Analyzer(_message.Message):
    __slots__ = ("id", "description", "enabled_by_default")
    ID_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    ENABLED_BY_DEFAULT_FIELD_NUMBER: _ClassVar[int]
    id: str
    description: str
    enabled_by_default: bool
    def __init__(self, id: _Optional[str] = ..., description: _Optional[str] = ..., enabled_by_default: _Optional[bool] = ...) -> None: ...

class ListAnalyzersRequest(_message.Message):
    __slots__ = ("program_id",)
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    def __init__(self, program_id: _Optional[str] = ...) -> None: ...

class ListAnalyzersResponse(_message.Message):
    __slots__ = ("analyzers",)
    ANALYZERS_FIELD_NUMBER: _ClassVar[int]
    analyzers: _containers.RepeatedCompositeFieldContainer[Analyzer]
    def __init__(self, analyzers: _Optional[_Iterable[_Union[Analyzer, _Mapping]]] = ...) -> None: ...

class StartAnalysisRequest(_message.Message):
    __slots__ = ("program_id", "analyzers", "ranges", "provenance")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ANALYZERS_FIELD_NUMBER: _ClassVar[int]
    RANGES_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    analyzers: _containers.RepeatedScalarFieldContainer[str]
    ranges: _containers.RepeatedCompositeFieldContainer[_common_pb2.AddressRange]
    provenance: _common_pb2.Provenance
    def __init__(self, program_id: _Optional[str] = ..., analyzers: _Optional[_Iterable[str]] = ..., ranges: _Optional[_Iterable[_Union[_common_pb2.AddressRange, _Mapping]]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class StartAnalysisResponse(_message.Message):
    __slots__ = ("job",)
    JOB_FIELD_NUMBER: _ClassVar[int]
    job: AnalysisJob
    def __init__(self, job: _Optional[_Union[AnalysisJob, _Mapping]] = ...) -> None: ...

class CancelAnalysisRequest(_message.Message):
    __slots__ = ("job_id",)
    JOB_ID_FIELD_NUMBER: _ClassVar[int]
    job_id: str
    def __init__(self, job_id: _Optional[str] = ...) -> None: ...

class CancelAnalysisResponse(_message.Message):
    __slots__ = ("job",)
    JOB_FIELD_NUMBER: _ClassVar[int]
    job: AnalysisJob
    def __init__(self, job: _Optional[_Union[AnalysisJob, _Mapping]] = ...) -> None: ...

class GetAnalysisStatusRequest(_message.Message):
    __slots__ = ("program_id",)
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    def __init__(self, program_id: _Optional[str] = ...) -> None: ...

class GetAnalysisStatusResponse(_message.Message):
    __slots__ = ("jobs", "idle", "head_revision")
    JOBS_FIELD_NUMBER: _ClassVar[int]
    IDLE_FIELD_NUMBER: _ClassVar[int]
    HEAD_REVISION_FIELD_NUMBER: _ClassVar[int]
    jobs: _containers.RepeatedCompositeFieldContainer[AnalysisJob]
    idle: bool
    head_revision: int
    def __init__(self, jobs: _Optional[_Iterable[_Union[AnalysisJob, _Mapping]]] = ..., idle: _Optional[bool] = ..., head_revision: _Optional[int] = ...) -> None: ...

class AnalysisJob(_message.Message):
    __slots__ = ("job_id", "program_id", "state", "analyzers", "phase", "progress", "started_at", "finished_at", "first_revision", "last_revision", "message")
    JOB_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    ANALYZERS_FIELD_NUMBER: _ClassVar[int]
    PHASE_FIELD_NUMBER: _ClassVar[int]
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    STARTED_AT_FIELD_NUMBER: _ClassVar[int]
    FINISHED_AT_FIELD_NUMBER: _ClassVar[int]
    FIRST_REVISION_FIELD_NUMBER: _ClassVar[int]
    LAST_REVISION_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    job_id: str
    program_id: str
    state: AnalysisState
    analyzers: _containers.RepeatedScalarFieldContainer[str]
    phase: str
    progress: float
    started_at: _timestamp_pb2.Timestamp
    finished_at: _timestamp_pb2.Timestamp
    first_revision: int
    last_revision: int
    message: str
    def __init__(self, job_id: _Optional[str] = ..., program_id: _Optional[str] = ..., state: _Optional[_Union[AnalysisState, str]] = ..., analyzers: _Optional[_Iterable[str]] = ..., phase: _Optional[str] = ..., progress: _Optional[float] = ..., started_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., finished_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., first_revision: _Optional[int] = ..., last_revision: _Optional[int] = ..., message: _Optional[str] = ...) -> None: ...

class AnalysisProgress(_message.Message):
    __slots__ = ("job",)
    JOB_FIELD_NUMBER: _ClassVar[int]
    job: AnalysisJob
    def __init__(self, job: _Optional[_Union[AnalysisJob, _Mapping]] = ...) -> None: ...
