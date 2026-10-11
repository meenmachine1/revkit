from revkit.v1 import common_pb2 as _common_pb2
from revkit.v1 import presence_pb2 as _presence_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class VersionVector(_message.Message):
    __slots__ = ("entries",)
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    entries: _containers.RepeatedCompositeFieldContainer[VersionVectorEntry]
    def __init__(self, entries: _Optional[_Iterable[_Union[VersionVectorEntry, _Mapping]]] = ...) -> None: ...

class VersionVectorEntry(_message.Message):
    __slots__ = ("replica", "counter")
    REPLICA_FIELD_NUMBER: _ClassVar[int]
    COUNTER_FIELD_NUMBER: _ClassVar[int]
    replica: int
    counter: int
    def __init__(self, replica: _Optional[int] = ..., counter: _Optional[int] = ...) -> None: ...

class ReplicatedOp(_message.Message):
    __slots__ = ("id", "encoded")
    ID_FIELD_NUMBER: _ClassVar[int]
    ENCODED_FIELD_NUMBER: _ClassVar[int]
    id: _common_pb2.OpId
    encoded: bytes
    def __init__(self, id: _Optional[_Union[_common_pb2.OpId, _Mapping]] = ..., encoded: _Optional[bytes] = ...) -> None: ...

class ProjectSyncState(_message.Message):
    __slots__ = ("project_id", "replica", "version_vector", "waiting", "head_revision", "missing_programs")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    REPLICA_FIELD_NUMBER: _ClassVar[int]
    VERSION_VECTOR_FIELD_NUMBER: _ClassVar[int]
    WAITING_FIELD_NUMBER: _ClassVar[int]
    HEAD_REVISION_FIELD_NUMBER: _ClassVar[int]
    MISSING_PROGRAMS_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    replica: int
    version_vector: VersionVector
    waiting: int
    head_revision: int
    missing_programs: _containers.RepeatedCompositeFieldContainer[MissingProgram]
    def __init__(self, project_id: _Optional[str] = ..., replica: _Optional[int] = ..., version_vector: _Optional[_Union[VersionVector, _Mapping]] = ..., waiting: _Optional[int] = ..., head_revision: _Optional[int] = ..., missing_programs: _Optional[_Iterable[_Union[MissingProgram, _Mapping]]] = ...) -> None: ...

class MissingProgram(_message.Message):
    __slots__ = ("program_id", "sha256", "size")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    sha256: str
    size: int
    def __init__(self, program_id: _Optional[str] = ..., sha256: _Optional[str] = ..., size: _Optional[int] = ...) -> None: ...

class GetSyncStateRequest(_message.Message):
    __slots__ = ("project_id",)
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    def __init__(self, project_id: _Optional[str] = ...) -> None: ...

class GetSyncStateResponse(_message.Message):
    __slots__ = ("format", "projects")
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    PROJECTS_FIELD_NUMBER: _ClassVar[int]
    format: int
    projects: _containers.RepeatedCompositeFieldContainer[ProjectSyncState]
    def __init__(self, format: _Optional[int] = ..., projects: _Optional[_Iterable[_Union[ProjectSyncState, _Mapping]]] = ...) -> None: ...

class PullRequest(_message.Message):
    __slots__ = ("project_id", "replica", "have", "format", "live", "include_presence", "max_batch", "peer")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    REPLICA_FIELD_NUMBER: _ClassVar[int]
    HAVE_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    LIVE_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_PRESENCE_FIELD_NUMBER: _ClassVar[int]
    MAX_BATCH_FIELD_NUMBER: _ClassVar[int]
    PEER_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    replica: int
    have: VersionVector
    format: int
    live: bool
    include_presence: bool
    max_batch: int
    peer: str
    def __init__(self, project_id: _Optional[str] = ..., replica: _Optional[int] = ..., have: _Optional[_Union[VersionVector, _Mapping]] = ..., format: _Optional[int] = ..., live: _Optional[bool] = ..., include_presence: _Optional[bool] = ..., max_batch: _Optional[int] = ..., peer: _Optional[str] = ...) -> None: ...

class PullResponse(_message.Message):
    __slots__ = ("hello", "ops", "caught_up", "presence", "heartbeat")
    HELLO_FIELD_NUMBER: _ClassVar[int]
    OPS_FIELD_NUMBER: _ClassVar[int]
    CAUGHT_UP_FIELD_NUMBER: _ClassVar[int]
    PRESENCE_FIELD_NUMBER: _ClassVar[int]
    HEARTBEAT_FIELD_NUMBER: _ClassVar[int]
    hello: PullHello
    ops: OpBatch
    caught_up: CaughtUp
    presence: _presence_pb2.Presence
    heartbeat: SyncHeartbeat
    def __init__(self, hello: _Optional[_Union[PullHello, _Mapping]] = ..., ops: _Optional[_Union[OpBatch, _Mapping]] = ..., caught_up: _Optional[_Union[CaughtUp, _Mapping]] = ..., presence: _Optional[_Union[_presence_pb2.Presence, _Mapping]] = ..., heartbeat: _Optional[_Union[SyncHeartbeat, _Mapping]] = ...) -> None: ...

class PullHello(_message.Message):
    __slots__ = ("replica", "version_vector", "format", "head_revision")
    REPLICA_FIELD_NUMBER: _ClassVar[int]
    VERSION_VECTOR_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    HEAD_REVISION_FIELD_NUMBER: _ClassVar[int]
    replica: int
    version_vector: VersionVector
    format: int
    head_revision: int
    def __init__(self, replica: _Optional[int] = ..., version_vector: _Optional[_Union[VersionVector, _Mapping]] = ..., format: _Optional[int] = ..., head_revision: _Optional[int] = ...) -> None: ...

class OpBatch(_message.Message):
    __slots__ = ("ops",)
    OPS_FIELD_NUMBER: _ClassVar[int]
    ops: _containers.RepeatedCompositeFieldContainer[ReplicatedOp]
    def __init__(self, ops: _Optional[_Iterable[_Union[ReplicatedOp, _Mapping]]] = ...) -> None: ...

class CaughtUp(_message.Message):
    __slots__ = ("version_vector",)
    VERSION_VECTOR_FIELD_NUMBER: _ClassVar[int]
    version_vector: VersionVector
    def __init__(self, version_vector: _Optional[_Union[VersionVector, _Mapping]] = ...) -> None: ...

class SyncHeartbeat(_message.Message):
    __slots__ = ("head_revision",)
    HEAD_REVISION_FIELD_NUMBER: _ClassVar[int]
    head_revision: int
    def __init__(self, head_revision: _Optional[int] = ...) -> None: ...

class PushRequest(_message.Message):
    __slots__ = ("project_id", "from_replica", "format", "ops", "presence", "program", "create_project")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    FROM_REPLICA_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    OPS_FIELD_NUMBER: _ClassVar[int]
    PRESENCE_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_FIELD_NUMBER: _ClassVar[int]
    CREATE_PROJECT_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    from_replica: int
    format: int
    ops: _containers.RepeatedCompositeFieldContainer[ReplicatedOp]
    presence: _containers.RepeatedCompositeFieldContainer[_presence_pb2.Presence]
    program: ProgramChunk
    create_project: bool
    def __init__(self, project_id: _Optional[str] = ..., from_replica: _Optional[int] = ..., format: _Optional[int] = ..., ops: _Optional[_Iterable[_Union[ReplicatedOp, _Mapping]]] = ..., presence: _Optional[_Iterable[_Union[_presence_pb2.Presence, _Mapping]]] = ..., program: _Optional[_Union[ProgramChunk, _Mapping]] = ..., create_project: _Optional[bool] = ...) -> None: ...

class PushResponse(_message.Message):
    __slots__ = ("version_vector", "staged", "duplicate", "waiting", "rejected", "errors", "snapshot", "missing_programs", "replica")
    VERSION_VECTOR_FIELD_NUMBER: _ClassVar[int]
    STAGED_FIELD_NUMBER: _ClassVar[int]
    DUPLICATE_FIELD_NUMBER: _ClassVar[int]
    WAITING_FIELD_NUMBER: _ClassVar[int]
    REJECTED_FIELD_NUMBER: _ClassVar[int]
    ERRORS_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    MISSING_PROGRAMS_FIELD_NUMBER: _ClassVar[int]
    REPLICA_FIELD_NUMBER: _ClassVar[int]
    version_vector: VersionVector
    staged: int
    duplicate: int
    waiting: int
    rejected: int
    errors: _containers.RepeatedScalarFieldContainer[str]
    snapshot: _common_pb2.Snapshot
    missing_programs: _containers.RepeatedCompositeFieldContainer[MissingProgram]
    replica: int
    def __init__(self, version_vector: _Optional[_Union[VersionVector, _Mapping]] = ..., staged: _Optional[int] = ..., duplicate: _Optional[int] = ..., waiting: _Optional[int] = ..., rejected: _Optional[int] = ..., errors: _Optional[_Iterable[str]] = ..., snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., missing_programs: _Optional[_Iterable[_Union[MissingProgram, _Mapping]]] = ..., replica: _Optional[int] = ...) -> None: ...

class ProgramChunk(_message.Message):
    __slots__ = ("sha256", "offset", "total_size", "data")
    SHA256_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    TOTAL_SIZE_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    sha256: str
    offset: int
    total_size: int
    data: bytes
    def __init__(self, sha256: _Optional[str] = ..., offset: _Optional[int] = ..., total_size: _Optional[int] = ..., data: _Optional[bytes] = ...) -> None: ...

class FetchProgramRequest(_message.Message):
    __slots__ = ("project_id", "sha256", "offset", "max_bytes")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    MAX_BYTES_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    sha256: str
    offset: int
    max_bytes: int
    def __init__(self, project_id: _Optional[str] = ..., sha256: _Optional[str] = ..., offset: _Optional[int] = ..., max_bytes: _Optional[int] = ...) -> None: ...

class FetchProgramResponse(_message.Message):
    __slots__ = ("chunk",)
    CHUNK_FIELD_NUMBER: _ClassVar[int]
    chunk: ProgramChunk
    def __init__(self, chunk: _Optional[_Union[ProgramChunk, _Mapping]] = ...) -> None: ...
