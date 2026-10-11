from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class RestartDaemonRequest(_message.Message):
    __slots__ = ("dry_run", "reason")
    DRY_RUN_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    dry_run: bool
    reason: str
    def __init__(self, dry_run: _Optional[bool] = ..., reason: _Optional[str] = ...) -> None: ...

class RestartDaemonResponse(_message.Message):
    __slots__ = ("mode", "open_streams")
    MODE_FIELD_NUMBER: _ClassVar[int]
    OPEN_STREAMS_FIELD_NUMBER: _ClassVar[int]
    mode: str
    open_streams: int
    def __init__(self, mode: _Optional[str] = ..., open_streams: _Optional[int] = ...) -> None: ...

class GetServerInfoRequest(_message.Message):
    __slots__ = ("client",)
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    client: str
    def __init__(self, client: _Optional[str] = ...) -> None: ...

class GetServerInfoResponse(_message.Message):
    __slots__ = ("api_major", "api_minor", "server_version", "features", "retained_revisions", "max_request_bytes", "uptime_seconds", "launch_args", "socket_activated")
    API_MAJOR_FIELD_NUMBER: _ClassVar[int]
    API_MINOR_FIELD_NUMBER: _ClassVar[int]
    SERVER_VERSION_FIELD_NUMBER: _ClassVar[int]
    FEATURES_FIELD_NUMBER: _ClassVar[int]
    RETAINED_REVISIONS_FIELD_NUMBER: _ClassVar[int]
    MAX_REQUEST_BYTES_FIELD_NUMBER: _ClassVar[int]
    UPTIME_SECONDS_FIELD_NUMBER: _ClassVar[int]
    LAUNCH_ARGS_FIELD_NUMBER: _ClassVar[int]
    SOCKET_ACTIVATED_FIELD_NUMBER: _ClassVar[int]
    api_major: str
    api_minor: int
    server_version: str
    features: _containers.RepeatedScalarFieldContainer[str]
    retained_revisions: int
    max_request_bytes: int
    uptime_seconds: int
    launch_args: _containers.RepeatedScalarFieldContainer[str]
    socket_activated: bool
    def __init__(self, api_major: _Optional[str] = ..., api_minor: _Optional[int] = ..., server_version: _Optional[str] = ..., features: _Optional[_Iterable[str]] = ..., retained_revisions: _Optional[int] = ..., max_request_bytes: _Optional[int] = ..., uptime_seconds: _Optional[int] = ..., launch_args: _Optional[_Iterable[str]] = ..., socket_activated: _Optional[bool] = ...) -> None: ...
