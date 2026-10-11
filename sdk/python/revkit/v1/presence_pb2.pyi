import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from revkit.v1 import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Presence(_message.Message):
    __slots__ = ("client_id", "who", "display_name", "program_id", "address", "selection", "view", "sequence", "expires_at", "left", "origin_replica")
    CLIENT_ID_FIELD_NUMBER: _ClassVar[int]
    WHO_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_NAME_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SELECTION_FIELD_NUMBER: _ClassVar[int]
    VIEW_FIELD_NUMBER: _ClassVar[int]
    SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    LEFT_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_REPLICA_FIELD_NUMBER: _ClassVar[int]
    client_id: str
    who: _common_pb2.Provenance
    display_name: str
    program_id: str
    address: _common_pb2.Address
    selection: _common_pb2.AddressRange
    view: str
    sequence: int
    expires_at: _timestamp_pb2.Timestamp
    left: bool
    origin_replica: int
    def __init__(self, client_id: _Optional[str] = ..., who: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., display_name: _Optional[str] = ..., program_id: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., selection: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., view: _Optional[str] = ..., sequence: _Optional[int] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., left: _Optional[bool] = ..., origin_replica: _Optional[int] = ...) -> None: ...

class UpdatePresenceRequest(_message.Message):
    __slots__ = ("project_id", "presence", "ttl_seconds")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PRESENCE_FIELD_NUMBER: _ClassVar[int]
    TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    presence: Presence
    ttl_seconds: int
    def __init__(self, project_id: _Optional[str] = ..., presence: _Optional[_Union[Presence, _Mapping]] = ..., ttl_seconds: _Optional[int] = ...) -> None: ...

class UpdatePresenceResponse(_message.Message):
    __slots__ = ("presence",)
    PRESENCE_FIELD_NUMBER: _ClassVar[int]
    presence: Presence
    def __init__(self, presence: _Optional[_Union[Presence, _Mapping]] = ...) -> None: ...

class ListPresenceRequest(_message.Message):
    __slots__ = ("project_id", "program_id")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    program_id: str
    def __init__(self, project_id: _Optional[str] = ..., program_id: _Optional[str] = ...) -> None: ...

class ListPresenceResponse(_message.Message):
    __slots__ = ("presence",)
    PRESENCE_FIELD_NUMBER: _ClassVar[int]
    presence: _containers.RepeatedCompositeFieldContainer[Presence]
    def __init__(self, presence: _Optional[_Iterable[_Union[Presence, _Mapping]]] = ...) -> None: ...
