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

class Role(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ROLE_UNSPECIFIED: _ClassVar[Role]
    ROLE_VIEWER: _ClassVar[Role]
    ROLE_EDITOR: _ClassVar[Role]
    ROLE_ADMIN: _ClassVar[Role]
    ROLE_PEER: _ClassVar[Role]

class PrincipalKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PRINCIPAL_KIND_UNSPECIFIED: _ClassVar[PrincipalKind]
    PRINCIPAL_KIND_USER: _ClassVar[PrincipalKind]
    PRINCIPAL_KIND_AGENT: _ClassVar[PrincipalKind]
    PRINCIPAL_KIND_PEER: _ClassVar[PrincipalKind]
    PRINCIPAL_KIND_ANONYMOUS: _ClassVar[PrincipalKind]

class AuthMethod(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AUTH_METHOD_UNSPECIFIED: _ClassVar[AuthMethod]
    AUTH_METHOD_NONE: _ClassVar[AuthMethod]
    AUTH_METHOD_SESSION: _ClassVar[AuthMethod]
    AUTH_METHOD_TOKEN: _ClassVar[AuthMethod]
    AUTH_METHOD_PEER_SECRET: _ClassVar[AuthMethod]
ROLE_UNSPECIFIED: Role
ROLE_VIEWER: Role
ROLE_EDITOR: Role
ROLE_ADMIN: Role
ROLE_PEER: Role
PRINCIPAL_KIND_UNSPECIFIED: PrincipalKind
PRINCIPAL_KIND_USER: PrincipalKind
PRINCIPAL_KIND_AGENT: PrincipalKind
PRINCIPAL_KIND_PEER: PrincipalKind
PRINCIPAL_KIND_ANONYMOUS: PrincipalKind
AUTH_METHOD_UNSPECIFIED: AuthMethod
AUTH_METHOD_NONE: AuthMethod
AUTH_METHOD_SESSION: AuthMethod
AUTH_METHOD_TOKEN: AuthMethod
AUTH_METHOD_PEER_SECRET: AuthMethod

class Identity(_message.Message):
    __slots__ = ("kind", "name", "role", "projects", "method", "provenance", "expires_at")
    KIND_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    PROJECTS_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    kind: PrincipalKind
    name: str
    role: Role
    projects: _containers.RepeatedScalarFieldContainer[str]
    method: AuthMethod
    provenance: _common_pb2.Provenance
    expires_at: _timestamp_pb2.Timestamp
    def __init__(self, kind: _Optional[_Union[PrincipalKind, str]] = ..., name: _Optional[str] = ..., role: _Optional[_Union[Role, str]] = ..., projects: _Optional[_Iterable[str]] = ..., method: _Optional[_Union[AuthMethod, str]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class LoginRequest(_message.Message):
    __slots__ = ("username", "password", "session_cookie", "client")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    PASSWORD_FIELD_NUMBER: _ClassVar[int]
    SESSION_COOKIE_FIELD_NUMBER: _ClassVar[int]
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    username: str
    password: str
    session_cookie: bool
    client: str
    def __init__(self, username: _Optional[str] = ..., password: _Optional[str] = ..., session_cookie: _Optional[bool] = ..., client: _Optional[str] = ...) -> None: ...

class LoginResponse(_message.Message):
    __slots__ = ("token", "expires_at", "identity", "csrf_token")
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    CSRF_TOKEN_FIELD_NUMBER: _ClassVar[int]
    token: str
    expires_at: _timestamp_pb2.Timestamp
    identity: Identity
    csrf_token: str
    def __init__(self, token: _Optional[str] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., identity: _Optional[_Union[Identity, _Mapping]] = ..., csrf_token: _Optional[str] = ...) -> None: ...

class LogoutRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class LogoutResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class WhoAmIRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class WhoAmIResponse(_message.Message):
    __slots__ = ("auth_enabled", "identity", "csrf_token")
    AUTH_ENABLED_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    CSRF_TOKEN_FIELD_NUMBER: _ClassVar[int]
    auth_enabled: bool
    identity: Identity
    csrf_token: str
    def __init__(self, auth_enabled: _Optional[bool] = ..., identity: _Optional[_Union[Identity, _Mapping]] = ..., csrf_token: _Optional[str] = ...) -> None: ...

class ChangePasswordRequest(_message.Message):
    __slots__ = ("old_password", "new_password")
    OLD_PASSWORD_FIELD_NUMBER: _ClassVar[int]
    NEW_PASSWORD_FIELD_NUMBER: _ClassVar[int]
    old_password: str
    new_password: str
    def __init__(self, old_password: _Optional[str] = ..., new_password: _Optional[str] = ...) -> None: ...

class ChangePasswordResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class User(_message.Message):
    __slots__ = ("name", "role", "projects", "created_at")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    PROJECTS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    name: str
    role: Role
    projects: _containers.RepeatedScalarFieldContainer[str]
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, name: _Optional[str] = ..., role: _Optional[_Union[Role, str]] = ..., projects: _Optional[_Iterable[str]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListUsersRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListUsersResponse(_message.Message):
    __slots__ = ("users",)
    USERS_FIELD_NUMBER: _ClassVar[int]
    users: _containers.RepeatedCompositeFieldContainer[User]
    def __init__(self, users: _Optional[_Iterable[_Union[User, _Mapping]]] = ...) -> None: ...

class CreateUserRequest(_message.Message):
    __slots__ = ("name", "role", "password", "projects")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    PASSWORD_FIELD_NUMBER: _ClassVar[int]
    PROJECTS_FIELD_NUMBER: _ClassVar[int]
    name: str
    role: Role
    password: str
    projects: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, name: _Optional[str] = ..., role: _Optional[_Union[Role, str]] = ..., password: _Optional[str] = ..., projects: _Optional[_Iterable[str]] = ...) -> None: ...

class CreateUserResponse(_message.Message):
    __slots__ = ("user",)
    USER_FIELD_NUMBER: _ClassVar[int]
    user: User
    def __init__(self, user: _Optional[_Union[User, _Mapping]] = ...) -> None: ...

class UpdateUserRequest(_message.Message):
    __slots__ = ("name", "role", "password", "set_projects", "projects")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    PASSWORD_FIELD_NUMBER: _ClassVar[int]
    SET_PROJECTS_FIELD_NUMBER: _ClassVar[int]
    PROJECTS_FIELD_NUMBER: _ClassVar[int]
    name: str
    role: Role
    password: str
    set_projects: bool
    projects: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, name: _Optional[str] = ..., role: _Optional[_Union[Role, str]] = ..., password: _Optional[str] = ..., set_projects: _Optional[bool] = ..., projects: _Optional[_Iterable[str]] = ...) -> None: ...

class UpdateUserResponse(_message.Message):
    __slots__ = ("user",)
    USER_FIELD_NUMBER: _ClassVar[int]
    user: User
    def __init__(self, user: _Optional[_Union[User, _Mapping]] = ...) -> None: ...

class DeleteUserRequest(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class DeleteUserResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ApiToken(_message.Message):
    __slots__ = ("id", "name", "role", "user", "projects", "created_at", "expires_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    USER_FIELD_NUMBER: _ClassVar[int]
    PROJECTS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    role: Role
    user: str
    projects: _containers.RepeatedScalarFieldContainer[str]
    created_at: _timestamp_pb2.Timestamp
    expires_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., role: _Optional[_Union[Role, str]] = ..., user: _Optional[str] = ..., projects: _Optional[_Iterable[str]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListTokensRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListTokensResponse(_message.Message):
    __slots__ = ("tokens",)
    TOKENS_FIELD_NUMBER: _ClassVar[int]
    tokens: _containers.RepeatedCompositeFieldContainer[ApiToken]
    def __init__(self, tokens: _Optional[_Iterable[_Union[ApiToken, _Mapping]]] = ...) -> None: ...

class CreateTokenRequest(_message.Message):
    __slots__ = ("name", "role", "user", "projects", "ttl_seconds")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    USER_FIELD_NUMBER: _ClassVar[int]
    PROJECTS_FIELD_NUMBER: _ClassVar[int]
    TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    name: str
    role: Role
    user: str
    projects: _containers.RepeatedScalarFieldContainer[str]
    ttl_seconds: int
    def __init__(self, name: _Optional[str] = ..., role: _Optional[_Union[Role, str]] = ..., user: _Optional[str] = ..., projects: _Optional[_Iterable[str]] = ..., ttl_seconds: _Optional[int] = ...) -> None: ...

class CreateTokenResponse(_message.Message):
    __slots__ = ("token", "secret")
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    SECRET_FIELD_NUMBER: _ClassVar[int]
    token: ApiToken
    secret: str
    def __init__(self, token: _Optional[_Union[ApiToken, _Mapping]] = ..., secret: _Optional[str] = ...) -> None: ...

class RevokeTokenRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    def __init__(self, id: _Optional[str] = ...) -> None: ...

class RevokeTokenResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
