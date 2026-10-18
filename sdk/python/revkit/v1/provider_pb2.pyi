from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ProviderRunStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PROVIDER_RUN_STATUS_UNSPECIFIED: _ClassVar[ProviderRunStatus]
    PROVIDER_RUN_STATUS_OK: _ClassVar[ProviderRunStatus]
    PROVIDER_RUN_STATUS_FAILED: _ClassVar[ProviderRunStatus]
    PROVIDER_RUN_STATUS_CRASHED: _ClassVar[ProviderRunStatus]
    PROVIDER_RUN_STATUS_TIMEOUT: _ClassVar[ProviderRunStatus]
    PROVIDER_RUN_STATUS_OUT_OF_MEMORY: _ClassVar[ProviderRunStatus]
    PROVIDER_RUN_STATUS_OUTPUT_LIMIT: _ClassVar[ProviderRunStatus]
    PROVIDER_RUN_STATUS_SANDBOX_ERROR: _ClassVar[ProviderRunStatus]
PROVIDER_RUN_STATUS_UNSPECIFIED: ProviderRunStatus
PROVIDER_RUN_STATUS_OK: ProviderRunStatus
PROVIDER_RUN_STATUS_FAILED: ProviderRunStatus
PROVIDER_RUN_STATUS_CRASHED: ProviderRunStatus
PROVIDER_RUN_STATUS_TIMEOUT: ProviderRunStatus
PROVIDER_RUN_STATUS_OUT_OF_MEMORY: ProviderRunStatus
PROVIDER_RUN_STATUS_OUTPUT_LIMIT: ProviderRunStatus
PROVIDER_RUN_STATUS_SANDBOX_ERROR: ProviderRunStatus

class ProviderInput(_message.Message):
    __slots__ = ("program_id", "file")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    FILE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    file: ProviderFileRef
    def __init__(self, program_id: _Optional[str] = ..., file: _Optional[_Union[ProviderFileRef, _Mapping]] = ...) -> None: ...

class ProviderFileRef(_message.Message):
    __slots__ = ("session_id", "path")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    path: str
    def __init__(self, session_id: _Optional[str] = ..., path: _Optional[str] = ...) -> None: ...

class ProviderInputKind(_message.Message):
    __slots__ = ("kind", "version", "description")
    KIND_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    kind: str
    version: str
    description: str
    def __init__(self, kind: _Optional[str] = ..., version: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class ProviderInfo(_message.Message):
    __slots__ = ("name", "title", "tool", "license", "homepage", "kinds", "output", "language", "available", "disabled", "version", "reason", "path", "found_by", "read_paths")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    TOOL_FIELD_NUMBER: _ClassVar[int]
    LICENSE_FIELD_NUMBER: _ClassVar[int]
    HOMEPAGE_FIELD_NUMBER: _ClassVar[int]
    KINDS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    AVAILABLE_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    FOUND_BY_FIELD_NUMBER: _ClassVar[int]
    READ_PATHS_FIELD_NUMBER: _ClassVar[int]
    name: str
    title: str
    tool: str
    license: str
    homepage: str
    kinds: _containers.RepeatedScalarFieldContainer[str]
    output: str
    language: str
    available: bool
    disabled: bool
    version: str
    reason: str
    path: str
    found_by: str
    read_paths: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, name: _Optional[str] = ..., title: _Optional[str] = ..., tool: _Optional[str] = ..., license: _Optional[str] = ..., homepage: _Optional[str] = ..., kinds: _Optional[_Iterable[str]] = ..., output: _Optional[str] = ..., language: _Optional[str] = ..., available: _Optional[bool] = ..., disabled: _Optional[bool] = ..., version: _Optional[str] = ..., reason: _Optional[str] = ..., path: _Optional[str] = ..., found_by: _Optional[str] = ..., read_paths: _Optional[_Iterable[str]] = ...) -> None: ...

class ListProvidersRequest(_message.Message):
    __slots__ = ("input", "refresh")
    INPUT_FIELD_NUMBER: _ClassVar[int]
    REFRESH_FIELD_NUMBER: _ClassVar[int]
    input: ProviderInput
    refresh: bool
    def __init__(self, input: _Optional[_Union[ProviderInput, _Mapping]] = ..., refresh: _Optional[bool] = ...) -> None: ...

class ListProvidersResponse(_message.Message):
    __slots__ = ("providers", "input_kind", "applicable", "default_provider", "cached", "sandbox", "limits")
    PROVIDERS_FIELD_NUMBER: _ClassVar[int]
    INPUT_KIND_FIELD_NUMBER: _ClassVar[int]
    APPLICABLE_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_PROVIDER_FIELD_NUMBER: _ClassVar[int]
    CACHED_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_FIELD_NUMBER: _ClassVar[int]
    LIMITS_FIELD_NUMBER: _ClassVar[int]
    providers: _containers.RepeatedCompositeFieldContainer[ProviderInfo]
    input_kind: ProviderInputKind
    applicable: _containers.RepeatedScalarFieldContainer[str]
    default_provider: str
    cached: _containers.RepeatedScalarFieldContainer[str]
    sandbox: str
    limits: ProviderLimits
    def __init__(self, providers: _Optional[_Iterable[_Union[ProviderInfo, _Mapping]]] = ..., input_kind: _Optional[_Union[ProviderInputKind, _Mapping]] = ..., applicable: _Optional[_Iterable[str]] = ..., default_provider: _Optional[str] = ..., cached: _Optional[_Iterable[str]] = ..., sandbox: _Optional[str] = ..., limits: _Optional[_Union[ProviderLimits, _Mapping]] = ...) -> None: ...

class ProviderLimits(_message.Message):
    __slots__ = ("timeout_seconds", "memory_bytes", "output_bytes", "output_files", "max_input_bytes")
    TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_BYTES_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_BYTES_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FILES_FIELD_NUMBER: _ClassVar[int]
    MAX_INPUT_BYTES_FIELD_NUMBER: _ClassVar[int]
    timeout_seconds: int
    memory_bytes: int
    output_bytes: int
    output_files: int
    max_input_bytes: int
    def __init__(self, timeout_seconds: _Optional[int] = ..., memory_bytes: _Optional[int] = ..., output_bytes: _Optional[int] = ..., output_files: _Optional[int] = ..., max_input_bytes: _Optional[int] = ...) -> None: ...

class ProviderOutputFile(_message.Message):
    __slots__ = ("path", "size", "language")
    PATH_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    path: str
    size: int
    language: str
    def __init__(self, path: _Optional[str] = ..., size: _Optional[int] = ..., language: _Optional[str] = ...) -> None: ...

class DecompileExternalRequest(_message.Message):
    __slots__ = ("input", "provider", "refresh", "max_inline_bytes")
    INPUT_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    REFRESH_FIELD_NUMBER: _ClassVar[int]
    MAX_INLINE_BYTES_FIELD_NUMBER: _ClassVar[int]
    input: ProviderInput
    provider: str
    refresh: bool
    max_inline_bytes: int
    def __init__(self, input: _Optional[_Union[ProviderInput, _Mapping]] = ..., provider: _Optional[str] = ..., refresh: _Optional[bool] = ..., max_inline_bytes: _Optional[int] = ...) -> None: ...

class DecompileExternalResponse(_message.Message):
    __slots__ = ("provider", "provider_version", "input_kind", "input_sha256", "status", "detail", "stderr_tail", "seconds", "cached", "output", "language", "files", "total_bytes", "main_file", "main_text", "main_truncated", "sandbox")
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_VERSION_FIELD_NUMBER: _ClassVar[int]
    INPUT_KIND_FIELD_NUMBER: _ClassVar[int]
    INPUT_SHA256_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    STDERR_TAIL_FIELD_NUMBER: _ClassVar[int]
    SECONDS_FIELD_NUMBER: _ClassVar[int]
    CACHED_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    FILES_FIELD_NUMBER: _ClassVar[int]
    TOTAL_BYTES_FIELD_NUMBER: _ClassVar[int]
    MAIN_FILE_FIELD_NUMBER: _ClassVar[int]
    MAIN_TEXT_FIELD_NUMBER: _ClassVar[int]
    MAIN_TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_FIELD_NUMBER: _ClassVar[int]
    provider: str
    provider_version: str
    input_kind: ProviderInputKind
    input_sha256: str
    status: ProviderRunStatus
    detail: str
    stderr_tail: str
    seconds: float
    cached: bool
    output: str
    language: str
    files: _containers.RepeatedCompositeFieldContainer[ProviderOutputFile]
    total_bytes: int
    main_file: str
    main_text: str
    main_truncated: bool
    sandbox: str
    def __init__(self, provider: _Optional[str] = ..., provider_version: _Optional[str] = ..., input_kind: _Optional[_Union[ProviderInputKind, _Mapping]] = ..., input_sha256: _Optional[str] = ..., status: _Optional[_Union[ProviderRunStatus, str]] = ..., detail: _Optional[str] = ..., stderr_tail: _Optional[str] = ..., seconds: _Optional[float] = ..., cached: _Optional[bool] = ..., output: _Optional[str] = ..., language: _Optional[str] = ..., files: _Optional[_Iterable[_Union[ProviderOutputFile, _Mapping]]] = ..., total_bytes: _Optional[int] = ..., main_file: _Optional[str] = ..., main_text: _Optional[str] = ..., main_truncated: _Optional[bool] = ..., sandbox: _Optional[str] = ...) -> None: ...

class ReadProviderOutputRequest(_message.Message):
    __slots__ = ("input", "provider", "path", "offset", "max_bytes")
    INPUT_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    MAX_BYTES_FIELD_NUMBER: _ClassVar[int]
    input: ProviderInput
    provider: str
    path: str
    offset: int
    max_bytes: int
    def __init__(self, input: _Optional[_Union[ProviderInput, _Mapping]] = ..., provider: _Optional[str] = ..., path: _Optional[str] = ..., offset: _Optional[int] = ..., max_bytes: _Optional[int] = ...) -> None: ...

class ReadProviderOutputResponse(_message.Message):
    __slots__ = ("path", "data", "size", "language", "truncated")
    PATH_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    path: str
    data: bytes
    size: int
    language: str
    truncated: bool
    def __init__(self, path: _Optional[str] = ..., data: _Optional[bytes] = ..., size: _Optional[int] = ..., language: _Optional[str] = ..., truncated: _Optional[bool] = ...) -> None: ...

class ProviderSettings(_message.Message):
    __slots__ = ("enabled", "providers", "java_path", "node_path", "dotnet_root", "timeout_seconds", "memory_bytes", "output_bytes", "output_files", "max_input_bytes", "cache_max_bytes", "allow_weak_sandbox")
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    PROVIDERS_FIELD_NUMBER: _ClassVar[int]
    JAVA_PATH_FIELD_NUMBER: _ClassVar[int]
    NODE_PATH_FIELD_NUMBER: _ClassVar[int]
    DOTNET_ROOT_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_BYTES_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_BYTES_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FILES_FIELD_NUMBER: _ClassVar[int]
    MAX_INPUT_BYTES_FIELD_NUMBER: _ClassVar[int]
    CACHE_MAX_BYTES_FIELD_NUMBER: _ClassVar[int]
    ALLOW_WEAK_SANDBOX_FIELD_NUMBER: _ClassVar[int]
    enabled: bool
    providers: _containers.RepeatedCompositeFieldContainer[ProviderConfig]
    java_path: str
    node_path: str
    dotnet_root: str
    timeout_seconds: int
    memory_bytes: int
    output_bytes: int
    output_files: int
    max_input_bytes: int
    cache_max_bytes: int
    allow_weak_sandbox: bool
    def __init__(self, enabled: _Optional[bool] = ..., providers: _Optional[_Iterable[_Union[ProviderConfig, _Mapping]]] = ..., java_path: _Optional[str] = ..., node_path: _Optional[str] = ..., dotnet_root: _Optional[str] = ..., timeout_seconds: _Optional[int] = ..., memory_bytes: _Optional[int] = ..., output_bytes: _Optional[int] = ..., output_files: _Optional[int] = ..., max_input_bytes: _Optional[int] = ..., cache_max_bytes: _Optional[int] = ..., allow_weak_sandbox: _Optional[bool] = ...) -> None: ...

class ProviderConfig(_message.Message):
    __slots__ = ("name", "path", "disabled")
    NAME_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    name: str
    path: str
    disabled: bool
    def __init__(self, name: _Optional[str] = ..., path: _Optional[str] = ..., disabled: _Optional[bool] = ...) -> None: ...

class GetProviderSettingsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetProviderSettingsResponse(_message.Message):
    __slots__ = ("settings", "cache_dir")
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    CACHE_DIR_FIELD_NUMBER: _ClassVar[int]
    settings: ProviderSettings
    cache_dir: str
    def __init__(self, settings: _Optional[_Union[ProviderSettings, _Mapping]] = ..., cache_dir: _Optional[str] = ...) -> None: ...

class SetProviderSettingsRequest(_message.Message):
    __slots__ = ("settings",)
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    settings: ProviderSettings
    def __init__(self, settings: _Optional[_Union[ProviderSettings, _Mapping]] = ...) -> None: ...

class SetProviderSettingsResponse(_message.Message):
    __slots__ = ("settings", "providers")
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    PROVIDERS_FIELD_NUMBER: _ClassVar[int]
    settings: ProviderSettings
    providers: _containers.RepeatedCompositeFieldContainer[ProviderInfo]
    def __init__(self, settings: _Optional[_Union[ProviderSettings, _Mapping]] = ..., providers: _Optional[_Iterable[_Union[ProviderInfo, _Mapping]]] = ...) -> None: ...
