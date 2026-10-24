import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from revkit.v1 import apple_pb2 as _apple_pb2
from revkit.v1 import common_pb2 as _common_pb2
from revkit.v1 import project_pb2 as _project_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class FileSystemEntryKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FILE_SYSTEM_ENTRY_KIND_UNSPECIFIED: _ClassVar[FileSystemEntryKind]
    FILE_SYSTEM_ENTRY_KIND_FILE: _ClassVar[FileSystemEntryKind]
    FILE_SYSTEM_ENTRY_KIND_DIRECTORY: _ClassVar[FileSystemEntryKind]
    FILE_SYSTEM_ENTRY_KIND_SYMLINK: _ClassVar[FileSystemEntryKind]
    FILE_SYSTEM_ENTRY_KIND_HARDLINK: _ClassVar[FileSystemEntryKind]
    FILE_SYSTEM_ENTRY_KIND_CHAR_DEVICE: _ClassVar[FileSystemEntryKind]
    FILE_SYSTEM_ENTRY_KIND_BLOCK_DEVICE: _ClassVar[FileSystemEntryKind]
    FILE_SYSTEM_ENTRY_KIND_FIFO: _ClassVar[FileSystemEntryKind]
    FILE_SYSTEM_ENTRY_KIND_SOCKET: _ClassVar[FileSystemEntryKind]
    FILE_SYSTEM_ENTRY_KIND_OTHER: _ClassVar[FileSystemEntryKind]
FILE_SYSTEM_ENTRY_KIND_UNSPECIFIED: FileSystemEntryKind
FILE_SYSTEM_ENTRY_KIND_FILE: FileSystemEntryKind
FILE_SYSTEM_ENTRY_KIND_DIRECTORY: FileSystemEntryKind
FILE_SYSTEM_ENTRY_KIND_SYMLINK: FileSystemEntryKind
FILE_SYSTEM_ENTRY_KIND_HARDLINK: FileSystemEntryKind
FILE_SYSTEM_ENTRY_KIND_CHAR_DEVICE: FileSystemEntryKind
FILE_SYSTEM_ENTRY_KIND_BLOCK_DEVICE: FileSystemEntryKind
FILE_SYSTEM_ENTRY_KIND_FIFO: FileSystemEntryKind
FILE_SYSTEM_ENTRY_KIND_SOCKET: FileSystemEntryKind
FILE_SYSTEM_ENTRY_KIND_OTHER: FileSystemEntryKind

class FileSystemLimits(_message.Message):
    __slots__ = ("max_file_bytes", "max_total_bytes", "max_depth", "max_entries", "max_ratio")
    MAX_FILE_BYTES_FIELD_NUMBER: _ClassVar[int]
    MAX_TOTAL_BYTES_FIELD_NUMBER: _ClassVar[int]
    MAX_DEPTH_FIELD_NUMBER: _ClassVar[int]
    MAX_ENTRIES_FIELD_NUMBER: _ClassVar[int]
    MAX_RATIO_FIELD_NUMBER: _ClassVar[int]
    max_file_bytes: int
    max_total_bytes: int
    max_depth: int
    max_entries: int
    max_ratio: int
    def __init__(self, max_file_bytes: _Optional[int] = ..., max_total_bytes: _Optional[int] = ..., max_depth: _Optional[int] = ..., max_entries: _Optional[int] = ..., max_ratio: _Optional[int] = ...) -> None: ...

class OpenFileSystemRequest(_message.Message):
    __slots__ = ("project_id", "host_path", "program_id", "upload_id", "content", "name", "limits")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    HOST_PATH_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    UPLOAD_ID_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    LIMITS_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    host_path: str
    program_id: str
    upload_id: str
    content: bytes
    name: str
    limits: FileSystemLimits
    def __init__(self, project_id: _Optional[str] = ..., host_path: _Optional[str] = ..., program_id: _Optional[str] = ..., upload_id: _Optional[str] = ..., content: _Optional[bytes] = ..., name: _Optional[str] = ..., limits: _Optional[_Union[FileSystemLimits, _Mapping]] = ...) -> None: ...

class FileSystemLayer(_message.Message):
    __slots__ = ("format", "description", "warnings", "path", "container_path", "depth")
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    CONTAINER_PATH_FIELD_NUMBER: _ClassVar[int]
    DEPTH_FIELD_NUMBER: _ClassVar[int]
    format: str
    description: str
    warnings: _containers.RepeatedScalarFieldContainer[str]
    path: str
    container_path: str
    depth: int
    def __init__(self, format: _Optional[str] = ..., description: _Optional[str] = ..., warnings: _Optional[_Iterable[str]] = ..., path: _Optional[str] = ..., container_path: _Optional[str] = ..., depth: _Optional[int] = ...) -> None: ...

class OpenFileSystemResponse(_message.Message):
    __slots__ = ("session_id", "name", "root", "limits")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ROOT_FIELD_NUMBER: _ClassVar[int]
    LIMITS_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    name: str
    root: FileSystemLayer
    limits: FileSystemLimits
    def __init__(self, session_id: _Optional[str] = ..., name: _Optional[str] = ..., root: _Optional[_Union[FileSystemLayer, _Mapping]] = ..., limits: _Optional[_Union[FileSystemLimits, _Mapping]] = ...) -> None: ...

class FileSystemEntry(_message.Message):
    __slots__ = ("name", "path", "kind", "size", "size_unknown", "stored_size", "permissions", "mode", "has_owner", "uid", "gid", "modified", "link_target", "link_path", "note", "unreadable", "renamed", "detected", "detected_kind", "container_format", "processor", "child_count", "language_id", "load_address", "has_load_address", "content_kind", "bundle_kind")
    NAME_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    SIZE_UNKNOWN_FIELD_NUMBER: _ClassVar[int]
    STORED_SIZE_FIELD_NUMBER: _ClassVar[int]
    PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    HAS_OWNER_FIELD_NUMBER: _ClassVar[int]
    UID_FIELD_NUMBER: _ClassVar[int]
    GID_FIELD_NUMBER: _ClassVar[int]
    MODIFIED_FIELD_NUMBER: _ClassVar[int]
    LINK_TARGET_FIELD_NUMBER: _ClassVar[int]
    LINK_PATH_FIELD_NUMBER: _ClassVar[int]
    NOTE_FIELD_NUMBER: _ClassVar[int]
    UNREADABLE_FIELD_NUMBER: _ClassVar[int]
    RENAMED_FIELD_NUMBER: _ClassVar[int]
    DETECTED_FIELD_NUMBER: _ClassVar[int]
    DETECTED_KIND_FIELD_NUMBER: _ClassVar[int]
    CONTAINER_FORMAT_FIELD_NUMBER: _ClassVar[int]
    PROCESSOR_FIELD_NUMBER: _ClassVar[int]
    CHILD_COUNT_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_ID_FIELD_NUMBER: _ClassVar[int]
    LOAD_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    HAS_LOAD_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    CONTENT_KIND_FIELD_NUMBER: _ClassVar[int]
    BUNDLE_KIND_FIELD_NUMBER: _ClassVar[int]
    name: str
    path: str
    kind: FileSystemEntryKind
    size: int
    size_unknown: bool
    stored_size: int
    permissions: str
    mode: int
    has_owner: bool
    uid: int
    gid: int
    modified: _timestamp_pb2.Timestamp
    link_target: str
    link_path: str
    note: str
    unreadable: bool
    renamed: bool
    detected: str
    detected_kind: str
    container_format: str
    processor: str
    child_count: int
    language_id: str
    load_address: int
    has_load_address: bool
    content_kind: str
    bundle_kind: str
    def __init__(self, name: _Optional[str] = ..., path: _Optional[str] = ..., kind: _Optional[_Union[FileSystemEntryKind, str]] = ..., size: _Optional[int] = ..., size_unknown: _Optional[bool] = ..., stored_size: _Optional[int] = ..., permissions: _Optional[str] = ..., mode: _Optional[int] = ..., has_owner: _Optional[bool] = ..., uid: _Optional[int] = ..., gid: _Optional[int] = ..., modified: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., link_target: _Optional[str] = ..., link_path: _Optional[str] = ..., note: _Optional[str] = ..., unreadable: _Optional[bool] = ..., renamed: _Optional[bool] = ..., detected: _Optional[str] = ..., detected_kind: _Optional[str] = ..., container_format: _Optional[str] = ..., processor: _Optional[str] = ..., child_count: _Optional[int] = ..., language_id: _Optional[str] = ..., load_address: _Optional[int] = ..., has_load_address: _Optional[bool] = ..., content_kind: _Optional[str] = ..., bundle_kind: _Optional[str] = ...) -> None: ...

class ListFileSystemRequest(_message.Message):
    __slots__ = ("session_id", "path", "detect", "recursive", "offset", "limit")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    DETECT_FIELD_NUMBER: _ClassVar[int]
    RECURSIVE_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    path: str
    detect: bool
    recursive: bool
    offset: int
    limit: int
    def __init__(self, session_id: _Optional[str] = ..., path: _Optional[str] = ..., detect: _Optional[bool] = ..., recursive: _Optional[bool] = ..., offset: _Optional[int] = ..., limit: _Optional[int] = ...) -> None: ...

class ListFileSystemResponse(_message.Message):
    __slots__ = ("layer", "directory", "entries", "total", "detect_incomplete")
    LAYER_FIELD_NUMBER: _ClassVar[int]
    DIRECTORY_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    DETECT_INCOMPLETE_FIELD_NUMBER: _ClassVar[int]
    layer: FileSystemLayer
    directory: FileSystemEntry
    entries: _containers.RepeatedCompositeFieldContainer[FileSystemEntry]
    total: int
    detect_incomplete: bool
    def __init__(self, layer: _Optional[_Union[FileSystemLayer, _Mapping]] = ..., directory: _Optional[_Union[FileSystemEntry, _Mapping]] = ..., entries: _Optional[_Iterable[_Union[FileSystemEntry, _Mapping]]] = ..., total: _Optional[int] = ..., detect_incomplete: _Optional[bool] = ...) -> None: ...

class ReadFileSystemFileRequest(_message.Message):
    __slots__ = ("session_id", "path", "offset", "length")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    path: str
    offset: int
    length: int
    def __init__(self, session_id: _Optional[str] = ..., path: _Optional[str] = ..., offset: _Optional[int] = ..., length: _Optional[int] = ...) -> None: ...

class ReadFileSystemFileResponse(_message.Message):
    __slots__ = ("data", "size", "eof")
    DATA_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    EOF_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    size: int
    eof: bool
    def __init__(self, data: _Optional[bytes] = ..., size: _Optional[int] = ..., eof: _Optional[bool] = ...) -> None: ...

class GetFileSystemFileInfoRequest(_message.Message):
    __slots__ = ("session_id", "path", "hashes")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    HASHES_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    path: str
    hashes: bool
    def __init__(self, session_id: _Optional[str] = ..., path: _Optional[str] = ..., hashes: _Optional[bool] = ...) -> None: ...

class GetFileSystemFileInfoResponse(_message.Message):
    __slots__ = ("entry", "container_path", "sha256", "sha1", "md5", "magic", "container", "layer")
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    CONTAINER_PATH_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    SHA1_FIELD_NUMBER: _ClassVar[int]
    MD5_FIELD_NUMBER: _ClassVar[int]
    MAGIC_FIELD_NUMBER: _ClassVar[int]
    CONTAINER_FIELD_NUMBER: _ClassVar[int]
    LAYER_FIELD_NUMBER: _ClassVar[int]
    entry: FileSystemEntry
    container_path: str
    sha256: str
    sha1: str
    md5: str
    magic: bytes
    container: FileSystemLayer
    layer: FileSystemLayer
    def __init__(self, entry: _Optional[_Union[FileSystemEntry, _Mapping]] = ..., container_path: _Optional[str] = ..., sha256: _Optional[str] = ..., sha1: _Optional[str] = ..., md5: _Optional[str] = ..., magic: _Optional[bytes] = ..., container: _Optional[_Union[FileSystemLayer, _Mapping]] = ..., layer: _Optional[_Union[FileSystemLayer, _Mapping]] = ...) -> None: ...

class ImportFromFileSystemRequest(_message.Message):
    __slots__ = ("session_id", "project_id", "folder_id", "paths", "recursive", "descend", "programs_only", "detect_raw", "preview", "max_programs", "options", "keep_folders", "provenance")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    FOLDER_ID_FIELD_NUMBER: _ClassVar[int]
    PATHS_FIELD_NUMBER: _ClassVar[int]
    RECURSIVE_FIELD_NUMBER: _ClassVar[int]
    DESCEND_FIELD_NUMBER: _ClassVar[int]
    PROGRAMS_ONLY_FIELD_NUMBER: _ClassVar[int]
    DETECT_RAW_FIELD_NUMBER: _ClassVar[int]
    PREVIEW_FIELD_NUMBER: _ClassVar[int]
    MAX_PROGRAMS_FIELD_NUMBER: _ClassVar[int]
    OPTIONS_FIELD_NUMBER: _ClassVar[int]
    KEEP_FOLDERS_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    project_id: str
    folder_id: str
    paths: _containers.RepeatedScalarFieldContainer[str]
    recursive: bool
    descend: bool
    programs_only: bool
    detect_raw: bool
    preview: bool
    max_programs: int
    options: _project_pb2.ImportOptions
    keep_folders: bool
    provenance: _common_pb2.Provenance
    def __init__(self, session_id: _Optional[str] = ..., project_id: _Optional[str] = ..., folder_id: _Optional[str] = ..., paths: _Optional[_Iterable[str]] = ..., recursive: _Optional[bool] = ..., descend: _Optional[bool] = ..., programs_only: _Optional[bool] = ..., detect_raw: _Optional[bool] = ..., preview: _Optional[bool] = ..., max_programs: _Optional[int] = ..., options: _Optional[_Union[_project_pb2.ImportOptions, _Mapping]] = ..., keep_folders: _Optional[bool] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class FileSystemImport(_message.Message):
    __slots__ = ("path", "container_path", "detected", "action", "reason", "program", "warnings", "language_id", "library_of")
    PATH_FIELD_NUMBER: _ClassVar[int]
    CONTAINER_PATH_FIELD_NUMBER: _ClassVar[int]
    DETECTED_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_ID_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_OF_FIELD_NUMBER: _ClassVar[int]
    path: str
    container_path: str
    detected: str
    action: str
    reason: str
    program: _project_pb2.ProgramInfo
    warnings: _containers.RepeatedScalarFieldContainer[str]
    language_id: str
    library_of: str
    def __init__(self, path: _Optional[str] = ..., container_path: _Optional[str] = ..., detected: _Optional[str] = ..., action: _Optional[str] = ..., reason: _Optional[str] = ..., program: _Optional[_Union[_project_pb2.ProgramInfo, _Mapping]] = ..., warnings: _Optional[_Iterable[str]] = ..., language_id: _Optional[str] = ..., library_of: _Optional[str] = ...) -> None: ...

class ImportFromFileSystemResponse(_message.Message):
    __slots__ = ("items", "imported", "skipped", "failed", "capped", "snapshot", "libraries_not_found", "library_warnings")
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    IMPORTED_FIELD_NUMBER: _ClassVar[int]
    SKIPPED_FIELD_NUMBER: _ClassVar[int]
    FAILED_FIELD_NUMBER: _ClassVar[int]
    CAPPED_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    LIBRARIES_NOT_FOUND_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_WARNINGS_FIELD_NUMBER: _ClassVar[int]
    items: _containers.RepeatedCompositeFieldContainer[FileSystemImport]
    imported: int
    skipped: int
    failed: int
    capped: bool
    snapshot: _common_pb2.Snapshot
    libraries_not_found: _containers.RepeatedCompositeFieldContainer[_project_pb2.MissingLibrary]
    library_warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, items: _Optional[_Iterable[_Union[FileSystemImport, _Mapping]]] = ..., imported: _Optional[int] = ..., skipped: _Optional[int] = ..., failed: _Optional[int] = ..., capped: _Optional[bool] = ..., snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., libraries_not_found: _Optional[_Iterable[_Union[_project_pb2.MissingLibrary, _Mapping]]] = ..., library_warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class ExtractFromFileSystemRequest(_message.Message):
    __slots__ = ("session_id", "paths", "host_dir", "overwrite")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PATHS_FIELD_NUMBER: _ClassVar[int]
    HOST_DIR_FIELD_NUMBER: _ClassVar[int]
    OVERWRITE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    paths: _containers.RepeatedScalarFieldContainer[str]
    host_dir: str
    overwrite: bool
    def __init__(self, session_id: _Optional[str] = ..., paths: _Optional[_Iterable[str]] = ..., host_dir: _Optional[str] = ..., overwrite: _Optional[bool] = ...) -> None: ...

class ExtractFromFileSystemResponse(_message.Message):
    __slots__ = ("files", "bytes", "written", "skipped")
    FILES_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    WRITTEN_FIELD_NUMBER: _ClassVar[int]
    SKIPPED_FIELD_NUMBER: _ClassVar[int]
    files: int
    bytes: int
    written: _containers.RepeatedScalarFieldContainer[str]
    skipped: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, files: _Optional[int] = ..., bytes: _Optional[int] = ..., written: _Optional[_Iterable[str]] = ..., skipped: _Optional[_Iterable[str]] = ...) -> None: ...

class CloseFileSystemRequest(_message.Message):
    __slots__ = ("session_id",)
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    def __init__(self, session_id: _Optional[str] = ...) -> None: ...

class CloseFileSystemResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListFileSystemsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class OpenFileSystemSession(_message.Message):
    __slots__ = ("session_id", "name", "format", "project_id", "owner", "opened_at", "held_bytes")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    OPENED_AT_FIELD_NUMBER: _ClassVar[int]
    HELD_BYTES_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    name: str
    format: str
    project_id: str
    owner: str
    opened_at: _timestamp_pb2.Timestamp
    held_bytes: int
    def __init__(self, session_id: _Optional[str] = ..., name: _Optional[str] = ..., format: _Optional[str] = ..., project_id: _Optional[str] = ..., owner: _Optional[str] = ..., opened_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., held_bytes: _Optional[int] = ...) -> None: ...

class ListFileSystemsResponse(_message.Message):
    __slots__ = ("sessions",)
    SESSIONS_FIELD_NUMBER: _ClassVar[int]
    sessions: _containers.RepeatedCompositeFieldContainer[OpenFileSystemSession]
    def __init__(self, sessions: _Optional[_Iterable[_Union[OpenFileSystemSession, _Mapping]]] = ...) -> None: ...

class GetAndroidPackageRequest(_message.Message):
    __slots__ = ("session_id", "path", "skip_native", "skip_dex")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    SKIP_NATIVE_FIELD_NUMBER: _ClassVar[int]
    SKIP_DEX_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    path: str
    skip_native: bool
    skip_dex: bool
    def __init__(self, session_id: _Optional[str] = ..., path: _Optional[str] = ..., skip_native: _Optional[bool] = ..., skip_dex: _Optional[bool] = ...) -> None: ...

class AndroidIntentData(_message.Message):
    __slots__ = ("scheme", "host", "port", "path", "path_prefix", "path_pattern", "mime_type")
    SCHEME_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    PATH_PREFIX_FIELD_NUMBER: _ClassVar[int]
    PATH_PATTERN_FIELD_NUMBER: _ClassVar[int]
    MIME_TYPE_FIELD_NUMBER: _ClassVar[int]
    scheme: str
    host: str
    port: str
    path: str
    path_prefix: str
    path_pattern: str
    mime_type: str
    def __init__(self, scheme: _Optional[str] = ..., host: _Optional[str] = ..., port: _Optional[str] = ..., path: _Optional[str] = ..., path_prefix: _Optional[str] = ..., path_pattern: _Optional[str] = ..., mime_type: _Optional[str] = ...) -> None: ...

class AndroidIntentFilter(_message.Message):
    __slots__ = ("actions", "categories", "data", "priority", "auto_verify")
    ACTIONS_FIELD_NUMBER: _ClassVar[int]
    CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    PRIORITY_FIELD_NUMBER: _ClassVar[int]
    AUTO_VERIFY_FIELD_NUMBER: _ClassVar[int]
    actions: _containers.RepeatedScalarFieldContainer[str]
    categories: _containers.RepeatedScalarFieldContainer[str]
    data: _containers.RepeatedCompositeFieldContainer[AndroidIntentData]
    priority: int
    auto_verify: bool
    def __init__(self, actions: _Optional[_Iterable[str]] = ..., categories: _Optional[_Iterable[str]] = ..., data: _Optional[_Iterable[_Union[AndroidIntentData, _Mapping]]] = ..., priority: _Optional[int] = ..., auto_verify: _Optional[bool] = ...) -> None: ...

class AndroidComponent(_message.Message):
    __slots__ = ("kind", "name", "exported", "exported_explicit", "enabled", "permission", "process", "authorities", "read_permission", "write_permission", "grant_uri_permissions", "target_activity", "launcher", "intent_filters")
    KIND_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    EXPORTED_FIELD_NUMBER: _ClassVar[int]
    EXPORTED_EXPLICIT_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    PERMISSION_FIELD_NUMBER: _ClassVar[int]
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    AUTHORITIES_FIELD_NUMBER: _ClassVar[int]
    READ_PERMISSION_FIELD_NUMBER: _ClassVar[int]
    WRITE_PERMISSION_FIELD_NUMBER: _ClassVar[int]
    GRANT_URI_PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    TARGET_ACTIVITY_FIELD_NUMBER: _ClassVar[int]
    LAUNCHER_FIELD_NUMBER: _ClassVar[int]
    INTENT_FILTERS_FIELD_NUMBER: _ClassVar[int]
    kind: str
    name: str
    exported: bool
    exported_explicit: bool
    enabled: bool
    permission: str
    process: str
    authorities: str
    read_permission: str
    write_permission: str
    grant_uri_permissions: bool
    target_activity: str
    launcher: bool
    intent_filters: _containers.RepeatedCompositeFieldContainer[AndroidIntentFilter]
    def __init__(self, kind: _Optional[str] = ..., name: _Optional[str] = ..., exported: _Optional[bool] = ..., exported_explicit: _Optional[bool] = ..., enabled: _Optional[bool] = ..., permission: _Optional[str] = ..., process: _Optional[str] = ..., authorities: _Optional[str] = ..., read_permission: _Optional[str] = ..., write_permission: _Optional[str] = ..., grant_uri_permissions: _Optional[bool] = ..., target_activity: _Optional[str] = ..., launcher: _Optional[bool] = ..., intent_filters: _Optional[_Iterable[_Union[AndroidIntentFilter, _Mapping]]] = ...) -> None: ...

class AndroidPermission(_message.Message):
    __slots__ = ("name", "max_sdk", "protection_level")
    NAME_FIELD_NUMBER: _ClassVar[int]
    MAX_SDK_FIELD_NUMBER: _ClassVar[int]
    PROTECTION_LEVEL_FIELD_NUMBER: _ClassVar[int]
    name: str
    max_sdk: int
    protection_level: str
    def __init__(self, name: _Optional[str] = ..., max_sdk: _Optional[int] = ..., protection_level: _Optional[str] = ...) -> None: ...

class AndroidManifest(_message.Message):
    __slots__ = ("package", "version_code", "version_name", "min_sdk", "target_sdk", "max_sdk", "compile_sdk", "compile_sdk_codename", "platform_build_version_code", "platform_build_version_name", "install_location", "shared_user_id", "uses_permissions", "permissions", "uses_features", "uses_libraries", "queries_packages", "application_class", "label", "icon", "theme", "process", "app_component_factory", "debuggable", "allow_backup", "uses_cleartext_traffic", "extract_native_libs", "test_only", "large_heap", "has_code", "request_legacy_external_storage", "network_security_config", "network_security_config_file", "full_backup_content", "data_extraction_rules", "components", "meta_data")
    class MetaDataEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    PACKAGE_FIELD_NUMBER: _ClassVar[int]
    VERSION_CODE_FIELD_NUMBER: _ClassVar[int]
    VERSION_NAME_FIELD_NUMBER: _ClassVar[int]
    MIN_SDK_FIELD_NUMBER: _ClassVar[int]
    TARGET_SDK_FIELD_NUMBER: _ClassVar[int]
    MAX_SDK_FIELD_NUMBER: _ClassVar[int]
    COMPILE_SDK_FIELD_NUMBER: _ClassVar[int]
    COMPILE_SDK_CODENAME_FIELD_NUMBER: _ClassVar[int]
    PLATFORM_BUILD_VERSION_CODE_FIELD_NUMBER: _ClassVar[int]
    PLATFORM_BUILD_VERSION_NAME_FIELD_NUMBER: _ClassVar[int]
    INSTALL_LOCATION_FIELD_NUMBER: _ClassVar[int]
    SHARED_USER_ID_FIELD_NUMBER: _ClassVar[int]
    USES_PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    USES_FEATURES_FIELD_NUMBER: _ClassVar[int]
    USES_LIBRARIES_FIELD_NUMBER: _ClassVar[int]
    QUERIES_PACKAGES_FIELD_NUMBER: _ClassVar[int]
    APPLICATION_CLASS_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    ICON_FIELD_NUMBER: _ClassVar[int]
    THEME_FIELD_NUMBER: _ClassVar[int]
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    APP_COMPONENT_FACTORY_FIELD_NUMBER: _ClassVar[int]
    DEBUGGABLE_FIELD_NUMBER: _ClassVar[int]
    ALLOW_BACKUP_FIELD_NUMBER: _ClassVar[int]
    USES_CLEARTEXT_TRAFFIC_FIELD_NUMBER: _ClassVar[int]
    EXTRACT_NATIVE_LIBS_FIELD_NUMBER: _ClassVar[int]
    TEST_ONLY_FIELD_NUMBER: _ClassVar[int]
    LARGE_HEAP_FIELD_NUMBER: _ClassVar[int]
    HAS_CODE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_LEGACY_EXTERNAL_STORAGE_FIELD_NUMBER: _ClassVar[int]
    NETWORK_SECURITY_CONFIG_FIELD_NUMBER: _ClassVar[int]
    NETWORK_SECURITY_CONFIG_FILE_FIELD_NUMBER: _ClassVar[int]
    FULL_BACKUP_CONTENT_FIELD_NUMBER: _ClassVar[int]
    DATA_EXTRACTION_RULES_FIELD_NUMBER: _ClassVar[int]
    COMPONENTS_FIELD_NUMBER: _ClassVar[int]
    META_DATA_FIELD_NUMBER: _ClassVar[int]
    package: str
    version_code: int
    version_name: str
    min_sdk: int
    target_sdk: int
    max_sdk: int
    compile_sdk: int
    compile_sdk_codename: str
    platform_build_version_code: int
    platform_build_version_name: str
    install_location: str
    shared_user_id: str
    uses_permissions: _containers.RepeatedCompositeFieldContainer[AndroidPermission]
    permissions: _containers.RepeatedCompositeFieldContainer[AndroidPermission]
    uses_features: _containers.RepeatedScalarFieldContainer[str]
    uses_libraries: _containers.RepeatedScalarFieldContainer[str]
    queries_packages: _containers.RepeatedScalarFieldContainer[str]
    application_class: str
    label: str
    icon: str
    theme: str
    process: str
    app_component_factory: str
    debuggable: bool
    allow_backup: bool
    uses_cleartext_traffic: bool
    extract_native_libs: bool
    test_only: bool
    large_heap: bool
    has_code: bool
    request_legacy_external_storage: bool
    network_security_config: str
    network_security_config_file: str
    full_backup_content: str
    data_extraction_rules: str
    components: _containers.RepeatedCompositeFieldContainer[AndroidComponent]
    meta_data: _containers.ScalarMap[str, str]
    def __init__(self, package: _Optional[str] = ..., version_code: _Optional[int] = ..., version_name: _Optional[str] = ..., min_sdk: _Optional[int] = ..., target_sdk: _Optional[int] = ..., max_sdk: _Optional[int] = ..., compile_sdk: _Optional[int] = ..., compile_sdk_codename: _Optional[str] = ..., platform_build_version_code: _Optional[int] = ..., platform_build_version_name: _Optional[str] = ..., install_location: _Optional[str] = ..., shared_user_id: _Optional[str] = ..., uses_permissions: _Optional[_Iterable[_Union[AndroidPermission, _Mapping]]] = ..., permissions: _Optional[_Iterable[_Union[AndroidPermission, _Mapping]]] = ..., uses_features: _Optional[_Iterable[str]] = ..., uses_libraries: _Optional[_Iterable[str]] = ..., queries_packages: _Optional[_Iterable[str]] = ..., application_class: _Optional[str] = ..., label: _Optional[str] = ..., icon: _Optional[str] = ..., theme: _Optional[str] = ..., process: _Optional[str] = ..., app_component_factory: _Optional[str] = ..., debuggable: _Optional[bool] = ..., allow_backup: _Optional[bool] = ..., uses_cleartext_traffic: _Optional[bool] = ..., extract_native_libs: _Optional[bool] = ..., test_only: _Optional[bool] = ..., large_heap: _Optional[bool] = ..., has_code: _Optional[bool] = ..., request_legacy_external_storage: _Optional[bool] = ..., network_security_config: _Optional[str] = ..., network_security_config_file: _Optional[str] = ..., full_backup_content: _Optional[str] = ..., data_extraction_rules: _Optional[str] = ..., components: _Optional[_Iterable[_Union[AndroidComponent, _Mapping]]] = ..., meta_data: _Optional[_Mapping[str, str]] = ...) -> None: ...

class AndroidResourceTypeSummary(_message.Message):
    __slots__ = ("name", "id", "entries", "values", "configs")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    CONFIGS_FIELD_NUMBER: _ClassVar[int]
    name: str
    id: int
    entries: int
    values: int
    configs: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, name: _Optional[str] = ..., id: _Optional[int] = ..., entries: _Optional[int] = ..., values: _Optional[int] = ..., configs: _Optional[_Iterable[str]] = ...) -> None: ...

class AndroidResourcePackage(_message.Message):
    __slots__ = ("id", "name", "types")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPES_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    types: _containers.RepeatedCompositeFieldContainer[AndroidResourceTypeSummary]
    def __init__(self, id: _Optional[int] = ..., name: _Optional[str] = ..., types: _Optional[_Iterable[_Union[AndroidResourceTypeSummary, _Mapping]]] = ...) -> None: ...

class AndroidResourcesSummary(_message.Message):
    __slots__ = ("present", "packages", "strings", "values", "warnings")
    PRESENT_FIELD_NUMBER: _ClassVar[int]
    PACKAGES_FIELD_NUMBER: _ClassVar[int]
    STRINGS_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    present: bool
    packages: _containers.RepeatedCompositeFieldContainer[AndroidResourcePackage]
    strings: int
    values: int
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, present: _Optional[bool] = ..., packages: _Optional[_Iterable[_Union[AndroidResourcePackage, _Mapping]]] = ..., strings: _Optional[int] = ..., values: _Optional[int] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class AndroidNativeLibrary(_message.Message):
    __slots__ = ("abi", "path", "name", "size", "machine", "soname", "build_id", "needed", "exports", "jni_exports", "jni_onload", "flutter", "error")
    ABI_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    MACHINE_FIELD_NUMBER: _ClassVar[int]
    SONAME_FIELD_NUMBER: _ClassVar[int]
    BUILD_ID_FIELD_NUMBER: _ClassVar[int]
    NEEDED_FIELD_NUMBER: _ClassVar[int]
    EXPORTS_FIELD_NUMBER: _ClassVar[int]
    JNI_EXPORTS_FIELD_NUMBER: _ClassVar[int]
    JNI_ONLOAD_FIELD_NUMBER: _ClassVar[int]
    FLUTTER_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    abi: str
    path: str
    name: str
    size: int
    machine: str
    soname: str
    build_id: str
    needed: _containers.RepeatedScalarFieldContainer[str]
    exports: int
    jni_exports: _containers.RepeatedScalarFieldContainer[str]
    jni_onload: bool
    flutter: str
    error: str
    def __init__(self, abi: _Optional[str] = ..., path: _Optional[str] = ..., name: _Optional[str] = ..., size: _Optional[int] = ..., machine: _Optional[str] = ..., soname: _Optional[str] = ..., build_id: _Optional[str] = ..., needed: _Optional[_Iterable[str]] = ..., exports: _Optional[int] = ..., jni_exports: _Optional[_Iterable[str]] = ..., jni_onload: _Optional[bool] = ..., flutter: _Optional[str] = ..., error: _Optional[str] = ...) -> None: ...

class AndroidDexFile(_message.Message):
    __slots__ = ("path", "version", "strings", "types", "methods", "classes", "native_methods")
    PATH_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    STRINGS_FIELD_NUMBER: _ClassVar[int]
    TYPES_FIELD_NUMBER: _ClassVar[int]
    METHODS_FIELD_NUMBER: _ClassVar[int]
    CLASSES_FIELD_NUMBER: _ClassVar[int]
    NATIVE_METHODS_FIELD_NUMBER: _ClassVar[int]
    path: str
    version: str
    strings: int
    types: int
    methods: int
    classes: int
    native_methods: int
    def __init__(self, path: _Optional[str] = ..., version: _Optional[str] = ..., strings: _Optional[int] = ..., types: _Optional[int] = ..., methods: _Optional[int] = ..., classes: _Optional[int] = ..., native_methods: _Optional[int] = ...) -> None: ...

class AndroidNativeMethod(_message.Message):
    __slots__ = ("class_name", "method", "signature", "is_static", "dex", "jni_name", "jni_long_name", "libraries")
    CLASS_NAME_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    IS_STATIC_FIELD_NUMBER: _ClassVar[int]
    DEX_FIELD_NUMBER: _ClassVar[int]
    JNI_NAME_FIELD_NUMBER: _ClassVar[int]
    JNI_LONG_NAME_FIELD_NUMBER: _ClassVar[int]
    LIBRARIES_FIELD_NUMBER: _ClassVar[int]
    class_name: str
    method: str
    signature: str
    is_static: bool
    dex: str
    jni_name: str
    jni_long_name: str
    libraries: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, class_name: _Optional[str] = ..., method: _Optional[str] = ..., signature: _Optional[str] = ..., is_static: _Optional[bool] = ..., dex: _Optional[str] = ..., jni_name: _Optional[str] = ..., jni_long_name: _Optional[str] = ..., libraries: _Optional[_Iterable[str]] = ...) -> None: ...

class AndroidDartSnapshot(_message.Message):
    __slots__ = ("symbol", "file_offset", "size", "header", "length", "kind", "kind_name", "hash", "features")
    SYMBOL_FIELD_NUMBER: _ClassVar[int]
    FILE_OFFSET_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    KIND_NAME_FIELD_NUMBER: _ClassVar[int]
    HASH_FIELD_NUMBER: _ClassVar[int]
    FEATURES_FIELD_NUMBER: _ClassVar[int]
    symbol: str
    file_offset: int
    size: int
    header: bool
    length: int
    kind: int
    kind_name: str
    hash: str
    features: str
    def __init__(self, symbol: _Optional[str] = ..., file_offset: _Optional[int] = ..., size: _Optional[int] = ..., header: _Optional[bool] = ..., length: _Optional[int] = ..., kind: _Optional[int] = ..., kind_name: _Optional[str] = ..., hash: _Optional[str] = ..., features: _Optional[str] = ...) -> None: ...

class AndroidFlutterAbi(_message.Message):
    __slots__ = ("abi", "libapp", "libflutter", "snapshot_hash", "hash_candidates", "features", "snapshots", "engine_build_id", "dart_version", "toolchain", "warnings")
    ABI_FIELD_NUMBER: _ClassVar[int]
    LIBAPP_FIELD_NUMBER: _ClassVar[int]
    LIBFLUTTER_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_HASH_FIELD_NUMBER: _ClassVar[int]
    HASH_CANDIDATES_FIELD_NUMBER: _ClassVar[int]
    FEATURES_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOTS_FIELD_NUMBER: _ClassVar[int]
    ENGINE_BUILD_ID_FIELD_NUMBER: _ClassVar[int]
    DART_VERSION_FIELD_NUMBER: _ClassVar[int]
    TOOLCHAIN_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    abi: str
    libapp: str
    libflutter: str
    snapshot_hash: str
    hash_candidates: _containers.RepeatedScalarFieldContainer[str]
    features: str
    snapshots: _containers.RepeatedCompositeFieldContainer[AndroidDartSnapshot]
    engine_build_id: str
    dart_version: str
    toolchain: _containers.RepeatedScalarFieldContainer[str]
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, abi: _Optional[str] = ..., libapp: _Optional[str] = ..., libflutter: _Optional[str] = ..., snapshot_hash: _Optional[str] = ..., hash_candidates: _Optional[_Iterable[str]] = ..., features: _Optional[str] = ..., snapshots: _Optional[_Iterable[_Union[AndroidDartSnapshot, _Mapping]]] = ..., engine_build_id: _Optional[str] = ..., dart_version: _Optional[str] = ..., toolchain: _Optional[_Iterable[str]] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class AndroidFlutter(_message.Message):
    __slots__ = ("detected", "snapshot_hash", "abis")
    DETECTED_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_HASH_FIELD_NUMBER: _ClassVar[int]
    ABIS_FIELD_NUMBER: _ClassVar[int]
    detected: bool
    snapshot_hash: str
    abis: _containers.RepeatedCompositeFieldContainer[AndroidFlutterAbi]
    def __init__(self, detected: _Optional[bool] = ..., snapshot_hash: _Optional[str] = ..., abis: _Optional[_Iterable[_Union[AndroidFlutterAbi, _Mapping]]] = ...) -> None: ...

class AndroidPackage(_message.Message):
    __slots__ = ("path", "container_path", "manifest_present", "manifest", "manifest_xml", "manifest_xml_resolved", "resources", "abis", "native_libraries", "dex_files", "native_methods", "flutter", "warnings")
    PATH_FIELD_NUMBER: _ClassVar[int]
    CONTAINER_PATH_FIELD_NUMBER: _ClassVar[int]
    MANIFEST_PRESENT_FIELD_NUMBER: _ClassVar[int]
    MANIFEST_FIELD_NUMBER: _ClassVar[int]
    MANIFEST_XML_FIELD_NUMBER: _ClassVar[int]
    MANIFEST_XML_RESOLVED_FIELD_NUMBER: _ClassVar[int]
    RESOURCES_FIELD_NUMBER: _ClassVar[int]
    ABIS_FIELD_NUMBER: _ClassVar[int]
    NATIVE_LIBRARIES_FIELD_NUMBER: _ClassVar[int]
    DEX_FILES_FIELD_NUMBER: _ClassVar[int]
    NATIVE_METHODS_FIELD_NUMBER: _ClassVar[int]
    FLUTTER_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    path: str
    container_path: str
    manifest_present: bool
    manifest: AndroidManifest
    manifest_xml: str
    manifest_xml_resolved: str
    resources: AndroidResourcesSummary
    abis: _containers.RepeatedScalarFieldContainer[str]
    native_libraries: _containers.RepeatedCompositeFieldContainer[AndroidNativeLibrary]
    dex_files: _containers.RepeatedCompositeFieldContainer[AndroidDexFile]
    native_methods: _containers.RepeatedCompositeFieldContainer[AndroidNativeMethod]
    flutter: AndroidFlutter
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, path: _Optional[str] = ..., container_path: _Optional[str] = ..., manifest_present: _Optional[bool] = ..., manifest: _Optional[_Union[AndroidManifest, _Mapping]] = ..., manifest_xml: _Optional[str] = ..., manifest_xml_resolved: _Optional[str] = ..., resources: _Optional[_Union[AndroidResourcesSummary, _Mapping]] = ..., abis: _Optional[_Iterable[str]] = ..., native_libraries: _Optional[_Iterable[_Union[AndroidNativeLibrary, _Mapping]]] = ..., dex_files: _Optional[_Iterable[_Union[AndroidDexFile, _Mapping]]] = ..., native_methods: _Optional[_Iterable[_Union[AndroidNativeMethod, _Mapping]]] = ..., flutter: _Optional[_Union[AndroidFlutter, _Mapping]] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class GetAndroidPackageResponse(_message.Message):
    __slots__ = ("package",)
    PACKAGE_FIELD_NUMBER: _ClassVar[int]
    package: AndroidPackage
    def __init__(self, package: _Optional[_Union[AndroidPackage, _Mapping]] = ...) -> None: ...

class DecodeAndroidXmlRequest(_message.Message):
    __slots__ = ("session_id", "path", "resolve")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    RESOLVE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    path: str
    resolve: bool
    def __init__(self, session_id: _Optional[str] = ..., path: _Optional[str] = ..., resolve: _Optional[bool] = ...) -> None: ...

class DecodeAndroidXmlResponse(_message.Message):
    __slots__ = ("xml", "root", "warnings")
    XML_FIELD_NUMBER: _ClassVar[int]
    ROOT_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    xml: str
    root: str
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, xml: _Optional[str] = ..., root: _Optional[str] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class ListAndroidResourcesRequest(_message.Message):
    __slots__ = ("session_id", "path", "type", "config", "query", "offset", "limit")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    CONFIG_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    path: str
    type: str
    config: str
    query: str
    offset: int
    limit: int
    def __init__(self, session_id: _Optional[str] = ..., path: _Optional[str] = ..., type: _Optional[str] = ..., config: _Optional[str] = ..., query: _Optional[str] = ..., offset: _Optional[int] = ..., limit: _Optional[int] = ...) -> None: ...

class AndroidResourceEntry(_message.Message):
    __slots__ = ("id", "name", "type", "key", "config", "value", "value_type", "reference", "items", "parent")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    CONFIG_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    VALUE_TYPE_FIELD_NUMBER: _ClassVar[int]
    REFERENCE_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    type: str
    key: str
    config: str
    value: str
    value_type: str
    reference: str
    items: _containers.RepeatedScalarFieldContainer[str]
    parent: str
    def __init__(self, id: _Optional[int] = ..., name: _Optional[str] = ..., type: _Optional[str] = ..., key: _Optional[str] = ..., config: _Optional[str] = ..., value: _Optional[str] = ..., value_type: _Optional[str] = ..., reference: _Optional[str] = ..., items: _Optional[_Iterable[str]] = ..., parent: _Optional[str] = ...) -> None: ...

class ListAndroidResourcesResponse(_message.Message):
    __slots__ = ("entries", "total", "types", "configs")
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    TYPES_FIELD_NUMBER: _ClassVar[int]
    CONFIGS_FIELD_NUMBER: _ClassVar[int]
    entries: _containers.RepeatedCompositeFieldContainer[AndroidResourceEntry]
    total: int
    types: _containers.RepeatedScalarFieldContainer[str]
    configs: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, entries: _Optional[_Iterable[_Union[AndroidResourceEntry, _Mapping]]] = ..., total: _Optional[int] = ..., types: _Optional[_Iterable[str]] = ..., configs: _Optional[_Iterable[str]] = ...) -> None: ...

class GetAppleBundleRequest(_message.Message):
    __slots__ = ("session_id", "path", "skip_info_plist")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    SKIP_INFO_PLIST_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    path: str
    skip_info_plist: bool
    def __init__(self, session_id: _Optional[str] = ..., path: _Optional[str] = ..., skip_info_plist: _Optional[bool] = ...) -> None: ...

class GetAppleBundleResponse(_message.Message):
    __slots__ = ("bundle", "apps")
    BUNDLE_FIELD_NUMBER: _ClassVar[int]
    APPS_FIELD_NUMBER: _ClassVar[int]
    bundle: _apple_pb2.AppleBundle
    apps: _containers.RepeatedCompositeFieldContainer[_apple_pb2.AppleBundleRef]
    def __init__(self, bundle: _Optional[_Union[_apple_pb2.AppleBundle, _Mapping]] = ..., apps: _Optional[_Iterable[_Union[_apple_pb2.AppleBundleRef, _Mapping]]] = ...) -> None: ...

class ReadPropertyListRequest(_message.Message):
    __slots__ = ("session_id", "path", "max_values", "max_data_bytes", "resolve_keyed_archive")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    MAX_VALUES_FIELD_NUMBER: _ClassVar[int]
    MAX_DATA_BYTES_FIELD_NUMBER: _ClassVar[int]
    RESOLVE_KEYED_ARCHIVE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    path: str
    max_values: int
    max_data_bytes: int
    resolve_keyed_archive: bool
    def __init__(self, session_id: _Optional[str] = ..., path: _Optional[str] = ..., max_values: _Optional[int] = ..., max_data_bytes: _Optional[int] = ..., resolve_keyed_archive: _Optional[bool] = ...) -> None: ...

class ReadPropertyListResponse(_message.Message):
    __slots__ = ("format", "root", "truncated", "values", "keyed_archive", "warnings")
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    ROOT_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    KEYED_ARCHIVE_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    format: str
    root: _apple_pb2.PlistValue
    truncated: bool
    values: int
    keyed_archive: bool
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, format: _Optional[str] = ..., root: _Optional[_Union[_apple_pb2.PlistValue, _Mapping]] = ..., truncated: _Optional[bool] = ..., values: _Optional[int] = ..., keyed_archive: _Optional[bool] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class ListUiActionsRequest(_message.Message):
    __slots__ = ("session_id", "path", "program_id", "include_documents")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_DOCUMENTS_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    path: str
    program_id: str
    include_documents: bool
    def __init__(self, session_id: _Optional[str] = ..., path: _Optional[str] = ..., program_id: _Optional[str] = ..., include_documents: _Optional[bool] = ...) -> None: ...

class ListUiActionsResponse(_message.Message):
    __slots__ = ("actions", "outlets", "documents", "program_id", "warnings")
    ACTIONS_FIELD_NUMBER: _ClassVar[int]
    OUTLETS_FIELD_NUMBER: _ClassVar[int]
    DOCUMENTS_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    actions: _containers.RepeatedCompositeFieldContainer[_apple_pb2.UiAction]
    outlets: _containers.RepeatedCompositeFieldContainer[_apple_pb2.UiOutlet]
    documents: _containers.RepeatedCompositeFieldContainer[_apple_pb2.InterfaceDocument]
    program_id: str
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, actions: _Optional[_Iterable[_Union[_apple_pb2.UiAction, _Mapping]]] = ..., outlets: _Optional[_Iterable[_Union[_apple_pb2.UiOutlet, _Mapping]]] = ..., documents: _Optional[_Iterable[_Union[_apple_pb2.InterfaceDocument, _Mapping]]] = ..., program_id: _Optional[str] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...
