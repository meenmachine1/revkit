import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
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
    __slots__ = ("name", "path", "kind", "size", "size_unknown", "stored_size", "permissions", "mode", "has_owner", "uid", "gid", "modified", "link_target", "link_path", "note", "unreadable", "renamed", "detected", "detected_kind", "container_format", "processor", "child_count", "language_id", "load_address", "has_load_address")
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
    def __init__(self, name: _Optional[str] = ..., path: _Optional[str] = ..., kind: _Optional[_Union[FileSystemEntryKind, str]] = ..., size: _Optional[int] = ..., size_unknown: _Optional[bool] = ..., stored_size: _Optional[int] = ..., permissions: _Optional[str] = ..., mode: _Optional[int] = ..., has_owner: _Optional[bool] = ..., uid: _Optional[int] = ..., gid: _Optional[int] = ..., modified: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., link_target: _Optional[str] = ..., link_path: _Optional[str] = ..., note: _Optional[str] = ..., unreadable: _Optional[bool] = ..., renamed: _Optional[bool] = ..., detected: _Optional[str] = ..., detected_kind: _Optional[str] = ..., container_format: _Optional[str] = ..., processor: _Optional[str] = ..., child_count: _Optional[int] = ..., language_id: _Optional[str] = ..., load_address: _Optional[int] = ..., has_load_address: _Optional[bool] = ...) -> None: ...

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
    __slots__ = ("path", "container_path", "detected", "action", "reason", "program", "warnings", "language_id")
    PATH_FIELD_NUMBER: _ClassVar[int]
    CONTAINER_PATH_FIELD_NUMBER: _ClassVar[int]
    DETECTED_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_ID_FIELD_NUMBER: _ClassVar[int]
    path: str
    container_path: str
    detected: str
    action: str
    reason: str
    program: _project_pb2.ProgramInfo
    warnings: _containers.RepeatedScalarFieldContainer[str]
    language_id: str
    def __init__(self, path: _Optional[str] = ..., container_path: _Optional[str] = ..., detected: _Optional[str] = ..., action: _Optional[str] = ..., reason: _Optional[str] = ..., program: _Optional[_Union[_project_pb2.ProgramInfo, _Mapping]] = ..., warnings: _Optional[_Iterable[str]] = ..., language_id: _Optional[str] = ...) -> None: ...

class ImportFromFileSystemResponse(_message.Message):
    __slots__ = ("items", "imported", "skipped", "failed", "capped", "snapshot")
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    IMPORTED_FIELD_NUMBER: _ClassVar[int]
    SKIPPED_FIELD_NUMBER: _ClassVar[int]
    FAILED_FIELD_NUMBER: _ClassVar[int]
    CAPPED_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    items: _containers.RepeatedCompositeFieldContainer[FileSystemImport]
    imported: int
    skipped: int
    failed: int
    capped: bool
    snapshot: _common_pb2.Snapshot
    def __init__(self, items: _Optional[_Iterable[_Union[FileSystemImport, _Mapping]]] = ..., imported: _Optional[int] = ..., skipped: _Optional[int] = ..., failed: _Optional[int] = ..., capped: _Optional[bool] = ..., snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ...) -> None: ...

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
