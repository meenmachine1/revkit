import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from revkit.v1 import assertion_pb2 as _assertion_pb2
from revkit.v1 import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ImportPhase(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    IMPORT_PHASE_UNSPECIFIED: _ClassVar[ImportPhase]
    IMPORT_PHASE_READING: _ClassVar[ImportPhase]
    IMPORT_PHASE_LOADING: _ClassVar[ImportPhase]
    IMPORT_PHASE_DEBUG_INFO: _ClassVar[ImportPhase]
    IMPORT_PHASE_FUNCTIONS: _ClassVar[ImportPhase]
    IMPORT_PHASE_DATA: _ClassVar[ImportPhase]
    IMPORT_PHASE_PROTOTYPES: _ClassVar[ImportPhase]
    IMPORT_PHASE_SAVING: _ClassVar[ImportPhase]
    IMPORT_PHASE_DONE: _ClassVar[ImportPhase]

class DetectConfidence(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DETECT_CONFIDENCE_UNSPECIFIED: _ClassVar[DetectConfidence]
    DETECT_CONFIDENCE_LOW: _ClassVar[DetectConfidence]
    DETECT_CONFIDENCE_MEDIUM: _ClassVar[DetectConfidence]
    DETECT_CONFIDENCE_HIGH: _ClassVar[DetectConfidence]

class RawRegionKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RAW_REGION_KIND_UNSPECIFIED: _ClassVar[RawRegionKind]
    RAW_REGION_KIND_RAM: _ClassVar[RawRegionKind]
    RAW_REGION_KIND_MMIO: _ClassVar[RawRegionKind]
    RAW_REGION_KIND_UNKNOWN: _ClassVar[RawRegionKind]

class RawSegmentKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RAW_SEGMENT_KIND_UNSPECIFIED: _ClassVar[RawSegmentKind]
    RAW_SEGMENT_KIND_PADDING: _ClassVar[RawSegmentKind]
    RAW_SEGMENT_KIND_HIGH_ENTROPY: _ClassVar[RawSegmentKind]
    RAW_SEGMENT_KIND_TEXT: _ClassVar[RawSegmentKind]
    RAW_SEGMENT_KIND_CODE: _ClassVar[RawSegmentKind]

class RawDetectPhase(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RAW_DETECT_PHASE_UNSPECIFIED: _ClassVar[RawDetectPhase]
    RAW_DETECT_PHASE_QUEUED: _ClassVar[RawDetectPhase]
    RAW_DETECT_PHASE_READING: _ClassVar[RawDetectPhase]
    RAW_DETECT_PHASE_SEGMENTS: _ClassVar[RawDetectPhase]
    RAW_DETECT_PHASE_PROCESSOR: _ClassVar[RawDetectPhase]
    RAW_DETECT_PHASE_LAYOUT: _ClassVar[RawDetectPhase]
    RAW_DETECT_PHASE_DONE: _ClassVar[RawDetectPhase]

class LibraryResolution(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    LIBRARY_RESOLUTION_UNSPECIFIED: _ClassVar[LibraryResolution]
    LIBRARY_RESOLUTION_NONE: _ClassVar[LibraryResolution]
    LIBRARY_RESOLUTION_LINKED: _ClassVar[LibraryResolution]
    LIBRARY_RESOLUTION_NAME: _ClassVar[LibraryResolution]
    LIBRARY_RESOLUTION_SONAME: _ClassVar[LibraryResolution]

class Endianness(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENDIANNESS_UNSPECIFIED: _ClassVar[Endianness]
    ENDIANNESS_LITTLE: _ClassVar[Endianness]
    ENDIANNESS_BIG: _ClassVar[Endianness]

class AddressSpaceKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ADDRESS_SPACE_KIND_UNSPECIFIED: _ClassVar[AddressSpaceKind]
    ADDRESS_SPACE_KIND_CONSTANT: _ClassVar[AddressSpaceKind]
    ADDRESS_SPACE_KIND_RAM: _ClassVar[AddressSpaceKind]
    ADDRESS_SPACE_KIND_REGISTER: _ClassVar[AddressSpaceKind]
    ADDRESS_SPACE_KIND_STACK: _ClassVar[AddressSpaceKind]
    ADDRESS_SPACE_KIND_UNIQUE: _ClassVar[AddressSpaceKind]
    ADDRESS_SPACE_KIND_OVERLAY: _ClassVar[AddressSpaceKind]
    ADDRESS_SPACE_KIND_OTHER: _ClassVar[AddressSpaceKind]

class MemoryBlockSourceKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MEMORY_BLOCK_SOURCE_KIND_UNSPECIFIED: _ClassVar[MemoryBlockSourceKind]
    MEMORY_BLOCK_SOURCE_KIND_IMAGE: _ClassVar[MemoryBlockSourceKind]
    MEMORY_BLOCK_SOURCE_KIND_FILE: _ClassVar[MemoryBlockSourceKind]
    MEMORY_BLOCK_SOURCE_KIND_ZERO: _ClassVar[MemoryBlockSourceKind]
    MEMORY_BLOCK_SOURCE_KIND_NONE: _ClassVar[MemoryBlockSourceKind]
IMPORT_PHASE_UNSPECIFIED: ImportPhase
IMPORT_PHASE_READING: ImportPhase
IMPORT_PHASE_LOADING: ImportPhase
IMPORT_PHASE_DEBUG_INFO: ImportPhase
IMPORT_PHASE_FUNCTIONS: ImportPhase
IMPORT_PHASE_DATA: ImportPhase
IMPORT_PHASE_PROTOTYPES: ImportPhase
IMPORT_PHASE_SAVING: ImportPhase
IMPORT_PHASE_DONE: ImportPhase
DETECT_CONFIDENCE_UNSPECIFIED: DetectConfidence
DETECT_CONFIDENCE_LOW: DetectConfidence
DETECT_CONFIDENCE_MEDIUM: DetectConfidence
DETECT_CONFIDENCE_HIGH: DetectConfidence
RAW_REGION_KIND_UNSPECIFIED: RawRegionKind
RAW_REGION_KIND_RAM: RawRegionKind
RAW_REGION_KIND_MMIO: RawRegionKind
RAW_REGION_KIND_UNKNOWN: RawRegionKind
RAW_SEGMENT_KIND_UNSPECIFIED: RawSegmentKind
RAW_SEGMENT_KIND_PADDING: RawSegmentKind
RAW_SEGMENT_KIND_HIGH_ENTROPY: RawSegmentKind
RAW_SEGMENT_KIND_TEXT: RawSegmentKind
RAW_SEGMENT_KIND_CODE: RawSegmentKind
RAW_DETECT_PHASE_UNSPECIFIED: RawDetectPhase
RAW_DETECT_PHASE_QUEUED: RawDetectPhase
RAW_DETECT_PHASE_READING: RawDetectPhase
RAW_DETECT_PHASE_SEGMENTS: RawDetectPhase
RAW_DETECT_PHASE_PROCESSOR: RawDetectPhase
RAW_DETECT_PHASE_LAYOUT: RawDetectPhase
RAW_DETECT_PHASE_DONE: RawDetectPhase
LIBRARY_RESOLUTION_UNSPECIFIED: LibraryResolution
LIBRARY_RESOLUTION_NONE: LibraryResolution
LIBRARY_RESOLUTION_LINKED: LibraryResolution
LIBRARY_RESOLUTION_NAME: LibraryResolution
LIBRARY_RESOLUTION_SONAME: LibraryResolution
ENDIANNESS_UNSPECIFIED: Endianness
ENDIANNESS_LITTLE: Endianness
ENDIANNESS_BIG: Endianness
ADDRESS_SPACE_KIND_UNSPECIFIED: AddressSpaceKind
ADDRESS_SPACE_KIND_CONSTANT: AddressSpaceKind
ADDRESS_SPACE_KIND_RAM: AddressSpaceKind
ADDRESS_SPACE_KIND_REGISTER: AddressSpaceKind
ADDRESS_SPACE_KIND_STACK: AddressSpaceKind
ADDRESS_SPACE_KIND_UNIQUE: AddressSpaceKind
ADDRESS_SPACE_KIND_OVERLAY: AddressSpaceKind
ADDRESS_SPACE_KIND_OTHER: AddressSpaceKind
MEMORY_BLOCK_SOURCE_KIND_UNSPECIFIED: MemoryBlockSourceKind
MEMORY_BLOCK_SOURCE_KIND_IMAGE: MemoryBlockSourceKind
MEMORY_BLOCK_SOURCE_KIND_FILE: MemoryBlockSourceKind
MEMORY_BLOCK_SOURCE_KIND_ZERO: MemoryBlockSourceKind
MEMORY_BLOCK_SOURCE_KIND_NONE: MemoryBlockSourceKind

class ProjectFolder(_message.Message):
    __slots__ = ("folder_id", "parent_id", "name", "path", "origin")
    FOLDER_ID_FIELD_NUMBER: _ClassVar[int]
    PARENT_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    folder_id: str
    parent_id: str
    name: str
    path: str
    origin: _common_pb2.FactOrigin
    def __init__(self, folder_id: _Optional[str] = ..., parent_id: _Optional[str] = ..., name: _Optional[str] = ..., path: _Optional[str] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ...) -> None: ...

class CreateFolderRequest(_message.Message):
    __slots__ = ("project_id", "parent_id", "name", "provenance")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PARENT_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    parent_id: str
    name: str
    provenance: _common_pb2.Provenance
    def __init__(self, project_id: _Optional[str] = ..., parent_id: _Optional[str] = ..., name: _Optional[str] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class CreateFolderResponse(_message.Message):
    __slots__ = ("snapshot", "folder", "assertion")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FOLDER_FIELD_NUMBER: _ClassVar[int]
    ASSERTION_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    folder: ProjectFolder
    assertion: _assertion_pb2.Assertion
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., folder: _Optional[_Union[ProjectFolder, _Mapping]] = ..., assertion: _Optional[_Union[_assertion_pb2.Assertion, _Mapping]] = ...) -> None: ...

class RenameFolderRequest(_message.Message):
    __slots__ = ("project_id", "folder_id", "name", "provenance")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    FOLDER_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    folder_id: str
    name: str
    provenance: _common_pb2.Provenance
    def __init__(self, project_id: _Optional[str] = ..., folder_id: _Optional[str] = ..., name: _Optional[str] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class RenameFolderResponse(_message.Message):
    __slots__ = ("snapshot", "folder", "assertion")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FOLDER_FIELD_NUMBER: _ClassVar[int]
    ASSERTION_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    folder: ProjectFolder
    assertion: _assertion_pb2.Assertion
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., folder: _Optional[_Union[ProjectFolder, _Mapping]] = ..., assertion: _Optional[_Union[_assertion_pb2.Assertion, _Mapping]] = ...) -> None: ...

class DeleteFolderRequest(_message.Message):
    __slots__ = ("project_id", "folder_id", "provenance")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    FOLDER_ID_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    folder_id: str
    provenance: _common_pb2.Provenance
    def __init__(self, project_id: _Optional[str] = ..., folder_id: _Optional[str] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class DeleteFolderResponse(_message.Message):
    __slots__ = ("snapshot", "assertion")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ASSERTION_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    assertion: _assertion_pb2.Assertion
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., assertion: _Optional[_Union[_assertion_pb2.Assertion, _Mapping]] = ...) -> None: ...

class MoveToFolderRequest(_message.Message):
    __slots__ = ("project_id", "folder_id", "program_ids", "folder_ids", "provenance")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    FOLDER_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_IDS_FIELD_NUMBER: _ClassVar[int]
    FOLDER_IDS_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    folder_id: str
    program_ids: _containers.RepeatedScalarFieldContainer[str]
    folder_ids: _containers.RepeatedScalarFieldContainer[str]
    provenance: _common_pb2.Provenance
    def __init__(self, project_id: _Optional[str] = ..., folder_id: _Optional[str] = ..., program_ids: _Optional[_Iterable[str]] = ..., folder_ids: _Optional[_Iterable[str]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class MoveToFolderResponse(_message.Message):
    __slots__ = ("snapshot", "assertions")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ASSERTIONS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    assertions: _containers.RepeatedCompositeFieldContainer[_assertion_pb2.Assertion]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., assertions: _Optional[_Iterable[_Union[_assertion_pb2.Assertion, _Mapping]]] = ...) -> None: ...

class ProjectArchiveManifest(_message.Message):
    __slots__ = ("format", "format_version", "created_by", "created_at", "project_name", "annotations_only", "programs", "folders", "log", "op_format")
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    FORMAT_VERSION_FIELD_NUMBER: _ClassVar[int]
    CREATED_BY_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    PROJECT_NAME_FIELD_NUMBER: _ClassVar[int]
    ANNOTATIONS_ONLY_FIELD_NUMBER: _ClassVar[int]
    PROGRAMS_FIELD_NUMBER: _ClassVar[int]
    FOLDERS_FIELD_NUMBER: _ClassVar[int]
    LOG_FIELD_NUMBER: _ClassVar[int]
    OP_FORMAT_FIELD_NUMBER: _ClassVar[int]
    format: str
    format_version: int
    created_by: str
    created_at: _timestamp_pb2.Timestamp
    project_name: str
    annotations_only: bool
    programs: _containers.RepeatedCompositeFieldContainer[ArchiveProgram]
    folders: _containers.RepeatedScalarFieldContainer[str]
    log: ArchiveFile
    op_format: int
    def __init__(self, format: _Optional[str] = ..., format_version: _Optional[int] = ..., created_by: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., project_name: _Optional[str] = ..., annotations_only: _Optional[bool] = ..., programs: _Optional[_Iterable[_Union[ArchiveProgram, _Mapping]]] = ..., folders: _Optional[_Iterable[str]] = ..., log: _Optional[_Union[ArchiveFile, _Mapping]] = ..., op_format: _Optional[int] = ...) -> None: ...

class ArchiveProgram(_message.Message):
    __slots__ = ("key", "name", "program_id", "sha256", "size", "format", "language_id", "folder", "has_binary", "ordinal", "regions", "op_count")
    KEY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_ID_FIELD_NUMBER: _ClassVar[int]
    FOLDER_FIELD_NUMBER: _ClassVar[int]
    HAS_BINARY_FIELD_NUMBER: _ClassVar[int]
    ORDINAL_FIELD_NUMBER: _ClassVar[int]
    REGIONS_FIELD_NUMBER: _ClassVar[int]
    OP_COUNT_FIELD_NUMBER: _ClassVar[int]
    key: str
    name: str
    program_id: str
    sha256: str
    size: int
    format: str
    language_id: str
    folder: str
    has_binary: bool
    ordinal: int
    regions: _containers.RepeatedCompositeFieldContainer[ArchiveFile]
    op_count: int
    def __init__(self, key: _Optional[str] = ..., name: _Optional[str] = ..., program_id: _Optional[str] = ..., sha256: _Optional[str] = ..., size: _Optional[int] = ..., format: _Optional[str] = ..., language_id: _Optional[str] = ..., folder: _Optional[str] = ..., has_binary: _Optional[bool] = ..., ordinal: _Optional[int] = ..., regions: _Optional[_Iterable[_Union[ArchiveFile, _Mapping]]] = ..., op_count: _Optional[int] = ...) -> None: ...

class ArchiveFile(_message.Message):
    __slots__ = ("path", "size", "sha256", "offset", "count")
    PATH_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    path: str
    size: int
    sha256: str
    offset: int
    count: int
    def __init__(self, path: _Optional[str] = ..., size: _Optional[int] = ..., sha256: _Optional[str] = ..., offset: _Optional[int] = ..., count: _Optional[int] = ...) -> None: ...

class ExportProjectRequest(_message.Message):
    __slots__ = ("project_id", "program_ids", "folder_ids", "annotations_only", "host_path")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_IDS_FIELD_NUMBER: _ClassVar[int]
    FOLDER_IDS_FIELD_NUMBER: _ClassVar[int]
    ANNOTATIONS_ONLY_FIELD_NUMBER: _ClassVar[int]
    HOST_PATH_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    program_ids: _containers.RepeatedScalarFieldContainer[str]
    folder_ids: _containers.RepeatedScalarFieldContainer[str]
    annotations_only: bool
    host_path: str
    def __init__(self, project_id: _Optional[str] = ..., program_ids: _Optional[_Iterable[str]] = ..., folder_ids: _Optional[_Iterable[str]] = ..., annotations_only: _Optional[bool] = ..., host_path: _Optional[str] = ...) -> None: ...

class ExportProjectResponse(_message.Message):
    __slots__ = ("summary", "data")
    SUMMARY_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    summary: ExportSummary
    data: bytes
    def __init__(self, summary: _Optional[_Union[ExportSummary, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class ExportSummary(_message.Message):
    __slots__ = ("file_name", "manifest", "size")
    FILE_NAME_FIELD_NUMBER: _ClassVar[int]
    MANIFEST_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    file_name: str
    manifest: ProjectArchiveManifest
    size: int
    def __init__(self, file_name: _Optional[str] = ..., manifest: _Optional[_Union[ProjectArchiveManifest, _Mapping]] = ..., size: _Optional[int] = ...) -> None: ...

class UploadChunkRequest(_message.Message):
    __slots__ = ("upload_id", "offset", "data", "total_size", "file_name")
    UPLOAD_ID_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    TOTAL_SIZE_FIELD_NUMBER: _ClassVar[int]
    FILE_NAME_FIELD_NUMBER: _ClassVar[int]
    upload_id: str
    offset: int
    data: bytes
    total_size: int
    file_name: str
    def __init__(self, upload_id: _Optional[str] = ..., offset: _Optional[int] = ..., data: _Optional[bytes] = ..., total_size: _Optional[int] = ..., file_name: _Optional[str] = ...) -> None: ...

class UploadChunkResponse(_message.Message):
    __slots__ = ("upload_id", "received", "complete")
    UPLOAD_ID_FIELD_NUMBER: _ClassVar[int]
    RECEIVED_FIELD_NUMBER: _ClassVar[int]
    COMPLETE_FIELD_NUMBER: _ClassVar[int]
    upload_id: str
    received: int
    complete: bool
    def __init__(self, upload_id: _Optional[str] = ..., received: _Optional[int] = ..., complete: _Optional[bool] = ...) -> None: ...

class ArchiveSource(_message.Message):
    __slots__ = ("path", "content", "upload_id")
    PATH_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    UPLOAD_ID_FIELD_NUMBER: _ClassVar[int]
    path: str
    content: bytes
    upload_id: str
    def __init__(self, path: _Optional[str] = ..., content: _Optional[bytes] = ..., upload_id: _Optional[str] = ...) -> None: ...

class ImportProjectArchiveRequest(_message.Message):
    __slots__ = ("archive", "project_id", "new_project_name", "folder_id", "binaries", "search_dir", "skip_missing", "inspect_only", "provenance")
    ARCHIVE_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    NEW_PROJECT_NAME_FIELD_NUMBER: _ClassVar[int]
    FOLDER_ID_FIELD_NUMBER: _ClassVar[int]
    BINARIES_FIELD_NUMBER: _ClassVar[int]
    SEARCH_DIR_FIELD_NUMBER: _ClassVar[int]
    SKIP_MISSING_FIELD_NUMBER: _ClassVar[int]
    INSPECT_ONLY_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    archive: ArchiveSource
    project_id: str
    new_project_name: str
    folder_id: str
    binaries: _containers.RepeatedCompositeFieldContainer[ArchiveSource]
    search_dir: str
    skip_missing: bool
    inspect_only: bool
    provenance: _common_pb2.Provenance
    def __init__(self, archive: _Optional[_Union[ArchiveSource, _Mapping]] = ..., project_id: _Optional[str] = ..., new_project_name: _Optional[str] = ..., folder_id: _Optional[str] = ..., binaries: _Optional[_Iterable[_Union[ArchiveSource, _Mapping]]] = ..., search_dir: _Optional[str] = ..., skip_missing: _Optional[bool] = ..., inspect_only: _Optional[bool] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class ImportProjectArchiveResponse(_message.Message):
    __slots__ = ("snapshot", "project", "manifest", "programs", "warnings")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    PROJECT_FIELD_NUMBER: _ClassVar[int]
    MANIFEST_FIELD_NUMBER: _ClassVar[int]
    PROGRAMS_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    project: ProjectInfo
    manifest: ProjectArchiveManifest
    programs: _containers.RepeatedCompositeFieldContainer[ImportedArchiveProgram]
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., project: _Optional[_Union[ProjectInfo, _Mapping]] = ..., manifest: _Optional[_Union[ProjectArchiveManifest, _Mapping]] = ..., programs: _Optional[_Iterable[_Union[ImportedArchiveProgram, _Mapping]]] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class ImportedArchiveProgram(_message.Message):
    __slots__ = ("key", "name", "sha256", "binary_source", "program", "skipped")
    KEY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    BINARY_SOURCE_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_FIELD_NUMBER: _ClassVar[int]
    SKIPPED_FIELD_NUMBER: _ClassVar[int]
    key: str
    name: str
    sha256: str
    binary_source: str
    program: ProgramInfo
    skipped: bool
    def __init__(self, key: _Optional[str] = ..., name: _Optional[str] = ..., sha256: _Optional[str] = ..., binary_source: _Optional[str] = ..., program: _Optional[_Union[ProgramInfo, _Mapping]] = ..., skipped: _Optional[bool] = ...) -> None: ...

class AddMemoryRegionRequest(_message.Message):
    __slots__ = ("program_id", "region", "path", "content", "file_name", "file_offset", "length", "provenance", "validate_only")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    REGION_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    FILE_NAME_FIELD_NUMBER: _ClassVar[int]
    FILE_OFFSET_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    VALIDATE_ONLY_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    region: MemoryRegion
    path: str
    content: bytes
    file_name: str
    file_offset: int
    length: int
    provenance: _common_pb2.Provenance
    validate_only: bool
    def __init__(self, program_id: _Optional[str] = ..., region: _Optional[_Union[MemoryRegion, _Mapping]] = ..., path: _Optional[str] = ..., content: _Optional[bytes] = ..., file_name: _Optional[str] = ..., file_offset: _Optional[int] = ..., length: _Optional[int] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., validate_only: _Optional[bool] = ...) -> None: ...

class AddMemoryRegionResponse(_message.Message):
    __slots__ = ("snapshot", "region_id", "block", "assertion")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    REGION_ID_FIELD_NUMBER: _ClassVar[int]
    BLOCK_FIELD_NUMBER: _ClassVar[int]
    ASSERTION_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    region_id: str
    block: MemoryBlock
    assertion: _assertion_pb2.Assertion
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., region_id: _Optional[str] = ..., block: _Optional[_Union[MemoryBlock, _Mapping]] = ..., assertion: _Optional[_Union[_assertion_pb2.Assertion, _Mapping]] = ...) -> None: ...

class UpdateMemoryRegionRequest(_message.Message):
    __slots__ = ("program_id", "region_id", "block_start", "region", "provenance", "validate_only")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    REGION_ID_FIELD_NUMBER: _ClassVar[int]
    BLOCK_START_FIELD_NUMBER: _ClassVar[int]
    REGION_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    VALIDATE_ONLY_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    region_id: str
    block_start: _common_pb2.Address
    region: MemoryRegion
    provenance: _common_pb2.Provenance
    validate_only: bool
    def __init__(self, program_id: _Optional[str] = ..., region_id: _Optional[str] = ..., block_start: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., region: _Optional[_Union[MemoryRegion, _Mapping]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., validate_only: _Optional[bool] = ...) -> None: ...

class UpdateMemoryRegionResponse(_message.Message):
    __slots__ = ("snapshot", "block", "assertion")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    BLOCK_FIELD_NUMBER: _ClassVar[int]
    ASSERTION_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    block: MemoryBlock
    assertion: _assertion_pb2.Assertion
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., block: _Optional[_Union[MemoryBlock, _Mapping]] = ..., assertion: _Optional[_Union[_assertion_pb2.Assertion, _Mapping]] = ...) -> None: ...

class RemoveMemoryRegionRequest(_message.Message):
    __slots__ = ("program_id", "region_id", "block_start", "provenance")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    REGION_ID_FIELD_NUMBER: _ClassVar[int]
    BLOCK_START_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    region_id: str
    block_start: _common_pb2.Address
    provenance: _common_pb2.Provenance
    def __init__(self, program_id: _Optional[str] = ..., region_id: _Optional[str] = ..., block_start: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class LoadPdbRequest(_message.Message):
    __slots__ = ("program_id", "path", "upload_id", "symbol_path", "force", "provenance")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    UPLOAD_ID_FIELD_NUMBER: _ClassVar[int]
    SYMBOL_PATH_FIELD_NUMBER: _ClassVar[int]
    FORCE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    path: str
    upload_id: str
    symbol_path: bool
    force: bool
    provenance: _common_pb2.Provenance
    def __init__(self, program_id: _Optional[str] = ..., path: _Optional[str] = ..., upload_id: _Optional[str] = ..., symbol_path: _Optional[bool] = ..., force: _Optional[bool] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class LoadPdbResponse(_message.Message):
    __slots__ = ("snapshot", "pdb_file", "exact", "source", "functions", "variables", "types", "warnings", "search_log", "assertion_seqs")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    PDB_FILE_FIELD_NUMBER: _ClassVar[int]
    EXACT_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    VARIABLES_FIELD_NUMBER: _ClassVar[int]
    TYPES_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    SEARCH_LOG_FIELD_NUMBER: _ClassVar[int]
    ASSERTION_SEQS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    pdb_file: str
    exact: bool
    source: str
    functions: int
    variables: int
    types: int
    warnings: _containers.RepeatedScalarFieldContainer[str]
    search_log: _containers.RepeatedScalarFieldContainer[str]
    assertion_seqs: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., pdb_file: _Optional[str] = ..., exact: _Optional[bool] = ..., source: _Optional[str] = ..., functions: _Optional[int] = ..., variables: _Optional[int] = ..., types: _Optional[int] = ..., warnings: _Optional[_Iterable[str]] = ..., search_log: _Optional[_Iterable[str]] = ..., assertion_seqs: _Optional[_Iterable[int]] = ...) -> None: ...

class SymbolSettings(_message.Message):
    __slots__ = ("symbol_path", "downloads", "cache_dir")
    SYMBOL_PATH_FIELD_NUMBER: _ClassVar[int]
    DOWNLOADS_FIELD_NUMBER: _ClassVar[int]
    CACHE_DIR_FIELD_NUMBER: _ClassVar[int]
    symbol_path: str
    downloads: bool
    cache_dir: str
    def __init__(self, symbol_path: _Optional[str] = ..., downloads: _Optional[bool] = ..., cache_dir: _Optional[str] = ...) -> None: ...

class GetSymbolSettingsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetSymbolSettingsResponse(_message.Message):
    __slots__ = ("settings",)
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    settings: SymbolSettings
    def __init__(self, settings: _Optional[_Union[SymbolSettings, _Mapping]] = ...) -> None: ...

class SetSymbolSettingsRequest(_message.Message):
    __slots__ = ("settings",)
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    settings: SymbolSettings
    def __init__(self, settings: _Optional[_Union[SymbolSettings, _Mapping]] = ...) -> None: ...

class SetSymbolSettingsResponse(_message.Message):
    __slots__ = ("settings",)
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    settings: SymbolSettings
    def __init__(self, settings: _Optional[_Union[SymbolSettings, _Mapping]] = ...) -> None: ...

class SetImageBaseRequest(_message.Message):
    __slots__ = ("program_id", "image_base", "provenance", "validate_only")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    IMAGE_BASE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    VALIDATE_ONLY_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    image_base: int
    provenance: _common_pb2.Provenance
    validate_only: bool
    def __init__(self, program_id: _Optional[str] = ..., image_base: _Optional[int] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., validate_only: _Optional[bool] = ...) -> None: ...

class SetImageBaseResponse(_message.Message):
    __slots__ = ("snapshot", "assertion", "image_base", "previous_image_base", "import_image_base")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ASSERTION_FIELD_NUMBER: _ClassVar[int]
    IMAGE_BASE_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_IMAGE_BASE_FIELD_NUMBER: _ClassVar[int]
    IMPORT_IMAGE_BASE_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    assertion: _assertion_pb2.Assertion
    image_base: int
    previous_image_base: int
    import_image_base: int
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., assertion: _Optional[_Union[_assertion_pb2.Assertion, _Mapping]] = ..., image_base: _Optional[int] = ..., previous_image_base: _Optional[int] = ..., import_image_base: _Optional[int] = ...) -> None: ...

class SetProgramLanguageRequest(_message.Message):
    __slots__ = ("program_id", "language_id", "compiler_spec_id", "provenance", "validate_only", "progress_id")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_ID_FIELD_NUMBER: _ClassVar[int]
    COMPILER_SPEC_ID_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    VALIDATE_ONLY_FIELD_NUMBER: _ClassVar[int]
    PROGRESS_ID_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    language_id: str
    compiler_spec_id: str
    provenance: _common_pb2.Provenance
    validate_only: bool
    progress_id: str
    def __init__(self, program_id: _Optional[str] = ..., language_id: _Optional[str] = ..., compiler_spec_id: _Optional[str] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., validate_only: _Optional[bool] = ..., progress_id: _Optional[str] = ...) -> None: ...

class SetProgramLanguageResponse(_message.Message):
    __slots__ = ("snapshot", "assertion", "language_id", "compiler_spec_id", "previous_language_id", "previous_compiler_spec_id")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ASSERTION_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_ID_FIELD_NUMBER: _ClassVar[int]
    COMPILER_SPEC_ID_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_LANGUAGE_ID_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_COMPILER_SPEC_ID_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    assertion: _assertion_pb2.Assertion
    language_id: str
    compiler_spec_id: str
    previous_language_id: str
    previous_compiler_spec_id: str
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., assertion: _Optional[_Union[_assertion_pb2.Assertion, _Mapping]] = ..., language_id: _Optional[str] = ..., compiler_spec_id: _Optional[str] = ..., previous_language_id: _Optional[str] = ..., previous_compiler_spec_id: _Optional[str] = ...) -> None: ...

class CompareLanguagesRequest(_message.Message):
    __slots__ = ("program_id", "language_ids")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_IDS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    language_ids: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, program_id: _Optional[str] = ..., language_ids: _Optional[_Iterable[str]] = ...) -> None: ...

class LanguageFit(_message.Message):
    __slots__ = ("language_id", "mode", "description", "current", "compatible", "decoded", "instructions", "invalid", "unimplemented", "reached", "reached_invalid", "recommended", "note")
    LANGUAGE_ID_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    CURRENT_FIELD_NUMBER: _ClassVar[int]
    COMPATIBLE_FIELD_NUMBER: _ClassVar[int]
    DECODED_FIELD_NUMBER: _ClassVar[int]
    INSTRUCTIONS_FIELD_NUMBER: _ClassVar[int]
    INVALID_FIELD_NUMBER: _ClassVar[int]
    UNIMPLEMENTED_FIELD_NUMBER: _ClassVar[int]
    REACHED_FIELD_NUMBER: _ClassVar[int]
    REACHED_INVALID_FIELD_NUMBER: _ClassVar[int]
    RECOMMENDED_FIELD_NUMBER: _ClassVar[int]
    NOTE_FIELD_NUMBER: _ClassVar[int]
    language_id: str
    mode: str
    description: str
    current: bool
    compatible: bool
    decoded: float
    instructions: int
    invalid: int
    unimplemented: int
    reached: int
    reached_invalid: int
    recommended: bool
    note: str
    def __init__(self, language_id: _Optional[str] = ..., mode: _Optional[str] = ..., description: _Optional[str] = ..., current: _Optional[bool] = ..., compatible: _Optional[bool] = ..., decoded: _Optional[float] = ..., instructions: _Optional[int] = ..., invalid: _Optional[int] = ..., unimplemented: _Optional[int] = ..., reached: _Optional[int] = ..., reached_invalid: _Optional[int] = ..., recommended: _Optional[bool] = ..., note: _Optional[str] = ...) -> None: ...

class CompareLanguagesResponse(_message.Message):
    __slots__ = ("fits", "bytes", "samples", "elapsed_seconds")
    FITS_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    SAMPLES_FIELD_NUMBER: _ClassVar[int]
    ELAPSED_SECONDS_FIELD_NUMBER: _ClassVar[int]
    fits: _containers.RepeatedCompositeFieldContainer[LanguageFit]
    bytes: int
    samples: int
    elapsed_seconds: float
    def __init__(self, fits: _Optional[_Iterable[_Union[LanguageFit, _Mapping]]] = ..., bytes: _Optional[int] = ..., samples: _Optional[int] = ..., elapsed_seconds: _Optional[float] = ...) -> None: ...

class RemoveMemoryRegionResponse(_message.Message):
    __slots__ = ("snapshot", "assertion")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ASSERTION_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    assertion: _assertion_pb2.Assertion
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., assertion: _Optional[_Union[_assertion_pb2.Assertion, _Mapping]] = ...) -> None: ...

class DeleteProgramRequest(_message.Message):
    __slots__ = ("program_id", "provenance")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    provenance: _common_pb2.Provenance
    def __init__(self, program_id: _Optional[str] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class DeleteProgramResponse(_message.Message):
    __slots__ = ("snapshot", "assertion")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ASSERTION_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    assertion: _assertion_pb2.Assertion
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., assertion: _Optional[_Union[_assertion_pb2.Assertion, _Mapping]] = ...) -> None: ...

class RenameProgramRequest(_message.Message):
    __slots__ = ("program_id", "name", "provenance")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    name: str
    provenance: _common_pb2.Provenance
    def __init__(self, program_id: _Optional[str] = ..., name: _Optional[str] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class RenameProgramResponse(_message.Message):
    __slots__ = ("snapshot", "program", "assertion")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_FIELD_NUMBER: _ClassVar[int]
    ASSERTION_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    program: ProgramInfo
    assertion: _assertion_pb2.Assertion
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., program: _Optional[_Union[ProgramInfo, _Mapping]] = ..., assertion: _Optional[_Union[_assertion_pb2.Assertion, _Mapping]] = ...) -> None: ...

class ListLanguagesRequest(_message.Message):
    __slots__ = ("include_deprecated",)
    INCLUDE_DEPRECATED_FIELD_NUMBER: _ClassVar[int]
    include_deprecated: bool
    def __init__(self, include_deprecated: _Optional[bool] = ...) -> None: ...

class AvailableLanguage(_message.Message):
    __slots__ = ("language_id", "processor", "endianness", "address_size", "variant", "description", "deprecated", "compiler_spec_ids")
    LANGUAGE_ID_FIELD_NUMBER: _ClassVar[int]
    PROCESSOR_FIELD_NUMBER: _ClassVar[int]
    ENDIANNESS_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_SIZE_FIELD_NUMBER: _ClassVar[int]
    VARIANT_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DEPRECATED_FIELD_NUMBER: _ClassVar[int]
    COMPILER_SPEC_IDS_FIELD_NUMBER: _ClassVar[int]
    language_id: str
    processor: str
    endianness: Endianness
    address_size: int
    variant: str
    description: str
    deprecated: bool
    compiler_spec_ids: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, language_id: _Optional[str] = ..., processor: _Optional[str] = ..., endianness: _Optional[_Union[Endianness, str]] = ..., address_size: _Optional[int] = ..., variant: _Optional[str] = ..., description: _Optional[str] = ..., deprecated: _Optional[bool] = ..., compiler_spec_ids: _Optional[_Iterable[str]] = ...) -> None: ...

class ListLanguagesResponse(_message.Message):
    __slots__ = ("languages",)
    LANGUAGES_FIELD_NUMBER: _ClassVar[int]
    languages: _containers.RepeatedCompositeFieldContainer[AvailableLanguage]
    def __init__(self, languages: _Optional[_Iterable[_Union[AvailableLanguage, _Mapping]]] = ...) -> None: ...

class ListHostFilesRequest(_message.Message):
    __slots__ = ("path", "include_hidden")
    PATH_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_HIDDEN_FIELD_NUMBER: _ClassVar[int]
    path: str
    include_hidden: bool
    def __init__(self, path: _Optional[str] = ..., include_hidden: _Optional[bool] = ...) -> None: ...

class HostFileEntry(_message.Message):
    __slots__ = ("name", "path", "directory", "size", "modified")
    NAME_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    DIRECTORY_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    MODIFIED_FIELD_NUMBER: _ClassVar[int]
    name: str
    path: str
    directory: bool
    size: int
    modified: _timestamp_pb2.Timestamp
    def __init__(self, name: _Optional[str] = ..., path: _Optional[str] = ..., directory: _Optional[bool] = ..., size: _Optional[int] = ..., modified: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListHostFilesResponse(_message.Message):
    __slots__ = ("path", "parent", "entries", "roots", "truncated")
    PATH_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    ROOTS_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    path: str
    parent: str
    entries: _containers.RepeatedCompositeFieldContainer[HostFileEntry]
    roots: _containers.RepeatedScalarFieldContainer[str]
    truncated: bool
    def __init__(self, path: _Optional[str] = ..., parent: _Optional[str] = ..., entries: _Optional[_Iterable[_Union[HostFileEntry, _Mapping]]] = ..., roots: _Optional[_Iterable[str]] = ..., truncated: _Optional[bool] = ...) -> None: ...

class ProjectInfo(_message.Message):
    __slots__ = ("project_id", "name", "path", "open", "head_revision", "oldest_retained_revision", "program_count")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    OPEN_FIELD_NUMBER: _ClassVar[int]
    HEAD_REVISION_FIELD_NUMBER: _ClassVar[int]
    OLDEST_RETAINED_REVISION_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_COUNT_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    name: str
    path: str
    open: bool
    head_revision: int
    oldest_retained_revision: int
    program_count: int
    def __init__(self, project_id: _Optional[str] = ..., name: _Optional[str] = ..., path: _Optional[str] = ..., open: _Optional[bool] = ..., head_revision: _Optional[int] = ..., oldest_retained_revision: _Optional[int] = ..., program_count: _Optional[int] = ...) -> None: ...

class ListProjectsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListProjectsResponse(_message.Message):
    __slots__ = ("projects",)
    PROJECTS_FIELD_NUMBER: _ClassVar[int]
    projects: _containers.RepeatedCompositeFieldContainer[ProjectInfo]
    def __init__(self, projects: _Optional[_Iterable[_Union[ProjectInfo, _Mapping]]] = ...) -> None: ...

class OpenProjectRequest(_message.Message):
    __slots__ = ("project_id", "path", "create_if_missing", "name")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    CREATE_IF_MISSING_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    path: str
    create_if_missing: bool
    name: str
    def __init__(self, project_id: _Optional[str] = ..., path: _Optional[str] = ..., create_if_missing: _Optional[bool] = ..., name: _Optional[str] = ...) -> None: ...

class OpenProjectResponse(_message.Message):
    __slots__ = ("project", "programs", "folders")
    PROJECT_FIELD_NUMBER: _ClassVar[int]
    PROGRAMS_FIELD_NUMBER: _ClassVar[int]
    FOLDERS_FIELD_NUMBER: _ClassVar[int]
    project: ProjectInfo
    programs: _containers.RepeatedCompositeFieldContainer[ProgramInfo]
    folders: _containers.RepeatedCompositeFieldContainer[ProjectFolder]
    def __init__(self, project: _Optional[_Union[ProjectInfo, _Mapping]] = ..., programs: _Optional[_Iterable[_Union[ProgramInfo, _Mapping]]] = ..., folders: _Optional[_Iterable[_Union[ProjectFolder, _Mapping]]] = ...) -> None: ...

class CloseProjectRequest(_message.Message):
    __slots__ = ("project_id",)
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    def __init__(self, project_id: _Optional[str] = ...) -> None: ...

class CloseProjectResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ProgramInfo(_message.Message):
    __slots__ = ("program_id", "project_id", "name", "format", "language_id", "sha256", "imported_at", "deleted", "deleted_origin", "name_origin", "folder_id", "folder_path", "folder_origin", "container_path", "compiler_spec_id", "file_size")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_ID_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    IMPORTED_AT_FIELD_NUMBER: _ClassVar[int]
    DELETED_FIELD_NUMBER: _ClassVar[int]
    DELETED_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    NAME_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    FOLDER_ID_FIELD_NUMBER: _ClassVar[int]
    FOLDER_PATH_FIELD_NUMBER: _ClassVar[int]
    FOLDER_ORIGIN_FIELD_NUMBER: _ClassVar[int]
    CONTAINER_PATH_FIELD_NUMBER: _ClassVar[int]
    COMPILER_SPEC_ID_FIELD_NUMBER: _ClassVar[int]
    FILE_SIZE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    project_id: str
    name: str
    format: str
    language_id: str
    sha256: str
    imported_at: _timestamp_pb2.Timestamp
    deleted: bool
    deleted_origin: _common_pb2.FactOrigin
    name_origin: _common_pb2.FactOrigin
    folder_id: str
    folder_path: str
    folder_origin: _common_pb2.FactOrigin
    container_path: str
    compiler_spec_id: str
    file_size: int
    def __init__(self, program_id: _Optional[str] = ..., project_id: _Optional[str] = ..., name: _Optional[str] = ..., format: _Optional[str] = ..., language_id: _Optional[str] = ..., sha256: _Optional[str] = ..., imported_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., deleted: _Optional[bool] = ..., deleted_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., name_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., folder_id: _Optional[str] = ..., folder_path: _Optional[str] = ..., folder_origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., container_path: _Optional[str] = ..., compiler_spec_id: _Optional[str] = ..., file_size: _Optional[int] = ...) -> None: ...

class ListProgramsRequest(_message.Message):
    __slots__ = ("project_id", "read", "include_deleted")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_DELETED_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    read: _common_pb2.ReadOptions
    include_deleted: bool
    def __init__(self, project_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., include_deleted: _Optional[bool] = ...) -> None: ...

class ListProgramsResponse(_message.Message):
    __slots__ = ("snapshot", "programs", "folders")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    PROGRAMS_FIELD_NUMBER: _ClassVar[int]
    FOLDERS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    programs: _containers.RepeatedCompositeFieldContainer[ProgramInfo]
    folders: _containers.RepeatedCompositeFieldContainer[ProjectFolder]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., programs: _Optional[_Iterable[_Union[ProgramInfo, _Mapping]]] = ..., folders: _Optional[_Iterable[_Union[ProjectFolder, _Mapping]]] = ...) -> None: ...

class ImportProgramRequest(_message.Message):
    __slots__ = ("project_id", "path", "content", "name", "options", "provenance", "import_id", "folder_id")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    OPTIONS_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    IMPORT_ID_FIELD_NUMBER: _ClassVar[int]
    FOLDER_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    path: str
    content: bytes
    name: str
    options: ImportOptions
    provenance: _common_pb2.Provenance
    import_id: str
    folder_id: str
    def __init__(self, project_id: _Optional[str] = ..., path: _Optional[str] = ..., content: _Optional[bytes] = ..., name: _Optional[str] = ..., options: _Optional[_Union[ImportOptions, _Mapping]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., import_id: _Optional[str] = ..., folder_id: _Optional[str] = ...) -> None: ...

class GetImportProgressRequest(_message.Message):
    __slots__ = ("project_id", "import_id")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    IMPORT_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    import_id: str
    def __init__(self, project_id: _Optional[str] = ..., import_id: _Optional[str] = ...) -> None: ...

class GetImportProgressResponse(_message.Message):
    __slots__ = ("phase", "message", "progress", "done", "error", "program_id", "functions_found", "elapsed_seconds")
    PHASE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    DONE_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FOUND_FIELD_NUMBER: _ClassVar[int]
    ELAPSED_SECONDS_FIELD_NUMBER: _ClassVar[int]
    phase: ImportPhase
    message: str
    progress: float
    done: bool
    error: str
    program_id: str
    functions_found: int
    elapsed_seconds: float
    def __init__(self, phase: _Optional[_Union[ImportPhase, str]] = ..., message: _Optional[str] = ..., progress: _Optional[float] = ..., done: _Optional[bool] = ..., error: _Optional[str] = ..., program_id: _Optional[str] = ..., functions_found: _Optional[int] = ..., elapsed_seconds: _Optional[float] = ...) -> None: ...

class DetectRawLayoutRequest(_message.Message):
    __slots__ = ("project_id", "path", "content", "hints", "detect_id")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    HINTS_FIELD_NUMBER: _ClassVar[int]
    DETECT_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    path: str
    content: bytes
    hints: RawDetectHints
    detect_id: str
    def __init__(self, project_id: _Optional[str] = ..., path: _Optional[str] = ..., content: _Optional[bytes] = ..., hints: _Optional[_Union[RawDetectHints, _Mapping]] = ..., detect_id: _Optional[str] = ...) -> None: ...

class RawDetectHints(_message.Message):
    __slots__ = ("language_id", "processor")
    LANGUAGE_ID_FIELD_NUMBER: _ClassVar[int]
    PROCESSOR_FIELD_NUMBER: _ClassVar[int]
    language_id: str
    processor: str
    def __init__(self, language_id: _Optional[str] = ..., processor: _Optional[str] = ...) -> None: ...

class DetectEvidence(_message.Message):
    __slots__ = ("about", "text")
    ABOUT_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    about: str
    text: str
    def __init__(self, about: _Optional[str] = ..., text: _Optional[str] = ...) -> None: ...

class RawLayoutSuggestion(_message.Message):
    __slots__ = ("options", "processor_confidence", "variant_confidence", "base_confidence", "offset_confidence", "evidence", "tie_group", "score", "language_pinned", "region_details")
    OPTIONS_FIELD_NUMBER: _ClassVar[int]
    PROCESSOR_CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    VARIANT_CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    BASE_CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    OFFSET_CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    TIE_GROUP_FIELD_NUMBER: _ClassVar[int]
    SCORE_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_PINNED_FIELD_NUMBER: _ClassVar[int]
    REGION_DETAILS_FIELD_NUMBER: _ClassVar[int]
    options: ImportOptions
    processor_confidence: DetectConfidence
    variant_confidence: DetectConfidence
    base_confidence: DetectConfidence
    offset_confidence: DetectConfidence
    evidence: _containers.RepeatedCompositeFieldContainer[DetectEvidence]
    tie_group: _containers.RepeatedScalarFieldContainer[str]
    score: float
    language_pinned: bool
    region_details: _containers.RepeatedCompositeFieldContainer[RawRegionSuggestion]
    def __init__(self, options: _Optional[_Union[ImportOptions, _Mapping]] = ..., processor_confidence: _Optional[_Union[DetectConfidence, str]] = ..., variant_confidence: _Optional[_Union[DetectConfidence, str]] = ..., base_confidence: _Optional[_Union[DetectConfidence, str]] = ..., offset_confidence: _Optional[_Union[DetectConfidence, str]] = ..., evidence: _Optional[_Iterable[_Union[DetectEvidence, _Mapping]]] = ..., tie_group: _Optional[_Iterable[str]] = ..., score: _Optional[float] = ..., language_pinned: _Optional[bool] = ..., region_details: _Optional[_Iterable[_Union[RawRegionSuggestion, _Mapping]]] = ...) -> None: ...

class RawRegionSuggestion(_message.Message):
    __slots__ = ("kind", "region", "spec", "confidence", "evidence")
    KIND_FIELD_NUMBER: _ClassVar[int]
    REGION_FIELD_NUMBER: _ClassVar[int]
    SPEC_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    kind: RawRegionKind
    region: MemoryRegion
    spec: str
    confidence: DetectConfidence
    evidence: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, kind: _Optional[_Union[RawRegionKind, str]] = ..., region: _Optional[_Union[MemoryRegion, _Mapping]] = ..., spec: _Optional[str] = ..., confidence: _Optional[_Union[DetectConfidence, str]] = ..., evidence: _Optional[_Iterable[str]] = ...) -> None: ...

class RawDetectRefusal(_message.Message):
    __slots__ = ("reason", "detail")
    REASON_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    reason: str
    detail: str
    def __init__(self, reason: _Optional[str] = ..., detail: _Optional[str] = ...) -> None: ...

class RawFileSegment(_message.Message):
    __slots__ = ("offset", "size", "kind")
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    offset: int
    size: int
    kind: RawSegmentKind
    def __init__(self, offset: _Optional[int] = ..., size: _Optional[int] = ..., kind: _Optional[_Union[RawSegmentKind, str]] = ...) -> None: ...

class DetectRawLayoutResponse(_message.Message):
    __slots__ = ("suggestions", "refusal", "segments", "file_size", "elapsed_seconds")
    SUGGESTIONS_FIELD_NUMBER: _ClassVar[int]
    REFUSAL_FIELD_NUMBER: _ClassVar[int]
    SEGMENTS_FIELD_NUMBER: _ClassVar[int]
    FILE_SIZE_FIELD_NUMBER: _ClassVar[int]
    ELAPSED_SECONDS_FIELD_NUMBER: _ClassVar[int]
    suggestions: _containers.RepeatedCompositeFieldContainer[RawLayoutSuggestion]
    refusal: RawDetectRefusal
    segments: _containers.RepeatedCompositeFieldContainer[RawFileSegment]
    file_size: int
    elapsed_seconds: float
    def __init__(self, suggestions: _Optional[_Iterable[_Union[RawLayoutSuggestion, _Mapping]]] = ..., refusal: _Optional[_Union[RawDetectRefusal, _Mapping]] = ..., segments: _Optional[_Iterable[_Union[RawFileSegment, _Mapping]]] = ..., file_size: _Optional[int] = ..., elapsed_seconds: _Optional[float] = ...) -> None: ...

class GetRawDetectProgressRequest(_message.Message):
    __slots__ = ("project_id", "detect_id")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    DETECT_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    detect_id: str
    def __init__(self, project_id: _Optional[str] = ..., detect_id: _Optional[str] = ...) -> None: ...

class GetRawDetectProgressResponse(_message.Message):
    __slots__ = ("phase", "message", "progress", "done", "error", "cancelled", "candidates_done", "candidates_total", "elapsed_seconds")
    PHASE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    DONE_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    CANCELLED_FIELD_NUMBER: _ClassVar[int]
    CANDIDATES_DONE_FIELD_NUMBER: _ClassVar[int]
    CANDIDATES_TOTAL_FIELD_NUMBER: _ClassVar[int]
    ELAPSED_SECONDS_FIELD_NUMBER: _ClassVar[int]
    phase: RawDetectPhase
    message: str
    progress: float
    done: bool
    error: str
    cancelled: bool
    candidates_done: int
    candidates_total: int
    elapsed_seconds: float
    def __init__(self, phase: _Optional[_Union[RawDetectPhase, str]] = ..., message: _Optional[str] = ..., progress: _Optional[float] = ..., done: _Optional[bool] = ..., error: _Optional[str] = ..., cancelled: _Optional[bool] = ..., candidates_done: _Optional[int] = ..., candidates_total: _Optional[int] = ..., elapsed_seconds: _Optional[float] = ...) -> None: ...

class CancelRawDetectRequest(_message.Message):
    __slots__ = ("project_id", "detect_id")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    DETECT_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    detect_id: str
    def __init__(self, project_id: _Optional[str] = ..., detect_id: _Optional[str] = ...) -> None: ...

class CancelRawDetectResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ImportOptions(_message.Message):
    __slots__ = ("format", "language_id", "compiler_spec_id", "has_image_base", "image_base", "analyze", "raw_offset", "raw_length", "raw_permissions", "has_entry_point", "entry_point", "regions", "raw_space", "raw_format", "import_libraries", "library_search_paths", "library_depth")
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_ID_FIELD_NUMBER: _ClassVar[int]
    COMPILER_SPEC_ID_FIELD_NUMBER: _ClassVar[int]
    HAS_IMAGE_BASE_FIELD_NUMBER: _ClassVar[int]
    IMAGE_BASE_FIELD_NUMBER: _ClassVar[int]
    ANALYZE_FIELD_NUMBER: _ClassVar[int]
    RAW_OFFSET_FIELD_NUMBER: _ClassVar[int]
    RAW_LENGTH_FIELD_NUMBER: _ClassVar[int]
    RAW_PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    HAS_ENTRY_POINT_FIELD_NUMBER: _ClassVar[int]
    ENTRY_POINT_FIELD_NUMBER: _ClassVar[int]
    REGIONS_FIELD_NUMBER: _ClassVar[int]
    RAW_SPACE_FIELD_NUMBER: _ClassVar[int]
    RAW_FORMAT_FIELD_NUMBER: _ClassVar[int]
    IMPORT_LIBRARIES_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_SEARCH_PATHS_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_DEPTH_FIELD_NUMBER: _ClassVar[int]
    format: str
    language_id: str
    compiler_spec_id: str
    has_image_base: bool
    image_base: int
    analyze: bool
    raw_offset: int
    raw_length: int
    raw_permissions: str
    has_entry_point: bool
    entry_point: int
    regions: _containers.RepeatedCompositeFieldContainer[MemoryRegion]
    raw_space: str
    raw_format: str
    import_libraries: bool
    library_search_paths: _containers.RepeatedScalarFieldContainer[str]
    library_depth: int
    def __init__(self, format: _Optional[str] = ..., language_id: _Optional[str] = ..., compiler_spec_id: _Optional[str] = ..., has_image_base: _Optional[bool] = ..., image_base: _Optional[int] = ..., analyze: _Optional[bool] = ..., raw_offset: _Optional[int] = ..., raw_length: _Optional[int] = ..., raw_permissions: _Optional[str] = ..., has_entry_point: _Optional[bool] = ..., entry_point: _Optional[int] = ..., regions: _Optional[_Iterable[_Union[MemoryRegion, _Mapping]]] = ..., raw_space: _Optional[str] = ..., raw_format: _Optional[str] = ..., import_libraries: _Optional[bool] = ..., library_search_paths: _Optional[_Iterable[str]] = ..., library_depth: _Optional[int] = ...) -> None: ...

class MemoryRegion(_message.Message):
    __slots__ = ("name", "start", "size", "read", "write", "execute", "initialized", "is_volatile", "space")
    NAME_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    WRITE_FIELD_NUMBER: _ClassVar[int]
    EXECUTE_FIELD_NUMBER: _ClassVar[int]
    INITIALIZED_FIELD_NUMBER: _ClassVar[int]
    IS_VOLATILE_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    start: int
    size: int
    read: bool
    write: bool
    execute: bool
    initialized: bool
    is_volatile: bool
    space: str
    def __init__(self, name: _Optional[str] = ..., start: _Optional[int] = ..., size: _Optional[int] = ..., read: _Optional[bool] = ..., write: _Optional[bool] = ..., execute: _Optional[bool] = ..., initialized: _Optional[bool] = ..., is_volatile: _Optional[bool] = ..., space: _Optional[str] = ...) -> None: ...

class ImportProgramResponse(_message.Message):
    __slots__ = ("snapshot", "program", "analysis_job_id", "warnings", "libraries", "libraries_not_found")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_FIELD_NUMBER: _ClassVar[int]
    ANALYSIS_JOB_ID_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    LIBRARIES_FIELD_NUMBER: _ClassVar[int]
    LIBRARIES_NOT_FOUND_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    program: ProgramInfo
    analysis_job_id: str
    warnings: _containers.RepeatedScalarFieldContainer[str]
    libraries: _containers.RepeatedCompositeFieldContainer[ProgramInfo]
    libraries_not_found: _containers.RepeatedCompositeFieldContainer[MissingLibrary]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., program: _Optional[_Union[ProgramInfo, _Mapping]] = ..., analysis_job_id: _Optional[str] = ..., warnings: _Optional[_Iterable[str]] = ..., libraries: _Optional[_Iterable[_Union[ProgramInfo, _Mapping]]] = ..., libraries_not_found: _Optional[_Iterable[_Union[MissingLibrary, _Mapping]]] = ...) -> None: ...

class MissingLibrary(_message.Message):
    __slots__ = ("name", "needed_by")
    NAME_FIELD_NUMBER: _ClassVar[int]
    NEEDED_BY_FIELD_NUMBER: _ClassVar[int]
    name: str
    needed_by: str
    def __init__(self, name: _Optional[str] = ..., needed_by: _Optional[str] = ...) -> None: ...

class ListProgramLibrariesRequest(_message.Message):
    __slots__ = ("program_id", "read", "include_imports")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_IMPORTS_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    include_imports: bool
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., include_imports: _Optional[bool] = ...) -> None: ...

class ProgramLibrary(_message.Message):
    __slots__ = ("name", "resolution", "program_id", "program_name", "folder_path", "origin", "imports_resolved", "depth", "needed_by")
    NAME_FIELD_NUMBER: _ClassVar[int]
    RESOLUTION_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_NAME_FIELD_NUMBER: _ClassVar[int]
    FOLDER_PATH_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    IMPORTS_RESOLVED_FIELD_NUMBER: _ClassVar[int]
    DEPTH_FIELD_NUMBER: _ClassVar[int]
    NEEDED_BY_FIELD_NUMBER: _ClassVar[int]
    name: str
    resolution: LibraryResolution
    program_id: str
    program_name: str
    folder_path: str
    origin: _common_pb2.FactOrigin
    imports_resolved: int
    depth: int
    needed_by: str
    def __init__(self, name: _Optional[str] = ..., resolution: _Optional[_Union[LibraryResolution, str]] = ..., program_id: _Optional[str] = ..., program_name: _Optional[str] = ..., folder_path: _Optional[str] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., imports_resolved: _Optional[int] = ..., depth: _Optional[int] = ..., needed_by: _Optional[str] = ...) -> None: ...

class ResolvedImport(_message.Message):
    __slots__ = ("name", "library", "thunk", "slot", "program_id", "address", "function_name", "resolved")
    NAME_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_FIELD_NUMBER: _ClassVar[int]
    THUNK_FIELD_NUMBER: _ClassVar[int]
    SLOT_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    RESOLVED_FIELD_NUMBER: _ClassVar[int]
    name: str
    library: str
    thunk: _common_pb2.Address
    slot: _common_pb2.Address
    program_id: str
    address: _common_pb2.Address
    function_name: str
    resolved: bool
    def __init__(self, name: _Optional[str] = ..., library: _Optional[str] = ..., thunk: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., slot: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., program_id: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., function_name: _Optional[str] = ..., resolved: _Optional[bool] = ...) -> None: ...

class ListProgramLibrariesResponse(_message.Message):
    __slots__ = ("snapshot", "libraries", "imports", "soname", "build_id")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    LIBRARIES_FIELD_NUMBER: _ClassVar[int]
    IMPORTS_FIELD_NUMBER: _ClassVar[int]
    SONAME_FIELD_NUMBER: _ClassVar[int]
    BUILD_ID_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    libraries: _containers.RepeatedCompositeFieldContainer[ProgramLibrary]
    imports: _containers.RepeatedCompositeFieldContainer[ResolvedImport]
    soname: str
    build_id: str
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., libraries: _Optional[_Iterable[_Union[ProgramLibrary, _Mapping]]] = ..., imports: _Optional[_Iterable[_Union[ResolvedImport, _Mapping]]] = ..., soname: _Optional[str] = ..., build_id: _Optional[str] = ...) -> None: ...

class LinkProgramLibraryRequest(_message.Message):
    __slots__ = ("program_id", "library", "target_program_id", "provenance")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_FIELD_NUMBER: _ClassVar[int]
    TARGET_PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    library: str
    target_program_id: str
    provenance: _common_pb2.Provenance
    def __init__(self, program_id: _Optional[str] = ..., library: _Optional[str] = ..., target_program_id: _Optional[str] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class LinkProgramLibraryResponse(_message.Message):
    __slots__ = ("snapshot", "assertion", "library")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ASSERTION_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    assertion: _assertion_pb2.Assertion
    library: ProgramLibrary
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., assertion: _Optional[_Union[_assertion_pb2.Assertion, _Mapping]] = ..., library: _Optional[_Union[ProgramLibrary, _Mapping]] = ...) -> None: ...

class ResolveImportRequest(_message.Message):
    __slots__ = ("program_id", "read", "address", "name")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    address: _common_pb2.Address
    name: str
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., name: _Optional[str] = ...) -> None: ...

class ResolveImportResponse(_message.Message):
    __slots__ = ("snapshot", "resolved")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    RESOLVED_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    resolved: ResolvedImport
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., resolved: _Optional[_Union[ResolvedImport, _Mapping]] = ...) -> None: ...

class GetProgramSummaryRequest(_message.Message):
    __slots__ = ("program_id", "read")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ...) -> None: ...

class GetProgramSummaryResponse(_message.Message):
    __slots__ = ("snapshot", "summary")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    SUMMARY_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    summary: ProgramSummary
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., summary: _Optional[_Union[ProgramSummary, _Mapping]] = ...) -> None: ...

class ProgramSummary(_message.Message):
    __slots__ = ("info", "language", "image_base", "entry_points", "memory", "function_count", "instruction_count", "file_size", "spaces", "import_image_base")
    INFO_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    IMAGE_BASE_FIELD_NUMBER: _ClassVar[int]
    ENTRY_POINTS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_COUNT_FIELD_NUMBER: _ClassVar[int]
    INSTRUCTION_COUNT_FIELD_NUMBER: _ClassVar[int]
    FILE_SIZE_FIELD_NUMBER: _ClassVar[int]
    SPACES_FIELD_NUMBER: _ClassVar[int]
    IMPORT_IMAGE_BASE_FIELD_NUMBER: _ClassVar[int]
    info: ProgramInfo
    language: LanguageInfo
    image_base: _common_pb2.Address
    entry_points: _containers.RepeatedCompositeFieldContainer[EntryPoint]
    memory: _containers.RepeatedCompositeFieldContainer[MemoryBlock]
    function_count: int
    instruction_count: int
    file_size: int
    spaces: _containers.RepeatedCompositeFieldContainer[AddressSpaceInfo]
    import_image_base: _common_pb2.Address
    def __init__(self, info: _Optional[_Union[ProgramInfo, _Mapping]] = ..., language: _Optional[_Union[LanguageInfo, _Mapping]] = ..., image_base: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., entry_points: _Optional[_Iterable[_Union[EntryPoint, _Mapping]]] = ..., memory: _Optional[_Iterable[_Union[MemoryBlock, _Mapping]]] = ..., function_count: _Optional[int] = ..., instruction_count: _Optional[int] = ..., file_size: _Optional[int] = ..., spaces: _Optional[_Iterable[_Union[AddressSpaceInfo, _Mapping]]] = ..., import_image_base: _Optional[_Union[_common_pb2.Address, _Mapping]] = ...) -> None: ...

class LanguageInfo(_message.Message):
    __slots__ = ("language_id", "compiler_spec_id", "processor", "endianness", "pointer_size", "default_space")
    LANGUAGE_ID_FIELD_NUMBER: _ClassVar[int]
    COMPILER_SPEC_ID_FIELD_NUMBER: _ClassVar[int]
    PROCESSOR_FIELD_NUMBER: _ClassVar[int]
    ENDIANNESS_FIELD_NUMBER: _ClassVar[int]
    POINTER_SIZE_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_SPACE_FIELD_NUMBER: _ClassVar[int]
    language_id: str
    compiler_spec_id: str
    processor: str
    endianness: Endianness
    pointer_size: int
    default_space: str
    def __init__(self, language_id: _Optional[str] = ..., compiler_spec_id: _Optional[str] = ..., processor: _Optional[str] = ..., endianness: _Optional[_Union[Endianness, str]] = ..., pointer_size: _Optional[int] = ..., default_space: _Optional[str] = ...) -> None: ...

class AddressSpaceInfo(_message.Message):
    __slots__ = ("name", "kind", "size", "word_size", "overlay_base", "key_base", "is_default", "alias")
    NAME_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    WORD_SIZE_FIELD_NUMBER: _ClassVar[int]
    OVERLAY_BASE_FIELD_NUMBER: _ClassVar[int]
    KEY_BASE_FIELD_NUMBER: _ClassVar[int]
    IS_DEFAULT_FIELD_NUMBER: _ClassVar[int]
    ALIAS_FIELD_NUMBER: _ClassVar[int]
    name: str
    kind: AddressSpaceKind
    size: int
    word_size: int
    overlay_base: str
    key_base: int
    is_default: bool
    alias: bool
    def __init__(self, name: _Optional[str] = ..., kind: _Optional[_Union[AddressSpaceKind, str]] = ..., size: _Optional[int] = ..., word_size: _Optional[int] = ..., overlay_base: _Optional[str] = ..., key_base: _Optional[int] = ..., is_default: _Optional[bool] = ..., alias: _Optional[bool] = ...) -> None: ...

class EntryPoint(_message.Message):
    __slots__ = ("address", "kind", "name")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    kind: str
    name: str
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., kind: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class MemoryBlock(_message.Message):
    __slots__ = ("name", "range", "read", "write", "execute", "initialized", "has_file_offset", "file_offset", "overlay", "origin", "is_volatile", "region_id", "edited", "source", "rejected")
    NAME_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    WRITE_FIELD_NUMBER: _ClassVar[int]
    EXECUTE_FIELD_NUMBER: _ClassVar[int]
    INITIALIZED_FIELD_NUMBER: _ClassVar[int]
    HAS_FILE_OFFSET_FIELD_NUMBER: _ClassVar[int]
    FILE_OFFSET_FIELD_NUMBER: _ClassVar[int]
    OVERLAY_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    IS_VOLATILE_FIELD_NUMBER: _ClassVar[int]
    REGION_ID_FIELD_NUMBER: _ClassVar[int]
    EDITED_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    REJECTED_FIELD_NUMBER: _ClassVar[int]
    name: str
    range: _common_pb2.AddressRange
    read: bool
    write: bool
    execute: bool
    initialized: bool
    has_file_offset: bool
    file_offset: int
    overlay: bool
    origin: _common_pb2.FactOrigin
    is_volatile: bool
    region_id: str
    edited: bool
    source: MemoryBlockSource
    rejected: str
    def __init__(self, name: _Optional[str] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., read: _Optional[bool] = ..., write: _Optional[bool] = ..., execute: _Optional[bool] = ..., initialized: _Optional[bool] = ..., has_file_offset: _Optional[bool] = ..., file_offset: _Optional[int] = ..., overlay: _Optional[bool] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., is_volatile: _Optional[bool] = ..., region_id: _Optional[str] = ..., edited: _Optional[bool] = ..., source: _Optional[_Union[MemoryBlockSource, _Mapping]] = ..., rejected: _Optional[str] = ...) -> None: ...

class MemoryBlockSource(_message.Message):
    __slots__ = ("kind", "file", "file_offset", "length", "sha256", "missing")
    KIND_FIELD_NUMBER: _ClassVar[int]
    FILE_FIELD_NUMBER: _ClassVar[int]
    FILE_OFFSET_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    MISSING_FIELD_NUMBER: _ClassVar[int]
    kind: MemoryBlockSourceKind
    file: str
    file_offset: int
    length: int
    sha256: str
    missing: bool
    def __init__(self, kind: _Optional[_Union[MemoryBlockSourceKind, str]] = ..., file: _Optional[str] = ..., file_offset: _Optional[int] = ..., length: _Optional[int] = ..., sha256: _Optional[str] = ..., missing: _Optional[bool] = ...) -> None: ...
