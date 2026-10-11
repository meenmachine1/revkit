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

class ChecksumAlgorithm(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CHECKSUM_ALGORITHM_UNSPECIFIED: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_SUM8: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_SUM16: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_SUM32: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_SUM16_WORDS_LE: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_SUM16_WORDS_BE: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_SUM32_WORDS_LE: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_SUM32_WORDS_BE: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_SUM8_NEG: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_SUM32_NEG: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_XOR8: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_FLETCHER16: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_FLETCHER32: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_ADLER32: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_CRC16_CCITT_FALSE: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_CRC16_XMODEM: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_CRC16_KERMIT: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_CRC16_MODBUS: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_CRC16_ARC: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_CRC32: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_CRC32_BZIP2: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_CRC32_MPEG2: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_CRC32_POSIX: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_CRC32_JAMCRC: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_CRC32C: _ClassVar[ChecksumAlgorithm]
    CHECKSUM_ALGORITHM_PE: _ClassVar[ChecksumAlgorithm]

class ExportFormat(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EXPORT_FORMAT_UNSPECIFIED: _ClassVar[ExportFormat]
    EXPORT_FORMAT_FILE: _ClassVar[ExportFormat]
    EXPORT_FORMAT_IMAGE: _ClassVar[ExportFormat]
CHECKSUM_ALGORITHM_UNSPECIFIED: ChecksumAlgorithm
CHECKSUM_ALGORITHM_SUM8: ChecksumAlgorithm
CHECKSUM_ALGORITHM_SUM16: ChecksumAlgorithm
CHECKSUM_ALGORITHM_SUM32: ChecksumAlgorithm
CHECKSUM_ALGORITHM_SUM16_WORDS_LE: ChecksumAlgorithm
CHECKSUM_ALGORITHM_SUM16_WORDS_BE: ChecksumAlgorithm
CHECKSUM_ALGORITHM_SUM32_WORDS_LE: ChecksumAlgorithm
CHECKSUM_ALGORITHM_SUM32_WORDS_BE: ChecksumAlgorithm
CHECKSUM_ALGORITHM_SUM8_NEG: ChecksumAlgorithm
CHECKSUM_ALGORITHM_SUM32_NEG: ChecksumAlgorithm
CHECKSUM_ALGORITHM_XOR8: ChecksumAlgorithm
CHECKSUM_ALGORITHM_FLETCHER16: ChecksumAlgorithm
CHECKSUM_ALGORITHM_FLETCHER32: ChecksumAlgorithm
CHECKSUM_ALGORITHM_ADLER32: ChecksumAlgorithm
CHECKSUM_ALGORITHM_CRC16_CCITT_FALSE: ChecksumAlgorithm
CHECKSUM_ALGORITHM_CRC16_XMODEM: ChecksumAlgorithm
CHECKSUM_ALGORITHM_CRC16_KERMIT: ChecksumAlgorithm
CHECKSUM_ALGORITHM_CRC16_MODBUS: ChecksumAlgorithm
CHECKSUM_ALGORITHM_CRC16_ARC: ChecksumAlgorithm
CHECKSUM_ALGORITHM_CRC32: ChecksumAlgorithm
CHECKSUM_ALGORITHM_CRC32_BZIP2: ChecksumAlgorithm
CHECKSUM_ALGORITHM_CRC32_MPEG2: ChecksumAlgorithm
CHECKSUM_ALGORITHM_CRC32_POSIX: ChecksumAlgorithm
CHECKSUM_ALGORITHM_CRC32_JAMCRC: ChecksumAlgorithm
CHECKSUM_ALGORITHM_CRC32C: ChecksumAlgorithm
CHECKSUM_ALGORITHM_PE: ChecksumAlgorithm
EXPORT_FORMAT_UNSPECIFIED: ExportFormat
EXPORT_FORMAT_FILE: ExportFormat
EXPORT_FORMAT_IMAGE: ExportFormat

class AssembleRequest(_message.Message):
    __slots__ = ("program_id", "address", "text", "cursor", "complete", "max_candidates", "read", "context")
    class ContextEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    CURSOR_FIELD_NUMBER: _ClassVar[int]
    COMPLETE_FIELD_NUMBER: _ClassVar[int]
    MAX_CANDIDATES_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    address: _common_pb2.Address
    text: str
    cursor: int
    complete: bool
    max_candidates: int
    read: _common_pb2.ReadOptions
    context: _containers.ScalarMap[str, int]
    def __init__(self, program_id: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., text: _Optional[str] = ..., cursor: _Optional[int] = ..., complete: _Optional[bool] = ..., max_candidates: _Optional[int] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., context: _Optional[_Mapping[str, int]] = ...) -> None: ...

class AssemblyCandidate(_message.Message):
    __slots__ = ("bytes", "text", "hamming", "current")
    BYTES_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    HAMMING_FIELD_NUMBER: _ClassVar[int]
    CURRENT_FIELD_NUMBER: _ClassVar[int]
    bytes: bytes
    text: str
    hamming: int
    current: bool
    def __init__(self, bytes: _Optional[bytes] = ..., text: _Optional[str] = ..., hamming: _Optional[int] = ..., current: _Optional[bool] = ...) -> None: ...

class AssembleResponse(_message.Message):
    __slots__ = ("snapshot", "candidates", "error", "error_column", "expected", "completion_from", "completions", "current_text", "current_bytes", "context", "truncated", "micros")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    CANDIDATES_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    ERROR_COLUMN_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_FIELD_NUMBER: _ClassVar[int]
    COMPLETION_FROM_FIELD_NUMBER: _ClassVar[int]
    COMPLETIONS_FIELD_NUMBER: _ClassVar[int]
    CURRENT_TEXT_FIELD_NUMBER: _ClassVar[int]
    CURRENT_BYTES_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    MICROS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    candidates: _containers.RepeatedCompositeFieldContainer[AssemblyCandidate]
    error: str
    error_column: int
    expected: _containers.RepeatedScalarFieldContainer[str]
    completion_from: int
    completions: _containers.RepeatedScalarFieldContainer[str]
    current_text: str
    current_bytes: bytes
    context: str
    truncated: bool
    micros: int
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., candidates: _Optional[_Iterable[_Union[AssemblyCandidate, _Mapping]]] = ..., error: _Optional[str] = ..., error_column: _Optional[int] = ..., expected: _Optional[_Iterable[str]] = ..., completion_from: _Optional[int] = ..., completions: _Optional[_Iterable[str]] = ..., current_text: _Optional[str] = ..., current_bytes: _Optional[bytes] = ..., context: _Optional[str] = ..., truncated: _Optional[bool] = ..., micros: _Optional[int] = ...) -> None: ...

class PatchInstructionRequest(_message.Message):
    __slots__ = ("program_id", "address", "text", "bytes", "pad", "provenance", "expected_head_revision", "context")
    class ContextEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    PAD_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_HEAD_REVISION_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    address: _common_pb2.Address
    text: str
    bytes: bytes
    pad: bool
    provenance: _common_pb2.Provenance
    expected_head_revision: int
    context: _containers.ScalarMap[str, int]
    def __init__(self, program_id: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., text: _Optional[str] = ..., bytes: _Optional[bytes] = ..., pad: _Optional[bool] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., expected_head_revision: _Optional[int] = ..., context: _Optional[_Mapping[str, int]] = ...) -> None: ...

class PatchInstructionResponse(_message.Message):
    __slots__ = ("snapshot", "revision", "seqs", "bytes", "padding", "text")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    SEQS_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    PADDING_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    revision: int
    seqs: _containers.RepeatedScalarFieldContainer[int]
    bytes: bytes
    padding: bytes
    text: str
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., revision: _Optional[int] = ..., seqs: _Optional[_Iterable[int]] = ..., bytes: _Optional[bytes] = ..., padding: _Optional[bytes] = ..., text: _Optional[str] = ...) -> None: ...

class PatchBytesRequest(_message.Message):
    __slots__ = ("program_id", "address", "data", "provenance", "expected_head_revision")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_HEAD_REVISION_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    address: _common_pb2.Address
    data: bytes
    provenance: _common_pb2.Provenance
    expected_head_revision: int
    def __init__(self, program_id: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., data: _Optional[bytes] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., expected_head_revision: _Optional[int] = ...) -> None: ...

class PatchBytesResponse(_message.Message):
    __slots__ = ("snapshot", "revision", "seqs")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    SEQS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    revision: int
    seqs: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., revision: _Optional[int] = ..., seqs: _Optional[_Iterable[int]] = ...) -> None: ...

class PatchInfo(_message.Message):
    __slots__ = ("seq", "address", "bytes", "original", "text", "original_text", "typed_text", "provenance", "revision", "time", "function", "function_name", "shadowed_bytes")
    SEQ_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    ORIGINAL_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    ORIGINAL_TEXT_FIELD_NUMBER: _ClassVar[int]
    TYPED_TEXT_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    TIME_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    SHADOWED_BYTES_FIELD_NUMBER: _ClassVar[int]
    seq: int
    address: _common_pb2.Address
    bytes: bytes
    original: bytes
    text: str
    original_text: str
    typed_text: str
    provenance: _common_pb2.Provenance
    revision: int
    time: _timestamp_pb2.Timestamp
    function: _common_pb2.Address
    function_name: str
    shadowed_bytes: int
    def __init__(self, seq: _Optional[int] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., bytes: _Optional[bytes] = ..., original: _Optional[bytes] = ..., text: _Optional[str] = ..., original_text: _Optional[str] = ..., typed_text: _Optional[str] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., revision: _Optional[int] = ..., time: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., function_name: _Optional[str] = ..., shadowed_bytes: _Optional[int] = ...) -> None: ...

class ListPatchesRequest(_message.Message):
    __slots__ = ("program_id", "range", "read")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    range: _common_pb2.AddressRange
    read: _common_pb2.ReadOptions
    def __init__(self, program_id: _Optional[str] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ...) -> None: ...

class ListPatchesResponse(_message.Message):
    __slots__ = ("snapshot", "patches", "patched_bytes")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    PATCHES_FIELD_NUMBER: _ClassVar[int]
    PATCHED_BYTES_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    patches: _containers.RepeatedCompositeFieldContainer[PatchInfo]
    patched_bytes: int
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., patches: _Optional[_Iterable[_Union[PatchInfo, _Mapping]]] = ..., patched_bytes: _Optional[int] = ...) -> None: ...

class RevertPatchesRequest(_message.Message):
    __slots__ = ("program_id", "seqs", "range", "provenance", "expected_head_revision")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    SEQS_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_HEAD_REVISION_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    seqs: _containers.RepeatedScalarFieldContainer[int]
    range: _common_pb2.AddressRange
    provenance: _common_pb2.Provenance
    expected_head_revision: int
    def __init__(self, program_id: _Optional[str] = ..., seqs: _Optional[_Iterable[int]] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., expected_head_revision: _Optional[int] = ...) -> None: ...

class RevertPatchesResponse(_message.Message):
    __slots__ = ("snapshot", "revision", "seqs")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    SEQS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    revision: int
    seqs: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., revision: _Optional[int] = ..., seqs: _Optional[_Iterable[int]] = ...) -> None: ...

class ChecksumSpec(_message.Message):
    __slots__ = ("algorithm", "start", "end", "skip_padding", "field", "field_offset", "field_width", "field_big_endian", "name")
    ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    END_FIELD_NUMBER: _ClassVar[int]
    SKIP_PADDING_FIELD_NUMBER: _ClassVar[int]
    FIELD_FIELD_NUMBER: _ClassVar[int]
    FIELD_OFFSET_FIELD_NUMBER: _ClassVar[int]
    FIELD_WIDTH_FIELD_NUMBER: _ClassVar[int]
    FIELD_BIG_ENDIAN_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    algorithm: ChecksumAlgorithm
    start: int
    end: int
    skip_padding: bool
    field: bool
    field_offset: int
    field_width: int
    field_big_endian: bool
    name: bool
    def __init__(self, algorithm: _Optional[_Union[ChecksumAlgorithm, str]] = ..., start: _Optional[int] = ..., end: _Optional[int] = ..., skip_padding: _Optional[bool] = ..., field: _Optional[bool] = ..., field_offset: _Optional[int] = ..., field_width: _Optional[int] = ..., field_big_endian: _Optional[bool] = ..., name: _Optional[bool] = ...) -> None: ...

class ExportFixup(_message.Message):
    __slots__ = ("checksum", "pe_checksum")
    CHECKSUM_FIELD_NUMBER: _ClassVar[int]
    PE_CHECKSUM_FIELD_NUMBER: _ClassVar[int]
    checksum: ChecksumSpec
    pe_checksum: bool
    def __init__(self, checksum: _Optional[_Union[ChecksumSpec, _Mapping]] = ..., pe_checksum: _Optional[bool] = ...) -> None: ...

class ExportSettings(_message.Message):
    __slots__ = ("format", "fixups", "file_name_template")
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    FIXUPS_FIELD_NUMBER: _ClassVar[int]
    FILE_NAME_TEMPLATE_FIELD_NUMBER: _ClassVar[int]
    format: ExportFormat
    fixups: _containers.RepeatedCompositeFieldContainer[ExportFixup]
    file_name_template: str
    def __init__(self, format: _Optional[_Union[ExportFormat, str]] = ..., fixups: _Optional[_Iterable[_Union[ExportFixup, _Mapping]]] = ..., file_name_template: _Optional[str] = ...) -> None: ...

class ExportProgramRequest(_message.Message):
    __slots__ = ("program_id", "settings", "use_stored_settings", "host_path", "skip_verify", "read")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    USE_STORED_SETTINGS_FIELD_NUMBER: _ClassVar[int]
    HOST_PATH_FIELD_NUMBER: _ClassVar[int]
    SKIP_VERIFY_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    settings: ExportSettings
    use_stored_settings: bool
    host_path: str
    skip_verify: bool
    read: _common_pb2.ReadOptions
    def __init__(self, program_id: _Optional[str] = ..., settings: _Optional[_Union[ExportSettings, _Mapping]] = ..., use_stored_settings: _Optional[bool] = ..., host_path: _Optional[str] = ..., skip_verify: _Optional[bool] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ...) -> None: ...

class ExportChange(_message.Message):
    __slots__ = ("file_offset", "length", "address", "what")
    FILE_OFFSET_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    WHAT_FIELD_NUMBER: _ClassVar[int]
    file_offset: int
    length: int
    address: _common_pb2.Address
    what: str
    def __init__(self, file_offset: _Optional[int] = ..., length: _Optional[int] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., what: _Optional[str] = ...) -> None: ...

class ExportVerification(_message.Message):
    __slots__ = ("ok", "compared", "mismatches", "first_mismatch", "detail")
    OK_FIELD_NUMBER: _ClassVar[int]
    COMPARED_FIELD_NUMBER: _ClassVar[int]
    MISMATCHES_FIELD_NUMBER: _ClassVar[int]
    FIRST_MISMATCH_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    ok: bool
    compared: int
    mismatches: int
    first_mismatch: _common_pb2.Address
    detail: str
    def __init__(self, ok: _Optional[bool] = ..., compared: _Optional[int] = ..., mismatches: _Optional[int] = ..., first_mismatch: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., detail: _Optional[str] = ...) -> None: ...

class ExportProgramResponse(_message.Message):
    __slots__ = ("snapshot", "data", "file_name", "path", "size", "sha256", "changes", "fixups", "verification")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    FILE_NAME_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    CHANGES_FIELD_NUMBER: _ClassVar[int]
    FIXUPS_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    data: bytes
    file_name: str
    path: str
    size: int
    sha256: str
    changes: _containers.RepeatedCompositeFieldContainer[ExportChange]
    fixups: _containers.RepeatedScalarFieldContainer[str]
    verification: ExportVerification
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., data: _Optional[bytes] = ..., file_name: _Optional[str] = ..., path: _Optional[str] = ..., size: _Optional[int] = ..., sha256: _Optional[str] = ..., changes: _Optional[_Iterable[_Union[ExportChange, _Mapping]]] = ..., fixups: _Optional[_Iterable[str]] = ..., verification: _Optional[_Union[ExportVerification, _Mapping]] = ...) -> None: ...

class DetectChecksumRequest(_message.Message):
    __slots__ = ("program_id", "expected", "file_name", "patched", "read")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_FIELD_NUMBER: _ClassVar[int]
    FILE_NAME_FIELD_NUMBER: _ClassVar[int]
    PATCHED_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    expected: str
    file_name: str
    patched: bool
    read: _common_pb2.ReadOptions
    def __init__(self, program_id: _Optional[str] = ..., expected: _Optional[str] = ..., file_name: _Optional[str] = ..., patched: _Optional[bool] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ...) -> None: ...

class ChecksumHit(_message.Message):
    __slots__ = ("spec", "value", "evidence", "file_name_template")
    SPEC_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    FILE_NAME_TEMPLATE_FIELD_NUMBER: _ClassVar[int]
    spec: ChecksumSpec
    value: int
    evidence: str
    file_name_template: str
    def __init__(self, spec: _Optional[_Union[ChecksumSpec, _Mapping]] = ..., value: _Optional[int] = ..., evidence: _Optional[str] = ..., file_name_template: _Optional[str] = ...) -> None: ...

class DetectChecksumResponse(_message.Message):
    __slots__ = ("snapshot", "hits", "tried")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    HITS_FIELD_NUMBER: _ClassVar[int]
    TRIED_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    hits: _containers.RepeatedCompositeFieldContainer[ChecksumHit]
    tried: int
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., hits: _Optional[_Iterable[_Union[ChecksumHit, _Mapping]]] = ..., tried: _Optional[int] = ...) -> None: ...

class GetExportSettingsRequest(_message.Message):
    __slots__ = ("program_id", "read")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    read: _common_pb2.ReadOptions
    def __init__(self, program_id: _Optional[str] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ...) -> None: ...

class GetExportSettingsResponse(_message.Message):
    __slots__ = ("snapshot", "settings", "stored", "file_name")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    STORED_FIELD_NUMBER: _ClassVar[int]
    FILE_NAME_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    settings: ExportSettings
    stored: bool
    file_name: str
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., settings: _Optional[_Union[ExportSettings, _Mapping]] = ..., stored: _Optional[bool] = ..., file_name: _Optional[str] = ...) -> None: ...

class SetExportSettingsRequest(_message.Message):
    __slots__ = ("program_id", "settings", "provenance")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    settings: ExportSettings
    provenance: _common_pb2.Provenance
    def __init__(self, program_id: _Optional[str] = ..., settings: _Optional[_Union[ExportSettings, _Mapping]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class SetExportSettingsResponse(_message.Message):
    __slots__ = ("snapshot", "revision")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    revision: int
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., revision: _Optional[int] = ...) -> None: ...

class OpenOriginalRequest(_message.Message):
    __slots__ = ("program_id", "provenance")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    provenance: _common_pb2.Provenance
    def __init__(self, program_id: _Optional[str] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class OpenOriginalResponse(_message.Message):
    __slots__ = ("snapshot", "program_id", "created")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    program_id: str
    created: bool
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., program_id: _Optional[str] = ..., created: _Optional[bool] = ...) -> None: ...
