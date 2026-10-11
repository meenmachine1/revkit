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

class BSimTemplate(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    BSIM_TEMPLATE_UNSPECIFIED: _ClassVar[BSimTemplate]
    BSIM_TEMPLATE_64: _ClassVar[BSimTemplate]
    BSIM_TEMPLATE_32: _ClassVar[BSimTemplate]
    BSIM_TEMPLATE_NOSIZE: _ClassVar[BSimTemplate]
BSIM_TEMPLATE_UNSPECIFIED: BSimTemplate
BSIM_TEMPLATE_64: BSimTemplate
BSIM_TEMPLATE_32: BSimTemplate
BSIM_TEMPLATE_NOSIZE: BSimTemplate

class BSimDatabase(_message.Message):
    __slots__ = ("id", "name", "description", "template", "settings", "lsh_k", "lsh_l", "executables", "functions", "created", "error")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TEMPLATE_FIELD_NUMBER: _ClassVar[int]
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    LSH_K_FIELD_NUMBER: _ClassVar[int]
    LSH_L_FIELD_NUMBER: _ClassVar[int]
    EXECUTABLES_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    description: str
    template: BSimTemplate
    settings: int
    lsh_k: int
    lsh_l: int
    executables: int
    functions: int
    created: _timestamp_pb2.Timestamp
    error: str
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., description: _Optional[str] = ..., template: _Optional[_Union[BSimTemplate, str]] = ..., settings: _Optional[int] = ..., lsh_k: _Optional[int] = ..., lsh_l: _Optional[int] = ..., executables: _Optional[int] = ..., functions: _Optional[int] = ..., created: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., error: _Optional[str] = ...) -> None: ...

class CreateBSimDatabaseRequest(_message.Message):
    __slots__ = ("project_id", "path", "name", "description", "template", "lsh_k", "lsh_l", "provenance")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TEMPLATE_FIELD_NUMBER: _ClassVar[int]
    LSH_K_FIELD_NUMBER: _ClassVar[int]
    LSH_L_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    path: str
    name: str
    description: str
    template: BSimTemplate
    lsh_k: int
    lsh_l: int
    provenance: _common_pb2.Provenance
    def __init__(self, project_id: _Optional[str] = ..., path: _Optional[str] = ..., name: _Optional[str] = ..., description: _Optional[str] = ..., template: _Optional[_Union[BSimTemplate, str]] = ..., lsh_k: _Optional[int] = ..., lsh_l: _Optional[int] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class CreateBSimDatabaseResponse(_message.Message):
    __slots__ = ("database",)
    DATABASE_FIELD_NUMBER: _ClassVar[int]
    database: BSimDatabase
    def __init__(self, database: _Optional[_Union[BSimDatabase, _Mapping]] = ...) -> None: ...

class AttachBSimDatabaseRequest(_message.Message):
    __slots__ = ("project_id", "path", "provenance")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    path: str
    provenance: _common_pb2.Provenance
    def __init__(self, project_id: _Optional[str] = ..., path: _Optional[str] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class AttachBSimDatabaseResponse(_message.Message):
    __slots__ = ("database",)
    DATABASE_FIELD_NUMBER: _ClassVar[int]
    database: BSimDatabase
    def __init__(self, database: _Optional[_Union[BSimDatabase, _Mapping]] = ...) -> None: ...

class DetachBSimDatabaseRequest(_message.Message):
    __slots__ = ("project_id", "database", "provenance")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    DATABASE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    database: str
    provenance: _common_pb2.Provenance
    def __init__(self, project_id: _Optional[str] = ..., database: _Optional[str] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ...) -> None: ...

class DetachBSimDatabaseResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListBSimDatabasesRequest(_message.Message):
    __slots__ = ("project_id",)
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    def __init__(self, project_id: _Optional[str] = ...) -> None: ...

class ListBSimDatabasesResponse(_message.Message):
    __slots__ = ("databases",)
    DATABASES_FIELD_NUMBER: _ClassVar[int]
    databases: _containers.RepeatedCompositeFieldContainer[BSimDatabase]
    def __init__(self, databases: _Optional[_Iterable[_Union[BSimDatabase, _Mapping]]] = ...) -> None: ...

class IngestBSimRequest(_message.Message):
    __slots__ = ("project_id", "database", "program_ids", "categories", "threads", "source")
    class CategoriesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    DATABASE_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_IDS_FIELD_NUMBER: _ClassVar[int]
    CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    THREADS_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    database: str
    program_ids: _containers.RepeatedScalarFieldContainer[str]
    categories: _containers.ScalarMap[str, str]
    threads: int
    source: str
    def __init__(self, project_id: _Optional[str] = ..., database: _Optional[str] = ..., program_ids: _Optional[_Iterable[str]] = ..., categories: _Optional[_Mapping[str, str]] = ..., threads: _Optional[int] = ..., source: _Optional[str] = ...) -> None: ...

class BSimIngested(_message.Message):
    __slots__ = ("program_id", "executable", "replaced", "functions", "excluded", "seconds", "warning")
    class ExcludedEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    EXECUTABLE_FIELD_NUMBER: _ClassVar[int]
    REPLACED_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    EXCLUDED_FIELD_NUMBER: _ClassVar[int]
    SECONDS_FIELD_NUMBER: _ClassVar[int]
    WARNING_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    executable: BSimExecutable
    replaced: bool
    functions: int
    excluded: _containers.ScalarMap[str, int]
    seconds: float
    warning: str
    def __init__(self, program_id: _Optional[str] = ..., executable: _Optional[_Union[BSimExecutable, _Mapping]] = ..., replaced: _Optional[bool] = ..., functions: _Optional[int] = ..., excluded: _Optional[_Mapping[str, int]] = ..., seconds: _Optional[float] = ..., warning: _Optional[str] = ...) -> None: ...

class IngestBSimResponse(_message.Message):
    __slots__ = ("programs",)
    PROGRAMS_FIELD_NUMBER: _ClassVar[int]
    programs: _containers.RepeatedCompositeFieldContainer[BSimIngested]
    def __init__(self, programs: _Optional[_Iterable[_Union[BSimIngested, _Mapping]]] = ...) -> None: ...

class BSimExecutable(_message.Message):
    __slots__ = ("id", "name", "path", "language", "compiler", "md5", "ingested", "source", "categories", "function_count")
    class CategoriesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    COMPILER_FIELD_NUMBER: _ClassVar[int]
    MD5_FIELD_NUMBER: _ClassVar[int]
    INGESTED_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_COUNT_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    path: str
    language: str
    compiler: str
    md5: str
    ingested: _timestamp_pb2.Timestamp
    source: str
    categories: _containers.ScalarMap[str, str]
    function_count: int
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., path: _Optional[str] = ..., language: _Optional[str] = ..., compiler: _Optional[str] = ..., md5: _Optional[str] = ..., ingested: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., source: _Optional[str] = ..., categories: _Optional[_Mapping[str, str]] = ..., function_count: _Optional[int] = ...) -> None: ...

class ListBSimExecutablesRequest(_message.Message):
    __slots__ = ("project_id", "database", "filter", "language")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    DATABASE_FIELD_NUMBER: _ClassVar[int]
    FILTER_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    database: str
    filter: str
    language: str
    def __init__(self, project_id: _Optional[str] = ..., database: _Optional[str] = ..., filter: _Optional[str] = ..., language: _Optional[str] = ...) -> None: ...

class ListBSimExecutablesResponse(_message.Message):
    __slots__ = ("executables",)
    EXECUTABLES_FIELD_NUMBER: _ClassVar[int]
    executables: _containers.RepeatedCompositeFieldContainer[BSimExecutable]
    def __init__(self, executables: _Optional[_Iterable[_Union[BSimExecutable, _Mapping]]] = ...) -> None: ...

class BSimFunction(_message.Message):
    __slots__ = ("name", "entry", "prototype", "size", "default_name", "feature_count", "executable_id")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    PROTOTYPE_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_NAME_FIELD_NUMBER: _ClassVar[int]
    FEATURE_COUNT_FIELD_NUMBER: _ClassVar[int]
    EXECUTABLE_ID_FIELD_NUMBER: _ClassVar[int]
    name: str
    entry: _common_pb2.Address
    prototype: str
    size: int
    default_name: bool
    feature_count: int
    executable_id: str
    def __init__(self, name: _Optional[str] = ..., entry: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., prototype: _Optional[str] = ..., size: _Optional[int] = ..., default_name: _Optional[bool] = ..., feature_count: _Optional[int] = ..., executable_id: _Optional[str] = ...) -> None: ...

class ListBSimFunctionsRequest(_message.Message):
    __slots__ = ("project_id", "database", "executable", "name_contains", "offset", "limit")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    DATABASE_FIELD_NUMBER: _ClassVar[int]
    EXECUTABLE_FIELD_NUMBER: _ClassVar[int]
    NAME_CONTAINS_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    database: str
    executable: str
    name_contains: str
    offset: int
    limit: int
    def __init__(self, project_id: _Optional[str] = ..., database: _Optional[str] = ..., executable: _Optional[str] = ..., name_contains: _Optional[str] = ..., offset: _Optional[int] = ..., limit: _Optional[int] = ...) -> None: ...

class ListBSimFunctionsResponse(_message.Message):
    __slots__ = ("functions", "total")
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    functions: _containers.RepeatedCompositeFieldContainer[BSimFunction]
    total: int
    def __init__(self, functions: _Optional[_Iterable[_Union[BSimFunction, _Mapping]]] = ..., total: _Optional[int] = ...) -> None: ...

class UpdateBSimExecutableRequest(_message.Message):
    __slots__ = ("project_id", "database", "executable", "name", "categories", "set_categories")
    class CategoriesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    DATABASE_FIELD_NUMBER: _ClassVar[int]
    EXECUTABLE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    SET_CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    database: str
    executable: str
    name: str
    categories: _containers.ScalarMap[str, str]
    set_categories: bool
    def __init__(self, project_id: _Optional[str] = ..., database: _Optional[str] = ..., executable: _Optional[str] = ..., name: _Optional[str] = ..., categories: _Optional[_Mapping[str, str]] = ..., set_categories: _Optional[bool] = ...) -> None: ...

class UpdateBSimExecutableResponse(_message.Message):
    __slots__ = ("executable",)
    EXECUTABLE_FIELD_NUMBER: _ClassVar[int]
    executable: BSimExecutable
    def __init__(self, executable: _Optional[_Union[BSimExecutable, _Mapping]] = ...) -> None: ...

class DeleteBSimExecutablesRequest(_message.Message):
    __slots__ = ("project_id", "database", "executables")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    DATABASE_FIELD_NUMBER: _ClassVar[int]
    EXECUTABLES_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    database: str
    executables: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, project_id: _Optional[str] = ..., database: _Optional[str] = ..., executables: _Optional[_Iterable[str]] = ...) -> None: ...

class DeleteBSimExecutablesResponse(_message.Message):
    __slots__ = ("deleted", "missing")
    DELETED_FIELD_NUMBER: _ClassVar[int]
    MISSING_FIELD_NUMBER: _ClassVar[int]
    deleted: int
    missing: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, deleted: _Optional[int] = ..., missing: _Optional[_Iterable[str]] = ...) -> None: ...

class SearchBSimRequest(_message.Message):
    __slots__ = ("project_id", "database", "program_id", "functions", "all_functions", "min_similarity", "min_confidence", "max_matches", "executables", "exclude_executables", "include_self", "languages", "name_contains", "categories", "exclude_default_names", "overview", "exhaustive", "threads", "index_only")
    class CategoriesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    DATABASE_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    ALL_FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    MIN_SIMILARITY_FIELD_NUMBER: _ClassVar[int]
    MIN_CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    MAX_MATCHES_FIELD_NUMBER: _ClassVar[int]
    EXECUTABLES_FIELD_NUMBER: _ClassVar[int]
    EXCLUDE_EXECUTABLES_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_SELF_FIELD_NUMBER: _ClassVar[int]
    LANGUAGES_FIELD_NUMBER: _ClassVar[int]
    NAME_CONTAINS_FIELD_NUMBER: _ClassVar[int]
    CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    EXCLUDE_DEFAULT_NAMES_FIELD_NUMBER: _ClassVar[int]
    OVERVIEW_FIELD_NUMBER: _ClassVar[int]
    EXHAUSTIVE_FIELD_NUMBER: _ClassVar[int]
    THREADS_FIELD_NUMBER: _ClassVar[int]
    INDEX_ONLY_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    database: str
    program_id: str
    functions: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    all_functions: bool
    min_similarity: float
    min_confidence: float
    max_matches: int
    executables: _containers.RepeatedScalarFieldContainer[str]
    exclude_executables: _containers.RepeatedScalarFieldContainer[str]
    include_self: bool
    languages: _containers.RepeatedScalarFieldContainer[str]
    name_contains: str
    categories: _containers.ScalarMap[str, str]
    exclude_default_names: bool
    overview: bool
    exhaustive: bool
    threads: int
    index_only: bool
    def __init__(self, project_id: _Optional[str] = ..., database: _Optional[str] = ..., program_id: _Optional[str] = ..., functions: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., all_functions: _Optional[bool] = ..., min_similarity: _Optional[float] = ..., min_confidence: _Optional[float] = ..., max_matches: _Optional[int] = ..., executables: _Optional[_Iterable[str]] = ..., exclude_executables: _Optional[_Iterable[str]] = ..., include_self: _Optional[bool] = ..., languages: _Optional[_Iterable[str]] = ..., name_contains: _Optional[str] = ..., categories: _Optional[_Mapping[str, str]] = ..., exclude_default_names: _Optional[bool] = ..., overview: _Optional[bool] = ..., exhaustive: _Optional[bool] = ..., threads: _Optional[int] = ..., index_only: _Optional[bool] = ...) -> None: ...

class BSimMatch(_message.Message):
    __slots__ = ("executable", "function", "similarity", "confidence", "program_id")
    EXECUTABLE_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    SIMILARITY_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    executable: BSimExecutable
    function: BSimFunction
    similarity: float
    confidence: float
    program_id: str
    def __init__(self, executable: _Optional[_Union[BSimExecutable, _Mapping]] = ..., function: _Optional[_Union[BSimFunction, _Mapping]] = ..., similarity: _Optional[float] = ..., confidence: _Optional[float] = ..., program_id: _Optional[str] = ...) -> None: ...

class BSimQueryResult(_message.Message):
    __slots__ = ("function", "name", "feature_count", "self_significance", "hit_count", "matches", "skipped")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    FEATURE_COUNT_FIELD_NUMBER: _ClassVar[int]
    SELF_SIGNIFICANCE_FIELD_NUMBER: _ClassVar[int]
    HIT_COUNT_FIELD_NUMBER: _ClassVar[int]
    MATCHES_FIELD_NUMBER: _ClassVar[int]
    SKIPPED_FIELD_NUMBER: _ClassVar[int]
    function: _common_pb2.Address
    name: str
    feature_count: int
    self_significance: float
    hit_count: int
    matches: _containers.RepeatedCompositeFieldContainer[BSimMatch]
    skipped: str
    def __init__(self, function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., name: _Optional[str] = ..., feature_count: _Optional[int] = ..., self_significance: _Optional[float] = ..., hit_count: _Optional[int] = ..., matches: _Optional[_Iterable[_Union[BSimMatch, _Mapping]]] = ..., skipped: _Optional[str] = ...) -> None: ...

class SearchBSimResponse(_message.Message):
    __slots__ = ("results", "scored", "total", "seconds")
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    SCORED_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    SECONDS_FIELD_NUMBER: _ClassVar[int]
    results: _containers.RepeatedCompositeFieldContainer[BSimQueryResult]
    scored: int
    total: int
    seconds: float
    def __init__(self, results: _Optional[_Iterable[_Union[BSimQueryResult, _Mapping]]] = ..., scored: _Optional[int] = ..., total: _Optional[int] = ..., seconds: _Optional[float] = ...) -> None: ...
