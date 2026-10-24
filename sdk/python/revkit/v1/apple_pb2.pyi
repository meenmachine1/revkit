import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from revkit.v1 import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class PlistValue(_message.Message):
    __slots__ = ("string_value", "integer_value", "unsigned_value", "real_value", "bool_value", "date_value", "data_value", "array_value", "dict_value", "uid_value", "null_value", "data_size", "omitted")
    STRING_VALUE_FIELD_NUMBER: _ClassVar[int]
    INTEGER_VALUE_FIELD_NUMBER: _ClassVar[int]
    UNSIGNED_VALUE_FIELD_NUMBER: _ClassVar[int]
    REAL_VALUE_FIELD_NUMBER: _ClassVar[int]
    BOOL_VALUE_FIELD_NUMBER: _ClassVar[int]
    DATE_VALUE_FIELD_NUMBER: _ClassVar[int]
    DATA_VALUE_FIELD_NUMBER: _ClassVar[int]
    ARRAY_VALUE_FIELD_NUMBER: _ClassVar[int]
    DICT_VALUE_FIELD_NUMBER: _ClassVar[int]
    UID_VALUE_FIELD_NUMBER: _ClassVar[int]
    NULL_VALUE_FIELD_NUMBER: _ClassVar[int]
    DATA_SIZE_FIELD_NUMBER: _ClassVar[int]
    OMITTED_FIELD_NUMBER: _ClassVar[int]
    string_value: str
    integer_value: int
    unsigned_value: int
    real_value: float
    bool_value: bool
    date_value: _timestamp_pb2.Timestamp
    data_value: bytes
    array_value: PlistArray
    dict_value: PlistDict
    uid_value: int
    null_value: bool
    data_size: int
    omitted: int
    def __init__(self, string_value: _Optional[str] = ..., integer_value: _Optional[int] = ..., unsigned_value: _Optional[int] = ..., real_value: _Optional[float] = ..., bool_value: _Optional[bool] = ..., date_value: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., data_value: _Optional[bytes] = ..., array_value: _Optional[_Union[PlistArray, _Mapping]] = ..., dict_value: _Optional[_Union[PlistDict, _Mapping]] = ..., uid_value: _Optional[int] = ..., null_value: _Optional[bool] = ..., data_size: _Optional[int] = ..., omitted: _Optional[int] = ...) -> None: ...

class PlistArray(_message.Message):
    __slots__ = ("items",)
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    items: _containers.RepeatedCompositeFieldContainer[PlistValue]
    def __init__(self, items: _Optional[_Iterable[_Union[PlistValue, _Mapping]]] = ...) -> None: ...

class PlistDict(_message.Message):
    __slots__ = ("entries",)
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    entries: _containers.RepeatedCompositeFieldContainer[PlistEntry]
    def __init__(self, entries: _Optional[_Iterable[_Union[PlistEntry, _Mapping]]] = ...) -> None: ...

class PlistEntry(_message.Message):
    __slots__ = ("key", "value")
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    value: PlistValue
    def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[PlistValue, _Mapping]] = ...) -> None: ...

class AppleDocumentType(_message.Message):
    __slots__ = ("name", "role", "handler_rank", "content_types", "extensions")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    HANDLER_RANK_FIELD_NUMBER: _ClassVar[int]
    CONTENT_TYPES_FIELD_NUMBER: _ClassVar[int]
    EXTENSIONS_FIELD_NUMBER: _ClassVar[int]
    name: str
    role: str
    handler_rank: str
    content_types: _containers.RepeatedScalarFieldContainer[str]
    extensions: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, name: _Optional[str] = ..., role: _Optional[str] = ..., handler_rank: _Optional[str] = ..., content_types: _Optional[_Iterable[str]] = ..., extensions: _Optional[_Iterable[str]] = ...) -> None: ...

class AppleTypeDeclaration(_message.Message):
    __slots__ = ("identifier", "description", "conforms_to", "extensions", "mime_types")
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    CONFORMS_TO_FIELD_NUMBER: _ClassVar[int]
    EXTENSIONS_FIELD_NUMBER: _ClassVar[int]
    MIME_TYPES_FIELD_NUMBER: _ClassVar[int]
    identifier: str
    description: str
    conforms_to: _containers.RepeatedScalarFieldContainer[str]
    extensions: _containers.RepeatedScalarFieldContainer[str]
    mime_types: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, identifier: _Optional[str] = ..., description: _Optional[str] = ..., conforms_to: _Optional[_Iterable[str]] = ..., extensions: _Optional[_Iterable[str]] = ..., mime_types: _Optional[_Iterable[str]] = ...) -> None: ...

class AppleUsageDescription(_message.Message):
    __slots__ = ("key", "text")
    KEY_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    key: str
    text: str
    def __init__(self, key: _Optional[str] = ..., text: _Optional[str] = ...) -> None: ...

class AppleBundleInfo(_message.Message):
    __slots__ = ("identifier", "name", "display_name", "executable", "version", "short_version", "package_type", "minimum_os", "supported_platforms", "device_families", "url_schemes", "queried_url_schemes", "document_types", "background_modes", "usage_descriptions", "exported_types", "imported_types", "required_capabilities", "extension_point", "principal_class", "main_storyboard", "main_nib", "launch_storyboard", "allows_arbitrary_loads", "ats_exception_domains", "sdk", "xcode", "build_machine_os")
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_NAME_FIELD_NUMBER: _ClassVar[int]
    EXECUTABLE_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    SHORT_VERSION_FIELD_NUMBER: _ClassVar[int]
    PACKAGE_TYPE_FIELD_NUMBER: _ClassVar[int]
    MINIMUM_OS_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_PLATFORMS_FIELD_NUMBER: _ClassVar[int]
    DEVICE_FAMILIES_FIELD_NUMBER: _ClassVar[int]
    URL_SCHEMES_FIELD_NUMBER: _ClassVar[int]
    QUERIED_URL_SCHEMES_FIELD_NUMBER: _ClassVar[int]
    DOCUMENT_TYPES_FIELD_NUMBER: _ClassVar[int]
    BACKGROUND_MODES_FIELD_NUMBER: _ClassVar[int]
    USAGE_DESCRIPTIONS_FIELD_NUMBER: _ClassVar[int]
    EXPORTED_TYPES_FIELD_NUMBER: _ClassVar[int]
    IMPORTED_TYPES_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    EXTENSION_POINT_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_CLASS_FIELD_NUMBER: _ClassVar[int]
    MAIN_STORYBOARD_FIELD_NUMBER: _ClassVar[int]
    MAIN_NIB_FIELD_NUMBER: _ClassVar[int]
    LAUNCH_STORYBOARD_FIELD_NUMBER: _ClassVar[int]
    ALLOWS_ARBITRARY_LOADS_FIELD_NUMBER: _ClassVar[int]
    ATS_EXCEPTION_DOMAINS_FIELD_NUMBER: _ClassVar[int]
    SDK_FIELD_NUMBER: _ClassVar[int]
    XCODE_FIELD_NUMBER: _ClassVar[int]
    BUILD_MACHINE_OS_FIELD_NUMBER: _ClassVar[int]
    identifier: str
    name: str
    display_name: str
    executable: str
    version: str
    short_version: str
    package_type: str
    minimum_os: str
    supported_platforms: _containers.RepeatedScalarFieldContainer[str]
    device_families: _containers.RepeatedScalarFieldContainer[str]
    url_schemes: _containers.RepeatedScalarFieldContainer[str]
    queried_url_schemes: _containers.RepeatedScalarFieldContainer[str]
    document_types: _containers.RepeatedCompositeFieldContainer[AppleDocumentType]
    background_modes: _containers.RepeatedScalarFieldContainer[str]
    usage_descriptions: _containers.RepeatedCompositeFieldContainer[AppleUsageDescription]
    exported_types: _containers.RepeatedCompositeFieldContainer[AppleTypeDeclaration]
    imported_types: _containers.RepeatedCompositeFieldContainer[AppleTypeDeclaration]
    required_capabilities: _containers.RepeatedScalarFieldContainer[str]
    extension_point: str
    principal_class: str
    main_storyboard: str
    main_nib: str
    launch_storyboard: str
    allows_arbitrary_loads: bool
    ats_exception_domains: _containers.RepeatedScalarFieldContainer[str]
    sdk: str
    xcode: str
    build_machine_os: str
    def __init__(self, identifier: _Optional[str] = ..., name: _Optional[str] = ..., display_name: _Optional[str] = ..., executable: _Optional[str] = ..., version: _Optional[str] = ..., short_version: _Optional[str] = ..., package_type: _Optional[str] = ..., minimum_os: _Optional[str] = ..., supported_platforms: _Optional[_Iterable[str]] = ..., device_families: _Optional[_Iterable[str]] = ..., url_schemes: _Optional[_Iterable[str]] = ..., queried_url_schemes: _Optional[_Iterable[str]] = ..., document_types: _Optional[_Iterable[_Union[AppleDocumentType, _Mapping]]] = ..., background_modes: _Optional[_Iterable[str]] = ..., usage_descriptions: _Optional[_Iterable[_Union[AppleUsageDescription, _Mapping]]] = ..., exported_types: _Optional[_Iterable[_Union[AppleTypeDeclaration, _Mapping]]] = ..., imported_types: _Optional[_Iterable[_Union[AppleTypeDeclaration, _Mapping]]] = ..., required_capabilities: _Optional[_Iterable[str]] = ..., extension_point: _Optional[str] = ..., principal_class: _Optional[str] = ..., main_storyboard: _Optional[str] = ..., main_nib: _Optional[str] = ..., launch_storyboard: _Optional[str] = ..., allows_arbitrary_loads: _Optional[bool] = ..., ats_exception_domains: _Optional[_Iterable[str]] = ..., sdk: _Optional[str] = ..., xcode: _Optional[str] = ..., build_machine_os: _Optional[str] = ...) -> None: ...

class AppleBundleRef(_message.Message):
    __slots__ = ("path", "kind", "role", "identifier", "executable_path", "extension_point", "version")
    PATH_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    EXECUTABLE_PATH_FIELD_NUMBER: _ClassVar[int]
    EXTENSION_POINT_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    path: str
    kind: str
    role: str
    identifier: str
    executable_path: str
    extension_point: str
    version: str
    def __init__(self, path: _Optional[str] = ..., kind: _Optional[str] = ..., role: _Optional[str] = ..., identifier: _Optional[str] = ..., executable_path: _Optional[str] = ..., extension_point: _Optional[str] = ..., version: _Optional[str] = ...) -> None: ...

class CodeDirectory(_message.Message):
    __slots__ = ("version", "flags", "flag_names", "identifier", "team_id", "hash_type", "hash_size", "page_size", "code_slots", "special_slots", "code_limit", "platform", "special_hashes", "exec_seg_base", "exec_seg_limit", "exec_seg_flags", "exec_seg_flag_names", "runtime_version", "cdhash", "alternate", "slot")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    FLAG_NAMES_FIELD_NUMBER: _ClassVar[int]
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    TEAM_ID_FIELD_NUMBER: _ClassVar[int]
    HASH_TYPE_FIELD_NUMBER: _ClassVar[int]
    HASH_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    CODE_SLOTS_FIELD_NUMBER: _ClassVar[int]
    SPECIAL_SLOTS_FIELD_NUMBER: _ClassVar[int]
    CODE_LIMIT_FIELD_NUMBER: _ClassVar[int]
    PLATFORM_FIELD_NUMBER: _ClassVar[int]
    SPECIAL_HASHES_FIELD_NUMBER: _ClassVar[int]
    EXEC_SEG_BASE_FIELD_NUMBER: _ClassVar[int]
    EXEC_SEG_LIMIT_FIELD_NUMBER: _ClassVar[int]
    EXEC_SEG_FLAGS_FIELD_NUMBER: _ClassVar[int]
    EXEC_SEG_FLAG_NAMES_FIELD_NUMBER: _ClassVar[int]
    RUNTIME_VERSION_FIELD_NUMBER: _ClassVar[int]
    CDHASH_FIELD_NUMBER: _ClassVar[int]
    ALTERNATE_FIELD_NUMBER: _ClassVar[int]
    SLOT_FIELD_NUMBER: _ClassVar[int]
    version: int
    flags: int
    flag_names: _containers.RepeatedScalarFieldContainer[str]
    identifier: str
    team_id: str
    hash_type: str
    hash_size: int
    page_size: int
    code_slots: int
    special_slots: int
    code_limit: int
    platform: int
    special_hashes: _containers.RepeatedScalarFieldContainer[str]
    exec_seg_base: int
    exec_seg_limit: int
    exec_seg_flags: int
    exec_seg_flag_names: _containers.RepeatedScalarFieldContainer[str]
    runtime_version: int
    cdhash: str
    alternate: bool
    slot: int
    def __init__(self, version: _Optional[int] = ..., flags: _Optional[int] = ..., flag_names: _Optional[_Iterable[str]] = ..., identifier: _Optional[str] = ..., team_id: _Optional[str] = ..., hash_type: _Optional[str] = ..., hash_size: _Optional[int] = ..., page_size: _Optional[int] = ..., code_slots: _Optional[int] = ..., special_slots: _Optional[int] = ..., code_limit: _Optional[int] = ..., platform: _Optional[int] = ..., special_hashes: _Optional[_Iterable[str]] = ..., exec_seg_base: _Optional[int] = ..., exec_seg_limit: _Optional[int] = ..., exec_seg_flags: _Optional[int] = ..., exec_seg_flag_names: _Optional[_Iterable[str]] = ..., runtime_version: _Optional[int] = ..., cdhash: _Optional[str] = ..., alternate: _Optional[bool] = ..., slot: _Optional[int] = ...) -> None: ...

class CodeRequirement(_message.Message):
    __slots__ = ("type", "type_name", "text")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    TYPE_NAME_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    type: int
    type_name: str
    text: str
    def __init__(self, type: _Optional[int] = ..., type_name: _Optional[str] = ..., text: _Optional[str] = ...) -> None: ...

class SigningCertificate(_message.Message):
    __slots__ = ("subject", "common_name", "organizational_unit", "issuer", "not_before", "not_after")
    SUBJECT_FIELD_NUMBER: _ClassVar[int]
    COMMON_NAME_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATIONAL_UNIT_FIELD_NUMBER: _ClassVar[int]
    ISSUER_FIELD_NUMBER: _ClassVar[int]
    NOT_BEFORE_FIELD_NUMBER: _ClassVar[int]
    NOT_AFTER_FIELD_NUMBER: _ClassVar[int]
    subject: str
    common_name: str
    organizational_unit: str
    issuer: str
    not_before: str
    not_after: str
    def __init__(self, subject: _Optional[str] = ..., common_name: _Optional[str] = ..., organizational_unit: _Optional[str] = ..., issuer: _Optional[str] = ..., not_before: _Optional[str] = ..., not_after: _Optional[str] = ...) -> None: ...

class CodeSignatureBlob(_message.Message):
    __slots__ = ("slot", "magic", "offset", "length")
    SLOT_FIELD_NUMBER: _ClassVar[int]
    MAGIC_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    slot: int
    magic: int
    offset: int
    length: int
    def __init__(self, slot: _Optional[int] = ..., magic: _Optional[int] = ..., offset: _Optional[int] = ..., length: _Optional[int] = ...) -> None: ...

class CodeSignature(_message.Message):
    __slots__ = ("code_directories", "entitlements", "entitlements_xml", "has_der_entitlements", "requirements", "has_cms", "cms_size", "certificates", "adhoc", "blobs", "warnings", "offset", "size")
    CODE_DIRECTORIES_FIELD_NUMBER: _ClassVar[int]
    ENTITLEMENTS_FIELD_NUMBER: _ClassVar[int]
    ENTITLEMENTS_XML_FIELD_NUMBER: _ClassVar[int]
    HAS_DER_ENTITLEMENTS_FIELD_NUMBER: _ClassVar[int]
    REQUIREMENTS_FIELD_NUMBER: _ClassVar[int]
    HAS_CMS_FIELD_NUMBER: _ClassVar[int]
    CMS_SIZE_FIELD_NUMBER: _ClassVar[int]
    CERTIFICATES_FIELD_NUMBER: _ClassVar[int]
    ADHOC_FIELD_NUMBER: _ClassVar[int]
    BLOBS_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    code_directories: _containers.RepeatedCompositeFieldContainer[CodeDirectory]
    entitlements: PlistValue
    entitlements_xml: str
    has_der_entitlements: bool
    requirements: _containers.RepeatedCompositeFieldContainer[CodeRequirement]
    has_cms: bool
    cms_size: int
    certificates: _containers.RepeatedCompositeFieldContainer[SigningCertificate]
    adhoc: bool
    blobs: _containers.RepeatedCompositeFieldContainer[CodeSignatureBlob]
    warnings: _containers.RepeatedScalarFieldContainer[str]
    offset: int
    size: int
    def __init__(self, code_directories: _Optional[_Iterable[_Union[CodeDirectory, _Mapping]]] = ..., entitlements: _Optional[_Union[PlistValue, _Mapping]] = ..., entitlements_xml: _Optional[str] = ..., has_der_entitlements: _Optional[bool] = ..., requirements: _Optional[_Iterable[_Union[CodeRequirement, _Mapping]]] = ..., has_cms: _Optional[bool] = ..., cms_size: _Optional[int] = ..., certificates: _Optional[_Iterable[_Union[SigningCertificate, _Mapping]]] = ..., adhoc: _Optional[bool] = ..., blobs: _Optional[_Iterable[_Union[CodeSignatureBlob, _Mapping]]] = ..., warnings: _Optional[_Iterable[str]] = ..., offset: _Optional[int] = ..., size: _Optional[int] = ...) -> None: ...

class ProvisioningProfile(_message.Message):
    __slots__ = ("name", "uuid", "app_id_name", "application_identifier", "team_identifiers", "team_name", "platforms", "creation_date", "expiration_date", "provisioned_devices", "provisions_all_devices", "get_task_allow", "kind", "entitlements", "developer_certificates", "signer_certificates", "plist", "warnings")
    NAME_FIELD_NUMBER: _ClassVar[int]
    UUID_FIELD_NUMBER: _ClassVar[int]
    APP_ID_NAME_FIELD_NUMBER: _ClassVar[int]
    APPLICATION_IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    TEAM_IDENTIFIERS_FIELD_NUMBER: _ClassVar[int]
    TEAM_NAME_FIELD_NUMBER: _ClassVar[int]
    PLATFORMS_FIELD_NUMBER: _ClassVar[int]
    CREATION_DATE_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_DATE_FIELD_NUMBER: _ClassVar[int]
    PROVISIONED_DEVICES_FIELD_NUMBER: _ClassVar[int]
    PROVISIONS_ALL_DEVICES_FIELD_NUMBER: _ClassVar[int]
    GET_TASK_ALLOW_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ENTITLEMENTS_FIELD_NUMBER: _ClassVar[int]
    DEVELOPER_CERTIFICATES_FIELD_NUMBER: _ClassVar[int]
    SIGNER_CERTIFICATES_FIELD_NUMBER: _ClassVar[int]
    PLIST_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    name: str
    uuid: str
    app_id_name: str
    application_identifier: str
    team_identifiers: _containers.RepeatedScalarFieldContainer[str]
    team_name: str
    platforms: _containers.RepeatedScalarFieldContainer[str]
    creation_date: _timestamp_pb2.Timestamp
    expiration_date: _timestamp_pb2.Timestamp
    provisioned_devices: int
    provisions_all_devices: bool
    get_task_allow: bool
    kind: str
    entitlements: PlistValue
    developer_certificates: int
    signer_certificates: _containers.RepeatedCompositeFieldContainer[SigningCertificate]
    plist: PlistValue
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, name: _Optional[str] = ..., uuid: _Optional[str] = ..., app_id_name: _Optional[str] = ..., application_identifier: _Optional[str] = ..., team_identifiers: _Optional[_Iterable[str]] = ..., team_name: _Optional[str] = ..., platforms: _Optional[_Iterable[str]] = ..., creation_date: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., expiration_date: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., provisioned_devices: _Optional[int] = ..., provisions_all_devices: _Optional[bool] = ..., get_task_allow: _Optional[bool] = ..., kind: _Optional[str] = ..., entitlements: _Optional[_Union[PlistValue, _Mapping]] = ..., developer_certificates: _Optional[int] = ..., signer_certificates: _Optional[_Iterable[_Union[SigningCertificate, _Mapping]]] = ..., plist: _Optional[_Union[PlistValue, _Mapping]] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class AppleBundle(_message.Message):
    __slots__ = ("path", "container_path", "kind", "layout", "platform", "info_plist_path", "info", "info_plist", "executable_path", "executable_detected", "code_signature", "nested", "interface_files", "provisioning_profile_path", "provisioning_profile", "code_resources_path", "warnings")
    PATH_FIELD_NUMBER: _ClassVar[int]
    CONTAINER_PATH_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    LAYOUT_FIELD_NUMBER: _ClassVar[int]
    PLATFORM_FIELD_NUMBER: _ClassVar[int]
    INFO_PLIST_PATH_FIELD_NUMBER: _ClassVar[int]
    INFO_FIELD_NUMBER: _ClassVar[int]
    INFO_PLIST_FIELD_NUMBER: _ClassVar[int]
    EXECUTABLE_PATH_FIELD_NUMBER: _ClassVar[int]
    EXECUTABLE_DETECTED_FIELD_NUMBER: _ClassVar[int]
    CODE_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    NESTED_FIELD_NUMBER: _ClassVar[int]
    INTERFACE_FILES_FIELD_NUMBER: _ClassVar[int]
    PROVISIONING_PROFILE_PATH_FIELD_NUMBER: _ClassVar[int]
    PROVISIONING_PROFILE_FIELD_NUMBER: _ClassVar[int]
    CODE_RESOURCES_PATH_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    path: str
    container_path: str
    kind: str
    layout: str
    platform: str
    info_plist_path: str
    info: AppleBundleInfo
    info_plist: PlistValue
    executable_path: str
    executable_detected: str
    code_signature: CodeSignature
    nested: _containers.RepeatedCompositeFieldContainer[AppleBundleRef]
    interface_files: _containers.RepeatedScalarFieldContainer[str]
    provisioning_profile_path: str
    provisioning_profile: ProvisioningProfile
    code_resources_path: str
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, path: _Optional[str] = ..., container_path: _Optional[str] = ..., kind: _Optional[str] = ..., layout: _Optional[str] = ..., platform: _Optional[str] = ..., info_plist_path: _Optional[str] = ..., info: _Optional[_Union[AppleBundleInfo, _Mapping]] = ..., info_plist: _Optional[_Union[PlistValue, _Mapping]] = ..., executable_path: _Optional[str] = ..., executable_detected: _Optional[str] = ..., code_signature: _Optional[_Union[CodeSignature, _Mapping]] = ..., nested: _Optional[_Iterable[_Union[AppleBundleRef, _Mapping]]] = ..., interface_files: _Optional[_Iterable[str]] = ..., provisioning_profile_path: _Optional[str] = ..., provisioning_profile: _Optional[_Union[ProvisioningProfile, _Mapping]] = ..., code_resources_path: _Optional[str] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class InterfaceObject(_message.Message):
    __slots__ = ("id", "class_name", "custom_class", "original_class", "placeholder", "label", "parent", "has_parent", "nib_name", "storyboard_identifier")
    ID_FIELD_NUMBER: _ClassVar[int]
    CLASS_NAME_FIELD_NUMBER: _ClassVar[int]
    CUSTOM_CLASS_FIELD_NUMBER: _ClassVar[int]
    ORIGINAL_CLASS_FIELD_NUMBER: _ClassVar[int]
    PLACEHOLDER_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    HAS_PARENT_FIELD_NUMBER: _ClassVar[int]
    NIB_NAME_FIELD_NUMBER: _ClassVar[int]
    STORYBOARD_IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    id: int
    class_name: str
    custom_class: str
    original_class: str
    placeholder: str
    label: str
    parent: int
    has_parent: bool
    nib_name: str
    storyboard_identifier: str
    def __init__(self, id: _Optional[int] = ..., class_name: _Optional[str] = ..., custom_class: _Optional[str] = ..., original_class: _Optional[str] = ..., placeholder: _Optional[str] = ..., label: _Optional[str] = ..., parent: _Optional[int] = ..., has_parent: _Optional[bool] = ..., nib_name: _Optional[str] = ..., storyboard_identifier: _Optional[str] = ...) -> None: ...

class InterfaceConnection(_message.Message):
    __slots__ = ("kind", "id", "label", "source", "has_source", "destination", "has_destination", "event_mask", "events")
    KIND_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    HAS_SOURCE_FIELD_NUMBER: _ClassVar[int]
    DESTINATION_FIELD_NUMBER: _ClassVar[int]
    HAS_DESTINATION_FIELD_NUMBER: _ClassVar[int]
    EVENT_MASK_FIELD_NUMBER: _ClassVar[int]
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    kind: str
    id: int
    label: str
    source: int
    has_source: bool
    destination: int
    has_destination: bool
    event_mask: int
    events: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, kind: _Optional[str] = ..., id: _Optional[int] = ..., label: _Optional[str] = ..., source: _Optional[int] = ..., has_source: _Optional[bool] = ..., destination: _Optional[int] = ..., has_destination: _Optional[bool] = ..., event_mask: _Optional[int] = ..., events: _Optional[_Iterable[str]] = ...) -> None: ...

class InterfaceDocument(_message.Message):
    __slots__ = ("path", "format", "storyboard", "owner_class", "owner_class_from", "objects", "connections", "warnings")
    PATH_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    STORYBOARD_FIELD_NUMBER: _ClassVar[int]
    OWNER_CLASS_FIELD_NUMBER: _ClassVar[int]
    OWNER_CLASS_FROM_FIELD_NUMBER: _ClassVar[int]
    OBJECTS_FIELD_NUMBER: _ClassVar[int]
    CONNECTIONS_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    path: str
    format: str
    storyboard: str
    owner_class: str
    owner_class_from: str
    objects: _containers.RepeatedCompositeFieldContainer[InterfaceObject]
    connections: _containers.RepeatedCompositeFieldContainer[InterfaceConnection]
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, path: _Optional[str] = ..., format: _Optional[str] = ..., storyboard: _Optional[str] = ..., owner_class: _Optional[str] = ..., owner_class_from: _Optional[str] = ..., objects: _Optional[_Iterable[_Union[InterfaceObject, _Mapping]]] = ..., connections: _Optional[_Iterable[_Union[InterfaceConnection, _Mapping]]] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class UiAction(_message.Message):
    __slots__ = ("document", "storyboard", "control", "control_class", "control_label", "events", "event_mask", "selector", "target", "target_class", "target_class_from", "resolution", "method", "implemented_by", "implementation", "function_name", "candidates")
    DOCUMENT_FIELD_NUMBER: _ClassVar[int]
    STORYBOARD_FIELD_NUMBER: _ClassVar[int]
    CONTROL_FIELD_NUMBER: _ClassVar[int]
    CONTROL_CLASS_FIELD_NUMBER: _ClassVar[int]
    CONTROL_LABEL_FIELD_NUMBER: _ClassVar[int]
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    EVENT_MASK_FIELD_NUMBER: _ClassVar[int]
    SELECTOR_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    TARGET_CLASS_FIELD_NUMBER: _ClassVar[int]
    TARGET_CLASS_FROM_FIELD_NUMBER: _ClassVar[int]
    RESOLUTION_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    IMPLEMENTED_BY_FIELD_NUMBER: _ClassVar[int]
    IMPLEMENTATION_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    CANDIDATES_FIELD_NUMBER: _ClassVar[int]
    document: str
    storyboard: str
    control: int
    control_class: str
    control_label: str
    events: _containers.RepeatedScalarFieldContainer[str]
    event_mask: int
    selector: str
    target: str
    target_class: str
    target_class_from: str
    resolution: str
    method: str
    implemented_by: str
    implementation: _common_pb2.Address
    function_name: str
    candidates: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, document: _Optional[str] = ..., storyboard: _Optional[str] = ..., control: _Optional[int] = ..., control_class: _Optional[str] = ..., control_label: _Optional[str] = ..., events: _Optional[_Iterable[str]] = ..., event_mask: _Optional[int] = ..., selector: _Optional[str] = ..., target: _Optional[str] = ..., target_class: _Optional[str] = ..., target_class_from: _Optional[str] = ..., resolution: _Optional[str] = ..., method: _Optional[str] = ..., implemented_by: _Optional[str] = ..., implementation: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., function_name: _Optional[str] = ..., candidates: _Optional[_Iterable[str]] = ...) -> None: ...

class UiOutlet(_message.Message):
    __slots__ = ("document", "source_class", "name", "destination_class", "destination_label")
    DOCUMENT_FIELD_NUMBER: _ClassVar[int]
    SOURCE_CLASS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESTINATION_CLASS_FIELD_NUMBER: _ClassVar[int]
    DESTINATION_LABEL_FIELD_NUMBER: _ClassVar[int]
    document: str
    source_class: str
    name: str
    destination_class: str
    destination_label: str
    def __init__(self, document: _Optional[str] = ..., source_class: _Optional[str] = ..., name: _Optional[str] = ..., destination_class: _Optional[str] = ..., destination_label: _Optional[str] = ...) -> None: ...
