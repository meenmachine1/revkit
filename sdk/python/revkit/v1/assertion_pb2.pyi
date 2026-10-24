import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from revkit.v1 import common_pb2 as _common_pb2
from revkit.v1 import diff_pb2 as _diff_pb2
from revkit.v1 import types_pb2 as _types_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ComparisonForm(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    COMPARISON_FORM_UNSPECIFIED: _ClassVar[ComparisonForm]
    COMPARISON_FORM_GHIDRA: _ClassVar[ComparisonForm]
    COMPARISON_FORM_RIGHT: _ClassVar[ComparisonForm]
    COMPARISON_FORM_ENCODED: _ClassVar[ComparisonForm]

class LoadTypes(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    LOAD_TYPES_UNSPECIFIED: _ClassVar[LoadTypes]
    LOAD_TYPES_GHIDRA: _ClassVar[LoadTypes]
    LOAD_TYPES_WORDS: _ClassVar[LoadTypes]
    LOAD_TYPES_ALL: _ClassVar[LoadTypes]

class ScalarFormat(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SCALAR_FORMAT_UNSPECIFIED: _ClassVar[ScalarFormat]
    SCALAR_FORMAT_HEX: _ClassVar[ScalarFormat]
    SCALAR_FORMAT_SIGNED_DECIMAL: _ClassVar[ScalarFormat]
    SCALAR_FORMAT_UNSIGNED_DECIMAL: _ClassVar[ScalarFormat]
    SCALAR_FORMAT_OCTAL: _ClassVar[ScalarFormat]
    SCALAR_FORMAT_BINARY: _ClassVar[ScalarFormat]
    SCALAR_FORMAT_CHAR: _ClassVar[ScalarFormat]
    SCALAR_FORMAT_FLOAT: _ClassVar[ScalarFormat]

class EquateScope(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EQUATE_SCOPE_UNSPECIFIED: _ClassVar[EquateScope]
    EQUATE_SCOPE_FUNCTION: _ClassVar[EquateScope]
    EQUATE_SCOPE_PROGRAM: _ClassVar[EquateScope]

class ReferenceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    REFERENCE_TYPE_UNSPECIFIED: _ClassVar[ReferenceType]
    REFERENCE_TYPE_DATA: _ClassVar[ReferenceType]
    REFERENCE_TYPE_DATA_READ: _ClassVar[ReferenceType]
    REFERENCE_TYPE_DATA_WRITE: _ClassVar[ReferenceType]
    REFERENCE_TYPE_CALL: _ClassVar[ReferenceType]
    REFERENCE_TYPE_JUMP: _ClassVar[ReferenceType]
    REFERENCE_TYPE_COMPUTED_CALL: _ClassVar[ReferenceType]
    REFERENCE_TYPE_COMPUTED_JUMP: _ClassVar[ReferenceType]

class InstructionSet(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INSTRUCTION_SET_UNSPECIFIED: _ClassVar[InstructionSet]
    INSTRUCTION_SET_ARM: _ClassVar[InstructionSet]
    INSTRUCTION_SET_THUMB: _ClassVar[InstructionSet]

class StringLayout(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    STRING_LAYOUT_UNSPECIFIED: _ClassVar[StringLayout]
    STRING_LAYOUT_TERMINATED: _ClassVar[StringLayout]
    STRING_LAYOUT_FIXED: _ClassVar[StringLayout]
    STRING_LAYOUT_PASCAL: _ClassVar[StringLayout]
    STRING_LAYOUT_PASCAL16: _ClassVar[StringLayout]

class StringEncoding(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    STRING_ENCODING_UNSPECIFIED: _ClassVar[StringEncoding]
    STRING_ENCODING_UTF8: _ClassVar[StringEncoding]
    STRING_ENCODING_UTF16: _ClassVar[StringEncoding]
    STRING_ENCODING_UTF32: _ClassVar[StringEncoding]

class Mutability(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MUTABILITY_UNSPECIFIED: _ClassVar[Mutability]
    MUTABILITY_DEFAULT: _ClassVar[Mutability]
    MUTABILITY_NORMAL: _ClassVar[Mutability]
    MUTABILITY_CONSTANT: _ClassVar[Mutability]
    MUTABILITY_VOLATILE: _ClassVar[Mutability]

class DataFormat(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DATA_FORMAT_UNSPECIFIED: _ClassVar[DataFormat]
    DATA_FORMAT_HEX: _ClassVar[DataFormat]
    DATA_FORMAT_DECIMAL: _ClassVar[DataFormat]
    DATA_FORMAT_OCTAL: _ClassVar[DataFormat]
    DATA_FORMAT_BINARY: _ClassVar[DataFormat]
    DATA_FORMAT_CHAR: _ClassVar[DataFormat]

class DataSignedness(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DATA_SIGNEDNESS_UNSPECIFIED: _ClassVar[DataSignedness]
    DATA_SIGNEDNESS_SIGNED: _ClassVar[DataSignedness]
    DATA_SIGNEDNESS_UNSIGNED: _ClassVar[DataSignedness]

class DataEndian(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DATA_ENDIAN_UNSPECIFIED: _ClassVar[DataEndian]
    DATA_ENDIAN_LITTLE: _ClassVar[DataEndian]
    DATA_ENDIAN_BIG: _ClassVar[DataEndian]

class DataPadding(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DATA_PADDING_UNSPECIFIED: _ClassVar[DataPadding]
    DATA_PADDING_PADDED: _ClassVar[DataPadding]
    DATA_PADDING_UNPADDED: _ClassVar[DataPadding]

class StringTermination(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    STRING_TERMINATION_UNSPECIFIED: _ClassVar[StringTermination]
    STRING_TERMINATION_NUL: _ClassVar[StringTermination]
    STRING_TERMINATION_ALL: _ClassVar[StringTermination]

class PointerKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    POINTER_KIND_UNSPECIFIED: _ClassVar[PointerKind]
    POINTER_KIND_ABSOLUTE: _ClassVar[PointerKind]
    POINTER_KIND_IMAGE_BASE_OFFSET: _ClassVar[PointerKind]
    POINTER_KIND_RELATIVE: _ClassVar[PointerKind]

class CommentKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    COMMENT_KIND_UNSPECIFIED: _ClassVar[CommentKind]
    COMMENT_KIND_EOL: _ClassVar[CommentKind]
    COMMENT_KIND_PRE: _ClassVar[CommentKind]
    COMMENT_KIND_POST: _ClassVar[CommentKind]
    COMMENT_KIND_PLATE: _ClassVar[CommentKind]
    COMMENT_KIND_REPEATABLE: _ClassVar[CommentKind]
    COMMENT_KIND_DECOMPILER: _ClassVar[CommentKind]

class FlowOverrideKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FLOW_OVERRIDE_KIND_UNSPECIFIED: _ClassVar[FlowOverrideKind]
    FLOW_OVERRIDE_KIND_NONE: _ClassVar[FlowOverrideKind]
    FLOW_OVERRIDE_KIND_BRANCH: _ClassVar[FlowOverrideKind]
    FLOW_OVERRIDE_KIND_CALL: _ClassVar[FlowOverrideKind]
    FLOW_OVERRIDE_KIND_CALL_RETURN: _ClassVar[FlowOverrideKind]
    FLOW_OVERRIDE_KIND_RETURN: _ClassVar[FlowOverrideKind]

class AssertionOp(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ASSERTION_OP_UNSPECIFIED: _ClassVar[AssertionOp]
    ASSERTION_OP_ASSERT: _ClassVar[AssertionOp]
    ASSERTION_OP_RETRACT: _ClassVar[AssertionOp]

class AssertionStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ASSERTION_STATUS_UNSPECIFIED: _ClassVar[AssertionStatus]
    ASSERTION_STATUS_EFFECTIVE: _ClassVar[AssertionStatus]
    ASSERTION_STATUS_SHADOWED: _ClassVar[AssertionStatus]
    ASSERTION_STATUS_RETRACTED: _ClassVar[AssertionStatus]
    ASSERTION_STATUS_DEPENDENCY_DEAD: _ClassVar[AssertionStatus]
COMPARISON_FORM_UNSPECIFIED: ComparisonForm
COMPARISON_FORM_GHIDRA: ComparisonForm
COMPARISON_FORM_RIGHT: ComparisonForm
COMPARISON_FORM_ENCODED: ComparisonForm
LOAD_TYPES_UNSPECIFIED: LoadTypes
LOAD_TYPES_GHIDRA: LoadTypes
LOAD_TYPES_WORDS: LoadTypes
LOAD_TYPES_ALL: LoadTypes
SCALAR_FORMAT_UNSPECIFIED: ScalarFormat
SCALAR_FORMAT_HEX: ScalarFormat
SCALAR_FORMAT_SIGNED_DECIMAL: ScalarFormat
SCALAR_FORMAT_UNSIGNED_DECIMAL: ScalarFormat
SCALAR_FORMAT_OCTAL: ScalarFormat
SCALAR_FORMAT_BINARY: ScalarFormat
SCALAR_FORMAT_CHAR: ScalarFormat
SCALAR_FORMAT_FLOAT: ScalarFormat
EQUATE_SCOPE_UNSPECIFIED: EquateScope
EQUATE_SCOPE_FUNCTION: EquateScope
EQUATE_SCOPE_PROGRAM: EquateScope
REFERENCE_TYPE_UNSPECIFIED: ReferenceType
REFERENCE_TYPE_DATA: ReferenceType
REFERENCE_TYPE_DATA_READ: ReferenceType
REFERENCE_TYPE_DATA_WRITE: ReferenceType
REFERENCE_TYPE_CALL: ReferenceType
REFERENCE_TYPE_JUMP: ReferenceType
REFERENCE_TYPE_COMPUTED_CALL: ReferenceType
REFERENCE_TYPE_COMPUTED_JUMP: ReferenceType
INSTRUCTION_SET_UNSPECIFIED: InstructionSet
INSTRUCTION_SET_ARM: InstructionSet
INSTRUCTION_SET_THUMB: InstructionSet
STRING_LAYOUT_UNSPECIFIED: StringLayout
STRING_LAYOUT_TERMINATED: StringLayout
STRING_LAYOUT_FIXED: StringLayout
STRING_LAYOUT_PASCAL: StringLayout
STRING_LAYOUT_PASCAL16: StringLayout
STRING_ENCODING_UNSPECIFIED: StringEncoding
STRING_ENCODING_UTF8: StringEncoding
STRING_ENCODING_UTF16: StringEncoding
STRING_ENCODING_UTF32: StringEncoding
MUTABILITY_UNSPECIFIED: Mutability
MUTABILITY_DEFAULT: Mutability
MUTABILITY_NORMAL: Mutability
MUTABILITY_CONSTANT: Mutability
MUTABILITY_VOLATILE: Mutability
DATA_FORMAT_UNSPECIFIED: DataFormat
DATA_FORMAT_HEX: DataFormat
DATA_FORMAT_DECIMAL: DataFormat
DATA_FORMAT_OCTAL: DataFormat
DATA_FORMAT_BINARY: DataFormat
DATA_FORMAT_CHAR: DataFormat
DATA_SIGNEDNESS_UNSPECIFIED: DataSignedness
DATA_SIGNEDNESS_SIGNED: DataSignedness
DATA_SIGNEDNESS_UNSIGNED: DataSignedness
DATA_ENDIAN_UNSPECIFIED: DataEndian
DATA_ENDIAN_LITTLE: DataEndian
DATA_ENDIAN_BIG: DataEndian
DATA_PADDING_UNSPECIFIED: DataPadding
DATA_PADDING_PADDED: DataPadding
DATA_PADDING_UNPADDED: DataPadding
STRING_TERMINATION_UNSPECIFIED: StringTermination
STRING_TERMINATION_NUL: StringTermination
STRING_TERMINATION_ALL: StringTermination
POINTER_KIND_UNSPECIFIED: PointerKind
POINTER_KIND_ABSOLUTE: PointerKind
POINTER_KIND_IMAGE_BASE_OFFSET: PointerKind
POINTER_KIND_RELATIVE: PointerKind
COMMENT_KIND_UNSPECIFIED: CommentKind
COMMENT_KIND_EOL: CommentKind
COMMENT_KIND_PRE: CommentKind
COMMENT_KIND_POST: CommentKind
COMMENT_KIND_PLATE: CommentKind
COMMENT_KIND_REPEATABLE: CommentKind
COMMENT_KIND_DECOMPILER: CommentKind
FLOW_OVERRIDE_KIND_UNSPECIFIED: FlowOverrideKind
FLOW_OVERRIDE_KIND_NONE: FlowOverrideKind
FLOW_OVERRIDE_KIND_BRANCH: FlowOverrideKind
FLOW_OVERRIDE_KIND_CALL: FlowOverrideKind
FLOW_OVERRIDE_KIND_CALL_RETURN: FlowOverrideKind
FLOW_OVERRIDE_KIND_RETURN: FlowOverrideKind
ASSERTION_OP_UNSPECIFIED: AssertionOp
ASSERTION_OP_ASSERT: AssertionOp
ASSERTION_OP_RETRACT: AssertionOp
ASSERTION_STATUS_UNSPECIFIED: AssertionStatus
ASSERTION_STATUS_EFFECTIVE: AssertionStatus
ASSERTION_STATUS_SHADOWED: AssertionStatus
ASSERTION_STATUS_RETRACTED: AssertionStatus
ASSERTION_STATUS_DEPENDENCY_DEAD: AssertionStatus

class AssertionBody(_message.Message):
    __slots__ = ("rename", "retype", "comment", "function_bounds", "flow_override", "note", "define_type", "bind_type_name", "diff_match", "patch", "memory_region", "listing_edit", "mutability", "type_category", "operand_display", "reference", "image_base", "type_archive", "call_signature", "no_return", "language", "data_settings", "fallthrough", "register_value", "decompiler_settings")
    RENAME_FIELD_NUMBER: _ClassVar[int]
    RETYPE_FIELD_NUMBER: _ClassVar[int]
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_BOUNDS_FIELD_NUMBER: _ClassVar[int]
    FLOW_OVERRIDE_FIELD_NUMBER: _ClassVar[int]
    NOTE_FIELD_NUMBER: _ClassVar[int]
    DEFINE_TYPE_FIELD_NUMBER: _ClassVar[int]
    BIND_TYPE_NAME_FIELD_NUMBER: _ClassVar[int]
    DIFF_MATCH_FIELD_NUMBER: _ClassVar[int]
    PATCH_FIELD_NUMBER: _ClassVar[int]
    MEMORY_REGION_FIELD_NUMBER: _ClassVar[int]
    LISTING_EDIT_FIELD_NUMBER: _ClassVar[int]
    MUTABILITY_FIELD_NUMBER: _ClassVar[int]
    TYPE_CATEGORY_FIELD_NUMBER: _ClassVar[int]
    OPERAND_DISPLAY_FIELD_NUMBER: _ClassVar[int]
    REFERENCE_FIELD_NUMBER: _ClassVar[int]
    IMAGE_BASE_FIELD_NUMBER: _ClassVar[int]
    TYPE_ARCHIVE_FIELD_NUMBER: _ClassVar[int]
    CALL_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    NO_RETURN_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    DATA_SETTINGS_FIELD_NUMBER: _ClassVar[int]
    FALLTHROUGH_FIELD_NUMBER: _ClassVar[int]
    REGISTER_VALUE_FIELD_NUMBER: _ClassVar[int]
    DECOMPILER_SETTINGS_FIELD_NUMBER: _ClassVar[int]
    rename: Rename
    retype: Retype
    comment: Comment
    function_bounds: SetFunctionBounds
    flow_override: FlowOverride
    note: Note
    define_type: DefineType
    bind_type_name: BindTypeName
    diff_match: _diff_pb2.DiffMatchBody
    patch: PatchBody
    memory_region: MemoryRegionEdit
    listing_edit: ListingEdit
    mutability: SetMutability
    type_category: SetTypeCategory
    operand_display: OperandDisplay
    reference: UserReference
    image_base: ImageBaseBody
    type_archive: TypeArchiveSetting
    call_signature: CallSignatureOverride
    no_return: SetNoReturn
    language: ProgramLanguageBody
    data_settings: SetDataSettings
    fallthrough: SetFallthrough
    register_value: SetRegisterValue
    decompiler_settings: SetDecompilerSettings
    def __init__(self, rename: _Optional[_Union[Rename, _Mapping]] = ..., retype: _Optional[_Union[Retype, _Mapping]] = ..., comment: _Optional[_Union[Comment, _Mapping]] = ..., function_bounds: _Optional[_Union[SetFunctionBounds, _Mapping]] = ..., flow_override: _Optional[_Union[FlowOverride, _Mapping]] = ..., note: _Optional[_Union[Note, _Mapping]] = ..., define_type: _Optional[_Union[DefineType, _Mapping]] = ..., bind_type_name: _Optional[_Union[BindTypeName, _Mapping]] = ..., diff_match: _Optional[_Union[_diff_pb2.DiffMatchBody, _Mapping]] = ..., patch: _Optional[_Union[PatchBody, _Mapping]] = ..., memory_region: _Optional[_Union[MemoryRegionEdit, _Mapping]] = ..., listing_edit: _Optional[_Union[ListingEdit, _Mapping]] = ..., mutability: _Optional[_Union[SetMutability, _Mapping]] = ..., type_category: _Optional[_Union[SetTypeCategory, _Mapping]] = ..., operand_display: _Optional[_Union[OperandDisplay, _Mapping]] = ..., reference: _Optional[_Union[UserReference, _Mapping]] = ..., image_base: _Optional[_Union[ImageBaseBody, _Mapping]] = ..., type_archive: _Optional[_Union[TypeArchiveSetting, _Mapping]] = ..., call_signature: _Optional[_Union[CallSignatureOverride, _Mapping]] = ..., no_return: _Optional[_Union[SetNoReturn, _Mapping]] = ..., language: _Optional[_Union[ProgramLanguageBody, _Mapping]] = ..., data_settings: _Optional[_Union[SetDataSettings, _Mapping]] = ..., fallthrough: _Optional[_Union[SetFallthrough, _Mapping]] = ..., register_value: _Optional[_Union[SetRegisterValue, _Mapping]] = ..., decompiler_settings: _Optional[_Union[SetDecompilerSettings, _Mapping]] = ...) -> None: ...

class DecompilerSettings(_message.Message):
    __slots__ = ("comparison_form", "compilable_c", "load_types", "ghidra_flag_tests")
    COMPARISON_FORM_FIELD_NUMBER: _ClassVar[int]
    COMPILABLE_C_FIELD_NUMBER: _ClassVar[int]
    LOAD_TYPES_FIELD_NUMBER: _ClassVar[int]
    GHIDRA_FLAG_TESTS_FIELD_NUMBER: _ClassVar[int]
    comparison_form: ComparisonForm
    compilable_c: bool
    load_types: LoadTypes
    ghidra_flag_tests: bool
    def __init__(self, comparison_form: _Optional[_Union[ComparisonForm, str]] = ..., compilable_c: _Optional[bool] = ..., load_types: _Optional[_Union[LoadTypes, str]] = ..., ghidra_flag_tests: _Optional[bool] = ...) -> None: ...

class SetDecompilerSettings(_message.Message):
    __slots__ = ("settings",)
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    settings: DecompilerSettings
    def __init__(self, settings: _Optional[_Union[DecompilerSettings, _Mapping]] = ...) -> None: ...

class ProgramLanguageBody(_message.Message):
    __slots__ = ("language_id", "compiler_spec_id", "previous_language_id", "previous_compiler_spec_id")
    LANGUAGE_ID_FIELD_NUMBER: _ClassVar[int]
    COMPILER_SPEC_ID_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_LANGUAGE_ID_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_COMPILER_SPEC_ID_FIELD_NUMBER: _ClassVar[int]
    language_id: str
    compiler_spec_id: str
    previous_language_id: str
    previous_compiler_spec_id: str
    def __init__(self, language_id: _Optional[str] = ..., compiler_spec_id: _Optional[str] = ..., previous_language_id: _Optional[str] = ..., previous_compiler_spec_id: _Optional[str] = ...) -> None: ...

class SetRegisterValue(_message.Message):
    __slots__ = ("register_name", "range", "value", "clear")
    REGISTER_NAME_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    CLEAR_FIELD_NUMBER: _ClassVar[int]
    register_name: str
    range: _common_pb2.AddressRange
    value: int
    clear: bool
    def __init__(self, register_name: _Optional[str] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., value: _Optional[int] = ..., clear: _Optional[bool] = ...) -> None: ...

class SetNoReturn(_message.Message):
    __slots__ = ("function", "no_return")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    NO_RETURN_FIELD_NUMBER: _ClassVar[int]
    function: _common_pb2.Address
    no_return: bool
    def __init__(self, function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., no_return: _Optional[bool] = ...) -> None: ...

class SetFallthrough(_message.Message):
    __slots__ = ("address", "target", "no_fallthrough")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    NO_FALLTHROUGH_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    target: _common_pb2.Address
    no_fallthrough: bool
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., target: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., no_fallthrough: _Optional[bool] = ...) -> None: ...

class CallSignatureOverride(_message.Message):
    __slots__ = ("call", "signature")
    CALL_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    call: _common_pb2.Address
    signature: TypeSpec
    def __init__(self, call: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., signature: _Optional[_Union[TypeSpec, _Mapping]] = ...) -> None: ...

class ImageBaseBody(_message.Message):
    __slots__ = ("image_base", "previous_image_base", "import_image_base")
    IMAGE_BASE_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_IMAGE_BASE_FIELD_NUMBER: _ClassVar[int]
    IMPORT_IMAGE_BASE_FIELD_NUMBER: _ClassVar[int]
    image_base: int
    previous_image_base: int
    import_image_base: int
    def __init__(self, image_base: _Optional[int] = ..., previous_image_base: _Optional[int] = ..., import_image_base: _Optional[int] = ...) -> None: ...

class EquateName(_message.Message):
    __slots__ = ("name", "enum_type_hash", "member")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ENUM_TYPE_HASH_FIELD_NUMBER: _ClassVar[int]
    MEMBER_FIELD_NUMBER: _ClassVar[int]
    name: str
    enum_type_hash: str
    member: str
    def __init__(self, name: _Optional[str] = ..., enum_type_hash: _Optional[str] = ..., member: _Optional[str] = ...) -> None: ...

class OperandDisplay(_message.Message):
    __slots__ = ("address", "operand_index", "value", "format", "equate", "constant_hash", "apply_to")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    OPERAND_INDEX_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    EQUATE_FIELD_NUMBER: _ClassVar[int]
    CONSTANT_HASH_FIELD_NUMBER: _ClassVar[int]
    APPLY_TO_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    operand_index: int
    value: int
    format: ScalarFormat
    equate: EquateName
    constant_hash: int
    apply_to: EquateScope
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., operand_index: _Optional[int] = ..., value: _Optional[int] = ..., format: _Optional[_Union[ScalarFormat, str]] = ..., equate: _Optional[_Union[EquateName, _Mapping]] = ..., constant_hash: _Optional[int] = ..., apply_to: _Optional[_Union[EquateScope, str]] = ...) -> None: ...

class UserReference(_message.Message):
    __slots__ = ("operand_index", "to", "type", "primary", "remove")
    FROM_FIELD_NUMBER: _ClassVar[int]
    OPERAND_INDEX_FIELD_NUMBER: _ClassVar[int]
    TO_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    PRIMARY_FIELD_NUMBER: _ClassVar[int]
    REMOVE_FIELD_NUMBER: _ClassVar[int]
    operand_index: int
    to: _common_pb2.Address
    type: ReferenceType
    primary: bool
    remove: bool
    def __init__(self, operand_index: _Optional[int] = ..., to: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., type: _Optional[_Union[ReferenceType, str]] = ..., primary: _Optional[bool] = ..., remove: _Optional[bool] = ..., **kwargs) -> None: ...

class ListingEdit(_message.Message):
    __slots__ = ("address", "clear", "disassemble", "data")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    CLEAR_FIELD_NUMBER: _ClassVar[int]
    DISASSEMBLE_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    clear: ClearCode
    disassemble: Disassemble
    data: DefineData
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., clear: _Optional[_Union[ClearCode, _Mapping]] = ..., disassemble: _Optional[_Union[Disassemble, _Mapping]] = ..., data: _Optional[_Union[DefineData, _Mapping]] = ...) -> None: ...

class ClearCode(_message.Message):
    __slots__ = ("length",)
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    length: int
    def __init__(self, length: _Optional[int] = ...) -> None: ...

class Disassemble(_message.Message):
    __slots__ = ("instruction_set", "function")
    INSTRUCTION_SET_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    instruction_set: InstructionSet
    function: bool
    def __init__(self, instruction_set: _Optional[_Union[InstructionSet, str]] = ..., function: _Optional[bool] = ...) -> None: ...

class DefineData(_message.Message):
    __slots__ = ("type", "count", "string", "layout", "collapsed", "size", "type_hash", "type_name")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    STRING_FIELD_NUMBER: _ClassVar[int]
    LAYOUT_FIELD_NUMBER: _ClassVar[int]
    COLLAPSED_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    TYPE_HASH_FIELD_NUMBER: _ClassVar[int]
    TYPE_NAME_FIELD_NUMBER: _ClassVar[int]
    type: TypeSpec
    count: int
    string: StringEncoding
    layout: StringLayout
    collapsed: bool
    size: int
    type_hash: str
    type_name: str
    def __init__(self, type: _Optional[_Union[TypeSpec, _Mapping]] = ..., count: _Optional[int] = ..., string: _Optional[_Union[StringEncoding, str]] = ..., layout: _Optional[_Union[StringLayout, str]] = ..., collapsed: _Optional[bool] = ..., size: _Optional[int] = ..., type_hash: _Optional[str] = ..., type_name: _Optional[str] = ...) -> None: ...

class SetMutability(_message.Message):
    __slots__ = ("address", "length", "mutability")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    MUTABILITY_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    length: int
    mutability: Mutability
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., length: _Optional[int] = ..., mutability: _Optional[_Union[Mutability, str]] = ...) -> None: ...

class DataSettings(_message.Message):
    __slots__ = ("format", "signedness", "endian", "padding", "charset", "termination", "pointer_kind", "pointer_mask", "pointer_shift")
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    SIGNEDNESS_FIELD_NUMBER: _ClassVar[int]
    ENDIAN_FIELD_NUMBER: _ClassVar[int]
    PADDING_FIELD_NUMBER: _ClassVar[int]
    CHARSET_FIELD_NUMBER: _ClassVar[int]
    TERMINATION_FIELD_NUMBER: _ClassVar[int]
    POINTER_KIND_FIELD_NUMBER: _ClassVar[int]
    POINTER_MASK_FIELD_NUMBER: _ClassVar[int]
    POINTER_SHIFT_FIELD_NUMBER: _ClassVar[int]
    format: DataFormat
    signedness: DataSignedness
    endian: DataEndian
    padding: DataPadding
    charset: str
    termination: StringTermination
    pointer_kind: PointerKind
    pointer_mask: int
    pointer_shift: int
    def __init__(self, format: _Optional[_Union[DataFormat, str]] = ..., signedness: _Optional[_Union[DataSignedness, str]] = ..., endian: _Optional[_Union[DataEndian, str]] = ..., padding: _Optional[_Union[DataPadding, str]] = ..., charset: _Optional[str] = ..., termination: _Optional[_Union[StringTermination, str]] = ..., pointer_kind: _Optional[_Union[PointerKind, str]] = ..., pointer_mask: _Optional[int] = ..., pointer_shift: _Optional[int] = ...) -> None: ...

class SetDataSettings(_message.Message):
    __slots__ = ("address", "field", "type_name", "settings")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    FIELD_FIELD_NUMBER: _ClassVar[int]
    TYPE_NAME_FIELD_NUMBER: _ClassVar[int]
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    field: str
    type_name: str
    settings: DataSettings
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., field: _Optional[str] = ..., type_name: _Optional[str] = ..., settings: _Optional[_Union[DataSettings, _Mapping]] = ...) -> None: ...

class PatchBody(_message.Message):
    __slots__ = ("address", "data", "original", "text", "canonical_text", "alternatives", "context")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    ORIGINAL_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    CANONICAL_TEXT_FIELD_NUMBER: _ClassVar[int]
    ALTERNATIVES_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    data: bytes
    original: bytes
    text: str
    canonical_text: str
    alternatives: int
    context: str
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., data: _Optional[bytes] = ..., original: _Optional[bytes] = ..., text: _Optional[str] = ..., canonical_text: _Optional[str] = ..., alternatives: _Optional[int] = ..., context: _Optional[str] = ...) -> None: ...

class MemoryRegionEdit(_message.Message):
    __slots__ = ("region_id", "block_start", "removed", "name", "start", "size", "read", "write", "execute", "initialized", "is_volatile", "file", "file_offset", "length")
    REGION_ID_FIELD_NUMBER: _ClassVar[int]
    BLOCK_START_FIELD_NUMBER: _ClassVar[int]
    REMOVED_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    WRITE_FIELD_NUMBER: _ClassVar[int]
    EXECUTE_FIELD_NUMBER: _ClassVar[int]
    INITIALIZED_FIELD_NUMBER: _ClassVar[int]
    IS_VOLATILE_FIELD_NUMBER: _ClassVar[int]
    FILE_FIELD_NUMBER: _ClassVar[int]
    FILE_OFFSET_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    region_id: str
    block_start: _common_pb2.Address
    removed: bool
    name: str
    start: int
    size: int
    read: bool
    write: bool
    execute: bool
    initialized: bool
    is_volatile: bool
    file: str
    file_offset: int
    length: int
    def __init__(self, region_id: _Optional[str] = ..., block_start: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., removed: _Optional[bool] = ..., name: _Optional[str] = ..., start: _Optional[int] = ..., size: _Optional[int] = ..., read: _Optional[bool] = ..., write: _Optional[bool] = ..., execute: _Optional[bool] = ..., initialized: _Optional[bool] = ..., is_volatile: _Optional[bool] = ..., file: _Optional[str] = ..., file_offset: _Optional[int] = ..., length: _Optional[int] = ...) -> None: ...

class Target(_message.Message):
    __slots__ = ("address", "local")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LOCAL_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    local: LocalVariableRef
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., local: _Optional[_Union[LocalVariableRef, _Mapping]] = ...) -> None: ...

class LocalVariableRef(_message.Message):
    __slots__ = ("function", "storage_key")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    STORAGE_KEY_FIELD_NUMBER: _ClassVar[int]
    function: _common_pb2.Address
    storage_key: str
    def __init__(self, function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., storage_key: _Optional[str] = ...) -> None: ...

class Rename(_message.Message):
    __slots__ = ("target", "name")
    TARGET_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    target: Target
    name: str
    def __init__(self, target: _Optional[_Union[Target, _Mapping]] = ..., name: _Optional[str] = ...) -> None: ...

class Retype(_message.Message):
    __slots__ = ("target", "type")
    TARGET_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    target: Target
    type: TypeSpec
    def __init__(self, target: _Optional[_Union[Target, _Mapping]] = ..., type: _Optional[_Union[TypeSpec, _Mapping]] = ...) -> None: ...

class TypeSpec(_message.Message):
    __slots__ = ("type_hash", "c_declaration")
    TYPE_HASH_FIELD_NUMBER: _ClassVar[int]
    C_DECLARATION_FIELD_NUMBER: _ClassVar[int]
    type_hash: str
    c_declaration: str
    def __init__(self, type_hash: _Optional[str] = ..., c_declaration: _Optional[str] = ...) -> None: ...

class Comment(_message.Message):
    __slots__ = ("address", "kind", "text")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    kind: CommentKind
    text: str
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., kind: _Optional[_Union[CommentKind, str]] = ..., text: _Optional[str] = ...) -> None: ...

class SetFunctionBounds(_message.Message):
    __slots__ = ("entry", "body", "remove", "instruction_set")
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    REMOVE_FIELD_NUMBER: _ClassVar[int]
    INSTRUCTION_SET_FIELD_NUMBER: _ClassVar[int]
    entry: _common_pb2.Address
    body: _containers.RepeatedCompositeFieldContainer[_common_pb2.AddressRange]
    remove: bool
    instruction_set: InstructionSet
    def __init__(self, entry: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., body: _Optional[_Iterable[_Union[_common_pb2.AddressRange, _Mapping]]] = ..., remove: _Optional[bool] = ..., instruction_set: _Optional[_Union[InstructionSet, str]] = ...) -> None: ...

class FlowOverride(_message.Message):
    __slots__ = ("address", "kind")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    kind: FlowOverrideKind
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., kind: _Optional[_Union[FlowOverrideKind, str]] = ...) -> None: ...

class Note(_message.Message):
    __slots__ = ("address", "tag", "text")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    TAG_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    tag: str
    text: str
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., tag: _Optional[str] = ..., text: _Optional[str] = ...) -> None: ...

class DefineType(_message.Message):
    __slots__ = ("type",)
    TYPE_FIELD_NUMBER: _ClassVar[int]
    type: _types_pb2.TypeNode
    def __init__(self, type: _Optional[_Union[_types_pb2.TypeNode, _Mapping]] = ...) -> None: ...

class BindTypeName(_message.Message):
    __slots__ = ("type",)
    TYPE_FIELD_NUMBER: _ClassVar[int]
    type: _types_pb2.TypeNodeRef
    def __init__(self, type: _Optional[_Union[_types_pb2.TypeNodeRef, _Mapping]] = ...) -> None: ...

class SetTypeCategory(_message.Message):
    __slots__ = ("named_key", "path")
    NAMED_KEY_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    named_key: str
    path: str
    def __init__(self, named_key: _Optional[str] = ..., path: _Optional[str] = ...) -> None: ...

class TypeArchiveSetting(_message.Message):
    __slots__ = ("name", "enabled", "header", "sidecar", "detach")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    SIDECAR_FIELD_NUMBER: _ClassVar[int]
    DETACH_FIELD_NUMBER: _ClassVar[int]
    name: str
    enabled: bool
    header: str
    sidecar: str
    detach: bool
    def __init__(self, name: _Optional[str] = ..., enabled: _Optional[bool] = ..., header: _Optional[str] = ..., sidecar: _Optional[str] = ..., detach: _Optional[bool] = ...) -> None: ...

class Assertion(_message.Message):
    __slots__ = ("seq", "revision", "time", "provenance", "op", "key", "body", "retracts_seq", "depends_on_seq", "status", "retracted_by", "id", "stamp", "retracts_id", "depends_on_id", "retracted_by_ids", "supersedes", "ported_from")
    SEQ_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    TIME_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    OP_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    RETRACTS_SEQ_FIELD_NUMBER: _ClassVar[int]
    DEPENDS_ON_SEQ_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RETRACTED_BY_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    STAMP_FIELD_NUMBER: _ClassVar[int]
    RETRACTS_ID_FIELD_NUMBER: _ClassVar[int]
    DEPENDS_ON_ID_FIELD_NUMBER: _ClassVar[int]
    RETRACTED_BY_IDS_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDES_FIELD_NUMBER: _ClassVar[int]
    PORTED_FROM_FIELD_NUMBER: _ClassVar[int]
    seq: int
    revision: int
    time: _timestamp_pb2.Timestamp
    provenance: _common_pb2.Provenance
    op: AssertionOp
    key: _common_pb2.FactKey
    body: AssertionBody
    retracts_seq: int
    depends_on_seq: int
    status: AssertionStatus
    retracted_by: _containers.RepeatedScalarFieldContainer[int]
    id: _common_pb2.OpId
    stamp: int
    retracts_id: _common_pb2.OpId
    depends_on_id: _common_pb2.OpId
    retracted_by_ids: _containers.RepeatedCompositeFieldContainer[_common_pb2.OpId]
    supersedes: _common_pb2.OpId
    ported_from: _diff_pb2.PortedFrom
    def __init__(self, seq: _Optional[int] = ..., revision: _Optional[int] = ..., time: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., op: _Optional[_Union[AssertionOp, str]] = ..., key: _Optional[_Union[_common_pb2.FactKey, _Mapping]] = ..., body: _Optional[_Union[AssertionBody, _Mapping]] = ..., retracts_seq: _Optional[int] = ..., depends_on_seq: _Optional[int] = ..., status: _Optional[_Union[AssertionStatus, str]] = ..., retracted_by: _Optional[_Iterable[int]] = ..., id: _Optional[_Union[_common_pb2.OpId, _Mapping]] = ..., stamp: _Optional[int] = ..., retracts_id: _Optional[_Union[_common_pb2.OpId, _Mapping]] = ..., depends_on_id: _Optional[_Union[_common_pb2.OpId, _Mapping]] = ..., retracted_by_ids: _Optional[_Iterable[_Union[_common_pb2.OpId, _Mapping]]] = ..., supersedes: _Optional[_Union[_common_pb2.OpId, _Mapping]] = ..., ported_from: _Optional[_Union[_diff_pb2.PortedFrom, _Mapping]] = ...) -> None: ...

class AssertionInput(_message.Message):
    __slots__ = ("body", "depends_on_seq")
    BODY_FIELD_NUMBER: _ClassVar[int]
    DEPENDS_ON_SEQ_FIELD_NUMBER: _ClassVar[int]
    body: AssertionBody
    depends_on_seq: int
    def __init__(self, body: _Optional[_Union[AssertionBody, _Mapping]] = ..., depends_on_seq: _Optional[int] = ...) -> None: ...

class AppendAssertionsRequest(_message.Message):
    __slots__ = ("program_id", "assertions", "provenance", "expected_head_revision", "validate_only", "project_scope", "skip_invalid")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ASSERTIONS_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_HEAD_REVISION_FIELD_NUMBER: _ClassVar[int]
    VALIDATE_ONLY_FIELD_NUMBER: _ClassVar[int]
    PROJECT_SCOPE_FIELD_NUMBER: _ClassVar[int]
    SKIP_INVALID_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    assertions: _containers.RepeatedCompositeFieldContainer[AssertionInput]
    provenance: _common_pb2.Provenance
    expected_head_revision: int
    validate_only: bool
    project_scope: bool
    skip_invalid: bool
    def __init__(self, program_id: _Optional[str] = ..., assertions: _Optional[_Iterable[_Union[AssertionInput, _Mapping]]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., expected_head_revision: _Optional[int] = ..., validate_only: _Optional[bool] = ..., project_scope: _Optional[bool] = ..., skip_invalid: _Optional[bool] = ...) -> None: ...

class RefusedAssertion(_message.Message):
    __slots__ = ("index", "reason")
    INDEX_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    index: int
    reason: str
    def __init__(self, index: _Optional[int] = ..., reason: _Optional[str] = ...) -> None: ...

class AppendAssertionsResponse(_message.Message):
    __slots__ = ("snapshot", "assertions", "changed_keys", "refused")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ASSERTIONS_FIELD_NUMBER: _ClassVar[int]
    CHANGED_KEYS_FIELD_NUMBER: _ClassVar[int]
    REFUSED_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    assertions: _containers.RepeatedCompositeFieldContainer[Assertion]
    changed_keys: _containers.RepeatedCompositeFieldContainer[_common_pb2.FactKey]
    refused: _containers.RepeatedCompositeFieldContainer[RefusedAssertion]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., assertions: _Optional[_Iterable[_Union[Assertion, _Mapping]]] = ..., changed_keys: _Optional[_Iterable[_Union[_common_pb2.FactKey, _Mapping]]] = ..., refused: _Optional[_Iterable[_Union[RefusedAssertion, _Mapping]]] = ...) -> None: ...

class RetractAssertionsRequest(_message.Message):
    __slots__ = ("program_id", "seqs", "provenance", "expected_head_revision", "project_id")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    SEQS_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_HEAD_REVISION_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    seqs: _containers.RepeatedScalarFieldContainer[int]
    provenance: _common_pb2.Provenance
    expected_head_revision: int
    project_id: str
    def __init__(self, program_id: _Optional[str] = ..., seqs: _Optional[_Iterable[int]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., expected_head_revision: _Optional[int] = ..., project_id: _Optional[str] = ...) -> None: ...

class RetractAssertionsResponse(_message.Message):
    __slots__ = ("snapshot", "retractions", "changed_keys")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    RETRACTIONS_FIELD_NUMBER: _ClassVar[int]
    CHANGED_KEYS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    retractions: _containers.RepeatedCompositeFieldContainer[Assertion]
    changed_keys: _containers.RepeatedCompositeFieldContainer[_common_pb2.FactKey]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., retractions: _Optional[_Iterable[_Union[Assertion, _Mapping]]] = ..., changed_keys: _Optional[_Iterable[_Union[_common_pb2.FactKey, _Mapping]]] = ...) -> None: ...

class GetHistoryRequest(_message.Message):
    __slots__ = ("key", "read", "page")
    KEY_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    key: _common_pb2.FactKey
    read: _common_pb2.ReadOptions
    page: _common_pb2.PageRequest
    def __init__(self, key: _Optional[_Union[_common_pb2.FactKey, _Mapping]] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., page: _Optional[_Union[_common_pb2.PageRequest, _Mapping]] = ...) -> None: ...

class GetHistoryResponse(_message.Message):
    __slots__ = ("snapshot", "entries", "page")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    entries: _containers.RepeatedCompositeFieldContainer[Assertion]
    page: _common_pb2.PageInfo
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., entries: _Optional[_Iterable[_Union[Assertion, _Mapping]]] = ..., page: _Optional[_Union[_common_pb2.PageInfo, _Mapping]] = ...) -> None: ...

class BlameRequest(_message.Message):
    __slots__ = ("key", "read")
    KEY_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    key: _common_pb2.FactKey
    read: _common_pb2.ReadOptions
    def __init__(self, key: _Optional[_Union[_common_pb2.FactKey, _Mapping]] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ...) -> None: ...

class BlameResponse(_message.Message):
    __slots__ = ("snapshot", "key", "value_text", "origin", "candidates", "concurrent_seqs")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_TEXT_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    CANDIDATES_FIELD_NUMBER: _ClassVar[int]
    CONCURRENT_SEQS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    key: _common_pb2.FactKey
    value_text: str
    origin: _common_pb2.FactOrigin
    candidates: _containers.RepeatedCompositeFieldContainer[Assertion]
    concurrent_seqs: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., key: _Optional[_Union[_common_pb2.FactKey, _Mapping]] = ..., value_text: _Optional[str] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ..., candidates: _Optional[_Iterable[_Union[Assertion, _Mapping]]] = ..., concurrent_seqs: _Optional[_Iterable[int]] = ...) -> None: ...

class ProvenanceFilter(_message.Message):
    __slots__ = ("kind", "id", "version", "session", "on_behalf_of")
    KIND_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    SESSION_FIELD_NUMBER: _ClassVar[int]
    ON_BEHALF_OF_FIELD_NUMBER: _ClassVar[int]
    kind: _common_pb2.ProvenanceKind
    id: str
    version: str
    session: str
    on_behalf_of: str
    def __init__(self, kind: _Optional[_Union[_common_pb2.ProvenanceKind, str]] = ..., id: _Optional[str] = ..., version: _Optional[str] = ..., session: _Optional[str] = ..., on_behalf_of: _Optional[str] = ...) -> None: ...

class AssertionFilter(_message.Message):
    __slots__ = ("provenance", "kinds", "range", "min_revision", "max_revision", "include_inactive")
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    KINDS_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    MIN_REVISION_FIELD_NUMBER: _ClassVar[int]
    MAX_REVISION_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_INACTIVE_FIELD_NUMBER: _ClassVar[int]
    provenance: ProvenanceFilter
    kinds: _containers.RepeatedScalarFieldContainer[_common_pb2.FactKind]
    range: _common_pb2.AddressRange
    min_revision: int
    max_revision: int
    include_inactive: bool
    def __init__(self, provenance: _Optional[_Union[ProvenanceFilter, _Mapping]] = ..., kinds: _Optional[_Iterable[_Union[_common_pb2.FactKind, str]]] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., min_revision: _Optional[int] = ..., max_revision: _Optional[int] = ..., include_inactive: _Optional[bool] = ...) -> None: ...

class ListAssertionsRequest(_message.Message):
    __slots__ = ("program_id", "filter", "read", "page")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    FILTER_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    filter: AssertionFilter
    read: _common_pb2.ReadOptions
    page: _common_pb2.PageRequest
    def __init__(self, program_id: _Optional[str] = ..., filter: _Optional[_Union[AssertionFilter, _Mapping]] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ..., page: _Optional[_Union[_common_pb2.PageRequest, _Mapping]] = ...) -> None: ...

class ListAssertionsResponse(_message.Message):
    __slots__ = ("snapshot", "assertions", "page")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ASSERTIONS_FIELD_NUMBER: _ClassVar[int]
    PAGE_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    assertions: _containers.RepeatedCompositeFieldContainer[Assertion]
    page: _common_pb2.PageInfo
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., assertions: _Optional[_Iterable[_Union[Assertion, _Mapping]]] = ..., page: _Optional[_Union[_common_pb2.PageInfo, _Mapping]] = ...) -> None: ...

class RevertByProvenanceRequest(_message.Message):
    __slots__ = ("program_id", "filter", "since_revision", "provenance", "dry_run")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    FILTER_FIELD_NUMBER: _ClassVar[int]
    SINCE_REVISION_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    DRY_RUN_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    filter: ProvenanceFilter
    since_revision: int
    provenance: _common_pb2.Provenance
    dry_run: bool
    def __init__(self, program_id: _Optional[str] = ..., filter: _Optional[_Union[ProvenanceFilter, _Mapping]] = ..., since_revision: _Optional[int] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., dry_run: _Optional[bool] = ...) -> None: ...

class RevertByProvenanceResponse(_message.Message):
    __slots__ = ("snapshot", "retracted_seqs", "retractions", "changed_keys")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    RETRACTED_SEQS_FIELD_NUMBER: _ClassVar[int]
    RETRACTIONS_FIELD_NUMBER: _ClassVar[int]
    CHANGED_KEYS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    retracted_seqs: _containers.RepeatedScalarFieldContainer[int]
    retractions: _containers.RepeatedCompositeFieldContainer[Assertion]
    changed_keys: _containers.RepeatedCompositeFieldContainer[_common_pb2.FactKey]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., retracted_seqs: _Optional[_Iterable[int]] = ..., retractions: _Optional[_Iterable[_Union[Assertion, _Mapping]]] = ..., changed_keys: _Optional[_Iterable[_Union[_common_pb2.FactKey, _Mapping]]] = ...) -> None: ...
