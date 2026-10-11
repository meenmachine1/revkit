from revkit.v1 import assertion_pb2 as _assertion_pb2
from revkit.v1 import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class PluginKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PLUGIN_KIND_UNSPECIFIED: _ClassVar[PluginKind]
    PLUGIN_KIND_ANALYZER: _ClassVar[PluginKind]
    PLUGIN_KIND_LOADER: _ClassVar[PluginKind]
    PLUGIN_KIND_COMMAND: _ClassVar[PluginKind]
    PLUGIN_KIND_PERIPHERAL: _ClassVar[PluginKind]

class PluginFactKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PLUGIN_FACT_KIND_UNSPECIFIED: _ClassVar[PluginFactKind]
    PLUGIN_FACT_KIND_LABEL: _ClassVar[PluginFactKind]
    PLUGIN_FACT_KIND_COMMENT: _ClassVar[PluginFactKind]
    PLUGIN_FACT_KIND_DATA_TYPE: _ClassVar[PluginFactKind]
    PLUGIN_FACT_KIND_NOTE: _ClassVar[PluginFactKind]
PLUGIN_KIND_UNSPECIFIED: PluginKind
PLUGIN_KIND_ANALYZER: PluginKind
PLUGIN_KIND_LOADER: PluginKind
PLUGIN_KIND_COMMAND: PluginKind
PLUGIN_KIND_PERIPHERAL: PluginKind
PLUGIN_FACT_KIND_UNSPECIFIED: PluginFactKind
PLUGIN_FACT_KIND_LABEL: PluginFactKind
PLUGIN_FACT_KIND_COMMENT: PluginFactKind
PLUGIN_FACT_KIND_DATA_TYPE: PluginFactKind
PLUGIN_FACT_KIND_NOTE: PluginFactKind

class PluginArg(_message.Message):
    __slots__ = ("name", "description", "required")
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_FIELD_NUMBER: _ClassVar[int]
    name: str
    description: str
    required: bool
    def __init__(self, name: _Optional[str] = ..., description: _Optional[str] = ..., required: _Optional[bool] = ...) -> None: ...

class Plugin(_message.Message):
    __slots__ = ("name", "version", "kind", "interface_version", "description", "capabilities", "loaded", "error", "function_scope", "args", "magic", "magic_offset", "module_fingerprint", "fuel", "memory_bytes", "peripheral_outputs", "peripheral_inputs", "peripheral_size")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    INTERFACE_VERSION_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    LOADED_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_SCOPE_FIELD_NUMBER: _ClassVar[int]
    ARGS_FIELD_NUMBER: _ClassVar[int]
    MAGIC_FIELD_NUMBER: _ClassVar[int]
    MAGIC_OFFSET_FIELD_NUMBER: _ClassVar[int]
    MODULE_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    FUEL_FIELD_NUMBER: _ClassVar[int]
    MEMORY_BYTES_FIELD_NUMBER: _ClassVar[int]
    PERIPHERAL_OUTPUTS_FIELD_NUMBER: _ClassVar[int]
    PERIPHERAL_INPUTS_FIELD_NUMBER: _ClassVar[int]
    PERIPHERAL_SIZE_FIELD_NUMBER: _ClassVar[int]
    name: str
    version: str
    kind: PluginKind
    interface_version: int
    description: str
    capabilities: _containers.RepeatedScalarFieldContainer[str]
    loaded: bool
    error: str
    function_scope: bool
    args: _containers.RepeatedCompositeFieldContainer[PluginArg]
    magic: str
    magic_offset: int
    module_fingerprint: str
    fuel: int
    memory_bytes: int
    peripheral_outputs: _containers.RepeatedScalarFieldContainer[str]
    peripheral_inputs: int
    peripheral_size: int
    def __init__(self, name: _Optional[str] = ..., version: _Optional[str] = ..., kind: _Optional[_Union[PluginKind, str]] = ..., interface_version: _Optional[int] = ..., description: _Optional[str] = ..., capabilities: _Optional[_Iterable[str]] = ..., loaded: _Optional[bool] = ..., error: _Optional[str] = ..., function_scope: _Optional[bool] = ..., args: _Optional[_Iterable[_Union[PluginArg, _Mapping]]] = ..., magic: _Optional[str] = ..., magic_offset: _Optional[int] = ..., module_fingerprint: _Optional[str] = ..., fuel: _Optional[int] = ..., memory_bytes: _Optional[int] = ..., peripheral_outputs: _Optional[_Iterable[str]] = ..., peripheral_inputs: _Optional[int] = ..., peripheral_size: _Optional[int] = ...) -> None: ...

class ListPluginsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListPluginsResponse(_message.Message):
    __slots__ = ("plugins", "interface_version")
    PLUGINS_FIELD_NUMBER: _ClassVar[int]
    INTERFACE_VERSION_FIELD_NUMBER: _ClassVar[int]
    plugins: _containers.RepeatedCompositeFieldContainer[Plugin]
    interface_version: int
    def __init__(self, plugins: _Optional[_Iterable[_Union[Plugin, _Mapping]]] = ..., interface_version: _Optional[int] = ...) -> None: ...

class RunCommandRequest(_message.Message):
    __slots__ = ("program_id", "plugin", "args", "provenance", "dry_run", "expected_head_revision")
    class ArgsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    PLUGIN_FIELD_NUMBER: _ClassVar[int]
    ARGS_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    DRY_RUN_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_HEAD_REVISION_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    plugin: str
    args: _containers.ScalarMap[str, str]
    provenance: _common_pb2.Provenance
    dry_run: bool
    expected_head_revision: int
    def __init__(self, program_id: _Optional[str] = ..., plugin: _Optional[str] = ..., args: _Optional[_Mapping[str, str]] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., dry_run: _Optional[bool] = ..., expected_head_revision: _Optional[int] = ...) -> None: ...

class RunCommandResponse(_message.Message):
    __slots__ = ("snapshot", "assertions", "log", "fuel_consumed")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ASSERTIONS_FIELD_NUMBER: _ClassVar[int]
    LOG_FIELD_NUMBER: _ClassVar[int]
    FUEL_CONSUMED_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    assertions: _containers.RepeatedCompositeFieldContainer[_assertion_pb2.Assertion]
    log: _containers.RepeatedScalarFieldContainer[str]
    fuel_consumed: int
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., assertions: _Optional[_Iterable[_Union[_assertion_pb2.Assertion, _Mapping]]] = ..., log: _Optional[_Iterable[str]] = ..., fuel_consumed: _Optional[int] = ...) -> None: ...

class PluginFact(_message.Message):
    __slots__ = ("address", "kind", "text", "sub", "origin")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    SUB_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    kind: PluginFactKind
    text: str
    sub: str
    origin: _common_pb2.FactOrigin
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., kind: _Optional[_Union[PluginFactKind, str]] = ..., text: _Optional[str] = ..., sub: _Optional[str] = ..., origin: _Optional[_Union[_common_pb2.FactOrigin, _Mapping]] = ...) -> None: ...

class PluginRunError(_message.Message):
    __slots__ = ("plugin", "scope", "failure", "message")
    PLUGIN_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    plugin: str
    scope: _common_pb2.Address
    failure: str
    message: str
    def __init__(self, plugin: _Optional[str] = ..., scope: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., failure: _Optional[str] = ..., message: _Optional[str] = ...) -> None: ...

class GetPluginFactsRequest(_message.Message):
    __slots__ = ("program_id", "plugins", "range", "read")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    PLUGINS_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    plugins: _containers.RepeatedScalarFieldContainer[str]
    range: _common_pb2.AddressRange
    read: _common_pb2.ReadOptions
    def __init__(self, program_id: _Optional[str] = ..., plugins: _Optional[_Iterable[str]] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., read: _Optional[_Union[_common_pb2.ReadOptions, _Mapping]] = ...) -> None: ...

class GetPluginFactsResponse(_message.Message):
    __slots__ = ("snapshot", "facts", "errors")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FACTS_FIELD_NUMBER: _ClassVar[int]
    ERRORS_FIELD_NUMBER: _ClassVar[int]
    snapshot: _common_pb2.Snapshot
    facts: _containers.RepeatedCompositeFieldContainer[PluginFact]
    errors: _containers.RepeatedCompositeFieldContainer[PluginRunError]
    def __init__(self, snapshot: _Optional[_Union[_common_pb2.Snapshot, _Mapping]] = ..., facts: _Optional[_Iterable[_Union[PluginFact, _Mapping]]] = ..., errors: _Optional[_Iterable[_Union[PluginRunError, _Mapping]]] = ...) -> None: ...
