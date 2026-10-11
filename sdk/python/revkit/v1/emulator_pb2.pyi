from revkit.v1 import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EmulatorStartMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EMULATOR_START_MODE_UNSPECIFIED: _ClassVar[EmulatorStartMode]
    EMULATOR_START_MODE_PROCESS: _ClassVar[EmulatorStartMode]
    EMULATOR_START_MODE_CALL: _ClassVar[EmulatorStartMode]
    EMULATOR_START_MODE_BARE: _ClassVar[EmulatorStartMode]

class EmulatorRunMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EMULATOR_RUN_MODE_UNSPECIFIED: _ClassVar[EmulatorRunMode]
    EMULATOR_RUN_MODE_RUN: _ClassVar[EmulatorRunMode]
    EMULATOR_RUN_MODE_STEP_INTO: _ClassVar[EmulatorRunMode]
    EMULATOR_RUN_MODE_STEP_OVER: _ClassVar[EmulatorRunMode]
    EMULATOR_RUN_MODE_STEP_OUT: _ClassVar[EmulatorRunMode]

class EmulatorStopKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EMULATOR_STOP_KIND_UNSPECIFIED: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_NONE: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_STEPPED: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_STEP_LIMIT: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_BREAKPOINT: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_UNTIL: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_RETURNED: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_EXITED: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_HALTED: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_UNMAPPED: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_PROTECTION: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_DECODE: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_UNIMPLEMENTED: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_USEROP: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_SYSCALL: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_WATCHPOINT: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_HOOK: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_DIVIDE_BY_ZERO: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_MEMORY_LIMIT: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_TIME_LIMIT: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_CANCELLED: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_SESSION_LIMIT: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_EXCEPTION: _ClassVar[EmulatorStopKind]
    EMULATOR_STOP_KIND_IDLE: _ClassVar[EmulatorStopKind]
EMULATOR_START_MODE_UNSPECIFIED: EmulatorStartMode
EMULATOR_START_MODE_PROCESS: EmulatorStartMode
EMULATOR_START_MODE_CALL: EmulatorStartMode
EMULATOR_START_MODE_BARE: EmulatorStartMode
EMULATOR_RUN_MODE_UNSPECIFIED: EmulatorRunMode
EMULATOR_RUN_MODE_RUN: EmulatorRunMode
EMULATOR_RUN_MODE_STEP_INTO: EmulatorRunMode
EMULATOR_RUN_MODE_STEP_OVER: EmulatorRunMode
EMULATOR_RUN_MODE_STEP_OUT: EmulatorRunMode
EMULATOR_STOP_KIND_UNSPECIFIED: EmulatorStopKind
EMULATOR_STOP_KIND_NONE: EmulatorStopKind
EMULATOR_STOP_KIND_STEPPED: EmulatorStopKind
EMULATOR_STOP_KIND_STEP_LIMIT: EmulatorStopKind
EMULATOR_STOP_KIND_BREAKPOINT: EmulatorStopKind
EMULATOR_STOP_KIND_UNTIL: EmulatorStopKind
EMULATOR_STOP_KIND_RETURNED: EmulatorStopKind
EMULATOR_STOP_KIND_EXITED: EmulatorStopKind
EMULATOR_STOP_KIND_HALTED: EmulatorStopKind
EMULATOR_STOP_KIND_UNMAPPED: EmulatorStopKind
EMULATOR_STOP_KIND_PROTECTION: EmulatorStopKind
EMULATOR_STOP_KIND_DECODE: EmulatorStopKind
EMULATOR_STOP_KIND_UNIMPLEMENTED: EmulatorStopKind
EMULATOR_STOP_KIND_USEROP: EmulatorStopKind
EMULATOR_STOP_KIND_SYSCALL: EmulatorStopKind
EMULATOR_STOP_KIND_WATCHPOINT: EmulatorStopKind
EMULATOR_STOP_KIND_HOOK: EmulatorStopKind
EMULATOR_STOP_KIND_DIVIDE_BY_ZERO: EmulatorStopKind
EMULATOR_STOP_KIND_MEMORY_LIMIT: EmulatorStopKind
EMULATOR_STOP_KIND_TIME_LIMIT: EmulatorStopKind
EMULATOR_STOP_KIND_CANCELLED: EmulatorStopKind
EMULATOR_STOP_KIND_SESSION_LIMIT: EmulatorStopKind
EMULATOR_STOP_KIND_EXCEPTION: EmulatorStopKind
EMULATOR_STOP_KIND_IDLE: EmulatorStopKind

class EmulatorStop(_message.Message):
    __slots__ = ("kind", "pc", "address", "detail", "exit_code", "steps")
    KIND_FIELD_NUMBER: _ClassVar[int]
    PC_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    EXIT_CODE_FIELD_NUMBER: _ClassVar[int]
    STEPS_FIELD_NUMBER: _ClassVar[int]
    kind: EmulatorStopKind
    pc: _common_pb2.Address
    address: _common_pb2.Address
    detail: str
    exit_code: int
    steps: int
    def __init__(self, kind: _Optional[_Union[EmulatorStopKind, str]] = ..., pc: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., detail: _Optional[str] = ..., exit_code: _Optional[int] = ..., steps: _Optional[int] = ...) -> None: ...

class EmulatorRegisterValue(_message.Message):
    __slots__ = ("name", "size", "value", "bytes", "changed")
    NAME_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    CHANGED_FIELD_NUMBER: _ClassVar[int]
    name: str
    size: int
    value: int
    bytes: bytes
    changed: bool
    def __init__(self, name: _Optional[str] = ..., size: _Optional[int] = ..., value: _Optional[int] = ..., bytes: _Optional[bytes] = ..., changed: _Optional[bool] = ...) -> None: ...

class EmulatorRegisterWrite(_message.Message):
    __slots__ = ("name", "value", "bytes")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: int
    bytes: bytes
    def __init__(self, name: _Optional[str] = ..., value: _Optional[int] = ..., bytes: _Optional[bytes] = ...) -> None: ...

class EmulatorMemoryWrite(_message.Message):
    __slots__ = ("address", "data")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    data: bytes
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class EmulatorRegisterInfo(_message.Message):
    __slots__ = ("name", "size", "display")
    NAME_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_FIELD_NUMBER: _ClassVar[int]
    name: str
    size: int
    display: bool
    def __init__(self, name: _Optional[str] = ..., size: _Optional[int] = ..., display: _Optional[bool] = ...) -> None: ...

class EmulatorRegion(_message.Message):
    __slots__ = ("name", "range", "permissions", "kind")
    NAME_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    name: str
    range: _common_pb2.AddressRange
    permissions: str
    kind: str
    def __init__(self, name: _Optional[str] = ..., range: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ..., permissions: _Optional[str] = ..., kind: _Optional[str] = ...) -> None: ...

class EmulatorLimits(_message.Message):
    __slots__ = ("max_steps_per_call", "max_total_steps", "max_memory_bytes", "trace_capacity", "time_limit_ms")
    MAX_STEPS_PER_CALL_FIELD_NUMBER: _ClassVar[int]
    MAX_TOTAL_STEPS_FIELD_NUMBER: _ClassVar[int]
    MAX_MEMORY_BYTES_FIELD_NUMBER: _ClassVar[int]
    TRACE_CAPACITY_FIELD_NUMBER: _ClassVar[int]
    TIME_LIMIT_MS_FIELD_NUMBER: _ClassVar[int]
    max_steps_per_call: int
    max_total_steps: int
    max_memory_bytes: int
    trace_capacity: int
    time_limit_ms: int
    def __init__(self, max_steps_per_call: _Optional[int] = ..., max_total_steps: _Optional[int] = ..., max_memory_bytes: _Optional[int] = ..., trace_capacity: _Optional[int] = ..., time_limit_ms: _Optional[int] = ...) -> None: ...

class CreateEmulatorSessionRequest(_message.Message):
    __slots__ = ("program_id", "entry", "mode", "arguments", "registers", "memory", "breakpoints", "limits", "import_return", "no_library_stubs", "stdin", "client", "machine", "machine_name")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    ARGUMENTS_FIELD_NUMBER: _ClassVar[int]
    REGISTERS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_FIELD_NUMBER: _ClassVar[int]
    BREAKPOINTS_FIELD_NUMBER: _ClassVar[int]
    LIMITS_FIELD_NUMBER: _ClassVar[int]
    IMPORT_RETURN_FIELD_NUMBER: _ClassVar[int]
    NO_LIBRARY_STUBS_FIELD_NUMBER: _ClassVar[int]
    STDIN_FIELD_NUMBER: _ClassVar[int]
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    MACHINE_FIELD_NUMBER: _ClassVar[int]
    MACHINE_NAME_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    entry: _common_pb2.Address
    mode: EmulatorStartMode
    arguments: _containers.RepeatedScalarFieldContainer[int]
    registers: _containers.RepeatedCompositeFieldContainer[EmulatorRegisterWrite]
    memory: _containers.RepeatedCompositeFieldContainer[EmulatorMemoryWrite]
    breakpoints: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    limits: EmulatorLimits
    import_return: int
    no_library_stubs: bool
    stdin: bytes
    client: str
    machine: str
    machine_name: str
    def __init__(self, program_id: _Optional[str] = ..., entry: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., mode: _Optional[_Union[EmulatorStartMode, str]] = ..., arguments: _Optional[_Iterable[int]] = ..., registers: _Optional[_Iterable[_Union[EmulatorRegisterWrite, _Mapping]]] = ..., memory: _Optional[_Iterable[_Union[EmulatorMemoryWrite, _Mapping]]] = ..., breakpoints: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., limits: _Optional[_Union[EmulatorLimits, _Mapping]] = ..., import_return: _Optional[int] = ..., no_library_stubs: _Optional[bool] = ..., stdin: _Optional[bytes] = ..., client: _Optional[str] = ..., machine: _Optional[str] = ..., machine_name: _Optional[str] = ...) -> None: ...

class EmulatorDevice(_message.Message):
    __slots__ = ("name", "kind", "base", "size", "state", "next_tick")
    NAME_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    BASE_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    NEXT_TICK_FIELD_NUMBER: _ClassVar[int]
    name: str
    kind: str
    base: int
    size: int
    state: str
    next_tick: int
    def __init__(self, name: _Optional[str] = ..., kind: _Optional[str] = ..., base: _Optional[int] = ..., size: _Optional[int] = ..., state: _Optional[str] = ..., next_tick: _Optional[int] = ...) -> None: ...

class EmulatorMachineInfo(_message.Message):
    __slots__ = ("name", "cpu", "devices", "hz", "wall_clock")
    NAME_FIELD_NUMBER: _ClassVar[int]
    CPU_FIELD_NUMBER: _ClassVar[int]
    DEVICES_FIELD_NUMBER: _ClassVar[int]
    HZ_FIELD_NUMBER: _ClassVar[int]
    WALL_CLOCK_FIELD_NUMBER: _ClassVar[int]
    name: str
    cpu: str
    devices: _containers.RepeatedCompositeFieldContainer[EmulatorDevice]
    hz: int
    wall_clock: bool
    def __init__(self, name: _Optional[str] = ..., cpu: _Optional[str] = ..., devices: _Optional[_Iterable[_Union[EmulatorDevice, _Mapping]]] = ..., hz: _Optional[int] = ..., wall_clock: _Optional[bool] = ...) -> None: ...

class EmulatorException(_message.Message):
    __slots__ = ("step", "tick", "kind", "number", "pc", "handler", "source", "detail")
    STEP_FIELD_NUMBER: _ClassVar[int]
    TICK_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    NUMBER_FIELD_NUMBER: _ClassVar[int]
    PC_FIELD_NUMBER: _ClassVar[int]
    HANDLER_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    step: int
    tick: int
    kind: str
    number: int
    pc: _common_pb2.Address
    handler: _common_pb2.Address
    source: str
    detail: str
    def __init__(self, step: _Optional[int] = ..., tick: _Optional[int] = ..., kind: _Optional[str] = ..., number: _Optional[int] = ..., pc: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., handler: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., source: _Optional[str] = ..., detail: _Optional[str] = ...) -> None: ...

class EmulatorMachineState(_message.Message):
    __slots__ = ("cpu", "mode", "tick", "hz", "waiting", "exceptions_taken", "registers", "devices", "pending", "log", "exception_breaks")
    CPU_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    TICK_FIELD_NUMBER: _ClassVar[int]
    HZ_FIELD_NUMBER: _ClassVar[int]
    WAITING_FIELD_NUMBER: _ClassVar[int]
    EXCEPTIONS_TAKEN_FIELD_NUMBER: _ClassVar[int]
    REGISTERS_FIELD_NUMBER: _ClassVar[int]
    DEVICES_FIELD_NUMBER: _ClassVar[int]
    PENDING_FIELD_NUMBER: _ClassVar[int]
    LOG_FIELD_NUMBER: _ClassVar[int]
    EXCEPTION_BREAKS_FIELD_NUMBER: _ClassVar[int]
    cpu: str
    mode: str
    tick: int
    hz: int
    waiting: bool
    exceptions_taken: int
    registers: _containers.RepeatedCompositeFieldContainer[EmulatorRegisterValue]
    devices: _containers.RepeatedCompositeFieldContainer[EmulatorDevice]
    pending: _containers.RepeatedScalarFieldContainer[str]
    log: _containers.RepeatedScalarFieldContainer[str]
    exception_breaks: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, cpu: _Optional[str] = ..., mode: _Optional[str] = ..., tick: _Optional[int] = ..., hz: _Optional[int] = ..., waiting: _Optional[bool] = ..., exceptions_taken: _Optional[int] = ..., registers: _Optional[_Iterable[_Union[EmulatorRegisterValue, _Mapping]]] = ..., devices: _Optional[_Iterable[_Union[EmulatorDevice, _Mapping]]] = ..., pending: _Optional[_Iterable[str]] = ..., log: _Optional[_Iterable[str]] = ..., exception_breaks: _Optional[_Iterable[str]] = ...) -> None: ...

class CreateEmulatorSessionResponse(_message.Message):
    __slots__ = ("session_id", "language", "registers", "pc_register", "sp_register", "state", "limits", "machine")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    REGISTERS_FIELD_NUMBER: _ClassVar[int]
    PC_REGISTER_FIELD_NUMBER: _ClassVar[int]
    SP_REGISTER_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    LIMITS_FIELD_NUMBER: _ClassVar[int]
    MACHINE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    language: str
    registers: _containers.RepeatedCompositeFieldContainer[EmulatorRegisterInfo]
    pc_register: str
    sp_register: str
    state: EmulatorState
    limits: EmulatorLimits
    machine: EmulatorMachineInfo
    def __init__(self, session_id: _Optional[str] = ..., language: _Optional[str] = ..., registers: _Optional[_Iterable[_Union[EmulatorRegisterInfo, _Mapping]]] = ..., pc_register: _Optional[str] = ..., sp_register: _Optional[str] = ..., state: _Optional[_Union[EmulatorState, _Mapping]] = ..., limits: _Optional[_Union[EmulatorLimits, _Mapping]] = ..., machine: _Optional[_Union[EmulatorMachineInfo, _Mapping]] = ...) -> None: ...

class CloseEmulatorSessionRequest(_message.Message):
    __slots__ = ("session_id",)
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    def __init__(self, session_id: _Optional[str] = ...) -> None: ...

class CloseEmulatorSessionResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListEmulatorSessionsRequest(_message.Message):
    __slots__ = ("client",)
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    client: str
    def __init__(self, client: _Optional[str] = ...) -> None: ...

class EmulatorSessionInfo(_message.Message):
    __slots__ = ("session_id", "program_id", "client", "steps", "last_stop", "idle_ms")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    STEPS_FIELD_NUMBER: _ClassVar[int]
    LAST_STOP_FIELD_NUMBER: _ClassVar[int]
    IDLE_MS_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    program_id: str
    client: str
    steps: int
    last_stop: EmulatorStop
    idle_ms: int
    def __init__(self, session_id: _Optional[str] = ..., program_id: _Optional[str] = ..., client: _Optional[str] = ..., steps: _Optional[int] = ..., last_stop: _Optional[_Union[EmulatorStop, _Mapping]] = ..., idle_ms: _Optional[int] = ...) -> None: ...

class ListEmulatorSessionsResponse(_message.Message):
    __slots__ = ("sessions",)
    SESSIONS_FIELD_NUMBER: _ClassVar[int]
    sessions: _containers.RepeatedCompositeFieldContainer[EmulatorSessionInfo]
    def __init__(self, sessions: _Optional[_Iterable[_Union[EmulatorSessionInfo, _Mapping]]] = ...) -> None: ...

class EmulatorState(_message.Message):
    __slots__ = ("pc", "thumb", "steps", "last_stop", "registers", "breakpoints", "memory_used", "stdout", "stderr", "stdout_size", "stderr_size", "regions", "machine", "tick", "waiting")
    PC_FIELD_NUMBER: _ClassVar[int]
    THUMB_FIELD_NUMBER: _ClassVar[int]
    STEPS_FIELD_NUMBER: _ClassVar[int]
    LAST_STOP_FIELD_NUMBER: _ClassVar[int]
    REGISTERS_FIELD_NUMBER: _ClassVar[int]
    BREAKPOINTS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_USED_FIELD_NUMBER: _ClassVar[int]
    STDOUT_FIELD_NUMBER: _ClassVar[int]
    STDERR_FIELD_NUMBER: _ClassVar[int]
    STDOUT_SIZE_FIELD_NUMBER: _ClassVar[int]
    STDERR_SIZE_FIELD_NUMBER: _ClassVar[int]
    REGIONS_FIELD_NUMBER: _ClassVar[int]
    MACHINE_FIELD_NUMBER: _ClassVar[int]
    TICK_FIELD_NUMBER: _ClassVar[int]
    WAITING_FIELD_NUMBER: _ClassVar[int]
    pc: _common_pb2.Address
    thumb: bool
    steps: int
    last_stop: EmulatorStop
    registers: _containers.RepeatedCompositeFieldContainer[EmulatorRegisterValue]
    breakpoints: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    memory_used: int
    stdout: bytes
    stderr: bytes
    stdout_size: int
    stderr_size: int
    regions: _containers.RepeatedCompositeFieldContainer[EmulatorRegion]
    machine: bool
    tick: int
    waiting: bool
    def __init__(self, pc: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., thumb: _Optional[bool] = ..., steps: _Optional[int] = ..., last_stop: _Optional[_Union[EmulatorStop, _Mapping]] = ..., registers: _Optional[_Iterable[_Union[EmulatorRegisterValue, _Mapping]]] = ..., breakpoints: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., memory_used: _Optional[int] = ..., stdout: _Optional[bytes] = ..., stderr: _Optional[bytes] = ..., stdout_size: _Optional[int] = ..., stderr_size: _Optional[int] = ..., regions: _Optional[_Iterable[_Union[EmulatorRegion, _Mapping]]] = ..., machine: _Optional[bool] = ..., tick: _Optional[int] = ..., waiting: _Optional[bool] = ...) -> None: ...

class EmulatorStateOptions(_message.Message):
    __slots__ = ("registers", "all_registers", "stdout_offset", "stderr_offset", "include_regions")
    REGISTERS_FIELD_NUMBER: _ClassVar[int]
    ALL_REGISTERS_FIELD_NUMBER: _ClassVar[int]
    STDOUT_OFFSET_FIELD_NUMBER: _ClassVar[int]
    STDERR_OFFSET_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_REGIONS_FIELD_NUMBER: _ClassVar[int]
    registers: _containers.RepeatedScalarFieldContainer[str]
    all_registers: bool
    stdout_offset: int
    stderr_offset: int
    include_regions: bool
    def __init__(self, registers: _Optional[_Iterable[str]] = ..., all_registers: _Optional[bool] = ..., stdout_offset: _Optional[int] = ..., stderr_offset: _Optional[int] = ..., include_regions: _Optional[bool] = ...) -> None: ...

class RunEmulatorRequest(_message.Message):
    __slots__ = ("session_id", "mode", "max_steps", "until", "time_limit_ms", "state")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    MAX_STEPS_FIELD_NUMBER: _ClassVar[int]
    UNTIL_FIELD_NUMBER: _ClassVar[int]
    TIME_LIMIT_MS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    mode: EmulatorRunMode
    max_steps: int
    until: _common_pb2.Address
    time_limit_ms: int
    state: EmulatorStateOptions
    def __init__(self, session_id: _Optional[str] = ..., mode: _Optional[_Union[EmulatorRunMode, str]] = ..., max_steps: _Optional[int] = ..., until: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., time_limit_ms: _Optional[int] = ..., state: _Optional[_Union[EmulatorStateOptions, _Mapping]] = ...) -> None: ...

class RunEmulatorResponse(_message.Message):
    __slots__ = ("stop", "state")
    STOP_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    stop: EmulatorStop
    state: EmulatorState
    def __init__(self, stop: _Optional[_Union[EmulatorStop, _Mapping]] = ..., state: _Optional[_Union[EmulatorState, _Mapping]] = ...) -> None: ...

class GetEmulatorStateRequest(_message.Message):
    __slots__ = ("session_id", "state")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    state: EmulatorStateOptions
    def __init__(self, session_id: _Optional[str] = ..., state: _Optional[_Union[EmulatorStateOptions, _Mapping]] = ...) -> None: ...

class GetEmulatorStateResponse(_message.Message):
    __slots__ = ("state",)
    STATE_FIELD_NUMBER: _ClassVar[int]
    state: EmulatorState
    def __init__(self, state: _Optional[_Union[EmulatorState, _Mapping]] = ...) -> None: ...

class WriteEmulatorRegistersRequest(_message.Message):
    __slots__ = ("session_id", "registers", "state")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    REGISTERS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    registers: _containers.RepeatedCompositeFieldContainer[EmulatorRegisterWrite]
    state: EmulatorStateOptions
    def __init__(self, session_id: _Optional[str] = ..., registers: _Optional[_Iterable[_Union[EmulatorRegisterWrite, _Mapping]]] = ..., state: _Optional[_Union[EmulatorStateOptions, _Mapping]] = ...) -> None: ...

class WriteEmulatorRegistersResponse(_message.Message):
    __slots__ = ("state",)
    STATE_FIELD_NUMBER: _ClassVar[int]
    state: EmulatorState
    def __init__(self, state: _Optional[_Union[EmulatorState, _Mapping]] = ...) -> None: ...

class ReadEmulatorMemoryRequest(_message.Message):
    __slots__ = ("session_id", "address", "length")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    address: _common_pb2.Address
    length: int
    def __init__(self, session_id: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., length: _Optional[int] = ...) -> None: ...

class EmulatorByteRange(_message.Message):
    __slots__ = ("offset", "length")
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    offset: int
    length: int
    def __init__(self, offset: _Optional[int] = ..., length: _Optional[int] = ...) -> None: ...

class ReadEmulatorMemoryResponse(_message.Message):
    __slots__ = ("address", "data", "unmapped")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    UNMAPPED_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    data: bytes
    unmapped: _containers.RepeatedCompositeFieldContainer[EmulatorByteRange]
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., data: _Optional[bytes] = ..., unmapped: _Optional[_Iterable[_Union[EmulatorByteRange, _Mapping]]] = ...) -> None: ...

class WriteEmulatorMemoryRequest(_message.Message):
    __slots__ = ("session_id", "address", "data")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    address: _common_pb2.Address
    data: bytes
    def __init__(self, session_id: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class WriteEmulatorMemoryResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SetEmulatorBreakpointsRequest(_message.Message):
    __slots__ = ("session_id", "add", "remove", "clear", "exception_breaks", "set_exception_breaks")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ADD_FIELD_NUMBER: _ClassVar[int]
    REMOVE_FIELD_NUMBER: _ClassVar[int]
    CLEAR_FIELD_NUMBER: _ClassVar[int]
    EXCEPTION_BREAKS_FIELD_NUMBER: _ClassVar[int]
    SET_EXCEPTION_BREAKS_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    add: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    remove: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    clear: bool
    exception_breaks: _containers.RepeatedScalarFieldContainer[str]
    set_exception_breaks: bool
    def __init__(self, session_id: _Optional[str] = ..., add: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., remove: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., clear: _Optional[bool] = ..., exception_breaks: _Optional[_Iterable[str]] = ..., set_exception_breaks: _Optional[bool] = ...) -> None: ...

class SetEmulatorBreakpointsResponse(_message.Message):
    __slots__ = ("breakpoints", "exception_breaks")
    BREAKPOINTS_FIELD_NUMBER: _ClassVar[int]
    EXCEPTION_BREAKS_FIELD_NUMBER: _ClassVar[int]
    breakpoints: _containers.RepeatedCompositeFieldContainer[_common_pb2.Address]
    exception_breaks: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, breakpoints: _Optional[_Iterable[_Union[_common_pb2.Address, _Mapping]]] = ..., exception_breaks: _Optional[_Iterable[str]] = ...) -> None: ...

class GetEmulatorTraceRequest(_message.Message):
    __slots__ = ("session_id", "from_index", "limit", "json")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    FROM_INDEX_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    JSON_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    from_index: int
    limit: int
    json: bool
    def __init__(self, session_id: _Optional[str] = ..., from_index: _Optional[int] = ..., limit: _Optional[int] = ..., json: _Optional[bool] = ...) -> None: ...

class EmulatorMemoryAccess(_message.Message):
    __slots__ = ("address", "data", "mmio")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    MMIO_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    data: bytes
    mmio: bool
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., data: _Optional[bytes] = ..., mmio: _Optional[bool] = ...) -> None: ...

class EmulatorTraceEntry(_message.Message):
    __slots__ = ("index", "pc", "thumb", "bytes", "text", "registers", "reads", "writes", "event", "exception", "exception_number")
    INDEX_FIELD_NUMBER: _ClassVar[int]
    PC_FIELD_NUMBER: _ClassVar[int]
    THUMB_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    REGISTERS_FIELD_NUMBER: _ClassVar[int]
    READS_FIELD_NUMBER: _ClassVar[int]
    WRITES_FIELD_NUMBER: _ClassVar[int]
    EVENT_FIELD_NUMBER: _ClassVar[int]
    EXCEPTION_FIELD_NUMBER: _ClassVar[int]
    EXCEPTION_NUMBER_FIELD_NUMBER: _ClassVar[int]
    index: int
    pc: _common_pb2.Address
    thumb: bool
    bytes: bytes
    text: str
    registers: _containers.RepeatedCompositeFieldContainer[EmulatorRegisterValue]
    reads: _containers.RepeatedCompositeFieldContainer[EmulatorMemoryAccess]
    writes: _containers.RepeatedCompositeFieldContainer[EmulatorMemoryAccess]
    event: str
    exception: str
    exception_number: int
    def __init__(self, index: _Optional[int] = ..., pc: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., thumb: _Optional[bool] = ..., bytes: _Optional[bytes] = ..., text: _Optional[str] = ..., registers: _Optional[_Iterable[_Union[EmulatorRegisterValue, _Mapping]]] = ..., reads: _Optional[_Iterable[_Union[EmulatorMemoryAccess, _Mapping]]] = ..., writes: _Optional[_Iterable[_Union[EmulatorMemoryAccess, _Mapping]]] = ..., event: _Optional[str] = ..., exception: _Optional[str] = ..., exception_number: _Optional[int] = ...) -> None: ...

class EmulatorTraceSummary(_message.Message):
    __slots__ = ("steps", "recorded", "dropped", "unique_pcs", "memory_reads", "memory_writes", "mmio_reads", "mmio_writes", "syscalls", "stub_calls", "userops", "exceptions")
    STEPS_FIELD_NUMBER: _ClassVar[int]
    RECORDED_FIELD_NUMBER: _ClassVar[int]
    DROPPED_FIELD_NUMBER: _ClassVar[int]
    UNIQUE_PCS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_READS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_WRITES_FIELD_NUMBER: _ClassVar[int]
    MMIO_READS_FIELD_NUMBER: _ClassVar[int]
    MMIO_WRITES_FIELD_NUMBER: _ClassVar[int]
    SYSCALLS_FIELD_NUMBER: _ClassVar[int]
    STUB_CALLS_FIELD_NUMBER: _ClassVar[int]
    USEROPS_FIELD_NUMBER: _ClassVar[int]
    EXCEPTIONS_FIELD_NUMBER: _ClassVar[int]
    steps: int
    recorded: int
    dropped: int
    unique_pcs: int
    memory_reads: int
    memory_writes: int
    mmio_reads: int
    mmio_writes: int
    syscalls: int
    stub_calls: int
    userops: int
    exceptions: int
    def __init__(self, steps: _Optional[int] = ..., recorded: _Optional[int] = ..., dropped: _Optional[int] = ..., unique_pcs: _Optional[int] = ..., memory_reads: _Optional[int] = ..., memory_writes: _Optional[int] = ..., mmio_reads: _Optional[int] = ..., mmio_writes: _Optional[int] = ..., syscalls: _Optional[int] = ..., stub_calls: _Optional[int] = ..., userops: _Optional[int] = ..., exceptions: _Optional[int] = ...) -> None: ...

class GetEmulatorTraceResponse(_message.Message):
    __slots__ = ("entries", "summary", "json")
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    SUMMARY_FIELD_NUMBER: _ClassVar[int]
    JSON_FIELD_NUMBER: _ClassVar[int]
    entries: _containers.RepeatedCompositeFieldContainer[EmulatorTraceEntry]
    summary: EmulatorTraceSummary
    json: str
    def __init__(self, entries: _Optional[_Iterable[_Union[EmulatorTraceEntry, _Mapping]]] = ..., summary: _Optional[_Union[EmulatorTraceSummary, _Mapping]] = ..., json: _Optional[str] = ...) -> None: ...

class WriteEmulatorInputRequest(_message.Message):
    __slots__ = ("session_id", "data", "peripheral")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    PERIPHERAL_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    data: bytes
    peripheral: str
    def __init__(self, session_id: _Optional[str] = ..., data: _Optional[bytes] = ..., peripheral: _Optional[str] = ...) -> None: ...

class WriteEmulatorInputResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetEmulatorMachineRequest(_message.Message):
    __slots__ = ("session_id", "from_event", "limit")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    FROM_EVENT_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    from_event: int
    limit: int
    def __init__(self, session_id: _Optional[str] = ..., from_event: _Optional[int] = ..., limit: _Optional[int] = ...) -> None: ...

class GetEmulatorMachineResponse(_message.Message):
    __slots__ = ("state", "events", "first_event", "event_count")
    STATE_FIELD_NUMBER: _ClassVar[int]
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    FIRST_EVENT_FIELD_NUMBER: _ClassVar[int]
    EVENT_COUNT_FIELD_NUMBER: _ClassVar[int]
    state: EmulatorMachineState
    events: _containers.RepeatedCompositeFieldContainer[EmulatorException]
    first_event: int
    event_count: int
    def __init__(self, state: _Optional[_Union[EmulatorMachineState, _Mapping]] = ..., events: _Optional[_Iterable[_Union[EmulatorException, _Mapping]]] = ..., first_event: _Optional[int] = ..., event_count: _Optional[int] = ...) -> None: ...

class MachineInfo(_message.Message):
    __slots__ = ("name", "program_id", "description", "modified_unix", "bytes", "persisted")
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    MODIFIED_UNIX_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    PERSISTED_FIELD_NUMBER: _ClassVar[int]
    name: str
    program_id: str
    description: str
    modified_unix: int
    bytes: int
    persisted: bool
    def __init__(self, name: _Optional[str] = ..., program_id: _Optional[str] = ..., description: _Optional[str] = ..., modified_unix: _Optional[int] = ..., bytes: _Optional[int] = ..., persisted: _Optional[bool] = ...) -> None: ...

class ListMachinesRequest(_message.Message):
    __slots__ = ("program_id",)
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    def __init__(self, program_id: _Optional[str] = ...) -> None: ...

class ListMachinesResponse(_message.Message):
    __slots__ = ("machines",)
    MACHINES_FIELD_NUMBER: _ClassVar[int]
    machines: _containers.RepeatedCompositeFieldContainer[MachineInfo]
    def __init__(self, machines: _Optional[_Iterable[_Union[MachineInfo, _Mapping]]] = ...) -> None: ...

class GetMachineRequest(_message.Message):
    __slots__ = ("program_id", "name")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    name: str
    def __init__(self, program_id: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class GetMachineResponse(_message.Message):
    __slots__ = ("info", "machine")
    INFO_FIELD_NUMBER: _ClassVar[int]
    MACHINE_FIELD_NUMBER: _ClassVar[int]
    info: MachineInfo
    machine: str
    def __init__(self, info: _Optional[_Union[MachineInfo, _Mapping]] = ..., machine: _Optional[str] = ...) -> None: ...

class SaveMachineRequest(_message.Message):
    __slots__ = ("program_id", "name", "machine")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    MACHINE_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    name: str
    machine: str
    def __init__(self, program_id: _Optional[str] = ..., name: _Optional[str] = ..., machine: _Optional[str] = ...) -> None: ...

class SaveMachineResponse(_message.Message):
    __slots__ = ("info",)
    INFO_FIELD_NUMBER: _ClassVar[int]
    info: MachineInfo
    def __init__(self, info: _Optional[_Union[MachineInfo, _Mapping]] = ...) -> None: ...

class DeleteMachineRequest(_message.Message):
    __slots__ = ("program_id", "name")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    name: str
    def __init__(self, program_id: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class DeleteMachineResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DeriveMachineRequest(_message.Message):
    __slots__ = ("program_id", "trial_steps", "no_trial")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    TRIAL_STEPS_FIELD_NUMBER: _ClassVar[int]
    NO_TRIAL_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    trial_steps: int
    no_trial: bool
    def __init__(self, program_id: _Optional[str] = ..., trial_steps: _Optional[int] = ..., no_trial: _Optional[bool] = ...) -> None: ...

class DeriveMachineResponse(_message.Message):
    __slots__ = ("machine", "notes", "mmio_registers", "polling_loops", "trial_steps", "trial_stop")
    MACHINE_FIELD_NUMBER: _ClassVar[int]
    NOTES_FIELD_NUMBER: _ClassVar[int]
    MMIO_REGISTERS_FIELD_NUMBER: _ClassVar[int]
    POLLING_LOOPS_FIELD_NUMBER: _ClassVar[int]
    TRIAL_STEPS_FIELD_NUMBER: _ClassVar[int]
    TRIAL_STOP_FIELD_NUMBER: _ClassVar[int]
    machine: str
    notes: _containers.RepeatedScalarFieldContainer[str]
    mmio_registers: int
    polling_loops: int
    trial_steps: int
    trial_stop: EmulatorStop
    def __init__(self, machine: _Optional[str] = ..., notes: _Optional[_Iterable[str]] = ..., mmio_registers: _Optional[int] = ..., polling_loops: _Optional[int] = ..., trial_steps: _Optional[int] = ..., trial_stop: _Optional[_Union[EmulatorStop, _Mapping]] = ...) -> None: ...

class ListPeripheralKindsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class PeripheralKind(_message.Message):
    __slots__ = ("kind", "description", "plugin", "outputs")
    KIND_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    PLUGIN_FIELD_NUMBER: _ClassVar[int]
    OUTPUTS_FIELD_NUMBER: _ClassVar[int]
    kind: str
    description: str
    plugin: bool
    outputs: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, kind: _Optional[str] = ..., description: _Optional[str] = ..., plugin: _Optional[bool] = ..., outputs: _Optional[_Iterable[str]] = ...) -> None: ...

class ListPeripheralKindsResponse(_message.Message):
    __slots__ = ("kinds",)
    KINDS_FIELD_NUMBER: _ClassVar[int]
    kinds: _containers.RepeatedCompositeFieldContainer[PeripheralKind]
    def __init__(self, kinds: _Optional[_Iterable[_Union[PeripheralKind, _Mapping]]] = ...) -> None: ...
