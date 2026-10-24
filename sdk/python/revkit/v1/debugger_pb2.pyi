from revkit.v1 import common_pb2 as _common_pb2
from revkit.v1 import decompile_pb2 as _decompile_pb2
from revkit.v1 import emulator_pb2 as _emulator_pb2
from revkit.v1 import project_pb2 as _project_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class DebugRunMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DEBUG_RUN_MODE_UNSPECIFIED: _ClassVar[DebugRunMode]
    DEBUG_RUN_MODE_RUN: _ClassVar[DebugRunMode]
    DEBUG_RUN_MODE_STEP_INTO: _ClassVar[DebugRunMode]
    DEBUG_RUN_MODE_STEP_OVER: _ClassVar[DebugRunMode]
    DEBUG_RUN_MODE_STEP_OUT: _ClassVar[DebugRunMode]

class DebugStopKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DEBUG_STOP_KIND_UNSPECIFIED: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_NONE: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_STEPPED: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_STEP_LIMIT: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_BREAKPOINT: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_UNTIL: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_RETURNED: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_EXITED: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_HALTED: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_UNMAPPED: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_PROTECTION: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_DECODE: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_UNIMPLEMENTED: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_USEROP: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_SYSCALL: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_WATCHPOINT: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_HOOK: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_DIVIDE_BY_ZERO: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_MEMORY_LIMIT: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_TIME_LIMIT: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_CANCELLED: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_SESSION_LIMIT: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_SIGNAL: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_INTERRUPTED: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_RUNNING: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_KILLED: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_DETACHED: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_DISCONNECTED: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_EXCEPTION: _ClassVar[DebugStopKind]
    DEBUG_STOP_KIND_IDLE: _ClassVar[DebugStopKind]

class DebugTargetState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DEBUG_TARGET_STATE_UNSPECIFIED: _ClassVar[DebugTargetState]
    DEBUG_TARGET_STATE_STOPPED: _ClassVar[DebugTargetState]
    DEBUG_TARGET_STATE_RUNNING: _ClassVar[DebugTargetState]
    DEBUG_TARGET_STATE_EXITED: _ClassVar[DebugTargetState]
    DEBUG_TARGET_STATE_DETACHED: _ClassVar[DebugTargetState]
    DEBUG_TARGET_STATE_DISCONNECTED: _ClassVar[DebugTargetState]
    DEBUG_TARGET_STATE_REPLAY: _ClassVar[DebugTargetState]

class DebugBreakpointKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DEBUG_BREAKPOINT_KIND_UNSPECIFIED: _ClassVar[DebugBreakpointKind]
    DEBUG_BREAKPOINT_KIND_SOFTWARE: _ClassVar[DebugBreakpointKind]
    DEBUG_BREAKPOINT_KIND_HARDWARE: _ClassVar[DebugBreakpointKind]
    DEBUG_BREAKPOINT_KIND_WATCH_WRITE: _ClassVar[DebugBreakpointKind]
    DEBUG_BREAKPOINT_KIND_WATCH_READ: _ClassVar[DebugBreakpointKind]
    DEBUG_BREAKPOINT_KIND_WATCH_ACCESS: _ClassVar[DebugBreakpointKind]

class DebugCopyMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DEBUG_COPY_MODE_UNSPECIFIED: _ClassVar[DebugCopyMode]
    DEBUG_COPY_MODE_BLOCK: _ClassVar[DebugCopyMode]
    DEBUG_COPY_MODE_PATCH: _ClassVar[DebugCopyMode]
    DEBUG_COPY_MODE_NEW_PROGRAM: _ClassVar[DebugCopyMode]

class DebugHookKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DEBUG_HOOK_KIND_UNSPECIFIED: _ClassVar[DebugHookKind]
    DEBUG_HOOK_KIND_FUNCTION: _ClassVar[DebugHookKind]
    DEBUG_HOOK_KIND_SYSCALL: _ClassVar[DebugHookKind]
    DEBUG_HOOK_KIND_MMIO: _ClassVar[DebugHookKind]
    DEBUG_HOOK_KIND_USEROP: _ClassVar[DebugHookKind]

class DebugSnapshotKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DEBUG_SNAPSHOT_KIND_UNSPECIFIED: _ClassVar[DebugSnapshotKind]
    DEBUG_SNAPSHOT_KIND_STOP: _ClassVar[DebugSnapshotKind]
    DEBUG_SNAPSHOT_KIND_STEP: _ClassVar[DebugSnapshotKind]
    DEBUG_SNAPSHOT_KIND_EDIT: _ClassVar[DebugSnapshotKind]
DEBUG_RUN_MODE_UNSPECIFIED: DebugRunMode
DEBUG_RUN_MODE_RUN: DebugRunMode
DEBUG_RUN_MODE_STEP_INTO: DebugRunMode
DEBUG_RUN_MODE_STEP_OVER: DebugRunMode
DEBUG_RUN_MODE_STEP_OUT: DebugRunMode
DEBUG_STOP_KIND_UNSPECIFIED: DebugStopKind
DEBUG_STOP_KIND_NONE: DebugStopKind
DEBUG_STOP_KIND_STEPPED: DebugStopKind
DEBUG_STOP_KIND_STEP_LIMIT: DebugStopKind
DEBUG_STOP_KIND_BREAKPOINT: DebugStopKind
DEBUG_STOP_KIND_UNTIL: DebugStopKind
DEBUG_STOP_KIND_RETURNED: DebugStopKind
DEBUG_STOP_KIND_EXITED: DebugStopKind
DEBUG_STOP_KIND_HALTED: DebugStopKind
DEBUG_STOP_KIND_UNMAPPED: DebugStopKind
DEBUG_STOP_KIND_PROTECTION: DebugStopKind
DEBUG_STOP_KIND_DECODE: DebugStopKind
DEBUG_STOP_KIND_UNIMPLEMENTED: DebugStopKind
DEBUG_STOP_KIND_USEROP: DebugStopKind
DEBUG_STOP_KIND_SYSCALL: DebugStopKind
DEBUG_STOP_KIND_WATCHPOINT: DebugStopKind
DEBUG_STOP_KIND_HOOK: DebugStopKind
DEBUG_STOP_KIND_DIVIDE_BY_ZERO: DebugStopKind
DEBUG_STOP_KIND_MEMORY_LIMIT: DebugStopKind
DEBUG_STOP_KIND_TIME_LIMIT: DebugStopKind
DEBUG_STOP_KIND_CANCELLED: DebugStopKind
DEBUG_STOP_KIND_SESSION_LIMIT: DebugStopKind
DEBUG_STOP_KIND_SIGNAL: DebugStopKind
DEBUG_STOP_KIND_INTERRUPTED: DebugStopKind
DEBUG_STOP_KIND_RUNNING: DebugStopKind
DEBUG_STOP_KIND_KILLED: DebugStopKind
DEBUG_STOP_KIND_DETACHED: DebugStopKind
DEBUG_STOP_KIND_DISCONNECTED: DebugStopKind
DEBUG_STOP_KIND_EXCEPTION: DebugStopKind
DEBUG_STOP_KIND_IDLE: DebugStopKind
DEBUG_TARGET_STATE_UNSPECIFIED: DebugTargetState
DEBUG_TARGET_STATE_STOPPED: DebugTargetState
DEBUG_TARGET_STATE_RUNNING: DebugTargetState
DEBUG_TARGET_STATE_EXITED: DebugTargetState
DEBUG_TARGET_STATE_DETACHED: DebugTargetState
DEBUG_TARGET_STATE_DISCONNECTED: DebugTargetState
DEBUG_TARGET_STATE_REPLAY: DebugTargetState
DEBUG_BREAKPOINT_KIND_UNSPECIFIED: DebugBreakpointKind
DEBUG_BREAKPOINT_KIND_SOFTWARE: DebugBreakpointKind
DEBUG_BREAKPOINT_KIND_HARDWARE: DebugBreakpointKind
DEBUG_BREAKPOINT_KIND_WATCH_WRITE: DebugBreakpointKind
DEBUG_BREAKPOINT_KIND_WATCH_READ: DebugBreakpointKind
DEBUG_BREAKPOINT_KIND_WATCH_ACCESS: DebugBreakpointKind
DEBUG_COPY_MODE_UNSPECIFIED: DebugCopyMode
DEBUG_COPY_MODE_BLOCK: DebugCopyMode
DEBUG_COPY_MODE_PATCH: DebugCopyMode
DEBUG_COPY_MODE_NEW_PROGRAM: DebugCopyMode
DEBUG_HOOK_KIND_UNSPECIFIED: DebugHookKind
DEBUG_HOOK_KIND_FUNCTION: DebugHookKind
DEBUG_HOOK_KIND_SYSCALL: DebugHookKind
DEBUG_HOOK_KIND_MMIO: DebugHookKind
DEBUG_HOOK_KIND_USEROP: DebugHookKind
DEBUG_SNAPSHOT_KIND_UNSPECIFIED: DebugSnapshotKind
DEBUG_SNAPSHOT_KIND_STOP: DebugSnapshotKind
DEBUG_SNAPSHOT_KIND_STEP: DebugSnapshotKind
DEBUG_SNAPSHOT_KIND_EDIT: DebugSnapshotKind

class DebugEmulatorTarget(_message.Message):
    __slots__ = ("entry", "mode", "arguments", "registers", "memory", "limits", "import_return", "no_library_stubs", "stdin", "machine", "machine_name", "from_session", "from_snapshot")
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    ARGUMENTS_FIELD_NUMBER: _ClassVar[int]
    REGISTERS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_FIELD_NUMBER: _ClassVar[int]
    LIMITS_FIELD_NUMBER: _ClassVar[int]
    IMPORT_RETURN_FIELD_NUMBER: _ClassVar[int]
    NO_LIBRARY_STUBS_FIELD_NUMBER: _ClassVar[int]
    STDIN_FIELD_NUMBER: _ClassVar[int]
    MACHINE_FIELD_NUMBER: _ClassVar[int]
    MACHINE_NAME_FIELD_NUMBER: _ClassVar[int]
    FROM_SESSION_FIELD_NUMBER: _ClassVar[int]
    FROM_SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    entry: _common_pb2.Address
    mode: _emulator_pb2.EmulatorStartMode
    arguments: _containers.RepeatedScalarFieldContainer[int]
    registers: _containers.RepeatedCompositeFieldContainer[_emulator_pb2.EmulatorRegisterWrite]
    memory: _containers.RepeatedCompositeFieldContainer[_emulator_pb2.EmulatorMemoryWrite]
    limits: _emulator_pb2.EmulatorLimits
    import_return: int
    no_library_stubs: bool
    stdin: bytes
    machine: str
    machine_name: str
    from_session: str
    from_snapshot: int
    def __init__(self, entry: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., mode: _Optional[_Union[_emulator_pb2.EmulatorStartMode, str]] = ..., arguments: _Optional[_Iterable[int]] = ..., registers: _Optional[_Iterable[_Union[_emulator_pb2.EmulatorRegisterWrite, _Mapping]]] = ..., memory: _Optional[_Iterable[_Union[_emulator_pb2.EmulatorMemoryWrite, _Mapping]]] = ..., limits: _Optional[_Union[_emulator_pb2.EmulatorLimits, _Mapping]] = ..., import_return: _Optional[int] = ..., no_library_stubs: _Optional[bool] = ..., stdin: _Optional[bytes] = ..., machine: _Optional[str] = ..., machine_name: _Optional[str] = ..., from_session: _Optional[str] = ..., from_snapshot: _Optional[int] = ...) -> None: ...

class DebugRemoteTarget(_message.Message):
    __slots__ = ("address", "attach_pid", "timeout_ms")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    ATTACH_PID_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    address: str
    attach_pid: int
    timeout_ms: int
    def __init__(self, address: _Optional[str] = ..., attach_pid: _Optional[int] = ..., timeout_ms: _Optional[int] = ...) -> None: ...

class DebugLaunchTarget(_message.Message):
    __slots__ = ("arguments", "environment", "attach_pid", "qemu")
    ARGUMENTS_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    ATTACH_PID_FIELD_NUMBER: _ClassVar[int]
    QEMU_FIELD_NUMBER: _ClassVar[int]
    arguments: _containers.RepeatedScalarFieldContainer[str]
    environment: _containers.RepeatedScalarFieldContainer[str]
    attach_pid: int
    qemu: str
    def __init__(self, arguments: _Optional[_Iterable[str]] = ..., environment: _Optional[_Iterable[str]] = ..., attach_pid: _Optional[int] = ..., qemu: _Optional[str] = ...) -> None: ...

class DebugTraceTarget(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class DebugCrashTarget(_message.Message):
    __slots__ = ("dump_program_id", "host_path", "upload_id")
    DUMP_PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    HOST_PATH_FIELD_NUMBER: _ClassVar[int]
    UPLOAD_ID_FIELD_NUMBER: _ClassVar[int]
    dump_program_id: str
    host_path: str
    upload_id: str
    def __init__(self, dump_program_id: _Optional[str] = ..., host_path: _Optional[str] = ..., upload_id: _Optional[str] = ...) -> None: ...

class DebugTimelineLimits(_message.Message):
    __slots__ = ("max_snapshots", "max_bytes", "stops_only", "stack_bytes")
    MAX_SNAPSHOTS_FIELD_NUMBER: _ClassVar[int]
    MAX_BYTES_FIELD_NUMBER: _ClassVar[int]
    STOPS_ONLY_FIELD_NUMBER: _ClassVar[int]
    STACK_BYTES_FIELD_NUMBER: _ClassVar[int]
    max_snapshots: int
    max_bytes: int
    stops_only: bool
    stack_bytes: int
    def __init__(self, max_snapshots: _Optional[int] = ..., max_bytes: _Optional[int] = ..., stops_only: _Optional[bool] = ..., stack_bytes: _Optional[int] = ...) -> None: ...

class DebugAddress(_message.Message):
    __slots__ = ("offset", "program")
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_FIELD_NUMBER: _ClassVar[int]
    offset: int
    program: bool
    def __init__(self, offset: _Optional[int] = ..., program: _Optional[bool] = ...) -> None: ...

class DebugLocation(_message.Message):
    __slots__ = ("address", "program_address", "module", "module_offset", "library_program_id", "library_address", "library_function")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    MODULE_FIELD_NUMBER: _ClassVar[int]
    MODULE_OFFSET_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_FUNCTION_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    program_address: _common_pb2.Address
    module: str
    module_offset: int
    library_program_id: str
    library_address: _common_pb2.Address
    library_function: str
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., program_address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., module: _Optional[str] = ..., module_offset: _Optional[int] = ..., library_program_id: _Optional[str] = ..., library_address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., library_function: _Optional[str] = ...) -> None: ...

class DebugAddressMapping(_message.Message):
    __slots__ = ("known", "slide", "how")
    KNOWN_FIELD_NUMBER: _ClassVar[int]
    SLIDE_FIELD_NUMBER: _ClassVar[int]
    HOW_FIELD_NUMBER: _ClassVar[int]
    known: bool
    slide: int
    how: str
    def __init__(self, known: _Optional[bool] = ..., slide: _Optional[int] = ..., how: _Optional[str] = ...) -> None: ...

class DebugStop(_message.Message):
    __slots__ = ("kind", "pc", "address", "detail", "exit_code", "steps", "signal", "thread", "hook")
    KIND_FIELD_NUMBER: _ClassVar[int]
    PC_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    EXIT_CODE_FIELD_NUMBER: _ClassVar[int]
    STEPS_FIELD_NUMBER: _ClassVar[int]
    SIGNAL_FIELD_NUMBER: _ClassVar[int]
    THREAD_FIELD_NUMBER: _ClassVar[int]
    HOOK_FIELD_NUMBER: _ClassVar[int]
    kind: DebugStopKind
    pc: DebugLocation
    address: _common_pb2.Address
    detail: str
    exit_code: int
    steps: int
    signal: int
    thread: str
    hook: DebugHookEvent
    def __init__(self, kind: _Optional[_Union[DebugStopKind, str]] = ..., pc: _Optional[_Union[DebugLocation, _Mapping]] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., detail: _Optional[str] = ..., exit_code: _Optional[int] = ..., steps: _Optional[int] = ..., signal: _Optional[int] = ..., thread: _Optional[str] = ..., hook: _Optional[_Union[DebugHookEvent, _Mapping]] = ...) -> None: ...

class DebugRegisterInfo(_message.Message):
    __slots__ = ("name", "target_name", "size", "display", "group", "sleigh")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TARGET_NAME_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_FIELD_NUMBER: _ClassVar[int]
    GROUP_FIELD_NUMBER: _ClassVar[int]
    SLEIGH_FIELD_NUMBER: _ClassVar[int]
    name: str
    target_name: str
    size: int
    display: bool
    group: str
    sleigh: str
    def __init__(self, name: _Optional[str] = ..., target_name: _Optional[str] = ..., size: _Optional[int] = ..., display: _Optional[bool] = ..., group: _Optional[str] = ..., sleigh: _Optional[str] = ...) -> None: ...

class DebugRegisterValue(_message.Message):
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

class DebugRegisterWrite(_message.Message):
    __slots__ = ("name", "value", "bytes")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: int
    bytes: bytes
    def __init__(self, name: _Optional[str] = ..., value: _Optional[int] = ..., bytes: _Optional[bytes] = ...) -> None: ...

class DebugBreakpointSpec(_message.Message):
    __slots__ = ("address", "kind", "size", "condition", "ignore_count", "disabled")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    CONDITION_FIELD_NUMBER: _ClassVar[int]
    IGNORE_COUNT_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    address: DebugAddress
    kind: DebugBreakpointKind
    size: int
    condition: str
    ignore_count: int
    disabled: bool
    def __init__(self, address: _Optional[_Union[DebugAddress, _Mapping]] = ..., kind: _Optional[_Union[DebugBreakpointKind, str]] = ..., size: _Optional[int] = ..., condition: _Optional[str] = ..., ignore_count: _Optional[int] = ..., disabled: _Optional[bool] = ...) -> None: ...

class DebugBreakpointUpdate(_message.Message):
    __slots__ = ("id", "condition", "ignore_count", "disabled")
    ID_FIELD_NUMBER: _ClassVar[int]
    CONDITION_FIELD_NUMBER: _ClassVar[int]
    IGNORE_COUNT_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    id: int
    condition: str
    ignore_count: int
    disabled: bool
    def __init__(self, id: _Optional[int] = ..., condition: _Optional[str] = ..., ignore_count: _Optional[int] = ..., disabled: _Optional[bool] = ...) -> None: ...

class DebugBreakpoint(_message.Message):
    __slots__ = ("id", "kind", "location", "size", "inserted", "pending", "error", "hits", "condition", "ignore_count", "disabled", "condition_error")
    ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    INSERTED_FIELD_NUMBER: _ClassVar[int]
    PENDING_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    HITS_FIELD_NUMBER: _ClassVar[int]
    CONDITION_FIELD_NUMBER: _ClassVar[int]
    IGNORE_COUNT_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    CONDITION_ERROR_FIELD_NUMBER: _ClassVar[int]
    id: int
    kind: DebugBreakpointKind
    location: DebugLocation
    size: int
    inserted: bool
    pending: bool
    error: str
    hits: int
    condition: str
    ignore_count: int
    disabled: bool
    condition_error: str
    def __init__(self, id: _Optional[int] = ..., kind: _Optional[_Union[DebugBreakpointKind, str]] = ..., location: _Optional[_Union[DebugLocation, _Mapping]] = ..., size: _Optional[int] = ..., inserted: _Optional[bool] = ..., pending: _Optional[bool] = ..., error: _Optional[str] = ..., hits: _Optional[int] = ..., condition: _Optional[str] = ..., ignore_count: _Optional[int] = ..., disabled: _Optional[bool] = ..., condition_error: _Optional[str] = ...) -> None: ...

class DebugThread(_message.Message):
    __slots__ = ("id", "name", "current", "pc", "core")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    CURRENT_FIELD_NUMBER: _ClassVar[int]
    PC_FIELD_NUMBER: _ClassVar[int]
    CORE_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    current: bool
    pc: DebugLocation
    core: int
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., current: _Optional[bool] = ..., pc: _Optional[_Union[DebugLocation, _Mapping]] = ..., core: _Optional[int] = ...) -> None: ...

class DebugState(_message.Message):
    __slots__ = ("target_state", "pc", "last_stop", "registers", "breakpoints", "thread", "thumb", "steps", "snapshot", "historical", "last_snapshot", "output", "output_size", "mapping", "threads", "machine", "tick", "waiting", "rewindable")
    TARGET_STATE_FIELD_NUMBER: _ClassVar[int]
    PC_FIELD_NUMBER: _ClassVar[int]
    LAST_STOP_FIELD_NUMBER: _ClassVar[int]
    REGISTERS_FIELD_NUMBER: _ClassVar[int]
    BREAKPOINTS_FIELD_NUMBER: _ClassVar[int]
    THREAD_FIELD_NUMBER: _ClassVar[int]
    THUMB_FIELD_NUMBER: _ClassVar[int]
    STEPS_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    HISTORICAL_FIELD_NUMBER: _ClassVar[int]
    LAST_SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_SIZE_FIELD_NUMBER: _ClassVar[int]
    MAPPING_FIELD_NUMBER: _ClassVar[int]
    THREADS_FIELD_NUMBER: _ClassVar[int]
    MACHINE_FIELD_NUMBER: _ClassVar[int]
    TICK_FIELD_NUMBER: _ClassVar[int]
    WAITING_FIELD_NUMBER: _ClassVar[int]
    REWINDABLE_FIELD_NUMBER: _ClassVar[int]
    target_state: DebugTargetState
    pc: DebugLocation
    last_stop: DebugStop
    registers: _containers.RepeatedCompositeFieldContainer[DebugRegisterValue]
    breakpoints: _containers.RepeatedCompositeFieldContainer[DebugBreakpoint]
    thread: str
    thumb: bool
    steps: int
    snapshot: int
    historical: bool
    last_snapshot: int
    output: bytes
    output_size: int
    mapping: DebugAddressMapping
    threads: _containers.RepeatedCompositeFieldContainer[DebugThread]
    machine: bool
    tick: int
    waiting: bool
    rewindable: bool
    def __init__(self, target_state: _Optional[_Union[DebugTargetState, str]] = ..., pc: _Optional[_Union[DebugLocation, _Mapping]] = ..., last_stop: _Optional[_Union[DebugStop, _Mapping]] = ..., registers: _Optional[_Iterable[_Union[DebugRegisterValue, _Mapping]]] = ..., breakpoints: _Optional[_Iterable[_Union[DebugBreakpoint, _Mapping]]] = ..., thread: _Optional[str] = ..., thumb: _Optional[bool] = ..., steps: _Optional[int] = ..., snapshot: _Optional[int] = ..., historical: _Optional[bool] = ..., last_snapshot: _Optional[int] = ..., output: _Optional[bytes] = ..., output_size: _Optional[int] = ..., mapping: _Optional[_Union[DebugAddressMapping, _Mapping]] = ..., threads: _Optional[_Iterable[_Union[DebugThread, _Mapping]]] = ..., machine: _Optional[bool] = ..., tick: _Optional[int] = ..., waiting: _Optional[bool] = ..., rewindable: _Optional[bool] = ...) -> None: ...

class DebugStateOptions(_message.Message):
    __slots__ = ("registers", "all_registers", "output_offset", "include_threads")
    REGISTERS_FIELD_NUMBER: _ClassVar[int]
    ALL_REGISTERS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_OFFSET_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_THREADS_FIELD_NUMBER: _ClassVar[int]
    registers: _containers.RepeatedScalarFieldContainer[str]
    all_registers: bool
    output_offset: int
    include_threads: bool
    def __init__(self, registers: _Optional[_Iterable[str]] = ..., all_registers: _Optional[bool] = ..., output_offset: _Optional[int] = ..., include_threads: _Optional[bool] = ...) -> None: ...

class CreateDebugSessionRequest(_message.Message):
    __slots__ = ("program_id", "emulator", "remote", "launch", "trace", "crash", "breakpoints", "timeline", "slide", "client")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    EMULATOR_FIELD_NUMBER: _ClassVar[int]
    REMOTE_FIELD_NUMBER: _ClassVar[int]
    LAUNCH_FIELD_NUMBER: _ClassVar[int]
    TRACE_FIELD_NUMBER: _ClassVar[int]
    CRASH_FIELD_NUMBER: _ClassVar[int]
    BREAKPOINTS_FIELD_NUMBER: _ClassVar[int]
    TIMELINE_FIELD_NUMBER: _ClassVar[int]
    SLIDE_FIELD_NUMBER: _ClassVar[int]
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    emulator: DebugEmulatorTarget
    remote: DebugRemoteTarget
    launch: DebugLaunchTarget
    trace: DebugTraceTarget
    crash: DebugCrashTarget
    breakpoints: _containers.RepeatedCompositeFieldContainer[DebugBreakpointSpec]
    timeline: DebugTimelineLimits
    slide: int
    client: str
    def __init__(self, program_id: _Optional[str] = ..., emulator: _Optional[_Union[DebugEmulatorTarget, _Mapping]] = ..., remote: _Optional[_Union[DebugRemoteTarget, _Mapping]] = ..., launch: _Optional[_Union[DebugLaunchTarget, _Mapping]] = ..., trace: _Optional[_Union[DebugTraceTarget, _Mapping]] = ..., crash: _Optional[_Union[DebugCrashTarget, _Mapping]] = ..., breakpoints: _Optional[_Iterable[_Union[DebugBreakpointSpec, _Mapping]]] = ..., timeline: _Optional[_Union[DebugTimelineLimits, _Mapping]] = ..., slide: _Optional[int] = ..., client: _Optional[str] = ...) -> None: ...

class CreateDebugSessionResponse(_message.Message):
    __slots__ = ("session_id", "target_kind", "description", "language", "registers", "pc_register", "sp_register", "state", "timeline", "machine", "crash")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    TARGET_KIND_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    REGISTERS_FIELD_NUMBER: _ClassVar[int]
    PC_REGISTER_FIELD_NUMBER: _ClassVar[int]
    SP_REGISTER_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    TIMELINE_FIELD_NUMBER: _ClassVar[int]
    MACHINE_FIELD_NUMBER: _ClassVar[int]
    CRASH_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    target_kind: str
    description: str
    language: str
    registers: _containers.RepeatedCompositeFieldContainer[DebugRegisterInfo]
    pc_register: str
    sp_register: str
    state: DebugState
    timeline: DebugTimelineLimits
    machine: _emulator_pb2.EmulatorMachineInfo
    crash: DebugCrash
    def __init__(self, session_id: _Optional[str] = ..., target_kind: _Optional[str] = ..., description: _Optional[str] = ..., language: _Optional[str] = ..., registers: _Optional[_Iterable[_Union[DebugRegisterInfo, _Mapping]]] = ..., pc_register: _Optional[str] = ..., sp_register: _Optional[str] = ..., state: _Optional[_Union[DebugState, _Mapping]] = ..., timeline: _Optional[_Union[DebugTimelineLimits, _Mapping]] = ..., machine: _Optional[_Union[_emulator_pb2.EmulatorMachineInfo, _Mapping]] = ..., crash: _Optional[_Union[DebugCrash, _Mapping]] = ...) -> None: ...

class CloseDebugSessionRequest(_message.Message):
    __slots__ = ("session_id", "kill")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    KILL_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    kill: bool
    def __init__(self, session_id: _Optional[str] = ..., kill: _Optional[bool] = ...) -> None: ...

class CloseDebugSessionResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListDebugSessionsRequest(_message.Message):
    __slots__ = ("client",)
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    client: str
    def __init__(self, client: _Optional[str] = ...) -> None: ...

class DebugSessionInfo(_message.Message):
    __slots__ = ("session_id", "program_id", "client", "target_kind", "description", "target_state", "last_stop", "snapshots", "idle_ms")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    TARGET_KIND_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TARGET_STATE_FIELD_NUMBER: _ClassVar[int]
    LAST_STOP_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOTS_FIELD_NUMBER: _ClassVar[int]
    IDLE_MS_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    program_id: str
    client: str
    target_kind: str
    description: str
    target_state: DebugTargetState
    last_stop: DebugStop
    snapshots: int
    idle_ms: int
    def __init__(self, session_id: _Optional[str] = ..., program_id: _Optional[str] = ..., client: _Optional[str] = ..., target_kind: _Optional[str] = ..., description: _Optional[str] = ..., target_state: _Optional[_Union[DebugTargetState, str]] = ..., last_stop: _Optional[_Union[DebugStop, _Mapping]] = ..., snapshots: _Optional[int] = ..., idle_ms: _Optional[int] = ...) -> None: ...

class ListDebugSessionsResponse(_message.Message):
    __slots__ = ("sessions",)
    SESSIONS_FIELD_NUMBER: _ClassVar[int]
    sessions: _containers.RepeatedCompositeFieldContainer[DebugSessionInfo]
    def __init__(self, sessions: _Optional[_Iterable[_Union[DebugSessionInfo, _Mapping]]] = ...) -> None: ...

class ResumeDebugSessionRequest(_message.Message):
    __slots__ = ("session_id", "mode", "max_steps", "until", "time_limit_ms", "state")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    MAX_STEPS_FIELD_NUMBER: _ClassVar[int]
    UNTIL_FIELD_NUMBER: _ClassVar[int]
    TIME_LIMIT_MS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    mode: DebugRunMode
    max_steps: int
    until: DebugAddress
    time_limit_ms: int
    state: DebugStateOptions
    def __init__(self, session_id: _Optional[str] = ..., mode: _Optional[_Union[DebugRunMode, str]] = ..., max_steps: _Optional[int] = ..., until: _Optional[_Union[DebugAddress, _Mapping]] = ..., time_limit_ms: _Optional[int] = ..., state: _Optional[_Union[DebugStateOptions, _Mapping]] = ...) -> None: ...

class ResumeDebugSessionResponse(_message.Message):
    __slots__ = ("stop", "state")
    STOP_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    stop: DebugStop
    state: DebugState
    def __init__(self, stop: _Optional[_Union[DebugStop, _Mapping]] = ..., state: _Optional[_Union[DebugState, _Mapping]] = ...) -> None: ...

class WaitDebugSessionRequest(_message.Message):
    __slots__ = ("session_id", "wait_ms", "state")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    WAIT_MS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    wait_ms: int
    state: DebugStateOptions
    def __init__(self, session_id: _Optional[str] = ..., wait_ms: _Optional[int] = ..., state: _Optional[_Union[DebugStateOptions, _Mapping]] = ...) -> None: ...

class WaitDebugSessionResponse(_message.Message):
    __slots__ = ("stop", "state")
    STOP_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    stop: DebugStop
    state: DebugState
    def __init__(self, stop: _Optional[_Union[DebugStop, _Mapping]] = ..., state: _Optional[_Union[DebugState, _Mapping]] = ...) -> None: ...

class InterruptDebugSessionRequest(_message.Message):
    __slots__ = ("session_id",)
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    def __init__(self, session_id: _Optional[str] = ...) -> None: ...

class InterruptDebugSessionResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetDebugStateRequest(_message.Message):
    __slots__ = ("session_id", "state", "snapshot")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    state: DebugStateOptions
    snapshot: int
    def __init__(self, session_id: _Optional[str] = ..., state: _Optional[_Union[DebugStateOptions, _Mapping]] = ..., snapshot: _Optional[int] = ...) -> None: ...

class GetDebugStateResponse(_message.Message):
    __slots__ = ("state",)
    STATE_FIELD_NUMBER: _ClassVar[int]
    state: DebugState
    def __init__(self, state: _Optional[_Union[DebugState, _Mapping]] = ...) -> None: ...

class GetDebugBacktraceRequest(_message.Message):
    __slots__ = ("session_id", "snapshot", "max_frames")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    MAX_FRAMES_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    snapshot: int
    max_frames: int
    def __init__(self, session_id: _Optional[str] = ..., snapshot: _Optional[int] = ..., max_frames: _Optional[int] = ...) -> None: ...

class DebugFrame(_message.Message):
    __slots__ = ("level", "pc", "sp", "cfa", "how", "function", "function_entry", "function_offset", "registers")
    LEVEL_FIELD_NUMBER: _ClassVar[int]
    PC_FIELD_NUMBER: _ClassVar[int]
    SP_FIELD_NUMBER: _ClassVar[int]
    CFA_FIELD_NUMBER: _ClassVar[int]
    HOW_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_ENTRY_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_OFFSET_FIELD_NUMBER: _ClassVar[int]
    REGISTERS_FIELD_NUMBER: _ClassVar[int]
    level: int
    pc: DebugLocation
    sp: int
    cfa: int
    how: str
    function: str
    function_entry: _common_pb2.Address
    function_offset: int
    registers: _containers.RepeatedCompositeFieldContainer[DebugRegisterValue]
    def __init__(self, level: _Optional[int] = ..., pc: _Optional[_Union[DebugLocation, _Mapping]] = ..., sp: _Optional[int] = ..., cfa: _Optional[int] = ..., how: _Optional[str] = ..., function: _Optional[str] = ..., function_entry: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., function_offset: _Optional[int] = ..., registers: _Optional[_Iterable[_Union[DebugRegisterValue, _Mapping]]] = ...) -> None: ...

class GetDebugBacktraceResponse(_message.Message):
    __slots__ = ("frames", "snapshot", "unsupported")
    FRAMES_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    UNSUPPORTED_FIELD_NUMBER: _ClassVar[int]
    frames: _containers.RepeatedCompositeFieldContainer[DebugFrame]
    snapshot: int
    unsupported: str
    def __init__(self, frames: _Optional[_Iterable[_Union[DebugFrame, _Mapping]]] = ..., snapshot: _Optional[int] = ..., unsupported: _Optional[str] = ...) -> None: ...

class EvaluateDebugRequest(_message.Message):
    __slots__ = ("session_id", "snapshot", "frame", "items", "compare_snapshot", "depth")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FRAME_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    COMPARE_SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    DEPTH_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    snapshot: int
    frame: int
    items: _containers.RepeatedCompositeFieldContainer[DebugEvalItem]
    compare_snapshot: int
    depth: int
    def __init__(self, session_id: _Optional[str] = ..., snapshot: _Optional[int] = ..., frame: _Optional[int] = ..., items: _Optional[_Iterable[_Union[DebugEvalItem, _Mapping]]] = ..., compare_snapshot: _Optional[int] = ..., depth: _Optional[int] = ...) -> None: ...

class DebugEvalItem(_message.Message):
    __slots__ = ("expression", "variable", "operand", "frame_function")
    EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    VARIABLE_FIELD_NUMBER: _ClassVar[int]
    OPERAND_FIELD_NUMBER: _ClassVar[int]
    FRAME_FUNCTION_FIELD_NUMBER: _ClassVar[int]
    expression: str
    variable: DebugVariable
    operand: DebugOperand
    frame_function: _common_pb2.Address
    def __init__(self, expression: _Optional[str] = ..., variable: _Optional[_Union[DebugVariable, _Mapping]] = ..., operand: _Optional[_Union[DebugOperand, _Mapping]] = ..., frame_function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ...) -> None: ...

class DebugVariable(_message.Message):
    __slots__ = ("function", "storage", "type", "name", "address")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    STORAGE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    function: _common_pb2.Address
    storage: _containers.RepeatedCompositeFieldContainer[_common_pb2.Varnode]
    type: _decompile_pb2.TypeRef
    name: str
    address: _common_pb2.Address
    def __init__(self, function: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., storage: _Optional[_Iterable[_Union[_common_pb2.Varnode, _Mapping]]] = ..., type: _Optional[_Union[_decompile_pb2.TypeRef, _Mapping]] = ..., name: _Optional[str] = ..., address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ...) -> None: ...

class DebugOperand(_message.Message):
    __slots__ = ("address", "operand")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    OPERAND_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    operand: int
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., operand: _Optional[int] = ...) -> None: ...

class DebugValueChild(_message.Message):
    __slots__ = ("name", "text", "type", "address")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    name: str
    text: str
    type: str
    address: int
    def __init__(self, name: _Optional[str] = ..., text: _Optional[str] = ..., type: _Optional[str] = ..., address: _Optional[int] = ...) -> None: ...

class DebugValue(_message.Message):
    __slots__ = ("text", "type", "hex", "address", "register_name", "program_address", "location", "bytes", "error", "changed", "children", "name")
    TEXT_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    HEX_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    REGISTER_NAME_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    CHANGED_FIELD_NUMBER: _ClassVar[int]
    CHILDREN_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    text: str
    type: str
    hex: str
    address: int
    register_name: str
    program_address: int
    location: str
    bytes: bytes
    error: str
    changed: bool
    children: _containers.RepeatedCompositeFieldContainer[DebugValueChild]
    name: str
    def __init__(self, text: _Optional[str] = ..., type: _Optional[str] = ..., hex: _Optional[str] = ..., address: _Optional[int] = ..., register_name: _Optional[str] = ..., program_address: _Optional[int] = ..., location: _Optional[str] = ..., bytes: _Optional[bytes] = ..., error: _Optional[str] = ..., changed: _Optional[bool] = ..., children: _Optional[_Iterable[_Union[DebugValueChild, _Mapping]]] = ..., name: _Optional[str] = ...) -> None: ...

class EvaluateDebugResponse(_message.Message):
    __slots__ = ("values", "snapshot", "frame", "function", "function_entry")
    VALUES_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FRAME_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_ENTRY_FIELD_NUMBER: _ClassVar[int]
    values: _containers.RepeatedCompositeFieldContainer[DebugValue]
    snapshot: int
    frame: int
    function: str
    function_entry: _common_pb2.Address
    def __init__(self, values: _Optional[_Iterable[_Union[DebugValue, _Mapping]]] = ..., snapshot: _Optional[int] = ..., frame: _Optional[int] = ..., function: _Optional[str] = ..., function_entry: _Optional[_Union[_common_pb2.Address, _Mapping]] = ...) -> None: ...

class DisassembleDebugMemoryRequest(_message.Message):
    __slots__ = ("session_id", "address", "snapshot", "count", "before")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    BEFORE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    address: DebugAddress
    snapshot: int
    count: int
    before: int
    def __init__(self, session_id: _Optional[str] = ..., address: _Optional[_Union[DebugAddress, _Mapping]] = ..., snapshot: _Optional[int] = ..., count: _Optional[int] = ..., before: _Optional[int] = ...) -> None: ...

class DebugInstruction(_message.Message):
    __slots__ = ("location", "bytes", "mnemonic", "operands", "symbol", "target", "target_symbol", "call", "branch", "ret", "pc", "breakpoint", "error")
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    MNEMONIC_FIELD_NUMBER: _ClassVar[int]
    OPERANDS_FIELD_NUMBER: _ClassVar[int]
    SYMBOL_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    TARGET_SYMBOL_FIELD_NUMBER: _ClassVar[int]
    CALL_FIELD_NUMBER: _ClassVar[int]
    BRANCH_FIELD_NUMBER: _ClassVar[int]
    RET_FIELD_NUMBER: _ClassVar[int]
    PC_FIELD_NUMBER: _ClassVar[int]
    BREAKPOINT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    location: DebugLocation
    bytes: bytes
    mnemonic: str
    operands: str
    symbol: str
    target: int
    target_symbol: str
    call: bool
    branch: bool
    ret: bool
    pc: bool
    breakpoint: bool
    error: str
    def __init__(self, location: _Optional[_Union[DebugLocation, _Mapping]] = ..., bytes: _Optional[bytes] = ..., mnemonic: _Optional[str] = ..., operands: _Optional[str] = ..., symbol: _Optional[str] = ..., target: _Optional[int] = ..., target_symbol: _Optional[str] = ..., call: _Optional[bool] = ..., branch: _Optional[bool] = ..., ret: _Optional[bool] = ..., pc: _Optional[bool] = ..., breakpoint: _Optional[bool] = ..., error: _Optional[str] = ...) -> None: ...

class DisassembleDebugMemoryResponse(_message.Message):
    __slots__ = ("instructions", "snapshot", "next", "unreadable")
    INSTRUCTIONS_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    NEXT_FIELD_NUMBER: _ClassVar[int]
    UNREADABLE_FIELD_NUMBER: _ClassVar[int]
    instructions: _containers.RepeatedCompositeFieldContainer[DebugInstruction]
    snapshot: int
    next: int
    unreadable: bool
    def __init__(self, instructions: _Optional[_Iterable[_Union[DebugInstruction, _Mapping]]] = ..., snapshot: _Optional[int] = ..., next: _Optional[int] = ..., unreadable: _Optional[bool] = ...) -> None: ...

class CopyDebugMemoryRequest(_message.Message):
    __slots__ = ("session_id", "address", "length", "region", "mode", "name", "snapshot", "provenance", "permissions", "analyze")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    REGION_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    ANALYZE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    address: DebugAddress
    length: int
    region: bool
    mode: DebugCopyMode
    name: str
    snapshot: int
    provenance: _common_pb2.Provenance
    permissions: str
    analyze: bool
    def __init__(self, session_id: _Optional[str] = ..., address: _Optional[_Union[DebugAddress, _Mapping]] = ..., length: _Optional[int] = ..., region: _Optional[bool] = ..., mode: _Optional[_Union[DebugCopyMode, str]] = ..., name: _Optional[str] = ..., snapshot: _Optional[int] = ..., provenance: _Optional[_Union[_common_pb2.Provenance, _Mapping]] = ..., permissions: _Optional[str] = ..., analyze: _Optional[bool] = ...) -> None: ...

class CopyDebugMemoryResponse(_message.Message):
    __slots__ = ("address", "length", "program_address", "revision", "seqs", "region_id", "block", "program", "changed")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    SEQS_FIELD_NUMBER: _ClassVar[int]
    REGION_ID_FIELD_NUMBER: _ClassVar[int]
    BLOCK_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_FIELD_NUMBER: _ClassVar[int]
    CHANGED_FIELD_NUMBER: _ClassVar[int]
    address: int
    length: int
    program_address: int
    revision: int
    seqs: _containers.RepeatedScalarFieldContainer[int]
    region_id: str
    block: _project_pb2.MemoryBlock
    program: _project_pb2.ProgramInfo
    changed: int
    def __init__(self, address: _Optional[int] = ..., length: _Optional[int] = ..., program_address: _Optional[int] = ..., revision: _Optional[int] = ..., seqs: _Optional[_Iterable[int]] = ..., region_id: _Optional[str] = ..., block: _Optional[_Union[_project_pb2.MemoryBlock, _Mapping]] = ..., program: _Optional[_Union[_project_pb2.ProgramInfo, _Mapping]] = ..., changed: _Optional[int] = ...) -> None: ...

class RewindDebugSessionRequest(_message.Message):
    __slots__ = ("session_id", "snapshot", "step_back", "save_branch_as", "state")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    STEP_BACK_FIELD_NUMBER: _ClassVar[int]
    SAVE_BRANCH_AS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    snapshot: int
    step_back: bool
    save_branch_as: str
    state: DebugStateOptions
    def __init__(self, session_id: _Optional[str] = ..., snapshot: _Optional[int] = ..., step_back: _Optional[bool] = ..., save_branch_as: _Optional[str] = ..., state: _Optional[_Union[DebugStateOptions, _Mapping]] = ...) -> None: ...

class RewindDebugSessionResponse(_message.Message):
    __slots__ = ("stop", "state", "discarded", "saved")
    STOP_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    DISCARDED_FIELD_NUMBER: _ClassVar[int]
    SAVED_FIELD_NUMBER: _ClassVar[int]
    stop: DebugStop
    state: DebugState
    discarded: int
    saved: DebugTraceInfo
    def __init__(self, stop: _Optional[_Union[DebugStop, _Mapping]] = ..., state: _Optional[_Union[DebugState, _Mapping]] = ..., discarded: _Optional[int] = ..., saved: _Optional[_Union[DebugTraceInfo, _Mapping]] = ...) -> None: ...

class DebugHookSpec(_message.Message):
    __slots__ = ("kind", "address", "size", "number", "name", "read", "write")
    KIND_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    NUMBER_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    WRITE_FIELD_NUMBER: _ClassVar[int]
    kind: DebugHookKind
    address: DebugAddress
    size: int
    number: int
    name: str
    read: bool
    write: bool
    def __init__(self, kind: _Optional[_Union[DebugHookKind, str]] = ..., address: _Optional[_Union[DebugAddress, _Mapping]] = ..., size: _Optional[int] = ..., number: _Optional[int] = ..., name: _Optional[str] = ..., read: _Optional[bool] = ..., write: _Optional[bool] = ...) -> None: ...

class DebugHook(_message.Message):
    __slots__ = ("id", "spec", "address", "hits")
    ID_FIELD_NUMBER: _ClassVar[int]
    SPEC_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    HITS_FIELD_NUMBER: _ClassVar[int]
    id: int
    spec: DebugHookSpec
    address: int
    hits: int
    def __init__(self, id: _Optional[int] = ..., spec: _Optional[_Union[DebugHookSpec, _Mapping]] = ..., address: _Optional[int] = ..., hits: _Optional[int] = ...) -> None: ...

class DebugHookEvent(_message.Message):
    __slots__ = ("hook_id", "kind", "pc", "name", "number", "args", "address", "size", "write", "value")
    HOOK_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    PC_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    NUMBER_FIELD_NUMBER: _ClassVar[int]
    ARGS_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    WRITE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    hook_id: int
    kind: DebugHookKind
    pc: int
    name: str
    number: int
    args: _containers.RepeatedScalarFieldContainer[int]
    address: int
    size: int
    write: bool
    value: int
    def __init__(self, hook_id: _Optional[int] = ..., kind: _Optional[_Union[DebugHookKind, str]] = ..., pc: _Optional[int] = ..., name: _Optional[str] = ..., number: _Optional[int] = ..., args: _Optional[_Iterable[int]] = ..., address: _Optional[int] = ..., size: _Optional[int] = ..., write: _Optional[bool] = ..., value: _Optional[int] = ...) -> None: ...

class SetDebugHooksRequest(_message.Message):
    __slots__ = ("session_id", "add", "remove", "clear")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ADD_FIELD_NUMBER: _ClassVar[int]
    REMOVE_FIELD_NUMBER: _ClassVar[int]
    CLEAR_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    add: _containers.RepeatedCompositeFieldContainer[DebugHookSpec]
    remove: _containers.RepeatedScalarFieldContainer[int]
    clear: bool
    def __init__(self, session_id: _Optional[str] = ..., add: _Optional[_Iterable[_Union[DebugHookSpec, _Mapping]]] = ..., remove: _Optional[_Iterable[int]] = ..., clear: _Optional[bool] = ...) -> None: ...

class SetDebugHooksResponse(_message.Message):
    __slots__ = ("hooks",)
    HOOKS_FIELD_NUMBER: _ClassVar[int]
    hooks: _containers.RepeatedCompositeFieldContainer[DebugHook]
    def __init__(self, hooks: _Optional[_Iterable[_Union[DebugHook, _Mapping]]] = ...) -> None: ...

class AnswerDebugHookRequest(_message.Message):
    __slots__ = ("session_id", "hook_id", "value", "state")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    HOOK_ID_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    hook_id: int
    value: int
    state: DebugStateOptions
    def __init__(self, session_id: _Optional[str] = ..., hook_id: _Optional[int] = ..., value: _Optional[int] = ..., state: _Optional[_Union[DebugStateOptions, _Mapping]] = ...) -> None: ...

class AnswerDebugHookResponse(_message.Message):
    __slots__ = ("state",)
    STATE_FIELD_NUMBER: _ClassVar[int]
    state: DebugState
    def __init__(self, state: _Optional[_Union[DebugState, _Mapping]] = ...) -> None: ...

class WriteDebugRegistersRequest(_message.Message):
    __slots__ = ("session_id", "registers", "state")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    REGISTERS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    registers: _containers.RepeatedCompositeFieldContainer[DebugRegisterWrite]
    state: DebugStateOptions
    def __init__(self, session_id: _Optional[str] = ..., registers: _Optional[_Iterable[_Union[DebugRegisterWrite, _Mapping]]] = ..., state: _Optional[_Union[DebugStateOptions, _Mapping]] = ...) -> None: ...

class WriteDebugRegistersResponse(_message.Message):
    __slots__ = ("state",)
    STATE_FIELD_NUMBER: _ClassVar[int]
    state: DebugState
    def __init__(self, state: _Optional[_Union[DebugState, _Mapping]] = ...) -> None: ...

class ReadDebugMemoryRequest(_message.Message):
    __slots__ = ("session_id", "address", "length", "snapshot")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    address: DebugAddress
    length: int
    snapshot: int
    def __init__(self, session_id: _Optional[str] = ..., address: _Optional[_Union[DebugAddress, _Mapping]] = ..., length: _Optional[int] = ..., snapshot: _Optional[int] = ...) -> None: ...

class DebugByteRange(_message.Message):
    __slots__ = ("offset", "length")
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    offset: int
    length: int
    def __init__(self, offset: _Optional[int] = ..., length: _Optional[int] = ...) -> None: ...

class ReadDebugMemoryResponse(_message.Message):
    __slots__ = ("address", "data", "unavailable", "stale", "snapshot")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    UNAVAILABLE_FIELD_NUMBER: _ClassVar[int]
    STALE_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    address: int
    data: bytes
    unavailable: _containers.RepeatedCompositeFieldContainer[DebugByteRange]
    stale: _containers.RepeatedCompositeFieldContainer[DebugByteRange]
    snapshot: int
    def __init__(self, address: _Optional[int] = ..., data: _Optional[bytes] = ..., unavailable: _Optional[_Iterable[_Union[DebugByteRange, _Mapping]]] = ..., stale: _Optional[_Iterable[_Union[DebugByteRange, _Mapping]]] = ..., snapshot: _Optional[int] = ...) -> None: ...

class WriteDebugMemoryRequest(_message.Message):
    __slots__ = ("session_id", "address", "data")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    address: DebugAddress
    data: bytes
    def __init__(self, session_id: _Optional[str] = ..., address: _Optional[_Union[DebugAddress, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class WriteDebugMemoryResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SetDebugBreakpointsRequest(_message.Message):
    __slots__ = ("session_id", "add", "remove_ids", "remove", "clear", "exception_breaks", "set_exception_breaks", "update")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ADD_FIELD_NUMBER: _ClassVar[int]
    REMOVE_IDS_FIELD_NUMBER: _ClassVar[int]
    REMOVE_FIELD_NUMBER: _ClassVar[int]
    CLEAR_FIELD_NUMBER: _ClassVar[int]
    EXCEPTION_BREAKS_FIELD_NUMBER: _ClassVar[int]
    SET_EXCEPTION_BREAKS_FIELD_NUMBER: _ClassVar[int]
    UPDATE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    add: _containers.RepeatedCompositeFieldContainer[DebugBreakpointSpec]
    remove_ids: _containers.RepeatedScalarFieldContainer[int]
    remove: _containers.RepeatedCompositeFieldContainer[DebugAddress]
    clear: bool
    exception_breaks: _containers.RepeatedScalarFieldContainer[str]
    set_exception_breaks: bool
    update: _containers.RepeatedCompositeFieldContainer[DebugBreakpointUpdate]
    def __init__(self, session_id: _Optional[str] = ..., add: _Optional[_Iterable[_Union[DebugBreakpointSpec, _Mapping]]] = ..., remove_ids: _Optional[_Iterable[int]] = ..., remove: _Optional[_Iterable[_Union[DebugAddress, _Mapping]]] = ..., clear: _Optional[bool] = ..., exception_breaks: _Optional[_Iterable[str]] = ..., set_exception_breaks: _Optional[bool] = ..., update: _Optional[_Iterable[_Union[DebugBreakpointUpdate, _Mapping]]] = ...) -> None: ...

class SetDebugBreakpointsResponse(_message.Message):
    __slots__ = ("breakpoints", "exception_breaks")
    BREAKPOINTS_FIELD_NUMBER: _ClassVar[int]
    EXCEPTION_BREAKS_FIELD_NUMBER: _ClassVar[int]
    breakpoints: _containers.RepeatedCompositeFieldContainer[DebugBreakpoint]
    exception_breaks: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, breakpoints: _Optional[_Iterable[_Union[DebugBreakpoint, _Mapping]]] = ..., exception_breaks: _Optional[_Iterable[str]] = ...) -> None: ...

class SelectDebugThreadRequest(_message.Message):
    __slots__ = ("session_id", "thread_id", "state")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    THREAD_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    thread_id: str
    state: DebugStateOptions
    def __init__(self, session_id: _Optional[str] = ..., thread_id: _Optional[str] = ..., state: _Optional[_Union[DebugStateOptions, _Mapping]] = ...) -> None: ...

class SelectDebugThreadResponse(_message.Message):
    __slots__ = ("state",)
    STATE_FIELD_NUMBER: _ClassVar[int]
    state: DebugState
    def __init__(self, state: _Optional[_Union[DebugState, _Mapping]] = ...) -> None: ...

class ListDebugModulesRequest(_message.Message):
    __slots__ = ("session_id",)
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    def __init__(self, session_id: _Optional[str] = ...) -> None: ...

class DebugModule(_message.Message):
    __slots__ = ("name", "path", "base", "size", "load_bias", "main", "program", "program_id", "library_slide")
    NAME_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    BASE_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    LOAD_BIAS_FIELD_NUMBER: _ClassVar[int]
    MAIN_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_SLIDE_FIELD_NUMBER: _ClassVar[int]
    name: str
    path: str
    base: int
    size: int
    load_bias: int
    main: bool
    program: bool
    program_id: str
    library_slide: int
    def __init__(self, name: _Optional[str] = ..., path: _Optional[str] = ..., base: _Optional[int] = ..., size: _Optional[int] = ..., load_bias: _Optional[int] = ..., main: _Optional[bool] = ..., program: _Optional[bool] = ..., program_id: _Optional[str] = ..., library_slide: _Optional[int] = ...) -> None: ...

class DebugMemoryRegion(_message.Message):
    __slots__ = ("start", "size", "permissions", "name", "kind", "offset")
    START_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    start: int
    size: int
    permissions: str
    name: str
    kind: str
    offset: int
    def __init__(self, start: _Optional[int] = ..., size: _Optional[int] = ..., permissions: _Optional[str] = ..., name: _Optional[str] = ..., kind: _Optional[str] = ..., offset: _Optional[int] = ...) -> None: ...

class ListDebugModulesResponse(_message.Message):
    __slots__ = ("modules", "regions", "mapping")
    MODULES_FIELD_NUMBER: _ClassVar[int]
    REGIONS_FIELD_NUMBER: _ClassVar[int]
    MAPPING_FIELD_NUMBER: _ClassVar[int]
    modules: _containers.RepeatedCompositeFieldContainer[DebugModule]
    regions: _containers.RepeatedCompositeFieldContainer[DebugMemoryRegion]
    mapping: DebugAddressMapping
    def __init__(self, modules: _Optional[_Iterable[_Union[DebugModule, _Mapping]]] = ..., regions: _Optional[_Iterable[_Union[DebugMemoryRegion, _Mapping]]] = ..., mapping: _Optional[_Union[DebugAddressMapping, _Mapping]] = ...) -> None: ...

class DebugSnapshot(_message.Message):
    __slots__ = ("index", "kind", "pc", "thread", "steps", "stop", "detail", "text", "changed", "time_us", "gap", "event", "event_number")
    INDEX_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    PC_FIELD_NUMBER: _ClassVar[int]
    THREAD_FIELD_NUMBER: _ClassVar[int]
    STEPS_FIELD_NUMBER: _ClassVar[int]
    STOP_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    CHANGED_FIELD_NUMBER: _ClassVar[int]
    TIME_US_FIELD_NUMBER: _ClassVar[int]
    GAP_FIELD_NUMBER: _ClassVar[int]
    EVENT_FIELD_NUMBER: _ClassVar[int]
    EVENT_NUMBER_FIELD_NUMBER: _ClassVar[int]
    index: int
    kind: DebugSnapshotKind
    pc: DebugLocation
    thread: str
    steps: int
    stop: DebugStopKind
    detail: str
    text: str
    changed: _containers.RepeatedScalarFieldContainer[str]
    time_us: int
    gap: bool
    event: str
    event_number: int
    def __init__(self, index: _Optional[int] = ..., kind: _Optional[_Union[DebugSnapshotKind, str]] = ..., pc: _Optional[_Union[DebugLocation, _Mapping]] = ..., thread: _Optional[str] = ..., steps: _Optional[int] = ..., stop: _Optional[_Union[DebugStopKind, str]] = ..., detail: _Optional[str] = ..., text: _Optional[str] = ..., changed: _Optional[_Iterable[str]] = ..., time_us: _Optional[int] = ..., gap: _Optional[bool] = ..., event: _Optional[str] = ..., event_number: _Optional[int] = ...) -> None: ...

class GetDebugTimelineRequest(_message.Message):
    __slots__ = ("session_id", "from_snapshot", "limit", "stops_only", "events_only")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    FROM_SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    STOPS_ONLY_FIELD_NUMBER: _ClassVar[int]
    EVENTS_ONLY_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    from_snapshot: int
    limit: int
    stops_only: bool
    events_only: bool
    def __init__(self, session_id: _Optional[str] = ..., from_snapshot: _Optional[int] = ..., limit: _Optional[int] = ..., stops_only: _Optional[bool] = ..., events_only: _Optional[bool] = ...) -> None: ...

class GetDebugTimelineResponse(_message.Message):
    __slots__ = ("snapshots", "first", "last", "count", "dropped", "bytes", "complete", "limits")
    SNAPSHOTS_FIELD_NUMBER: _ClassVar[int]
    FIRST_FIELD_NUMBER: _ClassVar[int]
    LAST_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    DROPPED_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    COMPLETE_FIELD_NUMBER: _ClassVar[int]
    LIMITS_FIELD_NUMBER: _ClassVar[int]
    snapshots: _containers.RepeatedCompositeFieldContainer[DebugSnapshot]
    first: int
    last: int
    count: int
    dropped: int
    bytes: int
    complete: bool
    limits: DebugTimelineLimits
    def __init__(self, snapshots: _Optional[_Iterable[_Union[DebugSnapshot, _Mapping]]] = ..., first: _Optional[int] = ..., last: _Optional[int] = ..., count: _Optional[int] = ..., dropped: _Optional[int] = ..., bytes: _Optional[int] = ..., complete: _Optional[bool] = ..., limits: _Optional[_Union[DebugTimelineLimits, _Mapping]] = ...) -> None: ...

class DebugTraceInfo(_message.Message):
    __slots__ = ("name", "program_id", "created_unix", "snapshots", "bytes", "target_kind", "description", "persisted")
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    CREATED_UNIX_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOTS_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    TARGET_KIND_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    PERSISTED_FIELD_NUMBER: _ClassVar[int]
    name: str
    program_id: str
    created_unix: int
    snapshots: int
    bytes: int
    target_kind: str
    description: str
    persisted: bool
    def __init__(self, name: _Optional[str] = ..., program_id: _Optional[str] = ..., created_unix: _Optional[int] = ..., snapshots: _Optional[int] = ..., bytes: _Optional[int] = ..., target_kind: _Optional[str] = ..., description: _Optional[str] = ..., persisted: _Optional[bool] = ...) -> None: ...

class SaveDebugTraceRequest(_message.Message):
    __slots__ = ("session_id", "name")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    name: str
    def __init__(self, session_id: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class SaveDebugTraceResponse(_message.Message):
    __slots__ = ("trace",)
    TRACE_FIELD_NUMBER: _ClassVar[int]
    trace: DebugTraceInfo
    def __init__(self, trace: _Optional[_Union[DebugTraceInfo, _Mapping]] = ...) -> None: ...

class ListDebugTracesRequest(_message.Message):
    __slots__ = ("program_id",)
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    def __init__(self, program_id: _Optional[str] = ...) -> None: ...

class ListDebugTracesResponse(_message.Message):
    __slots__ = ("traces",)
    TRACES_FIELD_NUMBER: _ClassVar[int]
    traces: _containers.RepeatedCompositeFieldContainer[DebugTraceInfo]
    def __init__(self, traces: _Optional[_Iterable[_Union[DebugTraceInfo, _Mapping]]] = ...) -> None: ...

class DeleteDebugTraceRequest(_message.Message):
    __slots__ = ("program_id", "name")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    name: str
    def __init__(self, program_id: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class DeleteDebugTraceResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class WriteDebugInputRequest(_message.Message):
    __slots__ = ("session_id", "data", "peripheral")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    PERIPHERAL_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    data: bytes
    peripheral: str
    def __init__(self, session_id: _Optional[str] = ..., data: _Optional[bytes] = ..., peripheral: _Optional[str] = ...) -> None: ...

class WriteDebugInputResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetDebugMachineRequest(_message.Message):
    __slots__ = ("session_id", "from_event", "limit")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    FROM_EVENT_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    from_event: int
    limit: int
    def __init__(self, session_id: _Optional[str] = ..., from_event: _Optional[int] = ..., limit: _Optional[int] = ...) -> None: ...

class GetDebugMachineResponse(_message.Message):
    __slots__ = ("state", "events", "first_event", "event_count")
    STATE_FIELD_NUMBER: _ClassVar[int]
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    FIRST_EVENT_FIELD_NUMBER: _ClassVar[int]
    EVENT_COUNT_FIELD_NUMBER: _ClassVar[int]
    state: _emulator_pb2.EmulatorMachineState
    events: _containers.RepeatedCompositeFieldContainer[_emulator_pb2.EmulatorException]
    first_event: int
    event_count: int
    def __init__(self, state: _Optional[_Union[_emulator_pb2.EmulatorMachineState, _Mapping]] = ..., events: _Optional[_Iterable[_Union[_emulator_pb2.EmulatorException, _Mapping]]] = ..., first_event: _Optional[int] = ..., event_count: _Optional[int] = ...) -> None: ...

class DebugCrashThread(_message.Message):
    __slots__ = ("id", "name", "crashed", "pc", "sp", "where")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    CRASHED_FIELD_NUMBER: _ClassVar[int]
    PC_FIELD_NUMBER: _ClassVar[int]
    SP_FIELD_NUMBER: _ClassVar[int]
    WHERE_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    crashed: bool
    pc: DebugLocation
    sp: int
    where: str
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., crashed: _Optional[bool] = ..., pc: _Optional[_Union[DebugLocation, _Mapping]] = ..., sp: _Optional[int] = ..., where: _Optional[str] = ...) -> None: ...

class DebugCrashModule(_message.Message):
    __slots__ = ("name", "path", "base", "size", "main", "program_id", "version", "timestamp", "pdb_name", "pdb_guid", "build_id")
    NAME_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    BASE_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    MAIN_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    PDB_NAME_FIELD_NUMBER: _ClassVar[int]
    PDB_GUID_FIELD_NUMBER: _ClassVar[int]
    BUILD_ID_FIELD_NUMBER: _ClassVar[int]
    name: str
    path: str
    base: int
    size: int
    main: bool
    program_id: str
    version: str
    timestamp: int
    pdb_name: str
    pdb_guid: str
    build_id: str
    def __init__(self, name: _Optional[str] = ..., path: _Optional[str] = ..., base: _Optional[int] = ..., size: _Optional[int] = ..., main: _Optional[bool] = ..., program_id: _Optional[str] = ..., version: _Optional[str] = ..., timestamp: _Optional[int] = ..., pdb_name: _Optional[str] = ..., pdb_guid: _Optional[str] = ..., build_id: _Optional[str] = ...) -> None: ...

class DebugCrash(_message.Message):
    __slots__ = ("format", "arch", "reason", "signal", "signal_name", "signal_code", "code_name", "exception_code", "exception_name", "access", "fault_address", "crashed_thread", "pc", "module", "module_offset", "function", "instruction", "instruction_bytes", "backtrace", "threads", "modules", "pid", "command", "args", "os", "cpu", "segments", "dumped_bytes", "main_program_id", "summary", "comments", "warnings")
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    SIGNAL_FIELD_NUMBER: _ClassVar[int]
    SIGNAL_NAME_FIELD_NUMBER: _ClassVar[int]
    SIGNAL_CODE_FIELD_NUMBER: _ClassVar[int]
    CODE_NAME_FIELD_NUMBER: _ClassVar[int]
    EXCEPTION_CODE_FIELD_NUMBER: _ClassVar[int]
    EXCEPTION_NAME_FIELD_NUMBER: _ClassVar[int]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    FAULT_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    CRASHED_THREAD_FIELD_NUMBER: _ClassVar[int]
    PC_FIELD_NUMBER: _ClassVar[int]
    MODULE_FIELD_NUMBER: _ClassVar[int]
    MODULE_OFFSET_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    INSTRUCTION_FIELD_NUMBER: _ClassVar[int]
    INSTRUCTION_BYTES_FIELD_NUMBER: _ClassVar[int]
    BACKTRACE_FIELD_NUMBER: _ClassVar[int]
    THREADS_FIELD_NUMBER: _ClassVar[int]
    MODULES_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    ARGS_FIELD_NUMBER: _ClassVar[int]
    OS_FIELD_NUMBER: _ClassVar[int]
    CPU_FIELD_NUMBER: _ClassVar[int]
    SEGMENTS_FIELD_NUMBER: _ClassVar[int]
    DUMPED_BYTES_FIELD_NUMBER: _ClassVar[int]
    MAIN_PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    SUMMARY_FIELD_NUMBER: _ClassVar[int]
    COMMENTS_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    format: str
    arch: str
    reason: str
    signal: int
    signal_name: str
    signal_code: int
    code_name: str
    exception_code: int
    exception_name: str
    access: str
    fault_address: int
    crashed_thread: str
    pc: DebugLocation
    module: str
    module_offset: int
    function: str
    instruction: str
    instruction_bytes: bytes
    backtrace: _containers.RepeatedCompositeFieldContainer[DebugFrame]
    threads: _containers.RepeatedCompositeFieldContainer[DebugCrashThread]
    modules: _containers.RepeatedCompositeFieldContainer[DebugCrashModule]
    pid: int
    command: str
    args: str
    os: str
    cpu: str
    segments: int
    dumped_bytes: int
    main_program_id: str
    summary: str
    comments: _containers.RepeatedScalarFieldContainer[str]
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, format: _Optional[str] = ..., arch: _Optional[str] = ..., reason: _Optional[str] = ..., signal: _Optional[int] = ..., signal_name: _Optional[str] = ..., signal_code: _Optional[int] = ..., code_name: _Optional[str] = ..., exception_code: _Optional[int] = ..., exception_name: _Optional[str] = ..., access: _Optional[str] = ..., fault_address: _Optional[int] = ..., crashed_thread: _Optional[str] = ..., pc: _Optional[_Union[DebugLocation, _Mapping]] = ..., module: _Optional[str] = ..., module_offset: _Optional[int] = ..., function: _Optional[str] = ..., instruction: _Optional[str] = ..., instruction_bytes: _Optional[bytes] = ..., backtrace: _Optional[_Iterable[_Union[DebugFrame, _Mapping]]] = ..., threads: _Optional[_Iterable[_Union[DebugCrashThread, _Mapping]]] = ..., modules: _Optional[_Iterable[_Union[DebugCrashModule, _Mapping]]] = ..., pid: _Optional[int] = ..., command: _Optional[str] = ..., args: _Optional[str] = ..., os: _Optional[str] = ..., cpu: _Optional[str] = ..., segments: _Optional[int] = ..., dumped_bytes: _Optional[int] = ..., main_program_id: _Optional[str] = ..., summary: _Optional[str] = ..., comments: _Optional[_Iterable[str]] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class GetDebugCrashRequest(_message.Message):
    __slots__ = ("session_id", "max_frames")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    MAX_FRAMES_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    max_frames: int
    def __init__(self, session_id: _Optional[str] = ..., max_frames: _Optional[int] = ...) -> None: ...

class GetDebugCrashResponse(_message.Message):
    __slots__ = ("crash",)
    CRASH_FIELD_NUMBER: _ClassVar[int]
    crash: DebugCrash
    def __init__(self, crash: _Optional[_Union[DebugCrash, _Mapping]] = ...) -> None: ...
