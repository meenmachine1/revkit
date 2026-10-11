from revkit.v1 import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ScriptLibrary(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SCRIPT_LIBRARY_UNSPECIFIED: _ClassVar[ScriptLibrary]
    SCRIPT_LIBRARY_SHIPPED: _ClassVar[ScriptLibrary]
    SCRIPT_LIBRARY_USER: _ClassVar[ScriptLibrary]
    SCRIPT_LIBRARY_PROJECT: _ClassVar[ScriptLibrary]
SCRIPT_LIBRARY_UNSPECIFIED: ScriptLibrary
SCRIPT_LIBRARY_SHIPPED: ScriptLibrary
SCRIPT_LIBRARY_USER: ScriptLibrary
SCRIPT_LIBRARY_PROJECT: ScriptLibrary

class ScriptArg(_message.Message):
    __slots__ = ("name", "type", "has_default", "default_value", "description", "choices")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    HAS_DEFAULT_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_VALUE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    CHOICES_FIELD_NUMBER: _ClassVar[int]
    name: str
    type: str
    has_default: bool
    default_value: str
    description: str
    choices: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, name: _Optional[str] = ..., type: _Optional[str] = ..., has_default: _Optional[bool] = ..., default_value: _Optional[str] = ..., description: _Optional[str] = ..., choices: _Optional[_Iterable[str]] = ...) -> None: ...

class ScriptInfo(_message.Message):
    __slots__ = ("script_id", "library", "project_id", "file_name", "name", "category", "description", "menupath", "keybinding", "context", "args", "sha256", "trusted", "writable", "errors", "modified_unix", "size")
    SCRIPT_ID_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    FILE_NAME_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    MENUPATH_FIELD_NUMBER: _ClassVar[int]
    KEYBINDING_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    ARGS_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    TRUSTED_FIELD_NUMBER: _ClassVar[int]
    WRITABLE_FIELD_NUMBER: _ClassVar[int]
    ERRORS_FIELD_NUMBER: _ClassVar[int]
    MODIFIED_UNIX_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    script_id: str
    library: ScriptLibrary
    project_id: str
    file_name: str
    name: str
    category: str
    description: str
    menupath: str
    keybinding: str
    context: str
    args: _containers.RepeatedCompositeFieldContainer[ScriptArg]
    sha256: str
    trusted: bool
    writable: bool
    errors: _containers.RepeatedScalarFieldContainer[str]
    modified_unix: int
    size: int
    def __init__(self, script_id: _Optional[str] = ..., library: _Optional[_Union[ScriptLibrary, str]] = ..., project_id: _Optional[str] = ..., file_name: _Optional[str] = ..., name: _Optional[str] = ..., category: _Optional[str] = ..., description: _Optional[str] = ..., menupath: _Optional[str] = ..., keybinding: _Optional[str] = ..., context: _Optional[str] = ..., args: _Optional[_Iterable[_Union[ScriptArg, _Mapping]]] = ..., sha256: _Optional[str] = ..., trusted: _Optional[bool] = ..., writable: _Optional[bool] = ..., errors: _Optional[_Iterable[str]] = ..., modified_unix: _Optional[int] = ..., size: _Optional[int] = ...) -> None: ...

class ListScriptsRequest(_message.Message):
    __slots__ = ("project_id",)
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    def __init__(self, project_id: _Optional[str] = ...) -> None: ...

class ListScriptsResponse(_message.Message):
    __slots__ = ("scripts", "host_enabled", "host_disabled_reason", "python", "python_problem")
    SCRIPTS_FIELD_NUMBER: _ClassVar[int]
    HOST_ENABLED_FIELD_NUMBER: _ClassVar[int]
    HOST_DISABLED_REASON_FIELD_NUMBER: _ClassVar[int]
    PYTHON_FIELD_NUMBER: _ClassVar[int]
    PYTHON_PROBLEM_FIELD_NUMBER: _ClassVar[int]
    scripts: _containers.RepeatedCompositeFieldContainer[ScriptInfo]
    host_enabled: bool
    host_disabled_reason: str
    python: str
    python_problem: str
    def __init__(self, scripts: _Optional[_Iterable[_Union[ScriptInfo, _Mapping]]] = ..., host_enabled: _Optional[bool] = ..., host_disabled_reason: _Optional[str] = ..., python: _Optional[str] = ..., python_problem: _Optional[str] = ...) -> None: ...

class GetScriptRequest(_message.Message):
    __slots__ = ("script_id",)
    SCRIPT_ID_FIELD_NUMBER: _ClassVar[int]
    script_id: str
    def __init__(self, script_id: _Optional[str] = ...) -> None: ...

class GetScriptResponse(_message.Message):
    __slots__ = ("script", "source")
    SCRIPT_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    script: ScriptInfo
    source: str
    def __init__(self, script: _Optional[_Union[ScriptInfo, _Mapping]] = ..., source: _Optional[str] = ...) -> None: ...

class ScriptContext(_message.Message):
    __slots__ = ("address", "selection")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SELECTION_FIELD_NUMBER: _ClassVar[int]
    address: _common_pb2.Address
    selection: _common_pb2.AddressRange
    def __init__(self, address: _Optional[_Union[_common_pb2.Address, _Mapping]] = ..., selection: _Optional[_Union[_common_pb2.AddressRange, _Mapping]] = ...) -> None: ...

class RunScriptRequest(_message.Message):
    __slots__ = ("script_id", "program_id", "args", "context", "confirm_sha256", "reason", "interactive", "input", "ghidra_names")
    class ArgsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    SCRIPT_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    ARGS_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    CONFIRM_SHA256_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    INTERACTIVE_FIELD_NUMBER: _ClassVar[int]
    INPUT_FIELD_NUMBER: _ClassVar[int]
    GHIDRA_NAMES_FIELD_NUMBER: _ClassVar[int]
    script_id: str
    program_id: str
    args: _containers.ScalarMap[str, str]
    context: ScriptContext
    confirm_sha256: str
    reason: str
    interactive: bool
    input: str
    ghidra_names: bool
    def __init__(self, script_id: _Optional[str] = ..., program_id: _Optional[str] = ..., args: _Optional[_Mapping[str, str]] = ..., context: _Optional[_Union[ScriptContext, _Mapping]] = ..., confirm_sha256: _Optional[str] = ..., reason: _Optional[str] = ..., interactive: _Optional[bool] = ..., input: _Optional[str] = ..., ghidra_names: _Optional[bool] = ...) -> None: ...

class ScriptStarted(_message.Message):
    __slots__ = ("run_id", "script", "program_id", "started_at_ms", "console_started", "history", "read_only", "python_version", "completion_engine")
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    SCRIPT_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    STARTED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    CONSOLE_STARTED_FIELD_NUMBER: _ClassVar[int]
    HISTORY_FIELD_NUMBER: _ClassVar[int]
    READ_ONLY_FIELD_NUMBER: _ClassVar[int]
    PYTHON_VERSION_FIELD_NUMBER: _ClassVar[int]
    COMPLETION_ENGINE_FIELD_NUMBER: _ClassVar[int]
    run_id: str
    script: ScriptInfo
    program_id: str
    started_at_ms: int
    console_started: bool
    history: _containers.RepeatedScalarFieldContainer[str]
    read_only: bool
    python_version: str
    completion_engine: str
    def __init__(self, run_id: _Optional[str] = ..., script: _Optional[_Union[ScriptInfo, _Mapping]] = ..., program_id: _Optional[str] = ..., started_at_ms: _Optional[int] = ..., console_started: _Optional[bool] = ..., history: _Optional[_Iterable[str]] = ..., read_only: _Optional[bool] = ..., python_version: _Optional[str] = ..., completion_engine: _Optional[str] = ...) -> None: ...

class ScriptOutput(_message.Message):
    __slots__ = ("stream", "text")
    STREAM_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    stream: str
    text: str
    def __init__(self, stream: _Optional[str] = ..., text: _Optional[str] = ...) -> None: ...

class ScriptProgress(_message.Message):
    __slots__ = ("current", "maximum", "message")
    CURRENT_FIELD_NUMBER: _ClassVar[int]
    MAXIMUM_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    current: int
    maximum: int
    message: str
    def __init__(self, current: _Optional[int] = ..., maximum: _Optional[int] = ..., message: _Optional[str] = ...) -> None: ...

class ScriptPrompt(_message.Message):
    __slots__ = ("prompt_id", "kind", "name", "message", "has_default", "default_value", "choices")
    PROMPT_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    HAS_DEFAULT_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_VALUE_FIELD_NUMBER: _ClassVar[int]
    CHOICES_FIELD_NUMBER: _ClassVar[int]
    prompt_id: int
    kind: str
    name: str
    message: str
    has_default: bool
    default_value: str
    choices: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, prompt_id: _Optional[int] = ..., kind: _Optional[str] = ..., name: _Optional[str] = ..., message: _Optional[str] = ..., has_default: _Optional[bool] = ..., default_value: _Optional[str] = ..., choices: _Optional[_Iterable[str]] = ...) -> None: ...

class ScriptResult(_message.Message):
    __slots__ = ("status", "revisions", "seqs", "discarded", "seconds", "exit_code")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    REVISIONS_FIELD_NUMBER: _ClassVar[int]
    SEQS_FIELD_NUMBER: _ClassVar[int]
    DISCARDED_FIELD_NUMBER: _ClassVar[int]
    SECONDS_FIELD_NUMBER: _ClassVar[int]
    EXIT_CODE_FIELD_NUMBER: _ClassVar[int]
    status: str
    revisions: _containers.RepeatedScalarFieldContainer[int]
    seqs: _containers.RepeatedScalarFieldContainer[int]
    discarded: int
    seconds: float
    exit_code: int
    def __init__(self, status: _Optional[str] = ..., revisions: _Optional[_Iterable[int]] = ..., seqs: _Optional[_Iterable[int]] = ..., discarded: _Optional[int] = ..., seconds: _Optional[float] = ..., exit_code: _Optional[int] = ...) -> None: ...

class ScriptError(_message.Message):
    __slots__ = ("result", "message", "error_type", "traceback", "script_id", "line")
    RESULT_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    ERROR_TYPE_FIELD_NUMBER: _ClassVar[int]
    TRACEBACK_FIELD_NUMBER: _ClassVar[int]
    SCRIPT_ID_FIELD_NUMBER: _ClassVar[int]
    LINE_FIELD_NUMBER: _ClassVar[int]
    result: ScriptResult
    message: str
    error_type: str
    traceback: str
    script_id: str
    line: int
    def __init__(self, result: _Optional[_Union[ScriptResult, _Mapping]] = ..., message: _Optional[str] = ..., error_type: _Optional[str] = ..., traceback: _Optional[str] = ..., script_id: _Optional[str] = ..., line: _Optional[int] = ...) -> None: ...

class ScriptTrustRequired(_message.Message):
    __slots__ = ("script", "source", "reason", "previous_sha256")
    SCRIPT_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_SHA256_FIELD_NUMBER: _ClassVar[int]
    script: ScriptInfo
    source: str
    reason: str
    previous_sha256: str
    def __init__(self, script: _Optional[_Union[ScriptInfo, _Mapping]] = ..., source: _Optional[str] = ..., reason: _Optional[str] = ..., previous_sha256: _Optional[str] = ...) -> None: ...

class ConsoleResult(_message.Message):
    __slots__ = ("more", "status", "revisions", "seqs", "discarded", "seconds", "error")
    MORE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    REVISIONS_FIELD_NUMBER: _ClassVar[int]
    SEQS_FIELD_NUMBER: _ClassVar[int]
    DISCARDED_FIELD_NUMBER: _ClassVar[int]
    SECONDS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    more: bool
    status: str
    revisions: _containers.RepeatedScalarFieldContainer[int]
    seqs: _containers.RepeatedScalarFieldContainer[int]
    discarded: int
    seconds: float
    error: str
    def __init__(self, more: _Optional[bool] = ..., status: _Optional[str] = ..., revisions: _Optional[_Iterable[int]] = ..., seqs: _Optional[_Iterable[int]] = ..., discarded: _Optional[int] = ..., seconds: _Optional[float] = ..., error: _Optional[str] = ...) -> None: ...

class RunScriptResponse(_message.Message):
    __slots__ = ("run_id", "started", "output", "progress", "prompt", "result", "error", "trust_required", "console_result")
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    STARTED_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    PROMPT_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    TRUST_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    CONSOLE_RESULT_FIELD_NUMBER: _ClassVar[int]
    run_id: str
    started: ScriptStarted
    output: ScriptOutput
    progress: ScriptProgress
    prompt: ScriptPrompt
    result: ScriptResult
    error: ScriptError
    trust_required: ScriptTrustRequired
    console_result: ConsoleResult
    def __init__(self, run_id: _Optional[str] = ..., started: _Optional[_Union[ScriptStarted, _Mapping]] = ..., output: _Optional[_Union[ScriptOutput, _Mapping]] = ..., progress: _Optional[_Union[ScriptProgress, _Mapping]] = ..., prompt: _Optional[_Union[ScriptPrompt, _Mapping]] = ..., result: _Optional[_Union[ScriptResult, _Mapping]] = ..., error: _Optional[_Union[ScriptError, _Mapping]] = ..., trust_required: _Optional[_Union[ScriptTrustRequired, _Mapping]] = ..., console_result: _Optional[_Union[ConsoleResult, _Mapping]] = ...) -> None: ...

class AnswerPromptRequest(_message.Message):
    __slots__ = ("run_id", "prompt_id", "value", "values", "cancelled")
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    PROMPT_ID_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    CANCELLED_FIELD_NUMBER: _ClassVar[int]
    run_id: str
    prompt_id: int
    value: str
    values: _containers.RepeatedScalarFieldContainer[str]
    cancelled: bool
    def __init__(self, run_id: _Optional[str] = ..., prompt_id: _Optional[int] = ..., value: _Optional[str] = ..., values: _Optional[_Iterable[str]] = ..., cancelled: _Optional[bool] = ...) -> None: ...

class AnswerPromptResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class CancelScriptRequest(_message.Message):
    __slots__ = ("run_id", "interrupt")
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    INTERRUPT_FIELD_NUMBER: _ClassVar[int]
    run_id: str
    interrupt: bool
    def __init__(self, run_id: _Optional[str] = ..., interrupt: _Optional[bool] = ...) -> None: ...

class CancelScriptResponse(_message.Message):
    __slots__ = ("was_running",)
    WAS_RUNNING_FIELD_NUMBER: _ClassVar[int]
    was_running: bool
    def __init__(self, was_running: _Optional[bool] = ...) -> None: ...

class UpdateContextRequest(_message.Message):
    __slots__ = ("run_id", "context")
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    run_id: str
    context: ScriptContext
    def __init__(self, run_id: _Optional[str] = ..., context: _Optional[_Union[ScriptContext, _Mapping]] = ...) -> None: ...

class UpdateContextResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SaveScriptRequest(_message.Message):
    __slots__ = ("library", "project_id", "file_name", "source", "expected_sha256")
    LIBRARY_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    FILE_NAME_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_SHA256_FIELD_NUMBER: _ClassVar[int]
    library: ScriptLibrary
    project_id: str
    file_name: str
    source: str
    expected_sha256: str
    def __init__(self, library: _Optional[_Union[ScriptLibrary, str]] = ..., project_id: _Optional[str] = ..., file_name: _Optional[str] = ..., source: _Optional[str] = ..., expected_sha256: _Optional[str] = ...) -> None: ...

class SaveScriptResponse(_message.Message):
    __slots__ = ("script",)
    SCRIPT_FIELD_NUMBER: _ClassVar[int]
    script: ScriptInfo
    def __init__(self, script: _Optional[_Union[ScriptInfo, _Mapping]] = ...) -> None: ...

class ScriptRun(_message.Message):
    __slots__ = ("run_id", "script_id", "name", "version", "program_id", "caller", "status", "started_at_ms", "seconds", "revisions", "assertions", "error")
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    SCRIPT_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    CALLER_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    STARTED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    SECONDS_FIELD_NUMBER: _ClassVar[int]
    REVISIONS_FIELD_NUMBER: _ClassVar[int]
    ASSERTIONS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    run_id: str
    script_id: str
    name: str
    version: str
    program_id: str
    caller: str
    status: str
    started_at_ms: int
    seconds: float
    revisions: _containers.RepeatedScalarFieldContainer[int]
    assertions: int
    error: str
    def __init__(self, run_id: _Optional[str] = ..., script_id: _Optional[str] = ..., name: _Optional[str] = ..., version: _Optional[str] = ..., program_id: _Optional[str] = ..., caller: _Optional[str] = ..., status: _Optional[str] = ..., started_at_ms: _Optional[int] = ..., seconds: _Optional[float] = ..., revisions: _Optional[_Iterable[int]] = ..., assertions: _Optional[int] = ..., error: _Optional[str] = ...) -> None: ...

class ListScriptRunsRequest(_message.Message):
    __slots__ = ("program_id", "limit")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    limit: int
    def __init__(self, program_id: _Optional[str] = ..., limit: _Optional[int] = ...) -> None: ...

class ListScriptRunsResponse(_message.Message):
    __slots__ = ("runs",)
    RUNS_FIELD_NUMBER: _ClassVar[int]
    runs: _containers.RepeatedCompositeFieldContainer[ScriptRun]
    def __init__(self, runs: _Optional[_Iterable[_Union[ScriptRun, _Mapping]]] = ...) -> None: ...

class SetupScriptPythonRequest(_message.Message):
    __slots__ = ("force",)
    FORCE_FIELD_NUMBER: _ClassVar[int]
    force: bool
    def __init__(self, force: _Optional[bool] = ...) -> None: ...

class SetupScriptPythonResponse(_message.Message):
    __slots__ = ("output", "result")
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    output: str
    result: SetupScriptPythonResult
    def __init__(self, output: _Optional[str] = ..., result: _Optional[_Union[SetupScriptPythonResult, _Mapping]] = ...) -> None: ...

class SetupScriptPythonResult(_message.Message):
    __slots__ = ("ok", "python", "error", "directory")
    OK_FIELD_NUMBER: _ClassVar[int]
    PYTHON_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    DIRECTORY_FIELD_NUMBER: _ClassVar[int]
    ok: bool
    python: str
    error: str
    directory: str
    def __init__(self, ok: _Optional[bool] = ..., python: _Optional[str] = ..., error: _Optional[str] = ..., directory: _Optional[str] = ...) -> None: ...

class CompleteConsoleRequest(_message.Message):
    __slots__ = ("program_id", "text", "limit")
    PROGRAM_ID_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    program_id: str
    text: str
    limit: int
    def __init__(self, program_id: _Optional[str] = ..., text: _Optional[str] = ..., limit: _Optional[int] = ...) -> None: ...

class ConsoleCompletion(_message.Message):
    __slots__ = ("text", "kind", "signature", "doc")
    TEXT_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    DOC_FIELD_NUMBER: _ClassVar[int]
    text: str
    kind: str
    signature: str
    doc: str
    def __init__(self, text: _Optional[str] = ..., kind: _Optional[str] = ..., signature: _Optional[str] = ..., doc: _Optional[str] = ...) -> None: ...

class CompleteConsoleResponse(_message.Message):
    __slots__ = ("completions", "prefix_length", "engine")
    COMPLETIONS_FIELD_NUMBER: _ClassVar[int]
    PREFIX_LENGTH_FIELD_NUMBER: _ClassVar[int]
    ENGINE_FIELD_NUMBER: _ClassVar[int]
    completions: _containers.RepeatedCompositeFieldContainer[ConsoleCompletion]
    prefix_length: int
    engine: str
    def __init__(self, completions: _Optional[_Iterable[_Union[ConsoleCompletion, _Mapping]]] = ..., prefix_length: _Optional[int] = ..., engine: _Optional[str] = ...) -> None: ...
