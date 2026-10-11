"""``Unsupported``, and the table of Ghidra APIs the shim refuses with the
revkit way to do the same (docs/scripting.md, "Running Ghidra scripts")."""

from __future__ import annotations


class Unsupported(NotImplementedError, AttributeError):
    """A Ghidra API the compat shim doesn't provide. The message names the API
    and what to use instead: ``getBookmarkManager: revkit has notes:
    note(addr, text, tag)``. Calling a missing method raises it; it is also
    an AttributeError, so ``hasattr``/``getattr(x, name, default)`` probes
    say "no" as Python expects."""

    def __init__(self, api: str, replacement: str = ""):
        self.api = api
        self.replacement = replacement or replacement_for(api)
        super().__init__(f"{api}: {self.replacement}")


# What a script uses instead, per Ghidra API (or family: the key is matched
# exactly first, then by its last component, then by its class). Every entry
# is listed in docs/scripting.md; tests/test_ghidra_compat.py checks that.
UNSUPPORTED: dict[str, str] = {
    # The tool, its services and its windows.
    "state.getTool": "revkit scripts run without a Ghidra tool; the UI's cursor and selection are currentAddress and currentSelection",
    "getState().getTool": "revkit scripts run without a Ghidra tool; the UI's cursor and selection are currentAddress and currentSelection",
    "getService": "no tool services in revkit scripts; the daemon's API is current_program and client (revkit.script)",
    "createTableChooserDialog": "no table dialogs yet; print rows, or write JSON/CSV (export_functions starter script)",
    "TableChooserDialog": "no table dialogs yet; print rows, or write JSON/CSV (export_functions starter script)",
    "show": "no result tables yet; print the addresses",
    "createSelection": "no tool selection to set; print or return the addresses",
    "setCurrentSelection": "no tool selection to set; print or return the addresses",
    "createHighlight": "no highlights; print the addresses",
    "setCurrentHighlight": "no highlights; print the addresses",
    "setBackgroundColor": "no listing colors; use note(addr, text, tag) to mark places",
    "clearBackgroundColor": "no listing colors; use note(addr, text, tag) to mark places",
    "openProgram": "the run has one program; revkit.Client(...).program(id) opens others",
    "closeProgram": "the run has one program; revkit.Client(...).program(id) opens others",
    "importFile": "import with rk-script --import FILE, or revkit.Client.import_program",
    "importFileAsBinary": "import with revkit.Client.import_program(..., options=raw)",
    "saveProgram": "revkit saves every edit as it commits; nothing to save",
    "askProgram": "the run has one program; rk-script --program ID picks it",
    "askDomainFile": "no Ghidra project files; rk-script --program ID picks the program",
    "askProjectFolder": "no Ghidra project folders; revkit projects are directories (Client.projects())",
    "askLanguage": "the language comes with the program (currentProgram.getLanguage())",
    "askValues": "ask each value: askString/askInt/askChoice, or revkit.script.ask_values({...})",
    "askPassword": "read secrets from the environment (os.environ)",
    "runScript": "chain scripts with rk-script --pre P.py / --post Q.py, or import a Python module",
    "runCommand": "run the command's revkit equivalent (rename, comment, set_function, define_data, ...)",
    "analyzeAll": "current_program.analyze() (the daemon's analysis jobs), or wait for analysis_status().idle",
    "analyzeChanges": "current_program.analyze() (the daemon's analysis jobs)",
    "setAnalysisOption": "analysis options are rk-daemon flags and AnalysisService requests, not per-program options",
    "getCurrentAnalysisOptionsAndValues": "analysis options are rk-daemon flags and AnalysisService requests",
    "resetAnalysisOptions": "analysis options are rk-daemon flags and AnalysisService requests",
    "openDataTypeArchive": "parse a C header instead: current_program.parse_c / define_type(c_source)",
    "getProgramFile": "the imported file is on the daemon's host; current_program.export() writes it with patches",
    "goToHome": "no tool navigation in revkit scripts",
    "setToolStatusMessage": "print the message",
    # Program model families revkit models differently.
    "getBookmarkManager": "revkit has notes: note(addr, text, tag) and current_program.assertions()",
    "createBookmark": "revkit has notes: note(addr, text, tag)",
    "getBookmarks": "revkit has notes: current_program.assertions() (note bodies)",
    "removeBookmark": "retract the note's assertion (current_program.retract(seq))",
    "addExternalReference": "revkit has no external references; imports are thunks named after their targets",
    "addStackReference": "revkit has no stack references; locals come from the decompiler",
    "addRegisterReference": "revkit has no register references",
    "addOffsetMemReference": "revkit has memory references only: addMemoryReference(from, to, type, source, opIndex)",
    "createExternalReference": "revkit has no external references; imports are thunks named after their targets",
    "createStackReference": "revkit has no stack references; locals come from the decompiler",
    "addEntryPoint": "entry points come from the loader; set_function(addr) makes a function there",
    "removeEntryPoint": "entry points come from the loader",
    "createMemoryBlock": "current_program.add_memory_region(name, start, size, ...)",
    "removeMemoryBlock": "current_program.remove_memory_region(region)",
    "Memory.split": "the memory map's regions: current_program.add_memory_region / update_memory_region",
    "Memory.join": "the memory map's regions: current_program.update_memory_region",
    "Memory.createInitializedBlock": "current_program.add_memory_region(name, start, size, initialized=True)",
    "Memory.createUninitializedBlock": "current_program.add_memory_region(name, start, size)",
    "MemoryBlock.setName": "current_program.update_memory_region(start, name=...)",
    "MemoryBlock.setRead": "current_program.update_memory_region(start, perms='r--')",
    "MemoryBlock.setWrite": "current_program.update_memory_region(start, perms='rw-')",
    "MemoryBlock.setExecute": "current_program.update_memory_region(start, perms='r-x')",
    "MemoryBlock.setVolatile": "current_program.update_memory_region(start, volatile=True)",
    "MemoryBlock.getSourceInfos": "the block's source: current_program.memory_map() (MemoryBlock.source)",
    "getNamespace": "revkit names are global: one name per address",
    "createNamespace": "revkit names are global: one name per address",
    "createClass": "revkit names are global; describe classes with C types (define_type)",
    "Symbol.setNamespace": "revkit names are global: one name per address",
    "Symbol.delete": "rename the address instead (rename(addr, name)); a derived name can't be deleted",
    "removeSymbol": "rename the address instead (rename(addr, name)); a derived name can't be deleted",
    "getExternalManager": "revkit has no external locations; imports are thunks named after their targets",
    "Function.setReturnType": "give the prototype as C: retype(entry, 'int f(char *s)')",
    "Function.updateFunction": "give the prototype as C: retype(entry, 'int f(char *s)')",
    "Function.replaceParameters": "give the prototype as C: retype(entry, 'int f(char *s)')",
    "Function.addParameter": "give the prototype as C: retype(entry, 'int f(char *s)')",
    "Function.insertParameter": "give the prototype as C: retype(entry, 'int f(char *s)')",
    "Function.removeParameter": "give the prototype as C: retype(entry, 'int f(char *s)')",
    "Function.setCallingConvention": "give the prototype as C with its convention: retype(entry, 'int __stdcall f(int)')",
    "Function.setNoReturn": "give the prototype as C: retype(entry, '__attribute__((noreturn)) void f(void)')",
    "Function.setCustomVariableStorage": "revkit keeps the decompiler's storage; rename_local/retype_local name and type it",
    "Function.addLocalVariable": "locals come from the decompiler; rename_local/retype_local name and type them",
    "Function.removeVariable": "locals come from the decompiler",
    "Function.getStackFrame": "locals come from the decompiler: DecompInterface ... getHighFunction().getLocalSymbolMap()",
    "Function.setBody": "set_function(entry, body=[(first, last), ...])",
    "Function.setThunkedFunction": "revkit finds thunks itself",
    "Function.setInline": "no inline flag in revkit",
    "Function.addTag": "use note(entry, text, tag)",
    "Function.getTags": "notes: current_program.assertions() (note bodies)",
    "Data.getComponent": "data components: current_program.listing() rows (data_field, data_parent)",
    "Data.getComponentAt": "data components: current_program.listing() rows (data_field, data_parent)",
    "Instruction.getPrototype": "the decoded instruction: current_program.instruction(addr) (tokens, operands, p-code)",
    "Instruction.getInstructionContext": "processor context is not exposed to scripts",
    "Instruction.setFallThrough": "flow_override(addr, kind)",
    "Instruction.setFlowOverride": "flow_override(addr, kind)",
    "Program.getProgramContext": "processor context is not exposed to scripts",
    "Program.getDomainFile": "no Ghidra project files; current_program.summary().info names the program",
    "Program.getChanges": "current_program.assertions() lists what changed",
    "Program.getRelocationTable": "relocations are applied by the loader and not listed to scripts",
    "Program.getSourceFileManager": "no source-file mapping in revkit",
    "Program.getUsrPropertyManager": "use notes: note(addr, text, tag)",
    "Program.getTreeManager": "no program trees (fragments) in revkit",
    "Program.getRegister": "register names: Varnode.register_name in instruction and decompiler results",
    "Program.endTransaction(rollback)": "edits are buffered until the run ends; raise an exception to discard them",
    "Language.getRegisters": "register names: Varnode.register_name in instruction and decompiler results",
    "Language.getProgramCounter": "register names: Varnode.register_name in instruction and decompiler results",
    "DataTypeManager.addDataType": "define_type(c_source) (or CParser(dtm).parse(c) then addDataType)",
    "DataTypeManager.resolve": "define_type(c_source)",
    "DataTypeManager.remove": "retract the type's assertion",
    "DataTypeManager.createCategory": "revkit types have no categories",
    "DataTypeManager.getCategory": "revkit types have no categories",
    "DataTypeManager.getRootCategory": "revkit types have no categories",
    "DataTypeManager.getAllStructures": "current_program.find_types() (kind STRUCT)",
    # Analysis machinery.
    "BasicBlockModel": "the function's blocks: current_program GetFunctionGraph (QueryService)",
    "SimpleBlockModel": "the function's blocks: current_program GetFunctionGraph (QueryService)",
    "PartitionCodeSubModel": "the function's blocks: current_program GetFunctionGraph (QueryService)",
    "IsolatedEntrySubModel": "the function's blocks: current_program GetFunctionGraph (QueryService)",
    "CodeBlockModel": "the function's blocks: current_program GetFunctionGraph (QueryService)",
    "CyclomaticComplexity": "edges - blocks + 2 from GetFunctionGraph (QueryService)",
    "SearchBaseExtended": "operand masks need the instruction's encoding: search_memory(bits, format='binary') with x for masked bits",
    "InstructionSearchApi": "operand masks need the instruction's encoding: search_memory(bits, format='binary') with x for masked bits",
    "AutoAnalysisManager": "current_program.analyze() (the daemon's analysis jobs)",
    "ParallelDecompiler": "decompile_many(funcs) decompiles on the daemon's workers (revkit.script)",
    "DecompilerCallback": "decompile_many(funcs) decompiles on the daemon's workers (revkit.script)",
    "DecompilerUtils": "DecompInterface().decompileFunction(f, timeout, monitor), with the daemon's options",
    "DecompileResults.getCCodeMarkup": "the decompiler's tokens: decompile(f).lines (CodeLine/CodeToken, with addresses and variables)",
    "HighFunction.getBasicBlocks": "the function's blocks: GetFunctionGraph (QueryService)",
    "HighFunction.getGlobalSymbolMap": "globals: decompile(f).variables (kind GLOBAL)",
    "HighFunction.getVarnodes": "decompile(f).varnodes (each varnode and its variable)",
    "HighFunctionDBUtil.commitParamsToDatabase": "give the prototype as C: retype(entry, 'int f(char *s)')",
    "HighFunctionDBUtil.commitLocalNamesToDatabase": "rename_local(f, storage_key, name) per variable",
    "Varnode.getDef": "def-use chains are not exposed; decompile(f).varnodes maps varnodes to variables",
    "Varnode.getDescendants": "def-use chains are not exposed; decompile(f).varnodes maps varnodes to variables",
    "PcodeBlockBasic": "the function's blocks: GetFunctionGraph (QueryService)",
    "DataGatheringParams": "read the bytes and instructions around entries yourself: getBytes, getInstructionAt",
    "FunctionBitPatternInfo": "read the bytes and instructions around entries yourself: getBytes, getInstructionAt",
    "CompoundCmd": "call the edits directly (Symbol.setName, createLabel, setEOLComment, ...): a run is already one undo step",
    "RenameLabelCmd": "Symbol.setName(name, source) or createLabel(addr, name, True)",
    "AddLabelCmd": "createLabel(addr, name, True)",
    "SetCommentCmd": "setEOLComment / setPlateComment / setPreComment / setPostComment",
    "CreateFunctionCmd": "createFunction(addr, name)",
    "DisassembleCommand": "disassemble(addr)",
    "ClearCmd": "clearListing(start, end)",
    "AlignmentDataType": "revkit has no alignment data type; createData(addr, ArrayDataType(ByteDataType(), n, 1))",
    "PseudoDisassembler": "decode with current_program.instruction(addr) (any address, without disassembling it)",
    # Emulation, debugging, version tracking, BSim, FID.
    "EmulatorHelper": "revkit's emulator: current_program.emulate(...) (EmulatorService)",
    "PcodeEmulator": "revkit's emulator: current_program.emulate(...) (EmulatorService)",
    "DebuggerTraceManagerService": "revkit's debugger: current_program.debug(...) (DebuggerService)",
    "VTSession": "program diffing: client.diff(project, program_a, program_b) (DiffService)",
    "BSim": "program diffing: client.diff(project, program_a, program_b) (DiffService)",
    "FidService": "use revkit's Function ID: revkit.script.fid_matches()/run_fid()/apply_fid(), Program.fid_matches() (docs/fid.md)",
    # Java and the GUI.
    "java": "Java classes aren't available: revkit runs scripts in CPython; use Python's standard library",
    "javax": "no Swing: print, or use askString/askChoice for input",
    "docking": "no Ghidra GUI: print, or use askString/askChoice for input",
    "jpype": "no JVM: revkit runs scripts in CPython",
}


def replacement_for(api: str) -> str:
    """The table's replacement for ``api`` ("Function.setNoReturn",
    "createBookmark", "java.util.LinkedList")."""
    if api in UNSUPPORTED:
        return UNSUPPORTED[api]
    last = api.rsplit(".", 1)[-1]
    if last in UNSUPPORTED:
        return UNSUPPORTED[last]
    head = api.split(".", 1)[0]
    if head in UNSUPPORTED:
        return UNSUPPORTED[head]
    for key, value in UNSUPPORTED.items():
        if api.startswith(key + "."):
            return value
    return "not in revkit's Ghidra compatibility shim; use revkit.script (docs/scripting.md)"
