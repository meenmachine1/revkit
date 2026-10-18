# Lifting bytecode and scripts

How revkit could analyse programs written in scripting and managed
languages: their bytecode (`.pyc`, Lua chunks, `.class` and `.dex`, CIL,
WebAssembly, JavaScript engine bytecode) and the scripts packed into
native executables (PyInstaller, Electron, pkg, Lua in firmware). This is
a design note from a study with experiments. Step 1 of the plan
(identify and extract) is built (2026-10-18, `api_minor` 94 to 96: [What
revkit has today](#what-revkit-has-today)), and step 2, the external
decompiler providers ([providers.md](providers.md)); the rest isn't, beyond
the experiment files in [bytecode-lifting/](bytecode-lifting/).
(revkit's own Python scripting API is [scripting.md](scripting.md); this
page is about analysing programs that *other people* wrote in such
languages.)

- [Summary](#summary)
- [What revkit has today](#what-revkit-has-today)
- [The approaches](#the-approaches)
- [Per language](#per-language)
- [Experiments](#experiments)
- [Plan](#plan)
- [Where it goes in revkit](#where-it-goes-in-revkit)
- [Licensing](#licensing)

## Summary

The vendored decompiler can already do much more on bytecode than revkit
asks of it. Replayed with the constant-pool records and per-instruction
injections that Ghidra's Java side computes, it gives Ghidra's own Java
output for JVM methods (`this.f`, `new StringBuilder()`,
`param1.length()`) ([E3](#e3-the-vendored-decompiler-given-ghidras-injections)).
What revkit lacks is the Java code around it: the loaders, the injection
libraries and the constant pools. Hand-written SLEIGH sketches of Lua 5.4
and CPython 3.12 decompile real control flow to correct structured C in
revkit unchanged, at about 100 lines each
([E4, E5](#e4-cpython-312-as-a-sleigh-processor)). The vendored SLEIGH
compiler builds Ghidra's JVM, Dalvik and eBPF specs byte for byte
([E6](#e6-the-vendored-sleigh-compiler)).

What to build, in order:

1. ~~**Identify and extract**~~ *done* (approach d; [What revkit has
   today](#what-revkit-has-today)): name every bytecode format in the
   detector, and add container formats for the packers: PyInstaller,
   py2exe and cx_Freeze (their zips already open), Electron `asar`, Node
   pkg, nexe and SEA blobs, Deno and Bun executables, and Lua and LuaJIT
   chunks carved out of firmware. Also two quick fixes found here. A .NET
   assembly is analysed today as x86 code; it should be recognised by its
   CLR header and left alone, or handed on. An eBPF object needs `--lang`;
   `EM_BPF` should map to Ghidra's eBPF language, which then decompiles
   ([E7](#e7-ebpf-and-net-as-they-load-today)). This is the cheapest step
   (S to M), and every later step needs it. Most real targets arrive packed,
   and once the scripts are out, the decompilers users already run apply.
2. **External decompiler providers** (approach c): one mechanism that runs
   a dedicated decompiler as a sandboxed child process, as `rk-decompd`
   runs Ghidra's. It shows the output as source in the decompiler pane and
   as files in the container browser. Start with ILSpy for .NET, jadx for
   DEX and APK, Vineflower for JVM jars, unluac for Lua 5.0 to 5.4, pycdc
   for Python, webcrack for JavaScript bundles and wasm-decompile for
   WebAssembly. The framework is M and each provider S. For .NET and
   Android this gives source-level output that no p-code route will match,
   and it needs no vendoring, so no licence questions. **Built**
   (2026-10-18, api_minor 92): all seven, and CFR beside Vineflower, run
   by `rk-sandbox` (limits, Landlock, seccomp), cached by the input's
   SHA-256, the provider and the tool's version, in the decompiler pane and
   the file system browser, the API, the SDK and MCP
   ([providers.md](providers.md)). wasm-decompile left WABT after 1.0.41.
3. **JVM and Dalvik through SLEIGH, end to end** (approach a): `.class`,
   jar, `.dex` and APK loaders, and C++ ports of Ghidra's injection
   libraries and constant pools (Apache-2.0) in the decompiler worker. Use
   the Java printer the decompiler already has. Effort M. This brings
   Ghidra parity, which the experiments show is in reach. It also puts
   bytecode into revkit's own analysis, which an external decompiler can't:
   references, search, BSim, diff, and the JNI boundary
   between an APK's dex and its native `.so` files in one project.

After those: **Lua** through SLEIGH (5.1 to 5.4 and LuaJIT, specs
generated from each version's opcode table, M), for firmware and games,
where VMs are often modified and unluac gives up. Then **CPython 3.11+**
per minor version (L): the pattern-matching Python decompilers fall
behind every release, while the decompiler's structuring of p-code doesn't
depend on the version, so this fills a real gap. Exception tables are the
main work. **WebAssembly** needs SLEIGH plus a stack-height pre-pass, or a
dedicated front end (M to L), after the wasm-decompile provider. The rest are later:
Hermes (under [JavaScript](#javascript)), and Dart AOT, EVM, BEAM,
AutoIt, PHP and Ruby (under [Others](#others)).

## What revkit has today

- **Ghidra's bytecode processors load and lift.** The sweep
  ([processors.md](processors.md#the-sweep)) loads, lifts and discovers
  `JVM:BE:32:default`, the thirteen Dalvik languages, `BPF` and both
  `eBPF` byte orders. JVM and Dalvik stop at decompilation with "Missing
  dynamic inject". eBPF and BPF decompile.
- **The decompiler's managed-code machinery is all vendored and linked**
  (`third_party/ghidra`): the `CPOOLREF` and `NEW` p-code ops and their
  rules, `ConstantPool` (`cpool.cc`: `ConstantPoolInternal` holds records
  decoded from XML), dynamic injection payloads (`InjectPayloadDynamic`
  in `inject_sleigh.cc`), which hold per-address p-code supplied from
  outside, and the Java printer (`printjava.cc`, `setlanguage
  java-language`). revkit uses none of them. `ImageArchitecture` keeps
  SleighArchitecture's empty constant pool and its injection library, so a
  `CPOOLREF` prints as `UNKNOWNREF`, and a `dynamic="true"` payload throws.
- **What "Missing dynamic inject" is.** JVM's and Dalvik's compiler specs
  declare their entry injection (`<pcode inject="uponentry"
  dynamic="true"/>`) and some call-other fixups as dynamic: Ghidra's Java
  classes (`PcodeInjectLibraryJava`, `PcodeInjectLibraryDex`, named in the
  `.pspec`'s `pcodeInjectLibraryClass`) compute the p-code per method from
  the class file. In detail:
  - the entry injection moves the parameters into the locals, from the
    method descriptor (JVM) or from `registers_size`, `ins_size` and the
    prototype (Dalvik);
  - JVM's `getfield`, `invoke*`, `ldc`, `new` and the rest become
    `CPOOLREF` ops and loads, stores and calls typed from the constant
    pool;
  - Dalvik's range invokes copy a run of registers (`moveRangeToIV`);
    Dalvik's SLEIGH emits `CPOOLREF` itself.
- **The SLEIGH compiler is vendored but not built.** `slgh_compile.cc`,
  `slghparse.cc` and `slghscan.cc` are in the fork. revkit loads only the
  `.sla` files a Ghidra install ships, from that one root
  ([getting-started.md](getting-started.md#ghidra-processor-specs)). A
  processor revkit ships itself would need a second spec directory.
- **Loaders**: ELF, PE, Mach-O and raw (`loader::Format`). There is no
  class, dex or wasm loader. `EM_BPF` (247) maps to Ghidra's eBPF language
  (`eBPF:LE:64:default`, `eBPF:BE:64:default`), so a clang-built eBPF
  object decompiles without `--lang` (*done*, step 1; test `rk_lift_ebpf`).
- **Detection** (`src/container/bytecode.cc`, *done*, step 1) names every
  format here by its header, with a [content kind](filesystems.md#content-kinds)
  the providers dispatch on: `.pyc` (2.0 to 3.16 by magic number), Lua 5.1
  to 5.5 and LuaJIT 2.0 and 2.1 chunks (with their sizes), Java classes,
  DEX, wasm, Hermes, V8 code caches, YARB, PHP opcache, BEAM, JerryScript,
  jars and APKs, and scripts by their `#!` line.
- **.NET** (*done*, step 1; `api_minor` 94): a PE's CLR header makes it a
  .NET assembly (`ProgramInfo.dotnet`: metadata and runtime versions,
  flags, IL-only or mixed-mode, ReadyToRun). An IL-only assembly is
  imported **without code analysis** and a warning saying why (before, it
  loaded as `x86:LE:32:default` with its IL disassembled as x86); it isn't
  refused, so the program is there for a provider's output. Mixed-mode and
  ReadyToRun images keep their native analysis.
- **Containers** ([filesystems.md](filesystems.md#packed-executables),
  *done*, step 1; `api_minor` 96) extract what packers carry: PyInstaller
  (the CArchive and its PYZ, every script and module a valid `.pyc` with
  its header restored), Electron asar (unpacked files too), pkg, nexe,
  Node SEA blobs and Bun executables, an appended zip (py2exe's library,
  cx_Freeze's older builds; `lib/library.zip` and jars and APKs browse as
  zips already), and Lua and LuaJIT chunks carved out of firmware by
  header and a walk of their functions. A packed executable stays a
  program, with `ProgramInfo.payload_format` naming its archive. Not yet:
  Deno, py2exe's `PYTHONSCRIPT`, Nuitka, AutoIt, AutoHotkey.
- **Content kinds** are what the providers (step 2) dispatch on: each
  extracted or detected file says what it is, `pyc:3.12`, `lua:5.4`,
  `luajit:2.1`, `java-class:21`, `dex:035`, `wasm`, `hermes:96`,
  `v8-cache`, `dotnet:il`, `jar`, `apk`, `js-source`, `jsc-bytecode`, ...
  (the full list: [filesystems.md](filesystems.md#content-kinds)). A
  provider takes the family before the colon; the version after it says
  which of its decoders applies.

## The approaches

| | (a) SLEIGH processor | (b) dedicated front end | (c) existing decompiler | (d) extraction only |
| --- | --- | --- | --- | --- |
| What | a `.slaspec` for the VM; loader lays out code and tables; analysis and decompiler unchanged | C++ decoder emitting p-code (a `Translate` of its own), or a new IR and decompiler | run pycdc, unluac, jadx, ILSpy, ... as a provider | unpack scripts and bytecode from native containers and show them as files |
| Output | C-like (or Java-like) code from Ghidra's decompiler; types weak for dynamic languages | as (a), or source-like if it has its own back end | the tool's own source-level output | the files; then (a) or (c) |
| Integration | full: references, search, BSim, diff, emulation, patching, the listing | p-code consumers work; listing text, assembler and patching need their own code | text only, no addresses inside revkit unless the tool gives a mapping | full container-browser support |
| Version churn | one spec per opcode table; generate them | data-driven tables at run time | the tool's problem (and often its weak point) | formats change slowly |
| Fits | register VMs (Lua, Dalvik, Hermes, V8), simple stack VMs (JVM, CPython, CIL) | wasm (LEB128, block nesting), EVM (256-bit), anything needing decode state | .NET, Android, Java, JS bundles, Python up to 3.8 | everything packed |

### What SLEIGH can express, with tricks

The experiments settle where (a) works and what it takes:

- **An operand stack** is memory below a stack pointer, as Ghidra's JVM
  models it. `push` and `pop` are stores and loads through `SP`. The
  decompiler's stack analysis turns them back into expressions.
- **Locals and VM registers** go in a space of their own (`fast:` for
  CPython, `stk:` for Lua, `localVariableArray` for the JVM). The slot is
  computed from the operand, `*[fast]:8 (arg*8)`, so they become ordinary
  variables. Mark that space unaffected by calls in the compiler spec, as
  Dalvik's spec does for its registers, or a call kills every local.
- **Calls need fixed parameter storage.** A VM passes arguments in a
  window that moves (Lua's `R[A+1..]`, the top of CPython's stack). The
  call instruction copies them into fixed argument registers (`a0`..),
  which are the prototype's inputs. The callee's entry injection copies
  them into its own slots. A static injection that copies all four
  argument registers is enough: the copies a function doesn't read are
  dead code. That avoids JVM's and Dalvik's dynamic per-method injection
  wherever the parameter count isn't needed for anything else.
- **Instruction pairs and inline caches** fold into one instruction.
  Examples are Lua 5.4's arithmetic and the `MMBIN` metamethod fallback
  after it, a test and the `JMP` after it, and CPython 3.11+'s `CACHE`
  entries after `BINARY_OP` and `CALL`. A SLEIGH pattern can span both
  tokens.
- **Constants** can come from a read-only table the loader lays out. The
  decompiler folds a load from read-only memory, so `LOAD_CONST 1` prints
  as `10`. Constants of a richer kind (strings, classes, fields, methods)
  need the constant pool: `CPOOLREF` with records that give a name, a
  type and a kind. JVM and Dalvik use these.
- **Per-function tables** (each Lua proto's `K[]`, each code object's
  `co_consts`) need the table's base per function. That is either a
  context variable the loader paints over the function's body (revkit
  paints ARM's Thumb bit per function already) or `CPOOLREF` with the
  function in the reference.

Where SLEIGH breaks:

- **Variable arity and multiple results** (Lua's `CALL A 0 0`, `VARARG`,
  `RETURN` with `B=0`; CPython's `CALL_FUNCTION_EX`) depend on a dynamic
  top of stack. The decompiler's prototypes have fixed storage and one
  output. These become call-other ops, or dynamic injections that know
  the top.
- **Exceptions** are outside the instruction stream: CPython 3.11+'s
  exception table, the JVM's exception table, CIL's EH clauses. SLEIGH
  can't express them, and Ghidra's decompiler has no try/catch. Ghidra's
  own JVM output leaves out handlers. The loader can add the handlers as
  extra entry points or flow overrides, so they're decompiled. Showing
  them as `try` blocks needs decompiler work.
- **Dynamic typing**: every value is an object reference. With integer
  p-code (`INT_ADD` for `BINARY_OP +`), the output reads like the source.
  But the types print as `long`, and the decompiler's integer
  simplifications are wrong for strings, floats or overloaded operators.
  A core `object` type, and call-other ops for operators the decompiler
  must not fold, keep it honest.
- **Decode state**: WebAssembly branches name a block depth, not an
  address; its immediates are LEB128; its stack height decides which slot
  an operand is. Those need an analysis pass before decoding that paints
  context (what the community wasm plugin does) or a dedicated decoder
  (b).
- **Wide words**: EVM's 256-bit stack values exceed what the decompiler's
  constant folding handles (64-bit `uintb`).
- **Source syntax**: the decompiler prints C or Java. Lua or Python
  syntax means a new `PrintLanguage`; `printjava.cc` (a PrintC subclass)
  shows the size of one, a patch to the fork.

### What a dedicated front end buys

A `Translate` subclass that decodes in C++ and emits p-code (b) lifts the
decode-state limits. It can also load opcode tables at run time, so one
front end covers every CPython minor version. But revkit's listing text
(`ghidra_text.cc` reads SLEIGH constructors), its assembler and patching
(inverted SLEIGH), and the shared SLEIGH engines assume SLEIGH, so each
would need a second implementation. Generating SLEIGH from opcode tables
at build time keeps all of them and covers most of what (b) offers. Use
(b) only where SLEIGH can't decode at all (wasm without a pre-pass, EVM).
A front end with its own IR and source-level back end is a new decompiler
per language. That is the providers' job (c).

## Per language

Effort: **S** under a week for one worker, **M** one to three weeks,
**L** more. Value is to a reverse engineer: how often the target turns up
and how badly the current tools serve it.

### Python

**Formats.** A `.pyc` is a header and then a `marshal`ed code object. The
header is the magic and mtime on 2.7; magic, mtime and size on 3.3 to
3.6; and from 3.7 a flags word, then mtime and size, or a source hash
(PEP 552). `marshal` is a small tagged format (code, bytes, str, tuple,
ints, refs with the `0x80` flag since 3.4). It changes rarely, but every
minor version changes the opcode table and often the code object's
fields.

**Bytecode by version.**

| Version | Change |
| --- | --- |
| 2.7 and 3.0 to 3.5 | variable length (1 or 3 bytes), absolute jumps, a block stack (`SETUP_LOOP`, `SETUP_EXCEPT`) |
| 3.6 | 2-byte wordcode with `EXTENDED_ARG` prefixes |
| 3.8 | no `SETUP_LOOP` |
| 3.10 | jump arguments in instruction units |
| 3.11 | inline `CACHE` entries after many opcodes; a zero-cost exception table (`co_exceptiontable`, varint ranges to handler, stack depth and lasti); relative forward and backward jumps; `PRECALL`/`CALL` |
| 3.12 | comprehensions inlined (PEP 709); `RETURN_CONST`, `END_FOR`, `LOAD_FAST_CHECK` |
| 3.13 and 3.14 | renumbered again; `LOAD_FAST_LOAD_FAST` and other superinstructions are now real opcodes in `.pyc` files |

The **adaptive interpreter** (3.11+, PEP 659) specialises opcodes
(`LOAD_ATTR_INSTANCE_VALUE`, `BINARY_OP_ADD_INT`) in memory only. A
`.pyc` holds the generic opcodes with zeroed caches, so a lifter needs only
the generic table. A memory dump of a running process holds specialised
opcodes and filled caches. Those map back to the generic ones through
CPython's `_PyOpcode_Deopt` table.

**Packers.**

- **PyInstaller**: a CArchive appended to the bootloader. It ends in a
  cookie whose magic is `MEI\014\013\012\013\016`, with the Python version
  and library name, and a zlib-compressed table of contents. Entries are
  scripts (marshalled code *without* a `.pyc` header, which extraction
  must add), modules, binaries and a PYZ archive (`PYZ\0`, a marshalled
  TOC and zlib entries). Versions before 6.0 could encrypt the PYZ
  (AES, with the key inside the archive).
- **py2exe**: the `PYTHONSCRIPT` resource (a marshalled list of code
  objects) and a zip library appended or beside it.
- **cx_Freeze**: `lib/library.zip` of `.pyc` files and a frozen
  `__main__`.
- **Nuitka** compiles Python to C, so its output is native code. There is
  no bytecode to lift. Its onefile mode appends a zstd-compressed payload
  holding the real executable. Extraction plus revkit's native pipeline
  is the route. Nuitka's helper functions are worth recognising, by
  signatures or Function ID, and module and constant names come from its
  serialized constants blob.

**Assessment.**

| Approach | Feasibility | Effort | Notes |
| --- | --- | --- | --- |
| (d) PyInstaller, py2exe, cx_Freeze extraction; `.pyc` and marshal parsing in detection | high | S to M | highest value: Python malware and tools arrive packed |
| (c) pycdc (C++, GPL-3.0) | high | S | 2.x to 3.x, but partial on 3.11+; uncompyle6 and decompyle3 (GPL-3.0) are complete only up to 3.8 |
| (a) SLEIGH per minor version | proven on 3.12 ([E4](#e4-cpython-312-as-a-sleigh-processor)) | L | generated from CPython's opcode metadata; exception tables, generators, `with` and keyword calls are the work |
| (b) | possible | L | only if per-version SLEIGH proves unmanageable |

Value: high. Python 3.11+ is where the existing decompilers fail most, and
that is the gap (a) can fill. Recommended: (d), then (c) pycdc, then (a)
for 3.11+.

### Lua

**Formats.** A chunk starts with `\x1bLua` and a version byte (`0x51` to
`0x54`). From 5.2 a check block follows (`\x19\x93\r\n\x1a\n` and the
sizes of `Instruction`, `lua_Integer` and `lua_Number`), so a loader
learns the build's word sizes from the header. That matters on embedded
targets, where 32-bit floats or integers are common. Every version is a
**register VM** with fixed 32-bit instructions:

| Version | Layout |
| --- | --- |
| 5.1 | op 6 bits, A 8, C 9, B 9 (Bx 18) |
| 5.2 and 5.3 | the same layout; `_ENV` upvalues and `EXTRAARG`; 5.3 adds integers and bitwise ops |
| 5.4 | op 7 bits, A 8, k 1, B 8, C 8 (Bx 17, sJ 25); `MMBIN*` after arithmetic, test-and-skip pairs, to-be-closed variables |
| LuaJIT 2.0 and 2.1 | magic `\x1bLJ` and version 1 or 2; op 8 bits, A 8, C 8, B 8 or D 16; GC constants indexed down from the end of the constant array, numeric constants apart; typed comparisons; 2.1's `FR2` two-slot frames |

**Embedded Lua.** Firmware (routers, printers, industrial controllers),
games (scripts in packs, often with modified VMs) and Redis or nginx
scripts. Chunks carve out of a blob by their header. Modified VMs often
permute opcodes, change sizes or encrypt chunks. unluac handles stock
versions only. A generated SLEIGH spec takes a permuted opcode table as
an input.

**Assessment.**

| Approach | Feasibility | Effort | Notes |
| --- | --- | --- | --- |
| (d) chunk carving in firmware and packs; header parsing in detection | high | S | the header says the version and sizes |
| (c) unluac (Java, MIT) | high | S | 5.0 to 5.4, good output; LuaJIT through ljd forks or luajit-decompiler-v2 (no clear licence: provider only) |
| (a) SLEIGH per version, generated from `lopcodes.h` and LuaJIT's `lj_bc.h` | proven on 5.4 ([E5](#e5-lua-54-as-a-sleigh-processor)) | M | register VM maps directly; varargs, multiple results, `SETLIST`, closures and upvalues need call-other ops or injections |
| (b) | not needed | - | |

Value: medium to high, and high in firmware and game work, where the
modified-VM case leaves no other tool. Recommended: (d) and (c) unluac
first, then (a) with a generated spec, sharing the loader.

### JavaScript

**Engines and their bytecode.**

| Engine | Where | Bytecode | Assessment |
| --- | --- | --- | --- |
| V8 (Node, Electron, Chrome) | `bytenode` `.jsc`, Node `--snapshot-blob` startup snapshots, pkg's compiled sources, Electron `v8_context_snapshot.bin` | Ignition: an accumulator and register machine; constant pool and feedback slots per function | the bytecode itself would suit SLEIGH. But a code cache is a serialized V8 heap tied to one V8 version and flag hash. Reading it means rebuilding that version's deserializer (View8's approach drives a matching `d8` instead). L, and a moving target. Extract, and use the source where it survives |
| Hermes (React Native) | `index.android.bundle` with magic `c6 1f bc 03 c1 03 19 1f` | register machine, documented in `BytecodeList.def`; the version changes the table (about 59 to 96) | good fit for a SLEIGH spec generated from `BytecodeList.def` per version (M). Providers: hermes-dec (AGPL-3.0, fine to vendor), hbctool (MIT) |
| QuickJS | `qjsc` output, embedded devices | stack machine, atoms table; format tied to `BC_VERSION` | (a) feasible like CPython (M); low frequency |
| JerryScript | microcontrollers, snapshots with magic `JRRY` | compact byte code (CBC), literal tables, versioned | (a) feasible (M); low frequency, but firmware-relevant |

**Packers.**

- **Electron**: `resources/app.asar`, a Chromium pickle with a JSON
  header and then the files (and `app.asar.unpacked`). Trivial to extract.
- **pkg** (vercel/pkg, now yao-pkg): a payload and prelude appended to a
  Node binary, a virtual file system, sources optionally compiled to V8
  bytecode.
- **nexe**: resources appended with a `<nexe~~sentinel>` trailer.
- **Node SEA**: a `NODE_SEA_BLOB` resource (ELF note, PE resource, Mach-O
  section) injected by postject, optionally with a code cache.
- **Deno** `compile`: an eszip appended, trailer `d3n0l4nd`.
- **Bun** `--compile`: a module graph with a `---- Bun! ----` trailer.

**Minified and bundled JS.** webcrack (MIT) unpacks webpack and browserify
bundles, undoes obfuscator.io and unminifies. wakaru (Apache-2.0)
unminifies and reverses transpiled syntax. Both are TypeScript CLIs, so
revkit runs them as providers. The input is source text, so p-code
doesn't apply.

Value: high for Electron and Node malware and apps (most ship plain JS
once unpacked), medium for React Native (Hermes). Recommended: (d) for all
the packers, and (c) webcrack, both early. Hermes by (a) with a generated
spec later. V8 bytecode only on demand.

### JVM and Dalvik

Ghidra ships SLEIGH processors for both (`Ghidra/Processors/JVM`,
`Ghidra/Processors/Dalvik`). revkit loads them as they are and lifts them
correctly. What's missing is everything Ghidra does in Java around them.

The **JVM** side:

- `JavaLoader` lays the class file out in a `constantPool` space, puts
  each method's code in `ram` from `0x10000` (aligned to 4) and builds a
  `method_lookup` table at `0xe0000000`.
- It paints the `alignmentPad` context register per address, which
  `tableswitch` and `lookupswitch` padding needs.
- `PcodeInjectLibraryJava`, `ConstantPoolJava` and their helpers are about
  2,600 lines of Java: the entry injection from the descriptor, and
  thirteen call-other fixups that pop operands, emit `CPOOLREF` and
  push results by the field's or method's descriptor.

The **Dalvik** side:

- the DEX loader (in FileFormats);
- `InjectPayloadDexParameters`, which copies `iv0..` into the top
  `ins_size` registers of the frame;
- `InjectPayloadDexRange`, for range invokes;
- `ConstantPoolDex`, with methods, fields, strings and types from the DEX
  tables.

Altogether that's about 600 lines of Java, besides the loader.

The experiments ([E1 to E3](#e1-jvm-and-dalvik-as-they-load-today))
show the C++ decompiler needs nothing else. With the entry injection
supplied, `add` and `sum` decompile correctly on both VMs. With Ghidra's
recorded injections and constant-pool records, the vendored decompiler
prints Ghidra's Java output exactly.

**How revkit would do it.**

- A loader for `.class` (and jars through the zip container) and one for
  `.dex` (and APKs), with the language picked by the DEX version
  (`035` to `039`, mapped to `DEX_*`). Methods become functions named
  `Class.method(descriptor)`, and classes become types.
- In the worker, a `PcodeInjectLibrary` of revkit's own for these
  languages, registered in `ImageArchitecture::buildPcodeInjectLibrary`.
  It computes the entry and call-other payloads from the method and the
  constant pool, as Ghidra's Java does, ported to C++.
- A `ConstantPool` subclass answering `CPOOLREF` from the same tables.
- Both read a new part of the bundle: the method's metadata (descriptor,
  static flag, register and in counts) and the constant-pool entries the
  method's p-code names. The parent predicts those by scanning the
  method's `CPOOLREF` and call-other operands, as it predicts addresses
  today. A miss falls back to a rerun, as now.
- The `java-language` printer, through the bundle's options.
- Context painting for `alignmentPad`: one value per address, which
  revkit's per-function context painting doesn't cover yet. Alternatively
  revkit could ship a JVM spec that computes the pad from `inst_start`.

The result is Ghidra's Java-flavoured output. It has no try/catch (Ghidra
drops the handlers), no lambdas or generics, and the names are what the
class file keeps. jadx (DEX, Apache-2.0) and Vineflower (Apache-2.0) or
CFR (MIT) give better source, so they come first as providers.

| Approach | Feasibility | Effort | Notes |
| --- | --- | --- | --- |
| (c) jadx for DEX and APK, Vineflower or CFR for jars | high | S each | best source; needs a JRE (the user's JDK) |
| (a) Ghidra's processors with ported injections, constant pools and loaders | proven ([E1 to E3](#e1-jvm-and-dalvik-as-they-load-today)) | M | Ghidra parity; references, BSim, diff; JNI calls into an APK's `.so` files in one project |
| (d) jars and APKs | done | - | they browse as zips; DEX inside an APK needs only the loader |

Value: high for Android (APK malware, apps with native libraries), medium
for desktop Java. Recommended: (c) first, then (a).

### .NET CIL

CIL is a stack machine with metadata tokens: a JVM with richer metadata
(ECMA-335). Ghidra has no CIL processor or decompiler. ILSpy (MIT, C#)
is the standard decompiler, and `ilspycmd` is installed on this host
([E8](#e8-net-through-ilspycmd)). Its output is essentially the source.
A SLEIGH processor with token constant pools (as the JVM) is feasible
(M to L). It would serve integration, not readability, and only once (c)
exists.

Things revkit must get right regardless:

- detect the CLR header (data directory 14) and stop analysing IL as x86
  ([E7](#e7-ebpf-and-net-as-they-load-today));
- mixed-mode C++/CLI assemblies: native code next to IL;
- ReadyToRun images: precompiled native code with the IL kept;
- NativeAOT executables: native only, with reflection metadata.

| Approach | Feasibility | Effort | Notes |
| --- | --- | --- | --- |
| (d) recognise managed PEs; list resources and embedded assemblies (Costura, single-file bundles) | high | S | today an assembly is mis-analysed as x86 |
| (c) ILSpy (`ilspycmd` as provider, MIT) | proven | S | source-level C#, project export |
| (a) CIL SLEIGH with token pools | feasible | M to L | only for references, BSim and diff over IL |

Value: very high (.NET malware and tools are common). Recommended: (d)
detection now, (c) ILSpy as the first provider.

### WebAssembly

Wasm is a typed stack machine with structured control flow (`block`,
`loop`, `br` to a depth), LEB128 immediates and a module of sections. A
community SLEIGH plugin (nneonneo's ghidra-wasm-plugin, GPL-3.0, so it
could be vendored) works with a pre-analysis that computes each
instruction's stack height and branch targets and sets them as context.
That is how SLEIGH has to do it.

In revkit that pre-pass belongs in the loader or in discovery. It would
paint per-address context, the same mechanism the JVM's `alignmentPad`
needs, or flow overrides. Alternatively a dedicated decoder (b) that
tracks the stack itself.

| Approach | Feasibility | Effort | Notes |
| --- | --- | --- | --- |
| (d) module parsing in detection (imports, exports, names section, data segments) | high | S | |
| (c) wasm-decompile (WABT, Apache-2.0; C++, could even be linked) | high | S | readable pseudo-code; no integration |
| (a) SLEIGH with a stack-height pre-pass (porting the plugin's spec) | feasible | M | linear memory as `ram`, locals as a space, globals as a table |
| (b) a C++ wasm front end | feasible | M to L | cleaner than painting context; loses SLEIGH's listing and assembler |

Value: medium and rising (browser malware, plugins, blockchain
contracts). Recommended: (c) first, (a) with the pre-pass later.

### Others

| Format | What it is | Recommended | Effort | Value |
| --- | --- | --- | --- | --- |
| eBPF | Ghidra's eBPF SLEIGH; ELF objects with `EM_BPF` | (a) as it is: map `EM_BPF` to `eBPF:LE:64:default` (and BE), then BPF relocations (map references on `ld_imm64`), helper names for `call imm`, BTF types | S, then M | medium (kernel and container security, rootkits) |
| Classic BPF | Ghidra's `BPF` SLEIGH; filters in memory or pcap programs | (a) raw import works today | - | low |
| Ruby YARV | `RubyVM::InstructionSequence#to_binary` (`YARB`), version-specific | (d) detection only | S | low |
| PHP opcache | file-cache `.bin` with `OPCACHE` magic and a system id per PHP build | (d) detection only | S | low |
| AutoIt | the compiled script in an RCDATA resource (`AU3!EA06`), encrypted and compressed by a known scheme | (d) extraction (AutoIt-Ripper, MIT, as the reference) | S to M | medium (commodity malware) |
| AutoHotkey | the script as plain text in RCDATA (`>AUTOHOTKEY SCRIPT<`) | (d) extraction | S | medium (malware) |
| EVM | 256-bit stack machine, contracts as raw bytecode | (b) a front end, or a provider (heimdall-rs, MIT; panoramix, MIT); SLEIGH breaks on 256-bit words | M to L | low for revkit's audience |
| Erlang BEAM | IFF `FOR1`/`BEAM` chunks; `Dbgi` (or old `Abst`) holds the abstract code when built with debug info | (d) chunk listing and source from debug info; (a) only without it | S, then L | low |
| Dart and Flutter AOT | native ARM64 or x86-64 code in `libapp.so` (`_kDartIsolateSnapshotInstructions`); objects reached through the object pool register (x27 on ARM64) | native pipeline plus a snapshot parser for class and function names and object-pool entries (blutter, MIT, as the reference) | L | medium to high (Flutter apps), version-specific |

## Experiments

Run on this host under `systemd-run ... -p MemoryMax=4G`, with
master's build (`rk-lift` of 2026-10-10) and Ghidra 12.1.4. The files are
in [bytecode-lifting/](bytecode-lifting/).

- `make-root.sh` builds a Ghidra root with every processor linked in,
  copies of JVM and Dalvik with a static entry injection, and the two
  sketch processors compiled.
- `rawdec.sh` decompiles a flat image with `rk-lift --raw`.
- `classcode.py` prints a class file's method code offsets.
- `pyimg.py` and `luaimg.py` lay out the sample functions.

```sh
d=docs/bytecode-lifting
$d/make-root.sh ~/ghidra/ghidra_12.1.4_PUBLIC /tmp/bc/root         # or with a C++ sleighc as 3rd arg
javac --release 8 -g:none -d /tmp/bc $d/Tiny.java && python3 -I $d/classcode.py /tmp/bc/Tiny.class
$d/rawdec.sh /tmp/bc/root JVM:BE:32:default:default /tmp/bc/Tiny.class 1fb 11 /tmp/bc/add.json --no-instructions
python3 -I $d/pyimg.py /tmp/bc && $d/rawdec.sh /tmp/bc/root PyVM:LE:32:cpython312:default /tmp/bc/py_g.img 0 700 /tmp/bc/g.json --raw-perms r-x
python3 -I $d/luaimg.py /tmp/bc && $d/rawdec.sh /tmp/bc/root LuaVM:LE:32:lua54:default /tmp/bc/lua_g.img 0 700 /tmp/bc/lg.json --raw-perms r-x
```

### E1: JVM and Dalvik as they load today

The method bytes come from `Tiny.java` (javac 21, `--release 8`); the
Dalvik methods were assembled by hand, as no `d8` is installed. Raw
import, `--lang JVM:BE:32:default:default` or
`Dalvik:LE:32:DEX_Android12:default`:

- **Lifting is correct.** `iload_0` loads `localVariableArray[0]` and
  pushes it through `SP`; `if_icmple` and `iinc` are right. Dalvik's
  `add-int`, `if-gt`, `add-int/lit8` and `mul-int/lit8` give the register
  p-code expected, and `invoke-static` lifts to `CPOOLREF` and
  `CALLIND`.
- **Decompilation fails on every method**: `Missing dynamic inject`, at
  the entry. This is the entry injection, not a constant-pool callback.

### E2: with a static entry injection

`make-root.sh` swaps each spec's dynamic entry injection for the p-code
that Ghidra's Java would compute for a two-argument static method:
`LVA = 0; t = *[parameterSpace] LVA; *[localVariableArray] LVA = t; LVA += 4`
twice for the JVM, and `v1 = iv0; v2 = iv1` for Dalvik.

```c
int entry(int param_1,int param_2)        // JVM add(II)I, and the same for Dalvik
{
  param_1 = param_1 + param_2;
  if (10 < param_1) {
    param_1 = param_1 + -3;
  }
  return param_1 * 2;
}
```

`sum([I)I` decompiles to the right loop, but the array length is
`(int)UNKNOWNREF`: `arraylength` is a `CPOOLREF` with no record.

- JVM `getF` (`getfield`) still fails: a dynamic call-other fixup.
- Dalvik `iget` gives `return *(undefined4 *)UNKNOWNREF;`.
- Dalvik `invoke-static {v1, v2}` gives
  `uVar1 = (*(code *)UNKNOWNREF)(param_1,param_2);`: the arguments are
  right, and only the target's name and prototype are missing, which
  `ConstantPoolDex` would provide.

So for Dalvik the entry injection and constant-pool records are
everything, and for the JVM those plus the call-other fixups.

### E3: the vendored decompiler, given Ghidra's injections

`tools/ghidra-export/ghidra_debug_xml.py` captured Ghidra's decompiler
debug files for `getF`, `hello` and `sum`. Ghidra's JavaLoader
and analysis had run first. The files hold `<injectdebug>` (each dynamic
payload as p-code, per address: seven for `hello`), `<constantpool>`
(`<cpoolrec ref="0x7" tag="field"><token>f</token>` with its type) and
`<setlanguage>java-language</setlanguage>`. Replayed in the fork's
console (`ghidra_decomp_dbg`), each prints exactly Ghidra's output:

```java
int getF_int(Tiny this) { return this.f; }

String hello_java.lang.String_java.lang.String(String param1)
{
  StringBuilder pSVar1; int iVar2; String pSVar3;
  pSVar1 = new StringBuilder();
  pSVar1 = pSVar1.append("hi ");
  iVar2 = param1.length();
  pSVar1 = pSVar1.append(iVar2);
  pSVar3 = pSVar1.toString();
  return pSVar3;
}
```

`sum` gives `if (param1.length <= iVar2) break;` and `param1[iVar2]`.
Nothing on the C++ side is missing. The parent must produce what the
debug file holds: payloads, records and the print language.

### E4: CPython 3.12 as a SLEIGH processor

`py312.slaspec` (about 100 lines) covers seventeen opcodes. The value stack
is in `ram` below `SP`, and locals are in a `fast` space. Constants come
from a read-only table at `0x400`, and names from a pointer table at
`0x500`. `CACHE` entries are folded into their instruction, and calls
copy their arguments to `a0..a3`. The code objects come from
the host's Python 3.12 (`f.__code__.co_code`), unmodified:

```c
long entry(long param_1,long param_2)     // def add(a, b): c = a + b; if c > 10: c -= 3; return c * 2
{
  param_1 = param_1 + param_2;
  if (10 < param_1) {
    param_1 = param_1 + -3;
  }
  return param_1 * 2;
}

long entry(undefined8 param_1)            // def g(xs): s = 0; for x in xs: s += len(x); return s
{
  ...
  lVar3 = 0;
  uVar1 = py_getiter(param_1);
  while (lVar4 = py_next(uVar1), lVar4 != 0) {
    uVar2 = py_global(0x600);
    lVar4 = (*(code *)uVar2)(lVar4);
    lVar3 = lVar3 + lVar4;
  }
  return lVar3;
}
```

What it took, and what the first attempts showed:

- With parameters as inputs in the `fast` space and arguments left on
  the stack, the call lost its argument and the accumulator, and the
  function returned `in_stack_00000000`. The fix was fixed argument
  registers, a static entry copy, and the `fast` space marked unaffected.
- The name `len` is `0x600`, a pointer to the string, until the loader
  labels the name table.
- The types are integers.
- Exception handlers are invisible: they're reachable only through
  `co_exceptiontable`.

### E5: Lua 5.4 as a SLEIGH processor

`lua54.slaspec` (about 90 lines) covers eighteen opcodes over Lua 5.4's real encoding.
The opcode numbers and field layout were checked against `lopcodes.h`,
and the jump and loop semantics against `lvm.c`, both 5.4.6. Each
arithmetic opcode takes its `MMBIN`, and each comparison its `JMP`, as
one instruction. `R[n]` is `stk:n*8`, and `K[]` is a read-only table.
There is no `luac` on this host, so the three functions were assembled
by hand as `luac` 5.4 compiles them:

```c
long entry(long param_1)                  // function g(n) local s = 0; for i = 1, n do s = s + i end; return s end
{
  long lVar1; long lVar2;
  lVar1 = 0;
  if (0 < param_1) {
    lVar2 = 1;
    do {
      lVar1 = lVar1 + lVar2;
      lVar2 = lVar2 + 1;
    } while (lVar2 <= param_1);
  }
  return lVar1;
}

undefined8 entry(undefined8 param_1)      // function h(x) return tostring(x) end
{
  undefined8 uVar1;
  uVar1 = lua_gettabup(0,0x600);
  uVar1 = (*(code *)uVar1)(param_1);
  return uVar1;
}
```

`f` (the same arithmetic as `add`) gives the same C as E2. The register
VM needed none of CPython's stack tricks, only the argument registers and
the static entry copy. The numeric `for` was modelled with its step's
sign tested. Lua 5.4 keeps an iteration count rather than the limit,
which a faithful spec would mirror.

### E6: the vendored SLEIGH compiler

Built from the fork's `slgh_compile.cc`, `slghparse.cc` and `slghscan.cc`
against `libghidra_decomp.a` (three files). It compiles the following:

- `JVM.slaspec`, `Dalvik_DEX_Android12.slaspec` and `eBPF_le.slaspec`,
  each byte-identical to the `.sla` Ghidra ships;
- the two sketches, each byte-identical to the output of Ghidra's Java
  compiler (`support/sleigh`).

revkit can therefore compile its own processors, or generated
per-version specs, with no Java (the wishlist's "SLEIGH compiler" item).

### E7: eBPF and .NET as they loaded before step 1

Both are fixed now: `EM_BPF` maps to the eBPF language, and a .NET
assembly is recognised by its CLR header ([What revkit has
today](#what-revkit-has-today)).

- **eBPF**: `clang -O2 -target bpfel -c` builds a socket filter. On that
  object, `rk-lift` says `no Ghidra language for machine 247; use --lang`.
  With `--lang eBPF:LE:64:default:default` it discovers `filt` and
  decompiles it correctly, with the loop unrolled as clang emitted it:
  `return param_1[1] == 6 && 3 < (uVar1 >> 7 & 1) + ... + (uVar1 & 1);`.
- **.NET**: a `net10.0` class library loads as `x86:LE:32:default`, with
  one function, `entry`, of IL decoded as x86.

### E8: .NET through ilspycmd

`ilspycmd` 11.1 (ICSharpCode.Decompiler, MIT) on the same library
prints the class as written: `Add`, `Sum` as `foreach`, `GetF`, and
`Hello` as `return "hi " + n.Length;`. It takes about a second. This is
the output an external provider gives at no lifting cost.

## Plan

| Phase | What | Effort |
| --- | --- | --- |
| 0. Quick fixes | ~~`EM_BPF` to eBPF (and BE); recognise CLR headers and skip x86 discovery of IL, with a warning; name `.pyc` (by magic table), Lua and LuaJIT chunks, Hermes, `bytenode` and V8 caches, `YARB`, `OPCACHE`, BEAM~~ *done* (2026-10-18); Dart snapshots in detection | S |
| 1. Extraction | ~~container formats: PyInstaller CArchive and PYZ (adding `.pyc` headers to scripts), `asar`, pkg, nexe, Node SEA, Bun; Lua chunk carving in blobs~~ *done* (2026-10-18); py2exe's `PYTHONSCRIPT`, Deno, Nuitka onefile; AutoIt and AutoHotkey scripts from resources; .NET embedded resources and single-file bundles | M |
| 2. Providers (**built**: [providers.md](providers.md)) | an `ExternalDecompiler` provider kind: a configured command per format, run in the worker sandbox with time and memory limits, the output cached by content hash and shown as source (decompiler pane, files in the container browser), API and MCP tool to fetch it. Providers: ilspycmd, jadx, Vineflower or CFR, unluac, pycdc, webcrack, wasm-decompile | M, then S each |
| 3. JVM and Dalvik | the `.class` and DEX loaders (the language from the DEX version); the entry and call-other injection library and the constant pools in the worker (ported from Ghidra, Apache-2.0); the bundle's managed-metadata part and its prediction; the Java printer; per-address context for `alignmentPad`; exception handlers as entry points | M |
| 4. SLEIGH toolchain | build `rk-sleigh` from the fork; a revkit processors directory beside Ghidra's (shipped specs, generated ones); a generator from opcode tables to `.slaspec` | S to M |
| 5. Lua | chunk loader (all versions; protos as functions, `K[]` and upvalue tables laid out, names from debug info); generated specs for 5.1 to 5.4 and LuaJIT 2.0 and 2.1, permuted tables as input; varargs and multiple results through call-other ops | M |
| 6. Python 3.11+ | `.pyc` loader (marshal, code objects as functions, consts and names laid out or as constant pool); specs generated per minor version from CPython's opcode metadata; exception-table handlers as entry points; an `object` core type | L |
| 7. Wasm | module loader; the stack-height pre-pass painting context; the spec | M to L |
| Later | Hermes (generated from `BytecodeList.def`), Dart AOT metadata, a Lua or Python `PrintLanguage`, CIL SLEIGH, EVM | L each |

Phases 0 to 2 give the most for the least, and need no decompiler work.
Phase 3 is the strongest case for the p-code route, being already proven.
Phases 5 and 6 are where revkit can be better than the existing tools, not
just equal to them.

## Where it goes in revkit

- **Loaders** (`src/loader`): a new `Format` per container of code
  (`java_class`, `dex`, `pyc`, `lua_chunk`, `wasm`), each a parser that
  fills an `Image`, as `parse_elf` and `parse_pe` do:
  - blocks in the language's spaces (`constantPool`, the method code in
    `ram`);
  - a function range and a symbol per method or proto;
  - the language from the header.
  `guess_language` maps them. Per-function context (the base of a
  proto's constant table, JVM's `alignmentPad`) goes through
  `FunctionFacts::context`, which needs a per-address form for the JVM.
- **Languages**: Ghidra's JVM, Dalvik and eBPF as they are. revkit's own
  specs come from a processors directory searched after the Ghidra root
  (`SleighArchitecture`'s spec paths take several directories), built by
  `rk-sleigh`.
- **The decompiler** (`src/lift/image_arch.cc`, `src/decompd`): override
  `buildPcodeInjectLibrary` and `buildConstantPool` for managed languages
  with revkit's classes. These are fed from a new bundle part holding the
  method metadata and the constant-pool entries the p-code references. A
  bundle format change means a new hash prefix, which other workers'
  repros record. Set `setlanguage` per language. Everything stays in the
  worker process, so a crash in the new code costs one function, as now.
- **Containers** (`src/container`): each packer is a `FileSystem` opener
  like `open_uimage`. It is recognised by its magic or trailer, has
  bounded reads (hostile input) and is fuzzed like the rest.
- **Providers**: a sibling of `rk-decompd`. The daemon starts the
  configured tool on the extracted file, in a scope with limits, and
  stores the result as a derived artifact keyed by the input's hash. As
  built: `src/providers` (definitions, detection, the sandbox, the cache),
  `tools/rk-sandbox` (the helper that confines itself and runs the tool),
  `ProviderService` in the daemon; results are files in the project's
  data directory, not facts ([providers.md](providers.md)).

## Licensing

revkit is AGPL-3.0. Running a tool as a separate program (a provider)
raises no licence question, whatever its licence. Porting or vendoring
code needs a licence compatible with AGPL-3.0: Apache-2.0, MIT, BSD,
GPL-3.0 and AGPL-3.0 all are. GPL-2.0-only isn't. Licences checked against
the projects' repositories (2026-10-16):

| Project | Licence | Use |
| --- | --- | --- |
| Ghidra (JVM, Dalvik processors; `PcodeInjectLibraryJava`, `ConstantPoolJava`, `PcodeInjectLibraryDex`, `ConstantPoolDex`, the loaders) | Apache-2.0 | port to C++ with a header naming the source |
| pycdc (Decompyle++) | GPL-3.0 | provider, or vendor |
| uncompyle6, decompyle3, pylingual | GPL-3.0 | provider |
| pyinstxtractor, pyinstxtractor-ng | GPL-3.0 | reference; PyInstaller's format is simple enough to implement from its own documentation |
| CPython (opcode metadata) | PSF | generate specs from it |
| unluac | MIT | provider, or port |
| luajit-decompiler-v2 | no clear licence | provider only |
| Lua, LuaJIT | MIT | generate specs from `lopcodes.h`, `lj_bc.h` |
| jadx | Apache-2.0 | provider |
| Vineflower, Fernflower | Apache-2.0 | provider |
| CFR | MIT | provider |
| ILSpy / ICSharpCode.Decompiler | MIT | provider (`ilspycmd`) |
| dnSpy (dnSpyEx), de4dot | GPL-3.0 | provider |
| WABT (wasm-decompile) | Apache-2.0 | provider, or link |
| ghidra-wasm-plugin | GPL-3.0 | port the spec and pre-analysis |
| webcrack | MIT | provider |
| wakaru | Apache-2.0 | provider |
| Hermes (`BytecodeList.def`) | MIT | generate specs |
| hermes-dec | AGPL-3.0 | provider, or vendor |
| hbctool | MIT | provider, or port |
| bytenode, pkg, nexe, asar | MIT | format references |
| JerryScript | Apache-2.0 | format reference |
| blutter | MIT | reference for Dart snapshots |
| AutoIt-Ripper | MIT | reference for AutoIt extraction |
| heimdall-rs, panoramix | MIT | EVM providers |
| Nuitka | AGPL-3.0 | format reference (onefile) |
