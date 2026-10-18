// A revkit::api::Backend that serves real ELF and PE binaries.
//
// Programs are loaded with revkit::loader, listed and lifted with SLEIGH
// (revkit::lift) and decompiled by Ghidra's decompiler in process. Each
// project is one revkit::facts::FactDb: user, agent and importer edits are
// its assertions (precedence, retraction, blame, bulk revert), API
// revisions are its revisions, and everything derived from a program
// (functions, listing, xrefs, decompilations) is a memoized fact-store
// query. With a project directory, projects persist in LMDB and reopen
// with their assertions and cached derived facts.
//
// See docs/backend.md for what is derived and how it is invalidated.
#pragma once

#include "revkit/inputs/param_id.h"

#include "revkit/api/backend.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace revkit::plugins {
class Host;
}
namespace revkit::facts {
class Engine;
}

namespace revkit::backend {

enum class InferMode { off, automatic, on };

struct ImageBackendOptions {
  // Ghidra install with the processor specs (.ldefs, .sla, .pspec, .cspec).
  std::string ghidra_root;
  // Revisions kept readable per project (ReadOptions.revision).
  std::uint32_t retained_revisions = 256;
  std::string server_version = "rk-daemon (image backend)";
  // A project created at startup, so clients can import without opening
  // one first. Empty: none.
  std::string default_project = "default";
  // Per program: decompiler instances (each held by one thread at a time)
  // and SLEIGH engines for listing pages and instruction detail.
  unsigned decompilers_per_program = 2;
  unsigned lifters_per_program = 4;
  // SLEIGH engines idle this long are parked (docs/memory.md "SLEIGH
  // engines"): their decoded .sla goes to their language's spares, shared by
  // every program of the language, and the next use takes one back (a reset,
  // not a decode). Checked as often; 0: never.
  unsigned engine_idle_seconds = 15;
  // Decompiler worker processes (rk-decompd) shared by every program: at
  // most this many decompilations run at once (0: decompilers_per_program).
  // A worker that crashes, hangs past its deadline or runs out of memory
  // costs that decompilation only (DecompileResponse.failure).
  unsigned decompile_workers = 0;
  // Debugging only (under gdb): decompile in the daemon's process. A crash
  // in the decompiler then ends the daemon.
  bool decompile_in_process = false;
  // Bounds on one decompilation (lift::DecompileLimits): a timeout, which
  // a request's DecompileOptions.timeout_ms replaces and its deadline
  // shortens (0: none; rk-daemon sets Ghidra's 30 s), and the varnodes a
  // function may grow to, about 1 KB each (0: none). A run over either is
  // a decompiler failure (timeout, oom), memoized as its output is; a
  // timeout may be retried once with a longer deadline (DecompileOptions.
  // escalate).
  double decompile_timeout_seconds = 0;
  std::size_t decompile_max_varnodes = std::size_t{1} << 20;
  // Projects live in <project_dir>/<project id>/ (LMDB) and are reopened at
  // startup. Empty: in memory, gone when the backend is.
  std::string project_dir;
  // Directories ListHostFiles may list (rk-daemon --browse-root). Empty:
  // browsing the host is off.
  std::vector<std::string> browse_roots;
  // Import debug info (DWARF; a PE's matching PDB) as import:dwarf and
  // import:pdb assertions: names, prototypes and types.
  bool import_debug_info = true;
  // Microsoft-specific analysis of a PE at import (docs/pe.md): MSVC RTTI
  // and vftables, the PE headers and directories and exception data as
  // analysis:msvc and analysis:pe assertions (typed data, names, functions,
  // virtual methods' `this`); also a Mach-O's Objective-C and Swift
  // metadata (analysis:objc, analysis:swift) and a Go program's function
  // table (analysis:go, docs/go.md).
  bool import_pe_analysis = true;
  // Where Load PDB looks a program's PDB up (docs/pdb.md "Symbol
  // servers"): _NT_SYMBOL_PATH syntax; whether it may download from the
  // servers the path names (off by default: network access,
  // docs/security.md); and where downloads go when an entry names no
  // cache ("": <project_dir>/.revkit/symbols, or none without a project
  // directory). SetSymbolSettings changes them while running; with a
  // project directory they are kept in <project_dir>/.revkit/symbols.json.
  std::string symbol_path;
  bool symbol_downloads = false;
  std::string symbol_cache;
  // Separate debug files for ELF (docs/backend.md "External debug files"):
  // directories searched as /usr/lib/debug is (by build ID and debuglink),
  // whether debuginfod servers may be contacted (off by default: network
  // access, docs/security.md), which (https only unless http is allowed),
  // and the largest file and the cache's size (0: 1 GiB, 4 GiB). Fetched
  // and loaded files are kept in <project_dir>/.revkit/debuginfod. Kept
  // with the symbol settings.
  std::vector<std::string> debug_dirs;
  bool debuginfod = false;
  std::vector<std::string> debuginfod_urls;
  bool debuginfod_allow_http = false;
  std::uint64_t debug_file_max_bytes = 0;
  std::uint64_t debug_cache_max_bytes = 0;
  // External decompilers (docs/providers.md, api_minor 92): all of them on
  // or off, tools' paths ("jadx=/opt/jadx/lib/jadx-1.5.6-all.jar"), the
  // ones turned off, the per-run timeout and memory (0: 120 s, 4 GiB), and
  // whether they may run where the kernel has no Landlock.
  // SetProviderSettings changes them while running; with a project
  // directory they are kept in <project_dir>/.revkit/providers.json (read
  // at startup unless provider_options_given) and results are cached in
  // <project_dir>/.revkit/providers/.
  bool providers = true;
  std::vector<std::string> provider_paths;
  std::vector<std::string> providers_disabled;
  double provider_timeout_seconds = 0;
  std::uint64_t provider_memory_bytes = 0;
  bool provider_allow_weak_sandbox = false;
  bool provider_options_given = false;
  // Threads for import-time analysis (function discovery, references);
  // 0: the hardware's, at most 8.
  unsigned analysis_threads = 0;
  // revkit::infer's prototypes (docs/infer.md): inferred in the background
  // after import and on reopen, never during them, and published to the
  // decompiler when inference reaches its fixpoint (an analysis job,
  // "infer.prototypes", with progress; CancelAnalysis stops it), for the
  // functions nothing asserts a prototype for and no debug info or library
  // archive gives one. Automatic: in programs without debug info where
  // inference knows the calling convention (infer::supports: x86-64,
  // AArch64, RISC-V 64), as rk-lift; on: every program; off: none.
  // rk-daemon's default is automatic; the library's off, so embedders and
  // tests see the decompiler's own prototypes unless they ask.
  InferMode infer_prototypes = InferMode::off;
  // Function ID (docs/fid.md): names library functions in PE and ELF
  // programs in the background after import, from the databases attached
  // (Ghidra's shipped ones under ghidra_root, the user's, the project's).
  // rk-daemon's default is on; the library's off, so embedders and tests
  // see discovery's names unless they ask.
  bool function_id = false;
  // Ghidra's Decompiler Parameter ID (docs/param-id.md): where Ghidra runs
  // it (automatic: a PE below 2 MiB of addresses), always, or never. It
  // runs in the background after import and after each edit, using at most
  // decompile_workers - 1 workers; decompilations show the signatures it
  // commits as they arrive. Inference (infer_prototypes) refines it.
  inputs::ParamIdMode param_id = inputs::ParamIdMode::automatic;
  // Resident derived facts per project, in bytes. Over it, memos are
  // evicted (spilled to the project directory when there is one).
  std::size_t memo_budget = std::size_t{2} << 30;
  // WebAssembly plugins (docs/plugins.md): loaders tried for files the
  // built-in loaders don't recognise, analyzers served by GetPluginFacts,
  // commands run by RunCommand. Null: no plugins (PluginService answers
  // with an empty list).
  std::shared_ptr<plugins::Host> plugins;
  // DebugService's live targets (docs/debugger.md): connecting to GDB
  // remote stubs and launching or attaching to processes on this host
  // (rk-daemon --debug-live). Off: the emulator and saved traces only.
  bool debug_live = false;
};

// Throws revkit::lift::LiftError if ghidra_root is not a Ghidra install.
std::unique_ptr<api::Backend> MakeImageBackend(ImageBackendOptions options);

// Fact-engine counters of one project's rules (queries.h), by rule name,
// since the last reset: how much an edit or a reopen recomputed. For tests
// and benchmarks; `backend` must come from MakeImageBackend.
struct RuleCounters {
  std::uint64_t executions = 0;   // computed
  std::uint64_t validations = 0;  // re-checked by fingerprint, not recomputed
  std::uint64_t hits = 0;         // memo valid at the revision read
  std::uint64_t loads = 0;        // read back from the project directory
};
std::map<std::string, RuleCounters> QueryCounters(api::Backend &backend, const std::string &project_id);
// A project's fact engine (its head: engine.snapshot()), for jobs over a
// snapshot (SignatureJob) and tests.
facts::Engine &ProjectEngine(api::Backend &backend, const std::string &project_id);
void ResetQueryCounters(api::Backend &backend, const std::string &project_id);

}  // namespace revkit::backend
