// The backend's fact-store queries: everything it derives from a program,
// each a rule with a name and version (the name is what blame and
// FactOrigin.derived.rule report). All of them, function discovery's
// (src/analysis) included, are registered by RegisterQueries.
//
// Inputs are the assertion log (facts::AssertedFact and its key index),
// the program's bytes (the file's, and the loaded image's that analysis
// decodes), and the inputs set at import: the program's source, analysis's
// ProgramInfo, the project's program list and the decompiler options.
// Every value below is a pure function of those, so a memo is valid
// exactly as long as the facts it read, which is how a rename re-decompiles
// only the functions that looked the name up, and an asserted entry point
// re-runs only the discovery and decompilations it changes.
//
//   analysis.*         function discovery, keyed by program id     <- image bytes, ProgramInfo,
//                                                                     FUNCTION_BOUNDS and
//                                                                     FLOW_OVERRIDE assertions
//   functions.table    analysis's functions and bodies             <- analysis.functions
//   names.loader       non-function symbols, import slots          <- source, analysis seeds
//   listing.code       instruction spans discovery reached         <- analysis.functions
//   xrefs.function     one function's references, jump tables      <- analysis.function/flow
//   listing.user_data  user data relaid by bound type names         <- analysis.data, types.closure/resolved
//   xrefs.static       every function's, by from and by to;        <- functions.table, xrefs.function,
//                      data pointers (user and analysis)              analysis.data, listing.user_data
//   names.default      loader names + FUN_/LAB_/DAT_ targets, data  <- names.loader, functions.table,
//                                                                     xrefs.static
//   listing.rows       row <-> address, a row per data item        <- listing.code, names.default,
//                                                                    analysis.data
//   listing.page       256 rows: bytes, SLEIGH tokens, flow        <- listing.rows
//   listing.search_page  a page as the searches read it: each row's  <- listing.rows
//                      text and the scalars in it (SearchRow)
//   listing.header_*   header lines above code units (header_rows), <- listing.rows, functions.table,
//                      per 64 KiB bucket, and the buckets' index       names.default, NAME and
//                                                                     plate/pre COMMENT keys there
//   symbols.effective  name, kind, size, type, no-return at one    <- analysis.function, NAME/TYPE
//                      address                                        assertions there, names.default
//   symbols.container  the sized label around one address          <- names.default
//   types.closure      a type hash and every type it reaches       <- TYPE_DEF assertions
//   types.names        named types and BindTypeName bindings       <- TYPE_DEF assertions
//   types.resolved     a closure with bound names substituted      <- TYPE_DEF assertions, the
//                                                                     bindings of names it reaches
//   decompile.inputs   body, comments, flow overrides, jump tables <- analysis.function/flow, COMMENT
//                                                                     and FLOW_OVERRIDE keys in the body
//   plugins.*          analyzer plugins and the facts they read    <- plugins.program, analysis.*,
//                      (src/plugins, docs/plugins.md)                 pages, NAME assertions
//   decompile.ghidra   Ghidra's output for one function            <- source, options, inputs, and
//                                                                     symbols.effective/container and
//                                                                     types.closure for every address
//                                                                     and prototype the decompiler
//                                                                     looked up
#pragma once

#include "library_types.h"
#include "model.h"

#include "revkit/analysis/analysis.h"
#include "revkit/analysis/data.h"
#include "revkit/facts/fact_db.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace revkit::backend::q {

// --- Inputs ------------------------------------------------------------------

struct Source {
  static constexpr std::string_view name = "program.source";
  using Key = std::string;  // program id
  using Value = ProgramSource;
};

// The separate debug file a program read at load (debug_files.h): its path
// and size, "" when none. Staged with Source; the queries that read
// Program::debug() read it too, so a debug file found (or gone) since their
// memos were made recomputes them.
struct DebugFile {
  static constexpr std::string_view name = "program.debug_file";
  using Key = std::string;  // program id
  using Value = std::string;
};

// Programs in the project at a revision, in import order.
struct Programs {
  static constexpr std::string_view name = "project.programs";
  using Key = std::uint8_t;  // always 0
  using Value = std::vector<std::string>;
};

// Everything about the decompiler's configuration that changes its output
// (the Ghidra version, printer and options), as one string per program.
struct DecompilerOptions {
  static constexpr std::string_view name = "decompiler.options";
  using Key = std::string;
  using Value = std::string;
};

// --- Derived -----------------------------------------------------------------

using ProgramKey = std::string;                           // program id
using AddressKey = std::pair<std::string, std::uint64_t>;  // (program id, address)

struct LoaderNames {
  static constexpr std::string_view name = "names.loader";
  static constexpr std::uint32_t version = 4;  // 3: the memory map (docs/memory-map.md); 4: demangled (docs/demangle.md)
  using Key = ProgramKey;
  using Value = LabelMap;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

struct Functions {
  static constexpr std::string_view name = "functions.table";
  static constexpr std::uint32_t version = 3;  // 3: demangled names (docs/demangle.md)
  using Key = ProgramKey;
  using Value = FunctionTable;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

struct Code {
  static constexpr std::string_view name = "listing.code";
  static constexpr std::uint32_t version = 3;  // 2: Thumb spans; 3: the memory map
  using Key = ProgramKey;
  using Value = CodeMap;
  static Value compute(facts::QueryContext &ctx, const Key &program);
  static std::size_t weight(const Value &v);
};

struct FunctionXrefs {
  static constexpr std::string_view name = "xrefs.function";
  static constexpr std::uint32_t version = 4;  // 2: operands resolved when served; 3: the memory map; 4: user flags
  using Key = AddressKey;  // (program, entry)
  using Value = std::vector<StaticXref>;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::size_t weight(const Value &v) { return sizeof(Value) + v.capacity() * sizeof(StaticXref); }
};

// The user's data definitions (analysis.data's kDataUser items) whose
// element type reaches a name a BindTypeName binds to another definition
// (types.resolved differs from types.closure): each laid out again from the
// bound definition, as the decompiler sees it, with the references its
// pointers make. The item keeps its extent and stride (the CODE_UNIT mark's
// length and element size, which discovery and the other edits go by):
// fields and pointers past the element are left out. Usually empty.
struct UserData {
  static constexpr std::string_view name = "listing.user_data";
  static constexpr std::uint32_t version = 1;
  using Key = ProgramKey;
  using Value = std::vector<analysis::DataItem>;  // by address
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

struct Xrefs {
  static constexpr std::string_view name = "xrefs.static";
  static constexpr std::uint32_t version = 6;  // 4: references from the user's data; 5: from analysis's pointers,
                                               // user data laid out by bound names (listing.user_data);
                                               // 6: user references (REFERENCE keys)
  using Key = ProgramKey;
  using Value = XrefTable;
  static Value compute(facts::QueryContext &ctx, const Key &program);
  static std::size_t weight(const Value &v);
};

struct DefaultNames {
  static constexpr std::string_view name = "names.default";
  static constexpr std::uint32_t version = 5;  // 3: data analysis's names; 4: the memory map; 5: demangled names
  using Key = ProgramKey;
  using Value = LabelMap;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

struct Rows {
  static constexpr std::string_view name = "listing.rows";
  static constexpr std::uint32_t version = 6;  // 3: data rows; 4: the memory map; 5: the user's data, field rows;
                                               // 6: user data laid out by bound names (listing.user_data)
  using Key = ProgramKey;
  using Value = RowIndex;
  static Value compute(facts::QueryContext &ctx, const Key &program);
  static std::size_t weight(const Value &v);
};

struct Page {
  static constexpr std::string_view name = "listing.page";
  // 2: instructions' flow and targets; 3: data rows; 4: patched bytes; 5: patches through patch.page; 6: the memory map;
  // 7: the listing's edits (typed data, field rows); 8: scalar tokens' widths; 9: data settings
  static constexpr std::uint32_t version = 9;
  using Key = std::pair<std::string, std::int64_t>;  // (program id, page)
  using Value = std::vector<StaticRow>;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::size_t weight(const Value &v);
};

// A listing page as the searches read it (SearchRow), decoded on its own
// rather than from listing.page, so a search through a large program
// neither keeps nor evicts the full pages the listing view uses.
struct SearchPage {
  static constexpr std::string_view name = "listing.search_page";
  static constexpr std::uint32_t version = 2;  // 2: data settings
  using Key = std::pair<std::string, std::int64_t>;  // (program id, page)
  using Value = std::vector<SearchRow>;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::size_t weight(const Value &v);
};

// Header lines above code units for GetListing's header_rows numbering
// (plate and pre-comment lines, function signatures, labels), per 64 KiB
// bucket of addresses: a name or plate/pre comment asserted in a bucket
// re-runs that bucket and the (small) index of buckets, nothing else.
struct HeaderBucket {
  static constexpr std::string_view name = "listing.header_bucket";
  static constexpr std::uint32_t version = 1;
  using Key = AddressKey;  // (program id, address >> facts::kBucketShift)
  using Value = backend::HeaderBucket;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::size_t weight(const Value &v) { return sizeof(Value) + v.entries.capacity() * sizeof(Value::Entry); }
};

// The buckets that may have header lines: those with a function, a default
// label, or an asserted name or comment.
struct HeaderSlots {
  static constexpr std::string_view name = "listing.header_slots";
  static constexpr std::uint32_t version = 1;
  using Key = ProgramKey;
  using Value = std::vector<std::uint64_t>;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

struct Headers {
  static constexpr std::string_view name = "listing.headers";
  static constexpr std::uint32_t version = 2;
  using Key = ProgramKey;
  using Value = HeaderIndex;
  static Value compute(facts::QueryContext &ctx, const Key &program);
  static std::size_t weight(const Value &v) { return sizeof(Value) + v.buckets.capacity() * sizeof(HeaderIndex::Bucket); }
};

struct Symbol {
  static constexpr std::string_view name = "symbols.effective";
  static constexpr std::uint32_t version = 6;  // 4: the memory map; 5: the user's data definitions' types;
                                               // 6: demangled names, the type's rank
  using Key = AddressKey;
  using Value = SymbolInfo;
  static Value compute(facts::QueryContext &ctx, const Key &key);
};

// The demangler analysis (docs/demangle.md): the scopes the program's
// mangled symbols show are classes (inputs::ClassScopes), and one
// function's prototype from its mangled name (none where it has none, or
// where cparse can't read it). What the decompiler is told comes from
// revkit::inputs (inputs.program); these say the same for the API.
struct DemangleScopes {
  static constexpr std::string_view name = "analysis.demangler.scopes";
  static constexpr std::uint32_t version = 1;
  using Key = ProgramKey;
  using Value = std::vector<std::string>;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

// MSVC RTTI's classes (docs/pe.md): revkit::msvc::scan_rtti over the
// program's image (with the memory map's edits), as GetClassHierarchy's
// classes, deterministic protobuf bytes; effective names are the handler's.
struct RttiClasses {
  static constexpr std::string_view name = "msvc.classes";
  static constexpr std::uint32_t version = 1;
  using Key = ProgramKey;
  using Value = std::string;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

struct Demangled {
  static constexpr std::string_view name = "analysis.demangler";
  static constexpr std::uint32_t version = 1;
  using Key = AddressKey;  // (program, function entry)
  using Value = std::optional<DemangledProto>;
  static Value compute(facts::QueryContext &ctx, const Key &key);
};

// The asserted types of a function's parameters and locals (retypes of
// "local:<storage key>"), with the storage each key names, for the
// decompiler (own_inputs.cc); by key. Key: (program, function entry).
struct VariableTypes {
  static constexpr std::string_view name = "symbols.variable_types";
  static constexpr std::uint32_t version = 1;
  using Key = AddressKey;
  using Value = std::vector<VariableType>;
  static Value compute(facts::QueryContext &ctx, const Key &key);
};

// Start of the sized default label whose extent covers an address (not the
// address itself), or the address when there is none.
struct Container {
  static constexpr std::string_view name = "symbols.container";
  static constexpr std::uint32_t version = 1;
  using Key = AddressKey;
  using Value = std::uint64_t;
  static Value compute(facts::QueryContext &ctx, const Key &key);
};

struct Types {
  static constexpr std::string_view name = "types.closure";
  static constexpr std::uint32_t version = 2;  // 2: project-scope types
  using Key = std::pair<std::string, std::string>;  // (program id, type hash)
  using Value = TypeClosure;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::size_t weight(const Value &v);
};

// revkit's library archives parsed for the program's target
// (inputs/library.h): the prototypes inputs.program applies to imports by
// name and the named types types.library lists. Computed in each process
// (the value holds a type store), its encoding the archives' identity.
struct LibraryRef {
  std::string identity;  // empty: no archives
  std::shared_ptr<const inputs::LibraryPrototypes> lib;
  bool ghidra = true;  // Ghidra's .gdt archive after them
  void encode(facts::Encoder &e) const {
    e.bytes(identity);
    e.u8(ghidra ? 1 : 0);
  }
  static LibraryRef decode(facts::Decoder &d) {
    LibraryRef r;
    r.identity = std::string(d.bytes());
    r.ghidra = d.u8() != 0;
    return r;
  }
};
// The project's type archive settings (AssertionBody.type_archive): the
// library archives turned off, and the archives attached, by name.
struct TypeArchiveSetting {
  std::string name;
  bool enabled = true;
  bool attached = false;  // an attached archive (with its header), else a shipped one's switch
  std::string header, sidecar;
  void encode(facts::Encoder &e) const;
  static TypeArchiveSetting decode(facts::Decoder &d);
  friend bool operator==(const TypeArchiveSetting &, const TypeArchiveSetting &) = default;
};
struct TypeArchiveSettings {
  static constexpr std::string_view name = "types.archive_settings";
  static constexpr std::uint32_t version = 1;
  using Key = std::uint8_t;  // always 0: the project
  using Value = std::vector<TypeArchiveSetting>;
  static Value compute(facts::QueryContext &ctx, const Key &);
};

struct LibraryPrototypes {
  static constexpr std::string_view name = "library.prototypes";
  static constexpr std::uint32_t version = 2;  // 2: the project's archive settings
  static constexpr bool persistent = false;
  using Key = ProgramKey;
  using Value = LibraryRef;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

// The library archive's named types for the program (library_types.h):
// browsable and usable by hash like the program's own, never asserted.
struct Library {
  static constexpr std::string_view name = "types.library";
  static constexpr std::uint32_t version = 2;  // 2: revkit's archives (library.prototypes), then Ghidra's
  using Key = ProgramKey;
  using Value = LibraryTypes;
  static Value compute(facts::QueryContext &ctx, const Key &program);
  static std::size_t weight(const Value &v);
};

// The program's named types and name bindings (BindTypeName), from every
// TYPE_DEF key: what FindTypes searches and ResolvedTypes substitutes by.
struct TypeNames {
  static constexpr std::string_view name = "types.names";
  static constexpr std::uint32_t version = 2;  // 2: project-scope types
  using Key = ProgramKey;
  using Value = NamedTypes;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

// Every struct and union the program defines (its TYPE_DEF records: debug
// info, DefineType, anonymous ones too) and the library archive's, by the
// id the decompiler knows it by (inputs::GhidraTypes: the struct kind's id
// range with the first 6 bytes of the hash), sorted: what names a FIELD
// token's parent (CodeToken.parent_type_hash, feature "field-tokens").
struct AggregateIds {
  static constexpr std::string_view name = "types.aggregate_ids";
  static constexpr std::uint32_t version = 2;  // 2: project-scope types
  using Key = ProgramKey;
  using Value = std::vector<std::pair<std::uint64_t, std::string>>;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

// The categories named types are filed under (SetTypeCategory: TYPE_DEF
// "category:<key>" = path): named key -> path, by key. Apart from
// types.names so filing a type never touches what the decompiler reads.
struct TypeCategories {
  static constexpr std::string_view name = "types.categories";
  static constexpr std::uint32_t version = 2;  // 2: project-scope types
  using Key = ProgramKey;
  using Value = std::vector<std::pair<std::string, std::string>>;
  static Value compute(facts::QueryContext &ctx, const Key &program);
};

// types.closure as uses see it: wherever the closure reaches a named type
// whose name a BindTypeName binds to another definition, that definition
// (and what it reaches) stands in for it, under the original hash too, so
// interning the records makes both one type. This is how an edited type
// reaches prototypes and displays that pinned the old one. GetTypes reads
// types.closure, never this. Reads only the bindings of the names it meets.
struct ResolvedTypes {
  static constexpr std::string_view name = "types.resolved";
  static constexpr std::uint32_t version = 2;  // 2: project-scope types
  using Key = std::pair<std::string, std::string>;  // (program id, type hash)
  using Value = TypeClosure;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::size_t weight(const Value &v) { return Types::weight(v); }
};

struct Inputs {
  static constexpr std::string_view name = "decompile.inputs";
  static constexpr std::uint32_t version = 4;  // 3: the user's equates, call targets and jump tables; 4: calls'
                                               // signature overrides
  using Key = AddressKey;
  using Value = DecompileInputs;
  static Value compute(facts::QueryContext &ctx, const Key &key);
};

struct Decompile {
  static constexpr std::string_view name = "decompile.ghidra";
  static constexpr std::uint32_t version = 16;  // 4: decompiled in a worker from a bundle; failures are values; 5: labels of
                                               // the function's own jump targets outside every body; 6: patched bytes
                                               // through patch.page; 7: inferred prototypes through infer.published;
                                               // 8: pointer accesses (auto-struct); 9: variable types committed
                                               // (symbols.variable_types); 10: prototypes' calling
                                               // conventions; 11: FIELD tokens' parents and offsets; 12: the
                                               // user's equates and references, constants' hashes; 13: demangled
                                               // names and prototypes (bundle version 4); 14: calls' signature
                                               // overrides, TYPE tokens' struct ids (bundle version 5); 15: accesses
                                               // through loaded values by path key ("param:0->0x20"); 16: the
                                               // data-flow graph and tokens' ops (slices)
  using Key = AddressKey;
  using Value = DecompileOutput;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::size_t weight(const Value &v);
};

}  // namespace revkit::backend::q

namespace revkit::backend {

// Registers the inputs and every query above on a project's engine.
void RegisterQueries(facts::Engine &engine);

// The program as the memory map at the reader's revision lays it out
// (docs/memory-map.md): ProgramSource::program with analysis.memory's
// edits, Program::WithMemory. Through a query context, the source and the
// map become the query's dependencies.
std::shared_ptr<const Program> EffectiveProgram(facts::QueryContext &ctx, const std::string &program);
std::shared_ptr<const Program> EffectiveProgram(const facts::Snapshot &snap, const std::string &program);
// Bytes staged for a region (AddMemoryRegion), by their sha256: building a
// variant takes them from here rather than reading their pages again.
void RememberRegionBytes(const std::string &sha256, std::shared_ptr<const loader::Bytes> bytes);

// Fact keys of a program's facts: `space` is its ProgramSource::ram_space.
facts::FactKey FactKeyAt(facts::FactKind kind, facts::SpaceId space, std::uint64_t address, std::string sub = {});
facts::FactKey TypeDefKey(facts::SpaceId space, const std::string &hash);

// The value a FUNCTION_BOUNDS assertion with remove = true asserts:
// analysis's "no function starts here".
inline constexpr std::int64_t kRemovedFunction = analysis::kNotAFunction;

// Analysis's key for a program.
inline analysis::ProgramKey AnalysisKey(const std::string &program) { return {program}; }

// The decompiler configuration recorded in q::DecompilerOptions.
std::string DefaultDecompilerOptions();

}  // namespace revkit::backend
