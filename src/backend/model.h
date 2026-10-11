// Values of the backend's fact-store inputs and queries (queries.h), with
// the canonical encodings the store fingerprints and persists.
#pragma once

#include "revkit/analysis/data.h"
#include "revkit/decompd/pool.h"
#include "revkit/facts/address.h"
#include "revkit/facts/codec.h"
#include "revkit/infer/accesses.h"
#include "revkit/lift/lifter.hh"
#include "revkit/v1/assertion.pb.h"
#include "revkit/v1/decompile.pb.h"
#include "revkit/v1/listing.pb.h"

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace revkit::backend {

namespace pb = ::revkit::v1;
class Program;

using Range = std::pair<std::uint64_t, std::uint64_t>;  // inclusive

bool Contains(const std::vector<Range> &ranges, std::uint64_t a);

// What a program is: its identity and the options its derived facts are a
// function of, set at import and never changed. The file itself is in the
// fact store's bytes, in `file_space`.
struct ProgramSource {
  std::string id;  // "project/name"
  std::string name;
  std::string sha256;
  std::uint64_t file_size = 0;
  std::int64_t imported_at = 0;  // unix seconds
  std::string language_id;       // as requested; empty = detect
  std::string compiler_spec_id;
  std::optional<std::uint64_t> image_base;
  facts::SpaceId ram_space = 0;   // program addresses in fact keys
  facts::SpaceId file_space = 0;  // the file's bytes
  std::uint32_t ordinal = 0;      // import order within the project
  // The loader plugin that loaded it ("name@version"), empty for the
  // built-in loaders. Encoded only when set, so other records (and their
  // fingerprints) are unchanged.
  std::string loader;
  // Where the file was imported from, if from a path: a PE's PDB is looked
  // up beside it again when the project is reopened.
  std::string path;
  // A raw image (ImportOptions format "raw"): how its bytes were laid out.
  // `raw->language` is unused (language_id says it). Encoded only when set.
  std::optional<loader::RawOptions> raw;
  // Where it came from inside a container (ImportFromFileSystem):
  // "zip://fw.zip!/rootfs.sqfs!/bin/busybox". Encoded only when set.
  std::string container_path;

  // The loaded program: a cache of parse(file, options), which the encoding
  // already covers through sha256 and the options. It is not encoded, so
  // the fingerprint, and every memo that depends on it, survives a reopen.
  std::shared_ptr<const Program> program;

  void encode(facts::Encoder &e) const;
  static ProgramSource decode(facts::Decoder &d);
};

struct Label {
  std::uint64_t address = 0;
  std::string name;
  std::uint64_t size = 0;  // 0: unknown
  // The symbol as the file spells it, when `name` is its demangled name
  // (docs/demangle.md); "" otherwise.
  std::string mangled;

  void encode(facts::Encoder &e) const;
  static Label decode(facts::Decoder &d);
  friend bool operator==(const Label &, const Label &) = default;
};

// Labels sorted by address, one per address.
struct LabelMap {
  std::vector<Label> labels;

  const Label *find(std::uint64_t a) const;
  // The sized label whose extent covers a (a itself included), or null.
  const Label *containing(std::uint64_t a) const;

  void encode(facts::Encoder &e) const { facts::encode(e, labels); }
  static LabelMap decode(facts::Decoder &d) { return {facts::decode<std::vector<Label>>(d)}; }
};

struct StaticXref {
  // `operand` when the instruction's text decides it (Program::XrefOperand):
  // references come from p-code, and decoding every instruction's display
  // text to place them in an operand was most of their cost.
  static constexpr int kOperandFromText = -2;

  std::uint64_t from = 0;
  std::uint64_t to = 0;
  pb::XrefKind kind = pb::XREF_KIND_UNSPECIFIED;
  int operand = -1;         // -1: none
  bool delay_slot = false;  // `from` is a delay-slot instruction
  // A user reference (a REFERENCE key, analysis/user_refs.h), and whether
  // it is its operand's primary one.
  bool user = false;
  bool primary = false;

  void encode(facts::Encoder &e) const;
  static StaticXref decode(facts::Decoder &d);
  friend bool operator==(const StaticXref &, const StaticXref &) = default;
};

// A run of listing rows inside one memory block. Code spans list their rows;
// data spans have one row per 16-byte line (the first may be shorter), so
// even a huge .bss costs nothing.
struct ListingSpan {
  std::uint64_t start = 0;
  std::uint64_t end = 0;  // exclusive
  std::int64_t first_row = 0;
  std::uint32_t block = 0;  // index into image.blocks
  bool code = false;
  bool thumb = false;  // code decoded as Thumb (ARM interworking)
  bool data = false;   // one defined data item (analysis::Data): a single row, or, for
                       // a user's expanded struct or array, its row and then one per
                       // field or element at `rows` (offsets from `start`, rows[0] = 0)
  // Code spans: row offsets from `start`; kDelaySlot marks an instruction in
  // a delay slot (kUndefined, bytes that did not decode, is kept for pages
  // persisted by earlier versions).
  std::vector<std::uint32_t> rows;

  static constexpr std::uint32_t kUndefined = 0x80000000u;
  static constexpr std::uint32_t kDelaySlot = 0x40000000u;
  static constexpr std::uint32_t kOffsetMask = 0x3fffffffu;
  static constexpr std::uint64_t kDataLine = 16;
  std::int64_t row_count() const;

  void encode(facts::Encoder &e) const;
  static ListingSpan decode(facts::Decoder &d);
  friend bool operator==(const ListingSpan &, const ListingSpan &) = default;
};

// The program's known code as listing spans: runs of adjacent instructions
// that function discovery reached. Gaps between them are data.
struct CodeMap {
  std::vector<ListingSpan> spans;  // in address order
  // Whether the code at `addr` is Thumb (false outside code).
  bool thumb_at(std::uint64_t addr) const;
  std::uint32_t instructions = 0;

  void encode(facts::Encoder &e) const;
  static CodeMap decode(facts::Decoder &d);
};

// Row number <-> address for the whole program.
struct RowIndex {
  static constexpr std::int64_t kPageRows = 256;
  std::vector<ListingSpan> spans;
  std::int64_t total_rows = 0;
  // The data the data spans show, by address.
  std::vector<analysis::DataItem> data;

  // Row containing addr, or the first row after it; total_rows if none.
  std::int64_t row_at(std::uint64_t addr) const;
  std::uint64_t row_address(std::int64_t row) const;
  const ListingSpan &span_of_row(std::int64_t row) const;

  void encode(facts::Encoder &e) const;
  static RowIndex decode(facts::Decoder &d);
};

struct XrefTable {
  std::vector<StaticXref> xrefs;    // by (from, to, kind)
  std::vector<std::uint32_t> by_to;  // indexes into xrefs, by to; not encoded

  void index();  // builds by_to
  std::vector<const StaticXref *> to(std::uint64_t first, std::uint64_t last) const;
  std::vector<const StaticXref *> from(std::uint64_t first, std::uint64_t last) const;
  std::uint32_t count_to(std::uint64_t addr) const;

  void encode(facts::Encoder &e) const { facts::encode(e, xrefs); }
  static XrefTable decode(facts::Decoder &d);
};

// A listing row's revision-independent content.
struct StaticRow {
  std::uint64_t address = 0;
  std::uint32_t length = 0;
  pb::ListingRowKind kind = pb::LISTING_ROW_KIND_UNSPECIFIED;
  std::uint32_t block = 0;
  std::string bytes;                // empty for uninitialized memory
  std::vector<lift::Token> tokens;  // instructions only
  // Instructions only: the flow its p-code decodes to (before any flow
  // override) and its static branch and call targets.
  pb::FlowKind flow = pb::FLOW_KIND_UNSPECIFIED;
  std::vector<std::uint64_t> targets;
  // Data rows: the type's name ("string", "pointer", "undefined4"), the
  // mnemonic Ghidra's listing shows ("ds", "addr", "undefined4"), and the
  // value: text (a quoted string, bytes in hex), or an address.
  std::string data_type, data_mnemonic, data_value;
  std::optional<std::uint64_t> data_target;
  // Some byte is patched (docs/patching.md): `bytes` are the patched ones,
  // `original` the file's.
  bool patched = false;
  std::string original;
  // A user's data definition (docs/listing-edit.md): on the item's row, its
  // field or element rows and whether it shows them; on those rows, the
  // field's path from the item, its depth, and the item's address.
  std::uint32_t data_components = 0;
  bool data_collapsed = false;
  std::string data_field;
  std::uint32_t data_depth = 0;
  std::optional<std::uint64_t> data_parent;

  void encode(facts::Encoder &e) const;
  static StaticRow decode(facts::Decoder &d);
};

// What the searches read of a listing row (queries.h, listing.search_page):
// its address, kind and the text its tokens print, with the scalars and
// addresses in that text, but not the token objects a page keeps (a tenth
// of the memory, so a large program's whole listing stays searchable in
// memory).
struct SearchRow {
  // A scalar or address token: where it is in `text`, its value, width and
  // operand.
  struct Number {
    std::uint32_t at = 0, len = 0;
    std::uint64_t value = 0;
    std::uint8_t bits = 0;
    std::int8_t operand = -1;
    bool address = false;
  };
  std::uint64_t address = 0;
  std::uint32_t length = 0;
  pb::ListingRowKind kind = pb::LISTING_ROW_KIND_UNSPECIFIED;
  // Instructions: the tokens' text and where the operands begin; data: the
  // value's text (StaticRow.data_value).
  std::string text;
  std::uint32_t operands = 0;
  std::vector<Number> numbers;
  // Data: as StaticRow; `bytes` only for items of at most 8 bytes.
  std::string data_type, data_mnemonic, bytes;
  std::optional<std::uint64_t> data_target;

  static SearchRow From(const StaticRow &r);
  void encode(facts::Encoder &e) const;
  static SearchRow decode(facts::Decoder &d);
};

// Header lines above code units (plate comment lines, a function's
// signature, the label, pre-comment lines), for GetListing's header_rows
// numbering, in two levels so that an edit recomputes only its part: the
// code units of one 64 KiB bucket of addresses (the fact store's key index
// buckets), and the non-empty buckets with their totals. Base row r
// (listing.rows) is shown at display row r + (header lines of code units
// before it) + (its own header lines).
struct HeaderBucket {
  struct Entry {
    std::uint64_t address = 0;
    std::int64_t row = 0;     // base row, whose address this is
    std::uint32_t lines = 0;  // > 0
    std::int64_t before = 0;  // lines of earlier entries in the bucket (not encoded)
  };
  std::vector<Entry> entries;  // by row
  std::int64_t lines = 0;      // not encoded

  void index();
  void encode(facts::Encoder &e) const;
  static HeaderBucket decode(facts::Decoder &d);
};

struct HeaderIndex {
  struct Bucket {
    std::uint64_t index = 0;  // address >> facts::kBucketShift
    std::int64_t first_row = 0, last_row = 0;  // of its first and last entries
    std::int64_t lines = 0;
    std::int64_t before = 0;  // lines of earlier buckets (not encoded)
  };
  std::vector<Bucket> buckets;  // non-empty, by index (so by row)
  std::int64_t total_lines = 0;  // not encoded

  void index();
  void encode(facts::Encoder &e) const;
  static HeaderIndex decode(facts::Decoder &d);
};

// The lines a plate or pre-comment shows as header rows (at most 64; a
// trailing newline adds none).
std::vector<std::string> CommentLines(const std::string &text);

struct Func {
  std::uint64_t entry = 0;
  std::vector<Range> body;  // inclusive, sorted
  bool asserted = false;    // a FUNCTION_BOUNDS assertion made it or gave its body
  std::string name;         // analysis's name: symbol, import, thunk target or FUN_, demangled
  std::string mangled;      // the name as the file spells it, when `name` is its demangled name; ""
  std::uint16_t flags = 0;  // analysis::FunctionFlags
  std::uint64_t thunk_target = 0;  // direct thunks: the function they forward to
  bool contains(std::uint64_t a) const { return Contains(body, a); }

  void encode(facts::Encoder &e) const;
  static Func decode(facts::Decoder &d);
};

// The effective functions of a program at one revision: analysis's, with
// the asserted entries, removals and bodies it already applied.
struct FunctionTable {
  std::vector<Func> funcs;  // by entry
  // Disjoint pieces of the bodies for "containing" lookups; where bodies
  // overlap, the earlier-starting function owns the overlap. Not encoded.
  struct Piece {
    std::uint64_t first, last, entry;
  };
  std::vector<Piece> pieces;

  void index();  // builds pieces
  const Func *at(std::uint64_t entry) const;
  const Func *containing(std::uint64_t a) const;

  void encode(facts::Encoder &e) const { facts::encode(e, funcs); }
  static FunctionTable decode(facts::Decoder &d);
};

// The effective symbol at one address, as the decompiler sees it.
struct SymbolInfo {
  enum class Kind : std::uint8_t { None, Function, CodeLabel, Data };
  Kind kind = Kind::None;
  std::string name;
  std::uint64_t size = 0;
  // The effective TYPE value at the address: "h:<type hash>" (feeds the
  // decompiler) or "c:<C declaration>" (display only); "" if none.
  std::string type;
  // Functions analysis found never return (the decompiler's noreturn).
  bool no_return = false;
  // The name is an assertion's (any author, imports too), not the loader's
  // or a default.
  bool asserted = false;
  // The rank (facts::rank) of the assertion that gave `type`; -1: none.
  // A demangled prototype (an import's rank) outranks agents' and
  // scripts' (docs/demangle.md).
  int type_rank = -1;

  void encode(facts::Encoder &e) const;
  static SymbolInfo decode(facts::Decoder &d);
  friend bool operator==(const SymbolInfo &, const SymbolInfo &) = default;
};

// The demangler analysis's prototype of one function (docs/demangle.md,
// analysis.demangler): its return type and parameter list as the listing
// prints them, around the function's name.
struct DemangledProto {
  std::string ret;            // "undefined", "int", "geo::Shape *"
  std::string params;         // "(geo::Circle *this, double param_2)"
  // Without `this`, when it is a guess (lift::FunctionFacts::this_guessed):
  // what the function list shows where inference finds the mangled
  // parameters alone.
  std::string params_static;
  bool this_guessed = false;
  std::vector<bool> param_float;  // the mangled parameters (no `this`): floating-point
  std::string full;               // the demangler's whole output

  std::string text(const std::string &name, bool without_this = false) const;
  void encode(facts::Encoder &e) const;
  static DemangledProto decode(facts::Decoder &d);
  friend bool operator==(const DemangledProto &, const DemangledProto &) = default;
};

// A parameter's or local's asserted type (a retype of the variable by its
// storage key, by hash), with its asserted name, and the storage the key
// names: what the decompiler is told as a committed, type-locked variable
// (docs/decompiler-inputs.md, "Variable types").
struct VariableType {
  std::string key;   // the decompilation's storage key: "param:0", "stack:-0x18", "register:RBX@0x401234"
  std::string hash;  // the asserted type
  std::string name;  // the asserted name, or ""
  int param = -1;    // "param:N": N
  // A local's storage: its space ("stack", "register", ...; "" when the
  // key names none the decompiler can be told, as a temporary's), offset
  // (a stack offset sign-extended to 64 bits) and, for a register the key
  // names, the register's size (0 when the key gives an offset).
  std::string space;
  std::uint64_t offset = 0;
  std::uint32_t size = 0;
  std::optional<std::uint64_t> pc;  // where a register variable is first written

  void encode(facts::Encoder &e) const;
  static VariableType decode(facts::Decoder &d);
  friend bool operator==(const VariableType &, const VariableType &) = default;
};

// What the decompiler is told about one function besides symbols: its
// bounds, the comments it shows and the flow overrides inside it.
struct DecompileInputs {
  std::uint64_t entry = 0;
  bool exists = false;
  std::vector<Range> body;
  struct Comment {
    std::uint64_t address = 0;
    pb::CommentKind kind = pb::COMMENT_KIND_UNSPECIFIED;
    std::string text;
    friend bool operator==(const Comment &, const Comment &) = default;
  };
  std::vector<Comment> comments;
  std::map<std::uint64_t, int> flow_overrides;  // address -> FlowOverrideKind
  // Jump tables analysis recovered in the body: computed jump -> its
  // destinations, given to the decompiler where it can't recover them.
  std::map<std::uint64_t, std::vector<std::uint64_t>> jump_tables;
  // The user's (docs/api.md, "Equates and user references"): equates and
  // conversions of the body's constants (EQUATE keys); computed calls
  // with a user call reference, and their targets; computed jumps with
  // user jump references, whose `jump_tables` entry (with the user's
  // targets) is given even where the decompiler recovers its own.
  std::vector<lift::EquateFacts> equates;
  std::map<std::uint64_t, std::uint64_t> call_targets;
  std::set<std::uint64_t> forced_tables;
  // Calls' signature overrides in the body (CALL_SIGNATURE keys; docs/api.md,
  // "Call-site signature overrides"): call -> the function type's hash.
  std::map<std::uint64_t, std::string> call_signatures;

  void encode(facts::Encoder &e) const;
  static DecompileInputs decode(facts::Decoder &d);
};

// One decompiler run's output, before per-request overlays (local names and
// types, an asserted C prototype).
struct DecompileOutput {
  pb::DecompiledFunction function;  // no text; names as the decompiler printed them
  struct TokenRef {
    int line = 0;
    int token = 0;
  };
  // Tokens of the function's prototype line, in order.
  std::vector<TokenRef> prototype;
  // TYPE tokens of a variable's declaration: (token, variable index).
  std::vector<std::pair<TokenRef, std::uint32_t>> declaration_types;
  // Addresses of functions and globals the output names (call targets,
  // global variables).
  std::vector<std::uint64_t> references;
  // Every address the decompiler looked up in the symbol table: the run's
  // symbol dependencies.
  std::vector<std::uint64_t> touched;
  double milliseconds = 0;
  // The decompiler failed (its worker crashed, ran past its deadline or out
  // of memory): `function` holds only an error line. A failure is a fact of
  // the bundle it was observed on and of the decompiler build, so it is
  // memoized like any output: retried when the facts the bundle holds or
  // the build change, or once with a longer deadline on request.
  std::optional<decompd::Failure> failure;
  std::string failure_bundle;  // the bundle it failed on (encoded): the repro
  // Accesses through each pointer-sized variable (parameters and locals,
  // by storage key): infer::pointer_accesses over the run's p-code, what
  // infer.pointer_accesses and TypeService.AutoStructure read.
  std::vector<std::pair<std::string, std::vector<infer::PointerAccess>>> accesses;
  // Variables the decompiler mapped by a hash of their p-code (a
  // temporary's, in the unique space), by storage key: (hash, the address
  // it is taken at), what committing one's type needs (Ghidra's dynamic
  // storage).
  std::vector<std::pair<std::string, std::pair<std::uint64_t, std::uint64_t>>> dynamic;
  // FIELD tokens' parents as the decompiler's type ids: the overlay names
  // them by revkit's type hash (CodeToken.parent_type_hash).
  std::vector<std::pair<TokenRef, std::uint64_t>> field_parents;

  void encode(facts::Encoder &e) const;
  static DecompileOutput decode(facts::Decoder &d);
};

// A type and every type it references: (hash, record) pairs sorted by hash
// (records per type_record.h).
using TypeClosure = std::vector<std::pair<std::string, std::string>>;

// The program's named types, from the TYPE_DEF records whose type has a
// name (struct, union, enum, typedef), and the names BindTypeName binds.
struct NamedTypes {
  struct Entry {
    std::string key;   // NamedTypeKey: "struct foo"
    std::string hash;
    bool library = false;  // the library archive's (types.library), not asserted
    bool project = false;  // defined at project scope (docs/types.md#project-types)
    friend bool operator==(const Entry &, const Entry &) = default;
  };
  std::vector<Entry> types;                                   // by (key, hash)
  std::vector<std::pair<std::string, std::string>> bindings;  // key -> hash, by key

  const std::string *bound(const std::string &key) const;
  void encode(facts::Encoder &e) const;
  static NamedTypes decode(facts::Decoder &d);
  friend bool operator==(const NamedTypes &, const NamedTypes &) = default;
};

// Deterministic protobuf bytes, for fingerprints.
std::string Deterministic(const google::protobuf::MessageLite &m);

}  // namespace revkit::backend
