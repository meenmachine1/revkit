// What the decompiler is told about a program besides its bytes: function
// signatures and local variables, global data and labels, external
// references, comments, flow overrides and data types. This is the
// information Ghidra's Java side serves the decompiler from its program
// database (DecompileCallback); docs/decompiler-inputs.md describes the
// JSON form that tools/ghidra-export/ghidra_dbexport.py writes.
//
// install_inputs() turns these facts into the decompiler's symbol table the
// way Ghidra's Java encoders would (HighFunction, LocalSymbolMap,
// FunctionPrototype, HighCodeSymbol), so a function decompiles under the
// same conditions as in Ghidra.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace ghidra {
class Architecture;
class Element;
class Funcdata;
}  // namespace ghidra

namespace revkit::lift {

class ImageArchitecture;

// An element of the decompiler's own encoding (the XML Ghidra exchanges with
// the decompiler process), used for data types and type references. An
// attribute named "content" is the element's text.
struct DecompElement {
  using Value = std::variant<std::string, std::int64_t, std::uint64_t, bool>;
  std::string tag;
  std::vector<std::pair<std::string, Value>> attrs;
  std::vector<DecompElement> children;

  const Value *attr(const std::string &name) const;
};

struct StorageVarnode {
  std::string space;  // "register", "stack", "ram", ...
  std::uint64_t offset = 0;
  int size = 0;
  friend bool operator==(const StorageVarnode &, const StorageVarnode &) = default;
};

enum class SignatureSource { default_, analysis, imported, user_defined };

// A namespace path below the global scope: (Ghidra namespace id, name), outermost first.
using NamespacePath = std::vector<std::pair<std::uint64_t, std::string>>;

struct ParamFacts {
  std::string name;
  bool valid = true;
  std::vector<StorageVarnode> storage;
  bool stack = false;
  DecompElement type;     // type reference, sized to the storage
  std::string auto_kind;  // "THIS", "RETURN_STORAGE_PTR", or empty
  std::uint64_t id = 0;   // symbol id, 0 if none
};

struct LocalFacts {
  std::string name;
  bool undefined = false;  // an undefinedN type: not type-locked
  int first_use = 0;       // offset from the entry where the variable starts
  std::optional<std::uint64_t> hash;  // dynamic (hash) storage instead of `storage`
  std::vector<StorageVarnode> storage;
  DecompElement type;
  bool is_float = false;
  int type_size = 0;
  int size = 0;  // for hash storage
  std::uint64_t id = 0;
  // revkit's hash of the debug-info type it was made from (see
  // FunctionFacts), so a rebound type name can reach it; not sent to the
  // decompiler.
  std::string source_type;
};

struct FunctionFacts {
  std::uint64_t entry = 0;  // 0 for an external function
  std::string name;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> body;  // inclusive ranges
  SignatureSource signature_source = SignatureSource::default_;
  std::optional<std::string> convention;  // calling convention name, "unknown" when unset
  bool has_this = false;
  std::optional<int> extrapop;  // nullopt: unknown
  std::string call_fixup;
  bool call_fixup_noreturn = false;
  bool varargs = false;
  bool is_inline = false;
  bool noreturn = false;
  bool custom_storage = false;
  // Parameter and return storage (and extrapop) are to be assigned from the
  // calling convention when the inputs are installed, as Ghidra's Java side
  // does for a function with dynamic storage; `params[i].storage` and
  // `ret.storage` are then ignored. A convention of "default" is the
  // compiler spec's default prototype.
  bool dynamic_storage = false;
  struct Return {
    DecompElement type;
    bool is_default = false;  // Ghidra's DEFAULT ("undefined") data type
    std::optional<std::vector<StorageVarnode>> storage;  // nullopt: invalid
    bool void_storage = false;
    int size = 0;
  } ret;
  std::vector<ParamFacts> params;
  std::vector<LocalFacts> locals;
  std::uint64_t id = 0;  // Ghidra's function id (its local scope's id)
  NamespacePath ns;
  std::string label;  // its code label when that differs from `name` ("<EXTERNAL>_abort")
  // revkit's hash of the type the signature was made from (debug info),
  // and the name the debug info gives, so an assertion of the same can be
  // told from a different one; not sent to the decompiler.
  std::string source_type;
  std::string source_name;
  // Context variables painted over the body before it is decoded (ARM's
  // TMode = 1 for a Thumb function), as Java's program context holds them.
  std::vector<std::pair<std::string, std::uint32_t>> context;
  // Ranges (inclusive) outside the body the context is painted over too:
  // code of other functions that this one's flow runs or jumps into.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> context_reach;
  // The prototype is the demangler's, which took the function for a
  // member (an Itanium name can't say whether a function in a class is
  // static): its first parameter is `this` on a guess, which a front end
  // with better evidence (an inferred parameter count) may drop
  // (inputs::refine_demangled_this). Not sent to the decompiler.
  bool this_guessed = false;
  // The signature is the demangler's (inputs::apply_demangled): it ranks
  // as an import, above agents' prototypes. Not sent to the decompiler.
  bool demangled = false;
};

enum class Mutability { normal, constant, is_volatile };

struct DataFacts {
  std::string space;  // empty: the default space
  std::uint64_t addr = 0;
  std::string name;
  std::uint64_t length = 1;
  DecompElement type;  // reference sized to `length`
  Mutability mutability = Mutability::normal;
  std::uint64_t id = 0;
  NamespacePath ns;
  std::optional<std::string> string;  // a defined string's value (UTF-8)
  std::string source_type;  // revkit's hash of the type it was made from (see FunctionFacts)
  std::string source_name;
};

struct ExternalRefFacts {
  std::string space;
  std::uint64_t addr = 0;  // the pointer slot (IAT entry)
  std::string label;
  std::optional<FunctionFacts> function;  // the external function, if Ghidra has one
};

struct LabelFacts {
  std::string space;
  std::uint64_t addr = 0;
  std::string name;
  NamespacePath ns;
};

struct CommentFacts {
  std::uint64_t addr = 0;
  enum Kind { eol, pre, post, plate } kind = pre;
  std::string text;
};

struct TrackedFacts {
  StorageVarnode reg;
  std::string register_name;  // instead of `reg`: a register the language names
  std::uint64_t value = 0;
};

struct BlockFacts {
  std::string name;
  std::uint64_t start = 0, end = 0;  // inclusive
  bool write = false, execute = false, initialized = true, is_volatile = false, external = false;
  std::string space;  // empty: default space
  friend bool operator==(const BlockFacts &, const BlockFacts &) = default;
};

// An equate or a conversion of a constant in the function being
// decompiled, as Java's LocalSymbolMap.grabEquates sends one: an
// EquateSymbol on the constant the instruction's p-code holds, attached by
// its dynamic hash (docs/decompiler-inputs.md, "Equates").
struct EquateFacts {
  std::uint64_t addr = 0;   // the instruction
  std::uint64_t value = 0;  // the scalar's value, as the listing has it
  // Shown in place of the value (an equate, an enum member, or text the
  // decompiler can't format itself); empty for a conversion.
  std::string name;
  // A conversion (Symbol::force_hex ... force_char): 1 hex, 2 decimal, 3
  // octal, 4 binary, 5 char; 0 with a name.
  int format = 0;
  // The constant's dynamic hash; 0: every constant input of the
  // instruction's p-code that holds `value` (Java's
  // DynamicHash.calcConstantHash).
  std::uint64_t hash = 0;
  friend bool operator==(const EquateFacts &, const EquateFacts &) = default;
};

// An EquateFacts placed: the hash of one constant varnode.
struct EquateSymbolFacts {
  std::string name;
  int format = 0;
  std::uint64_t value = 0;
  std::uint64_t addr = 0;
  std::uint64_t hash = 0;
};

struct DecompilerInputs {
  std::string language;  // "x86:LE:64:default"
  std::string compiler;  // "gcc"
  std::string default_convention;
  std::string address_prefix;  // "ram_" where Ghidra's dynamic names show the space
  std::vector<BlockFacts> memory;
  std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>> synthesized_memory;  // blocks no file backs
  std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>> patches;  // relocated bytes
  std::vector<FunctionFacts> functions;
  std::vector<DataFacts> data;
  std::vector<ExternalRefFacts> external_refs;
  std::vector<LabelFacts> labels;       // global labels outside function bodies
  std::vector<LabelFacts> code_labels;  // primary names inside function bodies
  std::vector<CommentFacts> comments;
  std::map<std::uint64_t, std::vector<TrackedFacts>> tracked;  // by function entry
  std::map<std::uint64_t, std::string> flow_overrides;          // "CALL_RETURN", ...
  std::vector<DecompElement> types;  // named data types, in Ghidra's encoding
};

// Encodings, exposed for tests and for dumping what the decompiler is told.
// The <mapsym> for a function, as Ghidra's getMappedSymbols sends it:
// `include_default_names` for the function being decompiled, not for callees.
// `equates`: EquateSymbols in its local scope (the function being
// decompiled).
DecompElement encode_function_symbol(const FunctionFacts &f, std::uint64_t at, bool include_default_names,
                                     int size = 1, const std::vector<EquateSymbolFacts> *equates = nullptr);
DecompElement encode_data_symbol(const DataFacts &d);
std::string to_xml(const DecompElement &e);  // for debugging

DecompElement encode_label_symbol(const LabelFacts &l);
DecompElement encode_external_ref(std::uint64_t slot, const std::string &label);
// A 1-byte symbol of Ghidra's DEFAULT ("undefined") type, as Java sends for
// undefined bytes with a (possibly dynamic) name.
DecompElement encode_undefined_symbol(std::uint64_t addr, const std::string &name, Mutability mutability);

// Builds a ghidra::Element tree (owned by the caller) from an encoding.
ghidra::Element *to_element(const DecompElement &e);

}  // namespace revkit::lift
