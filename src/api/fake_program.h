// The static half of the fake backend: a hand-assembled x86-64 program whose
// bytes, instructions, p-code, xrefs and decompiler templates agree with one
// another. Nothing here changes after construction; fake_backend.cc layers
// assertion-derived state (names, comments, types, bounds) on top.
#pragma once

#include "revkit/v1/decompile.pb.h"
#include "revkit/v1/listing.pb.h"
#include "revkit/v1/types.pb.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace revkit::api::fake_internal {

namespace pb = ::revkit::v1;

struct VN {
  std::string space;
  std::uint64_t offset = 0;
  std::uint32_t size = 0;
  std::string reg;  // register name, when space == "register"
};

struct PcodeDef {
  pb::PcodeOpcode op;
  std::optional<VN> out;
  std::vector<VN> in;
};

// One operand as display text. "{}" stands for the symbol at `target`, so the
// operand re-renders when that symbol is renamed.
struct OperandDef {
  OperandDef(std::string t, std::optional<std::uint64_t> tgt = std::nullopt)
      : text(std::move(t)), target(tgt) {}
  std::string text;
  std::optional<std::uint64_t> target;
};

struct RefDef {
  std::uint64_t to;
  pb::XrefKind kind;
  int operand;
};

struct InsnDef {
  std::uint64_t addr;
  std::vector<std::uint8_t> bytes;
  std::string mnemonic;
  std::vector<OperandDef> operands;
  pb::FlowKind flow;
  std::vector<std::uint64_t> flow_targets;
  std::vector<RefDef> refs;
  std::vector<PcodeDef> pcode;
};

struct DataDef {
  std::uint64_t addr;
  std::uint32_t length;
  std::string type;          // default data type display
  std::string default_name;  // "s_hello_00402000"
  std::string value_text;    // rendered value
};

struct BlockDef {
  std::string name;
  std::uint64_t start;
  std::uint64_t size;
  bool read, write, execute, initialized;
  std::uint64_t file_offset;
  std::vector<std::uint8_t> bytes;  // empty when !initialized
};

struct FunctionDef {
  std::uint64_t entry;
  std::uint64_t last;  // inclusive
  std::string default_name;
};

// Decompiler templates. Variable names and types, function names and
// comments are filled in at render time from effective facts.
struct VarDef {
  pb::VariableKind kind;
  std::string default_name;
  std::string default_type;
  std::string storage_key;
  std::vector<VN> storage;
  std::uint64_t address = 0;  // globals
};

struct TokDef {
  TokDef(pb::CodeTokenKind k, std::string t) : kind(k), text(std::move(t)) {}
  pb::CodeTokenKind kind;
  std::string text;               // literal text (ignored for var/fn tokens)
  int var = -1;                   // variable index: text = its current name
  std::uint64_t addr = 0;         // source instruction
  std::uint64_t target = 0;       // function/global: text = symbol name
  std::vector<std::uint32_t> vns; // indexes into DecompDef::varnodes
  std::optional<std::uint64_t> value;
};

struct LineDef {
  std::uint32_t indent;
  std::vector<TokDef> toks;
};

struct VarnodeDef {
  VN vn;
  int var = -1;
  std::uint64_t defined_at = 0;
};

struct DecompDef {
  std::uint64_t entry;
  std::string return_type;
  std::vector<VarDef> vars;
  std::vector<LineDef> body;
  std::vector<VarnodeDef> varnodes;
};

struct RowDef {
  std::uint64_t addr;
  std::uint32_t length;
  pb::ListingRowKind kind;
  int insn = -1;  // index into insns
  int data = -1;  // index into data
  std::string block;
};

struct XrefDef {
  std::uint64_t from;
  std::uint64_t to;
  pb::XrefKind kind;
  int operand;
};

class SyntheticProgram {
 public:
  static const SyntheticProgram &Get();

  std::uint64_t image_base = 0x400000;
  std::vector<BlockDef> blocks;
  std::vector<InsnDef> insns;  // address order
  std::vector<DataDef> data;   // address order
  std::vector<FunctionDef> functions;
  std::map<std::uint64_t, DecompDef> decomps;
  std::vector<RowDef> rows;  // whole listing, address order
  std::vector<XrefDef> xrefs;
  std::map<std::uint64_t, std::string> jump_labels;  // derived LAB_ names
  std::vector<pb::TypeDefinition> types;

  const InsnDef *insn_at(std::uint64_t addr) const;
  const DataDef *data_at(std::uint64_t addr) const;
  const BlockDef *block_containing(std::uint64_t addr) const;
  const FunctionDef *default_function_at(std::uint64_t entry) const;
  std::optional<std::uint8_t> byte_at(std::uint64_t addr) const;
  // Index of the first row whose end is past addr.
  std::size_t row_index_at(std::uint64_t addr) const;
  // Address of the instruction after `addr` that ends a straight-line run
  // (RET/HLT/JMP), used to derive bodies for user-declared functions.
  std::uint64_t run_end(std::uint64_t addr) const;

  const pb::TypeDefinition *type_by_hash(const std::string &hash) const;
  // Hash for a C spelling, or empty if the catalog has no such type.
  std::string hash_for_display(const std::string &display) const;
  std::uint32_t xrefs_to_count(std::uint64_t addr) const;

 private:
  SyntheticProgram();
};

// x86-64 register varnode by name ("RAX", "EDI"), or nullopt.
std::optional<VN> RegisterVarnode(const std::string &name);
// Sixteen lowercase hex digits of FNV-1a 64 over text; the fake's stand-in
// for real content hashes.
std::string FakeHash(const std::string &text);

}  // namespace revkit::api::fake_internal
