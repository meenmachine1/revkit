// A toy instruction set, a synthetic program generator, and a small analysis
// pipeline over FactDb. It exercises the engine the way the real analyses
// will (bytes -> instructions -> xrefs -> "decompiled" summaries that read
// names, types and struct layouts) without SLEIGH. Used by the tests and by
// rk-factbench.
//
// Encoding (little-endian operands):
//   01 rr              alu            02 rr i32          mov imm
//   03 rr a32          load global    04 rr a32 ff       load global.field
//   05 a32             call           06 d8              jump (intra-function)
//   07                 ret            anything else      invalid, 1 byte
#pragma once

#include "revkit/facts/fact_db.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace revkit::facts::toy {

enum Opcode : std::uint8_t {
  kAlu = 1,
  kMovImm = 2,
  kLoad = 3,
  kLoadField = 4,
  kCall = 5,
  kJump = 6,
  kRet = 7,
  kInvalid = 0xff,
};

int length_of(std::uint8_t opcode);

struct Insn {
  std::uint64_t offset = 0;  // from the start of the decoded range
  std::uint32_t operand = 0;
  std::uint8_t op = kInvalid;
  std::uint8_t len = 1;
  std::uint8_t reg = 0;
  std::uint8_t field = 0;
  friend bool operator==(const Insn &, const Insn &) = default;
};

// Instructions of one function, delta-encoded on disk.
struct InsnList {
  Address start;
  std::vector<Insn> insns;
  bool truncated = false;

  void encode(Encoder &e) const;
  static InsnList decode(Decoder &d);
  friend bool operator==(const InsnList &, const InsnList &) = default;
};

enum class XrefKind : std::uint8_t { Call, Data, Field };

struct Xref {
  Address from;
  Address to;
  XrefKind kind = XrefKind::Call;
  std::uint8_t field = 0;

  void encode(Encoder &e) const;
  static Xref decode(Decoder &d);
  friend bool operator==(const Xref &, const Xref &) = default;
};

struct Field {
  std::string name;
  std::string type;
  std::uint32_t offset = 0;
  std::uint32_t size = 0;

  void encode(Encoder &e) const;
  static Field decode(Decoder &d);
  friend bool operator==(const Field &, const Field &) = default;
};

struct Layout {
  std::vector<Field> fields;
  std::uint32_t size = 0;

  const Field *at(std::uint32_t offset) const;
  void encode(Encoder &e) const;
  static Layout decode(Decoder &d);
  friend bool operator==(const Layout &, const Layout &) = default;
};

// "f0:int;f1:ptr" -> fields laid out with natural alignment.
Layout parse_layout(std::string_view def);

// Decodes the function whose bounds are asserted at the key.
struct DecodeFunction {
  static constexpr std::string_view name = "toy.decode";
  static constexpr std::uint32_t version = 1;
  using Key = Address;
  using Value = InsnList;
  static Value compute(QueryContext &ctx, const Key &entry);
  static std::size_t weight(const Value &v) {
    return sizeof(Value) + v.insns.capacity() * sizeof(Insn);
  }
};

struct FunctionXrefs {
  static constexpr std::string_view name = "toy.xrefs";
  static constexpr std::uint32_t version = 1;
  using Key = Address;
  using Value = std::vector<Xref>;
  static Value compute(QueryContext &ctx, const Key &entry);
  static std::size_t weight(const Value &v) { return sizeof(Value) + v.capacity() * sizeof(Xref); }
};

// Layout of a struct from its TypeDef assertion; uncertain if undefined.
struct StructLayout {
  static constexpr std::string_view name = "toy.layout";
  static constexpr std::uint32_t version = 1;
  using Key = std::string;
  using Value = Layout;
  static Value compute(QueryContext &ctx, const Key &type_name);
};

// Stand-in for a decompiled function: callee names and typed field accesses.
// Reads names of callees and globals, global types and struct layouts.
struct FunctionSummary {
  static constexpr std::string_view name = "toy.summary";
  static constexpr std::uint32_t version = 1;
  using Key = Address;
  using Value = std::string;
  static Value compute(QueryContext &ctx, const Key &entry);
  static std::size_t weight(const Value &v) { return sizeof(Value) + v.capacity(); }
};

void register_queries(Engine &engine);

struct ProgramSpec {
  std::uint64_t functions = 100;
  std::uint32_t insns_per_function = 50;  // average; actual is uniform in [n/2, 3n/2]
  std::uint32_t globals = 64;
  std::uint32_t structs = 8;
  std::uint64_t seed = 1;
  SpaceId space = 1;  // ram in SpaceTable::standard()
  std::uint64_t text_base = 0x400000;
  std::uint64_t data_base = 0x10000000;
  std::uint32_t named_percent = 50;
  std::uint64_t functions_per_commit = 4096;
};

struct Program {
  std::vector<Address> functions;
  std::vector<Address> globals;
  std::vector<std::uint32_t> global_struct;  // struct index per global
  std::vector<std::string> structs;          // type names
  std::uint64_t instructions = 0;
  std::uint64_t text_bytes = 0;
  std::uint64_t assertions = 0;
};

inline const Provenance kImporter = Provenance::import("toygen");

std::string struct_name(std::uint32_t i);
// Initial definition of struct i: 2 + i % 6 int fields.
std::string struct_def(std::uint32_t i);

// Writes the program's bytes and import assertions (function bounds, some
// names, global types, struct definitions) through transactions on db.
// Deterministic for a given spec.
Program generate(FactDb &db, const ProgramSpec &spec,
                 const std::function<void(std::uint64_t done)> &progress = {});

}  // namespace revkit::facts::toy
