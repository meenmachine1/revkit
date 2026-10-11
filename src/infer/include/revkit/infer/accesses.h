// How a pointer is used, and structures composed from it (Ghidra's Auto
// Create Structure and Auto Fill in Structure; docs/types.md, "Structures
// from pointer use").
//
// pointer_accesses() walks a decompiled function's p-code from one of its
// variables, as FillOutStructureHelper does: through copies, casts, joins
// and constant additions (INT_ADD, INT_SUB, PTRADD and PTRSUB with
// constant operands), it records every LOAD and STORE whose address is the
// variable plus a constant (the offset, the size, whether the value is a
// pointer, a float or an integer), and every call the pointer (plus a
// constant) is passed to, with the parameter it is passed as, so a caller
// can follow it into the callee. compose_structure() turns accesses into a
// structure's fields; neither reads the fact store.
#pragma once

#include "revkit/facts/codec.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ghidra {
class Funcdata;
class HighVariable;
class Varnode;
}  // namespace ghidra

namespace revkit::infer {

enum class AccessKind : std::uint8_t {
  load = 0,    // read through the pointer
  store = 1,   // written through it
  passed = 2,  // the pointer (plus `offset`) is a call's argument
};

// What the value read or written is, as far as the code says.
enum class ValueKind : std::uint8_t {
  unknown = 0,
  pointer = 1,   // typed as a pointer, or itself dereferenced
  signed_int = 2,
  unsigned_int = 3,
  floating = 4,
  boolean = 5,
};

struct PointerAccess {
  std::int64_t offset = 0;  // from the variable's value
  std::uint32_t size = 0;   // bytes read or written; 0 for passed
  AccessKind kind = AccessKind::load;
  ValueKind value = ValueKind::unknown;
  std::uint64_t address = 0;  // the instruction
  // passed: the callee's entry (0: an indirect call or unknown), which
  // parameter it is (0-based; -1 if the call's prototype doesn't say),
  // and that parameter's storage as the call's prototype has it
  // ("register:RDI", "stack:0x8"; empty if unknown).
  std::uint64_t callee = 0;
  std::int32_t parameter = -1;
  std::string storage;

  friend bool operator==(const PointerAccess &, const PointerAccess &) = default;
  void encode(facts::Encoder &e) const;
  static PointerAccess decode(facts::Decoder &d);
};

// A value loaded through the pointer (at a non-negative offset): what a
// structure's field holds, followed for chained structures
// (param_1->field_0x20->...).
struct LoadedValue {
  std::int64_t offset = 0;
  const ghidra::Varnode *value = nullptr;
};

// Every access through `high` in `fd` (whose analysis is complete), in
// p-code order. Offsets reach at most +-1 MiB; at most 4096 accesses.
// `loads`, if given, gets each value a LOAD through it produced.
std::vector<PointerAccess> pointer_accesses(const ghidra::Funcdata &fd, const ghidra::HighVariable &high,
                                            std::vector<LoadedValue> *loads = nullptr);
// The same from these varnodes (a loaded value).
std::vector<PointerAccess> pointer_accesses(const ghidra::Funcdata &fd, const std::vector<const ghidra::Varnode *> &roots,
                                            std::vector<LoadedValue> *loads = nullptr);

// A structure's field, as compose_structure() lays it out.
struct PlannedField {
  std::uint64_t offset = 0;
  std::uint32_t size = 0;
  ValueKind value = ValueKind::unknown;  // what the type is: undefinedN, undefined *, an int or a float
  std::uint32_t accesses = 0;  // loads and stores that start here (any size)
  bool existing = false;       // a field of the structure being filled in, kept as it was
  bool truncated = false;      // the accesses here were wider than the room before the next field
  std::string name;            // "field_0x10"; an existing field's own name
};

struct StructurePlan {
  std::uint64_t size = 0;
  std::vector<PlannedField> fields;  // by offset, disjoint
};

struct ExistingField {
  std::uint64_t offset = 0;
  std::uint32_t size = 0;
  std::string name;
};

struct ComposeOptions {
  // Accesses past this offset are dropped unless an existing structure is
  // that large (Ghidra's sanity limit).
  std::uint64_t max_offset = 0x1000;
  std::uint32_t pointer_size = 8;
};

// Fields from accesses (offsets already relative to the structure: a
// callee's are shifted by where the pointer was passed): one per offset an
// access starts at, as wide as the commonest access there (the widest of
// those on a tie) but never into the next field (compilers merge adjacent
// stores); a passed pointer plus an offset marks a field too (one byte,
// unless an access says more). The size is the end of the furthest
// access. With `existing` (Auto Fill in), its fields stay as they are,
// new ones go only where no existing field is, and the size only grows.
StructurePlan compose_structure(const std::vector<PointerAccess> &accesses, const ComposeOptions &options,
                                const std::vector<ExistingField> &existing = {}, std::uint64_t existing_size = 0);

// "field_0x10".
std::string field_name(std::uint64_t offset);

}  // namespace revkit::infer
