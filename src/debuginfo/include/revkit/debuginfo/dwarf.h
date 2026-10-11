// DWARF 2-5 debug info reader: functions, global variables and types.
//
// The reader takes raw section bytes, so it works with any container
// (ELF, Mach-O, PE with DWARF) and needs no relocation support: it expects
// linked images. All reads are bounds-checked; malformed units are skipped
// and reported in DebugInfo::diagnostics.
#pragma once

#include "revkit/types/store.h"

#include <bit>
#include <cstdint>
#include <functional>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::debuginfo {

// Section name ("`.debug_info`", ...) to bytes, plus the target's byte order
// and address size. The bytes must outlive the import_dwarf() call.
struct Sections {
  std::map<std::string, std::span<const std::uint8_t>, std::less<>> by_name;
  std::endian byte_order = std::endian::little;
  std::uint8_t address_size = 8;

  std::span<const std::uint8_t> get(std::string_view name) const {
    auto it = by_name.find(name);
    return it == by_name.end() ? std::span<const std::uint8_t>{} : it->second;
  }
};

// Half-open [begin, end).
struct AddressRange {
  std::uint64_t begin = 0;
  std::uint64_t end = 0;
  friend auto operator<=>(const AddressRange &, const AddressRange &) = default;
};

// A parameter or local variable of a function. Read from PDB symbols
// (S_LOCAL with its first S_DEFRANGE_*, S_REGREL32, S_BPREL32, S_REGISTER)
// and from DWARF (formal parameters and variables of the subprogram and its
// lexical blocks whose DW_AT_location is a single expression: DW_OP_fbreg,
// DW_OP_breg*, DW_OP_reg*; a location list leaves it Unknown).
struct LocalVariable {
  // Cfa: the call frame address (DWARF frame bases only).
  enum class Location : std::uint8_t { Unknown, Register, RegisterRelative, FrameRelative, Cfa };
  std::string name;
  types::TypeId type;
  bool is_param = false;
  Location location = Location::Unknown;
  // Register, RegisterRelative: a CodeView register id (PDB) or a DWARF
  // register number (DWARF).
  std::uint16_t reg = 0;
  std::int32_t offset = 0;  // from `reg`, or from the frame (FrameRelative)
  // DWARF: the start of the lexical block declaring it, 0 for the function's
  // own scope.
  std::uint64_t scope_start = 0;
};

struct Function {
  std::string name;            // DW_AT_name, unqualified
  std::string qualified_name;  // with enclosing C++ namespaces and classes
  std::string linkage_name;    // mangled name, if any
  std::uint64_t entry = 0;
  std::vector<AddressRange> ranges;  // sorted
  types::TypeId prototype;           // a FunctionType in the store; invalid if unknown
  std::vector<std::string> param_names;  // as declared; empty for unnamed
  bool external = false;
  bool noreturn = false;
  // DW_CC_nocall: the compiler changed this function's calling convention
  // (GCC IPA-SRA and friends), so the declared prototype is not its ABI.
  bool abi_changed = false;
  // DWARF: the DIE's .debug_info offset. PDB: module index << 32 | the
  // procedure symbol's offset in the module stream.
  std::uint64_t die_offset = 0;
  std::vector<LocalVariable> locals;  // in symbol (DIE) order, not inlinees
  // DWARF: DW_AT_frame_base when it is a single expression (Cfa, Register,
  // RegisterRelative), else Unknown.
  LocalVariable frame_base;
};

struct Variable {
  std::string name;
  std::string qualified_name;
  std::string linkage_name;
  std::uint64_t address = 0;
  types::TypeId type;
  bool external = false;
  bool function_local = false;  // a static inside a function
  std::string scope;            // that function's name (DWARF)
  std::uint64_t die_offset = 0;
};

struct CompileUnit {
  std::uint64_t offset = 0;
  std::uint16_t version = 0;
  std::uint16_t language = 0;
  std::string name;
  std::string producer;
};

struct Diagnostic {
  std::uint64_t offset = 0;  // in .debug_info, where known
  std::string message;
};

struct DebugInfo {
  std::vector<CompileUnit> units;
  std::vector<Function> functions;  // sorted by entry, then DIE offset
  std::vector<Variable> variables;  // sorted by address, then DIE offset
  std::vector<types::TypeId> types;  // every type imported, sorted, unique
  std::vector<Diagnostic> diagnostics;
  // DWARF only: each base type's name as the producer spelled it ("long
  // unsigned int", clang's "unsigned long"), the first one in DIE order.
  // The type model keeps the C type, not its spelling; Ghidra's importer
  // names types by the spelling.
  std::map<types::TypeId, std::string> base_type_names;
  // Each named struct, union, enum and typedef's declaring file, where the
  // debug info says (DWARF: DW_AT_decl_file through the unit's line table,
  // the first DIE that names one; PDB: LF_UDT_SRC_LINE), as written there.
  std::map<types::TypeId, std::string> type_files;
};

struct ImportOptions {
  // Point declarations of structs, unions and enums (struct foo;) at the
  // binary's definition when it has exactly one distinct definition.
  bool resolve_declarations = true;
};

DebugInfo import_dwarf(const Sections &sections, types::TypeStore &store,
                       const ImportOptions &options = {});

}  // namespace revkit::debuginfo
