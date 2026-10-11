// revkit types (src/types) in Ghidra's data type encoding, named as
// Ghidra's DWARF importer names them (DWARFDataTypeImporter,
// DWARFDataTypeManager.getBaseType): the decompiler then declares and
// casts with the names Ghidra would.
//
//   int, uint, long, ulong, char, uchar ...  C base types Ghidra knows by name
//   typedef uLong -> ulong                   a typedef of a base type: Ghidra's
//                                            generic type for its size and
//                                            encoding (fixed-size, dword or
//                                            sqword, when the name says its bits)
//   "unsigned long" -> typedef of ulong      a spelling Ghidra doesn't know
//   const and volatile                       dropped
//   int (*)(lua_State *)                     _func_int_lua_State_ptr *
//
// References are what Ghidra's encoders write where a type is used (a
// parameter, a field, data): named types by reference, with their
// definitions collected for the decompiler's type queries.
#pragma once

#include "revkit/lift/decomp_inputs.hh"
#include "revkit/loader/image.hh"
#include "revkit/types/store.h"

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::inputs {

// The compiler spec's data organization, as far as type naming needs it
// (Ghidra's defaults where the spec says nothing).
struct DataOrg {
  unsigned pointer = 8;
  unsigned shrt = 2;
  unsigned integer = 4;
  unsigned lng = 8;
  unsigned longlong = 8;
  unsigned wchar = 2;
  unsigned long_double = 8;          // as the spec says
  unsigned long_double_aligned = 8;  // its aligned length
  int extrapop = 0;                  // the default prototype's, for function types
};
DataOrg data_org(const loader::Image &image, const std::string &language_id);

// A Ghidra built-in type ("int", "undefined4", "void") as the decompiler
// is told it: inline, with Ghidra's id; undefined types by reference.
lift::DecompElement builtin_type(const std::string &name, const DataOrg &org);

// The id the decompiler knows a struct or union by, from revkit's hash as
// hex (TypeStore::hash().hex()): 0 for text that isn't one. What names a
// decompiler field token's parent back (backend types.aggregate_ids).
std::uint64_t aggregate_id(std::string_view hash_hex);

class GhidraTypes {
 public:
  // `base_names`: DWARF base type spellings (debuginfo::DebugInfo), or null.
  GhidraTypes(const types::TypeStore &store, DataOrg org, const std::map<types::TypeId, std::string> *base_names);

  // How a use of `id` is encoded.
  lift::DecompElement ref(types::TypeId id);
  // Ghidra's display name of the type (for _func_ names).
  std::string name(types::TypeId id);
  std::uint64_t size(types::TypeId id) const;

  const types::TypeStore &store() const { return store_; }

  // Definitions of the named types references so far reached.
  std::vector<lift::DecompElement> take_definitions();

  // A builtin type by Ghidra name ("undefined4", "int"), inline.
  lift::DecompElement builtin(const std::string &name) const;

 private:
  struct Named {
    std::uint64_t id = 0;
    std::string name;
    int size = 0;  // for function types' references
  };
  lift::DecompElement typeref(const Named &n) const;
  lift::DecompElement base(types::TypeId id, const std::string &spelling);
  lift::DecompElement generic(bool is_float, bool is_signed, bool is_char, std::uint64_t size, const std::string &spelling);
  lift::DecompElement named_typedef(const std::string &name, lift::DecompElement target, std::uint64_t key);
  lift::DecompElement aggregate(types::TypeId id, const types::AggregateType &a);
  lift::DecompElement enumeration(types::TypeId id, const types::EnumType &e);
  lift::DecompElement function(types::TypeId id, const types::FunctionType &f);
  std::string spelling(types::TypeId id) const;
  std::string name_part(types::TypeId id);
  std::string generic_name(bool is_float, bool is_signed, bool is_char, std::uint64_t size, bool fixed) const;

  const types::TypeStore &store_;
  DataOrg org_;
  const std::map<types::TypeId, std::string> *base_names_;
  std::map<types::TypeId, Named> named_;           // aggregates, enums, typedefs, functions
  std::map<std::string, Named> spelled_;           // typedefs Ghidra makes for base type spellings
  std::map<types::TypeId, std::string> names_;     // display names, memoized
  std::vector<lift::DecompElement> defs_;
  int depth_ = 0;
};

}  // namespace revkit::inputs
