// Ghidra's data type archives (.gdt): the library function prototypes and
// the types they use that Ghidra's "Apply Data Archives" analyzer gives
// imported functions (generic_clib_64 for 64-bit ELF, windows_vs12_64 for
// 64-bit PE). They are data files of the Ghidra install, like the .sla and
// .cspec files revkit already reads; this reads them without Java.
//
// A .gdt is a packed Ghidra database (ItemSerializer: a Java header, then a
// zip entry holding a LocalBufferFile). The reader follows Ghidra's db
// package: buffers, the master table of table schemas, long-key and
// fixed-key B-trees, chained buffers for large records; then the data type
// manager's tables (DataTypeManagerDB) by column name.
#pragma once

#include "revkit/inputs/ghidra_types.h"
#include "revkit/lift/decomp_inputs.hh"

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace revkit::inputs {

class ArchiveError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class GhidraArchive {
 public:
  // Data type ids are Ghidra's: the table kind in the top byte
  // (DataTypeManagerDB: 0 built-in, 1 composite, 3 array, 4 pointer, 5
  // typedef, 6 function definition, 8 enum) and the record key.
  struct Param {
    std::string name;
    std::uint64_t type = 0;
  };
  struct FunctionDef {
    std::string name;
    std::uint64_t ret = 0;
    std::vector<Param> params;
    bool varargs = false;
    bool noreturn = false;
    std::string convention;  // "unknown" or a model name
  };
  struct Builtin {
    std::string name;
    std::string class_name;  // ghidra.program.model.data.IntegerDataType
  };
  struct Typedef {
    std::string name;
    std::uint64_t target = 0;
  };
  struct Pointer {
    std::uint64_t target = 0;
    int length = -1;  // -1: the data organization's pointer size
  };
  struct Array {
    std::uint64_t element = 0;
    int count = 0;
    int element_length = 0;
  };
  struct Component {
    int offset = 0;
    std::uint64_t type = 0;
    std::string name;
    int size = 0;
    int ordinal = 0;
  };
  struct Composite {
    std::string name;
    bool is_union = false;
    int length = 0;
    int alignment = 0;
    std::vector<Component> components;  // by ordinal
  };
  struct Enum {
    std::string name;
    int size = 4;
    std::vector<std::pair<std::string, std::int64_t>> values;
  };

  // Reads a .gdt. Throws ArchiveError.
  static std::shared_ptr<const GhidraArchive> load(const std::filesystem::path &gdt);
  // The archive Ghidra applies to a program (DataTypeArchiveUtility), from
  // a Ghidra install; null if there is none. Loaded once per path.
  static std::shared_ptr<const GhidraArchive> for_program(const std::filesystem::path &ghidra_root, bool pe,
                                                         unsigned pointer_bits);

  // The function definition of that name, as ApplyFunctionDataTypesCmd
  // finds it: null if absent or defined differently more than once.
  const FunctionDef *function(const std::string &name) const;

  const Builtin *builtin(std::uint64_t id) const;
  const Typedef *typedef_(std::uint64_t id) const;
  const Pointer *pointer(std::uint64_t id) const;
  const Array *array(std::uint64_t id) const;
  const Composite *composite(std::uint64_t id) const;
  const Enum *enumeration(std::uint64_t id) const;
  const FunctionDef *function_type(std::uint64_t id) const;

  std::size_t function_count() const { return by_name_.size(); }

  // Every named type, for browsing the archive (its composites, enums and
  // typedefs by id).
  const std::map<std::uint64_t, Composite> &composites() const { return composites_; }
  const std::map<std::uint64_t, Enum> &enums() const { return enums_; }
  const std::map<std::uint64_t, Typedef> &typedefs() const { return typedefs_; }
  // The table kind of a data type id (the top byte; see above).
  static std::uint64_t kind_of(std::uint64_t id) { return id >> 56; }

 private:
  std::map<std::uint64_t, Builtin> builtins_;
  std::map<std::uint64_t, Typedef> typedefs_;
  std::map<std::uint64_t, Pointer> pointers_;
  std::map<std::uint64_t, Array> arrays_;
  std::map<std::uint64_t, Composite> composites_;
  std::map<std::uint64_t, Enum> enums_;
  std::map<std::uint64_t, FunctionDef> functions_;
  std::map<std::string, std::uint64_t> by_name_;  // 0: ambiguous
};

// Archive types in the decompiler's encoding, as Ghidra's program would
// hold them once applied (names, fields, typedefs), with ids of their own.
class ArchiveTypes {
 public:
  ArchiveTypes(const GhidraArchive &archive, DataOrg org) : archive_(archive), org_(org) {}

  lift::DecompElement ref(std::uint64_t id);
  // Definitions of the named types references reached.
  std::vector<lift::DecompElement> take_definitions() { return std::exchange(defs_, {}); }

 private:
  lift::DecompElement builtin(const GhidraArchive::Builtin &b) const;
  std::uint64_t own_id(std::uint64_t id) const;
  int size_of(std::uint64_t id) const;

  const GhidraArchive &archive_;
  DataOrg org_;
  std::map<std::uint64_t, bool> defined_;
  std::vector<lift::DecompElement> defs_;
  int depth_ = 0;
};

}  // namespace revkit::inputs
