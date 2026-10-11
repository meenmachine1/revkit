// Microsoft-specific analysis of PE images (docs/pe.md): what Ghidra's
// RTTI analyzer, its PE loader's markup and its Windows PE analyzers find,
// as a pure function of the loaded image.
//
//   scan_rtti()    MSVC run-time type information: TypeDescriptors (".?AV"
//                  and ".?AU" names), CompleteObjectLocators,
//                  ClassHierarchyDescriptors, BaseClassArrays and
//                  BaseClassDescriptors (32-bit images hold absolute
//                  pointers, 64-bit ones image-relative offsets), and the
//                  vftables their locators lead to
//   analyze()      what a program gets from it: typed data (the RTTI
//                  structures, vftables, the PE headers and directories,
//                  exception data), names, functions to make (vftable
//                  entries, exception handlers, TLS callbacks, guarded
//                  call targets) and the `this` type of virtual methods
//
// Everything is read through bounds-checked accessors over the image's
// memory: a malformed or hostile image yields less markup, never a crash.
#pragma once

#include "revkit/loader/image.hh"
#include "revkit/types/store.h"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace revkit::msvc {

// ---- RTTI ----

// BaseClassDescriptor attributes (rttidata.h).
inline constexpr std::uint32_t kBcdNotVisible = 0x01;
inline constexpr std::uint32_t kBcdAmbiguous = 0x02;
inline constexpr std::uint32_t kBcdPrivOrProtBase = 0x04;
inline constexpr std::uint32_t kBcdPrivOrProtInCompositeObj = 0x08;
inline constexpr std::uint32_t kBcdVbOfContObj = 0x10;
inline constexpr std::uint32_t kBcdNonPolymorphic = 0x20;
inline constexpr std::uint32_t kBcdHasPchd = 0x40;
// ClassHierarchyDescriptor attributes.
inline constexpr std::uint32_t kChdMultipleInheritance = 0x01;
inline constexpr std::uint32_t kChdVirtualInheritance = 0x02;
inline constexpr std::uint32_t kChdAmbiguous = 0x04;

struct BaseClass {
  std::uint64_t descriptor = 0;       // its BaseClassDescriptor
  std::uint64_t type_descriptor = 0;  // the base's TypeDescriptor
  std::string name;                   // the base's demangled name
  std::uint32_t contained_bases = 0;  // bases below it in the array (its subtree)
  std::int32_t mdisp = 0;             // member displacement: the subobject's offset
  std::int32_t pdisp = -1;            // vbtable displacement; -1 for a non-virtual base
  std::int32_t vdisp = 0;             // displacement inside the vbtable
  std::uint32_t attributes = 0;
  std::uint64_t hierarchy = 0;        // the base's own ClassHierarchyDescriptor, 0 if absent
  std::uint32_t depth = 0;            // in the array's tree: 0 is the class itself
  bool is_virtual() const { return pdisp != -1; }
};

struct ClassInfo {
  std::string name;     // "geo::Rect"
  std::string mangled;  // ".?AVRect@geo@@"
  bool is_struct = false;  // ".?AU": declared struct (else class)
  std::uint64_t type_descriptor = 0;
  std::uint32_t name_length = 0;  // the name's bytes, terminator included
  std::uint64_t hierarchy = 0;    // its ClassHierarchyDescriptor; 0: none found
  std::uint32_t hierarchy_attributes = 0;
  std::uint64_t base_array = 0;
  // The BaseClassArray in order: [0] is the class itself, then a preorder
  // walk of the bases (each entry's subtree is the next contained_bases).
  std::vector<BaseClass> bases;
  // Direct bases: indices into `bases`.
  std::vector<std::size_t> direct_bases() const;
};

struct Locator {
  std::uint64_t address = 0;
  std::uint32_t signature = 0;  // 0 (32-bit) or 1 (64-bit, image-relative)
  std::uint32_t offset = 0;     // the vftable's subobject offset in the class
  std::uint32_t cd_offset = 0;  // constructor displacement offset
  std::uint64_t type_descriptor = 0;
  std::uint64_t hierarchy = 0;
  std::size_t cls = 0;          // index into Rtti::classes
};

struct Vftable {
  std::uint64_t address = 0;  // its first entry
  std::uint64_t meta = 0;     // the slot before it, which points to the locator
  std::uint64_t locator = 0;
  std::size_t cls = 0;        // index into Rtti::classes
  std::uint32_t offset = 0;   // the locator's subobject offset
  // The class whose subobject the table belongs to (`cls` for offset 0, else
  // the base at that offset), and its name for "vftable_for_<base>".
  std::size_t subobject = 0;
  std::vector<std::uint64_t> entries;
};

struct Rtti {
  unsigned pointer = 8;  // pointer size in bytes
  bool image_relative = true;
  std::vector<ClassInfo> classes;  // by TypeDescriptor address
  std::vector<Locator> locators;   // by address
  std::vector<Vftable> vftables;   // by address

  const ClassInfo *by_type_descriptor(std::uint64_t td) const;
  std::optional<std::size_t> index_of(std::uint64_t td) const;
};

Rtti scan_rtti(const loader::Image &image);

// The class a TypeDescriptor name names: ".?AVRect@geo@@" -> "geo::Rect"
// (revkit::demangle); nullopt for a name that doesn't demangle.
std::optional<std::string> class_name(std::string_view type_descriptor_name);

// ---- markup ----

struct DataDef {
  std::uint64_t address = 0;
  types::TypeId type;       // the element
  std::uint64_t count = 0;  // an array of `count` elements; 0: one element
  std::string name;         // "" leaves the address's name alone
  bool collapsed = false;   // shown as one row
  bool string = false;      // a NUL-terminated char string (type char[n])
  std::string pass;         // what found it: "msvc" (RTTI, C++ EH), "pe" (headers, directories)
};

struct LabelDef {
  std::uint64_t address = 0;
  std::string name;
  std::string pass;
};

struct FunctionDef {
  std::uint64_t entry = 0;
  std::string name;  // "" leaves the function's name alone
  // Make a function here (a FUNCTION_BOUNDS seed): false where only its
  // name or `this` is given.
  bool create = true;
  // A virtual method: its `this` type (a pointer to the class), invalid
  // when none; and the prototype carrying it: `undefined __thiscall
  // f(Class *this, ...)` on 32-bit, the default convention on 64-bit.
  types::TypeId this_type;
  types::TypeId prototype;
  std::string why;  // "vftable", "pdata", "eh_handler", "tls_callback", "guard_cf", ...
  std::string pass;
};

// One class for the class hierarchy and the struct `this` points to.
struct ClassStruct {
  std::string name;
  types::TypeId type;     // the struct: its vftable pointer as field 0
  types::TypeId vftable;  // the vftable struct its field 0 points to, invalid when none
};

struct Markup {
  types::TypeStore store;
  std::vector<DataDef> data;          // sorted by address, disjoint
  std::vector<LabelDef> labels;       // names without data, sorted
  std::vector<FunctionDef> functions; // sorted by entry, one per entry
  std::vector<ClassStruct> classes;   // by name
  std::vector<std::string> warnings;
  // How much of each kind was found, for import messages: "rtti_classes",
  // "vftables", "pe_headers", ...
  std::map<std::string, std::size_t> counts;
};

struct MarkupOptions {
  bool rtti = true;
  bool pe = true;
  // The name a loader symbol or the debug info already gives `address`
  // (demangled), or "": such an address keeps its name (its function is
  // still made and typed), and a vftable's field for it is named after it.
  std::function<std::string(std::uint64_t)> named;
  // The struct a class's `this` points to, when another source (a PDB)
  // defines the class: its type in `Markup::store` is made from this
  // callback's (typically a copy interned into the store). Invalid: make
  // the RTTI one.
  std::function<types::TypeId(const std::string &class_name, types::TypeStore &store)> class_type;
  // How many bytes past `this` a virtual method at `entry` reads or writes
  // (0: unknown): a class struct is as large as its methods reach.
  std::function<std::uint64_t(std::uint64_t entry)> this_extent;
};

Markup analyze(const loader::Image &image, const MarkupOptions &options = {});

// The pass a Markup::counts entry belongs to: "msvc" or "pe".
std::string count_pass(const std::string &what);

}  // namespace revkit::msvc
