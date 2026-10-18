// Objective-C and Swift metadata of a Mach-O image (docs/macho.md), as
// Ghidra's Objective-C Type Metadata and Swift Type Metadata analyzers
// read it, as a pure function of the loaded image:
//
//   scan()     the Objective-C 2 runtime's structures: classes and their
//              metaclasses (class_t, class_ro_t), method lists (pointer
//              and relative ones), ivars, properties, protocols,
//              categories, selector, class, super and protocol references;
//              and Swift's type context descriptors (__swift5_types):
//              names, kinds, fields and class vtables
//   markup()   what a program gets from it: typed data (the structures
//              with Objective-C's own names), names (_OBJC_CLASS_$_Point,
//              -[Point sum]), functions at every method's implementation
//              with its prototype from the type encoding (self typed as
//              the class's struct, whose ivars are its fields), strings
//              for the names and types the structures point to
//
// Pointers are read as dyld leaves them: a chained fixup's rebase at its
// target, a bind as the symbol it names (an external class's
// _OBJC_CLASS_$_NSObject). Everything is bounds-checked: a malformed image
// yields less, never a crash.
#pragma once

#include "revkit/loader/image.hh"
#include "revkit/msvc/msvc.h"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace revkit::objc {

struct Method {
  std::string selector;
  std::string types;      // the type encoding: "i16@0:8"
  std::uint64_t imp = 0;  // 0: none (a protocol's requirement)
  bool class_method = false;
};

struct MethodList {
  std::uint64_t address = 0;
  bool relative = false;  // method_list_t's smallMethodListFlag (int32 offsets)
  std::uint32_t entsize = 0;
  std::vector<Method> methods;
};

struct Ivar {
  std::string name;
  std::string type;  // the type encoding: "i", "@\"NSString\""
  std::uint64_t offset_address = 0;  // the ivar offset variable (_OBJC_IVAR_$_C.n)
  std::uint32_t offset = 0;          // its value
  std::uint32_t size = 0;
  std::uint32_t alignment = 0;  // log2, as alignment_raw says
};

struct Property {
  std::string name;
  std::string attributes;  // "Ti,N,V_x"
};

// A class_t and its class_ro_t; the metaclass's ro holds the class methods.
struct Class {
  std::string name;
  std::uint64_t address = 0;  // class_t
  std::uint64_t ro = 0;
  std::uint64_t metaclass = 0;
  std::uint64_t meta_ro = 0;
  std::string superclass;  // the superclass's name ("" for a root class)
  std::uint64_t superclass_address = 0;  // 0: external (bound) or none
  std::uint32_t flags = 0;               // class_ro_t flags (RO_ROOT 2, ...)
  std::uint32_t instance_start = 0;
  std::uint32_t instance_size = 0;
  bool swift = false;  // the data pointer's Swift bits
  std::optional<MethodList> instance_methods, class_methods;
  std::uint64_t ivar_list = 0, property_list = 0, protocol_list = 0;
  std::vector<Ivar> ivars;
  std::vector<Property> properties;
  std::vector<std::string> protocols;
};

struct Category {
  std::string name;
  std::string class_name;  // the class it extends (external ones by their bind)
  std::uint64_t address = 0;
  std::uint64_t class_address = 0;  // 0: external
  std::optional<MethodList> instance_methods, class_methods;
  std::uint64_t property_list = 0, protocol_list = 0;
  std::vector<Property> properties;
  std::vector<std::string> protocols;
};

struct Protocol {
  std::string name;
  std::uint64_t address = 0;
  std::optional<MethodList> instance_methods, class_methods, optional_instance_methods, optional_class_methods;
  std::uint64_t property_list = 0, protocol_list = 0;
  std::vector<Property> properties;
  std::vector<std::string> protocols;
};

// A Swift nominal type's context descriptor.
struct SwiftType {
  std::string name;   // "Point"
  std::string parent; // its module or enclosing type, when named: "Shapes"
  std::string kind;   // "class", "struct", "enum", "protocol"
  std::uint64_t descriptor = 0;
  std::uint64_t accessor = 0;  // the metadata accessor function (0: none)
  std::uint64_t field_descriptor = 0;
  std::vector<std::string> fields;  // field names in order
  // A non-generic class's vtable: the methods' implementations, by slot.
  std::vector<std::uint64_t> vtable;
};

struct Metadata {
  std::vector<Class> classes;        // by class_t address
  std::vector<Category> categories;
  std::vector<Protocol> protocols;
  std::map<std::uint64_t, std::string> selector_refs;  // slot -> selector
  std::map<std::uint64_t, std::string> class_refs;     // slot -> class name (classrefs, superrefs)
  std::map<std::uint64_t, std::string> protocol_refs;  // slot -> protocol name
  std::optional<std::uint64_t> image_info;             // __objc_imageinfo's address
  std::vector<SwiftType> swift_types;
  std::vector<std::string> warnings;

  const Class *class_at(std::uint64_t address) const;
};

Metadata scan(const loader::Image &image);

struct MarkupOptions {
  // The name a loader symbol or the debug info gives `address`, or "":
  // such an address keeps it.
  std::function<std::string(std::uint64_t)> named;
};

// The markup as revkit::msvc's model (its DataDef, LabelDef, FunctionDef),
// pass "objc" (Objective-C) and "swift". counts: "objc_classes",
// "objc_categories", "objc_protocols", "objc_methods", "objc_selector_refs",
// "swift_types".
msvc::Markup markup(const loader::Image &image, const Metadata &metadata, const MarkupOptions &options = {});

// A method's function name as clang spells it: "-[Point sum]",
// "+[Base alloc]", "-[Point(Extra) diff]".
std::string method_name(const std::string &class_name, const std::string &category, const Method &m);

// The pass a markup count belongs to: "objc" or "swift".
std::string count_pass(const std::string &what);

}  // namespace revkit::objc
