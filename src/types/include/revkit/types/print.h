// Rendering types as C declarations.
//
// Two styles:
//  - C: standard C declarator syntax with qualifiers:
//      int main(int argc, char **argv), void (*)(int), const char *
//  - Ghidra: what Ghidra's Function.getPrototypeString(false, false) prints
//    for the same type imported from DWARF, the notation of the `prototype`
//    field in docs/reference-format.md: no struct/enum keywords or
//    qualifiers, Ghidra's integer names (uint, ulong, longlong, ...), spaced
//    pointer stars (char * * argv), arrays as int[8], and anonymous function
//    types named _func_<ret>_<params>.
#pragma once

#include "revkit/types/store.h"

#include <string>
#include <string_view>

namespace revkit::types {

enum class Style { C, Ghidra };

struct PrintOptions {
  Style style = Style::C;
  bool resolve_typedefs = false;  // print typedefs as their underlying types
  // C style: an anonymous struct, union or enum is written out in full where
  // it is used ("struct { int a; } *p", "typedef enum { A, B } ab;"),
  // instead of under a made-up name, so the text parses back to the same
  // type (type archives).
  bool inline_anonymous = false;
  // definition(): field offsets as comments ("/* 0x8 */").
  bool offset_comments = true;
  // C style: a function type's calling convention as its keyword before
  // the declarator ("int __stdcall f(int)", "void (__fastcall *p)(void)",
  // __attribute__((ms_abi)) and sysv_abi), so the text parses back to the
  // same type on 32-bit x86 (type archives).
  bool calling_conventions = false;
};

// The type as an abstract declarator: "char **", "int (*)(int)".
std::string type_name(const TypeStore &store, TypeId id, const PrintOptions &opt = {});

// The type declaring `name`: "char **argv", "int (*fn)(int)".
std::string declaration(const TypeStore &store, TypeId id, std::string_view name,
                        const PrintOptions &opt = {});

// A function type as a prototype: "int main(int argc, char **argv)". Unnamed
// parameters are printed as param_1, param_2, ... (as Ghidra does), and an
// empty parameter list as (void).
std::string prototype(const TypeStore &store, TypeId fn, std::string_view name,
                      const PrintOptions &opt = {});

// A full C definition of an aggregate, enum or typedef, with field offsets
// as comments; other types print as type_name(). Always C style.
std::string definition(const TypeStore &store, TypeId id);
std::string definition(const TypeStore &store, TypeId id, const PrintOptions &opt);

// One member of an aggregate as definition() writes it: indented by
// `indent` levels of four spaces, with its bitfield width, the semicolon,
// the offset comment (if asked for) and a newline.
std::string field_definition(const TypeStore &store, const Field &field, int indent, const PrintOptions &opt = {});

// An enum's or anonymous aggregate's body lines as definition() writes them.
std::string enum_values(const EnumType &e, int indent = 0);

}  // namespace revkit::types
