// Symbol demangling: Itanium (GCC, Clang), Microsoft (MSVC, clang-cl),
// Rust v0 and D, backed by LLVM's demangler (third_party/llvm-demangle).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::demangle {

enum class Scheme { None, Itanium, Microsoft, Rust, D };

// The mangling scheme a symbol appears to use, from its prefix alone.
Scheme detect(std::string_view symbol);

// The demangled name, or nullopt if `symbol` isn't a valid mangled name in
// any supported scheme. Itanium names may carry GCC clone suffixes
// (".isra.0", ".cold") and a leading '_' from Mach-O-style prefixes.
std::optional<std::string> demangle(std::string_view symbol);

// Demangled name, or the symbol unchanged.
std::string demangle_or_self(std::string_view symbol);

std::optional<std::string> demangle_itanium(std::string_view symbol, bool with_params = true);
std::optional<std::string> demangle_microsoft(std::string_view symbol);

// The pieces of a mangled function name, for naming functions without
// their parameter lists. Itanium only.
struct FunctionParts {
  std::string name;        // "ns::Class::method" (with template args)
  std::string base_name;   // "method"
  std::string context;     // "ns::Class"
  std::string parameters;  // "(int, char const*)"
  std::string return_type; // empty unless encoded (templates)
  bool is_ctor_or_dtor = false;
};
std::optional<FunctionParts> itanium_function_parts(std::string_view symbol);

}  // namespace revkit::demangle

// ---------------------------------------------------------------------------
// Structured demangling (docs/demangle.md): what the demangler analysis
// names a symbol, and the parts of a function's mangled signature it turns
// into a prototype.
// ---------------------------------------------------------------------------

namespace revkit::demangle {

// A C++ type as a mangled signature spells it.
struct Type {
  enum class Kind : std::uint8_t {
    Builtin,        // "int", "unsigned long", "char", "bool", "double", "wchar_t", "void", ...
    Named,          // a class, struct, union or enum by qualified name (Itanium can't tell which)
    Enum,           // an enum the mangling says is one (Microsoft)
    Record,         // a class, struct or union the mangling says is one (Microsoft)
    Pointer,        // children[0] is the pointee
    Reference,      // an lvalue or rvalue reference; children[0] is the referee
    Array,          // children[0] is the element; `count` (0: unknown)
    Function,       // children[0] is the return type (absent: void), then the parameters
    Unknown,        // what has no C counterpart: member pointers, vectors, packs, ...
  };
  Kind kind = Kind::Unknown;
  std::string name;  // Builtin, Named, Enum, Record: the C++ spelling; Unknown: the demangler's text
  bool is_const = false;
  bool is_volatile = false;
  std::uint64_t count = 0;  // Array
  bool varargs = false;     // Function
  std::vector<Type> children;

  friend bool operator==(const Type &, const Type &) = default;
};

// Whether a function takes `this`.
enum class Member : std::uint8_t {
  Unknown,  // a function in a scope that may be a class or a namespace (Itanium)
  Yes,      // a non-static member function: const or ref-qualified, a constructor or
            // destructor, or one the Microsoft mangling says is a member
  No,       // a free function, or one the Microsoft mangling says is static
};

struct FunctionSignature {
  std::string context;    // "ns::Class" (template arguments included); "" at global scope
  std::string base_name;  // "method", "Class", "~Class", "operator+"
  Member member = Member::Unknown;
  bool constructor = false;
  bool destructor = false;
  bool operator_name = false;    // an overloaded operator
  bool this_const = false;       // a const member function
  std::optional<Type> ret;       // when the mangling encodes it (templates, Microsoft)
  std::vector<Type> params;
  bool varargs = false;
  std::string convention;        // Microsoft: "__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall"
  // A GCC clone (".isra.0", ".constprop.0", ".part.0", ".cold"): its
  // parameters may differ from the mangled signature's.
  std::string clone_suffix;
};

struct Demangled {
  Scheme scheme = Scheme::None;
  // What the analysis names the symbol: the qualified name without its
  // parameter list ("std::vector<int, std::allocator<int>>::push_back",
  // "geo::Shape::vtable"), Ghidra's "use short names" form. A clone keeps
  // its suffix ("helper.isra.0").
  std::string name;
  // The demangler's whole output ("geo::Shape::make(int)").
  std::string full;
  // A function's signature, when the symbol names one (Itanium, Microsoft).
  std::optional<FunctionSignature> function;
};

// The structured form of a mangled symbol, or nullopt when it isn't one.
std::optional<Demangled> parse(std::string_view symbol);

}  // namespace revkit::demangle
