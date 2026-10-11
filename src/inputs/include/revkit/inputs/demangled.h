// The demangler analysis (docs/demangle.md): names and prototypes from
// mangled symbol names, as Ghidra's Demangler analyzers give them.
//
// A mangled name becomes the qualified name without its parameter list
// (Ghidra's "use short names": "std::vector<int, std::allocator<int>>::push_back").
// A function's mangled signature becomes a prototype where it can be
// written as C that revkit::cparse reads for the program's target:
// references as pointers, classes as declared structs of their qualified
// names, `this` (a pointer to the class) first for a member function, the
// return type where the mangling encodes it (else unknown, so the
// decompiler decides it), and a Microsoft name's calling convention. A
// parameter passed by value whose layout the name can't say (a class, or
// in an Itanium name anything that may be one) gives no prototype.
#pragma once

#include "revkit/cparse/cparse.h"
#include "revkit/demangle/demangle.h"
#include "revkit/lift/decomp_inputs.hh"
#include "revkit/types/store.h"

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::inputs {

class GhidraTypes;
class CWriter;

// Scopes a program's symbols show are classes (whose functions take
// `this`): those of constructors, destructors, const or ref-qualified
// member functions, vtables, VTTs and typeinfo, and Microsoft member
// functions. Itanium can't tell a static member from a free function in a
// namespace; a function in one of these scopes is taken for a member.
class ClassScopes {
 public:
  void add(const demangle::Demangled &d);
  void insert(std::string scope) { classes_.insert(std::move(scope)); }
  bool is_class(std::string_view scope) const;
  std::size_t size() const { return classes_.size(); }
  std::vector<std::string> list() const { return {classes_.begin(), classes_.end()}; }

 private:
  std::set<std::string, std::less<>> classes_;
};

// Whether a function the demangler parsed takes `this`.
bool takes_this(const demangle::FunctionSignature &f, const ClassScopes &scopes);

struct DemangledPrototype {
  types::TypeId type;           // a FunctionType in the caller's store
  std::string c;                // the C declaration cparse read (placeholder names for classes)
  bool unknown_return = false;  // the mangling doesn't say: the decompiler decides it
  bool has_this = false;
  bool this_guessed = false;    // `this` because the scope is a class (lift::FunctionFacts::this_guessed)
  std::size_t params = 0;       // `this` included
};

// The demangler analysis's name for a symbol (demangle::Demangled::name),
// or nullopt when it isn't a mangled name.
// A calling convention as the compiler specs name its prototype model
// ("__stdcall"); empty for the default.
std::string convention_name(types::CallConv cc);

std::optional<std::string> demangled_name(std::string_view symbol);

// A qualified name's parts at its top-level "::" separators (not those in
// template arguments, parameter lists or lambda names):
// "std::vector<a::b>::push_back" -> {"std", "vector<a::b>", "push_back"}.
std::vector<std::string> split_qualified(std::string_view name);

// The decompiler's namespace path for a demangled name's scope parts, with
// ids that are the same for the same path in every program.
lift::NamespacePath namespace_path(const std::vector<std::string> &scope);

// Prototypes of many demangled functions, read by cparse as one
// translation unit (a program's thousands of mangled functions parse in
// one pass): add() each, parse() once, then get() each.
class DemangledPrototypes {
 public:
  DemangledPrototypes(const ClassScopes &scopes, const cparse::Profile &profile, types::TypeStore &store);
  ~DemangledPrototypes();
  // nullopt where the signature can't be written as C.
  std::optional<std::size_t> add(const demangle::Demangled &d);
  void parse();
  // nullopt where cparse didn't read it.
  const std::optional<DemangledPrototype> &get(std::size_t i) const;

 private:
  struct Pending;
  const ClassScopes &scopes_;
  const cparse::Profile &profile_;
  types::TypeStore &store_;
  std::unique_ptr<CWriter> writer_;
  std::vector<Pending> pending_;
  std::vector<std::optional<DemangledPrototype>> results_;
};

// The prototype of a demangled function, interned in `store`, or nullopt
// where the signature can't be written as C or cparse doesn't read it.
// The function type's return is `void` when unknown_return.
std::optional<DemangledPrototype> demangled_prototype(const demangle::Demangled &d, const ClassScopes &scopes,
                                                      const cparse::Profile &profile, types::TypeStore &store);

// The prototype as a decompiler signature (signature source `imported`,
// the calling convention where the compiler spec has a model for it),
// applied to `f`; `enc` (over the prototype's store) collects the
// definitions of the types it reaches.
void apply_demangled(lift::FunctionFacts &f, const DemangledPrototype &p, GhidraTypes &enc,
                     const std::set<std::string> &models);

// Drops a guessed `this` (lift::FunctionFacts::this_guessed) where another
// analysis counts the function's parameters as the mangled ones alone (a
// static member function, as Ghidra's DemangledFunction.isThisCall tells
// them apart by the parameter count it found). Returns whether it did.
// `found_float` has one entry per parameter the other analysis found:
// whether it is a floating-point one. `this` goes only when the counts of
// both kinds match the mangled parameters' (an integer register more is
// `this`, whatever the total).
bool refine_demangled_this(lift::FunctionFacts &f, const std::vector<bool> &found_float);

// The prototype as the listing and function list print it: "undefined
// geo::Shape::area(geo::Shape *this)".
std::string demangled_display(const DemangledPrototype &p, const types::TypeStore &store, std::string_view name);

}  // namespace revkit::inputs
