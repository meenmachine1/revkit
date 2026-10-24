// TypeService.ParseC and C-declaration retypes: revkit::cparse over a
// program's target and its named types (docs/cparse.md).
#pragma once

#include "model.h"
#include "program.h"

#include "revkit/api/backend.h"
#include "revkit/cparse/cparse.h"
#include "revkit/types/store.h"
#include "revkit/v1/types.pb.h"

#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace revkit::backend {

// The C parser's target for a program: its compiler spec's data
// organization over the target its language, compiler and format name
// (cparse::profile_for). Cached per language, compiler and format.
cparse::Profile ProgramProfile(const Program &program, std::vector<std::string> *notes = nullptr);

// A program's named types as the C parser's lookup: a name is its bound
// definition, else the program's own (debug info, DefineType), else the
// library archive's; interned (unresolved: hashes as recorded) into `store`.
class ProgramTypes {
 public:
  using Closure = std::function<TypeClosure(const std::string &hash)>;
  ProgramTypes(const NamedTypes &names, Closure closure, types::TypeStore &store);

  // cparse::Options::lookup.
  std::optional<types::TypeId> lookup(std::string_view key);
  // The hash of the program's definition of `key`, or "".
  std::string definition(const std::string &key) const;
  // Its definition is only the library archive's (the program has none of
  // its own and binds none).
  bool library_only(const std::string &key) const { return !definition(key).empty() && !own(key); }
  // The recorded hash of a type interned from the program's records, or
  // nullptr for a type the parse made.
  const std::string *recorded(types::TypeId id) const;
  // Interns `hash` (and what it reaches) from the program's records.
  std::optional<types::TypeId> intern(const std::string &hash);

 private:
  // Whether the program defines or binds `key`.
  bool own(const std::string &key) const;

  const NamedTypes &names_;
  // NamedTypes from types.names is sorted by (key, hash) and its bindings by
  // key: definition() and own() search it, so a parse costs nothing per
  // named type (a batch of thousands of retypes or data definitions made
  // one each). Another's is indexed here.
  bool sorted_ = true;
  std::map<std::string, std::string> definitions_;  // unsorted names: key -> hash, as definition() picks
  std::set<std::string> own_;                       // unsorted names: keys the program defines or binds
  Closure closure_;
  types::TypeStore &store_;
  std::map<std::string, types::TypeId> by_hash_;
  std::map<types::TypeId, std::string> recorded_;
};

struct ParseCContext {
  const Program &program;
  const NamedTypes &names;
  ProgramTypes::Closure closure;
  std::vector<std::string> browse_roots;
  // types.categories (named key -> path), for ParseCNamedType's categories.
  const std::map<std::string, std::string> *categories = nullptr;
};

// TypeService.ParseC (pure: reads only).
api::Status ParseC(const ParseCContext &c, const pb::ParseCRequest &req, pb::ParseCResponse &resp);

// A Retype's c_declaration as a type of the program: the type (a
// prototype for a function's entry, with its parameter names) and the
// records of everything it reaches that the program lacks, to define with
// it; nullopt when the text doesn't parse cleanly (it is then kept as
// text, as before the parser existed).
struct ParsedRetype {
  std::string hash;
  struct Def {
    std::string record;       // the TYPE_DEF record
    pb::AssertionBody body;   // as a define_type body (references by hash)
  };
  std::map<std::string, Def> types;  // hash -> what to define
};
std::optional<ParsedRetype> ParseRetype(const ParseCContext &c, const std::string &declaration, bool function);

// ParseRetype for many declarations against one program (a batch of
// prototypes): the program's named types are gathered once, not per
// declaration, which was most of a parse's time.
class RetypeParser {
 public:
  explicit RetypeParser(const ParseCContext &c);
  std::optional<ParsedRetype> parse(const std::string &declaration, bool function);

 private:
  types::TypeStore store_;
  ProgramTypes program_;
  cparse::Options options_;
};

// A function prototype as text (a BSim database's, docs/bsim.md "Applying
// matches") as a skeleton signature of the program, as Ghidra's BSim Apply
// Signature makes one: a type name the program has (its own, bound, or its
// library archive's) is its type; one it lacks becomes an empty placeholder
// structure of that name (an incomplete struct), whose records come with
// the result to define. `placeholders` gets their names. nullopt (and
// `error`) when the text isn't a prototype even so.
std::optional<ParsedRetype> ParseSkeletonPrototype(const ParseCContext &c, const std::string &declaration,
                                                   std::vector<std::string> *placeholders, std::string *error);

}  // namespace revkit::backend
