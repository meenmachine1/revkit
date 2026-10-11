// The declaration parser (internal): tokens from the preprocessor into
// revkit types, laid out by the profile's rules.
#pragma once

#include "preprocessor.h"
#include "token.h"

#include "revkit/types/store.h"

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace revkit::cparse::detail {

struct ParseError {
  Token at;
  std::string message;
};

struct Attrs {
  std::uint32_t aligned = 0;  // aligned(N), alignas, __declspec(align(N)); the largest wins
  bool packed = false;
  std::uint32_t mode = 0;         // mode(QI/HI/SI/DI/TI/word): bytes
  std::uint32_t vector_size = 0;  // vector_size(N): bytes
  std::optional<types::CallConv> cc;
  // A declaration's asm label (glibc's __REDIRECT: `__asm__ ("" "__isoc99_sscanf")`),
  // the symbol name it links as; noreturn (attribute, __declspec, _Noreturn).
  std::string asm_label;
  bool noreturn = false;
  void merge(const Attrs &o);
};

// A constant expression's value.
struct Value {
  std::int64_t v = 0;
  bool is_unsigned = false;
  std::uint8_t size = 4;  // int unless a long, long long or size_t operand made it wider
};

class Parser {
 public:
  Parser(Context &ctx, Preprocessor &pp, types::TypeStore &store);
  // Parses every source and fills the context's Result.
  void run();
  // Parses exactly one declaration instead (parse_declaration).
  void set_single() { single_ = true; }
  struct Single {
    types::TypeId type;
    std::string name;
    bool function = false;
  };
  const std::optional<Single> &single() const { return single_out_; }

 private:
  using TypeId = types::TypeId;

  // --- Tokens ---
  const Token &peek(std::size_t n = 0);
  Token next();
  bool at(std::string_view p) { return peek().is(p); }
  bool accept(std::string_view p);
  void expect(std::string_view p);
  [[noreturn]] void fail(const Token &at, std::string message);
  bool at_eof() { return peek().kind == TK::Eof; }
  void apply_pragma(const Token &t);
  void skip_balanced();  // at an opening bracket: skips through its match
  void skip_initializer();
  void skip_to_semicolon();

  // --- Types ---
  TypeId add(types::Type t);
  types::Type get(TypeId id) const;
  const types::Type *peek_type(TypeId id) const;
  std::uint64_t size_of(TypeId id, int depth = 0) const;
  std::uint32_t align_of(TypeId id, int depth = 0) const;
  TypeId strip(TypeId id) const;  // typedefs and qualifiers
  bool complete(TypeId id) const;
  TypeId int_type(std::uint32_t size, bool is_signed, types::IntRank rank);
  TypeId plain_char();
  TypeId void_type();
  TypeId pointer_to(TypeId t);
  TypeId qualified(TypeId t, std::uint8_t quals);
  TypeId undefined_placeholder(const Token &name);
  TypeId va_list_type();
  std::optional<TypeId> target_builtin_type(const std::string &w);
  TypeId sized_int_for_mode(TypeId base, std::uint32_t bytes, const Token &at);

  // --- Names ---
  struct Sym {
    enum class Kind : std::uint8_t { Typedef, EnumConst, Object, Function } kind = Kind::Object;
    TypeId type;
    Value value;
  };
  struct Tag {
    TypeId id;
    types::Kind kind = types::Kind::Aggregate;
    types::AggregateKind agg = types::AggregateKind::Struct;
    bool defined = false;
    bool existing = false;  // from Options::lookup
    std::uint32_t file = 0, line = 0;
  };
  std::string qualify(const std::string &name) const;
  const Sym *find_sym(const std::string &name) const;
  Tag *find_tag(const std::string &name);
  bool is_type_name(const Token &t);
  std::optional<TypeId> existing(const std::string &key);

  // --- Declarations ---
  struct Specs {
    bool is_typedef = false, is_extern = false, is_static = false, is_inline = false, is_friend = false,
         is_virtual = false, is_constexpr = false;
    int n_void = 0, n_bool = 0, n_char = 0, n_short = 0, n_int = 0, n_long = 0, n_float = 0, n_double = 0,
        n_signed = 0, n_unsigned = 0, n_complex = 0, n_int128 = 0;
    std::optional<TypeId> named;  // a typedef name, tag, typeof, builtin type
    bool defined_tag = false;     // a struct/union/enum body was given here
    bool anonymous_tag = false;   // ... without a name
    bool typedef_name = false;    // the type is a typedef name's (or a type the lookup gave by name)
    std::uint8_t quals = 0;
    Attrs attrs;
    Token where;
    bool any_type() const {
      return named || n_void || n_bool || n_char || n_short || n_int || n_long || n_float || n_double || n_signed ||
             n_unsigned || n_complex || n_int128;
    }
  };
  struct FuncInfo {
    std::vector<types::Param> params;
    bool varargs = false;
    bool unprototyped = false;
  };
  struct DeclOp {
    enum class Kind : std::uint8_t { Ptr, LRef, RRef, Array, Func } kind = Kind::Ptr;
    std::uint8_t quals = 0;
    std::uint64_t count = 0;
    std::shared_ptr<FuncInfo> func;
  };
  struct Declarator {
    std::string name;
    Token where;
    std::vector<DeclOp> ops;
    Attrs attrs;
    bool qualified_name = false;  // C++ A::b (a member defined outside its class)
    bool operator_name = false;
  };

  void external_declaration();
  void declaration(bool top_level);
  Specs decl_specs(bool member_ctx = false);
  void type_keyword(Specs &s, const Token &t);
  TypeId base_type(const Specs &s);
  TypeId specs_type(Specs &s);  // base type with the specifiers' qualifiers and attributes
  Declarator declarator(bool abstract_ok, int depth = 0);
  void declarator_suffixes(std::vector<DeclOp> &suffixes, int depth);
  std::shared_ptr<FuncInfo> params(int depth);
  TypeId apply(TypeId base, const Declarator &d, bool keep_names, std::optional<types::CallConv> cc);
  TypeId type_name();  // specs + abstract declarator
  bool starts_type_name(std::size_t n = 0);
  Attrs attributes();  // any run of __attribute__, __declspec, [[...]], alignas
  bool at_attribute();
  void gnu_attribute_list(Attrs &a, bool declspec);
  void static_assert_decl();
  void define_typedef(const std::string &name, TypeId type, const Token &where, const Attrs &attrs);
  void record_function(const std::string &name, TypeId type, const Token &where, bool defined, const Attrs &attrs);
  void skip_function_body();
  void template_decl();
  void namespace_decl();
  void using_decl();

  // --- Aggregates and enums ---
  TypeId struct_spec(const Token &kw, Specs &s);
  TypeId enum_spec(const Token &kw, Specs &s);
  struct Member {
    std::string name;
    TypeId type;
    std::optional<std::uint32_t> width;  // a bitfield
    Attrs attrs;
    Token where;
  };
  void member_declaration(std::vector<Member> &members, const std::string &class_name, bool &has_virtual);
  void layout(types::AggregateType &agg, std::vector<Member> &members, const Attrs &attrs, std::uint32_t pack,
              std::uint32_t &align_out);
  TypeId tag_reference(const std::string &key, types::Kind kind, types::AggregateKind agg, const Token &where,
                       bool declaration_only);

  // --- Constant expressions ---
  Value const_expr(int depth = 0);
  Value conditional(int depth);
  Value binary(int min_prec, int depth);
  Value unary(int depth);
  Value primary(int depth);
  Value cast_value(Value v, TypeId to);
  Value offsetof_expr(int depth);
  Value wrap(Value v) const;
  std::optional<TypeId> expr_type(int depth);  // the type of a unary expression, for sizeof and typeof
  std::optional<Value> eval_tokens(std::vector<Token> toks);
  bool same_type(TypeId a, TypeId b, int depth = 0) const;
  bool is_keyword(const std::string &w) const;
  bool is_nested_declarator_start();
  std::set<std::string> existing_sym_keys_;  // syms_ entries that came from Options::lookup
  std::set<std::uint32_t> placeholder_ids_;
  std::set<std::uint32_t> vector_ids_;  // arrays that are GCC vector types (functions may return them)
  std::set<std::string> not_existing_;

  // --- Results ---
  void finish();

  Context &ctx_;
  Preprocessor &pp_;
  types::TypeStore &store_;
  types::TypeGraph g_;
  const LayoutRules &rules_;
  bool cpp_ = false;

  std::deque<Token> la_;
  std::vector<Token> *replay_ = nullptr;  // evaluating a token list instead of the stream
  std::size_t replay_pos_ = 0;
  Token eof_;
  Token last_;

  std::vector<std::uint32_t> pack_stack_;
  std::uint32_t pack_ = 0;
  std::vector<std::string> scope_;  // C++ namespaces and classes
  int extern_c_depth_ = 0;
  std::vector<char> blocks_;  // 'n': namespace, 'e': extern "C" block

  std::unordered_map<std::string, Sym> syms_;
  std::unordered_map<std::string, Tag> tags_;
  std::unordered_map<std::uint32_t, std::uint32_t> local_align_;  // local aggregate -> its alignment
  std::unordered_map<std::uint32_t, std::uint32_t> typedef_align_; // typedef (raw id) -> aligned(N)
  std::set<std::string> unknown_reported_;
  std::unordered_map<std::string, TypeId> unknown_types_;
  std::optional<TypeId> va_list_;

  struct NamedEntry {
    std::string key;
    TypeId id;
    std::uint32_t file = 0, line = 0;
  };
  std::vector<NamedEntry> named_;
  std::map<std::string, std::size_t> named_index_;  // key -> named_
  struct ProtoEntry {
    std::string name;
    TypeId type;
    std::uint32_t file = 0, line = 0;
    bool defined = false;
    std::string asm_label;
    bool noreturn = false;
  };
  std::vector<ProtoEntry> protos_;
  std::map<std::string, std::size_t> proto_index_;
  std::vector<std::pair<std::string, TypeId>> used_existing_;
  std::set<std::string> used_existing_keys_;
  std::vector<std::pair<TypeId, std::uint32_t>> local_aggregates_;
  std::uint32_t nesting_ = 0;
  bool single_ = false;
  std::optional<Single> single_out_;
  void single_declaration();
  int in_params_ = 0;
};

}  // namespace revkit::cparse::detail
