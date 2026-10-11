// The C preprocessor (internal): directives, includes, macro expansion
// with hide sets (Prosser's algorithm), #if expressions.
#pragma once

#include "token.h"

#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace revkit::cparse::detail {

struct Macro {
  enum class Builtin : std::uint8_t { None, File, Line, Counter, Date, Time, IncludeLevel, BaseFile, HasQuery };
  std::uint32_t id = 0;
  bool function_like = false;
  bool variadic = false;  // the last parameter takes the rest (__VA_ARGS__ or a GNU named one)
  std::vector<std::string> params;
  std::vector<Token> body;
  Builtin builtin = Builtin::None;
  std::uint32_t file = 0, line = 0;
};

// An object-like macro the sources defined, for constants.
struct DefineRecord {
  std::string name;
  std::uint32_t file = 0, line = 0;
};

class Preprocessor {
 public:
  explicit Preprocessor(Context &ctx);

  // Queues a source; sources are read in order after the predefined macros.
  void add_source(const Source &s);
  // The next token after preprocessing; TK::Eof once every source is read.
  Token next();

  // Fully macro-expands `tokens` with the macros defined now (for
  // constants: the object-like macros' bodies at the end of the parse).
  std::vector<Token> expand(std::vector<Token> tokens);
  const Macro *macro(const std::string &name) const;
  const std::vector<DefineRecord> &defines() const { return defines_; }
  bool cplusplus_active() const { return cplusplus_; }

 private:
  struct Frame {
    std::vector<Token> toks;
    std::size_t pos = 0;
    std::uint32_t file = 0;      // index of the physical file
    std::uint32_t shown = 0;     // file shown in diagnostics (#line, linemarkers)
    std::int64_t line_offset = 0;
    std::size_t cond_base = 0;   // conditional stack depth when the file started
    bool passthrough = false;    // preprocessed text (clang -E, cl /E): no expansion
  };
  struct Cond {
    bool taken = false;    // some branch of this #if was taken
    bool in_else = false;
    Token where;
  };
  struct SearchDir {
    std::string path;  // "" for the built-in headers
    bool system = false;
    bool builtin = false;
  };

  // Input
  bool read_raw(Token &out, bool &from_frame);
  const Token *peek_raw();
  void start_next_source();
  void pop_frame();
  void push_front(std::vector<Token> toks);
  std::vector<Token> rest_of_line();
  void skip_line();
  Token adjust(const Token &t, const Frame &f) const;

  // Directives
  void directive(const Token &hash);
  void do_define(const std::vector<Token> &line, const Token &at);
  void do_include(std::vector<Token> line, const Token &at, bool next, bool import);
  void do_pragma(std::vector<Token> line, const Token &at);
  void do_line(const std::vector<Token> &line, const Token &at, bool marker);
  void skip_conditional(const Token &at);
  bool eval_condition(std::vector<Token> line, const Token &at);
  void pragma_text(const std::string &text, const Token &at);

  // Includes
  struct Found {
    std::string canonical;  // or "<builtin>/name"
    std::string shown;
    int index = -1;
    bool system = false;
    bool builtin = false;
  };
  std::optional<Found> find_include(const std::string &name, bool quoted, bool next, const Token &at);
  bool push_file(const Found &f, const std::string &text, const Token &at);

  // Macros
  bool expand_macro(const Token &tok);
  struct Arg {
    std::vector<Token> raw;
    std::optional<std::vector<Token>> expanded;
  };
  bool read_args(const Macro &m, std::vector<Arg> &args, Token &rparen, const Token &name);
  std::vector<Token> subst(const Macro &m, std::vector<Arg> &args, const Token *begin, const Token *end,
                           const Token &site, int depth);
  std::vector<Token> &expanded(Arg &a);
  Token stringize(const std::vector<Token> &toks, const Token &site);
  std::vector<Token> paste(const Token &lhs, const Token &rhs, const Token &site);
  std::uint32_t macro_id(const std::string &name);
  std::uint32_t hs_with(std::uint32_t hs, std::uint32_t id);
  std::uint32_t hs_union(std::uint32_t a, std::uint32_t b);
  std::uint32_t hs_intersect(std::uint32_t a, std::uint32_t b);
  bool hs_has(std::uint32_t hs, std::uint32_t id) const;
  std::uint32_t hs_intern(std::vector<std::uint32_t> s);
  void define_builtin(const std::string &name, Macro::Builtin kind);

  // #if
  struct Value {
    std::uint64_t v = 0;
    bool is_unsigned = false;
  };
  bool has_query(const std::string &name, std::vector<Token> &line, std::size_t &i, Value &out, const Token &at);

  Context &ctx_;
  bool cplusplus_ = false;
  std::deque<Source> pending_;
  std::vector<Frame> frames_;
  std::vector<Token> pushback_;  // reversed: back() is next
  std::size_t pushback_floor_ = 0;  // while expanding an argument: tokens below belong to the caller
  bool isolated_ = false;           // reading an argument in isolation: never read frames
  std::vector<Cond> conds_;
  std::unordered_map<std::string, Macro> macros_;
  std::unordered_map<std::string, std::uint32_t> macro_ids_;
  std::vector<std::vector<std::uint32_t>> hs_sets_{{}};
  std::map<std::vector<std::uint32_t>, std::uint32_t> hs_index_;
  std::unordered_map<std::uint64_t, std::uint32_t> hs_with_memo_, hs_union_memo_;
  std::map<std::string, std::vector<std::optional<Macro>>> pushed_macros_;
  std::vector<DefineRecord> defines_;
  std::set<std::string> once_;
  std::map<std::string, std::string> guards_;  // canonical path -> include guard macro
  std::vector<SearchDir> dirs_;
  std::size_t builtin_index_ = 0;  // index of the built-in directory in dirs_
  std::uint32_t counter_ = 0;
  std::uint32_t expand_depth_ = 0;
  bool in_condition_ = false;  // expanding a #if line
  std::size_t base_file_ = 0;
};

// The built-in headers' text (stddef.h, stdint.h, ...), or nullptr.
const char *builtin_header(const std::string &name);
std::vector<std::string> builtin_header_names();

}  // namespace revkit::cparse::detail
