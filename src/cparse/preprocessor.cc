#include "preprocessor.h"

#include "literal.h"

#include <algorithm>
#include <cstring>

namespace revkit::cparse::detail {

namespace {

bool is_cplusplus_name(const std::string &name) {
  for (const char *ext : {".hpp", ".hh", ".hxx", ".h++", ".cpp", ".cc", ".cxx", ".c++", ".ipp", ".tcc"})
    if (name.size() > std::strlen(ext) && name.ends_with(ext)) return true;
  return false;
}

std::string dir_of(const std::string &path) {
  auto slash = path.rfind('/');
  if (slash == std::string::npos) return {};
  return slash == 0 ? "/" : path.substr(0, slash);
}

Token placemarker(const Token &site) {
  Token t = site;
  t.kind = TK::Other;
  t.text.clear();
  t.extra = "placemarker";
  return t;
}
bool is_placemarker(const Token &t) { return t.kind == TK::Other && t.text.empty() && t.extra == "placemarker"; }

// Attributes __has_attribute answers yes for: what GCC has and the parser
// reads or safely ignores.
bool known_attribute(std::string a) {
  if (a.size() > 4 && a.starts_with("__") && a.ends_with("__")) a = a.substr(2, a.size() - 4);
  static const std::set<std::string> k = {
      "aligned", "packed", "mode", "vector_size", "unused", "used", "noreturn", "nothrow", "leaf", "pure",
      "const", "malloc", "deprecated", "unavailable", "visibility", "format", "format_arg", "nonnull",
      "warn_unused_result", "always_inline", "noinline", "cold", "hot", "may_alias", "alloc_size",
      "returns_nonnull", "sentinel", "weak", "alias", "section", "cdecl", "stdcall", "fastcall", "ms_abi",
      "sysv_abi", "regparm", "transparent_union", "artificial", "gnu_inline", "fallthrough", "access",
      "nonstring", "warning", "error", "constructor", "destructor", "aligned", "cleanup", "tls_model",
      "ms_struct", "gcc_struct", "designated_init", "externally_visible", "flatten", "noclone", "noipa",
      "alloc_align", "assume_aligned", "copy", "dllimport", "dllexport", "selectany", "thiscall",
      "vectorcall", "naked", "target", "optimize", "no_instrument_function", "returns_twice"};
  return k.contains(a);
}

}  // namespace

Preprocessor::Preprocessor(Context &ctx) : ctx_(ctx) {
  cplusplus_ = ctx.options.cplusplus;
  for (const std::string &d : ctx.options.include_dirs) dirs_.push_back({d, false, false});
  builtin_index_ = dirs_.size();
  if (ctx.options.builtin_headers) dirs_.push_back({"", true, true});
  for (const std::string &d : ctx.options.system_include_dirs) dirs_.push_back({d, true, false});

  define_builtin("__FILE__", Macro::Builtin::File);
  define_builtin("__LINE__", Macro::Builtin::Line);
  define_builtin("__COUNTER__", Macro::Builtin::Counter);
  define_builtin("__DATE__", Macro::Builtin::Date);
  define_builtin("__TIME__", Macro::Builtin::Time);
  define_builtin("__TIMESTAMP__", Macro::Builtin::Date);
  define_builtin("__INCLUDE_LEVEL__", Macro::Builtin::IncludeLevel);
  define_builtin("__BASE_FILE__", Macro::Builtin::BaseFile);
  define_builtin("__FILE_NAME__", Macro::Builtin::File);
  for (const char *q : {"__has_include", "__has_include_next", "__has_attribute", "__has_cpp_attribute",
                        "__has_c_attribute", "__has_declspec_attribute", "__has_builtin", "__has_feature",
                        "__has_extension", "__has_warning", "__is_identifier", "__has_embed"})
    define_builtin(q, Macro::Builtin::HasQuery);

  // The command line: the profile's macros, -D, -U.
  std::string text;
  for (const auto &[name, body] : ctx.options.profile.predefined()) text += "#define " + name + " " + body + "\n";
  if (cplusplus_) text += "#define __cplusplus 201703L\n";
  for (const auto &[name, value] : ctx.options.defines)
    text += "#define " + name + " " + (value.empty() ? std::string("1") : value) + "\n";
  for (const std::string &name : ctx.options.undefines) text += "#undef " + name + "\n";
  FileInfo cmd;
  cmd.name = "<command line>";
  cmd.builtin = true;
  cmd.system = true;
  ctx.files.push_back(cmd);
  Frame f;
  f.file = f.shown = static_cast<std::uint32_t>(ctx.files.size() - 1);
  f.toks = tokenize(ctx, f.file, text);
  frames_.push_back(std::move(f));
}

void Preprocessor::define_builtin(const std::string &name, Macro::Builtin kind) {
  Macro m;
  m.id = macro_id(name);
  m.builtin = kind;
  macros_[name] = std::move(m);
}

const Macro *Preprocessor::macro(const std::string &name) const {
  auto it = macros_.find(name);
  return it == macros_.end() ? nullptr : &it->second;
}

void Preprocessor::add_source(const Source &s) { pending_.push_back(s); }

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

void Preprocessor::start_next_source() {
  Source s = std::move(pending_.front());
  pending_.pop_front();
  if (!ctx_.options.cplusplus) cplusplus_ = is_cplusplus_name(s.name);
  if (cplusplus_ && !macros_.contains("__cplusplus")) {
    Macro m;
    m.id = macro_id("__cplusplus");
    Token t;
    t.kind = TK::Number;
    t.text = "201703L";
    m.body.push_back(t);
    macros_["__cplusplus"] = std::move(m);
  } else if (!cplusplus_ && !ctx_.options.cplusplus) {
    macros_.erase("__cplusplus");
  }
  Found f;
  f.shown = s.name;
  std::string text = std::move(s.text);
  if (s.path) {
    std::optional<std::string> canon = ctx_.options.fs ? ctx_.options.fs->resolve(s.name) : std::nullopt;
    std::optional<std::string> body;
    if (canon) body = ctx_.options.fs->read(*canon, ctx_.options.limits.max_bytes);
    if (!body) {
      ctx_.diag(Severity::Error, 0, 0, 0,
                "cannot read " + s.name + (canon ? "" : ": no such file, or not under an allowed directory"));
      return;
    }
    f.canonical = *canon;
    text = std::move(*body);
  }
  base_file_ = ctx_.files.size();
  Token at;
  push_file(f, text, at);
}

bool Preprocessor::push_file(const Found &found, const std::string &text, const Token &at) {
  if (frames_.size() >= ctx_.options.limits.max_include_depth) {
    ctx_.error(at, "#include nested deeper than " + std::to_string(ctx_.options.limits.max_include_depth));
    return false;
  }
  if (ctx_.files.size() >= ctx_.options.limits.max_files) throw LimitReached{"more than " + std::to_string(ctx_.options.limits.max_files) + " files"};
  ctx_.add_bytes(text.size());
  FileInfo info;
  info.name = found.shown;
  info.canonical = found.canonical;
  info.system = found.system;
  info.builtin = found.builtin;
  info.search_index = found.index;
  ctx_.files.push_back(info);
  if (!found.builtin) ctx_.result.files.push_back(found.canonical.empty() ? found.shown : found.canonical);
  Frame f;
  f.file = f.shown = static_cast<std::uint32_t>(ctx_.files.size() - 1);
  f.toks = tokenize(ctx_, f.file, text);
  f.cond_base = conds_.size();
  // Preprocessed text starts with a line marker: # 1 "file" or #line 1 "file".
  if (f.toks.size() >= 2 && f.toks[0].punct("#") && (f.toks[1].kind == TK::Number || f.toks[1].ident("line")))
    f.passthrough = true;
  // An include guard: #ifndef X / #define X ... #endif, the #endif last.
  if (!found.canonical.empty() && f.toks.size() > 6 && f.toks[0].punct("#") && f.toks[1].ident("ifndef") &&
      f.toks[2].kind == TK::Ident && f.toks[3].bol && f.toks[3].punct("#") && f.toks[4].ident("define") &&
      f.toks[5].text == f.toks[2].text) {
    int depth = 0;
    bool guarded = false;
    for (std::size_t i = 0; i + 1 < f.toks.size(); ++i) {
      if (!f.toks[i].bol || !f.toks[i].punct("#")) continue;
      const std::string &d = f.toks[i + 1].text;
      if (d == "if" || d == "ifdef" || d == "ifndef") ++depth;
      else if (d == "endif" && --depth == 0) {
        std::size_t j = i + 2;
        while (j < f.toks.size() && !f.toks[j].bol) ++j;
        guarded = j == f.toks.size();
        break;
      }
    }
    if (guarded) guards_[found.canonical] = f.toks[2].text;
  }
  frames_.push_back(std::move(f));
  return true;
}

void Preprocessor::pop_frame() {
  Frame &f = frames_.back();
  if (conds_.size() > f.cond_base) {
    ctx_.error(conds_.back().where, "unterminated conditional directive");
    conds_.resize(f.cond_base);
  }
  frames_.pop_back();
}

Token Preprocessor::adjust(const Token &t, const Frame &f) const {
  Token out = t;
  if (f.line_offset) out.line = static_cast<std::uint32_t>(std::max<std::int64_t>(1, std::int64_t(t.line) + f.line_offset));
  out.file = f.shown;
  return out;
}

bool Preprocessor::read_raw(Token &out, bool &from_frame) {
  if (pushback_.size() > pushback_floor_) {
    out = std::move(pushback_.back());
    pushback_.pop_back();
    from_frame = false;
    return true;
  }
  if (isolated_) return false;
  for (;;) {
    if (frames_.empty()) {
      if (pending_.empty()) return false;
      start_next_source();
      continue;
    }
    Frame &f = frames_.back();
    if (f.pos >= f.toks.size()) {
      pop_frame();
      continue;
    }
    out = adjust(f.toks[f.pos++], f);
    from_frame = true;
    return true;
  }
}

const Token *Preprocessor::peek_raw() {
  if (pushback_.size() > pushback_floor_) return &pushback_.back();
  if (isolated_ || frames_.empty()) return nullptr;
  Frame &f = frames_.back();
  if (f.pos >= f.toks.size()) return nullptr;
  const Token &t = f.toks[f.pos];
  if (t.bol && t.punct("#")) return nullptr;
  return &t;
}

void Preprocessor::push_front(std::vector<Token> toks) {
  for (auto it = toks.rbegin(); it != toks.rend(); ++it) pushback_.push_back(std::move(*it));
}

std::vector<Token> Preprocessor::rest_of_line() {
  std::vector<Token> out;
  if (frames_.empty()) return out;
  Frame &f = frames_.back();
  while (f.pos < f.toks.size() && !f.toks[f.pos].bol) out.push_back(adjust(f.toks[f.pos++], f));
  return out;
}

void Preprocessor::skip_line() {
  if (frames_.empty()) return;
  Frame &f = frames_.back();
  while (f.pos < f.toks.size() && !f.toks[f.pos].bol) ++f.pos;
}

Token Preprocessor::next() {
  for (;;) {
    Token t;
    bool ff = false;
    if (!read_raw(t, ff)) {
      Token eof;
      eof.kind = TK::Eof;
      return eof;
    }
    if (ff && t.bol && t.punct("#")) {
      directive(t);
      continue;
    }
    if (t.kind == TK::Ident) {
      const bool passthrough = ff && !frames_.empty() && frames_.back().passthrough;
      if (!passthrough && expand_macro(t)) continue;
      if (t.text == "_Pragma" || t.text == "__pragma") {
        const Token *p = peek_raw();
        if (p && p->punct("(")) {
          Token x;
          bool f2;
          read_raw(x, f2);
          std::string text;
          int depth = 0;
          while (read_raw(x, f2)) {
            if (x.punct("(")) ++depth;
            if (x.punct(")") && depth-- == 0) break;
            if (t.text == "_Pragma" && x.kind == TK::String) {
              text += string_value(x.text);
            } else {
              if (!text.empty() && x.space) text += ' ';
              text += x.text;
            }
          }
          pragma_text(text, t);
          continue;
        }
      }
    }
    return t;
  }
}

std::vector<Token> Preprocessor::expand(std::vector<Token> toks) {
  ctx_.check_nesting(++expand_depth_);
  const std::size_t old_floor = pushback_floor_;
  const bool old_iso = isolated_;
  pushback_floor_ = pushback_.size();
  isolated_ = true;
  push_front(std::move(toks));
  std::vector<Token> out;
  Token t;
  bool ff;
  try {
    // In a #if, the operand of a `defined` an expansion produced isn't
    // expanded (GCC's behavior; mingw-w64's __INTRINSIC_PROLOG relies on it).
    int protect = 0;
    while (read_raw(t, ff)) {
      if (in_condition_ && t.kind == TK::Ident) {
        if (t.text == "defined") {
          protect = 2;
          out.push_back(std::move(t));
          continue;
        }
        if (protect) {
          protect = 0;
          out.push_back(std::move(t));
          continue;
        }
      } else if (protect && t.punct("(")) {
        out.push_back(std::move(t));
        continue;
      } else {
        protect = 0;
      }
      if (t.kind == TK::Ident && expand_macro(t)) continue;
      out.push_back(std::move(t));
    }
  } catch (...) {
    pushback_.resize(pushback_floor_);
    pushback_floor_ = old_floor;
    isolated_ = old_iso;
    --expand_depth_;
    throw;
  }
  pushback_floor_ = old_floor;
  isolated_ = old_iso;
  --expand_depth_;
  return out;
}

// ---------------------------------------------------------------------------
// Directives
// ---------------------------------------------------------------------------

void Preprocessor::directive(const Token &hash) {
  std::vector<Token> line = rest_of_line();
  if (line.empty()) return;  // the null directive
  const Token name = line.front();
  line.erase(line.begin());
  const std::string &d = name.text;
  const bool passthrough = !frames_.empty() && frames_.back().passthrough;
  if (name.kind == TK::Number) {
    // A line marker: # 12 "file" flags.
    line.insert(line.begin(), name);
    do_line(line, hash, true);
    return;
  }
  if (d == "define") return do_define(line, hash);
  if (d == "undef") {
    if (line.empty() || line[0].kind != TK::Ident) return ctx_.error(hash, "macro name missing in #undef");
    auto it = macros_.find(line[0].text);
    if (it != macros_.end() && it->second.builtin == Macro::Builtin::None) macros_.erase(it);
    return;
  }
  if (d == "include" || d == "include_next" || d == "import")
    return do_include(std::move(line), hash, d == "include_next", d == "import");
  if (d == "if" || d == "ifdef" || d == "ifndef") {
    ctx_.check_nesting(static_cast<std::uint32_t>(conds_.size() + 1));
    bool v = false;
    if (d == "if") {
      v = eval_condition(std::move(line), hash);
    } else {
      if (line.empty() || line[0].kind != TK::Ident) ctx_.error(hash, "macro name missing in #" + d);
      else v = macros_.contains(line[0].text) == (d == "ifdef");
    }
    conds_.push_back({v, false, hash});
    if (!v) skip_conditional(hash);
    return;
  }
  if (d == "elif" || d == "elifdef" || d == "elifndef" || d == "else") {
    if (conds_.size() <= (frames_.empty() ? 0 : frames_.back().cond_base))
      return ctx_.error(hash, "#" + d + " without #if");
    if (conds_.back().in_else) ctx_.error(hash, "#" + d + " after #else");
    if (d == "else") conds_.back().in_else = true;
    conds_.back().taken = true;
    skip_conditional(hash);
    return;
  }
  if (d == "endif") {
    if (conds_.size() <= (frames_.empty() ? 0 : frames_.back().cond_base))
      return ctx_.error(hash, "#endif without #if");
    conds_.pop_back();
    return;
  }
  if (d == "line") {
    if (!passthrough) line = expand(std::move(line));
    return do_line(line, hash, false);
  }
  if (d == "pragma") return do_pragma(std::move(line), hash);
  if (d == "error" || d == "warning") {
    std::string text;
    for (const Token &t : line) {
      if (!text.empty() && t.space) text += ' ';
      text += t.text;
    }
    ctx_.diag(d == "error" ? Severity::Error : Severity::Warning, hash, "#" + d + " " + text);
    return;
  }
  if (d == "ident" || d == "sccs" || d == "assert" || d == "unassert") return;
  if (!passthrough) ctx_.warning(hash, "unknown directive #" + d);
}

void Preprocessor::skip_conditional(const Token &at) {
  if (frames_.empty()) return;
  Frame &f = frames_.back();
  int depth = 0;
  while (f.pos < f.toks.size()) {
    const Token &t = f.toks[f.pos];
    if (!(t.bol && t.punct("#")) || f.pos + 1 >= f.toks.size() || f.toks[f.pos + 1].bol) {
      ++f.pos;
      continue;
    }
    const Token hash = adjust(t, f);
    const std::string d = f.toks[f.pos + 1].text;
    f.pos += 2;
    if (d == "if" || d == "ifdef" || d == "ifndef") {
      ++depth;
      skip_line();
      continue;
    }
    if (depth > 0) {
      if (d == "endif") --depth;
      skip_line();
      continue;
    }
    if (d == "endif") {
      skip_line();
      conds_.pop_back();
      return;
    }
    Cond &c = conds_.back();
    if (d == "else") {
      skip_line();
      if (c.in_else) ctx_.error(hash, "#else after #else");
      c.in_else = true;
      if (!c.taken) {
        c.taken = true;
        return;
      }
      continue;
    }
    if (d == "elif" || d == "elifdef" || d == "elifndef") {
      std::vector<Token> line = rest_of_line();
      if (c.taken) continue;
      bool v = false;
      if (d == "elif") v = eval_condition(std::move(line), hash);
      else if (!line.empty() && line[0].kind == TK::Ident) v = macros_.contains(line[0].text) == (d == "elifdef");
      if (v) {
        c.taken = true;
        return;
      }
      continue;
    }
    skip_line();
  }
  (void)at;
}

void Preprocessor::do_define(const std::vector<Token> &line, const Token &at) {
  if (line.empty() || line[0].kind != TK::Ident) return ctx_.error(at, "macro name missing in #define");
  const std::string &name = line[0].text;
  if (name == "defined") return ctx_.error(at, "\"defined\" cannot be used as a macro name");
  Macro m;
  m.id = macro_id(name);
  m.file = at.file;
  m.line = at.line;
  std::size_t i = 1;
  if (line.size() > 1 && line[1].punct("(") && !line[1].space) {
    m.function_like = true;
    i = 2;
    bool ok = false;
    while (i < line.size()) {
      const Token &t = line[i++];
      if (t.punct(")")) {
        ok = true;
        break;
      }
      if (t.punct(",")) continue;
      if (t.punct("...")) {
        m.variadic = true;
        m.params.push_back("__VA_ARGS__");
        continue;
      }
      if (t.kind != TK::Ident || m.variadic) break;
      m.params.push_back(t.text);
      if (i < line.size() && line[i].punct("...")) {  // GNU: args...
        m.variadic = true;
        ++i;
      }
    }
    if (!ok) return ctx_.error(at, "bad parameter list in the definition of macro " + name);
  }
  for (; i < line.size(); ++i) {
    Token t = line[i];
    t.bol = false;
    m.body.push_back(std::move(t));
  }
  if (!m.body.empty()) m.body.front().space = false;
  if (!m.body.empty() && (m.body.front().punct("##") || m.body.back().punct("##")))
    return ctx_.error(at, "'##' cannot appear at either end of a macro expansion");
  auto it = macros_.find(name);
  if (it != macros_.end() && it->second.builtin != Macro::Builtin::None) return;
  macros_[name] = std::move(m);
  const bool builtin = at.file < ctx_.files.size() && ctx_.files[at.file].builtin;
  if (!macros_[name].function_like && !builtin) defines_.push_back({name, at.file, at.line});
}

void Preprocessor::do_line(const std::vector<Token> &line, const Token &at, bool marker) {
  if (frames_.empty() || line.empty() || line[0].kind != TK::Number) {
    if (!marker) ctx_.error(at, "#line needs a line number");
    return;
  }
  Frame &f = frames_.back();
  std::uint64_t n = 0;
  for (char c : line[0].text) {
    if (c < '0' || c > '9') break;
    n = n * 10 + std::uint64_t(c - '0');
    if (n > 0xffffffffu) break;
  }
  // The physical line of the directive: the raw token before the cursor.
  const std::uint32_t phys = f.pos > 0 ? f.toks[f.pos - 1].line : 0;
  f.line_offset = std::int64_t(n) - std::int64_t(phys) - 1;
  if (line.size() > 1 && line[1].kind == TK::String) {
    FileInfo info;
    info.name = string_value(line[1].text);
    info.system = ctx_.files[f.file].system;
    for (std::size_t k = 2; k < line.size(); ++k)
      if (line[k].text == "3") info.system = true;
    // Reuse the entry for a name seen before, so diagnostics agree.
    std::uint32_t idx = static_cast<std::uint32_t>(ctx_.files.size());
    for (std::uint32_t k = 0; k < ctx_.files.size(); ++k)
      if (ctx_.files[k].name == info.name && ctx_.files[k].canonical.empty() && ctx_.files[k].system == info.system)
        idx = k;
    if (idx == ctx_.files.size()) ctx_.files.push_back(info);
    f.shown = idx;
  }
}

void Preprocessor::do_pragma(std::vector<Token> line, const Token &at) {
  if (line.empty()) return;
  const std::string &p = line[0].text;
  if (p == "once") {
    if (!frames_.empty()) {
      const FileInfo &fi = ctx_.files[frames_.back().file];
      once_.insert(fi.canonical.empty() ? fi.name : fi.canonical);
    }
    return;
  }
  if (p == "GCC" && line.size() > 1 && line[1].text == "system_header") {
    if (!frames_.empty()) ctx_.files[frames_.back().file].system = true;
    return;
  }
  if ((p == "push_macro" || p == "pop_macro") && line.size() >= 4 && line[2].kind == TK::String) {
    const std::string name = string_value(line[2].text);
    auto &stack = pushed_macros_[name];
    if (p == "push_macro") {
      auto it = macros_.find(name);
      stack.push_back(it == macros_.end() ? std::nullopt : std::optional<Macro>(it->second));
      if (stack.size() > 1024) stack.erase(stack.begin());
    } else if (!stack.empty()) {
      if (stack.back()) macros_[name] = *stack.back();
      else macros_.erase(name);
      stack.pop_back();
    }
    return;
  }
  if (p == "pack") {
    std::string args;
    for (std::size_t i = 1; i < line.size(); ++i) {
      if (line[i].punct("(") && i == 1) continue;
      if (line[i].punct(")") && i + 1 == line.size()) continue;
      args += line[i].text;
      if (line[i].punct(",")) continue;
    }
    // Macros in pack arguments (pack(push, MY_PACK)) are expanded.
    if (args.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_") != std::string::npos) {
      std::vector<Token> inner(line.begin() + 1, line.end());
      inner = expand(std::move(inner));
      args.clear();
      for (std::size_t i = 0; i < inner.size(); ++i) {
        if (inner[i].punct("(") && i == 0) continue;
        if (inner[i].punct(")") && i + 1 == inner.size()) continue;
        args += inner[i].text;
      }
    }
    Token t = at;
    t.kind = TK::Pragma;
    t.text = "pack";
    t.extra = args;
    t.bol = false;
    pushback_.push_back(std::move(t));
    return;
  }
  // Everything else (GCC diagnostic, warning, comment, STDC, ...) has no
  // effect on declarations.
}

void Preprocessor::pragma_text(const std::string &text, const Token &at) {
  std::vector<Token> toks = tokenize(ctx_, at.file, text);
  for (Token &t : toks) {
    t.line = at.line;
    t.col = at.col;
    t.bol = false;
  }
  do_pragma(std::move(toks), at);
}

// ---------------------------------------------------------------------------
// Includes
// ---------------------------------------------------------------------------

std::optional<Preprocessor::Found> Preprocessor::find_include(const std::string &name, bool quoted, bool next,
                                                              const Token &at) {
  FileSystem *fs = ctx_.options.fs;
  auto try_path = [&](const std::string &path, int index, bool system) -> std::optional<Found> {
    if (!fs) return std::nullopt;
    std::optional<std::string> c = fs->resolve(path);
    if (!c) return std::nullopt;
    return Found{*c, path, index, system, false};
  };
  if (!name.empty() && name[0] == '/') {
    if (auto f = try_path(name, -1, false)) return f;
    return std::nullopt;
  }
  std::size_t start = 0;
  const FileInfo *cur = frames_.empty() ? nullptr : &ctx_.files[frames_.back().file];
  if (next && cur && cur->search_index >= 0) start = static_cast<std::size_t>(cur->search_index) + 1;
  if (quoted && !next && cur && !cur->canonical.empty() && !cur->builtin) {
    if (auto f = try_path(dir_of(cur->canonical) + "/" + name, -1, cur->system)) return f;
  }
  for (std::size_t i = start; i < dirs_.size(); ++i) {
    const SearchDir &d = dirs_[i];
    if (d.builtin) {
      if (builtin_header(name)) return Found{"<builtin>/" + name, "<builtin>/" + name, int(i), true, true};
      continue;
    }
    std::string base = d.path;
    if (!base.empty() && base.back() == '/') base.pop_back();
    if (auto f = try_path(base + "/" + name, int(i), d.system)) return f;
  }
  (void)at;
  return std::nullopt;
}

void Preprocessor::do_include(std::vector<Token> line, const Token &at, bool next, bool import) {
  std::string name;
  bool quoted = false;
  auto header_name = [&](const std::vector<Token> &l) -> bool {
    if (l.empty()) return false;
    if (l[0].kind == TK::String && l[0].text.size() >= 2 && l[0].text[0] == '<') {
      name = l[0].text.substr(1, l[0].text.size() - 2);
      return true;
    }
    if (l[0].kind == TK::String && l[0].text.size() >= 2 && l[0].text[0] == '"') {
      name = l[0].text.substr(1, l[0].text.size() - 2);
      quoted = true;
      return true;
    }
    if (l[0].punct("<")) {
      for (std::size_t i = 1; i < l.size() && !l[i].punct(">"); ++i) {
        if (i > 1 && l[i].space) name += ' ';
        name += l[i].text;
      }
      return true;
    }
    return false;
  };
  if (!header_name(line) && !header_name(expand(std::move(line))))
    return ctx_.error(at, "#include expects \"FILENAME\" or <FILENAME>");
  if (name.empty()) return ctx_.error(at, "empty filename in #include");
  std::optional<Found> found = find_include(name, quoted, next, at);
  if (!found) return ctx_.error(at, "'" + name + "' file not found");
  if (once_.contains(found->canonical)) return;
  if (auto g = guards_.find(found->canonical); g != guards_.end() && macros_.contains(g->second)) return;
  if (import) once_.insert(found->canonical);
  std::string text;
  if (found->builtin) {
    text = builtin_header(name);
  } else {
    std::optional<std::string> body = ctx_.options.fs->read(found->canonical, ctx_.options.limits.max_bytes);
    if (!body) return ctx_.error(at, "cannot read '" + name + "'");
    text = std::move(*body);
  }
  push_file(*found, text, at);
}

// ---------------------------------------------------------------------------
// Macros
// ---------------------------------------------------------------------------

std::uint32_t Preprocessor::macro_id(const std::string &name) {
  auto [it, fresh] = macro_ids_.try_emplace(name, static_cast<std::uint32_t>(macro_ids_.size() + 1));
  return it->second;
}

std::uint32_t Preprocessor::hs_intern(std::vector<std::uint32_t> s) {
  if (s.empty()) return 0;
  auto it = hs_index_.find(s);
  if (it != hs_index_.end()) return it->second;
  const auto id = static_cast<std::uint32_t>(hs_sets_.size());
  hs_sets_.push_back(s);
  hs_index_.emplace(std::move(s), id);
  return id;
}

bool Preprocessor::hs_has(std::uint32_t hs, std::uint32_t id) const {
  const auto &s = hs_sets_[hs];
  return std::binary_search(s.begin(), s.end(), id);
}

std::uint32_t Preprocessor::hs_with(std::uint32_t hs, std::uint32_t id) {
  if (hs_has(hs, id)) return hs;
  const std::uint64_t key = (std::uint64_t(hs) << 32) | id;
  if (auto it = hs_with_memo_.find(key); it != hs_with_memo_.end()) return it->second;
  std::vector<std::uint32_t> s = hs_sets_[hs];
  s.insert(std::lower_bound(s.begin(), s.end(), id), id);
  const std::uint32_t out = hs_intern(std::move(s));
  hs_with_memo_.emplace(key, out);
  return out;
}

std::uint32_t Preprocessor::hs_union(std::uint32_t a, std::uint32_t b) {
  if (a == 0 || a == b) return b;
  if (b == 0) return a;
  const std::uint64_t key = (std::uint64_t(a) << 32) | b;
  if (auto it = hs_union_memo_.find(key); it != hs_union_memo_.end()) return it->second;
  std::vector<std::uint32_t> s;
  std::set_union(hs_sets_[a].begin(), hs_sets_[a].end(), hs_sets_[b].begin(), hs_sets_[b].end(), std::back_inserter(s));
  const std::uint32_t out = hs_intern(std::move(s));
  hs_union_memo_.emplace(key, out);
  return out;
}

std::uint32_t Preprocessor::hs_intersect(std::uint32_t a, std::uint32_t b) {
  if (a == 0 || b == 0) return 0;
  if (a == b) return a;
  std::vector<std::uint32_t> s;
  std::set_intersection(hs_sets_[a].begin(), hs_sets_[a].end(), hs_sets_[b].begin(), hs_sets_[b].end(),
                        std::back_inserter(s));
  return hs_intern(std::move(s));
}

bool Preprocessor::expand_macro(const Token &tok) {
  auto it = macros_.find(tok.text);
  if (it == macros_.end()) return false;
  if (hs_has(tok.hideset, it->second.id)) return false;
  const Macro m = it->second;  // a copy: directives inside arguments may redefine it
  auto make = [&](TK kind, std::string text) {
    Token t = tok;
    t.kind = kind;
    t.text = std::move(text);
    t.hideset = hs_with(tok.hideset, m.id);
    push_front({t});
    return true;
  };
  switch (m.builtin) {
    case Macro::Builtin::None: break;
    case Macro::Builtin::File: {
      std::string name = tok.file < ctx_.files.size() ? ctx_.files[tok.file].name : "";
      if (tok.text == "__FILE_NAME__" && name.rfind('/') != std::string::npos) name = name.substr(name.rfind('/') + 1);
      return make(TK::String, quote_string(name));
    }
    case Macro::Builtin::BaseFile:
      return make(TK::String, quote_string(base_file_ < ctx_.files.size() ? ctx_.files[base_file_].name : ""));
    case Macro::Builtin::Line: return make(TK::Number, std::to_string(tok.line));
    case Macro::Builtin::Counter: return make(TK::Number, std::to_string(counter_++));
    case Macro::Builtin::Date: return make(TK::String, tok.text == "__TIME__" ? "\"00:00:00\"" : "\"Jan  1 1970\"");
    case Macro::Builtin::Time: return make(TK::String, "\"00:00:00\"");
    case Macro::Builtin::IncludeLevel:
      return make(TK::Number, std::to_string(frames_.empty() ? 0 : frames_.size() - 1));
    case Macro::Builtin::HasQuery: return false;
  }
  if (!m.function_like) {
    std::vector<Token> body = m.body;
    const std::uint32_t hs = hs_with(tok.hideset, m.id);
    for (Token &b : body) {
      b.hideset = hs_union(b.hideset, hs);
      b.file = tok.file;
      b.line = tok.line;
      b.col = tok.col;
      b.bol = false;
    }
    if (!body.empty()) body.front().space = tok.space;
    ctx_.add_expansion(body.size() + 1);
    push_front(std::move(body));
    return true;
  }
  const Token *p = peek_raw();
  if (!p || !p->punct("(")) return false;
  std::vector<Arg> args;
  Token rparen;
  ctx_.check_nesting(++expand_depth_);
  struct Depth {
    std::uint32_t &d;
    ~Depth() { --d; }
  } depth{expand_depth_};
  if (!read_args(m, args, rparen, tok)) return true;
  const std::uint32_t hs = hs_with(hs_intersect(tok.hideset, rparen.hideset), m.id);
  std::vector<Token> body = subst(m, args, m.body.data(), m.body.data() + m.body.size(), tok, 0);
  for (Token &b : body) {
    b.hideset = hs_union(b.hideset, hs);
    b.file = tok.file;
    b.line = tok.line;
    b.col = tok.col;
    b.bol = false;
  }
  if (!body.empty()) body.front().space = tok.space;
  ctx_.add_expansion(body.size() + 1);
  push_front(std::move(body));
  return true;
}

bool Preprocessor::read_args(const Macro &m, std::vector<Arg> &args, Token &rparen, const Token &name) {
  Token t;
  bool ff;
  read_raw(t, ff);  // (
  // Reads one token of the arguments, never past the end of the file the
  // invocation started in.
  auto read = [&](Token &out, bool &from_frame) {
    if (pushback_.size() > pushback_floor_ || isolated_) return read_raw(out, from_frame);
    if (frames_.empty() || frames_.back().pos >= frames_.back().toks.size()) return false;
    return read_raw(out, from_frame);
  };
  const std::size_t nparams = m.params.size();
  args.emplace_back();
  int depth = 0;
  std::size_t count = 0;
  for (;;) {
    if (!read(t, ff)) {
      ctx_.error(name, "unterminated argument list invoking macro \"" + name.text + "\"");
      return false;
    }
    if (ff && t.bol && t.punct("#")) {
      directive(t);  // GCC allows conditionals inside macro arguments
      continue;
    }
    if (++count % 1024 == 0) ctx_.add_expansion(1024);
    if (t.punct("(")) ++depth;
    else if (t.punct(")")) {
      if (depth == 0) {
        rparen = t;
        break;
      }
      --depth;
    } else if (t.punct(",") && depth == 0 && !(m.variadic && args.size() == nparams)) {
      args.emplace_back();
      continue;
    }
    args.back().raw.push_back(std::move(t));
  }
  if (nparams == 0 && args.size() == 1 && args[0].raw.empty()) args.clear();
  if (m.variadic && args.size() + 1 == nparams) args.emplace_back();
  if (args.size() != nparams) {
    ctx_.error(name, "macro \"" + name.text + "\" requires " + std::to_string(nparams) + " arguments, but " +
                         std::to_string(args.size()) + " given");
    return false;
  }
  return true;
}

std::vector<Token> &Preprocessor::expanded(Arg &a) {
  if (!a.expanded) a.expanded = expand(a.raw);
  return *a.expanded;
}

Token Preprocessor::stringize(const std::vector<Token> &toks, const Token &site) {
  std::string s = "\"";
  for (std::size_t i = 0; i < toks.size(); ++i) {
    if (i > 0 && toks[i].space) s += ' ';
    if (toks[i].kind == TK::String || toks[i].kind == TK::Char) {
      for (char c : toks[i].text) {
        if (c == '"' || c == '\\') s += '\\';
        s += c;
      }
    } else {
      s += toks[i].text;
    }
  }
  s += '"';
  Token t = site;
  t.kind = TK::String;
  t.text = std::move(s);
  t.hideset = 0;
  return t;
}

std::vector<Token> Preprocessor::paste(const Token &lhs, const Token &rhs, const Token &site) {
  if (is_placemarker(lhs)) return {rhs};
  if (is_placemarker(rhs)) return {lhs};
  std::vector<Token> toks = tokenize(ctx_, site.file, lhs.text + rhs.text);
  if (toks.size() == 1) {
    Token t = std::move(toks[0]);
    t.file = site.file;
    t.line = site.line;
    t.col = site.col;
    t.bol = false;
    t.space = lhs.space;
    t.hideset = lhs.hideset;
    return {t};
  }
  // GCC tolerates pasting a comma or other non-token in some system
  // headers' idioms; keep both tokens.
  if (!lhs.punct(","))
    ctx_.warning(site, "pasting \"" + lhs.text + "\" and \"" + rhs.text + "\" does not give a valid preprocessing token");
  return {lhs, rhs};
}

std::vector<Token> Preprocessor::subst(const Macro &m, std::vector<Arg> &args, const Token *begin, const Token *end,
                                       const Token &site, int depth) {
  ctx_.check_nesting(static_cast<std::uint32_t>(depth));
  auto param = [&](const Token &t) -> int {
    if (t.kind != TK::Ident) return -1;
    for (std::size_t i = 0; i < m.params.size(); ++i)
      if (m.params[i] == t.text) return static_cast<int>(i);
    return -1;
  };
  auto va_nonempty = [&]() {
    if (!m.variadic || args.empty()) return false;
    return !expanded(args.back()).empty();
  };
  // __VA_OPT__ ( content ): the range of the content, or nullopt.
  auto va_opt = [&](const Token *p, const Token *&content_begin, const Token *&content_end) -> const Token * {
    if (!m.variadic || !p->ident("__VA_OPT__") || p + 1 >= end || !(p + 1)->punct("(")) return nullptr;
    int d = 0;
    for (const Token *q = p + 1; q < end; ++q) {
      if (q->punct("(")) ++d;
      else if (q->punct(")") && --d == 0) {
        content_begin = p + 2;
        content_end = q;
        return q;
      }
    }
    return nullptr;
  };
  std::vector<Token> out;
  for (const Token *p = begin; p < end; ++p) {
    const Token &t = *p;
    // # parameter
    if (m.function_like && t.punct("#") && p + 1 < end) {
      const int k = param(p[1]);
      if (k >= 0) {
        Token s = stringize(args[std::size_t(k)].raw, site);
        s.space = t.space;
        out.push_back(std::move(s));
        ++p;
        continue;
      }
      const Token *cb, *ce;
      if (const Token *close = va_opt(p + 1, cb, ce)) {
        std::vector<Token> inner = va_nonempty() ? subst(m, args, cb, ce, site, depth + 1) : std::vector<Token>{};
        std::erase_if(inner, is_placemarker);
        out.push_back(stringize(inner, site));
        p = close;
        continue;
      }
    }
    // GNU: , ## __VA_ARGS__ drops the comma when there are no variable arguments.
    if (t.punct(",") && p + 2 < end && p[1].punct("##") && m.variadic && param(p[2]) == int(m.params.size() - 1)) {
      const std::vector<Token> &va = args.back().raw;
      if (va.empty()) {
        p += 2;
        continue;
      }
      out.push_back(t);
      for (const Token &x : va) out.push_back(x);
      p += 2;
      continue;
    }
    if (t.punct("##")) {
      if (out.empty() || p + 1 >= end) continue;  // diagnosed at #define
      ++p;
      std::vector<Token> rhs;
      const Token *cb, *ce;
      if (const int k = param(*p); k >= 0) {
        rhs = args[std::size_t(k)].raw;
        if (rhs.empty()) rhs.push_back(placemarker(site));
      } else if (const Token *close = va_opt(p, cb, ce)) {
        rhs = va_nonempty() ? subst(m, args, cb, ce, site, depth + 1) : std::vector<Token>{};
        if (rhs.empty()) rhs.push_back(placemarker(site));
        p = close;
      } else {
        rhs.push_back(*p);
      }
      Token lhs = std::move(out.back());
      out.pop_back();
      for (Token &x : paste(lhs, rhs.front(), site)) out.push_back(std::move(x));
      for (std::size_t i = 1; i < rhs.size(); ++i) out.push_back(std::move(rhs[i]));
      continue;
    }
    const Token *cb, *ce;
    if (const Token *close = va_opt(p, cb, ce)) {
      std::vector<Token> inner = va_nonempty() ? subst(m, args, cb, ce, site, depth + 1) : std::vector<Token>{};
      if (inner.empty()) out.push_back(placemarker(site));
      for (Token &x : inner) out.push_back(std::move(x));
      p = close;
      continue;
    }
    if (const int k = param(t); k >= 0) {
      Arg &a = args[std::size_t(k)];
      // An operand of ## is the argument as written; anything else is
      // fully expanded first.
      if (p + 1 < end && p[1].punct("##")) {
        if (a.raw.empty()) out.push_back(placemarker(site));
        for (const Token &x : a.raw) out.push_back(x);
      } else {
        const std::vector<Token> &e = expanded(a);
        const std::size_t first = out.size();
        for (const Token &x : e) out.push_back(x);
        if (out.size() > first) out[first].space = t.space;
      }
      ctx_.add_expansion(a.raw.size());
      continue;
    }
    out.push_back(t);
  }
  if (depth == 0) std::erase_if(out, is_placemarker);
  return out;
}

// ---------------------------------------------------------------------------
// #if
// ---------------------------------------------------------------------------

bool Preprocessor::has_query(const std::string &name, std::vector<Token> &line, std::size_t &i, Value &out,
                             const Token &at) {
  // line[i] is the query's name; reads ( ... ) after it.
  if (i + 1 >= line.size() || !line[i + 1].punct("(")) {
    ctx_.error(at, "missing '(' after " + name);
    return false;
  }
  std::size_t j = i + 2;
  int depth = 0;
  std::vector<Token> arg;
  for (; j < line.size(); ++j) {
    if (line[j].punct("(")) ++depth;
    if (line[j].punct(")") && depth-- == 0) break;
    arg.push_back(line[j]);
  }
  if (j >= line.size()) {
    ctx_.error(at, "missing ')' after " + name);
    return false;
  }
  i = j;
  out = {0, false};
  if (name == "__has_include" || name == "__has_include_next" || name == "__has_embed") {
    std::string file;
    bool quoted = false;
    if (!arg.empty() && arg[0].kind != TK::String && !arg[0].punct("<")) arg = expand(std::move(arg));
    if (!arg.empty() && arg[0].kind == TK::String) {
      file = arg[0].text.size() >= 2 ? arg[0].text.substr(1, arg[0].text.size() - 2) : "";
      quoted = arg[0].text[0] == '"';
    } else if (!arg.empty() && arg[0].punct("<")) {
      for (std::size_t k = 1; k < arg.size() && !arg[k].punct(">"); ++k) {
        if (k > 1 && arg[k].space) file += ' ';
        file += arg[k].text;
      }
    }
    if (!file.empty() && name != "__has_embed") out.v = find_include(file, quoted, name == "__has_include_next", at) ? 1 : 0;
    return true;
  }
  std::string what;
  for (const Token &t : arg) what += t.text;
  if (name == "__has_attribute" || name == "__has_cpp_attribute" || name == "__has_c_attribute" ||
      name == "__has_declspec_attribute") {
    if (auto colons = what.rfind("::"); colons != std::string::npos) what = what.substr(colons + 2);
    out.v = known_attribute(what) ? 1 : 0;
  } else if (name == "__has_builtin") {
    out.v = what == "__builtin_va_list" || what == "__builtin_offsetof" || what == "__builtin_va_start" ||
                    what == "__builtin_va_end" || what == "__builtin_va_arg" || what == "__builtin_va_copy"
                ? 1
                : 0;
  } else if (name == "__is_identifier") {
    out.v = 1;
  }
  return true;
}

bool Preprocessor::eval_condition(std::vector<Token> line, const Token &at) {
  // defined and the __has_ queries, before expansion.
  std::vector<Token> pre;
  auto number = [&](std::uint64_t v, const Token &where) {
    Token t = where;
    t.kind = TK::Number;
    t.text = std::to_string(v);
    return t;
  };
  for (std::size_t i = 0; i < line.size(); ++i) {
    const Token &t = line[i];
    if (t.ident("defined")) {
      std::size_t j = i + 1;
      const bool paren = j < line.size() && line[j].punct("(");
      if (paren) ++j;
      if (j >= line.size() || line[j].kind != TK::Ident) {
        ctx_.error(at, "macro name missing after \"defined\"");
        return false;
      }
      const bool def = macros_.contains(line[j].text);
      if (paren) {
        if (j + 1 >= line.size() || !line[j + 1].punct(")")) {
          ctx_.error(at, "missing ')' after \"defined\"");
          return false;
        }
        ++j;
      }
      pre.push_back(number(def, t));
      i = j;
      continue;
    }
    if (t.kind == TK::Ident) {
      auto it = macros_.find(t.text);
      if (it != macros_.end() && it->second.builtin == Macro::Builtin::HasQuery) {
        Value v;
        if (!has_query(t.text, line, i, v, at)) return false;
        pre.push_back(number(v.v, t));
        continue;
      }
    }
    pre.push_back(t);
  }
  in_condition_ = true;
  std::vector<Token> toks;
  try {
    toks = expand(std::move(pre));
  } catch (...) {
    in_condition_ = false;
    throw;
  }
  in_condition_ = false;
  // Expansion can produce more queries (#define HAS(x) __has_include(x)).
  for (std::size_t i = 0; i < toks.size(); ++i) {
    if (toks[i].kind != TK::Ident) continue;
    auto it = macros_.find(toks[i].text);
    if (it != macros_.end() && it->second.builtin == Macro::Builtin::HasQuery) {
      Value v;
      std::size_t j = i;
      if (!has_query(toks[i].text, toks, j, v, at)) return false;
      toks.erase(toks.begin() + std::ptrdiff_t(i) + 1, toks.begin() + std::ptrdiff_t(j) + 1);
      toks[i] = number(v.v, toks[i]);
    } else if (toks[i].text == "defined" && i + 1 < toks.size()) {
      // From an expansion: undefined behavior, which GCC evaluates.
      std::size_t j = i + 1;
      const bool paren = toks[j].punct("(");
      if (paren) ++j;
      if (j < toks.size() && toks[j].kind == TK::Ident) {
        const bool def = macros_.contains(toks[j].text);
        if (paren && j + 1 < toks.size()) ++j;
        toks.erase(toks.begin() + std::ptrdiff_t(i) + 1, toks.begin() + std::ptrdiff_t(j) + 1);
        toks[i] = number(def, toks[i]);
      }
    }
  }
  ExprResult r = evaluate_pp(toks, cplusplus_, ctx_.options.limits.max_nesting);
  if (!r.ok) {
    ctx_.error(at, r.error.empty() ? std::string("invalid #if expression") : r.error);
    return false;
  }
  return r.value != 0;
}

}  // namespace revkit::cparse::detail
