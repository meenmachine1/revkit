#include "export_c.h"

#include <cctype>
#include <cstdio>
#include <string_view>

namespace revkit::backend {

cparse::Dialect DialectOf(revkit::v1::CDialect d) {
  return d == revkit::v1::C_DIALECT_C89 ? cparse::Dialect::C89 : cparse::Dialect::C11;
}

namespace {

// The data model's unsigned integer of `size` bytes ("unsigned int"), and
// whether it is a `long long` (which C89 only has under __extension__).
std::string unsigned_of(const cparse::LayoutRules &r, unsigned size, bool &longlong) {
  longlong = false;
  if (size == 1) return "unsigned char";
  if (r.short_size == size) return "unsigned short";
  if (r.int_size == size) return "unsigned int";
  if (r.long_size == size) return "unsigned long";
  longlong = true;
  return "unsigned long long";
}

}  // namespace

const std::set<std::string> &GhidraBuiltinNames() {
  static const std::set<std::string> names = {
      "undefined", "undefined1", "undefined2", "undefined4", "undefined8", "byte",     "sbyte",   "word",
      "dword",     "qword",      "uchar",      "ushort",     "uint",       "ulong",    "longlong", "ulonglong",
      "wchar16",   "wchar32",    "float4",     "float8",     "code",       "_func_void", "bool"};
  return names;
}

std::string FunctionTypeName(const std::string &text) {
  const std::size_t paren = text.find('(');
  if (paren == std::string::npos) return {};
  std::size_t b = paren;
  while (b > 0 && (std::isalnum(static_cast<unsigned char>(text[b - 1])) || text[b - 1] == '_')) --b;
  return text.substr(b, paren - b);
}

std::string TagTypedefs(const revkit::v1::TypeArchiveSidecar &archive, std::set<std::string> &names) {
  for (const revkit::v1::TypeArchiveEntry &t : archive.types())
    if (t.key().rfind("typedef ", 0) == 0) names.insert(t.key().substr(8));
  std::string tags;
  for (const revkit::v1::TypeArchiveEntry &t : archive.types())
    for (std::string_view kind : {"struct ", "union ", "enum "})
      if (t.key().rfind(kind, 0) == 0 && names.insert(t.key().substr(kind.size())).second)
        tags += "typedef " + t.key() + " " + t.key().substr(kind.size()) + ";\n";
  return tags;
}

bool CIdentifier(const std::string &name) {
  if (name.empty() || std::isdigit(static_cast<unsigned char>(name[0]))) return false;
  for (char c : name)
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') return false;
  return true;
}

bool FunctionTypesNamed(const std::string &p, const std::set<std::string> &names) {
  for (std::size_t at = p.find("_func_"); at != std::string::npos; at = p.find("_func_", at + 1)) {
    if (at > 0 && (std::isalnum(static_cast<unsigned char>(p[at - 1])) || p[at - 1] == '_')) continue;
    std::size_t e = at;
    while (e < p.size() && (std::isalnum(static_cast<unsigned char>(p[e])) || p[e] == '_')) ++e;
    if (!names.contains(p.substr(at, e - at))) return false;
  }
  return true;
}

std::string GlobalDeclaration(const revkit::v1::Variable &var) {
  std::string ty = var.type().display().empty() ? std::string("undefined") : var.type().display();
  // "undefined1 [16]": the array's bounds go after the name.
  std::string bounds;
  if (const std::size_t br = ty.find('['); br != std::string::npos) {
    bounds = ty.substr(br);
    ty = ty.substr(0, br);
    while (!ty.empty() && ty.back() == ' ') ty.pop_back();
  }
  std::string decl = "extern " + ty + (ty.ends_with('*') ? "" : " ") + var.name() + bounds + ";";
  if (var.has_address()) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%08llx", static_cast<unsigned long long>(var.address().offset()));
    decl += " /* " + std::string(b) + " */";
  }
  return decl;
}

std::string GhidraBuiltinTypedefs(const cparse::Profile &profile, cparse::Dialect dialect) {
  const bool c89 = dialect == cparse::Dialect::C89;
  const cparse::LayoutRules &r = profile.rules;
  std::string out = "/* Ghidra's built-in type names, as the decompiler prints them";
  out += c89 ? " (C89). */\n" : ". */\n";
  out += "#ifndef REVKIT_GHIDRA_TYPES\n#define REVKIT_GHIDRA_TYPES\n";
  if (c89) {
    out += "#if !defined(__GNUC__) && !defined(__extension__)\n#define __extension__\n#endif\n";
    out += "#if !defined(__cplusplus) && !defined(bool) && !defined(REVKIT_BOOL)\n#define REVKIT_BOOL\n"
           "typedef unsigned char bool;\n#endif\n";
    out += "#if !defined(__cplusplus) && !defined(true)\n#define true 1\n#define false 0\n#endif\n";
  } else {
    out += "#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L)\n"
           "#include <stdbool.h>\n#endif\n";
  }
  auto td = [&](const std::string &type, const std::string &name, bool longlong) {
    out += std::string(c89 && longlong ? "__extension__ " : "") + "typedef " + type + " " + name + ";\n";
  };
  bool ll = false;
  auto u = [&](unsigned size) { return unsigned_of(r, size, ll); };
  std::string t;
  td("unsigned char", "undefined", false);
  td("unsigned char", "undefined1", false);
  t = u(2), td(t, "undefined2", ll);
  t = u(4), td(t, "undefined4", ll);
  t = u(8), td(t, "undefined8", ll);
  td("unsigned char", "byte", false);
  td("signed char", "sbyte", false);
  t = u(2), td(t, "word", ll);
  t = u(4), td(t, "dword", ll);
  t = u(8), td(t, "qword", ll);
  td("unsigned char", "uchar", false);
  td("unsigned short", "ushort", false);
  td("unsigned int", "uint", false);
  td("unsigned long", "ulong", false);
  td("long long", "longlong", true);
  td("unsigned long long", "ulonglong", true);
  t = u(2), td(t, "wchar16", ll);
  t = u(4), td(t, "wchar32", ll);
  td("float", "float4", false);
  td("double", "float8", false);
  // A function of unknown prototype: called with any arguments, its result
  // read as a word (`(*(code *)p)(a, b)`, `x = (*(code *)p)()`), which C
  // spells without a prototype (C23 and C++ with `...`).
  out += "#if defined(__cplusplus) || (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L)\n"
         "typedef int code(...);\n#else\n#ifdef __clang__\n#pragma clang diagnostic push\n"
         "#pragma clang diagnostic ignored \"-Wstrict-prototypes\"\n#endif\ntypedef int code();\n"
         "#ifdef __clang__\n#pragma clang diagnostic pop\n#endif\n#endif\n";
  out += "typedef void _func_void(void);\n";
  out += "/* Ghidra's calling-convention names, where the compiler has none. */\n"
         "#ifndef _MSC_VER\n"
         "#ifndef __stdcall\n#define __stdcall\n#endif\n"
         "#ifndef __cdecl\n#define __cdecl\n#endif\n"
         "#ifndef __fastcall\n#define __fastcall\n#endif\n"
         "#ifndef __thiscall\n#define __thiscall\n#endif\n"
         "#ifndef __vectorcall\n#define __vectorcall\n#endif\n"
         "#endif\n"
         "#define processEntry\n";
  out += "#endif /* REVKIT_GHIDRA_TYPES */\n";
  return out;
}

}  // namespace revkit::backend
