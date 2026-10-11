#include "revkit/demangle/demangle.h"

#include "llvm/Demangle/Demangle.h"

#include <cstdlib>
#include <memory>

namespace revkit::demangle {
namespace {

struct Free {
  void operator()(char *p) const { std::free(p); }
};
using CString = std::unique_ptr<char, Free>;

std::optional<std::string> take(char *p) {
  CString owned(p);
  if (!owned) return std::nullopt;
  return std::string(owned.get());
}

// Itanium symbols appear with one to three leading underscores (Mach-O adds
// one; block invocations use ___Z).
bool itanium_prefix(std::string_view s) {
  for (int i = 0; i < 3 && !s.empty() && s[0] == '_'; ++i) {
    s.remove_prefix(1);
    if (!s.empty() && s[0] == 'Z') return true;
  }
  return false;
}

// LLVM's demanglers take string_views, but some (D) read the byte past
// the end, expecting a C string. Every call goes through a std::string copy
// so that byte is a NUL.

}  // namespace

Scheme detect(std::string_view s) {
  if (itanium_prefix(s) || s.starts_with("_GLOBAL__")) return Scheme::Itanium;
  if (s.starts_with("?") || s.starts_with("__imp_?")) return Scheme::Microsoft;
  if (s.starts_with("_R")) return Scheme::Rust;
  if (s == "_Dmain" || (s.starts_with("_D") && s.size() > 2 && s[2] >= '0' && s[2] <= '9'))
    return Scheme::D;
  return Scheme::None;
}

std::optional<std::string> demangle_itanium(std::string_view symbol, bool with_params) {
  const std::string owned(symbol);
  std::string_view s = owned;
  // llvm::itaniumDemangle wants exactly "_Z..." or "___Z...".
  if (s.starts_with("__Z") && !s.starts_with("___Z")) s.remove_prefix(1);
  return take(llvm::itaniumDemangle(s, with_params));
}

std::optional<std::string> demangle_microsoft(std::string_view symbol) {
  const std::string owned(symbol);
  std::string_view s = owned;
  if (s.starts_with("__imp_")) s.remove_prefix(6);
  int status = 0;
  std::size_t consumed = 0;
  CString out(llvm::microsoftDemangle(s, &consumed, &status));
  if (status != llvm::demangle_success || !out) return std::nullopt;
  return std::string(out.get());
}

std::optional<std::string> demangle(std::string_view symbol) {
  switch (detect(symbol)) {
    case Scheme::Itanium: return demangle_itanium(symbol);
    case Scheme::Microsoft: return demangle_microsoft(symbol);
    case Scheme::Rust: return take(llvm::rustDemangle(std::string(symbol)));
    case Scheme::D: return take(llvm::dlangDemangle(std::string(symbol)));
    case Scheme::None: break;
  }
  return std::nullopt;
}

std::string demangle_or_self(std::string_view symbol) {
  return demangle(symbol).value_or(std::string(symbol));
}

std::optional<FunctionParts> itanium_function_parts(std::string_view symbol) {
  if (detect(symbol) != Scheme::Itanium) return std::nullopt;
  std::string s(symbol);
  if (s.starts_with("__Z") && !s.starts_with("___Z")) s.erase(0, 1);
  llvm::ItaniumPartialDemangler d;
  if (d.partialDemangle(s.c_str()) || !d.isFunction()) return std::nullopt;
  auto get = [&](char *(llvm::ItaniumPartialDemangler::*fn)(char *, std::size_t *) const) {
    std::size_t n = 0;
    CString out((d.*fn)(nullptr, &n));
    return out ? std::string(out.get()) : std::string();
  };
  FunctionParts p;
  p.name = get(&llvm::ItaniumPartialDemangler::getFunctionName);
  p.base_name = get(&llvm::ItaniumPartialDemangler::getFunctionBaseName);
  p.context = get(&llvm::ItaniumPartialDemangler::getFunctionDeclContextName);
  p.parameters = get(&llvm::ItaniumPartialDemangler::getFunctionParameters);
  p.return_type = get(&llvm::ItaniumPartialDemangler::getFunctionReturnType);
  p.is_ctor_or_dtor = d.isCtorOrDtor();
  return p;
}

}  // namespace revkit::demangle
