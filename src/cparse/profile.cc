// Targets: layout rules and predefined macros.

#include "revkit/cparse/cparse.h"

#include <algorithm>
#include <cstdlib>
#include <map>
#include <set>

namespace revkit::cparse {

std::uint32_t LayoutRules::scalar_align(std::uint64_t size) const {
  std::uint32_t a = 1;
  std::uint32_t best = 0;
  for (const auto &[s, al] : size_alignment) {
    if (s == size) {
      a = al;
      best = s;
      break;
    }
    if (s < size && s >= best) {
      best = s;
      a = al;
    }
  }
  if (best == 0) a = 1;
  if (max_alignment) a = std::min(a, max_alignment);
  return std::max<std::uint32_t>(a, 1);
}

namespace {

enum class Model { LP64, LLP64, ILP32 };

Profile make(std::string name, std::string arch, Os os, Compiler compiler, Model model) {
  Profile p;
  p.name = std::move(name);
  p.arch = std::move(arch);
  p.os = os;
  p.compiler = compiler;
  LayoutRules &r = p.rules;
  switch (model) {
    case Model::LP64: break;
    case Model::LLP64: r.long_size = 4; break;
    case Model::ILP32:
      r.pointer_size = 4;
      r.long_size = 4;
      r.has_int128 = false;
      break;
  }
  if (os == Os::Windows) {
    r.wchar_size = 2;
    r.wchar_signed = false;
    r.bitfields = BitfieldModel::Msvc;
  }
  return p;
}

const std::map<std::string, Profile, std::less<>> &profiles() {
  static const std::map<std::string, Profile, std::less<>> m = [] {
    std::map<std::string, Profile, std::less<>> m;
    auto add = [&](Profile p) { m.emplace(p.name, std::move(p)); };
    add(make("x86_64-linux-gnu", "x86_64", Os::Linux, Compiler::Gcc, Model::LP64));
    {
      Profile p = make("aarch64-linux-gnu", "aarch64", Os::Linux, Compiler::Gcc, Model::LP64);
      p.rules.char_signed = false;
      p.rules.zero_width_bitfield_aligns = true;
      p.rules.wchar_signed = false;
      add(p);
    }
    {
      Profile p = make("riscv64-linux-gnu", "riscv64", Os::Linux, Compiler::Gcc, Model::LP64);
      p.rules.char_signed = false;
      add(p);
    }
    add(make("x86_64-w64-mingw32", "x86_64", Os::Windows, Compiler::Gcc, Model::LLP64));
    {
      Profile p = make("x86_64-pc-windows-msvc", "x86_64", Os::Windows, Compiler::Msvc, Model::LLP64);
      p.rules.long_double_size = p.rules.long_double_align = 8;
      p.rules.has_int128 = false;
      p.rules.msvc_enums = true;
      p.rules.size_alignment = {{1, 1}, {2, 2}, {4, 4}, {8, 8}};
      add(p);
    }
    {
      Profile p = make("aarch64-pc-windows-msvc", "aarch64", Os::Windows, Compiler::Msvc, Model::LLP64);
      p.rules.long_double_size = p.rules.long_double_align = 8;
      p.rules.has_int128 = false;
      p.rules.msvc_enums = true;
      add(p);
    }
    {
      Profile p = make("i386-linux-gnu", "i386", Os::Linux, Compiler::Gcc, Model::ILP32);
      p.rules.long_double_size = 12;
      p.rules.long_double_align = 4;
      p.rules.size_alignment = {{1, 1}, {2, 2}, {4, 4}, {8, 4}, {16, 16}};
      add(p);
    }
    {
      Profile p = make("i686-w64-mingw32", "i386", Os::Windows, Compiler::Gcc, Model::ILP32);
      p.rules.long_double_size = 12;
      p.rules.long_double_align = 4;
      add(p);
    }
    {
      Profile p = make("i386-pc-windows-msvc", "i386", Os::Windows, Compiler::Msvc, Model::ILP32);
      p.rules.long_double_size = p.rules.long_double_align = 8;
      p.rules.msvc_enums = true;
      p.rules.size_alignment = {{1, 1}, {2, 2}, {4, 4}, {8, 8}};
      add(p);
    }
    {
      Profile p = make("arm-linux-gnueabihf", "arm", Os::Linux, Compiler::Gcc, Model::ILP32);
      p.rules.char_signed = false;
      p.rules.zero_width_bitfield_aligns = true;
      p.rules.wchar_signed = false;
      p.rules.biggest_alignment = p.rules.max_vector_alignment = 8;
      p.rules.long_double_size = p.rules.long_double_align = 8;
      p.rules.size_alignment = {{1, 1}, {2, 2}, {4, 4}, {8, 8}};
      add(p);
    }
    {
      Profile p = make("arm-none-eabi", "arm", Os::None, Compiler::Gcc, Model::ILP32);
      p.rules.char_signed = false;
      p.rules.zero_width_bitfield_aligns = true;
      p.rules.wchar_signed = false;
      p.rules.biggest_alignment = p.rules.max_vector_alignment = 8;
      p.rules.long_double_size = p.rules.long_double_align = 8;
      p.rules.size_alignment = {{1, 1}, {2, 2}, {4, 4}, {8, 8}};
      add(p);
    }
    {
      Profile p = make("riscv32-linux-gnu", "riscv32", Os::Linux, Compiler::Gcc, Model::ILP32);
      p.rules.char_signed = false;
      add(p);
    }
    {
      Profile p = make("powerpc-linux-gnu", "powerpc", Os::Linux, Compiler::Gcc, Model::ILP32);
      p.rules.char_signed = false;
      p.rules.big_endian = true;
      add(p);
    }
    for (bool be : {true, false}) {
      Profile p = make(be ? "mips-linux-gnu" : "mipsel-linux-gnu", be ? "mips" : "mipsel", Os::Linux, Compiler::Gcc,
                       Model::ILP32);
      p.rules.big_endian = be;
      p.rules.biggest_alignment = 8;
      p.rules.long_double_size = p.rules.long_double_align = 8;
      p.rules.size_alignment = {{1, 1}, {2, 2}, {4, 4}, {8, 8}};
      add(p);
    }
    return m;
  }();
  return m;
}

std::string int_type(std::uint32_t size, bool is_unsigned, const LayoutRules &r) {
  std::string u = is_unsigned ? "unsigned " : "";
  if (size == 1) return is_unsigned ? "unsigned char" : "signed char";
  if (size == 2) return is_unsigned ? "short unsigned int" : "short int";
  if (size == r.int_size) return u + "int";
  if (size == r.long_size) return is_unsigned ? "long unsigned int" : "long int";
  if (size == r.long_long_size) return is_unsigned ? "long long unsigned int" : "long long int";
  return u + "int";
}

std::string max_of(std::uint32_t size, bool is_unsigned) {
  if (size >= 8) return is_unsigned ? "0xffffffffffffffffU" : "0x7fffffffffffffff";
  std::uint64_t v = (std::uint64_t(1) << (size * 8 - (is_unsigned ? 0 : 1))) - 1;
  return std::to_string(v) + (is_unsigned && size >= 4 ? "U" : "");
}

}  // namespace

std::optional<Profile> profile_named(std::string_view name) {
  auto it = profiles().find(name);
  if (it == profiles().end()) return std::nullopt;
  return it->second;
}

std::vector<std::string> profile_names() {
  std::vector<std::string> out;
  for (const auto &[k, _] : profiles()) out.push_back(k);
  return out;
}

std::vector<std::pair<std::string, std::string>> Profile::predefined() const {
  std::vector<std::pair<std::string, std::string>> d;
  auto def = [&](std::string n, std::string v = "1") { d.emplace_back(std::move(n), std::move(v)); };
  const LayoutRules &r = rules;
  const bool msvc = compiler == Compiler::Msvc;
  const bool lp64 = r.pointer_size == 8 && r.long_size == 8;
  const bool win = os == Os::Windows;

  // revkit's own parser (type archives keep their compiler-only lines from it).
  def("__revkit__");
  if (!msvc) {
    def("__STDC__");
    def("__STDC_VERSION__", "201710L");
    def("__STDC_HOSTED__");
    if (compiler == Compiler::Clang) {
      def("__clang__");
      def("__clang_major__", "19");
      def("__clang_minor__", "1");
      def("__clang_patchlevel__", "7");
      def("__GNUC__", "4");
      def("__GNUC_MINOR__", "2");
      def("__GNUC_PATCHLEVEL__", "1");
      def("__VERSION__", "\"Clang 19.1.7\"");
    } else {
      def("__GNUC__", "14");
      def("__GNUC_MINOR__", "2");
      def("__GNUC_PATCHLEVEL__", "0");
      def("__VERSION__", "\"14.2.0\"");
    }
    def("__GNUC_STDC_INLINE__");
    def("__USER_LABEL_PREFIX__", (win && r.pointer_size == 4) ? "_" : "");
    def("__REGISTER_PREFIX__", "");
    def("__NO_INLINE__");
    def("__ATOMIC_RELAXED", "0");
    def("__ATOMIC_SEQ_CST", "5");
    def("__ATOMIC_ACQUIRE", "2");
    def("__ATOMIC_RELEASE", "3");
    def("__ATOMIC_ACQ_REL", "4");
    def("__ATOMIC_CONSUME", "1");
  } else {
    def("_MSC_VER", "1938");
    def("_MSC_FULL_VER", "193833130");
    def("_MSC_EXTENSIONS");
    def("_INTEGRAL_MAX_BITS", "64");
    def("__STDC_HOSTED__");
    def("_MT");
  }
  // Sizes, limits and the types the built-in headers use.
  def("__CHAR_BIT__", "8");
  def("__SIZEOF_SHORT__", std::to_string(r.short_size));
  def("__SIZEOF_INT__", std::to_string(r.int_size));
  def("__SIZEOF_LONG__", std::to_string(r.long_size));
  def("__SIZEOF_LONG_LONG__", std::to_string(r.long_long_size));
  def("__SIZEOF_POINTER__", std::to_string(r.pointer_size));
  def("__SIZEOF_FLOAT__", std::to_string(r.float_size));
  def("__SIZEOF_DOUBLE__", std::to_string(r.double_size));
  def("__SIZEOF_LONG_DOUBLE__", std::to_string(r.long_double_size));
  def("__SIZEOF_SIZE_T__", std::to_string(r.pointer_size));
  def("__SIZEOF_PTRDIFF_T__", std::to_string(r.pointer_size));
  def("__SIZEOF_WCHAR_T__", std::to_string(r.wchar_size));
  def("__SIZEOF_WINT_T__", win ? "2" : "4");
  if (r.has_int128) def("__SIZEOF_INT128__", "16");
  def("__BIGGEST_ALIGNMENT__", std::to_string(r.biggest_alignment));
  def("__SCHAR_MAX__", "0x7f");
  def("__SHRT_MAX__", "0x7fff");
  def("__INT_MAX__", "0x7fffffff");
  def("__LONG_MAX__", r.long_size == 8 ? "0x7fffffffffffffffL" : "0x7fffffffL");
  def("__LONG_LONG_MAX__", "0x7fffffffffffffffLL");
  def("__WCHAR_MAX__", r.wchar_size == 2 ? "0xffff" : (r.wchar_signed ? "0x7fffffff" : "0xffffffffU"));
  def("__WCHAR_MIN__", r.wchar_signed ? "(-__WCHAR_MAX__ - 1)" : (r.wchar_size == 2 ? "0" : "0U"));
  def("__WINT_MAX__", win ? "0xffff" : "0xffffffffU");
  def("__WINT_MIN__", win ? "0" : "0U");
  def("__PTRDIFF_MAX__", r.pointer_size == 8 ? (lp64 ? "0x7fffffffffffffffL" : "0x7fffffffffffffffLL") : "0x7fffffff");
  def("__SIZE_MAX__", r.pointer_size == 8 ? (lp64 ? "0xffffffffffffffffUL" : "0xffffffffffffffffULL") : "0xffffffffU");
  def("__INTMAX_MAX__", lp64 ? "0x7fffffffffffffffL" : "0x7fffffffffffffffLL");
  def("__UINTMAX_MAX__", lp64 ? "0xffffffffffffffffUL" : "0xffffffffffffffffULL");
  def("__INTPTR_MAX__", r.pointer_size == 8 ? (lp64 ? "0x7fffffffffffffffL" : "0x7fffffffffffffffLL") : "0x7fffffff");
  def("__UINTPTR_MAX__", r.pointer_size == 8 ? (lp64 ? "0xffffffffffffffffUL" : "0xffffffffffffffffULL") : "0xffffffffU");
  def("__SIG_ATOMIC_MAX__", "0x7fffffff");
  def("__SIG_ATOMIC_MIN__", "(-__SIG_ATOMIC_MAX__ - 1)");
  def("__SIG_ATOMIC_TYPE__", "int");
  const std::string i64 = int_type(8, false, r), u64 = int_type(8, true, r);
  if (r.pointer_size == 8) {
    def("__SIZE_TYPE__", lp64 ? "long unsigned int" : "long long unsigned int");
    def("__PTRDIFF_TYPE__", lp64 ? "long int" : "long long int");
    def("__INTPTR_TYPE__", lp64 ? "long int" : "long long int");
    def("__UINTPTR_TYPE__", lp64 ? "long unsigned int" : "long long unsigned int");
  } else {
    def("__SIZE_TYPE__", "unsigned int");
    def("__PTRDIFF_TYPE__", "int");
    def("__INTPTR_TYPE__", "int");
    def("__UINTPTR_TYPE__", "unsigned int");
  }
  def("__WCHAR_TYPE__", r.wchar_size == 2 ? "short unsigned int" : (r.wchar_signed ? "int" : "unsigned int"));
  def("__WINT_TYPE__", win ? "short unsigned int" : "unsigned int");
  def("__CHAR16_TYPE__", "short unsigned int");
  def("__CHAR32_TYPE__", "unsigned int");
  def("__INTMAX_TYPE__", i64);
  def("__UINTMAX_TYPE__", u64);
  for (std::uint32_t bits : {8u, 16u, 32u, 64u}) {
    const std::string b = std::to_string(bits);
    const std::string s = int_type(bits / 8, false, r), u = int_type(bits / 8, true, r);
    def("__INT" + b + "_TYPE__", s);
    def("__UINT" + b + "_TYPE__", u);
    def("__INT_LEAST" + b + "_TYPE__", s);
    def("__UINT_LEAST" + b + "_TYPE__", u);
    const bool wide = bits == 16 || bits == 32;
    const std::string fs = wide && lp64 ? "long int" : (wide ? "int" : s);
    const std::string fu = wide && lp64 ? "long unsigned int" : (wide ? "unsigned int" : u);
    def("__INT_FAST" + b + "_TYPE__", fs);
    def("__UINT_FAST" + b + "_TYPE__", fu);
    def("__INT" + b + "_MAX__", max_of(bits / 8, false) + (bits == 64 ? (lp64 ? "L" : "LL") : ""));
    def("__UINT" + b + "_MAX__", max_of(bits / 8, true) + (bits == 64 ? (lp64 ? "L" : "LL") : ""));
    const std::string suffix = bits < 32 ? "" : bits == 32 ? "" : (lp64 ? "L" : "LL");
    def("__INT" + b + "_C(c)", suffix.empty() ? "c" : "c ## " + suffix);
    def("__UINT" + b + "_C(c)", bits < 32 ? "c" : "c ## U" + suffix);
  }
  def("__INTMAX_C(c)", lp64 ? "c ## L" : "c ## LL");
  def("__UINTMAX_C(c)", lp64 ? "c ## UL" : "c ## ULL");
  def("__LDBL_MANT_DIG__", r.long_double_size <= 8 ? "53" : (arch == "x86_64" || arch == "i386") ? "64" : "113");
  def("__FLT_MANT_DIG__", "24");
  def("__DBL_MANT_DIG__", "53");
  def("__FLT_RADIX__", "2");
  if (!r.char_signed) def("__CHAR_UNSIGNED__");
  if (!r.wchar_signed && !msvc) def("__WCHAR_UNSIGNED__");
  def("__ORDER_LITTLE_ENDIAN__", "1234");
  def("__ORDER_BIG_ENDIAN__", "4321");
  def("__ORDER_PDP_ENDIAN__", "3412");
  def("__BYTE_ORDER__", r.big_endian ? "__ORDER_BIG_ENDIAN__" : "__ORDER_LITTLE_ENDIAN__");
  def("__FLOAT_WORD_ORDER__", r.big_endian ? "__ORDER_BIG_ENDIAN__" : "__ORDER_LITTLE_ENDIAN__");
  if (lp64) {
    def("__LP64__");
    def("_LP64");
  }

  // The operating system.
  if (os == Os::Linux) {
    def("__linux__");
    def("__linux");
    def("__gnu_linux__");
    def("__unix__");
    def("__unix");
    def("__ELF__");
    def("linux");
    def("unix");
  } else if (os == Os::Windows) {
    def("_WIN32");
    if (r.pointer_size == 8) def("_WIN64");
    if (!msvc) {
      def("__WIN32__");
      def("__WIN32");
      def("WIN32");
      def("__WINNT__");
      def("__WINNT");
      def("WINNT");
      def("__MINGW32__");
      def("__MSVCRT__");
      if (r.pointer_size == 8) {
        def("__WIN64__");
        def("__WIN64");
        def("WIN64");
        def("__MINGW64__");
        def("__SEH__");
      }
    }
  } else if (os == Os::Darwin) {
    def("__APPLE__");
    def("__MACH__");
  } else if (!msvc) {
    def("__ELF__");
  }

  // The processor.
  if (arch == "x86_64") {
    if (msvc) {
      def("_M_X64", "100");
      def("_M_AMD64", "100");
    } else {
      def("__x86_64__");
      def("__x86_64");
      def("__amd64__");
      def("__amd64");
      def("__k8");
      def("__k8__");
      def("__MMX__");
      def("__SSE__");
      def("__SSE2__");
      def("__FXSR__");
      def("__SSE_MATH__");
      def("__SSE2_MATH__");
    }
  } else if (arch == "i386") {
    if (msvc) {
      def("_M_IX86", "600");
      def("_X86_");
    } else {
      def("__i386__");
      def("__i386");
      def("i386");
      def("__i686__");
      def("__i686");
      if (win) def("_X86_");
    }
  } else if (arch == "aarch64") {
    if (msvc) {
      def("_M_ARM64");
    } else {
      def("__aarch64__");
      def("__ARM_64BIT_STATE");
      def("__ARM_ARCH", "8");
      def("__ARM_ARCH_ISA_A64");
      def("__ARM_PCS_AAPCS64");
      def("__AARCH64EL__");
      def("__ARM_FP", "14");
      def("__ARM_NEON");
    }
  } else if (arch == "arm") {
    def("__arm__");
    def("__ARM_EABI__");
    def("__ARM_ARCH", "7");
    def("__ARMEL__");
    def("__APCS_32__");
    if (os == Os::Linux) {
      def("__ARM_PCS_VFP");
      def("__VFP_FP__");
    }
  } else if (arch == "riscv64" || arch == "riscv32") {
    def("__riscv");
    def("__riscv_xlen", arch == "riscv64" ? "64" : "32");
    def("__riscv_flen", "64");
    def("__riscv_float_abi_double");
    def("__riscv_atomic");
    def("__riscv_mul");
    def("__riscv_div");
    def("__riscv_compressed");
  } else if (arch == "powerpc") {
    def("__powerpc__");
    def("__powerpc");
    def("__PPC__");
    def("__ppc__");
    def("_ARCH_PPC");
    def("__BIG_ENDIAN__");
    def("_BIG_ENDIAN");
  } else if (arch == "mips" || arch == "mipsel") {
    def("__mips__");
    def("__mips", "32");
    def("_MIPS_SZPTR", "32");
    def("_MIPS_SZINT", "32");
    def("_MIPS_SZLONG", "32");
    def("_ABIO32", "1");
    def("_MIPS_SIM", "_ABIO32");
    def(arch == "mips" ? "__MIPSEB__" : "__MIPSEL__");
    def(arch == "mips" ? "_MIPSEB" : "_MIPSEL");
  }
  return d;
}

Profile profile_for(const ProfileInputs &in, std::vector<std::string> *notes) {
  auto note = [&](std::string s) {
    if (notes) notes->push_back(std::move(s));
  };
  // language id: processor:endian:size:variant
  std::vector<std::string> parts;
  {
    std::string cur;
    for (char c : in.language_id) {
      if (c == ':') {
        parts.push_back(cur);
        cur.clear();
      } else {
        cur += c;
      }
    }
    parts.push_back(cur);
  }
  const std::string proc = parts.empty() ? "" : parts[0];
  const bool be = parts.size() > 1 && parts[1] == "BE";
  const unsigned bits = parts.size() > 2 ? unsigned(std::atoi(parts[2].c_str())) : 64;
  const bool windows = in.format == "pe" || in.compiler_id == "windows" || in.compiler_id == "Visual Studio";
  const bool bare = in.format == "raw" || in.format == "binary";
  std::string name;
  if (proc == "x86") {
    if (windows) name = bits == 64 ? "x86_64-pc-windows-msvc" : "i386-pc-windows-msvc";
    else name = bits == 64 ? "x86_64-linux-gnu" : "i386-linux-gnu";
    if (windows && (in.compiler_id == "gcc" || in.compiler_id == "clang"))
      name = bits == 64 ? "x86_64-w64-mingw32" : "i686-w64-mingw32";
  } else if (proc == "AARCH64") {
    name = windows ? "aarch64-pc-windows-msvc" : "aarch64-linux-gnu";
  } else if (proc == "RISCV") {
    name = bits == 32 ? "riscv32-linux-gnu" : "riscv64-linux-gnu";
  } else if (proc == "ARM") {
    name = bare ? "arm-none-eabi" : "arm-linux-gnueabihf";
  } else if (proc == "PowerPC") {
    name = "powerpc-linux-gnu";
  } else if (proc == "MIPS") {
    name = be ? "mips-linux-gnu" : "mipsel-linux-gnu";
  }
  Profile p;
  if (auto known = profile_named(name)) {
    p = *known;
  } else {
    // An architecture without a profile: the size and byte order of the
    // language, C's usual sizes, no OS.
    p = make(proc.empty() ? "unknown" : proc, proc, Os::None, Compiler::Gcc, bits >= 64 ? Model::LP64 : Model::ILP32);
    p.rules.pointer_size = bits >= 64 ? 8 : bits <= 16 ? 2 : bits <= 24 ? 3 : 4;
    p.rules.big_endian = be;
    p.rules.long_double_size = p.rules.long_double_align = 8;
    if (bits <= 24) {
      // A microcontroller (16-bit or 24-bit addresses: AVR, 8051, Z80,
      // PIC, MSP430): its compilers' int is 2 bytes and long 4 (SDCC, Keil,
      // XC8, avr-gcc, msp430-gcc), and nothing is aligned beyond 2 bytes.
      p.rules.int_size = 2;
      p.rules.long_size = 4;
      p.rules.wchar_size = 2;
      p.rules.long_double_size = p.rules.long_double_align = 4;
      p.rules.double_size = 4;
      p.rules.max_alignment = 2;
      p.rules.has_int128 = false;
      static const std::set<std::string, std::less<>> eight_bit = {
          "8051", "80251", "80390", "8048", "8085", "z80", "z8401x", "z180", "z182", "6502", "65C02", "6800", "6805",
          "6809", "HC05", "HC08", "HCS08", "M8C", "PIC-12", "PIC-16", "PIC-17", "PIC-18", "avr8"};
      // An 8-bit core: its compilers align nothing.
      if (eight_bit.contains(proc)) p.rules.max_alignment = 1;
    }
    note("no profile for " + in.language_id + "; using C's usual sizes for " + std::to_string(bits) + "-bit" +
         (bits <= 24 ? std::string(" microcontrollers (int 2 bytes, long 4, double 4") +
                           (p.rules.max_alignment == 1 ? ", nothing aligned" : ", aligned to at most 2") + ")"
                     : std::string()));
  }
  if (bare && p.os == Os::Linux) p.os = Os::None;
  if (p.arch == "powerpc" || p.arch == "mips") p.rules.big_endian = be;
  if (!in.data_org) return p;

  const DataOrganization &o = *in.data_org;
  LayoutRules &r = p.rules;
  const LayoutRules abi = r;
  auto take = [&](const std::optional<std::uint32_t> &v, std::uint32_t &field) {
    if (v && *v > 0 && *v <= 16) field = *v;
  };
  take(o.pointer_size, r.pointer_size);
  take(o.short_size, r.short_size);
  take(o.integer_size, r.int_size);
  take(o.long_size, r.long_size);
  take(o.long_long_size, r.long_long_size);
  take(o.float_size, r.float_size);
  take(o.double_size, r.double_size);
  take(o.wchar_size, r.wchar_size);
  if (o.absolute_max_alignment) r.max_alignment = *o.absolute_max_alignment;
  if (o.ms_bitfields) r.bitfields = BitfieldModel::Msvc;
  if (!o.size_alignment.empty()) {
    std::vector<std::pair<std::uint32_t, std::uint32_t>> m = o.size_alignment;
    for (const auto &[s, a] : abi.size_alignment)
      if (std::none_of(m.begin(), m.end(), [&](auto &e) { return e.first == s; })) {
        // The spec doesn't list this size (RISC-V's specs stop at 8: no
        // 16-byte long double or __int128 alignment).
        bool larger = std::any_of(m.begin(), m.end(), [&](auto &e) { return e.first > s; });
        if (!larger) {
          m.emplace_back(s, a);
          note("the compiler spec gives no alignment for " + std::to_string(s) + "-byte scalars; using the ABI's " +
               std::to_string(a));
        }
      }
    std::sort(m.begin(), m.end());
    r.size_alignment = std::move(m);
  }
  if (o.long_double_size) {
    const std::uint32_t ld = *o.long_double_size;
    if (ld == 10 || ld == 12) {
      // x87 extended: the spec gives the value's size; storage is the ABI's.
      r.long_double_size = abi.long_double_size;
      r.long_double_align = abi.long_double_align;
    } else if (ld != abi.long_double_size && (p.arch == "aarch64" || p.arch.starts_with("riscv")) &&
               p.os == Os::Linux) {
      note("the compiler spec's long double is " + std::to_string(ld) + " bytes; " + p.arch +
           " Linux's ABI makes it 16 (IEEE quad), which is used");
    } else if (ld > 0 && ld <= 16) {
      r.long_double_size = ld;
      r.long_double_align = r.scalar_align(ld);
    }
  }
  if (o.char_signed) {
    if (*o.char_signed != abi.char_signed && p.os == Os::Linux && !abi.char_signed) {
      note("the compiler spec makes char signed; " + p.arch + " Linux's ABI makes it unsigned, which is used");
    } else {
      r.char_signed = *o.char_signed;
    }
  } else if (!abi.char_signed) {
    note("plain char is unsigned on " + p.arch + " (the ABI; the compiler spec doesn't say)");
  }
  return p;
}

}  // namespace revkit::cparse
