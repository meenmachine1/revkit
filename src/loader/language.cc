// Machine -> Ghidra language mapping, following the .opinion files shipped
// with Ghidra 12.1.4 (Ghidra/Processors/*/data/languages/*.opinion).

#include "revkit/loader/load.hh"

#include "revkit/loader/buildinfo.hh"
#include "revkit/loader/gopclntab.hh"

#include <algorithm>
#include <array>

namespace revkit::loader {

namespace {

namespace em {
constexpr std::uint32_t i386 = 3;
constexpr std::uint32_t mips = 8;
constexpr std::uint32_t mips_rs3_le = 10;
constexpr std::uint32_t ppc = 20;
constexpr std::uint32_t ppc64 = 21;
constexpr std::uint32_t arm = 40;
constexpr std::uint32_t x86_64 = 62;
constexpr std::uint32_t aarch64 = 183;
constexpr std::uint32_t riscv = 243;
constexpr std::uint32_t sparc = 2;
constexpr std::uint32_t m68k = 4;
constexpr std::uint32_t parisc = 15;
constexpr std::uint32_t sparc32plus = 18;
constexpr std::uint32_t sh = 42;
constexpr std::uint32_t sparcv9 = 43;
constexpr std::uint32_t tricore = 44;
constexpr std::uint32_t avr = 83;
constexpr std::uint32_t v850 = 87;
constexpr std::uint32_t xtensa = 94;
constexpr std::uint32_t msp430 = 105;
constexpr std::uint32_t hexagon = 164;
constexpr std::uint32_t bpf = 247;
constexpr std::uint32_t loongarch = 258;
}  // namespace em

namespace pe {
constexpr std::uint32_t i386 = 0x14c;
constexpr std::uint32_t amd64 = 0x8664;
constexpr std::uint32_t arm64 = 0xaa64;
constexpr std::uint32_t arm = 0x1c0;
constexpr std::uint32_t armnt = 0x1c4;
}  // namespace pe

constexpr std::uint32_t EF_ARM_BE8 = 0x00800000;
constexpr std::uint32_t EF_MIPS_ABI2 = 0x00000020;
constexpr std::uint32_t EF_MIPS_MICROMIPS = 0x02000000;
constexpr std::uint32_t EF_MIPS_ARCH = 0xf0000000;
constexpr std::uint32_t E_MIPS_ARCH_3 = 0x20000000;
constexpr std::uint32_t E_MIPS_ARCH_4 = 0x30000000;
constexpr std::uint32_t E_MIPS_ARCH_64 = 0x60000000;
constexpr std::uint32_t E_MIPS_ARCH_64R2 = 0x80000000;
constexpr std::uint32_t E_MIPS_ARCH_32R6 = 0x90000000;
constexpr std::uint32_t E_MIPS_ARCH_64R6 = 0xa0000000;
constexpr std::uint32_t EF_AVR_ARCH_MASK = 0x7f;  // avr2 .. avrxmega7, avrtiny = 100
constexpr std::uint32_t EF_AVR_ARCH_AVR6 = 6;     // 3-byte PC: ATmega2560
constexpr std::uint32_t EF_MSP430_MACH_MSP430X = 45;
constexpr std::uint32_t EF_LARCH_ABI_MODIFIER_MASK = 0x7;

std::optional<LanguageSpec> guess(Format format, std::uint32_t machine, unsigned bits, Endian endian,
                                  std::uint32_t flags) {
  const std::string e = endian == Endian::little ? "LE" : "BE";
  if (format == Format::pe) {
    switch (machine) {
      case pe::i386: return LanguageSpec{"x86:LE:32:default", "windows"};
      case pe::amd64: return LanguageSpec{"x86:LE:64:default", "windows"};
      case pe::arm64: return LanguageSpec{"AARCH64:LE:64:v8A", "windows"};
      case pe::arm:
      case pe::armnt: return LanguageSpec{"ARM:LE:32:v8", "windows"};
      default: return std::nullopt;
    }
  }

  switch (machine) {
    case em::i386:
      if (endian != Endian::little) return std::nullopt;
      return LanguageSpec{"x86:LE:32:default", "gcc"};
    case em::x86_64:
      if (endian != Endian::little) return std::nullopt;
      return LanguageSpec{"x86:LE:64:default", "gcc"};
    case em::aarch64:
      if (bits == 32) return LanguageSpec{"AARCH64:" + e + ":32:ilp32", "default"};
      return LanguageSpec{"AARCH64:" + e + ":64:v8A", "default"};
    case em::arm:
      // BE8: big-endian data with little-endian instructions.
      if (endian == Endian::big && (flags & EF_ARM_BE8) != 0)
        return LanguageSpec{"ARM:LEBE:32:v8LEInstruction", "default"};
      return LanguageSpec{"ARM:" + e + ":32:v8", "default"};
    case em::riscv:
      if (endian != Endian::little) return std::nullopt;
      return LanguageSpec{bits == 64 ? "RISCV:LE:64:default" : "RISCV:LE:32:default", "gcc"};
    case em::ppc:
      return LanguageSpec{"PowerPC:" + e + ":32:default", "default"};
    case em::ppc64:
      return LanguageSpec{"PowerPC:" + e + ":64:default", "default"};
    case em::mips:
    case em::mips_rs3_le: {
      const std::uint32_t arch = flags & EF_MIPS_ARCH;
      const bool micro = (flags & EF_MIPS_MICROMIPS) != 0;
      if (bits == 64) {
        if (arch == E_MIPS_ARCH_64R6) return LanguageSpec{"MIPS:" + e + ":64:R6", "default"};
        if (micro) return LanguageSpec{"MIPS:" + e + ":64:micro", "default"};
        return LanguageSpec{"MIPS:" + e + ":64:default", "default"};
      }
      if ((flags & EF_MIPS_ABI2) != 0) return LanguageSpec{"MIPS:" + e + ":64:64-32addr", "n32"};
      if (arch == E_MIPS_ARCH_32R6) return LanguageSpec{"MIPS:" + e + ":32:R6", "default"};
      if (arch == E_MIPS_ARCH_3 || arch == E_MIPS_ARCH_4 || arch == E_MIPS_ARCH_64 ||
          arch == E_MIPS_ARCH_64R2)
        return LanguageSpec{"MIPS:" + e + ":64:64-32addr", "default"};
      if (micro) return LanguageSpec{"MIPS:" + e + ":32:micro", "default"};
      return LanguageSpec{"MIPS:" + e + ":32:default", "default"};
    }
    // The rest as Ghidra 12.1.4's .opinion files map them.
    case em::sparc:
    case em::sparc32plus: return LanguageSpec{"sparc:BE:32:default", "default"};
    case em::sparcv9: return LanguageSpec{"sparc:BE:64:default", "default"};
    case em::m68k: return LanguageSpec{"68000:BE:32:default", "default"};
    case em::parisc: return LanguageSpec{"pa-risc:BE:32:default", "default"};
    case em::sh: return LanguageSpec{"SuperH4:" + e + ":32:default", "default"};
    case em::tricore: return LanguageSpec{"tricore:LE:32:default", "default"};
    case em::v850: return LanguageSpec{"V850:LE:32:default", "default"};
    case em::xtensa: return LanguageSpec{"Xtensa:" + e + ":32:default", "default"};
    case em::hexagon: return LanguageSpec{"Hexagon:LE:32:default", "default"};
    case em::avr: {
      const std::uint32_t arch = flags & EF_AVR_ARCH_MASK;
      if (arch == EF_AVR_ARCH_AVR6) return LanguageSpec{"avr8:LE:16:atmega256", "gcc"};
      if (arch >= 101 && arch <= 107) return LanguageSpec{"avr8:LE:24:xmega", "gcc"};
      return LanguageSpec{"avr8:LE:16:default", "gcc"};
    }
    case em::msp430:
      if ((flags & 0xff) == EF_MSP430_MACH_MSP430X) return LanguageSpec{"TI_MSP430X:LE:32:default", "default"};
      return LanguageSpec{"TI_MSP430:LE:16:default", "default"};
    // Linux eBPF objects (clang -target bpf): eBPF.opinion maps 247 to both
    // byte orders, 64-bit, compiler "default".
    case em::bpf:
      if (bits != 64) return std::nullopt;
      return LanguageSpec{"eBPF:" + e + ":64:default", "default"};
    case em::loongarch: {
      const bool d = (flags & EF_LARCH_ABI_MODIFIER_MASK) != 2;  // 2: single-float ABI
      if (bits == 32) return LanguageSpec{d ? "Loongarch:LE:32:ilp32d" : "Loongarch:LE:32:ilp32f", "default"};
      return LanguageSpec{d ? "Loongarch:LE:64:lp64d" : "Loongarch:LE:64:lp64f", "default"};
    }
    default:
      return std::nullopt;
  }
}

// Ghidra 12.1.4's "Mac OS X Mach-O" opinions (x86, AARCH64, ARM, PowerPC
// and Sparc .opinion files); the compiler is Swift's or Go's where the
// file has their sections (MachoLoader.detectCompilerName).
std::optional<LanguageSpec> guess_macho(std::uint32_t cputype, std::uint32_t cpusubtype, const std::string &special) {
  auto with = [&](std::string language, std::string compiler, bool specials) -> std::optional<LanguageSpec> {
    if (specials && !special.empty()) compiler = special;
    return LanguageSpec{std::move(language), std::move(compiler)};
  };
  switch (cputype) {
    case 7: return with("x86:LE:32:default", "gcc", false);
    case 0x01000007: return with("x86:LE:64:default", "gcc", special == "swift");
    case 0x0100000c: return with("AARCH64:LE:64:AppleSilicon", "default", true);
    case 0x0200000c: return with("AARCH64:LE:32:ilp32", "default", false);
    case 12:
      // Ghidra names 12.0, .5 (v4t), .6 (v6) and .9-.12 (v7 family: v8);
      // the rest are revkit's: v5 and XScale as v5t, v6-M, v7-M and v7E-M
      // as Cortex, v8-M as v8-m, anything else v8.
      switch (cpusubtype & 0x00ffffff) {
        case 5: return with("ARM:LE:32:v4t", "default", false);
        case 6: return with("ARM:LE:32:v6", "default", false);
        case 7:
        case 8: return with("ARM:LE:32:v5t", "default", false);
        case 14:
        case 15:
        case 16: return with("ARM:LE:32:Cortex", "default", false);
        case 17: return with("ARM:LE:32:v8-m", "default", false);
        default: return with("ARM:LE:32:v8", "default", false);
      }
    case 18: return with("PowerPC:BE:32:default", "default", false);
    case 0x01000012: return with("PowerPC:BE:64:default", "default", false);
    case 14: return with("sparc:BE:32:default", "default", false);
    default: return std::nullopt;
  }
}

}  // namespace

// Go's minor version (17 for go1.17.13) from the build info, else the
// least the pclntab's layout says (1.18 and 1.20 layouts; the 1.16 one is
// 1.16 or 1.17, the 1.2 one older); nullopt when the image isn't Go.
std::optional<int> go_minor(const Image &image) {
  std::string error;
  if (auto b = read_go_buildinfo(image, &error)) {
    std::string_view v = b->go_version;
    if (auto at = v.find("go1."); at != std::string_view::npos) {
      int minor = 0;
      std::size_t i = at + 4, digits = 0;
      for (; i < v.size() && v[i] >= '0' && v[i] <= '9' && digits < 4; ++i, ++digits) minor = minor * 10 + (v[i] - '0');
      if (digits) return minor;
    }
  }
  // Without build info: the header of a named table (the scan for a
  // stripped PE's is left to the import's pass).
  for (const Section &s : image.sections) {
    const std::string_view n = s.name;
    if (n != ".gopclntab" && n != ".data.rel.ro.gopclntab" && n != "__gopclntab") continue;
    std::span<const std::byte> b = section_bytes(image, s);
    if (b.size() < 8) continue;
    std::uint32_t le = 0, be = 0;
    for (int i = 0; i < 4; ++i) {
      le |= std::to_integer<std::uint32_t>(b[i]) << (8 * i);
      be = be << 8 | std::to_integer<std::uint32_t>(b[i]);
    }
    for (std::uint32_t m : {le, be}) {
      if (m == 0xfffffff1) return 20;
      if (m == 0xfffffff0) return 18;
      if (m == 0xfffffffa) return 16;
      if (m == 0xfffffffb) return 2;
    }
  }
  return std::nullopt;
}

// Ghidra's opinions give a Go binary the golang compiler spec (x86.opinion:
// PE i386 and amd64, ELF x86-64; AARCH64.opinion: ELF and Mach-O arm64).
// revkit does where the spec's default prototype is how the Go version
// passes arguments: abi0 (the stack) on i386, Go's register ABI
// (ABIInternal) on amd64 from Go 1.17 and arm64 from 1.18. An older Go
// keeps the platform's spec: Ghidra fixes each function up to abi0, which
// revkit's prototypes can't say yet (docs/go.md).
bool go_compiler(const Image &image, std::string_view language) {
  if (image.format == Format::raw) return false;
  const bool x86_64 = language.starts_with("x86:LE:64:"), x86_32 = language.starts_with("x86:LE:32:"),
             arm64 = language.starts_with("AARCH64:LE:64:");
  if (!x86_64 && !x86_32 && !arm64) return false;
  auto minor = go_minor(image);
  if (!minor) return false;
  if (x86_32) return true;
  return *minor >= (x86_64 ? 17 : 18);
}

std::optional<LanguageSpec> guess_language(const Image &image) {
  std::optional<LanguageSpec> out;
  if (image.format == Format::macho) {
    if (!image.macho) return std::nullopt;
    // SwiftUtils.isSwift (Ghidra prefers it to Go's sections).
    bool swift = false;
    for (const Section &s : image.sections)
      swift |= s.name.starts_with("__swift") || s.name.starts_with("swift") || s.name.starts_with(".sw5");
    out = guess_macho(image.macho->cputype, image.macho->cpusubtype, swift ? "swift" : "");
    if (swift) return out;
  } else {
    out = guess(image.format, image.machine, image.bits, image.endian, image.flags);
  }
  if (out && go_compiler(image, out->language)) out->compiler = "golang";
  return out;
}

std::vector<LanguageSpec> all_language_specs() {
  std::vector<LanguageSpec> out;
  auto add = [&](std::optional<LanguageSpec> s) {
    if (!s) return;
    bool seen = std::any_of(out.begin(), out.end(), [&](const LanguageSpec &o) {
      return o.language == s->language && o.compiler == s->compiler;
    });
    if (!seen) out.push_back(*s);
  };
  const std::array<std::uint32_t, 23> elf_machines{
      em::i386,  em::mips,      em::mips_rs3_le, em::ppc,     em::ppc64,   em::arm,       em::x86_64, em::aarch64,
      em::riscv, em::sparc,     em::m68k,        em::parisc,  em::sparc32plus, em::sh,    em::sparcv9, em::tricore,
      em::avr,   em::v850,      em::xtensa,      em::msp430,  em::hexagon, em::loongarch, em::bpf};
  const std::array<std::uint32_t, 15> flag_sets{
      0, EF_ARM_BE8, EF_MIPS_ABI2, EF_MIPS_MICROMIPS, E_MIPS_ARCH_3, E_MIPS_ARCH_4, E_MIPS_ARCH_64,
      E_MIPS_ARCH_64R2, E_MIPS_ARCH_32R6, E_MIPS_ARCH_64R6, E_MIPS_ARCH_64R6 | EF_MIPS_MICROMIPS,
      EF_AVR_ARCH_AVR6, 107, EF_MSP430_MACH_MSP430X, 2};
  for (std::uint32_t m : elf_machines)
    for (unsigned bits : {32u, 64u})
      for (Endian e : {Endian::little, Endian::big})
        for (std::uint32_t f : flag_sets) add(guess(Format::elf, m, bits, e, f));
  for (std::uint32_t m : {pe::i386, pe::amd64, pe::arm64, pe::arm, pe::armnt})
    add(guess(Format::pe, m, 32, Endian::little, 0));
  // Go's (go_compiler).
  for (const char *l : {"x86:LE:64:default", "x86:LE:32:default", "AARCH64:LE:64:v8A", "AARCH64:LE:64:AppleSilicon"})
    add(LanguageSpec{l, "golang"});
  for (std::uint32_t cpu : {7u, 0x01000007u, 0x0100000cu, 0x0200000cu, 12u, 18u, 0x01000012u, 14u})
    for (std::uint32_t sub : {0u, 5u, 6u, 7u, 9u, 15u, 17u})
      for (const char *special : {"", "swift", "golang"}) add(guess_macho(cpu, sub, special));
  return out;
}

}  // namespace revkit::loader
