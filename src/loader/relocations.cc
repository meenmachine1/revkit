// The relocation table (Ghidra's Window → Relocation Table): a relocation
// type's name for the machines revkit knows, and a PE image's base
// relocations (which Image::relocations, ELF only, doesn't hold).
#include "revkit/loader/image.hh"

#include <algorithm>
#include <cstring>
#include <map>

namespace revkit::loader {
namespace {

constexpr std::uint32_t EM_386 = 3, EM_MIPS = 8, EM_PPC = 20, EM_PPC64 = 21, EM_ARM = 40, EM_X86_64 = 62,
                        EM_AARCH64 = 183, EM_RISCV = 243;

using Names = std::map<std::uint32_t, std::string_view>;

const Names &elf_names(std::uint32_t machine) {
  static const Names none;
  static const Names x86_64 = {
      {0, "NONE"},       {1, "64"},           {2, "PC32"},          {3, "GOT32"},          {4, "PLT32"},
      {5, "COPY"},       {6, "GLOB_DAT"},     {7, "JUMP_SLOT"},     {8, "RELATIVE"},       {9, "GOTPCREL"},
      {10, "32"},        {11, "32S"},         {12, "16"},           {13, "PC16"},          {14, "8"},
      {15, "PC8"},       {16, "DTPMOD64"},    {17, "DTPOFF64"},     {18, "TPOFF64"},       {19, "TLSGD"},
      {20, "TLSLD"},     {21, "DTPOFF32"},    {22, "GOTTPOFF"},     {23, "TPOFF32"},       {24, "PC64"},
      {25, "GOTOFF64"},  {26, "GOTPC32"},     {32, "SIZE32"},       {33, "SIZE64"},        {34, "GOTPC32_TLSDESC"},
      {35, "TLSDESC_CALL"}, {36, "TLSDESC"},  {37, "IRELATIVE"},    {38, "RELATIVE64"},    {41, "GOTPCRELX"},
      {42, "REX_GOTPCRELX"}};
  static const Names i386 = {
      {0, "NONE"},       {1, "32"},           {2, "PC32"},          {3, "GOT32"},          {4, "PLT32"},
      {5, "COPY"},       {6, "GLOB_DAT"},     {7, "JMP_SLOT"},      {8, "RELATIVE"},       {9, "GOTOFF"},
      {10, "GOTPC"},     {14, "TLS_TPOFF"},   {35, "TLS_DTPMOD32"}, {36, "TLS_DTPOFF32"},  {37, "TLS_TPOFF32"},
      {42, "IRELATIVE"}, {43, "GOT32X"}};
  static const Names aarch64 = {
      {0, "NONE"},         {257, "ABS64"},        {258, "ABS32"},        {259, "ABS16"},
      {260, "PREL64"},     {261, "PREL32"},       {262, "PREL16"},       {275, "ADR_PREL_PG_HI21"},
      {277, "ADD_ABS_LO12_NC"}, {278, "LDST8_ABS_LO12_NC"}, {282, "JUMP26"}, {283, "CALL26"},
      {284, "LDST16_ABS_LO12_NC"}, {285, "LDST32_ABS_LO12_NC"}, {286, "LDST64_ABS_LO12_NC"},
      {299, "LDST128_ABS_LO12_NC"}, {311, "ADR_GOT_PAGE"}, {312, "LD64_GOT_LO12_NC"},
      {1024, "COPY"},      {1025, "GLOB_DAT"},    {1026, "JUMP_SLOT"},   {1027, "RELATIVE"},
      {1028, "TLS_DTPMOD"}, {1029, "TLS_DTPREL"}, {1030, "TLS_TPREL"},   {1031, "TLSDESC"},
      {1032, "IRELATIVE"}};
  static const Names arm = {
      {0, "NONE"},          {1, "PC24"},          {2, "ABS32"},         {3, "REL32"},
      {10, "THM_CALL"},     {17, "TLS_DTPMOD32"}, {18, "TLS_DTPOFF32"}, {19, "TLS_TPOFF32"},
      {20, "COPY"},         {21, "GLOB_DAT"},     {22, "JUMP_SLOT"},    {23, "RELATIVE"},
      {24, "GOTOFF32"},     {25, "BASE_PREL"},    {26, "GOT_BREL"},     {27, "PLT32"},
      {28, "CALL"},         {29, "JUMP24"},       {30, "THM_JUMP24"},   {40, "V4BX"},
      {42, "PREL31"},       {43, "MOVW_ABS_NC"},  {44, "MOVT_ABS"},     {47, "THM_MOVW_ABS_NC"},
      {48, "THM_MOVT_ABS"}, {160, "IRELATIVE"}};
  static const Names riscv = {
      {0, "NONE"},          {1, "32"},            {2, "64"},            {3, "RELATIVE"},
      {4, "COPY"},          {5, "JUMP_SLOT"},     {6, "TLS_DTPMOD32"},  {7, "TLS_DTPMOD64"},
      {8, "TLS_DTPREL32"},  {9, "TLS_DTPREL64"},  {10, "TLS_TPREL32"},  {11, "TLS_TPREL64"},
      {16, "BRANCH"},       {17, "JAL"},          {18, "CALL"},         {19, "CALL_PLT"},
      {20, "GOT_HI20"},     {23, "PCREL_HI20"},   {24, "PCREL_LO12_I"}, {25, "PCREL_LO12_S"},
      {26, "HI20"},         {27, "LO12_I"},       {28, "LO12_S"},       {51, "RELAX"},
      {58, "IRELATIVE"}};
  static const Names mips = {
      {0, "NONE"},   {1, "16"},       {2, "32"},       {3, "REL32"},    {4, "26"},
      {5, "HI16"},   {6, "LO16"},     {7, "GPREL16"},  {8, "LITERAL"},  {9, "GOT16"},
      {10, "PC16"},  {11, "CALL16"},  {12, "GPREL32"}, {126, "COPY"},   {127, "JUMP_SLOT"}};
  static const Names ppc = {
      {0, "NONE"},       {1, "ADDR32"},    {2, "ADDR24"},  {3, "ADDR16"},    {4, "ADDR16_LO"},
      {5, "ADDR16_HI"},  {6, "ADDR16_HA"}, {10, "REL24"},  {19, "COPY"},     {20, "GLOB_DAT"},
      {21, "JMP_SLOT"},  {22, "RELATIVE"}, {26, "REL32"},  {248, "IRELATIVE"}};
  static const Names ppc64 = {
      {0, "NONE"},      {1, "ADDR32"},    {10, "REL24"},    {19, "COPY"},     {20, "GLOB_DAT"},
      {21, "JMP_SLOT"}, {22, "RELATIVE"}, {26, "REL32"},    {38, "ADDR64"},   {44, "REL64"},
      {51, "TOC"},      {248, "IRELATIVE"}};
  switch (machine) {
    case EM_X86_64: return x86_64;
    case EM_386: return i386;
    case EM_AARCH64: return aarch64;
    case EM_ARM: return arm;
    case EM_RISCV: return riscv;
    case EM_MIPS: return mips;
    case EM_PPC: return ppc;
    case EM_PPC64: return ppc64;
    default: return none;
  }
}

std::string_view elf_prefix(std::uint32_t machine) {
  switch (machine) {
    case EM_X86_64: return "R_X86_64_";
    case EM_386: return "R_386_";
    case EM_AARCH64: return "R_AARCH64_";
    case EM_ARM: return "R_ARM_";
    case EM_RISCV: return "R_RISCV_";
    case EM_MIPS: return "R_MIPS_";
    case EM_PPC: return "R_PPC_";
    case EM_PPC64: return "R_PPC64_";
    default: return "";
  }
}

// IMAGE_REL_BASED_*; 5, 7, 8 and 9 depend on the machine.
std::string pe_name(std::uint32_t machine, std::uint32_t type) {
  const bool arm = machine == 0x1c0 || machine == 0x1c2 || machine == 0x1c4;
  const bool mips = machine == 0x162 || machine == 0x166 || machine == 0x168 || machine == 0x169;
  const bool riscv = machine == 0x5032 || machine == 0x5064 || machine == 0x5128;
  switch (type) {
    case 0: return "IMAGE_REL_BASED_ABSOLUTE";
    case 1: return "IMAGE_REL_BASED_HIGH";
    case 2: return "IMAGE_REL_BASED_LOW";
    case 3: return "IMAGE_REL_BASED_HIGHLOW";
    case 4: return "IMAGE_REL_BASED_HIGHADJ";
    case 5: return arm ? "IMAGE_REL_BASED_ARM_MOV32" : riscv ? "IMAGE_REL_BASED_RISCV_HIGH20" : mips ? "IMAGE_REL_BASED_MIPS_JMPADDR" : "IMAGE_REL_BASED_5";
    case 7: return arm ? "IMAGE_REL_BASED_THUMB_MOV32" : riscv ? "IMAGE_REL_BASED_RISCV_LOW12I" : "IMAGE_REL_BASED_7";
    case 8: return riscv ? "IMAGE_REL_BASED_RISCV_LOW12S" : "IMAGE_REL_BASED_8";
    case 9: return mips ? "IMAGE_REL_BASED_MIPS_JMPADDR16" : "IMAGE_REL_BASED_9";
    case 10: return "IMAGE_REL_BASED_DIR64";
    default: return "IMAGE_REL_BASED_" + std::to_string(type);
  }
}

std::uint64_t read_le(const Image &image, std::uint64_t addr, unsigned size, bool &ok) {
  std::byte b[8]{};
  ok = image.memory.read(addr, std::span<std::byte>(b, size)) == size;
  std::uint64_t v = 0;
  for (unsigned i = 0; i < size; ++i) v |= std::uint64_t{std::to_integer<std::uint8_t>(b[i])} << (8 * i);
  return v;
}

}  // namespace

std::string relocation_type_name(const Image &image, std::uint32_t type) {
  if (image.format == Format::pe) return pe_name(image.machine, type);
  const Names &names = elf_names(image.machine);
  if (auto it = names.find(type); it != names.end()) return std::string(elf_prefix(image.machine)) + std::string(it->second);
  return "type " + std::to_string(type);
}

std::vector<Relocation> pe_base_relocations(const Image &image, std::size_t limit) {
  std::vector<Relocation> out;
  if (image.format != Format::pe) return out;
  const std::uint64_t base = image.image_base;
  bool ok = false;
  const std::uint64_t lfanew = read_le(image, base + 0x3c, 4, ok);
  if (!ok || read_le(image, base + lfanew, 4, ok) != 0x4550 || !ok) return out;
  const std::uint64_t opt = base + lfanew + 24;
  const std::uint64_t magic = read_le(image, opt, 2, ok);
  const bool plus = magic == 0x20b;
  if (!ok || (!plus && magic != 0x10b)) return out;
  const std::uint64_t count = read_le(image, opt + (plus ? 108 : 92), 4, ok);
  if (!ok || count <= 5) return out;
  const std::uint64_t dirs = opt + (plus ? 112 : 96);
  const std::uint64_t rva = read_le(image, dirs + 5 * 8, 4, ok);
  const std::uint64_t size = ok ? read_le(image, dirs + 5 * 8 + 4, 4, ok) : 0;
  if (!ok || rva == 0 || size == 0 || size > (64u << 20)) return out;
  for (std::uint64_t at = base + rva, end = at + size; at + 8 <= end && out.size() < limit;) {
    const std::uint64_t page = read_le(image, at, 4, ok);
    if (!ok) break;
    const std::uint64_t block = read_le(image, at + 4, 4, ok);
    if (!ok || block < 8 || block > end - at) break;
    for (std::uint64_t e = at + 8; e + 2 <= at + block && out.size() < limit; e += 2) {
      const std::uint64_t v = read_le(image, e, 2, ok);
      if (!ok) break;
      const std::uint32_t type = static_cast<std::uint32_t>(v >> 12);
      if (type == 0) continue;  // padding to a 32-bit boundary
      Relocation r;
      r.address = base + page + (v & 0xfff);
      r.type = type;
      // The stored word is the link-time address the loader adds the delta to.
      if (type == 3 || type == 10) {
        r.kind = RelocationKind::absolute;
        bool read = false;
        const std::uint64_t stored = read_le(image, r.address, type == 10 ? 8 : 4, read);
        if (read) {
          r.addend = static_cast<std::int64_t>(stored);
          r.target = stored + (image.image_base - image.file_base);  // where it points once loaded here
        }
      }
      out.push_back(std::move(r));
    }
    at += block;
  }
  std::stable_sort(out.begin(), out.end(), [](const Relocation &a, const Relocation &b) { return a.address < b.address; });
  return out;
}

}  // namespace revkit::loader
