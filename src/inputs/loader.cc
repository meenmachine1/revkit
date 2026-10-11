// What Ghidra's loaders put in the program besides the file's bytes: the
// ELF EXTERNAL block, relocated pointer slots, tracked register values.

#include "revkit/inputs/inputs.h"

#include <algorithm>
#include <map>
#include <set>

namespace revkit::inputs {

namespace {

constexpr std::uint64_t kLinkageAlignment = 0x1000;  // ElfLoadAdapter.getLinkageBlockAlignment

std::uint64_t align_up(std::uint64_t v, std::uint64_t a) { return (v + a - 1) / a * a; }

void put_word(std::vector<std::uint8_t> &out, std::uint64_t v, unsigned size, loader::Endian endian) {
  out.resize(size);
  for (unsigned i = 0; i < size; ++i) {
    unsigned shift = endian == loader::Endian::little ? 8 * i : 8 * (size - 1 - i);
    out[i] = static_cast<std::uint8_t>((v >> shift) & 0xff);
  }
}

}  // namespace

const ExternalSymbol *ExternalBlock::find(const std::string &name) const {
  for (const ExternalSymbol &s : symbols)
    if (s.name == name) return &s;
  return nullptr;
}

const ExternalSymbol *ExternalBlock::at(std::uint64_t address) const {
  auto it = std::lower_bound(symbols.begin(), symbols.end(), address,
                             [](const ExternalSymbol &s, std::uint64_t a) { return s.address < a; });
  return it != symbols.end() && it->address == address ? &*it : nullptr;
}

ExternalBlock external_block(const loader::Image &image) {
  ExternalBlock out;
  if (image.format != loader::Format::elf) return out;
  const std::uint64_t word = image.bits / 8;
  std::uint64_t last = 0;
  for (const loader::Block &b : image.blocks)
    if (b.size != 0) last = std::max(last, b.start + (b.size - 1));
  out.start = align_up(last + 1, kLinkageAlignment);
  std::uint64_t next = out.start;
  std::map<std::string, std::size_t> by_name;
  for (const loader::Symbol &s : image.symbols) {
    if (s.source == loader::SymbolSource::pe_export || s.name.empty()) continue;
    if (s.type == loader::SymbolType::file || s.type == loader::SymbolType::tls ||
        s.type == loader::SymbolType::section)
      continue;
    // ElfProgramBuilder.calculateSymbolAddress: undefined global and weak
    // symbols (and COMMON ones) are external; an undefined local one only
    // when its value is 0.
    const bool common = s.type == loader::SymbolType::common;
    if (s.defined && !common) continue;
    if (!common && s.bind == loader::SymbolBind::local && s.value != 0) continue;
    if (s.name == "_GLOBAL_OFFSET_TABLE_") continue;
    // free@GLIBC_2.2.5 (in .symtab) is the slot of "free" already made from
    // .dynsym; an unknown versioned name gets a slot of its own.
    std::string name = s.name;
    if (auto at = name.find('@'); at != std::string::npos && at > 0) {
      std::string real = name.substr(0, at);
      if (by_name.contains(real)) continue;
    }
    if (by_name.contains(name)) continue;
    std::uint64_t size = word;
    const bool data = s.type == loader::SymbolType::object;
    if (data && s.size > 0 && s.size < 0x7fffffff) size = align_up(s.size, word);
    by_name.emplace(name, out.symbols.size());
    out.symbols.push_back({name, next, size, data});
    next += size;
  }
  out.end = next - 1;
  if (out.symbols.empty()) out.end = out.start - 1;
  return out;
}

std::vector<Patch> relocation_patches(const loader::Image &image, const ExternalBlock &external) {
  std::vector<Patch> out;
  if (image.format != loader::Format::elf) return out;
  const unsigned word = image.bits / 8;
  std::set<std::string> undefined;
  for (const loader::Symbol &s : image.symbols)
    if (!s.defined && !s.name.empty()) undefined.insert(s.name);
  std::map<std::uint64_t, std::uint64_t> values;
  for (const loader::Relocation &r : image.relocations) {
    switch (r.kind) {
      case loader::RelocationKind::relative:
        if (r.target) values[r.address] = *r.target;
        break;
      case loader::RelocationKind::jump_slot:
      case loader::RelocationKind::glob_dat:
      case loader::RelocationKind::absolute: {
        if (r.symbol.empty() || !undefined.contains(r.symbol)) break;
        std::string name = r.symbol;
        if (auto at = name.find('@'); at != std::string::npos && at > 0) name = name.substr(0, at);
        const ExternalSymbol *x = external.find(name);
        if (x == nullptr) break;
        // JUMP_SLOT and GLOB_DAT ignore the addend on most machines; an
        // absolute relocation adds it.
        std::uint64_t v = x->address;
        if (r.kind == loader::RelocationKind::absolute) v += static_cast<std::uint64_t>(r.addend);
        values[r.address] = v;
        break;
      }
      default: break;
    }
  }
  for (const auto &[addr, v] : values) {
    if (!image.memory.is_mapped(addr)) continue;
    Patch p{addr, {}};
    put_word(p.second, word == 4 ? v & 0xffffffffu : v, word, image.endian);
    out.push_back(std::move(p));
  }
  return out;
}

std::vector<TrackedRegister> tracked_registers(const loader::Image &image, const std::string &language_id) {
  std::vector<TrackedRegister> out;
  if (language_id.starts_with("RISCV:")) {
    // RISCVAddressAnalyzer: gp is __global_pointer$ wherever constant
    // propagation reaches a function without a gp value.
    for (const loader::Symbol &s : image.symbols)
      if (s.defined && s.name == "__global_pointer$") {
        out.push_back({"gp", s.value});
        break;
      }
  }
  return out;
}

}  // namespace revkit::inputs
