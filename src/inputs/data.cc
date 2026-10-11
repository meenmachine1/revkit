// Data analysis results as decompiler data facts (data.h).

#include "data.h"

#include <algorithm>
#include <array>
#include <span>
#include <cstdio>
#include <set>

namespace revkit::inputs {

namespace an = analysis;

namespace {

constexpr std::uint64_t kUndefinedId = 0xc000000000000000ULL;  // Ghidra's DEFAULT data type


lift::DecompElement undefined_type(std::uint32_t size) {
  if (size <= 1) return {"typeref", {{"name", std::string("undefined")}, {"id", kUndefinedId}}, {}};
  return {"typeref", {{"name", "undefined" + std::to_string(size)}, {"id", kUndefinedId | (0xb3 + size)}}, {}};
}

lift::DecompElement array_of(lift::DecompElement elem, std::uint64_t count, std::uint64_t size) {
  return {"type",
          {{"arraysize", static_cast<std::int64_t>(count)},
           {"metatype", std::string("array")},
           {"name", std::string()},
           {"size", static_cast<std::int64_t>(size)}},
          {std::move(elem)}};
}

// The decompiler's type for an item (PcodeDataTypeManager's encoding of
// Ghidra's string, unicode, unicode32 and pointer types).
lift::DecompElement type_of(const an::DataItem &d, unsigned wide_char, unsigned word) {
  switch (d.kind) {
    case an::DataKind::string:
      return array_of({"typeref", {{"name", std::string("char")}, {"id", 0xc00000000000007bULL}}, {}}, d.length,
                      d.length);
    case an::DataKind::unicode:
    case an::DataKind::unicode32: {
      const unsigned w = d.kind == an::DataKind::unicode ? 2 : 4;
      lift::DecompElement elem =
          w == wide_char ? lift::DecompElement{"typeref", {{"name", std::string("wchar_t")}, {"id", 0xc0000000000000cdULL}}, {}}
          : w == 2       ? lift::DecompElement{"typeref", {{"name", std::string("wchar16")}, {"id", 0xc0000000000000cbULL}}, {}}
                         : lift::DecompElement{"typeref", {{"name", std::string("wchar32")}, {"id", 0xc0000000000000ccULL}}, {}};
      return array_of(std::move(elem), d.length / w, d.length);
    }
    case an::DataKind::pointer:
      return {"type",
              {{"metatype", std::string("ptr")}, {"name", std::string()}, {"size", static_cast<std::int64_t>(word)}},
              {undefined_type(1)}};
    case an::DataKind::undefined:
    case an::DataKind::label:
    case an::DataKind::defined: break;
  }
  return undefined_type(d.length);
}

lift::Mutability mutability(const loader::Image &image, std::uint64_t a) {
  for (const loader::Block &b : image.blocks)
    if (a >= b.start && a - b.start < b.size)
      return b.is_volatile ? lift::Mutability::is_volatile
             : b.perms.write ? lift::Mutability::normal
                             : lift::Mutability::constant;
  return lift::Mutability::normal;
}

const loader::Block *block_at(const loader::Image &image, std::uint64_t a) {
  for (const loader::Block &b : image.blocks)
    if (a >= b.start && a - b.start < b.size) return &b;
  return nullptr;
}

// The image's own bytes: initialized, executable, not I/O (a raw image's
// file contents, not a declared RAM or peripheral region).
bool in_image(const loader::Image &image, std::uint64_t a) {
  const loader::Block *b = block_at(image, a);
  return b != nullptr && b->initialized && !b->is_volatile && b->perms.exec;
}

// What a literal-pool word may be folded to: the strings data analysis
// found and the program's functions.
// The bytes are read as patched where the program has a reader for them
// (docs/patching.md): a patched pool word folds to its new value.
struct FoldTargets {
  std::set<std::uint64_t> strings, code;
  const ByteRead &read;
  FoldTargets(const an::DataList &list, const lift::DecompilerInputs &in, const ByteRead &r) : read(r) {
    for (const an::DataItem &d : list.items)
      if (d.kind == an::DataKind::string || d.kind == an::DataKind::unicode || d.kind == an::DataKind::unicode32)
        strings.insert(d.address);
    for (const lift::FunctionFacts &f : in.functions) code.insert(f.entry);
  }
};

// An item's mutability. A raw image is read/write/execute as Ghidra's raw
// loader maps it, so nothing in it would be constant; but a string in the
// image that no code writes is a constant of the program (flash or ROM in
// firmware; what .rodata is in an ELF), and so is a literal-pool word:
// constant, so the decompiler shows the string ("text", not
// s_text_0800f00c) and folds the pool word where it holds a string's or a
// function's address, or a number outside memory (a mask, a magic
// multiplier), instead of reading DAT_08000254. Ghidra leaves both
// writable here unless its user marks the block read-only.
//
// A pool word holding any other address stays as it was: with a constant
// address into RAM or a peripheral region the decompiler forwards a store
// there to the loads after it, so a register polled after a write (or a
// flag an interrupt sets) becomes an infinite loop wherever the region
// isn't declared volatile, and in an image at a low address a small
// number (a size, a count) would read as a pointer into it.
lift::Mutability mutability(const loader::Image &image, const an::DataItem &d, const FoldTargets &fold) {
  lift::Mutability m = mutability(image, d.address);
  if (d.written && m == lift::Mutability::constant) return lift::Mutability::normal;
  if (image.format != loader::Format::raw || d.written || m != lift::Mutability::normal) return m;
  if (!in_image(image, d.address)) return m;
  if (fold.strings.contains(d.address)) return lift::Mutability::constant;
  if (!d.literal || d.length != image.bits / 8) return m;
  std::array<std::byte, 8> raw{};
  if (fold.read) fold.read(d.address, std::span(raw.data(), d.length));
  else image.memory.read(d.address, std::span(raw.data(), d.length));
  std::uint64_t v = 0;
  for (std::uint32_t i = 0; i < d.length; ++i)
    v = (v << 8) | static_cast<std::uint64_t>(raw[image.endian == loader::Endian::big ? i : d.length - 1 - i]);
  // (A Thumb function's address has its low bit set.)
  if (fold.strings.contains(v) || fold.code.contains(v) || ((v & 1) && fold.code.contains(v - 1)) ||
      block_at(image, v) == nullptr)
    return lift::Mutability::constant;
  return m;
}

}  // namespace

namespace {

// The data already laid out (ELF object symbols), by start.
struct Laid {
  std::map<std::uint64_t, std::size_t> at;
  explicit Laid(const lift::DecompilerInputs &in) {
    for (std::size_t i = 0; i < in.data.size(); ++i)
      if (in.data[i].space.empty()) at[in.data[i].addr] = i;
  }
  // Inside other data, not at its start.
  bool inside_other(const lift::DecompilerInputs &in, std::uint64_t a) const {
    auto it = at.upper_bound(a);
    if (it == at.begin()) return false;
    --it;
    const lift::DataFacts &x = in.data[it->second];
    return it->first != a && a <= x.addr + (std::max<std::uint64_t>(x.length, 1) - 1);
  }
};

}  // namespace

std::map<std::uint64_t, std::string> add_analyzed_values(const an::DataList &list, const loader::Image &image,
                                                         const std::string &prefix, lift::DecompilerInputs &in,
                                                         std::unordered_map<std::uint64_t, std::string> &names,
                                                         const ByteRead &read) {
  std::map<std::uint64_t, std::string> added;
  const unsigned word = image.bits / 8;
  const unsigned wide = image.format == loader::Format::pe ? 2 : 4;
  Laid laid(in);
  const FoldTargets fold(list, in, read);
  for (const an::DataItem &d : list.items) {
    if (d.kind == an::DataKind::pointer || laid.inside_other(in, d.address)) continue;
    if (auto it = laid.at.find(d.address); it != laid.at.end()) {
      // A symbol's undefinedN: a string takes its place, keeping the name.
      if (d.kind == an::DataKind::undefined || d.kind == an::DataKind::label) continue;
      lift::DataFacts &x = in.data[it->second];
      x.length = d.length;
      x.type = type_of(d, wide, word);
      x.string = d.text;
      continue;
    }
    lift::DataFacts f;
    f.addr = d.address;
    f.length = d.length;
    f.type = type_of(d, wide, word);
    f.mutability = mutability(image, d, fold);
    switch (d.kind) {
      case an::DataKind::string: f.name = an::string_label("s_", d.text) + "_" + loader::name_address(image, d.address, prefix); break;
      case an::DataKind::unicode:
      case an::DataKind::unicode32: f.name = an::string_label("u_", d.text) + "_" + loader::name_address(image, d.address, prefix); break;
      default: f.name = "DAT_" + loader::name_address(image, d.address, prefix); break;
    }
    if (d.kind != an::DataKind::undefined && d.kind != an::DataKind::label) f.string = d.text;
    names.emplace(d.address, f.name);
    added.emplace(d.address, f.name);
    laid.at[d.address] = in.data.size();
    in.data.push_back(std::move(f));
  }
  return added;
}

std::map<std::uint64_t, std::string> add_analyzed_pointers(const an::DataList &list, const loader::Image &image,
                                                           const SlotNames &names, lift::DecompilerInputs &in,
                                                           const ByteRead &read) {
  std::map<std::uint64_t, std::string> added;
  const unsigned word = image.bits / 8;
  Laid laid(in);
  const FoldTargets fold(list, in, read);
  for (const an::DataItem &d : list.items) {
    if (d.kind != an::DataKind::pointer || laid.inside_other(in, d.address)) continue;
    if (auto it = laid.at.find(d.address); it != laid.at.end()) {
      lift::DataFacts &x = in.data[it->second];  // a symbol's: keeps its name
      x.length = d.length;
      x.type = type_of(d, 2, word);
      continue;
    }
    lift::DataFacts f;
    f.addr = d.address;
    f.length = d.length;
    f.type = type_of(d, 2, word);
    f.mutability = mutability(image, d, fold);
    f.name = pointer_name(d.address, d.value, true, names);
    added.emplace(d.address, f.name);
    in.data.push_back(std::move(f));
  }
  return added;
}

bool SlotNames::in_body(std::uint64_t a) const {
  auto b = std::upper_bound(bodies.begin(), bodies.end(), a, [](std::uint64_t x, const auto &r) { return x < r.first; });
  return b != bodies.begin() && std::prev(b)->second >= a;
}

const std::uint64_t *SlotNames::pointer_at(std::uint64_t a) const {
  auto it = std::lower_bound(pointers.begin(), pointers.end(), std::make_pair(a, std::uint64_t{0}));
  return it != pointers.end() && it->first == a ? &it->second : nullptr;
}

std::string pointer_name(std::uint64_t at, std::uint64_t value, bool mapped, const SlotNames &names) {
  auto hex = [&](const std::string &p, std::uint64_t a) {
    return names.image != nullptr ? p.substr(0, p.size() - names.prefix.size()) + loader::name_address(*names.image, a, names.prefix)
                                  : p + loader::name_address(loader::Image{}, a);
  };
  const std::string suffix = hex("_" + names.prefix, at);
  auto n = names.names.find(value);
  // (EXTERNAL entries aren't mapped in the image, but have names.)
  if ((!mapped && n == names.names.end()) || value == 0) return "PTR" + suffix;
  if (value == at) return "PTR_LOOP" + suffix;
  const std::string target_address = hex("_" + names.prefix, value);
  // A name the database holds (a symbol) is used whole; a default one
  // (FUN_00101000, s_hi_00104000) without its address.
  const bool dynamic = n == names.names.end() || (n->second.size() > target_address.size() &&
                                                  n->second.ends_with(target_address));
  if (!dynamic) return "PTR_" + n->second + suffix;
  // Pointers to pointers: a cycle of two is a loop, deeper is PTR_PTR.
  if (const std::uint64_t *next = names.pointer_at(value)) return *next == at ? "PTR_LOOP" + suffix : "PTR_PTR" + suffix;
  // (SymbolUtilities.getCleanSymbolName strips the address only where the
  // name spells it as getAddressString does: not where the space shows,
  // as in FUN_ram_00101000.)
  std::string label = n != names.names.end() ? n->second
                                              : (names.in_body(value) ? "LAB" : "DAT") + target_address;
  if (names.prefix.empty()) label.resize(label.size() - target_address.size());
  return "PTR_" + label + suffix;
}

void drop_overlapped(lift::DecompilerInputs &in) {
  // Debug-info variables' extents (they carry the name the debug info gives).
  std::vector<std::pair<std::uint64_t, std::uint64_t>> vars;
  for (const lift::DataFacts &d : in.data)
    if (d.space.empty() && !d.source_name.empty() && d.length > 1) vars.emplace_back(d.addr, d.addr + (d.length - 1));
  if (vars.empty()) return;
  std::sort(vars.begin(), vars.end());
  // Merged, so one look back suffices.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> merged;
  for (const auto &v : vars) {
    if (!merged.empty() && v.first <= merged.back().second) merged.back().second = std::max(merged.back().second, v.second);
    else merged.push_back(v);
  }
  std::erase_if(in.data, [&](const lift::DataFacts &d) {
    if (!d.space.empty() || !d.source_name.empty()) return false;
    auto it = std::upper_bound(merged.begin(), merged.end(), std::make_pair(d.addr, ~std::uint64_t{0}));
    if (it == merged.begin()) return false;
    --it;
    // Inside a variable, not at its start (a variable there replaced it).
    return d.addr > it->first && d.addr <= it->second;
  });
}

}  // namespace revkit::inputs
