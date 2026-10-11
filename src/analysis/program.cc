// ProgramInfo: codecs, lookups, building it from a loaded image, and
// writing an image into a fact store.

#include "revkit/analysis/analysis.h"
#include "revkit/analysis/data.h"

#include "revkit/lift/abi.hh"
#include "revkit/lift/context.hh"
#include "revkit/lift/lifter.hh"

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <span>
#include <cstdio>
#include <map>
#include <mutex>
#include <set>

namespace revkit::analysis {

using facts::Decoder;
using facts::Encoder;

// ---- codecs ----

void Range::encode(Encoder &e) const {
  e.varint(first);
  e.varint(last - first);
}

Range Range::decode(Decoder &d) {
  Range r;
  r.first = d.varint();
  std::uint64_t span = d.varint();
  if (span > ~std::uint64_t{0} - r.first) throw facts::DecodeError("range wraps");
  r.last = r.first + span;
  return r;
}

void Seed::encode(Encoder &e) const {
  e.varint(address);
  e.varint(flags);
  e.bytes(name);
  facts::encode(e, named_by_symbol);
}

Seed Seed::decode(Decoder &d) {
  Seed s;
  s.address = d.varint();
  s.flags = facts::decode<std::uint16_t>(d);
  s.name = std::string(d.bytes());
  s.named_by_symbol = facts::decode<bool>(d);
  return s;
}

void ImportSlot::encode(Encoder &e) const {
  e.varint(address);
  e.bytes(name);
}

ImportSlot ImportSlot::decode(Decoder &d) {
  ImportSlot s;
  s.address = d.varint();
  s.name = std::string(d.bytes());
  return s;
}

void ContextSetting::encode(Encoder &e) const {
  e.bytes(name);
  e.varint(value);
  range.encode(e);
}

ContextSetting ContextSetting::decode(Decoder &d) {
  ContextSetting c;
  c.name = std::string(d.bytes());
  c.value = facts::decode<std::uint32_t>(d);
  c.range = Range::decode(d);
  return c;
}

void StartPattern::encode(Encoder &e) const {
  e.bytes(std::string_view(reinterpret_cast<const char *>(value.data()), value.size()));
  e.bytes(std::string_view(reinterpret_cast<const char *>(mask.data()), mask.size()));
  e.varint(pre);
  e.varint(align);
  e.svarint(isa);
  facts::encode(e, kind);
  facts::encode(e, after);
  e.varint(valid_min);
  e.varint(valid_max);
  facts::encode(e, contiguous);
}

StartPattern StartPattern::decode(Decoder &d) {
  StartPattern p;
  auto bytes = [&] {
    std::string_view b = d.bytes();
    return std::vector<std::uint8_t>(b.begin(), b.end());
  };
  p.value = bytes();
  p.mask = bytes();
  p.pre = facts::decode<std::uint32_t>(d);
  p.align = facts::decode<std::uint32_t>(d);
  p.isa = static_cast<std::int32_t>(d.svarint());
  p.kind = facts::decode<StartPattern::Kind>(d);
  p.after = facts::decode<StartPattern::After>(d);
  p.valid_min = facts::decode<std::uint16_t>(d);
  p.valid_max = facts::decode<std::uint16_t>(d);
  p.contiguous = facts::decode<bool>(d);
  if (p.value.size() != p.mask.size() || p.pre > p.value.size() || p.align == 0 ||
      p.kind > StartPattern::Kind::possible || p.after > StartPattern::After::pointer)
    throw facts::DecodeError("bad start pattern");
  return p;
}

void SpaceInfo::encode(Encoder &e) const {
  e.bytes(name);
  e.varint(base);
  e.varint(wordsize);
  e.varint(digits);
  facts::encode(e, alias);
}

SpaceInfo SpaceInfo::decode(Decoder &d) {
  SpaceInfo s;
  s.name = std::string(d.bytes());
  s.base = d.varint();
  s.wordsize = facts::decode<std::uint32_t>(d);
  s.digits = facts::decode<std::uint32_t>(d);
  s.alias = facts::decode<bool>(d);
  if (s.wordsize == 0 || s.wordsize > 8 || s.digits > 16) throw facts::DecodeError("bad space");
  return s;
}

void ProgramInfo::encode(Encoder &e) const {
  e.bytes(language);
  e.bytes(compiler);
  e.varint(space);
  e.bytes(code_space);
  facts::encode(e, qualify_names);
  facts::encode(e, big_endian);
  e.u8(pointer_size);
  facts::encode(e, code);
  facts::encode(e, data_in_code);
  facts::encode(e, plt);
  facts::encode(e, context);
  facts::encode(e, seeds);
  facts::encode(e, imports);
  facts::encode(e, references);
  facts::encode(e, mapped);
  e.bytes(isa_context);
  facts::encode(e, isa_register);
  facts::encode(e, link_register);
  // `search` with flags for the byte sources and call-preserved registers
  // that follow `patterns`, so a program without memory-map edits or a
  // known <unaffected> list encodes (and fingerprints) as before.
  e.u8(static_cast<std::uint8_t>((search ? 1 : 0) | (sources.empty() ? 0 : 2) | (call_preserved.empty() ? 0 : 4)));
  facts::encode(e, patterns);
  if (!sources.empty()) {
    e.varint(sources.size());
    for (const SourceRange &b : sources) {
      b.range.encode(e);
      e.varint(b.space);
      e.varint(b.offset);
    }
  }
  if (!call_preserved.empty()) facts::encode(e, call_preserved);
  // A trailer, so records of single-space programs are unchanged.
  if (spaces.size() > 1 || (spaces.size() == 1 && (spaces[0].wordsize != 1 || spaces[0].digits != 8)) ||
      !register_memory.empty()) {
    facts::encode(e, spaces);
    facts::encode(e, register_memory);
  }
}

ProgramInfo ProgramInfo::decode(Decoder &d) {
  ProgramInfo p;
  p.language = std::string(d.bytes());
  p.compiler = std::string(d.bytes());
  p.space = facts::decode<facts::SpaceId>(d);
  p.code_space = std::string(d.bytes());
  p.qualify_names = facts::decode<bool>(d);
  p.big_endian = facts::decode<bool>(d);
  p.pointer_size = d.u8();
  p.code = facts::decode<std::vector<Range>>(d);
  p.data_in_code = facts::decode<std::vector<Range>>(d);
  p.plt = facts::decode<std::vector<Range>>(d);
  p.context = facts::decode<std::vector<ContextSetting>>(d);
  p.seeds = facts::decode<std::vector<Seed>>(d);
  p.imports = facts::decode<std::vector<ImportSlot>>(d);
  p.references = facts::decode<bool>(d);
  p.mapped = facts::decode<std::vector<Range>>(d);
  p.isa_context = std::string(d.bytes());
  p.isa_register = facts::decode<std::optional<RegisterSlot>>(d);
  p.link_register = facts::decode<std::optional<RegisterSlot>>(d);
  const std::uint8_t flags = d.u8();
  if (flags > 7) throw facts::DecodeError("bad ProgramInfo flags");
  p.search = (flags & 1) != 0;
  p.patterns = facts::decode<std::vector<StartPattern>>(d);
  if (flags & 2) {
    const std::uint64_t n = d.varint();
    for (std::uint64_t i = 0; i < n; ++i) {
      SourceRange b;
      b.range = Range::decode(d);
      b.space = facts::decode<facts::SpaceId>(d);
      b.offset = d.varint();
      p.sources.push_back(b);
    }
  }
  if (flags & 4) p.call_preserved = facts::decode<std::vector<RegisterSlot>>(d);
  if (!d.done()) {
    p.spaces = facts::decode<std::vector<SpaceInfo>>(d);
    p.register_memory = facts::decode<std::vector<Range>>(d);
  }
  return p;
}

// ---- lookups ----

namespace {

// The range in a sorted, disjoint list that contains `a`.
const Range *find_range(const std::vector<Range> &ranges, std::uint64_t a) {
  auto it = std::upper_bound(ranges.begin(), ranges.end(), a,
                             [](std::uint64_t x, const Range &r) { return x < r.first; });
  if (it == ranges.begin()) return nullptr;
  --it;
  return it->contains(a) ? &*it : nullptr;
}

}  // namespace

bool ProgramInfo::is_mapped(std::uint64_t a) const { return find_range(mapped, a) != nullptr; }

std::optional<std::uint64_t> ProgramInfo::space_key(std::string_view space, std::uint64_t offset) const {
  if (space.empty() || space == code_space) return offset;
  for (const SpaceInfo &s : spaces) {
    if (s.name != space) continue;
    if (s.alias || s.base == 0) return offset;
    if (offset >= (std::uint64_t{1} << loader::kSpaceKeyShift)) return std::nullopt;
    return s.base + offset;
  }
  return std::nullopt;
}

std::optional<std::uint64_t> ProgramInfo::pointer_key(std::string_view space, std::uint64_t value) const {
  if (space.empty()) space = code_space;
  std::uint32_t wordsize = 1;
  for (const SpaceInfo &s : spaces)
    if (s.name == space) wordsize = s.wordsize;
  if (wordsize > 1) {
    if (value > (~std::uint64_t{0}) / wordsize) return std::nullopt;
    value *= wordsize;
  }
  return space_key(space, value);
}

const SpaceInfo *ProgramInfo::space_of(std::uint64_t key) const {
  const std::uint64_t base = key & ~((std::uint64_t{1} << loader::kSpaceKeyShift) - 1);
  const SpaceInfo *out = spaces.empty() ? nullptr : &spaces.front();
  if (base != 0)
    for (const SpaceInfo &s : spaces)
      if (!s.alias && s.base == base) out = &s;
  return out;
}

bool ProgramInfo::is_code(std::uint64_t a) const {
  return find_range(code, a) != nullptr && find_range(data_in_code, a) == nullptr;
}

bool ProgramInfo::thumb(std::uint64_t key) const {
  if (isa_context.empty()) return false;
  if (key & 1) return true;
  for (const ContextSetting &c : context)
    if (c.name == isa_context && c.value == 1 && c.range.contains(key)) return true;
  return false;
}

std::uint64_t ProgramInfo::code_key(std::uint64_t address, bool is_thumb) const {
  if (isa_context.empty()) return address;
  address &= ~std::uint64_t{1};
  return is_thumb && !thumb(address) ? address | 1 : address;
}

const Seed *ProgramInfo::seed_at(std::uint64_t a) const {
  auto it = std::lower_bound(seeds.begin(), seeds.end(), a,
                             [](const Seed &s, std::uint64_t x) { return s.address < x; });
  return it != seeds.end() && it->address == a ? &*it : nullptr;
}

const ImportSlot *ProgramInfo::import_at(std::uint64_t slot) const {
  auto it = std::lower_bound(imports.begin(), imports.end(), slot,
                             [](const ImportSlot &s, std::uint64_t x) { return s.address < x; });
  return it != imports.end() && it->address == slot ? &*it : nullptr;
}

std::string describe(const Location &l) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(l.address));
  return l.program.id.empty() ? std::string(buf) : l.program.id + ":" + buf;
}

std::string default_name(const ProgramInfo &info, std::uint64_t address) {
  return address_name(info, "FUN_", address);
}

std::string address_name(const ProgramInfo &info, std::string_view prefix, std::uint64_t key) {
  const SpaceInfo *s = info.space_of(key);
  std::uint64_t offset = key - (s ? s->base : 0);
  if (s && s->wordsize > 1) offset /= s->wordsize;
  char buf[32];
  std::snprintf(buf, sizeof buf, "%0*llx", static_cast<int>(s ? s->digits : 8), static_cast<unsigned long long>(offset));
  std::string out(prefix);
  if (info.qualify_names) out.append(s ? s->name : info.code_space).push_back('_');
  return out + buf;
}

bool is_known_no_return(std::string_view name) {
  // Ghidra's ElfFunctionsThatDoNotReturn and PEFunctionsThatDoNotReturn
  // (compared without leading underscores, as Ghidra does), plus the
  // err()/errx() family, quick_exit, __cxa_rethrow and the fortify
  // failure entry points, which are declared noreturn in glibc. Ghidra's
  // ELF list also has "cexit" and "c_exit"; msvcrt's _cexit and _c_exit
  // run exit-time cleanup and return, so they are left out.
  static const std::set<std::string_view> kNames = {
      // ELF
      "exit", "Exit", "abort", "reboot", "longjmp", "longjmp_chk", "siglongjmp", "panic",
      "stack_chk_fail", "stack_chk_fail_local", "cxa_throw", "cxa_rethrow", "cxa_terminate",
      "cxa_call_unexpected", "cxa_bad_cast", "cxa_bad_typeid", "cxa_throw_bad_array_new_length",
      "Unwind_Resume", "assert_fail", "assert_rtn", "assert_perror_fail", "fortify_fail", "chk_fail",
      "ZSt9terminatev", "ZN10__cxxabiv111__terminateEPFvvE", "pthread_exit", "quick_exit", "err", "errx",
      "verr", "verrx", "libc_fatal",
      // PE
      "CxxThrowException", "CxxThrowException@8", "CxxFrameHandler3", "crtExitProcess", "ExitProcess",
      "ExitThread", "ExRaiseAccessViolation", "ExRaiseDatatypeMisalignment", "ExRaiseStatus",
      "FreeLibraryAndExitThread", "invalid_parameter_noinfo_noreturn", "invoke_watson", "KeBugCheck",
      "KeBugCheckEx", "RpcRaiseException", "terminate", "raise_securityfailure",
      "report_rangecheckfailure", "report_gsfailure", "?terminate@@YAXXZ",
  };
  while (!name.empty() && name.front() == '_') name.remove_prefix(1);
  return kNames.contains(name);
}

// ---- describe ----

namespace {

int bind_rank(loader::SymbolBind b) {
  switch (b) {
    case loader::SymbolBind::global: return 0;
    case loader::SymbolBind::weak: return 1;
    default: return 2;
  }
}

// Adjacent and overlapping ranges merged, sorted.
std::vector<Range> normalize(std::vector<Range> v) {
  std::sort(v.begin(), v.end());
  std::vector<Range> out;
  for (const Range &r : v) {
    if (!out.empty() && (out.back().last == ~std::uint64_t{0} || r.first <= out.back().last + 1))
      out.back().last = std::max(out.back().last, r.last);
    else
      out.push_back(r);
  }
  return out;
}

struct SeedBuilder {
  struct Entry {
    std::uint16_t flags = 0;
    std::string symbol;  // best symbol/export name
    int symbol_rank = 99;
    std::string conventional;  // "entry", "_INIT_0", ...
    int conventional_rank = 99;
  };
  std::map<std::uint64_t, Entry> entries;
  const ProgramInfo &info;

  void add(std::uint64_t a, std::uint16_t flags) {
    if (!info.is_code(a)) return;
    entries[a].flags |= flags;
  }
  void symbol(std::uint64_t a, std::uint16_t flags, const std::string &name, int rank) {
    if (!info.is_code(a) || name.empty()) return;
    Entry &e = entries[a];
    e.flags |= flags;
    if (rank < e.symbol_rank || (rank == e.symbol_rank && name < e.symbol)) {
      e.symbol = name;
      e.symbol_rank = rank;
    }
  }
  void conventional(std::uint64_t a, std::uint16_t flags, const std::string &name, int rank) {
    if (!info.is_code(a)) return;
    Entry &e = entries[a];
    e.flags |= flags;
    if (rank < e.conventional_rank) {
      e.conventional = name;
      e.conventional_rank = rank;
    }
  }
  std::vector<Seed> finish() const {
    std::vector<Seed> out;
    for (const auto &[a, e] : entries) {
      Seed s{a, e.flags, e.symbol.empty() ? e.conventional : e.symbol, !e.symbol.empty()};
      out.push_back(std::move(s));
    }
    return out;
  }
};

// What describe() reads from SLEIGH about a language (`language` without
// its compiler) and its compiler spec: building an engine parses the .sla,
// so it is done once per language and compiler.
struct LanguageFacts {
  std::string code_space;
  bool qualify = false;
  std::vector<lift::ProcessorSymbol> processor;
  std::optional<RegisterSlot> isa_register, link_register;
  std::vector<RegisterSlot> call_preserved;
  std::vector<lift::SpaceDef> spaces;
  std::vector<lift::RegisterDef> memory_registers;  // registers outside the register space
};

const LanguageFacts &language_facts(const std::string &language, const std::string &compiler) {
  static std::mutex mu;
  static std::map<std::string, LanguageFacts> cache;
  std::unique_lock lock(mu);
  const std::string cache_key = language + "|" + compiler;
  auto it = cache.find(cache_key);
  if (it == cache.end()) {
    lock.unlock();
    LanguageFacts facts;
    lift::Lifter lifter(std::make_shared<const loader::Image>(), language);
    facts.code_space = lifter.code_space_name();
    facts.qualify = lifter.memory_spaces().size() > 1;
    facts.spaces = lifter.spaces();
    for (lift::RegisterDef &r : lifter.registers())
      if (r.space != "register" && r.size != 0) facts.memory_registers.push_back(std::move(r));
    facts.processor = lift::processor_symbols(language);
    // ARM interworking: the register BX and BLX set to the target's
    // instruction set (TB; Ghidra's pspec calls it ISAModeSwitch).
    std::optional<lift::Varnode> isa;
    // ARM v4 and v5 have the register but no Thumb (no TMode context).
    if (language.starts_with("ARM:") && lifter.has_context("TMode")) isa = lifter.register_varnode("TB");
    if (isa) {
      facts.isa_register = RegisterSlot{isa->offset, isa->size};
      if (auto lr = lifter.register_varnode("lr")) facts.link_register = RegisterSlot{lr->offset, lr->size};
    }
    try {
      for (const std::string &name : lift::read_abi(language, compiler).call_preserved)
        if (auto r = lifter.register_varnode(name)) facts.call_preserved.push_back(RegisterSlot{r->offset, r->size});
      std::sort(facts.call_preserved.begin(), facts.call_preserved.end());
    } catch (const lift::LiftError &) {
      facts.call_preserved.clear();  // unknown: calls forget everything
    }
    lock.lock();
    it = cache.emplace(cache_key, std::move(facts)).first;
  }
  return it->second;
}

}  // namespace

void prepare_language(const std::string &language) {
  // As describe() splits it.
  if (std::count(language.begin(), language.end(), ':') >= 4) {
    const auto colon = language.rfind(':');
    language_facts(language.substr(0, colon), language.substr(colon + 1));
  } else {
    language_facts(language, {});
  }
}

ProgramInfo describe(const loader::Image &image, const std::string &language, facts::SpaceId space,
                     const ByteSource &bytes) {
  ProgramInfo info;
  std::vector<lift::ProcessorSymbol> processor;
  info.language = language;
  if (std::count(language.begin(), language.end(), ':') >= 4) {
    auto colon = language.rfind(':');
    info.language = language.substr(0, colon);
    info.compiler = language.substr(colon + 1);
  }
  info.space = space;
  {
    // What the language's spaces are, from SLEIGH (language_facts).
    const LanguageFacts &lf = language_facts(info.language, info.compiler);
    info.code_space = lf.code_space;
    info.qualify_names = lf.qualify;
    processor = lf.processor;
    // The spaces addresses are keyed in: the default one, then the image's.
    auto digits = [](const lift::SpaceDef &d) { return std::min<std::uint32_t>(8, std::max<std::uint32_t>(1, 2 * d.address_size)); };
    for (const lift::SpaceDef &d : lf.spaces)
      if (d.is_default) info.spaces.push_back({d.name, 0, d.wordsize, digits(d), false});
    if (info.spaces.empty()) info.spaces.push_back({info.code_space, 0, 1, 8, false});
    for (const loader::AddressSpace &a : image.spaces)
      for (const lift::SpaceDef &d : lf.spaces)
        if (d.name == a.name && !d.is_default) info.spaces.push_back({a.name, a.base, d.wordsize, digits(d), a.alias_of_default});
    std::vector<Range> regs;
    for (const lift::RegisterDef &r : lf.memory_registers)
      if (auto k = info.space_key(r.space, r.offset)) regs.push_back({*k, *k + (r.size - 1)});
    info.register_memory = normalize(std::move(regs));
    // Processor symbols' addresses count in their space's units.
    for (lift::ProcessorSymbol &p : processor) {
      const std::string space = p.space.empty() ? info.code_space : p.space;
      for (const lift::SpaceDef &d : lf.spaces)
        if (d.name == space && d.wordsize > 1) p.address *= d.wordsize;
    }
    info.isa_register = lf.isa_register;
    info.link_register = lf.link_register;
    info.call_preserved = lf.call_preserved;
    if (info.isa_register) info.isa_context = "TMode";
  }
  info.big_endian = image.endian == loader::Endian::big;
  info.pointer_size = static_cast<std::uint8_t>(image.bits / 8);

  std::vector<Range> code;
  for (const loader::Block &b : image.blocks)
    if (b.perms.exec && b.initialized && b.size != 0) code.push_back({b.start, b.start + (b.size - 1)});
  info.code = normalize(std::move(code));
  std::vector<Range> mapped;
  for (const loader::Region &r : image.memory.regions())
    if (r.size != 0) mapped.push_back({r.start, r.last()});
  info.mapped = normalize(std::move(mapped));
  std::vector<Range> data;
  for (const auto &[first, last] : lift::embedded_data(image)) data.push_back({first, last});
  info.data_in_code = normalize(std::move(data));
  for (const lift::ContextRegion &c : lift::image_context(image))
    if (c.end > c.start) info.context.push_back({c.name, c.value, {c.start, c.end - 1}});

  // The processor's vectors held as pointers (type="code_ptr": Cortex-M,
  // MSP430, 6502, the 68HC families, V850): the pointer's slot is data and
  // the code it points to is an entry. The spec puts Cortex-M's table at 0,
  // but firmware is usually loaded at its flash address with the table at
  // the image's start (VTOR): when the spec's slots aren't mapped, they are
  // taken from the lowest mapped address, if the first entry's pointer
  // there lands in code.
  auto in_code_space = [&](const lift::ProcessorSymbol &p) { return p.space.empty() || p.space == info.code_space; };
  auto read_ptr = [&](std::uint64_t at) -> std::optional<std::uint64_t> {
    const unsigned n = info.pointer_size;
    if (n == 0 || n > 8) return std::nullopt;
    std::array<std::byte, 8> buf{};
    if (image.memory.read(at, std::span<std::byte>(buf.data(), n)) != n) return std::nullopt;
    std::uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i) v = (v << 8) | std::to_integer<unsigned>(buf[info.big_endian ? i : n - 1 - i]);
    return v;
  };
  // A vector's target: Thumb pointers carry the mode in bit 0.
  auto target = [&](std::uint64_t v) { return info.isa_register ? (v & ~std::uint64_t{1}) : v; };
  std::uint64_t vector_base = 0;
  bool vectors = false;
  for (const lift::ProcessorSymbol &p : processor) {
    if (!p.code_ptr || !p.entry || !in_code_space(p)) continue;
    if (image.memory.is_mapped(p.address)) {
      vectors = true;
    } else if (!image.memory.regions().empty()) {
      const std::uint64_t base = image.memory.regions().front().start;
      auto v = read_ptr(base + p.address);
      if (v && *v != 0 && find_range(info.code, target(*v)) != nullptr) vector_base = base, vectors = true;
    }
    break;
  }
  std::vector<std::pair<std::uint64_t, std::string>> vector_seeds;
  if (vectors) {
    std::vector<Range> slots;
    std::uint64_t end = 0;
    for (const lift::ProcessorSymbol &p : processor) {
      if (!p.code_ptr || !in_code_space(p)) continue;
      const std::uint64_t at = p.address + vector_base;
      if (!image.memory.is_mapped(at)) continue;
      slots.push_back({at, at + (info.pointer_size - 1)});
      end = std::max(end, at + info.pointer_size);
      if (auto v = read_ptr(at); p.entry && v && *v != 0) vector_seeds.emplace_back(target(*v), p.name);
    }
    // Cortex-M's table goes on past the spec's symbols, one handler per
    // external interrupt from 0x40 (the spec's "IRQ" is the first): words
    // that are Thumb pointers into code, or 0 for an unused one, up to 496
    // interrupts. They are named by number, IRQ1 at 0x44.
    if (info.language.find("Cortex") != std::string::npos && end != 0) {
      const std::uint64_t first_irq = vector_base + 0x40;
      for (; end < first_irq + 496 * std::uint64_t{info.pointer_size}; end += info.pointer_size) {
        auto v = read_ptr(end);
        if (!v || (*v != 0 && ((*v & 1) == 0 || find_range(info.code, target(*v)) == nullptr))) break;
        slots.push_back({end, end + (info.pointer_size - 1)});
        if (*v != 0 && end >= first_irq)
          vector_seeds.emplace_back(target(*v), "IRQ" + std::to_string((end - first_irq) / info.pointer_size));
      }
    }
    for (const Range &r : info.data_in_code) slots.push_back(r);
    info.data_in_code = normalize(std::move(slots));
  }

  SeedBuilder seeds{{}, info};
  const bool pe = image.format == loader::Format::pe;
  if (image.entry) seeds.conventional(*image.entry, kSeedEntry, "entry", 0);
  // The processor's entry points (Ghidra's "Apply Processor Defined
  // Labels"): ARM's exception vectors, where code is mapped there, and the
  // code the pointer vectors above point to.
  for (const lift::ProcessorSymbol &p : processor)
    if (p.entry && !p.code_ptr && in_code_space(p)) seeds.conventional(p.address, kSeedProcessor, p.name, 3);
  for (const auto &[a, name] : vector_seeds) seeds.conventional(a, kSeedProcessor, name, 3);
  for (const loader::Symbol &s : image.symbols) {
    if (!s.defined || (s.type != loader::SymbolType::func && s.type != loader::SymbolType::ifunc)) continue;
    seeds.symbol(lift::function_address(image, s), kSeedSymbol, s.name, bind_rank(s.bind));
  }
  for (const loader::Export &e : image.exports)
    if (e.forwarder.empty()) seeds.symbol(e.address, kSeedExport, e.name, 3);
  for (const loader::FunctionRange &r : image.function_ranges)
    if (r.end > r.start) seeds.add(r.start, kSeedUnwind);

  const loader::InitFini &init = image.init_fini;
  if (init.init) seeds.conventional(*init.init, kSeedInit, "_DT_INIT", 2);
  if (init.fini) seeds.conventional(*init.fini, kSeedInit, "_DT_FINI", 2);
  auto array = [&](const std::vector<std::uint64_t> &entries, const char *prefix) {
    for (std::size_t i = 0; i < entries.size(); ++i)
      seeds.conventional(entries[i], kSeedInit, prefix + std::to_string(i), 1);
  };
  array(init.preinit_array, "_PREINIT_");
  array(init.init_array, "_INIT_");
  array(init.fini_array, "_FINI_");

  // PLT stubs. With IBT (.plt.sec present), .plt's own stubs are lazy
  // binding trampolines nothing calls; only its header is code to keep.
  const bool ibt = std::any_of(image.plt_sections.begin(), image.plt_sections.end(),
                               [](const loader::PltSection &p) { return p.name == ".plt.sec"; });
  std::vector<Range> plt;
  for (const loader::PltSection &p : image.plt_sections) {
    plt.push_back({p.start, p.start + (p.size - 1)});
    if (p.header_size != 0) seeds.add(p.start, kSeedPlt);
    if (p.entry_size == 0 || (ibt && p.name == ".plt")) continue;
    for (std::uint64_t at = p.start + p.header_size; at + p.entry_size <= p.start + p.size; at += p.entry_size)
      seeds.add(at, kSeedPlt);
  }
  info.plt = normalize(std::move(plt));

  // Import slots.
  std::map<std::uint64_t, std::string> slots;
  if (pe) {
    for (const loader::Import &imp : image.imports) {
      if (imp.iat_address == 0) continue;
      std::string name = imp.name;
      if (name.empty() && imp.ordinal) name = "Ordinal_" + std::to_string(*imp.ordinal);
      if (!name.empty()) slots.emplace(imp.iat_address, std::move(name));
    }
  } else {
    std::set<std::string> undefined;
    for (const loader::Symbol &s : image.symbols)
      if (!s.defined && !s.name.empty()) undefined.insert(s.name);
    for (const loader::Relocation &r : image.relocations) {
      if (r.symbol.empty()) continue;
      bool slot = r.kind == loader::RelocationKind::jump_slot || r.kind == loader::RelocationKind::glob_dat ||
                  (r.kind == loader::RelocationKind::absolute && r.addend == 0 && undefined.contains(r.symbol));
      if (slot) slots.emplace(r.address, r.symbol);
    }
  }
  for (auto &[a, name] : slots) info.imports.push_back({a, std::move(name)});

  // PE import stubs (mingw's "jmp [__imp_f]; nop; nop", 8-byte aligned):
  // linker-made functions even when nothing calls them directly. Functions
  // with unwind info are compiled code, never stubs.
  if (pe && (image.machine == 0x8664 || image.machine == 0x14c)) {
    const bool wide = image.machine == 0x8664;
    auto covered = [&](std::uint64_t a) {
      auto it = std::upper_bound(image.function_ranges.begin(), image.function_ranges.end(), a,
                                 [](std::uint64_t x, const loader::FunctionRange &r) { return x < r.start; });
      return it != image.function_ranges.begin() && std::prev(it)->end > a;
    };
    std::array<std::byte, 8> b{};
    for (const Range &r : info.code) {
      for (std::uint64_t a = (r.first + 7) & ~std::uint64_t{7}; a + 8 <= r.last + 1 && a >= r.first; a += 8) {
        if ((bytes ? bytes(a, b) : image.memory.read(a, b)) != b.size()) continue;
        auto u8 = [&](int i) { return std::to_integer<std::uint8_t>(b[i]); };
        if (u8(0) != 0xff || u8(1) != 0x25 || u8(6) != 0x90 || u8(7) != 0x90) continue;
        std::uint32_t d = static_cast<std::uint32_t>(u8(2) | u8(3) << 8 | u8(4) << 16 | u8(5) << 24);
        std::uint64_t slot = wide ? a + 6 + static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(d))) : d;
        if (info.import_at(slot) && !covered(a)) seeds.add(a, kSeedPlt);
      }
    }
  }
  info.seeds = seeds.finish();
  // A raw image has nothing to seed from but the processor's vectors and
  // an entry point: search the code nothing reaches too.
  // So does a stripped ARM ELF: no static symbol table's functions (only
  // what it exports, if anything), so little but its entry point, init
  // arrays, exports and PLT to start from; Ghidra's default analysis looks
  // for function starts and follows code pointers there too. (Measured on
  // ARM only so far: elsewhere a stripped ELF is walked from what it has.)
  const bool stripped = image.format == loader::Format::elf && !info.isa_context.empty() &&
                        std::none_of(image.symbols.begin(), image.symbols.end(), [](const loader::Symbol &s) {
                          return s.defined && s.type == loader::SymbolType::func &&
                                 s.source == loader::SymbolSource::symtab;
                        });
  if (image.format == loader::Format::raw || stripped) {
    info.search = true;
    info.patterns = load_start_patterns(info.language, info.compiler);
  }
  return info;
}

// ---- import ----

void stage_image(facts::FactDb::Transaction &tx, const ProgramKey &program, const loader::Image &image,
                 const ProgramInfo &info) {
  // Pointer-sized relative relocations, applied to the copies we write.
  std::map<std::uint64_t, std::uint64_t> patches;
  for (const loader::Relocation &r : image.relocations)
    if (r.kind == loader::RelocationKind::relative && r.target) patches[r.address] = *r.target;

  std::vector<std::byte> buf;
  for (const loader::Region &region : image.memory.regions()) {
    if (region.file_size == 0) continue;
    buf.resize(static_cast<std::size_t>(region.file_size));
    image.memory.read(region.start, buf);
    const unsigned n = info.pointer_size;
    for (auto it = patches.lower_bound(region.start);
         it != patches.end() && it->first - region.start + n <= region.file_size; ++it) {
      std::uint64_t off = it->first - region.start;
      for (unsigned i = 0; i < n; ++i) {
        unsigned shift = info.big_endian ? 8 * (n - 1 - i) : 8 * i;
        buf[static_cast<std::size_t>(off + i)] = static_cast<std::byte>((it->second >> shift) & 0xff);
      }
    }
    tx.write_bytes(facts::Address{info.space, region.start},
                   std::string_view(reinterpret_cast<const char *>(buf.data()), buf.size()));
  }
  tx.set<LoadedProgram>(program, info);
  tx.set<LoadedDataProgram>(program, describe_data(image));
}

facts::Revision import_image(facts::FactDb &db, const ProgramKey &program, const loader::Image &image,
                             const ProgramInfo &info) {
  auto tx = db.begin();
  stage_image(tx, program, image, info);
  return tx.commit();
}

}  // namespace revkit::analysis
