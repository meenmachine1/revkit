// Memory beyond the image: the RAM and the devices' registers (MMIO) the
// code uses, from what its trace says about addresses outside the image
// (docs/autodetect.md, "Memory regions").
//
// Evidence, strongest first: loads and stores at addresses the code names,
// with their widths, directions and stored constants; registers reached as
// small offsets from one base constant (a device's register block); the
// initial stack pointer (the top of RAM); startup copies from the image and
// clears (the start of RAM). The processor's architectural memory map, where
// it has one, is a prior and a boundary, never a source.
#include "revkit/detect/detect.hh"

#include "revkit/lift/lifter.hh"

#include <algorithm>
#include <bit>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <tuple>
#include <unordered_map>

namespace revkit::detect {

namespace {

constexpr std::uint64_t kLongestFill = 16u << 20;  // a copy or clear longer than this isn't a startup's
constexpr std::uint64_t kStartupReach = 64u << 10;  // startup code is this near the image's start or end
constexpr std::uint64_t kPollLoop = 32;            // a polling loop is a few instructions
constexpr std::uint64_t kGap = 64u << 10;          // accesses further apart than this are different memories
constexpr std::uint64_t kNear = 16u << 20;         // a stack this far above RAM's variables is still its top
constexpr std::uint64_t kPage = 0x1000;

std::string hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::string bare_hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::string size_text(std::uint64_t n) {
  if (n >= (1u << 20) && n % (1u << 20) == 0) return std::to_string(n >> 20) + " MiB";
  if (n >= 1024 && n % 1024 == 0) return std::to_string(n >> 10) + " KiB";
  return std::to_string(n) + " bytes";
}

std::uint64_t round_down(std::uint64_t v, std::uint64_t to) { return v / to * to; }
std::uint64_t round_up(std::uint64_t v, std::uint64_t to) { return (v + to - 1) / to * to; }

// The smallest size RAM comes in that holds `n`: a power of two, or one
// and a half (192 KiB, 384 KiB). At least a page; `n` itself where no
// such size is (past half the 64-bit space).
std::uint64_t plausible_size(std::uint64_t n, std::uint64_t page = kPage) {
  std::uint64_t s = page;
  while (s < n) {
    if (s >= 2 * page && s + s / 2 >= n) return s + s / 2;
    if (s > (~std::uint64_t{0} >> 2)) return n;
    s *= 2;
  }
  return s;
}

std::string widths_text(std::uint32_t widths) {
  std::string out;
  for (unsigned b = 1; b <= 8; b *= 2)
    if (widths & (1u << b)) out += (out.empty() ? "" : ", ") + std::to_string(b);
  return out;
}

void dump(const MemoryFacts &m) {
  if (m.image_start)
    std::fprintf(stderr, "image %llx-%llx\n", (unsigned long long)*m.image_start, (unsigned long long)*m.image_end);
  for (std::uint64_t s : m.stack_tops)
    std::fprintf(stderr, "stack %llx%s\n", (unsigned long long)s, m.vector_table_stack == s ? " (vt)" : "");
  for (const MemoryFill &f : m.fills)
    std::fprintf(stderr, "%s %llx-%llx from %llx\n", f.source ? "copy" : "clear", (unsigned long long)f.start,
                 (unsigned long long)f.end, (unsigned long long)f.source.value_or(0));
  std::map<std::uint64_t, std::vector<const MemoryUse *>> pages;
  for (const MemoryUse &u : m.uses) pages[u.address >> 16].push_back(&u);
  for (const auto &[page, us] : pages) {
    unsigned reads = 0, writes = 0, polled = 0, modified = 0, flags = 0, values = 0, widths = 0;
    for (const MemoryUse *u : us)
      reads += u->reads, writes += u->writes, polled += u->polled, modified += u->modified, flags += u->flags,
          values += u->values, widths |= u->widths;
    std::fprintf(stderr,
                 "page %llx0000: %zu addresses %llx-%llx reads %u writes %u polled %u modified %u values %u flags %u "
                 "widths %x\n",
                 (unsigned long long)page, us.size(), (unsigned long long)us.front()->address,
                 (unsigned long long)us.back()->address, reads, writes, polled, modified, values, flags, widths);
  }
}

}  // namespace

std::string_view name(RegionSuggestion::Kind k) {
  switch (k) {
    case RegionSuggestion::Kind::ram: return "ram";
    case RegionSuggestion::Kind::mmio: return "mmio";
    case RegionSuggestion::Kind::unknown: return "unknown";
  }
  return "?";
}

std::vector<std::pair<std::uint64_t, std::uint64_t>> startup_windows(std::span<const std::byte> file,
                                                                     const std::vector<Segment> &segments,
                                                                     std::uint64_t offset) {
  std::vector<std::pair<std::uint64_t, std::uint64_t>> out;
  for (const Segment &s : segments) {
    // (A header's fill may run into the image's: from the image's start.)
    const std::uint64_t start = std::max(s.offset, offset), end = s.offset + s.size;
    if (s.kind == Segment::Kind::padding && s.size <= kStartupReach && end > start &&
        (start < offset + kStartupReach || end + kStartupReach > file.size()))
      out.emplace_back(start, end - start);
  }
  return out;
}

void add_memory(Trace &to, const Trace &from) {
  to.memory.insert(to.memory.end(), from.memory.begin(), from.memory.end());
  to.stack_values.insert(to.stack_values.end(), from.stack_values.begin(), from.stack_values.end());
  to.back_jumps.insert(to.back_jumps.end(), from.back_jumps.begin(), from.back_jumps.end());
  to.setups.insert(to.setups.end(), from.setups.begin(), from.setups.end());
  std::vector<std::uint64_t> words;
  std::set_union(to.code_words.begin(), to.code_words.end(), from.code_words.begin(), from.code_words.end(),
                 std::back_inserter(words));
  to.code_words = std::move(words);
}

MemoryFacts memory_facts(std::span<const std::byte> file, const Trace &trace, std::optional<std::uint64_t> base,
                         std::uint64_t offset, unsigned address_bits, bool big_endian, bool vector_table) {
  MemoryFacts out;
  const std::uint64_t mask = address_bits >= 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << address_bits) - 1;
  offset = std::min<std::uint64_t>(offset, file.size());
  if (base) {
    out.image_start = *base & mask;
    out.image_end = std::min<std::uint64_t>(*out.image_start + (file.size() - offset),
                                            mask == ~std::uint64_t{0} ? mask : mask + 1);
  }
  auto inside = [&](std::uint64_t a) { return out.image_start && a >= *out.image_start && a < *out.image_end; };
  // Small numbers are offsets and counts more often than addresses.
  auto outside = [&](std::uint64_t a) { return a >= 0x100 && a <= mask && !inside(a); };
  auto startup = [&](std::uint64_t at) {
    return (at >= offset && at < offset + kStartupReach) || at + kStartupReach >= file.size();
  };

  // Accesses in file order (the startup trace comes after the rest).
  std::vector<const Trace::Access *> memory;
  for (const Trace::Access &a : trace.memory) memory.push_back(&a);
  std::stable_sort(memory.begin(), memory.end(), [](const auto *a, const auto *b) { return a->at < b->at; });
  std::vector<std::uint64_t> store_sites;
  for (const Trace::Access *a : memory)
    if (a->write) store_sites.push_back(a->at);
  // Loops of a few instructions, by where they start: a load in one that
  // stores nothing waits for something else to change the memory (a device,
  // or an interrupt).
  std::vector<std::pair<std::uint64_t, std::uint64_t>> loops = trace.back_jumps;
  std::sort(loops.begin(), loops.end());
  auto polled = [&](std::uint64_t at) {
    for (auto it = std::lower_bound(loops.begin(), loops.end(), std::pair{at > kPollLoop ? at - kPollLoop : 0, std::uint64_t{0}});
         it != loops.end() && it->first <= at; ++it) {
      if (it->second < at || it->second - it->first > kPollLoop) continue;
      const auto s = std::lower_bound(store_sites.begin(), store_sites.end(), it->first);
      if (s == store_sites.end() || *s > it->second) return true;
    }
    return false;
  };

  // One instruction moving many words (PowerPC's lmw and stmw, ARM's ldm
  // and stm) saves or restores registers, or copies a block: it names no
  // device's registers, and the words aren't variables of their own.
  std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> per_site;
  for (const Trace::Access *a : memory) {
    auto &v = per_site[a->at];
    if (v.size() <= 2 && std::find(v.begin(), v.end(), a->address) == v.end()) v.push_back(a->address);
  }
  std::map<std::uint64_t, MemoryUse> uses;
  std::unordered_map<std::uint64_t, std::uint64_t> last_read;  // address -> the offset of its last load
  for (const Trace::Access *a : memory) {
    if (!outside(a->address) || per_site[a->at].size() > 2) continue;
    MemoryUse &u = uses[a->address];
    u.address = a->address;
    if (a->size < 32) u.widths |= 1u << a->size;
    if (std::find(u.bases.begin(), u.bases.end(), a->base) == u.bases.end()) u.bases.push_back(a->base);
    if (std::find(u.sites.begin(), u.sites.end(), a->at) == u.sites.end()) u.sites.push_back(a->at);
    if (!a->write) {
      ++u.reads;
      if (polled(a->at)) ++u.polled;
      last_read[a->address] = a->at;
      continue;
    }
    ++u.writes;
    if (const auto it = last_read.find(a->address); it != last_read.end() && it->second < a->at && a->at - it->second <= 32)
      ++u.modified;
    if (a->value) {
      ++u.values;
      const std::uint64_t all = a->size >= 8 ? ~std::uint64_t{0} : (std::uint64_t{1} << (8 * a->size)) - 1;
      if (std::popcount(*a->value) == 1 || *a->value == all) ++u.flags;
    }
  }
  for (auto &[address, u] : uses) {
    std::sort(u.bases.begin(), u.bases.end());
    std::sort(u.sites.begin(), u.sites.end());
    out.uses.push_back(std::move(u));
  }

  // The stack: set to a constant by startup code (and moved down a little
  // at once: the top is the highest of a few close together).
  std::vector<std::uint64_t> tops;
  for (const auto &[v, at] : trace.stack_values)
    if (outside(v) && v % 4 == 0 && startup(at)) tops.push_back(v);
  if (vector_table && offset + 8 <= file.size()) {
    // A Cortex-M vector table: the initial stack, then the reset handler
    // (Thumb: odd) in the image.
    auto word = [&](std::uint64_t at) {
      std::uint64_t w = 0;
      for (int k = 0; k < 4; ++k) w = w << 8 | static_cast<std::uint8_t>(file[at + (big_endian ? k : 3 - k)]);
      return w;
    };
    const std::uint64_t stack = word(offset), reset = word(offset + 4);
    if (outside(stack) && stack % 4 == 0 && (reset & 1) && inside(reset & ~std::uint64_t{1})) {
      tops.push_back(stack);
      out.vector_table_stack = stack;
    }
  }
  // A stack's top is the end of a memory as a rule, a page boundary; where
  // one is, values that aren't are something else.
  if (std::any_of(tops.begin(), tops.end(), [](std::uint64_t v) { return v % kPage == 0; }))
    std::erase_if(tops, [&](std::uint64_t v) { return v % kPage != 0 && v != out.vector_table_stack; });
  std::sort(tops.begin(), tops.end());
  for (std::size_t i = 0; i < tops.size(); ++i)
    if (i + 1 == tops.size() || tops[i + 1] - tops[i] > 256) out.stack_tops.push_back(tops[i]);

  // The startup copy of initial data from the end of the image to the start
  // of RAM: a destination outside the image, a source in it and a length
  // (memcpy's arguments) or an end (a copy loop's), such that the copy
  // takes the image's last bytes; then the clear of what follows it (.bss:
  // memset's arguments, a clear loop's). Other copies and clears say
  // nothing of where RAM starts.
  if (out.image_start) {
    std::uint64_t at = file.size();  // past the fill at the image's end
    while (at > offset && (file[at - 1] == std::byte{0} || file[at - 1] == std::byte{0xff})) --at;
    const std::uint64_t content_end = *out.image_start + (at - offset);
    auto ends = [&](std::uint64_t source_end) {
      return source_end == *out.image_end || (source_end >= content_end && source_end <= content_end + 16);
    };
    std::vector<std::pair<std::uint64_t, std::uint64_t>> clears;
    for (const Trace::Setup &s : trace.setups) {
      std::vector<std::uint64_t> away, here, numbers;
      bool zero = false;
      for (std::uint64_t v : s.values) {
        if (v == 0) zero = true;
        else if (inside(v)) here.push_back(v);
        else if (outside(v) && v % 4 == 0) away.push_back(v);
        if (v != 0 && v < kLongestFill) numbers.push_back(v);
      }
      for (std::uint64_t to : away) {
        for (std::uint64_t from : here)
          for (std::uint64_t n : numbers)
            if (n != to && ends(from + n)) out.fills.push_back({to, to + n, from});
        for (std::uint64_t end : away)
          if (end > to && end - to <= kLongestFill) {
            for (std::uint64_t from : here)
              if (ends(from + (end - to))) out.fills.push_back({to, end, from});
            if (zero) clears.emplace_back(to, end);
          }
        if (zero)
          for (std::uint64_t n : numbers)
            if (n != to && outside(to + n - 1)) clears.emplace_back(to, to + n);
      }
    }
    std::vector<MemoryFill> copies = out.fills;
    for (const auto &[start, end] : clears)
      for (const MemoryFill &c : copies)
        if (start >= c.end && start - c.end < 16) out.fills.push_back({start, end, std::nullopt});
  }
  std::sort(out.fills.begin(), out.fills.end(), [](const MemoryFill &a, const MemoryFill &b) {
    return std::tie(a.start, a.end, a.source) < std::tie(b.start, b.end, b.source);
  });
  out.fills.erase(std::unique(out.fills.begin(), out.fills.end(),
                              [](const MemoryFill &a, const MemoryFill &b) {
                                return a.start == b.start && a.end == b.end && a.source == b.source;
                              }),
                  out.fills.end());

  for (std::uint64_t p : trace.pointers)
    if (outside(p)) out.pointers.push_back(p);
  if (std::getenv("RK_DETECT_DEBUG")) dump(out);
  return out;
}

namespace {

// What a processor's architecture says of its address space, where it says
// anything: windows whose memory type is fixed, which regions never cross.
// From the architecture manuals; PowerPC and 68k have none (their devices
// are wherever the board puts them).
struct Window {
  std::uint64_t start, end;  // [start, end)
  enum class Lean : std::uint8_t {
    any,         // anything
    code,        // the code and its aliases: accesses there make no region
    ram,         // RAM as a rule (cached, SRAM)
    mmio,        // devices as a rule (uncached)
    mmio_fixed,  // devices by definition
  } lean;
  const char *name;
};

struct ArchMap {
  std::string name;  // "Cortex-M"; empty: none
  std::vector<Window> windows;
  // MIPS kseg0/kseg1, SuperH P1/P2: two windows on one physical memory,
  // cached and not. The physical address is the low 29 bits.
  bool segments_alias = false;
  bool bit_band = false;  // Cortex-M bit-band aliases
};

ArchMap arch_map(const std::string &processor, unsigned bits, bool vector_table) {
  using L = Window::Lean;
  ArchMap m;
  if (bits != 32) return m;
  if (processor == "ARM" && vector_table) {
    // ARMv7-M and ARMv8-M's fixed memory map.
    m.name = "Cortex-M";
    m.bit_band = true;
    m.windows = {{0x00000000, 0x20000000, L::code, "code"},
                 {0x20000000, 0x40000000, L::ram, "SRAM"},
                 {0x40000000, 0x60000000, L::mmio_fixed, "peripheral"},
                 {0x60000000, 0xa0000000, L::ram, "external RAM"},
                 {0xa0000000, 0xe0000000, L::mmio, "external device"},
                 {0xe0000000, 0xe0100000, L::mmio_fixed, "private peripheral bus"},
                 {0xe0100000, 0x100000000, L::mmio, "vendor system"}};
  } else if (processor == "MIPS") {
    m.name = "MIPS32";
    m.segments_alias = true;
    m.windows = {{0x00000000, 0x80000000, L::any, "kuseg"},
                 {0x80000000, 0xa0000000, L::ram, "kseg0 (cached)"},
                 {0xa0000000, 0xc0000000, L::mmio, "kseg1 (uncached)"},
                 {0xc0000000, 0x100000000, L::any, "kseg2"}};
  } else if (processor == "SuperH4") {
    m.name = "SH-4";
    m.segments_alias = true;
    m.windows = {{0x00000000, 0x80000000, L::any, "P0"},
                 {0x80000000, 0xa0000000, L::ram, "P1 (cached)"},
                 {0xa0000000, 0xc0000000, L::mmio, "P2 (uncached)"},
                 {0xc0000000, 0xe0000000, L::any, "P3"},
                 {0xe0000000, 0x100000000, L::mmio_fixed, "P4 (control registers)"}};
  } else if (processor == "Xtensa") {
    // The ESP chips' data and instruction buses; the rest depends on the
    // chip.
    m.name = "Xtensa (ESP)";
    m.windows = {{0x00000000, 0x3f000000, L::any, "low"},
                 {0x3f000000, 0x40000000, L::any, "data bus"},
                 {0x40000000, 0x50000000, L::code, "instruction bus"},
                 {0x50000000, 0x100000000, L::any, "high"}};
  }
  return m;
}

const Window *window_of(const ArchMap &m, std::uint64_t a) {
  for (const Window &w : m.windows)
    if (a >= w.start && a < w.end) return &w;
  return nullptr;
}

// Text decoded as code names addresses whose bytes are all printable.
bool printable_word(std::uint64_t v) {
  if (v > 0xffffffff) return false;
  for (int k = 0; k < 4; ++k) {
    const auto c = static_cast<std::uint8_t>(v >> (8 * k));
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

// Accesses close together, in one window.
struct Cluster {
  std::uint64_t lo = 0, hi = 0;  // [lo, hi): from the lowest address to past the highest access
  const Window *window = nullptr;
  std::vector<const MemoryUse *> uses;
  std::vector<std::uint64_t> stacks;   // initial stack pointers it holds or ends at
  std::vector<const MemoryFill *> fills;
  std::uint64_t pointers = 0;          // addresses the code builds that land in it
  std::uint64_t alias_of = 0;          // the same memory through the other window (MIPS, SH-4): its cluster's start
  // Evidence, counted once the cluster is complete.
  std::uint32_t reads = 0, writes = 0, widths = 0, polled = 0, values = 0, flags = 0;
  std::uint32_t width4 = 0, width1 = 0;  // addresses accessed only as words, only as bytes
  bool many = false, structured = false, constants = false, polls = false, arch_mmio = false;
  std::uint64_t bases = 0;
  std::uint64_t places = 0;  // 256-byte stretches of the file the accesses are made from
  std::uint64_t sites = 0;   // instructions making them
  RegionSuggestion::Kind kind = RegionSuggestion::Kind::unknown;

  std::size_t addresses() const { return uses.size(); }
  bool ram_anchor() const { return !stacks.empty() || !fills.empty(); }
  // Enough to say anything: three addresses used from several places in
  // the code, or many by many instructions in one place (a table of
  // settings written in a row; not one instruction moving many words, as
  // PowerPC's stmw does). Bytes that aren't code, decoded, name a few
  // addresses from one stretch of the file.
  bool kept() const {
    return (addresses() >= 3 && places >= 3) || (addresses() >= 8 && sites >= 8) || ram_anchor();
  }
};

void measure(Cluster &c) {
  c.reads = c.writes = c.widths = c.polled = c.values = c.flags = c.width4 = c.width1 = 0;
  std::map<std::uint64_t, std::pair<std::uint64_t, std::uint64_t>> spans;  // base -> lowest, highest address
  std::vector<std::uint64_t> places;
  for (const MemoryUse *u : c.uses) {
    for (std::uint64_t at : u->sites) places.push_back(at >> 8);
    c.reads += u->reads, c.writes += u->writes, c.widths |= u->widths, c.polled += u->polled, c.values += u->values,
        c.flags += u->flags;
    if (u->widths == 1u << 4) ++c.width4;
    if (u->widths == 1u << 1) ++c.width1;
    for (std::uint64_t b : u->bases) {
      auto [it, fresh] = spans.try_emplace(b, u->address, u->address);
      it->second.first = std::min(it->second.first, u->address);
      it->second.second = std::max(it->second.second, u->address);
    }
  }
  std::vector<std::uint64_t> sites;
  for (const MemoryUse *u : c.uses) sites.insert(sites.end(), u->sites.begin(), u->sites.end());
  std::sort(sites.begin(), sites.end());
  c.sites = static_cast<std::uint64_t>(std::unique(sites.begin(), sites.end()) - sites.begin());
  std::sort(places.begin(), places.end());
  c.places = static_cast<std::uint64_t>(std::unique(places.begin(), places.end()) - places.begin());
  const std::size_t n = c.addresses();
  // RAM's variables: many, of several sizes.
  c.many = n >= 40 && std::popcount(c.widths) >= 2;
  // A device's registers: a few bases, each with its registers within a
  // page above it, words (or all bytes).
  c.bases = spans.size();
  bool near_base = true;
  for (const auto &[b, span] : spans) near_base = near_base && span.first >= b && span.second - b < kPage;
  c.structured = n >= 3 && spans.size() * 2 <= n && near_base && (10 * c.width4 >= 7 * n || c.width1 == n);
  // Written with constants: control registers are set to values.
  c.constants = c.values >= 2 && 2 * c.values >= c.writes;
  c.polls = c.polled >= 1;
  c.arch_mmio = c.window && (c.window->lean == Window::Lean::mmio_fixed || c.window->lean == Window::Lean::mmio);
}

int mmio_kinds(const Cluster &c) { return c.structured + c.constants + c.polls + c.arch_mmio; }

// Where RAM is the rule, a structure's fields reached from its address
// look like a register block, and RAM is written with constants and polled
// too (volatile variables): a device takes a register block written with
// constants or polled.
bool ram_window_device(const Cluster &c) { return c.structured && (c.constants || c.polls); }

}  // namespace

Regions regions(std::span<const std::byte> file, const Trace &trace, std::optional<std::uint64_t> base,
                std::uint64_t offset, const std::string &language) {
  using K = RegionSuggestion::Kind;
  Regions out;
  const std::string processor = language.substr(0, language.find(':'));
  unsigned bits = 0;
  {
    const std::size_t a = language.find(':'), b = a == std::string::npos ? a : language.find(':', a + 1);
    if (b != std::string::npos) bits = static_cast<unsigned>(std::atoi(language.c_str() + b + 1));
  }
  if (bits < 16) return out;
  const bool big = language.find(":BE:") != std::string::npos;
  const MemoryFacts facts = memory_facts(file, trace, base, offset, bits, big, processor == "ARM");
  const ArchMap arch = arch_map(processor, bits, facts.vector_table_stack.has_value());
  const std::uint64_t space_end = bits >= 64 ? ~std::uint64_t{0} : std::uint64_t{1} << bits;
  // The gaps and pages are a 32-bit system-on-chip's; a small address
  // space has its devices and RAM in proportion (a 64 KiB space: 256 bytes
  // apart is another memory, 256-byte pages).
  const std::uint64_t kGap = std::min(::revkit::detect::kGap, space_end >> 8);
  const std::uint64_t kPage = std::min(::revkit::detect::kPage, space_end >> 8);
  const std::uint64_t kNear = std::min(::revkit::detect::kNear, space_end >> 4);

  // The processor's own I/O registers (small processors' specs list them)
  // are known to analysis already.
  try {
    const std::vector<lift::VolatileRange> declared = lift::processor_volatile_ranges(language);
    if (!declared.empty()) {
      std::string text = "the processor's specification declares its I/O registers volatile (";
      for (std::size_t i = 0; i < declared.size() && i < 4; ++i)
        text += (i ? ", " : "") + declared[i].space + ":" + hex(declared[i].first) + "-" + hex(declared[i].last);
      text += declared.size() > 4 ? ", ...)" : ")";
      out.evidence.push_back({"regions", text + "; analysis knows them without a region"});
    }
  } catch (const std::exception &) {
    // no spec to read: nothing to say
  }

  // What the accesses are, aliases folded: Cortex-M's bit-band words are
  // their base word's bits; MIPS and SuperH reach one physical memory
  // through two windows, and the image's own alias is the image.
  auto physical = [](std::uint64_t a) { return a & 0x1fffffff; };
  auto aliased = [&](std::uint64_t a) { return arch.segments_alias && a >= 0x80000000 && a < 0xc0000000; };
  std::uint64_t image_aliases = 0, text_like = 0, misaligned = 0, in_code = 0, small = 0, code_like = 0;
  std::vector<MemoryUse> folded;
  for (const MemoryUse &u : facts.uses) {
    MemoryUse f = u;
    if (arch.bit_band && ((f.address >= 0x22000000 && f.address < 0x24000000) ||
                          (f.address >= 0x42000000 && f.address < 0x44000000))) {
      const std::uint64_t region = f.address & 0xf0000000;
      f.address = region + (((f.address - region - 0x2000000) >> 5) & ~std::uint64_t{3});
    }
    // Small numbers either side of zero are offsets and counts more often
    // than addresses: there only a device block reached from a round base
    // address in the top 64 KiB counts (a negative offset from nothing, as
    // PowerPC's d(0), is no base).
    if (bits >= 32 && (f.address < 0x10000 ||
                       (f.address >= space_end - 0x10000 &&
                        std::none_of(f.bases.begin(), f.bases.end(), [&](std::uint64_t b) {
                          return b != f.address && b >= space_end - 0x10000 && b % 0x100 == 0;
                        })))) {
      ++small;
      continue;
    }
    const unsigned narrowest = f.widths == 0 ? 1 : static_cast<unsigned>(std::countr_zero(f.widths));  // bytes
    if (narrowest > 1 && narrowest <= 8 && f.address % narrowest != 0) {
      ++misaligned;  // compilers align what they access: these are bytes that aren't code
      continue;
    }
    if (!f.bases.empty() && std::all_of(f.bases.begin(), f.bases.end(), printable_word)) {
      ++text_like;
      continue;
    }
    // Made only from words that are instructions of the code, read as
    // literals by data decoded as loads (ARM's mov and blx words look like
    // addresses at the top of the space).
    if (!f.bases.empty() && std::all_of(f.bases.begin(), f.bases.end(), [&](std::uint64_t b) {
          return std::binary_search(trace.code_words.begin(), trace.code_words.end(), b);
        })) {
      ++code_like;
      continue;
    }
    if (facts.image_start && aliased(f.address) && aliased(*facts.image_start) &&
        physical(f.address) >= physical(*facts.image_start) &&
        physical(f.address) < physical(*facts.image_start) + (*facts.image_end - *facts.image_start)) {
      ++image_aliases;
      continue;
    }
    if (const Window *w = window_of(arch, f.address); w && w->lean == Window::Lean::code) {
      ++in_code;
      continue;
    }
    folded.push_back(std::move(f));
  }
  std::sort(folded.begin(), folded.end(), [](const MemoryUse &a, const MemoryUse &b) { return a.address < b.address; });
  std::vector<MemoryUse> uses;  // two uses of one bit-band word are one
  for (MemoryUse &f : folded) {
    if (!uses.empty() && uses.back().address == f.address) {
      MemoryUse &u = uses.back();
      u.reads += f.reads, u.writes += f.writes, u.widths |= f.widths, u.polled += f.polled, u.modified += f.modified,
          u.flags += f.flags, u.values += f.values;
      u.bases.insert(u.bases.end(), f.bases.begin(), f.bases.end());
      u.sites.insert(u.sites.end(), f.sites.begin(), f.sites.end());
    } else {
      uses.push_back(std::move(f));
    }
  }
  if (image_aliases != 0)
    out.evidence.push_back({"regions", std::to_string(image_aliases) +
                                           " addresses are the image itself through the other (cached or uncached) "
                                           "window: no region"});

  // Clusters: accesses within kGap of each other, in one window.
  std::vector<Cluster> clusters;
  for (const MemoryUse &u : uses) {
    const Window *w = window_of(arch, u.address);
    const std::uint64_t width = u.widths == 0 ? 1 : static_cast<std::uint64_t>(31 - std::countl_zero(u.widths));  // bytes
    if (clusters.empty() || clusters.back().window != w ||
        (u.address > clusters.back().hi && u.address - clusters.back().hi > kGap)) {
      clusters.push_back({});
      clusters.back().lo = u.address;
      clusters.back().window = w;
    }
    Cluster &c = clusters.back();
    c.uses.push_back(&u);
    c.hi = std::max(c.hi, u.address + width);
  }
  for (Cluster &c : clusters) measure(c);
  // The startup copy goes to the start of RAM (its first variable), never
  // to a device; the clear after it to the same RAM.
  auto device = [](const Cluster &c) {
    if (c.many) return false;
    return c.window && c.window->lean == Window::Lean::ram ? ram_window_device(c) : mmio_kinds(c) != 0;
  };
  for (const MemoryFill &f : facts.fills)
    for (Cluster &c : clusters)
      if (f.source && f.start <= c.lo && c.lo - f.start < 16 && !device(c)) c.fills.push_back(&f);
  for (const MemoryFill &f : facts.fills)
    for (Cluster &c : clusters)
      if (!f.source && !c.fills.empty() && f.start < c.hi && c.lo < f.end) c.fills.push_back(&f);

  // The stack's top: in a cluster, or the end of the nearest one below it in
  // its window that isn't a device's (the stack grows down from RAM's end,
  // over memory nothing names); else RAM of its own.
  const bool one_stack = facts.stack_tops.size() == 1;
  for (std::uint64_t sp : facts.stack_tops) {
    const Window *w = window_of(arch, sp - 1);
    if (w && w->lean == Window::Lean::mmio_fixed) continue;
    Cluster *below = nullptr;
    for (Cluster &c : clusters)
      if (c.window == w && c.lo < sp && c.kept() && (!below || c.lo > below->lo)) below = &c;
    const bool image_between = below && facts.image_start && *facts.image_start >= below->hi && *facts.image_start < sp;
    // Far above: only RAM by its own evidence (variables, the startup copy).
    const bool ram = below && (below->many || !below->fills.empty() || (w && w->lean == Window::Lean::ram));
    if (below && !image_between && !device(*below) && (sp <= below->hi + kGap || (sp - below->hi <= kNear && ram))) {
      below->stacks.push_back(sp);
      below->hi = std::max(below->hi, sp);
      // What little lies between (the stack's own first pushes) is part of it.
      for (Cluster &c : clusters)
        if (&c != below && !c.kept() && c.lo >= below->lo && c.lo < sp && c.window == w) {
          below->uses.insert(below->uses.end(), c.uses.begin(), c.uses.end());
          c.uses.clear();
          measure(c);
        }
      measure(*below);
    } else if (one_stack || sp == facts.vector_table_stack) {
      Cluster c;
      c.lo = round_down(sp - 1, kGap);
      if (w) c.lo = std::max(c.lo, w->start);
      if (below) c.lo = std::max(c.lo, round_up(below->hi, kPage));
      if (facts.image_start && *facts.image_end <= sp) c.lo = std::max(c.lo, round_up(*facts.image_end, kPage));
      c.hi = sp;
      c.window = w;
      c.stacks.push_back(sp);
      measure(c);
      clusters.push_back(std::move(c));
    }
  }
  std::sort(clusters.begin(), clusters.end(), [](const Cluster &a, const Cluster &b) { return a.lo < b.lo; });
  for (Cluster &c : clusters) {
    const auto from = std::lower_bound(facts.pointers.begin(), facts.pointers.end(), c.lo);
    const auto to = std::lower_bound(facts.pointers.begin(), facts.pointers.end(), c.hi);
    c.pointers = static_cast<std::uint64_t>(to - from);
  }

  // Classify: RAM where the stack or a startup copy says so, or many
  // variables of several sizes; a device where its registers look like one.
  for (Cluster &c : clusters) {
    if (c.ram_anchor()) c.kind = K::ram;
    else if (c.many && !(c.structured && c.arch_mmio)) c.kind = K::ram;
    // RAM is written with constants and polled too (volatile variables):
    // where RAM is the rule, only a register block says device.
    else if (c.window && c.window->lean == Window::Lean::ram ? ram_window_device(c) : mmio_kinds(c) >= 1) c.kind = K::mmio;
    else c.kind = K::unknown;
  }
  // The other window's view of RAM is RAM (uncached, for DMA).
  if (arch.segments_alias)
    for (Cluster &a : clusters)
      for (const Cluster &b : clusters)
        if (&a != &b && aliased(a.lo) && aliased(b.lo) && a.window != b.window && physical(a.lo) < physical(b.hi - 1) + 1 &&
            physical(b.lo) < physical(a.hi - 1) + 1) {
          a.alias_of = b.lo;
          if (b.kind == K::ram && a.kind != K::ram && !a.ram_anchor()) a.kind = K::ram;
        }

  // Extents. Devices: each cluster's hull in pages, the clusters of one
  // window nothing else separates as one block. RAM: from its lowest
  // address in 64 KiB to a size RAM comes in, short of the next region, the
  // image and the window's end.
  std::vector<const Cluster *> kept;
  for (const Cluster &c : clusters)
    if (c.kept()) kept.push_back(&c);
  struct Draft {
    RegionSuggestion r;
    std::vector<const Cluster *> parts;
    std::string rounding;
  };
  std::vector<Draft> drafts;
  for (std::size_t i = 0; i < kept.size(); ++i) {
    const Cluster &c = *kept[i];
    if (c.kind == K::mmio && !drafts.empty() && drafts.back().r.kind == K::mmio && c.window &&
        drafts.back().parts.back()->window == c.window && c.lo - drafts.back().parts.back()->hi <= kNear) {
      Draft &prev = drafts.back();
      prev.parts.push_back(&c);
      prev.r.size = round_up(c.hi, kPage) - prev.r.start;
      continue;
    }
    Draft d;
    d.r.kind = c.kind;
    d.parts.push_back(&c);
    if (c.kind == K::ram) {
      std::uint64_t lo = c.lo, hi = c.hi;
      for (const MemoryFill *f : c.fills) lo = std::min(lo, f->start), hi = std::max(hi, f->end);
      std::uint64_t floor = c.window ? c.window->start : 0;
      if (!drafts.empty()) floor = std::max(floor, drafts.back().r.start + drafts.back().r.size);
      if (facts.image_start && *facts.image_end <= lo) floor = std::max(floor, round_up(*facts.image_end, kPage));
      d.r.start = std::max(round_down(lo, kGap), floor);
      std::uint64_t ceiling = c.window ? c.window->end : space_end;
      std::string why = arch.name.empty() ? "the top of the address space" : "the end of the window";
      if (i + 1 < kept.size() && round_down(kept[i + 1]->lo, kPage) < ceiling)
        ceiling = round_down(kept[i + 1]->lo, kPage), why = "the next region";
      if (facts.image_start && *facts.image_start >= hi && *facts.image_start < ceiling)
        ceiling = round_down(*facts.image_start, kPage), why = "the image";
      // The previous region or the image ends past the cluster's last
      // access: it is theirs, not a region of its own.
      if (hi <= d.r.start) continue;
      const std::uint64_t size = plausible_size(hi - d.r.start, kPage);
      if (d.r.start + size <= ceiling) {
        d.r.size = size;
        d.rounding = "size rounded up to " + size_text(size) +
                     (std::has_single_bit(size) ? " (a power of two)" : " (one and a half times a power of two)");
      } else {
        d.r.size = std::max(round_up(hi, kPage), ceiling) - d.r.start;
        d.rounding = "up to " + why + " at " + hex(d.r.start + d.r.size);
      }
      d.rounding += ", covering every access";
      if (d.r.start != lo) d.rounding = "start rounded down to " + size_text(kGap) + "; " + d.rounding;
    } else {
      d.r.start = round_down(c.lo, kPage);
      d.r.size = round_up(c.hi, kPage) - d.r.start;
      d.rounding = "rounded out to pages of " + size_text(kPage);
    }
    drafts.push_back(std::move(d));
  }

  // Confidence and evidence.
  std::map<K, int> count;
  for (Draft &d : drafts) {
    RegionSuggestion &r = d.r;
    std::uint32_t reads = 0, writes = 0, widths = 0, polled = 0, values = 0, flags = 0, n = 0, bases = 0;
    std::uint64_t pointers = 0, lo = ~std::uint64_t{0}, hi = 0;
    bool many = false, structured = false, constants = false, polls = false, arch_mmio = false, alias = false;
    std::vector<std::uint64_t> stacks;
    std::vector<const MemoryFill *> fills;
    for (const Cluster *c : d.parts) {
      reads += c->reads, writes += c->writes, widths |= c->widths, polled += c->polled, values += c->values,
          flags += c->flags, n += static_cast<std::uint32_t>(c->addresses()), bases += static_cast<std::uint32_t>(c->bases);
      pointers += c->pointers;
      many = many || c->many, structured = structured || c->structured, constants = constants || c->constants,
      polls = polls || c->polls, arch_mmio = arch_mmio || c->arch_mmio, alias = alias || c->alias_of != 0;
      stacks.insert(stacks.end(), c->stacks.begin(), c->stacks.end());
      fills.insert(fills.end(), c->fills.begin(), c->fills.end());
      for (const MemoryUse *u : c->uses) lo = std::min(lo, u->address), hi = std::max(hi, u->address);
    }
    const Window *w = d.parts.front()->window;
    std::vector<std::string> &ev = r.evidence;
    // Never over the image where it will load: at its base, or at 0 where
    // the base is unknown, which is where an import without one puts it.
    // What remains on the side with more of the accesses stays, if any do.
    std::string clipped;
    {
      const std::uint64_t img_lo = facts.image_start ? *facts.image_start : 0;
      const std::uint64_t img_hi = facts.image_start ? *facts.image_end : img_lo + (file.size() - std::min<std::uint64_t>(offset, file.size()));
      const std::uint64_t end = r.start + r.size;
      if (r.start < img_hi && img_lo < end) {
        std::uint64_t below = 0, above = 0;
        for (const Cluster *c : d.parts)
          for (const MemoryUse *u : c->uses) {
            if (u->address < img_lo) ++below;
            else if (u->address >= img_hi) ++above;
          }
        const std::uint64_t left_end = round_down(img_lo, kPage), right_start = round_up(img_hi, kPage);
        if (above >= below && above != 0 && right_start < end) r.size = end - right_start, r.start = right_start;
        else if (below != 0 && left_end > r.start) r.size = left_end - r.start;
        else continue;  // nothing of it lies outside the image
        clipped = "cut short of the image at " + hex(img_lo) + "-" + hex(img_hi - 1) +
                  (facts.image_start ? "" : " (at 0: where the image loads is unknown, and an import without a base puts it there)");
      }
    }
    // Scattered accesses over much of the address space are no one memory.
    // (RAM the stack or a startup copy says is there may be large.)
    const bool anchored = !stacks.empty() || !fills.empty();
    if (bits < 64 && r.size > space_end / 4 && !(r.kind == K::ram && anchored)) continue;
    if (r.kind == K::ram) {
      // Two kinds of evidence that agree, and not in a window of devices:
      // high.
      const int kinds = !stacks.empty() + !fills.empty() + many;
      r.confidence = kinds >= 2 && !arch_mmio ? Confidence::high : Confidence::medium;
      for (std::uint64_t sp : stacks)
        ev.push_back("the initial stack pointer is " + hex(sp) +
                     (sp == facts.vector_table_stack ? " (the vector table's first word)" : " (set by startup code)"));
      for (const MemoryFill *f : fills)
        ev.push_back(f->source ? "code copies " + std::to_string(f->end - f->start) + " bytes from the image (" +
                                     hex(*f->source) + ") to " + hex(f->start)
                               : "code clears " + hex(f->start) + "-" + hex(f->end - 1));
    } else if (r.kind == K::mmio) {
      const int kinds = structured + constants + polls + arch_mmio;
      // Many accesses too: a few are what bytes that aren't code make.
      r.confidence = kinds >= 2 && !many && reads + writes >= 10 ? Confidence::high : Confidence::medium;
      if (structured)
        ev.push_back(std::to_string(n) + " registers at " + hex(lo) + "-" + hex(hi) + ", reached from " +
                     std::to_string(bases) + (bases == 1 ? " base address" : " base addresses") +
                     " by small offsets, as a device's register block is");
      if (constants)
        ev.push_back(std::to_string(values) + " of " + std::to_string(writes) + " stores write constants" +
                     (flags ? " (" + std::to_string(flags) + " a single bit or all ones)" : std::string()));
      if (polls) ev.push_back(std::to_string(polled) + " loads wait in a loop that stores nothing (polling)");
    } else {
      r.confidence = Confidence::low;
      ev.push_back("accessed, but nothing says whether it is RAM or a device's registers");
    }
    if (n != 0 && (r.kind != K::mmio || !structured))
      ev.push_back(std::to_string(n) + " addresses " + hex(lo) + "-" + hex(hi) + " read " + std::to_string(reads) +
                   " times and written " + std::to_string(writes) + " times" +
                   (widths ? ", " + widths_text(widths) + " bytes wide" : std::string()));
    if (r.kind == K::ram && pointers) ev.push_back(std::to_string(pointers) + " addresses in it are taken as pointers");
    if (w && !arch.name.empty()) ev.push_back("in " + arch.name + "'s " + w->name + " window");
    if (alias) ev.push_back("the same memory is accessed through the other (cached or uncached) window too");
    if (d.parts.size() > 1) ev.push_back(std::to_string(d.parts.size()) + " groups of registers in one window, as one block");
    ev.push_back(d.rounding);
    if (!clipped.empty()) ev.push_back(clipped);
    if (!base && r.confidence == Confidence::high) r.confidence = Confidence::medium;
    // Why this confidence.
    if (r.kind == K::ram || r.kind == K::mmio) {
      const int kinds = r.kind == K::ram ? !stacks.empty() + !fills.empty() + many : structured + constants + polls + arch_mmio;
      std::string why = r.confidence == Confidence::high ? "high: " + std::to_string(kinds) + " kinds of evidence agree"
                        : !base                          ? "medium: where the image loads is unknown"
                        : kinds >= 2 && r.kind == K::ram ? "medium: in a window of devices"
                        : kinds >= 2                     ? "medium: few accesses, or as many as RAM has"
                                                         : "medium: one kind of evidence";
      ev.push_back(why);
    }
    const int k = ++count[r.kind];
    const std::string label = r.kind == K::ram ? "ram" : r.kind == K::mmio ? "mmio" : "mem";
    r.spec = label + (k > 1 ? std::to_string(k) : "") + ":" + bare_hex(r.start) + ":" + bare_hex(r.size) +
             (r.kind == K::mmio ? ":rw-:volatile" : "");
    out.regions.push_back(std::move(r));
  }
  if (out.regions.empty())
    out.evidence.push_back({"regions", uses.size() < 3 ? "no RAM or devices seen outside the image: its variables may "
                                                         "live in it, or be reached in ways the code doesn't spell out"
                                                       : "accesses outside the image are too scattered to make regions of"});
  if (code_like != 0)
    out.evidence.push_back({"regions", std::to_string(code_like) + (code_like == 1 ? " address" : " addresses") +
                                           " made only from instructions of the code read as words (by data "
                                           "decoded as loads) left out"});
  if (std::getenv("RK_DETECT_DEBUG"))
    std::fprintf(stderr, "regions: dropped %llu misaligned, %llu text-like, %llu code words, %llu in code windows, %llu small\n",
                 (unsigned long long)misaligned, (unsigned long long)text_like, (unsigned long long)code_like,
                 (unsigned long long)in_code, (unsigned long long)small);
  return out;
}

}  // namespace revkit::detect
