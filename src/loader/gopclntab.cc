// Go's pclntab (gopclntab.hh). The layouts are Go's own, as runtime/symtab.go,
// runtime/runtime2.go (pcHeader, _func, moduledata) and debug/gosym's
// pclntab.go (BSD-3-Clause, Copyright The Go Authors) define them; how a
// stripped binary's table is found (its magic, then the moduledata that
// points to it) follows Ghidra's Golang support (GoPcHeader, GoModuledata;
// Apache-2.0). No code is copied from either. The no-return names are
// Ghidra's GolangFunctionsThatDoNotReturn (Apache-2.0) and Go 1.25's
// bounds-check entry points. THIRD_PARTY_NOTICES.md.

#include "revkit/loader/gopclntab.hh"

#include "revkit/loader/load.hh"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <set>

namespace revkit::loader {

namespace {

constexpr std::uint32_t kMagic12 = 0xfffffffb;
constexpr std::uint32_t kMagic116 = 0xfffffffa;
constexpr std::uint32_t kMagic118 = 0xfffffff0;
constexpr std::uint32_t kMagic120 = 0xfffffff1;
constexpr std::size_t kMaxName = 4096;               // one name or file name
// The names and files read, in all: functions can share one long name, so
// this bounds the output rather than the input.
constexpr std::uint64_t kMaxStrings = 256ull << 20;
constexpr std::uint64_t kMaxScan = 1ull << 30;       // bytes the magic scan reads
constexpr std::uint64_t kMaxTable = 1ull << 30;      // bytes a table spans
constexpr std::size_t kMaxScanned = 32;              // headers the scan tries

// The bytes of a table, with the reads it needs bounds-checked: every read
// past the end gives nullopt.
class TableReader {
 public:
  TableReader(std::span<const std::byte> d, bool big) : d_(d), big_(big) {}
  std::uint64_t size() const { return d_.size(); }
  std::optional<std::uint64_t> uint(std::uint64_t at, unsigned n) const {
    if (at > d_.size() || d_.size() - at < n) return std::nullopt;
    std::uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i) v = (v << 8) | std::to_integer<std::uint64_t>(d_[at + (big_ ? i : n - 1 - i)]);
    return v;
  }
  std::optional<std::uint32_t> u32(std::uint64_t at) const {
    auto v = uint(at, 4);
    return v ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(*v)) : std::nullopt;
  }
  std::optional<std::uint8_t> u8(std::uint64_t at) const {
    if (at >= d_.size()) return std::nullopt;
    return std::to_integer<std::uint8_t>(d_[at]);
  }
  // A NUL-terminated string at `at`, at most kMaxName bytes (a longer one is
  // cut there); nullopt when `at` is outside or no NUL is in reach.
  std::optional<std::string_view> cstring(std::uint64_t at) const {
    if (at >= d_.size()) return std::nullopt;
    const std::uint64_t n = std::min<std::uint64_t>(d_.size() - at, kMaxName);
    const char *p = reinterpret_cast<const char *>(d_.data() + at);
    const void *nul = std::memchr(p, 0, static_cast<std::size_t>(n));
    if (nul == nullptr) {
      if (n == kMaxName) return std::string_view(p, n);
      return std::nullopt;
    }
    return std::string_view(p, static_cast<const char *>(nul) - p);
  }
  // A varint (Go's uvarint, at most 5 bytes for a uint32) at *at.
  std::optional<std::uint32_t> varint(std::uint64_t *at) const {
    std::uint32_t v = 0;
    for (unsigned shift = 0; shift < 35; shift += 7) {
      auto b = u8(*at);
      if (!b) return std::nullopt;
      ++*at;
      v |= static_cast<std::uint32_t>(*b & 0x7f) << shift;
      if ((*b & 0x80) == 0) return v;
    }
    return std::nullopt;
  }

 private:
  std::span<const std::byte> d_;
  bool big_;
};

// The value a pc-value table (pcfile, pcln) has at the function's entry:
// its first (value delta, pc delta) pair applied to -1.
std::optional<std::int32_t> entry_value(const TableReader &b, std::uint64_t table) {
  std::uint64_t at = table;
  auto uv = b.varint(&at);
  if (!uv) return std::nullopt;
  const std::int32_t delta = (*uv & 1) ? static_cast<std::int32_t>(~(*uv >> 1)) : static_cast<std::int32_t>(*uv >> 1);
  if (!b.varint(&at)) return std::nullopt;  // the pc delta: the value holds from the entry on
  return static_cast<std::int32_t>(static_cast<std::uint32_t>(-1) + static_cast<std::uint32_t>(delta));
}

// UTF-8 checked: invalid bytes as U+FFFD (the API's strings must be UTF-8).
std::string valid_utf8(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size();) {
    const auto c = static_cast<unsigned char>(s[i]);
    std::size_t n = c < 0x80 ? 1 : (c >= 0xc2 && c <= 0xdf) ? 2 : (c >= 0xe0 && c <= 0xef) ? 3 : (c >= 0xf0 && c <= 0xf4) ? 4 : 0;
    bool ok = n != 0 && i + n <= s.size();
    for (std::size_t k = 1; ok && k < n; ++k) ok = (static_cast<unsigned char>(s[i + k]) & 0xc0) == 0x80;
    if (ok && n > 1) {
      const auto c1 = static_cast<unsigned char>(s[i + 1]);
      ok = !(c == 0xe0 && c1 < 0xa0) && !(c == 0xed && c1 >= 0xa0) && !(c == 0xf0 && c1 < 0x90) && !(c == 0xf4 && c1 >= 0x90);
    }
    if (ok) {
      out.append(s.substr(i, n));
      i += n;
    } else {
      out += "\xef\xbf\xbd";
      ++i;
    }
  }
  return out;
}

std::string hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::optional<GoPclntabVersion> version_of(std::uint32_t magic) {
  switch (magic) {
    case kMagic12: return GoPclntabVersion::go12;
    case kMagic116: return GoPclntabVersion::go116;
    case kMagic118: return GoPclntabVersion::go118;
    case kMagic120: return GoPclntabVersion::go120;
    default: return std::nullopt;
  }
}

// The header's magic and byte order, when data[0..8) can start a table.
std::optional<std::pair<GoPclntabVersion, bool>> header_kind(std::span<const std::byte> d) {
  if (d.size() < 16) return std::nullopt;
  const auto u8 = [&](std::size_t i) { return std::to_integer<std::uint8_t>(d[i]); };
  if (u8(4) != 0 || u8(5) != 0 || (u8(6) != 1 && u8(6) != 2 && u8(6) != 4) || (u8(7) != 4 && u8(7) != 8))
    return std::nullopt;
  const std::uint32_t le = u8(0) | u8(1) << 8 | u8(2) << 16 | static_cast<std::uint32_t>(u8(3)) << 24;
  const std::uint32_t be = static_cast<std::uint32_t>(u8(0)) << 24 | u8(1) << 16 | u8(2) << 8 | u8(3);
  // The magics read differently in the other byte order (Go chose them so).
  if (auto v = version_of(le)) return std::pair{*v, false};
  if (auto v = version_of(be)) return std::pair{*v, true};
  return std::nullopt;
}

}  // namespace

std::string_view to_string(GoPclntabVersion v) {
  switch (v) {
    case GoPclntabVersion::go12: return "1.2";
    case GoPclntabVersion::go116: return "1.16";
    case GoPclntabVersion::go118: return "1.18";
    case GoPclntabVersion::go120: return "1.20";
  }
  return "?";
}

std::optional<GoPclntab> parse_go_pclntab(std::span<const std::byte> data, std::uint64_t address,
                                          const GoPointerFn &pointer, const GoPclntabOptions &options,
                                          std::string *error) {
  std::string scratch;
  if (!error) error = &scratch;
  error->clear();
  auto fail = [&](std::string why) -> std::optional<GoPclntab> {
    *error = "Go pclntab at 0x" + hex(address) + ": " + std::move(why);
    return std::nullopt;
  };
  if (data.size() > kMaxTable) data = data.first(kMaxTable);
  auto kind = header_kind(data);
  if (!kind) return fail("not a pclntab header");
  GoPclntab out;
  out.address = address;
  out.version = kind->first;
  out.endian = kind->second ? Endian::big : Endian::little;
  const TableReader b(data, kind->second);
  out.quantum = *b.u8(6);
  out.pointer_size = *b.u8(7);
  const unsigned ptr = out.pointer_size;
  const bool v118 = out.version >= GoPclntabVersion::go118;
  auto word = [&](unsigned i) { return b.uint(8 + std::uint64_t{i} * ptr, ptr); };
  auto ptr_at = [&](std::uint64_t at, std::uint64_t raw) { return pointer ? pointer(address + at, raw) : raw; };

  // Where the parts are, as offsets from the header.
  std::uint64_t funcnametab = 0, cutab = 0, filetab = 0, pctab = 0, funcdata = 0, functab = 0;
  std::uint64_t nfunc = 0, nfiles = 0;
  if (out.version == GoPclntabVersion::go12) {
    auto n = word(0);
    if (!n) return fail("truncated header");
    nfunc = *n;
    functab = 8 + ptr;
  } else {
    const unsigned base = v118 ? 3 : 2;  // 1.18 added textStart before the offsets
    std::array<std::uint64_t, 5> off{};
    for (unsigned i = 0; i < 5; ++i) {
      auto w = word(base + i);
      if (!w) return fail("truncated header");
      if (*w >= data.size()) return fail("a table offset past its end");
      off[i] = *w;
    }
    auto n = word(0), f = word(1);
    if (!n || !f) return fail("truncated header");
    nfunc = *n;
    nfiles = *f;
    funcnametab = off[0];
    cutab = off[1];
    filetab = off[2];
    pctab = off[3];
    funcdata = off[4];
    functab = off[4];
    if (v118) {
      if (options.text_start) {
        out.text_start = *options.text_start;
      } else {
        auto t = word(2);
        if (!t) return fail("truncated header");
        out.text_start = ptr_at(8 + 2 * ptr, *t);
      }
    }
  }
  if (nfunc == 0) return fail("no functions");
  if (nfunc > options.max_functions) return fail("more functions than the limit (" + std::to_string(nfunc) + ")");
  const unsigned fs = v118 ? 4 : ptr;  // a functab field
  const std::uint64_t functab_size = (2 * nfunc + 1) * fs;
  if (functab > data.size() || data.size() - functab < functab_size) return fail("the function table runs past the data");
  out.function_count = nfunc;
  if (out.version == GoPclntabVersion::go12) {
    // The file table follows the function table: its offset, then its
    // entries (a count first, then each file's string offset).
    auto fileoff = b.u32(functab + functab_size);
    if (!fileoff) return fail("truncated file table offset");
    filetab = *fileoff;
    auto nf = b.u32(filetab);
    if (!nf) return fail("the file table is outside the data");
    nfiles = *nf;
    if (std::uint64_t{nfiles} * 4 > data.size() - filetab) return fail("the file table runs past the data");
  }
  out.file_count = nfiles;

  auto pc = [&](std::uint64_t i) -> std::optional<std::uint64_t> {
    const std::uint64_t at = functab + 2 * i * fs;
    auto v = b.uint(at, fs);
    if (!v) return std::nullopt;
    if (v118) return out.text_start + *v;
    return ptr_at(at, *v);
  };
  auto funcoff = [&](std::uint64_t i) { return b.uint(functab + (2 * i + 1) * fs, fs); };

  std::uint64_t skipped = 0;
  std::string first_skip;
  auto skip = [&](std::uint64_t i, const std::string &why) {
    if (skipped++ == 0) first_skip = "function " + std::to_string(i) + ": " + why;
  };
  out.functions.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(nfunc, data.size() / (2 * fs))));
  std::uint64_t strings = 0;
  std::optional<std::uint64_t> next = pc(0);
  if (!next) return fail("truncated function table");
  for (std::uint64_t i = 0; i < nfunc; ++i) {
    const std::uint64_t entry = *next;
    next = pc(i + 1);
    if (!next) return fail("truncated function table");
    if (*next < entry) return fail("the function table isn't sorted at entry " + std::to_string(i));
    auto off = funcoff(i);
    if (!off || *off >= data.size() - funcdata) {
      skip(i, "its _func is outside the data");
      continue;
    }
    const std::uint64_t f = funcdata + *off;
    const unsigned sz0 = v118 ? 4 : ptr;  // _func.entry(Off)
    auto field = [&](unsigned n) { return b.u32(f + sz0 + (n - 1) * 4); };
    auto name_off = field(1);
    if (!name_off) {
      skip(i, "truncated _func");
      continue;
    }
    auto name = b.cstring(funcnametab + *name_off);
    if (!name || name->empty()) {
      skip(i, "no name");
      continue;
    }
    GoFunction g;
    g.entry = entry;
    g.end = *next;
    g.name = valid_utf8(*name);
    if (out.version != GoPclntabVersion::go12) {
      const unsigned tail = out.version == GoPclntabVersion::go120 ? 10 : 9;  // past cuOffset (and startLine)
      g.func_id = b.u8(f + sz0 + (tail - 1) * 4).value_or(0);
      g.flag = b.u8(f + sz0 + (tail - 1) * 4 + 1).value_or(0);
    }
    if (options.lines) {
      auto pcfile = field(5), pcln = field(6);
      if (pcfile && *pcfile != 0) {
        if (auto fno = entry_value(b, pctab + *pcfile)) {
          std::optional<std::uint64_t> name_at;
          if (out.version == GoPclntabVersion::go12) {
            if (*fno > 0 && static_cast<std::uint64_t>(*fno) < nfiles)
              if (auto o = b.u32(filetab + 4 * static_cast<std::uint64_t>(*fno))) name_at = *o;
          } else if (*fno >= 0) {
            auto cu = field(8);
            if (cu && *cu != ~std::uint32_t{0})
              if (auto o = b.u32(cutab + (std::uint64_t{*cu} + static_cast<std::uint64_t>(*fno)) * 4);
                  o && *o != ~std::uint32_t{0})
                name_at = filetab + *o;
          }
          if (name_at)
            if (auto s = b.cstring(*name_at)) g.file = valid_utf8(*s);
        }
      }
      if (out.version == GoPclntabVersion::go120) {
        if (auto l = field(9)) g.line = static_cast<std::int32_t>(*l);
      }
      if (g.line <= 0 && pcln && *pcln != 0)
        if (auto l = entry_value(b, pctab + *pcln); l && *l > 0) g.line = *l;
      if (g.line < 0) g.line = 0;
    }
    strings += g.name.size() + g.file.size();
    out.functions.push_back(std::move(g));
    if (strings > kMaxStrings) {
      out.warnings.push_back("stopped after " + std::to_string(i + 1) + " functions: their names pass " +
                             std::to_string(kMaxStrings >> 20) + " MiB");
      break;
    }
  }
  if (out.functions.empty()) return fail("no function decodes (" + first_skip + ")");
  if (skipped)
    out.warnings.push_back(std::to_string(skipped) + " of " + std::to_string(nfunc) +
                           " functions didn't decode (" + first_skip + ")");
  return out;
}

// --- finding the table -------------------------------------------------------------

namespace {

struct Candidate {
  std::uint64_t address = 0;
  std::string found_by;
};

GoPointerFn image_pointer(const Image &image) {
  // As the build-info reader: a RELATIVE relocation (or a Mach-O rebase)
  // at the slot says where a stored pointer goes; otherwise it moves with
  // the image.
  const std::uint64_t delta = image.image_base - image.file_base;
  return [&image, delta](std::uint64_t at, std::uint64_t raw) {
    const auto &rel = image.relocations;
    auto it = std::lower_bound(rel.begin(), rel.end(), at, [](const Relocation &r, std::uint64_t a) { return r.address < a; });
    if (it != rel.end() && it->address == at && it->target) return *it->target;
    return raw + delta;
  };
}

// The file-backed bytes of memory from `address` on, while the regions
// are contiguous, at most `limit` bytes.
std::vector<std::byte> mapped_from(const Image &image, std::uint64_t address, std::uint64_t limit) {
  std::uint64_t at = address, n = 0;
  while (n < limit) {
    const Region *r = image.memory.find(at);
    if (!r || at - r->start >= r->file_size) break;
    const std::uint64_t take = std::min(r->file_size - (at - r->start), limit - n);
    n += take;
    at += take;
    if (at - r->start < r->file_size) break;
  }
  std::vector<std::byte> out(static_cast<std::size_t>(n));
  if (n) image.memory.read(address, out);
  return out;
}

bool executable(const Image &image, std::uint64_t a) {
  const Region *r = image.memory.find(a);
  return r && r->perms.exec;
}

// How many of the table's functions start in executable memory.
std::size_t executable_entries(const Image &image, const GoPclntab &t) {
  std::size_t n = 0;
  for (const GoFunction &f : t.functions) n += executable(image, f.entry);
  return n;
}

struct Moduledata {
  std::uint64_t address = 0;
  std::uint64_t minpc = 0, maxpc = 0, text = 0;
};

// The moduledata pointing to the table at `table`: a pointer-sized word
// holding its address in writable data (the first field: pcHeader since
// Go 1.16, the pclntable slice's data before), whose next fields agree
// (the function-name slice or the function table at the header's offsets,
// minpc and maxpc the function table's first and last pc).
std::optional<Moduledata> find_moduledata(const Image &image, const GoPclntab &t, std::span<const std::byte> table) {
  const unsigned ptr = t.pointer_size;
  const bool big = t.endian == Endian::big;
  const GoPointerFn pointer = image_pointer(image);
  const TableReader tb(table, big);
  std::vector<std::uint64_t> slots;
  const std::uint64_t delta = image.image_base - image.file_base;
  for (const Relocation &r : image.relocations)
    if (r.target && *r.target == t.address) slots.push_back(r.address);
  std::uint64_t budget = kMaxScan;
  for (const Region &r : image.memory.regions()) {
    if (!r.perms.write || r.perms.exec || r.file_size == 0 || budget == 0) continue;
    const std::uint64_t n = std::min(r.file_size, budget);
    budget -= n;
    std::vector<std::byte> bytes(static_cast<std::size_t>(n));
    image.memory.read(r.start, bytes);
    const TableReader rb(bytes, big);
    const std::uint64_t first = (ptr - r.start % ptr) % ptr;
    for (std::uint64_t at = first; at + ptr <= n; at += ptr)
      if (auto w = rb.uint(at, ptr); w && *w + delta == t.address) slots.push_back(r.start + at);
  }
  std::sort(slots.begin(), slots.end());
  slots.erase(std::unique(slots.begin(), slots.end()), slots.end());
  const bool v116 = t.version != GoPclntabVersion::go12;
  // Field indexes (in words): the slice that must point into the table and
  // where it must point, then minpc, maxpc and text.
  const unsigned check = v116 ? 1 : 3;  // funcnametab.data / ftab.data
  std::uint64_t expect = 0;
  if (v116) {
    const unsigned base = t.version >= GoPclntabVersion::go118 ? 3 : 2;
    auto off = tb.uint(8 + std::uint64_t{base} * ptr, ptr);
    if (!off) return std::nullopt;
    expect = t.address + *off;
  } else {
    expect = t.address + 8 + ptr;
  }
  const unsigned minpc = v116 ? 20 : 10, maxpc = minpc + 1, text = minpc + 2;
  for (std::uint64_t s : slots) {
    auto read_word = [&](unsigned i) -> std::optional<std::uint64_t> {
      std::array<std::byte, 8> w{};
      const std::uint64_t at = s + std::uint64_t{i} * ptr;
      if (image.memory.read(at, std::span(w.data(), ptr)) != ptr) return std::nullopt;
      auto v = TableReader(std::span<const std::byte>(w.data(), ptr), big).uint(0, ptr);
      return pointer(at, *v);
    };
    auto c = read_word(check);
    if (!c || *c != expect) continue;
    Moduledata m;
    m.address = s;
    auto lo = read_word(minpc), hi = read_word(maxpc), tx = read_word(text);
    if (!lo || !hi || !tx) continue;
    m.minpc = *lo;
    m.maxpc = *hi;
    m.text = *tx;
    return m;
  }
  return std::nullopt;
}

// Where a 1.18+ table's entries count from when there's no moduledata:
// the runtime.text symbol, else the text section.
std::optional<std::uint64_t> text_symbol(const Image &image) {
  for (const Symbol &s : image.symbols)
    if (s.defined && s.name == "runtime.text" && s.value) return s.value;
  for (const Section &s : image.sections)
    if ((s.name == ".text" || s.name == "__text") && s.alloc && s.perms.exec) return s.addr;
  return std::nullopt;
}

// Tables whose header is in the image: named sections, the runtime's
// symbols, then (when neither) every 4-byte aligned magic in file-backed
// memory.
std::vector<Candidate> candidates(const Image &image) {
  std::vector<Candidate> out;
  for (const Section &s : image.sections) {
    const std::string_view n = s.name;
    if ((n == ".gopclntab" || n == ".data.rel.ro.gopclntab" || n == "__gopclntab" || n.ends_with(",__gopclntab")) &&
        s.alloc && s.file_size)
      out.push_back({s.addr, "section"});
  }
  for (const char *name : {"runtime.pcheader", "runtime.pclntab"})
    for (const Symbol &s : image.symbols)
      if (s.defined && s.name == name && s.value) out.push_back({s.value, "symbol"});
  if (!out.empty()) return out;
  // The scan, where a Go binary's table has no name: a PE (Go's linker
  // names none), an ELF without section headers. A Mach-O always has its
  // __gopclntab, and an ELF with sections its .gopclntab.
  if (image.format == Format::macho || (image.format == Format::elf && !image.sections.empty())) return out;
  std::uint64_t budget = kMaxScan;
  for (const Region &r : image.memory.regions()) {
    if (r.file_size < 16 || budget == 0) continue;
    const std::uint64_t n = std::min(r.file_size, budget);
    budget -= n;
    std::vector<std::byte> bytes(static_cast<std::size_t>(n));
    image.memory.read(r.start, bytes);
    const std::uint64_t first = (4 - r.start % 4) % 4;
    for (std::uint64_t at = first; at + 16 <= n; at += 4) {
      // Cheap first: the two zero pad bytes and the high magic bytes.
      if (bytes[at + 4] != std::byte{0} || bytes[at + 5] != std::byte{0}) continue;
      if (header_kind(std::span(bytes).subspan(at, 16))) {
        out.push_back({r.start + at, "scan"});
        // Each is decoded (a copy of the memory after it): a hostile file
        // full of magics gets only the first few.
        if (out.size() == kMaxScanned) return out;
      }
    }
  }
  return out;
}

}  // namespace

std::optional<GoPclntab> read_go_pclntab(const Image &image, std::string *error, const GoPclntabOptions &options) {
  std::string scratch;
  if (!error) error = &scratch;
  error->clear();
  const GoPointerFn pointer = image_pointer(image);
  const unsigned ptr = image.bits / 8;
  std::optional<GoPclntab> best;
  bool best_has_md = false;
  std::string first_error;
  for (const Candidate &c : candidates(image)) {
    std::vector<std::byte> bytes = mapped_from(image, c.address, kMaxTable);
    if (bytes.size() < 16) continue;
    auto kind = header_kind(bytes);
    if (!kind) continue;
    // A scanned header must be for this image's pointer size.
    if (c.found_by == "scan" && std::to_integer<unsigned>(bytes[7]) != ptr) continue;
    // The moduledata first: a 1.18+ table's entries count from its text
    // (the header's textStart is 0 since Go 1.2x: "unused").
    GoPclntab head;
    head.address = c.address;
    head.version = kind->first;
    head.endian = kind->second ? Endian::big : Endian::little;
    head.pointer_size = std::to_integer<unsigned>(bytes[7]);
    auto md = find_moduledata(image, head, bytes);
    GoPclntabOptions o = options;
    if (kind->first >= GoPclntabVersion::go118 && !o.text_start) {
      const TableReader hb(bytes, kind->second);
      const std::uint64_t slot = 8 + 2 * std::uint64_t{head.pointer_size};
      const std::uint64_t field = hb.uint(slot, head.pointer_size).value_or(0);
      const std::uint64_t from_header = field ? pointer(c.address + slot, field) : 0;
      if (md && md->text) o.text_start = md->text;
      else if (from_header) o.text_start = from_header;
      else if (auto t = text_symbol(image)) o.text_start = *t;
    }
    std::string why;
    auto t = parse_go_pclntab(bytes, c.address, pointer, o, &why);
    if (!t) {
      if (c.found_by != "scan" && first_error.empty()) first_error = why;
      continue;
    }
    t->found_by = c.found_by;
    if (md) {
      t->moduledata = md->address;
      if (md->minpc != t->functions.front().entry)
        t->warnings.push_back("the moduledata's minpc (0x" + hex(md->minpc) + ") isn't the first function's entry (0x" +
                              hex(t->functions.front().entry) + ")");
    }
    // The entries must be code.
    const std::size_t exec = executable_entries(image, *t);
    if (exec * 2 < t->functions.size()) {
      if (c.found_by != "scan" && first_error.empty())
        first_error = "Go pclntab at 0x" + hex(c.address) + ": its functions aren't in executable memory";
      continue;
    }
    // A named table wins; among scanned ones, the first a moduledata points to.
    if (c.found_by != "scan") {
      best = std::move(t);
      break;
    }
    if (!best || (!best_has_md && md)) {
      best_has_md = md.has_value();
      best = std::move(t);
      if (best_has_md) break;
    }
  }
  if (!best && !first_error.empty()) *error = first_error;
  return best;
}

std::string go_display_name(std::string_view name) {
  constexpr std::size_t kMax = 256;
  std::string s;
  s.reserve(name.size());
  for (std::size_t i = 0; i < name.size(); ++i) {
    const auto c = static_cast<unsigned char>(name[i]);
    if (name.substr(i, 2) == "\xc2\xb7") {  // U+00B7 middle dot
      s += '.';
      ++i;
    } else if (name.substr(i, 3) == "\xe2\x88\x95") {  // U+2215 division slash
      s += '/';
      i += 2;
    } else if (c <= 0x20 || c == 0x7f) {
      s += '_';
    } else {
      s += static_cast<char>(c);
    }
  }
  if (s.size() <= kMax) return s;
  // Each outermost [...] as "[...]".
  std::string short_form;
  int depth = 0;
  for (char c : s) {
    if (c == '[') {
      if (depth++ == 0) short_form += "[...]";
      continue;
    }
    if (c == ']' && depth > 0) {
      --depth;
      continue;
    }
    if (depth == 0) short_form += c;
  }
  if (depth == 0) s = std::move(short_form);
  if (s.size() <= kMax) return s;
  std::size_t cut = kMax;
  while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xc0) == 0x80) --cut;  // not inside a UTF-8 sequence
  s.resize(cut);
  return s;
}

bool go_function_no_return(std::string_view name) {
  static const std::set<std::string_view> kNames = {
      // Ghidra 12.1.4's GolangFunctionsThatDoNotReturn.
      "runtime.abort", "runtime.abort.abi0", "runtime.dieFromSignal", "runtime.exit.abi0", "runtime.exitThread",
      "runtime.fatal", "runtime.fatalpanic", "runtime.fatalthrow", "runtime.Goexit", "runtime.goexit0",
      "runtime.goexit0.abi0", "runtime.goexit1", "runtime.goexit.abi0", "runtime.gopanic",
      "runtime.goPanicExtendIndex", "runtime.goPanicExtendIndexU", "runtime.goPanicExtendSlice3Acap",
      "runtime.goPanicExtendSlice3AcapU", "runtime.goPanicExtendSlice3Alen", "runtime.goPanicExtendSlice3AlenU",
      "runtime.goPanicExtendSlice3B", "runtime.goPanicExtendSlice3BU", "runtime.goPanicExtendSlice3C",
      "runtime.goPanicExtendSlice3CU", "runtime.goPanicExtendSliceAcap", "runtime.goPanicExtendSliceAcapU",
      "runtime.goPanicExtendSliceAlen", "runtime.goPanicExtendSliceAlenU", "runtime.goPanicExtendSliceB",
      "runtime.goPanicExtendSliceBU", "runtime.goPanicIndex", "runtime.goPanicIndexU", "runtime.goPanicSlice3Acap",
      "runtime.goPanicSlice3AcapU", "runtime.goPanicSlice3Alen", "runtime.goPanicSlice3AlenU",
      "runtime.goPanicSlice3B", "runtime.goPanicSlice3BU", "runtime.goPanicSlice3C", "runtime.goPanicSlice3CU",
      "runtime.goPanicSliceAcap", "runtime.goPanicSliceAcapU", "runtime.goPanicSliceAlen",
      "runtime.goPanicSliceAlenU", "runtime.goPanicSliceB", "runtime.goPanicSliceBU",
      "runtime.goPanicSliceConvert", "runtime.mstart", "runtime.mstart0", "runtime.mstart.abi0",
      "runtime.newstack", "runtime.newstack.abi0", "runtime.panic", "runtime.panicCheck1", "runtime.panicCheck2",
      "runtime.panicdivide", "runtime.panicdottypeE", "runtime.panicdottypeI", "runtime.panicExtendIndex",
      "runtime.panicExtendIndexU", "runtime.panicExtendSlice3Acap", "runtime.panicExtendSlice3AcapU",
      "runtime.panicExtendSlice3Alen", "runtime.panicExtendSlice3AlenU", "runtime.panicExtendSlice3B",
      "runtime.panicExtendSlice3BU", "runtime.panicExtendSlice3C", "runtime.panicExtendSlice3CU",
      "runtime.panicExtendSliceAcap", "runtime.panicExtendSliceAcapU", "runtime.panicExtendSliceAlen",
      "runtime.panicExtendSliceAlenU", "runtime.panicExtendSliceB", "runtime.panicExtendSliceBU",
      "runtime.panicfloat", "runtime.panicIndex", "runtime.panicIndexU", "runtime.panicmakeslicecap",
      "runtime.panicmakeslicelen", "runtime.panicmem", "runtime.panicmemAddr", "runtime.panicnildottype",
      "runtime.panicoverflow", "runtime.panicshift", "runtime.panicSlice3Acap", "runtime.panicSlice3AcapU",
      "runtime.panicSlice3Alen", "runtime.panicSlice3AlenU", "runtime.panicSlice3B", "runtime.panicSlice3BU",
      "runtime.panicSlice3C", "runtime.panicSlice3CU", "runtime.panicSliceAcap", "runtime.panicSliceAcapU",
      "runtime.panicSliceAlen", "runtime.panicSliceAlenU", "runtime.panicSliceB", "runtime.panicSliceBU",
      "runtime.panicSliceConvert", "runtime.panicUnaligned", "runtime.panicunsafeslicelen",
      "runtime.panicunsafeslicelen1", "runtime.panicunsafeslicenilptr", "runtime.panicunsafeslicenilptr1",
      "runtime.panicunsafestringlen", "runtime.panicunsafestringnilptr", "runtime.panicwrap", "runtime.sigpanic",
      "runtime.sigpanic0.abi0", "runtime.systemstack_switch", "runtime.throw",
      // Go 1.25's bounds checks: generated code calls panicBounds (or
      // panicExtend on 32-bit), which call panicBounds64/32/32X.
      "runtime.panicBounds", "runtime.panicExtend", "runtime.panicBounds64", "runtime.panicBounds32",
      "runtime.panicBounds32X"};
  return kNames.contains(name);
}

}  // namespace revkit::loader
