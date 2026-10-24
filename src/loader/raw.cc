// Flat binaries (firmware, ROM dumps): Ghidra's "Raw Binary" loader, plus a
// header skip, a length and extra regions for RAM and memory-mapped I/O.

#include "revkit/loader/load.hh"

#include "reader.hh"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <span>
#include <vector>

namespace revkit::loader {

namespace {

using detail::fail;
using detail::hex;

std::vector<std::string_view> split(std::string_view s, char sep) {
  std::vector<std::string_view> out;
  for (;;) {
    std::size_t at = s.find(sep);
    out.push_back(s.substr(0, at));
    if (at == std::string_view::npos) break;
    s.remove_prefix(at + 1);
  }
  return out;
}

std::uint64_t parse_number(std::string_view s, std::string_view what) {
  if (s.starts_with("0x") || s.starts_with("0X")) s.remove_prefix(2);
  std::uint64_t v = 0;
  auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), v, 16);
  if (s.empty() || ec != std::errc() || end != s.data() + s.size())
    fail("bad " + std::string(what) + ": \"" + std::string(s) + "\"");
  return v;
}


// ---- Intel HEX and Motorola S-records ----

// One line's worth of data at an address.
struct Record {
  std::uint64_t address = 0;
  std::vector<std::byte> data;
};

struct TextImage {
  std::vector<Record> data;
  std::optional<std::uint64_t> entry;
};

int hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// The bytes a line of hex digits spells, or nullopt.
std::optional<std::vector<std::uint8_t>> hex_bytes(std::string_view digits) {
  if (digits.size() % 2 != 0) return std::nullopt;
  std::vector<std::uint8_t> out;
  out.reserve(digits.size() / 2);
  for (std::size_t i = 0; i < digits.size(); i += 2) {
    int hi = hex_digit(digits[i]), lo = hex_digit(digits[i + 1]);
    if (hi < 0 || lo < 0) return std::nullopt;
    out.push_back(static_cast<std::uint8_t>(hi << 4 | lo));
  }
  return out;
}

// The file's non-empty lines, trailing CR and blanks dropped.
std::vector<std::string_view> text_lines(std::span<const std::byte> file) {
  std::string_view text(reinterpret_cast<const char *>(file.data()), file.size());
  std::vector<std::string_view> out;
  for (std::string_view line : split(text, '\n')) {
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.remove_suffix(1);
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
    if (!line.empty()) out.push_back(line);
  }
  return out;
}

// Parses Intel HEX (record types 00-05); nullopt with `error` set when a
// line isn't a well-formed record.
std::optional<TextImage> parse_ihex(std::span<const std::byte> file, std::string &error) {
  TextImage out;
  std::uint64_t upper = 0;  // extended linear (04) or segment (02) base
  bool eof = false;
  std::size_t n = 0;
  for (std::string_view line : text_lines(file)) {
    ++n;
    auto bad = [&](const std::string &why) {
      error = "Intel HEX line " + std::to_string(n) + ": " + why;
      return std::nullopt;
    };
    if (eof) return bad("data after the end-of-file record");
    if (line.front() != ':') return bad("does not start with ':'");
    auto b = hex_bytes(line.substr(1));
    if (!b || b->size() < 5) return bad("not a record");
    const std::vector<std::uint8_t> &r = *b;
    if (r.size() != std::size_t{r[0]} + 5) return bad("length byte doesn't match");
    std::uint8_t sum = 0;
    for (std::uint8_t x : r) sum = static_cast<std::uint8_t>(sum + x);
    if (sum != 0) return bad("bad checksum");
    const std::uint32_t addr = static_cast<std::uint32_t>(r[1] << 8 | r[2]);
    const std::uint8_t type = r[3];
    std::span<const std::uint8_t> data(r.data() + 4, r[0]);
    auto be = [&](std::size_t k) {
      std::uint64_t v = 0;
      for (std::size_t i = 0; i < k; ++i) v = v << 8 | data[i];
      return v;
    };
    switch (type) {
      case 0: {
        Record rec;
        rec.address = upper + addr;
        for (std::uint8_t x : data) rec.data.push_back(static_cast<std::byte>(x));
        if (!rec.data.empty()) out.data.push_back(std::move(rec));
        break;
      }
      case 1: eof = true; break;
      case 2:
        if (data.size() != 2) return bad("bad extended segment address");
        upper = be(2) << 4;
        break;
      case 3:
        if (data.size() != 4) return bad("bad start segment address");
        out.entry = (be(4) >> 16 << 4) + (be(4) & 0xffff);
        break;
      case 4:
        if (data.size() != 2) return bad("bad extended linear address");
        upper = be(2) << 16;
        break;
      case 5:
        if (data.size() != 4) return bad("bad start linear address");
        out.entry = be(4);
        break;
      default: return bad("unknown record type " + std::to_string(type));
    }
  }
  if (n == 0) {
    error = "Intel HEX: no records";
    return std::nullopt;
  }
  return out;
}

// Parses Motorola S-records (S0-S9); nullopt with `error` set when a line
// isn't a well-formed record.
std::optional<TextImage> parse_srec(std::span<const std::byte> file, std::string &error) {
  TextImage out;
  std::size_t n = 0;
  for (std::string_view line : text_lines(file)) {
    ++n;
    auto bad = [&](const std::string &why) {
      error = "S-record line " + std::to_string(n) + ": " + why;
      return std::nullopt;
    };
    if (line.size() < 4 || line[0] != 'S' || line[1] < '0' || line[1] > '9') return bad("not an S-record");
    const int type = line[1] - '0';
    auto b = hex_bytes(line.substr(2));
    if (!b || b->empty()) return bad("not an S-record");
    const std::vector<std::uint8_t> &r = *b;
    if (r.size() != std::size_t{r[0]} + 1) return bad("count byte doesn't match");
    std::uint8_t sum = 0;
    for (std::size_t i = 0; i + 1 < r.size(); ++i) sum = static_cast<std::uint8_t>(sum + r[i]);
    if (static_cast<std::uint8_t>(~sum) != r.back()) return bad("bad checksum");
    static constexpr int kAddrBytes[10] = {2, 2, 3, 4, 0, 2, 3, 4, 3, 2};
    const int k = kAddrBytes[type];
    if (type == 4 || r.size() < static_cast<std::size_t>(k) + 2) return bad("bad record");
    std::uint64_t addr = 0;
    for (int i = 0; i < k; ++i) addr = addr << 8 | r[1 + i];
    if (type >= 1 && type <= 3) {
      Record rec;
      rec.address = addr;
      for (std::size_t i = 1 + k; i + 1 < r.size(); ++i) rec.data.push_back(static_cast<std::byte>(r[i]));
      if (!rec.data.empty()) out.data.push_back(std::move(rec));
    } else if (type >= 7) {
      out.entry = addr;
    }
  }
  if (n == 0) {
    error = "S-records: no records";
    return std::nullopt;
  }
  return out;
}

// The image's bytes in one buffer and a block per contiguous run, from
// records sorted by address; overlapping records are an error.
struct Runs {
  std::shared_ptr<Bytes> bytes = std::make_shared<Bytes>();
  struct Run {
    std::uint64_t start = 0, size = 0, offset = 0;
  };
  std::vector<Run> runs;
};

Runs gather(std::vector<Record> records) {
  std::stable_sort(records.begin(), records.end(),
                   [](const Record &a, const Record &b) { return a.address < b.address; });
  Runs out;
  for (const Record &r : records) {
    if (!out.runs.empty()) {
      Runs::Run &last = out.runs.back();
      const std::uint64_t end = last.start + last.size;
      if (r.address < end) fail("raw: records overlap at " + hex(r.address));
      if (r.address == end) {
        out.bytes->insert(out.bytes->end(), r.data.begin(), r.data.end());
        last.size += r.data.size();
        continue;
      }
    }
    out.runs.push_back({r.address, r.data.size(), out.bytes->size()});
    out.bytes->insert(out.bytes->end(), r.data.begin(), r.data.end());
  }
  return out;
}

}  // namespace

std::optional<Bytes> decode_hex_text(std::span<const std::byte> file) {
  std::string_view text(reinterpret_cast<const char *>(file.data()), file.size());
  auto blank = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
  std::size_t i = 0;
  while (i < text.size() && blank(text[i])) ++i;
  if (text.substr(i, 2) == "0x" || text.substr(i, 2) == "0X") i += 2;
  Bytes out;
  out.reserve(text.size() / 2);
  int hi = -1;
  for (; i < text.size(); ++i) {
    const char c = text[i];
    if (blank(c)) {
      if (hi >= 0) return std::nullopt;  // a digit pair split by a blank
      continue;
    }
    const int d = hex_digit(c);
    if (d < 0) return std::nullopt;
    if (hi < 0) {
      hi = d;
    } else {
      out.push_back(static_cast<std::byte>(hi << 4 | d));
      hi = -1;
    }
  }
  if (hi >= 0 || out.empty()) return std::nullopt;
  return out;
}

RawContainer detect_raw_container(std::span<const std::byte> file) {
  if (file.empty()) return RawContainer::binary;
  const char first = static_cast<char>(file[0]);
  std::string error;
  if (first == ':' && parse_ihex(file, error)) return RawContainer::ihex;
  if (first == 'S' && parse_srec(file, error)) return RawContainer::srec;
  // Hex text: "0x6080..." or bare digits, at least four bytes' worth.
  if (std::isxdigit(static_cast<unsigned char>(first)) && file.size() >= 8)
    if (auto bytes = decode_hex_text(file); bytes && bytes->size() >= 4) return RawContainer::hexbytes;
  return RawContainer::binary;
}

std::string_view to_string(RawContainer c) {
  switch (c) {
    case RawContainer::detect: return "detect";
    case RawContainer::binary: return "binary";
    case RawContainer::ihex: return "ihex";
    case RawContainer::srec: return "srec";
    case RawContainer::hexbytes: return "hexbytes";
  }
  return "binary";
}

std::optional<RawContainer> raw_container_from_string(std::string_view name) {
  for (RawContainer c : {RawContainer::detect, RawContainer::binary, RawContainer::ihex, RawContainer::srec,
                         RawContainer::hexbytes})
    if (to_string(c) == name) return c;
  if (name == "hex") return RawContainer::ihex;
  if (name == "bin" || name.empty()) return name.empty() ? RawContainer::detect : RawContainer::binary;
  return std::nullopt;
}

RawRegion parse_raw_region(std::string_view spec) {
  auto parts = split(spec, ':');
  if (parts.size() < 3 || parts.size() > 6 || parts[0].empty())
    fail("region \"" + std::string(spec) + "\" is not name:start:size[:perms][:init|uninit|volatile][:space=NAME]");
  RawRegion r;
  r.name = std::string(parts[0]);
  r.start = parse_number(parts[1], "region start");
  r.size = parse_number(parts[2], "region size");
  for (std::size_t i = 3; i < parts.size(); ++i) {
    std::string_view p = parts[i];
    if (p.starts_with("space=") && p.size() > 6) r.space = std::string(p.substr(6));
    else if (p == "init") r.initialized = true;
    else if (p == "uninit") r.initialized = false;
    else if (p == "volatile") r.is_volatile = true;
    else if (p.size() == 3 && (p[0] == 'r' || p[0] == '-') && (p[1] == 'w' || p[1] == '-') &&
             (p[2] == 'x' || p[2] == '-'))
      r.perms = {p[0] == 'r', p[1] == 'w', p[2] == 'x'};
    else
      fail("region \"" + std::string(spec) + "\": unknown flag \"" + std::string(p) + "\"");
  }
  return r;
}

Image parse_raw(std::shared_ptr<const Bytes> file, const RawOptions &options) {
  if (!file) fail("no input");
  // Hex text (an EVM contract's bytecode as solc and block explorers print
  // it): the bytes it spells, then as a binary file.
  RawContainer given = options.container;
  if (given == RawContainer::detect) given = detect_raw_container(*file);
  if (given == RawContainer::hexbytes) {
    std::optional<Bytes> decoded = decode_hex_text(*file);
    if (!decoded) fail("raw: the file isn't hex text");
    file = std::make_shared<const Bytes>(std::move(*decoded));
  }
  std::string language = options.language;
  auto parts = split(language, ':');
  if (parts.size() < 4 || parts.size() > 5)
    fail("raw: language \"" + language + "\" is not proc:endian:size:variant");
  Image img;
  img.format = Format::raw;
  img.file = file;
  img.memory = Memory(file);
  img.endian = parts[1] == "BE" ? Endian::big : Endian::little;
  unsigned bits = 0;
  std::from_chars(parts[2].data(), parts[2].data() + parts[2].size(), bits);
  if (bits < 8 || bits > 64 || bits % 8 != 0) fail("raw: language \"" + language + "\" has no pointer size");
  img.bits = bits;
  // Keys are bytes and a word-addressed space has more bytes than its
  // address size says (AVR's 16-bit code space holds 128 KB), so small
  // languages are checked against 32 bits; SLEIGH refuses what's past
  // the top of its spaces.
  const std::uint64_t top = bits == 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << std::max(bits, 32u)) - 1;

  // The language's spaces first, so their keys are the language's.
  const std::optional<LanguageMemory> lm = language_memory(language);
  if (lm) apply_language_memory(img, *lm, false);
  auto known_space = [&](const std::string &space) {
    if (space.empty() || !lm || bits > 32) return;
    for (const AddressSpace &a : lm->spaces)
      if (a.name == space) return;
    fail("raw: language " + language + " has no memory space \"" + space + "\"");
  };
  known_space(options.space);
  for (const RawRegion &r : options.regions) known_space(r.space);

  RawContainer container = given == RawContainer::hexbytes ? RawContainer::binary : given;

  struct Pending {
    Block block;
    Region region;
    std::string space;
    bool image = false;  // the file's bytes, not a declared region
    std::uint64_t shown = 0;  // the start as the user gave it (in its space)
  };
  std::vector<Pending> pending;
  std::optional<std::uint64_t> file_entry;
  bool image_block = false;  // the file's bytes made a block at `base`
  if (container == RawContainer::binary) {
    const std::uint64_t fsize = file->size();
    if (options.offset > fsize) fail("raw: offset " + hex(options.offset) + " is past the end of the file");
    const std::uint64_t length = options.length.value_or(fsize - options.offset);
    image_block = length != 0;
    if (length > fsize - options.offset) fail("raw: offset + length is past the end of the file");
    if (length != 0) {
      Pending p;
      p.block = {options.block_name.empty() ? "ram" : options.block_name, options.base, length, options.perms, true};
      p.region = {options.base, length, options.offset, length, options.perms};
      p.space = options.space;
      p.image = true;
      pending.push_back(std::move(p));
    }
  } else {
    std::string error;
    std::optional<TextImage> text =
        container == RawContainer::ihex ? parse_ihex(*file, error) : parse_srec(*file, error);
    if (!text) fail("raw: " + error);
    Runs runs = gather(std::move(text->data));
    img.memory = Memory(runs.bytes);
    img.file = runs.bytes;
    const std::string name = options.block_name.empty() ? "ram" : options.block_name;
    for (std::size_t i = 0; i < runs.runs.size(); ++i) {
      const Runs::Run &r = runs.runs[i];
      Pending p;
      p.block = {i == 0 ? name : name + "_" + std::to_string(i), r.start, r.size, options.perms, true};
      p.region = {r.start, r.size, r.offset, r.size, options.perms};
      p.space = options.space;
      p.image = true;
      pending.push_back(std::move(p));
    }
    file_entry = text->entry;
  }
  for (const RawRegion &r : options.regions) {
    if (r.name.empty()) fail("raw: a region has no name");
    if (r.size == 0) fail("raw: region " + r.name + " is empty");
    if (r.file_size > r.size) fail("raw: region " + r.name + " has more file bytes than its size");
    if (r.file_size != 0 && !r.initialized) fail("raw: region " + r.name + " takes file bytes but is uninitialized");
    if (r.file_size != 0 && container != RawContainer::binary)
      fail("raw: region " + r.name + " takes file bytes from a " + std::string(to_string(container)) + " file");
    Pending p;
    p.block = {r.name, r.start, r.size, r.perms, r.initialized, r.is_volatile};
    p.region = {r.start, r.size, r.file_offset, r.file_size, r.perms};
    p.space = r.space;
    pending.push_back(std::move(p));
  }
  if (pending.empty()) fail("raw: nothing to load");
  for (Pending &p : pending) {
    p.shown = p.region.start;
    const std::uint64_t space_top = p.space.empty() ? top : (std::uint64_t{1} << kSpaceKeyShift) - 1;
    if (p.region.size - 1 > space_top || p.region.start > space_top - (p.region.size - 1))
      fail("raw: block " + p.block.name + " at " + hex(p.block.start) + " is past the top of the " +
           (p.space.empty() ? std::to_string(std::max(bits, 32u)) + "-bit address space" : "space " + p.space));
    if (p.space.empty()) continue;
    add_space(img, p.space);  // LoadError for a 64-bit language
    const std::uint64_t key = *space_key(img, p.space, p.region.start);
    p.block.start = p.region.start = key;
  }
  std::sort(pending.begin(), pending.end(), [](const Pending &a, const Pending &b) { return a.block.start < b.block.start; });
  // Overlaps named, a declared region before the image it hits: "region
  // mmio (0x0–0xffff) overlaps the image block ram (0x0–0x1a49)".
  auto named = [](const Pending &p) {
    return std::string(p.image ? "the image block " : "region ") + p.block.name + " (" + hex(p.shown) + "–" +
           hex(p.shown + (p.region.size - 1)) + (p.space.empty() ? "" : " in " + p.space) + ")";
  };
  // Sorted and disjoint so far, the one before ends last.
  for (std::size_t i = 1; i < pending.size(); ++i)
    if (pending[i].region.start <= pending[i - 1].region.last()) {
      const bool swap = pending[i].image;
      fail(named(pending[swap ? i - 1 : i]) + " overlaps " + named(pending[swap ? i : i - 1]));
    }
  for (const Pending &p : pending) {
    img.memory.add(p.region);  // LoadError on overlap or bytes outside the file
    img.blocks.push_back(p.block);
  }
  // What the processor spec maps in every program (AVR's SRAM and I/O).
  if (lm) apply_language_memory(img, *lm, true);
  img.image_base = img.file_base =
      image_block ? space_key(img, options.space, options.base).value_or(options.base) : img.blocks.front().start;
  if (!options.symbols.empty()) {
    img.symbols = options.symbols;
    for (Symbol &sym : img.symbols) sym.source = SymbolSource::symtab;
    if (language.starts_with("ARM:")) img.machine = 40;  // EM_ARM: odd function symbols are Thumb
  }
  std::optional<std::uint64_t> entry;
  if (options.entry) entry = space_key(img, options.space, *options.entry);
  else if (file_entry) entry = space_key(img, options.space, *file_entry);
  if (entry) {
    if (img.memory.is_mapped(*entry)) img.entry = entry;
    else img.warnings.push_back("the entry point " + hex(*entry) + " is outside every block");
  }
  return img;
}

namespace {

struct PresetRegion {
  const char *name;
  std::uint64_t start, size;
};

// GBATEK, "DS Memory Maps": the ARM9's and ARM7's shared WRAM windows (the
// 16 or 32 KiB given to the CPU, mirrored through the window; 0x037F8000 is
// the mirror programs use) and I/O ports (the ARM7's wireless ports are at
// 0x04800000, in the same window). The last 4 KiB of main memory
// (0x027FF000, through the 0x027xxxxx mirror) is what both CPUs and the
// SDK's start-up code share: the cartridge header copy at 0x027FFE00
// (GBATEK, "DS Cartridge Header"), the VBlank counter and IPC words.
constexpr PresetRegion kNdsArm9[] = {
    {"main_shared", 0x027FF000, 0x1000},
    {"shared_wram", 0x03000000, 0x01000000},
    {"io", 0x04000000, 0x01000000},
};
constexpr PresetRegion kNdsArm7[] = {
    {"main_shared", 0x027FF000, 0x1000},
    {"shared_wram", 0x03000000, 0x00800000},
    {"io", 0x04000000, 0x01000000},
};

}  // namespace

std::vector<std::string> platform_presets() { return {"nds-arm9", "nds-arm7"}; }

std::optional<std::vector<RawRegion>> platform_regions(std::string_view preset,
                                                       const std::vector<std::pair<std::uint64_t, std::uint64_t>> &taken) {
  std::span<const PresetRegion> regions;
  if (preset == "nds-arm9") regions = kNdsArm9;
  else if (preset == "nds-arm7") regions = kNdsArm7;
  else return std::nullopt;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> busy(taken.begin(), taken.end());
  std::sort(busy.begin(), busy.end());
  std::vector<RawRegion> out;
  for (const PresetRegion &pr : regions) {
    // [first, last] minus every taken range, piece by piece.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> pieces{{pr.start, pr.start + (pr.size - 1)}};
    for (const auto &[tf, tl] : busy) {
      std::vector<std::pair<std::uint64_t, std::uint64_t>> next;
      for (const auto &[f, l] : pieces) {
        if (tl < f || tf > l) {
          next.emplace_back(f, l);
          continue;
        }
        if (tf > f) next.emplace_back(f, tf - 1);
        if (tl < l) next.emplace_back(tl + 1, l);
      }
      pieces = std::move(next);
    }
    for (std::size_t i = 0; i < pieces.size(); ++i) {
      RawRegion r;
      r.name = i == 0 ? std::string(pr.name) : std::string(pr.name) + "_" + std::to_string(i);
      r.start = pieces[i].first;
      r.size = pieces[i].second - pieces[i].first + 1;
      r.perms = {true, true, false};
      r.initialized = false;
      r.is_volatile = true;
      out.push_back(std::move(r));
    }
  }
  return out;
}

}  // namespace revkit::loader
